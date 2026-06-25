"""Pure-Python pattern triage over a notebook cell failure.

Cost rationale: Claude reading {"category":"missing_module","module":"xyz"}
costs ~15 tokens. Claude reading the raw traceback + cell source costs
500-2000+ tokens. The triager is deterministic regex matching with NO
LLM call, NO network, NO file system access, NO auto-edit — it just
returns metadata. Claude still validates and applies every fix.

If the pattern doesn't match, we return category='unknown' and Claude
falls back to full traceback analysis as today. No regressions.

Security: regexes are anchored and non-backtracking; input size is
capped before matching to defeat catastrophic-backtracking DoS.
"""
from __future__ import annotations

import re
from typing import Any

_MAX_INPUT_BYTES = 64 * 1024   # cap on traceback length we'll scan

# Each pattern: (category, compiled regex, extractor)
# - regex: matches the LAST line of the traceback (where exception lives)
# - extractor: lambda match -> dict of extracted fields
_PATTERNS: list[tuple[str, re.Pattern[str], Any]] = [
    ("missing_module",
     re.compile(r"^ModuleNotFoundError: No module named ['\"]([A-Za-z0-9_.\-]+)['\"]\s*$",
                re.MULTILINE),
     lambda m: {"module": m.group(1)}),

    ("import_error",
     re.compile(r"^ImportError: cannot import name ['\"]([A-Za-z0-9_]+)['\"] "
                r"from ['\"]([A-Za-z0-9_.\-]+)['\"]",
                re.MULTILINE),
     lambda m: {"name": m.group(1), "module": m.group(2)}),

    ("missing_file",
     re.compile(r"^FileNotFoundError: \[Errno 2\] No such file or directory: "
                r"['\"]([^'\"]+)['\"]\s*$",
                re.MULTILINE),
     lambda m: {"path": m.group(1)}),

    ("permission_error",
     re.compile(r"^PermissionError: \[Errno 13\] Permission denied: "
                r"['\"]([^'\"]+)['\"]\s*$",
                re.MULTILINE),
     lambda m: {"path": m.group(1)}),

    ("name_error",
     re.compile(r"^NameError: name ['\"]([A-Za-z0-9_]+)['\"] is not defined",
                re.MULTILINE),
     lambda m: {"name": m.group(1)}),

    ("attribute_error",
     re.compile(r"^AttributeError: ['\"]?([A-Za-z0-9_.]+)['\"]? object has "
                r"no attribute ['\"]([A-Za-z0-9_]+)['\"]",
                re.MULTILINE),
     lambda m: {"type": m.group(1), "attribute": m.group(2)}),

    ("key_error",
     re.compile(r"^KeyError: ['\"]?([^'\"\n]{0,200})['\"]?\s*$",
                re.MULTILINE),
     lambda m: {"key": m.group(1)}),

    ("syntax_error",
     re.compile(r"^SyntaxError: (.+)$", re.MULTILINE),
     lambda m: {"detail": m.group(1)[:200]}),

    ("type_error",
     re.compile(r"^TypeError: (.+)$", re.MULTILINE),
     lambda m: {"detail": m.group(1)[:200]}),

    ("value_error",
     re.compile(r"^ValueError: (.+)$", re.MULTILINE),
     lambda m: {"detail": m.group(1)[:200]}),

    ("assertion_error",
     re.compile(r"^AssertionError(?:: (.+))?$", re.MULTILINE),
     lambda m: {"detail": (m.group(1) or "")[:200]}),

    ("oom",
     re.compile(r"^(?:MemoryError|.*CUDA out of memory.*|.*OutOfMemoryError.*)$",
                re.MULTILINE | re.IGNORECASE),
     lambda m: {}),

    ("transient_network",
     re.compile(r"^(?:ConnectionResetError|ConnectionRefusedError|"
                r"requests\.exceptions\.ConnectionError|"
                r"urllib3\.exceptions\.ProtocolError|"
                r"httpx\.ConnectError|httpx\.ReadTimeout|"
                r".*HTTP (?:502|503|504).*)",
                re.MULTILINE | re.IGNORECASE),
     lambda m: {}),
]


# Recommended-action text shown to Claude. Kept short on purpose — Claude
# doesn't need a long prose explanation; the category + extracted fields
# carry the load. Claude validates and decides whether to apply.
_RECOMMENDED: dict[str, str] = {
    "missing_module":     "Add `!pip install <module>` as a new first cell, OR install in the runtime image.",
    "import_error":       "Check installed version of the module; the symbol may have moved/renamed across versions.",
    "missing_file":       "Verify the file exists at the path; check working directory; consider uploading via terra_upload_to_bucket.",
    "permission_error":   "File exists but is unreadable; check ownership/mode. Cell may be touching a system path it shouldn't.",
    "name_error":         "Likely a typo or missing assignment; check the cell for the undefined name.",
    "attribute_error":    "Object type lacks the attribute; check API surface vs the installed library version.",
    "key_error":          "Dictionary access on a missing key; add `.get()` or assert presence first.",
    "syntax_error":       "Syntactic error at parse time; check the indicated line.",
    "type_error":         "Operation between incompatible types; check argument types/order.",
    "value_error":        "Function argument has invalid value; check input bounds/format.",
    "assertion_error":    "Assertion failed at runtime; inspect the condition and inputs.",
    "oom":                "Out of memory — reduce batch size, downsample, or use a larger-memory machine type.",
    "transient_network":  "Likely transient — safe to retry the same job once with no code change.",
    "unknown":            "No pattern match; full traceback analysis required.",
}


def triage(failed_cell_source: str | None,
            failed_cell_traceback: str | None) -> dict:
    """Return a structured triage block. NEVER raises — falls back to
    `category='unknown'` on any error.

    Returns:
        {
            "category": <one of the categories above>,
            "confidence": "high" | "low",
            "extracted": {...},   # fields specific to the category
            "recommended_action": <short string>,
        }

    Notes:
        - Pure function: no I/O, no edits.
        - Inputs >64 KB are truncated (head + tail) to defeat regex DoS.
        - Caller should treat output as METADATA, not a directive.
    """
    if not isinstance(failed_cell_traceback, str) or not failed_cell_traceback:
        return _result("unknown", "low", {})
    tb = failed_cell_traceback
    if len(tb) > _MAX_INPUT_BYTES:
        # Keep head + tail (the exception line is usually at the END,
        # but the cell context is at the head).
        half = _MAX_INPUT_BYTES // 2
        tb = tb[:half] + "\n…[truncated]…\n" + tb[-half:]
    for category, pat, extract in _PATTERNS:
        m = pat.search(tb)
        if m:
            try:
                fields = extract(m)
            except (IndexError, ValueError):
                fields = {}
            return _result(category, "high", fields)
    return _result("unknown", "low", {})


def _result(category: str, confidence: str, fields: dict) -> dict:
    return {
        "category": category,
        "confidence": confidence,
        "extracted": fields,
        "recommended_action": _RECOMMENDED.get(category, _RECOMMENDED["unknown"]),
    }
