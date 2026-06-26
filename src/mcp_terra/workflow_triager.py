"""Deterministic Cromwell / Google-Batch (PAPI) workflow-failure classifier.

The WDL counterpart to bug_triager. Cromwell failure messages fall into a
stable set of categories; a tiny regex pass turns a verbose failure string into
{"category": "...", "recommended_action": "..."} so the auto-fix loop can act on
a 2-token signal instead of paying for an LLM read of every failure.

Pure function: it classifies caller-PROVIDED text and performs NO network I/O
and NO data fetch — so it never egresses anything new. Returns
category='unknown' on anything it can't match (the caller then reads the full
message itself).
"""
from __future__ import annotations

import re
from typing import Any

# Each pattern: (category, compiled regex). ORDER MATTERS — most specific first.
# A 137/OOM/"no space" must be classified oom_disk before the generic non-zero
# return code falls through to task_failed.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aborted",
     re.compile(r"\b[Aa]borted\b|was\s+aborted|workflow\s+aborted", re.IGNORECASE)),

    ("oom_disk",
     re.compile(r"return code 137"
                r"|exit(?:ed with)? (?:code|status) 137"
                r"|\bOOMKilled\b"
                r"|[Oo]ut\s?of\s?[Mm]emory"
                r"|OutOfMemory"
                r"|MemoryError"
                r"|No space left on device"
                r"|disk (?:is )?full"
                r"|PAPI error code 10\b"
                r"|exit code 10\b.*memory",
                re.IGNORECASE)),

    ("localization_failure",
     re.compile(r"[Ff]ailed to (?:de)?localize"
                r"|localization failed"
                r"|No such object"
                r"|does not (?:exist|have storage)"
                r"|Required (?:file|workflow output).*(?:does not exist|not found)"
                r"|AccessDenied(?:Exception)?"
                r"|403.*does not have storage\.objects",
                re.IGNORECASE)),

    ("wdl_error",
     re.compile(r"[Ff]ailed to import"
                r"|Unexpected (?:symbol|token|character)"
                r"|ERROR: Unexpected"
                r"|Cannot (?:lookup|resolve) (?:value|variable)"
                r"|womtool"
                r"|[Ss]yntax error"
                r"|could not parse"
                r"|Miscompiled",
                re.IGNORECASE)),

    ("bad_input",
     re.compile(r"Required workflow input.*not specified"
                r"|not specified and has no default"
                r"|Failed to evaluate"
                r"|Could not evaluate"
                r"|Workflow input processing failed"
                r"|input (?:value|expression).*(?:invalid|could not)"
                r"|Invalid (?:input|parameter)",
                re.IGNORECASE)),

    ("quota_transient",
     re.compile(r"Quota exceeded"
                r"|Resource exhausted"
                r"|\bpreempt(?:ed|ion)?\b"
                r"|VM was (?:unexpectedly|preempted)"
                r"|Connection (?:reset|refused|timed out)"
                r"|\b50[234]\b"
                r"|PAPI error code 1\b"
                r"|temporarily unavailable"
                r"|please try again",
                re.IGNORECASE)),

    # Generic catch-all for a task that ran but exited non-zero (PAPI error 9 /
    # a bad command). Kept LAST among the matchers so the specific ones win.
    ("task_failed",
     re.compile(r"Job exited with return code (?!0\b)\d+"
                r"|exited with (?:code|status) (?!0\b)\d+"
                r"|PAPI error code 9\b"
                r"|stderr"
                r"|Task .* failed"
                r"|non[- ]?zero",
                re.IGNORECASE)),
]

_RECOMMENDED: dict[str, str] = {
    "aborted":
        "The submission was aborted (e.g. stopped in the Terra UI). Stop the "
        "loop and surface the state — do not auto-resubmit.",
    "oom_disk":
        "The task ran out of memory or disk. Increase the task runtime block "
        "(memory / disk), re-register the method (new Agora snapshot), and "
        "re-submit. Call-caching reuses shards that already succeeded.",
    "localization_failure":
        "An input file could not be read: wrong GCS path, the object was moved/"
        "deleted, requester-pays (set MCP_TERRA_REQUESTER_PAYS_PROJECT), or a "
        "controlled-access auth-domain you are not in. Verify the path "
        "(terra_list_bucket / terra_get_bucket_object_metadata), fix the input, "
        "re-submit.",
    "wdl_error":
        "The WDL failed to parse/import or has a type error. Edit the WDL, "
        "validate locally (womtool), re-register (new snapshot), re-config "
        "(new name), re-submit. Agora is append-only.",
    "bad_input":
        "A required input is missing or an input expression is wrong. Fix "
        "inputs_json, create a new method config, re-submit.",
    "quota_transient":
        "Quota / preemption / transient infra. Surface to the user; do NOT "
        "loop on infra. A bare re-submit often succeeds (call-caching reuses "
        "succeeded shards).",
    "task_failed":
        "The task command failed on the VM (non-zero exit / PAPI error 9). "
        "Read the task stderr (terra_get_workflow_logs), fix the command or a "
        "missing Docker tool in runtime, re-register, re-submit.",
    "unknown":
        "No deterministic pattern matched. Read the full failure message and "
        "the task stderr (terra_get_workflow_logs) to diagnose.",
}


def classify(failure_text: str | None) -> dict[str, Any]:
    """Classify a Cromwell/Batch failure message.

    Returns: {"category", "confidence", "recommended_action"}. Never raises —
    returns category='unknown' on any error or empty input.
    """
    try:
        text = (failure_text or "").strip()
        if not text:
            return _result("unknown", "low")
        # Cap the scan to keep a pathological multi-MB message cheap.
        text = text[:20000]
        for category, pat in _PATTERNS:
            if pat.search(text):
                return _result(category, "high")
        return _result("unknown", "low")
    except Exception:
        return _result("unknown", "low")


def _result(category: str, confidence: str) -> dict[str, Any]:
    return {
        "category": category,
        "confidence": confidence,
        "recommended_action": _RECOMMENDED.get(category, _RECOMMENDED["unknown"]),
    }
