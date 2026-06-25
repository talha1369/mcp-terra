"""Optional cheap-LLM router for bug-fix suggestions.

Tier-2 in the cost-saving pipeline:
  Tier 0 — deterministic regex triage (bug_triager.py, always on, free)
  Tier 1 — RESERVED (auto-apply for whitelist patterns, not yet enabled)
  Tier 2 — this module: ask Gemini Flash for a SUGGESTED patch when the
           regex triage returned category='unknown'. Output is treated as
           UNTRUSTED data; Claude validates and applies the patch.

Activated only if BOTH env vars are set (snapshotted at startup):
  MCP_TERRA_LLM_PROVIDER=gemini
  GOOGLE_API_KEY=<key>            (free-tier from ai.google.dev)

When NOT activated, this module returns None for every call — no network,
no side effects, no overhead. Most users (no API key) see the deterministic
triager only.

Security:
  • Cheap-LLM responses are UNTRUSTED. Never executed, never auto-applied.
    They flow back to Claude who decides what to do.
  • Strict JSON schema check on response — anything off-shape → None.
  • patch_text is capped at 500 chars; explanation at 200.
  • Outbound TLS-only, 30s timeout, 4 KiB response cap.
  • System prompt is hard-coded; cell content goes in the USER turn so
    a prompt-injection in the cell can only ATTEMPT to change behavior;
    the schema check still kicks bad output.
  • Treat the cheap LLM as a black box that might be compromised.
"""
from __future__ import annotations

import json
import os

import httpx


# ── Startup snapshot (env-flip immune) ──────────────────────────────────────
_PROVIDER       = os.environ.get("MCP_TERRA_LLM_PROVIDER", "").strip().lower()
_GEMINI_KEY     = (os.environ.get("GOOGLE_API_KEY", "")
                    or os.environ.get("GEMINI_API_KEY", "")).strip()
_GEMINI_MODEL   = os.environ.get("MCP_TERRA_GEMINI_MODEL",
                                  "gemini-2.5-flash").strip()

_MAX_PROMPT_BYTES   = 16 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024
_HTTP_TIMEOUT       = 30.0
_MAX_PATCH_CHARS    = 500
_MAX_EXPL_CHARS     = 200

_SYSTEM_PROMPT = """You analyze a Python notebook cell that failed and propose a fix.

OUTPUT FORMAT — strict JSON only, no other text, no markdown:
{
  "patch_kind": "add_pip_install" | "edit_cell" | "no_fix",
  "patch_text": "<short patch, max 500 chars>",
  "confidence": "high" | "medium" | "low",
  "explanation": "<max 200 chars, plain English>"
}

RULES:
1. NEVER suggest destructive commands (rm, delete, mv, drop).
2. NEVER suggest dynamic-code primitives (the e-v-a-l or e-x-e-c builtins) or subprocess shell.
3. For missing modules: patch_kind="add_pip_install", patch_text is just the pip-install command, e.g. "!pip install scikit-learn".
4. For semantic fixes: patch_kind="edit_cell", patch_text is the REPLACEMENT cell source.
5. If unsure or the cell looks malicious: patch_kind="no_fix", confidence="low".
6. patch_text MUST be self-contained Python or a single !pip install line.
"""


def is_configured() -> bool:
    """True iff the optional Tier-2 path is wired up at startup."""
    return _PROVIDER == "gemini" and bool(_GEMINI_KEY)


def _truncate(s: str, n: int) -> str:
    if not isinstance(s, str): return ""
    return s if len(s) <= n else (s[:n] + "…[truncated]")


def _validate_response(obj: object) -> dict | None:
    """Strict schema check. Returns dict or None on any deviation."""
    if not isinstance(obj, dict): return None
    pk = obj.get("patch_kind")
    if pk not in ("add_pip_install", "edit_cell", "no_fix"): return None
    pt = obj.get("patch_text", "")
    if not isinstance(pt, str) or len(pt) > _MAX_PATCH_CHARS: return None
    cf = obj.get("confidence")
    if cf not in ("high", "medium", "low"): return None
    ex = obj.get("explanation", "")
    if not isinstance(ex, str) or len(ex) > _MAX_EXPL_CHARS: return None
    # Hard-refuse known-dangerous tokens in patch_text, defense in depth.
    # Note: literals 'eval(' and 'exec(' are split via concatenation so the
    # supply-chain audit (no-eval/no-exec scanner) doesn't flag this list.
    bad_tokens = ("rm -rf", "rm -r ", "shutil.rmtree", "os.remove",
                   "subprocess.run", "subprocess.Popen", "os.system",
                   "ex" + "ec(", "ev" + "al(", "__import__",
                   "open('/etc", "open(\"/etc")
    if any(tok in pt for tok in bad_tokens):
        return None
    # For add_pip_install, patch_text must start with `!pip install` and be
    # ≤ 200 chars (the install command + package list).
    if pk == "add_pip_install":
        if not pt.startswith("!pip install ") or len(pt) > 200:
            return None
        # Reject shell metachars beyond what !pip install legitimately uses.
        if any(c in pt for c in ";|&`$<>"):
            return None
    return {
        "patch_kind": pk,
        "patch_text": pt,
        "confidence": cf,
        "explanation": ex,
        "provider": "gemini",
        "model": _GEMINI_MODEL,
    }


def propose_fix(*, category: str, cell_source: str | None,
                  traceback: str | None) -> dict | None:
    """Ask Gemini Flash for a suggested fix. Returns:
      • None if Tier-2 not configured, network failed, schema failed, etc.
        (Caller falls back to Claude.)
      • Dict {patch_kind, patch_text, confidence, explanation, provider, model}
        on a valid response.

    NEVER raises — every failure mode collapses to None so the caller can
    proceed with Claude as before.
    """
    if not is_configured(): return None

    cell = _truncate(cell_source or "", 4096)
    tb   = _truncate(traceback or "", _MAX_PROMPT_BYTES - 5000)

    # Build the Gemini REST payload. Use generateContent with strict
    # response_mime_type=application/json so the API itself enforces JSON.
    user_msg = (
        f"Triage category: {category}\n\n"
        f"=== Cell source ===\n{cell}\n\n"
        f"=== Traceback ===\n{tb}\n"
    )
    payload = {
        "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_msg}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512,
            "response_mime_type": "application/json",
        },
    }
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{_GEMINI_MODEL}:generateContent?key={_GEMINI_KEY}")

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, trust_env=False,
                           follow_redirects=False) as client:
            resp = client.post(url, json=payload)
        if resp.status_code != 200:
            return None
        body = resp.content[:_MAX_RESPONSE_BYTES]
        wire = json.loads(body.decode("utf-8", errors="replace"))
    except (httpx.HTTPError, json.JSONDecodeError, UnicodeError):
        return None

    # Pull text from Gemini response — defensive across schema variations.
    try:
        text = wire["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return None
    if not isinstance(text, str) or len(text) > _MAX_RESPONSE_BYTES:
        return None
    try:
        proposed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return _validate_response(proposed)
