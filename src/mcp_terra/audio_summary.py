"""Audio summary helper — Google Cloud Text-to-Speech via gcloud OAuth.

Renders agent-drafted, verifier-approved summary TEXT to .mp3 bytes.
Uses the same gcloud Application Default Credentials as the rest of the
MCP — no new API key required. The user enables the TTS API ONCE:

    gcloud services enable texttospeech.googleapis.com

(Rationale: a Gemini-TTS variant exists and matches the NVIDIA + Google
Cloud drug-discovery lab the user admires, but it requires a Gemini API
key not every collaborator will have. Cloud TTS reuses the gcloud auth
that's already mandatory for the MCP — universal portability.)

Hallucination defense lives UPSTREAM: this module ONLY renders. The
agent + verifier sub-agent must approve the text before calling here.
This module trusts only:

  • Text fits the cap (≤ 4000 chars ≈ ~3 min audio)
  • Text contains no shell/script smuggling (sanitize_output applied)
  • Text contains no OAuth-token shape — checked raw, AFTER NFKC normalize,
    AND after confusable folding (defeats full-width AND Cyrillic/Greek
    homoglyph bypass; NFKC alone does not fold cross-script look-alikes)

If those pass, the text ships to Cloud TTS and the returned bytes are
returned. On ANY failure, raises AudioSummaryError — never returns
silently bad audio.
"""
from __future__ import annotations

import base64
import json
import os
import re
import unicodedata

import httpx

from . import auth, safety, secret_scan


class AudioSummaryError(RuntimeError):
    """Raised when synthesis refuses or fails. Carries no auth secret."""


_MAX_TEXT_CHARS   = 4000
_MIN_TEXT_CHARS   = 50
_HTTP_TIMEOUT     = 60.0
_MAX_AUDIO_BYTES  = 8 * 1024 * 1024

_YA29_RE = re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}")

_TTS_URL = "https://texttospeech.googleapis.com/v1/text:synthesize"


def is_configured() -> bool:
    """True iff gcloud auth is usable. Cloud TTS reuses it (no separate key)."""
    try:
        auth.get_access_token()
        return True
    except auth.AuthError:
        return False


def _nfkc_check_token_shape(text: str) -> None:
    """Refuse if text contains ya29.* in raw, NFKC-normalized, OR
    confusable-folded form.

    NFKC folds full-width / ligature variants; confusable folding additionally
    maps Cyrillic/Greek look-alikes (у/а/е/о/с/х …) to ASCII. Together they
    defeat homoglyph smuggling, where a raw substring match would miss but the
    visual rendering is identical to a real OAuth token.
    """
    for variant in (text,
                    unicodedata.normalize("NFKC", text),
                    secret_scan.fold_confusables(text)):
        if _YA29_RE.search(variant):
            raise AudioSummaryError(
                "summary_text contains ya29.* OAuth-token shape "
                "(raw / Unicode-normalized / de-homoglyphed) — refusing."
            )


def _validate_text(text: str) -> None:
    if not isinstance(text, str):
        raise AudioSummaryError(
            f"summary_text must be str; got {type(text).__name__}"
        )
    if not (_MIN_TEXT_CHARS <= len(text) <= _MAX_TEXT_CHARS):
        raise AudioSummaryError(
            f"summary_text length {len(text)} outside "
            f"{_MIN_TEXT_CHARS}..{_MAX_TEXT_CHARS}"
        )
    if "\r" in text:
        raise AudioSummaryError("summary_text contains CR (refusing).")
    _nfkc_check_token_shape(text)
    # Full secret scan before this text leaves via TTS / persisted audio — the
    # ya29 check above only covers Google OAuth tokens. Scan raw, NFKC-normalized,
    # AND confusable-folded forms (homoglyph defense), fail closed on ANY hit
    # (AWS keys, GitHub PATs, Slack tokens, PEM private keys, …).
    # (security review high finding.)
    hits = secret_scan.scan_bytes(text.encode("utf-8"), "audio-summary")
    for _tag, _variant in (
        ("nfkc", unicodedata.normalize("NFKC", text)),
        ("folded", secret_scan.fold_confusables(text)),
    ):
        if _variant != text:
            hits = hits + secret_scan.scan_bytes(_variant.encode("utf-8"),
                                                 f"audio-summary-{_tag}")
    if hits:
        raise AudioSummaryError(
            f"summary_text contains {len(hits)} secret-shaped value(s); "
            f"refusing to render/persist audio (no secret exfil via TTS).")


def synthesize(text: str, *, voice_name: str = "en-US-Studio-O",
                language_code: str = "en-US",
                speaking_rate: float = 1.0,
                quota_project: str = "") -> bytes:
    """Render `text` to MP3 bytes via Google Cloud TTS.

    Args:
        text: agent-drafted, verifier-approved summary.
        voice_name: Cloud TTS voice id (Studio voices are highest quality).
                    Examples: en-US-Studio-O (female), en-US-Studio-Q (male),
                    en-US-Neural2-J (neural), en-US-Wavenet-D.
        language_code: BCP-47 (e.g. 'en-US').
        speaking_rate: 0.25–4.0; default 1.0.

    Returns:
        Raw .mp3 bytes (≤ _MAX_AUDIO_BYTES).

    Raises:
        AudioSummaryError on any failure. Always raises — never returns
        silently malformed audio.
    """
    voice_name = voice_name or "en-US-Studio-O"   # coerce None/"" to a valid Studio voice
    _validate_text(text)
    # sanitize_output strips C0/C1 control chars + injection markers, then
    # we ship that to the TTS provider — same defense the email tool uses.
    safe_text = safety.sanitize_output(text)

    try:
        token = auth.get_access_token()
    except auth.AuthError as e:
        raise AudioSummaryError(
            f"cannot get gcloud OAuth token for TTS: {e}. Run "
            f"`gcloud auth application-default login` and retry."
        )

    payload = {
        "input":       {"text": safe_text},
        "voice":       {"languageCode": language_code, "name": voice_name},
        "audioConfig": {"audioEncoding": "MP3",
                        "speakingRate": float(speaking_rate)},
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    # Cloud TTS with user credentials needs a quota/billing project or it 403s
    # ("requires a quota project, which is not set by default"). Prefer the
    # explicit arg, then MCP_TERRA_TTS_QUOTA_PROJECT; else omit (best-effort).
    _qp = quota_project or os.environ.get("MCP_TERRA_TTS_QUOTA_PROJECT", "")
    if _qp:
        headers["X-Goog-User-Project"] = _qp

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, trust_env=False,
                           follow_redirects=False) as client:
            resp = client.post(_TTS_URL, headers=headers, json=payload)
    except httpx.HTTPError as e:
        raise AudioSummaryError(f"TTS network error: {type(e).__name__}: {e}")

    # Never leak the bearer token in error tails.
    def _redact(s: str) -> str:
        return s.replace(token, "[REDACTED_BEARER]")

    if resp.status_code == 403:
        raise AudioSummaryError(
            "TTS API returned 403. Enable the API once: "
            "`gcloud services enable texttospeech.googleapis.com` and retry."
        )
    if resp.status_code != 200:
        raise AudioSummaryError(
            f"TTS HTTP {resp.status_code}: {_redact(resp.text[:200])}"
        )

    try:
        body = json.loads(resp.content[:_MAX_AUDIO_BYTES + 1024])
        b64  = body.get("audioContent", "")
        if not isinstance(b64, str) or not b64:
            raise AudioSummaryError("TTS returned empty audioContent")
        audio = base64.b64decode(b64)
    except (json.JSONDecodeError, ValueError) as e:
        raise AudioSummaryError(f"TTS response parse: {e}")

    if len(audio) > _MAX_AUDIO_BYTES:
        raise AudioSummaryError(
            f"TTS returned {len(audio)} bytes (> {_MAX_AUDIO_BYTES} cap)"
        )
    if len(audio) < 100:
        raise AudioSummaryError(
            f"TTS returned suspiciously short audio ({len(audio)} bytes)"
        )
    return audio


# ── Local fallback: macOS `say` (no cloud, no IAM) ──────────────────────────

def say_available() -> bool:
    """True iff the macOS `say` command is usable (darwin + on PATH)."""
    import shutil
    import sys
    return sys.platform == "darwin" and shutil.which("say") is not None


def synthesize_say(text: str, *, voice: str = "") -> bytes:
    """Render `text` to .m4a (AAC) bytes using the macOS `say` command.

    A zero-dependency local fallback when Cloud TTS isn't authorized: no API,
    no IAM, no network. Same text-safety gate as the cloud path. The text is
    passed to `say` as an ARGV element (never via a shell), so it cannot inject
    a command. Returns m4a bytes.
    """
    import shutil
    import subprocess
    import sys
    import tempfile

    _validate_text(text)
    safe_text = safety.sanitize_output(text)
    if sys.platform != "darwin":
        raise AudioSummaryError("macOS `say` backend is only available on macOS")
    say_bin = shutil.which("say")
    if not say_bin:
        raise AudioSummaryError("`say` not found on PATH")

    fd, tmp = tempfile.mkstemp(prefix="mcp_say_", suffix=".m4a")
    os.close(fd)
    try:
        # SECURITY (security review): never put the summary TEXT in argv — argv is
        # world-readable via `ps`/process accounting on a multi-user host, so a
        # controlled-data summary in argv would be an egress path even with the
        # local backend. `say` reads the text to speak from STDIN when no string
        # operand is given, so we feed it via stdin and keep argv to flags only
        # (output path + voice name — neither is sensitive).
        args = [say_bin, "-o", tmp]
        if voice:
            args += ["-v", voice]
        try:
            r = subprocess.run(args, input=safe_text.encode("utf-8"),
                               capture_output=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            raise AudioSummaryError("`say` timed out")
        if r.returncode != 0:
            raise AudioSummaryError(
                f"`say` failed (rc {r.returncode}): "
                f"{r.stderr.decode('utf-8', 'replace')[:200]}")
        with open(tmp, "rb") as fh:
            audio = fh.read()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    if len(audio) < 100:
        raise AudioSummaryError(
            f"`say` produced suspiciously short audio ({len(audio)} bytes)")
    if len(audio) > _MAX_AUDIO_BYTES:
        raise AudioSummaryError(
            f"`say` produced {len(audio)} bytes (> {_MAX_AUDIO_BYTES} cap)")
    return audio


def render(text: str, *, voice_name: str = "", quota_project: str = "",
           backend: str = "auto") -> tuple[bytes, str, str]:
    """Render audio, choosing a backend. Returns (audio_bytes, ext, backend_used).

    backend:
      • 'auto'  — try Cloud TTS (Studio quality); on ANY failure (e.g. the IAM
                  403), fall back to macOS `say` when available.
      • 'cloud' — Cloud TTS only (raises if unavailable).
      • 'say'   — macOS `say` only (local).
    """
    backend = (backend or "auto").lower()
    if backend == "say":
        return synthesize_say(text), "m4a", "macos-say"
    if backend == "cloud":
        return (synthesize(text, voice_name=voice_name or None,
                           quota_project=quota_project), "mp3", "cloud-tts")
    # auto
    try:
        return (synthesize(text, voice_name=voice_name or None,
                           quota_project=quota_project), "mp3", "cloud-tts")
    except AudioSummaryError:
        if say_available():
            return synthesize_say(text), "m4a", "macos-say"
        raise
