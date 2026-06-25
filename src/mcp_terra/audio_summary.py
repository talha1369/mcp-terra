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
  • Text contains no OAuth-token shape — checked AFTER NFKC normalize
    (defeats Cyrillic / full-width homoglyph bypass)

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

from . import auth, safety


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
    """Refuse if text contains ya29.* in raw OR NFKC-normalized form.

    Defeats Cyrillic-у/а or full-width-y/a homoglyph smuggling, where a
    raw substring match would miss but the visual rendering is identical
    to a real OAuth token.
    """
    if _YA29_RE.search(text):
        raise AudioSummaryError(
            "summary_text contains ya29.* OAuth-token shape (refusing)."
        )
    normalized = unicodedata.normalize("NFKC", text)
    if _YA29_RE.search(normalized):
        raise AudioSummaryError(
            "summary_text contains ya29.* OAuth-token shape after Unicode "
            "normalization (homoglyph smuggling refused)."
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
