"""Internet-fetch helper with hard-coded domain allowlist.

The MCP CAN reach the network — Terra API calls already do. This module
adds a tool-callable fetch for getting Hail Batch code examples, Terra
docs, and other STATIC reference content from a small set of trusted
domains. NOT for arbitrary scraping.

Security posture:
  • DOMAIN ALLOWLIST: hardcoded list of known Terra / Hail / official-source
    hostnames. Subdomain matches only after a label boundary (so
    `evil.terra.bio.attacker.com` does NOT match `terra.bio`).
  • HTTPS-only: refuse plain http:// (which is MITM-friendly).
  • No redirects: defense against open-redirect-to-attacker-domain.
  • Response size capped at 5 MB so an attacker can't drain memory.
  • Response runs through `safety.sanitize_output` — same prompt-injection
    redaction the LLM-facing tools use.
  • No cookies / no `trust_env=True` → no proxy hijack, no shared session
    state, no auth header leakage.
  • The fetch tool is WRITE_SAFE in the MCP action-class hierarchy: gated by
    `MCP_TERRA_ALLOW_WRITES=1`. Per-call Claude Code permission prompts
    apply on top of this.
"""
from __future__ import annotations

import urllib.parse
from typing import Iterable

import httpx

from . import safety


# Domain allowlist. Add new hostnames here knowingly.
#   • Suffix match: an allowed entry "terra.bio" matches "terra.bio" itself
#     AND any subdomain like "leonardo.dsde-prod.terra.bio". The match is on
#     LABEL boundary, so "terra.bio.attacker.com" is NOT a match.
#   • HTTPS-only is enforced separately.
_ALLOWED_DOMAINS: tuple[str, ...] = (
    # Terra services
    "terra.bio",
    "dsde-prod.broadinstitute.org",
    "broadinstitute.org",
    # Hail (batch, docs)
    "hail.is",
    "batch.hail.is",
    # Source-of-truth code repos
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    # Google APIs (used by gsutil/Hail Batch under the hood)
    "googleapis.com",
)

# 5 MB cap on any fetched response. Bigger payloads are refused with a
# loud error rather than streamed.
_MAX_FETCH_BYTES = 5 * 1024 * 1024


class FetchError(RuntimeError):
    """Raised when the fetch tool refuses a URL or the response is bad."""


def _is_allowed_host(host: str, allowlist: Iterable[str]) -> bool:
    """Suffix-match host against the allowlist on label boundaries."""
    h = host.lower().strip(".")
    for entry in allowlist:
        e = entry.lower().strip(".")
        if h == e or h.endswith("." + e):
            return True
    return False


def fetch_url(url: str, *, max_bytes: int = _MAX_FETCH_BYTES,
              timeout: float = 30.0) -> str:
    """Fetch a URL from the domain allowlist. Returns sanitized text.

    Raises FetchError on:
      • non-HTTPS URL
      • host not in allowlist
      • response > max_bytes
      • non-2xx HTTP status

    Always:
      • HTTPS only (refuses http://, file://, gopher://, etc.)
      • No redirects (any 3xx is a refusal — defends against
        open-redirect-to-attacker-domain).
      • trust_env=False (no HTTPS_PROXY / NO_PROXY)
    """
    if not isinstance(url, str) or not url:
        raise FetchError("url must be a non-empty string")
    if len(url) > 4096:
        raise FetchError(f"url too long ({len(url)} chars; max 4096)")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise FetchError(
            f"only https:// URLs allowed; got scheme {parsed.scheme!r}. "
            f"This MCP refuses http:// (MITM-friendly), file://, and any "
            f"other scheme."
        )
    if not parsed.hostname:
        raise FetchError(f"url has no hostname: {url!r}")
    if not _is_allowed_host(parsed.hostname, _ALLOWED_DOMAINS):
        raise FetchError(
            f"host {parsed.hostname!r} is NOT in the MCP fetch allowlist. "
            f"Allowed (suffix-match): {sorted(_ALLOWED_DOMAINS)}. "
            f"Refusing — extend safety.fetch._ALLOWED_DOMAINS only after "
            f"explicit user consent."
        )
    # No userinfo, no fragments-as-control. Strip both.
    if parsed.username or parsed.password:
        raise FetchError("url must not embed user:password credentials")

    # Stream the body so an oversized response is terminated EARLY rather
    # than fully buffered before the cap check (which would defeat the cap
    # on a hostile allowlisted endpoint streaming gigabytes).
    chunks: list[bytes] = []
    accumulated = 0
    with httpx.Client(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        with client.stream("GET", url) as resp:
            if 300 <= resp.status_code < 400:
                raise FetchError(
                    f"HTTP {resp.status_code} from {url!r}. The MCP refuses "
                    f"redirects (any 3xx) to defeat open-redirect attacks. "
                    f"Re-issue against the final URL directly."
                )
            if not (200 <= resp.status_code < 300):
                # Read up to 200 bytes for the error tail
                preview = b""
                for chunk in resp.iter_bytes(chunk_size=200):
                    preview = chunk
                    break
                raise FetchError(
                    f"HTTP {resp.status_code} from {url!r}: "
                    f"{preview[:200].decode('utf-8', errors='replace')!r}"
                )
            for chunk in resp.iter_bytes(chunk_size=8192):
                accumulated += len(chunk)
                if accumulated > max_bytes:
                    raise FetchError(
                        f"response from {url!r} exceeds cap ({max_bytes} bytes) "
                        f"mid-stream; aborted at ~{accumulated} bytes."
                    )
                chunks.append(chunk)
    body = b"".join(chunks)
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = body.decode("latin-1", errors="replace")
    # Apply the standard output sanitization (prompt-injection markers,
    # control-char stripping, length cap) before returning to the LLM.
    return safety.sanitize_output(text)
