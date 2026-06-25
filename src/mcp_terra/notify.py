"""Slack completion-ping channel.

A second delivery channel alongside email: on run completion, post a compact
report (outcome, bugs fixed, key results, artifact links) to a Slack channel.

Security posture (mirrors the email recipient-lock):
  • The webhook URL is read ONCE from MCP_TERRA_SLACK_WEBHOOK at import (a
    startup snapshot, immune to mid-session env hijack). The agent CANNOT pass
    an arbitrary URL — this prevents the notify tool from becoming an
    exfiltration/SSRF primitive.
  • The URL must be https://hooks.slack.com/... (host-locked; defense in depth).
  • The outbound payload is secret-scanned before send — a token/key/password
    shape refuses the send (no leaking secrets into a chat channel).
  • httpx with trust_env=False and follow_redirects=False (no proxy hijack, no
    open-redirect to an attacker host). The webhook URL is never echoed in an
    error (it is itself a bearer secret).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from urllib.parse import urlparse

import httpx

from . import secret_scan

_SLACK_WEBHOOK = os.environ.get("MCP_TERRA_SLACK_WEBHOOK", "").strip()
_SLACK_HOST = "hooks.slack.com"


class NotifyError(Exception):
    """Raised on a refused or failed notification."""


def slack_configured() -> bool:
    """True iff a Slack webhook is configured (a real send is possible)."""
    return bool(_SLACK_WEBHOOK)


def _validate_webhook(url: str) -> None:
    u = urlparse(url)
    if u.scheme != "https" or (u.hostname or "").lower() != _SLACK_HOST:
        # Do NOT echo the URL — it is a bearer secret.
        raise NotifyError(
            "MCP_TERRA_SLACK_WEBHOOK must be an https://hooks.slack.com/... URL")


def send_slack(text: str, blocks: list | None = None) -> dict:
    """Post a message to the configured Slack webhook.

    Returns {sent, transport} on success, or {sent: False, reason} when no
    webhook is configured. Raises NotifyError on a refused/failed send.
    """
    if not _SLACK_WEBHOOK:
        return {"sent": False, "reason": "MCP_TERRA_SLACK_WEBHOOK not set"}
    _validate_webhook(_SLACK_WEBHOOK)

    if not text or not text.strip():
        raise NotifyError("Slack message text is empty")
    if len(text) > 40000:
        raise NotifyError(f"Slack message too long ({len(text)} chars; cap 40000)")

    body: dict = {"text": text}
    if blocks:
        body["blocks"] = blocks

    # Defense in depth: never push a credential into a chat channel.
    hits = secret_scan.scan_bytes(
        json.dumps(body).encode("utf-8"), "slack-message")
    if hits:
        raise NotifyError(
            f"refusing to send Slack message: outbound payload matched "
            f"{len(hits)} secret-shaped pattern(s)")

    try:
        with httpx.Client(timeout=15.0, trust_env=False,
                          follow_redirects=False) as client:
            resp = client.post(_SLACK_WEBHOOK, json=body)
    except httpx.HTTPError as e:
        raise NotifyError(f"Slack post failed: {type(e).__name__}")

    # Slack incoming-webhooks reply with 200 + body "ok".
    if resp.status_code != 200 or resp.text.strip().lower() != "ok":
        raise NotifyError(
            f"Slack post rejected: HTTP {resp.status_code} {resp.text[:150]!r}")
    return {"sent": True, "transport": "slack-webhook"}


# ── macOS Notification Center (local, no network) ───────────────────────────

# AppleScript run once with argv passed as PARAMETERS — the title/message are
# never interpolated into the script source, so they cannot inject AppleScript.
_OSA_SCRIPT = (
    "on run {t, m, s}\n"
    "  if s is \"\" then\n"
    "    display notification m with title t\n"
    "  else\n"
    "    display notification m with title t subtitle s\n"
    "  end if\n"
    "end run"
)


def macos_notifications_available() -> bool:
    """True iff a macOS desktop notification can be posted (darwin + osascript)."""
    return sys.platform == "darwin" and shutil.which("osascript") is not None


def _clean_notif(s: str, n: int) -> str:
    """Strip control chars (incl. newlines) and cap length for a notification."""
    cleaned = "".join(ch for ch in (s or "") if 0x20 <= ord(ch) and ord(ch) != 0x7f)
    return cleaned[:n]


def send_macos_notification(title: str, message: str, *, subtitle: str = "") -> dict:
    """Post a macOS Notification Center alert. Local only — no network, no data.

    Returns {sent, transport} on success, {sent: False, reason} off-macOS or if
    osascript is missing. Raises NotifyError on an osascript failure. Strings
    are control-char-stripped, length-capped, and passed to osascript as ARGV
    (never interpolated → no AppleScript injection).
    """
    if sys.platform != "darwin":
        return {"sent": False, "reason": "macOS notifications only available on darwin"}
    osa = shutil.which("osascript")
    if not osa:
        return {"sent": False, "reason": "osascript not found on PATH"}

    t = _clean_notif(title, 120) or "mcp-terra"
    m = _clean_notif(message, 500)
    s = _clean_notif(subtitle, 200)
    if not m:
        raise NotifyError("notification message is empty after sanitization")
    try:
        r = subprocess.run([osa, "-e", _OSA_SCRIPT, t, m, s],
                           capture_output=True, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        raise NotifyError("osascript timed out")
    if r.returncode != 0:
        raise NotifyError(
            f"osascript failed (rc {r.returncode}): "
            f"{r.stderr.decode('utf-8', 'replace')[:200]}")
    return {"sent": True, "transport": "macos-notification"}
