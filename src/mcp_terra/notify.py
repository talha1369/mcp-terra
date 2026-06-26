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

# Bot-token path (true file upload — webhooks can't upload files). Each user /
# collaborator sets their OWN token + channel; snapshotted at startup.
_SLACK_BOT_TOKEN = os.environ.get("MCP_TERRA_SLACK_BOT_TOKEN", "").strip()
_SLACK_CHANNEL = os.environ.get("MCP_TERRA_SLACK_CHANNEL", "").strip()
_SLACK_API = "https://slack.com/api"
_MAX_SLACK_UPLOAD_BYTES = 50 * 1024 * 1024


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


# ── Slack bot-token file upload (true attachment; webhooks can't upload) ─────

def slack_bot_configured() -> bool:
    """True iff a Slack BOT token + channel are set (a real file upload is
    possible). Distinct from the webhook (text-only) path."""
    return bool(_SLACK_BOT_TOKEN and _SLACK_CHANNEL)


def _slack_json(resp: httpx.Response) -> dict:
    try:
        return resp.json()
    except ValueError:
        raise NotifyError(f"Slack API returned non-JSON (HTTP {resp.status_code})")


def slack_upload_file(data: bytes, *, filename: str, title: str = "",
                      initial_comment: str = "") -> dict:
    """Upload a file to the configured Slack channel via the Web API
    (files.getUploadURLExternal -> PUT bytes -> files.completeUploadExternal).

    Returns {uploaded, transport, file_id} on success, or {uploaded: False,
    reason} when no bot token/channel is configured. Raises NotifyError on a
    refused/failed upload. The bot token is a bearer secret — it is never
    echoed in an error (Slack error bodies carry an error CODE, not the token).
    """
    if not slack_bot_configured():
        return {"uploaded": False,
                "reason": "MCP_TERRA_SLACK_BOT_TOKEN / MCP_TERRA_SLACK_CHANNEL not set"}
    if not data:
        raise NotifyError("file is empty")
    if len(data) > _MAX_SLACK_UPLOAD_BYTES:
        raise NotifyError(
            f"file too large for Slack ({len(data)} bytes; cap {_MAX_SLACK_UPLOAD_BYTES})")
    # Defense in depth: never push a credential into a chat channel via the
    # message comment (the binary file itself is content-type-locked by caller).
    if initial_comment:
        hits = secret_scan.scan_bytes(initial_comment.encode("utf-8"),
                                      "slack-upload-comment")
        if hits:
            raise NotifyError(
                f"refusing Slack upload: comment matched {len(hits)} "
                f"secret-shaped pattern(s)")
    safe_name = os.path.basename(str(filename)) or "attachment"
    headers = {"Authorization": f"Bearer {_SLACK_BOT_TOKEN}"}
    try:
        with httpx.Client(timeout=60.0, trust_env=False,
                          follow_redirects=False) as client:
            # 1) reserve an upload URL
            r1 = client.post(f"{_SLACK_API}/files.getUploadURLExternal",
                             headers=headers,
                             data={"filename": safe_name, "length": str(len(data))})
            j1 = _slack_json(r1)
            if not j1.get("ok"):
                raise NotifyError(f"Slack getUploadURLExternal: {j1.get('error', 'unknown')}")
            upload_url = j1.get("upload_url")
            file_id = j1.get("file_id")
            if not upload_url or not file_id:
                raise NotifyError("Slack getUploadURLExternal: missing upload_url/file_id")
            # 2) PUT the bytes to the reserved URL
            r2 = client.post(upload_url, files={"file": (safe_name, bytes(data))})
            if r2.status_code != 200:
                raise NotifyError(f"Slack file byte upload failed: HTTP {r2.status_code}")
            # 3) finalize + share into the channel
            payload: dict = {"files": [{"id": file_id, "title": title or safe_name}],
                             "channel_id": _SLACK_CHANNEL}
            if initial_comment:
                payload["initial_comment"] = initial_comment
            r3 = client.post(f"{_SLACK_API}/files.completeUploadExternal",
                             headers=headers, json=payload)
            j3 = _slack_json(r3)
            if not j3.get("ok"):
                raise NotifyError(f"Slack completeUploadExternal: {j3.get('error', 'unknown')}")
    except httpx.HTTPError as e:
        raise NotifyError(f"Slack upload network error: {type(e).__name__}")
    return {"uploaded": True, "transport": "slack-bot-files", "file_id": file_id}


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
