"""Terra auth helper — Application Default Credentials (gcloud).

Strategy: shell out to `gcloud auth application-default print-access-token` to
get a fresh OAuth2 access token. This works with any gcloud-authenticated user
account or service account on the host machine — collaborators just need
`gcloud auth login` (or service-account ADC) one-time set up.

We deliberately don't cache tokens — gcloud caches them itself and rotates as
needed, so a fresh subprocess call gets a valid one.
"""
from __future__ import annotations

import os
import shutil
import subprocess


class AuthError(RuntimeError):
    """Raised when we cannot obtain a Terra-usable access token."""


# Common gcloud install locations. Searched ONLY if `shutil.which("gcloud")`
# fails — covers the case where Claude Code (or any MCP client) was launched
# from a GUI on macOS with a stripped PATH, so the user's shell PATH never
# reached the MCP subprocess. We do not auto-install or modify anything.
_GCLOUD_FALLBACK_PATHS = (
    "/opt/homebrew/bin/gcloud",
    "/usr/local/bin/gcloud",
    "/usr/bin/gcloud",
    os.path.expanduser("~/google-cloud-sdk/bin/gcloud"),
    os.path.expanduser("~/Downloads/google-cloud-sdk/bin/gcloud"),
    os.path.expanduser("~/.local/google-cloud-sdk/bin/gcloud"),
    "/snap/bin/gcloud",   # linux snap
)


def _find_gcloud() -> str | None:
    """Return an absolute path to gcloud, or None. Tries PATH first, then
    a small fixed list of common install locations. Never executes — only
    stat-checks for executable presence.
    """
    p = shutil.which("gcloud")
    if p:
        return p
    for cand in _GCLOUD_FALLBACK_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def get_access_token() -> str:
    """Return a fresh Google OAuth2 access token from gcloud ADC.

    Raises AuthError with a clear remediation message if gcloud is missing,
    ADC is not set up, or the token retrieval fails. We never silently fall
    back to anything — Terra calls without a valid token would just 401.
    """
    gcloud = _find_gcloud()
    if gcloud is None:
        raise AuthError(
            "`gcloud` CLI not found on PATH or in common install locations "
            "(/opt/homebrew/bin, /usr/local/bin, ~/google-cloud-sdk/bin, …). "
            "Install Google Cloud SDK (https://cloud.google.com/sdk) and run "
            "`gcloud auth application-default login` as the user who has "
            "Terra access. If gcloud IS installed, add its bin dir to the "
            "MCP server's PATH env in ~/.claude/settings.json."
        )
    try:
        out = subprocess.run(
            [gcloud, "auth", "application-default", "print-access-token"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except subprocess.TimeoutExpired:
        raise AuthError("gcloud token fetch timed out after 15s.")
    except subprocess.CalledProcessError as e:
        raise AuthError(
            f"gcloud token fetch failed (exit {e.returncode}). stderr: "
            f"{(e.stderr or '').strip()[:300]}\n"
            "Run `gcloud auth application-default login` and retry."
        )
    token = out.stdout.strip()
    if not token or not token.startswith("ya29."):
        raise AuthError(
            f"gcloud returned an unexpected token format ({token[:20]!r}…). "
            "Re-run `gcloud auth application-default login`."
        )
    return token


def get_user_email() -> str:
    """Return the active gcloud account email (for logging / audit trail)."""
    gcloud = _find_gcloud()
    if gcloud is None:
        raise AuthError("`gcloud` CLI not found on PATH or fallback locations.")
    try:
        out = subprocess.run(
            [gcloud, "config", "get-value", "account"],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except subprocess.CalledProcessError as e:
        raise AuthError(f"gcloud config get-value account failed: {e.stderr}")
    email = out.stdout.strip()
    if not email or "@" not in email:
        raise AuthError(f"gcloud returned no active account email (got {email!r}).")
    return email
