# mcp-terra — authentication & credential posture

For a security reviewer: how the MCP authenticates, what credentials it touches,
and what it deliberately does not do.

## Identity & tokens

- **The MCP uses the user's existing gcloud Application Default Credentials
  (ADC)** — the same login the user already has for `gcloud`/`gsutil`. It does
  **not** prompt for, store, or mint credentials of its own.
- Terra access tokens are obtained on demand from gcloud
  (`auth.get_access_token()`); they are **never written to disk, logs, or tool
  output**. `_ok()` defensively refuses to return any payload that contains the
  in-flight token, and `terra_client._request` redacts the token (and the runner
  HMAC secret) from any echoed error body.
- The MCP runs at the privilege of the user's ADC — it cannot do anything the
  user could not already do with `gcloud`. It is a **safety-gated narrowing** of
  that surface (no delete, no overwrite, workspace lock, writes-gate, …), not an
  escalation.

## Per-channel secrets (all env-snapshot at startup, never in chat)

| Secret | Env var | Scope / lock |
|---|---|---|
| Runner HMAC secret | `MCP_TERRA_RUNNER_SECRET` | signs job specs + heartbeats; delivered to the VM via Leonardo `customEnvironmentVariables`, never GCS/argv/logs |
| SMTP app password | `MCP_TERRA_SMTP_PASS` | send-only; recipient hard-locked to the auth'd user |
| Slack bot token | `MCP_TERRA_SLACK_BOT_TOKEN` | `files:write`/`im:write`; targets env-locked (`MCP_TERRA_SLACK_CHANNEL`); never echoed in errors |
| Slack webhook | `MCP_TERRA_SLACK_WEBHOOK` | host-locked to `hooks.slack.com`; no `url` tool param |

All are read **once at process start** (snapshot), so flipping an env var
mid-session has no effect — a defense against mid-session env hijack. Provide
them via a terminal `getpass` write to `~/.claude.json`, never pasted in chat.

## What the MCP does NOT do

- No OAuth client registration / token minting (Terra whitelists OIDC client
  IDs; the MCP relies entirely on the user's existing ADC).
- No third-party credential storage; no credential in any tool argument.
- No bearer secret in any error message, audit-log line, or tool result.
- No destructive Terra operation regardless of what the credential could do.

## Controlled-access note

A valid token can, in principle, reach data the user is entitled to. The MCP's
controlled-access guard (`MCP_TERRA_CONTROLLED_ACCESS`, see
[compliance.md](compliance.md)) blocks **this MCP's** data egress to the LLM; for
controlled-access work, also run the orchestrating agent against a self-hosted /
NIST-800-171 model. Host/IAM controls remain the user's responsibility (an agent
with the user's gcloud creds could call `gsutil` directly, outside the MCP).
