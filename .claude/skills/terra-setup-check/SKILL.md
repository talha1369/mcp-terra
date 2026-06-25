---
name: terra-setup-check
description: Verify the mcp-terra environment is correctly configured before running any work. Reports missing env vars, weak runner secret, dead runner heartbeat, killswitch state, code-integrity, and writes-allowed posture.
allowed-tools: mcp-terra:terra_health, mcp-terra:terra_whoami, mcp-terra:terra_killswitch_status, Bash
---

# terra-setup-check

The user wants to verify their mcp-terra install is ready for work.
This skill calls the diagnostic tools and reports clearly. **Do not call
any write tool** during this skill — read-only diagnostics only.

## Step 1: call terra_health

Call `terra_health` and parse the structured result. Surface these
fields explicitly to the user, formatted as a short readiness table:

| Field | Value | Status |
|---|---|---|
| server_version | … | ✓ if non-empty |
| writes_allowed | true/false | ⚠ if false (most tools refuse to write) |
| workspace_lock | namespace/name or null | ⚠ if null (notebook submit will refuse) |
| runner_secret.configured | true/false | ✗ if false |
| runner_secret.strength_ok | true/false | ✗ if false (regenerate per SOP § 2.3) |
| killswitch.tripped | true/false | ✗ if true (everything refuses) |
| audit_chain.ok | true | ✗ if false → chain digest mismatch (see SOP for archive procedure) |
| runner_heartbeat.status | alive / stale / missing / corrupt | ⚠ if not 'alive' (call terra_start_runner_on_vm or SOP § 3b) |
| tools_count | should be 24 | ⚠ if different |
| rate_limit_per_min | typically 60 | informational |

## Step 2: identity check

Call `terra_whoami`. Confirm:
- The Sam-registered email matches the user's gcloud account
- `gcloud_account` is the same email the user expects

If they differ, that's the most common source of "permission denied"
errors downstream.

## Step 3: optional Tier-2 LLM router

Check the user's env for `MCP_TERRA_LLM_PROVIDER` and `GOOGLE_API_KEY`:

```bash
env | grep -E '^(MCP_TERRA_LLM_PROVIDER|GOOGLE_API_KEY|GEMINI_API_KEY)' \
    | sed 's/=.*/=<redacted>/'
```

Report whether the cheap-LLM router (Tier 2) is active. If not, explain
that bug triage will only use Tier 0 (deterministic regex) which is
already free and fine for most users.

## Step 4: summary

Give the user a one-line readiness verdict:

- **READY** — all green
- **READY (degraded)** — green but writes_allowed=false (read-only mode)
- **NOT READY** — at least one ✗ above; quote the SOP section that fixes it

Do NOT proceed to other work unless the user explicitly asks. This skill
is a diagnostic; the user reads the result and decides next steps.
