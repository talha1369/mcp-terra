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
| tools_count | non-zero; should match the tool count in SECURITY.md | ⚠ if 0 (server failed to register tools) |
| rate_limit_per_min | typically 60 | informational |

Do NOT hard-code an expected `tools_count` — the surface grows over releases.
Treat 0 (or a sharp drop) as the only red flag; the authoritative number lives
in SECURITY.md, regenerated from the test suite.

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

## Step 4: if something is wrong — plain-English, copy-paste fixes

For non-expert users, NEVER just print a stack trace or a code. For each
red/amber field, give the ONE command that fixes it, in plain words. Map:

| What's wrong | What it means (plain English) | Copy-paste fix |
|---|---|---|
| `terra_health`/`terra_whoami` error: "gcloud ADC not set up" | Your Google login for Terra has expired or was never set up. | `gcloud auth application-default login` (a browser opens — sign in with your Broad/Terra Google account) |
| `whoami` gcloud account ≠ your Terra email | You're logged into the wrong Google account. | `gcloud config set account <your-terra-email>` then re-run `gcloud auth application-default login` |
| `workspace_lock` is null | The MCP doesn't know which workspace to use; notebook/WDL submit will refuse. | Re-run `./install.sh <namespace>/<workspace>` (or set `MCP_TERRA_WORKSPACE=<ns>/<ws>` and restart Claude Code) |
| `writes_allowed` is false | The MCP is in read-only mode and won't submit jobs. | Re-run `./install.sh` (it sets `MCP_TERRA_ALLOW_WRITES=1`), then restart Claude Code |
| `runner_secret.configured` false / `strength_ok` false | The signing key the on-VM runner needs is missing/weak. | Re-run `./install.sh` — it generates a strong secret at `~/.mcp-terra/runner_secret` |
| `runner_heartbeat.status` not 'alive' | The little program that runs your notebook ON Terra isn't running on the VM. | Ask Claude to run `terra_start_runner_on_vm` (it restarts it for you — no SSH needed). If that fails, SOP § 3b. |
| `killswitch.tripped` true | A safety stop is engaged; every action refuses. | Ask Claude to check `terra_killswitch_status`; clear the kill-file it names once you've confirmed it's safe |
| `audit_chain.ok` false | The tamper-evident log's chain doesn't verify. | Stop and tell your admin — see SOP "audit chain" (do not ignore) |

## Step 5: summary

Give the user a one-line readiness verdict:

- **READY** — all green ("You're set — say *run my notebook …* or use /terra-bugfix-loop")
- **READY (degraded)** — green but writes_allowed=false (read-only mode)
- **NOT READY** — at least one ✗ above; show the plain-English fix from the table

Do NOT proceed to other work unless the user explicitly asks. This skill
is a diagnostic; the user reads the result and decides next steps.
