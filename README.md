# mcp-terra

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-386%20passing-brightgreen.svg)
![Lint](https://img.shields.io/badge/lint-ruff-black.svg)
![Security](https://img.shields.io/badge/security-detect--secrets%20%2B%20pip--audit-success.svg)
<!-- After publishing, add the live CI badge:
![CI](https://github.com/your-org/mcp-terra/actions/workflows/ci.yml/badge.svg) -->

An MCP (Model Context Protocol) server that lets an AI assistant — any MCP-aware
agent — manage Terra (terra.bio) workspaces, runtime VMs, workspace buckets,
and WDL/Cromwell workflows on your behalf.

**The gap it closes:** on your laptop an AI coding assistant runs your code and
fixes the bugs; on Terra it could only copy a notebook into your bucket. mcp-terra
lets the assistant drive the *whole loop* — provision the right-sized VM, run the
notebook, **auto-fix** failures and re-run, then **email a verified report + an
audio explainer** of the results — from a single sentence, with **no
delete/overwrite primitive anywhere** and a controlled-access guard, spend cap,
and 24h-session awareness built in.

> **5-minute pitch deck:** open [`docs/pitch/index.html`](docs/pitch/index.html)
> in a browser; speaker script in
> [`docs/pitch/SPEAKER_NOTES.md`](docs/pitch/SPEAKER_NOTES.md).

Built for the Broad / Stanford Terra ecosystem. Wraps these Terra services:

- **Rawls** — workspaces, data tables, submissions, method configs
- **Leonardo** — runtime (Jupyter VM) lifecycle + seamless on-boot runner
- **Sam** — Terra user identity
- **Agora** — WDL method registration
- **Cromwell** (via Rawls) — workflow submission, metadata, cost
- plus **gsutil** for bucket I/O

## Install

Two ways in. Both end at the same place: the MCP connected + the Terra skills
loaded. **Prerequisite for both** (one-time per machine):

```bash
gcloud auth application-default login   # auth with your Terra-registered email
```

### Option A — Claude Code plugin (recommended for teams)

Bundles the MCP server **and** the Terra skills (`terra-bugfix-loop`,
`terra-wdl-run`, `terra-setup-check`, `terra-share-pack`) in one install:

```text
# In Claude Code:
/plugin marketplace add your-org/mcp-terra
/plugin install mcp-terra
```

Then run the one-time bootstrap (creates a dedicated venv, the runner secret,
and `~/.mcp-terra/config.env` — it does NOT touch your system Python or shell
rc), and restart Claude Code:

```bash
# Locate the bootstrap the plugin installed, then run it once with your workspace:
BOOTSTRAP="$(find ~/.claude/plugins -name terra-bootstrap.sh -path '*mcp-terra*' 2>/dev/null | head -1)"
bash "$BOOTSTRAP" your-namespace/your-workspace
```

The plugin's MCP server launches via `scripts/terra-mcp-launch.sh`, which loads
that config and starts the server from the venv. Re-run the bootstrap any time
to change workspace; it's idempotent.

### Option B — one-shot installer (single user / no marketplace)

```bash
git clone https://github.com/your-org/mcp-terra ~/projects/mcp-terra
cd ~/projects/mcp-terra
./install.sh your-namespace/your-workspace     # deps, secret, `claude mcp add`
claude
```

`install.sh` is idempotent — re-run any time to refresh the MCP registration.
It validates gcloud auth, runner-secret strength, your Terra workspace access
(via Rawls), then registers the MCP via `claude mcp add`. No manual editing of
`settings.json`, no env-vars in your shell rc, no PATH guessing. (Skills load
when you open Claude Code from the repo dir, or install Option A for them
globally.)

### First prompts (either option)

```text
Run terra_health.
Run <my-notebook>.ipynb via the auto-fix loop, auto-stop on success, email me the report.
```

## Architecture (trust boundaries)

```
   ┌─────────────┐    MCP stdio    ┌─────────────────────┐
   │ Claude /    │ ──────────────► │ mcp-terra (local)   │
   │ MCP client  │ ◄────────────── │  • _pre() gate      │
   └─────────────┘                 │  • safety.py        │
                                   │  • policy.py        │
                                   │  • audit chain      │
                                   └──┬──────────────┬───┘
                            HMAC-     │              │   gcloud OAuth
                            signed    │              │   (user identity)
                            spec      ▼              ▼
                              ┌──────────────┐   ┌──────────────┐
                              │ GCS bucket   │   │ Terra REST   │
                              │ (workspace)  │   │ Rawls/Leo/Sam│
                              └──────┬───────┘   └──────────────┘
                                     │
                              polled │   uploads result.json
                              every  │   + runner.log
                              15s    ▼   (HMAC-signed)
                              ┌──────────────────┐
                              │ on-VM runner.sh  │
                              │  • verifies sig  │
                              │  • verifies sha  │
                              │  • runs papermill│
                              │  • heartbeat     │
                              └──────────────────┘
                                     │
                                     ▼
                              Jupyter VM
```

**Trust boundaries:**
- `Agent ⇄ MCP`: stdio, in-process. Agent input is treated as untrusted.
- `MCP ⇄ GCS bucket`: gsutil with user's OAuth. No-clobber on every write.
- `MCP ⇄ Runner`: HMAC-SHA256 signed specs bound to `_spec_gcs` + `_submit_ts`.
  Bucket co-members **cannot** forge or replay jobs.
- `MCP ⇄ Terra REST`: Sam-authenticated; refuses cross-workspace ops when locked.
- `Runner ⇄ Notebook`: SHA-256 integrity check before execution. Bucket-side
  tamper between submit and pickup is detected.

## Why

If you've ever wanted Claude to:

- "Spin up a T4 GPU VM in my Terra workspace and start the training notebook"
- "Tail the log of the training job that's been running for 4 hours"
- "Upload these scripts to the workspace bucket"
- "Make sure all my Terra VMs are paused before I leave for the day"

…this is the bridge. The agent calls MCP tools; the tools call Terra REST APIs
under the user's gcloud OAuth credentials.

## Safety model

The MCP is designed to resist prompt-injection misuse by a connected agent.
Multiple layers, all enforced in code (not just docstrings):

**Hard guards** (cannot be bypassed by the agent):

1. **NO destruction primitive of any kind.** There is no `terra_delete_*`,
   no rm wrapper, no overwrite path. To delete anything (VM, bucket
   object, local file), use Terra UI / `gsutil rm` directly.

2. **No overwrites.** Bucket uploads refuse if the destination object
   already exists. Local downloads refuse if the local destination
   already exists.

3. **Local path blocklist.** Tools refuse local paths under:
   `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.azure`, `~/.netrc`,
   `~/.config/gcloud/application_default_credentials.json`, `~/.git-credentials`,
   and system paths `/etc/`, `/private/etc/`, `/System/`, `/usr/bin/`,
   `/Library/Keychains/`, etc. Symlinks are resolved before the check, so
   symlinks-to-blocked-paths also fail.

4. **Workspace-bucket allowlist.** Bucket reads/writes are restricted to
   `gs://` URIs whose bucket the user has Terra access to (refreshed every
   5 min from Rawls). Reads/writes to arbitrary public/private buckets
   are refused.

5. **Audit trail.** Every tool invocation writes one line to stderr with
   the tool name, action class (READ / WRITE-SAFE / SPEND), and arg
   summary. Easy to grep / review.

**Spend-rate gating** (docstring-based, agent confirms with user):

| Tool | Cost? | Notes |
|---|---|---|
| `terra_whoami` | no | identity check |
| `terra_list_workspaces` | no | |
| `terra_get_workspace` | no | |
| `terra_list_runtimes` | no | |
| `terra_get_runtime` | no | |
| `terra_stop_runtime` | no | pauses VM, saves money |
| `terra_start_runtime` | **yes** | resumes VM, agent confirms first |
| `terra_create_runtime` | **yes** | creates VM, agent confirms first |
| `terra_list_bucket` | no | restricted to workspace buckets |
| `terra_upload_to_bucket` | no | restricted; no overwrites; no credential paths |
| `terra_download_from_bucket` | no | restricted; no overwrites; no credential paths |

**No delete tool exists.** This is deliberate.

## Setup (one-time, per user)

### 1. Prerequisites

```bash
# Google Cloud SDK (gcloud + gsutil)
# https://cloud.google.com/sdk/docs/install

# Python 3.10+
python --version

# Authenticate as your Terra-registered user
gcloud auth application-default login
```

Make sure the email you authenticate with is a registered Terra user
(check at https://terra.bio).

### 2. Install the MCP

```bash
git clone <this repo url>  # or copy ~/projects/mcp-terra/
cd mcp-terra
pip install -e .
```

### 3. Wire into Claude Code

Use the `claude mcp add` CLI — **not** a `mcpServers` block in
`settings.json`. Current Claude Code ignores `mcpServers` in `settings.json`
silently (no error), so hand-editing it gives you a non-working MCP. The
`./install.sh` from the quickstart does this for you; to register manually:

```bash
claude mcp add terra \
  --env MCP_TERRA_ALLOW_WRITES=1 \
  --env MCP_TERRA_WORKSPACE=namespace/your-workspace \
  -- /absolute/path/to/python -m mcp_terra.server
```

Use the absolute path to a Python interpreter that has `mcp-terra` installed
(e.g. the venv `./install.sh` created). Then in Claude Code run `/mcp` and
confirm `terra` is connected. Re-run `claude mcp add` (or `./install.sh`) any
time you change env vars — they are snapshotted at MCP startup.

### 4. (Claude Desktop alternative)

Claude **Desktop** *does* use a JSON config — add a `mcpServers` block to
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "terra": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "mcp_terra.server"],
      "env": { "MCP_TERRA_ALLOW_WRITES": "1",
               "MCP_TERRA_WORKSPACE": "namespace/your-workspace" }
    }
  }
}
```

(This `mcpServers` form is correct for Claude Desktop only; Claude Code uses
`claude mcp add` as in §3.)

### 5. Verify

In Claude Code, ask: *"Run terra_whoami"*. The agent should respond with
your Sam-registered email + user subject ID.

### 6. Configuration matrix

All MCP behavior is controlled by environment variables. They are snapshotted
at startup — flipping them mid-session has no effect (defense against env
hijack). To change a value, restart the MCP process.

| Variable | Default | Required for | Meaning |
|---|---|---|---|
| `MCP_TERRA_ALLOW_WRITES` | `0` | Any write/spend tool | `1` enables WRITE-SAFE + SPEND tools. `0` = read-only mode. |
| `MCP_TERRA_WORKSPACE` | *(unset)* | Workspace lock | `namespace/name` — restricts the MCP to one workspace. Strongly recommended. |
| `MCP_TERRA_CONTROLLED_ACCESS` | `0` | NIH controlled data | `1` = refuse raw-data egress to the LLM (`terra_read_bucket_object`, `terra_get_entities`) for non-public buckets — GDS/DUC. Off by default (lab/public analysis unhindered). See [docs/compliance.md](docs/compliance.md). |
| `MCP_TERRA_DATA_EGRESS_ALLOW` | *(unset)* | Controlled-access exception | Comma/space-separated bucket names you certify as non-controlled (lab-open) that may be read even when the guard is on. Public reference buckets are allowed automatically. |
| `MCP_TERRA_RUNNER_SECRET` | *(unset)* | Notebook execution | ≥ 32 chars, ≥ 12 unique chars. HMAC-signs job specs. Generate via `python -c 'import secrets; print(secrets.token_urlsafe(32))'`. |
| `MCP_TERRA_MAX_CALLS_PER_MIN` | `60` | Rate limit | Bounds the per-minute call rate against runaway loops. |
| `MCP_TERRA_KILL_REFUSAL_THRESHOLD` | `10` | Auto-kill-switch | Auto-trips the kill switch after N refusals in the window. |
| `MCP_TERRA_KILL_REFUSAL_WINDOW_SEC` | `60` | Auto-kill-switch | Refusal-counting window for auto-trip. |
| `MCP_TERRA_SPEC_MAX_AGE_SEC` | `300` | Runner replay defense | Refuses specs older than this (clock-skew tolerance on the VM). |
| `MCP_TERRA_FAIL_STREAK_LIMIT` | `5` | Runner runaway cost | Halts the VM after N consecutive failed jobs. 1..50. |
| `MCP_TERRA_SMTP_HOST` | *(unset)* | Email send | SMTP host. Unset ⇒ falls back to `.eml` file under `~/.mcp-terra/reports/`. |
| `MCP_TERRA_SMTP_PORT` | `587` | Email send | `587` (STARTTLS) or `465` (implicit TLS). |
| `MCP_TERRA_SMTP_USER` | *(unset)* | Email send | Auth username. |
| `MCP_TERRA_SMTP_PASS` | *(unset)* | Email send | App-password (NOT main account password). |
| `MCP_TERRA_SMTP_STARTTLS` | `1` | Email send | `0` disables STARTTLS (only for port 465 implicit-TLS). |
| `MCP_TERRA_SMTP_FROM` | = `SMTP_USER` | Email send | `From:` header value. |
| `MCP_TERRA_SMTP_RELAY` | *(unset)* | Email send | `1` = no-auth relay (mode C): send without USER/PASS (relay authorizes by IP). Explicit opt-in only. |
| `MCP_TERRA_EMAIL_RECIPIENT_OVERRIDE` | *(unset)* | Test only | Must equal the auth'd Terra email; useful only if `gcloud account` differs from the desired inbox. Refused otherwise. |
| `MCP_TERRA_TTS_VOICE` | `en-US-Studio-O` | Audio summary | Cloud TTS voice id. Override e.g. `en-US-Studio-Q` (male), `en-US-Neural2-J`. Audio summary tool also requires `gcloud services enable texttospeech.googleapis.com`. |
| `MCP_TERRA_TTS_QUOTA_PROJECT` | = locked project | Audio summary | Quota/billing project for Cloud TTS (sent as `X-Goog-User-Project`). Needs `serviceusage.services.use` on that project. |
| `MCP_TERRA_SLACK_WEBHOOK` | *(unset)* | Slack ping (text) | `https://hooks.slack.com/services/...` incoming-webhook URL. Locked at startup; the `terra_notify_slack` tool has no URL parameter (anti-exfil). Unset ⇒ Slack ping is skipped. |
| `MCP_TERRA_SLACK_BOT_TOKEN` | *(unset)* | Slack file upload | `xoxb-…` bot token (Slack app with `files:write`). Required to attach the audio file to Slack (webhooks can't upload files). |
| `MCP_TERRA_SLACK_CHANNEL` | *(unset)* | Slack file upload | One **or more** targets (comma/space-separated) the bot uploads into — DM **and/or** channel. A **channel ID** (`C…`/`G…`; bot must be a member — `/invite @bot`), and/or a **user ID** (`U…`) to DM that user (no invite needed; requires the `im:write` bot scope). E.g. `U0123ABCD, C0456WXYZ`. Each target's outcome is reported independently. |

## Tool reference

All tools take simple parameters (strings, ints, bools) and return JSON
(or plain text). See docstrings in `src/mcp_terra/server.py` for full args.

This lists the most-used tools; `terra_health` reports the exact
`tools_count` (currently **39**), and `src/mcp_terra/server.py` is the
authoritative reference for every tool and its arguments.

### Read-only / inspection

```
terra_whoami() → {userEmail, userSubjectId, gcloud_account}
terra_list_workspaces() → [{namespace, name, bucketName, googleProject, accessLevel}, …]
terra_get_workspace(namespace, name) → {workspace: {bucketName, googleProject, …}}
terra_list_runtimes(google_project=None) → [{runtimeName, status, machineType, …}]
terra_get_runtime(google_project, runtime_name) → {status, runtimeConfig, …}
terra_list_bucket(bucket_uri, recursive=False) → ["gs://…", …]
terra_recommend_runtime_for_notebook(notebook_gcs) → {machine_type, gpu, rationale}
terra_health() → {writes_allowed, workspace_lock, runner_secret, audit_chain, tools_count, …}
terra_killswitch_status() → {tripped, reason, …}
```

### Workspace data & workflow inspection (read-only)

These give the MCP comprehensive read coverage —
all READ-class, no spend, no destruction.

```
terra_list_data_tables(namespace, name) → {entityType: {count, attributeNames, …}}
terra_get_entities(namespace, name, entity_type, page=1, page_size=50) → {results, resultMetadata}
terra_list_submissions(namespace, name) → [{submissionId, status, …}]
terra_get_submission(namespace, name, submission_id) → {status, workflows, …}
terra_get_workflow_metadata(namespace, name, submission_id, workflow_id, include_calls=False)
terra_get_workflow_outputs(namespace, name, submission_id, workflow_id)
terra_get_workflow_logs(namespace, name, submission_id, workflow_id, max_bytes=65536, failed_only=True)  # per-task Cromwell stderr — the real failure signal
terra_get_workflow_cost(namespace, name, submission_id, workflow_id)
terra_list_method_configs(namespace, name) → [{namespace, name, methodRepoMethod, …}]
terra_get_method_config(namespace, name, config_namespace, config_name)
terra_read_bucket_object(bucket_uri, max_bytes=102400) → {text, bytes_returned, truncated}
terra_get_bucket_object_metadata(bucket_uri) → {stat}
terra_get_batch_job_status(google_project, region, job_name) → {status, logging_command}
```

### Workflows (WDL / Cromwell) — authoring + submit

```
terra_register_method(method_namespace, method_name, wdl, synopsis="")   # Agora, append-only, secret-scanned
terra_create_method_config(...)                                          # no-clobber
terra_submit_workflow(namespace, name, config_namespace, config_name, …) # SPEND; no abort/delete by design
```

### Lifecycle (cost-incurring → agent confirms with user first)

```
terra_start_runtime(google_project, runtime_name)
terra_stop_runtime(google_project, runtime_name)
terra_create_runtime(google_project, runtime_name,
                     machine_type="n1-standard-4",
                     disk_size_gb=100,
                     gpu_type="",      # or "nvidia-tesla-t4" / "nvidia-tesla-v100"
                     num_gpus=0,
                     auto_pause_threshold_minutes=60,
                     tool_docker_image="",
                     bucket_uri="",          # defaults to the locked workspace bucket
                     auto_start_runner=True) # seamless on-boot runner (see below)
```

> **ATOMIC + seamless** (default `auto_start_runner=True`): the VM comes back
> with a **live runner**, or this call fails loud. It wires a Leonardo
> `startUserScriptUri` that auto-launches the on-VM runner on every start
> (create *and* resume) — no SSH, no IAM, no manual step — and blocks until
> the runner posts a fresh, identity-matched heartbeat (else it returns the
> on-VM runner-log tail). Pass `auto_start_runner=False` for the legacy
> fire-and-forget create.

> **There is intentionally no `terra_delete_runtime`.** The MCP cannot
> destroy VMs or disks — use the Terra UI to delete a runtime (choose **"Keep
> persistent disk"**). This is the no-destruction principle: deletes and
> overwrites are physically impossible through this MCP. To change a
> wrong-sized runtime, the `terra-bugfix-loop` skill detects the mismatch and
> *guides* you through the UI change, then recreates at the right spec.

### Bucket I/O

```
terra_upload_to_bucket(local_path, bucket_uri, recursive=False)
terra_download_from_bucket(bucket_uri, local_path, recursive=False)
```

### Completion record + delivery channels

On run completion the loop writes ONE provenance-bearing record (see
[docs/metadata.md](docs/metadata.md)) that the email, Slack, and audio channels
all render from — so every channel agrees and the verifier gate covers all
three at once.

```
terra_write_run_record(run_id, record_json, bucket_uri="")  # WRITE; no-clobber; MCP stamps provenance
terra_send_run_report_email(subject, body, job_id, verification_acknowledgment)  # recipient-locked
terra_notify_slack(text, run_id="")                         # WRITE; webhook env-locked (no url param)
terra_render_audio_summary(...)                             # "what the results mean" via Cloud TTS
```

## The bug-fix loop (notebook execution + `.BAK` versioning)

The end-to-end flow — *provision the right VM → run → auto-fix → emailed
report (+ optional NotebookLM-style audio explainer)* — is packaged as the
**`terra-bugfix-loop` Claude skill** (the canonical "run my Terra notebook"
entry point). It closes the gap that Claude Code alone can only *copy* a
notebook into the bucket; the MCP lets it actually provision, run, and report.
Under the hood the skill composes these credentialed primitives:

| Tool | Purpose | Cost |
|---|---|---|
| `terra_submit_notebook_job(notebook_gcs, bucket_uri, …, auto_stop_after_completion)` | Submit a notebook for async execution (HMAC-signed spec). Returns a `job_id`. | no (the VM is what costs) |
| `terra_get_notebook_job_result(bucket_uri, job_id, wait_for_complete, timeout_s)` | Poll a job. Returns status + deterministic triage + the failing cell's source/traceback if FAILED. Terminal state is read from the signed `result.json`. | no |
| `terra_get_run_log` · `terra_render_audio_summary` · `terra_send_run_report_email` | Ground-truth log · verifier-gated audio explainer · recipient-locked report email. | no / TTS / SMTP |
| `terra_install_notebook_runner(bucket_uri)` | *Legacy only* — the runner now auto-installs on VM boot (see above). | no |

> **MCP vs. skill (first principles):** the MCP is the credentialed,
> safety-gated *primitive* layer — it holds the Terra/GCS/HMAC credentials and
> enforces the hard invariants (no delete, no overwrite, signed jobs,
> writes-gate, audit, kill-switch, locked email recipient), with **no judgment
> and no destruction**. Claude *skills* hold the judgment + orchestration and
> cannot exceed the MCP's capability envelope — so even a buggy or
> prompt-injected skill still cannot destroy your data.

### Runner startup — seamless (no manual step)

The MCP can't drive Jupyter cells directly; it uses a job-spec contract via
GCS, executed by an on-VM runner. **You no longer start the runner by hand** —
`terra_create_runtime` (`auto_start_runner=True`, default) wires a Leonardo
`startUserScriptUri` that launches it on **every** VM start (create *and*
resume-from-autopause). The runner secret + bucket are delivered via Leonardo
`customEnvironmentVariables` (encrypted at rest; never in GCS, argv, or audit).

For a **legacy runtime** created before this feature, start the runner once
via `terra_start_runner_on_vm(...)` (gcloud-ssh; needs the SSH/IAM role) or
the manual Jupyter-terminal fallback in SOP §3b.

The runner polls the bucket every 15s and executes notebooks with `papermill`.
It NEVER deletes anything — consumed specs are renamed to `*.consumed` via
`gsutil mv`.

> **Workspace-bucket lock:** keep write access to `gs://<bucket>/mcp_terra_jobs/`
> (boot scripts + heartbeat) **owner-only**. A co-member with write access there
> could tamper with the boot scripts the VM executes — the one bucket-trust
> assumption the HMAC-signed job contract does not itself cover.

### The loop, end-to-end

1. Claude uploads notebook + scripts to GCS via `terra_upload_to_bucket`.
2. Claude calls `terra_submit_notebook_job(notebook_gcs, bucket_uri)`.
3. Claude polls `terra_get_notebook_job_result(bucket_uri, job_id)`.
4. **On `FAILED`**: result includes `failed_cell_index`, `failed_cell_source`,
   `failed_cell_traceback`. Claude reads the traceback, edits the source
   locally (using its `Read`/`Edit` tools), re-uploads via
   `terra_upload_to_bucket(..., version_existing=True, version_method='bak')`.
   The previous buggy version becomes `<name>.BAK.<ISO-ts>.<ext>`; the new
   version takes the original name. Loop back to (2).
5. **On `succeeded`**: download `executed_notebook_gcs` for outputs.

### Pre-authorizing the loop (so the agent doesn't pause for permission)

By default Claude Code prompts you before every tool call. For an unattended
bug-fix loop, add the following tools to your **allowed tools** list in
`~/.claude/settings.json` (or use the `/permissions` slash command in
Claude Code) so the loop runs without prompts:

```jsonc
{
  "permissions": {
    "allow": [
      "mcp-terra:terra_submit_notebook_job",
      "mcp-terra:terra_get_notebook_job_result",
      "mcp-terra:terra_upload_to_bucket",
      "mcp-terra:terra_get_run_log"
    ]
  }
}
```

Hard guards STAY in place during pre-authorized loops:

- `MCP_TERRA_ALLOW_WRITES=1` must still be set in the environment.
- The workspace lock (`MCP_TERRA_WORKSPACE`) is still enforced.
- The HMAC spec signing still applies — `MCP_TERRA_RUNNER_SECRET` must be
  a high-entropy value (≥ 32 chars, ≥ 12 unique chars).
- The kill-switch file `~/.mcp-terra/KILL` still aborts everything
  immediately if you create it.
- Rate limit (default 60 calls/min) still bounds runaway loops.

### End-of-run report email (with agent-verified non-hallucination)

After `succeeded`, the agent composes an end-of-run report describing each
bug it encountered and the specific fix it applied. To send it as an email:

   Three delivery modes — pick what your org allows:

   - **A — No credentials (`.eml` file).** Leave SMTP unset. The MCP writes the
     report as an `.eml` under `~/.mcp-terra/reports/` (mode `0o600`) and returns
     the path; you open/forward it. Zero credentials.
   - **B — Authenticated send (app password).** Set HOST + USER + PASS. The PASS
     is an **app password** (a scoped, revocable SMTP token — *not* your account
     password); it lives in your env/config, never in chat.
     ```bash
     export MCP_TERRA_SMTP_HOST=smtp.gmail.com
     export MCP_TERRA_SMTP_PORT=587
     export MCP_TERRA_SMTP_USER=you@broadinstitute.org
     export MCP_TERRA_SMTP_PASS='<app-password>'   # NOT your main password
     ```
   - **C — Relay, no password.** For a Workspace/Broad SMTP relay that authorizes
     by IP. Set HOST and the **explicit** opt-in `MCP_TERRA_SMTP_RELAY=1` (no
     USER/PASS needed); the MCP sends without authenticating.
     ```bash
     export MCP_TERRA_SMTP_HOST=smtp-relay.gmail.com
     export MCP_TERRA_SMTP_RELAY=1
     ```
     A merely-*forgotten* password never silently relays — relay requires the
     explicit `=1` opt-in; otherwise it falls back to the `.eml` file (mode A).

2. The recipient is **HARD-LOCKED** to your Terra account email — there is
   no `to` parameter on the email tool. The MCP refuses to send to anyone
   else, defeating data-exfil-via-email.

3. Before sending, the primary agent asks a second Claude agent (via the
   `Task` tool) to verify the report against `terra_get_run_log()` output.
   The verifier returns a free-form acknowledgment describing exactly what
   evidence they cross-checked. The email tool refuses to send unless the
   acknowledgment is ≥ 50 chars and describes concrete evidence (e.g.
   "verified against runner.stderr line 47 traceback"). The MCP does NOT
   enforce semantic correctness of the acknowledgment — that's the
   verifier agent's job. The MCP's role is to refuse blank approvals
   and to lock the recipient.

### `.BAK` vs timestamp versioning

`terra_upload_to_bucket(..., version_existing=True, version_method='bak')`:

- `gs://b/script.py` exists, user uploads a bug-fix
- Old → `gs://b/script.BAK.20260625T013000Z.py` (preserved, not deleted)
- New → `gs://b/script.py` (the bug-fixed version takes the original name)

`version_method='timestamp'` (default) puts the timestamp without `.BAK.`:

- Old → `gs://b/script.20260625T013000Z.py`

Use `bak` for code supersession (clear "this is the old/buggy one" signal);
use `timestamp` for data versioning.

## Running multiple / parallel jobs

The MCP supports running many jobs at once — there is no serialization at the
submission layer. Three layers of parallelism:

1. **WDL / Cromwell scatter (the parallel-compute path).** `terra_submit_workflow`
   launches a Cromwell submission; a `scatter` block fans every shard out as a
   separate Google Batch task, so **one** workflow runs hundreds of tasks in
   parallel (bounded by your project's Batch quota). Call-caching means a
   re-submit only re-runs the *failed* shards. This is the right tool for large
   parallel workloads — see the `terra-wdl-run` skill.
2. **Many concurrent submissions.** Each `terra_submit_workflow` /
   `terra_submit_notebook_job` is independent and non-blocking — submit several
   and they all run at once (each spend is confirmed separately).
3. **Notebooks across multiple runtimes.** Submit several notebook jobs and run
   several runtimes (VMs); the on-VM runner takes an **atomic per-spec claim**
   (a no-clobber `.claim` marker, keyed to the runtime), so each VM picks up a
   *different* job — notebooks run in parallel across VMs and the same job is
   never executed twice. (A single VM runs its own jobs sequentially, by design,
   to avoid OOM — for many notebooks at once, use more runtimes or the WDL path.)

## Multiple compute environments

The MCP is not limited to one runtime. `terra_create_runtime` takes a
`runtime_name`, so calling it with distinct names creates **several compute
environments** in the locked workspace's project (the lock is to the
project/workspace, not to a single runtime); `terra_list_runtimes`,
`terra_get_runtime`, `terra_start_runtime`, and `terra_stop_runtime` all operate
per-name. Run several at once for parallel work: each runtime's on-VM runner
takes an **atomic per-spec claim**, so the VMs pick up *different* notebook jobs
and never run the same one twice. Mix sizes too — e.g. a GPU env for training
and a high-mem env for preprocessing — and submit jobs to the shared bucket;
the running runtimes divide them. (For one VM to run several jobs at once, see
single-VM concurrency; for large fan-out, prefer the WDL/Cromwell scatter path.)

## Example collaboration flow

```text
You:    "Run my analysis.ipynb on Terra, fix any bugs, and email me the results."
Claude: [terra_recommend_runtime_for_notebook] → "Needs a T4 GPU VM (~$0.50/hr). OK?"
You:    "yes"
Claude: [terra_create_runtime]  → blocks ~5 min, returns status="ready"
          (VM Running AND runner live — no SSH, no IAM, no manual step)
        [terra_submit_notebook_job auto_stop=True] → job_id
        [terra_get_notebook_job_result wait_for_complete=True]
          → FAILED: triage = missing_module 'pyarrow'
        → prepends '!pip install pyarrow', re-uploads (.BAK), re-submits
          → succeeded (rc=0)
        [terra_get_run_log] → verifier sub-agent cross-checks the report
        [terra_render_audio_summary] + [terra_send_run_report_email]
          → "Emailed you the verified report + a NotebookLM-style audio explainer."
```

(This whole flow is the `terra-bugfix-loop` skill — provision → run → auto-fix
→ verified report + audio email.)

## Auth notes

- Tokens come from **gcloud Application Default Credentials**. There's no
  separate Terra OAuth flow — Terra trusts the same Google identity.
- The MCP never caches tokens. Each tool call invokes
  `gcloud auth application-default print-access-token` to get a fresh one
  (gcloud handles refresh internally).
- Collaborators each need their own gcloud auth and Terra registration.

## Limitations / not-yet-supported

- **WDL / Cromwell workflows** — not yet supported (planned). Use the Terra
  UI for workflow submission for now.
- **No interactive Jupyter-kernel control** — the MCP executes notebooks
  *headless* via the on-VM runner (`papermill`) — that's how the bug-fix loop
  runs them — but it does not drive cells in a live, interactive kernel.
- **No runtime or disk deletion** — by design (no-destruction). Delete a
  runtime in the Terra UI and choose "Keep persistent disk".
- **NotebookLM-style audio** needs Cloud TTS enabled on a project where you
  hold `serviceusage` permission (set `MCP_TERRA_TTS_QUOTA_PROJECT`); without
  it, the report still emails — just without the audio.
- No multi-region awareness — assumes Terra's defaults (us-central1 / us-east4).

## Contributing

PRs welcome. Add tools by:

1. Implementing the API call in `terra_client.py` (or `bucket.py` for gsutil ops)
2. Adding a `@server.tool()` wrapper in `server.py` with a clear docstring
3. Adding a smoke test in `tests/`

Keep the safety model intact — any spend-rate or destructive tool MUST tell
the agent in its docstring to confirm with the user first.

## License

MIT.
