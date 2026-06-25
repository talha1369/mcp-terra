# mcp-terra — Standard Operating Procedure

**For lab members and collaborators who want to run notebooks on Terra
through Claude (or another MCP client) with strong safety guarantees.**

This SOP covers the full workflow end-to-end: first-time setup, daily use,
the auto-bug-fix loop, the end-of-run email report, sharing with a
colleague, and what to do when something goes wrong.

If you only read one section: **§ 2 (First-time setup)** + **§ 4 (Daily
workflow)** is the 80 % path.

---

## 1. What is this MCP?

`mcp-terra` is a [Model Context Protocol](https://modelcontextprotocol.io/)
server that lets an LLM agent (Claude, Gemini, …) drive your Terra
workspace **without ever being able to overwrite or delete your data**.

Concretely the agent can:

- Identify you on Terra, list/inspect workspaces and Jupyter runtimes
- Upload and download files to your workspace bucket (no clobber, no delete)
- Submit a notebook job to a runner running on your Terra VM
- Poll the job, read the failing cell + traceback, fix the bug locally,
  re-upload (preserving the prior version as `.BAK.<ts>`), and re-submit
- Send you an end-of-run email report after a successful run

What the MCP **cannot do** by design:

- Delete or overwrite a single file in the bucket or on your laptop
- Operate on a workspace you don't own / haven't been granted access to
- Run any tool when the kill-switch is tripped
- Submit jobs without a valid HMAC signature (no co-member can forge a job)
- Send mail to anyone except your own Terra account email

---

## 2. First-time setup (one command, ~2 minutes)

### 2.1 Prerequisites — verify only (don't install yet)

```bash
gcloud --version                        # any version
python3 --version                       # ≥ 3.10
claude --version                        # Claude Code CLI
gcloud auth application-default login   # only if not already done
gcloud config get-value account         # must be your Terra-registered email
```

### 2.2 One-shot install

```bash
cd ~/projects/mcp-terra
./install.sh claussnitzer-fdp/your-workspace
```

That single command:

1. Verifies Python 3.10+, gcloud, and ADC
2. Installs the package + pinned deps (`requirements.lock --require-hashes`)
3. Generates an HMAC runner secret at `~/.mcp-terra/runner_secret` (mode `0600`).
   Reuses if one already exists — safe to re-run.
4. Looks up your workspace via Rawls to confirm access + finds the bucket name
5. **Registers the MCP with Claude Code via `claude mcp add`** (writes to
   `~/.claude.json`). This is the CORRECT registration mechanism —
   `settings.json`'s `mcpServers` block is **not** read by current Claude Code
   and is silently ignored. The installer also bakes a hardened `PATH` into
   the MCP's env so gcloud is found even when Claude Code is launched from
   Spotlight/Dock with a stripped environment.
6. Confirms `claude mcp list` shows `terra: ✔ Connected`

Idempotent — re-run any time to refresh the registration or pick up code
updates. Never touches your shell rc files.

### 2.3 Verify

Open Claude Code from anywhere:

```bash
claude
```

In the session:

> *"Run terra_health"*

You should see your Terra email, the workspace lock resolved, runner secret
configured + strength_ok, and 41 tools registered:

```jsonc
{
  "writes_allowed": true,
  "workspace_lock": {"namespace":"claussnitzer-fdp","name":"...","bucketName":"fc-secure-..."},
  "runner_secret": {"configured": true, "strength_ok": true},
  "audit_chain": {"ok": true, "reason": "chain intact"},
  "tools_count": 41
}
```

For the project-scoped skills (`/terra-setup-check`, `/terra-bugfix-loop`,
`/terra-share-pack`), launch from the repo: `cd ~/projects/mcp-terra && claude`.

### 2.4 Optional env vars

Set these by passing extra `-e KEY=VAL` to `claude mcp add` (or edit
`install.sh` and re-run). Defaults are sensible.

| Variable | Default | What it does |
|---|---|---|
| `MCP_TERRA_FAIL_STREAK_LIMIT` | `5` | VM halts after N consecutive failed jobs |
| `MCP_TERRA_MAX_SUBMITS_PER_SESSION` | `25` | Hard ceiling per MCP process |
| `MCP_TERRA_MAX_CALLS_PER_MIN` | `60` | Per-minute rate limit |
| `MCP_TERRA_SMTP_HOST/USER/PASS` | unset | If set, email report sends; else writes `.eml` |
| `MCP_TERRA_RLIMIT_NPROC` | `2000` | Subprocess cap (raise on unusually busy machines) |
| `MCP_TERRA_LLM_PROVIDER=gemini` + `GOOGLE_API_KEY` | unset | Opt-in: route hard bugs to Gemini Flash |
| `MCP_TERRA_TTS_VOICE` | `en-US-Studio-O` | Audio-summary voice |

Full matrix in `README.md § 6`.

---

## 3. Per-session setup: the runner (now automatic)

**For runtimes created by `terra_create_runtime` (the default,
`auto_start_runner=True`), there is no per-session setup.** The create wires
a Leonardo `startUserScriptUri` that launches the on-VM runner on every start
(initial create AND every resume after an auto-pause), and the call blocks
until the runner posts a fresh, identity-matched heartbeat — so a freshly
created or resumed VM always has a working runner. No SSH, no IAM, no manual
Jupyter terminal. The runner secret + bucket are delivered via Leonardo
`customEnvironmentVariables` (encrypted at rest; never in GCS, argv, or audit).

> **Keep `gs://<bucket>/mcp_terra_jobs/` owner-write-only.** The boot scripts
> and heartbeat live there; a workspace co-member with write access could
> tamper with the scripts the VM executes — the one bucket-trust assumption
> the HMAC-signed job contract does not itself cover.

The two paths below are **fallbacks for legacy runtimes** (created before the
seamless feature, or with `auto_start_runner=False`).

### 3a. Fallback (legacy) — `terra_start_runner_on_vm`

After you've called `terra_install_notebook_runner` once for the
workspace (one-time per bucket), every subsequent VM-session start is
one tool call:

> *"Call `terra_start_runner_on_vm` for runtime `<your-runtime-name>` in
> project `<your-google-project>`, bucket `gs://<your-bucket>`."*

The MCP will:

1. `gcloud compute instances list` → find the GCE instance + zone
2. `gcloud compute ssh` into it, piping the runner secret over **stdin**
   (not cmdline — never visible in `ps aux`)
3. `pkill` any previously-running runner (idempotent restart)
4. `nohup ./mcp_terra_runner.sh ... & disown` so the process survives
   SSH disconnect
5. Poll the heartbeat file in GCS for up to 60 s, only returning
   success once a fresh heartbeat (< 30 s old) appears — proves the
   runner is actually running, not just that SSH succeeded

If anything fails, the tool surfaces a structured error with the
exact `gcloud` command to re-run for diagnostics.

### 3b. Manual fallback

If `gcloud compute ssh` isn't available (you don't have the IAM role,
or the VM isn't yours), open a Jupyter terminal on the Terra VM
yourself:

```bash
cd /home/jupyter
gsutil cp gs://<your-bucket>/mcp_terra_jobs/mcp_terra_runner.sh .
chmod +x mcp_terra_runner.sh

# Get your secret with: cat ~/.mcp-terra/runner_secret  (on your laptop)
BUCKET=gs://<your-bucket> \
MCP_TERRA_RUNNER_SECRET='<paste the secret>' \
./mcp_terra_runner.sh
```

Leave the terminal open. The runner posts a heartbeat every 15 s; the
MCP refuses to submit jobs if the heartbeat is missing or > 90 s old.

---

## 4. Daily workflow — the end-to-end loop (`terra-bugfix-loop` skill)

No per-session setup needed (the runner auto-starts — §3). A typical run:

> **You:** *"Run my scprs_training.ipynb on Terra, fix any bugs, and email me
> a report with an audio explainer of the results."*
>
> **Claude (the `terra-bugfix-loop` skill):**
> 1. **Pre-flight** — `terra_health` (writes / lock / kill-switch / audit /
>    runner-secret).
> 2. **Right-size** — `terra_recommend_runtime_for_notebook`, compared to any
>    existing runtime. If none, `terra_create_runtime` (ATOMIC — returns only
>    once the VM is Running *and* the runner is live). If a runtime exists with
>    the **wrong** resources, Claude *guides you* through the Terra UI change
>    (keep the persistent disk) — the MCP never deletes — then recreates.
> 3. **Upload** — `terra_upload_to_bucket(...)` (pre-upload secret scan;
>    refuses if a secret is found).
> 4. **Submit** — `terra_submit_notebook_job(..., auto_stop_after_completion=True)`.
> 5. **Wait** — `terra_get_notebook_job_result(..., wait_for_complete=True,
>    timeout_s=3600)`; terminal state is read from the signed `result.json`.
> 6. **If FAILED** — read the `triage` block and apply the deterministic fix
>    (`missing_module` → prepend `!pip install …`; `name_error`/typo → fix the
>    cell; etc.), re-upload with `version_method='bak'`, re-submit.
>    (`transient_network` → just re-submit; `unknown` + a configured LLM key →
>    an `llm_suggested_patch` Claude validates, never auto-applies.)
> 7. **If succeeded** — pull `terra_get_run_log`, compose the **bug/method
>    report + a NotebookLM-style results explainer**, have a sub-agent verify
>    both against the log, then `terra_render_audio_summary` (if Cloud TTS is
>    configured — §5a) + `terra_send_run_report_email` with the verifier's
>    acknowledgment. Recipient is hard-locked to your Terra email.

**Token cost on the bug-fix loop:** Tier 0 (deterministic triage) cuts
Claude's per-iteration analysis cost ~50–70 %. Tier 2 (Gemini Flash, if
configured) cuts another 60 %+ of the remaining work.

---

## 5a. Audio summary (optional, agent-verified, no extra API key)

After a successful run, the MCP can render a spoken, NotebookLM-style
explainer of the results. It uses your existing gcloud auth (no separate API
key). **One-time setup, on a project where you hold `serviceusage`
permission** — a Terra-managed workspace project usually does NOT grant this,
so use a project you administer (TTS usage bills to it):

```bash
gcloud services enable texttospeech.googleapis.com --project <YOUR_PROJECT>
```

Then point the MCP's TTS quota project at it — Cloud TTS under *user*
credentials requires a quota project (sent as an `X-Goog-User-Project`
header), or it 403s with *"requires a quota project, which is not set by
default"*:

```bash
export MCP_TERRA_TTS_QUOTA_PROJECT=<YOUR_PROJECT>
```

If unset, the MCP defaults the quota project to the locked workspace's google
project (often `serviceusage`-locked). When TTS isn't usable, the run **report
still emails — just without the audio**.

The workflow:

1. The primary agent (Claude) drafts a 200-400 word summary of the run
   results — what was computed and what the numbers mean.
2. A verifier sub-agent (via the `Task` tool) reads the summary against
   `terra_get_run_log` + the executed notebook and returns a ≥ 50 char
   acknowledgment describing the specific evidence it cross-checked.
3. The agent calls `terra_render_audio_summary(job_id, bucket_uri,
   summary_text, verification_acknowledgment)`. The MCP validates the
   text (length cap, no CR, **no ya29 token in raw OR NFKC-normalized
   form** — homoglyph-bypass defended), sends to Cloud TTS, uploads the
   `.mp3` to `gs://.../mcp_terra_jobs/<job_id>/summary.mp3` (no clobber).
4. The agent calls `terra_send_run_report_email(..., audio_gcs=<path>)`
   so the email body contains a link to the .mp3 (and optionally
   attaches it as MIME).

Hard refusals (FAIL-CLOSED):
- `verification_acknowledgment` < 50 chars
- Summary text outside 50..4000 chars
- ya29.* OAuth-token shape in raw OR NFKC-normalized form
- CR characters in text (header-injection defense)
- Audio response > 8 MiB

If the TTS API isn't enabled, you get a 403 with a clear remediation
line. The agent can fall back to sending the email without audio.

## 5. The email report (with agent-verified non-hallucination)

After a successful run, the email contains:

- Final status (succeeded)
- A bug-by-bug list of what was auto-resolved vs. what required Claude
- A reviewer-agent acknowledgment paragraph describing what evidence the
  verifier cross-checked (e.g. *"verified against runner.stderr line 47…"*)

The MCP refuses to send:

- to anyone except your own Terra account email (hard-locked, no `to` param)
- if subject/body/ack contains `\r` or `\n` (header injection)
- if subject/body/ack contains a `ya29.*` OAuth token shape
- if the verification_acknowledgment is empty or < 50 chars
- if `gcloud auth application-default print-access-token` fails (fail-closed)

Three delivery modes (pick what your org allows):
- **A — `.eml` file (no credentials):** leave SMTP unset → the report is written
  under `~/.mcp-terra/reports/` (mode `0600`); open/forward it yourself.
- **B — authenticated send:** set `MCP_TERRA_SMTP_HOST/USER/PASS` (PASS = a
  scoped **app password**, not your account password; it lives in the MCP env,
  never in chat).
- **C — relay, no password:** set `MCP_TERRA_SMTP_HOST` + the explicit
  `MCP_TERRA_SMTP_RELAY=1` (for a Workspace/Broad relay that authorizes by IP).
  A forgotten password never silently relays — relay needs the explicit opt-in,
  else it falls back to mode A.

---

## 6. Auto-cost-stop after the last cell

When you tell Claude *"this is the last job, stop the VM after"*, it
passes `auto_stop_after_completion=True` to `terra_submit_notebook_job`.

The runner halts the VM only when:

- `rc == 0` (the notebook succeeded), AND
- The flag was set on the HMAC-bound spec

On any failure, the VM **stays alive** so the bug-fix loop has somewhere
to run. The runner also auto-halts the VM if `FAIL_STREAK_LIMIT` (default
5) consecutive jobs fail, to bound runaway-cost on a loop that never
converges.

---

## 7. Sharing this MCP with a lab member / collaborator

Send your colleague this packet (the `/terra-share-pack` skill builds it for
you):

1. **A copy of the repo** (or the share-pack tarball). The `requirements.lock`
   file contains pinned hashes for reproducible installs.
2. **This SOP file (`SOP.md`)**.
3. **Their Terra workspace name** (e.g. `claussnitzer-fdp/some-workspace`).

Their install is **one command**:

```bash
cd ~/projects/mcp-terra && ./install.sh claussnitzer-fdp/their-workspace
```

`install.sh` will:

- verify their gcloud auth is fresh,
- generate **their own** runner secret at `~/.mcp-terra/runner_secret`,
- look up their workspace via Rawls (fails loud if they don't have access),
- register the MCP with Claude Code via `claude mcp add`,
- confirm `claude mcp list` shows `terra: ✔ Connected`.

Then `claude` from anywhere and ask *"Run terra_health"* to verify.

**Do NOT share:**

- gcloud credentials — each user does their own `gcloud auth application-default login`
- Your runner secret — each user's installer generates a different one. If two
  people share a secret, they can sign each other's specs and the security
  model breaks.
- API keys (Gemini, OpenAI) — optional, per-user
- Your audit log — local-only state

### Optional: prepare a Docker image

The repo ships a hardened multi-stage `Dockerfile` (base image pinned by
sha256 digest, distroless-style runtime, non-root UID 10001). To share:

```bash
docker build -t mcp-terra:0.2.0 .
docker save mcp-terra:0.2.0 | gzip > mcp-terra-0.2.0.tgz
# colleague: docker load < mcp-terra-0.2.0.tgz
```

See the suggested `docker run` flags in the `Dockerfile` for `--read-only`,
`--cap-drop=ALL`, etc.

---

## 8. Security model in one paragraph

The MCP refuses by design to delete or overwrite any file. The agent's
notebook uploads use `.BAK.<timestamp>` versioning. Every notebook job
is HMAC-signed and replay-bound to a specific GCS path + submit time, so
a co-member can't forge or replay jobs. The runner verifies the notebook's
SHA-256 against the spec before executing — bucket-side tamper is caught.
The agent never sees the runner secret; it's scrubbed from papermill's
environment. Reports email only to your own Terra account email. The audit
log is an HMAC-chained, rotating file at `~/.mcp-terra/audit.log` — any
silent tampering breaks the chain. A kill-switch (`touch ~/.mcp-terra/KILL`)
refuses every subsequent operation; the MCP also auto-trips on bursts of
refusals. Pre-uploaded files are scanned for `ya29.*`, AWS keys, GitHub
PATs, Slack tokens, and PEM headers and the upload refused unless
`allow_secrets=True` is explicitly passed.

See `SECURITY.md` for the numbered threat model.

---

## 9. The kill switch

The fastest way to stop everything:

```bash
touch ~/.mcp-terra/KILL
```

From that moment, every tool call refuses. To re-enable:

```bash
rm ~/.mcp-terra/KILL
# AND restart the MCP process (the in-memory trip persists)
```

The MCP also auto-trips if more than 10 refused operations occur within
60 s — protects against scripted abuse.

---

## 10. Troubleshooting

| Symptom | What to do |
|---|---|
| `MCP_TERRA_RUNNER_SECRET must be ≥ 32 chars / low entropy` | Regenerate with the `secrets.token_urlsafe(32)` command in § 2.3 |
| `terra_submit_notebook_job refuses to run without MCP_TERRA_WORKSPACE` | Set the workspace lock env var and restart the MCP |
| `runner heartbeat is Xs old (stale > 90s)` | The on-VM runner died. SSH/Jupyter terminal into the VM and restart it (§ 3) |
| `per-session submit cap reached` | Restart the MCP process; raise `MCP_TERRA_MAX_SUBMITS_PER_SESSION` if you legitimately need more |
| `notebook SHA-256 mismatch; refusing` | A co-member (or accidental process) modified the notebook in the bucket between submit and pickup. Re-upload from your laptop |
| `sensitive-data scan blocked upload` | The pre-upload scanner found a `ya29.*` token / AWS key / SSH key / etc. Remove it from the file, OR pass `allow_secrets=True` explicitly after inspecting |
| `result.json HMAC signature invalid` | A workspace co-member may have spoofed a result file. Investigate the bucket ACL |
| `audit chain digest mismatch` (from `verify_audit_chain`) | Someone tampered with `~/.mcp-terra/audit.log`. Inspect immediately |

---

## 11. Version + provenance

This SOP applies to **mcp-terra v0.2.0**. The current rating from the
in-repo SOTA audit (categories: SECURITY, ROBUSTNESS, MCP_SPEC_COMPLIANCE,
OBSERVABILITY, SUPPLY_CHAIN, DOCUMENTATION, AUTOMATION_SAFETY) is recorded
in `CHANGELOG.md`. Re-run the audit anytime with:

```bash
# In Claude Code (this repo):
/workflow mcp-terra-sota-audit
```

Test suite (must be 100 % before sharing):

```bash
python tests/test_security_comprehensive.py
# → "mcp-terra security suite: N PASS / 0 FAIL of N"
```

---

## 12. Questions / Incident reporting

Security issues → `SECURITY.md` for the disclosure process.
General questions → open an issue against the repo or contact the
maintainer listed in `pyproject.toml`.
