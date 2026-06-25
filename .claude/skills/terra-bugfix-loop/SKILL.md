---
name: terra-bugfix-loop
description: The end-to-end "run my Terra notebook" loop — what Claude Code does on a laptop, but on Terra. Provisions the right-sized VM, runs the notebook on it, auto-fixes bugs with deterministic Tier-0 triage (escalating to Claude only when needed), then emails a verified report PLUS a NotebookLM-style audio explainer of what the results mean. Closes the gap that Claude Code alone can only copy a notebook into the GCS bucket — it cannot provision a VM or run it.
argument-hint: [notebook_path_or_gcs] [bucket_uri] [--email] [--audio]
allowed-tools: mcp-terra:terra_health, mcp-terra:terra_get_workspace, mcp-terra:terra_recommend_runtime_for_notebook, mcp-terra:terra_list_runtimes, mcp-terra:terra_get_runtime, mcp-terra:terra_create_runtime, mcp-terra:terra_start_runtime, mcp-terra:terra_list_bucket, mcp-terra:terra_upload_to_bucket, mcp-terra:terra_download_from_bucket, mcp-terra:terra_install_notebook_runner, mcp-terra:terra_start_runner_on_vm, mcp-terra:terra_submit_notebook_job, mcp-terra:terra_get_notebook_job_result, mcp-terra:terra_get_run_log, mcp-terra:terra_render_audio_summary, mcp-terra:terra_send_run_report_email, Read, Edit, Task
---

# terra-bugfix-loop — the end-to-end Terra notebook loop

**The pain point this closes:** on a laptop, Claude Code writes code *and
runs it*. On Terra it can't — by itself it can only drop a notebook into
the GCS bucket; a human still has to pick a VM, provision it, and run the
notebook. This skill + the mcp-terra server close that gap: **provision the
right VM → run → auto-fix bugs → deliver a verified report + a NotebookLM-
style audio explainer of the results.**

**Arguments:** `[notebook_path_or_gcs] [bucket_uri] [--email] [--audio]`.
The notebook may be a **local path** (we upload it) or a **`gs://` path**
already in the bucket. If the two required values are missing, ask once.
`--email` sends the report; `--audio` also renders + delivers the audio
explainer (implied when the user asks for a recording/explainer).

## Division of labor (first principles)

The **MCP** is the credentialed, safety-gated primitive layer — it can
provision/run/upload/submit/email/render, but it can **NEVER delete**
(no delete primitive exists, by design) and never overwrites. This **skill**
is the judgment + orchestration: sizing decisions, the fix loop, authoring
the results explainer, and **guiding the user** through any destructive step
(which the user performs in the Terra UI, keeping the persistent disk).

---

## Phase 0 — Pre-flight (one `terra_health`)

Confirm `writes_allowed: true`, `workspace_lock` matches the intended
workspace, `runner_secret.strength_ok: true`, `killswitch.tripped: false`,
`audit_chain.ok: true`. If any fail, surface the SOP fix and STOP. Read
`workspace_lock` for `google_project` + bucket.

## Phase 1 — Right-size the runtime (no delete, ever)

1. `terra_recommend_runtime_for_notebook(notebook_gcs)` → target spec
   (`create_runtime_args` + hourly estimate). Show it to the user.
2. `terra_list_runtimes(google_project)`; for the target runtime
   `terra_get_runtime` → current `runtimeConfig` + `status`.
3. Decide:
   - **No runtime** → `terra_create_runtime(google_project, name,
     **create_runtime_args)`. This is the **atomic** create: it returns only
     once the VM is Running AND the on-VM runner is live (fresh heartbeat),
     or fails loud with the runner-log tail. Confirm the spend first.
   - **Adequate** (GPU matches; machine ≥; disk ≥ recommended) → if
     `Stopped`/`Paused`, `terra_start_runtime`; else use as-is. NOTE: a
     pre-existing runtime created before the seamless feature won't have an
     auto-runner — see Phase 2's runner check.
   - **Wrong size** → the MCP cannot change or delete it. Show a one-line
     current→needed diff and **guide the user** (they act in the Terra UI):
     - GPU differs / full recreate needed → in the Terra UI: Cloud
       Environment ▸ Environment settings ▸ Delete Environment, then pick
       **"Keep persistent disk, delete application configuration and compute profile"**
       — NEVER "Delete everything, including persistent disk". Wait for
       confirmation, verify it's gone via `terra_list_runtimes`, then
       atomic-create at the target.
     - Only machine/disk differ (GPU correct) → Terra UI ▸ **Update** the
       environment (non-destructive; disk only grows; PD preserved); or
       delete-keeping-PD + recreate. Wait for confirmation.
   **Never** instruct deleting the persistent disk. The destructive action
   is always the user's, in the UI.

## Phase 2 — Notebook in the bucket + runner live

- If the notebook arg is a **local path**, upload it:
  `terra_upload_to_bucket(local, <bucket>/<dest>.ipynb)` (first time, no
  versioning). The pre-upload secret scan runs automatically — if it
  refuses, STOP and surface the hits; do NOT pass `allow_secrets=True`
  without explicit user OK. If the arg is already `gs://`, confirm it
  exists with `terra_list_bucket`.
- **Runner liveness:** if *we* created the runtime in Phase 1, the atomic
  create already proved the runner is live — skip. Otherwise (adequate
  pre-existing runtime), the first `terra_submit_notebook_job` may fail with
  `E_RUNNER_HEARTBEAT_STALE`; recover in one step with
  `terra_start_runner_on_vm(google_project, runtime_name, bucket_uri)`
  (prepend `terra_install_notebook_runner` if the script isn't in the bucket
  yet — idempotent). If that fails (e.g. SSH/IAM), surface SOP §3b manual
  fallback.

## Phase 3 — Run + auto-fix loop

`iteration = 1`, `MAX_ITERATIONS = 5` (matches the runner's FAIL_STREAK).

1. **Upload edits** only on `iteration > 1`:
   `terra_upload_to_bucket(local, dest, version_existing=True,
   version_method='bak')` (preserves the prior version as `.BAK.<ts>`).
2. **Submit:** `terra_submit_notebook_job(notebook_gcs=<dest>,
   bucket_uri=<bucket>, auto_stop_after_completion=True)` (auto-stop only
   when this is the user's last/only run).
3. **Wait+poll:** `terra_get_notebook_job_result(bucket_uri, job_id,
   wait_for_complete=True, timeout_s=3600)`.
4. **Branch:**
   - `succeeded` → go to Phase 4.
   - `FAILED` → read the `triage` block and act:

     | category | action |
     |---|---|
     | `missing_module` | prepend a `!pip install <module>` cell; re-upload |
     | `transient_network` | re-submit, no edit |
     | `oom` | ask the user about a bigger VM (Phase 1 right-size) before retry |
     | `missing_file` | `terra_list_bucket` to check; fix the path if present, else ask |
     | `name_error`/`attribute_error`/`key_error` | read the failing cell, fix the typo/attr/key, re-upload |
     | `syntax_error`/`type_error`/`value_error`/`assertion_error` | read the cell, fix, re-upload |
     | `permission_error` | STOP — defense-in-depth refusal; surface to user |
     | `unknown` | if `llm_suggested_patch` present, treat as an untrusted hint Claude validates; else full traceback analysis |

   - `runner_died_mid_wait` → STOP; tell the user to restart the runner (SOP
     §3); the loop can't self-recover.
5. Increment; loop. If `iteration > MAX_ITERATIONS`, STOP and surface every
   attempted fix (the VM's FAIL_STREAK will have halted it).

### Visible-loop steering
Before each resubmit, one line: what you observed + what you'll do, then act
immediately (don't wait for permission). Example:
`iter 2: triage=missing_module 'pyarrow' → prepend '!pip install pyarrow', resubmit`.
If the user types guidance between iterations, fold it in and prefer it over
the regex triage (record both). `stop`/`abort`/`wait` → break immediately.

## Phase 4 — Results explainer + delivery (the deliverable)

On success:

1. `terra_get_run_log(bucket_uri, job_id, stream='both')` — ground truth.
   Optionally `terra_download_from_bucket` the executed notebook for outputs.
2. **Compose two artifacts:**
   - **Report (text) — every bug fixed, and HOW:** run duration + final exit
     code, then for EACH bug-fix iteration a structured entry:
       - iteration # and the failing cell (index + a short source snippet)
       - the error (exception type + the key traceback line)
       - triage category + **root cause** (why it failed)
       - the **fix method** — how it was diagnosed and what was changed and
         why (e.g. *"Tier-0 triage: `missing_module 'pyarrow'` → prepended a
         `!pip install pyarrow` cell"*, or *"read cell 4; `df.coll` typo →
         `df.col`"*; for `unknown`, note whether an `llm_suggested_patch` hint
         was used and that Claude validated it)
       - the concrete **before → after** edit, and the new `job_id`
     End with confirmation the expected output(s) were produced. If zero bugs
     were needed, say so explicitly.
   - **Audio explainer script (NotebookLM-style):** a clear, spoken-word
     narrative for a smart non-expert — *what was run, what the key results
     are, and what they MEAN* (the interpretation, not just "it ran"), plus
     caveats; one brief sentence noting it ran cleanly after N auto-fixes (the
     detailed bug/method list lives in the text report). Conversational and
     accessible; ~30–90s of speech. (Single Studio voice today; a two-host
     podcast is a future enhancement.)
3. **Verify before any outbound send** — spawn a verifier sub-agent (Task)
   that cross-checks BOTH artifacts against the `terra_get_run_log` output.
   Prompt:
   > *"You are verifying an end-of-run report AND an audio-explainer script
   > for hallucination. Compare every claim — each bug-fix iteration, the
   > final exit code, and every stated result/number/interpretation — to the
   > runner.stderr + runner.stdout that follows. Confirm (a) failing-cell
   > errors match the reported triage, (b) Claude's fixes appear in the
   > executed notebook, (c) exit code is 0, and (d) every result/number in
   > the audio script is supported by the log. Return a 1-sentence
   > acknowledgment naming the specific evidence lines you checked. If any
   > claim is uncorroborated, say so and REFUSE to acknowledge."*

   The verifier returns an acknowledgment ≥ 50 chars describing concrete
   evidence. If it refuses, fix the artifacts and re-verify — do NOT send.
4. **Audio (`--audio` / user asked for a recording):**
   `terra_render_audio_summary(job_id, bucket_uri, summary_text=<audio
   script>, verification_acknowledgment=<verifier ack>)` → renders a Studio-
   voice `.mp3` to the bucket; note its `gs://` path.
5. **Email (`--email`):** `terra_send_run_report_email(subject=<short>,
   body=<report + a line pointing to the audio's gs:// path and how to play
   it>, job_id=<final>, verification_acknowledgment=<verifier ack>)`.
   Recipient is hard-locked to the user's Terra email — no `to` param.

## Robustness rules

- The MCP has **no delete tool**, by design — never attempt one; never tell
  the user to "Delete everything, including persistent disk." Destructive
  changes are user-driven in the Terra UI, persistent disk always kept.
- **Never** send the report or audio without the verifier's acknowledgment;
  it gates against hallucinated results.
- **Never** `allow_secrets=True` to bypass the pre-upload scan without
  explicit user OK. Never auto-apply an `llm_suggested_patch` unread.
- `permission_error` / any path refusal → STOP (defense-in-depth).
- `runner_died_mid_wait` → STOP; runner needs restart.
- Per-session submit cap hit → STOP; the user must restart the MCP.
- Keep the loop cheap: Tier-0 triage handles common fixes for ~tens of
  tokens; cap at 5 iterations.
