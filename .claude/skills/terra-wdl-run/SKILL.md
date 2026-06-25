---
name: terra-wdl-run
description: Author (or take) a WDL workflow, validate it, run it on Terra/Cromwell with DIRECT inputs, monitor to completion with an auto-fix loop, then email a verified report + NotebookLM-style audio explainer of the outputs. The MCP half is credentialed primitives only (no delete); this skill is the authoring + orchestration. Use when the user wants to run a WDL workflow (not a notebook) on Terra.
argument-hint: [wdl_path_or_spec] [--config namespace/name] [--email] [--audio]
allowed-tools: mcp-terra:terra_health, mcp-terra:terra_get_workspace, mcp-terra:terra_list_method_configs, mcp-terra:terra_register_method, mcp-terra:terra_create_method_config, mcp-terra:terra_submit_workflow, mcp-terra:terra_get_submission, mcp-terra:terra_get_workflow_outputs, mcp-terra:terra_render_audio_summary, mcp-terra:terra_send_run_report_email, Read, Edit, Bash, Task
---

# terra-wdl-run — run a WDL workflow on Terra (Cromwell)

Runs a WDL workflow on Terra with **direct/fixed inputs** (this workspace has
no data tables), monitors it, auto-fixes failures, and delivers a verified
report + optional audio explainer — the workflow analogue of
`terra-bugfix-loop`.

**Arguments:** `[wdl_path_or_spec] [--config ns/name] [--email] [--audio]`.
Pass a **WDL file path**, a **plain-English spec** (Claude authors the WDL), or
`--config namespace/name` to run an **existing** method config. If nothing is
clear, ask once.

## Division of labor (first principles)

The **MCP** is credentialed, gated, **no-delete** primitives only:
`terra_register_method` (Agora; append-only snapshots, secret-scanned),
`terra_create_method_config` (no-clobber), `terra_submit_workflow` (SPEND),
`terra_get_submission`, `terra_get_workflow_outputs`,
`terra_list_method_configs`. This **skill** is the judgment: authoring,
**womtool validation (Bash — not MCP, needs no Terra creds)**, input
assembly, the monitor + auto-fix loop, and the verified report/audio.

There is **no abort/delete** tool by design — to stop a running submission,
guide the user to the Terra UI.

---

## Phase 0 — Pre-flight
`terra_health` once: confirm `writes_allowed`, the `workspace_lock` matches,
`killswitch.tripped:false`, `audit_chain.ok:true`. Read `workspace_lock` for
`namespace`/`name`. If any fail, surface the SOP fix and STOP.

## Phase 1 — Obtain the WDL
- **Run-existing** (`--config ns/name`): skip to Phase 5 using that config.
  (`terra_list_method_configs(namespace, name)` lists choices.)
- **Author** (spec given): Claude writes the `.wdl` to a local file. Keep it
  minimal and correct; declare a `workflow` with explicit `input {}`.
- **Provided file**: `Read` it.

## Phase 2 — Validate locally (best-effort, no MCP)
If `womtool` is available on this machine, validate before publishing:
```bash
java -jar "$WOMTOOL_JAR" validate path/to.wdl     # or: womtool validate path/to.wdl
```
If `java`/`womtool` isn't installed, say so and proceed — Agora/Cromwell will
validate at register/submit time (just a slower feedback loop). Never block on
a missing local tool.

## Phase 3 — Register the method (authoring path)
`terra_register_method(method_namespace, method_name, wdl=<text>, synopsis=…)`
→ returns a new Agora **snapshotId** (append-only; the WDL is secret-scanned
before publish — if it refuses, surface the hits, do not work around). Use the
workspace namespace for `method_namespace` and a clear `method_name`.

## Phase 4 — Create the method config (direct inputs)
Assemble inputs as **literal expressions** (Rawls evaluates input strings):
a string → `"\"hello\""`, a number → `"42"`, a bool → `"true"`, a file →
`"\"gs://bucket/path\""`. Then:
```
terra_create_method_config(namespace, name,
  config_namespace=<ns>, config_name=<unique>,
  method_namespace=<ns>, method_name=<name>, method_version=<snapshotId>,
  inputs_json='{"WorkflowName.x": "\"hello\"", "WorkflowName.n": "42"}',
  root_entity_type="")          # EMPTY = direct/entity-less run
```
No-clobber: if the config name exists, pick a fresh one.

## Phase 5 — Submit (SPEND — confirm with the user)
`terra_submit_workflow(namespace, name, config_namespace, config_name)` —
leave `entity_type`/`entity_name` empty for the direct-input run. Confirm the
spend first. Capture the `submissionId`.

## Phase 6 — Monitor (auto-fix loop, cap 5)
Poll `terra_get_submission(namespace, name, submission_id)` until the
submission status is terminal (`Done`/`Aborted`) and read each workflow's
status. One line per check: `wf: status=Running (2/3 calls done)`.

- **All `Succeeded`** → Phase 7.
- **`Failed`** → read the workflow's failure messages. Fix by category:
  - WDL syntax/type error → edit the WDL, re-validate (Phase 2),
    **re-register** (new snapshot, Phase 3), **re-config** (new name, Phase 4),
    re-submit. (Agora is append-only — every fix is a new snapshot.)
  - bad input value/path → fix `inputs_json`, new config, re-submit.
  - missing Docker tool / runtime error → adjust the task `runtime`/`command`,
    re-register, re-submit.
  - quota / transient → surface to the user (don't loop on infra).
- **`Aborted`** (user stopped it in the UI) → STOP, surface state.

Cap at 5 fix iterations; then surface every attempt.

## Phase 7 — Results explainer + delivery
1. For each succeeded workflow, `terra_get_workflow_outputs(namespace, name,
   submission_id, workflow_id)`.
2. Compose **two artifacts** (same contract as the notebook loop):
   - **Report:** submission/workflow IDs, final statuses, each fix iteration
     (the error → root cause → the WDL/input change → new snapshot/config), and
     the output values + their GCS paths.
   - **Audio explainer script (NotebookLM-style):** what the workflow computed
     and what the key outputs MEAN, for a smart non-expert; ~30–90 s.
3. **Verify before sending** — spawn a verifier sub-agent (Task) that
   cross-checks BOTH artifacts against `terra_get_submission` +
   `terra_get_workflow_outputs`. It returns a ≥50-char acknowledgment naming
   concrete evidence (submission status, output values), or REFUSES.
4. **`--audio`:** `terra_render_audio_summary(job_id=<submission_id>, bucket_uri,
   summary_text=<script>, verification_acknowledgment=<ack>)` (needs Cloud TTS
   configured; if it 403s, skip audio and still send the report).
5. **`--email`:** `terra_send_run_report_email(subject, body=<report>,
   job_id=<submission_id>, verification_acknowledgment=<ack>)`. Recipient is
   hard-locked to the user's Terra email. If SMTP isn't configured the MCP
   writes a `.eml` file instead — tell the user it wasn't actually delivered.

## Robustness rules
- No abort/delete tool exists — to stop a submission, guide the user to the UI.
- Never bypass the WDL secret-scan in `terra_register_method`.
- Submit is SPEND — confirm before each submit; cap auto-fix at 5.
- Never send the report/audio without the verifier's acknowledgment.
- Workspace lock is enforced by the MCP; pass the locked namespace/name.
