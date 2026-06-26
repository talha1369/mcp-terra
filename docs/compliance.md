# mcp-terra — controlled-access data & compliance posture

This document states how mcp-terra handles NIH controlled-access genomic data
and how it maps to the relevant policies. It is written for a security /
compliance reviewer.

## TL;DR

- The MCP is built for **diagnosis** — it returns **logs, workflow metadata,
  status, and cost**, which are not controlled-access *data*.
- The two tools that could return raw **data** to the LLM — `terra_read_bucket_object`
  (object bytes) and `terra_get_entities` (data-table rows) — are gated by the
  **controlled-access guard** (`MCP_TERRA_CONTROLLED_ACCESS`).
- The guard is **off by default** (so lab-generated and public-database work is
  never hindered) and **opt-in per deployment** for a controlled-access
  workspace. Even when on, **public reference buckets** and operator-certified
  **non-controlled buckets** are still readable.
- The **analysis itself runs on the Terra VM** — data never leaves Terra through
  the MCP. The MCP is not a data pipe to the LLM.

## The policies

- **NIH Genomic Data Sharing (GDS) Policy + Data Use Certification (DUC),
  Non-Transferability** (NOT-OD-25-081, NOT-OD-24-157): sharing controlled-access
  data — including via prompts to a public generative AI — violates
  Non-Transferability. → The MCP must not send controlled-access data to a
  public LLM.
- **NIST 800-171**: controlled data must be processed in a compliant
  environment. → Terra (where the compute runs) is the compliant environment;
  the MCP orchestrates it without extracting data.

## What the controlled-access guard does

`MCP_TERRA_CONTROLLED_ACCESS=1` (env, snapshot at startup):

| Tool | Guard OFF (default) | Guard ON |
|---|---|---|
| `terra_read_bucket_object` (object bytes) | allowed | **refused** unless the bucket is an EXACT-name public reference bucket or in `MCP_TERRA_DATA_EGRESS_ALLOW` |
| `terra_list_bucket` (object paths) | allowed | **refused** for non-public/non-allowlisted buckets (object paths can encode controlled identifiers) |
| `terra_get_entities` (data-table rows) | allowed | **refused** (rows can carry controlled attributes) |
| `terra_get_workflow_outputs` (output values) | allowed | **refused** (outputs are data + controlled paths) |
| `terra_get_workflow_metadata` | allowed | **reduced** to `status` + `callsSummary` (inputs/outputs/failures withheld) |
| `terra_get_method_config` (config contents) | allowed | **reduced** to method ref + entity type + param **counts** (direct-input values AND key names withheld — key names are operator-controlled free text that could encode identifiers) |
| `terra_get_submission` (per-workflow detail) | allowed | **reduced** to submission/workflow **ids + statuses** (entity names + failure messages withheld) |
| `terra_get_workflow_logs` (per-task stderr) | allowed (path bound to the queried workspace bucket) | **content AND paths withheld** (per-task status kept; stderr can print controlled data) |
| `terra_get_run_log` (stdout/stderr) | allowed | **content withheld** (paths + status kept; a notebook can print controlled data) |
| `terra_get_notebook_job_result` | allowed | **cell source/traceback withheld**; `status`/`rc`/failed-cell-index/triage-category kept. The Tier-2 external-LLM fix proposal is **disabled** (it would egress the traceback) |
| `terra_get_batch_job_status` (Google Batch job) | allowed | **reduced** to `status` + `status_events` + logging command (full job JSON withheld) |
| `terra_render_audio_summary` (text→speech) | allowed (auto backend) | **forced to local `say`** (on-host, offline); external Cloud TTS **refused** so summary text never leaves the host |
| `terra_get_bucket_object_metadata` (size/md5/type) | allowed | allowed (metadata, not data) |
| `terra_list_data_tables` (schema + counts) · `terra_list_submissions` · `terra_get_workflow_cost` | allowed | allowed (status/metadata, no row/scalar values) |
| `terra://health` **resource** (auto-read by clients) | minimal posture | minimal posture — **no** workspace lock / bucket / project / paths, **no** network probe (call the `terra_health` *tool* for the full audited snapshot) |
| notebook/WDL **run loop** (executes on the Terra VM) | allowed | allowed (data stays in Terra; the in-process deterministic triager still categorizes failures without egress) |

All matching is by **exact bucket name** — a controlled bucket *named* to look
public (e.g. `gnomad-public-impostor`) is **not** trusted.

Refusals are **fail-loud** with a clear message and remediation — never a silent
drop or placeholder.

This table is **enforced by a structural meta-test** (`CC-ControlledAccess3`):
the suite enumerates every data-returning tool and fails if any one of them
ships without a controlled-access check, so a future tool cannot silently
re-open an egress path.

### Not hindering lab-generated or public data

- **Default off** → for non-controlled (lab-generated, public) workspaces, leave
  it off; nothing changes.
- **Public databases** are never blocked: a built-in allowlist of public
  reference bucket-name prefixes (`gnomad`, `broad-references`,
  `gcp-public-data`, `genomics-public-data`, `gatk-*`, `hail-*`, `1000genomes`,
  `encode-public`, …).
- **Lab-open buckets**: certify them via `MCP_TERRA_DATA_EGRESS_ALLOW`
  (comma/space-separated bucket names).
- **Analysis is never blocked**: the guard only stops raw-**data** *egress to the
  LLM*; running notebooks/workflows on the Terra VM (where lab analysis happens)
  is unaffected.

## Recommended deployment for controlled-access data

1. Set `MCP_TERRA_CONTROLLED_ACCESS=1` and lock the workspace
   (`MCP_TERRA_WORKSPACE=ns/name`).
2. Run the **orchestrating agent against a self-hosted / NIST-800-171 model**
   (e.g. a local Llama in Broad's cloud) rather than a public LLM endpoint —
   per the Broad guidance, a self-hosted model that does not redistribute inputs
   is permitted. The MCP is model-agnostic; it never sends data anywhere itself.
3. Keep `MCP_TERRA_DATA_EGRESS_ALLOW` to *only* buckets you have certified as
   non-controlled.

## What the MCP deliberately does NOT do

- No delete/destroy/abort/overwrite primitive at any layer (data is never
  mutated or removed by the MCP).
- No arbitrary file exfiltration: email recipient is hard-locked to the
  authenticated user; Slack targets + bot token are env-locked; attachments are
  the run's own audio only.
- No credential handling beyond the user's own gcloud ADC; tokens are never
  logged.

## Honest limitations

- An agent that *already* has the user's gcloud credentials can call `gsutil`/
  Terra directly, outside the MCP — the guard constrains **this MCP's** egress,
  not the host. In the controlled-access threat model the right control is the
  self-hosted model (step 2) plus host/IAM controls, not the MCP alone.
- The guard classifies by bucket, not by record-level data sensitivity; it is a
  coarse, conservative gate (refuse-by-default for the locked workspace's data).
