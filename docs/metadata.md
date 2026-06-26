# mcp-terra metadata & run-record specification

This document defines the metadata the MCP records for a Terra run, the
standards it aligns to, and the `run_record.json` schema. It is the contract
that the email report, the Slack notification, and the audio explainer all
render from — one verifiable source of truth per run.

> Status: **v1 (schema_version 1)**. Additive evolution only (see
> [§ Schema versioning](#schema-versioning)).

---

## 1. Principles

1. **Provenance first ("lab notebook").** Every run answers *who / what / when
   / which version* without guesswork: the authenticated Terra user, the input
   (by content hash), the MCP version + code-integrity hash, the runtime, and
   UTC timestamps.
2. **Verifiable, not merely descriptive.** Metadata references checksums
   (`md5`/`crc32c`), the HMAC-signed `result.json`, and the audit hash-chain —
   so a reviewer can *check* the record, not just read it.
3. **Align to standards; don't invent.** See [§ 3](#3-standards-alignment).
4. **Minimal & purposeful.** Every field has a consumer (email / Slack / audio /
   audit / reproducibility). No speculative fields; bounded retention.
5. **Sensitivity-aware by construction.** Records live in the secure workspace
   bucket; secrets/PII never enter metadata. See [§ 6](#6-sensitivity).
6. **Schema-versioned & evolvable.** Every blob carries `_schema_version`;
   changes are additive.

---

## 2. What already exists (don't duplicate)

| Layer | Metadata already emitted |
|---|---|
| Per job | `result.json` (HMAC-signed), `status.txt`, `runner.stdout/stderr`, `executed.ipynb`, `spec.json.consumed` under `mcp_terra_jobs/<job_id>/` |
| Tool output | `_schema_version`, `_server_version` envelope on every response |
| Tool protocol | `ToolAnnotations` (readOnly/destructive/idempotent/openWorld) + action class (READ/WRITE-SAFE/SPEND) |
| Errors | Stable structured envelope `{ok:false, error:{code,…}}` — see [error_codes.md](error_codes.md) |
| Integrity | HMAC audit hash-chain; code-integrity sha256 (via `terra_health`) |

The **run record** (this spec) is the missing piece: it ties the *iterations*
of one bug-fix loop into a single, portable, provenance-bearing object.

---

## 3. Standards alignment

The run record is a pragmatic projection of established standards — enough to be
interoperable and credible, without heavyweight tooling:

- **W3C PROV-O** — the run is a PROV bundle: `Agent` (the MCP + the Terra user),
  `Activity` (each job execution, each fix), `Entity` (input notebook/WDL,
  outputs). Fields map to `prov:wasGeneratedBy`, `prov:used`,
  `prov:wasAssociatedWith`, `prov:wasDerivedFrom`.
- **RO-Crate (lite)** — the `mcp_terra_jobs/<run_id>/` directory is a Research
  Object: `run_record.json` is its manifest, listing every artifact with a
  checksum and a role. (Not a full `ro-crate-metadata.json` yet; the field
  names are chosen so a future exporter is mechanical.)
- **Dublin Core / schema.org / Bioschemas** — descriptive fields
  (`title`, `created`, `creator`, `description`) use DC/schema.org semantics.
- **GA4GH** — Terra is GA4GH-aligned; the run-state vocabulary
  (`QUEUED/RUNNING/COMPLETE/EXECUTOR_ERROR`) and the run/task shape mirror
  WES so workflow and notebook runs read consistently.

A future `terra_export_ro_crate` tool can render this record to a strict
RO-Crate / PROV-O document; v1 keeps a single self-describing JSON.

---

## 4. The `run_record.json` schema

**Location:** `gs://<workspace-bucket>/mcp_terra_jobs/<run_id>/run_record.json`
(no-clobber write; versioned on update). `run_id` is the first job's id (e.g.
`20260625T172041Z-a877749a`) so the record sorts/locates with its jobs.

```jsonc
{
  "_schema_version": 1,
  "record_type": "mcp_terra_run_record",

  // ── identity / addressing ──────────────────────────────────────────────
  "run_id": "20260625T172041Z-a877749a",
  "title": "MCP-Terra smoke test",                 // DC: title
  "created": "2026-06-25T18:02:47Z",               // DC: created (UTC ISO-8601)

  // ── agent (PROV: wasAssociatedWith) ────────────────────────────────────
  "agent": {
    "mcp_version": "0.2.0",
    "code_integrity_digest": "sha256:<digest-of-the-module-hash-set>",
    "terra_user_subject_id": "<sam-subject-id>", // stable id, not PII
    "terra_user_email": "<email>",               // PII — sensitivity-gated (§6)
    "orchestrator": "terra-bugfix-loop"          // skill that drove the run
  },

  // ── workspace context ──────────────────────────────────────────────────
  "workspace": {
    "namespace": "your-namespace",
    "name": "your-workspace",
    "google_project": "terra-00000000",
    "bucket": "gs://fc-secure-…"
  },

  // ── subject = the entity being run (PROV: used) ────────────────────────
  "subject": {
    "kind": "notebook",                          // notebook | wdl
    "name": "all_scprs_sex_heldout_validation.ipynb",
    "input_gcs": "gs://…/notebooks/….ipynb",
    "input_sha256": "<sha256 of the submitted input>"
  },

  // ── runtime (PROV: used; reproducibility) ──────────────────────────────
  "runtime": {
    "runtime_name": "scprs-train",
    "machine_type": "n1-standard-4",
    "gpu_type": "", "num_gpus": 0,
    "tool_docker_image": "<image ref or ''=Terra default>"
  },

  // ── outcome summary ────────────────────────────────────────────────────
  "outcome": "succeeded",                         // succeeded | failed | aborted
  "started_at": "2026-06-25T17:20:41Z",
  "completed_at": "2026-06-25T18:02:47Z",
  "duration_sec": 2526,
  "iteration_count": 2,
  "bugs_fixed": 1,

  // ── iterations (PROV: each is an Activity) ─────────────────────────────
  "iterations": [
    {
      "n": 1,
      "job_id": "20260625T172041Z-a877749a",
      "status": "FAILED",                         // GA4GH-style state
      "rc": 1,
      "duration_sec": null,
      "failure": {
        "cell_index": 3,
        "error_type": "NameError",
        "message": "name 'pd' is not defined",
        "triage_category": "name_error"           // from bug_triager
      },
      "fix": {
        "applied_by": "claude",
        "summary": "added 'import pandas as pd'",
        "diff": "@@ cell 3 @@\n+import pandas as pd"
      },
      "spec_signature": "hmac-sha256:<sig>",       // integrity / provenance
      "artifacts": [
        { "role": "executed_notebook",
          "gcs": "gs://…/20260625T172041Z-a877749a/executed.ipynb",
          "size_bytes": 1234, "md5": "<b64>", "crc32c": "<b64>" },
        { "role": "result", "gcs": "…/result.json", "md5": "…" },
        { "role": "stderr", "gcs": "…/runner.stderr", "md5": "…" }
      ]
    },
    {
      "n": 2,
      "job_id": "20260625T180228Z-7cf9ccd7",
      "status": "COMPLETE",
      "rc": 0,
      "fix": null,
      "spec_signature": "hmac-sha256:<sig>",
      "artifacts": [ /* … */ ],
      "results": [                                  // optional, VERIFIED outputs
        { "name": "pearson_r", "value": "0.9962", "source": "stdout" },
        { "name": "mean_y",    "value": "101.30", "source": "stdout" },
        { "name": "slope",     "value": "1.985",  "source": "stdout" }
      ]
    }
  ],

  // ── final outputs (RO-Crate manifest of what to keep/share) ────────────
  "outputs": [
    { "role": "executed_notebook",
      "gcs": "gs://…/20260625T180228Z-7cf9ccd7/executed.ipynb",
      "size_bytes": 2744, "md5": "<b64>", "crc32c": "<b64>" }
  ],

  // ── verification (anti-hallucination gate) ─────────────────────────────
  "verification": {
    "verified": true,
    "method": "independent verifier agent vs runner logs + result.json",
    "acknowledgment_sha256": "sha256:<hash of the ack string>"
  },

  // ── deliveries (which channels rendered this record) ───────────────────
  "deliveries": {
    "email": { "sent": true, "transport": "smtp", "recipient_locked": true },
    "slack": { "sent": false, "reason": "no webhook configured" },
    "audio": { "rendered": false, "reason": "cloud-tts IAM not granted",
               "gcs": null }
  },

  // ── integrity & classification ─────────────────────────────────────────
  "audit_chain_ref": { "last_line_hmac": "sha256:<hmac>" },
  "sensitivity": "fc-secure"                       // see § 6
}
```

### Field rules

- **Timestamps**: UTC, ISO-8601, `Z` suffix. (Matches the audit log.)
- **Checksums**: `md5`/`crc32c` are GCS's own base64 values (from
  `terra_get_bucket_object_metadata` / `gsutil stat`) — no recomputation.
- **`results[]`**: only populated with values that were *verified* against the
  executed notebook / log. Never fabricated; absent if not verifiable.
- **`diff`**: a minimal, human-readable cell/line diff — enough to audit the
  change, not the whole file.
- **Unknown / not-applicable**: use explicit `null`, never omit a documented key.

---

## 5. Integrity & provenance

- The record references each job's **HMAC-signed** `result.json` and
  `spec_signature` — so the chain from *submitted spec* → *executed output* is
  cryptographically anchored, not asserted.
- `agent.code_integrity_digest` pins the exact MCP code that produced the run
  (the same hashes `terra_health` reports).
- `verification.acknowledgment_sha256` binds the record to the verifier's
  evidence statement without re-storing free text that could be edited later.
- `audit_chain_ref.last_line_hmac` ties the record to the tamper-evident audit
  log position at write time.

---

## 6. Sensitivity

- **Classification** (`sensitivity`): `fc-secure` (default for FireCloud secure
  buckets) | `restricted` | `internal` | `public`.
- **Records live in the secure workspace bucket** — never in the public Git
  repo, never echoed to an unauthenticated channel.
- **Never in metadata**: OAuth tokens, the runner HMAC secret, app passwords,
  PEM keys, or any value the secret-scanner would flag (the scan + output
  redaction already enforce this on every write path).
- `terra_user_email` is PII: included in the in-bucket record (the user owns
  their bucket) but **redacted** from any external delivery body except the
  recipient-locked email (which goes only to that same user).

---

## 7. Schema versioning

- Every metadata blob carries `_schema_version` (integer).
- **Additive only**: new optional keys may be added within a major version;
  existing keys never change meaning or type; removed keys are tombstoned in
  this doc, not silently dropped.
- A consumer on an older schema reads forward-compatibly (ignores unknown keys);
  a breaking change bumps the integer and is documented here.

---

## 8. Retention

- Run records and job artifacts persist in the workspace bucket **indefinitely**
  by default (no-delete principle — only the user removes data, via their own
  tooling). The MCP never garbage-collects.
- The local audit log rotates by size; rotation preserves the hash-chain seed.

---

## 9. How the channels consume the record

The completion record is rendered — never re-derived — by each channel, so all
three agree:

- **Email** (`terra_send_run_report_email`): the human-readable report.
- **Slack** (`terra_notify_slack`): a compact blocks message — outcome, bugs
  fixed, key results, links to the bucket artifacts.
- **Audio** (`terra_render_audio_summary`): a spoken "what the results mean"
  explainer from the `results[]` + interpretation, via Cloud TTS.

Because all three read the single `run_record.json`, a claim can't appear in one
channel and not another, and the verifier gate covers all of them at once.
