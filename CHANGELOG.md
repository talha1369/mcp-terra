# Changelog

All notable changes to mcp-terra are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Controlled-access data-egress guard (NIH GDS / DUC).** A new
  `MCP_TERRA_CONTROLLED_ACCESS=1` mode refuses to return raw workspace DATA to
  the LLM — `terra_read_bucket_object` (object bytes) and `terra_get_entities`
  (data-table rows) — because controlled-access genomic data must not reach a
  public generative AI (GDS/DUC Non-Transferability). Designed to **not hinder
  lab-generated or public-database analysis**: it is **off by default**; even
  when on, a built-in **public reference-bucket allowlist** (gnomAD,
  broad-references, gcp-public-data, gatk-*, hail-*, 1000genomes, …) and
  operator-certified `MCP_TERRA_DATA_EGRESS_ALLOW` buckets are still readable;
  metadata (`terra_get_bucket_object_metadata`, `terra_list_data_tables`), all
  diagnosis tools, and the on-VM analysis loop are unaffected (data never leaves
  Terra through the MCP). Refusals are fail-loud. `terra_health` and the startup
  banner surface the posture; see [docs/compliance.md](docs/compliance.md) for
  the policy mapping (GDS/DUC + NIST 800-171 + the self-hosted-model path).

- **Consolidated run record + multi-channel completion delivery, with a
  metadata spec.** A completed run now produces ONE provenance-bearing record
  (`mcp_terra_jobs/<run_id>/run_record.json`) that the email, Slack, and audio
  channels all render from — so the channels agree and the verifier gate covers
  all three at once.
  - **`docs/metadata.md`** — v1 run-record schema, projecting W3C PROV-O,
    RO-Crate-lite, Dublin Core / schema.org / Bioschemas, and GA4GH; with
    integrity, sensitivity-classification, and schema-versioning rules.
  - **`terra_write_run_record`** — the agent supplies the descriptive body; the
    MCP STAMPS the un-forgeable provenance (schema version, MCP version +
    code-integrity digest, the authenticated user, the locked workspace, the
    audit-chain head), secret-scans it, and writes it no-clobber.
  - **`terra_notify_slack`** — a second completion ping alongside email. The
    webhook is hard-locked to `MCP_TERRA_SLACK_WEBHOOK` (no `url` parameter, so
    it can't post to an arbitrary host); host/https-validated; the payload is
    secret-scanned before send.
  - **Audio explainer** stays `terra_render_audio_summary` (Cloud TTS, with the
    `X-Goog-User-Project` quota-project header) — render "what the results mean"
    from the run record's verified `results[]`. A **macOS `say` fallback** makes
    audio work with no Cloud-TTS IAM (renders a local `.m4a`).
  - **Audio email attachment** — `terra_send_run_report_email(attach_audio=True)`
    attaches the run's OWN audio explainer. The path is derived from `job_id` +
    the locked bucket and fixed to `summary.{m4a,mp3}` (never an arbitrary
    path), audio-MIME-locked, and size-capped — so the long-standing "no
    arbitrary attachments" anti-exfil invariant holds.
  - **True Slack file upload** — `terra_notify_slack(audio_job_id=…)` uploads
    the run's audio as a real Slack attachment via the bot Web API
    (`files.getUploadURLExternal` → bytes → `files.completeUploadExternal`),
    when `MCP_TERRA_SLACK_BOT_TOKEN` + `MCP_TERRA_SLACK_CHANNEL` are set (a
    Slack app with `files:write`). The bot token + channel are env-locked
    (no tool params), the file path is derived from the job (never arbitrary),
    the comment is secret-scanned, and the size is capped. Without a bot token
    it falls back to the webhook text + a note. Per-user/collaborator config —
    each sets their own token + channel. `MCP_TERRA_SLACK_CHANNEL` accepts
    MULTIPLE comma/space-separated targets — a DM **and/or** a channel: a user
    id `U…` is opened as a DM via `conversations.open` (needs the `im:write`
    scope; no `/invite`), a channel id `C…/G…` posts to that channel (bot must
    be invited). Each target is delivered independently and its success/failure
    surfaced (partial delivery is never hidden).

- **Read-only superset of `broadinstitute/fiss-mcp`** — nine new READ-class
  tools (no spend, no write, no destruction) close fiss-mcp's read-side lead so
  this MCP is a strict superset of its reads (it already exceeds fiss-mcp on
  runtimes, the notebook run/fix/report loop, WDL authoring, and every safety
  dimension):
  - `terra_list_data_tables` — workspace entity types + per-table metadata.
  - `terra_get_entities` — paged rows of a data table (`page_size` clamped 1..500
    to protect agent context).
  - `terra_list_submissions` — every submission in the workspace.
  - `terra_get_workflow_metadata` — Cromwell metadata; the (potentially huge)
    per-call tree is replaced by a context-cheap `callsSummary` unless
    `include_calls=True`.
  - `terra_get_workflow_cost` — cost of one workflow execution.
  - `terra_get_method_config` — read a method config's contents (the read
    counterpart to `terra_create_method_config`, for pre-submit verification).
  - `terra_read_bucket_object` — byte-range *head* read of an object (default
    100 KiB, hard ceiling 10 MiB) via `gsutil cat -r 0-N`; never downloads the
    whole object.
  - `terra_get_bucket_object_metadata` — `gsutil stat` for one object.
  - `terra_get_batch_job_status` — Google Batch job state for Cromwell-on-Batch
    infra triage; always returns a copy-pasteable `gcloud logging read` command.
  - **Not adopted** (would break no-destruction): fiss-mcp's `abort_submission`
    and entity-overwrite, and ops-terra-utils' delete scripts. Each gets a
    read-only/"plan + UI steps" counterpart instead.
- **Publication-readiness hardening** (for sharing as a public repo):
  - **Secret-scanning everywhere** — `detect-secrets` added as a fail-fast CI
    gate and a `pre-commit` hook, with a committed, audited `.secrets.baseline`
    (the only entries are confirmed test fixtures). A credential can no longer
    enter git history locally or pass CI.
  - **Community/health files** — `CODE_OF_CONDUCT.md` (Contributor Covenant),
    `CODEOWNERS`, a PR template with a safety checklist, and issue templates
    that route security reports to private disclosure.
  - **Ruff config** — a curated `[tool.ruff.lint]` in `pyproject.toml`; the
    default `E`/`F` rule set stays on (real defects still fail), only the three
    cosmetic rules matching the deliberate house style are disabled.
  - **README badges** + an accurate, regenerated tool reference and
    attack-class table (SECURITY.md now matches the suite: 244 tests / 34
    classes / 39 tools).
- **Seamless on-boot runner** — `terra_create_runtime` now installs a
  Leonardo `startUserScriptUri` (`start_runner.sh`) that launches the
  on-VM notebook runner on **every** start (initial create AND every
  resume after an auto-pause). A freshly created or resumed VM is never
  left idle-without-a-runner. No `gcloud compute ssh`, no
  `compute.instances.use` IAM, no manual Jupyter-terminal paste.
  - The runner HMAC secret is delivered via Leonardo
    `customEnvironmentVariables` (encrypted at rest, injected into the VM
    env on every start). It never touches GCS, a process command line, or
    an audit-log entry — the correct trust boundary for a shared
    workspace bucket.
- **Heartbeat identity-binding** — the on-VM runner writes
  `<epoch> <runtime_name>` to its heartbeat, and the atomic create verifies
  the fresh heartbeat belongs to the runtime it just created (defends
  against a *different* runner on the same bucket looking live). Implausibly
  future-dated heartbeats are rejected rather than read as fresh.
- **Content-addressed boot scripts** — the runner + start scripts upload as
  `<name>.<sha256>.sh` (no overwrite, no destruction); the VM boots the
  exact pinned version, and `terra_create_runtime` verifies an existing
  object's content before reuse (fail-closed on mismatch).
- **End-to-end "run my Terra notebook" skill** (`terra-bugfix-loop`,
  consolidated) — provision the right-sized VM → run → auto-fix bugs
  (Tier-0 triage) → verified report + an optional NotebookLM-style audio
  explainer, emailed. Runtime **right-sizing** is folded in as a guided
  phase (detect mismatch → guide the user through the Terra UI change,
  persistent disk always kept → recreate); the standalone right-size skill
  was removed in favor of this one.
- **Cloud-TTS quota project** — `terra_render_audio_summary` sends an
  `X-Goog-User-Project` header (from `MCP_TERRA_TTS_QUOTA_PROJECT`, else the
  locked workspace project) so Cloud TTS works under user credentials.
- **WDL / Cromwell workflow primitives** (v1, direct-input) — `terra_list_method_configs`,
  `terra_submit_workflow` (SPEND, workspace-lock-enforced, entity-less direct
  inputs), `terra_get_submission`, `terra_get_workflow_outputs`, plus the
  authoring path `terra_register_method` (Agora; append-only snapshots,
  secret-scanned before publish) and `terra_create_method_config` (no-clobber).
  **No submission abort/delete** primitive — stop a run in the Terra UI.
- **On-VM Claude Code for live coding** — `terra_create_runtime`
  (`install_claude_code=True`, default) has its `startUserScriptUri`
  best-effort install Claude Code on every VM (backgrounded *after* the runner
  launch so it never delays the heartbeat; idempotent; to `/home/jupyter` on
  the persistent disk). Auth stays per-user (`claude` login in a Jupyter
  terminal). Set `install_claude_code=False` / `MCP_TERRA_INSTALL_CLAUDE=0` to skip.
- **Email delivery — three modes.** A: no credentials → `.eml` file. B:
  authenticated send (HOST + USER + app-password). **C (new): no-password
  relay** — `MCP_TERRA_SMTP_HOST` + explicit `MCP_TERRA_SMTP_RELAY=1` sends via
  a Workspace/IP-authorized relay without logging in. A merely-forgotten
  password never silently relays (relay needs the explicit opt-in; else `.eml`).

### Changed

- **`terra_fetch_url` action class reconciled** — it is `WRITE_SAFE`-gated
  (a network side effect), so its annotation is now `ANN_WRITE_IDEMP`
  (`readOnlyHint=False`, idempotent) to match the `_pre` gate and docstring,
  instead of mis-claiming read-only to clients.
- **Single-source version** — `pyproject.toml` now derives the version
  dynamically from `mcp_terra.__version__` (one true source) instead of
  hardcoding a second copy that could drift.
- **`datetime.utcnow()` → timezone-aware `datetime.now(timezone.utc)`** across
  `policy.py`/`safety.py` (no more 3.12 deprecation warnings; timestamp output
  is byte-identical, so the audit HMAC chain is unaffected).
- **Docs reconciled with the code** — fixed the README install path (Claude
  Code uses `claude mcp add`, not a `settings.json` `mcpServers` block), the
  `install.sh` next-steps (seamless auto-start runner, not the legacy manual
  flow), and the stale test/tool counts in SECURITY.md and SOP.md.
- **`terra_create_runtime` is now ATOMIC** (when `auto_start_runner=True`,
  the default). It returns success only once Leonardo reports the runtime
  `Running` **and** the runner has posted a fresh heartbeat (< 30 s). If
  the heartbeat never arrives within ~5 min of `Running`, it fails loud
  with the on-VM runner-log tail — no more "VM up, runner mystery". Pass
  `auto_start_runner=False` for the previous fire-and-forget behavior.
- `terra_start_runner_on_vm` is now a **fallback for legacy runtimes**
  created before this change; new runtimes never need it.
- **Secrets never leave the trust boundary** — `terra_get_runtime` /
  `terra_list_runtimes` redact every non-allowlisted
  `customEnvironmentVariables` value (Leonardo echoes the field back);
  Leonardo error bodies redact the runner secret; the runner/start scripts
  pass secrets via shell ENV-assignment prefixes, never an `env VAR=val`
  argv (which would expose them in `/proc/<pid>/cmdline`).

### Fixed

Bugs surfaced only by **end-to-end execution on a live Terra VM** (unit
tests exercise the templates in isolation, so these were latent):

- **macOS `gsutil -m` deadlock** — `bucket.upload_file`/`download_file` used
  `gsutil -m cp`, which hangs under fork on macOS; every upload/download
  (including notebooks) would stall the full 600 s timeout then fail.
  Dropped `-m` (kept `-n` no-clobber).
- **Runner consumed no jobs** — the pending-spec filter regex was
  lowercase-only, but job_ids are `<YYYYMMDD>T<HHMMSS>Z-…` (uppercase T/Z),
  so every spec was rejected; the runner posted heartbeats but never picked
  anything up. Allow uppercase.
- **Runaway re-execution** — a permanent `result.json` upload failure left
  the job unrecorded, re-running the (succeeding) notebook forever (rc=0
  never trips the fail-streak guard). Record the processed id before
  continuing.
- **`terra_list_runtimes` returned `[]`** — it filtered with a non-existent
  Leonardo `project` label; now filters client-side on the real top-level
  `googleProject` field.
- **Job stuck at `running`** — `status.txt` was written no-clobber so it
  never transitioned off `running`, and `terra_get_notebook_job_result`
  keyed terminal detection on it. It now keys on the **signed `result.json`**
  (the authority); `status.txt` writes overwrite; and a status-value/path
  key collision in the result payload is fixed (`status_txt` exposes the
  path).

### Security / invariants

- **Adversarial-review hardening (Codex)** — fixed 6 findings against the
  run-record / Slack / desktop / audio work:
  - **CRITICAL** — `terra_download_from_bucket(version_existing=True)` skipped
    the local-path policy when the target already existed, so it could rename
    and overwrite a *blocked* target (`~/.ssh/id_rsa`, a shell rc, a symlink, a
    device node). New `safety.assert_local_write_policy` enforces the blocklist
    + symlink + non-regular checks **regardless of existence**; `version_existing`
    is no longer an escape hatch.
  - **HIGH** — the audio explainer now runs the full secret scanner (raw +
    NFKC) and fails closed before any TTS/persist (the prior ya29-only check
    let AWS keys / GitHub PATs / Slack tokens / PEM keys through an external
    channel); the run-record agent identity is now built from authoritative
    data only and fails closed on unresolved identity (was caller-forgeable on
    auth failure).
  - **MEDIUM** — the run record's embedded `run_id` is bound to its storage
    path; the local metadata temp blob is unlinked in `finally`; and
    `terra_write_run_record` does a no-clobber **preflight** so it can't report
    success while `gsutil cp -n` silently skipped.
  - Guarded by 10 new regression tests (`CC-CodexFixes`).
- **Adversarial-review hardening (Codex) — round 2** — 6 more findings on the
  attachment/delivery work:
  - **CRITICAL** — `assert_local_write_policy` matched blocklist prefixes with a
    trailing slash, so EXACT protected directories (`/usr/bin`, `/bin`,
    `/sbin`, `/System`, `/var/db`, `/var/root`, …) slipped past and
    `version_existing` could rename them. Fixed: exact-or-under path matching;
    the download tool also refuses `version_existing` on a directory.
  - **HIGH** — the audio email/Slack attachment had no provenance (a caller
    could stage bytes at `mcp_terra_jobs/<job>/summary.{mp3,m4a}` via a generic
    upload). Fixed: that path is now RESERVED — `terra_upload_to_bucket` refuses
    it, so only `terra_render_audio_summary` can produce it. The attachment size
    cap now runs as a `gsutil stat` **preflight before download** (no
    unbounded download/read).
  - **MEDIUM** — Slack upload now **fails loud** when all targets fail (raises;
    `partial_failure` flag when mixed); audio render preflights BOTH
    `summary.{mp3,m4a}` before sending text to the backend; the run record is
    **read back (md5)** after upload so a `cp -n` skip/race can't report a
    write that didn't persist.
  - Guarded by 7 new regression tests (`CC-CodexFixes2`).
- **No delete primitive, by design** — no tool (and no `leo_delete_runtime`
  at any layer) deletes a runtime or persistent disk; teardown is the user's
  action in the Terra UI ("Keep persistent disk"). The MCP detects a
  wrong-sized runtime and *guides*; it never destroys. Guarded by tests.
- **MCP vs. skill boundary** — the MCP is the credentialed, safety-gated
  *primitive* layer (no judgment, no destruction); Claude *skills* hold the
  judgment/orchestration and cannot exceed the MCP's capability envelope, so
  a buggy or prompt-injected skill still cannot delete data.
- **Workspace-bucket lock** — `mcp_terra_jobs/` (boot scripts + heartbeat)
  must be owner-write-only; a co-member with write access there could tamper
  with boot artifacts (see SOP).

## [0.2.0] — 2026-06-25

State-of-the-art hardening release. Tightens the safety model in
several measurable axes: schema-version negotiation, structured error
envelopes, operator-visible health surface, bounded runaway loops, and
non-streaming-fetch resource ceilings.

### Added

- **`terra_health`** — operator-visible health probe. Returns the
  effective configuration snapshot (writes enabled / workspace lock /
  rate-limit budget / kill-switch status / runner-secret presence) so an
  agent or human can confirm the server's posture without having to
  call a write tool to discover it.
- **`terra_send_run_report_email`** — end-of-run report mailer with a
  hard-locked recipient (= the authenticated Terra user, no `to` param)
  and a verifier-acknowledgment gate. Refuses blank approvals
  (acknowledgment must be >= 50 chars and describe concrete evidence).
- **`terra_get_run_log`** — bounded read of the runner stderr/stdout
  the email tool cross-checks against, exposed so a verifier agent can
  inspect raw evidence rather than trusting the report.
- **`wait_for_complete`** — synchronous-wait option on
  `terra_get_notebook_job_result` for clients that prefer a single
  blocking call to a polling loop. Bounded by `timeout_minutes` and the
  per-minute call rate.
- **`MCP_TERRA_FAIL_STREAK_LIMIT`** (default 5, range 1..50) — auto-halts
  a runner VM after N consecutive failed jobs. Defends against
  runaway-cost loops where an agent keeps resubmitting a broken
  notebook.
- **Tool annotations / schema version** — every tool advertises a
  `schemaVersion` and action class (READ / WRITE-SAFE / SPEND). Clients
  on an older schema get `E_SCHEMA_VERSION_MISMATCH` rather than a
  silent contract drift.
- **Structured error envelope** — every error path returns
  `{ok: false, error: {code, message, retryable, ...}}` with a stable
  `code` enum. See `docs/error_codes.md` for the full catalog and the
  recommended agent reaction for each code.
- **`parameters_json` bounds** — the notebook job submitter rejects
  parameter blobs above a fixed byte ceiling and refuses non-JSON
  payloads, preventing both DoS-by-huge-spec and eval-injection via
  surprise types.
- **Streaming `terra_fetch_url`** — read response bodies incrementally
  with a byte ceiling rather than buffering the whole body. Defends
  against agent-driven memory exhaustion when a URL surprises with a
  large response.
- **`requirements.lock`** — fully resolved transitive dep set with
  sha256 hashes for every artifact. Install with
  `pip install --require-hashes -r requirements.lock`.
- **CI pipeline** (`.github/workflows/ci.yml`) — runs the comprehensive
  security test suite, ruff lint, pip-audit (strict), and SBOM
  generation on every PR. Every third-party action pinned by commit SHA.
- **Dockerfile pinning** — base image pinned by sha256 digest; apt
  packages version-pinned where the Debian archive supports it.

### Changed

- **Version unification** — package `__version__`, the MCP handshake
  `serverInfo.version`, and the schema version reported by tool
  annotations now all derive from `pyproject.toml`. No more drift
  between "what the package says" and "what the server advertises".
- **Kill-switch semantics** — auto-trip threshold and window are now
  configurable via `MCP_TERRA_KILL_REFUSAL_THRESHOLD` and
  `MCP_TERRA_KILL_REFUSAL_WINDOW_SEC`. Default behavior unchanged.

### Security

- All file-write paths now resolve symlinks before the blocklist check
  (closes a symlink-bypass on the local-path guard).
- HMAC spec signing covers a wider field set (job_id, submitted_at,
  notebook_gcs, bucket_uri, parameters_json hash); replay defense
  unchanged (`MCP_TERRA_SPEC_MAX_AGE_SEC`).

## [0.1.0] — 2026-06-24

Initial release of the MCP server for Terra.

### Added

- Read tools: `terra_whoami`, `terra_list_workspaces`,
  `terra_get_workspace`, `terra_list_runtimes`, `terra_get_runtime`,
  `terra_list_bucket`.
- Write tools (gated by `MCP_TERRA_ALLOW_WRITES=1`):
  `terra_start_runtime`, `terra_stop_runtime`, `terra_create_runtime`,
  `terra_upload_to_bucket`, `terra_download_from_bucket`.
- Notebook bug-fix loop: `terra_install_notebook_runner`,
  `terra_submit_notebook_job`, `terra_get_notebook_job_result`.
- Kill-switch: `terra_killswitch_status`, `terra_killswitch_trip`
  (manual trip; auto-trip on refusal-rate threshold).
- Hard guards: no destruction primitive, no overwrites, local-path
  blocklist, workspace-bucket allowlist, audit trail to stderr.
- HMAC-signed runner spec contract for notebook execution.
- Hardened Dockerfile (non-root user, multi-stage build).
- Comprehensive security test suite (`tests/test_security_comprehensive.py`).
