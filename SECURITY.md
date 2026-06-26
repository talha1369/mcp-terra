# mcp-terra — Security Audit & Threat Model

Last audited: 2026-06-25.

## Threat model

| Threat | Defended? | Notes |
|---|---|---|
| Prompt-injection from external content reaching the agent | **Yes** (multiple layers) | Output sanitization, identifier validation, no destruction primitives. |
| Malicious actor with shell access + active gcloud auth | **Partially** | Read-only default, audit log, code-integrity hash. Attacker with shell can call `gsutil` / `curl` directly and bypass the MCP — this is an irreducible limitation. |
| Compromised dependency (mcp / httpx / pydantic) | Partial | Version bounds capped in pyproject.toml; no upper-cap defense vs supply-chain compromise within the allowed range. |
| Local TOCTOU between path check and file I/O | **No** | Window is small; race requires shell access (already in compromised-host scope). |
| Network-level MitM on Terra API calls | Inherited | TLS via httpx default; Terra services are HTTPS-only. |

## Audit history

### 2026-06-25 — initial v0.1.0 adversarial pass

8 findings, all addressed before initial use.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | **CRITICAL** | macOS case-insensitive FS bypass: `~/.SSH/id_rsa` not caught by blocklist (case-sensitive prefix match on a case-insensitive filesystem). | Fixed — `_norm()` lowercases on darwin/win32 before comparison; both `safe_local_read_path` and `safe_local_write_path` use it. Verified with `/Users/X/.SSH/foobar` and `/Users/X/.SsH/foobar` — both now refused. |
| 2 | HIGH | Audit log file opened without `O_NOFOLLOW`: an attacker who pre-creates `~/.mcp-terra/audit.log` as a symlink could redirect appends. | Fixed — `os.open(... O_WRONLY \| O_CREAT \| O_APPEND \| O_NOFOLLOW, 0o600)`. |
| 3 | HIGH | `CONFIG_DIR` symlink-follow: `.exists()` is true for a symlink, so a pre-created symlink at `~/.mcp-terra` could redirect all policy state. | Fixed — `_ensure_audit_dir` now refuses if `CONFIG_DIR.is_symlink()`, requires `st_uid == geteuid()`, and refuses if group/world perms cannot be tightened to `0o700`. |
| 4 | MEDIUM | Path length not validated for local paths (only identifiers). `MAX_PATH_LEN` constant was unused. | Fixed — `_check_path_length()` enforced in both `safe_local_read_path` and `safe_local_write_path`. |
| 5 | MEDIUM | Unicode lookalike injection markers bypass `_INJECTION_PATTERNS`: full-width `<｜im_start｜>` (U+FF5C pipes) reaches the LLM unredacted. | Fixed — `_redact_injection_markers` now NFKC-normalizes a SHADOW of the input first; if normalized form contains any sentinel, the entire output is replaced with `[MCP-REDACTED-OUTPUT]` plus a SHA-256 tag of the matched pattern (the tag does NOT echo the pattern itself). |
| 6 | MEDIUM | C1 control chars (0x80–0x9F) not stripped from outputs. C1 CSI (0x9B) is one byte of an ANSI escape sequence. | Fixed — `sanitize_output` now strips C0 (0x00–0x1F except `\n`, `\t`), DEL (0x7F), AND C1 (0x80–0x9F). |
| 7 | LOW | Dependency version bounds were lower-only (no upper caps). | Fixed — `pyproject.toml` now uses `mcp>=1.0.0,<2.0.0`, `httpx>=0.27.0,<1.0.0`, `pydantic>=2.0,<3.0`. Re-bump knowingly. |
| 8 | DISCLOSURE | `terra_upload_to_bucket(..., version_existing=True)` internally calls `gsutil mv`, which is a write that MOVES the destination object. Data is preserved under the versioned name; not data loss, but agent-driven movement. | Disclosed in docstring; gated behind `writes_allowed`; surfaces in audit log. Acknowledged as intended behavior. |

### 2026-06-25 — v0.2.0 + seamless-runner / WDL / read-superset passes

The hardening release and the subsequent feature work (seamless on-boot
runner, WDL primitives, the comprehensive-read read tools) each went through
adversarial review. Highlights:

| Source | Finding | Status |
|---|---|---|
| Adversarial security pass (seamless runner) | The on-VM Claude-Code installer inherited `MCP_TERRA_RUNNER_SECRET` from the environment. | Fixed — installer runs under `env -i` (scrubbed env); secret never reaches the install subprocess. Regression-tested (CC-SeamlessRunner). |
| Adversarial security pass (WDL) | `method_version` accepted a `bool` (`True` is an `int` subclass) → could bind Agora snapshot 1 unintentionally. | Fixed — explicit `isinstance(x, bool)` reject (CC-WDL). |
| Adversarial security pass (WDL) | A `deleteIntermediateOutputFiles` parameter could express a destructive intent. | Fixed — parameter removed; value hard-wired `False` at the client layer (CC-WDL). |
| **Live execution on a real Terra VM** | 6 latent bugs that only surface end-to-end (macOS `gsutil -m` deadlock; lowercase-only spec-filter regex rejecting all job ids; runaway re-exec on result-upload failure; `terra_list_runtimes` filtering on a non-existent label; job stuck at `running`; Cloud-TTS quota-project 403). | All fixed and regression-tested. See CHANGELOG "Fixed". |
| Two-reviewer publication-readiness review (security engineer + senior SWE) | Doc drift (stale test/tool counts, contradictory `terra_fetch_url` action class, version single-source fiction), missing secret-scanning in CI. | Fixed — counts regenerated from the suite; `terra_fetch_url` annotation reconciled with its gate; `pyproject` version made dynamic from `__init__`; `detect-secrets` added to CI + pre-commit with a committed baseline. |
| Adversarial security review (run-record / Slack / desktop / audio changes) | **CRITICAL**: `terra_download_from_bucket(version_existing=True)` skipped the local-path policy when the target existed → could rename/overwrite a blocked target (`~/.ssh/id_rsa`, shell rc, symlink, device). **HIGH**: audio text not secret-scanned before TTS/persist; run-record agent identity still caller-forgeable on auth failure. **MED**: run_id not bound to the record path; temp metadata blob left on disk; run-record no-clobber could report success without persisting. | All fixed — `safety.assert_local_write_policy` now runs regardless of existence (blocklist + symlink + non-regular); audio runs `secret_scan` (raw + NFKC) fail-closed; run-record agent block is built from authoritative data only and fails closed on unresolved identity; embedded run_id bound to the path; temp blob unlinked in `finally`; no-clobber preflight added. 10 regression tests (CC-HardeningFixes). |
| Adversarial security review — round 2 (attachment / delivery hardening) | **CRITICAL**: `assert_local_write_policy` matched blocklist prefixes with a trailing slash, so EXACT protected dirs (`/usr/bin`, `/bin`, `/System`, `/var/db`, …) slipped past and `version_existing` could rename them. **HIGH**: audio attachment lacked provenance (a caller could stage bytes at the summary path); attachment size cap ran only after a full download. **MED**: Slack upload could return success with zero deliveries; audio render checked no-clobber after the TTS side-effect; run-record no-clobber stayed racy. | All fixed — exact-or-under path matching (+ refuse `version_existing` on a directory); reserved `summary.{mp3,m4a}` path blocked from generic upload (provenance by construction); size preflight via `gsutil stat` before download; Slack raises when ALL targets fail (partial_failure flag otherwise); audio render preflights BOTH extensions before rendering; run-record read-back md5 verify after upload. 7 regression tests (CC-HardeningFixes2). |
| Adversarial security review — round 3 (controlled-access completeness) | **CRITICAL**: with `MCP_TERRA_CONTROLLED_ACCESS=1`, `get_run_log` + `get_notebook_job_result` still egressed runner stdout/stderr + cell traceback (a notebook can print controlled data). **HIGH**: `get_workflow_outputs`/`get_workflow_metadata` returned Rawls values/outputs uncovered by the guard; the public-bucket allowlist used name-PREFIX trust (a controlled bucket named `gnomad-public-impostor` was allowed). **MED**: audio render reported success without read-back after `cp -n`. | All fixed — the guard now covers every egress path: run-log content withheld, job-result source/traceback withheld + Tier-2 ext-LLM disabled, workflow outputs refused, metadata reduced to status+summary; the public allowlist is EXACT-name only; audio render read-back md5 verify. 6 regression tests (CC-ControlledAccess2) that execute the bypasses. |
| Adversarial security review — round 10 (re-review of round-9) | **HIGH×3**: the round-9 `cp -n` + read-back claim was NOT atomic (two VMs could both win); only `REFUSED` was treated terminal, so a same-runtime restart could re-execute a completed-but-not-`.consumed` job; `terra_write_run_record` (allowlisted no-data) actually returned the FULL enriched record (workspace ids + caller body). **MED×3**: `create_runtime`'s heartbeat-FAILURE raise leaked the bucket-derived `hb_path` + runner log tail; `terra_health`'s subtractive projection left absolute local paths (`kill_file`/`audit_log`), the domain sample, code hashes, and the full tools index; `get_workflow_cost` kept remote field NAMES (a numeric field whose key encodes an id leaked). | All fixed — the runner claim is now a **real atomic create-if-absent** via the GCS generation precondition (`ifGenerationMatch:0`) with a **compare-and-swap stale-claim reclaim** (no double-execution, dead owners recoverable); durable terminal markers now cover `succeeded`/`FAILED*` + an existing `result.json` (no restart re-execution); `write_run_record` returns a minimal ack; `create_runtime` errors are path-redacted in guard mode; `terra_health` is rebuilt from an explicit booleans/counts/status **allowlist**; `get_workflow_cost` filters by a cost-key allowlist (drops identifier-bearing keys). 33/43 tools guarded; +5 regression/sentinel tests. |
| Adversarial security review — round 9 (re-review of round-8) | **HIGH×3**: the round-8 `REFUSED` status-skip wasn't an ATOMIC claim — two runners (two VMs on one bucket) could both pick up the same pending spec before any terminal status existed → double-execution/double-spend; `terra_create_runtime`'s auto-start "ready" block still returned the (lock-derived) `bucket_uri`; `terra_health` (a directly-callable `_NO_DATA` tool) returned the full `workspace_lock` + heartbeat/bucket paths + sampled IAM writer principals. **MED×2**: the `_NO_DATA` meta-test only caught a *direct* `_ok(tc/bk call)` (missed a local var, dict-embed, helper, or `gsutil`/`gcloud` subprocess — `terra_health` proved the blind spot); `get_workflow_cost` kept `workflowId` + an unvalidated `currency`. | All fixed — the runner now wins an **atomic per-spec claim** (stable per-runtime id + no-clobber `.claim` marker with read-back) before any verify/execute/refuse, so different VMs run **different** jobs in parallel but never the same job twice; `create_runtime` ready block drops `bucket_uri`; `terra_health` is projected to booleans/counts/status (lock/paths/IAM-principals withheld) and moved into the guarded set; the structural meta-test now also catches the **local-var taint** AND forbids any `_NO_DATA` tool from calling a remote service unless justified in `_NO_DATA_REMOTE_OK`; cost is numeric-only with a validated currency enum. 32/43 tools guarded; +9 regression/sentinel tests. |
| Adversarial security review — round 8 (re-review of round-7) | **HIGH×4**: the controlled-access guard covered READ tools but the **write/lifecycle RETURN values** still raw-echoed operator strings — `terra_submit_workflow` (methodConfigurationName/entity), `terra_register_method` + `terra_create_method_config` (WDL payload, inputs/outputs, rootEntityType), and `terra_refresh_workspace_allowlist` (full cross-workspace bucket list even when locked); a `REFUSED-SESSION-WINDOW` job whose status-write succeeded but spec-move failed could be re-executed by a second runner. **MED×3**: `terra_start_runtime`/`terra_stop_runtime`/`terra_create_runtime` serialized the raw Leonardo response; `terra_get_workflow_cost` was raw pass-through; the **`_NO_DATA` meta-test was not fail-closed** (it never checked that no-data tools avoid raw remote returns — the structural root cause that let the write leaks pass). | All fixed — every write/lifecycle/cost tool now projects in guard mode (ids/ack/counts/numeric only) + `terra_upload_to_bucket` (raw gsutil output → ack); refusal writes the terminal status FIRST and the pickup loop **skips any `REFUSED*` spec** (cross-runner re-exec/spend closed); refresh is always count-only. **A new fail-closed structural meta-test asserts no `_NO_DATA` tool raw-returns a `tc.*`/`bk.*` payload** (caller's-own-identity exception allowlisted), closing the root cause. 31/43 tools now guarded; +14 regression/sentinel tests (CC-ControlledAccess3 / CC-SessionLimit). |
| Adversarial security review — round 7 (re-review of round-6) | **HIGH×4**: the new `timeout --verbose` marker wasn't gated to RC 137, so an ordinary papermill failure whose stderr contained that line was relabelled `FAILED-SESSION-LIMIT` (fake cause); the `REFUSED-SESSION-WINDOW` branch could mark a job processed after the spec move even if the REFUSED status write failed (poller stuck on stale `running`); `terra_list_runtimes`/`terra_get_runtime` still emitted user-chosen runtime names/labels/URLs in guard mode; `terra_recommend_runtime_for_notebook` catted controlled notebook bytes into the MCP host with no egress guard. **MED×2**: the stat projection still returned the operator-settable `Content-Type` value; `terra_refresh_workspace_allowlist` returned up to 50 bucket names. | All fixed — the marker is gated to RC 137; the refusal writes the terminal status FIRST and only then moves the spec / marks processed (else stays retryable); the two runtime reads + recommend + refresh moved into the guarded set with controlled-mode projections + sentinel tests; `Content-Type` dropped from the stat allowlist. +8 regression tests (CC-ControlledAccess3 / CC-SessionLimit). |
| Adversarial security review — round 6 (re-review of round-5) | **HIGH×3**: the `gsutil stat` projection matched safe labels as a SUBSTRING anywhere in the line (a custom key `x-goog-meta-Content-Type-NA12878:` slipped through); `terra_list_data_tables` + `terra_list_submissions` still returned Rawls payloads verbatim (table/attribute names, methodConfigurationName); the existing-VM `terra_start_runner_on_vm` path didn't propagate the session budget/margin. **MED×3**: `terra_list_workspaces` emitted every namespace/name regardless of guard mode; the `REFUSED-SESSION-WINDOW` branch marked a job processed even if the status/spec writes failed (could strand it forever); the RC 137 session-limit test was a wall-clock heuristic (OOM-at-budget / clock-step). | All fixed — stat projection now matches EXACT labels at line-start + drops the whole Metadata block; `list_data_tables`/`list_submissions`/`list_workspaces` moved into the guarded set with controlled-mode projections + sentinel tests; the SSH bootstrap now propagates `MCP_TERRA_MAX_RUN_HOURS`/`SESSION_MARGIN_SEC`; the refusal only marks processed once the spec move (durable marker) succeeds (else stays retryable); session-limit detection is now **causal** (`timeout --verbose` marker, not wall-clock). +8 regression tests (CC-ControlledAccess3 / CC-SessionLimit). |
| Adversarial security review — round 5 (re-review of round-4b + the 24h guard) | **HIGH×3**: the `method_config` projection still returned operator-controlled method namespace/name + rootEntityType; the fail-closed meta-test had classified four tools (`get_workspace`, `list_method_configs`, `get_bucket_object_metadata`, `download_from_bucket`) as no-data even though they return UNPROJECTED Rawls/gsutil payloads (workspace attributes, config names, custom object metadata, bytes→local disk); the 24h budget reset per-JOB instead of per-SESSION, so a job after a long prior job could still run past the credential window. **MED×3**: `MCP_TERRA_MAX_RUN_HOURS`/`SESSION_MARGIN` were advertised by submit but not propagated to the auto-started VM runner; RC 137 (OOM SIGKILL) was mislabelled `FAILED-SESSION-LIMIT`; the per-object stderr-truncation flag reused the early-break flag, dropping later failed tasks. | All fixed — `method_config` now returns counts + integer version only; the four payload tools moved into the guarded set with controlled-mode projections + **sentinel-identifier** tests; the runner anchors ONE session deadline at start and caps/refuses per remaining window; the budget+margin are propagated via `customEnvironmentVariables`; RC 137 → session-limit only when elapsed ≥ budget (else OOM `FAILED`); per-object `content_truncated` is split from the break-driving `truncated`. +8 regression tests (CC-ControlledAccess3 / CC-SessionLimit). |
| Adversarial security review — round 4b (re-review of the round-4 fixes) | **HIGH**: controlled-mode audio still passed the summary TEXT as a `say` argv element (world-readable via `ps` / process accounting). **HIGH**: the retry kill-switch was checked only before the backoff `sleep`, not before each attempt, the `sleep` was non-interruptible, and total time could exceed the budget by a full request timeout. **MED**: the `method_config` projection still returned operator-controlled input/output KEY NAMES (could encode identifiers); `workflow_logs` discarded `read_object`'s per-task `truncated` flag (partial stderr returned as `truncated:false`); the structural meta-test was a hardcoded substring list that omitted tools and accepted a docstring mention. | All fixed — `say` is fed via **stdin** (argv holds only flags); the retry loop uses a single deadline, re-checks the kill-switch before **every** attempt, caps each attempt's timeout to the remaining deadline, and backs off with an **interruptible** sleep; `method_config` is projected to **counts** (no key names); `workflow_logs` propagates per-task `stderr_truncated` and ORs it into the top-level flag; the meta-test is now **fail-closed + AST-based** (every registered tool must be explicitly classified, every data tool must have a runtime guard call). +6 regression tests incl. a sentinel-identifier test (CC-ControlledAccess3). |
| Adversarial security review — round 4 (egress closure across the full read surface + retry safety) | **HIGH**: in controlled mode `list_bucket` / `get_method_config` / `get_submission` / `get_batch_job_status` still egressed object paths, direct-input config values, per-workflow entity names + failure messages, and the full Batch job JSON; `render_audio_summary` could route controlled text to external **Cloud TTS**. **HIGH**: `terra_get_workflow_logs` trusted the Cromwell-metadata `stderr` path verbatim — a crafted/stale path could steer a read into a *different* workspace the caller can see — and had no aggregate fan-out/byte cap. **MED**: the `terra://health` *resource* (auto-read, bypasses the audit/rate path) mirrored the full `terra_health` snapshot (workspace lock, bucket/project, heartbeat paths) + did live network probes; the retry/backoff loop honored neither the kill-switch nor a total time budget. | All fixed — controlled mode now projects `list_bucket`/`method_config`/`submission`/`batch_job_status` to non-identifying fields and forces audio to **local `say`** (refuses if unavailable); `workflow_logs` resolves the *queried* workspace bucket and reads stderr only when the path is under it (else a visible `[refused: …]` marker), with a 50-task / 1 MiB aggregate cap + `truncated` flag; the health *resource* returns a minimal, network-free, identifier-free posture; the retry loop aborts on the kill-switch hook and obeys a bounded total budget. **A structural meta-test now enumerates every data-returning tool and fails if any lacks a controlled-access check.** 7 regression tests (CC-ControlledAccess3). |

## Acknowledged limitations

These are real but either out of scope or fundamentally hard:

1. **TOCTOU between path validation and operation.** The MCP validates a path, then `gsutil` reads it. An attacker with shell access can replace the file with a symlink in that window. We cannot fully mitigate because `gsutil` operates on paths, not file descriptors. In practice this is only exploitable in the **compromised-host** threat model, and in that model the attacker can call `gsutil` directly anyway.

2. **Code-integrity hash is informational only.** The startup banner prints SHA-256 of each `.py` file, but the MCP does NOT compare against a signed manifest. An attacker who modifies the source on disk can also adjust their expectations of what the hash should be. Real mitigation would require a signed manifest; out of scope for v1.

3. **Per-process rate limit.** The 60-call/min limit is enforced per-process. An attacker who can spawn MCP processes (i.e., has shell) can run multiple in parallel to bypass. This is consistent with the compromised-host threat model's irreducibility.

4. **Workspace allowlist relies on Terra's ACL.** Bucket access is gated by the user's Rawls-reported workspace list, refreshed every 5 minutes. If Terra itself is compromised and adds attacker-controlled buckets to the user's ACL, the MCP would honor that. Outside our threat model.

5. **Output max-length is post-redaction.** Truncation happens after the injection-redaction step. An attacker crafting a giant input could waste CPU on the NFKC normalization pass before the truncation kicks in. Bounded by Terra API response sizes, which are themselves bounded by Terra.

6. **No supply-chain defense within version bounds.** `httpx 0.27.0` and `httpx 0.99.0` are both accepted; if a malicious version is released in that range, we'd pick it up on next `pip install`. Standard pip caveat; pin tighter for production deployments.

## Comprehensive attack-class coverage (`tests/test_security_comprehensive.py`)

**349/349 tests pass** across 48 attack classes. The table below is generated
from the suite itself; the test file is the authoritative source. Run yourself:

```bash
cd ~/projects/mcp-terra
python tests/test_security_comprehensive.py
```

| Class | Tests | What it covers |
|---|---:|---|
| A-Injection | 9 | Shell metachars / backticks / `$()` / pipes / CRLF / NULL bytes in identifiers + paths; URL-encoded `%2e%2e/` traversal in bucket URIs; log-injection via tabs/newlines |
| B-Path | 13 | `/etc/passwd`, `~/.ssh/id_rsa`, case-insensitive-FS variants, `~/.aws/credentials`, gcloud ADC JSON, `/tmp/../etc/passwd`, trailing slash, oversize/empty path, overwrite refused, missing parent |
| C-PromptInjection | 9 | ASCII `<\|im_start\|>`, Unicode full-width (U+FF5C), `[INST]`, `<system>`, C0/C1/DEL stripping; newline+tab preserved; output truncation |
| D-Bucket | 6 | Non-`gs://` scheme, `http://`, non-workspace bucket, empty URI, bare `gs://`, CRLF in bucket URI |
| E-Policy | 5 | Writes default OFF; ON only with `MCP_TERRA_ALLOW_WRITES=1`; non-truthy stays OFF; rate limiter raises on burst |
| F-Tools | 3 | No destruction primitive registered; **42 tools** registered exactly; every spend/write tool has the correct action class |
| G-Edge | 6 | Valid identifiers accepted; empty/leading-non-alphanum refused; name-length cap; versioned-name shape; `Path(None)` handled |
| H-Supply | 5 | No `eval`/`exec`/`pickle.load*`/`shell=True` anywhere; dependency upper bounds present |
| I-Output | 1 | Token-leak defense-in-depth wired into `_ok()` |
| J-ReDoS | 2 | `_SAFE_ID_RE` / `_SAFE_GS_RE` complete in <0.1 s on 10 000-char inputs |
| K-Net | 1 | Terra service URLs are module constants; no user-controllable URL parameter |
| L-Audit | 3 | `O_NOFOLLOW` set, `CONFIG_DIR` validated vs symlink + ownership, file mode 0600 |
| M-Lock | 7 | Single-workspace lock: unset/ malformed/ valid parsing; workspace/project/bucket gates; no enforcement in open mode |
| N-Persistence | 6 | Local-write blocklist for persistence mechanisms: shell rc files, macOS LaunchAgents/Daemons, cron/at/startup dirs |
| O-KillSwitch | 5 | Kill-switch: clean state, manual trip persists, out-of-band file trip, fail-closed refuse-all |
| P-DataLoss | 4 | Non-regular files (device/FIFO/socket) refused; bucket upload/download pass `-n` no-clobber |
| Q-Fetch | 9 | `terra_fetch_url` allowlist: `http` refused, non-allowlisted host, subdomain-spoof, userinfo, `file:`/`javascript:` schemes, oversize, writes-gated |
| R-Hardening | 16 | Bucket-URI regex hardening; `writes_allowed` snapshotted at startup (env-flip immune); HMAC spec binding; dir-collision; locks |
| S-Round3 | 13 | Runner script scrubs `MCP_TERRA_RUNNER_SECRET` + other `MCP_TERRA_*` before papermill; spec signature binds spec-gcs + submit-ts |
| T-Docker | 10 | Dockerfile present; non-root `USER`; read-only env defaults; pinned base; documented hardening run-flags |
| U-Robustness | 10 | Every tool carries `ToolAnnotations`; destructive-hint only on kill-switch; read tools `readOnlyHint=True`; schema/version envelope |
| V-EmailExfil | 14 | Recipient-locked email: CR/LF header injection, body smuggling, raw-token exfil defense, homoglyph/NFKC checks |
| W-RunLog | 4 | `terra_get_run_log` read-only; stream arg validated; `max_bytes` bounds |
| X-Triage | 8 | `bug_triager` categorization (missing_module / name_error / attribute_error / oom / …) + safe traceback truncation |
| Y-SecretScan | 8 | `secret_scan` blocks ya29 / AWS key / PEM / GitHub PAT before upload; reports context not value; fail-closed on unreadable |
| Z-LLMRouter | 5 | Optional LLM router: defaults off, schema validation, refuses dangerous tokens / shell metachars |
| AA-AuditChain | 3 | HMAC audit hash-chain: ok on fresh chain, detects a tampered line, continues across restart |
| BB-AudioSummary | 8 | Audio summary: length bounds, refuses raw token shapes, sends quota-project header |
| CC-StartRunnerOnVM | 6 | Legacy gcloud-SSH runner start: identifier validation, secret via stdin (not argv), heartbeat verification |
| CC-SeamlessRunner | 20 | Seamless on-boot runner (`startUserScriptUri` + `customEnvironmentVariables`); no literal secret; env redaction; the live-execution regression fixes |
| CC-HeartbeatBinding | 7 | Heartbeat identity-binding (`<epoch> <runtime_name>`) parsing + verification |
| CC-WDL | 7 | WDL submission primitives: entity-less body, no abort/delete, workspace-lock, SPEND gate, no delete-outputs switch, bool `method_version` rejected |
| CC-Email | 1 | SMTP modes: A `.eml` (no creds), B authenticated, C relay (explicit opt-in only) |
| CC-Reads | 10 | comprehensive-read read tools: READ-class, no write/delete, paging clamps, call-tree summary, byte-range read, allowlist, Batch logging command |
| CC-RunRecord | 6 | Provenance run record: schema/version stamping, derived counts, agent-forged provenance overwritten, workspace from the lock, malformed-record rejection, order-independent integrity digest, secret-scan before persist |
| CC-Notify | 4 | Slack ping: no-webhook safe return, host/https-locked webhook, secret-shaped payload refused before network, no `url` param (webhook env-locked, anti-exfil) |
| CC-NoDeleteAttack | 7 | Social-engineering "delete the malware-infected files" request achieves nothing: no delete-capable tool, bucket layer uses only non-destructive verbs, no rmtree/rmdir call, os.unlink only on temp files, no delete primitive on any client layer, LLM-patch validator blocklists destructive tokens, attack has no callable to fulfill it |
| CC-HardeningFixes | 10 | Regressions for the 6 adversarial-review findings: version_existing write-policy bypass (blocked paths / symlink / non-regular, exist-independent), audio secret-scan fail-closed, non-forgeable run-record agent identity (+ fail-closed), run_id↔path binding, temp-blob cleanup, run-record no-clobber preflight |
| CC-AudioAttach | 6 | Audio email attachment is exfil-safe: audio/* MIME only, non-audio extension refused, oversized/empty refused, no-attachment stays single-part, path DERIVED from job_id (never arbitrary), temp blob cleaned up |
| CC-SlackUpload | 6 | True Slack file upload (bot Web API): bot config requires token+channel, safe no-op when unconfigured, secret-shaped comment refused before any network, empty/oversized refused before network, env-locked tool (no url/token/channel params) with webhook fallback, user-id→DM resolution + multi-target (DM and/or channel) parsing |
| CC-HardeningFixes2 | 7 | Regressions for the 2nd adversarial-review round: exact protected-dir blocklist bypass (trailing-slash) fixed, download refuses version_existing on a directory, reserved audio path (provenance) blocked from generic upload, audio fetch size-preflights before download, Slack fails loud when all targets fail, audio render preflights both extensions before the TTS side-effect, run-record read-back md5 verify |
| CC-ControlledAccess | 5 | NIH GDS/DUC data-egress guard: off by default (lab/public unhindered), guard ON refuses the secure bucket but allows public + operator-allowlisted buckets, blocks `get_entities` rows, `read_bucket_object` enforces it while metadata-only stays available, `terra_health` surfaces the posture |
| CC-ControlledAccess2 | 6 | Round-3 egress-path closure (executes the bypasses): exact-name public allowlist (prefix-collision blocked), `get_workflow_outputs` refused, `get_workflow_metadata` reduced to status+summary, `get_run_log` content withheld, `get_notebook_job_result` redacts source/traceback + gates the Tier-2 external LLM, audio render read-back md5 verify |
| CC-Retry | 5 | Transient-failure retry in `terra_client._request`: Retry-After parse + bounded backoff, GET retries 429 then succeeds, POST is NOT retried (no double-submit), retries are bounded (exhaust→raise), non-retryable 4xx not retried |
| CC-WorkflowLogs | 2 | `terra_get_workflow_logs` (per-task Cromwell stderr): controlled mode withholds stderr content (paths/status kept), off-mode reads the failed task's stderr tail with `failed_only` filtering |
| CC-ControlledAccess3 | 34 | Round-4 egress closure + retry safety: a **fail-closed AST meta-test** (every registered tool must be explicitly classified; every data tool must carry a *runtime* guard call — a docstring mention can't satisfy it), `method_config` projected to **counts** (values AND key names withheld; sentinel-identifier test), `submission` projected to ids+statuses, `workflow_logs` refuses a stderr path outside the queried workspace bucket + flags per-task truncation, audio `say` fed via **stdin not argv**, retry aborts on the kill-switch hook (interruptible backoff) + deadline-capped, the `terra://health` resource is minimal + data-free |
| CC-SessionLimit | 4 | Terra ~24h session/credential-window guard: `policy.max_run_hours` clamps 1..24, the on-VM runner wraps each run in a **total wall-clock budget** (coreutils `timeout`, TERM→KILL) so a too-long run is halted as `FAILED-SESSION-LIMIT` (not silently truncated), submit advises the limit + WDL path for long runs |
| CC-Discoverability | 3 | MCP resources + prompts (discoverability): registered, the `terra://posture` resource exposes config only (no bucket/entity/data read), prompts are guidance-only (no destructive instruction) |

## Single-workspace lock (`MCP_TERRA_WORKSPACE`)

Strongest containment available: when `MCP_TERRA_WORKSPACE=namespace/name` is
set in the environment, the MCP instance is **restricted to one workspace only**.

- `terra_list_workspaces` returns ONLY the locked workspace (verified live: 348 → 1).
- `terra_get_workspace` / `terra_get_runtime` / `terra_list_runtimes` / `terra_start_runtime` / `terra_stop_runtime` / `terra_create_runtime` refuse any project that isn't the locked workspace's `googleProject`.
- `terra_list_bucket` / `terra_upload_to_bucket` / `terra_download_from_bucket` refuse any `gs://` URI whose bucket isn't the locked workspace's bucket.

A malformed `MCP_TERRA_WORKSPACE` value (e.g. `../etc/passwd`, `ns; rm -rf /`) fails loud at startup. The MCP refuses to run with a broken lock — safer than silently dropping the lock.

**Recommended usage**: one MCP instance per workspace. Each Claude Code session
opens the project's MCP with `MCP_TERRA_WORKSPACE=<that-project>` set so the
blast radius is at most one workspace even if the agent is compromised by
prompt injection.

Example settings.json entry:

```json
{
  "mcpServers": {
    "terra-scprs": {
      "command": "/Users/<you>/bin/python",
      "args": ["-m", "mcp_terra.server"],
      "env": {
        "MCP_TERRA_WORKSPACE": "claussnitzer-fdp/talha_notebooks",
        "MCP_TERRA_ALLOW_WRITES": "0"
      }
    }
  }
}
```

## How to verify the MCP's integrity yourself

At startup, the MCP logs SHA-256 of every `.py` file. To detect tampering:

```bash
# Run the MCP once and capture the startup banner:
MCP_TERRA_ALLOW_WRITES=0 python -m mcp_terra.server 2>banner.txt < /dev/null
grep -A 10 "code integrity" banner.txt
```

Save the hashes somewhere safe. Compare on every startup. Any change means
the MCP code was modified (legitimately by an upgrade, or by an attacker).

## How to report a security issue

Email trehman@broadinstitute.org with `[mcp-terra security]` in the subject.
**Do NOT open a public GitHub issue for security reports.**

If you prefer, use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") once the repository is published.

### Coordinated-disclosure policy

- **Acknowledgement:** within **3 business days** of your report.
- **Triage + initial assessment:** within **10 business days**.
- **Coordinated disclosure window:** **90 days** from acknowledgement, or
  sooner once a fix ships. We will agree a disclosure date with you and credit
  you in the release notes unless you ask otherwise.
- Please give us a reasonable chance to remediate before any public disclosure.

This mirrors the policy referenced in
[CONTRIBUTING.md](CONTRIBUTING.md#security-disclosure).
