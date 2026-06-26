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
runner, WDL primitives, the fiss-mcp-superset read tools) each went through
adversarial review. Highlights:

| Source | Finding | Status |
|---|---|---|
| Codex adversarial pass (seamless runner) | The on-VM Claude-Code installer inherited `MCP_TERRA_RUNNER_SECRET` from the environment. | Fixed — installer runs under `env -i` (scrubbed env); secret never reaches the install subprocess. Regression-tested (CC-SeamlessRunner). |
| Codex adversarial pass (WDL) | `method_version` accepted a `bool` (`True` is an `int` subclass) → could bind Agora snapshot 1 unintentionally. | Fixed — explicit `isinstance(x, bool)` reject (CC-WDL). |
| Codex adversarial pass (WDL) | A `deleteIntermediateOutputFiles` parameter could express a destructive intent. | Fixed — parameter removed; value hard-wired `False` at the client layer (CC-WDL). |
| **Live execution on a real Terra VM** | 6 latent bugs that only surface end-to-end (macOS `gsutil -m` deadlock; lowercase-only spec-filter regex rejecting all job ids; runaway re-exec on result-upload failure; `terra_list_runtimes` filtering on a non-existent label; job stuck at `running`; Cloud-TTS quota-project 403). | All fixed and regression-tested. See CHANGELOG "Fixed". |
| Two-reviewer publication-readiness review (security engineer + senior SWE) | Doc drift (stale test/tool counts, contradictory `terra_fetch_url` action class, version single-source fiction), missing secret-scanning in CI. | Fixed — counts regenerated from the suite; `terra_fetch_url` annotation reconciled with its gate; `pyproject` version made dynamic from `__init__`; `detect-secrets` added to CI + pre-commit with a committed baseline. |
| Codex adversarial review (run-record / Slack / desktop / audio changes) | **CRITICAL**: `terra_download_from_bucket(version_existing=True)` skipped the local-path policy when the target existed → could rename/overwrite a blocked target (`~/.ssh/id_rsa`, shell rc, symlink, device). **HIGH**: audio text not secret-scanned before TTS/persist; run-record agent identity still caller-forgeable on auth failure. **MED**: run_id not bound to the record path; temp metadata blob left on disk; run-record no-clobber could report success without persisting. | All fixed — `safety.assert_local_write_policy` now runs regardless of existence (blocklist + symlink + non-regular); audio runs `secret_scan` (raw + NFKC) fail-closed; run-record agent block is built from authoritative data only and fails closed on unresolved identity; embedded run_id bound to the path; temp blob unlinked in `finally`; no-clobber preflight added. 10 regression tests (CC-CodexFixes). |

## Acknowledged limitations

These are real but either out of scope or fundamentally hard:

1. **TOCTOU between path validation and operation.** The MCP validates a path, then `gsutil` reads it. An attacker with shell access can replace the file with a symlink in that window. We cannot fully mitigate because `gsutil` operates on paths, not file descriptors. In practice this is only exploitable in the **compromised-host** threat model, and in that model the attacker can call `gsutil` directly anyway.

2. **Code-integrity hash is informational only.** The startup banner prints SHA-256 of each `.py` file, but the MCP does NOT compare against a signed manifest. An attacker who modifies the source on disk can also adjust their expectations of what the hash should be. Real mitigation would require a signed manifest; out of scope for v1.

3. **Per-process rate limit.** The 60-call/min limit is enforced per-process. An attacker who can spawn MCP processes (i.e., has shell) can run multiple in parallel to bypass. This is consistent with the compromised-host threat model's irreducibility.

4. **Workspace allowlist relies on Terra's ACL.** Bucket access is gated by the user's Rawls-reported workspace list, refreshed every 5 minutes. If Terra itself is compromised and adds attacker-controlled buckets to the user's ACL, the MCP would honor that. Outside our threat model.

5. **Output max-length is post-redaction.** Truncation happens after the injection-redaction step. An attacker crafting a giant input could waste CPU on the NFKC normalization pass before the truncation kicks in. Bounded by Terra API response sizes, which are themselves bounded by Terra.

6. **No supply-chain defense within version bounds.** `httpx 0.27.0` and `httpx 0.99.0` are both accepted; if a malicious version is released in that range, we'd pick it up on next `pip install`. Standard pip caveat; pin tighter for production deployments.

## Comprehensive attack-class coverage (`tests/test_security_comprehensive.py`)

**277/277 tests pass** across 39 attack classes. The table below is generated
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
| CC-Reads | 10 | fiss-mcp-superset read tools: READ-class, no write/delete, paging clamps, call-tree summary, byte-range read, allowlist, Batch logging command |
| CC-RunRecord | 6 | Provenance run record: schema/version stamping, derived counts, agent-forged provenance overwritten, workspace from the lock, malformed-record rejection, order-independent integrity digest, secret-scan before persist |
| CC-Notify | 4 | Slack ping: no-webhook safe return, host/https-locked webhook, secret-shaped payload refused before network, no `url` param (webhook env-locked, anti-exfil) |
| CC-NoDeleteAttack | 7 | Social-engineering "delete the malware-infected files" request achieves nothing: no delete-capable tool, bucket layer uses only non-destructive verbs, no rmtree/rmdir call, os.unlink only on temp files, no delete primitive on any client layer, LLM-patch validator blocklists destructive tokens, attack has no callable to fulfill it |
| CC-CodexFixes | 10 | Regressions for the 6 adversarial-review findings: version_existing write-policy bypass (blocked paths / symlink / non-regular, exist-independent), audio secret-scan fail-closed, non-forgeable run-record agent identity (+ fail-closed), run_id↔path binding, temp-blob cleanup, run-record no-clobber preflight |
| CC-AudioAttach | 6 | Audio email attachment is exfil-safe: audio/* MIME only, non-audio extension refused, oversized/empty refused, no-attachment stays single-part, path DERIVED from job_id (never arbitrary), temp blob cleaned up |

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
