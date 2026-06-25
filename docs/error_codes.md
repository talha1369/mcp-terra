# mcp-terra error code reference

Every error path in mcp-terra returns a structured envelope:

```json
{
  "ok": false,
  "error": {
    "code": "E_WRITES_DISABLED",
    "message": "Human-readable explanation.",
    "retryable": false,
    "details": { ... optional, code-specific ... }
  }
}
```

Agents should branch on `code` (stable across versions) rather than
`message` (subject to wording changes). The `retryable` field is the
canonical hint for whether a retry might succeed without operator
action; `details` carries code-specific structured data (e.g. the
sensitive-path that was blocked, the workspace that's locked).

The codes below are the complete catalog. New codes can only be added
in a minor version bump; existing codes never change meaning.

---

## E_WRITES_DISABLED

**Meaning.** A WRITE-SAFE or SPEND tool was invoked but the server was
started with `MCP_TERRA_ALLOW_WRITES=0` (the default).

**Common cause.** Operator forgot to opt into writes, or intentionally
running the MCP in read-only mode.

**Recommended agent response.** Abort the operation. Tell the user the
server is in read-only mode and they need to restart it with
`MCP_TERRA_ALLOW_WRITES=1` (and ideally `MCP_TERRA_WORKSPACE=ns/name`
too) for the call to succeed. Do NOT retry. **User action required.**

---

## E_RATE_LIMITED

**Meaning.** The per-minute call budget (`MCP_TERRA_MAX_CALLS_PER_MIN`,
default 60) has been exhausted in the current rolling window.

**Common cause.** Tight polling loop, or a multi-tool fan-out exceeding
the budget.

**Recommended agent response.** **Retryable** after backoff. Wait the
duration in `details.retry_after_seconds` (or 30s if absent), then
retry. If you hit this twice in a row, switch to longer polling
intervals — do not hammer.

---

## E_KILLSWITCH_TRIPPED

**Meaning.** The kill-switch file (`~/.mcp-terra/KILL`) exists OR the
auto-trip threshold (refusals per window) was crossed.

**Common cause.** Operator manually tripped it, or the agent triggered
too many refusals in too short a time (often a sign the agent is
fighting the safety model).

**Recommended agent response.** **Abort.** Do not retry — every call
will fail until the kill switch is cleared by the operator. Tell the
user the kill switch is tripped and they need to remove
`~/.mcp-terra/KILL` (and investigate WHY it tripped before re-enabling).
**User action required.**

---

## E_POLICY_DENIED

**Meaning.** The requested operation is allowed by the server's
configuration in principle, but the specific arguments violated a
policy (sensitive local path, non-workspace bucket, recipient mismatch
on email, etc.). `details.policy` names which policy fired.

**Common cause.** Agent tried to access `~/.ssh/id_rsa` or a bucket
outside the user's Terra workspaces, or supplied a different
recipient than the authenticated Terra email.

**Recommended agent response.** **Abort.** Do NOT retry the same call.
Explain to the user which policy fired (from `details.policy`) and ask
them whether the request was intentional. If yes, the user must change
the input — the policy itself cannot be relaxed at runtime.
**User action required.**

---

## E_OVERWRITE_REFUSED

**Meaning.** The destination (bucket object or local file) already
exists, and `version_existing=False` (the default).

**Common cause.** Re-uploading a file that's already in the bucket, or
downloading to a local path that already has content.

**Recommended agent response.** **Abort the specific call.** If the
intent is to supersede a buggy file, retry with
`version_existing=True, version_method='bak'`. If the intent is to
create a sibling file, pick a different name. If the intent was to
update in place, ask the user to confirm — overwriting is a
data-destructive operation. **User action required** for the in-place
case.

---

## E_GSUTIL_TRANSIENT

**Meaning.** `gsutil` returned an exit code consistent with a transient
GCS issue (5xx, network reset, token refresh race). The MCP did NOT
internally retry — it surfaces the error so the agent owns the retry
budget.

**Common cause.** GCS hiccup, expired ADC token mid-call, transient
network blip.

**Recommended agent response.** **Retryable** with exponential backoff
(start 2s, double, cap 60s, give up after 5 attempts). If 5 retries all
fail with this code, escalate to the user — likely a real outage or
expired credentials.

---

## E_AUTH_EXPIRED

**Meaning.** The gcloud ADC token could not be obtained, or Terra
rejected it as invalid/expired.

**Common cause.** User hasn't run `gcloud auth application-default
login` recently enough, or the refresh token has been revoked.

**Recommended agent response.** **Abort.** Tell the user to run
`gcloud auth application-default login` and restart the MCP. Do not
retry — every subsequent call will fail the same way until ADC is
refreshed. **User action required.**

---

## E_SIGNATURE_INVALID

**Meaning.** A notebook runner spec was rejected because its HMAC
signature did not verify with `MCP_TERRA_RUNNER_SECRET`, OR the spec
was older than `MCP_TERRA_SPEC_MAX_AGE_SEC` (replay defense).

**Common cause.** Secret mismatch between the agent-side MCP and the
VM-side runner, or system clock skew, or a tampered spec.

**Recommended agent response.** **Abort.** Do NOT retry — same secret,
same clock = same failure. Tell the user to verify the runner secret
matches on both ends and that the VM clock is in sync (within
`SPEC_MAX_AGE_SEC` of the submitting host). **User action required.**

---

## E_NOT_IN_WORKSPACE

**Meaning.** The workspace lock (`MCP_TERRA_WORKSPACE=ns/name`) is set,
but the requested operation referenced a different workspace or a
bucket outside the locked workspace.

**Common cause.** Agent tried to reach across to a workspace the user
didn't authorize for this session.

**Recommended agent response.** **Abort.** Explain to the user that the
server is locked to a single workspace and surface the mismatch.
Restarting the MCP without the lock (or with a different lock) is the
only way to broaden scope. **User action required.**

---

## E_SENSITIVE_DATA_DETECTED

**Meaning.** A payload (notebook source, run report, fetch response)
matched a heuristic for sensitive content (raw private-key blocks, AWS
access keys, gcloud refresh tokens, etc.) and the operation was
refused before transmitting.

**Common cause.** An agent inadvertently included a credential snippet
in a notebook or report, or a fetched URL returned a page with
embedded keys.

**Recommended agent response.** **Abort.** Do NOT retry the same
payload — it will be refused again. Scrub the suspected secret, re-run.
This code never indicates a transient problem. If you cannot identify
what triggered it, ask the user to inspect — the MCP intentionally does
not echo the matched secret back. **User action required** for novel
matches.

---

## E_INTEGRITY_MISMATCH

**Meaning.** A file's sha256 after upload did not match the sha256
computed locally before upload (corruption detected), OR a downloaded
file's sha256 did not match the expected value from the runner spec.

**Common cause.** GCS transient corruption (rare), buggy resumable
upload, or — alarming — tampering in flight.

**Recommended agent response.** **Retryable ONCE** — if the mismatch
repeats, abort and escalate to the user. A second mismatch is a strong
signal something is wrong beyond a single bad packet. **User action
required** after one failed retry.

---

## E_SUBMIT_CAP_EXCEEDED

**Meaning.** The notebook-job submitter rejected a submit because the
spec body exceeded `parameters_json` bounds OR the per-window submit
cap was hit.

**Common cause.** Agent loaded a huge dict into `parameters_json`, or
submitted too many jobs in quick succession.

**Recommended agent response.** **Abort the specific call.** Shrink
`parameters_json` (move large payloads into a separate GCS file the
notebook reads), or wait the window out and resubmit. If the cap is
the problem, this is rate-limit-like and retryable after backoff;
`details.retry_after_seconds` will be present.

---

## E_RUNNER_HEARTBEAT_STALE

**Meaning.** `terra_get_notebook_job_result` was called for a job that
the runner has not heart-beat for longer than the staleness threshold
— likely the VM was paused, the runner crashed, or it was never
started.

**Common cause.** User forgot to start the runner on the VM, or the VM
auto-paused.

**Recommended agent response.** **Abort polling.** Tell the user to
check the VM is running and the runner is active (`ps aux | grep
mcp_terra_runner`). Resubmitting from the agent side will only stack
specs; do not retry without operator intervention. **User action
required.**

---

## E_SCHEMA_VERSION_MISMATCH

**Meaning.** The client's expected tool-schema version (advertised in
the MCP handshake) differs by a major version from the server's
schema, AND the server cannot safely service the request under the
client's contract.

**Common cause.** Client built against an older mcp-terra and a tool's
contract changed in a backward-incompatible way (rare — semver minor
bumps stay compatible).

**Recommended agent response.** **Abort.** Surface
`details.server_schema` and `details.client_schema` to the user. They
need to upgrade the client (or pin the server to a matching older
release). Do not retry. **User action required.**

---

## Code stability guarantee

- Codes never change meaning across releases.
- Removing a code requires a major-version bump.
- Adding a code requires only a minor-version bump.
- Agents that branch on an unknown code SHOULD fall through to "abort
  and surface the message + code verbatim to the user" rather than
  guess.
