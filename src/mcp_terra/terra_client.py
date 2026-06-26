"""Thin HTTPS clients for the three Terra services we touch.

  Rawls    — workspace metadata           (terra.bio's workspace registry)
  Leonardo — runtime (VM) lifecycle       (Jupyter VMs, GPUs)
  Sam      — user identity / Terra auth   (registration check)

All clients accept a fresh OAuth bearer token (from auth.get_access_token).
We do NOT swallow errors: any non-2xx response surfaces as TerraAPIError
with the request path + response body so the agent sees the real failure.
"""
from __future__ import annotations

import json
import os
import random
import time
import urllib.parse
from typing import Any

import httpx


RAWLS_BASE = "https://rawls.dsde-prod.broadinstitute.org"
LEO_BASE   = "https://leonardo.dsde-prod.broadinstitute.org"
SAM_BASE   = "https://sam.dsde-prod.broadinstitute.org"
AGORA_BASE = "https://agora.dsde-prod.broadinstitute.org"


# ── Transient-failure retry policy ──────────────────────────────────────────
# Bounded retry with exponential backoff + jitter, honoring Retry-After — for
# IDEMPOTENT methods only. common Terra Python clients do not retry the Terra API at all;
# this makes the MCP more resilient to 429/5xx without ever auto-retrying a
# non-idempotent POST (a Terra createSubmission is BILLABLE; a blind retry on a
# transient error could double-submit, and Terra has no idempotency-key support).
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES = max(0, min(int(os.environ.get("MCP_TERRA_MAX_RETRIES", "3")), 8))
_RETRY_BASE_SEC = 0.5
_RETRY_CAP_SEC = 8.0
# Hard ceiling on TOTAL time spent retrying a single request, so a GET can't sit
# in backoff sleeps for minutes (e.g. after the operator trips the kill-switch).
_RETRY_TOTAL_BUDGET_SEC = max(
    1.0, min(float(os.environ.get("MCP_TERRA_RETRY_TOTAL_BUDGET_SEC", "30")), 120.0))

# Optional cancellation hook (set by the server layer to the kill-switch check,
# avoiding a terra_client→policy circular import). Returns True ⇒ stop retrying.
abort_check = None  # type: ignore[var-annotated]


def _aborted() -> bool:
    """True if the kill-switch hook says stop. Fail-SAFE: never raises (a broken
    hook must not wedge a request)."""
    if abort_check is None:
        return False
    try:
        return bool(abort_check())
    except Exception:
        return False


def _interruptible_sleep(seconds: float) -> bool:
    """Sleep up to `seconds`, waking early if the kill-switch trips. Sleeps in
    short slices so a kill-file created mid-backoff is noticed within ~0.2s
    instead of after the whole delay. Returns True if it slept the full time,
    False if it was aborted partway."""
    end = time.monotonic() + max(0.0, seconds)
    while True:
        if _aborted():
            return False
        remaining = end - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(0.2, remaining))


def _retry_ok(start_monotonic: float, attempt: int,
              retry_after: float | None) -> float | None:
    """Decide whether to perform another retry, returning the backoff delay to
    use (or None to STOP). Computing the jittered delay HERE — once — guarantees
    the budget check and the actual sleep use the SAME value (no recompute
    drift). Returns None if the kill-switch tripped, or if the next backoff
    would push total retry time past `_RETRY_TOTAL_BUDGET_SEC`."""
    if _aborted():
        return None
    delay = _retry_delay(attempt, retry_after)
    if (time.monotonic() - start_monotonic) + delay > _RETRY_TOTAL_BUDGET_SEC:
        return None
    return delay


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header's delta-seconds form. Returns seconds (capped
    at 60s so a hostile/huge value can't hang the call), or None for the
    HTTP-date form (caller falls back to computed backoff)."""
    if not value:
        return None
    try:
        return max(0.0, min(float(value.strip()), 60.0))
    except (ValueError, AttributeError):
        return None


def _retry_delay(attempt: int, retry_after: float | None) -> float:
    """Backoff seconds for a 1-based attempt. Honor Retry-After if present; else
    exponential (base*2^(n-1)) capped, plus jitter to avoid thundering herd."""
    if retry_after is not None:
        return retry_after
    return min(_RETRY_CAP_SEC, _RETRY_BASE_SEC * (2 ** (attempt - 1))) + random.uniform(0, 0.5)


class TerraAPIError(RuntimeError):
    """Raised when a Terra API call returns non-2xx."""
    def __init__(self, service: str, method: str, path: str, status: int, body: str):
        self.service = service; self.method = method; self.path = path
        self.status = status; self.body = body
        super().__init__(
            f"{service} {method} {path} → HTTP {status}: {body[:400]}"
        )


def _request(service: str, method: str, base: str, path: str, token: str,
             *, json_body: Any = None, params: dict | None = None,
             timeout: float = 30.0) -> Any:
    """Issue a request to a Terra service. Returns parsed JSON or empty dict.

    Security posture:
      • `path` is built by callers via f-strings — those callers MUST first
        run `safety.validate_identifier()` on every interpolated component.
        As defense in depth this function does NOT alter `path`, but we
        document the contract so callers can't sneak control chars through.
      • `httpx.Client(..., trust_env=False, follow_redirects=False)` — refuse
        to honor HTTPS_PROXY / NO_PROXY from the environment, and refuse to
        follow redirects (Terra services never redirect; a redirect would
        be a MITM / SSRF signal).
      • Errors NEVER contain the OAuth token; defense-in-depth check in
        the caller (server._ok) catches any echoed-back Authorization header.

    Raises TerraAPIError on any non-2xx so failures are surfaced loudly.
    """
    url = base.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    # Retry ONLY idempotent methods. A non-idempotent POST/PUT/PATCH (e.g. a
    # billable createSubmission) is attempted exactly once — retrying a transient
    # error could duplicate the side effect.
    idempotent = method.upper() in ("GET", "HEAD")
    max_attempts = (1 + _MAX_RETRIES) if idempotent else 1
    _start = time.monotonic()
    # Total wall-clock is bounded: the first attempt's own timeout PLUS the retry
    # budget. Each attempt's timeout is then capped to whatever remains, so a
    # hung retry can never blow far past the budget — and the kill-switch is
    # re-checked before every attempt and during every backoff. (security review.)
    _deadline = _start + float(timeout) + _RETRY_TOTAL_BUDGET_SEC
    resp = None
    with httpx.Client(trust_env=False, follow_redirects=False) as client:
        for attempt in range(1, max_attempts + 1):
            if _aborted():
                raise TerraAPIError(service, method, path, 0,
                                    "aborted by kill-switch before request")
            _remaining = _deadline - time.monotonic()
            if _remaining <= 0:
                raise TerraAPIError(service, method, path, 0,
                                    "retry deadline exhausted")
            _req_timeout = max(1.0, min(float(timeout), _remaining))
            try:
                resp = client.request(method, url, headers=headers,
                                      json=json_body, params=params,
                                      timeout=_req_timeout)
            except httpx.HTTPError as e:
                if idempotent and attempt < max_attempts:
                    _d = _retry_ok(_start, attempt, None)
                    if _d is not None and _interruptible_sleep(_d):
                        continue
                raise TerraAPIError(service, method, path, 0,
                                    f"network error: {type(e).__name__}")
            if 200 <= resp.status_code < 300:
                break
            if (idempotent and attempt < max_attempts
                    and resp.status_code in _RETRY_STATUSES):
                _d = _retry_ok(_start, attempt,
                               _parse_retry_after(resp.headers.get("Retry-After")))
                # _interruptible_sleep returns False if the kill-switch tripped
                # mid-backoff → fall through to the non-2xx handler (fail loud).
                if _d is not None and _interruptible_sleep(_d):
                    continue
            break   # non-retryable, exhausted, cancelled, or over budget → handle below
    if resp is None:   # never assigned (all attempts aborted before a response)
        raise TerraAPIError(service, method, path, 0, "no response (aborted)")
    if not (200 <= resp.status_code < 300):
        # Refuse to echo secrets even if a misbehaving Terra service echoed the
        # request back: the OAuth token, AND the runner HMAC secret (which
        # terra_create_runtime sends inside customEnvironmentVariables).
        body = resp.text
        if token and token in body:
            body = "[response body contained OAuth token — redacted for safety]"
        _runner_secret = os.environ.get("MCP_TERRA_RUNNER_SECRET", "")
        if _runner_secret and _runner_secret in body:
            body = body.replace(_runner_secret, "[REDACTED_RUNNER_SECRET]")
        raise TerraAPIError(service, method, path, resp.status_code, body)
    if resp.status_code == 204 or not resp.content:
        return {}
    try:
        return resp.json()
    except json.JSONDecodeError:
        return {"_raw": resp.text}


def _quote(component: str) -> str:
    """URL-encode a single path component (defense in depth for path injection).

    Callers should ALREADY have validated identifiers via safety.validate_identifier,
    but a defense-in-depth layer here means a future caller who forgets the
    validator still can't inject `..` or scheme-changing characters.
    """
    return urllib.parse.quote(component, safe="")


# ── Rawls (workspaces) ──────────────────────────────────────────────────────

def rawls_list_workspaces(token: str) -> list[dict]:
    """List all workspaces visible to the current user."""
    return _request("rawls", "GET", RAWLS_BASE, "/api/workspaces", token)


def rawls_get_workspace(token: str, namespace: str, name: str) -> dict:
    """Get a specific workspace's metadata (bucket, googleProject, ...)."""
    return _request(
        "rawls", "GET", RAWLS_BASE,
        f"/api/workspaces/{_quote(namespace)}/{_quote(name)}", token,
    )


# ── Leonardo (runtimes / VMs) ───────────────────────────────────────────────

def leo_list_runtimes(token: str, google_project: str | None = None) -> list[dict]:
    """List Leonardo runtimes visible to the user (role=creator).

    If google_project is given, filter to it CLIENT-SIDE on each runtime's
    top-level ``googleProject`` field. (Leonardo's list endpoint treats an
    unknown query param like ``project`` as a LABEL selector, and there is no
    ``project`` label — so a server-side ``project=`` filter silently matches
    NOTHING and returns []. Filtering on the real field is robust.)
    """
    resp = _request("leo", "GET", LEO_BASE,
                    "/api/google/v1/runtimes", token, params={"role": "creator"})
    items = resp if isinstance(resp, list) else []
    if google_project:
        items = [r for r in items
                 if isinstance(r, dict) and r.get("googleProject") == google_project]
    return items


def leo_get_runtime(token: str, google_project: str, runtime_name: str) -> dict:
    return _request(
        "leo", "GET", LEO_BASE,
        f"/api/google/v1/runtimes/{_quote(google_project)}/{_quote(runtime_name)}", token,
    )


def leo_create_runtime(
    token: str, google_project: str, runtime_name: str,
    *, machine_type: str = "n1-standard-4",
    disk_size_gb: int = 100,
    gpu_type: str | None = None,
    num_gpus: int = 0,
    auto_pause_threshold_minutes: int = 60,
    tool_docker_image: str | None = None,
    start_user_script_uri: str | None = None,
    custom_env_vars: dict | None = None,
    extra: dict | None = None,
) -> dict:
    """Create a Leonardo runtime (Jupyter VM).

    This is a WRITE operation that incurs cost. The MCP server gates this
    behind a permission step before calling.

    start_user_script_uri: gs:// path Leonardo runs on EVERY runtime start
        (create + resume). Used to auto-launch the on-VM notebook runner so a
        fresh/resumed VM is never idle-without-a-runner.
    custom_env_vars: dict injected into the VM env on every start; Leonardo
        encrypts it at rest. Used to deliver the runner HMAC secret to the
        startup script without it ever touching GCS, argv, or the audit log.
    """
    runtime_config: dict = {
        "cloudService": "GCE",
        "machineType": machine_type,
        "diskSize": disk_size_gb,
    }
    if gpu_type and num_gpus > 0:
        runtime_config["gpuConfig"] = {
            "gpuType": gpu_type,
            "numOfGpus": num_gpus,
        }
    body: dict = {
        "runtimeConfig": runtime_config,
        "autopauseThreshold": auto_pause_threshold_minutes,
    }
    if tool_docker_image:
        body["toolDockerImage"] = tool_docker_image
    if start_user_script_uri:
        # Leonardo runs this on EVERY runtime start (create + resume), as the
        # VM service account, to auto-start the MCP notebook runner.
        body["startUserScriptUri"] = start_user_script_uri
    if custom_env_vars:
        # Encrypted at rest by Leonardo; injected into the VM env on every
        # start. Carries the runner HMAC secret so it never lands in GCS,
        # argv, or audit logs.
        body["customEnvironmentVariables"] = dict(custom_env_vars)
    if extra:
        body.update(extra)
    return _request(
        "leo", "POST", LEO_BASE,
        f"/api/google/v1/runtimes/{_quote(google_project)}/{_quote(runtime_name)}", token,
        json_body=body,
    )


def leo_start_runtime(token: str, google_project: str, runtime_name: str) -> dict:
    return _request(
        "leo", "POST", LEO_BASE,
        f"/api/google/v1/runtimes/{_quote(google_project)}/{_quote(runtime_name)}/start", token,
    )


def leo_stop_runtime(token: str, google_project: str, runtime_name: str) -> dict:
    return _request(
        "leo", "POST", LEO_BASE,
        f"/api/google/v1/runtimes/{_quote(google_project)}/{_quote(runtime_name)}/stop", token,
    )


# NOTE: leo_delete_runtime was intentionally REMOVED from this module
# per the audit finding "delete primitives must not exist at any layer".
# To call Leonardo's DELETE endpoint, the user must (a) write new code,
# (b) push through code review. The MCP itself has no destruction surface.


# ── Sam (identity) ──────────────────────────────────────────────────────────

def sam_user_info(token: str) -> dict:
    """Return the Sam-registered user identity (Terra auth check)."""
    return _request("sam", "GET", SAM_BASE,
                    "/register/user/v2/self/info", token)


# ── Rawls workflow submissions (WDL / Cromwell) ─────────────────────────────
# NOTE: there is intentionally NO submission-abort/delete primitive here —
# stopping/aborting a submission is deferred to the user (Terra UI), consistent
# with the no-destruction principle.

def rawls_list_method_configs(token: str, namespace: str, name: str) -> list[dict]:
    """List the workspace's method configurations (each binds a WDL method to
    its inputs/outputs). Read-only."""
    resp = _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}/methodconfigs",
                    token)
    return resp if isinstance(resp, list) else []


def rawls_create_submission(token: str, namespace: str, name: str, *,
                            method_config_namespace: str,
                            method_config_name: str,
                            entity_type: str | None = None,
                            entity_name: str | None = None,
                            use_call_cache: bool = True) -> dict:
    """Submit a Cromwell workflow against a method config. SPEND.

    For DIRECT-input (entity-less) runs — the v1 path, since this workspace has
    no data tables — leave entity_type/entity_name as None. Returns the created
    submission record (submissionId, status, …).
    """
    body: dict = {
        "methodConfigurationNamespace": method_config_namespace,
        "methodConfigurationName": method_config_name,
        "useCallCache": bool(use_call_cache),
        # Hard-wired False — the MCP never deletes (no-destruction). No
        # delete-outputs switch is exposed at any layer.
        "deleteIntermediateOutputFiles": False,
    }
    if entity_type and entity_name:
        body["entityType"] = entity_type
        body["entityName"] = entity_name
    return _request("rawls", "POST", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}/submissions",
                    token, json_body=body)


def rawls_get_submission(token: str, namespace: str, name: str,
                         submission_id: str) -> dict:
    """Get a submission's status + its workflows (poll to terminal). Read-only."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/submissions/{_quote(submission_id)}", token)


def rawls_get_workflow_outputs(token: str, namespace: str, name: str,
                               submission_id: str, workflow_id: str) -> dict:
    """Get a finished workflow's outputs. Read-only."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/submissions/{_quote(submission_id)}"
                    f"/workflows/{_quote(workflow_id)}/outputs", token)


# ── Method authoring (Agora method repo + Rawls method configs) ─────────────
# Append-only by design: Agora versions every register as a NEW snapshot
# (never overwrites a prior one); creating a method config is no-clobber
# (Rawls rejects a duplicate config name). There are NO delete primitives.

def agora_register_method(token: str, namespace: str, name: str,
                          wdl_payload: str, *, synopsis: str = "",
                          documentation: str = "") -> dict:
    """Register a WDL as a new Agora method SNAPSHOT (append-only — never
    overwrites a prior snapshot). Returns the method incl. its snapshotId."""
    body = {
        "namespace": namespace,
        "name": name,
        "synopsis": synopsis,
        "documentation": documentation,
        "payload": wdl_payload,
        "entityType": "Workflow",
    }
    return _request("agora", "POST", AGORA_BASE,
                    "/api/v1/methods", token, json_body=body)


def rawls_create_method_config(token: str, namespace: str, name: str, *,
                               config_namespace: str, config_name: str,
                               method_namespace: str, method_name: str,
                               method_version: int,
                               inputs: dict, outputs: dict | None = None,
                               root_entity_type: str | None = None) -> dict:
    """Create a workspace method configuration binding an Agora method to its
    inputs (literal expressions for DIRECT/entity-less runs). No-clobber —
    Rawls rejects a duplicate config name (no overwrite)."""
    body: dict = {
        "namespace": config_namespace,
        "name": config_name,
        "methodRepoMethod": {
            "sourceRepo": "agora",
            "methodNamespace": method_namespace,
            "methodName": method_name,
            "methodVersion": int(method_version),
        },
        "inputs": inputs or {},
        "outputs": outputs or {},
        "prerequisites": {},
        "methodConfigVersion": 1,
        "deleted": False,
    }
    if root_entity_type:
        body["rootEntityType"] = root_entity_type
    return _request("rawls", "POST", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}/methodconfigs",
                    token, json_body=body)


# ── Read-only workspace data + submission/workflow inspection ───────────────
# These provide a comprehensive read surface (data tables, submissions,
# strict superset of its reads. Every function here is GET-only — no write,
# no spend, no destruction.

def rawls_list_data_tables(token: str, namespace: str, name: str) -> dict:
    """List the workspace's entity types (data tables) and per-type metadata
    (row count, attribute names, id column). Read-only."""
    resp = _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}/entities",
                    token)
    return resp if isinstance(resp, dict) else {}


def rawls_get_entities(token: str, namespace: str, name: str, entity_type: str, *,
                       page: int = 1, page_size: int = 50) -> dict:
    """Paged rows of one data table via the entityQuery endpoint. Read-only.

    Returns {results: [...], resultMetadata: {unfilteredCount, filteredCount,
    filteredPageCount}}. Caller is responsible for sane page_size caps."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/entityQuery/{_quote(entity_type)}", token,
                    params={"page": int(page), "pageSize": int(page_size)})


def rawls_list_submissions(token: str, namespace: str, name: str) -> list[dict]:
    """List every submission in the workspace (each: submissionId, status,
    submissionDate, methodConfigurationName, workflow counts). Read-only."""
    resp = _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}/submissions",
                    token)
    return resp if isinstance(resp, list) else []


def rawls_get_workflow_metadata(token: str, namespace: str, name: str,
                                submission_id: str, workflow_id: str) -> dict:
    """Full Cromwell metadata for one workflow (status, the per-call execution
    tree, inputs, failures, timing). Read-only. Can be very large — the server
    tool summarizes the call tree by default."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/submissions/{_quote(submission_id)}"
                    f"/workflows/{_quote(workflow_id)}", token)


def rawls_get_workflow_cost(token: str, namespace: str, name: str,
                            submission_id: str, workflow_id: str) -> dict:
    """Compute cost of one workflow execution. Read-only."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/submissions/{_quote(submission_id)}"
                    f"/workflows/{_quote(workflow_id)}/cost", token)


def rawls_get_method_config(token: str, namespace: str, name: str,
                            config_namespace: str, config_name: str) -> dict:
    """Read one method configuration's contents (method ref, inputs, outputs,
    root entity type). Read-only — the counterpart to create_method_config,
    useful for verifying a config before a submit."""
    return _request("rawls", "GET", RAWLS_BASE,
                    f"/api/workspaces/{_quote(namespace)}/{_quote(name)}"
                    f"/methodconfigs/{_quote(config_namespace)}/{_quote(config_name)}",
                    token)
