"""Runtime policy enforcement for mcp-terra.

Threat model: attacker has shell access + already-authenticated gcloud /
Terra. They could call gsutil/curl directly and bypass the MCP entirely —
so the MCP CANNOT fundamentally prevent a fully compromised host. What
this module does:

  • makes the MCP NOT be the easiest weapon (defaults to read-only)
  • leaves a clear forensic trail (append-only audit log)
  • bounds the rate of operations (limits bulk-exfil if abused)
  • lets the user opt into a workspace allowlist smaller than their
    full Terra ACL
  • surfaces tampering at startup via a code-integrity hash

All policy state is read from env vars and a per-user config dir at
`~/.mcp-terra/`. There are no per-call overrides — the agent CANNOT change
policy by passing a parameter.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from pathlib import Path


# ── Config locations ───────────────────────────────────────────────────────

CONFIG_DIR = Path.home() / ".mcp-terra"
AUDIT_LOG  = CONFIG_DIR / "audit.log"
ALLOW_FILE = CONFIG_DIR / "allowed_workspaces.txt"
KILL_FILE  = CONFIG_DIR / "KILL"   # tripwire: existence ⇒ MCP refuses everything


class PolicyError(RuntimeError):
    """Raised when a policy precondition is violated.

    Optional structured fields (set by caller; default None) so the MCP
    client / agent can branch on a stable code instead of substring-matching
    the message. See docs/error_codes.md for the taxonomy.
    """

    def __init__(self, message: str, *, code: str | None = None,
                 retryable: bool = False, user_action_required: str | None = None):
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.user_action_required = user_action_required


# ── Env-var policy switches ────────────────────────────────────────────────

def _env_truthy(name: str) -> bool:
    """Return True if the env var is set to a truthy value."""
    v = os.environ.get(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


# ── Controlled-access data-egress guard (NIH GDS / DUC) ─────────────────────
# When MCP_TERRA_CONTROLLED_ACCESS is on, the MCP refuses to return raw
# workspace DATA (object bytes, data-table rows) to the LLM — controlled-access
# genomic data must not reach a public generative AI (GDS/DUC Non-
# Transferability). It is OFF BY DEFAULT, so lab-generated and public-database
# analysis is never hindered. Even when ON: PUBLIC reference buckets and
# operator-certified non-controlled buckets are still allowed, and the on-VM
# analysis loop + all diagnosis tools (logs, metadata, workflow status, cost)
# remain fully available — the guard only blocks raw-DATA egress to the LLM.
_CONTROLLED_ACCESS = _env_truthy("MCP_TERRA_CONTROLLED_ACCESS")
_DATA_EGRESS_ALLOW = frozenset(
    b.strip().lower()
    for b in os.environ.get("MCP_TERRA_DATA_EGRESS_ALLOW", "").replace(",", " ").split()
    if b.strip())

# Well-known PUBLIC genomics/reference buckets, matched by EXACT name only.
# Prefix matching is unsafe — a controlled bucket could be NAMED to collide
# (e.g. 'gnomad-public-impostor'), turning the guard into bucket-name trust
# (security review finding). Bucket names are a flat global namespace, so only exact
# identity is trustworthy. Operators add others via MCP_TERRA_DATA_EGRESS_ALLOW.
_PUBLIC_DATA_BUCKETS = frozenset({
    "gcp-public-data--broad-references",
    "gcp-public-data--gnomad",
    "genomics-public-data",
    "gatk-test-data",
    "gatk-best-practices",
    "hail-common",
    "hail-datasets-us",
    "hail-datasets-eu",
})


def controlled_access_enabled() -> bool:
    """True if the controlled-access data-egress guard is active."""
    return _CONTROLLED_ACCESS


def max_run_hours() -> int:
    """The Terra interactive-session/credential window (hours) used to bound a
    single on-VM notebook run, so a long run is halted with a clear status
    instead of hitting the ~24h credential cliff mid-execution. The on-VM
    runner reads the SAME env (MCP_TERRA_MAX_RUN_HOURS) independently; this
    helper is the submit-side mirror for the user-facing advisory. Clamp 1..24."""
    try:
        h = int(os.environ.get("MCP_TERRA_MAX_RUN_HOURS", "24") or "24")
    except (TypeError, ValueError):
        h = 24
    return max(1, min(h, 24))


def session_margin_sec() -> int:
    """Safety headroom (seconds) subtracted from the session window before the
    runner halts a run — so it stops BEFORE the credential cliff, not at it. The
    on-VM runner reads the same env (MCP_TERRA_SESSION_MARGIN_SEC) independently;
    this is the submit-side mirror for propagation into the VM. Clamp 60..3600."""
    try:
        m = int(os.environ.get("MCP_TERRA_SESSION_MARGIN_SEC", "1800") or "1800")
    except (TypeError, ValueError):
        m = 1800
    return max(60, min(m, 3600))


def max_cost_usd() -> float:
    """Workspace credit cap (USD) the user opts into via MCP_TERRA_MAX_COST_USD.
    0 / unset = no cap. When set, the on-VM runner self-HALTS the VM (stop/pause,
    persistent disk kept — never delete) before the estimated VM spend exceeds
    it, and the submit tools warn in advance. Clamp >= 0."""
    try:
        c = float(os.environ.get("MCP_TERRA_MAX_COST_USD", "0") or "0")
    except (TypeError, ValueError):
        c = 0.0
    return max(0.0, c)


def vm_hourly_usd() -> float:
    """The operator's VM hourly rate (USD) for the spend-cap estimate, set via
    MCP_TERRA_VM_HOURLY_USD. We do NOT hardcode GCP prices (they drift + vary by
    machine/GPU/region) — the estimate is honest (real uptime x the user's real
    rate). 0 / unset = the VM self-halt is disabled (cap stays advisory)."""
    try:
        r = float(os.environ.get("MCP_TERRA_VM_HOURLY_USD", "0") or "0")
    except (TypeError, ValueError):
        r = 0.0
    return max(0.0, r)


# ── Rolling spend budget (opt-in; per-run cap OR over a time window) ─────────
# The PER-RUN cap is passed to terra_create_runtime (max_cost_usd) and enforced
# by the on-VM runner (the VM self-stops before that estimate). The ROLLING
# budget below is an opt-in ceiling over a time window (e.g. $500 / 30 days): the
# MCP refuses a new run when the sum of per-run caps committed within the window
# plus this run's cap would exceed it. It is a WORST-CASE bound (each run cannot
# exceed its own cap, so actual spend <= committed caps); for an authoritative,
# cloud-enforced monthly cap, ALSO set a GCP billing budget on the project.
_SPEND_LEDGER = CONFIG_DIR / "spend_ledger.jsonl"


def budget_usd() -> float:
    """Opt-in rolling spend budget (USD) over budget_window_days(). 0/unset = off."""
    try:
        b = float(os.environ.get("MCP_TERRA_BUDGET_USD", "0") or "0")
    except (TypeError, ValueError):
        b = 0.0
    return max(0.0, b)


def budget_window_days() -> int:
    """The rolling window (days) the budget applies over. Default 30; clamp 1..366."""
    try:
        d = int(os.environ.get("MCP_TERRA_BUDGET_WINDOW_DAYS", "30") or "30")
    except (TypeError, ValueError):
        d = 30
    return max(1, min(d, 366))


def windowed_spend_usd(now_epoch: float) -> float:
    """Sum the per-run caps recorded in the ledger within the rolling window."""
    if not _SPEND_LEDGER.exists():
        return 0.0
    cutoff = now_epoch - budget_window_days() * 86400
    total = 0.0
    try:
        for line in _SPEND_LEDGER.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                continue
            try:
                if float(rec.get("ts", 0)) >= cutoff:
                    total += max(0.0, float(rec.get("usd", 0)))
            except (TypeError, ValueError):
                continue
    except OSError:
        pass
    return total


def assert_within_budget(new_run_usd: float, now_epoch: float) -> None:
    """Refuse a new run when a rolling budget is set and it would be exceeded.
    Fail-LOUD. No-op when no budget is configured."""
    b = budget_usd()
    if b <= 0:
        return
    if new_run_usd <= 0:
        raise PolicyError(
            "A rolling spend budget (MCP_TERRA_BUDGET_USD) is set, so each run "
            "MUST specify a per-run cap (max_cost_usd) — otherwise spend cannot "
            "be bounded against the budget.",
            code="E_BUDGET_REQUIRES_CAP",
            user_action_required="pass a max_cost_usd to this run")
    spent = windowed_spend_usd(now_epoch)
    if spent + new_run_usd > b:
        raise PolicyError(
            f"rolling spend budget would be exceeded: ${spent:.2f} already "
            f"committed in the last {budget_window_days()}d + ${new_run_usd:.2f} "
            f"for this run > ${b:.2f} budget (MCP_TERRA_BUDGET_USD). Wait for the "
            f"window to roll off, lower this run's cap, or raise the budget.",
            code="E_BUDGET_EXCEEDED",
            user_action_required="lower the run cap, wait, or raise the budget")


def record_run_cost(usd: float, ref: str, now_epoch: float) -> None:
    """Append a run's committed per-run cap to the ledger (only when a budget is
    active and the cap is positive). Best-effort; never raises."""
    if budget_usd() <= 0 or usd <= 0:
        return
    try:
        _SPEND_LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with open(_SPEND_LEDGER, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": now_epoch, "usd": float(usd),
                                 "ref": str(ref)[:200]}) + "\n")
    except OSError:
        pass


def runner_concurrency() -> int:
    """How many job specs ONE on-VM runner may execute at once (single-VM
    concurrency / bounded papermill pool). The on-VM runner reads the SAME env
    (MCP_TERRA_RUNNER_CONCURRENCY) independently; this helper is the submit-side
    mirror so the MCP can propagate the value to the VM. Default 4, clamp 1..16."""
    try:
        c = int(os.environ.get("MCP_TERRA_RUNNER_CONCURRENCY", "4") or "4")
    except (TypeError, ValueError):
        c = 4
    return max(1, min(c, 16))


def is_egress_allowed_bucket(bucket: str) -> bool:
    """True if `bucket` may have its DATA returned to the LLM even under the
    controlled-access guard — an EXACT-name match against a known PUBLIC
    reference bucket OR an operator-certified non-controlled bucket
    (MCP_TERRA_DATA_EGRESS_ALLOW). EXACT match only: no prefix trust."""
    b = (bucket or "").strip().lower()
    if not b:
        return False
    return b in _DATA_EGRESS_ALLOW or b in _PUBLIC_DATA_BUCKETS


def assert_data_egress_allowed(bucket: str, what: str) -> None:
    """Refuse to return raw workspace DATA to the LLM when the guard is on and
    `bucket` is not public/allowlisted. No-op when the guard is off (lab/public
    analysis unhindered). Fail-loud — never a silent drop."""
    if not _CONTROLLED_ACCESS:
        return
    if is_egress_allowed_bucket(bucket):
        return
    raise PolicyError(
        f"controlled-access mode (MCP_TERRA_CONTROLLED_ACCESS=1): refusing to "
        f"return {what} from bucket {bucket!r} to the LLM — it may be NIH "
        f"controlled-access data, and GDS/DUC Non-Transferability forbids "
        f"sending controlled-access data to a public generative AI. Options: "
        f"(a) lab-open or public data → add the bucket to "
        f"MCP_TERRA_DATA_EGRESS_ALLOW; (b) run the orchestrating agent against a "
        f"self-hosted / NIST-800-171 model; (c) disable the guard for a "
        f"non-controlled workspace. Status/metadata-only tools remain available.")


def assert_no_controlled_data_egress(what: str) -> None:
    """Refuse a workspace-scoped read that would return potential controlled
    DATA (values, outputs, free-text logs/tracebacks, sample ids/paths) to the
    LLM when the guard is on. Unlike `assert_data_egress_allowed` there is no
    per-bucket exception — the locked workspace itself is controlled when the
    guard is set. No-op when the guard is off."""
    if not _CONTROLLED_ACCESS:
        return
    raise PolicyError(
        f"controlled-access mode (MCP_TERRA_CONTROLLED_ACCESS=1): refusing to "
        f"return {what} to the LLM — it may carry controlled-access data "
        f"(values, sample ids, object paths, or printed output). GDS/DUC "
        f"forbids controlled data to a public generative AI. Use a self-hosted "
        f"/ NIST-800-171 model, or disable the guard for a non-controlled "
        f"workspace. Status/metadata-only tools remain available.")


# ── Startup snapshots ──────────────────────────────────────────────────────
#
# Per audit: reading MCP_TERRA_ALLOW_WRITES and MCP_TERRA_WORKSPACE on EVERY
# tool call lets an attacker with shell access flip them mid-session to
# slip a write through or to redirect operations to a different workspace.
# Snapshot both at module load and never re-read. The audit log records
# the snapshot in the startup banner.
#
# Trade-off: changing these vars after MCP start requires a restart. That's
# the intended behaviour — the security policy of an MCP session is fixed
# the moment it begins.

_WRITES_ALLOWED_SNAPSHOT: bool | None = None    # None = not yet snapshotted
_WORKSPACE_LOCK_RAW_SNAPSHOT: str | None = None
_SNAPSHOT_LOCK = threading.Lock()


def _snapshot_env_once() -> None:
    """Capture writes-allowed + workspace-lock env vars once. Idempotent."""
    global _WRITES_ALLOWED_SNAPSHOT, _WORKSPACE_LOCK_RAW_SNAPSHOT
    with _SNAPSHOT_LOCK:
        if _WRITES_ALLOWED_SNAPSHOT is None:
            _WRITES_ALLOWED_SNAPSHOT = _env_truthy("MCP_TERRA_ALLOW_WRITES")
            _WORKSPACE_LOCK_RAW_SNAPSHOT = os.environ.get("MCP_TERRA_WORKSPACE", "").strip()


def writes_allowed() -> bool:
    """Whether write/spend tools may run this session.

    Reads from the immutable startup snapshot. Default: NO.
    The user must set MCP_TERRA_ALLOW_WRITES=1 BEFORE starting the MCP.
    Changing the env var after the MCP starts has NO effect — defense
    against an attacker with shell access toggling writes mid-session.
    """
    if _WRITES_ALLOWED_SNAPSHOT is None:
        _snapshot_env_once()
    return bool(_WRITES_ALLOWED_SNAPSHOT)


def writes_required_message() -> str:
    return (
        "This operation is a write/spend action, but the MCP is currently in "
        "READ-ONLY mode (the default). To enable write/spend operations, set "
        "MCP_TERRA_ALLOW_WRITES=1 in the environment before starting the MCP. "
        "(This is a deliberate guard — the user must explicitly opt into writes.)"
    )


# ── Workspace allowlist override (optional, in addition to Terra ACL) ──────

def load_workspace_allowlist() -> set[str] | None:
    """Return the user's optional workspace allowlist (subset of Terra ACL).

    Reads `~/.mcp-terra/allowed_workspaces.txt`. One workspace per line, in
    the form `namespace/name`. Lines starting with `#` are comments. If
    the file doesn't exist, returns None (meaning: fall back to full Terra
    ACL allowlist, with a warning).
    """
    if not ALLOW_FILE.exists():
        return None
    out: set[str] = set()
    for raw in ALLOW_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "/" not in line:
            print(f"[mcp-terra policy] warn: malformed allowlist line {raw!r}",
                  file=sys.stderr)
            continue
        out.add(line)
    return out


# ── Single-workspace lock (one MCP instance = one workspace) ───────────────
#
# When `MCP_TERRA_WORKSPACE=namespace/name` is set, the MCP refuses to touch
# any workspace, project, or bucket OTHER than that one. This is the
# strongest containment: even if a prompt-injection attacker hijacks the
# agent, the blast radius is at most one workspace.
#
# Format: MCP_TERRA_WORKSPACE="your-namespace/your-workspace"
# When unset: MCP operates in "open" mode (any workspace the user can see).

import re as _re

_LOCKED: dict | None = None      # cached resolved workspace metadata
_LOCKED_RESOLVED = False         # has the cache been populated this process?
_LOCKED_LOCK = threading.Lock()
_LOCK_PATTERN = _re.compile(r"^([A-Za-z0-9][A-Za-z0-9_\-.]{0,126})/([A-Za-z0-9][A-Za-z0-9_\-.]{0,126})$")


def get_locked_workspace_id() -> tuple[str, str] | None:
    """Parse the snapshotted MCP_TERRA_WORKSPACE value.

    Reads from the immutable startup snapshot — env changes after MCP
    start are ignored.
    """
    _snapshot_env_once()
    raw = _WORKSPACE_LOCK_RAW_SNAPSHOT or ""
    if not raw:
        return None
    m = _LOCK_PATTERN.match(raw)
    if not m:
        raise PolicyError(
            f"MCP_TERRA_WORKSPACE={raw!r} is malformed. Expected format: "
            f"'namespace/name' with alphanumeric, '-', '_', or '.' characters. "
            f"Refusing to start MCP with broken workspace lock."
        )
    return m.group(1), m.group(2)


def resolve_locked_workspace() -> dict | None:
    """Resolve the locked workspace's bucket + googleProject via Rawls.

    Cached per process (single lookup at first use). Thread-safe.
    Returns dict with {namespace, name, bucketName, googleProject} or None
    if no lock set. Raises PolicyError if the locked workspace doesn't
    exist / isn't accessible.
    """
    global _LOCKED, _LOCKED_RESOLVED
    with _LOCKED_LOCK:
        if _LOCKED_RESOLVED:
            return _LOCKED
    # Resolve outside the lock (network call). On race, both threads do the
    # same Rawls lookup and arrive at the same _LOCKED — idempotent.
    lock_id = get_locked_workspace_id()
    if lock_id is None:
        with _LOCKED_LOCK:
            _LOCKED_RESOLVED = True
            _LOCKED = None
            return None
    namespace, name = lock_id
    from . import auth, terra_client as tc
    token = auth.get_access_token()
    try:
        ws = tc.rawls_get_workspace(token, namespace, name)
    except tc.TerraAPIError as e:
        raise PolicyError(
            f"MCP_TERRA_WORKSPACE={namespace}/{name}: Rawls lookup failed: {e}. "
            f"Either you don't have access, or the workspace doesn't exist. "
            f"Refusing to start MCP with broken workspace lock."
        )
    wsd = ws.get("workspace", {})
    bucket = wsd.get("bucketName")
    project = wsd.get("googleProject")
    if not bucket or not project:
        raise PolicyError(
            f"Locked workspace {namespace}/{name} resolved but missing "
            f"bucketName or googleProject. Rawls response: {ws}"
        )
    with _LOCKED_LOCK:
        _LOCKED = {
            "namespace": namespace,
            "name": name,
            "bucketName": bucket,
            "googleProject": project,
        }
        _LOCKED_RESOLVED = True
        return _LOCKED


def assert_workspace_allowed(namespace: str, name: str) -> None:
    """Refuse if the lock is set and the requested workspace isn't it."""
    lock = resolve_locked_workspace()
    if lock is None:
        return  # open mode, all workspaces allowed via Terra ACL
    if namespace != lock["namespace"] or name != lock["name"]:
        raise PolicyError(
            f"MCP locked to workspace {lock['namespace']}/{lock['name']} via "
            f"MCP_TERRA_WORKSPACE. Refusing to access {namespace}/{name}."
        )


def assert_project_allowed(google_project: str) -> None:
    """Refuse if the lock is set and the requested project isn't the locked one."""
    lock = resolve_locked_workspace()
    if lock is None:
        return
    if google_project != lock["googleProject"]:
        raise PolicyError(
            f"MCP locked to project {lock['googleProject']} (workspace "
            f"{lock['namespace']}/{lock['name']}). Refusing to access "
            f"project {google_project!r}."
        )


def assert_bucket_allowed(gs_uri: str) -> None:
    """Refuse if the lock is set and the gs:// bucket isn't the locked one."""
    lock = resolve_locked_workspace()
    if lock is None:
        return
    if not gs_uri.startswith("gs://"):
        raise PolicyError(f"bucket URI must start with gs://; got {gs_uri!r}")
    bucket_name = gs_uri[5:].split("/", 1)[0]
    if bucket_name != lock["bucketName"]:
        raise PolicyError(
            f"MCP locked to bucket {lock['bucketName']} (workspace "
            f"{lock['namespace']}/{lock['name']}). Refusing to access bucket "
            f"{bucket_name!r}."
        )


# ── Rate limiting (sliding window) ─────────────────────────────────────────

class RateLimiter:
    """Two-tier sliding-window per-process rate limiter.

    A bot that paces itself just under a per-minute cap can still grind
    indefinitely (60/min = 3600/hr). So we enforce BOTH a burst window
    (per-minute) AND a sustained window (per-hour): a caller may burst up to
    `max_per_minute` but cannot exceed `max_per_hour` over any rolling hour.

    This caps the FREQUENCY of MCP tool calls, NOT the duration of a Terra job.
    A notebook/WDL run can take many hours — it is a single submit plus periodic
    status polls; the cap is sized so even heavy parallel monitoring (dozens of
    concurrent submissions polled every 30-60s) stays well under it.

    Defaults: 60/min, 3000/hour. Override via MCP_TERRA_MAX_CALLS_PER_MIN /
    MCP_TERRA_MAX_CALLS_PER_HOUR.
    """
    def __init__(self, max_per_minute: int = 60, max_per_hour: int = 3000):
        # Clamp to >=1 so a misconfigured 0/negative cap fails CLOSED (a tiny
        # limit) instead of crashing: with max=0, check() would index an empty
        # deque while building the wait message → IndexError on the first call.
        try:
            self.max = max(1, int(max_per_minute))
        except (TypeError, ValueError):
            self.max = 60
        try:
            self.max_hour = max(1, int(max_per_hour))
        except (TypeError, ValueError):
            self.max_hour = 3000
        self.window: collections.deque[float] = collections.deque()
        self.hour_window: collections.deque[float] = collections.deque()
        self.lock = threading.Lock()

    def check(self, tool_name: str) -> None:
        """Record a call. Raises PolicyError if over the burst or sustained cap."""
        now = time.monotonic()
        with self.lock:
            # Sustained (per-hour) window first — the anti-grind defense.
            while self.hour_window and now - self.hour_window[0] > 3600.0:
                self.hour_window.popleft()
            if len(self.hour_window) >= self.max_hour:
                wait_s = int(3600 - (now - self.hour_window[0]))
                raise PolicyError(
                    f"mcp-terra sustained rate limit exceeded: {self.max_hour} "
                    f"calls/hour. Last hour saw {len(self.hour_window)} tool calls. "
                    f"This is a defense against a self-paced bot grinding under the "
                    f"per-minute cap. Wait ~{wait_s}s.",
                    code="E_RATE_LIMITED",
                    retryable=True,
                    user_action_required=f"wait ~{wait_s}s and retry",
                )
            # Burst (per-minute) window — drop entries older than 60s.
            while self.window and now - self.window[0] > 60.0:
                self.window.popleft()
            if len(self.window) >= self.max:
                wait_s = int(60 - (now - self.window[0]))
                err = PolicyError(
                    f"mcp-terra rate limit exceeded: {self.max} calls/minute. "
                    f"Last 60s saw {len(self.window)} tool calls. "
                    f"This is a defense against bulk exfiltration. Wait ~{wait_s}s.",
                    code="E_RATE_LIMITED",
                    retryable=True,
                    user_action_required=f"wait ~{wait_s}s and retry",
                )
                raise err
            self.window.append(now)
            self.hour_window.append(now)


def _int_env_clamped(name: str, default: int) -> int:
    """Parse a positive-int env, falling back to default on junk/0/negative.
    Keeps a misconfigured limit from crashing the process at import."""
    try:
        v = int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default
    return v if v >= 1 else default


_RATE_LIMIT = _int_env_clamped("MCP_TERRA_MAX_CALLS_PER_MIN", 60)
_RATE_LIMIT_HOUR = _int_env_clamped("MCP_TERRA_MAX_CALLS_PER_HOUR", 3000)
_LIMITER = RateLimiter(max_per_minute=_RATE_LIMIT, max_per_hour=_RATE_LIMIT_HOUR)


def enforce_rate_limit(tool_name: str) -> None:
    _LIMITER.check(tool_name)


# ── Per-session submit cap (runaway-cost defense) ───────────────────────────
# Bounds how many notebook jobs a single MCP process can submit before the
# user must restart. Defends against an agent that has been pre-authorized
# to call terra_submit_notebook_job without per-call permission burning
# through spend in an unbounded loop. The runner has its own FAIL_STREAK
# ceiling; this is the MCP-side complement.
_MAX_SUBMITS_PER_SESSION = int(os.environ.get("MCP_TERRA_MAX_SUBMITS_PER_SESSION", "25"))
_submit_count = 0
_submit_lock = threading.Lock()


def enforce_submit_cap() -> None:
    """Increment + check the per-session submit counter.

    Raises PolicyError when the cap is reached. The cap is intentionally
    hard — restart the MCP process to reset. This is FAIL-CLOSED.
    """
    global _submit_count
    with _submit_lock:
        if _submit_count >= _MAX_SUBMITS_PER_SESSION:
            raise PolicyError(
                f"per-session submit cap reached: {_submit_count} / "
                f"{_MAX_SUBMITS_PER_SESSION}. Restart the MCP process to "
                f"reset (the cap is intentional — runaway-cost defense). "
                f"To raise the ceiling, set MCP_TERRA_MAX_SUBMITS_PER_SESSION "
                f"before restart.",
                code="E_SUBMIT_CAP_EXCEEDED",
                retryable=False,
                user_action_required=(
                    "Restart the MCP process; optionally raise "
                    "MCP_TERRA_MAX_SUBMITS_PER_SESSION first."
                ),
            )
        _submit_count += 1


def submits_remaining() -> int:
    with _submit_lock:
        return max(0, _MAX_SUBMITS_PER_SESSION - _submit_count)


# ── Kill-switch (panic abort) ──────────────────────────────────────────────
#
# Two trip mechanisms, both checked on EVERY tool call:
#
#   1. **File tripwire** — `~/.mcp-terra/KILL` exists.
#      Quickest possible abort from any terminal: `touch ~/.mcp-terra/KILL`.
#      Once tripped, the MCP refuses ALL operations (even reads) and exits
#      the process after surfacing the abort. The user must `rm KILL` to
#      re-enable — failure mode is FAIL-CLOSED.
#
#   2. **Refusal threshold** — if more than _KILL_REFUSAL_THRESHOLD operations
#      are refused (by safety check, lock check, or write gate) within
#      _KILL_REFUSAL_WINDOW seconds, the MCP auto-trips. This catches
#      scripted-abuse attempts (e.g., an agent in a fixed loop banging on
#      writes_allowed=False).
#
# The tripwire is checked at the head of every tool's _pre() — see
# server.check_killswitch(). On trip the MCP writes a final audit line
# and raises KillSwitchError (a subclass of PolicyError), then on the next
# stdio read it exits.

import collections as _collections
import threading as _threading

_KILL_REFUSAL_THRESHOLD = int(os.environ.get("MCP_TERRA_KILL_REFUSAL_THRESHOLD", "10"))
_KILL_REFUSAL_WINDOW    = float(os.environ.get("MCP_TERRA_KILL_REFUSAL_WINDOW_SEC", "60"))
_refusal_times: _collections.deque[float] = _collections.deque()
_refusal_lock = _threading.Lock()
_killed_flag = False
_killed_reason: str | None = None


class KillSwitchError(PolicyError):
    """Raised when the MCP has been tripped — refuses ALL operations.

    Once raised, the MCP should exit cleanly. The user must remove
    ~/.mcp-terra/KILL to re-enable, AND restart the MCP process.
    """


def _trip_killswitch(reason: str) -> None:
    """Mark the MCP as tripped, write the KILL file, and audit-log it."""
    global _killed_flag, _killed_reason
    _killed_flag = True
    _killed_reason = reason
    _ensure_audit_dir()
    try:
        with open(KILL_FILE, "w") as fh:
            fh.write(f"TRIPPED at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')}Z\n"
                     f"reason: {reason}\n"
                     f"pid: {os.getpid()}\n")
        os.chmod(KILL_FILE, 0o600)
    except OSError:
        # Even if we can't write the file, the in-memory flag holds for
        # this process. Other MCP processes won't see it though.
        pass
    audit_log("__killswitch__", "TRIPPED", reason)
    print(f"\n[mcp-terra] KILL SWITCH TRIPPED: {reason}\n"
          f"[mcp-terra] All further operations refused until "
          f"{KILL_FILE} is removed AND the MCP process is restarted.",
          file=sys.stderr, flush=True)


def check_killswitch(tool_name: str) -> None:
    """Refuse any operation if the MCP is tripped (either flag or file).

    Called at the head of every tool via server._pre().
    """
    global _killed_flag, _killed_reason
    if _killed_flag:
        raise KillSwitchError(
            f"MCP is KILL-SWITCHED in-process (reason: {_killed_reason}). "
            f"All operations refused. Remove {KILL_FILE} AND restart the MCP.",
            code="E_KILLSWITCH_TRIPPED",
            retryable=False,
            user_action_required=f"rm {KILL_FILE} AND restart the MCP process",
        )
    if KILL_FILE.exists():
        # File-based trip: also set the in-memory flag so subsequent calls
        # are fast-refused even if the file is later removed.
        _killed_flag = True
        try:
            _killed_reason = KILL_FILE.read_text().strip()[:300]
        except OSError:
            _killed_reason = "KILL file present"
        raise KillSwitchError(
            f"MCP kill-switch file present at {KILL_FILE}. "
            f"All operations refused. Remove the file AND restart the MCP "
            f"to re-enable. Reason on file: {_killed_reason!r}",
            code="E_KILLSWITCH_TRIPPED",
            retryable=False,
            user_action_required=f"rm {KILL_FILE} AND restart the MCP process",
        )


def record_refusal(tool_name: str, reason: str) -> None:
    """Record a refused operation. Auto-trips the kill-switch if too many
    refusals happen within the window.

    Called by server._pre() after a check fails (writes_allowed gate,
    workspace lock, etc.).
    """
    now = time.monotonic()
    with _refusal_lock:
        # Drop entries older than the window
        while _refusal_times and now - _refusal_times[0] > _KILL_REFUSAL_WINDOW:
            _refusal_times.popleft()
        _refusal_times.append(now)
        n_in_window = len(_refusal_times)
    if n_in_window >= _KILL_REFUSAL_THRESHOLD:
        _trip_killswitch(
            f"{n_in_window} operations refused in the last "
            f"{_KILL_REFUSAL_WINDOW:.0f}s — auto-trip threshold "
            f"({_KILL_REFUSAL_THRESHOLD}) exceeded. "
            f"Last tool: {tool_name}, last reason: {reason[:120]}"
        )


def killswitch_reset() -> None:
    """Reset the in-memory kill-switch flag.

    The MCP NEVER calls this. It exists so an automated test can re-enable
    after a deliberate trip. Removing ~/.mcp-terra/KILL alone is NOT
    sufficient in a running process — the process must be restarted.
    """
    global _killed_flag, _killed_reason, _refusal_times
    _killed_flag = False
    _killed_reason = None
    _refusal_times.clear()


# ── Append-only audit log ──────────────────────────────────────────────────

def _ensure_audit_dir() -> None:
    """Ensure CONFIG_DIR exists, is owned by current user, is not a symlink.

    Refuses if:
      • CONFIG_DIR exists as a symlink (attacker pre-created a link to elsewhere)
      • CONFIG_DIR exists but is not owned by the current uid
      • permissions are too loose (group/world writable)
    """
    if CONFIG_DIR.is_symlink():
        raise PolicyError(
            f"CONFIG_DIR {CONFIG_DIR} is a symlink. Refusing to use — an "
            f"attacker may have replaced the config dir with a redirect to "
            f"a sensitive location. Inspect and remove manually."
        )
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, mode=0o700)
    # Verify ownership + permissions
    st = os.lstat(CONFIG_DIR)
    if st.st_uid != os.geteuid():
        raise PolicyError(
            f"CONFIG_DIR {CONFIG_DIR} is owned by uid {st.st_uid}, not us "
            f"(uid {os.geteuid()}). Refusing to use a config dir we don't own."
        )
    if st.st_mode & 0o077:
        # Group / world have ANY perm — tighten and re-check.
        os.chmod(CONFIG_DIR, 0o700)
        st = os.lstat(CONFIG_DIR)
        if st.st_mode & 0o077:
            raise PolicyError(
                f"CONFIG_DIR {CONFIG_DIR} has group/world permissions "
                f"that could not be removed (mode {oct(st.st_mode)}). "
                f"Inspect manually."
            )


_AUDIT_MAX_BYTES = int(os.environ.get("MCP_TERRA_AUDIT_MAX_BYTES", str(100 * 1024 * 1024)))
_AUDIT_BACKUPS = int(os.environ.get("MCP_TERRA_AUDIT_BACKUPS", "5"))
_audit_lock = threading.Lock()
_audit_prev_hash: str | None = None   # rolling chain head (in-memory)


def _seed_audit_prev_hash() -> None:
    """On startup, seed _audit_prev_hash from the LAST line of AUDIT_LOG
    so the chain continues across MCP restarts. Without this, every
    restart writes a line whose prev_hash="" — and verify_audit_chain()
    flags the discontinuity as tampering.
    """
    global _audit_prev_hash
    if _audit_prev_hash is not None: return
    if not AUDIT_LOG.exists(): return
    try:
        with open(AUDIT_LOG, "rb") as fh:
            # Tail efficiently: seek to last 8 KiB.
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 8192))
            tail = fh.read()
        last = tail.splitlines()[-1] if tail.splitlines() else b""
        if not last: return
        try:
            _, digest = last.rsplit(b"\t", 1)
            _audit_prev_hash = digest.decode("ascii", errors="replace")
        except ValueError:
            return
    except OSError:
        return


def _audit_chain_secret() -> bytes:
    """HMAC key for the tamper-evident audit chain.

    Reuses MCP_TERRA_RUNNER_SECRET (already required for notebook execution
    and already entropy-checked). If unset, the chain falls back to plain
    SHA-256 — the chain still detects tampering by any attacker who lacks
    a snapshot of the previous hash, but a sophisticated attacker who reads
    the audit log could rebuild it. With the secret set, only someone who
    also reads the secret can re-forge the chain.
    """
    s = os.environ.get("MCP_TERRA_RUNNER_SECRET", "")
    return s.encode("utf-8") if s else b""


def _rotate_audit_if_needed() -> None:
    """Rotate AUDIT_LOG → .1 .. .N when it exceeds _AUDIT_MAX_BYTES.

    Each backup is renamed atomically. The oldest backup is RENAMED to
    `.N+1.archive` (NEVER deleted — no-destruction principle). The user
    can manually move/compress archives offline.
    """
    try:
        if not AUDIT_LOG.exists(): return
        if AUDIT_LOG.stat().st_size < _AUDIT_MAX_BYTES: return
    except OSError:
        return
    # Push backups up the chain. .5 → .6.archive (preserve), .4 → .5, etc.
    for i in range(_AUDIT_BACKUPS, 0, -1):
        src = AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + f".{i}")
        if not src.exists(): continue
        if i == _AUDIT_BACKUPS:
            dst = AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + f".{i+1}.archive")
            n = 1
            while dst.exists():
                n += 1
                dst = AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + f".{i+1}.archive.{n}")
        else:
            dst = AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + f".{i+1}")
        try:
            os.rename(src, dst)
        except OSError:
            pass
    try:
        os.rename(AUDIT_LOG, AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + ".1"))
    except OSError:
        pass


def _read_last_chain_digest_from_disk() -> str:
    """Read the last 64-hex chain digest from AUDIT_LOG, or '' if none.

    Used to refresh prev_hash IMMEDIATELY before each write so that
    concurrent writers (multiple Python processes sharing the same file
    e.g. an MCP server + ad-hoc scripts) don't corrupt the chain. The
    write itself is held under fcntl.flock so two processes can't
    interleave at the byte level either.
    """
    if not os.path.exists(AUDIT_LOG):
        return ""
    try:
        with open(AUDIT_LOG, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 8192))
            tail = fh.read()
    except OSError:
        return ""
    import re as _re
    hex64 = _re.compile(rb"^[0-9a-f]{64}$")
    for raw in reversed(tail.splitlines()):
        stripped = raw.rstrip(b"\n")
        if not stripped:
            continue
        try:
            _, recorded = stripped.rsplit(b"\t", 1)
        except ValueError:
            continue
        if hex64.match(recorded):
            return recorded.decode("ascii")
    return ""   # no chain-format line found; first write starts fresh


def audit_log(tool: str, action: str, detail: str) -> None:
    """Append a tamper-evident line to the persistent audit log.

    Each line is: <ts>\\t<pid>\\t<tool>\\t<action>\\t<detail>\\t<chain_hmac>
    where chain_hmac = HMAC-SHA256(secret, prev_hmac || line_body).

    An attacker who silently deletes or alters past lines BREAKS the chain:
    the next legitimate audit call's prev-hash won't match a re-computation
    from disk, and offline verification (re-hashing the file) will surface
    the tamper.

    Cross-process correct: we re-read prev_hash from disk under fcntl.flock
    immediately before computing the new digest. This means multiple Python
    processes can safely share AUDIT_LOG — without the lock + re-read, each
    process's in-memory `_audit_prev_hash` would diverge from the on-disk
    state once another process wrote a line in between.

    Rotation: at 100 MB the log rotates to audit.log.1 .. .5, with .6+
    preserved as `.archive` files (no-destruction principle).
    """
    global _audit_prev_hash
    if not _audit_lock.acquire(timeout=5.0):
        print(f"[mcp-terra audit] WARN: audit lock contended; degrading to "
              f"stderr for {tool}/{action}", file=sys.stderr)
        return
    try:
        try:
            _ensure_audit_dir()
        except PolicyError as e:
            print(f"[mcp-terra audit] WARN: audit dir unusable ({e}); "
                  f"degrading to stderr for {tool}/{action}", file=sys.stderr)
            return
        _rotate_audit_if_needed()
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        pid = os.getpid()
        def _safe(s: str) -> str:
            if not isinstance(s, str): s = str(s)
            return s.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")
        body = f"{ts}\t{pid}\t{_safe(tool)}\t{_safe(action)}\t{_safe(detail)}"

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(AUDIT_LOG, flags, 0o600)
        except OSError as e:
            print(f"[mcp-terra audit] WARN: audit open failed ({e}); "
                  f"degrading to stderr for {tool}/{action}", file=sys.stderr)
            return
        try:
            # Cross-process exclusive lock so re-read + write are atomic
            # vs. any other process also writing audit_log.
            import fcntl as _fcntl
            try:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            except OSError:
                pass   # not all filesystems support flock; fall through
            # Re-read prev from disk UNDER the lock — defeats cross-process
            # in-memory drift.
            disk_prev = _read_last_chain_digest_from_disk()
            prev = disk_prev.encode("utf-8")
            key = _audit_chain_secret()
            if key:
                digest = hmac.new(key, prev + body.encode("utf-8"),
                                  hashlib.sha256).hexdigest()
            else:
                digest = hashlib.sha256(prev + body.encode("utf-8")).hexdigest()
            line = f"{body}\t{digest}\n"
            try:
                os.write(fd, line.encode("utf-8"))
            except OSError as e:
                print(f"[mcp-terra audit] WARN: audit write failed ({e})",
                      file=sys.stderr)
                return
            _audit_prev_hash = digest
        finally:
            try: os.close(fd)
            except OSError: pass
    finally:
        _audit_lock.release()


def verify_audit_chain(path=None) -> dict:
    """Re-hash the audit log on disk and verify chain integrity.

    Returns {ok: bool, lines: int, first_break_line: int|None, reason: str}.
    A break means an attacker (or disk corruption) tampered with the log.
    """
    p = path or AUDIT_LOG
    if not os.path.exists(p):
        return {"ok": True, "lines": 0, "first_break_line": None,
                "reason": "no audit log present"}
    key = _audit_chain_secret()
    prev = b""
    lines = 0
    legacy_skipped = 0
    # A chain digest is 64 lowercase-hex chars. Anything else in the last
    # tab-delimited column means this line predates the HMAC-chain rollout
    # (legacy 5-column format) — skip it rather than false-flag tampering.
    import re as _re
    HEX64 = _re.compile(rb"^[0-9a-f]{64}$")
    with open(p, "rb") as fh:
        for raw in fh:
            lines += 1
            stripped = raw.rstrip(b"\n")
            if not stripped:
                continue
            try:
                body_bytes, recorded = stripped.rsplit(b"\t", 1)
            except ValueError:
                return {"ok": False, "lines": lines, "first_break_line": lines,
                        "reason": "line has no tab separator"}
            # Legacy (pre-chain) lines: last col isn't a 64-hex digest.
            if not HEX64.match(recorded):
                legacy_skipped += 1
                continue
            if key:
                expected = hmac.new(key, prev + body_bytes, hashlib.sha256).hexdigest()
            else:
                expected = hashlib.sha256(prev + body_bytes).hexdigest()
            try:
                ok = hmac.compare_digest(expected, recorded.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                ok = False
            if not ok:
                return {"ok": False, "lines": lines, "first_break_line": lines,
                        "reason": "chain digest mismatch",
                        "legacy_skipped": legacy_skipped}
            prev = recorded
    reason = "chain intact"
    if legacy_skipped:
        reason += f" ({legacy_skipped} pre-chain legacy lines skipped)"
    return {"ok": True, "lines": lines, "first_break_line": None,
            "reason": reason, "legacy_skipped": legacy_skipped}


# ── Code-integrity hash (startup self-check) ───────────────────────────────

def _module_dir() -> Path:
    return Path(__file__).parent


def compute_code_integrity() -> dict[str, str]:
    """SHA-256 hash of every .py file in the mcp_terra/ package.

    Surfaces tampering: if an attacker modified the MCP source on disk
    to disable safety checks, the user can compare these hashes against
    a known-good manifest.
    """
    pkg_dir = _module_dir()
    out: dict[str, str] = {}
    for p in sorted(pkg_dir.glob("*.py")):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        out[p.name] = h
    return out


# ── Runtime hardening (Docker-style properties enforced at the process layer) ──
#
# Even when not running in a container, apply best-effort defense-in-depth:
#   • refuse to run as root (uid 0)
#   • bound RLIMIT_NPROC (no fork-bomb)
#   • bound RLIMIT_AS (no memory-bomb beyond ~2 GB)
#   • bound RLIMIT_FSIZE (no single file > 1 GB)
#   • bound RLIMIT_CORE (no core dumps; would leak the OAuth token)
# These are advisory in the sense that an attacker WITH SHELL ACCESS can
# override; but they constrain prompt-injection-driven misbehavior of the
# MCP process itself.

def harden_process_runtime() -> None:
    """Apply Docker-style runtime hardening to the MCP process.

    Refuses to run as root (UID 0) — opens too many destructive primitives.
    Sets resource limits via the standard library `resource` module.
    Effective on POSIX systems; on Windows the resource module is unavailable
    and the function no-ops with a warning.
    """
    import sys
    # Refuse to run as root
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = -1     # non-POSIX; can't check
    if euid == 0:
        raise PolicyError(
            "mcp-terra refuses to run as root (UID 0). Root inside the MCP "
            "process means an attacker who hijacks the agent has root-level "
            "destructive power. Re-run as a non-root user. (Inside Docker, "
            "use `--user=10001:10001` or USER directive — the provided "
            "Dockerfile does this by default.)"
        )

    # Resource limits — soft caps that defeat most runaway behaviour.
    try:
        import resource as _resource
    except ImportError:
        print("[mcp-terra harden] `resource` module unavailable; skipping rlimits.",
              file=sys.stderr)
        return

    # Disable core dumps — would persist the OAuth token to disk on crash.
    try:
        _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        pass

    # Cap virtual memory at 2 GB. This is wider than the MCP needs, narrower
    # than the rampage-via-list-bucket DoS would want.
    try:
        soft = _resource.RLIMIT_AS
        cur_soft, cur_hard = _resource.getrlimit(soft)
        target_hard = cur_hard if cur_hard != _resource.RLIM_INFINITY else 2 * 1024**3
        target_soft = min(target_hard, 2 * 1024**3)
        _resource.setrlimit(soft, (target_soft, target_hard))
    except (OSError, ValueError):
        pass

    # Cap a single file at 1 GB. Prevents an upload-script bug from writing
    # an unbounded local file.
    try:
        cur_soft, cur_hard = _resource.getrlimit(_resource.RLIMIT_FSIZE)
        target_hard = cur_hard if cur_hard != _resource.RLIM_INFINITY else 1 * 1024**3
        target_soft = min(target_hard, 1 * 1024**3)
        _resource.setrlimit(_resource.RLIMIT_FSIZE, (target_soft, target_hard))
    except (OSError, ValueError):
        pass

    # Cap number of subprocesses to bound fork-bomb behaviour.
    #
    # CAVEAT: RLIMIT_NPROC is counted PER-USER on macOS/Linux, not per-process.
    # That means capping at "256" denies fork as soon as the USER's TOTAL
    # process count (Chrome + IDEs + Terminal tabs + this MCP) exceeds 256 —
    # which is almost always true on a working dev machine. The MCP's
    # subprocess calls (gcloud, gsutil) then fail with EAGAIN at startup.
    #
    # Default raised to 2000 (well above a typical 400-process workstation,
    # comfortably below the macOS default soft limit of 2666). Env-tunable
    # via MCP_TERRA_RLIMIT_NPROC for power users on busy machines.
    try:
        target = int(os.environ.get("MCP_TERRA_RLIMIT_NPROC", "2000"))
        if target < 32:   # sanity floor; below this nothing can fork
            target = 32
        cur_soft, cur_hard = _resource.getrlimit(_resource.RLIMIT_NPROC)
        # Never RAISE the hard limit (privileged op); only lower if needed.
        target_hard = cur_hard if cur_hard != _resource.RLIM_INFINITY else target
        target_hard = min(target_hard, target) if target_hard < target else target_hard
        target_soft = min(target_hard, target)
        _resource.setrlimit(_resource.RLIMIT_NPROC, (target_soft, target_hard))
    except (OSError, ValueError):
        pass

    print("[mcp-terra harden] runtime hardening applied (no root, rlimits set, "
          "core dumps disabled).", file=sys.stderr)


def print_startup_banner() -> None:
    """Log the policy state + code-integrity hashes once at startup.

    Robustness: if the workspace-lock resolution fails (e.g. gcloud not on
    PATH, ADC expired, Rawls unreachable), we log a WARNING and continue
    rather than crashing the MCP at startup. The lock IS still enforced —
    every tool that touches a workspace bucket re-runs assert_workspace_allowed
    on each call, so an unresolved-at-startup lock will fail-closed the
    first time a write is attempted. This makes the server bootstrap
    resilient on macOS where GUI-launched Claude Code may not pass the
    user's shell PATH to the MCP subprocess.
    """
    _ensure_audit_dir()
    writes = "ON" if writes_allowed() else "OFF (read-only mode; set MCP_TERRA_ALLOW_WRITES=1 to enable)"
    try:
        allow = load_workspace_allowlist()
        allow_msg = f"{len(allow)} workspaces" if allow else "none (using full Terra ACL)"
    except Exception as e:  # noqa: BLE001 — startup-banner is best-effort
        allow = None
        allow_msg = f"UNRESOLVED ({type(e).__name__}: {str(e)[:120]})"
    # Surface workspace lock — but degrade to WARNING if auth/Rawls can't
    # be reached at startup. The lock check is re-attempted per tool call.
    try:
        lock = resolve_locked_workspace()
        if lock is None:
            lock_msg = ("OPEN MODE — any workspace this user can see "
                        "(set MCP_TERRA_WORKSPACE=ns/name to lock)")
        else:
            lock_msg = (f"LOCKED to {lock['namespace']}/{lock['name']}  "
                        f"(bucket={lock['bucketName']}, project={lock['googleProject']})")
    except Exception as e:  # noqa: BLE001
        lock = None
        lock_msg = (f"WARNING — lock resolution failed at startup "
                    f"({type(e).__name__}: {str(e)[:200]}). Re-attempted "
                    f"per-call; first write to a workspace bucket will "
                    f"fail-closed if still unresolved.")
    ca_msg = (f"ON — raw-data egress to the LLM blocked for non-public buckets "
              f"(GDS/DUC); {len(_DATA_EGRESS_ALLOW)} bucket(s) allowlisted"
              if _CONTROLLED_ACCESS else
              "OFF — no data-egress restriction (lab/public analysis unhindered)")
    print(f"[mcp-terra policy] writes:                {writes}", file=sys.stderr)
    print(f"[mcp-terra policy] controlled-access:    {ca_msg}", file=sys.stderr)
    print(f"[mcp-terra policy] workspace allowlist:  {allow_msg}", file=sys.stderr)
    print(f"[mcp-terra policy] workspace lock:       {lock_msg}", file=sys.stderr)
    print(f"[mcp-terra policy] rate limit:           {_RATE_LIMIT}/min, {_RATE_LIMIT_HOUR}/hr (call frequency, not job duration)", file=sys.stderr)
    print(f"[mcp-terra policy] audit log:            {AUDIT_LOG}", file=sys.stderr)
    print("[mcp-terra policy] code integrity SHA-256 (record these to detect tampering):",
          file=sys.stderr)
    for name, h in compute_code_integrity().items():
        print(f"  {h}  {name}", file=sys.stderr)
    audit_log("__startup__", "INIT",
              f"writes={writes_allowed()} rate_limit={_RATE_LIMIT}/min "
              f"allowlist={'custom' if allow else 'terra-acl'} "
              f"lock={'locked' if lock else 'open'}")
