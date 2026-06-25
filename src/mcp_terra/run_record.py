"""Run-record builder — the single, provenance-bearing record of a Terra run.

See docs/metadata.md for the full v1 schema and the standards it projects
(W3C PROV-O, RO-Crate-lite, Dublin Core / GA4GH). This module is PURE: it
validates an agent-supplied descriptive record and ENRICHES it with provenance
the agent must not be able to forge (MCP version + code-integrity digest, the
authenticated user, the locked workspace, the audit-chain head). The server
tool handles I/O (writing to the bucket).

Design rule: the agent describes *what happened* (iterations, fixes, results);
the MCP stamps *the trustworthy facts* (who/which-version/integrity). A buggy
or prompt-injected caller therefore cannot forge provenance.
"""
from __future__ import annotations

import hashlib

SCHEMA_VERSION = 1
RECORD_TYPE = "mcp_terra_run_record"
VALID_OUTCOMES = ("succeeded", "failed", "aborted")
VALID_SENSITIVITY = ("fc-secure", "restricted", "internal", "public")


class RunRecordError(ValueError):
    """Raised when an agent-supplied run record is malformed or under-specified."""


def code_integrity_digest(module_hashes: dict[str, str]) -> str:
    """Collapse the per-module sha256 set into one order-independent digest.

    Same inputs as terra_health's `code_integrity_sha256`, so the digest pins
    the exact MCP code that produced the run.
    """
    joined = "\n".join(f"{k}={module_hashes[k]}" for k in sorted(module_hashes))
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def build_record(record_in: dict, *, mcp_version: str,
                 module_hashes: dict[str, str], user_email: str = "",
                 workspace: dict | None = None,
                 audit_last_hmac: str | None = None) -> dict:
    """Validate + enrich an agent-supplied run record. Returns the enriched
    dict ready to serialize and write. Raises RunRecordError on a malformed or
    under-specified record.

    The agent supplies the descriptive body (run_id, title, subject, runtime,
    iterations, outputs, verification, deliveries, sensitivity). This function
    overwrites the provenance/identity fields so they cannot be forged.
    """
    if not isinstance(record_in, dict):
        raise RunRecordError("run record must be a JSON object")
    rec = dict(record_in)  # shallow copy; we never mutate the caller's dict

    # ── required descriptive fields (agent-supplied) ──
    run_id = rec.get("run_id")
    if not run_id or not isinstance(run_id, str):
        raise RunRecordError("run record requires a non-empty string 'run_id'")
    outcome = rec.get("outcome")
    if outcome not in VALID_OUTCOMES:
        raise RunRecordError(f"'outcome' must be one of {VALID_OUTCOMES}; got {outcome!r}")
    iterations = rec.get("iterations")
    if not isinstance(iterations, list) or not iterations:
        raise RunRecordError("run record requires a non-empty 'iterations' list")
    for i, it in enumerate(iterations):
        if not isinstance(it, dict) or not it.get("job_id"):
            raise RunRecordError(f"iteration[{i}] must be an object with a 'job_id'")

    # ── stamp schema/type (overwrite — not agent-forgeable) ──
    rec["_schema_version"] = SCHEMA_VERSION
    rec["record_type"] = RECORD_TYPE

    # ── provenance: agent identity + code integrity (authoritative) ──
    agent = dict(rec.get("agent") or {})
    agent["mcp_version"] = mcp_version
    agent["code_integrity_digest"] = code_integrity_digest(module_hashes)
    if user_email:
        agent["terra_user_email"] = user_email
    rec["agent"] = agent

    # ── workspace: from the lock, authoritative (overwrites any caller value) ──
    if workspace:
        rec["workspace"] = {
            "namespace": workspace.get("namespace"),
            "name": workspace.get("name"),
            "google_project": workspace.get("googleProject") or workspace.get("google_project"),
            "bucket": (f"gs://{workspace['bucketName']}"
                       if workspace.get("bucketName") else workspace.get("bucket")),
        }

    # ── derived summary ──
    rec["iteration_count"] = len(iterations)
    rec["bugs_fixed"] = sum(1 for it in iterations if it.get("fix"))

    # ── integrity ref: audit-chain head at write time ──
    air = dict(rec.get("audit_chain_ref") or {})
    if audit_last_hmac:
        air["last_line_hmac"] = audit_last_hmac
    rec["audit_chain_ref"] = air

    # ── sensitivity (default + validate) ──
    sens = rec.get("sensitivity", "fc-secure")
    if sens not in VALID_SENSITIVITY:
        raise RunRecordError(f"'sensitivity' must be one of {VALID_SENSITIVITY}; got {sens!r}")
    rec["sensitivity"] = sens

    return rec
