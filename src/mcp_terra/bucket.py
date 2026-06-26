"""Workspace-bucket helpers — thin wrappers around `gsutil`.

We prefer gsutil over the Cloud Storage REST API because:
  1. It reuses the user's gcloud auth without extra plumbing.
  2. Resumable / parallel transfers (`-m`) are built in.
  3. Identical behavior to what Terra docs tell users to use locally.

All errors are surfaced (no try/except/pass). If gsutil exits non-zero, we
raise BucketError with the exact stderr so the caller can act on it.
"""
from __future__ import annotations

import os
import shutil
import subprocess


class BucketError(RuntimeError):
    """Raised when a gsutil command fails."""


_DEFAULT_GSUTIL_MAX_BYTES = 64 * 1024 * 1024   # 64 MiB safety cap on stdout

# Same fallback pattern as auth._find_gcloud — covers MCP launched from a GUI
# (Spotlight/Dock on macOS) where the user's shell PATH never reaches the
# subprocess. gsutil lives next to gcloud in every supported install layout.
_GSUTIL_FALLBACK_PATHS = (
    "/opt/homebrew/bin/gsutil",
    "/usr/local/bin/gsutil",
    "/usr/bin/gsutil",
    os.path.expanduser("~/google-cloud-sdk/bin/gsutil"),
    os.path.expanduser("~/Downloads/google-cloud-sdk/bin/gsutil"),
    os.path.expanduser("~/.local/google-cloud-sdk/bin/gsutil"),
    "/snap/bin/gsutil",
)


def _find_gsutil() -> str | None:
    p = shutil.which("gsutil")
    if p: return p
    for cand in _GSUTIL_FALLBACK_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _run_gsutil(args: list[str], *, timeout: float = 120.0,
                 max_bytes: int = _DEFAULT_GSUTIL_MAX_BYTES) -> str:
    """Run `gsutil <args>` and return stdout. Raise on non-zero exit.

    The stdout is capped at `max_bytes` (default 64 MiB) — a gsutil `cat`
    against a multi-GB object would otherwise buffer everything in memory.
    The cap protects the MCP from OOM if a caller targets a giant object.
    """
    gsutil = _find_gsutil()
    if gsutil is None:
        raise BucketError(
            "`gsutil` not found on PATH or in common install locations. "
            "Install the Google Cloud SDK (https://cloud.google.com/sdk). "
            "If installed, add its bin dir to the MCP server's PATH env in "
            "~/.claude/settings.json."
        )
    try:
        out = subprocess.run(
            [gsutil] + args,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise BucketError(f"gsutil timed out after {timeout}s: gsutil {' '.join(args[:3])}…")
    if out.returncode != 0:
        raise BucketError(
            f"gsutil exit {out.returncode}: {(out.stderr or '').strip()[:400]}"
        )
    if len(out.stdout) > max_bytes:
        raise BucketError(
            f"gsutil stdout exceeded {max_bytes} bytes cap (got "
            f"{len(out.stdout)}). Object likely too large for in-memory read; "
            f"download to a file via `gsutil cp` instead."
        )
    return out.stdout


def list_bucket(bucket_uri: str, recursive: bool = False) -> list[str]:
    """List paths under a gs:// URI. Returns a list of one path per line.

    bucket_uri may be a bucket root (`gs://bkt`) or a prefix (`gs://bkt/dir/`).
    """
    if not bucket_uri.startswith("gs://"):
        raise BucketError(f"bucket_uri must start with gs://; got {bucket_uri!r}")
    args = ["ls"]
    if recursive:
        args.append("-r")
    args.append(bucket_uri)
    out = _run_gsutil(args, timeout=60.0)
    return [ln for ln in out.splitlines() if ln.strip()]


def list_bucket_detailed(bucket_uri: str, recursive: bool = False,
                         max_items: int = 1000) -> dict:
    """Structured listing via `gsutil ls -l` — per object: name, size_bytes,
    updated (so the agent can find + size + verify outputs in ONE call instead
    of N follow-up stat calls). Returns {objects, count, truncated}.

    `gsutil ls -l` prints `<size>  <RFC3339 time>  gs://...` per object, a
    `TOTAL:` summary line, and bare `gs://.../` lines for sub-prefixes.
    """
    if not bucket_uri.startswith("gs://"):
        raise BucketError(f"bucket_uri must start with gs://; got {bucket_uri!r}")
    n = max(1, min(int(max_items), 10000))
    args = ["ls", "-l"]
    if recursive:
        args.append("-r")
    args.append(bucket_uri)
    out = _run_gsutil(args, timeout=120.0)
    objects: list[dict] = []
    truncated = False
    for ln in out.splitlines():
        s = ln.strip()
        if not s or s.startswith("TOTAL:"):
            continue
        if len(objects) >= n:
            truncated = True
            break
        parts = s.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            objects.append({"name": parts[2], "size_bytes": int(parts[0]),
                            "updated": parts[1]})
        elif s.startswith("gs://"):           # a sub-prefix (no size in ls -l)
            objects.append({"name": s, "size_bytes": None, "updated": None,
                            "is_prefix": True})
    return {"objects": objects, "count": len(objects), "truncated": truncated}


def upload_file(local_path: str, bucket_uri: str, *, recursive: bool = False) -> str:
    """Upload a local file (or dir with recursive=True) to a gs:// destination.

    SAFETY: always passes `gsutil cp -n` (no-clobber). This is the
    second-line defense against silent overwrites — the Python-side
    collision check is the first. If both layers fail, the gsutil
    operation itself returns an error rather than clobbering the
    destination.
    """
    if not bucket_uri.startswith("gs://"):
        raise BucketError(f"bucket_uri must start with gs://; got {bucket_uri!r}")
    # -n = never clobber an existing dest. NO -m: gsutil's `-m` (parallel)
    # deadlocks under Python's fork on macOS (where the MCP runs) and gives
    # no benefit for single-file uploads — it would hang every upload.
    args = ["cp", "-n"]
    if recursive:
        args.append("-r")
    args.extend([local_path, bucket_uri])
    return _run_gsutil(args, timeout=600.0)


def download_file(bucket_uri: str, local_path: str, *, recursive: bool = False) -> str:
    """Download a gs:// path to a local destination.

    SAFETY: always passes `gsutil cp -n` (no-clobber) for the same
    reason as upload_file.
    """
    if not bucket_uri.startswith("gs://"):
        raise BucketError(f"bucket_uri must start with gs://; got {bucket_uri!r}")
    # NO -m: gsutil's `-m` (parallel) deadlocks under fork on macOS (where the
    # MCP runs) and gives no benefit for single-file downloads. -n = no-clobber.
    args = ["cp", "-n"]
    if recursive:
        args.append("-r")
    args.extend([bucket_uri, local_path])
    return _run_gsutil(args, timeout=600.0)


def stat_object(bucket_uri: str) -> str:
    """Return `gsutil stat` output for one object (raises if missing)."""
    return _run_gsutil(["stat", bucket_uri], timeout=30.0)


def read_object(bucket_uri: str, *, max_bytes: int = 102400) -> dict:
    """Read only the FIRST `max_bytes` of an object via a byte-range fetch.

    Uses `gsutil cat -r 0-(max_bytes-1)`, which asks GCS for just that byte
    range — it never downloads the whole object, so this is safe against
    multi-GB targets (unlike `download_file`). `max_bytes` is clamped to a 10 MiB
    hard ceiling regardless of the caller's request.

    Returns {uri, text, bytes_returned, max_bytes, truncated}. `truncated` is
    True when the object is at least `max_bytes` long (i.e. there is more to
    read past this window).
    """
    if not bucket_uri.startswith("gs://"):
        raise BucketError(f"bucket_uri must start with gs://; got {bucket_uri!r}")
    n = max(1, min(int(max_bytes), 10 * 1024 * 1024))  # hard ceiling 10 MiB
    out = _run_gsutil(["cat", "-r", f"0-{n - 1}", bucket_uri],
                      timeout=120.0, max_bytes=n + 4096)
    nbytes = len(out.encode("utf-8", "replace"))
    return {
        "uri": bucket_uri,
        "text": out,
        "bytes_returned": nbytes,
        "max_bytes": n,
        # If we filled the window the object very likely has more bytes; report
        # it as truncated so the caller knows to widen the range or download.
        "truncated": nbytes >= n,
    }
