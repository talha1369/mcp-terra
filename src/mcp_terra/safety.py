"""Safety guards for mcp-terra. (HIGH-SECURITY profile)

Threat model: a prompt-injected agent could try to read/write things the
user did not intend, or exfiltrate workspace data. These guards make most
of that impossible at the tool layer.

Defense layers (all enforced in code, NOT just docstrings):

  1. **No overwrite, ever**:
     Writes (upload to bucket, download to local) refuse if the destination
     object already exists. With `version_existing=True`, the EXISTING
     object is renamed by appending an ISO-timestamp suffix BEFORE the new
     write happens — original data is preserved under the versioned name.
     A collision on the versioned name itself is also refused loudly.

  2. **No destruction primitive**:
     No tool deletes anything. There is no terra_delete_*, no gsutil rm
     wrapper. The MCP cannot lose data even if the agent tries to call it.

  3. **Local path blocklist**:
     Paths are resolved to absolute form (symlinks followed), then checked
     against a blocklist: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.azure,
     ~/.config/gcloud/application_default_credentials.json, ~/.netrc,
     ~/.git-credentials, ~/.config/gh/hosts.yml, and system paths /etc/,
     /private/etc/, /System/, /usr/bin/, /Library/Keychains/, etc.

  4. **Workspace-bucket allowlist**:
     Bucket I/O restricted to gs:// URIs whose bucket the auth'd user has
     workspace access to, refreshed every 60s from Rawls (tunable via
     MCP_TERRA_BUCKET_CACHE_TTL_SEC). Force-refresh via
     terra_refresh_workspace_allowlist after revoking a workspace ACL.

  5. **Identifier validation**:
     Workspace names, runtime names, google_project IDs are regex-validated
     so they cannot inject shell metacharacters, control chars, or
     path-traversal sequences into downstream gsutil / API calls.

  6. **Audit-log sanitization**:
     Audit lines escape control characters and cap arg length, defeating
     log-injection (newline-stuffing) attempts.

  7. **Bounded input sizes**:
     Path lengths, URI lengths, and identifier lengths are bounded to
     prevent pathologically long inputs.
"""
from __future__ import annotations

import datetime
import os
import re
import sys
import time
from pathlib import Path

from . import auth, terra_client as tc, bucket as bk


# ── Local path safety ───────────────────────────────────────────────────────

# Paths the MCP must NEVER read or write under, even if the user-supplied path
# resolves into one of them. Match by prefix on the resolved absolute path.
#
# Expanded 2026-06-25 audit pass to cover:
#   • System binaries / OS config (/etc/, /System/, /usr/bin/ etc.)
#   • Linux pseudo-filesystems (/proc/, /sys/, /dev/, /run/) — exfil + DoS surface
#   • macOS persistence launch dirs (/Library/LaunchDaemons, /Library/LaunchAgents)
#   • Cron + scheduled-task dirs (/etc/cron*, /var/spool/cron, /etc/anacrontab)
#   • The lab SMB share (/Volumes/broad_mcl/) — precious lab data; MCP should
#     never write there. (Reading the share is also blocked since it could
#     exfil precious data; the user can mount a different path if they need
#     selective read access.)
_LOCAL_BLOCKLIST_PREFIXES = (
    # OS / system binaries
    "/etc/",
    "/private/etc/",
    "/var/db/",
    "/var/root/",
    "/private/var/db/",
    "/private/var/root/",
    "/usr/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/bin/",
    "/System/",
    "/Library/Keychains/",
    "/private/Library/Keychains/",
    # macOS persistence launch dirs
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/Library/StartupItems/",
    # Linux pseudo-filesystems (exfil / DoS)
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    # Cron / scheduled persistence (both /var and macOS /private/var symlink target)
    "/var/spool/cron/",
    "/var/at/",
    "/private/var/spool/cron/",
    "/private/var/at/",
    # Per audit: lab SMB share. Add other shares as needed.
    "/Volumes/broad_mcl/",
)

# Inside the user's home, these names are forbidden (credentials + persistence
# mechanisms). Each name is matched after `os.path.expanduser(~)` joins it to
# the resolved home dir. Comparison is case-insensitive on darwin/win32 via
# _norm() so .ZSHRC and .zshrc both fail.
_HOME_BLOCKLIST_NAMES = (
    # Credentials / secrets
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".azure",
    ".git-credentials",
    ".netrc",
    ".pypirc",
    ".npmrc",
    ".docker/config.json",
    ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/credentials.db",
    ".config/gh/hosts.yml",
    ".terraformrc",
    # Shell startup files — RANSOMWARE/PERSISTENCE vector
    # An attacker who can write any of these gets code execution at next
    # interactive login. Block both standard and per-user variants.
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".config/fish/config.fish",
    ".config/fish/conf.d",
    # Editor / tool startup files (less common attack but pre-RCE on next open)
    ".vimrc",
    ".gvimrc",
    ".tmux.conf",
    ".inputrc",
    # macOS per-user launchd / cron (persistence)
    "Library/LaunchAgents",
    ".config/launchd",
    # Git: writing here lets an attacker rewrite git behaviour project-wide
    ".gitconfig",
    ".gitattributes",
)


class SafetyError(RuntimeError):
    """Raised when a tool input fails a safety check."""


# ── Bounded input sizes & identifier validation ─────────────────────────────

MAX_PATH_LEN = 1024     # well above any reasonable path; defeats pathologically long inputs
MAX_URI_LEN  = 1024
MAX_NAME_LEN = 128      # Leonardo runtime names cap at 63 anyway

# Identifier patterns — strict, no shell metachars, no path-traversal seeds.
#   workspace namespace / name / runtime name / google project id
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{0,126}$")
# Bucket gs:// URI — allow only alphanumerics, dashes, dots, slashes, underscores
_SAFE_GS_RE = re.compile(r"^gs://[a-z0-9][a-z0-9\-_.]{0,221}(/[A-Za-z0-9_./\-]*)?$")


def validate_identifier(value: str, what: str) -> str:
    """Validate a Terra identifier (namespace / name / project / runtime).

    Refuses control chars, shell metacharacters, path-traversal sequences,
    and over-long inputs.
    """
    if not isinstance(value, str):
        raise SafetyError(f"{what} must be a string; got {type(value).__name__}")
    if len(value) > MAX_NAME_LEN:
        raise SafetyError(f"{what} too long ({len(value)} chars; max {MAX_NAME_LEN}).")
    if not _SAFE_ID_RE.match(value):
        raise SafetyError(
            f"{what}={value!r} is not a valid identifier. "
            f"Allowed: alphanumeric, underscore, dash, dot. "
            f"First char must be alphanumeric."
        )
    if ".." in value:
        raise SafetyError(f"{what} contains '..' — refused.")
    return value


def _sanitize_for_log(s: str, max_len: int = 200) -> str:
    """Make a string safe to splat into an audit log line.

    Escapes control chars (so an attacker can't inject newlines / ANSI
    sequences into the audit log), then truncates.
    """
    if not isinstance(s, str):
        s = str(s)
    # Replace any C0 control char (incl. \n \r \t \x1b) with hex escape
    out = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7f:
            out.append(f"\\x{cp:02x}")
        else:
            out.append(ch)
    s2 = "".join(out)
    if len(s2) > max_len:
        s2 = s2[:max_len] + "…"
    return s2


def _audit(tool: str, action: str, detail: str) -> None:
    """Write a sanitized audit line to stderr.

    The line cannot be tampered with via newline-injection in the detail
    string — control chars are hex-escaped before printing.
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_tool = _sanitize_for_log(tool, 64)
    safe_action = _sanitize_for_log(action, 32)
    safe_detail = _sanitize_for_log(detail, 200)
    print(
        f"[mcp-terra audit {ts}] {safe_tool}: {safe_action} — {safe_detail}",
        file=sys.stderr, flush=True,
    )


def _norm(p: str) -> str:
    """Normalize a path string for case-insensitive comparison on platforms
    where the filesystem is case-insensitive (macOS APFS default, Windows).

    This is the FIX for the case-insensitive FS bypass: `/Users/X/.SSH/...`
    must hit the same blocklist entry as `/Users/X/.ssh/...` on macOS.

    On case-sensitive systems (Linux ext4) this is a no-op (lowercasing
    is harmless because we use it ONLY for comparison, not for I/O).
    """
    # We always normcase for the comparison; the real path I/O uses the
    # un-normcased path. macOS / Windows are case-insensitive; Linux isn't.
    # Lowercasing is the safe-default normalization for case-insensitive FS.
    if sys.platform in ("darwin", "win32"):
        return os.path.normcase(p).lower()
    return p


def _check_path_length(p: str, what: str) -> None:
    """Refuse pathologically long path inputs to defeat DoS / overflow."""
    if len(p) > MAX_PATH_LEN:
        raise SafetyError(
            f"{what} too long ({len(p)} chars; max {MAX_PATH_LEN}). "
            f"This MCP refuses unbounded path inputs."
        )


def safe_local_read_path(p: str) -> Path:
    """Validate a local path the MCP is about to READ from.

    Returns the resolved absolute Path. Raises SafetyError on:
      • empty or oversized path
      • path resolution failure (e.g. ELOOP from symlink chain)
      • path-traversal landing in a blocklisted system dir
      • path inside a credentials / config / shell-rc subdir
      • non-regular-file targets (block devices, /dev/zero, FIFOs, sockets)
    """
    import stat as _stat
    if not p:
        raise SafetyError("path is empty")
    _check_path_length(p, "local path")
    try:
        resolved = Path(p).expanduser().resolve()
    except OSError as e:
        raise SafetyError(
            f"path resolution failed for {p!r}: {type(e).__name__}: {e}. "
            f"This MCP refuses to operate on unresolvable paths "
            f"(typically a symlink loop or missing component)."
        )
    is_dir = False
    try:
        is_dir = resolved.is_dir()
    except OSError:
        pass
    s = str(resolved) + ("/" if is_dir else "")
    home = str(Path.home())
    s_norm = _norm(s)
    for prefix in _LOCAL_BLOCKLIST_PREFIXES:
        if s_norm.startswith(_norm(prefix)):
            raise SafetyError(
                f"path {s!r} is under blocked system prefix {prefix!r}. "
                f"This MCP refuses to touch system / OS paths, persistence "
                f"locations, or lab-data shares."
            )
    for name in _HOME_BLOCKLIST_NAMES:
        forbidden_str = str((Path(home) / name))
        forbidden_norm = _norm(forbidden_str)
        if s_norm == forbidden_norm or s_norm.startswith(forbidden_norm + "/"):
            raise SafetyError(
                f"path {s!r} is at or under blocked location {forbidden_str!r}. "
                f"This MCP refuses to read or write credentials, shell-rc "
                f"files, or other persistence vectors."
            )
    # Refuse non-regular files (block devices, FIFOs, sockets, char devices).
    # /dev/zero would stream gigabytes; /dev/random depletes entropy; a FIFO
    # could be a redirection target for a separate exfil pipeline.
    if resolved.exists() and not is_dir:
        try:
            mode = resolved.lstat().st_mode
        except OSError as e:
            raise SafetyError(
                f"could not stat {resolved!r}: {type(e).__name__}: {e}"
            )
        if not _stat.S_ISREG(mode):
            raise SafetyError(
                f"path {resolved!r} is not a regular file "
                f"(mode {oct(mode)}). The MCP refuses to read device files, "
                f"FIFOs, sockets, or other non-regular nodes."
            )
    return resolved


def safe_local_write_path(p: str) -> Path:
    """Validate a local path the MCP is about to WRITE to.

    Same as safe_local_read_path, plus:
      • destination must NOT already exist (no overwrites).
      • parent dir must exist (so we don't silently create a wrong tree).
    """
    if not p:
        raise SafetyError("path is empty")
    _check_path_length(p, "local path")
    target = Path(p).expanduser()
    target = (Path.cwd() / target if not target.is_absolute() else target).resolve(strict=False)
    parent = target.parent
    if not parent.exists():
        raise SafetyError(
            f"destination parent dir {parent!r} does not exist. "
            f"Create it explicitly outside the MCP first."
        )
    if target.exists():
        raise SafetyError(
            f"destination {target!r} already exists. The MCP refuses to overwrite. "
            f"Delete the existing path outside the MCP if you really want to overwrite."
        )
    s = str(target)
    s_norm = _norm(s)
    for prefix in _LOCAL_BLOCKLIST_PREFIXES:
        if s_norm.startswith(_norm(prefix)):
            raise SafetyError(
                f"destination {s!r} is under blocked system prefix {prefix!r}."
            )
    home = str(Path.home())
    for name in _HOME_BLOCKLIST_NAMES:
        forbidden_str = str((Path(home) / name))
        forbidden_norm = _norm(forbidden_str)
        if s_norm == forbidden_norm or s_norm.startswith(forbidden_norm + "/"):
            raise SafetyError(
                f"destination {s!r} is inside credentials dir {forbidden_str!r}."
            )
    return target


# ── Workspace-bucket allowlist ──────────────────────────────────────────────

import threading as _threading

_BUCKET_CACHE: dict = {"ts": 0.0, "set": set()}
_BUCKET_CACHE_TTL = float(os.environ.get("MCP_TERRA_BUCKET_CACHE_TTL_SEC", "60"))
_BUCKET_CACHE_LOCK = _threading.Lock()


def _refresh_workspace_buckets() -> set[str]:
    """Pull the user's workspace buckets from Rawls and cache. Thread-safe."""
    token = auth.get_access_token()
    ws_list = tc.rawls_list_workspaces(token)
    buckets = {
        w["workspace"]["bucketName"]
        for w in ws_list
        if w.get("workspace", {}).get("bucketName")
    }
    with _BUCKET_CACHE_LOCK:
        _BUCKET_CACHE["ts"] = time.time()
        _BUCKET_CACHE["set"] = buckets
        return set(buckets)   # return a copy so caller can't mutate cache


def _allowed_buckets() -> set[str]:
    """Return a snapshot of allowed bucket names. Refreshes under lock."""
    with _BUCKET_CACHE_LOCK:
        stale = time.time() - _BUCKET_CACHE["ts"] > _BUCKET_CACHE_TTL
        if not stale:
            return set(_BUCKET_CACHE["set"])   # snapshot copy
    # Refresh outside the lock (network call); ok if two threads race —
    # both will populate the cache with the same Rawls result.
    return _refresh_workspace_buckets()


def force_refresh_bucket_allowlist() -> set[str]:
    """Explicit invalidate-and-refresh. Use after revoking a workspace ACL.

    Returns the new set of allowed bucket names. Bypasses the TTL.
    """
    with _BUCKET_CACHE_LOCK:
        _BUCKET_CACHE["ts"] = 0.0   # mark stale
    return _refresh_workspace_buckets()


def safe_bucket_uri(gs_uri: str) -> str:
    """Validate a gs:// URI is one of the user's workspace buckets.

    Returns the input unchanged on success. Raises SafetyError on:
      • empty / oversized URI
      • bad scheme / malformed
      • bucket not in the user's Terra workspaces
      • bucket not the LOCKED workspace's bucket (if MCP_TERRA_WORKSPACE set)
    """
    if not gs_uri or not gs_uri.startswith("gs://"):
        raise SafetyError(f"bucket URI must start with gs://; got {gs_uri!r}")
    if len(gs_uri) > MAX_URI_LEN:
        raise SafetyError(
            f"bucket URI too long ({len(gs_uri)} chars; max {MAX_URI_LEN})."
        )
    # Reject control chars / newline injection (defense in depth)
    for ch in gs_uri:
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise SafetyError(
                f"bucket URI contains control character (codepoint {ord(ch)}). "
                f"Refused."
            )
    # Strict character allowlist — defends against whitespace, semicolons,
    # backticks, and any other shell-injection or path-traversal characters
    # that the basic checks above might miss. Note: _SAFE_GS_RE requires
    # lowercase bucket names (GCS bucket-naming rule).
    if not _SAFE_GS_RE.match(gs_uri):
        raise SafetyError(
            f"bucket URI {gs_uri!r} failed strict allowlist regex. "
            f"Allowed: lowercase bucket name + alphanumeric/underscore/dot/dash/slash "
            f"in the path. Refused."
        )
    # gs://BUCKET/path/... — extract BUCKET
    body = gs_uri[len("gs://"):]
    bucket = body.split("/", 1)[0]
    if not bucket:
        raise SafetyError(f"bucket URI has empty bucket name: {gs_uri!r}")
    # First gate: Terra-ACL allowlist (user must have access via Rawls)
    allowed = _allowed_buckets()
    if bucket not in allowed:
        raise SafetyError(
            f"bucket {bucket!r} is not one of your Terra workspace buckets. "
            f"The MCP refuses to access buckets outside your registered workspaces. "
            f"(Total allowed: {len(allowed)} buckets across your workspaces.)"
        )
    # Second gate: single-workspace lock (if MCP_TERRA_WORKSPACE is set)
    from . import policy   # avoid top-level circular import
    try:
        policy.assert_bucket_allowed(gs_uri)
    except policy.PolicyError as e:
        raise SafetyError(str(e))
    return gs_uri


def bucket_object_exists(gs_uri: str) -> bool:
    """Check whether a specific gs:// object already exists. Used to refuse overwrites."""
    if not gs_uri.endswith("/"):
        # gsutil stat on a single object; non-zero exit if missing
        try:
            bk.stat_object(gs_uri)
            return True
        except bk.BucketError:
            return False
    # for a "directory" URI, treat ls returning anything as exists
    try:
        listing = bk.list_bucket(gs_uri, recursive=False)
        return len(listing) > 0
    except bk.BucketError:
        return False


# ── Versioning (rename-instead-of-overwrite) ────────────────────────────────

def _iso_timestamp() -> str:
    """Filesystem-safe ISO 8601 timestamp suffix (UTC). E.g. '20260624T204500Z'."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def versioned_name(path: str, method: str = "timestamp") -> str:
    """Build a versioned filename so old data is preserved (never overwritten).

    Two methods supported:

      method="timestamp" (default):
        Insert an ISO-timestamp suffix before the final extension.
        'foo.py'              → 'foo.20260624T204500Z.py'
        'gs://b/dir/foo.py'   → 'gs://b/dir/foo.20260624T204500Z.py'
        'foo'                 → 'foo.20260624T204500Z'

      method="bak":
        Insert a '.BAK.<timestamp>' marker before the final extension.
        Use this for the common "I just fixed a bug, supersede the old one"
        pattern, where the new version takes the original name and the
        prior version becomes a .BAK.<timestamp>.
        'foo.py'              → 'foo.BAK.20260624T204500Z.py'
        'gs://b/dir/foo.py'   → 'gs://b/dir/foo.BAK.20260624T204500Z.py'
        'foo'                 → 'foo.BAK.20260624T204500Z'

    Both methods preserve uniqueness — every supersession event leaves a
    distinctly-named file. No data is ever overwritten or deleted.
    """
    if method not in ("timestamp", "bak"):
        raise SafetyError(f"versioned_name method must be 'timestamp' or 'bak'; "
                          f"got {method!r}")
    ts = _iso_timestamp()
    marker = ts if method == "timestamp" else f"BAK.{ts}"
    if "/" in path:
        head, tail = path.rsplit("/", 1)
        head += "/"
    else:
        head, tail = "", path
    if "." in tail:
        stem, ext = tail.rsplit(".", 1)
        return f"{head}{stem}.{marker}.{ext}"
    return f"{head}{tail}.{marker}"


def version_existing_local(target: Path, method: str = "timestamp") -> Path:
    """Rename an existing local file to a versioned name (no overwrite, no delete).

    Args:
        target: existing local file to version
        method: 'timestamp' (default) or 'bak' (see versioned_name())
    """
    if not target.exists():
        raise SafetyError(
            f"version_existing_local called on non-existent {target!r} — "
            f"internal logic error."
        )
    versioned = Path(versioned_name(str(target), method=method))
    if versioned.exists():
        raise SafetyError(
            f"versioned name {versioned!r} already exists — refusing to overwrite. "
            f"Move or rename it manually outside the MCP."
        )
    target.rename(versioned)
    _audit("version_existing_local", "WRITE-SAFE-RENAME",
           f"{target} → {versioned}  (method={method})")
    return versioned


# ── Prompt-injection defenses on tool OUTPUTS ──────────────────────────────
# Threat: a malicious value lurking in returned data (file names, workspace
# descriptions, etc.) could carry prompt-injection markers that re-poison
# the agent. We sanitize every outgoing string before it reaches the LLM.

# Injection markers we want stripped/escaped from tool outputs. These cover
# common chat-template / harness sentinels that attackers use to escape
# context. Each is replaced with a clearly-marked redaction.
_INJECTION_PATTERNS: tuple[str, ...] = (
    "<|im_start|>", "<|im_end|>",
    "<|system|>", "<|user|>", "<|assistant|>",
    "<|endoftext|>", "<|start_header_id|>", "<|end_header_id|>",
    "<|eot_id|>", "<|begin_of_text|>",
    "[INST]", "[/INST]",
    "<system>", "</system>",
    "<|tool_call|>",
    "###Instruction###", "###Instruction:",
    "===NEW INSTRUCTIONS===",
)

# Cap response length so a colossal listing can't drown the agent context.
MAX_OUTPUT_LEN = 200_000   # ~50K tokens of text — generous but bounded


def _redact_injection_markers(s: str) -> str:
    """Replace known prompt-injection markers with a visible redaction.

    Uses Unicode normalization (NFKC) on a SHADOW copy first so full-width
    /lookalike variants of the markers also match. We redact on the
    shadow's match positions but mutate the original — preserving the
    surrounding text untouched.
    """
    import unicodedata
    shadow = unicodedata.normalize("NFKC", s)
    # If NFKC didn't change anything, just do the direct replacement loop
    if shadow == s:
        for pat in _INJECTION_PATTERNS:
            if pat in s:
                s = s.replace(pat, f"[MCP-REDACTED:{len(pat)}b]")
        return s
    # Otherwise scan the shadow for patterns; redact corresponding spans in s.
    # Since NFKC may change lengths, we can't simply map indices 1:1.
    # Pragmatic fix: if ANY injection pattern is found in the NFKC form,
    # redact the entire output as containing a likely lookalike-attack.
    for pat in _INJECTION_PATTERNS:
        if pat in shadow:
            # Don't include `pat` in the redaction message — that would
            # echo the very pattern we're trying to redact. Just say SHA256
            # of the matched pattern so the operator can debug if needed.
            import hashlib
            tag = hashlib.sha256(pat.encode("utf-8")).hexdigest()[:12]
            return (f"[MCP-REDACTED-OUTPUT] A Unicode-normalized form of this "
                    f"tool's output contained a known prompt-injection sentinel "
                    f"(pattern-hash: {tag}). The entire output was suppressed "
                    f"to defeat lookalike-marker attacks.")
    return s


def sanitize_output(text: str) -> str:
    """Sanitize a tool's output before it reaches the calling LLM.

    Steps:
      1. Redact known prompt-injection markers (including Unicode lookalikes
         via NFKC normalization on a shadow copy).
      2. Strip ALL non-printable control chars: C0 (0x00–0x1F except \\n, \\t)
         AND C1 (0x80–0x9F). C1 includes ESC-like CSI bytes used in some
         terminal escape exploits.
      3. Strip DEL (0x7F).
      4. Cap to MAX_OUTPUT_LEN.

    NEVER returns secrets — tokens stay in the process. NEVER returns file
    *contents* — tools only return paths / metadata.
    """
    if not isinstance(text, str):
        text = str(text)
    text = _redact_injection_markers(text)
    out = []
    for ch in text:
        cp = ord(ch)
        # C0 controls (allow newline + tab only)
        if cp < 0x20 and ch not in ("\n", "\t"):
            continue
        # DEL
        if cp == 0x7f:
            continue
        # C1 controls (0x80–0x9F) — terminal-control bytes, never desirable
        # in tool output destined for an LLM.
        if 0x80 <= cp <= 0x9f:
            continue
        out.append(ch)
    text = "".join(out)
    if len(text) > MAX_OUTPUT_LEN:
        text = text[:MAX_OUTPUT_LEN] + f"\n…[MCP-TRUNCATED to {MAX_OUTPUT_LEN} chars]"
    return text


def assert_token_not_in(s: str, token: str) -> None:
    """Refuse to return a response that contains the auth token.

    Defense in depth: the API client never puts the token in response bodies,
    but if a Terra service ever echoed an Authorization header, this catches it.
    """
    if token and token in s:
        raise SafetyError(
            "INTERNAL: tool response contained the OAuth token. Refusing to "
            "return. This is a defense-in-depth check; if it ever fires, "
            "report a bug."
        )


# ── Free-form string argument scrubbing ────────────────────────────────────

# For args like docker_image, machine_type — allow only a narrow charset.
_SAFE_FREEFORM_RE = re.compile(r"^[A-Za-z0-9._/:\-]{0,256}$")


def validate_freeform_string(value: str, what: str, allow_empty: bool = True) -> str:
    """Validate a free-form string arg (docker image URL, machine type, etc.).

    Allows: alphanumeric, dot, underscore, slash, colon, dash, hyphen.
    Refuses: shell metachars, control chars, spaces, anything > 256 chars.
    """
    if value == "" and allow_empty:
        return value
    if not isinstance(value, str):
        raise SafetyError(f"{what} must be a string; got {type(value).__name__}")
    if not _SAFE_FREEFORM_RE.match(value):
        raise SafetyError(
            f"{what}={value!r} contains disallowed characters. Allowed: "
            f"alphanumeric, dot, underscore, slash, colon, dash. Max 256 chars."
        )
    return value


def version_existing_bucket(gs_uri: str, method: str = "timestamp") -> str:
    """Rename an existing bucket object to a versioned name (no overwrite, no delete).

    Args:
        gs_uri: existing bucket object
        method: 'timestamp' (default) or 'bak'
    """
    if not bucket_object_exists(gs_uri):
        raise SafetyError(
            f"version_existing_bucket called on non-existent {gs_uri!r} — "
            f"internal logic error."
        )
    versioned = versioned_name(gs_uri, method=method)
    if bucket_object_exists(versioned):
        raise SafetyError(
            f"versioned URI {versioned!r} already exists — refusing to overwrite. "
            f"Move or rename it manually outside the MCP."
        )
    # gsutil mv = server-side rename (atomic enough). Data preserved at versioned name.
    bk._run_gsutil(["mv", gs_uri, versioned], timeout=300.0)
    _audit("version_existing_bucket", "WRITE-SAFE-RENAME",
           f"{gs_uri} → {versioned}  (method={method})")
    return versioned
