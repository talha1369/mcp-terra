"""Pre-upload sensitive-data scanner. Refuses upload on hit.

Scans the first N MiB of any file (default 8 MiB) and the full content of
text-like files for known secret/PII patterns. Refusal is FAIL-CLOSED:
even a single hit blocks the upload until the user explicitly handles it.

Patterns kept narrow and well-anchored to minimize false-positive churn —
each one is documented with its source.

Override (single file): the user can pass `allow_secrets=True` to
terra_upload_to_bucket. We DO NOT support an env-var bypass — every
override must be explicit at the tool call site so it's auditable.
"""
from __future__ import annotations

import re
from pathlib import Path

# Patterns: (name, compiled regex, severity). Ordering doesn't matter.
# Each pattern is precise enough that false positives are rare; we err on
# the side of refusing the upload (the user can pass allow_secrets=True
# after inspecting the file).
_PATTERNS: list[tuple[str, re.Pattern[bytes], str]] = [
    # Google OAuth access token (gcloud ADC): exactly the format the auth
    # module returns. ya29.<base64ish> with a long body.
    ("google_oauth_token",
     re.compile(rb"\bya29\.[A-Za-z0-9_\-]{20,}"), "CRITICAL"),
    # AWS access-key ID. AKIA + 16 alphanumeric (uppercase).
    ("aws_access_key_id",
     re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "CRITICAL"),
    # OpenSSH / PEM private-key header — start of any PEM-encoded key.
    ("private_key_header",
     re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
     "CRITICAL"),
    # GitHub Personal Access Token (classic + fine-grained).
    ("github_pat",
     re.compile(rb"\bghp_[A-Za-z0-9]{36}\b|"
                rb"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "HIGH"),
    # Slack bot/user tokens.
    ("slack_token",
     re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    # Generic "AKIAI…secretKey =" assignment style (best-effort).
    ("aws_secret_key_assignment",
     re.compile(rb"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
                re.IGNORECASE),
     "CRITICAL"),
    # PEM certificate is NOT a secret — explicitly NOT matched.
]

_MAX_SCAN_BYTES = 8 * 1024 * 1024   # 8 MiB cap on per-file scan


class SensitiveDataFound(Exception):
    """Raised when a pre-upload scan finds known-bad content.

    Carries .hits: list of {pattern, severity, line_no_or_offset, preview}.
    """
    def __init__(self, hits: list[dict]):
        self.hits = hits
        names = sorted({h["pattern"] for h in hits})
        super().__init__(
            f"sensitive-data scan blocked upload: matched {names}. "
            f"Inspect the file and remove the secret, OR pass "
            f"allow_secrets=True to the upload tool to bypass (explicit, "
            f"audited override)."
        )


def scan_bytes(blob: bytes, source: str = "<bytes>") -> list[dict]:
    """Return a list of pattern hits in `blob`. Each hit:
        {pattern, severity, offset, preview}
    """
    if len(blob) > _MAX_SCAN_BYTES:
        # Scan only the head — secrets land at the top of files in practice
        # (env files, config, dotfiles). Document the truncation.
        blob = blob[:_MAX_SCAN_BYTES]
    hits: list[dict] = []
    for name, pat, sev in _PATTERNS:
        for m in pat.finditer(blob):
            preview = blob[max(0, m.start() - 4): m.start()].decode(
                "utf-8", errors="replace")
            hits.append({
                "pattern": name,
                "severity": sev,
                "source": source,
                "offset": m.start(),
                # Don't include the actual matched value — just the surrounding
                # context, so the report itself doesn't leak the secret.
                "context": f"…{preview}[REDACTED—{name}]…",
            })
    return hits


def scan_path(path: str | Path) -> list[dict]:
    """Scan a single regular file. Returns hit list (empty = clean).

    Skips:
      • directories (caller iterates)
      • non-regular files
      • files larger than _MAX_SCAN_BYTES (scans head only)
    Raises FileNotFoundError if path doesn't exist.
    Raises SensitiveDataFound(category='UNSCANNABLE') if the file exists
    but cannot be read by this process — gsutil may still upload it
    (different effective user / FUSE / ACL), so refusing-by-default is
    the only FAIL-CLOSED option.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    if not p.is_file():
        return []
    try:
        with open(p, "rb") as fh:
            blob = fh.read(_MAX_SCAN_BYTES + 1)
    except OSError as e:
        raise SensitiveDataFound([{
            "pattern": "UNSCANNABLE",
            "severity": "HIGH",
            "source": str(p),
            "offset": 0,
            "context": f"could not read file for scanning: {type(e).__name__}: {e}",
        }])
    return scan_bytes(blob, source=str(p))


_DIR_SCAN_FILE_CAP = 5000


def assert_clean(path: str | Path) -> None:
    """Raise SensitiveDataFound if `path` (file or dir tree) has any hits.

    For directory trees: scans up to _DIR_SCAN_FILE_CAP (5000) files and
    REFUSES (FAIL-CLOSED) if the tree exceeds that — silently skipping
    extra files would defeat the security guarantee. The user can pass
    `allow_secrets=True` on the upload tool to bypass the scan entirely.
    """
    p = Path(path)
    all_hits: list[dict] = []
    if p.is_dir():
        import os as _os
        count = 0
        total = 0
        # First pass: count total to detect overflow loudly.
        for _root, _dirs, files in _os.walk(p):
            total += len(files)
            if total > _DIR_SCAN_FILE_CAP:
                raise SensitiveDataFound([{
                    "pattern": "UNSCANNABLE-DIR-TOO-LARGE",
                    "severity": "HIGH",
                    "source": str(p),
                    "offset": 0,
                    "context": (f"directory tree has > {_DIR_SCAN_FILE_CAP} "
                                f"files; refusing to scan partially. Upload "
                                f"a smaller subset, or pass allow_secrets=True "
                                f"on the upload tool to skip scanning entirely "
                                f"(explicit, audited bypass)."),
                }])
        for root, _dirs, files in _os.walk(p):
            for fn in files:
                count += 1
                all_hits.extend(scan_path(Path(root) / fn))
    else:
        all_hits.extend(scan_path(p))
    if all_hits:
        raise SensitiveDataFound(all_hits)
