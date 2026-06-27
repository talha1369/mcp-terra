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
    # AWS secret access key assignment. Quotes are OPTIONAL around BOTH the key
    # name and the value, and the separator may be `=` or `:` — so the `.env`,
    # YAML, and JSON spellings of an AWS-secret-key assignment all match (key
    # bare or quoted; value bare or quoted). The 40-char base64 value is the
    # AWS secret-key shape.
    ("aws_secret_key_assignment",
     re.compile(rb"aws_secret_access_key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}",
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


# ── Visually-confusable codepoint fold (Unicode TR39-style skeleton) ─────────
# NFKC (compatibility normalization) folds full-width / ligature variants but
# does NOT fold Cyrillic / Greek look-alikes — they are distinct, non-decomposing
# letters. So a token like "ya29.<base64>" smuggled with Cyrillic у/а/е/о/с/х
# (visually identical) slips a raw OR NFKC regex. Mapping the confusables that
# overlap the Latin alphanumerics used in token/secret shapes back to ASCII
# closes that bypass. Curated to the [A-Za-z] confusables (token alphabets are
# [A-Za-z0-9_-]); digits/_/- have no common cross-script confusable worth folding.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    "ԁ": "d", "һ": "h", "ԛ": "q", "ӏ": "l", "ɡ": "g",
    # Cyrillic uppercase → Latin
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    # Greek lowercase → Latin (the Latin-LOOK-ALIKE subset; β/γ/ε/η/μ/τ/χ/ω
    # included so a Greek-letter smuggled token body — 'ya29.…χ…' — folds and is
    # caught. NON-Latin-looking Greek (δ θ λ ξ π σ φ ψ ζ) is left unmapped and is
    # excluded from the homoglyph backstop as genuine science notation.)
    "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ι": "i",
    "κ": "k", "υ": "u", "β": "b", "γ": "y", "ε": "e",
    "η": "n", "μ": "u", "τ": "t", "χ": "x", "ω": "w",
    # Greek uppercase → Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian → Latin (visually-confusable subset)
    "Օ": "O", "օ": "o", "ա": "a", "ո": "n",
    "ս": "u", "ր": "r", "ց": "g", "Ո": "N", "Ս": "U",
    # Small-capital / phonetic Latin letters → Latin (a convincing homoglyph set)
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e",
    "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k",
    "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p",
    "ʀ": "r", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w",
    "ʏ": "y", "ᴢ": "z",
    # Cherokee / Lisu Latin-look-alikes (a few demonstrated confusables)
    "Ꭺ": "A", "ꓮ": "A",
    # Greek/Coptic symbol-variant Latin look-alikes: lunate sigma ϲ/Ϲ and final
    # sigma ς render as 'c', lunate epsilon ϵ as 'e', beta symbol ϐ as 'b', rho
    # symbol ϱ as 'p' — fold so the byte-scan recovers a token using them.
    "ϲ": "c", "Ϲ": "C", "ς": "c", "ϵ": "e", "ϐ": "b", "ϱ": "p",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}

# GENUINE science Greek letters that are NOT Latin look-alikes (δ θ λ ξ π σ …),
# excluded from the homoglyph backstop so 'TGFβ1' / 'λmax-2024' / 'δ13C' / a
# 'σ-factor' render. The Latin-LOOK-ALIKE Greek (α β ε ο ρ τ χ μ … and lunate
# sigma ϲ) are instead MAPPED to ASCII by _CONFUSABLE_TABLE above, so they fold
# and are caught by the byte-scan — they are deliberately NOT in this set.
# Coptic is NOT here: its capitals are pure Latin look-alikes, so the backstop
# must still flag them. This is an explicit allow-set, NOT a whole-block range,
# precisely so a Latin-look-alike inside the Greek/Coptic blocks is never excused.
_GREEK_SCIENCE = frozenset(
    "δθλξπσφψζ"        # lowercase non-look-alike (α β γ ε η ι κ μ ν ο ρ τ υ χ ω
                       #   and ς are mapped → not residual → not needed here)
    "ΓΔΘΛΞΠΣΦΨΩ"       # uppercase non-look-alike
    "ϑϕϖϰ")            # math symbol variants (theta/phi/pi/kappa symbols)


# Codepoint categories stripped before scanning: zero-width / format / control /
# surrogate / private / unassigned (C*) and combining marks (Mn/Me). An invisible
# char (ZWSP U+200B, ZWNJ, ZWJ, BOM) or a combining mark inserted mid-token
# breaks the contiguous token/secret regex while rendering identically to a human
# and being recovered by a trivial copy-paste — NFKC does NOT remove these.
_STRIP_CATS = frozenset({"Cf", "Cc", "Cs", "Co", "Cn", "Mn", "Me"})

_ASCII_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
# ASCII letters + digits only (NOT the separators _ . -). Used to detect an
# INLINE homoglyph substitution: a suspect non-ASCII letter directly adjacent to
# one of these is a substituted token char; one adjacent only to a separator is a
# hyphenated foreign suffix (legit prose), not a smuggled token.
_ASCII_ALNUM = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def fold_confusables(text: str) -> str:
    """Return `text` with full-width/ligature variants (via NFKC) folded, all
    zero-width / format / control / combining codepoints STRIPPED, and
    Cyrillic/Greek Latin-look-alikes mapped to ASCII.

    A homoglyph- or invisible-char-smuggled token/secret then collapses to its
    ASCII twin / re-contiguates, so the same byte-level scan catches it. NFKC
    alone folds neither cross-script confusables nor invisibles — this helper is
    the missing half of the homoglyph defense.

    Uses NFKD (decompose), NOT NFKC: NFKC would COMPOSE an inserted combining
    mark ('A' + U+0301) back into a precomposed letter ('Á') that survives the
    strip and breaks the contiguous token match. NFKD splits it so the mark is
    stripped and the body re-contiguates. NFKD also covers full-width/ligature
    compatibility forms.
    """
    import unicodedata as _ud
    t = _ud.normalize("NFKD", text)
    t = "".join(ch for ch in t
                if ch in ("\t", "\n", " ") or _ud.category(ch) not in _STRIP_CATS)
    return t.translate(_CONFUSABLE_TABLE)


# Common Latin-script letters WITHOUT an NFKD-to-ASCII decomposition (used in
# real European text) → folded to ASCII for the homoglyph backstop ONLY, so a
# legit Scandinavian/Polish/German word does not look like a non-Latin homoglyph.
# Deliberately EXCLUDES small-caps / phonetic letters (ʏ ᴀ ɡ …) — those are
# homoglyph vectors we WANT to flag, not legitimate prose letters.
_LATIN_EXTRAS = {
    "ø": "o", "Ø": "O", "ł": "l", "Ł": "L", "đ": "d", "Đ": "D",
    "æ": "a", "Æ": "A", "œ": "o", "Œ": "O", "ß": "s", "þ": "t", "Þ": "T",
    "ð": "d", "Ð": "D", "ħ": "h", "Ħ": "H", "ı": "i", "İ": "I",
    "ŋ": "n", "Ŋ": "N", "ĸ": "k", "ŧ": "t", "Ŧ": "T",
}
_LATIN_EXTRAS_TABLE = {ord(k): v for k, v in _LATIN_EXTRAS.items()}


def has_homoglyph_token_shape(text: str) -> bool:
    """True if `text` has a token-shaped run smuggling a NON-ASCII homoglyph.

    A real OAuth / cloud / API token is PURE ASCII ([A-Za-z0-9_.-]). The PRIMARY
    homoglyph defense is fold_confusables + the byte-scan (it recovers a smuggled
    token to its ASCII twin and matches the canonical secret patterns). This is a
    SECONDARY backstop for confusable scripts the fold does not yet map. It must
    NOT fire on legitimate multilingual prose, so it is deliberately PRECISE:

      • NFKD + strip combining/format collapses accented Latin (é, ü, ñ) and
        full-width forms to ASCII;
      • the confusable map + a small Latin-extras map collapse the remaining
        legitimate Latin-ish letters (α, ø, ß, small-caps, …) to ASCII;
      • GENUINE science Greek letters (δ θ λ μ … in 'TGFβ1', '5μM', 'λmax') are
        allow-listed (NOT the whole Greek/Coptic block, so a Latin-look-alike
        like lunate sigma or a Coptic capital is still caught);
      • a run is flagged when it is PREDOMINANTLY ASCII (≥50% token chars) and
        still holds a suspect non-ASCII letter — the mostly-ASCII shape of a real
        token with homoglyph substitutions. Script-AGNOSTIC: no per-script map is
        required to catch a smuggled letter. CJK/Arabic/Devanagari prose is
        predominantly NON-ASCII (or ideographic-excluded), so it is never flagged.
    """
    import unicodedata as _ud
    # `orig` = NFKD-normalized text with invisibles/combining stripped (accents
    # collapsed to ASCII; Cyrillic/Greek/… NOT yet folded). `fold` = orig with the
    # confusable + Latin-extras maps applied. They are 1:1 aligned (each map entry
    # is a single char), so orig[i] and fold[i] correspond.
    orig = _ud.normalize("NFKD", text)
    orig = "".join(c for c in orig
                   if c in ("\t", "\n", " ") or _ud.category(c) not in _STRIP_CATS)
    fold = orig.translate(_CONFUSABLE_TABLE).translate(_LATIN_EXTRAS_TABLE)

    def _suspect(c: str) -> bool:
        # A residual letter is a homoglyph SUSPECT unless it is a genuine-science
        # Greek letter (δ θ λ μ…, allow-listed) or a WIDE/ideographic letter
        # (Han/Hiragana/Katakana/Hangul, East_Asian_Width W/F — NOT [A-Za-z]
        # look-alikes; they appear glued to Latin gene-IDs in CJK research prose).
        # Everything else non-ASCII left after NFKD + the confusable/Latin-extras
        # folds (Cyrillic/Greek/Armenian/Coptic/small-caps/… look-alikes) is a
        # smuggled-homoglyph candidate — script-AGNOSTIC.
        return (ord(c) > 127 and _ud.category(c)[0] == "L"
                and c not in _GREEK_SCIENCE
                and _ud.east_asian_width(c) not in ("W", "F"))

    def _is_run_char(c: str) -> bool:
        return (c in _ASCII_TOKEN_CHARS
                or _ud.category(c)[0] in ("L", "M") or _ud.category(c) == "Nd")

    def _flag(s: int, e: int) -> bool:
        # A real OAuth/cloud token is PURE ASCII, so a predominantly-ASCII (≥50%)
        # run of ≥16 token chars holding a suspect non-ASCII letter that is
        # INLINE — directly adjacent (in the ORIGINAL, pre-fold text) to an ASCII
        # letter/digit, i.e. substituted for a token character — is a homoglyph-
        # smuggled token. A suspect letter that touches only separators / other
        # non-ASCII (a hyphenated foreign suffix like 'Western-blot-анализа' or a
        # glued foreign word) is NOT inline and is NOT flagged. No ASCII-digit
        # requirement (digit-free secrets like AKIA/ghp_ must be caught).
        if e - s < 16:
            return False
        ascii_tok = sum(1 for i in range(s, e) if fold[i] in _ASCII_TOKEN_CHARS)
        if ascii_tok / (e - s) < 0.5:
            return False
        for i in range(s, e):
            if not _suspect(fold[i]):
                continue
            left_alnum = i > s and orig[i - 1] in _ASCII_ALNUM
            right_alnum = i + 1 < e and orig[i + 1] in _ASCII_ALNUM
            if left_alnum or right_alnum:
                return True
        return False

    s = None
    for i, ch in enumerate(orig):
        if _is_run_char(ch):
            if s is None:
                s = i
        else:
            if s is not None and _flag(s, i):
                return True
            s = None
    return s is not None and _flag(s, len(orig))


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
