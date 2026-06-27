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
    # AWS secret access key assignment. The label words may be separated by spaces,
    # underscores, or hyphens ([\s_-]*), so the .env / YAML / JSON config spellings
    # ('aws_secret_access_key=…') AND the natural-English prose an LLM writes in a
    # run report ('AWS Secret Access Key: …', 'Secret access key = …') all match.
    # 'aws' and 'access' are optional. Quotes optional around the value; separator
    # ':' or '='. The 40-char base64 value is the AWS secret-key shape.
    ("aws_secret_key_assignment",
     re.compile(rb"(?:aws[\s_-]*)?secret[\s_-]*(?:access[\s_-]*)?key[\s_-]*"
                rb"[\"']?[\s_-]*[:=][\s_-]*[\"']?[A-Za-z0-9/+=]{40}",
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
# Coptic alphabet → Latin, built from codepoints (the glyphs are not eye-
# distinguishable, so a literal-glyph dict is error-prone). Coptic capitals
# render near-identically to Latin caps (Ro→P, Kapa→K, Me→M, …); folding lets
# the byte-scan recover a homoglyph token / PEM header even though PEM keyword
# words are too short for the ≥16-char run backstop. Each tuple is the CAPITAL
# codepoint (the lowercase is +1) and its ASCII look-alike.
_COPTIC_CONFUSABLES = {
    0x2C80: "A", 0x2C82: "B", 0x2C88: "E", 0x2C8C: "H", 0x2C92: "I",
    0x2C94: "K", 0x2C98: "M", 0x2C9A: "N", 0x2C9E: "O", 0x2CA2: "P",
    0x2CA4: "C", 0x2CA6: "T", 0x2CA8: "Y", 0x2CAC: "X",
}
# Extended-Latin / IPA confusables → ASCII, built from codepoints (the glyphs are
# not eye-distinguishable in source, so a literal-glyph dict is error-prone). These
# are Latin-SCRIPT letters that render like an ASCII letter — IPA alpha ɑ↔a, small-
# capital Q ꞯ↔Q, the African hook letters ɓ↔b ɗ↔d ƙ↔k ƴ↔y, the retroflex/turned
# IPA letters, and the small-capital series. FOLDING them (rather than name-
# exempting every 'LATIN …' letter, the R14 regression that let ɑ/ꞯ bypass) does
# double duty: the byte-scan recovers a secret that substituted one in, AND a
# legitimate Azerbaijani/Hausa/Fula word that uses them folds to ASCII so it is NOT
# a residual non-ASCII letter → no false refusal. Letters that do NOT resemble any
# ASCII char (glottals ʔʕ, clicks ʘǁǂ, esh ʃ, ezh ʒ) are deliberately omitted —
# folding them would be wrong, and they do not occur in token-shaped runs.
_EXTLATIN_CONFUSABLES = {
    0x0250: "a", 0x0251: "a", 0x0252: "a", 0x0253: "b", 0x0254: "o", 0x0255: "c",
    0x0256: "d", 0x0257: "d", 0x0258: "e", 0x0259: "e", 0x025B: "e", 0x025C: "e",
    0x025E: "e", 0x0260: "g", 0x0261: "g", 0x0262: "G", 0x0265: "h", 0x0266: "h",
    0x0267: "h", 0x0268: "i", 0x0269: "i", 0x026A: "i", 0x026B: "l", 0x026C: "l",
    0x026D: "l", 0x026F: "m", 0x0270: "m", 0x0271: "m", 0x0272: "n", 0x0273: "n",
    0x0274: "N", 0x0275: "o", 0x0277: "w", 0x0279: "r", 0x027A: "r", 0x027B: "r",
    0x027C: "r", 0x027D: "r", 0x027E: "r", 0x0280: "R", 0x0282: "s", 0x0288: "t",
    0x0289: "u", 0x028A: "u", 0x028B: "v", 0x028C: "v", 0x028D: "w", 0x028E: "y",
    0x0290: "z", 0x0291: "z", 0x0299: "B", 0x029B: "G", 0x029C: "H", 0x029D: "j",
    0x029F: "l",
    # Latin Extended-B hook / stroke letters used in African orthographies
    0x0192: "f", 0x0199: "k", 0x0198: "K", 0x01A5: "p", 0x01AB: "t", 0x01AD: "t",
    0x01B4: "y", 0x01B3: "Y", 0x0188: "c", 0x0263: "g", 0x0237: "j",
    0x0249: "j", 0x024D: "r", 0x024F: "y",
    # Latin small-capital letters in the Latin Extended-D block (ꞯ small-cap Q is
    # the R15 bypass char — it carries a 'LATIN …' name and was name-exempted)
    0xA7AF: "Q", 0xA7B0: "T", 0x1D04: "c", 0x1D07: "e", 0x1D0A: "j", 0x1D0B: "k",
    0x1D18: "p", 0x1D1B: "t", 0x1D20: "v", 0x1D21: "w", 0x1D22: "z",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}
for _cp, _lat in _COPTIC_CONFUSABLES.items():
    _CONFUSABLE_TABLE[_cp] = _lat            # capital
    _CONFUSABLE_TABLE[_cp + 1] = _lat.lower()  # lowercase (Coptic pairs are cap, cap+1)
for _cp, _lat in _EXTLATIN_CONFUSABLES.items():
    _CONFUSABLE_TABLE.setdefault(_cp, _lat)  # don't override a curated mapping

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

    def _foldch(ch: str) -> str:
        # Non-ASCII DECIMAL digits (Arabic-Indic ٢٩, Devanagari २९, Bengali ২৯, …)
        # render like ASCII digits but NFKD does NOT fold them and the confusable
        # table maps only letters — so a digit substituted into a numeric anchor
        # (e.g. 'ya29.' → 'ya٢٩.') would slip the byte-scan. Map every non-ASCII
        # Nd digit to its ASCII value so the anchored patterns fire.
        if ord(ch) > 127 and _ud.category(ch) == "Nd":
            _d = _ud.decimal(ch, None)
            if _d is not None:
                return str(_d)
        return ch

    t = _ud.normalize("NFKD", text)
    t = "".join(_foldch(ch) for ch in t
                if ch in ("\t", "\n", " ") or _ud.category(ch) not in _STRIP_CATS)
    return t.translate(_CONFUSABLE_TABLE)


# Common Latin-script letters WITHOUT an NFKD-to-ASCII decomposition (used in
# real European text) → folded to ASCII for the homoglyph backstop ONLY, so a
# legit Scandinavian/Polish/German word does not look like a non-Latin homoglyph.
# The ASCII-RESEMBLING small-caps / phonetic letters (ʏ ᴀ ɡ ɑ ꞯ …) are folded too,
# via _CONFUSABLE_TABLE / _EXTLATIN_CONFUSABLES — they are homoglyph vectors, so
# folding them lets the byte-scan recover the real token (stronger than the
# backstop merely refusing).
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
        # A residual (post-fold) letter is a homoglyph SUSPECT unless it is:
        #  • a genuine-science Greek letter (δ θ λ μ…, allow-listed); or
        #  • a WIDE/ideographic letter (Han/Hiragana/Katakana/Hangul, EAW W/F —
        #    not [A-Za-z] look-alikes; glued to Latin gene-IDs in CJK prose); or
        #  • a conjoining HANGUL JAMO. A precomposed Hangul syllable is EAW='W',
        #    but the NFKD this function runs first DECOMPOSES it into jamo whose
        #    medial/final pieces are EAW='N' — so the W/F test alone wrongly flags
        #    a Korean word glued into a Latin identifier. Jamo are distinct Korean
        #    shapes (no Latin look-alikes), so exempting their blocks is safe.
        # We do NOT name-exempt 'LATIN …' letters: that was the R15 bypass — IPA
        # alpha ɑ and small-capital Q ꞯ carry 'LATIN …' names yet render as a/Q.
        # Instead the ASCII-resembling extended-Latin/IPA letters are FOLDED to
        # ASCII (so fold[i] is ASCII and never reaches here), and legitimate
        # extended-Latin orthography (Azerbaijani ə, Hausa ɓ/ɗ/ɛ/ɔ/ƙ/ƴ, Norse
        # ø/ð/þ, dotless ı, ŋ) is likewise folded by _CONFUSABLE_TABLE /
        # _LATIN_EXTRAS → not residual → not flagged. So the only Latin letters
        # reaching here are UNFOLDED ones (a confusable we missed, or an exotic
        # non-prose phonetic letter); flagging them is the intended defense in
        # depth. Cross-script confusables (Cyrillic/Armenian/Coptic/…) likewise
        # remain suspects — the actual smuggling vector.
        _o = ord(c)
        if (0x1100 <= _o <= 0x11FF or 0x3130 <= _o <= 0x318F
                or 0xA960 <= _o <= 0xA97F or 0xD7B0 <= _o <= 0xD7FF):
            return False                      # conjoining Hangul jamo (NFKD of 가-힣)
        # Spaceless / space-optional SE-Asian scripts (Thai, Lao, Khmer, Myanmar)
        # are written without inter-word spaces, so a Latin gene/accession ID (e.g.
        # GCF_000001405.40) glues directly to a native word — but their letters are
        # EAW='N' (narrow) so the W/F test does not exempt them. They are distinct
        # native shapes with NO ASCII look-alikes (not a smuggling vector), exactly
        # like the CJK/jamo rationale, so exempt their blocks to avoid refusing a
        # legitimate non-English researcher's summary.
        if (0x0E00 <= _o <= 0x0E7F or 0x0E80 <= _o <= 0x0EFF      # Thai, Lao
                or 0x1000 <= _o <= 0x109F or 0x1780 <= _o <= 0x17FF):  # Myanmar, Khmer
            return False
        return (_o > 127 and _ud.category(c)[0] == "L"
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


# Boundary-relaxed variants of the anchored secret patterns — for scanning a
# WHITESPACE-COLLAPSED variant where a secret was split by an inserted space /
# newline (the \b word-boundaries would otherwise fail once neighbouring words
# glue onto the secret). The patterns stay distinctive (ya29. / AKIA / ghp_ /
# xox / PEM / aws_secret), so dropping the boundaries adds negligible FP risk.
_DENSE_PATTERNS = [
    (name,
     re.compile(pat.pattern.replace(rb"\b", b"").replace(b" ", b"").replace(rb"|ASIA", b""),
                pat.flags),
     sev)
    # \b boundaries removed AND literal spaces removed — the dense scan runs on a
    # WHITESPACE-COLLAPSED string, so a multi-word pattern (the PEM header, the
    # only one with required internal spaces) must drop its spaces too, else a
    # space-split PEM header would slip the dense pass. The AWS 'ASIA' alternative
    # is dropped here: without the \b boundary it would match an all-caps word like
    # 'ASIA PACIFIC REGION COHORT…' once whitespace is collapsed. 'AKIA' (not an
    # English word) is kept; contiguous ASIA keys are still caught by the raw scan.
    for name, pat, sev in _PATTERNS
]
# RELAXED split-detection patterns — each self-identifying prefix with its internal
# distinguisher dropped (ya29's '.', ghp's '_', slack's '-', the dashes/spaces of
# PEM). These are applied ONLY to re-contiguated candidates that are already known
# to be a SECRET-SHAPED structure — a single whitespace TOKEN stripped of its
# separators, or a "one separator between every character" run that has been
# collapsed — NEVER to globally-glued prose. In those contexts the relaxations are
# false-positive-safe (ordinary prose is neither a single long token nor a per-char
# separated run). 'AKIA'/'ASIA' both included (a collapsed 'A S I A …' run is a
# genuine split key, not the all-caps word 'ASIA' which is not per-char separated).
# PEM-header keywords (whole-word) for the fold-tolerant homoglyphed-PEM backstop.
_PEM_KEYWORDS = frozenset({"BEGIN", "PRIVATE", "PUBLIC", "KEY", "CERTIFICATE"})
# The hex/base64/base64url/base32 candidate alphabet — used to decide whether a
# decoded blob is itself plausibly ANOTHER encoded layer (recursive decode pass).
_ENC_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")  # pragma: allowlist secret
_SPLIT_PATTERNS = [
    ("aws_access_key_id", re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"), "CRITICAL"),
    ("google_oauth_token", re.compile(rb"ya29[A-Za-z0-9_-]{20,}"), "CRITICAL"),
    ("github_pat", re.compile(rb"ghp[A-Za-z0-9]{36}|githubpat[A-Za-z0-9]{82}"), "HIGH"),
    ("slack_token", re.compile(rb"xox[abprs][A-Za-z0-9]{10,}"), "HIGH"),
]


def scan_egress(text: str) -> list[dict]:
    """Scan agent-authored text bound for an OUTBOUND human channel (TTS audio /
    email) for ANY secret shape, defeating homoglyph, zero-width, whitespace-
    split, and encoding evasions. Returns a list of hits (empty = clean):

      • raw, NFKC-normalized, and confusable-folded (+ invisible/combining-
        stripped) forms scanned with the anchored patterns;
      • a WHITESPACE-COLLAPSED fold scanned with boundary-relaxed AND space-
        stripped patterns, so a secret split by an inserted space/newline (incl. a
        spaced PEM header) re-contiguates. A homoglyph-smuggled PEM header is
        already recovered by the confusable fold + the contiguous PEM pattern, so
        no separate (false-positive-prone) frame heuristic is needed.

    The homoglyph token backstop (has_homoglyph_token_shape) is complementary and
    called separately by the egress validators.
    """
    import unicodedata as _ud
    hits: list[dict] = []
    fold = fold_confusables(text)
    for variant in (text, _ud.normalize("NFKC", text), fold):
        if variant:
            hits += scan_bytes(variant.encode("utf-8", "replace"), "egress")
    dense = re.sub(r"\s+", "", fold)
    if dense:
        blob = dense.encode("utf-8", "replace")
        for name, pat, sev in _DENSE_PATTERNS:
            for m in pat.finditer(blob):
                hits.append({"pattern": name, "severity": sev,
                             "source": "egress-dense", "offset": m.start(),
                             "context": f"…[REDACTED—{name}]…"})
    # PUNCTUATION-split PLAINTEXT secret: a secret split by a non-whitespace
    # separator BETWEEN its characters ('AKIA.IOSF.ODNN…', 'g-h-p-_a…') is kept
    # intact by `dense` (which only collapses whitespace) but is still ONE
    # whitespace token, so we re-contiguate PER TOKEN. Per-token (not a global
    # strip) is essential to avoid false positives: a global strip glues
    # neighbouring prose words, letting a short word like 'ASIA'/'Maya29'/'github
    # pat' acquire a 16+ char body from its neighbours and match. A real secret
    # rebuilds to >=18 chars, so short prose tokens are skipped entirely. Each
    # rebuilt token is scanned with the boundary-relaxed _DENSE_PATTERNS (ya29
    # keeps its required '.', unaffected) plus the bare-literal _BARE_PATTERNS for
    # AKIA / fine-grained github_pat (whose '_' separators are also stripped).
    for _tok in fold.split():
        if len(_tok) < 18:                       # real secret rebuilds to >=18
            continue
        _forms = set()
        for _strip in (r"[^A-Za-z0-9+/=_-]", r"[^A-Za-z0-9_]"):
            _f = re.sub(_strip, "", _tok)
            if len(_f) >= 18:
                _forms.add(_f)
        for _f in _forms:
            _fb = _f.encode("utf-8", "replace")
            for name, pat, sev in _DENSE_PATTERNS:
                if pat.search(_fb):
                    hits.append({"pattern": name, "severity": sev,
                                 "source": "egress-tokensplit", "offset": 0,
                                 "context": f"…[REDACTED—{name}]…"})
        _bare = re.sub(r"[^A-Za-z0-9]", "", _tok)   # strip '_' and '-' too
        if len(_bare) >= 18:
            _bb = _bare.encode("utf-8", "replace")
            for name, pat, sev in _SPLIT_PATTERNS:    # ya29/ghp/slack distinguisher dropped
                if pat.search(_bb):
                    hits.append({"pattern": name, "severity": sev,
                                 "source": "egress-tokensplit", "offset": 0,
                                 "context": f"…[REDACTED—{name}]…"})
    # "One separator between every character" exfil ('A S I A …', 'A.K.I.A…',
    # 'g_h_p_…') that SPANS whitespace (so the per-token pass above cannot rejoin
    # it): a run of single chars each followed by the SAME single separator. Real
    # prose has MULTI-char words between separators, so it does not match this
    # structure → no false positive. Collapse the separator and scan the result
    # with the relaxed split patterns (safe: only a genuine per-char run reaches
    # here). The backreference \1 pins one consistent separator (incl. '_'/'-').
    for _m in re.finditer(r"[A-Za-z0-9]([^A-Za-z0-9])(?:[A-Za-z0-9]\1){15,}", fold):
        _collapsed = _m.group(0).replace(_m.group(1), "")
        _cb = _collapsed.encode("utf-8", "replace")
        for name, pat, sev in _SPLIT_PATTERNS:
            if pat.search(_cb):
                hits.append({"pattern": name, "severity": sev,
                             "source": "egress-charsplit", "offset": _m.start(),
                             "context": f"…[REDACTED—{name}]…"})
    # `punct_dense` (base64 alphabet kept) feeds the DECODE pass below: an ENCODED
    # secret split by whitespace OR punctuation re-contiguates here for decoding.
    punct_dense = re.sub(r"[^A-Za-z0-9+/=_-]", "", fold)
    # Fold-tolerant PEM-FRAME backstop. The literal private_key_header pattern needs
    # the exact ASCII '-----BEGIN … PRIVATE KEY-----'; a homoglyph in a keyword that
    # the per-glyph fold did not map (e.g. Cherokee Ꮐ U+13C0 → 'G' in BEGIN) breaks
    # the literal match, and the has_homoglyph_token_shape backstop cannot help —
    # PEM keyword runs (BEGIN/RSA/PRIVATE/KEY) are all < its 16-char floor. So flag
    # a dashed frame -----…----- whose folded inner STILL carries a non-ASCII letter
    # AND contains ≥2 distinct PEM keywords as WHOLE WORDS. Requiring two whole-word
    # keywords (a real header is 'BEGIN … PRIVATE KEY' / 'BEGIN … PUBLIC KEY' /
    # 'BEGIN CERTIFICATE', so a single homoglyph still leaves ≥2 intact) avoids the
    # false positive of a bilingual report heading where ONE keyword appears as an
    # ordinary label ('----- 主要指标 KEY METRICS -----', '----- 開始 BEGIN SECTION
    # -----') and the whole-word match avoids MONKEY/DONKEY/TURKEY/HOTKEY. A
    # decorative/accented frame ('----- LÉGENDE -----') folds to ASCII → no residual.
    for _fm in re.finditer(r"-{4,}([^\n-]{1,80}?)-{4,}", fold):
        _inner = _fm.group(1)
        if any(ord(_c) > 127 and _ud.category(_c)[0] == "L" for _c in _inner):
            _words = {_w.upper() for _w in re.findall(r"[A-Za-z]+", _inner)}
            if len(_words & _PEM_KEYWORDS) >= 2:
                hits.append({"pattern": "private_key_header_homoglyph",
                             "severity": "CRITICAL", "source": "egress-pemframe",
                             "offset": _fm.start(),
                             "context": "…[REDACTED—homoglyphed PEM header]…"})
    # DECODE pass: an agent could hex/base32/base64-encode a secret so the raw
    # scanner misses it but the email recipient / TTS listener trivially decodes
    # it. Decode plausible encoded blobs and scan the decoded bytes with the same
    # anchored patterns. Decoding ordinary text/hashes yields random bytes that
    # match no anchored pattern, so this adds no false positive. Bounded to keep
    # it cheap on large summaries.
    # Process EVERY distinct candidate (no count cap that an attacker could push
    # the real secret past with junk fillers — that was a bypass). The input is
    # already length-bounded by the callers (audio ≤4000 chars, email ≤64 KiB);
    # bound the total decoded volume and FAIL CLOSED on pathological volume.
    # Scan the fold, the whitespace-collapsed `dense` form, AND a form with every
    # non-encoding-alphabet char removed (`punct_dense`): an encoded secret split by
    # an inserted space/newline re-contiguates in `dense`, and one split by inserted
    # PUNCTUATION ('eWEy.OS5B…', which `dense` keeps because it only collapses
    # whitespace) re-contiguates in `punct_dense`. _try_decode's 0-3/0-7 alignment
    # offsets re-align the secret even when prose chars glue to it, and decoding
    # glued prose yields random bytes that match no anchored pattern (no false
    # positive). Shared `_seen` decodes a blob appearing in multiple forms once.
    # (`punct_dense` was built above for the punctuation-collapsed anchored scan.)
    # RECURSE to a bounded depth: an agent that knows to base64-encode a secret
    # equally knows to encode it TWICE (the recipient just decodes twice), so a
    # single-layer decode leaks a MULTI-level-encoded credential. After decoding a
    # candidate, if the result is itself a mostly-encoding-alphabet printable string
    # (i.e. plausibly another encoded layer), re-feed it for another round — up to
    # `_MAX_DECODE_DEPTH`, sharing `_seen` and the volume guard so cost stays
    # bounded and fail-closed. Random/text decodes are non-printable or not
    # alphabet-dense, so they terminate immediately → no false positive. (Mirrors
    # the runner-secret validator's multi-level decoded-passphrase screen.)
    _seen: set = set()
    _total = 0
    _MAX_DECODE_DEPTH = 3
    _work = [(_src, 0) for _src in (fold, dense, punct_dense)]
    while _work:
        _src, _depth = _work.pop()
        for _m in re.finditer(r"[A-Za-z0-9+/=_-]{24,}", _src):
            _b = _m.group(0)
            if _b in _seen or len(_b) > 200000:
                continue
            _seen.add(_b)
            for _dec in _try_decode(_b):
                if not _dec:
                    continue
                _total += len(_dec)
                # Scan decoded bytes with BOTH the anchored patterns AND the
                # boundary-relaxed _DENSE_PATTERNS. A prose word whose length is a
                # multiple of the encoding group glues to the secret's base64 so the
                # decoded bytes place an alnum byte immediately before the token
                # anchor — the \b in the anchored patterns then fails, but the secret
                # is fully present and recipient-recoverable. The \b-stripped
                # _DENSE_PATTERNS catch it; random/hash/text decodes still match no
                # distinctive prefix, so no false positive.
                hits += scan_bytes(_dec, "egress-decoded")
                for _dn, _dp, _dsev in _DENSE_PATTERNS:
                    if _dp.search(_dec):
                        hits.append({"pattern": _dn, "severity": _dsev,
                                     "source": "egress-decoded-dense", "offset": 0,
                                     "context": f"…[REDACTED—{_dn}]…"})
                if _total > 4_000_000:   # pathological volume → refuse (fail closed)
                    hits.append({"pattern": "egress_decode_volume", "severity": "HIGH",
                                 "source": "egress", "offset": 0,
                                 "context": "…[REDACTED—excessive encoded content]…"})
                    return hits
                if _depth < _MAX_DECODE_DEPTH:
                    try:
                        _dtext = _dec.decode("ascii")
                    except UnicodeDecodeError:
                        continue                 # non-ASCII bytes → not another layer
                    # only recurse on an alphabet-DENSE printable string (an encoded
                    # layer is ~100% [A-Za-z0-9+/=_-]); random/text decodes are not,
                    # so they terminate the recursion (no FP, bounded cost).
                    if (len(_dtext) >= 24
                            and sum(c in _ENC_ALPHABET for c in _dtext) >= 0.9 * len(_dtext)):
                        _work.append((_dtext, _depth + 1))
    return hits


def _try_decode(blob: str) -> list[bytes]:
    """Return decoded-byte candidates for hex / base64 / base64url / base32
    interpretations of `blob`.

    For each encoding and each alignment OFFSET a glued prefix would introduce
    (e.g. `key=<base64>` or re-contiguated prose+secret), try BOTH:
      • a right-TRUNCATED slice (length cut to a whole group) — preserves the
        alignment of a secret embedded after a prefix even when stripping an
        inserted/padding char left a non-group length; and
      • a right-PADDED slice — preserves the final bytes of a STANDALONE
        exact-length secret (so e.g. an AKIA value is not shortened below its
        fixed pattern length).
    Together these recover an encoded secret whether it is standalone, glued to
    prose, or split by an inserted whitespace/punctuation char (whose stripping
    would otherwise misalign the remainder). Failures are skipped."""
    import base64 as _b64
    import binascii as _ba
    out: list[bytes] = []
    b = blob.encode("ascii", "ignore")

    def _attempt(decoder, s: bytes) -> None:
        if s:
            try:
                out.append(decoder(s))
            except (ValueError, _ba.Error):
                pass

    _hx = re.sub(rb"[^0-9a-fA-F]", b"", b)
    for _off in (0, 1):                       # even-length alignment
        _s = _hx[_off:]
        if len(_s) >= 40:
            _attempt(lambda x: bytes.fromhex(x.decode("ascii")),
                     _s[: len(_s) // 2 * 2])
    for _strip, _dec in ((rb"[^A-Za-z0-9+/]", _b64.b64decode),
                         (rb"[^A-Za-z0-9_-]", _b64.urlsafe_b64decode)):
        _clean = re.sub(_strip, b"", b)
        for _off in range(4):                  # base64 is 4-char aligned
            _s = _clean[_off:]
            if len(_s) < 24:
                continue
            _attempt(_dec, _s[: len(_s) // 4 * 4])           # truncate (start-aligned)
            if len(_s) % 4 != 1:                              # %4==1 cannot be padded
                _attempt(_dec, _s + b"=" * (-len(_s) % 4))   # pad (keep tail bytes)
    _b32 = re.sub(rb"[^A-Za-z2-7]", b"", b).upper()
    for _off in range(8):                      # base32 is 8-char aligned
        _s = _b32[_off:]
        if len(_s) < 32:
            continue
        _attempt(_b64.b32decode, _s[: len(_s) // 8 * 8])
        _attempt(lambda x: _b64.b32decode(x + b"=" * (-len(x) % 8)), _s)
    return out


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
