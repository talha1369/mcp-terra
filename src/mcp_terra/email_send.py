"""Email-send helper for the MCP — strictly scoped to one purpose:

  Deliver an end-of-run report to the AUTH'D TERRA USER (and ONLY that
  address). No third-party recipients, no arbitrary headers, and no ARBITRARY
  attachments — to defeat data-exfil-via-email. The ONLY permitted attachment
  is the run's own audio explainer (.mp3/.m4a), whose path the caller derives
  from job_id + the locked bucket (never an arbitrary path); size-capped and
  audio-MIME-locked here.

Configuration (env, snapshotted at startup):
  MCP_TERRA_SMTP_HOST          required for live send (else file fallback)
  MCP_TERRA_SMTP_PORT          default 587
  MCP_TERRA_SMTP_USER          required for live send
  MCP_TERRA_SMTP_PASS          required for live send (app password, NOT main pw)
  MCP_TERRA_SMTP_STARTTLS      default '1'; set to '0' to disable (TLS-only ports use 465 implicit-TLS)
  MCP_TERRA_SMTP_FROM          default = MCP_TERRA_SMTP_USER
  MCP_TERRA_EMAIL_RECIPIENT_OVERRIDE
                               OPTIONAL — used ONLY in tests; if set, sends to
                               this address instead of the Terra account email.
                               Refused unless the override matches the auth'd
                               user. Useful when gcloud account != desired inbox.

Fallback when SMTP env vars are missing:
  An RFC-822 .eml file is written under ~/.mcp-terra/reports/<ts>-<job_id>.eml
  (mode 0o600). The tool RETURNS the path so the user can open it manually.

Hard refusals:
  • Subject contains \\r or \\n  → refuse (header injection)
  • Subject longer than 200 chars → refuse
  • Body > 64 KiB              → refuse (capped)
  • Body contains the OAuth token → refuse (defense in depth)
  • Recipient != auth.get_user_email() → refuse (no-exfil)
  • verification_acknowledgment empty or < 50 chars → refuse
"""
from __future__ import annotations

import email.message
import email.utils
import os
import smtplib
import socket
import ssl
import time
from pathlib import Path

from . import auth, safety, secret_scan


class EmailError(RuntimeError):
    """Raised when the email tool refuses or fails."""


# Snapshot env at module load — so an attacker who flips env mid-session
# can't redirect the SMTP host. (Same pattern as the writes-allowed snapshot.)
_SMTP_HOST     = os.environ.get("MCP_TERRA_SMTP_HOST", "").strip()
_SMTP_PORT     = int(os.environ.get("MCP_TERRA_SMTP_PORT", "587"))
_SMTP_USER     = os.environ.get("MCP_TERRA_SMTP_USER", "").strip()
_SMTP_PASS     = os.environ.get("MCP_TERRA_SMTP_PASS", "")
_SMTP_STARTTLS = os.environ.get("MCP_TERRA_SMTP_STARTTLS", "1").strip() != "0"
_SMTP_FROM     = os.environ.get("MCP_TERRA_SMTP_FROM", "").strip() or _SMTP_USER
# Option C: no-auth relay (e.g. a Google Workspace / Broad SMTP relay that
# authorizes by IP, so no app-password is needed). EXPLICIT opt-in only — a
# merely-forgotten USER/PASS must fall back to the .eml file, never silently
# send unauthenticated.
_SMTP_RELAY    = os.environ.get("MCP_TERRA_SMTP_RELAY", "").strip() not in ("", "0")
_RECIPIENT_OVERRIDE = os.environ.get("MCP_TERRA_EMAIL_RECIPIENT_OVERRIDE", "").strip()

_REPORTS_DIR = Path.home() / ".mcp-terra" / "reports"

_MAX_SUBJECT = 200
_MAX_BODY    = 64 * 1024
_MIN_ACK_LEN = 50
_MAX_ACK_LEN = 4096      # upper cap on verification_acknowledgment (SOTA fix)


def _safe_recipient() -> str:
    """Return the Terra user email, with optional same-user override.

    Refuses unless any override equals the auth'd address. This defeats
    a malicious env-flip that tries to redirect mail to a third party.
    """
    me = auth.get_user_email().strip().lower()
    if not me or "@" not in me:
        raise EmailError(f"could not resolve Terra account email; got {me!r}")
    if _RECIPIENT_OVERRIDE:
        if _RECIPIENT_OVERRIDE.lower() != me:
            raise EmailError(
                f"MCP_TERRA_EMAIL_RECIPIENT_OVERRIDE ({_RECIPIENT_OVERRIDE!r}) "
                f"does not match the auth'd Terra account email ({me!r}). "
                f"Refusing — the override exists only for same-user inbox "
                f"redirection, not for sending to other people."
            )
    return me


def _validate_inputs(subject: str, body: str, job_id: str,
                      verification_acknowledgment: str) -> None:
    if not isinstance(subject, str):
        raise EmailError(f"subject must be str; got {type(subject).__name__}")
    if not isinstance(body, str):
        raise EmailError(f"body must be str; got {type(body).__name__}")
    if not isinstance(job_id, str):
        raise EmailError(f"job_id must be str; got {type(job_id).__name__}")
    if not isinstance(verification_acknowledgment, str):
        raise EmailError(
            f"verification_acknowledgment must be str; got "
            f"{type(verification_acknowledgment).__name__}"
        )
    if len(subject) == 0 or len(subject) > _MAX_SUBJECT:
        raise EmailError(
            f"subject length {len(subject)} out of range (1..{_MAX_SUBJECT})"
        )
    if "\r" in subject or "\n" in subject:
        raise EmailError(
            "subject contains CR/LF — refusing (header-injection defense)"
        )
    if len(body) > _MAX_BODY:
        raise EmailError(
            f"body length {len(body)} exceeds cap ({_MAX_BODY} bytes)"
        )
    if "\r" in body:
        # Mangle CR — keep LF only to defeat header-smuggling in body lines
        # that get re-interpreted as headers by some buggy MTAs.
        raise EmailError(
            "body contains CR characters — refusing (header-injection defense)"
        )
    if len(verification_acknowledgment) < _MIN_ACK_LEN:
        raise EmailError(
            f"verification_acknowledgment must be ≥ {_MIN_ACK_LEN} chars; "
            f"got {len(verification_acknowledgment)}. The agent who reviewed "
            f"this report must explicitly describe what evidence they "
            f"checked (run log path, traceback lines, etc.)."
        )
    if len(verification_acknowledgment) > _MAX_ACK_LEN:
        raise EmailError(
            f"verification_acknowledgment length {len(verification_acknowledgment)} "
            f"exceeds cap ({_MAX_ACK_LEN} bytes)"
        )
    if "\r" in verification_acknowledgment:
        raise EmailError(
            "verification_acknowledgment contains CR characters — refusing "
            "(header-injection defense)"
        )
    # Defense in depth #1: shape-based detection — refuse any ya29.* token
    # anywhere in body/subject/ack. Catches STALE tokens that no longer
    # equal the freshly-fetched one (Google OAuth tokens live ~3600s; an
    # agent could have captured one earlier and tried to exfil it now).
    # Check raw, NFKC-normalized, AND confusable-folded forms so full-width
    # AND Cyrillic/Greek homoglyphs (e.g. Cyrillic у/а for ASCII y/a — which
    # NFKC does NOT fold) cannot smuggle a token.
    import re as _re
    _YA29_RE = _re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}")
    for field_name, field_val in (
        ("subject", subject), ("body", body),
        ("verification_acknowledgment", verification_acknowledgment),
    ):
        if _YA29_RE.search(field_val):
            raise EmailError(
                f"refusing to send: ya29.* OAuth-token shape detected in "
                f"{field_name}. This is a defense-in-depth check (catches "
                f"stale tokens too)."
            )
        # Same check on the de-homoglyphed form (NFKD + confusable fold +
        # invisible-char strip) — defeats homoglyph / zero-width smuggling NFKC
        # alone would miss.
        if _YA29_RE.search(secret_scan.fold_confusables(field_val)):
            raise EmailError(
                f"refusing to send: ya29.* OAuth-token shape detected in "
                f"{field_name} (de-homoglyphed). Homoglyph-smuggling defense."
            )
        # Full secret scan over raw AND de-homoglyphed forms — the ya29 check
        # above is Google-OAuth only; an email must not exfil ANY secret shape
        # (AWS / GitHub / Slack / PEM …), plain or homoglyph-smuggled. (security
        # review: email previously scanned ONLY ya29.)
        _hits = secret_scan.scan_bytes(field_val.encode("utf-8"), f"email-{field_name}")
        _folded = secret_scan.fold_confusables(field_val)
        if _folded != field_val:
            _hits = _hits + secret_scan.scan_bytes(_folded.encode("utf-8"),
                                                   f"email-{field_name}-folded")
        if _hits:
            raise EmailError(
                f"refusing to send: {len(_hits)} secret-shaped value(s) detected "
                f"in {field_name} (raw or de-homoglyphed) — no secret exfil by email."
            )
        # Catch homoglyphs outside the curated fold (secondary backstop):
        # a token-shaped run with a residual non-ASCII letter is not a real
        # (pure-ASCII) token — refuse rather than risk emailing a smuggled secret.
        if secret_scan.has_homoglyph_token_shape(field_val):
            raise EmailError(
                f"refusing to send: a non-ASCII homoglyph inside a token-shaped "
                f"run detected in {field_name} (possible secret smuggling)."
            )
    # Defense in depth #2: also block the CURRENTLY-active token by exact
    # match (catches the rare case the regex misses or a non-Google token
    # format). FAIL CLOSED if auth lookup itself fails — do NOT silently
    # skip the check.
    try:
        token = auth.get_access_token()
    except auth.AuthError as e:
        raise EmailError(
            f"cannot verify token absence before send: auth lookup failed "
            f"({type(e).__name__}). Refusing to send (fail-closed). Retry "
            f"after `gcloud auth application-default login`."
        )
    try:
        safety.assert_token_not_in(body, token)
        safety.assert_token_not_in(subject, token)
        safety.assert_token_not_in(verification_acknowledgment, token)
    except safety.SafetyError as e:
        raise EmailError(
            "refusing to send: OAuth token detected in subject/body/ack. "
            "This is a defense-in-depth check."
        ) from e
    # job_id must look like a job id
    safety.validate_identifier(job_id, "job_id")


def _validate_from_address(recipient: str) -> str:
    """Resolve the From address and refuse spoofing.

    Rules: From MUST equal either the auth'd Terra user, MCP_TERRA_SMTP_USER,
    or be empty (auto-default to recipient). No arbitrary From values —
    defeats an attacker who flips MCP_TERRA_SMTP_FROM to forge mail
    appearing to come from a colleague.
    """
    from_val = (_SMTP_FROM or "").strip().lower()
    if not from_val:
        return recipient    # auto-default to the auth'd user
    user = (_SMTP_USER or "").strip().lower()
    if from_val == recipient.lower() or (user and from_val == user):
        return _SMTP_FROM
    raise EmailError(
        f"MCP_TERRA_SMTP_FROM ({_SMTP_FROM!r}) does not match the Terra "
        f"account email or SMTP user. Refusing to send — From-spoofing "
        f"defense. Leave SMTP_FROM unset to auto-default to the recipient."
    )


# Attachments are NARROWLY scoped: the ONLY thing that may be attached is the
# run's own audio explainer (.mp3/.m4a), and the caller (server tool) derives
# its path from job_id + the locked bucket — never an arbitrary path. Combined
# with the hard recipient-lock (mail only ever goes to the data owner), this
# preserves the anti-exfil posture: it cannot be coerced into mailing out an
# arbitrary file to a third party.
_MAX_ATTACH_BYTES = 15 * 1024 * 1024
_AUDIO_SUBTYPE = {"mp3": "mpeg", "m4a": "mp4"}   # ext -> MIME audio subtype


def _build_message(recipient: str, subject: str, body: str,
                    job_id: str, acknowledgment: str,
                    audio_attachment: tuple[bytes, str] | None = None,
                    ) -> email.message.EmailMessage:
    msg = email.message.EmailMessage()
    msg["From"] = _validate_from_address(recipient)
    msg["To"] = recipient
    # Subject is already CR/LF-free (validated above)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["X-MCP-Terra-Job-Id"] = job_id
    msg["X-MCP-Terra-Sender"] = "mcp-terra"
    # Note: NOT setting Reply-To. The user replies to themselves; no thread to
    # an external party.
    # Sanitize the ack via safety.sanitize_output before embedding so any
    # prompt-injection markers in the reviewer agent's text don't propagate
    # into the user's inbox.
    safe_ack = safety.sanitize_output(acknowledgment.strip())[:_MAX_ACK_LEN]
    attach_note = ""
    if audio_attachment is not None:
        attach_note = "\nAn audio explainer of the results is attached.\n"
    full_body = (
        f"This is an automated end-of-run report from mcp-terra.\n"
        f"Job ID: {job_id}\n"
        f"Reviewed-by agent acknowledgment:\n"
        f"  {safe_ack}\n"
        f"{attach_note}"
        f"\n"
        f"--- report ---\n"
        f"{body}\n"
        f"--- end report ---\n"
        f"\nThis email was sent by mcp-terra to the Terra-authenticated user "
        f"({recipient}). The MCP refuses to send mail to anyone else.\n"
    )
    msg.set_content(full_body)

    if audio_attachment is not None:
        data, filename = audio_attachment
        if not isinstance(data, (bytes, bytearray)):
            raise EmailError("audio attachment must be bytes")
        if not data:
            raise EmailError("audio attachment is empty")
        if len(data) > _MAX_ATTACH_BYTES:
            raise EmailError(
                f"audio attachment too large ({len(data)} bytes; "
                f"cap {_MAX_ATTACH_BYTES}).")
        # Filename is locked to a basename + an audio extension — defense in
        # depth even though the caller derives it.
        safe_name = os.path.basename(str(filename))
        if "\r" in safe_name or "\n" in safe_name:
            raise EmailError("attachment filename contains CR/LF")
        ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        subtype = _AUDIO_SUBTYPE.get(ext)
        if subtype is None:
            raise EmailError(
                f"attachment must be an audio file (.mp3/.m4a); got {safe_name!r}")
        msg.add_attachment(bytes(data), maintype="audio", subtype=subtype,
                           filename=safe_name)
    return msg


def _smtp_configured() -> bool:
    # B (authenticated): HOST + USER + PASS.  C (relay, no password):
    # HOST + explicit MCP_TERRA_SMTP_RELAY=1.  Else → A (.eml fallback).
    if not _SMTP_HOST:
        return False
    return bool(_SMTP_USER and _SMTP_PASS) or _SMTP_RELAY


def _send_via_smtp(msg: email.message.EmailMessage) -> dict:
    """Open an SMTP connection and send. Times out aggressively.

    SECURITY: SMTPAuthenticationError messages from some servers ECHO the
    password in their str() (e.g. `(535, b'bad password supersecret')`).
    We catch auth failures separately and return a generic message; the
    raw exception text NEVER reaches the caller.
    """
    # Relay mode (C): explicit opt-in AND no usable USER/PASS → send WITHOUT
    # authenticating (the relay authorizes by IP/network).
    relay_mode = _SMTP_RELAY and not (_SMTP_USER and _SMTP_PASS)
    context = ssl.create_default_context()
    started = time.monotonic()
    try:
        if _SMTP_PORT == 465:
            # Implicit-TLS port — SMTP_SSL
            with smtplib.SMTP_SSL(_SMTP_HOST, _SMTP_PORT,
                                    timeout=30, context=context) as s:
                if not relay_mode:
                    s.login(_SMTP_USER, _SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=30) as s:
                s.ehlo()
                if _SMTP_STARTTLS:
                    s.starttls(context=context)
                    s.ehlo()
                if not relay_mode:
                    s.login(_SMTP_USER, _SMTP_PASS)
                s.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        # Generic — auth-error text may include the password verbatim.
        raise EmailError("SMTP authentication failed. Check MCP_TERRA_SMTP_USER / "
                          "MCP_TERRA_SMTP_PASS (use an app-password, not your main "
                          "password). The MCP refuses to echo the auth exception.")
    except (smtplib.SMTPException, socket.timeout, OSError) as e:
        # Other SMTP errors are safe to surface (typed exception name only).
        # Strip the auth password out as defense-in-depth in case some server
        # smuggles it into a non-auth error code.
        msg_text = str(e)
        if _SMTP_PASS and _SMTP_PASS in msg_text:
            msg_text = msg_text.replace(_SMTP_PASS, "[REDACTED_PASS]")
        raise EmailError(f"SMTP send failed: {type(e).__name__}: {msg_text}")
    return {
        "transport": "smtp",
        "mode": "relay" if relay_mode else "authenticated",
        "host": _SMTP_HOST,
        "port": _SMTP_PORT,
        "starttls": _SMTP_STARTTLS,
        "elapsed_sec": round(time.monotonic() - started, 2),
    }


def _fallback_to_file(msg: email.message.EmailMessage, job_id: str) -> dict:
    """Write the .eml under ~/.mcp-terra/reports/ for manual delivery."""
    # SECURITY: symlink check BEFORE mkdir. If _REPORTS_DIR is already a
    # symlink, mkdir(exist_ok=True) follows it and creates dirs under the
    # attacker target. Check first.
    if _REPORTS_DIR.exists() and _REPORTS_DIR.is_symlink():
        raise EmailError(
            f"reports dir {_REPORTS_DIR} is a symlink — refusing to write."
        )
    # Parent ~/.mcp-terra must also not be a symlink (intermediate component).
    parent = _REPORTS_DIR.parent
    if parent.exists() and parent.is_symlink():
        raise EmailError(
            f"parent {parent} is a symlink — refusing to write."
        )
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Defensively tighten perms (mkdir doesn't tighten existing dir).
    try:
        os.chmod(str(_REPORTS_DIR), 0o700)
    except OSError:
        pass
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    # Sanitize job_id (already validated as identifier — safe basename)
    fname = f"{ts}-{job_id}.eml"
    path = _REPORTS_DIR / fname
    # Refuse overwrite — every send creates a new file
    if path.exists():
        raise EmailError(f"report path already exists: {path}")
    # O_NOFOLLOW + mode 0o600
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(bytes(msg))
    except Exception:
        # If write failed, leave the empty file (caller can inspect); don't
        # remove anything (no-destruction principle).
        raise
    return {
        "transport": "file",
        "path": str(path),
        "reason": "SMTP env vars (MCP_TERRA_SMTP_HOST/USER/PASS) not set; "
                  "open the .eml manually or configure SMTP and resend.",
    }


def send_run_report(*, subject: str, body: str, job_id: str,
                     verification_acknowledgment: str,
                     audio_attachment: tuple[bytes, str] | None = None) -> dict:
    """Send the end-of-run report.

    Recipient is HARD-LOCKED to the auth'd Terra user. No `to` parameter.

    audio_attachment: optional (bytes, filename) of the run's own audio
        explainer. The caller MUST derive it from the job (never an arbitrary
        path); only .mp3/.m4a are accepted and the size is capped.
    """
    _validate_inputs(subject, body, job_id, verification_acknowledgment)
    recipient = _safe_recipient()
    msg = _build_message(recipient, subject, body, job_id,
                          verification_acknowledgment,
                          audio_attachment=audio_attachment)
    if _smtp_configured():
        send_info = _send_via_smtp(msg)
    else:
        send_info = _fallback_to_file(msg, job_id)
    return {
        "status": "sent",
        "recipient": recipient,
        "subject": subject,
        "job_id": job_id,
        "audio_attached": audio_attachment is not None,
        **send_info,
    }
