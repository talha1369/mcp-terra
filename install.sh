#!/usr/bin/env bash
# mcp-terra one-shot installer for lab members / collaborators.
#
# Usage:
#   ./install.sh                                # interactive — asks for workspace
#   ./install.sh your-namespace/your-ws      # non-interactive with workspace
#
# What this does (idempotent — safe to re-run):
#   1. Verifies Python ≥ 3.10, gcloud, gcloud ADC login, Claude Code CLI
#   2. Creates a dedicated venv at ~/.mcp-terra/venv (sidesteps PEP 668 on
#      Homebrew Python so we never touch your system interpreter)
#   3. Installs the package + pinned deps into THAT venv
#   4. Generates a runner secret (or reuses an existing ~/.mcp-terra/runner_secret)
#   5. Verifies you have access to the Terra workspace (Rawls lookup)
#   6. Registers the MCP via `claude mcp add` with the venv python + all env vars
#   7. Confirms the MCP shows ✔ Connected
#
# Does NOT do:
#   • Edit your .zshrc / shell rc (we keep secrets out of dotfiles)
#   • Touch your system Python or any other venv
#   • Submit any jobs (the first agent prompt does that)
#
# Note: the on-VM runner now starts AUTOMATICALLY on every VM boot/resume
# (terra_create_runtime wires a Leonardo startUserScriptUri). No manual
# Jupyter-terminal step is needed for new runtimes.
set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_DIR="$HOME/.mcp-terra/venv"
SECRET_FILE="$HOME/.mcp-terra/runner_secret"

step() { printf "\n\033[1;34m▶ %s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*"; exit 1; }
info() { printf "  · %s\n" "$*"; }

# ── 1. Prereqs ──────────────────────────────────────────────────────────────
step "Checking prerequisites"

# Python ≥ 3.10 (only used to BOOTSTRAP the venv; we then use the venv python)
BOOT_PY="$(command -v python3 || command -v python || true)"
[ -n "$BOOT_PY" ] || fail "python3 not found on PATH"
PY_OK="$("$BOOT_PY" -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')"
[ "$PY_OK" = "1" ] || fail "$BOOT_PY is $($BOOT_PY -V); mcp-terra needs Python ≥ 3.10"
ok "Python (for venv bootstrap): $($BOOT_PY -V) at $BOOT_PY"

# gcloud — search PATH plus common install locations
GCLOUD=""
for cand in "$(command -v gcloud 2>/dev/null || true)" \
            /opt/homebrew/bin/gcloud \
            /usr/local/bin/gcloud \
            "$HOME/google-cloud-sdk/bin/gcloud" \
            "$HOME/Downloads/google-cloud-sdk/bin/gcloud"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then GCLOUD="$cand"; break; fi
done
[ -n "$GCLOUD" ] || fail "gcloud not found. Install from https://cloud.google.com/sdk"
ok "gcloud: $GCLOUD"

# ADC token
"$GCLOUD" auth application-default print-access-token >/dev/null 2>&1 \
  || fail "gcloud ADC not set up. Run: gcloud auth application-default login"
ACCOUNT="$("$GCLOUD" config get-value account 2>/dev/null)"
[ -n "$ACCOUNT" ] && [[ "$ACCOUNT" == *@* ]] || fail "gcloud account not set"
ok "gcloud account: $ACCOUNT"

# Claude Code CLI
CLAUDE_BIN="$(command -v claude || true)"
[ -n "$CLAUDE_BIN" ] || fail "Claude Code CLI 'claude' not found on PATH"
ok "Claude Code: $CLAUDE_BIN"

# ── 2. Venv ────────────────────────────────────────────────────────────────
step "Provisioning ~/.mcp-terra/venv"

mkdir -p "$HOME/.mcp-terra" && chmod 700 "$HOME/.mcp-terra"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$BOOT_PY" -m venv "$VENV_DIR" || fail "Could not create venv at $VENV_DIR"
  ok "Created venv at $VENV_DIR"
else
  ok "Reusing existing venv at $VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
# Sanity: venv python must be ≥ 3.10 too (boot python guarantees it, but check anyway).
"$VENV_PY" -c 'import sys; assert sys.version_info >= (3,10)' \
  || fail "Venv python at $VENV_PY is too old"

"$VENV_PY" -m pip install --quiet --upgrade pip wheel >/dev/null 2>&1 \
  || fail "Could not upgrade pip/wheel inside venv"

# ── 3. Install package ─────────────────────────────────────────────────────
step "Installing mcp-terra into venv"

cd "$REPO_DIR"

# Install pinned deps with hash verification (PEP 491 / requirements.lock).
if [ -f requirements.lock ]; then
  "$VENV_PY" -m pip install --quiet --require-hashes -r requirements.lock \
    || fail "pip install --require-hashes failed (see output above)"
  ok "Installed pinned deps from requirements.lock"
fi

# Install the package itself (editable so iteration on the repo updates the
# installed copy — perfect for the typical sharer who'll keep tweaking).
"$VENV_PY" -m pip install --quiet -e . \
  || fail "pip install -e . failed (see output above)"

# Verify import — REAL check, no `|| true` masking failure.
"$VENV_PY" -c 'import mcp_terra; print(f"  · mcp_terra version: {mcp_terra.__version__}")' \
  || fail "mcp_terra failed to import after install"
ok "Package importable from venv"

# ── 3b. Pre-authorize the MCP tools (no per-call permission prompts) ─────────
# Every install pre-approves the terra MCP tools in ~/.claude/settings.json
# (permissions.allow) so the auto-fix loop runs automatically, without a
# permission prompt on each tool call. The MCP's OWN hard guards remain the
# safety net regardless: there is NO delete/overwrite primitive anywhere, plus
# the spend cap, per-session submit cap, controlled-access guard, rate limit, and
# kill-switch. Opt OUT with MCP_TERRA_NO_AUTO_APPROVE=1 (then you'll be prompted
# per tool, as Claude Code does by default).
if [ -z "${MCP_TERRA_NO_AUTO_APPROVE:-}" ]; then
  step "Pre-authorizing MCP tools (Claude Code permissions.allow)"
  if "$VENV_PY" - <<'PYAUTH'
import contextlib, io, json, os, sys, tempfile
settings = os.path.expanduser("~/.claude/settings.json")
# Enumerate the ACTUAL registered tool surface (future-proof; no hardcoded list).
try:
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        from mcp_terra import server as _s
        tools = sorted(t.name for t in _s.server._tool_manager.list_tools())
except Exception as e:
    print(f"could not enumerate tools: {e}", file=sys.stderr); sys.exit(1)
want = [f"mcp-terra:{t}" for t in tools] + ["mcp-terra:*"]
os.makedirs(os.path.dirname(settings), exist_ok=True)
data = {}
if os.path.exists(settings):
    try:
        with open(settings) as fh:
            data = json.load(fh)
    except Exception:
        # Never clobber an unreadable/foreign settings file — fail loud instead.
        print("~/.claude/settings.json is not valid JSON; refusing to modify it", file=sys.stderr)
        sys.exit(1)
allow = data.setdefault("permissions", {}).setdefault("allow", [])
added = sum(1 for w in want if w not in allow and not allow.append(w))
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(settings))
with os.fdopen(fd, "w") as fh:
    json.dump(data, fh, indent=2)
os.chmod(tmp, 0o600)
os.replace(tmp, settings)
print(f"pre-authorized {len(tools)} terra tools (+ wildcard); {added} new entry(ies)")
PYAUTH
  then
    ok "MCP tools pre-authorized in ~/.claude/settings.json (opt out: MCP_TERRA_NO_AUTO_APPROVE=1)"
  else
    info "Could not pre-authorize MCP tools automatically (non-fatal; you may see per-tool prompts)."
  fi
else
  info "MCP_TERRA_NO_AUTO_APPROVE set — leaving Claude Code to prompt per tool."
fi

# ── 4. Runner secret ───────────────────────────────────────────────────────
step "Runner secret (HMAC key)"

if [ -e "$SECRET_FILE" ] && [ -s "$SECRET_FILE" ]; then
  # Reuse — but only a SAFE secret file: a regular file (not a symlink/device),
  # owned by us, with no group/other access. An attacker who pre-creates the
  # secret (or symlinks it) could otherwise steal/redirect the HMAC key that
  # signs runner-accepted specs. Fail loud rather than trust a suspect file.
  [ -L "$SECRET_FILE" ] && fail "$SECRET_FILE is a symlink — refusing (move it aside)."
  [ -f "$SECRET_FILE" ] || fail "$SECRET_FILE is not a regular file — refusing."
  # Owner == current user
  _own="$(stat -f '%u' "$SECRET_FILE" 2>/dev/null || stat -c '%u' "$SECRET_FILE" 2>/dev/null || echo -1)"
  [ "$_own" = "$(id -u)" ] || fail "$SECRET_FILE is not owned by you (uid $_own) — refusing."
  # Perms must be 0600 (no group/other). Tighten if looser; never widen.
  _mode="$(stat -f '%Lp' "$SECRET_FILE" 2>/dev/null || stat -c '%a' "$SECRET_FILE" 2>/dev/null || echo 000)"
  case "$_mode" in
    600) : ;;
    *) chmod 600 "$SECRET_FILE" && info "tightened $SECRET_FILE to mode 0600 (was $_mode)" ;;
  esac
  ok "Reusing existing runner secret at $SECRET_FILE"
  RUNNER_SECRET="$(cat "$SECRET_FILE")"
else
  RUNNER_SECRET="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  umask 077
  printf '%s' "$RUNNER_SECRET" > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  ok "Generated new runner secret → $SECRET_FILE (mode 0600)"
fi

# Validate strength in the venv where mcp_terra is importable. Pass the secret
# via the ENVIRONMENT (read with os.environ), NEVER interpolated into the
# `python -c` source — argv is visible to other users via `ps`, env is not.
MCP_TERRA_RUNNER_SECRET="$RUNNER_SECRET" "$VENV_PY" -c '
import os
from mcp_terra.notebook_runner import _validate_secret_strength
_validate_secret_strength(os.environ["MCP_TERRA_RUNNER_SECRET"])
' || fail "Runner secret failed strength check (length ≥ 32, ≥ 12 unique chars, Shannon ≥ 3.5)"
ok "Secret passes length + entropy checks"

# ── 5. Workspace ───────────────────────────────────────────────────────────
step "Terra workspace"

WORKSPACE="${1:-}"
if [ -z "$WORKSPACE" ]; then
  printf "  Enter your Terra workspace as 'namespace/name'\n"
  printf "  (e.g. your-namespace/your-workspace): "
  read -r WORKSPACE
fi
[[ "$WORKSPACE" == */* ]] || fail "Workspace must be 'namespace/name', got '$WORKSPACE'"
ok "Workspace: $WORKSPACE"

NS="${WORKSPACE%%/*}"
NM="${WORKSPACE#*/}"
TOKEN="$("$GCLOUD" auth application-default print-access-token)"
TMPF="$(mktemp)"; trap 'rm -f "$TMPF"' EXIT
HTTP_CODE="$(curl -s -o "$TMPF" -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "https://rawls.dsde-prod.broadinstitute.org/api/workspaces/$NS/$NM?fields=workspace.bucketName")"
if [ "$HTTP_CODE" != "200" ]; then
  fail "Workspace lookup returned HTTP $HTTP_CODE. Check spelling and your Terra access."
fi
BUCKET="$("$VENV_PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['workspace']['bucketName'])" "$TMPF")"
ok "Workspace bucket: gs://$BUCKET"

# ── 5b. Shared config.env (sourced by the plugin launcher) ─────────────────
# Robust PATH so the MCP subprocess finds gcloud regardless of how Claude Code
# is launched (Dock/Spotlight on macOS strip the shell PATH).
MCP_PATH="$(dirname "$GCLOUD"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

step "Writing ~/.mcp-terra/config.env (for the plugin launcher)"
CONFIG_FILE="$HOME/.mcp-terra/config.env"
umask 077
cat > "$CONFIG_FILE" <<EOF
# mcp-terra config — sourced by the plugin launcher (scripts/terra-mcp-launch.sh).
# Generated by install.sh. Mode 0600. Do NOT commit; do NOT share (refs the secret).
MCP_TERRA_ALLOW_WRITES=1
MCP_TERRA_WORKSPACE=$WORKSPACE
MCP_TERRA_RUNNER_SECRET_FILE=$SECRET_FILE
PATH=$MCP_PATH
HOME=$HOME
EOF
chmod 600 "$CONFIG_FILE"
ok "Wrote $CONFIG_FILE (mode 0600)"

# In PLUGIN MODE the plugin's .mcp.json already registers the server via the
# launcher (which sources config.env above) — so SKIP `claude mcp add` and the
# connect check; the user just restarts Claude Code.
if [ -n "${MCP_TERRA_PLUGIN_MODE:-}" ]; then
  step "Plugin bootstrap complete"
  cat <<EOF

  The mcp-terra plugin is bootstrapped. Restart Claude Code so the plugin's
  MCP server connects (it launches via scripts/terra-mcp-launch.sh, which loads
  $CONFIG_FILE).

  Then verify with:   Run terra_health
  Workspace bucket:   gs://$BUCKET

EOF
  exit 0
fi

# ── 6. Register MCP with Claude Code ───────────────────────────────────────
step "Registering MCP with Claude Code"

# Idempotent: remove any prior registration first.
"$CLAUDE_BIN" mcp remove terra -s user >/dev/null 2>&1 || true

# Robust PATH so the MCP subprocess finds gcloud regardless of how Claude
# Code is launched (Dock/Spotlight on macOS strip the shell PATH).
MCP_PATH="$(dirname "$GCLOUD"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

# Register the secret by FILE PATH, never by value: putting the raw HMAC key on
# the `claude mcp add` argv would expose it via `ps` and persist it in the MCP
# env config. The server reads MCP_TERRA_RUNNER_SECRET_FILE (a 0600 file) at
# runtime; the secret value never appears in argv or any config.
"$CLAUDE_BIN" mcp add terra \
  -s user \
  -e "MCP_TERRA_ALLOW_WRITES=1" \
  -e "MCP_TERRA_WORKSPACE=$WORKSPACE" \
  -e "MCP_TERRA_RUNNER_SECRET_FILE=$SECRET_FILE" \
  -e "PATH=$MCP_PATH" \
  -e "HOME=$HOME" \
  -- "$VENV_PY" -m mcp_terra.server >/dev/null \
  || fail "claude mcp add failed"
ok "Registered (user scope) → claude mcp list"

# Verify it boots and connects.
STATUS_LINE="$("$CLAUDE_BIN" mcp list 2>/dev/null | grep -E '^terra:' || true)"
if echo "$STATUS_LINE" | grep -q "Connected"; then
  ok "MCP server is ✔ Connected"
else
  echo "  $STATUS_LINE"
  fail "MCP server did not connect. Try: claude mcp list   (or claude --debug 2>&1 | grep -iE 'mcp|terra')"
fi

# ── 7. Done ────────────────────────────────────────────────────────────────
step "Install complete"

cat <<EOF

  Next steps:

  1. Open Claude Code from anywhere:

       claude                            # or: cd $REPO_DIR && claude
                                         # the second form also loads the
                                         # /terra-setup-check, /terra-bugfix-loop,
                                         # /terra-share-pack project skills.

  2. First prompt to verify:

       Run terra_health

  3. To run a notebook end-to-end (NO MANUAL VM SETUP — the MCP handles it):

       Run gs://$BUCKET/notebooks/<your-notebook>.ipynb end-to-end via
       the auto-fix loop, auto-stop on success, email me the verified report.

     The agent will (in order):
       a. terra_create_runtime (ATOMIC + seamless — the VM boots with a live
          on-VM runner via startUserScriptUri, or the call fails loud; no SSH,
          no manual Jupyter step)
       b. terra_submit_notebook_job (signed spec → bucket → on-VM runner)
       c. Wait + auto-fix any failures via the deterministic triager
       d. terra_send_run_report_email with verifier-acknowledged report

  Legacy fallback (runtimes created before the seamless flow, or if you must
  restart the runner on an existing VM):
     terra_start_runner_on_vm (gcloud ssh), or SOP.md § 3b — open a Jupyter
     terminal on the Terra VM and paste the bootstrap. Secret at $SECRET_FILE.

  Re-run ./install.sh any time to refresh the registration. Idempotent.

EOF
