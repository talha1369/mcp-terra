#!/usr/bin/env bash
# mcp-terra one-shot installer for lab members / collaborators.
#
# Usage:
#   ./install.sh                                # interactive — asks for workspace
#   ./install.sh claussnitzer-fdp/your-ws      # non-interactive with workspace
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

# ── 4. Runner secret ───────────────────────────────────────────────────────
step "Runner secret (HMAC key)"

if [ -f "$SECRET_FILE" ] && [ -s "$SECRET_FILE" ]; then
  ok "Reusing existing runner secret at $SECRET_FILE"
  RUNNER_SECRET="$(cat "$SECRET_FILE")"
else
  RUNNER_SECRET="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  umask 077
  printf '%s' "$RUNNER_SECRET" > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  ok "Generated new runner secret → $SECRET_FILE (mode 0600)"
fi

# Validate strength in the venv where mcp_terra is importable.
"$VENV_PY" -c "
import os
os.environ['MCP_TERRA_RUNNER_SECRET']='$RUNNER_SECRET'
from mcp_terra.notebook_runner import _validate_secret_strength
_validate_secret_strength('$RUNNER_SECRET')
" || fail "Runner secret failed strength check (length ≥ 32, ≥ 12 unique chars, Shannon ≥ 3.5)"
ok "Secret passes length + entropy checks"

# ── 5. Workspace ───────────────────────────────────────────────────────────
step "Terra workspace"

WORKSPACE="${1:-}"
if [ -z "$WORKSPACE" ]; then
  printf "  Enter your Terra workspace as 'namespace/name'\n"
  printf "  (e.g. claussnitzer-fdp/talha_notebooks): "
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

# ── 6. Register MCP with Claude Code ───────────────────────────────────────
step "Registering MCP with Claude Code"

# Idempotent: remove any prior registration first.
"$CLAUDE_BIN" mcp remove terra -s user >/dev/null 2>&1 || true

# Robust PATH so the MCP subprocess finds gcloud regardless of how Claude
# Code is launched (Dock/Spotlight on macOS strip the shell PATH).
MCP_PATH="$(dirname "$GCLOUD"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

"$CLAUDE_BIN" mcp add terra \
  -s user \
  -e "MCP_TERRA_ALLOW_WRITES=1" \
  -e "MCP_TERRA_WORKSPACE=$WORKSPACE" \
  -e "MCP_TERRA_RUNNER_SECRET=$RUNNER_SECRET" \
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
