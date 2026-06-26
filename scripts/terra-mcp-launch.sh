#!/usr/bin/env bash
# mcp-terra plugin launcher.
#
# The plugin's .mcp.json points Claude Code at THIS script. It loads the
# per-user config written by the one-time bootstrap, then execs the MCP server
# from the dedicated venv. Secrets are NEVER baked into the shared plugin — they
# live only in ~/.mcp-terra (mode 0600), exactly like the install.sh path.
set -euo pipefail

CFG="${HOME}/.mcp-terra/config.env"
VENV_PY="${HOME}/.mcp-terra/venv/bin/python"
HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -f "$CFG" ] || [ ! -x "$VENV_PY" ]; then
  cat >&2 <<EOF
[mcp-terra] Not bootstrapped yet — the venv + config are missing.

Run this ONCE (creates ~/.mcp-terra/venv, the runner secret, and config.env),
then restart Claude Code:

    bash "${HERE}/terra-bootstrap.sh" <namespace>/<workspace>

e.g.  bash "${HERE}/terra-bootstrap.sh" claussnitzer-fdp/your-workspace
EOF
  exit 1
fi

# Validate the config file BEFORE reading it: a regular file (not a symlink/
# device), owned by us, with no group/other access. We then PARSE allowlisted
# KEY=VALUE lines literally — we do NOT `source` it, so even a tampered value
# containing shell syntax cannot execute on launch.
[ -L "$CFG" ] && { echo "[mcp-terra] $CFG is a symlink — refusing." >&2; exit 1; }
[ -f "$CFG" ] || { echo "[mcp-terra] $CFG is not a regular file — refusing." >&2; exit 1; }
_own="$(stat -f '%u' "$CFG" 2>/dev/null || stat -c '%u' "$CFG" 2>/dev/null || echo -1)"
[ "$_own" = "$(id -u)" ] || { echo "[mcp-terra] $CFG not owned by you — refusing." >&2; exit 1; }
_mode="$(stat -f '%Lp' "$CFG" 2>/dev/null || stat -c '%a' "$CFG" 2>/dev/null || echo 000)"
case "$_mode" in
  600|400) : ;;
  *) echo "[mcp-terra] $CFG must be mode 0600 (is $_mode) — refusing." >&2; exit 1 ;;
esac

# Parse allowlisted keys literally and export them (no source/eval). `export
# "$k=$v"` assigns the value as a literal string — variable expansion does NOT
# recursively evaluate command substitution, so a value like $(cmd) is inert.
while IFS= read -r _line || [ -n "$_line" ]; do
  case "$_line" in ''|\#*) continue ;; esac
  _k="${_line%%=*}"; _v="${_line#*=}"
  case "$_k" in
    MCP_TERRA_ALLOW_WRITES|MCP_TERRA_WORKSPACE|MCP_TERRA_RUNNER_SECRET_FILE|\
    MCP_TERRA_RUNNER_CONCURRENCY|MCP_TERRA_MAX_RUN_HOURS|MCP_TERRA_SESSION_MARGIN_SEC|\
    MCP_TERRA_MAX_COST_USD|MCP_TERRA_VM_HOURLY_USD|MCP_TERRA_REQUESTER_PAYS_PROJECT|\
    MCP_TERRA_CONTROLLED_ACCESS|PATH|HOME)
      export "$_k=$_v" ;;
    *)
      echo "[mcp-terra] ignoring unrecognized config key: $_k" >&2 ;;
  esac
done < "$CFG"

exec "$VENV_PY" -m mcp_terra.server
