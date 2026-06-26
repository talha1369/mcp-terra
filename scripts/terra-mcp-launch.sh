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

# Load config (KEY=VALUE lines) into the environment, then hand off.
set -a
# shellcheck disable=SC1090
. "$CFG"
set +a

exec "$VENV_PY" -m mcp_terra.server
