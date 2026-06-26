#!/usr/bin/env bash
# mcp-terra plugin bootstrap — one-time, idempotent.
#
# Wraps install.sh in PLUGIN MODE: it provisions the venv + deps + runner secret,
# verifies your Terra workspace, and writes ~/.mcp-terra/config.env — but does
# NOT run `claude mcp add` (the plugin's .mcp.json already registers the server
# via terra-mcp-launch.sh). Run once, then restart Claude Code.
#
# Usage:
#   bash terra-bootstrap.sh                       # interactive (asks for workspace)
#   bash terra-bootstrap.sh namespace/workspace   # non-interactive
set -euo pipefail

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL="$HERE/../install.sh"

[ -f "$INSTALL" ] || {
  echo "[mcp-terra] cannot find install.sh next to the plugin (looked at $INSTALL)" >&2
  exit 1
}

MCP_TERRA_PLUGIN_MODE=1 exec bash "$INSTALL" "$@"
