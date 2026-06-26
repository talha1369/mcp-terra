# Slack post (internal — e.g. #terra / #data-science)

:rocket: *mcp-terra — run, fix & explain your Terra analyses from chat*

On your laptop, an AI coding assistant runs your code, reads the error, fixes it,
and runs again. On Terra it could only copy a notebook into your bucket — you
still had to size a VM, start it, run, and debug by hand.

*mcp-terra* closes that gap. Ask in plain English —
_“run my notebook end-to-end, auto-stop on success, email me the report”_ — and it:
• provisions the right-sized VM (CPU/GPU/RAM)
• runs the notebook and *auto-fixes* the bugs that come up, then re-runs
• emails you a *verified report + a short audio explainer* of the results and the fixes

Built safety-first for shared workspaces:
• *No delete or overwrite* primitive — anywhere
• Controlled-access guard (keeps data off external models; off by default)
• Spend cap — the VM self-stops before your $ limit — and 24h-session aware
• Parallel jobs: multiple VMs, WDL scatter, and multiple jobs per VM
• 382 passing security tests across 52 attack classes

One-command install (plugin or script); works with any MCP-aware assistant.
:point_right: Repo + 5-min demo deck: <link> · questions welcome in-thread :thread:
