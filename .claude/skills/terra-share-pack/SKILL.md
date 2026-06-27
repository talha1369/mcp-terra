---
name: terra-share-pack
description: Generate a share-pack (tarball + onboarding note) for a lab member or collaborator who wants to install mcp-terra. Bundles the repo, generates a personalized README with one-time setup steps, and explicitly DOES NOT include any secrets.
argument-hint: [colleague_name] [optional_output_dir]
allowed-tools: Bash, Read, Write
disable-model-invocation: true
---

# terra-share-pack

The user wants to share their mcp-terra install with a colleague. This
skill creates a clean tarball + a personalized cover note. **It must
not include the user's runner secret, gcloud credentials, audit log,
reports dir, or any other personal state.**

**Arguments:** `$ARGUMENTS` — typically `<colleague_name> [output_dir]`

If no colleague name was given, ask once. Default `output_dir` to
`~/Downloads/`.

## Step 1: confirm working tree is clean

```bash
cd /Users/trehman/projects/mcp-terra
git status --porcelain 2>&1 | head -10
```

If there are uncommitted changes, ASK the user whether to:
(a) commit them first (recommended),
(b) include them in the pack as-is (warn that lab review of unmerged
changes is harder), or
(c) abort.

## Step 2: assemble the bundle

Create a tarball with ONLY these paths — explicitly NOT the runtime state:

```bash
TS="$(date +%Y%m%d-%H%M%S)"
PACK="${OUTPUT_DIR:-$HOME/Downloads}/mcp-terra-share-${TS}.tar.gz"

cd /Users/trehman/projects/mcp-terra
tar -czf "$PACK" \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='*.pyc' \
    --exclude='.ruff_cache' \
    --exclude='.mypy_cache' \
    --exclude='.pytest_cache' \
    --exclude='*.egg-info' \
    src/ tests/ pyproject.toml requirements.lock \
    Dockerfile README.md SECURITY.md SOP.md CHANGELOG.md \
    CONTRIBUTING.md docs/ .claude/skills/ .github/

echo "Pack: $PACK ($(du -h "$PACK" | cut -f1))"
```

Sanity-check the pack contains no secrets:

```bash
tar -tzf "$PACK" | grep -iE '\.env|secret|credential|\.mcp-terra' && echo "WARNING: pack contains suspect path"
```

If anything matches, STOP and remove those paths.

## Step 3: write the personalized cover note

Write `<output_dir>/mcp-terra-share-<ts>-ONBOARDING.md` containing:

```markdown
# Onboarding pack for: <colleague_name>

This is the mcp-terra v0.2.0 share-pack from <user's name>.

## Quick start (≈10 minutes)

1. **Extract**
   ```
   mkdir -p ~/projects && cd ~/projects
   tar -xzf <path-to-pack>.tar.gz
   mv mcp-terra mcp-terra-from-<user>      # rename to avoid collision
   ```

2. **Install** (pinned lockfile — reproducible)
   ```
   cd mcp-terra-from-<user>
   pip install -r requirements.lock --require-hashes
   pip install -e .
   ```

3. **Authenticate as YOUR Terra user**
   ```
   gcloud auth application-default login
   gcloud config get-value account  # must be your Terra email
   ```

4. **Generate YOUR OWN runner secret** (DO NOT reuse the sender's)
   ```
   python -c 'import secrets; print(secrets.token_urlsafe(32))'
   # → save this; you'll use it in step 5
   ```

5. **Set env vars** in your shell rc:
   ```
   export MCP_TERRA_ALLOW_WRITES=1
   export MCP_TERRA_WORKSPACE='<your-namespace>/<your-workspace>'
   export MCP_TERRA_RUNNER_SECRET='<the secret you just generated>'
   ```

6. **Wire into Claude Code** — see SOP.md § 2.5

7. **Verify** — run the `/terra-setup-check` skill or ask Claude:
   > *"Run terra_health"*

   You should see writes_allowed:true and your workspace lock set.

8. **Start the on-VM runner** (per VM session) — see SOP.md § 3.

## Reading order

- `SOP.md` — the full daily-workflow runbook
- `SECURITY.md` — threat model + how the no-destruction guarantees hold
- `docs/error_codes.md` — what the structured error envelope means
- `README.md` — reference docs for all 45 tools
- `CHANGELOG.md` — what each release added

## Skills shipped with this MCP

- `/terra-setup-check` — first thing to run after install
- `/terra-bugfix-loop` — canonical auto-fix workflow
- `/terra-share-pack` — share with the NEXT colleague

## Questions

The threat model + no-destruction invariants are deliberately strong.
If you find a way around any guarantee, that's a security issue worth
reporting — see SECURITY.md for the disclosure process.

— sent by <user>
```

## Step 4: verify pack contents one more time

```bash
echo "=== Pack contents (top 30) ==="
tar -tzf "$PACK" | head -30
echo
echo "=== Sanity (no secrets) ==="
tar -tzf "$PACK" | grep -ciE 'KILL|audit\.log|reports/|\.env' || echo "clean"
echo
echo "=== Size ==="
ls -lh "$PACK"
```

## Step 5: surface to the user

Print the final paths and tell the user how to send it:
- Path to the tarball
- Path to the onboarding note
- Suggestion: send via Slack DM / email / Google Drive (whatever's normal
  in their workflow). Do NOT recommend public file shares.

DO NOT actually send anything — the user does the delivery themselves.

## Hard rules

- NEVER include `.mcp-terra/` (audit log + reports + KILL file)
- NEVER include `~/.config/gcloud/` (ADC credentials)
- NEVER include the user's `MCP_TERRA_RUNNER_SECRET` — the colleague
  generates their own
- NEVER include uncommitted changes without explicit user OK
