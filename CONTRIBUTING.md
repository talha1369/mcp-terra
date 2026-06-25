# Contributing to mcp-terra

Thanks for considering a contribution. This MCP touches irreplaceable lab
data and runs against live cloud spend — the bar for changes is high.
Please read this whole doc before opening a PR.

## Dev environment

```bash
git clone <repo-url>
cd mcp-terra

# Use a virtualenv (NEVER pip-install into the system Python).
python3.12 -m venv .venv
source .venv/bin/activate

# Install the locked dev/runtime dep set. --require-hashes refuses any
# wheel whose sha256 is not pinned in requirements.lock.
pip install --require-hashes -r requirements.lock

# Editable install of the package itself (no deps — already locked).
pip install --no-deps -e .

# CI-only audit / lint tools (versions match .github/workflows/ci.yml).
pip install "ruff==0.7.4" "pip-audit==2.7.3"
```

Confirm the package imports:

```bash
python -c "import mcp_terra.server; print('ok')"
```

## Running the security test suite

This is the gate every PR must pass. The same script runs in CI; you
should run it locally before pushing.

```bash
python tests/test_security_comprehensive.py
```

A passing run prints a summary line of the form `PASS / N total`. Any
failing assertion stops the run and prints the assertion that fired —
read the traceback, fix the underlying issue, re-run.

Lint:

```bash
ruff check src/ tests/
```

Dependency audit (offline-failing CVE check against pinned versions):

```bash
pip-audit --strict --requirement requirements.lock
```

## The invariants this codebase enforces

These are NOT just docstring suggestions — they are enforced in code,
and the security test suite verifies each one. If your change weakens
any of these, the PR will be rejected.

1. **No destruction primitive.** There is no `terra_delete_*`, no rm
   wrapper, no overwrite path. To delete anything, the user goes
   through the Terra UI or runs `gsutil rm` directly. Adding a delete
   tool is out of scope for this MCP — open an issue first if you think
   you need one.

2. **No overwrites.** Bucket uploads refuse if the destination object
   already exists. Local downloads refuse if the local destination
   already exists. Versioning (`version_existing=True`) preserves the
   prior file under a timestamped or `.BAK.` name — it never deletes.

3. **Local-path blocklist.** Tools refuse local paths under common
   credential locations (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
   `~/.azure`, `~/.netrc`, ADC json, etc.) and under system paths
   (`/etc/`, `/private/etc/`, `/System/`, `/usr/bin/`,
   `/Library/Keychains/`). Symlinks are resolved before the check.

4. **Workspace-bucket allowlist.** Bucket reads/writes are restricted
   to `gs://` URIs whose bucket the user has Terra access to. Arbitrary
   bucket access is refused.

5. **Audit trail.** Every tool invocation logs one line to stderr with
   the tool name, action class, and arg summary. No tool may execute
   without producing an audit line.

6. **Recipient lock on outbound email.** `terra_send_run_report_email`
   has NO `to` parameter — the recipient is the authenticated Terra
   user, full stop. This defeats data-exfil-via-email.

7. **Kill switch.** The file `~/.mcp-terra/KILL` aborts every tool call.
   The rate-of-refusals auto-trips the switch.

## Security disclosure

Do NOT open public GitHub issues for security findings. See
[SECURITY.md](SECURITY.md) for the disclosure protocol and contact
address. A 90-day coordinated-disclosure timeline applies.

## Branch / PR conventions

- Branch from `main`. Branch names: `feat/<short-desc>`,
  `fix/<short-desc>`, `docs/<short-desc>`, `chore/<short-desc>`.
- Keep PRs focused — one logical change per PR. Reviewers will ask
  you to split mixed PRs.
- Commits should be small and self-describing. Squash before merge
  unless the history is genuinely useful.
- PR description must include:
  - **What changed** and **why**.
  - **Threat model impact**: does this change affect any of the
    invariants above? If yes, explain how the change preserves them.
  - **How tested**: which security tests cover the change.
- CI must be green before merge. The `security-tests` job is required.

## Adding a tool

1. Implement the API call in `terra_client.py` (or `bucket.py` for
   gsutil ops). Keep network I/O in the client layer.
2. Add a `@server.tool()` wrapper in `server.py` with a docstring that
   tells the agent the action class (READ / WRITE-SAFE / SPEND) and
   whether it must confirm with the user first.
3. If the tool can mutate state or incur spend, gate it behind
   `MCP_TERRA_ALLOW_WRITES=1` and add at least one negative test in
   `tests/test_security_comprehensive.py` proving the gate works.
4. Update `docs/error_codes.md` if the tool can return a new structured
   error code, and `CHANGELOG.md` under `[Unreleased]`.

## Releasing

1. Bump `version` in `pyproject.toml` (semver).
2. Move `[Unreleased]` entries in `CHANGELOG.md` under a new
   `[X.Y.Z] — YYYY-MM-DD` heading.
3. Regenerate `requirements.lock`:
   ```bash
   python -m piptools compile --generate-hashes \
       --output-file=requirements.lock pyproject.toml
   ```
4. Tag: `git tag -s vX.Y.Z -m "vX.Y.Z"` (signed tags only).
5. Push tag; CI must be green.
