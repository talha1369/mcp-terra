<!-- Thanks for contributing to mcp-terra. Keep the safety model intact. -->

## What & why

<!-- One or two sentences. Link any related issue (#123). -->

## Changes

-

## Safety checklist

- [ ] No new delete / destroy / abort / overwrite primitive at any layer
      (the no-destruction invariant is enforced by tests — keep it that way).
- [ ] Any new tool declares a correct action class (READ / WRITE-SAFE / SPEND)
      and `ToolAnnotations`, and routes through `_pre(...)`.
- [ ] No secrets, tokens, or credentials added to the repo (the
      `detect-secrets` gate must stay green).
- [ ] Docs updated if the tool surface or counts changed
      (`terra_health` `tools_count`, README, SECURITY.md).

## Verification

- [ ] `python tests/test_security_comprehensive.py` → all pass
- [ ] `ruff check src/ tests/` → clean
- [ ] `pip-audit --strict --requirement requirements.lock` → clean
