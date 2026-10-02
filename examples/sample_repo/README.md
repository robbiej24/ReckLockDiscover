# Sample repository

Tiny fixtures used to demonstrate ReckLock Discover reports in documentation.


<!-- hl-readme-agent:start -->
## Agent quick access

- New chat entry: `bash scripts/agent_task_entry.sh "<task>"` (from repo root).
- Monorepo agent map: [`AGENTS.md`](../../../../../../AGENTS.md).
- Stack pins: [`STACK_VERSIONS.md`](../../../../../../STACK_VERSIONS.md).
- Pytest: `scripts/run-pytest.sh` or package `.venv/bin/python -m pytest` (never bare Homebrew `python3 -m pytest`).
- AWS: agent shells use `AWS_PROFILE=hl-sso-ro` only; deploy/`hl-sso-admin` is human-only.

<!-- hl-readme-agent:end -->

<!-- hl-readme-stack:start -->
## Current stack versions

Direct dependencies from nearby manifests. Full monorepo inventory: [`STACK_VERSIONS.md`](../../../../../../STACK_VERSIONS.md). Regenerate with `python3 scripts/sync_readme_agent_sections.py`.

### `Core/ReckLockFamily/ReckLockShield/ReckLockDiscover/examples/sample_repo/package.json`

- Package name: `sample-repo`
- Kind: `npm`

| Package | Spec |
|---|---|
| `openai` | `^6.45.0` |
| `stripe` | `^22.3.0` |


<!-- hl-readme-stack:end -->
