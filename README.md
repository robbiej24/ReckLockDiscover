# ReckLock Discover

**Find the AI agents, automations, CI/CD workflows, deployment scripts, and sensitive execution paths already hiding in your codebase.**

ReckLock Discover is a **standalone**, **offline** static analyzer. It does not call remote APIs, does not upload your source code, and does not phone home. Run it locally from the CLI and get JSON & Markdown reports you can paste into GitHub issues or attach to security reviews.

---

## Why agent discovery matters

Repos accumulate autonomous workflows quickly: Slack bots, coding assistants, deploy scripts, Stripe handlers, nightly cron jobs, LLM calls from CI, browser automation against vendor portals. Most teams never inventory these paths. Without an inventory:

- New automation ships without review.
- Risky capabilities (deploy, payments, database writes) pile up unnoticed.
- Incident response slows because nobody knows what runs where.

ReckLock Discover produces a **deterministic catalog** of candidate workflows so security & platform teams can prioritize governance work — even if you never adopt any other ReckLock suite product.

---

## Example terminal output

After installation:

```bash
recklock-discover scan /path/to/repo
```

You’ll see a short Rich summary (risk & recommended-action counts), plus paths to the JSON & Markdown reports. Use `--format json` to stream the full report object to stdout for piping into other tools.

---

## Install

**Requirements:** Python 3.11+

From PyPI (once published):

```bash
pip install recklock-discover
```

From a checkout:

```bash
pip install -e ".[dev]"
```

The CLI entrypoint is **`recklock-discover`**.

---

## Quick start

```bash
recklock-discover scan .
recklock-discover scan ~/repos/my-project
recklock-discover scan . --output-dir reports/
recklock-discover scan . --format json
recklock-discover scan . --min-confidence medium
recklock-discover scan . --add-to-registry
recklock-discover scan . --export-manifests
```

Common flags:

| Flag | Purpose |
| --- | --- |
| `--output-dir`, `-o` | Where to write `recklock_discover_scan_report.json` & `.md` (default: cwd) |
| `--format`, `-f` | `human` (default) or `json` (full report on stdout) |
| `--min-confidence` | `low` \| `medium` \| `high` — drop lower-confidence findings |
| `--include` | Comma-separated globs (e.g. `*.py,.github/workflows/*.yml`) |
| `--exclude` | Extra directory names or globs to skip |
| `--add-to-registry` / `--skip-registry` | Opt in or out of writing draft ReckLock Registry manifests after discovery |
| `--export-manifests` | Emit draft YAML manifests under `recklock_manifest_exports/` |
| `--manifest-dir` | Override manifest export directory |

---

## Example scan report

Reports include:

- **Scan Summary** — counts by type, risk, and recommended action  
- **Critical Findings** & **High-Risk Findings**  
- **AI Agent Candidates** — LLM surfaces & agent-shaped code paths  
- **Deployment Workflows** — CI/CD, schedules, Docker & infra signals  
- **Financial/Payment Workflows** — payments & money-movement heuristics  
- **Suggested Governance Targets** — critical paths worth tight controls  
- **Suggested ReckLock Registry Candidates** — findings suited for registration review  
- **All findings** — every file-level finding with redacted snippets  

See `examples/sample_scan_report.md` & `examples/sample_scan_report.json` in this repository.

---

## Supported detections (overview)

| Area | Examples |
| --- | --- |
| LLM / AI | OpenAI, Anthropic, Gemini/Vertex, LangChain/LangGraph, CrewAI, AutoGen, tool calling |
| Outbound comms | SMTP, Slack/Discord/Twilio, webhooks |
| Browser / HTTP | Playwright, Selenium, Puppeteer, requests/httpx/aiohttp |
| Deploy / infra | Docker, kubectl, Terraform, Pulumi, AWS/GCP/Azure CLIs, Vercel/Netlify/Railway/Fly.io |
| Datastores | SQLAlchemy/Prisma/Supabase/Firebase/Redis, `DATABASE_URL`, INSERT/UPDATE/DELETE heuristics |
| Payments | Stripe/Plaid/PayPal/Dwolla & money-movement verbs |
| Secrets | API keys, tokens, bearer headers, high-entropy literals |
| Scheduling | cron, Celery, GitHub `schedule`, workers |
| Shell | `subprocess`, `os.system`, Node `child_process` |
| CI/CD | `.github/workflows/*.yml` |

Supported file kinds include `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, shell scripts, `.yaml`/`.yml`, `Dockerfile`, `package.json`, `pyproject.toml`, `requirements.txt`, and GitHub Actions workflows.

See **[docs/detection-rules.md](docs/detection-rules.md)** for the full rule catalog.

---

## Manifest export (`--export-manifests`)

When enabled, the scanner writes **unsigned** YAML manifests compatible with **[ReckLock Registry](https://github.com/robbiej24/ReckLockRegistry)** import flows — one file per eligible finding (`register`, `govern`, or `manual_review` recommendations).

For local human runs, ReckLock Discover can also ask whether you want to take the next step:

> ReckLock Discover found 6 AI agents. Add them to your ReckLock Registry so you can display:
>
> - That you own them
> - What their capabilities are
> - Which risks they carry &
> - Allow other people who want to license your agents to contact you?

Choosing yes writes the same draft manifests as `--export-manifests`. Non-interactive runs and JSON output never prompt; use `--add-to-registry` to opt in explicitly or `--skip-registry` to skip.

Default output directory:

```
recklock_manifest_exports/
```

Treat these as **drafts**: edit names, scopes, & risk before publishing. See **[docs/manifest-export.md](docs/manifest-export.md)**.

---

## Security & privacy guarantees

- **No network calls** — analysis is local filesystem + regex/heuristics only.  
- **No telemetry** — the scanner does not send usage data anywhere.  
- **No secret leakage in reports** — snippets pass through redaction for keys, bearer tokens, private key blocks, & high-entropy strings.  
- **Static analysis only** — no runtime hooks, no enforcement, no approvals engine.

---

## Relationship to ReckLock Registry

ReckLock Discover is useful **on its own** for visibility & inventory. If you use **ReckLock Registry**, exported manifests are a fast way to seed `registry/discovered/` after human review (see Registry docs for `import-scan-manifests`-style workflows).

---

## Roadmap (ideas)

- Additional language surfaces (Go, Ruby, JVM) where demand exists  
- Optional SARIF export for CI dashboards  
- Community-contributed detector packs  

---

## GitHub Actions

Run a **manual** scan from the **Actions** tab with the **ReckLock Discover** workflow: it checks out a **pinned release tag** (default **`v1.0.1`**), runs the same offline scanner as the CLI, & uploads **JSON & Markdown** reports as an artifact.

- **Full guide:** **[docs/github-actions.md](docs/github-actions.md)** — how to run it (UI & CLI), what each step does, permissions, & risks (artifacts, heuristics, fork behavior).
- **Quick context:** open `.github/workflows/recklock-discover.yml` in this repo for header comments & pointers.

---

## Documentation

- **[GitHub Actions workflow](docs/github-actions.md)** — manual workflow: usage, behavior, risks & trust  
- **[Architecture](docs/architecture.md)** — how the scanner is structured  
- **[Detection rules](docs/detection-rules.md)** — signal catalog  
- **[Risk classification](docs/risk-classification.md)** — how findings become risk & actions  
- **[Manifest export](docs/manifest-export.md)** — YAML draft format  

---

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check recklock_scanner tests
ruff format --check recklock_scanner tests
```

---

## License

MIT — see [LICENSE](LICENSE).
