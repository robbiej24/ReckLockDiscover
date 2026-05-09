# Detection rules

Detectors are implemented as regular expressions & substring checks over file contents, plus filename-driven signals (for example GitHub Actions paths, `Dockerfile`, dependency manifests).

Signals carry:

- **name** — human-readable label  
- **category** — coarse grouping (`llm_ai`, `outbound`, `deploy_infra`, …)  
- **line_number** — first matching line when applicable  
- **redacted_snippet** — preview of the matching line after secret redaction  

## Categories

| Category id | Typical detectors |
| --- | --- |
| `llm_ai` | OpenAI/Anthropic/Google SDKs, LangChain/LangGraph, CrewAI, AutoGen, tool/function calling, agent frameworks |
| `outbound` | SMTP, SendGrid/Postmark/Resend/Mailgun, Slack/Discord/Twilio, generic webhooks |
| `browser_or_http` | Playwright/Selenium/Puppeteer/browser-use, `requests`/`httpx`/`aiohttp` |
| `deploy_infra` | Docker/kubectl/Helm/Terraform/Pulumi/cloud CLIs/paas CLIs, prod keywords |
| `database` | connection strings, ORMs, Redis/Firebase/Supabase, INSERT/UPDATE/DELETE heuristics |
| `payments_financial` | Stripe/Plaid/PayPal/Dwolla, banking keywords, money-movement verbs |
| `secrets` | API keys, tokens, bearer headers, credential filenames |
| `schedule` | cron, Celery/RQ, GitHub `schedule`, worker keywords |
| `shell_execution` | `subprocess`, `os.system`, Node `child_process` |
| `ci_cd` | GitHub Actions workflow bodies |
| `file_marker` | Dependency manifests (`package.json`, etc.) |

Dependency manifests (`package.json`, `pyproject.toml`, `requirements.txt`) receive additional signals when known SDK names appear in the blob.

## File coverage

Scannable paths include standard extensions (Python/TS/JS/YAML/JSON/TOML/shell), GitHub Actions workflows under `.github/workflows/`, `Dockerfile` variants, and compose files.

Large/binary files are skipped; each file is capped at 1 MiB of text.

See `agenttrust_scanner/detectors.py` for the authoritative pattern list.
