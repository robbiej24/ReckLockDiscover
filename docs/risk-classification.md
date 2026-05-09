# Risk classification

Classification is **rule-based**: each file yields many `ScannerSignal` rows; `classifiers.classify_finding` merges them into one `ScannerFinding` with:

- `finding_type` — workflow shape (AI agent, CI/CD, deployment, …)  
- `confidence` — `low` / `medium` / `high` based on signal diversity & count  
- `risk_level` — `low` → `critical` via monotonic bumps from category combinations  
- `recommended_action` — `monitor`, `register`, `govern`, or `manual_review`  

## Finding types

Examples include `ai_agent`, `llm_tool`, `ci_cd_workflow`, `deployment_workflow`, `payment_or_financial_workflow`, `browser_agent`, `database_writer`, `shell_execution_workflow`, `secret_using_workflow`, and `unknown`.

Workflow YAML under `.github/workflows/` becomes `deployment_workflow` when deploy signals are present; otherwise scheduled workflows become `scheduled_job`, and generic pipelines become `ci_cd_workflow`.

## Risk ladder

Starting from `low`, risk bumps upward when signals indicate:

- Browser/HTTP, LLM usage, schedules, CI/CD bodies, secret references, or `DATABASE_URL`-style strings → at least **medium** for some combinations  
- Outbound comms, shell execution, database writes, deploy/infra tooling, or LLM tool calling → often **high**  
- Payments combined with money-movement indicators or database writes, deploy + secrets, or deploy + shell + secrets → often **critical**  

Exact merging rules live in `agenttrust_scanner/classifiers.py`.

## Recommended actions

| Risk | Confidence | Typical action |
| --- | --- | --- |
| `critical` | any | `govern` (unless confidence is `low` with conflicting signals → `manual_review`) |
| `high` | `low` | `manual_review` |
| `high` | `medium`/`high` | `register` |
| `medium` | `high` | `register` |
| `medium` | lower | `monitor` |
| `low` | any | `monitor` |

These labels are **planning hints**, not automated enforcement.
