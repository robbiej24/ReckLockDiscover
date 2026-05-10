# ReckLock Discover Report

## Scan Summary

- **Scanner version:** `1.0.1`
- **Scanned path:** `examples/sample_repo`
- **Scanned at:** `2026-05-08T21:09:06Z`
- **Files scanned:** 4
- **Files with findings:** 4
- **Total findings:** 4

### Findings by type

| Bucket | Count |
| --- | --- |
| `ai_agent` | 1 |
| `deployment_workflow` | 1 |
| `payment_or_financial_workflow` | 1 |
| `scheduled_job` | 1 |

### Findings by risk

| Bucket | Count |
| --- | --- |
| `critical` | 1 |
| `high` | 2 |
| `medium` | 1 |

### Findings by recommended action

| Bucket | Count |
| --- | --- |
| `govern` | 1 |
| `register` | 3 |

## Critical Findings

- `package.json` — **payment_or_financial_workflow** (critical, high) → `govern` (`find_7ae45ad102ea`)

## High-Risk Findings

- `deploy/production.sh` — **deployment_workflow** (high, medium) → `register` (`find_48cdabc5d172`)
- `src/chat_agent.py` — **ai_agent** (high, medium) → `register` (`find_e70c699ec38e`)

## AI Agent Candidates

- `src/chat_agent.py` — **ai_agent** (high, medium) → `register` (`find_e70c699ec38e`)

## Deployment Workflows

- `.github/workflows/nightly.yml` — **scheduled_job** (medium, high) → `register` (`find_0d5658b41509`)
- `deploy/production.sh` — **deployment_workflow** (high, medium) → `register` (`find_48cdabc5d172`)

## Financial/Payment Workflows

- `package.json` — **payment_or_financial_workflow** (critical, high) → `govern` (`find_7ae45ad102ea`)

## Suggested Governance Targets

_Critical-risk automation that likely needs strict governance first._

- `package.json` — **payment_or_financial_workflow** (critical) → `govern` (`find_7ae45ad102ea`)

## Suggested ReckLock Registry Candidates

_Findings tagged **register** or **manual_review** — strong registry candidates after review._

- `.github/workflows/nightly.yml` — **scheduled_job** (medium) → `register` (`find_0d5658b41509`)
- `deploy/production.sh` — **deployment_workflow** (high) → `register` (`find_48cdabc5d172`)
- `src/chat_agent.py` — **ai_agent** (high) → `register` (`find_e70c699ec38e`)

## All findings

### `.github/workflows/nightly.yml` — Nightly

- finding_id: `find_0d5658b41509`
- finding_type: `scheduled_job`
- risk_level: **medium**
- confidence: `high`
- recommended_action: **register**
- likely_capabilities: `ci_pipeline`, `scheduled_execution`
- likely_permission_scopes: `ci.execute`, `repository.write`, `scheduler.trigger`
- rationale: _Classified as scheduled_job (high confidence) at risk=medium. Recommended action: register. Top signals: GitHub Actions schedule, GitHub Actions workflow body, GitHub Actions workflow file, cron / crontab._
- signals:
  - **GitHub Actions workflow file** (ci_cd, filename match)
  - **cron / crontab** (schedule, line 4) — `    - cron: "0 6 * * *"`
  - **GitHub Actions schedule** (schedule, line 2) — `on:`
  - **GitHub Actions workflow body** (ci_cd, line 9) — `      - uses: actions/checkout@v4`

### `deploy/production.sh` — Production

- finding_id: `find_48cdabc5d172`
- finding_type: `deployment_workflow`
- risk_level: **high**
- confidence: `medium`
- recommended_action: **register**
- likely_capabilities: `deploy_code`, `infrastructure_mutate`
- likely_permission_scopes: `infrastructure.write`, `production.deploy`
- rationale: _Classified as deployment_workflow (medium confidence) at risk=high. Recommended action: register. Top signals: aws CLI invocation, kubectl invocation._
- signals:
  - **kubectl invocation** (deploy_infra, line 3) — `kubectl apply -f ./k8s/`
  - **aws CLI invocation** (deploy_infra, line 4) — `aws ecs update-service --cluster prod --service api --force-new-deployment`

### `package.json` — Package

- finding_id: `find_7ae45ad102ea`
- finding_type: `payment_or_financial_workflow`
- risk_level: **critical**
- confidence: `high`
- recommended_action: **govern**
- likely_capabilities: `financial_data_access`, `initiate_payment`, `llm_inference`
- likely_permission_scopes: `ai.invoke`, `finance.read`, `payments.initiate`
- rationale: _Classified as payment_or_financial_workflow (high confidence) at risk=critical. Recommended action: govern. Top signals: Stripe SDK / API, dependency declares OpenAI SDK, dependency declares Stripe SDK, dependency manifest._
- signals:
  - **dependency manifest** (file_marker, filename match)
  - **dependency declares OpenAI SDK** (llm_ai, filename match)
  - **dependency declares Stripe SDK** (payments_financial, filename match)
  - **Stripe SDK / API** (payments_financial, line 6) — `    "stripe": "^14.0.0"`

### `src/chat_agent.py` — Chat Agent

- finding_id: `find_e70c699ec38e`
- finding_type: `ai_agent`
- risk_level: **high**
- confidence: `medium`
- recommended_action: **register**
- likely_capabilities: `agent_tool_calls`, `llm_inference`, `write_database`
- likely_permission_scopes: `ai.invoke`, `database.write`, `tools.invoke`
- rationale: _Classified as ai_agent (medium confidence) at risk=high. Recommended action: register. Top signals: database write operation, imports or calls OpenAI, tool calling / function calling._
- signals:
  - **imports or calls OpenAI** (llm_ai, line 3) — `from openai import OpenAI`
  - **tool calling / function calling** (llm_ai, line 11) — `    tool_choice="auto",`
  - **database write operation** (database, line 7) — `resp = client.chat.completions.create(`

---

_ReckLock Discover uses deterministic static analysis. Findings are educated guesses, not proof of behavior. Review high-risk paths manually before acting._
