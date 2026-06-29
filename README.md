# AS215932 Agentic Observatory

Internal operator-only progressive server-rendered console for active Agentic Loops, CaseService/LHP-v1 state, Agent-Core trace replay, Knowledge artifacts, verification objectives, and balanced change-impact analysis.

## Routes

Canonical no-JS routes: `/`, `/loops`, `/loops/{loop_id}`, `/cases`, `/cases/{case_id}`, `/handoffs`, `/runs`, `/runs/{run_id}`, `/knowledge`, `/knowledge/artifacts/{artifact_id}`, `/verification`, `/changes`, `/changes/{change_key}`, `/analysis`, `/login`, `/logout`.

Visualization JSON routes: `/api/loops/topology`, `/api/cases/{case_id}/timeline`, `/api/runs/{run_id}/replay`, `/api/changes/{change_key}/impact`.

## Security model

- Operator session cookie: HttpOnly, Secure outside development, SameSite=Strict, 12h TTL.
- Password verification supports Vault-stored Argon2 hashes via `OBSERVATORY_OPERATOR_PASSWORD_HASH`.
- Every POST validates CSRF and records audit/idempotency state.
- NOC CaseService actions are signed with `OBSERVATORY_NOC_LOOP_CONSOLE_SECRET`.
- Actions stay disabled unless `OBSERVATORY_ACTIONS_ENABLED=true` and `OBSERVATORY_READ_ONLY=false`.

## Local development

```sh
uv sync --group dev
OBSERVATORY_ENVIRONMENT=development \
OBSERVATORY_OPERATOR_PASSWORD_HASH=secret \
uv run uvicorn agentic_observatory.app:app --reload --port 8780
```

Optional frontend island build:

```sh
npm install
npm run typecheck
npm run build
```
