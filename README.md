# AS215932 Agentic Observatory

Internal operator-only progressive server-rendered console for active Agentic Loops, organization-wide LHP-v2 coordinator state, Agent-Core trace replay, Knowledge artifacts, verification objectives, and balanced change-impact analysis. During migration it can fall back to the legacy NOC CaseService projection, but the coordinator is the target system of record for cross-loop cases, handoffs, leases, approvals, results, and verification.

## Routes

Canonical no-JS routes: `/`, `/loops`, `/loops/{loop_id}`, `/cases`, `/cases/{case_id}`, `/handoffs`, `/approvals`, `/runs`, `/runs/{run_id}`, `/knowledge`, `/knowledge/artifacts/{artifact_id}`, `/verification`, `/changes`, `/changes/{change_key}`, `/analysis`, `/login`, `/logout`.

Visualization JSON routes: `/api/loops/topology`, `/api/cases/{case_id}/timeline`, `/api/runs/{run_id}/replay`, `/api/changes/{change_key}/impact`.

## Security model

- Operator session cookie: HttpOnly, Secure outside development, SameSite=Strict, 12h TTL.
- Production authentication uses GitHub OAuth for the configured organization. An active organization membership and organization-enforced 2FA are required; members of the `ops` team receive `operator`, while organization owners receive `senior`.
- OAuth state is signed and short-lived, authorization uses PKCE, and the GitHub access token is discarded after the membership/role checks.
- Password verification supports Vault-stored Argon2 hashes for development or explicit break-glass rollout only. Local login is disabled in production by default.
- Every POST validates CSRF and records audit/idempotency state.
- NOC CaseService actions are signed with `OBSERVATORY_NOC_LOOP_CONSOLE_SECRET`.
- LHP-v2 reads and decisions are signed as the dedicated `observatory` identity. An approval is bound to the immutable handoff scope hash and expires; senior-tier work cannot be approved by an operator.
- Actions stay disabled unless `OBSERVATORY_ACTIONS_ENABLED=true` and `OBSERVATORY_READ_ONLY=false`.

Minimum production authentication and coordination settings:

```sh
OBSERVATORY_GITHUB_OAUTH_CLIENT_ID=... \
OBSERVATORY_GITHUB_OAUTH_CLIENT_SECRET=... \
OBSERVATORY_GITHUB_OAUTH_POLICY_TOKEN=... \
OBSERVATORY_GITHUB_OAUTH_ORG=AS215932 \
OBSERVATORY_GITHUB_OAUTH_OPS_TEAM_SLUG=ops \
OBSERVATORY_GITHUB_OAUTH_REQUIRE_ORG_2FA=true \
OBSERVATORY_COORDINATOR_BASE_URL=http://127.0.0.1:8771 \
OBSERVATORY_COORDINATOR_KEY_ID=v1 \
OBSERVATORY_COORDINATOR_SECRET=... \
agentic-observatory
```

The user OAuth credential only requests `read:user read:org`. GitHub restricts the organization 2FA field to organization-owner credentials, so `OBSERVATORY_GITHUB_OAUTH_POLICY_TOKEN` is a separate Vault-rendered fine-grained token owned by an organization owner and used only for the read-only organization-policy check. Missing or false 2FA policy fails closed. Handoff controls are separately staged through `OBSERVATORY_ENABLED_ACTIONS=handoff_approval,handoff_cancel`; read-only shadow deployment leaves those actions off.

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
