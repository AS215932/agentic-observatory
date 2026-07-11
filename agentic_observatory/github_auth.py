"""GitHub organization OAuth authentication and role mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from agentic_observatory.config import Settings


class GitHubOAuthError(RuntimeError):
    """Authentication failed closed at a GitHub organization gate."""


@dataclass(frozen=True)
class GitHubOperator:
    user_id: int
    login: str
    role: str


class GitHubOAuthClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport

    def authorization_url(self, *, state: str, code_challenge: str) -> str:
        query = urlencode(
            {
                "client_id": self.settings.github_oauth_client_id,
                "redirect_uri": self.settings.github_callback_url,
                "scope": "read:user read:org",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"https://github.com/login/oauth/authorize?{query}"

    async def authenticate(self, *, code: str, code_verifier: str) -> GitHubOperator:
        timeout = self.settings.request_timeout_seconds
        async with httpx.AsyncClient(timeout=timeout, transport=self.transport) as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.settings.github_oauth_client_id,
                    "client_secret": self.settings.github_oauth_client_secret,
                    "code": code,
                    "redirect_uri": self.settings.github_callback_url,
                    "code_verifier": code_verifier,
                },
            )
            token_response.raise_for_status()
            token = str(token_response.json().get("access_token") or "")
            if not token:
                raise GitHubOAuthError("GitHub did not issue an OAuth token")
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2026-03-10",
            }
            user = await self._json(client, "/user", headers)
            login = str(user.get("login") or "")
            user_id = int(user.get("id") or 0)
            if not login or not user_id:
                raise GitHubOAuthError("GitHub user identity is incomplete")

            organization = self.settings.github_oauth_org
            membership = await self._json(
                client, f"/user/memberships/orgs/{organization}", headers
            )
            if membership.get("state") != "active":
                raise GitHubOAuthError(f"active {organization} membership is required")

            if self.settings.github_oauth_require_org_2fa:
                if not self.settings.github_oauth_policy_token:
                    raise GitHubOAuthError(
                        "GitHub organization 2FA verification token is not configured"
                    )
                policy_headers = {
                    **headers,
                    "Authorization": f"Bearer {self.settings.github_oauth_policy_token}",
                }
                org = await self._json(
                    client, f"/orgs/{organization}", policy_headers
                )
                if org.get("two_factor_requirement_enabled") is not True:
                    raise GitHubOAuthError(
                        f"{organization} must enforce two-factor authentication"
                    )

            if membership.get("role") == "admin":
                role = "senior"
            else:
                team_path = (
                    f"/orgs/{organization}/teams/"
                    f"{self.settings.github_oauth_ops_team_slug}/memberships/{login}"
                )
                team_response = await client.get(
                    f"https://api.github.com{team_path}", headers=headers
                )
                if team_response.status_code != 200:
                    raise GitHubOAuthError(
                        f"membership in {organization}/{self.settings.github_oauth_ops_team_slug} "
                        "is required"
                    )
                team = self._mapping(team_response.json())
                if team.get("state") != "active":
                    raise GitHubOAuthError("GitHub operations team membership is not active")
                role = "operator"
        return GitHubOperator(user_id=user_id, login=login, role=role)

    async def _json(
        self, client: httpx.AsyncClient, path: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        response = await client.get(f"https://api.github.com{path}", headers=headers)
        if response.status_code != 200:
            raise GitHubOAuthError(f"GitHub organization gate failed at {path}")
        return self._mapping(response.json())

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise GitHubOAuthError("GitHub returned an invalid response")
        return value
