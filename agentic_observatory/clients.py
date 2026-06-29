from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import AnyHttpUrl


def _canonical_json(body: Any) -> str:
    return json.dumps(body if body is not None else {}, sort_keys=True, separators=(",", ":"), default=str)


def build_loop_signature(*, secret: str, method: str, path: str, timestamp: str, body: Any) -> str:
    message = "\n".join([method.upper(), path, timestamp, _canonical_json(body)]).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


class CollectorClient:
    def __init__(self, base_url: AnyHttpUrl | str | None, *, timeout: float = 10.0) -> None:
        self.base_url = str(base_url).rstrip("/") if base_url else ""
        self.timeout = timeout

    async def _get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        if not self.base_url:
            return {} if path not in {"/v1/loops", "/v1/runs", "/v1/actions"} else []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}{path}", params=dict(params or {}))
            response.raise_for_status()
            return response.json()

    async def loops(self) -> list[dict[str, Any]]:
        data = await self._get("/v1/loops")
        return list(data.get("loops", data) if isinstance(data, dict) else data)

    async def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        data = await self._get("/v1/runs", {"limit": limit})
        return list(data.get("runs", data) if isinstance(data, dict) else data)

    async def run(self, run_id: str) -> dict[str, Any]:
        data = await self._get(f"/v1/runs/{run_id}")
        return dict(data.get("run", data) if isinstance(data, dict) else {})

    async def run_events(self, run_id: str) -> list[dict[str, Any]]:
        data = await self._get(f"/v1/runs/{run_id}/events")
        return list(data.get("events", data) if isinstance(data, dict) else data)

    async def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        data = await self._get("/v1/actions", {"limit": limit})
        return list(data.get("actions", data) if isinstance(data, dict) else data)

    async def topology(self) -> dict[str, Any]:
        data = await self._get("/v1/topology")
        return dict(data) if isinstance(data, dict) else {"nodes": [], "edges": []}

    async def daily_metrics(self) -> list[dict[str, Any]]:
        data = await self._get("/v1/metrics/daily")
        return list(data.get("metrics", data) if isinstance(data, dict) else data)


class NOCClient:
    def __init__(self, base_url: AnyHttpUrl | str | None, secret: str, *, timeout: float = 10.0) -> None:
        self.base_url = str(base_url).rstrip("/") if base_url else ""
        self.secret = secret
        self.timeout = timeout

    def _headers(self, method: str, path: str, body: Any) -> dict[str, str]:
        timestamp = datetime.now(UTC).isoformat()
        signed_path = path.split("?", 1)[0]
        return {
            "x-noc-loop-identity": "observatory",
            "x-noc-loop-timestamp": timestamp,
            "x-noc-loop-signature": build_loop_signature(
                secret=self.secret, method=method, path=signed_path, timestamp=timestamp, body=body
            ),
        }

    async def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        if not self.base_url or not self.secret:
            return {"status": "disabled", "enabled": False}
        payload = body if body is not None else {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(
                method,
                f"{self.base_url}{path}",
                json=payload if method != "GET" else None,
                headers=self._headers(method, path, payload),
            )
            response.raise_for_status()
            return response.json()

    async def health(self) -> dict[str, Any]:
        return dict(await self._request("GET", "/loop-console/v1/health"))

    async def cases(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        path = f"/loop-console/v1/cases?limit={limit}"
        if status:
            path += f"&status={status}"
        data = await self._request("GET", path)
        return list(data.get("cases", []) if isinstance(data, dict) else [])

    async def case_detail(self, case_id: str) -> dict[str, Any]:
        return dict(await self._request("GET", f"/loop-console/v1/cases/{case_id}"))

    async def case_timeline(self, case_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/loop-console/v1/cases/{case_id}/timeline")
        return list(data.get("timeline", []) if isinstance(data, dict) else [])

    async def handoffs(self, case_id: str | None = None) -> list[dict[str, Any]]:
        if case_id:
            data = await self._request("GET", f"/loop-console/v1/cases/{case_id}/handoffs")
        else:
            cases = await self.cases(limit=100)
            handoffs: list[dict[str, Any]] = []
            for case in cases:
                case_id_value = str(case.get("case_id") or "")
                if case_id_value:
                    handoffs.extend(await self.handoffs(case_id_value))
            return handoffs
        return list(data.get("handoffs", []) if isinstance(data, dict) else [])

    async def verification_objectives(self, case_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/loop-console/v1/cases/{case_id}/verification-objectives")
        return list(data.get("verification_objectives", []) if isinstance(data, dict) else [])

    async def knowledge_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/loop-console/v1/cases/{case_id}/knowledge-artifacts")
        return list(data.get("knowledge_artifacts", []) if isinstance(data, dict) else [])

    async def outbox(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/loop-console/v1/outbox")
        return list(data.get("outbox", []) if isinstance(data, dict) else [])

    async def post_action(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return dict(await self._request("POST", path, body))


class GitHubClient:
    def __init__(self, token: str = "", *, timeout: float = 10.0) -> None:
        self.token = token
        self.timeout = timeout

    async def pull_request(self, repository: str, number: int) -> dict[str, Any]:
        if not self.token or not repository or not number:
            return {}
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            response = await client.get(f"https://api.github.com/repos/{repository}/pulls/{number}")
            response.raise_for_status()
            return dict(response.json())
