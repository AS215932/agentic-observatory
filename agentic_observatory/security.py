from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from fastapi import HTTPException, Request, Response, status

from agentic_observatory.config import Settings

SESSION_COOKIE = "obs_session"
CSRF_COOKIE = "obs_csrf_seed"


@dataclass(frozen=True)
class OperatorSession:
    actor_id: str
    csrf_seed: str
    expires_at: int


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _json_payload(data: dict[str, Any]) -> str:
    return _b64(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith("$argon2"):
        try:
            return PasswordHasher().verify(password_hash, password)
        except Argon2Error:
            return False
    return hmac.compare_digest(password_hash, password)


def make_session(actor_id: str, settings: Settings) -> tuple[str, OperatorSession]:
    expires_at = int(time.time()) + settings.session_ttl_seconds
    session = OperatorSession(actor_id=actor_id, csrf_seed=secrets.token_urlsafe(24), expires_at=expires_at)
    payload = _json_payload({"sub": session.actor_id, "csrf": session.csrf_seed, "exp": expires_at})
    return f"{payload}.{_sign(settings.session_secret, payload)}", session


def parse_session(cookie_value: str | None, settings: Settings) -> OperatorSession | None:
    if not cookie_value or "." not in cookie_value:
        return None
    payload, signature = cookie_value.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(settings.session_secret, payload)):
        return None
    try:
        data = json.loads(_unb64(payload))
        session = OperatorSession(
            actor_id=str(data["sub"]),
            csrf_seed=str(data["csrf"]),
            expires_at=int(data["exp"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if session.expires_at < int(time.time()):
        return None
    return session


def login_csrf_token(seed: str, settings: Settings) -> str:
    return _sign(settings.csrf_secret, f"login:{seed}")


def session_csrf_token(session: OperatorSession, settings: Settings) -> str:
    return _sign(settings.csrf_secret, f"session:{session.actor_id}:{session.csrf_seed}")


def set_session_cookie(response: Response, value: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        value,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.environment != "development",
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)


def ensure_login_csrf_cookie(request: Request, response: Response, settings: Settings) -> str:
    seed = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(24)
    response.set_cookie(
        CSRF_COOKIE,
        seed,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.environment != "development",
        samesite="strict",
    )
    return login_csrf_token(seed, settings)


def validate_login_csrf(request: Request, token: str, settings: Settings) -> None:
    seed = request.cookies.get(CSRF_COOKIE, "")
    expected = login_csrf_token(seed, settings) if seed else ""
    if not token or not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def current_session(request: Request, settings: Settings) -> OperatorSession | None:
    return parse_session(request.cookies.get(SESSION_COOKIE), settings)


def require_session(request: Request, settings: Settings) -> OperatorSession:
    session = current_session(request, settings)
    if session is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return session


async def form_csrf_token(request: Request) -> str:
    form = await request.form()
    raw = form.get("csrf_token")
    return str(raw or "")


async def validate_session_csrf(request: Request, session: OperatorSession, settings: Settings) -> None:
    token = request.headers.get("x-csrf-token") or await form_csrf_token(request)
    expected = session_csrf_token(session, settings)
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
