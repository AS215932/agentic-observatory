from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    Column("audit_id", String(80), primary_key=True),
    Column("actor_id", String(120), nullable=False),
    Column("action", String(120), nullable=False),
    Column("target_type", String(80), nullable=False),
    Column("target_id", String(180), nullable=False),
    Column("idempotency_key", String(180), nullable=False),
    Column("status", String(40), nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

idempotency_records = Table(
    "idempotency_records",
    metadata,
    Column("scope", String(120), primary_key=True),
    Column("key", String(180), primary_key=True),
    Column("actor_id", String(120), nullable=False),
    Column("result_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

cache_snapshots = Table(
    "cache_snapshots",
    metadata,
    Column("cache_key", String(180), primary_key=True),
    Column("payload_json", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


class ObservatoryStore:
    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    async def get_idempotency(self, scope: str, key: str) -> dict[str, Any] | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(idempotency_records.c.result_json).where(
                        idempotency_records.c.scope == scope,
                        idempotency_records.c.key == key,
                    )
                )
            ).first()
        return json.loads(str(row[0])) if row else None

    async def record_idempotency(
        self, *, scope: str, key: str, actor_id: str, result: dict[str, Any]
    ) -> None:
        async with self.session_factory() as session, session.begin():
            try:
                await session.execute(
                    insert(idempotency_records).values(
                        scope=scope,
                        key=key,
                        actor_id=actor_id,
                        result_json=json.dumps(result, sort_keys=True, default=str),
                        created_at=datetime.now(UTC),
                    )
                )
            except IntegrityError:
                await session.rollback()

    async def audit(
        self,
        *,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        idempotency_key: str,
        status: str,
        payload: dict[str, Any],
    ) -> str:
        audit_id = f"audit_{uuid4().hex}"
        async with self.session_factory() as session, session.begin():
            await session.execute(
                insert(audit_events).values(
                    audit_id=audit_id,
                    actor_id=actor_id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    idempotency_key=idempotency_key,
                    status=status,
                    payload_json=json.dumps(payload, sort_keys=True, default=str),
                    created_at=datetime.now(UTC),
                )
            )
        return audit_id

    async def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(
                    select(audit_events).order_by(audit_events.c.created_at.desc()).limit(limit)
                )
            ).mappings()
            return [dict(row) for row in rows]

    async def put_cache(self, key: str, payload: dict[str, Any]) -> None:
        existing = await self.get_cache(key)
        async with self.session_factory() as session, session.begin():
            payload_json = json.dumps(payload, sort_keys=True, default=str)
            if existing is None:
                await session.execute(
                    insert(cache_snapshots).values(
                        cache_key=key,
                        payload_json=payload_json,
                        updated_at=datetime.now(UTC),
                    )
                )
            else:
                await session.execute(
                    update(cache_snapshots)
                    .where(cache_snapshots.c.cache_key == key)
                    .values(payload_json=payload_json, updated_at=datetime.now(UTC))
                )

    async def get_cache(self, key: str) -> dict[str, Any] | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(cache_snapshots.c.payload_json).where(cache_snapshots.c.cache_key == key)
                )
            ).first()
        return json.loads(str(row[0])) if row else None
