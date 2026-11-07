"""Engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from reddysec.config import get_settings

from .migrations import migrate
from .models import Base


class Database:
    def __init__(self, url: str, *, echo: bool = False, **engine_kwargs: Any):
        """``engine_kwargs`` go to ``create_async_engine`` (tests pass
        ``poolclass=NullPool`` to use one database from two event loops)."""
        self.url = url
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args = {"timeout": 30}
        self.engine: AsyncEngine = create_async_engine(url, echo=echo, connect_args=connect_args, **engine_kwargs)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    async def create_all(self) -> list[str]:
        """Create missing tables and apply pending schema upgrades
        (``store.migrations``): idempotent and safe to run from several
        processes at once. Returns a line per change made."""
        return await migrate(self.engine)

    async def drop_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as s:
            try:
                yield s
                await s.commit()
            except BaseException:
                await s.rollback()
                raise

    async def dispose(self) -> None:
        await self.engine.dispose()


_db: Database | None = None


def get_database() -> Database:
    global _db
    if _db is None:
        _db = Database(get_settings().database_url)
    return _db


def set_database(db: Database | None) -> None:
    """Tests inject an in-memory database here."""
    global _db
    _db = db
