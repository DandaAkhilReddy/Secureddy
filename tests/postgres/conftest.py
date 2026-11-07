"""A real PostgreSQL for the ``postgres`` tests, or a clean skip.

SQLite ignores ``VARCHAR(n)``, so the production bug where a mailbox cursor
overflowed ``VARCHAR(100)`` could not fail any SQLite test. These fixtures
give the tests the database production runs:

* ``RS_TEST_POSTGRES_URL`` (e.g. ``postgresql://postgres@localhost:5432/postgres``)
  points at a server you already have; each test gets its own database on it.
* Otherwise a throwaway cluster is started from the local PostgreSQL install
  (``initdb``/``pg_ctl`` on PATH or under ``/usr/lib/postgresql/*/bin``) in a
  temp directory, on a free port, with trust auth on 127.0.0.1 only. As root
  it runs as the ``postgres`` system user, since PostgreSQL refuses root.
* No asyncpg, no binaries, or a cluster that will not start: every
  ``postgres`` test is skipped with the reason.
"""

from __future__ import annotations

import asyncio
import glob
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.postgres


def _pg_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidates = sorted(glob.glob(f"/usr/lib/postgresql/*/bin/{name}"), key=lambda p: int(p.split("/")[4]))
    return candidates[-1] if candidates else None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _as_owner(cmd: list[str], owner: str | None) -> list[str]:
    return ["runuser", "-u", owner, "--", *cmd] if owner else cmd


@pytest.fixture(scope="session")
def postgres_admin_url() -> Iterator[str]:
    """``postgresql://`` URL of a server we may create databases on."""
    try:
        import asyncpg  # noqa: F401
    except ImportError:
        pytest.skip("asyncpg is not installed (pip install asyncpg)")
    external = os.environ.get("RS_TEST_POSTGRES_URL")
    if external:
        yield external.replace("postgresql+asyncpg://", "postgresql://")
        return
    initdb, pg_ctl = _pg_bin("initdb"), _pg_bin("pg_ctl")
    if not initdb or not pg_ctl:
        pytest.skip("no PostgreSQL server binaries (initdb/pg_ctl) and no RS_TEST_POSTGRES_URL")
    owner: str | None = None
    if os.geteuid() == 0:
        if not shutil.which("runuser"):
            pytest.skip("running as root without runuser; PostgreSQL will not start as root")
        try:
            pwd.getpwnam("postgres")
        except KeyError:
            pytest.skip("running as root and there is no 'postgres' user to run the server as")
        owner = "postgres"
    base = Path(tempfile.mkdtemp(prefix="rs-pg-"))
    if owner:
        shutil.chown(base, user=owner)
    data, port = base / "data", _free_port()
    try:
        subprocess.run(
            _as_owner([initdb, "-D", str(data), "-A", "trust", "-U", "postgres", "-E", "UTF8"], owner),
            check=True,
            capture_output=True,
            timeout=120,
        )
        options = f"-p {port} -k {base} -c listen_addresses=127.0.0.1 -c fsync=off"
        subprocess.run(
            _as_owner([pg_ctl, "-D", str(data), "-o", options, "-l", str(base / "log"), "-w", "start"], owner),
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        shutil.rmtree(base, ignore_errors=True)
        pytest.skip(f"could not start a local PostgreSQL: {exc}")
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(
            _as_owner([pg_ctl, "-D", str(data), "-m", "immediate", "stop"], owner),
            capture_output=True,
            timeout=60,
        )
        shutil.rmtree(base, ignore_errors=True)


async def _admin(admin_url: str, sql: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(admin_url)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest.fixture
async def pg_url(postgres_admin_url: str) -> Iterator[str]:
    """SQLAlchemy URL of a fresh, empty database for this test."""
    name = f"rs_{uuid.uuid4().hex[:12]}"
    await _admin(postgres_admin_url, f'CREATE DATABASE "{name}"')
    base = postgres_admin_url.rsplit("/", 1)[0]
    try:
        yield f"{base.replace('postgresql://', 'postgresql+asyncpg://', 1)}/{name}"
    finally:
        await asyncio.wait_for(_admin(postgres_admin_url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'), 60)


@pytest.fixture
async def pg_db(pg_url: str):
    """A ``Database`` on that fresh database, schema not created yet."""
    from reddysec.store.db import Database

    database = Database(pg_url)
    yield database
    await database.dispose()
