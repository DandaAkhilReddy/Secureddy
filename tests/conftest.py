"""Shared fixtures. Keep the environment deterministic and offline."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("RS_ENV", "test")
os.environ.setdefault("RS_INTEL_ONLINE", "false")
os.environ.setdefault("RS_DEV_LOGIN_ENABLED", "true")
os.environ.setdefault("RS_SANDBOX_BACKEND", "local")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_env(tmp_path, monkeypatch):
    """Point artifacts and the database at a temp directory and reset settings."""
    from reddysec.config import reset_settings_cache

    monkeypatch.setenv("RS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("RS_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    reset_settings_cache()
    yield tmp_path
    reset_settings_cache()


@pytest.fixture
def artifact_store(tmp_path):
    from reddysec.core.artifacts import LocalArtifactStore

    return LocalArtifactStore(tmp_path / "artifacts")


@pytest.fixture
def fake_detonator():
    from reddysec.testing.fakes import FakeDetonator

    return FakeDetonator()


@pytest.fixture
def fake_mailbox():
    from reddysec.testing.fakes import FakeMailbox

    return FakeMailbox()


@pytest.fixture
def fake_intel():
    from reddysec.testing.fakes import FakeIntel

    return FakeIntel()


@pytest.fixture
async def db(tmp_env):
    from reddysec.store.db import Database, set_database

    database = Database(f"sqlite+aiosqlite:///{tmp_env / 'test.db'}")
    await database.create_all()
    set_database(database)
    yield database
    set_database(None)
    await database.dispose()
