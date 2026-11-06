"""Integration fixtures: the local evil site and a shared artifact store.

Everything here is marked implicitly integration by the test modules that use
it. The evil site is module-scoped so one pair of HTTP servers serves a whole
test file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # make evil_server importable

from .evil_server import EvilSite  # noqa: E402


@pytest.fixture(scope="module")
def evil_site():
    site = EvilSite(slow_seconds=20).start()
    try:
        yield site
    finally:
        site.stop()


@pytest.fixture
def store(tmp_path):
    from reddysec.core.artifacts import LocalArtifactStore

    return LocalArtifactStore(tmp_path / "artifacts")
