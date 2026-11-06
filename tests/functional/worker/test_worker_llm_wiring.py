"""The worker hands the configured language model to the analysis context."""

from __future__ import annotations

from reddysec.analysis.bec import AnthropicAssessor, NoopLlm
from reddysec.config import Settings
from reddysec.worker.engine import Worker


async def _noop_factory(_row):
    raise AssertionError("not used")


def test_worker_llm_defaults_to_noop(db):
    worker = Worker(db, Settings(llm_provider="none"), connector_factory=_noop_factory)
    assert isinstance(worker.llm, NoopLlm)


def test_worker_llm_from_settings(db):
    settings = Settings(llm_provider="anthropic", anthropic_api_key="k", anthropic_model="claude-haiku-4-5")
    worker = Worker(db, settings, connector_factory=_noop_factory)
    assert isinstance(worker.llm, AnthropicAssessor)
    assert worker.llm is worker.llm  # built once
