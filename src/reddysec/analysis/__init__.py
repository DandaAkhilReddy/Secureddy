"""The analysis engine.

Typical use from the worker::

    from reddysec.analysis import AnalysisContext, CompositeIntel, OfflineIntel, OnlineIntel, analyze, parse_raw

    parsed = parse_raw(raw_bytes, provider_message_id=..., mailbox_id=..., received_at=...)
    ctx = AnalysisContext(policy=policy, history=history, intel=intel, detonator=chamber)
    verdict = await analyze(parsed, ctx)

Modules:

parser       raw RFC 5322 bytes -> ParsedMessage (headers, bodies, attachments, auth, URLs)
urls         URL extraction (HTML, text, QR codes, PDFs, attachments) and normalisation
domains      brand knowledge and lookalike-domain detection
headers      sender / authentication / display-name signals
attachments  file-type sniffing, macros, PDF actions, archives, HTML smuggling
intel        offline lists, online reputation and domain-age lookups
bec          wire-fraud heuristics and the optional LLM reviewer
dynamic      per-URL static signals and signals from detonation results
policy       triage lanes and detonation selection
scoring      score combination, plain-English summaries, per-item verdicts
pipeline     ``analyze``: the whole thing, never raising
"""

from .attachments import attachment_signals, sniff_type
from .bec import AzureOpenAiAssessor, LlmAssessment, LlmAssessor, NoopLlm, bec_signals
from .domains import LookalikeResult, brand_for_domain, brands_mentioned, lookalike_analysis
from .dynamic import dynamic_signals, url_static_signals
from .headers import sender_signals
from .intel import CompositeIntel, IntelClient, OfflineIntel, OnlineIntel, is_popular, is_tracking_domain
from .parser import parse_raw
from .pipeline import AnalysisContext, analyze
from .policy import choose_lane, select_attachments_to_detonate, select_urls_to_detonate
from .scoring import combine, summarize
from .urls import extract_all, normalize_url, registrable_domain

__all__ = [
    "AnalysisContext",
    "AzureOpenAiAssessor",
    "CompositeIntel",
    "IntelClient",
    "LlmAssessment",
    "LlmAssessor",
    "LookalikeResult",
    "NoopLlm",
    "OfflineIntel",
    "OnlineIntel",
    "analyze",
    "attachment_signals",
    "bec_signals",
    "brand_for_domain",
    "brands_mentioned",
    "choose_lane",
    "combine",
    "dynamic_signals",
    "extract_all",
    "is_popular",
    "is_tracking_domain",
    "lookalike_analysis",
    "normalize_url",
    "parse_raw",
    "registrable_domain",
    "select_attachments_to_detonate",
    "select_urls_to_detonate",
    "sender_signals",
    "sniff_type",
    "summarize",
    "url_static_signals",
]
