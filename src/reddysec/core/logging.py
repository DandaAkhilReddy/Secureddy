"""Structured logging. JSON in production, readable in development.

Never log message bodies, subjects, or addresses at INFO. Log ids and
verdict codes; the dashboard shows the rest to the people entitled to see it.

Every event passes through ``core.redact.structlog_processor`` and every
standard-library record (uvicorn, httpx, the Azure SDK) through
:class:`RedactingFilter`, so a token that slips into a log line is masked
before it is written.
"""

from __future__ import annotations

import logging
import sys

import structlog

from .redact import redact_text, redact_value, structlog_processor


class RedactingFilter(logging.Filter):
    """Masks secrets in standard-library log records (message and args)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            if isinstance(record.args, dict):
                record.args = redact_value(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_value(a) for a in record.args)
        except Exception:  # noqa: BLE001 - logging must never fail because of redaction
            pass
        return True


def configure_logging(level: str = "INFO", json: bool = False) -> None:
    logging.basicConfig(level=level.upper(), stream=sys.stdout, format="%(message)s")
    root = logging.getLogger()
    for handler in root.handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())
    renderer = structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
