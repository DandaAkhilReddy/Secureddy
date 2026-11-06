"""Inbound webhooks. Today: Gmail push notifications via Cloud Pub/Sub.

Pub/Sub retries any non-2xx response with backoff, and a single bad message
would otherwise be redelivered for a week. So the only error we return is 403
for a wrong shared token; every other problem is logged and acknowledged.
Losing a push is harmless because the worker polls Gmail anyway; the push
only makes it faster.
"""

from __future__ import annotations

import base64
import binascii
import json

from fastapi import APIRouter, Query, Request, Response, status

from reddysec.core.logging import get_logger
from reddysec.web.security import tokens_match

log = get_logger(__name__)

# Deliberately *not* a protected_router: Pub/Sub has no browser session.
router = APIRouter()


def decode_push(payload: dict) -> tuple[str, str] | None:
    """Extract ``(email_address, history_id)`` from a Pub/Sub push envelope or
    return ``None`` for anything malformed."""
    message = payload.get("message") if isinstance(payload, dict) else None
    data = message.get("data") if isinstance(message, dict) else None
    if not isinstance(data, str):
        return None
    try:
        body = json.loads(base64.b64decode(data, validate=True))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    email = body.get("emailAddress")
    history_id = body.get("historyId")
    if not isinstance(email, str) or not email or history_id is None:
        return None
    return email, str(history_id)


@router.post("/hooks/gmail/pubsub", name="gmail_pubsub", status_code=status.HTTP_204_NO_CONTENT)
async def gmail_pubsub(request: Request, token: str | None = Query(default=None)) -> Response:
    expected = request.app.state.pubsub_token
    if not expected or not tokens_match(expected, token):
        return Response(status_code=status.HTTP_403_FORBIDDEN)
    try:
        payload = json.loads(await request.body())
    except ValueError:
        log.warning("gmail_push_bad_json")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    decoded = decode_push(payload)
    if decoded is None:
        log.warning("gmail_push_bad_payload")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    handler = request.app.state.on_gmail_push
    if handler is not None:
        try:
            await handler(*decoded)
        except Exception:
            log.exception("gmail_push_handler_failed", history_id=decoded[1])
    return Response(status_code=status.HTTP_204_NO_CONTENT)
