"""Page and API routers. Each module owns one area and exposes ``router``.

Every router is created with ``dependencies=[Depends(csrf_protect)]`` so a
state-changing request cannot reach a handler without the session's CSRF
token. The Pub/Sub webhook is the one exception: it has no browser session and
authenticates with a shared token instead.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..security import csrf_protect


def protected_router(**kwargs) -> APIRouter:
    """An ``APIRouter`` with CSRF protection already attached. Routers must be
    built through this helper; the functional tests post to every route
    without a token and expect a 403."""
    deps = list(kwargs.pop("dependencies", []))
    deps.append(Depends(csrf_protect))
    return APIRouter(dependencies=deps, **kwargs)
