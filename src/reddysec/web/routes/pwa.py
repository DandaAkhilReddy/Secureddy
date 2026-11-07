"""Installable web app: manifest, service worker and the offline page.

Rules the service worker follows (and the tests check in its source):

* It precaches only the app shell: the stylesheet, the scripts, the icons and
  the offline page. Nothing in the shell belongs to a person.
* Pages are fetched from the network first and are **never stored**: an
  HTML page here is someone's mail. When the network is gone, the offline
  page is shown instead.
* Anything under the private prefixes in ``NEVER_CACHE`` (the JSON API,
  screenshots and safe copies under ``/artifacts/``, sign-in, the Reading
  Room, the assistant) goes straight to the network and is never touched.
* The cache name embeds the package version and a hash of the shell files,
  so every deploy that changes them installs a fresh cache and deletes the
  old one.

The worker is served from ``/sw.js`` (not ``/static/``) so its scope is the
whole site; ``Service-Worker-Allowed: /`` says so explicitly. Our CSP
(``script-src 'self'``) covers it: it is a same-origin script.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from reddysec import __version__

from ..templating import asset_version

router = APIRouter()

THEME_COLOR = "#0e1318"  # --bg (dark brand)
THEME_COLOR_LIGHT = "#f6f1e7"  # --bg in the light theme
OFFLINE_URL = "/offline"
NEVER_CACHE = (
    "/api/",
    "/artifacts/",
    "/auth/",
    "/room/",
    "/hooks/",
    "/assistant",
    "/messages",
    "/mailboxes",
    "/notifications",
    "/settings",
    "/audit",
    "/concierge",
    "/lock",
    "/go",
)
ICONS = (
    {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
)


def shell_urls() -> list[str]:
    v = asset_version()
    return [
        f"/static/app.css?v={v}",
        f"/static/app.js?v={v}",
        f"/static/assistant.js?v={v}",
        f"/static/lock.js?v={v}",
        "/static/icons/icon-192.png",
        "/static/icons/icon-512.png",
        "/static/icons/apple-touch-icon.png",
        "/static/icons/favicon-32.png",
        OFFLINE_URL,
    ]


def cache_version() -> str:
    return f"{__version__}-{asset_version()}"


def manifest() -> dict[str, object]:
    return {
        "id": "/",
        "name": "Secureddy",
        "short_name": "Secureddy",
        "description": "A bodyguard for your inbox. Links and files are opened on our servers before they reach you.",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "any",
        "background_color": THEME_COLOR,
        "theme_color": THEME_COLOR,
        "categories": ["security", "productivity"],
        "icons": list(ICONS),
    }


SERVICE_WORKER = r"""/* Secureddy service worker. Cache version __VERSION__.
   Precaches the app shell only. Pages are network-first and never stored;
   private paths (NEVER_CACHE) are never touched. See web/routes/pwa.py. */
"use strict";

var CACHE = "secureddy-shell-__VERSION__";
var OFFLINE_URL = "__OFFLINE__";
var SHELL = __SHELL__;
var NEVER_CACHE = __NEVER__;

function isPrivate(url) {
  return NEVER_CACHE.some(function (prefix) { return url.pathname.indexOf(prefix) === 0; });
}

function isShell(url) {
  return SHELL.indexOf(url.pathname + url.search) !== -1;
}

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE)
      .then(function (cache) { return cache.addAll(SHELL); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.filter(function (key) {
          return key.indexOf("secureddy-") === 0 && key !== CACHE;
        }).map(function (key) { return caches.delete(key); }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (event) {
  var request = event.request;
  if (request.method !== "GET") { return; }
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) { return; }

  if (request.mode === "navigate") {
    // Network first. The page is never put in the cache: it may be someone's mail.
    event.respondWith(fetch(request).catch(function () { return caches.match(OFFLINE_URL); }));
    return;
  }
  if (isPrivate(url)) { return; }  // straight to the network, never cached
  if (isShell(url)) {
    event.respondWith(caches.match(request).then(function (hit) { return hit || fetch(request); }));
  }
});
"""


def service_worker_source() -> str:
    return (
        SERVICE_WORKER.replace("__VERSION__", cache_version())
        .replace("__OFFLINE__", OFFLINE_URL)
        .replace("__SHELL__", json.dumps(shell_urls()))
        .replace("__NEVER__", json.dumps(list(NEVER_CACHE)))
    )


@router.get("/manifest.webmanifest", include_in_schema=False)
async def web_manifest() -> Response:
    return JSONResponse(
        manifest(), media_type="application/manifest+json", headers={"Cache-Control": "no-cache"}
    )


@router.get("/sw.js", include_in_schema=False)
async def service_worker() -> Response:
    return Response(
        service_worker_source(),
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


@router.get(OFFLINE_URL, include_in_schema=False)
async def offline_page(request: Request) -> Response:
    """Rendered without the session (no cookie, no CSRF token, no user) so the
    copy the service worker keeps holds nothing personal."""
    html = request.app.state.templates.env.get_template("offline.html").render(
        app_version=__version__, asset_version=asset_version(), theme_color=THEME_COLOR,
        theme_color_light=THEME_COLOR_LIGHT,
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


@router.get("/apple-touch-icon.png", include_in_schema=False)
@router.get("/apple-touch-icon-precomposed.png", include_in_schema=False)
async def apple_touch_icon() -> Response:
    return RedirectResponse("/static/icons/apple-touch-icon.png", status_code=308)


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return RedirectResponse("/static/icons/favicon-32.png", status_code=308)
