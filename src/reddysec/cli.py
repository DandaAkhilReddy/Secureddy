"""``reddysec`` command line: operate the service without touching the database.

Subcommands
-----------
init-db             create the schema
migrate             create missing tables and apply pending schema upgrades
web                 run the FastAPI app (uvicorn)
worker              run the processing loop (and, by default, the dead man's switch)
deadman             run only the dead man's switch
add-user            create a user (principal, family, assistant, concierge, admin)
add-imap-mailbox    attach a Yahoo / iCloud / Outlook.com / generic IMAP mailbox
release-all         manually release every held message of a mailbox (dead man by hand)
list-mailboxes      show mailboxes and their state

Server-starting commands delegate to module-level functions (``_serve_web``,
``_run_services``) so tests can check the argument wiring without binding ports.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from collections.abc import Sequence

from reddysec.config import Settings, get_settings
from reddysec.core.logging import configure_logging
from reddysec.mail.factory import connector_factory_from_settings
from reddysec.mail.imap import IMAP_PRESETS, ImapCredentials
from reddysec.mail.vault import KIND_IMAP_PASSWORD, CredentialVault, cipher_from_settings
from reddysec.models import Provider, Role
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.worker.deadman import DeadManSwitch
from reddysec.worker.notify import Notifier

IMAP_PROVIDERS = [
    Provider.YAHOO.value,
    Provider.ICLOUD.value,
    Provider.OUTLOOK.value,
    Provider.GENERIC_IMAP.value,
]


# ------------------------------------------------------------ service hooks
def _serve_web(host: str, port: int) -> None:  # pragma: no cover - binds a port
    import uvicorn

    from reddysec.web.app import create_app  # lazy: pulls in FastAPI and the chamber

    settings = get_settings()
    # The web process hosts the Reading Room (Chromium) and verifies Pub/Sub
    # pushes with the shared token when one is configured.
    app = create_app(
        settings,
        enable_reading_room=True,
        pubsub_token=settings.pubsub_token or None,
    )
    uvicorn.run(app, host=host, port=port, proxy_headers=True, forwarded_allow_ips="*")


def _run_services(settings: Settings, *, with_worker: bool, with_deadman: bool) -> None:  # pragma: no cover
    from reddysec.worker.__main__ import run

    asyncio.run(run(settings, with_worker=with_worker, with_deadman=with_deadman))


# ----------------------------------------------------------------- commands
def cmd_init_db(args: argparse.Namespace, settings: Settings) -> int:
    async def go() -> None:
        db = Database(settings.database_url)
        try:
            await db.create_all()
        finally:
            await db.dispose()

    asyncio.run(go())
    print(f"database ready at {settings.database_url}")
    return 0


def cmd_migrate(args: argparse.Namespace, settings: Settings) -> int:
    """Same work as ``init-db`` (``create_all`` runs the upgrades), but reports
    what changed. Safe to run any time, also while the services run."""

    async def go() -> list[str]:
        db = Database(settings.database_url)
        try:
            return await db.create_all()
        finally:
            await db.dispose()

    changes = asyncio.run(go())
    for change in changes:
        print(change)
    print(f"schema up to date ({len(changes)} change{'s' if len(changes) != 1 else ''} applied)")
    return 0


def cmd_web(args: argparse.Namespace, settings: Settings) -> int:
    _serve_web(args.host, args.port)
    return 0


def cmd_worker(args: argparse.Namespace, settings: Settings) -> int:
    _run_services(settings, with_worker=True, with_deadman=not args.no_deadman)
    return 0


def cmd_deadman(args: argparse.Namespace, settings: Settings) -> int:
    _run_services(settings, with_worker=False, with_deadman=True)
    return 0


def cmd_add_user(args: argparse.Namespace, settings: Settings) -> int:
    async def go() -> int:
        db = Database(settings.database_url)
        try:
            async with db.session() as session:
                if await repo.get_user_by_email(session, args.email) is not None:
                    print(f"user {args.email} already exists", file=sys.stderr)
                    return 1
                user = await repo.create_user(
                    session, email=args.email, display_name=args.name, role=args.role
                )
                await repo.audit(
                    session, None, "admin", "user_created", details={"user_id": user.id, "role": args.role}
                )
            print(f"created user {user.id} ({user.login_email}, {user.role})")
            return 0
        finally:
            await db.dispose()

    return asyncio.run(go())


def _read_password(args: argparse.Namespace) -> str:
    if args.password_env:
        value = os.environ.get(args.password_env, "")
        if not value:
            raise SystemExit(f"environment variable {args.password_env} is empty or missing")
        return value
    return getpass.getpass("App password (input hidden): ")


def cmd_add_imap_mailbox(args: argparse.Namespace, settings: Settings) -> int:
    provider = Provider(args.provider)
    if provider is Provider.GENERIC_IMAP and not args.host:
        raise SystemExit("--host is required for a generic IMAP mailbox")
    password = _read_password(args)
    credentials = ImapCredentials(
        username=args.username or args.address.strip().lower(),
        password=password,
        host=args.host or (IMAP_PRESETS[provider][0] if provider in IMAP_PRESETS else None),
        port=args.port or (IMAP_PRESETS[provider][1] if provider in IMAP_PRESETS else 993),
    )

    async def go() -> int:
        db = Database(settings.database_url)
        vault = CredentialVault(cipher_from_settings(settings))
        try:
            async with db.session() as session:
                user = await repo.get_user_by_email(session, args.user_email)
                if user is None:
                    print(f"no user with email {args.user_email}; run add-user first", file=sys.stderr)
                    return 1
                mailbox = await repo.create_mailbox(
                    session, user_id=user.id, provider=provider.value, address=args.address, mode=args.mode
                )
                await vault.store(
                    session, mailbox.id, KIND_IMAP_PASSWORD, credentials.model_dump(exclude_none=True)
                )
                await repo.audit(
                    session,
                    user.id,
                    "admin",
                    "mailbox_added",
                    mailbox.id,
                    details={"provider": provider.value, "mode": args.mode},
                )
            print(f"created mailbox {mailbox.id} ({provider.value}, {args.address}, mode={args.mode})")
            print("the worker will create the folders on its next cycle")
            return 0
        finally:
            await db.dispose()

    return asyncio.run(go())


def cmd_release_all(args: argparse.Namespace, settings: Settings) -> int:
    async def go() -> int:
        db = Database(settings.database_url)
        try:
            async with db.session() as session:
                mailbox = await repo.get_mailbox(session, args.mailbox_id)
            if mailbox is None:
                print(f"no mailbox {args.mailbox_id}", file=sys.stderr)
                return 1
            switch = DeadManSwitch(
                db,
                settings,
                connector_factory=connector_factory_from_settings(settings, db),
                notifier=Notifier(db, settings),
            )
            count = await switch.release_mailbox(mailbox, reason=args.reason, actor_role="admin")
            print(f"released {count} held message(s) for {mailbox.address}; mailbox is now in error state")
            return 0
        finally:
            await db.dispose()

    return asyncio.run(go())


def cmd_list_mailboxes(args: argparse.Namespace, settings: Settings) -> int:
    async def go() -> int:
        db = Database(settings.database_url)
        try:
            async with db.session() as session:
                mailboxes = await repo.list_mailboxes(session)
                users = {u.id: u for u in await repo.list_users(session)}
        finally:
            await db.dispose()
        if not mailboxes:
            print("no mailboxes")
            return 0
        header = f"{'id':<30} {'provider':<8} {'mode':<5} {'status':<8} {'owner':<28} address"
        print(header)
        for m in mailboxes:
            owner = users[m.user_id].login_email if m.user_id in users else m.user_id
            print(f"{m.id:<30} {m.provider:<8} {m.mode:<5} {m.status:<8} {owner:<28} {m.address}")
            if m.last_error:
                print(f"{'':<30} last error: {m.last_error}")
        return 0

    return asyncio.run(go())


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reddysec", description="Secureddy operations")
    parser.add_argument("--log-level", default=None, help="override RS_LOG_LEVEL")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create the database schema").set_defaults(func=cmd_init_db)
    sub.add_parser("migrate", help="apply pending schema upgrades (idempotent)").set_defaults(func=cmd_migrate)

    web = sub.add_parser("web", help="run the web application")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    web.set_defaults(func=cmd_web)

    worker = sub.add_parser("worker", help="run the processing loop")
    worker.add_argument(
        "--no-deadman", action="store_true", help="do not run the dead man's switch in this process"
    )
    worker.set_defaults(func=cmd_worker)

    sub.add_parser("deadman", help="run only the dead man's switch").set_defaults(func=cmd_deadman)

    add_user = sub.add_parser("add-user", help="create a user")
    add_user.add_argument("--email", required=True)
    add_user.add_argument("--name", required=True)
    add_user.add_argument("--role", default=Role.PRINCIPAL.value, choices=[r.value for r in Role])
    add_user.set_defaults(func=cmd_add_user)

    imap = sub.add_parser(
        "add-imap-mailbox", help="attach an IMAP mailbox (Yahoo, iCloud, Outlook.com, generic)"
    )
    imap.add_argument("--user-email", required=True)
    imap.add_argument("--provider", required=True, choices=IMAP_PROVIDERS)
    imap.add_argument("--address", required=True)
    imap.add_argument("--username", default=None, help="IMAP login if different from the address")
    imap.add_argument("--host", default=None)
    imap.add_argument("--port", type=int, default=None)
    imap.add_argument("--mode", default="scan", choices=["scan", "hold"])
    imap.add_argument(
        "--password-env", default=None, help="read the app password from this environment variable"
    )
    imap.set_defaults(func=cmd_add_imap_mailbox)

    release = sub.add_parser("release-all", help="release every held message of a mailbox now")
    release.add_argument("--mailbox-id", required=True)
    release.add_argument("--reason", default="manual release by operator")
    release.set_defaults(func=cmd_release_all)

    sub.add_parser("list-mailboxes", help="list mailboxes").set_defaults(func=cmd_list_mailboxes)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(args.log_level or settings.log_level, json=settings.is_prod)
    return int(args.func(args, settings))


if __name__ == "__main__":  # pragma: no cover - process entry point
    sys.exit(main())
