"""``python -m reddysec.worker``: run the worker and the dead man's switch.

Both services share one process here for development convenience. In
production run ``reddysec worker`` and ``reddysec deadman`` separately (the
watchdog on another host) so the switch survives whatever kills the worker.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal

from reddysec.config import Settings, get_settings
from reddysec.core.logging import configure_logging, get_logger
from reddysec.mail.factory import connector_factory_from_settings
from reddysec.store.db import Database
from reddysec.worker.deadman import DeadManSwitch
from reddysec.worker.engine import Worker
from reddysec.worker.notify import Notifier

log = get_logger(__name__)


def install_stop_signals(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows / non-main thread
            loop.add_signal_handler(sig, stop_event.set)


async def run(
    settings: Settings | None = None,
    *,
    with_worker: bool = True,
    with_deadman: bool = True,
    stop_event: asyncio.Event | None = None,
    db: Database | None = None,
) -> None:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json=settings.is_prod)
    db = db or Database(settings.database_url)
    # Creates missing tables and applies pending schema upgrades (idempotent,
    # advisory-locked): the worker may start before the web app ever has.
    changes = await db.create_all()
    log.info("db.schema_ready", changes=len(changes))
    stop = stop_event or asyncio.Event()
    install_stop_signals(stop)

    factory = connector_factory_from_settings(settings, db)
    notifier = Notifier(db, settings)
    tasks: list[asyncio.Task[None]] = []
    if with_worker:
        worker = Worker(db, settings, connector_factory=factory, notifier=notifier)
        tasks.append(asyncio.create_task(worker.run_forever(stop), name="worker"))
    if with_deadman:
        deadman = DeadManSwitch(db, settings, connector_factory=factory, notifier=notifier)
        tasks.append(asyncio.create_task(deadman.run_forever(stop), name="deadman"))
    if not tasks:
        return
    log.info("services.started", worker=with_worker, deadman=with_deadman)
    try:
        await asyncio.gather(*tasks)
    finally:
        stop.set()
        await db.dispose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":  # pragma: no cover - process entry point
    main()
