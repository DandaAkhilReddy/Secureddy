"""The processing loop: poll mailboxes -> parse -> analyze -> act -> notify.

``engine.Worker`` does the work, ``deadman.DeadManSwitch`` guards HOLD mode,
``notify.Notifier`` talks to people. ``python -m reddysec.worker`` runs them.
"""
