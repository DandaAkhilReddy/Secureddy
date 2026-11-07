"""CLI argument wiring. Server commands are stubbed; data commands hit the temp SQLite DB."""

from __future__ import annotations

import asyncio
import getpass
from typing import Any

import pytest

from reddysec import cli
from reddysec.config import get_settings
from reddysec.mail.vault import CredentialVault, cipher_from_settings
from reddysec.models import ProtectionMode
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.testing.fakes import FakeMailbox


def run_db(coro_factory):
    """Run an async check against the CLI's database (sync test context)."""

    async def go():
        db = Database(get_settings().database_url)
        try:
            async with db.session() as s:
                return await coro_factory(s)
        finally:
            await db.dispose()

    return asyncio.run(go())


@pytest.fixture
def cli_env(tmp_env, monkeypatch):
    monkeypatch.setenv("RS_SECRET_KEY", "cli-test-secret")
    from reddysec.config import reset_settings_cache

    reset_settings_cache()
    assert cli.main(["init-db"]) == 0
    return tmp_env


class TestMigrate:
    def test_migrate_reports_and_is_idempotent(self, cli_env, capsys):
        assert cli.main(["migrate"]) == 0
        assert "schema up to date (0 changes applied)" in capsys.readouterr().out

    def test_migrate_prints_each_change(self, cli_env, capsys, monkeypatch):
        async def fake_create_all(self):
            return ["widened mailboxes.cursor from varchar(100) to text"]

        monkeypatch.setattr(cli.Database, "create_all", fake_create_all)
        assert cli.main(["migrate"]) == 0
        out = capsys.readouterr().out
        assert "widened mailboxes.cursor" in out and "(1 change applied)" in out


class TestServiceCommands:
    def test_web_passes_host_and_port(self, cli_env, monkeypatch):
        seen: dict[str, Any] = {}
        monkeypatch.setattr(cli, "_serve_web", lambda host, port: seen.update(host=host, port=port))
        assert cli.main(["web", "--host", "0.0.0.0", "--port", "9000"]) == 0
        assert seen == {"host": "0.0.0.0", "port": 9000}
        cli.main(["web"])
        assert seen == {"host": "127.0.0.1", "port": 8000}

    def test_worker_and_deadman_flags(self, cli_env, monkeypatch):
        seen: list[dict[str, Any]] = []
        monkeypatch.setattr(
            cli, "_run_services", lambda settings, **kw: seen.append({"env": settings.env, **kw})
        )
        assert cli.main(["worker"]) == 0
        assert cli.main(["worker", "--no-deadman"]) == 0
        assert cli.main(["--log-level", "debug", "deadman"]) == 0
        assert seen == [
            {"env": "test", "with_worker": True, "with_deadman": True},
            {"env": "test", "with_worker": True, "with_deadman": False},
            {"env": "test", "with_worker": False, "with_deadman": True},
        ]

    def test_missing_command_is_a_usage_error(self, cli_env):
        with pytest.raises(SystemExit) as info:
            cli.main([])
        assert info.value.code == 2


class TestDataCommands:
    def test_init_db_and_add_user(self, cli_env, capsys):
        assert cli.main(["add-user", "--email", "Client@Example.com", "--name", "The Client"]) == 0
        out = capsys.readouterr().out
        assert "created user usr_" in out and "client@example.com" in out and "principal" in out
        assert (
            cli.main(["add-user", "--email", "client@example.com", "--name", "Again", "--role", "admin"]) == 1
        )
        assert "already exists" in capsys.readouterr().err
        assert (
            cli.main(["add-user", "--email", "ana@rs.example", "--name", "Ana", "--role", "concierge"]) == 0
        )

        async def check(s):
            return [(u.login_email, u.role) for u in await repo.list_users(s)]

        assert run_db(check) == [("client@example.com", "principal"), ("ana@rs.example", "concierge")]

    def test_add_imap_mailbox_with_password_env(self, cli_env, monkeypatch, capsys):
        cli.main(["add-user", "--email", "c@example.com", "--name", "C"])
        monkeypatch.setenv("YAHOO_PW", "app-pass-123")
        assert (
            cli.main(
                [
                    "add-imap-mailbox",
                    "--user-email",
                    "c@example.com",
                    "--provider",
                    "yahoo",
                    "--address",
                    "C@Yahoo.com",
                    "--mode",
                    "hold",
                    "--password-env",
                    "YAHOO_PW",
                ]
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "created mailbox mbx_" in out and "mode=hold" in out and "next cycle" in out

        async def check(s):
            (mailbox,) = await repo.list_mailboxes(s)
            vault = CredentialVault(cipher_from_settings(get_settings()))
            kind, secret = await vault.load(s, mailbox.id)
            audit = [a.action for a in await repo.list_audit(s, mailbox.id)]
            return mailbox, kind, secret, audit

        mailbox, kind, secret, audit = run_db(check)
        assert mailbox.provider == "yahoo" and mailbox.address == "c@yahoo.com" and mailbox.mode == "hold"
        assert mailbox.labels == {}  # the worker sets up on its first cycle
        assert kind == "imap_password"
        assert secret == {
            "username": "c@yahoo.com",
            "password": "app-pass-123",
            "host": "imap.mail.yahoo.com",
            "port": 993,
        }
        assert audit == ["mailbox_added"]

    def test_add_imap_mailbox_prompts_for_password(self, cli_env, monkeypatch):
        cli.main(["add-user", "--email", "c@example.com", "--name", "C"])
        monkeypatch.setattr(getpass, "getpass", lambda prompt: "typed-secret")
        assert (
            cli.main(
                [
                    "add-imap-mailbox",
                    "--user-email",
                    "c@example.com",
                    "--provider",
                    "imap",
                    "--address",
                    "c@corp.example",
                    "--host",
                    "mail.corp.example",
                    "--port",
                    "1993",
                    "--username",
                    "corp\\c",
                ]
            )
            == 0
        )

        async def check(s):
            (mailbox,) = await repo.list_mailboxes(s)
            return await CredentialVault(cipher_from_settings(get_settings())).load(s, mailbox.id)

        kind, secret = run_db(check)
        assert secret == {
            "username": "corp\\c",
            "password": "typed-secret",
            "host": "mail.corp.example",
            "port": 1993,
        }

    def test_add_imap_mailbox_errors(self, cli_env, monkeypatch, capsys):
        monkeypatch.setenv("EMPTY_PW", "")
        with pytest.raises(SystemExit, match="EMPTY_PW"):
            cli.main(
                [
                    "add-imap-mailbox",
                    "--user-email",
                    "x@example.com",
                    "--provider",
                    "yahoo",
                    "--address",
                    "x@yahoo.com",
                    "--password-env",
                    "EMPTY_PW",
                ]
            )
        with pytest.raises(SystemExit, match="--host is required"):
            cli.main(
                [
                    "add-imap-mailbox",
                    "--user-email",
                    "x@example.com",
                    "--provider",
                    "imap",
                    "--address",
                    "x@corp",
                    "--password-env",
                    "EMPTY_PW",
                ]
            )
        monkeypatch.setenv("PW", "p")
        assert (
            cli.main(
                [
                    "add-imap-mailbox",
                    "--user-email",
                    "nobody@example.com",
                    "--provider",
                    "icloud",
                    "--address",
                    "x@icloud.com",
                    "--password-env",
                    "PW",
                ]
            )
            == 1
        )
        assert "run add-user first" in capsys.readouterr().err
        with pytest.raises(SystemExit):
            cli.main(
                ["add-imap-mailbox", "--user-email", "x", "--provider", "gmail", "--address", "x@gmail.com"]
            )

    def test_list_mailboxes(self, cli_env, monkeypatch, capsys):
        assert cli.main(["list-mailboxes"]) == 0
        assert "no mailboxes" in capsys.readouterr().out
        cli.main(["add-user", "--email", "c@example.com", "--name", "C"])
        monkeypatch.setenv("PW", "p")
        cli.main(
            [
                "add-imap-mailbox",
                "--user-email",
                "c@example.com",
                "--provider",
                "outlook",
                "--address",
                "c@outlook.com",
                "--password-env",
                "PW",
            ]
        )

        async def mark_error(s):
            (mailbox,) = await repo.list_mailboxes(s)
            await repo.set_mailbox_status(s, mailbox.id, "error", error="token revoked")
            return mailbox.id

        mailbox_id = run_db(mark_error)
        capsys.readouterr()
        assert cli.main(["list-mailboxes"]) == 0
        out = capsys.readouterr().out
        assert mailbox_id in out and "outlook" in out and "c@example.com" in out and "c@outlook.com" in out
        assert "last error: token revoked" in out

    def test_release_all(self, cli_env, monkeypatch, capsys):
        cli.main(["add-user", "--email", "c@example.com", "--name", "C"])
        monkeypatch.setenv("PW", "p")
        cli.main(
            [
                "add-imap-mailbox",
                "--user-email",
                "c@example.com",
                "--provider",
                "yahoo",
                "--address",
                "c@yahoo.com",
                "--mode",
                "hold",
                "--password-env",
                "PW",
            ]
        )

        async def setup(s):
            (mailbox,) = await repo.list_mailboxes(s)
            await repo.set_mailbox_labels(s, mailbox.id, {"Secureddy": "L1", "_mode": "hold"})
            return mailbox.id

        mailbox_id = run_db(setup)
        fake = FakeMailbox(mailbox_id)
        asyncio.run(fake.setup(ProtectionMode.HOLD))
        fake.deliver(b"raw", "held-1")
        fake.deliver(b"raw", "held-2")

        def fake_factory(settings, db, **kw):
            async def build(mailbox):
                assert mailbox.id == mailbox_id
                return fake

            return build

        monkeypatch.setattr(cli, "connector_factory_from_settings", fake_factory)
        capsys.readouterr()
        assert cli.main(["release-all", "--mailbox-id", mailbox_id, "--reason", "ops drill"]) == 0
        out = capsys.readouterr().out
        assert "released 2 held message(s) for c@yahoo.com" in out
        assert fake.actions[0] == ("release_all_pending", "2") and all(fake.in_inbox.values())

        async def check(s):
            mailbox = await repo.get_mailbox(s, mailbox_id)
            return (
                mailbox.status,
                mailbox.labels,
                [
                    (a.action, a.actor_role, a.details.get("reason"))
                    for a in await repo.list_audit(s, mailbox_id)
                ],
            )

        status, labels, audit = run_db(check)
        assert status == "error" and labels == {"Secureddy": "L1"}
        assert ("deadman_release", "admin", "ops drill") in audit
        assert cli.main(["release-all", "--mailbox-id", "mbx_missing"]) == 1
        assert "no mailbox" in capsys.readouterr().err
