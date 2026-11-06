"""Unit tests for the shared core: ids, crypto, artifact store, queue, models."""

from __future__ import annotations

import asyncio
import base64
import os

import pytest

from reddysec.core.artifacts import LocalArtifactStore
from reddysec.core.crypto import DecryptError, TokenCipher, derive_dev_key, key_from_b64, sha256_hex
from reddysec.core.ids import is_id, new_id
from reddysec.core.queue import InMemoryJobQueue, Job
from reddysec.models import (
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    Attachment,
    DetonationJob,
    DetonationKind,
    ParsedMessage,
    Provider,
    VerdictLevel,
    level_for_score,
)


class TestIds:
    def test_new_id_shape_and_prefix(self):
        value = new_id("msg")
        assert value.startswith("msg_")
        assert is_id(value, "msg")
        assert not is_id(value, "job")
        assert not is_id("msg_short", "msg")

    def test_ids_are_unique_and_time_sortable(self):
        a = new_id("x")
        b = new_id("x")
        assert a != b
        assert a[:12] <= b[:12]  # prefix + 10 time chars: same millisecond or later


class TestCrypto:
    def test_round_trip_with_aad(self):
        cipher = TokenCipher({"k1": os.urandom(32)}, "k1")
        token = cipher.encrypt("refresh-token-123", aad="mbx_1")
        assert token.startswith("v1.k1.")
        assert cipher.decrypt(token, aad="mbx_1") == "refresh-token-123"

    def test_wrong_aad_fails(self):
        cipher = TokenCipher({"k1": os.urandom(32)}, "k1")
        token = cipher.encrypt("secret", aad="mbx_1")
        with pytest.raises(DecryptError):
            cipher.decrypt(token, aad="mbx_2")

    def test_rotation(self):
        old, new = os.urandom(32), os.urandom(32)
        c1 = TokenCipher({"k1": old}, "k1")
        token = c1.encrypt("s")
        c2 = TokenCipher({"k1": old, "k2": new}, "k2")
        assert c2.decrypt(token) == "s"
        assert c2.needs_rotation(token)
        assert not c2.needs_rotation(c2.encrypt("s"))

    def test_malformed_inputs(self):
        cipher = TokenCipher({"k1": os.urandom(32)}, "k1")
        for bad in ["", "v1.k1", "v2.k1.AAAA", "v1.zz.AAAA", "v1.k1." + base64.urlsafe_b64encode(b"short").decode()]:
            with pytest.raises(DecryptError):
                cipher.decrypt(bad)

    def test_key_validation(self):
        with pytest.raises(ValueError):
            TokenCipher({"k1": b"short"}, "k1")
        with pytest.raises(ValueError):
            TokenCipher({"k1": os.urandom(32)}, "missing")
        with pytest.raises(ValueError):
            key_from_b64(base64.b64encode(b"x" * 16).decode())

    def test_from_settings_dev_and_prod(self):
        dev = TokenCipher.from_settings("", "secret")
        assert dev.current_key_id == "dev"
        assert derive_dev_key("secret") == derive_dev_key("secret")
        prod = TokenCipher.from_settings(base64.b64encode(os.urandom(32)).decode(), "ignored")
        assert prod.current_key_id.startswith("k") and prod.current_key_id != "dev"

    def test_sha256_hex(self):
        assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestArtifactStore:
    def test_put_get_dedupe_delete(self, tmp_path):
        store = LocalArtifactStore(tmp_path)
        ref = store.put(b"hello", suffix="png")
        assert ref.startswith("local:") and ref.endswith(".png")
        assert store.get(ref) == b"hello"
        assert store.put(b"hello", "png") == ref  # content addressed
        assert store.exists(ref)
        store.delete(ref)
        assert not store.exists(ref)
        store.delete(ref)  # idempotent

    def test_suffix_normalisation(self, tmp_path):
        store = LocalArtifactStore(tmp_path)
        assert store.put(b"a", ".pdf").endswith(".pdf")
        assert store.put(b"b", "").endswith(sha256_hex(b"b"))

    def test_rejects_bad_refs(self, tmp_path):
        store = LocalArtifactStore(tmp_path)
        for bad in ["s3:x", "local:", "local:../etc/passwd", "local:/abs"]:
            with pytest.raises(ValueError):
                store.get(bad)


class TestQueue:
    async def test_fifo_and_kind_filter(self):
        q = InMemoryJobQueue()
        await q.enqueue(Job(kind="a", payload={"n": 1}))
        await q.enqueue(Job(kind="b", payload={"n": 2}))
        got = await q.dequeue(kinds={"b"})
        assert got is not None and got.payload["n"] == 2 and got.attempts == 1
        got = await q.dequeue()
        assert got is not None and got.kind == "a"
        assert await q.dequeue(timeout=0.01) is None
        assert await q.size() == 0

    async def test_fail_requeues_then_dead_letters(self):
        q = InMemoryJobQueue()
        job = Job(kind="a", max_attempts=2)
        await q.enqueue(job)
        j = await q.dequeue()
        await q.fail(j, "boom")
        assert await q.size() == 1
        j = await q.dequeue()
        await q.fail(j, "boom again")
        assert await q.size() == 0
        assert q.dead_letters and q.dead_letters[0].last_error == "boom again"
        await q.ack(j)

    async def test_blocking_dequeue_wakes_on_enqueue(self):
        q = InMemoryJobQueue()

        async def producer():
            await asyncio.sleep(0.02)
            await q.enqueue(Job(kind="late"))

        asyncio.create_task(producer())
        got = await q.dequeue(timeout=1)
        assert got is not None and got.kind == "late"


class TestModels:
    def test_level_for_score_bands(self):
        assert level_for_score(0) is VerdictLevel.SAFE
        assert level_for_score(SUSPICIOUS_THRESHOLD - 1) is VerdictLevel.SAFE
        assert level_for_score(SUSPICIOUS_THRESHOLD) is VerdictLevel.SUSPICIOUS
        assert level_for_score(MALICIOUS_THRESHOLD) is VerdictLevel.MALICIOUS
        assert VerdictLevel.MALICIOUS.rank > VerdictLevel.SUSPICIOUS.rank > VerdictLevel.SAFE.rank

    def test_attachment_bytes_never_serialized(self):
        a = Attachment(filename="x.pdf", content_type="application/pdf", size=1, sha256="0" * 64, data=b"\x00")
        assert "data" not in a.model_dump()
        assert "data" not in a.model_dump_json()

    def test_parsed_message_helpers(self):
        from datetime import UTC, datetime

        m = ParsedMessage(provider_message_id="1", mailbox_id="m", received_at=datetime.now(UTC),
                          from_address="Bob@Example.com")
        assert m.from_domain == "example.com"
        assert not m.needs_deep_analysis
        m.attachments.append(Attachment(filename="logo.png", content_type="image/png", size=1, sha256="a" * 64,
                                        is_inline=True))
        assert not m.has_attachments  # inline images don't count
        assert Provider.YAHOO.uses_imap and not Provider.GMAIL.uses_imap

    def test_detonation_job_defaults(self):
        job = DetonationJob(job_id="det_1", kind=DetonationKind.URL, url="https://example.com")
        assert job.profile.interact and job.timeout_s == 45


class _FakeBlob:
    def __init__(self, store: dict, name: str):
        self._store, self._name = store, name

    def exists(self):
        return self._name in self._store

    def upload_blob(self, data, overwrite=False):
        if self._name in self._store and not overwrite:
            raise RuntimeError("exists")
        self._store[self._name] = bytes(data)

    class _Downloader:
        def __init__(self, data):
            self._data = data

        def readall(self):
            return self._data

    def download_blob(self):
        return self._Downloader(self._store[self._name])

    def delete_blob(self):
        del self._store[self._name]


class _FakeContainer:
    def __init__(self):
        self.blobs: dict[str, bytes] = {}

    def get_blob_client(self, name: str):
        return _FakeBlob(self.blobs, name)


class TestAzureBlobArtifactStore:
    def test_round_trip_dedupe_and_delete(self):
        from reddysec.core.artifacts import AzureBlobArtifactStore

        container = _FakeContainer()
        store = AzureBlobArtifactStore("https://acct.blob.core.windows.net", "artifacts", client=container)
        ref = store.put(b"shot", "jpg")
        assert ref.startswith("blob:") and ref.endswith(".jpg")
        assert store.put(b"shot", ".jpg") == ref and len(container.blobs) == 1
        assert store.get(ref) == b"shot" and store.exists(ref)
        store.delete(ref)
        assert not store.exists(ref)
        store.delete(ref)
        with pytest.raises(ValueError):
            store.get("blob:../x")
        with pytest.raises(ValueError):
            store.get("local:abc")

    def test_factory_picks_backend(self, tmp_path):
        from types import SimpleNamespace

        from reddysec.core.artifacts import (
            AzureBlobArtifactStore,
            LocalArtifactStore,
            artifact_store_from_settings,
        )

        local = artifact_store_from_settings(SimpleNamespace(storage_account_url="", artifacts_dir=str(tmp_path)))
        assert isinstance(local, LocalArtifactStore)
        blob = artifact_store_from_settings(
            SimpleNamespace(storage_account_url="https://a.blob.core.windows.net", artifacts_container="c",
                            artifacts_dir="")
        )
        assert isinstance(blob, AzureBlobArtifactStore) and blob.container == "c"


class TestKeyRotation:
    def test_previous_key_decrypts_and_flags_rotation(self):
        import base64 as b64

        from reddysec.core.crypto import key_id_for

        old = b64.b64encode(os.urandom(32)).decode()
        new = b64.b64encode(os.urandom(32)).decode()
        before = TokenCipher.from_settings(old, "s")
        token = before.encrypt("refresh", aad="mbx")
        during = TokenCipher.from_settings(new, "s", previous_kek_b64=old)
        assert during.decrypt(token, aad="mbx") == "refresh"
        assert during.needs_rotation(token)
        rotated = during.encrypt("refresh", aad="mbx")
        assert not during.needs_rotation(rotated)
        after = TokenCipher.from_settings(new, "s")
        assert after.decrypt(rotated, aad="mbx") == "refresh"
        with pytest.raises(DecryptError):
            after.decrypt(token, aad="mbx")  # old key dropped
        assert key_id_for(key_from_b64(new)) == after.current_key_id
        assert TokenCipher.from_settings(new, "s", previous_kek_b64=new).current_key_id == after.current_key_id
