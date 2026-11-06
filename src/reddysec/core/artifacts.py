"""Artifact store: screenshots, downloaded files, sanitized copies.

References look like ``local:2026/11/05/ab/abcdef...png``. The local backend
is a directory tree; the Azure backend (infra) maps the same references to a
Blob container. Content is addressed by SHA-256 so duplicates are free.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ArtifactStore(Protocol):
    def put(self, data: bytes, suffix: str = "") -> str: ...
    def get(self, ref: str) -> bytes: ...
    def exists(self, ref: str) -> bool: ...
    def delete(self, ref: str) -> None: ...


class LocalArtifactStore:
    scheme = "local"

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _rel(self, ref: str) -> Path:
        scheme, _, rel = ref.partition(":")
        if scheme != self.scheme or not rel or ".." in rel.split("/") or rel.startswith("/"):
            raise ValueError(f"bad artifact ref {ref!r}")
        return Path(rel)

    def path(self, ref: str) -> Path:
        return self.root / self._rel(ref)

    def put(self, data: bytes, suffix: str = "") -> str:
        digest = hashlib.sha256(data).hexdigest()
        day = datetime.now(UTC).strftime("%Y/%m/%d")
        suffix = suffix if (not suffix or suffix.startswith(".")) else "." + suffix
        rel = f"{day}/{digest[:2]}/{digest}{suffix}"
        target = self.root / rel
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, target)
        return f"{self.scheme}:{rel}"

    def get(self, ref: str) -> bytes:
        return self.path(ref).read_bytes()

    def exists(self, ref: str) -> bool:
        return self.path(ref).exists()

    def delete(self, ref: str) -> None:
        p = self.path(ref)
        if p.exists():
            p.unlink()


class AzureBlobArtifactStore:
    """Artifacts in an Azure Blob container. Same reference grammar as the
    local store (``blob:<relative path>``) so a reference minted by the worker
    is readable by the web tier, which is the whole point of a shared store.

    The SDK is imported lazily and the container client is injectable, so this
    module imports (and is tested) on machines without the Azure SDK. Auth is
    the pod's managed identity (``DefaultAzureCredential``); the account allows
    identity access only, no keys.
    """

    scheme = "blob"

    def __init__(self, account_url: str, container: str, *, client: object | None = None):
        self.account_url = account_url
        self.container = container
        self._client = client

    @property
    def client(self):  # pragma: no cover - real SDK only
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient

            service = BlobServiceClient(self.account_url, credential=DefaultAzureCredential())
            self._client = service.get_container_client(self.container)
        return self._client

    def _rel(self, ref: str) -> str:
        scheme, _, rel = ref.partition(":")
        if scheme != self.scheme or not rel or ".." in rel.split("/") or rel.startswith("/"):
            raise ValueError(f"bad artifact ref {ref!r}")
        return rel

    def put(self, data: bytes, suffix: str = "") -> str:
        digest = hashlib.sha256(data).hexdigest()
        day = datetime.now(UTC).strftime("%Y/%m/%d")
        suffix = suffix if (not suffix or suffix.startswith(".")) else "." + suffix
        rel = f"{day}/{digest[:2]}/{digest}{suffix}"
        blob = self.client.get_blob_client(rel)
        if not blob.exists():
            blob.upload_blob(data, overwrite=False)
        return f"{self.scheme}:{rel}"

    def get(self, ref: str) -> bytes:
        return self.client.get_blob_client(self._rel(ref)).download_blob().readall()

    def exists(self, ref: str) -> bool:
        return bool(self.client.get_blob_client(self._rel(ref)).exists())

    def delete(self, ref: str) -> None:
        blob = self.client.get_blob_client(self._rel(ref))
        if blob.exists():
            blob.delete_blob()


def artifact_store_from_settings(settings) -> ArtifactStore:
    """Blob storage when ``RS_STORAGE_ACCOUNT_URL`` is set, else a local directory."""
    if getattr(settings, "storage_account_url", ""):
        return AzureBlobArtifactStore(settings.storage_account_url, settings.artifacts_container)
    return LocalArtifactStore(settings.artifacts_dir)
