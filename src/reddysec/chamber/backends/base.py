"""The detonation chamber: a policy wrapper around a sandbox backend.

A ``SandboxBackend`` knows how to run ``reddysec.chamber.detonate`` somewhere
isolated (a subprocess, a hardened container, an ACI container group) and
bring the result back. ``DetonationChamber`` is what the worker talks to
(it implements ``models.Detonator``) and owns everything the backends should
not have to agree on:

* **target policy** - only http/https, only hosts that resolve to public
  addresses (unless ``allow_private_targets`` for dev/test), FILE jobs only for
  files that exist in the artifact store; refusals come back as BLOCKED;
* **capacity** - an ``asyncio.Semaphore`` so a burst of mail cannot start
  fifty browsers on a two-core box;
* **time** - ``asyncio.wait_for(job.timeout_s + grace)`` around the backend;
  a sandbox that never answers yields a TIMEOUT result, never an exception;
* **finalization** - any ``file:`` output still carried in memory is stored
  in the artifact store, ``job_id`` / ``sandbox_backend`` / ``duration_ms`` are
  set from the host's point of view (the sandbox is not trusted to label
  itself).

``make_chamber(settings, artifact_store)`` picks the backend from
``settings.sandbox_backend``.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from reddysec.core.artifacts import ArtifactStore
from reddysec.core.logging import get_logger
from reddysec.models import DetonationJob, DetonationKind, DetonationResult, DetonationStatus

from ..protocol import is_file_ref, rehome
from ..targets import decide_target

if TYPE_CHECKING:
    from reddysec.config import Settings

log = get_logger(__name__)

DEFAULT_GRACE_S = 10


@runtime_checkable
class SandboxBackend(Protocol):
    """Runs one job in isolation and returns its result.

    Implementations return a ``DetonationResult`` (or a ``protocol.SandboxOutput``
    still carrying bytes) and are free to raise: the chamber turns exceptions
    into ERROR results. They must respect ``job.timeout_s`` and kill whatever
    they started when it is exceeded.
    """

    name: str

    async def run(self, job: DetonationJob) -> DetonationResult: ...


class DetonationChamber:
    """``Detonator`` implementation used by the worker. See module docstring."""

    def __init__(
        self,
        backend: SandboxBackend,
        artifact_store: ArtifactStore,
        max_concurrency: int = 2,
        default_timeout_s: int = 45,
        allow_private_targets: bool = False,
        grace_s: int = DEFAULT_GRACE_S,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.backend = backend
        self.artifact_store = artifact_store
        self.default_timeout_s = default_timeout_s
        self.allow_private_targets = allow_private_targets
        self.grace_s = grace_s
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_concurrency = max_concurrency

    @property
    def available_slots(self) -> int:
        return self._semaphore._value  # noqa: SLF001 - diagnostics only

    async def detonate(self, job: DetonationJob) -> DetonationResult:
        started = time.monotonic()
        if job.timeout_s <= 0:
            job = job.model_copy(update={"timeout_s": self.default_timeout_s})

        refusal = await self._validate(job)
        if refusal is not None:
            return self._finish(job, refusal, started)

        async with self._semaphore:
            try:
                result = await asyncio.wait_for(self.backend.run(job), timeout=job.timeout_s + self.grace_s)
            except TimeoutError:
                log.warning("detonation.timeout", job_id=job.job_id, backend=self.backend.name, timeout_s=job.timeout_s)
                result = DetonationResult(
                    job_id=job.job_id,
                    status=DetonationStatus.TIMEOUT,
                    error=f"sandbox did not return within {job.timeout_s + self.grace_s}s",
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the backend is infrastructure; never let it take the worker down
                log.error("detonation.backend_error", job_id=job.job_id, backend=self.backend.name, error=str(exc))
                result = DetonationResult(
                    job_id=job.job_id,
                    status=DetonationStatus.ERROR,
                    error=f"{type(exc).__name__}: {exc}"[:500],
                )
        return self._finish(job, result, started)

    # -- policy ------------------------------------------------------------------

    async def _validate(self, job: DetonationJob) -> DetonationResult | None:
        if job.kind is DetonationKind.URL:
            decision = await decide_target(job.url, allow_private=self.allow_private_targets)
            if decision.allowed:
                return None
            status = DetonationStatus.ERROR if decision.reason == "dns_failure" else DetonationStatus.BLOCKED
            return DetonationResult(job_id=job.job_id, status=status, error=f"{decision.reason}: {decision.detail}")
        if job.kind is DetonationKind.FILE:
            if not job.file_ref:
                return DetonationResult(job_id=job.job_id, status=DetonationStatus.BLOCKED, error="no_file: file job without file_ref")
            if is_file_ref(job.file_ref):
                return DetonationResult(job_id=job.job_id, status=DetonationStatus.BLOCKED, error="bad_ref: file_ref must be an artifact reference")
            try:
                present = self.artifact_store.exists(job.file_ref)
            except ValueError as exc:
                return DetonationResult(job_id=job.job_id, status=DetonationStatus.BLOCKED, error=f"bad_ref: {exc}")
            if not present:
                return DetonationResult(job_id=job.job_id, status=DetonationStatus.ERROR, error=f"missing_file: {job.file_ref} is not in the artifact store")
            return None
        return DetonationResult(job_id=job.job_id, status=DetonationStatus.BLOCKED, error=f"unsupported job kind {job.kind!r}")  # pragma: no cover

    # -- finalization ----------------------------------------------------------------

    def _finish(self, job: DetonationJob, result: DetonationResult, started: float) -> DetonationResult:
        try:
            result = rehome(result, self.artifact_store)
        except Exception as exc:  # a broken store must not hide the detonation itself
            log.error("detonation.rehome_failed", job_id=job.job_id, error=str(exc))
            result = result.model_copy(update={"screenshot_ref": None})
            for d in result.downloads:
                d.stored_ref = None if is_file_ref(d.stored_ref) else d.stored_ref
                d.safe_copy_ref = None if is_file_ref(d.safe_copy_ref) else d.safe_copy_ref
            result.console_errors.append(f"host: artifact store failed: {exc}"[:300])
        result.job_id = job.job_id
        result.sandbox_backend = self.backend.name
        if result.duration_ms <= 0:
            result.duration_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "detonation.done",
            job_id=job.job_id,
            backend=self.backend.name,
            status=result.status.value,
            duration_ms=result.duration_ms,
            requests=len(result.requests),
            downloads=len(result.downloads),
        )
        return result


def make_chamber(settings: Settings, artifact_store: ArtifactStore) -> DetonationChamber:
    """Build the chamber the worker should use for ``settings``.

    * ``local``  - subprocess isolation; development only.
    * ``docker`` - hardened container on the dirty network (``RS_CHAMBER_IMAGE``,
      ``RS_CHAMBER_NETWORK`` env vars override the defaults).
    * ``aci``    - one Azure Container Instances group per detonation
      (``RS_ACI_SUBSCRIPTION_ID``, ``RS_ACI_RESOURCE_GROUP``, ``RS_ACI_SUBNET_ID``,
      optional ``RS_ACI_LOCATION``).

    Private targets are allowed only in the ``test`` environment or when
    ``RS_CHAMBER_ALLOW_PRIVATE=1`` is set explicitly; ``Settings`` has no field
    for it on purpose, so it cannot be switched on by a typo in ``.env``.
    """
    import os

    name = settings.sandbox_backend
    backend: SandboxBackend
    if name == "local":
        from .local import LocalProcessBackend

        backend = LocalProcessBackend(artifact_store)
    elif name == "docker":
        from .docker import DockerBackend

        backend = DockerBackend(
            artifact_store,
            image=os.environ.get("RS_CHAMBER_IMAGE", "reddysec-chamber:latest"),
            network=os.environ.get("RS_CHAMBER_NETWORK", "rs-detonation"),
        )
    elif name == "aci":
        from .azure_aci import AzureContainerInstancesBackend, RegistryCredential

        registry = None
        if os.environ.get("RS_ACI_REGISTRY_SERVER"):
            registry = RegistryCredential(
                server=os.environ["RS_ACI_REGISTRY_SERVER"],
                username=os.environ["RS_ACI_REGISTRY_USERNAME"],
                password=os.environ["RS_ACI_REGISTRY_PASSWORD"],
            )
        backend = AzureContainerInstancesBackend(
            artifact_store,
            subscription_id=os.environ["RS_ACI_SUBSCRIPTION_ID"],
            resource_group=os.environ["RS_ACI_RESOURCE_GROUP"],
            location=os.environ.get("RS_ACI_LOCATION", "westus2"),
            subnet_id=os.environ["RS_ACI_SUBNET_ID"],
            image=os.environ.get("RS_CHAMBER_IMAGE", "reddysec-chamber:latest"),
            registry=registry,
        )
    else:  # pragma: no cover - Settings already restricts the literal
        raise ValueError(f"unknown sandbox backend {name!r}")
    allow_private = settings.env == "test" or os.environ.get("RS_CHAMBER_ALLOW_PRIVATE") == "1"
    return DetonationChamber(
        backend,
        artifact_store,
        max_concurrency=settings.detonation_max_concurrency,
        default_timeout_s=settings.detonation_timeout_s,
        allow_private_targets=allow_private,
    )
