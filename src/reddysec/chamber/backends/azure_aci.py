"""Azure Container Instances backend: a fresh VM-isolated container group per
detonation.

Why ACI: every container group runs inside its own hypervisor-isolated
boundary that Azure creates for it and tears down afterwards. We create one
group per job, in a dedicated resource group and a VNet subnet whose network
security group denies all private ranges and the Azure metadata endpoint
(see ``infra/azure``), with no public IP. A page that fully compromises
Chromium ends up owning a VM that is deleted a minute later and can reach
nothing but the internet. That is the isolation story a Docker daemon on a
shared host cannot give.

Flow for one job::

    begin_create_or_update(rs-det-<job id>)   image, no IP, RS_JOB (secure env) = job envelope,
                                              command: python -m reddysec.chamber.detonate --env
    poll container_groups.get                 until the group / container has terminated
    containers.list_logs                      the last line is the result envelope (protocol.py)
    begin_delete                              always, in ``finally``

Transport limits: the job travels in a secure environment variable and the
result in container logs. Both are small channels, so FILE jobs larger than
``max_env_bytes`` are refused with an ERROR, and envelope files larger than
``max_file_bytes`` (default 1 MiB; a q60 screenshot is well under that) are
dropped with their hash kept. Blob-storage staging in both directions is the
obvious next step and is deliberately not in this version.

The Azure SDK (``azure-mgmt-containerinstance``, ``azure-identity``) is
imported lazily so this module - and ``make_chamber`` - import on machines
without it. Tests inject a duck-typed ``client`` and an identity
``model_factory``; the SDK path itself is the only thing left untested here.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from reddysec.core.artifacts import ArtifactStore
from reddysec.core.logging import get_logger
from reddysec.models import DetonationJob, DetonationResult, DetonationStatus

from ..protocol import (
    ProtocolError,
    SandboxOutput,
    decode_result_envelope,
    encode_job_envelope,
    rehome,
    stage_job,
)

log = get_logger(__name__)

@dataclass(frozen=True)
class RegistryCredential:
    """Pull credential for a private registry (a repository-scoped ACR token)."""

    server: str
    username: str
    password: str = field(repr=False)


CONTAINER_NAME = "chamber"
DEFAULT_GRACE_S = 120
DEFAULT_POLL_INTERVAL_S = 3.0
DEFAULT_MAX_ENV_BYTES = 48 * 1024
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
TERMINAL_GROUP_STATES = frozenset({"succeeded", "failed", "stopped", "terminated"})

_NAME_RE = re.compile(r"[^a-z0-9-]+")


def group_name_for(job: DetonationJob) -> str:
    """``rs-det-<job id lower>``, restricted to what ACI accepts (lower-case
    letters, digits and hyphens, at most 63 characters)."""
    body = _NAME_RE.sub("-", job.job_id.lower()).strip("-")
    return f"rs-det-{body}"[:63].rstrip("-")


class AzureContainerInstancesBackend:
    name = "aci"

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        subscription_id: str,
        resource_group: str,
        location: str,
        subnet_id: str,
        image: str,
        cpu: float = 1.5,
        memory_gb: float = 2.0,
        registry: RegistryCredential | None = None,
        client: Any | None = None,
        credential: Any | None = None,
        model_factory: Callable[[dict[str, Any]], Any] | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        grace_s: int = DEFAULT_GRACE_S,
        max_env_bytes: int = DEFAULT_MAX_ENV_BYTES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.artifact_store = artifact_store
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.location = location
        self.subnet_id = subnet_id
        self.image = image
        self.cpu = cpu
        self.memory_gb = memory_gb
        self.registry = registry
        self._client = client
        self._credential = credential
        self._model_factory = model_factory
        self.poll_interval_s = poll_interval_s
        self.grace_s = grace_s
        self.max_env_bytes = max_env_bytes
        self.max_file_bytes = max_file_bytes
        self._sleep = sleep
        self._clock = clock

    # -- SDK plumbing (lazy) ----------------------------------------------------------

    @property
    def client(self) -> Any:
        if self._client is None:  # pragma: no cover - real SDK only
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.containerinstance import ContainerInstanceManagementClient

            credential = self._credential or DefaultAzureCredential()
            self._client = ContainerInstanceManagementClient(credential, self.subscription_id)
        return self._client

    def _to_model(self, spec: dict[str, Any]) -> Any:
        if self._model_factory is not None:
            return self._model_factory(spec)
        from azure.mgmt.containerinstance.models import ContainerGroup  # pragma: no cover - real SDK only

        return ContainerGroup.from_dict(spec)  # pragma: no cover - real SDK only

    # -- spec ----------------------------------------------------------------------------

    def build_group_spec(self, job: DetonationJob, envelope: str) -> dict[str, Any]:
        """The container group, in the REST (JSON) shape of the ACI API.

        The registry is Entra-only (no admin user, no anonymous pull) and Azure
        Policy in the detonation resource group denies managed identities on
        container groups, so the image is pulled with a repository-scoped ACR
        token (``RS_ACI_REGISTRY_*``) that can do nothing but pull this image."""
        properties: dict[str, Any] = {
            "osType": "Linux",
            "sku": "Standard",
            "restartPolicy": "Never",
            "subnetIds": [{"id": self.subnet_id}],
        }
        if self.registry is not None:
            properties["imageRegistryCredentials"] = [
                {
                    "server": self.registry.server,
                    "username": self.registry.username,
                    "password": self.registry.password,
                }
            ]
        return {
            "location": self.location,
            "tags": {"reddysec": "detonation", "job_id": job.job_id},
            "properties": {
                **properties,
                "volumes": [{"name": "work", "emptyDir": {}}],
                "containers": [
                    {
                        "name": CONTAINER_NAME,
                        "properties": {
                            "image": self.image,
                            "command": [
                                "python",
                                "-m",
                                "reddysec.chamber.detonate",
                                "--env",
                                "--workdir",
                                "/work",
                                "--max-file-bytes",
                                str(self.max_file_bytes),
                            ],
                            "environmentVariables": [
                                {"name": "RS_JOB", "secureValue": envelope},
                                {"name": "RS_CHAMBER", "value": "1"},
                            ],
                            "resources": {"requests": {"cpu": self.cpu, "memoryInGB": self.memory_gb}},
                            "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                        },
                    }
                ],
            },
        }

    # -- run --------------------------------------------------------------------------------

    async def run(self, job: DetonationJob) -> DetonationResult:
        shipped, files = stage_job(job, self.artifact_store)
        envelope = encode_job_envelope(shipped, files)
        if len(envelope) > self.max_env_bytes:
            output = SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.ERROR,
                error=f"job envelope of {len(envelope)} bytes exceeds the ACI environment budget of {self.max_env_bytes}",
            )
            return rehome(output, self.artifact_store)

        name = group_name_for(job)
        budget = float(job.timeout_s + self.grace_s)
        try:
            output = await asyncio.wait_for(self._create_and_wait(job, name, envelope), timeout=budget)
        except TimeoutError:
            log.warning("chamber.aci.timeout", job_id=job.job_id, group=name, budget_s=budget)
            output = SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.TIMEOUT,
                error=f"container group {name} did not terminate within {budget:.0f}s",
            )
        except Exception as exc:
            log.error("chamber.aci.error", job_id=job.job_id, group=name, error=str(exc))
            output = SandboxOutput(job_id=job.job_id, status=DetonationStatus.ERROR, error=f"{type(exc).__name__}: {exc}"[:1000])
        finally:
            # Always: a half-created group costs money and keeps a VM alive.
            # Deleting one that never came into existence is a harmless 404.
            await self._delete(name)
        return rehome(output, self.artifact_store)

    async def _create_and_wait(self, job: DetonationJob, name: str, envelope: str) -> SandboxOutput:
        spec = self._to_model(self.build_group_spec(job, envelope))
        poller = await asyncio.to_thread(self.client.container_groups.begin_create_or_update, self.resource_group, name, spec)
        await asyncio.to_thread(poller.result)

        while True:
            group = await asyncio.to_thread(self.client.container_groups.get, self.resource_group, name)
            if _is_terminal(group):
                break
            await self._sleep(self.poll_interval_s)

        logs = await asyncio.to_thread(self.client.containers.list_logs, self.resource_group, name, CONTAINER_NAME)
        content = getattr(logs, "content", None) or ""
        try:
            return decode_result_envelope(content)
        except ProtocolError as exc:
            return SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.ERROR,
                error=f"container group {name} ended in state {_group_state(group)!r} without a result: {exc}",
            )

    async def _delete(self, name: str) -> None:
        try:
            await asyncio.to_thread(self.client.container_groups.begin_delete, self.resource_group, name)
        except Exception as exc:  # the group may never have been created
            log.error("chamber.aci.delete_failed", group=name, error=str(exc))


def _group_state(group: Any) -> str:
    view = getattr(group, "instance_view", None)
    return str(getattr(view, "state", None) or "").lower()


def _is_terminal(group: Any) -> bool:
    if _group_state(group) in TERMINAL_GROUP_STATES:
        return True
    for container in getattr(group, "containers", None) or []:
        view = getattr(container, "instance_view", None)
        current = getattr(view, "current_state", None)
        if str(getattr(current, "state", None) or "").lower() == "terminated":
            return True
    return False
