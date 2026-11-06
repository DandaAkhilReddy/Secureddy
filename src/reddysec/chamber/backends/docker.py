"""Docker backend: one hardened, throwaway container per detonation.

The container runs ``python -m reddysec.chamber.detonate --stdio`` from the
``reddysec-chamber`` image. The job envelope goes in on stdin, the result
envelope (result JSON + base64 files, one line) comes out on stdout, and the
container is gone when the process exits (``--rm``). Nothing is mounted.

Hardening, and why each flag is there:

``--network rs-detonation``   a "dirty" network whose egress rules drop RFC1918,
                              link-local and the host; the sandbox must only
                              reach the internet.
``--read-only`` + ``--tmpfs``  the image is immutable; ``/tmp`` and ``/work`` are
                              RAM-backed and vanish with the container.
``--cap-drop ALL``            Chromium needs no capabilities.
``--security-opt no-new-privileges``  no setuid escalation inside.
``--security-opt seccomp=seccomp-chamber.json``  Docker's default profile plus
                              the namespace syscalls Chromium's own sandbox
                              needs (clone with CLONE_NEWUSER/NEWPID/NEWNET,
                              unshare, setns); see the JSON file header.
``--pids-limit 256 --memory 2g --cpus 1.5``  a fork bomb or a crypto miner on
                              the page cannot take the host with it.
``--init``                    a real PID 1 reaps zombie renderer processes.
``-e RS_CHAMBER=1``           tells the entrypoint it is inside the chamber.

On timeout the client process is killed *and* ``docker rm -f <name>`` is
issued, because killing ``docker run`` alone leaves the container running.

Docker gives process-level isolation (a shared kernel). Run the daemon on a
dedicated host, or under a hypervisor-isolated runtime (Kata, gVisor), for
production; or use the ACI backend, which gets that boundary from Azure.
"""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

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

DEFAULT_IMAGE = "reddysec-chamber:latest"
DEFAULT_NETWORK = "rs-detonation"
DEFAULT_GRACE_S = 15
SECCOMP_PROFILE = Path(__file__).resolve().parents[1] / "seccomp-chamber.json"


@dataclass(frozen=True)
class RunOutcome:
    """What running a command produced."""

    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Runner = Callable[[list[str], bytes, float], Awaitable[RunOutcome]]


async def subprocess_runner(argv: list[str], stdin: bytes, timeout_s: float) -> RunOutcome:
    """Default runner: a real subprocess in its own session, killed as a
    group when ``timeout_s`` elapses."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout_s)
    except TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()
        return RunOutcome(proc.returncode, b"", b"", timed_out=True)
    return RunOutcome(proc.returncode, stdout, stderr)


class DockerBackend:
    name = "docker"

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        image: str = DEFAULT_IMAGE,
        network: str = DEFAULT_NETWORK,
        docker_bin: str = "docker",
        seccomp_profile: str | os.PathLike[str] = SECCOMP_PROFILE,
        runner: Runner | None = None,
        grace_s: int = DEFAULT_GRACE_S,
        memory: str = "2g",
        cpus: str = "1.5",
        pids_limit: int = 256,
        max_file_bytes: int | None = None,
    ) -> None:
        self.artifact_store = artifact_store
        self.image = image
        self.network = network
        self.docker_bin = docker_bin
        self.seccomp_profile = Path(seccomp_profile)
        self.runner: Runner = runner or subprocess_runner
        self.grace_s = grace_s
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.max_file_bytes = max_file_bytes

    # -- argv ----------------------------------------------------------------------

    @staticmethod
    def container_name(job: DetonationJob) -> str:
        safe = "".join(c if c.isalnum() or c in "_-" else "-" for c in job.job_id.lower())
        return f"rs-det-{safe}"[:63]

    def build_argv(self, job: DetonationJob) -> list[str]:
        argv = [
            self.docker_bin,
            "run",
            "--rm",
            "-i",
            "--name",
            self.container_name(job),
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={self.seccomp_profile}",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            self.memory,
            "--cpus",
            self.cpus,
            "--tmpfs",
            "/tmp:rw,size=512m",
            "--tmpfs",
            "/work:rw,size=1g",
            "-e",
            "RS_CHAMBER=1",
            "--init",
            self.image,
            "python",
            "-m",
            "reddysec.chamber.detonate",
            "--stdio",
            "--workdir",
            "/work",
        ]
        if self.max_file_bytes is not None:
            argv += ["--max-file-bytes", str(self.max_file_bytes)]
        return argv

    def kill_argv(self, job: DetonationJob) -> list[str]:
        return [self.docker_bin, "rm", "-f", self.container_name(job)]

    # -- run -------------------------------------------------------------------------

    async def run(self, job: DetonationJob) -> DetonationResult:
        shipped, files = stage_job(job, self.artifact_store)
        payload = (encode_job_envelope(shipped, files) + "\n").encode("utf-8")
        outcome = await self.runner(self.build_argv(job), payload, float(job.timeout_s + self.grace_s))

        if outcome.timed_out:
            log.warning("chamber.docker.timeout", job_id=job.job_id, container=self.container_name(job))
            try:
                await self.runner(self.kill_argv(job), b"", 30.0)
            except Exception as exc:  # best effort; the daemon may already have removed it
                log.error("chamber.docker.kill_failed", job_id=job.job_id, error=str(exc))
            output = SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.TIMEOUT,
                error=f"container did not finish within {job.timeout_s + self.grace_s}s and was removed",
            )
            return rehome(output, self.artifact_store)

        try:
            output = decode_result_envelope(outcome.stdout)
        except ProtocolError as exc:
            tail = outcome.stderr[-2000:].decode("utf-8", errors="replace").strip()
            output = SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.ERROR,
                error=f"container exited with {outcome.returncode}: {exc}; stderr: {tail}"[:1000],
            )
        return rehome(output, self.artifact_store)
