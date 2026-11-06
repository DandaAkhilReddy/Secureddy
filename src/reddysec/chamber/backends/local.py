"""Backends that run the detonation on this machine.

``LocalProcessBackend`` runs ``python -m reddysec.chamber.detonate`` as a
child process in its own session with a scrubbed environment and a throwaway
work directory. That buys crash isolation, a hard kill on timeout and no
access to our secrets - and nothing more. A page that exploits Chromium owns
the account the worker runs as. **Process isolation is for development.**
Production isolation is a hypervisor-isolated container per detonation
(``docker`` on a dedicated host with the seccomp profile, or ``azure_aci``).

``InProcessBackend`` calls ``detonate()`` directly in the worker's event loop.
It exists for fast tests and for debugging the sandbox code with a debugger
attached; it offers no isolation at all.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path

from reddysec.core.artifacts import ArtifactStore
from reddysec.core.logging import get_logger
from reddysec.models import DetonationJob, DetonationResult, DetonationStatus

from ..protocol import SandboxOutput, load_output, rehome, stage_job, write_job_files

log = get_logger(__name__)

# Variables the child may see. Everything else - and in particular every
# RS_* setting, cloud credentials and proxy variables - stays on the host.
ENV_PASSTHROUGH: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "PLAYWRIGHT_BROWSERS_PATH", "RS_CHAMBER_NO_SANDBOX")
DEFAULT_GRACE_S = 5
STDERR_TAIL = 2000


def scrubbed_environment(workdir: Path, source: dict[str, str] | None = None) -> dict[str, str]:
    """The minimal environment for the sandbox process.

    ``HOME`` and ``TMPDIR`` point at the work directory so Chromium's profile
    and temp files live (and die) there. Playwright locates browsers under
    ``$HOME/.cache/ms-playwright`` unless ``PLAYWRIGHT_BROWSERS_PATH`` says
    otherwise, so when the variable is absent we pin it to the host's default
    location - otherwise the relocated HOME would hide the browser.
    """
    source = os.environ if source is None else source
    env = {key: source[key] for key in ENV_PASSTHROUGH if key in source}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    env["HOME"] = str(workdir)
    env["TMPDIR"] = str(workdir)
    if "PLAYWRIGHT_BROWSERS_PATH" not in env:
        default_browsers = Path(source.get("HOME", Path.home())) / ".cache" / "ms-playwright"
        if default_browsers.is_dir():
            env["PLAYWRIGHT_BROWSERS_PATH"] = str(default_browsers)
    return env


class LocalProcessBackend:
    """Subprocess sandbox. See module docstring for what it does *not* protect against."""

    name = "local"

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        python: str = sys.executable,
        grace_s: int = DEFAULT_GRACE_S,
        keep_workdir: bool = False,
        workdir_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self.artifact_store = artifact_store
        self.python = python
        self.grace_s = grace_s
        self.keep_workdir = keep_workdir
        self.workdir_root = Path(workdir_root) if workdir_root else None

    def build_argv(self, job_path: Path, out_path: Path, workdir: Path) -> list[str]:
        return [
            self.python,
            "-m",
            "reddysec.chamber.detonate",
            "--job",
            str(job_path),
            "--out",
            str(out_path),
            "--workdir",
            str(workdir),
        ]

    async def run(self, job: DetonationJob) -> DetonationResult:
        if self.workdir_root is not None:
            self.workdir_root.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="rs-det-", dir=self.workdir_root))
        try:
            shipped, files = stage_job(job, self.artifact_store)
            write_job_files(files, workdir)
            job_path = workdir / "job.json"
            out_path = workdir / "result.json"
            job_path.write_text(shipped.model_dump_json(), encoding="utf-8")

            proc = await asyncio.create_subprocess_exec(
                *self.build_argv(job_path, out_path, workdir),
                cwd=str(workdir),
                env=scrubbed_environment(workdir),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            timed_out = False
            stderr = b""
            try:
                _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=job.timeout_s + self.grace_s)
            except TimeoutError:
                timed_out = True
                await _kill_process_group(proc)

            if out_path.is_file():
                output = load_output(out_path.read_text(encoding="utf-8"), workdir)
            else:
                output = SandboxOutput(
                    job_id=job.job_id,
                    status=DetonationStatus.TIMEOUT if timed_out else DetonationStatus.ERROR,
                    error=(
                        f"sandbox process killed after {job.timeout_s + self.grace_s}s"
                        if timed_out
                        else f"sandbox process exited with {proc.returncode} and no result: {_tail(stderr)}"
                    ),
                )
            if timed_out and output.status is DetonationStatus.OK:
                output.status = DetonationStatus.TIMEOUT
            return rehome(output, self.artifact_store)
        finally:
            if not self.keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)


async def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the child *and* everything it spawned (the Playwright driver and
    Chromium share its session), then reap it."""
    if proc.returncode is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:  # pragma: no cover - different uid; fall back to the child alone
        proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:  # pragma: no cover - the kernel did not reap a SIGKILLed process in 5s
        log.error("chamber.local.unreaped", pid=proc.pid)


def _tail(data: bytes) -> str:
    return data[-STDERR_TAIL:].decode("utf-8", errors="replace").strip()


class InProcessBackend:
    """Runs ``detonate()`` in the current process. Tests and debugging only."""

    name = "inprocess"

    def __init__(self, artifact_store: ArtifactStore, *, keep_workdir: bool = False) -> None:
        self.artifact_store = artifact_store
        self.keep_workdir = keep_workdir

    async def run(self, job: DetonationJob) -> DetonationResult:
        from ..detonate import detonate

        workdir = Path(tempfile.mkdtemp(prefix="rs-det-"))
        try:
            shipped, files = stage_job(job, self.artifact_store)
            write_job_files(files, workdir)
            result = await detonate(shipped, workdir)
            output = load_output(result.model_dump(mode="json"), workdir)
            return rehome(output, self.artifact_store)
        finally:
            if not self.keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)
