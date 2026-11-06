"""How results travel from inside a sandbox back to the host.

Inside the sandbox ``detonate()`` has a scratch directory and nothing else: no
artifact store, no database, no secrets. It therefore writes binary outputs
(the screenshot, downloaded files) as plain files and references them from
the result JSON with ``file:<relative path>``::

    {"screenshot_ref": "file:screenshot.jpg",
     "downloads": [{"stored_ref": "file:dl_0.bin", ...}]}

Each backend moves those bytes across its own boundary (shared directory for
the local process, stdout for Docker, container logs for ACI) using the
single-line *envelope* defined here::

    {"v": 1, "result": {<DetonationResult>}, "files": {"screenshot.jpg": "<base64>", ...}}

and the host finally *re-homes* every ``file:`` reference into the artifact
store (``rehome``), so nothing that leaves this package ever carries a
sandbox path.

Input travels the other way in a sibling envelope::

    {"v": 1, "job": {<DetonationJob>}, "files": {"input/invoice.pdf": "<base64>"}}

A FILE job's ``file_ref`` is rewritten by the host to ``file:input/<name>``
before the job enters the sandbox, because the sandbox cannot read the store.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from pydantic import Field

from reddysec.core.artifacts import ArtifactStore
from reddysec.models import DetonationJob, DetonationResult

from .common import safe_filename

PROTOCOL_VERSION = 1
FILE_SCHEME = "file:"
SCREENSHOT_NAME = "screenshot.jpg"
INPUT_DIR = "input"


class ProtocolError(ValueError):
    """The sandbox produced output we refuse to interpret."""


class SandboxOutput(DetonationResult):
    """A DetonationResult that still carries its binary outputs in memory.

    ``files`` is excluded from serialization on purpose (like
    ``Attachment.data``): bytes never travel through JSON by accident, only
    through the explicit envelope functions below.
    """

    files: dict[str, bytes] = Field(default_factory=dict, exclude=True, repr=False)


# --- path helpers -----------------------------------------------------------


def is_file_ref(ref: str | None) -> bool:
    return bool(ref) and ref.startswith(FILE_SCHEME)  # type: ignore[union-attr]


def file_ref_name(ref: str) -> str:
    """The relative path inside a ``file:`` reference, validated against
    traversal: the sandbox is hostile territory and names it chose are data."""
    if not is_file_ref(ref):
        raise ProtocolError(f"not a file reference: {ref!r}")
    rel = ref[len(FILE_SCHEME) :]
    parts = rel.split("/")
    if not rel or rel.startswith("/") or any(p in ("", ".", "..") for p in parts) or "\\" in rel:
        raise ProtocolError(f"unsafe file reference: {ref!r}")
    return rel


def input_file_ref(file_name: str | None) -> str:
    """Where a FILE job's bytes live inside the sandbox work directory."""
    return f"{FILE_SCHEME}{INPUT_DIR}/{safe_filename(file_name, default='attachment.bin')}"


def _referenced_files(result: DetonationResult) -> list[str]:
    names: list[str] = []
    if is_file_ref(result.screenshot_ref):
        names.append(file_ref_name(result.screenshot_ref))  # type: ignore[arg-type]
    for d in result.downloads:
        if is_file_ref(d.stored_ref):
            names.append(file_ref_name(d.stored_ref))  # type: ignore[arg-type]
        if is_file_ref(d.safe_copy_ref):
            names.append(file_ref_name(d.safe_copy_ref))  # type: ignore[arg-type]
    return names


# --- loading results produced on disk ----------------------------------------


def load_output(result_json: str | bytes | dict[str, Any], workdir: Path) -> SandboxOutput:
    """Parse a result written by ``detonate`` and pull its ``file:`` outputs
    from ``workdir`` into memory. Missing files are tolerated (the reference is
    cleared and noted) so a partial result after a crash is still useful."""
    data = json.loads(result_json) if not isinstance(result_json, dict) else result_json
    output = SandboxOutput.model_validate(data)
    for name in _referenced_files(output):
        path = workdir / name
        if path.is_file():
            output.files[name] = path.read_bytes()
    return _drop_missing(output)


def _drop_missing(output: SandboxOutput) -> SandboxOutput:
    """Clear ``file:`` refs whose bytes did not make it across the boundary."""
    if is_file_ref(output.screenshot_ref) and file_ref_name(output.screenshot_ref) not in output.files:  # type: ignore[arg-type]
        output.console_errors.append(f"sandbox: screenshot {output.screenshot_ref} was not produced")
        output.screenshot_ref = None
    for d in output.downloads:
        if is_file_ref(d.stored_ref) and file_ref_name(d.stored_ref) not in output.files:  # type: ignore[arg-type]
            output.console_errors.append(f"sandbox: download bytes {d.stored_ref} were not produced")
            d.stored_ref = None
        if is_file_ref(d.safe_copy_ref) and file_ref_name(d.safe_copy_ref) not in output.files:  # type: ignore[arg-type]
            d.safe_copy_ref = None
    return output


# --- envelopes --------------------------------------------------------------


def encode_result_envelope(output: SandboxOutput, *, max_file_bytes: int | None = None) -> str:
    """One line of JSON carrying the result and its files (base64).

    ``max_file_bytes`` lets a transport with a small payload budget (ACI
    container logs) drop oversized files instead of producing an envelope the
    other side cannot read; the dropped reference is cleared and noted.
    """
    files: dict[str, str] = {}
    keep = output.model_copy(deep=True)
    keep.files = dict(output.files)
    for name in _referenced_files(keep):
        blob = keep.files.get(name)
        if blob is None:
            continue
        if max_file_bytes is not None and len(blob) > max_file_bytes:
            keep.files.pop(name, None)
            keep.console_errors.append(f"transport: {name} ({len(blob)} bytes) exceeds the {max_file_bytes}-byte budget")
            continue
        files[name] = base64.b64encode(blob).decode("ascii")
    keep = _drop_missing(keep)
    body = {"v": PROTOCOL_VERSION, "result": keep.model_dump(mode="json"), "files": files}
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True)


def decode_result_envelope(text: str | bytes) -> SandboxOutput:
    """Find the envelope in ``text`` (the last line that parses as one) and
    return it with files decoded. Sandboxes are noisy - Chromium and
    LibreOffice write to stdout/stderr - so the result is always the last
    well-formed line, and everything else is ignored."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            body = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(body, dict) and body.get("v") == PROTOCOL_VERSION and "result" in body:
            return _envelope_to_output(body)
    raise ProtocolError("no result envelope found in sandbox output")


def _envelope_to_output(body: dict[str, Any]) -> SandboxOutput:
    try:
        output = SandboxOutput.model_validate(body["result"])
    except Exception as exc:  # pydantic.ValidationError or TypeError
        raise ProtocolError(f"malformed result in envelope: {exc}") from exc
    files = body.get("files")
    if files is None:
        files = {}
    elif not isinstance(files, dict):
        raise ProtocolError("envelope 'files' must be an object")
    for name, b64 in files.items():
        try:
            file_ref_name(FILE_SCHEME + str(name))
            output.files[str(name)] = base64.b64decode(b64, validate=True)
        except (ProtocolError, binascii.Error, TypeError) as exc:
            output.console_errors.append(f"transport: dropped file {name!r}: {exc}")
    return _drop_missing(output)


def encode_job_envelope(job: DetonationJob, files: dict[str, bytes] | None = None) -> str:
    body = {
        "v": PROTOCOL_VERSION,
        "job": job.model_dump(mode="json"),
        "files": {name: base64.b64encode(blob).decode("ascii") for name, blob in (files or {}).items()},
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True)


def decode_job_envelope(text: str | bytes) -> tuple[DetonationJob, dict[str, bytes]]:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    try:
        body = json.loads(text.strip().splitlines()[-1] if text.strip() else "")
    except (json.JSONDecodeError, IndexError) as exc:
        raise ProtocolError(f"malformed job envelope: {exc}") from exc
    if not isinstance(body, dict) or body.get("v") != PROTOCOL_VERSION or "job" not in body:
        raise ProtocolError("not a job envelope")
    try:
        job = DetonationJob.model_validate(body["job"])
    except Exception as exc:
        raise ProtocolError(f"malformed job in envelope: {exc}") from exc
    files: dict[str, bytes] = {}
    for name, b64 in (body.get("files") or {}).items():
        rel = file_ref_name(FILE_SCHEME + str(name))
        try:
            files[rel] = base64.b64decode(b64, validate=True)
        except (binascii.Error, TypeError) as exc:
            raise ProtocolError(f"bad base64 for {name!r}") from exc
    return job, files


def write_job_files(files: dict[str, bytes], workdir: Path) -> None:
    """Materialize job input files under ``workdir`` (names already validated)."""
    for name, blob in files.items():
        target = workdir / file_ref_name(FILE_SCHEME + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)


def stage_job(job: DetonationJob, store: ArtifactStore) -> tuple[DetonationJob, dict[str, bytes]]:
    """Prepare ``job`` for the sandbox: a FILE job's artifact is fetched from
    the store and its ``file_ref`` rewritten to the in-sandbox path. URL jobs
    pass through untouched. Returns the job to ship and the files to ship with it."""
    if job.file_ref is None or is_file_ref(job.file_ref):
        return job, {}
    data = store.get(job.file_ref)
    ref = input_file_ref(job.file_name)
    return job.model_copy(update={"file_ref": ref}), {file_ref_name(ref): data}


# --- re-homing into the artifact store ---------------------------------------

_SUFFIX_FOR = {"screenshot": ".jpg", "download": ".bin", "safe_copy": ".pdf"}


def rehome(output: DetonationResult, store: ArtifactStore) -> DetonationResult:
    """Store every in-memory file of ``output`` and rewrite its ``file:``
    references to artifact references. Returns a plain ``DetonationResult``.

    Downloads are stored with a neutral ``.bin`` suffix on purpose: an
    artifact directory full of ``invoice.exe`` files is a hazard for whoever
    administers the host, and the original name is kept in the record.
    """
    files = output.files if isinstance(output, SandboxOutput) else {}
    result = DetonationResult.model_validate(output.model_dump(mode="python"))

    def _store(ref: str | None, kind: str) -> str | None:
        if not is_file_ref(ref):
            return ref
        name = file_ref_name(ref)  # type: ignore[arg-type]
        blob = files.get(name)
        if blob is None:
            result.console_errors.append(f"host: {kind} {ref} had no bytes to store")
            return None
        return store.put(blob, _SUFFIX_FOR[kind])

    result.screenshot_ref = _store(result.screenshot_ref, "screenshot")
    for d in result.downloads:
        d.stored_ref = _store(d.stored_ref, "download")
        d.safe_copy_ref = _store(d.safe_copy_ref, "safe_copy")
    return result
