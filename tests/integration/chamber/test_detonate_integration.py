"""Integration tests: real headless Chromium against the local evil site.

Marked ``integration`` (they launch a browser and bind ports). Most run
through ``InProcessBackend`` for speed; a couple run through
``LocalProcessBackend`` to prove the subprocess path and environment
scrubbing. The chamber wrapper is used so screenshots land in the artifact
store, exactly as in production.
"""

from __future__ import annotations

import pytest

from reddysec.chamber.backends.base import DetonationChamber
from reddysec.chamber.backends.local import InProcessBackend, LocalProcessBackend
from reddysec.models import DetonationJob, DetonationKind, DetonationProfile, DetonationStatus

pytestmark = pytest.mark.integration

FAST = DetonationProfile(max_wait_ms=2000, interact=False)


def chamber(store, backend=None):
    return DetonationChamber(backend or InProcessBackend(store), store, max_concurrency=2, allow_private_targets=True)


def url_job(site, path, job_id="det_it", timeout_s=20, profile=FAST):
    return DetonationJob(job_id=job_id, kind=DetonationKind.URL, url=site.url(path), timeout_s=timeout_s, profile=profile)


class TestPhishLogin:
    async def test_credential_harvest_page(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/phish-login"))
        assert result.status is DetonationStatus.OK
        features = result.features
        assert features.has_password_field is True
        assert features.external_form_action is True  # form posts to the other host
        assert "chase" in features.brand_keywords
        # screenshot was captured and re-homed into the artifact store
        assert result.screenshot_ref and result.screenshot_ref.startswith("local:")
        assert store.exists(result.screenshot_ref)
        assert store.get(result.screenshot_ref)[:3] == b"\xff\xd8\xff"  # JPEG
        # the form's action host differs from the page host
        form = features.forms[0]
        assert form.has_password and form.has_identity_field


class TestRedirects:
    async def test_http_redirect_chain(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/redirect-chain"))
        assert result.status is DetonationStatus.OK
        assert len(result.redirects) >= 2
        assert result.redirects[0].kind == "http"
        assert result.features.final_host == "localhost"  # ended on the other host
        # at least one hop carried a 302
        assert any(h.status == 302 for h in result.redirects)

    async def test_meta_refresh(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/meta-refresh"))
        assert result.features.meta_refresh is True
        assert result.features.final_url.endswith("/final")
        assert any(h.kind == "meta" for h in result.redirects)

    async def test_js_redirect(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/js-redirect"))
        assert result.features.js_redirect is True
        assert result.features.final_url.endswith("/final")
        assert any(h.kind == "js" for h in result.redirects)


class TestDownloads:
    async def test_executable_download(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/download"))
        assert len(result.downloads) == 1
        dl = result.downloads[0]
        assert dl.suggested_filename == "invoice.exe"
        assert len(dl.sha256) == 64
        assert dl.sniffed_type == "pe"
        assert dl.stored_ref and store.exists(dl.stored_ref)
        assert store.get(dl.stored_ref)[:2] == b"MZ"

    async def test_pdf_download(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/pdf-download"))
        assert len(result.downloads) == 1
        assert result.downloads[0].sniffed_type == "pdf"
        assert len(result.downloads[0].sha256) == 64


class TestContentSignals:
    async def test_obfuscated_javascript(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/obfuscated"))
        assert result.features.obfuscated_js_score > 50

    async def test_captcha_detected(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/captcha"))
        assert result.features.captcha_detected is True

    async def test_qr_code_decoded(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/qr"))
        assert any(url.endswith("/phish-login") for url in result.features.qr_codes)

    async def test_hidden_text_ratio(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/hidden-text"))
        assert result.features.hidden_text_ratio > 0.5

    async def test_benign_page_is_clean(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/benign"))
        assert result.status is DetonationStatus.OK
        assert result.features.has_password_field is False
        assert result.features.brand_keywords == []
        assert result.features.obfuscated_js_score < 30
        assert result.features.captcha_detected is False


class TestTimeout:
    async def test_slow_page_times_out(self, store, evil_site):
        # /slow sleeps 20s; a 5s job must come back TIMEOUT within the grace.
        import time

        chm = DetonationChamber(InProcessBackend(store), store, allow_private_targets=True, grace_s=5)
        started = time.monotonic()
        result = await chm.detonate(url_job(evil_site, "/slow", timeout_s=5, profile=DetonationProfile(max_wait_ms=15000, interact=False)))
        elapsed = time.monotonic() - started
        assert result.status is DetonationStatus.TIMEOUT
        assert elapsed < 5 + 5 + 3  # timeout_s + grace_s + slack


class TestFileJobs:
    async def test_html_attachment_cannot_phone_home(self, store, evil_site):
        # A FILE job opens from file:// with all non-file requests aborted, so
        # the beacons in the fixture must never reach the server.
        html = evil_site.exfil_fixture_html().encode()
        ref = store.put(html, ".html")
        before = len(evil_site.hits_matching("/beacon"))
        job = DetonationJob(
            job_id="det_file_html",
            kind=DetonationKind.FILE,
            file_ref=ref,
            file_name="shared-document.html",
            timeout_s=15,
            profile=DetonationProfile(max_wait_ms=1500, interact=False),
        )
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.OK
        # No request recorded to any non-file scheme.
        assert all(r.url.startswith("file:") for r in result.requests)
        # And the server saw no new beacon hits.
        assert len(evil_site.hits_matching("/beacon")) == before
        assert evil_site.hits_matching("/beacon") == []

    async def test_pdf_attachment_rendered(self, store, evil_site):
        from .evil_server import pdf_with_javascript

        ref = store.put(pdf_with_javascript("Chase account statement"), ".pdf")
        job = DetonationJob(
            job_id="det_file_pdf",
            kind=DetonationKind.FILE,
            file_ref=ref,
            file_name="statement.pdf",
            timeout_s=15,
            profile=DetonationProfile(max_wait_ms=1500, interact=False),
        )
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.OK
        assert result.features is not None
        assert "chase" in result.features.brand_keywords  # text extracted from the PDF
        assert result.screenshot_ref and store.exists(result.screenshot_ref)

    async def test_executable_attachment_not_detonated(self, store, evil_site):
        ref = store.put(b"MZ\x90\x00" + b"\x00" * 100, ".bin")
        job = DetonationJob(job_id="det_file_exe", kind=DetonationKind.FILE, file_ref=ref, file_name="invoice.exe", timeout_s=15)
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.OK
        assert result.features is None  # not browser-viewable
        assert any("not detonated" in e for e in result.console_errors)


class TestBrowserBehaviours:
    async def test_interaction_path(self, store, evil_site):
        # interact=True drives mouse + scroll; the page must still be read.
        job = url_job(evil_site, "/benign", profile=DetonationProfile(max_wait_ms=1500, interact=True))
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.OK
        assert result.features.title == "Quarterly newsletter"

    async def test_dialog_does_not_hang(self, store, evil_site):
        # /dialog calls alert() on load; the chamber dismisses it and reads on.
        result = await chamber(store).detonate(url_job(evil_site, "/dialog", timeout_s=15))
        assert result.status is DetonationStatus.OK
        assert "after the alert" in result.features.text_excerpt

    async def test_forbidden_sets_blocked_hint(self, store, evil_site):
        result = await chamber(store).detonate(url_job(evil_site, "/forbidden"))
        # 403 with an (empty) body sets the automation-blocked hint and records the status.
        assert result.features is not None
        assert result.features.status_code == 403
        assert result.features.automation_blocked_hint is True


class TestCli:
    async def test_cli_job_to_out_file(self, store, evil_site, tmp_path):
        # Exercise the --job/--out CLI path end to end (what the local backend
        # spawns), against the benign page.
        import asyncio

        from reddysec.chamber.detonate import main
        from reddysec.models import DetonationResult

        job = DetonationJob(
            job_id="det_cli",
            kind=DetonationKind.URL,
            url=evil_site.url("/benign"),
            timeout_s=20,
            profile=DetonationProfile(max_wait_ms=1500, interact=False),
        )
        job_path = tmp_path / "job.json"
        out_path = tmp_path / "out.json"
        work = tmp_path / "work"
        job_path.write_text(job.model_dump_json())
        rc = await asyncio.to_thread(main, ["--job", str(job_path), "--out", str(out_path), "--workdir", str(work)])
        assert rc == 0
        result = DetonationResult.model_validate_json(out_path.read_text())
        assert result.status is DetonationStatus.OK
        assert result.features.title == "Quarterly newsletter"
        assert result.screenshot_ref == "file:screenshot.jpg"
        assert (work / "screenshot.jpg").is_file()

    async def test_cli_stdio(self, store, evil_site, tmp_path, capsys):
        # The Docker path: a job envelope on stdin, a result envelope on stdout.
        import asyncio
        import sys

        from reddysec.chamber.detonate import main
        from reddysec.chamber.protocol import decode_result_envelope, encode_job_envelope

        job = DetonationJob(
            job_id="det_stdio",
            kind=DetonationKind.URL,
            url=evil_site.url("/download"),
            timeout_s=20,
            profile=DetonationProfile(max_wait_ms=1500, interact=False),
        )

        def run_stdio():
            import io

            sys.stdin = io.StringIO(encode_job_envelope(job) + "\n")
            try:
                return main(["--stdio", "--workdir", str(tmp_path / "work")])
            finally:
                sys.stdin = sys.__stdin__

        rc = await asyncio.to_thread(run_stdio)
        assert rc == 0
        out = capsys.readouterr().out
        output = decode_result_envelope(out)
        assert output.status is DetonationStatus.OK
        # the downloaded exe came back in the envelope's files
        assert output.downloads and output.downloads[0].sniffed_type == "pe"
        name = output.downloads[0].stored_ref[len("file:") :]
        assert output.files[name][:2] == b"MZ"

    async def test_cli_env(self, store, evil_site, tmp_path, monkeypatch, capsys):
        # The ACI path: the job envelope arrives in RS_JOB.
        import asyncio

        from reddysec.chamber.detonate import main
        from reddysec.chamber.protocol import decode_result_envelope, encode_job_envelope

        job = DetonationJob(
            job_id="det_env",
            kind=DetonationKind.URL,
            url=evil_site.url("/benign"),
            timeout_s=20,
            profile=DetonationProfile(max_wait_ms=1500, interact=False),
        )
        monkeypatch.setenv("RS_JOB", encode_job_envelope(job))
        rc = await asyncio.to_thread(main, ["--env", "--workdir", str(tmp_path / "work")])
        assert rc == 0
        output = decode_result_envelope(capsys.readouterr().out)
        assert output.status is DetonationStatus.OK and output.features.title == "Quarterly newsletter"


class TestLocalProcessBackend:
    """The subprocess path: isolation, env scrubbing, and a real result."""

    async def test_detonates_in_subprocess(self, store, evil_site):
        chm = chamber(store, LocalProcessBackend(store))
        result = await chm.detonate(url_job(evil_site, "/phish-login", job_id="det_subproc"))
        assert result.status is DetonationStatus.OK
        assert result.sandbox_backend == "local"
        assert result.features.has_password_field is True
        assert result.screenshot_ref and store.exists(result.screenshot_ref)

    async def test_subprocess_download_rehomed(self, store, evil_site):
        chm = chamber(store, LocalProcessBackend(store))
        result = await chm.detonate(url_job(evil_site, "/download", job_id="det_subproc_dl"))
        assert result.downloads and result.downloads[0].sniffed_type == "pe"
        assert store.exists(result.downloads[0].stored_ref)

    def test_environment_is_scrubbed(self):
        from reddysec.chamber.backends.local import scrubbed_environment

        source = {"PATH": "/usr/bin", "HOME": "/root", "RS_SECRET_KEY": "top-secret", "RS_TOKEN_KEK": "kek", "LANG": "en_US.UTF-8", "AWS_SECRET_ACCESS_KEY": "aws"}
        env = scrubbed_environment(__import__("pathlib").Path("/tmp/work"), source)
        assert "RS_SECRET_KEY" not in env
        assert "RS_TOKEN_KEK" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert env["HOME"] == "/tmp/work" and env["TMPDIR"] == "/tmp/work"
        assert env["PATH"] == "/usr/bin"
