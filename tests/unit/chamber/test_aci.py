"""Unit tests for the Azure ACI backend with a fake, duck-typed SDK client.

The real ``azure.mgmt.containerinstance`` is never imported: the backend takes
an injected ``client`` and a ``model_factory`` (so the spec stays a dict).
"""

from __future__ import annotations

from reddysec.chamber.backends.azure_aci import AzureContainerInstancesBackend, group_name_for
from reddysec.chamber.protocol import SandboxOutput, decode_job_envelope, encode_result_envelope
from reddysec.models import DetonationJob, DetonationKind, DetonationStatus, PageFeatures

# --- fake SDK ------------------------------------------------------------------------


class FakeState:
    def __init__(self, state):
        self.state = state


class FakeContainerView:
    def __init__(self, state):
        self.current_state = FakeState(state)


class FakeContainer:
    def __init__(self, state):
        self.instance_view = FakeContainerView(state)


class FakeGroup:
    def __init__(self, group_state=None, container_state=None):
        self.instance_view = FakeState(group_state) if group_state else None
        self.containers = [FakeContainer(container_state)] if container_state else []


class FakePoller:
    def __init__(self, value=None):
        self._value = value

    def result(self, *a, **k):
        return self._value


class FakeLogs:
    def __init__(self, content):
        self.content = content


class FakeContainerGroups:
    def __init__(self, states, logs_content):
        self._states = list(states)  # list of FakeGroup returned by successive get()
        self._logs = logs_content
        self.created: list[tuple[str, str, object]] = []
        self.deleted: list[str] = []
        self.gets = 0
        self.delete_error: Exception | None = None

    def begin_create_or_update(self, rg, name, spec):
        self.created.append((rg, name, spec))
        return FakePoller()

    def get(self, rg, name):
        self.gets += 1
        index = min(self.gets - 1, len(self._states) - 1)
        return self._states[index]

    def begin_delete(self, rg, name):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(name)
        return FakePoller()


class FakeContainers:
    def __init__(self, logs_content):
        self._logs = logs_content
        self.listed: list[str] = []

    def list_logs(self, rg, name, container):
        self.listed.append(container)
        return FakeLogs(self._logs)


class FakeClient:
    def __init__(self, states, logs_content):
        self.container_groups = FakeContainerGroups(states, logs_content)
        self.containers = FakeContainers(logs_content)


def make_backend(store, states, logs_content, **kw):
    async def no_sleep(_s):
        return None

    return AzureContainerInstancesBackend(
        store,
        subscription_id="sub-1",
        resource_group="rg-detonation",
        location="westus2",
        subnet_id="/subscriptions/sub-1/.../subnets/detonation",
        image="reddysec-chamber:latest",
        client=FakeClient(states, logs_content),
        model_factory=lambda spec: spec,  # keep the spec a plain dict for assertions
        sleep=no_sleep,
        **kw,
    )


def url_job(job_id="det_XYZ", **kw):
    return DetonationJob(job_id=job_id, kind=DetonationKind.URL, url="https://example.com", **kw)


# --- tests --------------------------------------------------------------------------------


class TestGroupName:
    def test_lowercased_and_sanitized(self):
        assert group_name_for(url_job(job_id="det_AbC123")) == "rs-det-det_abc123".replace("_", "-")

    def test_bounded_to_63(self):
        assert len(group_name_for(url_job(job_id="det_" + "Z" * 90))) <= 63


class TestSpec:
    def test_spec_shape(self, store):
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], "")
        job = url_job()
        from reddysec.chamber.protocol import encode_job_envelope

        spec = backend.build_group_spec(job, encode_job_envelope(job))
        props = spec["properties"]
        assert props["restartPolicy"] == "Never"
        assert props["subnetIds"] == [{"id": backend.subnet_id}]
        assert "ipAddress" not in props  # no public IP
        container = props["containers"][0]["properties"]
        assert container["command"][:4] == ["python", "-m", "reddysec.chamber.detonate", "--env"]
        env = {e["name"]: e for e in container["environmentVariables"]}
        assert "secureValue" in env["RS_JOB"]  # the job envelope is a secret
        assert env["RS_CHAMBER"]["value"] == "1"
        assert container["resources"]["requests"] == {"cpu": 1.5, "memoryInGB": 2.0}


class TestRunLifecycle:
    async def test_success_creates_polls_reads_deletes(self, store):
        out = SandboxOutput(job_id="det_XYZ", status=DetonationStatus.OK, features=PageFeatures(title="hi", status_code=200))
        logs = "startup chatter\n" + encode_result_envelope(out)
        states = [FakeGroup(container_state="Running"), FakeGroup(container_state="Terminated")]
        backend = make_backend(store, states, logs)
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.OK and result.features.title == "hi"
        assert backend.client.container_groups.created  # created
        assert backend.client.containers.listed == ["chamber"]  # logs read
        assert backend.client.container_groups.deleted == [group_name_for(url_job())]  # deleted

    async def test_job_envelope_in_secure_env(self, store):
        out = SandboxOutput(job_id="det_XYZ", status=DetonationStatus.OK)
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], encode_result_envelope(out))
        await backend.run(url_job())
        _rg, _name, spec = backend.client.container_groups.created[0]
        env = {e["name"]: e for e in spec["properties"]["containers"][0]["properties"]["environmentVariables"]}
        job, _files = decode_job_envelope(env["RS_JOB"]["secureValue"])
        assert job.job_id == "det_XYZ"

    async def test_group_level_terminal_state(self, store):
        out = SandboxOutput(job_id="det_XYZ", status=DetonationStatus.OK)
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], encode_result_envelope(out))
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.OK

    async def test_deletes_even_when_logs_have_no_result(self, store):
        states = [FakeGroup(container_state="Terminated")]
        backend = make_backend(store, states, "the container crashed, no envelope here")
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.ERROR
        assert backend.client.container_groups.deleted == [group_name_for(url_job())]

    async def test_deadline_expiry_yields_timeout_and_deletes(self, store):
        # get() never returns a terminal state -> _create_and_wait loops until
        # the outer wait_for deadline fires.
        backend = make_backend(store, [FakeGroup(container_state="Running")], "", grace_s=0, poll_interval_s=0.01)
        result = await backend.run(url_job(timeout_s=0))
        # timeout_s floored by model? job.timeout_s=0 -> budget 0 -> immediate timeout
        assert result.status is DetonationStatus.TIMEOUT
        assert backend.client.container_groups.deleted == [group_name_for(url_job())]

    async def test_delete_failure_is_swallowed(self, store):
        out = SandboxOutput(job_id="det_XYZ", status=DetonationStatus.OK)
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], encode_result_envelope(out))
        backend.client.container_groups.delete_error = RuntimeError("already gone")
        result = await backend.run(url_job())  # must not raise
        assert result.status is DetonationStatus.OK

    async def test_create_failure_becomes_error_and_still_deletes(self, store):
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], "")

        def boom(rg, name, spec):
            raise RuntimeError("quota exceeded")

        backend.client.container_groups.begin_create_or_update = boom
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.ERROR and "quota exceeded" in result.error
        assert backend.client.container_groups.deleted == [group_name_for(url_job())]

    async def test_oversized_envelope_refused_without_calling_azure(self, store):
        ref = store.put(b"x" * 100_000, ".bin")
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], "", max_env_bytes=1000)
        job = DetonationJob(job_id="det_big", kind=DetonationKind.FILE, file_ref=ref, file_name="big.bin")
        result = await backend.run(job)
        assert result.status is DetonationStatus.ERROR and "budget" in result.error
        assert not backend.client.container_groups.created


class TestRegistryCredential:
    def test_spec_carries_pull_credential_when_configured(self, store):
        from reddysec.chamber.backends.azure_aci import RegistryCredential
        from reddysec.chamber.protocol import encode_job_envelope

        plain = make_backend(store, [FakeGroup(group_state="Succeeded")], "")
        job = url_job()
        assert "imageRegistryCredentials" not in plain.build_group_spec(job, encode_job_envelope(job))["properties"]

        cred = RegistryCredential(server="rsacr.azurecr.io", username="chamber-pull", password="tok")
        assert "tok" not in repr(cred)  # the token never lands in logs
        backend = make_backend(store, [FakeGroup(group_state="Succeeded")], "", registry=cred)
        props = backend.build_group_spec(job, encode_job_envelope(job))["properties"]
        assert props["imageRegistryCredentials"] == [
            {"server": "rsacr.azurecr.io", "username": "chamber-pull", "password": "tok"}
        ]
        assert props["restartPolicy"] == "Never" and "ipAddress" not in props

    def test_factory_reads_registry_from_environment(self, store, monkeypatch):
        from types import SimpleNamespace

        from reddysec.chamber.backends.base import make_chamber

        for key, value in {
            "RS_ACI_SUBSCRIPTION_ID": "sub",
            "RS_ACI_RESOURCE_GROUP": "rg",
            "RS_ACI_SUBNET_ID": "/subnets/det",
            "RS_ACI_REGISTRY_SERVER": "rsacr.azurecr.io",
            "RS_ACI_REGISTRY_USERNAME": "pull",
            "RS_ACI_REGISTRY_PASSWORD": "secret",
        }.items():
            monkeypatch.setenv(key, value)
        settings = SimpleNamespace(
            sandbox_backend="aci", env="prod", detonation_max_concurrency=2, detonation_timeout_s=45
        )
        chamber = make_chamber(settings, store)
        assert chamber.backend.registry.server == "rsacr.azurecr.io"
        assert chamber.allow_private_targets is False
