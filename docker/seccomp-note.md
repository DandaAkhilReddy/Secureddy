# Seccomp profile for the chamber

The profile lives with the chamber code, not here:

    src/reddysec/chamber/seccomp-chamber.json

It is owned by the chamber module. The docker backend
(`chamber/backends/docker.py`) resolves it from its own package location and
passes it as `--security-opt seccomp=<path>` on every `docker run`, together
with `--read-only`, `--cap-drop ALL`, `--pids-limit`, `--memory`, `--cpus` and
tmpfs mounts for `/tmp` and `/work`. The `chamber` service in
`docker/docker-compose.yml` mirrors those options for a manual run.

What it has to allow, in short:

- what Docker's default profile allows, minus `ptrace`, `mount`, `keyctl`,
  `bpf`, `perf_event_open`, `userfaultfd` and the `*_module` family;
- `clone`/`unshare` with `CLONE_NEWUSER` **only if** Chromium's own sandbox is
  turned on (`chromium_sandbox=True`). Playwright for Python defaults to
  `--no-sandbox`, so the chamber relies on the container boundary and the
  profile can keep user namespaces blocked.

Where it applies:

| backend | isolation | seccomp |
|---------|-----------|---------|
| local   | none (dev laptop) | n/a |
| docker  | namespaces + cgroups + this profile + `--cap-drop ALL`, `--read-only`, `--pids-limit` | yes |
| aci     | hypervisor-isolated container group, one per detonation, deleted afterwards | ACI does not take a custom seccomp profile; the VM boundary is the control |

Check the profile is valid JSON before committing:

    python -m json.tool src/reddysec/chamber/seccomp-chamber.json > /dev/null
