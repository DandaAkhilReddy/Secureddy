# Testing Secureddy

Everything runs offline. Mail providers, OAuth, the sandbox and the language
model are fakes unless a test says otherwise. See
[docs/test-plan.md](docs/test-plan.md) for which test covers which feature.

## One-time setup

```bash
pip install -e ".[dev]"
python -m playwright install chromium     # for the integration suite
```

PostgreSQL tests need either `RS_TEST_POSTGRES_URL`
(e.g. `postgresql://postgres@localhost:5432/postgres`) or a local PostgreSQL
install (`initdb` / `pg_ctl` on PATH or under `/usr/lib/postgresql/*/bin`).
Without one they are skipped, not failed.

## The suites

| Suite | Command | What it is |
|-------|---------|------------|
| Unit | `python -m pytest tests/unit -q -p no:cacheprovider` | One module at a time: parser, URL extraction, "is this email worth checking", scoring, connectors against in-memory Gmail / Graph / IMAP servers, store, CLI |
| Functional | `python -m pytest tests/functional -q -p no:cacheprovider` | The whole web app (every route, every sign-in provider through fakes), the worker loop end to end, the email corpus through the real analysis pipeline |
| PostgreSQL | `python -m pytest tests/postgres -q -p no:cacheprovider` | Schema upgrades, sessions, invites, the text-only purge and a sign-in on a real PostgreSQL 16 |
| Integration | `python -m pytest tests -m integration -q -p no:cacheprovider` | Real Chromium: the sandbox opening hostile local pages, the Reading Room, the web app in a browser (assistant, PIN lock, People page, settings), one end-to-end phish |
| Everything but Chromium | `python -m pytest tests -m "not integration" -q -p no:cacheprovider` | Unit + functional + PostgreSQL (what CI runs first) |

Regression corpora (part of the functional suite):

* `tests/functional/analysis/test_false_positives.py`: real-world mail that must stay SAFE.
* `tests/functional/analysis/test_lure_corpus.py`, `test_corpus.py`: ClickFix, AiTM, device-code, callback, QR, macro, smuggling... must stay caught.
* `tests/functional/analysis/test_text_only_corpus.py`: text-only mail that must be skipped, and proof that every corpus email with a link or file is still checked.

## Coverage

```bash
rm -f .coverage
python -m pytest tests -m "not integration" -q -p no:cacheprovider --cov=reddysec --cov-branch --cov-report=
python -m pytest tests -m integration -q -p no:cacheprovider --cov=reddysec --cov-branch --cov-append --cov-report=
coverage report | tail -1        # combined; keep it at 95% or more
```

## Lint and infrastructure

```bash
ruff check src tests
/tmp/bicep build infra/azure/main.bicep --stdout >/dev/null
/tmp/bicep build-params infra/azure/main.dev.bicepparam --stdout >/dev/null
```

## Writing a test

* Web: use the fixtures in `tests/functional/web/conftest.py` (`client`, `login`,
  `seed`, `FakeOAuthProvider`). The default test server is "open" sign-up with
  room to spare; invite-only tests build their own app (see `test_web_people.py`).
* Worker: use `Harness` from `tests/functional/worker/test_worker_flows.py`. Its
  test emails carry a link by default, because text-only email is ignored.
* A new route that takes an id is covered by `test_web_authz_matrix.py`
  automatically; a new *kind* of id makes that test fail until you add it.
