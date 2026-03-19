# Testing

HashCrush has two browser-testing modes:

1. `e2e`
- local, self-bootstrapped, fully automated
- primary browser test path
- used by CI

2. `e2e_external`
- external smoke tests against an already running instance
- optional
- useful after deployment or when validating the real runtime environment

## Supported Entry Point

Preferred Docker-native Compose entrypoints:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test test

COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test-external test-external
```

Both Docker-native paths should use a fresh Compose project name per run so the
test stack gets a fresh PostgreSQL volume and does not inherit queued smoke jobs
or other state from earlier attempts.

If you intentionally reuse a fixed Compose project name, clean it first:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test \
docker compose --profile test down -v --remove-orphans
```

The automated harness injects its own `HASHCRUSH_DATA_ENCRYPTION_KEY`. For manual
smoke runs against a real instance, make sure the target app has its production
encryption key configured before running the external suite.

The Compose services run the same two-stage harness internally:

1. non-E2E tests:
```bash
python3 -m pytest -q -m "not e2e and not e2e_external" -rs
```
2. browser tests:
- local `e2e` in the `test` service
- HTTPS `e2e_external` smoke in the `test-external` service

Optional host-side direct pytest equivalents:

```bash
PYTHONPATH=. pytest -q -m "not e2e and not e2e_external" -rs
PYTHONPATH=. pytest -q -m e2e -rs
PYTHONPATH=. pytest -q -m e2e_external -rs
```

Automated tests are PostgreSQL-backed. By default the suite reuses the configured
HashCrush PostgreSQL database and isolates each test app in its own temporary schema.
To point the suite at a different PostgreSQL database, set
`HASHCRUSH_TEST_POSTGRES_URI`.

If neither `HASHCRUSH_TEST_POSTGRES_URI` nor `HASHCRUSH_DATABASE_URI` is set and no
active HashCrush config file is present, the suite falls back to the standard local
development URI:

```text
postgresql+psycopg://hashcrush:hashcrush@127.0.0.1:5432/hashcrush
```

`HASHCRUSH_TEST_POSTGRES_ADMIN_URI` remains supported only as a fallback for
environments where schema creation is unavailable but temporary database creation
is possible.

The non-E2E suite includes a PostgreSQL backup/restore round-trip validation using
`pg_dump` and `pg_restore`. Keep those client tools installed on environments that
run the automated tests.

## Local Automated Browser Tests

Docker-native entrypoint:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test test
```

Equivalent direct command:

```bash
PYTHONPATH=. pytest -q -m e2e -rs
```

What local mode does automatically:
- starts a temporary app server
- creates a temporary test database
- creates temporary runtime directories
- seeds:
  - admin user
  - second non-admin user
  - domain
  - hashfile
  - wordlist
  - task
  - uploaded-style managed files for shared wordlists/rules under temporary storage

Local mode is the authoritative automated path and should stay green in CI.

In the Docker-native path, the test runner itself also stays in Docker. That flow
uses the `db` service from `compose.yaml` and runs the Python/Playwright harness
from the dedicated `test` container.

The local automated path creates a temporary schema in the configured PostgreSQL
database for each test app instance and drops those schemas at process exit. If that
is not possible and `HASHCRUSH_TEST_POSTGRES_ADMIN_URI` is set, it falls back to
creating temporary databases instead.

## External Smoke Tests

Use external mode only when you want to validate a real running instance.

Docker-native full-stack flow:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test-external test-external
```

Equivalent direct command:

```bash
PYTHONPATH=. pytest -q -m e2e_external -rs
```

In external mode:
- `tests/.env.test` is loaded automatically if present
- `hashcrush.py setup --test` writes a ready-to-use `tests/.env.test`
- the suite targets `HASHCRUSH_E2E_BASE_URL`
- the suite does not bootstrap its own server or database
- the configured external test account should be an admin account, because the smoke
  flow creates a shared wordlist, a shared task, and a new domain/job

In the Docker-native full-stack flow, Compose starts the full app stack (`db`,
`bootstrap`, `web-test`, `nginx-test`, and `worker`) and then executes the
smoke suite from the dedicated `test-external` container.

External mode validates:
- real PostgreSQL connectivity
- real TLS/certificate handling
- real config/runtime paths
- real deployment packaging
- real worker pickup and result import for a small dictionary crack job

Recommended post-deploy smoke sequence:

1. deploy the new code
2. run:
```bash
python3 ./hashcrush.py upgrade --dry-run
python3 ./hashcrush.py upgrade
```
3. restart the app
4. confirm the target URL loads over HTTPS
5. run:
```bash
COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test-external test-external
```

Expected result:
- the external smoke suite completes with no skips
- login works
- a tiny dictionary cracking job is created and completed by the live worker
- the smoke job reaches `Completed` with `3/3` recovered
- logout redirects back to login

## E2E Skip Policy

The Docker-native test services treat skipped browser tests as a failure by default.

Reason:
- skipped browser tests should not count as a successful full validation run
- stale credentials, missing fixtures, or an unreachable external host must fail loudly

## Marks

Configured in [pytest.ini](/home/bajok/hashcrush/pytest.ini):

- `e2e`
  local self-bootstrapped browser tests
- `e2e_external`
  external smoke tests against a running instance

## When To Use Which Mode

Use local `e2e` when:
- developing features
- validating pull requests
- running CI
- debugging browser regressions quickly

Use `e2e_external` when:
- validating a deployed instance
- checking PostgreSQL/TLS/config integration
- running a final post-upgrade smoke test

## Backup / Restore Verification

The PostgreSQL non-E2E suite includes a backup/restore round-trip test:

```bash
PYTHONPATH=. pytest -q tests/integration/test_backup_restore.py -rs
```

What it validates:
- schema-scoped `pg_dump` / `pg_restore` round trip
- restored schema version tracking
- restored encrypted hash material remains readable with the configured data encryption key
- restored managed wordlist/rule files under `STORAGE_PATH`
