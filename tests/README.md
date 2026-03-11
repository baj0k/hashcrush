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

Use the wrapper:

```bash
./tests/test-all.sh
```

The automated harness injects its own `HASHCRUSH_DATA_ENCRYPTION_KEY`. For manual smoke runs against a real instance, make sure the target app has its production encryption key configured before running the external suite.

It runs:

1. non-E2E tests:
```bash
PYTHONPATH=. pytest -q -m "not e2e and not e2e_external" -rs
```

2. browser tests:
- local `e2e` by default
- external `e2e_external` only when `HASHCRUSH_E2E_MODE=external`

Automated tests are PostgreSQL-backed. By default the suite reuses the configured
HashCrush PostgreSQL database and isolates each test app in its own temporary schema.
To point the suite at a different PostgreSQL database, set
`HASHCRUSH_TEST_POSTGRES_URI`.

`HASHCRUSH_TEST_POSTGRES_ADMIN_URI` remains supported only as a fallback for
environments where schema creation is unavailable but temporary database creation
is possible.

The non-E2E suite includes a PostgreSQL backup/restore round-trip validation using
`pg_dump` and `pg_restore`. Keep those client tools installed on environments that
run the automated tests.

## Local Automated Browser Tests

Default mode:

```bash
./tests/test-all.sh
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

The local automated path creates a temporary schema in the configured PostgreSQL
database for each test app instance and drops those schemas at process exit. If that
is not possible and `HASHCRUSH_TEST_POSTGRES_ADMIN_URI` is set, it falls back to
creating temporary databases instead.

## External Smoke Tests

Use external mode only when you want to validate a real running instance.

Typical flow:

```bash
python3 ./hashcrush.py setup --test
python3 ./hashcrush.py
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

Equivalent direct command:

```bash
PYTHONPATH=. pytest -q -m e2e_external -rs
```

In external mode:
- `.env.test` is loaded automatically if present
- `hashcrush.py setup --test` writes a ready-to-use `.env.test`
- the suite targets `HASHCRUSH_E2E_BASE_URL`
- the suite does not bootstrap its own server or database

External mode validates:
- real PostgreSQL connectivity
- real TLS/certificate handling
- real config/runtime paths
- real deployment packaging

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
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

Expected result:
- the external smoke suite completes with no skips
- login works
- the Jobs page is reachable after login
- logout redirects back to login

## E2E Skip Policy

The wrapper treats skipped browser tests as a failure by default.

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
