# HashCrush v1.0

**HashCrush** is a tool for organization and automation of password cracking tasks. It also produces some analytics.

## Requirements
1. Python 3.10+
2. PostgreSQL running locally
3. Administrative privileges for local PostgreSQL bootstrap
4. Hashcat configured with drivers required by your hardware

## Installation
#### 1) Setup PostgreSQL
```
sudo apt update -y
sudo apt install postgresql postgresql-contrib -y
sudo service postgresql start
```

#### 2) Install HashCrush
```
git clone https://github.com/baj0k/hashcrush.git
cd hashcrush
sudo apt install python3 python3-pip python3-flask -y
python3 ./hashcrush.py setup
```
Disposable live-test environment bootstrap:
```bash
python3 ./hashcrush.py setup --test
```
`hashcrush.py setup --test` rebuilds the DB, creates dummy users/data, and writes `.env.test` for E2E runs.
##### Important Setup Warning

`hashcrush.py setup` is destructive.

It rebuilds the `hashcrush` database from scratch and overwrites `hashcrush/config.conf`.
Do not run it on an instance where data must be preserved.

#### 3) It's alive
```
python3 ./hashcrush.py
```
Navigate to your server at [https://127.0.0.1:8443](https://127.0.0.1:8443) and Setup admin user.

Because HashCrush starts with a self-signed certificate, browsers will warn by default.
Production deployments should provide certificate paths via environment variables:
- `HASHCRUSH_SSL_CERT_PATH`
- `HASHCRUSH_SSL_KEY_PATH`
- `HASHCRUSH_TRUST_X_FORWARDED_FOR` (set only behind a trusted reverse proxy)

If either TLS file is missing/unreadable, startup fails with an explicit error.
`hashcrush.py setup` now defaults to generating the certificate and key under `/etc/hashcrush/ssl`.
It applies restrictive permissions (`cert.pem` `0644`, `key.pem` `0600`) and prompts for another writable directory if `/etc/hashcrush/ssl` is not writable.


## Running HashCrush

```bash
python3 ./hashcrush.py
```

Recommended production environment overrides:

```bash
export HASHCRUSH_SECRET_KEY='<strong-random-secret>'
export HASHCRUSH_DATABASE_URI='postgresql+psycopg2://hashcrush:<strong-db-password>@127.0.0.1:5432/hashcrush'
export HASHCRUSH_SSL_CERT_PATH='/run/secrets/hashcrush-cert.pem'
export HASHCRUSH_SSL_KEY_PATH='/run/secrets/hashcrush-key.pem'
```

If you do not want to use a full URI, HashCrush also supports:

```bash
export HASHCRUSH_DB_HOST='127.0.0.1'
export HASHCRUSH_DB_PORT='5432'
export HASHCRUSH_DB_NAME='hashcrush'
export HASHCRUSH_DB_USERNAME='hashcrush'
export HASHCRUSH_DB_PASSWORD='<strong-db-password>'
```

Optional flags:

- --debug
- --reset-admin-password
- --reset-admin-password --admin-username <admin_username>
- upgrade
- upgrade --dry-run
- setup
- setup --test

## Production Upgrades

Do not use `hashcrush.py setup` on an existing deployment. It is destructive.

Use the upgrade path instead:

```bash
# 1. Back up the database and config first.
# 2. Deploy the new code.
python3 ./hashcrush.py upgrade --dry-run
python3 ./hashcrush.py upgrade
python3 ./hashcrush.py
```

`hashcrush.py upgrade` is non-destructive. It applies tracked schema/data migrations in place and preserves existing data.
If the database schema is older than the code expects, app startup now stops with an explicit error until `hashcrush.py upgrade` is run.
Tracked in-place upgrades are supported only for schema-versioned deployments created from this release onward.
Non-empty unversioned legacy databases are not auto-adopted; rebuild them with `hashcrush.py setup` or migrate them manually before using `hashcrush.py upgrade`.

## External Wordlists and Rules
`hashcrush.py setup` prompts for paths and writes them to `hashcrush/config.conf`.
They should point to external repositories such as SecLists and hashcat rules:

```ini
[app]
wordlists_path = /path/to/SecLists/Passwords
rules_path = /path/to/hashcat/rules
```

## Security Notes
- `hashcrush/config.conf` must stay local and never be distributed.
- Rotate `SECRET_KEY`, DB credentials, and TLS cert/key on deployment.

## Account and Password Management
- Admins can set a temporary password for users from the Users page.
- Users can change their own password in Profile after login.
- Local break-glass admin password reset is available via CLI:
  - `python3 ./hashcrush.py --reset-admin-password`

## Testing

Install test dependencies and Playwright browser:
```bash
python3 -m pip install -r requirements.txt -r requirements-test.txt
python3 -m playwright install chromium
```

Default fully automated test path:
```bash
./tests/test-all.sh
```

`tests/test-all.sh` is the supported test entrypoint.
It runs:
- non-E2E tests first
- then a self-bootstrapped local browser suite by default

The local browser path:
- starts a temporary app instance automatically
- uses a temporary SQLite database
- seeds its own users, domain, hashfile, wordlist, and task
- does not require `hashcrush.py setup --test`
- is the authoritative CI path

GitHub Actions runs the same wrapper from [.github/workflows/tests.yml](/home/bajok/hashcrush/.github/workflows/tests.yml).

Direct pytest entrypoints:
```bash
PYTHONPATH=. pytest -q -m "not e2e and not e2e_external" -rs
PYTHONPATH=. pytest -q -m e2e -rs
```

Optional external-host smoke path:
```bash
python3 ./hashcrush.py setup --test
python3 ./hashcrush.py
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

When `HASHCRUSH_E2E_MODE=external` is set, `tests/test-all.sh` switches to the smaller `e2e_external` smoke suite against the already running host from `.env.test` / `HASHCRUSH_E2E_BASE_URL`.

Use external mode for:
- post-deploy smoke checks
- validating the real PostgreSQL/TLS/config deployment shape
- checking the actual running instance rather than the temporary local harness

Direct external smoke entrypoint:
```bash
PYTHONPATH=. pytest -q -m e2e_external -rs
```

Recommended post-deploy smoke checklist:
1. deploy the new code
2. run `python3 ./hashcrush.py upgrade --dry-run`
3. run `python3 ./hashcrush.py upgrade`
4. restart the app
5. confirm the target URL responds over HTTPS
6. run:
```bash
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

By default the wrapper treats any E2E skip as a failure, so stale credentials, missing fixtures, or an unreachable host do not produce a false-green run.
Set `HASHCRUSH_ALLOW_E2E_SKIPS=1` only if you intentionally want a permissive external smoke run.

Detailed testing documentation is in [tests/README.md](/home/bajok/hashcrush/tests/README.md).
