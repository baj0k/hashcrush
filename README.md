# HashCrush v1.1

**HashCrush** is a tool for organization and automation of password cracking tasks. It also produces some analytics.

## Requirements
1. Python 3.10+
2. PostgreSQL running locally
3. Administrative privileges for local PostgreSQL bootstrap
4. Hashcat configured with drivers required by your hardware

Prefer downloading the Hashcat release bundle manually from the official website instead of relying on distro packages. The official release is usually newer.

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
python3 -m pip install -r requirements.txt
python3 ./hashcrush.py setup
```
Disposable live-test environment bootstrap:
```bash
python3 ./hashcrush.py setup --test
```
`hashcrush.py setup --test` rebuilds the DB, creates dummy users/data, and writes `.env.test` for E2E tests.
##### Important Setup Warning

`hashcrush.py setup` is destructive.

It rebuilds the `hashcrush` database from scratch.
Do not run it on a production instance.

#### 3) It's alive
```
python3 ./hashcrush.py
```
Navigate to your server at [https://127.0.0.1:8443](https://127.0.0.1:8443) and log in with the admin account you created during `hashcrush.py setup`.

Because HashCrush starts with a self-signed certificate, browsers will warn by default.
Production deployments should provide certificate paths via environment variables:
- `HASHCRUSH_SSL_CERT_PATH`
- `HASHCRUSH_SSL_KEY_PATH`
- `HASHCRUSH_TRUST_X_FORWARDED_FOR` (set only behind a trusted reverse proxy)

If either TLS file is missing/unreadable, startup fails with an explicit error.
Initial bootstrap defaults to generating the certificate and key under `/etc/hashcrush/ssl`.
It applies restrictive permissions (`cert.pem` `0644`, `key.pem` `0600`) and prompts for another writable directory if `/etc/hashcrush/ssl` is not writable.


## Running HashCrush

```bash
python3 ./hashcrush.py
```

Recommended production environment overrides:

```bash
export HASHCRUSH_SECRET_KEY='<strong-random-secret>'
export HASHCRUSH_DATA_ENCRYPTION_KEY='<fernet-key>'
export HASHCRUSH_DATABASE_URI='postgresql+psycopg://hashcrush:<strong-db-password>@127.0.0.1:5432/hashcrush'
export HASHCRUSH_SSL_CERT_PATH='/run/secrets/hashcrush-cert.pem'
export HASHCRUSH_SSL_KEY_PATH='/run/secrets/hashcrush-key.pem'
```

Persisted data is encrypted at rest with the data encryption key. Keep `HASHCRUSH_DATA_ENCRYPTION_KEY` in a secret store or environment, not in shell history.

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
If the database schema is older than the code expects, app startup shows an explicit error until an upgrade is performed.
Current releases expect schema version `5`.

## Account and Password Management
- Admins can reset a password of any user.
- Users can change their own password after login.
- Local break-glass admin password reset is available via CLI:
  - `python3 ./hashcrush.py --reset-admin-password`

## Testing

Install test dependencies and Playwright browser:
```bash
python3 -m pip install -r requirements.txt -r requirements-test.txt
python3 -m playwright install chromium
```

Supported test entrypoint:
```bash
./tests/test-all.sh
```

Automated tests are PostgreSQL-backed. By default the suite reuses the configured
HashCrush PostgreSQL database and isolates each test app in its own temporary schema.
If you want to point tests at a different PostgreSQL database, set
`HASHCRUSH_TEST_POSTGRES_URI`. The older `HASHCRUSH_TEST_POSTGRES_ADMIN_URI` path is
only a fallback for environments where schema creation is not available but temporary
database creation is.

Local automated browser tests are the default.
Optional live-instance smoke:
```bash
python3 ./hashcrush.py setup --test
python3 ./hashcrush.py
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

Detailed testing documentation, direct pytest commands, and the post-deploy live smoke checklist are in [tests/README.md](/home/bajok/hashcrush/tests/README.md).
