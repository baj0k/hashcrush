# HashCrush v2.0

**HashCrush** is a tool for organization and automation of password cracking tasks. It also produces some analytics.

## Quick Start

Docker Compose is the recommended deployment path.

Requirements:
1. Docker
2. Docker Compose plugin

#### 1) Clone the repo

```bash
git clone https://github.com/baj0k/hashcrush.git
cd hashcrush
```

#### 2) Create `.env`

```bash
cp .env.example .env
```

Then edit `.env` and set:
- `POSTGRES_PASSWORD`
- `HASHCRUSH_SECRET_KEY`
- `HASHCRUSH_DATA_ENCRYPTION_KEY`
- `HASHCRUSH_INITIAL_ADMIN_PASSWORD`

#### 3) Start the stack

```bash
docker compose up -d --build
```

Watch startup:

```bash
docker compose logs -f bootstrap web worker
```

#### 4) Open the app

Browse to:

```text
http://127.0.0.1:8080
```

Login:
- username: `admin`
- password: the value you set in `.env`

The Compose stack starts:
- PostgreSQL
- a one-shot bootstrap container that applies schema/data upgrades and seeds the initial admin/settings/default tasks
- a Gunicorn web container
- a dedicated worker container

Important notes:
- `docker compose down` stops the stack and keeps the data volumes
- `docker compose down -v` wipes the database and uploaded asset volumes
- the stack serves plain HTTP on port `8080` by default
- if you place a TLS reverse proxy in front of the stack, set `HASHCRUSH_SESSION_COOKIE_SECURE=1` in `.env`

## Future Upgrades and Migrations

For future releases, use the same Compose workflow:

```bash
git pull
docker compose up -d --build
```

The bootstrap container reruns tracked schema/data upgrades before the web and worker services become ready.

If you need to rerun the bootstrap step by itself:

```bash
docker compose run --rm bootstrap
```

Do not use `python3 ./hashcrush.py setup` on an existing deployment. It is destructive and rebuilds the database from scratch.

Current releases expect schema version `6`.

## Manual Host Installation

Docker Compose is the recommended deployment path. If you do not want to use Docker, the supported host layout keeps state outside the repo:

- `/etc/hashcrush/config.conf`
- `/etc/hashcrush/ssl/cert.pem`
- `/etc/hashcrush/ssl/key.pem`
- `/var/lib/hashcrush/wordlists/...`
- `/var/lib/hashcrush/rules/...`
- `/tmp/hashcrush-runtime/...`

Host requirements:
1. Python 3.10+
2. PostgreSQL running locally
3. Administrative privileges for local PostgreSQL bootstrap
4. Hashcat configured with drivers required by your hardware

Prefer downloading the Hashcat release bundle manually from the official website instead of relying on distro packages. The official release is usually newer.

Fresh host deployment:

```bash
sudo apt update -y
sudo apt install postgresql postgresql-contrib python3 python3-pip -y
sudo service postgresql start
python3 -m pip install -r requirements.txt
sudo install -o "$USER" -g "$USER" -m 700 -d \
  /etc/hashcrush /etc/hashcrush/ssl \
  /var/lib/hashcrush /var/lib/hashcrush/wordlists /var/lib/hashcrush/rules \
  /tmp/hashcrush-runtime /tmp/hashcrush-runtime/tmp /tmp/hashcrush-runtime/hashes /tmp/hashcrush-runtime/outfiles
python3 ./hashcrush.py setup
```

Then run the web app and worker separately:

```bash
python3 ./hashcrush.py serve
python3 ./hashcrush.py worker
```

Manual production topology:
- reverse proxy such as `nginx` or `caddy`
- WSGI server serving `wsgi:app`
- one `python3 ./hashcrush.py worker` process

Example manual web entrypoint:

```bash
gunicorn --bind 127.0.0.1:8000 wsgi:app
```

CLI commands:

- `serve`
- `serve --debug`
- `serve --reset-admin-password`
- `serve --reset-admin-password --admin-username <admin_username>`
- `worker`
- `upgrade`
- `upgrade --dry-run`
- `setup`
- `setup --test`

## PostgreSQL Backup and Restore

Supported backup set:
- PostgreSQL database dump
- the active config file (recommended host path: `/etc/hashcrush/config.conf`) or the equivalent secret-store values for:
  - `HASHCRUSH_SECRET_KEY`
  - `HASHCRUSH_DATA_ENCRYPTION_KEY`
  - PostgreSQL connection settings
  - `HASHCRUSH_STORAGE_PATH`
  - TLS certificate/key paths
- `STORAGE_PATH` contents

Do not back up `RUNTIME_PATH`. It is ephemeral scratch/output space and should be recreated empty on restore.

Database backup:

```bash
pg_dump --format=custom --file hashcrush_$(date +%F_%H%M%S).dump "$HASHCRUSH_DATABASE_URI"
```

Config and managed-storage backup:

```bash
cp "${HASHCRUSH_CONFIG_PATH:-/etc/hashcrush/config.conf}" hashcrush_config_$(date +%F_%H%M%S).conf
tar -C "$(dirname "$HASHCRUSH_STORAGE_PATH")" \
  -czf hashcrush_storage_$(date +%F_%H%M%S).tar.gz \
  "$(basename "$HASHCRUSH_STORAGE_PATH")"
```

Restore into a fresh environment:

```bash
# 1. Install PostgreSQL, Python dependencies, and HashCrush code.
# 2. Recreate the target database/role or point HASHCRUSH_DATABASE_URI at an empty target DB.
pg_restore --clean --if-exists --no-owner --dbname="$HASHCRUSH_DATABASE_URI" hashcrush.dump
tar -C "$(dirname "$HASHCRUSH_STORAGE_PATH")" -xzf hashcrush_storage.tar.gz
python3 ./hashcrush.py upgrade --dry-run
python3 ./hashcrush.py upgrade
python3 ./hashcrush.py
```

Restore expectations:
- `STORAGE_PATH` should be restored to the same absolute path whenever possible.
- Uploaded wordlists and rules are stored by absolute path in the database. If you restore them to a different path, those DB paths must be rewritten before use.
- `RUNTIME_PATH` should exist and be writable, but its previous contents should not be restored.
- `HASHCRUSH_DATA_ENCRYPTION_KEY` must match the key used when the data was written, or encrypted hash material will be unreadable.

Production deploy checklist:
1. Run `pg_dump` before deploying.
2. Back up the active config file or the equivalent secret-store values.
3. Back up `STORAGE_PATH`.
4. Deploy the new code.
5. Run `python3 ./hashcrush.py upgrade --dry-run`.
6. Run `python3 ./hashcrush.py upgrade`.
7. Restart the app.
8. Run the external smoke suite:
   - `export HASHCRUSH_E2E_MODE=external`
   - `./tests/test-all.sh`

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
python3 ./hashcrush.py serve
export HASHCRUSH_E2E_MODE=external
./tests/test-all.sh
```

Detailed testing documentation, direct pytest commands, and the post-deploy live smoke checklist are in [tests/README.md](/home/bajok/hashcrush/tests/README.md).
