# HashCrush
**HashCrush** is a tool for automation and organization of password cracking tasks. It also produces some analytics.

## Quick Start
Requirements:
- Docker with the compose plugin
- NVIDIA Container Toolkit
- Working Docker GPU support on the host

#### 0) Ensure prerequisites are met

Verify Docker can see the NVIDIA GPU before building HashCrush:

```bash
docker run --rm --gpus all ubuntu nvidia-smi
```

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
- optional: `HASHCRUSH_HTTPS_PORT` to publish HTTPS on a different host port
- optional: `HASHCRUSH_HASHCAT_VERSION` to override the bundled worker Hashcat version

Safe ways to generate secret keys:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Use the first output for `HASHCRUSH_SECRET_KEY` and the second for
`HASHCRUSH_DATA_ENCRYPTION_KEY`.

#### 3) Start the stack

```bash
docker compose up -d --build
```

Watch startup:

```bash
docker compose logs -f bootstrap web upload-worker worker nginx
```

#### 4) Verify the GPU worker

The worker image bundles Hashcat. Confirm it sees CUDA before relying on job
execution:

```bash
docker run --rm --gpus all hashcrush-worker hashcat -I
docker run --rm --gpus all hashcrush-worker hashcat -b -m 1000
```

Expected result:
- `hashcat -I` shows `CUDA API`
- your NVIDIA GPU appears as a backend device

`clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR` is expected here when Hashcat is
using CUDA directly instead of OpenCL.

#### 5) Open the app

Open the app - by default it should be reachable under this URL:


```text
https://127.0.0.1:8443
```

That `8443` value comes from `HASHCRUSH_HTTPS_PORT` in `.env`.

The Compose bootstrap step generates a self-signed TLS certificate automatically
if one is not already present in the shared SSL volume. Your browser will likely
show a certificate warning unless you replace it with your own certificate.

The Compose stack starts:
- PostgreSQL
- a one-shot bootstrap container that applies schema/data upgrades and seeds the initial admin account plus default tasks
- a Gunicorn web UI container that is internal-only
- an `nginx` reverse proxy that is the only public entrypoint
- a dedicated `upload-worker` container for long-running imports
- a GPU cracking worker container

Important notes:
- `docker compose down` stops the stack and keeps the data volumes
- `docker compose down -v` wipes the database and uploaded asset volumes
- the app is only exposed over HTTPS in the default Compose topology
- the internal `web` container is not published directly to the host

To replace the generated self-signed cert with your own certificate, mount or
copy your `cert.pem` and `key.pem` into `/etc/hashcrush/ssl/` for both the
`bootstrap` and `nginx` services via a Compose override.

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

Current releases expect schema version `9`.

## External Mounted Wordlists

For very large static wordlists, prefer mounting them into the containers and
registering the container path in HashCrush instead of uploading and copying the
file into managed storage.

Recommended pattern:

1. Keep normal app storage under `HASHCRUSH_STORAGE_PATH`.
2. Mount a separate read-only host directory, for example:
   - host: `/srv/hashcrush-wordlists`
   - container: `/mnt/hashcrush-wordlists`
3. HashCrush mounts that host directory read-only into `web`, `web-test`,
   `upload-worker`, and `worker` at `/mnt/hashcrush-wordlists`.
4. Set the host path in `.env`:
   - `HASHCRUSH_EXTERNAL_WORDLISTS_HOST_PATH=/srv/hashcrush-wordlists`
5. In the UI, use `Wordlists -> Add Wordlist -> Register Mounted File`.

Example startup:

```bash
docker compose up -d --build
```

Docker Compose reads `HASHCRUSH_EXTERNAL_WORDLISTS_HOST_PATH` from `.env` and
mounts it at the fixed container path `/mnt/hashcrush-wordlists`.

Behavior notes:
- external wordlists are stored by absolute container path in the database
- the mounted path inside the containers is always `/mnt/hashcrush-wordlists`
- the host directory and filenames can change, but the in-container path must
  remain stable for already-registered external wordlists
- deleting an external wordlist in HashCrush removes only the DB record, not the mounted file
- external wordlists are not included in the managed `STORAGE_PATH` backup tarball

## Manual Host Installation

Docker Compose is the recommended deployment path. If you do not want to use Docker, the supported host layout keeps state outside the repo:

- `/etc/hashcrush/config.conf`
- `/etc/hashcrush/ssl/cert.pem`
- `/etc/hashcrush/ssl/key.pem`
- `/var/lib/hashcrush/wordlists/...`
- `/var/lib/hashcrush/rules/...`
- `/tmp/hashcrush-runtime/...`

Host requirements:
1. Python 3.11+
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
python3 ./hashcrush.py upload-worker
python3 ./hashcrush.py worker
```

Manual production topology:
- reverse proxy such as `nginx` or `caddy`
- WSGI server serving `wsgi:app`
- one `python3 ./hashcrush.py upload-worker` process
- one `python3 ./hashcrush.py worker` process

Example manual web entrypoint:

```bash
gunicorn --config ./docker/gunicorn.conf.py wsgi:app
```

CLI commands:

- `serve`
- `serve --debug`
- `serve --reset-admin-password`
- `serve --reset-admin-password --admin-username <admin_username>`
- `worker`
- `upload-worker`
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
- External mounted wordlists are not stored under `STORAGE_PATH`; back up and restore those host directories separately.
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
8. Run the Docker-native external smoke suite with a fresh test project:
   - `COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \`
   - `docker compose --profile test up --build --abort-on-container-exit --exit-code-from test-external test-external`

## Account and Password Management
- Admins can reset a password of any user.
- Users can change their own password after login.
- Local break-glass admin password reset is available via CLI:
  - `python3 ./hashcrush.py --reset-admin-password`

## Testing

Preferred Docker-native test entrypoints:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test test

COMPOSE_PROJECT_NAME=hashcrush-test-$(date +%s) \
docker compose --profile test up --build --abort-on-container-exit --exit-code-from test-external test-external
```

These commands keep the test runner and the app-under-test in Docker. The
`test` service runs the non-E2E suite plus local browser tests, while
`test-external` runs the non-E2E suite and then an HTTPS smoke test through
`nginx-test`, `web-test`, `upload-worker`, and the real cracking worker container.

If you intentionally reuse a fixed project name, clean it first:

```bash
COMPOSE_PROJECT_NAME=hashcrush-test \
docker compose --profile test down -v --remove-orphans
```

Optional host-side direct pytest setup:

```bash
python3 -m pip install -r requirements.txt -r requirements-test.txt
python3 -m playwright install chromium
```

Automated tests are PostgreSQL-backed. By default the suite reuses the configured
HashCrush PostgreSQL database and isolates each test app in its own temporary schema.
If you want to point tests at a different PostgreSQL database, set
`HASHCRUSH_TEST_POSTGRES_URI`. The older `HASHCRUSH_TEST_POSTGRES_ADMIN_URI` path is
only a fallback for environments where schema creation is not available but temporary
database creation is.

Detailed testing documentation, direct pytest commands, and the smoke-test
workflow are in [tests/README.md](/home/bajok/hashcrush/tests/README.md).
