# HashCrush v0.9.97

**HashCrush** is a tool for organization and automation of password cracking tasks. It also produces some analytics.

## Requirements
1. Python 3.10+
2. MySQL running locally
3. Administrative privileges for local MySQL bootstrap
4. Hashcat configured with drivers required by your hardware

## Installation
#### 1) Setup MySQL
```
sudo apt update -y
sudo apt install mysql-server -y
sudo service mysql start
sudo mysql_secure_installation
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
export HASHCRUSH_DB_HOST='127.0.0.1'
export HASHCRUSH_DB_USERNAME='hashcrush'
export HASHCRUSH_DB_PASSWORD='<strong-db-password>'
export HASHCRUSH_SSL_CERT_PATH='/run/secrets/hashcrush-cert.pem'
export HASHCRUSH_SSL_KEY_PATH='/run/secrets/hashcrush-key.pem'
```

Optional flags:

- --debug
- --reset-admin-password
- --reset-admin-password --admin-username <admin_username>
- setup
- setup --test

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

Fastest disposable live-test path:
```bash
python3 ./hashcrush.py setup --test
python3 ./hashcrush.py
./scripts/test-all.sh
```

`hashcrush.py setup --test` writes the `.env.test`.  
`scripts/test-all.sh` auto-loads `.env.test`, runs non-E2E tests first, then runs E2E tests.

## Docker

Currently completely unreliable.
