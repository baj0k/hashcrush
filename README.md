# HashCrush v0.9.97

**HashCrush** is a tool for organization and automation of password cracking tasks. It also produces some analytics.

## Requirements
1. Python 3.10+
2. MySQL running locally
3. Administrative privileges for local MySQL bootstrap during setup.py
4. Hashcat

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
./setup.py # Follow prompts
```
##### Important Setup Warning

`setup.py` is destructive.

It rebuilds the `hashcrush` database from scratch and overwrites `hashcrush/config.conf`.
Do not run setup.py on an instance where data must be preserved.

#### 3) It's alive
```
python3 ./hashcrush.py
```
Navigate to your server at [https://127.0.0.1:8443](https://127.0.0.1:8443) and Setup admin user.

Because HashCrush starts with a self-signed certificate, browsers will warn by default.
To use your own certificate, replace:
- `hashcrush/ssl/cert.pem`
- `hashcrush/ssl/key.pem`


## Running HashCrush

```bash
python3 ./hashcrush.py
```

Optional flags:

- --debug
- --no-ssl (default port 5000)
- --reset-admin-password
- --reset-admin-password --admin-username <admin_username>

## External Wordlists and Rules
`setup.py` prompts for paths and writes them to `hashcrush/config.conf`.
They should point to external repositories such as SecLists and hashcat rules:

```ini
[app]
wordlists_path = /path/to/SecLists/Passwords
rules_path = /path/to/hashcat/rules
```

## Account and Password Management
- Admins can set a temporary password for users from the Users page.
- Users can change their own password in Profile after login.
- Local break-glass admin password reset is available via CLI:
  - `python3 ./hashcrush.py --reset-admin-password`

## Testing

Install test dependencies:
```bash
python3 -m pip install -r requirements-test.txt
pytest -q
```

## Docker

currently not working as intended. completely unreliable
