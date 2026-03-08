### Security and Access Control
- [ ] `P0-SEC-01` Remove committed TLS private key and rotate TLS cert/key immediately.
  - Files: `hashcrush/ssl/key.pem`, `hashcrush.py`.
  - Done when: keys are no longer in repo history, startup reads cert/key from secure path/env/secret volume.

- [ ] `P0-SEC-02` Remove committed application/database secrets and rotate them.
  - Files: `hashcrush/config.conf`, setup/install docs.
  - Done when: `secret_key` and DB credentials are rotated; `config.conf` is never committed.

- [ ] `P0-AUTH-02` Enforce tenant scoping for non-admin users across UI routes and exports.
  - Files: `hashcrush/users/routes.py`, `hashcrush/jobs/routes.py`, `hashcrush/tasks/routes.py`, `hashcrush/searches/routes.py`, `hashcrush/analytics/routes.py`, `hashcrush/domains/routes.py`, `hashcrush/wordlists/routes.py`, `hashcrush/rules/routes.py`, `hashcrush/hashfiles/routes.py`, `hashcrush/main/routes.py`.
  - Done when: non-admin queries are owner/domain-scoped by default; bulk `.all()` usage is removed where data is tenant-sensitive.

### Documentation and UX Clarity
- [ ] `P2-OPS-01 (New)` Align container/runtime versions and startup model.
  - Files: `Dockerfile`, `pyproject.toml`, runtime docs.
  - Done when: supported Python version matches codebase requirements and container runs a production server configuration.

## P3 - Product and UX Backlog (Decision-Driven)
- [ ] `P3-PROD-12 (New)` Implement task/task-group import/export inside the app using JSON.
- [] Dashboard and job status should also show recovered amount of hashes similar to console log
- --no-ssl should start on port 8080 by default


-- when job is stopped it does not save the already cracked hashes? 
