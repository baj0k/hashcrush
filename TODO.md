### Security and Access Control
- [ ] `P0-SEC-01` Remove committed TLS private key and rotate TLS cert/key immediately.
  - Files: `hashcrush/ssl/key.pem`, `hashcrush.py`.
  - Done when: keys are no longer in repo history, startup reads cert/key from secure path/env/secret volume.

- [ ] `P0-SEC-02` Remove committed application/database secrets and rotate them.
  - Files: `hashcrush/config.conf`, setup/install docs.
  - Done when: `secret_key` and DB credentials are rotated; `config.conf` is never committed.

- [ ] `P0-WEB-01` Convert all state-changing `GET` routes to `POST`/`DELETE` and enforce CSRF.
  - Files: `hashcrush/jobs/routes.py`, `hashcrush/task_groups/routes.py`, `hashcrush/users/routes.py`, `hashcrush/wordlists/routes.py`, `hashcrush/settings/routes.py`, `hashcrush/hashfiles/routes.py`, `hashcrush/rules/routes.py`, `hashcrush/main/routes.py`, matching templates.
  - Done when: all mutating endpoints reject `GET`; templates use forms with CSRF tokens.

- [ ] `P0-AUTH-01` Add missing authorization checks for task-group mutation routes (IDOR risk).
  - File: `hashcrush/task_groups/routes.py`.
  - Done when: each read/write route enforces `current_user.admin or task_group.owner_id == current_user.id`.

- [ ] `P0-AUTH-02` Enforce tenant scoping for non-admin users across UI routes and exports.
  - Files: `hashcrush/users/routes.py`, `hashcrush/jobs/routes.py`, `hashcrush/tasks/routes.py`, `hashcrush/searches/routes.py`, `hashcrush/analytics/routes.py`, `hashcrush/domains/routes.py`, `hashcrush/wordlists/routes.py`, `hashcrush/rules/routes.py`, `hashcrush/hashfiles/routes.py`, `hashcrush/main/routes.py`.
  - Done when: non-admin queries are owner/domain-scoped by default; bulk `.all()` usage is removed where data is tenant-sensitive.

- [ ] `P0-AUTH-04 (New)` Scope dynamic wordlist generation to authorized data.
  - File: `hashcrush/utils/utils.py` (`update_dynamic_wordlist`).
  - Done when: dynamic wordlists for non-admin users include only plaintexts from hashes they are allowed to access.

### Data Integrity and Correctness
- [ ] `P0-DATA-01` Fix plaintext storage format inconsistency (raw uppercase vs hex-encoded expected by readers).
  - Files: `hashcrush/executor/service.py`, `hashcrush/analytics/routes.py`, `hashcrush/searches/routes.py`, `hashcrush/utils/utils.py`.
  - Done when: one format is enforced end-to-end (recommended: hex-encoded bytes), existing rows are migrated, tests protect against regression.

- [ ] `P0-DATA-02` Validate job hashfile assignment ownership/domain scope before accepting `hashfile_id` from form.
  - File: `hashcrush/jobs/routes.py`.
  - Done when: selected hashfile is confirmed to exist, match job domain, and be visible to current user.

- [ ] `P0-DATA-03 (New)` Fix domain delete logic to avoid deleting domains with active jobs.
  - File: `hashcrush/domains/routes.py`.
  - Done when: deletion aborts early if jobs exist and never leaves orphaned records or throws integrity errors.

## P1 - High Priority

### Functional Bugs
- [ ] `P1-BUG-01` Fix wordlist route logic and authorization bugs.
  - File: `hashcrush/wordlists/routes.py`.
  - Done when: dynamic delete path has proper `return`, dynamic update enforces owner/admin authorization.

- [ ] `P1-BUG-02 (New)` Add consistent null/object-not-found handling to avoid internal server errors.
  - Files: all mutating route modules (for example `jobs_delete`, `tasks_delete`, `rules_delete`, `wordlists_delete`).
  - Done when: invalid IDs return `404` or safe redirect with error flash, not `500`.

- [ ] `P1-BUG-04` Investigate and fix user profile internal server error.
  - Files: `hashcrush/users/routes.py`, `hashcrush/templates/profile.html`, related model constraints.
  - Done when: profile page loads and updates reliably under normal/admin users.

### Filesystem and Runtime Hygiene
- [ ] `P1-FS-01` Eliminate temp-file leakage in download flows.
  - Files: `hashcrush/analytics/routes.py`.
  - Done when: downloads stream in-memory or use guaranteed post-response cleanup.

- [ ] `P1-FS-02` Move job runtime artifacts out of project files and enforce cleanup.
  - Files: `hashcrush/executor/service.py`, `hashcrush/utils/utils.py`, `hashcrush/jobs/routes.py`, `hashcrush/models.py`.
  - Done when: `control/{tmp,outfiles,hashes}` is ephemeral and cleaned after job completion/startup fallback cleanup.

- [ ] `P1-CONF-01` Externalize rules/masks/wordlists paths via config and setup flow.
  - Files: `setup.py`, `hashcrush/config.py`, `hashcrush/setup/__init__.py`, route modules using control paths.
  - Done when: paths are configurable, preserved on setup rerun, and no project-local path assumptions remain.

### Database Constraints and Query Performance
- [ ] `P1-DB-01` Add indexes/constraints for hot paths.
  - Files: `hashcrush/models.py`, `migrations/versions/0001_single_node_baseline.py`.
  - Required: index on `hashfile_hashes.hashfile_id`, composite index for queue scheduling (`status`, `priority`, `id`).

- [ ] `P1-DB-02 (New)` Add missing foreign keys and sensible cascade behavior.
  - Files: `hashcrush/models.py`, migrations.
  - Target tables: `hashfile_hashes`, `job_tasks`, `hashfiles` ownership/domain references.

### Security Hardening
- [ ] `P1-SEC-02 (New)` Prevent admin lockout scenarios.
  - Files: `hashcrush/users/routes.py`.
  - Done when: app cannot delete the last admin account and warns on self-delete/reset edge cases.

- [ ] `P1-SEC-03 (New)` Add authentication abuse protection.
  - Files: login flow (`hashcrush/users/routes.py`) and config.
  - Done when: login attempts are rate-limited / throttled and observable.

- [ ] `P1-SEC-04 (New)` Enforce secure session cookie settings in production.
  - Files: app config/bootstrap.
  - Done when: `Secure`, `HttpOnly`, and `SameSite` are explicitly configured for deployed mode.

## P2 - Medium Priority

### Validation, Dependencies, and Tests
- [ ] `P2-VAL-01` Refactor hash validators from `readlines()` to streaming line-by-line parsing.
  - File: `hashcrush/utils/utils.py`.
  - Done when: validators enforce per-line and total file size limits without loading whole files in memory.

- [ ] `P2-DEP-01` Pin and update dependencies to secure versions; remove deprecated packages.
  - Files: `requirements.txt`, `requirements-test.txt`.
  - Notes: remove/replace `flask-script`; pin `flask`, `flask-sqlalchemy`, `authlib` (if introduced), etc.

- [ ] `P2-TEST-01` Expand automated tests for authorization and method safety.
  - Files: `tests/security/*`, `tests/e2e/test_security.py`.
  - Minimum coverage: non-admin scoping, CSRF/method safety, task-group auth, plaintext format consistency.

- [ ] `P2-TEST-02 (New)` Add regressions for newly discovered issues.
  - Minimum coverage: dynamic wordlist tenant scope, domain delete guard, invalid ID handling (`404` not `500`).

### Documentation and UX Clarity
- [ ] `P2-OPS-01 (New)` Align container/runtime versions and startup model.
  - Files: `Dockerfile`, `pyproject.toml`, runtime docs.
  - Done when: supported Python version matches codebase requirements and container runs a production server configuration.

## P3 - Product and UX Backlog (Decision-Driven)
- [ ] `P3-PROD-12 (New)` Implement task/task-group import/export inside the app using JSON.

