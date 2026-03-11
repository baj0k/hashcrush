# TODO

## P1 - Production Runtime

- [ ] Split the in-process executor into a dedicated worker command.
  Scope:
  1. Add `python3 ./hashcrush.py worker`.
  2. Stop auto-starting the executor from the web process.
  3. Keep one DB-backed queue/executor owner per deployment.
  4. Document the supported `serve` + `worker` production topology.

- [ ] Replace the Flask development server production path with reverse proxy + WSGI app server.
  Scope:
  1. Define the supported production topology as reverse proxy (`nginx` or `caddy`) plus a real WSGI server.
  2. Stop treating `app.run(...)` as the long-term production serving model.
  3. Decide whether TLS terminates at the reverse proxy and simplify app-side serving accordingly.
  4. Document the supported deployment/runbook around the WSGI server entrypoint.

- [ ] Define and test backup/restore for PostgreSQL deployments.
  Scope:
  1. Document the supported `pg_dump` / restore workflow.
  2. Verify restore into a fresh environment.
  3. Include config backup expectations and runtime-path expectations.
  4. Add the backup/restore flow to the production deploy checklist.

## P3 - Audit and Operations

- [ ] Add audit-log filtering and export for production use.
  Scope:
  1. Filter by actor, event type, target type, and date range.
  2. Add admin-only CSV export.
  3. Keep the default audit view usable on larger datasets.

## P3 - Database and Platform

- [ ] Keep validating future ORM cleanup batches against the PostgreSQL automated lane.
  Scope:
  1. Treat PostgreSQL as the required source-of-truth database for ORM/runtime changes.
  2. Do not rely on a production database or `setup --test` as the primary automated validation path.
