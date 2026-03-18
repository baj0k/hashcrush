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

- [ ] Ensure `docker compose up` serves an HTTPS-only application behind an `nginx` reverse proxy.
  Scope:
  1. Add an `nginx` service in Compose that terminates TLS and forwards to the internal Gunicorn app.
  2. Stop exposing the app container directly over plain HTTP in the default Compose topology.
  3. Set secure-cookie defaults for the HTTPS Compose path and align `.env.example` with it.
  4. Document certificate provisioning, reverse-proxy config, and the supported HTTPS-only local/prod runbook.
