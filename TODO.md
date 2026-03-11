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