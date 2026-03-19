# TODO

## P1 - Production Runtime
- [ ] Support serving the local Compose deployment on a configurable hostname such as `hashcrush.test`.
  Scope:
  1. Add a configurable hostname/domain setting for the local reverse-proxy path.
  2. Include that hostname in generated self-signed certificate SANs and `nginx` `server_name` config.
  3. Document local DNS or `/etc/hosts` setup for reaching the app by name.
  4. Prefer a safe local-only domain such as `.test` over `.local`, and document the tradeoffs.
