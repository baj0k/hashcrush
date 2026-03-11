#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .env.test ]]; then
  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    line="${raw_line#"${raw_line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    [[ -z "$key" || "$key" == "$line" ]] && continue
    if [[ "$value" =~ ^\".*\"$ ]] || [[ "$value" =~ ^\'.*\'$ ]]; then
      value="${value:1:${#value}-2}"
    fi
    if [[ -z "${!key+x}" ]]; then
      export "$key=$value"
    fi
  done < .env.test
fi

export PYTHONPATH="${PYTHONPATH:-.}"
export HASHCRUSH_E2E_MODE="${HASHCRUSH_E2E_MODE:-local}"

echo "[1/2] Running non-E2E tests"
pytest -q -m "not e2e and not e2e_external" -rs

if [[ "${HASHCRUSH_E2E_MODE}" == "external" ]]; then
  echo "[2/2] Running E2E tests against external host ${HASHCRUSH_E2E_BASE_URL}"
  e2e_marker="e2e_external"
else
  echo "[2/2] Running E2E tests against self-bootstrapped local app"
  e2e_marker="e2e"
fi
e2e_log="$(mktemp)"
trap 'rm -f "$e2e_log"' EXIT

set +e
pytest -q -m "$e2e_marker" -rs | tee "$e2e_log"
pytest_status=${PIPESTATUS[0]}
set -e

if (( pytest_status != 0 )); then
  exit "$pytest_status"
fi

if grep -q '^SKIPPED ' "$e2e_log"; then
  echo >&2
  echo "E2E suite reported skipped tests. Fix the live credentials, fixtures, or host availability before treating the run as successful." >&2
  exit 1
fi
