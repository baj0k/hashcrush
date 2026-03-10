#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .env.test ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.test
  set +a
fi

export PYTHONPATH="${PYTHONPATH:-.}"

echo "[1/2] Running non-E2E tests"
pytest -q -m "not e2e" -rs

required_e2e_vars=(
  HASHCRUSH_E2E_BASE_URL
  HASHCRUSH_E2E_USERNAME
  HASHCRUSH_E2E_PASSWORD
  HASHCRUSH_E2E_SECOND_USERNAME
  HASHCRUSH_E2E_SECOND_PASSWORD
  HASHCRUSH_E2E_DOMAIN_ID
  HASHCRUSH_E2E_HASHFILE_ID
  HASHCRUSH_E2E_TASK_ID
  HASHCRUSH_E2E_TASK_NAME
)

missing_vars=()
for var_name in "${required_e2e_vars[@]}"; do
  if [[ -z "${!var_name:-}" ]]; then
    missing_vars+=("$var_name")
  fi
done

if (( ${#missing_vars[@]} > 0 )); then
  echo >&2
  echo "Missing E2E variables: ${missing_vars[*]}" >&2
  echo "Run python3 ./hashcrush.py setup --test to generate a ready-to-use .env.test." >&2
  exit 1
fi

echo "[2/2] Running E2E tests"
pytest -q -m e2e -rs
