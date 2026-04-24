#!/bin/bash
# Issue a certificate via subsd POST /spaces/{space}/{subspace}/issue so
# certificate_issued callbacks run (CLI `subs cert issue` bypasses subsd).
set -euo pipefail

handle="${1:-}"
if [[ -z "$handle" ]]; then
  echo "Usage: $0 <subspace>@<space_name>" >&2
  echo "  Example: $0 alice@bitcoin2026" >&2
  echo "  Env: SUBSD_RPC_URL (default http://127.0.0.1:7244), SUBSD_RPC_USER, SUBSD_RPC_PASSWORD" >&2
  exit 1
fi

if [[ "$handle" != *"@"* ]] || [[ "$handle" == *@*@* ]]; then
  echo "Error: handle must be exactly <subspace>@<space_name> (single @)" >&2
  exit 1
fi

subspace="${handle%%@*}"
space_name="${handle#*@}"

BASE_URL="${SUBSD_RPC_URL:-http://127.0.0.1:7244}"
BASE_URL="${BASE_URL%/}"

if [[ -z "${SUBSD_RPC_USER:-}" ]] || [[ -z "${SUBSD_RPC_PASSWORD:-}" ]]; then
  echo "Error: SUBSD_RPC_USER and SUBSD_RPC_PASSWORD must be set (e.g. source setup-subsd-env.sh)" >&2
  exit 1
fi

curl -sS -f -u "${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}" \
  -X POST \
  -H 'Accept: application/json' \
  "${BASE_URL}/spaces/${space_name}/${subspace}/issue"

echo
