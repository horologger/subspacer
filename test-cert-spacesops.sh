#!/bin/bash
set -euo pipefail

handle="${1:-}"
if [[ -z "$handle" ]]; then
  echo "Usage: $0 <handle>" >&2
  echo "  Example: $0 test@bitcoin2026" >&2
  exit 1
fi

if [[ "$handle" != *"@"* ]] || [[ "$handle" == *@*@* ]]; then
  echo "Error: handle must be exactly <subname>@<space_name> (single @)" >&2
  exit 1
fi

subname="${handle%%@*}"
space_name="${handle#*@}"

BASE_URL="${SUBSD_CERT_BASE_URL:-http://127.0.0.1:7264}"

curl -s "${BASE_URL}/api/subsd/spaces/${space_name}/${subname}/cert.json" \
  -H 'accept: */*'
