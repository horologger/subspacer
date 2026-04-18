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

space_name="${handle#*@}"

curl -X 'POST' \
  "https://spacesops.com/api/subsd/spaces/${space_name}/add" \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"handle":"%s","script_pubkey":"5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a"}' "$handle")"
