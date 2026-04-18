#!/bin/bash

curl -X 'POST' \
  'http://127.0.0.1:7244/spaces/bitcoin2026/add' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "handle": "test@bitcoin2026",
  "script_pubkey": "5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a"
}'
