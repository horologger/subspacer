# Find handles by script pubkey

This document describes how **subsd** and the **subspacer** repo resolve **handles** (e.g. `user@bitcoin2026`) from **script pubkeys** using a CSV index and an HTTP API. It is intended for integration from other projects (CLIs, backends, browsers).

---

## Concepts

| Term | Meaning |
|------|---------|
| **Handle** | String `{subname}@{space_name}` matching certificate request files (`*.req.json`). |
| **Script pubkey** | Hex string in a request JSON’s `script_pubkey` field (same value the API matches on). |
| **Index file** | `scanned-pubkeys.csv` — one row per unique `handle,script_pubkey` pair discovered from request files. |

Matching is **exact string equality** on `script_pubkey` after normalization (no trimming inside the hex string beyond CSV line handling).

---

## Index file: `scanned-pubkeys.csv`

### Location (subsd)

**subsd** reads the CSV from the **parent directory of `SUBSD_DATA_DIR`**, with filename **`scanned-pubkeys.csv`**.

Example:

| `SUBSD_DATA_DIR` | CSV path |
|------------------|----------|
| `./data/spaces` | `./data/scanned-pubkeys.csv` |
| `/var/lib/subsd/spaces` | `/var/lib/subsd/scanned-pubkeys.csv` |

If that file is missing, the HTTP API returns **404** (see below).

### Line format

- **Encoding:** UTF-8 text, one record per line.
- **Shape:** `handle,script_pubkey`
- **Delimiter:** The **first comma** on the line separates `handle` from `script_pubkey`. The substring **after** that comma is the full pubkey (handles are not expected to contain commas).
- **Empty lines** are ignored.

Example:

```text
admin@bitcoin2026,51204cfed5829bc76a173a556ac2b97cb6f53c31c08fa4c3572e147a343dc5196a52
```

### Populating the CSV (this repo)

From the **repository root**, run:

```bash
./scan-script-pubkeys
```

- Recursively finds `*.req.json` under `data/spaces/`.
- For each file, reads JSON fields `handle` and `script_pubkey` and appends `handle,script_pubkey` to `data/scanned-pubkeys.csv`.
- **Does not** append a line if that exact line already exists (`grep -Fxq`).
- Requires **`jq`**.

**Operational note:** Run `scan-script-pubkeys` (or your own indexer) whenever request files change, and deploy/sync `scanned-pubkeys.csv` next to your spaces data so **subsd** can read it.

---

## CLI: `find-handles`

Script: **`find-handles`** (repo root).

Prints **one handle per line** for rows whose `script_pubkey` equals the argument.

```bash
./find-handles <script_pubkey>
```

Example:

```bash
./find-handles 51204cfed5829bc76a173a556ac2b97cb6f53c31c08fa4c3572e147a343dc5196a52
```

Uses the same **first-comma** split as **subsd** and the same default CSV path: **`data/scanned-pubkeys.csv`** relative to the script’s repo root.

---

## HTTP API (subsd)

### Endpoint

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/spaces/find-handles` |
| **Authentication** | None (anonymous) |
| **Content-Type** | `application/json` |

**Why POST:** Browsers disallow a request body on `GET`/`HEAD` (`fetch` throws). POST is used so browser and Swagger clients can send JSON.

### Request body

```json
{
  "script_pubkeys": [
    "512079b4e497ef23074f0772fdcd541ae0e3eee753d4b325311dbaf14585b61a9b13",
    "5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a"
  ]
}
```

- `script_pubkeys`: array of hex strings (exact match against the CSV’s second field).
- Duplicates in the array are fine; the server treats the set of pubkeys to look up as a set for matching purposes.

### Success response — `200 OK`

`Content-Type: application/json`

Body: **JSON array** of objects. One object **per CSV row** whose `script_pubkey` is in `script_pubkeys`. Order follows **CSV line order**, not the order of keys in the request.

```json
[
  {
    "handle": "admin@bitcoin2026",
    "script_pubkey": "51204cfed5829bc76a173a556ac2b97cb6f53c31c08fa4c3572e147a343dc5196a52"
  }
]
```

If nothing matches, the array is **`[]`**.

### Error responses

| Status | When | Body shape |
|--------|------|------------|
| **404** | `scanned-pubkeys.csv` not found at the resolved path | `{ "error": "<message>" }` |
| **500** | CSV exists but cannot be read | `{ "error": "<message>" }` |

Malformed JSON or wrong schema may yield **4xx** from the framework (e.g. **400** / **422**).

### CORS

**subsd** enables permissive CORS (`tower-http` `CorsLayer::permissive()`) so browser clients (e.g. Swagger UI on another port) can call this API. If you still see network errors, check **mixed content** (page `https://` calling `http://` API) or corporate proxies.

### Base URL

Configured by **`SUBSD_RPC_URL`** / bind (e.g. `http://127.0.0.1:7244`). Full URL example:

`http://127.0.0.1:7244/api/spaces/find-handles`

### OpenAPI

Interactive docs: **`GET /docs`** (Swagger UI). OpenAPI JSON: **`GET /openapi.json`**.

### Example: `curl`

```bash
curl -s -X POST 'http://127.0.0.1:7244/api/spaces/find-handles' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"script_pubkeys":["512079b4e497ef23074f0772fdcd541ae0e3eee753d4b325311dbaf14585b61a9b13"]}'
```

### Example: browser `fetch`

```javascript
const res = await fetch("http://127.0.0.1:7244/api/spaces/find-handles", {
  method: "POST",
  headers: { "Content-Type": "application/json", Accept: "application/json" },
  body: JSON.stringify({
    script_pubkeys: [
      "512079b4e497ef23074f0772fdcd541ae0e3eee753d4b325311dbaf14585b61a9b13",
    ],
  }),
});
if (!res.ok) throw new Error(await res.text());
const matches = await res.json(); // Array<{ handle: string, script_pubkey: string }>
```

---

## Semantics summary (for implementers)

1. Build/maintain **`scanned-pubkeys.csv`** next to **`SUBSD_DATA_DIR`’s parent** (see table above).
2. Each line: **`handle` + first comma + `script_pubkey`** (rest of line).
3. API returns **all rows** where `script_pubkey` is in the request list (multiple handles can share a pubkey if you ever duplicate rows; normally one row per pair).
4. Matching is **case-sensitive** hex string equality (consistent with how the CSV is written).

---

## Related files in this repo

| File | Role |
|------|------|
| `scan-script-pubkeys` | Build/update `data/scanned-pubkeys.csv` from `*.req.json` |
| `find-handles` | CLI lookup by one pubkey |
| `subsd` (`src/main.rs`) | `POST /api/spaces/find-handles` |
