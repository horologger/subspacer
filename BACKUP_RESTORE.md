# Space backup and restore (subsd)

These RPCs operate on **`SUBSD_DATA_DIR`** (typically `data/spaces`). **Archive files** are stored under **`data/spaces_backups`**, which is the **sibling** of the `spaces` folder (same parent as `SUBSD_DATA_DIR`):

| `SUBSD_DATA_DIR` | Space data | Backups directory |
|------------------|------------|-------------------|
| `./data/spaces` | `./data/spaces/{space_name}` | `./data/spaces_backups` |

Both endpoints require **HTTP Basic Authentication** (`SUBSD_RPC_USER` / `SUBSD_RPC_PASSWORD`).

---

## Backup

**`GET /spaces/{space_name}/backup`**

- Requires the space folder **`{SUBSD_DATA_DIR}/{space_name}`** to exist (otherwise **404**).
- Runs `tar` on the **contents** of that folder only (nothing under `spaces_backups` is included).
- Writes **`{YYYYMMDD}_{space_name}.tar`** into **`spaces_backups/`** (directory is created if needed).
- Returns that archive as **`Content-Type: application/x-tar`** with **`Content-Disposition: attachment`**.

### curl (download to file)

Replace host, port, space name, and credentials.

```bash
export SUBSD_RPC_URL="${SUBSD_RPC_URL:-http://127.0.0.1:7244}"
export SUBSD_RPC_USER="${SUBSD_RPC_USER:-subsdadmin}"
export SUBSD_RPC_PASSWORD="${SUBSD_RPC_PASSWORD:-yourpassword}"

SPACE="bitcoin2026"

curl -sS -u "${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}" \
  -o "backup-${SPACE}.tar" \
  "${SUBSD_RPC_URL}/spaces/${SPACE}/backup"
```

### curl (stdout to file with explicit name)

```bash
curl -sS -u "${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}" \
  "${SUBSD_RPC_URL}/spaces/bitcoin2026/backup" \
  -o my-backup.tar
```

---

## Restore

**`POST /spaces/{space_name}/restore`**

- **Multipart form** with one part: field name **`file`** (same convention as certificate request upload).
- Body must be a **`.tar`** archive (e.g. from backup above).
- The upload is **saved** under **`spaces_backups/`** as `restore_{space_name}_{nanos}.tar`, then **`tar -xf`** runs from that path into **`{SUBSD_DATA_DIR}/{space_name}`** (directory created if needed).
- **Overwrites / merges** files from the archive with existing files in that folder. Use only with trusted archives.
- If **`tar` extract fails**, the saved file under `spaces_backups` is removed.

Success response **200** JSON:

```json
{
  "success": true,
  "message": "Archive saved under spaces_backups and extracted into space directory",
  "space": "bitcoin2026",
  "path": "/absolute/path/to/data/spaces/bitcoin2026",
  "archive_path": "/absolute/path/to/data/spaces_backups/restore_bitcoin2026_123456789.tar"
}
```

### curl (upload a tar file)

```bash
export SUBSD_RPC_URL="${SUBSD_RPC_URL:-http://127.0.0.1:7244}"
export SUBSD_RPC_USER="${SUBSD_RPC_USER:-subsdadmin}"
export SUBSD_RPC_PASSWORD="${SUBSD_RPC_PASSWORD:-yourpassword}"

SPACE="bitcoin2026"
ARCHIVE="./backup-bitcoin2026.tar"

curl -sS -u "${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}" \
  -X POST \
  -F "file=@${ARCHIVE}" \
  "${SUBSD_RPC_URL}/spaces/${SPACE}/restore"
```

### curl (verbose, inspect HTTP status)

```bash
curl -v -u "${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}" \
  -X POST \
  -F "file=@${ARCHIVE}" \
  "${SUBSD_RPC_URL}/spaces/${SPACE}/restore"
```

---

## Requirements

- **`tar`** must be available on the **subsd** host (`tar` is invoked for create and extract).
- Backup builds the archive in a **temp file** first, then copies the finished file into **`spaces_backups/`**, so the tarball never lives inside the space folder and is never included in its own archive.

---

## Errors (summary)

| HTTP | Typical cause |
|------|-------------------|
| **401** | Missing or wrong Basic Auth |
| **400** | Invalid `space_name` (must be a single path segment: no `/`, `\\`, or `..`) |
| **404** (backup) | Space directory does not exist |
| **400** (restore) | No `file` part, empty upload, or read error |
| **500** | `tar` failed, or filesystem error |

---

## OpenAPI

See **`GET /docs`** on the server for interactive try-out; spec is at **`GET /openapi.json`**.
