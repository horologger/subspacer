# Certificate Callback API Documentation

## Overview

The Certificate Callback API allows external clients to register webhooks that receive notifications when certificate lifecycle events occur in a space. Callbacks are registered per space and can watch specific subspaces or all subspaces.

**Important:** Webhooks are delivered by **`subsd`**. Operations that do not go through `subsd` (for example running `subs cert issue` or `subs prove` in your shell against the data directory) **do not** trigger callbacks, because `subsd` is never involved in those commands.

## Authentication

**Callback management** — register, list, get, update watches, delete — requires HTTP Basic authentication using `SUBSD_RPC_USER` and `SUBSD_RPC_PASSWORD`.

**Space operations** that change data or start work (`POST` issue, request upload, `POST` prove, backup/restore, etc.) use the same credentials. `GET /jobs/{job_id}` (job status) is **unauthenticated** in the current server.

## Event Types

The following events are emitted by `subsd` when the corresponding HTTP flow succeeds:

| Event | Trigger (must use `subsd` HTTP API) |
|--------|--------------------------------------|
| **`certificate_issued`** | `POST /spaces/{space_name}/{subspace}/issue` — `subsd` runs `subs cert issue` and then notifies. A local `subs cert issue` in the shell does **not** fire this event. |
| **`request_uploaded`** | `POST` to a request-upload route (e.g. `/spaces/{space}/{subspace}/req` with body, or other `subsd` upload handlers) after the `.req.json` is written. |
| **`request_added`** | After the same upload path runs `subs add .` successfully. |
| **`prove_completed`** | `POST /spaces/{space_name}/prove` — asynchronous prove job finishes successfully. Optional body `{"force": true}` runs **`subs prove`** even when **`subs commit`** has nothing to do (see [Prove jobs (HTTP API)](#prove-jobs-http-api)). See [Watch filtering](#watch-filtering). |

Base URL in examples is `http://127.0.0.1:7244` (or your `SUBSD_RPC_URL`). Paths are shown without an `/api` prefix except for callback **registration** routes under `/api/spaces/...`.

## Endpoints

### Register Callback

Register a new callback for a space.

**Endpoint:** `POST /api/spaces/{space_name}/callbacks/register`

**Request Body:**
```json
{
  "callback_url": "https://example.com/webhooks/certificates",
  "watched_subnames": ["alice", "bob"]
}
```

- `callback_url` (required): The URL to receive callback notifications
- `watched_subnames` (optional): Array of subspace names to watch. Empty array `[]` means watch all subspaces.

**Example:**
```bash
curl -X POST http://127.0.0.1:7244/api/spaces/tabconf/callbacks/register \
  -u subsdadmin:OtherRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "callback_url": "https://example.com/webhooks/certificates",
    "watched_subnames": ["alice", "bob"]
  }'
```

**Response:**
```json
{
  "id": "tabconf_1234567890",
  "callback_url": "https://example.com/webhooks/certificates",
  "watched_subnames": ["alice", "bob"],
  "created_at": 1234567890
}
```

### List Callbacks

Get all registered callbacks for a space.

**Endpoint:** `GET /api/spaces/{space_name}/callbacks`

**Example:**
```bash
curl -X GET http://127.0.0.1:7244/api/spaces/tabconf/callbacks \
  -u subsdadmin:OtherRisk84
```

**Response:**
```json
{
  "space_name": "tabconf",
  "callbacks": [
    {
      "id": "tabconf_1234567890",
      "callback_url": "https://example.com/webhooks/certificates",
      "watched_subnames": ["alice", "bob"],
      "created_at": 1234567890
    },
    {
      "id": "tabconf_1234567891",
      "callback_url": "https://another-service.com/hooks",
      "watched_subnames": [],
      "created_at": 1234567891
    }
  ]
}
```

### Get Callback

Get details of a specific callback.

**Endpoint:** `GET /api/spaces/{space_name}/callbacks/{callback_id}`

**Example:**
```bash
curl -X GET http://127.0.0.1:7244/api/spaces/tabconf/callbacks/tabconf_1234567890 \
  -u subsdadmin:OtherRisk84
```

**Response:**
```json
{
  "id": "tabconf_1234567890",
  "callback_url": "https://example.com/webhooks/certificates",
  "watched_subnames": ["alice", "bob"],
  "created_at": 1234567890
}
```

### Update Watch List

Update the list of subspaces watched by a callback.

**Endpoint:** `PUT /api/spaces/{space_name}/callbacks/{callback_id}/watches`

**Request Body:**
```json
{
  "watched_subnames": ["alice", "bob", "charlie"]
}
```

**Example:**
```bash
curl -X PUT http://127.0.0.1:7244/api/spaces/tabconf/callbacks/tabconf_1234567890/watches \
  -u subsdadmin:OtherRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "watched_subnames": ["alice", "bob", "charlie"]
  }'
```

**Response:**
```json
{
  "id": "tabconf_1234567890",
  "callback_url": "https://example.com/webhooks/certificates",
  "watched_subnames": ["alice", "bob", "charlie"],
  "created_at": 1234567890
}
```

### Unregister Callback

Remove a callback registration.

**Endpoint:** `DELETE /api/spaces/{space_name}/callbacks/{callback_id}`

**Example:**
```bash
curl -X DELETE http://127.0.0.1:7244/api/spaces/tabconf/callbacks/tabconf_1234567890 \
  -u subsdadmin:OtherRisk84
```

**Response:**
```json
{
  "success": true,
  "message": "Callback 'tabconf_1234567890' unregistered"
}
```

## Prove jobs (HTTP API)

To run `subs commit` and `subs prove` in a space **through** `subsd` (so the `prove_completed` callback can run and the job `result` includes a parsed chain tip):

1. **Start a job** — requires Basic auth (`SUBSD_RPC_USER` / `SUBSD_RPC_PASSWORD`):

   **`POST /spaces/{space_name}/prove`**

   **Optional body** (empty body or `{}` is valid), JSON:
   - **`force` (boolean, default `false`)** — If `true`, a failed **`subs commit`** that is *only* due to nothing to commit (messages such as *No changes to commit* or *no uncommitted changes found* from `subs`) does **not** stop the job: `subsd` records the commit step as `skipped` and still runs **`subs prove`**. Any other commit failure (e.g. spawn error) still fails the job. If `false` (default) or omitted, a no-op commit causes the job to end in `failed` and **`subs prove`** is not run.

   **Response (immediate):**
   ```json
   {
     "job_id": "tabconf_1234567890",
     "status": "pending",
     "created_at": 1234567890
   }
   ```

   The immediate response does **not** include the new chain anchor. When the job finishes, `result` and `prove_completed`’s `event_data` include **`anchor`** (chain tip) and **`force`** (boolean: `true` if commit was skipped and prove ran only because the request set `"force": true` and commit had no work).

2. **Poll for completion:**

   **`GET /jobs/{job_id}`** (no Basic auth in the current server)

   When the job ends, `status` is `completed` or `failed`. `result` includes `steps`, `anchor` (best-effort from `chain.json`), and `force` (see start-a-job body above; `false` on commit failure with no `force` resume). On failure, `error` is set. Example for a successful run:

   ```json
   {
     "job_id": "tabconf_1234567890",
     "status": "completed",
     "created_at": 1234567890,
     "completed_at": 1234567891,
     "result": {
       "steps": [ ... ],
       "anchor": "4c41e6a059483b20ea8fb65089a11315a46d07f6d2f6edf7960acec376c02327",
       "force": false
     },
     "error": null
   }
   ```

   - **`result.anchor`**: `post_diff_root` of the last entry in `{data_dir}/{space_name}/chain.json` at the end of the job (hex), or `null` if not available. Same as `event_data.anchor` in the `prove_completed` webhook.
   - **`result.force`**: `true` only if the run skipped a no-op commit and continued to prove because the client sent `"force": true`. Otherwise `false` (including failed jobs where commit did not use this path).

3. **Examples:**
   ```bash
   # Default: require subs commit to succeed (or job fails on “no changes to commit”)
   curl -sS -u "$SUBSD_RPC_USER:$SUBSD_RPC_PASSWORD" \
     -X POST "http://127.0.0.1:7244/spaces/tabconf/prove"
   ```
   ```bash
   # Run subs prove even when there is nothing to commit
   curl -sS -u "$SUBSD_RPC_USER:$SUBSD_RPC_PASSWORD" \
     -X POST "http://127.0.0.1:7244/spaces/tabconf/prove" \
     -H "Content-Type: application/json" \
     -d '{"force": true}'
   ```

## Callback Payload Format

When an event occurs, the server sends a POST request to the registered callback URL with the following payload structure:

```json
{
  "event_type": "certificate_issued",
  "space_name": "tabconf",
  "subspace": "alice",
  "handle": "alice@tabconf",
  "timestamp": 1234567890,
  "event_data": {
    // Event-specific data (see below)
  }
}
```

### Certificate Issued Event

Triggered when a certificate is successfully issued **by `subsd`** through **`POST /spaces/{space_name}/{subspace}/issue`**. If you only run `subs cert issue` in the terminal, `subsd` does not see it and this event is **not** sent.

**Payload:**
```json
{
  "event_type": "certificate_issued",
  "space_name": "tabconf",
  "subspace": "alice",
  "handle": "alice@tabconf",
  "timestamp": 1234567890,
  "event_data": {
    "cert_file": "alice@tabconf.cert.json",
    "anchor": "7ae80ecce2645b26c6ed273eb0c70c34d38e44f5c51a62f3915446c7511a0326"
  }
}
```

### Request Uploaded Event

Triggered when a certificate request file is uploaded through **`subsd`** (e.g. the multipart or JSON upload route for that subspace’s `.req.json`).

**Payload:**
```json
{
  "event_type": "request_uploaded",
  "space_name": "tabconf",
  "subspace": "alice",
  "handle": "alice@tabconf",
  "timestamp": 1234567890,
  "event_data": {
    "req_file": "alice@tabconf.req.json"
  }
}
```

### Request Added Event

Triggered when **`subsd`** runs `subs add .` successfully after an upload (same upload flow that wrote the request file).

**Payload:**
```json
{
  "event_type": "request_added",
  "space_name": "tabconf",
  "subspace": "alice",
  "handle": "alice@tabconf",
  "timestamp": 1234567890,
  "event_data": {
    "req_file": "alice@tabconf.req.json",
    "subs_output": "Added alice@tabconf to batch"
  }
}
```

### Prove Completed Event

Triggered when a prove job completes successfully. Note: `subspace` will be `null` for this event as it's space-level.

`event_data.anchor` is the current chain tip: the `post_diff_root` of the last entry in the space’s `chain.json` after the job (hex string), or `null` if the file is missing or has no entries. **`event_data.force`** is `true` if the commit step was skipped (no changes) and the job used **`"force": true`** on `POST /prove` so that **`subs prove`** still ran; otherwise `false`.

**Payload:**
```json
{
  "event_type": "prove_completed",
  "space_name": "tabconf",
  "subspace": null,
  "handle": null,
  "timestamp": 1234567890,
  "event_data": {
    "job_id": "tabconf_1234567890",
    "anchor": "4c41e6a059483b20ea8fb65089a11315a46d07f6d2f6edf7960acec376c02327",
    "force": false,
    "steps": [
      {
        "command": "subs commit",
        "status": "success",
        "output": "Committed batch"
      },
      {
        "command": "subs prove",
        "status": "success",
        "output": "Proof generated"
      }
    ]
  }
}
```

When commit was skipped due to `force: true` on the request, the first step often looks like `"status": "skipped"` with a `"note"` instead of a successful commit step.

See [Prove jobs (HTTP API)](#prove-jobs-http-api). `GET /jobs/{job_id}` returns the same `anchor`, `force`, and `steps` under `result` when the job has finished (success or failure; `anchor` is read from `chain.json` when possible).

## Watch Filtering

Callbacks can watch specific subspaces or all subspaces:

- **Specific subspaces**: Set `watched_subnames` to an array of subspace names (e.g., `["alice", "bob"]`)
- **All subspaces**: Set `watched_subnames` to an empty array `[]`

**`prove_completed` is space-level:** the outer payload has `subspace: null` and `handle: null`. The server only delivers `prove_completed` to registrations whose filter matches a “no subspace” event — in practice, **only** callbacks with **`watched_subnames: []` (watch all)** receive it. A callback restricted to e.g. `["alice"]` will **not** get `prove_completed`, because that event is not tied to a single subname.

**Example: Watch all subspaces**
```bash
curl -X POST http://127.0.0.1:7244/api/spaces/tabconf/callbacks/register \
  -u subsdadmin:OtherRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "callback_url": "https://example.com/webhooks/all-certificates",
    "watched_subnames": []
  }'
```

## Retry Logic

The server implements automatic retry logic for failed callback deliveries:

- **Retry attempts**: 3 attempts maximum
- **Backoff strategy**: Exponential backoff (1s, 2s, 4s delays)
- **Timeout**: 30 seconds per request

If all retry attempts fail, the error is logged but does not affect the main operation.

## Example Webhook Handler

Here's an example webhook handler in Python using Flask:

```python
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/webhooks/certificates', methods=['POST'])
def handle_certificate_callback():
    data = request.json
    
    event_type = data.get('event_type')
    space_name = data.get('space_name')
    subspace = data.get('subspace')
    handle = data.get('handle')
    timestamp = data.get('timestamp')
    event_data = data.get('event_data')
    
    logging.info(f"Received {event_type} event for {handle}")
    
    if event_type == 'certificate_issued':
        cert_file = event_data.get('cert_file')
        anchor = event_data.get('anchor')
        logging.info(f"Certificate issued: {cert_file} with anchor {anchor}")
        # Process certificate issuance...
        
    elif event_type == 'request_uploaded':
        req_file = event_data.get('req_file')
        logging.info(f"Request uploaded: {req_file}")
        # Process request upload...
        
    elif event_type == 'request_added':
        req_file = event_data.get('req_file')
        subs_output = event_data.get('subs_output')
        logging.info(f"Request added: {req_file} - {subs_output}")
        # Process request addition...
        
    elif event_type == 'prove_completed':
        job_id = event_data.get('job_id')
        anchor = event_data.get('anchor')  # chain tip post_diff_root, or None
        force = event_data.get('force', False)  # True if commit was skipped, prove ran with force
        steps = event_data.get('steps')
        logging.info(f"Prove completed for job {job_id} anchor={anchor} force={force}")
        # Process prove completion...
    
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

## Complete Example Workflow

1. **Register a callback:**
```bash
curl -X POST http://127.0.0.1:7244/api/spaces/tabconf/callbacks/register \
  -u subsdadmin:OtherRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "callback_url": "https://your-service.com/webhooks",
    "watched_subnames": ["alice"]
  }'
```

2. **Upload a certificate request** (triggers `request_uploaded` callback):
```bash
curl -X POST http://127.0.0.1:7244/spaces/tabconf/req \
  -u subsdadmin:OtherRisk84 \
  -F "file=@alice@tabconf.req.json"
```

3. **Issue a certificate** (triggers `certificate_issued` only when issued **via** `subsd`):
```bash
curl -X POST http://127.0.0.1:7244/spaces/tabconf/alice/issue \
  -u subsdadmin:OtherRisk84
```

4. **Start a prove job** (optional). `prove_completed` is only sent to callbacks registered with **`watched_subnames: []`** (watch all), not to a per-subname list like `["alice"]` — register a second callback with an empty list if you need this event alongside scoped cert webhooks.
```bash
curl -sS -X POST http://127.0.0.1:7244/spaces/tabconf/prove \
  -u subsdadmin:OtherRisk84
# Then poll: GET http://127.0.0.1:7244/jobs/{job_id}
# If the batch is empty and you still need subs prove, use: -H "Content-Type: application/json" -d '{"force": true}'
```

5. **Check registered callbacks:**
```bash
curl -X GET http://127.0.0.1:7244/api/spaces/tabconf/callbacks \
  -u subsdadmin:OtherRisk84
```

6. **Unregister when done:**
```bash
curl -X DELETE http://127.0.0.1:7244/api/spaces/tabconf/callbacks/tabconf_1234567890 \
  -u subsdadmin:OtherRisk84
```

## Best Practices

1. **Idempotency**: Design your webhook handler to be idempotent. The same event may be delivered multiple times due to retries.

2. **Response Time**: Respond to callback requests quickly (within 5 seconds) to avoid timeouts.

3. **Status Codes**: Return HTTP 200-299 for successful processing. Any other status code will trigger retries.

4. **Logging**: Log all received callbacks for debugging and auditing purposes.

5. **Security**: Validate callback payloads and consider implementing signature verification if handling sensitive data.

6. **Error Handling**: Handle errors gracefully and return appropriate HTTP status codes.

7. **Watch Lists**: Use specific watch lists when possible to reduce unnecessary callbacks.

## Storage

Callbacks are persisted to disk at `<data_dir>/<space_name>/callbacks.json`. The server loads all callbacks on startup, so registrations survive server restarts.

## Error Responses

All endpoints return standard HTTP status codes:

- `200 OK` - Success
- `400 Bad Request` - Invalid request (e.g., empty callback_url)
- `401 Unauthorized` - Missing or invalid authentication
- `404 Not Found` - Callback or space not found
- `500 Internal Server Error` - Server error

Error response format:
```json
{
  "error": "Error message describing what went wrong"
}
```
