# Certificate Callback API Documentation

## Overview

The Certificate Callback API allows external clients to register webhooks that receive notifications when certificate lifecycle events occur in a space. Callbacks are registered per space and can watch specific subspaces or all subspaces.

## Authentication

All callback management endpoints require Basic Authentication using the credentials configured in `SUBSD_RPC_USER` and `SUBSD_RPC_PASSWORD`.

## Event Types

The following events trigger callbacks:

1. **`certificate_issued`** - When a certificate is successfully issued via `subs cert issue`
2. **`request_uploaded`** - When a certificate request file (`.req.json`) is uploaded
3. **`request_added`** - When `subs add .` successfully processes a request
4. **`prove_completed`** - When a prove job completes successfully

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

Triggered when a certificate is successfully issued.

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

Triggered when a certificate request file is uploaded.

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

Triggered when `subs add .` successfully processes a request.

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

## Watch Filtering

Callbacks can watch specific subspaces or all subspaces:

- **Specific subspaces**: Set `watched_subnames` to an array of subspace names (e.g., `["alice", "bob"]`)
- **All subspaces**: Set `watched_subnames` to an empty array `[]`

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
        steps = event_data.get('steps')
        logging.info(f"Prove completed for job {job_id}")
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

3. **Issue a certificate** (triggers `certificate_issued` callback):
```bash
curl -X POST http://127.0.0.1:7244/spaces/tabconf/alice/issue \
  -u subsdadmin:OtherRisk84
```

4. **Check registered callbacks:**
```bash
curl -X GET http://127.0.0.1:7244/api/spaces/tabconf/callbacks \
  -u subsdadmin:OtherRisk84
```

5. **Unregister when done:**
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
