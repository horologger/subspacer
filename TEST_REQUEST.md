# Submitting a Certificate Request in Node.js

This document describes how to submit a subspace certificate request to `subsd` using the
`POST /spaces/{space_name}/{subspace}/req` RPC endpoint, and how to use the included
`test_request.js` test program.

## Prerequisites

- Node.js 18 or later (uses the built-in `fetch` API)
- A running `subsd` instance

## RPC Endpoint

```
POST /spaces/{space_name}/{subspace}/req
```

Uploads a certificate request for a subspace. The request body must be a JSON object with the
following fields:

| Field | Type | Description |
|---|---|---|
| `handle` | string | The subspace handle in the format `{subspace}@{space_name}` |
| `script_pubkey` | string | The hex-encoded script public key for the subspace |

### Authentication

HTTP Basic Authentication is required. Credentials are configured via environment variables (see below).

### Response

On success (`200 OK`):

```json
{
  "success": true,
  "message": "Certificate request file uploaded and processed successfully",
  "file_path": "<path to saved .req.json file>",
  "subs_output": "<output from subs add .>"
}
```

On error, an appropriate HTTP status code is returned with `{ "error": "<message>" }`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SUBSD_RPC_URL` | `http://0.0.0.0:7244` | Base URL of the `subsd` RPC server |
| `SUBSD_RPC_USER` | `<rpc_user>` | Basic Auth username |
| `SUBSD_RPC_PASSWORD` | `<rpc_password>` | Basic Auth password |

You can source the provided setup script to configure these for a local dev environment:

```bash
source setup-subsd-env.sh
```

## Node.js Example

The following is the minimal code to submit a certificate request:

```javascript
const SUBSD_RPC_URL = process.env.SUBSD_RPC_URL || "http://0.0.0.0:7244";
const SUBSD_RPC_USER = process.env.SUBSD_RPC_USER || "<rpc_user>";
const SUBSD_RPC_PASSWORD = process.env.SUBSD_RPC_PASSWORD || "<rpc_password>";

const space_name = "eurt";
const subspace = "custom";

const certRequest = {
  handle: "custom@eurt",
  script_pubkey: "5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a",
};

const url = `${SUBSD_RPC_URL}/spaces/${space_name}/${subspace}/req`;
const credentials = Buffer.from(`${SUBSD_RPC_USER}:${SUBSD_RPC_PASSWORD}`).toString("base64");

const response = await fetch(url, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Basic ${credentials}`,
  },
  body: JSON.stringify(certRequest),
});

const result = await response.json();
console.log(result);
```

## Using `test_request.js`

`test_request.js` is a command-line program that submits a certificate request to `subsd`.

### Usage

```
node test_request.js <handle> <script_pubkey>
```

| Argument | Description |
|---|---|
| `handle` | The subspace handle in the format `{subspace}@{space_name}` |
| `script_pubkey` | The hex-encoded script public key |

The `space_name` and `subspace` are automatically parsed from the handle by splitting on `@`.

### Example

```bash
node test_request.js custom@eurt 5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a
```

This submits the following JSON to `POST /spaces/eurt/custom/req`:

```json
{
  "handle": "custom@eurt",
  "script_pubkey": "5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a"
}
```

### Example with environment overrides

```bash
SUBSD_RPC_URL=http://127.0.0.1:7244 \
SUBSD_RPC_USER=<rpc_user> \
SUBSD_RPC_PASSWORD=<rpc_password> \
node test_request.js custom@eurt 5120fae0ee07ffd7b6411b09f7e1585d9516888a02099d4ae909f26a27419d2f680a
```

### Success output

```
Success: {
  success: true,
  message: 'Certificate request file uploaded and processed successfully',
  file_path: 'data/spaces/eurt/custom@eurt.req.json',
  subs_output: '...'
}
```

### Error output

If the handle format is invalid:
```
Error: handle must be in the format <subspace>@<space_name>
```

If the server returns an error:
```
Error: 401 { error: 'Unauthorized' }
```
