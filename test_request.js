const SUBSD_RPC_URL = process.env.SUBSD_RPC_URL || "http://0.0.0.0:7244";
const SUBSD_RPC_USER = process.env.SUBSD_RPC_USER || "subsdadmin";
const SUBSD_RPC_PASSWORD = process.env.SUBSD_RPC_PASSWORD || "OtherRisk84";

const handle = process.argv[2];
const script_pubkey = process.argv[3];

if (!handle || !script_pubkey) {
  console.error("Usage: node test_request.js <handle> <script_pubkey>");
  console.error("  Example: node test_request.js custom@eurt 5120fae0...");
  process.exit(1);
}

const [subspace, space_name] = handle.split("@");

if (!subspace || !space_name) {
  console.error("Error: handle must be in the format <subspace>@<space_name>");
  process.exit(1);
}

const certRequest = { handle, script_pubkey };

async function uploadCertRequest() {
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

  if (!response.ok) {
    console.error("Error:", response.status, result);
    process.exit(1);
  }

  console.log("Success:", result);
}

uploadCertRequest().catch(console.error);
