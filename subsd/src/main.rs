use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use anyhow::{Context, Result};
use axum::{
    extract::{Path as PathExtractor, State, Query},
    http::{header, StatusCode, HeaderMap},
    response::{Html, Json, IntoResponse},
    routing::get,
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
struct Config {
    spaced_rpc_url: String,
    spaced_rpc_user: String,
    spaced_rpc_password: String,
    data_dir: String,
    rpc_bind: String,
    rpc_port: u16,
    rpc_url: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Config {
            spaced_rpc_url: env::var("SUBSD_SPACED_RPC_URL")
                .context("SUBSD_SPACED_RPC_URL not set")?,
            spaced_rpc_user: env::var("SUBSD_SPACED_RPC_USER")
                .context("SUBSD_SPACED_RPC_USER not set")?,
            spaced_rpc_password: env::var("SUBSD_SPACED_RPC_PASSWORD")
                .context("SUBSD_SPACED_RPC_PASSWORD not set")?,
            data_dir: env::var("SUBSD_DATA_DIR")
                .context("SUBSD_DATA_DIR not set")?,
            rpc_bind: env::var("SUBSD_RPC_BIND")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            rpc_port: env::var("SUBSD_RPC_PORT")
                .unwrap_or_else(|_| "7244".to_string())
                .parse()
                .context("SUBSD_RPC_PORT must be a valid port number")?,
            rpc_url: env::var("SUBSD_RPC_URL")
                .unwrap_or_else(|_| format!("http://127.0.0.1:7244")),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CertFile {
    handle: String,
    script_pubkey: String,
    anchor: String,
    #[serde(flatten)]
    _other: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
struct SearchCertFile {
    handle: String,
    script_pubkey: String,
    anchor: String,
    status: String,
    commitment: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommitmentResponse {
    state_root: String,
    prev_root: Option<String>,
    history_hash: String,
    block_height: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
    jsonrpc: String,
    result: Option<CommitmentResponse>,
    error: Option<serde_json::Value>,
    id: u64,
}

#[derive(Serialize, Deserialize)]
struct SpaceInfo {
    handle: String,
    anchor: String,
    certificate_requests: usize,
    issued_certificates: usize,
}

async fn healthcheck(_state: State<Config>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn list_spaces(state: State<Config>) -> impl IntoResponse {
    let data_dir = Path::new(&state.data_dir);
    
    let mut folders = Vec::new();
    
    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_dir() {
                            if let Some(folder_name) = path.file_name() {
                                if let Some(name_str) = folder_name.to_str() {
                                    folders.push(name_str.to_string());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading directory entry: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            let error_html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error - Subsd</title>
</head>
<body>
    <h1>Error</h1>
    <p>Failed to read data directory: {}</p>
</body>
</html>"#,
                html_escape(&e.to_string())
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)).into_response();
        }
    }
    
    folders.sort();
    
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subsd - Spaces List</title>
    <style>
        body {{
            font-family: monospace;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }}
        ul {{
            list-style-type: none;
            padding: 0;
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
        }}
        li {{
            padding: 8px;
            border-bottom: 1px solid #eee;
        }}
        li:last-child {{
            border-bottom: none;
        }}
        .count {{
            color: #666;
            font-size: 0.9em;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <h1>Spaces</h1>
    <ul>
{}
    </ul>
    <div class="count">Total: {} folder(s)</div>
</body>
</html>"#,
        folders
            .iter()
            .map(|f| format!("        <li>{}</li>", html_escape(f)))
            .collect::<Vec<_>>()
            .join("\n"),
        folders.len()
    );
    
    Html(html).into_response()
}

#[derive(Deserialize)]
struct FormatQuery {
    format: Option<String>,
}

async fn check_commitment_on_chain(
    config: &Config,
    space_name: &str,
    anchor: &str,
) -> String {
    let client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create HTTP client: {}", e);
            return "Failed to create HTTP client".to_string();
        }
    };

    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(
            format!("{}:{}", config.spaced_rpc_user, config.spaced_rpc_password)
        )
    );

    let space_handle = format!("@{}", space_name);
    let mut current_anchor = anchor.to_string();

    loop {
        let rpc_request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getcommitment".to_string(),
            params: vec![
                serde_json::Value::String(space_handle.clone()),
                serde_json::Value::String(current_anchor.clone()),
            ],
            id: 1,
        };

        let response = match client
            .post(&config.spaced_rpc_url)
            .header("Content-Type", "application/json")
            .header("Authorization", &auth_header)
            .json(&rpc_request)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to call SPACED RPC: {}", e);
                return "Failed to call SPACED RPC".to_string();
            }
        };

        let rpc_response: RpcResponse = match response.json().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to parse RPC response: {}", e);
                return "Failed to parse RPC response".to_string();
            }
        };

        if let Some(error) = rpc_response.error {
            warn!("RPC error: {:?}", error);
            return "RPC error:".to_string();
        }
        
        let commitment = match rpc_response.result {
            Some(commitment) => commitment,
            None => {
                warn!("RPC response missing result");
                return "unable to check commitment".to_string();
            }
        };

        // Check if state_root matches the subspace anchor
        if commitment.state_root == anchor {
            return "commitment is on chain".to_string();
        }

        // If prev_root is null, we've reached the end without finding a match
        match commitment.prev_root {
            Some(prev_root) => {
                current_anchor = prev_root;
                // Continue the loop with the prev_root
            }
            None => {
                // prev_root is null and we didn't find a match
                return "this handle does not appear in any on chain commitment".to_string();
            }
        }
    }
}

async fn get_subspace_cert(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    Query(params): Query<FormatQuery>,
    State(config): State<Config>,
) -> impl IntoResponse {
    // Determine response format: check query parameter first, then Accept header
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);
    
    // Construct the path to the cert file: <data_dir>/<space_name>/<subspace>@<space_name>.cert.json
    let space_dir = Path::new(&config.data_dir).join(&space_name);
    let cert_file_path = space_dir.join(format!("{}@{}.cert.json", subspace, space_name));

    // Check if cert file exists
    if !cert_file_path.exists() {
        // Check if a request file exists
        let req_file_path = space_dir.join(format!("{}@{}.req.json", subspace, space_name));
        
        let error_msg = if req_file_path.exists() {
            format!("Certificate request exists for {}@{}, but a certificate has not yet been issued", subspace, space_name)
        } else {
            format!("Certificate not found: {}@{}.cert.json", subspace, space_name)
        };
        
        if wants_json {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": error_msg
                })),
            )
                .into_response();
        } else {
            return (
                StatusCode::NOT_FOUND,
                Html(format!(
                    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Not Found - Subsd</title>
</head>
<body>
    <h1>Not Found</h1>
    <p>{}</p>
</body>
</html>"#,
                    html_escape(&error_msg)
                )),
            )
                .into_response();
        }
    }

    // Read and parse the cert file
    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            let error_msg = format!("Failed to read certificate file: {}", e);
            if wants_json {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": error_msg
                    })),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!(
                        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error - Subsd</title>
</head>
<body>
    <h1>Error</h1>
    <p>{}</p>
</body>
</html>"#,
                        html_escape(&error_msg)
                    )),
                )
                    .into_response();
            }
        }
    };

    let cert: CertFile = match serde_json::from_str(&cert_content) {
        Ok(cert) => cert,
        Err(e) => {
            warn!("Failed to parse cert file {}: {}", cert_file_path.display(), e);
            let error_msg = format!("Failed to parse certificate file: {}", e);
            if wants_json {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": error_msg
                    })),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!(
                        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error - Subsd</title>
</head>
<body>
    <h1>Error</h1>
    <p>{}</p>
</body>
</html>"#,
                        html_escape(&error_msg)
                    )),
                )
                    .into_response();
            }
        }
    };

    // Read and parse the root space certificate to compare anchors
    let root_cert_path = space_dir.join(format!("@{}.cert.json", space_name));
    let status = match fs::read_to_string(&root_cert_path) {
        Ok(root_cert_content) => {
            match serde_json::from_str::<CertFile>(&root_cert_content) {
                Ok(root_cert) => {
                    if cert.anchor == root_cert.anchor {
                        "matches root anchor".to_string()
                    } else {
                        "not in most recent root anchor".to_string()
                    }
                }
                Err(e) => {
                    warn!("Failed to parse root cert file {}: {}", root_cert_path.display(), e);
                    "unable to verify anchor".to_string()
                }
            }
        }
        Err(e) => {
            warn!("Failed to read root cert file {}: {}", root_cert_path.display(), e);
            "unable to verify anchor".to_string()
        }
    };

    // Check commitment on chain
    let commitment = check_commitment_on_chain(&config, &space_name, &cert.anchor).await;

    let search_cert = SearchCertFile {
        handle: cert.handle.clone(),
        script_pubkey: cert.script_pubkey.clone(),
        anchor: cert.anchor.clone(),
        status: status.clone(),
        commitment: commitment.clone(),
    };

    if wants_json {
        Json(search_cert).into_response()
    } else {
        // Return HTML response
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}@{} - Subsd</title>
    <style>
        body {{
            font-family: monospace;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }}
        .info {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
            margin-top: 20px;
        }}
        .field {{
            margin-bottom: 15px;
        }}
        .field-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}
        .field-value {{
            color: #333;
            word-break: break-all;
        }}
        .status {{
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .status.matches {{
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        .status.not-matches {{
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }}
        .status.unknown {{
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        .commitment {{
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .commitment.on-chain {{
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        .commitment.not-on-chain {{
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }}
        .commitment.unknown {{
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
    </style>
</head>
<body>
    <h1>Subspace: {}@{}</h1>
    <div class="info">
        <div class="field">
            <div class="field-label">Handle</div>
            <div class="field-value">{}</div>
        </div>
        <div class="field">
            <div class="field-label">Script Pubkey</div>
            <div class="field-value">{}</div>
        </div>
        <div class="field">
            <div class="field-label">Anchor</div>
            <div class="field-value">{}</div>
        </div>
        <div class="status {}">
            Status: {}
        </div>
        <div class="commitment {}">
            Commitment: {}
        </div>
    </div>
</body>
</html>"#,
            html_escape(&subspace),
            html_escape(&space_name),
            html_escape(&subspace),
            html_escape(&space_name),
            html_escape(&cert.handle),
            html_escape(&cert.script_pubkey),
            html_escape(&cert.anchor),
            if status == "matches root anchor" {
                "matches"
            } else if status == "not in most recent root anchor" {
                "not-matches"
            } else {
                "unknown"
            },
            html_escape(&status),
            if commitment == "commitment is on chain" {
                "on-chain"
            } else if commitment == "this handle does not appear in any on chain commitment" {
                "not-on-chain"
            } else {
                "unknown"
            },
            html_escape(&commitment)
        );
        Html(html).into_response()
    }
}

async fn get_space_info(
    PathExtractor(space_name): PathExtractor<String>,
    headers: HeaderMap,
    Query(params): Query<FormatQuery>,
    State(config): State<Config>,
) -> impl IntoResponse {
    // Determine response format: check query parameter first, then Accept header
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);

    // Construct the path to the cert file: <data_dir>/<space_name>/@<space_name>.cert.json
    let space_dir = Path::new(&config.data_dir).join(&space_name);
    let cert_file_path = space_dir.join(format!("@{}.cert.json", space_name));

    // Read and parse the cert file
    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            let error_msg = format!("Certificate file not found: @{}.cert.json", space_name);
            if wants_json {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": error_msg
                    })),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::NOT_FOUND,
                    Html(format!(
                        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Not Found - Subsd</title>
</head>
<body>
    <h1>Not Found</h1>
    <p>{}</p>
</body>
</html>"#,
                        html_escape(&error_msg)
                    )),
                )
                    .into_response();
            }
        }
    };

    let cert: CertFile = match serde_json::from_str(&cert_content) {
        Ok(cert) => cert,
        Err(e) => {
            warn!("Failed to parse cert file {}: {}", cert_file_path.display(), e);
            let error_msg = format!("Failed to parse certificate file: {}", e);
            if wants_json {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": error_msg
                    })),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!(
                        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error - Subsd</title>
</head>
<body>
    <h1>Error</h1>
    <p>{}</p>
</body>
</html>"#,
                        html_escape(&error_msg)
                    )),
                )
                    .into_response();
            }
        }
    };

    // Count certificate requests (*@<space_name>.req.json)
    let mut certificate_requests = 0;
    let mut issued_certificates = 0;
    
    match fs::read_dir(&space_dir) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                            // Count certificate requests: *@<space_name>.req.json
                            if file_name.ends_with(&format!("@{}.req.json", space_name)) {
                                certificate_requests += 1;
                            }
                            // Count issued certificates: *@<space_name>.cert.json (but exclude @<space_name>.cert.json itself)
                            if file_name.ends_with(&format!("@{}.cert.json", space_name))
                                && file_name != format!("@{}.cert.json", space_name)
                            {
                                issued_certificates += 1;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to read space directory {}: {}", space_dir.display(), e);
        }
    }

    let space_info = SpaceInfo {
        handle: cert.handle.clone(),
        anchor: cert.anchor.clone(),
        certificate_requests,
        issued_certificates,
    };

    if wants_json {
        Json(space_info).into_response()
    } else {
        // Return HTML response
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Subsd</title>
    <style>
        body {{
            font-family: monospace;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }}
        .info {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
            margin-top: 20px;
        }}
        .field {{
            margin-bottom: 15px;
        }}
        .field-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}
        .field-value {{
            color: #333;
            word-break: break-all;
        }}
        .stats {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        .stat-item {{
            display: inline-block;
            margin-right: 30px;
        }}
        .stat-label {{
            font-weight: bold;
            color: #666;
            margin-right: 5px;
        }}
        .stat-value {{
            color: #333;
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <h1>Space: {}</h1>
    <div class="info">
        <div class="field">
            <div class="field-label">Handle</div>
            <div class="field-value">{}</div>
        </div>
        <div class="field">
            <div class="field-label">Anchor</div>
            <div class="field-value">{}</div>
        </div>
        <div class="stats">
            <div class="stat-item">
                <span class="stat-label">Certificate Requests:</span>
                <span class="stat-value">{}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Issued Certificates:</span>
                <span class="stat-value">{}</span>
            </div>
        </div>
    </div>
</body>
</html>"#,
            html_escape(&space_name),
            html_escape(&space_name),
            html_escape(&cert.handle),
            html_escape(&cert.anchor),
            certificate_requests,
            issued_certificates
        );
        Html(html).into_response()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Load configuration from environment
    let config = Config::from_env()?;

    info!("Starting subsd RPC server");
    info!("Configuration:");
    info!("  Spaced RPC URL: {}", config.spaced_rpc_url);
    info!("  Data directory: {}", config.data_dir);
    info!("  RPC bind: {}:{}", config.rpc_bind, config.rpc_port);
    info!("  RPC URL: {}", config.rpc_url);

    // Build the application router
    let app = Router::new()
        .route("/", get(list_spaces))
        .route("/health", get(healthcheck))
        .route("/spaces/:space_name", get(get_space_info))
        .route("/spaces/:space_name/:subspace", get(get_subspace_cert))
        .with_state(config.clone());

    // Create the server address
    let addr: SocketAddr = format!("{}:{}", config.rpc_bind, config.rpc_port)
        .parse()
        .context("Invalid bind address")?;

    info!("Listening on {}", addr);

    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Server error")?;

    Ok(())
}

