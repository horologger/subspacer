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
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Clone)]
struct Config {
    spaced_rpc_url: String,
    spaced_rpc_user: String,
    spaced_rpc_password: String,
    data_dir: String,
    rpc_bind: String,
    rpc_port: u16,
    rpc_url: String,
    list_subspaces: bool,
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
            list_subspaces: env::var("SUBSD_LIST_SUBSPACES")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        })
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
struct HealthResponse {
    /// Status of the server
    status: String,
    /// Version of the server
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

#[derive(Serialize, Deserialize, Debug, ToSchema)]
struct SearchCertFile {
    /// Full handle (e.g., "user@did")
    handle: String,
    /// Script public key
    script_pubkey: String,
    /// Anchor hash
    anchor: String,
    /// Status compared to root anchor: "matches root anchor" or "not in most recent root anchor"
    status: String,
    /// On-chain commitment status: "commitment is on chain" or "this handle does not appear in any on chain commitment"
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

#[derive(Serialize, Deserialize, ToSchema)]
struct SpaceInfo {
    /// Handle of the space (e.g., "self@did")
    handle: String,
    /// Anchor hash of the space
    anchor: String,
    /// Number of certificate requests
    certificate_requests: usize,
    /// Number of issued certificates
    issued_certificates: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct ParamInfo {
    name: String,
    #[serde(rename = "type")]
    param_type: String,
    required: bool,
    description: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EndpointInfo {
    path: String,
    method: String,
    description: String,
    path_params: Vec<ParamInfo>,
    query_params: Vec<ParamInfo>,
    response_formats: Vec<String>,
    example_path: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct DiscoveryResponse {
    /// Server version
    version: String,
    /// Server name
    server_name: String,
    /// Base URL of the server
    base_url: String,
    /// List of available endpoints
    endpoints: Vec<EndpointInfo>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
struct ErrorResponse {
    /// Error message
    error: String,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        healthcheck,
        get_space_info,
        get_subspace_cert,
        discover_endpoints
    ),
    components(schemas(
        HealthResponse,
        SpaceInfo,
        SearchCertFile,
        DiscoveryResponse,
        ErrorResponse
    )),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "spaces", description = "Space management endpoints"),
        (name = "discovery", description = "API discovery endpoints")
    ),
    info(
        title = "Subsd API",
        description = "RPC server for managing spaces and certificates",
        version = "0.1.0"
    ),
    servers(
        (url = "http://127.0.0.1:7244", description = "Local development server")
    )
)]
struct ApiDoc;

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Server is healthy", body = HealthResponse)
    )
)]
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
        li a {{
            color: #007bff;
            text-decoration: none;
        }}
        li a:hover {{
            text-decoration: underline;
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
            .map(|f| format!("        <li><a href=\"/spaces/{}\">{}</a></li>", html_escape(f), html_escape(f)))
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

#[utoipa::path(
    get,
    path = "/api",
    tag = "discovery",
    params(
        ("format" = Option<String>, Query, description = "Response format: 'json' for JSON, omit for HTML")
    ),
    responses(
        (status = 200, description = "API discovery information", body = DiscoveryResponse, content_type = "application/json"),
        (status = 200, description = "API discovery information (HTML)", content_type = "text/html")
    )
)]
async fn discover_endpoints(
    headers: HeaderMap,
    Query(params): Query<FormatQuery>,
    State(config): State<Config>,
) -> impl IntoResponse {
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);

    let base_url = config.rpc_url.clone();
    let endpoints = vec![
        EndpointInfo {
            path: "/".to_string(),
            method: "GET".to_string(),
            description: "List all spaces (folders) found in the data directory".to_string(),
            path_params: vec![],
            query_params: vec![],
            response_formats: vec!["html".to_string()],
            example_path: Some("/".to_string()),
        },
        EndpointInfo {
            path: "/health".to_string(),
            method: "GET".to_string(),
            description: "Health check endpoint".to_string(),
            path_params: vec![],
            query_params: vec![],
            response_formats: vec!["json".to_string()],
            example_path: Some("/health".to_string()),
        },
        EndpointInfo {
            path: "/spaces/{space_name}".to_string(),
            method: "GET".to_string(),
            description: "Get information about a specific space, including handle, anchor, certificate requests count, and issued certificates count".to_string(),
            path_params: vec![ParamInfo {
                name: "space_name".to_string(),
                param_type: "string".to_string(),
                required: true,
                description: "Name of the space (folder name without leading '@')".to_string(),
            }],
            query_params: vec![ParamInfo {
                name: "format".to_string(),
                param_type: "string".to_string(),
                required: false,
                description: "Response format: 'json' for JSON, omit for HTML".to_string(),
            }],
            response_formats: vec!["html".to_string(), "json".to_string()],
            example_path: Some("/spaces/did".to_string()),
        },
        EndpointInfo {
            path: "/spaces/{space_name}/{subspace}".to_string(),
            method: "GET".to_string(),
            description: "Get certificate information for a subspace, including handle, script_pubkey, anchor, anchor status comparison, and on-chain commitment verification".to_string(),
            path_params: vec![
                ParamInfo {
                    name: "space_name".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    description: "Name of the space (folder name without leading '@')".to_string(),
                },
                ParamInfo {
                    name: "subspace".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    description: "Subspace name (part before '@' in handle, e.g., 'user' from 'user@did')".to_string(),
                },
            ],
            query_params: vec![ParamInfo {
                name: "format".to_string(),
                param_type: "string".to_string(),
                required: false,
                description: "Response format: 'json' for JSON, omit for HTML".to_string(),
            }],
            response_formats: vec!["html".to_string(), "json".to_string()],
            example_path: Some("/spaces/did/user".to_string()),
        },
        EndpointInfo {
            path: "/api".to_string(),
            method: "GET".to_string(),
            description: "API discovery endpoint - returns this list of available endpoints".to_string(),
            path_params: vec![],
            query_params: vec![ParamInfo {
                name: "format".to_string(),
                param_type: "string".to_string(),
                required: false,
                description: "Response format: 'json' for JSON, omit for HTML".to_string(),
            }],
            response_formats: vec!["html".to_string(), "json".to_string()],
            example_path: Some("/api".to_string()),
        },
    ];

    let discovery = DiscoveryResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        server_name: "subsd".to_string(),
        base_url,
        endpoints,
    };

    if wants_json {
        Json(discovery).into_response()
    } else {
        let endpoints_html: String = discovery.endpoints.iter().map(|ep| {
            let path_params_html = if ep.path_params.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="params"><strong>Path Parameters:</strong><ul>{}</ul></div>"#,
                    ep.path_params.iter().map(|p| format!(
                        "<li><code>{}</code> ({}) - {} {}</li>",
                        html_escape(&p.name), html_escape(&p.param_type),
                        if p.required { "<strong>required</strong>" } else { "optional" },
                        html_escape(&p.description)
                    )).collect::<Vec<_>>().join("")
                )
            };
            let query_params_html = if ep.query_params.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="params"><strong>Query Parameters:</strong><ul>{}</ul></div>"#,
                    ep.query_params.iter().map(|p| format!(
                        "<li><code>{}</code> ({}) - {} {}</li>",
                        html_escape(&p.name), html_escape(&p.param_type),
                        if p.required { "<strong>required</strong>" } else { "optional" },
                        html_escape(&p.description)
                    )).collect::<Vec<_>>().join("")
                )
            };
            let example_html = ep.example_path.as_ref().map(|ex| {
                format!(r#"<div class="example"><strong>Example:</strong> <code>{}</code></div>"#, html_escape(ex))
            }).unwrap_or_default();
            format!(
                r#"<div class="endpoint"><div class="endpoint-header"><span class="method">{}</span><span class="path">{}</span></div><div class="description">{}</div><div class="formats"><strong>Response Formats:</strong> {}</div>{}{}{}</div>"#,
                html_escape(&ep.method), html_escape(&ep.path), html_escape(&ep.description),
                ep.response_formats.join(", "), path_params_html, query_params_html, example_html
            )
        }).collect::<Vec<_>>().join("
");
        let html = format!(
            r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>API Discovery - Subsd</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:1000px;margin:50px auto;padding:20px;background-color:#f5f5f5}}h1{{color:#333;border-bottom:3px solid #333;padding-bottom:10px}}.info{{background-color:white;border:1px solid #ddd;border-radius:4px;padding:20px;margin-bottom:20px}}.endpoint{{background-color:white;border:1px solid #ddd;border-radius:4px;padding:20px;margin-bottom:15px}}.endpoint-header{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}.method{{background-color:#007bff;color:white;padding:4px 8px;border-radius:3px;font-weight:bold;font-size:0.9em}}.path{{font-family:monospace;font-size:1.1em;color:#333}}.description{{color:#666;margin-bottom:10px}}.formats{{color:#666;font-size:0.9em;margin-bottom:10px}}.params{{margin-top:10px;margin-bottom:10px}}.params ul{{margin:5px 0;padding-left:20px}}.params li{{margin:5px 0}}.params code{{background-color:#f4f4f4;padding:2px 6px;border-radius:3px;font-family:monospace}}.example{{margin-top:10px;padding:10px;background-color:#f8f9fa;border-left:3px solid #007bff}}.example code{{font-family:monospace;color:#007bff}}</style></head><body><h1>Subsd API Discovery</h1><div class="info"><p><strong>Server:</strong> {}</p><p><strong>Version:</strong> {}</p><p><strong>Base URL:</strong> <code>{}</code></p></div><h2>Available Endpoints</h2>{}</body></html>"#,
            html_escape(&discovery.server_name), html_escape(&discovery.version),
            html_escape(&discovery.base_url), endpoints_html
        );
        Html(html).into_response()
    }
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

#[utoipa::path(
    get,
    path = "/spaces/{space_name}/{subspace}",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space (folder name without leading '@')"),
        ("subspace" = String, Path, description = "Subspace name (part before '@' in handle, e.g., 'user' from 'user@did')"),
        ("format" = Option<String>, Query, description = "Response format: 'json' for JSON, omit for HTML")
    ),
    responses(
        (status = 200, description = "Subspace certificate information", body = SearchCertFile, content_type = "application/json"),
        (status = 200, description = "Subspace certificate information (HTML)", content_type = "text/html"),
        (status = 404, description = "Certificate not found or request exists but not issued", body = ErrorResponse)
    )
)]
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
        .back-link {{
            margin-bottom: 15px;
        }}
        .back-link a {{
            color: #007bff;
            text-decoration: none;
            font-size: 0.9em;
        }}
        .back-link a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="back-link"><a href="/spaces/{}">← Back to Space: {}</a></div>
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
            html_escape(&space_name),
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

#[utoipa::path(
    get,
    path = "/spaces/{space_name}",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space (folder name without leading '@')"),
        ("format" = Option<String>, Query, description = "Response format: 'json' for JSON, omit for HTML")
    ),
    responses(
        (status = 200, description = "Space information", body = SpaceInfo, content_type = "application/json"),
        (status = 200, description = "Space information (HTML)", content_type = "text/html"),
        (status = 404, description = "Space not found", body = ErrorResponse)
    )
)]
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
    let mut subspaces: Vec<(String, bool)> = Vec::new(); // (subspace_name, has_cert)
    
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
                                
                                // Extract subspace name if listing is enabled
                                if config.list_subspaces {
                                    if let Some(subspace_name) = file_name.strip_suffix(&format!("@{}.req.json", space_name)) {
                                        let cert_file_name = format!("{}@{}.cert.json", subspace_name, space_name);
                                        let cert_path = space_dir.join(&cert_file_name);
                                        let has_cert = cert_path.exists();
                                        subspaces.push((subspace_name.to_string(), has_cert));
                                    }
                                }
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
    
    // Sort subspaces by name
    if config.list_subspaces {
        subspaces.sort_by(|a, b| a.0.cmp(&b.0));
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
        .back-link {{
            margin-bottom: 15px;
        }}
        .back-link a {{
            color: #007bff;
            text-decoration: none;
            font-size: 0.9em;
        }}
        .back-link a:hover {{
            text-decoration: underline;
        }}
        .subspaces {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        .subspaces h3 {{
            color: #666;
            font-size: 1em;
            margin-bottom: 10px;
        }}
        .subspaces ul {{
            list-style-type: none;
            padding: 0;
            margin: 0;
        }}
        .subspaces li {{
            padding: 5px 0;
        }}
        .subspaces li a {{
            color: #007bff;
            text-decoration: none;
        }}
        .subspaces li a:hover {{
            text-decoration: underline;
        }}
        .subspaces li .no-link {{
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="back-link"><a href="/">← Back to Spaces List</a></div>
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
        {}
    </div>
</body>
</html>"#,
            html_escape(&space_name),
            html_escape(&space_name),
            html_escape(&cert.handle),
            html_escape(&cert.anchor),
            certificate_requests,
            issued_certificates,
            if config.list_subspaces && !subspaces.is_empty() {
                let subspaces_html: String = subspaces
                    .iter()
                    .map(|(subspace_name, has_cert)| {
                        if *has_cert {
                            format!(
                                "<li><a href=\"/spaces/{}/{}\">{}</a></li>",
                                html_escape(&space_name),
                                html_escape(subspace_name),
                                html_escape(subspace_name)
                            )
                        } else {
                            format!(
                                "<li><span class=\"no-link\">{}</span></li>",
                                html_escape(subspace_name)
                            )
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    r#"<div class="subspaces">
            <h3>Subspaces:</h3>
            <ul>
{}
            </ul>
        </div>"#,
                    subspaces_html
                )
            } else {
                String::new()
            }
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
        .merge(
            SwaggerUi::new("/docs")
                .url("/openapi.json", ApiDoc::openapi())
        )
        .route("/", get(list_spaces))
        .route("/health", get(healthcheck))
        .route("/api", get(discover_endpoints))
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

