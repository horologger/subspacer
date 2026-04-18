use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use anyhow::{Context, Result};
use axum::{
    extract::{Path as PathExtractor, State, Query, Multipart},
    http::{header, StatusCode, HeaderMap, HeaderValue},
    response::{Html, Json, IntoResponse, Response},
    routing::{get, post, delete, put},
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
enum JobStatus {
    Pending,
    Processing,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct Job {
    id: String,
    space_name: String,
    status: JobStatus,
    created_at: u64,
    completed_at: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct JobResponse {
    job_id: String,
    status: String,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct JobStatusResponse {
    job_id: String,
    status: String,
    created_at: u64,
    completed_at: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

type JobStore = Arc<Mutex<HashMap<String, Job>>>;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct CallbackRegistration {
    /// Unique callback ID
    id: String,
    /// Callback URL to notify
    callback_url: String,
    /// List of subnames to watch (empty = watch all)
    watched_subnames: Vec<String>,
    /// Creation timestamp
    created_at: u64,
}

type CallbackStore = Arc<Mutex<HashMap<String, Vec<CallbackRegistration>>>>;

#[derive(Debug, Clone)]
struct Config {
    spaced_rpc_url: String,
    spaced_rpc_user: String,
    spaced_rpc_password: String,
    data_dir: String,
    rpc_bind: String,
    rpc_port: u16,
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    list_subspaces: bool,
}

type AppConfigs = Arc<Mutex<HashMap<String, Vec<String>>>>;

#[derive(Debug, Clone)]
struct AppState {
    config: Config,
    jobs: JobStore,
    app_configs: AppConfigs,
    callbacks: CallbackStore,
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
            rpc_user: env::var("SUBSD_RPC_USER")
                .context("SUBSD_RPC_USER not set")?,
            rpc_password: env::var("SUBSD_RPC_PASSWORD")
                .context("SUBSD_RPC_PASSWORD not set")?,
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
    /// State: "taken" when certificate exists
    state: String,
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
    /// Script public key
    script_pubkey: String,
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

/// Certificate request JSON body (anonymous add endpoint)
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
struct CertRequestJsonBody {
    /// Handle in the form `{subname}@{space_name}`
    handle: String,
    /// Hex-encoded script public key
    script_pubkey: String,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        healthcheck,
        get_space_info,
        upload_space_req_file,
        add_space_req_json,
        prove_space,
        get_job_status,
        get_subspace_cert,
        download_cert,
        download_cert_json,
        upload_req_file,
        issue_cert,
        discover_endpoints,
        register_cert_callback,
        unregister_cert_callback,
        update_cert_watches,
        get_cert_callback,
        list_cert_callbacks
    ),
    components(schemas(
        HealthResponse,
        SpaceInfo,
        SearchCertFile,
        DiscoveryResponse,
        ErrorResponse,
        CertRequestJsonBody,
        JobResponse,
        JobStatusResponse,
        JobStatus,
        CallbackRegistration,
        RegisterCallbackRequest,
        UpdateWatchesRequest,
        CallbackListResponse
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
async fn healthcheck(_state: State<AppState>) -> Json<HealthResponse> {
    info!("Health check endpoint called");
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn list_spaces(state: State<AppState>) -> impl IntoResponse {
    let data_dir = Path::new(&state.config.data_dir);
    
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

async fn get_app_config(
    Query(params): Query<AppQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let wants_json = params.format.as_deref() == Some("json");
    
    let spaces = match params.app {
        Some(app_name) => {
            let app_configs = state.app_configs.lock().await;
            app_configs.get(&app_name).cloned().unwrap_or_default()
        }
        None => Vec::new(),
    };

    if wants_json {
        Json(serde_json::json!({
            "spaces": spaces
        })).into_response()
    } else {
        let result = spaces.join(",");
        (StatusCode::OK, result).into_response()
    }
}

#[derive(Deserialize)]
struct FormatQuery {
    format: Option<String>,
    app: Option<String>,
}

#[derive(Deserialize)]
struct AppQuery {
    app: Option<String>,
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
    State(state): State<AppState>,
) -> impl IntoResponse {
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);

    let base_url = state.config.rpc_url.clone();
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
            path: "/spaces/{space_name}/add".to_string(),
            method: "POST".to_string(),
            description: "Anonymous JSON upload of a certificate request (same processing as /spaces/{space_name}/req but body is JSON with handle and script_pubkey; no authentication)".to_string(),
            path_params: vec![ParamInfo {
                name: "space_name".to_string(),
                param_type: "string".to_string(),
                required: true,
                description: "Name of the space; must match the handle suffix".to_string(),
            }],
            query_params: vec![],
            response_formats: vec!["json".to_string()],
            example_path: Some("/spaces/bitcoin2026/add".to_string()),
        },
        EndpointInfo {
            path: "/spaces/{space_name}/{subspace}/cert.json".to_string(),
            method: "GET".to_string(),
            description: "Get the subspace certificate file as inline JSON (same data as /cert without Basic Auth and without Content-Disposition attachment)".to_string(),
            path_params: vec![
                ParamInfo {
                    name: "space_name".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    description: "Name of the space".to_string(),
                },
                ParamInfo {
                    name: "subspace".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    description: "Subspace name (part before '@' in the handle)".to_string(),
                },
            ],
            query_params: vec![],
            response_formats: vec!["json".to_string()],
            example_path: Some("/spaces/bitcoin2026/test/cert.json".to_string()),
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
    let mut iteration = 0;
    const MAX_ITERATIONS: usize = 100; // Prevent infinite loops

    info!("Checking commitment for space {} with anchor {}", space_name, anchor);

    loop {
        iteration += 1;
        if iteration > MAX_ITERATIONS {
            warn!("Max iterations reached checking commitment for space {} anchor {}", space_name, anchor);
            return "unable to check commitment (max iterations reached)".to_string();
        }

        let rpc_request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getcommitment".to_string(),
            params: vec![
                serde_json::Value::String(space_handle.clone()),
                serde_json::Value::String(current_anchor.clone()),
            ],
            id: 1,
        };

        info!("RPC call {}: getcommitment({}, {})", iteration, space_handle, current_anchor);

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
            warn!("RPC error for space {} anchor {}: {:?}", space_name, current_anchor, error);
            return format!("RPC error: {:?}", error);
        }
        
        let commitment = match rpc_response.result {
            Some(commitment) => commitment,
            None => {
                if iteration == 1 {
                    // First iteration with no result means the anchor doesn't exist in any commitment
                    warn!("Anchor {} for space {} not found in any commitment - subspace may not be committed on-chain yet", current_anchor, space_name);
                    return "this handle does not appear in any on chain commitment".to_string();
                } else {
                    // Subsequent iteration with no result shouldn't happen, but handle it
                    warn!("RPC response missing result for space {} anchor {} at iteration {}", space_name, current_anchor, iteration);
                    return "unable to check commitment".to_string();
                }
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
        (status = 200, description = "Subspace is available (no cert or request exists)", body = serde_json::Value, content_type = "application/json"),
        (status = 404, description = "Certificate request exists but certificate has not yet been issued", body = ErrorResponse)
    )
)]
async fn get_subspace_cert(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    Query(params): Query<FormatQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Determine response format: check query parameter first, then Accept header
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);
    
    // Get spaces list if app parameter is present
    let spaces = if params.app.is_some() {
        vec![space_name.clone()]
    } else {
        Vec::new()
    };
    
    // Construct the path to the cert file: <data_dir>/<space_name>/<subspace>@<space_name>.cert.json
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
    
    // Check if the space folder exists
    if !space_dir.exists() {
        if wants_json {
            let mut response = serde_json::json!({
                "state": "unhosted",
                "handle": format!("{}@{}", subspace, space_name),
                "1_block_fee": 10000,
                "6_block_fee": 2000,
                "48_block_fee": 1000
            });
            if params.app.is_some() {
                response["spaces"] = serde_json::json!(spaces);
            }
            info!("Response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
            return (
                StatusCode::OK,
                Json(response),
            )
                .into_response();
        } else {
            return (
                StatusCode::OK,
                Html(format!(
                    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Subspace Unhosted - Subsd</title>
</head>
<body>
    <h1>Subspace: {}@{}</h1>
    <p>Status: <strong>unhosted</strong></p>
    <p>This space is not hosted on this server.</p>
</body>
</html>"#,
                    html_escape(&subspace),
                    html_escape(&space_name)
                )),
            )
                .into_response();
        }
    }
    
    let cert_file_path = space_dir.join(format!("{}@{}.cert.json", subspace, space_name));

    // Check if cert file exists
    if !cert_file_path.exists() {
        // Check if a request file exists
        let req_file_path = space_dir.join(format!("{}@{}.req.json", subspace, space_name));
        
        if !req_file_path.exists() {
            // No cert and no request - check reserved list and validation
            // First check if reserved
            if is_reserved_subname(&subspace) {
                // Reserved subnames are not available
                if wants_json {
                    let mut response = serde_json::json!({
                        "state": "reserved",
                        "handle": format!("{}@{}", subspace, space_name),
                        "1_block_fee": 10000,
                        "6_block_fee": 2000,
                        "48_block_fee": 1000
                    });
                    if params.app.is_some() {
                        response["spaces"] = serde_json::json!(spaces);
                    }
                    info!("Response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
                    return (
                        StatusCode::OK,
                        Json(response),
                    )
                        .into_response();
                } else {
                    return (
                        StatusCode::OK,
                        Html(format!(
                            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Subspace Reserved - Subsd</title>
</head>
<body>
    <h1>Subspace: {}@{}</h1>
    <p>Status: <strong>reserved</strong></p>
    <p>This subspace is reserved and cannot be registered.</p>
</body>
</html>"#,
                            html_escape(&subspace),
                            html_escape(&space_name)
                        )),
                    )
                        .into_response();
                }
            }
            
            // Check if subname is too short
            if subspace.len() < 3 {
                if wants_json {
                    let mut response = serde_json::json!({
                        "state": "invalid",
                        "handle": format!("{}@{}", subspace, space_name),
                        "1_block_fee": 10000,
                        "6_block_fee": 2000,
                        "48_block_fee": 1000
                    });
                    if params.app.is_some() {
                        response["spaces"] = serde_json::json!(spaces);
                    }
                    info!("Response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
                    return (
                        StatusCode::OK,
                        Json(response),
                    )
                        .into_response();
                } else {
                    return (
                        StatusCode::OK,
                        Html(format!(
                            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Subspace Invalid - Subsd</title>
</head>
<body>
    <h1>Subspace: {}@{}</h1>
    <p>Status: <strong>invalid</strong></p>
    <p>Subspace names must be at least 3 characters long.</p>
</body>
</html>"#,
                            html_escape(&subspace),
                            html_escape(&space_name)
                        )),
                    )
                        .into_response();
                }
            }
            
            // Subspace is available - calculate price
            let price = subname_pricer(&subspace);
            if wants_json {
                let mut response = serde_json::json!({
                    "state": "available",
                    "handle": format!("{}@{}", subspace, space_name),
                    "price": price,
                    "1_block_fee": 10000,
                    "6_block_fee": 2000,
                    "48_block_fee": 1000
                });
                if params.app.is_some() {
                    response["spaces"] = serde_json::json!(spaces);
                }
                info!("Response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
                return (
                    StatusCode::OK,
                    Json(response),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::OK,
                    Html(format!(
                        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Subspace Available - Subsd</title>
</head>
<body>
    <h1>Subspace: {}@{}</h1>
    <p>Status: <strong>available</strong></p>
    <p>Price: <strong>{} satoshis</strong></p>
    <p>This subspace is available and has not been requested or issued.</p>
</body>
</html>"#,
                        html_escape(&subspace),
                        html_escape(&space_name),
                        price
                    )),
                )
                    .into_response();
            }
        }
        
        // Request exists but cert doesn't - certificate not yet issued
        let error_msg = format!("Certificate request exists for {}@{}, but a certificate has not yet been issued", subspace, space_name);
        
        if wants_json {
            let mut response = serde_json::json!({
                "error": error_msg,
                "1_block_fee": 10000,
                "6_block_fee": 2000,
                "48_block_fee": 1000
            });
            if params.app.is_some() {
                response["spaces"] = serde_json::json!(spaces);
            }
            return (
                StatusCode::NOT_FOUND,
                Json(response),
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
                let mut response = serde_json::json!({
                    "error": error_msg,
                    "1_block_fee": 10000,
                    "6_block_fee": 2000,
                    "48_block_fee": 1000
                });
                if params.app.is_some() {
                    response["spaces"] = serde_json::json!(spaces);
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(response),
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
                let mut response = serde_json::json!({
                    "error": error_msg,
                    "1_block_fee": 10000,
                    "6_block_fee": 2000,
                    "48_block_fee": 1000
                });
                if params.app.is_some() {
                    response["spaces"] = serde_json::json!(spaces);
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(response),
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
    let commitment = check_commitment_on_chain(&state.config, &space_name, &cert.anchor).await;

    let search_cert = SearchCertFile {
        handle: cert.handle.clone(),
        state: "taken".to_string(),
        script_pubkey: cert.script_pubkey.clone(),
        anchor: cert.anchor.clone(),
        status: status.clone(),
        commitment: commitment.clone(),
    };

    if wants_json {
        let mut response = serde_json::to_value(&search_cert).unwrap_or_else(|_| serde_json::json!({}));
        // Add fee fields
        response["1_block_fee"] = serde_json::json!(10000);
        response["6_block_fee"] = serde_json::json!(2000);
        response["48_block_fee"] = serde_json::json!(1000);
        // Always add spaces if app parameter was provided, even if empty
        if params.app.is_some() {
            response["spaces"] = serde_json::json!(spaces);
        }
        info!("Response: {}", serde_json::to_string_pretty(&response).unwrap_or_default());
        Json(response).into_response()
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
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5em;
            line-height: 1.2;
            margin: 0;
        }}
        .download-link {{
            font-size: 0.8em !important;
            line-height: 1.2;
            vertical-align: middle;
            display: inline-flex;
            align-items: center;
            text-decoration: none;
            color: #007bff;
            font-size: 0.8em;
            padding: 4px 8px;
            border: 1px solid #007bff;
            border-radius: 4px;
            transition: background-color 0.2s;
            background-color: transparent;
            cursor: pointer;
            font-family: monospace;
        }}
        .download-link:hover {{
            background-color: #007bff;
            color: white;
        }}
        .download-icon {{
            width: 16px;
            height: 16px;
            margin-right: 4px;
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
    <h1>
        Subspace: {}@{}
        <a href="/spaces/{}/{}/cert" class="download-link" title="Download certificate">
            <svg class="download-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Certificate
        </a>
    </h1>
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
            html_escape(&space_name),
            html_escape(&subspace),
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
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Determine response format: check query parameter first, then Accept header
    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/json"))
            .unwrap_or(false);

    // Construct the path to the cert file: <data_dir>/<space_name>/@<space_name>.cert.json
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
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
                                if state.config.list_subspaces {
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
    if state.config.list_subspaces {
        subspaces.sort_by(|a, b| a.0.cmp(&b.0));
    }

    let space_info = SpaceInfo {
        handle: cert.handle.clone(),
        script_pubkey: cert.script_pubkey.clone(),
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
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5em;
            line-height: 1.2;
            margin: 0;
        }}
        .download-link {{
            font-size: 0.8em !important;
            line-height: 1.2;
            vertical-align: middle;
            display: inline-flex;
            align-items: center;
            text-decoration: none;
            color: #007bff;
            font-size: 0.8em;
            padding: 4px 8px;
            border: 1px solid #007bff;
            border-radius: 4px;
            transition: background-color 0.2s;
            background-color: transparent;
            cursor: pointer;
            font-family: monospace;
            margin-left: auto;
        }}
        .download-link:hover {{
            background-color: #007bff;
            color: white;
        }}
        .download-icon {{
            width: 16px;
            height: 16px;
            margin-right: 4px;
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
        .upload-section {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        .upload-section.collapsed {{
            margin-top: 10px;
            padding-top: 10px;
            margin-bottom: 5px;
        }}
        .upload-section h3 {{
            cursor: pointer;
            user-select: none;
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 0;
        }}
        .upload-section h3:hover {{
            color: #007bff;
        }}
        .upload-toggle-icon {{
            width: 16px;
            height: 16px;
            transition: transform 0.2s;
        }}
        .upload-section.collapsed .upload-toggle-icon {{
            transform: rotate(-90deg);
        }}
        .upload-section-content {{
            display: none;
            margin-top: 10px;
        }}
        .upload-section:not(.collapsed) .upload-section-content {{
            display: block;
        }}
        .upload-form {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .upload-button {{
            display: inline-flex;
            align-items: center;
            text-decoration: none;
            color: #007bff;
            font-size: 0.8em;
            padding: 4px 8px;
            border: 1px solid #007bff;
            border-radius: 4px;
            transition: background-color 0.2s;
            background-color: transparent;
            cursor: pointer;
            font-family: monospace;
        }}
        .upload-button:hover {{
            background-color: #007bff;
            color: white;
        }}
        .upload-icon {{
            width: 16px;
            height: 16px;
            margin-right: 4px;
        }}
        .file-input {{
            padding: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="back-link"><a href="/spaces">← Back to Spaces List</a></div>
    <h1>
        Space: {}
        <a href="/spaces/{}/cert" class="download-link" title="Download root certificate">
            <svg class="download-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Root Certificate
        </a>
    </h1>
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
        <div class="upload-section collapsed">
            <h3 onclick="this.parentElement.classList.toggle('collapsed')">
                <svg class="upload-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
                Upload Certificate Request
            </h3>
            <div class="upload-section-content">
                <form id="upload-form" action="/spaces/{}/req" method="post" enctype="multipart/form-data" class="upload-form">
                    <input type="file" name="file" accept=".req.json" class="file-input" required>
                    <button type="submit" class="upload-button">
                        <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                        Upload Request
                    </button>
                </form>
                <p style="font-size: 0.85em; color: #666; margin-top: 8px; white-space: nowrap;">
                    File must be named: &lt;subname&gt;@{}.req.json
                </p>
            </div>
        </div>
        {}
        <script>
            document.getElementById('upload-form').addEventListener('submit', function(e) {{
                e.preventDefault();
                const form = e.target;
                const formData = new FormData(form);
                
                // Prompt for Basic Auth credentials
                const username = prompt('Enter username:');
                if (!username) return;
                
                const password = prompt('Enter password:');
                if (!password) return;
                
                // Create Basic Auth header
                const auth = btoa(username + ':' + password);
                
                // Submit with fetch to include Authorization header
                fetch(form.action, {{
                    method: 'POST',
                    headers: {{
                        'Authorization': 'Basic ' + auth
                    }},
                    body: formData
                }})
                .then(response => {{
                    if (response.ok) {{
                        return response.json();
                    }} else {{
                        return response.json().then(err => Promise.reject(err));
                    }}
                }})
                .then(data => {{
                    alert('Upload successful: ' + (data.message || 'File uploaded'));
                    window.location.reload();
                }})
                .catch(error => {{
                    alert('Upload failed: ' + (error.error || error.message || 'Unknown error'));
                }});
            }});
        </script>
    </div>
</body>
</html>"#,
            html_escape(&space_name),
            html_escape(&space_name),
            html_escape(&space_name),
            html_escape(&cert.handle),
            html_escape(&cert.script_pubkey),
            html_escape(&cert.anchor),
            certificate_requests,
            issued_certificates,
            html_escape(&space_name),
            html_escape(&space_name),
            if state.config.list_subspaces && !subspaces.is_empty() {
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

/// Check if a subname is in the reserved list
fn is_reserved_subname(subname: &str) -> bool {
    let reserved = vec!["admin", "user"];
    reserved.contains(&subname)
}

/// Calculate the price for a subname based on its length
/// Special case: if handle ends in "xxxxx", return 1000 satoshis
/// First calculate effective length as min(length, 11)
/// Then Price = (13 - effective_length) * 100000 satoshis
/// Minimum length is 3
fn subname_pricer(subname: &str) -> u64 {
    // Special case: handles ending in "xxxxx" return 1000 sats
    if subname.ends_with("xxxxx") {
        return 1000;
    }
    
    let length = subname.len();
    if length < 3 {
        return 0; // Invalid, but return 0 for safety
    }
    let effective_length = length.min(11);
    let price_multiplier = 13u64.saturating_sub(effective_length as u64);
    // For length 3: min(3,11) = 3, then (13-3) * 100000 = 1000000
    // For length 5: min(5,11) = 5, then (13-5) * 100000 = 800000
    // For length 10: min(10,11) = 10, then (13-10) * 100000 = 300000
    // For length 11: min(11,11) = 11, then (13-11) * 100000 = 200000
    // For length 15: min(15,11) = 11, then (13-11) * 100000 = 200000
    price_multiplier * 100000
}

/// Load callbacks from file for a space
fn load_callbacks(data_dir: &str, space_name: &str) -> Vec<CallbackRegistration> {
    let callbacks_file = Path::new(data_dir)
        .join(space_name)
        .join("callbacks.json");
    
    if !callbacks_file.exists() {
        return Vec::new();
    }
    
    match fs::read_to_string(&callbacks_file) {
        Ok(content) => {
            match serde_json::from_str::<Vec<CallbackRegistration>>(&content) {
                Ok(callbacks) => callbacks,
                Err(e) => {
                    warn!("Failed to parse callbacks file {}: {}", callbacks_file.display(), e);
                    Vec::new()
                }
            }
        }
        Err(e) => {
            warn!("Failed to read callbacks file {}: {}", callbacks_file.display(), e);
            Vec::new()
        }
    }
}

/// Save callbacks to file for a space
fn save_callbacks(data_dir: &str, space_name: &str, callbacks: &[CallbackRegistration]) -> Result<()> {
    let space_dir = Path::new(data_dir).join(space_name);
    
    // Ensure space directory exists
    fs::create_dir_all(&space_dir)
        .context("Failed to create space directory")?;
    
    let callbacks_file = space_dir.join("callbacks.json");
    let json_content = serde_json::to_string_pretty(callbacks)
        .context("Failed to serialize callbacks")?;
    
    fs::write(&callbacks_file, json_content)
        .context("Failed to write callbacks file")?;
    
    Ok(())
}

/// Load all callbacks from filesystem
fn load_all_callbacks(data_dir: &str) -> HashMap<String, Vec<CallbackRegistration>> {
    let mut callbacks_map = HashMap::new();
    
    let data_path = Path::new(data_dir);
    if !data_path.exists() {
        return callbacks_map;
    }
    
    match fs::read_dir(data_path) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(space_name) = path.file_name().and_then(|n| n.to_str()) {
                            let callbacks = load_callbacks(data_dir, space_name);
                            if !callbacks.is_empty() {
                                callbacks_map.insert(space_name.to_string(), callbacks);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to read data directory {}: {}", data_dir, e);
        }
    }
    
    callbacks_map
}

/// Check if a callback should be triggered for a subspace
fn should_trigger_callback(callback: &CallbackRegistration, subspace: Option<&str>) -> bool {
    // Empty watched_subnames means watch all subspaces
    if callback.watched_subnames.is_empty() {
        return true;
    }
    
    // If subspace is None, only trigger if watching all (already handled above)
    if let Some(subspace) = subspace {
        callback.watched_subnames.contains(&subspace.to_string())
    } else {
        false
    }
}

/// Execute a single callback HTTP request
async fn execute_callback(callback_url: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to create HTTP client")?;
    
    let response = client
        .post(callback_url)
        .json(payload)
        .send()
        .await
        .context("Failed to send callback request")?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Callback returned status {}: {}", status, body);
    }
    
    Ok(())
}

/// Execute callback with exponential backoff retry
async fn execute_callback_with_retry(
    callback_url: &str,
    payload: &serde_json::Value,
    max_attempts: usize,
) {
    let mut delay = 1u64; // Start with 1 second
    
    for attempt in 1..=max_attempts {
        match execute_callback(callback_url, payload).await {
            Ok(_) => {
                info!("Callback executed successfully: {} (attempt {})", callback_url, attempt);
                return;
            }
            Err(e) => {
                warn!("Callback execution failed (attempt {}/{}): {} - {}", attempt, max_attempts, callback_url, e);
                if attempt < max_attempts {
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    delay *= 2; // Exponential backoff: 1s, 2s, 4s
                } else {
                    error!("Callback execution failed after {} attempts: {}", max_attempts, callback_url);
                }
            }
        }
    }
}

/// Trigger callbacks for a space and optional subspace
async fn trigger_callbacks(
    callbacks: CallbackStore,
    space_name: &str,
    subspace: Option<&str>,
    event_type: &str,
    event_data: serde_json::Value,
) {
    let callbacks_map = callbacks.lock().await;
    
    if let Some(space_callbacks) = callbacks_map.get(space_name) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let payload = serde_json::json!({
            "event_type": event_type,
            "space_name": space_name,
            "subspace": subspace,
            "handle": subspace.map(|s| format!("{}@{}", s, space_name)),
            "timestamp": timestamp,
            "event_data": event_data,
        });
        
        for callback in space_callbacks {
            if should_trigger_callback(callback, subspace) {
                let callback_url = callback.callback_url.clone();
                let payload_clone = payload.clone();
                
                // Execute callback asynchronously without blocking
                tokio::spawn(async move {
                    execute_callback_with_retry(&callback_url, &payload_clone, 3).await;
                });
            }
        }
    }
}

/// Verify Basic Authentication credentials
fn verify_basic_auth(headers: &HeaderMap, expected_user: &str, expected_password: &str) -> bool {
    let auth_header = match headers.get(header::AUTHORIZATION) {
        Some(h) => h,
        None => return false,
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    if !auth_str.starts_with("Basic ") {
        return false;
    }

    let encoded = &auth_str[6..];
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }

    parts[0] == expected_user && parts[1] == expected_password
}

/// Download root certificate file endpoint
/// Anonymous access - no authentication required
async fn download_root_cert(
    PathExtractor(space_name): PathExtractor<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Build the root certificate file path: @space_name.cert.json
    let cert_file_name = format!("@{}.cert.json", space_name);
    let cert_file_path = Path::new(&state.config.data_dir)
        .join(&space_name)
        .join(&cert_file_name);

    // Check if file exists
    if !cert_file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            format!("Certificate file not found: {}", cert_file_name),
        )
            .into_response();
    }

    // Read the certificate file
    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read certificate file: {}", e),
            )
                .into_response();
        }
    };

    // Return the certificate file with appropriate headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", cert_file_name),
        )
        .body(cert_content)
        .unwrap()
        .into_response()
}

/// Download certificate file endpoint
/// Requires Basic Authentication
#[utoipa::path(
    get,
    path = "/spaces/{space_name}/{subspace}/cert",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("subspace" = String, Path, description = "Name of the subspace")
    ),
    responses(
        (status = 200, description = "Certificate file", content_type = "application/json"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Certificate not found")
    ),
    security(
        ("basic" = [])
    )
)]
async fn download_cert(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            "Unauthorized",
        )
            .into_response();
    }

    // Build the certificate file path
    let cert_file_name = format!("{}@{}.cert.json", subspace, space_name);
    let cert_file_path = Path::new(&state.config.data_dir)
        .join(&space_name)
        .join(&cert_file_name);

    // Check if file exists
    if !cert_file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            format!("Certificate file not found: {}", cert_file_name),
        )
            .into_response();
    }

    // Read the certificate file
    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read certificate file: {}", e),
            )
                .into_response();
        }
    };

    // Return the certificate file with appropriate headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", cert_file_name),
        )
        .body(cert_content)
        .unwrap()
        .into_response()
}

/// Get subspace certificate as inline JSON (same file as `/cert`, no Basic Auth, no download attachment)
#[utoipa::path(
    get,
    path = "/spaces/{space_name}/{subspace}/cert.json",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("subspace" = String, Path, description = "Name of the subspace")
    ),
    responses(
        (status = 200, description = "Certificate JSON"),
        (status = 404, description = "Certificate not found", body = ErrorResponse),
        (status = 500, description = "Read error or invalid JSON in certificate file", body = ErrorResponse)
    )
)]
async fn download_cert_json(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let cert_file_name = format!("{}@{}.cert.json", subspace, space_name);
    let cert_file_path = Path::new(&state.config.data_dir)
        .join(&space_name)
        .join(&cert_file_name);

    if !cert_file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Certificate file not found: {}", cert_file_name),
            }),
        )
            .into_response();
    }

    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to read certificate file: {}", e),
                }),
            )
                .into_response();
        }
    };

    match serde_json::from_str::<serde_json::Value>(&cert_content) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(e) => {
            error!("Invalid JSON in cert file {}: {}", cert_file_path.display(), e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Certificate file contains invalid JSON: {}", e),
                }),
            )
                .into_response()
        }
    }
}

/// Issue certificate endpoint - issues certificate and returns it as download
/// Requires Basic Authentication
#[utoipa::path(
    post,
    path = "/spaces/{space_name}/{subspace}/issue",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("subspace" = String, Path, description = "Name of the subspace")
    ),
    responses(
        (status = 200, description = "Certificate issued and returned", content_type = "application/json"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Space not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("basic" = [])
    )
)]
async fn issue_cert(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            "Unauthorized",
        )
            .into_response();
    }

    // Check if space directory exists
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
    if !space_dir.exists() {
        return (
            StatusCode::NOT_FOUND,
            format!("Space '{}' not found", space_name),
        )
            .into_response();
    }

    // Build certificate handle
    let cert_handle = format!("{}@{}", subspace, space_name);
    let cert_file_name = format!("{}@{}.cert.json", subspace, space_name);
    let cert_file_path = space_dir.join(&cert_file_name);

    // Execute "subs cert issue" command
    info!("Issuing certificate: {}", cert_handle);
    let output = match tokio::process::Command::new("subs")
        .arg("cert")
        .arg("issue")
        .arg(&cert_handle)
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute 'subs cert issue {}': {}", cert_handle, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to execute 'subs cert issue' command: {}", e),
            )
                .into_response();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("'subs cert issue {}' command failed: {}", cert_handle, stderr);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to issue certificate: {}", stderr),
        )
            .into_response();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("'subs cert issue {}' command succeeded: {}", cert_handle, stdout);

    // Check if certificate file was created
    if !cert_file_path.exists() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Certificate file was not created: {}", cert_file_name),
        )
            .into_response();
    }

    // Read the certificate file
    let cert_content = match fs::read_to_string(&cert_file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read cert file {}: {}", cert_file_path.display(), e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read certificate file: {}", e),
            )
                .into_response();
        }
    };

    // Parse certificate to get anchor for callback
    let cert_data: serde_json::Value = match serde_json::from_str(&cert_content) {
        Ok(data) => data,
        Err(_) => serde_json::json!({}),
    };

    // Trigger callbacks for certificate issued event
    let callbacks_clone = state.callbacks.clone();
    let space_name_clone = space_name.clone();
    let subspace_clone = subspace.clone();
    let cert_file_name_clone = cert_file_name.clone();
    let anchor = cert_data.get("anchor").and_then(|a| a.as_str()).unwrap_or("").to_string();
    tokio::spawn(async move {
        trigger_callbacks(
            callbacks_clone,
            &space_name_clone,
            Some(&subspace_clone),
            "certificate_issued",
            serde_json::json!({
                "cert_file": cert_file_name_clone,
                "anchor": anchor,
            }),
        )
        .await;
    });

    // Return the certificate file with appropriate headers for download
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", cert_file_name),
        )
        .body(cert_content)
        .unwrap()
        .into_response()
}

/// Upload certificate request file endpoint
/// Requires Basic Authentication
#[utoipa::path(
    post,
    path = "/spaces/{space_name}/{subspace}/req",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("subspace" = String, Path, description = "Name of the subspace")
    ),
    request_body(
        content = String,
        description = "Certificate request JSON file content",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "File uploaded and processed successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("basic" = [])
    )
)]
async fn upload_req_file(
    PathExtractor((space_name, subspace)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Read the request body
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Failed to read request body: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Validate JSON content
    let json_content = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid UTF-8 in request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Request body must be valid UTF-8"
                })),
            )
                .into_response();
        }
    };

    // Validate it's valid JSON
    if serde_json::from_str::<serde_json::Value>(&json_content).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Request body must be valid JSON"
            })),
        )
            .into_response();
    }

    // Build the file path
    let req_file_name = format!("{}@{}.req.json", subspace, space_name);
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
    let req_file_path = space_dir.join(&req_file_name);

    // Ensure the space directory exists
    if let Err(e) = fs::create_dir_all(&space_dir) {
        error!("Failed to create space directory {}: {}", space_dir.display(), e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create space directory: {}", e)
            })),
        )
            .into_response();
    }

    // Write the file
    if let Err(e) = fs::write(&req_file_path, &json_content) {
        error!("Failed to write req file {}: {}", req_file_path.display(), e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to write certificate request file: {}", e)
            })),
        )
            .into_response();
    }

    info!("Uploaded certificate request file: {}", req_file_path.display());

    // Trigger callbacks for request uploaded event
    let callbacks_clone = state.callbacks.clone();
    let space_name_clone = space_name.clone();
    let subspace_clone = subspace.clone();
    let req_file_name_clone = req_file_name.clone();
    tokio::spawn(async move {
        trigger_callbacks(
            callbacks_clone.clone(),
            &space_name_clone,
            Some(&subspace_clone),
            "request_uploaded",
            serde_json::json!({
                "req_file": req_file_name_clone,
            }),
        )
        .await;
    });

    // Execute "subs add ." command in the space directory
    let output = match tokio::process::Command::new("subs")
        .arg("add")
        .arg(".")
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute 'subs add .' command: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to execute 'subs add .' command: {}", e),
                    "file_uploaded": true,
                    "file_path": req_file_path.to_string_lossy().to_string()
                })),
            )
                .into_response();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("'subs add .' command failed: {}", stderr);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("'subs add .' command failed: {}", stderr),
                "file_uploaded": true,
                "file_path": req_file_path.to_string_lossy().to_string()
            })),
        )
            .into_response();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_str = stdout.to_string();
    info!("'subs add .' command succeeded: {}", stdout);

    // Trigger callbacks for request added event
    let callbacks_clone = state.callbacks.clone();
    let space_name_clone = space_name.clone();
    let subspace_clone = subspace.clone();
    let req_file_name_clone = req_file_name.clone();
    let stdout_clone = stdout_str.clone();
    tokio::spawn(async move {
        trigger_callbacks(
            callbacks_clone,
            &space_name_clone,
            Some(&subspace_clone),
            "request_added",
            serde_json::json!({
                "req_file": req_file_name_clone,
                "subs_output": stdout_clone.trim(),
            }),
        )
        .await;
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Certificate request file uploaded and processed successfully",
            "file_path": req_file_path.to_string_lossy().to_string(),
            "subs_output": stdout.trim()
        })),
    )
        .into_response()
}

/// Upload certificate request file endpoint for space
/// Requires Basic Authentication
#[utoipa::path(
    post,
    path = "/spaces/{space_name}/req",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space")
    ),
    request_body(
        content = String,
        description = "Multipart form data with certificate request file",
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 200, description = "File uploaded successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("basic" = [])
    )
)]
async fn upload_space_req_file(
    PathExtractor(space_name): PathExtractor<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
    
    // Ensure the space directory exists
    if let Err(e) = fs::create_dir_all(&space_dir) {
        error!("Failed to create space directory {}: {}", space_dir.display(), e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create space directory: {}", e)
            })),
        )
            .into_response();
    }

    let mut file_saved = false;
    let mut saved_filename = String::new();
    let mut error_message = String::new();

    // Process multipart form data
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let field_name = field.name().unwrap_or("").to_string();
        
        if field_name == "file" || field_name.is_empty() {
            let filename = field.file_name().unwrap_or("").to_string();
            
            // Extract subname from filename: subname@space_name.req.json
            if filename.is_empty() {
                error_message = "No filename provided".to_string();
                continue;
            }

            // Validate filename format: should end with @space_name.req.json
            let expected_suffix = format!("@{}.req.json", space_name);
            if !filename.ends_with(&expected_suffix) {
                error_message = format!(
                    "Invalid filename format. Expected format: <subname>@{}.req.json, got: {}",
                    space_name, filename
                );
                continue;
            }

            // Extract subname from filename
            let subname = filename
                .strip_suffix(&expected_suffix)
                .unwrap_or("")
                .to_string();

            if subname.is_empty() {
                error_message = format!(
                    "Invalid filename: subname cannot be empty. Expected format: <subname>@{}.req.json",
                    space_name
                );
                continue;
            }

            // Read file data
            let data = match field.bytes().await {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to read file data: {}", e);
                    error_message = format!("Failed to read file data: {}", e);
                    continue;
                }
            };

            // Validate JSON content
            let json_content = match String::from_utf8(data.to_vec()) {
                Ok(s) => s,
                Err(e) => {
                    error!("Invalid UTF-8 in file: {}", e);
                    error_message = "File must contain valid UTF-8".to_string();
                    continue;
                }
            };

            // Validate it's valid JSON
            if serde_json::from_str::<serde_json::Value>(&json_content).is_err() {
                error_message = "File must contain valid JSON".to_string();
                continue;
            }

            // Save the file
            let req_file_path = space_dir.join(&filename);
            if let Err(e) = fs::write(&req_file_path, &json_content) {
                error!("Failed to write req file {}: {}", req_file_path.display(), e);
                error_message = format!("Failed to save file: {}", e);
                continue;
            }

            info!("Uploaded certificate request file: {}", req_file_path.display());
            file_saved = true;
            saved_filename = filename.clone();

            // Trigger callbacks for request uploaded event
            let callbacks_clone = state.callbacks.clone();
            let space_name_clone = space_name.clone();
            let subname_clone = subname.clone();
            let filename_clone = filename.clone();
            tokio::spawn(async move {
                trigger_callbacks(
                    callbacks_clone.clone(),
                    &space_name_clone,
                    Some(&subname_clone),
                    "request_uploaded",
                    serde_json::json!({
                        "req_file": filename_clone,
                    }),
                )
                .await;
            });
        }
    }

    if !error_message.is_empty() && !file_saved {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": error_message
            })),
        )
            .into_response();
    }

    if !file_saved {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No file was uploaded"
            })),
        )
            .into_response();
    }

    // Execute "subs add ." command in the space directory
    let output = match tokio::process::Command::new("subs")
        .arg("add")
        .arg(".")
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute 'subs add .' command: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to execute 'subs add .' command: {}", e),
                    "file_uploaded": true,
                    "file_path": saved_filename
                })),
            )
                .into_response();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("'subs add .' command failed: {}", stderr);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("'subs add .' command failed: {}", stderr),
                "file_uploaded": true,
                "file_path": saved_filename
            })),
        )
            .into_response();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_str = stdout.to_string();
    info!("'subs add .' command succeeded: {}", stdout);

    // Extract subname from saved_filename for callback
    let subname = saved_filename
        .strip_suffix(&format!("@{}.req.json", space_name))
        .unwrap_or("")
        .to_string();

    // Trigger callbacks for request added event
    if !subname.is_empty() {
        let callbacks_clone = state.callbacks.clone();
        let space_name_clone = space_name.clone();
        let subname_clone = subname.clone();
        let saved_filename_clone = saved_filename.clone();
        let stdout_clone = stdout_str.clone();
        tokio::spawn(async move {
            trigger_callbacks(
                callbacks_clone,
                &space_name_clone,
                Some(&subname_clone),
                "request_added",
                serde_json::json!({
                    "req_file": saved_filename_clone,
                    "subs_output": stdout_clone.trim(),
                }),
            )
            .await;
        });
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Certificate request file uploaded and processed successfully",
            "file_path": saved_filename,
            "subs_output": stdout.trim()
        })),
    )
        .into_response()
}

/// Anonymous JSON upload: same as POST /spaces/{space_name}/req but with a JSON body and no auth.
#[utoipa::path(
    post,
    path = "/spaces/{space_name}/add",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space")
    ),
    request_body(
        content = CertRequestJsonBody,
        description = "Certificate request (handle + script_pubkey)",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "File saved and subs add completed"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn add_space_req_json(
    PathExtractor(space_name): PathExtractor<String>,
    State(state): State<AppState>,
    Json(body): Json<CertRequestJsonBody>,
) -> impl IntoResponse {
    let parts: Vec<&str> = body.handle.split('@').collect();
    if parts.len() != 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "handle must be exactly one @ separating subname and space (e.g. admin@bitcoin2026)"
            })),
        )
            .into_response();
    }
    let subname = parts[0];
    let space_from_handle = parts[1];
    if subname.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "subname in handle cannot be empty"
            })),
        )
            .into_response();
    }
    if space_from_handle != space_name.as_str() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": format!(
                    "handle space '{}' does not match path space_name '{}'",
                    space_from_handle, space_name
                )
            })),
        )
            .into_response();
    }

    let filename = format!("{}@{}.req.json", subname, space_name);
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);

    if let Err(e) = fs::create_dir_all(&space_dir) {
        error!("Failed to create space directory {}: {}", space_dir.display(), e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create space directory: {}", e)
            })),
        )
            .into_response();
    }

    let json_content = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to serialize request: {}", e)
                })),
            )
                .into_response();
        }
    };

    let req_file_path = space_dir.join(&filename);
    if let Err(e) = fs::write(&req_file_path, &json_content) {
        error!("Failed to write req file {}: {}", req_file_path.display(), e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to save certificate request file: {}", e)
            })),
        )
            .into_response();
    }

    info!("Uploaded certificate request file (anonymous): {}", req_file_path.display());

    let callbacks_clone = state.callbacks.clone();
    let space_name_clone = space_name.clone();
    let subname_owned = subname.to_string();
    let filename_clone = filename.clone();
    tokio::spawn(async move {
        trigger_callbacks(
            callbacks_clone.clone(),
            &space_name_clone,
            Some(&subname_owned),
            "request_uploaded",
            serde_json::json!({
                "req_file": filename_clone,
            }),
        )
        .await;
    });

    let output = match tokio::process::Command::new("subs")
        .arg("add")
        .arg(".")
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute 'subs add .' command: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to execute 'subs add .' command: {}", e),
                    "file_uploaded": true,
                    "file_path": filename
                })),
            )
                .into_response();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("'subs add .' command failed: {}", stderr);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("'subs add .' command failed: {}", stderr),
                "file_uploaded": true,
                "file_path": filename
            })),
        )
            .into_response();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_str = stdout.to_string();
    info!("'subs add .' command succeeded: {}", stdout);

    let callbacks_clone = state.callbacks.clone();
    let space_name_clone = space_name.clone();
    let subname_clone = subname.to_string();
    let filename_clone = filename.clone();
    let stdout_clone = stdout_str.clone();
    tokio::spawn(async move {
        trigger_callbacks(
            callbacks_clone,
            &space_name_clone,
            Some(&subname_clone),
            "request_added",
            serde_json::json!({
                "req_file": filename_clone,
                "subs_output": stdout_clone.trim(),
            }),
        )
        .await;
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Certificate request file uploaded and processed successfully",
            "file_path": filename,
            "subs_output": stdout.trim()
        })),
    )
        .into_response()
}

/// Generate a unique job ID
fn generate_job_id(space_name: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}_{}", space_name, timestamp)
}

/// Background task to execute prove commands
async fn execute_prove_job(
    job_id: String,
    space_name: String,
    space_dir: std::path::PathBuf,
    jobs: JobStore,
    callbacks: CallbackStore,
) {
    // Update job status to Processing
    {
        let mut jobs_map = jobs.lock().await;
        if let Some(job) = jobs_map.get_mut(&job_id) {
            job.status = JobStatus::Processing;
        }
    }

    let mut results = Vec::new();
    let mut error_message = None;

    // Step 1: subs commit
    info!("Job {}: Executing 'subs commit' for space {}", job_id, space_name);
    match tokio::process::Command::new("subs")
        .arg("commit")
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                results.push(serde_json::json!({
                    "command": "subs commit",
                    "status": "success",
                    "output": stdout.trim()
                }));
                info!("Job {}: 'subs commit' succeeded", job_id);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error_message = Some(format!("'subs commit' failed: {}", stderr));
                results.push(serde_json::json!({
                    "command": "subs commit",
                    "status": "failed",
                    "error": stderr.trim()
                }));
                error!("Job {}: 'subs commit' failed: {}", job_id, stderr);
            }
        }
        Err(e) => {
            error_message = Some(format!("Failed to execute 'subs commit': {}", e));
            error!("Job {}: Failed to execute 'subs commit': {}", job_id, e);
        }
    }

    // If commit failed, mark job as failed
    if error_message.is_some() {
        let completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut jobs_map = jobs.lock().await;
        if let Some(job) = jobs_map.get_mut(&job_id) {
            job.status = JobStatus::Failed(error_message.clone().unwrap());
            job.completed_at = Some(completed_at);
            job.error = error_message;
            job.result = Some(serde_json::json!({ "steps": results }));
        }
        return;
    }

    // Step 2: subs prove
    info!("Job {}: Executing 'subs prove' for space {}", job_id, space_name);
    match tokio::process::Command::new("subs")
        .arg("prove")
        .current_dir(&space_dir)
        .output()
        .await
    {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                results.push(serde_json::json!({
                    "command": "subs prove",
                    "status": "success",
                    "output": stdout.trim()
                }));
                info!("Job {}: 'subs prove' succeeded", job_id);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error_message = Some(format!("'subs prove' failed: {}", stderr));
                results.push(serde_json::json!({
                    "command": "subs prove",
                    "status": "failed",
                    "error": stderr.trim()
                }));
                error!("Job {}: 'subs prove' failed: {}", job_id, stderr);
            }
        }
        Err(e) => {
            error_message = Some(format!("Failed to execute 'subs prove': {}", e));
            error!("Job {}: Failed to execute 'subs prove': {}", job_id, e);
        }
    }

    // Step 3: Commitment call to spaced (placeholder for now)
    results.push(serde_json::json!({
        "command": "commitment call to spaced",
        "status": "pending",
        "note": "To be implemented"
    }));

    // Update job status
    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut jobs_map = jobs.lock().await;
    let job_completed = if let Some(job) = jobs_map.get_mut(&job_id) {
        let completed = error_message.is_none();
        if let Some(err_msg) = error_message.clone() {
            job.status = JobStatus::Failed(err_msg.clone());
            job.error = Some(err_msg);
        } else {
            job.status = JobStatus::Completed;
        }
        job.completed_at = Some(completed_at);
        job.result = Some(serde_json::json!({ "steps": results }));
        completed
    } else {
        false
    };

    // Trigger callbacks for prove completed event
    let error_message_clone = error_message.clone();
    if job_completed && error_message_clone.is_none() {
        let callbacks_clone = callbacks.clone();
        let space_name_clone = space_name.clone();
        let job_id_clone = job_id.clone();
        let results_clone = results.clone();
        tokio::spawn(async move {
            trigger_callbacks(
                callbacks_clone,
                &space_name_clone,
                None, // Prove completion is space-level, not subspace-specific
                "prove_completed",
                serde_json::json!({
                    "job_id": job_id_clone,
                    "steps": results_clone,
                }),
            )
            .await;
        });
    }
}

/// Prove space endpoint - starts async job
/// Requires Basic Authentication
#[utoipa::path(
    post,
    path = "/spaces/{space_name}/prove",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space")
    ),
    responses(
        (status = 200, description = "Job created", body = JobResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Space not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("basic" = [])
    )
)]
async fn prove_space(
    PathExtractor(space_name): PathExtractor<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Check if space directory exists
    let space_dir = Path::new(&state.config.data_dir).join(&space_name);
    if !space_dir.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Space '{}' not found", space_name)
            })),
        )
            .into_response();
    }

    // Generate job ID
    let job_id = generate_job_id(&space_name);
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create job
    let job = Job {
        id: job_id.clone(),
        space_name: space_name.clone(),
        status: JobStatus::Pending,
        created_at,
        completed_at: None,
        result: None,
        error: None,
    };

    // Store job
    {
        let mut jobs_map = state.jobs.lock().await;
        jobs_map.insert(job_id.clone(), job);
    }

    info!("Created prove job {} for space {}", job_id, space_name);

    // Spawn background task
    let jobs_clone = state.jobs.clone();
    let callbacks_clone = state.callbacks.clone();
    let job_id_clone = job_id.clone();
    tokio::spawn(async move {
        execute_prove_job(job_id_clone, space_name, space_dir, jobs_clone, callbacks_clone).await;
    });

    // Return job response
    (
        StatusCode::OK,
        Json(JobResponse {
            job_id,
            status: "pending".to_string(),
            created_at,
        }),
    )
        .into_response()
}

/// Get job status endpoint
#[utoipa::path(
    get,
    path = "/jobs/{job_id}",
    tag = "spaces",
    params(
        ("job_id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job status", body = JobStatusResponse),
        (status = 404, description = "Job not found")
    )
)]
async fn get_job_status(
    PathExtractor(job_id): PathExtractor<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let jobs_map = state.jobs.lock().await;
    
    match jobs_map.get(&job_id) {
        Some(job) => {
            let status_str = match &job.status {
                JobStatus::Pending => "pending",
                JobStatus::Processing => "processing",
                JobStatus::Completed => "completed",
                JobStatus::Failed(_) => "failed",
            };

            let error_msg = match &job.status {
                JobStatus::Failed(msg) => Some(msg.clone()),
                _ => job.error.clone(),
            };

            (
                StatusCode::OK,
                Json(JobStatusResponse {
                    job_id: job.id.clone(),
                    status: status_str.to_string(),
                    created_at: job.created_at,
                    completed_at: job.completed_at,
                    result: job.result.clone(),
                    error: error_msg,
                }),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Job '{}' not found", job_id)
            })),
        )
            .into_response(),
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
struct RegisterCallbackRequest {
    /// Callback URL to notify
    callback_url: String,
    /// List of subnames to watch (empty = watch all)
    watched_subnames: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct UpdateWatchesRequest {
    /// Updated list of subnames to watch (empty = watch all)
    watched_subnames: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct CallbackListResponse {
    /// Space name
    space_name: String,
    /// List of callbacks
    callbacks: Vec<CallbackRegistration>,
}

/// Register certificate callback endpoint
/// Requires Basic Authentication
#[utoipa::path(
    post,
    path = "/api/spaces/{space_name}/callbacks/register",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space")
    ),
    request_body(
        content = RegisterCallbackRequest,
        description = "Callback registration request",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "Callback registered successfully", body = CallbackRegistration),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Bad request")
    ),
    security(
        ("basic" = [])
    )
)]
async fn register_cert_callback(
    PathExtractor(space_name): PathExtractor<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<RegisterCallbackRequest>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Validate callback URL
    if request.callback_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "callback_url cannot be empty"
            })),
        )
            .into_response();
    }

    // Generate unique callback ID
    let callback_id = format!(
        "{}_{}",
        space_name,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let callback = CallbackRegistration {
        id: callback_id.clone(),
        callback_url: request.callback_url.clone(),
        watched_subnames: request.watched_subnames.clone(),
        created_at,
    };

    // Add to in-memory store
    {
        let mut callbacks_map = state.callbacks.lock().await;
        let space_callbacks = callbacks_map.entry(space_name.clone()).or_insert_with(Vec::new);
        space_callbacks.push(callback.clone());
    }

    // Save to file
    {
        let callbacks_map = state.callbacks.lock().await;
        if let Some(space_callbacks) = callbacks_map.get(&space_name) {
            if let Err(e) = save_callbacks(&state.config.data_dir, &space_name, space_callbacks) {
                error!("Failed to save callbacks for space {}: {}", space_name, e);
                // Remove from memory if save failed
                let mut callbacks_map = state.callbacks.lock().await;
                if let Some(space_callbacks) = callbacks_map.get_mut(&space_name) {
                    space_callbacks.retain(|c| c.id != callback_id);
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to save callback: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    }

    info!("Registered callback {} for space {}", callback_id, space_name);
    (StatusCode::OK, Json(callback)).into_response()
}

/// Unregister certificate callback endpoint
/// Requires Basic Authentication
#[utoipa::path(
    delete,
    path = "/api/spaces/{space_name}/callbacks/{callback_id}",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("callback_id" = String, Path, description = "Callback ID to unregister")
    ),
    responses(
        (status = 200, description = "Callback unregistered successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Callback not found")
    ),
    security(
        ("basic" = [])
    )
)]
async fn unregister_cert_callback(
    PathExtractor((space_name, callback_id)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Remove from in-memory store
    let removed = {
        let mut callbacks_map = state.callbacks.lock().await;
        if let Some(space_callbacks) = callbacks_map.get_mut(&space_name) {
            let initial_len = space_callbacks.len();
            space_callbacks.retain(|c| c.id != callback_id);
            initial_len != space_callbacks.len()
        } else {
            false
        }
    };

    if !removed {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Callback '{}' not found for space '{}'", callback_id, space_name)
            })),
        )
            .into_response();
    }

    // Save to file
    {
        let callbacks_map = state.callbacks.lock().await;
        if let Some(space_callbacks) = callbacks_map.get(&space_name) {
            if let Err(e) = save_callbacks(&state.config.data_dir, &space_name, space_callbacks) {
                error!("Failed to save callbacks for space {}: {}", space_name, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to save callbacks: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    }

    info!("Unregistered callback {} for space {}", callback_id, space_name);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": format!("Callback '{}' unregistered", callback_id)
        })),
    )
        .into_response()
}

/// Update certificate callback watches endpoint
/// Requires Basic Authentication
#[utoipa::path(
    put,
    path = "/api/spaces/{space_name}/callbacks/{callback_id}/watches",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("callback_id" = String, Path, description = "Callback ID to update")
    ),
    request_body(
        content = UpdateWatchesRequest,
        description = "Updated watch list",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "Watches updated successfully", body = CallbackRegistration),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Callback not found")
    ),
    security(
        ("basic" = [])
    )
)]
async fn update_cert_watches(
    PathExtractor((space_name, callback_id)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<UpdateWatchesRequest>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Update in-memory store
    let updated_callback = {
        let mut callbacks_map = state.callbacks.lock().await;
        if let Some(space_callbacks) = callbacks_map.get_mut(&space_name) {
            if let Some(callback) = space_callbacks.iter_mut().find(|c| c.id == callback_id) {
                callback.watched_subnames = request.watched_subnames.clone();
                Some(callback.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    let callback = match updated_callback {
        Some(cb) => cb,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("Callback '{}' not found for space '{}'", callback_id, space_name)
                })),
            )
                .into_response();
        }
    };

    // Save to file
    {
        let callbacks_map = state.callbacks.lock().await;
        if let Some(space_callbacks) = callbacks_map.get(&space_name) {
            if let Err(e) = save_callbacks(&state.config.data_dir, &space_name, space_callbacks) {
                error!("Failed to save callbacks for space {}: {}", space_name, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to save callbacks: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    }

    info!("Updated watches for callback {} in space {}", callback_id, space_name);
    (StatusCode::OK, Json(callback)).into_response()
}

/// Get certificate callback endpoint
/// Requires Basic Authentication
#[utoipa::path(
    get,
    path = "/api/spaces/{space_name}/callbacks/{callback_id}",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space"),
        ("callback_id" = String, Path, description = "Callback ID")
    ),
    responses(
        (status = 200, description = "Callback details", body = CallbackRegistration),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Callback not found")
    ),
    security(
        ("basic" = [])
    )
)]
async fn get_cert_callback(
    PathExtractor((space_name, callback_id)): PathExtractor<(String, String)>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    let callbacks_map = state.callbacks.lock().await;
    
    if let Some(space_callbacks) = callbacks_map.get(&space_name) {
        if let Some(callback) = space_callbacks.iter().find(|c| c.id == callback_id) {
            return (StatusCode::OK, Json(callback.clone())).into_response();
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": format!("Callback '{}' not found for space '{}'", callback_id, space_name)
        })),
    )
        .into_response()
}

/// List certificate callbacks endpoint
/// Requires Basic Authentication
#[utoipa::path(
    get,
    path = "/api/spaces/{space_name}/callbacks",
    tag = "spaces",
    params(
        ("space_name" = String, Path, description = "Name of the space")
    ),
    responses(
        (status = 200, description = "List of callbacks", body = CallbackListResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("basic" = [])
    )
)]
async fn list_cert_callbacks(
    PathExtractor(space_name): PathExtractor<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Verify Basic Auth
    if !verify_basic_auth(&headers, &state.config.rpc_user, &state.config.rpc_password) {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"subsd\""),
            )],
            Json(serde_json::json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    let callbacks_map = state.callbacks.lock().await;
    let callbacks = callbacks_map
        .get(&space_name)
        .cloned()
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(CallbackListResponse {
            space_name: space_name.clone(),
            callbacks,
        }),
    )
        .into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Load configuration from environment
    let config = Config::from_env()?;

    info!("═══════════════════════════════════════════════════════════════");
    info!("🚀 Starting subsd RPC server");
    info!("═══════════════════════════════════════════════════════════════");
    info!("");
    info!("📋 Environment Configuration (loaded from environment variables):");
    info!("");
    info!("   Server Configuration:");
    info!("     • RPC Bind Address: {}:{}", config.rpc_bind, config.rpc_port);
    info!("     • RPC URL: {}", config.rpc_url);
    info!("     • RPC User: {}", config.rpc_user);
    info!("     • RPC Password: {} (hidden)", "*".repeat(config.rpc_password.len().min(8)));
    info!("");
    info!("   Data Configuration:");
    info!("     • Data Directory: {}", config.data_dir);
    info!("     • List Subspaces: {}", config.list_subspaces);
    info!("");
    info!("   SPACED RPC Configuration:");
    info!("     • SPACED RPC URL: {}", config.spaced_rpc_url);
    info!("     • SPACED RPC User: {}", config.spaced_rpc_user);
    info!("     • SPACED RPC Password: {} (hidden)", "*".repeat(config.spaced_rpc_password.len().min(8)));
    info!("");
    info!("💡 To load environment variables, use: source ./setup-subsd-env.sh");
    info!("");
    info!("🌐 Server is running at: {}", config.rpc_url);
    info!("   • Health Check: {}/health", config.rpc_url);
    info!("   • API Discovery: {}/api", config.rpc_url);
    info!("   • Swagger UI: {}/docs", config.rpc_url);
    info!("");
    info!("═══════════════════════════════════════════════════════════════");

    // Create job store
    let jobs: JobStore = Arc::new(Mutex::new(HashMap::new()));

    // Initialize app configurations
    let mut app_configs_map = HashMap::new();
    app_configs_map.insert("spaces-wallet".to_string(), vec!["usdt".to_string(), "xaut".to_string(), "btc".to_string()]);
    app_configs_map.insert("other-wallet".to_string(), vec!["usdc".to_string(), "eth".to_string(), "btc".to_string()]);
    let app_configs: AppConfigs = Arc::new(Mutex::new(app_configs_map));

    // Initialize callback store and load from filesystem
    let callbacks: CallbackStore = Arc::new(Mutex::new(load_all_callbacks(&config.data_dir)));
    info!("Loaded {} space(s) with callbacks", callbacks.lock().await.len());

    // Create app state
    let app_state = AppState {
        config: config.clone(),
        jobs: jobs.clone(),
        app_configs: app_configs.clone(),
        callbacks: callbacks.clone(),
    };

    // Build the application router
    let app = Router::new()
        .merge(
            SwaggerUi::new("/docs")
                .url("/openapi.json", ApiDoc::openapi())
        )
        .route("/", get(list_spaces))
        .route("/spaces", get(list_spaces))
        .route("/spaces/", get(get_app_config))
        .route("/health", get(healthcheck))
        .route("/api", get(discover_endpoints))
        .route("/spaces/:space_name", get(get_space_info))
        .route("/spaces/:space_name/cert", get(download_root_cert))
        .route("/spaces/:space_name/req", post(upload_space_req_file))
        .route("/spaces/:space_name/add", post(add_space_req_json))
        .route("/spaces/:space_name/prove", post(prove_space))
        .route("/spaces/:space_name/:subspace", get(get_subspace_cert))
        .route("/spaces/:space_name/:subspace/cert.json", get(download_cert_json))
        .route("/spaces/:space_name/:subspace/cert", get(download_cert))
        .route("/spaces/:space_name/:subspace/req", post(upload_req_file))
        .route("/spaces/:space_name/:subspace/issue", post(issue_cert))
        .route("/api/spaces/:space_name/callbacks/register", post(register_cert_callback))
        .route("/api/spaces/:space_name/callbacks", get(list_cert_callbacks))
        .route("/api/spaces/:space_name/callbacks/:callback_id", get(get_cert_callback))
        .route("/api/spaces/:space_name/callbacks/:callback_id", delete(unregister_cert_callback))
        .route("/api/spaces/:space_name/callbacks/:callback_id/watches", put(update_cert_watches))
        .route("/jobs/:job_id", get(get_job_status))
        .with_state(app_state);

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

