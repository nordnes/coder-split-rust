//! MCP (Model Context Protocol) HTTP transport handler.
//!
//! Implements `POST /mcp/http` which accepts JSON-RPC 2.0 messages
//! and dispatches them through the MCP tool registry.

use super::*;

use coder_mcp::{
    JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse, McpCapabilities,
    McpInitializeResult, McpServerInfo, McpToolCallParams, McpToolCapabilities, McpToolListResult,
    ToolContext,
};

/// POST /mcp/http — MCP HTTP transport endpoint.
///
/// Accepts a JSON-RPC 2.0 request, dispatches it to the appropriate MCP
/// method handler, and returns a JSON-RPC 2.0 response.
pub(crate) async fn mcp_http_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Parse the JSON-RPC request from the raw body.
    let request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            let error_response = JsonRpcResponse::error(
                serde_json::Value::Null,
                JsonRpcError::from_code(
                    JsonRpcErrorCode::ParseError,
                    format!("Invalid JSON-RPC request: {e}"),
                ),
            );
            return Ok((StatusCode::OK, Json(error_response)).into_response());
        }
    };

    let tool_context = ToolContext {
        user_id: context.actor.user_id,
        username: context.actor.username.clone(),
        telemetry_enabled: false, // TODO: wire telemetry_enabled into ServerConfig
        access_url: state.config.access_url.to_string(),
        deployment_id: state.deployment_id.to_string(),
        server_version: state.build_metadata.version.clone(),
    };

    let response = dispatch_mcp_request(&state, &request, &tool_context);
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Routes a parsed JSON-RPC request to the appropriate MCP method handler.
fn dispatch_mcp_request(
    state: &AppState,
    request: &JsonRpcRequest,
    tool_context: &ToolContext,
) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => handle_initialize(state, request),
        "initialized" => {
            // Client acknowledgement — no response needed for notifications,
            // but since we're in request-response HTTP mode, return success.
            JsonRpcResponse::success(request.id.clone(), serde_json::json!({}))
        }
        "tools/list" => handle_tools_list(request),
        "tools/call" => handle_tools_call(request, tool_context),
        "ping" => JsonRpcResponse::success(request.id.clone(), serde_json::json!({})),
        _ => JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError::from_code(
                JsonRpcErrorCode::MethodNotFound,
                format!("Unknown method: {}", request.method),
            ),
        ),
    }
}

/// Handles the MCP `initialize` handshake.
fn handle_initialize(state: &AppState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let result = McpInitializeResult {
        protocol_version: "2024-11-05".to_owned(),
        capabilities: McpCapabilities {
            tools: Some(McpToolCapabilities {
                list_changed: Some(false),
            }),
        },
        server_info: McpServerInfo {
            name: "coder".to_owned(),
            version: state.build_metadata.version.clone(),
        },
    };

    match serde_json::to_value(&result) {
        Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError::from_code(
                JsonRpcErrorCode::InternalError,
                format!("Failed to serialize initialize result: {e}"),
            ),
        ),
    }
}

/// Handles `tools/list` — returns all registered MCP tools.
fn handle_tools_list(request: &JsonRpcRequest) -> JsonRpcResponse {
    let registry = coder_mcp::McpToolRegistry::new();
    let result = McpToolListResult {
        tools: registry.list_tools().to_vec(),
    };

    match serde_json::to_value(&result) {
        Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JsonRpcError::from_code(
                JsonRpcErrorCode::InternalError,
                format!("Failed to serialize tool list: {e}"),
            ),
        ),
    }
}

/// Handles `tools/call` — invokes a named tool with arguments.
fn handle_tools_call(request: &JsonRpcRequest, tool_context: &ToolContext) -> JsonRpcResponse {
    // Parse the tool call parameters from the request params.
    let params: McpToolCallParams = match &request.params {
        Some(params_value) => match serde_json::from_value(params_value.clone()) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::from_code(
                        JsonRpcErrorCode::InvalidParams,
                        format!("Invalid tool call parameters: {e}"),
                    ),
                );
            }
        },
        None => {
            return JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError::from_code(
                    JsonRpcErrorCode::InvalidParams,
                    "Missing tool call parameters".to_owned(),
                ),
            );
        }
    };

    let registry = coder_mcp::McpToolRegistry::new();

    match registry.call_tool(&params.name, params.arguments.as_ref(), tool_context) {
        Ok(result) => match serde_json::to_value(&result) {
            Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
            Err(e) => JsonRpcResponse::error(
                request.id.clone(),
                JsonRpcError::from_code(
                    JsonRpcErrorCode::InternalError,
                    format!("Failed to serialize tool result: {e}"),
                ),
            ),
        },
        Err(rpc_error) => JsonRpcResponse::error(request.id.clone(), rpc_error),
    }
}
