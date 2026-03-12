//! JSON-RPC 2.0 and MCP protocol types.
//!
//! Defines the wire-format types used by the MCP HTTP transport endpoint.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 primitives
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request object.
#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,
    /// Method name to invoke.
    pub method: String,
    /// Optional structured parameters.
    #[serde(default)]
    pub params: Option<Value>,
    /// Request identifier — may be a number or string.
    ///
    /// Per JSON-RPC 2.0, notifications MUST NOT include `id`.  We default to
    /// `Value::Null` so that notification payloads deserialize correctly.
    #[serde(default)]
    pub id: Value,
}

/// A JSON-RPC 2.0 success response.
#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcResponse {
    /// Protocol version — always `"2.0"`.
    pub jsonrpc: &'static str,
    /// The result payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error payload on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Echoed request identifier.
    pub id: Value,
}

impl JsonRpcResponse {
    /// Builds a successful JSON-RPC response.
    #[must_use]
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Builds an error JSON-RPC response.
    #[must_use]
    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// Standard JSON-RPC 2.0 error codes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JsonRpcErrorCode {
    /// Invalid JSON was received.
    ParseError = -32700,
    /// The JSON sent is not a valid Request object.
    InvalidRequest = -32600,
    /// The method does not exist or is not available.
    MethodNotFound = -32601,
    /// Invalid method parameters.
    InvalidParams = -32602,
    /// Internal JSON-RPC error.
    InternalError = -32603,
}

/// A JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i32,
    /// Short human-readable description.
    pub message: String,
    /// Optional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Creates an error from a standard error code.
    pub fn from_code(code: JsonRpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            data: None,
        }
    }
}

// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

/// Parameters for the `initialize` MCP method.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeParams {
    /// Protocol version requested by the client.
    pub protocol_version: String,
    /// Client information.
    #[serde(default)]
    pub client_info: Option<McpClientInfo>,
    /// Capabilities the client supports.
    #[serde(default)]
    pub capabilities: Option<Value>,
}

/// Client information sent during initialization.
#[derive(Clone, Debug, Deserialize)]
pub struct McpClientInfo {
    /// Client name.
    pub name: String,
    /// Client version.
    #[serde(default)]
    pub version: Option<String>,
}

/// Result of the `initialize` MCP method.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeResult {
    /// Protocol version supported by the server.
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: McpCapabilities,
    /// Server information.
    pub server_info: McpServerInfo,
}

/// Capabilities advertised by the MCP server.
#[derive(Clone, Debug, Default, Serialize)]
pub struct McpCapabilities {
    /// Tool capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<McpToolCapabilities>,
}

/// Tool-specific capability flags.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCapabilities {
    /// Whether the tool list may change dynamically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Server identification.
#[derive(Clone, Debug, Serialize)]
pub struct McpServerInfo {
    /// Human-readable server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// An MCP tool definition.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    /// Unique tool name.
    pub name: String,
    /// Human-readable tool description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: McpToolInputSchema,
}

/// JSON Schema describing tool input parameters.
#[derive(Clone, Debug, Serialize)]
pub struct McpToolInputSchema {
    /// Schema type — always `"object"`.
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Property definitions.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, Value>,
    /// Required property names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

/// Parameters for `tools/call`.
#[derive(Clone, Debug, Deserialize)]
pub struct McpToolCallParams {
    /// Name of the tool to invoke.
    pub name: String,
    /// Arguments to pass to the tool.
    #[serde(default)]
    pub arguments: Option<Value>,
}

/// Result of a `tools/call` invocation.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallResult {
    /// Content items returned by the tool.
    pub content: Vec<McpToolContent>,
    /// Whether the tool call resulted in an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// A content item in a tool call result.
#[derive(Clone, Debug, Serialize)]
pub struct McpToolContent {
    /// Content type — typically `"text"`.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Textual content.
    pub text: String,
}

impl McpToolContent {
    /// Creates a text content item.
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            content_type: "text".to_owned(),
            text: value.into(),
        }
    }
}

/// Result of `tools/list`.
#[derive(Clone, Debug, Serialize)]
pub struct McpToolListResult {
    /// Available tools.
    pub tools: Vec<McpTool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn json_rpc_request_deserializes() -> Result<(), Box<dyn Error>> {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
            "id": 1
        }"#;
        let req: JsonRpcRequest = serde_json::from_str(json)?;
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, serde_json::json!(1));
        Ok(())
    }

    #[test]
    fn json_rpc_response_success_serializes() -> Result<(), Box<dyn Error>> {
        let resp = JsonRpcResponse::success(serde_json::json!(1), serde_json::json!({"ok": true}));
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
        Ok(())
    }

    #[test]
    fn json_rpc_response_error_serializes() -> Result<(), Box<dyn Error>> {
        let resp = JsonRpcResponse::error(
            serde_json::json!(1),
            JsonRpcError::from_code(JsonRpcErrorCode::MethodNotFound, "not found"),
        );
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
        Ok(())
    }

    #[test]
    fn mcp_initialize_params_deserializes() -> Result<(), Box<dyn Error>> {
        let json = r#"{
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "1.0"},
            "capabilities": {}
        }"#;
        let params: McpInitializeParams = serde_json::from_str(json)?;
        assert_eq!(params.protocol_version, "2024-11-05");
        assert!(params.client_info.is_some());
        if let Some(ref info) = params.client_info {
            assert_eq!(info.name, "test-client");
        }
        Ok(())
    }

    #[test]
    fn mcp_tool_call_params_deserializes() -> Result<(), Box<dyn Error>> {
        let json = r#"{"name": "coder_get_deployment_info", "arguments": {}}"#;
        let params: McpToolCallParams = serde_json::from_str(json)?;
        assert_eq!(params.name, "coder_get_deployment_info");
        Ok(())
    }

    #[test]
    fn mcp_tool_content_text_creates_text_type() {
        let content = McpToolContent::text("hello");
        assert_eq!(content.content_type, "text");
        assert_eq!(content.text, "hello");
    }

    #[test]
    fn mcp_tool_serializes_with_schema() -> Result<(), Box<dyn Error>> {
        let tool = McpTool {
            name: "test_tool".to_owned(),
            description: Some("A test tool".to_owned()),
            input_schema: McpToolInputSchema {
                schema_type: "object".to_owned(),
                properties: HashMap::new(),
                required: Vec::new(),
            },
        };
        let json = serde_json::to_value(&tool)?;
        assert_eq!(json["name"], "test_tool");
        assert_eq!(json["inputSchema"]["type"], "object");
        Ok(())
    }

    #[test]
    fn json_rpc_notification_without_id_deserializes() -> Result<(), Box<dyn Error>> {
        // JSON-RPC 2.0 notifications MUST NOT include an `id` field.
        let json = r#"{"jsonrpc":"2.0","method":"initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json)?;
        assert_eq!(req.method, "initialized");
        assert_eq!(req.id, serde_json::Value::Null);
        Ok(())
    }

    #[test]
    fn error_code_values() {
        assert_eq!(JsonRpcErrorCode::ParseError as i32, -32700);
        assert_eq!(JsonRpcErrorCode::InvalidRequest as i32, -32600);
        assert_eq!(JsonRpcErrorCode::MethodNotFound as i32, -32601);
        assert_eq!(JsonRpcErrorCode::InvalidParams as i32, -32602);
        assert_eq!(JsonRpcErrorCode::InternalError as i32, -32603);
    }
}
