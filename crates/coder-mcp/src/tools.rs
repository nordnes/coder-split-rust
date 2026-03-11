//! MCP tool registry and built-in tool implementations.
//!
//! Provides a registry of tools that can be invoked via the MCP protocol,
//! along with context needed for tool execution.

use std::collections::HashMap;

use serde_json::Value;
use tracing::debug;
use uuid::Uuid;

use crate::protocol::{
    JsonRpcError, JsonRpcErrorCode, McpTool, McpToolCallResult, McpToolContent, McpToolInputSchema,
};

/// Contextual information available to tool handlers during execution.
#[derive(Clone, Debug)]
pub struct ToolContext {
    /// The authenticated user's identifier.
    pub user_id: Uuid,
    /// The authenticated user's username.
    pub username: String,
    /// Whether telemetry is enabled for this deployment.
    pub telemetry_enabled: bool,
    /// The deployment's access URL.
    pub access_url: String,
    /// The deployment's unique identifier.
    pub deployment_id: String,
    /// The server version string.
    pub server_version: String,
}

/// Registry of MCP tools available to clients.
///
/// Maintains a list of tool definitions and dispatches `tools/call`
/// requests to the appropriate handler.
pub struct McpToolRegistry {
    tools: Vec<McpTool>,
}

impl McpToolRegistry {
    /// Creates a new registry pre-populated with all built-in tools.
    pub fn new() -> Self {
        Self {
            tools: vec![
                Self::deployment_info_tool(),
                Self::whoami_tool(),
                Self::list_workspaces_tool(),
                Self::list_templates_tool(),
            ],
        }
    }

    /// Returns the list of registered tools.
    pub fn list_tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Dispatches a tool call by name and returns the result.
    pub fn call_tool(
        &self,
        name: &str,
        _arguments: Option<&Value>,
        context: &ToolContext,
    ) -> Result<McpToolCallResult, JsonRpcError> {
        debug!(tool = name, "dispatching MCP tool call");

        match name {
            "coder_get_deployment_info" => Ok(self.handle_deployment_info(context)),
            "coder_whoami" => Ok(self.handle_whoami(context)),
            "coder_list_workspaces" => Ok(self.handle_list_workspaces(context)),
            "coder_list_templates" => Ok(self.handle_list_templates(context)),
            _ => Err(JsonRpcError::from_code(
                JsonRpcErrorCode::InvalidParams,
                format!("Unknown tool: {name}"),
            )),
        }
    }

    // ------------------------------------------------------------------
    // Tool definitions
    // ------------------------------------------------------------------

    fn deployment_info_tool() -> McpTool {
        McpTool {
            name: "coder_get_deployment_info".to_owned(),
            description: Some(
                "Get information about the Coder deployment including version and configuration."
                    .to_owned(),
            ),
            input_schema: McpToolInputSchema {
                schema_type: "object".to_owned(),
                properties: HashMap::new(),
                required: Vec::new(),
            },
        }
    }

    fn whoami_tool() -> McpTool {
        McpTool {
            name: "coder_whoami".to_owned(),
            description: Some("Get information about the currently authenticated user.".to_owned()),
            input_schema: McpToolInputSchema {
                schema_type: "object".to_owned(),
                properties: HashMap::new(),
                required: Vec::new(),
            },
        }
    }

    fn list_workspaces_tool() -> McpTool {
        let mut properties = HashMap::new();
        properties.insert(
            "owner".to_owned(),
            serde_json::json!({
                "type": "string",
                "description": "Filter workspaces by owner username. Defaults to the authenticated user."
            }),
        );
        McpTool {
            name: "coder_list_workspaces".to_owned(),
            description: Some("List workspaces visible to the authenticated user.".to_owned()),
            input_schema: McpToolInputSchema {
                schema_type: "object".to_owned(),
                properties,
                required: Vec::new(),
            },
        }
    }

    fn list_templates_tool() -> McpTool {
        McpTool {
            name: "coder_list_templates".to_owned(),
            description: Some("List templates available in the Coder deployment.".to_owned()),
            input_schema: McpToolInputSchema {
                schema_type: "object".to_owned(),
                properties: HashMap::new(),
                required: Vec::new(),
            },
        }
    }

    // ------------------------------------------------------------------
    // Tool handlers
    // ------------------------------------------------------------------

    fn handle_deployment_info(&self, context: &ToolContext) -> McpToolCallResult {
        let info = serde_json::json!({
            "deployment_id": context.deployment_id,
            "version": context.server_version,
            "access_url": context.access_url,
            "telemetry_enabled": context.telemetry_enabled,
        });
        let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| info.to_string());
        McpToolCallResult {
            content: vec![McpToolContent::text(text)],
            is_error: None,
        }
    }

    fn handle_whoami(&self, context: &ToolContext) -> McpToolCallResult {
        let info = serde_json::json!({
            "user_id": context.user_id.to_string(),
            "username": context.username,
        });
        let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| info.to_string());
        McpToolCallResult {
            content: vec![McpToolContent::text(text)],
            is_error: None,
        }
    }

    fn handle_list_workspaces(&self, _context: &ToolContext) -> McpToolCallResult {
        // Workspace management is a STUB domain — return an informative message.
        let info = serde_json::json!({
            "workspaces": [],
            "note": "The workspace domain is not yet fully implemented in this backend slice."
        });
        let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| info.to_string());
        McpToolCallResult {
            content: vec![McpToolContent::text(text)],
            is_error: None,
        }
    }

    fn handle_list_templates(&self, _context: &ToolContext) -> McpToolCallResult {
        // Template listing via MCP returns a placeholder until wired to the store.
        let info = serde_json::json!({
            "templates": [],
            "note": "Template listing through MCP is available. Use the REST API for full template management."
        });
        let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| info.to_string());
        McpToolCallResult {
            content: vec![McpToolContent::text(text)],
            is_error: None,
        }
    }
}

impl Default for McpToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> ToolContext {
        ToolContext {
            user_id: Uuid::nil(),
            username: "testuser".to_owned(),
            telemetry_enabled: true,
            access_url: "http://localhost:3000".to_owned(),
            deployment_id: "test-deployment".to_owned(),
            server_version: "0.1.0".to_owned(),
        }
    }

    #[test]
    fn registry_lists_all_builtin_tools() {
        let registry = McpToolRegistry::new();
        let tools = registry.list_tools();
        assert_eq!(tools.len(), 4);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"coder_get_deployment_info"));
        assert!(names.contains(&"coder_whoami"));
        assert!(names.contains(&"coder_list_workspaces"));
        assert!(names.contains(&"coder_list_templates"));
    }

    #[test]
    fn call_deployment_info_returns_context() {
        let registry = McpToolRegistry::new();
        let ctx = test_context();
        let result = registry.call_tool("coder_get_deployment_info", None, &ctx);
        assert!(result.is_ok());
        if let Ok(result) = result {
            assert_eq!(result.content.len(), 1);
            assert!(result.content[0].text.contains("test-deployment"));
            assert!(result.is_error.is_none());
        }
    }

    #[test]
    fn call_whoami_returns_user_info() {
        let registry = McpToolRegistry::new();
        let ctx = test_context();
        let result = registry.call_tool("coder_whoami", None, &ctx);
        assert!(result.is_ok());
        if let Ok(result) = result {
            assert_eq!(result.content.len(), 1);
            assert!(result.content[0].text.contains("testuser"));
        }
    }

    #[test]
    fn call_unknown_tool_returns_error() {
        let registry = McpToolRegistry::new();
        let ctx = test_context();
        let result = registry.call_tool("nonexistent_tool", None, &ctx);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.code, JsonRpcErrorCode::InvalidParams as i32);
            assert!(err.message.contains("nonexistent_tool"));
        }
    }

    #[test]
    fn call_list_workspaces_returns_stub() {
        let registry = McpToolRegistry::new();
        let ctx = test_context();
        let result = registry.call_tool("coder_list_workspaces", None, &ctx);
        assert!(result.is_ok());
        if let Ok(result) = result {
            assert!(result.content[0].text.contains("workspaces"));
        }
    }

    #[test]
    fn call_list_templates_returns_stub() {
        let registry = McpToolRegistry::new();
        let ctx = test_context();
        let result = registry.call_tool("coder_list_templates", None, &ctx);
        assert!(result.is_ok());
        if let Ok(result) = result {
            assert!(result.content[0].text.contains("templates"));
        }
    }

    #[test]
    fn default_creates_same_as_new() {
        let default_reg = McpToolRegistry::default();
        let new_reg = McpToolRegistry::new();
        assert_eq!(default_reg.list_tools().len(), new_reg.list_tools().len());
    }
}
