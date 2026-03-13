//! MCP (Model Context Protocol) HTTP transport for the Coder backend.
//!
//! Implements JSON-RPC 2.0 based MCP protocol handling including tool
//! registration, request routing, and response generation.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod protocol;
mod tools;

pub use protocol::{
    JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse, McpCapabilities,
    McpInitializeParams, McpInitializeResult, McpServerInfo, McpTool, McpToolCallParams,
    McpToolCallResult, McpToolCapabilities, McpToolContent, McpToolListResult,
};
pub use tools::{McpToolRegistry, ToolContext};
