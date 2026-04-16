//! Handler traits for the agent RPC service.
//!
//! The server reads `INVOKE` + `MESSAGE` pairs off the wire and dispatches
//! them to an implementation of [`AgentRpcHandler`]. The trait is
//! intentionally narrow in Phase 1: each method takes an already-decoded
//! request protobuf and returns an already-encoded response protobuf.
//!
//! Implementations should keep business logic out of the framing layer and
//! return a typed [`RpcError`] for anything that cannot be served.

use async_trait::async_trait;
use thiserror::Error;

use crate::proto::agent_v2 as agent;

/// Errors returned by handler methods. These are mapped onto DRPC error
/// frames by the stream server.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The handler does not know how to serve this method.
    #[error("unimplemented: {0}")]
    Unimplemented(String),
    /// The request was rejected because it was malformed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The handler encountered an internal error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Trait describing the subset of the agent DRPC service that the Rust
/// server currently implements. Methods default to `Unimplemented`, matching
/// the Go server's behaviour when an RPC path is unregistered.
#[async_trait]
pub trait AgentRpcHandler: Send + Sync {
    async fn get_manifest(
        &self,
        _req: agent::GetManifestRequest,
    ) -> Result<agent::Manifest, RpcError> {
        Err(RpcError::Unimplemented("GetManifest".into()))
    }

    async fn get_announcement_banners(
        &self,
        _req: agent::GetAnnouncementBannersRequest,
    ) -> Result<agent::GetAnnouncementBannersResponse, RpcError> {
        Err(RpcError::Unimplemented("GetAnnouncementBanners".into()))
    }

    async fn update_startup(
        &self,
        _req: agent::UpdateStartupRequest,
    ) -> Result<agent::Startup, RpcError> {
        Err(RpcError::Unimplemented("UpdateStartup".into()))
    }

    async fn batch_update_app_health(
        &self,
        _req: agent::BatchUpdateAppHealthRequest,
    ) -> Result<agent::BatchUpdateAppHealthResponse, RpcError> {
        Err(RpcError::Unimplemented("BatchUpdateAppHealths".into()))
    }
}

/// A do-nothing implementation used in tests and as a default integration
/// point while Phase-2 handlers are in flight. Each method returns an empty
/// but well-formed response so that the transport can be exercised without
/// pulling in database or pubsub dependencies.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubHandler;

#[async_trait]
impl AgentRpcHandler for StubHandler {
    async fn get_manifest(
        &self,
        _req: agent::GetManifestRequest,
    ) -> Result<agent::Manifest, RpcError> {
        Ok(agent::Manifest::default())
    }

    async fn get_announcement_banners(
        &self,
        _req: agent::GetAnnouncementBannersRequest,
    ) -> Result<agent::GetAnnouncementBannersResponse, RpcError> {
        Ok(agent::GetAnnouncementBannersResponse::default())
    }

    async fn update_startup(
        &self,
        req: agent::UpdateStartupRequest,
    ) -> Result<agent::Startup, RpcError> {
        Ok(req.startup.unwrap_or_default())
    }

    async fn batch_update_app_health(
        &self,
        _req: agent::BatchUpdateAppHealthRequest,
    ) -> Result<agent::BatchUpdateAppHealthResponse, RpcError> {
        Ok(agent::BatchUpdateAppHealthResponse::default())
    }
}
