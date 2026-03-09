//! HTTP error mapping for the Rust backend slice.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use coder_core::{ApiResponse, StorageError};
use thiserror::Error;
use tracing::{error, warn};

/// Top-level HTTP handler errors.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Backing store failures.
    #[error("{0}")]
    Storage(#[from] StorageError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Storage(StorageError::Unavailable { .. }) => {
                warn!(error = %self, "request failed because the backing store is unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The backing store is unavailable.",
                )
            }
            Self::Storage(StorageError::InvalidData { .. }) => {
                error!(error = %self, "request failed because stored data is invalid");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Stored deployment data is invalid.",
                )
            }
        };

        (status, Json(ApiResponse::error(message, self.to_string()))).into_response()
    }
}
