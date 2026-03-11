//! HTTP error mapping for the Rust backend slice.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use coder_auth::{AuthServiceError, ExternalAuthServiceError, OAuth2ProviderError};
use coder_core::{ApiResponse, StorageError, ValidationError};
use coder_identity::IdentityServiceError;
use thiserror::Error;
use tracing::{error, warn};

/// Top-level HTTP handler errors.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Backing store failures.
    #[error("{0}")]
    Storage(#[from] StorageError),

    /// The caller is not authenticated.
    #[error("{message}")]
    Unauthorized { message: String },

    /// The caller is authenticated but not allowed to perform the action.
    #[error("{message}")]
    Forbidden { message: String },

    /// The requested resource does not exist.
    #[error("{message}")]
    NotFound { message: String },

    /// The request is invalid.
    #[error("{message}")]
    BadRequest {
        message: String,
        detail: Option<String>,
        validations: Vec<ValidationError>,
    },

    /// The request conflicted with existing state.
    #[error("{message}")]
    Conflict {
        message: String,
        detail: Option<String>,
        validations: Vec<ValidationError>,
    },

    /// An internal error occurred.
    #[error("{message}")]
    InternalError { message: String, detail: String },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Storage(StorageError::Unavailable { .. }) => {
                warn!(error = %self, "request failed because the backing store is unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiResponse::error(
                        "The backing store is unavailable.",
                        self.to_string(),
                    )),
                )
                    .into_response()
            }
            Self::Storage(StorageError::NotFound { message }) => (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("Resource not found.", message)),
            )
                .into_response(),
            Self::Storage(StorageError::InvalidData { .. }) => {
                error!(error = %self, "request failed because stored data is invalid");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "Stored deployment data is invalid.",
                        self.to_string(),
                    )),
                )
                    .into_response()
            }
            Self::Unauthorized { message } => {
                (StatusCode::UNAUTHORIZED, Json(ApiResponse::ok(message))).into_response()
            }
            Self::Forbidden { message } => {
                (StatusCode::FORBIDDEN, Json(ApiResponse::ok(message))).into_response()
            }
            Self::NotFound { message } => {
                (StatusCode::NOT_FOUND, Json(ApiResponse::ok(message))).into_response()
            }
            Self::BadRequest {
                message,
                detail,
                validations,
            } => (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    message,
                    detail,
                    validations,
                }),
            )
                .into_response(),
            Self::Conflict {
                message,
                detail,
                validations,
            } => (
                StatusCode::CONFLICT,
                Json(ApiResponse {
                    message,
                    detail,
                    validations,
                }),
            )
                .into_response(),
            Self::InternalError { message, detail } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(message, detail)),
            )
                .into_response(),
        }
    }
}

// ---------------------------------------------------------------------------
// From conversions for service error types
// ---------------------------------------------------------------------------

impl From<AuthServiceError> for AppError {
    fn from(error: AuthServiceError) -> Self {
        match error {
            AuthServiceError::Storage(e) => Self::Storage(e),
            AuthServiceError::Unauthorized { message } => Self::Unauthorized { message },
            AuthServiceError::Forbidden { message } => Self::Forbidden { message },
            AuthServiceError::NotFound { message } => Self::NotFound { message },
            AuthServiceError::BadRequest { message, detail } => Self::BadRequest {
                message,
                detail,
                validations: Vec::new(),
            },
            AuthServiceError::Validation {
                message,
                validations,
            } => Self::BadRequest {
                message,
                detail: None,
                validations,
            },
            AuthServiceError::Conflict {
                message,
                detail,
                validations,
            } => Self::Conflict {
                message,
                detail,
                validations,
            },
        }
    }
}

impl From<IdentityServiceError> for AppError {
    fn from(error: IdentityServiceError) -> Self {
        match error {
            IdentityServiceError::Storage(e) => Self::Storage(e),
            IdentityServiceError::NotFound { message } => Self::NotFound { message },
            IdentityServiceError::Forbidden { message } => Self::Forbidden { message },
            IdentityServiceError::BadRequest { message, detail } => Self::BadRequest {
                message,
                detail,
                validations: Vec::new(),
            },
            IdentityServiceError::Validation {
                message,
                validations,
            } => Self::BadRequest {
                message,
                detail: None,
                validations,
            },
            IdentityServiceError::Conflict {
                message,
                detail,
                validations,
            } => Self::Conflict {
                message,
                detail,
                validations,
            },
        }
    }
}

impl From<OAuth2ProviderError> for AppError {
    fn from(error: OAuth2ProviderError) -> Self {
        match error {
            OAuth2ProviderError::Storage(e) => Self::Storage(e),
            OAuth2ProviderError::BadRequest { message } => Self::BadRequest {
                message,
                detail: Some(String::new()),
                validations: Vec::new(),
            },
            OAuth2ProviderError::NotFound { message } => Self::NotFound { message },
            OAuth2ProviderError::Unauthorized { message } => Self::Unauthorized { message },
        }
    }
}

impl AppError {
    /// Convert an [`ExternalAuthServiceError`] into an [`AppError`], wrapping
    /// the service-level detail with a caller-supplied user-facing message.
    pub(crate) fn from_external_auth(
        message: &'static str,
        error: ExternalAuthServiceError,
    ) -> Self {
        match error {
            ExternalAuthServiceError::BadRequest(detail) => Self::BadRequest {
                message: message.to_owned(),
                detail: Some(detail),
                validations: Vec::new(),
            },
            ExternalAuthServiceError::Storage(e) => Self::Storage(e),
            ExternalAuthServiceError::Internal(detail) => Self::InternalError {
                message: message.to_owned(),
                detail,
            },
        }
    }
}
