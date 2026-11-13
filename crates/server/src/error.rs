//! One error type for every handler, rendered as `{"error": "..."}` JSON.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("request body is too large")]
    PayloadTooLarge,
    #[error("too many requests; try again in {retry_after_secs} seconds")]
    TooManyRequests { retry_after_secs: u64 },
    #[error("internal error")]
    Internal(#[source] BoxError),
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl ApiError {
    pub fn internal(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(Box::new(error))
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(source) = &self {
            tracing::error!(error = %source, "request failed");
        }
        let mut response = (self.status(), Json(json!({ "error": self.to_string() }))).into_response();
        if let Self::TooManyRequests { retry_after_secs } = &self {
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(error)
    }
}

/// Only used when *serialising* validated values for storage, which is an
/// internal failure, never a client error. Client JSON errors are handled by
/// the `ApiJson` extractor.
impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::internal(error)
    }
}

/// Crypto errors only arise from validating client-supplied values.
impl From<klavyn_core::CryptoError> for ApiError {
    fn from(error: klavyn_core::CryptoError) -> Self {
        Self::BadRequest(error.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
