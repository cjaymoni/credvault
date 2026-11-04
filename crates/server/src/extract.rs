//! JSON body extractor that reports malformed input as a 400 in the same
//! `{"error": ...}` shape as every other error, instead of axum's default 422.

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::Json;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::PayloadTooLarge),
            Err(rejection) => Err(ApiError::BadRequest(rejection.body_text())),
        }
    }
}
