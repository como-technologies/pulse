use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Axum extractor and response type for postcard-encoded binary protocol messages.
///
/// Mirrors `axum::Json<T>` but uses `postcard` instead of `serde_json`.
pub struct Binary<T>(pub T);

impl<S, T> FromRequest<S> for Binary<T>
where
    T: for<'de> Deserialize<'de>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::BadRequest("failed to read request body".to_string()))?;
        let value = postcard::from_bytes(&bytes)
            .map_err(|_| ApiError::BadRequest("malformed binary request body".to_string()))?;
        Ok(Binary(value))
    }
}

impl<T: Serialize> IntoResponse for Binary<T> {
    fn into_response(self) -> Response {
        match postcard::to_allocvec(&self.0) {
            Ok(bytes) => {
                ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
            }
            Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
