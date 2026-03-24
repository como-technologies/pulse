use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;

use crate::SignalState;
use crate::analytics::AnalyticsError;
use crate::error::ApiError;

#[derive(serde::Deserialize)]
pub struct BatchQueryParams {
    pub tenant_id: String,
}

/// `GET /analytics/batch/:batch_id?tenant_id=<uuid>`
///
/// Aggregate responses for a question batch — decrypts response payloads,
/// groups by segment, computes average scores, and enforces k-anonymity suppression.
pub async fn aggregate_batch(
    State(state): State<Arc<SignalState>>,
    Path(batch_id_str): Path<String>,
    Query(params): Query<BatchQueryParams>,
) -> impl IntoResponse {
    let batch_id = match uuid::Uuid::parse_str(&batch_id_str) {
        Ok(id) => pulse_protocol::QuestionBatchId::from_uuid(id),
        Err(_) => return ApiError::BadRequest("invalid batch ID".to_string()).into_response(),
    };
    let tenant_id = match uuid::Uuid::parse_str(&params.tenant_id) {
        Ok(id) => pulse_protocol::TenantId::from_uuid(id),
        Err(_) => return ApiError::BadRequest("invalid tenant ID".to_string()).into_response(),
    };

    let engine = match &state.analytics {
        Some(engine) => engine,
        None => {
            return ApiError::AnalyticsUnavailable.into_response();
        }
    };

    match engine.aggregate_batch(&batch_id, &tenant_id) {
        Ok(result) => Json(result).into_response(),
        Err(e) => map_analytics_error(e).into_response(),
    }
}

fn map_analytics_error(e: AnalyticsError) -> ApiError {
    match e {
        AnalyticsError::DekNotFound => {
            ApiError::AnalyticsNotFound("tenant not found or crypto-shredded".to_string())
        }
        AnalyticsError::DekUnwrapFailed(msg) => {
            tracing::error!(error = %msg, "analytics DEK unwrap failed");
            ApiError::AnalyticsInternal("DEK unwrap failed".to_string())
        }
    }
}
