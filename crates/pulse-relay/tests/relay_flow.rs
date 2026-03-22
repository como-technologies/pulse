//! Integration tests for the anonymizing relay.
//!
//! Tests use a mock Signal zone (Axum server on port 0) that records
//! received requests and returns configurable responses.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Router, routing::post};
use tokio::net::TcpListener;

use pulse_relay::RelayState;
use pulse_relay::batcher::{self, Batcher};
use pulse_relay::config::Config;
use pulse_relay::routes;

/// A request as seen by the mock Signal zone.
struct ReceivedRequest {
    body: Vec<u8>,
    headers: HeaderMap,
}

/// Shared state for the mock Signal zone.
struct MockSignalState {
    requests: Mutex<Vec<ReceivedRequest>>,
    response_status: StatusCode,
    response_body: String,
}

async fn mock_handler(
    State(state): State<Arc<MockSignalState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.requests.lock().unwrap().push(ReceivedRequest {
        body: body.to_vec(),
        headers,
    });
    (state.response_status, state.response_body.clone())
}

/// Start a mock Signal zone that records requests and returns the given status/body.
async fn start_mock_signal(status: StatusCode, body: &str) -> (String, Arc<MockSignalState>) {
    let state = Arc::new(MockSignalState {
        requests: Mutex::new(Vec::new()),
        response_status: status,
        response_body: body.to_string(),
    });

    let router = Router::new()
        .route("/response", post(mock_handler))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, router).into_future());

    (format!("http://{addr}"), state)
}

/// Start a relay pointed at the given signal URL.
async fn start_relay(signal_url: &str, batch_size: usize) -> String {
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".to_string(),
        signal_url: signal_url.to_string(),
        batch_size,
        batch_window_secs: 1,
        min_delay_ms: 0,
        max_delay_ms: 0,
        request_timeout_secs: 5,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()
        .unwrap();

    let batcher = Arc::new(Batcher::new(config.batch_size));

    let relay_state = Arc::new(RelayState {
        batcher: batcher.clone(),
        config: config.clone(),
        client: client.clone(),
    });

    tokio::spawn(batcher::flush_loop(batcher, config, client));

    let router = Router::new()
        .route("/response", post(routes::relay_response))
        .with_state(relay_state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, router).into_future());

    format!("http://{addr}")
}

#[tokio::test]
async fn basic_forwarding() {
    let (signal_url, mock) = start_mock_signal(StatusCode::OK, r#"{"status":"accepted"}"#).await;
    let relay_url = start_relay(&signal_url, 1).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{relay_url}/response"))
        .body(b"hello world".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "accepted");

    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"hello world");
}

#[tokio::test]
async fn no_client_headers_forwarded() {
    let (signal_url, mock) = start_mock_signal(StatusCode::OK, r#"{"status":"accepted"}"#).await;
    let relay_url = start_relay(&signal_url, 1).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{relay_url}/response"))
        .header("User-Agent", "EvilBrowser/1.0")
        .header("X-Forwarded-For", "192.168.1.100")
        .header("Authorization", "Bearer secret-token")
        .header("Cookie", "session=abc123")
        .body(b"test".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let received = &requests[0].headers;

    // The relay builds a fresh request — none of the client's headers should arrive
    assert!(
        received.get("user-agent").is_none()
            || received.get("user-agent").unwrap().to_str().unwrap() != "EvilBrowser/1.0",
        "client User-Agent must not be forwarded"
    );
    assert!(
        received.get("x-forwarded-for").is_none(),
        "X-Forwarded-For must not be forwarded"
    );
    assert!(
        received.get("authorization").is_none(),
        "Authorization must not be forwarded"
    );
    assert!(
        received.get("cookie").is_none(),
        "Cookie must not be forwarded"
    );

    // Content-Type should be application/octet-stream (set by relay)
    let ct = received.get("content-type").unwrap().to_str().unwrap();
    assert_eq!(ct, "application/octet-stream");
}

#[tokio::test]
async fn batching_delivers_all_requests() {
    let (signal_url, mock) = start_mock_signal(StatusCode::OK, r#"{"status":"accepted"}"#).await;
    // batch_size=2 so two requests trigger a flush
    let relay_url = start_relay(&signal_url, 2).await;

    let client = reqwest::Client::new();

    // Send two requests concurrently — they should batch together
    let (r1, r2) = tokio::join!(
        client
            .post(format!("{relay_url}/response"))
            .body(b"request-1".to_vec())
            .send(),
        client
            .post(format!("{relay_url}/response"))
            .body(b"request-2".to_vec())
            .send(),
    );

    assert_eq!(r1.unwrap().status(), 200);
    assert_eq!(r2.unwrap().status(), 200);

    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 2, "both requests must be forwarded");

    // Both bodies should arrive (order may differ due to shuffling)
    let bodies: Vec<&[u8]> = requests.iter().map(|r| r.body.as_slice()).collect();
    assert!(bodies.contains(&b"request-1".as_slice()));
    assert!(bodies.contains(&b"request-2".as_slice()));
}

#[tokio::test]
async fn upstream_error_forwarded() {
    let (signal_url, _mock) = start_mock_signal(
        StatusCode::UNPROCESSABLE_ENTITY,
        r#"{"code":"RESPONSE_INVALID_SIGNATURE","message":"bad sig"}"#,
    )
    .await;
    let relay_url = start_relay(&signal_url, 1).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{relay_url}/response"))
        .body(b"bad-request".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_INVALID_SIGNATURE");
}

#[tokio::test]
async fn body_opacity() {
    let (signal_url, mock) = start_mock_signal(StatusCode::OK, r#"{"status":"accepted"}"#).await;
    let relay_url = start_relay(&signal_url, 1).await;

    // Send non-JSON binary bytes — relay should forward unchanged
    let binary_payload: Vec<u8> = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{relay_url}/response"))
        .body(binary_payload.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body, binary_payload,
        "binary bytes must pass through unchanged"
    );
}
