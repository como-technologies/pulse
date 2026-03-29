//! In-memory `HttpTransport` implementation for deterministic testing.
//!
//! Routes are matched by HTTP method + URL substring. No network, no TCP.
//! Records all requests for assertion.

use std::sync::Mutex;

use pulse_client::error::ClientError;
use pulse_client::transport::{HttpTransport, TransportResponse};

/// HTTP method for route matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    PostJson,
    PostBinary,
}

/// A recorded request for assertion.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: HttpMethod,
    pub url: String,
    pub body: Vec<u8>,
    pub bearer_token: Option<String>,
}

/// A pre-configured response for a URL pattern.
struct MockRoute {
    method: HttpMethod,
    url_contains: String,
    response: TransportResponse,
}

/// In-memory HTTP transport that matches requests against pre-configured routes.
///
/// # Example
///
/// ```ignore
/// let transport = MockTransport::new()
///     .on(HttpMethod::PostJson, "/auth", TransportResponse {
///         status: 200,
///         body: br#"{"session_token":"tok-123"}"#.to_vec(),
///     });
/// ```
pub struct MockTransport {
    routes: Mutex<Vec<MockRoute>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            routes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Add a route that responds to requests matching `url_contains`.
    pub fn on(self, method: HttpMethod, url_contains: &str, response: TransportResponse) -> Self {
        self.routes.lock().expect("poisoned").push(MockRoute {
            method,
            url_contains: url_contains.to_string(),
            response,
        });
        self
    }

    /// Get a snapshot of all recorded requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("poisoned").clone()
    }

    /// Assert that exactly `expected` requests were made matching the given URL pattern.
    pub fn assert_request_count(&self, url_contains: &str, expected: usize) {
        let count = self
            .requests
            .lock()
            .expect("poisoned")
            .iter()
            .filter(|r| r.url.contains(url_contains))
            .count();
        assert_eq!(
            count, expected,
            "expected {expected} requests matching '{url_contains}', found {count}"
        );
    }

    fn find_response(
        &self,
        method: &HttpMethod,
        url: &str,
    ) -> Result<TransportResponse, ClientError> {
        let routes = self.routes.lock().expect("poisoned");
        for route in routes.iter() {
            if &route.method == method && url.contains(&route.url_contains) {
                return Ok(TransportResponse {
                    status: route.response.status,
                    body: route.response.body.clone(),
                });
            }
        }
        Err(ClientError::Transport(format!(
            "no mock route for {method:?} {url}"
        )))
    }

    fn record(&self, method: HttpMethod, url: &str, body: &[u8], bearer_token: Option<&str>) {
        self.requests
            .lock()
            .expect("poisoned")
            .push(RecordedRequest {
                method,
                url: url.to_string(),
                body: body.to_vec(),
                bearer_token: bearer_token.map(String::from),
            });
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HttpTransport for MockTransport {
    async fn post_json(&self, url: &str, body: &[u8]) -> Result<TransportResponse, ClientError> {
        self.record(HttpMethod::PostJson, url, body, None);
        self.find_response(&HttpMethod::PostJson, url)
    }

    async fn post_binary(
        &self,
        url: &str,
        body: &[u8],
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError> {
        self.record(HttpMethod::PostBinary, url, body, bearer_token);
        self.find_response(&HttpMethod::PostBinary, url)
    }

    async fn get_binary(
        &self,
        url: &str,
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError> {
        self.record(HttpMethod::Get, url, &[], bearer_token);
        self.find_response(&HttpMethod::Get, url)
    }
}
