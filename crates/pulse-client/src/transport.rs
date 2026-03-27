use crate::error::ClientError;

/// Raw HTTP response from the transport layer.
pub struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Minimal HTTP transport trait for the Pulse protocol.
///
/// Three methods match the exact HTTP patterns used by the protocol:
/// - `post_json`: auth endpoint (JSON in, JSON out)
/// - `post_binary`: token signing + response submission (postcard in, postcard out)
/// - `get_binary`: question fetch (binary response, optional auth)
#[async_trait::async_trait]
pub trait HttpTransport: Send + Sync {
    /// POST a JSON body, return the raw response.
    async fn post_json(&self, url: &str, body: &[u8]) -> Result<TransportResponse, ClientError>;

    /// POST a binary (postcard) body with an optional Bearer token.
    async fn post_binary(
        &self,
        url: &str,
        body: &[u8],
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError>;

    /// GET with an optional Bearer token, return the raw response.
    async fn get_binary(
        &self,
        url: &str,
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError>;
}

#[cfg(feature = "reqwest-transport")]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "reqwest-transport")]
impl ReqwestTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "reqwest-transport")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "reqwest-transport")]
#[async_trait::async_trait]
impl HttpTransport for ReqwestTransport {
    async fn post_json(&self, url: &str, body: &[u8]) -> Result<TransportResponse, ClientError> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .to_vec();

        Ok(TransportResponse { status, body })
    }

    async fn post_binary(
        &self,
        url: &str,
        body: &[u8],
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError> {
        let mut req = self
            .client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec());

        if let Some(token) = bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .to_vec();

        Ok(TransportResponse { status, body })
    }

    async fn get_binary(
        &self,
        url: &str,
        bearer_token: Option<&str>,
    ) -> Result<TransportResponse, ClientError> {
        let mut req = self.client.get(url);

        if let Some(token) = bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
            .to_vec();

        Ok(TransportResponse { status, body })
    }
}
