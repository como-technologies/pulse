use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::StatusCode;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use tokio::sync::{Notify, oneshot};

use crate::config::Config;

/// Result of forwarding a request to the Signal zone.
pub enum ForwardResult {
    /// Upstream responded with a status code and body.
    Response { status: StatusCode, body: Bytes },
    /// Forwarding failed (network error, timeout, etc.).
    Error(String),
}

/// A request waiting to be batched and forwarded.
struct PendingRequest {
    body: Bytes,
    reply: oneshot::Sender<ForwardResult>,
}

/// Batch queue that accumulates requests and forwards them in shuffled batches.
pub struct Batcher {
    queue: Mutex<Vec<PendingRequest>>,
    notify: Arc<Notify>,
    batch_size: usize,
}

impl Batcher {
    pub fn new(batch_size: usize) -> Self {
        Self {
            queue: Mutex::new(Vec::new()),
            notify: Arc::new(Notify::new()),
            batch_size,
        }
    }

    /// Enqueue a request body for batched forwarding.
    /// Returns a receiver that will eventually contain the upstream response.
    pub fn enqueue(&self, body: Bytes) -> oneshot::Receiver<ForwardResult> {
        let (tx, rx) = oneshot::channel();
        let mut queue = self.queue.lock().expect("batcher queue lock poisoned");
        queue.push(PendingRequest { body, reply: tx });
        if queue.len() >= self.batch_size {
            self.notify.notify_one();
        }
        rx
    }

    /// Drain all pending requests from the queue.
    fn drain(&self) -> Vec<PendingRequest> {
        let mut queue = self.queue.lock().expect("batcher queue lock poisoned");
        queue.drain(..).collect()
    }

    /// Get a handle to the notify for the flush loop.
    pub fn notifier(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

/// Forward a single request to the Signal zone.
async fn forward(client: &reqwest::Client, signal_url: &str, body: Bytes) -> ForwardResult {
    let url = format!("{signal_url}/response");
    match client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            match resp.bytes().await {
                Ok(body) => ForwardResult::Response { status, body },
                Err(e) => ForwardResult::Error(format!("failed to read upstream body: {e}")),
            }
        }
        Err(e) => ForwardResult::Error(format!("upstream request failed: {e}")),
    }
}

/// Background task that drains, shuffles, and forwards batched requests.
pub async fn flush_loop(batcher: Arc<Batcher>, config: Arc<Config>, client: reqwest::Client) {
    let notify = batcher.notifier();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.batch_window_secs)) => {},
            _ = notify.notified() => {},
        }

        let mut batch = batcher.drain();
        if batch.is_empty() {
            continue;
        }

        // Shuffle for timing decorrelation and pre-compute delays.
        let mut rng = StdRng::from_os_rng();
        batch.shuffle(&mut rng);
        let delays: Vec<u64> = batch
            .iter()
            .map(|_| {
                if config.max_delay_ms > config.min_delay_ms {
                    rng.random_range(config.min_delay_ms..=config.max_delay_ms)
                } else {
                    0
                }
            })
            .collect();

        tracing::info!(batch_size = batch.len(), "flushing batch");

        for (item, delay) in batch.into_iter().zip(delays) {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            let result = forward(&client, &config.signal_url, item.body).await;
            // If the client already disconnected, the send fails silently — that's fine
            let _ = item.reply.send(result);
        }
    }
}
