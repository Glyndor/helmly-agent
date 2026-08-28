use crate::{
    auth::verify_bearer,
    error::{AgentError, Result},
    metrics,
    state::AppState,
};
use axum::{
    extract::{ws::WebSocket, State, WebSocketUpgrade},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::time::Duration;
use tracing::warn;

const SYSTEM_INTERVAL: Duration = Duration::from_secs(5);
const CONTAINER_INTERVAL: Duration = Duration::from_secs(10);

pub async fn metrics_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    if !authorize_metrics_ws(&headers, &state.config.internal_token) {
        return Err(AgentError::Unauthorized);
    }
    Ok(ws
        .on_upgrade(|socket| async move { stream_metrics(socket).await })
        .into_response())
}

/// Extract the bearer token from the `Authorization: Bearer <token>` header
/// and verify it against `expected`. Returns `false` for any mismatch,
/// including a missing header, the wrong scheme, an empty token, or a
/// header value that isn't valid UTF-8.
///
/// Extracted from `metrics_ws` so the header-parsing rules are reachable
/// without an axum `WebSocketUpgrade` (which is not constructible outside
/// axum's internal upgrade flow). Mirrors the same extraction pattern
/// already used in `internal/handlers/system.rs::execute_command`.
fn authorize_metrics_ws(headers: &HeaderMap, expected: &str) -> bool {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    verify_bearer(token, expected)
}

pub async fn stream_metrics(socket: WebSocket) {
    let mut socket = socket;
    stream_metrics_with(
        &mut socket,
        metrics::sample_system,
        metrics::sample_containers,
        |d| async move { tokio::time::sleep(d).await },
        SYSTEM_INTERVAL,
        CONTAINER_INTERVAL,
    )
    .await;
}

/// WebSocket send surface — abstracted so the inner stream loop is
/// testable without an axum `WebSocket` (which is only constructible via
/// the internal upgrade handshake). Production wires the trait to
/// `axum::extract::ws::WebSocket`; tests wire a recording stub that
/// counts sends and injects failures.
///
/// `: Send` on the trait so `dyn WsSender` is `Send` — required for
/// `axum::extract::ws::WebSocketUpgrade::on_upgrade`'s `Send + 'static`
/// bound on the upgrade callback's future.
pub(crate) trait WsSender: Send {
    /// Send a JSON value as a text frame. `Err(())` collapses every
    /// send failure (closed socket, write error) so the loop can use
    /// a single `is_err()` check, mirroring
    /// `axum::extract::ws::WebSocket::send`'s `Result<(), axum::Error>`
    /// contract.
    fn send_json(&mut self, value: serde_json::Value)
        -> BoxFuture<'_, std::result::Result<(), ()>>;
}

impl WsSender for WebSocket {
    fn send_json(
        &mut self,
        value: serde_json::Value,
    ) -> BoxFuture<'_, std::result::Result<(), ()>> {
        use axum::extract::ws::Message;
        Box::pin(async move {
            let msg = serde_json::to_string(&value).unwrap_or_default();
            self.send(Message::Text(msg.into())).await.map_err(|_| ())
        })
    }
}

/// Inner stream loop, extracted from `stream_metrics` so the cadence,
/// sample-error, and send-error paths are testable without running
/// podman or constructing a real `WebSocket`.
///
/// Cadence:
/// - The system sample is sent every tick (one tick = one
///   `sleep_fn` invocation).
/// - The container sample is sent at most every `container_interval`,
///   with the first tick always firing because `last_container` is
///   pre-rolled by `container_interval` so the initial
///   `last_container.elapsed()` is at least `container_interval`.
pub(crate) async fn stream_metrics_with<F, Fut, G, H, FutH>(
    sender: &mut dyn WsSender,
    mut sample_system_fn: F,
    mut sample_containers_fn: G,
    mut sleep_fn: H,
    system_interval: Duration,
    container_interval: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<metrics::SystemMetrics>>,
    G: FnMut() -> metrics::ContainerMetrics,
    H: FnMut(Duration) -> FutH,
    FutH: std::future::Future<Output = ()>,
{
    use std::time::Instant;

    let mut last_container = Instant::now()
        .checked_sub(container_interval)
        .unwrap_or_else(Instant::now);

    loop {
        match sample_system_fn().await {
            Ok(m) => {
                let v = serde_json::to_value(&m).unwrap_or_default();
                if sender.send_json(v).await.is_err() {
                    break;
                }
            }
            Err(_e) => {
                warn!("system metrics sample error");
                break;
            }
        }

        if last_container.elapsed() >= container_interval {
            let c = sample_containers_fn();
            let v = serde_json::to_value(&c).unwrap_or_default();
            if sender.send_json(v).await.is_err() {
                break;
            }
            last_container = Instant::now();
        }

        sleep_fn(system_interval).await;
    }
}

#[cfg(test)]
mod tests;
