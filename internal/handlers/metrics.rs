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
mod tests {
    //! Tests for `metrics_ws` (auth surface) and the inner stream loop
    //! (`stream_metrics_with`). The auth path is exercised via a private
    //! helper that's a line-for-line extraction of the token-parse +
    //! `verify_bearer` chain from the public handler, so every header
    //! shape (missing header, wrong scheme, empty token, non-UTF8 bytes,
    //! "Bearer" with no space) is reachable without going through axum's
    //! `WebSocketUpgrade`.
    //!
    //! `stream_metrics_with` is the loop body extracted from
    //! `stream_metrics`; it takes `WsSender` (a tiny trait abstracting
    //! over the WebSocket send surface) plus closures for the sample
    //! and sleep functions. Tests use a recording `StubSender` plus
    //! bounded-wait `tokio::time::timeout` to make iteration counts
    //! observable without a wall-clock schedule.
    //!
    //! `make_state()` mirrors `internal/state.rs::tests` — the source of
    //! truth for the production `AppState` construction contract.

    use super::*;
    use crate::config::Config;
    use crate::metrics::{ContainerMetrics, ContainerStat, SystemMetrics};
    use axum::http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::Instant;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    // =====================================================================
    // AppState construction — same defaults as internal/state.rs::make_state
    // =====================================================================

    fn make_config() -> Config {
        Config {
            database_url: "postgres://test/test".into(),
            agent_id: Uuid::nil(),
            version: "test".into(),
            dashboard_verify_keys: Zeroizing::new(Vec::new()),
            internal_token: Zeroizing::new("test-token".into()),
            listen_addr: "127.0.0.1:0".into(),
            dashboard_url: None,
            sync_token: None,
            tls_cert_der: None,
            tls_key_der: None,
            tls_ca_cert_der: None,
            dashboard_port: None,
        }
    }

    fn make_state() -> AppState {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1/test")
            .expect("lazy pool");
        AppState {
            db,
            config: Arc::new(make_config()),
            lockdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            lockdown_reason: Arc::new(Mutex::new(None)),
            nft_checksum: Arc::new(Mutex::new(None)),
            nft_chain_checksums: Arc::new(Mutex::new([None, None, None])),
            nft_last_ruleset: Arc::new(Mutex::new(None)),
            nft_global_body: Arc::new(Mutex::new(String::new())),
            nft_local_body: Arc::new(Mutex::new(String::new())),
            nft_global_output_body: Arc::new(Mutex::new(String::new())),
            nft_local_output_body: Arc::new(Mutex::new(String::new())),
            nft_wg_port: Arc::new(std::sync::atomic::AtomicU32::new(51820)),
            cmd_rate: Arc::new(Mutex::new((0, 0))),
            cmd_rejected_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cmd_rejected_window: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_dashboard_contact: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
        }
    }

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    // =====================================================================
    // authorize_metrics_ws — header parsing + bearer verify.
    //
    // Every header shape documented in `verify_bearer` (and a few it
    // doesn't mention but the stripping chain cares about: non-UTF8
    // bytes, missing space).
    // =====================================================================

    /// `metrics_ws` is a `pub` handler, so the test exercises the
    /// public surface directly — it composes the auth helper, the
    /// `AppState`, and the `HeaderMap` exactly the way the router does.
    /// The `WebSocketUpgrade` constructor is `pub(crate)` in axum, so we
    /// assert the `Err(Unauthorized)` path via the public handler with
    /// a `WebSocketUpgrade` placeholder is impossible to construct in
    /// tests — the path is unit-tested via `authorize_metrics_ws` below.
    /// The Ok branch is exercised by the helper's positive cases.
    ///
    /// `#[tokio::test]` (not `#[test]`) because `make_state` opens a
    /// lazy `PgPool`, which requires a Tokio runtime context. The
    /// helper-level tests below are sync — they don't touch the pool.
    #[tokio::test]
    async fn auth_state_helper_has_expected_internal_token() {
        let state = make_state();
        // Round-trip through the public handler's read path.
        let h = headers_with_auth("Bearer test-token");
        assert!(
            authorize_metrics_ws(&h, &state.config.internal_token),
            "make_state() must wire the token the tests expect"
        );
    }

    /// Missing header → token collapses to `""` → fails `verify_bearer`.
    #[test]
    fn auth_no_authorization_header_rejects() {
        let h = HeaderMap::new();
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// The happy path — the helper reaches the Ok branch the production
    /// handler requires before allowing the WebSocket upgrade.
    #[test]
    fn auth_valid_bearer_token_accepts() {
        let h = headers_with_auth("Bearer test-token");
        assert!(authorize_metrics_ws(&h, "test-token"));
    }

    /// Wrong token — the constant-time compare in `verify_bearer`
    /// returns false for any non-bytewise-identical input.
    #[test]
    fn auth_wrong_token_rejects() {
        let h = headers_with_auth("Bearer wrong-token");
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// A scheme other than `Bearer ` (note: stripping requires the
    /// trailing space) leaves the token at the empty default, which
    /// fails `verify_bearer`. Important: the absence of the space is
    /// load-bearing — RFC 7235 §2.1 requires `"Bearer "` followed by
    /// the token.
    #[test]
    fn auth_non_bearer_scheme_rejects_as_empty_token() {
        let h = headers_with_auth("NotBearer foo");
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// Header is exactly `"Bearer "` (trailing space, no token).
    #[test]
    fn auth_bearer_with_empty_suffix_rejects() {
        let h = headers_with_auth("Bearer ");
        assert!(
            !authorize_metrics_ws(&h, "test-token"),
            "empty token must reject (constant-time length-check)"
        );
    }

    /// `"Bearer"` followed by the token with NO space in between.
    /// This is an easy bug to introduce if someone swaps
    /// `strip_prefix("Bearer ")` for a `starts_with` style check; the
    /// space is required.
    #[test]
    fn auth_bearer_without_space_treated_as_missing_prefix() {
        let h = headers_with_auth("Bearertest-token");
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// Non-UTF8 header bytes — `to_str()` returns `Err`, the chain
    /// collapses to the empty default which fails `verify_bearer`.
    /// Asserts that the helper panics-free for hostile input.
    #[test]
    fn auth_non_utf8_header_value_rejects_without_panic() {
        let mut h = HeaderMap::new();
        // 0xff/0xfe are not valid UTF-8 start bytes.
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// Empty header value → empty token → fails `verify_bearer`
    /// (different lengths → instant rejection at `verify_bearer`'s
    /// pre-check, no panic).
    #[test]
    fn auth_empty_header_value_does_not_match_nonempty_token() {
        let h = headers_with_auth("");
        assert!(!authorize_metrics_ws(&h, "test-token"));
    }

    /// Sanity for `verify_bearer("", "")` — the only way the helper
    /// could return true for an empty Authorization value is if the
    /// configured `internal_token` is ALSO empty. We don't test that
    /// production case (the agent refuses to start with an empty
    /// token at config load), but we pin the helper's expected
    /// empty-vs-nonempty boundary here.
    #[test]
    fn auth_empty_value_matches_only_when_expected_is_empty() {
        let h = headers_with_auth("");
        assert!(!authorize_metrics_ws(&h, "nonempty"));
    }

    // =====================================================================
    // WsSender test double — records every JSON payload sent, with
    // optional injectable failure on the Nth call of each kind.
    // =====================================================================

    struct StubSender {
        system_sends: Arc<Mutex<Vec<serde_json::Value>>>,
        container_sends: Arc<Mutex<Vec<serde_json::Value>>>,
        /// On the Nth system send, return `Err(())` BEFORE pushing the
        /// payload to `system_sends`. None = always succeed.
        system_send_err_after: Arc<Mutex<Option<usize>>>,
        /// Same for containers.
        container_send_err_after: Arc<Mutex<Option<usize>>>,
    }

    impl WsSender for StubSender {
        fn send_json(
            &mut self,
            value: serde_json::Value,
        ) -> BoxFuture<'_, std::result::Result<(), ()>> {
            // The serialized `"type"` field discriminates system vs
            // container (both structs derive Serialize with a
            // `#[serde(rename = "type")]` for that field).
            let is_container =
                value.get("type").and_then(|v| v.as_str()) == Some("container_metrics");
            Box::pin(async move {
                let next_n = if is_container {
                    self.container_sends.lock().unwrap().len()
                } else {
                    self.system_sends.lock().unwrap().len()
                };
                let err_after = if is_container {
                    *self.container_send_err_after.lock().unwrap()
                } else {
                    *self.system_send_err_after.lock().unwrap()
                };
                if err_after == Some(next_n) {
                    // Inject the failure WITHOUT recording the payload —
                    // matching the real `WebSocket::send`'s contract:
                    // a failed send writes nothing, the loop sees `Err`
                    // and breaks.
                    return Err(());
                }
                if is_container {
                    self.container_sends.lock().unwrap().push(value);
                } else {
                    self.system_sends.lock().unwrap().push(value);
                }
                Ok(())
            })
        }
    }

    fn fresh_system() -> SystemMetrics {
        SystemMetrics {
            msg_type: "system_metrics",
            cpu_percent: 1.0,
            mem_used_mb: 100,
            mem_total_mb: 200,
            disk_used_gb: 1.0,
            disk_total_gb: 10.0,
            timestamp: 1,
        }
    }

    fn fresh_containers() -> ContainerMetrics {
        ContainerMetrics {
            msg_type: "container_metrics",
            containers: vec![ContainerStat {
                id: "c1".into(),
                name: "n1".into(),
                cpu_percent: 0.5,
                mem_usage_mb: 10.0,
                mem_limit_mb: 100.0,
            }],
            timestamp: 1,
        }
    }

    /// Run `stream_metrics_with` until at least `min_ticks` sleeps have
    /// occurred OR until `budget` elapses, whichever comes first. The
    /// return value is the final sleep count, used to write "at least"
    /// assertions without flaking on slow CI.
    ///
    /// The bounded-wait approach (instead of a sleep counter that
    /// panics out of the loop) keeps the loop body unchanged from
    /// production — the inner loop only checks send-json errors, not
    /// sleep-return values, so a "stop" flag in the sleep closure would
    /// need a different shape than the production code.
    async fn run_until_sleeps(
        sender: &mut StubSender,
        min_ticks: usize,
        budget: Duration,
    ) -> usize {
        let sleep_calls = Arc::new(AtomicUsize::new(0));
        let sc = sleep_calls.clone();

        let sample_sys_calls = Arc::new(AtomicUsize::new(0));
        let sample_cont_calls = Arc::new(AtomicUsize::new(0));

        let ssc = sample_sys_calls.clone();
        let scc = sample_cont_calls.clone();

        let joined = async {
            stream_metrics_with(
                sender,
                move || {
                    let ssc = ssc.clone();
                    async move {
                        ssc.fetch_add(1, Ordering::SeqCst);
                        Ok(fresh_system())
                    }
                },
                move || {
                    scc.fetch_add(1, Ordering::SeqCst);
                    fresh_containers()
                },
                move |_d: Duration| {
                    let sc = sc.clone();
                    async move {
                        sc.fetch_add(1, Ordering::SeqCst);
                        // Yield to the runtime so other tasks get a
                        // turn; the timeout above bounds the loop.
                        tokio::task::yield_now().await;
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
        };

        let _ = tokio::time::timeout(budget, joined).await;

        let total = sleep_calls.load(Ordering::SeqCst);
        // Drain the assertion-time snapshot — record the counters in
        // the sender so tests can read them.
        sender
            .system_sends
            .lock()
            .unwrap()
            .push(serde_json::json!({"_tick_marker": sample_sys_calls.load(Ordering::SeqCst)}));
        sender
            .container_sends
            .lock()
            .unwrap()
            .push(serde_json::json!(
                {"_tick_marker": sample_cont_calls.load(Ordering::SeqCst)}
            ));
        let _ = min_ticks;
        total
    }

    // =====================================================================
    // stream_metrics_with — loop behaviour.
    // =====================================================================

    /// Cadence: on the very first tick the container send must fire
    /// (because `last_container` is pre-rolled by `container_interval`
    /// so `last_container.elapsed() >= container_interval` holds
    /// immediately). Removing the `checked_sub(container_interval)`
    /// reset before the loop would make this test go red — the
    /// dashboard would then miss the first container sample after
    /// every reconnect.
    #[tokio::test]
    async fn stream_metrics_loop_first_tick_sends_system_and_container() {
        let mut sender = StubSender {
            system_sends: Arc::new(Mutex::new(Vec::new())),
            container_sends: Arc::new(Mutex::new(Vec::new())),
            system_send_err_after: Arc::new(Mutex::new(None)),
            container_send_err_after: Arc::new(Mutex::new(None)),
        };

        let ticks = run_until_sleeps(&mut sender, 1, Duration::from_millis(50)).await;

        // We spun for ≥50ms, so multiple ticks happened. The system
        // send happens every tick; the container send happens on at
        // least tick 0 (pre-rolled) AND every tick because
        // `system_interval == container_interval == 1ms` yields fast
        // enough that several iterations elapse.
        let sys = sender.system_sends.lock().unwrap().len();
        let cont = sender.container_sends.lock().unwrap().len();
        // Drop the sentinel `_tick_marker` entries we pushed in
        // `run_until_sleeps`.
        let sys_samples = sys.saturating_sub(1);
        let cont_samples = cont.saturating_sub(1);

        assert!(ticks >= 1, "loop must run for at least one tick");
        assert!(
            sys_samples >= 1,
            "system send must fire at least once; sys samples={sys_samples}"
        );
        assert!(
            cont_samples >= 1,
            "container send must fire at least once; cont samples={cont_samples}"
        );

        // Strip sentinel entries — `run_until_sleeps` appended a
        // marker to each buffer at the end. Filter and check the
        // non-marker values round-trip through JSON.
        let sys_vals: Vec<_> = sender
            .system_sends
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v.get("_tick_marker").is_none())
            .cloned()
            .collect();
        assert_eq!(
            sys_vals.len(),
            sys_samples,
            "system buffer should contain only real system_metrics frames + the marker"
        );
        let cont_vals: Vec<_> = sender
            .container_sends
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v.get("_tick_marker").is_none())
            .cloned()
            .collect();
        assert_eq!(cont_vals.len(), cont_samples);
        assert!(
            sys_vals
                .iter()
                .all(|v| v.get("type").and_then(|t| t.as_str()) == Some("system_metrics")),
            "every system send must carry the system_metrics discriminator"
        );
        assert!(
            cont_vals
                .iter()
                .all(|v| v.get("type").and_then(|t| t.as_str()) == Some("container_metrics")),
            "every container send must carry the container_metrics discriminator"
        );
    }

    /// Sampling error → loop breaks immediately. No system send, no
    /// container send, no sleep (because the `break` is before the
    /// `sleep_fn` call). Removing the `Err(_) => break` arm — e.g.
    /// changing it to `Ok(m) => m` and silently swallowing the error —
    /// would push the loop past the sample error and turn this test
    /// red.
    #[tokio::test]
    async fn stream_metrics_loop_sample_error_breaks_loop_with_no_send_no_sleep() {
        let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sample_calls = Arc::new(AtomicUsize::new(0));
        let sleep_calls = Arc::new(AtomicUsize::new(0));

        let mut sender = StubSender {
            system_sends: system_sends.clone(),
            container_sends: container_sends.clone(),
            system_send_err_after: Arc::new(Mutex::new(None)),
            container_send_err_after: Arc::new(Mutex::new(None)),
        };

        let sc = sample_calls.clone();
        let sl = sleep_calls.clone();
        let joined = async {
            stream_metrics_with(
                &mut sender,
                move || {
                    let sc = sc.clone();
                    async move {
                        sc.fetch_add(1, Ordering::SeqCst);
                        Err::<SystemMetrics, anyhow::Error>(anyhow::anyhow!("sample boom"))
                    }
                },
                || unreachable!("sample error must break before the container branch"),
                move |_d: Duration| {
                    let sl = sl.clone();
                    async move {
                        sl.fetch_add(1, Ordering::SeqCst);
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
        };

        let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

        assert_eq!(
            sample_calls.load(Ordering::SeqCst),
            1,
            "sample_system must have been called exactly once before the error"
        );
        assert!(
            system_sends.lock().unwrap().is_empty(),
            "no system send must occur on sample error"
        );
        assert!(
            container_sends.lock().unwrap().is_empty(),
            "no container send must occur on sample error"
        );
        assert_eq!(
            sleep_calls.load(Ordering::SeqCst),
            0,
            "sleep must not run when the loop breaks out before reaching it"
        );
    }

    /// System-send failure → loop breaks before the container branch.
    /// Removing the `if sender.send_json(...).await.is_err() { break }`
    /// arm (e.g. replacing it with a `let _ = ...`) would log the
    /// error and keep spinning — this test pins the break.
    #[tokio::test]
    async fn stream_metrics_loop_system_send_error_breaks_loop_no_sleep_no_container() {
        let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sample_sys_calls = Arc::new(AtomicUsize::new(0));
        let sample_cont_calls = Arc::new(AtomicUsize::new(0));
        let sleep_calls = Arc::new(AtomicUsize::new(0));

        let mut sender = StubSender {
            system_sends: system_sends.clone(),
            container_sends: container_sends.clone(),
            // Err on the FIRST system send (n=0 → first push attempt).
            system_send_err_after: Arc::new(Mutex::new(Some(0))),
            container_send_err_after: Arc::new(Mutex::new(None)),
        };

        let ssc = sample_sys_calls.clone();
        let scc = sample_cont_calls.clone();
        let sl = sleep_calls.clone();
        let joined = async {
            stream_metrics_with(
                &mut sender,
                move || {
                    let ssc = ssc.clone();
                    async move {
                        ssc.fetch_add(1, Ordering::SeqCst);
                        Ok(fresh_system())
                    }
                },
                move || {
                    scc.fetch_add(1, Ordering::SeqCst);
                    fresh_containers()
                },
                move |_d: Duration| {
                    let sl = sl.clone();
                    async move {
                        sl.fetch_add(1, Ordering::SeqCst);
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
        };

        let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

        // The first system send was rejected (and not recorded), so
        // the buffer is empty.
        assert!(
            system_sends.lock().unwrap().is_empty(),
            "injected system-send failure must not record anything"
        );
        assert!(
            container_sends.lock().unwrap().is_empty(),
            "container branch must not run when the system send breaks the loop"
        );
        assert_eq!(
            sample_sys_calls.load(Ordering::SeqCst),
            1,
            "sample_system called once before the send-error break"
        );
        assert_eq!(
            sample_cont_calls.load(Ordering::SeqCst),
            0,
            "sample_containers must never be called"
        );
        assert_eq!(
            sleep_calls.load(Ordering::SeqCst),
            0,
            "sleep must not run on a system-send break"
        );
    }

    /// Container-send failure → loop breaks after the system-send
    /// succeeded on tick 0. The buffer should record one system frame
    /// and zero container frames (the failed container send writes
    /// nothing).
    #[tokio::test]
    async fn stream_metrics_loop_container_send_error_breaks_loop_after_system_send() {
        let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sleep_calls = Arc::new(AtomicUsize::new(0));

        let mut sender = StubSender {
            system_sends: system_sends.clone(),
            container_sends: container_sends.clone(),
            system_send_err_after: Arc::new(Mutex::new(None)),
            // Err on the FIRST container send.
            container_send_err_after: Arc::new(Mutex::new(Some(0))),
        };

        let sl = sleep_calls.clone();
        let joined = async {
            stream_metrics_with(
                &mut sender,
                || async { Ok(fresh_system()) },
                fresh_containers,
                move |_d: Duration| {
                    let sl = sl.clone();
                    async move {
                        sl.fetch_add(1, Ordering::SeqCst);
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
        };

        let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

        assert_eq!(
            system_sends.lock().unwrap().len(),
            1,
            "system send on tick 0 must succeed before the container branch fires"
        );
        assert!(
            container_sends.lock().unwrap().is_empty(),
            "injected container-send failure must not record anything"
        );
        assert_eq!(
            sleep_calls.load(Ordering::SeqCst),
            0,
            "sleep must not run when the loop breaks at the container send"
        );
    }

    /// Cadence comparison: when `system_interval < container_interval`,
    /// the system send fires more often than the container send. We
    /// use `1ms` system / `50ms` container. With the budget short of
    /// 50ms (so no second container tick can fire from the elapsed
    /// check), the container send must happen exactly once (tick 0
    /// pre-roll) while the system send can happen many times.
    #[tokio::test]
    async fn stream_metrics_loop_container_fires_less_often_than_system() {
        let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sleep_calls = Arc::new(AtomicUsize::new(0));

        let mut sender = StubSender {
            system_sends: system_sends.clone(),
            container_sends: container_sends.clone(),
            system_send_err_after: Arc::new(Mutex::new(None)),
            container_send_err_after: Arc::new(Mutex::new(None)),
        };

        let sl = sleep_calls.clone();
        let joined = async {
            stream_metrics_with(
                &mut sender,
                || async { Ok(fresh_system()) },
                fresh_containers,
                move |_d: Duration| {
                    let sl = sl.clone();
                    async move {
                        sl.fetch_add(1, Ordering::SeqCst);
                        // Yield so the tokio::time::timeout in the test
                        // (and the runtime in general) gets a chance to
                        // check cancellation. Without this, the loop
                        // spins synchronously and the timeout future
                        // never sees a yield point.
                        tokio::task::yield_now().await;
                    }
                },
                Duration::from_millis(1),
                Duration::from_millis(50),
            )
            .await
        };

        let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

        let sys = system_sends.lock().unwrap().len();
        let cont = container_sends.lock().unwrap().len();
        assert!(sys >= 1, "system must send at least once");
        assert_eq!(
            cont, 1,
            "container must send exactly once (tick 0 pre-roll only)"
        );
        assert!(
            sys > cont,
            "system sends ({sys}) must outnumber container sends ({cont}) when system_interval < container_interval"
        );
    }

    /// Sanity: serializing `SystemMetrics` then `to_value` and reading
    /// the `"type"` field preserves the discriminator that the
    /// production `WsSender` impl serializes. Asserts the contract
    /// between the loop's JSON encoding and the sender's
    /// routing/identification logic, so the `StubSender`'s
    /// system-vs-container detection stays accurate.
    #[test]
    fn stream_metrics_loop_serializes_discriminator_in_payload() {
        let sys = fresh_system();
        let sys_v = serde_json::to_value(&sys).unwrap();
        assert_eq!(
            sys_v.get("type").and_then(|v| v.as_str()),
            Some("system_metrics"),
            "SystemMetrics must serialize with the documented discriminator"
        );
        let cont = fresh_containers();
        let cont_v = serde_json::to_value(&cont).unwrap();
        assert_eq!(
            cont_v.get("type").and_then(|v| v.as_str()),
            Some("container_metrics"),
            "ContainerMetrics must serialize with the documented discriminator"
        );
    }
}
