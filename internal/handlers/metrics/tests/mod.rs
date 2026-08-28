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

mod authorize_ws;
mod stream_loop;
