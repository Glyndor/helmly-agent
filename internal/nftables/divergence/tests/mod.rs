//! Unit tests for the nftables divergence detector.
//!
//! The whole module is a state machine driven by a handful of external
//! calls (`nft list table`, `nft list chain`, `nft -f -`). The
//! production code now accepts those calls as closures, so tests
//! inject canned runners and assert side effects on `AppState`
//! (lockdown, expected checksums, last ruleset applied) without
//! touching the real binary.
//!
//! Per `standards/testing/index.md`: each test mutates a control it
//! names. Mutation notes inline on every test.
//!
//! Coverage map for `nftables/divergence.rs`:
//! - `run_divergence_check` (loop body): covered indirectly via
//!   `run_divergence_check_with`'s closure signature being exercised
//!   by every `check_once_with` test.
//! - `check_once_with`: every branch (baseline short-circuit, current
//!   checksum failure, match-returns, divergence + restore OK /
//!   restore fail + emergency OK / emergency fail) covered.
//! - `is_chain_diverged_with`: every arm (unknown chain, no baseline,
//!   match, differ, query Err) covered.
//! - `restore_with`: every branch (no last ruleset, apply OK,
//!   apply Err) covered.
//! - `notify_dashboard`: both early-return branches (no URL, no
//!   token) covered; the live HTTP path is skipped — it would
//!   require an axum test server and the early-return path is the
//!   only one exercised in normal divergence flows (dashboard URL
//!   is optional in `Config`).
//! - The SHA256-of-nft-output contract is covered by
//!   `chain_checksum_*` tests, which mirror the hashing step from
//!   `nftables::chain_checksum_raw` in lockstep.

use super::*;
use crate::config::Config;
use crate::state::LockdownReason;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

// ---------- helpers ---------------------------------------------------

/// Build an `AppState` with `dashboard_url` and `sync_token` unset so
/// `notify_dashboard` returns early. The DB pool is a lazy connection
/// that never queries anything in these tests.
fn make_state() -> AppState {
	make_state_with_dashboard(None, None)
}

fn make_state_with_dashboard(dashboard_url: Option<&str>, sync_token: Option<&str>) -> AppState {
	let cfg = Config {
		database_url: "postgres://test/test".into(),
		agent_id: uuid::Uuid::nil(),
		version: "test".into(),
		dashboard_verify_keys: Zeroizing::new(vec![[0u8; 32]]),
		internal_token: Zeroizing::new("test".into()),
		listen_addr: "127.0.0.1:0".into(),
		dashboard_url: dashboard_url.map(str::to_owned),
		sync_token: sync_token.map(|s| Zeroizing::new(s.to_owned())),
		tls_cert_der: None,
		tls_key_der: None,
		tls_ca_cert_der: None,
		dashboard_port: None,
	};
	let db = PgPoolOptions::new()
		.connect_lazy("postgres://test:test@127.0.0.1/test")
		.expect("lazy pool");
	AppState {
		db,
		config: Arc::new(cfg),
		lockdown: Arc::new(AtomicBool::new(false)),
		lockdown_reason: Arc::new(Mutex::new(None)),
		nft_checksum: Arc::new(Mutex::new(None)),
		nft_chain_checksums: Arc::new(Mutex::new([None, None, None])),
		nft_last_ruleset: Arc::new(Mutex::new(None)),
		nft_global_body: Arc::new(Mutex::new(String::new())),
		nft_local_body: Arc::new(Mutex::new(String::new())),
		nft_global_output_body: Arc::new(Mutex::new(String::new())),
		nft_local_output_body: Arc::new(Mutex::new(String::new())),
		nft_wg_port: Arc::new(AtomicU32::new(51820)),
		cmd_rate: Arc::new(Mutex::new((0, 0))),
		cmd_rejected_count: Arc::new(AtomicU64::new(0)),
		cmd_rejected_window: Arc::new(AtomicU64::new(0)),
		last_dashboard_contact: Arc::new(AtomicU64::new(0)),
		last_heartbeat: Arc::new(Mutex::new(Instant::now())),
	}
}

/// Stub: returns a constant current-table checksum on every call.
fn stub_current(checksum: &'static str) -> impl Fn() -> anyhow::Result<String> {
	move || Ok(checksum.to_owned())
}

/// Stub: returns a per-chain checksum; any chain name not in the
/// map yields `default`. Pass `default = Err(...)` to simulate a
/// missing/deleted chain (which the detector attributes as diverged).
fn stub_chain(
	per_chain: &'static [(&'static str, &'static str)],
	default: anyhow::Result<String>,
) -> impl Fn(&str) -> anyhow::Result<String> {
	move |chain: &str| match per_chain.iter().find(|(c, _)| *c == chain) {
		Some((_, cs)) => Ok((*cs).to_owned()),
		None => match &default {
			Ok(s) => Ok(s.clone()),
			Err(_) => Err(anyhow::anyhow!("chain {} missing", chain)),
		},
	}
}

/// Stub: records the ruleset string the detector hands to the apply
/// callback. Returns `Ok(())` unless the test overrides the closure.
fn stub_apply_recording(sink: Arc<Mutex<Vec<String>>>) -> impl Fn(&str) -> anyhow::Result<()> {
	move |r: &str| {
		sink.lock().unwrap().push(r.to_owned());
		Ok(())
	}
}

fn stub_emergency_ok() -> impl Fn() -> anyhow::Result<()> {
	|| Ok(())
}

fn stub_emergency_err() -> impl Fn() -> anyhow::Result<()> {
	|| Err(anyhow::anyhow!("emergency apply failed"))
}

mod chain_diverged;
mod check_once;
mod checksum;
mod notify;
mod restore;
