use crate::config::Config;
use sqlx::PgPool;
use std::sync::{
	atomic::{AtomicBool, AtomicU64, Ordering},
	Arc, Mutex,
};
use std::time::Instant;

/// Tracks why the agent entered lockdown.
/// Only `Heartbeat` (and `None`) can be cleared by a `heartbeat_ack`.
/// All other reasons require a manual service restart to clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownReason {
	Heartbeat,
	PgUnreachable,
	IncompatibleSoftware,
	NftablesFailure,
}

#[derive(Clone)]
pub struct AppState {
	pub db: PgPool,
	pub config: Arc<Config>,
	/// Set to true when the agent enters lockdown.
	pub lockdown: Arc<AtomicBool>,
	/// The reason the agent entered lockdown, if any.
	pub lockdown_reason: Arc<Mutex<Option<LockdownReason>>>,
	/// Last known-good nftables checksum after apply(). None = no ruleset applied yet.
	pub nft_checksum: Arc<Mutex<Option<String>>>,
	/// Per-chain checksums captured after each successful apply() — used for divergence attribution.
	pub nft_chain_checksums: Arc<Mutex<[Option<String>; 3]>>,
	/// Rendered nft ruleset from last successful apply() — used for restore.
	pub nft_last_ruleset: Arc<Mutex<Option<String>>>,
	/// Body of the helmly-global chain (input, managed by dashboard global rules).
	pub nft_global_body: Arc<Mutex<String>>,
	/// Body of the helmly-local chain (input, managed by dashboard local rules for this agent).
	pub nft_local_body: Arc<Mutex<String>>,
	/// Body of the helmly-global-output chain (output, managed by dashboard global rules).
	pub nft_global_output_body: Arc<Mutex<String>>,
	/// Body of the helmly-local-output chain (output, managed by dashboard local rules for this agent).
	pub nft_local_output_body: Arc<Mutex<String>>,
	/// WireGuard port used in the last full nftables apply (stored for chain-only updates).
	pub nft_wg_port: Arc<std::sync::atomic::AtomicU32>,
	/// In-memory command rate limiter: (window_start_secs, count_in_window)
	pub cmd_rate: Arc<Mutex<(u64, u64)>>,
	/// Count of `rejected_rate_limit` events in the current minute — alert threshold.
	pub cmd_rejected_count: Arc<AtomicU64>,
	/// Epoch-second when the current rejection-count minute window started.
	pub cmd_rejected_window: Arc<AtomicU64>,
	/// Epoch-second of last successful dashboard contact (WS connect or message received).
	/// 0 = never connected. Used by the fallback updater to detect dashboard absence.
	pub last_dashboard_contact: Arc<AtomicU64>,
	/// Instant of last received heartbeat ACK from dashboard.
	/// Reset by both the HTTP /heartbeat handler and the WS heartbeat_ack path.
	/// The lockdown watchdog fires when this exceeds HEARTBEAT_TIMEOUT_SECS.
	pub last_heartbeat: Arc<Mutex<Instant>>,
}

impl AppState {
	pub fn is_locked_down(&self) -> bool {
		self.lockdown.load(Ordering::SeqCst)
	}

	/// Enter lockdown with an explicit reason.
	pub fn set_lockdown(&self, reason: LockdownReason) {
		self.lockdown.store(true, Ordering::SeqCst);
		*self.lockdown_reason.lock().unwrap() = Some(reason);
	}

	/// Clear lockdown only when the reason is `Heartbeat` or `None`.
	/// Reasons such as `PgUnreachable`, `IncompatibleSoftware`, and
	/// `NftablesFailure` require a manual service restart to clear.
	pub fn clear_lockdown_if_heartbeat(&self) {
		let mut guard = self.lockdown_reason.lock().unwrap();
		match *guard {
			None | Some(LockdownReason::Heartbeat) => {
				self.lockdown.store(false, Ordering::SeqCst);
				*guard = None;
			}
			_ => {}
		}
	}

	/// Returns true if the command is within the 100/min limit, false if it should be rejected.
	pub fn check_cmd_rate(&self) -> bool {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let mut guard = self.cmd_rate.lock().unwrap();
		let (window_start, count) = *guard;
		if now >= window_start + 60 {
			*guard = (now, 1);
			true
		} else if count < 100 {
			guard.1 += 1;
			true
		} else {
			false
		}
	}

	/// Record a rejected-rate-limit event. Returns count in current minute.
	pub fn record_rate_rejection(&self) -> u64 {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let window = self.cmd_rejected_window.load(Ordering::SeqCst);
		if now >= window + 60 {
			self.cmd_rejected_window.store(now, Ordering::SeqCst);
			self.cmd_rejected_count.store(1, Ordering::SeqCst);
			1
		} else {
			self.cmd_rejected_count.fetch_add(1, Ordering::SeqCst) + 1
		}
	}

	pub fn nft_wg_port(&self) -> u16 {
		self.nft_wg_port.load(Ordering::SeqCst) as u16
	}

	pub fn set_nft_wg_port(&self, port: u16) {
		self.nft_wg_port.store(port as u32, Ordering::SeqCst);
	}

	pub fn set_nft_checksum(&self, checksum: String) {
		*self.nft_checksum.lock().unwrap() = Some(checksum);
	}

	pub fn expected_nft_checksum(&self) -> Option<String> {
		self.nft_checksum.lock().unwrap().clone()
	}

	/// Store per-chain checksums: (base, global, local).
	pub fn set_nft_chain_checksums(
		&self,
		base: Option<String>,
		global: Option<String>,
		local: Option<String>,
	) {
		let mut g = self.nft_chain_checksums.lock().unwrap();
		g[0] = base;
		g[1] = global;
		g[2] = local;
	}

	/// Expected chain checksum by index: 0=base, 1=global, 2=local.
	pub fn expected_chain_checksum(&self, idx: usize) -> Option<String> {
		self.nft_chain_checksums.lock().unwrap()[idx].clone()
	}

	pub fn set_nft_last_ruleset(&self, ruleset: String) {
		*self.nft_last_ruleset.lock().unwrap() = Some(ruleset);
	}

	pub fn nft_last_ruleset(&self) -> Option<String> {
		self.nft_last_ruleset.lock().unwrap().clone()
	}

	pub fn set_nft_global_body(&self, body: String) {
		*self.nft_global_body.lock().unwrap() = body;
	}

	pub fn nft_global_body(&self) -> String {
		self.nft_global_body.lock().unwrap().clone()
	}

	pub fn set_nft_local_body(&self, body: String) {
		*self.nft_local_body.lock().unwrap() = body;
	}

	pub fn nft_local_body(&self) -> String {
		self.nft_local_body.lock().unwrap().clone()
	}

	pub fn set_nft_global_output_body(&self, body: String) {
		*self.nft_global_output_body.lock().unwrap() = body;
	}

	pub fn nft_global_output_body(&self) -> String {
		self.nft_global_output_body.lock().unwrap().clone()
	}

	pub fn set_nft_local_output_body(&self, body: String) {
		*self.nft_local_output_body.lock().unwrap() = body;
	}

	pub fn nft_local_output_body(&self) -> String {
		self.nft_local_output_body.lock().unwrap().clone()
	}
}

#[cfg(test)]
mod tests {
	//! Pure-logic tests for `AppState`. No DB, no I/O — every helper in this
	//! file operates on `Arc`s / `Atomic`s / `Mutex`es that are observable
	//! through the (already-public) fields.
	//!
	//! `make_state()` below mirrors the struct literal in `internal/main.rs`
	//! line-for-line — that's the contract the tests verify against. If the
	//! production construction drifts (e.g. `nft_wg_port` default changes,
	//! or a new field is added without a default), these tests should be
	//! updated in the same commit.

	use super::*;
	use crate::config::Config;
	use sqlx::postgres::PgPoolOptions;
	use std::sync::atomic::AtomicU32;
	use std::time::{Duration, Instant};
	use zeroize::Zeroizing;

	/// sqlx's lazy pool spins up background tasks on construction, so even
	/// non-async tests need a tokio runtime. `#[tokio::test]` matches the
	/// pattern in `internal/audit/mod.rs`.
	fn make_state() -> AppState {
		let cfg = Config {
			database_url: "postgres://test/test".into(),
			agent_id: uuid::Uuid::nil(),
			version: "test".into(),
			dashboard_verify_keys: Zeroizing::new(vec![[0u8; 32]]),
			internal_token: Zeroizing::new("test".into()),
			listen_addr: "127.0.0.1:0".into(),
			dashboard_url: None,
			sync_token: None,
			tls_cert_der: None,
			tls_key_der: None,
			tls_ca_cert_der: None,
			dashboard_port: None,
		};
		// Lazy pool — never connects until something queries it, which these
		// tests never do.
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

	fn now_secs() -> u64 {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs()
	}

	// --- construction ----------------------------------------------------

	#[tokio::test]
	async fn struct_literal_construction_populates_fields() {
		let state = make_state();
		assert!(!state.is_locked_down());
		assert_eq!(state.config.agent_id, uuid::Uuid::nil());
		assert_eq!(state.nft_wg_port(), 51820);
		assert!(state.expected_nft_checksum().is_none());
	}

	// --- clone semantics -------------------------------------------------

	/// The whole point of `Clone` here is that the inner `Arc`s are shared,
	/// not deep-cloned. If a future refactor swaps `Arc<Config>` for `Config`
	/// (or for a `Box<Config>`) the clone would deep-copy and these `ptr_eq`
	/// assertions would go red — exactly the failure mode we want to catch.
	#[tokio::test]
	async fn clone_shares_config_arc() {
		let state = make_state();
		let cloned = state.clone();
		assert!(Arc::ptr_eq(&state.config, &cloned.config));
	}

	/// Mutations through one handle must be visible through the other for
	/// every shared `Arc` field — lockdown flag and reason are the cleanest
	/// observable pair.
	#[tokio::test]
	async fn clone_shares_lockdown_state() {
		let state = make_state();
		let cloned = state.clone();
		state.set_lockdown(LockdownReason::Heartbeat);
		assert!(cloned.is_locked_down());
		assert_eq!(
			*cloned.lockdown_reason.lock().unwrap(),
			Some(LockdownReason::Heartbeat),
		);
	}

	// --- lockdown state machine -----------------------------------------

	#[tokio::test]
	async fn lockdown_initial_state_is_false() {
		let state = make_state();
		assert!(!state.is_locked_down());
	}

	#[tokio::test]
	async fn set_lockdown_sets_flag_and_reason() {
		let state = make_state();
		state.set_lockdown(LockdownReason::PgUnreachable);
		assert!(state.is_locked_down());
		assert_eq!(
			*state.lockdown_reason.lock().unwrap(),
			Some(LockdownReason::PgUnreachable),
		);
	}

	/// `Heartbeat` is the only non-`None` reason that `clear_lockdown_if_heartbeat`
	/// will release. Removing the `Heartbeat` arm from the `match` makes this
	/// test go red.
	#[tokio::test]
	async fn clear_lockdown_with_heartbeat_reason_succeeds() {
		let state = make_state();
		state.set_lockdown(LockdownReason::Heartbeat);
		state.clear_lockdown_if_heartbeat();
		assert!(!state.is_locked_down());
		assert!(state.lockdown_reason.lock().unwrap().is_none());
	}

	/// `PgUnreachable` must require a manual service restart to clear —
	/// clearing it on a heartbeat ACK is the silent-failure mode that would
	/// re-open traffic against an unreachable database. The test stays green
	/// only as long as the `_ => {}` arm of `clear_lockdown_if_heartbeat`
	/// preserves the lockdown for these reasons.
	#[tokio::test]
	async fn clear_lockdown_with_pg_unreachable_is_no_op() {
		let state = make_state();
		state.set_lockdown(LockdownReason::PgUnreachable);
		state.clear_lockdown_if_heartbeat();
		assert!(
			state.is_locked_down(),
			"PgUnreachable lockdown must require a restart to clear"
		);
		assert_eq!(
			*state.lockdown_reason.lock().unwrap(),
			Some(LockdownReason::PgUnreachable),
		);
	}

	#[tokio::test]
	async fn clear_lockdown_with_incompatible_software_is_no_op() {
		let state = make_state();
		state.set_lockdown(LockdownReason::IncompatibleSoftware);
		state.clear_lockdown_if_heartbeat();
		assert!(state.is_locked_down());
		assert_eq!(
			*state.lockdown_reason.lock().unwrap(),
			Some(LockdownReason::IncompatibleSoftware),
		);
	}

	#[tokio::test]
	async fn clear_lockdown_with_nftables_failure_is_no_op() {
		let state = make_state();
		state.set_lockdown(LockdownReason::NftablesFailure);
		state.clear_lockdown_if_heartbeat();
		assert!(state.is_locked_down());
		assert_eq!(
			*state.lockdown_reason.lock().unwrap(),
			Some(LockdownReason::NftablesFailure),
		);
	}

	/// Calling `clear_lockdown_if_heartbeat` on a fresh, never-locked-down
	/// state must be a no-op (the `None` arm). Otherwise every heartbeat ACK
	/// would race to clear a lockdown that some other path had just raised.
	#[tokio::test]
	async fn clear_lockdown_with_no_reason_is_no_op() {
		let state = make_state();
		state.clear_lockdown_if_heartbeat();
		assert!(!state.is_locked_down());
		assert!(state.lockdown_reason.lock().unwrap().is_none());
	}

	// --- default values --------------------------------------------------

	/// Every default mirrored from `internal/main.rs:229-247`. Each line is
	/// a contract: if `main.rs` changes the default for one of these fields,
	/// this test must be updated in lockstep — otherwise the construction
	/// path diverges silently.
	#[tokio::test]
	async fn defaults_match_construction_contract() {
		let state = make_state();
		// nftables
		assert_eq!(state.nft_wg_port(), 51820);
		assert!(state.expected_nft_checksum().is_none());
		assert_eq!(
			*state.nft_chain_checksums.lock().unwrap(),
			[None, None, None]
		);
		assert!(state.nft_last_ruleset().is_none());
		assert_eq!(state.nft_global_body(), "");
		assert_eq!(state.nft_local_body(), "");
		assert_eq!(state.nft_global_output_body(), "");
		assert_eq!(state.nft_local_output_body(), "");
		// lockdown
		assert!(!state.is_locked_down());
		assert!(state.lockdown_reason.lock().unwrap().is_none());
		// command rate
		assert_eq!(*state.cmd_rate.lock().unwrap(), (0, 0));
		assert_eq!(state.cmd_rejected_count.load(Ordering::SeqCst), 0);
		assert_eq!(state.cmd_rejected_window.load(Ordering::SeqCst), 0);
		assert_eq!(state.last_dashboard_contact.load(Ordering::SeqCst), 0);
		// last_heartbeat: just set to `Instant::now()`, so elapsed must be tiny
		assert!(state.last_heartbeat.lock().unwrap().elapsed() < Duration::from_secs(60));
	}

	// --- nft helpers (round-trip) ----------------------------------------

	#[tokio::test]
	async fn nft_wg_port_round_trip() {
		let state = make_state();
		state.set_nft_wg_port(12345);
		assert_eq!(state.nft_wg_port(), 12345);
	}

	#[tokio::test]
	async fn nft_checksum_round_trip() {
		let state = make_state();
		assert!(state.expected_nft_checksum().is_none());
		state.set_nft_checksum("abc123".into());
		assert_eq!(state.expected_nft_checksum().as_deref(), Some("abc123"));
	}

	/// The index contract — 0=base, 1=global, 2=local — is load-bearing for
	/// divergence attribution in `nftables::divergence.rs`. Swapping any
	/// index would route "base" checksums into the "global" slot and the
	/// divergence report would mis-attribute.
	#[tokio::test]
	async fn nft_chain_checksums_indices_zero_through_two() {
		let state = make_state();
		assert_eq!(state.expected_chain_checksum(0), None);
		assert_eq!(state.expected_chain_checksum(1), None);
		assert_eq!(state.expected_chain_checksum(2), None);
		state.set_nft_chain_checksums(
			Some("base".into()),
			Some("global".into()),
			Some("local".into()),
		);
		assert_eq!(state.expected_chain_checksum(0).as_deref(), Some("base"));
		assert_eq!(state.expected_chain_checksum(1).as_deref(), Some("global"));
		assert_eq!(state.expected_chain_checksum(2).as_deref(), Some("local"));
	}

	#[tokio::test]
	async fn nft_last_ruleset_round_trip() {
		let state = make_state();
		assert!(state.nft_last_ruleset().is_none());
		state.set_nft_last_ruleset("table inet helmly {}".into());
		assert_eq!(
			state.nft_last_ruleset().as_deref(),
			Some("table inet helmly {}")
		);
	}

	#[tokio::test]
	async fn nft_global_local_bodies_round_trip() {
		let state = make_state();
		// defaults are empty strings, not None — verify both
		assert_eq!(state.nft_global_body(), "");
		assert_eq!(state.nft_local_body(), "");
		state.set_nft_global_body("chain helmly-global {}".into());
		state.set_nft_local_body("chain helmly-local {}".into());
		assert_eq!(state.nft_global_body(), "chain helmly-global {}");
		assert_eq!(state.nft_local_body(), "chain helmly-local {}");
	}

	#[tokio::test]
	async fn nft_global_output_body_round_trip() {
		let state = make_state();
		assert_eq!(state.nft_global_output_body(), "");
		state.set_nft_global_output_body("output body".into());
		assert_eq!(state.nft_global_output_body(), "output body");
	}

	#[tokio::test]
	async fn nft_local_output_body_round_trip() {
		let state = make_state();
		assert_eq!(state.nft_local_output_body(), "");
		state.set_nft_local_output_body("local output body".into());
		assert_eq!(state.nft_local_output_body(), "local output body");
	}

	// --- command-rate limiter -------------------------------------------

	/// A fresh state has `window_start = 0`, so `now >= 0 + 60` is always
	/// true and the first call resets the window to `(now, 1)` and returns
	/// true. This exercises the window-expired reset path.
	#[tokio::test]
	async fn cmd_rate_resets_window_on_expired() {
		let state = make_state();
		assert!(state.check_cmd_rate());
		assert_eq!(state.cmd_rate.lock().unwrap().1, 1);
	}

	/// Pin `window_start` an hour into the future so the window cannot
	/// expire mid-loop, then verify the documented "100/min" budget:
	/// 100 calls succeed, the 101st is rejected. Lowering the limit to 99
	/// makes iteration 100 fail; raising it to 101 makes the 101st succeed.
	/// Either change breaks this test — that's the point.
	#[tokio::test]
	async fn cmd_rate_rejects_after_one_hundred_in_window() {
		let state = make_state();
		*state.cmd_rate.lock().unwrap() = (now_secs() + 3600, 0);
		for i in 1..=100 {
			assert!(
				state.check_cmd_rate(),
				"call #{i} within the window must succeed"
			);
		}
		assert!(
			!state.check_cmd_rate(),
			"101st call within the window must be rejected"
		);
	}

	/// Once the window rolls over, the counter must restart — otherwise a
	/// brief burst would lock the agent out for the rest of the day.
	#[tokio::test]
	async fn cmd_rate_resets_when_window_rolls_over() {
		let state = make_state();
		// Saturate the budget under a pinned window.
		*state.cmd_rate.lock().unwrap() = (now_secs() + 3600, 100);
		assert!(!state.check_cmd_rate());

		// Rewind `window_start` so the next call sees the window as expired.
		*state.cmd_rate.lock().unwrap() = (now_secs().saturating_sub(120), 100);
		assert!(
			state.check_cmd_rate(),
			"after the window elapses the limiter must accept again"
		);
		assert_eq!(state.cmd_rate.lock().unwrap().1, 1);
	}

	// --- rejection-rate counter -----------------------------------------

	#[tokio::test]
	async fn record_rate_rejection_first_call_returns_one() {
		let state = make_state();
		assert_eq!(state.record_rate_rejection(), 1);
		assert_eq!(state.cmd_rejected_count.load(Ordering::SeqCst), 1);
	}

	#[tokio::test]
	async fn record_rate_rejection_increments_within_window() {
		let state = make_state();
		assert_eq!(state.record_rate_rejection(), 1);
		assert_eq!(state.record_rate_rejection(), 2);
		assert_eq!(state.record_rate_rejection(), 3);
		assert_eq!(state.cmd_rejected_count.load(Ordering::SeqCst), 3);
	}

	/// The alert threshold (`cmd_rejected_count`) must restart at 1 after a
	/// minute boundary — otherwise a noisy neighbor would permanently trip
	/// the dashboard alert.
	#[tokio::test]
	async fn record_rate_rejection_resets_after_window_elapses() {
		let state = make_state();
		for _ in 0..5 {
			state.record_rate_rejection();
		}
		// Rewind the window so the next call sees it as expired.
		state
			.cmd_rejected_window
			.store(now_secs().saturating_sub(120), Ordering::SeqCst);
		assert_eq!(
			state.record_rate_rejection(),
			1,
			"after the window elapses the counter must restart at 1"
		);
	}
}
