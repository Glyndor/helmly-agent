use super::*;
use crate::auth::{PermissionLevel, VerifiedCommand};
use crate::config::Config;
use crate::state::AppState;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::{
	atomic::{AtomicBool, AtomicU32, AtomicU64},
	Arc, Mutex,
};
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---- validate_id (existing happy-path coverage) ----

#[test]
fn validate_id_accepts_valid() {
	assert!(validate_id("test-org-001", "k").is_ok());
	assert!(validate_id("my_project", "k").is_ok());
	assert!(validate_id("abc123", "k").is_ok());
	assert!(validate_id("a", "k").is_ok());
	assert!(validate_id(&"x".repeat(128), "k").is_ok());
}

#[test]
fn validate_id_rejects_path_traversal() {
	assert!(validate_id("../../etc/passwd", "k").is_err());
	assert!(validate_id("../secret", "k").is_err());
	assert!(validate_id("org/subdir", "k").is_err());
	assert!(validate_id("org\\evil", "k").is_err());
}

#[test]
fn validate_id_rejects_shell_metacharacters() {
	assert!(validate_id("org; rm -rf /", "k").is_err());
	assert!(validate_id("org$(id)", "k").is_err());
	assert!(validate_id("org`id`", "k").is_err());
	assert!(validate_id("org | cat", "k").is_err());
	assert!(validate_id("org\nrm", "k").is_err());
	assert!(validate_id("org\x00evil", "k").is_err());
}

#[test]
fn validate_id_rejects_empty_and_too_long() {
	assert!(validate_id("", "k").is_err());
	assert!(validate_id(&"x".repeat(129), "k").is_err());
}

// ---- Test helpers ---------------------------------------------------
//
// Mirrors `internal/handlers/system.rs::tests` and
// `internal/state.rs::tests` line-for-line. `connect_lazy` never
// opens a socket until a query runs, so tests that fail before the
// DB call (permission gates, missing-field checks, validate_compose
// rejections) don't need a real DB.
//
// If `state.rs` adds a field, every `make_state` call here must
// change in lockstep — same contract the system.rs tests enforce.

fn make_db() -> sqlx::PgPool {
	PgPoolOptions::new()
		.connect_lazy("postgres://test:test@127.0.0.1/test")
		.expect("lazy pool")
}

fn make_config() -> Config {
	Config {
		database_url: "postgres://test/test".into(),
		agent_id: Uuid::nil(),
		version: "test".into(),
		dashboard_verify_keys: Zeroizing::new(Vec::new()),
		internal_token: Zeroizing::new("test".into()),
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
	AppState {
		db: make_db(),
		config: Arc::new(make_config()),
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

fn make_cmd(permission: PermissionLevel, command: Value) -> VerifiedCommand {
	VerifiedCommand {
		user_id: Uuid::nil(),
		organization_id: None,
		permission,
		command,
	}
}

mod permission_gates;
mod required_fields;
