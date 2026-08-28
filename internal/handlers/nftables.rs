use crate::{auth::PermissionLevel, error::AgentError, nftables, state::AppState};

use serde_json::{json, Value};

pub async fn handle_nftables_apply(
	state: &AppState,
	cmd: &crate::auth::VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission == PermissionLevel::Read {
		return Err(AgentError::Forbidden(
			"nftables.apply requires write permission",
		));
	}

	// Chain-specific update
	if let Some(chain) = cmd.command.get("chain").and_then(|v| v.as_str()) {
		let rules = cmd
			.command
			.get("rules")
			.and_then(|v| v.as_str())
			.unwrap_or("")
			.to_string();

		match chain {
            "helmly-global" => state.set_nft_global_body(rules.clone()),
            "helmly-local" => state.set_nft_local_body(rules.clone()),
            "helmly-global-output" => state.set_nft_global_output_body(rules.clone()),
            "helmly-local-output" => state.set_nft_local_output_body(rules.clone()),
            _ => {
                return Err(AgentError::BadRequest(
                    "unknown chain: must be helmly-global, helmly-local, helmly-global-output, or helmly-local-output",
                ))
            }
        }

		let result = apply_current_ruleset(state)?;
		let wg = state.nft_wg_port() as i32;
		let _ = sqlx::query!(
            "UPDATE nftables_state SET body = $1, wg_port = $2, updated_at = NOW() WHERE chain = $3",
            rules, wg, chain
        )
        .execute(&state.db)
        .await;
		return Ok(result);
	}

	// Full apply: { wireguard_port: 51820 }
	let wg_port = cmd
		.command
		.get("wireguard_port")
		.and_then(|v| v.as_u64())
		.unwrap_or(51820) as u16;

	state.set_nft_wg_port(wg_port);

	let result = apply_current_ruleset(state)?;
	let wg = wg_port as i32;
	let _ = sqlx::query!(
		"UPDATE nftables_state SET wg_port = $1, updated_at = NOW()",
		wg
	)
	.execute(&state.db)
	.await;
	Ok(result)
}

fn apply_current_ruleset(state: &AppState) -> std::result::Result<Value, AgentError> {
	let ruleset = nftables::Ruleset {
		wireguard_port: state.nft_wg_port(),
		dashboard_port: state.config.dashboard_port,
		dashboard_wg_ip: crate::nftables::extract_url_host(
			state.config.dashboard_url.as_deref().unwrap_or(""),
		),
		org_networks: vec![],
		global_body: state.nft_global_body(),
		local_body: state.nft_local_body(),
		global_output_body: state.nft_global_output_body(),
		local_output_body: state.nft_local_output_body(),
	};

	let rendered = nftables::apply(&ruleset)?;
	let checksum = nftables::current_checksum()?;
	state.set_nft_checksum(checksum);
	state.set_nft_chain_checksums(
		nftables::chain_checksum("helmly-base").ok(),
		nftables::chain_checksum("helmly-global").ok(),
		nftables::chain_checksum("helmly-local").ok(),
	);
	state.set_nft_last_ruleset(rendered);

	Ok(json!({ "ok": true }))
}

pub fn handle_nftables_restore(
	state: &AppState,
	cmd: &crate::auth::VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission == PermissionLevel::Read {
		return Err(AgentError::Forbidden(
			"nftables.restore requires write permission",
		));
	}

	let ruleset = state
		.nft_last_ruleset()
		.ok_or_else(|| AgentError::BadRequest("no ruleset has been applied yet"))?;

	nftables::apply_raw(&ruleset)?;

	let checksum = nftables::current_checksum()?;
	state.set_nft_checksum(checksum);
	state.set_nft_chain_checksums(
		nftables::chain_checksum("helmly-base").ok(),
		nftables::chain_checksum("helmly-global").ok(),
		nftables::chain_checksum("helmly-local").ok(),
	);

	Ok(json!({ "ok": true, "action": "restored" }))
}

pub fn handle_nftables_accept(
	state: &AppState,
	cmd: &crate::auth::VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission == PermissionLevel::Read {
		return Err(AgentError::Forbidden(
			"nftables.accept requires write permission",
		));
	}

	let current = nftables::current_checksum()?;
	state.set_nft_checksum(current.clone());
	state.set_nft_last_ruleset(String::new());

	Ok(json!({ "ok": true, "action": "accepted", "checksum": &current[..16] }))
}

#[cfg(test)]
mod tests {
	//! Permission gates, field validation, and routing for the three
	//! nftables handlers. The handlers spawn `nft` for the happy path,
	//! which fails without root — those paths are exercised as
	//! "got past the gate, apply failed" cases, asserting the
	//! observable side-effects (state mutation, error type) on the
	//! way out. Audit logging is the dispatcher's responsibility
	//! (`system::run_verified_command` → `audit::append`); these
	//! handlers do not call `audit::append` themselves.

	use super::{handle_nftables_accept, handle_nftables_apply, handle_nftables_restore};
	use crate::auth::{PermissionLevel, VerifiedCommand};
	use crate::config::Config;
	use crate::error::AgentError;
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

	// =================================================================
	// Permission gates — `nftables.{apply,restore,accept}` each spawn
	// `nft -f -` (apply/restore) or `nft list` (accept) under Write,
	// and mutate the agent's nftables ruleset. Read-only dashboard
	// roles must not reach any of them. Each test asserts the exact
	// `Forbidden(_)` message so a missing-gate mutation (which would
	// proceed to nft and fail with `Internal` from the lazy-pool
	// `nftables::apply`/`current_checksum` calls) goes red.
	// =================================================================

	/// `nftables.apply` overwrites the helmly-agent table with a
	/// dashboard-pushed ruleset. Read permission must be rejected
	/// before any state mutation or `nft` invocation.
	#[tokio::test]
	async fn nftables_apply_read_permission_is_forbidden() {
		let state = make_state();
		// No `chain` field — full-apply path. The gate must fire
		// before the handler reaches `cmd.command.get("wireguard_port")`
		// or `apply_current_ruleset`.
		let cmd = make_cmd(PermissionLevel::Read, json!({ "type": "nftables.apply" }));

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Forbidden(msg)) => assert_eq!(
				msg, "nftables.apply requires write permission",
				"Forbidden message must match the gate's exact text"
			),
			other => panic!(
				"expected Forbidden(\"nftables.apply requires write permission\"); got {other:?}"
			),
		}
	}

	/// `nftables.restore` re-applies the last ruleset verbatim.
	/// Same gate, different command — tested independently because a
	/// future refactor could split the gate across handlers or lift
	/// one of them by accident.
	#[tokio::test]
	async fn nftables_restore_read_permission_is_forbidden() {
		let state = make_state();
		let cmd = make_cmd(PermissionLevel::Read, json!({ "type": "nftables.restore" }));

		match handle_nftables_restore(&state, &cmd) {
			Err(AgentError::Forbidden(msg)) => assert_eq!(
				msg, "nftables.restore requires write permission",
				"Forbidden message must match the gate's exact text"
			),
			other => panic!(
				"expected Forbidden(\"nftables.restore requires write permission\"); got {other:?}"
			),
		}
	}

	/// `nftables.accept` empties the last-rendered ruleset (operator
	/// ACKs the live ruleset as the new baseline). The gate must
	/// fire before `current_checksum()` runs `nft list`.
	#[tokio::test]
	async fn nftables_accept_read_permission_is_forbidden() {
		let state = make_state();
		let cmd = make_cmd(PermissionLevel::Read, json!({ "type": "nftables.accept" }));

		match handle_nftables_accept(&state, &cmd) {
			Err(AgentError::Forbidden(msg)) => assert_eq!(
				msg, "nftables.accept requires write permission",
				"Forbidden message must match the gate's exact text"
			),
			other => panic!(
				"expected Forbidden(\"nftables.accept requires write permission\"); got {other:?}"
			),
		}
	}

	// =================================================================
	// Field validation — `apply` rejects unknown chain names; `restore`
	// requires a previously-applied ruleset to exist in state. These
	// are the only input-shape rejections the handlers perform; rules
	// body content is delegated to `nftables::apply` (no parse-check
	// at the handler boundary).
	// =================================================================

	/// `apply` with an unknown chain name must reject with
	/// `BadRequest("unknown chain: must be helmly-global, ...")`.
	/// Asserting the exact message (rather than just `BadRequest`)
	/// ensures an unrelated missing-field rejection cannot satisfy
	/// the test, per `standards/testing/index.md` ("a rejection test
	/// asserts *which* rejection").
	#[tokio::test]
	async fn nftables_apply_unknown_chain_returns_bad_request() {
		let state = make_state();
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"chain": "helmly-evil",
				"rules": "tcp dport 22 accept",
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::BadRequest(msg)) => assert!(
				msg.contains("unknown chain"),
				"unknown-chain rejection must surface 'unknown chain'; got: {msg}"
			),
			other => panic!("expected BadRequest(\"unknown chain: ...\"); got {other:?}"),
		}
	}

	/// `restore` without a previously-applied ruleset must reject
	/// with `BadRequest("no ruleset has been applied yet")`. There
	/// is nothing to restore from — sending the handler straight to
	/// `apply_raw` would fail later, but the explicit precondition
	/// error makes the cause obvious to the dashboard operator.
	#[tokio::test]
	async fn nftables_restore_without_last_ruleset_returns_bad_request() {
		let state = make_state();
		// `make_state()` initializes `nft_last_ruleset` to None.
		assert!(state.nft_last_ruleset().is_none());

		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({ "type": "nftables.restore" }),
		);

		match handle_nftables_restore(&state, &cmd) {
			Err(AgentError::BadRequest(msg)) => assert_eq!(
				msg, "no ruleset has been applied yet",
				"missing-ruleset rejection must surface the exact message"
			),
			other => {
				panic!("expected BadRequest(\"no ruleset has been applied yet\"); got {other:?}")
			}
		}
	}

	// =================================================================
	// Chain-routing side effects.
	//
	// `apply` matches on the `chain` field and routes to one of four
	// `set_nft_*_body` setters. The chain-set happens BEFORE the
	// `apply_current_ruleset(state)?` call, so even when `nft` fails
	// (no root in this test env → `Internal`) the body mutation is
	// observable through state. Each test asserts both the error
	// type (so we know the handler reached `apply_current_ruleset`)
	// and the body content (so we know the matching arm ran). If a
	// future refactor moves the body-set after the apply call, or
	// routes the wrong chain to the wrong setter, the body
	// assertion goes red.
	// =================================================================

	#[tokio::test]
	async fn nftables_apply_chain_match_routes_to_global_body() {
		let state = make_state();
		let rules = "        tcp dport 443 accept";
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"chain": "helmly-global",
				"rules": rules,
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {} // expected: nft unavailable
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_global_body(),
			rules,
			"helmly-global chain must write nft_global_body"
		);
		assert_eq!(
			state.nft_local_body(),
			"",
			"helmly-global chain must not touch nft_local_body"
		);
	}

	#[tokio::test]
	async fn nftables_apply_chain_match_routes_to_local_body() {
		let state = make_state();
		let rules = "        tcp dport 8080 accept";
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"chain": "helmly-local",
				"rules": rules,
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {}
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_local_body(),
			rules,
			"helmly-local chain must write nft_local_body"
		);
		assert_eq!(
			state.nft_global_body(),
			"",
			"helmly-local chain must not touch nft_global_body"
		);
	}

	#[tokio::test]
	async fn nftables_apply_chain_match_routes_to_global_output_body() {
		let state = make_state();
		let rules = "        tcp dport 53 accept";
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"chain": "helmly-global-output",
				"rules": rules,
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {}
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_global_output_body(),
			rules,
			"helmly-global-output chain must write nft_global_output_body"
		);
	}

	#[tokio::test]
	async fn nftables_apply_chain_match_routes_to_local_output_body() {
		let state = make_state();
		let rules = "        udp dport 53 accept";
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"chain": "helmly-local-output",
				"rules": rules,
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {}
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_local_output_body(),
			rules,
			"helmly-local-output chain must write nft_local_output_body"
		);
	}

	// =================================================================
	// Full-apply WireGuard port handling — the no-chain path stores
	// `wireguard_port` in state and proceeds to a full ruleset
	// apply. The default (when the field is absent) is 51820.
	// =================================================================

	/// With `wireguard_port` absent, the handler must fall back to
	/// 51820 — pin the initial state to a non-default value so a
	/// no-op mutation can't satisfy the assertion.
	#[tokio::test]
	async fn nftables_apply_full_apply_defaults_wireguard_port_to_51820() {
		let state = make_state();
		state.set_nft_wg_port(9999);

		let cmd = make_cmd(PermissionLevel::Write, json!({ "type": "nftables.apply" }));

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {}
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_wg_port(),
			51820,
			"absent wireguard_port must default to 51820"
		);
	}

	/// With `wireguard_port` present, the handler must store the
	/// operator-supplied value. Removing the `as_u64()` cast (or
	/// the `set_nft_wg_port` call) makes this test go red.
	#[tokio::test]
	async fn nftables_apply_full_apply_uses_custom_wireguard_port() {
		let state = make_state();
		let cmd = make_cmd(
			PermissionLevel::Write,
			json!({
				"type": "nftables.apply",
				"wireguard_port": 12345,
			}),
		);

		match handle_nftables_apply(&state, &cmd).await {
			Err(AgentError::Internal(_)) => {}
			other => panic!("expected Internal from apply_current_ruleset; got {other:?}"),
		}
		assert_eq!(
			state.nft_wg_port(),
			12345,
			"custom wireguard_port must be stored verbatim"
		);
	}

	// =================================================================
	// `accept` — passing the gate but not `nft list`.
	//
	// `handle_nftables_accept` immediately calls
	// `nftables::current_checksum()` which spawns `nft list`. With no
	// root, this returns `Internal`. The test verifies the gate is
	// past (Read is rejected upstream; here we use Write) and that
	// the handler attempts the checksum — i.e. a regression that
	// short-circuited before `current_checksum()` would surface as
	// a different error type (e.g. `Ok` with stale data) or as
	// pre-mutated state we can observe.
	// =================================================================

	#[tokio::test]
	async fn nftables_accept_with_write_permission_attempts_checksum() {
		let state = make_state();
		// Seed a non-empty last ruleset so we can observe whether
		// `set_nft_last_ruleset(String::new())` would have run had
		// the checksum succeeded. Without root, the handler errors
		// out at `current_checksum()?` before reaching that line.
		state.set_nft_last_ruleset("table inet helmly-agent {}".into());

		let cmd = make_cmd(PermissionLevel::Write, json!({ "type": "nftables.accept" }));

		match handle_nftables_accept(&state, &cmd) {
			Err(AgentError::Internal(_)) => {} // expected: nft unavailable
			other => panic!("expected Internal from current_checksum; got {other:?}"),
		}
		// Last ruleset must NOT be cleared — the handler errors out
		// before `set_nft_last_ruleset(String::new())`. A regression
		// that cleared state before the checksum would empty this.
		assert_eq!(
			state.nft_last_ruleset().as_deref(),
			Some("table inet helmly-agent {}"),
			"last ruleset must not be cleared when checksum fails"
		);
	}
}
