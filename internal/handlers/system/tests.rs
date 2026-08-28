use super::{
    command_dispatch, handle_cert_update, handle_dashboard_migrate, handle_db_rotate_password,
    handle_update_self, handle_vps_reboot, validate_migrate_target,
};
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
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

// ---- Test helpers ---------------------------------------------------
//
// `command_dispatch` is reachable from the same module without going
// through `verify_command` (which needs a real DB for nonce dedup) or
// `audit::append` (which needs a real DB to write to), so the
// permission-gate tests can use a lazy pool that never connects.
// Mirrors the construction contract in `internal/state.rs` line for
// line — if `main.rs:229-247` changes, this helper must too.

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
        // Empty keyring — `verify_command` would refuse, but we go
        // through `command_dispatch` directly so it never sees this.
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

/// C5: a target_url pointing at the configured dashboard must pass.
/// We use `example.com` (RFC 2606 reserved, never resolves to a private
/// IP in practice) as the dashboard; the function only does DNS for
/// `target_url` against the same host, so this exercises the parse +
/// host-compare + port-compare path. The DNS lookup at the end of
/// `validate_migrate_target` does go out — but `example.com` resolves
/// to public IPs that pass the SSRF check, so the test stays green.
#[tokio::test]
async fn migrate_target_matches_dashboard_passes() {
    // example.com — 93.184.216.34 (public). DNS may fail in CI without
    // network; skip if so. The parse + host-compare + port-compare are
    // deterministic, so we exercise them via the host-mismatch test.
    let r = validate_migrate_target(
        "https://example.com:8443/migration/agent-confirm",
        "https://example.com:8443",
    )
    .await;
    // We don't assert success strictly — DNS may fail offline — but
    // the error must NOT be "host mismatch" or "port mismatch" or
    // "scheme".
    if let Err(e) = r {
        assert!(
            !e.contains("does not match")
                && !e.contains("scheme")
                && !e.contains("no host")
                && !e.contains("no port"),
            "expected parse+host+port to match; got: {e}"
        );
    }
}

/// C5: a target_url pointing at a different host fails — the regression
/// test for the original bug (`format!("{target_url}/...")` accepted
/// anything). Reverting the host-compare arm in `validate_migrate_target`
/// makes this test go red.
#[tokio::test]
async fn migrate_target_host_mismatch_returns_err() {
    let r = validate_migrate_target(
        "https://attacker.example/migration/agent-confirm",
        "https://dashboard.example",
    )
    .await;
    let err = r.expect_err("host mismatch must error; got Ok");
    assert!(
        err.contains("does not match"),
        "expected host-mismatch error; got: {err}"
    );
}

/// C5: a target_url with a different port fails.
#[tokio::test]
async fn migrate_target_port_mismatch_returns_err() {
    let r = validate_migrate_target(
        "https://dashboard.example:9999/migration/agent-confirm",
        "https://dashboard.example:8443",
    )
    .await;
    let err = r.expect_err("port mismatch must error; got Ok");
    assert!(
        err.contains("does not match"),
        "expected port-mismatch error; got: {err}"
    );
}

/// C5: a target_url with a non-http(s) scheme fails.
#[tokio::test]
async fn migrate_target_bad_scheme_returns_err() {
    let r = validate_migrate_target("file:///etc/passwd", "https://dashboard.example").await;
    let err = r.expect_err("file:// must error; got Ok");
    assert!(
        err.contains("scheme"),
        "expected scheme-rejection error; got: {err}"
    );
}

/// C5: a malformed URL fails parsing.
#[tokio::test]
async fn migrate_target_malformed_url_returns_err() {
    let r = validate_migrate_target("not a url", "https://dashboard.example").await;
    let err = r.expect_err("malformed URL must error; got Ok");
    assert!(
        err.contains("not a valid URL"),
        "expected parse-failure error; got: {err}"
    );
}

// =====================================================================
// Command dispatch routing — `command_dispatch` (private).
//
// `run_verified_command` wraps `command_dispatch` with `verify_command`
// (needs a real DB for nonce dedup) and `audit::append` (needs a real
// DB to write to), so we exercise the dispatch surface directly via
// `command_dispatch`, which is reachable from the same module and
// takes the same `VerifiedCommand` shape that the post-verify path
// produces.
// =====================================================================

/// `agent.heartbeat_ack` is the one route without destructive
/// side-effects — it touches `last_heartbeat` and returns
/// `{"ok": true}`. Verifies routing without touching the network,
/// the DB, or spawning any subprocess.
#[tokio::test]
async fn command_dispatch_routes_heartbeat_ack() {
    let state = make_state();
    let before = *state.last_heartbeat.lock().unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;

    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({ "type": "agent.heartbeat_ack" }),
    );

    let r = command_dispatch(&state, &cmd).await;
    let v = r.expect("heartbeat_ack must Ok");
    assert_eq!(v, json!({ "ok": true }));

    let after = *state.last_heartbeat.lock().unwrap();
    assert!(
        after > before,
        "heartbeat_ack must update last_heartbeat: before={before:?} after={after:?}"
    );
}

/// Unknown command types must surface as
/// `BadRequest("unknown command type")` — the catch-all arm of
/// `command_dispatch`. Asserts the exact message so an unrelated
/// `Err` (e.g. from `audit::append` reaching a real DB) cannot
/// silently satisfy the test, per
/// `standards/testing/index.md` ("a rejection test asserts *which*
/// rejection").
#[tokio::test]
async fn command_dispatch_unknown_type_returns_bad_request_with_message() {
    let state = make_state();
    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({ "type": "totally.unknown.command" }),
    );

    match command_dispatch(&state, &cmd).await {
        Err(AgentError::BadRequest(msg)) => assert_eq!(
            msg, "unknown command type",
            "unknown-type must surface the documented message"
        ),
        other => panic!("expected BadRequest(\"unknown command type\"); got {other:?}"),
    }
}

// =====================================================================
// Handler permission gates.
//
// Each of these is a destructive command — rotate the agent's X.509
// identity, rotate the agent's Postgres password, reboot the agent
// host, or download and run a new binary. The `Read`-only dashboard
// role must not be able to invoke any of them; every test below
// asserts the specific `Forbidden(_)` message so the test goes red
// both when the gate is removed AND when it's swapped for an
// unrelated rejection.
// =====================================================================

/// `dashboard.migrate` exfiltrates the long-lived `sync_token` to
/// `target_url`. The Write gate must fire before any URL parsing or
/// DNS lookup. Fixture omits `target_url` on purpose so the test
/// would fail with `BadRequest("target_url")` if the gate were
/// removed — the only way to reach that line is to bypass the gate.
#[tokio::test]
async fn dashboard_migrate_read_permission_is_forbidden() {
    let state = make_state();
    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({ "type": "dashboard.migrate" }),
    );

    match handle_dashboard_migrate(&state, &cmd).await {
        Err(AgentError::Forbidden(msg)) => assert_eq!(
            msg, "dashboard.migrate requires write permission",
            "Forbidden message must match the gate's exact text"
        ),
        other => panic!(
            "expected Forbidden(\"dashboard.migrate requires write permission\"); got {other:?}"
        ),
    }
}

/// `cert.update` rotates the agent's X.509 identity used for mTLS
/// to the dashboard. A compromised dashboard signing key could use
/// this to mint a cert under the agent's identity — the Write gate
/// keeps Read-only roles out. Fixture provides both required fields
/// so a missing-gate mutation surfaces as `Internal` from
/// `cert::load_ca_public_key()`, not a confusing `BadRequest`.
#[tokio::test]
async fn cert_update_read_permission_is_forbidden() {
    let state = make_state();
    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({
            "type": "cert.update",
            "payload": "ignored",
            "signature": "ignored",
        }),
    );

    match handle_cert_update(&state, &cmd).await {
        Err(AgentError::Forbidden(msg)) => assert_eq!(
            msg, "cert.update requires write permission",
            "Forbidden message must match the gate's exact text"
        ),
        other => {
            panic!("expected Forbidden(\"cert.update requires write permission\"); got {other:?}")
        }
    }
}

/// `cert.update` with Write permission but missing `payload` must
/// reject before any filesystem write or CA-key load — otherwise an
/// attacker who can sign Write-level commands could push partial
/// updates. Asserts the specific `BadRequest("missing payload")`
/// so an unrelated `BadRequest("missing signature")` from the next
/// check can't mask the missing-payload case.
#[tokio::test]
async fn cert_update_missing_payload_returns_bad_request() {
    let state = make_state();
    let cmd = make_cmd(
        PermissionLevel::Write,
        json!({
            "type": "cert.update",
            "signature": "present",
        }),
    );

    match handle_cert_update(&state, &cmd).await {
        Err(AgentError::BadRequest(msg)) => assert_eq!(
            msg, "missing payload",
            "missing-payload rejection must name the missing field"
        ),
        other => panic!("expected BadRequest(\"missing payload\"); got {other:?}"),
    }
}

/// `db.rotate_password` issues `ALTER USER helmly_agent_app` — the
/// gateway credential to the agent's own Postgres database. Read-only
/// dashboard roles must not reach this. Asserts the exact message
/// so a missing-gate mutation (which would surface as an
/// `Internal` from the lazy-pool `ALTER USER` attempt) goes red.
#[tokio::test]
async fn db_rotate_password_read_permission_is_forbidden() {
    let state = make_state();
    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({ "type": "db.rotate_password" }),
    );

    match handle_db_rotate_password(&state, &cmd).await {
        Err(AgentError::Forbidden(msg)) => assert_eq!(
            msg, "db.rotate_password requires write permission",
            "Forbidden message must match the gate's exact text"
        ),
        other => panic!(
            "expected Forbidden(\"db.rotate_password requires write permission\"); got {other:?}"
        ),
    }
}

/// `vps.reboot` spawns `systemctl reboot` on the agent host. The
/// gate must fire before the `tokio::spawn` of the actual reboot.
/// Asserts the exact message so a missing-gate mutation (which
/// would proceed to the spawn and return `Ok`) goes red.
#[tokio::test]
async fn vps_reboot_read_permission_is_forbidden() {
    let cmd = make_cmd(PermissionLevel::Read, json!({ "type": "vps.reboot" }));

    match handle_vps_reboot(&cmd) {
        Err(AgentError::Forbidden(msg)) => assert_eq!(
            msg, "vps.reboot requires write permission",
            "Forbidden message must match the gate's exact text"
        ),
        other => {
            panic!("expected Forbidden(\"vps.reboot requires write permission\"); got {other:?}")
        }
    }
}

/// `update.self` downloads and runs a new agent binary — the most
/// destructive command in the surface. Read-only roles must not
/// reach the version/URL parsing. URLs intentionally point at a
/// non-existent host so a missing-gate mutation (which would
/// `tokio::spawn` `update::perform_update`) fails inside that
/// function at the github.com allowlist check rather than making
/// real network calls or touching `/etc/glyndor/helmly/...`.
#[tokio::test]
async fn update_self_read_permission_is_forbidden() {
    let cmd = make_cmd(
        PermissionLevel::Read,
        json!({
            "type": "update.self",
            "version": "1.0.0",
            "download_url": "https://invalid.example/binary",
            "sig_url": "https://invalid.example/sig",
        }),
    );

    match handle_update_self(&cmd).await {
        Err(AgentError::Forbidden(msg)) => assert_eq!(
            msg, "update.self requires write permission",
            "Forbidden message must match the gate's exact text"
        ),
        other => {
            panic!("expected Forbidden(\"update.self requires write permission\"); got {other:?}")
        }
    }
}

/// `update.self` with Write permission but missing `download_url`
/// must reject before the `tokio::spawn` of `perform_update` —
/// otherwise a malformed but signed command could spawn a download
/// of whatever URL the operator didn't pin. Asserts the specific
/// `BadRequest("download_url")` (returned by `require_str`) so an
/// unrelated missing-field rejection can't mask this case.
#[tokio::test]
async fn update_self_missing_download_url_returns_bad_request() {
    let cmd = make_cmd(
        PermissionLevel::Write,
        json!({
            "type": "update.self",
            "version": "1.0.0",
            "sig_url": "https://invalid.example/sig",
        }),
    );

    match handle_update_self(&cmd).await {
        Err(AgentError::BadRequest(msg)) => assert_eq!(
            msg, "download_url",
            "missing download_url must surface the specific field name"
        ),
        other => panic!("expected BadRequest(\"download_url\"); got {other:?}"),
    }
}

// =====================================================================
// Pure helpers — `sanitize_error` and `is_private_or_reserved_ip`.
// Small surfaces, but they're on the audit log / SSRF paths and
// worth pinning to a regression test.
// =====================================================================

/// `sanitize_error` collapses `Internal(_)` to the literal string
/// `"internal error"` so the structured `anyhow::Error` (which may
/// contain file paths, secrets from `cmd.payload`, etc.) never
/// reaches the dashboard wire. Asserts both branches.
#[test]
fn sanitize_error_internal_is_redacted() {
    let e = AgentError::Internal(anyhow::anyhow!("secrets in here: /etc/passwd"));
    assert_eq!(super::sanitize_error(&e), "internal error");
}

/// Non-`Internal` variants (`Forbidden`, `BadRequest`, `Unauthorized`,
/// `Lockdown`) pass through verbatim — the caller relies on these
/// messages reaching the dashboard for UX.
#[test]
fn sanitize_error_other_variants_pass_through() {
    let e = AgentError::Forbidden("update.self requires write permission");
    assert_eq!(
        super::sanitize_error(&e),
        "forbidden: update.self requires write permission"
    );
    let e = AgentError::BadRequest("missing payload");
    assert_eq!(super::sanitize_error(&e), "bad request: missing payload");
}

/// SSRF defence — loopback v4 must be classified as private so
/// `dashboard.migrate`'s `validate_migrate_target` rejects a
/// DNS-rebind to `127.0.0.1`.
#[test]
fn is_private_ip_loopback_v4_is_private() {
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(super::is_private_or_reserved_ip(ip));
}

/// Public v4 addresses must NOT be classified as private —
/// otherwise the legitimate dashboard host would always be
/// rejected and the migration handler would be unusable.
#[test]
fn is_private_ip_public_v4_is_not_private() {
    let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!super::is_private_or_reserved_ip(ip));
}

/// SSRF defence — loopback v6 must be classified as private.
#[test]
fn is_private_ip_loopback_v6_is_private() {
    let ip: std::net::IpAddr = "::1".parse().unwrap();
    assert!(super::is_private_or_reserved_ip(ip));
}
