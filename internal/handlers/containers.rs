use crate::{
    auth::{PermissionLevel, VerifiedCommand},
    error::AgentError,
    podman,
    state::AppState,
};
use serde_json::{json, Value};

pub fn handle_container_list(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let containers = podman::list_containers(&tenant_id)?;
    Ok(json!({ "containers": containers }))
}

pub fn handle_tenant_ensure(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "tenant.ensure requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    podman::ensure_tenant_user(&tenant_id)?;
    Ok(json!({ "ok": true, "tenant_id": tenant_id }))
}

pub async fn handle_container_deploy(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "container.deploy requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let project_id = require_valid_id(&cmd.command, "project_id")?;
    let compose_yaml = require_str(&cmd.command, "compose_yaml")?;

    // C4: deny-list walker on the compose YAML. The audit's attack
    // chain (`privileged: true` + `volumes: ["/:/host"]` → root on host)
    // requires validation *before* the file lands on disk and is
    // exec'd by `podman compose up -d`. Rejection here means the
    // payload never reaches the podman CLI.
    let project_dir = format!("/var/lib/glyndor/helmly/tenants/{tenant_id}/{project_id}");
    if let Err(e) = super::validate::validate_compose(&compose_yaml, project_dir.as_str()) {
        // Log the detailed reason server-side; don't leak host/port details
        // to the caller (an attacker probing for valid tenant dirs could
        // otherwise distinguish allowed from disallowed by the response shape).
        tracing::warn!("container.deploy rejected: {e}");
        return Err(AgentError::Forbidden("container.deploy compose rejected"));
    }

    let compose_path = podman::compose_deploy(podman::DeployOptions {
        tenant_id: &tenant_id,
        project_id: &project_id,
        compose_yaml: &compose_yaml,
    })?;

    // Persist desired state so agent can restart on reboot (safety net).
    sqlx::query(
        r#"
        INSERT INTO container_deployments (tenant_id, project_id, compose_path, desired)
        VALUES ($1, $2, $3, 'running')
        ON CONFLICT (tenant_id, project_id)
        DO UPDATE SET compose_path = EXCLUDED.compose_path,
                      desired      = 'running',
                      updated_at   = NOW()
        "#,
    )
    .bind(&tenant_id)
    .bind(&project_id)
    .bind(&compose_path)
    .execute(&state.db)
    .await
    .map_err(|e| AgentError::Internal(anyhow::anyhow!(e)))?;

    Ok(json!({ "ok": true }))
}

pub fn handle_container_start(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "container.start requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let name = require_valid_id(&cmd.command, "name")?;
    podman::container_start(&tenant_id, &name)?;
    Ok(json!({ "ok": true }))
}

pub fn handle_container_stop(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "container.stop requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let name = require_valid_id(&cmd.command, "name")?;
    podman::container_stop(&tenant_id, &name)?;
    Ok(json!({ "ok": true }))
}

pub async fn handle_container_down(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    if cmd.permission != PermissionLevel::Destructive {
        return Err(AgentError::Forbidden(
            "container.down requires destructive permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let project_id = require_valid_id(&cmd.command, "project_id")?;

    podman::compose_down(&tenant_id, &project_id)?;

    // Mark desired state as stopped so agent won't restart on reboot.
    sqlx::query(
        "UPDATE container_deployments SET desired = 'stopped', updated_at = NOW() WHERE tenant_id = $1 AND project_id = $2",
    )
    .bind(&tenant_id)
    .bind(&project_id)
    .execute(&state.db)
    .await
    .map_err(|e| AgentError::Internal(anyhow::anyhow!(e)))?;

    Ok(json!({ "ok": true }))
}

pub fn handle_container_remove(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission != PermissionLevel::Destructive {
        return Err(AgentError::Forbidden(
            "container.remove requires destructive permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let name = require_valid_id(&cmd.command, "name")?;
    let force = cmd
        .command
        .get("force")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    podman::container_remove(&tenant_id, &name, force)?;
    Ok(json!({ "ok": true }))
}

pub fn handle_container_restart(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "container.restart requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let name = require_valid_id(&cmd.command, "name")?;
    podman::container_restart(&tenant_id, &name)?;
    Ok(json!({ "ok": true }))
}

pub fn handle_container_update(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "container.update requires write permission",
        ));
    }
    let tenant_id = require_valid_id(&cmd.command, "tenant_id")?;
    let name = require_valid_id(&cmd.command, "name")?;
    let cpus = cmd.command.get("cpus").and_then(|v| v.as_f64());
    let memory_mb = cmd.command.get("memory_mb").and_then(|v| v.as_u64());
    podman::container_update(&tenant_id, &name, cpus, memory_mb)?;
    Ok(json!({ "ok": true }))
}

pub fn require_str(
    cmd: &serde_json::Value,
    key: &'static str,
) -> std::result::Result<String, AgentError> {
    cmd.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or(AgentError::BadRequest(key))
}

/// Validates a resource identifier (tenant_id, project_id, container name).
/// Allows alphanumeric, hyphens, and underscores only — no path separators or
/// shell metacharacters. Max 128 characters.
pub fn validate_id(value: &str, key: &'static str) -> std::result::Result<(), AgentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AgentError::BadRequest(key));
    }
    Ok(())
}

pub fn require_valid_id(
    cmd: &serde_json::Value,
    key: &'static str,
) -> std::result::Result<String, AgentError> {
    let val = require_str(cmd, key)?;
    validate_id(&val, key)?;
    Ok(val)
}

#[cfg(test)]
mod tests {
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

    // =====================================================================
    // Permission gates
    //
    // Every mutating container handler refuses `Read`. `container.list`
    // is the documented exception — listing is a read-only operation,
    // so the handler intentionally has no gate. The test below pins
    // that design choice: adding a gate there would silently break the
    // dashboard's tenant-overview page.
    //
    // The mutation target per `standards/testing/index.md`:
    //   `< Write` → `== Destructive` flips which permission is forbidden.
    //   Each gate test below goes red if its handler's `if` arm is
    //   rewritten that way.
    // =====================================================================

    /// `container.list` deliberately has no permission gate — it only
    /// reads container state. The test asserts the absence: Read does
    /// NOT produce `Forbidden`. A regression that adds a gate here
    /// would break the dashboard's read-only tenant view.
    #[tokio::test]
    async fn container_list_has_no_permission_gate() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({ "type": "container.list", "tenant_id": "valid-org" }),
        );
        // Don't assert Ok — `podman::list_containers` would fail in a
        // unit-test environment (no podman binary, no tenant user) — but
        // the error must NOT be `Forbidden`. Adding
        // `if permission == Read { Err(Forbidden) }` here would surface
        // as `Forbidden(_)` and this test fails.
        match handle_container_list(&cmd) {
            Err(AgentError::Forbidden(msg)) => panic!(
                "container.list has no permission gate; Read must pass through; got Forbidden({msg})"
            ),
            _ => {} // Ok or any non-Forbidden error is acceptable
        }
    }

    /// `tenant.ensure` creates the `helmly-tenant-{id}` system user
    /// and assigns its subuid/subgid range. Read-only roles must not
    /// reach `useradd` / `usermod`. Mutation target: rewriting the
    /// `if cmd.permission == PermissionLevel::Read` arm to anything
    /// else makes Read pass through.
    #[tokio::test]
    async fn tenant_ensure_read_permission_is_forbidden() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({ "type": "tenant.ensure", "tenant_id": "valid-org" }),
        );
        match handle_tenant_ensure(&cmd) {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "tenant.ensure requires write permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"tenant.ensure requires write permission\"); got {other:?}"
            ),
        }
    }

    /// `container.deploy` writes the compose file and runs
    /// `podman compose up -d` — the highest-impact container op. Read
    /// must be refused before any field parsing or `validate_compose`
    /// walk. The fixture provides all three required fields so a
    /// missing-gate mutation surfaces as `Internal` from
    /// `podman::compose_deploy`, not a confusing `BadRequest`.
    #[tokio::test]
    async fn container_deploy_read_permission_is_forbidden() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.deploy",
                "tenant_id": "valid-org",
                "project_id": "valid-proj",
                "compose_yaml": "services: {}\n",
            }),
        );
        match handle_container_deploy(&state, &cmd).await {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.deploy requires write permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.deploy requires write permission\"); got {other:?}"
            ),
        }
    }

    /// `container.start` calls `podman start <name>` as the tenant
    /// user — a side-effecting op even though it's a "start". Read
    /// must be refused. Mutation target: the `== Read` arm.
    #[tokio::test]
    async fn container_start_read_permission_is_forbidden() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.start",
                "tenant_id": "valid-org",
                "name": "valid-name",
            }),
        );
        match handle_container_start(&cmd) {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.start requires write permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.start requires write permission\"); got {other:?}"
            ),
        }
    }

    /// `container.stop` calls `podman stop --time 10 <name>`. Same
    /// gate shape as `container.start`.
    #[tokio::test]
    async fn container_stop_read_permission_is_forbidden() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.stop",
                "tenant_id": "valid-org",
                "name": "valid-name",
            }),
        );
        match handle_container_stop(&cmd) {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.stop requires write permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.stop requires write permission\"); got {other:?}"
            ),
        }
    }

    /// `container.update` calls `podman update --cpus=... --memory=...m <name>`.
    /// Resource limits are not destructive per se but they're a
    /// tenant-visible side-effect — Read must be refused.
    #[tokio::test]
    async fn container_update_read_permission_is_forbidden() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.update",
                "tenant_id": "valid-org",
                "name": "valid-name",
                "cpus": 0.5,
                "memory_mb": 256,
            }),
        );
        match handle_container_update(&cmd) {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.update requires write permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.update requires write permission\"); got {other:?}"
            ),
        }
    }

    /// `container.remove` calls `podman rm [--force] <name>` — the
    /// container is gone afterward. Gate shape is `!= Destructive`,
    /// which rejects both Read and Write. Mutation target: rewriting
    /// to `== Destructive` would accept Read/Write and only refuse
    /// Destructive — Read would then pass and this test fails.
    #[tokio::test]
    async fn container_remove_read_permission_is_forbidden() {
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.remove",
                "tenant_id": "valid-org",
                "name": "valid-name",
            }),
        );
        match handle_container_remove(&cmd) {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.remove requires destructive permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.remove requires destructive permission\"); got {other:?}"
            ),
        }
    }

    /// `container.down` runs `podman compose down --remove-orphans`
    /// AND updates `container_deployments.desired = 'stopped'` in
    /// the agent's DB — two destructive surfaces. Same Destructive-only
    /// gate as `container.remove`. Mutation target: `!= Destructive`.
    #[tokio::test]
    async fn container_down_read_permission_is_forbidden() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Read,
            json!({
                "type": "container.down",
                "tenant_id": "valid-org",
                "project_id": "valid-proj",
            }),
        );
        match handle_container_down(&state, &cmd).await {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.down requires destructive permission",
                "Forbidden message must match the gate's exact text"
            ),
            other => panic!(
                "expected Forbidden(\"container.down requires destructive permission\"); got {other:?}"
            ),
        }
    }

    // =====================================================================
    // Missing required fields
    //
    // Each handler reads `tenant_id` (and possibly `name` /
    // `project_id` / `compose_yaml`) through `require_str` or
    // `require_valid_id`, both of which return
    // `BadRequest(<key-name>)`. Asserting the variant AND the exact
    // key name prevents a stray `BadRequest("tenant_id")` from
    // satisfying a test that meant to catch a missing `name`.
    //
    // The fixture uses valid IDs in the OTHER fields so a missing-key
    // mutation (e.g. dropping the `name` line) surfaces as the right
    // key's BadRequest, not a confusing earlier key.
    // =====================================================================

    /// `container.list` requires only `tenant_id`.
    #[tokio::test]
    async fn container_list_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(PermissionLevel::Read, json!({ "type": "container.list" }));
        match handle_container_list(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    /// `tenant.ensure` requires only `tenant_id`.
    #[tokio::test]
    async fn tenant_ensure_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(PermissionLevel::Write, json!({ "type": "tenant.ensure" }));
        match handle_tenant_ensure(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    /// `container.deploy` requires `tenant_id`, `project_id`, and
    /// `compose_yaml`. Each is tested independently.
    #[tokio::test]
    async fn container_deploy_missing_tenant_id_returns_bad_request() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({
                "type": "container.deploy",
                "project_id": "valid-proj",
                "compose_yaml": "services: {}\n",
            }),
        );
        match handle_container_deploy(&state, &cmd).await {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_deploy_missing_project_id_returns_bad_request() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({
                "type": "container.deploy",
                "tenant_id": "valid-org",
                "compose_yaml": "services: {}\n",
            }),
        );
        match handle_container_deploy(&state, &cmd).await {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "project_id",
                "missing-project_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"project_id\"); got {other:?}"),
        }
    }

    /// Missing `compose_yaml` must be rejected BEFORE `validate_compose`
    /// runs — otherwise a signed but incomplete payload could spawn
    /// a podman-compose run with an empty file. Asserts the specific
    /// `BadRequest("compose_yaml")` from `require_str`.
    #[tokio::test]
    async fn container_deploy_missing_compose_yaml_returns_bad_request() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({
                "type": "container.deploy",
                "tenant_id": "valid-org",
                "project_id": "valid-proj",
            }),
        );
        match handle_container_deploy(&state, &cmd).await {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "compose_yaml",
                "missing-compose_yaml rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"compose_yaml\"); got {other:?}"),
        }
    }

    /// `container.start` requires `tenant_id` and `name`.
    #[tokio::test]
    async fn container_start_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.start", "name": "valid-name" }),
        );
        match handle_container_start(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_start_missing_name_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.start", "tenant_id": "valid-org" }),
        );
        match handle_container_start(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "name",
                "missing-name rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"name\"); got {other:?}"),
        }
    }

    /// `container.stop` requires `tenant_id` and `name`.
    #[tokio::test]
    async fn container_stop_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.stop", "name": "valid-name" }),
        );
        match handle_container_stop(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_stop_missing_name_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.stop", "tenant_id": "valid-org" }),
        );
        match handle_container_stop(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "name",
                "missing-name rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"name\"); got {other:?}"),
        }
    }

    /// `container.down` requires `tenant_id` and `project_id`. The
    /// handler is gated by `Destructive`, so the test uses that level.
    #[tokio::test]
    async fn container_down_missing_tenant_id_returns_bad_request() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Destructive,
            json!({ "type": "container.down", "project_id": "valid-proj" }),
        );
        match handle_container_down(&state, &cmd).await {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_down_missing_project_id_returns_bad_request() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Destructive,
            json!({ "type": "container.down", "tenant_id": "valid-org" }),
        );
        match handle_container_down(&state, &cmd).await {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "project_id",
                "missing-project_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"project_id\"); got {other:?}"),
        }
    }

    /// `container.remove` requires `tenant_id` and `name`. Destructive
    /// gate — use `Destructive` permission.
    #[tokio::test]
    async fn container_remove_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Destructive,
            json!({ "type": "container.remove", "name": "valid-name" }),
        );
        match handle_container_remove(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_remove_missing_name_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Destructive,
            json!({ "type": "container.remove", "tenant_id": "valid-org" }),
        );
        match handle_container_remove(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "name",
                "missing-name rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"name\"); got {other:?}"),
        }
    }

    /// `container.update` requires `tenant_id` and `name`. The
    /// `cpus` and `memory_mb` fields are optional — not tested here.
    #[tokio::test]
    async fn container_update_missing_tenant_id_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.update", "name": "valid-name" }),
        );
        match handle_container_update(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "missing-tenant_id rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    #[tokio::test]
    async fn container_update_missing_name_returns_bad_request() {
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({ "type": "container.update", "tenant_id": "valid-org" }),
        );
        match handle_container_update(&cmd) {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "name",
                "missing-name rejection must name the missing field"
            ),
            other => panic!("expected BadRequest(\"name\"); got {other:?}"),
        }
    }

    // =====================================================================
    // `require_valid_id` rejection paths
    //
    // `validate_id` is already covered (path traversal, shell
    // metacharacters, empty, too long). `require_valid_id` wraps it
    // with `require_str`, so the same rejection classes pass through
    // with a `BadRequest(<key>)` error. We assert the key name
    // surfaces — the call site uses it for the rejection reason
    // (`agent.heartbeat_ack` keys on the error code).
    //
    // Removing the `validate_id` call inside `require_valid_id` would
    // let the bad value reach `podman::list_containers` / `compose_*`
    // and execute as a shell-interpreted argument. Each test below
    // catches that mutation by asserting the right BadRequest.
    // =====================================================================

    /// Path traversal in `tenant_id` is the classic escape — `..`
    /// segments walk out of `/var/lib/glyndor/helmly/orgs/{id}` to
    /// anywhere on the filesystem. `require_valid_id` must reject
    /// before `podman::list_containers` ever sees the value.
    #[test]
    fn require_valid_id_path_traversal_returns_bad_request() {
        let cmd = json!({ "tenant_id": "../etc" });
        match require_valid_id(&cmd, "tenant_id") {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "path-traversal rejection must surface with the offending key"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    /// Shell metacharacters (`;`, `$()`, backticks, pipe, etc.) are
    /// rejected even though `podman` is invoked via `runuser -u <user> --
    /// podman` (no shell). The validation is defence-in-depth: a future
    /// refactor that switches to a shell-invoking path would silently
    /// re-introduce the injection vector.
    #[test]
    fn require_valid_id_shell_metacharacters_returns_bad_request() {
        let cmd = json!({ "tenant_id": "foo; rm -rf /" });
        match require_valid_id(&cmd, "tenant_id") {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "shell-metachar rejection must surface with the offending key"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    /// Empty string is rejected — `podman` with an empty `--user` or
    /// `-f` argument would either error opaquely or, worse, match a
    /// real user.
    #[test]
    fn require_valid_id_empty_string_returns_bad_request() {
        let cmd = json!({ "tenant_id": "" });
        match require_valid_id(&cmd, "tenant_id") {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "empty-string rejection must surface with the offending key"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    /// Too-long string (200 chars; limit is 128) is rejected — a
    /// pathological tenant_id that exceeds the bound would be passed
    /// to `useradd` / `runuser` as a giant username and either error
    /// opaquely or hit some other length-based system limit.
    #[test]
    fn require_valid_id_too_long_returns_bad_request() {
        let cmd = json!({ "tenant_id": "a".repeat(200) });
        match require_valid_id(&cmd, "tenant_id") {
            Err(AgentError::BadRequest(key)) => assert_eq!(
                key, "tenant_id",
                "too-long rejection must surface with the offending key"
            ),
            other => panic!("expected BadRequest(\"tenant_id\"); got {other:?}"),
        }
    }

    // =====================================================================
    // `handle_container_deploy` × `validate_compose` integration
    //
    // The C4 unit tests in `internal/handlers/validate.rs` cover
    // `validate_compose` itself; here we verify the handler-level
    // integration: a signed `container.deploy` carrying
    // `privileged: true` must surface as `Forbidden`, not
    // `BadRequest` (which would imply the field gate fired first) and
    // not `Internal` (which would imply an `anyhow` error escaped the
    // mapping at `containers.rs:50`). The mapping at line 50 collapses
    // every `validate_compose` rejection into the constant string
    // `"container.deploy compose rejected"` so attackers can't
    // distinguish allowed from disallowed by the response shape.
    // =====================================================================

    /// The full chain — `Write` permission, valid IDs, payload contains
    /// the C4 attack vector `privileged: true` — must surface as
    /// `Forbidden("container.deploy compose rejected")`.
    ///
    /// Mutation targets:
    ///   - Removing the `validate_compose` call entirely makes the
    ///     handler proceed to `podman::compose_deploy`, which fails
    ///     with `Internal(anyhow)` — `Forbidden` becomes `Internal`,
    ///     this test goes red.
    ///   - Replacing `Forbidden` with `BadRequest` (or `Internal`)
    ///     also makes this test fail.
    ///   - Removing the `tracing::warn!` log line doesn't change the
    ///     error type, so it would not be caught here — but the
    ///     audited log surface is in `validate.rs`, not the handler.
    #[tokio::test]
    async fn container_deploy_privileged_compose_returns_forbidden_not_internal() {
        let state = make_state();
        let cmd = make_cmd(
            PermissionLevel::Write,
            json!({
                "type": "container.deploy",
                "tenant_id": "valid-org",
                "project_id": "valid-proj",
                "compose_yaml": "services:\n  web:\n    image: nginx\n    privileged: true\n",
            }),
        );
        match handle_container_deploy(&state, &cmd).await {
            Err(AgentError::Forbidden(msg)) => assert_eq!(
                msg, "container.deploy compose rejected",
                "validate_compose rejection must surface as Forbidden with the constant message"
            ),
            Err(AgentError::BadRequest(key)) => panic!(
                "expected Forbidden(\"container.deploy compose rejected\"); got BadRequest({key}) \
                 — the field gate fired before validate_compose, which means a signed \
                 compose_yaml=privileged payload reached the field parser"
            ),
            Err(AgentError::Internal(e)) => panic!(
                "expected Forbidden; got Internal({e:#}) — validate_compose error escaped \
                 the mapping at containers.rs:50"
            ),
            Err(AgentError::Lockdown) => panic!("expected Forbidden; got Lockdown"),
            Err(AgentError::Unauthorized) => panic!("expected Forbidden; got Unauthorized"),
            other => {
                panic!("expected Forbidden(\"container.deploy compose rejected\"); got {other:?}")
            }
        }
    }
}
