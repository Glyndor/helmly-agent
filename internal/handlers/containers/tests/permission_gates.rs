use super::*;

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
    if let Err(AgentError::Forbidden(msg)) = handle_container_list(&cmd) {
        panic!(
            "container.list has no permission gate; Read must pass through; got Forbidden({msg})"
        )
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
        other => {
            panic!("expected Forbidden(\"tenant.ensure requires write permission\"); got {other:?}")
        }
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
