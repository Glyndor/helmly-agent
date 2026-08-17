use super::*;

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
