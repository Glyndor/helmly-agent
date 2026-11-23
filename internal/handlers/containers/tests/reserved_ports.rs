//! The host ports `container.deploy` refuses to let a tenant publish on.

use super::*;

// `make_state` builds a lazy pool, which needs a runtime.
#[tokio::test]
async fn reserved_ports_name_own_ports() {
	let mut state = make_state();
	let mut config = make_config();
	config.listen_addr = "0.0.0.0:9191".into();
	config.dashboard_port = Some(19444);
	state.config = Arc::new(config);
	state.set_nft_wg_port(51999);
	let mut ports = reserved_host_ports(&state);
	ports.sort_unstable();
	assert_eq!(ports, vec![9191, 19443, 19444, 51999]);
}

#[tokio::test]
async fn listener_address_without_a_port_reserves_the_default() {
	let mut state = make_state();
	let mut config = make_config();
	config.listen_addr = "not-an-address".into();
	state.config = Arc::new(config);
	assert!(reserved_host_ports(&state).contains(&9090));
}

/// A compose that publishes on helmly-agent's own listener is refused by the
/// handler with the constant message, before anything reaches the runner.
#[tokio::test]
async fn deploy_publishing_on_the_listener_is_forbidden() {
	let mut state = make_state();
	let mut config = make_config();
	config.listen_addr = "0.0.0.0:9191".into();
	state.config = Arc::new(config);
	let cmd = make_cmd(
		PermissionLevel::Write,
		json!({
			"tenant_id": "t1",
			"project_id": "p1",
			"compose_yaml": "services:\n  web:\n    image: nginx\n    ports: [\"9191:80\"]\n",
		}),
	);
	match handle_container_deploy(&state, &cmd).await {
		Err(AgentError::Forbidden(msg)) => assert_eq!(msg, "container.deploy compose rejected"),
		other => panic!("expected Forbidden; got {other:?}"),
	}
}
