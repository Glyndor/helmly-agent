use crate::{
	auth::{PermissionLevel, VerifiedCommand},
	error::AgentError,
	state::AppState,
};
use serde_json::{json, Value};

use super::containers::require_str;

pub(crate) const NGINX_CONTAINER: &str = "helmly-nginx";
pub(crate) const NGINX_CONFIG_PATH: &str = "/etc/nginx/conf.d/helmly.conf";
const NGINX_TMP_CONFIG_PATH: &str = "/etc/nginx/conf.d/helmly.conf.new";
const WEBROOT_PATH: &str = "/var/lib/glyndor/helmly/nginx/webroot";

/// Deploy the nginx reverse-proxy container. Idempotent — removes the old container first
/// if it exists (stopped or otherwise).
pub async fn handle_nginx_deploy(
	state: &AppState,
	cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission < PermissionLevel::Write {
		return Err(AgentError::Forbidden(
			"nginx.deploy requires write permission",
		));
	}

	let image = require_str(&cmd.command, "image")?;

	// Stop + remove old container if present (ignore errors — it may not exist).
	let _ = std::process::Command::new("podman")
		.args(["stop", NGINX_CONTAINER])
		.status();
	let _ = std::process::Command::new("podman")
		.args(["rm", NGINX_CONTAINER])
		.status();

	let status = std::process::Command::new("podman")
		.args([
			"run",
			"--detach",
			"--restart=always",
			"--name",
			NGINX_CONTAINER,
			"--publish",
			"80:80",
			"--publish",
			"443:443",
			&image,
		])
		.status()
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("podman run nginx: {e}")))?;

	if !status.success() {
		return Err(AgentError::Internal(anyhow::anyhow!(
			"nginx container start failed"
		)));
	}

	// Persist config to DB if provided (optional — may come separately via nginx.update_config).
	if let Some(cfg) = cmd.command.get("config").and_then(|v| v.as_str()) {
		persist_config(state, cfg).await?;
		if let Err(e) = std::fs::write(NGINX_CONFIG_PATH, cfg) {
			tracing::warn!("failed to write nginx config to disk: {e}");
		}
		reload_nginx()?;
	}

	tracing::info!("nginx container deployed");
	Ok(json!({ "ok": true, "container": NGINX_CONTAINER }))
}

/// Update nginx config: write to a temp path, validate via `nginx -t`,
/// only swap on success. The allow-list walker in
/// `internal/handlers/validate.rs` rejects the payload before nginx
/// ever sees it; `nginx -t` is defence-in-depth so a config that's
/// structurally OK for the walker but syntactically broken still fails
/// closed.
pub async fn handle_nginx_update_config(
	state: &AppState,
	cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission < PermissionLevel::Write {
		return Err(AgentError::Forbidden(
			"nginx.update_config requires write permission",
		));
	}

	let config = require_str(&cmd.command, "config")?;

	if let Err(e) = super::validate::validate_nginx(&config) {
		tracing::warn!("nginx.update_config rejected by allow-list walker: {e}");
		return Err(AgentError::Forbidden("nginx.update_config config rejected"));
	}

	// Stage to a temp file first. If `nginx -t` fails, we keep the
	// previous config live (no swap). The temp filename must differ from
	// any include directive in the live config — the include scanner
	// is line-based and would also load the .new file if the live config
	// does `include *.conf;`. We keep the temp file outside /etc/nginx
	// for that reason, then pass it via `nginx -t -c <tmp>` so the
	// include scanner reads only the temp.
	std::fs::write(NGINX_TMP_CONFIG_PATH, config.as_bytes())
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("write nginx tmp config: {e}")))?;

	if !nginx_test_config(NGINX_TMP_CONFIG_PATH) {
		let _ = std::fs::remove_file(NGINX_TMP_CONFIG_PATH);
		return Err(AgentError::Forbidden(
			"nginx.update_config config failed nginx -t (parse error)",
		));
	}

	persist_config(state, &config).await?;

	// Atomic swap (same filesystem): write over the live path.
	std::fs::rename(NGINX_TMP_CONFIG_PATH, NGINX_CONFIG_PATH)
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("swap nginx config: {e}")))?;

	reload_nginx()?;

	tracing::info!("nginx config updated and reloaded");
	Ok(json!({ "ok": true }))
}

async fn persist_config(state: &AppState, config: &str) -> std::result::Result<(), AgentError> {
	let id = uuid::Uuid::now_v7();
	sqlx::query!(
		"INSERT INTO nginx_configs (id, config_content, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT DO NOTHING",
		id,
		config,
	)
	.execute(&state.db)
	.await
	.map_err(|e| AgentError::Internal(anyhow::anyhow!("persist nginx config: {e}")))?;

	// Keep only the latest row — truncate old ones.
	sqlx::query!(
        "DELETE FROM nginx_configs WHERE id != (SELECT id FROM nginx_configs ORDER BY updated_at DESC LIMIT 1)"
    )
    .execute(&state.db)
    .await
    .ok();

	Ok(())
}

fn reload_nginx() -> std::result::Result<(), AgentError> {
	let status = std::process::Command::new("podman")
		.args(["exec", NGINX_CONTAINER, "nginx", "-s", "reload"])
		.status()
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("nginx reload: {e}")))?;

	if !status.success() {
		return Err(AgentError::Internal(anyhow::anyhow!(
			"nginx -s reload failed"
		)));
	}
	Ok(())
}

/// Run `nginx -t -c <path>` inside the helmly-nginx container. Returns
/// true if the config parses cleanly, false otherwise. The test invocation
/// is the canonical nginx self-test; it does not depend on the allow-list
/// walker — it catches the structural/syntactic bugs that walker misses.
fn nginx_test_config(path: &str) -> bool {
	let status = std::process::Command::new("podman")
		.args(["exec", NGINX_CONTAINER, "nginx", "-t", "-c", path])
		.status();
	match status {
		Ok(s) => s.success(),
		Err(_) => false,
	}
}

/// Install an externally-provided TLS certificate (Cloudflare Origin or custom).
/// Writes cert + optional key to disk, then reloads nginx.
pub fn handle_nginx_install_cert(
	_state: &AppState,
	cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission < PermissionLevel::Write {
		return Err(AgentError::Forbidden(
			"nginx.install_cert requires write permission",
		));
	}

	let domain = require_str(&cmd.command, "domain")?;
	validate_domain_for_path(&domain)?;
	let cert_pem = require_str(&cmd.command, "cert_pem")?;

	let cert_dir = format!("/etc/glyndor/helmly/nginx/certs/{domain}");
	std::fs::create_dir_all(&cert_dir)
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("create cert dir: {e}")))?;

	let cert_path = format!("{cert_dir}/fullchain.pem");
	let key_path = format!("{cert_dir}/privkey.pem");

	std::fs::write(&cert_path, cert_pem.as_bytes())
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("write cert: {e}")))?;

	if let Some(key_pem) = cmd.command.get("key_pem").and_then(|v| v.as_str()) {
		std::fs::write(&key_path, key_pem.as_bytes())
			.map_err(|e| AgentError::Internal(anyhow::anyhow!("write key: {e}")))?;
	}

	// Reload nginx if the container is running.
	let _ = reload_nginx();

	tracing::info!(domain, "external TLS cert installed");
	Ok(json!({ "ok": true, "domain": domain, "cert_path": cert_path }))
}

/// Obtain a Let's Encrypt certificate via certbot (webroot challenge).
pub async fn handle_certbot_obtain(
	_state: &AppState,
	cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	if cmd.permission < PermissionLevel::Write {
		return Err(AgentError::Forbidden(
			"certbot.obtain requires write permission",
		));
	}

	let domain = require_str(&cmd.command, "domain")?;
	let email = require_str(&cmd.command, "email")?;

	std::fs::create_dir_all(WEBROOT_PATH)
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("create webroot: {e}")))?;

	let status = tokio::process::Command::new("certbot")
		.args([
			"certonly",
			"--webroot",
			"--webroot-path",
			WEBROOT_PATH,
			"--non-interactive",
			"--agree-tos",
			"--email",
			&email,
			"-d",
			&domain,
		])
		.status()
		.await
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("certbot exec: {e}")))?;

	if !status.success() {
		return Err(AgentError::Internal(anyhow::anyhow!(
			"certbot failed to obtain certificate"
		)));
	}

	tracing::info!(domain, "Let's Encrypt cert obtained");
	Ok(json!({ "ok": true, "domain": domain }))
}

fn validate_domain_for_path(domain: &str) -> std::result::Result<(), AgentError> {
	if domain.is_empty()
		|| domain.len() > 253
		|| domain.contains("..")
		|| domain.contains('/')
		|| domain.contains('\0')
		|| !domain
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
		|| domain.starts_with('.')
		|| domain.ends_with('.')
	{
		return Err(AgentError::BadRequest("invalid domain for cert path"));
	}
	Ok(())
}

/// Close port 19443 via nftables once a domain is confirmed active.
pub fn handle_close_setup_port(
	state: &AppState,
	cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
	let _ = state;
	close_setup_port_with(cmd, &nft_run)
}

/// The setup port, as `setup-agent.sh` writes it into the bootstrap ruleset.
pub(crate) const SETUP_PORT: u16 = 19443;

/// Run `nft` with `args` and return its stdout.
fn nft_run(args: &[&str]) -> anyhow::Result<String> {
	let out = std::process::Command::new("nft")
		.args(args)
		.output()
		.map_err(|e| anyhow::anyhow!("spawn nft: {e}"))?;
	if !out.status.success() {
		anyhow::bail!(
			"nft {:?} failed: {}",
			args,
			String::from_utf8_lossy(&out.stderr).trim()
		);
	}
	Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Close the setup port by DELETING the rule that accepts it.
///
/// The previous implementation appended `tcp dport 19443 drop` and returned
/// `{"ok": true}`. `nft add rule` appends, the chain `setup-agent.sh` builds
/// already accepts 19443 higher up, and a chain is evaluated in order with
/// `accept` as a terminal verdict, so the appended rule was unreachable. It
/// sat below the chain's own trailing `drop` as well. The port stayed open
/// and the operator was told it had closed.
///
/// Appending a deny after an allow is not closing anything. So this finds
/// every rule in the chain that accepts the port, deletes each by handle,
/// and then RE-READS the chain to confirm none is left before reporting
/// success. Asserting the shape of a control is not asserting the control,
/// which is the whole lesson of the bug being fixed.
pub(crate) fn close_setup_port_with<F>(
	cmd: &VerifiedCommand,
	nft: &F,
) -> std::result::Result<Value, AgentError>
where
	F: Fn(&[&str]) -> anyhow::Result<String>,
{
	if cmd.permission < PermissionLevel::Write {
		return Err(AgentError::Forbidden(
			"nftables.close_setup_port requires write permission",
		));
	}

	let list = |nft: &F| -> std::result::Result<String, AgentError> {
		nft(&["-a", "list", "chain", "inet", "helmly-agent", "helmly-base"])
			.map_err(|e| AgentError::Internal(anyhow::anyhow!("list chain: {e}")))
	};

	let handles = accepting_handles(&list(nft)?);
	for h in &handles {
		let h = h.to_string();
		nft(&[
			"delete",
			"rule",
			"inet",
			"helmly-agent",
			"helmly-base",
			"handle",
			&h,
		])
		.map_err(|e| AgentError::Internal(anyhow::anyhow!("delete rule handle {h}: {e}")))?;
	}

	// Re-read. The delete above can succeed on every handle and still leave
	// the port open if the chain gained another accepting rule, so the answer
	// comes from the ruleset rather than from the exit codes.
	let remaining = accepting_handles(&list(nft)?);
	if !remaining.is_empty() {
		return Err(AgentError::Internal(anyhow::anyhow!(
			"port {SETUP_PORT} still accepted by {} rule(s) after deleting {}; refusing to report it closed",
			remaining.len(),
			handles.len()
		)));
	}

	tracing::info!(
		"setup port {SETUP_PORT} closed: {} accepting rule(s) deleted, none remaining",
		handles.len()
	);
	Ok(json!({ "ok": true, "port": SETUP_PORT, "rules_deleted": handles.len() }))
}

/// Handles of every rule in `chain_listing` that accepts the setup port.
///
/// `nft -a list chain` prints one rule per line ending in `# handle N`. A
/// rule counts when it names the port as a `dport` AND reaches `accept`;
/// a rule that merely mentions the number, or that drops it, is not what
/// keeps the port open.
fn accepting_handles(chain_listing: &str) -> Vec<u64> {
	let dport = format!("dport {SETUP_PORT}");
	chain_listing
		.lines()
		.filter(|l| l.contains(&dport) && l.split_whitespace().any(|w| w == "accept"))
		.filter_map(|l| {
			let (_, after) = l.rsplit_once("# handle ")?;
			after.trim().parse::<u64>().ok()
		})
		.collect()
}

#[cfg(test)]
mod tests;
