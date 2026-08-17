use crate::{
    audit::{self, AuditEntry, AuditResult},
    auth::{verify_bearer, verify_command, PermissionLevel, SignedCommand, VerifiedCommand},
    cert,
    error::{AgentError, Result},
    state::AppState,
    update,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tracing::{info, warn};

use super::containers::require_str;
use super::{
    containers::{
        handle_container_deploy, handle_container_down, handle_container_list,
        handle_container_remove, handle_container_restart, handle_container_start,
        handle_container_stop, handle_container_update, handle_tenant_ensure,
    },
    nftables::{handle_nftables_accept, handle_nftables_apply, handle_nftables_restore},
    nginx_cmd::{
        handle_certbot_obtain, handle_close_setup_port, handle_nginx_deploy,
        handle_nginx_install_cert, handle_nginx_update_config,
    },
    wireguard::{
        handle_wg_data_plane_setup, handle_wg_data_plane_teardown, handle_wg_management_add_peer,
        handle_wg_management_list_peers, handle_wg_management_remove_peer, handle_wg_rotate_psk,
    },
};

pub async fn health() -> StatusCode {
    StatusCode::OK
}

/// Verify a signed command, execute it, and write the audit entry.
/// Returns the result `Value` on success.
/// Called by both the HTTP handler (after bearer auth) and the WS client.
pub async fn run_verified_command(
    state: &AppState,
    signed: SignedCommand,
) -> std::result::Result<Value, AgentError> {
    if !state.check_cmd_rate() {
        let count = state.record_rate_rejection();
        audit::append(
            &state.db,
            AuditEntry {
                agent_id: state.config.agent_id,
                organization_id: None,
                user_id: None,
                command_type: "unknown",
                result: AuditResult::RejectedRateLimit,
                error: None,
            },
        )
        .await
        .ok();
        if count >= 3 {
            tracing::warn!(count, "rate limit threshold reached — alerting");
        }
        return Err(AgentError::BadRequest("rate limit exceeded"));
    }

    let verified = match verify_command(
        &state.db,
        &signed,
        &state.config.dashboard_verify_key,
        state.config.agent_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("command rejected: {e}");
            audit::append(
                &state.db,
                AuditEntry {
                    agent_id: state.config.agent_id,
                    organization_id: None,
                    user_id: None,
                    command_type: "unknown",
                    result: AuditResult::Rejected,
                    error: Some(e.to_string()),
                },
            )
            .await
            .ok();
            return Err(AgentError::Unauthorized);
        }
    };

    let cmd_type = verified
        .command
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    info!(
        cmd_type = %cmd_type,
        user_id = %verified.user_id,
        permission = ?verified.permission,
        "executing command"
    );

    let result = command_dispatch(state, &verified).await;

    let audit_result = match &result {
        Ok(_) => AuditResult::Success,
        Err(AgentError::BadRequest(_))
        | Err(AgentError::Unauthorized)
        | Err(AgentError::Forbidden(_)) => AuditResult::Rejected,
        Err(_) => AuditResult::Failed,
    };

    audit::append(
        &state.db,
        AuditEntry {
            agent_id: state.config.agent_id,
            organization_id: verified.organization_id,
            user_id: Some(verified.user_id),
            command_type: &cmd_type,
            result: audit_result,
            error: match &result {
                Err(e) => Some(sanitize_error(e)),
                Ok(_) => None,
            },
        },
    )
    .await?;

    result
}

/// HTTP handler — adds bearer token auth and lockdown check on top of `run_verified_command`.
pub async fn execute_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(signed): Json<SignedCommand>,
) -> Result<Response> {
    if state.is_locked_down() {
        return Err(AgentError::Lockdown);
    }

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !verify_bearer(token, &state.config.internal_token) {
        return Err(AgentError::Unauthorized);
    }

    run_verified_command(&state, signed)
        .await
        .map(|v| Json(v).into_response())
}

async fn command_dispatch(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    match cmd
        .command
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
    {
        "nftables.apply" => handle_nftables_apply(state, cmd).await,
        "nftables.restore" => handle_nftables_restore(state, cmd),
        "nftables.accept" => handle_nftables_accept(state, cmd),
        "container.list" => handle_container_list(cmd),
        "tenant.ensure" => handle_tenant_ensure(cmd),
        "container.deploy" => handle_container_deploy(state, cmd).await,
        "container.down" => handle_container_down(state, cmd).await,
        "container.start" => handle_container_start(cmd),
        "container.stop" => handle_container_stop(cmd),
        "container.remove" => handle_container_remove(cmd),
        "container.restart" => handle_container_restart(cmd),
        "container.update" => handle_container_update(cmd),
        "update.self" => handle_update_self(cmd).await,
        "wg.rotate_psk" => handle_wg_rotate_psk(cmd),
        "wg.management.add_peer" => handle_wg_management_add_peer(cmd),
        "wg.management.remove_peer" => handle_wg_management_remove_peer(cmd),
        "wg.management.list_peers" => handle_wg_management_list_peers(cmd),
        "wg.data_plane.setup" => handle_wg_data_plane_setup(cmd),
        "wg.data_plane.teardown" => handle_wg_data_plane_teardown(cmd),
        "dashboard.migrate" => handle_dashboard_migrate(state, cmd).await,
        "cert.update" => handle_cert_update(state, cmd).await,
        "vps.reboot" => handle_vps_reboot(cmd),
        "nginx.deploy" => handle_nginx_deploy(state, cmd).await,
        "nginx.update_config" => handle_nginx_update_config(state, cmd).await,
        "nginx.install_cert" => Ok(handle_nginx_install_cert(state, cmd)?),
        "certbot.obtain" => handle_certbot_obtain(state, cmd).await,
        "nftables.close_setup_port" => Ok(handle_close_setup_port(state, cmd)?),
        "db.rotate_password" => handle_db_rotate_password(state, cmd).await,
        // Heartbeat ACK resets the lockdown timer and exits lockdown.
        // Handled here so WS path can also process it via run_verified_command.
        "agent.heartbeat_ack" => {
            *state.last_heartbeat.lock().unwrap() = std::time::Instant::now();
            state.clear_lockdown_if_heartbeat();
            Ok(json!({ "ok": true }))
        }
        other => {
            warn!("unknown command type: {other}");
            Err(AgentError::BadRequest("unknown command type"))
        }
    }
}

async fn handle_update_self(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "update.self requires write permission",
        ));
    }
    let version = require_str(&cmd.command, "version")?;
    let download_url = require_str(&cmd.command, "download_url")?;
    let sig_url = require_str(&cmd.command, "sig_url")?;

    tokio::spawn(async move {
        if let Err(e) = update::perform_update(&version, &download_url, &sig_url).await {
            tracing::error!(version, "update failed: {e:#}");
        }
    });

    Ok(json!({ "ok": true, "message": "update initiated" }))
}

pub async fn handle_dashboard_migrate(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    if cmd.permission == PermissionLevel::Read {
        return Err(AgentError::Forbidden(
            "dashboard.migrate requires write permission",
        ));
    }

    let target_url = require_str(&cmd.command, "target_url")?;

    // C5: a dashboard compromised or one whose signing key leaked could exfiltrate
    // the long-lived `sync_token` to any URL by signing `dashboard.migrate` with a
    // hostile `target_url`. The handler used to POST `Authorization: Bearer <token>`
    // verbatim to whatever the signed command said.
    //
    // The validation requires `target_url` to point at the same host+port as the
    // configured `dashboard_url`, AND to resolve to a non-private address. Fail
    // closed at every step.
    let dashboard_url = state.config.dashboard_url.as_deref().ok_or_else(|| {
        AgentError::Forbidden("dashboard.migrate refused: DASHBOARD_URL is not configured")
    })?;
    validate_migrate_target(&target_url, dashboard_url)
        .await
        .map_err(|e| {
            // Log the reason server-side; don't leak host/port details to the
            // caller (an attacker probing for valid dashboard hosts could
            // otherwise distinguish allowed from disallowed).
            tracing::warn!("dashboard.migrate rejected: {e}");
            AgentError::Forbidden("dashboard.migrate target rejected")
        })?;

    let sync_token = match state.config.sync_token.as_deref() {
        Some(t) => t.to_string(),
        None => return Err(AgentError::BadRequest("no sync token configured")),
    };
    let agent_id = state.config.agent_id;

    tokio::spawn(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
        else {
            return;
        };

        let _ = client
            .post(format!("{target_url}/migration/agent-confirm"))
            .header("Authorization", format!("Bearer {sync_token}"))
            .json(&serde_json::json!({ "agent_id": agent_id }))
            .send()
            .await;

        tracing::info!("notified VPS-B of migration confirmation");
    });

    Ok(json!({ "ok": true, "message": "migration acknowledgment sent" }))
}

pub async fn handle_cert_update(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    if cmd.permission < PermissionLevel::Write {
        return Err(AgentError::Forbidden(
            "cert.update requires write permission",
        ));
    }

    let payload = cmd
        .command
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or(AgentError::BadRequest("missing payload"))?
        .to_string();
    let signature = cmd
        .command
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or(AgentError::BadRequest("missing signature"))?
        .to_string();

    let cert_entry = cert::SignedCert { payload, signature };

    let ca_public = cert::load_ca_public_key()
        .ok_or_else(|| AgentError::Internal(anyhow::anyhow!("CA_PUBLIC_KEY not configured")))?;

    cert::verify(&cert_entry, &ca_public, state.config.agent_id).map_err(AgentError::Internal)?;

    let cert_json =
        serde_json::to_string(&cert_entry).map_err(|e| AgentError::Internal(anyhow::anyhow!(e)))?;

    let cert_path = std::path::Path::new("/etc/glyndor/helmly/cert.json");
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AgentError::Internal(anyhow::anyhow!(e)))?;
    }
    tokio::fs::write(cert_path, cert_json.as_bytes())
        .await
        .map_err(|e| AgentError::Internal(anyhow::anyhow!(e)))?;

    tracing::info!(agent_id = %state.config.agent_id, "agent cert renewed and persisted to /etc/glyndor/helmly/cert.json");

    Ok(json!({ "ok": true }))
}

async fn handle_db_rotate_password(
    state: &AppState,
    cmd: &VerifiedCommand,
) -> std::result::Result<Value, AgentError> {
    if cmd.permission < PermissionLevel::Write {
        return Err(AgentError::Forbidden(
            "db.rotate_password requires write permission",
        ));
    }

    use rand::Rng;
    use zeroize::Zeroizing;
    let mut buf = [0u8; 24];
    rand::rng().fill_bytes(&mut buf);
    let new_pass = Zeroizing::new(buf.iter().map(|b| format!("{b:02x}")).collect::<String>());

    // Dollar-quoting ($$...$$) avoids any quote-based injection.
    // new_pass is hex [0-9a-f] so "$$" can never appear inside it.
    sqlx::query(&format!(
        "ALTER USER helmly_agent_app PASSWORD $${}$$",
        *new_pass
    ))
    .execute(&state.db)
    .await
    .map_err(|e| AgentError::Internal(anyhow::anyhow!("ALTER USER: {e}")))?;

    let status = std::process::Command::new("podman")
        .args(["secret", "create", "--replace", "helmly-agent-pg-pass", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(new_pass.as_bytes())?;
            child.wait()
        })
        .map_err(|e| AgentError::Internal(anyhow::anyhow!("podman secret create: {e}")))?;

    if !status.success() {
        tracing::warn!("failed to update Podman secret helmly-agent-pg-pass — password rotated in DB but secret not updated");
    }

    // Update /etc/glyndor/helmly/credentials/database-url so systemd LoadCredential
    // serves the new password on next agent restart.
    match update_database_url_credential(&state.config.database_url, &new_pass) {
        Ok(()) => tracing::info!("updated /etc/glyndor/helmly/credentials/database-url with new password"),
        Err(e) => tracing::warn!("failed to update /etc/glyndor/helmly/credentials/database-url: {e} — credential file still has old password"),
    }

    tracing::info!("agent PostgreSQL password rotated");
    Ok(json!({ "ok": true }))
}

fn update_database_url_credential(current_url: &str, new_pass: &str) -> anyhow::Result<()> {
    let mut parsed = url::Url::parse(current_url)
        .map_err(|e| anyhow::anyhow!("failed to parse database_url: {e}"))?;
    parsed
        .set_password(Some(new_pass))
        .map_err(|_| anyhow::anyhow!("failed to set password in database URL"))?;
    let new_url = parsed.to_string();
    let path = std::path::Path::new("/etc/glyndor/helmly/credentials/database-url");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, new_url.as_bytes())?;
    // 600 — readable only by helmly-agent
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn handle_vps_reboot(cmd: &VerifiedCommand) -> std::result::Result<Value, AgentError> {
    if cmd.permission < PermissionLevel::Write {
        return Err(AgentError::Forbidden(
            "vps.reboot requires write permission",
        ));
    }
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let _ = std::process::Command::new("systemctl")
            .arg("reboot")
            .status();
    });
    Ok(json!({ "ok": true, "message": "reboot initiated" }))
}

fn sanitize_error(e: &AgentError) -> String {
    match e {
        AgentError::Internal(_) => "internal error".to_string(),
        other => other.to_string(),
    }
}

/// C5: validate that a `dashboard.migrate` `target_url` points at the
/// configured dashboard host+port and resolves to a non-private IP.
///
/// Pure function (modulo the DNS lookup) so unit tests can exercise
/// parse / host-compare / port-compare without a live DNS or socket.
/// `pub(crate)` for tests; not part of the public API.
pub(crate) async fn validate_migrate_target(
    target_url: &str,
    dashboard_url: &str,
) -> std::result::Result<(), String> {
    use std::net::IpAddr;

    let parsed_target = url::Url::parse(target_url)
        .map_err(|e| format!("target_url is not a valid URL: {e}"))?;
    let parsed_dash = url::Url::parse(dashboard_url)
        .map_err(|e| format!("DASHBOARD_URL is not a valid URL: {e}"))?;

    // 1. Scheme must be http or https. file://, gopher://, etc. are not
    //    legitimate for an HTTPS dashboard.
    match parsed_target.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "target_url scheme {other:?} rejected; only http(s) allowed"
            ));
        }
    }
    // Same shape check on the configured dashboard, so a misconfigured
    // DASHBOARD_URL (e.g. accidentally `file:///foo`) fails the comparison.
    match parsed_dash.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "DASHBOARD_URL scheme {other:?} rejected; only http(s) allowed"
            ));
        }
    }

    // 2. Host compare (case-insensitive — URLs are case-insensitive on host).
    let target_host = parsed_target
        .host_str()
        .ok_or_else(|| "target_url has no host".to_string())?
        .to_ascii_lowercase();
    let dash_host = parsed_dash
        .host_str()
        .ok_or_else(|| "DASHBOARD_URL has no host".to_string())?
        .to_ascii_lowercase();
    if target_host != dash_host {
        return Err(format!(
            "target_url host {target_host:?} does not match DASHBOARD_URL host {dash_host:?}"
        ));
    }

    // 3. Port compare (use scheme default if absent — https=443, http=80).
    let target_port = parsed_target.port_or_known_default().ok_or_else(|| {
        format!(
            "target_url has no port and no known default for scheme {:?}",
            parsed_target.scheme()
        )
    })?;
    let dash_port = parsed_dash.port_or_known_default().ok_or_else(|| {
        format!(
            "DASHBOARD_URL has no port and no known default for scheme {:?}",
            parsed_dash.scheme()
        )
    })?;
    if target_port != dash_port {
        return Err(format!(
            "target_url port {target_port} does not match DASHBOARD_URL port {dash_port}"
        ));
    }

    // 4. Resolve DNS and reject private/loopback/link-local/ULA/multicast/broadcast
    //    addresses — DNS-rebinding defence. `is_private_ip` lives in `update`
    //    and already covers the SSRF surface for the self-update path; reuse
    //    the same predicate here.
    let lookup = tokio::net::lookup_host(format!("{target_host}:{target_port}"))
        .await
        .map_err(|e| format!("DNS lookup of {target_host} failed: {e}"))?;
    let addrs: Vec<std::net::SocketAddr> = lookup.collect();
    if addrs.is_empty() {
        return Err(format!(
            "DNS lookup of {target_host} returned no addresses"
        ));
    }
    for addr in addrs.iter().take(16) {
        let ip: IpAddr = addr.ip();
        if is_private_or_reserved_ip(ip) {
            return Err(format!(
                "target_url {target_host} resolves to private/reserved IP {ip}"
            ));
        }
    }

    Ok(())
}

/// IP-address surface for SSRF rejection in `validate_migrate_target`.
///
/// Mirrors `update::is_private_ip` (which gates the self-update fetch) and
/// adds the `is_multicast` / `is_broadcast` cases the standard requires but
/// that the update path got away with skipping because its URL allowlist
/// (`github.com` / `objects.githubusercontent.com`) never returns those kinds
/// of records.
fn is_private_or_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xff00) == 0xff00 // ff00::/8 multicast
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_migrate_target;

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
        let r = validate_migrate_target(
            "file:///etc/passwd",
            "https://dashboard.example",
        )
        .await;
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
}
