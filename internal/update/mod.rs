pub mod fallback;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::PathBuf;

const AGENT_BINARY: &str = "/etc/glyndor/helmly/bin/helmly-agent";
const CRITICAL_FILE: &str = "/etc/glyndor/helmly/CRITICAL";

/// Download new binary, verify Ed25519 signature, backup to .prev, atomic swap, restart via systemd.
///
/// The release verify key (`RELEASE_VERIFY_KEY_B64`) is compiled into the binary and is distinct
/// from the dashboard command-signing key. The corresponding private key lives only in GitHub
/// Actions secrets — compromising the repo or the dashboard does not allow forging signatures.
pub async fn perform_update(version: &str, download_url: &str, sig_url: &str) -> Result<()> {
    validate_github_url(download_url)?;
    validate_github_url(sig_url)?;

    // C3: refuse to overwrite a dpkg-managed binary. The marker file is
    // written by `setup-agent.sh` (value "script") and by the future
    // `helmly-agent.deb` postinst (value "dpkg"). Absence defaults to
    // "script" so today's installs continue to self-update. Fail-closed
    // on unreadable / invalid contents — a corrupted marker must not
    // silently degrade to script-style overwrite on top of a dpkg
    // record. Operator rollback: `sudo rm /etc/glyndor/helmly/.install-method`.
    check_install_method_marker_at(INSTALL_METHOD_MARKER_PATH)?;

    tracing::info!(version, "starting self-update");

    // Build separate SSRF-safe clients per URL: resolves DNS once, validates
    // the resolved IP is not RFC1918/loopback, then pins the hostname to that
    // IP for the actual request (prevents DNS TOCTOU rebinding attacks).
    let bin_client = build_ssrf_safe_client(download_url)
        .await
        .context("SSRF check for binary URL")?;
    let sig_client = build_ssrf_safe_client(sig_url)
        .await
        .context("SSRF check for sig URL")?;

    // Download binary
    let binary_bytes = download_bytes(&bin_client, download_url)
        .await
        .context("download binary")?;

    // Download signature
    let sig_bytes = download_bytes(&sig_client, sig_url)
        .await
        .context("download signature")?;

    // Verify Ed25519 signature
    verify_signature(&binary_bytes, &sig_bytes)
        .context("signature verification failed — update aborted")?;

    tracing::info!(version, bytes = binary_bytes.len(), "signature verified");

    let target = PathBuf::from(AGENT_BINARY);
    let prev = PathBuf::from(format!("{AGENT_BINARY}.prev"));
    let tmp = PathBuf::from(format!("{AGENT_BINARY}.new"));

    std::fs::write(&tmp, &binary_bytes).with_context(|| format!("write to {tmp:?}"))?;

    // Make it executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms)?;
    }

    // Back up current binary to .prev before swap
    if target.exists() {
        std::fs::copy(&target, &prev).context("backup agent binary to .prev")?;
    }

    // Atomic rename: tmp → canonical path (POSIX atomic on same filesystem)
    std::fs::rename(&tmp, &target).with_context(|| format!("rename {tmp:?} → {target:?}"))?;

    tracing::info!(version, "binary swapped — restarting via systemd");

    // Systemd will restart the unit (Restart=always in the service unit).
    // Exit 0 so systemd records a clean restart, not a failure.
    std::process::exit(0);
}

/// Spawn a background task that monitors agent startup health.
///
/// Polls `http://127.0.0.1:9090/health` every 2s for 30s.
/// If still unhealthy → attempt `.prev` restore and exit 1 (systemd restarts with old binary).
/// If `.prev` unavailable or restore fails → write `/etc/glyndor/helmly/CRITICAL` and exit 1.
/// On healthy startup → delete `/etc/glyndor/helmly/CRITICAL` if present (recovery from prior critical state).
pub fn spawn_startup_health_guard() {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if client
                .get("http://127.0.0.1:9090/health") // audit-urls: ok — self health check, not a download
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                // Healthy — clear any leftover CRITICAL file from a previous failed startup.
                let _ = std::fs::remove_file(CRITICAL_FILE);
                return;
            }
        }

        // Still unhealthy after 30s — attempt .prev restore.
        tracing::error!("startup health check failed — restoring .prev binary");
        let target = PathBuf::from(AGENT_BINARY);
        let prev = PathBuf::from(format!("{AGENT_BINARY}.prev"));

        let restore_ok = if prev.exists() {
            // Atomic rename to avoid ETXTBSY — the current binary is a running executable,
            // so copy() with O_TRUNC fails. Write to .new first, then rename (POSIX atomic).
            let tmp = PathBuf::from(format!("{AGENT_BINARY}.restoring"));
            std::fs::copy(&prev, &tmp).is_ok() && std::fs::rename(&tmp, &target).is_ok()
        } else {
            false
        };

        let reason = if restore_ok {
            "new binary failed health check; restored .prev"
        } else {
            "new binary failed health check; .prev unavailable — MANUAL RECOVERY REQUIRED"
        };

        let ts = chrono::Utc::now().to_rfc3339();
        let _ = std::fs::write(
            CRITICAL_FILE,
            format!("timestamp={ts}\ncomponent=helmly-agent\nreason={reason}\n"),
        );

        tracing::error!(reason, "critical state — exiting for systemd restart");
        std::process::exit(1);
    });
}

async fn download_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} for {url}", resp.status());
    }

    // content_length is a hint; we still cap to 200 MiB
    if let Some(len) = resp.content_length() {
        if len > 200 * 1024 * 1024 {
            anyhow::bail!("Content-Length {len} exceeds 200 MiB safety limit");
        }
    }

    let bytes = resp.bytes().await.context("read response body")?;
    if bytes.len() > 200 * 1024 * 1024 {
        anyhow::bail!("download exceeded 200 MiB safety limit");
    }
    Ok(bytes.to_vec())
}

fn verify_signature(binary: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let key_bytes = load_verify_key()?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("parse DASHBOARD_VERIFY_KEY")?;

    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes, got {}", sig_bytes.len()))?;
    let sig = Signature::from_bytes(&sig_arr);

    key.verify(binary, &sig)
        .context("Ed25519 signature invalid")
}

const RELEASE_VERIFY_KEY_B64: &str = "HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=";

fn load_verify_key() -> Result<[u8; 32]> {
    use base64ct::{Base64, Encoding};
    let bytes = Base64::decode_vec(RELEASE_VERIFY_KEY_B64)
        .context("decode hardcoded release verify key")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("release verify key must be 32 bytes"))
}

fn validate_github_url(url: &str) -> Result<()> {
    let allowed = [
        "https://github.com/",
        "https://objects.githubusercontent.com/",
    ];
    if allowed.iter().any(|prefix| url.starts_with(prefix)) {
        Ok(())
    } else {
        anyhow::bail!("download URL not on allowed domain: {url}")
    }
}

/// Builds an HTTP client with SSRF protection:
/// 1. Resolves the hostname of `url` via DNS (once).
/// 2. Rejects if any resolved IP is RFC1918, loopback, or link-local.
/// 3. Pins the hostname to the validated IP so reqwest never re-resolves it
///    (prevents DNS rebinding / TOCTOU attacks).
async fn build_ssrf_safe_client(url: &str) -> Result<reqwest::Client> {
    let parsed = url::Url::parse(url).context("parse URL for SSRF check")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("URL has unknown port: {url}"))?;

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .with_context(|| format!("DNS lookup for {host}"))?
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("DNS lookup for {host} returned no addresses");
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            anyhow::bail!(
                "SSRF protection: {host} resolved to private/reserved IP {}",
                addr.ip()
            );
        }
    }

    reqwest::Client::builder()
        .user_agent(format!("helmly-agent/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(300))
        .resolve(&host, addrs[0])
        .build()
        .context("build SSRF-safe HTTP client")
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Path to the install-method marker file. Set by `setup-agent.sh` and
/// (in the future) by the debian postinst. Read by `check_install_method_marker`.
pub(crate) const INSTALL_METHOD_MARKER_PATH: &str = "/etc/glyndor/helmly/.install-method";

/// C3: refuse to overwrite an apt-managed helmly-agent binary.
///
/// Marker values:
/// - `"script"` — installed by `setup-agent.sh`. Self-update is allowed.
/// - `"dpkg"` — installed (or upgraded to) by the helmly-agent `.deb`.
///   Self-update is refused; the operator runs `apt upgrade helmly-agent`.
/// - Absent — treated as `"script"` (preserves behaviour of every
///   pre-marker install).
/// - Anything else, or unreadable — fail closed.
///
/// The path is an argument so unit tests can point at a temp file; the
/// `perform_update` caller passes the constant.
pub(crate) fn check_install_method_marker_at(path: &str) -> Result<()> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No marker — assume script-installed (today's behaviour).
            return Ok(());
        }
        Err(e) => {
            anyhow::bail!(
                "{path} is unreadable ({e}); refusing self-update. \
                 Delete the file to allow script-based updates, or fix it \
                 to contain exactly 'script' or 'dpkg'."
            );
        }
    };
    match contents.trim() {
        "script" => Ok(()),
        "dpkg" => {
            anyhow::bail!(
                "{path} marks this install as managed by a package manager \
                 (helmly-agent.deb). Run `apt upgrade helmly-agent` (or \
                 the equivalent for your package manager) instead of \
                 triggering an in-band self-update. To roll back the \
                 check, `sudo rm {path}`."
            );
        }
        other => {
            anyhow::bail!(
                "{path} contains an unrecognised value {other:?}; refusing \
                 self-update. Allowed values: 'script' or 'dpkg'. \
                 Delete the file to roll back."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check_install_method_marker_at;
    use std::io::Write;

    fn tmp_marker(content: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "helmly-agent-install-method-{}-{}.marker",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut f = std::fs::File::create(&path).expect("create tmp marker");
        f.write_all(content.as_bytes()).expect("write tmp marker");
        path
    }

    /// C3: missing marker is treated as "script" — preserves today's
    /// behaviour of every pre-marker install.
    #[test]
    fn install_method_marker_absent_is_ok() {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "helmly-agent-install-method-{}-{}-absent.marker",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&p);
        assert!(check_install_method_marker_at(p.to_str().unwrap()).is_ok());
    }

    /// C3: marker = "script" allows self-update (today's path).
    #[test]
    fn install_method_marker_script_allows() {
        let p = tmp_marker("script\n");
        assert!(check_install_method_marker_at(p.to_str().unwrap()).is_ok());
    }

    /// C3: marker = "dpkg" refuses self-update. Reverting the
    /// `bail!` arm back to `Ok(())` makes this test go red.
    #[test]
    fn install_method_marker_dpkg_refuses() {
        let p = tmp_marker("dpkg\n");
        let r = check_install_method_marker_at(p.to_str().unwrap());
        let err = match r {
            Ok(()) => panic!("dpkg marker must refuse self-update; got Ok"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("managed by a package manager"),
            "refusal message must name the cause; got: {msg}"
        );
    }

    /// C3: an unrecognised value fails closed (refuses self-update).
    /// Defends against typos or attacker edits to the marker.
    #[test]
    fn install_method_marker_invalid_value_refuses() {
        let p = tmp_marker("docker\n");
        let r = check_install_method_marker_at(p.to_str().unwrap());
        let err = r.expect_err("invalid marker must fail closed; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unrecognised value"),
            "invalid-value message must name the cause; got: {msg}"
        );
    }

    /// C3: a file the agent cannot read also fails closed.
    /// Use the absolute path to a directory — opening a directory as a
    /// file is an I/O error kind that is NOT NotFound.
    #[cfg(unix)]
    #[test]
    fn install_method_marker_unreadable_refuses() {
        let r = check_install_method_marker_at("/proc");
        let err = r.expect_err("unreadable marker must fail closed; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unreadable"),
            "unreadable-message must name the cause; got: {msg}"
        );
    }
}
