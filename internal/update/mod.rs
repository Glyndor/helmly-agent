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
        let outcome = run_startup_health_check(
            || async {
                let client = match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(3))
                    .build()
                {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                client
                    .get("http://127.0.0.1:9090/health") // audit-urls: ok — self health check, not a download
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            },
            15,
            std::time::Duration::from_secs(2),
            AGENT_BINARY,
            CRITICAL_FILE,
        )
        .await;

        if let Err(reason) = outcome {
            tracing::error!(reason, "critical state — exiting for systemd restart");
            std::process::exit(1);
        }
    });
}

/// Inner health-check loop extracted from `spawn_startup_health_guard` so
/// tests can drive it with a stubbed health check and a tiny interval.
///
/// On health success the function deletes `critical_file` if present
/// (recovery from a previous failed startup) and returns `Ok(())`. After
/// `max_attempts` failures it attempts to restore `{agent_binary}.prev`
/// over `agent_binary`, writes the `critical_file` with the outcome,
/// and returns `Err(reason)`. The caller is responsible for translating
/// `Err` into `std::process::exit(1)`.
pub(crate) async fn run_startup_health_check<F, Fut>(
    mut health_check: F,
    max_attempts: usize,
    attempt_interval: std::time::Duration,
    agent_binary: &str,
    critical_file: &str,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..max_attempts {
        tokio::time::sleep(attempt_interval).await;
        if health_check().await {
            // Healthy — clear any leftover CRITICAL file from a previous failed startup.
            let _ = std::fs::remove_file(critical_file);
            return Ok(());
        }
    }

    // Still unhealthy after all attempts — attempt .prev restore.
    tracing::error!("startup health check failed — restoring .prev binary");
    let target = PathBuf::from(agent_binary);
    let prev = PathBuf::from(format!("{agent_binary}.prev"));

    let restore_ok = if prev.exists() {
        // Atomic rename to avoid ETXTBSY — the current binary is a running executable,
        // so copy() with O_TRUNC fails. Write to .new first, then rename (POSIX atomic).
        let tmp = PathBuf::from(format!("{agent_binary}.restoring"));
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
        critical_file,
        format!("timestamp={ts}\ncomponent=helmly-agent\nreason={reason}\n"),
    );

    Err(reason.to_string())
}

/// Inner download loop extracted from `download_bytes` so tests can
/// drive it with a tiny `max_bytes` cap (200 MiB is impractical in a
/// unit test). The HTTP fetch path, status check, Content-Length cap,
/// and body-length cap are unchanged — this is the same code with a
/// parameter in place of the constant.
pub(crate) async fn download_bytes_with(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} for {url}", resp.status());
    }

    // content_length is a hint; we still cap to max_bytes
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            anyhow::bail!("Content-Length {len} exceeds {max_bytes} safety limit");
        }
    }

    let bytes = resp.bytes().await.context("read response body")?;
    if bytes.len() > max_bytes {
        anyhow::bail!("download exceeded {max_bytes} safety limit");
    }
    Ok(bytes.to_vec())
}

async fn download_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    download_bytes_with(client, url, 200 * 1024 * 1024).await
}

/// C2: two-slot release verify pubkey, mirroring `podup`'s `RELEASE_PUBKEYS`
/// (`standards/releases/index.md:52-58`). Slot 0 is the active signing
/// key; slot 1 carries the next key during a two-phase rotation, or is
/// all-zero when no rotation is in flight. A zeroed slot is skipped
/// during verify; if both slots are zeroed the verify fails closed.
///
/// Slot 1 must be `GLYNDOR_RELEASE_ED25519_KEY`'s predecessor or successor
/// at the moment of the release. Operators: the new key goes in slot 1
/// of the *next* release; after telemetry confirms every agent holds it,
/// the *next-next* release swaps slot 0 to the new key and zeroes slot 1.
pub(crate) const RELEASE_PUBKEYS: &[[u8; 32]; 2] = &[
    // Slot 0: GLYNDOR_RELEASE_ED25519_KEY = HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=
    // (kept in sync with `RELEASE_VERIFY_KEY_B64` below via the release.yml
    // pin check at `.github/workflows/release.yml:107-111`.)
    [
        0x1c, 0x5b, 0xfb, 0xbe, 0x0e, 0x45, 0x09, 0x8e, 0xd8, 0xc8, 0xa5, 0x03, 0x6c, 0x98, 0x5a,
        0x41, 0x27, 0xc1, 0xf5, 0x26, 0xe8, 0x24, 0x64, 0x9b, 0x94, 0x9b, 0x45, 0x6c, 0xb9, 0x8b,
        0x1f, 0x33,
    ],
    // Slot 1: empty (no rotation in flight).
    [0u8; 32],
];

/// Reference for the release.yml pin-check (`.github/workflows/
/// release.yml:107-111` greps the b64 literal in setup-agent.sh,
/// update-agent.sh, and this file to assert the three agree). The
/// actual verification path uses `RELEASE_PUBKEYS` above.
#[allow(dead_code)]
pub(crate) const RELEASE_VERIFY_KEY_B64: &str = "HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=";

/// Iterate non-zeroed pubkey slots in `keyring` and accept the first
/// one that verifies. Zeroed slots are skipped. If none verify, fail
/// closed. `verify_signature` calls this with the embedded
/// `RELEASE_PUBKEYS`; tests call it with synthetic keys.
fn verify_signature_with(binary: &[u8], sig_bytes: &[u8], keyring: &[[u8; 32]]) -> Result<()> {
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes, got {}", sig_bytes.len()))?;
    let sig = Signature::from_bytes(&sig_arr);

    let mut last_err: Option<anyhow::Error> = None;
    let mut matched = false;
    for (i, slot) in keyring.iter().enumerate() {
        if slot == &[0u8; 32] {
            continue;
        }
        let key = match VerifyingKey::from_bytes(slot) {
            Ok(k) => k,
            Err(e) => {
                last_err = Some(anyhow::anyhow!("keyring slot {i} invalid: {e}"));
                continue;
            }
        };
        if key.verify(binary, &sig).is_ok() {
            matched = true;
            break;
        }
        last_err = Some(anyhow::anyhow!(
            "release signature did not verify against slot {i}"
        ));
    }
    if matched {
        Ok(())
    } else {
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("release signature did not verify against any non-zeroed slot")
        }))
    }
}

fn verify_signature(binary: &[u8], sig_bytes: &[u8]) -> Result<()> {
    verify_signature_with(binary, sig_bytes, RELEASE_PUBKEYS)
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
    use super::{check_install_method_marker_at, verify_signature_with};
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

    // ---- C2: release-keyring rotation tests (added during rebase of
    // C2's fix/c2-keyring branch onto the C3-merged develop) ----

    /// C2: regression — any non-zeroed slot in the keyring verifies its
    /// own signature. Today's behaviour, one active key.
    #[test]
    fn release_verify_accepts_any_non_zeroed_slot() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let pub_key = signing.verifying_key().to_bytes();
        let binary = b"helmly-agent binary";
        let sig = signing.sign(binary);
        let keyring = [[0u8; 32], pub_key];
        assert!(
            verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
            "any non-zeroed slot that matches must verify"
        );
    }

    /// C2: regression — two-phase rotation. The OLD key continues to
    /// verify on agents that already hold `[OLD, NEW]` (slot 1 just added
    /// for the new key).
    #[test]
    fn release_verify_old_key_works_after_new_key_added() {
        use ed25519_dalek::Signer;
        let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        let binary = b"transition release signed by old";
        let sig = old.sign(binary);
        let keyring = [
            old.verifying_key().to_bytes(),
            new.verifying_key().to_bytes(),
        ];
        assert!(
            verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
            "transition release signed by OLD must verify against the [OLD,NEW] ring"
        );
    }

    /// C2: regression — the NEW key verifies against the [OLD,NEW] ring.
    /// (The cut-over to `[NEW, ZERO]` ships in the *next* release; this
    /// test exercises the mid-rotation state.)
    #[test]
    fn release_verify_new_key_works_in_two_slot_ring() {
        use ed25519_dalek::Signer;
        let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        let binary = b"transition release signed by new";
        let sig = new.sign(binary);
        let keyring = [
            old.verifying_key().to_bytes(),
            new.verifying_key().to_bytes(),
        ];
        assert!(
            verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
            "transition release signed by NEW must verify against the [OLD,NEW] ring"
        );
    }

    /// C2: regression — cut-over. After Phase 2, slot 0 is the new
    /// key and slot 1 is zeroed. A release signed by the OLD key no
    /// longer verifies (operator has retired OLD).
    #[test]
    fn release_verify_old_key_rejected_after_cutover() {
        use ed25519_dalek::Signer;
        let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        let binary = b"forged release signed by retired OLD";
        let sig = old.sign(binary);
        let keyring = [new.verifying_key().to_bytes(), [0u8; 32]];
        let r = verify_signature_with(binary, &sig.to_bytes(), &keyring);
        let err = r.expect_err("OLD key after cut-over must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("did not verify against slot 0") || msg.contains("no non-zeroed slot"),
            "rejection must name the cause; got: {msg}"
        );
    }

    /// C2: regression — a forged signature (made by a key that's never
    /// been in the ring) is rejected, even if the ring has both slots
    /// populated. Fail closed.
    #[test]
    fn release_verify_rejects_forged_signature() {
        use ed25519_dalek::Signer;
        let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let binary = b"binary";
        let sig = attacker.sign(binary);
        let keyring = [
            old.verifying_key().to_bytes(),
            new.verifying_key().to_bytes(),
        ];
        assert!(
            verify_signature_with(binary, &sig.to_bytes(), &keyring).is_err(),
            "forged signature must fail closed"
        );
    }

    /// C2: regression — an empty keyring (both slots zeroed) fails
    /// closed. Removing the iteration entirely (i.e. always returning
    /// Ok) makes this go red.
    #[test]
    fn release_verify_rejects_when_keyring_all_zeroed() {
        let keyring = [[0u8; 32], [0u8; 32]];
        let r = verify_signature_with(b"binary", &[0u8; 64], &keyring);
        let err = r.expect_err("zeroed keyring must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("any non-zeroed slot"),
            "rejection must name the cause; got: {msg}"
        );
    }

    // ---- download_bytes happy path -----------------------------------------
    //
    // The download loop is extracted as `download_bytes_with(client, url,
    // max_bytes)` so tests can drive it with a small cap (the production
    // 200 MiB would be impractical in a unit test). The HTTP path, status
    // check, and both size caps are unchanged — only the constant became a
    // parameter. Tests run against a real in-process axum server bound to
    // 127.0.0.1 on an ephemeral port, so the SSRF safe-client wrapper is
    // bypassed and the actual HTTP behaviour is exercised end-to-end.

    use super::download_bytes_with;

    /// Spin up a one-route axum server on 127.0.0.1:<random> that
    /// returns `status` and `body` for every request. Returns the URL
    /// the test should hand to `download_bytes_with`.
    async fn spawn_http_server(status: u16, body: Vec<u8>) -> String {
        use axum::{body::Body, http::StatusCode, response::Response, routing::get, Router};
        use std::sync::Arc;
        let body = Arc::new(body);
        let status = StatusCode::from_u16(status).unwrap();
        let app = Router::new().route(
            "/",
            get(move || {
                let body = Arc::clone(&body);
                let status = status;
                async move {
                    let mut resp = Response::new(Body::from((*body).clone()));
                    *resp.status_mut() = status;
                    resp
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    /// Server returns a streaming body of `chunk_count` chunks of
    /// `chunk_size` bytes each, with **no** `Content-Length` header
    /// (HTTP/1.1 chunked transfer encoding). Used to exercise the
    /// post-read size cap: with no `Content-Length`, the pre-read
    /// check is skipped, so the post-read `bytes.len() > max_bytes`
    /// arm is what must reject an over-cap response.
    async fn spawn_http_server_streaming(chunk_count: usize, chunk_size: usize) -> String {
        use axum::{body::Body, routing::get, Router};
        use futures_util::stream;
        let app = Router::new().route(
            "/",
            get(move || async move {
                let stream = stream::iter((0..chunk_count).map(move |_| {
                    Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; chunk_size]))
                }));
                Body::from_stream(stream)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{}/", addr.port())
    }

    /// Happy path: 2xx with body under the cap returns the bytes.
    /// Mutating `download_bytes_with` to always return `Ok(vec![])` makes
    /// this go red.
    #[tokio::test]
    async fn download_bytes_with_2xx_returns_body() {
        let body = b"helmly-agent binary blob".to_vec();
        let url = spawn_http_server(200, body.clone()).await;
        let client = reqwest::Client::new();
        let bytes = download_bytes_with(&client, &url, 1024)
            .await
            .expect("2xx under cap must Ok");
        assert_eq!(bytes, body, "must return the full body");
    }

    /// Pre-read Content-Length cap: axum auto-sets Content-Length to the
    /// body length, so a 100-byte body with cap=50 is rejected by the
    /// `if len > max_bytes` arm before the body is read. Removing that
    /// arm makes this go red.
    #[tokio::test]
    async fn download_bytes_with_oversize_content_length_errors() {
        let body = vec![b'x'; 100];
        let url = spawn_http_server(200, body).await;
        let client = reqwest::Client::new();
        let r = download_bytes_with(&client, &url, 50).await;
        let err = r.expect_err("body > cap must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Content-Length 100 exceeds 50 safety limit"),
            "pre-read cap must name the cause; got: {msg}"
        );
    }

    /// Post-read body-length cap: streaming response with no
    /// Content-Length header. The pre-read check is skipped (no header),
    /// so the `if bytes.len() > max_bytes` arm is what must fire.
    /// Removing that arm makes this go red.
    #[tokio::test]
    async fn download_bytes_with_oversize_streaming_body_errors() {
        // 100 chunks × 1 byte = 100 bytes streamed, no Content-Length.
        let url = spawn_http_server_streaming(100, 1).await;
        let client = reqwest::Client::new();
        let r = download_bytes_with(&client, &url, 50).await;
        let err = r.expect_err("streaming body > cap must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeded 50 safety limit"),
            "post-read cap must name the cause; got: {msg}"
        );
    }

    /// Status check: 4xx must be rejected. Removing the
    /// `!resp.status().is_success()` arm makes this go red.
    #[tokio::test]
    async fn download_bytes_with_4xx_errors() {
        let url = spawn_http_server(404, Vec::new()).await;
        let client = reqwest::Client::new();
        let r = download_bytes_with(&client, &url, 1024).await;
        let err = r.expect_err("4xx must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("404"),
            "rejection must surface status; got: {msg}"
        );
    }

    /// Status check: 5xx must be rejected. Same mutation as above.
    #[tokio::test]
    async fn download_bytes_with_5xx_errors() {
        let url = spawn_http_server(503, Vec::new()).await;
        let client = reqwest::Client::new();
        let r = download_bytes_with(&client, &url, 1024).await;
        let err = r.expect_err("5xx must fail; got Ok");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("503"),
            "rejection must surface status; got: {msg}"
        );
    }

    /// Network error: a closed local port must produce an error (the
    /// status / size checks never run). Binding to 0 and immediately
    /// dropping the listener gives ECONNREFUSED without depending on
    /// any external service.
    #[tokio::test]
    async fn download_bytes_with_connection_refused_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .unwrap();
        let r = download_bytes_with(&client, &url, 1024).await;
        assert!(r.is_err(), "connection refused must fail; got Ok");
    }

    // ---- spawn_startup_health_guard happy path -----------------------------
    //
    // The health-check loop is extracted as
    // `run_startup_health_check(check, max_attempts, interval, binary, crit)`
    // so tests can substitute a stub health check and a 1 ms interval
    // (production uses 15 × 2 s — too slow for unit tests). The loop body,
    // restore path, and CRITICAL-file write are unchanged; only the call
    // sites became parameters. Production behaviour is preserved:
    // `spawn_startup_health_guard` still calls this helper and translates
    // `Err(_)` into `std::process::exit(1)`.

    use super::run_startup_health_check;

    fn unique_tmp(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "helmly-agent-test-{}-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            label,
        ));
        p
    }

    /// Happy path: health returns true on the first attempt — the
    /// leftover CRITICAL file must be removed and the call must Ok.
    /// Removing the `remove_file(critical_file)` line makes this go red.
    #[tokio::test]
    async fn health_check_passes_and_clears_critical_when_healthy() {
        let binary = unique_tmp("healthy-bin");
        let crit = unique_tmp("healthy-crit");
        std::fs::write(&crit, "leftover from a previous failed startup").unwrap();
        assert!(crit.exists(), "pre-condition: CRITICAL exists");

        let r = run_startup_health_check(
            || async { true },
            1,
            std::time::Duration::from_millis(1),
            &binary.to_string_lossy(),
            &crit.to_string_lossy(),
        )
        .await;
        assert!(r.is_ok(), "healthy must Ok; got: {r:?}");
        assert!(
            !crit.exists(),
            "CRITICAL file must be removed on healthy startup"
        );
    }

    /// Failure path with restorable .prev: after the loop exhausts, the
    /// helper copies `.prev` over the binary and writes CRITICAL with
    /// `restored .prev`. The binary contents must now match `.prev`.
    /// Removing the `std::fs::copy + rename` block makes the CRITICAL
    /// file say `MANUAL RECOVERY` instead — assertion catches that.
    #[tokio::test]
    async fn health_check_writes_critical_with_prev_restored() {
        let binary = unique_tmp("restore-bin");
        let prev = std::path::PathBuf::from(format!("{}.prev", binary.display()));
        let crit = unique_tmp("restore-crit");
        std::fs::write(&binary, "new binary contents").unwrap();
        std::fs::write(&prev, "previous binary contents").unwrap();

        let r = run_startup_health_check(
            || async { false },
            1,
            std::time::Duration::from_millis(1),
            &binary.to_string_lossy(),
            &crit.to_string_lossy(),
        )
        .await;
        let reason = r.expect_err("unhealthy must Err");
        assert!(
            reason.contains("restored .prev"),
            "reason must name restore outcome; got: {reason}"
        );

        let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
        assert!(
            crit_content.contains("restored .prev"),
            "CRITICAL file must name the cause; got: {crit_content}"
        );
        assert!(
            crit_content.contains("component=helmly-agent"),
            "CRITICAL must identify the component; got: {crit_content}"
        );

        let binary_contents = std::fs::read_to_string(&binary).unwrap();
        assert_eq!(
            binary_contents, "previous binary contents",
            "restore must overwrite the binary with .prev contents"
        );
    }

    /// Failure path with .prev missing: CRITICAL must say
    /// `MANUAL RECOVERY`. Removing the `else { false }` branch in the
    /// restore logic, or the unconditional CRITICAL write after the loop,
    /// makes this go red.
    #[tokio::test]
    async fn health_check_writes_critical_manual_recovery_when_prev_missing() {
        let binary = unique_tmp("noprev-bin");
        let crit = unique_tmp("noprev-crit");
        std::fs::write(&binary, "new binary").unwrap();
        // Intentionally no .prev written.

        let r = run_startup_health_check(
            || async { false },
            1,
            std::time::Duration::from_millis(1),
            &binary.to_string_lossy(),
            &crit.to_string_lossy(),
        )
        .await;
        let reason = r.expect_err("unhealthy + no .prev must Err");
        assert!(
            reason.contains("MANUAL RECOVERY"),
            "reason must name manual recovery; got: {reason}"
        );

        let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
        assert!(
            crit_content.contains("MANUAL RECOVERY"),
            "CRITICAL must name manual recovery; got: {crit_content}"
        );
        // The new binary must NOT have been overwritten — nothing to
        // restore from.
        let binary_contents = std::fs::read_to_string(&binary).unwrap();
        assert_eq!(
            binary_contents, "new binary",
            "binary must be untouched when .prev is missing"
        );
    }

    /// Failure path with .prev unreadable (0o000 on Unix): the copy()
    /// fails, restore_ok is false, CRITICAL must say `MANUAL RECOVERY`.
    /// Restoring read permissions after the test so the temp directory
    /// doesn't leave an unreadable file behind for the OS to clean up.
    #[cfg(unix)]
    #[tokio::test]
    async fn health_check_writes_critical_manual_recovery_when_prev_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let binary = unique_tmp("unreadable-bin");
        let prev = std::path::PathBuf::from(format!("{}.prev", binary.display()));
        let crit = unique_tmp("unreadable-crit");
        std::fs::write(&binary, "new binary").unwrap();
        std::fs::write(&prev, "previous binary").unwrap();
        std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = run_startup_health_check(
            || async { false },
            1,
            std::time::Duration::from_millis(1),
            &binary.to_string_lossy(),
            &crit.to_string_lossy(),
        )
        .await;

        // Restore perms before any assertion that could fail — otherwise
        // a panic here would leave 0o000 on a temp file (annoying to
        // debug, though not a security issue since the file is empty).
        std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o600)).unwrap();

        let reason = r.expect_err("unhealthy + unreadable .prev must Err");
        assert!(
            reason.contains("MANUAL RECOVERY"),
            "reason must name manual recovery; got: {reason}"
        );

        let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
        assert!(
            crit_content.contains("MANUAL RECOVERY"),
            "CRITICAL must name manual recovery; got: {crit_content}"
        );
    }
}
