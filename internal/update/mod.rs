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
	// pin check at the "Verify signatures against the pinned install key" step in `.github/workflows/release.yml`.)
	[
		0x1c, 0x5b, 0xfb, 0xbe, 0x0e, 0x45, 0x09, 0x8e, 0xd8, 0xc8, 0xa5, 0x03, 0x6c, 0x98, 0x5a,
		0x41, 0x27, 0xc1, 0xf5, 0x26, 0xe8, 0x24, 0x64, 0x9b, 0x94, 0x9b, 0x45, 0x6c, 0xb9, 0x8b,
		0x1f, 0x33,
	],
	// Slot 1: empty (no rotation in flight).
	[0u8; 32],
];

/// Reference for the release.yml pin-check (the "Verify signatures against the pinned install key" step in `.github/workflows/release.yml` greps the b64 literal in setup-agent.sh,
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
mod tests;
