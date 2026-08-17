use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use zeroize::Zeroizing;

/// Path to the persistent dashboard verify-keyring file (C2). On first
/// boot the agent seeds this from the legacy `DASHBOARD_VERIFY_KEY` env
/// so existing single-key deployments continue to verify their existing
/// commands; the operator then rotates keys in-band by writing a new line
/// to this file (one base64 32-byte key per line).
pub(crate) const DASHBOARD_KEYRING_PATH: &str = "/etc/glyndor/helmly/dashboard-keyring";

pub struct Config {
    pub database_url: String,
    pub agent_id: uuid::Uuid,
    pub version: String,
    /// C2: ring of Ed25519 public key bytes (32 each), wrapped in
    /// `Zeroizing` so the heap copy is wiped on drop. Verified against
    /// each entry at `verify_command` time — converting to `VerifyingKey`
    /// for the ed25519-dalek call is cheap and avoids storing the parsed
    /// type (which doesn't implement `Zeroize`).
    ///
    /// Loader order: file first, else env (seed-on-load), else error.
    /// Always non-empty — empty rings fail-closed at `verify_command`.
    /// Two-phase rotation adds a second key to the ring while the old
    /// one is still active, then drops the old one — mirroring `podup`'s
    /// `RELEASE_PUBKEYS` two-slot pattern (`standards/releases/index.md:52-58`).
    pub dashboard_verify_keys: Zeroizing<Vec<[u8; 32]>>,
    /// Bearer token for dashboard→agent API calls (internal, WireGuard-only)
    pub internal_token: Zeroizing<String>,
    pub listen_addr: String,
    /// Dashboard API base URL via WireGuard (e.g. http://10.100.0.1:8080). Optional.
    pub dashboard_url: Option<String>,
    /// Sync token for agent→dashboard audit log sync. Optional — sync disabled if absent.
    pub sync_token: Option<Zeroizing<String>>,
    /// X.509 TLS server certificate DER — for mTLS listener. None = plain HTTP.
    pub tls_cert_der: Option<Vec<u8>>,
    /// X.509 TLS server private key DER (PKCS#8).
    pub tls_key_der: Option<Zeroizing<Vec<u8>>>,
    /// X.509 CA certificate DER — used to verify dashboard client certs.
    pub tls_ca_cert_der: Option<Vec<u8>>,
    /// Dashboard panel port to open in nftables (Some(19443) on dashboard VPS, None on remote agents).
    pub dashboard_port: Option<u16>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let database_url = load_secret("DATABASE_URL")
            .map(|s| s.as_str().to_owned())
            .context("DATABASE_URL or DATABASE_URL_FILE required")?;

        let agent_id_str = std::env::var("AGENT_ID").context("AGENT_ID required")?;
        let agent_id = uuid::Uuid::parse_str(&agent_id_str).context("AGENT_ID must be UUID v7")?;

        // C2: dashboard verify-keyring. Loader order (file-first):
        // 1. `/etc/glyndor/helmly/dashboard-keyring` — one b64 32-byte key per line,
        //    blank/`#` lines skipped. Mode 0o600 enforced.
        // 2. Legacy `DASHBOARD_VERIFY_KEY` / `_FILE` — single key. On first
        //    boot, the agent seeds-on-load: writes the file atomically so
        //    the next start reads the ring instead of the env.
        // 3. Else error out — matches today's failure mode.
        let dashboard_verify_keys = load_dashboard_keyring().context(
            "no dashboard verify keys: supply DASHBOARD_VERIFY_KEY (legacy single-key env) \
             or seed /etc/glyndor/helmly/dashboard-keyring with at least one b64 32-byte line",
        )?;
        if dashboard_verify_keys.is_empty() {
            anyhow::bail!(
                "dashboard verify keyring is empty; refusing all commands. \
                 Add at least one key to /etc/glyndor/helmly/dashboard-keyring."
            );
        }
        let internal_token = load_secret("INTERNAL_TOKEN")?;
        let listen_addr =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9090".to_string());
        let dashboard_url = std::env::var("DASHBOARD_URL").ok();
        let sync_token = load_secret_opt("SYNC_TOKEN");
        let version = std::env::var("AGENT_VERSION")
            .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());

        let tls_cert_der = load_der_file_opt("TLS_CERT_DER_FILE");
        let tls_key_der = load_der_file_zeroize_opt("TLS_KEY_DER_FILE");
        let tls_ca_cert_der = load_der_file_opt("TLS_CA_CERT_DER_FILE");

        let dashboard_port = std::env::var("DASHBOARD_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok());

        Ok(Config {
            database_url,
            agent_id,
            dashboard_verify_keys,
            internal_token,
            listen_addr,
            dashboard_url,
            sync_token,
            version,
            tls_cert_der,
            tls_key_der,
            tls_ca_cert_der,
            dashboard_port,
        })
    }
}

fn load_secret(env: &str) -> Result<Zeroizing<String>> {
    let file_env = format!("{env}_FILE");
    if let Ok(path) = std::env::var(&file_env) {
        let val =
            std::fs::read_to_string(&path).with_context(|| format!("read {file_env}={path}"))?;
        return Ok(Zeroizing::new(val.trim().to_string()));
    }
    let val = std::env::var(env).with_context(|| format!("{env} required"))?;
    Ok(Zeroizing::new(val))
}

fn load_secret_opt(env: &str) -> Option<Zeroizing<String>> {
    let file_env = format!("{env}_FILE");
    if let Ok(path) = std::env::var(&file_env) {
        if let Ok(val) = std::fs::read_to_string(&path) {
            return Some(Zeroizing::new(val.trim().to_string()));
        }
    }
    std::env::var(env).ok().map(Zeroizing::new)
}

fn load_der_file_opt(env: &str) -> Option<Vec<u8>> {
    let path = std::env::var(env).ok()?;
    std::fs::read(&path).ok()
}

fn load_der_file_zeroize_opt(env: &str) -> Option<Zeroizing<Vec<u8>>> {
    load_der_file_opt(env).map(Zeroizing::new)
}

/// C2: load the dashboard verify-keyring. Returns an empty Vec on
/// legitimate absence / parse failure so the caller can surface a
/// tailored error. Seeds-on-load: if the env `DASHBOARD_VERIFY_KEY`
/// is set but the file is absent, write the file atomically (mode
/// 0o600, `O_EXCL`) so the next start reads the ring instead.
fn load_dashboard_keyring() -> Result<Zeroizing<Vec<[u8; 32]>>> {
        // 1. File path first.
        let path = std::path::Path::new(DASHBOARD_KEYRING_PATH);
        if path.exists() {
            // Refuse to load if perms are wider than 0o600 — the audit
            // calls this out as M17 (secrets-at-rest). `metadata` can fail
            // on some filesystems; treat that as "skip file" so the legacy
            // env path picks up.
            if let Ok(meta) = std::fs::metadata(path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        anyhow::bail!(
                            "{DASHBOARD_KEYRING_PATH} is world- or group-readable \
                             (mode {mode:o}); refusing to load. chmod 600 the file \
                             and restart."
                        );
                    }
                }
            }
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read {DASHBOARD_KEYRING_PATH}"))?;
            let mut ring = Zeroizing::new(Vec::with_capacity(2));
            for (idx, line) in raw.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let bytes = Base64::decode_vec(trimmed)
                    .with_context(|| format!("{DASHBOARD_KEYRING_PATH}:{idx} not base64"))?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "{DASHBOARD_KEYRING_PATH}:{idx} must decode to exactly 32 bytes, got {}",
                            bytes.len()
                        )
                    })?;
                ring.push(arr);
            }
            return Ok(ring);
        }

        // 2. Legacy env (single-key).
        if let Some(bytes) = load_key32_opt("DASHBOARD_VERIFY_KEY") {
            // Seed-on-load: write the file atomically so the next start
            // reads the ring instead of the env. `O_EXCL` prevents clobbering
            // an existing file; if the file appeared between our `exists()`
            // and the open we just continue without writing — the next start
            // reads the file.
            let mut ring = Zeroizing::new(Vec::with_capacity(1));
            ring.push(bytes);
            seed_keyring_file(&bytes).context("seed dashboard-keyring on first boot")?;
            return Ok(ring);
        }

        // 3. No source — caller surfaces the user-facing error.
        Ok(Zeroizing::new(Vec::new()))
    }

fn load_key32_opt(env: &str) -> Option<[u8; 32]> {
    let file_env = format!("{env}_FILE");
    if let Ok(path) = std::env::var(&file_env) {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(bytes) = Base64::decode_vec(raw.trim()) {
                if let Ok(arr) = bytes.try_into() {
                    return Some(arr);
                }
            }
        }
    }
    std::env::var(env)
        .ok()
        .and_then(|s| Base64::decode_vec(s.trim()).ok())
        .and_then(|b| b.try_into().ok())
}

/// Best-effort write of the legacy single env key to the keyring file.
/// Mode 0o600, written atomically via a temp + rename. Logs a warning
/// if the write fails — the in-memory ring still loads, only the
/// next-start persistence is lost.
fn seed_keyring_file(bytes: &[u8; 32]) -> Result<()> {
    use std::io::Write;
    let encoded = Base64::encode_string(bytes);
    let tmp_path = format!("{DASHBOARD_KEYRING_PATH}.tmp");
    // Make sure the parent dir exists.
    if let Some(parent) = std::path::Path::new(DASHBOARD_KEYRING_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .truncate(false)
            .open(&tmp_path)
            .with_context(|| format!("open {tmp_path}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .truncate(false)
                .open(&tmp_path)
                .with_context(|| format!("open {tmp_path}"))?;
            let mut f = f;
            f.write_all(encoded.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            f.write_all(encoded.as_bytes())?;
        }
        writeln!(f)?;
    }
    std::fs::rename(&tmp_path, DASHBOARD_KEYRING_PATH)
        .with_context(|| format!("rename {tmp_path} -> {DASHBOARD_KEYRING_PATH}"))?;
    tracing::info!(
        "{} seeded with the legacy DASHBOARD_VERIFY_KEY (mode 0600)",
        DASHBOARD_KEYRING_PATH
    );
    Ok(())
}
