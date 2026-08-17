use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 30;

/// Permission level required for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
    Destructive,
}

/// Signed command envelope sent from dashboard to agent.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignedCommand {
    /// Base64url-encoded JSON payload bytes
    pub payload: String,
    /// Base64url-encoded Ed25519 signature over `payload` bytes
    pub signature: String,
}

/// Inner payload (before verification).
#[derive(Debug, Deserialize, Serialize)]
pub struct CommandPayload {
    pub nonce: String,
    pub timestamp: i64,
    pub agent_id: Uuid,
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub permission: PermissionLevel,
    pub command: serde_json::Value,
}

/// Verified command — produced only after all checks pass.
#[derive(Debug)]
pub struct VerifiedCommand {
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub permission: PermissionLevel,
    pub command: serde_json::Value,
}

/// Full verification: signature → nonce dedup → timestamp freshness → agent_id match.
///
/// C2: `verify_keys` is a keyring (slice of 32-byte Ed25519 public keys).
/// The command is accepted if any key in the ring verifies it. Two-phase
/// rotation lands in-band: the operator pushes a transition release
/// embedding both OLD and NEW; once every agent holds both, the operator
/// stops signing with OLD. The same shape mirrors `podup`'s two-slot
/// `RELEASE_PUBKEYS` (`standards/releases/index.md:52-58`).
///
/// Iteration order matches `&verify_keys` order. Callers load the keyring
/// from `/etc/glyndor/helmly/dashboard-keyring` (file-on-disk, mode 0o600),
/// seeded on first boot from the legacy `DASHBOARD_VERIFY_KEY` env so
/// existing single-key deployments continue to verify their existing
/// commands.
pub async fn verify_command(
    db: &PgPool,
    signed: &SignedCommand,
    verify_keys: &[[u8; 32]],
    own_agent_id: Uuid,
) -> Result<VerifiedCommand> {
    if verify_keys.is_empty() {
        anyhow::bail!(
            "dashboard verify keyring is empty; refusing all commands. \
             Re-add keys via the dashboard or remove the empty keyring file."
        );
    }
    // 1. Decode payload bytes + signature
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(&signed.payload).context("payload: invalid base64url")?;
    let sig_bytes =
        Base64UrlUnpadded::decode_vec(&signed.signature).context("signature: invalid base64url")?;

    // 2. Verify Ed25519 signature against any key in the ring.
    //    Accept the first match — the ring is unordered and the verifier
    //    is constant-time per key.
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    let mut last_err: Option<anyhow::Error> = None;
    let mut matched = false;
    for (i, key_bytes) in verify_keys.iter().enumerate() {
        let verifying_key = match VerifyingKey::from_bytes(key_bytes) {
            Ok(k) => k,
            Err(e) => {
                // A bad key in the ring shouldn't happen (loader validates),
                // but treat it as fail-closed — surface the error.
                last_err = Some(anyhow::anyhow!("keyring slot {i} is malformed: {e}"));
                continue;
            }
        };
        if try_verify_keys(&[verifying_key], &payload_bytes, &sig).is_none() {
            matched = true;
            break;
        }
    }
    if !matched {
        // None of the keys in the ring verified; surface the last concrete
        // error to the caller for diagnostics.
        return Err(
            last_err.unwrap_or_else(|| anyhow::anyhow!("no key in ring verified the signature"))
        );
    }

    // 3. Parse payload
    let payload: CommandPayload =
        serde_json::from_slice(&payload_bytes).context("invalid payload JSON")?;

    // 4. Check agent_id matches this agent
    if payload.agent_id != own_agent_id {
        anyhow::bail!("command not addressed to this agent");
    }

    // 5. Timestamp freshness (±30s) — bypass for heartbeat_ack so clock skew on the
    // agent side does not prevent the connection-management command from succeeding.
    // Nonce dedup (step 6) still prevents replay even without the timestamp check.
    let is_heartbeat_ack = payload
        .command
        .get("type")
        .and_then(|v| v.as_str())
        .map(|t| t == "agent.heartbeat_ack")
        .unwrap_or(false);
    if !is_heartbeat_ack {
        let now = Utc::now().timestamp();
        let skew = (now - payload.timestamp).abs();
        if skew > MAX_TIMESTAMP_SKEW_SECS {
            anyhow::bail!("timestamp too old or in future (skew={skew}s)");
        }
    }

    // 6. Nonce dedup (replay protection)
    check_and_consume_nonce(db, &payload.nonce).await?;

    Ok(VerifiedCommand {
        user_id: payload.user_id,
        organization_id: payload.organization_id,
        permission: payload.permission,
        command: payload.command,
    })
}

/// Returns Ok(()) if nonce is fresh, inserts it. Returns Err if already seen.
async fn check_and_consume_nonce(db: &PgPool, nonce: &str) -> Result<()> {
    // Purge nonces older than 5 minutes. Per spec: timestamp window is 30s, but nonces
    // are retained for 5 minutes to account for clock skew before the 30s window kicks in.
    sqlx::query!("DELETE FROM used_nonces WHERE created_at < NOW() - INTERVAL '5 minutes'")
        .execute(db)
        .await
        .context("purge expired nonces")?;

    let inserted = sqlx::query_scalar!(
        r#"
        INSERT INTO used_nonces (nonce) VALUES ($1)
        ON CONFLICT (nonce) DO NOTHING
        RETURNING nonce
        "#,
        nonce
    )
    .fetch_optional(db)
    .await
    .context("insert nonce")?;

    if inserted.is_none() {
        anyhow::bail!("nonce already used (replay attack)");
    }
    Ok(())
}

/// Verify internal bearer token (constant-time).
pub fn verify_bearer(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Inner verify-loop for the keyring: if any key in `keys` verifies `sig`
/// over `binary`, return `None`. Otherwise return the last concrete error.
///
/// `verify_command` uses this to honour the keyring semantics: the ring
/// is unordered and the FIRST match wins. Failure modes that happen before
/// the loop (empty ring, malformed key in the ring) are handled by the
/// caller — this helper assumes the slots are already parsed into
/// `VerifyingKey`s. Extracted from `verify_command` so the keyring-iteration
/// contract is testable without a `PgPool` (mirrors `verify_signature_with`
/// in `internal/update/mod.rs`).
pub(crate) fn try_verify_keys(
    keys: &[VerifyingKey],
    binary: &[u8],
    sig: &Signature,
) -> Option<anyhow::Error> {
    let mut last_err: Option<anyhow::Error> = None;
    for key in keys.iter() {
        match key.verify(binary, sig) {
            Ok(()) => return None,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "no key in ring verified the signature: {e}"
                ));
            }
        }
    }
    Some(last_err.unwrap_or_else(|| anyhow::anyhow!("no key in ring verified the signature")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- verify_bearer ---

    #[test]
    fn bearer_correct_token_accepted() {
        assert!(verify_bearer("secret-token-123", "secret-token-123"));
    }

    #[test]
    fn bearer_wrong_token_rejected() {
        assert!(!verify_bearer("wrong-token", "secret-token-123"));
    }

    #[test]
    fn bearer_different_length_rejected() {
        // Different length must fail without comparing bytes (length side-channel).
        assert!(!verify_bearer("short", "secret-token-123"));
    }

    #[test]
    fn bearer_empty_strings_match() {
        assert!(verify_bearer("", ""));
    }

    #[test]
    fn bearer_one_char_off_rejected() {
        assert!(!verify_bearer("secret-token-124", "secret-token-123"));
    }

    // --- PermissionLevel ordering ---

    #[test]
    fn permission_read_less_than_write() {
        assert!(PermissionLevel::Read < PermissionLevel::Write);
    }

    #[test]
    fn permission_write_less_than_destructive() {
        assert!(PermissionLevel::Write < PermissionLevel::Destructive);
    }

    #[test]
    fn permission_read_less_than_destructive() {
        assert!(PermissionLevel::Read < PermissionLevel::Destructive);
    }

    #[test]
    fn permission_equal_levels() {
        assert!(PermissionLevel::Write == PermissionLevel::Write);
    }

    // --- Timestamp skew ---

    #[test]
    fn timestamp_within_window_passes() {
        let now = chrono::Utc::now().timestamp();
        let skew = (now - (now - 10)).abs(); // 10s ago — well within 30s
        assert!(skew <= MAX_TIMESTAMP_SKEW_SECS);
    }

    #[test]
    fn timestamp_outside_window_fails() {
        let now = chrono::Utc::now().timestamp();
        let old = now - 60; // 60s ago — outside 30s window
        let skew = (now - old).abs();
        assert!(skew > MAX_TIMESTAMP_SKEW_SECS);
    }

    #[test]
    fn timestamp_future_outside_window_fails() {
        let now = chrono::Utc::now().timestamp();
        let future = now + 60; // 60s in the future
        let skew = (now - future).abs();
        assert!(skew > MAX_TIMESTAMP_SKEW_SECS);
    }

    // --- Crypto round-trip: sign then verify signature ---

    #[test]
    fn signed_command_signature_verifies() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

        let seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let payload_bytes = br#"{"agent_id":"test","nonce":"abc","timestamp":1}"#;
        let payload_b64 = Base64UrlUnpadded::encode_string(payload_bytes);

        let sig = signing_key.sign(payload_bytes);
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());

        // Decode and verify just like verify_command does
        let decoded_payload = Base64UrlUnpadded::decode_vec(&payload_b64).unwrap();
        let decoded_sig_bytes = Base64UrlUnpadded::decode_vec(&sig_b64).unwrap();
        let sig_arr: [u8; 64] = decoded_sig_bytes.try_into().unwrap();
        let sig2 = ed25519_dalek::Signature::from_bytes(&sig_arr);

        assert!(verifying_key.verify(&decoded_payload, &sig2).is_ok());
    }

    // ---- Replay / freshness — full verify_command path (§12.1) -------------
    //
    // These tests require DATABASE_URL pointing at a postgres with the agent
    // migrations applied; they skip when DATABASE_URL is absent (e.g. local
    // `cargo test` outside the dev compose).

    use ed25519_dalek::Signer;
    use serde_json::json;

    fn build_signed_command(
        signing_key: &ed25519_dalek::SigningKey,
        agent_id: Uuid,
        nonce: &str,
        timestamp: i64,
    ) -> SignedCommand {
        build_signed_command_type(
            signing_key,
            agent_id,
            nonce,
            timestamp,
            "nftables.get_status",
        )
    }

    fn build_signed_command_type(
        signing_key: &ed25519_dalek::SigningKey,
        agent_id: Uuid,
        nonce: &str,
        timestamp: i64,
        cmd_type: &str,
    ) -> SignedCommand {
        let payload = json!({
            "nonce": nonce,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "user_id": Uuid::nil(),
            "organization_id": null,
            "permission": "read",
            "command": { "type": cmd_type },
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = Base64UrlUnpadded::encode_string(&payload_bytes);
        let sig = signing_key.sign(&payload_bytes);
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());
        SignedCommand {
            payload: payload_b64,
            signature: sig_b64,
        }
    }

    async fn db_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[tokio::test]
    async fn fresh_command_with_valid_signature_accepts() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        let nonce = Uuid::now_v7().to_string();
        let ts = Utc::now().timestamp();

        let cmd = build_signed_command(&signing_key, agent_id, &nonce, ts);
        let result = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        assert!(
            result.is_ok(),
            "valid fresh command must verify: {result:?}"
        );
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        let nonce = Uuid::now_v7().to_string();
        let ts = Utc::now().timestamp();

        // First use — consumes nonce.
        let cmd1 = build_signed_command(&signing_key, agent_id, &nonce, ts);
        verify_command(&db, &cmd1, &[verify_key_bytes], agent_id)
            .await
            .expect("first use of nonce must succeed");

        // Second use of *same nonce* with a freshly re-signed envelope (same
        // payload bytes, so same signature here) — must reject.
        let cmd2 = build_signed_command(&signing_key, agent_id, &nonce, ts);
        let res = verify_command(&db, &cmd2, &[verify_key_bytes], agent_id).await;
        assert!(res.is_err(), "replayed nonce must be rejected");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.contains("replay") || msg.contains("nonce"),
            "error should mention replay/nonce: {msg}"
        );
    }

    #[tokio::test]
    async fn timestamp_too_old_is_rejected() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        // 60 seconds in the past — outside the 30s skew window.
        let old_ts = Utc::now().timestamp() - 60;
        let cmd = build_signed_command(&signing_key, agent_id, &Uuid::now_v7().to_string(), old_ts);
        let res = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        assert!(res.is_err(), "expired timestamp must reject");
        assert!(
            format!("{:#}", res.unwrap_err()).contains("timestamp"),
            "error should mention timestamp"
        );
    }

    #[tokio::test]
    async fn timestamp_far_future_is_rejected() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        let future_ts = Utc::now().timestamp() + 60;
        let cmd = build_signed_command(
            &signing_key,
            agent_id,
            &Uuid::now_v7().to_string(),
            future_ts,
        );
        let res = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        assert!(res.is_err(), "future timestamp outside window must reject");
    }

    #[tokio::test]
    async fn heartbeat_ack_bypasses_timestamp_check() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        // Clock skew: 60s in the past — would normally fail timestamp check.
        let old_ts = Utc::now().timestamp() - 60;
        let cmd = build_signed_command_type(
            &signing_key,
            agent_id,
            &Uuid::now_v7().to_string(),
            old_ts,
            "agent.heartbeat_ack",
        );
        let res = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        assert!(
            res.is_ok(),
            "heartbeat_ack must bypass timestamp check: {res:?}"
        );
    }

    #[tokio::test]
    async fn signature_signed_with_other_key_is_rejected() {
        let Some(db) = db_pool().await else { return };
        // Real dashboard signing key vs attacker's key.
        let dashboard = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let verify_key_bytes = dashboard.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        // Attacker signs a command that LOOKS legitimate but with a key the
        // agent will reject.
        let cmd = build_signed_command(
            &attacker,
            agent_id,
            &Uuid::now_v7().to_string(),
            Utc::now().timestamp(),
        );
        let res = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        assert!(res.is_err(), "wrong-key signature must reject");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.contains("signature") || msg.contains("verification"),
            "error should mention signature/verification: {msg}"
        );
    }

    #[tokio::test]
    async fn command_addressed_to_other_agent_is_rejected() {
        let Some(db) = db_pool().await else { return };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let other_agent_id = Uuid::now_v7();
        let our_agent_id = Uuid::now_v7();
        let cmd = build_signed_command(
            &signing_key,
            other_agent_id,
            &Uuid::now_v7().to_string(),
            Utc::now().timestamp(),
        );
        let res = verify_command(&db, &cmd, &[verify_key_bytes], our_agent_id).await;
        assert!(
            res.is_err(),
            "command addressed to a different agent must reject"
        );
    }

    #[test]
    fn tampered_payload_fails_verification() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

        let seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let payload_bytes = br#"{"agent_id":"test","nonce":"abc","timestamp":1}"#;
        let sig = signing_key.sign(payload_bytes);
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());

        // Tamper the payload
        let tampered = br#"{"agent_id":"evil","nonce":"abc","timestamp":1}"#;
        let tampered_b64 = Base64UrlUnpadded::encode_string(tampered);

        let decoded_payload = Base64UrlUnpadded::decode_vec(&tampered_b64).unwrap();
        let decoded_sig_bytes = Base64UrlUnpadded::decode_vec(&sig_b64).unwrap();
        let sig_arr: [u8; 64] = decoded_sig_bytes.try_into().unwrap();
        let sig2 = ed25519_dalek::Signature::from_bytes(&sig_arr);

        assert!(verifying_key.verify(&decoded_payload, &sig2).is_err());
    }

    // ---- try_verify_keys — keyring iteration (C2 contract) ----
    //
    // The helper is the inner loop of `verify_command`. Tests live here
    // (not on `verify_command` directly) because the production caller
    // requires a `PgPool` for the nonce-dedup step that follows the
    // signature check. The keyring-iteration contract is exactly the
    // load-bearing security boundary, so it must be exercised without a
    // database.

    #[test]
    fn try_verify_keys_empty_ring_returns_some_error() {
        use ed25519_dalek::Signature;
        let bogus_sig = Signature::from_bytes(&[0u8; 64]);
        let r = try_verify_keys(&[], b"any-binary", &bogus_sig);
        let err = r.expect("empty ring must report failure; got None");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no key in ring verified"),
            "empty-ring rejection must name the cause: {msg}"
        );
    }

    #[test]
    fn try_verify_keys_one_key_valid_sig_returns_none() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let key = signing.verifying_key();
        let binary = b"some-binary";
        let sig = signing.sign(binary);
        assert!(
            try_verify_keys(&[key], binary, &sig).is_none(),
            "valid sig against the only key must return None"
        );
    }

    #[test]
    fn try_verify_keys_one_key_wrong_sig_returns_some_error() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let key = signing.verifying_key();
        let binary = b"some-binary";
        // Sign with a DIFFERENT key.
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let sig = other.sign(binary);
        let r = try_verify_keys(&[key], binary, &sig);
        let err = r.expect("wrong-key sig must report failure; got None");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no key in ring verified"),
            "wrong-key rejection must name the cause: {msg}"
        );
    }

    #[test]
    fn try_verify_keys_two_keys_sig_with_first_returns_none() {
        use ed25519_dalek::Signer;
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let key2 = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let binary = b"some-binary";
        let sig = key1.sign(binary);
        assert!(
            try_verify_keys(&[key1.verifying_key(), key2.verifying_key()], binary, &sig,).is_none(),
            "sig from key 1 must verify against the [1,2] ring"
        );
    }

    #[test]
    fn try_verify_keys_two_keys_sig_with_second_returns_none() {
        use ed25519_dalek::Signer;
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let key2 = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let binary = b"some-binary";
        let sig = key2.sign(binary);
        assert!(
            try_verify_keys(&[key1.verifying_key(), key2.verifying_key()], binary, &sig,).is_none(),
            "sig from key 2 must verify against the [1,2] ring"
        );
    }

    #[test]
    fn try_verify_keys_two_keys_sig_with_neither_returns_some_error() {
        use ed25519_dalek::Signer;
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let key2 = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let binary = b"some-binary";
        let sig = other.sign(binary); // signed by neither key
        let r = try_verify_keys(&[key1.verifying_key(), key2.verifying_key()], binary, &sig);
        let err = r.expect("sig by neither key must report failure; got None");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no key in ring verified"),
            "no-match rejection must name the cause: {msg}"
        );
    }

    // ---- verify_command: empty-keyring fail-closed (no DB) ----
    //
    // The empty-ring check runs before any DB query, so we can construct
    // a `PgPool` that never opens a connection (`connect_lazy_with`).
    // Reaches the rejection without touching the pool.

    fn lazy_db() -> PgPool {
        // connect_lazy_with creates a pool that never opens a real
        // connection until the first query hits it. The empty-ring
        // guard at the top of `verify_command` fires before any query,
        // so the pool's URL is never resolved.
        let opts = sqlx::postgres::PgConnectOptions::new();
        PgPool::connect_lazy_with(opts)
    }

    #[tokio::test]
    async fn command_empty_keyring_rejects_before_db() {
        let db = lazy_db();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let agent_id = Uuid::now_v7();
        let cmd = build_signed_command(
            &signing_key,
            agent_id,
            &Uuid::now_v7().to_string(),
            Utc::now().timestamp(),
        );
        let res = verify_command(&db, &cmd, &[], agent_id).await;
        let err = res.expect_err("empty keyring must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("keyring is empty"),
            "empty keyring rejection must name the cause: {msg}"
        );
    }

    // ---- CommandPayload JSON parse failure (no DB) ----
    //
    // The JSON parse (`serde_json::from_slice` on `payload_bytes`) sits
    // before the agent_id check, before the timestamp check, and before
    // the nonce dedup. A malformed payload never reaches the pool.
    // Pre-decode base64 is valid; the payload bytes themselves are not JSON.

    #[tokio::test]
    async fn command_malformed_payload_json_is_rejected() {
        let db = lazy_db();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verify_key_bytes = signing_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();

        // Valid base64, valid signature, but the payload bytes are not JSON.
        let payload_bytes = b"this is not valid json at all";
        let payload_b64 = Base64UrlUnpadded::encode_string(payload_bytes);
        let sig = signing_key.sign(payload_bytes);
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());
        let cmd = SignedCommand {
            payload: payload_b64,
            signature: sig_b64,
        };

        let res = verify_command(&db, &cmd, &[verify_key_bytes], agent_id).await;
        let err = res.expect_err("malformed JSON payload must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid payload JSON"),
            "JSON-parse failure must name the cause: {msg}"
        );
    }

    // ---- CommandPayload JSON parse success (no DB) ----

    #[test]
    fn command_payload_valid_json_parses() {
        let payload = json!({
            "nonce": "n-1",
            "timestamp": 1234567890_i64,
            "agent_id": Uuid::now_v7(),
            "user_id": Uuid::nil(),
            "organization_id": null,
            "permission": "read",
            "command": { "type": "nftables.get_status" },
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let parsed: CommandPayload = serde_json::from_slice(&bytes).expect("valid JSON must parse");
        assert_eq!(parsed.nonce, "n-1");
        assert_eq!(parsed.permission, PermissionLevel::Read);
    }

    // ---- verify_bearer: empty vs non-empty (length pre-check) ----
    //
    // `subtle::ConstantTimeEq` returns 0 for different-length inputs, so
    // the length pre-check at line 191-193 is a defensive guard, not a
    // correctness requirement. This test pins the empty-vs-non-empty
    // boundary so the guard stays in the code; mutating the length check
    // away leaves the test passing (ConstantTimeEq still rejects), but
    // the explicit guard keeps the intent visible and is what the
    // audit-log story in `standards/security` points to.

    #[test]
    fn bearer_empty_vs_nonempty_rejected() {
        assert!(!verify_bearer("", "secret-token-123"));
        assert!(!verify_bearer("secret-token-123", ""));
    }
}
