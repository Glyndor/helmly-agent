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
mod tests;
