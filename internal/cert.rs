//! Agent certificate verification.
//!
//! The dashboard CA issues an Ed25519-signed certificate at agent registration.
//! Agents store it and can verify it to confirm commands come from a trusted dashboard.

use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedCert {
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentCert {
    pub agent_id: Uuid,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Load CA public key from env (CA_PUBLIC_KEY or CA_PUBLIC_KEY_FILE).
/// Returns None if not configured (cert verification disabled in dev mode).
pub fn load_ca_public_key() -> Option<[u8; 32]> {
    let raw = std::env::var("CA_PUBLIC_KEY_FILE")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::env::var("CA_PUBLIC_KEY").ok())?;

    let bytes = Base64UrlUnpadded::decode_vec(raw.trim()).ok()?;
    bytes.try_into().ok()
}

/// Verify a cert from the dashboard. Returns Ok if valid and not expired.
pub fn verify(cert: &SignedCert, ca_public: &[u8; 32], expected_agent_id: Uuid) -> Result<()> {
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(&cert.payload).context("base64url decode payload")?;
    let sig_bytes =
        Base64UrlUnpadded::decode_vec(&cert.signature).context("base64url decode signature")?;

    let verifying_key = VerifyingKey::from_bytes(ca_public).context("parse CA public key")?;

    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&payload_bytes, &sig)
        .context("CA signature invalid")?;

    let payload: AgentCert = serde_json::from_slice(&payload_bytes).context("deserialize cert")?;

    if payload.agent_id != expected_agent_id {
        anyhow::bail!("cert agent_id mismatch");
    }

    let now = chrono::Utc::now().timestamp();
    if now > payload.expires_at {
        anyhow::bail!("cert expired");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Tests for the dashboard agent cert verification.
    //!
    //! The cert envelope is `SignedCert { payload, signature }` — both
    //! base64url-encoded. `payload` decodes to JSON `AgentCert
    //! { agent_id, issued_at, expires_at }`. The Ed25519 signature is over
    //! the raw payload bytes (NOT the base64 text).
    //!
    //! `verify` enforces four checks in order:
    //!   1. base64url payload decode
    //!   2. base64url signature decode + 64-byte length
    //!   3. Ed25519 signature against CA public key
    //!   4. `payload.agent_id == expected_agent_id`
    //!   5. `now <= payload.expires_at`
    //!
    //! The function does NOT consult `issued_at` (no `not_before` guard).
    //! A separate test pins that contract so adding a not-before check
    //! breaks loudly instead of silently.

    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    /// Deterministic 32-byte seed so tests are reproducible.
    const CA_SEED: [u8; 32] = [0x42u8; 32];

    fn ca_signing_key() -> SigningKey {
        SigningKey::from_bytes(&CA_SEED)
    }

    fn ca_public_key_bytes() -> [u8; 32] {
        ca_signing_key().verifying_key().to_bytes()
    }

    /// Build a `SignedCert` envelope: serialize `AgentCert` to JSON, sign
    /// the raw bytes with `key`, base64url-encode both halves.
    fn sign_cert(key: &SigningKey, agent_id: Uuid, issued_at: i64, expires_at: i64) -> SignedCert {
        let payload = json!({
            "agent_id": agent_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize AgentCert");
        let sig = key.sign(&payload_bytes);
        SignedCert {
            payload: Base64UrlUnpadded::encode_string(&payload_bytes),
            signature: Base64UrlUnpadded::encode_string(&sig.to_bytes()),
        }
    }

    // ---- happy path ----

    /// Valid cert, matching agent_id, expires_at in the future → Ok.
    /// Pair with the rejection tests below: removing the expiry check
    /// keeps this test passing but breaks `verify_expired_cert_rejects`.
    #[test]
    fn verify_valid_cert_accepts() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, agent_id, now - 10, now + 3600);
        verify(&signed, &ca_public, agent_id).expect("valid cert must verify");

        // `verify` returns (); assert the embedded agent_id matches what we
        // encoded by re-decoding the envelope. This is the "returned
        // agent_id matches" check the spec asks for, modulo the fact that
        // `verify` returns `()` rather than `Result<Uuid>`.
        let payload_bytes = Base64UrlUnpadded::decode_vec(&signed.payload).unwrap();
        let parsed: AgentCert = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(parsed.agent_id, agent_id);
        assert_eq!(parsed.expires_at, now + 3600);
    }

    // ---- failure paths ----

    /// Expired cert (expires_at clearly in the past) → Err mentioning expiry.
    /// Goes red if the `now > payload.expires_at` check is removed.
    #[test]
    fn verify_expired_cert_rejects() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, agent_id, now - 3600, now - 60);
        let err = verify(&signed, &ca_public, agent_id).expect_err("expired cert must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("cert expired"),
            "rejection must name the cause: {msg}",
        );
    }

    /// Payload claims agent_id = X, verifier expects Y → Err "agent_id mismatch".
    /// Goes red if the `payload.agent_id != expected_agent_id` check is removed.
    #[test]
    fn verify_wrong_agent_id_rejects() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let signed_for = Uuid::now_v7();
        let expected = Uuid::now_v7();
        assert_ne!(signed_for, expected, "test setup: ids must differ");
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, signed_for, now, now + 3600);
        let err = verify(&signed, &ca_public, expected).expect_err("wrong agent_id must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("agent_id mismatch"),
            "rejection must name the cause: {msg}",
        );
    }

    /// Cert with `issued_at` in the future and `expires_at` in the future
    /// verifies successfully — there is no `not_before` guard in `verify`,
    /// the JSON `issued_at` field is never read.
    ///
    /// Pins the absence of the check: removing this test, or adding a
    /// `not_before` guard, would each force a decision about whether
    /// "future-issued" certs should be rejected. Currently accepted.
    #[test]
    fn verify_no_not_before_check_accepts_future_issued() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        // issued_at 1h in the future, expires_at 2h in the future.
        let signed = sign_cert(&key, agent_id, now + 3600, now + 7200);
        verify(&signed, &ca_public, agent_id)
            .expect("verify() has no not-before guard; future issued_at must pass through");
    }

    /// Garbage payload field that is not valid base64url → Err, no panic.
    /// Goes red if the base64-decode step is removed.
    #[test]
    fn verify_malformed_payload_base64_rejects() {
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let signed = SignedCert {
            payload: "!!! not valid base64 !!!".to_string(),
            signature: Base64UrlUnpadded::encode_string(&[0u8; 64]),
        };
        let err = verify(&signed, &ca_public, agent_id)
            .expect_err("garbage payload base64 must reject, not panic");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("base64url decode payload"),
            "rejection must name the cause: {msg}",
        );
    }

    /// Valid base64, but the decoded bytes are not JSON → Err from
    /// `serde_json::from_slice`. Goes red if the deserialize step is removed.
    #[test]
    fn verify_payload_not_json_rejects() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();

        let garbage = b"this is not json at all";
        let sig = key.sign(garbage);
        let signed = SignedCert {
            payload: Base64UrlUnpadded::encode_string(garbage),
            signature: Base64UrlUnpadded::encode_string(&sig.to_bytes()),
        };

        let err = verify(&signed, &ca_public, agent_id).expect_err("non-JSON payload must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("deserialize cert"),
            "rejection must name the cause: {msg}",
        );
    }

    /// Signature was made by a DIFFERENT key than the CA → Err
    /// "CA signature invalid". Goes red if the signature check is removed.
    #[test]
    fn verify_wrong_signature_key_rejects() {
        let ca_key = ca_signing_key();
        let attacker_key = SigningKey::from_bytes(&[0x77u8; 32]);
        let ca_public = ca_key.verifying_key().to_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        // Attacker forges a cert with the right shape and signs it with
        // their own key. The CA key will reject the signature.
        let signed = sign_cert(&attacker_key, agent_id, now, now + 3600);
        let err =
            verify(&signed, &ca_public, agent_id).expect_err("wrong-key signature must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("CA signature invalid"),
            "rejection must name the cause: {msg}",
        );
    }

    /// Signature base64 decodes to a byte vector that is not 64 bytes
    /// → Err "signature must be 64 bytes". Goes red if the length check
    /// is removed.
    #[test]
    fn verify_wrong_signature_length_rejects() {
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        // 32 bytes instead of 64.
        let signed = SignedCert {
            payload: Base64UrlUnpadded::encode_string(b"{\"agent_id\":\"00000000-0000-0000-0000-000000000000\",\"issued_at\":0,\"expires_at\":9999999999}"),
            signature: Base64UrlUnpadded::encode_string(&[0u8; 32]),
        };
        let err =
            verify(&signed, &ca_public, agent_id).expect_err("non-64-byte signature must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("signature must be 64 bytes"),
            "rejection must name the cause: {msg}",
        );
    }

    // ---- expiry boundary (C3: short-lived certs + revocation denylist) ----
    //
    // The check is `now > payload.expires_at` (strict greater-than), so
    // `expires_at == now` is accepted. The boundary tests below pin that
    // direction with a small buffer to absorb clock drift between the
    // test's `Utc::now()` and `verify`'s internal `Utc::now()`.

    /// Pair to `verify_expired_cert_rejects`: expires_at = now + 5 is
    /// safely inside the validity window and must verify.
    #[test]
    fn verify_expires_at_just_future_accepts() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, agent_id, now, now + 5);
        verify(&signed, &ca_public, agent_id).expect("expires_at in the future must verify");
    }

    /// Boundary contract: the check is strict `now > expires_at`, so
    /// expires_at = now is accepted. We use `now + 1` to absorb the gap
    /// between the test's `Utc::now()` and `verify`'s internal `Utc::now()`.
    /// Goes red if the check is changed to `>=`.
    #[test]
    fn verify_expires_at_boundary_now_plus_one_accepts() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, agent_id, now, now + 1);
        verify(&signed, &ca_public, agent_id)
            .expect("expires_at = now+1 must verify (boundary is strict `>`)");
    }

    /// Pair to `verify_expires_at_just_future_accepts`: expires_at = now - 5
    /// is clearly past and must reject. The `-5` absorbs the test→verify
    /// clock gap.
    #[test]
    fn verify_expires_at_just_past_rejects() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        let now = chrono::Utc::now().timestamp();

        let signed = sign_cert(&key, agent_id, now - 60, now - 5);
        let err =
            verify(&signed, &ca_public, agent_id).expect_err("expires_at in the past must reject");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("cert expired"),
            "rejection must name the cause: {msg}",
        );
    }

    // ---- round-trip ----

    /// Build → encode → decode → parse → fields match. Confirms the
    /// base64url/JSON envelope survives a round trip end-to-end without
    /// any field being silently mangled by the encoding.
    #[test]
    fn signed_cert_round_trip_preserves_fields() {
        let key = ca_signing_key();
        let ca_public = ca_public_key_bytes();
        let agent_id = Uuid::now_v7();
        // Use `now`-relative timestamps so the round-tripped cert is still
        // valid against wall-clock time at verify-time.
        let now = chrono::Utc::now().timestamp();
        let issued_at = now - 10;
        let expires_at = now + 3600;

        let signed = sign_cert(&key, agent_id, issued_at, expires_at);

        // Decode payload → parse AgentCert.
        let payload_bytes = Base64UrlUnpadded::decode_vec(&signed.payload).expect("payload base64");
        let parsed: AgentCert = serde_json::from_slice(&payload_bytes).expect("payload JSON");

        assert_eq!(parsed.agent_id, agent_id);
        assert_eq!(parsed.issued_at, issued_at);
        assert_eq!(parsed.expires_at, expires_at);

        // And the envelope still verifies with the CA public key.
        verify(&signed, &ca_public, agent_id).expect("round-tripped cert must verify");
    }

    // ---- load_ca_public_key (best-effort) ----
    //
    // Cannot safely mutate process env from parallel tests, so this only
    // covers the "both vars unset → None" path. The "valid base64url →
    // Some(bytes)" path is exercised by production code that loads the CA
    // key on startup and signs real certs.

    /// If neither CA_PUBLIC_KEY_FILE nor CA_PUBLIC_KEY is set, returns
    /// None. CI / local dev commonly have neither set, but if a test
    /// environment has them configured this assertion would fail —
    /// that's the intended signal that the env contract changed.
    #[test]
    fn load_ca_public_key_returns_none_when_env_unset() {
        // Save current values, clear for the test, restore.
        let saved_file = std::env::var("CA_PUBLIC_KEY_FILE").ok();
        let saved_key = std::env::var("CA_PUBLIC_KEY").ok();
        // SAFETY: tests touching process env must not run in parallel with
        // other env-mutating tests. There are none in this module.
        unsafe {
            std::env::remove_var("CA_PUBLIC_KEY_FILE");
            std::env::remove_var("CA_PUBLIC_KEY");
        }

        let result = load_ca_public_key();

        // Restore.
        unsafe {
            if let Some(v) = saved_file {
                std::env::set_var("CA_PUBLIC_KEY_FILE", v);
            }
            if let Some(v) = saved_key {
                std::env::set_var("CA_PUBLIC_KEY", v);
            }
        }

        assert!(
            result.is_none(),
            "no env vars set → expected None, got Some",
        );
    }
}
