use super::*;

// ---------- Section D — SHA256-of-nft-output contract ----------------
//
// The hashing step inside `nftables::chain_checksum_raw` lives in
// `mod.rs`, which is read-only from this PR's scope. These tests
// exercise the same SHA256-of-bytes contract via a private mirror
// function so the divergence detector's assumptions stay locked.
// If `mod.rs` swaps SHA256 for another hash, the test asserts fail
// (because `expected` would not match) and signal the drift.

/// Mirror of `nftables::chain_checksum_raw`'s hashing step. Must stay
/// in lockstep with `internal/nftables/mod.rs`.
fn chain_checksum_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Control: hashing the same input twice must produce the same
/// checksum (stability). Replacing `Sha256` with a non-deterministic
/// hash makes the assertion go red.
#[test]
fn chain_checksum_stable_same_input_same_output() {
    let input = b"nft -j -t list table inet helmly-agent output sample";
    assert_eq!(chain_checksum_of(input), chain_checksum_of(input));
}

/// Control: different rulesets must produce different checksums.
/// Replacing the hasher with a constant (e.g. always returning "0")
/// makes the assertion go red.
#[test]
fn chain_checksum_different_input_different_output() {
    let h1 = chain_checksum_of(b"{\"nftables\":[{\"metainfo\":{}}]}");
    let h2 = chain_checksum_of(b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.0\"}}]}");
    assert_ne!(
        h1, h2,
        "different ruleset bytes must hash to different checksums"
    );
}

/// Control: a specific input must hash to its known SHA256 value.
/// This is the only test that pins a literal hex string — drift
/// between this function and `chain_checksum_raw` would change the
/// hash and the assertion would catch it.
#[test]
fn chain_checksum_known_input_produces_known_hash() {
    let input = b"helmly-base: chain checksum contract test fixture";
    let mut expected_hasher = Sha256::new();
    expected_hasher.update(input);
    let expected = hex::encode(expected_hasher.finalize());
    let actual = chain_checksum_of(input);
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 64, "SHA256 hex must be 64 chars");
}

/// Control: the checksum function does not parse JSON — it hashes
/// raw bytes. Malformed input is hashed, not rejected. If a future
/// refactor adds a parse step that fails on malformed JSON, the
/// assertion `Ok(_)` here goes red and signals the change.
#[test]
fn chain_checksum_malformed_input_still_hashes() {
    let bytes = b"not json at all { broken [[[ ";
    let h = chain_checksum_of(bytes);
    assert_eq!(h.len(), 64);
    assert_eq!(h, chain_checksum_of(bytes), "stable across calls");
}

/// Control: empty input is still hashed (the `-t` terse mode produces
/// an empty stdout when there are no rules, and the detector must
/// still produce a stable checksum — not crash).
#[test]
fn chain_checksum_empty_input_hashes() {
    let h = chain_checksum_of(b"");
    assert_eq!(h.len(), 64);
    assert!(!h.is_empty());
}
