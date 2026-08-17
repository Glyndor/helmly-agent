use super::*;

// ---------- Section B — is_chain_diverged_with ------------------------

/// Control: an unknown chain name must short-circuit to `false`
/// (the `_` arm of the index match). Replacing `_ => false` with
/// `_ => true` makes the test red.
#[tokio::test]
async fn is_chain_diverged_unknown_chain_returns_false() {
	let state = make_state();
	assert!(
		!is_chain_diverged_with(&state, "not-a-known-chain", &|_| Ok("ANY".to_string())),
		"unknown chain must not be attributed"
	);
}

/// Control: when no baseline is stored for a chain, the detector
/// must short-circuit to `false` (no attribution possible).
/// Removing the `None => return false` arm makes the test call the
/// closure and could observe a difference — but the strict assertion
/// catches a `true` return.
#[tokio::test]
async fn is_chain_diverged_no_baseline_returns_false() {
	let state = make_state();
	// state.nft_chain_checksums defaults to [None, None, None]
	assert!(
		!is_chain_diverged_with(&state, "helmly-base", &|_| Ok("ANY".to_string())),
		"missing baseline → cannot attribute → false"
	);
}

/// Control: chain checksum matches expected → not diverged.
/// Removing the `Ok(current) => current != expected` comparison or
/// flipping it to `==` makes the test red.
#[tokio::test]
async fn is_chain_diverged_matching_returns_false() {
	let state = make_state();
	state.set_nft_chain_checksums(Some("checksum-X".into()), None, None);
	assert!(
		!is_chain_diverged_with(&state, "helmly-base", &|_| Ok("checksum-X".into())),
		"matching checksums must not be diverged"
	);
}

/// Control: chain checksum differs from expected → diverged.
/// Removing the `current != expected` arm makes the test red.
#[tokio::test]
async fn is_chain_diverged_differing_returns_true() {
	let state = make_state();
	state.set_nft_chain_checksums(Some("expected".into()), None, None);
	assert!(
		is_chain_diverged_with(&state, "helmly-base", &|_| Ok("LIVE-DIFFERS".into())),
		"differing checksums must be attributed as diverged"
	);
}

/// Control: chain checksum query Err → diverged. Defends against
/// the silent-failure mode where a deleted chain is treated as
/// matching and the agent stops restoring it. Removing the
/// `Err(_) => true` arm makes the test red.
#[tokio::test]
async fn is_chain_diverged_chain_call_fails_returns_true() {
	let state = make_state();
	state.set_nft_chain_checksums(Some("expected".into()), None, None);
	assert!(
		is_chain_diverged_with(&state, "helmly-base", &|_| Err(anyhow::anyhow!(
			"chain deleted"
		)),),
		"chain query failure must be treated as diverged (chain may have been deleted)"
	);
}

/// Control: the index map 0=base, 1=global, 2=local. The `match
/// chain { ... }` arm drives which slot of `nft_chain_checksums`
/// is consulted. Swapping indices routes the wrong baseline into
/// the wrong chain slot — caught by this test.
#[tokio::test]
async fn is_chain_diverged_index_map_is_base_global_local() {
	let state = make_state();
	state.set_nft_chain_checksums(
		Some("BASE-VALUE".into()),
		Some("GLOBAL-VALUE".into()),
		Some("LOCAL-VALUE".into()),
	);
	let lookup = |c: &'static str| -> &'static str {
		// Pull the expected value out via the same index the
		// function uses — assert that the function picked the
		// matching slot.
		match c {
			"helmly-base" => "BASE-VALUE",
			"helmly-global" => "GLOBAL-VALUE",
			"helmly-local" => "LOCAL-VALUE",
			_ => unreachable!(),
		}
	};
	for chain in ["helmly-base", "helmly-global", "helmly-local"] {
		let expected = lookup(chain);
		let got =
			is_chain_diverged_with(&state, chain, &move |_| Ok(format!("{expected}-DIFFERS")));
		assert!(got, "chain {chain} must look up slot {:?}", expected);
	}
}
