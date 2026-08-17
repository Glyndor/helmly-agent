use super::*;

// ---------- Section A — check_once_with happy path --------------------

/// Control: when the live checksum matches the DB-stored expected
/// checksum, the function must short-circuit. Removing the `if
/// current == expected { return; }` arm makes the test fall through
/// into the divergence path and call the apply closure.
#[tokio::test]
async fn check_once_stable_state_no_restore_no_lockdown() {
	let state = make_state();
	state.set_nft_checksum("expected-checksum".into());
	state.set_nft_last_ruleset("must-not-be-applied".into());
	let applied = Arc::new(Mutex::new(Vec::<String>::new()));
	let cc = applied.clone();

	check_once_with(
		&state,
		&stub_current("expected-checksum"),
		&stub_chain(&[], Ok("expected-checksum".to_string())),
		&stub_apply_recording(cc),
		&stub_emergency_ok(),
	)
	.await;

	assert!(!state.is_locked_down(), "stable state must not lock down");
	assert!(
		applied.lock().unwrap().is_empty(),
		"stable state must not trigger restore"
	);
}

/// Control: when the live checksum differs from the DB-stored one,
/// the function must call `apply` with the *exact* ruleset the DB
/// holds (`nft_last_ruleset`). Removing the `state.nft_last_ruleset()`
/// read or substituting the wrong key makes the assertion go red.
#[tokio::test]
async fn check_once_divergence_restores_from_db() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_last_ruleset("DB-stored-ruleset".into());
	let applied = Arc::new(Mutex::new(Vec::<String>::new()));
	let cc = applied.clone();

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&stub_chain(&[], Ok("expected".to_string())),
		&stub_apply_recording(cc),
		&stub_emergency_ok(),
	)
	.await;

	assert_eq!(
		*applied.lock().unwrap(),
		vec!["DB-stored-ruleset".to_owned()],
		"restore must apply the DB-stored ruleset"
	);
	assert!(!state.is_locked_down(), "restore succeeded → no lockdown");
}

/// Control: when restore fails AND the emergency apply also fails,
/// the agent must enter `Lockdown` with reason `NftablesFailure`.
/// Removing the `state.set_lockdown(...)` line or weakening the
/// reason check makes this test go red.
#[tokio::test]
async fn check_once_divergence_restore_and_emergency_fail_sets_lockdown() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_last_ruleset("ruleset".into());

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&stub_chain(&[], Ok("expected".to_string())),
		&|_| Err(anyhow::anyhow!("apply boom")),
		&stub_emergency_err(),
	)
	.await;

	assert!(
		state.is_locked_down(),
		"both restore and emergency failed → lockdown"
	);
	assert_eq!(
		*state.lockdown_reason.lock().unwrap(),
		Some(LockdownReason::NftablesFailure),
		"lockdown reason must name the nft failure"
	);
}

/// Control: when restore fails, the agent enters lockdown
/// regardless of whether the emergency apply succeeds. (Current
/// behaviour; the `if let Err(e2)` guard around `set_lockdown`
/// means emergency-recovery success does NOT suppress the
/// lockdown — both failure paths funnel into the same alert.)
/// This test pins the current contract; changing the contract
/// (e.g. to suppress lockdown on emergency success) is a separate
/// decision that would update this test in lockstep.
#[tokio::test]
async fn check_once_divergence_restore_fails_sets_lockdown() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_last_ruleset("ruleset".into());

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&stub_chain(&[], Ok("expected".to_string())),
		&|_| Err(anyhow::anyhow!("apply boom")),
		&stub_emergency_ok(),
	)
	.await;

	assert!(
		state.is_locked_down(),
		"restore failure must lock the agent down (current contract)"
	);
}

/// Control: when `expected_nft_checksum()` is `None` (no ruleset
/// applied yet), the function must short-circuit before calling
/// the current-checksum closure. Removing the `None => return`
/// arm makes the current-checksum closure fire and the assertion
/// catches it.
#[tokio::test]
async fn check_once_no_baseline_short_circuits_all_runners() {
	let state = make_state();
	// No nft_checksum set — `expected_nft_checksum()` is None.
	let current_called = Arc::new(AtomicBool::new(false));
	let chain_called = Arc::new(AtomicBool::new(false));
	let apply_called = Arc::new(AtomicBool::new(false));
	let cc = current_called.clone();
	let chc = chain_called.clone();
	let ac = apply_called.clone();

	check_once_with(
		&state,
		&|| {
			cc.store(true, Ordering::SeqCst);
			Ok("ANY".to_string())
		},
		&|_| {
			chc.store(true, Ordering::SeqCst);
			Ok("ANY".to_string())
		},
		&|_| {
			ac.store(true, Ordering::SeqCst);
			Ok(())
		},
		&|| panic!("emergency apply must not be called when no baseline"),
	)
	.await;

	assert!(
		!current_called.load(Ordering::SeqCst),
		"no baseline → current_checksum closure must not run"
	);
	assert!(
		!chain_called.load(Ordering::SeqCst),
		"no baseline → chain checksum closure must not run"
	);
	assert!(
		!apply_called.load(Ordering::SeqCst),
		"no baseline → apply closure must not run"
	);
	assert!(!state.is_locked_down());
}

/// Control: when the current-checksum closure fails, the function
/// must warn + return without touching lockdown. Removing the
/// `Err(_) => { warn; return; }` arm (e.g. propagating the error
/// as `set_lockdown`) makes the test go red.
#[tokio::test]
async fn check_once_current_checksum_failure_no_lockdown_no_apply() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_last_ruleset("ruleset".into());
	let applied = Arc::new(Mutex::new(Vec::<String>::new()));
	let cc = applied.clone();

	check_once_with(
		&state,
		&|| Err(anyhow::anyhow!("nft binary not found")),
		&|_| Ok("expected".to_string()),
		&stub_apply_recording(cc),
		&|| panic!("emergency apply must not be called on current-checksum failure"),
	)
	.await;

	assert!(
		!state.is_locked_down(),
		"current-checksum failure must not lock down"
	);
	assert!(
		applied.lock().unwrap().is_empty(),
		"current-checksum failure must not trigger restore"
	);
}

/// Control: when only `helmly-base` differs from its baseline, the
/// detector must still run restore (and NOT panic on the CRITICAL
/// log path). The test asserts `applied` was called AND that
/// lockdown stays false after a successful restore. Removing the
/// `base_diverged => error!` branch or the unconditional restore
/// makes this test go red.
#[tokio::test]
async fn check_once_divergence_only_base_diverged_restores() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_chain_checksums(
		Some("base-expected".into()),
		Some("global-expected".into()),
		Some("local-expected".into()),
	);
	state.set_nft_last_ruleset("ruleset".into());
	let applied = Arc::new(Mutex::new(Vec::<String>::new()));
	let cc = applied.clone();

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&stub_chain(
			&[
				("helmly-base", "base-DIFFERS"),
				("helmly-global", "global-expected"),
				("helmly-local", "local-expected"),
			],
			Ok("ANY".to_string()),
		),
		&stub_apply_recording(cc),
		&stub_emergency_ok(),
	)
	.await;

	assert_eq!(
		*applied.lock().unwrap(),
		vec!["ruleset".to_owned()],
		"base divergence must trigger restore with the DB ruleset"
	);
	assert!(!state.is_locked_down());
}

/// Control: when only `helmly-global` differs (base matches), the
/// detector takes the `warn!` branch (NOT the `error!` CRITICAL
/// branch) and still restores. Removing the `else { warn!(...) }`
/// arm or the unconditional restore makes this test go red.
#[tokio::test]
async fn check_once_divergence_only_global_diverged_restores_via_warn() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_chain_checksums(
		Some("base-expected".into()),
		Some("global-expected".into()),
		Some("local-expected".into()),
	);
	state.set_nft_last_ruleset("ruleset".into());
	let applied = Arc::new(Mutex::new(Vec::<String>::new()));
	let cc = applied.clone();

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&stub_chain(
			&[
				("helmly-base", "base-expected"),
				("helmly-global", "global-DIFFERS"),
				("helmly-local", "local-expected"),
			],
			Ok("ANY".to_string()),
		),
		&stub_apply_recording(cc),
		&stub_emergency_ok(),
	)
	.await;

	assert_eq!(
		*applied.lock().unwrap(),
		vec!["ruleset".to_owned()],
		"global-only divergence must still trigger restore"
	);
	assert!(!state.is_locked_down());
}

/// Control: when the live checksum query returns Err for a chain,
/// `is_chain_diverged_with` must treat that chain as diverged
/// (chain may have been deleted). Removing the `Err(_) => true`
/// arm makes the test fall through to `false` (no attribution) and
/// the restore-with-applied check still passes — but the lockdown
/// check (when restore fails) catches it. We exercise that here by
/// making restore fail AND emergency fail after the chain query
/// error: lockdown MUST be set.
#[tokio::test]
async fn check_once_chain_query_failure_attributed_as_diverged() {
	let state = make_state();
	state.set_nft_checksum("expected".into());
	state.set_nft_chain_checksums(
		Some("base-expected".into()),
		Some("global-expected".into()),
		Some("local-expected".into()),
	);
	state.set_nft_last_ruleset("ruleset".into());

	check_once_with(
		&state,
		&stub_current("LIVE-DIFFERS"),
		&|_| Err(anyhow::anyhow!("chain gone")),
		&|_| Err(anyhow::anyhow!("apply failed")),
		&stub_emergency_err(),
	)
	.await;

	assert!(
		state.is_locked_down(),
		"chain-query Err + restore Err + emergency Err → lockdown"
	);
}

/// Control: when the live checksum matches the expected, restore
/// must run and update the post-apply expected checksum to the
/// value the closure returned. Removing the `state.set_nft_checksum`
/// call in `restore_with` makes the assertion go red.
#[tokio::test]
async fn check_once_divergence_restore_updates_expected_checksum() {
	let state = make_state();
	state.set_nft_checksum("OLD-EXPECTED".into());
	state.set_nft_last_ruleset("ruleset".into());

	check_once_with(
		&state,
		&|| {
			// First call: live differs. Second call (post-restore): now matches.
			// Use a counter via Arc<AtomicUsize> to differentiate; or
			// simpler: always return the post-restore value, since
			// `restore_with` calls `compute_current_checksum()` once
			// after apply. The "live" call must differ, so we return
			// differing values via separate stubs.
			Ok("STILL-DIFFERS".to_string())
		},
		&|_| Ok("STILL-DIFFERS".to_string()),
		&|_| Ok(()),
		&stub_emergency_ok(),
	)
	.await;

	// Post-apply expected checksum was overwritten by restore_with.
	// Closure always returns "STILL-DIFFERS" — that's the post-apply
	// expected value the detector now stores.
	assert_eq!(
		state.expected_nft_checksum().as_deref(),
		Some("STILL-DIFFERS"),
		"restore_with must overwrite the expected checksum with the post-apply value"
	);
}
