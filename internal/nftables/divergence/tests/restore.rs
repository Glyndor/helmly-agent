use super::*;

// ---------- Section C — restore_with ---------------------------------

/// Control: when `state.nft_last_ruleset()` is None, `restore_with`
/// must return Err *before* calling the apply closure. Removing
/// the `ok_or_else(...)` arm makes the closure panic.
#[tokio::test]
async fn restore_with_no_last_ruleset_errors_without_calling_apply() {
    let state = make_state();
    let r = restore_with(
        &state,
        &|| Ok("ANY".to_string()),
        &|_| Ok("ANY".to_string()),
        &|_| panic!("apply must not be called when no last ruleset"),
    );
    let err = r.expect_err("no last ruleset must Err");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no last ruleset"),
        "rejection must name the cause; got: {msg}"
    );
}

/// Control: when restore succeeds, the post-apply expected checksum
/// and per-chain checksums must be overwritten with the values the
/// runners returned. Removing the `state.set_nft_checksum(...)`
/// and `state.set_nft_chain_checksums(...)` calls makes this test red.
#[tokio::test]
async fn restore_with_success_updates_expected_checksums() {
    let state = make_state();
    state.set_nft_last_ruleset("ruleset".into());

    let r = restore_with(
        &state,
        &|| Ok("new-table-checksum".into()),
        &|c| Ok(format!("new-{c}")),
        &|_| Ok(()),
    );
    assert!(r.is_ok(), "successful restore must Ok");

    assert_eq!(
        state.expected_nft_checksum().as_deref(),
        Some("new-table-checksum"),
        "post-apply table checksum must be stored"
    );
    assert_eq!(
        state.expected_chain_checksum(0).as_deref(),
        Some("new-helmly-base"),
        "post-apply base chain checksum must be stored"
    );
    assert_eq!(
        state.expected_chain_checksum(1).as_deref(),
        Some("new-helmly-global"),
        "post-apply global chain checksum must be stored"
    );
    assert_eq!(
        state.expected_chain_checksum(2).as_deref(),
        Some("new-helmly-local"),
        "post-apply local chain checksum must be stored"
    );
}

/// Control: when apply fails, `restore_with` must propagate the Err
/// without updating the state. Removing the `apply_nft_ruleset(&last)?;`
/// line (e.g. always returning Ok) makes the closure's Err invisible
/// to the caller.
#[tokio::test]
async fn restore_with_apply_failure_returns_error_and_skips_state_update() {
    let state = make_state();
    state.set_nft_last_ruleset("ruleset".into());

    let r = restore_with(
        &state,
        &|| panic!("current_checksum closure must not be called when apply fails"),
        &|_| panic!("chain_checksum closure must not be called when apply fails"),
        &|_| Err(anyhow::anyhow!("apply boom")),
    );

    assert!(r.is_err(), "apply failure must surface as Err");
    assert!(
        state.expected_nft_checksum().is_none(),
        "state must not be updated when apply fails"
    );
    assert_eq!(
        *state.nft_chain_checksums.lock().unwrap(),
        [None, None, None],
        "per-chain checksums must not be touched when apply fails"
    );
}
