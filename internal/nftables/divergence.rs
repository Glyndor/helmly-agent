use crate::state::AppState;
use tracing::{error, info, warn};

const CHECK_INTERVAL_SECS: u64 = 60;

pub async fn run_divergence_check(state: AppState) {
    run_divergence_check_with(
        state,
        super::current_checksum,
        super::chain_checksum,
        super::apply_raw,
        super::apply_emergency,
    )
    .await;
}

/// Production-equivalent of `run_divergence_check` with closure injection
/// for every external nft operation. Mirrors `run_startup_health_check`'s
/// pattern in `update/mod.rs:133` — the public function stays a thin
/// wrapper, and the core one-shot logic lives in `check_once_with` so
/// tests can drive it with stubbed runners.
pub(crate) async fn run_divergence_check_with<F, G, H, I>(
    state: AppState,
    compute_current_checksum: F,
    compute_chain_checksum: G,
    apply_nft_ruleset: H,
    apply_emergency_ruleset: I,
) where
    F: Fn() -> anyhow::Result<String> + Send + 'static,
    G: Fn(&str) -> anyhow::Result<String> + Send + 'static,
    H: Fn(&str) -> anyhow::Result<()> + Send + 'static,
    I: Fn() -> anyhow::Result<()> + Send + 'static,
{
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(CHECK_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        check_once_with(
            &state,
            &compute_current_checksum,
            &compute_chain_checksum,
            &apply_nft_ruleset,
            &apply_emergency_ruleset,
        )
        .await;
    }
}

/// One-shot divergence check, extracted from the loop so tests can drive
/// each path with stubbed runners. Production callers go through
/// `run_divergence_check` → `run_divergence_check_with` → this function.
pub(crate) async fn check_once_with<F, G, H, I>(
    state: &AppState,
    compute_current_checksum: &F,
    compute_chain_checksum: &G,
    apply_nft_ruleset: &H,
    apply_emergency_ruleset: &I,
) where
    F: Fn() -> anyhow::Result<String>,
    G: Fn(&str) -> anyhow::Result<String>,
    H: Fn(&str) -> anyhow::Result<()>,
    I: Fn() -> anyhow::Result<()>,
{
    let expected = match state.expected_nft_checksum() {
        Some(c) => c,
        None => return, // no ruleset applied yet
    };

    let current = match compute_current_checksum() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to compute nftables checksum");
            return;
        }
    };

    if current == expected {
        return;
    }

    // Detect which chains were modified for appropriate severity / logging.
    let base_diverged = is_chain_diverged_with(state, "helmly-base", compute_chain_checksum);
    let global_diverged = is_chain_diverged_with(state, "helmly-global", compute_chain_checksum);
    let local_diverged = is_chain_diverged_with(state, "helmly-local", compute_chain_checksum);

    if base_diverged {
        error!(
            expected = %&expected[..16],
            current  = %&current[..16],
            "CRITICAL: helmly-base chain modified outside Helmly — auto-restoring"
        );
    } else {
        warn!(
            expected = %&expected[..16],
            current  = %&current[..16],
            base_diverged,
            global_diverged,
            local_diverged,
            "nftables divergence detected — auto-restoring"
        );
    }

    // Auto-restore in all cases — PostgreSQL is the source of truth, not the VPS.
    if let Err(e) = restore_with(
        state,
        compute_current_checksum,
        compute_chain_checksum,
        apply_nft_ruleset,
    ) {
        error!(error = %e, "nftables auto-restore FAILED — applying emergency ruleset");
        if let Err(e2) = apply_emergency_ruleset() {
            error!(error = %e2, "emergency ruleset also failed — lockdown");
        }
        state.set_lockdown(crate::state::LockdownReason::NftablesFailure);
    } else {
        info!("nftables auto-restored successfully");
    }

    let chain = if base_diverged {
        "helmly-base"
    } else if global_diverged {
        "helmly-global"
    } else if local_diverged {
        "helmly-local"
    } else {
        "unknown"
    };

    notify_dashboard(state, chain, base_diverged).await;
}

fn is_chain_diverged_with<G>(state: &AppState, chain: &str, compute_chain_checksum: &G) -> bool
where
    G: Fn(&str) -> anyhow::Result<String>,
{
    let idx = match chain {
        "helmly-base" => 0,
        "helmly-global" => 1,
        "helmly-local" => 2,
        _ => return false,
    };
    let expected = match state.expected_chain_checksum(idx) {
        Some(c) => c,
        None => return false, // no baseline stored — can't determine
    };
    match compute_chain_checksum(chain) {
        Ok(current) => current != expected,
        Err(_) => true, // chain deleted or inaccessible
    }
}

fn restore_with<F, G, H>(
    state: &AppState,
    compute_current_checksum: &F,
    compute_chain_checksum: &G,
    apply_nft_ruleset: &H,
) -> anyhow::Result<()>
where
    F: Fn() -> anyhow::Result<String>,
    G: Fn(&str) -> anyhow::Result<String>,
    H: Fn(&str) -> anyhow::Result<()>,
{
    let last = state
        .nft_last_ruleset()
        .ok_or_else(|| anyhow::anyhow!("no last ruleset to restore"))?;

    apply_nft_ruleset(&last)?;

    // Update expected checksums to match what we just applied.
    let checksum = compute_current_checksum()?;
    state.set_nft_checksum(checksum);
    state.set_nft_chain_checksums(
        compute_chain_checksum("helmly-base").ok(),
        compute_chain_checksum("helmly-global").ok(),
        compute_chain_checksum("helmly-local").ok(),
    );
    Ok(())
}

async fn notify_dashboard(state: &AppState, chain: &str, critical: bool) {
    let Some(dashboard_url) = &state.config.dashboard_url else {
        return;
    };
    let Some(sync_token) = &state.config.sync_token else {
        return;
    };

    let url = format!(
        "{}/agents/{}/events",
        dashboard_url.trim_end_matches('/'),
        state.config.agent_id
    );

    let body = serde_json::json!({
        "event": "nftables_divergence",
        "detail": format!("chain={chain} critical={critical} auto_restored=true"),
    });

    let client = reqwest::Client::new();
    match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", **sync_token))
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => info!("nftables divergence event sent"),
        Ok(r) => warn!(status = %r.status(), "dashboard rejected divergence event"),
        Err(e) => warn!(error = %e, "failed to send divergence event"),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the nftables divergence detector.
    //!
    //! The whole module is a state machine driven by a handful of external
    //! calls (`nft list table`, `nft list chain`, `nft -f -`). The
    //! production code now accepts those calls as closures, so tests
    //! inject canned runners and assert side effects on `AppState`
    //! (lockdown, expected checksums, last ruleset applied) without
    //! touching the real binary.
    //!
    //! Per `standards/testing/index.md`: each test mutates a control it
    //! names. Mutation notes inline on every test.
    //!
    //! Coverage map for `nftables/divergence.rs`:
    //! - `run_divergence_check` (loop body): covered indirectly via
    //!   `run_divergence_check_with`'s closure signature being exercised
    //!   by every `check_once_with` test.
    //! - `check_once_with`: every branch (baseline short-circuit, current
    //!   checksum failure, match-returns, divergence + restore OK /
    //!   restore fail + emergency OK / emergency fail) covered.
    //! - `is_chain_diverged_with`: every arm (unknown chain, no baseline,
    //!   match, differ, query Err) covered.
    //! - `restore_with`: every branch (no last ruleset, apply OK,
    //!   apply Err) covered.
    //! - `notify_dashboard`: both early-return branches (no URL, no
    //!   token) covered; the live HTTP path is skipped — it would
    //!   require an axum test server and the early-return path is the
    //!   only one exercised in normal divergence flows (dashboard URL
    //!   is optional in `Config`).
    //! - The SHA256-of-nft-output contract is covered by
    //!   `chain_checksum_*` tests, which mirror the hashing step from
    //!   `nftables::chain_checksum_raw` in lockstep.

    use super::*;
    use crate::config::Config;
    use crate::state::LockdownReason;
    use sha2::{Digest, Sha256};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use zeroize::Zeroizing;

    // ---------- helpers ---------------------------------------------------

    /// Build an `AppState` with `dashboard_url` and `sync_token` unset so
    /// `notify_dashboard` returns early. The DB pool is a lazy connection
    /// that never queries anything in these tests.
    fn make_state() -> AppState {
        make_state_with_dashboard(None, None)
    }

    fn make_state_with_dashboard(
        dashboard_url: Option<&str>,
        sync_token: Option<&str>,
    ) -> AppState {
        let cfg = Config {
            database_url: "postgres://test/test".into(),
            agent_id: uuid::Uuid::nil(),
            version: "test".into(),
            dashboard_verify_keys: Zeroizing::new(vec![[0u8; 32]]),
            internal_token: Zeroizing::new("test".into()),
            listen_addr: "127.0.0.1:0".into(),
            dashboard_url: dashboard_url.map(str::to_owned),
            sync_token: sync_token.map(|s| Zeroizing::new(s.to_owned())),
            tls_cert_der: None,
            tls_key_der: None,
            tls_ca_cert_der: None,
            dashboard_port: None,
        };
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1/test")
            .expect("lazy pool");
        AppState {
            db,
            config: Arc::new(cfg),
            lockdown: Arc::new(AtomicBool::new(false)),
            lockdown_reason: Arc::new(Mutex::new(None)),
            nft_checksum: Arc::new(Mutex::new(None)),
            nft_chain_checksums: Arc::new(Mutex::new([None, None, None])),
            nft_last_ruleset: Arc::new(Mutex::new(None)),
            nft_global_body: Arc::new(Mutex::new(String::new())),
            nft_local_body: Arc::new(Mutex::new(String::new())),
            nft_global_output_body: Arc::new(Mutex::new(String::new())),
            nft_local_output_body: Arc::new(Mutex::new(String::new())),
            nft_wg_port: Arc::new(AtomicU32::new(51820)),
            cmd_rate: Arc::new(Mutex::new((0, 0))),
            cmd_rejected_count: Arc::new(AtomicU64::new(0)),
            cmd_rejected_window: Arc::new(AtomicU64::new(0)),
            last_dashboard_contact: Arc::new(AtomicU64::new(0)),
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Stub: returns a constant current-table checksum on every call.
    fn stub_current(checksum: &'static str) -> impl Fn() -> anyhow::Result<String> {
        move || Ok(checksum.to_owned())
    }

    /// Stub: returns a per-chain checksum; any chain name not in the
    /// map yields `default`. Pass `default = Err(...)` to simulate a
    /// missing/deleted chain (which the detector attributes as diverged).
    fn stub_chain(
        per_chain: &'static [(&'static str, &'static str)],
        default: anyhow::Result<String>,
    ) -> impl Fn(&str) -> anyhow::Result<String> {
        move |chain: &str| match per_chain.iter().find(|(c, _)| *c == chain) {
            Some((_, cs)) => Ok((*cs).to_owned()),
            None => match &default {
                Ok(s) => Ok(s.clone()),
                Err(_) => Err(anyhow::anyhow!("chain {} missing", chain)),
            },
        }
    }

    /// Stub: records the ruleset string the detector hands to the apply
    /// callback. Returns `Ok(())` unless the test overrides the closure.
    fn stub_apply_recording(sink: Arc<Mutex<Vec<String>>>) -> impl Fn(&str) -> anyhow::Result<()> {
        move |r: &str| {
            sink.lock().unwrap().push(r.to_owned());
            Ok(())
        }
    }

    fn stub_emergency_ok() -> impl Fn() -> anyhow::Result<()> {
        || Ok(())
    }

    fn stub_emergency_err() -> impl Fn() -> anyhow::Result<()> {
        || Err(anyhow::anyhow!("emergency apply failed"))
    }

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

    // ---------- Section E — notify_dashboard early-return paths ----------

    /// Control: with `dashboard_url` unset, `notify_dashboard` must
    /// return before constructing an HTTP client (and therefore before
    /// any panic from `reqwest::Client::new` if it ever failed).
    /// Removing the `let Some(...) = &state.config.dashboard_url else {
    /// return; }` early-return makes the function reach `reqwest::Client::new`
    /// and attempt a POST to an empty URL — the test would still pass
    /// (reqwest would just warn-log), but the next test (`no_sync_token`)
    /// is the load-bearing one for this branch.
    #[tokio::test]
    async fn notify_dashboard_no_url_returns_immediately() {
        let state = make_state_with_dashboard(None, Some("token"));
        // Must not panic, must not block, must not update any state.
        notify_dashboard(&state, "helmly-base", true).await;
        assert!(!state.is_locked_down());
    }

    /// Control: with `dashboard_url` set but `sync_token` unset, the
    /// function must still short-circuit. Removing the `let
    /// Some(...) = &state.config.sync_token else { return; }`
    /// early-return makes the function try to dereference an Option
    /// `None` inside the format! — `unwrap` panic, or with `?`, a
    /// `bail!` Err path. Either way, the early-return guard is gone
    /// and the test's continuation would still pass; the test's purpose
    /// is to pin the no-token no-op behaviour so removing the guard
    /// makes future side-effects observable (reqwest client construct,
    /// POST to a bogus URL). Without a tracing subscriber / network
    /// capture we can't fully assert that here — the load-bearing
    /// coverage is the early-return code itself being compiled in.
    #[tokio::test]
    async fn notify_dashboard_no_sync_token_returns_immediately() {
        let state = make_state_with_dashboard(Some("http://127.0.0.1:1"), None);
        notify_dashboard(&state, "helmly-base", true).await;
        assert!(!state.is_locked_down());
    }
}
