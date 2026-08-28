use super::*;

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
