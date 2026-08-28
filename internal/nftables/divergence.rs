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
mod tests;
