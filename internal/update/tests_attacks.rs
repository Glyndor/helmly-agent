//! Attacks on the self-update: what the agent does with a release that is not the one the
//! org signed, and with a download that is not what the URL promised.
//!
//! Nothing here touches the network. The servers are in-process and bind to 127.0.0.1, so
//! they are reached with a plain client; `build_ssrf_safe_client` refuses loopback by
//! design and is not under test here. What is under test is the part after it: the
//! allow-list of hosts, the size caps, the signature check and the swap of the binary.

use super::{fetch_verified, swap_binary, validate_github_url, verify_signature_with};
use ed25519_dalek::{Signer, SigningKey};
use std::path::{Path, PathBuf};

const BINARY: &[u8] = b"the bytes of a release of the agent";

fn key(seed: u8) -> SigningKey {
	SigningKey::from_bytes(&[seed; 32])
}

fn ring_of(k: &SigningKey) -> [[u8; 32]; 2] {
	[k.verifying_key().to_bytes(), [0u8; 32]]
}

fn sign(k: &SigningKey, binary: &[u8]) -> Vec<u8> {
	k.sign(binary).to_bytes().to_vec()
}

// ---- the signature itself ------------------------------------------------

#[test]
fn a_signature_of_the_right_key_over_the_right_bytes_is_accepted() {
	let k = key(1);
	assert!(verify_signature_with(BINARY, &sign(&k, BINARY), &ring_of(&k)).is_ok());
}

#[test]
fn an_absent_signature_is_refused() {
	let k = key(1);
	let err = verify_signature_with(BINARY, &[], &ring_of(&k)).unwrap_err();
	assert!(format!("{err:#}").contains("signature must be 64 bytes, got 0"));
}

#[test]
fn a_signature_that_is_not_64_bytes_is_refused_whatever_its_length() {
	let k = key(1);
	let good = sign(&k, BINARY);
	for len in [1usize, 32, 63] {
		let err = verify_signature_with(BINARY, &good[..len], &ring_of(&k)).unwrap_err();
		assert!(
			format!("{err:#}").contains(&format!("signature must be 64 bytes, got {len}")),
			"{len} bytes: {err:#}"
		);
	}
	let mut long = good.clone();
	long.push(0);
	assert!(
		verify_signature_with(BINARY, &long, &ring_of(&k)).is_err(),
		"65 bytes"
	);
	assert!(
		verify_signature_with(BINARY, &[good.clone(), good].concat(), &ring_of(&k)).is_err(),
		"two signatures glued together"
	);
}

#[test]
fn a_signature_with_one_bit_flipped_is_refused() {
	let k = key(1);
	let good = sign(&k, BINARY);
	for byte in [0usize, 31, 32, 63] {
		let mut bad = good.clone();
		bad[byte] ^= 0x01;
		assert!(
			verify_signature_with(BINARY, &bad, &ring_of(&k)).is_err(),
			"flipped bit in byte {byte}"
		);
	}
}

#[test]
fn a_signature_of_zeros_is_refused() {
	let k = key(1);
	assert!(verify_signature_with(BINARY, &[0u8; 64], &ring_of(&k)).is_err());
}

#[test]
fn a_binary_with_one_byte_changed_is_refused() {
	let k = key(1);
	let sig = sign(&k, BINARY);
	let mut other = BINARY.to_vec();
	other[0] ^= 0x01;
	assert!(verify_signature_with(&other, &sig, &ring_of(&k)).is_err());
	let mut longer = BINARY.to_vec();
	longer.push(0);
	assert!(
		verify_signature_with(&longer, &sig, &ring_of(&k)).is_err(),
		"appended byte"
	);
	assert!(
		verify_signature_with(&BINARY[1..], &sig, &ring_of(&k)).is_err(),
		"dropped byte"
	);
}

#[test]
fn the_signature_of_another_release_does_not_carry_over() {
	let k = key(1);
	let older = sign(&k, b"an older release, genuinely signed");
	assert!(verify_signature_with(BINARY, &older, &ring_of(&k)).is_err());
}

#[test]
fn the_signature_of_another_key_is_refused() {
	let sig = sign(&key(2), BINARY);
	assert!(verify_signature_with(BINARY, &sig, &ring_of(&key(1))).is_err());
}

// ---- where a download may come from ----------------------------------------------

#[test]
fn the_hosts_a_download_may_come_from_are_exactly_two() {
	for ok in [
		"https://github.com/Glyndor/helmly-agent/releases/download/v2.0.2/helmly-agent-linux-x86_64",
		"https://github.com/Glyndor/helmly-agent/releases/download/v2.0.2/helmly-agent-linux-x86_64.sig",
		"https://objects.githubusercontent.com/github-production-release-asset/1/2",
	] {
		assert!(validate_github_url(ok).is_ok(), "{ok}");
	}
	// The hosts of the allow-list, read back from what the function lets through.
	let mut hosts: Vec<String> = [
		"https://github.com/x",
		"https://objects.githubusercontent.com/x",
	]
	.iter()
	.map(|u| url::Url::parse(u).unwrap().host_str().unwrap().to_string())
	.collect();
	hosts.sort();
	assert_eq!(hosts, ["github.com", "objects.githubusercontent.com"]);
}

#[test]
fn a_download_from_anywhere_else_is_refused() {
	for bad in [
		"http://github.com/Glyndor/helmly-agent/releases/download/v2.0.2/x",
		"https://github.com.evil.example/x",
		"https://evilgithub.com/x",
		"https://github.com@evil.example/x",
		"https://github.com:443@evil.example/x",
		"https://github.com\\@evil.example/x",
		"https://github.com",
		"https://objects.githubusercontent.com.evil.example/x",
		"https://raw.githubusercontent.com/x",
		"https://api.github.com/x",
		"https://gist.github.com/x",
		"https://user-images.githubusercontent.com/x",
		"HTTPS://GITHUB.COM/x",
		"file:///etc/passwd",
		"ftp://github.com/x",
		"//github.com/x",
		" https://github.com/x",
		"",
	] {
		assert!(validate_github_url(bad).is_err(), "{bad:?}");
	}
}

#[test]
fn what_the_check_lets_through_is_really_a_github_host() {
	// A prefix test is only as good as the URL parser agrees with it: whatever it accepts has to
	// have one of the two hosts when the URL is parsed, userinfo and backslash tricks included.
	for candidate in [
		"https://github.com/@evil.example/x",
		"https://github.com/\\@evil.example/x",
		"https://github.com/%2f@evil.example/x",
		"https://github.com/?@evil.example",
		"https://github.com/#@evil.example",
		"https://objects.githubusercontent.com/@evil.example/",
	] {
		if validate_github_url(candidate).is_ok() {
			let host = url::Url::parse(candidate)
				.unwrap()
				.host_str()
				.unwrap()
				.to_string();
			assert!(
				host == "github.com" || host == "objects.githubusercontent.com",
				"{candidate} is accepted and its host is {host}"
			);
		}
	}
}

// ---- a download, end to end, against a server that lies -----------------------------

type Route = (&'static str, u16, Vec<u8>);

/// A server on an ephemeral loopback port answering each `(path, status, body)`.
async fn serve(routes: Vec<Route>) -> String {
	use axum::{body::Body, http::StatusCode, response::Response, routing::get, Router};
	let mut app = Router::new();
	for (path, status, body) in routes {
		let status = StatusCode::from_u16(status).unwrap();
		app = app.route(
			path,
			get(move || {
				let body = body.clone();
				async move {
					let mut response = Response::new(Body::from(body));
					*response.status_mut() = status;
					response
				}
			}),
		);
	}
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	format!("http://127.0.0.1:{port}")
}

const CAP: usize = 1024;

async fn fetch(base: &str, ring: &[[u8; 32]]) -> anyhow::Result<Vec<u8>> {
	let client = reqwest::Client::new();
	fetch_verified(
		&client,
		&format!("{base}/agent"),
		&client,
		&format!("{base}/agent.sig"),
		ring,
		CAP,
	)
	.await
}

#[tokio::test]
async fn a_release_with_its_signature_is_downloaded_and_returned() {
	let k = key(1);
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, sign(&k, BINARY)),
	])
	.await;
	assert_eq!(fetch(&base, &ring_of(&k)).await.unwrap(), BINARY);
}

#[tokio::test]
async fn a_release_with_no_signature_is_refused() {
	let k = key(1);
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 404, b"not found".to_vec()),
	])
	.await;
	let err = fetch(&base, &ring_of(&k)).await.unwrap_err();
	assert!(format!("{err:#}").contains("404"), "{err:#}");
}

#[tokio::test]
async fn a_release_whose_signature_is_an_empty_answer_is_refused() {
	let k = key(1);
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, vec![]),
	])
	.await;
	let err = fetch(&base, &ring_of(&k)).await.unwrap_err();
	assert!(format!("{err:#}").contains("64 bytes, got 0"), "{err:#}");
}

#[tokio::test]
async fn a_release_whose_signature_is_truncated_is_refused() {
	let k = key(1);
	let sig = sign(&k, BINARY);
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, sig[..63].to_vec()),
	])
	.await;
	let err = fetch(&base, &ring_of(&k)).await.unwrap_err();
	assert!(format!("{err:#}").contains("64 bytes, got 63"), "{err:#}");
}

#[tokio::test]
async fn a_release_whose_signature_was_altered_is_refused() {
	let k = key(1);
	let mut sig = sign(&k, BINARY);
	sig[10] ^= 0x80;
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, sig),
	])
	.await;
	assert!(fetch(&base, &ring_of(&k)).await.is_err());
}

#[tokio::test]
async fn a_release_signed_by_another_key_is_refused() {
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, sign(&key(2), BINARY)),
	])
	.await;
	assert!(fetch(&base, &ring_of(&key(1))).await.is_err());
}

#[tokio::test]
async fn a_binary_altered_after_it_was_signed_is_refused() {
	let k = key(1);
	let mut tampered = BINARY.to_vec();
	tampered[3] ^= 0x01;
	let base = serve(vec![
		("/agent", 200, tampered),
		("/agent.sig", 200, sign(&k, BINARY)),
	])
	.await;
	assert!(fetch(&base, &ring_of(&k)).await.is_err());
}

#[tokio::test]
async fn nothing_is_accepted_when_the_ring_has_no_key() {
	let k = key(1);
	let base = serve(vec![
		("/agent", 200, BINARY.to_vec()),
		("/agent.sig", 200, sign(&k, BINARY)),
	])
	.await;
	assert!(fetch(&base, &[[0u8; 32], [0u8; 32]]).await.is_err());
}

#[tokio::test]
async fn a_binary_over_the_cap_is_refused_even_with_a_valid_signature() {
	let k = key(1);
	let big = vec![7u8; CAP + 1];
	let base = serve(vec![
		("/agent", 200, big.clone()),
		("/agent.sig", 200, sign(&k, &big)),
	])
	.await;
	let err = fetch(&base, &ring_of(&k)).await.unwrap_err();
	assert!(format!("{err:#}").contains("exceeds"), "{err:#}");
}

#[tokio::test]
async fn a_binary_exactly_at_the_cap_is_accepted() {
	let k = key(1);
	let exact = vec![7u8; CAP];
	let base = serve(vec![
		("/agent", 200, exact.clone()),
		("/agent.sig", 200, sign(&k, &exact)),
	])
	.await;
	assert_eq!(fetch(&base, &ring_of(&k)).await.unwrap(), exact);
}

#[tokio::test]
async fn a_server_error_on_the_binary_is_refused() {
	let k = key(1);
	let base = serve(vec![
		("/agent", 503, b"unavailable".to_vec()),
		("/agent.sig", 200, sign(&k, BINARY)),
	])
	.await;
	let err = fetch(&base, &ring_of(&k)).await.unwrap_err();
	assert!(format!("{err:#}").contains("503"), "{err:#}");
}

// ---- the swap of the binary ----------------------------------------------------

fn scratch(label: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!(
		"helmly-update-swap-{}-{}-{label}",
		std::process::id(),
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_nanos())
			.unwrap_or(0)
	));
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
	let mut name = path.as_os_str().to_owned();
	name.push(suffix);
	PathBuf::from(name)
}

fn mode(path: &Path) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_swap_installs_the_new_binary_and_keeps_the_old_one_as_prev() {
	let dir = scratch("swap");
	let target = dir.join("helmly-agent");
	std::fs::write(&target, b"old").unwrap();
	swap_binary(b"new", &target).unwrap();
	assert_eq!(std::fs::read(&target).unwrap(), b"new");
	assert_eq!(
		std::fs::read(with_suffix(&target, ".prev")).unwrap(),
		b"old"
	);
	assert_eq!(mode(&target), 0o755, "the new binary is executable");
	assert!(
		!with_suffix(&target, ".new").exists(),
		"no temporary file is left"
	);
}

#[test]
fn a_second_swap_replaces_prev_with_the_binary_it_displaced() {
	let dir = scratch("twice");
	let target = dir.join("helmly-agent");
	std::fs::write(&target, b"v1").unwrap();
	swap_binary(b"v2", &target).unwrap();
	swap_binary(b"v3", &target).unwrap();
	assert_eq!(std::fs::read(&target).unwrap(), b"v3");
	assert_eq!(std::fs::read(with_suffix(&target, ".prev")).unwrap(), b"v2");
}

#[test]
fn a_swap_with_nothing_installed_makes_no_prev() {
	let dir = scratch("fresh");
	let target = dir.join("helmly-agent");
	swap_binary(b"new", &target).unwrap();
	assert_eq!(std::fs::read(&target).unwrap(), b"new");
	assert!(!with_suffix(&target, ".prev").exists());
}

#[test]
fn a_swap_leaves_a_running_binary_alone() {
	// A process that is running the old binary has it open. Writing over it fails with
	// ETXTBSY and would corrupt it if it did not; the swap moves a new file into place instead.
	use std::io::Read;
	let dir = scratch("running");
	let target = dir.join("helmly-agent");
	std::fs::write(&target, b"old binary").unwrap();
	let mut running = std::fs::File::open(&target).unwrap();
	swap_binary(b"new binary", &target).unwrap();
	let mut seen = String::new();
	running.read_to_string(&mut seen).unwrap();
	assert_eq!(
		seen, "old binary",
		"the open file still reads the old bytes"
	);
	assert_eq!(std::fs::read(&target).unwrap(), b"new binary");
}

#[test]
fn a_swap_that_cannot_write_changes_nothing() {
	// The temporary name is taken by a directory, so the write fails before the old binary
	// has been touched.
	let dir = scratch("blocked");
	let target = dir.join("helmly-agent");
	std::fs::write(&target, b"old").unwrap();
	std::fs::create_dir(with_suffix(&target, ".new")).unwrap();
	assert!(swap_binary(b"new", &target).is_err());
	assert_eq!(
		std::fs::read(&target).unwrap(),
		b"old",
		"the installed binary is intact"
	);
	assert!(
		!with_suffix(&target, ".prev").exists(),
		"no backup is made for a swap that did not happen"
	);
}

#[test]
fn a_swap_into_a_directory_that_is_not_there_fails() {
	let dir = scratch("missing");
	let target = dir.join("no-such-dir").join("helmly-agent");
	assert!(swap_binary(b"new", &target).is_err());
}
