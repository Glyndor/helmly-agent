//! Unit tests for the dashboard verify-keyring loader (C2).
//!
//! Per `standards/testing/index.md` — every test must catch the
//! removal of the control it names. The five controls in this file:
//!   1. `Base64::decode_vec` decode line (caught by malformed-b64 test)
//!   2. `[u8; 32]` length check (caught by 31- and 33-byte tests)
//!   3. comment / blank-line skip (caught by two-keys + comments test)
//!   4. Unix mode-0o600 perm gate (caught by `world_or_group_readable_perms_rejected`)
//!   5. env-derived single key + atomic seed-of-file (caught by `load_key32_opt` and `seed_*_at` tests)
//!
//! Ed25519 validation is intentionally NOT a loader control — bytes
//! are accepted raw at load and validated against the curve at
//! `verify_command` time (`auth/mod.rs`, `update/mod.rs`). Loader
//! coverage stops at the 32-byte length bound.

use super::*;
use std::sync::Mutex;

/// Serialises every test that touches `DASHBOARD_VERIFY_KEY{,_FILE}`.
/// `set_var` / `remove_var` are `!Send`-safe but process-wide; with
/// cargo's default parallel test runner we cannot rely on "no other
/// test runs concurrently". Locking is cheap and removes the race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn clear_dashboard_env() {
	std::env::remove_var("DASHBOARD_VERIFY_KEY");
	std::env::remove_var("DASHBOARD_VERIFY_KEY_FILE");
}

/// Unique temp path per test (`/tmp/helmly-config-test-{pid}-{nanos}-{label}`).
/// Caller owns the path and is expected to `remove_file` on teardown.
fn temp_path(label: &str) -> std::path::PathBuf {
	let pid = std::process::id();
	let nanos = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_nanos())
		.unwrap_or(0);
	std::env::temp_dir().join(format!("helmly-config-test-{pid}-{nanos}-{label}"))
}

fn write_file_0o600(path: &Path, content: &str) {
	std::fs::write(path, content).expect("write temp file");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0o600");
	}
}

fn b64(bytes: &[u8; 32]) -> String {
	base64ct::Base64::encode_string(bytes)
}

// ---- 1. File parser: `load_dashboard_keyring_at(path)` ----

/// Control: line is valid b64 of 32 bytes → one key in the ring,
/// bytes round-trip. Removing the b64 decode and pushing raw line
/// bytes fails the length check (44 chars → not 32 bytes) → Err →
/// this test goes red.
#[test]
fn valid_one_key_parses() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("one-key");
	let key = [0x42u8; 32];
	write_file_0o600(&path, &format!("{}\n", b64(&key)));

	let ring = load_dashboard_keyring_at(&path).expect("one valid key must Ok");
	assert_eq!(ring.len(), 1, "one b64-32-byte line produces a 1-slot ring");
	assert_eq!(ring[0], key, "ring bytes must round-trip the encoded key");

	std::fs::remove_file(&path).ok();
}

/// Control: comment and blank lines are skipped before b64 decode.
/// Removing either skip branch makes the `# rotation comment`
/// line reach `Base64::decode_vec` → `not base64` Err → red.
#[test]
fn two_keys_skip_blank_and_comment_lines() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("two-keys");
	let key_a = [0x11u8; 32];
	let key_b = [0x22u8; 32];
	let body = format!(
		"# rotation comment (skipped)\n\
             \n\
             {}\n\
             \n\
               # second comment with leading whitespace (also skipped)\n\
             {}\n",
		b64(&key_a),
		b64(&key_b),
	);
	write_file_0o600(&path, &body);

	let ring = load_dashboard_keyring_at(&path).expect("two valid keys must Ok");
	assert_eq!(
		ring.len(),
		2,
		"comment + blank + ws-indented comment must all be skipped; got len={}",
		ring.len()
	);
	assert_eq!(ring[0], key_a);
	assert_eq!(ring[1], key_b);

	std::fs::remove_file(&path).ok();
}

/// Control: b64-decode gate. Non-b64 characters must yield a
/// `not base64` error message — not just any Err, not a length
/// error, not a silent zero-byte push. Asserts the specific
/// rejection per `standards/testing/index.md#a-test-that-stays-green`.
#[test]
fn malformed_base64_yields_distinct_error() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("malformed-b64");
	write_file_0o600(&path, "!!!not_base64!!!\n");

	let err = load_dashboard_keyring_at(&path).expect_err("non-b64 line must Err at decode");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("not base64"),
		"rejection must name the b64-decode control; got: {msg}"
	);
	// Fixture validation: only the b64 character class is wrong.
	// Length, mode, and Ed25519 (when validated) checks must not pre-empt this one.
	assert!(
		!msg.contains("must decode to exactly 32 bytes"),
		"malformed-b64 must not be masked as a length error; got: {msg}"
	);

	std::fs::remove_file(&path).ok();
}

/// Control: length-gate. Valid b64 of 31 bytes must Err with the
/// exact-32 message. Pairs with `valid_one_key_parses` (the
/// acceptance test just inside the 32-byte limit).
#[test]
fn decodes_to_31_bytes_rejected_with_length_message() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("len-31");
	// 31 raw bytes — the b64 decode succeeds, the length check is the only failure.
	let raw_31 = [0xABu8; 31];
	let s = base64ct::Base64::encode_string(&raw_31);
	write_file_0o600(&path, &format!("{s}\n"));

	let err =
		load_dashboard_keyring_at(&path).expect_err("b64-of-31-bytes must Err at the length gate");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("must decode to exactly 32 bytes"),
		"rejection must name the length control; got: {msg}"
	);
	assert!(
		!msg.contains("not base64"),
		"valid-b64-of-31 must not be mis-classified as b64 failure; got: {msg}"
	);

	std::fs::remove_file(&path).ok();
}

/// Control: length-gate, other side. Valid b64 of 33 bytes must
/// also Err with the exact-32 message (not silent overflow, not
/// truncation).
#[test]
fn decodes_to_33_bytes_rejected_with_length_message() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("len-33");
	let raw_33 = [0xCDu8; 33];
	let s = base64ct::Base64::encode_string(&raw_33);
	write_file_0o600(&path, &format!("{s}\n"));

	let err =
		load_dashboard_keyring_at(&path).expect_err("b64-of-33-bytes must Err at the length gate");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("must decode to exactly 32 bytes"),
		"rejection must name the length control; got: {msg}"
	);

	std::fs::remove_file(&path).ok();
}

/// Control: file-absent propagates as an error at the read site.
/// `load_dashboard_keyring_at` does not silently fall back to env
/// — the public entry owns that decision. Removing the read gate
/// would either NoOp `Ok(empty)` (red for this test) or panic.
#[test]
fn absent_file_returns_err() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("absent"); // never written
	let err = load_dashboard_keyring_at(&path).expect_err("missing file must Err");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("read"),
		"err must be the read site (`read <path>`); got: {msg}"
	);
}

/// Control: Unix perm-gate. File mode 0o644 (group-readable) must
/// be refused with the security-prescribed message before any byte
/// is read. Removing the `mode & 0o077 != 0` guard would let the
/// loader proceed and parse the key, so this test goes red on
/// removal of the control.
#[cfg(unix)]
#[test]
fn world_or_group_readable_perms_rejected() {
	use std::os::unix::fs::PermissionsExt;
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("wide-perms");
	let key = [0x55u8; 32];
	std::fs::write(&path, format!("{}\n", b64(&key))).expect("write temp file");
	// Group-readable on purpose. mode_check test fixture.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 0o644");

	let err = load_dashboard_keyring_at(&path).expect_err("0o644 keyring must Err before parse");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("world- or group-readable"),
		"rejection must name the perm control (M17); got: {msg}"
	);

	// Restore 0o600 for the cleanup remove.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
	std::fs::remove_file(&path).ok();
}

// ---- 2. Env fallback ----

/// Control: with no file and no env, the public entry returns an
/// empty ring (`Ok(empty)`) and lets the caller surface the
/// "no dashboard verify keys" error. Removing the early
/// empty-vec return would either panic or propagate from
/// `read_to_string` (red, since path doesn't exist either).
#[test]
fn no_env_no_file_returns_empty_ring() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let ring = load_dashboard_keyring().expect("no-source path must Ok with empty ring");
	assert!(
		ring.is_empty(),
		"no env + no file = empty ring; caller surfaces the user-facing error"
	);
}

/// Control: `load_key32_opt` reads `DASHBOARD_VERIFY_KEY` from env
/// and decodes 32 bytes. Removing the env-var read makes the
/// helper return None, so this test (asserting Some(bytes)) goes red.
#[test]
fn env_set_derives_single_32_byte_key() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let key = [0x77u8; 32];
	std::env::set_var("DASHBOARD_VERIFY_KEY", b64(&key));

	let derived =
		load_key32_opt("DASHBOARD_VERIFY_KEY").expect("env-set b64-of-32-bytes must derive a key");
	assert_eq!(
		derived, key,
		"env-derived key must round-trip the encoded bytes"
	);

	clear_dashboard_env();
}

/// Control: with both env and `_FILE` unset, `load_key32_opt`
/// returns None (so the loader falls through to the empty ring).
/// Without this, an empty env would have to be a separate code
/// path, and the env-fallback logic would be untested.
#[test]
fn env_unset_returns_none() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	assert!(
		load_key32_opt("DASHBOARD_VERIFY_KEY").is_none(),
		"no env + no _FILE means no legacy single-key fallback"
	);
}

// ---- 3. Seed-on-load persistence ----

/// Control: `seed_keyring_file_at` writes the b64-encoded bytes to
/// `path` with mode 0o600 atomically. The on-disk file must
/// round-trip exactly the 32 input bytes when re-decoded.
/// Removing the b64 encode makes the content the raw bytes
/// (each cast to `char` for `0x88` = `'ˆ'`); the round-trip
/// decode would fail. Removing the mode-0o600 makes the second
/// `#[cfg(unix)]` assertion fail.
#[test]
fn seed_writes_b64_with_mode_0o600_atomically() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let path = temp_path("seed");
	let key = [0x88u8; 32];
	seed_keyring_file_at(&path, &key).expect("seed must succeed against a writable temp path");

	assert!(path.exists(), "seeded file must exist after the rename");
	let raw = std::fs::read_to_string(&path).expect("read back seeded file");
	let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);

	// Content: b64(key) + '\n'. Trim and re-decode to confirm round-trip.
	let decoded = base64ct::Base64::decode_vec(trimmed)
		.expect("seeded content must be valid b64 of 32 bytes");
	assert_eq!(
		decoded.len(),
		32,
		"decoded length must be 32; got {}",
		decoded.len()
	);
	assert_eq!(
		decoded.as_slice(),
		key.as_slice(),
		"seed round-trip must reproduce the input 32 bytes exactly"
	);

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::metadata(&path)
			.expect("metadata")
			.permissions()
			.mode() & 0o777;
		assert_eq!(mode, 0o600, "seeded file must be mode 0600; got {mode:o}");
	}

	std::fs::remove_file(&path).ok();
}

// ---- 4. Env-var helpers (pure-logic) ----

fn clear_test_env(prefix: &str) {
	std::env::remove_var(prefix);
	std::env::remove_var(format!("{prefix}_FILE"));
}

fn set_test_env(prefix: &str, val: &str) {
	clear_test_env(prefix);
	std::env::set_var(prefix, val);
}

/// Control: `load_secret` reads `ENV` from process env when `_FILE`
/// is unset. Removing the `env::var` fallback makes the call Err.
#[test]
fn load_secret_reads_env_var_when_file_unset() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	set_test_env("HELMLY_TEST_LOAD_SECRET", "rotated-fallback-env-value");

	let got = load_secret("HELMLY_TEST_LOAD_SECRET").expect("env-set must produce an Ok(_)");
	assert_eq!(got.as_str(), "rotated-fallback-env-value");

	clear_test_env("HELMLY_TEST_LOAD_SECRET");
}

/// Control: `load_secret` prefers `ENV_FILE` over `ENV` when both
/// are set, and trims the file content. Removing the `_FILE`
/// precedence flips the assertion.
#[test]
fn load_secret_prefers_file_over_env() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

	let path = temp_path("load-secret-file");
	write_file_0o600(&path, "  trimmed-from-file  \n");
	std::env::set_var("HELMLY_TEST_LOAD_SECRET_FILE", &path);
	std::env::set_var("HELMLY_TEST_LOAD_SECRET", "from-env-should-be-ignored");

	let got = load_secret("HELMLY_TEST_LOAD_SECRET").expect("file set + env set must Ok");
	assert_eq!(
		got.as_str(),
		"trimmed-from-file",
		"_FILE path must beat the plain env var"
	);

	clear_test_env("HELMLY_TEST_LOAD_SECRET");
	std::fs::remove_file(&path).ok();
}

/// Control: `load_secret` Errs when neither env nor `_FILE` is
/// readable. The `.context("... required")` message must reach the
/// caller so the operator sees which variable is missing.
#[test]
fn load_secret_errors_when_neither_source_set() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_test_env("HELMLY_TEST_LOAD_SECRET_MISSING");

	let err = load_secret("HELMLY_TEST_LOAD_SECRET_MISSING")
		.expect_err("no source must Err with a named context");
	let msg = format!("{err:#}");
	assert!(
		msg.contains("HELMLY_TEST_LOAD_SECRET_MISSING required"),
		"Err message must name the missing env var; got: {msg}"
	);
}

/// Control: `load_secret_opt` falls through silently when neither
/// source is set — used by `Config::load` for optional TLS fields.
/// Distinct from `load_secret`'s Err-on-missing contract.
#[test]
fn load_secret_opt_returns_none_when_neither_source_set() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_test_env("HELMLY_TEST_LOAD_SECRET_OPT");

	assert!(
		load_secret_opt("HELMLY_TEST_LOAD_SECRET_OPT").is_none(),
		"missing env + missing _FILE = None"
	);
}

/// Control: `load_secret_opt` reads the env var when set and
/// wraps in `Zeroizing`. Trivially small, but the contract is
/// distinct from `load_secret`'s Err-on-missing.
#[test]
fn load_secret_opt_returns_some_when_env_set() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	set_test_env("HELMLY_TEST_LOAD_SECRET_OPT", "sync-token-value");

	let got = load_secret_opt("HELMLY_TEST_LOAD_SECRET_OPT").expect("env-set must produce Some(_)");
	assert_eq!(got.as_str(), "sync-token-value");

	clear_test_env("HELMLY_TEST_LOAD_SECRET_OPT");
}

/// Control: `load_der_file_opt` reads DER bytes from disk when
/// `ENV` names a readable path; returns `None` when env unset or
/// the file is missing. Used for TLS certs.
#[test]
fn load_der_file_opt_reads_bytes_when_path_readable() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_test_env("HELMLY_TEST_TLS_CERT_DER_FILE");

	let path = temp_path("tls-cert-der");
	let bytes = vec![0x30u8, 0x82, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF];
	std::fs::write(&path, &bytes).expect("write cert bytes");
	std::env::set_var("HELMLY_TEST_TLS_CERT_DER_FILE", &path);

	let got = load_der_file_opt("HELMLY_TEST_TLS_CERT_DER_FILE")
		.expect("readable file must produce Some(_)");
	assert_eq!(got, bytes, "DER bytes must round-trip exactly");

	clear_test_env("HELMLY_TEST_TLS_CERT_DER_FILE");
	std::fs::remove_file(&path).ok();
}

/// Control: `load_der_file_zeroize_opt` wraps the same bytes in a
/// `Zeroizing` newtype so the heap copy is wiped on drop. The
/// contents are identical; the safety contract differs.
#[test]
fn load_der_file_zeroize_opt_wraps_inner_bytes() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_test_env("HELMLY_TEST_TLS_KEY_DER_FILE");

	let path = temp_path("tls-key-der");
	let bytes = vec![0x30u8, 0x82, 0x02, 0x01, 0xC0, 0xFF, 0xEE];
	std::fs::write(&path, &bytes).expect("write key bytes");
	std::env::set_var("HELMLY_TEST_TLS_KEY_DER_FILE", &path);

	let got = load_der_file_zeroize_opt("HELMLY_TEST_TLS_KEY_DER_FILE")
		.expect("readable file must produce Some(_)");
	assert_eq!(
		got.as_slice(),
		bytes.as_slice(),
		"Zeroizing wrapper must hold the same bytes"
	);

	clear_test_env("HELMLY_TEST_TLS_KEY_DER_FILE");
	std::fs::remove_file(&path).ok();
}

// ---- 5. Public entry: env-set tries to seed-on-load (fails in tests,
//         exercises the env-fallback branch) ----

/// Control: when the keyring file is absent and `DASHBOARD_VERIFY_KEY`
/// is set, `load_dashboard_keyring` enters the env-fallback branch
/// and tries to write to `/etc/glyndor/...`. As a non-root test user
/// that write fails — but the branch is exercised either way.
/// Removing the env-fallback branch (i.e. always returning `Ok(empty)`
/// on file-absent) would skip the seed attempt and this test would
/// see `Ok(empty)`, panicking.
#[cfg(unix)] // seed-on-load uses Unix mode 0o600; skip on non-Unix.
#[test]
fn env_set_in_public_loader_attempts_seed_with_msg() {
	let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
	clear_dashboard_env();

	let key = [0xAAu8; 32];
	std::env::set_var("DASHBOARD_VERIFY_KEY", b64(&key));
	let result = load_dashboard_keyring();
	let msg = match &result {
		Err(e) => format!("{e:#}"),
		Ok(ring) => panic!(
			"seed-on-load must Err against non-root test env; got Ok with len={}",
			ring.len()
		),
	};
	assert!(
		msg.contains("seed") || msg.contains("permission") || msg.contains("create"),
		"err must come from the seed-write step (seed/open/rename/create); got: {msg}"
	);

	clear_dashboard_env();
}
