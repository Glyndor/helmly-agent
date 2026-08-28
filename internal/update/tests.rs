use super::{check_install_method_marker_at, verify_signature_with};
use std::io::Write;

fn tmp_marker(content: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "helmly-agent-install-method-{}-{}.marker",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let mut f = std::fs::File::create(&path).expect("create tmp marker");
    f.write_all(content.as_bytes()).expect("write tmp marker");
    path
}

/// C3: missing marker is treated as "script" — preserves today's
/// behaviour of every pre-marker install.
#[test]
fn install_method_marker_absent_is_ok() {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "helmly-agent-install-method-{}-{}-absent.marker",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    assert!(check_install_method_marker_at(p.to_str().unwrap()).is_ok());
}

/// C3: marker = "script" allows self-update (today's path).
#[test]
fn install_method_marker_script_allows() {
    let p = tmp_marker("script\n");
    assert!(check_install_method_marker_at(p.to_str().unwrap()).is_ok());
}

/// C3: marker = "dpkg" refuses self-update. Reverting the
/// `bail!` arm back to `Ok(())` makes this test go red.
#[test]
fn install_method_marker_dpkg_refuses() {
    let p = tmp_marker("dpkg\n");
    let r = check_install_method_marker_at(p.to_str().unwrap());
    let err = match r {
        Ok(()) => panic!("dpkg marker must refuse self-update; got Ok"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("managed by a package manager"),
        "refusal message must name the cause; got: {msg}"
    );
}

/// C3: an unrecognised value fails closed (refuses self-update).
/// Defends against typos or attacker edits to the marker.
#[test]
fn install_method_marker_invalid_value_refuses() {
    let p = tmp_marker("docker\n");
    let r = check_install_method_marker_at(p.to_str().unwrap());
    let err = r.expect_err("invalid marker must fail closed; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unrecognised value"),
        "invalid-value message must name the cause; got: {msg}"
    );
}

/// C3: a file the agent cannot read also fails closed.
/// Use the absolute path to a directory — opening a directory as a
/// file is an I/O error kind that is NOT NotFound.
#[cfg(unix)]
#[test]
fn install_method_marker_unreadable_refuses() {
    let r = check_install_method_marker_at("/proc");
    let err = r.expect_err("unreadable marker must fail closed; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unreadable"),
        "unreadable-message must name the cause; got: {msg}"
    );
}

// ---- C2: release-keyring rotation tests (added during rebase of
// C2's fix/c2-keyring branch onto the C3-merged develop) ----

/// C2: regression — any non-zeroed slot in the keyring verifies its
/// own signature. Today's behaviour, one active key.
#[test]
fn release_verify_accepts_any_non_zeroed_slot() {
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let pub_key = signing.verifying_key().to_bytes();
    let binary = b"helmly-agent binary";
    let sig = signing.sign(binary);
    let keyring = [[0u8; 32], pub_key];
    assert!(
        verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
        "any non-zeroed slot that matches must verify"
    );
}

/// C2: regression — two-phase rotation. The OLD key continues to
/// verify on agents that already hold `[OLD, NEW]` (slot 1 just added
/// for the new key).
#[test]
fn release_verify_old_key_works_after_new_key_added() {
    use ed25519_dalek::Signer;
    let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let binary = b"transition release signed by old";
    let sig = old.sign(binary);
    let keyring = [
        old.verifying_key().to_bytes(),
        new.verifying_key().to_bytes(),
    ];
    assert!(
        verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
        "transition release signed by OLD must verify against the [OLD,NEW] ring"
    );
}

/// C2: regression — the NEW key verifies against the [OLD,NEW] ring.
/// (The cut-over to `[NEW, ZERO]` ships in the *next* release; this
/// test exercises the mid-rotation state.)
#[test]
fn release_verify_new_key_works_in_two_slot_ring() {
    use ed25519_dalek::Signer;
    let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let binary = b"transition release signed by new";
    let sig = new.sign(binary);
    let keyring = [
        old.verifying_key().to_bytes(),
        new.verifying_key().to_bytes(),
    ];
    assert!(
        verify_signature_with(binary, &sig.to_bytes(), &keyring).is_ok(),
        "transition release signed by NEW must verify against the [OLD,NEW] ring"
    );
}

/// C2: regression — cut-over. After Phase 2, slot 0 is the new
/// key and slot 1 is zeroed. A release signed by the OLD key no
/// longer verifies (operator has retired OLD).
#[test]
fn release_verify_old_key_rejected_after_cutover() {
    use ed25519_dalek::Signer;
    let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let binary = b"forged release signed by retired OLD";
    let sig = old.sign(binary);
    let keyring = [new.verifying_key().to_bytes(), [0u8; 32]];
    let r = verify_signature_with(binary, &sig.to_bytes(), &keyring);
    let err = r.expect_err("OLD key after cut-over must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("did not verify against slot 0") || msg.contains("no non-zeroed slot"),
        "rejection must name the cause; got: {msg}"
    );
}

/// C2: regression — a forged signature (made by a key that's never
/// been in the ring) is rejected, even if the ring has both slots
/// populated. Fail closed.
#[test]
fn release_verify_rejects_forged_signature() {
    use ed25519_dalek::Signer;
    let old = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let new = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
    let binary = b"binary";
    let sig = attacker.sign(binary);
    let keyring = [
        old.verifying_key().to_bytes(),
        new.verifying_key().to_bytes(),
    ];
    assert!(
        verify_signature_with(binary, &sig.to_bytes(), &keyring).is_err(),
        "forged signature must fail closed"
    );
}

/// C2: regression — an empty keyring (both slots zeroed) fails
/// closed. Removing the iteration entirely (i.e. always returning
/// Ok) makes this go red.
#[test]
fn release_verify_rejects_when_keyring_all_zeroed() {
    let keyring = [[0u8; 32], [0u8; 32]];
    let r = verify_signature_with(b"binary", &[0u8; 64], &keyring);
    let err = r.expect_err("zeroed keyring must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("any non-zeroed slot"),
        "rejection must name the cause; got: {msg}"
    );
}

// ---- download_bytes happy path -----------------------------------------
//
// The download loop is extracted as `download_bytes_with(client, url,
// max_bytes)` so tests can drive it with a small cap (the production
// 200 MiB would be impractical in a unit test). The HTTP path, status
// check, and both size caps are unchanged — only the constant became a
// parameter. Tests run against a real in-process axum server bound to
// 127.0.0.1 on an ephemeral port, so the SSRF safe-client wrapper is
// bypassed and the actual HTTP behaviour is exercised end-to-end.

use super::download_bytes_with;

/// Spin up a one-route axum server on 127.0.0.1:<random> that
/// returns `status` and `body` for every request. Returns the URL
/// the test should hand to `download_bytes_with`.
async fn spawn_http_server(status: u16, body: Vec<u8>) -> String {
    use axum::{body::Body, http::StatusCode, response::Response, routing::get, Router};
    use std::sync::Arc;
    let body = Arc::new(body);
    let status = StatusCode::from_u16(status).unwrap();
    let app = Router::new().route(
        "/",
        get(move || {
            let body = Arc::clone(&body);
            let status = status;
            async move {
                let mut resp = Response::new(Body::from((*body).clone()));
                *resp.status_mut() = status;
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{}/", addr.port())
}

/// Server returns a streaming body of `chunk_count` chunks of
/// `chunk_size` bytes each, with **no** `Content-Length` header
/// (HTTP/1.1 chunked transfer encoding). Used to exercise the
/// post-read size cap: with no `Content-Length`, the pre-read
/// check is skipped, so the post-read `bytes.len() > max_bytes`
/// arm is what must reject an over-cap response.
async fn spawn_http_server_streaming(chunk_count: usize, chunk_size: usize) -> String {
    use axum::{body::Body, routing::get, Router};
    use futures_util::stream;
    let app = Router::new().route(
        "/",
        get(move || async move {
            let stream = stream::iter((0..chunk_count).map(move |_| {
                Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; chunk_size]))
            }));
            Body::from_stream(stream)
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{}/", addr.port())
}

/// Happy path: 2xx with body under the cap returns the bytes.
/// Mutating `download_bytes_with` to always return `Ok(vec![])` makes
/// this go red.
#[tokio::test]
async fn download_bytes_with_2xx_returns_body() {
    let body = b"helmly-agent binary blob".to_vec();
    let url = spawn_http_server(200, body.clone()).await;
    let client = reqwest::Client::new();
    let bytes = download_bytes_with(&client, &url, 1024)
        .await
        .expect("2xx under cap must Ok");
    assert_eq!(bytes, body, "must return the full body");
}

/// Pre-read Content-Length cap: axum auto-sets Content-Length to the
/// body length, so a 100-byte body with cap=50 is rejected by the
/// `if len > max_bytes` arm before the body is read. Removing that
/// arm makes this go red.
#[tokio::test]
async fn download_bytes_with_oversize_content_length_errors() {
    let body = vec![b'x'; 100];
    let url = spawn_http_server(200, body).await;
    let client = reqwest::Client::new();
    let r = download_bytes_with(&client, &url, 50).await;
    let err = r.expect_err("body > cap must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Content-Length 100 exceeds 50 safety limit"),
        "pre-read cap must name the cause; got: {msg}"
    );
}

/// Post-read body-length cap: streaming response with no
/// Content-Length header. The pre-read check is skipped (no header),
/// so the `if bytes.len() > max_bytes` arm is what must fire.
/// Removing that arm makes this go red.
#[tokio::test]
async fn download_bytes_with_oversize_streaming_body_errors() {
    // 100 chunks × 1 byte = 100 bytes streamed, no Content-Length.
    let url = spawn_http_server_streaming(100, 1).await;
    let client = reqwest::Client::new();
    let r = download_bytes_with(&client, &url, 50).await;
    let err = r.expect_err("streaming body > cap must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("exceeded 50 safety limit"),
        "post-read cap must name the cause; got: {msg}"
    );
}

/// Status check: 4xx must be rejected. Removing the
/// `!resp.status().is_success()` arm makes this go red.
#[tokio::test]
async fn download_bytes_with_4xx_errors() {
    let url = spawn_http_server(404, Vec::new()).await;
    let client = reqwest::Client::new();
    let r = download_bytes_with(&client, &url, 1024).await;
    let err = r.expect_err("4xx must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("404"),
        "rejection must surface status; got: {msg}"
    );
}

/// Status check: 5xx must be rejected. Same mutation as above.
#[tokio::test]
async fn download_bytes_with_5xx_errors() {
    let url = spawn_http_server(503, Vec::new()).await;
    let client = reqwest::Client::new();
    let r = download_bytes_with(&client, &url, 1024).await;
    let err = r.expect_err("5xx must fail; got Ok");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("503"),
        "rejection must surface status; got: {msg}"
    );
}

/// Network error: a closed local port must produce an error (the
/// status / size checks never run). Binding to 0 and immediately
/// dropping the listener gives ECONNREFUSED without depending on
/// any external service.
#[tokio::test]
async fn download_bytes_with_connection_refused_errors() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://127.0.0.1:{}/", addr.port());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let r = download_bytes_with(&client, &url, 1024).await;
    assert!(r.is_err(), "connection refused must fail; got Ok");
}

// ---- spawn_startup_health_guard happy path -----------------------------
//
// The health-check loop is extracted as
// `run_startup_health_check(check, max_attempts, interval, binary, crit)`
// so tests can substitute a stub health check and a 1 ms interval
// (production uses 15 × 2 s — too slow for unit tests). The loop body,
// restore path, and CRITICAL-file write are unchanged; only the call
// sites became parameters. Production behaviour is preserved:
// `spawn_startup_health_guard` still calls this helper and translates
// `Err(_)` into `std::process::exit(1)`.

use super::run_startup_health_check;

fn unique_tmp(label: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "helmly-agent-test-{}-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        label,
    ));
    p
}

/// Happy path: health returns true on the first attempt — the
/// leftover CRITICAL file must be removed and the call must Ok.
/// Removing the `remove_file(critical_file)` line makes this go red.
#[tokio::test]
async fn health_check_passes_and_clears_critical_when_healthy() {
    let binary = unique_tmp("healthy-bin");
    let crit = unique_tmp("healthy-crit");
    std::fs::write(&crit, "leftover from a previous failed startup").unwrap();
    assert!(crit.exists(), "pre-condition: CRITICAL exists");

    let r = run_startup_health_check(
        || async { true },
        1,
        std::time::Duration::from_millis(1),
        &binary.to_string_lossy(),
        &crit.to_string_lossy(),
    )
    .await;
    assert!(r.is_ok(), "healthy must Ok; got: {r:?}");
    assert!(
        !crit.exists(),
        "CRITICAL file must be removed on healthy startup"
    );
}

/// Failure path with restorable .prev: after the loop exhausts, the
/// helper copies `.prev` over the binary and writes CRITICAL with
/// `restored .prev`. The binary contents must now match `.prev`.
/// Removing the `std::fs::copy + rename` block makes the CRITICAL
/// file say `MANUAL RECOVERY` instead — assertion catches that.
#[tokio::test]
async fn health_check_writes_critical_with_prev_restored() {
    let binary = unique_tmp("restore-bin");
    let prev = std::path::PathBuf::from(format!("{}.prev", binary.display()));
    let crit = unique_tmp("restore-crit");
    std::fs::write(&binary, "new binary contents").unwrap();
    std::fs::write(&prev, "previous binary contents").unwrap();

    let r = run_startup_health_check(
        || async { false },
        1,
        std::time::Duration::from_millis(1),
        &binary.to_string_lossy(),
        &crit.to_string_lossy(),
    )
    .await;
    let reason = r.expect_err("unhealthy must Err");
    assert!(
        reason.contains("restored .prev"),
        "reason must name restore outcome; got: {reason}"
    );

    let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
    assert!(
        crit_content.contains("restored .prev"),
        "CRITICAL file must name the cause; got: {crit_content}"
    );
    assert!(
        crit_content.contains("component=helmly-agent"),
        "CRITICAL must identify the component; got: {crit_content}"
    );

    let binary_contents = std::fs::read_to_string(&binary).unwrap();
    assert_eq!(
        binary_contents, "previous binary contents",
        "restore must overwrite the binary with .prev contents"
    );
}

/// Failure path with .prev missing: CRITICAL must say
/// `MANUAL RECOVERY`. Removing the `else { false }` branch in the
/// restore logic, or the unconditional CRITICAL write after the loop,
/// makes this go red.
#[tokio::test]
async fn health_check_writes_critical_manual_recovery_when_prev_missing() {
    let binary = unique_tmp("noprev-bin");
    let crit = unique_tmp("noprev-crit");
    std::fs::write(&binary, "new binary").unwrap();
    // Intentionally no .prev written.

    let r = run_startup_health_check(
        || async { false },
        1,
        std::time::Duration::from_millis(1),
        &binary.to_string_lossy(),
        &crit.to_string_lossy(),
    )
    .await;
    let reason = r.expect_err("unhealthy + no .prev must Err");
    assert!(
        reason.contains("MANUAL RECOVERY"),
        "reason must name manual recovery; got: {reason}"
    );

    let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
    assert!(
        crit_content.contains("MANUAL RECOVERY"),
        "CRITICAL must name manual recovery; got: {crit_content}"
    );
    // The new binary must NOT have been overwritten — nothing to
    // restore from.
    let binary_contents = std::fs::read_to_string(&binary).unwrap();
    assert_eq!(
        binary_contents, "new binary",
        "binary must be untouched when .prev is missing"
    );
}

/// Failure path with .prev unreadable (0o000 on Unix): the copy()
/// fails, restore_ok is false, CRITICAL must say `MANUAL RECOVERY`.
/// Restoring read permissions after the test so the temp directory
/// doesn't leave an unreadable file behind for the OS to clean up.
#[cfg(unix)]
#[tokio::test]
async fn health_check_writes_critical_manual_recovery_when_prev_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let binary = unique_tmp("unreadable-bin");
    let prev = std::path::PathBuf::from(format!("{}.prev", binary.display()));
    let crit = unique_tmp("unreadable-crit");
    std::fs::write(&binary, "new binary").unwrap();
    std::fs::write(&prev, "previous binary").unwrap();
    std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o000)).unwrap();

    let r = run_startup_health_check(
        || async { false },
        1,
        std::time::Duration::from_millis(1),
        &binary.to_string_lossy(),
        &crit.to_string_lossy(),
    )
    .await;

    // Restore perms before any assertion that could fail — otherwise
    // a panic here would leave 0o000 on a temp file (annoying to
    // debug, though not a security issue since the file is empty).
    std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o600)).unwrap();

    let reason = r.expect_err("unhealthy + unreadable .prev must Err");
    assert!(
        reason.contains("MANUAL RECOVERY"),
        "reason must name manual recovery; got: {reason}"
    );

    let crit_content = std::fs::read_to_string(&crit).expect("CRITICAL written");
    assert!(
        crit_content.contains("MANUAL RECOVERY"),
        "CRITICAL must name manual recovery; got: {crit_content}"
    );
}
