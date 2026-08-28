use super::*;
use crate::config::Config;
use uuid::Uuid;
use zeroize::Zeroizing;

fn empty_tls_config() -> Config {
	Config {
		database_url: String::new(),
		agent_id: Uuid::now_v7(),
		version: "test".into(),
		dashboard_verify_keys: Zeroizing::new(Vec::new()),
		internal_token: Zeroizing::new(String::new()),
		listen_addr: "127.0.0.1:0".into(),
		dashboard_url: None,
		sync_token: None,
		tls_cert_der: None,
		tls_key_der: None,
		tls_ca_cert_der: None,
		dashboard_port: None,
	}
}

fn partial_tls_config(cert: bool, key: bool, ca: bool) -> Config {
	let mut c = empty_tls_config();
	c.tls_cert_der = cert.then(|| vec![0xAA; 64]);
	c.tls_key_der = key.then(|| Zeroizing::new(vec![0xBB; 32]));
	c.tls_ca_cert_der = ca.then(|| vec![0xCC; 64]);
	c
}

/// C1: missing certs without opt-in must fail closed.
/// This is the regression test — reverting `build_tls_acceptor` to
/// `return Ok(None)` (the old fall-back-to-plain-HTTP behaviour) makes this
/// test go red.
#[test]
fn tls_missing_certs_without_opt_in_returns_err() {
	let r = build_tls_acceptor(&empty_tls_config(), false);
	let err = match r {
		Err(e) => e,
		Ok(_) => panic!("TLS-required-but-not-configured must fail closed; got Ok(_)"),
	};
	let msg = format!("{err:#}");
	assert!(
		msg.contains("TLS required but not configured"),
		"error message must name the cause; got: {msg}"
	);
}

/// C1: missing certs WITH explicit dev opt-in must serve plain HTTP,
/// not panic and not silently fail-closed.
#[test]
fn tls_missing_certs_with_opt_in_returns_ok_none() {
	match build_tls_acceptor(&empty_tls_config(), true) {
		Ok(None) => {} // expected
		Ok(Some(_)) => panic!("opt-in yields None (plain HTTP), not Some(acceptor)"),
		Err(e) => panic!("INSECURE_PLAIN_HTTP=1 must permit plaintext; got Err({e})"),
	}
}

/// C1: a *partial* set (e.g. cert + CA but no key) is a misconfiguration —
/// refusing to silently serve plaintext is the only safe move.
#[test]
fn tls_partial_config_returns_err() {
	let r = build_tls_acceptor(&partial_tls_config(true, false, true), false);
	let err = match r {
		Err(e) => e,
		Ok(_) => panic!("partial TLS config must fail closed; got Ok(_)"),
	};
	let msg = format!("{err:#}");
	assert!(
		msg.contains("partially configured"),
		"error message must name the cause; got: {msg}"
	);
}

/// C1: malformed DER bytes (cert set, but garbage) must fail closed too,
/// not silently fall back to plaintext.
#[test]
fn tls_malformed_der_returns_err() {
	let r = build_tls_acceptor(&partial_tls_config(true, true, true), false);
	assert!(r.is_err(), "malformed DER must fail closed");
}

// ---------------------------------------------------------------------------
// Request body bound (#168).
//
// Everything the dashboard sends arrives as Json<SignedCommand>, and the
// threat model treats it as untrusted input with bounded sizes. Until this
// layer existed the only bound was axum's implicit default, which is a
// framework choice rather than one made here.
//
// The signature does not answer this: a correctly signed body of any size is
// still read in full before the verifier can decide anything about it, which
// is why the cap is a layer and not a check inside a handler.
// ---------------------------------------------------------------------------

/// The constant is what the router is built with. Asserting the number alone
/// would pin a value and not a behaviour, so the two tests below drive a real
/// router through the layer instead; this one only pins the magnitude, so a
/// fat-fingered 256 * 1024 * 1024 is caught by something.
#[test]
fn the_body_limit_is_the_documented_size() {
	assert_eq!(crate::MAX_REQUEST_BODY_BYTES, 256 * 1024);
}

/// Drives the router `main` actually serves, not a synthetic one.
///
/// The first version of these tests built their own `Router` with the same
/// layer, and deleting `.layer(...)` from `build_router` left them green.
/// They were asserting that axum's DefaultBodyLimit works, which it does and
/// which is not this repository's question.
async fn status_for_body_of(len: usize) -> axum::http::StatusCode {
	use axum::body::Body;
	use tower::ServiceExt;
	let state = crate::state::AppState::for_test();
	let app = crate::build_router(state);
	app.oneshot(
		axum::http::Request::post("/cmd")
			.header("content-type", "application/json")
			.body(Body::from(vec![b'x'; len]))
			.expect("request"),
	)
	.await
	.expect("response")
	.status()
}

#[tokio::test]
async fn a_body_one_byte_over_the_limit_is_refused_by_the_real_router() {
	assert_eq!(
		status_for_body_of(crate::MAX_REQUEST_BODY_BYTES + 1).await,
		axum::http::StatusCode::PAYLOAD_TOO_LARGE,
		"one byte over must be refused, not truncated and not accepted"
	);
}

#[tokio::test]
async fn a_body_at_the_limit_reaches_the_handler() {
	// Not 200: the body is `xxxx...`, which is not a SignedCommand, so the
	// Json extractor rejects it. That is the point. Anything other than
	// PAYLOAD_TOO_LARGE means the limit let it through to be parsed, which
	// is what "at the limit is accepted" has to mean here.
	assert_ne!(
		status_for_body_of(crate::MAX_REQUEST_BODY_BYTES).await,
		axum::http::StatusCode::PAYLOAD_TOO_LARGE,
		"a body exactly at the limit must reach the extractor"
	);
}
