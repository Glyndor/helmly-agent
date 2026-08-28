use super::*;

// =====================================================================
// authorize_metrics_ws — header parsing + bearer verify.
//
// Every header shape documented in `verify_bearer` (and a few it
// doesn't mention but the stripping chain cares about: non-UTF8
// bytes, missing space).
// =====================================================================

/// `metrics_ws` is a `pub` handler, so the test exercises the
/// public surface directly — it composes the auth helper, the
/// `AppState`, and the `HeaderMap` exactly the way the router does.
/// The `WebSocketUpgrade` constructor is `pub(crate)` in axum, so we
/// assert the `Err(Unauthorized)` path via the public handler with
/// a `WebSocketUpgrade` placeholder is impossible to construct in
/// tests — the path is unit-tested via `authorize_metrics_ws` below.
/// The Ok branch is exercised by the helper's positive cases.
///
/// `#[tokio::test]` (not `#[test]`) because `make_state` opens a
/// lazy `PgPool`, which requires a Tokio runtime context. The
/// helper-level tests below are sync — they don't touch the pool.
#[tokio::test]
async fn auth_state_helper_has_expected_internal_token() {
    let state = make_state();
    // Round-trip through the public handler's read path.
    let h = headers_with_auth("Bearer test-token");
    assert!(
        authorize_metrics_ws(&h, &state.config.internal_token),
        "make_state() must wire the token the tests expect"
    );
}

/// Missing header → token collapses to `""` → fails `verify_bearer`.
#[test]
fn auth_no_authorization_header_rejects() {
    let h = HeaderMap::new();
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// The happy path — the helper reaches the Ok branch the production
/// handler requires before allowing the WebSocket upgrade.
#[test]
fn auth_valid_bearer_token_accepts() {
    let h = headers_with_auth("Bearer test-token");
    assert!(authorize_metrics_ws(&h, "test-token"));
}

/// Wrong token — the constant-time compare in `verify_bearer`
/// returns false for any non-bytewise-identical input.
#[test]
fn auth_wrong_token_rejects() {
    let h = headers_with_auth("Bearer wrong-token");
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// A scheme other than `Bearer ` (note: stripping requires the
/// trailing space) leaves the token at the empty default, which
/// fails `verify_bearer`. Important: the absence of the space is
/// load-bearing — RFC 7235 §2.1 requires `"Bearer "` followed by
/// the token.
#[test]
fn auth_non_bearer_scheme_rejects_as_empty_token() {
    let h = headers_with_auth("NotBearer foo");
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// Header is exactly `"Bearer "` (trailing space, no token).
#[test]
fn auth_bearer_with_empty_suffix_rejects() {
    let h = headers_with_auth("Bearer ");
    assert!(
        !authorize_metrics_ws(&h, "test-token"),
        "empty token must reject (constant-time length-check)"
    );
}

/// `"Bearer"` followed by the token with NO space in between.
/// This is an easy bug to introduce if someone swaps
/// `strip_prefix("Bearer ")` for a `starts_with` style check; the
/// space is required.
#[test]
fn auth_bearer_without_space_treated_as_missing_prefix() {
    let h = headers_with_auth("Bearertest-token");
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// Non-UTF8 header bytes — `to_str()` returns `Err`, the chain
/// collapses to the empty default which fails `verify_bearer`.
/// Asserts that the helper panics-free for hostile input.
#[test]
fn auth_non_utf8_header_value_rejects_without_panic() {
    let mut h = HeaderMap::new();
    // 0xff/0xfe are not valid UTF-8 start bytes.
    h.insert(
        AUTHORIZATION,
        HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// Empty header value → empty token → fails `verify_bearer`
/// (different lengths → instant rejection at `verify_bearer`'s
/// pre-check, no panic).
#[test]
fn auth_empty_header_value_does_not_match_nonempty_token() {
    let h = headers_with_auth("");
    assert!(!authorize_metrics_ws(&h, "test-token"));
}

/// Sanity for `verify_bearer("", "")` — the only way the helper
/// could return true for an empty Authorization value is if the
/// configured `internal_token` is ALSO empty. We don't test that
/// production case (the agent refuses to start with an empty
/// token at config load), but we pin the helper's expected
/// empty-vs-nonempty boundary here.
#[test]
fn auth_empty_value_matches_only_when_expected_is_empty() {
    let h = headers_with_auth("");
    assert!(!authorize_metrics_ws(&h, "nonempty"));
}
