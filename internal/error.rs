use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("lockdown active")]
    Lockdown,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AgentError>;

impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AgentError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AgentError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AgentError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AgentError::Lockdown => (StatusCode::SERVICE_UNAVAILABLE, "lockdown"),
            AgentError::Internal(e) => {
                error!("internal: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    //! Tests for `AgentError` — `Display`, `IntoResponse`, and
    //! `From<anyhow::Error>`. These three surfaces are part of the same
    //! contract:
    //!
    //! - `Display` is what `sanitize_error` (audit log) and `tracing::error!`
    //!   use, so the messages reach the dashboard wire and operator logs.
    //! - `IntoResponse` is what HTTP clients see.
    //! - `From<anyhow::Error>` is the conversion every handler uses to lift a
    //!   domain error into a typed `AgentError::Internal(_)`.
    //!
    //! The wire codes are pinned by exact-string assertion: a regression
    //! that swapped `"forbidden"` for `"permission denied"`, or that
    //! surfaced the raw `anyhow` message (which may carry secrets from
    //! `cmd.payload` / file paths / DB error strings) would go red
    //! immediately.

    use super::AgentError;
    use axum::{
        body::to_bytes,
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use serde_json::{json, Value};

    /// Collect the response body into a JSON value.
    /// `usize::MAX` because the JSON payloads here are tiny — well under any
    /// sane body limit; the helper exists to keep the assertions readable.
    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body readable");
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    // =====================================================================
    // Display — exact strings, no fragments.
    // =====================================================================

    #[test]
    fn display_unauthorized_is_unauthorized() {
        assert_eq!(AgentError::Unauthorized.to_string(), "unauthorized");
    }

    #[test]
    fn display_forbidden_includes_reason() {
        assert_eq!(AgentError::Forbidden("foo").to_string(), "forbidden: foo",);
    }

    #[test]
    fn display_bad_request_includes_reason() {
        assert_eq!(
            AgentError::BadRequest("bar").to_string(),
            "bad request: bar",
        );
    }

    #[test]
    fn display_lockdown_is_lockdown_active() {
        assert_eq!(AgentError::Lockdown.to_string(), "lockdown active");
    }

    /// `Internal` sanitises — the structured `anyhow::Error` (which may
    /// carry file paths, secrets from `cmd.payload`, DB error strings,
    /// etc.) MUST NOT reach the dashboard wire or audit log. Asserts
    /// both the redacted literal AND that the inner message is absent,
    /// so a mutation that surfaced the chain via `#[error("{0}")]`
    /// trips both the equality and the negative assertion.
    #[test]
    fn display_internal_redacts_chain() {
        let e = AgentError::Internal(anyhow::anyhow!("super-secret-payload"));
        let s = e.to_string();
        assert_eq!(s, "internal error");
        assert!(
            !s.contains("super-secret-payload"),
            "internal error must not leak the anyhow chain; got {s:?}",
        );
    }

    // =====================================================================
    // IntoResponse — status code + JSON body mapping.
    //
    // Each test asserts both the HTTP status AND the exact wire body. A
    // mutation that swapped the body code (e.g. "forbidden" → "denied")
    // OR the status (e.g. 403 → 400) goes red on at least one of the
    // two assertions.
    // =====================================================================

    #[tokio::test]
    async fn into_response_unauthorized_is_401_with_code() {
        let r = AgentError::Unauthorized.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(r).await, json!({ "error": "unauthorized" }),);
    }

    #[tokio::test]
    async fn into_response_forbidden_is_403_with_code() {
        let r = AgentError::Forbidden("nope").into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(r).await, json!({ "error": "forbidden" }));
    }

    #[tokio::test]
    async fn into_response_bad_request_is_400_with_code() {
        let r = AgentError::BadRequest("missing x").into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(r).await, json!({ "error": "bad_request" }));
    }

    #[tokio::test]
    async fn into_response_lockdown_is_503_with_code() {
        let r = AgentError::Lockdown.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_json(r).await, json!({ "error": "lockdown" }));
    }

    /// `Internal` returns 500 and emits `{"error":"internal_error"}` —
    /// never the underlying anyhow chain. Asserts the JSON shape
    /// directly so a mutation that replaced `Json(json!({...}))` with
    /// `Json(json!({ "error": e.to_string() }))` would leak secrets
    /// and the test would catch it via the exact-code assertion.
    #[tokio::test]
    async fn into_response_internal_is_500_with_redacted_code() {
        let r =
            AgentError::Internal(anyhow::anyhow!("contains secret: /etc/passwd")).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(r).await;
        assert_eq!(
            body,
            json!({ "error": "internal_error" }),
            "internal wire body must be exactly {{error: internal_error}} — \
             no chain, no anyhow message, no exception name",
        );
    }

    // =====================================================================
    // From<anyhow::Error>.
    //
    // Every handler uses `?` on `anyhow::Error` (DB / fs / crypto); the
    // `From` impl is what lets that compile against the agent's
    // `Result<T> = std::result::Result<T, AgentError>` alias.
    // =====================================================================

    /// `AgentError::from(anyhow)` produces `Internal(_)`. The variant
    /// must match — `From<anyhow>` does NOT collapse to `Internal`
    /// for any of the other variants.
    #[test]
    fn from_anyhow_produces_internal_variant() {
        let original = anyhow::anyhow!("underlying cause");
        let converted: AgentError = original.into();
        assert!(
            matches!(converted, AgentError::Internal(_)),
            "AgentError::from(anyhow) must produce Internal(_); got {converted:?}",
        );
    }

    /// The inner message is preserved for `tracing::error!` (server-side
    /// log) but MUST NOT reach `Display` (which the audit log and HTTP
    /// body use). This is the sanitisation contract — without it,
    /// secrets from the `anyhow!` cause would leak through `to_string()`.
    /// Pairs with `display_internal_redacts_chain` above: both must
    /// fail together if `#[error("internal error")]` is replaced by
    /// `#[error("{0}")]`.
    #[test]
    fn from_anyhow_does_not_leak_inner_message_via_display() {
        let converted: AgentError = anyhow::anyhow!("secret-from-anyhow").into();
        let s = converted.to_string();
        assert!(
            !s.contains("secret-from-anyhow"),
            "from(anyhow) must not surface inner message via Display; got {s:?}",
        );
    }
}
