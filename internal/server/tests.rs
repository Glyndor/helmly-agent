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
