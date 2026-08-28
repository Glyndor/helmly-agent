//! The dashboard-facing listener: building the mTLS acceptor and serving over it.
//!
//! Split out of `main.rs` so the entry point stays readable and so the
//! fail-closed TLS logic sits next to the tests that pin it.

use anyhow::Context;
use axum::Router;

/// Build the mTLS acceptor for the dashboard-facing listener.
///
/// Returns:
/// - `Ok(Some(_))` — certs were configured and the acceptor built cleanly.
/// - `Ok(None)` — certs were deliberately opted out via `INSECURE_PLAIN_HTTP=1`
///   (development on a loopback address only; a loud warning is logged on use).
/// - `Err(_)` — TLS is required by the deployment but could not be set up: missing
///   certs/CA/key, malformed DER, or rustls build failure. **Fail closed.** The
///   caller exits the process on `Err`; the listener never opens a plaintext
///   socket by accident.
///
/// `build_tls_acceptor` is `pub(crate)` so tests can mutate `allow_plain_http`
/// without env-var races.
pub(crate) fn build_tls_acceptor(
	config: &crate::config::Config,
	allow_plain_http: bool,
) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
	use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
	use std::sync::Arc as StdArc;

	let cert_der = config.tls_cert_der.as_ref();
	let key_der = config.tls_key_der.as_ref();
	let ca_cert_der = config.tls_ca_cert_der.as_ref();

	// All three are required for mTLS. If any is absent, the listener cannot
	// do its job; refuse unless the operator opted out explicitly.
	let (cert_der, key_der, ca_cert_der) = match (cert_der, key_der, ca_cert_der) {
		(Some(c), Some(k), Some(ca)) => (c, k, ca),
		(None, None, None) if allow_plain_http => {
			tracing::warn!(
				"INSECURE_PLAIN_HTTP=1: serving plain HTTP. This is for local development \
                 only — a managed server with this set is unauthenticated on the wire."
			);
			return Ok(None);
		}
		(None, None, None) => {
			anyhow::bail!(
				"TLS required but not configured: TLS_CERT_DER_FILE, TLS_KEY_DER_FILE, \
                 and TLS_CA_CERT_DER_FILE are all unset. Set INSECURE_PLAIN_HTTP=1 to \
                 allow plaintext for local development."
			);
		}
		_ => {
			anyhow::bail!(
				"TLS partially configured: TLS_CERT_DER_FILE, TLS_KEY_DER_FILE, and \
                 TLS_CA_CERT_DER_FILE must all be set together. Got \
                 cert={} key={} ca={}.",
				cert_der.is_some(),
				key_der.is_some(),
				ca_cert_der.is_some(),
			);
		}
	};

	// Clone into owned data so the resulting ServerConfig is 'static.
	let cert_chain = vec![CertificateDer::from(cert_der.clone())];
	let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

	// Build client cert verifier trusting only the dashboard CA.
	let mut root_store = rustls::RootCertStore::empty();
	root_store
		.add(CertificateDer::from(ca_cert_der.clone()))
		.map_err(|e| anyhow::anyhow!("TLS CA cert add failed: {e}"))?;

	let client_verifier = rustls::server::WebPkiClientVerifier::builder(StdArc::new(root_store))
		.build()
		.map_err(|e| anyhow::anyhow!("TLS client verifier build failed: {e}"))?;

	let server_config = rustls::ServerConfig::builder()
		.with_client_cert_verifier(client_verifier)
		.with_single_cert(cert_chain, key)
		.map_err(|e| anyhow::anyhow!("TLS ServerConfig build failed: {e}"))?;

	Ok(Some(tokio_rustls::TlsAcceptor::from(StdArc::new(
		server_config,
	))))
}

pub(crate) async fn serve_tls(
	listener: tokio::net::TcpListener,
	app: Router,
	acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<()> {
	use hyper::server::conn::http1;
	use hyper_util::rt::TokioIo;

	loop {
		let (tcp_stream, _remote_addr) = listener.accept().await.context("accept TCP")?;
		let acceptor = acceptor.clone();
		let app = app.clone();

		tokio::spawn(async move {
			let tls_stream = match acceptor.accept(tcp_stream).await {
				Ok(s) => s,
				Err(e) => {
					tracing::debug!("TLS handshake failed: {e}");
					return;
				}
			};

			let io = TokioIo::new(tls_stream);

			// Bridge hyper::body::Incoming → axum::body::Body so the router can handle it.
			let svc =
				hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
					let app = app.clone();
					async move {
						use tower::ServiceExt;
						let req = req.map(axum::body::Body::new);
						app.oneshot(req).await
					}
				});

			if let Err(e) = http1::Builder::new()
				.serve_connection(io, svc)
				.with_upgrades()
				.await
			{
				tracing::debug!("HTTP connection error: {e}");
			}
		});
	}
}

#[cfg(test)]
mod tests;
