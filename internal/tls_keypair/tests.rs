use super::*;
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("helmly-tls-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

#[test]
fn generate_requires_at_least_one_san() {
    // `expect_err` is not available here on purpose: GeneratedKeypair holds
    // a private key and deliberately does not implement Debug, so it cannot
    // be formatted into a panic message or a log line.
    match generate(&[]) {
        Ok(_) => panic!("no SAN must be refused"),
        Err(e) => assert!(
            e.to_string().contains("subject alternative name"),
            "the error must name the missing input, got: {e}"
        ),
    }
}

#[test]
fn an_ip_san_is_encoded_as_an_ip_address_not_a_dns_name() {
    // The distinction is the point. A dashboard dialing the agent by
    // address needs an iPAddress SAN; the same string encoded as a
    // dNSName fails the handshake, and the error names the certificate
    // rather than the encoding. rcgen classifies it, so this asserts it
    // classified it the way the WireGuard-address deployment needs.
    let kp = generate(&["10.100.0.2".to_string()]).expect("generate");
    let (_, parsed) =
        x509_parser::parse_x509_certificate(&kp.cert_der).expect("output must be valid DER X.509");
    let sans = parsed
        .subject_alternative_name()
        .expect("SAN extension parses")
        .expect("SAN extension present");
    let names = &sans.value.general_names;
    assert_eq!(names.len(), 1, "one SAN in, one SAN out");
    match &names[0] {
        x509_parser::extensions::GeneralName::IPAddress(bytes) => {
            assert_eq!(*bytes, &[10u8, 100, 0, 2][..], "wrong address encoded");
        }
        other => panic!("expected an IPAddress SAN, got {other:?}"),
    }
}

#[test]
fn a_hostname_san_is_encoded_as_a_dns_name() {
    let kp = generate(&["agent.internal".to_string()]).expect("generate");
    let (_, parsed) = x509_parser::parse_x509_certificate(&kp.cert_der).expect("valid DER X.509");
    let sans = parsed
        .subject_alternative_name()
        .expect("SAN parses")
        .expect("SAN present");
    match &sans.value.general_names[0] {
        x509_parser::extensions::GeneralName::DNSName(n) => assert_eq!(*n, "agent.internal"),
        other => panic!("expected a DNSName SAN, got {other:?}"),
    }
}

#[test]
fn key_der_is_a_pkcs8_private_key_matching_the_certificate() {
    // rustls 0.23 refuses to pick a crypto provider on its own. main.rs
    // installs one at startup; a unit test has no main, so it installs one
    // here or every rustls call panics on an error about crate features
    // rather than about the keypair under test.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let kp = generate(&["localhost".to_string()]).expect("generate");
    // rustls is what actually consumes these two at runtime, so parse them
    // the way it does rather than trusting the encoder.
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(kp.key_der.to_vec());
    let chain = vec![rustls::pki_types::CertificateDer::from(kp.cert_der.clone())];
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .expect("rustls must accept the generated pair; a mismatch fails here");
}

#[test]
fn fingerprint_is_sha256_over_the_certificate_der() {
    use sha2::Digest;
    let kp = generate(&["localhost".to_string()]).expect("generate");
    let expect = sha2::Sha256::digest(&kp.cert_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(kp.fingerprint_sha256, expect);
    assert_eq!(kp.fingerprint_sha256.len(), 64, "hex SHA-256 is 64 chars");
    assert!(!kp.fingerprint_sha256.contains(':'));
}

#[test]
fn two_generations_do_not_collide() {
    let a = generate(&["localhost".to_string()]).expect("generate");
    let b = generate(&["localhost".to_string()]).expect("generate");
    assert_ne!(
        a.fingerprint_sha256, b.fingerprint_sha256,
        "each provisioning must produce a distinct identity"
    );
}

#[test]
fn write_secret_creates_the_file_at_0600() {
    let d = tmpdir();
    let p = d.join("key.der");
    write_secret(&p, b"secret bytes").expect("write");
    assert_eq!(std::fs::read(&p).expect("read"), b"secret bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private material must not be readable");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn write_secret_refuses_to_overwrite() {
    let d = tmpdir();
    let p = d.join("key.der");
    write_secret(&p, b"first").expect("first write");
    let err = write_secret(&p, b"second").expect_err("second write must be refused");
    assert!(err.to_string().contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read(&p).expect("read"),
        b"first",
        "the original must survive the refused write"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_certificate_actually_expires_after_cert_validity_days() {
    // The command prints "valid for N days". This asserts the certificate
    // agrees, because a printed number is not a validity period.
    let kp = generate(&["localhost".to_string()]).expect("generate");
    let (_, parsed) = x509_parser::parse_x509_certificate(&kp.cert_der).expect("valid DER");
    let span = parsed.validity().not_after.timestamp() - parsed.validity().not_before.timestamp();
    let expected = CERT_VALIDITY_DAYS * 86_400;
    // A minute of slack: the two bounds are taken from separate reads of
    // the clock, and rcgen encodes to second granularity.
    assert!(
        (span - expected).abs() <= 60,
        "certificate spans {span}s, expected {expected}s (CERT_VALIDITY_DAYS = {CERT_VALIDITY_DAYS})"
    );
    assert!(
        parsed.validity().not_after.timestamp() > parsed.validity().not_before.timestamp(),
        "not_after must follow not_before"
    );
}
