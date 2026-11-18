use std::net::IpAddr;
use std::path::Path;

use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

pub const MAX_CA_DAYS: u32 = 7300;
pub const MAX_SERVER_DAYS: u32 = 825;

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Positive, non-zero, full 128-bit DER INTEGER.
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    SerialNumber::from_slice(&bytes)
}

fn entry_exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// Writes a private key first, then its certificate. If the certificate
/// cannot be written and we created a fresh key, the key is removed so no
/// half-pair is left behind.
fn write_pair(
    cert_out: &Path,
    cert_pem: &str,
    key_out: &Path,
    key_pem: &str,
    force: bool,
) -> Result<(), String> {
    aim_fs::write_private_atomic(key_out, key_pem.as_bytes(), force)?;
    if let Err(e) = aim_fs::write_public_atomic(cert_out, cert_pem.as_bytes(), force) {
        if !force {
            let _ = std::fs::remove_file(key_out);
        }
        return Err(e);
    }
    Ok(())
}

pub fn init_ca(
    ca_cert_out: &Path,
    ca_key_out: &Path,
    common_name: &str,
    days: u32,
    force: bool,
) -> Result<(), String> {
    if days == 0 || days > MAX_CA_DAYS {
        return Err(format!("CA validity days must be 1-{MAX_CA_DAYS}"));
    }
    if !force && (entry_exists(ca_cert_out) || entry_exists(ca_key_out)) {
        return Err("CA certificate or key already exists (pass --force to overwrite)".into());
    }
    let mut params = CertificateParams::new(Vec::new()).map_err(|e| e.to_string())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.serial_number = Some(random_serial());
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "AIM Private CA");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(i64::from(days));

    let key = KeyPair::generate().map_err(|e| format!("failed generating CA key: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("failed signing CA cert: {e}"))?;
    let key_pem = Zeroizing::new(key.serialize_pem());
    write_pair(ca_cert_out, &cert.pem(), ca_key_out, &key_pem, force)
}

/// Validates a DNS SAN as an RFC 1123 host name (no wildcards).
pub fn validate_dns_san(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 253 {
        return Err(format!("invalid DNS SAN '{name}': length must be 1-253"));
    }
    if name.starts_with('.') || name.ends_with('.') {
        return Err(format!("invalid DNS SAN '{name}': leading/trailing dot"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS SAN '{name}': bad label length"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "invalid DNS SAN '{name}': label starts/ends with '-'"
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!(
                "invalid DNS SAN '{name}': only letters, digits, '-' and '.' are allowed (no wildcards)"
            ));
        }
    }
    Ok(())
}

pub fn validate_ip_san(ip: IpAddr) -> Result<(), String> {
    let bad = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    if bad {
        return Err(format!(
            "invalid IP SAN '{ip}': unspecified, multicast and broadcast addresses are refused"
        ));
    }
    Ok(())
}

/// Confirms that `ca_cert_pem` is a single CA certificate whose public key
/// matches `ca_key`.
fn verify_ca_pair(ca_cert_pem: &[u8], ca_key: &KeyPair) -> Result<(), String> {
    let mut slice = ca_cert_pem;
    let ders: Vec<_> = rustls_pemfile::certs(&mut slice)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid CA certificate PEM: {e}"))?;
    if ders.len() != 1 {
        return Err(format!(
            "CA certificate file must contain exactly one certificate (found {})",
            ders.len()
        ));
    }
    let (_, cert) = X509Certificate::from_der(ders[0].as_ref())
        .map_err(|e| format!("invalid CA certificate DER: {e}"))?;
    match cert.basic_constraints() {
        Ok(Some(ext)) if ext.value.ca => {}
        _ => return Err("CA certificate is not marked as a CA (BasicConstraints ca=false)".into()),
    }
    if cert.public_key().raw != ca_key.public_key_der().as_slice() {
        return Err("CA key does not match the CA certificate".into());
    }
    Ok(())
}

pub fn init_server_cert(
    ca_cert_path: &Path,
    ca_key_path: &Path,
    server_cert_out: &Path,
    server_key_out: &Path,
    sans: &[String],
    days: u32,
    force: bool,
) -> Result<(), String> {
    if sans.is_empty() {
        return Err(
            "specify at least one --san (for example --san aim.example.internal --san 10.0.0.10)"
                .into(),
        );
    }
    if days == 0 || days > MAX_SERVER_DAYS {
        return Err(format!(
            "server cert validity days must be 1-{MAX_SERVER_DAYS}"
        ));
    }
    if !force && (entry_exists(server_cert_out) || entry_exists(server_key_out)) {
        return Err("server certificate or key already exists (pass --force to overwrite)".into());
    }

    let mut san_entries = Vec::with_capacity(sans.len());
    for san in sans {
        let trimmed = san.trim();
        if trimmed != san.as_str() || trimmed.is_empty() {
            return Err(format!("invalid SAN '{san}': whitespace is not allowed"));
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            validate_ip_san(ip)?;
            san_entries.push(SanType::IpAddress(ip));
        } else {
            validate_dns_san(trimmed)?;
            let dns = trimmed
                .to_string()
                .try_into()
                .map_err(|e| format!("invalid DNS SAN '{trimmed}': {e}"))?;
            san_entries.push(SanType::DnsName(dns));
        }
    }

    let ca_cert_bytes = aim_fs::read_trusted_config_bytes(ca_cert_path, 1024 * 1024)?;
    let ca_cert_pem = String::from_utf8(ca_cert_bytes)
        .map_err(|_| format!("{} is not valid UTF-8", ca_cert_path.display()))?;
    let ca_key_pem = Zeroizing::new(aim_fs::read_private_string(ca_key_path, 1024 * 1024)?);

    let ca_key = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| format!("invalid CA key {}: {e}", ca_key_path.display()))?;
    verify_ca_pair(ca_cert_pem.as_bytes(), &ca_key)?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
        .map_err(|e| format!("invalid CA cert {}: {e}", ca_cert_path.display()))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("failed reconstructing CA issuer: {e}"))?;

    let mut params = CertificateParams::new(Vec::new()).map_err(|e| e.to_string())?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.serial_number = Some(random_serial());
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name.push(DnType::CommonName, &sans[0]);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = san_entries;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(i64::from(days));

    let server_key =
        KeyPair::generate().map_err(|e| format!("failed generating server key: {e}"))?;
    let server_cert = params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|e| format!("failed signing server cert: {e}"))?;
    let key_pem = Zeroizing::new(server_key.serialize_pem());
    write_pair(
        server_cert_out,
        &server_cert.pem(),
        server_key_out,
        &key_pem,
        force,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sans() -> Vec<String> {
        vec!["localhost".into(), "127.0.0.1".into()]
    }

    #[test]
    fn generates_ca_and_signed_server_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_crt = dir.path().join("ca.crt");
        let ca_key = dir.path().join("ca.key");
        let srv_crt = dir.path().join("server.crt");
        let srv_key = dir.path().join("server.key");

        init_ca(&ca_crt, &ca_key, "AIM Test CA", 365, false).unwrap();
        init_server_cert(&ca_crt, &ca_key, &srv_crt, &srv_key, &sans(), 90, false).unwrap();

        let srv_pem = std::fs::read_to_string(&srv_crt).unwrap();
        assert!(srv_pem.contains("BEGIN CERTIFICATE"));
        // Refuses to overwrite without force.
        assert!(
            init_server_cert(&ca_crt, &ca_key, &srv_crt, &srv_key, &sans(), 90, false).is_err()
        );
    }

    #[test]
    fn rejects_mismatched_or_non_ca_and_bad_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        init_ca(&p("a.crt"), &p("a.key"), "CA A", 365, false).unwrap();
        init_ca(&p("b.crt"), &p("b.key"), "CA B", 365, false).unwrap();

        // Cert from CA A with key from CA B.
        let err = init_server_cert(
            &p("a.crt"),
            &p("b.key"),
            &p("s.crt"),
            &p("s.key"),
            &sans(),
            90,
            false,
        )
        .unwrap_err();
        assert!(err.contains("does not match"), "{err}");

        // A server (non-CA) cert used as CA.
        init_server_cert(
            &p("a.crt"),
            &p("a.key"),
            &p("s.crt"),
            &p("s.key"),
            &sans(),
            90,
            false,
        )
        .unwrap();
        let err = init_server_cert(
            &p("s.crt"),
            &p("s.key"),
            &p("t.crt"),
            &p("t.key"),
            &sans(),
            90,
            false,
        )
        .unwrap_err();
        assert!(err.contains("not marked as a CA"), "{err}");

        for bad in [
            "*.example.internal",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "bad host",
            "-x.example",
        ] {
            assert!(
                init_server_cert(
                    &p("a.crt"),
                    &p("a.key"),
                    &p("u.crt"),
                    &p("u.key"),
                    &[bad.to_string()],
                    90,
                    false
                )
                .is_err(),
                "{bad} should be rejected"
            );
        }
        assert!(init_server_cert(
            &p("a.crt"),
            &p("a.key"),
            &p("v.crt"),
            &p("v.key"),
            &sans(),
            826,
            false
        )
        .is_err());
        assert!(init_ca(&p("c.crt"), &p("c.key"), "CA C", MAX_CA_DAYS + 1, false).is_err());
    }
}
