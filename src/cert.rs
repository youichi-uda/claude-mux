use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use std::path::Path;
use time::OffsetDateTime;

/// Generate a self-signed CA certificate and key pair.
/// Returns (cert_pem, key_pem).
pub fn generate_ca() -> Result<(String, String)> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Claude Mux Local CA");
    dn.push(DnType::OrganizationName, "claude-mux");
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    // Valid for 10 years
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(3650))
        .unwrap();

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Generate a TLS certificate for a specific hostname, signed by our CA.
pub fn generate_host_cert(
    hostname: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(String, String)> {
    // Parse CA
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Create host cert
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()?)];

    // Valid for 1 year
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(365))
        .unwrap();

    let host_key = KeyPair::generate()?;
    let host_cert = params.signed_by(&host_key, &ca_cert, &ca_key)?;

    Ok((host_cert.pem(), host_key.serialize_pem()))
}

/// Load or generate CA certificate. Returns (cert_pem, key_pem).
pub fn ensure_ca(cert_path: &Path, key_path: &Path) -> Result<(String, String)> {
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read_to_string(cert_path).context("Reading CA cert")?;
        let key = std::fs::read_to_string(key_path).context("Reading CA key")?;
        return Ok((cert, key));
    }

    tracing::info!("Generating new CA certificate...");
    let (cert, key) = generate_ca()?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, &cert)?;
    std::fs::write(key_path, &key)?;

    // Restrict key file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!("CA certificate saved to {}", cert_path.display());
    Ok((cert, key))
}
