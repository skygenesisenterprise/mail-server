use crate::config::TlsConfig;
use crate::error::{MailServerError, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub async fn load_tls_config(config: &TlsConfig) -> Result<Arc<TlsAcceptor>> {
    // Load certificates
    let cert_file = File::open(&config.cert_path)
        .map_err(|e| MailServerError::Configuration(format!("Failed to open cert file: {}", e)))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain = certs(&mut cert_reader)
        .map_err(|e| {
            MailServerError::Configuration(format!("Failed to parse certificates: {}", e))
        })?
        .into_iter()
        .map(Certificate)
        .collect();

    // Load private key
    let key_file = File::open(&config.key_path)
        .map_err(|e| MailServerError::Configuration(format!("Failed to open key file: {}", e)))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut key_reader).map_err(|e| {
        MailServerError::Configuration(format!("Failed to parse private key: {}", e))
    })?;

    if keys.is_empty() {
        return Err(MailServerError::Configuration(
            "No private key found".to_string(),
        ));
    }

    let private_key = PrivateKey(keys.remove(0));

    // Create TLS configuration
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| {
            MailServerError::Configuration(format!("Failed to create TLS config: {}", e))
        })?;

    Ok(Arc::new(TlsAcceptor::from(Arc::new(tls_config))))
}

pub fn create_self_signed_cert() -> Result<()> {
    // This would contain logic to generate self-signed certificates for development
    // For production, proper certificates should be used
    todo!("Implement self-signed certificate generation for development")
}
