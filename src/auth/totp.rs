use crate::error::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

pub fn generate_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let secret: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret)
}

pub fn verify_code(secret: &str, code: &str) -> bool {
    let secret_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret) {
        Some(bytes) => bytes,
        None => return false,
    };

    let time_step = get_current_time_step();
    
    // Check current time step and adjacent ones (to account for clock drift)
    for offset in -1..=1 {
        if let Ok(expected_code) = generate_totp_code(&secret_bytes, time_step + offset) {
            if expected_code == code {
                return true;
            }
        }
    }
    
    false
}

pub fn generate_totp_code(secret: &[u8], time_step: u64) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret)
        .map_err(|_| crate::error::MailServerError::Authentication("Invalid TOTP secret".to_string()))?;
    
    mac.update(&time_step.to_be_bytes());
    let result = mac.finalize().into_bytes();
    
    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | ((result[offset + 1] & 0xff) as u32) << 16
        | ((result[offset + 2] & 0xff) as u32) << 8
        | (result[offset + 3] & 0xff) as u32;
    
    Ok(format!("{:06}", code % 1_000_000))
}

fn get_current_time_step() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now / 30 // 30-second time steps
}

pub fn generate_qr_code_url(secret: &str, account_name: &str, issuer: &str) -> String {
    let totp_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        urlencoding::encode(issuer),
        urlencoding::encode(account_name),
        secret,
        urlencoding::encode(issuer)
    );
    
    format!(
        "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={}",
        urlencoding::encode(&totp_url)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let secret = "JBSWY3DPEHPK3PXP";
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret).unwrap();
        
        // Test with known time step
        let code = generate_totp_code(&secret_bytes, 1).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_numeric()));
    }

    #[test]
    fn test_secret_generation() {
        let secret = generate_secret();
        assert!(!secret.is_empty());
        assert!(secret.len() >= 16); // Base32 encoded 20 bytes should be at least 32 chars
    }
}
