use crate::error::{FastVaultError, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1};

pub struct TotpGenerator;

impl TotpGenerator {
    pub fn generate_code(secret_b32: &str) -> Result<String> {
        let clean_secret = secret_b32.trim().replace(' ', "").to_uppercase();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(clean_secret.as_bytes())
            .map_err(|e| FastVaultError::TotpError(format!("Invalid Base32 secret: {}", e)))?;

        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FastVaultError::TotpError(e.to_string()))?
            .as_secs();

        let code = totp_custom::<Sha1>(30, 6, &bytes, seconds);
        Ok(code)
    }

    pub fn time_remaining() -> u64 {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        30 - (seconds % 30)
    }
}
