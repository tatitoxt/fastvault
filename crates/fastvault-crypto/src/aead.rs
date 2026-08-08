use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use fastvault_core::error::{FastVaultError, Result};
use rand::RngCore;

pub struct AeadCipher;

impl AeadCipher {
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    pub fn encrypt(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, [u8; 12])> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| FastVaultError::CryptoError(format!("Invalid key length: {}", e)))?;

        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(&[]),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| FastVaultError::CryptoError(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(
        key: &[u8; 32],
        ciphertext: &[u8],
        nonce_bytes: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| FastVaultError::CryptoError(format!("Invalid key length: {}", e)))?;

        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad: aad.unwrap_or(&[]),
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| FastVaultError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}
