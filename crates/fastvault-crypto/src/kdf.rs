use argon2::{Algorithm, Argon2, Params, Version};
use fastvault_core::error::{FastVaultError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,  // 64 MB
            t_cost: 3,      // 3 iterations
            p_cost: 4,      // 4 parallelism
            output_len: 32, // 256 bits KEK
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

pub struct KdfProvider;

impl KdfProvider {
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<DerivedKey> {
        if salt.len() < 16 {
            return Err(FastVaultError::CryptoError(
                "KDF salt must be at least 16 bytes".to_string(),
            ));
        }

        let argon_params = Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(params.output_len),
        )
        .map_err(|e| FastVaultError::CryptoError(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| FastVaultError::CryptoError(format!("KDF derivation failed: {}", e)))?;

        Ok(DerivedKey(key_bytes))
    }
}
