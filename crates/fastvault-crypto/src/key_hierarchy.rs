use crate::aead::AeadCipher;
use crate::kdf::{KdfParams, KdfProvider};
use fastvault_core::error::{FastVaultError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKey {
    pub encrypted_key: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey(pub [u8; 32]);

impl DataEncryptionKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }
}

pub struct KeyHierarchy;

impl KeyHierarchy {
    pub fn create_vault_keys(
        password: &str,
        params: &KdfParams,
    ) -> Result<([u8; 32], WrappedKey, DataEncryptionKey)> {
        let salt = KdfProvider::generate_salt();
        let kek = KdfProvider::derive_key(password, &salt, params)?;
        let dek = DataEncryptionKey::generate();

        let (encrypted_key, nonce) = AeadCipher::encrypt(&kek.0, &dek.0, Some(b"DEK_WRAPPING"))?;

        let wrapped_dek = WrappedKey {
            encrypted_key,
            nonce,
        };

        Ok((salt, wrapped_dek, dek))
    }

    pub fn unwrap_dek(
        password: &str,
        salt: &[u8],
        params: &KdfParams,
        wrapped_dek: &WrappedKey,
    ) -> Result<DataEncryptionKey> {
        let kek = KdfProvider::derive_key(password, salt, params)?;
        let dek_bytes = AeadCipher::decrypt(
            &kek.0,
            &wrapped_dek.encrypted_key,
            &wrapped_dek.nonce,
            Some(b"DEK_WRAPPING"),
        )?;

        if dek_bytes.len() != 32 {
            return Err(FastVaultError::CryptoError(
                "Invalid unwrapped DEK length".to_string(),
            ));
        }

        let mut dek_array = [0u8; 32];
        dek_array.copy_from_slice(&dek_bytes);
        Ok(DataEncryptionKey(dek_array))
    }

    pub fn rewrap_dek(
        old_password: &str,
        new_password: &str,
        old_salt: &[u8],
        params: &KdfParams,
        wrapped_dek: &WrappedKey,
    ) -> Result<([u8; 32], WrappedKey, DataEncryptionKey)> {
        let dek = Self::unwrap_dek(old_password, old_salt, params, wrapped_dek)?;

        let new_salt = KdfProvider::generate_salt();
        let new_kek = KdfProvider::derive_key(new_password, &new_salt, params)?;

        let (encrypted_key, nonce) =
            AeadCipher::encrypt(&new_kek.0, &dek.0, Some(b"DEK_WRAPPING"))?;

        let new_wrapped_dek = WrappedKey {
            encrypted_key,
            nonce,
        };

        Ok((new_salt, new_wrapped_dek, dek))
    }
}
