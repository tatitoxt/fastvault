use crate::aead::AeadCipher;
use crate::kdf::KdfParams;
use crate::key_hierarchy::{DataEncryptionKey, KeyHierarchy, WrappedKey};
use fastvault_core::error::{FastVaultError, Result};
use fastvault_core::secret::Secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAGIC_BYTES: &[u8; 8] = b"FASTVALT";
pub const CURRENT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub format_version: u32,
    pub vault_id: Uuid,
    pub kdf_params: KdfParams,
    pub kdf_salt: [u8; 32],
    pub wrapped_dek: WrappedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedVault {
    pub header: VaultHeader,
    pub payload_nonce: [u8; 12],
    pub encrypted_payload: Vec<u8>,
}

impl VersionedVault {
    pub fn create_empty(password: &str, params: KdfParams) -> Result<(Self, DataEncryptionKey)> {
        let vault_id = Uuid::new_v4();
        let (kdf_salt, wrapped_dek, dek) = KeyHierarchy::create_vault_keys(password, &params)?;

        let header = VaultHeader {
            magic: *MAGIC_BYTES,
            format_version: CURRENT_FORMAT_VERSION,
            vault_id,
            kdf_params: params,
            kdf_salt,
            wrapped_dek,
        };

        let empty_secrets: Vec<Secret> = Vec::new();
        let serialized_payload = bincode::serialize(&empty_secrets)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let aad = vault_id.as_bytes();
        let (encrypted_payload, payload_nonce) =
            AeadCipher::encrypt(&dek.0, &serialized_payload, Some(aad))?;

        let vault = VersionedVault {
            header,
            payload_nonce,
            encrypted_payload,
        };

        Ok((vault, dek))
    }

    pub fn unlock(&self, password: &str) -> Result<(DataEncryptionKey, Vec<Secret>)> {
        if &self.header.magic != MAGIC_BYTES {
            return Err(FastVaultError::VaultError(
                "Invalid vault magic header".to_string(),
            ));
        }

        if self.header.format_version > CURRENT_FORMAT_VERSION {
            return Err(FastVaultError::VaultError(format!(
                "Unsupported vault version: {}",
                self.header.format_version
            )));
        }

        let dek = KeyHierarchy::unwrap_dek(
            password,
            &self.header.kdf_salt,
            &self.header.kdf_params,
            &self.header.wrapped_dek,
        )?;

        let secrets = self.decrypt_secrets(&dek)?;
        Ok((dek, secrets))
    }

    pub fn decrypt_secrets(&self, dek: &DataEncryptionKey) -> Result<Vec<Secret>> {
        let aad = self.header.vault_id.as_bytes();
        let plaintext_bytes = AeadCipher::decrypt(
            &dek.0,
            &self.encrypted_payload,
            &self.payload_nonce,
            Some(aad),
        )?;

        let secrets: Vec<Secret> = bincode::deserialize(&plaintext_bytes)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        Ok(secrets)
    }

    pub fn update_secrets(&mut self, dek: &DataEncryptionKey, secrets: &[Secret]) -> Result<()> {
        let serialized_payload = bincode::serialize(secrets)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let aad = self.header.vault_id.as_bytes();
        let (encrypted_payload, payload_nonce) =
            AeadCipher::encrypt(&dek.0, &serialized_payload, Some(aad))?;

        self.encrypted_payload = encrypted_payload;
        self.payload_nonce = payload_nonce;
        Ok(())
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let (new_salt, new_wrapped_dek, _dek) = KeyHierarchy::rewrap_dek(
            old_password,
            new_password,
            &self.header.kdf_salt,
            &self.header.kdf_params,
            &self.header.wrapped_dek,
        )?;

        self.header.kdf_salt = new_salt;
        self.header.wrapped_dek = new_wrapped_dek;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf_params() -> KdfParams {
        KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        }
    }

    #[test]
    fn test_vault_lifecycle() {
        let pwd = "SuperSecretPassword123!";
        let params = test_kdf_params();

        let (mut vault, dek) = VersionedVault::create_empty(pwd, params).unwrap();

        let mut secret1 = Secret::new("api_key", "prod", "sk_live_123456789");
        secret1.tags = vec!["stripe".to_string(), "backend".to_string()];

        vault.update_secrets(&dek, &[secret1.clone()]).unwrap();

        let (unlocked_dek, secrets) = vault.unlock(pwd).unwrap();
        assert_eq!(unlocked_dek.0, dek.0);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "api_key");
        assert_eq!(secrets[0].value.as_str(), "sk_live_123456789");

        // Wrong password test
        assert!(vault.unlock("WrongPassword").is_err());
    }

    #[test]
    fn test_password_change_rewrapping() {
        let old_pwd = "OldPassword123";
        let new_pwd = "NewPassword456";
        let params = test_kdf_params();

        let (mut vault, dek) = VersionedVault::create_empty(old_pwd, params).unwrap();

        let secret = Secret::new("db_pass", "prod", "p@ssword!");
        vault.update_secrets(&dek, &[secret]).unwrap();

        // Change password
        vault.change_password(old_pwd, new_pwd).unwrap();

        // Old password should fail
        assert!(vault.unlock(old_pwd).is_err());

        // New password should succeed and yield identical secret
        let (_, secrets) = vault.unlock(new_pwd).unwrap();
        assert_eq!(secrets[0].value.as_str(), "p@ssword!");
    }
}
