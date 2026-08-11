use chrono::{DateTime, Utc};
use fastvault_core::error::{FastVaultError, Result};
use fastvault_crypto::VersionedVault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackup {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub checksum_sha256: String,
    pub vault: VersionedVault,
}

pub struct BackupEngine;

impl BackupEngine {
    pub fn create_backup(
        vault: &VersionedVault,
        output_path: impl AsRef<Path>,
    ) -> Result<VaultBackup> {
        let serialized_vault = bincode::serialize(vault)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized_vault);
        let checksum = hex::encode(hasher.finalize());

        let backup = VaultBackup {
            version: 1,
            created_at: Utc::now(),
            checksum_sha256: checksum,
            vault: vault.clone(),
        };

        let backup_bytes = bincode::serialize(&backup)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        fs::write(output_path, backup_bytes)?;
        Ok(backup)
    }

    pub fn inspect_backup(backup_path: impl AsRef<Path>) -> Result<VaultBackup> {
        let bytes = fs::read(backup_path)?;
        let backup: VaultBackup = bincode::deserialize(&bytes)
            .map_err(|e| FastVaultError::VaultError(format!("Invalid backup format: {}", e)))?;

        // Verify checksum
        let serialized_vault = bincode::serialize(&backup.vault)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized_vault);
        let computed_checksum = hex::encode(hasher.finalize());

        if computed_checksum != backup.checksum_sha256 {
            return Err(FastVaultError::VaultError(
                "Backup integrity check failed: SHA256 checksum mismatch".to_string(),
            ));
        }

        Ok(backup)
    }

    pub fn restore_backup(backup_path: impl AsRef<Path>) -> Result<VersionedVault> {
        let backup = Self::inspect_backup(backup_path)?;
        Ok(backup.vault)
    }
}
