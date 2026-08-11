use fd_lock::RwLock;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use fastvault_audit::AuditLog;
use fastvault_core::error::{FastVaultError, Result};
use fastvault_crypto::{KdfParams, VersionedVault};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct VaultStore {
    vault_path: PathBuf,
    audit_path: PathBuf,
}

impl VaultStore {
    pub fn new(vault_path: impl Into<PathBuf>, audit_path: impl Into<PathBuf>) -> Self {
        Self {
            vault_path: vault_path.into(),
            audit_path: audit_path.into(),
        }
    }

    pub fn default_paths() -> Result<(PathBuf, PathBuf)> {
        let home = dirs::home_dir().ok_or_else(|| {
            FastVaultError::VaultError("Could not locate home directory".to_string())
        })?;
        let dir = home.join(".fastvault");
        let vault_file = dir.join("vault.fvt");
        let audit_file = dir.join("audit.json");
        Ok((vault_file, audit_file))
    }

    pub fn init_vault(
        &self,
        password: &str,
        params: KdfParams,
    ) -> Result<(VersionedVault, AuditLog)> {
        if self.vault_path.exists() {
            return Err(FastVaultError::VaultError(
                "Vault already exists at target location".to_string(),
            ));
        }

        self.ensure_directory_permissions()?;

        let (vault, _dek) = VersionedVault::create_empty(password, params)?;
        self.save_vault(&vault)?;

        let mut hmac_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut hmac_key);
        let mut audit_log = AuditLog::new(hmac_key);

        audit_log.record_event(
            fastvault_audit::AuditEventType::VaultCreated,
            "system",
            None,
            std::collections::HashMap::new(),
        )?;

        self.save_audit_log(&audit_log)?;

        Ok((vault, audit_log))
    }

    pub fn load_vault(&self) -> Result<VersionedVault> {
        if !self.vault_path.exists() {
            return Err(FastVaultError::VaultError(
                "Vault file does not exist".to_string(),
            ));
        }

        let file = File::open(&self.vault_path)?;
        let mut lock = RwLock::new(file);
        let mut read_guard = lock.write().map_err(|e| {
            FastVaultError::VaultError(format!("Failed to acquire read lock: {}", e))
        })?;

        let mut buffer = Vec::new();
        read_guard.read_to_end(&mut buffer)?;

        let vault: VersionedVault = bincode::deserialize(&buffer)
            .map_err(|e| FastVaultError::VaultError(format!("Corrupted vault data: {}", e)))?;

        Ok(vault)
    }

    pub fn save_vault(&self, vault: &VersionedVault) -> Result<()> {
        self.ensure_directory_permissions()?;

        let serialized = bincode::serialize(vault)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let parent = self.vault_path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = NamedTempFile::new_in(parent)?;

        temp_file.write_all(&serialized)?;
        temp_file.as_file().sync_all()?;

        #[cfg(unix)]
        {
            let mut perms = temp_file.as_file().metadata()?.permissions();
            perms.set_mode(0o600);
            temp_file.as_file().set_permissions(perms)?;
        }

        temp_file.persist(&self.vault_path).map_err(|e| {
            FastVaultError::VaultError(format!("Failed atomic persist of vault: {}", e))
        })?;

        Ok(())
    }

    pub fn load_audit_log(&self) -> Result<AuditLog> {
        if !self.audit_path.exists() {
            let key = [0u8; 32];
            return Ok(AuditLog::new(key));
        }

        let content = fs::read_to_string(&self.audit_path)?;
        let log: AuditLog = serde_json::from_str(&content)
            .map_err(|e| FastVaultError::AuditError(format!("Corrupted audit log: {}", e)))?;

        Ok(log)
    }

    pub fn save_audit_log(&self, audit_log: &AuditLog) -> Result<()> {
        self.ensure_directory_permissions()?;

        let serialized = serde_json::to_string_pretty(audit_log)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let parent = self.audit_path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = NamedTempFile::new_in(parent)?;

        temp_file.write_all(serialized.as_bytes())?;
        temp_file.as_file().sync_all()?;

        #[cfg(unix)]
        {
            let mut perms = temp_file.as_file().metadata()?.permissions();
            perms.set_mode(0o600);
            temp_file.as_file().set_permissions(perms)?;
        }

        temp_file.persist(&self.audit_path).map_err(|e| {
            FastVaultError::AuditError(format!("Failed atomic persist of audit log: {}", e))
        })?;

        Ok(())
    }

    fn ensure_directory_permissions(&self) -> Result<()> {
        if let Some(parent) = self.vault_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(parent)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(parent, perms)?;
            }
        }
        Ok(())
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_store_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("test_vault.fvt");
        let audit_file = dir.path().join("test_audit.json");

        let store = VaultStore::new(&vault_file, &audit_file);

        let kdf_params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };

        let (vault, _audit) = store.init_vault("TestPassword123", kdf_params).unwrap();
        assert!(store.vault_exists());

        let loaded_vault = store.load_vault().unwrap();
        assert_eq!(loaded_vault.header.vault_id, vault.header.vault_id);
    }
}
