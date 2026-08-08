use fastvault_core::error::{FastVaultError, Result};
use fastvault_core::secret::Secret;

pub struct TrashBin;

impl TrashBin {
    pub fn soft_delete(secrets: &mut [Secret], secret_path: &str) -> Result<Secret> {
        let secret = secrets
            .iter_mut()
            .find(|s| s.path() == secret_path && !s.is_deleted)
            .ok_or_else(|| FastVaultError::SecretNotFound(secret_path.to_string()))?;

        secret.is_deleted = true;
        secret.updated_at = chrono::Utc::now();
        Ok(secret.clone())
    }

    pub fn restore(secrets: &mut [Secret], secret_path: &str) -> Result<Secret> {
        let secret = secrets
            .iter_mut()
            .find(|s| s.path() == secret_path && s.is_deleted)
            .ok_or_else(|| FastVaultError::SecretNotFound(secret_path.to_string()))?;

        secret.is_deleted = false;
        secret.updated_at = chrono::Utc::now();
        Ok(secret.clone())
    }

    pub fn list_deleted(secrets: &[Secret]) -> Vec<&Secret> {
        secrets.iter().filter(|s| s.is_deleted).collect()
    }

    pub fn list_active(secrets: &[Secret]) -> Vec<&Secret> {
        secrets.iter().filter(|s| !s.is_deleted).collect()
    }

    pub fn permanent_delete(secrets: &mut Vec<Secret>, secret_path: &str) -> Result<Secret> {
        let idx = secrets
            .iter()
            .position(|s| s.path() == secret_path)
            .ok_or_else(|| FastVaultError::SecretNotFound(secret_path.to_string()))?;

        Ok(secrets.remove(idx))
    }
}
