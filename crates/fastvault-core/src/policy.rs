use crate::error::{FastVaultError, Result};
use crate::secret::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub max_session_ttl_secs: u64,
    pub enforce_secret_expiration: bool,
    pub clipboard_auto_clear_secs: u64,
    pub require_confirmation_for_delete: bool,
    pub max_password_age_days: Option<u32>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_session_ttl_secs: 900, // 15 minutes default
            enforce_secret_expiration: true,
            clipboard_auto_clear_secs: 30,
            require_confirmation_for_delete: true,
            max_password_age_days: None,
        }
    }
}

pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn validate_access(&self, secret: &Secret) -> Result<()> {
        if self.config.enforce_secret_expiration && secret.is_expired() {
            return Err(FastVaultError::PolicyViolation(format!(
                "Secret '{}' has expired and cannot be accessed",
                secret.name
            )));
        }
        Ok(())
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }
}
