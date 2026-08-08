use fastvault_core::error::{FastVaultError, Result};
use fastvault_core::secret::Secret;
use fastvault_crypto::DataEncryptionKey;
use std::process::Command;

pub fn execute_env_run(
    env_mappings: &[String],
    command: &[String],
    _dek: &DataEncryptionKey,
    secrets: &[Secret],
) -> Result<()> {
    if command.is_empty() {
        return Err(FastVaultError::VaultError(
            "No command provided to execute".to_string(),
        ));
    }

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    for mapping in env_mappings {
        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(FastVaultError::VaultError(format!(
                "Invalid env mapping format '{}'. Expected VAR_NAME=path/to/secret",
                mapping
            )));
        }

        let var_name = parts[0].trim();
        let secret_path = parts[1].trim();

        let secret = secrets
            .iter()
            .find(|s| s.path() == secret_path && !s.is_deleted)
            .ok_or_else(|| FastVaultError::SecretNotFound(secret_path.to_string()))?;

        cmd.env(var_name, secret.value.as_str());
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| FastVaultError::VaultError(format!("Failed to spawn child process: {}", e)))?;

    let status = child
        .wait()
        .map_err(|e| FastVaultError::VaultError(format!("Process execution error: {}", e)))?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}
