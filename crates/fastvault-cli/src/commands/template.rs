use fastvault_core::error::{FastVaultError, Result};
use fastvault_core::secret::Secret;
use regex::Regex;
use std::fs;
use std::path::Path;

pub fn render_template(template_path: impl AsRef<Path>, secrets: &[Secret]) -> Result<String> {
    let content = fs::read_to_string(template_path)?;
    let re = Regex::new(r"\{\{\s*fastvault:([a-zA-Z0-9_/-]+)\s*\}\}").unwrap();

    let mut missing_secrets = Vec::new();

    let result = re.replace_all(&content, |caps: &regex::Captures| {
        let path = &caps[1];
        if let Some(secret) = secrets.iter().find(|s| s.path() == path && !s.is_deleted) {
            secret.value.as_str().to_string()
        } else {
            missing_secrets.push(path.to_string());
            format!("{{MISSING:{}}}", path)
        }
    });

    if !missing_secrets.is_empty() {
        return Err(FastVaultError::SecretNotFound(format!(
            "Template reference to missing secret(s): {}",
            missing_secrets.join(", ")
        )));
    }

    Ok(result.to_string())
}
