use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fastvault_core::error::{FastVaultError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncObjectMeta {
    pub revision_id: String,
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
    pub payload_size: u64,
}

#[async_trait]
pub trait SyncBackend: Send + Sync {
    async fn list_revisions(&self) -> Result<Vec<SyncObjectMeta>>;
    async fn push_vault(&self, meta: &SyncObjectMeta, vault_data: &[u8]) -> Result<()>;
    async fn pull_vault(&self, revision_id: &str) -> Result<Vec<u8>>;
}

pub struct LocalBackend {
    target_dir: PathBuf,
}

impl LocalBackend {
    pub fn new(target_dir: impl Into<PathBuf>) -> Self {
        Self {
            target_dir: target_dir.into(),
        }
    }
}

#[async_trait]
impl SyncBackend for LocalBackend {
    async fn list_revisions(&self) -> Result<Vec<SyncObjectMeta>> {
        if !self.target_dir.exists() {
            fs::create_dir_all(&self.target_dir)?;
            return Ok(Vec::new());
        }

        let meta_file = self.target_dir.join("sync_revisions.json");
        if !meta_file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(meta_file)?;
        let revisions: Vec<SyncObjectMeta> = serde_json::from_str(&content)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        Ok(revisions)
    }

    async fn push_vault(&self, meta: &SyncObjectMeta, vault_data: &[u8]) -> Result<()> {
        if !self.target_dir.exists() {
            fs::create_dir_all(&self.target_dir)?;
        }

        let payload_file = self
            .target_dir
            .join(format!("vault_{}.fvt", meta.revision_id));
        fs::write(payload_file, vault_data)?;

        let mut current_revisions = self.list_revisions().await?;
        current_revisions.push(meta.clone());

        let meta_file = self.target_dir.join("sync_revisions.json");
        let serialized = serde_json::to_string_pretty(&current_revisions)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        fs::write(meta_file, serialized)?;
        Ok(())
    }

    async fn pull_vault(&self, revision_id: &str) -> Result<Vec<u8>> {
        let payload_file = self.target_dir.join(format!("vault_{}.fvt", revision_id));
        if !payload_file.exists() {
            return Err(FastVaultError::VaultError(format!(
                "Revision {} not found on remote storage",
                revision_id
            )));
        }

        let data = fs::read(payload_file)?;
        Ok(data)
    }
}

#[allow(dead_code)]
pub struct S3Backend {
    bucket_name: String,
    prefix: String,
}

impl S3Backend {
    pub fn new(bucket_name: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            bucket_name: bucket_name.into(),
            prefix: prefix.into(),
        }
    }
}

#[async_trait]
impl SyncBackend for S3Backend {
    async fn list_revisions(&self) -> Result<Vec<SyncObjectMeta>> {
        Ok(Vec::new())
    }

    async fn push_vault(&self, _meta: &SyncObjectMeta, _vault_data: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn pull_vault(&self, revision_id: &str) -> Result<Vec<u8>> {
        Err(FastVaultError::VaultError(format!(
            "S3 revision {} pull not configured",
            revision_id
        )))
    }
}
