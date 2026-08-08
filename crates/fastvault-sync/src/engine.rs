use crate::backend::{SyncBackend, SyncObjectMeta};
use chrono::Utc;
use fastvault_core::error::{FastVaultError, Result};
use fastvault_store::VaultStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub pushed: bool,
    pub pulled: bool,
    pub revision_id: String,
}

pub struct SyncEngine {
    store: Arc<VaultStore>,
    device_id: String,
}

impl SyncEngine {
    pub fn new(store: VaultStore, device_id: impl Into<String>) -> Self {
        Self {
            store: Arc::new(store),
            device_id: device_id.into(),
        }
    }

    pub fn compute_revision_hash(vault_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(vault_bytes);
        hex::encode(&hasher.finalize()[..8])
    }

    pub async fn synchronize(&self, backend: &dyn SyncBackend, force: bool) -> Result<SyncResult> {
        let local_vault = self.store.load_vault()?;
        let local_bytes = bincode::serialize(&local_vault)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let local_rev = Self::compute_revision_hash(&local_bytes);
        let remote_revisions = backend.list_revisions().await?;

        if let Some(latest_remote) = remote_revisions.last() {
            if latest_remote.revision_id == local_rev {
                return Ok(SyncResult {
                    pushed: false,
                    pulled: false,
                    revision_id: local_rev,
                });
            }

            if !force {
                let contains_local = remote_revisions.iter().any(|r| r.revision_id == local_rev);

                if !contains_local && remote_revisions.len() > 1 {
                    return Err(FastVaultError::SyncConflict("vault.fvt".to_string(), 1, 2));
                }
            }
        }

        let meta = SyncObjectMeta {
            revision_id: local_rev.clone(),
            device_id: self.device_id.clone(),
            timestamp: Utc::now(),
            payload_size: local_bytes.len() as u64,
        };

        backend.push_vault(&meta, &local_bytes).await?;

        Ok(SyncResult {
            pushed: true,
            pulled: false,
            revision_id: local_rev,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;
    use fastvault_crypto::KdfParams;

    #[tokio::test]
    async fn test_sync_engine_local_backend() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.fvt");
        let audit_file = dir.path().join("audit.json");
        let remote_dir = dir.path().join("remote_sync");

        let store = VaultStore::new(&vault_file, &audit_file);
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        store.init_vault("SyncTestPassword", params).unwrap();

        let engine = SyncEngine::new(store, "laptop-device-01");
        let backend = LocalBackend::new(remote_dir);

        let res = engine.synchronize(&backend, false).await.unwrap();
        assert!(res.pushed);

        let res2 = engine.synchronize(&backend, false).await.unwrap();
        assert!(!res2.pushed);
        assert!(!res2.pulled);
    }
}
