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
                // Conflict only when the latest remote revision was written
                // by ANOTHER device and this local hash isn't already on the
                // remote — same-device pushes are fast-forwards, even once
                // the remote holds several of this device's revisions.
                let from_other_device = latest_remote.device_id != self.device_id;
                let contains_local = remote_revisions.iter().any(|r| r.revision_id == local_rev);

                if from_other_device && !contains_local {
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

    fn make_store(dir: &tempfile::TempDir, name: &str) -> VaultStore {
        let vault_file = dir.path().join(format!("{}.fvt", name));
        let audit_file = dir.path().join(format!("{}-audit.json", name));
        let store = VaultStore::new(&vault_file, &audit_file);
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        store.init_vault("SyncTestPassword", params).unwrap();
        store
    }

    #[tokio::test]
    async fn test_same_device_third_push_is_not_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let remote_dir = dir.path().join("remote");
        let backend = LocalBackend::new(&remote_dir);

        let store_a = make_store(&dir, "a");
        let engine_a = SyncEngine::new(store_a, "laptop-01");
        engine_a.synchronize(&backend, false).await.unwrap();

        // A second, different vault pushed by the same device.
        let store_b = make_store(&dir, "b");
        let engine_b = SyncEngine::new(store_b, "laptop-01");
        engine_b.synchronize(&backend, false).await.unwrap();

        // A third divergent revision from the same device is a fast-forward.
        let store_c = make_store(&dir, "c");
        let engine_c = SyncEngine::new(store_c, "laptop-01");
        let res = engine_c.synchronize(&backend, false).await.unwrap();
        assert!(res.pushed);
        assert_eq!(backend.list_revisions().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_other_device_divergence_conflicts_until_forced() {
        let dir = tempfile::tempdir().unwrap();
        let remote_dir = dir.path().join("remote");
        let backend = LocalBackend::new(&remote_dir);

        let store_a = make_store(&dir, "a");
        SyncEngine::new(store_a, "laptop-01")
            .synchronize(&backend, false)
            .await
            .unwrap();

        // A different device pushing divergent content conflicts...
        let store_b = make_store(&dir, "b");
        let engine_b = SyncEngine::new(store_b, "desktop-02");
        assert!(engine_b.synchronize(&backend, false).await.is_err());
        // ...until forced.
        let res = engine_b.synchronize(&backend, true).await.unwrap();
        assert!(res.pushed);
    }
}
