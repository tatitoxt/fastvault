use crate::protocol::{AgentRequest, AgentResponse};
use chrono::{DateTime, Utc};
use fastvault_core::error::{FastVaultError, Result};
use fastvault_store::VaultStore;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use zeroize::Zeroize;

#[derive(Clone, Default)]
struct SessionState {
    cached_dek: Option<[u8; 32]>,
    expires_at: Option<DateTime<Utc>>,
    ttl_secs: u64,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        if let Some(ref mut dek) = self.cached_dek {
            dek.zeroize();
        }
    }
}

pub struct AgentServer {
    socket_path: PathBuf,
    state: Arc<RwLock<SessionState>>,
    store: Arc<VaultStore>,
}

impl AgentServer {
    pub fn new(socket_path: impl Into<PathBuf>, store: VaultStore) -> Self {
        Self {
            socket_path: socket_path.into(),
            state: Arc::new(RwLock::new(SessionState::default())),
            store: Arc::new(store),
        }
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            FastVaultError::VaultError("Could not locate home directory".to_string())
        })?;
        Ok(home.join(".fastvault").join("agent.sock"))
    }

    pub async fn run(&self) -> Result<()> {
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.socket_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.socket_path, perms)?;
        }

        let state_clone = self.state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let mut state = state_clone.write().await;
                if let Some(expires_at) = state.expires_at {
                    if Utc::now() > expires_at {
                        if let Some(ref mut dek) = state.cached_dek {
                            dek.zeroize();
                        }
                        state.cached_dek = None;
                        state.expires_at = None;
                    }
                }
            }
        });

        loop {
            let (mut socket, _) = listener.accept().await?;
            let state = self.state.clone();
            let store = self.store.clone();

            tokio::spawn(async move {
                let mut len_buf = [0u8; 4];
                if socket.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }

                let req: AgentRequest = match serde_json::from_slice(&buf) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = AgentResponse::Error(e.to_string());
                        let resp_bytes = serde_json::to_vec(&resp).unwrap();
                        let resp_len = (resp_bytes.len() as u32).to_be_bytes();
                        let _ = socket.write_all(&resp_len).await;
                        let _ = socket.write_all(&resp_bytes).await;
                        return;
                    }
                };

                let response = Self::handle_request(req, state, store).await;
                let resp_bytes = serde_json::to_vec(&response).unwrap();
                let resp_len = (resp_bytes.len() as u32).to_be_bytes();
                let _ = socket.write_all(&resp_len).await;
                let _ = socket.write_all(&resp_bytes).await;
            });
        }
    }

    async fn handle_request(
        req: AgentRequest,
        state: Arc<RwLock<SessionState>>,
        store: Arc<VaultStore>,
    ) -> AgentResponse {
        match req {
            AgentRequest::Ping => AgentResponse::Pong,
            AgentRequest::Unlock { password, ttl_secs } => match store.load_vault() {
                Ok(vault) => match vault.unlock(&password) {
                    Ok((dek, _)) => {
                        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
                        let mut st = state.write().await;
                        st.cached_dek = Some(dek.0);
                        st.expires_at = Some(expires_at);
                        st.ttl_secs = ttl_secs;
                        AgentResponse::Unlocked { expires_at }
                    }
                    Err(_) => AgentResponse::Error("Authentication failed".to_string()),
                },
                Err(e) => AgentResponse::Error(e.to_string()),
            },
            AgentRequest::Lock => {
                let mut st = state.write().await;
                if let Some(ref mut dek) = st.cached_dek {
                    dek.zeroize();
                }
                st.cached_dek = None;
                st.expires_at = None;
                AgentResponse::Locked
            }
            AgentRequest::GetStatus => {
                let st = state.read().await;
                let is_unlocked = st.cached_dek.is_some()
                    && st.expires_at.map(|exp| Utc::now() <= exp).unwrap_or(false);
                AgentResponse::Status {
                    is_unlocked,
                    expires_at: st.expires_at,
                    ttl_secs: st.ttl_secs,
                }
            }
            AgentRequest::GetCachedDek => {
                let st = state.read().await;
                if let Some(expires_at) = st.expires_at {
                    if Utc::now() <= expires_at {
                        if let Some(dek) = st.cached_dek {
                            return AgentResponse::Dek {
                                dek_bytes: dek.to_vec(),
                            };
                        }
                    }
                }
                AgentResponse::Error("Session locked or expired".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AgentClient;
    use fastvault_crypto::KdfParams;

    #[tokio::test]
    async fn test_agent_ipc_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let socket_file = dir.path().join("agent.sock");
        let vault_file = dir.path().join("vault.fvt");
        let audit_file = dir.path().join("audit.json");

        let store = VaultStore::new(&vault_file, &audit_file);
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        store.init_vault("MasterPassword123", params).unwrap();

        let server = AgentServer::new(&socket_file, store);
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to bind socket
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = AgentClient::new(&socket_file);

        // Ping test
        let ping_resp = client.send_request(AgentRequest::Ping).await.unwrap();
        assert!(matches!(ping_resp, AgentResponse::Pong));

        // Unlock session via agent
        let unlock_resp = client
            .send_request(AgentRequest::Unlock {
                password: "MasterPassword123".to_string(),
                ttl_secs: 10,
            })
            .await
            .unwrap();
        assert!(matches!(unlock_resp, AgentResponse::Unlocked { .. }));

        // Get status
        let status_resp = client.send_request(AgentRequest::GetStatus).await.unwrap();
        if let AgentResponse::Status { is_unlocked, .. } = status_resp {
            assert!(is_unlocked);
        } else {
            panic!("Expected Status response");
        }

        // Lock session
        let lock_resp = client.send_request(AgentRequest::Lock).await.unwrap();
        assert!(matches!(lock_resp, AgentResponse::Locked));
    }
}
