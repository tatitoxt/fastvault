use crate::protocol::{AgentRequest, AgentResponse};
use fastvault_core::error::{FastVaultError, Result};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        crate::server::AgentServer::default_socket_path()
    }

    pub async fn send_request(&self, req: AgentRequest) -> Result<AgentResponse> {
        if !self.socket_path.exists() {
            return Err(FastVaultError::AgentSessionError(
                "FastVault agent is not running".to_string(),
            ));
        }

        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            FastVaultError::AgentSessionError(format!("Failed to connect to agent: {}", e))
        })?;

        let req_bytes = serde_json::to_vec(&req)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        let len_bytes = (req_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&req_bytes).await?;

        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        let resp: AgentResponse = serde_json::from_slice(&resp_buf)
            .map_err(|e| FastVaultError::SerializationError(e.to_string()))?;

        Ok(resp)
    }
}
