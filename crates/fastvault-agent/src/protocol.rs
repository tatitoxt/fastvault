use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRequest {
    Ping,
    Unlock { password: String, ttl_secs: u64 },
    Lock,
    GetStatus,
    GetCachedDek,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResponse {
    Pong,
    Unlocked {
        expires_at: DateTime<Utc>,
    },
    Locked,
    Status {
        is_unlocked: bool,
        expires_at: Option<DateTime<Utc>>,
        ttl_secs: u64,
    },
    Dek {
        dek_bytes: Vec<u8>,
    },
    Error(String),
}
