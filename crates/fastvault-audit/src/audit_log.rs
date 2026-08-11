use chrono::{DateTime, Utc};
use fastvault_core::error::{FastVaultError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventType {
    VaultCreated,
    VaultUnlocked,
    VaultLocked,
    SecretCreated,
    SecretRead,
    SecretUpdated,
    SecretDeleted,
    SecretRestored,
    MasterPasswordChanged,
    KeyRotated,
    SyncExecuted,
    BackupCreated,
    BackupRestored,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: String,
    pub secret_path: Option<String>,
    pub details: HashMap<String, String>,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub events: Vec<AuditEvent>,
    pub hmac_key: [u8; 32],
}

impl AuditLog {
    pub fn new(hmac_key: [u8; 32]) -> Self {
        Self {
            events: Vec::new(),
            hmac_key,
        }
    }

    pub fn last_hash(&self) -> String {
        self.events
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "GENESIS_HASH".to_string())
    }

    pub fn compute_hash(
        hmac_key: &[u8; 32],
        id: &Uuid,
        timestamp: &DateTime<Utc>,
        event_type: &AuditEventType,
        actor: &str,
        secret_path: Option<&str>,
        previous_hash: &str,
    ) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| FastVaultError::AuditError(e.to_string()))?;

        mac.update(previous_hash.as_bytes());
        mac.update(id.as_bytes());
        mac.update(timestamp.to_rfc3339().as_bytes());
        mac.update(format!("{:?}", event_type).as_bytes());
        mac.update(actor.as_bytes());
        if let Some(path) = secret_path {
            mac.update(path.as_bytes());
        }

        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    pub fn record_event(
        &mut self,
        event_type: AuditEventType,
        actor: impl Into<String>,
        secret_path: Option<String>,
        details: HashMap<String, String>,
    ) -> Result<&AuditEvent> {
        let id = Uuid::new_v4();
        let timestamp = Utc::now();
        let previous_hash = self.last_hash();
        let actor_str = actor.into();

        let entry_hash = Self::compute_hash(
            &self.hmac_key,
            &id,
            &timestamp,
            &event_type,
            &actor_str,
            secret_path.as_deref(),
            &previous_hash,
        )?;

        let event = AuditEvent {
            id,
            timestamp,
            event_type,
            actor: actor_str,
            secret_path,
            details,
            previous_hash,
            entry_hash,
        };

        self.events.push(event);
        Ok(self.events.last().unwrap())
    }

    pub fn verify_integrity(&self) -> Result<bool> {
        let mut expected_previous = "GENESIS_HASH".to_string();

        for event in &self.events {
            if event.previous_hash != expected_previous {
                return Ok(false);
            }

            let recomputed = Self::compute_hash(
                &self.hmac_key,
                &event.id,
                &event.timestamp,
                &event.event_type,
                &event.actor,
                event.secret_path.as_deref(),
                &event.previous_hash,
            )?;

            if recomputed != event.entry_hash {
                return Ok(false);
            }

            expected_previous = event.entry_hash.clone();
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hash_chain_verification() {
        let key = [7u8; 32];
        let mut log = AuditLog::new(key);

        log.record_event(
            AuditEventType::VaultUnlocked,
            "fausto",
            None,
            HashMap::new(),
        )
        .unwrap();

        log.record_event(
            AuditEventType::SecretCreated,
            "fausto",
            Some("prod/db_pass".to_string()),
            HashMap::new(),
        )
        .unwrap();

        assert!(log.verify_integrity().unwrap());

        // Tamper test
        if let Some(event) = log.events.get_mut(1) {
            event.actor = "malicious_user".to_string();
        }

        assert!(!log.verify_integrity().unwrap());
    }
}
