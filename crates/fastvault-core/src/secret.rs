use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected sensitive string that zeroizes memory on drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(pub String);

impl SecretValue {
    pub fn new(val: impl Into<String>) -> Self {
        Self(val.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretValue {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SecretType {
    #[default]
    Generic,
    Password,
    ApiKey,
    Token,
    SshKey,
    Database,
    EnvVar,
    SecureNote,
    Totp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretVersion {
    pub version: u32,
    pub value: SecretValue,
    pub timestamp: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Secret {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub secret_type: SecretType,
    pub value: SecretValue,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub version: u32,
    pub history: Vec<SecretVersion>,
    pub is_deleted: bool,
}

impl Secret {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        value: impl Into<SecretValue>,
    ) -> Self {
        let now = Utc::now();
        let val = value.into();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            namespace: namespace.into(),
            secret_type: SecretType::Generic,
            value: val.clone(),
            description: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
            created_at: now,
            updated_at: now,
            expires_at: None,
            version: 1,
            history: vec![SecretVersion {
                version: 1,
                value: val,
                timestamp: now,
                created_by: "system".to_string(),
            }],
            is_deleted: false,
        }
    }

    pub fn update_value(
        &mut self,
        new_value: impl Into<SecretValue>,
        updated_by: impl Into<String>,
    ) {
        let val = new_value.into();
        self.version += 1;
        self.updated_at = Utc::now();
        self.history.push(SecretVersion {
            version: self.version,
            value: val.clone(),
            timestamp: self.updated_at,
            created_by: updated_by.into(),
        });
        self.value = val;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn path(&self) -> String {
        if self.namespace.is_empty() || self.namespace == "default" {
            self.name.clone()
        } else {
            format!("{}/{}", self.namespace, self.name)
        }
    }
}
