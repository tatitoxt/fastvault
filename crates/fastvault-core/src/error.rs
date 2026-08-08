use thiserror::Error;

#[derive(Error, Debug)]
pub enum FastVaultError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Authentication failed: invalid master password or MAC mismatch")]
    AuthenticationFailed,

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Secret already exists: {0}")]
    SecretAlreadyExists(String),

    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Audit log error: {0}")]
    AuditError(String),

    #[error("Sync conflict detected for secret {0} (remote rev: {1}, local rev: {2})")]
    SyncConflict(String, u64, u64),

    #[error("Agent session error: {0}")]
    AgentSessionError(String),

    #[error("Invalid TOTP configuration: {0}")]
    TotpError(String),
}

pub type Result<T> = std::result::Result<T, FastVaultError>;
