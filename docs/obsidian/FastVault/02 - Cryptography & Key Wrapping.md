# 02 - Cryptography & Key Wrapping
#fastvault #cryptography #argon2id #aes-gcm #zeroize

Back link: [[00 - FastVault Index]]

FastVault uses a versioned DEK/KEK key-wrapping architecture.

## 🔐 Key Hierarchy Diagram

```
Master Password + Random Salt (32B)
            │
            ▼ (Argon2id KDF: m=64MB, t=3, p=4)
Key Encryption Key (KEK, 256-bit)
            │
            ▼ (AES-256-GCM Encrypt with AAD "DEK_WRAPPING")
Wrapped Data Encryption Key (Wrapped DEK)
            │
            ▼ (Unwrap with KEK)
Data Encryption Key (DEK, 256-bit random)
            │
            ▼ (AES-256-GCM Encrypt with AAD = Vault UUID)
Encrypted Vault Payload (Bincode serialized secrets)
```

## ⚙️ Cryptographic Primitives

| Operation | Algorithm | Parameters |
| :--- | :--- | :--- |
| **KDF** | Argon2id | $m=65536$ (64MB), $t=3$ iterations, $p=4$ parallelism, 32B salt |
| **AEAD Encryption** | AES-256-GCM | 256-bit Key, 96-bit Nonce, 128-bit Auth Tag |
| **Audit Hash Chain** | HMAC-SHA256 | 256-bit Key, SHA-256 Digest |
| **Memory Safety** | Zeroize | Automatic zeroization of sensitive key buffers on drop |

### Key Advantage: Instant Password Change
Updating the Master Password (`fastvault passwd`) derives a new KEK and re-wraps the 32-byte DEK in `~45.1 ms` without re-encrypting the underlying vault payload.

Related Notes:
- [[03 - Threat Model & Security Boundaries]]
- [[04 - Vault Format & File Layout]]
