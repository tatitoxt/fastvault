# FastVault Cryptographic Specification

FastVault employs a versioned, multi-layered key-wrapping hierarchy utilizing audited, industry-standard cryptographic primitives.

## 1. Cryptographic Primitives

| Purpose | Algorithm / Primitive | Crate / Implementation | Parameters |
| :--- | :--- | :--- | :--- |
| Key Derivation (KDF) | **Argon2id** (RFC 9106) | `argon2` v0.5 | `m=65536` (64MB), `t=3`, `p=4`, `salt_len=32B` |
| Symmetric Encryption | **AES-256-GCM** (NIST SP 800-38D) | `aes-gcm` v0.10 | 256-bit Key, 96-bit Nonce, 128-bit Tag |
| Tamper-Evident Audit | **HMAC-SHA256** | `hmac` + `sha2` | 256-bit Key, SHA-256 Digest |
| Randomness | Cryptographically Secure PRNG | `rand` / `getrandom` | System OS entropy source |

## 2. Key Hierarchy Architecture

```
Master Password + Random Salt (32B)
            │
            ▼ (Argon2id KDF)
Key Encryption Key (KEK, 256-bit)
            │
            ▼ (AES-256-GCM Encrypt with AAD "DEK_WRAPPING")
Wrapped Data Encryption Key (Wrapped DEK)
            │
            ▼ (Unwrap with KEK)
Data Encryption Key (DEK, 256-bit random)
            │
            ▼ (AES-256-GCM Encrypt with AAD = Vault UUID)
Encrypted Vault Payload (Bincode serialized Secrets)
```

### Key Wrapping Benefits
1. **Instant Password Changes**: Changing the master password only requires deriving a new KEK and re-wrapping the 32-byte DEK. The underlying encrypted secrets payload does not need to be decrypted and re-encrypted.
2. **Key Isolation**: Sensitive records are always encrypted with a cryptographically uniform random DEK rather than a direct KDF output.

## 3. Memory Hygiene & Zeroization

All sensitive buffers (master passwords, derived KEKs, unwrapped DEKs, secret values) utilize the `zeroize` crate with explicit `ZeroizeOnDrop` implementations. Upon dropping out of scope, application-owned heap and stack memory allocated for sensitive buffers are overwritten with zeros.

*Limitation Notice*: Operating system swap files, compiler optimizations, kernel memory caching, or cold-boot hardware attacks are outside the scope of user-space memory zeroization guarantees.
