# FastVault File Format Specification (`.fvt`)

FastVault uses a binary envelope format serialized via Bincode and authenticated via AES-256-GCM AEAD.

## Binary Structure Layout

```
+-----------------------------------------------------------------------+
| Vault Header                                                          |
|  - Magic Bytes: "FASTVALT" (8 bytes)                                  |
|  - Format Version: u32 (1)                                            |
|  - Vault UUID: 16-byte UUID v4                                        |
|  - KDF Params: m_cost (u32), t_cost (u32), p_cost (u32), len (usize)  |
|  - KDF Salt: 32 bytes random salt                                     |
|  - Wrapped DEK:                                                       |
|      * Encrypted Key Bytes (32B ciphertext + 16B GCM Tag)              |
|      * Nonce: 12-byte random nonce                                    |
+-----------------------------------------------------------------------+
| Payload Nonce: 12-byte random nonce                                   |
+-----------------------------------------------------------------------+
| Encrypted Payload: AES-256-GCM Ciphertext + 16-byte Auth Tag         |
| (Bincode serialized Vec<Secret>)                                      |
+-----------------------------------------------------------------------+
```

## AAD Binding Rules
- **DEK Wrapping AAD**: `b"DEK_WRAPPING"`
- **Vault Payload AAD**: 16-byte raw UUID bytes of `vault_id` from header.
This binds payload ciphertexts strictly to their unique vault identity, preventing mix-and-match replay attacks across different vaults.
