# FastVault

FastVault es una CLI en Rust para guardar secretos cifrados localmente y entregarlos a procesos sin escribirlos en un archivo `.env`. El repositorio está organizado como un workspace con CLI, núcleo, agente local y registro de auditoría.

```bash
git clone https://github.com/tatitoxt/fastvault.git && cd fastvault
cargo build --workspace
cargo run -p fastvault-cli -- --help
```

## Requisitos

- Rust y Cargo
- macOS o Linux para las funciones que usan sockets Unix

## Compilar y probar

Ejecutá la suite del workspace desde la raíz:

```bash
cargo test --workspace
```

Las pruebas cubren, entre otras cosas, el ciclo de vida del vault, el cambio de contraseña, el almacenamiento local, el agente y la verificación de la cadena de auditoría. Para ver los comandos disponibles en la CLI, ejecutá `cargo run -p fastvault-cli -- --help`.

El código usa Argon2id para derivación de claves y AES-256-GCM para cifrado. FastVault está en desarrollo y no cuenta con una auditoría de seguridad independiente; no lo uses como único resguardo de credenciales críticas.

## Documentación

- [Diseño criptográfico](docs/CRYPTOGRAPHY.md)
- [Modelo de amenazas](docs/THREAT_MODEL.md)
- [Formato del vault](docs/VAULT_FORMAT.md)

## Licencia

MIT o Apache-2.0, a elección. Ver [LICENSE-MIT](LICENSE-MIT) y [LICENSE-APACHE](LICENSE-APACHE).
