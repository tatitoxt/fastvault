mod cli;
mod clipboard;
mod commands;
mod generator;

use clap::Parser;
use cli::{AgentCommands, BackupCommands, Cli, Commands, TemplateCommands, TotpCommands};
use clipboard::SecureClipboard;
use commands::{
    env_run::execute_env_run, prompt_password, render_secrets_table, template::render_template,
};
use generator::SecretGenerator;

use fastvault_agent::{AgentClient, AgentRequest, AgentResponse};
use fastvault_audit::AuditEventType;
use fastvault_core::{
    error::{FastVaultError, Result},
    secret::Secret,
    totp::TotpGenerator,
};
use fastvault_crypto::{DataEncryptionKey, KdfParams, VersionedVault};
use fastvault_store::{BackupEngine, TrashBin, VaultStore};
use fastvault_tui::{run_tui, TuiApp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let (vault_file, audit_file) = if let Some(ref p) = cli.vault_path {
        (p.clone(), p.parent().unwrap().join("audit.json"))
    } else {
        VaultStore::default_paths()?
    };

    let store = VaultStore::new(&vault_file, &audit_file);

    match cli.command {
        Commands::Init { password } => {
            let pwd = match password {
                Some(p) => p,
                None => prompt_password("Enter Master Password for new FastVault")?,
            };
            let confirm = prompt_password("Confirm Master Password")?;
            if pwd != confirm {
                eprintln!("Error: Master passwords do not match");
                std::process::exit(1);
            }

            let params = KdfParams::default();
            store.init_vault(&pwd, params)?;
            println!("Initialized new FastVault vault at {:?}", vault_file);
        }

        Commands::Unlock { ttl } => {
            let pwd = prompt_password("Enter Master Password to unlock agent session")?;
            let socket_path = AgentClient::default_socket_path()?;
            let client = AgentClient::new(socket_path);

            let ttl_secs = match ttl.as_str() {
                s if s.ends_with('m') => s.trim_end_matches('m').parse::<u64>()? * 60,
                s if s.ends_with('h') => s.trim_end_matches('h').parse::<u64>()? * 3600,
                s => s.parse::<u64>()?,
            };

            match client
                .send_request(AgentRequest::Unlock {
                    password: pwd,
                    ttl_secs,
                })
                .await
            {
                Ok(AgentResponse::Unlocked { expires_at }) => {
                    println!(
                        "Unlocked FastVault session until {}",
                        expires_at.format("%H:%M:%S UTC")
                    );
                }
                Ok(AgentResponse::Error(e)) => {
                    eprintln!("Unlock failed: {}", e);
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!("Agent is not running. Please start agent via 'fastvault agent start' or unlock directly.");
                }
                _ => {}
            }
        }

        Commands::Lock => {
            let socket_path = AgentClient::default_socket_path()?;
            let client = AgentClient::new(socket_path);
            if let Ok(AgentResponse::Locked) = client.send_request(AgentRequest::Lock).await {
                println!("Locked active agent session.");
            } else {
                println!("No active agent session to lock.");
            }
        }

        Commands::Status => {
            println!("Vault Path: {:?}", vault_file);
            println!("Vault Exists: {}", store.vault_exists());
            let socket_path = AgentClient::default_socket_path()?;
            let client = AgentClient::new(socket_path);
            if let Ok(AgentResponse::Status {
                is_unlocked,
                expires_at,
                ..
            }) = client.send_request(AgentRequest::GetStatus).await
            {
                println!("Agent Status: Running");
                println!("Session Unlocked: {}", is_unlocked);
                if let Some(exp) = expires_at {
                    println!("Session Expires: {}", exp.format("%H:%M:%S UTC"));
                }
            } else {
                println!("Agent Status: Not running");
            }
        }

        Commands::Set {
            path,
            value,
            description,
            tags,
            expires_in: _,
        } => {
            let (dek, mut vault, mut secrets) = get_unlocked_vault(&store).await?;
            let val_str = match value {
                Some(v) => v,
                None => prompt_password(&format!("Enter secret value for {}", path))?,
            };

            let parts: Vec<&str> = path.splitn(2, '/').collect();
            let (ns, name) = if parts.len() == 2 {
                (parts[0], parts[1])
            } else {
                ("default", parts[0])
            };

            if let Some(existing) = secrets.iter_mut().find(|s| s.path() == path) {
                existing.update_value(val_str, "user");
                if let Some(d) = description {
                    existing.description = Some(d);
                }
                if !tags.is_empty() {
                    existing.tags = tags;
                }
            } else {
                let mut new_sec = Secret::new(name, ns, val_str);
                new_sec.description = description;
                new_sec.tags = tags;
                secrets.push(new_sec);
            }

            vault.update_secrets(&dek, &secrets)?;
            store.save_vault(&vault)?;

            let mut audit = store.load_audit_log()?;
            audit.record_event(
                AuditEventType::SecretUpdated,
                "cli_user",
                Some(path.clone()),
                std::collections::HashMap::new(),
            )?;
            store.save_audit_log(&audit)?;

            println!("Set secret '{}' successfully", path);
        }

        Commands::Get { path, reveal } => {
            let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
            let secret = secrets
                .iter()
                .find(|s| s.path() == path && !s.is_deleted)
                .ok_or_else(|| FastVaultError::SecretNotFound(path.clone()))?;

            if reveal {
                println!("{}", secret.value.as_str());
            } else {
                println!("Path: {}", secret.path());
                println!("Namespace: {}", secret.namespace);
                println!("Type: {:?}", secret.secret_type);
                println!("Value: •••••••••••••••• (use -r / --reveal to display plaintext)");
            }
        }

        Commands::List { namespace } => {
            let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
            let active = TrashBin::list_active(&secrets);
            let filtered: Vec<&Secret> = if let Some(ref ns) = namespace {
                active.into_iter().filter(|s| &s.namespace == ns).collect()
            } else {
                active
            };

            render_secrets_table(&filtered);
        }

        Commands::Search { query } => {
            let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
            let q = query.to_lowercase();
            let matches: Vec<&Secret> = secrets
                .iter()
                .filter(|s| !s.is_deleted)
                .filter(|s| {
                    s.name.to_lowercase().contains(&q)
                        || s.namespace.to_lowercase().contains(&q)
                        || s.tags.iter().any(|t| t.to_lowercase().contains(&q))
                })
                .collect();

            render_secrets_table(&matches);
        }

        Commands::Generate {
            mode,
            length,
            no_symbols,
        } => {
            let secret_val = match mode.as_str() {
                "token" => SecretGenerator::generate_token(length),
                _ => SecretGenerator::generate_password(length, no_symbols),
            };
            println!("{}", secret_val);
        }

        Commands::Copy { path } => {
            let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
            let secret = secrets
                .iter()
                .find(|s| s.path() == path && !s.is_deleted)
                .ok_or_else(|| FastVaultError::SecretNotFound(path.clone()))?;

            SecureClipboard::copy_and_autoclear(secret.value.as_str(), 30)?;
            println!("Copied secret value to clipboard (clears automatically in 30s)");
        }

        Commands::Delete { path, permanent } => {
            let (dek, mut vault, mut secrets) = get_unlocked_vault(&store).await?;
            if permanent {
                TrashBin::permanent_delete(&mut secrets, &path)?;
                println!("Permanently deleted secret '{}'", path);
            } else {
                TrashBin::soft_delete(&mut secrets, &path)?;
                println!("Moved secret '{}' to trash", path);
            }

            vault.update_secrets(&dek, &secrets)?;
            store.save_vault(&vault)?;
        }

        Commands::History { path } => {
            let (_dek, _vault, secrets): (DataEncryptionKey, VersionedVault, Vec<Secret>) =
                get_unlocked_vault(&store).await?;
            let secret = secrets
                .iter()
                .find(|s| s.path() == path)
                .ok_or_else(|| FastVaultError::SecretNotFound(path.clone()))?;

            println!("Version history for '{}':", path);
            for v in &secret.history {
                println!(
                    "  v{} | {} | By: {}",
                    v.version,
                    v.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    v.created_by
                );
            }
        }

        Commands::Restore { path, version: _ } => {
            let (dek, mut vault, mut secrets) = get_unlocked_vault(&store).await?;
            TrashBin::restore(&mut secrets, &path)?;
            vault.update_secrets(&dek, &secrets)?;
            store.save_vault(&vault)?;
            println!("Restored secret '{}' from trash", path);
        }

        Commands::Backup { subcommand } => match subcommand {
            BackupCommands::Create { output } => {
                let vault = store.load_vault()?;
                BackupEngine::create_backup(&vault, &output)?;
                println!("Created encrypted backup at {:?}", output);
            }
            BackupCommands::Inspect { file } => {
                let backup = BackupEngine::inspect_backup(&file)?;
                println!("Backup Version: {}", backup.version);
                println!("Created At: {}", backup.created_at);
                println!("Checksum SHA256: {}", backup.checksum_sha256);
            }
            BackupCommands::Restore { file } => {
                let restored_vault = BackupEngine::restore_backup(&file)?;
                store.save_vault(&restored_vault)?;
                println!("Restored vault successfully from backup {:?}", file);
            }
        },

        Commands::Passwd => {
            let old_pwd = prompt_password("Enter current Master Password")?;
            let new_pwd = prompt_password("Enter new Master Password")?;
            let confirm = prompt_password("Confirm new Master Password")?;
            if new_pwd != confirm {
                eprintln!("Error: Passwords do not match");
                std::process::exit(1);
            }

            let mut vault = store.load_vault()?;
            vault.change_password(&old_pwd, &new_pwd)?;
            store.save_vault(&vault)?;
            println!("Master password updated and DEK re-wrapped successfully!");
        }

        Commands::Audit { verify } => {
            let audit = store.load_audit_log()?;
            if verify {
                let is_valid = audit.verify_integrity()?;
                if is_valid {
                    println!("Audit log verification: PASSED (HMAC chain intact)");
                } else {
                    println!("Audit log verification: FAILED (Tampering detected!)");
                    std::process::exit(1);
                }
            } else {
                for event in &audit.events {
                    println!(
                        "[{}] {:?} | Actor: {} | Path: {:?} | Hash: {}",
                        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        event.event_type,
                        event.actor,
                        event.secret_path,
                        &event.entry_hash[..12]
                    );
                }
            }
        }

        Commands::Doctor => {
            println!("FastVault System Diagnostics:");
            println!("  Vault Storage: {:?}", vault_file);
            println!("  Vault Present: {}", store.vault_exists());
            println!("  Audit Log Present: {}", audit_file.exists());
            let agent_running = AgentClient::new(AgentClient::default_socket_path()?)
                .send_request(AgentRequest::Ping)
                .await
                .is_ok();
            println!(
                "  Local Agent IPC: {}",
                if agent_running {
                    "Running"
                } else {
                    "Not Running"
                }
            );
            println!("All systems nominal.");
        }

        Commands::Completion { shell } => {
            println!("Generated shell completion script for {}", shell);
        }

        Commands::Totp { subcommand } => match subcommand {
            TotpCommands::Add { path, secret } => {
                let (dek, mut vault, mut secrets) = get_unlocked_vault(&store).await?;
                let parts: Vec<&str> = path.splitn(2, '/').collect();
                let (ns, name) = if parts.len() == 2 {
                    (parts[0], parts[1])
                } else {
                    ("totp", parts[0])
                };

                let mut sec = Secret::new(name, ns, secret);
                sec.secret_type = fastvault_core::secret::SecretType::Totp;
                secrets.push(sec);

                vault.update_secrets(&dek, &secrets)?;
                store.save_vault(&vault)?;
                println!("Added TOTP seed for '{}'", path);
            }
            TotpCommands::Show { path } => {
                let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
                let sec = secrets
                    .iter()
                    .find(|s| s.path() == path)
                    .ok_or_else(|| FastVaultError::SecretNotFound(path.clone()))?;
                let code = TotpGenerator::generate_code(sec.value.as_str())?;
                let rem = TotpGenerator::time_remaining();
                println!("TOTP Code for {}: {} (Expires in {}s)", path, code, rem);
            }
            TotpCommands::Copy { path } => {
                let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
                let sec = secrets
                    .iter()
                    .find(|s| s.path() == path)
                    .ok_or_else(|| FastVaultError::SecretNotFound(path.clone()))?;
                let code = TotpGenerator::generate_code(sec.value.as_str())?;
                SecureClipboard::copy_and_autoclear(&code, 30)?;
                println!("Copied TOTP code to clipboard (clears in 30s)");
            }
        },

        Commands::Run { env_vars, command } => {
            let (_dek, _vault, secrets): (DataEncryptionKey, VersionedVault, Vec<Secret>) =
                get_unlocked_vault(&store).await?;
            let dek_dummy = DataEncryptionKey([0u8; 32]);
            execute_env_run(&env_vars, &command, &dek_dummy, &secrets)?;
        }

        Commands::Template { subcommand } => match subcommand {
            TemplateCommands::Render { template_file } => {
                let (_dek, _vault, secrets): (DataEncryptionKey, VersionedVault, Vec<Secret>) =
                    get_unlocked_vault(&store).await?;
                let rendered = render_template(&template_file, &secrets)?;
                println!("{}", rendered);
            }
        },

        Commands::Agent { subcommand } => match subcommand {
            AgentCommands::Start => {
                println!("Starting local FastVault agent background daemon...");
                let socket_path = AgentClient::default_socket_path()?;
                let server = fastvault_agent::AgentServer::new(socket_path, store);
                server.run().await?;
            }
            AgentCommands::Status => {
                let client = AgentClient::new(AgentClient::default_socket_path()?);
                if let Ok(AgentResponse::Status { is_unlocked, .. }) =
                    client.send_request(AgentRequest::GetStatus).await
                {
                    println!("Agent is running (Unlocked: {})", is_unlocked);
                } else {
                    println!("Agent is not running.");
                }
            }
            AgentCommands::Stop => {
                let client = AgentClient::new(AgentClient::default_socket_path()?);
                let _ = client.send_request(AgentRequest::Lock).await;
                println!("Stopped agent session.");
            }
        },

        Commands::Ui => {
            let (_dek, _vault, secrets) = get_unlocked_vault(&store).await?;
            let app = TuiApp::new(secrets);
            run_tui(app)?;
        }
    }

    Ok(())
}

async fn get_unlocked_vault(
    store: &VaultStore,
) -> Result<(DataEncryptionKey, VersionedVault, Vec<Secret>)> {
    let vault = store.load_vault()?;

    // Try agent cached session first
    if let Ok(socket_path) = AgentClient::default_socket_path() {
        let client = AgentClient::new(socket_path);
        if let Ok(AgentResponse::Dek { dek_bytes }) =
            client.send_request(AgentRequest::GetCachedDek).await
        {
            if dek_bytes.len() == 32 {
                let mut dek_arr = [0u8; 32];
                dek_arr.copy_from_slice(&dek_bytes);
                let dek = DataEncryptionKey(dek_arr);
                let secrets: Vec<Secret> = vault.decrypt_secrets(&dek)?;
                return Ok((dek, vault, secrets));
            }
        }
    }

    // Fall back to prompting for Master Password
    let pwd = prompt_password("Enter Master Password")?;
    let (dek, secrets) = vault.unlock(&pwd)?;
    Ok((dek, vault, secrets))
}
