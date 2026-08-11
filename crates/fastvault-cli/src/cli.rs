use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "fastvault",
    author = "Fausto Pastura",
    version = "0.1.0",
    about = "High-performance, local-first secrets manager in Rust"
)]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub vault_path: Option<PathBuf>,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new FastVault vault
    Init {
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Unlock vault session in local agent
    Unlock {
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
    /// Lock active vault agent session
    Lock,
    /// Display vault status and session info
    Status,
    /// Store or update a secret
    Set {
        /// Secret path (e.g., prod/database or api_key)
        path: String,
        /// Secret value (if omitted, prompt interactively or read stdin)
        value: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(short, long)]
        tags: Vec<String>,
        #[arg(short, long)]
        expires_in: Option<String>,
    },
    /// Retrieve a secret value
    Get {
        path: String,
        #[arg(short, long)]
        reveal: bool,
    },
    /// Delete a secret (soft delete by default)
    Delete {
        path: String,
        #[arg(long)]
        permanent: bool,
    },
    /// List all secrets in vault
    List {
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Search secrets by name, tag, or namespace
    Search { query: String },
    /// Cryptographically generate password or token
    Generate {
        #[arg(default_value = "password")]
        mode: String,
        #[arg(short, long, default_value_t = 24)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
    /// Copy secret value to clipboard with auto-clear
    Copy { path: String },
    /// View secret version history
    History { path: String },
    /// Restore secret to previous version or from trash
    Restore {
        path: String,
        #[arg(short, long)]
        version: Option<u32>,
    },
    /// Manage encrypted backups
    Backup {
        #[command(subcommand)]
        subcommand: BackupCommands,
    },
    /// Rotate master password or key material
    Passwd,
    /// Inspect audit trail
    Audit {
        #[arg(long)]
        verify: bool,
    },
    /// Run diagnostic checks on system and vault
    Doctor,
    /// Generate shell autocompletion script
    Completion { shell: String },
    /// TOTP multi-factor code commands
    Totp {
        #[command(subcommand)]
        subcommand: TotpCommands,
    },
    /// Run a process with injected secret environment variables
    Run {
        /// Environment mappings (e.g., --env DB_URL=prod/database)
        #[arg(short, long = "env", value_name = "KEY=PATH")]
        env_vars: Vec<String>,
        /// Command to execute
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Render template files containing {{fastvault:path}}
    Template {
        #[command(subcommand)]
        subcommand: TemplateCommands,
    },
    /// Local background agent management
    Agent {
        #[command(subcommand)]
        subcommand: AgentCommands,
    },
    /// Launch interactive Ratatui terminal UI
    Ui,
}

#[derive(Subcommand, Debug)]
pub enum BackupCommands {
    Create { output: PathBuf },
    Inspect { file: PathBuf },
    Restore { file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum TotpCommands {
    Add { path: String, secret: String },
    Show { path: String },
    Copy { path: String },
}

#[derive(Subcommand, Debug)]
pub enum TemplateCommands {
    Render { template_file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum AgentCommands {
    Start,
    Status,
    Stop,
}
