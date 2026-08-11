pub mod env_run;
pub mod template;

use comfy_table::{Cell, Color, Table};
use fastvault_core::error::{FastVaultError, Result};
use fastvault_core::secret::Secret;

pub fn prompt_password(prompt: &str) -> Result<String> {
    dialoguer::Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| FastVaultError::VaultError(e.to_string()))
}

pub fn render_secrets_table(secrets: &[&Secret]) {
    let mut table = Table::new();
    table.set_header(vec!["Namespace", "Name", "Type", "Version", "Updated"]);

    for s in secrets {
        table.add_row(vec![
            Cell::new(&s.namespace).fg(Color::Cyan),
            Cell::new(&s.name).fg(Color::Green),
            Cell::new(format!("{:?}", s.secret_type)),
            Cell::new(s.version.to_string()),
            Cell::new(s.updated_at.format("%Y-%m-%d %H:%M").to_string()),
        ]);
    }

    println!("{}", table);
}
