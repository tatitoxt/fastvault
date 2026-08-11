use arboard::Clipboard;
use fastvault_core::error::{FastVaultError, Result};
use std::thread;
use std::time::Duration;

pub struct SecureClipboard;

impl SecureClipboard {
    pub fn copy_and_autoclear(content: &str, clear_after_secs: u64) -> Result<()> {
        let mut clipboard = Clipboard::new()
            .map_err(|e| FastVaultError::VaultError(format!("Clipboard error: {}", e)))?;

        clipboard
            .set_text(content.to_string())
            .map_err(|e| FastVaultError::VaultError(format!("Clipboard set error: {}", e)))?;

        let text_to_clear = content.to_string();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(clear_after_secs));
            if let Ok(mut cb) = Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    if current == text_to_clear {
                        let _ = cb.set_text("".to_string());
                    }
                }
            }
        });

        Ok(())
    }
}
