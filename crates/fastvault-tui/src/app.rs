use fastvault_core::secret::Secret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tab {
    Secrets,
    AuditLog,
    SyncStatus,
}

pub struct TuiApp {
    pub active_tab: Tab,
    pub secrets: Vec<Secret>,
    pub selected_index: usize,
    pub search_query: String,
    pub is_searching: bool,
    pub mask_secrets: bool,
    pub status_message: String,
    pub should_quit: bool,
}

impl TuiApp {
    pub fn new(secrets: Vec<Secret>) -> Self {
        Self {
            active_tab: Tab::Secrets,
            secrets,
            selected_index: 0,
            search_query: String::new(),
            is_searching: false,
            mask_secrets: true,
            status_message: "Press '?' for help | 'm' to toggle mask | 'q' to quit".to_string(),
            should_quit: false,
        }
    }

    pub fn filtered_secrets(&self) -> Vec<&Secret> {
        if self.search_query.is_empty() {
            self.secrets.iter().filter(|s| !s.is_deleted).collect()
        } else {
            let q = self.search_query.to_lowercase();
            self.secrets
                .iter()
                .filter(|s| !s.is_deleted)
                .filter(|s| {
                    s.name.to_lowercase().contains(&q) || s.namespace.to_lowercase().contains(&q)
                })
                .collect()
        }
    }

    pub fn selected_secret(&self) -> Option<&Secret> {
        let list = self.filtered_secrets();
        list.get(self.selected_index).copied()
    }

    pub fn next(&mut self) {
        let len = self.filtered_secrets().len();
        if len > 0 {
            self.selected_index = (self.selected_index + 1) % len;
        }
    }

    pub fn previous(&mut self) {
        let len = self.filtered_secrets().len();
        if len > 0 {
            if self.selected_index == 0 {
                self.selected_index = len - 1;
            } else {
                self.selected_index -= 1;
            }
        }
    }

    pub fn toggle_mask(&mut self) {
        self.mask_secrets = !self.mask_secrets;
        self.status_message = if self.mask_secrets {
            "Secret values masked".to_string()
        } else {
            "Secret values UNMASKED".to_string()
        };
    }
}
