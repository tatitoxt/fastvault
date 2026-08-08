# 06 - CLI & Agent Integration Guide
#fastvault #cli #agent #ipc #usage

Back link: [[00 - FastVault Index]]

## 🚀 Quick Command Reference

```bash
# Initialize vault
fastvault init

# Store and retrieve secrets
fastvault set prod/database "postgres://user:pass@localhost:5432/db"
fastvault get prod/database -r

# Copy secret value with 30s auto-clear worker
fastvault copy prod/database

# Process Secret Injection (Zero plaintext files on disk)
fastvault run --env DATABASE_URL=prod/database -- npm start

# Render secret templates
fastvault template render .env.template

# Local Agent Session
fastvault unlock --ttl 15m
fastvault status
fastvault lock

# Ratatui Terminal UI
fastvault ui
```

Related Notes:
- [[01 - Architecture & Design]]
- [[03 - Threat Model & Security Boundaries]]
