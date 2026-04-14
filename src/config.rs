use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub accounts: Vec<AccountConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    pub name: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: ListenConfig {
                host: "127.0.0.1".to_string(),
                port: 8119,
            },
            accounts: vec![],
        }
    }
}

impl Config {
    pub fn dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".claude-mux")
    }

    pub fn path() -> PathBuf {
        Self::dir().join("config.json")
    }

    pub fn ca_cert_path() -> PathBuf {
        Self::dir().join("ca-cert.pem")
    }

    pub fn ca_key_path() -> PathBuf {
        Self::dir().join("ca-key.pem")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        serde_json::from_str(&contents).context("Failed to parse config")
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::dir();
        std::fs::create_dir_all(&dir)?;
        let path = Self::path();
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }

    pub fn add_account(&mut self, account: AccountConfig) {
        // Replace if same name exists
        self.accounts.retain(|a| a.name != account.name);
        self.accounts.push(account);
    }

    pub fn update_account_tokens(
        path: &Path,
        name: &str,
        access_token: &str,
        refresh_token: &str,
        expires_at: u64,
    ) -> Result<()> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&contents)?;
        if let Some(acct) = config.accounts.iter_mut().find(|a| a.name == name) {
            acct.access_token = access_token.to_string();
            acct.refresh_token = refresh_token.to_string();
            acct.expires_at = expires_at;
        }
        let contents = serde_json::to_string_pretty(&config)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}
