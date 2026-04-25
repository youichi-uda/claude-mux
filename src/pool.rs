use crate::config::{AccountConfig, Config};
use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

// Mirrors the constants embedded in the official `claude` binary
// (cli-wrapper.cjs / native build):
//   TOKEN_URL  = https://platform.claude.com/v1/oauth/token
//   CLIENT_ID  = 9d1c250a-e61b-44d9-88ed-5944d1962f5e
//   max scopes = user:profile user:inference user:sessions:claude_code
//                user:mcp_servers user:file_upload
const TOKEN_REFRESH_URL: &str = "https://platform.claude.com/v1/oauth/token";
const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const MAX_SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
];
const REFRESH_MARGIN_MS: u64 = 5 * 60 * 1000; // 5 minutes before expiry

#[derive(Debug)]
pub struct Account {
    pub name: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64, // epoch ms
    pub scopes: Vec<String>,
    pub cooldown_until: u64, // epoch ms — 0 = not rate limited
    pub request_count: u64,
    pub rate_limit_count: u64,
}

impl Account {
    fn from_config(cfg: &AccountConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            access_token: cfg.access_token.clone(),
            refresh_token: cfg.refresh_token.clone(),
            expires_at: cfg.expires_at,
            scopes: cfg.scopes.clone(),
            cooldown_until: 0,
            request_count: 0,
            rate_limit_count: 0,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    pub fn is_token_expired(&self) -> bool {
        Self::now_ms() >= self.expires_at.saturating_sub(REFRESH_MARGIN_MS)
    }

    pub fn is_available(&self) -> bool {
        Self::now_ms() >= self.cooldown_until
    }
}

#[derive(Debug)]
pub struct AccountPool {
    pub accounts: RwLock<Vec<Account>>,
    /// One mutex per account, used to serialize OAuth refresh calls.
    /// Anthropic rotates `refresh_token` on every successful refresh —
    /// concurrent refreshes for the same account would race, with one of them
    /// hitting `invalid_grant` because the second call uses an already-rotated
    /// refresh_token. The lock guarantees only one in-flight refresh per
    /// account; subsequent callers re-check whether the access_token has
    /// already been updated and skip a redundant refresh.
    refresh_locks: Vec<Arc<Mutex<()>>>,
    current_index: RwLock<usize>,
    http_client: reqwest::Client,
}

impl AccountPool {
    pub fn new(configs: &[AccountConfig]) -> Arc<Self> {
        let accounts: Vec<Account> = configs.iter().map(Account::from_config).collect();
        let refresh_locks: Vec<Arc<Mutex<()>>> =
            (0..accounts.len()).map(|_| Arc::new(Mutex::new(()))).collect();
        info!(
            "Account pool initialized with {} accounts: {:?}",
            accounts.len(),
            accounts.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
        Arc::new(Self {
            accounts: RwLock::new(accounts),
            refresh_locks,
            current_index: RwLock::new(0),
            http_client: reqwest::Client::new(),
        })
    }

    /// Pick the best available account. Returns (index, access_token).
    /// Uses round-robin among available accounts.
    pub async fn pick(&self) -> Option<(usize, String)> {
        let accounts = self.accounts.read().await;
        let n = accounts.len();
        if n == 0 {
            return None;
        }

        let current = *self.current_index.read().await;

        // First pass: find an available, non-expired account starting from current
        for offset in 0..n {
            let idx = (current + offset) % n;
            let acct = &accounts[idx];
            if acct.is_available() && !acct.is_token_expired() {
                drop(accounts);
                *self.current_index.write().await = (idx + 1) % n;
                let accounts = self.accounts.read().await;
                return Some((idx, accounts[idx].access_token.clone()));
            }
        }

        // (Auto-refresh of expired tokens disabled: the only refresh endpoint
        // we know of mints Console API tokens, which break Max subscription
        // accounts. Use the existing access token even past its expires_at —
        // it usually still works because subscription tokens are long-lived.)

        // Final pass: all on cooldown, pick the one that recovers soonest
        let (best_idx, token) = {
            let accounts = self.accounts.read().await;
            let mut best_idx = 0;
            let mut best_cooldown = u64::MAX;
            for (i, acct) in accounts.iter().enumerate() {
                if acct.cooldown_until < best_cooldown {
                    best_cooldown = acct.cooldown_until;
                    best_idx = i;
                }
            }
            (best_idx, accounts[best_idx].access_token.clone())
        };
        Some((best_idx, token))
    }

    /// Pick the next account, excluding a specific index.
    pub async fn pick_excluding(&self, exclude: usize) -> Option<(usize, String)> {
        let accounts = self.accounts.read().await;
        let n = accounts.len();
        if n <= 1 {
            return None;
        }

        let current = *self.current_index.read().await;

        for offset in 0..n {
            let idx = (current + offset) % n;
            if idx == exclude {
                continue;
            }
            let acct = &accounts[idx];
            if acct.is_available() && !acct.is_token_expired() {
                let token = acct.access_token.clone();
                drop(accounts);
                *self.current_index.write().await = (idx + 1) % n;
                return Some((idx, token));
            }
        }

        None
    }

    /// Mark an account as rate-limited with a cooldown period.
    pub async fn mark_rate_limited(&self, index: usize, cooldown_seconds: u64) {
        let mut accounts = self.accounts.write().await;
        if let Some(acct) = accounts.get_mut(index) {
            acct.cooldown_until = Account::now_ms() + cooldown_seconds * 1000;
            acct.rate_limit_count += 1;
            warn!(
                "[{}] rate limited — cooldown {}s (total: {} times)",
                acct.name, cooldown_seconds, acct.rate_limit_count
            );
        }
    }

    /// Increment request count for an account.
    pub async fn record_request(&self, index: usize) {
        let mut accounts = self.accounts.write().await;
        if let Some(acct) = accounts.get_mut(index) {
            acct.request_count += 1;
        }
    }

    /// Refresh the OAuth access token for an account.
    /// Mirrors the request format used by the official `claude` binary:
    ///   POST https://platform.claude.com/v1/oauth/token
    ///   Content-Type: application/json
    ///   { grant_type, refresh_token, client_id, scope }
    /// `scope` is critical — it determines whether the response is a Max
    /// subscription token or a Console API token. Always pass the existing
    /// account scopes (or the Max default if the stored scopes are empty).
    pub async fn refresh_token(&self, index: usize) -> Result<()> {
        self.refresh_token_inner(index, None).await
    }

    /// Refresh only if the current `access_token` still matches the snapshot.
    /// Use this from the proxy's 401 path so concurrent 401s on the same
    /// account don't double-refresh and burn the rotated refresh_token.
    pub async fn refresh_if_token_matches(
        &self,
        index: usize,
        snapshot_access_token: &str,
    ) -> Result<()> {
        self.refresh_token_inner(index, Some(snapshot_access_token.to_string()))
            .await
    }

    async fn refresh_token_inner(&self, index: usize, expected: Option<String>) -> Result<()> {
        // Serialize refreshes for this account to avoid `invalid_grant` when
        // two concurrent callers try to use the same (one-time-use) refresh_token.
        let lock = self.refresh_locks[index].clone();
        let _guard = lock.lock().await;

        // After acquiring the lock, re-check: another concurrent caller may
        // have just refreshed. If our caller's snapshot no longer matches the
        // stored access_token, skip — the new token is what they need.
        if let Some(snapshot) = &expected {
            let (current, name) = {
                let accounts = self.accounts.read().await;
                (
                    accounts[index].access_token.clone(),
                    accounts[index].name.clone(),
                )
            };
            if &current != snapshot {
                info!(
                    "[{}] Refresh skipped — token already updated by a concurrent request",
                    name
                );
                return Ok(());
            }
        }

        let (refresh_token, name, scopes) = {
            let accounts = self.accounts.read().await;
            let a = &accounts[index];
            (a.refresh_token.clone(), a.name.clone(), a.scopes.clone())
        };

        let scope = if scopes.is_empty() {
            MAX_SCOPES.join(" ")
        } else {
            scopes.join(" ")
        };

        info!("[{}] Refreshing access token (scope={})...", name, scope);

        let resp = self
            .http_client
            .post(TOKEN_REFRESH_URL)
            .json(&serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OAUTH_CLIENT_ID,
                "scope": scope,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "[{}] Token refresh failed: {} {}",
                name,
                status,
                &body[..body.len().min(200)]
            );
        }

        let data: serde_json::Value = resp.json().await?;
        let new_access = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access_token in refresh response"))?;
        let new_refresh = data["refresh_token"].as_str().unwrap_or(&refresh_token);
        // Claude Code uses Date.now() + expires_in*1000 — there's no expires_at
        // in the response.
        let new_expires = data["expires_in"]
            .as_u64()
            .map(|secs| Account::now_ms() + secs * 1000)
            .or_else(|| data["expires_at"].as_u64())
            .unwrap_or_else(|| Account::now_ms() + 3_600_000);
        let new_scopes: Vec<String> = data["scope"]
            .as_str()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_else(|| scopes.clone());

        {
            let mut accounts = self.accounts.write().await;
            let acct = &mut accounts[index];
            acct.access_token = new_access.to_string();
            acct.refresh_token = new_refresh.to_string();
            acct.expires_at = new_expires;
            acct.scopes = new_scopes.clone();
        }

        // Persist to config file
        let _ = Config::update_account_tokens(
            &Config::path(),
            &name,
            new_access,
            new_refresh,
            new_expires,
            &new_scopes,
        );

        info!("[{}] Token refreshed successfully", name);
        Ok(())
    }

    /// Get status summary of all accounts.
    pub async fn status(&self) -> Vec<AccountStatus> {
        let accounts = self.accounts.read().await;
        let now = Account::now_ms();
        accounts
            .iter()
            .map(|a| AccountStatus {
                name: a.name.clone(),
                available: a.is_available(),
                token_expired: a.is_token_expired(),
                cooldown_remaining_sec: if a.cooldown_until > now {
                    (a.cooldown_until - now) / 1000
                } else {
                    0
                },
                request_count: a.request_count,
                rate_limit_count: a.rate_limit_count,
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct AccountStatus {
    pub name: String,
    pub available: bool,
    pub token_expired: bool,
    pub cooldown_remaining_sec: u64,
    pub request_count: u64,
    pub rate_limit_count: u64,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if !self.available {
            format!("COOLDOWN ({}s)", self.cooldown_remaining_sec)
        } else if self.token_expired {
            "EXPIRED".to_string()
        } else {
            "READY".to_string()
        };
        write!(
            f,
            "{:<15} {:<20} reqs: {:<6} 429s: {}",
            self.name, status, self.request_count, self.rate_limit_count
        )
    }
}
