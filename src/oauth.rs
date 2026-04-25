use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// Mirrors the constants embedded in the official `claude` binary:
//   CLAUDE_AI_AUTHORIZE_URL = https://claude.com/cai/oauth/authorize
//   TOKEN_URL               = https://platform.claude.com/v1/oauth/token
//   MANUAL_REDIRECT_URL     = https://platform.claude.com/oauth/code/callback
//   CLIENT_ID               = 9d1c250a-e61b-44d9-88ed-5944d1962f5e
// Scopes for a Max subscription (`XP_` in the binary):
//   user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload
const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";
const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
const SCOPES: &str =
    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        Self { verifier, challenge }
    }
}

pub fn build_authorize_url(pkce: &PkcePair) -> String {
    let mut url = reqwest::Url::parse(AUTHORIZE_URL).expect("authorize URL is valid");
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", SCOPES)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &pkce.verifier);
    url.to_string()
}

pub struct OauthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

pub async fn exchange_code(code_input: &str, pkce: &PkcePair) -> Result<OauthTokens> {
    let trimmed = code_input.trim();
    let (code, state) = match trimmed.split_once('#') {
        Some((c, s)) => (c.to_string(), s.to_string()),
        None => (trimmed.to_string(), pkce.verifier.clone()),
    };

    let resp = reqwest::Client::new()
        .post(TOKEN_URL)
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "state": state,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": pkce.verifier,
        }))
        .send()
        .await
        .context("Failed to reach token endpoint")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Token exchange failed: {} {}",
            status,
            &body[..body.len().min(500)]
        );
    }

    let data: serde_json::Value = resp.json().await?;

    let access_token = data["access_token"]
        .as_str()
        .context("No access_token in token response")?
        .to_string();
    let refresh_token = data["refresh_token"]
        .as_str()
        .context("No refresh_token in token response")?
        .to_string();

    let expires_at = data["expires_at"]
        .as_u64()
        .or_else(|| {
            data["expires_in"].as_u64().map(|secs| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                now + secs * 1000
            })
        })
        .unwrap_or(0);

    let scopes = data["scope"]
        .as_str()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    Ok(OauthTokens {
        access_token,
        refresh_token,
        expires_at,
        scopes,
    })
}

/// Verify that an access token can actually talk to the Anthropic API.
/// Uses POST /v1/messages/count_tokens — cheap and authenticated.
pub async fn check_token(access_token: &str) -> Result<()> {
    let resp = reqwest::Client::new()
        .post("https://api.anthropic.com/v1/messages/count_tokens")
        .header("authorization", format!("Bearer {}", access_token))
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "model": "claude-haiku-4-5-20251001",
            "messages": [{"role": "user", "content": "ping"}]
        }))
        .send()
        .await
        .context("network error")?;

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }

    let body = resp.text().await.unwrap_or_default();
    let snippet = body.chars().take(200).collect::<String>();
    anyhow::bail!("HTTP {} — {}", status.as_u16(), snippet)
}
