mod cert;
mod config;
mod oauth;
mod pool;
mod proxy;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::{AccountConfig, Config};
use pool::AccountPool;
use proxy::ProxyServer;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "claude-mux",
    about = "Transparent multi-account proxy for Claude Code Max subscriptions",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// One-time setup: generate CA cert and trust it
    Setup,

    /// Add a Claude Max account from current Claude Code credentials
    Add {
        /// Account name (e.g., "personal", "work1", "work2")
        name: String,
    },

    /// Log in to a Claude Max account via OAuth (no `claude` CLI needed)
    Login {
        /// Account name (e.g., "personal", "work1", "work2")
        name: String,
    },

    /// Import credentials directly with tokens
    Import {
        /// Account name
        name: String,
        /// Access token
        #[arg(long)]
        access_token: String,
        /// Refresh token
        #[arg(long)]
        refresh_token: String,
        /// Token expiry (epoch ms)
        #[arg(long, default_value = "0")]
        expires_at: u64,
    },

    /// Start the proxy server
    Start {
        /// Listen port
        #[arg(short, long, default_value = "8119")]
        port: u16,
    },

    /// Show account status (with live API connectivity check)
    Status,

    /// Refresh OAuth access tokens to verify renewal works
    Renew {
        /// Account name (omit to refresh all accounts)
        name: Option<String>,
    },

    /// Print the CA certificate path (for manual trust)
    CaPath,

    /// Print environment variables to set for Claude Code
    Env,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "claude_mux=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => cmd_setup().await,
        Commands::Add { name } => cmd_add(&name).await,
        Commands::Login { name } => cmd_login(&name).await,
        Commands::Import {
            name,
            access_token,
            refresh_token,
            expires_at,
        } => cmd_import(&name, &access_token, &refresh_token, expires_at).await,
        Commands::Start { port } => cmd_start(port).await,
        Commands::Status => cmd_status().await,
        Commands::Renew { name } => cmd_renew(name.as_deref()).await,
        Commands::CaPath => cmd_ca_path(),
        Commands::Env => cmd_env(),
    }
}

async fn cmd_setup() -> Result<()> {
    let config_dir = Config::dir();
    std::fs::create_dir_all(&config_dir)?;

    // Generate CA certificate
    cert::ensure_ca(&Config::ca_cert_path(), &Config::ca_key_path())?;
    println!("CA certificate generated at: {}", Config::ca_cert_path().display());

    // Create default config if it doesn't exist
    if !Config::path().exists() {
        Config::default().save()?;
        println!("Config created at: {}", Config::path().display());
    }

    // Trust CA in macOS Keychain
    println!("\nInstalling CA certificate to system keychain...");
    println!("You may be prompted for your password.\n");

    let status = std::process::Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            Config::ca_cert_path().to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("CA certificate trusted successfully!");
        }
        _ => {
            println!("Failed to auto-trust CA. You can manually trust it:");
            println!("  sudo security add-trusted-cert -d -r trustRoot \\");
            println!("    -k /Library/Keychains/System.keychain \\");
            println!("    {}", Config::ca_cert_path().display());
        }
    }

    println!("\nSetup complete! Next steps:");
    println!("  1. Add accounts:  claude-mux add account1");
    println!("  2. Start proxy:   claude-mux start");
    println!("  3. Launch Claude:  HTTPS_PROXY=http://127.0.0.1:8119 claude");

    Ok(())
}

async fn cmd_add(name: &str) -> Result<()> {
    // Read credentials from macOS Keychain
    let output = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s", "Claude Code-credentials",
            "-w",
        ])
        .output()
        .context("Failed to read keychain")?;

    if !output.status.success() {
        anyhow::bail!(
            "No Claude Code credentials found in keychain. \
             Make sure you're logged in with `claude` first."
        );
    }

    let creds_json = String::from_utf8(output.stdout)?.trim().to_string();
    let creds: serde_json::Value = serde_json::from_str(&creds_json)
        .context("Failed to parse keychain credentials")?;

    let oauth = creds
        .get("claudeAiOauth")
        .ok_or_else(|| anyhow::anyhow!("No OAuth credentials found"))?;

    let account = AccountConfig {
        name: name.to_string(),
        access_token: oauth["accessToken"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token"))?
            .to_string(),
        refresh_token: oauth["refreshToken"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No refresh token"))?
            .to_string(),
        expires_at: oauth["expiresAt"].as_u64().unwrap_or(0),
        scopes: oauth["scopes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    };

    let mut config = Config::load()?;
    config.add_account(account);
    config.save()?;

    println!("Account '{}' added successfully!", name);
    println!(
        "Total accounts: {}",
        config.accounts.len()
    );

    if config.accounts.len() >= 2 {
        println!("\nReady to start! Run: claude-mux start");
    } else {
        println!(
            "\nLog in to another account (`claude login`) then run: claude-mux add <name>"
        );
    }

    Ok(())
}

async fn cmd_login(name: &str) -> Result<()> {
    use std::io::Write;

    let pkce = oauth::PkcePair::generate();
    let url = oauth::build_authorize_url(&pkce);

    println!("To log in to a new Claude account, open this URL in your browser:\n");
    println!("  {}\n", url);
    println!(
        "TIP: To log in to a *different* Claude account without logging out\n\
         of your current browser session, open the URL in a Private/Incognito\n\
         window or a separate browser profile.\n"
    );

    // Best-effort: open the URL automatically (macOS).
    let _ = std::process::Command::new("open").arg(&url).status();

    print!("Paste the authorization code shown after login: ");
    std::io::stdout().flush()?;

    let mut code_input = String::new();
    std::io::stdin().read_line(&mut code_input)?;
    let code_input = code_input.trim();

    if code_input.is_empty() {
        anyhow::bail!("No authorization code entered.");
    }

    let tokens = oauth::exchange_code(code_input, &pkce)
        .await
        .context("Failed to exchange authorization code")?;

    let account = AccountConfig {
        name: name.to_string(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_at,
        scopes: tokens.scopes,
    };

    let mut config = Config::load()?;
    config.add_account(account);
    config.save()?;

    println!("\nAccount '{}' added successfully!", name);
    println!("Total accounts: {}", config.accounts.len());

    if config.accounts.len() >= 2 {
        println!("\nReady to start! Run: claude-mux start");
    } else {
        println!(
            "\nLog in to another account (in a Private window) with: \
             claude-mux login <name>"
        );
    }

    Ok(())
}

async fn cmd_import(
    name: &str,
    access_token: &str,
    refresh_token: &str,
    expires_at: u64,
) -> Result<()> {
    let account = AccountConfig {
        name: name.to_string(),
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        expires_at,
        scopes: vec![],
    };

    let mut config = Config::load()?;
    config.add_account(account);
    config.save()?;

    println!("Account '{}' imported successfully!", name);
    Ok(())
}

async fn cmd_start(port: u16) -> Result<()> {
    let config = Config::load()?;

    if config.accounts.is_empty() {
        anyhow::bail!(
            "No accounts configured. Add accounts first:\n  claude-mux add <name>"
        );
    }

    // Load CA cert
    let (ca_cert, ca_key) = cert::ensure_ca(&Config::ca_cert_path(), &Config::ca_key_path())?;

    // Create account pool
    let pool = AccountPool::new(&config.accounts);

    // Create proxy server
    let server = ProxyServer::new(pool.clone(), ca_cert, ca_key);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    println!("claude-mux proxy started on http://{}", addr);
    println!("Accounts loaded: {}", config.accounts.len());
    for acct in &config.accounts {
        println!("  - {}", acct.name);
    }
    println!();
    println!("Launch Claude Code with:");
    println!("  HTTPS_PROXY=http://127.0.0.1:{} \\", port);
    println!("  NODE_EXTRA_CA_CERTS={} \\", Config::ca_cert_path().display());
    println!("  claude");
    println!();

    // Spawn status printer
    let pool_status = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let statuses = pool_status.status().await;
            let total_reqs: u64 = statuses.iter().map(|s| s.request_count).sum();
            let total_429s: u64 = statuses.iter().map(|s| s.rate_limit_count).sum();
            if total_reqs > 0 {
                info!(
                    "Pool status — total reqs: {}, total 429s: {}, accounts: {}",
                    total_reqs,
                    total_429s,
                    statuses
                        .iter()
                        .map(|s| format!("{}({})", s.name, if !s.available { "cd" } else if s.token_expired { "exp" } else { "ok" }))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    });

    // Accept connections
    loop {
        let (stream, peer) = listener.accept().await?;
        let server = server.clone();

        tokio::spawn(async move {
            server.handle_connection(stream, peer).await;
        });
    }
}

async fn cmd_status() -> Result<()> {
    let config = Config::load()?;
    if config.accounts.is_empty() {
        println!("No accounts configured.");
        return Ok(());
    }

    println!("Checking {} account(s)...\n", config.accounts.len());

    // Run connectivity checks in parallel
    let mut set = tokio::task::JoinSet::new();
    for acct in &config.accounts {
        let name = acct.name.clone();
        let token = acct.access_token.clone();
        set.spawn(async move {
            let started = std::time::Instant::now();
            let result = oauth::check_token(&token).await;
            (name, result, started.elapsed())
        });
    }

    let mut results: std::collections::HashMap<String, (Result<()>, std::time::Duration)> =
        std::collections::HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((name, res, dur)) = joined {
            results.insert(name, (res, dur));
        }
    }

    println!("Configured accounts:");
    println!("{:-<78}", "");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for acct in &config.accounts {
        let token_preview = if acct.access_token.len() > 20 {
            format!(
                "{}...{}",
                &acct.access_token[..10],
                &acct.access_token[acct.access_token.len() - 6..]
            )
        } else {
            acct.access_token.clone()
        };

        let expired_str = if acct.expires_at == 0 {
            " (no expiry)".to_string()
        } else if now >= acct.expires_at {
            " (EXPIRED)".to_string()
        } else {
            let remaining = (acct.expires_at - now) / 1000 / 60; // minutes
            if remaining < 60 {
                format!(" (expires in {}m)", remaining)
            } else {
                format!(" (expires in {}h)", remaining / 60)
            }
        };

        let check_str = match results.get(&acct.name) {
            Some((Ok(()), dur)) => format!("  ✓ OK ({}ms)", dur.as_millis()),
            Some((Err(e), _)) => format!("  ✗ FAIL: {}", e),
            None => "  ? (not checked)".to_string(),
        };

        println!("  {} — {}{}", acct.name, token_preview, expired_str);
        println!("    {}", check_str);
    }

    println!("\nProxy: http://127.0.0.1:{}", config.listen.port);
    println!(
        "Launch: HTTPS_PROXY=http://127.0.0.1:{} claude",
        config.listen.port
    );

    Ok(())
}

async fn cmd_renew(name: Option<&str>) -> Result<()> {
    let config = Config::load()?;
    if config.accounts.is_empty() {
        anyhow::bail!("No accounts configured.");
    }

    let pool = pool::AccountPool::new(&config.accounts);

    let targets: Vec<(usize, String)> = if let Some(filter) = name {
        let accounts = pool.accounts.read().await;
        match accounts.iter().position(|a| a.name == filter) {
            Some(idx) => vec![(idx, filter.to_string())],
            None => anyhow::bail!("Account '{}' not found", filter),
        }
    } else {
        let accounts = pool.accounts.read().await;
        accounts
            .iter()
            .enumerate()
            .map(|(i, a)| (i, a.name.clone()))
            .collect()
    };

    println!("Refreshing {} account(s)...\n", targets.len());

    let mut all_ok = true;
    for (idx, acct_name) in targets {
        print!("  {} — refreshing... ", acct_name);
        use std::io::Write;
        std::io::stdout().flush()?;

        match pool.refresh_token(idx).await {
            Ok(()) => {
                print!("refreshed, verifying... ");
                std::io::stdout().flush()?;

                let token = {
                    let accounts = pool.accounts.read().await;
                    accounts[idx].access_token.clone()
                };
                match oauth::check_token(&token).await {
                    Ok(()) => println!("✓ OK"),
                    Err(e) => {
                        println!("✗ refresh succeeded but API check failed: {}", e);
                        all_ok = false;
                    }
                }
            }
            Err(e) => {
                println!("✗ FAILED: {}", e);
                all_ok = false;
            }
        }
    }

    if !all_ok {
        anyhow::bail!("one or more accounts failed renewal");
    }
    Ok(())
}

fn cmd_ca_path() -> Result<()> {
    println!("{}", Config::ca_cert_path().display());
    Ok(())
}

fn cmd_env() -> Result<()> {
    let config = Config::load()?;
    println!("export HTTPS_PROXY=http://127.0.0.1:{}", config.listen.port);
    println!("export NODE_EXTRA_CA_CERTS={}", Config::ca_cert_path().display());
    Ok(())
}
