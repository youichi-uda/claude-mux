# claude-mux

Transparent multi-account proxy for Claude Code Max subscriptions.

Seamlessly rotates between multiple Claude Max accounts when rate limits are hit — **without breaking your session**.

## Why

Claude Code Max subscriptions have usage limits. If you have multiple Max accounts, `claude-mux` lets you use them as a unified pool. When one account hits its limit, the proxy transparently switches to the next account. Your Claude Code session continues uninterrupted.

## How it works

```
Claude Code (HTTPS_PROXY=http://127.0.0.1:8119)
    │
    ▼
┌─────────────────────────────────┐
│  claude-mux (local MITM proxy)  │
│                                 │
│  Account Pool:                  │
│    acct1 ── READY (42 reqs)     │
│    acct2 ── READY (38 reqs)     │
│    acct3 ── COOLDOWN (2m left)  │
│                                 │
│  → Intercepts api.anthropic.com │
│  → Swaps Authorization header   │
│  → On 429: retry with next acct │
│  → Auto-refreshes OAuth tokens  │
└─────────────────────────────────┘
```

- MITM proxy that intercepts only `api.anthropic.com` traffic
- All other HTTPS traffic is tunneled through unchanged
- Generates a local CA certificate (trusted on setup)
- Round-robin token rotation with automatic 429 failover
- OAuth token auto-refresh before expiry
- SSE streaming passthrough (no buffering)

## Quick start

### 1. Install

```bash
cargo install claude-mux
```

Or build from source:

```bash
git clone https://github.com/anthropics/claude-mux
cd claude-mux
cargo build --release
# Binary at target/release/claude-mux
```

### 2. Setup (one-time)

```bash
# Generate CA cert and trust it in macOS Keychain
claude-mux setup
```

### 3. Add accounts

Log in to each Claude Max account and add it:

```bash
# Log in to account 1 (already logged in? skip this)
claude login

# Add current credentials
claude-mux add personal

# Log in to account 2
claude login  # Use different email/account

# Add those credentials
claude-mux add work1

# Repeat for account 3...
claude-mux add work2
```

### 4. Start proxy & use Claude Code

```bash
# Terminal 1: start the proxy
claude-mux start

# Terminal 2: launch Claude Code through the proxy
HTTPS_PROXY=http://127.0.0.1:8119 claude
```

Or add to your shell profile:

```bash
# ~/.zshrc
alias claude-proxied='HTTPS_PROXY=http://127.0.0.1:8119 claude'
```

## Commands

| Command | Description |
|---|---|
| `claude-mux setup` | Generate CA cert and install to system keychain |
| `claude-mux add <name>` | Add current Claude Code credentials as a named account |
| `claude-mux import <name> --access-token ... --refresh-token ...` | Import credentials directly |
| `claude-mux start [-p PORT]` | Start the proxy (default port: 8119) |
| `claude-mux status` | Show configured accounts and their status |
| `claude-mux env` | Print `export HTTPS_PROXY=...` for shell |
| `claude-mux ca-path` | Print path to CA certificate |

## How rate limit handling works

1. Claude Code sends a request through the proxy
2. Proxy picks the next available account (round-robin)
3. Proxy swaps the `Authorization` header with that account's token
4. If the upstream returns `429 Too Many Requests`:
   - The account is put on cooldown (using `Retry-After` header)
   - The request is automatically retried with the next account
   - Up to 3 retries across different accounts
5. If all accounts are rate-limited, the 429 is passed through to Claude Code

## Configuration

Config is stored at `~/.claude-mux/config.json`:

```json
{
  "listen": {
    "host": "127.0.0.1",
    "port": 8119
  },
  "accounts": [
    {
      "name": "personal",
      "access_token": "sk-ant-oat01-...",
      "refresh_token": "sk-ant-ort01-...",
      "expires_at": 1776192160892,
      "scopes": ["user:inference", "..."]
    }
  ]
}
```

## Security

- The proxy only listens on `127.0.0.1` (localhost only)
- Only `api.anthropic.com` traffic is intercepted; all other HTTPS is tunneled
- CA private key is stored with `0600` permissions
- Tokens are stored in `~/.claude-mux/config.json` — protect this file

## Platform support

- **macOS** — full support (Keychain integration for CA trust + credential extraction)
- **Linux** — works, but CA trust and credential extraction require manual steps
- **Windows** — not yet supported

## License

MIT
