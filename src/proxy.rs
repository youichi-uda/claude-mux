use crate::cert::generate_host_cert;
use crate::pool::AccountPool;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

const TARGET_HOST: &str = "api.anthropic.com";

pub struct ProxyServer {
    pool: Arc<AccountPool>,
    ca_cert_pem: String,
    ca_key_pem: String,
    http_client: reqwest::Client,
}

impl ProxyServer {
    pub fn new(pool: Arc<AccountPool>, ca_cert_pem: String, ca_key_pem: String) -> Arc<Self> {
        Arc::new(Self {
            pool,
            ca_cert_pem,
            ca_key_pem,
            http_client: reqwest::Client::builder()
                .no_proxy() // Don't loop through ourselves
                .build()
                .unwrap(),
        })
    }

    /// Handle an incoming connection (could be CONNECT or plain HTTP).
    pub async fn handle_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
    ) {
        let server = self.clone();
        let io = TokioIo::new(stream);

        let service = service_fn(move |req: Request<Incoming>| {
            let server = server.clone();
            async move {
                let result = if req.method() == Method::CONNECT {
                    server.handle_connect(req).await
                } else {
                    // Plain HTTP request (unlikely for Claude, but handle it)
                    server.handle_request(req, None).await
                };

                match result {
                    Ok(resp) => Ok::<_, Infallible>(resp),
                    Err(e) => {
                        error!("[{}] Error: {}", peer, e);
                        Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from(format!("Proxy error: {e}")))
                                .map_err(|e| match e {})
                                .boxed())
                            .unwrap())
                    }
                }
            }
        });

        if let Err(e) = http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
            if !e.to_string().contains("early eof")
                && !e.to_string().contains("connection closed")
            {
                debug!("[{}] Connection error: {}", peer, e);
            }
        }
    }

    /// Handle CONNECT method — this is the MITM entry point.
    async fn handle_connect(
        self: &Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>> {
        let host = req.uri().authority().map(|a| a.host().to_string())
            .or_else(|| req.uri().host().map(|h| h.to_string()))
            .unwrap_or_default();

        let connect_addr = req.uri().authority().map(|a| a.to_string())
            .unwrap_or_else(|| format!("{}:443", host));

        debug!("CONNECT {}", connect_addr);

        if host != TARGET_HOST {
            // Not our target — plain TCP tunnel (passthrough)
            return self.tunnel_passthrough(req, &connect_addr).await;
        }

        // MITM for api.anthropic.com
        info!("MITM intercept: {}", host);

        let server = self.clone();
        let host_clone = host.clone();

        // Respond with 200 to establish the tunnel
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);
                    if let Err(e) = server.mitm_connection(io, &host_clone).await {
                        error!("MITM error for {}: {}", host_clone, e);
                    }
                }
                Err(e) => {
                    error!("Upgrade failed for {}: {}", host_clone, e);
                }
            }
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(http_body_util::Empty::new().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { match e {} }).boxed())
            .unwrap())
    }

    /// Passthrough tunnel for non-target hosts.
    async fn tunnel_passthrough(
        self: &Arc<Self>,
        req: Request<Incoming>,
        addr: &str,
    ) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>> {
        let upstream = TcpStream::connect(addr).await?;
        let addr = addr.to_string();

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let mut client = TokioIo::new(upgraded);
                    let mut server = upstream;

                    let (mut cr, mut cw) = tokio::io::split(&mut client);
                    let (mut sr, mut sw) = tokio::io::split(&mut server);

                    let c2s = tokio::io::copy(&mut cr, &mut sw);
                    let s2c = tokio::io::copy(&mut sr, &mut cw);

                    let _ = tokio::try_join!(c2s, s2c);
                }
                Err(e) => {
                    error!("Tunnel upgrade failed for {}: {}", addr, e);
                }
            }
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(http_body_util::Empty::new().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { match e {} }).boxed())
            .unwrap())
    }

    /// MITM a TLS connection: act as TLS server to the client, then forward to upstream.
    async fn mitm_connection<I>(self: &Arc<Self>, client_io: I, hostname: &str) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Generate a certificate for this hostname
        let (cert_pem, key_pem) =
            generate_host_cert(hostname, &self.ca_cert_pem, &self.ca_key_pem)?;

        // Set up TLS acceptor
        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tls_stream = acceptor.accept(client_io).await?;
        let io = TokioIo::new(tls_stream);

        // Now serve HTTP on the decrypted stream
        let server = self.clone();
        let hostname = hostname.to_string();

        http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(
                io,
                service_fn(move |req: Request<Incoming>| {
                    let server = server.clone();
                    let hostname = hostname.clone();
                    async move {
                        match server.handle_request(req, Some(&hostname)).await {
                            Ok(resp) => Ok::<_, Infallible>(resp),
                            Err(e) => {
                                error!("Request handler error: {}", e);
                                Ok(Response::builder()
                                    .status(StatusCode::BAD_GATEWAY)
                                    .body(Full::new(Bytes::from(format!("Error: {e}")))
                                        .map_err(|e| match e {})
                                        .boxed())
                                    .unwrap())
                            }
                        }
                    }
                }),
            )
            .await?;

        Ok(())
    }

    /// Handle an individual HTTP request after TLS termination.
    /// This is where we swap tokens and handle 429 retries.
    async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
        hostname: Option<&str>,
    ) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let host = hostname.unwrap_or(TARGET_HOST);

        // Only rotate tokens on inference endpoints.
        // Other endpoints (auth, sessions, telemetry) keep their original headers.
        let should_rotate = path == "/v1/messages" || path == "/v1/messages/";

        // Collect headers. If rotating, strip x-api-key + authorization.
        // Otherwise, pass everything through unchanged.
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in req.headers() {
            if name == "host" {
                continue;
            }
            if should_rotate && (name == "x-api-key" || name == "authorization") {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                headers.insert(n, v);
            }
        }

        // Collect request body
        let body_bytes = req.collect().await?.to_bytes();

        // If not an inference endpoint, do a single passthrough request without token rotation.
        if !should_rotate {
            let url = format!("https://{}{}", host, path);
            let mut req_builder = self.http_client.request(method.clone(), &url);
            req_builder = req_builder.headers(headers.clone());
            req_builder = req_builder.header("Host", host);
            if !body_bytes.is_empty() {
                req_builder = req_builder.body(body_bytes.clone());
            }

            let resp = req_builder.send().await?;
            let status = resp.status();
            debug!("[passthrough] {} {} {}", status.as_u16(), method, path);

            let mut builder = Response::builder().status(status);
            for (name, value) in resp.headers() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            let stream = resp.bytes_stream();
            let body = StreamBody::new(
                tokio_stream::StreamExt::map(stream, |chunk| {
                    chunk
                        .map(Frame::data)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
                }),
            );
            return Ok(builder.body(body.boxed()).unwrap());
        }

        // Aggressive retry: keep going within a total time + attempt budget.
        // Server-side overload (global throttle) gets short cooldowns + many retries;
        // per-account quota gets the server's Retry-After and we rotate elsewhere.
        let started = std::time::Instant::now();
        let total_budget = std::time::Duration::from_secs(600); // 10 minutes
        // Max attempts is a sanity cap; the time budget is the real limit.
        // Each iteration is fast (no sleep) until accounts are all cooling
        // down, at which point the cooldown-wait branch slows the cadence.
        let max_attempts: u32 = 500;

        let mut last_acct_idx: Option<usize> = None;
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;
            let elapsed = started.elapsed();
            if attempt > max_attempts || elapsed >= total_budget {
                warn!(
                    "Retry budget exhausted for {} (attempt {}, elapsed {}s)",
                    path,
                    attempt - 1,
                    elapsed.as_secs(),
                );
                return Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(
                        Full::new(Bytes::from("All accounts rate limited"))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap());
            }

            // Pick — prefer rotating away from the previous attempt to spread load.
            let pick = match last_acct_idx {
                Some(prev) => match self.pool.pick_excluding(prev).await {
                    Some(v) => Some(v),
                    None => self.pool.pick().await,
                },
                None => self.pool.pick().await,
            };
            let (acct_idx, access_token) = match pick {
                Some(v) => v,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(
                            Full::new(Bytes::from("No accounts configured"))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap());
                }
            };
            last_acct_idx = Some(acct_idx);

            // If the picked account is on cooldown, sleep for it (capped per-iteration)
            // and retry. We still count the attempt so we don't loop forever.
            let cooldown_secs = {
                let accounts = self.pool.accounts.read().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let acct = &accounts[acct_idx];
                if acct.cooldown_until > now {
                    (acct.cooldown_until - now) / 1000 + 1
                } else {
                    0
                }
            };
            if cooldown_secs > 0 {
                let remaining_budget = total_budget.saturating_sub(elapsed).as_secs();
                let wait = cooldown_secs.min(60).min(remaining_budget);
                if wait == 0 {
                    warn!(
                        "Cooldown {}s exceeds remaining budget for {}",
                        cooldown_secs, path,
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(
                            Full::new(Bytes::from("All accounts rate limited"))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap());
                }
                info!(
                    "All accounts cooling down — waiting {}s (attempt {}, {}s left in budget)",
                    wait, attempt, remaining_budget,
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                continue;
            }

            let url = format!("https://{}{}", host, path);
            let mut req_builder = self.http_client.request(method.clone(), &url);
            req_builder = req_builder.headers(headers.clone());
            req_builder = req_builder.header("x-api-key", &access_token);
            req_builder = req_builder.header("authorization", format!("Bearer {}", access_token));
            req_builder = req_builder.header("Host", host);
            if !body_bytes.is_empty() {
                req_builder = req_builder.body(body_bytes.clone());
            }

            let acct_name = {
                let accounts = self.pool.accounts.read().await;
                accounts
                    .get(acct_idx)
                    .map(|a| a.name.clone())
                    .unwrap_or_default()
            };

            let resp = match req_builder.send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "[{}] network error on {} (attempt {}): {} — retrying",
                        acct_name, path, attempt, e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let status = resp.status();
            self.pool.record_request(acct_idx).await;

            if status == StatusCode::TOO_MANY_REQUESTS {
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60);

                // Distinguish server-side throttling ("not your usage limit") from
                // per-account quota. Server-side throttle → short cooldown so we
                // can keep retrying aggressively.
                let body = resp.bytes().await.unwrap_or_default();
                let body_str = std::str::from_utf8(&body).unwrap_or("");
                let is_server_overload = body_str.contains("not your usage limit")
                    || body_str.contains("overloaded_error");

                let cooldown = if is_server_overload {
                    retry_after.min(8)
                } else {
                    retry_after
                };

                self.pool.mark_rate_limited(acct_idx, cooldown).await;
                warn!(
                    "[{}] 429 ({}) on {} (attempt {}, cooldown {}s, {}s elapsed)",
                    acct_name,
                    if is_server_overload {
                        "server-overload"
                    } else {
                        "quota"
                    },
                    path,
                    attempt,
                    cooldown,
                    elapsed.as_secs(),
                );
                continue;
            }

            // 401: try refreshing the token in place. Pass our snapshot of
            // the access_token so concurrent 401s on the same account don't
            // race on the (one-time-use) refresh_token — the second caller
            // will see the access_token has already been rotated and skip.
            if status == StatusCode::UNAUTHORIZED {
                warn!("[{}] 401 on {} — attempting token refresh", acct_name, path);
                match self
                    .pool
                    .refresh_if_token_matches(acct_idx, &access_token)
                    .await
                {
                    Ok(()) => {
                        info!("[{}] Token refreshed after 401, retrying", acct_name);
                        last_acct_idx = None;
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "[{}] 401 on {} — refresh failed: {}, cooldown 24h",
                            acct_name, path, e
                        );
                        self.pool.mark_rate_limited(acct_idx, 24 * 3600).await;
                        continue;
                    }
                }
            }

            // Transient upstream errors — retry on a different account.
            if status == StatusCode::BAD_GATEWAY
                || status == StatusCode::SERVICE_UNAVAILABLE
                || status == StatusCode::GATEWAY_TIMEOUT
                || status.as_u16() == 529
            {
                warn!(
                    "[{}] {} on {} (attempt {}) — retrying",
                    acct_name,
                    status.as_u16(),
                    path,
                    attempt
                );
                self.pool.mark_rate_limited(acct_idx, 5).await;
                continue;
            }

            // Success — stream response back to client.
            info!(
                "[{}] {} {} {} (attempt {}, {}s elapsed)",
                acct_name,
                status.as_u16(),
                method,
                path,
                attempt,
                elapsed.as_secs(),
            );

            let mut builder = Response::builder().status(status);
            for (name, value) in resp.headers() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            let stream = resp.bytes_stream();
            let body = StreamBody::new(tokio_stream::StreamExt::map(stream, |chunk| {
                chunk
                    .map(Frame::data)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            }));
            return Ok(builder.body(body.boxed()).unwrap());
        }
    }
}
