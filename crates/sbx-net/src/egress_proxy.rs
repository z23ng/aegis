use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sbx_proto::{NetworkPolicy, SecretRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::dns_guard::{host_matches_pattern, normalize_host, DnsGuard, EgressDenyReason};

const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Host-only in-memory vault mapping `secret_ref -> real_secret`.
/// Secrets stored here must NEVER be passed directly into any sandbox environment or filesystem.
#[derive(Debug, Clone, Default)]
pub struct SecretVault {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, secret_ref: impl Into<String>, secret_value: impl Into<String>) {
        if let Ok(mut guard) = self.secrets.write() {
            guard.insert(secret_ref.into(), secret_value.into());
        }
    }

    pub fn get(&self, secret_ref: &str) -> Option<String> {
        self.secrets
            .read()
            .ok()
            .and_then(|g| g.get(secret_ref).cloned())
    }

    /// Populate secret references from host environment variables (`SBX_SECRET_<REF>` or exact name).
    pub fn load_from_host_env(&self, rules: &[SecretRule]) {
        for rule in rules {
            if self.get(&rule.secret_ref).is_some() {
                continue;
            }
            if let Ok(val) = std::env::var(&rule.secret_ref) {
                self.insert(rule.secret_ref.clone(), val);
                continue;
            }
            let prefixed = format!(
                "SBX_SECRET_{}",
                rule.secret_ref
                    .to_ascii_uppercase()
                    .replace(['-', '.'], "_")
            );
            if let Ok(val) = std::env::var(&prefixed) {
                self.insert(rule.secret_ref.clone(), val);
            }
        }
    }
}

/// Extract the TLS Server Name Indication (SNI) hostname from a raw TLS ClientHello record.
pub fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record header: ContentType=22 (Handshake), LegacyVersion(2), Length(2)
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let rec_end = (5 + rec_len).min(data.len());
    let hs = &data[5..rec_end];

    // Handshake header: HandshakeType=1 (ClientHello), Length(3)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    // Skip HandshakeType(1) + Length(3) + ClientVersion(2) + Random(32) = 38 bytes
    let mut pos = 38usize;
    if pos >= hs.len() {
        return None;
    }
    // Session ID
    let sess_len = hs[pos] as usize;
    pos = pos.checked_add(1 + sess_len)?;
    // Cipher Suites (2-byte length)
    if pos + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cs_len)?;
    // Compression Methods (1-byte length)
    if pos >= hs.len() {
        return None;
    }
    let comp_len = hs[pos] as usize;
    pos = pos.checked_add(1 + comp_len)?;
    // Extensions (2-byte length)
    if pos + 2 > hs.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total).min(hs.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 {
            // server_name extension
            let ext_data = &hs[pos..pos + ext_len];
            if ext_data.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            let mut lpos = 2usize;
            let list_end = (2 + list_len).min(ext_data.len());
            while lpos + 3 <= list_end {
                let name_type = ext_data[lpos];
                let name_len = u16::from_be_bytes([ext_data[lpos + 1], ext_data[lpos + 2]]) as usize;
                lpos += 3;
                if lpos + name_len > list_end {
                    break;
                }
                if name_type == 0x00 {
                    let sni = core::str::from_utf8(&ext_data[lpos..lpos + name_len]).ok()?;
                    return Some(normalize_host(sni));
                }
                lpos += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

/// Host-side Zero-Trust HTTP/HTTPS egress proxy and Secret Injector.
pub struct EgressProxy {
    proxy_url: String,
    listen_port: u16,
    shutdown_tx: watch::Sender<bool>,
}

impl EgressProxy {
    /// Start an `EgressProxy` bound on `127.0.0.1:0` in the host network namespace.
    pub async fn start(
        policy: &NetworkPolicy,
        secret_rules: Vec<SecretRule>,
        vault: SecretVault,
        host_overrides: HashMap<String, Vec<SocketAddr>>,
    ) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind EgressProxy listener")?;
        let port = listener.local_addr()?.port();
        Self::start_with_listener(listener, port, policy, secret_rules, vault, host_overrides)
    }

    /// Start an `EgressProxy` accepting on a pre-bound `RawFd` (e.g., passed via `SCM_RIGHTS`
    /// from inside a sandbox's isolated `CLONE_NEWNET` namespace).
    ///
    /// # Safety
    /// Caller transfers ownership of an open listening TCP socket `listener_fd`.
    pub unsafe fn start_from_raw_fd(
        listener_fd: RawFd,
        sandbox_listen_port: u16,
        policy: &NetworkPolicy,
        secret_rules: Vec<SecretRule>,
        vault: SecretVault,
        host_overrides: HashMap<String, Vec<SocketAddr>>,
    ) -> Result<Self> {
        let std_listener = std::net::TcpListener::from_raw_fd(listener_fd);
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        Self::start_with_listener(
            listener,
            sandbox_listen_port,
            policy,
            secret_rules,
            vault,
            host_overrides,
        )
    }

    fn start_with_listener(
        listener: TcpListener,
        sandbox_port: u16,
        policy: &NetworkPolicy,
        secret_rules: Vec<SecretRule>,
        vault: SecretVault,
        host_overrides: HashMap<String, Vec<SocketAddr>>,
    ) -> Result<Self> {
        let guard = Arc::new(DnsGuard::new(policy).with_host_overrides(host_overrides));
        let rules = Arc::new(secret_rules);
        let vault = Arc::new(vault);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let g = Arc::clone(&guard);
                                let r = Arc::clone(&rules);
                                let v = Arc::clone(&vault);
                                tokio::spawn(async move {
                                    if let Err(e) = handle_proxy_client(stream, g, r, v).await {
                                        debug!(error = %e, "egress proxy connection closed");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "egress proxy accept failed");
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            proxy_url: format!("http://127.0.0.1:{sandbox_port}"),
            listen_port: sandbox_port,
            shutdown_tx,
        })
    }

    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    pub fn port(&self) -> u16 {
        self.listen_port
    }

    /// Environment variables injected into the sandbox so HTTP clients route through this proxy.
    pub fn sandbox_env(&self) -> Vec<(String, String)> {
        vec![
            (String::from("HTTP_PROXY"), self.proxy_url.clone()),
            (String::from("HTTPS_PROXY"), self.proxy_url.clone()),
            (String::from("http_proxy"), self.proxy_url.clone()),
            (String::from("https_proxy"), self.proxy_url.clone()),
            (String::from("NO_PROXY"), String::from("localhost,127.0.0.1")),
        ]
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn handle_proxy_client(
    mut client: TcpStream,
    guard: Arc<DnsGuard>,
    rules: Arc<Vec<SecretRule>>,
    vault: Arc<SecretVault>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() >= MAX_HEADER_BYTES {
            send_http_error(&mut client, 431, "Request Header Fields Too Large").await;
            bail!("HTTP header exceeded {MAX_HEADER_BYTES} bytes");
        }
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head_bytes = &buf[..head_end];
    let body_prefix = &buf[head_end + 4..];
    let head_str = core::str::from_utf8(head_bytes).context("invalid UTF-8 in HTTP head")?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().context("missing HTTP request line")?;
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next().context("missing HTTP method")?;
    let target = req_parts.next().context("missing HTTP target")?;
    let version = req_parts.next().unwrap_or("HTTP/1.1");

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.push((name.trim().to_string(), val.trim().to_string()));
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443);
        let (norm_host, addrs) = match guard.resolve_and_verify(&host, port).await {
            Ok(res) => res,
            Err(reason) => {
                send_forbidden(&mut client, &reason).await;
                return Ok(());
            }
        };

        let mut upstream = TcpStream::connect(&addrs[..])
            .await
            .with_context(|| format!("connect upstream {norm_host}:{port} failed"))?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Inspect initial tunnel bytes for TLS ClientHello SNI verification if present.
        let mut initial = if !body_prefix.is_empty() {
            body_prefix.to_vec()
        } else {
            let mut sniff = [0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(1500), client.read(&mut sniff)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => sniff[..n].to_vec(),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => Vec::new(),
            }
        };

        if initial.first() == Some(&0x16) {
            if let Some(sni) = extract_tls_sni(&initial) {
                if sni != norm_host {
                    let reason = EgressDenyReason::SniMismatch {
                        requested: norm_host,
                        sni,
                    };
                    warn!(%reason, "blocked TLS SNI spoofing attempt");
                    return Ok(());
                }
            }
        }

        if !initial.is_empty() {
            upstream.write_all(&initial).await?;
            initial.clear();
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    // Standard HTTP proxy request (`GET http://host/path HTTP/1.1` or origin-form + `Host:`)
    let (host, port, origin_target) = parse_http_target(target, &headers)?;
    let (norm_host, addrs) = match guard.resolve_and_verify(&host, port).await {
        Ok(res) => res,
        Err(reason) => {
            send_forbidden(&mut client, &reason).await;
            return Ok(());
        }
    };

    let mut upstream = TcpStream::connect(&addrs[..])
        .await
        .with_context(|| format!("connect upstream {norm_host}:{port} failed"))?;

    let mut rewritten = String::with_capacity(head_str.len() + 128);
    rewritten.push_str(&format!("{method} {origin_target} {version}\r\n"));

    let mut has_host = false;
    for (name, val) in headers {
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        let injected = inject_secrets_for_host(&norm_host, &name, &val, &rules, &vault);
        rewritten.push_str(&format!("{name}: {injected}\r\n"));
    }
    if !has_host {
        if port == 80 {
            rewritten.push_str(&format!("Host: {norm_host}\r\n"));
        } else {
            rewritten.push_str(&format!("Host: {norm_host}:{port}\r\n"));
        }
    }
    rewritten.push_str("Connection: close\r\n\r\n");

    upstream.write_all(rewritten.as_bytes()).await?;
    if !body_prefix.is_empty() {
        upstream.write_all(body_prefix).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Replace matching `SecretRule` placeholders with real secrets from `SecretVault` ONLY
/// when `target_host` matches the rule's `allowed_hosts`.
pub fn inject_secrets_for_host(
    target_host: &str,
    header_name: &str,
    header_value: &str,
    rules: &[SecretRule],
    vault: &SecretVault,
) -> String {
    let mut out = header_value.to_string();
    for rule in rules {
        let header_matches = rule.header_name.is_empty()
            || rule.header_name == "*"
            || rule.header_name.eq_ignore_ascii_case(header_name);
        if !header_matches || rule.placeholder.is_empty() || !out.contains(&rule.placeholder) {
            continue;
        }
        let host_allowed = rule
            .allowed_hosts
            .iter()
            .any(|pat| host_matches_pattern(target_host, pat));
        if !host_allowed {
            continue;
        }
        if let Some(real_secret) = vault.get(&rule.secret_ref) {
            out = out.replace(&rule.placeholder, &real_secret);
        }
    }
    out
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_host_port(authority: &str, default_port: u16) -> (String, u16) {
    let trimmed = authority.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((ip6, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (format!("[{ip6}]"), port);
        }
    }
    if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        if let Ok(port) = p_str.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (trimmed.to_string(), default_port)
}

fn parse_http_target(target: &str, headers: &[(String, String)]) -> Result<(String, u16, String)> {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
    {
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) = parse_host_port(authority, 80);
        return Ok((host, port, path.to_string()));
    }

    let host_hdr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .context("missing Host header in relative HTTP request")?;
    let (host, port) = parse_host_port(host_hdr, 80);
    let path = if target.is_empty() { "/" } else { target };
    Ok((host, port, path.to_string()))
}

async fn send_forbidden(client: &mut TcpStream, reason: &EgressDenyReason) {
    let body = format!("Blocked by sbx-net egress policy: {reason}\n");
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = client.write_all(resp.as_bytes()).await;
}

async fn send_http_error(client: &mut TcpStream, code: u16, text: &str) {
    let resp = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = client.write_all(resp.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let entry_len = 1 + 2 + sni_bytes.len();
        let list_len = entry_len;
        let ext_len = 2 + list_len;
        let exts_total = 4 + ext_len;

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        hello.extend_from_slice(&[0xAA; 32]); // Random
        hello.push(0x00); // SessionID len
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // CipherSuite TLS_AES_128_GCM_SHA256
        hello.extend_from_slice(&[0x01, 0x00]); // Compression null
        hello.extend_from_slice(&(exts_total as u16).to_be_bytes());
        hello.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI ext
        hello.extend_from_slice(&(ext_len as u16).to_be_bytes());
        hello.extend_from_slice(&(list_len as u16).to_be_bytes());
        hello.push(0x00); // host_name
        hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(sni_bytes);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hlen = hello.len();
        hs.push(((hlen >> 16) & 0xFF) as u8);
        hs.push(((hlen >> 8) & 0xFF) as u8);
        hs.push((hlen & 0xFF) as u8);
        hs.extend_from_slice(&hello);

        let mut rec = Vec::new();
        rec.push(0x16); // Handshake
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_sni_parser_extracts_hostname() {
        let ch = build_tls_client_hello("API.GitHub.com");
        assert_eq!(extract_tls_sni(&ch).as_deref(), Some("api.github.com"));
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[tokio::test]
    async fn egress_proxy_blocks_disallowed_and_metadata_and_injects_secrets_only_for_bound_host() {
        // Start a mock upstream HTTP server echoing back the Authorization header & path.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let body = req;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let policy = NetworkPolicy::AllowlistProxy {
            allowed_hosts: vec![
                String::from("api.github.com"),
                String::from("other.example.com"),
            ],
            block_private_cidrs: true,
        };
        let rules = vec![SecretRule {
            placeholder: String::from("sbx_placeholder_gh_1"),
            allowed_hosts: vec![String::from("api.github.com")],
            header_name: String::from("Authorization"),
            secret_ref: String::from("github_pat"),
        }];
        let vault = SecretVault::new();
        vault.insert("github_pat", "ghp_REAL_SECRET_9999");

        let mut overrides = HashMap::new();
        overrides.insert(String::from("api.github.com"), vec![upstream_addr]);
        overrides.insert(String::from("other.example.com"), vec![upstream_addr]);

        let proxy = EgressProxy::start(&policy, rules, vault, overrides)
            .await
            .expect("proxy start");
        let proxy_addr = format!("127.0.0.1:{}", proxy.port());

        // 1. Disallowed external domain -> 403 Forbidden
        let resp1 = send_raw_http(
            &proxy_addr,
            "GET http://evil.example.com/steal HTTP/1.1\r\nHost: evil.example.com\r\n\r\n",
        )
        .await;
        assert!(resp1.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp1}");

        // 2. Cloud metadata IP -> 403 Forbidden
        let resp2 = send_raw_http(
            &proxy_addr,
            "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
        )
        .await;
        assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp2}");

        // 3. Host loopback direct access -> 403 Forbidden
        let resp3 = send_raw_http(
            &proxy_addr,
            &format!("GET http://127.0.0.1:{}/secret HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", upstream_addr.port(), upstream_addr.port()),
        )
        .await;
        assert!(resp3.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp3}");

        // 4. Allowed domain bound to secret -> placeholder replaced with REAL secret
        let resp4 = send_raw_http(
            &proxy_addr,
            "GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer sbx_placeholder_gh_1\r\n\r\n",
        )
        .await;
        assert!(resp4.starts_with("HTTP/1.1 200 OK"), "got: {resp4}");
        assert!(resp4.contains("Bearer ghp_REAL_SECRET_9999"), "secret not injected: {resp4}");
        assert!(!resp4.contains("sbx_placeholder_gh_1"), "placeholder remained: {resp4}");

        // 5. Allowed domain NOT bound to secret -> placeholder NOT replaced (zero leak!)
        let resp5 = send_raw_http(
            &proxy_addr,
            "GET http://other.example.com/echo HTTP/1.1\r\nHost: other.example.com\r\nAuthorization: Bearer sbx_placeholder_gh_1\r\n\r\n",
        )
        .await;
        assert!(resp5.starts_with("HTTP/1.1 200 OK"), "got: {resp5}");
        assert!(resp5.contains("Bearer sbx_placeholder_gh_1"), "placeholder should remain: {resp5}");
        assert!(!resp5.contains("ghp_REAL_SECRET_9999"), "secret leaked to unbound domain: {resp5}");

        // 6. CONNECT TLS SNI spoofing check
        let mut sni_conn = TcpStream::connect(&proxy_addr).await.unwrap();
        sni_conn
            .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = sni_conn.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        let spoofed_hello = build_tls_client_hello("evil.attacker.com");
        sni_conn.write_all(&spoofed_hello).await.unwrap();
        let mut eof_buf = [0u8; 64];
        let n2 = sni_conn.read(&mut eof_buf).await.unwrap_or(0);
        assert_eq!(n2, 0, "SNI spoofed tunnel must be closed immediately");
    }

    async fn send_raw_http(addr: &str, req: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp).await;
        String::from_utf8_lossy(&resp).into_owned()
    }
}
