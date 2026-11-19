use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use sbx_proto::NetworkPolicy;

use crate::netns::{is_forbidden_ip, parse_ip_literal};

/// Reason an outbound DNS query or TCP/HTTP connection was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDenyReason {
    NetworkDisabled,
    InvalidHost(String),
    ForbiddenIp(IpAddr),
    NotInAllowlist(String),
    DnsRebindingBlocked(String),
    ResolutionFailed(String),
    SniMismatch { requested: String, sni: String },
}

impl fmt::Display for EgressDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkDisabled => f.write_str("sandbox network is disabled"),
            Self::InvalidHost(h) => write!(f, "invalid host: {h}"),
            Self::ForbiddenIp(ip) => write!(f, "forbidden private or metadata IP: {ip}"),
            Self::NotInAllowlist(h) => write!(f, "host '{h}' is not in egress allowlist"),
            Self::DnsRebindingBlocked(h) => {
                write!(f, "host '{h}' resolved exclusively to forbidden private/metadata IPs")
            }
            Self::ResolutionFailed(h) => write!(f, "failed to resolve host '{h}'"),
            Self::SniMismatch { requested, sni } => {
                write!(f, "TLS SNI '{sni}' does not match CONNECT target '{requested}'")
            }
        }
    }
}

/// DNS & domain allowlist guard preventing unauthorized egress, raw IP bypass, and DNS rebinding.
#[derive(Debug, Clone)]
pub struct DnsGuard {
    disabled: bool,
    allowed_hosts: Vec<String>,
    block_private_cidrs: bool,
    host_overrides: HashMap<String, Vec<SocketAddr>>,
}

impl DnsGuard {
    pub fn new(policy: &NetworkPolicy) -> Self {
        match policy {
            NetworkPolicy::Disabled => Self {
                disabled: true,
                allowed_hosts: Vec::new(),
                block_private_cidrs: true,
                host_overrides: HashMap::new(),
            },
            NetworkPolicy::AllowlistProxy {
                allowed_hosts,
                block_private_cidrs,
            } => Self {
                disabled: false,
                allowed_hosts: allowed_hosts
                    .iter()
                    .map(|h| normalize_host(h))
                    .filter(|h| !h.is_empty())
                    .collect(),
                block_private_cidrs: *block_private_cidrs,
                host_overrides: HashMap::new(),
            },
        }
    }

    pub fn with_host_override(mut self, host: impl AsRef<str>, addr: SocketAddr) -> Self {
        self.host_overrides
            .entry(normalize_host(host.as_ref()))
            .or_default()
            .push(addr);
        self
    }

    pub fn with_host_overrides(mut self, overrides: HashMap<String, Vec<SocketAddr>>) -> Self {
        for (k, v) in overrides {
            self.host_overrides.insert(normalize_host(&k), v);
        }
        self
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    pub fn block_private_cidrs(&self) -> bool {
        self.block_private_cidrs
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Check whether `host` is permitted by the sandbox's egress policy.
    pub fn is_host_allowed(&self, host: &str) -> Result<String, EgressDenyReason> {
        if self.disabled {
            return Err(EgressDenyReason::NetworkDisabled);
        }
        let norm = normalize_host(host);
        if norm.is_empty() {
            return Err(EgressDenyReason::InvalidHost(host.to_string()));
        }

        if let Some(ip) = parse_ip_literal(&norm) {
            if is_forbidden_ip(ip, self.block_private_cidrs) {
                return Err(EgressDenyReason::ForbiddenIp(ip));
            }
            if !self
                .allowed_hosts
                .iter()
                .any(|pat| host_matches_pattern(&norm, pat))
            {
                return Err(EgressDenyReason::NotInAllowlist(norm));
            }
            return Ok(norm);
        }

        if !self
            .allowed_hosts
            .iter()
            .any(|pat| host_matches_pattern(&norm, pat))
        {
            return Err(EgressDenyReason::NotInAllowlist(norm));
        }

        Ok(norm)
    }

    /// Verify `host` is allowed, resolve DNS if needed, and reject forbidden/private IPs.
    pub async fn resolve_and_verify(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(String, Vec<SocketAddr>), EgressDenyReason> {
        let norm = self.is_host_allowed(host)?;

        if let Some(addrs) = self.host_overrides.get(&norm) {
            if !addrs.is_empty() {
                return Ok((norm, addrs.clone()));
            }
        }

        if let Some(ip) = parse_ip_literal(&norm) {
            return Ok((norm, vec![SocketAddr::new(ip, port)]));
        }

        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((norm.as_str(), port))
            .await
            .map_err(|_| EgressDenyReason::ResolutionFailed(norm.clone()))?
            .collect();

        if resolved.is_empty() {
            return Err(EgressDenyReason::ResolutionFailed(norm));
        }

        let filtered: Vec<SocketAddr> = resolved
            .into_iter()
            .filter(|addr| !is_forbidden_ip(addr.ip(), self.block_private_cidrs))
            .collect();

        if filtered.is_empty() {
            return Err(EgressDenyReason::DnsRebindingBlocked(norm));
        }

        Ok((norm, filtered))
    }

    /// Filter an incoming UDP DNS wire query against `allowed_hosts`.
    /// Non-allowlisted domains receive an immediate synthetic `NXDOMAIN` reply.
    pub fn filter_dns_packet(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (qname, qend) = parse_dns_qname(query)?;
        if self.is_host_allowed(&qname).is_err() {
            return build_dns_nxdomain_response(query);
        }
        let norm = normalize_host(&qname);
        if let Some(addrs) = self.host_overrides.get(&norm) {
            if let Some(SocketAddr::V4(v4)) = addrs.iter().find(|a| a.is_ipv4()) {
                return build_dns_a_response(query, qend, v4.ip().octets());
            }
        }
        None
    }
}

/// Normalize a hostname (strip brackets, trailing dots, lowercase).
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.to_ascii_lowercase()
}

/// Match `host` against an allowlist pattern (`api.github.com`, `*.github.com`, or `*`).
pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let h = normalize_host(host);
    let p = normalize_host(pattern);
    if h.is_empty() || p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return h.len() > suffix.len()
            && h.ends_with(suffix)
            && h.as_bytes()[h.len() - suffix.len() - 1] == b'.';
    }
    h == p
}

/// Parse the first QNAME from a standard DNS wire query (returns `(domain, end_of_question_offset)`).
pub fn parse_dns_qname(packet: &[u8]) -> Option<(String, usize)> {
    if packet.len() < 17 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    while pos < packet.len() {
        let len = packet[pos] as usize;
        pos += 1;
        if len == 0 {
            // Skip QTYPE (2) + QCLASS (2) if present
            let qend = if pos + 4 <= packet.len() {
                pos + 4
            } else {
                pos
            };
            return Some((labels.join("."), qend));
        }
        if (len & 0xC0) != 0 || pos + len > packet.len() {
            return None;
        }
        let label = core::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }
    None
}

/// Build an RFC 1035 NXDOMAIN (RCODE=3) response matching `query`.
pub fn build_dns_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    // Preserve ID (bytes 0..2), set QR=1 (0x80), keep RD (0x01)
    resp[2] = 0x80 | (query[2] & 0x01);
    // RA=0, RCODE=3 (NXDOMAIN)
    resp[3] = 0x03;
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[6..12].fill(0);
    Some(resp)
}

/// Build a minimal RFC 1035 Type-A DNS response for an overridden IPv4 address.
pub fn build_dns_a_response(query: &[u8], qend: usize, ipv4: [u8; 4]) -> Option<Vec<u8>> {
    if query.len() < qend || qend < 16 {
        return None;
    }
    let mut resp = Vec::with_capacity(qend + 16);
    resp.extend_from_slice(&query[..qend]);
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x80; // RA=1, RCODE=0
    resp[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    resp[8..12].fill(0);
    // Name pointer to offset 12 (0xC00C), Type A (1), Class IN (1), TTL=60, RDLENGTH=4, RDATA
    resp.extend_from_slice(&[
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
    ]);
    resp.extend_from_slice(&ipv4);
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_matching_works_for_exact_and_wildcard() {
        assert!(host_matches_pattern("api.github.com", "api.github.com"));
        assert!(host_matches_pattern("API.GITHUB.COM.", "api.github.com"));
        assert!(host_matches_pattern("api.github.com", "*.github.com"));
        assert!(host_matches_pattern("raw.sub.github.com", "*.github.com"));
        assert!(!host_matches_pattern("github.com", "*.github.com"));
        assert!(!host_matches_pattern("evilgithub.com", "*.github.com"));
    }

    #[test]
    fn allowlist_blocks_metadata_private_ips_and_unlisted_domains() {
        let policy = NetworkPolicy::AllowlistProxy {
            allowed_hosts: vec![String::from("api.github.com"), String::from("*.pypi.org")],
            block_private_cidrs: true,
        };
        let guard = DnsGuard::new(&policy);

        assert!(guard.is_host_allowed("api.github.com").is_ok());
        assert!(guard.is_host_allowed("files.pypi.org").is_ok());

        assert!(matches!(
            guard.is_host_allowed("evil.example.com"),
            Err(EgressDenyReason::NotInAllowlist(_))
        ));
        assert!(matches!(
            guard.is_host_allowed("169.254.169.254"),
            Err(EgressDenyReason::ForbiddenIp(_))
        ));
        assert!(matches!(
            guard.is_host_allowed("127.0.0.1"),
            Err(EgressDenyReason::ForbiddenIp(_))
        ));
        assert!(matches!(
            guard.is_host_allowed("10.0.0.1"),
            Err(EgressDenyReason::ForbiddenIp(_))
        ));
        assert!(matches!(
            guard.is_host_allowed("93.184.216.34"),
            Err(EgressDenyReason::NotInAllowlist(_))
        ));
    }

    #[test]
    fn dns_packet_filter_synthesizes_nxdomain_for_denied_domain() {
        let policy = NetworkPolicy::AllowlistProxy {
            allowed_hosts: vec![String::from("api.github.com")],
            block_private_cidrs: true,
        };
        let guard = DnsGuard::new(&policy);

        // Minimal DNS query for "evil.com"
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(b"\x04evil\x03com\x00");
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let resp = guard.filter_dns_packet(&query).expect("nxdomain reply");
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0F, 0x03); // RCODE=3 NXDOMAIN
    }
}
