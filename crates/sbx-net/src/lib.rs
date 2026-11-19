//! Zero-trust network namespace isolation, DNS/SNI guard, and Secret Injector proxy.

pub mod dns_guard;
pub mod egress_proxy;
pub mod netns;

pub use dns_guard::{host_matches_pattern, normalize_host, DnsGuard, EgressDenyReason};
pub use egress_proxy::{extract_tls_sni, inject_secrets_for_host, EgressProxy, SecretVault};
pub use netns::{
    bind_in_netns_tcp_listener, bring_up_loopback, is_forbidden_ip, parse_ip_literal, recv_fd,
    send_fd,
};
pub use sbx_proto::{NetworkPolicy, SecretRule};
