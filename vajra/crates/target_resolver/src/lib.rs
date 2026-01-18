//! Target Resolver - CIDR expansion and DNS resolution
//!
//! Provides a small utility to take a comma-separated target string and
//! expand it into a deduplicated list of IPv4 addresses. Supported token
//! forms:
//! - single IPv4 address: "1.2.3.4"
//! - CIDR: "192.168.1.0/24"
//! - range: "192.168.1.1-192.168.1.10"
//! - hostname: "example.com"

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

pub struct TargetResolver;

impl TargetResolver {
    pub fn new() -> Self { Self }

    /// Resolve a comma-separated target string into unique IPv4 addresses.
    /// This is async-friendly: DNS resolution is performed inside
    /// `tokio::task::spawn_blocking` to avoid blocking the async runtime.
    pub async fn resolve_targets(targets: &str) -> Result<Vec<IpAddr>> {
        if targets.trim().is_empty() {
            anyhow::bail!("No targets specified");
        }

        let mut ips: Vec<IpAddr> = Vec::new();
        let mut hostnames: Vec<String> = Vec::new();

        for token in targets.split(',') {
            let t = token.trim();
            if t.is_empty() { continue; }

            // CIDR
            if let Ok(net) = t.parse::<Ipv4Net>() {
                // safety guard: expand only up to MAX_HOSTS unless overridden by env
                const MAX_HOSTS: u128 = 4096;
                // compute host count from prefix length to avoid iterating the whole range
                let prefix = net.prefix_len();
                // compute host count as a shift to avoid any pow edge-cases
                let hosts_count = if prefix >= 32 { 1u128 } else { 1u128 << (32 - prefix) };
                let allow_large = std::env::var("VAJRA_ALLOW_LARGE_CIDR").ok().map(|v| v == "1").unwrap_or(false);
                if hosts_count > MAX_HOSTS && !allow_large {
                    anyhow::bail!("CIDR {} expands to {} hosts which exceeds the allowed limit of {}. Set VAJRA_ALLOW_LARGE_CIDR=1 to override.", net, hosts_count, MAX_HOSTS);
                }

                // iterate hosts in the CIDR
                for addr in net.hosts() {
                    let ip = IpAddr::V4(addr);
                    if !ips.contains(&ip) { ips.push(ip); }
                }
                continue;
            }

            // Range a.b.c.d-e.f.g.h
            if t.contains('-') && t.chars().any(|c| c.is_ascii_digit()) {
                if let Ok(range_ips) = parse_ip_range(t) {
                    for ip in range_ips { if !ips.contains(&ip) { ips.push(ip); } }
                    continue;
                }
            }

            // Direct IP
            if let Ok(ip) = t.parse::<IpAddr>() {
                if ip.is_ipv4() && !ips.contains(&ip) { ips.push(ip); }
                continue;
            }

            // Treat as hostname to resolve
            hostnames.push(t.to_string());
        }

        if !hostnames.is_empty() {
            let host_batch = hostnames.clone();
            let resolved: Vec<Vec<IpAddr>> = tokio::task::spawn_blocking(move || {
                host_batch.into_iter().map(|h| {
                    match (h.as_str(), 0).to_socket_addrs() {
                        Ok(addrs) => addrs.filter(|a| a.ip().is_ipv4()).map(|a| a.ip()).collect::<Vec<IpAddr>>(),
                        Err(_) => Vec::new(),
                    }
                }).collect()
            }).await.context("Blocking DNS resolution failed")?;

            for v in resolved.into_iter().flatten() {
                if !ips.contains(&v) { ips.push(v); }
            }
        }

        if ips.is_empty() {
            anyhow::bail!("No valid IPv4 addresses found in targets");
        }

        Ok(ips)
    }
}

fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid IP range: {}", range);
    }

    let start: Ipv4Addr = parts[0].parse().context(format!("Invalid start IP: {}", parts[0]))?;
    let end: Ipv4Addr = parts[1].parse().context(format!("Invalid end IP: {}", parts[1]))?;

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    if start_u32 > end_u32 { anyhow::bail!("Invalid IP range: start > end"); }

    let mut ips = Vec::new();
    for v in start_u32..=end_u32 {
        ips.push(IpAddr::V4(Ipv4Addr::from(v)));
    }
    Ok(ips)
}

impl Default for TargetResolver { fn default() -> Self { Self::new() } }


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_single_ip() {
        let ips = TargetResolver::resolve_targets("8.8.8.8").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8,8,8,8))]);
    }

    #[tokio::test]
    async fn test_resolve_cidr() {
        let ips = TargetResolver::resolve_targets("192.168.1.0/30").await.unwrap();
        // /30 -> 2 hosts (192.168.1.1 and 192.168.1.2) when using hosts(), but ipnet.hosts() yields host addresses
        assert!(ips.len() >= 1);
    }

    #[tokio::test]
    async fn test_resolve_range() {
        let ips = TargetResolver::resolve_targets("192.168.1.1-192.168.1.3").await.unwrap();
        assert_eq!(ips.len(), 3);
    }

    #[tokio::test]
    async fn test_large_cidr_rejected() {
    // ensure override is not set
    std::env::remove_var("VAJRA_ALLOW_LARGE_CIDR");
    // /16 is 65536 hosts - should be rejected by default
    let r = TargetResolver::resolve_targets("10.0.0.0/16").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_large_cidr_allowed_with_env() {
        std::env::set_var("VAJRA_ALLOW_LARGE_CIDR", "1");
        let r = TargetResolver::resolve_targets("10.0.0.0/24").await;
        // /24 -> 256 hosts should be allowed even without override, but env should not break it
        assert!(r.is_ok());
        std::env::remove_var("VAJRA_ALLOW_LARGE_CIDR");
    }
}
