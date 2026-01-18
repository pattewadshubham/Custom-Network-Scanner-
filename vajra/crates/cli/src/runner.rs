// runner.rs
use anyhow::{anyhow, Result, Context};
use std::{net::{IpAddr, Ipv4Addr, ToSocketAddrs}, sync::Arc, time::{Duration, Instant}};
use tracing::info;
use vajra_orchestrator::Orchestrator;
use vajra_scanner_tcp::TcpScanner;
use vajra_scanner_syn::SynScanner;
use vajra_common::{ScanJob, Target};
use crate::output::print_results;
use vajra_target_resolver::TargetResolver;

pub async fn run_scan(
    targets: String,
    ports: String,
    concurrency: usize,
    rate_limit: u64,
    timeout: u64,
    banner_timeout: u64,
    output_format: String,
    preset: String,
    scan_type: Option<String>,
) -> Result<()> {
    let scan_type = scan_type.unwrap_or_else(|| "tcp".to_string());
    info!("Starting scan...");
    info!("Targets: {}", targets);
    info!("Ports: {}", ports);
    info!("Concurrency: {}", concurrency);
    info!("Rate limit: {}/s", rate_limit);
    info!("Scanner type: {}", scan_type);

    // Parse targets and ports
    let ips = TargetResolver::resolve_targets(&targets).await?;
    let port_list = parse_ports(&ports)?;

    // Apply preset adjustments for accuracy vs speed
    // 'accurate' preset increases timeout and enables retries/bigger banner timeout
    let mut effective_timeout = timeout;
    let mut effective_banner_timeout = banner_timeout;
    let mut effective_retries = 0u32;
    if preset == "accurate" {
        effective_timeout = effective_timeout.max(3000);
        effective_banner_timeout = effective_banner_timeout.max(1000);
        effective_retries = 2;
    }
    
    // Build scan target list (IP × Port combinations)
    let mut scan_targets = Vec::new();
    for ip in &ips {
        for port in &port_list {
            scan_targets.push(Target::new(*ip, *port));
        }
    }
    
    // Log scan configuration
    info!("Found {} IPv4 address(es)", ips.len());
    info!("Port range: {} port(s)", port_list.len());
    if ips.len() > 1 {
        info!("Total scan targets: {} ({} IPs × {} ports)", scan_targets.len(), ips.len(), port_list.len());
    } else {
        info!("Total scan targets: {} port(s)", scan_targets.len());
    }

    // Initialize orchestrator
    let mut orchestrator = Orchestrator::new(concurrency, rate_limit as u32);

    // Register scanner
    match scan_type.as_str() {
        "tcp" => {
                let optimized_timeout = Duration::from_millis(effective_timeout.min(5000));
                let tcp_scanner = TcpScanner::new()
                    .with_timeout(optimized_timeout)
                    .with_retries(effective_retries)
                    .with_banner_timeout(Duration::from_millis(effective_banner_timeout));
            orchestrator.add_scanner("tcp", Arc::new(tcp_scanner));
        }
        "syn" => {
            vajra_scanner_syn::init()
                .context("Failed to initialize SYN scanner. Make sure you have CAP_NET_RAW capabilities or run with sudo.")?;
            
            let syn_scanner = SynScanner::new()
                .with_timeout(Duration::from_millis(timeout))
                .with_retries(1);
            orchestrator.add_scanner("syn", Arc::new(syn_scanner));
        }
        _ => return Err(anyhow!("Invalid scanner type '{}'", scan_type)),
    }

    // Submit job and run
    let job = ScanJob::new(scan_targets);
    orchestrator.submit_job(job).await?;
    
    // Start timing the scan
    let scan_start = Instant::now();
    orchestrator.run(Some(&scan_type)).await?;
    let scan_duration = scan_start.elapsed();

    // Collect results and print
    let results = orchestrator.get_results().await;
    print_results(&results, &output_format, scan_duration)?;
    Ok(())
}

// target parsing/resolution is delegated to `vajra-target-resolver`

/// Parses a port string like "80,443,1000-1010" into a vector of u16 ports
fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow!("Invalid port range: {}", part));
            }

            let start: u16 = range[0].parse().context(format!("Invalid start port: {}", range[0]))?;
            let end: u16 = range[1].parse().context(format!("Invalid end port: {}", range[1]))?;

            if start > end {
                return Err(anyhow!("Invalid range: start > end"));
            }

            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().context(format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        Err(anyhow!("No ports specified"))
    } else {
        Ok(ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn _test_parse_single_ip_placeholder() {
        // moved to target_resolver tests
    }

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_multiple() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("1-3").unwrap();
        assert_eq!(ports, vec![1, 2, 3]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_parse_ports_whitespace() {
        let ports = parse_ports(" 80 , 443 ").unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_parse_ports_empty() {
        assert!(parse_ports("").is_err());
        assert!(parse_ports("   ").is_err());
        assert!(parse_ports(",,,").is_err());
    }

    #[test]
    fn test_parse_ports_invalid() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("80-").is_err());
        assert!(parse_ports("-80").is_err());
        assert!(parse_ports("90-80").is_err());
    }

    #[test]
    fn test_parse_targets_async() {
        let rt = Runtime::new().unwrap();
    // single IP via target_resolver
    let ips = rt.block_on(TargetResolver::resolve_targets("8.8.8.8")).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8,8,8,8))]);

    // multiple comma separated
    let ips = rt.block_on(TargetResolver::resolve_targets("8.8.8.8,1.1.1.1")).unwrap();
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(8,8,8,8))));
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1,1,1,1))));

    // range
    let ips = rt.block_on(TargetResolver::resolve_targets("192.168.1.1-192.168.1.3")).unwrap();
    assert_eq!(ips.len(), 3);
    }
}


