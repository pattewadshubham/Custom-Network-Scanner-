//! Output formatting for scan results

use anyhow::Result;
use serde_json;
use std::time::Duration;
use vajra_common::{PortState, ProbeResult};

/// Print scan results in the specified format
pub fn print_results(results: &[ProbeResult], format: &str, scan_duration: Duration) -> Result<()> {
    // Normalize format string
    let format = format.trim().to_lowercase();
    match format.as_str() {
        "json" | "j" => print_json(results, scan_duration)?,
        "csv" | "c" => print_csv(results)?,
        "table" | "text" | "t" | "" => print_table(results, scan_duration),
        _ => {
            eprintln!("Warning: Unknown format '{}', using default table format", format);
            print_table(results, scan_duration);
        }
    }
    Ok(())
}

/// Print results as ASCII table (sorted by IP and port)
fn print_table(results: &[ProbeResult], scan_duration: Duration) {
    if results.is_empty() {
        println!("\nNo results to display.\n");
        return;
    }

    // Sort results by IP address first, then by port number
    let mut sorted_results = results.to_vec();
    sorted_results.sort_by(|a, b| {
        a.target.ip.cmp(&b.target.ip)
            .then_with(|| a.target.port.cmp(&b.target.port))
    });

    println!("\n{:-<80}", "");
    println!(
        "{:<20} {:<8} {:<15} {:<40}",
        "HOST", "PORT", "STATE", "SERVICE/VERSION"
    );
    println!("{:-<80}", "");

    let mut open_count = 0;
    let mut closed_count = 0;
    let mut filtered_count = 0;

    for result in &sorted_results {
        match result.state {
            PortState::Open => {
                // Build service display string with product and version
                let service_display = format_service_display(result);
                
                println!(
                    "{:<20} {:<8} {:<15} {:<40}",
                    result.target.ip.to_string(),
                    result.target.port,
                    result.state,
                    service_display
                );
                open_count += 1;
            }
            PortState::Filtered | PortState::OpenFiltered => {
                // Show filtered ports with service names and versions (like nmap)
                let service_display = format_service_display(result);
                
                println!(
                    "{:<20} {:<8} {:<15} {:<40}",
                    result.target.ip.to_string(),
                    result.target.port,
                    result.state,
                    service_display
                );
                filtered_count += 1;
            }
            PortState::Closed => {
                closed_count += 1;
            }
        }
    }

    println!("{:-<80}", "");
    println!("\n📊 Summary:");
    println!("  Total scanned: {}", results.len());
    println!("  ✓ Open ports: {}", open_count);
    println!("  ✗ Closed ports: {}", closed_count);
    println!("  ⊘ Filtered: {}", filtered_count);
    println!("  ⏱️  Scan duration: {}", format_duration(scan_duration));
    println!();
}

/// Print results as JSON
fn print_json(results: &[ProbeResult], scan_duration: Duration) -> Result<()> {
    use serde_json::json;
    
    // Group results by IP for better organization
    let mut results_by_ip = std::collections::BTreeMap::new();
    for result in results {
        results_by_ip
            .entry(result.target.ip.to_string())
            .or_insert_with(Vec::new)
            .push(serde_json::to_value(result)?);
    }
    
    let output = json!({
        "scan_info": {
            "duration_seconds": scan_duration.as_secs_f64(),
            "duration_formatted": format_duration(scan_duration),
            "total_targets": results_by_ip.len(),
            "total_scanned": results.len()
        },
        "results": results_by_ip
    });
    
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Print results as CSV
fn print_csv(results: &[ProbeResult]) -> Result<()> {
    // Enhanced CSV headers with more information
    println!("ip,port,state,service,product,version,banner,rtt_ms");

    for result in results {
        // Get service info
        let service = result.service.as_ref().map(|s| s.service.as_str()).unwrap_or("");
        let product = result.service.as_ref().and_then(|s| s.product.as_ref()).map(|s| s.as_str()).unwrap_or("");
        let version = result.service.as_ref().and_then(|s| s.version.as_ref()).map(|s| s.as_str()).unwrap_or("");
        
        // Escape and format banner
        let banner = result
            .banner
            .as_ref()
            .map(|b| {
                let escaped = b
                    .replace('"', "\"\"")
                    .replace('\n', " ")
                    .replace('\r', "");
                format!("\"{}\"", escaped)
            })
            .unwrap_or_else(|| "\"\"".to_string());

        // Print CSV line with enhanced fields
        println!(
            "{},{},{},\"{}\",\"{}\",\"{}\",{},{}",
            result.target.ip,
            result.target.port,
            result.state,
            service,
            product,
            version,
            banner,
            result.rtt.as_millis()
        );
    }

    Ok(())
}

/// Format service display string with product and version information
/// Shows: service (product) version
fn format_service_display(result: &ProbeResult) -> String {
    if let Some(ref service_match) = result.service {
        let mut display = service_match.service.clone();
        
        // Add product name if available
        if let Some(ref product) = service_match.product {
            display.push_str(&format!(" ({})", product));
        }
        
        // Add version if available
        if let Some(ref version) = service_match.version {
            display.push_str(&format!(" {}", version));
        }
        
        // Truncate if too long
        if display.len() > 38 {
            format!("{}...", &display[..35])
        } else {
            display
        }
    } else if let Some(ref banner) = result.banner {
        // Try to extract service from banner first line
        banner.lines().next()
            .map(|s| {
                if s.len() > 38 {
                    format!("{}...", &s[..35])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    }
}

/// Format duration in a human-readable way
fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();
    
    if total_secs == 0 {
        format!("{}ms", millis)
    } else if total_secs < 60 {
        if millis > 0 {
            format!("{}.{:03}s", total_secs, millis)
        } else {
            format!("{}s", total_secs)
        }
    } else {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        if secs > 0 {
            format!("{}m {}s", mins, secs)
        } else {
            format!("{}m", mins)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn test_print_results_json() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = vajra_common::Target::new(ip, 80);
        let result = ProbeResult::new(target, PortState::Open)
            .with_rtt(Duration::from_millis(10));

        let results = vec![result];
        let json_result = print_json(&results, Duration::from_secs(5));
        assert!(json_result.is_ok());
    }

    #[test]
    fn test_print_results_csv() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = vajra_common::Target::new(ip, 80);
        let result = ProbeResult::new(target, PortState::Open)
            .with_rtt(Duration::from_millis(10));

        let results = vec![result];
        let csv_result = print_csv(&results);
        assert!(csv_result.is_ok());
    }

    #[test]
    fn test_print_results_table() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let target = vajra_common::Target::new(ip, 80);
        let result = ProbeResult::new(target, PortState::Open)
            .with_rtt(Duration::from_millis(10));

        let results = vec![result];
        print_table(&results, Duration::from_secs(5));
    }
    
    #[test]
    fn test_format_duration() {
        use super::format_duration;
        
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_millis(5500)), "5.500s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
    }
}
