//! Service detection based on port numbers and banners
//! 
//! Provides fast service identification similar to nmap's service detection

use vajra_common::ServiceMatch;

/// Detect service from port number (comprehensive port mappings)
/// Based on IANA assigned ports and common services
/// Organized by service category for easy maintenance
pub fn detect_service_from_port(port: u16) -> Option<ServiceMatch> {
    let service = match port {
        // File Transfer Protocol
        20 => "ftp-data",
        21 => "ftp",
        990 => "ftps",
        
        // Secure Shell
        22 => "ssh",
        
        // Telnet
        23 => "telnet",
        
        // Simple Mail Transfer Protocol
        25 => "smtp",
        465 => "smtps",
        587 => "submission",
        
        // Domain Name System
        53 => "domain",
        
        // Hypertext Transfer Protocol
        80 => "http",
        443 => "https",
        8000 => "http-alt",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "http-alt",
        3000 => "http-alt",
        5000 => "http-alt",
        
        // Post Office Protocol
        109 => "pop2",
        110 => "pop3",
        995 => "pop3s",
        106 => "pop3pw",
        
        // Internet Message Access Protocol
        143 => "imap",
        220 => "imap3",
        993 => "imaps",
        
        // Remote Procedure Call / Microsoft Services
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        445 => "microsoft-ds",
        3389 => "rdp",
        5985 => "wsman",
        5986 => "wsmans",
        
        // Simple Network Management Protocol
        161 => "snmp",
        162 => "snmptrap",
        
        // Lightweight Directory Access Protocol
        389 => "ldap",
        636 => "ldaps",
        
        // Network Time Protocol
        123 => "ntp",
        
        // Network News Transfer Protocol
        119 => "nntp",
        
        // Border Gateway Protocol
        179 => "bgp",
        
        // Finger Protocol
        79 => "finger",
        
        // Kerberos
        88 => "kerberos",
        
        // Talk / Chat Services
        517 => "talk",
        518 => "ntalk",
        194 => "irc",
        6667 => "irc",
        6697 => "ircs",
        
        // Git
        9418 => "git",
        
        // System Logging
        514 => "syslog",
        
        // Remote Sync
        873 => "rsync",
        
        // Network File System
        2049 => "nfs",
        
        // SOCKS Proxy
        1080 => "socks",
        
        // Squid HTTP Proxy
        3128 => "squid-http",
        
        // Database Services
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        5432 => "postgresql",
        27017 => "mongodb",
        6379 => "redis",
        9200 => "elasticsearch",
        11211 => "memcached",
        
        // Virtual Network Computing
        5900 => "vnc",
        5901 => "vnc-1",
        5902 => "vnc-2",
        
        // Virtual Private Network
        1723 => "pptp",
        1194 => "openvpn",
        500 => "isakmp",
        4500 => "ipsec-nat-t",
        
        // Container & Orchestration
        2375 => "docker",
        2376 => "docker-tls",
        6443 => "kubernetes",
        10250 => "kubelet",
        
        // Message Queue Services
        5672 => "amqp",
        15672 => "rabbitmq",
        1883 => "mqtt",
        8883 => "mqtts",
        
        // Monitoring & Metrics
        9090 => "prometheus",
        
        // Common high ports (1000-2000 range)
        1000 => "cadlock",
        2000 => "cisco-sccp",
        _ => return None,
    };
    
    Some(ServiceMatch::new(service))
}

/// Detect service from banner content with version extraction
pub fn detect_service_from_banner(banner: &str, port: u16) -> Option<ServiceMatch> {
    let banner_lower = banner.to_lowercase();
    
    // HTTP/HTTPS detection with server version
    if banner_lower.starts_with("http/") || banner_lower.contains("server:") {
        let (service, product, version) = extract_http_info(&banner_lower, port);
        let mut svc = ServiceMatch::new(service);
        if let Some(p) = product {
            svc = svc.with_product(p);
        }
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // SSH detection with version
    if banner_lower.contains("ssh-") || banner_lower.starts_with("ssh") {
        let (product, version) = extract_ssh_info(&banner_lower);
        let mut svc = ServiceMatch::new("ssh");
        if let Some(p) = product {
            svc = svc.with_product(p);
        }
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // FTP detection with version
    if banner_lower.starts_with("220") && banner_lower.contains("ftp") {
        let (product, version) = extract_ftp_info(&banner_lower);
        let mut svc = ServiceMatch::new("ftp");
        if let Some(p) = product {
            svc = svc.with_product(p);
        }
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // SMTP detection with version
    if banner_lower.starts_with("220") && (banner_lower.contains("smtp") || banner_lower.contains("mail") || banner_lower.contains("esmtp")) {
        let (product, version) = extract_smtp_info(&banner_lower);
        let mut svc = ServiceMatch::new("smtp");
        if let Some(p) = product {
            svc = svc.with_product(p);
        }
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // POP3 detection
    if banner_lower.starts_with("+ok") || banner_lower.contains("pop3") {
        let version = extract_pop3_version(&banner_lower);
        let mut svc = ServiceMatch::new("pop3");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // IMAP detection
    if banner_lower.starts_with("* ok") || banner_lower.contains("imap") {
        let (product, version) = extract_imap_info(&banner_lower);
        let mut svc = ServiceMatch::new("imap");
        if let Some(p) = product {
            svc = svc.with_product(p);
        }
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // MySQL detection with version
    if banner_lower.contains("mysql") || (port == 3306 && banner.as_bytes().iter().any(|&b| b == 0)) {
        let version = extract_mysql_version(banner);
        let mut svc = ServiceMatch::new("mysql");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // PostgreSQL detection
    if banner_lower.contains("postgresql") || (banner.len() >= 4 && banner.as_bytes()[0..4.min(banner.len())].iter().all(|&b| b == 0)) {
        let version = extract_postgresql_version(&banner_lower);
        let mut svc = ServiceMatch::new("postgresql");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // Redis detection with version
    if banner_lower.contains("redis") || banner.starts_with("+") {
        let version = extract_redis_version(&banner_lower);
        let mut svc = ServiceMatch::new("redis");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // MongoDB detection
    if banner_lower.contains("mongodb") || port == 27017 {
        let version = extract_mongodb_version(&banner_lower);
        let mut svc = ServiceMatch::new("mongodb");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // Elasticsearch detection
    if banner_lower.contains("elasticsearch") || port == 9200 {
        let version = extract_elasticsearch_version(&banner_lower);
        let mut svc = ServiceMatch::new("elasticsearch");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // Telnet detection
    if banner_lower.contains("telnet") || banner_lower.contains("login:") {
        return Some(ServiceMatch::new("telnet"));
    }
    
    // VNC detection
    if banner_lower.contains("rfb") || banner_lower.contains("vnc") {
        let version = extract_vnc_version(&banner_lower);
        let mut svc = ServiceMatch::new("vnc");
        if let Some(v) = version {
            svc = svc.with_version(v);
        }
        return Some(svc);
    }
    
    // RDP detection (check for RDP protocol signature in bytes)
    if banner.len() >= 11 {
        let rdp_sig: [u8; 11] = [0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00];
        if banner.as_bytes()[0..11] == rdp_sig {
            return Some(ServiceMatch::new("rdp"));
        }
    }
    
    // Docker detection
    if banner_lower.contains("docker") || port == 2375 || port == 2376 {
        return Some(ServiceMatch::new("docker"));
    }
    
    // Kubernetes detection
    if banner_lower.contains("kubernetes") || port == 6443 {
        return Some(ServiceMatch::new("kubernetes"));
    }
    
    None
}

/// Extract HTTP server info (product and version)
fn extract_http_info(banner: &str, port: u16) -> (String, Option<String>, Option<String>) {
    let service = if port == 443 || banner.contains("ssl") || banner.contains("tls") {
        "https"
    } else {
        "http"
    };
    
    // Extract Server header: "Server: nginx/1.18.0"
    if let Some(server_idx) = banner.find("server:") {
        let server_line = &banner[server_idx..];
        if let Some(end) = server_line.find('\n') {
            let server_val = server_line[7..end].trim();
            let parts: Vec<&str> = server_val.split('/').collect();
            if parts.len() >= 2 {
                let product = parts[0].trim().to_string();
                let version = parts[1].split_whitespace().next().unwrap_or("").to_string();
                return (service.to_string(), Some(product), Some(version));
            } else if !server_val.is_empty() {
                return (service.to_string(), Some(server_val.to_string()), None);
            }
        }
    }
    
    // Try to detect common servers from other headers
    if banner.contains("nginx") {
        return (service.to_string(), Some("nginx".to_string()), extract_version_number(banner));
    } else if banner.contains("apache") {
        return (service.to_string(), Some("Apache".to_string()), extract_version_number(banner));
    } else if banner.contains("iis") || banner.contains("microsoft") {
        return (service.to_string(), Some("IIS".to_string()), extract_version_number(banner));
    }
    
    (service.to_string(), None, None)
}

/// Extract SSH product and version
fn extract_ssh_info(banner: &str) -> (Option<String>, Option<String>) {
    // Pattern: "SSH-2.0-OpenSSH_8.2" or "SSH-1.99-OpenSSH_7.4"
    if let Some(start) = banner.find("ssh-") {
        let rest = &banner[start..];
        let ssh_line = if let Some(end) = rest.find(|c: char| c == '\n' || c == '\r' || c == ' ') {
            &rest[..end]
        } else {
            rest
        };
        
        // Split by dash: SSH-2.0-OpenSSH_8.2
        let parts: Vec<&str> = ssh_line.split('-').collect();
        if parts.len() >= 3 {
            let product = parts[2].split('_').next().unwrap_or("").to_string();
            let version = parts[2].split('_').nth(1).map(|s| s.to_string());
            return (Some(product), version);
        }
    }
    (None, None)
}

/// Extract FTP product and version
fn extract_ftp_info(banner: &str) -> (Option<String>, Option<String>) {
    // Pattern: "220 ProFTPD 1.3.6 Server"
    let parts: Vec<&str> = banner.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        let part_lower = part.to_lowercase();
        if part_lower.contains("proftpd") || part_lower.contains("vsftpd") || 
           part_lower.contains("pure-ftpd") || part_lower.contains("filezilla") {
            let product = part.to_string();
            let version = if i + 1 < parts.len() {
                Some(parts[i + 1].to_string())
            } else {
                extract_version_number(banner)
            };
            return (Some(product), version);
        }
    }
    (None, extract_version_number(banner))
}

/// Extract SMTP product and version
fn extract_smtp_info(banner: &str) -> (Option<String>, Option<String>) {
    // Pattern: "220 mail.example.com ESMTP Postfix 3.4.0"
    let parts: Vec<&str> = banner.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        let part_lower = part.to_lowercase();
        if part_lower.contains("postfix") || part_lower.contains("sendmail") || 
           part_lower.contains("exim") || part_lower.contains("microsoft") ||
           part_lower.contains("exchange") {
            let product = part.to_string();
            let version = if i + 1 < parts.len() {
                Some(parts[i + 1].to_string())
            } else {
                extract_version_number(banner)
            };
            return (Some(product), version);
        }
    }
    (None, extract_version_number(banner))
}

/// Extract POP3 version
fn extract_pop3_version(banner: &str) -> Option<String> {
    extract_version_number(banner)
}

/// Extract IMAP product and version
fn extract_imap_info(banner: &str) -> (Option<String>, Option<String>) {
    // Pattern: "* OK Dovecot ready."
    if banner.contains("dovecot") {
        return (Some("Dovecot".to_string()), extract_version_number(banner));
    } else if banner.contains("cyrus") {
        return (Some("Cyrus".to_string()), extract_version_number(banner));
    }
    (None, extract_version_number(banner))
}

/// Extract MySQL version
fn extract_mysql_version(banner: &str) -> Option<String> {
    // MySQL version is usually in the initial handshake packet
    // Look for version patterns
    extract_version_number(banner)
}

/// Extract PostgreSQL version
fn extract_postgresql_version(banner: &str) -> Option<String> {
    // Pattern: "PostgreSQL 13.2"
    if let Some(idx) = banner.find("postgresql") {
        let rest = &banner[idx..];
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            return Some(parts[1].to_string());
        }
    }
    extract_version_number(banner)
}

/// Extract Redis version
fn extract_redis_version(banner: &str) -> Option<String> {
    // Pattern: "Redis server v=6.2.5"
    if let Some(idx) = banner.find("redis") {
        let rest = &banner[idx..];
        if let Some(v_idx) = rest.find("v=") {
            let version_part = &rest[v_idx + 2..];
            if let Some(end) = version_part.find(|c: char| c == ' ' || c == '\n' || c == '\r') {
                return Some(version_part[..end].to_string());
            }
        }
    }
    extract_version_number(banner)
}

/// Extract MongoDB version
fn extract_mongodb_version(banner: &str) -> Option<String> {
    // Pattern: "MongoDB 4.4.5"
    if let Some(idx) = banner.find("mongodb") {
        let rest = &banner[idx..];
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            return Some(parts[1].to_string());
        }
    }
    extract_version_number(banner)
}

/// Extract Elasticsearch version
fn extract_elasticsearch_version(banner: &str) -> Option<String> {
    // Usually in JSON response: "version": {"number": "7.10.0"}
    if let Some(idx) = banner.find("\"number\"") {
        let rest = &banner[idx..];
        if let Some(start) = rest.find('"') {
            let version_part = &rest[start + 1..];
            if let Some(end) = version_part.find('"') {
                return Some(version_part[..end].to_string());
            }
        }
    }
    extract_version_number(banner)
}

/// Extract VNC version
fn extract_vnc_version(banner: &str) -> Option<String> {
    // Pattern: "RFB 003.008"
    if let Some(idx) = banner.find("rfb") {
        let rest = &banner[idx..];
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Generic version number extractor (looks for version patterns)
/// Uses regex to find version numbers in text (e.g., "1.2.3", "v2.0", "version 3.4.5")
fn extract_version_number(text: &str) -> Option<String> {
    use once_cell::sync::Lazy;
    use regex::Regex;
    
    static VERSION_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:v|version)?\s*(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)").unwrap()
    });
    
    if let Some(captures) = VERSION_RE.captures(text) {
        if let Some(version) = captures.get(1) {
            return Some(version.as_str().to_string());
        }
    }
    None
}

/// Detect service from port and banner (combines both methods)
pub fn detect_service(port: u16, banner: Option<&str>) -> Option<ServiceMatch> {
    // First try banner-based detection (more accurate)
    if let Some(b) = banner {
        if let Some(service) = detect_service_from_banner(b, port) {
            return Some(service);
        }
    }
    
    // Fall back to port-based detection
    detect_service_from_port(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_detection() {
        assert_eq!(detect_service_from_port(80).unwrap().service, "http");
        assert_eq!(detect_service_from_port(443).unwrap().service, "https");
        assert_eq!(detect_service_from_port(22).unwrap().service, "ssh");
        assert_eq!(detect_service_from_port(3306).unwrap().service, "mysql");
    }

    #[test]
    fn test_banner_detection() {
        let http_banner = "HTTP/1.1 200 OK\r\nServer: nginx";
        assert_eq!(detect_service_from_banner(http_banner, 80).unwrap().service, "http");
        
        let ssh_banner = "SSH-2.0-OpenSSH_8.2";
        let ssh_service = detect_service_from_banner(ssh_banner, 22).unwrap();
        assert_eq!(ssh_service.service, "ssh");
    }

    #[test]
    fn test_combined_detection() {
        // Banner takes precedence
        let service = detect_service(8080, Some("HTTP/1.1 200 OK"));
        assert_eq!(service.unwrap().service, "http");
        
        // Port fallback
        let service = detect_service(80, None);
        assert_eq!(service.unwrap().service, "http");
    }
}

