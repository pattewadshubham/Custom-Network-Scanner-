// crates/scanner_tcp/src/scanner.rs
//! TCP connect scanner implementation

use anyhow::Result;
use async_trait::async_trait;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::instrument;

use vajra_common::{PortState, ProbeResult, Scanner, Target};
use crate::banner::BannerGrabber;
use vajra_fingerprint::detect_service;

/// Simple TCP connect scanner implementation.
pub struct TcpScanner {
    timeout: Duration,
    retries: u32,
    banner_timeout: Duration,
}

impl TcpScanner {
    /// Create a new scanner with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connect/read timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retry count for connect attempts.
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Set banner grab timeout
    pub fn with_banner_timeout(mut self, timeout: Duration) -> Self {
        self.banner_timeout = timeout;
        self
    }

    /// Try to establish a TCP connection with optimized timeouts.
    /// Uses shorter initial timeout for faster closed port detection.
    #[instrument(skip(self))]
    async fn try_connect(&self, addr: SocketAddr) -> Result<TcpStream> {
        // Use shorter timeout for initial attempt (closed ports respond quickly)
        // This matches nmap's behavior: fast detection of closed ports
        let initial_timeout = Duration::from_millis(400.min(self.timeout.as_millis() as u64));
        
        // Fast path: no retries
        if self.retries == 0 {
            match timeout(initial_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    // Use OS error codes for accurate detection
                    match e.kind() {
                        ErrorKind::ConnectionRefused => {
                            // Closed port - return immediately
                            return Err(anyhow::Error::from(e).context("Connection refused"));
                        }
                        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                            // Might be filtered - try once more with full timeout
                            match timeout(self.timeout, TcpStream::connect(addr)).await {
                                Ok(Ok(stream)) => return Ok(stream),
                                Ok(Err(e2)) => return Err(anyhow::Error::from(e2)),
                                Err(_) => return Err(anyhow::anyhow!("Connection timeout")),
                            }
                        }
                        _ => {
                            // Other errors - try once more with full timeout
                            match timeout(self.timeout, TcpStream::connect(addr)).await {
                                Ok(Ok(stream)) => return Ok(stream),
                                Ok(Err(e2)) => return Err(anyhow::Error::from(e2)),
                                Err(_) => return Err(anyhow::anyhow!("Connection timeout")),
                            }
                        }
                    }
                }
                Err(_) => {
                    // Initial timeout - try once more with full timeout for filtered ports
                    match timeout(self.timeout, TcpStream::connect(addr)).await {
                        Ok(Ok(stream)) => return Ok(stream),
                        Ok(Err(e)) => return Err(anyhow::Error::from(e)),
                        Err(_) => return Err(anyhow::anyhow!("Connection timeout")),
                    }
                }
            }
        }

        // Retry path (only if retries > 0)
        let mut last_error: Option<anyhow::Error> = None;
        for attempt in 0..=self.retries {
            if attempt > 0 {
                // Minimal backoff for retries
                let backoff = Duration::from_millis(50 * attempt as u64);
                tokio::time::sleep(backoff).await;
            }

            let attempt_timeout = if attempt == 0 { initial_timeout } else { self.timeout };
            match timeout(attempt_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_error = Some(anyhow::Error::from(e)),
                Err(_) => last_error = Some(anyhow::anyhow!("Connection timeout")),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("unknown connect error")))
    }
}

impl Default for TcpScanner {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(800), // 800ms timeout (nmap uses adaptive ~500-1000ms)
            retries: 0, // No retries by default - rely on concurrency for speed
            banner_timeout: Duration::from_millis(300), // Banner timeout (300ms) to improve version grabs
        }
    }
}

#[async_trait]
impl Scanner for TcpScanner {
    /// Scan a single target and produce a ProbeResult.
    async fn scan(&self, target: &Target) -> Result<ProbeResult> {
        let addr = SocketAddr::new(target.ip, target.port);
        let start = Instant::now();

        match self.try_connect(addr).await {
            Ok(mut stream) => {
                let rtt = start.elapsed();
                
                // Fast banner grab: only for common service ports to save time
                // Expanded list for better service detection
                let should_grab_banner = matches!(
                    target.port,
                    21 | 22 | 25 | 80 | 110 | 143 | 443 | 465 | 587 | 993 | 995 | 
                    3306 | 5432 | 6379 | 27017 | 9200 | 8080 | 8443 | 8000 | 8888 | 9000
                );
                
                let banner = if should_grab_banner {
                    let banner_grabber = BannerGrabber::new(self.banner_timeout);
                    // Use a race: try banner grab but don't wait too long
                    tokio::time::timeout(
                        self.banner_timeout,
                        banner_grabber.grab(&mut stream)
                    )
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                } else {
                    None
                };

                // Detect service from port and/or banner
                let service = detect_service(target.port, banner.as_deref());
                
                let mut result = ProbeResult::new(target.clone(), PortState::Open).with_rtt(rtt);
                if let Some(b) = banner {
                    result = result.with_banner(b);
                }
                if let Some(s) = service {
                    result = result.with_service(s);
                }
                Ok(result)
            }
            Err(e) => {
                let rtt = start.elapsed();
                let err_str = e.to_string().to_lowercase();
                
                // Better port state detection using OS error codes and RTT
                // Closed ports: ConnectionRefused error (RTT typically < 100ms)
                // Filtered ports: Timeout or other errors (RTT >= timeout)
                let state = {
                    // Try to extract the underlying IO error from the error chain
                    let mut current: Option<&dyn std::error::Error> = Some(&*e);
                    let mut found_io_error = false;
                    let mut io_kind = None;
                    
                    // Walk the error chain to find an IO error
                    while let Some(err) = current {
                        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                            io_kind = Some(io_err.kind());
                            found_io_error = true;
                            break;
                        }
                        current = err.source();
                    }
                    
                    // Use OS error kind if found, otherwise fall back to string matching and RTT
                    if found_io_error {
                        match io_kind.unwrap() {
                            ErrorKind::ConnectionRefused => PortState::Closed,
                            ErrorKind::TimedOut => PortState::Filtered,
                            _ => {
                                // Fall back to string matching and RTT
                                if err_str.contains("refused") {
                                    PortState::Closed
                                } else if err_str.contains("timeout") || rtt >= self.timeout {
                                    PortState::Filtered
                                } else if rtt < Duration::from_millis(100) {
                                    PortState::Closed
                                } else {
                                    PortState::Filtered
                                }
                            }
                        }
                    } else if err_str.contains("refused") {
                        PortState::Closed
                    } else if err_str.contains("timeout") || rtt >= self.timeout {
                        PortState::Filtered
                    } else if rtt < Duration::from_millis(100) {
                        PortState::Closed
                    } else {
                        PortState::Filtered
                    }
                };
                
                // Detect service from port number for all port states (like nmap)
                let service = vajra_fingerprint::detect_service_from_port(target.port);
                let mut result = ProbeResult::new(target.clone(), state).with_rtt(rtt);
                if let Some(s) = service {
                    result = result.with_service(s);
                }
                Ok(result)
            }
        }
    }

    fn name(&self) -> &str {
        "TCP Connect Scanner"
    }

    fn requires_root(&self) -> bool {
        false
    }
}
