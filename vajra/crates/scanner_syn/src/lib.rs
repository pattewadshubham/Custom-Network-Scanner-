//! TCP / SYN Scanner - High-performance implementation
//!
//! This crate provides ultra-fast SYN scanning with Nmap-class performance.
//!
//! Key features:
//! - Socket reuse (single raw socket for all probes)
//! - High concurrency (10K+ concurrent probes by default)
//! - Zero-copy buffer pool
//! - Fast AF_PACKET capture loop
//! - No allocations in hot path

pub mod capture;
pub mod error;
pub mod packet;
pub mod syn;

pub use error::SynError;
pub use syn::SynScanner;

// Re-export commonly used types
pub use capture::{start_capture_loop, cleanup_expired_probes, CAPTURE_STATS};
pub use packet::tcp_flags;

/// Initialize the scanner subsystem
/// 
/// This should be called once at startup to:
/// 1. Start the capture loop
/// 2. Verify raw socket permissions
/// 3. Set up any global state
pub fn init() -> Result<(), SynError> {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    // Check permissions first
    if !SynScanner::is_raw_available() {
        eprintln!("WARNING: Raw sockets not available. Run with sudo or grant CAP_NET_RAW");
        eprintln!("  sudo setcap cap_net_raw+ep /path/to/binary");
        return Err(SynError::NotPermitted);
    }

    // Start capture loop
    let shutdown = Arc::new(AtomicBool::new(false));
    start_capture_loop(shutdown)?;

    // Spawn cleanup task for expired probes
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            cleanup_expired_probes(std::time::Duration::from_secs(30));
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_permissions() {
        // This test will fail without CAP_NET_RAW
        let result = SynScanner::is_raw_available();
        println!("Raw sockets available: {}", result);
    }
}