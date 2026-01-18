//! Core traits for Vajra scanner components
//!
//! Optimizations:
//! - Batch scanning support for high throughput
//! - Async-first design
//! - Minimal allocations in trait signatures

use crate::types::{ProbeResult, ScanOptions, ServiceMatch, Target};
use anyhow::Result;
use async_trait::async_trait;
use uuid::Uuid;

/// Core scanner trait - all scanners must implement this
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Scan a single target
    async fn scan(&self, target: &Target) -> Result<ProbeResult>;

    /// Batch scan multiple targets (optimized for high throughput)
    ///
    /// Default implementation calls scan() for each target, but
    /// high-performance scanners should override this for better concurrency.
    async fn scan_batch(&self, targets: &[Target]) -> Result<Vec<ProbeResult>> {
        let mut results = Vec::with_capacity(targets.len());
        for target in targets {
            match self.scan(target).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Scan error for {}: {:?}", target, e);
                }
            }
        }
        Ok(results)
    }

    /// Scanner name/identifier
    fn name(&self) -> &str;

    /// Whether this scanner requires root/CAP_NET_RAW
    fn requires_root(&self) -> bool {
        false
    }

    /// Check if scanner is available on this system
    fn is_available(&self) -> bool {
        true
    }

    /// Get recommended scan options for this scanner type
    fn recommended_options(&self) -> ScanOptions {
        ScanOptions::default()
    }
}

/// Service fingerprinting trait
#[async_trait]
pub trait Fingerprinter: Send + Sync {
    /// Identify service from probe result
    async fn identify(&self, result: &ProbeResult) -> Result<Option<ServiceMatch>>;

    /// Load signature database
    async fn load_signatures(&mut self, path: &str) -> Result<()>;

    /// Get number of loaded signatures
    fn signature_count(&self) -> usize {
        0
    }
}

/// Storage backend trait for persisting results
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store a single result
    async fn store_result(&self, result: &ProbeResult) -> Result<()>;

    /// Store multiple results (batch operation)
    async fn store_batch(&self, results: &[ProbeResult]) -> Result<()> {
        for result in results {
            self.store_result(result).await?;
        }
        Ok(())
    }

    /// Get all results for a job
    async fn get_results(&self, job_id: Uuid) -> Result<Vec<ProbeResult>>;

    /// Export results as JSON
    async fn export_json(&self, job_id: Uuid) -> Result<String>;

    /// Export results as CSV
    async fn export_csv(&self, job_id: Uuid) -> Result<String> {
        let results = self.get_results(job_id).await?;
        let mut csv = String::from("target,port,protocol,state,rtt_ms,banner\n");
        
        for result in results {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                result.target.ip,
                result.target.port,
                result.target.protocol.as_str(),
                result.state,
                result.rtt.as_millis(),
                result.banner.as_deref().unwrap_or("")
            ));
        }
        
        Ok(csv)
    }

    /// Clear all results for a job
    async fn clear_results(&self, job_id: Uuid) -> Result<()>;
}

/// Rate limiter trait for controlling scan speed
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Wait until next operation is allowed
    async fn acquire(&self);

    /// Get current rate (operations per second)
    fn current_rate(&self) -> f64;

    /// Update rate limit
    fn set_rate(&mut self, rate: u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockScanner;

    #[async_trait]
    impl Scanner for MockScanner {
        async fn scan(&self, _target: &Target) -> Result<ProbeResult> {
            use crate::types::PortState;
            use std::net::Ipv4Addr;
            
            let target = Target::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
            Ok(ProbeResult::new(target, PortState::Open))
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_scanner_trait() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let scanner = MockScanner;
        let target = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        
        let result = scanner.scan(&target).await;
        assert!(result.is_ok());
    }
}
