//! Vajra Common - Shared types and traits (Performance Optimized)
//!
//! This crate provides core types, traits, and utilities used across
//! the Vajra scanner ecosystem.
//!
//! Key features:
//! - Zero-cost abstractions with inline helpers
//! - Efficient serialization with serde
//! - High-performance batch operations
//! - Comprehensive error handling

pub mod error;
pub mod traits;
pub mod types;

// Re-export commonly used types
pub use error::{VajraError, VajraResult};
pub use traits::{Fingerprinter, RateLimiter, Scanner, Storage};
pub use types::{
    PortState, ProbeResult, Protocol, ScanJob, ScanOptions, ScanStats, ServiceMatch, Target,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
