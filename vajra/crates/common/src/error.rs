//! Error types for Vajra scanner
//!
//! Comprehensive error handling for all scanner operations

use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum VajraError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Scanner not available: {0}")]
    ScannerUnavailable(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Fingerprinting error: {0}")]
    Fingerprint(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Operation cancelled")]
    Cancelled,
}

/// Result type alias for Vajra operations
pub type VajraResult<T> = Result<T, VajraError>;
