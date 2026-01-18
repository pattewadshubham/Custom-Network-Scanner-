//! Fingerprint Engine - Service detection and identification
//!
//! This module provides service detection capabilities including:
//! - Port-based service identification
//! - Banner-based service detection
//! - Combined detection strategies

mod service_detector;

pub use service_detector::{
    detect_service,
    detect_service_from_banner,
    detect_service_from_port,
};

/// Fingerprint Engine for advanced service detection
pub struct FingerprintEngine;

impl FingerprintEngine {
    /// Create a new fingerprint engine
    pub fn new() -> Self {
        Self
    }
}

impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

