//! Core data types for the Vajra Scanner Engine (Max-performance profile)
//!
//! This file is tuned for runtime speed in hot paths:
//! - aggressive `#[inline]` on small helpers
//! - direct field access for hot-path loops
//! - builder-style methods that consume `self` to avoid extra clones
//! - minimal panicking/allocations in methods used during scanning
//!
//! NOTE: kept `SystemTime` for `timestamp` so serde-friendly serialization is preserved.
//! If you want absolute microsecond accuracy for internal timing, consider adding
//! an `Instant` field annotated `#[serde(skip)]` in follow-up changes.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Supported network protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
}

impl Protocol {
    #[inline]
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
        }
    }
}

/// Port states returned by probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
        };
        f.write_str(s)
    }
}

/// Single scan target (IP + port + protocol).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

impl Target {
    #[inline]
    #[must_use]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            protocol: Protocol::TCP,
        }
    }

    #[inline]
    #[must_use]
    pub fn tcp(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            protocol: Protocol::TCP,
        }
    }

    #[inline]
    #[must_use]
    pub fn udp(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            protocol: Protocol::UDP,
        }
    }

    #[inline]
    #[must_use]
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // use protocol string to avoid Debug formatting cost
        write!(f, "{}:{}/{}", self.ip, self.port, self.protocol.as_str())
    }
}

/// Result of probing a single target.
///
/// Intentionally uses public fields for minimal accessor overhead in hot loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub target: Target,
    pub state: PortState,
    pub banner: Option<String>,
    pub service: Option<ServiceMatch>,
    pub timestamp: SystemTime,
    /// Round-trip time measured for the probe (Duration::ZERO when unknown).
    pub rtt: Duration,
}

impl ProbeResult {
    /// Create a fresh ProbeResult with zero RTT.
    #[inline]
    #[must_use]
    pub fn new(target: Target, state: PortState) -> Self {
        Self {
            target,
            state,
            banner: None,
            service: None,
            timestamp: SystemTime::now(),
            rtt: Duration::ZERO,
        }
    }

    /// Builder-style constructor that sets RTT at creation.
    #[inline]
    #[must_use]
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = rtt;
        self
    }

    /// Builder: attach banner string.
    #[inline]
    #[must_use]
    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self
    }

    /// Builder: attach service match.
    #[inline]
    #[must_use]
    pub fn with_service(mut self, service: ServiceMatch) -> Self {
        self.service = Some(service);
        self
    }

    /// Update RTT after construction (avoids reallocation).
    #[inline]
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    /// Update state in-place.
    #[inline]
    pub fn set_state(&mut self, state: PortState) {
        self.state = state;
    }

    /// Quick checks for hot-path predicates.
    #[inline]
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self.state, PortState::Open)
    }

    #[inline]
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, PortState::Closed)
    }

    #[inline]
    #[must_use]
    pub const fn is_filtered(&self) -> bool {
        matches!(self.state, PortState::Filtered | PortState::OpenFiltered)
    }
}

/// Matched service information for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMatch {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub confidence: f32,
}

impl ServiceMatch {
    #[inline]
    #[must_use]
    pub fn new<S: Into<String>>(service: S) -> Self {
        Self {
            service: service.into(),
            product: None,
            version: None,
            confidence: 1.0,
        }
    }

    #[inline]
    #[must_use]
    pub fn with_product(mut self, product: String) -> Self {
        self.product = Some(product);
        self
    }

    #[inline]
    #[must_use]
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    #[inline]
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }
}

/// Scan job: collection of targets + options + metadata.
///
/// Designed for lightweight cloning of `targets` when dispatching workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: Uuid,
    pub targets: Vec<Target>,
    pub options: ScanOptions,
    pub priority: u8,
    pub created_at: SystemTime,
}

impl ScanJob {
    #[inline]
    #[must_use]
    pub fn new(targets: Vec<Target>) -> Self {
        Self {
            id: Uuid::new_v4(),
            targets,
            options: ScanOptions::default(),
            priority: 0,
            created_at: SystemTime::now(),
        }
    }

    #[inline]
    #[must_use]
    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }

    #[inline]
    #[must_use]
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    #[inline]
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

/// Scan behaviour tuning options.
///
/// Keep fields `pub` so orchestrator / scanners can read them without accessor overhead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub retries: u32,
    pub fingerprint: bool,
    pub max_concurrency: usize,
    pub rate_limit: Option<u64>, // packets per second
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            retries: 1,
            fingerprint: false,
            max_concurrency: 10_000,
            rate_limit: None,
        }
    }
}

impl ScanOptions {
    /// Fast preset: low timeout, no retries, very high concurrency.
    #[inline]
    #[must_use]
    pub fn fast() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            retries: 0,
            fingerprint: false,
            max_concurrency: 20_000,
            rate_limit: None,
        }
    }

    /// Accurate preset: higher timeout and retries for reliability.
    #[inline]
    #[must_use]
    pub fn accurate() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            retries: 3,
            fingerprint: true,
            max_concurrency: 5_000,
            rate_limit: None,
        }
    }

    /// Stealth preset: lower concurrency and explicit rate limit.
    #[inline]
    #[must_use]
    pub fn stealth() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            retries: 1,
            fingerprint: false,
            max_concurrency: 100,
            rate_limit: Some(100),
        }
    }
}

/// Runtime scan statistics collected incrementally.
///
/// `average_rtt` stored as Duration for compatibility; computations use integer math to avoid
/// floating-point overhead in hot-path updates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_targets: usize,
    pub scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub errors: usize,
    pub average_rtt: Duration,
    pub elapsed: Duration,
}

impl ScanStats {
    #[inline]
    #[must_use]
    pub fn new(total_targets: usize) -> Self {
        Self {
            total_targets,
            ..Default::default()
        }
    }

    /// Progress percentage in [0.0, 100.0].
    #[inline]
    #[must_use]
    pub fn progress(&self) -> f32 {
        if self.total_targets == 0 {
            0.0
        } else {
            (self.scanned as f32 / self.total_targets as f32) * 100.0
        }
    }

    /// Scanning rate (targets per second).
    #[inline]
    #[must_use]
    pub fn rate(&self) -> f32 {
        if self.elapsed.as_secs_f32() == 0.0 {
            0.0
        } else {
            self.scanned as f32 / self.elapsed.as_secs_f32()
        }
    }

    /// Incrementally update stats. Intentionally minimal allocations.
    ///
    /// Note: `result.rtt` should be Duration::ZERO if not measured.
    pub fn update(&mut self, result: &ProbeResult) {
        self.scanned = self.scanned.saturating_add(1);
        match result.state {
            PortState::Open => self.open_ports = self.open_ports.saturating_add(1),
            PortState::Closed => self.closed_ports = self.closed_ports.saturating_add(1),
            PortState::Filtered | PortState::OpenFiltered => {
                self.filtered_ports = self.filtered_ports.saturating_add(1)
            }
        }

        // Update rolling average RTT using integer arithmetic:
        // new_avg = (old_avg * (n-1) + rtt) / n
        let n = self.scanned as u128;
        if n == 1 {
            self.average_rtt = result.rtt;
        } else {
            let old = self.average_rtt.as_nanos();
            let add = result.rtt.as_nanos();
            let tot = old.saturating_mul(n - 1).saturating_add(add);
            let new_avg_nanos = tot / n;
            self.average_rtt = Duration::from_nanos(new_avg_nanos as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn target_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let t = Target::new(ip, 80);
        assert_eq!(t.port, 80);
        assert_eq!(t.protocol, Protocol::TCP);
    }

    #[test]
    fn probe_result_builders() {
        let target = Target::tcp(IpAddr::V4(Ipv4Addr::LOCALHOST), 22);
        let r = ProbeResult::new(target.clone(), PortState::Open)
            .with_rtt(Duration::from_millis(10))
            .with_banner("ok".to_string());
        assert!(r.is_open());
        assert_eq!(r.rtt, Duration::from_millis(10));
        assert!(r.banner.is_some());
    }

    #[test]
    fn scan_options_presets() {
        let fast = ScanOptions::fast();
        assert_eq!(fast.timeout, Duration::from_secs(1));
        assert_eq!(fast.retries, 0);

        let stealth = ScanOptions::stealth();
        assert!(stealth.rate_limit.is_some());
    }

    #[test]
    fn scan_stats_updates() {
        let mut stats = ScanStats::new(3);
        let t = Target::tcp(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);

        let r1 = ProbeResult::new(t.clone(), PortState::Open).with_rtt(Duration::from_millis(5));
        stats.update(&r1);
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.open_ports, 1);

        let r2 = ProbeResult::new(t.clone(), PortState::Closed).with_rtt(Duration::from_millis(15));
        stats.update(&r2);
        assert_eq!(stats.scanned, 2);
        // average_rtt should be between 5 and 15
        assert!(stats.average_rtt >= Duration::from_millis(5));
        assert!(stats.average_rtt <= Duration::from_millis(15));
    }
}
