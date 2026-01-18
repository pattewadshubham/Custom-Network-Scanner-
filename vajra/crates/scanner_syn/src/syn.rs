//! Fixed SYN scanner with proper ProbeResult usage
//!
//! This file fixes the compilation error by using the correct
//! ProbeResult API from vajra-common

use crate::capture::{PendingKey, PENDING_PROBES};
use crate::error::SynError;
use crate::packet::{build_syn_packet, tcp_flags};
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Semaphore};
use tokio::time::timeout;
use vajra_common::{PortState, ProbeResult, Scanner, Target};
use async_trait::async_trait;
use anyhow::Result;

/// Optimized SYN scanner with socket reuse and high concurrency
pub struct SynScanner {
    /// Reusable raw socket (shared across all probes)
    raw_socket: Arc<Mutex<Option<RawSocket>>>,
    /// Buffer pool for zero-allocation sends
    buffer_pool: Arc<BufferPool>,
    /// Maximum concurrent probes
    max_concurrency: usize,
    /// Timeout for individual probes
    timeout: Duration,
    /// Number of retries per target
    retries: u32,
}

/// Raw socket wrapper (Linux-specific)
struct RawSocket {
    fd: i32,
}

impl RawSocket {
    fn new() -> Result<Self, SynError> {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
            if fd < 0 {
                return Err(SynError::NotPermitted);
            }

            unsafe {
                let one: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );

                let bufsize: libc::c_int = 8 * 1024 * 1024; // 8MB
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &bufsize as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            Ok(RawSocket { fd })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(SynError::NotImplemented)
        }
    }

    /// Send packet (non-blocking)
    fn send(&self, buf: &[u8], dst: &IpAddr) -> Result<(), SynError> {
        #[cfg(target_os = "linux")]
        {
            match dst {
                IpAddr::V4(addr) => unsafe {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as libc::sa_family_t;
                    sa.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());

                    let result = libc::sendto(
                        self.fd,
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                        0,
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    );

                    if result < 0 {
                        Err(SynError::Io(std::io::Error::last_os_error()))
                    } else {
                        Ok(())
                    }
                },
                _ => Err(SynError::NotImplemented),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(SynError::NotImplemented)
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Zero-allocation buffer pool for packet building
struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
}

impl BufferPool {
    fn new(capacity: usize) -> Self {
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffers.push(vec![0u8; 60]); // 60 bytes is enough for IPv4+TCP
        }

        BufferPool {
            buffers: Mutex::new(buffers),
        }
    }

    fn acquire(&self) -> Vec<u8> {
        self.buffers
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; 60])
    }

    fn release(&self, buf: Vec<u8>) {
        let mut buffers = self.buffers.lock();
        if buffers.len() < 1000 {
            buffers.push(buf);
        }
    }
}

impl SynScanner {
    pub fn new() -> Self {
        Self::with_concurrency(10000)
            .with_timeout(Duration::from_secs(2))
            .with_retries(1)
    }

    pub fn with_concurrency(max_concurrency: usize) -> Self {
        Self {
            raw_socket: Arc::new(Mutex::new(None)),
            buffer_pool: Arc::new(BufferPool::new(max_concurrency / 10)),
            max_concurrency,
            timeout: Duration::from_secs(2),
            retries: 1,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn is_raw_available() -> bool {
        #[cfg(target_os = "linux")]
        match RawSocket::new() {
            Ok(_) => true,
            Err(_) => false,
        }

        #[cfg(not(target_os = "linux"))]
        false
    }

    fn ensure_socket(&self) -> Result<(), SynError> {
        let mut sock = self.raw_socket.lock();
        if sock.is_none() {
            *sock = Some(RawSocket::new()?);
        }
        Ok(())
    }

    pub async fn probe_one(
        &self,
        target: Target,
        timeout_duration: Duration,
    ) -> Result<ProbeResult, SynError> {
        self.ensure_socket()?;
        let start = Instant::now();
        let src_port = rand::random::<u16>() % 32768 + 32768;
        let seq = rand::random::<u32>();
        let src_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let dst_ip = target.ip;
        let dst_port = target.port;

        let mut buf = self.buffer_pool.acquire();
        let pkt_len = build_syn_packet(&mut buf, &src_ip, &dst_ip, src_port, dst_port, seq);

        if pkt_len == 0 {
            self.buffer_pool.release(buf);
            return Err(SynError::NotImplemented);
        }

        let (tx, rx) = oneshot::channel();
        let key: PendingKey = (dst_ip, dst_port, src_port, seq);
        PENDING_PROBES.insert(key, (start, tx));

        {
            let sock = self.raw_socket.lock();
            if let Some(ref socket) = *sock {
                socket.send(&buf[0..pkt_len], &dst_ip)?;
            } else {
                PENDING_PROBES.remove(&key);
                self.buffer_pool.release(buf);
                return Err(SynError::NotPermitted);
            }
        }

        self.buffer_pool.release(buf);

        match timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => {
                PENDING_PROBES.remove(&key);
                let state = classify_response(response.flags);
                let result = ProbeResult::new(target, state).with_rtt(response.rtt);
                Ok(result)
            }
            Ok(Err(_)) => {
                PENDING_PROBES.remove(&key);
                Err(SynError::Capture("Channel closed".to_string()))
            }
            Err(_) => {
                PENDING_PROBES.remove(&key);
                Ok(ProbeResult::new(target, PortState::Filtered))
            }
        }
    }

    pub async fn probe_batch(
        &self,
        targets: Vec<Target>,
        timeout_duration: Duration,
    ) -> Result<Vec<ProbeResult>, SynError> {
        self.ensure_socket()?;
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = Vec::with_capacity(targets.len());

        for target in targets {
            let sem = semaphore.clone();
            let scanner = self.clone_for_task();
            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.probe_one(target, timeout_duration).await
            });
            tasks.push(task);
        }

        let mut results = Vec::with_capacity(tasks.len());
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => eprintln!("Probe error: {:?}", e),
                Err(e) => eprintln!("Task error: {:?}", e),
            }
        }

        Ok(results)
    }

    fn clone_for_task(&self) -> Self {
        Self {
            raw_socket: self.raw_socket.clone(),
            buffer_pool: self.buffer_pool.clone(),
            max_concurrency: self.max_concurrency,
            timeout: self.timeout,
            retries: self.retries,
        }
    }
}

#[inline(always)]
fn classify_response(flags: u8) -> PortState {
    if flags & tcp_flags::SYN != 0 && flags & tcp_flags::ACK != 0 {
        PortState::Open
    } else if flags & tcp_flags::RST != 0 {
        PortState::Closed
    } else {
        PortState::Filtered
    }
}

#[async_trait]
impl Scanner for SynScanner {
    fn name(&self) -> &str {
        "SYN Scanner"
    }

    fn requires_root(&self) -> bool {
        true
    }

    async fn scan(&self, target: &Target) -> Result<ProbeResult> {
        // Implement retries using probe_one
        let mut last_err = None;
        for _ in 0..=self.retries {
            match self.probe_one(target.clone(), self.timeout).await {
                Ok(res) => return Ok(res),
                Err(e) => last_err = Some(e),
            }
        }
        Err(anyhow::anyhow!(
            "Failed to scan {}:{} after {} retries: {:?}",
            target.ip,
            target.port,
            self.retries,
            last_err
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_scanner_creation() {
        let scanner = SynScanner::new();
        assert_eq!(scanner.max_concurrency, 10000);
        assert_eq!(scanner.timeout, Duration::from_secs(2));
        assert_eq!(scanner.retries, 1);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10);
        let buf1 = pool.acquire();
        assert_eq!(buf1.len(), 60);
        pool.release(buf1);
        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 60);
    }

    #[test]
    fn test_classify_response() {
        assert_eq!(
            classify_response(tcp_flags::SYN | tcp_flags::ACK),
            PortState::Open
        );
        assert_eq!(classify_response(tcp_flags::RST), PortState::Closed);
        assert_eq!(classify_response(tcp_flags::ACK), PortState::Filtered);
    }

    #[tokio::test]
    async fn test_raw_socket_check() {
        let available = SynScanner::is_raw_available();
        println!("Raw sockets available: {}", available);
    }
}
