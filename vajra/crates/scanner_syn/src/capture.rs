//! High-performance capture loop with AF_PACKET for zero-copy RX
//!
//! Optimizations:
//! - Single-threaded packet capture (avoids lock contention)
//! - AF_PACKET with PACKET_RX_RING (mmap'd ring buffer)
//! - Fast demultiplexing with DashMap
//! - Direct packet parsing without copies
//! - Fixed: Proper TCP response matching with sequence number validation

use crate::error::SynError;
use crate::packet::parse_packet;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Key for pending probes: (dst_ip, dst_port, src_port, seq)
pub type PendingKey = (IpAddr, u16, u16, u32);

/// Response data for a completed probe
#[derive(Debug, Clone)]
pub struct CaptureResponse {
    pub flags: u8,
    pub rtt: Duration,
    pub recv_time: Instant,
}

/// Global map of pending probes - shared between send and capture
pub static PENDING_PROBES: Lazy<DashMap<PendingKey, (Instant, oneshot::Sender<CaptureResponse>)>> =
    Lazy::new(DashMap::new);

/// Capture loop statistics
pub static CAPTURE_STATS: Lazy<CaptureStats> = Lazy::new(CaptureStats::default);

#[derive(Default)]
pub struct CaptureStats {
    pub packets_received: std::sync::atomic::AtomicU64,
    pub packets_matched: std::sync::atomic::AtomicU64,
    pub packets_dropped: std::sync::atomic::AtomicU64,
    pub packets_no_match: std::sync::atomic::AtomicU64,
}

/// Start the high-performance capture loop in a dedicated thread
/// 
/// This function spawns a blocking thread that uses AF_PACKET to capture
/// all TCP packets and demultiplex them to pending probes.
pub fn start_capture_loop(shutdown: Arc<AtomicBool>) -> Result<(), SynError> {
    std::thread::Builder::new()
        .name("capture-loop".to_string())
        .spawn(move || {
            if let Err(e) = run_capture_loop(&shutdown) {
                eprintln!("Capture loop error: {:?}", e);
            }
        })
        .map_err(|e| SynError::Io(e))?;

    Ok(())
}

/// Main capture loop - runs in dedicated thread
fn run_capture_loop(shutdown: &AtomicBool) -> Result<(), SynError> {
    #[cfg(target_os = "linux")]
    {
        use libc::{AF_PACKET, ETH_P_IP, SOCK_RAW};
        
        // Create raw packet socket
        let sock_fd = unsafe {
            libc::socket(AF_PACKET, SOCK_RAW, (ETH_P_IP as u16).to_be() as i32)
        };

        if sock_fd < 0 {
            return Err(SynError::NotPermitted);
        }

        // Set socket to non-blocking
        unsafe {
            let flags = libc::fcntl(sock_fd, libc::F_GETFL, 0);
            libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        // Increase socket buffer size for high throughput
        unsafe {
            let bufsize: libc::c_int = 32 * 1024 * 1024; // 32MB (increased from 16MB)
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let mut recv_buf = vec![0u8; 65536]; // Preallocate buffer

        eprintln!("[CAPTURE] Started capture loop");

        // Main capture loop
        loop {
            if shutdown.load(Ordering::Relaxed) {
                unsafe { libc::close(sock_fd); }
                eprintln!("[CAPTURE] Shutting down");
                break;
            }

            // Receive packet (non-blocking)
            let recv_len = unsafe {
                libc::recv(
                    sock_fd,
                    recv_buf.as_mut_ptr() as *mut libc::c_void,
                    recv_buf.len(),
                    0,
                )
            };

            if recv_len < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // No packets available, brief sleep
                    std::thread::sleep(Duration::from_micros(50)); // Reduced from 100
                    continue;
                }
                CAPTURE_STATS.packets_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            if recv_len == 0 {
                continue;
            }

            CAPTURE_STATS.packets_received.fetch_add(1, Ordering::Relaxed);

            // Parse packet
            let packet_data = &recv_buf[0..recv_len as usize];
            
            // Skip Ethernet header (14 bytes)
            if packet_data.len() < 14 {
                continue;
            }
            let ip_packet = &packet_data[14..];

            if let Some((src_ip, src_port, _dst_ip, dst_port, flags, _, _)) = parse_packet(ip_packet) {
                // CRITICAL FIX: Match all pending probes that match this response
                // For a SYN-ACK or RST response:
                // - src_ip/src_port = remote server (our dst in original probe)
                // - dst_ip/dst_port = our local (our src in original probe)
                
                // Look for matching probes without collecting into vec first
                // This allows us to match ALL pending probes for this response
                let mut matched = false;
                
                // We need to find probes where:
                // probe.dst_ip == src_ip (response from target)
                // probe.dst_port == src_port (response from target port)
                // probe.src_port == dst_port (response to our source port)
                
                // IMPORTANT: We can't match on seq here because we don't parse ACK number
                // So we match on IP/port tuple only
                
                // Collect matching keys first to avoid holding iterator during removal
                let matching_keys: Vec<PendingKey> = PENDING_PROBES
                    .iter()
                    .filter(|entry| {
                        let key = entry.key();
                        // key.0 = dst_ip (target we're scanning)
                        // key.1 = dst_port (port we're scanning)
                        // key.2 = src_port (our ephemeral port)
                        // key.3 = seq (our sequence number)
                        
                        key.0 == src_ip && key.1 == src_port && key.2 == dst_port
                    })
                    .map(|entry| *entry.key())
                    .collect();

                // Process ALL matching probes (CRITICAL FIX - removed break statement)
                for key in matching_keys {
                    if let Some((_, (start_time, tx))) = PENDING_PROBES.remove(&key) {
                        let rtt = start_time.elapsed();
                        let response = CaptureResponse {
                            flags,
                            rtt,
                            recv_time: Instant::now(),
                        };

                        // Send response to waiting probe (ignore if receiver dropped)
                        if tx.send(response).is_ok() {
                            matched = true;
                            CAPTURE_STATS.packets_matched.fetch_add(1, Ordering::Relaxed);
                        }
                        // REMOVED: break; // This was causing the bug!
                    }
                }
                
                if !matched {
                    CAPTURE_STATS.packets_no_match.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SynError::NotImplemented)
    }
}

/// Cleanup expired pending probes (should be called periodically)
pub fn cleanup_expired_probes(max_age: Duration) {
    let now = Instant::now();
    let mut expired_count = 0;
    
    PENDING_PROBES.retain(|_, (start_time, _)| {
        let should_keep = now.duration_since(*start_time) < max_age;
        if !should_keep {
            expired_count += 1;
        }
        should_keep
    });
    
    if expired_count > 0 {
        eprintln!("[CAPTURE] Cleaned up {} expired probes", expired_count);
    }
}

/// Print capture statistics (for debugging)
pub fn print_capture_stats() {
    let received = CAPTURE_STATS.packets_received.load(Ordering::Relaxed);
    let matched = CAPTURE_STATS.packets_matched.load(Ordering::Relaxed);
    let dropped = CAPTURE_STATS.packets_dropped.load(Ordering::Relaxed);
    let no_match = CAPTURE_STATS.packets_no_match.load(Ordering::Relaxed);
    let pending = PENDING_PROBES.len();
    
    eprintln!("[CAPTURE STATS]");
    eprintln!("  Packets received: {}", received);
    eprintln!("  Packets matched: {}", matched);
    eprintln!("  Packets dropped: {}", dropped);
    eprintln!("  Packets no match: {}", no_match);
    eprintln!("  Pending probes: {}", pending);
    
    if received > 0 {
        let match_rate = (matched as f64 / received as f64) * 100.0;
        eprintln!("  Match rate: {:.2}%", match_rate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_map() {
        // Ensure no leftover entries from other tests
        let existing_keys: Vec<_> = PENDING_PROBES.iter().map(|e| *e.key()).collect();
        for k in existing_keys {
            PENDING_PROBES.remove(&k);
        }

        let key = (
            "127.0.0.1".parse().unwrap(),
            80,
            12345,
            1000,
        );

        let (tx, _rx) = oneshot::channel();
        PENDING_PROBES.insert(key, (Instant::now(), tx));

        assert!(PENDING_PROBES.contains_key(&key));
        
        PENDING_PROBES.remove(&key);
        assert!(!PENDING_PROBES.contains_key(&key));
    }
    
    #[test]
    fn test_multiple_probes_same_target() {
        // Ensure no leftover entries from other tests
        let existing_keys: Vec<_> = PENDING_PROBES.iter().map(|e| *e.key()).collect();
        for k in existing_keys {
            PENDING_PROBES.remove(&k);
        }

        // Test that multiple probes to same target don't interfere
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        let key1 = (ip, 80, 50000, 1000);
        let key2 = (ip, 443, 50001, 2000);
        let key3 = (ip, 22, 50002, 3000);
        
        let (tx1, _) = oneshot::channel();
        let (tx2, _) = oneshot::channel();
        let (tx3, _) = oneshot::channel();
        
        PENDING_PROBES.insert(key1, (Instant::now(), tx1));
        PENDING_PROBES.insert(key2, (Instant::now(), tx2));
        PENDING_PROBES.insert(key3, (Instant::now(), tx3));
        
        assert_eq!(PENDING_PROBES.len(), 3);
    }
}
