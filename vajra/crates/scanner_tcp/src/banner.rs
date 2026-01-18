//! Banner grabbing functionality

use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument};

pub struct BannerGrabber {
    timeout: Duration,
    // reserved: max_bytes not currently used but kept for future limits
}

impl BannerGrabber {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
        }
    }

    #[instrument(skip(self, stream))]
    /// Grab a banner from a connected stream.
    pub async fn grab(&self, stream: &mut TcpStream) -> Result<String> {
        // Use smaller buffer for faster reads (limit to 512 bytes for speed)
        let mut buf = vec![0u8; 512];

        // Try passive banner grab first with very short timeout
        let short_timeout = Duration::from_millis(self.timeout.as_millis() as u64 / 2);
        match timeout(short_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                debug!("Passive banner grab: {} bytes", n);
                return Ok(banner);
            }
            _ => {
                debug!("No passive banner, trying active probe");
            }
        }

        // Try active probe - use generic HTTP probe for now
        // Protocol-specific probes can be added later if needed
        let write_timeout = Duration::from_millis(100);
        if let Err(_) = timeout(write_timeout, stream.write_all(b"GET / HTTP/1.0\r\n\r\n")).await {
            debug!("Failed to send HTTP probe");
            return Err(anyhow::anyhow!("No banner available"));
        }

        // Read response with short timeout
        match timeout(short_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                debug!("Active banner grab: {} bytes", n);
                Ok(banner)
            }
            Ok(Ok(_)) => {
                debug!("Empty response");
                Err(anyhow::anyhow!("Empty banner"))
            }
            Ok(Err(e)) => {
                debug!("Read error: {}", e);
                Err(anyhow::Error::from(e))
            }
            Err(_) => {
                debug!("Banner timeout");
                Err(anyhow::anyhow!("Banner timeout"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_grabber_creation() {
        let grabber = BannerGrabber::new(Duration::from_secs(2));
    assert_eq!(grabber.timeout, Duration::from_secs(2));
    }
}
