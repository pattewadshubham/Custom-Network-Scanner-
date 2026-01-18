//! Fast packet building and parsing with zero-copy operations
//!
//! Optimizations:
//! - Preallocated buffer reuse (no per-packet allocations)
//! - Inline checksum calculations
//! - Manual struct packing for speed
//! - Support for both IPv4 and IPv6

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP flag constants
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// Build a TCP SYN packet into the provided buffer.
/// Returns the number of bytes written.
///
/// # Performance Notes
/// - Buffer should be at least 60 bytes for IPv4 (40 for headers + options)
/// - No heap allocations
/// - Checksums computed inline
pub fn build_syn_packet(
    buf: &mut [u8],
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> usize {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_ipv4_syn(buf, src, dst, src_port, dst_port, seq)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_ipv6_syn(buf, src, dst, src_port, dst_port, seq)
        }
        _ => 0, // Mismatched IP versions
    }
}

/// Build IPv4 + TCP SYN packet (40 bytes minimum)
#[inline(always)]
fn build_ipv4_syn(
    buf: &mut [u8],
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> usize {
    if buf.len() < 40 {
        return 0;
    }

    // IPv4 Header (20 bytes)
    buf[0] = 0x45; // Version 4, IHL 5
    buf[1] = 0x00; // DSCP/ECN
    buf[2..4].copy_from_slice(&40u16.to_be_bytes()); // Total length
    buf[4..6].copy_from_slice(&(rand::random::<u16>()).to_be_bytes()); // ID
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: DF
    buf[8] = 64; // TTL
    buf[9] = 6; // Protocol: TCP
    buf[10..12].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());

    // Calculate IP header checksum
    let ip_checksum = checksum(&buf[0..20]);
    buf[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // TCP Header (20 bytes minimum)
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..28].copy_from_slice(&seq.to_be_bytes());
    buf[28..32].copy_from_slice(&0u32.to_be_bytes()); // ACK = 0
    buf[32] = 0x50; // Data offset: 5 (20 bytes)
    buf[33] = tcp_flags::SYN;
    buf[34..36].copy_from_slice(&65535u16.to_be_bytes()); // Window size
    buf[36..38].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[38..40].copy_from_slice(&[0, 0]); // Urgent pointer

    // Calculate TCP checksum with pseudo-header
    let tcp_checksum = tcp_checksum_v4(src, dst, &buf[20..40]);
    buf[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());

    40
}

/// Build IPv6 + TCP SYN packet (60 bytes minimum)
#[inline(always)]
fn build_ipv6_syn(
    buf: &mut [u8],
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> usize {
    if buf.len() < 60 {
        return 0;
    }

    // IPv6 Header (40 bytes)
    buf[0..4].copy_from_slice(&0x60000000u32.to_be_bytes()); // Version 6
    buf[4..6].copy_from_slice(&20u16.to_be_bytes()); // Payload length
    buf[6] = 6; // Next header: TCP
    buf[7] = 64; // Hop limit
    buf[8..24].copy_from_slice(&src.octets());
    buf[24..40].copy_from_slice(&dst.octets());

    // TCP Header (20 bytes)
    buf[40..42].copy_from_slice(&src_port.to_be_bytes());
    buf[42..44].copy_from_slice(&dst_port.to_be_bytes());
    buf[44..48].copy_from_slice(&seq.to_be_bytes());
    buf[48..52].copy_from_slice(&0u32.to_be_bytes());
    buf[52] = 0x50;
    buf[53] = tcp_flags::SYN;
    buf[54..56].copy_from_slice(&65535u16.to_be_bytes());
    buf[56..58].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[58..60].copy_from_slice(&[0, 0]);

    let tcp_checksum = tcp_checksum_v6(src, dst, &buf[40..60]);
    buf[56..58].copy_from_slice(&tcp_checksum.to_be_bytes());

    60
}

/// Parse a captured packet and extract TCP information.
/// Returns: (src_ip, src_port, dst_ip, dst_port, tcp_flags, payload_offset, payload_len)
pub fn parse_packet(buf: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8, usize, usize)> {
    if buf.len() < 40 {
        return None;
    }

    // Check IP version
    let version = buf[0] >> 4;

    match version {
        4 => parse_ipv4_packet(buf),
        6 => parse_ipv6_packet(buf),
        _ => None,
    }
}

#[inline(always)]
fn parse_ipv4_packet(buf: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8, usize, usize)> {
    if buf.len() < 40 {
        return None;
    }

    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 20 {
        return None;
    }

    let protocol = buf[9];
    if protocol != 6 {
        // Not TCP
        return None;
    }

    let src_ip = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let tcp_offset = ihl;
    let tcp = &buf[tcp_offset..];

    if tcp.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let data_offset = ((tcp[12] >> 4) as usize) * 4;

    let payload_offset = tcp_offset + data_offset;
    let payload_len = buf.len().saturating_sub(payload_offset);

    Some((src_ip, src_port, dst_ip, dst_port, flags, payload_offset, payload_len))
}

#[inline(always)]
fn parse_ipv6_packet(buf: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8, usize, usize)> {
    if buf.len() < 60 {
        return None;
    }

    let next_header = buf[6];
    if next_header != 6 {
        // Not TCP
        return None;
    }

    let src_ip = IpAddr::V6(Ipv6Addr::from([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]));

    let dst_ip = IpAddr::V6(Ipv6Addr::from([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
    ]));

    let tcp = &buf[40..];
    if tcp.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let data_offset = ((tcp[12] >> 4) as usize) * 4;

    let payload_offset = 40 + data_offset;
    let payload_len = buf.len().saturating_sub(payload_offset);

    Some((src_ip, src_port, dst_ip, dst_port, flags, payload_offset, payload_len))
}

/// Fast IP checksum calculation (inline for speed)
#[inline(always)]
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// TCP checksum with IPv4 pseudo-header
#[inline(always)]
fn tcp_checksum_v4(src: &Ipv4Addr, dst: &Ipv4Addr, tcp_data: &[u8]) -> u16 {
    let mut sum = 0u32;

    // Pseudo-header
    for &byte in &src.octets() {
        sum += (byte as u32) << 8;
    }
    for &byte in &dst.octets() {
        sum += (byte as u32) << 8;
    }
    sum += 6u32; // Protocol
    sum += tcp_data.len() as u32;

    // TCP segment
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }

    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// TCP checksum with IPv6 pseudo-header
#[inline(always)]
fn tcp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, tcp_data: &[u8]) -> u16 {
    let mut sum = 0u32;

    // Pseudo-header
    for &byte in &src.octets() {
        sum += (byte as u32) << 8;
    }
    for &byte in &dst.octets() {
        sum += (byte as u32) << 8;
    }
    sum += tcp_data.len() as u32;
    sum += 6u32; // Next header: TCP

    // TCP segment
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }

    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ipv4_syn() {
        let mut buf = vec![0u8; 60];
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);

        let len = build_ipv4_syn(&mut buf, &src, &dst, 12345, 80, 1000);
        assert_eq!(len, 40);

        // Verify IP version
        assert_eq!(buf[0] >> 4, 4);

        // Verify protocol is TCP
        assert_eq!(buf[9], 6);

        // Verify SYN flag
        assert_eq!(buf[33], tcp_flags::SYN);
    }

    #[test]
    fn test_parse_ipv4() {
        let mut buf = vec![0u8; 60];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        build_ipv4_syn(&mut buf, &src, &dst, 5000, 443, 9999);

        let parsed = parse_packet(&buf).unwrap();
        assert_eq!(parsed.0, IpAddr::V4(src));
        assert_eq!(parsed.1, 5000);
        assert_eq!(parsed.2, IpAddr::V4(dst));
        assert_eq!(parsed.3, 443);
        assert_eq!(parsed.4, tcp_flags::SYN);
    }
}
