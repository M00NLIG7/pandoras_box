#[cfg(unix)]
use std::io;
use std::net::IpAddr;
#[cfg(any(unix, test))]
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlSignature {
    Unix,
    Windows,
    Unknown,
}

#[must_use]
pub fn classify_ttl(ttl: u8) -> TtlSignature {
    match ttl {
        55..=64 => TtlSignature::Unix,
        110..=128 => TtlSignature::Windows,
        _ => TtlSignature::Unknown,
    }
}

#[async_trait]
pub trait TtlProber: Send + Sync {
    async fn probe_ttl(&self, ip: IpAddr) -> Option<u8>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTtlProber {
    timeout: Duration,
}

impl NativeTtlProber {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for NativeTtlProber {
    fn default() -> Self {
        Self::new(Duration::from_millis(900))
    }
}

#[async_trait]
impl TtlProber for NativeTtlProber {
    async fn probe_ttl(&self, ip: IpAddr) -> Option<u8> {
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || probe_ttl_blocking(ip, timeout))
            .await
            .ok()
            .flatten()
    }
}

pub type SharedTtlProber = Arc<dyn TtlProber>;

#[cfg(unix)]
fn probe_ttl_blocking(ip: IpAddr, timeout: Duration) -> Option<u8> {
    match ip {
        IpAddr::V4(ipv4) => match probe_ipv4_ttl(ipv4, timeout) {
            Ok(ttl) => ttl,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => None,
            Err(_) => None,
        },
        IpAddr::V6(_) => None,
    }
}

#[cfg(not(unix))]
fn probe_ttl_blocking(_ip: IpAddr, _timeout: Duration) -> Option<u8> {
    None
}

#[cfg(unix)]
fn probe_ipv4_ttl(ip: Ipv4Addr, timeout: Duration) -> io::Result<Option<u8>> {
    let timeout = duration_to_timeval(timeout);
    let identifier = std::process::id() as u16;
    let sequence = u16::from_be_bytes([ip.octets()[2], ip.octets()[3]]);
    let packet = build_icmp_echo_request(identifier, sequence);

    // SAFETY: libc socket APIs are used with valid pointers, lengths, and a closed-on-drop fd.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let _fd = SocketGuard(fd);

        let timeout_ptr = &timeout as *const libc::timeval as *const libc::c_void;
        let timeout_len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;

        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            timeout_ptr,
            timeout_len,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            timeout_ptr,
            timeout_len,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut target: libc::sockaddr_in = std::mem::zeroed();
        populate_sockaddr_in(&mut target, ip);

        let target_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let sent = libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &mut target as *mut libc::sockaddr_in as *mut libc::sockaddr,
            target_len,
        );

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buffer = [0_u8; 2048];
        loop {
            let received = libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            );

            if received < 0 {
                let err = io::Error::last_os_error();
                return match err.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(err),
                };
            }

            if let Some(reply) = parse_ipv4_icmp_echo_reply(&buffer[..received as usize]) {
                if reply.source == ip
                    && reply.identifier == identifier
                    && reply.sequence == sequence
                {
                    return Ok(Some(reply.ttl));
                }
            }
        }
    }
}

#[cfg(unix)]
fn duration_to_timeval(timeout: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    }
}

#[cfg(unix)]
fn populate_sockaddr_in(target: &mut libc::sockaddr_in, ip: Ipv4Addr) {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        target.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        target.sin_family = libc::AF_INET as u8;
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        target.sin_family = libc::AF_INET as libc::sa_family_t;
    }

    target.sin_port = 0;
    target.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
}

#[cfg(any(unix, test))]
fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![
        8,
        0,
        0,
        0,
        (identifier >> 8) as u8,
        identifier as u8,
        (sequence >> 8) as u8,
        sequence as u8,
    ];
    packet.extend_from_slice(b"pandoras-box");

    let checksum = icmp_checksum(&packet).to_be_bytes();
    packet[2] = checksum[0];
    packet[3] = checksum[1];
    packet
}

#[cfg(any(unix, test))]
fn icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0_u32;

    for chunk in packet.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]) as u32,
            [high] => ((*high as u16) << 8) as u32,
            _ => 0,
        };
        sum += word;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EchoReply {
    source: Ipv4Addr,
    ttl: u8,
    identifier: u16,
    sequence: u16,
}

#[cfg(any(unix, test))]
fn parse_ipv4_icmp_echo_reply(packet: &[u8]) -> Option<EchoReply> {
    if packet.len() < 20 {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }

    let icmp = &packet[header_len..];
    if icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }

    Some(EchoReply {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        ttl: packet[8],
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

#[cfg(unix)]
struct SocketGuard(libc::c_int);

#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        // SAFETY: fd came from libc::socket and is closed exactly once here.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_icmp_echo_request, classify_ttl, icmp_checksum, parse_ipv4_icmp_echo_reply};
    use super::{EchoReply, TtlSignature};

    #[test]
    fn classify_ttl_matches_expected_ranges() {
        assert_eq!(classify_ttl(64), TtlSignature::Unix);
        assert_eq!(classify_ttl(128), TtlSignature::Windows);
        assert_eq!(classify_ttl(42), TtlSignature::Unknown);
    }

    #[test]
    fn icmp_request_has_valid_checksum() {
        let packet = build_icmp_echo_request(0x1234, 0x5678);
        assert_eq!(icmp_checksum(&packet), 0);
    }

    #[test]
    fn parse_ipv4_icmp_echo_reply_extracts_ttl() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x24, 0x12, 0x34, 0x00, 0x00, 64, 1, 0x00, 0x00, 10, 0, 0, 8, 10, 0,
            0, 1, 0, 0, 0x00, 0x00, 0xab, 0xcd, 0x00, 0x09, b'p', b'o', b'n', b'g',
        ];

        assert_eq!(
            parse_ipv4_icmp_echo_reply(&packet),
            Some(EchoReply {
                source: std::net::Ipv4Addr::new(10, 0, 0, 8),
                ttl: 64,
                identifier: 0xabcd,
                sequence: 9,
            })
        );
    }

    #[test]
    fn parse_ipv4_icmp_echo_reply_rejects_non_reply_packets() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 64, 1, 0x00, 0x00, 10, 0, 0, 8, 10, 0,
            0, 1, 8, 0, 0x00, 0x00, 0xab, 0xcd, 0x00, 0x09,
        ];

        assert_eq!(parse_ipv4_icmp_echo_reply(&packet), None);
    }
}
