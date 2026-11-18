//! Listening sockets of the current network namespace.
//!
//! The kernel's sock_diag netlink interface returns only sockets in the requested
//! states, so the cost follows the number of listeners rather than every
//! connection on the machine. `/proc/net/*` is the fallback when it is unavailable.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub protocol: Protocol,
    pub address: IpAddr,
    pub port: u16,
    pub uid: u32,
    pub inode: u64,
}

const TCP_LISTEN: u8 = 10;
// An unconnected UDP socket reports the TCP_CLOSE state.
const UDP_UNCONNECTED: u8 = 7;

pub fn listeners(include_udp: bool) -> Vec<Listener> {
    scan(include_udp).0
}

pub fn scan(include_udp: bool) -> (Vec<Listener>, Vec<String>) {
    let mut result = Vec::new();
    let mut warnings = Vec::new();
    let mut plan = vec![(Protocol::Tcp, libc::AF_INET), (Protocol::Tcp, libc::AF_INET6)];
    if include_udp {
        plan.extend([(Protocol::Udp, libc::AF_INET), (Protocol::Udp, libc::AF_INET6)]);
    }
    for (protocol, family) in plan {
        match diag_dump(protocol, family) {
            Ok(mut items) => result.append(&mut items),
            Err(error) => match proc_net_result(protocol, family) {
                Ok(mut fallback) => {
                    result.append(&mut fallback);
                    warnings.push(format!(
                        "{} family {family}: netlink unavailable ({error}); procfs fallback is best effort",
                        protocol.name()
                    ));
                }
                Err(fallback) => {
                    warnings.push(format!("{} family {family}: observation unavailable ({fallback})", protocol.name()));
                }
            },
        }
    }
    result.sort_by_key(|a| (a.port, a.protocol, a.address));
    result.dedup_by(|a, b| a.inode == b.inode && a.inode != 0);
    (result, warnings)
}

#[allow(unsafe_code, reason = "Linux syscall ABI (recv, send, setsockopt, socket and others).")]
fn diag_dump(protocol: Protocol, family: i32) -> io::Result<Vec<Listener>> {
    // SAFETY: socket takes scalar arguments and returns a fresh descriptor.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = Fd(fd);
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: timeout is initialized and readable for the supplied length.
    unsafe {
        libc::setsockopt(
            socket.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as u32,
        );
    }
    let (ip_protocol, state) = match protocol {
        Protocol::Tcp => (libc::IPPROTO_TCP as u8, TCP_LISTEN),
        Protocol::Udp => (libc::IPPROTO_UDP as u8, UDP_UNCONNECTED),
    };
    let request = encode_request(family as u8, ip_protocol, 1u32 << state);
    // SAFETY: request is readable for request.len() bytes and socket owns fd.
    let sent = unsafe { libc::send(socket.0, request.as_ptr().cast(), request.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    // Dump datagrams can be one page long; on 64 KiB-page kernels 32 KiB truncates.
    // SAFETY: sysconf takes only a scalar query key.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let mut buffer = vec![0u8; (32 * 1024).max(page)];
    let mut result = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        if std::time::Instant::now() >= deadline || result.len() > 65536 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // SAFETY: buffer is writable for its full length; recv never writes beyond it.
        let received = unsafe { libc::recv(socket.0, buffer.as_mut_ptr().cast(), buffer.len(), libc::MSG_TRUNC) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received as usize > buffer.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match parse_messages(&buffer[..received as usize], protocol, state, &mut result)? {
            true => return Ok(result),
            false if received == 0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            false => {}
        }
    }
}

struct Fd(i32);

impl Drop for Fd {
    #[allow(unsafe_code, reason = "Linux syscall ABI (close).")]
    fn drop(&mut self) {
        // SAFETY: Fd uniquely owns this descriptor and Drop runs once.
        unsafe { libc::close(self.0) };
    }
}

const NLMSG_HEADER: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const DIAG_MESSAGE: usize = 72;

fn encode_request(family: u8, protocol: u8, states: u32) -> Vec<u8> {
    // nlmsghdr, then inet_diag_req_v2 with an all-zero socket id (no filter).
    let length = NLMSG_HEADER + 56;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&(length as u32).to_ne_bytes());
    bytes.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    bytes.extend_from_slice(&1u32.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[family, protocol, 0, 0]);
    bytes.extend_from_slice(&states.to_ne_bytes());
    bytes.resize(length, 0);
    bytes
}

fn parse_messages(mut data: &[u8], protocol: Protocol, state: u8, out: &mut Vec<Listener>) -> io::Result<bool> {
    while data.len() >= NLMSG_HEADER {
        let length = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        if length < NLMSG_HEADER || length > data.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let flags = u16::from_ne_bytes(data[6..8].try_into().unwrap());
        if flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match kind {
            NLMSG_DONE => {
                if length >= 20 {
                    let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                }
                return Ok(true);
            }
            NLMSG_ERROR => {
                let code = data.get(16..20).map_or(-libc::EIO, |b| i32::from_ne_bytes(b.try_into().unwrap()));
                return Err(io::Error::from_raw_os_error(-code));
            }
            _ => {
                if let Some(listener) = parse_diag(&data[NLMSG_HEADER..length], protocol, state) {
                    out.push(listener);
                }
            }
        }
        let aligned = (length + 3) & !3;
        data = data.get(aligned..).unwrap_or(&[]);
    }
    Ok(false)
}

fn parse_diag(body: &[u8], protocol: Protocol, state: u8) -> Option<Listener> {
    if body.len() < DIAG_MESSAGE || body[1] != state {
        return None;
    }
    let family = i32::from(body[0]);
    let port = u16::from_be_bytes([body[4], body[5]]);
    let remote_port = u16::from_be_bytes([body[6], body[7]]);
    if port == 0 || remote_port != 0 {
        return None;
    }
    let source = &body[8..24];
    let address = if family == libc::AF_INET {
        IpAddr::V4(Ipv4Addr::new(source[0], source[1], source[2], source[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(source).ok()?))
    };
    let uid = u32::from_ne_bytes(body[64..68].try_into().ok()?);
    let inode = u64::from(u32::from_ne_bytes(body[68..72].try_into().ok()?));
    Some(Listener { protocol, address, port, uid, inode })
}

#[cfg(test)]
fn proc_net(protocol: Protocol, family: i32) -> Vec<Listener> {
    proc_net_result(protocol, family).unwrap_or_default()
}

fn proc_net_result(protocol: Protocol, family: i32) -> io::Result<Vec<Listener>> {
    let name = match (protocol, family == libc::AF_INET6) {
        (Protocol::Tcp, false) => "tcp",
        (Protocol::Tcp, true) => "tcp6",
        (Protocol::Udp, false) => "udp",
        (Protocol::Udp, true) => "udp6",
    };
    let state = if protocol == Protocol::Tcp { TCP_LISTEN } else { UDP_UNCONNECTED };
    fs::read_to_string(format!("/proc/net/{name}")).map(|text| parse_proc_net(&text, protocol, state))
}

/// Parse procfs socket tables: address bytes in network order are printed as native 32-bit words.
pub fn parse_proc_net(text: &str, protocol: Protocol, state: u8) -> Vec<Listener> {
    let mut result = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 || u8::from_str_radix(fields[3], 16).ok() != Some(state) {
            continue;
        }
        let (Some((local, port)), Some((_, remote_port))) = (fields[1].split_once(':'), fields[2].split_once(':'))
        else {
            continue;
        };
        let (Ok(port), Ok(remote_port)) = (u16::from_str_radix(port, 16), u16::from_str_radix(remote_port, 16)) else {
            continue;
        };
        if port == 0 || remote_port != 0 {
            continue;
        }
        let Some(address) = parse_hex_address(local) else { continue };
        let (Ok(uid), Ok(inode)) = (fields[7].parse(), fields[9].parse()) else { continue };
        result.push(Listener { protocol, address, port, uid, inode });
    }
    result
}

fn parse_hex_address(text: &str) -> Option<IpAddr> {
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).ok().map(u32::to_ne_bytes);
    match text.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(text)?))),
        32 => {
            let mut bytes = [0u8; 16];
            for index in 0..4 {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word(text.get(index * 8..index * 8 + 8)?)?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn proc_net_ipv4_and_ipv6() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 424242 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:A1B2 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000  1000        0 999 1\n";
        let found = parse_proc_net(tcp, Protocol::Tcp, TCP_LISTEN);
        assert_eq!(
            found,
            vec![Listener {
                protocol: Protocol::Tcp,
                address: "127.0.0.1".parse().unwrap(),
                port: 3000,
                uid: 1000,
                inode: 424242
            }]
        );
        let tcp6 = "header\n   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 77 1\n";
        let found = parse_proc_net(tcp6, Protocol::Tcp, TCP_LISTEN);
        assert_eq!(found[0].address, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(found[0].port, 8080);
    }

    #[test]
    fn netlink_matches_proc_net_for_own_listeners() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let udp_port = udp.local_addr().unwrap().port();
        let diag = diag_dump(Protocol::Tcp, libc::AF_INET).unwrap();
        let text = proc_net(Protocol::Tcp, libc::AF_INET);
        let mine = |list: &[Listener], port| list.iter().find(|l| l.port == port).cloned();
        assert_eq!(mine(&diag, tcp_port), mine(&text, tcp_port));
        assert!(mine(&diag, tcp_port).unwrap().inode > 0);
        let all = listeners(true);
        assert!(all.iter().any(|l| l.protocol == Protocol::Udp && l.port == udp_port));
        assert!(all.iter().any(|l| l.protocol == Protocol::Tcp && l.port == tcp_port));
    }
}
