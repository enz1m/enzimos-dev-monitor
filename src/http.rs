use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "engine request deadline exceeded"))
}

pub struct Connection {
    pub stream: UnixStream,
    pub deadline: Option<Instant>,
}

impl Connection {
    #[allow(unsafe_code, reason = "Linux syscall ABI (connect, getsockopt, poll, socket).")]
    pub fn open(socket: &Path, deadline: Instant) -> io::Result<Self> {
        let bytes = socket.as_os_str().as_bytes();
        // SAFETY: sockaddr_un is a C integer/byte structure valid when zeroed.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if !socket.is_absolute() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid engine socket path"));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (to, from) in address.sun_path.iter_mut().zip(bytes) {
            *to = *from as _;
        }
        // SAFETY: socket takes scalar arguments and returns a fresh descriptor.
        let raw =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a successful socket result, transferred exactly once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
        // SAFETY: address and length describe a live, initialized Unix address.
        let result = unsafe { libc::connect(fd.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(), length) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
            loop {
                let millis = remaining(deadline)?.as_millis().clamp(1, i32::MAX as u128) as i32;
                let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
                // SAFETY: poll points to one initialized entry and fd remains owned.
                let count = unsafe { libc::poll(&mut poll, 1, millis) };
                if count == 0 {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                if count < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                let mut error: libc::c_int = 0;
                let mut size = size_of::<libc::c_int>() as libc::socklen_t;
                // SAFETY: error and size are writable buffers of the requested type.
                if unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut error as *mut libc::c_int).cast(),
                        &mut size,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error));
                }
                break;
            }
        }
        remaining(deadline)?;
        let stream = UnixStream::from(fd);
        stream.set_nonblocking(false)?;
        Ok(Self { stream, deadline: Some(deadline) })
    }

    #[allow(unsafe_code, reason = "Linux syscall ABI (getsockopt).")]
    pub fn peer_pid(&self) -> Option<u32> {
        // SAFETY: ucred contains only integer fields, valid when zeroed.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: credentials and size remain writable for the call; stream owns fd.
        let result = unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        };
        (result == 0).then(|| u32::try_from(credentials.pid).ok()).flatten()
    }

    pub fn send(&mut self, method: &str, path: &str) -> io::Result<()> {
        if !matches!(method, "GET" | "POST") || !path.starts_with('/') || path.bytes().any(|b| b <= b' ' || b == 127) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid engine request"));
        }
        let length = if method == "POST" { "Content-Length: 0\r\n" } else { "" };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: enzimos-dev-monitor\r\n{length}Connection: close\r\n\r\n"
        );
        let mut bytes = request.as_bytes();
        while !bytes.is_empty() {
            self.stream.set_write_timeout(self.deadline.map(remaining).transpose()?)?;
            let count = self.stream.write(bytes)?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }
}

impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(self.deadline.map(remaining).transpose()?)?;
        self.stream.read(bytes).map_err(|error| {
            if self.deadline.is_some() && matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
                io::Error::new(io::ErrorKind::TimedOut, "engine request deadline exceeded")
            } else {
                error
            }
        })
    }
}

#[derive(Debug)]
enum Framing {
    Empty,
    Length(u64),
    Chunked { left: u64, delimiter: bool },
    Eof,
}

pub struct Body<R> {
    input: BufReader<R>,
    framing: Framing,
    pub status: u16,
}

fn line<R: Read>(input: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut byte = [0];
    while result.len() < limit {
        input.read_exact(&mut byte)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n") {
            result.truncate(result.len() - 2);
            return Ok(result);
        }
    }
    Err(invalid("HTTP line exceeds limit"))
}

impl<R: Read> Body<R> {
    pub fn new(input: R) -> io::Result<Self> {
        let mut input = BufReader::new(input);
        let mut head = Vec::new();
        loop {
            let part = line(&mut input, HEADER_LIMIT.saturating_sub(head.len()))?;
            head.extend_from_slice(&part);
            head.extend_from_slice(b"\r\n");
            if part.is_empty() {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        if !response.parse(&head).map_err(|_| invalid("malformed HTTP headers"))?.is_complete() {
            return Err(invalid("incomplete HTTP headers"));
        }
        let status = response.code.ok_or_else(|| invalid("missing status"))?;
        if !(200..=599).contains(&status) {
            return Err(invalid("unsupported HTTP status"));
        }
        let mut length = None;
        let mut chunked = false;
        for header in response.headers {
            if header.name.eq_ignore_ascii_case("content-length") {
                let value = std::str::from_utf8(header.value).map_err(|_| invalid("invalid length"))?.trim();
                if length.is_some() || value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(invalid("ambiguous content length"));
                }
                length = Some(value.parse::<u64>().map_err(|_| invalid("invalid length"))?);
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(invalid("unsupported transfer encoding"));
                }
                chunked = true;
            }
        }
        if chunked && length.is_some() {
            return Err(invalid("conflicting response framing"));
        }
        let framing = if status == 204 || status == 304 {
            Framing::Empty
        } else if chunked {
            Framing::Chunked { left: 0, delimiter: false }
        } else if let Some(length) = length {
            Framing::Length(length)
        } else {
            Framing::Eof
        };
        Ok(Self { input, framing, status })
    }

    pub fn inner_mut(&mut self) -> &mut R {
        self.input.get_mut()
    }

    fn next_chunk(&mut self, delimiter: bool) -> io::Result<u64> {
        if delimiter {
            let mut crlf = [0; 2];
            self.input.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(invalid("invalid chunk delimiter"));
            }
        }
        let part = line(&mut self.input, 1024)?;
        let size = part.split(|c| *c == b';').next().unwrap_or_default();
        if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid("invalid chunk size"));
        }
        let size = u64::from_str_radix(std::str::from_utf8(size).map_err(|_| invalid("invalid chunk"))?, 16)
            .map_err(|_| invalid("invalid chunk size"))?;
        if size == 0 {
            let mut total = 0;
            loop {
                let trailer = line(&mut self.input, HEADER_LIMIT.saturating_sub(total))?;
                total += trailer.len() + 2;
                if trailer.is_empty() {
                    break;
                }
                let mut header = [httparse::EMPTY_HEADER; 1];
                let mut framed = trailer;
                framed.extend_from_slice(b"\r\n\r\n");
                httparse::parse_headers(&framed, &mut header).map_err(|_| invalid("invalid trailer"))?;
            }
        }
        Ok(size)
    }
}

impl<R: Read> Read for Body<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Framing::Chunked { left: 0, delimiter } = self.framing {
            let size = self.next_chunk(delimiter)?;
            self.framing = if size == 0 { Framing::Empty } else { Framing::Chunked { left: size, delimiter: true } };
        }
        let remaining = match self.framing {
            Framing::Empty | Framing::Length(0) => return Ok(0),
            Framing::Length(left) | Framing::Chunked { left, .. } => left,
            Framing::Eof => u64::MAX,
        };
        let amount = bytes.len().min(remaining.min(usize::MAX as u64) as usize);
        let count = self.input.read(&mut bytes[..amount])?;
        if count == 0 && !matches!(self.framing, Framing::Eof) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        match &mut self.framing {
            Framing::Length(left) | Framing::Chunked { left, .. } => *left -= count as u64,
            _ => {}
        }
        Ok(count)
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub peer_pid: Option<u32>,
}

impl Response {
    pub fn json(self) -> io::Result<serde_json::Value> {
        if self.status != 200 {
            return Err(io::Error::other(format!("engine answered {}: {}", self.status, self.message())));
        }
        serde_json::from_slice(&self.body).map_err(|e| invalid(&e.to_string()))
    }
    pub fn message(&self) -> String {
        serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v.get("message").and_then(|v| v.as_str()).map(str::to_owned))
            .unwrap_or_default()
    }
}

fn collect<R: Read>(body: Body<R>) -> io::Result<Response> {
    let status = body.status;
    let mut bytes = Vec::new();
    body.take((RESPONSE_LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > RESPONSE_LIMIT {
        return Err(invalid("engine response exceeds 8 MiB; narrow the request"));
    }
    Ok(Response { status, body: bytes, peer_pid: None })
}

pub fn request_until(socket: &Path, method: &str, path: &str, deadline: Instant) -> io::Result<Response> {
    let mut connection = Connection::open(socket, deadline)?;
    connection.send(method, path)?;
    let peer_pid = connection.peer_pid();
    let mut response = collect(Body::new(connection)?)?;
    response.peer_pid = peer_pid;
    Ok(response)
}

/// One Unix-socket HTTP request bounded by total elapsed time and response size.
pub fn request(socket: &Path, method: &str, path: &str, timeout: Duration) -> io::Result<Response> {
    request_until(socket, method, path, Instant::now() + timeout)
}

pub fn parse_response(raw: &[u8]) -> io::Result<Response> {
    collect(Body::new(raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_rejects_truncation_conflicts_and_bad_delimiters() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n[]".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]xx0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
        ] {
            assert!(parse_response(response).is_err());
        }
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").unwrap().body, b"[]");
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=x\r\n[]\r\n0\r\nX-End: yes\r\n\r\n"
            )
            .unwrap()
            .body,
            b"[]"
        );
    }

    #[test]
    fn oversized_body_is_an_error_not_a_truncated_success() {
        let mut response = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        response.resize(response.len() + RESPONSE_LIMIT + 1, b'x');
        assert!(parse_response(&response).is_err());
    }
}
