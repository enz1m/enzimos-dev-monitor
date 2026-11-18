use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

pub struct Output {
    pub status: ExitStatus,
    pub bytes: Vec<u8>,
}

#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, poll).")]
pub fn run(command: &mut Command, deadline: Instant, limit: usize) -> io::Result<Output> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let mut child = OwnedChild(command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?);
    let mut stdout = child.0.stdout.take().ok_or_else(|| io::Error::other("missing stdout"))?;
    // SAFETY: stdout owns a live descriptor; F_GETFL takes no pointer argument.
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: F_SETFL receives the existing flags and a valid owned descriptor.
    if flags < 0 || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut status = None;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(io::ErrorKind::TimedOut)?;
        let mut chunk = [0; 8192];
        if !eof {
            match stdout.read(&mut chunk) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if bytes.len() + count > limit {
                        return Err(crate::http::invalid("command output exceeds limit"));
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    continue;
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(error) => return Err(error),
            }
        }
        if status.is_none() {
            status = child.0.try_wait()?;
        }
        if let Some(status) = status.filter(|_| eof) {
            return Ok(Output { status, bytes });
        }
        let wait = remaining.min(Duration::from_millis(20));
        if eof {
            std::thread::sleep(wait);
        } else {
            let mut descriptor = libc::pollfd { fd: stdout.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: descriptor points to one initialized pollfd for this call.
            unsafe {
                libc::poll(&mut descriptor, 1, wait.as_millis().max(1) as i32);
            }
        }
    }
}

pub fn plain(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')).collect()
}
