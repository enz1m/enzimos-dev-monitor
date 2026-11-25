//! Which session-bus callers the service answers.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The installed Shell, the only default client for process and container control.
pub const SHELL: &str = "/usr/lib/enzui/bin/enzui-shell";

/// What a call can reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Snapshots, inspection and shortcuts.
    Observe,
    /// Signals, container actions and logs.
    Control,
}

/// The file identity of a root-owned executable that only root can modify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    dev: u64,
    ino: u64,
}

impl Client {
    /// The installed executable at `path`, or `None` when it is missing or not root-owned.
    pub fn installed(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        (metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
            .then(|| Self { dev: metadata.dev(), ino: metadata.ino() })
    }
}

fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("caller not admitted: {reason}"))
}

fn start_time(directory: &Path) -> io::Result<u64> {
    let text = fs::read(directory.join("stat"))?;
    crate::procfs::parse_stat(0, text).map(|entry| entry.start_time).ok_or_else(|| denied("process state"))
}

/// Admit caller `pid` from the process table at `proc`: it must run as `uid` outside a Flatpak
/// sandbox, and for [`Access::Control`] its own executable must be `client`.
///
/// # Errors
///
/// `PermissionDenied` when the caller does not qualify or changed during the check.
pub fn admit(proc: &Path, pid: u32, uid: u32, access: Access, client: Option<Client>) -> io::Result<()> {
    if pid <= 1 {
        return Err(denied("process"));
    }
    let directory = proc.join(pid.to_string());
    let before = start_time(&directory).map_err(|_| denied("process"))?;
    let owner = fs::metadata(&directory).map_err(|_| denied("process"))?.uid();
    if owner != uid || crate::procfs::status_uid(&directory) != Some(uid) {
        return Err(denied("user"));
    }
    if directory.join("root/.flatpak-info").try_exists().unwrap_or(true) {
        return Err(denied("sandboxed application"));
    }
    if access == Access::Control {
        let exe = fs::metadata(directory.join("exe")).map_err(|_| denied("executable"))?;
        if client != Some(Client { dev: exe.dev(), ino: exe.ino() }) {
            return Err(denied("only the Shell controls processes and containers"));
        }
    }
    if start_time(&directory).ok() != Some(before) {
        return Err(denied("process changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::current_uid;

    fn identity(path: &str) -> Client {
        let metadata = fs::metadata(path).expect("file identity");
        Client { dev: metadata.dev(), ino: metadata.ino() }
    }

    fn fake_process(proc: &Path, pid: u32, flatpak: bool) {
        let directory = proc.join(pid.to_string());
        fs::create_dir_all(directory.join("root")).expect("fake process directory");
        for name in ["stat", "status"] {
            fs::copy(format!("/proc/self/{name}"), directory.join(name)).expect("copy procfs file");
        }
        std::os::unix::fs::symlink("/proc/self/exe", directory.join("exe")).expect("exe link");
        if flatpak {
            fs::write(directory.join("root/.flatpak-info"), "[Application]\n").expect("flatpak marker");
        }
    }

    #[test]
    fn control_needs_the_client_executable_and_sandboxes_are_refused() {
        let proc = tempfile_dir();
        let own = identity("/proc/self/exe");
        let other = identity(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        fake_process(&proc, 4242, false);
        fake_process(&proc, 4343, true);
        let uid = current_uid();

        assert!(admit(&proc, 4242, uid, Access::Observe, None).is_ok(), "host observer");
        assert!(admit(&proc, 4242, uid, Access::Control, Some(own)).is_ok(), "client controls");
        assert!(admit(&proc, 4242, uid, Access::Control, Some(other)).is_err(), "other executable");
        assert!(admit(&proc, 4242, uid, Access::Control, None).is_err(), "client not installed");
        assert!(admit(&proc, 4242, uid.wrapping_add(1), Access::Observe, None).is_err(), "other user");
        assert!(admit(&proc, 4343, uid, Access::Observe, Some(own)).is_err(), "flatpak observer");
        assert!(admit(&proc, 4343, uid, Access::Control, Some(own)).is_err(), "flatpak control");
        assert!(admit(&proc, 4444, uid, Access::Observe, None).is_err(), "missing process");
        fs::remove_dir_all(&proc).expect("remove fake proc");
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("devmon-caller-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temporary directory");
        path
    }
}
