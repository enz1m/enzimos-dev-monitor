//! Stopping processes the caller owns. A process is named by its PID and start
//! time and signalled through a pidfd, so a PID reused after the snapshot is never hit.

use std::io;

use serde::Serialize;

use crate::describe::session_boundary;
use crate::procfs::{Table, current_uid, read_stat};

const PROTECTED: &[&str] = &[
    "systemd",
    "Hyprland",
    "enz-hyprland",
    "enzui-shell",
    "enzui-lock",
    "enzui-greeter",
    "pipewire",
    "wireplumber",
    "pipewire-pulse",
    "dbus-broker",
    "dbus-daemon",
    "gnome-keyring-d",
    "oo7-daemon",
    "xdg-desktop-por",
    "enzimos-dev-mon",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Process,
    /// Current descendants excluding protected branches; refuses trees reaching 4096 entries.
    Tree,
}

#[derive(Debug, Default, Serialize)]
pub struct SignalReport {
    pub signal: &'static str,
    pub delivered: Vec<u32>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Serialize)]
pub struct Skipped {
    pub pid: u32,
    pub reason: String,
}

pub fn signal(pid: u32, start_time: u64, scope: Scope, force: bool) -> io::Result<SignalReport> {
    let table = Table::scan();
    let uid = current_uid();
    let target = table
        .entries
        .get(&pid)
        .filter(|entry| entry.start_time == start_time)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the process has exited or the PID was reused"))?;
    if let Some(reason) = refusal(&table, target.pid, uid) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let (number, name) = if force { (libc::SIGKILL, "SIGKILL") } else { (libc::SIGTERM, "SIGTERM") };
    let members = match scope {
        Scope::Process => vec![target.pid],
        Scope::Tree => table.subtree(target.pid),
    };
    if members.len() >= 4096 {
        return Err(io::Error::other("process tree exceeds safe action limit"));
    }
    let mut protected_branches = std::collections::HashSet::new();
    let mut report = SignalReport { signal: name, ..SignalReport::default() };
    for member in members {
        let Some(entry) = table.entries.get(&member) else { continue };
        let reason = if protected_branches.contains(&entry.ppid) {
            Some("descendant of a protected session process".into())
        } else {
            refusal(&table, member, uid)
        };
        if let Some(reason) = reason {
            protected_branches.insert(member);
            report.skipped.push(Skipped { pid: member, reason });
            continue;
        }
        match send(member, entry.start_time, number) {
            Ok(()) => report.delivered.push(member),
            Err(error) => report.skipped.push(Skipped { pid: member, reason: error.to_string() }),
        }
    }
    Ok(report)
}

fn refusal(table: &Table, pid: u32, uid: u32) -> Option<String> {
    let entry = table.entries.get(&pid)?;
    let own = std::process::id();
    if pid <= 1 || pid == own || table.ancestors(own).contains(&pid) {
        return Some("this process runs the monitor or the session".into());
    }
    if entry.uid != uid {
        return Some("owned by another user".into());
    }
    if PROTECTED.contains(&entry.comm.as_str()) || session_boundary(entry) {
        return Some(format!("{} is protected session or container infrastructure", entry.comm));
    }
    None
}

#[allow(unsafe_code, reason = "Linux syscall ABI (close, syscall).")]
fn send(pid: u32, start_time: u64, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd_open takes scalar arguments and returns a new descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // The pidfd now pins the process; confirm it is still the one from the snapshot.
    let same = read_stat(pid).is_some_and(|entry| {
        entry.start_time == start_time && !PROTECTED.contains(&entry.comm.as_str()) && !session_boundary(&entry)
    });
    let result = if same {
        // SAFETY: fd is live; null siginfo requests the kernel-generated signal.
        let sent =
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, signal, std::ptr::null::<libc::siginfo_t>(), 0) };
        if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "process identity or protection changed"))
    };
    // SAFETY: this function owns fd and closes it exactly once.
    unsafe { libc::close(fd) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::{parse_stat, proc_path};
    use std::fs;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn wait_gone(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let state =
                fs::read_to_string(proc_path(pid, "stat")).ok().and_then(|text| parse_stat(pid, &text).map(|_| text));
            match state {
                None => return true,
                Some(text) if text.split(") ").nth(1).is_some_and(|rest| rest.starts_with('Z')) => return true,
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        false
    }

    #[test]
    fn stops_a_tree_and_refuses_stale_or_protected_targets() {
        let mut child = Command::new("sh").args(["-c", "sleep 30 & sleep 30; wait"]).spawn().unwrap();
        let pid = child.id();
        std::thread::sleep(Duration::from_millis(150));
        let table = Table::scan();
        let start = table.entries[&pid].start_time;
        let grandchildren = table.subtree(pid);
        assert!(grandchildren.len() >= 3, "{grandchildren:?}");
        assert!(signal(pid, start + 1, Scope::Tree, false).is_err());
        let report = signal(pid, start, Scope::Tree, false).unwrap();
        assert_eq!(report.signal, "SIGTERM");
        assert!(report.delivered.contains(&pid));
        for member in &grandchildren[1..] {
            assert!(report.delivered.contains(member), "{report:?}");
            assert!(wait_gone(*member));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(signal(1, Table::scan().entries.get(&1).map_or(0, |e| e.start_time), Scope::Process, true).is_err());
        for name in ["oo7-daemon", "enz-hyprland"] {
            let mut protected = Command::new("sh")
                .args(["-c", "printf '%s' \"$1\" > /proc/self/comm; read answer", "fixture", name])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            std::thread::sleep(Duration::from_millis(150));
            let table = Table::scan();
            let entry = &table.entries[&protected.id()];
            assert_eq!(entry.comm, name);
            let result = signal(entry.pid, entry.start_time, Scope::Process, true);
            let alive = protected.try_wait().unwrap().is_none();
            if alive {
                protected.kill().unwrap();
            }
            protected.wait().unwrap();
            assert!(result.is_err());
            assert!(alive, "protected process was signalled");
        }
    }
}
