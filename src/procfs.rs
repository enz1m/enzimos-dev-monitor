//! Process table from `/proc`, read only when a caller asks for it.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const CMDLINE_LIMIT: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub uid: u32,
    pub comm: String,
    /// User plus system CPU time, in clock ticks.
    pub cpu_ticks: u64,
    /// Start time after boot, in clock ticks; with `pid` it names one process.
    pub start_time: u64,
    pub rss_bytes: u64,
    pub threads: u32,
}

/// Parse Linux procfs stat fields; UID stays unknown until proc-directory metadata is read.
pub fn parse_stat(pid: u32, text: impl AsRef<[u8]>) -> Option<Entry> {
    let text = text.as_ref();
    let open = text.iter().position(|b| *b == b'(')?;
    // The command name may itself contain ") ", so the last parenthesis ends it.
    // It is raw bytes: the kernel cuts it at 15 bytes, even inside a UTF-8 character.
    let close = text.iter().rposition(|b| *b == b')')?;
    let comm = String::from_utf8_lossy(text.get(open + 1..close)?).into_owned();
    let fields: Vec<&str> = std::str::from_utf8(text.get(close + 1..)?).ok()?.split_ascii_whitespace().collect();
    let number = |index: usize| fields.get(index)?.parse::<u64>().ok();
    Some(Entry {
        pid,
        ppid: number(1)? as u32,
        pgrp: number(2)? as u32,
        session: number(3)? as u32,
        uid: u32::MAX,
        comm,
        cpu_ticks: number(11)? + number(12)?,
        start_time: number(19)?,
        rss_bytes: number(21)? * page_size(),
        threads: number(17)? as u32,
    })
}

pub fn read_stat(pid: u32) -> Option<Entry> {
    parse_stat(pid, fs::read(proc_path(pid, "stat")).ok()?)
}

#[allow(unsafe_code, reason = "Linux syscall ABI (sysconf).")]
pub fn page_size() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    // SAFETY: sysconf takes a scalar query key and does not dereference pointers.
    *VALUE.get_or_init(|| match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        size if size > 0 => size as u64,
        _ => 4096,
    })
}

#[allow(unsafe_code, reason = "Linux syscall ABI (sysconf).")]
pub fn clock_ticks() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    // SAFETY: sysconf takes a scalar query key and does not dereference pointers.
    *VALUE.get_or_init(|| match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        ticks if ticks > 0 => ticks as u64,
        _ => 100,
    })
}

/// Boot time in seconds since the epoch, from the `btime` line of `/proc/stat`.
pub fn boot_time() -> Option<u64> {
    static VALUE: OnceLock<Option<u64>> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let text = fs::read_to_string("/proc/stat").ok()?;
        text.lines().find_map(|line| line.strip_prefix("btime ")?.trim().parse().ok())
    })
}

#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no arguments or memory preconditions.
    unsafe { libc::getuid() }
}

pub struct Table {
    pub entries: HashMap<u32, Entry>,
    pub children: HashMap<u32, Vec<u32>>,
}

impl Table {
    /// Reads `stat` of every visible process. Processes that exit mid-scan are skipped.
    pub fn scan() -> Table {
        let mut entries = HashMap::new();
        let mut buffer = Vec::with_capacity(512);
        if let Ok(dir) = fs::read_dir("/proc") {
            for item in dir.flatten() {
                let Some(pid) = item.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
                    continue;
                };
                let Ok(meta) = item.metadata() else { continue };
                buffer.clear();
                let read = fs::File::open(item.path().join("stat")).and_then(|mut file| file.read_to_end(&mut buffer));
                if read.is_err() {
                    continue;
                }
                if let Some(mut entry) = parse_stat(pid, &buffer) {
                    // The kernel reports root as the /proc owner of non-dumpable
                    // tasks (setuid programs, ssh-agent, gpg-agent); take the real
                    // UID from `status` for those only, keeping the scan cheap.
                    entry.uid = observed_uid(&item.path(), meta.uid());
                    entries.insert(pid, entry);
                }
            }
        }
        Table::from_entries(entries)
    }

    pub fn from_entries(entries: HashMap<u32, Entry>) -> Table {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for entry in entries.values() {
            children.entry(entry.ppid).or_default().push(entry.pid);
        }
        for list in children.values_mut() {
            list.sort_unstable();
        }
        Table { entries, children }
    }

    /// Root and reachable descendants, parents first, deduplicated and capped at 4096 entries.
    pub fn subtree(&self, root: u32) -> Vec<u32> {
        let mut result = vec![root];
        let mut seen = std::collections::HashSet::from([root]);
        let mut index = 0;
        while index < result.len() && result.len() < 4096 {
            if let Some(list) = self.children.get(&result[index]) {
                for pid in list {
                    if result.len() == 4096 {
                        break;
                    }
                    if seen.insert(*pid) {
                        result.push(*pid);
                    }
                }
            }
            index += 1;
        }
        result
    }

    pub fn ancestors(&self, pid: u32) -> Vec<u32> {
        let mut result = Vec::new();
        let mut current = pid;
        while let Some(entry) = self.entries.get(&current) {
            if entry.ppid == 0 || result.len() >= 32 {
                break;
            }
            result.push(entry.ppid);
            current = entry.ppid;
        }
        result
    }
}

fn observed_uid(directory: &Path, owner: u32) -> u32 {
    if owner == 0 { status_uid(directory).unwrap_or(0) } else { owner }
}

pub(crate) fn process_uid(pid: u32) -> Option<u32> {
    let directory = proc_path(pid, "");
    Some(observed_uid(&directory, fs::metadata(&directory).ok()?.uid()))
}

pub fn proc_path(pid: u32, name: &str) -> PathBuf {
    Path::new("/proc").join(pid.to_string()).join(name)
}

/// NUL-separated arguments, limited to the first 8192 bytes of procfs cmdline.
pub fn cmdline(pid: u32) -> Vec<String> {
    let Ok(file) = fs::File::open(proc_path(pid, "cmdline")) else { return Vec::new() };
    let mut bytes = Vec::with_capacity(256);
    if file.take(CMDLINE_LIMIT as u64).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub fn link(pid: u32, name: &str) -> Option<String> {
    let target = fs::read_link(proc_path(pid, name)).ok()?;
    Some(target.to_string_lossy().into_owned())
}

pub fn host_cwd(pid: u32) -> Option<String> {
    let path = link(pid, "cwd")?;
    let actual = fs::metadata(proc_path(pid, "cwd")).ok()?;
    let local = fs::metadata(&path).ok()?;
    (actual.dev() == local.dev() && actual.ino() == local.ino() && local.is_dir()).then_some(path)
}

/// The innermost systemd unit in the unified cgroup path, such as `app-foo.scope`.
pub fn unit_from_cgroup(text: &str) -> Option<String> {
    let path = text.lines().find_map(|line| line.strip_prefix("0::"))?;
    path.rsplit('/').find(|part| part.ends_with(".service") || part.ends_with(".scope")).map(str::to_owned)
}

pub fn cgroup_path(pid: u32) -> Option<String> {
    let text = fs::read_to_string(proc_path(pid, "cgroup")).ok()?;
    text.lines().find_map(|line| line.strip_prefix("0::")).map(str::to_owned)
}

pub fn unit(pid: u32) -> Option<String> {
    unit_from_cgroup(&fs::read_to_string(proc_path(pid, "cgroup")).ok()?)
}

/// Proportional set size from `smaps_rollup`; costly for large processes, so only on inspection.
pub fn pss_bytes(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(proc_path(pid, "smaps_rollup")).ok()?;
    let line = text.lines().find(|line| line.starts_with("Pss:"))?;
    let kib: u64 = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

pub fn fd_count(pid: u32) -> Option<usize> {
    Some(fs::read_dir(proc_path(pid, "fd")).ok()?.count())
}

/// Real UID from the `Uid:` line of `/proc/<pid>/status`.
pub(crate) fn status_uid(process: &std::path::Path) -> Option<u32> {
    let mut text = String::new();
    use std::io::Read;
    fs::File::open(process.join("status")).ok()?.take(16384).read_to_string(&mut text).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_preserves_identity_with_unusual_names_and_rejects_truncation() {
        let text = "4242 (node (dev) x) S 4200 4242 4100 34816 4242 4194304 1 0 0 0 150 50 0 0 20 0 11 0 99000 1000 2500 18446744073709551615";
        let entry = parse_stat(4242, text).unwrap();
        assert_eq!(entry.comm, "node (dev) x");
        assert_eq!((entry.ppid, entry.pgrp, entry.session), (4200, 4242, 4100));
        assert_eq!(entry.cpu_ticks, 200);
        assert_eq!(entry.threads, 11);
        assert_eq!(entry.start_time, 99000);
        assert_eq!(entry.rss_bytes, 2500 * page_size());
        // Linux can truncate a command name within a UTF-8 code point.
        let mut text = b"77 (dev-s\xc3\xa9rvice-w\xc3".to_vec();
        text.extend_from_slice(b") S 1 77 77 0 0 0 0 0 0 0 3 4 0 0 20 0 2 0 500 0 9");
        let entry = parse_stat(77, &text).unwrap();
        assert_eq!(entry.comm, "dev-s\u{e9}rvice-w\u{fffd}");
        assert_eq!((entry.ppid, entry.cpu_ticks, entry.threads, entry.start_time), (1, 7, 2, 500));
        assert!(parse_stat(1, "1 (init) S 0 1").is_none());
    }

    #[test]
    fn unit_is_innermost_service_or_scope() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-enzimos\\x2dterminal-91.scope\n";
        assert_eq!(unit_from_cgroup(text).as_deref(), Some("app-enzimos\\x2dterminal-91.scope"));
        assert_eq!(unit_from_cgroup("0::/system.slice/docker-ab12.scope\n").as_deref(), Some("docker-ab12.scope"));
        assert_eq!(unit_from_cgroup("0::/\n"), None);
    }
}
