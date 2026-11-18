//! Maps socket inodes to the processes holding them.
//!
//! Linux exposes the owner only through each process's descriptor table, so a
//! cold lookup reads `/proc/<pid>/fd` of every process of the caller's user. The
//! previous answer is checked first, so repeated lookups only read the
//! descriptor tables of processes that already held a listener.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

use crate::procfs::{Table, proc_path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub start_time: u64,
}

/// How long an inode no readable descriptor table holds is not searched for again.
const UNRESOLVED_RETRY: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Resolver {
    previous: HashMap<u64, Owner>,
    unresolved: HashMap<u64, Instant>,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Cost {
    pub processes: usize,
    pub descriptors: usize,
}

impl Resolver {
    pub fn resolve(&mut self, table: &Table, uid: u32, wanted: &HashSet<u64>) -> (HashMap<u64, Owner>, Cost) {
        let mut found = HashMap::new();
        let mut cost = Cost::default();
        let now = Instant::now();
        self.unresolved.retain(|inode, at| wanted.contains(inode) && now.duration_since(*at) < UNRESOLVED_RETRY);
        let mut remaining: HashSet<u64> =
            wanted.iter().filter(|inode| !self.unresolved.contains_key(inode)).copied().collect();
        let mut visited = HashSet::new();
        let hinted: Vec<Owner> = {
            let mut list: Vec<Owner> = wanted.iter().filter_map(|inode| self.previous.get(inode).copied()).collect();
            list.sort_unstable_by_key(|owner| owner.pid);
            list.dedup();
            list
        };
        for owner in hinted {
            let current = table.entries.get(&owner.pid);
            if current.is_some_and(|entry| entry.start_time == owner.start_time) && visited.insert(owner.pid) {
                scan_descriptors(owner, &mut remaining, &mut found, &mut cost);
            }
        }
        if !remaining.is_empty() {
            let mut candidates: Vec<_> = table.entries.values().filter(|entry| entry.uid == uid).collect();
            // Newer processes are likelier to be the development servers being looked for.
            candidates.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.start_time));
            for entry in candidates {
                if remaining.is_empty() {
                    break;
                }
                if visited.insert(entry.pid) {
                    let owner = Owner { pid: entry.pid, start_time: entry.start_time };
                    scan_descriptors(owner, &mut remaining, &mut found, &mut cost);
                }
            }
        }
        for inode in remaining {
            self.unresolved.insert(inode, now);
        }
        self.previous.clone_from(&found);
        (found, cost)
    }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (close, open, readlinkat).")]
fn scan_descriptors(owner: Owner, remaining: &mut HashSet<u64>, found: &mut HashMap<u64, Owner>, cost: &mut Cost) {
    let directory = proc_path(owner.pid, "fd");
    let Ok(entries) = fs::read_dir(&directory) else { return };
    cost.processes += 1;
    let Ok(dir_path) = std::ffi::CString::new(directory.as_os_str().as_bytes()) else { return };
    // SAFETY: dir_path is NUL terminated; open returns a new owned descriptor.
    let dir_fd = unsafe { libc::open(dir_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dir_fd < 0 {
        return;
    }
    let mut target = [0u8; 64];
    for entry in entries.flatten() {
        cost.descriptors += 1;
        let Ok(name) = std::ffi::CString::new(entry.file_name().as_bytes()) else { continue };
        // SAFETY: name is NUL terminated and target is writable for target.len() bytes.
        let length = unsafe { libc::readlinkat(dir_fd, name.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
        if length <= 0 {
            continue;
        }
        if let Some(inode) = socket_inode(&target[..length as usize])
            && remaining.remove(&inode)
        {
            found.insert(inode, owner);
            if remaining.is_empty() {
                break;
            }
        }
    }
    // SAFETY: dir_fd is owned here and all descriptor reads are complete.
    unsafe { libc::close(dir_fd) };
}

/// Parses a descriptor link target of the form `socket:[123]`.
pub fn socket_inode(target: &[u8]) -> Option<u64> {
    let digits = target.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    std::str::from_utf8(digits).ok()?.parse().ok()
}
