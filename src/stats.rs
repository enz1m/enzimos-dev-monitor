use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use crate::procfs::{cgroup_path, read_stat};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u32,
    pub start_time: u64,
    pub device: u64,
    pub inode: u64,
    pub cgroup: String,
}

pub struct Sample {
    pub identity: Identity,
    pub at: Instant,
    pub cpu_usec: u64,
    pub memory: u64,
    pub memory_limit: Option<u64>,
    pub pids: Option<u64>,
}

pub fn container_cgroup(path: &str, id: &str) -> Option<PathBuf> {
    if !crate::container::valid_id(id)
        || !path.starts_with('/')
        || Path::new(path).components().any(|part| matches!(part, Component::ParentDir))
    {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => {
                relative.push(part);
                let part = part.to_str()?;
                if part == id || part == format!("docker-{id}.scope") || part == format!("libpod-{id}.scope") {
                    return Some(Path::new("/sys/fs/cgroup").join(relative));
                }
            }
            _ => return None,
        }
    }
    None
}

pub fn identity(pid: u32, id: &str) -> Option<Identity> {
    let stat = read_stat(pid)?;
    let cgroup = cgroup_path(pid)?;
    let directory = container_cgroup(&cgroup, id)?;
    let meta = fs::metadata(directory).ok()?;
    Some(Identity { pid, start_time: stat.start_time, device: meta.dev(), inode: meta.ino(), cgroup })
}

pub fn observe(pid: u32, id: &str) -> Option<Sample> {
    let before = identity(pid, id)?;
    let directory = container_cgroup(&before.cgroup, id)?;
    let number = |name| fs::read_to_string(directory.join(name)).ok()?.trim().parse::<u64>().ok();
    let cpu = fs::read_to_string(directory.join("cpu.stat")).ok()?;
    let at = Instant::now();
    let cpu_usec = cpu.lines().find_map(|line| line.strip_prefix("usage_usec "))?.trim().parse().ok()?;
    let memory = number("memory.current")?;
    let memory_limit = number("memory.max");
    let pids = number("pids.current");
    if identity(pid, id)? != before {
        return None;
    }
    Some(Sample { identity: before, at, cpu_usec, memory, memory_limit, pids })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_container_cgroups_are_attributable() {
        let id = "a".repeat(64);
        let expected = PathBuf::from(format!("/sys/fs/cgroup/user.slice/libpod-{id}.scope"));
        assert_eq!(container_cgroup(&format!("/user.slice/libpod-{id}.scope/child"), &id), Some(expected));
        assert!(container_cgroup("/user.slice/user-1000.slice", &id).is_none());
        assert!(container_cgroup(&format!("/other-{id}.scope"), &id).is_none());
        assert!(container_cgroup(&format!("/../docker-{id}.scope"), &id).is_none());
        assert!(observe(std::process::id(), &id).is_none());
    }
}
