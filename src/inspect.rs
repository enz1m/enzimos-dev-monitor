//! Detail for one process, including the costlier figures a list does not need.

use std::fs;
use std::io;

use serde::Serialize;

use crate::describe::label;
use crate::procfs::{self, Table, proc_path};

#[derive(Debug, Serialize)]
pub struct Detail {
    pub pid: u32,
    pub start_time: u64,
    pub name: String,
    pub label: String,
    pub cmdline: Vec<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub unit: Option<String>,
    pub threads: u32,
    pub rss_bytes: u64,
    /// Proportional set size: shared pages divided among the processes sharing them.
    pub pss_bytes: Option<u64>,
    pub open_descriptors: Option<usize>,
    pub read_bytes: Option<u64>,
    pub written_bytes: Option<u64>,
    pub children: Vec<Child>,
}

#[derive(Debug, Serialize)]
pub struct Child {
    pub pid: u32,
    pub start_time: u64,
    pub label: String,
    pub rss_bytes: u64,
}

pub fn inspect(pid: u32, start_time: u64) -> io::Result<Detail> {
    let table = Table::scan();
    let entry = table
        .entries
        .get(&pid)
        .filter(|entry| entry.start_time == start_time)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the process has exited or the PID was reused"))?;
    if entry.uid != procfs::current_uid() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "owned by another user"));
    }
    let argv = procfs::cmdline(pid);
    let exe = procfs::link(pid, "exe");
    let io_text = fs::read_to_string(proc_path(pid, "io")).unwrap_or_default();
    let io_value = |key: &str| io_text.lines().find_map(|line| line.strip_prefix(key)?.trim().parse().ok());
    let children = table
        .subtree(pid)
        .into_iter()
        .skip(1)
        .filter_map(|child| table.entries.get(&child))
        .take(256)
        .map(|child| Child {
            pid: child.pid,
            start_time: child.start_time,
            label: label(procfs::link(child.pid, "exe").as_deref(), &child.comm, &procfs::cmdline(child.pid)).0,
            rss_bytes: child.rss_bytes,
        })
        .collect();
    let detail = Detail {
        pid,
        start_time,
        name: entry.comm.clone(),
        label: label(exe.as_deref(), &entry.comm, &argv).0,
        cmdline: argv,
        exe,
        cwd: procfs::host_cwd(pid),
        unit: procfs::unit(pid),
        threads: entry.threads,
        rss_bytes: entry.rss_bytes,
        pss_bytes: procfs::pss_bytes(pid),
        open_descriptors: procfs::fd_count(pid),
        read_bytes: io_value("read_bytes:"),
        written_bytes: io_value("write_bytes:"),
        children,
    };
    let same = procfs::read_stat(pid).is_some_and(|entry| entry.start_time == start_time);
    if !same {
        return Err(io::Error::new(io::ErrorKind::NotFound, "process changed during inspection"));
    }
    Ok(detail)
}
