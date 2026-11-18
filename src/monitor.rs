use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub use crate::bindings::ContainerRef;
use crate::describe::{Project, Projects, label, session_boundary};
use crate::engines::{self, Cache, EngineReport};
use crate::owners::Resolver;
use crate::procfs::{self, Entry, Table, boot_time, clock_ticks, current_uid};
use crate::sockets;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub include_system: bool,
    pub include_udp: bool,
    pub containers: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub version: u32,
    pub scan_id: u64,
    pub taken_at_unix_ms: u64,
    pub ports: Vec<Port>,
    pub processes: Vec<Process>,
    pub engines: Vec<EngineReport>,
    pub projects: Vec<crate::projects::Group>,
    pub warnings: Vec<String>,
    pub cost: SnapshotCost,
}

impl Snapshot {
    pub fn select(&mut self, options: Options) {
        self.ports.retain(|p| {
            (options.include_udp || p.protocol != "udp")
                && (options.include_system || p.own || !p.published_by.is_empty())
        });
        self.processes
            .retain(|p| self.ports.iter().any(|port| port.pid == Some(p.pid) && port.start_time == Some(p.start_time)));
        self.projects = crate::projects::group(self);
    }
    pub fn attach(&mut self, engines: Vec<EngineReport>, options: Options) {
        crate::bindings::merge(&mut self.ports, &engines, options.include_udp);
        self.engines = engines;
        self.select(options);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotCost {
    pub elapsed_us: u64,
    pub processes_listed: usize,
    pub descriptor_tables_read: usize,
    pub descriptors_read: usize,
    pub listeners: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Port {
    pub protocol: &'static str,
    pub address: String,
    pub port: u16,
    /// Bind-address class, not a firewall or reachability assertion.
    pub exposure: &'static str,
    pub uid: Option<u32>,
    pub own: bool,
    pub pid: Option<u32>,
    pub start_time: Option<u64>,
    pub source: &'static str,
    pub container: Option<ContainerRef>,
    pub published_by: Vec<ContainerRef>,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Process {
    pub pid: u32,
    pub start_time: u64,
    pub ppid: u32,
    pub name: String,
    pub label: String,
    pub tool: Option<String>,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub project: Option<Project>,
    pub unit: Option<String>,
    pub started_unix_s: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub rss_bytes: u64,
    pub threads: u32,
    pub ports: Vec<u16>,
    pub launcher: Launcher,
}

#[derive(Clone, Debug, Serialize)]
pub struct Launcher {
    pub pid: u32,
    pub start_time: u64,
    pub label: String,
    pub cmdline: Vec<String>,
    pub parent: Option<String>,
    pub processes: usize,
    pub tree_limited: bool,
    pub rss_bytes: u64,
    pub cpu_percent: Option<f64>,
}

pub struct Monitor {
    uid: u32,
    home: Option<PathBuf>,
    resolver: Resolver,
    projects: Projects,
    cpu: HashMap<(u32, u64), (u64, Instant)>,
    containers: Cache,
    sequence: u64,
}

impl Default for Monitor {
    fn default() -> Self {
        Self {
            uid: current_uid(),
            home: std::env::var_os("HOME").map(PathBuf::from),
            resolver: Resolver::default(),
            projects: Projects::default(),
            cpu: HashMap::new(),
            containers: Cache::default(),
            sequence: 0,
        }
    }
}

impl Monitor {
    /// Enables event readers on container requests; release or drop when observation ends.
    pub fn watching() -> Self {
        Self { containers: Cache::watching(), ..Self::default() }
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn release(&mut self) {
        self.containers.release();
    }

    pub fn snapshot(&mut self, options: Options) -> Snapshot {
        let started = Instant::now();
        let table = Table::scan();
        let sampled_at = Instant::now();
        let (listeners, warnings) = sockets::scan(options.include_udp);
        let wanted: HashSet<u64> =
            listeners.iter().filter(|l| l.uid == self.uid && l.inode != 0).map(|l| l.inode).collect();
        let (owners, cost) = self.resolver.resolve(&table, self.uid, &wanted);
        let ports: Vec<_> = listeners
            .iter()
            .map(|listener| {
                let owner = owners.get(&listener.inode);
                Port {
                    protocol: listener.protocol.name(),
                    address: listener.address.to_string(),
                    port: listener.port,
                    exposure: crate::bindings::exposure(&listener.address),
                    uid: Some(listener.uid),
                    own: listener.uid == self.uid,
                    pid: owner.map(|o| o.pid),
                    start_time: owner.map(|o| o.start_time),
                    source: "socket",
                    container: None,
                    published_by: Vec::new(),
                    url: crate::bindings::url(listener.protocol, &listener.address, listener.port),
                }
            })
            .collect();
        let processes = self.processes(&table, &ports, sampled_at);
        let endpoints = if options.containers { engines::endpoints(&table, self.uid) } else { Vec::new() };
        self.containers.retain(&endpoints);
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let engines =
            endpoints.iter().map(|endpoint| engines::list_until(endpoint, &mut self.containers, deadline)).collect();
        self.sequence += 1;
        let mut snapshot = Snapshot {
            version: 2,
            scan_id: self.sequence,
            taken_at_unix_ms: unix_ms(),
            ports,
            processes,
            engines: Vec::new(),
            projects: Vec::new(),
            warnings,
            cost: SnapshotCost {
                elapsed_us: started.elapsed().as_micros() as u64,
                processes_listed: table.entries.len(),
                descriptor_tables_read: cost.processes,
                descriptors_read: cost.descriptors,
                listeners: listeners.len(),
            },
        };
        snapshot.attach(engines, options);
        snapshot
    }

    fn processes(&mut self, table: &Table, ports: &[Port], now: Instant) -> Vec<Process> {
        let mut by_owner: HashMap<(u32, u64), Vec<u16>> = HashMap::new();
        for port in ports {
            if let (Some(pid), Some(start)) = (port.pid, port.start_time) {
                let list = by_owner.entry((pid, start)).or_default();
                if !list.contains(&port.port) {
                    list.push(port.port);
                }
            }
        }
        let mut samples = HashMap::new();
        let mut launchers = HashMap::new();
        let mut result = Vec::new();
        let mut keys: Vec<_> = by_owner.keys().copied().collect();
        keys.sort_unstable();
        for key in keys {
            let Some(entry) = table.entries.get(&key.0).filter(|e| e.start_time == key.1) else { continue };
            let launcher_pid = launcher(table, entry, self.uid);
            let launcher = launchers
                .entry(launcher_pid)
                .or_insert_with(|| {
                    let launch = &table.entries[&launcher_pid];
                    let members = table.subtree(launcher_pid);
                    let mut rss = 0u64;
                    let mut count = 0;
                    let mut cpu_total = 0.0;
                    let mut sampled = false;
                    for pid in &members {
                        let Some(member) = table.entries.get(pid).filter(|p| p.uid == self.uid) else { continue };
                        count += 1;
                        rss = rss.saturating_add(member.rss_bytes);
                        // A member new since the last snapshot counts as idle; only
                        // an unsampled launcher leaves the tree's rate unknown.
                        let rate = self.cpu_rate(member, now, &mut samples);
                        sampled |= *pid == launcher_pid && rate.is_some();
                        cpu_total += rate.unwrap_or(0.0);
                    }
                    let argv = procfs::cmdline(launcher_pid);
                    Launcher {
                        pid: launcher_pid,
                        start_time: launch.start_time,
                        label: label(procfs::link(launcher_pid, "exe").as_deref(), &launch.comm, &argv).0,
                        cmdline: argv.into_iter().take(64).collect(),
                        parent: table.entries.get(&launch.ppid).map(|p| p.comm.clone()),
                        processes: count,
                        tree_limited: members.len() >= 4096,
                        rss_bytes: rss,
                        cpu_percent: sampled.then_some(cpu_total),
                    }
                })
                .clone();
            let argv = procfs::cmdline(entry.pid);
            let exe = procfs::link(entry.pid, "exe");
            let cwd = procfs::host_cwd(entry.pid);
            let project = cwd.as_deref().and_then(|cwd| self.projects.find(cwd, self.home.as_deref()));
            let (label, tool) = label(exe.as_deref(), &entry.comm, &argv);
            let mut ports = by_owner[&key].clone();
            ports.sort_unstable();
            result.push(Process {
                pid: entry.pid,
                start_time: entry.start_time,
                ppid: entry.ppid,
                name: entry.comm.clone(),
                label,
                tool,
                exe,
                cmdline: argv.into_iter().take(64).collect(),
                cwd,
                project,
                unit: procfs::unit(entry.pid),
                started_unix_s: boot_time().map(|boot| boot + entry.start_time / clock_ticks()),
                cpu_percent: self.cpu_rate(entry, now, &mut samples),
                rss_bytes: entry.rss_bytes,
                threads: entry.threads,
                ports,
                launcher,
            });
        }
        self.cpu = samples;
        result
    }

    fn cpu_rate(&self, entry: &Entry, now: Instant, samples: &mut HashMap<(u32, u64), (u64, Instant)>) -> Option<f64> {
        let key = (entry.pid, entry.start_time);
        samples.insert(key, (entry.cpu_ticks, now));
        let (before, at) = self.cpu.get(&key)?;
        let elapsed = now.duration_since(*at).as_secs_f64();
        (elapsed > 0.05 && entry.cpu_ticks >= *before)
            .then(|| (entry.cpu_ticks - before) as f64 / clock_ticks() as f64 / elapsed * 100.0)
    }
}

pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Outermost same-user/process-group ancestor below a shared or interactive parent, up to 32 hops.
pub fn launcher(table: &Table, entry: &Entry, uid: u32) -> u32 {
    launcher_with(table, entry, uid, session_boundary)
}

fn launcher_with(table: &Table, entry: &Entry, uid: u32, boundary: impl Fn(&Entry) -> bool) -> u32 {
    let mut current = entry;
    for _ in 0..32 {
        let Some(parent) = table.entries.get(&current.ppid) else { break };
        if parent.pid <= 1 || parent.uid != uid || parent.pgrp != current.pgrp || boundary(parent) {
            break;
        }
        current = parent;
    }
    current.pid
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_listener_appears_with_process_and_rate() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut monitor = Monitor::default();
        let first = monitor.snapshot(Options::default());
        let entry = first.ports.iter().find(|p| p.port == port).unwrap();
        assert_eq!(entry.pid, Some(std::process::id()));
        assert_eq!(entry.url.as_deref(), Some(&*format!("http://127.0.0.1:{port}")));
        assert!(first.processes.iter().find(|p| p.pid == std::process::id()).unwrap().cpu_percent.is_none());
        // CPU rates need a sampling interval longer than 50 ms.
        std::thread::sleep(std::time::Duration::from_millis(120));
        let second = monitor.snapshot(Options::default());
        assert!(second.processes.iter().find(|p| p.pid == std::process::id()).unwrap().cpu_percent.is_some());
    }
    #[test]
    fn launcher_stops_at_interactive_shell_not_command_wrapper() {
        let mut entries = HashMap::new();
        for (pid, ppid, comm) in
            [(2, 1, "bash"), (3, 2, "npm"), (4, 3, "sh"), (5, 4, "node"), (20, 1, "code"), (21, 20, "node")]
        {
            let mut e =
                procfs::parse_stat(pid, format!("{pid} ({comm}) S {ppid} 2 1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 1 0 0"))
                    .unwrap();
            e.uid = 7;
            entries.insert(pid, e);
        }
        let table = Table::from_entries(entries);
        let boundary = |p: &Entry| p.comm == "bash" || crate::describe::SESSION_PROCESSES.contains(&p.comm.as_str());
        assert_eq!(launcher_with(&table, &table.entries[&5], 7, boundary), 3);
        assert_eq!(launcher_with(&table, &table.entries[&21], 7, boundary), 21);
    }
}
