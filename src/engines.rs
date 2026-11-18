//! Queries to Docker-compatible Unix sockets can activate their owning service.
//! Callers own observation lifetimes; dropping the cache cancels its event readers.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

pub use crate::container::{Compose, Container, Mount, PublishedPort, describe, valid_id};
pub use crate::http::{Response, parse_response, request};
use crate::http::{invalid, request_until};
use crate::procfs::Table;
use crate::watch::Watch;

const RECONCILE: Duration = Duration::from_secs(30);
const BACKOFF: Duration = Duration::from_secs(3);
const CONTAINER_LIMIT: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub engine: String,
    pub socket: PathBuf,
    pub rootless: bool,
}

pub fn endpoints(table: &Table, uid: u32) -> Vec<Endpoint> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let daemon = |user| table.entries.values().any(|p| p.comm == "dockerd" && p.uid == user);
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut add = |engine: &str, socket: PathBuf| {
        let Ok(socket) = socket.canonicalize() else { return };
        let Ok(meta) = fs::metadata(&socket) else { return };
        if !meta.file_type().is_socket()
            || !matches!(meta.uid(), 0) && meta.uid() != uid
            || !seen.insert((meta.dev(), meta.ino()))
        {
            return;
        }
        result.push(Endpoint { engine: engine.into(), socket, rootless: meta.uid() == uid && uid != 0 });
    };
    if (daemon(0) || daemon(uid))
        && let Some(socket) = env::var("DOCKER_HOST").ok().and_then(|s| s.strip_prefix("unix://").map(PathBuf::from))
    {
        add("docker", socket);
    }
    if daemon(0) {
        add("docker", "/run/docker.sock".into());
    }
    if let Some(runtime) = runtime {
        if daemon(uid) {
            add("docker", runtime.join("docker.sock"));
        }
        add("podman", runtime.join("podman/podman.sock"));
    }
    result.truncate(8);
    result
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineReport {
    pub endpoint: Endpoint,
    pub containers: Vec<Container>,
    pub error: Option<String>,
    pub stale: bool,
    pub truncated: bool,
}

#[derive(Default)]
pub struct Cache {
    watch: bool,
    engines: HashMap<Endpoint, EngineCache>,
    startup: crate::startup::Cache,
}

#[derive(Default)]
struct EngineCache {
    socket_identity: Option<(u64, u64)>,
    watch: Option<Watch>,
    subscription_attempt: Option<Instant>,
    detail_cursor: usize,
    list: Vec<Value>,
    fetched: Option<Instant>,
    generation: u64,
    failed: Option<(Instant, String)>,
    details: HashMap<String, Detail>,
    previous: HashMap<String, crate::stats::Sample>,
    engine_unit: Option<String>,
    report: Option<EngineReport>,
    invalidated: bool,
}

struct Detail {
    container: Container,
    state: String,
    fetched: Instant,
    generation: u64,
}

impl Cache {
    /// Enables demand-created event readers; release or drop the cache to close them.
    pub fn watching() -> Self {
        Self { watch: true, ..Self::default() }
    }
    pub fn release(&mut self) {
        self.engines.clear();
    }
    pub fn observer_generation(&self, endpoint: &Endpoint) -> Option<u64> {
        self.engines.get(endpoint)?.watch.as_ref().filter(|w| w.ready() && !w.closed()).map(Watch::generation)
    }
    pub fn retain(&mut self, endpoints: &[Endpoint]) {
        self.engines.retain(|key, _| endpoints.contains(key));
    }
    pub fn invalidate(&mut self, endpoint: &Endpoint) {
        if let Some(cache) = self.engines.get_mut(endpoint) {
            cache.invalidated = true;
            cache.failed = None;
        }
    }
}

fn refresh(endpoint: &Endpoint, cache: &mut EngineCache, watching: bool, deadline: Instant) -> io::Result<()> {
    if let Some((at, error)) = &cache.failed
        && at.elapsed() < BACKOFF
    {
        return Err(io::Error::other(error.clone()));
    }
    let healthy = cache.watch.as_ref().is_some_and(|w| w.ready() && !w.closed());
    let unchanged = cache.watch.as_ref().is_none_or(|w| w.generation() == cache.generation);
    let lifetime = if healthy { RECONCILE } else { Duration::from_millis(500) };
    if watching && !cache.invalidated && unchanged && cache.fetched.is_some_and(|at| at.elapsed() < lifetime) {
        return Ok(());
    }
    if watching
        && cache.watch.as_ref().is_none_or(Watch::closed)
        && cache.subscription_attempt.is_none_or(|at| at.elapsed() >= BACKOFF)
    {
        cache.watch = None;
        cache.subscription_attempt = Some(Instant::now());
        cache.details.clear();
        cache.watch = Watch::open(&endpoint.socket, deadline).ok();
    }
    // A generation captured before I/O leaves concurrent events pending for the next request.
    let generation = cache.watch.as_ref().map_or(0, Watch::generation);
    let response = request_until(&endpoint.socket, "GET", "/containers/json?all=1", deadline)?;
    cache.engine_unit = response
        .peer_pid
        .and_then(crate::procfs::unit)
        .filter(|unit| unit.ends_with(".service") && !unit.starts_with("user@"))
        .or_else(|| crate::startup::socket_activation_unit(endpoint, response.peer_pid, deadline));
    if response.body.len() > 2 * 1024 * 1024 {
        return Err(invalid("container inventory exceeds 2 MiB"));
    }
    let value = response.json()?;
    let list = value.as_array().ok_or_else(|| invalid("engine inventory is not an array"))?;
    cache.list.clone_from(&list);
    cache.fetched = Some(Instant::now());
    cache.generation = generation;
    cache.failed = None;
    if cache.invalidated {
        cache.details.clear();
        cache.invalidated = false;
    }
    Ok(())
}

pub fn list(endpoint: &Endpoint, cache: &mut Cache) -> EngineReport {
    list_until(endpoint, cache, Instant::now() + Duration::from_secs(2))
}

pub fn list_until(endpoint: &Endpoint, samples: &mut Cache, deadline: Instant) -> EngineReport {
    let cache = samples.engines.entry(endpoint.clone()).or_default();
    let identity = fs::metadata(&endpoint.socket).and_then(|meta| {
        if meta.file_type().is_socket() {
            Ok((meta.dev(), meta.ino()))
        } else {
            Err(invalid("engine endpoint is no longer a socket"))
        }
    });
    if let Ok(identity) = identity.as_ref()
        && cache.socket_identity != Some(*identity)
    {
        *cache = EngineCache { socket_identity: Some(*identity), ..EngineCache::default() };
    }
    match identity.and_then(|_| refresh(endpoint, cache, samples.watch, deadline)) {
        Ok(()) => {}
        Err(error) => {
            let message = error.to_string();
            if cache.failed.as_ref().is_none_or(|(at, _)| at.elapsed() >= BACKOFF) {
                cache.failed = Some((Instant::now(), message.clone()));
            }
            cache.watch = None;
            let mut report = cache.report.clone().unwrap_or_else(|| EngineReport {
                endpoint: endpoint.clone(),
                containers: Vec::new(),
                error: None,
                stale: true,
                truncated: false,
            });
            report.error = Some(message);
            report.stale = true;
            return report;
        }
    }
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = 0;
    let mut inventory_invalid = false;
    let mut detail_requests = 0;
    let count = cache.list.len().min(CONTAINER_LIMIT);
    let start = cache.detail_cursor % count.max(1);
    cache.detail_cursor = (start + 32) % count.max(1);
    for item in cache.list[..count].iter().cycle().skip(start).take(count) {
        let Some(id) = item.get("Id").and_then(Value::as_str).filter(|id| valid_id(id)) else {
            pending += 1;
            inventory_invalid = true;
            continue;
        };
        if !seen.insert(id.to_owned()) {
            pending += 1;
            inventory_invalid = true;
            continue;
        }
        let state = item.get("State").and_then(Value::as_str).unwrap_or("");
        let cached = cache.details.get(id).filter(|detail| {
            detail.state == state && detail.generation == cache.generation && detail.fetched.elapsed() < RECONCILE
        });
        let mut container = if let Some(detail) = cached {
            detail.container.clone()
        } else {
            let detail = if detail_requests < 32 && Instant::now() < deadline {
                detail_requests += 1;
                request_until(&endpoint.socket, "GET", &format!("/containers/{id}/json"), deadline)
                    .and_then(|r| {
                        if r.body.len() <= 256 * 1024 {
                            r.json()
                        } else {
                            Err(invalid("inspect document exceeds 256 KiB"))
                        }
                    })
                    .and_then(|detail| {
                        if detail.get("Id").and_then(Value::as_str) == Some(id) {
                            Ok(detail)
                        } else {
                            Err(invalid("inspect container identity changed"))
                        }
                    })
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "detail refresh pending within request budget"))
            };
            let mut container = match detail {
                Ok(detail) => describe(&endpoint.engine, item, &detail),
                Err(error) => {
                    let mut c = describe(&endpoint.engine, item, &Value::Null);
                    c.detail_error = Some(error.to_string());
                    c
                }
            };
            if serde_json::to_vec(&container).map_or(true, |v| v.len() > 16 * 1024) {
                container = Container {
                    engine: endpoint.engine.clone(),
                    id: id.into(),
                    state: state.into(),
                    detail_error: Some("container description exceeds 16 KiB".into()),
                    ..Container::default()
                };
            }
            if container.detail_error.is_none() {
                cache.details.insert(
                    id.into(),
                    Detail {
                        container: container.clone(),
                        state: state.into(),
                        fetched: Instant::now(),
                        generation: cache.generation,
                    },
                );
            }
            container
        };
        if container.detail_error.is_some() {
            pending += 1;
        }
        if let Some(pid) = container.pid {
            if let Some(stats) = crate::stats::observe(pid, id) {
                container.memory_bytes = Some(stats.memory);
                container.memory_limit_bytes = stats.memory_limit;
                container.processes = stats.pids;
                if let Some(before) =
                    cache.previous.get(id).filter(|b| b.identity == stats.identity && b.cpu_usec <= stats.cpu_usec)
                {
                    let seconds = stats.at.duration_since(before.at).as_secs_f64();
                    if seconds >= 0.05 {
                        container.cpu_percent = Some((stats.cpu_usec - before.cpu_usec) as f64 / 10_000.0 / seconds);
                    }
                }
                cache.previous.insert(id.into(), stats);
            } else {
                cache.previous.remove(id);
                container.stats_error = Some("container PID/cgroup identity unavailable or changed".into());
            }
        } else {
            cache.previous.remove(id);
        }
        container.startup = samples.startup.verify(
            &endpoint.engine,
            endpoint.rootless,
            cache.engine_unit.as_deref(),
            &container,
            deadline,
        );
        container.autostart = container.startup.automatic();
        result.push(container);
    }
    cache.details.retain(|id, _| seen.contains(id));
    cache.previous.retain(|id, _| seen.contains(id));
    result.sort_by(|a, b| (!a.holds_ports(), &a.name, &a.id).cmp(&(!b.holds_ports(), &b.name, &b.id)));
    let report = EngineReport {
        endpoint: endpoint.clone(),
        containers: result,
        stale: false,
        truncated: cache.list.len() > CONTAINER_LIMIT || inventory_invalid,
        error: (pending > 0).then(|| format!("{pending} container details unavailable or pending")),
    };
    cache.report = Some(report.clone());
    report
}

pub fn select<'a>(reports: &'a [EngineReport], query: &str) -> io::Result<(&'a Endpoint, &'a Container)> {
    if query.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty container selector"));
    }
    if reports.iter().any(|r| r.stale || r.truncated) {
        return Err(io::Error::other("inventory incomplete; specify a healthy engine"));
    }
    let prefix = query.len() >= 12 && query.len() <= 64 && query.bytes().all(|c| c.is_ascii_hexdigit());
    let mut matches =
        reports.iter().flat_map(|r| r.containers.iter().map(move |c| (&r.endpoint, c))).filter(|(_, c)| {
            if valid_id(query) { c.id == query } else { c.name == query || prefix && c.id.starts_with(query) }
        });
    let selected = matches.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no matching container; id prefixes need at least 12 hex digits")
    })?;
    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ambiguous container; use a full id and --engine SOCKET",
        ));
    }
    Ok(selected)
}

/// Explicit start/stop/restart by full id; stop/restart allow ten seconds before engine kill.
pub fn action(endpoint: &Endpoint, id: &str, action: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a full lowercase container id is required"));
    }
    let path = match action {
        "start" => format!("/containers/{id}/start"),
        "stop" => format!("/containers/{id}/stop?t=10"),
        "restart" => format!("/containers/{id}/restart?t=10"),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown container action")),
    };
    let response = request(&endpoint.socket, "POST", &path, Duration::from_secs(15))?;
    if matches!(response.status, 200..=299 | 304) {
        Ok(())
    } else {
        Err(io::Error::other(format!("engine answered {}: {}", response.status, response.message())))
    }
}

pub fn shortcuts(endpoint: &Endpoint, id: &str) -> io::Result<crate::shortcuts::DirectoryShortcuts> {
    if !valid_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "full container id required"));
    }
    let detail = request(&endpoint.socket, "GET", &format!("/containers/{id}/json"), Duration::from_secs(2))?.json()?;
    if detail.get("Id").and_then(Value::as_str) != Some(id) {
        return Err(invalid("container identity changed"));
    }
    let directory = detail
        .pointer("/Config/Labels/com.docker.compose.project.working_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "container has no Compose project directory"))?;
    crate::shortcuts::for_directory(directory)
}

/// Up to 256 KiB of log tail; malformed or oversized input fails instead of returning a prefix.
pub fn logs(endpoint: &Endpoint, id: &str, tail: u32) -> io::Result<String> {
    if !valid_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a full lowercase container id is required"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let detail = request_until(&endpoint.socket, "GET", &format!("/containers/{id}/json"), deadline)?.json()?;
    if detail.get("Id").and_then(Value::as_str) != Some(id) {
        return Err(invalid("container identity changed"));
    }
    let tty = detail.pointer("/Config/Tty").and_then(Value::as_bool).unwrap_or(false);
    let response = request_until(
        &endpoint.socket,
        "GET",
        &format!("/containers/{id}/logs?stdout=1&stderr=1&tail={}", tail.clamp(1, 5000)),
        deadline,
    )?;
    if response.status != 200 {
        return Err(io::Error::other(format!("engine answered {}", response.status)));
    }
    let bytes = if tty { response.body } else { demultiplex(&response.body)? };
    let text = String::from_utf8_lossy(&bytes);
    let mut start = text.len().saturating_sub(256 * 1024);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    Ok(text[start..].to_owned())
}

/// Decode Docker's eight-byte stdout/stderr frame headers, rejecting incomplete frames.
pub fn demultiplex(mut data: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if data.len() < 8 || !matches!(data[0], 1 | 2) || data[1..4] != [0, 0, 0] {
            return Err(invalid("invalid log frame"));
        }
        let mut length_bytes = [0; 4];
        length_bytes.copy_from_slice(&data[4..8]);
        let length = u32::from_be_bytes(length_bytes) as usize;
        let end = 8usize
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| invalid("truncated log frame"))?;
        result.extend_from_slice(&data[8..end]);
        data = &data[end..];
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_names_and_prefixes_are_refused_across_engines() {
        let report = |socket: &str, id: String| EngineReport {
            endpoint: Endpoint { engine: "docker".into(), socket: socket.into(), rootless: false },
            containers: vec![Container { id, name: "web".into(), ..Container::default() }],
            error: None,
            stale: false,
            truncated: false,
        };
        let mut reports = [report("/a", "a".repeat(64)), report("/b", format!("{}{}", "a".repeat(12), "b".repeat(52)))];
        assert!(select(&reports, "web").is_err());
        assert!(select(&reports, &"a".repeat(12)).is_err());
        assert!(select(&reports, "").is_err());
        assert_eq!(select(&reports, &"a".repeat(64)).unwrap().0.socket, std::path::Path::new("/a"));
        reports[1].containers[0].name = "a".repeat(64);
        assert_eq!(select(&reports, &"a".repeat(64)).unwrap().0.socket, std::path::Path::new("/a"));
        reports[1].stale = true;
        assert!(select(&reports, "web").is_err());
    }
    #[test]
    fn log_frames_are_complete_and_typed() {
        assert_eq!(demultiplex(&[1, 0, 0, 0, 0, 0, 0, 2, b'x', b'\n']).unwrap(), b"x\n");
        assert!(demultiplex(&[1, 0, 0, 0, 0, 0, 0, 3, b'x']).is_err());
        assert!(demultiplex(&[8, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
