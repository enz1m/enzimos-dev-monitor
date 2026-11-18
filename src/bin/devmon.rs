//! `devmon`: the dev monitor from a terminal, without the D-Bus service.

use std::process::ExitCode;
use std::time::Duration;

use devmon::actions::{self, Scope};
use devmon::command::plain;
use devmon::engines;
use devmon::monitor::{Monitor, Options, Snapshot};
use devmon::procfs::{Table, current_uid};
use devmon::{inspect, shortcuts};

const USAGE: &str = "usage: devmon [--json] [--all] [--udp] [--no-containers] [COMMAND]

commands:
  (none)                      listening ports, their processes and containers
  port PORT                   what is listening on PORT
  inspect PID                 detail for one process
  stop PID [--tree] [--force] SIGTERM (SIGKILL with --force) to PID, or its whole tree
  container ACTION ID         start|stop|restart|logs|shortcuts|open-folder|open-terminal
  projects                    group processes and containers by project
  shortcuts PID               fresh folder/terminal launch descriptors
  open PID folder|terminal    explicit launch (--dry-run prints the descriptor)
  logs PID                    on-demand accessible journal entries

options:
  --engine SOCKET             disambiguate a container engine
  --start-time TICKS           require the identity from an earlier snapshot
";

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (engine, expected_start) = match options(&mut args) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("devmon: {}", plain(&error));
            return ExitCode::FAILURE;
        }
    };
    let mut flag = |name: &str| {
        let present = args.iter().any(|arg| arg == name);
        args.retain(|arg| arg != name);
        present
    };
    let json = flag("--json");
    let options =
        Options { include_system: flag("--all"), include_udp: flag("--udp"), containers: !flag("--no-containers") };
    let tree = flag("--tree");
    let force = flag("--force");
    let dry_run = flag("--dry-run");
    if flag("--help") || flag("-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if dry_run
        && !matches!(
            args.iter().map(String::as_str).collect::<Vec<_>>().as_slice(),
            ["open", _, _] | ["container", "open-folder" | "open-terminal", _]
        )
    {
        eprintln!("devmon: --dry-run applies only to open commands");
        return ExitCode::FAILURE;
    }
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => {
            overview(options, json);
            Ok(())
        }
        ["port", port] => port.parse().map_err(|_| "invalid port".to_owned()).map(|port| lookup(port, options, json)),
        ["inspect", pid] => with_pid(pid, expected_start, |pid, start| {
            inspect::inspect(pid, start).map(|detail| print_json(&detail)).map_err(|e| e.to_string())
        }),
        ["stop", pid] => with_pid(pid, expected_start, |pid, start| {
            let scope = if tree { Scope::Tree } else { Scope::Process };
            let report = actions::signal(pid, start, scope, force).map_err(|e| e.to_string())?;
            print_json(&report);
            if report.delivered.is_empty() || !report.skipped.is_empty() {
                Err("signal delivery incomplete; see report".into())
            } else {
                Ok(())
            }
        }),
        ["container", action, id] => container(action, id, engine.as_deref(), dry_run),
        ["projects"] => {
            print_json(&sampled(options).projects);
            Ok(())
        }
        ["shortcuts", pid] => with_pid(pid, expected_start, |pid, start| {
            shortcuts::for_process(pid, start).map(|s| print_json(&s)).map_err(|e| e.to_string())
        }),
        ["logs", pid] => with_pid(pid, expected_start, |pid, start| {
            let logs = shortcuts::process_logs(pid, start, 200).map_err(|e| e.to_string())?;
            if json {
                print_json(&logs);
            } else {
                print!("{}", plain(&logs.text));
            }
            Ok(())
        }),
        ["open", pid, kind] => with_pid(pid, expected_start, |pid, start| {
            let shortcuts = shortcuts::for_process(pid, start).map_err(|e| e.to_string())?;
            let launch = match *kind {
                "folder" => shortcuts.folder,
                "terminal" => shortcuts.terminal,
                _ => return Err("expected folder or terminal".into()),
            };
            shortcuts::verify(pid, start).map_err(|e| e.to_string())?;
            open(launch, dry_run)
        }),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("devmon: {}", plain(&message));
            ExitCode::FAILURE
        }
    }
}

fn options(args: &mut Vec<String>) -> Result<(Option<String>, Option<u64>), String> {
    let mut value = |name: &str| -> Result<Option<String>, String> {
        let Some(index) = args.iter().position(|a| a == name) else { return Ok(None) };
        if index + 1 >= args.len() {
            return Err(format!("missing value for {name}"));
        }
        args.remove(index);
        let value = args.remove(index);
        if args.iter().any(|a| a == name) {
            return Err(format!("duplicate {name}"));
        }
        Ok(Some(value))
    };
    let engine = value("--engine")?;
    let start =
        value("--start-time")?.map(|s| s.parse::<u64>().map_err(|_| "invalid start time".to_owned())).transpose()?;
    Ok((engine, start))
}

fn with_pid(text: &str, expected: Option<u64>, run: impl FnOnce(u32, u64) -> Result<(), String>) -> Result<(), String> {
    let pid: u32 = text.parse().map_err(|_| "invalid PID".to_owned())?;
    let start = Table::scan().entries.get(&pid).map(|entry| entry.start_time).ok_or("no such process")?;
    if expected.is_some_and(|expected| expected != start) {
        return Err("process identity changed".into());
    }
    run(pid, start)
}

fn open(launch: shortcuts::Launch, dry_run: bool) -> Result<(), String> {
    if dry_run {
        print_json(&launch);
        return Ok(());
    }
    std::process::Command::new(&launch.argv[0])
        .args(&launch.argv[1..])
        .current_dir(&launch.directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn container(action: &str, id: &str, socket: Option<&str>, dry_run: bool) -> Result<(), String> {
    let table = Table::scan();
    let mut samples = engines::Cache::default();
    let endpoints = engines::endpoints(&table, current_uid());
    let socket = socket.map(std::fs::canonicalize).transpose().map_err(|e| e.to_string())?;
    let reports: Vec<_> = endpoints
        .iter()
        .filter(|endpoint| socket.as_ref().is_none_or(|s| s == &endpoint.socket))
        .map(|endpoint| engines::list(endpoint, &mut samples))
        .collect();
    let (endpoint, found) = engines::select(&reports, id).map_err(|e| e.to_string())?;
    if matches!(action, "shortcuts" | "open-folder" | "open-terminal") {
        let paths = engines::shortcuts(endpoint, &found.id).map_err(|e| e.to_string())?;
        match action {
            "open-folder" => open(paths.folder, dry_run),
            "open-terminal" => open(paths.terminal, dry_run),
            _ => {
                print_json(&paths);
                Ok(())
            }
        }
    } else if action == "logs" {
        print!("{}", plain(&engines::logs(endpoint, &found.id, 200).map_err(|e| e.to_string())?));
        Ok(())
    } else {
        engines::action(endpoint, &found.id, action).map_err(|e| e.to_string())
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

fn sampled(options: Options) -> Snapshot {
    let mut monitor = Monitor::default();
    monitor.snapshot(options);
    std::thread::sleep(Duration::from_millis(500));
    monitor.snapshot(options)
}

fn lookup(port: u16, options: Options, json: bool) {
    let snapshot = sampled(Options { include_system: true, ..options });
    if json {
        let ports: Vec<_> = snapshot.ports.iter().filter(|p| p.port == port).collect();
        let processes: Vec<_> = snapshot.processes.iter().filter(|p| p.ports.contains(&port)).collect();
        print_json(&serde_json::json!({ "ports": ports, "processes": processes }));
        return;
    }
    let ports: Vec<_> = snapshot.ports.iter().filter(|p| p.port == port).collect();
    if ports.is_empty() {
        println!("no listener observed on port {port} in this network namespace");
    }
    for entry in ports {
        println!("{} {}:{} ({})", entry.protocol, entry.address, entry.port, entry.exposure);
        if let Some(container) = &entry.container {
            println!("  container {} ({})", plain(&container.name), plain(&container.engine));
        }
        match snapshot.processes.iter().find(|p| Some(p.pid) == entry.pid) {
            Some(process) => {
                println!("  {} (pid {})  {}", plain(&process.label), process.pid, plain(&process.cmdline.join(" ")));
                if let Some(cwd) = &process.cwd {
                    println!("  in {}", plain(cwd));
                }
                let launcher = &process.launcher;
                println!(
                    "  started as {} (pid {}, {} processes, {} RSS, {})",
                    plain(&launcher.label),
                    launcher.pid,
                    launcher.processes,
                    bytes(launcher.rss_bytes),
                    percent(launcher.cpu_percent)
                );
            }
            None if !entry.own && entry.uid.is_some() => {
                println!("  owned by uid {} (process not visible)", entry.uid.unwrap());
            }
            None => {}
        }
    }
}

fn overview(options: Options, json: bool) {
    let snapshot = sampled(options);
    if json {
        print_json(&snapshot);
        return;
    }
    println!(
        "{:<6} {:<5} {:<16} {:<9} {:>7} {:>6} {:>8}  {:<20} COMMAND",
        "PORT", "PROTO", "ADDRESS", "EXPOSURE", "PID", "CPU", "MEMORY", "PROJECT"
    );
    for port in &snapshot.ports {
        let process = snapshot.processes.iter().find(|p| Some(p.pid) == port.pid);
        let (pid, cpu, memory, project, command) = match (process, &port.container) {
            (Some(p), _) => (
                p.pid.to_string(),
                percent(p.launcher.cpu_percent),
                bytes(p.launcher.rss_bytes),
                p.project.as_ref().map(|project| project.name.clone()).unwrap_or_default(),
                if p.launcher.pid == p.pid { p.label.clone() } else { format!("{} ({})", p.label, p.launcher.label) },
            ),
            (None, Some(container)) => {
                (String::new(), String::new(), String::new(), String::new(), format!("container {}", container.name))
            }
            (None, None) => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                port.uid.map(|uid| format!("uid {uid}")).unwrap_or_default(),
            ),
        };
        println!(
            "{:<6} {:<5} {:<16} {:<9} {:>7} {:>6} {:>8}  {:<20} {}",
            port.port,
            port.protocol,
            port.address,
            port.exposure,
            pid,
            cpu,
            memory,
            truncate(&plain(&project), 20),
            plain(&command)
        );
    }
    for report in &snapshot.engines {
        println!();
        let kind = if report.endpoint.rootless { "rootless" } else { "system" };
        println!("{} ({kind}, {})", report.endpoint.engine, report.endpoint.socket.display());
        if let Some(error) = &report.error {
            println!("  {}: {}", if report.stale { "stale/unavailable" } else { "partial" }, plain(error));
        }
        println!(
            "  {:<24} {:<10} {:<14} {:>6} {:>8}  {:<16} MOUNTS",
            "NAME", "STATE", "AUTOSTART", "CPU", "MEMORY", "PORTS"
        );
        for container in &report.containers {
            let ports: Vec<String> =
                container.ports.iter().map(|p| format!("{}->{}", p.host_port, p.container_port)).collect();
            let mounts: Vec<String> =
                container.mounts.iter().filter(|m| m.kind == "bind").map(|m| m.source.clone()).collect();
            let autostart = match container.autostart {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            };
            println!(
                "  {:<24} {:<10} {:<14} {:>6} {:>8}  {:<16} {}",
                truncate(&plain(&container.name), 24),
                plain(&container.state),
                autostart,
                percent(container.cpu_percent),
                container.memory_bytes.map(bytes).unwrap_or_default(),
                truncate(&ports.join(","), 16),
                plain(&mounts.join(", "))
            );
        }
    }
    let cost = &snapshot.cost;
    eprintln!(
        "\n{} processes, {} listeners, {} descriptor tables ({} descriptors) read in {:.1} ms",
        cost.processes_listed,
        cost.listeners,
        cost.descriptor_tables_read,
        cost.descriptors_read,
        cost.elapsed_us as f64 / 1000.0
    );
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_owned()
    } else {
        text.chars().take(width - 1).chain(std::iter::once('…')).collect()
    }
}

fn percent(value: Option<f64>) -> String {
    value.map(|v| format!("{v:.1}%")).unwrap_or_default()
}

fn bytes(value: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if value as f64 >= 1024.0 * MIB {
        format!("{:.1}G", value as f64 / (1024.0 * MIB))
    } else {
        format!("{:.0}M", value as f64 / MIB)
    }
}
