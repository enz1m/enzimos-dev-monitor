//! Framework-neutral descriptions of a process: what it runs and which project it belongs to.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "bun", "deno", "python", "python3", "pypy3", "ruby", "php", "perl", "java", "dotnet", "elixir",
    "erl", "beam.smp", "sh", "bash", "dash", "zsh",
];

/// These processes serve multiple jobs; a dev-server stop must not traverse through them.
pub const SESSION_PROCESSES: &[&str] = &[
    "systemd",
    "tmux: server",
    "tmux",
    "screen",
    "sshd",
    "sshd-session",
    "login",
    "su",
    "sudo",
    "enzimos-termina",
    "kitty",
    "alacritty",
    "foot",
    "wezterm-gui",
    "gnome-terminal-",
    "konsole",
    "ghostty",
    "xterm",
    "Hyprland",
    "enzui-shell",
    "code",
    "electron",
    "zed",
    "zed-editor",
    "idea",
    "nvim",
    "vim",
    "emacs",
    "greetd",
    "dbus-daemon",
    "dbus-broker",
    "dockerd",
    "docker-proxy",
    "containerd",
    "containerd-shim",
    "rootlesskit",
    "rootlessport",
    "conmon",
    "pasta",
    "slirp4netns",
];

pub fn session_boundary(entry: &crate::procfs::Entry) -> bool {
    if SESSION_PROCESSES.contains(&entry.comm.as_str()) {
        return true;
    }
    if !matches!(entry.comm.as_str(), "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh" | "nu") {
        return false;
    }
    let argv = crate::procfs::cmdline(entry.pid);
    shell_is_interactive(&argv)
}

pub fn shell_is_interactive(argv: &[String]) -> bool {
    if argv.is_empty() || argv[0].starts_with('-') {
        return true;
    }
    let args = &argv[1..];
    let flag =
        |letter| args.iter().any(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(letter));
    if flag('i') || args.iter().any(|arg| arg == "--interactive" || arg == "--login") {
        return true;
    }
    if flag('c') || args.iter().any(|arg| arg == "--command") {
        return false;
    }
    !args.iter().any(|arg| !arg.starts_with('-'))
}

pub fn label(exe: Option<&str>, comm: &str, argv: &[String]) -> (String, Option<String>) {
    let program = trim_version(argv.first().map_or(comm, |arg| basename(arg)));
    let program = if program.is_empty() { comm } else { program };
    let exe_name = exe.map(|path| trim_version(basename(path)));
    let interpreter = INTERPRETERS.iter().any(|name| {
        let base = trim_version(name);
        program == base || exe_name == Some(base)
    });
    if !interpreter {
        let rest = words(argv.get(1..).unwrap_or_default(), 1);
        let label = if rest.is_empty() { program.to_owned() } else { format!("{program} {rest}") };
        return (label, None);
    }
    let mut index = 1;
    while let Some(arg) = argv.get(index) {
        match arg.as_str() {
            "-m" | "-jar" => {
                let module = argv.get(index + 1).map(|value| basename(value).to_owned()).unwrap_or_default();
                let rest = words(argv.get(index + 2..).unwrap_or_default(), 2);
                return (join(&module, &rest), Some(module));
            }
            "-c" if matches!(program, "sh" | "bash" | "dash" | "zsh") => {
                let script = argv.get(index + 1).map(String::as_str).unwrap_or_default();
                let separated = script.replace("&&", "\n").replace("||", "\n").replace(';', "\n").replace(" | ", "\n");
                let last = separated
                    .lines()
                    .map(|part| part.trim().trim_end_matches('&').trim())
                    .rfind(|part| !part.is_empty());
                let command: Vec<String> = last
                    .unwrap_or_default()
                    .split_ascii_whitespace()
                    .filter(|token| !token.contains(['>', '<']))
                    .map(str::to_owned)
                    .collect();
                if let Some(first) = command.first() {
                    let rest = words(&command[1..], 2);
                    return (join(basename(first), &rest), None);
                }
                return (program.to_owned(), None);
            }
            "-r" | "--require" | "--import" | "--loader" | "-e" | "-c" | "--eval" => index += 2,
            "run" | "x" | "exec" if program == "bun" || program == "deno" => {
                let rest = words(argv.get(index + 1..).unwrap_or_default(), 2);
                return (join(&format!("{program} {arg}"), &rest), None);
            }
            flag if flag.starts_with('-') => index += 1,
            script => {
                let tool = package_of(script).unwrap_or_else(|| strip_script(basename(script)).to_owned());
                let rest = words(argv.get(index + 1..).unwrap_or_default(), 2);
                return (join(&tool, &rest), Some(tool));
            }
        }
    }
    (program.to_owned(), None)
}

fn join(head: &str, rest: &str) -> String {
    if rest.is_empty() { head.to_owned() } else { format!("{head} {rest}") }
}

fn trim_version(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn strip_script(name: &str) -> &str {
    for suffix in [".js", ".mjs", ".cjs", ".ts", ".mts", ".py", ".rb", ".php", ".pl", ".jar"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            return stem;
        }
    }
    name
}

fn package_of(script: &str) -> Option<String> {
    let (_, inside) = script.rsplit_once("node_modules/")?;
    // `node_modules/.bin/../vite/bin/vite.js` names the `vite` package.
    let mut parts = inside.split('/').filter(|part| !matches!(*part, ".bin" | ".." | "." | ""));
    let first = parts.next()?;
    if first.starts_with('@') { Some(format!("{first}/{}", parts.next()?)) } else { Some(first.to_owned()) }
}

fn words(args: &[String], limit: usize) -> String {
    args.iter()
        .take_while(|arg| !arg.starts_with('-'))
        .filter(|arg| !arg.contains('/') && arg.len() <= 32)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Project {
    pub root: String,
    pub name: String,
    pub marker: String,
}

const MARKERS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "deno.json",
    "composer.json",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "mix.exs",
    "setup.py",
    "requirements.txt",
    "compose.yaml",
    "docker-compose.yml",
    ".git",
];

/// Project lookups may be reused for up to 30 seconds.
#[derive(Default)]
pub struct Projects {
    cache: HashMap<PathBuf, (Option<Project>, Instant)>,
}

impl Projects {
    pub fn find(&mut self, cwd: &str, home: Option<&Path>) -> Option<Project> {
        let key = PathBuf::from(cwd);
        if let Some((project, at)) = self.cache.get(&key)
            && at.elapsed() < Duration::from_secs(30)
        {
            return project.clone();
        }
        let project = find_project(&key, home);
        if self.cache.len() > 512 {
            self.cache.clear();
        }
        self.cache.insert(key, (project.clone(), Instant::now()));
        project
    }
}

/// The nearest ancestor of `cwd` holding a project marker; `.git` only counts as a
/// fallback, so a package in a monorepo is named after itself.
pub fn find_project(cwd: &Path, home: Option<&Path>) -> Option<Project> {
    let mut git_root = None;
    for (depth, directory) in cwd.ancestors().enumerate() {
        if depth > 12 || Some(directory) == home || directory == Path::new("/") {
            break;
        }
        for marker in MARKERS {
            if !directory.join(marker).exists() {
                continue;
            }
            if *marker == ".git" {
                git_root.get_or_insert_with(|| directory.to_path_buf());
                continue;
            }
            let name = manifest_name(directory, marker).unwrap_or_else(|| directory_name(directory));
            return Some(Project { root: directory.display().to_string(), name, marker: (*marker).to_owned() });
        }
    }
    git_root.map(|root| Project {
        name: directory_name(&root),
        root: root.display().to_string(),
        marker: ".git".into(),
    })
}

fn directory_name(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned())
}

fn manifest_name(directory: &Path, marker: &str) -> Option<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(marker))
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return None;
    }
    let mut text = String::new();
    file.take(256 * 1024 + 1).read_to_string(&mut text).ok()?;
    if text.len() > 256 * 1024 {
        return None;
    }
    let name = match marker {
        "package.json" | "deno.json" | "composer.json" => {
            let value: serde_json::Value = serde_json::from_str(&text).ok()?;
            value.get("name")?.as_str()?.to_owned()
        }
        "Cargo.toml" => toml_name(&text, "[package]")?,
        "pyproject.toml" => toml_name(&text, "[project]").or_else(|| toml_name(&text, "[tool.poetry]"))?,
        "go.mod" => text.lines().find_map(|line| line.strip_prefix("module "))?.trim().rsplit('/').next()?.to_owned(),
        _ => return None,
    };
    (!name.is_empty() && name.len() <= 128).then_some(name)
}

fn toml_name(text: &str, table: &str) -> Option<String> {
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == table;
            continue;
        }
        if inside
            && let Some(value) = line.strip_prefix("name").map(str::trim_start).and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value.trim().trim_matches('"').trim_matches('\'').to_owned());
        }
    }
    None
}
