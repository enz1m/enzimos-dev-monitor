use crate::procfs;
use serde::Serialize;
use std::io;
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
pub struct Launch {
    pub argv: Vec<String>,
    pub directory: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Shortcuts {
    pub pid: u32,
    pub start_time: u64,
    pub directory: String,
    pub folder_uri: String,
    pub folder: Launch,
    pub terminal: Launch,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryShortcuts {
    pub directory: String,
    pub folder_uri: String,
    pub folder: Launch,
    pub terminal: Launch,
}

pub fn for_directory(directory: &str) -> io::Result<DirectoryShortcuts> {
    if !valid_directory(directory) || !Path::new(directory).is_dir() {
        return Err(io::Error::other("project directory unavailable"));
    }
    let directory = Path::new(directory)
        .canonicalize()?
        .to_str()
        .ok_or_else(|| io::Error::other("directory is not UTF-8"))?
        .to_owned();
    if !valid_directory(&directory) {
        return Err(io::Error::other("project directory is not usable"));
    }
    let folder_uri = file_uri(&directory);
    Ok(DirectoryShortcuts {
        folder: Launch { argv: vec!["/usr/bin/xdg-open".into(), folder_uri.clone()], directory: directory.clone() },
        terminal: Launch {
            argv: vec!["/usr/bin/terminal-emulator".into(), "--working-directory".into(), directory.clone()],
            directory: directory.clone(),
        },
        directory,
        folder_uri,
    })
}

pub fn valid_directory(directory: &str) -> bool {
    let path = Path::new(directory);
    path.is_absolute()
        && directory.len() <= 4096
        && !directory.chars().any(char::is_control)
        && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

pub fn file_uri(directory: &str) -> String {
    let escaped: String = directory
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("file://{escaped}")
}

pub fn verify(pid: u32, start: u64) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let directory = procfs::proc_path(pid, "");
    let meta = std::fs::metadata(&directory)?;
    let entry = procfs::read_stat(pid).ok_or_else(|| io::Error::other("unreadable process identity"))?;
    if entry.start_time != start {
        return Err(io::Error::new(io::ErrorKind::NotFound, "process identity changed"));
    }
    // Non-dumpable tasks show root as their /proc owner, as in Table::scan.
    let uid = if meta.uid() == 0 { procfs::status_uid(&directory).unwrap_or(0) } else { meta.uid() };
    if uid != procfs::current_uid() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "owned by another user"));
    }
    Ok(())
}

pub fn for_process(pid: u32, start_time: u64) -> io::Result<Shortcuts> {
    verify(pid, start_time)?;
    let cwd =
        procfs::host_cwd(pid).ok_or_else(|| io::Error::other("process directory unavailable in the host namespace"))?;
    if !valid_directory(&cwd) || !Path::new(&cwd).is_dir() {
        return Err(io::Error::other("process directory is not a usable local path"));
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let directory = crate::describe::find_project(Path::new(&cwd), home.as_deref()).map(|p| p.root).unwrap_or(cwd);
    let shortcuts = for_directory(&directory)?;
    verify(pid, start_time)?;
    Ok(Shortcuts {
        pid,
        start_time,
        directory: shortcuts.directory,
        folder_uri: shortcuts.folder_uri,
        folder: shortcuts.folder,
        terminal: shortcuts.terminal,
    })
}

#[derive(Serialize)]
pub struct Logs {
    pub source: &'static str,
    pub text: String,
    pub note: &'static str,
}

pub fn process_logs(pid: u32, start_time: u64, tail: u32) -> io::Result<Logs> {
    verify(pid, start_time)?;
    let boot = procfs::boot_time().ok_or_else(|| io::Error::other("boot time unavailable"))?;
    let ticks = procfs::clock_ticks();
    let since = format!("@{}.{:06}", boot + start_time / ticks, start_time % ticks * 1_000_000 / ticks);
    let output = crate::command::run(
        Command::new("/usr/bin/journalctl").args([
            "--no-pager",
            "--quiet",
            "--output=short-iso",
            "-b",
            "--since",
            &since,
            "-n",
            &tail.clamp(1, 5000).to_string(),
            &format!("_UID={}", procfs::current_uid()),
            &format!("_PID={pid}"),
        ]),
        Instant::now() + Duration::from_secs(2),
        256 * 1024,
    )?;
    verify(pid, start_time)?;
    if !output.status.success() {
        return Err(io::Error::other("journal unavailable to this user"));
    }
    Ok(Logs {
        source: "journal",
        text: String::from_utf8_lossy(&output.bytes).into_owned(),
        note: "Only accessible journal entries since process start; terminal stdout is not captured",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_arguments_are_data_not_shell_commands() {
        let directory = "/tmp/a space/$(touch sentinel)#?";
        assert!(valid_directory(directory));
        assert_eq!(file_uri(directory), "file:///tmp/a%20space/%24%28touch%20sentinel%29%23%3F");
        assert!(!valid_directory("relative"));
        assert!(!valid_directory("/tmp/../etc"));
        assert!(!valid_directory("/tmp/\u{1b}bad"));
    }
}
