use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Startup {
    pub on_engine_start: Option<bool>,
    pub at_login: Option<bool>,
    pub at_boot: Option<bool>,
    pub unit: Option<String>,
    pub unit_file_state: Option<String>,
    pub verification_age_ms: Option<u64>,
    pub user_unit: bool,
    pub linger: Option<bool>,
    pub reason: String,
}

impl Startup {
    pub fn automatic(&self) -> Option<bool> {
        match (self.at_login, self.at_boot) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct Cache {
    states: HashMap<(bool, String), (Instant, Option<String>)>,
    linger: Option<(Instant, Option<bool>)>,
}

fn unit_name(unit: &str) -> bool {
    unit.len() <= 255
        && unit.ends_with(".service")
        && !unit.starts_with('-')
        && !unit.starts_with("user@")
        && unit.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-.@:\\".contains(&c))
}

fn enabled(state: Option<&str>) -> Option<bool> {
    match state {
        Some("enabled") => Some(true),
        Some("disabled" | "masked" | "masked-runtime" | "not-found") => Some(false),
        _ => None,
    }
}

fn query(command: &mut Command, deadline: Instant) -> Option<String> {
    let output = crate::command::run(command, deadline.min(Instant::now() + Duration::from_millis(250)), 1024).ok()?;
    let value = std::str::from_utf8(&output.bytes).ok()?.trim();
    (!value.is_empty() && !value.contains(char::is_whitespace)).then(|| value.to_owned())
}

pub fn socket_activation_unit(
    endpoint: &crate::engines::Endpoint,
    peer_pid: Option<u32>,
    deadline: Instant,
) -> Option<String> {
    let pid = peer_pid?;
    let entry = crate::procfs::read_stat(pid)?;
    if endpoint.engine != "docker" || entry.comm != "systemd" {
        return None;
    }
    let mut command = Command::new("/usr/bin/systemctl");
    if endpoint.rootless {
        command.arg("--user");
    }
    command.args([
        "show",
        "docker.socket",
        "--property=Listen",
        "--property=Triggers",
        "--property=ActiveState",
        "--no-pager",
    ]);
    let output =
        crate::command::run(&mut command, deadline.min(Instant::now() + Duration::from_millis(250)), 4096).ok()?;
    if !output.status.success() {
        return None;
    }
    activation_unit(std::str::from_utf8(&output.bytes).ok()?, &endpoint.socket)
}

fn activation_unit(properties: &str, socket: &std::path::Path) -> Option<String> {
    let property = |key: &str| properties.lines().find_map(|line| line.strip_prefix(key));
    if property("ActiveState=")? != "active" {
        return None;
    }
    let listen = property("Listen=")?.strip_suffix(" (Stream)")?;
    if std::path::Path::new(listen).canonicalize().ok()?.as_path() != socket {
        return None;
    }
    let trigger = property("Triggers=")?;
    unit_name(trigger).then(|| trigger.to_owned())
}

impl Cache {
    pub fn verify(
        &mut self,
        engine: &str,
        rootless: bool,
        engine_unit: Option<&str>,
        container: &crate::container::Container,
        deadline: Instant,
    ) -> Startup {
        let mut result = Startup {
            on_engine_start: match container.restart_policy.as_deref() {
                Some("always") => Some(true),
                Some("unless-stopped") if container.holds_ports() => Some(true),
                Some("unless-stopped") => None,
                Some(_) | None if container.detail_error.is_none() => Some(false),
                _ => None,
            },
            user_unit: rootless,
            ..Startup::default()
        };
        if engine == "podman" {
            result.on_engine_start = None;
        }
        let unit = if engine == "podman" {
            container.systemd_unit.as_deref().filter(|unit| {
                container
                    .pid
                    .and_then(|pid| crate::stats::identity(pid, &container.id))
                    .is_some_and(|identity| identity.cgroup.split('/').any(|part| part == *unit))
            })
        } else {
            engine_unit
        };
        let Some(unit) = unit.filter(|unit| unit_name(unit)) else {
            result.reason =
                "No verified owning systemd service; restart policy alone does not prove login/boot startup".into();
            return result;
        };
        result.unit = Some(unit.into());
        let key = (rootless, unit.to_owned());
        if self.states.get(&key).is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30)) {
            let mut command = Command::new("/usr/bin/systemctl");
            if rootless {
                command.arg("--user");
            }
            command.args(["is-enabled", "--", unit]).env("LC_ALL", "C");
            let value = query(&mut command, deadline);
            self.states.insert(key.clone(), (Instant::now(), value));
        }
        result.unit_file_state = self.states.get(&key).and_then(|(_, state)| state.clone());
        result.verification_age_ms = self.states.get(&key).map(|(at, _)| at.elapsed().as_millis() as u64);
        let policy = if engine == "podman" { Some(true) } else { result.on_engine_start };
        let automatic = match (enabled(result.unit_file_state.as_deref()), policy) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
        if rootless {
            if self.linger.as_ref().is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30)) {
                let uid = crate::procfs::current_uid().to_string();
                let value = query(
                    Command::new("/usr/bin/loginctl")
                        .args(["show-user", &uid, "--property=Linger", "--value"])
                        .env("LC_ALL", "C"),
                    deadline,
                );
                self.linger = Some((
                    Instant::now(),
                    value.and_then(|v| match v.as_str() {
                        "yes" => Some(true),
                        "no" => Some(false),
                        _ => None,
                    }),
                ));
            }
            result.linger = self.linger.and_then(|(_, value)| value);
            result.at_login = automatic;
            result.at_boot = match (automatic, result.linger) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            };
        } else {
            result.at_login = Some(false);
            result.at_boot = automatic;
        }
        result.reason =
            "Observed owning service and current unit enablement; conditions/dependencies may still prevent startup"
                .into();
        if self.states.len() > 1024 {
            self.states.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(30));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socket_activation_requires_matching_active_stream_and_one_service() {
        let path = std::env::temp_dir().join(format!("devmon-activation-{}.sock", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let valid = format!("ActiveState=active\nListen={} (Stream)\nTriggers=docker.service\n", path.display());
        assert_eq!(activation_unit(&valid, &path).as_deref(), Some("docker.service"));
        assert!(activation_unit(&valid.replace("active", "inactive"), &path).is_none());
        assert!(activation_unit(&valid.replace("docker.service", "docker.service other.service"), &path).is_none());
        assert!(activation_unit(&valid, std::path::Path::new("/different.sock")).is_none());
        drop(listener);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn podman_api_activation_is_not_a_container_restart_trigger() {
        let container = crate::container::Container { restart_policy: Some("always".into()), ..Default::default() };
        let status = Cache::default().verify("podman", true, None, &container, Instant::now() + Duration::from_secs(1));
        assert_eq!(status.on_engine_start, None);
        assert_eq!(status.automatic(), None);
    }

    #[test]
    fn runtime_enablement_and_static_units_do_not_prove_persistent_startup() {
        assert_eq!(enabled(Some("enabled")), Some(true));
        assert_eq!(enabled(Some("disabled")), Some(false));
        for state in ["static", "indirect", "enabled-runtime", "linked"] {
            assert_eq!(enabled(Some(state)), None);
        }
        assert_eq!(Startup::default().automatic(), None);
        assert!(!unit_name("../../docker.service"));
        assert!(!unit_name("user@1000.service"));
    }
}
