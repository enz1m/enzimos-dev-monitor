use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Container {
    pub engine: String,
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub health: Option<String>,
    pub created: Option<i64>,
    pub started_at: Option<String>,
    pub restart_policy: Option<String>,
    /// Configured boot/login startup; unknown when ownership or persistent enablement is unproven.
    pub autostart: Option<bool>,
    pub startup: crate::startup::Startup,
    pub systemd_unit: Option<String>,
    pub compose: Option<Compose>,
    pub ports: Vec<PublishedPort>,
    pub mounts: Vec<Mount>,
    pub pid: Option<u32>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub processes: Option<u64>,
    pub detail_error: Option<String>,
    pub stats_error: Option<String>,
}

impl Container {
    pub fn holds_ports(&self) -> bool {
        matches!(self.state.as_str(), "running" | "paused" | "restarting")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Compose {
    pub project: String,
    pub service: Option<String>,
    pub working_dir: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublishedPort {
    pub protocol: String,
    pub host_address: String,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mount {
    pub kind: String,
    pub source: String,
    pub destination: String,
    pub writable: bool,
    pub volume: Option<String>,
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn describe(engine: &str, item: &Value, detail: &Value) -> Container {
    let text = |value: &Value, path: &str| value.pointer(path).and_then(Value::as_str).map(str::to_owned);
    let labels = detail.pointer("/Config/Labels").filter(|v| v.is_object()).or_else(|| item.get("Labels"));
    let label = |key: &str| labels.and_then(|labels| labels.get(key)).and_then(Value::as_str).map(str::to_owned);
    let name = detail
        .get("Name")
        .and_then(Value::as_str)
        .or_else(|| item.pointer("/Names/0").and_then(Value::as_str))
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_owned();
    let restart_policy = text(detail, "/HostConfig/RestartPolicy/Name").filter(|p| !p.is_empty() && p != "no");
    let systemd_unit = label("PODMAN_SYSTEMD_UNIT");
    let compose = label("com.docker.compose.project").map(|project| Compose {
        project,
        service: label("com.docker.compose.service"),
        working_dir: label("com.docker.compose.project.working_dir"),
    });
    Container {
        engine: engine.to_owned(),
        id: text(item, "/Id").unwrap_or_default(),
        name,
        image: text(detail, "/Config/Image").or_else(|| text(item, "/Image")).unwrap_or_default(),
        state: text(detail, "/State/Status").or_else(|| text(item, "/State")).unwrap_or_default(),
        status: text(item, "/Status").unwrap_or_default(),
        health: text(detail, "/State/Health/Status"),
        created: item.get("Created").and_then(Value::as_i64),
        started_at: text(detail, "/State/StartedAt").filter(|at| !at.starts_with("0001-")),
        restart_policy,
        systemd_unit,
        compose,
        ports: published_ports(detail.pointer("/NetworkSettings/Ports")).unwrap_or_else(|| list_ports(item)),
        mounts: mounts(detail.get("Mounts").or_else(|| item.get("Mounts"))),
        pid: detail
            .pointer("/State/Pid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|p| *p > 0),
        ..Container::default()
    }
}

fn published_ports(value: Option<&Value>) -> Option<Vec<PublishedPort>> {
    let mut result = Vec::new();
    for (key, bindings) in value?.as_object()? {
        let (port, protocol) = key.split_once('/')?;
        if !matches!(protocol, "tcp" | "udp") {
            continue;
        }
        let Ok(container_port) = port.parse::<u16>() else { continue };
        for binding in bindings.as_array().map(Vec::as_slice).unwrap_or_default() {
            let host_port =
                binding.get("HostPort").and_then(Value::as_str).and_then(|p| p.parse::<u16>().ok()).filter(|p| *p > 0);
            let address = binding.get("HostIp").and_then(Value::as_str).unwrap_or("");
            if let Some(host_port) = host_port {
                if address.parse::<std::net::IpAddr>().is_err() {
                    continue;
                }
                result.push(PublishedPort {
                    protocol: protocol.into(),
                    host_address: address.into(),
                    host_port,
                    container_port,
                });
            }
        }
    }
    result
        .sort_by(|a, b| (a.host_port, &a.protocol, &a.host_address).cmp(&(b.host_port, &b.protocol, &b.host_address)));
    result.dedup();
    Some(result)
}

fn list_ports(item: &Value) -> Vec<PublishedPort> {
    let mut result = Vec::new();
    for port in item.get("Ports").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        let number = |key| port.get(key).and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok()).filter(|p| *p > 0);
        let protocol = port.get("Type").and_then(Value::as_str).unwrap_or("");
        let address = port.get("IP").and_then(Value::as_str).unwrap_or("");
        if !matches!(protocol, "tcp" | "udp") || address.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        if let (Some(host_port), Some(container_port)) = (number("PublicPort"), number("PrivatePort")) {
            result.push(PublishedPort {
                protocol: protocol.into(),
                host_address: address.into(),
                host_port,
                container_port,
            });
        }
    }
    result
}

fn mounts(value: Option<&Value>) -> Vec<Mount> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|mount| {
            let text = |key| mount.get(key).and_then(Value::as_str).unwrap_or_default().to_owned();
            Mount {
                kind: text("Type"),
                source: text("Source"),
                destination: text("Destination"),
                writable: mount.get("RW").and_then(Value::as_bool).unwrap_or(false),
                volume: mount.get("Name").and_then(Value::as_str).filter(|n| !n.is_empty()).map(str::to_owned),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_and_systemd_labels_do_not_claim_verified_autostart() {
        let c = describe(
            "podman",
            &json!({"Id": "a".repeat(64), "Names": ["/web"], "State": "running"}),
            &json!({"HostConfig":{"RestartPolicy":{"Name":"always"}}, "Config":{"Labels":{"PODMAN_SYSTEMD_UNIT":"web.service"}},
                "State":{"Pid":42,"Health":{"Status":"healthy"}}, "NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"::1","HostPort":"8080"}]}}}),
        );
        assert_eq!(c.autostart, None);
        assert_eq!(c.systemd_unit.as_deref(), Some("web.service"));
        assert_eq!(c.restart_policy.as_deref(), Some("always"));
        assert_eq!(c.ports[0].host_address, "::1");
        assert_eq!(c.health.as_deref(), Some("healthy"));
    }

    #[test]
    fn identifiers_and_ports_are_not_truncated_or_ambiguous() {
        assert!(valid_id(&"a".repeat(64)));
        for id in ["a", "abcdefabcdef", "../containers", &"G".repeat(64)] {
            assert!(!valid_id(id));
        }
        assert!(
            list_ports(&json!({"Ports":[{"PublicPort":65537,"PrivatePort":80,"IP":"::1","Type":"tcp"}]})).is_empty()
        );
    }
}
