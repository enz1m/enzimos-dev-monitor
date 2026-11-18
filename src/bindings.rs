use crate::engines::EngineReport;
use crate::monitor::Port;
use crate::sockets::Protocol;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContainerRef {
    pub engine: String,
    pub socket: String,
    pub id: String,
    pub name: String,
}

pub fn exposure(address: &IpAddr) -> &'static str {
    if address.is_loopback() {
        "loopback"
    } else if address.is_unspecified() {
        "all"
    } else {
        "address"
    }
}

pub fn url(protocol: Protocol, address: &IpAddr, port: u16) -> Option<String> {
    if protocol != Protocol::Tcp {
        return None;
    }
    let address = match address {
        IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_owned(),
        IpAddr::V6(ip) if ip.is_unspecified() => "[::1]".to_owned(),
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Some(format!("http://{address}:{port}"))
}

pub fn merge(ports: &mut Vec<Port>, reports: &[EngineReport], udp: bool) {
    for report in reports.iter().filter(|r| !r.stale) {
        for container in report.containers.iter().filter(|c| c.holds_ports() && c.detail_error.is_none()) {
            for binding in &container.ports {
                let protocol = match binding.protocol.as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" if udp => Protocol::Udp,
                    _ => continue,
                };
                let Ok(address) = binding.host_address.parse::<IpAddr>() else { continue };
                let reference = ContainerRef {
                    engine: report.endpoint.engine.clone(),
                    socket: report.endpoint.socket.to_string_lossy().into_owned(),
                    id: container.id.clone(),
                    name: container.name.clone(),
                };
                let existing = ports.iter_mut().find(|p| {
                    p.protocol == protocol.name() && p.address == address.to_string() && p.port == binding.host_port
                });
                if let Some(port) = existing {
                    if !port.published_by.contains(&reference) {
                        port.published_by.push(reference);
                    }
                    if port.source == "published" {
                        port.container = (port.published_by.len() == 1).then(|| port.published_by[0].clone());
                    }
                } else {
                    // Engine-forwarded ports may have no host listening socket (kernel forwarding).
                    ports.push(Port {
                        protocol: protocol.name(),
                        address: address.to_string(),
                        port: binding.host_port,
                        exposure: exposure(&address),
                        uid: None,
                        own: false,
                        pid: None,
                        start_time: None,
                        source: "published",
                        container: Some(reference.clone()),
                        published_by: vec![reference],
                        url: url(protocol, &address, binding.host_port),
                    });
                }
            }
        }
    }
    ports.sort_by(|a, b| (a.port, a.protocol, &a.address).cmp(&(b.port, b.protocol, &b.address)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{Container, Endpoint, PublishedPort};
    #[test]
    fn binding_identity_keeps_families_filters_udp_and_preserves_host_ownership() {
        let mut c = Container {
            engine: "docker".into(),
            id: "a".repeat(64),
            name: "web".into(),
            state: "running".into(),
            ..Container::default()
        };
        for (address, protocol) in [("127.0.0.2", "tcp"), ("::1", "tcp"), ("127.0.0.1", "udp")] {
            c.ports.push(PublishedPort {
                protocol: protocol.into(),
                host_address: address.into(),
                host_port: 8080,
                container_port: 80,
            });
        }
        let mut reports = vec![EngineReport {
            endpoint: Endpoint { engine: "docker".into(), socket: "/run/docker.sock".into(), rootless: false },
            containers: vec![c],
            error: None,
            stale: false,
            truncated: false,
        }];
        let mut ports = vec![];
        merge(&mut ports, &reports, false);
        assert_eq!(ports.len(), 2);
        assert_eq!(
            ports.iter().find(|p| p.address == "127.0.0.2").unwrap().url.as_deref(),
            Some("http://127.0.0.2:8080")
        );
        ports[0].source = "socket";
        ports[0].pid = Some(42);
        ports[0].container = None;
        merge(&mut ports, &reports, false);
        assert_eq!(ports[0].container, None);
        assert_eq!(ports[0].pid, Some(42));
        reports[0].containers[0].state = "exited".into();
        let mut ports = vec![];
        merge(&mut ports, &reports, true);
        assert!(ports.is_empty());
        reports[0].containers[0].state = "paused".into();
        merge(&mut ports, &reports, true);
        assert_eq!(ports.len(), 3);
    }
}
