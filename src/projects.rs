use crate::bindings::ContainerRef;
use crate::monitor::Snapshot;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Group {
    pub key: String,
    pub name: String,
    pub directory: Option<String>,
    pub processes: Vec<ProcessRef>,
    pub launchers: Vec<ProcessRef>,
    pub containers: Vec<ContainerRef>,
}

pub fn group(snapshot: &Snapshot) -> Vec<Group> {
    let mut groups = BTreeMap::new();
    for process in &snapshot.processes {
        let directory = process.project.as_ref().map(|p| p.root.clone());
        let key = directory.as_ref().map_or_else(
            || format!("process:{}:{}", process.launcher.pid, process.launcher.start_time),
            |d| format!("path:{d}"),
        );
        let name = process.project.as_ref().map_or_else(|| process.launcher.label.clone(), |p| p.name.clone());
        let group = groups.entry(key.clone()).or_insert_with(|| Group {
            key,
            name,
            directory,
            processes: vec![],
            launchers: vec![],
            containers: vec![],
        });
        group.processes.push(ProcessRef { pid: process.pid, start_time: process.start_time });
        let launcher = ProcessRef { pid: process.launcher.pid, start_time: process.launcher.start_time };
        if !group.launchers.contains(&launcher) {
            group.launchers.push(launcher);
        }
    }
    for report in &snapshot.engines {
        for container in &report.containers {
            let directory = container
                .compose
                .as_ref()
                .and_then(|c| c.working_dir.clone())
                .filter(|d| crate::shortcuts::valid_directory(d));
            let name = container.compose.as_ref().map_or_else(|| container.name.clone(), |c| c.project.clone());
            let key = directory.as_ref().map_or_else(
                || format!("container:{}:{}", report.endpoint.socket.display(), name),
                |d| format!("path:{d}"),
            );
            let group = groups.entry(key.clone()).or_insert_with(|| Group {
                key,
                name,
                directory,
                processes: vec![],
                launchers: vec![],
                containers: vec![],
            });
            group.containers.push(ContainerRef {
                engine: report.endpoint.engine.clone(),
                socket: report.endpoint.socket.to_string_lossy().into_owned(),
                id: container.id.clone(),
                name: container.name.clone(),
            });
        }
    }
    groups.into_values().collect()
}
