use devmon::actions::{self, Scope};
use devmon::caller::{self, Access, Client};
use devmon::monitor::Options;
use devmon::procfs::{Table, current_uid};
use devmon::worker::{Activity, Engines, Lane, Ports};
use devmon::{engines, inspect, shortcuts};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zbus::{fdo, message::Header};

const NAME: &str = "org.enzimos.DevMonitor1";
const PATH: &str = "/org/enzimos/DevMonitor1";

struct Service {
    ports: Lane<Ports>,
    engines: Lane<Engines>,
    queries: Lane<()>,
    controls: Lane<()>,
    signals: Lane<()>,
    activity: Arc<Activity>,
    control_client: PathBuf,
}

impl Service {
    async fn admit(&self, connection: &zbus::Connection, header: &Header<'_>, access: Access) -> fdo::Result<()> {
        let refused = || fdo::Error::AccessDenied("caller not admitted".into());
        let sender = header.sender().ok_or_else(refused)?;
        let credentials =
            fdo::DBusProxy::new(connection).await?.get_connection_credentials(sender.clone().into()).await?;
        let (Some(pid), Some(uid)) = (credentials.process_id(), credentials.unix_user_id()) else {
            return Err(refused());
        };
        if uid != current_uid() {
            return Err(refused());
        }
        let client = (access == Access::Control).then(|| Client::installed(&self.control_client)).flatten();
        caller::admit(Path::new("/proc"), pid, uid, access, client).map_err(failed)
    }
}

fn json<T: serde::Serialize>(value: &T) -> fdo::Result<String> {
    serde_json::to_string(value).map_err(|e| fdo::Error::Failed(e.to_string()))
}

fn failed(error: std::io::Error) -> fdo::Error {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => fdo::Error::AccessDenied(error.to_string()),
        std::io::ErrorKind::InvalidInput => fdo::Error::InvalidArgs(error.to_string()),
        std::io::ErrorKind::WouldBlock => fdo::Error::LimitsExceeded(error.to_string()),
        _ => fdo::Error::Failed(error.to_string()),
    }
}

fn endpoint(engine: &str, socket: &str) -> std::io::Result<engines::Endpoint> {
    engines::endpoints(&Table::scan(), current_uid())
        .into_iter()
        .find(|endpoint| endpoint.engine == engine && endpoint.socket.to_str() == Some(socket))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown or stopped container engine"))
}

#[zbus::interface(name = "org.enzimos.DevMonitor1")]
impl Service {
    async fn snapshot(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        include_system: bool,
        include_udp: bool,
        containers: bool,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Observe).await?;
        let options = Options { include_system, include_udp, containers };
        let mut snapshot = (*self.ports.call(Ports::snapshot).await.map_err(failed)?).clone();
        let engines = if containers { self.engines.call(Engines::snapshot).await.map_err(failed)? } else { Vec::new() };
        snapshot.attach(engines, options);
        json(&snapshot)
    }

    async fn lookup(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        port: u16,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Observe).await?;
        let mut snapshot = (*self.ports.call(Ports::snapshot).await.map_err(failed)?).clone();
        snapshot.attach(
            self.engines.call(Engines::snapshot).await.map_err(failed)?,
            Options { include_system: true, include_udp: true, containers: true },
        );
        let ports: Vec<_> = snapshot.ports.iter().filter(|p| p.port == port).collect();
        let processes: Vec<_> = snapshot.processes.iter().filter(|p| p.ports.contains(&port)).collect();
        json(&serde_json::json!({"ports":ports,"processes":processes,"warnings":snapshot.warnings}))
    }

    async fn inspect(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        pid: u32,
        start_time: u64,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Observe).await?;
        json(&self.queries.call(move |()| inspect::inspect(pid, start_time)).await.map_err(failed)?)
    }

    async fn signal(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        pid: u32,
        start_time: u64,
        tree: bool,
        force: bool,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Control).await?;
        json(
            &self
                .signals
                .call(move |()| {
                    actions::signal(pid, start_time, if tree { Scope::Tree } else { Scope::Process }, force)
                })
                .await
                .map_err(failed)?,
        )
    }

    async fn container(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        engine: String,
        socket: String,
        id: String,
        action: String,
    ) -> fdo::Result<()> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Control).await?;
        let endpoint = self
            .controls
            .call(move |()| {
                let endpoint = endpoint(&engine, &socket)?;
                engines::action(&endpoint, &id, &action)?;
                Ok(endpoint)
            })
            .await
            .map_err(failed)?;
        let _ = self
            .engines
            .call(move |state| {
                state.invalidate(&endpoint);
                Ok(())
            })
            .await;
        Ok(())
    }

    async fn container_logs(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        engine: String,
        socket: String,
        id: String,
        tail: u32,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Control).await?;
        self.queries.call(move |()| engines::logs(&endpoint(&engine, &socket)?, &id, tail)).await.map_err(failed)
    }

    async fn shortcuts(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        pid: u32,
        start_time: u64,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Observe).await?;
        json(&self.queries.call(move |()| shortcuts::for_process(pid, start_time)).await.map_err(failed)?)
    }

    async fn container_shortcuts(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        engine: String,
        socket: String,
        id: String,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Observe).await?;
        json(
            &self
                .queries
                .call(move |()| engines::shortcuts(&endpoint(&engine, &socket)?, &id))
                .await
                .map_err(failed)?,
        )
    }

    async fn process_logs(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        pid: u32,
        start_time: u64,
        tail: u32,
    ) -> fdo::Result<String> {
        let _active = self.activity.enter().map_err(failed)?;
        self.admit(connection, &header, Access::Control).await?;
        json(&self.queries.call(move |()| shortcuts::process_logs(pid, start_time, tail)).await.map_err(failed)?)
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        let _active = self.activity.enter();
        2
    }
}

// `--control-client PATH` names another root-owned control client in place of the Shell.
fn control_client() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, ..) => Ok(PathBuf::from(caller::SHELL)),
        (Some(flag), Some(path), None) if flag == "--control-client" => Ok(PathBuf::from(path)),
        _ => Err("usage: enzimos-dev-monitor [--control-client PATH]".into()),
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let activity = Arc::new(Activity::default());
    let service = Service {
        ports: Lane::new("port-scan", Ports::default(), Ports::idle)?,
        engines: Lane::new("containers", Engines::default(), Engines::idle)?,
        queries: Lane::new("details", (), |()| {})?,
        controls: Lane::new("controls", (), |()| {})?,
        signals: Lane::new("signals", (), |()| {})?,
        activity: activity.clone(),
        control_client: control_client()?,
    };
    let connection = zbus::blocking::connection::Builder::session()?.name(NAME)?.serve_at(PATH, service)?.build()?;
    activity.wait_idle(Duration::from_secs(60));
    drop(connection);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("enzimos-dev-monitor: {error}");
        std::process::exit(1);
    }
}
