use std::io::{self, BufRead, BufReader, Read};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::http::{Body, Connection, invalid};

// Health-check exec events are frequent and do not invalidate container metadata.
const EVENTS: &str = r#"{"type":["container"],"event":["create","destroy","die","start","stop","restart","rename","update","pause","unpause","oom","health_status"]}"#;

#[derive(Default)]
struct State {
    generation: AtomicU64,
    ready: AtomicBool,
    closed: AtomicBool,
    cancelled: AtomicBool,
}

pub struct Watch {
    socket: UnixStream,
    state: Arc<State>,
    thread: Option<JoinHandle<()>>,
}

impl Watch {
    pub fn open(socket: &Path, deadline: Instant) -> io::Result<Self> {
        let mut connection = Connection::open(socket, deadline)?;
        let control = connection.stream.try_clone()?;
        let filters: String = EVENTS.bytes().map(|byte| format!("%{byte:02X}")).collect();
        let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(1);
        connection.send("GET", &format!("/events?since={since}&filters={filters}"))?;
        let state = Arc::new(State::default());
        let shared = state.clone();
        let thread = std::thread::Builder::new().name("engine-events".into()).spawn(move || {
            let _ = consume(connection, &shared);
            shared.closed.store(true, Ordering::Release);
            shared.generation.fetch_add(1, Ordering::AcqRel);
        })?;
        Ok(Self { socket: control, state, thread: Some(thread) })
    }

    pub fn generation(&self) -> u64 {
        self.state.generation.load(Ordering::Acquire)
    }
    pub fn ready(&self) -> bool {
        self.state.ready.load(Ordering::Acquire)
    }
    pub fn closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.state.cancelled.store(true, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn consume(connection: Connection, state: &State) -> io::Result<()> {
    let mut body = Body::new(connection)?;
    if body.status != 200 {
        return Err(invalid("engine event subscription rejected"));
    }
    body.inner_mut().deadline = None;
    state.ready.store(true, Ordering::Release);
    let mut body = BufReader::new(body);
    while !state.cancelled.load(Ordering::Acquire) {
        let mut event = Vec::new();
        let count = (&mut body).take(64 * 1024 + 1).read_until(b'\n', &mut event)?;
        if count == 0 {
            return Ok(());
        }
        if count > 64 * 1024 || !event.ends_with(b"\n") {
            return Err(invalid("oversized or truncated engine event"));
        }
        let event: serde_json::Value = serde_json::from_slice(&event).map_err(|_| invalid("invalid engine event"))?;
        let kind = event.get("Type").and_then(|v| v.as_str());
        let action = event.get("Action").or_else(|| event.get("status")).and_then(|v| v.as_str()).unwrap_or("");
        if kind.is_none_or(|kind| kind == "container") && !action.starts_with("exec_") {
            state.generation.fetch_add(1, Ordering::AcqRel);
        }
    }
    Ok(())
}
