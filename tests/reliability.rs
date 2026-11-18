use devmon::engines::{self, Cache, Endpoint};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct State {
    items: Vec<Value>,
    details: Value,
    status: u16,
    header: bool,
    streams: Vec<UnixStream>,
    lists: usize,
    inspections: usize,
}

struct Engine {
    root: PathBuf,
    endpoint: Endpoint,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Engine {
    fn new(header: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "devmon-regression-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State { status: 200, header, ..State::default() }));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let done = stop.clone();
        let thread = thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_ascii_whitespace().nth(1).unwrap_or("");
                let mut state = shared.lock().unwrap();
                if path.starts_with("/events?") {
                    if state.header {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
                    }
                    state.streams.push(stream);
                    continue;
                }
                let (status, body) = if path.starts_with("/containers/json?") {
                    state.lists += 1;
                    (state.status, serde_json::to_vec(&state.items).unwrap())
                } else {
                    state.inspections += 1;
                    (200, serde_json::to_vec(&state.details).unwrap())
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        Self {
            root,
            endpoint: Endpoint { engine: "docker".into(), socket, rootless: false },
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn container(&self) {
        let id = "a".repeat(64);
        let mut state = self.state.lock().unwrap();
        state.items = vec![json!({"Id":id,"Names":["/fixture"],"State":"running"})];
        state.details =
            json!({"Id":id,"State":{"Pid":0,"Status":"running"},"HostConfig":{"RestartPolicy":{"Name":"no"}}});
    }

    fn event(&self, with_header: bool) {
        wait(|| !self.state.lock().unwrap().streams.is_empty());
        let mut state = self.state.lock().unwrap();
        let stream = state.streams.last_mut().unwrap();
        if with_header {
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        }
        let event = b"{\"Type\":\"container\",\"Action\":\"update\"}\n";
        write!(stream, "{:x}\r\n", event.len()).unwrap();
        stream.write_all(event).unwrap();
        stream.write_all(b"\r\n").unwrap();
        thread::sleep(Duration::from_millis(30));
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
        self.state.lock().unwrap().streams.clear();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

fn wait(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn first_coalesced_event_is_not_lost_and_update_invalidates_details() {
    let _serial = SERIAL.lock().unwrap();
    let engine = Engine::new(false);
    let mut cache = Cache::watching();
    assert!(engines::list(&engine.endpoint, &mut cache).containers.is_empty());
    engine.container();
    engine.event(true);
    let first = engines::list(&engine.endpoint, &mut cache);
    assert_eq!(first.containers.len(), 1);
    assert_eq!(first.containers[0].restart_policy, None);
    engine.state.lock().unwrap().details["HostConfig"]["RestartPolicy"]["Name"] = "always".into();
    engine.event(false);
    let second = engines::list(&engine.endpoint, &mut cache);
    assert_eq!(second.containers[0].restart_policy.as_deref(), Some("always"));
    assert_eq!(engine.state.lock().unwrap().inspections, 2);
}

#[test]
fn list_failure_closes_watcher_and_retries_are_backed_off() {
    let _serial = SERIAL.lock().unwrap();
    let engine = Engine::new(true);
    engine.state.lock().unwrap().status = 500;
    let mut cache = Cache::watching();
    for _ in 0..4 {
        assert!(engines::list(&engine.endpoint, &mut cache).error.is_some());
    }
    let mut state = engine.state.lock().unwrap();
    assert_eq!(state.lists, 1);
    assert_eq!(state.streams.len(), 1);
    state.streams[0].set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    assert_eq!(state.streams[0].read(&mut [0]).unwrap(), 0);
}

#[test]
fn replaced_socket_cancels_the_old_reader_and_discards_its_inventory() {
    let _serial = SERIAL.lock().unwrap();
    let first = Engine::new(true);
    let second = Engine::new(true);
    let mut cache = Cache::watching();
    assert!(engines::list(&first.endpoint, &mut cache).containers.is_empty());
    wait(|| !first.state.lock().unwrap().streams.is_empty());
    second.container();
    std::fs::rename(&second.endpoint.socket, &first.endpoint.socket).unwrap();
    let report = engines::list(&first.endpoint, &mut cache);
    assert_eq!(report.containers.len(), 1);
    assert!(!report.stale);
    let mut state = first.state.lock().unwrap();
    state.streams[0].set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    assert_eq!(state.streams[0].read(&mut [0]).unwrap(), 0);
}

#[test]
fn cache_drop_cancels_a_blocked_event_reader() {
    let _serial = SERIAL.lock().unwrap();
    let engine = Engine::new(true);
    let mut cache = Cache::watching();
    engines::list(&engine.endpoint, &mut cache);
    wait(|| !engine.state.lock().unwrap().streams.is_empty());
    let started = Instant::now();
    drop(cache);
    assert!(started.elapsed() < Duration::from_secs(1));
    let mut state = engine.state.lock().unwrap();
    state.streams[0].set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    assert_eq!(state.streams[0].read(&mut [0]).unwrap(), 0);
}

#[test]
fn fifo_manifest_is_not_opened_as_a_blocking_file() {
    let _serial = SERIAL.lock().unwrap();
    let engine = Engine::new(true);
    let path = engine.root.join("package.json");
    assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
    let started = Instant::now();
    let project = devmon::describe::find_project(&engine.root, None).unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(project.name, engine.root.file_name().unwrap().to_str().unwrap());
}

#[test]
fn request_deadline_is_total_not_per_byte() {
    let _serial = SERIAL.lock().unwrap();
    let engine = Engine::new(true);
    let path = engine.root.join("slow.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let writer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
        for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]" {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
    });
    let start = Instant::now();
    assert!(engines::request(&path, "GET", "/", Duration::from_millis(100)).is_err());
    assert!(start.elapsed() < Duration::from_millis(400));
    writer.join().unwrap();
}

#[test]
fn session_shells_and_command_wrappers_are_distinct() {
    use devmon::describe::shell_is_interactive;
    let argv = |args: &[&str]| args.iter().map(std::string::ToString::to_string).collect::<Vec<_>>();
    for args in [vec!["bash", "-i"], vec!["zsh"], vec!["-bash"], vec!["fish", "--interactive"]] {
        assert!(shell_is_interactive(&argv(&args)));
    }
    for args in [vec!["sh", "-c", "npm run dev"], vec!["bash", "-lc", "sleep 1"], vec!["bash", "script.sh"]] {
        assert!(!shell_is_interactive(&argv(&args)));
    }
}
