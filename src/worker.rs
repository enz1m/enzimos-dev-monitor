use crate::engines::{self, Cache, Endpoint, EngineReport};
use crate::monitor::{Monitor, Options, Snapshot};
use std::io;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

const FRESH: Duration = Duration::from_millis(250);
type Job<S> = Box<dyn FnOnce(&mut S) + Send>;

pub struct Lane<S> {
    sender: mpsc::SyncSender<Job<S>>,
}

impl<S: Send + 'static> Lane<S> {
    pub fn new(name: &str, mut state: S, idle: fn(&mut S)) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job<S>>(32);
        std::thread::Builder::new().name(name.into()).spawn(move || {
            while let Ok(job) = receiver.recv() {
                job(&mut state);
                loop {
                    match receiver.recv_timeout(Duration::from_secs(5)) {
                        Ok(job) => job(&mut state),
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            idle(&mut state);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            }
        })?;
        Ok(Self { sender })
    }

    pub async fn call<R: Send + 'static>(
        &self,
        run: impl FnOnce(&mut S) -> io::Result<R> + Send + 'static,
    ) -> io::Result<R> {
        let (sender, receiver) = async_channel::bounded(1);
        self.sender
            .try_send(Box::new(move |state| {
                if !sender.is_closed() {
                    let _ = sender.try_send(run(state));
                }
            }))
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "worker busy; do not queue another refresh"))?;
        receiver.recv().await.map_err(|_| io::Error::other("worker unavailable"))?
    }
}

#[derive(Default)]
pub struct Ports {
    monitor: Monitor,
    recent: Option<(Instant, Arc<Snapshot>)>,
}

impl Ports {
    pub fn snapshot(&mut self) -> io::Result<Arc<Snapshot>> {
        if let Some((at, snapshot)) = &self.recent
            && at.elapsed() < FRESH
        {
            return Ok(snapshot.clone());
        }
        let snapshot =
            Arc::new(self.monitor.snapshot(Options { include_system: true, include_udp: true, containers: false }));
        self.recent = Some((Instant::now(), snapshot.clone()));
        Ok(snapshot)
    }
    pub fn idle(&mut self) {
        self.recent = None;
    }
}

pub struct Engines {
    cache: Cache,
    recent: Option<(Instant, Vec<EngineReport>)>,
    cursor: usize,
}

impl Default for Engines {
    fn default() -> Self {
        Self { cache: Cache::watching(), recent: None, cursor: 0 }
    }
}

impl Engines {
    pub fn snapshot(&mut self) -> io::Result<Vec<EngineReport>> {
        if let Some((at, reports)) = &self.recent
            && at.elapsed() < FRESH
        {
            return Ok(reports.clone());
        }
        let table = crate::procfs::Table::scan();
        let mut endpoints = engines::endpoints(&table, crate::procfs::current_uid());
        self.cache.retain(&endpoints);
        let count = endpoints.len().max(1);
        endpoints.rotate_left(self.cursor % count);
        self.cursor = (self.cursor + 1) % count;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut reports: Vec<_> =
            endpoints.iter().map(|endpoint| engines::list_until(endpoint, &mut self.cache, deadline)).collect();
        reports.sort_by(|a, b| a.endpoint.socket.cmp(&b.endpoint.socket));
        self.recent = Some((Instant::now(), reports.clone()));
        Ok(reports)
    }
    pub fn idle(&mut self) {
        self.recent = None;
        self.cache.release();
    }
    pub fn invalidate(&mut self, endpoint: &Endpoint) {
        self.recent = None;
        self.cache.invalidate(endpoint);
    }
}

struct ActivityState {
    last: Instant,
    active: usize,
    closing: bool,
}
pub struct Activity {
    state: Mutex<ActivityState>,
    wake: Condvar,
}
pub struct Active(Arc<Activity>);

impl Default for Activity {
    fn default() -> Self {
        Self {
            state: Mutex::new(ActivityState { last: Instant::now(), active: 0, closing: false }),
            wake: Condvar::new(),
        }
    }
}

impl Activity {
    pub fn enter(self: &Arc<Self>) -> io::Result<Active> {
        let mut state = self.state.lock().map_err(|_| io::Error::other("activity unavailable"))?;
        if state.closing || state.active >= 64 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "service busy or closing"));
        }
        state.active += 1;
        state.last = Instant::now();
        self.wake.notify_all();
        Ok(Active(self.clone()))
    }
    pub fn wait_idle(&self, idle: Duration) {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.active > 0 {
                state = self.wake.wait(state).unwrap();
                continue;
            }
            if state.last.elapsed() >= idle {
                state.closing = true;
                return;
            }
            let wait = idle.saturating_sub(state.last.elapsed());
            state = self.wake.wait_timeout(state, wait).unwrap().0;
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.active -= 1;
            state.last = Instant::now();
            self.0.wake.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_queue_refuses_overload_and_dropped_requests_do_not_execute() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll, Waker};
        let lane = Lane::new("queue-test", (), |()| {}).unwrap();
        let (entered, started) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let mut first = Box::pin(lane.call(move |()| {
            entered.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut context).is_pending());
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        let executions = Arc::new(AtomicUsize::new(0));
        let mut queued = Vec::new();
        let mut rejected = 0;
        for _ in 0..40 {
            let executions = executions.clone();
            let mut call = Box::pin(lane.call(move |()| {
                executions.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }));
            match call.as_mut().poll(&mut context) {
                Poll::Pending => queued.push(call),
                Poll::Ready(Err(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    rejected += 1;
                }
                Poll::Ready(Ok(())) => panic!("blocked worker ran a queued request"),
            }
        }
        assert_eq!(rejected, 8);
        drop(queued);
        release.send(()).unwrap();
        while first.as_mut().poll(&mut context).is_pending() {
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(first);
        drop(lane);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(executions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn in_flight_work_delays_idle_exit() {
        let activity = Arc::new(Activity::default());
        let active = activity.enter().unwrap();
        let waiter = activity.clone();
        let thread = std::thread::spawn(move || waiter.wait_idle(Duration::from_millis(25)));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!thread.is_finished());
        drop(active);
        thread.join().unwrap();
        assert!(activity.enter().is_err());
    }
}
