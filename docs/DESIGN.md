# Design

## Demand-driven lifecycle

The service performs work only for a call. It has separate bounded workers for
port scans, container observations, expensive queries, container controls and
process signals. Each lane accepts at most 32 queued jobs; at most 64 calls are
in flight across the service. Overload is an explicit `LimitsExceeded` response.
A cancelled queued read is discarded before execution. A control that has started
may complete even if its caller disconnects; disconnect is not rollback.

Port requests share one full observation for 250 ms, then filter the answer for
system/UDP options. Engine requests share their results for the same interval.
There is no timer that refreshes either cache. Slow container operations cannot
hold the port worker or D-Bus executor; process signals have their own lane.

A worker has one inactivity wake after five seconds to discard live engine
subscriptions, then blocks without periodic wakes. Closing the last panel means
**stop calling**, including presence/version polls. The main process exits after
60 seconds with no call or in-flight work. The idle transition refuses new work
before disconnecting. Clients may retry a read after an activation race, but must
never automatically replay an uncertain mutation.

## Port and process observations

- `sock_diag` requests only TCP listeners and optional unconnected UDP sockets.
  Truncation, interrupted dumps and errors fall back to procfs with warnings;
  failed observations are not silently reported as a complete empty inventory.
- Socket ownership is a best-effort mapping from inode to a representative
  same-user descriptor holder. Previous owners are rechecked first; unresolved
  inodes are retried after 30 seconds. Shared/inherited sockets may have multiple
  holders that are not exhaustively reported.
- CPU/RSS come from one process-table scan. Timestamps are taken before engine
  I/O. Repeated owners of one launcher reuse its tree calculation within a scan.
  CPU starts unknown and is reset across PID/start-time changes. RSS is not PSS.
- Launcher discovery stays within a user/process group and stops at interactive
  shells, terminals, editors, service managers and shared engine infrastructure.
  Noninteractive `sh -c` wrappers remain part of a stoppable job.
- Host directory actions require matching device/inode identity between the
  process's cwd and the host path. A path from another mount namespace is not
  assumed to be a usable host directory merely because the strings match.
- Project lookup is cached for 30 seconds. Manifest reads reject symlinks and
  non-regular files, use nonblocking open, and read at most 256 KiB plus a size
  sentinel. Kernel/filesystem failures remain best effort; no filesystem parser
  can guarantee recovery from a kernel stuck in uninterruptible I/O.

## Container transport and caching

Only Unix-socket Docker-compatible APIs are supported. Socket aliases are
canonicalized and deduplicated by device/inode. Replacing a socket at the same
path discards its old inventory and cancels the previous event reader. Docker discovery requires an
observed daemon, but cannot exclude every stop/connect race or custom activation
configuration. Podman socket activation is intentional only on an explicit
container request. No TCP/TLS Docker host credentials are handled.

HTTP connections, request writes and finite response reads share an absolute
deadline. `httparse` validates headers; framing rejects conflicting lengths,
truncation and bad chunk delimiters. Header/trailer lines and total bodies are
bounded. Oversized logs fail instead of presenting an early prefix as the tail.
Controls have a 15-second request deadline, with a ten-second engine stop grace.
No control is automatically retried.

An event subscription owns its socket and reader thread. Drop shuts down the
socket and joins the reader, including error and endpoint-removal paths. Headers
and body are framed independently of read boundaries. Events include lifecycle,
update and health changes, excluding noisy exec events. Subscriptions request
recent events to bridge initial setup; a generation captured before listing
preserves changes during the list. A new subscription invalidates inspect data.

Failed lists back off for three seconds and close their subscription. Failed
subscriptions also back off; while requested, an unobserved engine uses a short
best-effort list cache. Healthy subscriptions avoid repeated list calls, with a
30-second reconciliation bound **only when a caller asks**. Inspect data is
invalidated by generation/state changes or age. Endpoint identities scope all
caches and CPU samples; no cache key is container id alone across daemons.

Engine work shares a two-second observation budget. Engines and pending details
rotate to avoid persistent starvation. At most 32 inspect requests are attempted
per pass. Partial details are visible and can fill in on later requested passes.
Limits are eight discovered endpoints, 256 containers per endpoint, a 2 MiB list,
256 KiB inspect document and 16 KiB retained description per container. Oversized
or malformed inventories are marked incomplete; CLI name/prefix controls refuse
incomplete inventories. The installed unit also has a memory limit. This is a
bounded developer tool, not a cluster-wide inventory service.

## Attribution and startup

Bindings are joined using protocol, address family, address and port. Paused
containers retain bindings; stopped-container saved mappings do not own a live
host port. Engine mappings on a socket row are candidates in `published_by`, not
process ownership. A synthetic published row has a singular `container` only
when its association is unambiguous. UDP filtering applies to both sources.
Suggested URLs preserve specific loopback addresses and IPv6 syntax. They are
only suggestions: no HTTP request is made automatically.

Container accounting requires an exact container-id cgroup component. PID/start
time, cgroup path and device/inode are rechecked around counter reads; unrelated
or inaccessible cgroups produce unknown values. A restarted container gets a new
CPU baseline. The cgroup memory figure includes accounted file cache and is not
promised to equal Docker's working-set display.

Startup is configuration evidence, not proof of a future successful boot:

- Docker restart-on-engine-start policy is distinct from service enablement.
- The daemon's observed systemd service can be checked for persistent enablement.
  Socket-activated Docker is resolved only through a matching active
  `docker.socket` stream path and one service trigger.
- A Podman service label must match the identity-checked container cgroup before
  its enablement is used. Unproven/stopped-unit associations remain unknown.
- User-service login startup and boot startup differ: boot also needs lingering.
- Runtime-only, indirect, static, missing/failed probes and unverified associations
  do not become `true`. Probe results are cached for 30 seconds and expose their
  age. A null state is not a successful verification.
- Podman's API activation is not an engine-start restart trigger. Unobserved
  external schedulers, Quadlet/restart-service configurations and custom boot
  orchestration may remain unknown rather than guessed.

## Actions and privacy

Process signals use pidfds after start-time validation and repeat the protected
process checks before sending. Tree traversal is bounded and prunes protected
branches. These checks prevent common mistakes, not deliberate evasion by a
same-user process. Partial delivery is reported; the CLI fails on incomplete
signal delivery. Container selectors must be unique; controls use a full id and
an explicit discovered endpoint.

Project groups join processes and Compose containers only on an identical
absolute host directory. Unmapped groups retain separate identities. Folder and
terminal actions return fixed argument vectors and a cwd; neither labels nor
paths are evaluated as shell code. Native clients execute them only after a click.
The CLI offers the same explicit actions, with dry-run support only for opening.

Process logs query the accessible journal for the user's PID and current boot,
bounded by process start time. They do not read or consume terminal output. Logs,
PSS, directory resolution and any future HTTP/disk-usage probe stay on demand.
There is currently no automatic HTTP probing or MCP exposure.

A session bus is not a sandbox permission boundary. The service has its user's
process and engine access. A shell plugin needs separate read/control broker
permissions, not blanket access to the interface. Command lines, project paths,
mounts and logs may contain secrets: do not export them as telemetry or grant
agents access implicitly. Human CLI output removes terminal control characters;
JSON retains data with normal JSON escaping.
