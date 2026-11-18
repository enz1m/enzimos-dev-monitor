# D-Bus API — version 2

Session bus: `org.enzimos.DevMonitor1`; object: `/org/enzimos/DevMonitor1`;
interface: `org.enzimos.DevMonitor1`. Property `Version` (`u`) is **2**. The bus
name remains unchanged. Version 1 clients must adapt to nullable `autostart` and
the distinction between host socket ownership and published-container mappings.
Unknown fields must be ignored; unknown protocol versions must not enable controls.

| Method | Signature | Result |
| --- | --- | --- |
| `Snapshot(include_system, include_udp, containers)` | `bbb → s` | JSON snapshot |
| `Lookup(port)` | `q → s` | JSON `{ports, processes, warnings}`; includes UDP/system/container observations |
| `Inspect(pid, start_time)` | `ut → s` | JSON process detail, PSS, descriptors, I/O and children |
| `Signal(pid, start_time, tree, force)` | `utbb → s` | JSON `{signal, delivered, skipped}` |
| `Container(engine, socket, id, action)` | `ssss → ()` | Explicit `start`, `stop` or `restart` |
| `ContainerLogs(engine, socket, id, tail)` | `sssu → s` | Plain UTF-8 log text, not JSON |
| `Shortcuts(pid, start_time)` | `ut → s` | JSON process identity plus directory/launch descriptors |
| `ContainerShortcuts(engine, socket, id)` | `sss → s` | JSON launch descriptors for the current Compose host directory |
| `ProcessLogs(pid, start_time, tail)` | `utu → s` | JSON `{source: "journal", text, note}` |

`engine` and the canonical `socket` must match a currently discovered endpoint.
Container controls/queries require the full 64-character lowercase hexadecimal
id. Names and abbreviated ids are CLI conveniences only; they must resolve
uniquely before a control is issued. Every process action carries the start time
from the displayed row. Clients must not replace that identity with a fresh
start time simply to make a failed action succeed.

## Scheduling and errors

`include_system` adds other users' and system socket rows; it does not grant
access to their process details.

An open panel should request a snapshot every one to two seconds, with at most
one outstanding refresh per client. Requests within 250 ms share work. Use
`Snapshot(..., containers=false)` for a ports-only view independent of slow
engines. Multiple clients do not need their own polling service.

**Stop all requests on close**, including presence and version polls. Engine
subscriptions close after five seconds without engine requests; the service exits
after 60 seconds without calls/in-flight work. There is no subscription that
keeps the service alive on behalf of a closed panel and no autonomous scan timer.

- `AccessDenied`: another user's process or a protected target.
- `InvalidArgs`: invalid/unknown endpoint, id or action.
- `LimitsExceeded`: worker/service overload; discard/coalesce stale refreshes.
- `Failed`: unavailable/changed process, timeout, malformed/oversized response or
  other operational failure.

A signal can partially succeed; inspect `delivered` and every `skipped` reason.
Force stop is a **new explicit user action**, not an automatic timeout callback.
Never automatically retry a mutating call after a timeout/disconnection: its
outcome may be uncertain. A read can be retried after activation or backoff.

## Snapshot fields

Top level: `version`, `scan_id`, `taken_at_unix_ms`, `ports`, `processes`,
`engines`, `projects`, `warnings`, `cost`. `scan_id` identifies the shared port
scan within one service lifetime, not a durable id. `cost` records local scan
work; service engine I/O happens separately and is not a whole-machine CPU metric.

### Ports

Each row contains:

- `protocol`, `address`, `port`, `exposure` (`loopback`, `all`, `address`).
- `uid`, `own`, optional `pid`/`start_time` for a representative readable owner.
- `source`: `socket` or `published`.
- `published_by`: zero or more `{engine, socket, id, name}` mapping claims.
- `container`: the sole unambiguous association for a synthetic published row;
  null for a host socket or ambiguous association.
- `url`: an HTTP URL suggestion for TCP, or null. Specific loopback addresses
  and IPv6 are preserved. The service has not tested HTTP or reachability.

A matching published port **does not authorize replacing a host process's
identity with a container identity**. Give the user distinct process/container
controls. Bindings on different addresses or address families remain separate.
Stopped-container configuration does not claim a live port; paused containers
can still hold bindings. `include_udp` applies to both observation sources.

### Processes

`pid`, `start_time`, `ppid`, `name`, `label`, optional `tool`, `exe`, `cmdline`,
optional host-mappable `cwd`, `project`, `unit`, `started_unix_s`, `cpu_percent`,
`rss_bytes`, `threads`, `ports`, and `launcher`.

`project` is `{root, name, marker}`. `launcher` contains its PID/start-time,
label/command, parent name, same-user process count, tree RSS and CPU.
`tree_limited` marks reaching the 4096-entry traversal cap: aggregates may then
be partial. Launcher boundaries
exclude interactive shells and shared engine infrastructure but retain ordinary
noninteractive job wrappers. Use the launcher's identity for an explicit tree
stop, not an arbitrary parent PID.

CPU is a rate since the previous actual sample, as percent of one core; first,
changed-identity and unavailable rates are null. Tree RSS may double-count shared
pages. `Inspect` adds per-process PSS, descriptor count, read/write storage bytes
and up to 256 descendants. Unavailable metrics are null, not zero.

### Engines and containers

Each engine report has `endpoint: {engine, socket, rootless}`, `containers`,
`error`, `stale` and `truncated`. `stale` means an earlier observation is retained
following a failed list. `truncated` also covers an incomplete/malformed identity
inventory. Do not treat either as a full current inventory. A non-null `error`
may instead describe individual details still pending within the work budget.

Container fields include full identity/name/image, state/status/health,
created/started timestamps, restart policy, startup evidence, Compose metadata,
ports, mounts, PID and cgroup CPU/memory/limit/process counts. `detail_error` and
`stats_error` explain unavailable details/accounting. Mount records carry kind,
source, destination, writable and optional volume name. Compose metadata carries
project, service and host working directory.

Cgroup metrics are accepted only with an exact container-id association and
stable PID/start-time/cgroup filesystem identity. `memory_bytes` includes
accounted cache; `memory_limit_bytes=null` can mean unlimited or unavailable, so
also check `stats_error`. CPU resets after a restart rather than using the previous
process's counter. Human `status` text is a cached engine summary; derive live
uptime from `started_at`, not by repeatedly parsing that text.

`autostart` is **`true`, `false` or `null`**, representing known configured login
or boot startup, not a guarantee a future launch will succeed. The `startup`
object explains it:

| Field | Meaning |
| --- | --- |
| `on_engine_start` | Docker restart-on-engine-start policy; null for Podman's daemonless API and uncertain cases |
| `at_login`, `at_boot` | Configuration evidence for those separate triggers; nullable |
| `unit`, `unit_file_state`, `user_unit` | Verified owning service and current enablement observation |
| `linger` | User manager lingering, where relevant and readable |
| `verification_age_ms` | Age of the latest enablement probe, including unsuccessful attempts |
| `reason` | Scope/limitations of the inference |

An observed Podman label is also provided separately as `systemd_unit`; it is
not itself proof of service ownership/enablement. Unknown external restart
orchestration stays unknown. Runtime-only/indirect/static enablement is not
silently treated as persistent automatic startup. Probe state is demand-cached
for up to 30 seconds.

### Project groups

`projects` contains `{key, name, directory, processes, launchers, containers}`.
Process and launcher references are `{pid, start_time}`; container references
include the engine socket. Identical absolute host project directories join
servers with Compose containers. Otherwise groups remain separate. Launcher
references are deduplicated so clients do not sum the same tree repeatedly.
There is no misleading combined RSS total across shared processes/containers.

## Explicit shortcuts and logs

A shortcut result contains `directory`, `folder_uri`, and `folder`/`terminal`
launch descriptors. Each descriptor is `{argv: [...], directory: ...}`. Process
shortcuts also include the validated PID/start-time. Re-query when the user clicks;
then use a process API with an argument vector and cwd, **never shell interpolation**.
The native defaults are `/usr/bin/xdg-open file://...` and
`/usr/bin/terminal-emulator --working-directory DIRECTORY`, with cwd also set to
that directory. Package this with the Terminal revision implementing that flag;
older Terminal versions prefer HOME and can ignore inherited cwd.

The service returns descriptors; it does not launch desktop applications.
`devmon open` and the container open commands explicitly execute them. `--dry-run`
is accepted only for opening, never silently ignored on a stop operation.
Missing/unmapped project directories fail instead of opening a different host path.

Container logs clamp `tail` to 1–5000 lines and return at most the final 256 KiB,
at a UTF-8 character boundary. Their complete HTTP input is bounded to 8 MiB;
exceeding it is an error, not a successful prefix. Stdout/stderr multiplex framing
is validated. Process logs are accessible journal records for the user/PID/current
boot since process start, limited to 256 KiB. They do not capture an application's
PTY output or read arbitrary descriptor targets.

Commands, paths and logs can contain secrets. Native shell access or narrowly
separated read/control broker permissions are required for plugins. No implicit
MCP/agent access, telemetry, background log following or automatic HTTP probe is
part of this interface.
