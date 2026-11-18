# enzimOS developer monitor

An on-demand view of listening ports, development servers and Docker/Podman
containers. Framework-neutral labels come from commands and nearby project
manifests, not a list of supported web frameworks.

## Build

Requires Rust 1.95 or newer and Linux. The service uses the session D-Bus;
container operations use an accessible Docker-compatible Unix socket.

```sh
cargo build --release --locked
```

This builds the `devmon` CLI and `enzimos-dev-monitor` service. Building does not
install binaries, enable services or start a container engine.

## Commands

```sh
devmon                            # ports, processes and containers
devmon --json --all --udp
devmon port 3000
devmon projects                   # structured groups shared by servers and Compose
devmon inspect PID
devmon shortcuts PID
devmon open PID folder
devmon open PID terminal --dry-run
devmon logs PID                   # accessible journal entries, not captured PTY output
devmon stop PID --start-time TICKS --tree
devmon stop PID --start-time TICKS --tree --force

devmon --engine /run/docker.sock container logs FULL_ID
devmon --engine /run/docker.sock container stop FULL_ID
devmon --engine /run/docker.sock container start FULL_ID
devmon --engine /run/docker.sock container restart FULL_ID
devmon --engine /run/docker.sock container shortcuts FULL_ID
devmon --engine /run/docker.sock container open-folder FULL_ID
devmon --engine /run/docker.sock container open-terminal FULL_ID --dry-run
```

The CLI takes two snapshots 500 ms apart to report CPU rates; that intentional
sampling delay is not the CPU cost of scanning.

Container names and prefixes of at least 12 hexadecimal characters must resolve
uniquely across the selected engines. A full id is interpreted as an id, not another
container's similar-looking name. Controls use full ids and engine socket
identity. Process controls use PID/start-time checks and pidfds; session shells,
terminals, editors and shared container infrastructure are refused. Protected
branches are excluded from tree actions. These are cooperative safety guards,
not isolation from a hostile same-user process.

Opening folders/terminals is explicit and passes an argument vector plus a
working directory, never a shell command. A process path must name the same
filesystem object in the host namespace. Compose shortcuts use its declared host
project directory. The shell can consume the same launch descriptors instead of
asking the service to launch UI applications. The terminal descriptor uses `/usr/bin/terminal-emulator --working-directory`
and requires a terminal launcher that supports that argument.

## Service and cost

`org.enzimos.DevMonitor1` is session-bus activated. Its API **Version is 2**;
`autostart` may be unknown (`null`). See [API](docs/API.md).

- No autonomous snapshots and no HTTP probes. **Do not poll with a closed panel.**
- Requests within 250 ms share work. Bounded queues reject overload rather than
  accumulating UI timer ticks. Slow engine/log work does not block port requests,
  process signals or D-Bus dispatch.
- Engine event subscriptions are cancelled after five seconds without engine
  requests, including when only port requests continue.
- The service exits after 60 seconds without calls or in-flight work. It retains
  a small resident process during that grace period; it is not immediately zero
  memory on panel close.
- PSS, logs and shortcut resolution are explicit requests. Container counters
  come from identity-checked cgroups, not per-container stats streams.

## Interpretation

- Wildcard binding means `all`, not proven firewall/network reachability.
- `source=socket` rows retain process ownership. `published_by` contains engine
  mapping claims, not proof that the host process belongs to that container.
- CPU is a percentage of one core. First/new-process samples are unknown. Tree
  RSS can double-count shared pages; cgroup memory includes accounted cache.
- Restart policy, configured login/boot startup and user lingering are separate.
  Unknown stays unknown: a Podman unit label alone is not an enabled-service
  check, and starting Podman's API does not start its containers.
- Podman and configured Unix sockets may activate a service when explicitly
  requested. Docker daemon discovery avoids the usual stopped-daemon case but is
  best effort, not a race-free guarantee against socket activation.
- Partial, stale and bounded results are explicit. An empty observation is not
  proof that a port is free. Limits and privacy boundaries are in [design](docs/DESIGN.md).

## Development

```sh
cargo test --locked
cargo clippy --all-targets --locked
cargo fmt --check
```

Integration tests require Python 3, D-Bus tools, Bash, `mkfifo` and bubblewrap.
They run on private buses and in private namespaces with captured launch targets;
they do not open desktop applications or control the user's containers.

`packaging/` contains the D-Bus activation file and systemd user unit. The CLI is
installed at `/usr/bin/devmon` and the service at
`/usr/lib/enzimos/enzimos-dev-monitor`. The service is activated on demand;
no login timer or permanently running monitor is required.

See [API](docs/API.md) for the client contract and [design](docs/DESIGN.md) for
process ownership, container identity, privacy and resource bounds. Shell controls
and consent belong to the integrating desktop.

## License

MIT; see [LICENSE](LICENSE).
