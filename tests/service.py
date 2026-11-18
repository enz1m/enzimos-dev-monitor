#!/usr/bin/env python3
import concurrent.futures
import json
import os
from pathlib import Path
import pty
import select
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

SERVICE, CLI = map(str, sys.argv[1:3])


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    for stream in (child.stdin, child.stdout, child.stderr):
        if stream:
            stream.close()


def main():
    with tempfile.TemporaryDirectory(prefix='devmon-service-') as root:
        root = Path(root)
        runtime = root / 'runtime'
        (runtime / 'podman').mkdir(parents=True)
        project = root / 'project with spaces'
        project.mkdir()
        (project / 'package.json').write_text('{"name":"shared-project"}')
        endpoint = runtime / 'podman/podman.sock'
        identifier = 'a' * 64
        state = {'delay': 0, 'lists': 0, 'closed': 0, 'events': 0}
        entered = threading.Event()
        control_entered = threading.Event()
        shutdown = threading.Event()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data = b''
                self.request.settimeout(10)
                while b'\r\n\r\n' not in data:
                    part = self.request.recv(4096)
                    if not part:
                        return
                    data += part
                method = data.split(b' ', 1)[0]
                path = data.split(b' ', 2)[1].decode()
                if path.startswith('/events?'):
                    state['events'] += 1
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
                    try:
                        while not shutdown.is_set():
                            if select.select([self.request], [], [], .1)[0] and not self.request.recv(1):
                                state['closed'] += 1
                                break
                    except OSError:
                        pass
                    return
                if method == b'POST':
                    control_entered.set()
                    time.sleep(1.2)
                    body = {}
                elif path.startswith('/containers/json?'):
                    state['lists'] += 1
                    entered.set()
                    time.sleep(state['delay'])
                    body = [{'Id': identifier, 'Names': ['/fixture'], 'State': 'running',
                             'Labels': {'com.docker.compose.project': 'shared-project',
                                        'com.docker.compose.project.working_dir': str(project)}}]
                else:
                    body = {'Id': identifier, 'Name': '/fixture', 'State': {'Status': 'running', 'Pid': 0},
                            'HostConfig': {'RestartPolicy': {'Name': 'no'}},
                            'Config': {'Labels': {'com.docker.compose.project.working_dir': str(project),
                                                 'com.docker.compose.project': 'shared-project'}}}
                raw = json.dumps(body).encode()
                try:
                    self.request.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n'.encode() + raw)
                except OSError:
                    pass

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        server = Server(str(endpoint), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        address = bus.stdout.readline().strip()
        environment = {**os.environ, 'DBUS_SESSION_BUS_ADDRESS': address, 'XDG_RUNTIME_DIR': str(runtime)}
        environment.pop('DOCKER_HOST', None)
        service = subprocess.Popen([SERVICE], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        listener = subprocess.Popen([sys.executable, '-c', 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); print(s.getsockname()[1],flush=True); time.sleep(90)'], cwd=project,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        listener_port = int(listener.stdout.readline())
        base = ['busctl', '--json=short', '--address=' + address, 'call', 'org.enzimos.DevMonitor1', '/org/enzimos/DevMonitor1']

        def call(method, signature=None, *arguments, interface='org.enzimos.DevMonitor1'):
            command = base + [interface, method]
            if signature:
                command += [signature, *map(str, arguments)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=8)
            assert result.returncode == 0, result.stderr
            if not result.stdout.strip():
                return None
            response = json.loads(result.stdout)
            return json.loads(response['data'][0]) if response['type'] == 's' else response

        try:
            for _ in range(40):
                result = subprocess.run(base + ['org.freedesktop.DBus.Properties', 'Get', 'ss', 'org.enzimos.DevMonitor1', 'Version'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    break
                time.sleep(.025)
            assert result.returncode == 0, result.stderr
            state['delay'] = 1.2
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                slow = pool.submit(call, 'Snapshot', 'bbb', 'false', 'false', 'true')
                assert entered.wait(3)
                before = time.monotonic()
                call('Get', 'ss', 'org.enzimos.DevMonitor1', 'Version', interface='org.freedesktop.DBus.Properties')
                fast = call('Snapshot', 'bbb', 'false', 'false', 'false')
                latency = time.monotonic() - before
                assert latency < .6, latency
                snapshot = slow.result(timeout=6)
            state['delay'] = 0
            assert snapshot['version'] == 2
            groups = [g for g in snapshot['projects'] if g['directory'] == str(project)]
            assert len(groups) == 1 and groups[0]['containers'] and groups[0]['processes'], groups
            port = next(p for p in snapshot['ports'] if p['port'] == listener_port and p['pid'] == listener.pid)
            start = port['start_time']
            shortcuts = call('Shortcuts', 'ut', listener.pid, start)
            assert shortcuts['terminal']['directory'] == str(project)
            assert shortcuts['folder_uri'].endswith('project%20with%20spaces')
            container_paths = call('ContainerShortcuts', 'sss', 'podman', str(endpoint), identifier)
            assert container_paths['directory'] == str(project)
            assert container_paths['terminal']['argv'] == ['/usr/bin/terminal-emulator', '--working-directory', container_paths['directory']]
            dry_run = subprocess.run([CLI, 'open', str(listener.pid), 'terminal', '--dry-run', '--start-time', str(start)], capture_output=True, text=True, timeout=5)
            assert dry_run.returncode == 0, dry_run.stderr
            assert json.loads(dry_run.stdout)['directory'] == str(project)
            time.sleep(.3)
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                replies = list(pool.map(lambda _: call('Snapshot', 'bbb', 'false', 'false', 'false'), range(20)))
            scan_ids = {r['scan_id'] for r in replies}
            assert len(scan_ids) <= 2, scan_ids
            lists = state['lists']
            deadline = time.monotonic() + 6.5
            while state['closed'] == 0 and time.monotonic() < deadline:
                call('Snapshot', 'bbb', 'false', 'false', 'false')
                time.sleep(.25)
            assert state['closed'] >= 1, state
            assert state['lists'] == lists, state
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                slow_control = pool.submit(call, 'Container', 'ssss', 'podman', str(endpoint), identifier, 'stop')
                assert control_entered.wait(3)
                before = time.monotonic()
                delivered = call('Signal', 'utbb', listener.pid, start, 'false', 'false')
                signal_latency = time.monotonic() - before
                assert listener.pid in delivered['delivered'] and signal_latency < .6
                slow_control.result(timeout=4)
            pid, terminal = pty.fork()
            if pid == 0:
                os.execvp('bash', ['bash', '--noprofile', '--norc', '-i'])
            pidfd = os.pidfd_open(pid)
            try:
                assert select.select([terminal], [], [], 3)[0]
                os.read(terminal, 4096)
                result = subprocess.run([CLI, 'stop', str(pid), '--force'], capture_output=True, text=True, timeout=5)
                assert result.returncode != 0, result.stdout
                assert not select.select([pidfd], [], [], 0)[0], 'interactive shell was killed'
            finally:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                os.close(pidfd)
                os.close(terminal)
                os.waitpid(pid, 0)
            print(json.dumps({'status': 'PASS', 'fast_calls_during_slow_engine_seconds': round(latency, 3),
                              'concurrent_clients': 20, 'distinct_scans': len(scan_ids), 'idle_event_connections_closed': state['closed'],
                              'project_grouping': True, 'shortcut_dry_run': True, 'interactive_shell_refused': True,
                              'signal_during_container_action_seconds': round(signal_latency, 3)}))
        finally:
            stop(listener)
            stop(service)
            stop(bus)
            shutdown.set()
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    main()
