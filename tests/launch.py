#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote


def inside(root, cli):
    project = root / 'project $(touch INJECTED)'
    project.mkdir()
    (project / 'package.json').write_text('{"name":"safe-project"}')
    child = subprocess.Popen([sys.executable, '-c', 'import time,ctypes; ctypes.CDLL(None).prctl(15,b"rootlesskit",0,0,0); time.sleep(30)'], cwd=project)
    try:
        time.sleep(.05)
        start = Path(f'/proc/{child.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
        for kind, executable in [('folder', 'xdg-open'), ('terminal', 'terminal-emulator')]:
            run = subprocess.run([cli, 'open', str(child.pid), kind, '--start-time', start], capture_output=True, text=True, timeout=3)
            assert run.returncode == 0, run.stderr
            result = project / ('capture-' + executable + '.json')
            deadline = time.monotonic() + 3
            while not result.exists():
                assert time.monotonic() < deadline, executable
                time.sleep(.01)
            record = json.loads(result.read_text())
            assert record['cwd'] == str(project), record
            if kind == 'folder':
                assert unquote(record['argv'][1].removeprefix('file://')) == str(project), record
            else:
                assert record['argv'][1:] == ['--working-directory', str(project)], record
        refused = subprocess.run([cli, 'stop', str(child.pid), '--force', '--dry-run'], capture_output=True, text=True, timeout=3)
        assert refused.returncode != 0 and child.poll() is None
        protected = subprocess.run([cli, 'stop', str(child.pid), '--force'], capture_output=True, text=True, timeout=3)
        assert protected.returncode != 0 and child.poll() is None
        assert not (project / 'INJECTED').exists()
        print(json.dumps({'status': 'PASS', 'actual_cli_spawns': ['folder', 'terminal'], 'cwd_preserved': True,
                          'shell_metacharacters_not_executed': True, 'dry_run_cannot_kill': True, 'engine_process_refused': True,
                          'scope': 'private mount/PID/user/network namespaces, capture executables, not GUI acceptance'}))
    finally:
        child.terminate()
        child.wait(timeout=3)


def main():
    if sys.argv[1] == '--inside':
        inside(Path(sys.argv[2]), sys.argv[3])
        return
    cli = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='devmon-launch-') as directory:
        root = Path(directory)
        stub = root / 'capture'
        stub.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\nPath("capture-"+Path(sys.argv[0]).name+".json").write_text(json.dumps({"argv":sys.argv,"cwd":os.getcwd()}))\n')
        stub.chmod(0o700)
        result = subprocess.run(['bwrap', '--ro-bind', '/', '/', '--bind', str(root), str(root), '--tmpfs', '/usr/bin',
            '--ro-bind', str(Path(sys.executable).resolve()), '/usr/bin/python3', '--ro-bind', str(stub), '/usr/bin/xdg-open',
            '--ro-bind', str(stub), '/usr/bin/terminal-emulator', '--unshare-user', '--uid', '0', '--gid', '0',
            '--unshare-pid', '--unshare-net', '--proc', '/proc', '--dev', '/dev', '--die-with-parent',
            '/usr/bin/python3', str(Path(__file__).resolve()), '--inside', str(root), cli], capture_output=True, text=True, timeout=12)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout, end='')


if __name__ == '__main__':
    main()
