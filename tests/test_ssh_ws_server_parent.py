"""The SSH console server (the script vms.py writes and starts in a session of its own)
goes when the PegaProx that started it is gone, also after a kill -9 of that one, which
left it holding its port for the next start.

MK Oct 2026
"""
import os
import re
import subprocess
import sys
import time


def _watch_source():
    src = open(os.path.join(os.path.dirname(__file__), '..', 'pegaprox', 'api', 'vms.py'), encoding='utf-8').read()
    script = src[src.index("server_script = '''"):]
    return re.search(r"(def _watch_parent\(\):.*?)\n\n\nif __name__ == '__main__':", script, re.S).group(1)


def test_the_console_server_exits_once_its_parent_is_gone(tmp_path):
    child = 'import os, time\n' + _watch_source() + '\n_watch_parent()\ntime.sleep(60)\n'
    # the parent starts it in a session of its own and is gone at once, as after a kill -9
    parent = ('import subprocess, sys\n'
              f'p = subprocess.Popen([sys.executable, "-c", {child!r}], start_new_session=True,\n'
              '                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n'
              'print(p.pid, flush=True)\n')
    out = subprocess.run([sys.executable, '-c', parent], capture_output=True, text=True, timeout=30)
    pid = int(out.stdout.strip())
    try:
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.5)
        else:
            raise AssertionError('the console server outlived its parent')
    finally:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
