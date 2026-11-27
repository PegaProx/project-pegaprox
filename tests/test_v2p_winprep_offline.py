"""The PegaProx side of the offline Windows preparation (core/v2p_winprep.py) and the download
of virtio-win.iso (core/v2p_packages.py).

MK Nov 2026 - the download runs on the node, over HTTPS with the certificate checked, into a
temporary name that is moved into place once complete, its sha256 for the task log. It runs here
in a sandbox: a PATH with a stand-in curl, the ISO folder in a temp dir.
"""
import json
import os
import shutil
import signal
import subprocess
import time
import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_packages as pk, v2p_winprep as wp


# --------------------------------------------------------------------------- the download, in a sandbox

_CURL = '''#!/bin/sh
# a curl that writes $SIZE bytes to -o, or fails like an unknown host
out=""; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a";; esac
  case "$a" in --insecure|-k) echo "INSECURE" >> "$LOG";; esac
  prev="$a"
done
echo "$*" >> "$LOG"
if [ "$MODE" = fail ]; then echo "curl: (6) Could not resolve host" >&2; exit 6; fi
head -c "$SIZE" /dev/zero > "$out"
if [ "$MODE" = hang ]; then sleep 60; fi
'''


class Box:
    def __init__(self, tmp, mode='ok', size=150 * 1024 * 1024):
        self.bin, self.iso = tmp / 'bin', tmp / 'iso'
        self.bin.mkdir()
        self.log = tmp / 'curl.log'
        for tool in ('mkdir', 'mktemp', 'stat', 'sha256sum', 'cut', 'chmod', 'mv', 'rm', 'tail', 'tr', 'head', 'cat',
                     'find', 'sleep'):
            os.symlink(shutil.which(tool), self.bin / tool)
        (self.bin / 'curl').write_text(_CURL)
        (self.bin / 'curl').chmod(0o755)
        self.env = {'PATH': str(self.bin), 'MODE': mode, 'SIZE': str(size), 'LOG': str(self.log)}

    def script(self, monkeypatch):
        d = dict(pk.DOWNLOADS['virtio-win.iso'], dir=str(self.iso))
        monkeypatch.setitem(pk.DOWNLOADS, 'virtio-win.iso', d)
        monkeypatch.setitem(pk.PACKAGE_CHECKS, 'virtio-win.iso', (f'test -f {self.iso}/virtio-win.iso',))
        return pk.download_script('virtio-win.iso')

    def run(self, monkeypatch):
        p = subprocess.run(['/bin/bash', '-c', self.script(monkeypatch)], env=self.env,
                           capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout


def test_the_iso_is_downloaded_over_https_and_moved_into_place_with_its_sha256(tmp_path, monkeypatch):
    box = Box(tmp_path, size=101 * 1024 * 1024 + 7)
    rc, out = box.run(monkeypatch)
    got = pk.parse_download(out)
    assert got and got[1] == 101 * 1024 * 1024 + 7 and got[2] == f'{box.iso}/virtio-win.iso'
    assert len(got[0]) == 64 and out.strip().endswith('INSTALLED virtio-win.iso')
    assert sorted(os.listdir(box.iso)) == ['virtio-win.iso']
    log = box.log.read_text()
    assert 'INSECURE' not in log and '--proto =https' in log and '--proto-redir =https' in log
    assert pk.VIRTIO_ISO_URL in log
    # the second time nothing is fetched
    rc, out = box.run(monkeypatch)
    assert out.strip() == 'PRESENT' and log == box.log.read_text()


@pytest.mark.parametrize('mode,size', [('fail', 0), ('ok', 1000)])
def test_a_failed_or_short_download_leaves_nothing_behind(tmp_path, monkeypatch, mode, size):
    box = Box(tmp_path, mode=mode, size=size)
    rc, out = box.run(monkeypatch)
    assert pk.parse_download(out) is None and out.strip().endswith('FAILED virtio-win.iso')
    assert os.listdir(box.iso) == []
    assert pk.parse_ensure(rc, out, ['virtio-win.iso'])[0] == 'FAILED'


@pytest.mark.parametrize('sig', [signal.SIGHUP, signal.SIGTERM])
def test_a_download_cut_off_with_its_session_leaves_nothing_behind(tmp_path, monkeypatch, sig):
    # the SSH session drops, or the node command is ended: the whole process group gets the signal
    box = Box(tmp_path, mode='hang', size=4096)
    box.iso.mkdir()
    # a shell started under nohup (a suite run in the background) has SIGHUP ignored, and a
    # signal ignored when bash starts can be neither trapped nor reset: the node's shell under
    # sshd has it at its default, so the script gets it the same way here
    p = subprocess.Popen(['/bin/bash', '-c', box.script(monkeypatch)], env=box.env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True,
                         preexec_fn=lambda: signal.signal(sig, signal.SIG_DFL))
    try:
        deadline = time.time() + 20
        while time.time() < deadline and not [e for e in os.listdir(box.iso) if not e.endswith('.err')
                                                and os.path.getsize(box.iso / e) == 4096]:
            time.sleep(0.05)
        assert os.listdir(box.iso), 'the download never started'
        os.killpg(p.pid, sig)
        p.wait(timeout=20)
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=10)
    assert os.listdir(box.iso) == []


def test_what_a_killed_download_left_is_removed_by_the_next_one_but_not_a_running_one(tmp_path, monkeypatch):
    # SIGKILL or a reboot of the node runs no trap: the next download takes the old temporary files
    box = Box(tmp_path, size=101 * 1024 * 1024)
    box.iso.mkdir()
    old, oerr, young = (box.iso / '.virtio-win.iso.AbCdEfGhIj', box.iso / '.virtio-win.iso.AbCdEfGhIj.err',
                        box.iso / '.virtio-win.iso.KlMnOpQrSt')
    for f in (old, oerr, young):
        f.write_bytes(b'x' * 10)
    gone = time.time() - (pk.DOWNLOAD_STALE_MINUTES + 5) * 60
    os.utime(old, (gone, gone))
    os.utime(oerr, (gone, gone))
    (box.iso / 'other.iso').write_bytes(b'y')
    os.utime(box.iso / 'other.iso', (gone, gone))
    rc, out = box.run(monkeypatch)
    assert out.strip().endswith('INSTALLED virtio-win.iso')
    assert sorted(os.listdir(box.iso)) == ['.virtio-win.iso.KlMnOpQrSt', 'other.iso', 'virtio-win.iso']


def test_the_transfer_ends_before_the_node_command_is_given_up(node, monkeypatch):
    # curl and wget stop on their own before the exec timeout of ensure_iso, so their own failure
    # path cleans up; a running download is never old enough for the next run to take it
    s = pk.download_script('virtio-win.iso')
    assert f'--max-time {pk.DOWNLOAD_MAX_SECONDS}' in s and f'timeout {pk.DOWNLOAD_MAX_SECONDS} wget' in s
    assert pk.DOWNLOAD_STALE_MINUTES * 60 > pk.DOWNLOAD_MAX_SECONDS
    seen = []
    real = v2p._pve_node_exec
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda m, n, cmd, timeout=60, **kw: (
        seen.append(timeout) if 'fedorapeople' in cmd else None) or real(m, n, cmd, timeout=timeout, **kw))
    wp.ensure_iso(None, _task())
    assert seen and min(seen) >= pk.DOWNLOAD_MAX_SECONDS + 120


def test_without_installs_the_iso_is_only_asked_for():
    s = pk.download_script('virtio-win.iso', install=False)
    assert 'curl' not in s and 'MISSING virtio-win.iso' in s
    assert pk.ensure_script('virtio_iso') == pk.download_script('virtio-win.iso')


# --------------------------------------------------------------------------- ensure_iso

def _task(**cfg):
    t = v2p.V2PMigrationTask('t1', 'vw1', 'vm-1', 'c', 'pve1', 'local-lvm', config=dict({'esxi_password': 'pw'}, **cfg))
    t.proxmox_vmid = 120
    return t


@pytest.fixture
def node(monkeypatch):
    st = types.SimpleNamespace(have=False, dl='ok', cmds=[])

    def exec_(mgr, n, cmd, timeout=60, **kw):
        st.cmds.append(cmd)
        if cmd.startswith('test -f ') and 'fedorapeople' not in cmd:
            return (0 if st.have else 1), '', ''
        if 'fedorapeople' in cmd:
            if st.dl == 'ok':
                st.have = True
                return 0, f'V2P_DL OK {"c" * 64} 800000000 /var/lib/vz/template/iso/virtio-win.iso\nINSTALLED virtio-win.iso\n', ''
            return 0, 'the download failed (exit code 6, 0 bytes)\nFAILED virtio-win.iso\n', ''
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', exec_)
    return st


def test_an_iso_on_the_node_is_used_as_it_is(node):
    node.have = True
    t = _task()
    assert wp.ensure_iso(None, t) == '/var/lib/vz/template/iso/virtio-win.iso'
    assert not [c for c in node.cmds if 'fedorapeople' in c]


def test_a_missing_iso_is_downloaded_once_and_logged(node):
    t = _task()
    assert wp.ensure_iso(None, t) == '/var/lib/vz/template/iso/virtio-win.iso'
    assert len([c for c in node.cmds if 'fedorapeople' in c]) == 1
    assert any('sha256 ' + 'c' * 64 in line for line in t.log_lines)


@pytest.mark.parametrize('cfg,dl,word', [
    ({}, 'fail', 'could not be downloaded'),
    ({'allow_package_install': False}, 'ok', 'may not download it'),
    ({'virtio_iso_path': '/mnt/isos/virtio.iso'}, 'ok', 'is not on node'),
])
def test_without_an_iso_the_guest_keeps_the_source_controller_and_the_run_says_why(node, cfg, dl, word):
    node.dl = dl
    t = _task(**cfg)
    assert wp.ensure_iso(None, t) is None
    assert any(word in w and 'source' in w for w in t.warnings), t.warnings
    if cfg:
        assert not [c for c in node.cmds if 'fedorapeople' in c]


# --------------------------------------------------------------------------- the first boot report

class _Pve:
    host, api_port = 'pve1.lab', 8006

    def __init__(self, files):
        self.files = files

    def _api_post(self, url, data=None, **kw):
        if url.endswith('/agent/exec'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': {'pid': 1}})
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': {}})

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/agent/exec-status'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': {'exited': 1, 'exitcode': 0, 'out-data': 'D:\r\n'}})
        c = self.files.get((params or {}).get('file'))
        return types.SimpleNamespace(status_code=200 if c is not None else 500, json=lambda: {'data': {'content': c}})


def test_the_first_boot_report_of_another_run_is_not_taken(monkeypatch):
    import time
    monkeypatch.setattr(time, 'sleep', lambda s: None)
    clock = iter(range(0, 10 ** 6, 5))
    monkeypatch.setattr(time, 'monotonic', lambda: next(clock))
    t = _task()
    pve = _Pve({'D:\\ProgramData\\KVMMigration\\firstboot.json': json.dumps({'run': 'old', 'state': 'applied'})})
    assert wp.read_first_boot(pve, t, 60) is None
    assert wp.work_path(pve, t) == 'D:\\ProgramData\\KVMMigration'


def test_a_first_boot_that_could_not_put_an_address_back_is_a_warning():
    t = _task()
    t._winprep = {'state': 'staged', 'work': 'C:\\ProgramData\\KVMMigration'}
    fb = {'run': 't1', 'state': 'partial', 'tools': 'disabled', 'devices': 'kept',
          'adapters': [{'n': 1, 'ip': '10.0.0.5', 'applied': False, 'why': 'netsh exit code 1'},
                       {'n': 2, 'ip': '10.0.1.5', 'index': '9', 'by': 'order', 'applied': True}]}
    wp.log_first_boot(_Pve({}), t, fb)
    assert any('10.0.0.5 (netsh exit code 1)' in w and 'tries again at the next boot' in w for w in t.warnings)
    assert any('ESXi guest tools could not be uninstalled' in w for w in t.warnings)
    assert any('10.0.1.5 is on interface 9 (matched by order)' in line for line in t.log_lines)


def test_the_node_gets_each_source_mac_with_the_mac_of_its_nic_on_proxmox(monkeypatch):
    t = _task()
    t._source_nics = [{'mac_address': '00:50:56:aa:00:01'}, {'mac_address': '00:50:56:aa:00:02'},
                      {'mac_address': '00:50:56:aa:00:03'}]
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda *a, **k: (
        0, 'net0: virtio=BC:24:11:00:00:01,bridge=vmbr0\nnet2: virtio=BC:24:11:00:00:03,bridge=vmbr1,tag=5\n', ''))
    # net1 was skipped in the nic_map: no pair for it
    assert wp.nic_pairs(None, t) == '005056aa0001=bc2411000001,005056aa0003=bc2411000003'


def test_the_tools_may_go_only_without_a_device_on_their_drivers():
    t = _task()
    t._attach_scsihw, t._net_model = 'virtio-scsi-single', 'virtio'
    assert wp.uninstall_tools_ok(t) is True
    t._attach_scsihw = 'pvscsi'
    assert wp.uninstall_tools_ok(t) is False
    t._attach_scsihw, t._net_model = 'virtio-scsi-single', 'vmxnet3'
    assert wp.uninstall_tools_ok(t) is False
