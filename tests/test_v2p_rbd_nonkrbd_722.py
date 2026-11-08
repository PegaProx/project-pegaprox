# #722 (mluenzer) — ESXi->Proxmox V2P into a NON-krbd Ceph RBD storage.
#
# A krbd=0 (librbd/qemu) RBD storage makes `pvesm path` return a librbd URI
# (rbd:<pool>/<image>:conf=...:id=...:keyring=...) instead of a /dev path, so the
# old alloc success-gate (`dev_path.startswith('/')`) rejected the valid URI and the
# migration died with "volume path could not be resolved". These cover the parsing,
# the `rbd map` command build (incl. shell-injection quoting) and the map-resolution.
#
# NOTE: the on-node `rbd map` / dd behaviour still needs a real-Ceph E2E — these
# tests pin the deterministic logic only (parsing + command string + resolution).

import json
import pegaprox.core.v2p as v2p


# --------------------------------------------------------------------------- #
# _parse_rbd_uri
# --------------------------------------------------------------------------- #

def test_parse_bare_uri():
    pool, image, opts = v2p._parse_rbd_uri('rbd:cephpool/vm-100-disk-0')
    assert (pool, image) == ('cephpool', 'vm-100-disk-0')
    assert opts == {}


def test_parse_uri_with_conf_id_keyring():
    uri = ('rbd:cephpool/vm-100-disk-0'
           ':conf=/etc/pve/priv/ceph/cephpool.conf'
           ':id=admin'
           ':keyring=/etc/pve/priv/ceph/cephpool.keyring')
    pool, image, opts = v2p._parse_rbd_uri(uri)
    assert (pool, image) == ('cephpool', 'vm-100-disk-0')
    assert opts['conf'] == '/etc/pve/priv/ceph/cephpool.conf'
    assert opts['id'] == 'admin'
    assert opts['keyring'] == '/etc/pve/priv/ceph/cephpool.keyring'


def test_parse_uri_with_monhost():
    uri = 'rbd:extpool/vm-5-disk-1:mon_host=10.0.0.1;10.0.0.2:id=admin:keyring=/x/y.keyring'
    pool, image, opts = v2p._parse_rbd_uri(uri)
    assert (pool, image) == ('extpool', 'vm-5-disk-1')
    assert opts['mon_host'] == '10.0.0.1;10.0.0.2'
    assert opts['id'] == 'admin'


def test_parse_uri_image_name_with_prefix():
    # PVE can prefix the image (e.g. base-/vm-); the split must keep the whole image
    pool, image, opts = v2p._parse_rbd_uri('rbd:pool2/base-9000-disk-0')
    assert (pool, image) == ('pool2', 'base-9000-disk-0')


def test_parse_rejects_non_pool_image():
    assert v2p._parse_rbd_uri('rbd:garbage') == (None, None, {})
    assert v2p._parse_rbd_uri('') == (None, None, {})
    # a real /dev path must NOT be mistaken for an rbd URI
    p, i, o = v2p._parse_rbd_uri('/dev/rbd-pve/fsid/cephpool/vm-1-disk-0')
    assert (p, i) == (None, None)


# --------------------------------------------------------------------------- #
# _rbd_map_command
# --------------------------------------------------------------------------- #

def test_map_command_bare():
    cmd = v2p._rbd_map_command('cephpool', 'vm-100-disk-0', {})
    assert cmd == 'rbd map -p cephpool vm-100-disk-0'


def test_map_command_full_opts():
    opts = {'id': 'admin',
            'conf': '/etc/pve/priv/ceph/cephpool.conf',
            'keyring': '/etc/pve/priv/ceph/cephpool.keyring'}
    cmd = v2p._rbd_map_command('cephpool', 'vm-100-disk-0', opts)
    assert '--id admin' in cmd
    assert '--conf /etc/pve/priv/ceph/cephpool.conf' in cmd
    assert '--keyring /etc/pve/priv/ceph/cephpool.keyring' in cmd
    assert cmd.endswith('-p cephpool vm-100-disk-0')


def test_map_command_quotes_shell_metachars():
    # mon_host carries ';' — must be quoted so it can't break out of the command.
    cmd = v2p._rbd_map_command('pool', 'img', {'mon_host': '10.0.0.1;rm -rf /'})
    assert "'10.0.0.1;rm -rf /'" in cmd
    # a hostile image/pool name is quoted too (defence in depth)
    cmd2 = v2p._rbd_map_command('pool', 'vm-1; touch /pwned', {})
    assert "'vm-1; touch /pwned'" in cmd2
    assert '; touch /pwned' not in cmd2.replace("'vm-1; touch /pwned'", '')


# --------------------------------------------------------------------------- #
# _map_rbd_uri_to_device  (node-exec stubbed)
# --------------------------------------------------------------------------- #

def _stub_exec(monkeypatch, handler):
    """Replace v2p._pve_node_exec with handler(cmd) -> (rc, out, err)."""
    def fake(pve_mgr, node, cmd, timeout=30):
        return handler(cmd)
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)


def test_map_returns_device_from_rbd_map_stdout(monkeypatch):
    def handler(cmd):
        if cmd.startswith('rbd map'):
            return (0, '/dev/rbd0\n', '')
        return (0, '', '')
    _stub_exec(monkeypatch, handler)
    dev = v2p._map_rbd_uri_to_device(None, 'pve1', 'cephpool:vm-1-disk-0',
                                     'rbd:cephpool/vm-1-disk-0')
    assert dev == '/dev/rbd0'


def test_map_falls_back_to_device_list_when_already_mapped(monkeypatch):
    # rbd map prints nothing (already mapped); resolve via `rbd device list`.
    listing = json.dumps([
        {'id': '0', 'pool': 'other', 'image': 'x', 'device': '/dev/rbd0'},
        {'id': '1', 'pool': 'cephpool', 'image': 'vm-1-disk-0', 'device': '/dev/rbd1'},
    ])

    def handler(cmd):
        if cmd.startswith('rbd map'):
            return (0, '', 'rbd: warning: image already mapped')
        if cmd.startswith('rbd device list'):
            return (0, listing, '')
        return (0, '', '')
    _stub_exec(monkeypatch, handler)
    dev = v2p._map_rbd_uri_to_device(None, 'pve1', 'cephpool:vm-1-disk-0',
                                     'rbd:cephpool/vm-1-disk-0')
    assert dev == '/dev/rbd1'


def test_map_returns_none_when_unmappable(monkeypatch):
    def handler(cmd):
        return (1, '', 'error')          # map fails, device list empty
    _stub_exec(monkeypatch, handler)
    dev = v2p._map_rbd_uri_to_device(None, 'pve1', 'cephpool:vm-1-disk-0',
                                     'rbd:cephpool/vm-1-disk-0')
    assert dev is None


def test_map_returns_none_on_unparseable_uri(monkeypatch):
    _stub_exec(monkeypatch, lambda cmd: (0, '', ''))
    assert v2p._map_rbd_uri_to_device(None, 'pve1', 'x', 'rbd:garbage') is None


# --------------------------------------------------------------------------- #
# #722 follow-up — teardown of the kernel rbd maps we created (non-krbd RBD)
# --------------------------------------------------------------------------- #

class _FakeTask:
    def __init__(self, devs=None):
        if devs is not None:
            self._mapped_rbd_devs = devs
        self.logs = []

    def log(self, m):
        self.logs.append(m)


def test_rbd_map_sink_creates_and_reuses_one_list():
    t = _FakeTask()
    a = v2p._rbd_map_sink(t)
    a.append('/dev/rbd5')
    b = v2p._rbd_map_sink(t)
    assert a is b
    assert b == ['/dev/rbd5']


def test_unmap_issues_rbd_unmap_per_device_and_clears(monkeypatch):
    calls = []
    _stub_exec(monkeypatch, lambda cmd: (calls.append(cmd), (0, '', ''))[1])
    t = _FakeTask(['/dev/rbd0', '/dev/rbd1'])
    v2p._unmap_v2p_rbd_devices(None, 'pve1', t)
    assert any('rbd unmap' in c and '/dev/rbd0' in c for c in calls)
    assert any('rbd unmap' in c and '/dev/rbd1' in c for c in calls)
    # cleared so a retry / the orchestrator finally can't double-unmap
    assert t._mapped_rbd_devs == []


def test_unmap_is_noop_when_nothing_tracked(monkeypatch):
    calls = []
    _stub_exec(monkeypatch, lambda cmd: (calls.append(cmd), (0, '', ''))[1])
    t = _FakeTask([])
    v2p._unmap_v2p_rbd_devices(None, 'pve1', t)
    assert calls == []
