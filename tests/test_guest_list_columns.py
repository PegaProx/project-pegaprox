"""The guest agent column of the guest list, from the agent sweep the manager already runs.

The IP sweep (refresh_ip_cache) asks network-get-interfaces of every running VM of a watched
cluster every 30s. What PVE answers there says whether the agent runs: data (200), "QEMU
guest agent is not running" / "No QEMU guest agent configured" / a timeout (500), or an
"Agent error" from the agent itself, which answered. get_vm_resources puts that on the row
as agent_running, so the list needs no call per guest. The disk throughput column is worked
out in the browser from the diskread/diskwrite counters and the uptime of the rows; it is
tested at runtime in test_lists_ui.py.
MK Oct 2026
"""
import threading

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig


class _Resp:
    def __init__(self, status, data=None, text=''):
        self.status_code = status
        self._data = data
        self.text = text

    def json(self):
        return {'data': self._data}


IFACES = {'result': [
    {'name': 'lo', 'ip-addresses': [{'ip-address': '127.0.0.1', 'ip-address-type': 'ipv4'}]},
    {'name': 'eth0', 'ip-addresses': [{'ip-address': 'fe80::1', 'ip-address-type': 'ipv6'},
                                      {'ip-address': '2001:db8::5', 'ip-address-type': 'ipv6'},
                                      {'ip-address': '10.0.0.5', 'ip-address-type': 'ipv4'}]},
]}

# vmid -> what network-get-interfaces answers
AGENT = {
    100: _Resp(200, IFACES),
    101: _Resp(500, None, '{"message":"QEMU guest agent is not running\\n","data":null}'),
    102: _Resp(500, None, '{"message":"No QEMU guest agent configured\\n","data":null}'),
    103: _Resp(500, None, "VM 103 qmp command 'guest-network-get-interfaces' failed - got timeout"),
    104: _Resp(500, None, 'Agent error: The command guest-network-get-interfaces has been disabled'),
    105: _Resp(403, None, 'Permission check failed'),
    106: _Resp(500, None, 'some other failure'),
}

GUESTS = [
    {'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 101, 'node': 'pve1', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 102, 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 103, 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 104, 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 105, 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 106, 'node': 'pve2', 'type': 'qemu', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 200, 'node': 'pve1', 'type': 'lxc', 'status': 'running', 'maxmem': 1, 'mem': 0},
    {'vmid': 300, 'node': 'pve1', 'type': 'qemu', 'status': 'stopped', 'maxmem': 1, 'mem': 0},
]


class _Session:
    def __init__(self, pve):
        self.pve = pve

    def get(self, url, params=None, timeout=None):
        path = url.split('/api2/json', 1)[1]
        self.pve.calls.append(path)
        if path == '/cluster/resources':
            return _Resp(200, [dict(g) for g in self.pve.guests])
        if path.endswith('/agent/network-get-interfaces'):
            vmid = int(path.split('/')[4])
            return self.pve.agent[vmid]
        if path.endswith('/agent/get-fsinfo'):
            return _Resp(200, {'result': []})
        if path.endswith('/interfaces'):
            return _Resp(200, [])
        return _Resp(404)


@pytest.fixture
def mgr():
    m = mgrmod.PegaProxManager('c1', PegaProxConfig({'name': 't', 'host': '127.0.0.1', 'user': 'root@pam',
                                                     'pass': 'pw'}))
    m.is_connected, m.session = True, object()
    m.guests, m.agent, m.calls = [dict(g) for g in GUESTS], dict(AGENT), []
    m._create_session = lambda: _Session(m)
    return m


def _rows(m):
    return {r['vmid']: r for r in m.get_vm_resources()}


def test_what_pve_answers_says_whether_the_agent_runs(mgr):
    assert mgr._probe_qemu_agent('pve1', 100) == (['10.0.0.5', '2001:db8::5'], True)
    assert mgr._probe_qemu_agent('pve1', 101) == ([], False)
    assert mgr._probe_qemu_agent('pve2', 102) == ([], False)
    assert mgr._probe_qemu_agent('pve2', 103) == ([], False)
    # the agent itself refused one command: it runs
    assert mgr._probe_qemu_agent('pve2', 104) == ([], True)
    # says nothing about the agent
    assert mgr._probe_qemu_agent('pve2', 105) == ([], None)
    assert mgr._probe_qemu_agent('pve2', 106) == ([], None)
    # every 500 still lands on the skip list, as before (#237)
    assert mgr._no_agent_vms == {101, 102, 103, 104, 106}
    calls = len(mgr.calls)
    assert mgr._probe_qemu_agent('pve1', 101) == ([], None)
    assert len(mgr.calls) == calls


def test_fetch_qemu_ips_keeps_its_answer(mgr):
    assert mgr._fetch_qemu_ips('pve1', 100) == ['10.0.0.5', '2001:db8::5']
    assert mgr._fetch_qemu_ips('pve1', 101) == []


def test_the_sweep_puts_the_agent_on_the_rows(mgr):
    assert all('agent_running' not in r for r in _rows(mgr).values())
    mgr.refresh_ip_cache()
    rows = _rows(mgr)
    assert rows[100]['agent_running'] is True and rows[100]['ip'] == '10.0.0.5'
    assert rows[101]['agent_running'] is False
    assert rows[102]['agent_running'] is False
    assert rows[103]['agent_running'] is False
    assert rows[104]['agent_running'] is True
    # a 403 tells nothing; a 500 that is no agent message lands on the skip list (#237),
    # and a guest on it reads as without agent
    assert 'agent_running' not in rows[105]
    assert rows[106]['agent_running'] is False
    # containers have no guest agent, a stopped VM none running
    assert 'agent_running' not in rows[200] and 'agent_running' not in rows[300]


def test_a_guest_skipped_by_the_next_sweep_keeps_what_it_said(mgr):
    mgr.refresh_ip_cache()
    probes = [c for c in mgr.calls if c.endswith('network-get-interfaces')]
    mgr.calls.clear()
    mgr.refresh_ip_cache()
    again = [c for c in mgr.calls if c.endswith('network-get-interfaces')]
    # the guests on the skip list are not asked again, their answer stays
    assert len(again) == len(probes) - 5
    rows = _rows(mgr)
    assert rows[101]['agent_running'] is False and rows[104]['agent_running'] is True


def test_an_agent_that_comes_up_is_seen_after_the_skip_list_clears(mgr):
    mgr.refresh_ip_cache()
    assert _rows(mgr)[101]['agent_running'] is False
    mgr.agent[101] = _Resp(200, IFACES)
    mgr._no_agent_vms.clear()   # what the 5 minute TTL and a VM start do
    mgr.refresh_ip_cache()
    assert _rows(mgr)[101]['agent_running'] is True


def test_a_reconnect_forgets_the_agents_with_the_ips():
    import inspect
    src = inspect.getsource(mgrmod.PegaProxManager.connect_to_proxmox)
    block = src[src.index('with self._ip_cache_lock:'):src.index('with self._disk_cache_lock:')]
    assert 'self._ip_cache.clear()' in block and 'self._agent_state.clear()' in block


def test_the_sweep_makes_no_new_call(mgr):
    mgr.refresh_ip_cache()
    per_vm = [c for c in mgr.calls if '/qemu/' in c or '/lxc/' in c]
    # one interfaces read per running guest and one fsinfo per running VM the agent did not refuse
    assert len([c for c in per_vm if c.endswith('network-get-interfaces')]) == 7
    assert len([c for c in per_vm if c.endswith('/interfaces') and '/lxc/' in c]) == 1
    assert not [c for c in per_vm if not c.endswith(('network-get-interfaces', 'get-fsinfo', '/interfaces'))]


def test_a_stand_in_without_the_agent_map_still_lists(mgr):
    # get_vm_resources is borrowed by lighter stand-ins elsewhere (drift): no _agent_state there
    class _Lite:
        host, api_port = 'pve.test', 8006
        get_vm_resources = mgrmod.PegaProxManager.get_vm_resources

        def __init__(self):
            self.is_connected, self.session = True, object()
            self._ip_cache, self._disk_cache = {}, {}
            self._ip_cache_lock, self._disk_cache_lock = threading.Lock(), threading.Lock()
            self._consecutive_failures = 0
            self.guests, self.agent, self.calls = [dict(g) for g in GUESTS], {}, []

        def _create_session(self):
            return _Session(self)
    rows = _Lite().get_vm_resources()
    assert len(rows) == len(GUESTS) and not getattr(rows, 'unavailable', False)
