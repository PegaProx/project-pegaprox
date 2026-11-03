"""Link speed per interface for the node's Network table.

PVE's /nodes/<n>/network carries the interface config only, never the negotiated speed, so
the speed is read from /sys/class/net/<if>/speed over SSH. The probe is a shell command,
so it runs here against a fake sysfs tree laid out like the kernel's: a NIC with link, a
NIC without link (the kernel answers -1; e.g., a nested VM), a bridge (the read fails) and a bond.
"""
import subprocess
import types

from pegaprox.core.manager import PegaProxManager


def _iface(root, name, speed=None, operstate='up', speed_error=False):
    d = root / name
    d.mkdir(parents=True)
    (d / 'operstate').write_text(operstate + '\n')
    if speed_error:
        (d / 'speed').mkdir()   # cat fails, like EINVAL on a bridge
    elif speed is not None:
        (d / 'speed').write_text(f'{speed}\n')


def _run_probe(root):
    cmd = PegaProxManager._LINK_SPEED_PROBE.replace('/sys/class/net', str(root))
    return subprocess.run(['sh', '-c', cmd], capture_output=True, text=True, check=True).stdout


def test_probe_and_parser_read_a_fake_sysfs(tmp_path):
    tmp_path = tmp_path / 'net'
    _iface(tmp_path, 'eno1', speed=1000)
    _iface(tmp_path, 'enp65s0f0', speed=25000)
    _iface(tmp_path, 'eno2', speed=-1, operstate='down')
    _iface(tmp_path, 'vmbr0', speed_error=True)
    _iface(tmp_path, 'bond0', speed=20000)
    _iface(tmp_path, 'lo', operstate='unknown')

    rows = {r['iface']: r for r in PegaProxManager._parse_link_speeds(_run_probe(tmp_path))}

    assert rows['eno1'] == {'iface': 'eno1', 'speed_mbps': 1000, 'operstate': 'up'}
    assert rows['enp65s0f0']['speed_mbps'] == 25000
    assert rows['bond0']['speed_mbps'] == 20000
    assert rows['eno2'] == {'iface': 'eno2', 'speed_mbps': None, 'operstate': 'down'}
    assert rows['vmbr0']['speed_mbps'] is None
    assert rows['lo']['speed_mbps'] is None


def test_probe_on_an_empty_class_dir_answers_nothing(tmp_path):
    net = tmp_path / 'net'
    net.mkdir()
    assert PegaProxManager._parse_link_speeds(_run_probe(net)) == []


def test_parser_skips_lines_it_cannot_read():
    out = 'eno1 1000 up\ngarbage\n\neno2 abc up\n'
    assert PegaProxManager._parse_link_speeds(out) == [
        {'iface': 'eno1', 'speed_mbps': 1000, 'operstate': 'up'},
        {'iface': 'eno2', 'speed_mbps': None, 'operstate': 'up'},
    ]


def test_endpoint_hands_on_the_rows(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    rows = [{'iface': 'eno1', 'speed_mbps': 10000, 'operstate': 'up'}]
    fake = types.SimpleNamespace(cluster_id='cluster_1', is_connected=True,
                                 get_node_link_speeds=lambda node: {'interfaces': rows})
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).get('/api/clusters/cluster_1/nodes/node1/network/link-speeds')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == {'interfaces': rows}


def test_endpoint_says_why_a_read_failed(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = types.SimpleNamespace(cluster_id='cluster_1', is_connected=True,
                                 get_node_link_speeds=lambda node: {'error': 'no answer from node node1 over SSH'})
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).get('/api/clusters/cluster_1/nodes/node1/network/link-speeds')
    assert resp.status_code == 502
    assert 'over SSH' in resp.get_json()['error']


def test_endpoint_graceful_for_manager_without_the_read(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', types.SimpleNamespace(cluster_id='cluster_1', is_connected=True))

    resp = api.as_user(admin).get('/api/clusters/cluster_1/nodes/node1/network/link-speeds')
    assert resp.status_code == 200
    assert 'not available' in resp.get_json()['error']


def test_ssh_switched_off_answers_before_any_lookup():
    mgr = PegaProxManager.__new__(PegaProxManager)
    mgr.ssh_blocked_reason = lambda node=None: 'SSH_DISABLED'
    mgr._get_node_ip = lambda node: (_ for _ in ()).throw(AssertionError('no IP lookup with SSH off'))
    res = mgr.get_node_link_speeds('node1')
    assert res['code'] == 'SSH_DISABLED'


def _member_check_mgr(members):
    # a connected manager whose SSH is allowed; any IP lookup or SSH login fails the test
    mgr = PegaProxManager.__new__(PegaProxManager)
    mgr.ssh_blocked_reason = lambda node=None: None
    mgr.is_connected = True
    mgr.__class__ = type('M', (PegaProxManager,), {'nodes': property(lambda self: members)})
    boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError('no lookup or SSH for a non-member'))
    mgr._get_node_ip = boom
    mgr.member_node_ip = boom
    mgr._ssh_read_output = boom
    return mgr


def test_a_non_member_name_is_refused_before_any_lookup():
    res = _member_check_mgr({'node1': {}}).get_node_link_speeds('attacker.example.com')
    assert res['code'] == 'NOT_A_MEMBER'


def test_an_unknown_member_list_refuses_too():
    res = _member_check_mgr({}).get_node_link_speeds('node1')
    assert res['code'] == 'NOT_A_MEMBER'


def test_endpoint_answers_404_for_a_non_member(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = types.SimpleNamespace(cluster_id='cluster_1', is_connected=True,
                                 get_node_link_speeds=lambda node: {'error': 'not a member', 'code': 'NOT_A_MEMBER'})
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).get('/api/clusters/cluster_1/nodes/evil/network/link-speeds')
    assert resp.status_code == 404
