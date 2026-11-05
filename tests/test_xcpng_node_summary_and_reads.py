"""XCP-ng node pages: the summary carries what the node pages read, a failed read says so.

GET .../nodes/<n>/summary on an XCP-ng pool answered the
get_node_details keys only (cpu_model, product_version, kernel_version ...). The node
pages call a summary without pveversion and without an uptime empty, the answer of a node
the server could not read, so every XCP-ng host had a warning that a retry never cleared
and its health could never be Normal. Now the summary also carries the keys of the
Proxmox one XAPI has: pveversion, kversion, cpuinfo, memory, uptime and loadavg (the last
two from the host row of the last refresh), never a swap or root figure XAPI has not got.

The same for XCP-ng: the time read of a host SSH could not reach answered {'timezone': 'UTC'},
a made up value; the system log and the certificate answered []. They are errors now.

MK Nov 2026
"""
import logging

import pytest

CLUSTER = 'xcp_1'
NODE = 'xcp-host1'

DETAILS = {
    'hostname': NODE, 'uuid': 'u-1', 'address': '10.0.0.5', 'enabled': True,
    'cpu_model': 'AMD EPYC 7302', 'cpu_count': 32, 'cpu_socket_count': 1,
    'memory_total': 64 * 2**30, 'memory_free': 48 * 2**30,
    'xen_version': '4.17', 'product_version': '8.3.0', 'product_brand': 'XCP-ng',
    'kernel_version': '4.19.0+1', 'build_number': 'release/yangtze', 'bios_vendor': 'X',
    'system_manufacturer': 'Y', 'system_product': 'Z', 'pci_devices': [],
}


def _xcp(details=DETAILS, row=None, ssh=None):
    from pegaprox.core.xcpng import XcpngManager
    m = object.__new__(XcpngManager)
    m.logger = logging.getLogger('test.xcpng')
    m.get_node_details = lambda node: dict(details) if details else {}
    m._cached_nodes = [row] if row else []
    if ssh is not None:
        m._ssh_exec = lambda node, cmd, timeout=60: ssh
    return m


ROW = {'node': NODE, 'uptime': 86400 + 3600, '_loadavg': [0.5], 'status': 'online'}


def test_the_summary_carries_the_keys_the_node_pages_read():
    s = _xcp(row=ROW).get_node_summary(NODE)
    assert s['pveversion'] == 'XCP-ng 8.3.0'
    assert s['uptime'] == 90000
    assert s['kversion'] == '4.19.0+1'
    assert s['cpuinfo'] == {'model': 'AMD EPYC 7302', 'cpus': 32, 'sockets': 1}
    assert s['memory'] == {'total': 64 * 2**30, 'used': 16 * 2**30, 'free': 48 * 2**30}
    assert s['loadavg'] == [0.5]
    assert (s['node'], s['status']) == (NODE, 'online')
    # what was there before stays
    for k, v in DETAILS.items():
        assert s[k] == v, k


def test_no_swap_or_root_figure_xapi_does_not_have():
    s = _xcp(row=ROW).get_node_summary(NODE)
    assert 'swap' not in s and 'rootfs' not in s


def test_an_unread_uptime_or_memory_is_left_out_not_zero():
    details = dict(DETAILS, memory_total=0, memory_free=0)
    s = _xcp(details=details, row=dict(ROW, uptime=0, _loadavg=None)).get_node_summary(NODE)
    assert 'uptime' not in s and 'memory' not in s and 'loadavg' not in s
    # without a product version there is no version to name either
    s = _xcp(details=dict(DETAILS, product_version='')).get_node_summary(NODE)
    assert 'pveversion' not in s


def test_a_host_that_could_not_be_read_stays_empty():
    assert _xcp(details={}).get_node_summary(NODE) == {}


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _route_mgr(api, xcp):
    from pegaprox.core.xcpng import XcpngManager
    m = api.make_fake_manager(CLUSTER, cluster_type='xcpng')
    m.is_connected = True
    for name in ('get_node_summary', 'get_node_time', 'get_node_syslog', 'get_node_certificates'):
        setattr(m, name, getattr(XcpngManager, name).__get__(xcp, XcpngManager))
    return api.set_manager(CLUSTER, m)


def test_the_summary_route_hands_the_keys_on(api, admin):
    _route_mgr(api, _xcp(row=ROW))
    r = admin.get(f'/api/clusters/{CLUSTER}/nodes/{NODE}/summary')
    assert r.status_code == 200
    assert (r.get_json()['pveversion'], r.get_json()['uptime']) == ('XCP-ng 8.3.0', 90000)


@pytest.mark.parametrize('route', ['time', 'syslog', 'certificates'])
def test_a_host_ssh_did_not_reach_is_an_error(api, admin, route):
    _route_mgr(api, _xcp(ssh=(-1, '', 'SSH connection failed')))
    r = admin.get(f'/api/clusters/{CLUSTER}/nodes/{NODE}/{route}')
    assert r.status_code == 502, (route, r.status_code, r.get_data(as_text=True))
    body = r.get_json()
    assert body['code'] == 'PVE_READ_FAILED'
    assert 'SSH connection failed' in body['error']
    assert 'timezone' not in body


@pytest.mark.parametrize('route,out,want', [
    ('time', 'Europe/Vienna\n---\n2026-11-03T10:00:00+01:00\n',
     {'timezone': 'Europe/Vienna', 'localtime': '2026-11-03T10:00:00+01:00'}),
    ('syslog', 'line one\nline two\n', [{'n': 0, 't': 'line one'}, {'n': 1, 't': 'line two'}]),
    ('syslog', '', []),
])
def test_a_host_that_answered_is_handed_on(api, admin, route, out, want):
    _route_mgr(api, _xcp(ssh=(0, out, '')))
    r = admin.get(f'/api/clusters/{CLUSTER}/nodes/{NODE}/{route}')
    assert (r.status_code, r.get_json()) == (200, want)
