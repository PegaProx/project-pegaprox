"""The manager and its HA checks on an IPv6-only control plane (#1158).

The URL form of a host ("[2001:db8::10]") reached places that want the address: the
node-address lookup handed it back for the connected node and compared it with addresses
the cluster reports (so its "no other node resolves to the connected host" filter never
held), the scp target lost the address at its first colon, sockets were AF_INET only, the
quorum defaults were three IPv4 resolvers (a v6-only PegaProx never got a vote and refused
every recovery), and the gateway check of the network verification knew only the IPv4
default route, so on a v6-only host it was skipped.

Each test below fails on the code before the fix. Nothing opens a real connection: the
sockets, ping, ip and DNS are fakes.
"""
import ipaddress
import logging
import shlex
import socket
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig


class _Answer:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


def _bare_manager(**cfg):
    data = {'name': 'lab', 'host': '2001:db8::10', 'user': 'root@pam', 'pass': 'pw'}
    data.update(cfg)
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = None
    m.config = PegaProxConfig(data)
    m.current_host = None
    m.ha_config = {}
    m.logger = MagicMock()
    return m


class _FakeSocket:
    """Records the family and the address; every connect answers."""
    made = []

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, *a, **kw):
        self.family = family
        self.addr = None
        _FakeSocket.made.append(self)

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        self.addr = addr
        return 0

    def connect(self, addr):
        self.addr = addr

    def getsockname(self):
        return ('2001:db8::99', 40000, 0, 0) if self.family == socket.AF_INET6 else ('192.0.2.99', 40000)

    def close(self):
        pass


@pytest.fixture
def fake_net(monkeypatch):
    """Sockets that answer and record, a DNS that knows nothing."""
    _FakeSocket.made = []

    def _no_dns(*a, **kw):
        raise socket.gaierror('no such name')
    monkeypatch.setattr(socket, 'socket', _FakeSocket)
    monkeypatch.setattr(socket, 'getaddrinfo', _no_dns)
    monkeypatch.setattr(socket, 'gethostbyname', _no_dns)
    return _FakeSocket.made


# --- the host properties ----------------------------------------------------------------

@pytest.mark.parametrize('stored,raw', [('[2001:db8::10]', '2001:db8::10'),
                                        ('2001:db8::10', '2001:db8::10'),
                                        ('192.0.2.10', '192.0.2.10'),
                                        ('pve1.lab', 'pve1.lab')])
def test_raw_host_has_no_url_brackets(stored, raw):
    m = _bare_manager(host=stored)
    assert m.raw_host == raw
    # the URL form keeps them
    assert m.host == (f'[{raw}]' if ':' in raw else raw)


def test_raw_host_keeps_a_bracketed_non_address():
    """Only a real IPv6 literal loses its brackets, nothing becomes an option."""
    m = _bare_manager(host='[-oProxyCommand=x]')
    assert m.raw_host == '[-oProxyCommand=x]'


# --- the node address lookup ------------------------------------------------------------

STATUS = [{'type': 'node', 'name': 'pve1', 'ip': '2001:db8::10', 'local': 1},
          {'type': 'node', 'name': 'pve2', 'ip': '2001:db8::11', 'local': 0},
          {'type': 'node', 'name': 'pve3', 'ip': '2001:db8::12', 'local': 0}]


def _lookup_manager(connected, configured=None, rows=STATUS, networks=None):
    networks = networks or {}

    def api_get(url, **kw):
        if url.endswith('/cluster/status'):
            return _Answer(200, rows)
        for node, data in networks.items():
            if url.endswith(f'/nodes/{node}/network'):
                return _Answer(200, data)
        return _Answer(595)
    bare = connected.strip('[]')
    return types.SimpleNamespace(
        id=None, is_connected=True, host=connected, raw_host=bare, api_port=8006,
        logger=logging.getLogger('test'),
        config=types.SimpleNamespace(host=configured or bare, ssh_port=22, ssh_disabled=False),
        _api_get=api_get)


def test_the_connected_node_comes_back_as_a_bare_address(fake_net):
    m = _lookup_manager('[2001:db8::10]')
    assert PegaProxManager._get_node_ip_impl(m, 'pve1') == '2001:db8::10'


def test_the_others_keep_their_own_address(fake_net):
    m = _lookup_manager('[2001:db8::10]')
    assert PegaProxManager._get_node_ip_impl(m, 'pve2') == '2001:db8::11'


@pytest.mark.parametrize('listed', ['2001:db8::10', '2001:DB8::10', '2001:db8:0:0::10'])
def test_no_other_node_resolves_to_the_connected_host(fake_net, listed):
    """The filter of #1136 compared the URL form with what the cluster reports, so with
    IPv6 it never matched: a member listed at the connected host's address got it, and
    SSH (with that member's own password) went to the wrong node."""
    rows = [dict(r) for r in STATUS]
    rows[2]['ip'] = listed
    m = _lookup_manager('[2001:db8::10]', rows=rows)
    got = PegaProxManager._get_node_ip_impl(m, 'pve3')
    assert got is None or ipaddress.ip_address(got) != ipaddress.ip_address('2001:db8::10'), got


@pytest.mark.parametrize('connected,resolved,af', [
    ('[2001:db8::10]', '2001:db8::10', socket.AF_INET6),
    ('192.168.1.2', '192.168.1.2', socket.AF_INET),
])
def test_the_dns_fallback_never_hands_out_the_connected_host(fake_net, monkeypatch,
                                                              connected, resolved, af):
    """A node the cluster does not list, whose name resolves to the connected host: the
    probing DNS loop skipped that address, the "return the first anyway" loop after it did
    not, and the node got the connected host's address with its own password."""
    rows = [r for r in STATUS if r['name'] != 'pve3']
    monkeypatch.setattr(socket, 'getaddrinfo',
                        lambda *a, **k: [(af, socket.SOCK_STREAM, 6, '', (resolved, 8006))])
    m = _lookup_manager(connected, rows=rows)
    got = PegaProxManager._get_node_ip_impl(m, 'pve3')
    assert got is None or ipaddress.ip_address(got) != ipaddress.ip_address(resolved), got


def test_an_ipv4_cluster_answers_as_before(fake_net):
    rows = [{'type': 'node', 'name': 'pve1', 'ip': '192.168.1.2', 'local': 1},
            {'type': 'node', 'name': 'pve2', 'ip': '192.168.1.3', 'local': 0},
            {'type': 'node', 'name': 'pve3', 'ip': '192.168.1.2', 'local': 0}]
    m = _lookup_manager('192.168.1.2', rows=rows)
    assert PegaProxManager._get_node_ip_impl(m, 'pve1') == '192.168.1.2'
    assert PegaProxManager._get_node_ip_impl(m, 'pve2') == '192.168.1.3'
    assert PegaProxManager._get_node_ip_impl(m, 'pve3') != '192.168.1.2'


def test_the_management_interface_of_an_ipv6_primary_is_found(fake_net):
    """STEP 1 read only `address`: an IPv6 primary never named its interface, so the
    target's address on the same interface got no exact-match score."""
    networks = {'pve1': [{'iface': 'vmbr0', 'type': 'bridge', 'address6': '2001:db8::10',
                          'cidr6': '2001:db8::10/64'},
                         {'iface': 'vmbr1', 'type': 'bridge', 'address': '10.99.0.1',
                          'cidr': '10.99.0.1/24'}]}
    m = _lookup_manager('[2001:db8::10]', networks=networks)
    PegaProxManager._get_node_ip_impl(m, 'pve2')
    assert m._cached_mgmt_iface == 'vmbr0'
    assert m._cached_mgmt_network == ipaddress.ip_network('2001:db8::/64')


def test_an_ipv4_primary_still_reads_address(fake_net):
    rows = [{'type': 'node', 'name': 'pve1', 'ip': '192.168.1.2', 'local': 1},
            {'type': 'node', 'name': 'pve2', 'ip': '192.168.1.3', 'local': 0}]
    networks = {'pve1': [{'iface': 'vmbr0', 'type': 'bridge', 'address': '192.168.1.2',
                          'cidr': '192.168.1.2/24', 'address6': '2001:db8::10',
                          'cidr6': '2001:db8::10/64'}]}
    m = _lookup_manager('192.168.1.2', rows=rows, networks=networks)
    PegaProxManager._get_node_ip_impl(m, 'pve2')
    assert m._cached_mgmt_iface == 'vmbr0'
    assert m._cached_mgmt_network == ipaddress.ip_network('192.168.1.0/24')


# --- the HA address helpers -------------------------------------------------------------

def _ha_manager(networks=None):
    sess = MagicMock()

    def get(url, **kw):
        if url.endswith('/network') and networks is not None:
            return _Answer(200, networks)
        return _Answer(595)
    sess.get.side_effect = get
    return types.SimpleNamespace(
        id=None, host='[2001:db8::10]', api_port=8006, ha_config={}, logger=logging.getLogger('test'),
        _get_node_ip=lambda n: None, _create_session=lambda: sess)


def test_all_node_ips_read_the_ipv6_fields(fake_net):
    m = _ha_manager([{'iface': 'vmbr0', 'address': '192.0.2.21', 'address6': '2001:db8::21'},
                     {'iface': 'vmbr1', 'cidr6': '2001:db8:1::21/64'},
                     {'iface': 'vmbr2', 'address6': 'fe80::21'}])
    ips = PegaProxManager._ha_get_all_node_ips(m, 'pve2')
    assert '2001:db8::21' in ips and '2001:db8:1::21' in ips
    assert '192.0.2.21' in ips
    assert not [ip for ip in ips if ip.startswith('fe80')]


def test_the_dns_fallback_knows_aaaa_records(monkeypatch):
    def gai(name, port, family=0, type=0, proto=0, flags=0):
        if name == 'pve2':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::30', 0, 0, 0))]
        raise socket.gaierror('no such name')

    def no_v4(*a, **kw):
        raise socket.gaierror('no A record')
    monkeypatch.setattr(socket, 'getaddrinfo', gai)
    monkeypatch.setattr(socket, 'gethostbyname', no_v4)
    assert PegaProxManager._ha_get_all_node_ips(_ha_manager(), 'pve2') == ['2001:db8::30']


def test_the_dns_fallback_keeps_the_ipv4_address_first(monkeypatch):
    def gai(name, port, family=0, type=0, proto=0, flags=0):
        if name == 'pve2':
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::30', 0, 0, 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.30', 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.31', 0))]
        raise socket.gaierror('no such name')
    def ghbn(name):
        if name == 'pve2':
            return '192.0.2.30'
        raise socket.gaierror('no such name')
    monkeypatch.setattr(socket, 'getaddrinfo', gai)
    monkeypatch.setattr(socket, 'gethostbyname', ghbn)
    ips = PegaProxManager._ha_get_all_node_ips(_ha_manager(), 'pve2')
    assert ips[0] == '192.0.2.30' and '2001:db8::30' in ips


@pytest.mark.parametrize('typed', ['2001:db8::40', '[2001:db8::40]'])
def test_the_ha_fallback_probe_uses_the_family_of_the_address(fake_net, typed):
    m = types.SimpleNamespace(logger=logging.getLogger('test'), _get_node_ip=lambda n: None,
                              _ha_get_all_node_ips=lambda n: [typed])
    assert PegaProxManager._ha_get_node_ip(m, 'pve4') == '2001:db8::40'
    assert fake_net and fake_net[0].family == socket.AF_INET6
    assert fake_net[0].addr == ('2001:db8::40', 8006)


def test_the_ha_fallback_probe_of_an_ipv4_address_is_unchanged(fake_net):
    m = types.SimpleNamespace(logger=logging.getLogger('test'), _get_node_ip=lambda n: None,
                              _ha_get_all_node_ips=lambda n: ['192.0.2.40'])
    assert PegaProxManager._ha_get_node_ip(m, 'pve4') == '192.0.2.40'
    assert fake_net[0].family == socket.AF_INET and fake_net[0].addr == ('192.0.2.40', 8006)


def test_our_address_for_the_agents_comes_from_an_ipv6_socket(fake_net):
    """AF_INET with "[2001:db8::10]" never got a socket: no agent URL for this instance."""
    m = _bare_manager(host='2001:db8::10')
    assert m._get_pegaprox_server_ip() == '2001:db8::99'
    assert fake_net[0].family == socket.AF_INET6
    assert fake_net[0].addr == ('2001:db8::10', 8006)


def test_our_address_on_an_ipv4_cluster_is_unchanged(fake_net):
    m = _bare_manager(host='192.0.2.10')
    assert m._get_pegaprox_server_ip() == '192.0.2.99'
    assert fake_net[0].family == socket.AF_INET and fake_net[0].addr == ('192.0.2.10', 8006)


# --- DNS pin (ssl_verify off) -----------------------------------------------------------

def _dual_stack_dns(monkeypatch, v4_configured):
    """pve.lab has A and AAAA. AI_ADDRCONFIG drops the A record on a host without IPv4."""
    asked = []

    def gai(host, port, family=0, type=0, proto=0, flags=0):
        asked.append(flags)
        a = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', port))
        aaaa = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::10', port, 0, 0))
        if flags & socket.AI_ADDRCONFIG and not v4_configured:
            return [aaaa]
        return [aaaa, a]
    monkeypatch.setattr(socket, 'getaddrinfo', gai)
    return asked


def test_the_pin_of_a_v6_only_pegaprox_is_the_aaaa_record(monkeypatch):
    asked = _dual_stack_dns(monkeypatch, v4_configured=False)
    assert PegaProxManager._resolve_host('pve.lab') == '2001:db8::10'
    assert asked and asked[0] & socket.AI_ADDRCONFIG


def test_a_dual_stack_pegaprox_still_pins_ipv4(monkeypatch):
    _dual_stack_dns(monkeypatch, v4_configured=True)
    assert PegaProxManager._resolve_host('pve.lab') == '192.0.2.10'


def test_the_pin_stays_where_addrconfig_finds_nothing(monkeypatch):
    """A box with only lo: AI_ADDRCONFIG answers nothing, the name is still pinned."""
    def gai(host, port, family=0, type=0, proto=0, flags=0):
        if flags & socket.AI_ADDRCONFIG:
            raise socket.gaierror(socket.EAI_NONAME, 'no address family configured')
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', port))]
    monkeypatch.setattr(socket, 'getaddrinfo', gai)
    assert PegaProxManager._resolve_host('pve.lab') == '192.0.2.10'


# --- quorum, ping and the network check -------------------------------------------------

V6_DEFAULTS = ['2001:4860:4860::8888', '2606:4700:4700::1111', '2620:fe::fe']
V4_DEFAULTS = ['8.8.8.8', '1.1.1.1', '9.9.9.9']


def _quorum(monkeypatch, answers, v4_route=True, **ha):
    m = _bare_manager()
    m.ha_config.update(ha)
    pinged = []

    def ping(host, timeout=3):
        pinged.append(host)
        return host in answers
    monkeypatch.setattr(m, '_ha_ping_host', ping, raising=False)
    monkeypatch.setattr(m, '_has_v4_default_route', lambda: v4_route, raising=False)
    return m, pinged


def _summary(m):
    return [c.args[0] for c in m.logger.info.call_args_list if 'Quorum check' in c.args[0]][-1]


def test_a_v6_only_pegaprox_gets_the_votes_of_the_default_resolvers(monkeypatch):
    m, pinged = _quorum(monkeypatch, set(V6_DEFAULTS), v4_route=False)
    assert m._ha_check_quorum() is True
    assert pinged == V6_DEFAULTS
    assert '4/4 votes' in _summary(m)


def test_on_ipv4_the_defaults_are_pinged_and_counted_as_before(monkeypatch):
    m, pinged = _quorum(monkeypatch, set(V4_DEFAULTS))
    assert m._ha_check_quorum() is True
    assert pinged == V4_DEFAULTS
    assert '4/4 votes' in _summary(m)


def test_a_dual_stack_box_without_its_v4_uplink_still_has_no_quorum(monkeypatch):
    """The v4 default route is there but nothing answers on it, while IPv6 would: the
    IPv6 resolvers must not stand in for the lost uplink (split-brain safety)."""
    m, pinged = _quorum(monkeypatch, set(V6_DEFAULTS), v4_route=True)
    assert m._ha_check_quorum() is False
    assert pinged == V4_DEFAULTS
    assert '1/4 votes' in _summary(m)


def test_nothing_answering_is_no_quorum(monkeypatch):
    m, pinged = _quorum(monkeypatch, set(), v4_route=False)
    assert m._ha_check_quorum() is False
    assert '1/4 votes' in _summary(m)
    assert pinged == V6_DEFAULTS


@pytest.mark.parametrize('table, expected', [
    # Iface Destination Gateway Flags ...
    ('eth0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\n', True),
    ('eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n', False),   # only a LAN route
    ('eth0\t00000000\t0102000A\t0002\t0\t0\t0\t00000000\n', False),   # default, not up
    ('', False),
])
def test_the_v4_default_route_is_read_from_proc(monkeypatch, tmp_path, table, expected):
    import builtins
    f = tmp_path / 'route'
    f.write_text('Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n' + table)
    real_open = builtins.open
    monkeypatch.setattr(builtins, 'open',
                        lambda p, *a, **k: real_open(f if p == '/proc/net/route' else p, *a, **k))
    assert PegaProxManager._has_v4_default_route() is expected


def test_without_proc_the_ipv4_defaults_stay(monkeypatch):
    import builtins
    real_open = builtins.open

    def no_proc(p, *a, **k):
        if p == '/proc/net/route':
            raise FileNotFoundError(p)
        return real_open(p, *a, **k)
    monkeypatch.setattr(builtins, 'open', no_proc)
    assert PegaProxManager._has_v4_default_route() is True


def test_configured_quorum_hosts_are_asked_alone(monkeypatch):
    m, pinged = _quorum(monkeypatch, {'192.0.2.1'}, quorum_hosts=['192.0.2.1', '192.0.2.2'])
    assert m._ha_check_quorum() is True
    assert pinged == ['192.0.2.1', '192.0.2.2']
    assert '2/3 votes' in _summary(m)


@pytest.fixture
def ping_argv(monkeypatch):
    calls = []

    def run(argv, *a, **kw):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(mgrmod.subprocess, 'run', run)
    return calls


@pytest.mark.parametrize('given,sent', [('[2001:db8::1]', '2001:db8::1'), ('2001:db8::1', '2001:db8::1'),
                                        ('fe80::1%eth0', 'fe80::1%eth0'), ('192.0.2.1', '192.0.2.1')])
def test_ping_gets_the_bare_address(ping_argv, given, sent):
    assert _bare_manager()._ha_ping_host(given) is True
    assert ping_argv == [['ping', '-c', '1', '-W', '3', sent]]


@pytest.mark.parametrize('bad', ['-f', '--help', '-c1000', '', None])
def test_ping_never_gets_an_option_for_a_host(ping_argv, bad):
    """A quorum host is typed in the HA settings; '-f' would be an option of ping, and a
    vote must not come from something that is no host."""
    assert _bare_manager()._ha_ping_host(bad) is False
    assert ping_argv == []


def test_without_ping_the_tcp_probe_follows_the_family(monkeypatch):
    def no_ping(argv, *a, **kw):
        raise FileNotFoundError('ping')
    seen = []

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def create_connection(addr, timeout=None, *a, **kw):
        seen.append(addr)
        return _Conn()
    monkeypatch.setattr(mgrmod.subprocess, 'run', no_ping)
    monkeypatch.setattr(socket, 'create_connection', create_connection)
    # the old AF_INET socket must not be what answers here
    monkeypatch.setattr(socket, 'socket', lambda *a, **k: pytest.fail('an AF_INET socket was made'))
    assert _bare_manager()._ha_ping_host('[2001:db8::1]') is True
    assert seen == [('2001:db8::1', 80)]


def test_without_ping_a_refused_connect_is_no_answer(monkeypatch):
    def no_ping(argv, *a, **kw):
        raise FileNotFoundError('ping')

    def refused(addr, timeout=None, *a, **kw):
        raise ConnectionRefusedError()
    monkeypatch.setattr(mgrmod.subprocess, 'run', no_ping)
    monkeypatch.setattr(socket, 'create_connection', refused)
    assert _bare_manager()._ha_ping_host('2001:db8::1') is False


V6_ROUTE = 'default via fe80::1 dev vmbr0 proto ra metric 1024 expires 1798sec hoplimit 64 pref medium\n'


def _routes(monkeypatch, v4, v6):
    ran = []

    def run(argv, *a, **kw):
        ran.append(list(argv))
        out = v6 if '-6' in argv else v4
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
    monkeypatch.setattr(mgrmod.subprocess, 'run', run)
    return ran


def test_a_v6_only_host_checks_its_ipv6_gateway(monkeypatch):
    """No IPv4 default route: the check was skipped and recovery went ahead unchecked."""
    _routes(monkeypatch, '', V6_ROUTE)
    m = _bare_manager()
    pinged = []
    monkeypatch.setattr(m, '_ha_ping_host', lambda h, timeout=3: pinged.append(h) or False, raising=False)
    assert m._ha_verify_network() is False
    assert pinged == ['fe80::1%vmbr0']


def test_a_reachable_ipv6_gateway_passes(monkeypatch):
    _routes(monkeypatch, '', V6_ROUTE)
    m = _bare_manager()
    monkeypatch.setattr(m, '_ha_ping_host', lambda h, timeout=3: h == 'fe80::1%vmbr0', raising=False)
    assert m._ha_verify_network() is True


def test_an_ipv4_gateway_is_checked_as_before(monkeypatch):
    ran = _routes(monkeypatch, 'default via 192.168.1.1 dev vmbr0 proto kernel onlink\n', V6_ROUTE)
    m = _bare_manager()
    pinged = []
    monkeypatch.setattr(m, '_ha_ping_host', lambda h, timeout=3: pinged.append(h) or True, raising=False)
    assert m._ha_verify_network() is True
    assert pinged == ['192.168.1.1']
    assert ran == [['ip', 'route', 'show', 'default']]     # IPv6 not even asked


def test_no_default_route_at_all_still_skips(monkeypatch):
    _routes(monkeypatch, '', '')
    m = _bare_manager()
    monkeypatch.setattr(m, '_ha_ping_host', lambda h, timeout=3: pytest.fail('pinged'), raising=False)
    assert m._ha_verify_network() is True


@pytest.mark.parametrize('out,gw', [
    (V6_ROUTE, 'fe80::1%vmbr0'),
    ('default via 2001:db8::1 dev eth0 metric 1024 pref medium', '2001:db8::1'),
    ('default proto ra metric 1024 pref medium\n\tnexthop via fe80::1 dev eno1 weight 1\n'
     '\tnexthop via fe80::2 dev eno2 weight 1\n', 'fe80::1%eno1'),
    ('default dev wg0 metric 1024', None),
    ('default via notanaddress dev eth0', None),
    ('default via fe80::1', None),                         # link-local with no interface
    ('default via fe80::1 dev bad;name', None),
    ('', None),
])
def test_the_ipv6_gateway_is_read_from_the_route(out, gw):
    assert PegaProxManager._v6_gateway_of(out) == gw


# --- the node-to-node scp ---------------------------------------------------------------

def _sync_manager(addresses):
    m = _bare_manager()
    m.id = 'c1'
    m.config.ssh_user = 'root'
    m.is_connected = True
    m._get_syncable_storage = lambda *a, **k: ({}, None)
    m.get_node_status = lambda: {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m.member_node_ip = lambda n: addresses[n]
    m._resolve_storage_path = lambda *a, **k: '/var/lib/vz/template/iso'
    m.ssh_password_to_offer = lambda host=None: ''
    m._own_password_at = lambda host: ''
    sent = []

    def connect(ip):
        client = MagicMock()

        def exec_command(cmd, timeout=None):
            sent.append(cmd)
            out = MagicMock()
            out.channel.recv_exit_status.return_value = 0
            out.read.return_value = b''
            return MagicMock(), out, MagicMock()
        client.exec_command.side_effect = exec_command
        client.open_sftp.side_effect = OSError('no sftp in tests')
        return client
    m._ssh_connect = connect
    return m, sent


def test_an_ipv6_scp_target_is_bracketed_and_quoted():
    m, sent = _sync_manager({'pve1': '2001:db8::1', 'pve2': '2001:db8::2'})
    res = m.sync_content_to_nodes('pve1', 'local', 'debian-12.iso')
    scp = [c for c in sent if c.startswith('scp ')]
    assert scp, sent
    words = shlex.split(scp[0])
    assert words[-3] == '--'
    assert words[-1] == 'root@[2001:db8::2]:/var/lib/vz/template/iso/'
    assert "'root@[2001:db8::2]':" in scp[0]
    assert res and res[0].get('method') == 'scp', res


def test_an_ipv4_scp_target_is_unchanged():
    m, sent = _sync_manager({'pve1': '10.20.0.1', 'pve2': '10.20.0.2'})
    m.sync_content_to_nodes('pve1', 'local', 'debian-12.iso')
    scp = [c for c in sent if c.startswith('scp ')]
    assert scp and shlex.split(scp[0])[-1] == 'root@10.20.0.2:/var/lib/vz/template/iso/'


# --- the SSH entry ----------------------------------------------------------------------

def test_ssh_connect_judges_the_bare_address(monkeypatch):
    """The credential check and the password lookup saw "[2001:db8::5]", paramiko the
    bare address: both now see the one that is connected to."""
    m = _bare_manager()
    judged = []
    m.ssh_blocked_reason = lambda host=None, node=None: judged.append(host) or 'SSH_DISABLED'
    assert m._ssh_connect('[2001:db8::5]') is None
    assert m._ssh_connect('[2001:db8::5]', pinned_as='[2001:db8::6]') is None
    assert judged == ['2001:db8::5', '2001:db8::6']
