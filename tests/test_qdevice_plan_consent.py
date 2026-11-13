"""The plan of a QDevice setup and the consent to it (core/qnetd.py plan, api/qnetd.py).

Before anything changes, the admin reads what a setup would do - on the QNetd host, on
which nodes, in corosync.conf, in the firewall - and agrees to it per cluster. The
server holds them to it: no setup starts without a consent, and the job reads the plan
again before it acts and stops when it is not the one agreed to (plan_changed). The plan
itself changes nothing anywhere.

The cluster, the nodes and the QNetd host are the fakes of tests/test_qnetd_core.py.
MK Oct 2026
"""
import hashlib
import json
import os
import shutil
import subprocess

import pytest

from pegaprox.core import qnetd

from test_qnetd_core import FakeFirewall, _agree, _checks, _run, world  # noqa: F401
from test_qnetd_api import CONSENT, DIGEST, SSH_HOST, env  # noqa: F401

REC = {'id': 'aaaaaaaaaaaa', 'kind': 'ssh', 'address': '192.0.2.50', 'port': 5403}
HELPER_COPY = (b'#!/usr/bin/python3 -I\nPROTOCOL = 2\n', 2)


@pytest.fixture(autouse=True)
def _clean():
    qnetd.reset_for_tests()
    yield
    qnetd.reset_for_tests()


# --- the digest --------------------------------------------------------------------------

def _basis(**kw):
    a = dict(cid='c1', name='pve', nodes=['pve2', 'pve1'], missing=['pve2'], rec=REC,
             opts={'install_packages': True, 'open_firewall': True}, sources=['10.0.0.2', '10.0.0.1', '10.0.0.1'],
             stores=[])
    a.update(kw)
    return qnetd.plan_basis(a['cid'], a['name'], a['nodes'], a['missing'], a['rec'], a['opts'], a['sources'],
                            a['stores'])


VOTES = {'id': 'votes', 'where': 'cluster', 'node': None, 'params': {'before': 2, 'after': 3},
         'text': 'The cluster has 3 votes instead of 2: one more from the QDevice'}


def test_the_digest_is_sha256_of_the_canonical_json():
    warnings = [{'id': 'ha_group_local', 'params': {'kind': 'local', 'members': 2}, 'text': 'x'},
                {'id': 'ha_resources', 'params': {'count': 3}, 'text': 'y'}]
    got = qnetd.plan_digest(_basis(), [VOTES], warnings)
    want = ('{"cluster_id":"c1","cluster_name":"pve","confirm_unverified_host":false,"install_packages":true,'
            '"items":[{"id":"votes","node":null,"params":{"after":3,"before":2},"where":"cluster"}],'
            '"missing_pkg":["pve2"],"nodes":["pve1","pve2"],"open_firewall":true,'
            '"qnetd":{"address":"192.0.2.50","id":"aaaaaaaaaaaa","kind":"ssh","port":5403,'
            '"ssh":{"host":"192.0.2.50","port":22,"user":"root"}},'
            '"replace_certificate":false,"sources":["10.0.0.1","10.0.0.2"],"stores":[],'
            '"warnings":["ha_group_local"]}')
    assert got == hashlib.sha256(want.encode()).hexdigest()
    assert qnetd.DIGEST_RE.match(got)
    # the text of an item is how it reads, not what it does
    assert got == qnetd.plan_digest(_basis(), [dict(VOTES, text='anders')], warnings)


def test_what_follows_from_an_option_is_in_the_digest_only_with_it():
    plain = qnetd.plan_digest(_basis(opts={}, sources=['10.0.0.1']))
    want = ('{"cluster_id":"c1","cluster_name":"pve","confirm_unverified_host":false,"install_packages":false,'
            '"items":[],"nodes":["pve1","pve2"],"open_firewall":false,'
            '"qnetd":{"address":"192.0.2.50","id":"aaaaaaaaaaaa","kind":"ssh","port":5403,'
            '"ssh":{"host":"192.0.2.50","port":22,"user":"root"}},'
            '"replace_certificate":false,"stores":[],"warnings":[]}')
    assert plain == hashlib.sha256(want.encode()).hexdigest()
    # so a node that lost its package or a new address changes nothing the admin did not ask for
    assert plain == qnetd.plan_digest(_basis(opts={}, missing=[], sources=['10.9.9.9']))
    # an option that is not exactly true is false
    assert plain == qnetd.plan_digest(_basis(opts={'install_packages': 'yes', 'open_firewall': 1},
                                             sources=['10.0.0.1']))
    # a QNetd host on this machine or in the sidecar has no SSH login to name
    local = json.loads(json.dumps(_basis(rec=dict(REC, kind='local', ssh_host='x', ssh_user='y'))))
    assert local['qnetd'] == {'address': '192.0.2.50', 'id': 'aaaaaaaaaaaa', 'kind': 'local', 'port': 5403}


@pytest.mark.parametrize('change', [
    {'cid': 'c2'}, {'name': 'pve2'}, {'nodes': ['pve1', 'pve2', 'pve3']}, {'missing': ['pve1', 'pve2']},
    {'sources': ['10.0.0.1', '10.0.0.3']}, {'rec': dict(REC, id='bbbbbbbbbbbb')}, {'rec': dict(REC, kind='local')},
    {'rec': dict(REC, address='192.0.2.51')}, {'rec': dict(REC, port=5404)},
    # the machine the helper, the packages and the firewall rules go to
    {'rec': dict(REC, ssh_host='198.51.100.99')}, {'rec': dict(REC, ssh_port=2222)}, {'rec': dict(REC, ssh_user='ops')},
    {'stores': ['pve1']},
    {'opts': {'install_packages': True, 'open_firewall': False}},
    {'opts': {'install_packages': True, 'open_firewall': True, 'replace_certificate': True}},
    {'opts': {'install_packages': True, 'open_firewall': True, 'confirm_unverified_host': True}},
    {'items': []}, {'items': [VOTES, dict(VOTES, id='corosync_reload', params={})]},
    {'items': [dict(VOTES, params={'before': 4, 'after': 5})]}, {'items': [dict(VOTES, where='node')]},
    {'items': [dict(VOTES, node='pve1')]},
    {'warnings': [{'id': 'ha_group_local', 'params': {}, 'text': ''}]},
])
def test_everything_the_admin_agrees_to_changes_the_digest(change):
    change = dict(change)
    items, warnings = change.pop('items', [VOTES]), change.pop('warnings', [])
    assert qnetd.plan_digest(_basis(), [VOTES]) != qnetd.plan_digest(_basis(**change), items, warnings)


@pytest.mark.parametrize('wid', ['unverified_host', 'firewall_manual', 'ha_resources'])
def test_a_warning_another_part_covers_or_about_nothing_the_setup_does_leaves_the_digest(wid):
    """unverified_host has its own option, firewall_manual is about a firewall PegaProx does
    not change (the port check blocks anyway), ha_resources about guests the setup does not
    touch, read best-effort: a read that failed once must not void a consent."""
    assert qnetd.plan_digest(_basis(), [VOTES]) == qnetd.plan_digest(
        _basis(), [VOTES], [{'id': wid, 'params': {'count': 1}, 'text': ''}])


# --- the plan changes nothing ---------------------------------------------------------------

READ_ONLY_OPS = {'version', 'status', 'ca', 'uuid'}


def _node_scripts_read_only(world):
    for node, script, data in world.cluster.all_calls():
        assert data is None, (node, script)
        assert (script.startswith('q() {') or script == qnetd.SOURCES_SCRIPT or script == qnetd.conf_read_script()
                or script.startswith('grep -r -l')), (node, script[:60])


def _helper_read_only(world):
    for op, name, data in world.helper.calls:
        if op == 'firewall':
            assert data == {'action': 'inspect'}, data
        else:
            assert op in READ_ONLY_OPS, op


@pytest.fixture
def no_writes(world, monkeypatch):
    """Anything that would change the QNetd host, a node or the pin fails the test."""
    monkeypatch.setattr(qnetd, 'check_host', lambda *a, **k: pytest.fail('check_host from a plan'))
    monkeypatch.setattr(qnetd.SshTransport, 'install_helper', lambda *a, **k: pytest.fail('helper installed'))
    monkeypatch.setattr(world.db, 'set_qnetd_ca_pin', lambda *a, **k: pytest.fail('CA pinned by a plan'))
    monkeypatch.setattr(world.db, 'save_qnetd_attachment', lambda *a, **k: pytest.fail('attached by a plan'))
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    return world


@pytest.mark.parametrize('state', ['ready', 'no_helper', 'outdated', 'no_qnetd', 'firewall', 'packages'])
def test_the_plan_reads_and_changes_nothing(no_writes, state):
    world = no_writes
    opts = {'install_packages': True, 'open_firewall': True, 'replace_certificate': True}
    if state == 'no_helper':
        world.helper.answers['version'] = qnetd.HelperError('the helper did not run (exit 127)', 'no_helper')
    elif state == 'outdated':
        world.helper.answers['version'] = dict(world.helper.answers['version'], protocol=1)
    elif state == 'no_qnetd':
        world.helper.answers['version'] = dict(world.helper.answers['version'], qnetd_installed=False)
        world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
        world.helper.answers['ca'] = {'ok': False, 'code': 'not_initialised', 'error': 'no CA yet'}
    elif state == 'firewall':
        world.helper.answers['firewall'] = FakeFirewall()
        world.cluster.port['pve1'] = False
    else:
        world.cluster.pkg['pve2'] = False
    got = qnetd.plan('c1', world.mgr, world.rec(), opts)
    assert got['plan']['items'], got
    _helper_read_only(world)
    _node_scripts_read_only(world)
    assert world.rec()['ca_sha256'] == ''
    fw = world.helper.answers['firewall']
    assert all(d['action'] == 'inspect' for _n, d in fw.calls) and fw.rules in ({}, {'pve': []})
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []
    assert qnetd.jobs() == []


def test_the_plan_route_changes_nothing_either(env, no_writes):
    r = env.admin.get('/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa&install_packages=1&open_firewall=1')
    assert r.status_code == 200, r.data
    _helper_read_only(no_writes)
    _node_scripts_read_only(no_writes)
    assert env.launched == [] and qnetd.jobs() == []


# --- what the plan says --------------------------------------------------------------------

def _ids(got):
    return [i['id'] for i in got['plan']['items']]


def _item(got, iid):
    return next(i for i in got['plan']['items'] if i['id'] == iid)


def test_a_plan_answers_in_the_shape_of_the_contract(world):
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert set(got) == {'ok', 'preflight', 'plan', 'firewall', 'warnings'}
    assert got['ok'] is True and got['preflight']['ok'] is True
    assert set(got['plan']) == {'digest', 'items'} and qnetd.DIGEST_RE.match(got['plan']['digest'])
    assert _ids(got) == ['node_certs', 'corosync_conf', 'qdevice_service', 'corosync_reload', 'votes']
    for it in got['plan']['items']:
        assert set(it) == {'id', 'where', 'node', 'params', 'text'}
        assert it['where'] in ('qnetd', 'node', 'cluster') and it['text'] and isinstance(it['params'], dict)
    assert _item(got, 'votes')['params'] == {'before': 2, 'after': 3}
    assert _item(got, 'corosync_conf')['params'] == {'address': '192.0.2.50', 'port': 5403}
    assert _item(got, 'qdevice_service')['params'] == {'nodes': ['pve1', 'pve2']}
    # the backend is read even when nobody asked to open the port: the wizard picks its default
    assert got['firewall'] == {'requested': False, 'backend': 'none', 'managed': False, 'blocking': False,
                               'port': 5403, 'sources': ['10.0.0.1', '10.0.0.2'], 'manual': ''}
    assert got['warnings'] == []
    assert [n['source_address'] for n in got['preflight']['nodes']] == ['10.0.0.1', '10.0.0.2']
    # the digest is the one of the facts the plan read, and of the very items it lists
    basis = qnetd.plan_basis('c1', 'pve', ['pve1', 'pve2'], [], world.rec(), {}, [], [])
    assert got['plan']['digest'] == qnetd.plan_digest(basis, got['plan']['items'], got['warnings'])


def test_the_options_add_their_items(world):
    world.cluster.pkg['pve2'] = False
    world.cluster.store['pve1'] = True
    # an earlier setup of this name left its certificate on the QNetd host
    world.helper.answers['status'] = dict(world.helper.answers['status'], certificates=['pve'])
    got = qnetd.plan('c1', world.mgr, world.rec(), {'install_packages': True, 'replace_certificate': True})
    assert got['ok'] is True
    assert _item(got, 'node_packages')['params'] == {'nodes': ['pve2']}
    assert _item(got, 'node_store_reset')['params'] == {'nodes': ['pve1']}
    assert _item(got, 'cert_replace') == {'id': 'cert_replace', 'where': 'qnetd', 'node': None,
                                          'params': {'cluster_name': 'pve'},
                                          'text': 'Replace the certificate the QNetd host holds for a cluster '
                                                  'named pve'}


def test_a_qnetd_host_without_corosync_qnetd_is_set_up_by_the_run(world):
    world.helper.answers['version'] = dict(world.helper.answers['version'], qnetd_installed=False,
                                           certutil_installed=False, package_manager='zypper')
    world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    world.helper.answers['ca'] = {'ok': False, 'code': 'not_initialised', 'error': 'no CA yet'}
    for n in world.cluster.nodes:
        world.cluster.port[n] = False          # nothing listens yet
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is True, got['preflight']['checks']
    assert _ids(got)[:4] == ['qnetd_packages', 'qnetd_ca', 'qnetd_tls', 'qnetd_start']
    assert _item(got, 'qnetd_packages')['params'] == {'package_manager': 'zypper',
                                                      'packages': ['corosync-qnetd', 'mozilla-nss-tools']}
    port = next(c for c in got['preflight']['checks'] if c['id'] == 'qnetd_port')
    assert port['ok'] is None and port['deferred'] is True and port['blocking'] is False
    # the preflight of the same host still fails: Check or the run has to set it up first
    assert qnetd.inspect('c1', world.mgr, world.rec())['ok'] is False


def test_no_known_package_manager_blocks_the_plan(world):
    world.helper.answers['version'] = dict(world.helper.answers['version'], qnetd_installed=False,
                                           package_manager=None)
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is False
    assert 'package manager' in next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'qnetd_ready')


@pytest.mark.parametrize('version,item', [
    (qnetd.HelperError('the helper did not run on the QNetd host (exit 127)', 'no_helper'), 'qnetd_helper_install'),
    ({'ok': True, 'protocol': 1, 'qnetd_installed': True, 'certutil_installed': True}, 'qnetd_helper_update'),
])
def test_an_ssh_host_without_a_current_helper_gets_it_from_the_run(world, monkeypatch, version, item):
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    asked = []
    world.helper.install_problem = lambda: asked.append(1) or ''
    world.helper.answers['version'] = version
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is True, got['preflight']['checks']
    assert _ids(got)[0] == item and asked == [1]
    assert _item(got, 'qnetd_packages')['params']['if_needed'] is True
    # what only the helper can tell is checked by the run, after it put the helper there
    checks = {c['id']: c for c in got['preflight']['checks']}
    for cid_ in ('name_unique', 'not_own_vm'):
        assert checks[cid_]['ok'] is None and checks[cid_]['deferred'] is True
    assert got['preflight']['needs_confirmation'] is False
    fwi = _item(got, 'firewall_open')
    assert fwi['params'] == {'backend': None, 'port': 5403, 'sources': ['10.0.0.1', '10.0.0.2']}
    assert got['firewall']['requested'] is True and got['firewall']['backend'] is None


@pytest.mark.parametrize('problem,copy', [
    ('the SSH user can neither log in as root nor sudo without a password: install the helper by hand', HELPER_COPY),
    ('', (None, 0)),
    ('', (b'#!/usr/bin/python3\nPROTOCOL = 1\n', 1)),
])
def test_a_helper_the_run_cannot_install_blocks_the_plan(world, monkeypatch, problem, copy):
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: copy)
    world.helper.install_problem = lambda: problem
    world.helper.answers['version'] = qnetd.HelperError('the helper did not run (exit 127)', 'no_helper')
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is False
    msg = next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'qnetd_ready')
    assert (problem or 'no helper of protocol') in msg


def test_a_failed_login_is_no_missing_helper(world):
    # only "the login worked and no helper answered" is something the run fixes
    world.helper.answers['version'] = qnetd.HelperError('the QNetd host refused the SSH login')
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is False and 'qnetd_helper_install' not in _ids(got)


@pytest.mark.parametrize('kind', ['local', 'sidecar'])
def test_a_local_or_sidecar_helper_of_protocol_1_fails_the_plan_clearly(world, monkeypatch, kind):
    world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), kind=kind, ssh_host='', ssh_user=''))
    world.helper.answers['version'] = {'ok': True, 'protocol': 1, 'qnetd_installed': True, 'certutil_installed': True}
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is False
    msg = next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'qnetd_ready')
    assert 'outdated' in msg
    if kind == 'local':
        # local mode stays as it is: the admin runs install.sh once more, PegaProx installs nothing
        assert 're-run packaging/qnetd/install.sh' in msg
    assert not any(i.startswith('qnetd_helper') for i in _ids(got))


def test_a_closed_port_is_opened_by_the_run_on_a_firewall_the_helper_changes(world):
    world.helper.answers['firewall'] = FakeFirewall('firewalld')
    world.cluster.port['pve2'] = False
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is True, got['preflight']['checks']
    it = _item(got, 'firewall_open')
    assert it['where'] == 'qnetd' and it['params'] == {'backend': 'firewalld', 'port': 5403,
                                                        'sources': ['10.0.0.1', '10.0.0.2']}
    assert '10.0.0.1, 10.0.0.2' in it['text']
    assert got['firewall'] == {'requested': True, 'backend': 'firewalld', 'managed': True, 'blocking': True,
                               'port': 5403, 'sources': ['10.0.0.1', '10.0.0.2'], 'manual': ''}
    port = next(c for c in got['preflight']['checks'] if c['id'] == 'qnetd_port')
    assert port['deferred'] is True
    # the helper was asked for this cluster's rules, by its name
    assert world.helper.answers['firewall'].calls == [('pve', {'action': 'inspect'})]


def test_without_the_option_a_closed_port_blocks_and_says_what_would_help(world):
    world.helper.answers['firewall'] = FakeFirewall('ufw')
    world.cluster.port['pve2'] = False
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is False and 'firewall_open' not in _ids(got)
    msg = next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'qnetd_port')
    assert 'pve2' in msg and 'ufw' in msg
    assert got['firewall']['requested'] is False and got['firewall']['managed'] is True


@pytest.mark.parametrize('backend', ['nftables', 'iptables', 'pve-firewall'])
def test_a_firewall_the_helper_does_not_change_is_left_to_the_admin(world, backend):
    world.helper.answers['firewall'] = FakeFirewall(backend, managed=False, blocking=True)
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is False and 'firewall_open' not in _ids(got)
    assert _checks(got['preflight'])['firewall'] is False
    warn = next(w for w in got['warnings'] if w['id'] == 'firewall_manual')
    assert warn['params']['backend'] == backend
    for src in ('10.0.0.1', '10.0.0.2'):
        assert src in warn['params']['manual'] and src in got['firewall']['manual']
    # the same without the option: the warning, and nothing that blocks for it
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['ok'] is True and any(w['id'] == 'firewall_manual' for w in got['warnings'])


def test_the_helper_lines_for_a_firewall_win_over_ours(world):
    world.helper.answers['firewall'] = FakeFirewall('nftables', managed=False, blocking=None,
                                                    manual='nft add rule inet pve input tcp dport 5403 accept')
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert got['firewall']['manual'] == 'nft add rule inet pve input tcp dport 5403 accept'


HELPER_LINES = '\n'.join([
    'nft insert rule inet filter input ip saddr <node address> tcp dport 5403 accept',
    'nft insert rule ip legacy input ip saddr <node address> tcp dport 5403 accept',
    '# ip6 saddr for a node with an IPv6 address',
    '# and the same in the nftables configuration (/etc/nftables.conf), or it is gone after a reboot',
    'iptables -I INPUT -p tcp -s <node address> --dport 5403 -j ACCEPT',
    'ip6tables -I INPUT -p tcp -s <node address> --dport 5403 -j ACCEPT',
])


def test_the_helper_lines_are_filled_in_with_the_node_addresses():
    got = qnetd.expand_manual(HELPER_LINES, ['10.0.0.1', '2001:db8::12']).splitlines()
    assert got == [
        'nft insert rule inet filter input ip saddr 10.0.0.1 tcp dport 5403 accept',
        'nft insert rule inet filter input ip6 saddr 2001:db8::12 tcp dport 5403 accept',
        # an ip table takes no IPv6 address
        'nft insert rule ip legacy input ip saddr 10.0.0.1 tcp dport 5403 accept',
        '# and the same in the nftables configuration (/etc/nftables.conf), or it is gone after a reboot',
        'iptables -I INPUT -p tcp -s 10.0.0.1 --dport 5403 -j ACCEPT',
        'ip6tables -I INPUT -p tcp -s 2001:db8::12 --dport 5403 -j ACCEPT',
    ]
    pve = '# in /etc/pve/nodes/w1/host.fw, section [RULES]\nIN ACCEPT -source <node address> -p tcp -dport 5403'
    assert qnetd.expand_manual(pve, ['10.0.0.1', '10.0.0.2']).splitlines()[1:] == [
        'IN ACCEPT -source 10.0.0.1 -p tcp -dport 5403', 'IN ACCEPT -source 10.0.0.2 -p tcp -dport 5403']


def test_the_plan_shows_the_helper_lines_for_these_nodes(world):
    world.helper.answers['firewall'] = FakeFirewall('nftables', managed=False, blocking=True, manual=HELPER_LINES)
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert '<node address>' not in got['firewall']['manual']
    assert 'nft insert rule inet filter input ip saddr 10.0.0.2 tcp dport 5403 accept' in got['firewall']['manual']
    assert next(w for w in got['warnings'] if w['id'] == 'firewall_manual')['params']['manual'] == \
        got['firewall']['manual']


def test_the_package_list_of_the_helper_is_the_one_shown(world):
    world.helper.answers['version'] = dict(world.helper.answers['version'], qnetd_installed=False,
                                           package_manager='dnf', packages=['corosync-qnetd', 'nss-tools', 'x;y'])
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert _item(got, 'qnetd_packages')['params'] == {'package_manager': 'dnf',
                                                      'packages': ['corosync-qnetd', 'nss-tools']}


def test_no_blocking_firewall_needs_nothing_opened(world):
    world.helper.answers['firewall'] = FakeFirewall('ufw', blocking=False)
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is True and 'firewall_open' not in _ids(got)
    assert _checks(got['preflight'])['firewall'] is True


def test_a_node_whose_source_address_is_unknown_blocks_opening_the_port(world):
    world.helper.answers['firewall'] = FakeFirewall('ufw')
    world.cluster.src['pve2'] = ''
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is False and 'firewall_open' not in _ids(got)
    assert 'pve2' in next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'firewall')


def test_the_sidecar_opens_no_firewall(world):
    world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), kind='sidecar', ssh_host='', ssh_user=''))
    got = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert got['ok'] is False
    assert 'Docker' in next(c['message'] for c in got['preflight']['checks'] if c['id'] == 'firewall')
    # and nobody asks its helper about a firewall
    assert not [c for c in world.helper.calls if c[0] == 'firewall']


def test_the_warnings(world, monkeypatch):
    from pegaprox.core import ha
    world.helper.answers['uuid'] = {'ok': True, 'product_uuid': ''}
    world.mgr.get_proxmox_ha_resources.return_value = [
        {'sid': 'vm:100', 'state': 'started'}, {'sid': 'vm:101', 'state': 'disabled'}, {'sid': 'ct:102'}]
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert {w['id']: w['params'] for w in got['warnings']} == {'unverified_host': {}, 'ha_resources': {'count': 2}}
    assert got['ok'] is False and got['preflight']['needs_confirmation'] is True
    assert qnetd.plan('c1', world.mgr, world.rec(), {'confirm_unverified_host': True})['ok'] is True
    # an HA group: local and sidecar are one member's machine
    monkeypatch.setattr(ha, 'members', lambda: [{'instance_id': 'b'}])
    assert not [w for w in qnetd.plan('c1', world.mgr, world.rec(), {})['warnings'] if w['id'] == 'ha_group_local']
    world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), kind='local', ssh_host='', ssh_user=''))
    warn = next(w for w in qnetd.plan('c1', world.mgr, world.rec(), {})['warnings'] if w['id'] == 'ha_group_local')
    assert warn['params'] == {'kind': 'local', 'members': 2}


def test_unreadable_ha_resources_are_left_out(world):
    world.mgr.get_proxmox_ha_resources.side_effect = RuntimeError('500')
    assert not [w for w in qnetd.plan('c1', world.mgr, world.rec(), {})['warnings'] if w['id'] == 'ha_resources']


# --- a certificate an earlier setup left on the QNetd host ---------------------------------
# The helper keeps the certificate of a cluster when its QDevice goes. A new setup of a
# cluster of that name went through the QNetd host step, the firewall and half of the node
# steps before sign refused it (name_exists): the plan says so before the admin agrees.

def _held(world, names=('pve',)):
    world.helper.answers['status'] = dict(world.helper.answers['status'], certificates=list(names))


def _cert_check(got):
    return next((c for c in got['preflight']['checks'] if c['id'] == 'cert_on_file'), None)


def test_a_certificate_of_an_earlier_setup_blocks_the_plan(world):
    _held(world, ['other', 'PVE'])          # qnetd matches the name without regard to case
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    row = _cert_check(got)
    assert row['ok'] is False and row['blocking'] is True and 'deferred' not in row
    assert row['message'] == ('The QNetd host holds a certificate for a cluster named pve from an earlier setup. '
                              'Replacing it is only right when that cluster is this one, set up again, or one '
                              'that is gone')
    assert got['ok'] is False and got['preflight']['ok'] is False
    assert 'cert_replace' not in _ids(got)


def test_with_the_replace_it_passes_and_the_plan_lists_the_replacement(world):
    _held(world)
    plain = qnetd.plan('c1', world.mgr, world.rec(), {})
    got = qnetd.plan('c1', world.mgr, world.rec(), {'replace_certificate': True})
    row = _cert_check(got)
    assert row['ok'] is True and row['blocking'] is True and 'replaces the certificate' in row['message']
    assert got['ok'] is True
    assert _item(got, 'cert_replace')['params'] == {'cluster_name': 'pve'}
    # another plan to agree to than the one without it
    assert got['plan']['digest'] != plain['plan']['digest']


@pytest.mark.parametrize('how', ['older_helper', 'not_a_list', 'a_bad_name', 'cut_short', 'no_helper'])
def test_a_certificate_nobody_can_see_yet_is_left_to_the_run(world, monkeypatch, how):
    status = world.helper.answers['status']
    if how == 'older_helper':
        del status['certificates']          # protocol 2, from before status listed them
    elif how == 'not_a_list':
        status['certificates'] = 'pve'
    elif how == 'a_bad_name':
        status['certificates'] = ['lab', 'pve; id']
    elif how == 'cut_short':
        # as many names as the helper lists at most, pve not among them: it may be past the cut
        status['certificates'] = ['c%04d' % i for i in range(qnetd.CERTS_MAX)]
    else:
        monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
        world.helper.answers['version'] = qnetd.HelperError('the helper did not run (exit 127)', 'no_helper')
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    row = _cert_check(got)
    assert row['ok'] is None and row['blocking'] is False and row['deferred'] is True, row
    assert got['ok'] is True, got['preflight']['checks']
    # asked to, the run may replace what it finds: the plan lists it
    got = qnetd.plan('c1', world.mgr, world.rec(), {'replace_certificate': True})
    assert 'cert_replace' in _ids(got)


def test_no_certificate_of_the_name_no_check(world):
    for names in ([], ['other', 'pve2', 'pv']):
        _held(world, names)
        got = qnetd.plan('c1', world.mgr, world.rec(), {})
        assert _cert_check(got) is None and got['ok'] is True
        # nothing on file to replace: the option alone puts nothing into the plan
        assert 'cert_replace' not in _ids(qnetd.plan('c1', world.mgr, world.rec(), {'replace_certificate': True}))


def test_a_connected_cluster_of_the_name_stays_the_name_check_s_refusal(world):
    _held(world)
    world.helper.answers['status']['clusters'] = [{'name': 'pve', 'nodes': []}]
    got = qnetd.plan('c1', world.mgr, world.rec(), {'replace_certificate': True})
    assert _checks(got['preflight'])['name_unique'] is False and _cert_check(got) is None
    assert got['ok'] is False
    # and another cluster of PegaProx with that name: no replace is offered for its certificate
    world.helper.answers['status']['clusters'] = []
    world.db.save_qnetd_attachment('c2', 'aaaaaaaaaaaa', 'pve', 'admin')
    got = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert _checks(got['preflight'])['name_unique'] is False and _cert_check(got) is None


# --- the job holds the admin to the plan ------------------------------------------------------

def _nothing_changed(world, view):
    row = view['clusters']['c1']
    assert row['state'] == 'failed' and row['failed_step'] == 'plan' and row['rolled_back'] is None
    _helper_read_only(world)
    _node_scripts_read_only(world)
    assert not world.cluster.conf_written
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []


def _actions(world):
    return [a[0][1] for a in world.audits]


def test_a_node_added_since_the_plan_stops_the_job(world):
    opts = _agree(world)
    world.cluster.nodes += ['pve3', 'pve4']
    for n in ('pve3', 'pve4'):
        world.cluster.pkg[n] = world.cluster.port[n] = True
        world.cluster.store[n] = False
        world.cluster.src[n] = '10.0.0.9'
    world.helper.calls.clear()
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    row = view['clusters']['c1']
    assert row['code'] == 'plan_changed' and row['error'] == qnetd.PLAN_CHANGED
    assert 'qdevice.consent' not in _actions(world)


def test_a_package_gone_since_the_plan_stops_the_job(world):
    opts = _agree(world, {'install_packages': True})
    world.cluster.pkg['pve1'] = False
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'
    assert not [n for n, s, d in world.cluster.all_calls() if s == qnetd.APT_SCRIPT]


def test_a_new_source_address_since_the_plan_stops_the_job(world):
    fw = world.helper.answers['firewall'] = FakeFirewall('ufw')
    opts = _agree(world, {'open_firewall': True})
    world.cluster.src['pve2'] = '10.0.0.77'
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'
    assert fw.rules in ({}, {'pve': []}) and all(d['action'] == 'inspect' for _n, d in fw.calls)


def test_an_option_the_admin_did_not_agree_to_stops_the_job(world):
    opts = _agree(world)
    opts['replace_certificate'] = True
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'


def test_a_qnetd_host_to_set_up_since_the_plan_stops_the_job(world, monkeypatch):
    """The admin agreed to a plan with nothing to do on the QNetd host; since then its
    helper went and corosync-qnetd stopped. On that consent the run would copy a helper,
    install packages and start a service there as root, none of which the admin saw."""
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    monkeypatch.setattr(qnetd, 'check_host', lambda *a, **k: pytest.fail('the QNetd host was set up'))
    opts = _agree(world)
    world.helper.answers['version'] = qnetd.HelperError('the helper did not run (exit 127)', 'no_helper')
    world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    now = qnetd.plan('c1', world.mgr, world.rec(), {})
    assert {'qnetd_helper_install', 'qnetd_packages', 'qnetd_start'} <= set(_ids(now))
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'
    assert 'qdevice.consent' not in _actions(world)


def _ha_two(monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'members', lambda: [{'instance_id': 'b'}])


@pytest.mark.parametrize('change', ['store', 'firewall', 'ssh_host', 'ssh_port', 'ssh_user', 'ha_group'])
def test_what_the_plan_does_changed_since_the_agreement_stops_the_job(world, monkeypatch, change):
    opts = {'open_firewall': True} if change == 'firewall' else {}
    if change == 'ha_group':
        world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), kind='local', ssh_host='', ssh_user=''))
    fw = world.helper.answers['firewall']
    opts = _agree(world, opts)
    if change == 'store':
        world.cluster.store['pve1'] = True              # the run would rm -rf it
    elif change == 'firewall':
        # nothing to open when the admin agreed; now ufw blocks the port
        fw = world.helper.answers['firewall'] = FakeFirewall('ufw')
        world.cluster.port = {n: False for n in world.cluster.nodes}
    elif change == 'ha_group':
        _ha_two(monkeypatch)                             # the warning the admin never saw
    else:
        # another machine behind the record (what PUT /api/qnetd/hosts allows while nothing is attached)
        moved = {'ssh_host': '198.51.100.99', 'ssh_port': 2222, 'ssh_user': 'ops'}[change]
        world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), **{change: moved}))
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'
    assert all(d['action'] == 'inspect' for _n, d in fw.calls)
    assert not [n for n, s, d in world.cluster.all_calls() if s == qnetd.STORE_RESET_SCRIPT]


def test_a_count_of_ha_resources_that_moved_leaves_the_consent(world):
    world.mgr.get_proxmox_ha_resources.return_value = [{'sid': 'vm:100', 'state': 'started'}]
    opts = _agree(world)
    world.mgr.get_proxmox_ha_resources.side_effect = RuntimeError('500')
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']


@pytest.mark.parametrize('late', ['nodes', 'package', 'store'])
def test_what_changed_while_the_qnetd_host_was_set_up_stops_the_job_before_the_nodes(world, monkeypatch, late):
    """The plan step matched, then the QNetd host step ran for minutes: a node that joined
    (or lost corosync-qdevice) in that time is not one the admin agreed to."""
    opts = _agree(world, {'install_packages': True})
    real = qnetd.inspect

    def meanwhile(*a, **k):
        if not k.get('plan'):
            if late == 'nodes':
                world.cluster.nodes += ['pve3', 'pve4']
                for n in ('pve3', 'pve4'):
                    world.cluster.pkg[n] = world.cluster.port[n] = True
                    world.cluster.store[n] = False
                    world.cluster.src[n] = '10.0.0.9'
            elif late == 'package':
                world.cluster.pkg['pve2'] = False
            else:
                world.cluster.store['pve1'] = True      # the run would remove it, unseen
        return real(*a, **k)
    monkeypatch.setattr(qnetd, 'inspect', meanwhile)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'preflight' and row['code'] == 'plan_changed' and row['rolled_back'] is None
    _node_scripts_read_only(world)
    assert not any(op in ('init', 'sign') for op, *_ in world.helper.calls)


def test_an_option_that_is_not_exactly_true_does_not_act(world):
    """The job reads its options the way the digest does: 'yes' installs nothing."""
    world.cluster.pkg['pve2'] = False
    opts = _agree(world, {'install_packages': 'yes'})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['clusters']['c1']['failed_step'] == 'plan'
    assert not [n for n, s, d in world.cluster.all_calls() if s == qnetd.APT_SCRIPT]


@pytest.mark.parametrize('consents', [None, {}, {'c1': ''}, {'c1': 'x' * 64}, {'c1': DIGEST.upper()}, {'c2': DIGEST}])
def test_a_job_without_a_valid_consent_does_nothing(world, consents):
    opts = {} if consents is None else {'consents': consents}
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'consent_required'
    # not even the plan was read again
    assert world.helper.calls == [] and world.cluster.all_calls() == []


def test_a_matching_plan_is_audited_with_its_digest_and_items(world):
    opts = _agree(world)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'root', '198.51.100.20'), qnetd.run_setup,
                world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    consent = [a for a in world.audits if a[0][1] == 'qdevice.consent']
    assert len(consent) == 1
    (user, _action, text), kw = consent[0]
    assert user == 'root' and opts['consents']['c1'] in text and kw['cluster_id'] == 'c1'
    assert 'node_certs, corosync_conf, qdevice_service, corosync_reload, votes' in text
    assert _actions(world).index('qdevice.consent') < _actions(world).index('qdevice.setup')
    assert view['steps'][0]['step'] == 'plan'


def test_a_consent_to_the_plan_without_the_replace_never_replaces(world):
    """The plan without the replace does not pass where a certificate of the name is on file,
    and the replace asked for with the digest of that plan is another plan: neither gets a
    sign with replace, nor any other change."""
    _held(world)
    plain = _agree(world)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), plain)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'name_exists'
    assert 'earlier setup' in view['clusters']['c1']['error']
    sneaky = dict(plain, replace_certificate=True)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), sneaky)
    _nothing_changed(world, view)
    assert view['clusters']['c1']['code'] == 'plan_changed'
    assert not any(op in ('init', 'sign') for op, *_ in world.helper.calls)
    # agreed to with the replace in the plan, it goes through and signs with replace
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(),
                _agree(world, {'replace_certificate': True}))
    assert view['state'] == 'done', view['steps']
    assert [d['replace'] for op, _n, d in world.helper.calls if op == 'sign'] == [True]


def test_the_replace_option_alone_replaces_nothing(world):
    """Nothing on file when the plan was read: no replacement in it, and the sign asks for
    none. A certificate that turned up since is sign's to refuse."""
    _held(world, [])
    opts = _agree(world, {'replace_certificate': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert [d['replace'] for op, _n, d in world.helper.calls if op == 'sign'] == [False]


@pytest.mark.parametrize('replace', [False, True])
def test_a_certificate_the_plan_could_not_see_stops_the_run_before_any_node(world, monkeypatch, replace):
    """The helper was outdated when the plan was read: the run updates it, and its preflight
    finds the certificate then, before a node is touched (not at sign, half way through)."""
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    current = world.helper.answers['version']
    world.helper.answers['version'] = dict(current, protocol=1)
    opts = _agree(world, {'replace_certificate': replace})

    def check_host(rec, init=True, upgrade=True):
        world.helper.answers['version'] = current
        _held(world)
        return {'ok': True, 'helper_installed': True}
    monkeypatch.setattr(qnetd, 'check_host', check_host)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    if replace:
        # the plan agreed to listed the replacement where nobody could tell yet
        assert view['state'] == 'done', view['steps']
        assert [d['replace'] for op, _n, d in world.helper.calls if op == 'sign'] == [True]
        return
    assert row['failed_step'] == 'preflight' and row['code'] == 'name_exists' and row['rolled_back'] is None
    assert 'earlier setup' in row['error']
    _node_scripts_read_only(world)
    assert not any(op in ('init', 'sign') for op, *_ in world.helper.calls)


# --- the routes -----------------------------------------------------------------------------

@pytest.fixture
def app(env, world):
    """The real routes on the fake cluster and QNetd host of the core tests."""
    return env


def test_the_plan_route_answers_the_core_plan(app, world):
    r = app.admin.get('/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa&install_packages=1'
                      '&open_firewall=true&replace_certificate=0')
    assert r.status_code == 200, r.data
    body = r.get_json()
    direct = qnetd.plan('c1', world.mgr, world.rec(), {'install_packages': True, 'open_firewall': True})
    assert body['plan']['digest'] == direct['plan']['digest']
    assert body['firewall']['requested'] is True
    assert app.admin.get('/api/clusters/c1/qdevice/plan?qnetd_id=nope').status_code == 404
    assert app.admin.get('/api/clusters/zz/qdevice/plan?qnetd_id=aaaaaaaaaaaa').status_code == 404


def test_a_plan_from_the_route_starts_a_setup_the_job_accepts(app, world):
    got = app.admin.get('/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa').get_json()
    r = app.admin.post('/api/clusters/c1/qdevice/setup', json={
        'qnetd_id': 'aaaaaaaaaaaa', 'consent': {'accepted': True, 'digest': got['plan']['digest']}})
    assert r.status_code == 202, r.data
    job, fn, args = app.launched[0]
    qnetd._release(job)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'root', ''), fn, *args)
    assert view['state'] == 'done', view['steps']


BAD_CONSENTS = [None, 'yes', [], {}, {'accepted': True}, {'digest': DIGEST}, {'accepted': False, 'digest': DIGEST},
                {'accepted': 'true', 'digest': DIGEST}, {'accepted': 1, 'digest': DIGEST},
                {'accepted': True, 'digest': DIGEST[:63]}, {'accepted': True, 'digest': DIGEST + 'a'},
                {'accepted': True, 'digest': DIGEST.upper()}, {'accepted': True, 'digest': 'g' * 64},
                {'accepted': True, 'digest': int('1' * 20)}, {'accepted': True, 'digest': None}]


@pytest.mark.parametrize('consent', BAD_CONSENTS)
def test_a_setup_without_a_consent_is_refused_before_any_job(app, consent):
    body = {'qnetd_id': 'aaaaaaaaaaaa'}
    if consent is not None:
        body['consent'] = consent
    r = app.admin.post('/api/clusters/c1/qdevice/setup', json=body)
    assert r.status_code == 400 and r.get_json()['code'] == 'consent_required', r.data
    assert app.launched == [] and qnetd.jobs() == [] and qnetd.busy_with('c1') is None


@pytest.mark.parametrize('consents,named', [
    (None, 'c1'), ('x', 'c1'), ([DIGEST], 'c1'), ({}, 'c1'), ({'c1': DIGEST}, 'c2'), ({'c2': DIGEST}, 'c1'),
    ({'c1': DIGEST, 'c2': 'nope'}, 'c2'), ({'c1': DIGEST, 'c2': DIGEST, 'c3': DIGEST}, 'c3'),
    ({'c1': DIGEST, 'c2': {'accepted': True, 'digest': DIGEST}}, 'c2'),
])
def test_a_bulk_setup_needs_one_consent_per_cluster_and_no_other(app, world, consents, named):
    from pegaprox.globals import cluster_managers
    cluster_managers['c2'] = world.mgr
    try:
        body = {'cluster_ids': ['c1', 'c2']}
        if consents is not None:
            body['consents'] = consents
        r = app.admin.post('/api/qnetd/hosts/aaaaaaaaaaaa/bulk-setup', json=body)
        assert r.status_code == 400, r.data
        assert r.get_json()['code'] == 'consent_required' and r.get_json()['cluster_id'] == named
        assert app.launched == [] and qnetd.jobs() == []
        r = app.admin.post('/api/qnetd/hosts/aaaaaaaaaaaa/bulk-setup',
                           json={'cluster_ids': ['c1', 'c2'], 'consents': {'c1': DIGEST, 'c2': 'cd' * 32}})
        assert r.status_code == 202, r.data
        assert app.launched[0][2][1]['consents'] == {'c1': DIGEST, 'c2': 'cd' * 32}
    finally:
        cluster_managers.pop('c2', None)


def test_who_may_not_read_a_plan_or_start_a_setup(app):
    lowered = app.api.as_user(app.seed.user('ladmin', role='admin', tenant_permissions={'default': {'role': 'user'}}))
    ops = app.api.as_user(app.seed.user('ops', role='user', permissions=[
        'cluster.config', 'node.shell', 'node.update', 'admin.settings', 'node.view']))
    app.seed.pool('c1', 'pool1', 'pooly', ['vm.view', 'vm.config', 'node.shell', 'cluster.config'])
    pooly = app.api.as_user(app.seed.user('pooly', role='user', permissions=['cluster.config', 'node.shell']))
    for client in (lowered, ops, pooly):
        assert client.get('/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa').status_code == 403
        assert client.post('/api/clusters/c1/qdevice/setup', json={
            'qnetd_id': 'aaaaaaaaaaaa', 'consent': CONSENT}).status_code == 403
        assert client.post('/api/qnetd/hosts/aaaaaaaaaaaa/bulk-setup', json={
            'cluster_ids': ['c1'], 'consents': {'c1': DIGEST}}).status_code == 403
    assert app.launched == []


def test_a_setup_without_the_xhr_header_is_refused(app):
    raw = app.api.app.test_client()
    r = raw.post('/api/clusters/c1/qdevice/setup', json={'qnetd_id': 'aaaaaaaaaaaa', 'consent': CONSENT},
                 headers={'X-Session-ID': app.admin.session_id}, base_url='http://localhost')
    assert r.status_code == 403
    r = raw.post('/api/qnetd/hosts/aaaaaaaaaaaa/bulk-setup', json={'cluster_ids': ['c1'], 'consents': {'c1': DIGEST}},
                 headers={'X-Session-ID': app.admin.session_id}, base_url='http://localhost')
    assert r.status_code == 403
    assert app.launched == []


def test_a_standby_reads_no_plan(app, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwards_read', lambda rule, view_args=None: False)
    monkeypatch.setattr(qnetd, 'plan', lambda *a, **k: pytest.fail('read the plan on a standby'))
    assert app.admin.get('/api/clusters/c1/qdevice/plan?qnetd_id=aaaaaaaaaaaa').status_code == 503


def test_a_job_on_an_instance_that_turned_standby_reads_no_plan(world, monkeypatch):
    from pegaprox.core import ha
    opts = _agree(world)
    world.helper.calls.clear()
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['clusters']['c1']['failed_step'] == 'plan' and world.helper.calls == []


def test_the_hosts_list_says_how_many_instances_there_are(app, monkeypatch):
    from pegaprox.core import ha
    assert app.admin.get('/api/qnetd/hosts').get_json()['ha_members'] == 1
    monkeypatch.setattr(ha, 'members', lambda: [{'instance_id': 'b'}, {'instance_id': 'c'}])
    assert app.admin.get('/api/qnetd/hosts').get_json()['ha_members'] == 3


# --- the node source address ------------------------------------------------------------------

FAKE_IP = r'''#!/bin/sh
# ip -o route get <address>
case "$4" in
  192.0.2.50) echo '192.0.2.50 via 10.0.0.254 dev vmbr0 src 10.0.0.11 uid 0 \    cache' ;;
  2001:db8::50) echo '2001:db8::50 from :: via fe80::1 dev vmbr0 proto ra src 2001:db8::11 metric 1024 pref medium' ;;
  198.51.100.9) echo "198.51.100.9 dev eth9 src $(printf 'x%.0s' $(seq 1 300)) uid 0" ;;
  *) echo 'RTNETLINK answers: Network is unreachable' >&2; exit 2 ;;
esac
'''
FAKE_GETENT = r'''#!/bin/sh
case "$2" in
  qnetd.example) printf '2001:db8::99    STREAM qnetd.example\n2001:db8::99    DGRAM\n192.0.2.50      STREAM\n' ;;
  192.0.2.50|2001:db8::50|198.51.100.9) printf '%s    STREAM %s\n' "$2" "$2" ;;
  *) exit 2 ;;
esac
'''
NEEDS = all(shutil.which(t) for t in ('bash', 'awk', 'head', 'timeout', 'seq'))


def _source(tmp_path, host):
    d = tmp_path / 'bin'
    d.mkdir(exist_ok=True)
    for name, text in (('ip', FAKE_IP), ('getent', FAKE_GETENT)):
        (d / name).write_text(text)
        (d / name).chmod(0o755)
    p = subprocess.run(['bash', '-c', qnetd.probe_script(host, 5403)], capture_output=True, text=True, timeout=60,
                       env={'PATH': f'{d}:/usr/bin:/bin'}, cwd=str(tmp_path))
    assert p.returncode == 0, p.stderr
    raw = qnetd._kv(p.stdout).get('src')
    return raw, qnetd.clean_source(raw)


@pytest.mark.skipif(not NEEDS, reason='bash, awk, head, timeout or seq missing')
@pytest.mark.parametrize('host,want', [
    ('192.0.2.50', '10.0.0.11'),
    ('2001:db8::50', '2001:db8::11'),
    # the first address of the name without a route is passed over, as a connect would
    ('qnetd.example', '10.0.0.11'),
    ('nowhere.example', None),
])
def test_the_probe_reports_the_address_a_node_sends_from(tmp_path, monkeypatch, host, want):
    monkeypatch.setattr(qnetd, 'clean_address', lambda v: v)
    assert _source(tmp_path, host)[1] == want


@pytest.mark.skipif(not NEEDS, reason='bash, awk, head, timeout or seq missing')
def test_a_long_source_answer_is_cut_and_refused(tmp_path):
    raw, clean = _source(tmp_path, '198.51.100.9')
    assert len(raw) <= 64 and clean is None


@pytest.mark.skipif(not NEEDS, reason='bash, awk, head, timeout or seq missing')
def test_the_source_probe_takes_the_host_as_data(tmp_path, monkeypatch):
    canary = tmp_path / 'pwned'
    monkeypatch.setattr(qnetd, 'clean_address', lambda v: v)
    for hostile in (f'$(touch {canary})', f'`touch {canary}`', f"x'; touch {canary}; '", f'a\ntouch {canary}'):
        assert _source(tmp_path, hostile)[1] is None
    assert not canary.exists()


def test_the_host_reaches_the_probe_quoted():
    import shlex
    script = qnetd.probe_script("it's.example", 5403)
    # the program of the inner bash is fixed text; the host is its positional argument
    host = shlex.quote("it's.example")
    assert f"bash -c {shlex.quote(qnetd._SOURCE_PROBE)} _ {host} 2>/dev/null" in script
    assert '$1' in qnetd._SOURCE_PROBE and 'example' not in qnetd._SOURCE_PROBE


@pytest.mark.parametrize('value,want', [
    ('10.0.0.1', '10.0.0.1'), (' 10.0.0.1 ', '10.0.0.1'), ('2001:DB8::1', '2001:db8::1'),
    ('::ffff:10.0.0.1', '10.0.0.1'), ('169.254.1.1', '169.254.1.1'),
    ('127.0.0.1', None), ('::1', None), ('0.0.0.0', None), ('::', None), ('224.0.0.1', None), ('ff02::1', None),
    ('10.0.0.0/24', None), ('fe80::1%eth0', None), ('qnetd.example', None), ('', None), (None, None), (7, None),
    ('1' * 80, None),
])
def test_a_source_is_one_address(value, want):
    assert qnetd.clean_source(value) == want


# --- the firewall request PegaProx sends ---------------------------------------------------

@pytest.mark.parametrize('data', [
    None, {}, {'action': 'open'}, {'action': 'allow'}, {'action': 'allow', 'sources': []},
    {'action': 'allow', 'sources': ['10.0.0.0/24']}, {'action': 'allow', 'sources': ['qnetd.example']},
    {'action': 'allow', 'sources': ['127.0.0.1']}, {'action': 'allow', 'sources': '10.0.0.1'},
    {'action': 'allow', 'sources': [f'10.0.{i // 250}.{i % 250 + 1}' for i in range(65)]},
    {'action': 'inspect', 'sources': ['10.0.0.1']}, {'action': 'remove', 'sources': []},
    {'action': 'allow', 'sources': ['10.0.0.1'], 'port': 22}, {'action': 'inspect', 'port': 22},
    {'action': ['allow']},
])
def test_a_firewall_request_outside_the_protocol_is_never_sent(data):
    with pytest.raises(qnetd.HelperError):
        qnetd._request('firewall', 'pve', data)


def test_a_firewall_request_needs_a_cluster_name_and_carries_no_port():
    with pytest.raises(qnetd.HelperError):
        qnetd._request('firewall', None, {'action': 'inspect'})
    with pytest.raises(qnetd.HelperError):
        qnetd._request('firewall', 'pve;id', {'action': 'inspect'})
    assert qnetd._request('firewall', 'pve', {'action': 'inspect'}) == {'action': 'inspect'}
    assert qnetd._request('firewall', 'pve', {'action': 'remove'}) == {'action': 'remove'}
    assert qnetd._request('firewall', 'pve', {'action': 'allow', 'sources': ['10.0.0.2', '::ffff:10.0.0.1',
                                                                             '10.0.0.2']}) == \
        {'action': 'allow', 'sources': ['10.0.0.1', '10.0.0.2']}
    # the other ops take no firewall data, and sign keeps its own
    with pytest.raises(qnetd.HelperError):
        qnetd._request('status', None, {'action': 'allow', 'sources': ['10.0.0.1']})


def test_the_version_answer_names_its_ops_and_package_manager():
    info = qnetd._version_info({'ok': True, 'protocol': 2, 'ops': ['version', 'firewall', 'x;y', 7],
                                'package_manager': 'dnf'})
    assert info['ops'] == ['version', 'firewall'] and info['firewall_op'] is True and info['package_manager'] == 'dnf'
    info = qnetd._version_info({'ok': True, 'protocol': 2, 'ops': 'firewall', 'package_manager': 'pacman'})
    assert info['ops'] == [] and info['firewall_op'] is False and info['package_manager'] is None
    assert qnetd.PROTOCOL == 2 and 'firewall' in qnetd.OPS


def test_the_plan_route_is_described_as_admin_only():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'docs', 'openapi.json'),
              encoding='utf-8') as fh:
        doc = json.load(fh)
    op = doc['paths']['/api/clusters/{cluster_id}/qdevice/plan']['get']
    assert op['x-pegaprox-roles'] == ['admin']
