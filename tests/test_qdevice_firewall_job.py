"""The setup job's QNetd host and firewall steps, and the firewall cleanup of a removal.

  plan -> qnetd_host (check_host with init and upgrade, only when the plan has a qnetd_*
  item, once per run) -> firewall (helper firewall allow for the nodes' source addresses,
  then the port is tried from every node again) -> preflight -> the setup steps.

A failed cluster loses exactly the firewall rules its job added; a removal asks the helper
to drop the rules of the cluster's name and stands when that fails. The helper's firewall
is a stand-in rule table (FakeFirewall), and the nodes reach the QNetd port only where it
lets them through.
MK Oct 2026
"""
import types
from unittest.mock import MagicMock

import pytest

from pegaprox.core import qnetd

from test_qnetd_core import FakeCluster, FakeFirewall, FakeHelper, FakeShell, _agree, _run, world  # noqa: F401

HELPER_COPY = (b'#!/usr/bin/python3 -I\nPROTOCOL = 2\n', 2)


@pytest.fixture(autouse=True)
def _clean():
    qnetd.reset_for_tests()
    yield
    qnetd.reset_for_tests()


class _Reach(dict):
    """port[node] of a FakeCluster: open exactly when the firewall lets the node's address in."""

    def __init__(self, cluster, fw, closed_on_the_way=()):
        super().__init__()
        self.cluster, self.fw, self.cut = cluster, fw, set(closed_on_the_way)

    def __getitem__(self, node):
        return node not in self.cut and self.fw.allowed(self.cluster.src[node])

    def __setitem__(self, node, value):
        pass


def _firewalled(world, backend='ufw', **kw):
    fw = world.helper.answers['firewall'] = FakeFirewall(backend, **kw)
    world.cluster.port = _Reach(world.cluster, fw)
    return fw


def _steps(view, state='ok'):
    return [s['step'] for s in view['steps'] if s['state'] == state]


def _changed_nodes(world):
    """The node scripts beyond the read-only ones of a plan or a preflight."""
    return [s for _n, s, _d in world.cluster.all_calls()
            if not (s.startswith('q() {') or s == qnetd.SOURCES_SCRIPT or s == qnetd.conf_read_script()
                    or s.startswith('grep -r -l'))]


# --- firewall step -------------------------------------------------------------------------

def test_the_run_opens_the_port_for_the_nodes_and_tries_it_from_each(world):
    fw = _firewalled(world)
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert _steps(view)[:4] == ['plan', 'firewall', 'firewall', 'preflight']
    allow = [d for _n, d in fw.calls if d['action'] == 'allow']
    assert allow == [{'action': 'allow', 'sources': ['10.0.0.1', '10.0.0.2']}]
    assert [n for n, _d in fw.calls] == ['pve'] * len(fw.calls)            # the cluster's name is the tag
    assert fw.rules['pve'] == ['10.0.0.1', '10.0.0.2']
    ok = [s['message'] for s in view['steps'] if s['step'] == 'firewall' and s['state'] == 'ok']
    assert 'ufw: port 5403 opened for 10.0.0.1, 10.0.0.2' in ok[0] and 'Every node reaches' in ok[1]
    assert world.db.list_qnetd_attachments(cluster_id='c1')


def test_a_rule_somebody_else_made_is_not_taken_over(world):
    fw = _firewalled(world)
    fw.foreign.add('10.0.0.1')
    world.cluster.fail['start'] = 1
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'qdevice_start' and row['rolled_back'] is True
    # added: only 10.0.0.2; the rollback takes out exactly that one, the admin's rule stays
    remove = [d for _n, d in fw.calls if d['action'] == 'remove']
    assert remove == [{'action': 'remove', 'sources': ['10.0.0.2']}]
    assert fw.rules['pve'] == [] and '10.0.0.1' in fw.foreign


def test_a_preflight_that_fails_after_the_port_was_opened_closes_it_again(world, monkeypatch):
    fw = _firewalled(world)
    opts = _agree(world, {'open_firewall': True})
    real = qnetd.inspect

    def then_a_vm(*a, **k):
        if not k.get('plan'):
            world.cluster.vm_hit = '/etc/pve/nodes/pve2/qemu-server/104.conf\n'
        return real(*a, **k)
    monkeypatch.setattr(qnetd, 'inspect', then_a_vm)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'preflight' and row['rolled_back'] is True
    assert fw.rules['pve'] == []
    assert [d for _n, d in fw.calls if d['action'] == 'remove'] == [
        {'action': 'remove', 'sources': ['10.0.0.1', '10.0.0.2']}]
    assert _changed_nodes(world) == []


def test_a_port_still_closed_after_opening_it_stops_before_any_node_changes(world):
    fw = _firewalled(world)
    world.cluster.port.cut.add('pve2')         # another firewall on the way
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'firewall' and 'still not reachable from: pve2' in row['error']
    assert row['rolled_back'] is True and fw.rules['pve'] == []
    assert _changed_nodes(world) == []
    assert not any(op in ('init', 'sign') for op, *_ in world.helper.calls)


def test_a_firewall_that_turned_unmanaged_since_the_plan_fails_the_plan(world):
    fw = _firewalled(world)
    opts = _agree(world, {'open_firewall': True})
    fw.managed = False
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    # the port to open is gone from the plan (it has to be opened by hand now): not the
    # plan agreed to, and nothing is asked to open
    assert row['failed_step'] == 'plan' and row['code'] == 'plan_changed'
    assert not [d for _n, d in fw.calls if d['action'] != 'inspect'] and _changed_nodes(world) == []
    again = qnetd.plan('c1', world.mgr, world.rec(), {'open_firewall': True})
    assert again['ok'] is False and any('by hand' in c['message'] for c in again['preflight']['checks'])


def test_an_allow_the_helper_refuses_changes_nothing(world):
    fw = _firewalled(world)
    real = fw.__call__

    def refuse(name, data):
        if data['action'] == 'allow':
            return {'ok': False, 'code': 'firewall_unmanaged', 'error': 'open it by hand: ufw allow ...'}
        return real(name, data)
    world.helper.answers['firewall'] = refuse
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'firewall' and row['code'] == 'firewall_unmanaged'
    assert row['rolled_back'] is None and _changed_nodes(world) == []


@pytest.mark.parametrize('how', ['refused', 'no_answer', 'broke'])
def test_an_allow_that_broke_off_part_way_takes_out_what_it_added(world, how):
    """ufw took the first address and refused the second (or the 80 s ran out, or the
    answer never came): the first rule is in and written down on the QNetd host. The
    rollback takes it out, and leaves the one the cluster's record held before the job."""
    fw = _firewalled(world)
    fw.rules['pve'] = ['10.0.0.2']               # left by an earlier setup, not this job's
    real = fw.__call__

    def half(name, data):
        if data['action'] != 'allow':
            return real(name, data)
        real(name, dict(data, sources=data['sources'][:1]))
        if how == 'refused':
            return {'ok': False, 'code': 'firewall_failed', 'error': 'ufw did not add the rule for 10.0.0.2: ERROR'}
        if how == 'broke':
            return {'ok': False, 'code': 'failed', 'error': 'firewall failed on the QNetd host (OSError)'}
        raise qnetd.HelperError('the QNetd helper did not answer firewall within 120 s')
    world.helper.answers['firewall'] = half
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'firewall' and row['rolled_back'] is True, view['steps']
    assert [d for _n, d in fw.calls if d['action'] == 'remove'] == [{'action': 'remove', 'sources': ['10.0.0.1']}]
    assert fw.rules['pve'] == ['10.0.0.2'] and not fw.allowed('10.0.0.1')
    assert _changed_nodes(world) == []
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []


def test_a_half_opened_ufw_of_the_real_helper_is_closed_again(world, tmp_path):
    """The same against the helper itself and the ufw stand-in: the second `ufw allow`
    fails, the first rule is in ufw and in firewall.json. After the rollback neither holds
    it, and the job says it rolled back instead of that nothing changed."""
    import os
    from test_qnetd_firewall import FwHost
    host = FwHost(tmp_path / 'q')
    host.ufw()
    world.helper.answers['firewall'] = lambda name, data: host.fw(name, **data)[1]
    world.cluster.port = {n: False for n in world.cluster.nodes}
    opts = _agree(world, {'open_firewall': True})
    with open(os.path.join(host.bin, 'ufw-fail-at'), 'w') as fh:
        fh.write('2')
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'firewall' and row['code'] == 'firewall_failed' and row['rolled_back'] is True
    assert host.ufw_rules() == [] and host.saved() == {}
    assert any(s['step'] == 'rollback' and s['state'] == 'ok' and '10.0.0.1' in s['message'] for s in view['steps'])


@pytest.mark.parametrize('code', ['busy', 'state_untrusted', 'state_full', 'not_supported', 'bad_request'])
def test_an_allow_refused_before_it_changed_anything_asks_for_no_removal(world, code):
    fw = _firewalled(world)
    real = fw.__call__
    world.helper.answers['firewall'] = lambda name, data: real(name, data) if data['action'] != 'allow' else {
        'ok': False, 'code': code, 'error': 'refused'}
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'firewall' and row['code'] == code and row['rolled_back'] is None
    assert [d['action'] for _n, d in fw.calls if d['action'] != 'inspect'] == []


def test_the_rollback_removes_only_what_the_job_asked_for(world):
    fw = _firewalled(world)
    world.cluster.fail['p12'] = 1
    real = fw.__call__

    def lying(name, data):
        ans = real(name, data)
        if data['action'] == 'allow':
            ans['added'] = ans['added'] + [{'source': '192.0.2.99', 'port': 5403}, {'source': '10.0.0.0/8'}]
        return ans
    world.helper.answers['firewall'] = lying
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['clusters']['c1']['failed_step'] == 'node_p12'
    remove = [d for _n, d in fw.calls if d['action'] == 'remove']
    assert remove == [{'action': 'remove', 'sources': ['10.0.0.1', '10.0.0.2']}]


def test_a_rollback_whose_firewall_remove_fails_says_so(world):
    fw = _firewalled(world)
    world.cluster.fail['start'] = 1
    opts = _agree(world, {'open_firewall': True})
    real = fw.__call__

    def broken_remove(name, data):
        if data['action'] == 'remove':
            return {'ok': False, 'code': 'failed', 'error': 'ufw failed on the QNetd host'}
        return real(name, data)
    world.helper.answers['firewall'] = broken_remove
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['rolled_back'] is False
    assert any(s['step'] == 'rollback' and s['state'] == 'failed' and 'ufw failed' in s['message']
               for s in view['steps'])


def test_without_the_option_the_firewall_is_not_touched(world):
    fw = _firewalled(world, blocking=False)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), _agree(world))
    assert view['state'] == 'done' and 'firewall' not in _steps(view)
    assert all(d['action'] == 'inspect' for _n, d in fw.calls)


def test_an_ipv6_node_gets_its_own_address_opened(world):
    fw = _firewalled(world, 'firewalld')
    world.cluster.src['pve2'] = '2001:db8::12'
    opts = _agree(world, {'open_firewall': True})
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert sorted(fw.rules['pve']) == ['10.0.0.1', '2001:db8::12']


# --- the QNetd host step ---------------------------------------------------------------------

def _no_qnetd_yet(world):
    """A host where the helper is there but corosync-qnetd is not; init puts it there."""
    h = world.helper
    h.answers['version'] = dict(h.answers['version'], qnetd_installed=False, certutil_installed=False)
    h.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    ca = h.answers['ca']
    h.answers['ca'] = {'ok': False, 'code': 'not_initialised', 'error': 'no CA yet'}
    inits = []

    def init(name, data):
        inits.append(1)
        h.answers['version'] = dict(h.answers['version'], qnetd_installed=True, certutil_installed=True)
        h.answers['status'] = {'ok': True, 'active': True, 'clusters': []}
        h.answers['ca'] = ca
        return {'ok': True, 'active': True, 'installed': True, 'tls_set': True}
    h.answers['init'] = init
    for n in world.cluster.nodes:
        world.cluster.port[n] = False
    return inits


def _qnetd_listens(world, inits):
    """The nodes reach the port once corosync-qnetd runs."""
    nodes = world.cluster.nodes

    class Listening(dict):
        def __getitem__(self, node):
            return bool(inits)
    world.cluster.port = Listening({n: False for n in nodes})


def test_a_qnetd_host_without_corosync_qnetd_is_set_up_first(world):
    inits = _no_qnetd_yet(world)
    _qnetd_listens(world, inits)
    opts = _agree(world)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert _steps(view)[:3] == ['plan', 'qnetd_host', 'preflight']
    # check_host's init, then the setup's own (which changes nothing on a host in place)
    assert len(inits) == 2
    assert world.rec()['ca_sha256']


def test_an_outdated_ssh_helper_is_replaced_before_the_port_is_opened(world, monkeypatch):
    fw = _firewalled(world)
    h = world.helper
    current = dict(h.answers['version'])
    h.answers['version'] = {'ok': True, 'protocol': 1, 'qnetd_installed': True, 'certutil_installed': True}
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    order = []
    h.install_helper = lambda payload: order.append('install') or h.answers.update(version=current)
    real = fw.__call__
    world.helper.answers['firewall'] = lambda name, data: order.append(data['action']) or real(name, data)
    opts = _agree(world, {'open_firewall': True})
    assert order == []                       # the plan asked the old helper nothing about a firewall
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert order[0] == 'install' and [o for o in order if o != 'inspect'][:2] == ['install', 'allow']
    assert fw.rules['pve'] == ['10.0.0.1', '10.0.0.2']


def test_a_qnetd_host_that_cannot_be_set_up_stops_before_any_node_changes(world, monkeypatch):
    _no_qnetd_yet(world)
    world.helper.answers['init'] = {'ok': False, 'code': 'no_package_sources', 'error': 'apt-get cannot reach'}
    opts = _agree(world)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'qnetd_host' and 'apt-get cannot reach' in row['error']
    assert row['rolled_back'] is None and _changed_nodes(world) == []


# --- bulk: the QNetd host once, after the first cluster that matched -----------------------------

@pytest.fixture
def two(db, monkeypatch):
    from pegaprox.globals import cluster_managers
    clusters = {'c1': FakeCluster(name='pve'), 'c2': FakeCluster(nodes=('pve3', 'pve4'), name='lab')}
    clusters['c2'].src = {'pve3': '10.0.1.3', 'pve4': '10.0.1.4'}
    mgrs = {}
    for cid, c in clusters.items():
        m = MagicMock(name=cid)
        m.cluster_type, m.is_connected = 'proxmox', True
        m.config.name = cid
        m._fake = c
        mgrs[cid] = cluster_managers[cid] = m
    monkeypatch.setattr(qnetd, '_cluster_status', lambda m: m._fake.entries())

    def shell(m, node):
        c = m._fake
        if node not in c.nodes:
            raise qnetd.NodeError(f'node {node}: unknown')
        s = c.shells[node] = FakeShell(node, c)
        return s
    monkeypatch.setattr(qnetd, '_open_shell', shell)
    h = FakeHelper()
    monkeypatch.setattr(qnetd, 'transport_for', lambda rec: h)
    db.save_qnetd_host('aaaaaaaaaaaa', {'name': 'witness', 'kind': 'ssh', 'address': '192.0.2.50', 'port': 5403,
                                        'ssh_host': '192.0.2.50', 'ssh_port': 22, 'ssh_user': 'root'},
                       password='pw')
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit', lambda *a, **k: None)
    checks = []
    real = qnetd.check_host

    def check_host(rec, init=True, upgrade=True):
        checks.append((init, upgrade))
        return real(rec, init=init, upgrade=upgrade)
    monkeypatch.setattr(qnetd, 'check_host', check_host)
    w = types.SimpleNamespace(clusters=clusters, mgrs=mgrs, helper=h, db=db, checks=checks,
                              rec=lambda: qnetd.get_qnetd('aaaaaaaaaaaa'))
    yield w
    for cid in clusters:
        cluster_managers.pop(cid, None)


def _consents(two, opts=None, wrong=()):
    opts = dict(opts or {})
    opts['consents'] = {}
    for cid in ('c1', 'c2'):
        d = qnetd.plan(cid, two.mgrs[cid], two.rec(), opts)['plan']['digest']
        opts['consents'][cid] = ('0' * 64) if cid in wrong else d
    return opts


def _bulk_no_qnetd(two):
    inits = _no_qnetd_yet(types.SimpleNamespace(helper=two.helper, cluster=types.SimpleNamespace(nodes=[], port={})))
    for c in two.clusters.values():
        class Listening(dict):
            def __getitem__(self, node):
                return bool(inits)
        c.port = Listening()
    return inits


def test_bulk_sets_up_the_qnetd_host_once(two):
    _bulk_no_qnetd(two)
    opts = _consents(two)
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert two.checks == [(True, True)]
    host = [(s['cluster_id'], s['state']) for s in view['steps'] if s['step'] == 'qnetd_host']
    # c2 agreed to the same QNetd host work as c1, and its plan was held to that before the
    # host changed: c2 takes over what c1's step did
    assert host == [('c1', 'running'), ('c1', 'ok'), ('c2', 'ok')]


def test_bulk_holds_every_plan_to_its_consent_before_the_qnetd_host_changes(two):
    """The QNetd host step is a change: no cluster of the run is compared with its plan
    after it, when the host work it agreed to is gone from a plan read then."""
    _bulk_no_qnetd(two)
    opts = _consents(two, wrong=('c2',))
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    steps = [(s['cluster_id'], s['step'], s['state']) for s in view['steps']]
    host = steps.index(('c1', 'qnetd_host', 'running'))
    assert steps.index(('c1', 'plan', 'ok')) < host and steps.index(('c2', 'plan', 'failed')) < host
    assert view['clusters']['c2']['code'] == 'plan_changed' and view['clusters']['c1']['state'] == 'done'
    assert {s for c, s, _st in steps if c == 'c2'} == {'plan'}
    assert view['state'] == 'partial' and two.checks == [(True, True)]


def test_bulk_with_the_port_to_open_on_a_host_set_up_by_the_run(two, monkeypatch):
    """Both plans were read before the helper was there, so before the firewall could be
    told: both clusters get their port opened once the run has put the helper there."""
    _bulk_no_qnetd(two)
    fw = two.helper.answers['firewall'] = FakeFirewall('ufw')
    version = two.helper.answers['version']
    two.helper.answers['version'] = qnetd.HelperError('the helper did not run (exit 127)', 'no_helper')
    two.helper.install_helper = lambda payload: two.helper.answers.update(version=version)
    monkeypatch.setattr(qnetd, 'local_helper_copy', lambda: HELPER_COPY)
    opts = _consents(two, {'open_firewall': True})
    for c in two.clusters.values():
        c.port = _Reach(c, fw)
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert two.checks == [(True, True)]
    assert fw.rules == {'pve': ['10.0.0.1', '10.0.0.2'], 'lab': ['10.0.1.3', '10.0.1.4']}


def test_bulk_does_not_set_up_the_qnetd_host_twice(two, monkeypatch):
    _bulk_no_qnetd(two)
    opts = _consents(two)
    real = qnetd.plan

    def still_says_so(cid, *a, **k):
        got = real(cid, *a, **k)
        if cid == 'c2':
            got['plan']['items'].insert(0, {'id': 'qnetd_start', 'where': 'qnetd', 'node': None, 'params': {},
                                            'text': ''})
        return got
    monkeypatch.setattr(qnetd, 'plan', still_says_so)
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert two.checks == [(True, True)]
    assert ('c2', 'ok', 'The QNetd host was set up earlier in this run') in [
        (s['cluster_id'], s['state'], s['message']) for s in view['steps'] if s['step'] == 'qnetd_host']


def test_bulk_never_touches_the_qnetd_host_before_a_plan_matched(two):
    _bulk_no_qnetd(two)
    opts = _consents(two, wrong=('c1',))
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['clusters']['c1']['code'] == 'plan_changed' and view['clusters']['c2']['state'] == 'done'
    assert view['state'] == 'partial' and two.checks == [(True, True)]
    first = next(s for s in view['steps'] if s['step'] == 'qnetd_host')
    assert first['cluster_id'] == 'c2'
    # nothing of c1 was changed: its plan step is all it got
    assert {s['step'] for s in view['steps'] if s['cluster_id'] == 'c1'} == {'plan'}


def test_bulk_with_no_plan_matching_sets_up_nothing(two):
    _bulk_no_qnetd(two)
    opts = _consents(two, wrong=('c1', 'c2'))
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['state'] == 'failed' and two.checks == []
    assert not any(op in ('init', 'sign') for op, *_ in two.helper.calls)


def test_bulk_does_not_retry_a_qnetd_host_that_could_not_be_set_up(two):
    _bulk_no_qnetd(two)
    two.helper.answers['init'] = {'ok': False, 'error': 'apt-get cannot reach the package sources'}
    opts = _consents(two)
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert two.checks == [(True, True)]
    for cid in ('c1', 'c2'):
        row = view['clusters'][cid]
        assert row['failed_step'] == 'qnetd_host' and 'apt-get cannot reach' in row['error']


def test_bulk_opens_the_port_per_cluster_under_its_own_name(two):
    fw = two.helper.answers['firewall'] = FakeFirewall('ufw')
    for c in two.clusters.values():
        c.port = _Reach(c, fw)
    opts = _consents(two, {'open_firewall': True})
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert fw.rules == {'pve': ['10.0.0.1', '10.0.0.2'], 'lab': ['10.0.1.3', '10.0.1.4']}


def _signs(two):
    return {name: data['replace'] for op, name, data in two.helper.calls if op == 'sign'}


def test_bulk_stops_a_cluster_whose_name_the_qnetd_host_holds_at_its_plan(two):
    """A certificate of an earlier setup for pve: its plan does not pass without the replace,
    the other cluster of the run goes on."""
    two.helper.answers['status']['certificates'] = ['pve']
    assert qnetd.plan('c1', two.mgrs['c1'], two.rec(), {})['ok'] is False
    opts = _consents(two)
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    row = view['clusters']['c1']
    assert row['failed_step'] == 'plan' and row['code'] == 'name_exists' and row['rolled_back'] is None
    assert view['clusters']['c2']['state'] == 'done' and view['state'] == 'partial'
    assert _signs(two) == {'lab': False}


def test_bulk_replaces_only_where_the_plan_of_the_cluster_lists_it(two):
    """One replace option for the run, and a certificate on file for pve only: the plan of pve
    lists the replacement, the one of lab has nothing to replace and its sign asks for none."""
    two.helper.answers['status']['certificates'] = ['pve', 'old']
    ids = {cid: [i['id'] for i in qnetd.plan(cid, two.mgrs[cid], two.rec(),
                                             {'replace_certificate': True})['plan']['items']]
           for cid in ('c1', 'c2')}
    assert 'cert_replace' in ids['c1'] and 'cert_replace' not in ids['c2']
    opts = _consents(two, {'replace_certificate': True})
    view = _run(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''), qnetd.run_bulk, two.rec(), opts)
    assert view['state'] == 'done', view['steps']
    assert _signs(two) == {'pve': True, 'lab': False}


# --- removal ---------------------------------------------------------------------------------

def test_remove_drops_the_firewall_rules_of_the_cluster(world):
    fw = _firewalled(world)
    fw.rules = {'pve': ['10.0.0.1', '10.0.0.2'], 'other': ['10.0.0.1']}
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'done'
    assert [(n, d) for n, d in fw.calls] == [('pve', {'action': 'remove'})]
    assert fw.rules == {'pve': [], 'other': ['10.0.0.1']}
    assert any(s['step'] == 'firewall' and s['state'] == 'ok' and '10.0.0.1, 10.0.0.2' in s['message']
               for s in view['steps'])


@pytest.mark.parametrize('breakage', ['refused', 'unreachable', 'outdated'])
def test_a_firewall_cleanup_that_fails_leaves_the_removal_standing(world, breakage):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    if breakage == 'refused':
        world.helper.answers['firewall'] = {'ok': False, 'code': 'failed', 'error': 'firewall-cmd failed'}
    elif breakage == 'unreachable':
        world.helper.answers['version'] = qnetd.HelperError('SSH to the QNetd host failed (timeout)')
    else:
        world.helper.answers['version'] = {'ok': True, 'protocol': 1, 'qnetd_installed': True}
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'done' and view['clusters']['c1']['state'] == 'done'
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []
    warn = [s for s in view['steps'] if s['step'] == 'firewall']
    assert len(warn) == 1 and warn[0]['state'] == 'warning' and 'pve' in warn[0]['message']


def test_a_sidecar_removal_asks_no_firewall(world):
    world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), kind='sidecar', ssh_host='', ssh_user=''))
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'done' and not [c for c in world.helper.calls if c[0] in ('firewall', 'version')]


def test_a_failed_remove_keeps_the_firewall_rules(world):
    fw = _firewalled(world)
    fw.rules = {'pve': ['10.0.0.1']}
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    world.cluster.fail['remove'] = 255
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'failed' and fw.rules == {'pve': ['10.0.0.1']} and fw.calls == []
