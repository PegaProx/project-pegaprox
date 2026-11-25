"""A remote migration from a Proxmox VE 9.3 node into an older target is refused up front.

qemu-server 9.2.21 and pve-container 6.1.25 raised the version of the websocket tunnel a
remote migration runs through from 2 to 3, and such a source aborts against a target that
reports 2: "Remote tunnel endpoint too old, upgrade required". It does so in the task, once
the target reserved the VMID. By then PegaProx had made a token on the target, and a
cross-cluster replication run had stopped and removed the old replica there: with the
primary upgraded first, the DR cluster held no replica at all. The move by hand, Site
Recovery, the cross-cluster balancer (every interval) and a move between two sites found
out only in the task as well.

Now the installed qemu-server (a VM) or pve-container (a container) of the source node and
of the node the guest lands on are compared first (core/migration_tunnel.py), and such a
move is refused before a token, a clone or a removal, with 409 PVE_TUNNEL_TOO_OLD on the
routes. A replication run that cannot read them keeps its old replica. Every pair from
before 9.3, and an older source into a newer target, moves as before, and elsewhere a
version that cannot be read refuses nothing.

Since the same releases, a remote migrate takes 'allow-new-uid': a move that keeps its
source sends it, to a node that knows it only.
"""
import logging
import re
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.api.vms as vms_api
import pegaprox.background.cross_cluster_lb as xclb
import pegaprox.globals as ppglobals
from pegaprox.core import migration_tunnel as mt
from pegaprox.core.manager import PegaProxManager

from test_migration_preflight import (  # noqa: F401 - _fresh and no_cleanup_thread are fixtures
    XPF, _codes, _fresh, _rows, _two, _xbody, _xrun, no_cleanup_thread)
from test_ha_sync_before_step import _Cluster
from test_sr_per_guest_failover import SRC, TGT, _admin, _done, _state, site  # noqa: F401

NEW = {'qemu-server': '9.2.21', 'pve-container': '6.1.25'}
OLD = {'qemu-server': '9.1.19', 'pve-container': '6.1.24'}
PVE8 = {'qemu-server': '8.3.13', 'pve-container': '5.2.6'}


class _R:
    def __init__(self, status=200, data=None, text=''):
        self.status_code, self._data, self.text, self.reason = status, data, text, ''
        self.headers = {}

    def json(self):
        return {'data': self._data}


def _answer(path, packages, local, ips=None):
    """The two reads of the check: a node's package versions (None: it does not answer) and
    the members, with the node behind the host PegaProx talks to and their cluster addresses.
    None for any other path."""
    hit = re.fullmatch(r'/nodes/([^/]+)/apt/versions', path)
    if hit:
        got = packages.get(hit.group(1))
        if got is None:
            return _R(500)
        # OldVersion is what is installed, Version what apt would install next
        return _R(200, [{'Package': p, 'OldVersion': v, 'Version': '9.9.9'} for p, v in got.items()])
    if path == '/cluster/status':
        if local is None:
            return _R(500)
        return _R(200, [{'type': 'cluster', 'name': 'c'}] +
                       [{'type': 'node', 'name': n, 'local': 1 if n == local else 0, 'ip': (ips or {}).get(n)}
                        for n in packages])
    return None


def _reads(packages, local, ips=None):
    """An _api_get of a MagicMock cluster that answers the check"""
    return lambda url, **kw: _answer(url.split('/api2/json', 1)[1], packages, local, ips) or _R(404)


class _Pve:
    """A cluster as the check reads it: per node its packages, and the node it answers from"""

    def __init__(self, cid, packages, local=None, name=None, ips=None):
        self.id, self.host, self.api_port = cid, f'{cid}.example', 8006
        self.config = types.SimpleNamespace(name=name or cid, transfer_network='', host=self.host)
        self.packages, self.local, self.ips, self.reads = packages, local, ips, []
        self.nodes = {n: {'node': n, 'status': 'online'} for n in packages}

    def _api_get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        self.reads.append(path)
        return _answer(path, self.packages, self.local, self.ips) or _R(404)


def _versions(m, packages, local=None):
    """Let a fake of another test answer the reads of the check too."""
    inner = m._api_get

    def get(url, **kw):
        got = _answer(url.split('/api2/json', 1)[1], packages, local)
        return got if got is not None else inner(url, **kw)
    m._api_get = get
    return packages


# --- the check ---------------------------------------------------------------------------

def test_the_tunnel_version_is_the_one_of_the_installed_package():
    m = _Pve('c', {'a': {'qemu-server': '9.2.20', 'pve-container': '6.1.25'}, 'b': {'qemu-server': '9.2.24'},
                   'c': None, 'd': PVE8})
    assert mt.tunnel_version(m, 'a', 'qemu') == 2 and mt.tunnel_version(m, 'a', 'lxc') == 3
    assert mt.tunnel_version(m, 'b', 'qemu') == 3 and mt.tunnel_version(m, 'b', 'lxc') is None
    assert mt.tunnel_version(m, 'c', 'qemu') is None and mt.tunnel_version(m, 'd', 'lxc') == 2
    # what apt would install next is no version the node runs
    assert mt.tunnel_version(m, 'a', 'qemu') == 2
    # one read per node while it is fresh
    assert m.reads.count('/nodes/a/apt/versions') == 1


def test_only_a_newer_source_into_an_older_target_is_refused():
    src = _Pve('a', {'s1': NEW, 's2': OLD, 's3': PVE8}, local='s1', name='primary')
    tgt = _Pve('b', {'t1': OLD}, local='t1', name='dr')
    why = mt.refusal(src, 's1', 'qemu', tgt)
    assert 'Upgrade the target cluster first' in why and 'Remote tunnel endpoint too old' in why
    assert 's1 of primary' in why and 't1 of dr (qemu-server 9.1.19)' in why
    assert 'pve-container 6.1.24' in mt.refusal(src, 's1', 'lxc', tgt)
    # an older source goes into it as before, and the target is not even read for it
    tgt.reads.clear()
    assert mt.refusal(src, 's2', 'qemu', tgt) is None and mt.refusal(src, 's3', 'lxc', tgt) is None
    assert tgt.reads == []
    # every source goes into a newer target
    new = _Pve('c', {'t1': NEW}, local='t1')
    assert all(mt.refusal(src, n, 'qemu', new) is None for n in ('s1', 's2', 's3'))
    # and two 8.x clusters stay what they were
    assert mt.refusal(_Pve('d', {'n': PVE8}), 'n', 'qemu', _Pve('e', {'m': PVE8}, local='m')) is None


def test_a_version_that_cannot_be_read_refuses_only_where_it_is_asked_to():
    src = _Pve('a', {'s1': NEW, 'sx': None}, local='s1')
    unread = _Pve('b', {'t1': None}, local='t1')
    old = _Pve('c', {'t1': OLD}, local='t1')
    assert mt.refusal(src, 's1', 'qemu', unread) is None
    assert mt.refusal(src, 'sx', 'qemu', old) is None
    assert 'could not be read' in mt.refusal(src, 's1', 'qemu', unread, strict=True)
    assert 'could not be read' in mt.refusal(src, 'sx', 'qemu', old, strict=True)
    # strict too: a target that takes every source needs no source version
    assert mt.refusal(src, 'sx', 'qemu', _Pve('d', {'t1': NEW}, local='t1'), strict=True) is None
    # nothing read for a source that is not known to run the newer tunnel
    old.reads.clear()
    mt.refusal(src, 'sx', 'qemu', old)
    assert old.reads == []


def test_the_check_takes_the_node_the_guest_lands_on():
    """PVE's remote_migrate sends the guest to the node behind the endpoint's host (the
    'local' one of its /cluster/status), not to a node the caller names."""
    src = _Pve('a', {'s1': NEW}, local='s1')
    tgt = _Pve('b', {'t1': OLD, 't2': NEW}, local='t2')
    assert mt.refusal(src, 's1', 'qemu', tgt, 't1') is None
    tgt = _Pve('b2', {'t1': OLD, 't2': NEW}, local='t1')
    assert 't1 of b2' in mt.refusal(src, 's1', 'qemu', tgt, 't2')
    # where that is not known, every online node it could be
    tgt = _Pve('b3', {'t1': NEW, 't2': OLD}, local=None)
    assert 't2 of b3' in mt.refusal(src, 's1', 'qemu', tgt)


def test_the_node_is_the_one_behind_the_host_the_endpoint_names():
    """The endpoint names config.host (get_cluster_fingerprint). While the HA fallback talks
    to another node, the 'local' one of /cluster/status is that other node: config.host is
    found among the members by its cluster address or its node name."""
    src = _Pve('a', {'s1': NEW}, local='s1')
    tgt = _Pve('b', {'t1': OLD, 't2': NEW}, local='t2', ips={'t1': '10.0.0.1', 't2': '10.0.0.2'})
    tgt.config.host, tgt.host, tgt.current_host, tgt._original_host = '10.0.0.1', '10.0.0.2', '10.0.0.2', '10.0.0.2'
    assert 't1 of b' in mt.refusal(src, 's1', 'qemu', tgt)
    tgt = _Pve('c', {'t1': OLD, 't2': NEW}, local='t2')
    tgt.config.host, tgt.host = 't1', 'c-fallback.example'
    assert 't1 of c' in mt.refusal(src, 's1', 'qemu', tgt)
    # a caller that dials the host it talks to (Site Recovery) lands where that one is local
    assert mt.refusal(src, 's1', 'qemu', tgt, host=tgt.host) is None
    # config.host resolved to the address PegaProx talks to is still that host
    tgt = _Pve('d', {'t1': OLD, 't2': NEW}, local='t2')
    tgt.config.host, tgt.host, tgt.current_host, tgt._original_host = 'pve.example', '10.0.0.2', '10.0.0.2', 'pve.example'
    assert mt.refusal(src, 's1', 'qemu', tgt) is None


def test_a_refusal_rests_on_a_fresh_read():
    """The versions are kept for minutes; an upgraded target is not refused from the cache."""
    src = _Pve('a', {'s1': NEW}, local='s1')
    tgt = _Pve('b', {'t1': OLD}, local='t1')
    assert mt.refusal(src, 's1', 'qemu', tgt)
    tgt.packages['t1'] = NEW
    assert mt.refusal(src, 's1', 'qemu', tgt) is None


@pytest.mark.parametrize('gone', ['source', 'target'])
def test_strict_does_not_pass_on_a_fresh_read_that_fails(gone):
    """A replication run removes its replica on strict's word: the cache knows the move is
    refused, and the side read again does not answer."""
    src = _Pve('a', {'s1': NEW}, local='s1')
    tgt = _Pve('b', {'t1': OLD}, local='t1')
    assert mt.refusal(src, 's1', 'qemu', tgt)
    (src.packages if gone == 'source' else tgt.packages)['s1' if gone == 'source' else 't1'] = None
    assert 'could not be read' in mt.refusal(src, 's1', 'qemu', tgt, strict=True)


def test_strict_does_not_trust_a_cached_older_source():
    """The source's packages were read before an upgrade of it: strict reads them again."""
    src = _Pve('a', {'s1': OLD}, local='s1')
    tgt = _Pve('b', {'t1': OLD}, local='t1')
    assert mt.refusal(src, 's1', 'qemu', tgt) is None
    src.packages['s1'] = NEW
    assert mt.refusal(src, 's1', 'qemu', tgt) is None
    assert 'Upgrade the target cluster first' in mt.refusal(src, 's1', 'qemu', tgt, strict=True)


# --- the move by hand ----------------------------------------------------------------------

def test_the_move_by_hand_is_refused_with_its_code_before_the_token(api, seed, no_cleanup_thread):
    src, dst = _two(api)
    _versions(src, {'pve1': NEW}, local='pve1')
    target = _versions(dst, {'far1': OLD}, local='far1')
    c = api.as_user(seed.user('root', role='admin'))
    r = _xrun(c)
    assert r.status_code == 409 and r.get_json()['code'] == 'PVE_TUNNEL_TOO_OLD', r.get_data(as_text=True)
    assert 'Upgrade the target cluster first' in r.get_json()['error']
    assert dst.tokens == [] and src.started == []
    # Proxmox VE refuses it, so there is nothing to override
    assert _xrun(c, override=[100], confirm_override=True).status_code == 409 and dst.tokens == []
    # the preflight says it for the VM and the container
    rows = _rows(c.post(XPF, json=_xbody()).get_json())
    assert _codes(rows[100], 'blocked') == ['tunnel_too_old'] and _codes(rows[101], 'blocked') == ['tunnel_too_old']
    assert rows[100]['overridable'] is False
    # the target upgraded: it goes
    target['far1'] = NEW
    r = _xrun(c)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(dst.tokens) == 1 and len(src.started) == 1


@pytest.mark.parametrize('source, target', [(OLD, OLD), (PVE8, OLD), (OLD, NEW), (None, OLD), (NEW, None)],
                         ids=['9.2 to 9.2', '8 to 9.2', '9.2 to 9.3', 'source unread', 'target unread'])
def test_every_other_pair_moves_as_before(api, seed, no_cleanup_thread, source, target):
    src, dst = _two(api)
    _versions(src, {'pve1': source}, local='pve1')
    _versions(dst, {'far1': target}, local='far1')
    r = _xrun(api.as_user(seed.user('root', role='admin')))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(dst.tokens) == 1 and len(src.started) == 1


def test_the_remote_migrate_route_holds_a_target_version_it_is_given(api, seed):
    """A move between two sites hands the source's route the target node's version, which
    only the target's site can read."""
    src, _dst = _two(api)
    _versions(src, {'pve1': NEW}, local='pve1')
    c = api.as_user(seed.user('root', role='admin'))
    path = '/api/clusters/cluster_1/vms/pve1/qemu/100/remote-migrate'
    body = {'target_endpoint': 'apitoken=PVEAPIToken=a@pve!t=s,host=10.0.0.5,fingerprint=AA',
            'target_storage': 'fast', 'target_bridge': 'vmbr0', 'delete_source': False}
    r = c.post(path, json=dict(body, target_tunnel=2))
    assert r.status_code == 409 and r.get_json()['code'] == 'PVE_TUNNEL_TOO_OLD' and src.started == []
    # one that takes it, and none given, as before
    assert c.post(path, json=dict(body, target_tunnel=3)).status_code == 200
    assert c.post(path, json=body).status_code == 200 and len(src.started) == 2


# --- a cross-cluster replication run -----------------------------------------------------------

class _Side(_Cluster):
    def __init__(self, node, guests, packages, options=None, **kw):
        super().__init__(node, guests, **kw)
        self.config = types.SimpleNamespace(host=self.host, name=node, transfer_network='')
        self.packages, self.options, self.snapshots, self.tokens = {node: packages}, options, [], []
        self.during_clone = None

    def _api_get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/options' and self.options is not None:
            return _R(200, self.options)
        got = _answer(path, self.packages, self.node)
        return got if got is not None else super()._api_get(url, params=params, **kw)

    def _api_post(self, url, data=None, **kw):
        if url.endswith('/snapshot'):
            self.snapshots.append(data['snapname'])
        if url.endswith('/clone') and self.during_clone:
            self.during_clone()
        return super()._api_post(url, data=data, **kw)

    def create_api_token(self, name, **kw):
        self.tokens.append(name)
        return super().create_api_token(name, **kw)


@pytest.fixture
def repl(db, monkeypatch):
    said, cleaned = [], []
    monkeypatch.setattr(vms_api, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    monkeypatch.setattr(vms_api.transfer_net, 'drop_token_when_done', lambda *a, **k: ('ok', 'OK'))
    monkeypatch.setattr(vms_api, '_capture_vm_identity', lambda *a, **k: {})
    monkeypatch.setattr(vms_api, '_restore_vm_identity', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_is_replica_of_job', lambda *a, **k: True)
    monkeypatch.setattr(vms_api, '_tag_as_replica', lambda *a, **k: (True, ''))
    monkeypatch.setattr(vms_api, '_cleanup_snapshot', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_enforce_retention', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_cleanup_clone_and_snap', lambda *a, **k: cleaned.append(a[2]))
    monkeypatch.setattr(vms_api, '_update_repl_status', lambda _db, job_id, status, error='':
                        said.append((status, error)))

    def go(source, target, replica='stopped', options=None, during_clone=None):
        src = _Side('s1', {100: 'running'}, source)
        tgt = _Side('t1', {100: replica} if replica else {}, target, options)
        if during_clone:
            src.during_clone = lambda: during_clone(src, tgt)
        monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
        monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
        vms_api._execute_replication({'id': 'j1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src',
                                      'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 't1',
                                      'mode': 'full'})
        return src, tgt, said, cleaned
    return go


def test_a_replication_run_into_an_older_target_makes_and_removes_nothing(repl):
    src, tgt, said, cleaned = repl(NEW, OLD)
    assert src.snapshots == [] and tgt.tokens == [] and cleaned == []
    assert tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'Upgrade the target cluster first' in error


def test_a_replication_run_that_cannot_read_a_version_keeps_the_old_replica(repl):
    """Removing the replica first is what turned a refused migration into no replica at all,
    so a version that might refuse it is read before, not found out after: before the
    snapshot, so a run that would end there takes no snapshot, clone or token either."""
    src, tgt, said, cleaned = repl(NEW, None)
    assert tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'could not be read' in error and 'the old replica 100 is kept' in error
    assert src.snapshots == [] and src.posts == [] and tgt.tokens == [] and cleaned == []


def _upgraded(src, tgt):
    src.packages['s1'] = NEW


def test_the_removal_asks_again_after_the_clone(repl):
    """The source was upgraded while the clone was made: the replica stays, and the clone
    and the token of the run go."""
    src, tgt, said, cleaned = repl(OLD, OLD, during_clone=_upgraded)
    assert src.snapshots and tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert 'Upgrade the target cluster first' in error and 'the old replica 100 is kept' in error
    assert cleaned == [9100] and tgt.tokens and set(tgt.tokens_deleted) == set(tgt.tokens)


def test_a_first_replication_run_removes_nothing_and_is_not_held_up(repl):
    src, tgt, said, cleaned = repl(NEW, None, replica=None)
    assert src.migrations == [9100] and said == [('ok', '')]


@pytest.mark.parametrize('source, target', [(OLD, OLD), (PVE8, PVE8), (OLD, NEW), (NEW, NEW)],
                         ids=['9.2', '8', '9.2 to 9.3', '9.3'])
def test_a_replication_run_replaces_its_replica_as_before(repl, source, target):
    src, tgt, said, cleaned = repl(source, target)
    assert tgt.posts == ['/nodes/t1/qemu/100/status/stop'] and tgt.deletes == ['/nodes/t1/qemu/100']
    assert src.migrations == [9100] and said == [('ok', '')]


# --- Site Recovery -------------------------------------------------------------------------------

def _sr_versions(source, target):
    src, tgt = ppglobals.cluster_managers[SRC], ppglobals.cluster_managers[TGT]
    src.config.name, tgt.config.name, tgt.config.transfer_network = 'primary', 'dr', ''
    tgt.config.host = tgt.host
    src.get_vm_resources.return_value = [{'vmid': v, 'node': 'n1', 'type': 'qemu'} for v in (100, 101, 102)]
    src._api_get.side_effect = _reads({'n1': source}, 'n1')
    tgt._api_get.side_effect = _reads({'d1': target}, 'd1')


def test_a_planned_failover_into_an_older_dr_cluster_moves_and_marks_nothing(api, site):
    _sr_versions(NEW, OLD)
    r = _admin(api, site).post('/api/site-recovery/plans/p1/failover')
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _done(site.db, 'planned')
    assert site.did.migrated == [] and _state(site.db) == {100: '', 101: '', 102: ''}
    for vmid in ('100', '101', '102'):
        assert 'Upgrade the target cluster first' in ev['details'][vmid]['error']


@pytest.mark.parametrize('source, target', [(NEW, NEW), (OLD, OLD), (OLD, NEW)])
def test_a_planned_failover_between_other_versions_moves_as_before(api, site, source, target):
    _sr_versions(source, target)
    assert _admin(api, site).post('/api/site-recovery/plans/p1/failover').status_code == 200
    _done(site.db, 'planned')
    assert site.did.migrated == [(SRC, 100), (SRC, 101), (SRC, 102)]


def test_site_recovery_checks_the_node_behind_the_host_it_dials(api, site):
    """Its endpoint names the host PegaProx talks to (here the fallback d2), not config.host
    (d1, the older one): the guests land on d2 and move."""
    _sr_versions(NEW, NEW)
    tgt = ppglobals.cluster_managers[TGT]
    tgt.config.host, tgt._original_host = '192.0.2.1', tgt.host
    tgt._api_get.side_effect = _reads({'d1': OLD, 'd2': NEW}, 'd2', {'d1': '192.0.2.1', 'd2': tgt.host})
    assert _admin(api, site).post('/api/site-recovery/plans/p1/failover').status_code == 200
    _done(site.db, 'planned')
    assert site.did.migrated == [(SRC, 100), (SRC, 101), (SRC, 102)]


# --- the cross-cluster balancer --------------------------------------------------------------

@pytest.fixture
def balance(monkeypatch):
    """Clusters by id: (load score, packages of their one node). hi is the busiest."""
    def go(clusters):
        mgrs = {}
        for cid, (score, packages) in clusters.items():
            m = MagicMock(id=cid)
            m.host, m.api_port, m.score = f'{cid}.example', 8006, score
            m.config.name, m.config.transfer_network, m.config.host = cid, '', m.host
            m._api_get.side_effect = _reads({f'{cid}1': packages}, f'{cid}1')
            m.find_migration_candidate.return_value = {'vmid': 100, 'name': 'web', 'type': 'qemu'}
            m.create_api_token.return_value = {'success': True, 'token_id': 'root@pam!x', 'token_value': 's'}
            m.get_cluster_fingerprint.return_value = {'success': True, 'host': m.host, 'fingerprint': 'AA'}
            m.remote_migrate_vm.return_value = {'success': True, 'task': 'UPID:hi1:1:qmigrate'}
            mgrs[cid] = m
        monkeypatch.setattr(xclb, 'cluster_managers', mgrs)
        monkeypatch.setattr(xclb, 'compute_cluster_score', lambda m: m.score)
        monkeypatch.setattr(xclb, '_pick_node', lambda m, highest: f'{m.id}1')
        monkeypatch.setattr(xclb, 'get_db', lambda: types.SimpleNamespace(
            query=lambda *a, **k: [{'id': cid} for cid in clusters], execute=lambda *a, **k: None))
        monkeypatch.setattr(xclb.ha, 'confirm_step', lambda *a, **k: True)
        monkeypatch.setattr(xclb.transfer_net, 'drop_token_when_done', lambda *a, **k: None)
        monkeypatch.setattr(xclb, 'log_audit', lambda *a, **k: None)
        xclb.run_cross_cluster_balance_check({'id': 'g1', 'name': 'group', 'cross_cluster_threshold': 5,
                                              'cross_cluster_dry_run': 0, 'cross_cluster_include_containers': 0})
        return mgrs
    return go


def test_the_balancer_moves_to_the_next_cluster_that_takes_the_guest(balance):
    m = balance({'hi': (90.0, NEW), 'old': (10.0, OLD), 'new': (20.0, NEW)})
    assert not m['old'].create_api_token.called
    assert m['new'].create_api_token.called and m['hi'].remote_migrate_vm.call_count == 1
    assert 'host=new.example' in m['hi'].remote_migrate_vm.call_args.kwargs['target_endpoint']


def test_the_balancer_leaves_a_guest_no_cluster_of_the_group_takes(balance):
    m = balance({'hi': (90.0, NEW), 'old': (10.0, OLD), 'new': (88.0, NEW)})
    assert not m['old'].create_api_token.called and not m['new'].create_api_token.called
    assert not m['hi'].remote_migrate_vm.called


def test_the_balancer_moves_between_older_clusters_as_before(balance):
    m = balance({'hi': (90.0, OLD), 'old': (10.0, PVE8), 'new': (20.0, NEW)})
    assert m['old'].create_api_token.called and not m['new'].create_api_token.called
    assert 'host=old.example' in m['hi'].remote_migrate_vm.call_args.kwargs['target_endpoint']


# --- a kept source and allow-new-uid ---------------------------------------------------------

class _Source:
    """The source node pve1 behind the API PegaProx talks to: its packages, the POST"""

    def __init__(self, packages):
        self.packages, self.posts = packages, []

    def get(self, url, params=None, **kw):
        return _answer(url.split('/api2/json', 1)[1], {'pve1': self.packages}, 'pve1') or _R(404)

    def post(self, url, data=None, **kw):
        self.posts.append(dict(data))
        return _R(200, 'UPID:pve1:00000001:00000001:6AF5E100:qmigrate:105:root@pam:')


def _keep(packages, vm_type='qemu', delete_source=False):
    mt.reset_for_tests()
    node = _Source(packages)
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='10.0.0.1', api_port=8006, user='root@pam')
    m.current_host, m.is_connected, m.api_timeout, m._consecutive_failures = None, True, 10, 0
    m.logger = logging.getLogger('test.allow_new_uid')
    m._create_session = lambda: types.SimpleNamespace(get=node.get, post=node.post)
    assert m.remote_migrate_vm('pve1', 105, vm_type, 'apitoken=x,host=10.0.0.5,fingerprint=AA', 'local-lvm:far',
                               'vmbr0', 105, True, delete_source)['success']
    (data,) = node.posts
    return data


def test_a_kept_source_lets_the_copy_get_a_new_uid_where_the_node_knows_it():
    """The copy of a guest that stays is a second guest: a target that has its uid (an
    earlier copy) refuses it unless the move allows a new one."""
    assert _keep(NEW)['allow-new-uid'] == 1 and 'delete' not in _keep(NEW)
    assert _keep(NEW, 'lxc')['allow-new-uid'] == 1
    # an older node refuses a parameter it does not know
    assert 'allow-new-uid' not in _keep(OLD) and 'allow-new-uid' not in _keep(PVE8)
    assert 'allow-new-uid' not in _keep({'qemu-server': '9.2.21', 'pve-container': '6.1.24'}, 'lxc')
    assert 'allow-new-uid' not in _keep(None)
    # a move that deletes its source stays as it was
    data = _keep(NEW, delete_source=True)
    assert data['delete'] == 1 and 'allow-new-uid' not in data
