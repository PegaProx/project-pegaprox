"""A replica that the next-id setting of its cluster would not let back is not removed.

Proxmox VE 9.3 gave the datacenter option next-id 'enforce' and 'unique': with 'enforce'
a new guest outside the lower/upper range is refused, and with 'unique' as well one under a
VMID that was used before ("guest ID N was used before", pve-guest-common GuestID.pm). A
destroyed guest counts as used. The replication runs replace their copy under the same
VMID: the cross-cluster run removes the old replica and remote-migrates the new one onto
its VMID, the local run with a pinned VMID removes it and clones into it, the incremental
run removes it before a reseed and creates the replica again. Under such a setting the old
replica was gone and the new one refused, and the job had no copy at all from then on.

Now each of them reads the option (GET /cluster/options) before it removes anything and
ends the run with an error that says why. Without the setting (an older Proxmox VE has no
such option) the runs replace their replica as before. Options that cannot be read keep the
replica too: the run cannot tell whether the copy would be let back, and the next run asks
again (a scan of the release pull request found that the unread case removed it).
"""
import pytest

import pegaprox.api.vms as vms

from test_a_move_into_an_older_migration_tunnel_is_refused_up_front import NEW, repl  # noqa: F401
from test_xcincr_replica_tag import FakeMgr, _R

UNIQUE = {'next-id': {'lower': 100, 'upper': 1000000, 'unique': 1, 'enforce': 1}}


class _Options:
    def __init__(self, answer):
        self.answer, self.host, self.api_port = answer, 'pve.example', 8006
        self.config = type('C', (), {'name': 'dr'})()

    def _api_get(self, url, **kw):
        assert url.endswith('/cluster/options'), url
        if isinstance(self.answer, Exception):
            raise self.answer
        return _R(200, self.answer) if isinstance(self.answer, (dict, list)) else _R(self.answer)


@pytest.mark.parametrize('options, vmid, refused', [
    (UNIQUE, 5000, 'counts as used'),
    ({'next-id': 'lower=100,upper=1000000,unique=1,enforce=1'}, 5000, 'counts as used'),
    ({'next-id': {'lower': 5000, 'enforce': 1}}, 100, 'no new guest outside 5000 to 999999'),
    ({'next-id': {'upper': 5000, 'enforce': 1}}, 5000, 'no new guest outside 100 to 4999'),
    ({'next-id': {'lower': 5000, 'enforce': 1}}, 5000, None),
    ({'next-id': {'unique': 1}}, 5000, None),
    ({'next-id': {'unique': 1, 'enforce': 0}}, 5000, None),
    ({}, 5000, None),
    (403, 5000, 'could not be read (HTTP 403)'),
    (ConnectionError('gone'), 5000, 'could not be read (no answer (ConnectionError))'),
    (['not', 'an', 'object'], 5000, 'could not be read (no object)'),
], ids=['unique', 'as a string', 'below the range', 'at the upper end', 'in the range', 'unique alone',
        'not enforced', 'not set', 'unread', 'no answer', 'not an object'])
def test_the_setting_is_read_as_proxmox_ve_applies_it(options, vmid, refused):
    why = vms._next_id_refusal(_Options(options), vmid)
    if refused is None:
        assert why is None
    elif 'could not be read' in refused:
        assert refused in why and 'Nothing was removed' in why and 'the next run tries again' in why
    else:
        assert refused in why and 'Nothing was removed' in why and why.startswith('dr enforces')


def test_a_cross_cluster_run_keeps_the_replica_the_target_would_not_let_back(repl):
    """Asked before the snapshot: a run that ends there makes no snapshot, clone or token
    on every interval."""
    src, tgt, said, cleaned = repl(NEW, NEW, options=UNIQUE)
    assert tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'unique guest IDs' in error
    assert src.snapshots == [] and src.posts == [] and tgt.tokens == [] and cleaned == []


def test_a_setting_made_while_the_clone_ran_still_keeps_the_replica(repl):
    def enforced(src, tgt):
        tgt.options = UNIQUE
    src, tgt, said, cleaned = repl(NEW, NEW, options={}, during_clone=enforced)
    assert src.snapshots and tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'unique guest IDs' in error
    # the clone and the token of this run do not stay behind
    assert cleaned == [9100] and tgt.tokens and set(tgt.tokens_deleted) == set(tgt.tokens)


def test_a_cross_cluster_run_without_the_setting_replaces_its_replica(repl):
    src, tgt, said, cleaned = repl(NEW, NEW, options={'next-id': {'unique': 1}})
    assert tgt.deletes == ['/nodes/t1/qemu/100'] and src.migrations == [9100] and said == [('ok', '')]


class _Local:
    """One cluster with the old local replica 9000 of guest 100 on n2"""

    def __init__(self, options):
        self.options, self.host, self.api_port = options, 'pve.example', 8006
        self.config = type('C', (), {'name': 'main'})()
        self.posts, self.deletes = [], []

    def _api_get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/nodes':
            return _R(200, [{'node': 'n1'}, {'node': 'n2'}])
        if path == '/nodes/n2/qemu/9000/status/current':
            return _R(200, {'name': 'repl-100-n2', 'status': 'stopped'})
        if path == '/cluster/options':
            return _R(200, self.options)
        return _R(500)

    def _api_post(self, url, data=None, **kw):
        self.posts.append(url)
        return _R(200, 'UPID:post')

    def _api_delete(self, url, params=None, **kw):
        self.deletes.append(url.split('/api2/json', 1)[1])
        return _R(200, 'UPID:delete')


def test_a_local_run_with_a_pinned_vmid_keeps_its_replica_under_the_setting(monkeypatch):
    monkeypatch.setattr(vms, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    mgr = _Local(UNIQUE)
    ok, why = vms._free_local_target_vmid(mgr, 9000, 100, 'qemu', 'n2')
    assert not ok and 'main enforces unique guest IDs' in why
    assert mgr.posts == [] and mgr.deletes == []
    # without it the old replica goes, as before
    mgr = _Local({})
    assert vms._free_local_target_vmid(mgr, 9000, 100, 'qemu', 'n2') == (True, '')
    assert mgr.deletes == ['/nodes/n2/qemu/9000']


class _Target(FakeMgr):
    def __init__(self, options):
        super().__init__('10.0.0.2', 't1', [100], {'fast': 'rbd'}, {})
        self.options, self.deletes = options, []

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/cluster/options'):
            return _R(200, self.options)
        return super()._api_get(url, params=params, **kw)

    def _api_delete(self, url, params=None, **kw):
        self.deletes.append(url)
        return _R(200, 'UPID:delete')


def test_an_incremental_reseed_keeps_the_replica_the_setting_would_not_let_back(monkeypatch):
    monkeypatch.setattr(vms, '_is_replica_of_job', lambda *a, **k: True)
    monkeypatch.setattr(vms, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    tgt = _Target({'next-id': {'lower': 1000, 'enforce': 1}})
    ok, why = vms._xcincr_remove_existing_replica(tgt, 100, 'qemu', 'job1')
    assert not ok and 'no new guest outside 1000 to 999999' in why
    assert tgt.posts == [] and tgt.deletes == []
    tgt = _Target({})
    assert vms._xcincr_remove_existing_replica(tgt, 100, 'qemu', 'job1') == (True, None)
    assert len(tgt.deletes) == 1
