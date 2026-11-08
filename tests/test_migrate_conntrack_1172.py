"""A live migration hands the VM's conntrack entries over, the way PVE's own dialog does (#1172).

PVE 9 moves a running VM's conntrack entries to the target when the migrate call carries
with-conntrack-state and both nodes have the dbus-vmstate helper. The dialog asks each node
(GET /nodes/<n>/capabilities/qemu/migration) and sends it when both say yes. We never sent
it, so the task log said "conntrack state migration not supported or disabled" and open
connections could drop during the move. A PVE 8 node has neither the endpoint nor the
parameter and refuses the whole call when it sees it, so it is only sent on a yes from both.

MK Oct 2026
"""
import logging
import types

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig

CAPS = '/capabilities/qemu/migration'


def _resp(status=200, data=None, text=''):
    return types.SimpleNamespace(status_code=status, json=lambda: {'data': data}, text=text)


def _manager(caps):
    """caps: node -> True/False (what the node reports), an int (that HTTP status) or an
    exception to raise. Every capabilities GET is logged in m.asked."""
    m = object.__new__(PegaProxManager)
    m.id = 'cluster_1'
    m.current_host = None
    m.config = PegaProxConfig({'name': 'lab', 'host': 'pve1.lab', 'user': 'u', 'dry_run': False})
    m.per_node_timeout = 4
    m.is_connected = True
    m.logger = logging.getLogger('test.migrate_conntrack')
    m._no_agent_vms = set()
    m.asked = []
    m.posts = []

    def get(url, timeout=None, **kw):
        if CAPS in url:
            node = url.split('/nodes/')[1].split('/')[0]
            m.asked.append(node)
            have = caps[node]
            if isinstance(have, Exception):
                raise have
            if isinstance(have, int) and not isinstance(have, bool):
                return _resp(have, None, 'Method not implemented')
            return _resp(200, {'has-dbus-vmstate': have})
        return _resp(200, {})
    m._create_session = lambda: types.SimpleNamespace(get=get, put=lambda *a, **k: _resp(200))

    def post(url, data=None, **kw):
        m.posts.append((url, dict(data or {})))
        return _resp(200, 'UPID:pve1:0001:qmigrate')
    m._api_post = post
    return m


def _sent(m):
    return m.posts[-1][1].get('with-conntrack-state')


# --- the manual move (migrate dialog, bulk runs, the API) ----------------------------------------

def test_a_live_move_between_two_nodes_with_the_helper_carries_the_conntrack_state():
    m = _manager({'pve1': True, 'pve2': True})
    r = m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    assert r['success'] is True
    url, data = m.posts[-1]
    assert url.endswith('/nodes/pve1/qemu/101/migrate')
    assert data['with-conntrack-state'] == 1 and data['online'] == 1 and data['target'] == 'pve2'
    assert sorted(m.asked) == ['pve1', 'pve2']


@pytest.mark.parametrize('caps', [
    {'pve1': True, 'pve2': False},      # target without the helper
    {'pve1': False, 'pve2': True},      # source without it
    {'pve1': True, 'pve2': 501},        # target still on PVE 8, no such endpoint
    {'pve1': 501, 'pve2': True},        # source on PVE 8 would refuse the parameter
    {'pve1': True, 'pve2': 403},        # no Sys.Audit on the target
    {'pve1': True, 'pve2': TimeoutError('slow')},
])
def test_it_is_only_sent_when_both_nodes_say_yes(caps):
    m = _manager(caps)
    assert m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)['success'] is True
    assert 'with-conntrack-state' not in m.posts[-1][1]


def test_an_offline_move_does_not_ask_and_does_not_send_it():
    m = _manager({'pve1': True, 'pve2': True})
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=False)
    assert 'with-conntrack-state' not in m.posts[-1][1]
    assert m.asked == []


def test_a_container_move_never_carries_it():
    m = _manager({'pve1': True, 'pve2': True})
    m.migrate_vm_manual('pve1', 200, 'lxc', 'pve2', online=True)
    assert m.posts[-1][0].endswith('/lxc/200/migrate')
    assert 'with-conntrack-state' not in m.posts[-1][1]
    assert m.asked == []


# --- the balancer, maintenance and rolling update path -------------------------------------------

def test_a_balancer_or_maintenance_move_carries_it_too():
    m = _manager({'pve1': True, 'pve3': True})
    m._wait_for_task = lambda node, upid, timeout=0: True
    m._note_migration = lambda *a, **k: None
    vm = {'vmid': 101, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'}
    assert m.migrate_vm(vm, 'pve3', dry_run=False) is True
    url, data = m.posts[-1]
    assert url.endswith('/nodes/pve1/qemu/101/migrate')
    assert data['with-conntrack-state'] == 1 and data['target'] == 'pve3'


def test_a_balancer_move_to_a_node_without_the_helper_leaves_it_out():
    m = _manager({'pve1': True, 'pve3': 501})
    m._wait_for_task = lambda node, upid, timeout=0: True
    m._note_migration = lambda *a, **k: None
    vm = {'vmid': 101, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'}
    assert m.migrate_vm(vm, 'pve3', dry_run=False) is True
    assert 'with-conntrack-state' not in m.posts[-1][1]


# --- asking once per node, not once per guest ----------------------------------------------------

def test_a_rolling_update_asks_each_node_once_and_not_per_guest():
    m = _manager({'pve1': True, 'pve2': True})
    for vmid in range(100, 140):
        m.migrate_vm_manual('pve1', vmid, 'qemu', 'pve2', online=True)
    assert len(m.posts) == 40 and all(d.get('with-conntrack-state') == 1 for _, d in m.posts)
    assert sorted(m.asked) == ['pve1', 'pve2']


def test_a_no_is_kept_as_well_and_asked_again_after_a_while(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(mgrmod.time, 'monotonic', lambda: clock[0])
    caps = {'pve1': True, 'pve2': 501}
    m = _manager(caps)
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    m.migrate_vm_manual('pve1', 102, 'qemu', 'pve2', online=True)
    assert m.asked.count('pve2') == 1 and 'with-conntrack-state' not in m.posts[-1][1]
    # pve2 got its PVE 9 upgrade during the rolling update: seen once the answer has aged out
    caps['pve2'] = True
    clock[0] += PegaProxManager._MIGRATION_CAPS_TTL + 1
    m.migrate_vm_manual('pve1', 103, 'qemu', 'pve2', online=True)
    assert m.asked.count('pve2') == 2 and _sent(m) == 1


def test_a_node_that_did_not_answer_is_asked_again_next_time():
    caps = {'pve1': True, 'pve2': TimeoutError('slow')}
    m = _manager(caps)
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    assert 'with-conntrack-state' not in m.posts[-1][1]
    caps['pve2'] = True
    m.migrate_vm_manual('pve1', 102, 'qemu', 'pve2', online=True)
    assert m.asked.count('pve2') == 2 and _sent(m) == 1


@pytest.mark.parametrize('status', [401, 500, 595])
def test_a_passing_error_is_not_kept(status):
    # a ticket that ran out or a node that was briefly away says nothing about the node
    caps = {'pve1': True, 'pve2': status}
    m = _manager(caps)
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    assert 'with-conntrack-state' not in m.posts[-1][1]
    caps['pve2'] = True
    m.migrate_vm_manual('pve1', 102, 'qemu', 'pve2', online=True)
    assert m.asked.count('pve2') == 2 and _sent(m) == 1


@pytest.mark.parametrize('status', [403, 501])
def test_a_real_no_is_kept(status):
    caps = {'pve1': True, 'pve2': status}
    m = _manager(caps)
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    caps['pve2'] = True
    m.migrate_vm_manual('pve1', 102, 'qemu', 'pve2', online=True)
    assert m.asked.count('pve2') == 1 and 'with-conntrack-state' not in m.posts[-1][1]


@pytest.mark.parametrize('body', [{'has-dbus-vmstate': 0}, {}, None])
def test_a_missing_or_false_flag_counts_as_no(body):
    m = _manager({'pve1': True, 'pve2': True})
    real = m._create_session

    def session():
        s = real()
        inner = s.get
        s.get = lambda url, **kw: _resp(200, body) if url.endswith('/nodes/pve2' + CAPS) else inner(url, **kw)
        return s
    m._create_session = session
    m.migrate_vm_manual('pve1', 101, 'qemu', 'pve2', online=True)
    assert 'with-conntrack-state' not in m.posts[-1][1]
