"""A slow answer for the object shown before must never land on the one shown now (#828).

Select A, select B, B's answer arrives, then A's: A's answer is right for A and still
wrong to apply to B's view. The corporate node view merged it into B's data (and a
late network answer then kept B's network tab from ever loading), the corporate VM view
wrote it into B's guest info, snapshots, charts and lock badge, useCloudData let it
replace the data, set an error or end the load of the next cluster's section, and the
initial task fetch of the cluster before merged its tasks into the next cluster's list.

These drive the built bundle in headless Chromium with the fake server of
test_ha_ui.py. The answers for the object shown before are held back and released only
after the next object has loaded: as a success, as an HTTP error and as a failed
request. They skip where Playwright is not installed.
LW
"""
import json
import re
import time

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, VM, _App, _FakeServer, _read, browser  # noqa: F401

C2 = dict(CLUSTER, id='c2', name='Other', display_name='Other', host='10.0.0.2')
VM_B = dict(VM, vmid=101, name='db01')
NODES = {'pve1': dict(NODE_METRICS['pve1']), 'pve2': dict(NODE_METRICS['pve1'])}
N = '/api/clusters/c1/nodes'
G = '/api/clusters/c1/vms/pve1/qemu'


class _SlowServer(_FakeServer):
    """The fake of test_ha_ui.py, plus answers by path and requests held back until
    the test lets them go."""

    def __init__(self, answers=None, hold=(), **kw):
        super().__init__(**kw)
        self.answers = dict(answers or {})
        self.holding = set(hold)
        self.waiting = {}

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path in self.holding or path in self.answers:
            self.calls.append((req.method, path))
            self.urls.append(req.url)
        if path in self.holding:
            self.waiting.setdefault(path, []).append(route)
            return None
        if path in self.answers:
            return self._answer(route, *self.answers[path])
        return super().handle(route)

    @staticmethod
    def _answer(route, status, body):
        if status is None:
            return route.abort('failed')
        return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})

    def let_go(self, path, status, body=None):
        for route in self.waiting.pop(path, []):
            self._answer(route, status, body)


@pytest.fixture
def open_slow(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _SlowServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _until(app, check, timeout=8.0, what='condition'):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        app.page.wait_for_timeout(100)
    raise AssertionError(f'timed out waiting for {what}')


def _held(app, path):
    _until(app, lambda: app.server.waiting.get(path), what=f'a request to {path}')


def _see(app, text):
    app.page.get_by_text(text).first.wait_for(timeout=8000)


def _count(app, text):
    return app.page.get_by_text(text).count()


def _errors(app):
    # a request released as a failure is logged by the page's fetch helpers on purpose
    return [e for e in app.errors if 'Failed to fetch' not in e]


def _settle(app):
    """Long enough for a released answer to be parsed and rendered."""
    app.page.wait_for_timeout(700)


LATE = [pytest.param(200, id='success'), pytest.param(500, id='http-error'), pytest.param(None, id='failure')]


# -- corporate node view -------------------------------------------------------------------

def _corp_tree(app):
    app.page.locator('.corp-tree-item', has_text='Testi').first.click()
    app.page.locator('.corp-tree-child', has_text='pve2').first.wait_for(timeout=8000)


def _node(app, name):
    app.page.locator('.corp-tree-child', has_text=name).first.click()


def _summary(model):
    return {'cpuinfo': {'model': model, 'cores': 4, 'cpus': 8, 'sockets': 1}}


def _node_app(open_slow, hold=(), **answers):
    base = {f'{N}/pve1/summary': (200, _summary('cpu-of-pve1')),
            f'{N}/pve2/summary': (200, _summary('cpu-of-pve2')),
            f'{N}/pve2/network': (200, [{'iface': 'eth-of-pve2', 'type': 'eth', 'active': 1}])}
    base.update(answers)
    app = open_slow(layout='corporate', clusters=[CLUSTER], resources=[VM], metrics=NODES,
                    answers=base, hold=hold)
    _corp_tree(app)
    return app


def test_runtime_a_late_network_answer_of_the_previous_node_never_lands(open_slow):
    """The reporter's mixed state: B's summary with A's interfaces, and B's network tab
    never asking for B's because the slot was already filled."""
    app = _node_app(open_slow, hold={f'{N}/pve1/network'})
    _node(app, 'pve1')
    _see(app, 'cpu-of-pve1')
    app.page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    _held(app, f'{N}/pve1/network')

    _node(app, 'pve2')
    _see(app, 'cpu-of-pve2')
    app.server.let_go(f'{N}/pve1/network', 200, [{'iface': 'eth-of-pve1', 'type': 'eth', 'active': 1}])
    _settle(app)
    assert _count(app, 'eth-of-pve1') == 0

    app.page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    _see(app, 'eth-of-pve2')
    assert ('GET', f'{N}/pve2/network') in app.server.calls
    assert _count(app, 'eth-of-pve1') == 0
    assert not _errors(app), _errors(app)


@pytest.mark.parametrize('status', LATE)
def test_runtime_a_late_summary_of_the_previous_node_never_replaces_the_current_one(open_slow, status):
    app = _node_app(open_slow, hold={f'{N}/pve1/summary'})
    _node(app, 'pve1')
    _held(app, f'{N}/pve1/summary')

    _node(app, 'pve2')
    _see(app, 'cpu-of-pve2')
    app.server.let_go(f'{N}/pve1/summary', status, _summary('cpu-of-pve1'))
    _settle(app)
    assert _count(app, 'cpu-of-pve2') > 0, 'the current summary was replaced'
    assert _count(app, 'cpu-of-pve1') == 0
    assert not _errors(app), _errors(app)


def test_runtime_a_late_answer_does_not_end_the_current_nodes_loading(open_slow):
    spinner = 'div.h-32 svg.animate-spin'
    app = _node_app(open_slow, hold={f'{N}/pve1/network', f'{N}/pve2/summary'})
    _node(app, 'pve1')
    _see(app, 'cpu-of-pve1')
    app.page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    _held(app, f'{N}/pve1/network')

    _node(app, 'pve2')
    _held(app, f'{N}/pve2/summary')
    app.page.locator(spinner).first.wait_for(timeout=5000)
    app.server.let_go(f'{N}/pve1/network', 200, [{'iface': 'eth-of-pve1', 'type': 'eth'}])
    _settle(app)
    assert app.page.locator(spinner).count() > 0, "the previous node's answer ended the current load"

    app.server.let_go(f'{N}/pve2/summary', 200, _summary('cpu-of-pve2'))
    _see(app, 'cpu-of-pve2')
    _until(app, lambda: app.page.locator(spinner).count() == 0, what='the spinner to go')
    assert not _errors(app), _errors(app)


def test_runtime_a_change_that_finishes_after_the_switch_reloads_nothing_here(open_slow):
    """The delete of an interface on pve1 returns once pve2 is shown: its reload of
    pve1's network must not fill pve2's slot."""
    gone = f'{N}/pve1/network/eth-of-pve1'
    app = _node_app(open_slow, hold={gone},
                    **{f'{N}/pve1/network': (200, [{'iface': 'eth-of-pve1', 'type': 'eth', 'active': 1}])})
    page = app.page
    _node(app, 'pve1')
    page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    _see(app, 'eth-of-pve1')
    page.once('dialog', lambda d: d.accept())
    page.locator('tr', has_text='eth-of-pve1').locator('button[title="Delete"]').click()
    _held(app, gone)

    _node(app, 'pve2')
    _see(app, 'cpu-of-pve2')
    asked = app.server.calls.count(('GET', f'{N}/pve1/network'))
    app.server.let_go(gone, 200, {})
    _settle(app)
    assert app.server.calls.count(('GET', f'{N}/pve1/network')) == asked
    page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    _see(app, 'eth-of-pve2')
    # the toast of the delete names it, the table must not
    assert page.locator('td', has_text='eth-of-pve1').count() == 0
    assert not _errors(app), _errors(app)


def test_runtime_the_first_visit_does_not_overwrite_the_second_visit(open_slow):
    """A -> B -> A: the node matches again, the request is still the old one."""
    app = _node_app(open_slow, hold={f'{N}/pve1/summary'})
    _node(app, 'pve1')
    _held(app, f'{N}/pve1/summary')
    _node(app, 'pve2')
    _see(app, 'cpu-of-pve2')

    app.server.holding.discard(f'{N}/pve1/summary')
    app.server.answers[f'{N}/pve1/summary'] = (200, _summary('cpu-of-pve1-now'))
    _node(app, 'pve1')
    _see(app, 'cpu-of-pve1-now')
    app.server.let_go(f'{N}/pve1/summary', 200, _summary('cpu-of-pve1-then'))
    _settle(app)
    assert _count(app, 'cpu-of-pve1-now') > 0
    assert _count(app, 'cpu-of-pve1-then') == 0
    assert not _errors(app), _errors(app)


# -- corporate VM view ---------------------------------------------------------------------

def _guest(name):
    return {'agent_running': True, 'hostname': f'host-of-{name}', 'ip_addresses': [f'ip-of-{name}']}


def _vm_app(open_slow, hold=(), **answers):
    base = {f'{G}/100/guest-info': (200, _guest('web01')),
            f'{G}/101/guest-info': (200, _guest('db01'))}
    base.update(answers)
    app = open_slow(layout='corporate', clusters=[CLUSTER], resources=[VM, VM_B], metrics=NODE_METRICS,
                    answers=base, hold=hold)
    app.page.locator('.corp-tree-item', has_text='Testi').first.click()
    app.page.locator('.corp-tree-child', has_text='db01').first.wait_for(timeout=8000)
    return app


def _vm(app, name):
    app.page.locator('.corp-tree-child', has_text=name).first.click()


@pytest.mark.parametrize('status', LATE)
def test_runtime_guest_info_of_the_previous_vm_never_lands(open_slow, status):
    app = _vm_app(open_slow, hold={f'{G}/100/guest-info'})
    _vm(app, 'web01')
    _held(app, f'{G}/100/guest-info')

    _vm(app, 'db01')
    _see(app, 'host-of-db01')
    app.server.let_go(f'{G}/100/guest-info', status, _guest('web01'))
    _settle(app)
    assert _count(app, 'host-of-db01') > 0, "the current VM's guest info went away"
    assert _count(app, 'host-of-web01') == 0
    assert not _errors(app), _errors(app)


def test_runtime_the_previous_vms_guest_info_is_not_shown_while_the_next_loads(open_slow):
    app = _vm_app(open_slow, hold={f'{G}/101/guest-info'})
    _vm(app, 'web01')
    _see(app, 'host-of-web01')

    _vm(app, 'db01')
    _held(app, f'{G}/101/guest-info')
    app.page.wait_for_timeout(300)
    assert _count(app, 'host-of-web01') == 0, "db01 shows web01's guest info while it loads"
    app.server.let_go(f'{G}/101/guest-info', 200, _guest('db01'))
    _see(app, 'host-of-db01')
    assert not _errors(app), _errors(app)


def test_runtime_late_snapshots_of_the_previous_vm_never_land(open_slow):
    snaps = lambda n: [{'name': f'snap-of-{n}', 'description': '', 'snaptime': 1700000000},
                       {'name': 'current', 'parent': f'snap-of-{n}'}]
    app = _vm_app(open_slow, hold={f'{G}/100/snapshots'},
                  **{f'{G}/100/efficient-snapshots': (200, []),
                     f'{G}/101/efficient-snapshots': (200, []),
                     f'{G}/101/snapshots': (200, snaps('db01'))})
    _vm(app, 'web01')
    app.page.locator('.corp-tab-strip').last.get_by_text('Snapshots').click()
    _held(app, f'{G}/100/snapshots')

    _vm(app, 'db01')
    _see(app, 'snap-of-db01')
    app.server.let_go(f'{G}/100/snapshots', 200, snaps('web01'))
    _settle(app)
    assert _count(app, 'snap-of-db01') > 0
    assert _count(app, 'snap-of-web01') == 0
    assert not _errors(app), _errors(app)


def test_runtime_a_snapshot_delete_that_finishes_after_the_switch_reloads_nothing_here(open_slow):
    snaps = lambda n: [{'name': f'snap-of-{n}', 'description': '', 'snaptime': 1700000000},
                       {'name': 'current', 'parent': f'snap-of-{n}'}]
    gone = f'{G}/100/snapshots/snap-of-web01'
    app = _vm_app(open_slow, hold={gone},
                  **{f'{G}/100/snapshots': (200, snaps('web01')),
                     f'{G}/100/efficient-snapshots': (200, []),
                     f'{G}/101/efficient-snapshots': (200, []),
                     f'{G}/101/snapshots': (200, snaps('db01'))})
    page = app.page
    _vm(app, 'web01')
    page.locator('.corp-tab-strip').last.get_by_text('Snapshots').click()
    _see(app, 'snap-of-web01')
    page.once('dialog', lambda d: d.accept())
    page.locator('.corp-snap-row', has_text='snap-of-web01').locator('button[title="Delete"]').click()
    _held(app, gone)

    _vm(app, 'db01')
    _see(app, 'snap-of-db01')
    asked = app.server.calls.count(('GET', f'{G}/100/snapshots'))
    app.server.let_go(gone, 200, {})
    _settle(app)
    assert app.server.calls.count(('GET', f'{G}/100/snapshots')) == asked
    assert _count(app, 'snap-of-db01') > 0
    assert _count(app, 'snap-of-web01') == 0
    assert not _errors(app), _errors(app)


def test_runtime_late_metrics_of_the_previous_vm_never_land(open_slow):
    series = {'metrics': {k: [1, 2, 3] for k in ('cpu', 'memory', 'disk_read', 'disk_write', 'net_in', 'net_out')},
              'timestamps': [1700000000, 1700000060, 1700000120]}
    app = _vm_app(open_slow, hold={f'{G}/100/rrd/hour'})
    _vm(app, 'web01')
    _held(app, f'{G}/100/rrd/hour')

    _vm(app, 'db01')          # its rrd is not mocked: a 404, no data
    _see(app, 'No data available')
    app.server.let_go(f'{G}/100/rrd/hour', 200, series)
    _settle(app)
    assert _count(app, 'Disk Read') == 0, "web01's charts were drawn for db01"
    assert _count(app, 'No data available') > 0
    assert not _errors(app), _errors(app)


def test_runtime_the_previous_vms_lock_never_lands(open_slow):
    """A late 'locked' for web01 would offer Unlock on db01."""
    app = _vm_app(open_slow, hold={f'{G}/100/lock'},
                  **{f'{G}/101/lock': (200, {'locked': False})})
    _vm(app, 'web01')
    _held(app, f'{G}/100/lock')

    _vm(app, 'db01')
    _see(app, 'host-of-db01')
    app.server.let_go(f'{G}/100/lock', 200, {'locked': True, 'lock_reason': 'backup'})
    _settle(app)
    assert app.page.locator('.corp-badge-locked').count() == 0
    assert not _errors(app), _errors(app)


# -- cloud: useCloudData -------------------------------------------------------------------

def _jobs(cid):
    return [{'id': f'job-{cid}', 'schedule': f'sched-of-{cid}', 'storage': f'store-{cid}', 'enabled': 1}]


def _cloud_backups(open_slow, hold):
    app = open_slow(layout='cloud', clusters=[CLUSTER, C2], resources=[VM], hold=hold,
                    answers={'/api/clusters/c1/datacenter/backup': (200, _jobs('c1')),
                             '/api/clusters/c2/datacenter/backup': (200, _jobs('c2')),
                             # the restore test card of the same page (core/recovery.py)
                             '/api/clusters/c1/recovery-report': (200, {'guests': [], 'summary': {}}),
                             '/api/clusters/c2/recovery-report': (200, {'guests': [], 'summary': {}})})
    app.page.get_by_text('Backups').first.click()
    return app


@pytest.mark.parametrize('status', LATE)
def test_runtime_cloud_a_late_answer_of_the_previous_cluster_never_lands(open_slow, status):
    app = _cloud_backups(open_slow, hold={'/api/clusters/c1/datacenter/backup'})
    _held(app, '/api/clusters/c1/datacenter/backup')

    app.page.locator('.cloud-cluster-select').select_option('c2')
    _see(app, 'sched-of-c2')
    app.server.let_go('/api/clusters/c1/datacenter/backup', status, _jobs('c1'))
    _settle(app)
    assert _count(app, 'sched-of-c2') > 0, "the current cluster's jobs are gone"
    assert _count(app, 'sched-of-c1') == 0
    assert _count(app, 'Could not load') == 0
    assert not _errors(app), _errors(app)


def test_runtime_cloud_a_late_answer_does_not_end_the_next_load(open_slow):
    app = _cloud_backups(open_slow, hold={'/api/clusters/c1/datacenter/backup',
                                          '/api/clusters/c2/datacenter/backup'})
    _held(app, '/api/clusters/c1/datacenter/backup')
    app.page.locator('.cloud-cluster-select').select_option('c2')
    _held(app, '/api/clusters/c2/datacenter/backup')

    app.server.let_go('/api/clusters/c1/datacenter/backup', 200, _jobs('c1'))
    _settle(app)
    assert _count(app, 'sched-of-c1') == 0
    assert app.page.locator('.cloud-empty', has_text='Loading').count() > 0
    app.server.let_go('/api/clusters/c2/datacenter/backup', 200, _jobs('c2'))
    _see(app, 'sched-of-c2')
    assert not _errors(app), _errors(app)


def test_runtime_cloud_a_change_that_finishes_after_the_switch_reloads_nothing_here(open_slow):
    """The reload a mutation kept from c1 must not fetch c1's jobs into c2's section."""
    toggle = '/api/clusters/c1/datacenter/backup/job-c1'
    app = _cloud_backups(open_slow, hold={toggle})
    _see(app, 'sched-of-c1')
    app.page.locator('button[title="Disable"]').first.click()
    _held(app, toggle)

    app.page.locator('.cloud-cluster-select').select_option('c2')
    _see(app, 'sched-of-c2')
    asked = app.server.calls.count(('GET', '/api/clusters/c1/datacenter/backup'))
    app.server.let_go(toggle, 200, {})
    _settle(app)
    assert app.server.calls.count(('GET', '/api/clusters/c1/datacenter/backup')) == asked
    assert _count(app, 'sched-of-c2') > 0
    assert _count(app, 'sched-of-c1') == 0
    assert not _errors(app), _errors(app)


def test_runtime_cloud_a_reload_of_the_same_cluster_keeps_working(open_slow):
    """Normal operation: the newest answer for the same path still lands."""
    app = _cloud_backups(open_slow, hold=())
    _see(app, 'sched-of-c1')
    app.server.answers['/api/clusters/c1/datacenter/backup'] = (200, _jobs('c1-again'))
    app.page.locator('.cloud-link-btn', has_text='Refresh').first.click()
    _see(app, 'sched-of-c1-again')
    assert not _errors(app), _errors(app)


# -- the cluster task list -----------------------------------------------------------------

def _task(cid):
    return [{'upid': f'UPID:{cid}:1', 'node': f'node-of-{cid}', 'type': 'qmstart', 'status': 'OK',
             'starttime': 1700000000, 'user': 'root@pam'}]


def test_runtime_a_late_initial_task_list_of_the_previous_cluster_never_merges(open_slow):
    app = open_slow(layout='modern', clusters=[CLUSTER, C2], resources=[VM],
                    hold={'/api/clusters/c1/tasks'},
                    answers={'/api/clusters/c2/tasks': (200, _task('c2'))})
    page = app.page
    page.get_by_text('Testi').first.click()
    _held(app, '/api/clusters/c1/tasks')
    page.get_by_text('Other').first.click()
    _until(app, lambda: ('GET', '/api/clusters/c2/tasks') in app.server.calls, what='the tasks of c2')
    page.wait_for_timeout(300)

    app.server.let_go('/api/clusters/c1/tasks', 200, _task('c1'))
    _settle(app)
    page.get_by_text('Tasks', exact=True).last.click()
    _see(app, 'node-of-c2')
    assert _count(app, 'node-of-c1') == 0, "the previous cluster's task merged into this list"
    assert not _errors(app), _errors(app)


# -- bundle --------------------------------------------------------------------------------

def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('navGenRef', 'slotSeqRef', 'snapSeqRef', 'metricsSeqRef', 'taskFetchGen'):
        assert needle in bundle, needle
