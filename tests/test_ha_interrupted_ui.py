"""Interrupted node recoveries in the HA settings of a cluster (#625, design 5.6).

A leader of an automatic group that stopped half way through a node recovery leaves runs in
the recovery journal; the HA status of the cluster lists them (interrupted_recoveries) while
the group runs automatically. Nothing resumes them on its own. The HA settings show each run
to who holds ha.config: the guests it moved and did not start with one Start button, the held
guests with the note why they were not started (and no button), the guests a step was begun
for that the cluster does not list, and Dismiss, which asks first.

The runtime tests drive the built bundle against the fake of test_ha_node_ui.py with the two
routes of pegaprox/api/clusters.py on top, answering in the order of their checks.
LW
"""
import copy
import json
import re
import time

import pytest

from test_ha_node_ui import (HA_CLUSTER, VIEW, _close_ha_settings, _NodeHaServer, _open_c2_settings,  # noqa: F401
                             _open_ha_settings, _wait_for, _wait_for_toast)
from test_ha_ui import BASE, LANGS, _App, _FakeServer, _block, _blocks, _read, _toasts, browser  # noqa: F401

RUN_A = '7.dddddddddddd.1f2e3d4c'
RUN_B = '7.dddddddddddd.5b6a7980'
RUN_C = '9.eeeeeeeeeeee.0a1b2c3d'
HELD_NOTE = ('moved while {node} was online and not started on purpose - {node} may still run it without a config '
             'there: check {node} before you start it by hand')
GUESTS = [{'vmid': v, 'name': n, 'type': 'qemu', 'status': 'stopped', 'node': 'pve1', 'cpu': 0, 'maxcpu': 2, 'mem': 0,
           'maxmem': 2147483648, 'disk': 0, 'maxdisk': 0, 'uptime': 0}
          for v, n in ((101, 'web01'), (102, 'db01'), (103, 'mail01'), (105, 'cache01'))]
START = '/api/clusters/c1/ha/interrupted-recoveries/start'
DISMISS = '/api/clusters/c1/ha/interrupted-recoveries/dismiss'
EM_DASH = chr(0x2014)


def _iso_utc(sec):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() - sec))


def _run(run, node='pve2', moved=(), held=(), guests_open=(), epoch=7, instance='d' * 32, ago=600):
    """One run as manager.ha_interrupted_recoveries lists it."""
    return {'run': run, 'cluster_id': 'c1', 'node': node, 'epoch': epoch, 'instance_id': instance, 'at': _iso_utc(ago),
            'open': [f'start {v}' for v in guests_open], 'guests_open': list(guests_open), 'moved': list(moved),
            'held': list(held), 'held_note': HELD_NOTE.format(node=node)}


class _RecoveryServer(_NodeHaServer):
    """The node HA fake with interrupted_recoveries in the status and the start and dismiss
    routes. start_ok: {vmid: False} for a guest PVE refuses to start; runs_key False is a
    status without the field (a manual group, or a server from before S4)."""

    def __init__(self, runs=(), start_ok=None, start_refusal=None, runs_key=True, **kw):
        kw.setdefault('resources', GUESTS)
        super().__init__(**kw)
        self.runs = [copy.deepcopy(r) for r in runs]
        self.start_ok = dict(start_ok or {})
        self.start_refusal = start_refusal
        self.runs_key = runs_key

    def ha_status(self):
        status = super().ha_status()
        if self.runs_key:
            status['interrupted_recoveries'] = copy.deepcopy(self.runs)
        return status

    def recovery_route(self, what, body):
        # require_auth(perms=['ha.config']), then the body (_recovery_runs_asked)
        if not self.admin and 'ha.config' not in self.permissions:
            return 403, {'error': 'Permission denied'}
        runs = body.get('runs')
        if (not isinstance(runs, list) or not runs or len(runs) > 256
                or not all(isinstance(r, str) and 0 < len(r) <= 64 for r in runs)):
            return 400, {'error': 'runs must be a list of run ids'}
        runs = list(dict.fromkeys(runs))
        known = {r['run'] for r in self.runs}
        if what == 'dismiss':
            gone = [r for r in runs if r in known]
            self.runs = [r for r in self.runs if r['run'] not in gone]
            return 200, {'dismissed': gone, 'unknown': sorted(set(runs) - known)}
        if self.start_refusal:
            return self.start_refusal
        asked = [r for r in self.runs if r['run'] in runs]
        started = {v: self.start_ok.get(v, True) for r in asked for v in r['moved']}
        held = [{'vmid': v, 'run': r['run'], 'node': r['node'], 'note': r['held_note']} for r in asked for v in r['held']]
        for r in asked:
            # a guest that runs now drops out of the list; a run with nothing left is forgotten
            r['moved'] = [v for v in r['moved'] if not started.get(v)]
            if not (r['moved'] or r['held'] or r['guests_open']):
                self.runs.remove(r)
        return 200, {'started': sorted(v for v, ok in started.items() if ok),
                     'failed': sorted(v for v, ok in started.items() if not ok), 'held': held,
                     'unknown': sorted(set(runs) - known)}

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/ha/interrupted-recoveries/(start|dismiss)', path)
        if not (m and req.method == 'POST' and req.url.startswith(BASE)):
            return super().handle(route)
        self.calls.append((req.method, path))
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        status, data = self.recovery_route(m.group(1), body)
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


class _TwoClusters(_RecoveryServer):
    """c1 as above, c2 a fake of its own behind the same routes. A request in `hold` as
    (method, path) waits until release() answers it."""

    def __init__(self, c2_runs=(), **kw):
        c2 = dict(HA_CLUSTER, id='c2', name='Zweit', display_name='Zweit', host='10.0.0.2')
        kw.setdefault('clusters', [dict(HA_CLUSTER), c2])
        super().__init__(**kw)
        self.c2 = _RecoveryServer(runs=c2_runs)
        self.hold = set()
        self.held = []

    def answer(self, route, cid, method, sub, body):
        srv = self if cid == 'c1' else self.c2
        rec = re.fullmatch(r'/interrupted-recoveries/(start|dismiss)', sub)
        status, data = srv.recovery_route(rec.group(1), body) if rec and method == 'POST' else srv.ha_route(method, sub, body)
        route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def release(self):
        held, self.held = self.held, []
        for args in held:
            self.answer(*args)

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/(c[12])/ha((?:/[a-z-]+)*)', path)
        if not (m and req.url.startswith(BASE)):
            return _FakeServer.handle(self, route)
        self.calls.append((req.method, path))
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        args = (route, m.group(1), req.method, m.group(2) or '', body)
        if (req.method, path) in self.hold:
            self.held.append(args)
            return None
        return self.answer(*args)


# -- source ---------------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def part(dash):
    start = dash.index('function HaNodeInterrupted(')
    return dash[start:dash.index('\n        function ', start + 10)]


def test_it_is_a_node_part_and_mounted_for_ha_config_only(dash, part):
    region = _block(dash, '// Node HA in the HA settings of a cluster (#625)', 'function PegaProxDashboard(')
    assert region.count('function HaNodeInterrupted(') == 1
    modal = _block(dash, '{/* HA Split-Brain Prevention Settings Modal */}', '{/* Sponsor footer.')
    mount = _block(modal, '{haWrite && (\n', '/>')
    assert '<HaNodeInterrupted key={selectedCluster.id} t={t} clusterId={selectedCluster.id} status={haStatus}' in mount
    assert 'resources={clusterResources} authFetch={authFetch} addToast={addToast} onReload={reloadHaStatus}' in mount
    # right under the warnings, before the strategy banner: it is the one thing to act on
    assert (modal.index('<HaNodeWarnings status={haStatus} t={t} />') < modal.index('<HaNodeInterrupted ')
            < modal.index('const fs = haStatus?.split_brain_prevention?.fence_strategy;'))
    # nothing without the field, and the field only counts with a run id to address
    assert ("? status.interrupted_recoveries.filter(r => r && typeof r === 'object' && typeof r.run === 'string' "
            "&& r.run) : [];") in part
    assert 'if (!runs.length) return null;' in part


def test_the_requests_are_what_the_routes_read(part):
    assert ("haNodeSend(authFetch, `${API_URL}/clusters/${clusterId}/ha/interrupted-recoveries/${what}`, 'POST',\n"
            "                                             { runs: [rec.run] }, t('operationFailed'));") in part
    assert part.count("send(rec, 'start')") == 1 and part.count("send(rec, 'dismiss')") == 1
    api = _read('pegaprox', 'api', 'clusters.py')
    asked = _block(api, 'def _recovery_runs_asked():', '@bp.route(')
    assert "runs = data.get('runs') if isinstance(data, dict) else None" in asked
    for name in ('start', 'dismiss'):
        route = _block(api, f"@bp.route('/api/clusters/<cluster_id>/ha/interrupted-recoveries/{name}', methods=['POST'])",
                       'def ')
        assert "@require_auth(perms=['ha.config'])" in route, name
    start = _block(api, 'def start_interrupted_recoveries(', '\n@bp.route(')
    assert "return jsonify({'started': ok_ids, 'failed': failed, 'held': held," in start


def test_held_guests_get_no_button_and_a_late_answer_fills_nothing(part):
    held = _block(part, '{held.length > 0 && (', '{open.length > 0 && (')
    assert '<button' not in held
    assert "t('haNodeIrHeldNote').replace(/\\{node\\}/g, () => node)" in held
    moved = _block(part, '{moved.length > 0 && (', '{held.length > 0 && (')
    assert moved.count('<button') == 1 and "onClick={() => send(rec, 'start')}" in moved
    send = _block(part, 'const send = async (rec, what) => {', '\n            };')
    assert send.index('if (!alive.current) return;') < send.index("setBusy('');") < send.index('onReload();')
    # Dismiss asks first
    assert "onClick={() => { setAsking(rec.run); setError(null); }}" in part
    assert "{asking === rec.run ? (" in part


def test_server_words_go_into_a_text_through_a_function(part):
    for m in re.finditer(r"\.replace\((?:'\{\w+\}'|/[^/]+/g), (.{0,6})", part):
        assert m.group(1).startswith('() =>'), part[m.start():m.start() + 80]


def _keys(dash):
    return sorted(set(re.findall(r"'(haNodeIr\w+)'", dash)))


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_exists_once_per_language(dash, lang):
    block = _blocks()[lang]
    keys = _keys(dash)
    assert len(keys) == 15
    for key in keys:
        assert len(re.findall(r'^ +%s: ' % key, block, re.M)) == 1, (lang, key)
        assert EM_DASH not in re.search(r'^ +%s: (.*)$' % key, block, re.M).group(1)


def test_house_rules(part):
    for text in (part, _read('tests', 'test_ha_interrupted_ui.py')):
        assert EM_DASH not in text
    assert part.count('LW Oct') == 0, 'the tag sits on the mount, once'


# -- runtime --------------------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(cls=_RecoveryServer, **kw):
        app = _App(browser, cls(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _settings(app):
    """The HA settings of c1, once its status is there."""
    return _open_ha_settings(app, wait='[data-ha-node-claim]')


def test_runtime_an_admin_starts_the_moved_guests(open_app):
    app = open_app(runs=[_run(RUN_A, moved=[101, 102], held=[103], guests_open=[104])], start_ok={102: False})
    page = app.page
    modal = _settings(app)
    card = modal.locator('[data-ha-node-interrupted]')
    assert card.get_attribute('data-ha-node-interrupted') == '1'
    assert card.locator('h4').inner_text().strip() == 'Interrupted node recoveries'
    assert card.locator('p').first.inner_text().startswith('A former leader stopped while it recovered a failed node.')
    run = card.locator(f'[data-ha-node-run="{RUN_A}"]')
    assert run.inner_text().startswith('Recovery of pve2 by dddddddd (epoch 7)')
    assert '10 minutes ago' in run.inner_text()
    moved = run.locator('[data-ha-node-run-moved]')
    assert moved.locator('p').inner_text().strip() == 'Moved and not started: 101 (web01), 102 (db01)'
    held = run.locator('[data-ha-node-run-held]')
    assert held.locator('p').first.inner_text().strip() == 'Held on purpose: 103 (mail01)'
    assert run.locator('[data-ha-node-run-held-note]').inner_text().strip() == (
        'pve2 was online when these guests were moved, so they were not started: it may still run them without a '
        'config. Check pve2 before you start them by hand.')
    assert held.locator('button').count() == 0
    assert run.locator('[data-ha-node-run-open]').inner_text().strip() == (
        'A step was begun for these guests and the cluster does not list them now: 104')
    assert run.get_by_role('button', name='Start the moved guests').count() == 1
    assert not [c for c in app.server.calls if 'interrupted-recoveries' in c[1]]

    reads = app.server.calls.count(('GET', '/api/clusters/c1/ha/status'))
    run.get_by_role('button', name='Start the moved guests').click()
    result = run.locator('[data-ha-node-run-result]')
    result.wait_for(timeout=5000)
    assert app.server.bodies[START] == [{'runs': [RUN_A]}]
    lines = result.locator('p').all_inner_texts()
    assert lines == ['Started: 101 (web01)', 'Not started: 102 (db01)']
    assert _wait_for_toast(page, 'Some of the moved guests did not start'), _toasts(page)
    # the status is read again: 101 runs now and leaves the list, the run stays for the rest
    assert _wait_for(page, lambda: app.server.calls.count(('GET', '/api/clusters/c1/ha/status')) > reads)
    assert _wait_for(page, lambda: moved.locator('p').inner_text().strip() == 'Moved and not started: 102 (db01)')
    # the name of a started guest stays with it, though it left the run
    assert result.locator('p').all_inner_texts() == ['Started: 101 (web01)', 'Not started: 102 (db01)']
    assert not app.errors, app.errors


def test_runtime_a_run_with_nothing_left_goes(open_app):
    app = open_app(runs=[_run(RUN_B, moved=[105])])
    page = app.page
    modal = _settings(app)
    modal.locator(f'[data-ha-node-run="{RUN_B}"]').get_by_role('button', name='Start the moved guests').click()
    assert _wait_for_toast(page, 'The moved guests were started'), _toasts(page)
    modal.locator('[data-ha-node-interrupted]').wait_for(state='detached', timeout=5000)
    assert app.server.bodies[START] == [{'runs': [RUN_B]}]
    assert not app.errors, app.errors


def test_runtime_held_guests_get_their_note_and_no_start(open_app):
    app = open_app(runs=[_run(RUN_C, node='pve1', held=[103], epoch=9, instance='e' * 32)])
    modal = _settings(app)
    run = modal.locator(f'[data-ha-node-run="{RUN_C}"]')
    assert run.inner_text().startswith('Recovery of pve1 by eeeeeeee (epoch 9)')
    assert run.get_by_role('button', name='Start the moved guests').count() == 0
    assert run.locator('[data-ha-node-run-held-note]').inner_text().startswith('pve1 was online when these guests')
    assert run.get_by_role('button', name='Dismiss').count() == 1
    assert not app.errors, app.errors


def test_runtime_dismiss_asks_first(open_app):
    app = open_app(runs=[_run(RUN_A, moved=[101]), _run(RUN_C, held=[103])])
    page = app.page
    modal = _settings(app)
    card = modal.locator('[data-ha-node-interrupted]')
    assert card.get_attribute('data-ha-node-interrupted') == '2'
    run = card.locator(f'[data-ha-node-run="{RUN_C}"]')
    run.get_by_role('button', name='Dismiss').click()
    ask = run.locator('[data-ha-node-run-ask]')
    assert ask.inner_text().startswith('Dismiss this run? It is no longer listed or reported. Nothing on the cluster changes.')
    ask.get_by_role('button', name='Cancel').click()
    ask.wait_for(state='detached', timeout=3000)
    assert DISMISS not in app.server.bodies
    run.get_by_role('button', name='Dismiss').click()
    run.locator('[data-ha-node-run-ask]').get_by_role('button', name='Dismiss').click()
    assert _wait_for_toast(page, 'Run dismissed'), _toasts(page)
    run.wait_for(state='detached', timeout=5000)
    assert app.server.bodies[DISMISS] == [{'runs': [RUN_C]}]
    # the other run is untouched
    assert card.get_attribute('data-ha-node-interrupted') == '1'
    assert not app.errors, app.errors


def test_runtime_a_refusal_shows_the_servers_words_at_its_run(open_app):
    app = open_app(runs=[_run(RUN_A, moved=[101])], start_refusal=(400, {'error': 'Node recoveries exist on Proxmox '
                                                                                  'clusters only'}))
    page = app.page
    modal = _settings(app)
    run = modal.locator(f'[data-ha-node-run="{RUN_A}"]')
    run.get_by_role('button', name='Start the moved guests').click()
    error = run.locator('[data-ha-node-run-error]')
    error.wait_for(timeout=3000)
    assert error.inner_text().strip() == 'Node recoveries exist on Proxmox clusters only'
    assert run.locator('[data-ha-node-run-result]').count() == 0
    page.wait_for_timeout(300)
    assert not any('moved guests' in t for t in _toasts(page))
    assert not app.errors, app.errors


@pytest.mark.parametrize('who,shown', [('admin', True), ('ha.config', True), ('ha.view', False), ('standby', False)])
def test_runtime_only_who_holds_ha_config_sees_the_runs(open_app, who, shown):
    """ha.view reads the status too, the runs included: the UI shows them, and the buttons that
    would be refused, only to who holds ha.config. A standby that does not forward changes
    nothing either."""
    kw = {'admin': {}, 'ha.config': dict(admin=False, permissions=VIEW + ['ha.config']),
          'ha.view': dict(admin=False, permissions=VIEW), 'standby': dict(role='standby')}[who]
    app = open_app(runs=[_run(RUN_A, moved=[101], held=[103])], **kw)
    page = app.page
    modal = _settings(app)
    card = modal.locator('[data-ha-node-interrupted]')
    if not shown:
        page.wait_for_timeout(500)
        assert card.count() == 0
        assert 'Interrupted node recoveries' not in modal.inner_text()
        assert not [c for c in app.server.calls if 'interrupted-recoveries' in c[1]]
        assert not app.errors, app.errors
        return
    card.locator(f'[data-ha-node-run="{RUN_A}"]').get_by_role('button', name='Start the moved guests').click()
    assert _wait_for_toast(page, 'The moved guests were started'), _toasts(page)
    assert app.server.bodies[START] == [{'runs': [RUN_A]}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['missing', 'empty', 'no_run_id'])
def test_runtime_nothing_shows_without_runs(open_app, case):
    kw = {'missing': dict(runs_key=False), 'empty': dict(runs=[]),
          'no_run_id': dict(runs=[dict(_run(RUN_A, moved=[101]), run='')])}[case]
    app = open_app(**kw)
    modal = _settings(app)
    app.page.wait_for_timeout(300)
    assert modal.locator('[data-ha-node-interrupted]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_late_answer_fills_only_its_own_cluster(open_app):
    """Start sent for c1, answered once the settings of c2 are open: nothing of it shows there,
    no toast, and c2's status stays c2's."""
    app = open_app(cls=_TwoClusters, runs=[_run(RUN_A, moved=[101])], c2_runs=[_run(RUN_C, node='pve9', held=[201])])
    page = app.page
    modal = _settings(app)
    app.server.hold.add(('POST', START))
    modal.locator(f'[data-ha-node-run="{RUN_A}"]').get_by_role('button', name='Start the moved guests').click()
    assert _wait_for(page, lambda: len(app.server.held) == 1)
    _close_ha_settings(page)
    m2 = _open_c2_settings(app)
    run = m2.locator(f'[data-ha-node-run="{RUN_C}"]')
    run.wait_for(timeout=5000)
    reads = app.server.calls.count(('GET', '/api/clusters/c2/ha/status'))
    app.server.hold.clear()
    app.server.release()
    page.wait_for_timeout(1200)
    assert m2.locator(f'[data-ha-node-run="{RUN_A}"]').count() == 0
    assert m2.locator('[data-ha-node-run-result]').count() == 0
    assert run.inner_text().startswith('Recovery of pve9 by dddddddd (epoch 7)')
    assert not any('moved guests' in t for t in _toasts(page)), _toasts(page)
    assert app.server.calls.count(('GET', '/api/clusters/c2/ha/status')) == reads
    # c1 did start it: the request went out once, to c1
    assert app.server.bodies[START] == [{'runs': [RUN_A]}]
    assert not [c for c in app.server.calls if c[1].startswith('/api/clusters/c2/ha/interrupted')]
    assert not app.errors, app.errors


def test_runtime_in_german(open_app):
    app = open_app(language='de', runs=[_run(RUN_A, moved=[101], held=[103], guests_open=[104])])
    modal = _open_ha_settings(app, settings='Einstellungen', button='Split-Brain Prävention', wait='[data-ha-node-interrupted]')
    card = modal.locator('[data-ha-node-interrupted]')
    text = card.inner_text()
    for needle in ('Unterbrochene Node-Wiederherstellungen', 'Wiederherstellung von pve2 durch dddddddd (Epoche 7)',
                   'Verschoben und nicht gestartet: 101 (web01)', 'Absichtlich zurückgehalten: 103 (mail01)',
                   'pve2 war online, als diese Gäste verschoben wurden', 'Verschobene Gäste starten', 'Verwerfen'):
        assert needle in text, needle
    assert 'haNode' not in text
    for english in ('Interrupted', 'Moved and not started', 'Held on purpose', 'Dismiss'):
        assert english not in text, english
    assert not app.errors, app.errors


def test_runtime_the_cloud_ha_page_names_the_guests_left(open_app):
    """The Cloud layout has no HA settings dialog: it names the guests an interrupted recovery
    left and says where to start or dismiss them."""
    app = open_app(layout='cloud', runs=[_run(RUN_A, moved=[101], held=[103], guests_open=[104])])
    page = app.page
    page.get_by_text('High Availability', exact=True).first.click()
    line = page.locator('[data-ha-node-cloud-line="interrupted"]')
    line.wait_for(timeout=5000)
    hint = 'Start or dismiss them in the HA settings of the cluster (Modern or Corporate layout)'
    assert line.inner_text().strip() == f'Interrupted node recoveries: 101, 103, 104 - {hint}'
    assert line.get_attribute('title') == hint
    assert not app.errors, app.errors
