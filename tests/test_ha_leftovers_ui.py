"""Two of the points left open when serving members were built (#625), in the web UI.

1. The node list on a member that forwards shows the maintenance and update of its nodes as
   the leader runs them: the dashboard reads /node-progress there (the server forwards it,
   tests/test_ha_leftovers.py) and lays it over the /metrics this instance reads itself.
2. Force Password Reset follows the rule every change follows (haReadOnly): usable while
   the member forwards, locked while it cannot. The settings around it stay locked on
   every standby (haStandby): POST /api/settings/server is refused there, forwarding or not.

Source checks, then the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py (skipped where Playwright is not installed).

LW Oct 2026
"""
import re

import pytest

from test_ha_ui import (_read, _function, _labels, _settings_tab, _toasts, browser, open_app,  # noqa: F401
                        CLUSTER, VM, NODE_METRICS, SSE_TOKEN, SETTINGS_READS)

FIELDS = ['maintenance_mode', 'maintenance_task', 'maintenance_acknowledged', 'is_updating', 'update_task']


@pytest.fixture(scope='module')
def ctx():
    return _read('web', 'src', 'contexts.js')


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def security():
    return _function(_read('web', 'src', 'security.js'), 'SecuritySettingsSection')


# -- 1. the leader's node progress ------------------------------------------------------------

def test_the_overlay_takes_the_five_fields_the_server_sends(ctx):
    body = ctx[ctx.index('const HA_NODE_JOB_FIELDS = '):]
    body = body[:body.index('\n        }\n') + 10]
    fields = re.search(r"const HA_NODE_JOB_FIELDS = \[([^\]]*)\];", body).group(1)
    assert [f.strip().strip("'") for f in fields.split(',')] == FIELDS
    # only for the cluster the answer is about, and only the nodes it names
    assert "progress && progress.cluster === clusterId ? progress.nodes : null" in body
    assert 'if (!metrics || !nodes || typeof nodes !== \'object\') return metrics;' in body
    assert 'out[name] = { ...here, ...job };' in body
    # the route answers those fields for every node it names
    vms = _read('pegaprox', 'api', 'vms.py')
    route = vms[vms.index('def get_node_progress('):]
    route = route[:route.index('\n\n\n')]
    for key in FIELDS:
        assert f"'{key}'" in route or f'{key}=' in route, key


def test_the_dashboard_lays_it_over_its_own_metrics(dash):
    main = _function(dash, 'PegaProxDashboard')
    assert 'const [ownClusterMetrics, setClusterMetrics] = useState({});' in main
    assert 'const [leaderNodeProgress, setLeaderNodeProgress] = useState(null);' in main
    memo = ('const clusterMetrics = useMemo(() => haWithLeaderProgress(ownClusterMetrics, '
            'leaderNodeProgress, selectedCluster?.id),')
    assert memo in main
    # declared before anything in the render reads it, and the only one of that name
    assert main.count('const [clusterMetrics,') == 0 and main.count('const clusterMetrics =') == 1
    assert main.index(memo) < main.index('clusterMetrics', main.index(memo) + len(memo))
    # every setter writes this instance's own figures
    assert 'setOwnClusterMetrics' not in main


def test_only_a_member_that_forwards_asks_the_leader(dash):
    main = _function(dash, 'PegaProxDashboard')
    at = main.index('`${API_URL}/clusters/${clusterId}/node-progress`')
    effect = main[main.rindex('useEffect(() => {', 0, at):]
    effect = effect[:effect.index('}, [selectedCluster?.id, haStandby, haReadOnly]);') + 60]
    assert 'setLeaderNodeProgress(null);' in effect
    assert 'if (!clusterId || !haStandby || haReadOnly) return;' in effect
    assert 'setLeaderNodeProgress({ cluster: clusterId, nodes: data.nodes });' in effect
    assert 'const timer = setInterval(poll, 5000);' in effect
    assert 'return () => { gone = true; clearInterval(timer); };' in effect
    # a quiet background read: the timeout every poll of this view has
    assert '{ timeout: POLL_TIMEOUT_MS }' in effect


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('haWithLeaderProgress', '/node-progress', 'HA_NODE_JOB_FIELDS'):
        assert needle in bundle, needle


# -- 2. Force Password Reset ------------------------------------------------------------------

def _spans(view, opening):
    return [(m.start(), view.index('</fieldset>', m.start())) for m in re.finditer(re.escape(opening), view)]


def test_the_reset_follows_the_forwarding_and_the_settings_stay_locked(security):
    assert re.search(r'const \{[^}]*\bhaReadOnly\b[^}]*\} = useAuth\(\);', security)
    view = security[security.index('\n            return (\n'):]
    locked = _spans(view, '<fieldset disabled={haStandby}')
    forwarded = _spans(view, '<fieldset disabled={haReadOnly}')
    assert len(forwarded) == 1 and len(locked) == 3
    button = view.index('onClick={() => setShowResetConfirm(true)}')
    confirm = view.index('onClick={resetAllPasswords}')
    inside = lambda at, spans: any(s < at < e for s, e in spans)  # noqa: E731
    assert inside(button, forwarded) and not inside(button, locked)
    # the confirmation box sits in no locked part either
    assert not inside(confirm, locked) and not inside(confirm, forwarded)
    # every field that saves the settings stays in a locked part
    saves = [m.start() for m in re.finditer(re.escape('saveSettings('), view)]
    assert saves and all(inside(at, locked) for at in saves)
    # one note for the locked settings, before the first of them
    assert view.count('<HaSettingsOnActive') == 1
    assert view.index('{haStandby && <HaSettingsOnActive />}') < locked[0][0]


# -- runtime ----------------------------------------------------------------------------------

NODES = {'pve1': dict(NODE_METRICS['pve1'], maintenance_task=None, update_task=None),
         'pve2': dict(NODE_METRICS['pve1'], maintenance_task=None, update_task=None)}
EVACUATING = {'node': 'pve1', 'status': 'evacuating', 'total_vms': 5, 'migrated_vms': 2,
              'progress_percent': 40.0, 'failed_vms': [], 'pending_vms': [],
              'current_vm': {'vmid': 103, 'name': 'app03'}, 'acknowledged': False}
UPDATING = {'node': 'pve2', 'status': 'running', 'phase': 'apt_upgrade', 'reboot': True,
            'output_lines': [{'timestamp': '2026-10-03T01:00:00', 'text': 'Unpacking pve-manager (9.0.4)'}]}
LEADER = {'nodes': {
    'pve1': {'maintenance_mode': True, 'maintenance_task': EVACUATING, 'maintenance_acknowledged': False,
             'is_updating': False, 'update_task': None},
    'pve2': {'maintenance_mode': False, 'maintenance_task': None, 'maintenance_acknowledged': False,
             'is_updating': True, 'update_task': UPDATING}}}
PROGRESS = ('GET', '/api/clusters/c1/node-progress')


def _progress_calls(app):
    return [c for c in app.server.calls if c == PROGRESS]


def _open_nodes(app):
    app.page.get_by_text('Testi').first.click()
    app.page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    app.page.wait_for_timeout(400)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_forwarding_member_shows_the_leaders_node_jobs(open_app, layout):
    app = open_app(role='standby', layout=layout, forward_writes=True, serve_assigned=True,
                   clusters=[CLUSTER], resources=[VM], metrics=NODES,
                   extra={**SSE_TOKEN, PROGRESS: (200, LEADER)})
    page = app.page
    if layout == 'modern':
        _open_nodes(app)
        page.get_by_text('Evacuating...').first.wait_for(timeout=8000)
        page.get_by_text('2 / 5 VMs').first.wait_for(timeout=3000)
        page.get_by_text('app03').first.wait_for(timeout=3000)
        page.get_by_text('Update running').first.wait_for(timeout=3000)
        page.get_by_text('Unpacking pve-manager (9.0.4)').first.wait_for(timeout=3000)
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('.corp-tree-child', has_text='pve1 (Maintenance)').first.wait_for(timeout=8000)
        page.locator('.corp-tree-child', has_text='pve2 (Updating)').first.wait_for(timeout=3000)
    # asked again while the page is open, not once
    first = len(_progress_calls(app))
    page.wait_for_timeout(5600)
    assert first >= 1 and len(_progress_calls(app)) > first
    assert not app.errors, app.errors


@pytest.mark.parametrize('role,forward', [('active', False), ('standby', False)])
def test_runtime_nobody_else_asks_for_it(open_app, role, forward):
    """The leader has it in its own /metrics; a member that does not forward would only read
    its own (empty) copy. Both show what /metrics says."""
    app = open_app(role=role, layout='modern', forward_writes=forward, clusters=[CLUSTER], resources=[VM],
                   metrics=NODES, extra={**SSE_TOKEN, PROGRESS: (200, LEADER)})
    _open_nodes(app)
    app.page.wait_for_timeout(5600)
    assert _progress_calls(app) == []
    labels = app.page.locator('body').inner_text()
    assert 'Evacuating...' not in labels and 'Update running' not in labels
    assert not app.errors, app.errors


def test_runtime_a_node_the_leader_does_not_name_keeps_its_own(open_app):
    """A node in maintenance here and not named by the leader (the answer of a member whose
    leader is away comes from the member itself): what /metrics says stays."""
    nodes = dict(NODES, pve1=dict(NODES['pve1'], maintenance_mode=True,
                                  maintenance_task=dict(EVACUATING, status='completed')))
    app = open_app(role='standby', layout='modern', forward_writes=True, clusters=[CLUSTER], resources=[VM],
                   metrics=nodes, extra={**SSE_TOKEN, PROGRESS: (200, {'nodes': {}})})
    _open_nodes(app)
    page = app.page
    page.get_by_text('Maintenance Mode').first.wait_for(timeout=5000)
    page.get_by_text('Ready').first.wait_for(timeout=3000)
    assert _progress_calls(app)
    assert 'Update running' not in page.locator('body').inner_text()
    assert not app.errors, app.errors


def test_runtime_the_overlay_on_its_own(open_app):
    """haWithLeaderProgress in the browser, as the bundle has it."""
    app = open_app(role='standby', layout='modern', forward_writes=True, extra=SSE_TOKEN)
    src = _read('web', 'src', 'contexts.js')
    start = src.index('const HA_NODE_JOB_FIELDS = ')
    end = src.index('\n        }\n', src.index('function haWithLeaderProgress(')) + 10
    out = app.page.evaluate('''([src, leader]) => {
        const f = new Function(src + '; return haWithLeaderProgress;')();
        const here = {pve1: {cpu_percent: 7, maintenance_mode: false, is_updating: false},
                      pve2: {cpu_percent: 9, maintenance_mode: true, maintenance_task: {status: 'completed'}},
                      pve3: {cpu_percent: 1}};
        const merged = f(here, {cluster: 'c1', nodes: leader}, 'c1');
        return {
            merged,
            otherCluster: f(here, {cluster: 'c2', nodes: leader}, 'c1') === here,
            none: f(here, null, 'c1') === here,
            empty: f(here, {cluster: 'c1', nodes: {}}, 'c1') === here,
            unknownNode: f(here, {cluster: 'c1', nodes: {pve9: leader.pve1}}, 'c1') === here,
            untouched: here.pve1.maintenance_mode === false,
        };
    }''', [src[start:end], {'pve1': LEADER['nodes']['pve1'], 'pve2': {'is_updating': True, 'update_task': UPDATING}}])
    assert out['otherCluster'] and out['none'] and out['empty'] and out['unknownNode'] and out['untouched']
    merged = out['merged']
    assert merged['pve1']['cpu_percent'] == 7 and merged['pve1']['maintenance_task']['status'] == 'evacuating'
    # a node the leader names takes all five fields from it, missing ones as "none"
    assert {k: merged['pve2'][k] for k in FIELDS} == {
        'maintenance_mode': False, 'maintenance_task': None, 'maintenance_acknowledged': False,
        'is_updating': True, 'update_task': UPDATING}
    assert merged['pve3'] == {'cpu_percent': 1}


EXPIRY_ON = {('GET', '/api/settings/server'): (200, dict(SETTINGS_READS[('GET', '/api/settings/server')][1],
                                                         password_expiry_enabled=True))}
RESET = ('POST', '/api/security/password-expiry/reset-all')


@pytest.mark.parametrize('role,forward', [('standby', True), ('standby', False), ('active', False)])
def test_runtime_force_password_reset_goes_where_changes_go(open_app, role, forward):
    app = open_app(role=role, layout='modern', forward_writes=forward,
                   extra={**SSE_TOKEN, **EXPIRY_ON, RESET: (200, {'success': True, 'reset_count': 3,
                                                                   'message': 'Password expiry reset for 3 users'})})
    page = app.page
    standby, usable = role == 'standby', not (role == 'standby' and not forward)
    app.open_settings()
    _settings_tab(app, 'Security Settings')
    page.get_by_text('Force Password Reset').first.wait_for(timeout=5000)
    button = page.get_by_role('button', name='Reset All', exact=True).first
    assert button.is_enabled() is usable
    # the settings themselves stay locked on every standby: their save is refused there
    expiry_days = page.locator('input[type="number"][min="7"][max="365"]').first
    assert expiry_days.is_enabled() is (not standby)
    assert page.locator('input[type="number"][min="1"][max="20"]').first.is_enabled() is (not standby)
    if usable:
        button.click()
        page.get_by_text('Confirm Password Reset').first.wait_for(timeout=3000)
        page.get_by_role('button', name='Reset All', exact=True).last.click()
        page.get_by_text('Password expiry reset for 3 users').first.wait_for(timeout=5000)
        assert RESET in app.server.calls
    else:
        assert RESET not in app.server.calls
    assert not [c for c in app.server.calls if c == ('POST', '/api/settings/server')]
    assert not [t for t in _toasts(page) if 'standby' in t.lower()], _toasts(page)
    assert not app.errors, app.errors
