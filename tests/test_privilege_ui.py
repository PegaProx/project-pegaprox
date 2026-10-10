"""Least privilege in the web UI: the role recipe (Add Cluster, Check connection), the list of
what works with a cluster's connection (Check connection, Re-configure) and the rolling
update that waits for its quorum (Update Manager).

The routes are tested in tests/test_pve_access_recipe_capabilities.py and
tests/test_rolling_quorum_gate.py. These read the source and the bundle, and the runtime
tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.

LW Oct 2026
"""
import copy
import json
import re

import pytest

from pegaprox.core import pve_access
from test_ha_ui import BASE, CLUSTER, LANGS, _App, _blocks, _classes, _read, browser, open_app  # noqa: F401
from test_connection_check_ui import PATH as CHECK, REPORT, _open_from_corporate_menu
from test_node_credentials_ui import _extra as _reconfigure_extra, _open_reconfigure
from test_rolling_runs_ui import INTERRUPTED, RESUME, _paused_banner, _Server as _RollServer

CAPS = '/api/clusters/c1/capabilities'
RECIPE = '/api/pve-role-recipe'
PREFIX = r'(?:capab[A-Z]\w*|pveRole[A-Z]\w*|rollQuorum(?!Text)[A-Z]\w*|connCheckFeat(?:Networks|Pools|Mappings|Replication|HaConfig))'


def _src():
    modals = _read('web', 'src', 'create_modals.js')
    recipe = modals[modals.index('// LW Oct 2026 - least privilege.'):modals.index('function AddClusterModal(')]
    add = modals[modals.index('{/* LW Oct 2026 - the least-privilege account or token'):
                 modals.index('{showSshSettings && (')]
    at = modals.index('<NodeCredentialsSection clusterId={reconfigureConfig._cluster_id}')
    reconf = modals[at:modals.index("<Slider label={t('migrationThreshold')}", at)]
    dash = _read('web', 'src', 'dashboard.js')
    # the whole connection check: its feature words name what the check reports missing
    check = dash[dash.index('        // LW Oct 2026 - the connection check of one PVE cluster'):
                 dash.index('// NS: Mar 2026 - Topology View redesign (#142)')]
    sec = _read('web', 'src', 'security.js')
    quorum = (sec[sec.index('// why a run waits for its quorum'):sec.index('const loadRollHistory = async')]
              + sec[sec.index("rollingUpdate.paused_reason === 'quorum' ? ("):sec.index('{/* Header with cancel button */}')]
              + sec[sec.index('// LW Oct 2026 - acceptRisk: Continue anyway'):sec.index('// Load cached update status')])
    return {'recipe': recipe, 'add': add, 'reconfigure': reconf, 'check': check, 'quorum': quorum}


def _used():
    keys = set()
    for part in _src().values():
        keys |= set(re.findall(r"'(%s)'" % PREFIX, part))
    return keys


# -- source ----------------------------------------------------------------------------------

def test_every_key_exists_once_per_language_and_none_is_unused():
    used = _used()
    assert len(used) > 70, len(used)
    for lang, block in _blocks().items():
        for key in used:
            n = len(re.findall(r'^ +%s: ' % key, block, re.M))
            assert n == 1, (lang, key, n)
        assert set(re.findall(r'^ +(%s): ' % PREFIX, block, re.M)) == used, lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_keys_sit_with_their_neighbours():
    for lang, block in _blocks().items():
        assert 0 < block.index('capabTitle:') - block.index('connCheckFeatSdn:') < 2000, lang
        assert 0 < block.index('rollQuorumHeld:') - block.index('rollRunCancel:') < 400, lang


def test_everything_the_server_sends_has_words():
    recipe = _src()['recipe']
    for fid, _feats, _extra in pve_access.CAPABILITIES:
        assert f'{fid}: ' in recipe, fid
    for f in pve_access.OPTIONAL:
        assert f'{f}: ' in recipe, f
    for need, _feats in pve_access.NOT_BY_ROLE:
        assert f'{need}: ' in recipe, need
    codes = {'not_checked', 'not_connected', 'priv_unread', 'ssh_disabled', 'ssh_no_credentials', 'ssh_some_nodes',
             'ssh_password', 'token_login', 'no_password', 'root_token', 'root_only', 'root_password', 'root_unknown'}
    src = open(pve_access.__file__, encoding='utf-8').read()
    sent = set(re.findall(r"'code': '([a-z_]+)'", src)) | {'not_checked', 'not_connected', 'priv_unread'}
    assert sent - {'priv'} <= codes, sent - codes
    for code in codes:
        assert f'{code}: ' in recipe, code
    for status in ('yes', 'partial', 'no', 'unknown'):
        assert f'{status}: {{' in recipe, status


def test_no_em_dash_icons_exist_and_classes_are_in_the_build():
    parts = _src()
    code = ''.join(parts.values())
    assert '\u2014' not in code and '\u2013' not in code
    for block in _blocks().values():
        for line in re.findall(r'^ +%s: .*$' % PREFIX, block, re.M):
            assert '\u2014' not in line and '\u2013' not in line, line
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r'Icons\.([A-Za-z]+)', code)) | {'CheckCircle', 'AlertTriangle', 'XCircle', 'Info'}:
        assert re.search(r'\b%s: \(' % name, icons), name
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(code)
    assert len(names) > 60
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_continue_anyway_needs_what_continue_needs():
    sec = _read('web', 'src', 'security.js')
    banner = sec[sec.index('data-testid="rolling-paused"'):sec.index('{/* Header with cancel button */}')]
    gate = banner.index(") : hasPerm('node.update') && (")
    assert banner.index('data-testid="rolling-continue-anyway"') > gate
    # a click on the plain Continue hands its event over: only a real true asks for the risk
    assert 'acceptRisk === true' in _src()['quorum']


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function PveRoleRecipe(', 'function ClusterCapabilities(', '/pve-role-recipe', '/capabilities',
                   'rolling-continue-anyway', 'accept_quorum_risk', 'data-pve-role-toggle'):
        assert needle in bundle, needle
    for key in _used():
        assert key in bundle, key


# -- runtime: Check connection ------------------------------------------------------------------

def _caps(**over):
    body = {
        'cluster_id': 'c1', 'connected': True,
        'login': {'type': 'api_token', 'user': 'ops@pve', 'token_id': 'ops@pve!pegaprox', 'realm': 'pve',
                  'root': False, 'has_password': False, 'ssh_key': False, 'ssh_disabled': False,
                  'node_passwords': 2},
        'privileges': {'state': 'read', 'source': 'kept', 'checked_at': '2026-10-10T08:00:00+00:00',
                       'missing': []},
        'features': [
            {'id': 'consoles', 'status': 'partial', 'via': 'api',
             'needs': [{'code': 'priv', 'privs': ['VM.Console'], 'path': '/vms', 'partial': True}]},
            {'id': 'nodeShell', 'status': 'partial', 'via': 'ssh',
             'needs': [{'code': 'ssh_some_nodes', 'nodes': ['pve1', 'pve2']}]},
            {'id': 'rollingUpdates', 'status': 'no', 'via': 'ssh',
             'needs': [{'code': 'priv', 'privs': ['Sys.Modify'], 'path': '/', 'partial': False},
                       {'code': 'ssh_some_nodes', 'nodes': ['pve1', 'pve2']}]},
            {'id': 'rawDevices', 'status': 'no', 'via': 'api', 'needs': [{'code': 'root_token'}]},
            {'id': 'guestTerminal', 'status': 'no', 'via': 'api', 'needs': [{'code': 'token_login'}]},
            {'id': 'backups', 'status': 'yes', 'via': 'api', 'needs': []},
        ],
    }
    body.update(over)
    return body


def _extra(**kw):
    return {('GET', CAPS): (200, _caps(**kw)), ('POST', CHECK): (200, REPORT),
            ('GET', RECIPE): (200, pve_access.recipe(None))}


def _gets(app, path):
    return [u for u in app.server.urls if u.split('?')[0].endswith(path)]


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_the_check_lists_what_works_and_offers_the_role(open_app, layout):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=_extra())
    page = app.page
    if layout == 'corporate':
        _open_from_corporate_menu(app)
    else:
        page.locator('button[title="Check connection"]').first.click()
        page.locator('[data-conn-check="c1"]').wait_for(timeout=3000)
    box = page.locator('[data-capabilities="c1"]')
    page.locator('[data-cap="backups"]').wait_for(timeout=5000)
    # shown from what is kept: the check itself was not started
    assert ('POST', CHECK) not in app.server.calls and len(_gets(app, CAPS)) == 1
    assert '?refresh' not in _gets(app, CAPS)[0]
    status = {f: page.locator(f'[data-cap="{f}"]').get_attribute('data-cap-status')
              for f in ('consoles', 'nodeShell', 'rollingUpdates', 'backups')}
    assert status == {'consoles': 'partial', 'nodeShell': 'partial', 'rollingUpdates': 'no', 'backups': 'yes'}
    text = box.inner_text()
    for needle in ('Signs in as ops@pve!pegaprox - API token', 'No SSH key', '2 node(s) with a root password',
                   'Has VM.Console only on some guests, pools or storages below /vms',
                   'Only on the nodes with a root password of their own: pve1, pve2', 'Needs Sys.Modify on /',
                   'Proxmox allows this to root@pam only, never to an API token',
                   'Needs a user name and password, an API token cannot do this', 'Rolling updates', 'not available'):
        assert needle in text, needle

    box.locator('button', has_text='Read the privileges').click()
    page.wait_for_timeout(600)
    assert _gets(app, CAPS)[-1].endswith('?refresh=1')
    # a new check reads the list again
    before = len(_gets(app, CAPS))
    page.locator('[data-conn-check] button', has_text='Run check').click()
    page.locator('[data-check-item="ssh:pve2"]').wait_for(timeout=5000)
    page.wait_for_timeout(600)
    assert len(_gets(app, CAPS)) == before + 1

    # the role, folded until asked for
    assert not _gets(app, RECIPE)
    page.locator('[data-check-toggle="role"]').click()
    pre = page.locator('[data-pve-commands="token"]')
    pre.wait_for(timeout=5000)
    assert "pveum aclmod / --tokens 'pegaprox@pve!pegaprox' --roles PegaProx" in pre.inner_text()
    assert 'Then add the cluster with pegaprox@pve!pegaprox as user name' in page.locator('[data-pve-role]').inner_text()
    page.locator('[data-pve-via="account"]').click()
    assert 'pveum passwd pegaprox@pve' in page.locator('[data-pve-commands="account"]').inner_text()
    page.locator('[data-pve-feature="sdn"]').uncheck()
    page.locator('[data-pve-release="8"]').click()
    page.wait_for_timeout(600)
    last = _gets(app, RECIPE)[-1]
    assert 'pve=8' in last and 'sdn' not in last.split('features=')[1].split('&')[0] and 'uploads' in last
    text = page.locator('[data-pve-role]').inner_text()
    assert 'No role can give these' in text and 'root@pam with its password: Raw PCI/USB devices' in text
    assert not app.errors, app.errors


def test_runtime_a_cluster_nobody_checked_says_so(open_app):
    priv = {'state': 'not_checked', 'source': 'not_checked', 'checked_at': None, 'missing': []}
    feats = [{'id': 'consoles', 'status': 'unknown', 'via': 'api', 'needs': [{'code': 'not_checked'}]}]
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER], extra=_extra(privileges=priv, features=feats))
    _open_from_corporate_menu(app)
    row = app.page.locator('[data-cap="consoles"]')
    row.wait_for(timeout=5000)
    assert row.get_attribute('data-cap-status') == 'unknown'
    text = app.page.locator('[data-capabilities="c1"]').inner_text()
    assert 'Privileges not read yet: run the check, or read them now.' in text and 'not known yet' in text
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='corporate', language='de', clusters=[CLUSTER], extra=_extra())
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    page.locator('.corp-context-menu').first.get_by_text('Verbindung prüfen').click()
    page.locator('[data-cap="backups"]').wait_for(timeout=5000)
    text = page.locator('[data-capabilities="c1"]').inner_text()
    assert 'Meldet sich an als ops@pve!pegaprox' in text and 'Proxmox erlaubt das nur root@pam, nie einem API-Token' in text
    page.locator('[data-check-toggle="role"]').click()
    page.locator('[data-pve-commands="token"]').wait_for(timeout=5000)
    assert 'Das kann keine Rolle geben' in page.locator('[data-pve-role]').inner_text()
    assert not app.errors, app.errors


# -- runtime: Add Cluster and Re-configure ------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_adding_a_cluster_offers_the_least_privilege_setup(open_app, layout):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=_extra())
    page = app.page
    if layout == 'corporate':
        page.locator('button[title="Add Cluster"]').first.click()
    else:
        page.locator('button', has_text='Add Cluster').first.click()
        page.get_by_role('button', name=re.compile(r'^Proxmox VE')).first.click()
    toggle = page.locator('[data-pve-role-toggle]')
    toggle.wait_for(timeout=5000)
    assert 'recommended in production' in toggle.inner_text()
    assert not _gets(app, RECIPE)
    toggle.click()
    pre = page.locator('[data-pve-commands="token"]')
    pre.wait_for(timeout=5000)
    assert 'pveum user token add pegaprox@pve pegaprox --privsep 1' in pre.inner_text()
    # nothing in the recipe submits the form
    page.locator('[data-pve-via="account"]').click()
    page.locator('[data-pve-feature="haConfig"]').uncheck()
    page.wait_for_timeout(400)
    assert ('POST', '/api/clusters') not in app.server.calls
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_re_configure_shows_what_works(open_app, layout):
    extra = {**_reconfigure_extra(), **_extra()}
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], extra=extra)
    page = app.page
    _open_reconfigure(app, layout)
    assert not _gets(app, CAPS), 'read before anyone opened it'
    page.locator('[data-capabilities-toggle]').click()
    page.locator('[data-cap="rawDevices"]').wait_for(timeout=5000)
    assert page.locator('[data-cap="rawDevices"]').get_attribute('data-cap-status') == 'no'
    assert not app.errors, app.errors


# -- runtime: a rolling update that waits for its quorum ----------------------------------------

QUORUM = dict(copy.deepcopy(INTERRUPTED), paused_reason='quorum', current_step='paused_quorum',
              paused_details={'node': 'pve1', 'phase': 'maintenance', 'reason': 'would_lose', 'expected': 3,
                              'needed': 2, 'have': 2, 'after': 1, 'offline': ['pve3'],
                              'qdevice': {'present': False, 'connected': False},
                              'message': 'Not going on before pve1 goes into maintenance ...'},
              resume_at={'index': 0, 'phase': 'maintenance'})


class _Server(_RollServer):
    """The rolling update server of test_rolling_runs_ui, with the bodies of Continue kept."""

    def handle(self, route):
        req = route.request
        if req.url.split('?')[0].endswith(RESUME):
            self.bodies.setdefault(RESUME, []).append(json.loads(req.post_data) if req.post_data else {})
        return super().handle(route)


@pytest.fixture
def ui(browser):  # noqa: F811
    apps = []

    def _open(layout='modern', **kw):
        kw.setdefault('run', QUORUM)
        app = _App(browser, _Server(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_run_held_for_its_quorum_says_why_and_continues(ui, layout):
    app = ui(layout=layout)
    banner = _paused_banner(app, layout)
    assert banner.get_attribute('data-reason') == 'quorum'
    text = banner.locator('[data-testid="rolling-quorum"]').inner_text()
    assert ('pve1 is not taken down: it would leave 1 of 3 votes, and the cluster needs 2 for its quorum.'
            in text), text
    assert 'Offline: pve3' in text and 'Continue anyway takes pve1 down all the same' in text
    assert 'The QDevice is not connected.' not in text
    banner.locator('[data-testid="rolling-continue"]').click()
    app.page.wait_for_timeout(1200)
    assert app.server.bodies[RESUME] == [{}]
    assert not app.errors, app.errors


def test_runtime_continue_anyway_asks_first(ui):
    app = ui(layout='modern', run=dict(QUORUM, paused_details=dict(
        QUORUM['paused_details'], qdevice={'present': True, 'connected': False}, offline=[])))
    banner = _paused_banner(app, 'modern')
    assert 'The QDevice is not connected.' in banner.inner_text()
    asked = []

    def dismiss(d):
        asked.append(d.message)
        d.dismiss()
    app.page.once('dialog', dismiss)
    banner.locator('[data-testid="rolling-continue-anyway"]').click()
    app.page.wait_for_timeout(500)
    assert asked and 'Take pve1 down although the cluster may lose its quorum?' in asked[0]
    assert RESUME not in app.server.bodies
    app.page.once('dialog', lambda d: d.accept())
    banner.locator('[data-testid="rolling-continue-anyway"]').click()
    app.page.wait_for_timeout(1200)
    assert app.server.bodies[RESUME] == [{'accept_quorum_risk': True}]
    assert not app.errors, app.errors


def test_runtime_only_a_quorum_hold_offers_continue_anyway_and_a_standby_none(ui):
    app = ui(layout='modern', run=INTERRUPTED)
    banner = _paused_banner(app, 'modern')
    assert banner.locator('[data-testid="rolling-continue"]').count() == 1
    assert banner.locator('[data-testid="rolling-continue-anyway"]').count() == 0
    app = ui(layout='modern', role='standby')
    banner = _paused_banner(app, 'modern')
    assert 'pve1 is not taken down' in banner.inner_text()
    assert banner.locator('[data-testid="rolling-continue-anyway"]').count() == 0
    assert banner.locator('[data-testid="rolling-continue"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_quorum_hold_speaks_german(ui):
    app = ui(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('button', has_text=re.compile(r'^\s*Einstellungen\s*$')).last.click()
    banner = page.locator('[data-testid="rolling-paused"]')
    banner.wait_for(timeout=8000)
    text = banner.inner_text()
    assert 'pve1 wird nicht aus dem Betrieb genommen: es blieben 1 von 3 Stimmen' in text
    assert banner.locator('[data-testid="rolling-continue-anyway"]').inner_text().strip() == 'Trotzdem fortsetzen'
    assert not app.errors, app.errors
