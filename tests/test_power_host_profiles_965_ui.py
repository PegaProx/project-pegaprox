"""Power & Carbon shows each host with its power profile and edits the profiles (#965).

The summary lists every host: own profile or cluster default, the watts it is costed with,
the average draw the estimate comes to (to hold a power meter against), and the part of
its power no guest accounts for. Notes say when the window is only partly covered, when a
guest's host comes from today's placement, and when only the caller's guests are shown.
"Host profiles" edits idle / full-load watts per host: PUT for a changed own profile,
DELETE to go back to the cluster default, nothing for an unchanged row.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
"""
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, _blocks, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS = ['powerHostProfiles', 'powerHostProfilesHint', 'powerHostIdleW', 'powerHostMaxW', 'powerHostGone',
        'powerHostsSaved', 'powerHostSaveFailed', 'powerHostLoadFailed', 'powerPerHost', 'powerProfile',
        'powerProfileHost', 'powerProfileCluster', 'powerOnlineH', 'powerAvgW', 'powerGuests',
        'powerUnallocated', 'powerUnallocatedHint', 'powerCoverage', 'powerNodeEstimated',
        'powerNodeGuessed', 'powerMigrated', 'powerScopedNote', 'powerHostWattsMissing']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _tab():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('function PowerCarbonTab(')
    return src[start:src.index('function CostDashboardTab(', start)]


def _added():
    """The blocks #965 added to the tab: the editor logic, the notes, the host table, the modal."""
    tab = _tab()
    parts = [tab[tab.index('const openHosts = async'):tab.index('const cur = summary?.rates')],
             tab[tab.index('{/* #965 - what is an estimate'):tab.index('{!summary.hosts?.length && summary.by_node')],
             tab[tab.index('{hostForm && ('):]]
    return '\n'.join(parts)


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_every_new_key_is_used():
    used = set(re.findall(r"t\('(power[A-Z]\w*)'\)", _tab()))
    assert set(KEYS) <= used


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in KEYS:
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_dash_in_what_this_change_added():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_added()] + lines:
        assert '—' not in text and '–' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_added()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r'Icons\.(\w+)', _tab())):
        assert re.search(r'^ +%s: \(' % name, icons, re.M), name


def test_the_editor_is_for_admins_off_a_standby_only():
    tab = _tab()
    assert '{canAct && (\n                                <button onClick={openHosts}' in tab.replace('\r\n', '\n')


# -- runtime ------------------------------------------------------------------------------------

SUMMARY = '/api/clusters/c1/power/summary'
PER_VM = '/api/clusters/c1/power/per-vm'
HOSTS = '/api/clusters/c1/power/hosts'
RATES = {'cluster_id': 'c1', 'node_idle_w': 80.0, 'node_max_w': 300.0, 'mem_w_per_gb': 0.3, 'pue': 1.5,
         'kwh_price': 0.3, 'kg_co2_per_kwh': 0.4, 'currency': 'EUR', 'notes': ''}


def _money(kwh):
    return {'kwh': kwh, 'cost': round(kwh * 0.3, 2), 'kg_co2': round(kwh * 0.4, 2)}


def _host(node, profile, idle, mx, kwh, unallocated, status='online'):
    return {'node': node, 'status': status, 'profile': profile, 'idle_w': idle, 'max_w': mx,
            'online_h': 720.0, 'avg_w': round(kwh * 1000 / 1.5 / 720, 1),
            'monthly': _money(kwh), 'monthly_unallocated': _money(unallocated)}


def _summary(scoped=False, missing_h=0.0, estimated=0):
    s = {'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'snapshots_count': 720, 'rates': RATES,
         'scoped': scoped, 'vm_count': 1,
         'coverage': {'window_h': 720, 'covered_h': 720.0 - missing_h, 'missing_h': missing_h,
                      'node_estimated_vms': estimated},
         'window': _money(150.0), 'monthly': _money(150.0),
         'by_node': {'pve1': _money(40.0), 'pve2': _money(110.0)}, 'top_consumers': []}
    if not scoped:
        s['hosts'] = [_host('pve1', 'host', 9.0, 65.0, 40.0, 5.5), _host('pve2', 'cluster', 80.0, 300.0, 110.0, 110.0)]
        s['allocated'] = {'window': _money(34.5), 'monthly': _money(34.5)}
        s['unallocated'] = {'window': _money(115.5), 'monthly': _money(115.5)}
    return s


ROW = {'vmid': '100', 'name': 'web01', 'node': 'pve1', 'type': 'qemu', 'avg_cpu_pct': 5.0, 'avg_mem_pct': 25.0,
       'cores': 2, 'memory_gb': 4.0, 'running_h': 720.0, 'kwh': 34.5, 'cost': 10.35, 'kg_co2': 13.8,
       'low_data': False, 'by_node': {'pve1': 20.0, 'pve2': 14.5}, 'node_estimated': True,
       'monthly_kwh': 34.5, 'monthly_cost': 10.35, 'monthly_co2': 13.8}

HOST_LIST = {'cluster_id': 'c1', 'cluster_profile': {'idle_w': 80.0, 'max_w': 300.0}, 'hosts': [
    {'node': 'pve1', 'in_cluster': True, 'status': 'online', 'cores': 8, 'memory_gb': 32.0, 'profile': 'host',
     'idle_w': 9.0, 'max_w': 65.0, 'notes': 'EliteDesk', 'updated_at': None, 'updated_by': 'root'},
    {'node': 'pve2', 'in_cluster': True, 'status': 'online', 'cores': 20, 'memory_gb': 64.0, 'profile': 'cluster',
     'idle_w': 80.0, 'max_w': 300.0, 'notes': '', 'updated_at': None, 'updated_by': ''},
    {'node': 'pve3', 'in_cluster': True, 'status': 'online', 'cores': 4, 'memory_gb': 16.0, 'profile': 'host',
     'idle_w': 30.0, 'max_w': 90.0, 'notes': '', 'updated_at': None, 'updated_by': 'root'},
]}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(summary=None, **kw):
        extra = dict(SSE_TOKEN)
        extra[('GET', SUMMARY)] = (200, summary or _summary())
        extra[('GET', PER_VM)] = (200, {'enough_data': True, 'cluster_id': 'c1', 'days': 30, 'rates': RATES,
                                        'rows': [ROW]})
        extra[('GET', HOSTS)] = (200, HOST_LIST)
        for node in ('pve1', 'pve2', 'pve3'):
            extra[('PUT', f'{HOSTS}/{node}')] = (200, {'ok': True})
            extra[('DELETE', f'{HOSTS}/{node}')] = (200, {'ok': True, 'removed': True})
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _wait_for(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _open_power(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Reports', exact=True).first.click()
    page.get_by_role('button', name='Power & Carbon', exact=True).first.click()
    page.get_by_text('Monthly kWh').first.wait_for(timeout=5000)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_hosts_with_their_profile_and_what_no_guest_accounts_for(open_app, layout):
    app = open_app(summary=_summary(missing_h=600.0, estimated=1), layout=layout)
    page = _open_power(app)
    table = page.locator('[data-power-hosts]')
    table.wait_for(timeout=5000)
    text = table.inner_text()
    assert 'Per host' in text and 'Own profile' in text and 'Cluster default' in text
    assert '9 / 65' in text and '80 / 300' in text
    notes = page.locator('[data-power-notes]').inner_text()
    assert 'Unallocated: 115.5 kWh' in notes and 'Guests: 34.5 kWh' in notes
    assert 'Estimate from 120 of 720 h of history' in notes
    assert 'For 1 guests the host is taken from where they run today' in notes
    # the guest that moved between hosts, and the one whose host is partly a guess
    assert page.locator('span[title^="Ran on several hosts in this window: pve1 20 kWh, pve2 14.5 kWh"]').count() == 1
    assert page.locator('span[title="Host partly taken from where it runs today"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_confined_caller_gets_the_node_split_and_a_note(open_app):
    app = open_app(summary=_summary(scoped=True))
    page = _open_power(app)
    page.locator('[data-power-notes]').wait_for(timeout=5000)
    assert 'Showing the share of your guests only.' in page.locator('[data-power-notes]').inner_text()
    assert page.locator('[data-power-hosts]').count() == 0
    assert page.get_by_text('Per node').count() == 1
    assert not app.errors, app.errors


def test_runtime_host_profiles_save_only_what_changed(open_app):
    app = open_app()
    page = _open_power(app)
    page.get_by_role('button', name='Host profiles', exact=True).click()
    modal = page.locator('[data-power-host-profiles]')
    modal.wait_for(timeout=5000)
    rows = modal.locator('tbody tr')
    assert rows.count() == 3
    # pve2: inherits, inputs locked until it gets its own profile
    pve2 = rows.nth(1)
    assert pve2.locator('input[type="number"]').first.is_disabled()
    pve2.locator('input[type="checkbox"]').check()
    pve2.locator('input[type="number"]').nth(0).fill('12')
    pve2.locator('input[type="number"]').nth(1).fill('95')
    pve2.locator('input[type="text"]').fill('Kodlix GD90')
    # pve3: back to the cluster default
    rows.nth(2).locator('input[type="checkbox"]').uncheck()
    modal.get_by_role('button', name='Save', exact=True).click()
    modal.wait_for(state='detached', timeout=5000)
    assert app.server.bodies[f'{HOSTS}/pve2'] == [{'idle_w': 12, 'max_w': 95, 'notes': 'Kodlix GD90'}]
    assert ('DELETE', f'{HOSTS}/pve3') in app.server.calls
    # pve1 was not touched, so nothing is written for it
    assert ('PUT', f'{HOSTS}/pve1') not in app.server.calls
    assert ('DELETE', f'{HOSTS}/pve1') not in app.server.calls
    # and the page reads the summary again
    assert _wait_for(page, lambda: app.server.calls.count(('GET', SUMMARY)) == 2)
    assert not app.errors, app.errors


def test_runtime_a_refused_profile_keeps_the_editor_open(open_app):
    app = open_app()
    app.server.extra[('PUT', f'{HOSTS}/pve1')] = (400, {'error': 'max_w must not be below idle_w'})
    page = _open_power(app)
    page.get_by_role('button', name='Host profiles', exact=True).click()
    modal = page.locator('[data-power-host-profiles]')
    modal.wait_for(timeout=5000)
    modal.locator('tbody tr').nth(0).locator('input[type="number"]').nth(1).fill('5')
    modal.get_by_role('button', name='Save', exact=True).click()
    page.get_by_text('pve1: max_w must not be below idle_w').first.wait_for(timeout=5000)
    assert modal.is_visible()


def test_runtime_an_empty_watt_field_is_caught_before_it_is_sent(open_app):
    app = open_app()
    page = _open_power(app)
    page.get_by_role('button', name='Host profiles', exact=True).click()
    modal = page.locator('[data-power-host-profiles]')
    modal.wait_for(timeout=5000)
    modal.locator('tbody tr').nth(0).locator('input[type="number"]').nth(0).fill('')
    modal.get_by_role('button', name='Save', exact=True).click()
    page.get_by_text('pve1: Enter idle and full-load watts').first.wait_for(timeout=5000)
    assert ('PUT', f'{HOSTS}/pve1') not in app.server.calls
    assert modal.is_visible()
