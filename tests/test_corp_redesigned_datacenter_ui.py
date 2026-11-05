"""Round 4 of Corporate Redesigned (Preview): Datacenter > Summary.

The summary of the variant tells the quorum and the state of nodes and resources apart: a cluster
keeps its quorum with nodes offline, so "Quorate" and "Critical" stand side by side. That state is
the dashboard's alert rules over the datacenter status (an offline node and a lost quorum are
critical, round 8), a single node and an XCP-ng pool have no quorum to tell. Nodes,
VMs and containers come from the lists the page holds (templates and other states on their own, the
parts add up to the total), CPU, RAM and storage from the datacenter status with used and free, the
CPU and RAM colours at 80/90 and the storage colours at 70/85. A compact node table fills the rest:
an offline node or one without a status read shows "-", never a 0, and a row opens the node.

What was not read is said: a status that failed, came back without nodes, is old or not readable
for the account, hardware monitoring that is off, active alerts that failed, a QDevice that is not
known. The page draws without waiting for the classic reads of the tab, reads three small things on
open, never one per node, and the votes of the corosync quorum only on a click.

Runs against the fake servers of the other redesign tests with the real backend shapes, and skips
without Playwright. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof).
LW Nov 2026
"""
import copy
import json
import os
import re
import urllib.parse

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS, STATUS, _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, VM, _GuardApp
from test_ha_ui import BASE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src')
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# --- the scene, in the shapes the backend answers ----------------------------------------------

def _status(quorate=True, online=3, offline=1, standalone=False, kind=None, hardware=None,
            vms=(2, 2, 5), cts=(1, 1, 2), cpu=(32, 6.4), mem=(256 * GIB, 64 * GIB), storage=(4096 * GIB, 1024 * GIB)):
    """/datacenter/status as pegaprox/api/vms.py answers it (stopped and total count templates too)."""
    cluster = {'name': 'testi', 'quorate': quorate, 'standalone': standalone, 'version': 7}
    if kind:
        cluster['cluster_type'] = kind

    def part(t, u):
        return {'total': t, 'used': u, 'percent': round(u / t * 100, 1) if t else 0}
    return {'cluster': cluster, 'nodes': {'online': online, 'offline': offline, 'total': online + offline},
            'guests': {'vms': {'running': vms[0], 'stopped': vms[1], 'total': vms[2]},
                       'containers': {'running': cts[0], 'stopped': cts[1], 'total': cts[2]}},
            'resources': {'cpu': part(*cpu), 'memory': part(*mem), 'storage': part(*storage)},
            'hardware': hardware}


def _node(cpu, mem, disk, **kw):
    """One row of /metrics with figures (pegaprox/core/manager.py get_node_status)."""
    mt, dt = 64 * GIB, 100 * GIB
    row = {'status': 'online', 'cpu_percent': cpu, 'mem_percent': mem, 'mem_used': mt * mem / 100, 'mem_total': mt,
           'disk_percent': disk, 'disk_used': dt * disk / 100, 'disk_total': dt, 'netin': 0, 'netout': 0, 'score': 0,
           'uptime': 86400, 'loadavg': ['0.50', '0.40', '0.30'], 'cpuinfo': {'cpus': 8}, 'pveversion': 'pve-manager/8.2.4',
           'ksm': {}, 'kversion': '', 'maintenance_mode': False, 'maintenance_task': None,
           'maintenance_acknowledged': False, 'is_updating': False, 'update_task': None, 'offline': False}
    row.update(kw)
    return row


def _blind(status, **kw):
    """A row without a status read: all figures 0 (the branch of manager.py without status_data)."""
    row = {'status': status, 'cpu_percent': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 'disk_percent': 0,
           'disk_used': 0, 'disk_total': 0, 'netin': 0, 'netout': 0, 'score': 0, 'uptime': 0, 'maintenance_mode': False,
           'maintenance_task': None, 'maintenance_acknowledged': False, 'offline': status != 'online'}
    row.update(kw)
    return row


MAINT = {'node': 'pve4', 'status': 'evacuating', 'total_vms': 2, 'migrated_vms': 1, 'progress_percent': 50.0,
         'failed_vms': [], 'acknowledged': False}
NODES = {'pve1': _node(12.5, 40, 88), 'pve2': _node(85, 60, 72), 'pve3': _blind('offline'),
         'pve4': _node(5, 20, 10, maintenance_mode=True, maintenance_task=MAINT)}
INFO = [{'name': f'pve{i}', 'node': f'pve{i}', 'nodeid': str(i), 'quorum_votes': '1', 'ring0_addr': f'10.0.0.{10 + i}',
         'online': 0 if i == 3 else 1} for i in range(1, 5)]


def _guest(vmid, kind, node, status, template=0):
    return dict(VM, vmid=vmid, name=f'g{vmid}', type=kind, node=node, status=status, template=template)


# VMs: 2 running, 1 stopped, 1 template, 1 paused; containers: 1 running, 1 stopped
GUESTS = [_guest(100, 'qemu', 'pve1', 'running'), _guest(101, 'qemu', 'pve2', 'running'),
          _guest(102, 'qemu', 'pve1', 'stopped'), _guest(103, 'qemu', 'pve1', 'stopped', template=1),
          _guest(104, 'qemu', 'pve2', 'paused'), _guest(200, 'lxc', 'pve1', 'running'),
          _guest(201, 'lxc', 'pve4', 'stopped')]


def _store(name, kind, content, total, used, **kw):
    s = {'storage': name, 'type': kind, 'content': content, 'total': total * GIB, 'used': used * GIB,
         'avail': (total - used) * GIB, 'active': 1, 'enabled': 1, 'shared': False}
    s.update(kw)
    return s


STORES = {'shared': [_store('ceph', 'rbd', 'images,rootdir', 4000, 1000, shared=True, active_on=['pve1', 'pve2', 'pve4'],
                            inactive_on=['pve3'])],
          'local': {'pve1': [_store('local-lvm', 'lvmthin', 'images,rootdir', 100, 60)],
                    'pve2': [_store('local-zfs', 'zfspool', 'images,rootdir', 100, 80)],
                    'pve3': [_store('local-lvm', 'lvmthin', 'images,rootdir', 0, 0, active=0, node_offline=True)],
                    'pve4': [_store('local', 'dir', 'iso,vztmpl,backup', 100, 50)]},
          'nodes': ['pve1', 'pve2', 'pve3', 'pve4'], 'offline_nodes': ['pve3']}
HW = {'health': 'warning', 'available': True, 'checked': 3, 'counts': {'ok': 2, 'warning': 1, 'critical': 0},
      'degraded': [{'node': 'pve2', 'health': 'warning', 'reasons': ['Fan 3: 0 RPM']}]}


def _incident(fid, severity, message, target_type, target_name, **kw):
    """One row of GET /api/clusters/<id>/active-alerts (pegaprox/api/alerts.py get_active_alerts)."""
    row = {'id': fid, 'alert_id': 'r-' + fid, 'severity': severity, 'message': message, 'target_type': target_type,
           'target_name': target_name, 'metric': 'disk', 'current_value': 91, 'threshold': 90, 'operator': '>',
           'triggered_at': '2026-10-30T08:40:00.123456', 'last_fired_at': '2026-10-30T08:59:00.123456',
           'acked_at': None, 'acked_by': None, 'escalation_step': 0, 'object_key': '', 'muted_until': None}
    row.update(kw)
    return row


ALERTS = {'active_alerts': [_incident('a1', 'critical', 'pve1 root above 90%', 'node', 'pve1'),
                            _incident('a2', 'warning', 'Ceph HEALTH_WARN', 'cluster', 'Testi', acked_by='ops')]}
HEALTH = {'score': 70, 'band': 'good', 'issues': ['1 node offline'], 'computed_at': '2026-10-30T08:59:30',
          'factors': [{'key': 'nodes_offline', 'label': 'Nodes offline', 'value': 1, 'delta': -25, 'severity': 'warning'},
                      {'key': 'storage', 'label': 'Worst storage', 'value': 80, 'delta': -5, 'severity': 'warning'}]}
PVECM = {'corosync': {'rings': [{'id': 0, 'status': 'OK', 'nodes': 3}]},
         'pvecm': {'quorate': 'Yes', 'expected_votes': 4, 'total_votes': 3, 'highest_expected': 4,
                   'cluster_name': 'testi', 'config_version': 7},
         'services': [{'name': 'corosync', 'active': 'active', 'sub': 'running', 'since': '', 'result': 'success'}],
         'ssh_unavailable': False}


def _qd(*connected, algorithm='Fifty-Fifty split'):
    """GET /qdevice with a QDevice: the daemon of each named node, connected or not."""
    return {'present': True, 'answered_by': 'pve1', 'algorithm': algorithm, 'echo_reply': '1 ms', 'last_poll': '',
            'model': 'Net', 'qnetd_host': '10.0.0.50', 'state': 'Connected', 'tie_breaker': 'Node with lowest node ID',
            'read_at': '2026-10-30T08:59:40+00:00',
            'nodes': [{'node': n, 'online': True, 'asked': True, 'answered': True, 'present': True, 'connected': up,
                       'state': 'Connected' if up else 'Disconnected', 'last_poll': '', 'echo_reply': '', 'error': ''}
                      for n, up in connected]}


C1 = '/api/clusters/c1'


class _DcServer(_DashServer):
    """The dashboard fake with the reads of the summary for Testi (c1); reads in hold wait for release()."""

    def __init__(self, c1=None, nodes=None, guests=None, extra=None, hold=(), **kw):
        status = copy.deepcopy(STATUS)
        status['c1'] = c1 if c1 is not None else _status()
        reads = {('GET', f'{C1}/datacenter/cluster-info'): (200, INFO),
                 ('GET', f'{C1}/qdevice'): (200, {'present': False}),
                 ('GET', f'{C1}/hardware/health'): (200, HW),
                 ('GET', f'{C1}/active-alerts'): (200, ALERTS),
                 ('GET', f'{C1}/health'): (200, HEALTH),
                 ('GET', f'{C1}/datastores'): (200, STORES),
                 ('GET', f'{C1}/nodes/pve1/cluster-health'): (200, PVECM)}
        reads.update(extra or {})
        super().__init__(status=status, extra=reads, bundle=BUNDLE, metrics=copy.deepcopy(NODES if nodes is None else nodes),
                         resources=list(GUESTS if guests is None else guests), **kw)
        self.hold = set(hold)
        self.held = []

    def handle(self, route):
        req = route.request
        if req.url.startswith(BASE):
            path = urllib.parse.unquote(re.sub(r'^https?://[^/]+', '', req.url).split('?')[0])
            if (req.method, path) in self.hold:
                self.calls.append((req.method, path))
                self.held.append((route, (req.method, path)))
                return None
        return super().handle(route)

    def release(self):
        held, self.held = self.held, []
        self.hold = set()
        for route, key in held:
            status, data = self.extra.get(key, (404, {'error': 'not mocked'}))
            route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    try:
        ff = pw.firefox.launch(headless=True)
    except Exception:
        ff = None
    yield {'chromium': br, 'firefox': ff}
    br.close()
    if ff:
        ff.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), theme='', **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, _DcServer(layout=LAYOUT, **kw), corp_theme=theme, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -----------------------------------------------------------------------------------

SUM = '[data-cr-dc-sum]'


def _need(page, selector, what, timeout=8000):
    """Wait for a selector; a missing one fails with the property it stands for."""
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _pick(app, cluster='Testi'):
    page = app.page
    page.locator('.corp-tree-item', has_text=cluster).first.click()
    page.locator('[data-cr-tab="datacenter"]').wait_for(timeout=8000)
    # what the rest of the page reads on a pick (the alert strip reads the active alerts) is done
    page.wait_for_timeout(800)
    return page


def _open_dc(app, cluster='Testi', settle=True):
    page = app.page
    page.locator('.corp-tree-item', has_text=cluster).first.click()
    page.locator('[data-cr-tab="datacenter"]').click()
    _need(page, SUM, 'the Datacenter summary is the redesigned one')
    if settle:
        # the three reads of the page answered
        page.wait_for_function('''() => { const s = document.querySelector('[data-cr-dc-sum]');
            return s && !/reading/i.test(s.querySelector('[data-cr-dc-cell="infra"]').innerText); }''', timeout=8000)
    return page


def _state(page):
    return page.locator(SUM).get_attribute('data-cr-dc-state')


def _verdict(page, cell):
    loc = page.locator(f'[data-cr-dc-cell="{cell}"]')
    return loc.get_attribute('data-cr-dc-value'), loc.locator('[data-cr-dc-verdict]').inner_text().strip()


def _line(page, lid):
    loc = page.locator(f'[data-cr-dc-line="{lid}"]')
    return loc.first.inner_text().strip() if loc.count() else None


def _tile(page, tid):
    return page.locator(f'[data-cr-dc-tile="{tid}"]').evaluate('''t => ({
        value: t.querySelector('[data-cr-dc-value]').innerText.trim(),
        tone: (t.querySelector('[data-cr-dc-value]').className.match(/cr-dc-tone-(\\w+)/) || [])[1] || null,
        bar: t.querySelector('.cr-dc-bar') ? (t.querySelector('.cr-dc-bar').className.match(/cr-tone-(\\w+)/) || [])[1] : null,
        kv: Object.fromEntries(Array.from(t.querySelectorAll('[data-cr-dc-kv]')).map(d => [d.dataset.crDcKv, d.querySelector('dd').innerText.trim()])),
        basis: (t.querySelector('.cr-dc-basis') || {}).innerText || '' })''')


ROWS = '''() => {
    const cols = Array.from(document.querySelectorAll('[data-cr-table="dc-nodes"] thead th')).map(th => th.dataset.crCol);
    return Array.from(document.querySelectorAll('[data-cr-table="dc-nodes"] tbody tr.cr-row')).map(tr => {
        const o = { cls: tr.className };
        Array.from(tr.children).forEach((td, i) => { o[cols[i]] = td.innerText.trim(); });
        const w = tr.querySelector('[data-cr-dc-warn]');
        o.chips = w ? w.dataset.crDcWarn : '';
        o.warnTitle = w ? (w.getAttribute('title') || '') : '';
        const s = tr.querySelector('[data-cr-state]');
        o.badge = s ? s.dataset.crState : null;
        return o;
    });
}'''


def _rows(page):
    return {r['name']: r for r in page.evaluate(ROWS)}


def _gets(server, *needles):
    return [p for m, p in server.calls if m == 'GET' and any(n in p for n in needles)]


# --- source ------------------------------------------------------------------------------------

def test_the_summary_is_gated_and_classic_keeps_its_markup():
    dc = _read('web', 'src', 'datacenter.js')
    # the variant's branch, and the classic block behind its negation with its markup untouched
    assert "{activeSection === 'summary' && crSummary && (" in dc
    assert "{activeSection === 'summary' && !crSummary && dcStatus && (" in dc
    assert "{dcStatus.cluster?.standalone ? '●' : dcStatus.cluster?.quorate ? '✓' : '✗'}" in dc
    assert "const crSummary = isCorpRedesigned && !!crDc;" in dc
    # the spinner waits as before everywhere but on the variant's summary
    assert "if (loading && !(crSummary && activeSection === 'summary')) {" in dc
    dash = _read('web', 'src', 'dashboard.js')
    mount = dash[dash.index('<DatacenterTab clusterId={selectedCluster.id}'):]
    mount = mount[:mount.index('/>')]
    assert 'crDc={isCorpRedesigned ? {' in mount and ': undefined}' in mount
    # the page only reads: no write route of any kind in it
    cr = _read('web', 'src', 'cr_datacenter.js')
    assert not re.search(r"method:\s*'(POST|PUT|DELETE|PATCH)'", cr)
    assert 'holds(' not in dash[dash.index('<DatacenterTab'):dash.index('<DatacenterTab') + 2000]


def test_the_new_code_keeps_the_house_rules():
    cr = _read('web', 'src', 'cr_datacenter.js')
    assert '\u2014' not in cr and '\u2013' not in cr
    assert not re.search(r'vm[w]are|vc[e]nter', cr, re.I)
    assert 'LW Nov 2026' in cr
    tr = _read('web', 'src', 'translations.js')
    for key in set(re.findall(r"'(crDc[A-Za-z0-9]+)'", cr)):
        lines = re.findall(rf'^                {key}: (.+)$', tr, re.M)
        assert len(lines) >= 2, key
        assert all('\u2014' not in v and '\u2013' not in v for v in lines), key


# --- quorum and infrastructure -----------------------------------------------------------------

def test_runtime_quorum_and_infrastructure_are_two_answers(open_app):
    app = open_app()
    page = _open_dc(app)
    assert _state(page) == 'ok'
    assert _verdict(page, 'connection') == ('connected', 'Connected')
    assert _verdict(page, 'quorum') == ('quorate', 'Quorate')
    # the spec's example: quorate with a node offline is not healthy; since round 8 an offline node is
    # critical, as the alert strip says it
    assert _verdict(page, 'infra') == ('critical', 'Critical')
    assert 'Held with 1 node(s) offline' in _line(page, 'q-held')
    reasons = page.locator('[data-cr-dc-cell="infra"] [data-cr-dc-line^="reason-"]').all_inner_texts()
    assert '1 node(s) offline' in reasons, reasons
    assert 'Degraded hardware on 1 node(s)' in reasons, reasons
    assert _line(page, 'hardware') == 'Hardware: 3 of 4 nodes checked, 1 degraded'
    assert _line(page, 'alerts').startswith('Active alerts: 2 open (1 critical)')
    assert _line(page, 'score') == 'Health score of the server: 70 (good)'
    # the classic summary (one quorum circle) is not drawn in the variant
    assert page.get_by_text('Quorate: Yes').count() == 0
    assert app.errors == []


def test_runtime_a_lost_quorum_is_critical(open_app):
    app = open_app(c1=_status(quorate=False, online=2, offline=2))
    page = _open_dc(app)
    assert _verdict(page, 'quorum') == ('lost', 'Not quorate')
    assert _verdict(page, 'infra') == ('critical', 'Critical')
    reasons = page.locator('[data-cr-dc-cell="infra"] [data-cr-dc-line^="reason-"]').all_inner_texts()
    assert reasons[0] == 'Quorum Lost', reasons
    assert _line(page, 'q-held') is None
    assert app.errors == []


@pytest.mark.parametrize('kind', ['standalone', 'xcpng'])
def test_runtime_a_single_node_and_an_xcpng_pool_have_no_quorum_verdict(open_app, kind):
    if kind == 'standalone':
        st = _status(quorate=None, online=1, offline=0, standalone=True)
        nodes = {'pve1': NODES['pve1']}
        app = open_app(c1=st, nodes=nodes, extra={('GET', f'{C1}/datacenter/cluster-info'): (200, [
            {'name': 'pve1', 'node': 'pve1', 'online': 1}])})
    else:
        st = _status(quorate=None, online=3, offline=1, kind='xcpng', cts=(0, 0, 0), cpu=(32, 0))
        app = open_app(c1=st, clusters=[dict(CLUSTERS[0], cluster_type='xcpng')] + CLUSTERS[1:])
    page = _open_dc(app)
    value, text = _verdict(page, 'quorum')
    assert value == ('standalone' if kind == 'standalone' else 'na'), value
    assert text in ('No quorum (single node)', 'Not applicable')
    assert 'Not quorate' not in page.locator(SUM).inner_text()
    # no corosync: no QDevice line, no votes, no SSH read offered
    assert _line(page, 'qdevice') is None and _line(page, 'votes') is None
    assert page.locator('[data-cr-dc-readvotes]').count() == 0
    if kind == 'xcpng':
        # no containers and no CPU in use: said, not drawn as 0
        assert _tile(page, 'cts')['value'] == '-' and 'XCP-ng has no containers' in _tile(page, 'cts')['basis']
        cpu = _tile(page, 'cpu')
        assert cpu['value'] == '-' and 'XCP-ng reports no CPU in use' in cpu['basis'], cpu
        assert _line(page, 'hardware') == 'Hardware: not available for XCP-ng'
        assert not _gets(app.server, '/hardware/health')
        assert '0%' not in page.locator('[data-cr-dc-tile="cpu"]').inner_text()
    else:
        assert _tile(page, 'cpu')['value'] == '20.0%'
        assert 'Single node testi, no cluster' in _line(page, 'conn-kind')
    assert app.errors == []


# --- a status that is not there ----------------------------------------------------------------

@pytest.mark.parametrize('case', ['http503', 'zero', 'forbidden'])
def test_runtime_a_status_that_was_not_read_is_its_own_state(open_app, case):
    if case == 'http503':
        app = open_app(extra={('GET', f'{C1}/datacenter/status'): (503, {'error': 'Cluster temporarily unreachable', 'offline': True})})
        want = 'failed'
    elif case == 'zero':
        # vms.py when Proxmox refused cluster/status: zeros and standalone
        app = open_app(c1=_status(quorate=None, online=0, offline=0, standalone=True, vms=(0, 0, 0), cts=(0, 0, 0),
                                  cpu=(0, 0), mem=(0, 0), storage=(0, 0)))
        want = 'empty'
    else:
        app = open_app(admin=False, permissions=['vm.view', 'storage.view', 'node.view'])
        want = 'forbidden'
    page = _open_dc(app, settle=False)
    page.wait_for_function(f'''() => document.querySelector('[data-cr-dc-sum]').dataset.crDcState === '{want}' ''', timeout=8000)
    callout = page.locator('[data-cr-dc-callout]').inner_text()
    if case == 'http503':
        assert 'could not be read (HTTP 503)' in callout, callout
    elif case == 'zero':
        assert 'without any node' in callout and 'not as an empty cluster' in callout, callout
    else:
        assert 'may not read the status of this cluster' in callout, callout
    # nothing drawn as healthy, standalone or 0
    assert _verdict(page, 'quorum')[0] == 'unknown'
    assert _verdict(page, 'infra')[0] == 'unknown'
    for tid in ('cpu', 'mem', 'storage'):
        assert _tile(page, tid)['value'] == '-', tid
    text = page.locator(SUM).inner_text()
    assert '0.0%' not in text and 'Standalone' not in text and 'Healthy' not in text
    assert app.errors == []


def test_runtime_a_cluster_switch_never_shows_the_cluster_before(open_app):
    # Prod's status fails: its summary must not keep Testi's figures (the classic tab did)
    app = open_app(extra={('GET', '/api/clusters/c2/datacenter/status'): (503, {'error': 'Cluster temporarily unreachable'})})
    page = _open_dc(app)
    assert _tile(page, 'cpu')['value'] == '20.0%'
    page.locator('.corp-tree-item', has_text='Prod').first.click()
    page.locator('[data-cr-tab="datacenter"]').click()
    page.wait_for_function('''() => { const s = document.querySelector('[data-cr-dc-sum]');
        return s && s.dataset.crDcState === 'failed'; }''', timeout=8000)
    for tid in ('cpu', 'mem', 'storage'):
        assert _tile(page, tid)['value'] == '-', tid
    assert 'testi' not in page.locator('[data-cr-dc-cell="connection"]').inner_text()
    assert app.errors == []


# --- guests, resources -------------------------------------------------------------------------

def test_runtime_guests_split_templates_and_other_states(open_app):
    app = open_app()
    page = _open_dc(app)
    vms, cts = _tile(page, 'vms'), _tile(page, 'cts')
    assert vms['value'] == '5' and vms['kv'] == {'running': '2', 'stopped': '1', 'templates': '1', 'other': '1'}, vms
    assert cts['value'] == '2' and cts['kv'] == {'running': '1', 'stopped': '1', 'templates': '0', 'other': '0'}, cts
    for t in (vms, cts):
        assert sum(int(v) for v in t['kv'].values()) == int(t['value'])
    assert 'templates counted on their own' in vms['basis']
    assert app.errors == []


def test_runtime_guests_not_read_are_no_zero(open_app):
    app = open_app(extra={('GET', f'{C1}/resources'): (503, {'error': 'Cluster temporarily unreachable'})})
    page = _open_dc(app)
    for tid in ('vms', 'cts'):
        tile = _tile(page, tid)
        assert tile['value'] == '-' and tile['kv'] == {}, tile
        assert 'not been read' in tile['basis'] or 'Not read' in tile['basis'], tile
    assert app.errors == []


@pytest.mark.parametrize('cpu,mem,storage,tones', [
    ((100, 80), (100 * GIB, 80 * GIB), (100 * GIB, 69.9 * GIB), ('success', 'success', 'success')),
    ((100, 80.1), (100 * GIB, 90 * GIB), (100 * GIB, 70 * GIB), ('warning', 'warning', 'warning')),
    ((100, 90.1), (100 * GIB, 95 * GIB), (100 * GIB, 85 * GIB), ('error', 'error', 'warning')),
    ((100, 10), (100 * GIB, 10 * GIB), (100 * GIB, 85.1 * GIB), ('success', 'success', 'error')),
], ids=['below', 'at-the-first-step', 'above', 'storage-critical'])
def test_runtime_resources_use_their_thresholds(open_app, cpu, mem, storage, tones):
    app = open_app(c1=_status(cpu=cpu, mem=mem, storage=storage))
    page = _open_dc(app)
    for tid, tone in zip(('cpu', 'mem', 'storage'), tones):
        assert _tile(page, tid)['bar'] == tone, (tid, _tile(page, tid))
    assert app.errors == []


def test_runtime_resources_show_used_and_free_and_no_storage_is_no_zero(open_app):
    app = open_app()
    page = _open_dc(app)
    cpu, mem, sto = _tile(page, 'cpu'), _tile(page, 'mem'), _tile(page, 'storage')
    assert cpu['value'] == '20.0%' and cpu['kv'] == {'used': '6.4 CPUs', 'total': '32 CPUs', 'free': '25.6 CPUs'}, cpu
    assert mem['value'] == '25.0%' and mem['kv'] == {'used': '64.0 GB', 'total': '256.0 GB', 'free': '192.0 GB'}, mem
    assert sto['value'] == '25.0%' and sto['kv'] == {'used': '1.0 TB', 'total': '4.0 TB', 'free': '3.0 TB'}, sto
    assert 'shared one once' in sto['basis']
    app2 = open_app(c1=_status(storage=(0, 0)))
    page2 = _open_dc(app2)
    sto = _tile(page2, 'storage')
    assert sto['value'] == '-' and sto['kv'] == {} and 'No active storage that takes guest disks' in sto['basis'], sto
    assert app.errors == [] and app2.errors == []


# --- the node table ----------------------------------------------------------------------------

def test_runtime_the_node_table_says_what_each_node_reported(open_app):
    extra = {('GET', f'{C1}/datacenter/cluster-info'): (200, INFO + [
        {'name': 'pve5', 'node': 'pve5', 'nodeid': '5', 'quorum_votes': '1', 'online': 1}])}
    nodes = dict(NODES, pve6=_blind('online'))
    app = open_app(nodes=nodes, extra=extra)
    page = _open_dc(app)
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="dc-nodes"] tbody tr.cr-row\').length === 6', timeout=8000)
    order = [r['name'] for r in page.evaluate(ROWS)]
    # offline first, then without data, maintenance, the rest
    assert order[0] == 'pve3' and order[-2:] == ['pve1', 'pve2'], order
    rows = _rows(page)
    off = rows['pve3']
    assert off['badge'] == 'offline' and 'cr-dc-row-off' in off['cls']
    assert (off['cpu'], off['mem'], off['root']) == ('-', '-', '-'), off
    assert off['local'] == '-' and off['warn'] == '-', off
    assert rows['pve6']['state'] == 'No data' and rows['pve6']['cpu'] == '-' and rows['pve6']['mem'] == '-'
    assert rows['pve5']['state'] == 'Listed only'
    assert rows['pve4']['badge'] == 'maintenance' and rows['pve4']['chips'] == 'maint' and '50%' in rows['pve4']['warn']
    assert rows['pve4']['local'] == '-'
    p1, p2 = rows['pve1'], rows['pve2']
    assert (p1['cpu'], p1['mem'], p1['root'], p1['local']) == ('13%', '40%', '88%', '60%'), p1
    assert p1['guests'] == '2 / 3' and p2['guests'] == '1 / 2' and rows['pve4']['guests'] == '0 / 1'
    # each warning from a signal that was read, the worst first
    assert p1['chips'].split() == ['root', 'inc'] or p1['chips'].split() == ['inc', 'root'], p1
    assert set(p2['chips'].split()) == {'cpu', 'root', 'local', 'hw'}, p2
    assert 'Fan 3: 0 RPM' in p2['warnTitle']
    assert app.errors == []


def test_runtime_a_row_opens_the_node_by_click_and_by_enter(open_app):
    app = open_app()
    page = _open_dc(app)
    page.locator('[data-cr-table="dc-nodes"] tbody tr.cr-row', has_text='pve2').click()
    _need(page, '[data-cr-objhead="node"]', 'a row opens the node view')
    assert 'pve2' in page.locator('[data-cr-objhead="node"]').inner_text()
    page.locator('[data-cr-tab="datacenter"]').click()
    _need(page, SUM, 'back on the summary')
    row = page.locator('[data-cr-table="dc-nodes"] tbody tr.cr-row', has_text='pve3')
    row.focus()
    page.keyboard.press('ArrowDown')
    page.wait_for_function('() => (document.activeElement.innerText || "").startsWith("pve4")', timeout=4000)
    page.keyboard.press('Enter')
    _need(page, '[data-cr-objhead="node"]', 'Enter on a row opens the node view')
    assert 'pve4' in page.locator('[data-cr-objhead="node"]').inner_text()
    assert app.errors == []


def test_runtime_200_nodes_and_not_one_request_per_node(open_app):
    nodes = {f'n{i:03d}': _node(10 + i % 70, 30, 40) for i in range(200)}
    nodes['n007'] = _blind('offline')
    app = open_app(nodes=nodes, c1=_status(online=199, offline=1),
                   extra={('GET', f'{C1}/datacenter/cluster-info'): (404, {'error': 'not mocked'})})
    _pick(app)
    before = {path: len([p for p in _gets(app.server, path) if p.startswith(C1)]) for path in ('/hardware/health', '/active-alerts', '/health')}
    page = _open_dc(app)
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="dc-nodes"] tbody tr.cr-row\').length === 200', timeout=10000)
    assert page.evaluate(ROWS)[0]['name'] == 'n007'
    assert _tile(page, 'nodes')['kv']['offline'] == '1'
    # the page's own reads, once each; nothing per node. The active alerts the strip read on the pick
    # are shared (one store since round 8): no second read within the minute
    for path, more in (('/hardware/health', 1), ('/active-alerts', 0), ('/health', 1)):
        assert len([p for p in _gets(app.server, path) if p.startswith(C1)]) == before[path] + more, path
    assert not [p for p in _gets(app.server, '/nodes/') if p.startswith(C1)]
    assert page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth') <= 0
    assert app.errors == []


# --- what was not read -------------------------------------------------------------------------

def test_runtime_warnings_say_what_was_not_read(open_app):
    extra = {('GET', f'{C1}/hardware/health'): (403, {'error': 'Hardware monitoring is not enabled', 'code': 'CONSENT_REQUIRED',
                                                      'current_version': 1}),
             ('GET', f'{C1}/active-alerts'): (200, {'active_alerts': [], 'error': 'Alert operation failed'})}
    app = open_app(extra=extra, nodes={'pve1': _node(10, 20, 30), 'pve2': _node(85, 20, 30)})
    page = _open_dc(app)
    assert _line(page, 'hardware') == 'Hardware: monitoring is off'
    assert _line(page, 'alerts') == 'Active alerts: not read (Alert operation failed)'
    rows = _rows(page)
    # a node without a warning from what was read is no "None" when hardware and alerts are unknown
    assert rows['pve1']['warn'] == '-'
    title = page.locator('[data-cr-table="dc-nodes"] tr.cr-row', has_text='pve1').locator('[data-cr-dc-warn]').get_attribute('title')
    assert 'monitoring is off' in title and 'active alerts not read' in title, title
    assert set(rows['pve2']['chips'].split()) == {'cpu', 'local'}, rows['pve2']
    # the verdict keeps its basis: the status's offline node (critical since round 8), not the unread parts
    assert _verdict(page, 'infra')[0] == 'critical'
    assert app.errors == []


def test_runtime_with_everything_read_a_quiet_node_says_none(open_app):
    app = open_app(nodes={'pve1': _node(10, 20, 30)}, c1=_status(online=1, offline=0),
                   extra={('GET', f'{C1}/active-alerts'): (200, {'active_alerts': []}),
                          ('GET', f'{C1}/hardware/health'): (200, dict(HW, health='ok', degraded=[], checked=1)),
                          ('GET', f'{C1}/datacenter/cluster-info'): (200, INFO[:1])})
    page = _open_dc(app)
    assert _verdict(page, 'infra') == ('healthy', 'Healthy')
    assert _rows(page)['pve1']['warn'] == 'None'
    assert _line(page, 'alerts') == 'Active alerts: none open'
    assert app.errors == []


def test_runtime_without_node_view_nothing_node_level_is_claimed(open_app):
    app = open_app(admin=False, permissions=['cluster.view', 'vm.view', 'storage.view'])
    page = _open_dc(app)
    assert _line(page, 'hardware') == 'Hardware: not visible to this account'
    assert 'not visible to this account' in _line(page, 'qdevice')
    assert 'alerts on nodes are not visible to this account' in _line(page, 'alerts')
    assert page.locator('[data-cr-dc-readvotes]').count() == 0
    assert not _gets(app.server, '/hardware/health', '/qdevice', '/cluster-health')
    # the node table still lists the nodes; their warnings say what is not known
    assert _rows(page)['pve1']['chips'] == 'root'
    assert app.errors == []


# --- QDevice and votes -------------------------------------------------------------------------

@pytest.mark.parametrize('case,answer,line,votes', [
    ('none', (200, {'present': False}), 'QDevice: none reported by the nodes asked',
     'Votes (calculated): 3 of 4 present, quorum needs 3'),
    ('connected', (200, _qd(('pve1', True), ('pve2', True), ('pve4', True))), 'QDevice: connected on 3 of 3 nodes (10.0.0.50)',
     'Votes (calculated, QDevice included): 4 of 5 present, quorum needs 3'),
    ('partly', (200, _qd(('pve1', True), ('pve2', False), ('pve4', True))), 'QDevice: connected on 2 of 3 nodes (10.0.0.50)',
     'Votes (calculated, QDevice included): 3 of 5 present, quorum needs 3'),
    ('lms', (200, _qd(('pve1', True), algorithm='LMS')), 'QDevice: connected on 1 of 1 nodes (10.0.0.50)',
     'Votes: not calculated, the QDevice uses the algorithm LMS'),
    ('refused', (403, {'error': 'Permission denied'}), 'QDevice: not visible to this account',
     'Votes: not calculated, whether there is a QDevice is not known'),
])
def test_runtime_the_qdevice_and_the_calculated_votes(open_app, case, answer, line, votes):
    app = open_app(extra={('GET', f'{C1}/qdevice'): answer})
    page = _open_dc(app)
    try:
        page.wait_for_function(f'''() => ((document.querySelector('[data-cr-dc-line="qdevice"]') || {{}}).innerText || '').startsWith({json.dumps(line)})
            && (document.querySelector('[data-cr-dc-line="votes"]') || {{}}).innerText === {json.dumps(votes)} ''', timeout=8000)
    except Exception:
        raise AssertionError((_line(page, 'qdevice'), _line(page, 'votes'))) from None
    assert 'not read from corosync' in page.locator('[data-cr-dc-line="votes"]').get_attribute('title').lower()
    if case == 'partly':
        assert page.locator('[data-cr-dc-line="qdevice"] .cr-dot-warning').count() == 1
    if case == 'connected':
        page.locator('[data-cr-dc-open="qdevice"]').click()
        page.wait_for_function('''() => Array.from(document.querySelectorAll('.cr-crumbs .cr-crumb-text')).pop().innerText.trim() === 'QDevice' ''',
                               timeout=8000)
    assert app.errors == []


def test_runtime_the_votes_are_read_from_a_node_only_on_a_click(open_app):
    key = ('GET', f'{C1}/nodes/pve1/cluster-health')
    app = open_app(hold=[key])
    page = _open_dc(app)
    assert not _gets(app.server, '/cluster-health')
    btn = page.locator('[data-cr-dc-readvotes]')
    assert btn.inner_text().strip() == 'Read votes from pve1'
    btn.click()
    page.wait_for_function('() => document.querySelector("[data-cr-dc-votes]").dataset.crDcVotes === "running"', timeout=4000)
    assert btn.is_disabled()
    # a section switch and back while it runs: still running, no second start
    page.locator('.corp-subnav-item', has_text='Options').click()
    page.locator('.corp-subnav-item', has_text='Summary').click()
    _need(page, '[data-cr-dc-votes="running"]', 'the read keeps running over a remount')
    assert page.locator('[data-cr-dc-readvotes]').is_disabled()
    assert len(_gets(app.server, '/cluster-health')) == 1
    app.server.release()
    page.wait_for_function('() => document.querySelector("[data-cr-dc-votes]").dataset.crDcVotes === "ok"', timeout=6000)
    out = page.locator('[data-cr-dc-votes-out]').inner_text()
    assert re.search(r'pve1 at .+: expected votes 4, total votes 3, quorate Yes', out), out
    assert len(_gets(app.server, '/cluster-health')) == 1
    assert app.errors == []


def test_runtime_votes_without_ssh_are_said_so(open_app):
    app = open_app(extra={('GET', f'{C1}/nodes/pve1/cluster-health'): (200, {
        'corosync': None, 'pvecm': None, 'services': [], 'ssh_unavailable': True})})
    page = _open_dc(app)
    page.locator('[data-cr-dc-readvotes]').click()
    _need(page, '[data-cr-dc-votes-out]', 'the answer is shown')
    assert page.locator('[data-cr-dc-votes-out]').inner_text() == 'pve1 could not be reached over SSH'
    assert app.errors == []


# --- freshness, reads, layout ------------------------------------------------------------------

def test_runtime_the_summary_does_not_wait_for_the_classic_reads(open_app):
    key = ('GET', f'{C1}/datacenter/cluster-info')
    app = open_app(hold=[key])
    page = _open_dc(app)
    # the tab's 14 reads are not through (the corosync list is held), the summary is drawn already
    assert _state(page) == 'ok' and _verdict(page, 'quorum')[0] == 'quorate'
    assert _line(page, 'votes') == 'Votes: waiting for the corosync node list'
    assert page.get_by_text('Loading datacenter data', exact=False).count() == 0
    # another section keeps the classic wait, with the section list kept to come back
    page.locator('.corp-subnav-item', has_text='Options').click()
    _need(page, '[data-cr-dc-wait]', 'the section list stays while another section waits')
    assert page.get_by_text('Loading datacenter data', exact=False).count() == 1
    page.locator('.corp-subnav-item', has_text='Summary').click()
    _need(page, SUM, 'the summary is one click away')
    app.server.release()
    page.wait_for_function('''() => (document.querySelector('[data-cr-dc-line="votes"]') || {}).innerText
        === 'Votes (calculated): 3 of 4 present, quorum needs 3' ''', timeout=8000)
    assert app.errors == []


def test_runtime_an_old_status_is_not_current_and_a_failed_refresh_says_why(open_app):
    app = open_app()
    page = _open_dc(app)
    assert _state(page) == 'ok'
    reads = len(_gets(app.server, f'{C1}/datacenter/status'))
    app.server.extra[('GET', f'{C1}/datacenter/status')] = (503, {'error': 'Cluster temporarily unreachable', 'offline': True})
    # two and a half polls later without a new answer
    app.ctx.clock.set_fixed_time(FIXED + 150)
    page.wait_for_function('() => document.querySelector("[data-cr-dc-sum]").dataset.crDcState === "stale"', timeout=15000)
    assert _verdict(page, 'infra') == ('stale', 'Not current')
    assert _line(page, 'i-last').startswith('Last verdict: Critical')
    assert _tile(page, 'cpu')['value'] == '20.0%'
    assert 'not current' in page.locator('[data-cr-dc-callout]').inner_text()
    page.locator('[data-cr-dc-refresh]').click()
    page.wait_for_function('''() => /The last read failed: Cluster temporarily unreachable - HTTP 503/
        .test(document.querySelector('[data-cr-dc-callout]').innerText)''', timeout=8000)
    assert len(_gets(app.server, f'{C1}/datacenter/status')) > reads
    assert app.errors == []


def test_runtime_refresh_reads_again_and_never_twice_at_once(open_app):
    key = ('GET', f'{C1}/hardware/health')
    app = open_app()
    page = _open_dc(app)
    before = {p: len(_gets(app.server, p)) for p in ('/hardware/health', '/active-alerts', f'{C1}/health', f'{C1}/datacenter/status')}
    app.server.hold = {key}
    page.locator('[data-cr-dc-refresh]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-dc-refresh]").disabled', timeout=4000)
    page.locator('[data-cr-dc-refresh]').dispatch_event('click')
    page.wait_for_timeout(300)
    app.server.release()
    page.wait_for_function('() => !document.querySelector("[data-cr-dc-refresh]").disabled', timeout=6000)
    after = {p: len(_gets(app.server, p)) for p in before}
    assert after['/hardware/health'] == before['/hardware/health'] + 1, (before, after)
    assert after['/active-alerts'] >= before['/active-alerts'] + 1
    assert after[f'{C1}/datacenter/status'] >= before[f'{C1}/datacenter/status'] + 1
    assert app.errors == []


@pytest.mark.parametrize('engine,size,theme', [('chromium', (1600, 1000), ''), ('chromium', (1280, 800), ''),
                                               ('firefox', (1600, 1000), ''), ('firefox', (1280, 800), ''),
                                               ('chromium', (1600, 1000), 'light')],
                         ids=['chromium-1600', 'chromium-1280', 'firefox-1600', 'firefox-1280', 'light-1600'])
def test_runtime_it_fits_without_sideways_scroll(open_app, engine, size, theme):
    app = open_app(engine=engine, viewport=size, theme=theme)
    page = _open_dc(app)
    assert page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth') <= 0
    inner = page.locator('[data-cr-table="dc-nodes"] .cr-table-scroll').evaluate('e => e.scrollWidth - e.clientWidth')
    assert inner <= 1, inner
    # the three answers sit side by side, the tiles in one row (1600) or two rows of three (1280)
    boxes = [page.locator(f'[data-cr-dc-cell="{c}"]').bounding_box() for c in ('connection', 'quorum', 'infra')]
    assert boxes[0]['y'] == boxes[1]['y'] == boxes[2]['y'] and boxes[0]['x'] < boxes[1]['x'] < boxes[2]['x']
    tops = sorted({round(page.locator(f'[data-cr-dc-tile="{t}"]').bounding_box()['y']) for t in
                   ('nodes', 'vms', 'cts', 'cpu', 'mem', 'storage')})
    assert len(tops) == (1 if size[0] >= 1500 else 2), tops
    # the table stays inside the window
    tb = page.locator('[data-cr-table="dc-nodes"] .cr-table-scroll').bounding_box()
    assert tb['height'] <= size[1]
    if theme == 'light':
        bg = page.locator('.cr-dc-status').evaluate('e => getComputedStyle(e).backgroundColor')
        assert bg == 'rgb(255, 255, 255)', bg
    assert app.errors == []


# --- the rules, as the bundle has them ---------------------------------------------------------

RULES = r'''
const out = {};
const c = { id: 'c1', name: 'Testi', connected: true, cluster_type: 'proxmox' };
const ok = { data: { cluster: { quorate: true, standalone: false }, nodes: { online: 2, offline: 0, total: 2 } }, lastUpdate: new Date(1000) };
const base = { cluster: c, entry: ok, canStatus: true, now: 2000, openedAt: 0 };
out.ok = crDcStatus(base).state;
out.esxi = crDcStatus({ ...base, cluster: { ...c, cluster_type: 'esxi' } }).state;
out.off = crDcStatus({ ...base, cluster: { ...c, connected: false } }).state;
out.forbidden = crDcStatus({ ...base, canStatus: false }).state;
out.old = crDcStatus({ ...base, now: 1000 + 76000 }).state;
out.failedAfter = crDcStatus({ ...base, read: { cid: 'c1', code: 502, at: 1500 } }).state;
out.failedBefore = crDcStatus({ ...base, read: { cid: 'c1', code: 502, at: 500 } }).state;
out.otherCluster = crDcStatus({ ...base, entry: null, read: { cid: 'c2', code: 502, at: 1500 } }).state;
out.failed = crDcStatus({ ...base, entry: null, read: { cid: 'c1', code: 0, at: 1500 } }).state;
out.refreshed = crDcStatus({ ...base, own: { cid: 'c1', code: 200, at: 1900, data: ok.data } }).at;
out.loading = crDcStatus({ ...base, entry: null }).state;
out.unread = crDcStatus({ ...base, entry: null, now: 46000 }).state;
out.zero = crDcStatus({ ...base, entry: { data: { cluster: { standalone: true, quorate: null }, nodes: { online: 0, offline: 0, total: 0 } }, lastUpdate: new Date(1000) } }).state;
out.quorum = [crDcQuorum({ data: ok.data }, c).state,
              crDcQuorum({ data: { cluster: { quorate: false, standalone: false }, nodes: { total: 3 } } }, c).state,
              crDcQuorum({ data: { cluster: { quorate: null, standalone: true }, nodes: { total: 1 } } }, c).state,
              crDcQuorum({ data: { cluster: { quorate: null, standalone: true }, nodes: { total: 3 } } }, c).state,
              crDcQuorum({ data: { cluster: { quorate: null, standalone: false, cluster_type: 'xcpng' }, nodes: { total: 2 } } }, c).state,
              crDcQuorum({ data: { cluster: { quorate: null, standalone: false }, nodes: { total: 2 } } }, c).state,
              crDcQuorum({}, c).state];
const info = [{ quorum_votes: '1', online: 1 }, { quorum_votes: '1', online: 1 }, { quorum_votes: '2', online: 0 }];
out.votes = crDcVotes(info, { present: false }, true);
out.votesNoList = [crDcVotes([], null, true).state, crDcVotes([{ quorum_votes: '1' }], { present: false }, true).state];
out.votesNoQd = [crDcVotes(info, undefined, true).state, crDcVotes(info, { present: false, refused: true }, true).state, crDcVotes(info, { present: false }, false).state];
const g = crDcGuests([{ type: 'qemu', status: 'running', node: 'a' }, { type: 'qemu', status: 'stopped', template: 1, node: 'a' },
                      { type: 'qemu', status: 'suspended', node: 'b' }, { type: 'lxc', status: 'stopped', node: 'a' },
                      { type: 'storage', status: 'available' }]);
out.guests = [g.vms, g.cts, Object.fromEntries(g.byNode)];
console.log(JSON.stringify(out));
'''


def test_the_rules_of_the_page():
    """The pure rules as the bundle under test has them (compiled, the functions keep their names)."""
    import shutil
    import subprocess
    node = shutil.which('node')
    if not node:
        pytest.skip('no node here')
    src = BUNDLE or _read('web', 'index.html')
    try:
        q = src[src.index('function qdeviceTone('):src.index('const QDEVICE_TONES')]
        rules = src[src.index('const CR_DC'):src.index('function crDcInfra(')]
    except ValueError:
        raise AssertionError('the bundle has no rules of the redesigned Datacenter summary') from None
    got = subprocess.run([node, '-e', q + rules + RULES], capture_output=True, text=True, timeout=30)
    assert got.returncode == 0, got.stderr
    out = json.loads(got.stdout)
    assert out['ok'] == 'ok' and out['esxi'] == 'unsupported' and out['off'] == 'disconnected'
    assert out['forbidden'] == 'forbidden' and out['old'] == 'stale' and out['zero'] == 'empty'
    # a failed read after the answer makes it not current, one before it changes nothing; another cluster's read is not ours
    assert out['failedAfter'] == 'stale' and out['failedBefore'] == 'ok' and out['otherCluster'] == 'loading'
    assert out['failed'] == 'failed' and out['refreshed'] == 1900
    assert out['loading'] == 'loading' and out['unread'] == 'unread'
    assert out['quorum'] == ['quorate', 'lost', 'standalone', 'unknown', 'na', 'unknown', 'unknown']
    assert out['votes'] == {'state': 'ok', 'present': 2, 'configured': 4, 'needed': 3, 'qdevice': False}
    assert out['votesNoList'] == ['nolist', 'novotes']
    assert out['votesNoQd'] == ['noqdevice', 'noqdevice', 'noqdevice']
    assert out['guests'][0] == {'total': 3, 'running': 1, 'stopped': 0, 'templates': 1, 'other': 1}
    assert out['guests'][1] == {'total': 1, 'running': 0, 'stopped': 1, 'templates': 0, 'other': 0}
    assert out['guests'][2] == {'a': {'running': 1, 'total': 2}, 'b': {'running': 0, 'total': 1}}


# --- stage X: what the review of round 4 found -----------------------------------------------------

def test_runtime_200_nodes_with_their_corosync_list_read_nothing_per_node_until_cpu_compatibility(open_app):
    # R-04: with a real cluster-info the classic tab read nodes/<n>/summary for every node on open (for
    # CPU Compatibility only) and the votes waited for it; the variant reads them when that section opens
    n = 200
    nodes = {f'n{i:03d}': _node(10 + i % 70, 30, 40) for i in range(n)}
    info = [{'name': f'n{i:03d}', 'node': f'n{i:03d}', 'nodeid': str(i + 1), 'quorum_votes': '1',
             'ring0_addr': f'10.1.{i // 250}.{i % 250}', 'online': 1} for i in range(n)]
    extra = {('GET', f'{C1}/datacenter/cluster-info'): (200, info)}
    for i in range(3):
        extra[('GET', f'{C1}/nodes/n{i:03d}/summary')] = (200, {'cpuinfo': {'model': 'Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz',
                                                                            'cores': 32, 'sockets': 2}})
    app = open_app(nodes=nodes, c1=_status(online=n, offline=0), extra=extra)
    page = _open_dc(app)
    page.wait_for_function('() => document.querySelectorAll(\'[data-cr-table="dc-nodes"] tbody tr.cr-row\').length === 200', timeout=10000)
    page.wait_for_function('() => /200 of 200 present/.test((document.querySelector(\'[data-cr-dc-line="votes"]\') || {}).innerText || "")',
                           timeout=8000)
    page.wait_for_timeout(1500)
    assert not [p for p in _gets(app.server, '/nodes/') if p.startswith(C1)], 'nothing per node on open'
    # CPU Compatibility: the summaries of the online nodes, once, when the section opens
    page.locator('button', has_text='CPU Compatibility').first.click()
    page.get_by_text('Detected Cluster CPUs').first.wait_for(timeout=8000)
    page.wait_for_function('() => /Gold 6338/.test(document.body.innerText)', timeout=15000)
    reads = [p for p in _gets(app.server, '/summary') if p.startswith(f'{C1}/nodes/')]
    assert len(reads) == n and len(set(reads)) == n, len(reads)
    page.locator('button', has_text='Summary').first.click()
    page.wait_for_timeout(300)
    page.locator('button', has_text='CPU Compatibility').first.click()
    page.wait_for_timeout(800)
    assert len([p for p in _gets(app.server, '/summary') if p.startswith(f'{C1}/nodes/')]) == n, 'read once per cluster'
    assert app.errors == []


def test_runtime_the_infrastructure_rules_say_alerts_are_not_part_of_the_verdict(open_app):
    # R-15 (decision open): the verdict keeps the dashboard's rules; their tooltip says what it leaves out
    app = open_app()
    page = _open_dc(app)
    title = page.locator('[data-cr-dc-line="i-basis"]').get_attribute('title')
    assert 'Active alerts are listed below and are not part of this verdict' in title, title
    assert app.errors == []
