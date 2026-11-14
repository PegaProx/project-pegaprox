"""The QDevice setup and the QNetd hosts in the web UI.

Settings > High Availability lists the QNetd hosts (QnetdHostsPanel): kind, address, helper
protocol, whether corosync-qnetd runs, the clusters that vote through each host with the
nodes the QNetd sees connected, and Add / Check / Read status / Edit / Delete / bulk setup.
Next to the nodes of a cluster without a QDevice there is Set up QDevice (a wizard: where
the QNetd runs, the options, the plan the admin agrees to per cluster, the job and its log;
tests/test_qdevice_wizard_ui.py drives it in depth), the QDevice view has Remove QDevice,
and the alert dialog offers the qnetd rule. All of it is for administrators only: the buttons show where
GET /api/qnetd/hosts answers and the instance acts. The routes are tested in
test_qnetd_api.py.

Source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, with the QNetd routes
added. They skip where Playwright is not installed.
LW Oct 2026
"""
import copy
import hashlib
import json
import os
import re

import pytest

from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _classes,  # noqa: F401
                        _wait_for_call, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EM_DASH = '\u2014'
EN_DASH = '\u2013'
BLOCK_START = '// LW Oct 2026 - the QDevice of a cluster set up and removed from here'
BLOCK_END = '// LW Oct 2026 (#1137) - the QDevice of a cluster as GET'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (pos, lang) in enumerate(starts)}


@pytest.fixture(scope='module')
def block():
    return _between(_read('web', 'src', 'node_modals.js'), BLOCK_START, BLOCK_END)


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


def _dash_parts(dash):
    return [
        _between(dash, '{/* LW Oct 2026 - a cluster without a QDevice can get one here', '{isCorporate ? ('),
        _between(dash, "EVENT_ALERT_METRICS.push('qnetd');", 'const [sessionExpired'),
        _between(dash, "if (alert.metric === 'qnetd')", '\n'),
        _between(dash, '<option value="qnetd">', '</select>'),
        _between(dash, ": alertMetricSel === 'qnetd' ? `", ': t('),
    ]


def _used_keys(block, dash):
    keys = set(re.findall(r"\bt\('([A-Za-z0-9_]+)'\)", block))
    # the labels of the checks, steps, states and kinds are looked up through maps
    keys |= set(re.findall(r"'((?:qdev|qnetd)[A-Z][A-Za-z0-9]*)'", block))
    for part in _dash_parts(dash):
        keys |= set(re.findall(r"\bt\('([A-Za-z0-9_]+)'\)", part))
    return keys


def _new_keys():
    return set(re.findall(r'^\s*((?:qdev[A-Z]|qnetd[A-Z])[A-Za-z0-9]*):', _blocks()['en'], re.M))


# --- source --------------------------------------------------------------------------------

def test_every_route_of_the_api_is_called_by_the_ui(block):
    """Each route of api/qnetd.py has its caller, with the method the route takes."""
    api = _read('pegaprox', 'api', 'qnetd.py')
    routes = re.findall(r"@bp\.route\('([^']+)', methods=\['([A-Z]+)'\]\)", api)
    assert len(routes) == 13, routes
    assert ('/api/clusters/<cluster_id>/qdevice/plan', 'GET') in routes
    # the preflight stays for scripts and tests: the UI reads the same report inside the plan
    routes.remove(('/api/clusters/<cluster_id>/qdevice/preflight', 'GET'))
    assert '/qdevice/preflight' not in block
    calls = re.findall(r"qdevApi\(getAuthHeaders, '([A-Z]+)', ([`'])(.*?)\2", block)
    assert calls
    # the form sends a new host with POST and a change with PUT
    assert "qdevApi(getAuthHeaders, editing ? 'PUT' : 'POST', editing ? `/qnetd/hosts/${host.id}` : '/qnetd/hosts', body)" in block
    calls += [('PUT', '`', '/qnetd/hosts/${host.id}'), ('POST', "'", '/qnetd/hosts')]
    seen = set()
    for method, _q, path in calls:
        # `${host.id}` and the like stand for one path segment, a query string is dropped
        shape = re.sub(r'\$\{[^}]+\}', '<x>', path).split('?')[0]
        seen.add((method, '/api' + shape))
    for path, method in routes:
        shape = re.sub(r'<[^>]+>', '<x>', path)
        assert (method, shape) in seen, f'{method} {path} has no caller in the UI'


def test_nothing_goes_in_as_markup(block, dash):
    for part in [block] + _dash_parts(dash):
        assert 'dangerouslySetInnerHTML' not in part and 'innerHTML' not in part
    # a server text is a text node, never a template of markup
    assert 'createElement(' not in block


def test_the_secrets_are_write_only_inputs(block):
    form = _between(block, 'function QnetdHostForm(', 'function QnetdHostCard(')
    # the password field masks what is typed and keeps the browser's saved logins out
    pw = _between(form, '<input id="qnetd-password"', '/>')
    assert 'type="password"' in pw and 'autoComplete="new-password"' in pw and 'value={password}' in pw
    # the key: no spell check (it would leave the page), no autofill
    key = _between(form, '<textarea id="qnetd-key"', '/>')
    assert 'spellCheck={false}' in key and 'autoComplete="off"' in key and 'value={sshKey}' in key
    # both start empty and are never filled from what the server sent
    assert "const [password, setPassword] = useState('');" in form
    assert "const [sshKey, setSshKey] = useState('');" in form
    # the browser keeps one thing of this block: when the QDevice notice of a cluster was hidden
    hint = _between(block, 'function qdevHintHidden(', 'function QdeviceHint(')
    assert hint.count('localStorage') == 2 and 'window.localStorage.setItem(qdevHintKey(cid), String(Date.now()))' in hint
    rest = block.replace(hint, '')
    for word in ('host.password', 'host.ssh_key', 'password_encrypted', 'ssh_key_encrypted', 'localStorage',
                 'sessionStorage', 'console.'):
        assert word not in rest, word
    # and they are dropped once the server took them
    assert ("setPassword('');\n                setSshKey('');\n"
            "                onDone(editing, r.data && typeof r.data.host === 'object' ? r.data.host : null);") in form


def test_the_actions_are_for_an_admin_on_an_instance_that_acts(block):
    hook = _between(block, 'function useQnetdAccess()', 'function useQdevJob(')
    assert 'return isAdmin && !haReadOnly && value && value.ok ? value : null;' in hook
    probe = _between(block, 'function qnetdProbe(', 'function useQnetdAccess()')
    # a refusal (confined admin) and a server without the routes are both a no
    assert 'r.status === 403 || r.status === 404' in probe
    for name in ('QdeviceSetupButton', 'QdeviceRemoveButton', 'QdeviceHint', 'QdeviceQuorumButton'):
        fn = _between(block, f'function {name}(', '\n        }\n')
        assert 'const access = useQnetdAccess();' in fn
    panel = _between(block, 'function QnetdHostsPanel(', '\n        }\n')
    assert "} else if (r.status === 403 || r.status === 404) {\n                    setState('absent');" in panel
    assert "if (state === 'absent') return null;" in panel
    # a standby that does not forward shows the list and says where changes are made
    assert '{haReadOnly && <HaSettingsOnActive />}' in panel
    assert '{!haReadOnly && !form && state' in panel and 'readOnly={haReadOnly}' in panel


def test_the_mounts(dash):
    modal = _read('web', 'src', 'settings_modal.js')
    assert ("{activeTab === 'ha' && isAdmin && (\n"
            "                                <QnetdHostsPanel t={t} addToast={addToast} getAuthHeaders={getAuthHeaders} />") in modal
    heading = _dash_parts(dash)[0]
    assert '<QdeviceSetupButton' in heading and 'onChanged={() => fetchQdevice(selectedCluster.id)}' in heading
    assert "q={selectedCluster.cluster_type === 'xcpng' ? null : qdeviceByCluster[selectedCluster.id]}" in heading
    # both QDevice views know their cluster and read it again after a removal
    for cid in ('selectedSidebarQdevice', 'qdeviceOpen'):
        assert f'clusterId={{{cid}}}' in dash and f'onChanged={{() => fetchQdevice({cid})}}' in dash
    detail = _between(_read('web', 'src', 'node_modals.js'), 'function QdeviceDetail(', '// Node Management Modal Component')
    assert detail.count('{remove}') == 2


def test_the_alert_rule_is_in_the_dialog(dash):
    assert "EVENT_ALERT_METRICS.push('qnetd');" in dash
    assert '<option value="qnetd">{t(\'qnetdAlertTitle\')}</option>' in dash
    # an administrator's rule: offered to them (and shown on a rule that is one already)
    assert "{(isAdmin || alertMetricSel === 'qnetd') && <option value=\"qnetd\">" in dash
    assert ": alertMetricSel === 'qnetd' ? `${t('qnetdAlertHelp')} ${t('qnetdAlertAdminNote')}`" in dash
    assert "if (alert.metric === 'qnetd') return t('qnetdAlertSummary');" in dash
    # the server pins the rule to the cluster: no target to pick
    assert "{alertMetricSel !== 'ceph_health' && alertMetricSel !== 'qnetd' && (" in dash


def test_odd_node_counts_are_explained(block):
    assert "{c.id === 'node_count_even' && c.ok === false && (" in block
    assert "const odd = Number.isInteger(nodeCount) && nodeCount % 2 === 1;" in block
    en = _blocks()['en']
    assert 'even number of nodes only' in re.search(r"^\s*qdevOddExplain: '(.*)',$", en, re.M).group(1)


def test_every_used_key_is_in_english_once_and_every_new_key_is_used(block, dash):
    en = _blocks()['en']
    used = _used_keys(block, dash)
    for key in sorted(used):
        n = len(re.findall(rf'^\s*{key}:', en, re.M))
        # a few generic keys were defined twice before this change
        assert n == 1 or key in ('name', 'node', 'online', 'cluster', 'failed', 'optional'), (key, n)
    new = _new_keys()
    assert new and new <= used, sorted(new - used)
    # the existing QDevice keys stay as they were (test_qdevice_ui pins that list)
    assert not any(k.startswith('qdevice') for k in new)


def test_new_keys_sit_before_the_pinned_ha_tail():
    en = _blocks()['en']
    tail = en.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
    for key in _new_keys():
        assert re.search(rf'^\s*{key}:', en, re.M).start() < tail, key


def test_placeholders_survive(block):
    en = _blocks()['en']
    want = {'qdevOddNodes': ['{n}'], 'qdevSetupDone': ['{host}'], 'qdevFailedAt': ['{error}', '{step}'],
            'qdevRemoveVia': ['{host}'], 'qdevBulkTitle': ['{host}'], 'qdevBulkAttached': ['{host}'],
            'qdevBulkOdd': ['{n}'], 'qdevBulkCheck': ['{n}'], 'qdevBulkStart': ['{n}'],
            'qdevBulkResult': ['{done}', '{n}'], 'qnetdNotAvailable': ['{reason}'],
            'qnetdProtocolOf': ['{have}', '{want}'], 'qnetdReadAgo': ['{n}'], 'qnetdNodesConnected': ['{n}'],
            'qnetdNodeId': ['{id}'], 'qnetdOtherClusters': ['{names}'], 'qnetdCheckFailed': ['{error}'],
            'qnetdDeleteAttached': ['{clusters}']}
    for key, marks in want.items():
        value = re.search(rf"^\s*{key}: '(.*)',$", en, re.M).group(1)
        assert sorted(re.findall(r'\{\w+\}', value)) == marks, (key, value)
        for mark in marks:
            assert f"t('{key}').replace('{mark}'" in block or f"replace('{mark}'" in block, (key, mark)
    # a server text replaced into a sentence goes in through a function: '$&' in it stays as it is
    found = 0
    for m in re.finditer(r"\.replace\('\{(error|reason|host|names|clusters|step)\}', (.{2})", block):
        assert m.group(2) == '()', m.group(0)
        found += 1
    assert found >= 10


def test_no_em_dash_and_no_forbidden_names(block, dash):
    en_lines = [ln for ln in _blocks()['en'].splitlines() if re.match(r'^\s*(?:qdev[A-Z]|qnetd[A-Z])', ln)]
    for text in [block, '\n'.join(en_lines)] + _dash_parts(dash):
        assert EM_DASH not in text and EN_DASH not in text
        assert not re.search(r'(?i)vm\s?ware|v\s?center', text)


def test_every_class_is_in_the_static_tailwind_build(block, dash):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(block)
    for part in _dash_parts(dash):
        names |= _classes(part)
    # class strings held in constants (QDEV_CARD, the notes, the state badges)
    for m in re.finditer(r"'((?:flex|rounded|bg|w-full|px|p-3|text|fixed)[a-z0-9:/\-\.\[\] ]*)'", block):
        names |= set(m.group(1).split())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_jobs_are_polled_until_they_end(block):
    hook = _between(block, 'function useQdevJob(', 'const QDEV_CHECK_KEYS')
    assert "`/qnetd/jobs/${jobId}`" in hook and 'QDEV_JOB_RE.test(jobId)' in hook
    assert "if (r.data.state !== 'running') return;" in hook
    assert 'timer = setTimeout(round' in hook and 'clearTimeout(timer)' in hook
    # a job the instance forgot (404) stops the polling
    assert 'r.status === 404' in hook
    # a window opened again follows the job that still runs
    assert block.count("x.state === 'running'") == 3


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function QnetdHostsPanel(', 'function QdeviceSetupDialog(', 'function QdeviceBulkDialog(',
                   'function QdeviceRemoveDialog(', 'function QdeviceHint(', 'function QdeviceQuorumButton(',
                   'data-qdev-setup-open', 'data-qdev-consent', 'data-qnetd-check-confirm', 'rolling-qdevice-setup',
                   'data-qnetd-panel', 'qnetdAlertHelp', '/qdevice/plan?', '/bulk-setup',
                   'React.createElement("option",{value:"qnetd"}'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

HOST_ID = 'a1b2c3d4e5f6'
JOB = '0123456789abcdef'
JOB2 = 'fedcba9876543210'
JOB3 = '1111111111111111'
HOSTILE = '<img src=x onerror="window.__pwned=1">'
SECRET = 'S3cret-pw-for-qnetd'


def _host(attached=True, protocol=2, kind='ssh', host_id=HOST_ID, name='witness'):
    clusters = [{'name': 'Testi', 'algorithm': 'Fifty-Fifty split', 'tie_breaker': 'Node with lowest node ID',
                 'nodes': [{'node_id': 1, 'addr': '10.0.0.1:41234', 'vote': 'ACK (ACK)', 'tls': 'Yes'},
                           {'node_id': 2, 'addr': '10.0.0.2:52011', 'vote': 'ACK (ACK)', 'tls': 'Yes'}]},
                {'name': 'elsewhere', 'algorithm': '', 'tie_breaker': '',
                 'nodes': [{'node_id': 1, 'addr': '10.9.9.9:4000', 'vote': 'ACK (ACK)', 'tls': 'Yes'}]}]
    return {
        'id': host_id, 'name': name, 'kind': kind, 'address': '10.0.0.9', 'port': 5403,
        'ssh_host': '10.0.0.9', 'ssh_port': 22, 'ssh_user': 'root', 'has_password': True, 'has_ssh_key': False,
        'ca_sha256': 'ab' * 32, 'created_by': 'admin', 'created_at': '2026-10-20T10:00:00+00:00',
        'updated_at': '2026-10-20T10:00:00+00:00',
        'attachments': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'attached_at': '2026-10-20T10:05:00+00:00',
                         'attached_by': 'admin'}] if attached else [],
        'status': {'qnetd_id': host_id, 'ok': True, 'active': True, 'protocol': protocol, 'outdated': protocol < 2,
                   'clusters': clusters if attached else clusters[1:], 'error': '',
                   'read_at': '2026-10-20T10:06:00+00:00', 'streak': 0, 'age': 12, 'expected_protocol': 2},
    }


def _check(cid, ok, message, blocking=True):
    return {'id': cid, 'ok': ok, 'blocking': blocking, 'message': message}


def _cert_held(report, replace):
    """The report of a cluster whose name the QNetd host holds a certificate of an earlier
    setup for: cert_on_file fails it, unless the plan replaces that certificate."""
    rep = copy.deepcopy(report)
    name = rep.get('cluster_name') or 'Testi'
    if replace:
        rep['checks'].append(_check('cert_on_file', True, f'The setup replaces the certificate the QNetd host '
                                                          f'holds for a cluster named {name} from an earlier setup'))
    else:
        rep['checks'].append(_check('cert_on_file', False, f'The QNetd host holds a certificate for a cluster named '
                                                           f'{name} from an earlier setup'))
        rep['ok'] = False
    return rep


def _report(cid='c1', nodes=2, name='Testi', ok=True):
    even = nodes % 2 == 0
    checks = [
        _check('node_count_even', even, f'{nodes} nodes' + ('' if even else
                                                          ': a QDevice is supported for an even number of nodes only')),
        _check('nodes_online', True, 'All nodes are online'),
        _check('quorate', True, 'The cluster is quorate'),
        # a server text with markup in it: shown as text
        _check('not_a_node', True, f'The QNetd host is no node of this cluster {HOSTILE}'),
        _check('qnetd_ready', True, 'The QNetd host answers (helper protocol 2) and corosync-qnetd runs'),
        _check('node_access', True, 'PegaProx can run commands on every node'),
        _check('packages', True, 'corosync-qdevice is installed on every node'),
        _check('qnetd_port', True, 'Every node reaches 10.0.0.9:5403'),
        _check('cluster_name', True, f'Cluster name {name}'),
        _check('no_qdevice', True, 'No QDevice is configured yet'),
        _check('two_node', True, 'two_node is not set'),
        _check('name_unique', ok, f'No other cluster named {name} uses this QNetd host' if ok
               else f'A cluster named {name} is connected to this QNetd host already'),
        _check('not_own_vm', True, 'The QNetd host is no guest of this cluster'),
    ]
    return {'ok': ok and even, 'cluster_id': cid, 'cluster_name': name, 'qnetd_id': HOST_ID, 'qnetd_name': 'witness',
            'qnetd_address': '10.0.0.9', 'qnetd_port': 5403, 'install_packages': False, 'needs_confirmation': False,
            'node_count': nodes, 'checks': checks, 'read_at': '2026-10-20T10:07:00+00:00',
            'nodes': [{'node': f'pve{i + 1}', 'online': True, 'ssh': True, 'packages': True, 'old_store': False,
                       'port_open': True, 'error': None} for i in range(nodes)]}


def _job(jid, kind, cids, state, rows, steps):
    return {'id': jid, 'kind': kind, 'qnetd_id': HOST_ID, 'cluster_ids': cids, 'user': 'admin', 'state': state,
            'error': '', 'created_at': '2026-10-20T10:08:00+00:00',
            'finished_at': None if state == 'running' else '2026-10-20T10:09:00+00:00',
            'clusters': {c: dict({'state': 'waiting', 'cluster_name': None, 'failed_step': None, 'error': '',
                                  'code': None, 'rolled_back': None, 'preflight': None}, **rows.get(c, {}))
                         for c in cids},
            'steps': [{'at': '2026-10-20T10:08:30+00:00', 'cluster_id': c, 'step': s, 'state': st, 'message': m}
                      for c, s, st, m in steps]}


SETUP_STEPS = [('c1', 'preflight', 'ok', 'Every check passed'),
               ('c1', 'qnetd_sign', 'ok', 'Cluster certificate for Testi signed'),
               ('c1', 'corosync_conf', 'ok', 'quorum.device written (net, tls on, ffsplit, host 10.0.0.9)'),
               ('c1', 'corosync_reload', 'ok', 'corosync configuration reloaded')]
TWO_NODES = dict(NODE_METRICS, pve2=dict(NODE_METRICS['pve1']))
THREE_NODES = dict(TWO_NODES, pve3=dict(NODE_METRICS['pve1']))
QDEV_PRESENT = {'present': True, 'answered_by': 'pve1', 'state': 'Connected', 'qnetd_host': '10.0.0.9:5403',
                'model': 'Net', 'algorithm': 'Fifty-Fifty split', 'tie_breaker': 'Node with lowest node ID',
                'last_poll': None, 'echo_reply': None, 'read_at': '2026-10-20T10:12:05+00:00',
                'nodes': [{'node': 'pve1', 'online': True, 'api_host': True, 'asked': True, 'answered': True,
                           'present': True, 'connected': True, 'state': 'Connected', 'last_poll': None,
                           'echo_reply': None, 'error': None}]}


HELPER = '/usr/lib/pegaprox/qnetd/pegaprox-qnetd-helper'
SOURCES = ['10.0.0.1', '10.0.0.2']
FW_UFW = {'backend': 'ufw', 'managed': True, 'blocking': True, 'port': 5403, 'manual': ''}
FW_UFW_OPEN = dict(FW_UFW, blocking=False)
FW_NFT = {'backend': 'nftables', 'managed': False, 'blocking': True, 'port': 5403,
          'manual': 'nft add rule inet filter input ip saddr 10.0.0.1 tcp dport 5403 accept\n'
                    'nft add rule inet filter input ip saddr 10.0.0.2 tcp dport 5403 accept'}
FW_NONE = {'backend': 'none', 'managed': False, 'blocking': False, 'port': 5403, 'manual': ''}
PLAN_OPTS = ('install_packages', 'open_firewall', 'confirm_unverified_host', 'replace_certificate')


def _item(id_, where, text, **params):
    return {'id': id_, 'where': where, 'node': None, 'params': params, 'text': text}


def _digest(cid, host_id, opts):
    body = dict(opts, cluster_id=cid, qnetd=host_id)
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _plan(cid, host, opts, report, fw, extra_items=(), held=None):
    """What /qdevice/plan answers, the way pegaprox/core/qnetd.py plan() builds it: a helper the
    QNetd host lacks (a host never read) puts what its init does there as items only where
    needed, and the firewall is unknown until the helper answers. held: the clusters whose name
    the QNetd host holds a certificate of an earlier setup for (None: its helper does not say)."""
    st = host.get('status') or {}
    sidecar = host['kind'] == 'sidecar'
    helper = None if sidecar or st.get('protocol', 0) >= 2 else ('update' if st else 'install')
    items = []
    if helper == 'install':
        items.append(_item('qnetd_helper_install', 'qnetd', f'Install the PegaProx helper on the QNetd host ({HELPER})',
                           path=HELPER))
        items += [_item('qnetd_packages', 'qnetd', 'Install corosync-qnetd and the NSS tools with the package manager '
                                                   'of the QNetd host where they are missing',
                        package_manager=None, packages=None, if_needed=True),
                  _item('qnetd_ca', 'qnetd', 'Create the QNetd certificate authority where there is none', if_needed=True),
                  _item('qnetd_tls', 'qnetd', 'Require TLS from the nodes (-s req)', if_needed=True),
                  _item('qnetd_start', 'qnetd', 'Enable and start corosync-qnetd where it does not run', if_needed=True)]
    elif helper == 'update':
        items.append(_item('qnetd_helper_update', 'qnetd', 'Replace the outdated PegaProx helper', path=HELPER))
    known = None if sidecar or helper == 'install' else fw
    if opts['open_firewall'] and not sidecar and (known is None or (known['managed'] and known['blocking'] is not False)):
        items.append(_item('firewall_open', 'qnetd', f"Open TCP port 5403 for {', '.join(SOURCES)}",
                           backend=known['backend'] if known else None, port=5403, sources=list(SOURCES)))
    name = report.get('cluster_name') or 'Testi'
    if opts['replace_certificate'] and (held is None or cid in held):
        items.append(_item('cert_replace', 'qnetd', f'Replace the certificate for {name}', cluster_name=name))
    nodes = [n['node'] for n in report.get('nodes') or []]
    if opts['install_packages']:
        items.append(_item('node_packages', 'node', f'Install corosync-qdevice with apt-get on {nodes[-1]}',
                           nodes=nodes[-1:]))
    items += [_item('node_certs', 'node', f"Import the QNetd CA on {', '.join(nodes)}", nodes=nodes),
              _item('corosync_conf', 'cluster', 'Add the quorum.device section', address=host['address'],
                    port=host['port']),
              _item('qdevice_service', 'node', f"Enable and start corosync-qdevice on {', '.join(nodes)}", nodes=nodes),
              _item('corosync_reload', 'cluster', 'Reload the corosync configuration'),
              _item('votes', 'cluster', 'One more vote', before=len(nodes), after=len(nodes) + 1)]
    items += [dict(i) for i in extra_items]
    firewall = None
    if known is not None or opts['open_firewall']:
        base = known or {'backend': None, 'managed': None, 'blocking': None, 'port': 5403, 'manual': ''}
        firewall = dict(base, requested=opts['open_firewall'], sources=list(SOURCES))
    warnings = []
    if firewall and firewall['manual'] and firewall['blocking'] is not False:
        warnings.append({'id': 'firewall_manual', 'text': 'PegaProx does not change the firewall of the QNetd host',
                         'params': {'backend': firewall['backend'], 'manual': firewall['manual']}})
    return {'ok': bool(report['ok']), 'preflight': report, 'firewall': firewall, 'warnings': warnings,
            'plan': {'digest': _digest(report.get('cluster_id') or cid, host['id'], opts), 'items': items}}


class _QnetdServer(_FakeServer):
    """The fake server of test_ha_ui with the QNetd routes: hosts, checks, the plan (with the
    preflight report in it), a setup that wants the digest of a plan it made, and jobs that
    run for one read and then end as the test says."""

    def __init__(self, hosts=None, hosts_status=200, reports=None, node_counts=None, qdevice=None,
                 jobs=None, firewall=FW_UFW, extra_items=(), ha_members=1, transports=None, held=None, **kw):
        kw.setdefault('extra', dict(SSE_TOKEN))
        super().__init__(**kw)
        self.q_hosts = copy.deepcopy(hosts or [])
        self.q_hosts_status = hosts_status
        self.q_reports = reports or {}
        self.q_nodes = node_counts or {}
        self.q_qdevice = qdevice or {}
        self.q_firewall = firewall
        self.q_extra_items = list(extra_items)
        self.q_ha_members = ha_members
        # the clusters whose name the QNetd host holds a certificate of an earlier setup for
        self.q_held = None if held is None else set(held)
        self.q_transports = transports or {
            'local': {'available': False, 'reason': 'helper not installed (packaging/qnetd/install.sh)'},
            'sidecar': {'available': False, 'reason': 'no helper socket'}}
        # every digest a plan answer carried: a setup has to name one of them
        self.q_digests = set()
        # job id -> the views it goes through; the last one stays
        self.q_jobs = {k: list(v) for k, v in (jobs or {}).items()}
        self.q_next_jobs = []
        self.q_reads = {}

    def _job_view(self, jid):
        views = self.q_jobs.get(jid)
        if not views:
            return None
        n = self.q_reads.get(jid, 0)
        self.q_reads[jid] = n + 1
        return views[min(n, len(views) - 1)]

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        qnetd = path.startswith('/api/qnetd/') or re.fullmatch(r'/api/clusters/[^/]+/(qdevice(/.*)?|nodes)', path)
        if not qnetd:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

        m = re.fullmatch(r'/api/clusters/([^/]+)/qdevice', path)
        if m:
            return answer(self.q_qdevice.get(m.group(1), {'present': False}))
        m = re.fullmatch(r'/api/clusters/([^/]+)/nodes', path)
        if m:
            n = self.q_nodes.get(m.group(1), 2)
            return answer([{'node': f'pve{i + 1}', 'status': 'online'} for i in range(n)])
        m = re.fullmatch(r'/api/clusters/([^/]+)/qdevice/preflight', path)
        if m:
            return answer(self.q_reports.get(m.group(1)) or _report(m.group(1)))
        m = re.fullmatch(r'/api/clusters/([^/]+)/qdevice/plan', path)
        if m:
            query = dict(re.findall(r'[?&]([a-z_]+)=([^&]*)', req.url))
            rec = next((h for h in self.q_hosts if h['id'] == query.get('qnetd_id')), None)
            if rec is None:
                return answer({'error': 'QNetd host not found'}, 404)
            opts = {k: query.get(k) == '1' for k in PLAN_OPTS}
            rep = self.q_reports.get(m.group(1)) or _report(m.group(1))
            if self.q_held and m.group(1) in self.q_held:
                rep = _cert_held(rep, opts['replace_certificate'])
            out = _plan(m.group(1), rec, opts, rep, self.q_firewall, self.q_extra_items, self.q_held)
            self.q_digests.add(out['plan']['digest'])
            return answer(out)
        # the agreement the real route wants before it registers a job
        if path.endswith('/qdevice/setup'):
            consent = body.get('consent') if isinstance(body.get('consent'), dict) else {}
            if consent.get('accepted') is not True or consent.get('digest') not in self.q_digests:
                return answer({'error': 'Agree to the plan of this cluster first', 'code': 'consent_required'}, 400)
        if path.endswith('/bulk-setup'):
            consents = body.get('consents') if isinstance(body.get('consents'), dict) else {}
            ids = body.get('cluster_ids') or []
            if sorted(consents) != sorted(ids) or not all(consents[c] in self.q_digests for c in ids):
                return answer({'error': 'agree to the plan of every cluster', 'code': 'consent_required'}, 400)
        if re.fullmatch(r'/api/clusters/[^/]+/qdevice/(setup|remove)', path) or path.endswith('/bulk-setup'):
            if self.q_next_jobs:
                jid = self.q_next_jobs.pop(0)
            else:
                # a test that does not follow the job: it is done at the first read
                one = re.fullmatch(r'/api/clusters/([^/]+)/qdevice/(setup|remove)', path)
                cids = [one.group(1)] if one else list(body.get('cluster_ids') or [])
                jid = format(0xabc000 + len(self.q_jobs), '016x')
                self.q_jobs[jid] = [_job(jid, one.group(2) if one else 'bulk', cids, 'done',
                                         {c: {'state': 'done'} for c in cids}, [])]
            return answer({'success': True, 'job_id': jid, 'job': self._job_view(jid)}, 202)
        m = re.fullmatch(r'/api/qnetd/jobs/([0-9a-f]+)', path)
        if m:
            view = self._job_view(m.group(1))
            return answer(view, 200) if view else answer({'error': 'Job not found'}, 404)
        if path == '/api/qnetd/jobs':
            return answer({'jobs': []})
        if path == '/api/qnetd/hosts' and req.method == 'GET':
            if self.q_hosts_status != 200:
                return answer({'error': 'refused'}, self.q_hosts_status)
            return answer({'hosts': self.q_hosts, 'protocol': 2, 'default_port': 5403,
                           'ha_members': self.q_ha_members, 'transports': self.q_transports})
        if path == '/api/qnetd/hosts' and req.method == 'POST':
            rec = {k: body.get(k) for k in ('name', 'kind', 'address', 'port', 'ssh_host', 'ssh_port', 'ssh_user')}
            rec.update(id='0f0f0f0f0f0f', has_password=bool(body.get('password')), has_ssh_key=bool(body.get('ssh_key')),
                       ca_sha256='', attachments=[], status=None)
            self.q_hosts.append(rec)
            return answer({'success': True, 'host': rec}, 201)
        m = re.fullmatch(r'/api/qnetd/hosts/([0-9a-f]{12})(/[a-z-]+)?', path)
        if m:
            rec = next((h for h in self.q_hosts if h['id'] == m.group(1)), None)
            if rec is None:
                return answer({'error': 'QNetd host not found'}, 404)
            if req.method == 'DELETE':
                if rec['attachments']:
                    return answer({'error': 'Clusters vote through this QNetd host: remove their QDevice first',
                                   'clusters': [a['cluster_name'] for a in rec['attachments']]}, 409)
                self.q_hosts.remove(rec)
                return answer({'success': True})
            if m.group(2) == '/status':
                st = dict(rec['status'] or _host()['status'], raw=f'Cluster "Testi":\n    Algorithm: Fifty-Fifty split {HOSTILE}')
                return answer({'status': st})
            if m.group(2) == '/check':
                return answer({'ok': True, 'helper_installed': True, 'active': True, 'error': '', 'protocol': 2,
                               'expected_protocol': 2, 'outdated': False, 'ca_sha256': 'ab' * 32})
        return answer({'error': 'not mocked'}, 404)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [VM])
        kw.setdefault('metrics', TWO_NODES)
        app = _App(browser, _QnetdServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _settings_panel(app):
    app.open_settings()
    app.page.locator('button', has_text='High Availability').first.click()
    panel = app.page.locator('[data-qnetd-panel]')
    panel.wait_for(timeout=5000)
    return panel


def _select_cluster(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/qdevice'), seconds=5)
    return page


def _no_markup_ran(page):
    assert page.evaluate('() => window.__pwned === undefined')


def _open_wizard(app, cid='c1'):
    page = _select_cluster(app)
    # a cluster of an even node count without a QDevice shows the notice, and its Set up opens
    # the wizard; the small button next to Nodes gives way to it (and is there for the others)
    button = page.locator(f'[data-qdev-hint-setup="{cid}"], [data-qdev-setup-open="{cid}"]').first
    button.wait_for(timeout=5000)
    button.click()
    dialog = page.locator(f'[data-qdev-setup="{cid}"]')
    dialog.wait_for(timeout=3000)
    return page, dialog


def _settled(dialog):
    """No plan read under way and Next (or Start's consent) usable: the plan on screen is the
    one of the options on screen."""
    dialog.page.wait_for_timeout(150)
    dialog.locator('[data-qdev-checking]').wait_for(state='detached', timeout=8000)


def _next(dialog):
    dialog.locator('[data-qdev-next]:not([disabled])').wait_for(timeout=8000)
    dialog.locator('[data-qdev-next]').click()


def _to_options(dialog):
    _next(dialog)
    dialog.locator('[data-qdev-options]').wait_for(timeout=3000)
    _settled(dialog)


def _to_review(dialog):
    _to_options(dialog)
    _next(dialog)
    dialog.locator('[data-qdev-review]').wait_for(timeout=3000)
    _settled(dialog)
    dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)


def _digest_on_screen(dialog):
    return dialog.locator('[data-qdev-review] [data-qdev-plan]').get_attribute('data-qdev-plan')


def _plan_reads(app, cid='c1'):
    return [u for u in app.server.urls if f'/api/clusters/{cid}/qdevice/plan?' in u]


def test_runtime_the_hosts_panel_lists_and_adds_a_host_whose_password_goes_out_once(open_app):
    app = open_app(hosts=[_host()])
    page = app.page
    panel = _settings_panel(app)
    card = panel.locator(f'[data-qnetd-host="{HOST_ID}"]')
    card.wait_for(timeout=5000)
    text = card.inner_text()
    for want in ('witness', 'Linux host over SSH', '10.0.0.9:5403', 'root@10.0.0.9:22', '2 (this PegaProx speaks 2)',
                 'Running', 'Testi', 'Nodes connected: 2', 'Node 1 - 10.0.0.1:41234 - vote: ACK (ACK)',
                 'Other clusters on this QNetd host: elsewhere', 'read 12 s ago'):
        assert want in text, want
    assert card.locator('[data-qnetd-state]').get_attribute('data-qnetd-state') == 'ok'
    assert card.locator('[data-qnetd-attachment="c1"] [data-qnetd-connected]').get_attribute('data-qnetd-connected') == '2'
    # the stored login is never shown, only that there is one
    assert 'ab' * 32 not in text and SECRET not in page.content()

    # delete is refused while a cluster votes through it, and says which, without asking the server
    card.locator('[data-qnetd-delete]').click()
    assert 'Remove the QDevice of these clusters first: Testi' in card.locator('[data-qnetd-refused]').inner_text()
    assert not any(c[0] == 'DELETE' for c in app.server.calls)

    # add an SSH host with a password
    panel.locator('[data-qnetd-add]').click()
    form = panel.locator('[data-qnetd-form="add"]')
    form.wait_for(timeout=3000)
    # the local and sidecar ways say why they are not ready on this machine
    assert 'helper not installed' in form.locator('[data-qnetd-kind-option="local"]').inner_text()
    page.fill('#qnetd-name', 'site-c')
    page.fill('#qnetd-address', '10.0.5.5')
    page.fill('#qnetd-password', SECRET)
    assert form.locator('#qnetd-password').get_attribute('type') == 'password'
    form.locator('[data-qnetd-save]').click()
    assert _wait_for_call(app, ('POST', '/api/qnetd/hosts'), seconds=5)
    sent = app.server.bodies['/api/qnetd/hosts'][-1]
    assert sent == {'name': 'site-c', 'kind': 'ssh', 'address': '10.0.5.5', 'port': 5403, 'ssh_host': '10.0.5.5',
                    'ssh_port': 22, 'ssh_user': 'root', 'password': SECRET}
    panel.locator('[data-qnetd-host="0f0f0f0f0f0f"]').wait_for(timeout=5000)
    assert panel.locator('[data-qnetd-form]').count() == 0
    # gone from the page once the server took it
    assert SECRET not in page.content()
    # the new host was read once (it had no status yet), the raw text is shown as text
    assert _wait_for_call(app, ('GET', '/api/qnetd/hosts/0f0f0f0f0f0f/status'), seconds=5)
    new = panel.locator('[data-qnetd-host="0f0f0f0f0f0f"]')
    new.get_by_text('Output of corosync-qnetd-tool').click()
    assert HOSTILE in new.locator('pre').inner_text()
    _no_markup_ran(page)
    assert not app.errors, app.errors


def test_runtime_check_and_delete_of_a_free_host(open_app):
    app = open_app(hosts=[_host(attached=False, protocol=1)])
    panel = _settings_panel(app)
    card = panel.locator(f'[data-qnetd-host="{HOST_ID}"]')
    card.wait_for(timeout=5000)
    assert 'None yet' in card.inner_text()
    # it never answered with protocol 2: what Check does on it comes first
    card.locator('[data-qnetd-check]').click()
    card.locator('[data-qnetd-check-confirm]').wait_for(timeout=2000)
    assert ('POST', f'/api/qnetd/hosts/{HOST_ID}/check') not in app.server.calls
    card.locator('[data-qnetd-check-go]').click()
    card.locator('[data-qnetd-checked="ok"]').wait_for(timeout=5000)
    assert 'Ready: corosync-qnetd runs - helper installed' in card.inner_text()
    assert app.server.bodies[f'/api/qnetd/hosts/{HOST_ID}/check'][-1] == {}
    card.locator('[data-qnetd-delete]').click()
    card.locator('[data-qnetd-delete-confirm]').wait_for(timeout=2000)
    card.locator('[data-qnetd-delete-go]').click()
    assert _wait_for_call(app, ('DELETE', f'/api/qnetd/hosts/{HOST_ID}'), seconds=5)
    panel.locator('[data-qnetd-empty]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_setup_from_the_cluster_checks_starts_and_follows_the_job(open_app):
    running = _job(JOB, 'setup', ['c1'], 'running', {'c1': {'state': 'running', 'cluster_name': 'Testi'}},
                   SETUP_STEPS[:2])
    done = _job(JOB, 'setup', ['c1'], 'done', {'c1': {'state': 'done', 'cluster_name': 'Testi'}}, SETUP_STEPS)
    app = open_app(hosts=[_host(attached=False)], jobs={JOB: [running, done]})
    app.server.q_next_jobs = [JOB]
    page, dialog = _open_wizard(app)
    # Where: the one QNetd host is taken, with its state
    where = dialog.locator(f'[data-qdev-where-host="{HOST_ID}"]')
    where.wait_for(timeout=5000)
    assert where.locator('input').is_checked()
    assert where.locator('[data-qdev-where-state]').get_attribute('data-qdev-where-state') == 'ok'
    _to_review(dialog)
    # the plan was read with corosync-qdevice on by default, then again with the port opened:
    # ufw blocks it on that host
    reads = _plan_reads(app)
    assert reads[0].endswith(f'/api/clusters/c1/qdevice/plan?qnetd_id={HOST_ID}&install_packages=1'), reads
    assert reads[-1].endswith(f'?qnetd_id={HOST_ID}&install_packages=1&open_firewall=1'), reads
    plan = dialog.locator('[data-qdev-review] [data-qdev-plan]')
    assert 'Open TCP port 5403 with ufw for 10.0.0.1, 10.0.0.2' in plan.locator('[data-qdev-item="firewall_open"]').inner_text()
    checks = dialog.locator('[data-qdev-check="node_count_even"]').inner_text()
    assert 'Even number of nodes' in checks and '2 nodes' in checks
    assert HOSTILE in dialog.locator('[data-qdev-check="not_a_node"]').inner_text()
    assert dialog.locator('[data-qdev-node]').count() == 2
    # nothing starts before the admin agreed to this plan for this cluster
    start = dialog.locator('[data-qdev-start]')
    assert start.is_disabled()
    assert 'I agree that PegaProx makes these changes on Testi' in dialog.inner_text()
    dialog.locator('[data-qdev-consent]').check()
    digest = _digest_on_screen(dialog)
    start.click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/setup'), seconds=5)
    assert app.server.bodies['/api/clusters/c1/qdevice/setup'][-1] == {
        'qnetd_id': HOST_ID, 'install_packages': True, 'open_firewall': True, 'confirm_unverified_host': False,
        'replace_certificate': False, 'consent': {'accepted': True, 'digest': digest}}
    # polled until it ends; the log names the steps
    dialog.locator('[data-qdev-outcome="done"]').wait_for(timeout=10000)
    assert 'The QDevice is set up: the cluster votes through witness now.' in dialog.inner_text()
    log = dialog.locator('[data-qdev-log]').inner_text()
    assert 'Write corosync.conf' in log and 'quorum.device written' in log
    assert app.server.q_reads[JOB] >= 2
    reads = app.server.calls.count(('GET', '/api/clusters/c1/qdevice'))
    dialog.get_by_role('button', name='Close').last.click()
    assert page.locator('[data-qdev-setup]').count() == 0
    # closing reads the cluster's QDevice again
    page.wait_for_timeout(500)
    assert app.server.calls.count(('GET', '/api/clusters/c1/qdevice')) > reads
    _no_markup_ran(page)
    assert not app.errors, app.errors


class _EnUs:
    """A browser whose new contexts run en-US, whatever the locale of this machine is."""

    def __init__(self, br):
        self.br = br

    def new_context(self, **kw):
        return self.br.new_context(locale='en-US', **kw)


@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
def test_runtime_the_job_log_writes_its_times_as_the_layout_does(browser, layout):  # noqa: F811
    """The classic layouts write a time in the browser's locale, the redesign in the UI
    language: a German page in Corporate Redesigned shows the steps at German 24 h times in
    an en-US browser, Modern the browser's own."""
    done = _job(JOB, 'setup', ['c1'], 'done', {'c1': {'state': 'done', 'cluster_name': 'Testi'}}, SETUP_STEPS)
    app = _App(_EnUs(browser), _QnetdServer(role='standalone', layout=layout, language='de', clusters=[CLUSTER],
                                           resources=[VM], metrics=TWO_NODES, hosts=[_host(attached=False)],
                                           jobs={JOB: [done]}))
    try:
        app.server.q_next_jobs = [JOB]
        page = app.page
        assert page.evaluate('() => navigator.language') == 'en-US'
        if layout == 'modern':
            page.get_by_text('Testi').first.click()
        else:
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        assert _wait_for_call(app, ('GET', '/api/clusters/c1/qdevice'), seconds=8)
        page.locator('[data-qdev-hint-setup="c1"], [data-qdev-setup-open="c1"]').first.click()
        dialog = page.locator('[data-qdev-setup="c1"]')
        dialog.wait_for(timeout=3000)
        _to_review(dialog)
        dialog.locator('[data-qdev-consent]').check()
        dialog.locator('[data-qdev-start]').click()
        dialog.locator('[data-qdev-outcome="done"]').wait_for(timeout=10000)
        at = '2026-10-20T10:08:30+00:00'
        want = page.evaluate("""([at, redesigned]) => redesigned
            ? new Intl.DateTimeFormat('de', {hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false}).format(new Date(at))
            : new Date(at).toLocaleTimeString()""", [at, layout != 'modern'])
        assert bool(re.search(r'[AP]M', want)) == (layout == 'modern'), want
        times = dialog.locator('[data-qdev-step] > span:first-child').all_inner_texts()
        assert times == [want] * len(SETUP_STEPS), (times, want)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_an_odd_cluster_is_told_why_and_cannot_start(open_app):
    app = open_app(hosts=[_host(attached=False)], metrics=THREE_NODES, reports={'c1': _report(nodes=3)})
    page, dialog = _open_wizard(app)
    hint = dialog.locator('[data-qdev-odd-hint]')
    hint.wait_for(timeout=3000)
    assert 'Nodes in this cluster: 3.' in hint.inner_text() and 'even number of nodes only' in hint.inner_text()
    _to_review(dialog)
    dialog.locator('[data-qdev-preflight="fail"]').wait_for(timeout=5000)
    row = dialog.locator('[data-qdev-check="node_count_even"]')
    assert row.get_attribute('data-qdev-check-tone') == 'bad'
    assert 'single point of failure' in row.locator('[data-qdev-odd]').inner_text()
    # a plan that does not pass cannot be agreed to
    assert dialog.locator('[data-qdev-consent]').is_disabled()
    assert dialog.locator('[data-qdev-start]').is_disabled()
    assert ('POST', '/api/clusters/c1/qdevice/setup') not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_name_held_by_an_earlier_setup_can_be_replaced(open_app):
    failed = _job(JOB, 'setup', ['c1'], 'failed',
                  {'c1': {'state': 'failed', 'cluster_name': 'Testi', 'failed_step': 'qnetd_sign', 'code': 'name_exists',
                          'error': 'sign: a certificate for Testi exists already', 'rolled_back': True}},
                  SETUP_STEPS[:1] + [('c1', 'qnetd_sign', 'failed', 'sign: a certificate for Testi exists already')])
    done = _job(JOB2, 'setup', ['c1'], 'done', {'c1': {'state': 'done', 'cluster_name': 'Testi'}}, SETUP_STEPS)
    app = open_app(hosts=[_host(attached=False)], jobs={JOB: [failed], JOB2: [done]})
    app.server.q_next_jobs = [JOB, JOB2]
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-consent]').check()
    first = _digest_on_screen(dialog)
    dialog.locator('[data-qdev-start]').click()
    outcome = dialog.locator('[data-qdev-outcome="failed"]')
    outcome.wait_for(timeout=8000)
    text = outcome.inner_text()
    assert 'Failed at "Sign on the QNetd host": sign: a certificate for Testi exists already' in text
    assert outcome.locator('[data-qdev-rolled-back]').count() == 1
    # replacing the certificate is another plan: shown, and agreed to again
    outcome.locator('[data-qdev-replace]').click()
    dialog.locator('[data-qdev-review]').wait_for(timeout=3000)
    _settled(dialog)
    dialog.locator('[data-qdev-item="cert_replace"]').wait_for(timeout=8000)
    assert 'Replace the certificate the QNetd host holds for the cluster name Testi' in dialog.inner_text()
    assert _plan_reads(app)[-1].endswith('&replace_certificate=1')
    assert not dialog.locator('[data-qdev-consent]').is_checked()
    assert dialog.locator('[data-qdev-start]').is_disabled()
    dialog.locator('[data-qdev-consent]').check()
    second = _digest_on_screen(dialog)
    assert second != first
    dialog.locator('[data-qdev-start]').click()
    dialog.locator('[data-qdev-outcome="done"]').wait_for(timeout=8000)
    sent = app.server.bodies['/api/clusters/c1/qdevice/setup'][-1]
    assert sent['replace_certificate'] is True and sent['consent'] == {'accepted': True, 'digest': second}
    assert not app.errors, app.errors


def test_runtime_remove_needs_the_word(open_app):
    done = _job(JOB, 'remove', ['c1'], 'done', {'c1': {'state': 'done'}},
                [('c1', 'remove', 'running', 'pvecm qdevice remove on pve1'), ('c1', 'remove', 'ok', 'QDevice removed')])
    app = open_app(hosts=[_host()], qdevice={'c1': QDEV_PRESENT}, jobs={JOB: [done]})
    app.server.q_next_jobs = [JOB]
    page = _select_cluster(app)
    # a cluster with a QDevice has no Set up button
    page.locator('[data-qdevice-entry="c1"]').first.click()
    view = page.locator('[data-qdevice-view]')
    view.wait_for(timeout=3000)
    assert page.locator('[data-qdev-setup-open]').count() == 0
    view.locator('[data-qdev-remove-open="c1"]').click()
    dialog = page.locator('[data-qdev-remove="c1"]')
    dialog.wait_for(timeout=3000)
    assert 'Set up by PegaProx with QNetd host witness' in dialog.inner_text()
    # the rules it opened the QNetd port with go too, and the admin reads that first
    assert 'The firewall rules PegaProx added for this cluster on the QNetd host are taken out as well' in \
        dialog.locator('[data-qdev-remove-firewall]').inner_text()
    go = dialog.locator('[data-qdev-remove-go]')
    assert go.is_disabled()
    page.fill('[data-qdev-remove-typed]', 'remove')
    assert go.is_disabled()
    page.fill('[data-qdev-remove-typed]', 'REMOVE')
    go.click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/remove'), seconds=5)
    dialog.locator('[data-qdev-outcome="done"]').wait_for(timeout=8000)
    assert 'QDevice removed' in dialog.locator('[data-qdev-log]').inner_text()
    assert not app.errors, app.errors


def test_runtime_bulk_setup_per_cluster(open_app):
    beta = dict(CLUSTER, id='c2', name='Beta', display_name='Beta')
    gamma = dict(CLUSTER, id='c3', name='Gamma', display_name='Gamma')
    final = _job(JOB, 'bulk', ['c1', 'c3'], 'partial',
                 {'c1': {'state': 'done', 'cluster_name': 'Testi'},
                  'c3': {'state': 'failed', 'cluster_name': 'Gamma', 'failed_step': 'qnetd_sign', 'code': 'name_exists',
                         'error': 'sign: a certificate for Gamma exists already', 'rolled_back': True}},
                 SETUP_STEPS + [('c3', 'qnetd_sign', 'failed', 'sign: a certificate for Gamma exists already')])
    retry = _job(JOB3, 'bulk', ['c3'], 'done', {'c3': {'state': 'done', 'cluster_name': 'Gamma'}},
                 [('c3', 'corosync_reload', 'ok', 'corosync configuration reloaded')])
    app = open_app(hosts=[_host(attached=False)], clusters=[CLUSTER, beta, gamma], node_counts={'c1': 2, 'c2': 3, 'c3': 4},
                   reports={'c1': _report('c1'), 'c3': _report('c3', nodes=4, name='Gamma')},
                   jobs={JOB: [final], JOB3: [retry]})
    app.server.q_next_jobs = [JOB, JOB3]
    page = app.page
    panel = _settings_panel(app)
    panel.locator(f'[data-qnetd-host="{HOST_ID}"] [data-qnetd-bulk]').click()
    dialog = page.locator(f'[data-qdev-bulk="{HOST_ID}"]')
    dialog.wait_for(timeout=3000)
    # the odd one says why it cannot be picked, once its nodes are counted
    odd = dialog.locator('[data-qdev-bulk-row="c2"] [data-qdev-bulk-why]')
    odd.wait_for(timeout=5000)
    assert odd.inner_text() == 'Nodes: 3 - a QDevice needs an even number'
    assert dialog.locator('[data-qdev-bulk-row="c2"] input[type="checkbox"]').is_disabled()
    dialog.locator('[data-qdev-bulk-row="c3"]').get_by_text('Nodes: 4').wait_for(timeout=5000)
    dialog.locator('[data-qdev-bulk-even]').click()
    dialog.locator('[data-qdev-bulk-check]').click()
    dialog.locator('[data-qdev-bulk-row="c3"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-bulk-row="c1"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    assert not any('/api/clusters/c2/qdevice/' in u for u in app.server.urls)
    # the first plan found ufw blocking the port: Open port is on for the run, every plan made with it
    assert dialog.locator('[data-qdev-firewall]').is_checked()
    plans = [u for u in app.server.urls if '/qdevice/plan?' in u]
    assert all(u.endswith('&open_firewall=1') for u in plans[1:]) and len(plans) == 3, plans
    # Start only once both plans were agreed to
    start = dialog.locator('[data-qdev-bulk-start]')
    assert start.is_disabled()
    dialog.locator('[data-qdev-bulk-consent="c1"]').check()
    assert start.is_disabled()
    dialog.locator('[data-qdev-bulk-show="c3"]').click()
    shown = dialog.locator('[data-qdev-bulk-row="c3"] [data-qdev-plan]').inner_text()
    assert 'Put the QNetd CA and the certificate of the cluster on pve1, pve2, pve3, pve4' in shown
    digests = {cid: dialog.locator(f'[data-qdev-bulk-row="{cid}"] [data-qdev-plan]').get_attribute('data-qdev-plan')
               for cid in ('c3',)}
    dialog.locator('[data-qdev-bulk-consent="c3"]').check()
    assert not start.is_disabled()
    start.click()
    assert _wait_for_call(app, ('POST', f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'), seconds=5)
    sent = app.server.bodies[f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'][-1]
    assert sorted(sent.pop('cluster_ids')) == ['c1', 'c3']
    consents = sent.pop('consents')
    assert sorted(consents) == ['c1', 'c3'] and consents['c3'] == digests['c3']
    assert sent == {'install_packages': False, 'open_firewall': True, 'confirm_unverified_host': False,
                    'replace_certificate': False}
    results = dialog.locator('[data-qdev-bulk-results]')
    results.wait_for(timeout=8000)
    assert dialog.locator('[data-qdev-bulk-result="c1"] [data-qdev-state]').get_attribute('data-qdev-state') == 'done'
    assert 'Failed at "Sign on the QNetd host"' in dialog.locator('[data-qdev-bulk-result="c3"]').inner_text()
    assert 'Clusters set up: 1 of 2' in dialog.inner_text()
    # the one whose name the QNetd host still holds: its plan again with a new certificate, agreed to again
    dialog.locator('[data-qdev-replace]').click()
    row = dialog.locator('[data-qdev-bulk-row="c3"][data-qdev-bulk-verdict="pass"]')
    row.wait_for(timeout=8000)
    assert [u for u in app.server.urls if '/qdevice/plan?' in u][-1].endswith('&replace_certificate=1')
    assert dialog.locator('[data-qdev-bulk-start]').is_disabled()
    dialog.locator('[data-qdev-bulk-consent="c3"]').check()
    dialog.locator('[data-qdev-bulk-start]').click()
    dialog.locator('[data-qdev-bulk-result="c3"] [data-qdev-state="done"]').wait_for(timeout=8000)
    sent = app.server.bodies[f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'][-1]
    assert sent['cluster_ids'] == ['c3'] and sent['replace_certificate'] is True and list(sent['consents']) == ['c3']
    assert not app.errors, app.errors


@pytest.mark.parametrize('status', [403, 404])
def test_runtime_nothing_shows_where_the_routes_refuse(open_app, status):
    app = open_app(hosts=[_host(attached=False)], hosts_status=status)
    page = _select_cluster(app)
    assert _wait_for_call(app, ('GET', '/api/qnetd/hosts'), seconds=5)
    page.wait_for_timeout(400)
    assert page.locator('[data-qdev-setup-open]').count() == 0
    app.open_settings()
    page.locator('button', has_text='High Availability').first.click()
    page.wait_for_timeout(800)
    assert page.locator('[data-qnetd-panel]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_standby_that_does_not_forward_only_shows(open_app):
    app = open_app(role='standby', hosts=[_host()], forward_writes=False)
    page = app.page
    app.page.locator('[data-ha-banner="classic"]').get_by_role('button', name='High Availability').click()
    panel = page.locator('[data-qnetd-panel]')
    panel.wait_for(timeout=5000)
    panel.locator(f'[data-qnetd-host="{HOST_ID}"]').wait_for(timeout=5000)
    assert panel.locator('[data-ha-settings-on-active]').count() == 1
    for sel in ('[data-qnetd-add]', '[data-qnetd-check]', '[data-qnetd-delete]', '[data-qnetd-bulk]', '[data-qnetd-edit]'):
        assert panel.locator(sel).count() == 0, sel
    assert not any(c[0] != 'GET' and c[1].startswith('/api/qnetd') for c in app.server.calls)
    assert not app.errors, app.errors
