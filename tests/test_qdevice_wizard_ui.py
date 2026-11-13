"""The QDevice setup wizard, the agreement per cluster and the QDevice hints in the web UI.

Set up QDevice is a wizard: where the QNetd runs (a QNetd host PegaProx knows, or a new one
saved right there as a record only), the options (install corosync-qdevice, on by default;
open the QNetd port on the QNetd host for the cluster nodes, on by default where ufw or
firewalld runs there and blocks it), then the plan GET /qdevice/plan made for exactly those
options, grouped by where it acts, with its warnings and checks. Nothing starts before the
admin ticked "I agree that PegaProx makes these changes on <cluster>"; Start sends the digest
of the plan on screen, and every option change reads the plan again and takes the tick back.
A job that finds another plan than the one agreed to stops (plan_changed) and the wizard
says so. The bulk dialog wants that agreement for every cluster it sets up, Check on a QNetd
host card says first what it does on a host that never spoke helper protocol 2, the overview
of a cluster with an even node count and no QDevice says what one gives, and a rolling update
held for its quorum offers Set up QDevice.

Source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_qnetd_ui.py (the one of
tests/test_ha_ui.py with the QNetd routes and the plan). They skip where Playwright is not
installed. QDEV_SHOTS=<dir> keeps a screenshot of each runtime test.
LW Oct 2026
"""
import copy
import os
import re

import pytest

from test_ha_ui import CLUSTER, _App, _classes, _wait_for_call, browser  # noqa: F401
from test_qnetd_ui import (FW_NFT, FW_NONE, FW_UFW, FW_UFW_OPEN, HOST_ID, HOSTILE, JOB, JOB2, SETUP_STEPS, THREE_NODES,
                           TWO_NODES, _check, _digest_on_screen, _host, _item, _job, _next, _no_markup_ran, _open_wizard,
                           _plan_reads, _QnetdServer, _read, _report, _select_cluster, _settings_panel, _settled,
                           _to_options, _to_review, open_app)  # noqa: F401
from test_rolling_options_ui_763_954 import CLUSTER as ROLL_CLUSTER
from test_rolling_runs_ui import INTERRUPTED, STATUS, _paused_banner, _Server as _RollServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('QDEV_SHOTS', '')
TAIL = '// LW Oct 2026 (#625) - the banners of a group that fails over automatically'
NEW_ID = '0f0f0f0f0f0f'
DAY_MS = 86400000

# the item and warning ids of the plan contract, and the params the server sends with each
ITEM_PARAMS = {
    'qnetd_helper_install': set(), 'qnetd_helper_update': set(), 'qnetd_packages': {'package_manager', 'packages'},
    'qnetd_ca': set(), 'qnetd_tls': set(), 'qnetd_start': set(), 'firewall_open': {'backend', 'port', 'sources'},
    'node_packages': {'nodes'}, 'node_certs': {'nodes'}, 'corosync_conf': {'address', 'port'},
    'qdevice_service': {'nodes'}, 'corosync_reload': set(), 'votes': {'before', 'after'},
    'cert_replace': {'cluster_name'}, 'node_store_reset': {'nodes'},
}
WARN_PARAMS = {'ha_group_local': set(), 'unverified_host': set(), 'firewall_manual': {'backend'},
               'ha_resources': set()}


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (pos, lang) in enumerate(starts)}


def _value(block, key):
    m = re.search(rf"^\s*{key}: '(.*)',$", block, re.M)
    return m.group(1) if m else None


@pytest.fixture(scope='module')
def code():
    src = _read('web', 'src', 'node_modals.js')
    return {
        'plan': _between(src, '// LW Oct 2026 - the plan of a setup (GET /clusters/<id>/qdevice/plan)',
                         '// Remove QDevice: pvecm qdevice remove on one node'),
        'hint': _between(src, '// LW Oct 2026 - the notice on the overview of a cluster',
                         '// Several clusters against one QNetd host'),
        'bulk': _between(src, 'function QdeviceBulkDialog(', "const QNETD_KINDS = ['local', 'ssh', 'sidecar'];"),
        'card': _between(src, 'function QnetdHostCard(', 'function QnetdHostsPanel('),
        'outcome': _between(src, 'function QdevOutcome(', 'function QdevJobState('),
        'checks': _between(src, 'const QDEV_CHECK_KEYS = {', 'function QdevDialog('),
        'preflight': _between(src, 'function QdevPreflight(', 'function QdevJobLog('),
        'remove': _between(src, 'function QdeviceRemoveDialog(', 'function QdeviceSetupButton('),
    }


def _used(code):
    keys = set()
    for part in code.values():
        keys |= set(re.findall(r"\bt\('([A-Za-z0-9_]+)'\)", part))
        keys |= set(re.findall(r"'((?:qdev|qnetd)[A-Z][A-Za-z0-9]*)'", part))
    return keys


def _new_keys():
    en = _blocks()['en']
    start = en.index('// LW Oct 2026 - the setup wizard: the plan, the agreement per cluster')
    return re.findall(r'^\s*((?:qdev|qnetd)[A-Z][A-Za-z0-9]*):', en[start:en.index(TAIL)], re.M)


# --- source --------------------------------------------------------------------------------

def test_every_new_key_is_in_english_and_german_once_with_the_same_placeholders(code):
    blocks = _blocks()
    new = _new_keys()
    assert len(new) >= 60, len(new)
    used = _used(code)
    assert set(new) <= used, sorted(set(new) - used)
    for key in new:
        for lang in ('en', 'de'):
            n = len(re.findall(rf'^\s*{key}:', blocks[lang], re.M))
            assert n == 1, (lang, key, n)
        en, de = _value(blocks['en'], key), _value(blocks['de'], key)
        assert en and de and en != de or key in ('qdevShowPlan',), key
        assert sorted(re.findall(r'\{\w+\}', en)) == sorted(re.findall(r'\{\w+\}', de)), key
    # the other seven languages are a later stage; the key nothing uses any more is gone here
    assert _value(blocks['en'], 'qdevNoHosts') is None and _value(blocks['de'], 'qdevNoHosts') is None


def test_the_new_keys_sit_before_the_pinned_ha_tail_in_english_and_german():
    for lang in ('en', 'de'):
        block = _blocks()[lang]
        tail = block.index(TAIL)
        for key in _new_keys():
            assert re.search(rf'^\s*{key}:', block, re.M).start() < tail, (lang, key)


def test_every_item_and_warning_of_the_plan_has_words_with_its_params(code):
    en = _blocks()['en']
    items = dict(re.findall(r"\b([a-z_]+): '(qdevItem[A-Za-z]+)'", _between(code['plan'], 'const QDEV_ITEM_KEYS = {', '};')))
    assert set(items) == set(ITEM_PARAMS), sorted(set(items) ^ set(ITEM_PARAMS))
    for iid, key in items.items():
        marks = set(re.findall(r'\{([a-z_]+)\}', _value(en, key)))
        assert marks <= ITEM_PARAMS[iid], (iid, marks)
    # the variants where the helper is not on the QNetd host yet
    assert "if (p.if_needed === true && QDEV_ITEM_IF_NEEDED[entry.id])" in code['plan']
    assert "if (entry.id === 'firewall_open' && !p.backend) return 'qdevItemFirewallOpenAny';" in code['plan']
    for key in ('qdevItemQnetdPackagesIfNeeded', 'qdevItemQnetdCaIfNeeded', 'qdevItemQnetdTlsIfNeeded',
                'qdevItemQnetdStartIfNeeded'):
        assert not re.findall(r'\{\w+\}', _value(en, key)), key
    assert set(re.findall(r'\{([a-z_]+)\}', _value(en, 'qdevItemFirewallOpenAny'))) == {'port', 'sources'}
    warns = dict(re.findall(r"\b([a-z_]+): '(qdev[A-Za-z]+)'", _between(code['plan'], 'const QDEV_WARN_KEYS = {', '};')))
    assert set(warns) == set(WARN_PARAMS)
    for wid, key in warns.items():
        assert set(re.findall(r'\{([a-z_]+)\}', _value(en, key))) <= WARN_PARAMS[wid], wid


def test_what_the_server_sends_today_has_words():
    """The ids the backend builds its plan, its warnings and its job log with: each has a sentence
    or a label here (an unknown one would fall back to the server's English text)."""
    core = _read('pegaprox', 'core', 'qnetd.py')
    src = _read('web', 'src', 'node_modals.js')
    items = set(re.findall(r"^\s+item\('([a-z_]+)'", core, re.M))
    warns = set(re.findall(r"^\s+warn\('([a-z_]+)'", core, re.M))
    steps = set(re.findall(r"job\.log\(cid, '([a-z_]+)'", core)) | set(re.findall(r"_StepFailed\('([a-z_]+)'", core))
    checks = set(re.findall(r"check\('([a-z_]+)'", core))
    item_map = _between(src, 'const QDEV_ITEM_KEYS = {', '};')
    warn_map = _between(src, 'const QDEV_WARN_KEYS = {', '};')
    step_map = _between(src, 'const QDEV_STEP_KEYS = {', '};')
    check_map = _between(src, 'const QDEV_CHECK_KEYS = {', '};')
    for name, found, where in (('item', items, item_map), ('warning', warns, warn_map), ('step', steps, step_map),
                               ('check', checks, check_map)):
        assert found, name
        missing = sorted(x for x in found if not re.search(rf'\b{x}: ', where))
        assert not missing, (name, missing)


def test_start_sends_the_agreement_to_the_plan_on_screen_and_nothing_else(code):
    wiz = _between(code['plan'], 'function QdeviceSetupDialog(', '\n        }\n')
    # the options the plan on screen was made with, and its digest
    assert ("const r = await qdevApi(getAuthHeaders, 'POST', `/clusters/${cid}/qdevice/setup`, {\n"
            "                    ...p.opts, consent: { accepted: true, digest: p.data.plan.digest } });") in wiz
    assert 'if (!p || p.loading || !p.data || p.data.ok !== true || !consent' in wiz
    assert 'const canStart = !jobId && !starting && canAgree && consent;' in wiz
    assert 'const canAgree = !!data && !loading && data.ok === true;' in wiz
    # every option is read into the plan again, and a new plan takes the tick back
    assert 'useEffect(() => { if (!jobId) fetchPlan(opts); }, [hostId, install, openFw, confirmed, replace, jobId]);' in wiz
    fetch = _between(wiz, 'const fetchPlan = async (o) => {', 'useEffect(() => { if (!jobId)')
    assert fetch.index('setConsent(false);') < fetch.index('await qdevApi(')
    assert 'if (mine !== seq.current) return;' in fetch
    # corosync-qdevice is installed by default; the port only where the firewall says so
    assert 'const [install, setInstall] = useState(true);' in wiz and 'const [openFw, setOpenFw] = useState(false);' in wiz
    assert "const qdevFirewallDefault = (kind, fw) => qdevFirewallState(kind, fw) === 'managed' && fw.blocking === true;" in code['plan']
    assert "const QDEV_FW_MANAGED = ['ufw', 'firewalld'];" in code['plan']
    # a sidecar never asks to open anything: Docker publishes the port
    assert "open_firewall: kind !== 'sidecar' && openFw" in wiz
    # the new host is a record: POST /qnetd/hosts of the form, then the plan against it
    assert 'onDone={(_edited, rec) => created(rec)}' in wiz and "'POST', '/qnetd/hosts'" not in wiz


def test_bulk_start_needs_the_agreement_of_every_selected_cluster(code):
    bulk = code['bulk']
    assert 'const agreed = (id) => good(id) && consents[id] === reports[id].plan.digest;' in bulk
    assert 'const allAgreed = !!planned && ids.length > 0 && ids.every(agreed);' in bulk
    assert 'disabled={locked || !allAgreed} onClick={start} data-qdev-bulk-start=""' in bulk
    assert 'consents: Object.fromEntries(list.map(id => [id, reports[id].plan.digest])),' in bulk
    # what it sends are the options those plans were made with
    for k in ('install_packages', 'open_firewall', 'confirm_unverified_host', 'replace_certificate'):
        assert f'{k}: planned.{k}' in bulk, k
    # a new check takes every agreement back
    check = _between(bulk, 'const check = async (list, base) => {', 'const change = ')
    assert check.index('setConsents({});') < check.index('await planOf(')


def test_the_check_confirm_and_the_outcome_of_a_changed_plan(code):
    card = code['card']
    assert 'const known = spoke.current || (!!st && st.ok === true && Number.isInteger(st.protocol) && st.protocol >= Math.max(2, Number(protocol) || 0));' in card
    assert "host.kind === 'ssh' && 'qnetdCheckDoesHelper'" in card and "host.kind !== 'sidecar' && 'qnetdCheckDoesPackages'" in card
    assert "{row.code === 'plan_changed' && <div className=\"text-yellow-200\" data-qdev-plan-changed=\"\">{t('qdevPlanChanged')}</div>}" in code['outcome']
    # a check the plan leaves to the run is never offered for confirmation
    assert 'return guest.length > 0 && guest.every(c => c.ok === null && !c.deferred);' in code['checks']


def test_the_hint_keeps_only_a_time_and_survives_a_storage_that_refuses(code):
    hint = code['hint']
    assert "const qdevHintKey = (cid) => `pegaprox-qdev-hint:${cid}`;" in hint
    assert hint.count('try {') == 2 and hint.count('} catch (e)') == 2
    assert 'Date.now() - at < QDEV_HINT_DAYS * 86400000' in hint and 'const QDEV_HINT_DAYS = 30;' in hint
    assert 'const even = Number.isInteger(nodeCount) && nodeCount >= 2 && nodeCount % 2 === 0;' in hint
    assert 'const absent = !!q && q.present === false && !q.refused && !q.stale;' in hint
    # the rolling update offers it only without a QDevice and with an even node count
    assert "held.qdevice.present === false" in hint and 'nodes >= 2 && nodes % 2 === 0' in hint
    sec = _read('web', 'src', 'security.js')
    banner = _between(sec, 'data-testid="rolling-paused"', '{/* Header with cancel button */}')
    gate = banner.index(") : hasPerm('node.update') && (")
    assert banner.index('<QdeviceQuorumButton clusterId={clusterId} clusterName={clusterName}') > gate
    dash = _read('web', 'src', 'dashboard.js')
    mount = _between(dash, '{/* LW Oct 2026 - what a QDevice gives a cluster of an even node count', '{isCorporate ? (')
    assert '<QdeviceHint' in mount and 'corporate={isCorporate}' in mount


def test_no_markup_no_dash_icons_that_exist_and_classes_in_the_build(code):
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    blocks = _blocks()
    lines = [ln for lang in ('en', 'de') for ln in blocks[lang].splitlines()
             if re.match(r'^\s*(?:qdev|qnetd)[A-Z]', ln)]
    for name, part in code.items():
        assert 'dangerouslySetInnerHTML' not in part and 'innerHTML' not in part and 'createElement(' not in part, name
        assert '\u2014' not in part and '\u2013' not in part, name
        used = set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
        assert used <= icons, (name, sorted(used - icons))
        missing = sorted(n for n in _classes(part) if n not in have)
        assert not missing, (name, missing)
    for ln in lines:
        assert '\u2014' not in ln and '\u2013' not in ln, ln


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function QdevPlan(', 'function QdevFirewall(', 'function QdevManual(', 'function QdeviceHint(',
                   'function QdeviceQuorumButton(', 'data-qdev-consent', 'data-qdev-bulk-consent', 'data-qdev-hint',
                   'pegaprox-qdev-hint:', 'rolling-qdevice-setup', 'qdevItemFirewallOpenAny', 'qdevHintTwo'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'), full_page=False)


def test_runtime_the_plan_is_grouped_by_where_translated_and_unknown_ids_fall_back(open_app):
    extra = [_item('future_step', 'cluster', f'Something a newer server does {HOSTILE}'),
             _item('qdevice_service', 'node', 'Enable corosync-qdevice on whatever', nodes=None)]
    app = open_app(hosts=[_host(attached=False, protocol=1)], extra_items=extra)
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    plan = dialog.locator('[data-qdev-review] [data-qdev-plan]')
    groups = plan.locator('[data-qdev-plan-group]')
    assert [groups.nth(i).get_attribute('data-qdev-plan-group') for i in range(groups.count())] == \
        ['qnetd', 'nodes', 'cluster']
    qnetd = plan.locator('[data-qdev-plan-group="qnetd"]').inner_text()
    assert 'On the QNetd host witness' in qnetd
    # the helper of a host that spoke protocol 1 is replaced, the port opened (ufw blocks it)
    assert 'Update the PegaProx helper in /usr/lib/pegaprox/qnetd' in qnetd
    assert 'Open TCP port 5403 with ufw for 10.0.0.1, 10.0.0.2' in qnetd
    nodes = plan.locator('[data-qdev-plan-group="nodes"]').inner_text()
    for want in ('On the nodes', 'Install corosync-qdevice on pve2',
                 'Put the QNetd CA and the certificate of the cluster on pve1, pve2',
                 'Enable and start corosync-qdevice on pve1, pve2',
                 # a param the sentence needs is missing: the server's own sentence
                 'Enable corosync-qdevice on whatever'):
        assert want in nodes, want
    cluster = plan.locator('[data-qdev-plan-group="cluster"]').inner_text()
    for want in ('In the cluster Testi', 'Add the QDevice to corosync.conf (model net, TLS on, ffsplit, host 10.0.0.9, port 5403)',
                 'Reload corosync on every node', 'Expected votes go from 2 to 3',
                 f'Something a newer server does {HOSTILE}'):
        assert want in cluster, want
    _shot(app, 'wizard-review')
    _no_markup_ran(page)
    assert not app.errors, app.errors


def test_runtime_a_new_ssh_host_is_saved_first_and_then_planned(open_app):
    deferred = _report()
    deferred['checks'] = [c for c in deferred['checks'] if c['id'] != 'not_own_vm'] + [
        dict(_check('not_own_vm', None, 'Whether the QNetd host is a guest of this cluster is checked once the helper '
                                        'is there', blocking=False), deferred=True)]
    app = open_app(hosts=[], reports={'c1': deferred})
    page, dialog = _open_wizard(app)
    where = dialog.locator('[data-qdev-where]')
    where.wait_for(timeout=5000)
    assert where.locator('[data-qdev-no-hosts]').inner_text() == 'No QNetd host yet.'
    # this machine has no helper socket: only the SSH way is offered
    assert where.locator('[data-qdev-where-new]').count() == 1
    assert dialog.locator('[data-qdev-next]').is_disabled()
    where.locator('[data-qdev-where-new="ssh"]').click()
    form = dialog.locator('[data-qnetd-form="add"]')
    form.wait_for(timeout=3000)
    # the kind is the one picked: no choice in the form
    assert form.locator('[data-qnetd-kind-option]').count() == 0
    assert 'saves the host first' in where.inner_text()
    page.fill('#qnetd-name', 'site-c')
    page.fill('#qnetd-address', '10.0.5.5')
    page.fill('#qnetd-password', 'pw-for-site-c')
    _shot(app, 'wizard-where-new-ssh')
    assert not _plan_reads(app)
    form.locator('[data-qnetd-save]').click()
    assert _wait_for_call(app, ('POST', '/api/qnetd/hosts'), seconds=5)
    sent = [b for b in app.server.bodies['/api/qnetd/hosts'] if b]
    assert len(sent) == 1 and sent[0]['kind'] == 'ssh' and sent[0]['name'] == 'site-c'
    # saved, the wizard goes on with the plan against that host; nothing was asked of it before
    dialog.locator('[data-qdev-options]').wait_for(timeout=5000)
    _settled(dialog)
    assert _plan_reads(app)[0].endswith(f'?qnetd_id={NEW_ID}&install_packages=1')
    assert app.server.calls.index(('POST', '/api/qnetd/hosts')) < \
        min(i for i, c in enumerate(app.server.calls) if c[1] == '/api/clusters/c1/qdevice/plan')
    assert 'QNetd host: site-c (10.0.5.5:5403)' in dialog.inner_text()
    # which firewall runs there is told once the helper answers: off, and it says why
    fw = dialog.locator('[data-qdev-fw]')
    assert fw.get_attribute('data-qdev-fw') == 'unknown'
    box = dialog.locator('[data-qdev-firewall]')
    assert not box.is_checked() and not box.is_disabled()
    assert 'known once the PegaProx helper answers there' in fw.inner_text()
    box.check()
    _settled(dialog)
    assert _plan_reads(app)[-1].endswith(f'?qnetd_id={NEW_ID}&install_packages=1&open_firewall=1')
    _next(dialog)
    dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)
    qnetd = dialog.locator('[data-qdev-plan-group="qnetd"]').inner_text()
    for want in ('On the QNetd host site-c', 'Copy the PegaProx helper to /usr/lib/pegaprox/qnetd, owned by root',
                 'Install corosync-qnetd and the NSS tools with the package manager of the QNetd host where they are missing',
                 'Create the certificate authority of the QNetd where there is none',
                 'Require TLS from the nodes (-s req) on a corosync-qnetd this setup installs, and restart it',
                 'Start corosync-qnetd and enable it at boot where it does not run',
                 'Open TCP port 5403 with ufw or firewalld, whichever is active, for 10.0.0.1, 10.0.0.2'):
        assert want in qnetd, want
    # what the run checks once the helper is there is no question to the admin
    guest = dialog.locator('[data-qdev-check="not_own_vm"]')
    assert guest.get_attribute('data-qdev-check-tone') == 'deferred' and 'checked during the setup' in guest.inner_text()
    assert dialog.locator('[data-qdev-confirm-guest]').count() == 0
    dialog.locator('[data-qdev-consent]').check()
    digest = _digest_on_screen(dialog)
    dialog.locator('[data-qdev-start]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/setup'), seconds=5)
    assert app.server.bodies['/api/clusters/c1/qdevice/setup'][-1] == {
        'qnetd_id': NEW_ID, 'install_packages': True, 'open_firewall': True, 'confirm_unverified_host': False,
        'replace_certificate': False, 'consent': {'accepted': True, 'digest': digest}}
    assert 'pw-for-site-c' not in page.content()
    assert not app.errors, app.errors


@pytest.mark.parametrize('variant', ['ufw-blocks', 'ufw-passes', 'nftables', 'none', 'sidecar'])
def test_runtime_the_firewall_of_the_qnetd_host_decides_open_port(open_app, variant):
    fw = {'ufw-blocks': FW_UFW, 'ufw-passes': FW_UFW_OPEN, 'nftables': FW_NFT, 'none': FW_NONE, 'sidecar': None}[variant]
    host = _host(attached=False, kind='sidecar') if variant == 'sidecar' else _host(attached=False)
    app = open_app(hosts=[host], firewall=fw)
    page, dialog = _open_wizard(app)
    dialog.locator(f'[data-qdev-where-host="{HOST_ID}"]').wait_for(timeout=5000)
    _to_options(dialog)
    section = dialog.locator('[data-qdev-fw]')
    box = dialog.locator('[data-qdev-firewall]')
    reads = _plan_reads(app)
    if variant == 'sidecar':
        assert section.get_attribute('data-qdev-fw') == 'sidecar' and box.count() == 0
        assert 'Docker publishes the port of the sidecar itself' in section.inner_text()
        assert not any('open_firewall' in u for u in reads)
    elif variant == 'ufw-blocks':
        assert section.get_attribute('data-qdev-fw') == 'managed'
        assert box.is_checked() and not box.is_disabled()
        text = section.inner_text()
        assert 'Open port 5403 on the QNetd host for the cluster nodes' in text
        assert 'ufw runs on the QNetd host and blocks the port' in text
        assert 'Only for the addresses the nodes use towards the QNetd host: 10.0.0.1, 10.0.0.2' in text
        # read once without, then with the port: the first plan is never shown
        assert len(reads) == 2 and reads[-1].endswith('&open_firewall=1')
    elif variant == 'ufw-passes':
        assert section.get_attribute('data-qdev-fw') == 'managed'
        assert not box.is_checked() and not box.is_disabled()
        assert 'lets the port through already' in section.inner_text()
        assert len(reads) == 1
    elif variant == 'nftables':
        assert section.get_attribute('data-qdev-fw') == 'unmanaged'
        assert not box.is_checked() and box.is_disabled()
        assert 'PegaProx does not change nftables on the QNetd host' in section.inner_text()
        manual = section.locator('[data-qdev-manual] pre').inner_text()
        assert 'ip saddr 10.0.0.1 tcp dport 5403 accept' in manual and 'ip saddr 10.0.0.2' in manual
        section.locator('[data-qdev-copy] button').click()
        _shot(app, 'wizard-firewall-manual')
        _next(dialog)
        warning = dialog.locator('[data-qdev-warning="firewall_manual"]')
        warning.wait_for(timeout=5000)
        assert 'PegaProx does not change nftables' in warning.inner_text()
        assert 'tcp dport 5403 accept' in warning.locator('[data-qdev-manual] pre').inner_text()
    else:
        assert section.get_attribute('data-qdev-fw') == 'none'
        assert not box.is_checked() and box.is_disabled()
        assert 'No firewall is active on the QNetd host' in section.inner_text()
    if variant != 'nftables':
        _next(dialog)
        dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-consent]').check()
    dialog.locator('[data-qdev-start]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/setup'), seconds=5)
    assert app.server.bodies['/api/clusters/c1/qdevice/setup'][-1]['open_firewall'] is (variant == 'ufw-blocks')
    assert not app.errors, app.errors


def test_runtime_an_option_change_reads_the_plan_again_and_takes_the_agreement_back(open_app):
    app = open_app(hosts=[_host(attached=False)], firewall=FW_UFW_OPEN)
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    consent = dialog.locator('[data-qdev-consent]')
    start = dialog.locator('[data-qdev-start]')
    assert start.is_disabled()
    consent.check()
    assert not start.is_disabled()
    before = _digest_on_screen(dialog)
    n = len(_plan_reads(app))
    dialog.locator('[data-qdev-back]').click()
    dialog.locator('[data-qdev-install]').uncheck()
    _settled(dialog)
    reads = _plan_reads(app)
    assert len(reads) == n + 1 and reads[-1].endswith(f'?qnetd_id={HOST_ID}')
    _next(dialog)
    dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)
    assert not consent.is_checked() and start.is_disabled()
    assert _digest_on_screen(dialog) != before
    assert dialog.locator('[data-qdev-item="node_packages"]').count() == 0
    # Check again is a new plan as well
    consent.check()
    dialog.locator('[data-qdev-recheck]').click()
    _settled(dialog)
    dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)
    assert not consent.is_checked()
    consent.check()
    digest = _digest_on_screen(dialog)
    start.click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/setup'), seconds=5)
    sent = app.server.bodies['/api/clusters/c1/qdevice/setup'][-1]
    assert sent['install_packages'] is False and sent['consent'] == {'accepted': True, 'digest': digest}
    assert not app.errors, app.errors


def test_runtime_a_plan_that_changed_since_the_agreement_is_said_and_checked_again(open_app):
    changed = _job(JOB, 'setup', ['c1'], 'failed',
                   {'c1': {'state': 'failed', 'cluster_name': 'Testi', 'failed_step': 'plan', 'code': 'plan_changed',
                           'error': 'The plan changed since you agreed: check again', 'rolled_back': None}},
                   [('c1', 'plan', 'failed', 'The plan changed since you agreed: check again')])
    done = _job(JOB2, 'setup', ['c1'], 'done', {'c1': {'state': 'done', 'cluster_name': 'Testi'}}, SETUP_STEPS)
    app = open_app(hosts=[_host(attached=False)], jobs={JOB: [changed], JOB2: [done]})
    app.server.q_next_jobs = [JOB, JOB2]
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-consent]').check()
    dialog.locator('[data-qdev-start]').click()
    outcome = dialog.locator('[data-qdev-outcome="failed"]')
    outcome.wait_for(timeout=8000)
    assert 'Failed at "Compare with the agreed plan"' in outcome.inner_text()
    assert outcome.locator('[data-qdev-plan-changed]').inner_text() == 'The plan changed since you agreed: check again.'
    assert outcome.locator('[data-qdev-unchanged]').count() == 1
    _shot(app, 'wizard-plan-changed')
    n = len(_plan_reads(app))
    dialog.locator('[data-qdev-again]').click()
    dialog.locator('[data-qdev-review]').wait_for(timeout=3000)
    _settled(dialog)
    dialog.locator('[data-qdev-review] [data-qdev-plan]').wait_for(timeout=8000)
    assert len(_plan_reads(app)) == n + 1
    assert not dialog.locator('[data-qdev-consent]').is_checked() and dialog.locator('[data-qdev-start]').is_disabled()
    dialog.locator('[data-qdev-consent]').check()
    dialog.locator('[data-qdev-start]').click()
    dialog.locator('[data-qdev-outcome="done"]').wait_for(timeout=8000)
    assert not app.errors, app.errors


def test_runtime_a_refused_agreement_shows_the_reason_and_the_plan_again(open_app):
    app = open_app(hosts=[_host(attached=False)])
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-consent]').check()
    # the server knows no such plan any more (another instance, a restart): it refuses
    app.server.q_digests.clear()
    n = len(_plan_reads(app))
    dialog.locator('[data-qdev-start]').click()
    refused = dialog.locator('[data-qdev-refused]')
    refused.wait_for(timeout=5000)
    assert refused.inner_text() == 'Agree to the plan of this cluster first'
    _settled(dialog)
    assert len(_plan_reads(app)) == n + 1 and not dialog.locator('[data-qdev-consent]').is_checked()
    assert not app.errors, app.errors


def test_runtime_bulk_start_waits_for_every_selected_cluster(open_app):
    gamma = dict(CLUSTER, id='c3', name='Gamma', display_name='Gamma')
    app = open_app(hosts=[_host(attached=False)], clusters=[CLUSTER, gamma], node_counts={'c1': 2, 'c3': 2},
                   reports={'c1': _report('c1'), 'c3': _report('c3', name='Gamma', ok=False)}, jobs={JOB: [
                       _job(JOB, 'bulk', ['c1'], 'done', {'c1': {'state': 'done', 'cluster_name': 'Testi'}}, SETUP_STEPS)]})
    app.server.q_next_jobs = [JOB]
    page = app.page
    panel = _settings_panel(app)
    panel.locator(f'[data-qnetd-host="{HOST_ID}"] [data-qnetd-bulk]').click()
    dialog = page.locator(f'[data-qdev-bulk="{HOST_ID}"]')
    dialog.locator('[data-qdev-bulk-row="c3"]').get_by_text('Nodes: 2').wait_for(timeout=5000)
    dialog.locator('[data-qdev-bulk-even]').click()
    dialog.locator('[data-qdev-bulk-check]').click()
    dialog.locator('[data-qdev-bulk-row="c3"][data-qdev-bulk-verdict="fail"]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-bulk-row="c1"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-bulk-check]:not([disabled])').wait_for(timeout=5000)
    # a plan that does not pass cannot be agreed to, and it holds the run back while it is picked
    assert dialog.locator('[data-qdev-bulk-consent="c3"]').is_disabled()
    dialog.locator('[data-qdev-bulk-consent="c1"]').check()
    start = dialog.locator('[data-qdev-bulk-start]')
    assert start.is_disabled()
    assert 'once you agreed to the plan of every selected cluster' in dialog.locator('[data-qdev-bulk-agree-all]').inner_text()
    _shot(app, 'bulk-consents')
    # left out, the others keep their plans and their agreement
    dialog.locator('[data-qdev-bulk-row="c3"] input[aria-label="Gamma"]').uncheck()
    assert dialog.locator('[data-qdev-bulk-consent="c1"]').is_checked()
    assert not start.is_disabled() and start.inner_text().strip() == 'Set up 1'
    start.click()
    assert _wait_for_call(app, ('POST', f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'), seconds=5)
    sent = app.server.bodies[f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'][-1]
    assert sent['cluster_ids'] == ['c1'] and list(sent['consents']) == ['c1']
    dialog.locator('[data-qdev-bulk-result="c1"] [data-qdev-state="done"]').wait_for(timeout=8000)
    assert not app.errors, app.errors


def test_runtime_check_says_first_what_it_does_on_a_host_that_never_spoke_protocol_2(open_app):
    local = _host(attached=False, protocol=1, kind='local', host_id='0a0a0a0a0a0a', name='here')
    current = _host(attached=False, protocol=2, host_id='0b0b0b0b0b0b', name='current')
    app = open_app(hosts=[_host(attached=False, protocol=1), local, current])
    panel = _settings_panel(app)
    card = panel.locator(f'[data-qnetd-host="{HOST_ID}"]')
    card.wait_for(timeout=5000)
    card.locator('[data-qnetd-check]').click()
    ask = card.locator('[data-qnetd-check-confirm]')
    ask.wait_for(timeout=2000)
    does = ask.locator('[data-qnetd-check-does]')
    assert [does.nth(i).get_attribute('data-qnetd-check-does') for i in range(does.count())] == [
        'qnetdCheckDoesHelper', 'qnetdCheckDoesPackages', 'qnetdCheckDoesCa', 'qnetdCheckDoesTls', 'qnetdCheckDoesStart']
    text = ask.inner_text()
    assert 'copy its helper to /usr/lib/pegaprox/qnetd' in text and '(apt-get, dnf, yum or zypper)' in text
    _shot(app, 'check-confirm')
    ask.get_by_role('button', name='Cancel').click()
    assert card.locator('[data-qnetd-check-confirm]').count() == 0
    assert ('POST', f'/api/qnetd/hosts/{HOST_ID}/check') not in app.server.calls
    # the local helper is the one install.sh put there: nothing is copied
    panel.locator('[data-qnetd-host="0a0a0a0a0a0a"] [data-qnetd-check]').click()
    local_ask = panel.locator('[data-qnetd-host="0a0a0a0a0a0a"] [data-qnetd-check-confirm]')
    local_ask.wait_for(timeout=2000)
    assert local_ask.locator('[data-qnetd-check-does="qnetdCheckDoesHelper"]').count() == 0
    # a host that answers with protocol 2 is checked at once
    panel.locator('[data-qnetd-host="0b0b0b0b0b0b"] [data-qnetd-check]').click()
    assert _wait_for_call(app, ('POST', '/api/qnetd/hosts/0b0b0b0b0b0b/check'), seconds=5)
    assert panel.locator('[data-qnetd-host="0b0b0b0b0b0b"] [data-qnetd-check-confirm]').count() == 0
    # and the first one asks no more once it answered with protocol 2
    card.locator('[data-qnetd-check]').click()
    card.locator('[data-qnetd-check-go]').click()
    card.locator('[data-qnetd-checked="ok"]').wait_for(timeout=5000)
    calls = app.server.calls.count(('POST', f'/api/qnetd/hosts/{HOST_ID}/check'))
    card.locator('[data-qnetd-check]:not([disabled])').click()
    for _ in range(50):
        if app.server.calls.count(('POST', f'/api/qnetd/hosts/{HOST_ID}/check')) > calls:
            break
        app.page.wait_for_timeout(100)
    assert app.server.calls.count(('POST', f'/api/qnetd/hosts/{HOST_ID}/check')) == calls + 1
    assert card.locator('[data-qnetd-check-confirm]').count() == 0
    assert not app.errors, app.errors


def _open_cluster(app, layout, read=True):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    if read:
        assert _wait_for_call(app, ('GET', '/api/clusters/c1/qdevice'), seconds=8)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_notice_says_what_a_qdevice_gives_and_hides_for_30_days(open_app, layout):
    app = open_app(hosts=[_host(attached=False)], layout=layout)
    page = _open_cluster(app, layout)
    hint = page.locator('[data-qdev-hint="c1"]')
    hint.wait_for(timeout=8000)
    text = hint.inner_text()
    assert 'This cluster has no QDevice' in text
    assert 'With two nodes, one node down (a crash, or a reboot for an update) leaves the other without quorum' in text
    _shot(app, f'notice-{layout}')
    # Set up QDevice opens the wizard for that cluster
    hint.locator('[data-qdev-hint-setup="c1"]').click()
    dialog = page.locator('[data-qdev-setup="c1"]')
    dialog.wait_for(timeout=3000)
    dialog.get_by_role('button', name='Close').last.click()
    assert page.locator('[data-qdev-setup]').count() == 0
    # hidden: the time is kept in this browser, the notice gone, and still gone after a reload
    hint.locator('[data-qdev-hint-hide="c1"]').click()
    assert page.locator('[data-qdev-hint]').count() == 0
    kept = page.evaluate("() => localStorage.getItem('pegaprox-qdev-hint:c1')")
    assert kept and abs(int(kept) - page.evaluate('() => Date.now()')) < 60000
    page.reload(wait_until='load')
    app.wait_for_app()
    page = _open_cluster(app, layout)
    page.wait_for_timeout(1200)
    assert page.locator('[data-qdev-hint]').count() == 0
    # after 30 days it is back
    page.evaluate(f"() => localStorage.setItem('pegaprox-qdev-hint:c1', String(Date.now() - 31 * {DAY_MS}))")
    page.reload(wait_until='load')
    app.wait_for_app()
    page = _open_cluster(app, layout)
    page.locator('[data-qdev-hint="c1"]').wait_for(timeout=8000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['present', 'odd', 'refused', 'viewer', 'storage-refuses'])
def test_runtime_no_notice_where_it_has_nothing_to_say(open_app, case):
    kw = {'hosts': [_host(attached=False)]}
    if case == 'present':
        kw['qdevice'] = {'c1': {'present': True, 'state': 'Connected', 'nodes': []}}
    elif case == 'odd':
        kw['metrics'] = THREE_NODES
    elif case == 'refused':
        kw['hosts_status'] = 403
    elif case == 'viewer':
        kw['admin'] = False
        kw['permissions'] = ['node.view']
    app = open_app(**kw)
    if case == 'storage-refuses':
        # a browser that refuses the storage for this key: the notice shows, Hide hides it for this view
        app.page.evaluate("""() => {
            const get = Storage.prototype.getItem, set = Storage.prototype.setItem;
            const ours = (k) => String(k).startsWith('pegaprox-qdev-hint:');
            Storage.prototype.getItem = function (k) { if (ours(k)) throw new Error('denied'); return get.call(this, k); };
            Storage.prototype.setItem = function (k, v) { if (ours(k)) throw new Error('denied'); return set.call(this, k, v); };
        }""")
    page = _open_cluster(app, 'modern', read=case != 'viewer')
    page.wait_for_timeout(1200)
    if case == 'storage-refuses':
        hint = page.locator('[data-qdev-hint="c1"]')
        hint.wait_for(timeout=5000)
        hint.locator('[data-qdev-hint-hide="c1"]').click()
        assert page.locator('[data-qdev-hint]').count() == 0
        # the small Set up button knows of the click as well, without the storage
        page.locator('[data-qdev-setup-open="c1"]').wait_for(timeout=3000)
    else:
        assert page.locator('[data-qdev-hint]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_small_set_up_button_gives_way_to_the_notice(open_app, layout):
    """Two buttons for the same wizard are one too many: while the notice of the cluster shows,
    with its Set up QDevice, the small one next to Nodes is not there. Hidden for 30 days, the
    notice leaves it the place again."""
    app = open_app(hosts=[_host(attached=False)], layout=layout)
    page = _open_cluster(app, layout)
    hint = page.locator('[data-qdev-hint="c1"]')
    hint.wait_for(timeout=8000)
    page.wait_for_timeout(800)
    assert page.locator('[data-qdev-setup-open="c1"]').count() == 0
    assert page.locator('[data-qdev-hint-setup="c1"]').count() == 1
    _shot(app, f'notice-alone-{layout}')
    hint.locator('[data-qdev-hint-hide="c1"]').click()
    assert page.locator('[data-qdev-hint]').count() == 0
    small = page.locator('[data-qdev-setup-open="c1"]')
    small.wait_for(timeout=3000)
    small.click()
    dialog = page.locator('[data-qdev-setup="c1"]')
    dialog.wait_for(timeout=3000)
    dialog.get_by_role('button', name='Close').last.click()
    assert page.locator('[data-qdev-setup]').count() == 0
    # and so after a reload, while the notice stays hidden
    page.reload(wait_until='load')
    app.wait_for_app()
    page = _open_cluster(app, layout)
    page.locator('[data-qdev-setup-open="c1"]').wait_for(timeout=8000)
    assert page.locator('[data-qdev-hint]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_certificate_of_an_earlier_setup_is_shown_before_the_agreement(open_app):
    """The QNetd host still holds the certificate of a cluster of this name (its QDevice was
    removed): the review says so, and nothing can be agreed to. Replace the certificate reads
    the plan again with the replacement in it, and that is the plan the admin agrees to."""
    app = open_app(hosts=[_host(attached=False)], held=('c1',))
    page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-preflight="fail"]').wait_for(timeout=5000)
    row = dialog.locator('[data-qdev-check="cert_on_file"]')
    assert row.get_attribute('data-qdev-check-tone') == 'bad'
    text = row.inner_text()
    assert 'Certificate of an earlier setup on the QNetd host' in text
    assert ('The QNetd host holds a certificate for a cluster of this name from an earlier setup. Replacing it is '
            'only right when that cluster is this one, set up again, or one that is gone.') in text
    assert dialog.locator('[data-qdev-consent]').is_disabled() and dialog.locator('[data-qdev-start]').is_disabled()
    assert dialog.locator('[data-qdev-item="cert_replace"]').count() == 0
    _shot(app, 'cert-on-file')
    first = _digest_on_screen(dialog)
    reads = len(_plan_reads(app))
    row.locator('[data-qdev-cert-replace]').click()
    dialog.locator('[data-qdev-review] [data-qdev-item="cert_replace"]').wait_for(timeout=8000)
    _settled(dialog)
    after = _plan_reads(app)[reads:]
    assert len(after) == 1 and after[0].endswith('&replace_certificate=1'), after
    assert dialog.locator('[data-qdev-check="cert_on_file"]').get_attribute('data-qdev-check-tone') == 'ok'
    assert dialog.locator('[data-qdev-cert-replace]').count() == 0
    assert 'Replace the certificate the QNetd host holds for the cluster name Testi' in \
        dialog.locator('[data-qdev-item="cert_replace"]').inner_text()
    second = _digest_on_screen(dialog)
    assert second != first
    # a new plan: not agreed to until ticked again
    consent = dialog.locator('[data-qdev-consent]')
    assert not consent.is_checked() and dialog.locator('[data-qdev-start]').is_disabled()
    consent.check()
    dialog.locator('[data-qdev-start]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/qdevice/setup'), seconds=5)
    sent = app.server.bodies['/api/clusters/c1/qdevice/setup'][-1]
    assert sent['replace_certificate'] is True and sent['consent'] == {'accepted': True, 'digest': second}
    _no_markup_ran(page)
    assert not app.errors, app.errors


def test_runtime_bulk_shows_a_held_certificate_in_the_row_of_its_cluster(open_app):
    gamma = dict(CLUSTER, id='c3', name='Gamma', display_name='Gamma')
    app = open_app(hosts=[_host(attached=False)], clusters=[CLUSTER, gamma], node_counts={'c1': 2, 'c3': 2},
                   reports={'c1': _report('c1'), 'c3': _report('c3', name='Gamma')}, held=('c1',))
    page = app.page
    panel = _settings_panel(app)
    panel.locator(f'[data-qnetd-host="{HOST_ID}"] [data-qnetd-bulk]').click()
    dialog = page.locator(f'[data-qdev-bulk="{HOST_ID}"]')
    dialog.wait_for(timeout=3000)
    for cid in ('c1', 'c3'):
        dialog.locator(f'[data-qdev-bulk-row="{cid}"]').get_by_text('Nodes: 2').wait_for(timeout=5000)
    dialog.locator('[data-qdev-bulk-even]').click()
    dialog.locator('[data-qdev-bulk-check]').click()
    dialog.locator('[data-qdev-bulk-row="c3"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    held = dialog.locator('[data-qdev-bulk-row="c1"][data-qdev-bulk-verdict="fail"]')
    held.wait_for(timeout=8000)
    dialog.locator('[data-qdev-checking]').wait_for(state='detached', timeout=8000)
    # why, and the way out, in the row of that cluster, without opening its plan; the other has neither
    assert 'Replacing it is only right when that cluster is this one' in held.locator('[data-qdev-cert-held]').inner_text()
    assert held.locator('[data-qdev-cert-replace]').count() == 1
    assert dialog.locator('[data-qdev-bulk-row="c3"] [data-qdev-cert-held]').count() == 0
    assert held.locator('[data-qdev-bulk-consent="c1"]').is_disabled()
    dialog.locator('[data-qdev-bulk-consent="c3"]').check()
    _shot(app, 'bulk-cert-on-file')
    reads = len([u for u in app.server.urls if '/qdevice/plan?' in u])
    held.locator('[data-qdev-cert-replace]').click()
    dialog.locator('[data-qdev-bulk-row="c1"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-bulk-row="c3"][data-qdev-bulk-verdict="pass"]').wait_for(timeout=8000)
    dialog.locator('[data-qdev-checking]').wait_for(state='detached', timeout=8000)
    plans = [u for u in app.server.urls if '/qdevice/plan?' in u][reads:]
    assert len(plans) == 2 and all(u.endswith('&replace_certificate=1') for u in plans), plans
    # every agreement went with the plan it was given to
    assert not dialog.locator('[data-qdev-bulk-consent="c3"]').is_checked()
    assert dialog.locator('[data-qdev-bulk-start]').is_disabled()
    assert dialog.locator('[data-qdev-cert-held]').count() == 0
    # only the plan of the cluster whose name the QNetd host holds replaces a certificate
    dialog.locator('[data-qdev-bulk-show="c1"]').click()
    dialog.locator('[data-qdev-bulk-row="c1"] [data-qdev-item="cert_replace"]').wait_for(timeout=3000)
    dialog.locator('[data-qdev-bulk-show="c3"]').click()
    dialog.locator('[data-qdev-bulk-row="c3"] [data-qdev-plan]').wait_for(timeout=3000)
    assert dialog.locator('[data-qdev-bulk-row="c3"] [data-qdev-item="cert_replace"]').count() == 0
    for cid in ('c1', 'c3'):
        dialog.locator(f'[data-qdev-bulk-consent="{cid}"]').check()
    dialog.locator('[data-qdev-bulk-start]').click()
    assert _wait_for_call(app, ('POST', f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'), seconds=5)
    sent = app.server.bodies[f'/api/qnetd/hosts/{HOST_ID}/bulk-setup'][-1]
    assert sent['replace_certificate'] is True and sorted(sent['consents']) == ['c1', 'c3']
    assert not app.errors, app.errors


class _RollQnetdServer(_RollServer, _QnetdServer):
    """The rolling update server of test_rolling_runs_ui with the QNetd routes."""


QUORUM = dict(copy.deepcopy(INTERRUPTED), paused_reason='quorum', current_step='paused_quorum',
              paused_details={'node': 'pve1', 'phase': 'maintenance', 'reason': 'would_lose', 'expected': 2,
                              'needed': 2, 'have': 2, 'after': 1, 'offline': [],
                              'qdevice': {'present': False, 'connected': False, 'not_connected': []},
                              'message': 'Not going on before pve1 goes into maintenance ...'},
              resume_at={'index': 0, 'phase': 'maintenance'})


@pytest.fixture
def roll(browser):  # noqa: F811
    apps = []

    def _open(**kw):
        kw.setdefault('run', QUORUM)
        kw.setdefault('hosts', [_host(attached=False)])
        app = _App(browser, _RollQnetdServer(layout=kw.pop('layout', 'modern'), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def test_runtime_a_rolling_update_held_for_its_quorum_offers_set_up_qdevice(roll):
    app = roll()
    banner = _paused_banner(app, 'modern')
    button = banner.locator('[data-testid="rolling-qdevice-setup"]')
    button.wait_for(timeout=5000)
    assert button.inner_text().strip() == 'Set up QDevice'
    assert banner.locator('[data-testid="rolling-continue-anyway"]').count() == 1
    button.scroll_into_view_if_needed()
    _shot(app, 'rolling-quorum')
    reads = app.server.calls.count(('GET', STATUS))
    button.click()
    dialog = app.page.locator(f'[data-qdev-setup="{ROLL_CLUSTER["id"]}"]')
    dialog.wait_for(timeout=3000)
    dialog.locator(f'[data-qdev-where-host="{HOST_ID}"]').wait_for(timeout=5000)
    dialog.get_by_role('button', name='Close').last.click()
    # closed, the run is read again: with the QDevice connected Continue goes on by itself
    app.page.wait_for_timeout(800)
    assert app.server.calls.count(('GET', STATUS)) > reads
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['has-qdevice', 'odd', 'refused'])
def test_runtime_no_rolling_button_where_a_qdevice_does_not_help(roll, case):
    kw = {}
    if case == 'has-qdevice':
        kw['run'] = dict(QUORUM, paused_details=dict(QUORUM['paused_details'],
                                                     qdevice={'present': True, 'connected': False}))
    elif case == 'odd':
        kw['node_counts'] = {ROLL_CLUSTER['id']: 3}
    else:
        kw['hosts_status'] = 403
    app = roll(**kw)
    banner = _paused_banner(app, 'modern')
    app.page.wait_for_timeout(1200)
    assert banner.locator('[data-testid="rolling-qdevice-setup"]').count() == 0
    assert banner.locator('[data-testid="rolling-continue-anyway"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_local_qnetd_in_an_ha_group_is_warned_about(open_app):
    app = open_app(hosts=[], ha_members=2,
                   transports={'local': {'available': True, 'reason': ''}, 'sidecar': {'available': False, 'reason': 'no'}})
    page, dialog = _open_wizard(app)
    dialog.locator('[data-qdev-where-new="local"]').wait_for(timeout=5000)
    assert dialog.locator('[data-qdev-where-new="sidecar"]').count() == 0
    assert dialog.locator('[data-qdev-ha-warn]').count() == 0
    dialog.locator('[data-qdev-where-new="local"]').click()
    warn = dialog.locator('[data-qdev-ha-warn]')
    warn.wait_for(timeout=2000)
    assert 'after a switchover the cluster no longer reaches it' in warn.inner_text()
    dialog.locator('[data-qdev-where-new="ssh"]').click()
    assert dialog.locator('[data-qdev-ha-warn]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_wizard_speaks_german(open_app):
    app = open_app(hosts=[_host(attached=False)], language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/qdevice'), seconds=8)
    # two nodes and no QDevice: the notice is there, and its Set up opens the wizard
    page.locator('[data-qdev-hint-setup="c1"]').click()
    dialog = page.locator('[data-qdev-setup="c1"]')
    dialog.wait_for(timeout=3000)
    assert '1. Wo' in dialog.locator('[data-qdev-steps]').inner_text()
    _to_review(dialog)
    text = dialog.locator('[data-qdev-review]').inner_text()
    for want in ('Was PegaProx tun wird', 'Auf dem QNetd-Host witness', 'TCP-Port 5403 mit ufw für 10.0.0.1, 10.0.0.2 öffnen',
                 'corosync-qdevice auf pve1, pve2 aktivieren und starten', 'Ich stimme zu, dass PegaProx diese Änderungen an Testi vornimmt',
                 'An den Nodes und in der corosync.conf wird dann nichts geändert.'):
        assert want in text, want
    assert not app.errors, app.errors
