"""What the UI says about the audit chain, the self-check score and unread hardening controls.

Settings > Compliance shows how many self-check controls were checked and why one was not,
and after "Verify Integrity" the chain findings in sentences: changed, missing and out of
order entries, the retention prune, the entries since the last checkpoint and the entries
from before the chain. The cluster Compliance dashboard and Harden PVE Node keep a control
whose output did not come back out of the score and say so. Runtime tests drive the built
bundle in headless Chromium against the fake server of tests/test_ha_ui.py and skip where
Playwright is not installed. LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, VM, SSE_TOKEN, NODE_METRICS, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEYS = ['auditChainTitle', 'auditChainIntact', 'auditChainEdited', 'auditChainMissing', 'auditChainBroken',
        'auditChainTruncated', 'auditChainBadCheckpoints', 'auditChainPruned', 'auditChainAfterCheckpoint',
        'auditLegacyRows', 'auditLegacyChanged', 'auditLegacyUnchanged', 'complianceCheckedOf',
        'complianceNotChecked', 'hardenNotChecked', 'hardenNotCheckedBadge', 'hardenNotCheckedHint',
        # the checkpoints' own chain and the copy of the newest one beside the key
        'auditChainCheckpointsMissing', 'auditChainCheckpointsBroken', 'auditChainNoStart',
        'auditChainRestarted', 'auditChainAnchorBad', 'auditChainAnchorMissing']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'\n            ([a-z]{2}): \{\n', src)]
    assert [lang for _, lang in starts] == LANGS
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (pos, lang) in enumerate(starts)}


def _findings_src():
    src = _read('web', 'src', 'security.js')
    start = src.index('function AuditChainFindings(')
    return src[start:src.index('function ComplianceSection(', start)]


def test_every_key_is_used_and_once_per_language():
    used = _read('web', 'src', 'security.js') + _read('web', 'src', 'dashboard.js')
    blocks = _blocks()
    for key in KEYS:
        assert f"t('{key}')" in used or f"'{key}'" in used, key
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            found = re.findall(r'^ +%s: (.*),$' % key, block, re.M)
            assert len(found) == 1, (lang, key, len(found))
            assert sorted(re.findall(r'\{\w+\}', found[0])) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_em_dash_in_what_was_added():
    blocks = _blocks()
    lines = [l for b in blocks.values() for l in b.splitlines() if any(f' {k}:' in l for k in KEYS)]
    for text in [_findings_src()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    sec = _read('web', 'src', 'security.js')
    block = sec[sec.index('{/* Compliance Score */}'):sec.index('{/* Encryption Key Management */}')]
    dash = _read('web', 'src', 'dashboard.js')
    hard = '\n'.join(l for l in dash.splitlines() if 'notChecked' in l or 'hardenNotChecked' in l)
    missing = sorted(n for n in _classes(_findings_src()) | _classes(block) | _classes(hard) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function AuditChainFindings(', 'complianceCheckedOf', 'hardenNotCheckedBadge', 'verdictOf',
                   'auditChainRestarted', 'auditChainAnchorMissing'):
        assert needle in bundle, needle


# --- runtime ---------------------------------------------------------------------------------

CONTROLS = [
    {'id': 'encryption_enabled', 'status': 'passed', 'detail': 'AES-256-GCM field key loaded', 'reason': ''},
    {'id': 'https_enabled', 'status': 'not_checked', 'detail': '',
     'reason': 'Behind a reverse proxy that does not report which scheme the client used'},
    {'id': 'two_factor_enforced', 'status': 'failed', 'detail': 'Two-factor sign-in is not required', 'reason': ''},
]
COMPLIANCE = {'compliance_score': 50.0, 'checked': 2, 'total': 3, 'passed': 1, 'not_checked': 1,
              'controls': CONTROLS, 'checks': {'encryption_enabled': True, 'https_enabled': None,
                                               'two_factor_enforced': False},
              'recommendations': [], 'default_password_warning': False}
INTEGRITY = {
    'total_entries': 40, 'verified': 37, 'unsigned': 1, 'potentially_tampered': 2,
    'integrity_percentage': 92.5, 'scanned_limit': None, 'intact': False,
    'chain': {'rows': 30, 'first_seq': 21, 'last_seq': 52, 'edited': 2, 'edited_seqs': [24, 30],
              'missing': 3, 'missing_ranges': [[40, 42]], 'broken_links': 0, 'broken_link_seqs': [],
              'truncated': False, 'after_checkpoint': 4, 'checkpoints': 3, 'bad_checkpoints': 0,
              'last_checkpoint': {'seq': 48, 'kind': 'periodic', 'created_at': '2026-10-10T09:00:00'},
              'pruned_through': 20, 'pruned_at': '2026-10-09T03:00:00', 'started': True},
    'legacy': {'rows': 10, 'verified': 9, 'unsigned': 1, 'tampered': 0, 'changed_since_chain_start': False,
               'count_at_last_checkpoint': 10},
}
HARDEN = {'node': 'pve1', 'profile': 'cis-l1', 'requested_profile': 'cis-l1', 'verbose': False,
          'controls': {'fs_modules': True, 'core_dumps': False, 'ssh_perms': None},
          'summary': {'total': 3, 'passed': 1, 'failed': 1, 'not_checked': 1, 'checked': 2}}
READS = {
    ('GET', '/api/security/compliance'): (200, COMPLIANCE),
    ('GET', '/api/security/key-info'): (200, {'exists': True, 'algorithm': 'AES-256-GCM', 'backups': []}),
    ('GET', '/api/security/cors'): (200, {'mode': 'same-origin', 'all_allowed': []}),
    ('GET', '/api/audit/integrity'): (200, INTEGRITY),
    ('GET', '/api/clusters/c1/nodes'): (200, [{'node': 'pve1', 'status': 'online'}]),
    ('GET', '/api/clusters/c1/nodes/pve1/hardening'): (200, HARDEN),
    ('GET', '/api/audit'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('GET', '/api/alert-channels'): (200, []),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='modern', **kw):
        extra = dict(READS)
        extra.update(SSE_TOKEN)
        app = _App(browser, _FakeServer(role='standalone', layout=layout, clusters=[CLUSTER], resources=[VM],
                                        metrics=NODE_METRICS, extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _settings_compliance(app, layout):
    page = app.page
    tabs = page.get_by_role('button', name='Compliance', exact=True)
    if layout == 'cloud':
        # the cloud nav has a Compliance item of its own: the modal's tab comes after it
        before = tabs.count()
        page.locator('button[title="Settings"]').first.click()
        page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
        assert tabs.count() == before + 1
        tabs.last.click()
    else:
        # no cluster is open yet, so the settings tab is the only one of that name
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press(',')
        tabs.first.click()
    page.locator('[data-testid="compliance-checked-of"]').wait_for(timeout=8000)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_self_check_says_what_it_checked(open_app, layout):
    app = open_app(layout)
    page = _settings_compliance(app, layout)
    assert page.locator('[data-testid="compliance-checked-of"]').inner_text().strip() == '2 of 3 controls checked'
    https = page.locator('[data-testid="compliance-control-https_enabled"]').inner_text()
    assert 'Not checked: Behind a reverse proxy' in https
    assert 'Two-factor sign-in is not required' in page.locator(
        '[data-testid="compliance-control-two_factor_enforced"]').inner_text()
    assert page.get_by_text('50%', exact=True).count() >= 1

    page.get_by_role('button', name='Verify Integrity').first.click()
    box = page.locator('[data-testid="audit-chain-findings"]')
    box.wait_for(timeout=5000)
    text = box.inner_text()
    assert '2 entries were changed after they were written (entries 24, 30).' in text
    assert '3 entries are missing, deleted from the log (entries 40-42).' in text
    assert 'Retention removed entries up to number 20' in text
    assert '4 entries were written since the last signed checkpoint' in text
    assert '10 entries are from before the chain: 9 signed, 1 unsigned, 0 changed.' in text
    assert 'None of them was removed or changed since the chain started.' in text
    assert 'out of order' not in text
    assert not app.errors, app.errors


def test_runtime_an_intact_chain_says_so_in_german(open_app):
    intact = dict(INTEGRITY, intact=True, potentially_tampered=0,
                  chain=dict(INTEGRITY['chain'], edited=0, edited_seqs=[], missing=0, missing_ranges=[],
                             after_checkpoint=0, pruned_through=0),
                  legacy=None)
    app = open_app('modern', language='de')
    app.server.extra[('GET', '/api/audit/integrity')] = (200, intact)
    page = _settings_compliance(app, 'modern')
    assert page.locator('[data-testid="compliance-checked-of"]').inner_text().strip() == '2 von 3 Kontrollen geprüft'
    page.get_by_role('button', name=re.compile('Integrität prüfen|Verify Integrity')).first.click()
    page.get_by_text('Seit Beginn der Kette wurde nichts geändert, entfernt oder umsortiert.').first.wait_for(timeout=5000)
    assert page.locator('[data-testid="audit-legacy"]').count() == 0
    assert not app.errors, app.errors


def _verify(app, integrity):
    app.server.extra[('GET', '/api/audit/integrity')] = (200, integrity)
    page = _settings_compliance(app, 'modern')
    page.get_by_role('button', name='Verify Integrity').first.click()
    box = page.locator('[data-testid="audit-chain-findings"]')
    box.wait_for(timeout=5000)
    return box.inner_text()


def test_runtime_an_end_cut_with_its_checkpoint_is_named(open_app):
    """The rows after checkpoint 3 went, and checkpoint 3 with them: the copy beside the key
    still has it"""
    cut = dict(INTEGRITY, intact=False, potentially_tampered=0, legacy=None,
               chain=dict(INTEGRITY['chain'], edited=0, edited_seqs=[], missing=5, missing_ranges=[[48, 52]],
                          truncated=True, after_checkpoint=0, checkpoints_missing=1, checkpoints_broken=0,
                          anchor='ok', anchor_seq=52, restarted=False, no_start=False))
    app = open_app('modern')
    text = _verify(app, cut)
    assert '1 signed checkpoints are missing from the database.' in text
    assert 'The log ends before its last signed checkpoint' in text
    assert 'Nothing was changed' not in text
    assert not app.errors, app.errors


def test_runtime_a_chain_started_over_and_a_missing_copy(open_app):
    restarted = dict(INTEGRITY, intact=False, potentially_tampered=0, legacy=None,
                     chain=dict(INTEGRITY['chain'], edited=0, edited_seqs=[], missing=0, missing_ranges=[],
                                after_checkpoint=0, pruned_through=0, restarted=True, restarted_after=812,
                                anchor='ok', no_start=False))
    app = open_app('modern')
    text = _verify(app, restarted)
    assert ('The chain was started over. The one this server kept a copy of reached entry 812 '
            'and is no longer in the database.') in text
    assert not app.errors, app.errors
    # nothing wrong, only no copy beside the key yet: said as context, not as a finding
    calm = dict(INTEGRITY, intact=True, potentially_tampered=0, legacy=None,
                chain=dict(INTEGRITY['chain'], edited=0, edited_seqs=[], missing=0, missing_ranges=[],
                           after_checkpoint=0, pruned_through=0, anchor='missing'))
    app = open_app('modern', language='de')
    app.server.extra[('GET', '/api/audit/integrity')] = (200, calm)
    page = _settings_compliance(app, 'modern')
    page.get_by_role('button', name=re.compile('Integrität prüfen|Verify Integrity')).first.click()
    page.get_by_text('Seit Beginn der Kette wurde nichts geändert, entfernt oder umsortiert.').first.wait_for(timeout=5000)
    assert page.get_by_text('Neben dem Verschlüsselungsschlüssel liegt noch keine Kopie des letzten Prüfpunkts.',
                            exact=False).count() == 1
    assert not app.errors, app.errors


def _cluster_compliance(app, layout):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.get_by_text('pve1', exact=True).first.wait_for(timeout=8000)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_dashboard_keeps_unread_controls_out_of_the_score(open_app, layout):
    app = open_app(layout)
    page = _cluster_compliance(app, layout)
    card = page.locator('div.bg-proxmox-dark', has=page.get_by_text('pve1', exact=True)).last
    card.get_by_text('1 not checked').wait_for(timeout=5000)
    text = card.inner_text()
    assert '1/2 passed' in text.lower() and '50%' in text, text
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_harden_node_marks_the_unread_control(open_app, layout):
    app = open_app(layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*Harden PVE Node\s*$')).first.click()
    page.locator('select', has=page.locator('option', has_text='pve1')).first.select_option('pve1')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text('1/2 controls active').first.wait_for(timeout=8000)
    page.get_by_text('· 1 not checked').first.wait_for(timeout=3000)
    badges = page.locator('span', has_text=re.compile(r'^Not checked$'))
    assert badges.count() == 1
    # the unread control is not ticked for an apply on its own, the failed one is
    assert page.locator('input[type="checkbox"]:checked').count() == 1
    assert not app.errors, app.errors
