"""Recovery assurance in the browser: coverage tiles, gap list, evidence export, manual
confirmation dialog, in Modern and Corporate, and the Cloud card. Source checks read web/src;
the runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py (skipped where Playwright is missing). The routes are tested in
tests/test_recovery_assurance.py.
LW Oct 2026
"""
import json
import re

import pytest

from test_restore_tests_ui import (_open_tab, _body, _reads, open_app, ROWS, REPORT, _read, LANGS, DASHES)  # noqa: F401
from test_ha_ui import _wait_for_call, browser  # noqa: F401

GUESTS = [dict(r, critical=(r['vmid'] != 102), proof=('proven' if r['vmid'] == 100 else 'not_proven'),
               missing=[] if r['vmid'] == 100 else ['restore_test'], gaps=[], confirmation=None) for r in ROWS]
GUESTS[1]['confirmation'] = {'id': '0123456789abcdef', 'vmid': 102, 'text': 'Restored by hand', 'confirmed_by': 'admin',
                             'confirmed_at': '2026-10-09T10:00:00', 'expires_at': '2026-11-09T10:00:00',
                             'revoked_at': None, 'revoked_by': None, 'active': True}
ASSURANCE = {
    'cluster_id': 'c1', 'cluster_name': 'Testi', 'stale_days': 30, 'backups_state': 'ok', 'critical_tags': ['critical'],
    'coverage': {'critical': {'total': 2, 'proven': 1, 'not_proven': 1, 'percent': 50.0},
                 'all': {'total': 3, 'proven': 1, 'not_proven': 2, 'percent': 33.3}},
    'gap_counts': {'app_failing': 1, 'never_tested': 1, 'plan_target_unreachable': 1},
    'gaps': [{'kind': 'app_failing', 'vmid': 101, 'name': 'db01', 'critical': True, 'cluster_id': 'c1', 'cluster_name': 'Testi'},
             {'kind': 'never_tested', 'vmid': 102, 'name': 'mail01', 'critical': False, 'cluster_id': 'c1', 'cluster_name': 'Testi'}],
    'plan_gaps': [{'kind': 'plan_target_unreachable', 'plan_id': 'p1', 'plan': 'DR Wien', 'vmid': None,
                   'target_cluster': 'c2', 'detail': 'target cluster is not connected'}],
    'gaps_truncated': False, 'guests': GUESTS,
}


def _assurance_reads():
    r = _reads()
    r.update({
        ('GET', '/api/clusters/c1/recovery-assurance'): (200, ASSURANCE),
        ('POST', '/api/clusters/c1/recovery-confirmations'): (200, {'success': True, 'id': 'abcdef0123456789'}),
        ('DELETE', '/api/clusters/c1/recovery-confirmations/0123456789abcdef'): (200, {'success': True}),
        ('POST', '/api/recovery-evidence/verify'): (200, {'signature_valid': True, 'audit_chain': 'present'}),
    })
    return r


# --- source --------------------------------------------------------------------------------

def _block():
    ui = _read('web', 'src', 'ui.js')
    s = ui.index('// LW Oct 2026 - recovery assurance under the restore tests')
    return ui[s:ui.index('function RestoreTestsPanel(', s)]


def test_every_assurance_string_is_in_every_language_once():
    tr = _read('web', 'src', 'translations.js')
    used = set(re.findall(r"t\('(rasr[A-Za-z]*)'\)", _block() + _read('web', 'src', 'cloud.js')))
    kinds = ['restore_failing', 'app_failing', 'agent_failing', 'never_tested', 'no_agent_check', 'no_app_checks',
             'rto_missed', 'test_stale', 'backup_old', 'no_backup', 'plan_target_unreachable', 'plan_no_replication']
    used |= {'rasrGap' + k[0].upper() + k[1:] for k in kinds}
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    assert [s[0] for s in starts] == LANGS
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        defined = re.findall(r'^\s*(rasr[A-Za-z_]*):', block, re.M)
        assert len(defined) == len(set(defined)) == 46, (lang, len(defined))
        assert used <= set(defined), (lang, sorted(used - set(defined)))
        # placed next to the restore test keys
        lines = [ln.strip().split(':', 1)[0] for ln in block.splitlines()]
        assert lines[lines.index('rtestCloudAttention') + 2] == 'rasrTitle'


def test_placeholders_survive_translation_and_no_em_dash():
    tr = _read('web', 'src', 'translations.js')
    names = sorted(set(re.findall(r'^\s*(rasr[A-Za-z_]*):', tr, re.M)))
    assert len(names) == 46
    for key in names:
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9, key
        wanted = set(re.findall(r'\{(\w+)\}', values[LANGS.index('en')]))
        for v in values:
            assert set(re.findall(r'\{(\w+)\}', v)) == wanted, (key, v)
            assert not any(d in v for d in DASHES), (key, v)
    assert not any(d in _block() for d in DASHES)


def test_icons_and_classes_exist():
    from test_ha_ui import _classes
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    assert set(re.findall(r'Icons\.([A-Za-z]+)', _block())) <= have
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    known = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_block()) - {'field'} if n not in known)
    assert not missing, missing


def test_the_bundle_has_the_panel_and_the_cloud_tiles():
    built = _read('web', 'index.html')
    for needle in ('function RecoveryAssurance(', '/recovery-assurance', '/recovery-confirmations', '/recovery-evidence',
                   'data-rasr-panel', 'data-rasr-cloud-kpi', 'rasrCloudCritical'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_coverage_gaps_export_and_confirmation(open_app, layout):
    app = open_app(extra=_assurance_reads(), layout=layout)
    page = _open_tab(app, layout)
    panel = page.locator('[data-rasr-panel="c1"]')
    panel.wait_for(timeout=8000)
    crit = panel.locator('[data-rasr-tile="critical"]')
    assert crit.get_attribute('data-proven') == '1' and crit.get_attribute('data-total') == '2'
    assert '50%' in crit.inner_text() and '1 of 2 proven' in crit.inner_text()
    assert '33.3%' in panel.locator('[data-rasr-tile="all"]').inner_text()
    # gaps: every kind with its count, a chip filters, the plan gap is listed
    assert panel.locator('[data-rasr-gap]').count() == 3
    panel.locator('[data-rasr-kind="never_tested"]').click()
    assert panel.locator('[data-rasr-gap]').count() == 1
    assert panel.locator('[data-rasr-gap]').get_attribute('data-vmid') == '102'
    panel.locator('[data-rasr-kind="plan_target_unreachable"]').click()
    assert 'DR Wien' in panel.locator('[data-rasr-gap]').inner_text()
    assert panel.locator('[data-rasr-confirm-open]').count() == 0          # a plan gap has no guest to confirm
    panel.locator('[data-rasr-kind="all"]').click()
    # export links carry the period
    assert panel.locator('[data-rasr-export="json"]').get_attribute('href').endswith('/recovery-evidence?days=30&format=json')
    assert panel.locator('[data-rasr-export="csv"]').get_attribute('href').endswith('/recovery-evidence?days=30&format=csv')
    # a confirmation is shown apart and still reads not proven
    conf = panel.locator('[data-rasr-confirmation="102"]')
    assert conf.get_attribute('data-proof') == 'not_proven' and 'Restored by hand' in conf.inner_text()
    assert 'Not proven' in conf.inner_text()
    # the dialog
    panel.locator('[data-rasr-confirm-open="102"]').click()
    dialog = page.locator('[data-rasr-dialog]')
    assert dialog.locator('[data-rasr-field="vmid"]').input_value() == '102'
    assert dialog.locator('[data-rasr-save-confirm]').is_disabled()          # no text, no save
    dialog.locator('[data-rasr-field="text"]').fill('Restored on the lab host')
    dialog.locator('[data-rasr-field="days"]').fill('30')
    dialog.locator('[data-rasr-save-confirm]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/recovery-confirmations'))
    assert _body(app, '/api/clusters/c1/recovery-confirmations') == {'vmid': 102, 'text': 'Restored on the lab host',
                                                                    'expires_days': 30}
    page.locator('[data-rasr-dialog]').wait_for(state='detached', timeout=5000)
    # withdrawing
    panel.locator('[data-rasr-withdraw="102"]').click()
    assert _wait_for_call(app, ('DELETE', '/api/clusters/c1/recovery-confirmations/0123456789abcdef'))
    # the critical tags
    panel.locator('[data-rasr-tags]').fill('critical, prod')
    panel.locator('[data-rasr-save-tags]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/recovery-settings'))
    assert _body(app, '/api/clusters/c1/recovery-settings') == {'critical_tags': ['critical', 'prod']}
    assert not app.errors, app.errors


def test_runtime_verify_a_document(open_app, tmp_path):
    app = open_app(extra=_assurance_reads(), layout='modern')
    page = _open_tab(app, 'modern')
    doc = tmp_path / 'evidence.json'
    doc.write_text(json.dumps({'format': 'pegaprox-recovery-evidence/1'}))
    page.locator('[data-rasr-verify]').set_input_files(str(doc))
    page.locator('[data-rasr-verdict="ok"]').wait_for(timeout=5000)
    assert 'Signature valid' in page.locator('[data-rasr-verdict]').inner_text()
    assert _body(app, '/api/recovery-evidence/verify') == {'format': 'pegaprox-recovery-evidence/1'}


def test_runtime_a_failing_read_shows_no_tiles(open_app):
    extra = _assurance_reads()
    extra[('GET', '/api/clusters/c1/recovery-assurance')] = (500, {'error': 'boom'})
    app = open_app(extra=extra, layout='modern')
    page = _open_tab(app, 'modern')
    page.locator('[data-rasr-error]').wait_for(timeout=5000)
    assert page.locator('[data-rasr-tile]').count() == 0
    # the report below it still works
    assert page.locator('[data-rtest-row]').count() == 3


def test_runtime_cloud_shows_the_coverage(open_app):
    extra = _assurance_reads()
    extra.update({('GET', '/api/clusters/c1/datacenter/backup'): (200, []),
                  ('GET', '/api/clusters/c1/datacenter/backup/last-runs'): (200, {'jobs': {}})})
    app = open_app(extra=extra, layout='cloud')
    page = app.page
    page.locator('.cloud-shell').get_by_text('Backups', exact=True).first.click()
    page.locator('[data-rtest-cloud="c1"] [data-rtest-row]').first.wait_for(timeout=8000)
    crit = page.locator('[data-rtest-cloud="c1"] [data-rasr-cloud-kpi="critical"]')
    crit.wait_for(timeout=5000)
    assert '50%' in crit.inner_text() and 'Critical proven' in crit.inner_text()
    assert '3' in page.locator('[data-rtest-cloud="c1"] [data-rasr-cloud-kpi="gaps"]').inner_text()
    assert page.locator('[data-rtest-cloud="c1"] [data-rasr-export="json"]').get_attribute('href').endswith(
        '/api/clusters/c1/recovery-evidence')
    assert not app.errors, app.errors
