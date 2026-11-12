"""The restore results list the secrets the backup did not carry.

The restore answers secrets_to_enter: each SMTP, LDAP, OIDC or ACME DNS secret, alert
channel and cluster that ends up without what it sends with, because the backup left it
out and this instance holds none for the same server (api/settings.py _restored_secrets),
the nodes of a cluster the backup moved that lost their own root password, and the HA
agent key and fence passwords an overwrite leaves empty.
The results of Settings, Security Settings, Restore from Backup list them, for the dry
run as well, and turn yellow as they do for errors.

These read the source and the translations; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py and skip where
Playwright is not installed. LW
"""
import re

import pytest

from test_ha_ui import LANGS, _blocks, _classes, _read, browser, open_app  # noqa: F401

PREFIX = r'restoreSecret\w*'


def _panel():
    sec = _read('web', 'src', 'security.js')
    start = sec.index('// LW Nov 2026 - what the restore answer names in secrets_to_enter')
    return (sec[start:sec.index('return (', start)]
            + sec[sec.index('{lastResult.secrets_to_enter?.length > 0 && ('):sec.index("{t('errors') || 'Errors'}")])


def _used():
    return set(re.findall(r"t\('(%s)'\)" % PREFIX, _panel()))


# -- source ----------------------------------------------------------------------------------

def test_every_setting_the_restore_names_has_its_label():
    from pegaprox.api.settings import _RESTORE_SECRETS
    panel = _panel()
    labelled = set(re.findall(r"^ +(\w+): t\('restoreSecret\w+'\),$", panel, re.M))
    assert labelled == set(_RESTORE_SECRETS)
    # the ones that carry a name
    assert "s.channel !== undefined" in panel and "s.cluster !== undefined" in panel
    # what belongs to a cluster before the cluster itself, which they carry the name of
    for kind in ('s.agent_token', 'Array.isArray(s.fences)', 'Array.isArray(s.nodes)'):
        assert panel.index(kind) < panel.index('s.cluster !== undefined'), kind


def test_the_results_list_them_and_turn_yellow():
    panel = _panel()
    assert '{lastResult.secrets_to_enter.map((s, i) => (' in panel
    assert '<li key={i}>{secretToEnter(s)}</li>' in panel
    sec = _read('web', 'src', 'security.js')
    assert ("lastResult.errors?.length > 0 || lastResult.secrets_to_enter?.length > 0 ? "
            "'bg-yellow-500/10 border-yellow-500/30'") in sec


def test_every_key_exists_once_per_language_and_none_is_unused():
    used = _used()
    assert len(used) == 12, sorted(used)
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


def test_the_keys_sit_with_the_restore_results():
    for lang, block in _blocks().items():
        assert 0 < block.index('restoreSecretsToEnter:') - block.index('restoreResults:') < 120, lang


def test_no_em_or_en_dash_in_the_new_text():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'restoreSecret' in line]
    for text in [_panel()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_panel()) if n not in have)
    assert not missing, missing


# -- runtime: the built bundle in a real browser ----------------------------------------------

ANSWER = {'mode': 'merge', 'dry_run': True, 'backup_version': '1.5.0', 'backup_date': '2026-11-01T10:00:00',
          'backup_by': 'admin', 'restored': {'server_settings': True, 'clusters': 1}, 'skipped': {},
          'errors': [], 'secrets_to_enter': [{'setting': 'smtp_password'}, {'setting': 'ldap_bind_password'},
                                             {'channel': 'ops'}, {'cluster': 'lab'},
                                             {'cluster': 'lab', 'nodes': ['pve2', 'pve3']},
                                             {'cluster': 'lab', 'agent_token': True},
                                             {'cluster': 'lab', 'fences': ['pve1']}]}


# what the way to the results reads in the two languages the tests click through
LABELS = {'en': ('PegaProx Settings', 'Security Settings', 'Restore Backup', 'Validate Backup', 'Dry Run Results'),
          'de': ('PegaProx Einstellungen', 'Sicherheitseinstellungen', 'Backup wiederherstellen',
                 'Backup validieren', 'Testlauf-Ergebnisse')}


def _restore_results(app, language='en'):
    title, tab, restore, validate, results = LABELS[language]
    page = app.page
    # "g ," is the settings shortcut
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.get_by_text(title).first.wait_for(timeout=5000)
    page.get_by_role('button', name=tab, exact=True).first.click()
    page.locator('button', has_text=restore).first.click()
    page.locator('input[type="file"][accept=".pegabackup,.json"]').set_input_files(
        {'name': 'pp.pegabackup', 'mimeType': 'application/octet-stream', 'buffer': b'\0' * 64})
    pw = page.locator('input[type="password"]')
    pw.nth(pw.count() - 2).fill('account-password')
    pw.nth(pw.count() - 1).fill('backup-password')
    page.locator('button', has_text=validate).first.click()
    box = page.locator('h5', has_text=results).locator('xpath=..')
    box.wait_for(timeout=5000)
    return box


def test_runtime_the_dry_run_lists_what_to_enter_again(open_app):
    app = open_app(role='standalone', layout='modern', extra={('POST', '/api/config/restore'): (200, ANSWER)})

    box = _restore_results(app)

    text = box.inner_text()
    for line in ('Secrets to enter again',
                 'The restore could not keep these: the backup does not carry them, or it points them at '
                 'another server.', 'SMTP password', 'LDAP bind password',
                 'Alert channel "ops": URL, and token or topic if it has one.', 'Cluster "lab": password or API token secret',
                 'Cluster "lab": own root password of node(s) pve2, pve3, under Node credentials',
                 'Cluster "lab": key of the HA self-fence agents. Install the self-fence agent again.',
                 'Cluster "lab": BMC password of the fence of node(s) pve1'):
        assert line in text, text
    assert 'restoreSecret' not in text
    assert 'bg-yellow-500/10' in box.get_attribute('class')
    assert ('POST', '/api/config/restore') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_without_any_the_results_stay_green(open_app):
    answer = dict(ANSWER, secrets_to_enter=None)
    del answer['secrets_to_enter']
    app = open_app(role='standalone', layout='modern', extra={('POST', '/api/config/restore'): (200, answer)})

    box = _restore_results(app)

    assert 'Secrets to enter again' not in box.inner_text()
    assert 'bg-green-500/10' in box.get_attribute('class')
    assert not app.errors, app.errors


def test_runtime_the_list_speaks_german(open_app):
    app = open_app(role='standalone', layout='modern', language='de',
                   extra={('POST', '/api/config/restore'): (200, ANSWER)})

    text = _restore_results(app, 'de').inner_text()

    for line in ('Neu einzugebende Geheimnisse', 'Die Wiederherstellung konnte sie nicht übernehmen',
                 'SMTP-Passwort', 'Alarmkanal "ops"', 'Cluster "lab": Passwort',
                 'Cluster "lab": eigenes Root-Passwort von Node(s) pve2, pve3',
                 'Cluster "lab": Schlüssel der HA-Self-Fence-Agenten', 'BMC-Passwort des Fencing von Node(s) pve1'):
        assert line in text, text
    assert not app.errors, app.errors
