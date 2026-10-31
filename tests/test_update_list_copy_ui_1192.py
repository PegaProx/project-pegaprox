"""The update list of the Update Manager as plain text (#1192).

"Copy as text" next to "Check for Updates" puts the list of the last check on the
clipboard for a change ticket: the cluster, when it was checked and copied, then every node
(and backup server) with a header line and one line per package, with the columns of the
tables in the section. Collapsed nodes are copied too; a node whose check failed and the
backup servers a reload left out (the browser keeps only the nodes) are named at the top.
The click reads nothing from the server. navigator.clipboard where the page has it, a
hidden textarea and execCommand('copy') on plain http where it does not. Disabled while
there is no list.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium with the fake server of tests/test_ha_ui.py; they skip where Playwright
is not installed.

LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import BASE, LANGS, TOASTS_JS, _App, _FakeServer, _blocks, _classes, _read, browser  # noqa: F401
from test_rolling_options_ui_763_954 import CLUSTER, READS, _to_updates

SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
CHECK_URL = '/api/clusters/cluster_1/updates/check'
STATUS_URL = '/api/clusters/cluster_1/updates/status'
DASHES = (chr(0x2014), chr(0x2013))

CHECK = {
    'success': True, 'cached': False,
    'summary': {'total_updates': 4, 'nodes_with_updates': 2, 'nodes_failed': 1, 'total_nodes': 4,
                'pbs_with_updates': 1, 'total_pbs': 1, 'checked_at': '2026-10-29 08:00:00'},
    'nodes': {
        'pve1': {'success': True, 'count': 2, 'updates': [
            {'Package': 'pve-manager', 'OldVersion': '8.2.4', 'Version': '8.2.7', 'Origin': 'Proxmox'},
            {'Package': 'proxmox-kernel-6.8', 'OldVersion': '6.8.12-2', 'Version': '6.8.12-4', 'Origin': 'Proxmox'}]},
        # longer than the 15 characters the table shows
        'pve2': {'success': True, 'count': 1, 'updates': [
            {'Package': 'libssl3', 'OldVersion': '3.0.11-1~deb12u2', 'Version': '3.0.15-1~deb12u1',
             'Origin': 'Debian', 'Section': 'security'}]},
        'pve3': {'success': True, 'count': 0, 'updates': []},
        'pve4': {'success': False, 'count': -1, 'updates': [], 'error': 'apt refresh failed: timed out'},
    },
    'pbs': {'pbs-main': {'success': True, 'pbs_id': 'pbs1', 'count': 1,
                         'updates': [{'Package': 'proxmox-backup-server', 'Version': '3.2.8-1'}]}},
}
EMPTY = {'success': True, 'cached': False, 'nodes': {}, 'pbs': {},
         'summary': {'total_updates': 0, 'nodes_with_updates': 0, 'nodes_failed': 0, 'total_nodes': 0}}

# what the page put on the clipboard: navigator.clipboard where it has one, else the copy event
# of the hidden textarea (pegaprox.test is plain http, so navigator.clipboard is not there)
WATCH_COPY = '''() => { window.__copied = [];
    document.addEventListener('copy', e => { const el = e.target;
        window.__copied.push(el && el.value !== undefined ? el.value.slice(el.selectionStart, el.selectionEnd) : String(getSelection())); }, true); }'''
SECURE_CLIPBOARD = '''() => { window.__written = [];
    Object.defineProperty(Navigator.prototype, 'clipboard', { configurable: true,
        get: () => ({ writeText: async (s) => { window.__written.push(s); } }) }); }'''
REFUSING_CLIPBOARD = '''() => { Object.defineProperty(Navigator.prototype, 'clipboard', { configurable: true,
        get: () => ({ writeText: async () => { throw new DOMException('denied', 'NotAllowedError'); } }) }); }'''


def _component():
    src = _read('web', 'src', 'security.js')
    start = src.index('function UpdateManagerSection(')
    return src[start:src.index('\n        function ', start + 10)]


def _new_code():
    comp = _component()
    return [comp[comp.index('// the Type column of a package row'):comp.index('// update single node')],
            comp[comp.index('{/* LW Oct 2026 (#1192)'):comp.index('{/* MK: Schedule button */}')]]


def _used_keys():
    return sorted(set(re.findall(r"t\('(updCopy\w+)'\)", _component())))


def _value(block, key):
    found = re.search(rf"^ +{key}: '((?:[^'\\]|\\.)*)',$", block, re.M)
    assert found, key
    return found.group(1)


# -- source ------------------------------------------------------------------------------------

def test_the_new_strings_are_their_own_keys():
    assert _used_keys() == sorted(['updCopyButton', 'updCopyHint', 'updCopyHeading', 'updCopyCopiedAt',
                                   'updCopyFailedHosts', 'updCopyPbsMissing', 'updCopyDone', 'updCopyFailed'])


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        assert set(re.findall(r'^ +(updCopy\w+): ', block, re.M)) == used, lang


HA_CHAIN = '// LW Oct 2026 (#625) - the banners of a group that fails over automatically, for every user'


def test_the_keys_sit_with_the_other_update_manager_strings():
    # in one run right under the column names of the package table, before the pinned tail
    for lang, block in _blocks().items():
        lines = block.splitlines()
        at = next(i for i, line in enumerate(lines) if line.strip().startswith('noUpdatesForNode:'))
        run = [line.strip().split(':')[0] for line in lines[at + 1:at + 1 + len(_used_keys())]]
        assert sorted(run) == _used_keys(), (lang, run)
        assert block.index('updCopyFailed:') < block.index(HA_CHAIN), lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = _value(blocks['en'], key)
        for lang, block in blocks.items():
            assert sorted(re.findall(r'\{\w+\}', _value(block, key))) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_no_em_or_en_dash_in_the_new_code_and_strings():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'updCopy' in line]
    for text in _new_code() + lines:
        assert not any(d in text for d in DASHES)


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    names -= {'textarea'}   # document.createElement('textarea'), not a class
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_no_icon_is_used_that_does_not_exist():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used and used <= icons, sorted(used - icons)


def test_the_copy_reads_nothing_from_the_server():
    text = _new_code()[0]
    text = text[text.index('const updateListText'):]
    assert 'fetch(' not in text and 'authFetch' not in text


def test_both_mounts_name_the_cluster():
    assert ('<UpdateManagerSection key={selectedCluster.id} clusterId={selectedCluster.id} '
            'clusterName={selectedCluster.display_name || selectedCluster.name}') in _read('web', 'src', 'dashboard.js')
    assert ('<UpdateManagerSection clusterId={cid} clusterName={selectedCluster && '
            '(selectedCluster.display_name || selectedCluster.name)}') in _read('web', 'src', 'cloud.js')


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    assert 'updates-copy-text' in bundle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime -----------------------------------------------------------------------------------

class _Server(_FakeServer):
    def __init__(self, check=None, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [])
        kw.setdefault('role', 'standalone')
        extra = dict(READS)
        extra[('POST', CHECK_URL)] = (200, check if check is not None else CHECK)
        super().__init__(extra=extra, **kw)


@pytest.fixture
def ui(browser):  # noqa: F811
    apps = []

    def _open(layout='modern', **kw):
        app = _App(browser, _Server(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _copy_button(app, layout='modern', cluster_name='Testi'):
    page = app.page
    head = _to_updates(app, layout, cluster_name)
    button = page.locator('[data-testid="updates-copy-text"]')
    if not button.count():
        head.click()
    button.wait_for(timeout=8000)
    return button


def _wait_listed(app, node='pve1'):
    app.page.get_by_text(node, exact=True).first.wait_for(timeout=8000)
    app.page.wait_for_timeout(200)


def _toasts(app):
    return app.page.evaluate(TOASTS_JS)


def _wait_toast(app, text):
    seen = set()
    for _ in range(30):
        seen.update(_toasts(app))
        if any(text in x for x in seen):
            return
        app.page.wait_for_timeout(100)
    raise AssertionError(f'no toast {text!r}, only {sorted(seen)}')


def _copied(app):
    return app.page.evaluate('() => window.__copied')


def _section(text, head):
    """The lines of one host: its header line up to the next blank line."""
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith(head))
    end = next((i for i in range(at, len(lines)) if not lines[i]), len(lines))
    return lines[at:end]


def _rows(section):
    return [re.split(r'\s{2,}', line.strip()) for line in section[1:]]


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_list_goes_out_as_text_over_plain_http(ui, layout):
    app = ui(layout=layout)
    button = _copy_button(app, layout)
    _wait_listed(app)
    assert button.inner_text().strip() == 'Copy as text'
    assert button.is_enabled()
    # nothing is expanded: the packages are on no screen, the text has them all the same
    assert app.page.get_by_text('pve-manager').count() == 0
    app.page.evaluate(WATCH_COPY)
    calls = len(app.server.calls)
    button.click()
    _wait_toast(app, 'Update list copied to the clipboard')
    assert not app.page.evaluate('() => window.isSecureContext'), 'this test is about plain http'
    copied = _copied(app)
    assert len(copied) == 1
    text = copied[0]
    lines = text.splitlines()
    assert lines[0] == 'Pending updates - Testi'
    assert lines[1].startswith('Last checked: ') and lines[2].startswith('Copied: ')
    assert lines[3] == '4 Updates available'
    assert lines[4] == 'Incomplete: 1 host(s) could not be checked, their packages are missing from this list'

    pve1 = _section(text, 'pve1 - ')
    assert pve1[0] == 'pve1 - 2 updates - Kernel'
    assert _rows(pve1) == [['Package', 'Current version', 'New', 'Type'],
                           ['pve-manager', '8.2.4', '8.2.7', 'Update'],
                           ['proxmox-kernel-6.8', '6.8.12-2', '6.8.12-4', 'Kernel']]
    # the version in full, where the table cuts it
    assert _rows(_section(text, 'pve2 - '))[1] == ['libssl3', '3.0.11-1~deb12u2', '3.0.15-1~deb12u1', 'Security']
    assert _section(text, 'pve2 - ')[0] == 'pve2 - 1 updates - Security'
    assert _section(text, 'pve3 - ') == ['pve3 - 0 updates']
    assert _section(text, 'pve4 - ') == ['pve4 - Check failed: apt refresh failed: timed out']
    assert 'Proxmox Backup Server' in lines
    assert _rows(_section(text, 'pbs-main - ')) == [['Package', 'Version'], ['proxmox-backup-server', '3.2.8-1']]
    assert _section(text, 'pbs-main - ')[0] == 'pbs-main - 1 updates'
    # the page polls on (the rolling status, the version check), the click asks for nothing
    after = [c for c in app.server.calls[calls:] if c[0] != 'GET' or ('/updates' in c[1] and c[1] != STATUS_URL)]
    assert after == [], after
    _shot(app, f'update-copy-{layout}')
    assert not app.errors, app.errors


def test_runtime_the_columns_line_up_and_carry_what_the_table_shows(ui):
    app = ui()
    button = _copy_button(app)
    _wait_listed(app)
    app.page.evaluate(WATCH_COPY)
    button.click()
    _wait_toast(app, 'Update list copied')
    text = _copied(app)[0]
    for host in ('pve1 - ', 'pve2 - ', 'pbs-main - '):
        table = _section(text, host)[1:]
        starts = [[m.start() for m in re.finditer(r'(?:^|(?<=  ))\S', line)] for line in table]
        assert len({tuple(s) for s in starts}) == 1, (host, table)
        assert not any(line != line.rstrip() for line in table)
    # the expanded node in the page: every cell of a row is in the text, cut versions as a prefix
    for node in ('pve1', 'pve2'):
        app.page.get_by_text(node, exact=True).first.click()
        app.page.wait_for_timeout(300)
        cells = app.page.locator('[data-update-manager] table tbody tr').evaluate_all(
            'rows => rows.map(r => Array.from(r.querySelectorAll("td")).map(td => td.innerText.trim()))')
        copied = _rows(_section(text, f'{node} - '))[1:]
        assert len(cells) == len(copied), (cells, copied)
        for shown, row in zip(cells, copied):
            assert shown[0] == row[0] and shown[3] == row[3]
            assert row[1].startswith(shown[1]) and row[2].startswith(shown[2])
    assert not app.errors, app.errors


def test_runtime_navigator_clipboard_is_used_where_the_page_has_it(ui):
    app = ui()
    button = _copy_button(app)
    _wait_listed(app)
    app.page.evaluate(WATCH_COPY)
    app.page.evaluate(SECURE_CLIPBOARD)
    button.click()
    _wait_toast(app, 'Update list copied to the clipboard')
    written = app.page.evaluate('() => window.__written')
    assert len(written) == 1 and written[0].startswith('Pending updates - Testi\n')
    assert '  pve-manager' in written[0]
    assert _copied(app) == [], 'the textarea ran although navigator.clipboard took the text'
    assert not app.errors, app.errors


def test_runtime_a_refused_clipboard_falls_back_to_the_textarea(ui):
    app = ui()
    button = _copy_button(app)
    _wait_listed(app)
    app.page.evaluate(WATCH_COPY)
    app.page.evaluate(REFUSING_CLIPBOARD)
    button.click()
    _wait_toast(app, 'Update list copied to the clipboard')
    assert len(_copied(app)) == 1 and _copied(app)[0].startswith('Pending updates - Testi\n')
    assert not app.errors, app.errors


def test_runtime_a_copy_the_browser_refuses_says_so(ui):
    app = ui()
    button = _copy_button(app)
    _wait_listed(app)
    app.page.evaluate(REFUSING_CLIPBOARD)
    app.page.evaluate("() => { document.execCommand = () => false; }")
    button.click()
    _wait_toast(app, 'The browser did not allow copying to the clipboard')
    assert not any('Update list copied' in x for x in _toasts(app))
    assert not app.errors, app.errors


def test_runtime_after_a_reload_the_text_says_the_backup_servers_are_missing(ui):
    app = ui()
    _copy_button(app)
    _wait_listed(app)
    assert app.server.calls.count(('POST', CHECK_URL)) == 1
    # the browser keeps the check of today: the reload shows it without checking again
    app.page.reload(wait_until='load')
    app.wait_for_app()
    button = _copy_button(app)
    _wait_listed(app)
    assert app.server.calls.count(('POST', CHECK_URL)) == 1
    assert app.page.get_by_text('pbs-main').count() == 0
    app.page.evaluate(WATCH_COPY)
    button.click()
    _wait_toast(app, 'Update list copied')
    text = _copied(app)[0]
    assert ('Incomplete: the packages of 1 backup server(s) are not loaded here, check for updates to list them'
            in text.splitlines())
    assert 'Proxmox Backup Server' not in text and '  pve-manager' in text
    assert not app.errors, app.errors


def test_runtime_nothing_to_copy_leaves_the_button_off(ui):
    app = ui(check=EMPTY)
    button = _copy_button(app)
    app.page.wait_for_timeout(800)
    assert app.server.calls.count(('POST', CHECK_URL)) == 1
    assert button.is_disabled()
    assert not app.errors, app.errors


def test_runtime_a_standby_without_a_list_has_the_button_off(ui):
    app = ui(role='standby')
    button = _copy_button(app)
    app.page.wait_for_timeout(800)
    assert ('POST', CHECK_URL) not in app.server.calls
    assert button.is_disabled()
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(ui):
    app = ui(language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.get_by_role('button', name='Update Manager', exact=True).click()
    button = page.locator('[data-testid="updates-copy-text"]')
    if not button.count():
        page.get_by_text('Update Manager').last.click()
    button.wait_for(timeout=8000)
    _wait_listed(app)
    assert button.inner_text().strip() == 'Als Text kopieren'
    page.evaluate(WATCH_COPY)
    button.click()
    _wait_toast(app, 'Update-Liste in die Zwischenablage kopiert')
    text = _copied(app)[0]
    assert text.startswith('Ausstehende Updates - Testi\nZuletzt geprüft: ')
    assert 'Unvollständig: 1 Host(s) konnten nicht geprüft werden' in text
    assert _rows(_section(text, 'pve1 - '))[0][0] == 'Paket'
    assert not app.errors, app.errors
