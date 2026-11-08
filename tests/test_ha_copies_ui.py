"""The copies of changes that were not carried over, and the config version, in the web UI (#625).

Stage 2 keeps a copy of what an instance held and a sync replaced (config/ha_orphans)
and counts the configuration the group shares (config_version). The status carries both,
the banner object a count of the copies; this is where an admin sees them: a list in the
HA tab with Download (after the account password) and Dismiss (deletes for good), the
version in the head card, and a banner line with the way to the tab.

The source checks hold the wiring and the translations; the runtime tests drive the built
bundle in headless Chromium against the fake server of test_ha_ui.py, with the two routes
of the copies added. They skip where Playwright is not installed.
LW
"""
import gzip
import json
import os
import re
import time

import pytest

from test_ha_ui import (  # noqa: F401  (browser is a fixture)
    BASE, LANGS, PASSWORD, PEER, SRC, _App, _FakeServer, _block, _blocks, _classes, _function, _iso_ago,
    _member, _open_ha, _read, _toasts, _until, _value, _wait_for_toast, browser)

OWN = 'a' * 32
OWN_FP = '5c1e0a77d2b94f13'
OTHER_FP = '9f2c41ab00c3d7e1'
OLD_FP = '0d4b6e2a91c37f58'
NAME_A = '3-14-20261002T101500Z-abcdef012345'
NAME_B = '2-9-20261001T080000Z-0123456789ab'
REASON_A = 'the configuration here changed after it was last synced or handed out'
REASON_B = 'the configuration here is at 2.9 (led by bbbbbbbb), which the snapshot does not carry'
NOT_OPENED = ('This copy is sealed under another master key (fingerprint 9f2c41ab00c3d7e1) than the one this '
              'instance runs with: the key store changed, or the copy came here from another host - it cannot '
              'be opened on this instance')
SYNC_BUSY = 'A sync is running right now - the copy is still here, try again in a moment'
# spelled by its code point, so this file holds none itself
EM_DASH = chr(0x2014)


@pytest.fixture(scope='module')
def modal():
    return _read('web', 'src', 'settings_modal.js')


@pytest.fixture(scope='module')
def panel(modal):
    return _function(modal[modal.index('// PegaProx - High Availability (#625)'):], 'HaPanel')


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def copies_ui(panel):
    """Everything the panel builds for the copies, from the content helper to the card."""
    return _block(panel, 'const copyContent = (c) =>', "// A standalone's first code makes it the active.")


@pytest.fixture(scope='module')
def copies_banner(dash):
    return _block(dash, 'function HaCopiesBanner(', '// Cluster Sidebar Item Component')


# -- the panel ------------------------------------------------------------------------------------

def test_the_list_comes_from_the_status_and_shows_only_with_copies(panel, copies_ui):
    assert "const copies = status?.orphans && typeof status.orphans === 'object' ? status.orphans : null;" in panel
    # an item without a name to address it by is not shown (it blanked the whole app)
    assert ('const copyItems = Array.isArray(copies?.items)\n'
            "                ? copies.items.filter(c => c && typeof c === 'object' && typeof c.name === 'string' "
            '&& c.name) : [];') in panel
    assert 'const copyCount = copies ? (Number(copies.count) || 0) : 0;' in panel
    assert 'const copiesCard = copyCount > 0 && (' in copies_ui
    # one card for every role, under the notes of the head and before what each role shows
    main = panel[panel.index('<div className="space-y-4" data-ha-role={role}>'):]
    assert main.count('{copiesCard}') == 1
    assert main.index('{removalNote}') < main.index('{copiesCard}') < main.index("{role === 'standalone' && (")
    # one row per copy, keyed by its name; the reason as the server gives it
    assert '{copyItems.map(c => {' in copies_ui
    assert '<div key={c.name} data-ha-copy={c.name}' in copies_ui
    # a reason that is no text would be handed to React as a child: it is not rendered
    assert "<span data-ha-copy-reason>{typeof c.reason === 'string' && c.reason ? c.reason : '-'}</span>" in copies_ui
    assert "{copies.over_limit === true && (" in copies_ui and "{t('haCopiesOverLimit')}" in copies_ui
    assert "{t('haCopiesIntro')}" in copies_ui


def test_a_copy_that_does_not_open_here_cannot_be_downloaded(copies_ui):
    assert 'const sealed = !!c.seal && c.seal.opens === false;' in copies_ui
    row = copies_ui[copies_ui.index('<button onClick={() => askCopy(c.name)}'):]
    assert row.startswith('<button onClick={() => askCopy(c.name)} disabled={!!busy || sealed}')
    hint = _block(copies_ui, '{sealed && (', '{oldKey && (')
    # the fingerprints come from the server: through a function, a replacement string reads $& and $`
    assert "t('haCopiesNoOpen').replace('{fp}', () => c.seal.fp || '-')" in hint
    assert "copies.seal?.fp && ` ${t('haCopiesOwnSeal').replace('{fp}', () => copies.seal.fp)}`" in hint
    assert "t('haCopiesValuesBackup').replace('{file}', () => c.key.backup)" in copies_ui
    # the field key of the values inside only matters for a copy that opens
    assert 'const oldKey = !sealed && c.key && c.key.current === false;' in copies_ui


def test_what_a_copy_holds_is_read_per_table(copies_ui):
    content = _block(copies_ui, 'const copyContent = (c) =>', 'const copyRow = ')
    assert "name !== 'files'" in content
    assert "t('haCopiesOnlyHere').replace('{n}', d.only_here)" in content
    assert "t('haCopiesOnlyThere').replace('{n}', d.only_there)" in content
    assert "const files = Array.isArray(diff.files) ? diff.files.filter(f => typeof f === 'string') : [];" in content
    assert "t('haCopiesJournal').replace('{n}', c.journal_rows)" in content
    assert "{c.repeats > 0 && copyRow(t('haCopiesRepeated'), (" in copies_ui


def test_download_asks_for_the_password_and_saves_the_file(panel, copies_ui):
    save = _block(panel, 'const saveCopy = (name) => run(', 'const askCopy = ')
    assert "fetch(`${API_URL}/ha/orphans/${encodeURIComponent(name)}/download`, {" in save
    assert "body: JSON.stringify(withPassword('copy', {}))" in save
    # a refused password stays at its field; 404 is gone, anything else in the server's words
    assert save.index("if (r.status === 404) {") < save.index("if (reauthRefused('copy', res)) return;")
    assert 'setCopyError({ text: res.error, code });' in save
    # saved as a file under the server's name, never opened in the page
    assert 'const blob = await r.blob();' in save
    assert "a.download = named ? named[1] : `pegaprox-ha-${name}.json.gz`;" in save
    assert 'window.open' not in save and 'location' not in save
    assert "const askCopy = (name) => sso ? saveCopy(name) : openCopy('download', name);" in panel
    # the password goes with the request, whatever the answer: a 409, a 500 or no answer at all
    request = save[save.index('try {'):save.index('if (!r.ok) {')]
    assert 'r = await fetch(' in request
    assert request.index('} finally {') < request.index("setPassword('copy', '');")
    # a box whose copy is no longer listed closes, and openCopy(null) empties the field
    gone = _block(panel, 'const copyNames = copyItems.map(c => c.name)', 'const WORD = ')
    assert "if (copyAction && !copyItems.some(c => c.name === copyAction.name)) openCopy(null);" in gone
    assert '}, [copyAction, copyNames]);' in gone
    open_ = _block(panel, 'const openCopy = (what, name = null) => {', 'const saveCopy = ')
    assert "setPassword('copy', '');" in open_
    # no box open at all: nothing to read a name of (with a copy without one it threw)
    assert 'const copyBox = (c, sealed) => !copyAction || copyAction.name !== c.name ? null :' in copies_ui
    box = _block(copies_ui, 'const copyBox = (c, sealed) =>', ') : (')
    assert "{!sso && <div className=\"max-w-sm\">{passwordInput('copy', 'pgha-copy-password')}</div>}" in box
    assert "{reauthNote('copy', 'pgha-copy-password')}" in box
    # a box opened before a poll found the copy sealed sends nothing either
    assert "disabled={needsPassword('copy') || !!busy || sealed}" in box
    assert '{copyBox(c, sealed)}' in copies_ui
    assert "const [passwords, setPasswords] = useState({ code: '', join: '', confirm: '', copy: '' });" in panel


def test_dismiss_confirms_and_names_a_running_sync(panel, copies_ui):
    dismiss = _block(panel, 'const dismissCopy = (name) => run(', 'const WORD = ')
    assert "send('POST', `orphans/${encodeURIComponent(name)}/dismiss`, { confirm: true }, t('haCopiesDismissFailed'))" in dismiss
    assert ("if (res.code === 'HA_SYNC_RUNNING') { setCopyError({ text: t('haCopiesSyncRunning'), code: res.code }); "
            "return; }") in dismiss
    # the answer's list goes in at once, and an older status may not bring the row back
    assert 'copiesSeq.current = loadSeq.current;' in dismiss
    assert 'setStatus(s => ({ ...(s || {}), orphans: res.data.orphans }));' in dismiss
    load = _block(panel, 'const load = async () => {', '\n            };')
    assert 'if (seq <= copiesSeq.current) setStatus(s => ({ ...data, orphans: s?.orphans ?? data.orphans }));' in load
    box = copies_ui[copies_ui.index('data-ha-copy-box="dismiss"'):]
    assert "{t('haCopiesDismissDesc')}" in box and "<button onClick={() => dismissCopy(c.name)} disabled={!!busy}" in box


def test_the_banner_is_read_again_when_its_count_is_not_the_lists(panel):
    assert 'const { ha: haBanner } = useAuth();' in panel
    effect = _block(panel, 'useEffect(() => {\n                if (!status) return;', '}, [!!status, copyCount]);')
    assert "const shown = typeof haBanner?.orphans === 'number' ? haBanner.orphans : 0;" in effect
    assert 'if (shown !== copyCount) refreshHa?.();' in effect


def test_the_config_version_is_in_the_head_card(panel):
    assert ("const cv = role !== 'standalone' && status.config_version && Array.isArray(status.config_version.cv)"
            in panel)
    assert "const cvText = cv && (cv.cv[0] > 0 || cv.cv[1] > 0) ? `${cv.cv[0]}.${cv.cv[1]}` : '';" in panel
    assert "cv.by === status.instance_id ? t('haCvThisInstance')" in panel
    # who stepped it is an instance id, a text: anything else names nobody (a number threw in .slice)
    assert "const cvBy = typeof cv?.by !== 'string' || !cv.by ? '' :" in panel
    head = _block(panel, "<span>{t('pgHaInstanceId')}:", '{broken && (')
    assert "<span data-ha-cv={cvText || (cv.joined ? 'joined' : 'none')} title={t('haCvHint')}>" in head
    assert "t('haCvBy').replace('{who}', () => cvBy)" in head and '{when(cv.at)}' in head
    assert "t(cv.joined ? 'haCvJoined' : 'haCvNone')" in head


# the placeholders the HA texts fill from what a server sent: names, addresses, fingerprints
SERVER_PLACEHOLDERS = ('who', 'fp', 'file', 'instance', 'epoch', 'nodes', 'name', 'by', 'url', 'rows', 'tables',
                       'max')


def test_server_words_go_into_a_text_through_a_function(panel, dash):
    """String.replace reads $&, $` and $' in a replacement string: a fingerprint or an address
    with one of them showed the placeholder, or the text around it, in its place."""
    node_parts = _block(dash, '// Node HA in the HA settings of a cluster (#625)', 'function PegaProxDashboard(')
    code = panel + node_parts + _function(dash, 'HaStandbyBanner')
    seen = 0
    for key in SERVER_PLACEHOLDERS:
        for m in re.finditer(r"\.replace\('\{%s\}', (.{0,6})" % key, code):
            seen += 1
            assert m.group(1).startswith('() =>'), (key, code[m.start():m.start() + 120])
    assert seen >= 20, seen


# -- the banner -----------------------------------------------------------------------------------

def test_the_banner_line_is_for_admins_in_every_role(copies_banner):
    assert "const n = typeof ha?.orphans === 'number' ? ha.orphans : 0;" in copies_banner
    assert 'if (!isAdmin || n < 1) return null;' in copies_banner
    # nothing about the role: a former active keeps its copies too
    for needle in ('ha?.role', 'ha.role', 'haStandby', 'standby'):
        assert needle not in copies_banner, needle
    assert "n === 1 ? t('haCopiesBannerOne') : t('haCopiesBanner').replace('{n}', n)" in copies_banner
    assert "{t('pgHaTab')}" in copies_banner


def test_every_layout_renders_the_line_next_to_the_standby_banner(dash):
    main = dash[dash.index('function PegaProxDashboard('):]
    assert ('<HaStandbyBanner onOpenHa={openHaSettings} />\n'
            '                    <HaCopiesBanner onOpenHa={openHaSettings} />') in main
    shell = _function(_read('web', 'src', 'cloud.js'), 'CloudShell')
    at = shell.index('<HaCopiesBanner cloud onOpenHa={() => {')
    assert shell.index('<HaStandbyBanner cloud') < at < shell.index('<div className="cloud-content-scroll">')
    opener = shell[at:shell.index('}} />', at)]
    assert 'onOpenSettings && onOpenSettings();' in opener
    assert "window.dispatchEvent(new CustomEvent('pegaprox-navigate-ha'));" in opener


# -- translations ---------------------------------------------------------------------------------

def _used_keys():
    keys = set()
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js') and name != 'translations.js':
            keys.update(re.findall(r"'((?:haCopies|haCv)\w+)'", _read('web', 'src', name)))
    return sorted(keys)


def test_the_keys_are_ours():
    keys = _used_keys()
    assert len(keys) >= 30
    # every one goes through t(): a literal key nowhere else
    src = _read('web', 'src', 'settings_modal.js') + _read('web', 'src', 'dashboard.js')
    for key in keys:
        assert re.search(r"t\((?:[^()]*\? )?'%s'" % key, src) or re.search(r": '%s'\)" % key, src), key


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    defined = set(re.findall(r'^ +((?:haCopies|haCv)\w+): ', block, re.M))
    assert defined == set(_used_keys()), sorted(defined ^ set(_used_keys()))


@pytest.mark.parametrize('lang', LANGS)
def test_the_keys_sit_right_after_the_ha_keys(lang):
    lines = _blocks()[lang].splitlines()
    last_ha = max(i for i, line in enumerate(lines) if re.match(r'^ +pgHa\w+: ', line))
    after = [line for line in lines[last_ha + 1:] if not line.strip().startswith('//')]
    ours = [re.match(r'^ +(\w+): ', line).group(1) for line in after[:len(_used_keys())]]
    assert sorted(ours) == _used_keys()
    # then the end of the language, or the block of the node HA keys (test_ha_node_ui.py)
    following = after[len(_used_keys())].strip()
    assert following == '},' or following.startswith('haNode'), following


def test_placeholders_survive_and_every_text_is_translated():
    blocks = _blocks()
    for key in _used_keys():
        en = _value(blocks['en'], key)
        for lang in LANGS:
            value = _value(blocks[lang], key)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)
            assert EM_DASH not in value, (lang, key)
            # a count sign is the same in most languages; everything else reads in the language
            if lang != 'en' and key != 'haCopiesRepeatedCount':
                assert value != en, (lang, key)


def test_korean_names_a_member_the_way_the_other_ha_keys_do():
    """The hint of the config version said 구성원 where every other HA key says 멤버."""
    ko = _blocks()['ko']
    assert '멤버와 리더가' in _value(ko, 'haCvHint')
    ha = dict(re.findall(r"^ +((?:pgHa|ha[A-Z])\w*): '(.*)',$", ko, re.M))
    assert not sorted(k for k, v in ha.items() if '구성원' in v)
    assert sum('멤버' in v for v in ha.values()) >= 5


def test_the_button_names_in_the_explanation_match_the_buttons():
    blocks = _blocks()
    for lang in LANGS:
        dismiss = _value(blocks[lang], 'haCopiesDismiss').strip("'")
        assert dismiss in _value(blocks[lang], 'haCopiesIntro'), lang


def test_no_em_dash_and_the_austrian_flag_stays(copies_ui, copies_banner, panel):
    head = _block(panel, 'const cv = role', 'return (')
    for text in (copies_ui, copies_banner, head, _read('tests', 'test_ha_copies_ui.py')):
        assert EM_DASH not in text
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


# -- styling, icons, bundle -------------------------------------------------------------------------

def test_every_class_is_in_the_static_tailwind_build(copies_ui, copies_banner, panel):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    head = _block(panel, '{cv && (', '{broken && (')
    names = _classes(copies_ui) | _classes(copies_banner) | _classes(head)
    names -= {'card', 'field', 'input', 'btn', 'btnGhost'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(copies_ui, copies_banner):
    icons = set(re.findall(r'^ {12}(\w+): ', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.(\w+)', copies_ui + copies_banner))
    assert used and used <= icons, sorted(used - icons)


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function HaCopiesBanner(', 'data-ha-copies-banner', '/ha/orphans/', 'haCvThisInstance'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime: the built bundle in a real browser -------------------------------------------------------

def _copy(name, reason, size=12288, captured=180, opens=True, differences=None, journal_rows=0,
          repeats=0, last=None, key=None):
    """One item as orphan_captures lists it."""
    return {'name': name, 'bytes': size, 'captured_at': _iso_ago(captured), 'reason': reason,
            'cv': [3, 14], 'replaced_by': {'instance_id': 'b' * 32, 'epoch': 4, 'cv': [4, 2]},
            'differences': differences if differences is not None else {'users': {'only_here': 2, 'only_there': 1}},
            'journal_rows': journal_rows,
            'key': key or {'fp': OWN_FP, 'current': True, 'backup': None},
            'seal': {'under': 'master' if not opens else 'field', 'fp': OWN_FP if opens else OTHER_FP,
                     'current': opens, 'backup': None, 'opens': opens},
            'repeats': repeats, 'last_at': _iso_ago(last) if last is not None else None}


def _two():
    full = _copy(NAME_A, REASON_A, size=12288, captured=180, journal_rows=4, repeats=3, last=300,
                 differences={'users': {'only_here': 2, 'only_there': 1}, 'clusters': {'only_here': 1, 'only_there': 0},
                              'vm_tags': {'only_here': 0, 'only_there': 0},
                              'files': ['ssh_known_hosts', 'branding/logo.png']},
                 key={'fp': OLD_FP, 'current': False, 'backup': '.pegaprox_aes256.key.pre-ha.1700000000'})
    sealed = _copy(NAME_B, REASON_B, size=2048, captured=90000, opens=False)
    return [full, sealed]


class _CopiesServer(_FakeServer):
    """The fake of test_ha_ui with the copies in the status and the banner, the config version,
    and the two routes: download (the password, 404, 409 for one that does not open) and
    dismiss (confirm, 409 HA_SYNC_RUNNING while a sync runs, 404)."""

    def __init__(self, copies=None, cv=None, over_limit=False, listed=None, busy=0, unopenable=(), **kw):
        super().__init__(**kw)
        self.copies = [dict(c) for c in (copies or [])]
        self.cv = cv
        self.over_limit = over_limit
        self.listed = listed            # the server lists the newest 50 at most
        self.busy = busy                # how many dismisses still find a sync running
        self.unopenable = set(unopenable)
        self.files = {}

    def orphans(self):
        items = self.copies if self.listed is None else self.copies[:self.listed]
        return {'count': len(self.copies), 'bytes': sum(c['bytes'] for c in self.copies),
                'over_limit': self.over_limit, 'seal': {'under': 'field', 'fp': OWN_FP},
                'items': [dict(c) for c in items]}

    def status(self):
        out = super().status()
        out['orphans'] = self.orphans()
        if self.cv is not None:
            out['config_version'] = dict(self.cv)
        return out

    def banner(self):
        out = super().banner()
        if self.copies:
            out['orphans'] = len(self.copies)
        return out

    def payload(self, name):
        return gzip.compress(json.dumps({'kind': 'pegaprox-ha-orphans', 'format': 1, 'name': name,
                                         'tables': {'users': {'columns': ['username'], 'rows': [['ops']]}}}).encode())

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/ha/orphans/([^/]+)/(download|dismiss)', path)
        if not m or not req.url.startswith(BASE) or req.method != 'POST':
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        name, what = m.group(1), m.group(2)
        known = any(c['name'] == name for c in self.copies)

        def answer(data, status=200, headers=None):
            return route.fulfill(status=status, body=json.dumps(data),
                                 headers=dict({'Content-Type': 'application/json'}, **(headers or {})))

        if what == 'download':
            # the order of the real route: a copy at all, the password, then whether it opens
            if not known:
                return answer({'error': 'There is no such copy'}, 404)
            refusal = self._reauth_refusal(body)
            if refusal:
                return answer(refusal, 403)
            if name in self.unopenable:
                return answer({'error': NOT_OPENED}, 409)
            return route.fulfill(status=200, body=self.payload(name), headers={
                'Content-Type': 'application/gzip', 'Cache-Control': 'no-store',
                'Content-Disposition': f'attachment; filename="pegaprox-ha-{name}.json.gz"'})
        if body.get('confirm') is not True:
            return answer({'error': 'Dismissing deletes the copy for good - confirm it to go ahead'}, 400)
        if not known:
            return answer({'error': 'There is no such copy'}, 404)
        if self.busy:
            self.busy -= 1
            return answer({'code': 'HA_SYNC_RUNNING', 'error': SYNC_BUSY}, 409, {'Retry-After': '10'})
        self.copies = [c for c in self.copies if c['name'] != name]
        return answer({'success': True, 'orphans': self.orphans()})


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _CopiesServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _copies_banner(app):
    return app.page.locator('[data-ha-copies-banner]')


def _open_copies(app):
    """The way an admin gets there: the button on the banner line."""
    _copies_banner(app).get_by_role('button').click()
    card = app.page.locator('[data-ha-copies]')
    card.wait_for(timeout=5000)
    return card


def _row(card, name):
    return card.locator(f'[data-ha-copy="{name}"]')


def _row_button(card, name, label):
    return _row(card, name).locator('button', has_text=label).first


def _reload(app):
    """The next poll would take ten seconds: Save on the interval reads the status again."""
    before = app.server.calls.count(('GET', '/api/ha/status'))
    app.page.locator('#pgha-interval + button').click()
    _until(app.page, lambda: app.server.calls.count(('GET', '/api/ha/status')) > before, 3)
    app.page.wait_for_timeout(300)


@pytest.mark.parametrize('role', ['standby', 'active', 'standalone'])
def test_runtime_the_list_renders_from_the_status(open_app, role):
    """Two copies, in every role: when, why, what, how often, the size, and whether it opens."""
    members = [_member('b', role='active', source=True)] if role == 'standby' else (
        [_member('b')] if role == 'active' else [])
    app = open_app(role=role, layout='modern', copies=_two(), members=members)
    card = _open_copies(app)
    assert app.page.locator(f'[data-ha-role="{role}"]').count() == 1
    assert card.get_attribute('data-ha-copies') == '2'
    head = card.inner_text()
    assert head.startswith('Changes that were not carried over'), head
    assert 'Copies: 2, 14.0 KB in total' in head
    assert ('A copy holds rows this instance held that a sync replaced with the configuration it took over. '
            'Nothing deletes a copy but its Dismiss button') in head
    assert card.locator('[data-ha-copies-over]').count() == 0
    assert card.locator('[data-ha-copies-more]').count() == 0
    # the newest first, as the server lists them
    assert card.locator('[data-ha-copy]').evaluate_all('rows => rows.map(r => r.dataset.haCopy)') == [NAME_A, NAME_B]

    a = _row(card, NAME_A)
    text = a.inner_text()
    assert a.locator('[data-ha-copy-kept]').inner_text().strip() == 'Kept 3 minutes ago'
    assert a.locator('[data-ha-copy-kept]').get_attribute('title')
    assert a.locator('[data-ha-copy-size]').inner_text().strip() == '12.0 KB'
    assert NAME_A in text
    assert a.locator('[data-ha-copy-reason]').inner_text().strip() == REASON_A
    assert a.locator('[data-ha-copy-table="users"]').inner_text().strip() == (
        'users: 2 rows only here, 1 rows only in the synced configuration')
    assert a.locator('[data-ha-copy-table="clusters"]').inner_text().strip() == 'clusters: 1 rows only here'
    # a table without a difference is no line
    assert a.locator('[data-ha-copy-table="vm_tags"]').count() == 0
    assert a.locator('[data-ha-copy-files]').inner_text().strip() == 'Files replaced: ssh_known_hosts, branding/logo.png'
    assert a.locator('[data-ha-copy-journal]').inner_text().strip() == '4 journal entries on who made these changes'
    assert a.locator('[data-ha-copy-repeats]').inner_text().strip() == '3×, last 5 minutes ago'
    assert 'Replaced again' in text
    # it opens here; the values inside are under the field key from before the join
    assert a.get_attribute('data-ha-copy-opens') == 'yes'
    assert a.locator('[data-ha-copy-sealed]').count() == 0
    assert a.locator('[data-ha-copy-key="backup"]').inner_text().strip() == (
        'Passwords and tokens in this copy are sealed under an earlier field key. Its backup is still on this '
        'instance: .pegaprox_aes256.key.pre-ha.1700000000')
    assert _row_button(card, NAME_A, 'Download').is_enabled()
    assert _row_button(card, NAME_A, 'Dismiss').is_enabled()

    b = _row(card, NAME_B)
    assert b.locator('[data-ha-copy-kept]').inner_text().strip() == 'Kept yesterday'
    assert b.locator('[data-ha-copy-size]').inner_text().strip() == '2.0 KB'
    assert b.locator('[data-ha-copy-reason]').inner_text().strip() == REASON_B
    # repeated never: no line for it
    assert b.locator('[data-ha-copy-repeats]').count() == 0
    assert b.get_attribute('data-ha-copy-opens') == 'no'
    assert b.locator('[data-ha-copy-sealed]').inner_text().strip() == (
        f'This copy is sealed under another key (fingerprint {OTHER_FP}) and cannot be opened on this instance, '
        f'so it cannot be downloaded here. This instance seals its copies under the key with the fingerprint {OWN_FP}.')
    assert b.locator('[data-ha-copy-key]').count() == 0
    assert _row_button(card, NAME_B, 'Download').is_disabled()
    assert _row_button(card, NAME_B, 'Dismiss').is_enabled()
    # nothing went out but the reads
    assert not [c for c in app.server.calls if '/orphans/' in c[1]]
    assert not app.errors, app.errors


@pytest.mark.parametrize('kind', ['zero', 'missing'])
def test_runtime_without_copies_nothing_shows(open_app, kind):
    """No copy (count 0), or a server from before stage 2 (no orphans at all): no section, no
    banner line, and the tab is as it was."""
    app = open_app(role='active', layout='modern', members=[_member('b')])
    if kind == 'missing':
        app.server.status = lambda: _FakeServer.status(app.server)
    panel = _open_ha(app, 'active')
    assert panel.locator('[data-ha-members]').count() == 1
    assert panel.locator('[data-ha-copies]').count() == 0
    assert 'Changes that were not carried over' not in panel.inner_text()
    assert _copies_banner(app).count() == 0
    assert not app.errors, app.errors


def test_runtime_copies_that_take_much_space_say_so_and_only_the_newest_are_listed(open_app):
    many = [_copy(f'3-{i}-20261002T1015{i:02d}Z-{i:012x}', REASON_A, captured=60 + i) for i in range(3)]
    app = open_app(role='standby', layout='modern', copies=many, over_limit=True, listed=2,
                   members=[_member('b', role='active', source=True)])
    card = _open_copies(app)
    assert card.locator('[data-ha-copies-over]').inner_text().strip() == (
        'The copies take up a lot of space on this instance. Review them and dismiss the ones you no longer need.')
    assert card.locator('[data-ha-copy]').count() == 2
    assert card.locator('[data-ha-copies-more]').inner_text().strip() == 'The newest 2 of 3 copies are listed here.'
    assert 'Copies: 3, 36.0 KB in total' in card.inner_text()
    assert not app.errors, app.errors


def test_runtime_download_sends_the_password_and_saves_the_file(open_app, tmp_path):
    app = open_app(role='standby', layout='modern', copies=_two(), members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Download').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="download"]')
    box.wait_for(timeout=3000)
    assert box.inner_text().startswith('The copy holds rows of this instance, accounts included')
    confirm = box.locator('button', has_text='Download')
    assert confirm.is_disabled(), 'the download must wait for the password'
    assert page.get_attribute('#pgha-copy-password', 'autocomplete') == 'current-password'
    assert not [c for c in app.server.calls if '/orphans/' in c[1]]

    # a wrong one stays at its field, and nothing is saved
    page.fill('#pgha-copy-password', 'wrong')
    downloads = []
    page.on('download', lambda d: downloads.append(d))
    confirm.click()
    note = box.locator('[data-ha-reauth="HA_REAUTH"]')
    note.wait_for(timeout=3000)
    assert 'Incorrect password' in note.inner_text()
    assert page.input_value('#pgha-copy-password') == ''
    assert page.get_attribute('#pgha-copy-password', 'aria-invalid') == 'true'
    assert confirm.is_disabled()
    assert not downloads

    page.fill('#pgha-copy-password', PASSWORD)
    with page.expect_download(timeout=5000) as info:
        confirm.click()
    download = info.value
    assert download.suggested_filename == f'pegaprox-ha-{NAME_A}.json.gz'
    target = tmp_path / download.suggested_filename
    download.save_as(str(target))
    assert json.loads(gzip.decompress(target.read_bytes()))['name'] == NAME_A
    path = f'/api/ha/orphans/{NAME_A}/download'
    assert app.server.bodies[path] == [{'user_password': 'wrong'}, {'user_password': PASSWORD}]
    assert _wait_for_toast(page, 'Copy downloaded'), _toasts(page)
    box.wait_for(state='detached', timeout=3000)
    # saved, not opened: no other page, and this one stays where it was
    assert len(app.ctx.pages) == 1 and page.url.rstrip('/') == BASE
    assert card.locator('[data-ha-copy]').count() == 2
    assert not app.errors, app.errors


def test_runtime_a_copy_that_does_not_open_says_why_in_the_servers_words(open_app):
    """The list said it opens; the server finds otherwise (the key store changed since): 409
    with the reason, at the box, and no file."""
    app = open_app(role='standby', layout='modern', copies=_two(), unopenable={NAME_A},
                   members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Download').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="download"]')
    page.fill('#pgha-copy-password', PASSWORD)
    downloads = []
    page.on('download', lambda d: downloads.append(d))
    box.locator('button', has_text='Download').click()
    error = box.locator('[data-ha-copy-error]')
    error.wait_for(timeout=3000)
    assert error.inner_text().strip() == NOT_OPENED
    assert box.locator('[data-ha-reauth]').count() == 0
    page.wait_for_timeout(500)
    assert not downloads
    # Cancel closes the box and its words
    box.locator('button', has_text='Cancel').click()
    box.wait_for(state='detached', timeout=3000)
    assert card.locator('[data-ha-copy-error]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_copy_dismissed_elsewhere_leaves_the_list(open_app):
    app = open_app(role='standby', layout='modern', copies=_two(), members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Download').click()
    page.fill('#pgha-copy-password', PASSWORD)
    # another admin dismissed it in the meantime
    app.server.copies = [c for c in app.server.copies if c['name'] != NAME_A]
    _row(card, NAME_A).locator('[data-ha-copy-box] button', has_text='Download').click()
    assert _wait_for_toast(page, 'There is no such copy'), _toasts(page)
    _row(card, NAME_A).wait_for(state='detached', timeout=3000)
    assert card.get_attribute('data-ha-copies') == '1'
    assert not app.errors, app.errors


@pytest.mark.parametrize('stale', [False, True])
def test_runtime_an_sso_account_downloads_without_a_password(open_app, stale):
    """No password to type: the click sends nothing but the request. A sign-in older than ten
    minutes is refused, and only then the box shows, with the way to sign in again."""
    app = open_app(role='standby', layout='modern', copies=_two(), auth_source='oidc', sso_stale=stale,
                   members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    assert card.locator('input[type="password"]').count() == 0
    path = f'/api/ha/orphans/{NAME_A}/download'
    if not stale:
        with page.expect_download(timeout=5000) as info:
            _row_button(card, NAME_A, 'Download').click()
        assert info.value.suggested_filename == f'pegaprox-ha-{NAME_A}.json.gz'
        assert app.server.bodies[path] == [{}]
        assert card.locator('[data-ha-copy-box]').count() == 0
    else:
        _row_button(card, NAME_A, 'Download').click()
        note = card.locator('[data-ha-copy-box="download"] [data-ha-reauth="HA_REAUTH_RECENT"]')
        note.wait_for(timeout=3000)
        assert 'older than 10 minutes' in note.inner_text()
        assert note.get_by_role('button', name='Sign in again').count() == 1
        assert card.locator('#pgha-copy-password').count() == 0
        assert app.server.bodies[path] == [{}]
    assert not app.errors, app.errors


def test_runtime_dismiss_confirms_and_removes_the_row(open_app):
    """The box says it is for good; Cancel sends nothing. Each dismiss sends confirm, the row goes,
    the count and the banner line follow, and with the last copy the section goes too."""
    app = open_app(role='active', layout='modern', copies=_two(), members=[_member('b')])
    page = app.page
    assert _copies_banner(app).get_attribute('data-ha-copies-count') == '2'
    card = _open_copies(app)
    _row_button(card, NAME_B, 'Dismiss').click()
    box = _row(card, NAME_B).locator('[data-ha-copy-box="dismiss"]')
    box.wait_for(timeout=3000)
    assert box.inner_text().startswith('Dismissing deletes this copy for good, and it cannot be brought back.')
    box.locator('button', has_text='Cancel').click()
    box.wait_for(state='detached', timeout=3000)
    assert not [c for c in app.server.calls if c[1].endswith('/dismiss')]

    _row_button(card, NAME_B, 'Dismiss').click()
    box.locator('button', has_text='Delete for good').click()
    assert _wait_for_toast(page, 'Copy dismissed'), _toasts(page)
    _row(card, NAME_B).wait_for(state='detached', timeout=3000)
    assert app.server.bodies[f'/api/ha/orphans/{NAME_B}/dismiss'] == [{'confirm': True}]
    assert card.get_attribute('data-ha-copies') == '1'
    assert 'Copies: 1, 12.0 KB in total' in card.inner_text()
    # the banner reads the count again
    assert _until(page, lambda: _copies_banner(app).get_attribute('data-ha-copies-count') == '1')
    assert _copies_banner(app).inner_text().strip().startswith(
        '1 copy of changes that were not carried over - review it in Settings > High Availability')

    _row_button(card, NAME_A, 'Dismiss').click()
    _row(card, NAME_A).locator('button', has_text='Delete for good').click()
    page.locator('[data-ha-copies]').wait_for(state='detached', timeout=3000)
    assert _until(page, lambda: _copies_banner(app).count() == 0)
    assert page.locator('[data-ha-role="active"] [data-ha-members]').count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('change', ['gone', 'same'])
def test_runtime_a_banner_count_from_before_is_read_again_with_the_list(open_app, change):
    """On a leader nothing polls the banner. Another admin dismissed a copy since this page
    loaded: opening the list reads the banner again, and it says one. The same count asks
    nothing (the counterproof)."""
    app = open_app(role='active', layout='modern', copies=_two(), members=[_member('b')])
    page = app.page
    if change == 'gone':
        app.server.copies = app.server.copies[:1]
    assert _copies_banner(app).get_attribute('data-ha-copies-count') == '2'
    checks = app.server.calls.count(('GET', '/api/auth/check'))
    card = _open_copies(app)
    if change == 'gone':
        assert _until(page, lambda: _copies_banner(app).get_attribute('data-ha-copies-count') == '1')
        assert card.get_attribute('data-ha-copies') == '1'
        assert app.server.calls.count(('GET', '/api/auth/check')) == checks + 1
    else:
        page.wait_for_timeout(800)
        assert app.server.calls.count(('GET', '/api/auth/check')) == checks
        assert _copies_banner(app).get_attribute('data-ha-copies-count') == '2'
    assert not app.errors, app.errors


def test_runtime_dismiss_during_a_sync_says_so_and_works_the_next_time(open_app):
    app = open_app(role='standby', layout='modern', copies=_two(), busy=1,
                   members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Dismiss').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="dismiss"]')
    box.locator('button', has_text='Delete for good').click()
    note = box.locator('[data-ha-copy-error="HA_SYNC_RUNNING"]')
    note.wait_for(timeout=3000)
    # translated, not the server's English
    assert note.inner_text().strip() == 'A sync is running right now. The copy is still here, try again in a moment.'
    assert card.get_attribute('data-ha-copies') == '2'
    assert box.is_visible()
    box.locator('button', has_text='Delete for good').click()
    _row(card, NAME_A).wait_for(state='detached', timeout=3000)
    assert app.server.bodies[f'/api/ha/orphans/{NAME_A}/dismiss'] == [{'confirm': True}, {'confirm': True}]
    assert not app.errors, app.errors


def test_runtime_a_poll_already_on_its_way_does_not_bring_a_dismissed_copy_back(open_app):
    app = open_app(role='active', layout='modern', copies=_two(), members=[_member('b')])
    page = app.page
    card = _open_copies(app)
    # a status request that leaves now, while both copies are there, and is answered late
    app.server.hold_status = True
    page.locator('#pgha-interval + button').click()
    assert _until(page, lambda: len(app.server.held) == 1, 3)
    assert len(app.server.held[0][1]['orphans']['items']) == 2
    app.server.hold_status = False
    _row_button(card, NAME_B, 'Dismiss').click()
    _row(card, NAME_B).locator('button', has_text='Delete for good').click()
    _row(card, NAME_B).wait_for(state='detached', timeout=3000)
    assert _until(page, lambda: app.server.calls.count(('GET', '/api/ha/status')) >= 3, 3)
    page.wait_for_timeout(300)
    app.server.release()
    page.wait_for_timeout(800)
    assert _row(card, NAME_B).count() == 0, 'an answer sent before the dismiss brought the copy back'
    assert card.get_attribute('data-ha-copies') == '1'
    # a later answer still shows a copy that is new
    app.server.copies.append(_copy('4-1-20261003T000000Z-ffffffffffff', REASON_A, captured=5))
    _reload(app)
    assert _until(page, lambda: card.get_attribute('data-ha-copies') == '2')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout,kind', [('modern', 'classic'), ('corporate', 'classic'), ('cloud', 'cloud')])
@pytest.mark.parametrize('admin', [True, False])
def test_runtime_the_banner_line_shows_for_an_admin_only(open_app, layout, kind, admin):
    """On a leader, so the standby banner is not there to lead the way: the line alone opens the tab."""
    app = open_app(role='active', layout=layout, admin=admin, copies=_two(), members=[_member('b')])
    line = _copies_banner(app)
    if not admin:
        assert line.count() == 0
        assert 'not carried over' not in app.page.locator('body').inner_text()
        assert not app.errors, app.errors
        return
    assert line.get_attribute('data-ha-copies-banner') == kind
    assert line.inner_text().strip().startswith(
        '2 copies of changes that were not carried over - review them in Settings > High Availability')
    assert app.page.locator('[data-ha-banner]').count() == 0
    if layout == 'modern':
        # above the header, where the other banners sit
        assert app.page.evaluate('() => !!(document.querySelector("[data-ha-copies-banner]").compareDocumentPosition('
                                 'document.querySelector("header")) & Node.DOCUMENT_POSITION_FOLLOWING)')
    elif layout == 'cloud':
        assert app.page.locator('.cloud-content [data-ha-copies-banner="cloud"]').count() == 1
    card = _open_copies(app)
    assert card.locator('[data-ha-copy]').count() == 2
    assert not app.errors, app.errors


def test_runtime_the_line_follows_the_standby_banner(open_app):
    app = open_app(role='standby', layout='modern', copies=_two()[:1], members=[_member('b', role='active', source=True)])
    page = app.page
    assert page.locator('[data-ha-banner="classic"]').is_visible()
    assert _copies_banner(app).inner_text().strip().startswith('1 copy of changes that were not carried over')
    assert page.evaluate('() => !!(document.querySelector("[data-ha-banner]").compareDocumentPosition('
                         'document.querySelector("[data-ha-copies-banner]")) & Node.DOCUMENT_POSITION_FOLLOWING)')
    _open_copies(app)
    assert not app.errors, app.errors


def _cv(epoch, count, by, at=600, joined=False):
    return {'cv': [epoch, count], 'segment': 'c' * 16 if by else None, 'by': by, 'base_cv': [epoch, 0],
            'at': _iso_ago(at) if at is not None else None, 'etag_known': True, 'joined': joined}


@pytest.mark.parametrize('role', ['active', 'standby'])
def test_runtime_the_config_version_on_the_leader_and_a_member(open_app, role):
    """The same version on both, so an admin can compare: who stepped it (this instance on the
    leader, the leader's address on a member) and when."""
    if role == 'active':
        app = open_app(role='active', layout='modern', members=[_member('b')], cv=_cv(3, 14, OWN, at=600))
        who = 'this instance'
    else:
        app = open_app(role='standby', layout='modern', cv=_cv(3, 14, 'b' * 32, at=600),
                       members=[_member('b', role='active', source=True)])
        who = 'https://pegaprox-b.example:5000'
    panel = _open_ha(app, role)
    cv = panel.locator('[data-ha-cv]')
    assert cv.get_attribute('data-ha-cv') == '3.14'
    assert cv.inner_text().strip() == f'Configuration version: 3.14 · last changed by {who} · 10 minutes ago'
    assert cv.get_attribute('title') == (
        'Counts the changes of the configuration the group shares, as epoch.count. A member is in step with its '
        'leader when both show the same version.')
    # in the head card, next to the epoch and the instance
    assert 'Epoch: 2' in panel.locator('[data-ha-cv]').locator('xpath=..').inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('case,want', [('joined', 'arrives with the first sync'), ('none', 'not counted yet'),
                                       ('stranger', 'last changed by dddddddd')])
def test_runtime_a_version_not_counted_yet_or_from_elsewhere(open_app, case, want):
    cv = {'joined': _cv(0, 0, None, at=None, joined=True), 'none': _cv(0, 0, None, at=None),
          'stranger': _cv(5, 2, 'd' * 32, at=None)}[case]
    app = open_app(role='standby', layout='modern', cv=cv, members=[_member('b', role='active', source=True)])
    panel = _open_ha(app, 'standby')
    node = panel.locator('[data-ha-cv]')
    assert node.get_attribute('data-ha-cv') == {'joined': 'joined', 'none': 'none', 'stranger': '5.2'}[case]
    assert want in node.inner_text()
    if case != 'stranger':
        assert 'last changed' not in node.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_standalone_shows_no_version(open_app):
    app = open_app(role='standalone', layout='modern', cv=_cv(3, 14, OWN))
    panel = _open_ha(app, 'standalone')
    assert panel.locator('[data-ha-cv]').count() == 0
    assert 'Configuration version' not in panel.inner_text()
    assert not app.errors, app.errors


DOLLARS = "$&$`$'"


def test_runtime_server_words_with_dollar_signs_show_as_sent(open_app):
    """$& stands for the placeholder in a replacement string, $` and $' for the text before and
    after it: a leader address, a fingerprint or a file name with them showed something else."""
    url = 'https://pegaprox-b.example:5000/' + DOLLARS
    sealed = _copy(NAME_B, REASON_B, opens=False)
    sealed['seal']['fp'] = 'fp' + DOLLARS
    backup = '.pegaprox_aes256.key.' + DOLLARS
    full = _copy(NAME_A, REASON_A, key={'fp': OLD_FP, 'current': False, 'backup': backup})
    app = open_app(role='standby', layout='modern', copies=[full, sealed], cv=_cv(3, 14, 'b' * 32, at=600),
                   members=[dict(_member('b', role='active', source=True), url=url)])
    orphans = app.server.orphans
    app.server.orphans = lambda: dict(orphans(), seal={'under': 'field', 'fp': 'own' + DOLLARS})
    card = _open_copies(app)
    assert app.page.locator('[data-ha-cv]').inner_text().strip() == (
        f'Configuration version: 3.14 · last changed by {url} · 10 minutes ago')
    assert _row(card, NAME_B).locator('[data-ha-copy-sealed]').inner_text().strip() == (
        f'This copy is sealed under another key (fingerprint fp{DOLLARS}) and cannot be opened on this instance, '
        f'so it cannot be downloaded here. This instance seals its copies under the key with the fingerprint '
        f'own{DOLLARS}.')
    assert _row(card, NAME_A).locator('[data-ha-copy-key="backup"]').inner_text().strip().endswith(
        f'Its backup is still on this instance: {backup}')
    assert not app.errors, app.errors


# -- runtime: in a second language ---------------------------------------------------------------------

GERMAN = {
    'banner': '2 Kopien von Änderungen, die nicht übernommen wurden - prüfen Sie sie unter Einstellungen > '
              'Hochverfügbarkeit',
    'title': 'Änderungen, die nicht übernommen wurden',
    'total': 'Kopien: 2, insgesamt 14.0 KB',
    'kept': 'Aufbewahrt vor 3 Minuten',
    'users': 'users: 2 Zeilen nur hier, 1 Zeilen nur in der synchronisierten Konfiguration',
    'files': 'Ersetzte Dateien: ssh_known_hosts, branding/logo.png',
    'journal': '4 Journaleinträge dazu, wer diese Änderungen gemacht hat',
    'repeats': '3×, zuletzt vor 5 Minuten',
    'sealed': f'Diese Kopie ist mit einem anderen Schlüssel versiegelt (Fingerabdruck {OTHER_FP})',
    'cv': 'Konfigurationsversion: 3.14 · zuletzt geändert von https://pegaprox-b.example:5000 · vor 10 Minuten',
    'download': 'Die Kopie enthält Zeilen dieser Instanz, auch Konten.',
    'dismiss': 'Verwerfen löscht diese Kopie endgültig, sie lässt sich nicht wiederherstellen.',
    'busy': 'Gerade läuft eine Synchronisierung. Die Kopie ist noch da, versuchen Sie es gleich noch einmal.',
}


def _visible_texts(page, within='body'):
    """innerText and every title under `within`: where a raw key would show. The HA tab and
    the banner line for English left over, the whole page for a key."""
    return page.evaluate('''(sel) => Array.from(document.querySelectorAll(sel)).flatMap(root => [root.innerText,
        ...Array.from(root.querySelectorAll('[title]')).map(e => e.getAttribute('title'))]).join('\\n')''', within)


OURS = '[data-ha-role], [data-ha-copies-banner]'
# what the runtime tests below put on screen word for word, without a placeholder
SHOWN_WHOLE = ('haCopiesTitle', 'haCopiesIntro', 'haCopiesReason', 'haCopiesContent', 'haCopiesFiles',
               'haCopiesRepeated', 'haCopiesDownload', 'haCopiesDismiss', 'haCopiesDownloadDesc',
               'haCopiesDismissDesc', 'haCopiesDismissConfirm', 'haCopiesSyncRunning', 'haCvLabel', 'haCvHint')


def _text(block, key):
    """The text of `key` in a language block as the page shows it, None when it is not there."""
    m = re.search(r"^ +%s: '(.*)',$" % key, block, re.M)
    return m.group(1).replace("\\'", "'") if m else None


def test_runtime_everything_speaks_german(open_app):
    app = open_app(role='standby', layout='modern', language='de', copies=_two(), busy=1,
                   cv=_cv(3, 14, 'b' * 32, at=600), members=[_member('b', role='active', source=True)])
    page = app.page
    assert _copies_banner(app).inner_text().strip().startswith(GERMAN['banner'])
    assert _copies_banner(app).get_by_role('button', name='Hochverfügbarkeit').count() == 1
    card = _open_copies(app)
    text = card.inner_text()
    for key in ('title', 'total'):
        assert GERMAN[key] in text, (key, text)
    a = _row(card, NAME_A)
    assert a.locator('[data-ha-copy-kept]').inner_text().strip() == GERMAN['kept']
    assert a.locator('[data-ha-copy-table="users"]').inner_text().strip() == GERMAN['users']
    assert a.locator('[data-ha-copy-files]').inner_text().strip() == GERMAN['files']
    assert a.locator('[data-ha-copy-journal]').inner_text().strip() == GERMAN['journal']
    assert a.locator('[data-ha-copy-repeats]').inner_text().strip() == GERMAN['repeats']
    for label in ('Grund', 'Inhalt', 'Erneut ersetzt'):
        assert label in a.inner_text(), label
    assert GERMAN['sealed'] in _row(card, NAME_B).locator('[data-ha-copy-sealed]').inner_text()
    assert page.locator('[data-ha-cv]').inner_text().strip() == GERMAN['cv']

    _row_button(card, NAME_A, 'Herunterladen').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="download"]')
    assert box.inner_text().startswith(GERMAN['download'])
    assert 'Ihr Passwort zur Bestätigung' in box.inner_text()
    box.locator('button', has_text='Abbrechen').click()
    _row_button(card, NAME_A, 'Verwerfen').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="dismiss"]')
    assert box.inner_text().startswith(GERMAN['dismiss'])
    box.locator('button', has_text='Endgültig löschen').click()
    note = box.locator('[data-ha-copy-error="HA_SYNC_RUNNING"]')
    note.wait_for(timeout=3000)
    assert note.inner_text().strip() == GERMAN['busy']
    # no key and no English left over, titles included
    shown = _visible_texts(page)
    assert not re.search(r'\b(haCopies|haCv)\w*', shown), re.findall(r'\b(?:haCopies|haCv)\w*', shown)
    ours = _visible_texts(page, OURS)
    assert GERMAN['title'] in ours
    for english in ('Changes that were not carried over', 'Configuration version', 'Dismiss', 'Kept ',
                    'rows only here', 'Files replaced', 'Counts the changes'):
        assert english not in ours, english
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', [lang for lang in LANGS if lang not in ('en', 'de')])
def test_runtime_no_key_shows_raw_in_any_language(open_app, lang):
    """Every text of the section, both boxes, the version and the banner line, read in the
    browser: t() hands back the key itself on a miss, so a gap would show as haCopies..."""
    app = open_app(role='standby', layout='modern', language=lang, copies=_two(), busy=1,
                   cv=_cv(3, 14, 'b' * 32, at=600), members=[_member('b', role='active', source=True)])
    page = app.page
    card = _open_copies(app)
    _row(card, NAME_A).locator('button').first.click()     # the box of the download
    _row(card, NAME_A).locator('[data-ha-copy-box="download"]').wait_for(timeout=3000)
    shown, ours = _visible_texts(page), _visible_texts(page, OURS)
    _row(card, NAME_A).locator('button').nth(1).click()    # the dismiss box replaces it
    box = _row(card, NAME_A).locator('[data-ha-copy-box="dismiss"]')
    box.wait_for(timeout=3000)
    box.locator('button').first.click()
    box.locator('[data-ha-copy-error="HA_SYNC_RUNNING"]').wait_for(timeout=3000)
    shown += _visible_texts(page)
    ours += _visible_texts(page, OURS)
    assert not re.search(r'\b(haCopies|haCv)\w*', shown), (lang, re.findall(r'\b(?:haCopies|haCv)\w*', shown))
    # t() falls back to English before the key: no English text on screen (the longest first,
    # so a sentence that fell back is named by its own key), and each one this language's own
    blocks = _blocks()
    for key in sorted(SHOWN_WHOLE, key=lambda k: -len(_text(blocks['en'], k))):
        assert _text(blocks['en'], key) not in ours, (lang, key, 'shows in English')
    for key in SHOWN_WHOLE:
        own = _text(blocks[lang], key)
        assert own and own in ours, (lang, key, own)
    assert not app.errors, app.errors


# -- runtime: a status the list does not expect, and answers that are no file -----------------------

UNSET = object()

# the passwords of the HaPanel, read from its hooks: what stays in React state after a request
PANEL_PASSWORDS_JS = '''() => {
    const root = document.getElementById('root')._reactRootContainer;
    if (!root) return null;
    const stack = [root.current];
    while (stack.length) {
        const f = stack.pop();
        if (typeof f.type === 'function' && f.type.name === 'HaPanel') {
            for (let h = f.memoizedState; h; h = h.next) {
                const s = h.memoizedState;
                if (s && typeof s === 'object' && 'copy' in s && 'confirm' in s && 'join' in s) return s.copy;
            }
            return null;
        }
        if (f.sibling) stack.push(f.sibling);
        if (f.child) stack.push(f.child);
    }
    return null;
}'''


class _OddServer(_CopiesServer):
    """The copies fake with the orphans and the config version sent as given, wrong types
    included, and answers for the download queued ahead of the route: (status, body, headers)
    or 'abort' for a request that gets no answer."""

    def __init__(self, raw_orphans=UNSET, raw_cv=UNSET, download=(), **kw):
        super().__init__(**kw)
        self.raw_orphans, self.raw_cv = raw_orphans, raw_cv
        self.download_q = list(download)

    def status(self):
        out = super().status()
        if self.raw_orphans is not UNSET:
            out['orphans'] = self.raw_orphans
        if self.raw_cv is not UNSET:
            out['config_version'] = self.raw_cv
        return out

    def banner(self):
        out = super().banner()
        if self.raw_orphans is not UNSET:
            out['orphans'] = 2
        return out

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not (self.download_q and req.method == 'POST' and req.url.startswith(BASE)
                and re.fullmatch(r'/api/ha/orphans/[^/]+/download', path)):
            return super().handle(route)
        self.calls.append((req.method, path))
        self.bodies.setdefault(path, []).append(json.loads(req.post_data or '{}'))
        answer = self.download_q.pop(0)
        if answer == 'abort':
            return route.abort('connectionrefused')
        status, body, headers = answer
        if not isinstance(body, str):
            body, headers = json.dumps(body), {'Content-Type': 'application/json'}
        return route.fulfill(status=status, body=body, headers=headers)


@pytest.fixture
def open_odd(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standby')
        kw.setdefault('layout', 'modern')
        kw.setdefault('members', [_member('b', role='active', source=True)])
        app = _App(browser, _OddServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _alive(app):
    return app.page.evaluate('() => !!(document.querySelector("header") || document.querySelector(".cloud-shell"))'
                             ' && document.getElementById("root").childElementCount > 0')


def _orphans(items):
    return {'count': len(items), 'bytes': 14336, 'over_limit': False, 'seal': {'under': 'field', 'fp': OWN_FP},
            'items': items}


@pytest.mark.parametrize('item', ['no-name', 'empty'])
def test_runtime_a_copy_without_a_name_is_left_out(open_odd, item):
    """Next to a good one: opening the list unmounted the whole app (copyBox read
    copyAction.what with no box open and c.name undefined)."""
    good = _two()[0]
    bad = {k: v for k, v in good.items() if k != 'name'} if item == 'no-name' else {}
    app = open_odd(raw_orphans=_orphans([good, bad]))
    card = _open_copies(app)
    app.page.wait_for_timeout(500)
    assert _alive(app)
    assert card.locator('[data-ha-copy]').evaluate_all('rows => rows.map(r => r.dataset.haCopy)') == [NAME_A]
    # the one with a name works as before
    _row_button(card, NAME_A, 'Dismiss').click()
    _row(card, NAME_A).locator('[data-ha-copy-box="dismiss"]').wait_for(timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('case', ['null-item', 'string-item', 'object-name', 'object-reason', 'number-by',
                                  'object-by'])
def test_runtime_fields_of_the_wrong_type_do_not_take_the_page_down(open_odd, case):
    items = _two()
    cv = _cv(3, 14, 'b' * 32)
    if case == 'null-item':
        items.insert(0, None)
    elif case == 'string-item':
        items.insert(0, 'x')
    elif case == 'object-name':
        items[1]['name'] = {'n': 1}
    elif case == 'object-reason':
        items[0]['reason'] = {'text': 'x'}
    elif case == 'number-by':
        cv['by'] = 12345
    else:
        cv['by'] = {'id': 'x'}
    app = open_odd(raw_orphans=_orphans(items), raw_cv=cv)
    card = _open_copies(app)
    app.page.wait_for_timeout(500)
    assert _alive(app) and app.page.locator('[data-ha-role="standby"]').count() == 1
    rows = card.locator('[data-ha-copy]').evaluate_all('rows => rows.map(r => r.dataset.haCopy)')
    assert rows == ([NAME_A] if case == 'object-name' else [NAME_A, NAME_B]), rows
    reason = _row(card, NAME_A).locator('[data-ha-copy-reason]').inner_text().strip()
    assert reason == ('-' if case == 'object-reason' else REASON_A)
    version = app.page.locator('[data-ha-cv]')
    assert version.get_attribute('data-ha-cv') == '3.14'
    if case.endswith('-by'):
        assert 'last changed by' not in version.inner_text()
    else:
        assert 'last changed by https://pegaprox-b.example:5000' in version.inner_text()
    assert not app.errors, app.errors


DOWNLOAD_FAILURES = {
    'conflict': (409, {'error': NOT_OPENED}, None),
    'server': (500, '<html><body>Internal Server Error</body></html>', {'Content-Type': 'text/html'}),
    'network': 'abort',
}


@pytest.mark.parametrize('kind', list(DOWNLOAD_FAILURES))
def test_runtime_the_password_goes_with_a_failed_download(open_odd, kind):
    """A refused password emptied the field; a 409, a 500 or no answer left the password in
    the panel's state for as long as the box stayed open."""
    app = open_odd(copies=_two(), download=[DOWNLOAD_FAILURES[kind]])
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Download').click()
    box = _row(card, NAME_A).locator('[data-ha-copy-box="download"]')
    box.wait_for(timeout=3000)
    page.fill('#pgha-copy-password', PASSWORD)
    assert page.evaluate(PANEL_PASSWORDS_JS) == PASSWORD
    downloads = []
    page.on('download', lambda d: downloads.append(d))
    box.locator('button', has_text='Download').click()
    assert _until(page, lambda: app.server.download_q == [] and page.evaluate(PANEL_PASSWORDS_JS) == '', 5)
    assert page.input_value('#pgha-copy-password') == ''
    assert not downloads
    if kind == 'conflict':
        assert box.locator('[data-ha-copy-error]').inner_text().strip() == NOT_OPENED
    # the box stays for the next try, which wants the password again
    assert box.locator('button', has_text='Download').is_disabled()
    page.fill('#pgha-copy-password', PASSWORD)
    with page.expect_download(timeout=8000):
        box.locator('button', has_text='Download').click()
    assert app.server.bodies[f'/api/ha/orphans/{NAME_A}/download'] == [{'user_password': PASSWORD}] * 2
    assert not app.errors, app.errors


def test_runtime_a_box_whose_copy_goes_closes_and_forgets_the_password(open_odd):
    app = open_odd(copies=_two())
    page = app.page
    card = _open_copies(app)
    _row_button(card, NAME_A, 'Download').click()
    _row(card, NAME_A).locator('[data-ha-copy-box="download"]').wait_for(timeout=3000)
    page.fill('#pgha-copy-password', PASSWORD)
    # dismissed by another admin: the next read no longer lists it
    app.server.copies = app.server.copies[1:]
    _reload(app)
    _row(card, NAME_A).wait_for(state='detached', timeout=5000)
    assert _until(page, lambda: page.evaluate(PANEL_PASSWORDS_JS) == '', 3)
    assert page.locator('#pgha-copy-password').count() == 0
    # the copy that is still there opens a box of its own, empty
    _row_button(card, NAME_B, 'Dismiss').click()
    _row(card, NAME_B).locator('[data-ha-copy-box="dismiss"]').wait_for(timeout=3000)
    assert not app.errors, app.errors
