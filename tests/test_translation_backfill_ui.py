"""Strings the UI asks for in every language, not just English and Polish.

The ESXi server form, the ESXi VM views and the PBS views were translated to English and
Polish only, so the seven other languages showed English there. apply, confirm and info
were defined in Portuguese alone: t() falls back to the key, not to the `|| 'Apply'` next
to the call, so every other language showed the raw word "apply". The tenant hint under
the user's tenant was missing in six languages and said something else in Portuguese.

Source checks read web/src/translations.js; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py and skip where Playwright
is not installed. LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, ESXI_READS, SSE_TOKEN, VM, VM_CONFIG, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEY_LINE = re.compile(r"^ {16}('?)([A-Za-z0-9_.]+)\1\s*:")

# a sample of the backfilled keys from each of the four views
ESXI_FORM = ['editEsxiServer', 'passwordUnchangedPlaceholder', 'connectionSuccessful', 'esxiNetworksTab',
             'esxiTasksEventsTab', 'esxiSearchVms', 'esxiGuestOs', 'esxiNoVmsFound']
ESXI_VM = ['backToVmList', 'vmInformation', 'guestTools', 'powerState', 'thinProvisioned',
           'vmPoweredOnConfigWarning', 'hardwareOverviewReadOnly', 'noSnapshotsCreateHint']
PBS_FORM = ['editPbsServer', 'pbsAuthMethodHint', 'apiTokenId', 'pbsSshOptionalTitle', 'pbsConnectionSuccessful']
PBS_VIEW = ['pbsConnected', 'pbsHealthTooltip', 'pbsGarbageCollection', 'pbsKeepLast', 'pbsRestoreTestDesc',
            'pbsEncryptionKeyDesc', 'pbsJsonEnvelopeInstruction', 'pbsPrunePermanentWarning']
GENERIC = ['apply', 'confirm', 'info', 'tenantAutoHint', 'nodeUiSuffix', 'nodeUiSuffixHint']
SAMPLE = ESXI_FORM + ESXI_VM + PBS_FORM + PBS_VIEW + GENERIC


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    """{lang: {key: [raw value, ...]}}, every definition of a key in that language's block."""
    lines = _read('web', 'src', 'translations.js').split('\n')
    starts = [(i, m.group(1)) for i, line in enumerate(lines)
              for m in [re.match(r'^ {12}([a-z]{2}): \{$', line)] if m]
    out = {}
    for n, (i, lang) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        keys = {}
        for line in lines[i + 1:end]:
            m = KEY_LINE.match(line)
            if m:
                keys.setdefault(m.group(2), []).append(line[m.end():].strip())
        out[lang] = keys
    return out


def _used():
    code = ''
    for name in sorted(os.listdir(os.path.join(ROOT, 'web', 'src'))):
        if name.endswith('.js') and name != 'translations.js':
            code += _read('web', 'src', name)
    return set(re.findall(r"""\bt\(\s*['"]([A-Za-z0-9_.]+)['"]""", code))


# --- source --------------------------------------------------------------------------------

def test_the_nine_languages_are_there():
    assert sorted(_blocks()) == sorted(LANGS)


def test_a_key_the_ui_asks_for_is_in_every_language():
    """A key defined in one language but not in another shows English there, or the key
    itself when English lacks it too."""
    blocks = _blocks()
    defined = set().union(*(set(b) for b in blocks.values()))
    gaps = {key: [lang for lang in LANGS if key not in blocks[lang]]
            for key in sorted(_used() & defined)}
    gaps = {key: langs for key, langs in gaps.items() if langs}
    assert not gaps, f'{len(gaps)} keys missing in some languages: {dict(list(gaps.items())[:20])}'


@pytest.mark.parametrize('lang', LANGS)
def test_the_backfilled_keys_are_there_once(lang):
    block = _blocks()[lang]
    for key in SAMPLE:
        assert len(block.get(key, [])) == 1, f'{key} is {len(block.get(key, []))} times in {lang}'


def test_placeholders_and_markup_survive():
    blocks = _blocks()
    tokens = re.compile(r'\{[A-Za-z_]+\}|<[^<>\s]+>')
    for key in SAMPLE:
        want = sorted(tokens.findall(blocks['en'][key][0]))
        for lang in LANGS:
            got = sorted(tokens.findall(blocks[lang][key][0]))
            if key == 'nodeUiSuffixHint' and lang in ('fr', 'es', 'pt', 'it'):
                # these name the parts of the host name in their own words
                assert len(got) == len(want), (lang, key, got)
                continue
            assert got == want, (lang, key, got)


def test_no_em_dash_in_the_backfill():
    blocks = _blocks()
    for key in SAMPLE:
        for lang in ('de', 'zh', 'fr', 'es', 'pt', 'ko', 'it'):
            assert '\u2014' not in blocks[lang][key][0], (lang, key)


def test_the_generic_buttons_are_words_not_keys():
    blocks = _blocks()
    for key in ('apply', 'confirm', 'info'):
        for lang in LANGS:
            value = blocks[lang][key][0].strip(",'\"")
            assert value and value != key, (lang, key, value)


def test_the_tenant_hint_speaks_of_the_role():
    """The hint sits under the tenant of a new user: a tenant role sets it. Portuguese said
    that new clusters go to this tenant, which is a different setting."""
    role = {'de': 'Rolle', 'en': 'role', 'zh': '角色', 'pl': 'roli', 'fr': 'rôle', 'es': 'rol',
            'pt': 'função', 'ko': '역할', 'it': 'ruolo'}
    blocks = _blocks()
    for lang in LANGS:
        value = blocks[lang]['tenantAutoHint'][0]
        assert role[lang] in value, (lang, value)
        assert 'cluster' not in value.lower(), (lang, value)
    assert "t('tenantAutoHint')" in _read('web', 'src', 'settings_modal.js')


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('ESXi-Server bearbeiten', 'PBS-Verschlüsselungsschlüssel', '작업 및 이벤트',
                   'Set automatically when you pick a tenant role'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

WORDS = {
    'de': {'esxiNetworksTab': 'Netzwerke', 'esxiTasksEventsTab': 'Aufgaben & Ereignisse',
           'esxiSearchVms': 'VMs suchen...', 'esxiGuestOs': 'Gast-OS', 'vmInformation': 'VM-Informationen',
           'powerState': 'Betriebszustand', 'poweredOn': 'AN', 'editEsxiServer': 'ESXi-Server bearbeiten',
           'passwordUnchangedPlaceholder': '(unverändert)', 'testConnection': 'Verbindung testen',
           'connectionSuccessful': 'Verbindung erfolgreich!', 'resources': 'Ressourcen',
           'configuration': 'Konfiguration', 'apply': 'Übernehmen'},
    'ko': {'esxiNetworksTab': '네트워크', 'esxiTasksEventsTab': '작업 및 이벤트',
           'esxiSearchVms': 'VM 검색...', 'esxiGuestOs': '게스트 OS', 'vmInformation': 'VM 정보',
           'powerState': '전원 상태', 'poweredOn': '켜짐', 'editEsxiServer': 'ESXi 서버 편집',
           'passwordUnchangedPlaceholder': '(변경 안 함)', 'testConnection': '연결 테스트',
           'connectionSuccessful': '연결에 성공했습니다!', 'resources': '리소스',
           'configuration': '구성', 'apply': '적용'},
}
TEST_OK = {('POST', '/api/vmware/test-connection'): (200, {'success': True})}
# the app, not the bundle's own script text
TEXT_JS = '() => document.getElementById("root").textContent'


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('lang', ['de', 'ko'])
def test_runtime_the_esxi_views_speak_the_language(open_app, lang):
    w = WORDS[lang]
    app = open_app(layout='modern', language=lang, extra={**ESXI_READS, **SSE_TOKEN, **TEST_OK})
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    for key in ('esxiNetworksTab', 'esxiTasksEventsTab'):
        assert page.locator('button', has_text=w[key]).count() >= 1, key
    assert page.locator(f'input[placeholder="{w["esxiSearchVms"]}"]').count() == 1
    text = page.evaluate(TEXT_JS)
    assert w['esxiGuestOs'] in text
    for english in ('Tasks & Events', 'Search VMs...', 'Guest OS'):
        assert english not in text, english

    # the guest: its facts and the power badge
    page.get_by_text('legacy01').first.click()
    page.get_by_text(w['vmInformation']).first.wait_for(timeout=5000)
    text = page.evaluate(TEXT_JS)
    for key in ('powerState', 'poweredOn'):
        assert w[key] in text, key
    assert 'VM Information' not in text and 'Power State' not in text

    # the server form: title, the kept password, the connection test
    page.locator('[data-esxi-edit]').first.click()
    dialog = page.locator('div.fixed', has_text=w['editEsxiServer']).last
    dialog.wait_for(timeout=3000)
    assert dialog.locator(f'input[placeholder="{w["passwordUnchangedPlaceholder"]}"]').count() == 1
    dialog.locator('button', has_text=w['testConnection']).click()
    dialog.get_by_text(w['connectionSuccessful']).wait_for(timeout=3000)
    assert 'Edit ESXi Server' not in dialog.text_content()
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', ['de', 'ko'])
def test_runtime_apply_is_a_word_in_the_corporate_vm_configuration(open_app, lang):
    """The Corporate configuration modal shows Apply once something changed. It said
    "apply" in every language but Portuguese."""
    w = WORDS[lang]
    app = open_app(layout='corporate', language=lang, clusters=[CLUSTER], resources=[VM],
                   extra={('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, VM_CONFIG), **SSE_TOKEN})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=w['resources']).first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator(f'button[title="{w["configuration"]}"]').first.click()
    name = page.locator('input[value="web01"]').first
    name.wait_for(timeout=8000)
    name.fill('web02')
    button = page.locator('.corp-vm-modal-actions button', has_text=w['apply'])
    button.wait_for(timeout=3000)
    assert button.inner_text().strip() == w['apply']
    assert page.locator('.corp-vm-modal-actions button', has_text='apply').count() == 0
    assert not app.errors, app.errors
