"""An ESXi migration that completed with something left undone says so where its result is
shown (#1245).

The run that prompted this reported COMPLETED while the VirtIO drivers it was asked for
never reached the guest; the only hint was one line deep in the log. The task now carries
`warnings`, and the UI lists them in the result: a badge on the row of the Tasks & Events
tab, a block under the outcome in the migration log, and a line on the migration card of
the VM's Migration tab.

Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Nov 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import ESXI_READS, SSE_TOKEN, _App, _classes, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z]{2}): \{', src, re.M)]
    ends = [pos for _, pos in starts[1:]] + [len(src)]
    return {lang: src[pos:end] for (lang, pos), end in zip(starts, ends)}


def _added_markup():
    """The three places of dashboard.js that render the warnings."""
    src = _read('web', 'src', 'dashboard.js')
    parts = []
    for anchor in ('{(m.warnings || []).map((w, i) => (',
                   '{(m.warnings || []).length > 0 && <span data-v2p-warnings',
                   '{(vmwareMigrationDetail.warnings || []).length > 0 && ('):
        at = src.index(anchor)
        parts.append(src[at:src.index('\n', src.index('data-v2p-warnings', at) + 200)])
    return '\n'.join(parts)


def test_every_language_has_the_label_once_and_in_its_own_words():
    blocks = _blocks()
    assert list(blocks) == LANGS
    values = {}
    for lang, block in blocks.items():
        found = re.findall(r"^\s*migrationWarnings: '([^']+)',", block, re.M)
        assert len(found) == 1, (lang, found)
        values[lang] = found[0]
    assert values['en'] == 'Warnings'
    assert all(v != 'Warnings' for lang, v in values.items() if lang != 'en'), values


def test_the_markup_uses_classes_the_static_build_has():
    # tailwind.min.css only: index.html.original names amber classes, but just for the light
    # Corporate theme, so on a dark page they do nothing
    css = _read('static', 'css', 'tailwind.min.css')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_added_markup()) if n not in have)
    assert not missing, missing


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    assert "migrationWarnings:'Warnings'" in bundle
    # LW Nov 2026 - German is web/i18n/de.json now, written by build.sh next to the bundle
    assert json.loads(_read('web', 'i18n', 'de.json'))['migrationWarnings'] == 'Warnungen'
    assert 'vmwareMigrationDetail.warnings' in bundle


# -- runtime ------------------------------------------------------------------------------------

WARNING = ("VirtIO drivers were not injected: RBD_MAP_FAILED: rbd: error opening pool 'vm-rbd': "
           "(2) No such file or directory. The guest boots without them, install them from the "
           "virtio-win ISO after the first boot.")


def _task(mid, name, warnings):
    return {'id': mid, 'vmware_id': 'v1', 'vm_id': 'vm-1', 'vm_name': name, 'target_cluster': 'c1',
            'target_node': 'pve1', 'target_storage': 'vm-rbd', 'proxmox_vmid': 100,
            'phase': 'completed', 'status': 'completed', 'progress': 100, 'error': None,
            'wait_for_confirmation': False, 'awaiting_confirmation': False,
            'started_at': '2026-11-05T13:50:00', 'completed_at': '2026-11-05T14:02:00',
            'disk_progress': {}, 'phase_times': {}, 'total_downtime_seconds': 42,
            'warnings': warnings,
            'log': ['[14:01:58] [VirtIO] Target storage type: rbd', '[14:02:00] Phase: completed'],
            'config': {}}


WARNED = _task('m1', 'legacy01', [WARNING])
CLEAN = _task('m2', 'quiet01', [])
READS = {('GET', '/api/vmware/migrations'): (200, [WARNED, CLEAN]),
         ('GET', '/api/vmware/migrations/m1'): (200, WARNED),
         ('GET', '/api/vmware/migrations/m2'): (200, CLEAN),
         ('GET', '/api/audit'): (200, [])}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = {**ESXI_READS, **SSE_TOKEN, **READS}
        app = _App(browser, _FakeServer(role='standalone', extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _visible(page, selector):
    return page.evaluate(
        '(sel) => Array.from(document.querySelectorAll(sel)).filter(e => e.offsetParent !== null)'
        '.map(e => e.innerText.trim())', selector)


def _looks_like_a_warning(locator, background=True):
    """Drawn in a warning colour: a text that is clearly more red/green than blue, and a
    tinted background where the markup asks for one. A class the static build lacks would
    leave both at the page defaults."""
    style = locator.evaluate('(e) => { const s = getComputedStyle(e);'
                             ' return [s.color, s.backgroundColor]; }')
    rgb = [float(x) for x in re.findall(r'[\d.]+', style[0])[:3]]
    assert rgb[0] > rgb[2] + 60 and rgb[1] > rgb[2] + 40, style
    if background:
        assert style[1] not in ('rgba(0, 0, 0, 0)', 'transparent'), style


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_the_warning_is_in_the_result_of_the_run(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.locator('button', has_text='Tasks & Events').first.click()

    # the row of the run that left something undone says so, the clean one does not
    page.get_by_text('Warnings: 1').first.wait_for(timeout=8000)
    badges = _visible(page, 'span[data-v2p-warnings]')
    assert badges == ['Warnings: 1'], badges
    _looks_like_a_warning(page.locator('span[data-v2p-warnings]').first)
    assert page.get_by_text('quiet01').first.is_visible()

    # the result of the run: the outcome, then what it left undone
    page.get_by_text('Warnings: 1').first.click()
    block = page.locator('div[data-v2p-warnings]').first
    block.wait_for(timeout=8000)
    text = block.inner_text()
    assert text.startswith('Warnings'), text
    assert WARNING in text, text
    _looks_like_a_warning(block)
    done = page.get_by_text('Completed! VMID: 100').first
    assert done.is_visible()
    assert done.bounding_box()['y'] < block.bounding_box()['y']
    _shot(page, f'{layout}-tasks.png')

    # the clean run opens without a warning block
    page.get_by_text('quiet01').first.click()
    page.get_by_text('(m2)').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    assert _visible(page, 'div[data-v2p-warnings]') == []

    # the card on the VM's Migration tab, where a run is started, shows it as well
    page.locator('button', has_text='Virtual Machines').first.click()
    page.get_by_text('legacy01').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Migration\s*$')).first.click()
    page.get_by_text('Active Migrations').first.wait_for(timeout=8000)
    lines = _visible(page, 'div[data-v2p-warnings]')
    assert lines == [WARNING], lines
    _looks_like_a_warning(page.locator('div[data-v2p-warnings]').first, background=False)
    _shot(page, f'{layout}-vm-card.png')
    assert not app.errors, app.errors


def test_runtime_the_label_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.locator('button', has_text='Aufgaben & Ereignisse').first.click()
    page.get_by_text('Warnungen: 1').first.wait_for(timeout=8000)
    assert not app.errors, app.errors
