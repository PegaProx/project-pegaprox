"""The VirtIO RNG card and dialog in the VM hardware settings, at runtime.

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py; the server's checks of rng0 are tested in test_vm_rng.py. The fake
server here keeps the VM config, so a saved device shows up the way PVE returns it. Modern,
Corporate and Cloud open the same ConfigModal. Skips where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, VM_CONFIG, _read, LANGS  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')

VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'stopped', 'node': 'pve1',
      'cpu': 0, 'cpu_percent': 0, 'maxcpu': 2, 'mem': 0, 'maxmem': 4294967296,
      'mem_percent': 0, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 0}
VM_URL = '/api/clusters/c1/vms/pve1/qemu/100'
CFG = f'{VM_URL}/config'


class _RngServer(_FakeServer):
    """The fake server with a VM config that a PUT changes, as PVE would."""

    def __init__(self, raw=None, put_error=None, **kw):
        super().__init__(**kw)
        self.vm_raw = {'name': 'web01', 'digest': 'x', **(raw or {})}
        self.put_error = put_error
        self.extra[('GET', f'{VM_URL}/passthrough')] = (200, {'pci': [], 'usb': [], 'serial': []})
        self.extra[('GET', '/api/clusters/c1/nodes/pve1/hardware/pci')] = (200, [])
        self.extra[('GET', '/api/clusters/c1/nodes/pve1/hardware/usb')] = (200, [])
        self._config()

    def _config(self):
        self.extra[('GET', CFG)] = (200, dict(VM_CONFIG, raw=dict(self.vm_raw), status={'status': 'stopped'}))

    def handle(self, route):
        req = route.request
        if req.method == 'PUT' and req.url.split('?')[0].endswith(CFG):
            if self.put_error:
                self.extra[('PUT', CFG)] = (400, {'error': self.put_error})
            else:
                body = json.loads(req.post_data or '{}')
                for key in str(body.pop('delete', '') or '').split(','):
                    self.vm_raw.pop(key.strip(), None)
                self.vm_raw.update(body)
                self._config()
                self.extra[('PUT', CFG)] = (200, {'message': 'Configuration updated'})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(raw=None, put_error=None, **kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [VM])
        app = _App(browser, _RngServer(raw=raw, put_error=put_error, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.wait_for_timeout(300)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _card(app, layout='modern', label='Hardware'):
    _open_config(app, 'web01', layout=layout)
    _tab(app, label).click()
    card = app.page.locator('[data-rng-card]')
    card.wait_for(timeout=5000)
    card.scroll_into_view_if_needed()
    return card


def _puts(app):
    return [b for b in app.server.bodies.get(CFG, []) if b]


def _dialog(app, kind):
    d = app.page.locator(f'[data-rng-dialog="{kind}"]')
    d.wait_for(timeout=3000)
    return d


def test_runtime_add_a_virtio_rng_with_the_defaults(open_app):
    app = open_app()
    page = app.page
    card = _card(app)
    text = card.inner_text()
    assert 'VirtIO RNG' in text and 'No VirtIO RNG' in text
    assert 'does not wait for randomness while booting' in text
    # a stopped VM takes the change at once
    assert 'Changes active after restart' not in text
    _shot(app, 'rng_empty_modern')

    card.locator('[data-rng-add]').click()
    d = _dialog(app, 'add')
    assert d.locator('[data-rng-source]').input_value() == '/dev/urandom'
    assert d.locator('[data-rng-max-bytes]').input_value() == '1024'
    assert d.locator('[data-rng-period]').input_value() == '1000'
    assert d.locator('[data-rng-warning]').count() == 0 and d.locator('[data-rng-problem]').count() == 0
    assert d.locator('[data-rng-source] option').all_inner_texts() == ['/dev/urandom', '/dev/random', '/dev/hwrng']
    save = d.locator('[data-rng-save]')
    assert save.inner_text() == 'Add' and save.is_enabled()
    _shot(app, 'rng_add_modern')
    save.click()
    page.get_by_text('VirtIO RNG saved').first.wait_for(timeout=3000)
    assert _puts(app) == [{'rng0': 'source=/dev/urandom,max_bytes=1024,period=1000'}]
    assert page.locator('[data-rng-dialog]').count() == 0

    row = card.locator('[data-rng-device]')
    row.wait_for(timeout=3000)
    assert row.locator('[data-rng-shown-source]').inner_text() == '/dev/urandom'
    assert row.locator('[data-rng-shown-limit]').inner_text() == '1024 bytes per 1000 ms'
    row.scroll_into_view_if_needed()
    _shot(app, 'rng_set_modern')
    assert not app.errors, app.errors


def test_runtime_edit_reads_the_pve_spelling_and_checks_the_numbers(open_app):
    # PVE's own GUI writes the bare source, and leaves the period to its default
    app = open_app(raw={'rng0': '/dev/hwrng,max_bytes=2048'})
    card = _card(app)
    row = card.locator('[data-rng-device]')
    assert row.locator('[data-rng-shown-source]').inner_text() == '/dev/hwrng'
    assert row.locator('[data-rng-shown-limit]').inner_text() == '2048 bytes per 1000 ms'

    row.locator('[data-rng-edit]').click()
    d = _dialog(app, 'edit')
    assert d.locator('[data-rng-source]').input_value() == '/dev/hwrng'
    assert d.locator('[data-rng-max-bytes]').input_value() == '2048'
    assert d.locator('[data-rng-period]').input_value() == '1000'
    assert 'The VM starts only on a node that has one' in d.locator('[data-rng-warning="hwrng"]').inner_text()
    d.locator('[data-rng-source]').select_option('/dev/random')
    assert '/dev/urandom is the better source' in d.locator('[data-rng-warning="random"]').inner_text()
    save = d.locator('[data-rng-save]')
    assert save.inner_text() == 'Save'

    period, limit = d.locator('[data-rng-period]'), d.locator('[data-rng-max-bytes]')
    for bad in ('0', '', '4294967296'):
        period.fill(bad)
        assert d.locator('[data-rng-problem="rngBadPeriod"]').is_visible(), bad
        assert save.is_disabled(), bad
    period.fill('500')
    assert d.locator('[data-rng-problem]').count() == 0 and save.is_enabled()
    for bad in ('-1', '', '9223372036854775808'):
        limit.fill(bad)
        assert d.locator('[data-rng-problem="rngBadMaxBytes"]').is_visible(), bad
        assert save.is_disabled(), bad
    _shot(app, 'rng_problem_modern')
    # no limit: the period is not used, and the dialog says what that means
    limit.fill('0')
    assert period.is_disabled() and save.is_enabled()
    assert 'put load on the host' in d.locator('[data-rng-warning="unlimited"]').inner_text()
    _shot(app, 'rng_unlimited_modern')
    limit.fill('4096')
    assert period.is_enabled() and period.input_value() == '500'
    save.click()
    app.page.get_by_text('VirtIO RNG saved').first.wait_for(timeout=3000)
    assert _puts(app) == [{'rng0': 'source=/dev/random,max_bytes=4096,period=500'}]
    row.locator('[data-rng-shown-source]').filter(has_text='/dev/random').wait_for(timeout=3000)
    assert row.locator('[data-rng-shown-limit]').inner_text() == '4096 bytes per 500 ms'
    assert not app.errors, app.errors


def test_runtime_no_limit_goes_without_a_period(open_app):
    app = open_app()
    card = _card(app)
    card.locator('[data-rng-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-rng-max-bytes]').fill('0')
    d.locator('[data-rng-save]').click()
    app.page.get_by_text('VirtIO RNG saved').first.wait_for(timeout=3000)
    assert _puts(app) == [{'rng0': 'source=/dev/urandom,max_bytes=0'}]
    card.locator('[data-rng-shown-limit]').filter(has_text='No limit').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_remove_asks_first(open_app):
    app = open_app(raw={'rng0': 'source=/dev/urandom,max_bytes=1024,period=1000'})
    page = app.page
    card = _card(app)
    answers = []

    def dialog(d):
        answers.append(d.message)
        d.dismiss() if len(answers) == 1 else d.accept()
    page.on('dialog', dialog)
    card.locator('[data-rng-remove]').click()
    page.wait_for_timeout(400)
    assert answers == ['Remove the VirtIO RNG from this VM?'] and not _puts(app)

    card.locator('[data-rng-remove]').click()
    page.get_by_text('VirtIO RNG removed').first.wait_for(timeout=3000)
    assert _puts(app) == [{'delete': 'rng0'}]
    card.locator('[data-rng-add]').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_a_refusal_keeps_the_dialog_open_with_the_reason(open_app):
    app = open_app(put_error='Invalid VirtIO RNG: rng0 period must be a whole number from 1 to 4294967295')
    page = app.page
    card = _card(app)
    card.locator('[data-rng-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-rng-save]').click()
    page.get_by_text('Invalid VirtIO RNG: rng0 period').first.wait_for(timeout=3000)
    assert d.is_visible() and d.locator('[data-rng-save]').is_enabled()
    assert card.locator('[data-rng-device]').count() == 0
    # the 400 is the mocked answer, not a page error
    assert not [e for e in app.errors if '400' not in e], app.errors


def test_runtime_a_running_vm_says_the_change_waits(open_app):
    app = open_app(resources=[dict(VM, status='running', uptime=3600)], raw={'rng0': '/dev/urandom'})
    card = _card(app)
    assert 'Changes active after restart' in card.inner_text()
    assert card.locator('[data-rng-shown-limit]').inner_text() == '1024 bytes per 1000 ms'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'cloud'])
def test_runtime_the_rng_in_the_other_layouts(open_app, layout):
    app = open_app(layout=layout)
    card = _card(app, layout=layout)
    card.locator('[data-rng-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-rng-source]').select_option('/dev/hwrng')
    d.locator('[data-rng-warning="hwrng"]').wait_for(timeout=3000)
    _shot(app, f'rng_add_{layout}')
    d.locator('[data-rng-save]').click()
    card.locator('[data-rng-device]').wait_for(timeout=3000)
    assert _puts(app) == [{'rng0': 'source=/dev/hwrng,max_bytes=1024,period=1000'}]
    card.scroll_into_view_if_needed()
    _shot(app, f'rng_set_{layout}')
    assert not app.errors, app.errors


def test_runtime_the_rng_in_german(open_app):
    app = open_app(language='de', raw={'rng0': '/dev/urandom,max_bytes=0'})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Konfiguration"], button[title="Configuration"]').first.click()
    _tab(app, 'Hardware').click()
    card = page.locator('[data-rng-card]')
    card.wait_for(timeout=5000)
    assert card.locator('[data-rng-shown-limit]').inner_text() == 'Kein Limit'
    card.locator('[data-rng-edit]').click()
    d = _dialog(app, 'edit')
    text = d.inner_text()
    for needle in ('VirtIO RNG bearbeiten', 'Entropiequelle', 'Limit (Bytes pro Periode)', 'Periode (ms)',
                   'den Host belasten', 'Speichern'):
        assert needle in text, needle
    assert not app.errors, app.errors


def test_runtime_a_standby_changes_no_rng(open_app):
    app = open_app(role='standby', raw={'rng0': '/dev/urandom'})
    card = _card(app)
    assert app.page.locator('fieldset[data-ha-locked]').count() == 1
    assert card.locator('[data-rng-edit]').is_disabled()
    assert card.locator('[data-rng-remove]').is_disabled()
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/qemu/100/' in c[1]]
    assert not app.errors, app.errors


def test_runtime_an_xcpng_pool_has_no_rng_card(open_app):
    app = open_app(clusters=[dict(CLUSTER, cluster_type='xcpng')])
    _open_config(app, 'web01')
    _tab(app, 'Hardware').click()
    app.page.get_by_text('Cloud-Init').first.wait_for(timeout=5000)
    assert app.page.locator('[data-rng-card]').count() == 0


# --- the source --------------------------------------------------------------------------------

def test_every_rng_string_is_in_all_nine_languages():
    tr = _read('web', 'src', 'translations.js')
    src = _read('web', 'src', 'vm_config.js')
    keys = set(re.findall(r"'(rng[A-Z]\w+)'", src))
    assert len(keys) == 22, sorted(keys)
    for key in keys:
        lines = re.findall(r'^\s*' + key + r':\s*(.+)$', tr, re.M)
        assert len(lines) == len(LANGS), key
        assert not [x for x in lines if '\u2014' in x], key
    for line in re.findall(r'^\s*rngLimitText:\s*(.+)$', tr, re.M):
        assert '{bytes}' in line and '{ms}' in line, line


def test_the_bundle_carries_the_rng():
    bundle = _read('web', 'index.html')
    for needle in ('data-rng-card', 'data-rng-dialog', 'rngRemoveConfirm', 'RNG_MAX_BYTES_TOP'):
        assert needle in bundle, needle
    assert re.search(r'^\s*Dice: \(\) =>', _read('web', 'src', 'icons.js'), re.M)
