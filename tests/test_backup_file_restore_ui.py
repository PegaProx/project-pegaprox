"""File restore from the Backups tab of the configuration modal, at runtime (#1139).

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py; the routes behind it are tested in test_backup_file_restore_1139.py.
The dialog lists the backup, walks into a directory, takes a file and a destination, and
says what the server answered: its own words for a 413, a 403 and a 502, not a fallback.
Skips where Playwright is not installed.
LW Oct 2026
"""
import base64
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, VM_CONFIG, _read, LANGS  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab, CT, CT_CONFIG

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')

VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'running', 'node': 'pve1',
      'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
      'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
VOLID = 'pbs1:backup/vm/100/2026-10-01T02:00:00Z'
BACKUP = {'volid': VOLID, 'filename': 'vm/100/2026-10-01T02:00:00Z', 'ctime': 1790000000,
          'size': 2147483648, 'storage': 'pbs1', 'notes': ''}


def _b64(path):
    return base64.b64encode(path.encode()).decode()


def _tree(*dirs, files=('hosts',)):
    """{path param: listing} as PVE's file-restore lists a backup: the archive at the root
    with a leading slash, below it the path from the archive on (proxmox-file-restore).
    `dirs` is the way down to etc, which holds `files` and ssh."""
    tree, key, here = {}, None, ''
    for i, name in enumerate(dirs):
        # a pxar archive and a directory are 'd', a disk and what is found on it 'v'
        kind = 'd' if name == 'etc' or 'pxar.didx' in name else 'v'
        path = '/' + name if i == 0 else f'{here}/{name}'
        tree[key] = [{'text': name, 'type': kind, 'leaf': 0, 'filepath': _b64(path)}]
        key, here = _b64(path), path.lstrip('/')
    tree[key] = [{'text': f, 'type': 'f', 'leaf': 1, 'size': 120, 'filepath': _b64(f'{here}/{f}')}
                 for f in files] + [{'text': 'ssh', 'type': 'd', 'leaf': 0, 'filepath': _b64(f'{here}/ssh')}]
    return tree


# a VM disk's first partition, and a container's archive
VM_WAY = ('drive-scsi0.img.fidx', 'part', '1', 'etc')
CT_WAY = ('root.pxar.didx', 'etc')
VM_HOSTS = _b64('drive-scsi0.img.fidx/part/1/etc/hosts')
REFUSALS = {
    413: 'VMs take files of up to 45 KB through the guest agent. Restore the whole VM for a larger file.',
    403: 'Permission denied: vm.console',
    502: 'Proxmox VE refused the stored credentials (HTTP 401): Guest agent file-write failed: no ticket',
}


class _RestoreServer(_FakeServer):
    """The fake server with one PBS backup of the guest; the listing answers by ?path=."""

    def __init__(self, restore=(200, {'success': True}), browse=None, tree=None, guest=None, backup=None, **kw):
        super().__init__(**kw)
        self.restore, self.browse = restore, browse
        self.tree = tree or _tree(*VM_WAY)
        self.url = f"/api/clusters/c1/vms/pve1/{(guest or VM)['type']}/{(guest or VM)['vmid']}"
        config = CT_CONFIG if (guest or VM)['type'] == 'lxc' else VM_CONFIG
        self.extra[('GET', f'{self.url}/config')] = (200, dict(config, status={'status': 'running'}))
        self.extra[('GET', f'{self.url}/backups')] = (200, [backup or BACKUP])
        self.listed = []

    def handle(self, route):
        req = route.request
        path = urlparse(req.url).path
        if req.method == 'GET' and path == f'{self.url}/backups/files':
            q = parse_qs(urlparse(req.url).query)
            self.listed.append({k: v[0] for k, v in q.items()})
            if self.browse:
                status, body = self.browse
            else:
                status, body = 200, self.tree.get(q.get('path', [None])[0], [])
            return route.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})
        if req.method == 'POST' and path == f'{self.url}/backups/file-restore':
            self.extra[('POST', path)] = self.restore
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(language='en', layout='modern', guest=None, **kw):
        app = _App(browser, _RestoreServer(role='standalone', layout=layout, language=language,
                                           clusters=[CLUSTER], resources=[guest or VM], guest=guest, **kw))
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


def _dialog(app, name='web01'):
    if app.server.layout == 'corporate':
        _open_resources(app, name)
        app.page.locator('button[title="Configuration"]').first.click()
        _tab(app, 'Options').wait_for(timeout=8000)
    else:
        _open_config(app, name)
    _tab(app, 'Backups').click()
    app.page.locator('[data-file-restore-open]').first.click()
    d = app.page.locator('[data-file-restore-dialog]')
    d.wait_for(timeout=5000)
    return d


def _open_resources(app, name):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text(name).first.wait_for(timeout=5000)
    page.wait_for_timeout(300)


def _pick_hosts(app, d, way=VM_WAY, name='hosts'):
    for entry in way + (name,):
        d.locator(f'[data-file-restore-entry="{entry}"]').click()
    dest = d.locator('[data-file-restore-dest]')
    dest.wait_for(timeout=3000)
    return dest


def _posts(app):
    return [b for b in app.server.bodies.get(f'{app.server.url}/backups/file-restore', [])]


def test_runtime_restore_a_file_into_a_vm(open_app):
    app = open_app()
    d = _dialog(app)
    assert app.server.listed == [{'volid': VOLID}]
    dest = _pick_hosts(app, d)
    assert app.server.listed[-1] == {'volid': VOLID, 'path': _b64('drive-scsi0.img.fidx/part/1/etc')}
    note = d.locator('[data-file-restore-note="qemu"]').inner_text()
    assert 'QEMU Guest Agent' in note and '45 KB' in note
    assert 'selected. Destination path in the guest:' in d.inner_text()
    # the path in the guest, not the one in the backup: disk and partition are gone (#1139)
    assert dest.input_value() == '/etc/hosts'
    _shot(app, 'file_restore_vm')
    # the button is drawn: the static Tailwind build has no teal, a class it lacks paints nothing
    submit = d.locator('[data-file-restore-submit]')
    assert submit.evaluate('e => getComputedStyle(e).backgroundColor') not in ('rgba(0, 0, 0, 0)', 'transparent')
    submit.click()
    app.page.get_by_text('File restored successfully').first.wait_for(timeout=3000)
    assert _posts(app) == [{'volid': VOLID, 'filepath': VM_HOSTS, 'dest_path': '/etc/hosts'}]
    assert app.page.locator('[data-file-restore-dialog]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('way,want', [
    (CT_WAY, '/etc/hosts'),
    (('root.mpxar.didx', 'etc'), '/etc/hosts'),
    (('drive-scsi0.img.fidx', 'raw', 'etc'), '/etc/hosts'),
    (('drive-virtio1.img.fidx', 'lvm', 'pve', 'root', 'etc'), '/etc/hosts'),
    # a pool's datasets mount where their properties say: no guess, the user types it
    (('drive-scsi0.img.fidx', 'zpool', 'rpool', 'etc'), ''),
])
def test_runtime_the_destination_is_the_path_in_the_guest(open_app, way, want):
    """PVE's filepath of a file starts with its archive and, on a VM disk, with where the
    file system was found. None of that is in the guest (#1139)."""
    app = open_app(tree=_tree(*way))
    d = _dialog(app)
    dest = _pick_hosts(app, d, way)
    assert dest.input_value() == want
    submit = d.locator('[data-file-restore-submit]')
    assert submit.is_enabled() == bool(want)
    if not want:
        dest.fill('/etc/hosts')
        assert submit.is_enabled()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_restore_a_file_into_a_container(open_app, layout):
    """The Backups tab is the same in both layouts; Corporate draws the modal around it
    with its own overlay, and the dialog has to come out on top of it, whole."""
    backup = dict(BACKUP, volid='pbs1:backup/ct/101/2026-10-01T02:00:00Z', filename='ct/101/2026-10-01T02:00:00Z')
    app = open_app(layout=layout, guest=CT, backup=backup, tree=_tree(*CT_WAY))
    d = _dialog(app, 'ct101')
    dest = _pick_hosts(app, d, CT_WAY)
    assert dest.input_value() == '/etc/hosts'
    assert 'SSH' in d.locator('[data-file-restore-note="lxc"]').inner_text()
    submit = d.locator('[data-file-restore-submit]')
    # on top and inside the window: the middle of the button is the button
    box = submit.bounding_box()
    assert box and 0 <= box['y'] and box['y'] + box['height'] <= 1000, box
    hit = app.page.evaluate('([x, y]) => !!document.elementFromPoint(x, y)?.closest("[data-file-restore-submit]")',
                            [box['x'] + box['width'] / 2, box['y'] + box['height'] / 2])
    assert hit
    _shot(app, f'file_restore_ct_{layout}')
    submit.click()
    app.page.get_by_text('File restored successfully').first.wait_for(timeout=3000)
    assert _posts(app) == [{'volid': backup['volid'], 'filepath': _b64('root.pxar.didx/etc/hosts'),
                            'dest_path': '/etc/hosts'}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('status', sorted(REFUSALS))
def test_runtime_the_servers_refusal_is_said_in_its_words(open_app, status):
    app = open_app(restore=(status, {'error': REFUSALS[status]}))
    d = _dialog(app)
    _pick_hosts(app, d)
    d.locator('[data-file-restore-submit]').click()
    app.page.get_by_text(REFUSALS[status]).first.wait_for(timeout=3000)
    # the server's sentence, not the fallback, and the dialog stays for another try
    assert app.page.get_by_text('File restore failed').count() == 0
    assert d.is_visible() and d.locator('[data-file-restore-submit]').is_enabled()
    assert len(_posts(app)) == 1
    _shot(app, f'file_restore_refused_{status}')
    # a refused request is a mocked answer, not a page error
    assert not [e for e in app.errors if str(status) not in e], app.errors


def test_runtime_a_backup_that_cannot_be_browsed_says_why(open_app):
    said = ('File-level restore is not available for vzdump VMA backups (vzdump-qemu-100.vma.zst). '
            "PVE's file-browse API only supports Proxmox Backup Server (PBS) backups.")
    app = open_app(browse=(400, {'error': said}))
    d = _dialog(app)
    err = d.locator('[data-file-restore-error]')
    err.wait_for(timeout=3000)
    assert said in err.inner_text()
    assert d.locator('[data-file-restore-entry]').count() == 0
    assert not [e for e in app.errors if '400' not in e], app.errors


def test_runtime_the_dialog_in_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Konfiguration"], button[title="Configuration"]').first.click()
    _tab(app, 'Backups').click()
    page.locator('[data-file-restore-open]').first.click()
    d = page.locator('[data-file-restore-dialog]')
    d.wait_for(timeout=5000)
    _pick_hosts(app, d)
    text = d.inner_text()
    for needle in ('Datei-Wiederherstellung', 'ausgewählt. Zielpfad im Gast:', 'Datei wiederherstellen',
                   'Der Agent nimmt Dateien bis 45 KB an.'):
        assert needle in text, needle
    assert d.locator('[data-file-restore-dest]').get_attribute('placeholder') == 'Zielpfad im Gast'
    assert not app.errors, app.errors


# --- the source --------------------------------------------------------------------------------

KEYS = ('fileRestore', 'fileRestoreBrowseFailed', 'fileRestoreSuccess', 'fileRestoreFailed',
        'fileRestoreNoteQemu', 'fileRestoreNoteLxc', 'selectedForRestore', 'destPath',
        'restoreFile', 'emptyDirectory')


def test_every_file_restore_string_is_in_all_nine_languages():
    tr = _read('web', 'src', 'translations.js')
    src = _read('web', 'src', 'vm_config.js')
    assert set(KEYS) <= set(re.findall(r"t\('(\w+)'\)", src))
    for key in KEYS:
        lines = re.findall(r'^\s*' + key + r':\s*(.+)$', tr, re.M)
        assert len(lines) == len(LANGS), key
        assert not [x for x in lines if chr(0x2014) in x], key
    for line in re.findall(r'^\s*fileRestoreNoteQemu:\s*(.+)$', tr, re.M):
        assert '45 K' in line, line


def test_every_class_of_the_dialog_is_in_the_static_tailwind_build():
    src = _read('web', 'src', 'vm_config.js')
    css = _read('static', 'css', 'tailwind.min.css')
    start = src.index('data-file-restore-open')
    part = src[start - 200:src.index('data-file-restore-open') + 600]
    part += src[src.index('{/* File Restore Modal */}'):src.index('{/* NS: Restore Backup Modal */}')]
    classes = set()
    for m in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\})', part):
        classes.update(re.sub(r'\$\{[^}]*\}', ' ', m.group(1) or m.group(2)).split())
    classes |= set(re.findall(r"'(bg-[\w/-]+)'", part))
    assert len(classes) > 50, sorted(classes)
    missing = sorted(c for c in classes if '.' + re.sub(r'([:/\[\].])', r'\\\1', c) not in css)
    assert not missing, missing


def test_the_bundle_carries_the_file_restore():
    bundle = _read('web', 'index.html')
    for needle in ('data-file-restore-dialog', 'data-file-restore-submit', 'fileRestoreNoteQemu',
                   'backups/file-restore'):
        assert needle in bundle, needle
