"""virtiofs in the VM hardware settings, directory mappings in the datacenter and the
migrate dialog of a VM with a share, at runtime.

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py; the server's checks are tested in test_virtiofs.py. The fake server
here keeps the VM config and the directory mappings, so what is saved shows up the way PVE
returns it. Modern, Corporate and Cloud open the same ConfigModal and the same mapping
section. Skips where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, VM_CONFIG, _read, _classes, LANGS  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')

VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'stopped', 'node': 'pve1',
      'cpu': 0, 'cpu_percent': 0, 'maxcpu': 2, 'mem': 0, 'maxmem': 4294967296,
      'mem_percent': 0, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 0}
VM_URL = '/api/clusters/c1/vms/pve1/qemu/100'
CFG = f'{VM_URL}/config'
DIR = '/api/clusters/c1/datacenter/mapping/dir'
_NODE = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0, 'score': 42.0,
         'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0, 'mem_used': 6871947673,
         'mem_total': 34359738368, 'disk_used': 0, 'disk_total': 0, 'cpu_count': 8, 'maxcpu': 8}
METRICS = {'pve1': dict(_NODE), 'pve2': dict(_NODE), 'pve3': dict(_NODE, status='offline')}
NODES = ['pve1', 'pve2', 'pve3']

DIRS = [
    {'id': 'backups', 'description': '', 'nodes': ['pve2'], 'entries': [{'node': 'pve2', 'path': '/srv/backups'}]},
    {'id': 'share', 'description': 'Media', 'nodes': ['pve1', 'pve2'],
     'entries': [{'node': 'pve1', 'path': '/mnt/share'}, {'node': 'pve2', 'path': '/srv/share'}]},
]


def _vm_dir_list(dirs, node='pve1', may_add=True, only=None):
    """GET .../passthrough/mappings?kind=dir as the server answers it"""
    out = []
    for d in dirs:
        if only is not None and d['id'] not in only:
            continue
        on = node in d['nodes']
        out.append({'id': d['id'], 'description': d['description'], 'nodes': d['nodes'],
                    'entries': [dict(e, id='', description='') for e in d['entries']],
                    'on_node': on, 'mdev': False, 'live_migration': False,
                    'checks': [] if on else [{'severity': 'warning', 'message': f'No mapping for node {node}.'}]})
    return {'kind': 'dir', 'node': node, 'supported': True, 'mappings': out, 'may_add': may_add}


class _VfsServer(_FakeServer):
    """The fake server with a VM config and directory mappings that writes change, as PVE would."""

    def __init__(self, raw=None, put_error=None, dirs=None, vm_dirs=None, dir_error=None, **kw):
        kw.setdefault('metrics', METRICS)
        super().__init__(**kw)
        self.vm_raw = {'name': 'web01', 'digest': 'x', 'ostype': 'l26', **(raw or {})}
        self.put_error = put_error
        self.dirs = [dict(d) for d in (DIRS if dirs is None else dirs)]
        self.digest = 'abc1'
        self.dir_error = dir_error
        self.extra[('GET', f'{VM_URL}/passthrough')] = (200, {'pci': [], 'usb': [], 'serial': []})
        self.extra[('GET', '/api/clusters/c1/nodes/pve1/hardware/pci')] = (200, [])
        self.extra[('GET', '/api/clusters/c1/nodes/pve1/hardware/usb')] = (200, [])
        for n in NODES:
            self.extra[('GET', f'/api/clusters/c1/nodes/{n}/storage')] = (200, [])
        self.extra[('GET', f'{VM_URL}/passthrough/mappings')] = (200, vm_dirs or _vm_dir_list(self.dirs))
        self.extra[('GET', '/api/clusters/c1/datacenter/mapping/pci')] = (200, [
            {'id': 'gpu0', 'description': 'RTX 4000', 'map': ['node=pve1,path=0000:01:00.0,id=10de:1b80',
                                                               'node=pve2,path=0000:41:00.0,id=10de:1b80']}])
        self.extra[('GET', '/api/clusters/c1/datacenter/mapping/usb')] = (200, [])
        self._config()
        self._dirs()

    def _config(self):
        self.extra[('GET', CFG)] = (200, dict(VM_CONFIG, raw=dict(self.vm_raw), status={'status': 'stopped'}))

    def _dirs(self):
        if self.dir_error:
            self.extra[('GET', DIR)] = self.dir_error
        else:
            self.extra[('GET', DIR)] = (200, {'supported': True, 'mappings': [dict(d) for d in self.dirs],
                                              'nodes': NODES, 'digest': self.digest})

    def handle(self, route):
        req = route.request
        path = req.url.split('?')[0]
        body = json.loads(req.post_data or '{}') if req.method in ('PUT', 'POST') else {}
        if req.method == 'PUT' and path.endswith(CFG):
            if self.put_error:
                self.extra[('PUT', CFG)] = (400, {'error': self.put_error})
            else:
                for key in str(body.pop('delete', '') or '').split(','):
                    self.vm_raw.pop(key.strip(), None)
                self.vm_raw.update(body)
                self._config()
                self.extra[('PUT', CFG)] = (200, {'message': 'Configuration updated'})
        elif req.method == 'POST' and path.endswith(DIR):
            entries = body.get('map') or []
            self.dirs.append({'id': body.get('id'), 'description': body.get('description') or '',
                              'nodes': sorted(e['node'] for e in entries), 'entries': entries})
            self.dirs.sort(key=lambda d: d['id'])
            self.digest += '1'
            self._dirs()
            self.extra[('POST', DIR)] = (200, {'success': True, 'id': body.get('id')})
        elif req.method in ('PUT', 'DELETE') and '/datacenter/mapping/dir/' in path:
            mid = path.rsplit('/', 1)[1]
            rel = DIR + '/' + mid
            if req.method == 'DELETE':
                self.dirs = [d for d in self.dirs if d['id'] != mid]
            else:
                for d in self.dirs:
                    if d['id'] == mid:
                        if 'map' in body:
                            d['entries'] = body['map']
                            d['nodes'] = sorted(e['node'] for e in body['map'])
                        if 'description' in body:
                            d['description'] = body['description']
            self.digest += '1'
            self._dirs()
            self.extra[(req.method, rel)] = (200, {'success': True})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [VM])
        app = _App(browser, _VfsServer(**kw))
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


def _card(app, layout='modern'):
    _open_config(app, 'web01', layout=layout)
    _tab(app, 'Hardware').click()
    card = app.page.locator('[data-vfs-card]')
    card.wait_for(timeout=5000)
    card.scroll_into_view_if_needed()
    return card


def _puts(app, path=CFG):
    return [b for b in app.server.bodies.get(path, []) if b]


def _dialog(app, kind, attr='data-vfs-dialog'):
    d = app.page.locator(f'[{attr}="{kind}"]')
    d.wait_for(timeout=3000)
    return d


# --- the share of a VM ---------------------------------------------------------------------------

def test_runtime_add_a_share_with_the_defaults(open_app):
    app = open_app()
    page = app.page
    card = _card(app)
    text = card.inner_text()
    for needle in ('Shared host directories (virtiofs)', 'No directory of the host is shared with this VM.',
                   'WinFsp', 'cannot be migrated live'):
        assert needle in text, needle
    assert 'Changes active after restart' not in text
    _shot(app, 'vfs_empty_modern')

    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    sel = d.locator('[data-vfs-mapping]')
    sel.wait_for(timeout=3000)
    assert sel.locator('option').all_inner_texts() == ['-- Choose a directory mapping --',
                                                        'backups (not on this node)', 'share - Media']
    save = d.locator('[data-vfs-save]')
    assert save.is_disabled() and d.locator('[data-vfs-problem="vfsPickMapping"]').is_visible()
    sel.select_option('share')
    detail = d.locator('[data-vfs-mapping-detail="share"]')
    assert 'Available on: pve1, pve2' in detail.inner_text() and 'pve1: /mnt/share' in detail.inner_text()
    assert d.locator('[data-vfs-cache]').input_value() == 'auto'
    assert d.locator('[data-vfs-cache] option').all_inner_texts() == ['auto (default)', 'always', 'metadata', 'never']
    assert not any(d.locator(f'[data-vfs-flag="{f}"] input').is_checked() for f in ('direct-io', 'expose-xattr', 'expose-acl'))
    assert save.inner_text() == 'Add' and save.is_enabled()
    _shot(app, 'vfs_add_modern')
    save.click()
    page.get_by_text('Share saved').first.wait_for(timeout=3000)
    assert _puts(app) == [{'virtiofs0': 'share'}]
    assert page.locator('[data-vfs-dialog]').count() == 0

    row = card.locator('[data-vfs-device="virtiofs0"]')
    row.wait_for(timeout=3000)
    assert row.locator('[data-vfs-shown-dirid]').inner_text() == 'share'
    assert row.locator('[data-vfs-shown-options]').inner_text() == 'cache=auto'
    assert row.locator('[data-vfs-shown-path]').inner_text() == 'pve1: /mnt/share'
    row.scroll_into_view_if_needed()
    _shot(app, 'vfs_set_modern')
    assert not app.errors, app.errors


def test_runtime_edit_reads_the_pve_spelling_and_acls_bring_xattr(open_app):
    app = open_app(raw={'virtiofs0': 'share', 'virtiofs3': 'dirid=backups,cache=never,expose-xattr=1'})
    card = _card(app)
    row = card.locator('[data-vfs-device="virtiofs3"]')
    row.wait_for(timeout=5000)
    assert row.locator('[data-vfs-shown-dirid]').inner_text() == 'backups'
    assert row.locator('[data-vfs-shown-options]').inner_text() == 'cache=never, expose-xattr'
    # backups has no directory on pve1, where the VM is
    row.locator('[data-vfs-off-node]').wait_for(timeout=3000)
    assert 'no directory on pve1' in row.inner_text()

    row.locator('[data-vfs-edit="virtiofs3"]').click()
    d = _dialog(app, 'edit')
    assert d.locator('[data-vfs-mapping]').input_value() == 'backups'
    assert d.locator('[data-vfs-off-node]').is_visible()
    assert d.locator('[data-vfs-cache]').input_value() == 'never'
    xattr, acl = d.locator('[data-vfs-flag="expose-xattr"] input'), d.locator('[data-vfs-flag="expose-acl"] input')
    assert xattr.is_checked() and not acl.is_checked()
    acl.check()
    assert xattr.is_checked() and xattr.is_disabled()
    assert 'ACLs bring the extended attributes with them.' in d.locator('[data-vfs-implied]').inner_text()
    d.locator('[data-vfs-flag="direct-io"] input').check()
    # another slot shares share already
    d.locator('[data-vfs-mapping]').select_option('share')
    assert 'already shares this directory as virtiofs0' in d.locator('[data-vfs-warning="twice"]').inner_text()
    d.locator('[data-vfs-mapping]').select_option('backups')
    _shot(app, 'vfs_edit_modern')
    save = d.locator('[data-vfs-save]')
    assert save.inner_text() == 'Save'
    save.click()
    app.page.get_by_text('Share saved').first.wait_for(timeout=3000)
    assert _puts(app) == [{'virtiofs3': 'backups,cache=never,direct-io=1,expose-acl=1,expose-xattr=1'}]
    row.locator('[data-vfs-shown-options]').filter(has_text='direct-io').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_a_windows_vm_takes_no_acls(open_app):
    app = open_app(raw={'ostype': 'win11'})
    card = _card(app)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-mapping]').select_option('share')
    d.locator('[data-vfs-flag="expose-acl"] input').check()
    problem = d.locator('[data-vfs-problem="vfsAclWindows"]')
    assert 'A Windows guest cannot mount the share with ACLs' in problem.inner_text()
    assert d.locator('[data-vfs-save]').is_disabled()
    d.locator('[data-vfs-flag="expose-acl"] input').uncheck()
    assert d.locator('[data-vfs-problem]').count() == 0 and d.locator('[data-vfs-save]').is_enabled()
    assert not app.errors, app.errors


def test_runtime_a_mapping_that_is_gone_is_said(open_app):
    app = open_app(raw={'virtiofs1': 'oldshare,cache=always'})
    card = _card(app)
    row = card.locator('[data-vfs-device="virtiofs1"]')
    row.locator('[data-vfs-gone]').wait_for(timeout=5000)
    assert 'The directory mapping oldshare does not exist' in row.inner_text()
    row.locator('[data-vfs-edit="virtiofs1"]').click()
    d = _dialog(app, 'edit')
    # kept as it is until another one is picked
    assert d.locator('[data-vfs-mapping]').input_value() == 'oldshare'
    assert d.locator('[data-vfs-cache]').input_value() == 'always'
    assert not app.errors, app.errors


def test_runtime_remove_asks_first(open_app):
    app = open_app(raw={'virtiofs0': 'share'})
    page = app.page
    card = _card(app)
    answers = []

    def dialog(d):
        answers.append(d.message)
        d.dismiss() if len(answers) == 1 else d.accept()
    page.on('dialog', dialog)
    card.locator('[data-vfs-remove="virtiofs0"]').click()
    page.wait_for_timeout(400)
    assert answers == ['Stop sharing share (virtiofs0) with this VM?'] and not _puts(app)
    card.locator('[data-vfs-remove="virtiofs0"]').click()
    page.get_by_text('Share removed').first.wait_for(timeout=3000)
    assert _puts(app) == [{'delete': 'virtiofs0'}]
    card.locator('[data-vfs-device]').first.wait_for(state='detached', timeout=3000)
    assert 'No directory of the host is shared' in card.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_confined_account_picks_only_the_vms_own(open_app):
    app = open_app(raw={'virtiofs0': 'backups'}, vm_dirs=_vm_dir_list(DIRS, may_add=False, only={'backups'}))
    card = _card(app)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-confined]').wait_for(timeout=3000)
    assert 'Sharing another one is a change for the whole cluster' in d.inner_text()
    assert d.locator('[data-vfs-mapping] option').all_inner_texts() == ['-- Choose a directory mapping --',
                                                                         'backups (not on this node)']
    assert d.locator('[data-vfs-no-mappings]').count() == 0
    assert not app.errors, app.errors


def test_runtime_an_older_pve_says_what_it_needs(open_app):
    app = open_app(vm_dirs={'kind': 'dir', 'node': 'pve1', 'supported': False, 'min_version': '8.4',
                            'mappings': [], 'may_add': False})
    card = _card(app)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-unsupported]').wait_for(timeout=3000)
    assert 'Proxmox VE 8.4 or newer' in d.inner_text()
    assert d.locator('[data-vfs-save]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_no_mapping_yet_says_where_to_make_one(open_app):
    app = open_app(dirs=[])
    card = _card(app)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-no-mappings]').wait_for(timeout=3000)
    assert 'Datacenter, Resource Mappings' in d.inner_text()
    assert d.locator('[data-vfs-save]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_a_refusal_keeps_the_dialog_open_with_the_reason(open_app):
    app = open_app(put_error='Invalid virtiofs: virtiofs0 names no directory mapping of this cluster (share)')
    page = app.page
    card = _card(app)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-mapping]').select_option('share')
    d.locator('[data-vfs-save]').click()
    page.get_by_text('names no directory mapping of this cluster').first.wait_for(timeout=3000)
    assert d.is_visible() and d.locator('[data-vfs-save]').is_enabled()
    assert card.locator('[data-vfs-device]').count() == 0
    assert not [e for e in app.errors if '400' not in e], app.errors


def test_runtime_a_running_vm_says_the_change_waits(open_app):
    app = open_app(resources=[dict(VM, status='running', uptime=3600)], raw={'virtiofs0': 'share'})
    card = _card(app)
    assert 'Changes active after restart' in card.inner_text()
    assert not app.errors, app.errors


def test_runtime_all_ten_slots_taken(open_app):
    app = open_app(raw={f'virtiofs{i}': 'share' for i in range(10)})
    card = _card(app)
    assert card.locator('[data-vfs-device]').count() == 10
    add = card.locator('[data-vfs-add]')
    assert add.is_disabled() and add.get_attribute('title') == 'All ten virtiofs slots are in use.'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'cloud'])
def test_runtime_the_share_in_the_other_layouts(open_app, layout):
    app = open_app(layout=layout)
    card = _card(app, layout=layout)
    card.locator('[data-vfs-add]').click()
    d = _dialog(app, 'add')
    d.locator('[data-vfs-mapping]').select_option('share')
    d.locator('[data-vfs-cache]').select_option('metadata')
    _shot(app, f'vfs_add_{layout}')
    d.locator('[data-vfs-save]').click()
    card.locator('[data-vfs-device="virtiofs0"]').wait_for(timeout=3000)
    assert _puts(app) == [{'virtiofs0': 'share,cache=metadata'}]
    card.scroll_into_view_if_needed()
    _shot(app, f'vfs_set_{layout}')
    assert not app.errors, app.errors


def test_runtime_the_share_in_german(open_app):
    app = open_app(language='de', raw={'virtiofs0': 'share,direct-io=1'})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Konfiguration"], button[title="Configuration"]').first.click()
    _tab(app, 'Hardware').click()
    card = page.locator('[data-vfs-card]')
    card.wait_for(timeout=5000)
    assert 'Geteilte Host-Verzeichnisse (virtiofs)' in card.inner_text()
    card.locator('[data-vfs-edit="virtiofs0"]').click()
    d = _dialog(app, 'edit')
    text = d.inner_text()
    for needle in ('Freigabe bearbeiten', 'Verzeichnis-Mapping', 'auto (Standard)', 'Erweiterte Attribute',
                   'Beachtet O_DIRECT', 'Speichern'):
        assert needle in text, needle
    assert not app.errors, app.errors


def test_runtime_a_standby_changes_no_share(open_app):
    app = open_app(role='standby', raw={'virtiofs0': 'share'})
    card = _card(app)
    assert app.page.locator('fieldset[data-ha-locked]').count() == 1
    for sel in ('[data-vfs-add]', '[data-vfs-edit="virtiofs0"]', '[data-vfs-remove="virtiofs0"]'):
        assert card.locator(sel).is_disabled(), sel
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/qemu/100/' in c[1]]
    assert not app.errors, app.errors


def test_runtime_an_xcpng_pool_has_no_virtiofs_card(open_app):
    app = open_app(clusters=[dict(CLUSTER, cluster_type='xcpng')])
    _open_config(app, 'web01')
    _tab(app, 'Hardware').click()
    app.page.get_by_text('Cloud-Init').first.wait_for(timeout=5000)
    assert app.page.locator('[data-vfs-card]').count() == 0
    # and asks nothing about mappings
    assert not [c for c in app.server.calls if 'mapping' in c[1]]


# --- the directory mappings of the datacenter ----------------------------------------------------

def _mappings(app, layout='modern'):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-shell').get_by_text('Resource Mappings', exact=True).first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Datacenter').first.click()
        page.locator('button', has_text='Resource Mappings').first.click()
    section = page.locator('[data-rm-section]')
    section.wait_for(timeout=8000)
    section.locator('[data-dm-row], [data-dm-none], [data-dm-error], [data-dm-unsupported]').first.wait_for(timeout=5000)
    return section


def test_runtime_the_mappings_list_their_paths_and_the_nodes_without(open_app):
    app = open_app()
    section = _mappings(app)
    share = section.locator('[data-dm-row="share"]')
    assert share.locator('[data-dm-entry="pve1"]').inner_text() == 'pve1: /mnt/share'
    assert share.locator('[data-dm-entry="pve2"]').inner_text() == 'pve2: /srv/share'
    assert 'No directory on pve3: VMs with this share do not start there.' == share.locator('[data-dm-missing]').inner_text()
    assert 'Media' in share.inner_text()
    backups = section.locator('[data-dm-row="backups"]')
    assert 'No directory on pve1, pve3' in backups.locator('[data-dm-missing]').inner_text()
    # PCI and USB to look at
    pci = section.locator('[data-rm-row="pci:gpu0"]')
    assert 'gpu0' in pci.inner_text() and 'pve1, pve2' in pci.inner_text()
    assert 'No USB resource mappings' in section.locator('[data-rm-none="usb"]').inner_text()
    assert 'every VM given the mapping can read and change everything in it'.lower() in section.inner_text().lower()
    _shot(app, 'dm_list_modern')
    assert not app.errors, app.errors


def test_runtime_add_a_mapping_and_what_the_dialog_refuses(open_app):
    app = open_app()
    page = app.page
    section = _mappings(app)
    section.locator('[data-dm-add]').click()
    d = _dialog(app, 'add', 'data-dm-dialog')
    save = d.locator('[data-dm-save]')
    # an id first, then a path for the node it starts with
    assert d.locator('[data-dm-node="0"]').input_value() == 'pve1'
    assert d.locator('[data-dm-problem="dmBadId"]').is_visible() and save.is_disabled()
    d.locator('[data-dm-id]').fill('1media')
    assert d.locator('[data-dm-problem="dmBadId"]').is_visible()
    d.locator('[data-dm-id]').fill('media')
    assert d.locator('[data-dm-problem="dmBadPath"]').is_visible()
    for bad in ('srv/media', '/', '/srv/a,b', '/srv/a=b', '/srv/(x)', '/srv/../etc', '/srv/media '):
        d.locator('[data-dm-path="0"]').fill(bad)
        assert d.locator('[data-dm-problem="dmBadPath"]').is_visible(), bad
        assert save.is_disabled(), bad
    d.locator('[data-dm-path="0"]').fill('/etc/pve')
    assert 'every VM given this mapping can change the node itself' in d.locator('[data-dm-warning="system"]').inner_text()
    assert save.is_enabled()
    d.locator('[data-dm-path="0"]').fill('/srv/media')
    assert d.locator('[data-dm-warning]').count() == 0
    # a second node, the same node twice is refused
    d.locator('[data-dm-add-entry]').click()
    assert d.locator('[data-dm-node="1"]').input_value() == 'pve2'
    assert d.locator('[data-dm-path="1"]').input_value() == '/srv/media'
    d.locator('[data-dm-node="1"]').select_option('pve1')
    assert d.locator('[data-dm-problem="dmNodeTwice"]').is_visible() and save.is_disabled()
    d.locator('[data-dm-node="1"]').select_option('pve2')
    d.locator('[data-dm-path="1"]').fill('/data/my media')
    d.locator('[data-dm-description]').fill('Photos')
    assert d.locator('[data-dm-problem]').count() == 0 and save.is_enabled()
    _shot(app, 'dm_add_modern')
    save.click()
    page.get_by_text('Directory mapping saved').first.wait_for(timeout=3000)
    assert _puts(app, DIR) == [{'id': 'media', 'description': 'Photos',
                                'map': [{'node': 'pve1', 'path': '/srv/media'}, {'node': 'pve2', 'path': '/data/my media'}]}]
    row = section.locator('[data-dm-row="media"]')
    row.wait_for(timeout=3000)
    assert row.locator('[data-dm-entry="pve2"]').inner_text() == 'pve2: /data/my media'
    assert not app.errors, app.errors


def test_runtime_edit_and_remove_a_mapping(open_app):
    app = open_app()
    page = app.page
    section = _mappings(app)
    section.locator('[data-dm-edit="share"]').click()
    d = _dialog(app, 'edit', 'data-dm-dialog')
    assert d.locator('[data-dm-id]').is_disabled() and d.locator('[data-dm-id]').input_value() == 'share'
    assert d.locator('[data-dm-path="1"]').input_value() == '/srv/share'
    d.locator('[data-dm-remove-entry="1"]').click()
    d.locator('[data-dm-description]').fill('')
    d.locator('[data-dm-save]').click()
    page.get_by_text('Directory mapping saved').first.wait_for(timeout=3000)
    assert _puts(app, f'{DIR}/share') == [{'description': '', 'map': [{'node': 'pve1', 'path': '/mnt/share'}],
                                          'digest': 'abc1'}]
    section.locator('[data-dm-row="share"] [data-dm-missing]').filter(has_text='pve2').wait_for(timeout=3000)

    answers = []

    def dialog(dlg):
        answers.append(dlg.message)
        dlg.dismiss() if len(answers) == 1 else dlg.accept()
    page.on('dialog', dialog)
    section.locator('[data-dm-delete="backups"]').click()
    page.wait_for_timeout(400)
    assert answers[0].startswith('Remove the directory mapping backups? VMs that share it do not start')
    assert not [c for c in app.server.calls if c[0] == 'DELETE']
    section.locator('[data-dm-delete="backups"]').click()
    page.get_by_text('Directory mapping removed').first.wait_for(timeout=3000)
    assert ('DELETE', f'{DIR}/backups') in app.server.calls
    section.locator('[data-dm-row="backups"]').wait_for(state='detached', timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'cloud'])
def test_runtime_the_mappings_in_the_other_layouts(open_app, layout):
    app = open_app(layout=layout)
    section = _mappings(app, layout)
    section.locator('[data-dm-row="share"]').wait_for(timeout=3000)
    _shot(app, f'dm_list_{layout}')
    section.locator('[data-dm-add]').click()
    d = _dialog(app, 'add', 'data-dm-dialog')
    d.locator('[data-dm-id]').fill('media')
    d.locator('[data-dm-path="0"]').fill('/srv/media')
    _shot(app, f'dm_add_{layout}')
    d.locator('[data-dm-save]').click()
    section.locator('[data-dm-row="media"]').wait_for(timeout=3000)
    assert _puts(app, DIR) == [{'id': 'media', 'description': '', 'map': [{'node': 'pve1', 'path': '/srv/media'}]}]
    assert not app.errors, app.errors


def test_runtime_the_mappings_in_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Ressourcen-Mappings').first.click()
    section = page.locator('[data-rm-section]')
    section.locator('[data-dm-row="share"]').wait_for(timeout=5000)
    text = section.inner_text()
    for needle in ('Verzeichnisse', 'PCI-Geräte', 'USB-Geräte', 'Kein Verzeichnis auf pve3'):
        assert needle in text, needle
    section.locator('[data-dm-add]').click()
    d = _dialog(app, 'add', 'data-dm-dialog')
    for needle in ('Verzeichnis-Mapping hinzufügen', 'Verzeichnis je Node', 'Node hinzufügen'):
        assert needle in d.inner_text(), needle
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_mappings_without_changing_them(open_app):
    app = open_app(role='standby')
    section = _mappings(app)
    section.locator('[data-dm-row="share"]').wait_for(timeout=3000)
    assert section.locator('[data-dm-add], [data-dm-edit], [data-dm-delete]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'mapping' in c[1]]
    assert not app.errors, app.errors


def test_runtime_an_older_pve_and_a_refused_list(open_app):
    app = open_app(dir_error=(200, {'supported': False, 'min_version': '8.4', 'mappings': [], 'nodes': [], 'digest': ''}))
    section = _mappings(app)
    assert 'Proxmox VE 8.4 or newer' in section.locator('[data-dm-unsupported]').inner_text()
    assert section.locator('[data-dm-add]').count() == 0
    app2 = open_app(dir_error=(403, {'error': 'Access denied: this action affects the whole cluster'}))
    section = _mappings(app2)
    assert 'affects the whole cluster' in section.locator('[data-dm-error]').inner_text()
    assert section.locator('[data-dm-add]').count() == 0
    assert not [e for e in app2.errors if '403' not in e], app2.errors


# --- the migrate dialog ----------------------------------------------------------------------------

def _migrate(app, layout='modern'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Migrate"]').first.click()
    modal = page.locator('div.fixed', has=page.get_by_text('Target Node', exact=False)).last
    modal.wait_for(timeout=5000)
    return modal


def _migrate_button(modal):
    return modal.get_by_role('button', name='Migrate', exact=True)


def test_runtime_a_running_vm_with_a_share_is_not_migrated_live(open_app):
    app = open_app(resources=[dict(VM, status='running', uptime=3600)], raw={'virtiofs0': 'share'})
    modal = _migrate(app)
    box = modal.locator('[data-mig-vfs="running"]')
    box.wait_for(timeout=5000)
    assert 'cannot be migrated live. Shut it down first' in box.inner_text()
    assert 'virtiofs0: share' in box.inner_text()
    modal.locator('select').first.select_option('pve2')
    assert _migrate_button(modal).is_disabled()
    _shot(app, 'vfs_migrate_running')
    assert not [c for c in app.server.calls if c[1].endswith('/migrate')]
    assert not app.errors, app.errors


def test_runtime_a_stopped_vm_goes_only_where_its_directories_are(open_app):
    app = open_app(raw={'virtiofs0': 'share'})
    modal = _migrate(app)
    box = modal.locator('[data-mig-vfs="stopped"]')
    box.wait_for(timeout=5000)
    assert 'The target node needs a directory in each of these directory mappings.' in box.inner_text()
    target = modal.locator('select').first
    target.select_option('pve3')
    box.locator('[data-mig-vfs-missing]').wait_for(timeout=3000)
    assert box.locator('[data-mig-vfs-missing]').inner_text() == 'pve3 has no directory for share, so Proxmox would refuse the migration.'
    assert _migrate_button(modal).is_disabled()
    target.select_option('pve2')
    assert box.locator('[data-mig-vfs-missing]').count() == 0
    assert _migrate_button(modal).is_enabled()
    _shot(app, 'vfs_migrate_stopped')
    assert not app.errors, app.errors


def test_runtime_a_vm_without_a_share_migrates_as_before(open_app):
    app = open_app(resources=[dict(VM, status='running', uptime=3600)])
    modal = _migrate(app)
    modal.locator('select').first.select_option('pve2')
    assert _migrate_button(modal).is_enabled()
    assert modal.locator('[data-mig-vfs]').count() == 0
    assert not [c for c in app.server.calls if 'mapping' in c[1]]
    assert not app.errors, app.errors


def test_runtime_the_migrate_warning_in_corporate(open_app):
    app = open_app(layout='corporate', resources=[dict(VM, status='running', uptime=3600)], raw={'virtiofs2': 'backups'})
    modal = _migrate(app, 'corporate')
    modal.locator('[data-mig-vfs="running"]').wait_for(timeout=5000)
    assert 'virtiofs2: backups' in modal.inner_text()
    _shot(app, 'vfs_migrate_corporate')
    assert not app.errors, app.errors


# --- the source ----------------------------------------------------------------------------------

def _src(name):
    return _read('web', 'src', name)


def _new_code():
    cfg, dc, modals, cloud = _src('vm_config.js'), _src('datacenter.js'), _src('vm_modals.js'), _src('cloud.js')
    parts = [cfg[cfg.index('// LW Oct 2026 - virtiofs, a directory of the host'):cfg.index('function ConfigModal(')],
             dc[dc.index('// LW Oct 2026 - the resource mappings of a cluster'):dc.index('// Datacenter Tab Component')]]
    start = modals.index('function MigrateModal(')
    parts.append(modals[start:modals.index('// Bulk Migrate Modal Component')])
    for marker in ('<VirtiofsCard', '<VirtiofsDialog'):
        i = cfg.index(marker)
        parts.append(cfg[i:i + 1500])
    i = cloud.index("case 'mappings':")
    parts.append(cloud[i:i + 300])
    return parts


def _keys():
    keys = set()
    for name in ('vm_config.js', 'datacenter.js', 'vm_modals.js', 'cloud.js'):
        keys |= set(re.findall(r"'((?:vfs|dm|rm|migVfs)[A-Z]\w+)'", _src(name)))
    return keys


def test_every_new_string_is_in_all_nine_languages_once():
    tr = _src('translations.js')
    keys = _keys()
    assert len(keys) == 63, sorted(keys)
    en = {}
    for key in keys:
        lines = re.findall(r'^\s*' + key + r':\s*(.+)$', tr, re.M)
        assert len(lines) == len(LANGS), key
        assert not [x for x in lines if '\u2014' in x or '\u2013' in x], key
        en[key] = lines
    # the placeholders survive the translation
    for key, lines in en.items():
        holders = [set(re.findall(r'\{[a-z]+\}', line)) for line in lines]
        assert all(h == holders[0] for h in holders), key
    for key, holder in (('vfsNotHere', '{node}'), ('vfsGone', '{id}'), ('vfsSameTwice', '{key}'),
                        ('vfsRemoveConfirm', '{key}'), ('dmMissingNodes', '{nodes}'), ('dmDeleteConfirm', '{id}'),
                        ('migVfsMissing', '{ids}')):
        assert all(holder in line for line in en[key]), key


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _src('contexts.js')


def test_no_em_dash_in_the_new_code():
    for part in _new_code():
        assert '\u2014' not in part and '\u2013' not in part


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _src('icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    used.add('Link')   # the datacenter and Cloud entries name it
    assert used and used <= icons, sorted(used - icons)


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('data-vfs-card', 'data-vfs-dialog', 'data-dm-dialog', 'data-rm-section', 'data-mig-vfs',
                   'vfsRemoveConfirm', 'dmDeleteConfirm', 'migVfsMissing', 'function ResourceMappingsSection'):
        assert needle in bundle, needle
