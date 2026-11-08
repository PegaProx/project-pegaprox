"""Container features and mapped passthrough in the configuration modal, at runtime.

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py; the routes behind it are tested in test_lxc_features_passthrough.py.
Modern, Corporate and Cloud all open the same ConfigModal, so each layout gets the card
once, and Modern takes the scenarios. Skips where Playwright is not installed.
LW Oct 2026
"""
import json
import os

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, VM_CONFIG, _read, LANGS  # noqa: F401

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')

CT = {'vmid': 101, 'name': 'ct101', 'type': 'lxc', 'status': 'running', 'node': 'pve1',
      'cpu': 0.01, 'cpu_percent': 1, 'maxcpu': 2, 'mem': 268435456, 'maxmem': 1073741824,
      'mem_percent': 25, 'disk': 0, 'maxdisk': 8589934592, 'uptime': 3600}
VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'stopped', 'node': 'pve1',
      'cpu': 0, 'cpu_percent': 0, 'maxcpu': 2, 'mem': 0, 'maxmem': 4294967296,
      'mem_percent': 0, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 0}
CT_CONFIG = {'general': {'hostname': 'ct101', 'description': '', 'tags': '', 'ostype': 'debian', 'arch': 'amd64'},
             'hardware': {'cores': 2, 'cpulimit': 0, 'cpuunits': 1024, 'memory': 1024, 'swap': 512},
             'options': {'onboot': 0, 'protection': 0, 'unprivileged': 1, 'features': 'nesting=1',
                         'startup': '', 'nameserver': '', 'searchdomain': ''},
             'disks': [{'id': 'rootfs', 'value': 'local-lvm:vm-101-disk-0,size=8G', 'storage': 'local-lvm', 'size': '8G'}],
             'networks': [], 'unused_disks': [], 'raw': {'hostname': 'ct101', 'digest': 'x'},
             'status': {'status': 'running'}, 'vmid': 101, 'node': 'pve1', 'type': 'lxc', 'lock': {'locked': False}}
FEATURES_URL = '/api/clusters/c1/vms/pve1/lxc/101/features'
TOKEN = {'via': 'token', 'root': False, 'fresh_ticket': False, 'reason': 'token'}
MINTED = {'via': 'token', 'root': True, 'fresh_ticket': True, 'reason': None}


def _features(access, unprivileged=True, pending=False, kept=()):
    flags = {'nesting': True, 'keyctl': False, 'fuse': False, 'mknod': False, 'mount': {'nfs': False, 'cifs': False}}
    return {'features': flags, 'current': flags, 'kept': list(kept), 'raw': 'nesting=1', 'pending': pending,
            'unprivileged': unprivileged, 'access': access}


def _ct_extra(access, **kw):
    return {('GET', '/api/clusters/c1/vms/pve1/lxc/101/config'): (200, CT_CONFIG),
            ('GET', FEATURES_URL): (200, _features(access, **kw)),
            ('PUT', FEATURES_URL): (200, {'success': True, 'changed': True, 'pending': True, 'root_login': False})}


MAPPINGS = [
    {'id': 'gpu0', 'description': 'RTX 4000', 'nodes': ['pve1', 'pve2'],
     'entries': [{'node': 'pve1', 'path': '0000:01:00.0', 'id': '10de:1b80', 'description': ''},
                 {'node': 'pve2', 'path': '0000:41:00.0', 'id': '10de:1b80', 'description': ''}],
     'on_node': True, 'mdev': False, 'live_migration': False, 'checks': []},
    {'id': 'nic3', 'description': 'X710 on pve3', 'nodes': ['pve3'],
     'entries': [{'node': 'pve3', 'path': '0000:05:00.0', 'id': '8086:1572', 'description': ''}],
     'on_node': False, 'mdev': False, 'live_migration': False, 'checks': []},
]
VM_URL = '/api/clusters/c1/vms/pve1/qemu/100'


def _vm_extra(access, mappings=MAPPINGS, devices=None):
    return {('GET', f'{VM_URL}/config'): (200, dict(VM_CONFIG, status={'status': 'stopped'})),
            ('GET', f'{VM_URL}/passthrough'): (200, devices or {'pci': [], 'usb': [], 'serial': []}),
            ('GET', '/api/clusters/c1/nodes/pve1/hardware/pci'): (200, [
                {'id': '0000:01:00.0', 'vendor_name': 'NVIDIA', 'device_name': 'RTX 4000', 'iommugroup': 12}]),
            ('GET', '/api/clusters/c1/nodes/pve1/hardware/usb'): (200, []),
            ('GET', f'{VM_URL}/passthrough/mappings'): (200, {'kind': 'pci', 'node': 'pve1', 'mappings': mappings,
                                                              'raw_allowed': access['root'], 'access': access}),
            ('POST', f'{VM_URL}/passthrough/pci'): (200, {'message': 'PCI device added at hostpci0', 'slot': 0,
                                                          'mapping': 'gpu0', 'nodes': ['pve1', 'pve2'],
                                                          'covers_node': True})}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _open_config(app, name, layout='modern'):
    page = app.page
    if layout == 'cloud':
        page.get_by_text('Containers' if name == 'ct101' else 'Virtual Machines').first.click()
        page.get_by_text(name).first.wait_for(timeout=5000)
        page.get_by_text(name).first.click()
        page.locator('.cloud-detail-actions button', has_text='Actions').click()
        page.get_by_text('Edit', exact=True).first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Resources').first.click()
        page.get_by_text(name).first.wait_for(timeout=5000)
        page.wait_for_timeout(300)
        page.locator('button[title="Configuration"]').first.click()
    _tab(app, 'Options').wait_for(timeout=8000)


def _tab(app, label):
    # the modal comes last in the page, after the views behind it
    return app.page.get_by_role('button', name=label, exact=True).last


def _options(app, label='Options'):
    _tab(app, label).click()
    card = app.page.locator('[data-ct-features]')
    card.locator('[data-ct-feature="nesting"]').wait_for(timeout=5000)
    return card


# --- container features -----------------------------------------------------------------

def test_runtime_a_token_cluster_changes_nesting_and_explains_the_rest(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[CT], extra=_ct_extra(TOKEN))
    page = app.page
    _open_config(app, 'ct101')
    card = _options(app)
    text = card.inner_text()
    for needle in ('Features', 'Nesting', 'keyctl', 'FUSE', 'Create device nodes', 'NFS mounts', 'SMB/CIFS mounts',
                   'NEEDS RESTART'):
        assert needle in text, needle
    # the flags only root@pam may change are locked, with the reason beside them
    assert card.locator('[data-ct-feature="nesting"] input').is_enabled()
    for key in ('keyctl', 'fuse', 'mknod', 'nfs', 'cifs'):
        assert card.locator(f'[data-ct-feature="{key}"] input').is_disabled(), key
        assert 'root@pam' in card.locator(f'[data-ct-feature="{key}"]').inner_text(), key
    note = card.locator('[data-ct-features-root="token"]')
    assert 'connected with an API token' in note.inner_text()
    assert 'nesting is the one exception' in note.inner_text()
    apply = card.locator('[data-ct-features-apply]')
    assert apply.is_disabled()
    _shot(app, 'ct_features_token_modern')

    card.locator('[data-ct-feature="nesting"] input').uncheck()
    assert apply.is_enabled()
    apply.click()
    page.get_by_text('Features saved - they take effect when the container starts again').first.wait_for(timeout=3000)
    assert [b for b in app.server.bodies[FEATURES_URL] if b][-1] == {'nesting': False}
    # its own save, not the modal's
    assert ('PUT', '/api/clusters/c1/vms/pve1/lxc/101/config') not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_minted_token_cluster_says_it_logs_in_as_root(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[CT],
                   extra=_ct_extra(MINTED, pending=True, kept=['force_rw_sys=1']))
    _open_config(app, 'ct101')
    card = _options(app)
    assert card.locator('[data-ct-features-root]').count() == 0
    assert 'A change waits for the next start of the container.' in card.inner_text()
    assert 'force_rw_sys=1' in card.inner_text()
    for key in ('keyctl', 'nfs'):
        card.locator(f'[data-ct-feature="{key}"] input').check()
    assert 'Done through a root@pam login of its own' in card.inner_text()
    _shot(app, 'ct_features_root_login_modern')
    card.locator('[data-ct-features-apply]').click()
    app.page.wait_for_timeout(600)
    assert [b for b in app.server.bodies[FEATURES_URL] if b][-1] == {'keyctl': True, 'mount': {'nfs': True}}
    assert not app.errors, app.errors


def test_runtime_a_privileged_container_names_why(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[CT],
                   extra=_ct_extra(TOKEN, unprivileged=False))
    _open_config(app, 'ct101')
    card = _options(app)
    assert card.locator('[data-ct-feature="nesting"] input').is_disabled()
    assert 'This is a privileged container' in card.locator('[data-ct-features-root]').inner_text()
    assert not app.errors, app.errors


def test_runtime_the_features_card_in_german(open_app):
    app = open_app(role='standalone', layout='modern', language='de', clusters=[CLUSTER], resources=[CT],
                   extra=_ct_extra(TOKEN))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('ct101').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Konfiguration"], button[title="Configuration"]').first.click()
    _tab(app, 'Optionen').wait_for(timeout=8000)
    card = _options(app, 'Optionen')
    text = card.inner_text()
    assert 'Geräteknoten anlegen' in text and 'Features übernehmen' in text
    assert 'API-Token' in card.locator('[data-ct-features-root]').inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['corporate', 'cloud'])
def test_runtime_the_features_card_in_the_other_layouts(open_app, layout):
    app = open_app(role='standalone', layout=layout, clusters=[CLUSTER], resources=[CT], extra=_ct_extra(MINTED))
    _open_config(app, 'ct101', layout=layout)
    card = _options(app)
    card.locator('[data-ct-feature="fuse"] input').check()
    assert card.locator('[data-ct-features-apply]').is_enabled()
    _shot(app, f'ct_features_{layout}')
    card.locator('[data-ct-features-apply]').click()
    app.page.wait_for_timeout(600)
    assert [b for b in app.server.bodies[FEATURES_URL] if b][-1] == {'fuse': True}
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_features_and_changes_none(open_app):
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[CT], extra=_ct_extra(MINTED))
    _open_config(app, 'ct101')
    card = _options(app)
    assert app.page.locator('fieldset[data-ha-locked]').count() == 1
    assert card.locator('[data-ct-feature="fuse"] input').is_disabled()
    assert card.locator('[data-ct-features-apply]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/lxc/101/' in c[1]]
    assert not app.errors, app.errors


# --- passthrough ------------------------------------------------------------------------------

def _open_add_pci(app, layout='modern'):
    page = app.page
    _open_config(app, 'web01', layout=layout)
    _tab(app, 'Hardware').click()
    page.locator('button', has_text='Add PCI').last.click()
    page.locator('[data-pt-mode="mapping"]').wait_for(timeout=5000)


def test_runtime_the_pci_dialog_offers_mappings_first(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], extra=_vm_extra(TOKEN))
    page = app.page
    _open_add_pci(app)
    page.locator('[data-pt-mapping-select="pci"]').wait_for(timeout=5000)
    assert 'bg-proxmox-orange' in page.locator('[data-pt-mode="mapping"]').get_attribute('class')
    add = page.locator('[data-pt-add="pci"]')
    assert add.is_disabled()
    options = page.locator('[data-pt-mapping-select="pci"] option').all_inner_texts()
    assert any(o.startswith('gpu0 - RTX 4000') for o in options), options
    assert any('nic3' in o and 'not on this node' in o for o in options), options

    page.select_option('[data-pt-mapping-select="pci"]', 'nic3')
    assert 'This mapping has no device on pve1' in page.locator('[data-pt-mapping-detail="nic3"]').inner_text()
    page.select_option('[data-pt-mapping-select="pci"]', 'gpu0')
    detail = page.locator('[data-pt-mapping-detail="gpu0"]').inner_text()
    assert 'Available on: pve1, pve2' in detail and '0000:01:00.0' in detail
    assert 'starts and migrates only on the nodes the mapping covers' in page.locator('body').inner_text()
    _shot(app, 'pt_mapping_modern')
    add.click()
    page.get_by_text('Device added').first.wait_for(timeout=3000)
    assert app.server.bodies[f'{VM_URL}/passthrough/pci'][-1] == {'mapping': 'gpu0', 'pcie': True, 'rombar': True}

    # a raw device needs root@pam, which a token cluster is not
    page.locator('button', has_text='Add PCI').last.click()
    page.locator('[data-pt-mode="raw"]').click()
    refused = page.locator('[data-pt-raw-refused="token"]')
    refused.wait_for(timeout=3000)
    assert 'only root@pam attach or remove a raw device' in refused.inner_text()
    assert page.locator('[data-pt-add="pci"]').is_disabled()
    _shot(app, 'pt_raw_refused_modern')
    assert not app.errors, app.errors


def test_runtime_no_mapping_and_root_opens_on_the_raw_device(open_app):
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra=_vm_extra(MINTED, mappings=[]))
    page = app.page
    _open_add_pci(app)
    page.locator('select', has_text='RTX 4000').first.wait_for(timeout=5000)
    assert 'bg-proxmox-orange' in page.locator('[data-pt-mode="raw"]').get_attribute('class')
    assert 'Done through a root@pam login of its own' in page.locator('body').inner_text()
    page.locator('[data-pt-mode="mapping"]').click()
    assert 'No PCI resource mappings in this cluster yet' in page.locator('[data-pt-no-mappings]').inner_text()
    assert not app.errors, app.errors


def test_runtime_an_attached_mapping_names_its_nodes(open_app):
    devices = {'pci': [{'slot': '0', 'key': 'hostpci0', 'value': 'mapping=gpu0,pcie=1',
                        'parsed': {'device': None, 'mapping': 'gpu0', 'options': {'pcie': '1'}}}],
               'usb': [], 'serial': []}
    app = open_app(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                   extra=_vm_extra(TOKEN, devices=devices))
    page = app.page
    _open_config(app, 'web01')
    _tab(app, 'Hardware').click()
    line = page.locator('[data-pt-mapped="gpu0"]')
    line.wait_for(timeout=5000)
    page.wait_for_function('() => document.querySelector("[data-pt-mapped=gpu0]").innerText.includes("pve2")', timeout=5000)
    assert 'Available on: pve1, pve2' in line.inner_text()
    assert not app.errors, app.errors


def test_runtime_the_pci_dialog_in_corporate(open_app):
    app = open_app(role='standalone', layout='corporate', clusters=[CLUSTER], resources=[VM], extra=_vm_extra(TOKEN))
    page = app.page
    _open_add_pci(app, layout='corporate')
    page.select_option('[data-pt-mapping-select="pci"]', 'gpu0')
    page.locator('[data-pt-mapping-detail="gpu0"]').wait_for(timeout=3000)
    # the corporate modal fades in; a shot taken at once caught an empty frame
    page.wait_for_timeout(400)
    _shot(app, 'pt_mapping_corporate')
    page.locator('[data-pt-add="pci"]').click()
    page.wait_for_timeout(600)
    assert app.server.bodies[f'{VM_URL}/passthrough/pci'][-1]['mapping'] == 'gpu0'
    assert not app.errors, app.errors


def test_runtime_a_standby_adds_no_device(open_app):
    app = open_app(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM], extra=_vm_extra(MINTED))
    page = app.page
    _open_config(app, 'web01')
    _tab(app, 'Hardware').click()
    add = page.locator('button', has_text='Add PCI').last
    add.wait_for(timeout=5000)
    assert add.is_disabled()
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/qemu/100/' in c[1]]
    assert not app.errors, app.errors


# --- the source --------------------------------------------------------------------------------

def test_every_new_string_is_in_all_nine_languages():
    import re
    tr = _read('web', 'src', 'translations.js')
    src = _read('web', 'src', 'vm_config.js')
    # every quoted key of the two features, wherever t() gets it from
    keys = set(re.findall(r"'((?:ctFeat|pveRoot|pt[A-Z])\w+)'", src))
    assert len(keys) >= 35, sorted(keys)
    for key in keys:
        assert len(re.findall(r'^\s*' + key + r':', tr, re.M)) == len(LANGS), key


def test_the_bundle_carries_both_features():
    bundle = _read('web', 'index.html')
    for needle in ('data-ct-features-apply', 'data-pt-mapping-select', '/passthrough/mappings?kind=', 'ptRawRootOnly'):
        assert needle in bundle, needle
