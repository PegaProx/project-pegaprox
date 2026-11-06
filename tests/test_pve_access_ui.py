"""The "Proxmox users" section of the datacenter (web/src/datacenter.js, PveAccessSection):
the users, groups, roles, permissions and realms of Proxmox VE itself, at runtime in headless
Chromium against the fake server of tests/test_ha_ui.py, plus the static checks the other
sections have. The server side is tested in test_pve_access.py. Skips without Playwright.
"""
import json
import re

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, _read, _classes, LANGS  # noqa: F401

B = '/api/clusters/c1/pve-access'


def _state():
    return {
        'users': [{'userid': 'root@pam', 'enable': 1, 'expire': 0, 'firstname': '', 'lastname': '', 'email': '',
                   'comment': '', 'groups': [], 'realm_type': 'pam', 'tokens': [], 'protected': True},
                  {'userid': 'anna@pve', 'enable': 1, 'expire': 0, 'firstname': 'Anna', 'lastname': 'K',
                   'email': 'a@x.ru', 'comment': '', 'groups': ['ops'], 'realm_type': 'pve', 'tokens': ['ci'],
                   'protected': False}],
        'groups': [{'groupid': 'ops', 'comment': 'Admins', 'users': ['anna@pve']}],
        'roles': [{'roleid': 'Administrator', 'privs': ['Sys.Audit', 'VM.Audit'], 'special': True},
                  {'roleid': 'PVEVMUser', 'privs': ['VM.Audit', 'VM.PowerMgmt'], 'special': True},
                  {'roleid': 'Backup', 'privs': ['VM.Backup'], 'special': False}],
        'acl': [{'path': '/', 'type': 'user', 'ugid': 'root@pam', 'roleid': 'Administrator', 'propagate': 1},
                {'path': '/vms/100', 'type': 'group', 'ugid': 'ops', 'roleid': 'PVEVMUser', 'propagate': 1}],
        'realms': [{'realm': 'pam', 'type': 'pam', 'comment': 'Linux PAM', 'default': False, 'tfa': ''},
                   {'realm': 'pve', 'type': 'pve', 'comment': '', 'default': True, 'tfa': ''}],
        'privileges': ['Sys.Audit', 'VM.Audit', 'VM.Backup', 'VM.PowerMgmt'],
    }


class _AccessServer(_FakeServer):
    """The fake server with the access data of a cluster that the writes change."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.access = _state()
        self.writes = []
        self._publish()

    def _publish(self):
        self.extra[('GET', B)] = (200, json.loads(json.dumps(self.access)))

    def handle(self, route):
        req = route.request
        path = req.url.split('?')[0]
        rel = path[path.index('/api/'):] if '/api/' in path else path
        if rel.startswith(B + '/') and req.method in ('POST', 'PUT', 'DELETE'):
            body = json.loads(req.post_data or '{}') if req.post_data else {}
            self.writes.append((req.method, rel[len(B):], body))
            a = self.access
            if (req.method, rel) == ('POST', B + '/users'):
                a['users'].append({'userid': body['userid'], 'enable': 1, 'expire': 0, 'firstname': body.get('firstname', ''),
                                   'lastname': body.get('lastname', ''), 'email': body.get('email', ''), 'comment': '',
                                   'groups': body.get('groups', []), 'realm_type': 'pve', 'tokens': [], 'protected': False})
            elif req.method == 'DELETE' and rel.startswith(B + '/users/'):
                uid = rel.rsplit('/', 1)[1].replace('%40', '@')
                a['users'] = [u for u in a['users'] if u['userid'] != uid]
            elif rel == B + '/acl':
                if body.get('delete'):
                    a['acl'] = [x for x in a['acl'] if not (x['path'] == body['path'] and x['roleid'] in body['roles'])]
                else:
                    for kind, key in (('user', 'users'), ('group', 'groups'), ('token', 'tokens')):
                        for ugid in body.get(key, []):
                            a['acl'].append({'path': body['path'], 'type': kind, 'ugid': ugid,
                                             'roleid': body['roles'][0], 'propagate': int(body.get('propagate', True))})
            self._publish()
            self.extra[(req.method, rel)] = (200, {'success': True})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        app = _App(browser, _AccessServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _datacenter(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()


def _section(app):
    _datacenter(app)
    app.page.locator('button', has_text='Proxmox users').first.click()
    section = app.page.locator('[data-pva-section]')
    section.wait_for(timeout=8000)
    section.locator('[data-pva-user], [data-pva-error]').first.wait_for(timeout=5000)
    return section


def test_runtime_lists_users_and_protects_root(open_app):
    app = open_app()
    section = _section(app)
    anna = section.locator('[data-pva-user="anna@pve"]')
    assert 'Anna K' in anna.inner_text() and 'ops' in anna.inner_text() and 'ci' in anna.inner_text()
    assert section.locator('[data-pva-delete-user="root@pam"]').count() == 0
    assert section.locator('[data-pva-password-user="root@pam"]').count() == 0
    assert section.locator('[data-pva-delete-user="anna@pve"]').count() == 1
    for tab, row in (('groups', '[data-pva-grouprow="ops"]'), ('roles', '[data-pva-rolerow="Backup"]'),
                     ('acl', '[data-pva-acl="/vms/100|ops|PVEVMUser"]'), ('realms', '[data-pva-realm="pve"]')):
        section.locator(f'[data-pva-tab="{tab}"]').click()
        section.locator(row).wait_for(timeout=3000)
    # built-in roles have no buttons, your own do
    section.locator('[data-pva-tab="roles"]').click()
    assert section.locator('[data-pva-rolerow="Administrator"] button').count() == 0
    assert section.locator('[data-pva-rolerow="Backup"] button').count() == 2
    assert not app.errors, app.errors


def test_runtime_add_a_user_with_a_group(open_app):
    app = open_app()
    section = _section(app)
    section.locator('[data-pva-add="users"]').click()
    d = app.page.locator('[data-pva-dialog]')
    save = d.locator('[data-pva-save]')
    assert save.is_disabled()
    d.locator('[data-pva-userid]').fill('ivan')
    assert 'name@realm' in d.locator('[data-pva-problem]').inner_text()
    d.locator('[data-pva-userid]').fill('ivan@pve')
    d.locator('[data-pva-password]').fill('short')
    assert '8 characters' in d.locator('[data-pva-problem]').inner_text()
    d.locator('[data-pva-password]').fill('Secret123!')
    d.locator('[data-pva-group="ops"]').check()
    assert save.is_enabled()
    save.click()
    section.locator('[data-pva-user="ivan@pve"]').wait_for(timeout=3000)
    method, path, body = app.server.writes[-1]
    assert (method, path) == ('POST', '/users')
    assert body['userid'] == 'ivan@pve' and body['password'] == 'Secret123!' and body['groups'] == ['ops']
    assert not app.errors, app.errors


def test_runtime_a_password_only_for_the_pve_realm(open_app):
    app = open_app()
    section = _section(app)
    section.locator('[data-pva-add="users"]').click()
    d = app.page.locator('[data-pva-dialog]')
    d.locator('[data-pva-userid]').fill('ivan@pam')
    assert d.locator('[data-pva-password]').is_disabled()
    assert d.locator('[data-pva-save]').is_enabled()


def test_runtime_grant_and_remove_a_role(open_app):
    app = open_app()
    page = app.page
    section = _section(app)
    section.locator('[data-pva-tab="acl"]').click()
    section.locator('[data-pva-add="acl"]').click()
    d = page.locator('[data-pva-dialog]')
    d.locator('[data-pva-path]').fill('vms/101')
    assert 'starts with /' in d.locator('[data-pva-problem]').inner_text()
    d.locator('[data-pva-path]').fill('/vms/101')
    d.locator('[data-pva-type]').select_option('token')
    d.locator('[data-pva-ugid]').select_option('anna@pve!ci')
    d.locator('[data-pva-role]').select_option('PVEVMUser')
    d.locator('[data-pva-save]').click()
    section.locator('[data-pva-acl="/vms/101|anna@pve!ci|PVEVMUser"]').wait_for(timeout=3000)
    assert app.server.writes[-1] == ('PUT', '/acl', {'path': '/vms/101', 'roles': ['PVEVMUser'],
                                                     'tokens': ['anna@pve!ci'], 'propagate': True})
    # root on / cannot be removed here
    assert section.locator('[data-pva-acl="/|root@pam|Administrator"] button').count() == 0
    answers = []

    def dialog(dlg):
        answers.append(dlg.message)
        dlg.accept()
    page.on('dialog', dialog)
    section.locator('[data-pva-acl="/vms/100|ops|PVEVMUser"] button').click()
    section.locator('[data-pva-acl="/vms/100|ops|PVEVMUser"]').wait_for(state='detached', timeout=3000)
    assert answers == ['Remove the role PVEVMUser on /vms/100 from ops?']
    assert app.server.writes[-1] == ('PUT', '/acl', {'path': '/vms/100', 'roles': ['PVEVMUser'], 'groups': ['ops'],
                                                     'delete': True})
    assert not app.errors, app.errors


def test_runtime_in_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Proxmox-Benutzer').first.click()
    section = page.locator('[data-pva-section]')
    section.locator('[data-pva-user="anna@pve"]').wait_for(timeout=8000)
    assert 'Die Konten und Berechtigungen des Clusters selbst' in section.inner_text()
    assert 'Benutzer hinzufügen' in section.locator('[data-pva-add="users"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_not_for_a_non_admin(open_app):
    app = open_app(admin=False)
    _datacenter(app)
    app.page.locator('button', has_text='Summary').first.wait_for(timeout=8000)
    assert app.page.locator('button', has_text='Proxmox users').count() == 0
    assert ('GET', B) not in app.server.calls


# --- static ----------------------------------------------------------------------------------

def _code():
    dc = _read('web', 'src', 'datacenter.js')
    return dc[dc.index('// Nov 2026 - the users, groups, roles'):dc.index('// LW Oct 2026 - the resource mappings of a cluster')]


def _keys():
    return sorted(set(re.findall(r"'(pva[A-Z]\w+)'", _code())) | {'pvaTitle'})


def test_every_key_is_in_every_language_once():
    tr = _read('web', 'src', 'translations.js')
    for key in _keys():
        lines = re.findall(r'^\s*' + key + r':\s*(.+)$', tr, re.M)
        assert len(lines) == len(LANGS), key
        holders = [sorted(re.findall(r'\{[a-z]+\}', x)) for x in lines]
        assert all(h == holders[0] for h in holders), key
        assert not [x for x in lines if '—' in x or '–' in x], key


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_code()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', _code()))
    assert used and used <= icons, sorted(used - icons)


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function PveAccessSection', 'data-pva-section', 'pvaDeleteAclConfirm'):
        assert needle in bundle, needle
