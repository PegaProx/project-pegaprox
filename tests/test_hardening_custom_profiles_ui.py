"""Custom hardening profiles in the web UI: the Harden PVE Node tab, its Manage profiles
dialog and the Compliance Dashboard.

The routes are tested with the API in test_hardening_custom_profiles.py. Here the source
checks read web/src, and the runtime tests drive the built bundle in headless Chromium
against the fake server of tests/test_ha_ui.py, with the profile routes kept in memory
the way the contract has them. They skip where Playwright is not installed. LW Oct 2026
"""
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _toasts,  # noqa: F401
                        _wait_for_call, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _function(src, name):
    start = src.index(f'        function {name}(')
    end = src.find('\n        function ', start + 10)
    return src[start:end]


def _lang_blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    return {lang: src[start:end] for (start, lang), end in zip(starts, ends)}


def _hp_keys():
    dash = _read('web', 'src', 'dashboard.js')
    return sorted(set(re.findall(r"\bt\('(hp[A-Z][A-Za-z]*)'\)", dash)))


# --- source ----------------------------------------------------------------------------------

def test_the_tab_and_the_editor_read_one_set_of_control_titles():
    dash = _read('web', 'src', 'dashboard.js')
    assert dash.count('const cisControls = {') == 1
    assert dash.count('const vsnfdControls = {') == 1
    assert ('const { cisControls, lynisControls, stigControls, pegaControls, vsnfdControls } = '
            'hardeningControlInfo(t);') in dash
    assert 'const info = hardeningControlInfo(t);' in _function(dash, 'HardeningProfileEditor')


def test_the_new_keys_are_in_english_and_german_once():
    keys = _hp_keys()
    assert len(keys) > 30
    blocks = _lang_blocks()
    for lang in ('en', 'de'):
        for key in keys:
            found = re.findall(rf"^ {{16}}{key}: '((?:[^'\\]|\\.)*)',$", blocks[lang], re.M)
            assert len(found) == 1, (lang, key)
            assert '\u2014' not in found[0] and '\u2013' not in found[0], (lang, key)
    # placeholders survive in German
    for key in keys:
        en = re.search(rf"^ {{16}}{key}: '(.*)',$", blocks['en'], re.M).group(1)
        de = re.search(rf"^ {{16}}{key}: '(.*)',$", blocks['de'], re.M).group(1)
        assert sorted(re.findall(r'\{\w+\}', en)) == sorted(re.findall(r'\{\w+\}', de)), key


def test_the_new_keys_sit_in_front_of_the_pinned_ha_chain():
    for lang in ('en', 'de'):
        block = _lang_blocks()[lang]
        banner = block.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        assert block.index('hpCustomProfiles:') < banner, lang


def test_no_em_dash_in_the_new_code():
    dash = _read('web', 'src', 'dashboard.js')
    for name in ('hardeningControlInfo', 'hardenParamsFor', 'HardeningProfileEditor', 'HardeningProfilesDialog'):
        body = _function(dash, name)
        assert '\u2014' not in body and '\u2013' not in body, name


def _classes(block):
    names = set()
    for m in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\})', block):
        txt = m.group(1) if m.group(1) is not None else m.group(2)
        txt = re.sub(r'\$\{[^}]*\}', ' ', txt)
        names.update(n for n in txt.split() if re.match(r'^[a-z]', n))
    for m in re.finditer(r"'([a-z][a-z0-9:/\-\.\[\] ]*)'", block):
        parts = m.group(1).split()
        if parts and any(re.match(r'^(bg|text|border|px|py|rounded|flex)-?', p) for p in parts):
            names.update(parts)
    return names


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    dash = _read('web', 'src', 'dashboard.js')
    names = set()
    for name in ('hardeningControlInfo', 'HardeningProfileEditor', 'HardeningProfilesDialog'):
        names |= _classes(_function(dash, name))
    names |= _classes('\n'.join(l for l in dash.splitlines() if 'data-hp-' in l))
    names -= {'field', 'btn'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function HardeningProfilesDialog(', 'function HardeningProfileEditor(',
                   'function hardeningControlInfo(', '/hardening/profiles'):
        assert needle in bundle, needle
    for key in _hp_keys():
        assert key in bundle, key


# --- the fake server -------------------------------------------------------------------------

FORMAT = 'pegaprox-hardening-profile'
CIS = ['fs_modules', 'core_dumps', 'mount_options', 'cron_hardening', 'net_protocols', 'journald', 'ssh_perms',
       'ssh_crypto', 'sshd_hardening', 'pam_nullok_removal', 'pam_faillock', 'pw_history', 'shell_timeout',
       'file_perms', 'backup_dns', 'postfix_banner', 'pw_hash_rounds', 'pw_quality', 'pam_password_repair',
       'pw_aging', 'default_umask', 'pkg_cleanup', 'debsums', 'login_banners', 'file_integrity', 'process_acct',
       'sysstat', 'usb_storage', 'restrict_compilers', 'apt_show_versions', 'pam_tmpdir', 'session_limit',
       'inactive_accounts', 'remove_legacy_svcs', 'audit_boot', 'audit_rules', 'aide_audit_protect',
       'mem_protection', 'audit_immutable', 'apparmor', 'disable_services', 'sysctl_hardening', 'auditd_service',
       'pve_fail2ban']
VSNFD = ['vsnfd_disk_encryption', 'vsnfd_audit_retention', 'vsnfd_journald_size', 'vsnfd_secure_boot',
         'vsnfd_kernel_lockdown', 'vsnfd_password_min_12']
IDS = CIS + VSNFD
DEFAULTS = {'backup_dns': {'dns1': '1.1.1.1', 'dns2': '9.9.9.9'},
            **{c: {'service_user': ''} for c in ('pam_faillock', 'pw_aging', 'session_limit', 'inactive_accounts')}}
CATALOG = [{'id': c, 'templated': c in DEFAULTS, 'param_keys': list(DEFAULTS.get(c, {})),
            'defaults': dict(DEFAULTS.get(c, {})), 'rollback': True} for c in IDS]
BSI = {'pw_aging', 'fs_modules', 'pw_hash_rounds', 'login_banners', 'pw_history', 'default_umask', 'ssh_perms',
       'sysctl_hardening', 'pw_quality', 'cron_hardening', 'shell_timeout', 'inactive_accounts', 'file_perms',
       'core_dumps', 'pam_tmpdir', 'pam_faillock', 'apparmor', 'audit_rules', 'ssh_crypto', 'mount_options',
       'file_integrity', 'audit_boot', 'session_limit', 'process_acct', 'mem_protection', 'auditd_service',
       'journald', 'aide_audit_protect'}
BUILTIN = [{'id': 'cis-l1', 'controls': list(CIS)}, {'id': 'cis-l2', 'controls': list(CIS)},
           {'id': 'bsi', 'controls': [c for c in IDS if c in BSI]}]
# the server's rule per parameter (core/manager.py hardening_param_value), near enough for the UI
VALUE = {'dns1': re.compile(r'[0-9a-fA-F.:]*[.:][0-9a-fA-F.:]*', re.ASCII),
         'dns2': re.compile(r'[0-9a-fA-F.:]*[.:][0-9a-fA-F.:]*', re.ASCII),
         'service_user': re.compile(r'[a-zA-Z][a-zA-Z0-9._-]{0,31}(?:,[a-zA-Z][a-zA-Z0-9._-]{0,31})*', re.ASCII)}
HARDEN_PATH = '/api/clusters/c1/nodes/pve1/hardening'
APPLIED = {'fs_modules'}   # what the fake node has already; everything else fails its check

P1 = {'id': '0123456789abcdef', 'name': 'Web tier', 'description': 'Nodes facing the internet\nreviewed yearly',
      'controls': ['fs_modules', 'pam_faillock', 'backup_dns'],
      'params': {'pam_faillock': {'service_user': 'monitoring'}, 'backup_dns': {'dns1': '10.0.0.53'}},
      'dropped_controls': ['legacy_control'], 'created_at': '2026-10-29T10:00:00Z',
      'updated_at': '2026-10-29T10:00:00Z', 'created_by': 'admin', 'updated_by': 'admin'}
P2 = {'id': 'fedcba9876543210', 'name': 'Backup hosts', 'description': '', 'controls': ['journald', 'ssh_perms'],
      'params': {}, 'dropped_controls': [], 'created_at': '2026-10-28T10:00:00Z',
      'updated_at': '2026-10-28T10:00:00Z', 'created_by': 'admin', 'updated_by': 'admin'}

READS = {
    ('GET', '/api/clusters/c1/nodes'): (200, [{'node': 'pve1', 'status': 'online'}]),
    ('GET', '/api/audit'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('GET', '/api/alert-channels'): (200, []),
    **SSE_TOKEN,
}


class _ProfileServer(_FakeServer):
    """The fake of tests/test_ha_ui.py plus the custom profile routes and the node check."""

    def __init__(self, profiles=(P1, P2), can_manage=True, role='standalone', **kw):
        extra = dict(READS)
        extra.update(kw.pop('extra', {}))
        super().__init__(role=role, clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                         extra=extra, **kw)
        self.profiles = [json.loads(json.dumps(p)) for p in profiles]
        self.can_manage = can_manage
        self.next_id = 0x1000
        self.checks = []    # the profile query of every node check
        self.applied = []   # the bodies of the apply posts

    def listing(self):
        custom = []
        for p in sorted(self.profiles, key=lambda x: x['name'].casefold()):
            p = dict(p)
            if not self.can_manage:
                p.pop('created_by', None)
                p.pop('updated_by', None)
            custom.append(p)
        return {'custom': custom, 'builtin': BUILTIN, 'catalog': CATALOG, 'can_manage': self.can_manage,
                'format': FORMAT, 'format_version': 1,
                'limits': {'profiles': 100, 'name': 64, 'description': 500, 'value': 256}}

    def validated(self, body, but=None):
        if 'format' in body or 'version' in body:
            if body.get('format') != FORMAT or body.get('version') != 1:
                return None, (400, 'This is not a hardening profile exported by PegaProx '
                                   '(pegaprox-hardening-profile, version 1)')
        name = str(body.get('name') or '').strip()
        if not name:
            return None, (400, 'Enter a name for the profile')
        controls = body.get('controls')
        if not isinstance(controls, list) or not controls:
            return None, (400, 'Pick at least one control')
        unknown = [c for c in controls if c not in IDS]
        if unknown:
            return None, (400, 'Unknown control: ' + ', '.join(unknown))
        params = {}
        for cid, vals in (body.get('params') or {}).items():
            if cid not in controls:
                return None, (400, f'{cid} has values but is not a control of this profile')
            if cid not in DEFAULTS:
                return None, (400, f'{cid} takes no parameters')
            for key, v in vals.items():
                if v.strip() and not VALUE[key].fullmatch(v.strip()):
                    takes = 'an IP address' if key.startswith('dns') else 'user names separated by commas'
                    return None, (400, f'{cid} {key}: not a value this control takes - {takes}')
                if v.strip():
                    params.setdefault(cid, {})[key] = v.strip()
        if any(p['id'] != but and p['name'].casefold() == name.casefold() for p in self.profiles):
            return None, (409, f"A profile named '{name}' exists already")
        return {'name': name, 'description': str(body.get('description') or '').strip(),
                'controls': [c for c in IDS if c in controls], 'params': params}, None

    def profile_route(self, method, pid, body):
        if method == 'GET' and pid is None:
            return 200, self.listing()
        if not self.can_manage:
            return 403, {'error': 'Custom hardening profiles are managed by administrators who are '
                                  'not limited to a tenant or to specific clusters'}
        if method == 'POST' and pid is None:
            fields, refused = self.validated(body)
            if refused:
                return refused[0], {'error': refused[1]}
            self.next_id += 1
            p = dict(fields, id=f'{self.next_id:016x}', dropped_controls=[], created_at='2026-10-30T09:00:00Z',
                     updated_at='2026-10-30T09:00:00Z', created_by='admin', updated_by='admin')
            self.profiles.append(p)
            return 201, {'success': True, 'profile': p}
        have = next((p for p in self.profiles if p['id'] == pid), None)
        if have is None:
            return 404, {'error': 'Profile not found'}
        if method == 'DELETE':
            self.profiles.remove(have)
            return 200, {'success': True, 'id': pid}
        if method == 'PUT':
            merged = {k: body.get(k, have[k]) for k in ('name', 'description', 'controls', 'params')}
            fields, refused = self.validated(merged, but=pid)
            if refused:
                return refused[0], {'error': refused[1]}
            changed = [k for k in fields if fields[k] != have[k]]
            have.update(fields, dropped_controls=[], updated_at='2026-10-30T10:00:00Z')
            return 200, {'success': True, 'profile': have, 'changed': changed}
        return 405, {'error': 'method'}

    def check(self, url):
        q = parse_qs(urlparse(url).query)
        profile = (q.get('profile') or [''])[0]
        self.checks.append(profile)
        out = {'node': 'pve1', 'verbose': False}
        if profile.startswith('custom:'):
            p = next((x for x in self.profiles if x['id'] == profile[7:]), None)
            if p is None:
                return 400, {'error': f'unknown profile: {profile}'}
            controls = p['controls']
            out.update(profile=profile, requested_profile=profile, profile_name=p['name'],
                       dropped_controls=p.get('dropped_controls') or [])
        else:
            controls = CIS
            out.update(profile=profile or 'cis-l1', requested_profile=profile or 'cis-l1')
        out['controls'] = {c: c in APPLIED for c in controls}
        passed = sum(1 for c in controls if c in APPLIED)
        out['summary'] = {'total': len(controls), 'passed': passed, 'failed': len(controls) - passed,
                          'not_checked': 0, 'checked': len(controls)}
        return 200, out

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/hardening/profiles(?:/([^/]+))?', path)
        if m or path == HARDEN_PATH:
            self.calls.append((req.method, path))
            self.urls.append(req.url)
            body = json.loads(req.post_data) if req.post_data else {}
            self.bodies.setdefault(path, []).append(body)
            if m:
                status, data = self.profile_route(req.method, m.group(1), body)
            elif req.method == 'GET':
                status, data = self.check(req.url)
            else:
                self.applied.append(body)
                status, data = 200, {'results': {c: {'success': True} for c in body.get('controls', [])}}
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='modern', **kw):
        app = _App(browser, _ProfileServer(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _harden_tab(page, layout):
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*Harden PVE Node\s*$')).first.click()
    page.locator('select', has=page.locator('option', has_text='pve1')).first.select_option('pve1')


def _profile_select(page):
    return page.locator('select', has=page.locator('option[value="stig"]')).first


def _open_manage(page):
    page.locator('[data-hp-manage]').click()
    dialog = page.locator('[data-hp-dialog]')
    dialog.wait_for(timeout=5000)
    return dialog


def _bodies(app, method, path):
    return [b for (m, p), b in zip([c for c in app.server.calls if c[1] == path],
                                   app.server.bodies.get(path, [])) if m == method]


def _poll(app, cond, seconds=8):
    deadline = time.time() + seconds
    while time.time() < deadline and not cond():
        app.page.wait_for_timeout(100)
    return cond()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors
    assert not app.errors, app.errors


# --- runtime: the manage dialog ----------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_an_admin_creates_edits_duplicates_and_deletes_a_profile(open_app, layout):
    app = open_app(layout)
    page = app.page
    _harden_tab(page, layout)
    dialog = _open_manage(page)
    assert dialog.locator('[data-hp-row]').count() == 2
    # sorted by name, the stored description keeps its line break, unknown controls are named
    assert dialog.locator('[data-hp-row]').first.get_attribute('data-hp-row') == P2['id']
    row = dialog.locator(f'[data-hp-row="{P1["id"]}"]')
    assert 'Nodes facing the internet\nreviewed yearly' in row.inner_text()
    assert '3 controls' in row.inner_text() and 'legacy_control' in row.inner_text()
    assert dialog.locator('[data-hp-total]').inner_text() == '2 of 100 profiles'

    # new, starting from BSI
    dialog.locator('[data-hp-start]').select_option('bsi')
    dialog.locator('[data-hp-new]').click()
    editor = dialog.locator('[data-hp-editor]')
    editor.wait_for(timeout=3000)
    assert editor.locator('[data-hp-count]').inner_text() == f'{len(BSI)} of {len(IDS)} selected'
    # every control the server knows has a title of the tab, none lands under Other
    assert editor.get_by_text('Other', exact=True).count() == 0
    assert editor.locator('[data-hp-control]').count() == len(IDS)
    editor.locator('[data-hp-search]').fill('faillock')
    assert editor.locator('[data-hp-control]').count() == 1
    editor.locator('[data-hp-search]').fill('')
    editor.locator('[data-hp-control="journald"] input[type="checkbox"]').uncheck()
    editor.locator('[data-hp-control="backup_dns"] input[type="checkbox"]').check()
    assert editor.locator('[data-hp-count]').inner_text() == f'{len(BSI)} of {len(IDS)} selected'
    editor.locator('[data-hp-param="backup_dns.dns2"]').fill('192.0.2.53')
    editor.locator('[data-hp-param="pam_faillock.service_user"]').fill('zabbix,backup')
    # the server's sentence shows inline and nothing closes
    editor.locator('[data-hp-save]').click()
    editor.locator('[data-hp-error]').wait_for(timeout=3000)
    assert editor.locator('[data-hp-error]').inner_text() == 'Enter a name for the profile'
    editor.locator('[data-hp-name]').fill('web tier')
    editor.locator('[data-hp-save]').click()
    editor.get_by_text("A profile named 'web tier' exists already").wait_for(timeout=3000)
    editor.locator('[data-hp-name]').fill('Hypervisors')
    editor.locator('[data-hp-description]').fill('All PVE nodes\nsecond line')
    editor.locator('[data-hp-save]').click()
    dialog.locator('[data-hp-list]').wait_for(timeout=3000)
    sent = _bodies(app, 'POST', '/api/hardening/profiles')[-1]
    assert sent['name'] == 'Hypervisors' and sent['description'] == 'All PVE nodes\nsecond line'
    assert sent['controls'] == [c for c in IDS if (c in BSI and c != 'journald') or c == 'backup_dns']
    assert sent['params'] == {'backup_dns': {'dns2': '192.0.2.53'}, 'pam_faillock': {'service_user': 'zabbix,backup'}}
    assert dialog.locator('[data-hp-row]').count() == 3

    # edit: what it saved comes back into the editor, a PUT sends the change
    new_id = next(p['id'] for p in app.server.profiles if p['name'] == 'Hypervisors')
    dialog.locator(f'[data-hp-row="{new_id}"]').get_by_role('button', name='Edit').click()
    assert editor.locator('[data-hp-name]').input_value() == 'Hypervisors'
    assert editor.locator('[data-hp-param="backup_dns.dns2"]').input_value() == '192.0.2.53'
    assert editor.locator('[data-hp-param="backup_dns.dns1"]').get_attribute('placeholder') == '1.1.1.1'
    editor.locator('[data-hp-control="pam_faillock"] input[type="checkbox"]').uncheck()
    editor.locator('[data-hp-param="backup_dns.dns2"]').fill('not a value;')
    editor.locator('[data-hp-save]').click()
    editor.get_by_text('backup_dns dns2: not a value this control takes').wait_for(timeout=3000)
    editor.locator('[data-hp-param="backup_dns.dns2"]').fill('')
    editor.locator('[data-hp-save]').click()
    dialog.locator('[data-hp-list]').wait_for(timeout=3000)
    put = _bodies(app, 'PUT', f'/api/hardening/profiles/{new_id}')[-1]
    assert 'pam_faillock' not in put['controls'] and put['params'] == {}

    # duplicate: a new one under another name, the original stays
    dialog.locator(f'[data-hp-row="{P1["id"]}"]').get_by_role('button', name='Duplicate').click()
    assert editor.locator('[data-hp-name]').input_value() == 'Web tier (copy)'
    # the copy carries what this version knows, nothing to warn about
    assert editor.locator('[data-hp-unknown]').count() == 0
    editor.locator('[data-hp-save]').click()
    dialog.locator('[data-hp-list]').wait_for(timeout=3000)
    dup = _bodies(app, 'POST', '/api/hardening/profiles')[-1]
    assert dup['controls'] == P1['controls'] and dup['params'] == P1['params']
    assert dup['description'] == P1['description']
    assert dialog.locator('[data-hp-row]').count() == 4

    # delete asks first; cancel keeps it
    row = dialog.locator(f'[data-hp-row="{P2["id"]}"]')
    row.get_by_role('button', name='Delete').click()
    row.locator('[data-hp-confirm]').get_by_text("Delete the profile 'Backup hosts'?").wait_for(timeout=2000)
    row.get_by_role('button', name='Cancel').click()
    assert ('DELETE', f'/api/hardening/profiles/{P2["id"]}') not in app.server.calls
    row.get_by_role('button', name='Delete').click()
    row.locator('[data-hp-confirm]').get_by_role('button', name='Delete').click()
    row.wait_for(state='detached', timeout=3000)
    assert ('DELETE', f'/api/hardening/profiles/{P2["id"]}') in app.server.calls
    assert dialog.locator('[data-hp-row]').count() == 3

    # the tab's select follows
    dialog.get_by_role('button', name='Close').click()
    options = _profile_select(page).locator('optgroup[label="Custom profiles"] option')
    assert sorted(options.all_inner_texts()) == ['Hypervisors', 'Web tier', 'Web tier (copy)']
    _no_errors(app)


def test_runtime_export_and_import(open_app, tmp_path):
    app = open_app('modern')
    page = app.page
    _harden_tab(page, 'modern')
    dialog = _open_manage(page)
    with page.expect_download() as dl:
        dialog.locator(f'[data-hp-row="{P1["id"]}"]').get_by_role('button', name='Export').click()
    download = dl.value
    assert download.suggested_filename == 'pegaprox-hardening-profile-web-tier.json'
    exported = json.loads(open(download.path(), encoding='utf-8').read())
    assert exported == {'format': FORMAT, 'version': 1, 'name': 'Web tier', 'description': P1['description'],
                        'controls': P1['controls'], 'params': P1['params']}

    # the same file back: the server gets it unchanged, its name is taken, so the editor
    # opens with it to be renamed
    raw = json.dumps(exported).encode()
    dialog.locator('[data-hp-import]').set_input_files(files=[{'name': 'p.json', 'mimeType': 'application/json',
                                                               'buffer': raw}])
    editor = dialog.locator('[data-hp-editor]')
    editor.wait_for(timeout=3000)
    assert _bodies(app, 'POST', '/api/hardening/profiles')[-1] == exported
    assert 'exists already' in editor.locator('[data-hp-error]').inner_text()
    assert editor.locator('[data-hp-name]').input_value() == 'Web tier'
    assert editor.locator('[data-hp-param="pam_faillock.service_user"]').input_value() == 'monitoring'
    editor.locator('[data-hp-name]').fill('Web tier imported')
    editor.locator('[data-hp-save]').click()
    dialog.locator('[data-hp-list]').wait_for(timeout=3000)
    saved = _bodies(app, 'POST', '/api/hardening/profiles')[-1]
    assert saved['name'] == 'Web tier imported' and saved['controls'] == P1['controls']
    assert saved['params'] == P1['params']

    # a file under a new name goes in at once
    other = dict(exported, name='From the other site')
    dialog.locator('[data-hp-import]').set_input_files(files=[{'name': 'o.json', 'mimeType': 'application/json',
                                                               'buffer': json.dumps(other).encode()}])
    dialog.locator('[data-hp-row]').filter(has_text='From the other site').wait_for(timeout=3000)
    assert any('Profile imported' in x for x in _toasts(page))

    # not JSON, and JSON of something else: said inline, the second by the server
    dialog.locator('[data-hp-import]').set_input_files(files=[{'name': 'x.json', 'mimeType': 'application/json',
                                                               'buffer': b'{nope'}])
    dialog.locator('[data-hp-error]').get_by_text('This file is not a hardening profile exported by PegaProx.').wait_for(timeout=3000)
    posts = len(_bodies(app, 'POST', '/api/hardening/profiles'))
    wrong = dict(exported, format='something-else', name='Wrong')
    dialog.locator('[data-hp-import]').set_input_files(files=[{'name': 'w.json', 'mimeType': 'application/json',
                                                               'buffer': json.dumps(wrong).encode()}])
    dialog.locator('[data-hp-error]').get_by_text('(pegaprox-hardening-profile, version 1)', exact=False).wait_for(timeout=3000)
    assert len(_bodies(app, 'POST', '/api/hardening/profiles')) == posts + 1
    assert dialog.locator('[data-hp-editor]').count() == 0
    _no_errors(app)


# --- runtime: the tab runs it ------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_tab_runs_a_custom_profile_with_its_values(open_app, layout):
    app = open_app(layout)
    page = app.page
    _harden_tab(page, layout)
    select = _profile_select(page)
    select.locator(f'option[value="custom:{P1["id"]}"]').wait_for(state='attached', timeout=5000)
    select.select_option(f'custom:{P1["id"]}')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text('1/3 controls active').first.wait_for(timeout=8000)
    assert app.server.checks[-1] == f'custom:{P1["id"]}'
    assert page.locator('[data-hp-ran]').inner_text() == 'Web tier'
    assert page.locator('[data-hp-dropped]').inner_text().endswith('legacy_control')
    # the profile's values are in the inputs of its controls
    dns = page.locator('input[placeholder="1.1.1.1"]').first
    assert dns.input_value() == '10.0.0.53'
    assert page.locator('input[placeholder="9.9.9.9"]').first.input_value() == '9.9.9.9'
    assert page.locator('input[placeholder="monitoring,backup"]').first.input_value() == 'monitoring'
    # and an apply sends them
    page.get_by_role('button', name=re.compile(r'Apply Selected \(2\)')).click()
    page.locator('label', has_text='I understand these controls change SSH').locator('input').check()
    page.get_by_role('button', name='Apply', exact=True).click()
    page.get_by_text('2/2 controls applied').first.wait_for(timeout=8000)
    sent = {b['controls'][0]: b['params'] for b in app.server.applied}
    assert sent['pam_faillock'] == {'pam_faillock': {'service_user': 'monitoring'}}
    assert sent['backup_dns'] == {'backup_dns': {'dns1': '10.0.0.53', 'dns2': '9.9.9.9'}}

    # back to a built-in profile: the defaults return
    select.select_option('bsi')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.locator('input[placeholder="monitoring,backup"]').first.wait_for(timeout=8000)
    assert app.server.checks[-1] == 'bsi'
    assert page.locator('input[placeholder="monitoring,backup"]').first.input_value() == ''
    assert page.locator('[data-hp-ran]').count() == 0
    _no_errors(app)


def test_runtime_save_selection_as_profile(open_app):
    app = open_app('modern')
    page = app.page
    _harden_tab(page, 'modern')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text(f'1/{len(CIS)} controls active').first.wait_for(timeout=8000)
    ticked = page.locator('#harden-report-content input[type="checkbox"]:checked')
    while ticked.count():
        ticked.first.uncheck()
    for title in ('Account Lockout (pam_faillock)', 'Backup Nameserver', 'Journald Hardening'):
        page.locator('div.bg-proxmox-card', has_text=title).locator('input[type="checkbox"]').first.check()
    page.locator('div.bg-proxmox-card', has_text='Account Lockout (pam_faillock)').locator(
        'input[placeholder="monitoring,backup"]').fill('zabbix')
    page.locator('[data-hp-save-selection]').click()
    editor = page.locator('[data-hp-editor]')
    editor.wait_for(timeout=3000)
    assert editor.locator('[data-hp-count]').inner_text() == f'3 of {len(IDS)} selected'
    assert editor.locator('[data-hp-param="pam_faillock.service_user"]').input_value() == 'zabbix'
    # the default DNS servers stay out, the profile keeps following the default
    assert editor.locator('[data-hp-param="backup_dns.dns1"]').input_value() == ''
    editor.locator('[data-hp-name]').fill('Picked by hand')
    editor.locator('[data-hp-save]').click()
    page.locator('[data-hp-dialog]').wait_for(state='detached', timeout=3000)
    sent = _bodies(app, 'POST', '/api/hardening/profiles')[-1]
    assert sent['controls'] == ['journald', 'pam_faillock', 'backup_dns']
    assert sent['params'] == {'pam_faillock': {'service_user': 'zabbix'}}
    assert _profile_select(page).locator('option', has_text='Picked by hand').count() == 1
    _no_errors(app)


def test_runtime_a_deleted_selected_profile_falls_back_to_all_controls(open_app):
    """The select cannot tell on its own: once the selected option is gone the browser shows
    the first one, whatever the state still holds. The next check and the values in the
    inputs tell."""
    app = open_app('modern')
    page = app.page
    _harden_tab(page, 'modern')
    select = _profile_select(page)
    select.locator(f'option[value="custom:{P1["id"]}"]').wait_for(state='attached', timeout=5000)
    select.select_option(f'custom:{P1["id"]}')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text('1/3 controls active').first.wait_for(timeout=8000)
    assert page.locator('input[placeholder="1.1.1.1"]').first.input_value() == '10.0.0.53'

    dialog = _open_manage(page)
    row = dialog.locator(f'[data-hp-row="{P1["id"]}"]')
    row.get_by_role('button', name='Delete').click()
    row.locator('[data-hp-confirm]').get_by_role('button', name='Delete').click()
    row.wait_for(state='detached', timeout=3000)
    dialog.get_by_role('button', name='Close').click()
    dialog.wait_for(state='detached', timeout=3000)

    checks = len(app.server.checks)
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    assert _poll(app, lambda: len(app.server.checks) > checks)
    assert app.server.checks[-1] == ''
    page.get_by_text(f'1/{len(CIS)} controls active').first.wait_for(timeout=8000)
    assert not [x for x in _toasts(page) if 'unknown profile' in x]
    # the deleted profile's values left the inputs with it
    assert page.locator('input[placeholder="1.1.1.1"]').first.input_value() == '1.1.1.1'
    assert page.locator('input[placeholder="9.9.9.9"]').first.input_value() == '9.9.9.9'
    assert page.locator('input[placeholder="monitoring,backup"]').first.input_value() == ''
    _no_errors(app)


def test_runtime_a_copy_name_is_cut_between_characters(open_app):
    """The server counts a name in code points. Cutting the copy name in UTF-16 units split
    an emoji at the limit and left half of it, which the server cannot store."""
    long = dict(P2, id='00000000000000aa', name='a' * 63 + '\U0001f512')
    app = open_app('modern', profiles=(P1, long))
    page = app.page
    _harden_tab(page, 'modern')
    dialog = _open_manage(page)
    dialog.locator(f'[data-hp-row="{long["id"]}"]').get_by_role('button', name='Duplicate').click()
    name = dialog.locator('[data-hp-editor] [data-hp-name]')
    name.wait_for(timeout=3000)
    got = name.evaluate("""el => ({ units: el.value.length, points: Array.from(el.value).length,
        lone: /[\\ud800-\\udbff](?![\\udc00-\\udfff])|(^|[^\\ud800-\\udbff])[\\udc00-\\udfff]/.test(el.value) })""")
    assert got == {'units': 65, 'points': 64, 'lone': False}, got
    assert name.input_value() == 'a' * 63 + '\U0001f512'
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_maintenance_user_runs_profiles_but_manages_none(open_app, layout):
    app = open_app(layout, admin=False, can_manage=False, permissions=['node.maintenance'])
    page = app.page
    _harden_tab(page, layout)
    select = _profile_select(page)
    select.locator(f'option[value="custom:{P2["id"]}"]').wait_for(state='attached', timeout=5000)
    assert page.locator('[data-hp-manage]').count() == 0
    select.select_option(f'custom:{P2["id"]}')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text('0/2 controls active').first.wait_for(timeout=8000)
    assert page.locator('[data-hp-ran]').inner_text() == 'Backup hosts'
    assert page.locator('[data-hp-save-selection]').count() == 0
    assert page.locator('[data-hp-manage]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_runs_profiles_but_changes_none(open_app, layout):
    """A standby that does not forward refuses writes (#625): the profiles stay usable for a
    check, the buttons that would write them are not there."""
    app = open_app(layout, role='standby')
    page = app.page
    _harden_tab(page, layout)
    select = _profile_select(page)
    select.locator(f'option[value="custom:{P2["id"]}"]').wait_for(state='attached', timeout=5000)
    select.select_option(f'custom:{P2["id"]}')
    page.get_by_role('button', name=re.compile('Check Status')).first.click()
    page.get_by_text('0/2 controls active').first.wait_for(timeout=8000)
    assert page.locator('[data-hp-manage]').count() == 0
    assert page.locator('[data-hp-save-selection]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'hardening' in c[1]]
    _no_errors(app)


def test_runtime_the_dialog_speaks_german(open_app):
    app = open_app('modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automatisierung\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*PVE Node härten\s*$')).first.click()
    dialog = _open_manage(page)
    assert dialog.locator('[data-hp-total]').inner_text() == '2 von 100 Profilen'
    assert dialog.get_by_text('Eigene Härtungsprofile').count() == 1
    assert dialog.get_by_role('button', name='Duplizieren').count() == 2
    dialog.locator('[data-hp-new]').click()
    assert dialog.locator('[data-hp-count]').inner_text() == f'0 von {len(IDS)} ausgewählt'
    _no_errors(app)


# --- runtime: the compliance dashboard -------------------------------------------------------

def _cluster_compliance(page, layout):
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.get_by_text('pve1', exact=True).first.wait_for(timeout=8000)


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_the_compliance_dashboard_drops_a_deleted_custom_profile(open_app, layout):
    """Deleted elsewhere while selected here: the next refresh goes back to CIS Level 1
    instead of asking every node for a profile that is gone. The select shows its first
    option either way, so the request and the label under the cards are what tell."""
    app = open_app(layout)
    page = app.page
    _cluster_compliance(page, layout)
    select = page.locator('select', has=page.locator('option[value="rgs"]')).first
    select.locator(f'option[value="custom:{P1["id"]}"]').wait_for(state='attached', timeout=5000)
    select.select_option(f'custom:{P1["id"]}')
    page.locator('[data-hp-score]').wait_for(timeout=5000)
    assert _poll(app, lambda: app.server.checks[-1:] == [f'custom:{P1["id"]}'])

    app.server.profiles = [p for p in app.server.profiles if p['id'] != P1['id']]
    # the Refresh beside the select; the cloud layout has one of its own in the header
    select.locator('xpath=..').get_by_role('button', name=re.compile(r'^\s*Refresh\s*$')).click()
    page.locator('[data-hp-score]').wait_for(state='detached', timeout=5000)
    assert _poll(app, lambda: app.server.checks[-1:] == ['cis-l1']), app.server.checks
    assert select.input_value() == 'cis-l1'
    page.get_by_text('Profile: ', exact=False).filter(has_text='CIS-L1').first.wait_for(timeout=3000)
    assert select.locator(f'option[value="custom:{P1["id"]}"]').count() == 0


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_compliance_dashboard_scores_a_custom_profile(open_app, layout):
    app = open_app(layout)
    page = app.page
    _cluster_compliance(page, layout)
    select = page.locator('select', has=page.locator('option[value="rgs"]')).first
    select.locator(f'option[value="custom:{P1["id"]}"]').wait_for(state='attached', timeout=5000)
    assert page.locator('[data-hp-score]').count() == 0
    frameworks = page.locator('div.bg-proxmox-card', has=page.get_by_text('DISA STIG', exact=True)).count()
    select.select_option(f'custom:{P1["id"]}')
    card = page.locator('[data-hp-score]')
    card.wait_for(timeout=5000)
    page.wait_for_function(f'() => document.querySelector("[data-hp-score]").innerText.includes("1/3")', timeout=8000)
    text = card.inner_text()
    assert 'Custom profile: Web tier' in text and '33%' in text, text
    # the cloud layout's t() answers nothing for a key whose English value is the key itself
    assert '1/3 controls' in text, text
    assert app.server.checks[-1] == f'custom:{P1["id"]}'
    # the framework cards stay
    assert page.locator('div.bg-proxmox-card', has=page.get_by_text('DISA STIG', exact=True)).count() == frameworks
    page.get_by_text('Profile: ', exact=False).filter(has_text='Web tier').first.wait_for(timeout=3000)
    select.select_option('cis-l1')
    card.wait_for(state='detached', timeout=3000)
    _no_errors(app)
