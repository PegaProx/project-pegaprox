# -*- coding: utf-8 -*-
"""Users, groups, roles, ACL and realms of Proxmox VE itself (pegaprox/api/pve_access.py):
admins only, ids checked before they reach the PVE path, root@pam protected."""
import json as _json

import pytest


class _Resp:
    def __init__(self, status, data=None, text=None):
        self.status_code = status
        self._data = data
        self.text = text if text is not None else _json.dumps({'data': data})

    def json(self):
        return {'data': self._data}


PVE = {
    'users': [{'userid': 'root@pam', 'enable': 1, 'realm-type': 'pam'},
              {'userid': 'anna@pve', 'enable': 1, 'email': 'a@x.ru', 'groups': 'ops',
               'tokens': [{'tokenid': 'ci'}]}],
    'groups': [{'groupid': 'ops', 'comment': 'Админы', 'users': 'anna@pve'}],
    'roles': [{'roleid': 'Administrator', 'special': 1, 'privs': 'VM.Audit,Sys.Audit'},
              {'roleid': 'Backup', 'special': 0, 'privs': 'VM.Backup,Datastore.AllocateSpace'}],
    'acl': [{'path': '/', 'type': 'user', 'ugid': 'root@pam', 'roleid': 'Administrator', 'propagate': 1}],
    'domains': [{'realm': 'pam', 'type': 'pam'}, {'realm': 'pve', 'type': 'pve', 'default': 1}],
}


class _Session:
    def __init__(self, calls, fail=None):
        self.calls, self.fail = calls, fail

    def _do(self, method, url, data=None, params=None, timeout=None):
        path = url.split('/api2/json/access/', 1)[1]
        self.calls.append((method, path, data, params))
        if self.fail:
            return _Resp(self.fail[0], text=_json.dumps({'errors': {'x': self.fail[1]}}))
        if method == 'get':
            return _Resp(200, PVE.get(path, []))
        return _Resp(200, None)

    def get(self, url, **kw): return self._do('get', url, **kw)
    def post(self, url, **kw): return self._do('post', url, **kw)
    def put(self, url, **kw): return self._do('put', url, **kw)
    def delete(self, url, **kw): return self._do('delete', url, **kw)


@pytest.fixture
def pve(api, seed):
    calls = []
    m = api.make_fake_manager('c1')
    m.config.name = 'c1'
    m.host, m.api_port = 'pve1', 8006
    state = {'fail': None}
    m._create_session.side_effect = lambda: _Session(calls, state['fail'])
    api.set_manager('c1', m)
    admin = api.as_user(seed.user('boss', role='admin'))
    return admin, calls, state


B = '/api/clusters/c1/pve-access'


def test_read_everything_in_one_call(pve):
    admin, calls, _ = pve
    r = admin.get(B)
    assert r.status_code == 200, r.get_json()
    d = r.get_json()
    anna = [u for u in d['users'] if u['userid'] == 'anna@pve'][0]
    assert anna['groups'] == ['ops'] and anna['tokens'] == ['ci']
    assert [u for u in d['users'] if u['userid'] == 'root@pam'][0]['protected'] is True
    assert d['roles'][0]['roleid'] == 'Administrator' and d['roles'][0]['special'] is True
    assert 'VM.Backup' in d['privileges']
    assert d['groups'][0]['users'] == ['anna@pve']
    assert [x['realm'] for x in d['realms']] == ['pam', 'pve']
    assert ('get', 'users', None, {'full': 1}) in calls


def test_only_admins(api, seed, pve):
    _, calls, _ = pve
    user = api.as_user(seed.user('joe', role='user'))
    n = len(calls)
    assert user.get(B).status_code == 403
    assert user.post(f'{B}/users', json={'userid': 'x@pve'}).status_code == 403
    assert len(calls) == n


def test_create_user_with_groups_and_password(pve):
    admin, calls, _ = pve
    r = admin.post(f'{B}/users', json={'userid': 'ivan@pve', 'password': 'Secret123!', 'groups': ['ops'],
                                       'email': 'i@x.ru', 'comment': 'dev'})
    assert r.status_code == 200, r.get_json()
    method, path, data, _ = calls[-1]
    assert (method, path) == ('post', 'users')
    assert data['groups'] == 'ops' and data['password'] == 'Secret123!' and data['userid'] == 'ivan@pve'


@pytest.mark.parametrize('body,why', [
    ({'userid': 'ivan'}, 'name@realm'),
    ({'userid': 'a/b@pve'}, 'name@realm'),
    ({'userid': 'ivan@pam', 'password': 'Secret123!'}, 'pve realm'),
    ({'userid': 'ivan@pve', 'password': 'short'}, '8 to 256'),
    ({'userid': 'ivan@pve', 'groups': ['../x']}, 'group list'),
    ({'userid': 'ivan@pve', 'comment': 'a\nb'}, 'single line'),
])
def test_bad_user_input_never_reaches_proxmox(pve, body, why):
    admin, calls, _ = pve
    r = admin.post(f'{B}/users', json=body)
    assert r.status_code == 400 and why in r.get_json()['error']
    assert calls == []


def test_update_clears_emptied_fields(pve):
    admin, calls, _ = pve
    r = admin.put(f'{B}/users/anna@pve', json={'email': '', 'groups': [], 'enable': False})
    assert r.status_code == 200, r.get_json()
    method, path, data, _ = calls[-1]
    assert (method, path) == ('put', 'users/anna@pve')
    assert data == {'groups': '', 'enable': 0, 'delete': 'email'}


def test_root_is_protected(pve):
    admin, calls, _ = pve
    assert admin.delete(f'{B}/users/root@pam').status_code == 400
    assert admin.put(f'{B}/users/root@pam', json={'enable': 0}).status_code == 400
    r = admin.put(f'{B}/acl', json={'path': '/', 'roles': ['Administrator'], 'users': ['root@pam'], 'delete': True})
    assert r.status_code == 400
    assert calls == []


def test_password_only_for_pve_realm(pve):
    admin, calls, _ = pve
    assert admin.put(f'{B}/users/root@pam/password', json={'password': 'Secret123!'}).status_code == 400
    assert admin.put(f'{B}/users/anna@pve/password', json={'password': 'Secret123!'}).status_code == 200
    assert calls[-1][:2] == ('put', 'password') and calls[-1][2]['userid'] == 'anna@pve'


def test_built_in_roles_cannot_be_changed(pve):
    admin, calls, _ = pve
    r = admin.put(f'{B}/roles/Administrator', json={'privs': ['VM.Audit']})
    assert r.status_code == 400 and 'built-in' in r.get_json()['error']
    assert not [c for c in calls if c[0] != 'get']
    r = admin.put(f'{B}/roles/Backup', json={'privs': ['VM.Backup', 'VM.Audit']})
    assert r.status_code == 200
    assert calls[-1] == ('put', 'roles/Backup', {'privs': 'VM.Audit,VM.Backup'}, None)
    assert admin.post(f'{B}/roles', json={'roleid': 'X', 'privs': ['rm -rf']}).status_code == 400


def test_groups(pve):
    admin, calls, _ = pve
    assert admin.post(f'{B}/groups', json={'groupid': 'dev', 'comment': 'Разработка'}).status_code == 200
    assert calls[-1] == ('post', 'groups', {'groupid': 'dev', 'comment': 'Разработка'}, None)
    assert admin.delete(f'{B}/groups/dev').status_code == 200
    assert calls[-1][:2] == ('delete', 'groups/dev')
    assert admin.post(f'{B}/groups', json={'groupid': 'a b'}).status_code == 400


def test_acl_grant_and_remove(pve):
    admin, calls, _ = pve
    r = admin.put(f'{B}/acl', json={'path': '/vms/100', 'roles': ['PVEVMUser'], 'users': ['anna@pve'],
                                    'groups': ['ops'], 'tokens': ['anna@pve!ci'], 'propagate': False})
    assert r.status_code == 200, r.get_json()
    assert calls[-1] == ('put', 'acl', {'path': '/vms/100', 'roles': 'PVEVMUser', 'propagate': 0,
                                        'users': 'anna@pve', 'groups': 'ops', 'tokens': 'anna@pve!ci'}, None)
    r = admin.put(f'{B}/acl', json={'path': '/vms/100', 'roles': ['PVEVMUser'], 'groups': ['ops'], 'delete': True})
    assert r.status_code == 200 and calls[-1][2]['delete'] == 1


@pytest.mark.parametrize('path', ['vms/100', '/vms/../x', '/vms/1 00', '', '/a//b'])
def test_acl_path_is_checked(pve, path):
    admin, calls, _ = pve
    r = admin.put(f'{B}/acl', json={'path': path, 'roles': ['PVEAuditor'], 'users': ['anna@pve']})
    assert r.status_code == 400
    assert calls == []


def test_proxmox_errors_are_passed_on(pve):
    admin, calls, state = pve
    state['fail'] = (500, 'user anna@pve already exists')
    r = admin.post(f'{B}/users', json={'userid': 'anna@pve'})
    assert r.status_code == 400 and 'already exists' in r.get_json()['error']
    state['fail'] = (403, 'Permission check failed')
    r = admin.get(B)
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH'


def test_not_for_other_cluster_types(api, pve):
    admin, _, _ = pve
    api.set_manager('x1', api.make_fake_manager('x1', cluster_type='xcpng'))
    assert admin.get('/api/clusters/x1/pve-access').status_code == 400
