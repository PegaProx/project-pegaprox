"""Container feature flags after creation, and PCI/USB passthrough through cluster resource
mappings.

Proxmox keeps two kinds of change for root@pam and compares the signed-in user with that
name as text, so an API token never passes, not even one of root's:

  * LXC feature flags: every flag of a privileged container, every flag but nesting of an
    unprivileged one (pve-container check_ct_modify_config_perm); nesting alone wants
    VM.Allocate. The running value is compared with the one sent, value by value.
  * a raw host device in hostpciN / usbN, added or removed (qemu-server check_hostpci_perm,
    check_usb_perm). A mapping=<id> needs Mapping.Use and VM.Config.HWType, which a token
    can hold.

The fake cluster below enforces both rules the way PVE does and refuses with 403
otherwise, so a test that passes has sent the change on a session PVE would take. The
three ways a cluster is connected: an API token and nothing else, root@pam with a
password that talks through the token minted at the first login (#110), and root@pam's
own password session.

MK Oct 2026
"""
import json
import types

import pytest

from pegaprox.core.manager import PegaProxManager

from test_ha_api import ha_env, _standby_of_active, _audit  # noqa: F401  (ha_env is a fixture)

CID = 'cluster_1'
CT = f'/api/clusters/{CID}/vms/pve1/lxc/101/features'
VM = f'/api/clusters/{CID}/vms/pve1/qemu/100'
ROOT_SESSIONS = ('session-root', 'ticket')


def _parse(text):
    out = {}
    for part in (text or '').split(','):
        k, sep, v = part.strip().partition('=')
        if k:
            out[k] = v if sep else ''
    return out


def _raw(value):
    """A host device: neither a mapping nor USB's host=spice"""
    return 'mapping=' not in value and value.split(',')[0].lower() != 'host=spice'


class _Resp:
    def __init__(self, status, data=None, message=None):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data, 'message': message} if message else {'data': data})

    def json(self):
        return {'data': self._data}


class FakePVE:
    """The few PVE endpoints these routes use, with PVE's root@pam rules."""

    def __init__(self, features='', unprivileged=True, running=True, mappings=None, vm_config=None):
        self.features, self.pending, self.pending_delete = features, None, False
        self.unprivileged, self.running = unprivileged, running
        self.digest = 'd1'
        self.mappings = mappings or {'pci': [], 'usb': []}
        self.vm_config = dict(vm_config or {})
        self.puts, self.gets, self.sessions = [], [], []
        self.check_node_fails = False
        self.put_fails = None

    def session(self, who):
        pve = self

        class _S:
            closed = False

            def get(s, url, params=None, timeout=None):
                pve.gets.append((who, url, dict(params or {})))
                return pve._get(url, params or {})

            def put(s, url, data=None, timeout=None):
                pve.puts.append((who, url, dict(data or {})))
                return pve._put(who, url, dict(data or {}))

            def close(s):
                s.closed = True
        s = _S()
        self.sessions.append((who, s))
        return s

    # --- reads
    def _get(self, url, params):
        if url.endswith('/lxc/101/pending'):
            rows = [{'key': 'unprivileged', 'value': 1 if self.unprivileged else 0},
                    {'key': 'digest', 'value': self.digest}, {'key': 'hostname', 'value': 'ct101'}]
            item = {'key': 'features'}
            if self.features:
                item['value'] = self.features
            if self.pending is not None:
                item['pending'] = self.pending
            if self.pending_delete:
                item['delete'] = 1
            if len(item) > 1:
                rows.append(item)
            return _Resp(200, rows)
        for kind in ('pci', 'usb'):
            if url.endswith(f'/cluster/mapping/{kind}'):
                if params.get('check-node') and self.check_node_fails:
                    return _Resp(500, None, 'no such node')
                rows = []
                for m in self.mappings[kind]:
                    row = dict(m)
                    if params.get('check-node'):
                        row['checks'] = list(m.get('_checks', []))
                    row.pop('_checks', None)
                    rows.append(row)
                return _Resp(200, rows)
        if url.endswith('/qemu/100/config'):
            return _Resp(200, dict(self.vm_config))
        return _Resp(404, None, 'not mocked')

    # --- writes, with PVE's permission rules
    def _features_allowed(self, who, new):
        if who in ROOT_SESSIONS:
            return True
        if not self.unprivileged:
            return False
        old = _parse(self.features)
        if new is None:
            return set(old) <= {'nesting'}
        new = _parse(new)
        return all(k == 'nesting' for k in set(old) | set(new) if old.get(k, '') != new.get(k, ''))

    def _put(self, who, url, body):
        if self.put_fails:
            return _Resp(self.put_fails[0], None, self.put_fails[1])
        if url.endswith('/lxc/101/config'):
            if body.get('digest') and body['digest'] != self.digest:
                return _Resp(500, None, 'detected modified configuration - file changed by other user?')
            new = None if body.get('delete') == 'features' else body.get('features')
            if not self._features_allowed(who, new):
                return _Resp(403, None, 'changing feature flags (except nesting) is only allowed for root@pam')
            if self.running:
                self.pending, self.pending_delete = (new, False) if new is not None else (None, True)
                if new == self.features:
                    self.pending = None
            else:
                self.features = new or ''
            self.digest = 'd2'
            return _Resp(200, None)
        if url.endswith('/qemu/100/config'):
            for key, value in body.items():
                if key == 'delete':
                    old = self.vm_config.get(value, '')
                    if _raw(old) and who not in ROOT_SESSIONS:
                        return _Resp(403, None, f"only root can set '{value}' config for real devices")
                    self.vm_config.pop(value, None)
                elif key.startswith(('hostpci', 'usb')):
                    if _raw(value) and who not in ROOT_SESSIONS:
                        return _Resp(403, None, f"only root can set '{key}' config for non-mapped devices")
                    self.vm_config[key] = value
            return _Resp(200, None)
        return _Resp(404, None, 'not mocked')


def _manager(api, pve, user='root@pam', has_pw=True, minted=True):
    """minted: the cluster talks to the API with a token (one we minted, or the one it was
    added with when user carries a '!')."""
    m = api.make_fake_manager(CID)
    cfg = types.SimpleNamespace(name=CID, user=user)
    cfg.pass_ = ('p' * 12) if has_pw else ''
    m.config = cfg
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m._api_token = 'root@pam!pp=fake' if minted or '!' in user else None
    m.pve_root_access = lambda: PegaProxManager.pve_root_access(m)
    direct = 'session-root' if (user == 'root@pam' and not m._api_token) else 'session-token'
    m._create_session = lambda: pve.session(direct)

    def _priv(what='OSD create/destroy'):
        return pve.session('ticket'), None
    m.create_privileged_session = _priv
    api.set_manager(CID, m)
    return m


TOKEN_ONLY = dict(user='root@pam!pegaprox', has_pw=True, minted=True)   # pass_ is the token secret here
MINTED = dict(user='root@pam', has_pw=True, minted=True)
ROOT_PW = dict(user='root@pam', has_pw=True, minted=False)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- what the connection may do -----------------------------------------------------------

@pytest.mark.parametrize('user,pw,api_token,expect', [
    ('root@pam', True, None, {'via': 'password', 'root': True, 'fresh_ticket': False, 'reason': None}),
    ('root@pam', True, 'root@pam!pp=x', {'via': 'token', 'root': True, 'fresh_ticket': True, 'reason': None}),
    ('root@pam', False, 'root@pam!pp=x', {'via': 'token', 'root': False, 'fresh_ticket': False, 'reason': 'no_password'}),
    ('root@pam!ci', True, 'root@pam!ci=x', {'via': 'token', 'root': False, 'fresh_ticket': False, 'reason': 'token'}),
    ('admin@pve', True, None, {'via': 'password', 'root': False, 'fresh_ticket': False, 'reason': 'not_root'}),
    ('admin@pve', True, 'admin@pve!pp=x', {'via': 'token', 'root': False, 'fresh_ticket': False, 'reason': 'not_root'}),
    # PVE compares the text: another realm's root is not root@pam
    ('root@pve', True, None, {'via': 'password', 'root': False, 'fresh_ticket': False, 'reason': 'not_root'}),
])
def test_root_access_follows_how_the_cluster_is_connected(user, pw, api_token, expect):
    cfg = types.SimpleNamespace(user=user)
    cfg.pass_ = 'p' * 12 if pw else ''
    fake = types.SimpleNamespace(config=cfg, _api_token=api_token)
    assert PegaProxManager.pve_root_access(fake) == expect


def test_a_root_login_with_two_factor_is_refused_by_name(monkeypatch):
    import logging
    import pegaprox.core.manager as mgr_mod

    class _Login:
        def __init__(self):
            self.cookies, self.headers, self.closed = {}, {}, False
            self.verify = None

        def mount(self, *a, **k):
            pass

        def post(self, url, data=None, timeout=None):
            r = types.SimpleNamespace(status_code=200)
            r.json = lambda: {'data': {'ticket': 'PVE:partial', 'CSRFPreventionToken': 'c', 'NeedTFA': 1}}
            return r

        def close(self):
            self.closed = True
    made = []
    monkeypatch.setattr(mgr_mod.requests, 'Session', lambda: made.append(_Login()) or made[-1])
    cfg = types.SimpleNamespace(user='root@pam')
    cfg.pass_ = 'p' * 12
    fake = types.SimpleNamespace(config=cfg, _ssl_verify=False, host='192.0.2.10', api_port=8006,
                                 logger=logging.getLogger('t'))
    session, err = PegaProxManager.create_privileged_session(fake, 'LXC feature flags')
    assert session is None
    assert 'two-factor' in err and 'LXC feature flags' in err
    assert made and made[0].closed
    # the Ceph callers keep their wording
    cfg.user = 'root@pam!x'
    assert 'OSD create/destroy' in PegaProxManager.create_privileged_session(fake)[1]


# --- container features ---------------------------------------------------------------------

def test_the_features_read_shows_what_runs_and_what_waits(api, admin):
    pve = FakePVE(features='nesting=1,force_rw_sys=1,mount=nfs;ext4')
    pve.pending = 'nesting=1,keyctl=1,force_rw_sys=1,mount=nfs;ext4'
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.get(CT)
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['features'] == {'nesting': True, 'keyctl': True, 'fuse': False, 'mknod': False,
                             'mount': {'nfs': True, 'cifs': False}}
    assert d['current']['keyctl'] is False
    assert d['pending'] is True and d['unprivileged'] is True
    assert d['kept'] == ['force_rw_sys=1', 'mount=ext4']
    assert d['access'] == {'via': 'token', 'root': False, 'fresh_ticket': False, 'reason': 'token'}
    assert not pve.puts


def test_nesting_alone_goes_through_the_token(api, admin):
    pve = FakePVE(features='')
    _manager(api, pve, user='root@pam', has_pw=False, minted=True)
    r = admin.put(CT, json={'nesting': True})
    assert r.status_code == 200, r.data
    assert r.get_json()['changed'] is True and r.get_json()['pending'] is True
    assert r.get_json()['root_login'] is False
    (who, url, body), = pve.puts
    assert who == 'session-token' and url.endswith('/nodes/pve1/lxc/101/config')
    assert body == {'features': 'nesting=1', 'digest': 'd1'}
    rows = _audit('vm.features_changed')
    assert len(rows) == 1 and "'-' -> 'nesting=1'" in rows[0]['details']


def test_a_root_only_flag_on_a_token_cluster_is_refused_with_the_reason(api, admin):
    pve = FakePVE(features='nesting=1')
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.put(CT, json={'keyctl': True})
    assert r.status_code == 403, r.data
    d = r.get_json()
    assert d['code'] == 'PVE_ROOT_REQUIRED' and d['reason'] == 'token'
    assert 'other than nesting' in d['error']
    assert not pve.puts and not _audit('vm.features_changed')


def test_a_minted_token_cluster_changes_root_flags_through_a_root_login(api, admin):
    pve = FakePVE(features='nesting=1')
    _manager(api, pve, **MINTED)
    r = admin.put(CT, json={'keyctl': True, 'mount': {'nfs': True, 'cifs': True}})
    assert r.status_code == 200, r.data
    assert r.get_json()['root_login'] is True and r.get_json()['pending'] is True
    (who, _url, body), = pve.puts
    assert who == 'ticket'
    assert body['features'] == 'nesting=1,keyctl=1,mount=nfs;cifs'
    # the session of its own is closed again
    assert all(s.closed for w, s in pve.sessions if w == 'ticket')
    assert 'through a root@pam login' in _audit('vm.features_changed')[0]['details']


def test_root_password_cluster_uses_its_own_session(api, admin):
    pve = FakePVE(features='', running=False)
    m = _manager(api, pve, **ROOT_PW)
    m.create_privileged_session = lambda *a, **k: pytest.fail('no second login for a root@pam session')
    r = admin.put(CT, json={'fuse': True, 'mknod': True})
    assert r.status_code == 200, r.data
    assert r.get_json()['pending'] is False      # stopped: applied at once
    assert [p[0] for p in pve.puts] == ['session-root']
    assert pve.features == 'fuse=1,mknod=1'


def test_a_privileged_container_needs_root_even_for_nesting(api, admin):
    pve = FakePVE(features='', unprivileged=False)
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.put(CT, json={'nesting': True})
    assert r.status_code == 403 and 'privileged container' in r.get_json()['error']
    assert not pve.puts
    # counterproof: with root at hand the same change goes through
    pve2 = FakePVE(features='', unprivileged=False)
    _manager(api, pve2, **MINTED)
    assert admin.put(CT, json={'nesting': True}).status_code == 200
    assert pve2.puts[0][0] == 'ticket'


def test_untouched_flags_keep_their_text_so_pve_sees_only_nesting(api, admin):
    """keyctl=0 is not the same text as no keyctl to PVE: rewriting it would make a
    nesting change a root@pam one."""
    pve = FakePVE(features='nesting=1,keyctl=0,force_rw_sys=1,mount=nfs;ext4')
    _manager(api, pve, user='root@pam', has_pw=False, minted=True)
    r = admin.put(CT, json={'nesting': False, 'keyctl': False, 'mount': {'nfs': True}})
    assert r.status_code == 200, r.data
    assert pve.puts[0][2]['features'] == 'keyctl=0,force_rw_sys=1,mount=nfs;ext4'


def test_switching_the_last_flag_off_deletes_the_key(api, admin):
    pve = FakePVE(features='nesting=1')
    _manager(api, pve, user='root@pam', has_pw=False, minted=True)
    assert admin.put(CT, json={'nesting': False}).status_code == 200
    assert pve.puts[0][2] == {'delete': 'features', 'digest': 'd1'}
    assert pve.pending_delete is True


def test_no_change_sends_nothing(api, admin):
    pve = FakePVE(features='nesting=1,mount=nfs')
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.put(CT, json={'nesting': True, 'mount': {'nfs': True, 'cifs': False}})
    assert r.status_code == 200 and r.get_json()['changed'] is False
    assert not pve.puts


@pytest.mark.parametrize('body', [
    {'nesting': 1}, {'keyctl': 'true'}, {'force_rw_sys': True}, {'mount': {'ext4': True}},
    {'mount': ['nfs']}, {'mount': {'nfs': 'yes'}}, ['nesting'],
])
def test_a_malformed_body_reaches_no_cluster(api, admin, body):
    pve = FakePVE(features='')
    _manager(api, pve, **ROOT_PW)
    r = admin.put(CT, json=body)
    assert r.status_code == 400, (body, r.data)
    assert not pve.puts and not pve.gets


def test_a_refusal_of_pve_is_reported_not_faked(api, admin):
    pve = FakePVE(features='')
    pve.put_fails = (500, "CT is locked (backup)")
    _manager(api, pve, **ROOT_PW)
    r = admin.put(CT, json={'nesting': True})
    assert r.status_code == 502 and 'locked' in r.get_json()['error']
    assert not _audit('vm.features_changed')


def test_a_change_made_elsewhere_in_between_is_not_overwritten(api, admin):
    """The digest of the read goes along: PVE refuses when the config moved meanwhile."""
    pve = FakePVE(features='')
    _manager(api, pve, **ROOT_PW)
    real_get = pve._get

    def moved(url, params):
        r = real_get(url, params)
        pve.digest = 'someone-else'
        return r
    pve._get = moved
    r = admin.put(CT, json={'fuse': True})
    assert r.status_code == 502 and 'modified' in r.get_json()['error']


# --- who reaches the feature routes ---------------------------------------------------------

def _identities(api, seed):
    # every tenant before the first request: rbac loads the tenant table once
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    return {
        'admin': api.as_user(seed.user('root', role='admin')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}})),
        'other_tenant': api.as_user(seed.user('ac', role='user', tenant_id='acme',
                                              permissions=['vm.config', 'vm.view'])),
        # an operator whose tenant owns the cluster is no confined caller
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }


def test_the_feature_routes_by_identity(api, seed):
    who = _identities(api, seed)
    pve = FakePVE(features='')
    _manager(api, pve, **ROOT_PW)
    expect = {'admin': (200, 200), 'viewer': (200, 403), 'confined_admin': (403, 403),
              'other_tenant': (403, 403), 'owning_tenant': (200, 200)}
    for name, (get_status, put_status) in expect.items():
        assert who[name].get(CT).status_code == get_status, name
        before = len(pve.puts)
        assert who[name].put(CT, json={'fuse': True}).status_code == put_status, name
        if put_status != 200:
            assert len(pve.puts) == before, name
        # the next caller starts from the same container again
        pve.pending, pve.pending_delete = None, False


def test_a_standby_changes_no_feature_and_attaches_nothing(ha_env, seed):
    api = ha_env.api
    admin = api.as_user(seed.user('root', role='admin'))
    pve = FakePVE(features='', mappings={'pci': [{'id': 'gpu0', 'map': ['node=pve1,path=0000:01:00.0,id=10de:1b80']}],
                                         'usb': []},
                  vm_config={'hostpci0': '0000:02:00.0'})
    _manager(api, pve, **ROOT_PW)
    _standby_of_active(ha_env)
    for method, path, body in (('put', CT, {'nesting': True}),
                               ('post', f'{VM}/passthrough/pci', {'mapping': 'gpu0'}),
                               ('post', f'{VM}/passthrough/usb', {'vendorid': '1234', 'productid': 'abcd'}),
                               ('delete', f'{VM}/passthrough/pci/hostpci0', None)):
        kw = {'json': body} if body is not None else {}
        r = getattr(admin, method)(path, **kw)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.data)
    assert not pve.puts
    # reading stays open there
    assert admin.get(CT).status_code == 200


# --- passthrough through mappings -----------------------------------------------------------

MAPPINGS = {
    'pci': [
        {'id': 'gpu0', 'description': 'RTX 4000', 'live-migration-capable': 0,
         'map': ['node=pve1,path=0000:01:00.0,id=10de:1b80,iommugroup=12',
                 'node=pve2,path=0000:41:00.0,id=10de:1b80,description="slot 2, lower"'],
         '_checks': [{'severity': 'warning', 'message': 'IOMMU group changed'}]},
        {'id': 'nic-only-pve3', 'description': '', 'map': ['node=pve3,path=0000:05:00.0,id=8086:1572']},
    ],
    'usb': [{'id': 'dongle', 'description': 'License key', 'map': ['node=pve1,id=096e:0006', 'node=pve2,path=1-2.3,id=096e:0006']}],
}


def test_the_mapping_list_names_the_nodes_and_this_nodes_checks(api, admin):
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.get(f'{VM}/passthrough/mappings?kind=pci')
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['raw_allowed'] is False and d['access']['reason'] == 'token'
    gpu, nic = d['mappings']
    assert gpu['id'] == 'gpu0' and gpu['nodes'] == ['pve1', 'pve2'] and gpu['on_node'] is True
    assert gpu['entries'][1]['description'] == 'slot 2, lower'
    assert gpu['checks'] == [{'severity': 'warning', 'message': 'IOMMU group changed'}]
    assert nic['on_node'] is False and nic['nodes'] == ['pve3']
    # one read, checked on the VM's node
    assert [g[2] for g in pve.gets] == [{'check-node': 'pve1'}]


def test_a_node_that_cannot_check_still_gets_the_list(api, admin):
    pve = FakePVE(mappings=MAPPINGS)
    pve.check_node_fails = True
    _manager(api, pve, **TOKEN_ONLY)
    d = admin.get(f'{VM}/passthrough/mappings?kind=usb').get_json()
    assert [m['id'] for m in d['mappings']] == ['dongle']
    assert d['mappings'][0]['nodes'] == ['pve1', 'pve2'] and d['mappings'][0]['checks'] == []
    assert [g[2] for g in pve.gets] == [{'check-node': 'pve1'}, {}]


def test_a_mapped_pci_device_goes_through_the_token(api, admin):
    pve = FakePVE(mappings=MAPPINGS, vm_config={'hostpci0': 'mapping=other'})
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.post(f'{VM}/passthrough/pci', json={'mapping': 'gpu0', 'pcie': True})
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['slot'] == 1 and d['nodes'] == ['pve1', 'pve2'] and d['covers_node'] is True
    assert pve.puts[-1][0] == 'session-token'
    assert pve.vm_config['hostpci1'] == 'mapping=gpu0,pcie=1'
    assert 'mapped PCI device gpu0' in _audit('vm.pci_added')[0]['details']


def test_a_mapping_off_this_node_is_added_with_a_warning(api, admin):
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **TOKEN_ONLY)
    d = admin.post(f'{VM}/passthrough/pci', json={'mapping': 'nic-only-pve3'}).get_json()
    assert d['covers_node'] is False and d['nodes'] == ['pve3']


def test_an_unknown_mapping_is_not_written(api, admin):
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.post(f'{VM}/passthrough/pci', json={'mapping': 'gpu9'})
    assert r.status_code == 404 and not pve.puts


@pytest.mark.parametrize('body', [
    {'device_id': '0000:01:00.0,romfile=/tmp/x.rom'}, {'device_id': '01:00.0;x'}, {'device_id': 5},
    {'mapping': 'gpu0,romfile=x'}, {'mapping': '0gpu'}, {'mapping': 'gpu0\n'}, {'device_id': '01:00.0\n'}, {},
])
def test_a_pci_id_that_would_add_options_is_refused(api, admin, body):
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **ROOT_PW)
    assert admin.post(f'{VM}/passthrough/pci', json=body).status_code == 400, body
    assert not pve.puts


def test_a_raw_pci_device_on_a_token_cluster_is_refused(api, admin):
    pve = FakePVE()
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.post(f'{VM}/passthrough/pci', json={'device_id': '0000:01:00.0'})
    assert r.status_code == 403
    assert r.get_json()['code'] == 'PVE_ROOT_REQUIRED' and 'resource mapping' in r.get_json()['error']
    assert not pve.puts


def test_a_raw_pci_device_on_a_minted_token_cluster_uses_a_root_login(api, admin):
    pve = FakePVE()
    _manager(api, pve, **MINTED)
    r = admin.post(f'{VM}/passthrough/pci', json={'device_id': '0000:01:00.0', 'pcie': True, 'rombar': False})
    assert r.status_code == 200, r.data
    assert pve.puts[-1][0] == 'ticket' and pve.vm_config['hostpci0'] == '0000:01:00.0,pcie=1,rombar=0'
    assert all(s.closed for w, s in pve.sessions if w == 'ticket')


def test_usb_by_mapping_and_by_id(api, admin):
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.post(f'{VM}/passthrough/usb', json={'mapping': 'dongle', 'usb3': True})
    assert r.status_code == 200 and pve.vm_config['usb0'] == 'mapping=dongle,usb3=1'
    r = admin.post(f'{VM}/passthrough/usb', json={'vendorid': '096e', 'productid': '0006'})
    assert r.status_code == 403 and r.get_json()['reason'] == 'token'
    for bad in ({'vendorid': '096e,x', 'productid': '0006'}, {'hostbus': '1', 'hostport': '2;3'}):
        assert admin.post(f'{VM}/passthrough/usb', json=bad).status_code == 400, bad
    pve2 = FakePVE()
    _manager(api, pve2, **ROOT_PW)
    assert admin.post(f'{VM}/passthrough/usb', json={'hostbus': '1', 'hostport': '2.3'}).status_code == 200
    assert pve2.vm_config['usb0'] == 'host=1-2.3' and pve2.puts[-1][0] == 'session-root'


def test_removing_follows_the_same_rule(api, admin):
    pve = FakePVE(vm_config={'hostpci0': '0000:01:00.0', 'hostpci1': 'mapping=gpu0', 'usb0': 'host=spice'})
    _manager(api, pve, **TOKEN_ONLY)
    r = admin.delete(f'{VM}/passthrough/pci/hostpci0')
    assert r.status_code == 403 and r.get_json()['code'] == 'PVE_ROOT_REQUIRED'
    assert admin.delete(f'{VM}/passthrough/pci/hostpci1').status_code == 200
    assert admin.delete(f'{VM}/passthrough/usb/usb0').status_code == 200     # spice is nobody's device
    assert [p[0] for p in pve.puts] == ['session-token', 'session-token']
    assert admin.delete(f'{VM}/passthrough/pci/hostpci0x').status_code == 400
    pve2 = FakePVE(vm_config={'hostpci0': '0000:01:00.0'})
    _manager(api, pve2, **MINTED)
    assert admin.delete(f'{VM}/passthrough/pci/hostpci0').status_code == 200
    assert pve2.puts[-1][0] == 'ticket' and 'hostpci0' not in pve2.vm_config


def test_the_device_list_names_the_mapping(api, admin):
    pve = FakePVE(vm_config={'hostpci0': 'mapping=gpu0,pcie=1', 'usb1': 'mapping=dongle', 'hostpci1': 'host=02:00.0'})
    _manager(api, pve, **TOKEN_ONLY)
    d = admin.get(f'{VM}/passthrough').get_json()
    by_key = {x['key']: x['parsed'] for x in d['pci'] + d['usb']}
    assert by_key['hostpci0'] == {'device': None, 'mapping': 'gpu0', 'options': {'pcie': '1'}}
    assert by_key['hostpci1']['device'] == '02:00.0'
    assert by_key['usb1']['mapping'] == 'dongle'


def test_the_passthrough_routes_by_identity(api, seed):
    who = _identities(api, seed)
    pve = FakePVE(mappings=MAPPINGS)
    _manager(api, pve, **TOKEN_ONLY)
    expect = {'admin': 200, 'viewer': 403, 'confined_admin': 403, 'other_tenant': 403,
              'owning_tenant': 200}
    for name, status in expect.items():
        assert who[name].get(f'{VM}/passthrough/mappings?kind=pci').status_code == status, name
        before = len(pve.puts)
        assert who[name].post(f'{VM}/passthrough/pci', json={'mapping': 'gpu0'}).status_code == status, name
        if status != 200:
            assert len(pve.puts) == before, name
