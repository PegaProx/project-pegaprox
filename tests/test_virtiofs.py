"""Directory mappings and virtiofs, a directory of the host shared with a VM (PVE 8.4+).

A directory mapping (pve-guest-common PVE/Mapping/Dir.pm, pve-manager
PVE/API2/Cluster/Mapping/Dir.pm) is an id with one map entry per node:

    node=<node>,path=<absolute path>

PVE checks the path against ^/[^;,=()]+ (not anchored at the end) and looks at the
directory itself only on the node that answers the request. A VM points at a mapping with
virtiofsN, a property string PVE parses as pve-qm-virtiofs (qemu-server
PVE/QemuServer/Virtiofs.pm):

    [dirid=]<mapping-id> [,cache=<auto|always|metadata|never>] [,direct-io=<1|0>]
    [,expose-acl=<1|0>] [,expose-xattr=<1|0>]

The fake PVE below parses both the way PVE::JSONSchema does and answers 400 for what PVE
refuses, and 500 for what PVE's own checks die on, so a value it stores is one PVE would
have stored too. What the VM then needs to start is _vm_starts.

MK Oct 2026
"""
import json
import logging
import re
import time
import types
from urllib.parse import parse_qs

import pytest

from pegaprox.core.manager import PegaProxManager

from test_ha_api import ha_env, _standby_of_active, _audit  # noqa: F401  (ha_env is a fixture)

CID = 'cluster_1'
VM = f'/api/clusters/{CID}/vms/pve1/qemu/100'
CFG = f'{VM}/config'
DIR = f'/api/clusters/{CID}/datacenter/mapping/dir'
NODES = ('pve1', 'pve2', 'pve3')
LOCAL = 'pve1'       # the node the API requests reach
CACHE = ('auto', 'always', 'metadata', 'never')
FLAGS = ('direct-io', 'expose-acl', 'expose-xattr')


def _parse_boolean(v):
    if re.fullmatch(r'(?i:1|on|yes|true)', v, re.A):
        return '1'
    if re.fullmatch(r'(?i:0|off|no|false)', v, re.A):
        return '0'
    return v


def _pve_parses(value):
    """pve-qm-virtiofs as PVE::JSONSchema::parse_property_string + check_object read it"""
    res = {}
    for part in value.split(','):
        if re.fullmatch(r'\s*', part):
            continue
        if '\n' in part:
            raise ValueError('properties must not contain newlines')
        m = re.fullmatch(r'([^=]+)=(.+)', part, re.S)
        if m:
            key, val = m.groups()
            if key in res:
                raise ValueError(f'duplicate key in comma-separated list property: {key}')
            if key not in ('dirid', 'cache') + FLAGS:
                raise ValueError(f'invalid key in comma-separated list property: {key}')
            res[key] = _parse_boolean(val) if key in FLAGS else val
        elif '=' not in part:
            if 'dirid' in res:
                raise ValueError('duplicate key in comma-separated list property: dirid')
            res['dirid'] = part
        else:
            raise ValueError('missing key in comma-separated list property')
    if 'dirid' not in res:
        raise ValueError('dirid: property is missing and it is not optional')
    if not re.fullmatch(r'[a-z][a-z0-9_-]+', res['dirid'], re.I | re.A):
        raise ValueError(f"dirid: invalid configuration ID '{res['dirid']}'")
    if 'cache' in res and res['cache'] not in CACHE:
        raise ValueError('cache: value does not have a value in the enumeration')
    for flag in FLAGS:
        if flag in res and res[flag] not in ('0', '1'):
            raise ValueError(f"{flag}: type check ('boolean') failed")
    return res


def _windows(ostype):
    return ostype in ('wxp', 'w2k', 'w2k3', 'w2k8', 'wvista') or bool(re.fullmatch(r'win\d+', ostype or ''))


def _map_entry(text):
    out = {}
    for part in text.split(','):
        k, _s, v = part.partition('=')
        out[k] = v
    return out


class _Resp:
    def __init__(self, status, data=None, message=None):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data, 'message': message} if message else {'data': data})

    def json(self):
        return {'data': self._data}


class FakePVE:
    """GET /nodes, the directory mapping API and a VM config, with PVE's checks."""

    def __init__(self, mappings=None, configs=None, local_paths=('/mnt/share', '/srv/media')):
        # id -> {'description': str, 'map': [str]}
        self.mappings = {k: dict(v) for k, v in (mappings or {}).items()}
        self.configs = {vmid: dict(c) for vmid, c in (configs or {100: {'name': 'web01', 'ostype': 'l26'}}).items()}
        self.local_paths = set(local_paths)
        self.digest = 'a1b2c3'
        self.calls = []

    def session(self):
        pve = self

        class _S:
            def get(s, url, params=None, timeout=None):
                pve.calls.append(('GET', url, dict(params or {})))
                return pve._get(url, params or {})

            def post(s, url, data=None, timeout=None):
                pve.calls.append(('POST', url, data))
                return pve._post(url, data or {})

            def put(s, url, data=None, timeout=None):
                pve.calls.append(('PUT', url, data))
                return pve._put(url, data or {})

            def delete(s, url, timeout=None):
                pve.calls.append(('DELETE', url, None))
                return pve._delete(url)

            def close(s):
                pass
        return _S()

    def writes(self):
        return [c for c in self.calls if c[0] != 'GET']

    def _get(self, url, params):
        if url.endswith('/api2/json/nodes'):
            return _Resp(200, [{'node': n, 'status': 'online' if n != 'pve3' else 'offline'} for n in NODES])
        if url.endswith('/cluster/mapping/dir'):
            rows = []
            for mid, m in self.mappings.items():
                row = {'id': mid, 'map': list(m['map']), 'digest': self.digest}
                if m.get('description'):
                    row['description'] = m['description']
                node = params.get('check-node')
                if node:
                    entries = [_map_entry(x) for x in m['map'] if _map_entry(x).get('node') == node]
                    row['checks'] = ([] if entries else [{'severity': 'warning', 'message': f'No mapping for node {node}.'}])
                    row['checks'] += [{'severity': 'error', 'message': f"Invalid configuration: Path {e['path']} does not exist\n"}
                                      for e in entries if node == LOCAL and e['path'] not in self.local_paths]
                rows.append(row)
            return _Resp(200, rows)
        return _Resp(404, None, 'not mocked')

    def _check_map(self, items):
        """check_config + assert_valid_map_list"""
        seen = {}
        for item in items:
            entry = _map_entry(item)
            if set(entry) != {'node', 'path'}:
                return _Resp(400, None, 'Parameter verification failed.')
            if not re.fullmatch(r'[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?', entry['node']):
                return _Resp(400, None, 'Parameter verification failed.')
            if not re.match(r'/[^;,=()]+', entry['path']):
                return _Resp(400, None, 'Parameter verification failed.')
            if entry['node'] == LOCAL and entry['path'] not in self.local_paths:
                return _Resp(500, None, f"Path {entry['path']} does not exist\n")
            seen[entry['node']] = seen.get(entry['node'], 0) + 1
        for node, n in seen.items():
            if n > 1:
                return _Resp(500, None, f"Node '{node}' is specified {n} times.\n")
        return None

    def _post(self, url, data):
        if url.endswith('/cluster/mapping/dir'):
            mid = data.get('id', '')
            if not re.fullmatch(r'[a-z][a-z0-9_-]+', mid, re.I):
                return _Resp(400, None, 'Parameter verification failed.')
            items = data.get('map') or []
            if isinstance(items, str):
                items = [items]
            if not items:
                return _Resp(400, None, 'Parameter verification failed.')
            bad = self._check_map(items)
            if bad:
                return bad
            if mid in self.mappings:
                return _Resp(500, None, f"create directory mapping failed: dir ID '{mid}' already defined\n")
            self.mappings[mid] = {'description': data.get('description', ''), 'map': list(items)}
            self.digest = format(int(self.digest, 16) + 1, 'x')
            return _Resp(200, None)
        return _Resp(404, None, 'not mocked')

    def _put(self, url, data):
        m = re.search(r'/cluster/mapping/dir/([^/]+)$', url)
        if m:
            mid = m.group(1)
            if data.get('digest') and data['digest'] != self.digest:
                return _Resp(500, None, 'update directory mapping failed: detected modified configuration - '
                                        'file changed by other user? Try again.\n')
            if mid not in self.mappings:
                return _Resp(500, None, f"update directory mapping failed: dir ID '{mid}' does not exist\n")
            if 'map' in data:
                items = data['map'] if isinstance(data['map'], list) else [data['map']]
                bad = self._check_map(items)
                if bad:
                    return bad
                self.mappings[mid]['map'] = list(items)
            if 'description' in data:
                self.mappings[mid]['description'] = data['description']
            if data.get('delete') == 'description':
                self.mappings[mid]['description'] = ''
            self.digest = format(int(self.digest, 16) + 1, 'x')
            return _Resp(200, None)
        return _Resp(404, None, 'not mocked')

    def _delete(self, url):
        m = re.search(r'/cluster/mapping/dir/([^/]+)$', url)
        if m:
            self.mappings.pop(m.group(1), None)
            return _Resp(200, None)
        return _Resp(404, None, 'not mocked')

    # the VM config, through the real PegaProxManager.update_vm_config
    def put_config(self, url, data):
        vmid = int(re.search(r'/qemu/(\d+)/config$', url).group(1))
        body = dict(data or {})
        self.calls.append(('PUT', url, dict(body)))
        for key, value in body.items():
            if key.startswith('virtiofs'):
                if not re.fullmatch(r'virtiofs[0-9]', key):
                    return _Resp(400, None, f"Parameter verification failed. {key}: property is not defined in schema")
                try:
                    _pve_parses(value)
                except ValueError as e:
                    return _Resp(400, None, f'Parameter verification failed. {key}: {e}')
        cfg = self.configs.setdefault(vmid, {})
        for key in str(body.pop('delete', '') or '').split(','):
            cfg.pop(key.strip(), None)
        cfg.update(body)
        return _Resp(200, None)

    def vm_starts(self, vmid, node='pve1'):
        """What qemu-server's config() and start_all_virtiofsd need on `node`"""
        cfg = self.configs[vmid]
        for key, value in cfg.items():
            if not re.fullmatch(r'virtiofs[0-9]', key):
                continue
            parsed = _pve_parses(value)
            mapping = self.mappings.get(parsed['dirid'])
            if mapping is None:
                return False     # Directory ID x does not exist
            if not [x for x in mapping['map'] if _map_entry(x)['node'] == node]:
                return False     # No directory mapping for node x
            if parsed.get('expose-acl') == '1' and _windows(cfg.get('ostype')):
                return False     # Please disable ACLs for virtiofs on Windows VMs
        return True


def _manager(api, pve, cluster_type='proxmox', version=(9, 0)):
    m = api.make_fake_manager(CID, cluster_type=cluster_type)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m.config = types.SimpleNamespace(name=CID)
    m.logger = logging.getLogger('test_virtiofs')
    m._create_session = pve.session
    m.get_pve_version_tuple = lambda: version
    m._api_put = lambda url, data=None, **kw: pve.put_config(url, data)
    m.update_vm_config = lambda node, vmid, vm_type, updates: PegaProxManager.update_vm_config(
        m, node, vmid, vm_type, updates)
    m.get_vm_config = lambda node, vmid, vm_type: (
        {'success': True, 'config': {'raw': dict(pve.configs[int(vmid)])}} if int(vmid) in pve.configs
        else {'success': False, 'error': 'no such VM'})
    api.set_manager(CID, m)
    return m


SHARE = {'share': {'description': 'Media', 'map': ['node=pve1,path=/mnt/share', 'node=pve2,path=/srv/share']},
         'backups': {'description': '', 'map': ['node=pve2,path=/srv/backups']}}


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- virtiofsN through the config route ---------------------------------------------------------

@pytest.mark.parametrize('sent,stored', [
    ('share', 'share'),
    ('dirid=share', 'share'),
    ('cache=never,share', 'share,cache=never'),
    ('share,,direct-io=yes,expose-xattr=ON', 'share,direct-io=1,expose-xattr=1'),
    ('share,expose-acl=1,expose-xattr=0', 'share,expose-acl=1,expose-xattr=0'),
    ('dirid=share,cache=metadata,direct-io=false', 'share,cache=metadata,direct-io=0'),
    ('share,cache=auto', 'share,cache=auto'),
])
def test_a_valid_virtiofs_reaches_pve_in_one_spelling(api, admin, sent, stored):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.put(CFG, json={'virtiofs0': sent})
    assert r.status_code == 200, r.data
    (method, url, body), = pve.writes()
    assert url.endswith('/nodes/pve1/qemu/100/config') and body == {'virtiofs0': stored}
    assert pve.configs[100]['virtiofs0'] == stored
    assert _pve_parses(stored) == _pve_parses(sent)
    assert pve.vm_starts(100)
    rows = _audit('vm.config_changed')
    assert len(rows) == 1 and f'virtiofs0={stored}' in rows[0]['details']


REFUSED = [
    # PVE refuses these itself; they stop here with the reason instead of a 500
    '', ',', 'cache=auto', 'share,backups', 'dirid=share,dirid=backups', 'share,dirid=backups',
    'share,cache=fast', 'share,cache=AUTO', 'share,cache= auto', 'share,direct-io=2',
    'share,direct-io=', 'share,=1', 'share,foo=1', 'share,mapping=gpu0', 's', '1share', 'share x',
    ' share', 'share,expose-acl=1\n', 'share\nbackups',
    # what Python's lower() or int() would read and PVE does not
    'share,direct-io=１', 'share,expose-xattr=İ',
    # PVE stores this one, and the VM then does not start: the mapping does not exist
    'nosuch',
    123, None, ['share'], {'dirid': 'share'},
]


@pytest.mark.parametrize('sent', REFUSED, ids=[repr(x)[:40] for x in REFUSED])
def test_an_invalid_virtiofs_is_refused_before_pve(api, admin, sent):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.put(CFG, json={'virtiofs0': sent})
    assert r.status_code == 400, r.data
    assert r.get_json()['error'].startswith('Invalid virtiofs: virtiofs0 ')
    assert not pve.writes() and 'virtiofs0' not in pve.configs[100]
    assert not _audit('vm.config_changed')


def test_every_refused_value_is_one_pve_or_the_start_would_fail_on():
    """The other way round: nothing on the refused list would have worked."""
    for sent in REFUSED:
        if not isinstance(sent, str):
            continue
        try:
            _pve_parses(sent)
        except ValueError:
            continue
        pve = FakePVE(mappings=SHARE, configs={100: {'ostype': 'l26', 'virtiofs0': sent}})
        assert not pve.vm_starts(100), sent


def test_the_error_names_what_is_wrong(api, admin):
    _manager(api, FakePVE(mappings=SHARE))
    msg = lambda v: admin.put(CFG, json={'virtiofs0': v}).get_json()['error']
    assert 'cache is one of auto, always, metadata, never' in msg('share,cache=fast')
    assert 'direct-io is 1 or 0' in msg('share,direct-io=2')
    assert "no option 'foo'" in msg('share,foo=1')
    assert 'dirid twice' in msg('share,backups')
    assert 'needs a directory mapping' in msg('cache=auto')
    assert 'no directory mapping of this cluster (nosuch)' in msg('nosuch')


def test_acls_on_a_windows_vm_are_refused(api, admin):
    pve = FakePVE(mappings=SHARE, configs={100: {'name': 'win', 'ostype': 'win11'}})
    _manager(api, pve)
    r = admin.put(CFG, json={'virtiofs0': 'share,expose-acl=1'})
    assert r.status_code == 400 and 'Windows' in r.get_json()['error'] and not pve.writes()
    # PVE would have stored it, and the VM would not start
    pve.configs[100]['virtiofs0'] = 'share,expose-acl=1'
    assert not pve.vm_starts(100)
    del pve.configs[100]['virtiofs0']
    assert admin.put(CFG, json={'virtiofs0': 'share,expose-xattr=1'}).status_code == 200
    # the ostype sent along counts, not the one before
    assert admin.put(CFG, json={'virtiofs1': 'backups,expose-acl=1', 'ostype': 'l26'}).status_code == 200
    r = admin.put(CFG, json={'virtiofs2': 'share,expose-acl=yes', 'ostype': 'w2k8'})
    assert r.status_code == 400
    assert pve.configs[100]['ostype'] == 'l26' and 'virtiofs2' not in pve.configs[100]


def test_only_virtiofs0_to_9_and_only_on_a_vm(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    for key in ('virtiofs10', 'virtiofs', 'virtiofsx', 'virtiofs01'):
        r = admin.put(CFG, json={key: 'share'})
        assert r.status_code == 400 and 'virtiofs0 to virtiofs9' in r.get_json()['error'], key
    r = admin.put(f'/api/clusters/{CID}/vms/pve1/lxc/101/config', json={'virtiofs0': 'share'})
    assert r.status_code == 400 and 'container' in r.get_json()['error']
    # one bad key stops the whole change
    r = admin.put(CFG, json={'cores': 4, 'virtiofs0': 'share', 'virtiofs1': 'share,cache=fast'})
    assert r.status_code == 400
    assert not pve.writes()
    assert admin.put(CFG, json={'virtiofs9': 'backups'}).status_code == 200


def test_removing_and_other_keys_pass_as_before(api, admin):
    pve = FakePVE(mappings=SHARE, configs={100: {'virtiofs0': 'share', 'cores': 2}})
    _manager(api, pve)
    assert admin.put(CFG, json={'delete': 'virtiofs0'}).status_code == 200
    assert pve.writes()[-1][2] == {'delete': 'virtiofs0'} and 'virtiofs0' not in pve.configs[100]
    assert admin.put(CFG, json={'cores': 4, 'name': 'web01'}).status_code == 200
    assert pve.writes()[-1][2] == {'cores': 4, 'name': 'web01'}
    # nothing to check, nothing read
    assert not [c for c in pve.calls if c[0] == 'GET']


@pytest.mark.parametrize('cluster_type', ['xcpng', 'esxi'])
def test_another_hypervisor_has_no_virtiofs(api, admin, cluster_type):
    m = api.make_fake_manager(CID, cluster_type=cluster_type)
    m.update_vm_config.return_value = {'success': True, 'message': 'ok'}
    m.config = types.SimpleNamespace(name=CID)
    api.set_manager(CID, m)
    r = admin.put(CFG, json={'virtiofs0': 'share'})
    assert r.status_code == 400 and 'Proxmox VE feature' in r.get_json()['error']
    m.update_vm_config.assert_not_called()


def test_an_older_pve_has_no_virtiofs(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve, version=(8, 3))
    r = admin.put(CFG, json={'virtiofs0': 'share'})
    assert r.status_code == 400 and '8.4' in r.get_json()['error']
    assert not pve.writes()


# --- who reaches it -----------------------------------------------------------------------------

def _pool_user(seed, name):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=[CID])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=['vm.config', 'vm.view', 'cluster.view'])
    seed.pool(CID, 'pool_1', name, ['pool.view', 'vm.view', 'vm.config'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'101:qemu': 'pool_1'}, 'timestamp': time.time(),
                                            'refreshing': False}
    return u


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
                                              permissions=['vm.config', 'vm.view', 'cluster.config'])),
        'pool_confined': api.as_user(_pool_user(seed, 'mallory')),
        # an operator whose tenant owns the cluster is no confined caller
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }


def test_the_virtiofs_by_identity(api, seed):
    who = _identities(api, seed)
    pve = FakePVE(mappings=SHARE, configs={100: {'ostype': 'l26'}, 101: {'ostype': 'l26', 'virtiofs0': 'backups'}})
    _manager(api, pve)
    expect = {'admin': 200, 'viewer': 403, 'confined_admin': 403, 'other_tenant': 403,
              'pool_confined': 403, 'owning_tenant': 200}
    for name, status in expect.items():
        before = len(pve.writes())
        r = who[name].put(CFG, json={'virtiofs0': 'share'})
        assert r.status_code == status, (name, r.data)
        if status != 200:
            assert len(pve.writes()) == before, name
        # a refusal comes before the value is looked at
        r = who[name].put(CFG, json={'virtiofs0': 'share,cache=fast'})
        assert r.status_code == (400 if status == 200 else status), name

    # the pool user changes the guest of their pool, but gives it no other directory of the host
    pool = who['pool_confined']
    vm101 = f'/api/clusters/{CID}/vms/pve1/qemu/101/config'
    r = pool.put(vm101, json={'virtiofs1': 'share'})
    assert r.status_code == 403 and r.get_json()['code'] == 'VIRTIOFS_CLUSTER_WIDE'
    assert 'virtiofs1' not in pve.configs[101]
    # not even one that does not exist: the answer is the same, nothing is told about the mappings
    r = pool.put(vm101, json={'virtiofs1': 'nosuch'})
    assert r.status_code == 403 and r.get_json()['code'] == 'VIRTIOFS_CLUSTER_WIDE'
    # the share the VM has: options may change, and it may go
    assert pool.put(vm101, json={'virtiofs0': 'backups,cache=never'}).status_code == 200
    assert pve.configs[101]['virtiofs0'] == 'backups,cache=never'
    assert pool.put(vm101, json={'delete': 'virtiofs0'}).status_code == 200
    assert 'virtiofs0' not in pve.configs[101]


def test_the_virtiofs_dialog_list_by_identity(api, seed):
    who = _identities(api, seed)
    pve = FakePVE(mappings=SHARE, configs={100: {'ostype': 'l26'}, 101: {'ostype': 'l26', 'virtiofs0': 'backups'}})
    _manager(api, pve)
    d = who['admin'].get(f'{VM}/passthrough/mappings?kind=dir').get_json()
    assert d['supported'] is True and d['may_add'] is True
    backups, share = d['mappings']
    assert share['id'] == 'share' and share['nodes'] == ['pve1', 'pve2'] and share['on_node'] is True
    assert share['entries'][0] == {'node': 'pve1', 'path': '/mnt/share', 'id': '', 'description': ''}
    assert backups['on_node'] is False and backups['checks'] == [{'severity': 'warning', 'message': 'No mapping for node pve1.'}]
    # checked on the VM's node
    assert [c[2] for c in pve.calls if c[1].endswith('/mapping/dir')] == [{'check-node': 'pve1'}]

    d = who['pool_confined'].get(f'/api/clusters/{CID}/vms/pve1/qemu/101/passthrough/mappings?kind=dir').get_json()
    assert [m['id'] for m in d['mappings']] == ['backups'] and d['may_add'] is False
    for name in ('viewer', 'confined_admin', 'other_tenant'):
        assert who[name].get(f'{VM}/passthrough/mappings?kind=dir').status_code == 403, name
    assert who['pool_confined'].get(f'{VM}/passthrough/mappings?kind=dir').status_code == 403


def test_a_standby_sets_no_virtiofs_and_no_mapping(ha_env, seed):
    api = ha_env.api
    admin = api.as_user(seed.user('root', role='admin'))
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    _standby_of_active(ha_env)
    for method, path, body in (('put', CFG, {'virtiofs0': 'share'}), ('put', CFG, {'delete': 'virtiofs0'}),
                               ('post', DIR, {'id': 'media', 'map': [{'node': 'pve1', 'path': '/srv/media'}]}),
                               ('put', f'{DIR}/share', {'description': 'x'}),
                               ('delete', f'{DIR}/share', None)):
        kw = {'json': body} if body is not None else {}
        r = getattr(admin, method)(path, **kw)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.data)
    assert not pve.writes()
    # reading stays open there
    assert admin.get(DIR).status_code == 200


# --- directory mappings -------------------------------------------------------------------------

def test_the_mapping_list_has_each_nodes_path_and_the_nodes(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.get(DIR)
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['supported'] is True and d['nodes'] == list(NODES) and d['digest'] == 'a1b2c3'
    assert d['mappings'] == [
        {'id': 'backups', 'description': '', 'nodes': ['pve2'], 'entries': [{'node': 'pve2', 'path': '/srv/backups'}]},
        {'id': 'share', 'description': 'Media', 'nodes': ['pve1', 'pve2'],
         'entries': [{'node': 'pve1', 'path': '/mnt/share'}, {'node': 'pve2', 'path': '/srv/share'}]},
    ]


def test_a_new_mapping_reaches_pve_with_its_map_and_is_audited(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.post(DIR, json={'id': 'media', 'description': ' Photos ',
                              'map': [{'node': 'pve1', 'path': '/srv/media'}, {'node': 'pve3', 'path': '/data/my media'}]})
    assert r.status_code == 200, r.data
    (method, url, body), = pve.writes()
    assert method == 'POST' and url.endswith('/api2/json/cluster/mapping/dir')
    assert body == {'id': 'media', 'description': 'Photos',
                    'map': ['node=pve1,path=/srv/media', 'node=pve3,path=/data/my media']}
    assert pve.mappings['media']['map'] == body['map']
    rows = _audit('mapping.dir_created')
    assert len(rows) == 1 and rows[0]['details'] == f'Directory mapping media: pve1=/srv/media, pve3=/data/my media [{CID}]'


def test_the_map_goes_to_pve_as_one_form_field_per_node(api, admin):
    """requests sends a list as the field repeated, which is how PVE takes an array"""
    import requests
    req = requests.Request('POST', 'https://192.0.2.10:8006/x',
                           data={'id': 'media', 'map': ['node=pve1,path=/a', 'node=pve2,path=/b']}).prepare()
    assert parse_qs(req.body) == {'id': ['media'], 'map': ['node=pve1,path=/a', 'node=pve2,path=/b']}


BAD_BODIES = [
    {'id': 'media', 'map': [{'node': 'pve1', 'path': 'srv/media'}]},
    {'id': 'media', 'map': [{'node': 'pve1', 'path': '/'}]},
    {'id': 'media', 'map': [{'node': 'pve1', 'path': '//'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a,b'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a=b'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a(b)'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a;b'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a\nb'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/media '}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/../etc'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': 5}]},
    {'id': 'media', 'map': [{'node': 'pve9', 'path': '/srv/media'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a'}, {'node': 'pve2', 'path': '/srv/b'}]},
    {'id': 'media', 'map': [{'node': 'pve1,path=/etc', 'path': '/srv/media'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/a', 'mode': 'rw'}]},
    {'id': 'media', 'map': ['node=pve2,path=/srv/a']},
    {'id': 'media', 'map': []},
    {'id': 'media', 'map': {'node': 'pve2', 'path': '/srv/a'}},
    {'id': 'media'},
    {'id': '1media', 'map': [{'node': 'pve2', 'path': '/srv/media'}]},
    {'id': 'm', 'map': [{'node': 'pve2', 'path': '/srv/media'}]},
    {'id': 'me dia', 'map': [{'node': 'pve2', 'path': '/srv/media'}]},
    {'map': [{'node': 'pve2', 'path': '/srv/media'}]},
    {'id': 'media', 'description': 'two\nlines', 'map': [{'node': 'pve2', 'path': '/srv/media'}]},
    {'id': 'media', 'map': [{'node': 'pve2', 'path': '/srv/media'}], 'shared': 1},
    ['media'],
]


@pytest.mark.parametrize('body', BAD_BODIES, ids=[json.dumps(b)[:50] for b in BAD_BODIES])
def test_a_mapping_pve_would_refuse_or_check_on_one_node_only_stops_here(api, admin, body):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.post(DIR, json=body)
    assert r.status_code == 400, r.data
    assert not pve.writes() and 'media' not in pve.mappings
    assert not _audit('mapping.dir_created')


def test_pve_checks_a_path_only_on_its_own_node():
    """Why the paths are checked here: PVE stores a bad path of another node, a node the
    cluster does not have and a path with ( ) in it - the start of the VM fails there later."""
    pve = FakePVE()
    for item in ('node=pve2,path=/srv/a(b', 'node=pve9,path=/srv/media', 'node=pve2,path=/srv/a b ',
                 'node=pve2,path=/srv/../etc'):
        assert pve._post('https://x/cluster/mapping/dir', {'id': 'm' + str(len(pve.mappings) + 10),
                                                           'map': [item]}).status_code == 200, item
    # and refuses what its own node does not have, or a path that is no path
    assert pve._post('https://x/cluster/mapping/dir', {'id': 'mx', 'map': ['node=pve1,path=/nope']}).status_code == 500
    assert pve._post('https://x/cluster/mapping/dir', {'id': 'my', 'map': ['node=pve2,path=srv']}).status_code == 400


def test_pve_refusals_come_back_with_the_reason(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    r = admin.post(DIR, json={'id': 'media', 'map': [{'node': 'pve1', 'path': '/nope'}]})
    assert r.status_code == 400 and 'Path /nope does not exist' in r.get_json()['error']
    r = admin.post(DIR, json={'id': 'share', 'map': [{'node': 'pve1', 'path': '/mnt/share'}]})
    assert r.status_code == 409 and 'already defined' in r.get_json()['error']
    assert not _audit('mapping.dir_created')


def test_a_change_replaces_the_map_and_an_empty_description_goes(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    digest = admin.get(DIR).get_json()['digest']
    r = admin.put(f'{DIR}/share', json={'map': [{'node': 'pve1', 'path': '/srv/media'}], 'description': '',
                                        'digest': digest})
    assert r.status_code == 200, r.data
    (method, url, body), = pve.writes()
    assert method == 'PUT' and url.endswith('/cluster/mapping/dir/share')
    assert body == {'map': ['node=pve1,path=/srv/media'], 'delete': 'description', 'digest': digest}
    assert pve.mappings['share'] == {'description': '', 'map': ['node=pve1,path=/srv/media']}
    rows = _audit('mapping.dir_updated')
    assert rows[0]['details'] == f"Directory mapping share: 'pve1=/mnt/share, pve2=/srv/share' -> 'pve1=/srv/media' [{CID}]"
    # the description alone
    assert admin.put(f'{DIR}/share', json={'description': 'Media 2'}).status_code == 200
    assert pve.writes()[-1][2] == {'description': 'Media 2'}
    # a change made elsewhere in between is not overwritten
    r = admin.put(f'{DIR}/share', json={'description': 'old view', 'digest': digest})
    assert r.status_code == 409 and pve.mappings['share']['description'] == 'Media 2'


def test_a_change_is_checked_like_a_new_one(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    for body in ({'map': [{'node': 'pve9', 'path': '/srv/a'}]}, {'map': [{'node': 'pve2', 'path': '/srv/a,b'}]},
                 {'map': []}, {}, {'digest': 'a1b2c3'}, {'id': 'other', 'description': 'x'}, {'digest': 'xyz!'}):
        assert admin.put(f'{DIR}/share', json=body).status_code == 400, body
    assert admin.put(f'{DIR}/nosuch', json={'description': 'x'}).status_code == 404
    assert admin.put(f'{DIR}/1bad', json={'description': 'x'}).status_code == 400
    assert not pve.writes()


def test_removing_a_mapping_is_audited_and_an_unknown_one_is_not_found(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    assert admin.delete(f'{DIR}/nosuch').status_code == 404
    assert not pve.writes()
    r = admin.delete(f'{DIR}/share')
    assert r.status_code == 200, r.data
    assert 'share' not in pve.mappings and pve.writes()[-1][0] == 'DELETE'
    rows = _audit('mapping.dir_deleted')
    assert rows[0]['details'] == f'Directory mapping share removed (was pve1=/mnt/share, pve2=/srv/share) [{CID}]'


def test_an_older_pve_has_no_directory_mappings(api, admin):
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve, version=(8, 3))
    d = admin.get(DIR).get_json()
    assert d['supported'] is False and d['mappings'] == [] and d['min_version'] == '8.4'
    r = admin.post(DIR, json={'id': 'media', 'map': [{'node': 'pve1', 'path': '/srv/media'}]})
    assert r.status_code == 400 and '8.4' in r.get_json()['error']
    d = admin.get(f'{VM}/passthrough/mappings?kind=dir').get_json()
    assert d['supported'] is False and d['mappings'] == []
    assert not [c for c in pve.calls if '/mapping/dir' in c[1]]


def test_another_hypervisor_has_no_directory_mappings(api, admin):
    m = api.make_fake_manager(CID, cluster_type='xcpng')
    api.set_manager(CID, m)
    assert admin.get(DIR).status_code == 400
    assert admin.post(DIR, json={'id': 'media', 'map': [{'node': 'pve1', 'path': '/srv/media'}]}).status_code == 400


def test_the_mapping_routes_by_identity(api, seed):
    who = _identities(api, seed)
    pve = FakePVE(mappings=SHARE)
    _manager(api, pve)
    # read: cluster.view and the whole cluster; write: cluster.config and the whole cluster
    expect = {'admin': (200, 200), 'viewer': (200, 403), 'confined_admin': (403, 403),
              'other_tenant': (403, 403), 'pool_confined': (403, 403), 'owning_tenant': (200, 403)}
    for name, (read, write) in expect.items():
        assert who[name].get(DIR).status_code == read, name
        before = len(pve.writes())
        for i, (method, path, body) in enumerate((
                ('post', DIR, {'id': f'm{name.replace("_", "")}', 'map': [{'node': 'pve1', 'path': '/srv/media'}]}),
                ('put', f'{DIR}/backups', {'description': name}),
                ('delete', f'{DIR}/share', None))):
            if write == 200 and method == 'delete':
                continue
            kw = {'json': body} if body is not None else {}
            assert getattr(who[name], method)(path, **kw).status_code == write, (name, method)
        if write != 200:
            assert len(pve.writes()) == before, name
