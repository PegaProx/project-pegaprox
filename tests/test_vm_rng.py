"""The VirtIO RNG of a VM (rng0) through the config route.

rng0 is a property string PVE parses as pve-qm-rng (qemu-server PVE/QemuServer/RNG.pm):

    [source=]</dev/urandom|/dev/random|/dev/hwrng> [,max_bytes=<integer>] [,period=<integer>]

PVE checks the source against its three files but takes any integer for the two numbers.
QEMU does not: a negative max-bytes or a period of 0 stops the VM from starting (max_bytes=0
switches the limit off, then the period is not passed on). The route holds the value to what
both take and sends it in one spelling.

The fake PVE below parses rng0 the way PVE::JSONSchema does and answers 400 for what PVE
refuses, so a value it stores is one PVE would have stored too.

MK Oct 2026
"""
import json
import logging
import re
import time
import types

import pytest

from pegaprox.core.manager import PegaProxManager

from test_ha_api import ha_env, _standby_of_active, _audit  # noqa: F401  (ha_env is a fixture)

CID = 'cluster_1'
CFG = f'/api/clusters/{CID}/vms/pve1/qemu/100/config'
SOURCES = ('/dev/urandom', '/dev/random', '/dev/hwrng')


def _pve_parses(value):
    """pve-qm-rng as PVE::JSONSchema::parse_property_string + check_object read it."""
    res = {}
    for part in value.split(','):
        if not part.strip():
            continue
        m = re.fullmatch(r'([^=]+)=(.+)', part, re.S)
        if m:
            key, val = m.groups()
            if key in res:
                raise ValueError(f'duplicate key in comma-separated list property: {key}')
            if key not in ('source', 'max_bytes', 'period'):
                raise ValueError(f'invalid key in comma-separated list property: {key}')
            res[key] = val
        elif '=' not in part:
            if 'source' in res:
                raise ValueError('duplicate key in comma-separated list property: source')
            res['source'] = part
        else:
            raise ValueError('missing key in comma-separated list property')
    if 'source' not in res:
        raise ValueError('source: property is missing and it is not optional')
    if res['source'] not in SOURCES:
        raise ValueError(f"source: value '{res['source']}' does not have a value in the enumeration")
    for key in ('max_bytes', 'period'):
        if key in res and not re.fullmatch(r'[+-]?\d+', res[key], re.A):
            raise ValueError(f'{key}: type check (\'integer\') failed')
    return res


def _qemu_starts(parsed):
    """What print_rng_device_commandline hands QEMU, and whether QEMU takes it."""
    max_bytes = int(parsed.get('max_bytes', 1024))
    period = int(parsed.get('period', 1000))
    if not max_bytes:
        return True
    return 0 < max_bytes <= 2 ** 63 - 1 and 0 < period <= 2 ** 32 - 1


class _Resp:
    def __init__(self, status, message=None):
        self.status_code = status
        self.text = json.dumps({'data': None, 'message': message} if message else {'data': None})

    def json(self):
        return {'data': None}


def _manager(api, raw=None, cluster_type='proxmox', cid=CID):
    """The real PegaProxManager.update_vm_config in front of a fake PVE config."""
    m = api.make_fake_manager(cid, cluster_type=cluster_type)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    m.config = types.SimpleNamespace(name=cid)
    m.logger = logging.getLogger('test_vm_rng')
    m.pve_raw = dict(raw or {})
    m.puts = []

    def _api_put(url, data=None, **kw):
        body = dict(data or {})
        m.puts.append((url, dict(body)))
        if 'rng0' in body:
            try:
                _pve_parses(body['rng0'])
            except ValueError as e:
                return _Resp(400, f'Parameter verification failed. rng0: {e}')
        for key in str(body.pop('delete', '') or '').split(','):
            m.pve_raw.pop(key.strip(), None)
        m.pve_raw.update(body)
        return _Resp(200)
    m._api_put = _api_put
    m.update_vm_config = lambda node, vmid, vm_type, updates: PegaProxManager.update_vm_config(
        m, node, vmid, vm_type, updates)
    m.get_vm_config = lambda node, vmid, vm_type: {'success': True, 'config': {'raw': dict(m.pve_raw)}}
    api.set_manager(cid, m)
    return m


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- what goes to PVE ---------------------------------------------------------------------

@pytest.mark.parametrize('sent,stored', [
    ('/dev/urandom', 'source=/dev/urandom'),
    ('source=/dev/random,max_bytes=2048,period=500', 'source=/dev/random,max_bytes=2048,period=500'),
    # PVE takes the bare value anywhere and skips empty parts
    ('period=2000,/dev/hwrng', 'source=/dev/hwrng,period=2000'),
    ('/dev/urandom,,max_bytes=010', 'source=/dev/urandom,max_bytes=10'),
    # 0 switches the limit off
    ('/dev/urandom,max_bytes=0', 'source=/dev/urandom,max_bytes=0'),
    (f'/dev/urandom,max_bytes={2 ** 63 - 1},period={2 ** 32 - 1}',
     f'source=/dev/urandom,max_bytes={2 ** 63 - 1},period={2 ** 32 - 1}'),
])
def test_a_valid_rng_reaches_pve_in_one_spelling(api, admin, sent, stored):
    m = _manager(api)
    r = admin.put(CFG, json={'rng0': sent})
    assert r.status_code == 200, r.data
    (url, body), = m.puts
    assert url.endswith('/nodes/pve1/qemu/100/config')
    assert body == {'rng0': stored}
    assert m.pve_raw['rng0'] == stored
    assert _qemu_starts(_pve_parses(stored))
    rows = _audit('vm.config_changed')
    assert len(rows) == 1 and f'rng0={stored}' in rows[0]['details']


REFUSED = [
    # PVE stores these, and the VM then does not start
    '/dev/urandom,max_bytes=-1',
    '/dev/urandom,period=0',
    '/dev/urandom,max_bytes=1024,period=-5',
    f'/dev/urandom,period={2 ** 32}',
    f'/dev/urandom,max_bytes={2 ** 63}',
    # PVE refuses these itself; they stop here with the reason instead of a 500
    '/dev/sda',
    'source=/etc/shadow',
    'max_bytes=1024',
    '/dev/urandom,/dev/random',
    'source=/dev/urandom,source=/dev/random',
    '/dev/urandom,max_bytes=1k',
    '/dev/urandom,max_bytes= 5',
    '/dev/urandom,max_bytes=',
    '/dev/urandom,foo=1',
    ' /dev/urandom',
    '',
    # digits Python's int() reads and PVE does not
    '/dev/urandom,max_bytes=\uff11\uff12',
    123, None, ['/dev/urandom'], {'source': '/dev/urandom'},
]


@pytest.mark.parametrize('sent', REFUSED, ids=[repr(x)[:40] for x in REFUSED])
def test_an_invalid_rng_is_refused_before_pve(api, admin, sent):
    m = _manager(api)
    r = admin.put(CFG, json={'rng0': sent})
    assert r.status_code == 400, r.data
    assert r.get_json()['error'].startswith('Invalid VirtIO RNG: ')
    assert not m.puts and 'rng0' not in m.pve_raw
    assert not _audit('vm.config_changed')


def test_every_refused_value_is_one_pve_or_qemu_would_fail_on():
    """The other way round: nothing on the refused list would have worked."""
    for sent in REFUSED:
        if not isinstance(sent, str):
            continue
        try:
            parsed = _pve_parses(sent)
        except ValueError:
            continue
        assert not _qemu_starts(parsed), sent


def test_the_error_names_what_is_wrong(api, admin):
    _manager(api)
    msg = lambda v: admin.put(CFG, json={'rng0': v}).get_json()['error']
    assert '/dev/urandom, /dev/random, /dev/hwrng' in msg('/dev/sda')
    assert 'period must be a whole number from 1 to 4294967295' in msg('/dev/urandom,period=0')
    assert 'max_bytes must be a whole number from 0 to' in msg('/dev/urandom,max_bytes=-1')
    assert "no option 'foo'" in msg('/dev/urandom,foo=1')
    assert 'source twice' in msg('/dev/urandom,/dev/random')


def test_only_rng0_and_only_on_a_vm(api, admin):
    m = _manager(api)
    r = admin.put(CFG, json={'rng1': '/dev/urandom'})
    assert r.status_code == 400 and 'rng0' in r.get_json()['error']
    r = admin.put(f'/api/clusters/{CID}/vms/pve1/lxc/101/config', json={'rng0': '/dev/urandom'})
    assert r.status_code == 400 and 'container' in r.get_json()['error']
    # one bad key stops the whole change
    r = admin.put(CFG, json={'cores': 4, 'rng0': '/dev/urandom,period=0'})
    assert r.status_code == 400
    assert not m.puts


def test_removing_the_rng_and_other_keys_pass_as_before(api, admin):
    m = _manager(api, raw={'rng0': '/dev/urandom,max_bytes=1024', 'cores': 2})
    assert admin.put(CFG, json={'delete': 'rng0'}).status_code == 200
    assert m.puts[-1][1] == {'delete': 'rng0'} and 'rng0' not in m.pve_raw
    assert admin.put(CFG, json={'cores': 4, 'name': 'web01'}).status_code == 200
    assert m.puts[-1][1] == {'cores': 4, 'name': 'web01'}


def test_a_body_that_is_no_object_is_refused(api, admin):
    m = _manager(api)
    r = admin.put(CFG, json=['rng0', '/dev/urandom'])
    assert r.status_code == 400
    assert not m.puts


def test_an_xcpng_pool_is_not_checked_for_a_proxmox_option(api, admin):
    m = api.make_fake_manager(CID, cluster_type='xcpng')
    m.update_vm_config.return_value = {'success': True, 'message': 'ok'}
    m.config = types.SimpleNamespace(name=CID)
    api.set_manager(CID, m)
    assert admin.put(CFG, json={'name_label': 'x'}).status_code == 200
    m.update_vm_config.assert_called_once()


# --- who reaches it -----------------------------------------------------------------------

def _pool_user(seed, name):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=[CID])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=['vm.config', 'vm.view'])
    seed.pool(CID, 'pool_1', name, ['pool.view', 'vm.view', 'vm.config'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'101:qemu': 'pool_1'}, 'timestamp': time.time(),
                                            'refreshing': False}
    return u


def test_the_rng_by_identity(api, seed):
    # every tenant before the first request: rbac loads the tenant table once
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    who = {
        'admin': api.as_user(seed.user('root', role='admin')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}})),
        'other_tenant': api.as_user(seed.user('ac', role='user', tenant_id='acme',
                                              permissions=['vm.config', 'vm.view'])),
        'pool_confined': api.as_user(_pool_user(seed, 'mallory')),
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }
    m = _manager(api)
    expect = {'admin': 200, 'viewer': 403, 'confined_admin': 403, 'other_tenant': 403,
              'pool_confined': 403, 'owning_tenant': 200}
    for name, status in expect.items():
        before = len(m.puts)
        r = who[name].put(CFG, json={'rng0': '/dev/urandom'})
        assert r.status_code == status, (name, r.data)
        if status != 200:
            assert len(m.puts) == before, name
        # a refusal comes before the value is looked at
        r = who[name].put(CFG, json={'rng0': '/dev/sda'})
        assert r.status_code == (400 if status == 200 else status), name
    # the pool user changes the guest of their pool
    r = who['pool_confined'].put(f'/api/clusters/{CID}/vms/pve1/qemu/101/config', json={'rng0': '/dev/urandom'})
    assert r.status_code == 200, r.data


def test_a_standby_sets_no_rng(ha_env, seed):
    api = ha_env.api
    admin = api.as_user(seed.user('root', role='admin'))
    m = _manager(api)
    _standby_of_active(ha_env)
    for body in ({'rng0': '/dev/urandom'}, {'delete': 'rng0'}):
        r = admin.put(CFG, json=body)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert not m.puts
