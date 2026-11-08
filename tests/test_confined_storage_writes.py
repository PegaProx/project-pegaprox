"""ISO, template and import content belongs to the whole cluster, not to a guest (#1109).

The upload, the two download-from-URL routes and the template download only asked whether
the caller reaches the cluster, and that question lets in whoever holds one pool grant or
one VM-ACL entry there. Such a caller with ROLE_USER's storage.upload/storage.download could
write to any storage of the cluster, and since a PVE upload overwrites a file of the same
name, swap an ISO other tenants boot from. The ISO sync already refused them.
"""
import io
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.utils.rbac as rbac

CID = 'cluster_1'
PERMS = ['storage.upload', 'storage.download', 'storage.view', 'cluster.view']


def _who(api, seed):
    seed.tenant('tenant_x', [CID])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    pool = seed.user('pooluser', role='user', tenant_id='tenant_x', permissions=PERMS)
    seed.pool(CID, 'pool_1', 'pooluser', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                            'refreshing': False}
    acl = seed.user('acluser', role='user', tenant_id='acme', permissions=PERMS)
    seed.vm_acl(CID, 100, ['acluser'])
    return {
        'pool': api.as_user(pool),
        'acl': api.as_user(acl),
        'owner': api.as_user(seed.user('op', role='user', tenant_id='ops', permissions=PERMS)),
        'admin': api.as_user(seed.user('root', role='admin')),
    }


def _stopped(status=500):
    r = MagicMock()
    r.status_code, r.text = status, 'stopped here'
    r.json.return_value = {}
    return r


def _manager(api, cluster_type='proxmox'):
    m = api.make_fake_manager(CID, cluster_type=cluster_type)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    m._create_session.return_value.post.return_value = _stopped()
    m._api_post.return_value = _stopped()
    m.upload_to_storage.return_value = {'success': False, 'error': 'stopped here'}
    return api.set_manager(CID, m)


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    monkeypatch.setattr('pegaprox.utils.url_security.resolve_and_pin_url', lambda url, **kw: url)


def _writes():
    return [
        ('vms download-url', f'/api/clusters/{CID}/datastores/local/download-url',
         {'json': {'url': 'https://example.com/x.iso', 'filename': 'x.iso', 'node': 'pve1'}}),
        ('storage download-url', f'/api/clusters/{CID}/nodes/pve1/storage/local/download-url',
         {'json': {'url': 'https://example.com/x.iso', 'filename': 'x.iso', 'content': 'iso'}}),
        ('template download', f'/api/clusters/{CID}/templates/download',
         {'json': {'storage': 'local', 'template': 'debian-12-standard_12.2-1_amd64.tar.zst', 'node': 'pve1'}}),
    ]


def _pve_was_asked(m):
    return m._create_session.return_value.post.called or m._api_post.called or m.upload_to_storage.called


@pytest.mark.parametrize('caller', ['pool', 'acl'])
def test_a_confined_caller_writes_no_shared_content(api, seed, caller):
    who = _who(api, seed)
    m = _manager(api)
    for name, path, kw in _writes():
        r = who[caller].post(path, **kw)
        assert r.status_code == 403, (name, r.data)
        assert 'whole cluster' in r.get_json()['error'], name
    r = who[caller].post(f'/api/clusters/{CID}/datastores/local/upload',
                         data={'content': 'iso', 'node': 'pve1',
                               'file': (io.BytesIO(b'not really an iso'), 'ubuntu.iso')},
                         content_type='multipart/form-data')
    assert r.status_code == 403, r.data
    assert not _pve_was_asked(m)


def test_a_confined_caller_uploads_nothing_to_an_xcpng_pool_either(api, seed):
    who = _who(api, seed)
    m = _manager(api, cluster_type='xcpng')
    r = who['pool'].post(f'/api/clusters/{CID}/datastores/iso-sr/upload',
                         data={'content': 'iso', 'file': (io.BytesIO(b'x'), 'x.iso')},
                         content_type='multipart/form-data')
    assert r.status_code == 403, r.data
    assert not m.upload_to_storage.called


@pytest.mark.parametrize('caller', ['owner', 'admin'])
def test_the_whole_cluster_still_writes_shared_content(api, seed, caller):
    who = _who(api, seed)
    m = _manager(api)
    for name, path, kw in _writes():
        before = m._create_session.return_value.post.call_count
        r = who[caller].post(path, **kw)
        # the fake PVE answers 500: the request got past every gate to the cluster
        assert r.status_code == 500, (name, r.data)
        assert m._create_session.return_value.post.call_count == before + 1, name
    # the upload checks the file before it reaches PVE: no file is a 400, not a 403
    r = who[caller].post(f'/api/clusters/{CID}/datastores/local/upload',
                         data={'content': 'iso', 'node': 'pve1'}, content_type='multipart/form-data')
    assert r.status_code == 400 and 'No file' in r.get_json()['error'], r.data
    m2 = _manager(api, cluster_type='xcpng')
    r = who[caller].post(f'/api/clusters/{CID}/datastores/iso-sr/upload',
                         data={'content': 'iso', 'file': (io.BytesIO(b'x'), 'x.iso')},
                         content_type='multipart/form-data')
    assert r.status_code == 500 and m2.upload_to_storage.called, r.data


def _token(owner, role):
    from pegaprox.utils.auth import create_api_token
    res = create_api_token(owner, f'ci-{owner}-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


def test_a_token_or_another_tenant_writes_no_shared_content(api, seed):
    """A confined owner's token is confined too, and another tenant's user without a grant
    here does not reach the cluster at all."""
    _who(api, seed)
    stranger = api.as_user(seed.user('stranger', role='user', tenant_id='acme', permissions=PERMS))
    m = _manager(api)
    for hdr in (_token('pooluser', 'user'), _token('acluser', 'user')):
        for name, path, kw in _writes():
            r = api.anon().post(path, headers=hdr, **kw)
            assert r.status_code == 403 and 'whole cluster' in r.get_json()['error'], (name, r.data)
    for name, path, kw in _writes():
        r = stranger.post(path, **kw)
        assert r.status_code == 403 and 'Access denied' in r.get_json()['error'], (name, r.data)
    assert not _pve_was_asked(m)
    # the admin's own token still gets through to the cluster
    name, path, kw = _writes()[0]
    assert api.anon().post(path, headers=_token('root', 'admin'), **kw).status_code == 500


def test_a_confined_caller_still_reads_the_shared_content(api, seed):
    """Reading ISOs and templates stays theirs: they boot their guests from them."""
    who = _who(api, seed)
    m = _manager(api)
    # MK Nov 2026 (#1218) - of a node their guest runs on
    m.get_vm_resources.return_value = [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}]
    listing = MagicMock(status_code=200)
    listing.json.return_value = {'data': [{'volid': 'local:iso/debian.iso', 'content': 'iso', 'size': 1}]}
    m._create_session.return_value.get.return_value = listing
    r = who['pool'].get(f'/api/clusters/{CID}/nodes/pve1/storage/local/content?content=iso')
    assert r.status_code == 200, r.data
    assert [x['volid'] for x in r.get_json()] == ['local:iso/debian.iso']
