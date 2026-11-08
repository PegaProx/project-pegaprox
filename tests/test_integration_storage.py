# Full-stack integration suite for the `storage` blueprint (pegaprox/api/storage.py).
#
# Drives the REAL Flask app + REAL storage blueprint, faking only the cluster
# manager. Every case traverses the actual decorator chain:
#   require_auth(perms=...) -> check_cluster_access (403) -> get_connected_manager /
#   "cluster not in cluster_managers" (404) -> manager call.
#
# Permission facts that drive these tests (pegaprox/models/permissions.py):
#   storage.view      -> admin, user, viewer   (everyone)
#   storage.download  -> admin, user           (NOT viewer)
#   storage.config    -> admin ONLY
#   storage.delete    -> admin ONLY
# require_auth checks perms BEFORE check_cluster_access, so a role that lacks the
# perm gets 403 (MISSING_PERMISSION) even in the all-cluster default tenant, and
# the manager is never touched.
#
# Routes covered:
#   GET    /api/clusters/<c>/datacenter/storage/<sid>                -> get_storage_config
#   PUT    /api/clusters/<c>/datacenter/storage/<sid>                -> update_storage
#   DELETE /api/clusters/<c>/datacenter/storage/<sid>                -> delete_storage
#   POST   /api/clusters/<c>/datacenter/storage                      -> create_storage
#   GET    /api/clusters/<c>/nodes/<n>/storage/<s>/content           -> get_node_storage_content
#   POST   /api/clusters/<c>/nodes/<n>/storage/<s>/download-url      -> download_from_url (SSRF)

import pegaprox.globals as _ppg


# ---------------------------------------------------------------------------
# route helpers
# ---------------------------------------------------------------------------

STORAGE_ITEM = '/api/clusters/cluster_1/datacenter/storage/local-lvm'
STORAGE_COLL = '/api/clusters/cluster_1/datacenter/storage'
CONTENT_ROUTE = '/api/clusters/cluster_1/nodes/pve1/storage/local/content'
DOWNLOAD_ROUTE = '/api/clusters/cluster_1/nodes/pve1/storage/local/download-url'


def _fake_pve_response(status_code=200, json_body=None, text=''):
    """A stand-in for a `requests` Response object as the routes consume it:
    they read .status_code, .json(), and sometimes .text."""
    from unittest.mock import MagicMock
    resp = MagicMock(name='PveResponse')
    resp.status_code = status_code
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = text
    return resp


def _mgr_with_session(api, verb, response):
    """A connected fake manager whose `_create_session().<verb>(...)` returns
    `response`. The datacenter-storage + download routes all reach PVE via
    manager._create_session().<verb>(url, ...). host/api_port/config.name are
    MagicMock attrs (fine — they're only string-formatted into URLs / audit)."""
    mgr = api.make_fake_manager(cluster_id='cluster_1')
    mgr.host = 'pve.example'
    mgr.api_port = 8006
    mgr.config.name = 'cluster_1'
    getattr(mgr._create_session.return_value, verb).return_value = response
    return mgr


def _get_mgr():
    return _ppg.cluster_managers['cluster_1']


# ===========================================================================
# get_storage_config  (GET, storage.view)  -- READ
# ===========================================================================

def test_get_storage_config_anon_401(api, seed):
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': {'type': 'lvmthin'}})))
    resp = api.anon().get(STORAGE_ITEM)
    assert resp.status_code == 401


def test_get_storage_config_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get',
        _fake_pve_response(200, {'data': {'storage': 'local-lvm',
                                          'type': 'lvmthin', 'content': 'images'}})))
    resp = api.as_user(admin).get(STORAGE_ITEM)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['type'] == 'lvmthin'
    assert body['storage'] == 'local-lvm'


def test_get_storage_config_viewer_200(api, seed):
    # viewer holds storage.view -> read allowed even though it can't write
    viewer = seed.user('look', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': {'type': 'dir'}})))
    resp = api.as_user(viewer).get(STORAGE_ITEM)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['type'] == 'dir'


def test_get_storage_config_user_allowed_200(api, seed):
    # additive-access invariant: a plain 'user' in the all-cluster default tenant
    # holds storage.view and reaches the read route WITHOUT any ACL/pool grant.
    # (Complements the cross-tenant deny — proves the deny is about tenant, not role.)
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': {'storage': 'local-lvm',
                                                      'type': 'lvmthin'}})))
    resp = api.as_user(user).get(STORAGE_ITEM)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['type'] == 'lvmthin'
    assert body['storage'] == 'local-lvm'
    _get_mgr()._create_session.return_value.get.assert_called_once()


def test_get_storage_config_cross_tenant_denied_403(api, seed):
    # bob's tenant owns cluster_2, not cluster_1 -> check_cluster_access 403.
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': {'type': 'dir'}})))
    resp = api.as_user(bob).get(STORAGE_ITEM)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # deny fires before the manager is consulted
    _get_mgr()._create_session.assert_not_called()


# ===========================================================================
# create_storage  (POST, storage.config = admin only)  -- WRITE
# ===========================================================================

def test_create_storage_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(admin).post(STORAGE_COLL, json={
        'type': 'dir', 'storage': 'backups', 'path': '/mnt/backups'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    # the route posted to PVE exactly once
    _get_mgr()._create_session.return_value.post.assert_called_once()


def test_create_storage_missing_type_400(api, seed):
    # admin passes the perm + cluster gates; the route's own validation rejects it.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(admin).post(STORAGE_COLL, json={'storage': 'x'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'type' in resp.get_json()['error'].lower()
    # validation happens before any PVE call
    _get_mgr()._create_session.return_value.post.assert_not_called()


def test_create_storage_viewer_denied_403(api, seed):
    # viewer lacks storage.config -> require_auth 403 before check_cluster_access.
    viewer = seed.user('look', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(viewer).post(STORAGE_COLL, json={
        'type': 'dir', 'storage': 'x', 'path': '/tmp'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'MISSING_PERMISSION'
    _get_mgr()._create_session.assert_not_called()


def test_create_storage_user_denied_403(api, seed):
    # a plain 'user' also lacks storage.config (admin-only perm).
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(user).post(STORAGE_COLL, json={
        'type': 'dir', 'storage': 'x', 'path': '/tmp'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _get_mgr()._create_session.assert_not_called()


# ===========================================================================
# update_storage  (PUT, storage.config = admin only)  -- WRITE
# ===========================================================================

def test_update_storage_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'put', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(admin).put(STORAGE_ITEM, json={'content': 'images,iso'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True
    _get_mgr()._create_session.return_value.put.assert_called_once()


def test_update_storage_viewer_denied_403(api, seed):
    viewer = seed.user('look', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'put', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(viewer).put(STORAGE_ITEM, json={'content': 'images'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'MISSING_PERMISSION'
    _get_mgr()._create_session.assert_not_called()


# ===========================================================================
# delete_storage  (DELETE, storage.delete = admin only)  -- WRITE
# ===========================================================================

def test_delete_storage_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'delete', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(admin).delete(STORAGE_ITEM)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True
    _get_mgr()._create_session.return_value.delete.assert_called_once()


def test_delete_storage_user_denied_403(api, seed):
    # 'user' lacks storage.delete (admin-only) -> 403 before manager.
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'delete', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(user).delete(STORAGE_ITEM)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _get_mgr()._create_session.assert_not_called()


# ===========================================================================
# get_node_storage_content  (GET, storage.view)  -- datastore content READ
# ===========================================================================

def test_datastore_content_admin_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get',
        _fake_pve_response(200, {'data': [
            {'volid': 'local:iso/debian.iso', 'content': 'iso', 'size': 700 * 1024**2},
            {'volid': 'local:vztmpl/alpine.tar', 'content': 'vztmpl', 'size': 5 * 1024**2},
        ]})))
    resp = api.as_user(admin).get(CONTENT_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list) and len(body) == 2
    assert body[0]['volid'] == 'local:iso/debian.iso'


def test_datastore_content_approx_size_backfilled(api, seed):
    # PVE 9.2: size may be absent, approximate-size present -> route surfaces
    # it as size + size_is_approx=True.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get',
        _fake_pve_response(200, {'data': [
            {'volid': 'shared:vm-100-disk-0', 'size': 0,
             'approximate-size': 12 * 1024**3},
        ]})))
    resp = api.as_user(admin).get(CONTENT_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    entry = resp.get_json()[0]
    assert entry['size'] == 12 * 1024**3
    assert entry['size_is_approx'] is True


def test_datastore_content_viewer_200(api, seed):
    viewer = seed.user('look', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': []})))
    resp = api.as_user(viewer).get(CONTENT_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == []


def test_datastore_content_cross_tenant_denied_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'get', _fake_pve_response(200, {'data': []})))
    resp = api.as_user(bob).get(CONTENT_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _get_mgr()._create_session.assert_not_called()


# ===========================================================================
# download_from_url  (POST, storage.download)  -- SSRF-gated WRITE
#   storage.download is held by admin + user, NOT viewer.
#   The route sanitises the URL with allowed_schemes=('https','http') and
#   require_resolution=True (default), so private/loopback/metadata literals
#   are rejected 400 WITHOUT the manager being called; a public IP literal
#   (no DNS needed) passes and reaches the manager.
# ===========================================================================

def test_download_url_metadata_rejected_400(api, seed):
    # cloud-metadata endpoint -> SSRF guard 400.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': 'UPID:...'})))
    resp = api.as_user(admin).post(DOWNLOAD_ROUTE, json={
        'url': 'http://169.254.169.254/latest/meta-data/',
        'filename': 'x.iso'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'SSRF' in resp.get_json()['error']
    # SSRF reject happens before the PVE download-url call
    _get_mgr()._create_session.return_value.post.assert_not_called()


def test_download_url_loopback_rejected_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': 'UPID:...'})))
    resp = api.as_user(admin).post(DOWNLOAD_ROUTE, json={
        'url': 'https://127.0.0.1/secret.iso', 'filename': 'x.iso'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'SSRF' in resp.get_json()['error']
    _get_mgr()._create_session.return_value.post.assert_not_called()


def test_download_url_private_rejected_400(api, seed):
    # RFC1918 private IP literal -> rejected.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': 'UPID:...'})))
    resp = api.as_user(admin).post(DOWNLOAD_ROUTE, json={
        'url': 'https://10.10.0.5/internal.iso', 'filename': 'x.iso'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'SSRF' in resp.get_json()['error']
    _get_mgr()._create_session.return_value.post.assert_not_called()


def test_download_url_public_reaches_manager_200(api, seed):
    # A public IP literal passes the SSRF guard with no DNS lookup (deterministic
    # offline) and reaches the PVE download-url delegation.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': 'UPID:pve1:...:download:'})))
    resp = api.as_user(admin).post(DOWNLOAD_ROUTE, json={
        'url': 'https://8.8.8.8/pub/debian-12.iso', 'filename': 'debian-12.iso',
        'content': 'iso'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['upid'] == 'UPID:pve1:...:download:'
    _get_mgr()._create_session.return_value.post.assert_called_once()


def test_download_url_missing_url_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(admin).post(DOWNLOAD_ROUTE, json={'filename': 'x.iso'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'URL is required' in resp.get_json()['error']
    _get_mgr()._create_session.return_value.post.assert_not_called()


def test_download_url_viewer_denied_403(api, seed):
    # viewer lacks storage.download -> 403 before any URL handling / manager call.
    viewer = seed.user('look', role='viewer', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(viewer).post(DOWNLOAD_ROUTE, json={
        'url': 'https://8.8.8.8/x.iso', 'filename': 'x.iso'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'MISSING_PERMISSION'
    _get_mgr()._create_session.assert_not_called()


def test_download_url_cross_tenant_denied_403(api, seed):
    # user with storage.download but wrong tenant -> cluster-level 403.
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': None})))
    resp = api.as_user(bob).post(DOWNLOAD_ROUTE, json={
        'url': 'https://8.8.8.8/x.iso', 'filename': 'x.iso'})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _get_mgr()._create_session.assert_not_called()


def test_download_url_user_allowed_200(api, seed):
    # additive-access + role invariant on a WRITE route: a plain same-tenant 'user'
    # HOLDS storage.download (viewer does not), so the very case denied for viewer
    # above must be ALLOWED here and reach the PVE download-url delegation.
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', _mgr_with_session(
        api, 'post', _fake_pve_response(200, {'data': 'UPID:pve1:...:download:'})))
    resp = api.as_user(user).post(DOWNLOAD_ROUTE, json={
        'url': 'https://8.8.8.8/pub/debian-12.iso', 'filename': 'debian-12.iso',
        'content': 'iso'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['upid'] == 'UPID:pve1:...:download:'
    _get_mgr()._create_session.return_value.post.assert_called_once()
