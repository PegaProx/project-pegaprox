"""The portal's container target must be a cluster the tenant's quota actually counts.

_create_ct enforces a tenant quota, and #556's later passes made that quota fail closed
and serialised it per tenant. But the two halves were measuring different worlds:

  check_tenant_quota(tenant_id, ...) sums usage across the clusters the TENANT holds,
  mgr.create_container(...)          runs on cc['cluster_id'], which the HOSTER configures.

Nothing required those to be the same cluster. Point ct_create at a cluster outside the
customer's tenant and the quota stops counting anything this route creates — on the one
endpoint a customer can call in a loop, which is exactly where a quota has to hold. The
target is admin-configured, so this is a misconfiguration rather than an attack, but it
turns an enforced quota into no quota with nothing in the logs to say so.

The gate uses the same resolver the quota uses, so they cannot disagree again, and a
default-tenant account (get_user_clusters answers None, "all clusters") is untouched.

Aikido ai_pentest 700489393. MK
"""
import contextlib

import pytest

import plugins.client_portal as portal


CT_FORM = {'template': 'debian-12.tar.zst', 'cores': 1, 'memory': 512,
           'disk_gb': 8, 'hostname': 'web01', 'password': 'hunter2hunter2'}


def _cfg(target_cluster):
    return {
        'allow_ct_create': True,
        'ct_create': {
            'cluster_id': target_cluster, 'node': 'pve1',
            'templates': ['debian-12.tar.zst'],
            'max_cores': 4, 'max_memory_mb': 4096, 'max_disk_gb': 32,
            'storage': 'local-lvm', 'bridge': 'vmbr0',
        },
    }


@contextlib.contextmanager
def _as(api, username, body):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = {'user': username, 'role': 'user'}
        yield


@pytest.fixture
def estate(api, seed, monkeypatch):
    for cid in ('cluster_a', 'cluster_b'):
        seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                           VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (cid, cid))
    # the customer's tenant holds cluster_a only
    seed.tenant('t_cust', ['cluster_a'])
    seed.user('cust', role='user', tenant_id='t_cust')

    made = []
    for cid in ('cluster_a', 'cluster_b'):
        m = api.make_fake_manager(cid)
        m.is_connected = True
        m.create_container.return_value = {'success': True, 'vmid': 200}
        api.set_manager(cid, m)
        made.append(m)

    import pegaprox.utils.rbac as rbac
    monkeypatch.setattr(rbac, 'tenants_db', {}, raising=False)  # force a fresh load
    return dict(zip(('cluster_a', 'cluster_b'), made))


def test_a_target_outside_the_tenant_is_refused(api, estate, monkeypatch):
    monkeypatch.setattr(portal, '_load_config', lambda: _cfg('cluster_b'))
    with _as(api, 'cust', CT_FORM):
        res = portal._create_ct()

    assert isinstance(res, tuple) and res[1] == 403, res
    estate['cluster_b'].create_container.assert_not_called()


def test_the_container_is_not_created_anywhere_when_refused(api, estate, monkeypatch):
    monkeypatch.setattr(portal, '_load_config', lambda: _cfg('cluster_b'))
    with _as(api, 'cust', CT_FORM):
        portal._create_ct()

    for m in estate.values():
        m.create_container.assert_not_called()


def test_a_target_inside_the_tenant_still_works(api, estate, monkeypatch):
    """The counterweight — the correctly configured hoster is unaffected."""
    monkeypatch.setattr(portal, '_load_config', lambda: _cfg('cluster_a'))
    with _as(api, 'cust', CT_FORM):
        res = portal._create_ct()

    assert not isinstance(res, tuple), res       # a bare dict is the success shape
    assert res.get('success') is True, res
    estate['cluster_a'].create_container.assert_called_once()


def test_a_default_tenant_customer_is_unaffected(api, estate, seed, monkeypatch):
    """get_user_clusters answers None for them, which means 'all clusters'."""
    seed.user('anyone', role='user')
    monkeypatch.setattr(portal, '_load_config', lambda: _cfg('cluster_b'))
    with _as(api, 'anyone', CT_FORM):
        res = portal._create_ct()

    assert not isinstance(res, tuple), res
    assert res.get('success') is True, res
