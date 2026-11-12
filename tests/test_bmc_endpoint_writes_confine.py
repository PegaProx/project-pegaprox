"""The BMC endpoint of a node is written and tested by a caller with the whole cluster only.

DELETE .../bmc-endpoint refused a caller confined to some guests of the cluster, the POST
beside it did not: with admin.settings granted to such an account it replaced the host,
switched the endpoint off or dropped the certificate check under the stored password, and
POST .../test sent the stored login to the BMC and answered with the host's health, which
/hardware keeps from that caller. One BMC watches the whole host and every tenant on it, so
both writes refuse a confined caller now, like the DELETE.
MK Nov 2026
"""
import inspect

import pytest

from pegaprox.core import bmc

from test_node_detail_and_datacenter_reads_confine import SCOPE_GATES

CID = 'cluster_1'
NODE = 'pve1'
BMC = f'/api/clusters/{CID}/nodes/{NODE}/bmc-endpoint'


@pytest.fixture
def who(api, seed, monkeypatch):
    monkeypatch.setattr('pegaprox.api.nodes.log_audit', lambda *a, **k: None)
    m = api.make_fake_manager(cluster_id=CID)
    m.config.name = CID
    api.set_manager(CID, m)
    seed.tenant('acme', clusters=[CID])          # owns the cluster
    seed.tenant('t_confined', clusters=[])        # reaches it through a pool grant only
    admin = seed.user('root', role='admin', tenant_id='default')
    r = api.as_user(admin).post('/api/hardware-monitoring/redfish-consent', json={
        'acknowledge': True, 'ack_version': bmc.REDFISH_CONSENT_VERSION, 'lang': 'en'})
    assert r.status_code == 200, r.get_data(as_text=True)
    r = api.as_user(admin).post(BMC, json={'host': '10.20.30.40', 'user': 'ro-monitor',
                                           'password': 'S3cret!', 'verify_ssl': True})
    assert r.status_code == 200, r.get_data(as_text=True)

    # admin.settings is in no role template: a global admin hands it out on purpose
    perms = ['admin.settings', 'cluster.view', 'node.view']
    pool_user = seed.user('bmcpool', role='viewer', tenant_id='t_confined', permissions=perms)
    seed.pool(CID, 'pool_1', 'bmcpool', ['pool.view', 'vm.view'])
    acl_user = seed.user('bmcacl', role='viewer', tenant_id='acme', permissions=perms)
    seed.vm_acl(CID, 100, ['bmcacl'])
    operator = seed.user('ops', role='viewer', tenant_id='acme', permissions=perms)
    return {'admin': api.as_user(admin), 'pool': api.as_user(pool_user),
            'acl': api.as_user(acl_user), 'operator': api.as_user(operator)}


def _stored():
    from pegaprox.core.db import get_db
    return get_db().get_bmc_endpoint(CID, NODE)


def _refused(r):
    assert r.status_code == 403 and 'whole cluster' in r.get_data(as_text=True), \
        (r.status_code, r.get_data(as_text=True))


@pytest.mark.parametrize('kind', ['pool', 'acl'])
def test_a_confined_caller_cannot_replace_the_endpoint(who, kind):
    _refused(who[kind].post(BMC, json={'host': '10.66.66.66', 'user': 'evil', 'password': 'mine'}))
    _refused(who[kind].delete(BMC))
    assert _stored()['host'] == '10.20.30.40' and _stored()['password'] == 'S3cret!'
    # counterproof: the operator with the whole cluster and the admin still write it
    for k in ('operator', 'admin'):
        r = who[k].post(BMC, json={'host': '10.20.30.40', 'password': '********', 'user': f'by-{k}'})
        assert r.status_code == 200, (k, r.get_data(as_text=True))
        assert _stored()['user'] == f'by-{k}' and _stored()['password'] == 'S3cret!'


@pytest.mark.parametrize('kind', ['pool', 'acl'])
def test_a_confined_caller_cannot_switch_it_off(who, kind):
    # what DELETE refuses, reached through POST: the stored host and the mask keep the
    # password, enabled=False stops the collector reading the node
    _refused(who[kind].post(BMC, json={'host': '10.20.30.40', 'password': '********',
                                       'enabled': False}))
    assert _stored()['enabled'] in (1, True)


@pytest.mark.parametrize('kind', ['pool', 'acl'])
def test_a_confined_caller_cannot_drop_tls_verification_under_the_stored_password(who, kind):
    _refused(who[kind].post(BMC, json={'host': '10.20.30.40', 'password': '********',
                                       'verify_ssl': False}))
    assert _stored()['verify_ssl'] in (1, True)


@pytest.mark.parametrize('kind', ['pool', 'acl'])
def test_a_confined_caller_cannot_send_the_stored_login_to_the_bmc(who, kind, monkeypatch):
    from pegaprox.core import redfish
    sent = []
    monkeypatch.setattr(redfish, 'read_node_bmc_redfish',
                        lambda host, user, pw, verify_ssl=False, timeout=10:
                        sent.append((host, user, pw, verify_ssl)) or
                        {'available': True, 'health': 'critical'})
    _refused(who[kind].post(f'{BMC}/test', json={'verify_ssl': False}))
    assert sent == []
    # counterproof: the operator tests the stored endpoint as it is
    r = who['operator'].post(f'{BMC}/test', json={})
    assert r.status_code == 200 and r.get_json()['health'] == 'critical', r.get_data(as_text=True)
    assert sent == [('10.20.30.40', 'ro-monitor', 'S3cret!', True)]


def test_every_node_write_of_a_cluster_has_a_scope_gate(api):
    """The write twin of the read check in test_node_detail_and_datacenter_reads_confine."""
    missing, seen = [], 0
    for rule in api.app.url_map.iter_rules():
        if not rule.methods & {'POST', 'PUT', 'PATCH', 'DELETE'}:
            continue
        if rule.endpoint.split('.')[0] != 'nodes' or not rule.rule.startswith('/api/clusters/<cluster_id>/'):
            continue
        seen += 1
        src = inspect.getsource(inspect.unwrap(api.app.view_functions[rule.endpoint]))
        if not any(g in src for g in SCOPE_GATES):
            missing.append(f'{rule.rule} ({rule.endpoint})')
    assert seen > 10
    assert not missing, '\n'.join(sorted(missing))
