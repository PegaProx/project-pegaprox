"""The BMC endpoint of a node is written and tested by a caller with the whole cluster only.

DELETE .../bmc-endpoint refused a caller confined to some guests of the cluster, the POST
beside it did not: with admin.settings granted to such an account it replaced the host,
switched the endpoint off or dropped the certificate check under the stored password, and
POST .../test sent the stored login to the BMC and answered with the host's health, which
/hardware keeps from that caller. One BMC watches the whole host and every tenant on it, so
both writes refuse a confined caller now, like the DELETE.

The two reads beside them handed the same caller the BMC host and login name of every
node, and the two consent switches, which turn the hardware reads on or off for the whole
installation, took any holder of admin.settings. The reads refuse a confined caller like
the writes; the switches take the bar of the interface lock and the banners: an account
limited to a tenant or to some clusters is refused.
MK Nov 2026
"""
import inspect

import pytest

from pegaprox.core import bmc

from test_node_detail_and_datacenter_reads_confine import SCOPE_GATES

CID = 'cluster_1'
NODE = 'pve1'
BMC = f'/api/clusters/{CID}/nodes/{NODE}/bmc-endpoint'
ALL_BMC = f'/api/clusters/{CID}/bmc-endpoints'
INBAND = '/api/hardware-monitoring/consent'
REDFISH = '/api/hardware-monitoring/redfish-consent'


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


# --- the two reads and the two consent switches -------------------------------------------

@pytest.mark.parametrize('kind', ['pool', 'acl'])
def test_a_confined_caller_cannot_read_the_endpoints(who, kind):
    _refused(who[kind].get(BMC))
    _refused(who[kind].get(ALL_BMC))
    # counterproof: with the whole cluster the host is there and the password stays masked
    for k in ('operator', 'admin'):
        r = who[k].get(BMC)
        assert r.status_code == 200, (k, r.get_data(as_text=True))
        assert r.get_json()['host'] == '10.20.30.40' and r.get_json()['password'] == '********'
        r = who[k].get(ALL_BMC)
        assert r.status_code == 200, (k, r.get_data(as_text=True))
        assert [e['host'] for e in r.get_json()['endpoints']] == ['10.20.30.40']
        assert 'S3cret!' not in r.get_data(as_text=True)


def _consent():
    from pegaprox.api.helpers import load_server_settings
    s = load_server_settings() or {}
    return ((s.get('hardware_monitoring') or {}).get('enabled'),
            (s.get('hardware_monitoring_redfish') or {}).get('enabled'))


def _switch_refused(r):
    assert r.status_code == 403 and 'not limited to a tenant' in r.get_data(as_text=True), \
        (r.status_code, r.get_data(as_text=True))


@pytest.mark.parametrize('kind', ['pool', 'acl', 'operator'])
def test_a_confined_holder_of_admin_settings_cannot_flip_the_consent(who, kind):
    """The operator sees the whole cluster but lives in a tenant limited to it: the
    switches are one for every cluster, so they are refused too."""
    before = _consent()
    assert before == (None, True)
    _switch_refused(who[kind].post(REDFISH, json={'enabled': False}))
    _switch_refused(who[kind].post(INBAND, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION, 'lang': 'en'}))
    _switch_refused(who[kind].post(INBAND, json={'enabled': False}))
    assert _consent() == before

    # counterproof: the admin of the installation switches both ways
    admin = who['admin']
    r = admin.post(INBAND, json={'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION, 'lang': 'en'})
    assert r.status_code == 200 and r.get_json()['enabled'] is True, r.get_data(as_text=True)
    r = admin.post(REDFISH, json={'enabled': False})
    assert r.status_code == 200 and r.get_json() == {'enabled': False}, r.get_data(as_text=True)
    assert _consent() == (True, False)


def test_the_consent_switches_refuse_when_the_scope_cannot_be_read(who, monkeypatch):
    def _broken(user):
        raise RuntimeError('rbac store not readable')
    monkeypatch.setattr('pegaprox.api.ha._unconfined', _broken)
    _switch_refused(who['admin'].post(REDFISH, json={'enabled': False}))
    _switch_refused(who['admin'].post(INBAND, json={'enabled': False}))
    assert _consent() == (None, True)
