# Full-stack integration suite for in-band hardware monitoring (#609) — the
# consent gate + audit trail added to pegaprox/api/nodes.py.
#
# Same harness as tests/test_integration_nodes.py: the REAL Flask app + REAL nodes
# blueprint, only the cluster manager is faked. The point of these tests is the
# CONSENT GATE and its AUDIT RECORD — the feature must not serve hardware data
# until an admin has acknowledged the versioned compliance warning, and that
# acknowledgement must land in the audit log ("dann heißt es nicht 'Ich hab es
# nie bekommen'").
#
# Gating recap (pegaprox/models/permissions.py ROLE_PERMISSIONS):
#   * node.view      -> admin, user, viewer   (read hardware, read consent status)
#   * admin.settings -> admin ONLY            (POST consent enable/disable)

import pegaprox.globals as _ppglobals
from pegaprox.core import bmc


CID = 'cluster_1'
NODE = 'pve1'

HW_ROUTE = f'/api/clusters/{CID}/nodes/{NODE}/hardware'
CONSENT_ROUTE = '/api/hardware-monitoring/consent'

# A full marker-delimited ipmitool sample so the read route parses to available=True.
SAMPLE = (
    "__PP_SENSORS__\n"
    "CPU1 Temp | 01h | ok | 3.1 | 45 degrees C\n"
    "Fan1 | 41h | ok | 29.1 | 4200 RPM\n"
    "__PP_CHASSIS__\nSystem Power : on\nChassis Intrusion : inactive\n"
    "__PP_POWER__\n    Instantaneous power reading:  210 Watts\n"
    "__PP_FRU__\n Product Name : PowerEdge R740\n Product Serial : CN7016AB012345\n"
    "__PP_SEL__\n"
)


def _mgr(api, **methods):
    m = api.make_fake_manager(cluster_id=CID, **methods)
    m.config.name = CID
    return m


def _current_mgr():
    return _ppglobals.cluster_managers[CID]


def _consent_on(api, seed, monkeypatch):
    """Flip the feature on as an admin (the way the UI would) so read-path tests
    start from an enabled state. Returns the audit-capture list."""
    audit = []
    monkeypatch.setattr('pegaprox.api.nodes.log_audit',
                        lambda u, a, d=None, **k: audit.append((u, a, d)))
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return audit


# ===========================================================================
# CONSENT STATUS (GET) — node.view gated, exposes the versioned warning
# ===========================================================================

def test_anon_hardware_read_is_401(api, seed):
    api.set_manager(CID, _mgr(api))
    assert api.anon().get(HW_ROUTE).status_code == 401


def test_consent_status_default_disabled_with_warning(api, seed):
    # viewer holds node.view -> may read the consent status. Feature starts OFF and
    # the current versioned warning is surfaced for the UI to render.
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    resp = api.as_user(viewer).get(CONSENT_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['enabled'] is False
    assert body['current_version'] == bmc.HW_CONSENT_VERSION
    assert body['warning']['version'] == bmc.HW_CONSENT_VERSION
    assert body['warning']['require_delay_seconds'] == 0   # in-band: confirm, no forced wait
    assert isinstance(body['warning']['points'], list) and body['warning']['points']


# ===========================================================================
# CONSENT WRITE (POST) — admin.settings gated + versioned + audited
# ===========================================================================

def test_user_cannot_enable_consent_403(api, seed):
    # 'user' holds node.view but NOT admin.settings -> perm gate denies the enable.
    user = seed.user('joe', role='user', tenant_id='default')
    resp = api.as_user(user).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_enable_requires_current_version(api, seed):
    # acknowledging an OLD warning version must not opt in (stale-UI protection).
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION - 1})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'ACK_REQUIRED'


def test_enable_writes_audit_record(api, seed, monkeypatch):
    audit = []
    monkeypatch.setattr('pegaprox.api.nodes.log_audit',
                        lambda u, a, d=None, **k: audit.append((u, a, d)))
    admin = seed.user('root', role='admin', tenant_id='default')

    resp = api.as_user(admin).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['enabled'] is True
    assert body['ack_version'] == bmc.HW_CONSENT_VERSION
    assert body['acknowledged_by'] == 'root'

    # THE point of step 2: a durable, attributed acknowledgement was logged.
    assert len(audit) == 1
    user, action, details = audit[0]
    assert user == 'root'
    assert action == 'hardware_monitoring.enabled'
    assert f'v{bmc.HW_CONSENT_VERSION}' in details

    # and the status endpoint now reports it enabled.
    status = api.as_user(admin).get(CONSENT_ROUTE).get_json()
    assert status['enabled'] is True and status['acknowledged_by'] == 'root'


# ===========================================================================
# Localized versioned warning (#609 phase 2) — same version, 7 languages
# ===========================================================================

def test_consent_warning_is_localized_by_lang(api, seed):
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    en = api.as_user(viewer).get(CONSENT_ROUTE + '?lang=en').get_json()['warning']
    de = api.as_user(viewer).get(CONSENT_ROUTE + '?lang=de').get_json()['warning']
    fr = api.as_user(viewer).get(CONSENT_ROUTE + '?lang=fr').get_json()['warning']
    # same version across languages, but distinct localized text
    assert en['version'] == de['version'] == fr['version'] == bmc.HW_CONSENT_VERSION
    assert 'IPMI' in en['title'] and 'aktivieren' in de['title'] and 'Activer' in fr['title']
    assert de['title'] != en['title'] and fr['title'] != en['title']
    assert len(de['points']) == 4 and de['confirm_label'] and de['compliance_note']


def test_consent_warning_unknown_lang_falls_back_to_english(api, seed):
    viewer = seed.user('ro', role='viewer', tenant_id='default')
    w = api.as_user(viewer).get(CONSENT_ROUTE + '?lang=zz').get_json()['warning']
    assert w['title'] == bmc.hw_consent_warning('en')['title']


def test_enable_records_acknowledged_language(api, seed, monkeypatch):
    audit = []
    monkeypatch.setattr('pegaprox.api.nodes.log_audit',
                        lambda u, a, d=None, **k: audit.append((u, a, d)))
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION, 'lang': 'de'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['ack_lang'] == 'de'
    # the acknowledged language is part of the non-repudiation record
    assert len(audit) == 1 and '[de]' in audit[0][2]
    # and it is surfaced back on the status endpoint
    assert api.as_user(admin).get(CONSENT_ROUTE).get_json()['ack_lang'] == 'de'


def test_enable_unknown_language_is_recorded_as_english(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post(CONSENT_ROUTE, json={
        'acknowledge': True, 'ack_version': bmc.HW_CONSENT_VERSION, 'lang': 'zz'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['ack_lang'] == 'en'


# ===========================================================================
# READ ROUTE — refuses until consent, serves after, cluster-access enforced
# ===========================================================================

def test_read_without_consent_is_403_and_never_touches_node(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))

    resp = api.as_user(admin).get(HW_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'CONSENT_REQUIRED'
    # the SSH probe must NOT run before consent
    _current_mgr()._ssh_run_command_output.assert_not_called()


def test_read_after_consent_returns_hardware_200(api, seed, monkeypatch):
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))

    resp = api.as_user(admin).get(HW_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['available'] is True
    assert body['power_w'] == 210.0
    assert body['fru']['product'] == 'PowerEdge R740'
    assert body['health'] == 'ok'
    _current_mgr()._ssh_run_command_output.assert_called_once()


def test_read_bad_node_name_is_400(api, seed, monkeypatch):
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))

    bad = f'/api/clusters/{CID}/nodes/bad;rm%20-rf/hardware'
    resp = api.as_user(admin).get(bad)
    assert resp.status_code == 400, resp.get_data(as_text=True)
    _current_mgr()._ssh_run_command_output.assert_not_called()


def test_cross_tenant_user_denied_hardware_403(api, seed, monkeypatch):
    # even with the feature enabled, a user from another tenant is stopped at the
    # cluster level (check_cluster_access) before any hardware read.
    _consent_on(api, seed, monkeypatch)
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))

    resp = api.as_user(bob).get(HW_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    _current_mgr()._ssh_run_command_output.assert_not_called()


def test_disable_turns_the_read_route_back_off(api, seed, monkeypatch):
    audit = _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))

    # sanity: enabled -> 200
    assert api.as_user(admin).get(HW_ROUTE).status_code == 200

    # disable, then the read route refuses again
    off = api.as_user(admin).post(CONSENT_ROUTE, json={'enabled': False})
    assert off.status_code == 200 and off.get_json()['enabled'] is False
    assert ('root', 'hardware_monitoring.disabled', 'In-band hardware monitoring disabled') in audit

    resp = api.as_user(admin).get(HW_ROUTE)
    assert resp.status_code == 403 and resp.get_json()['code'] == 'CONSENT_REQUIRED'


def test_missing_cluster_manager_is_404_after_consent(api, seed, monkeypatch):
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    # consent on, node name valid, but no manager loaded -> 404 (not 403/500)
    resp = api.as_user(admin).get(HW_ROUTE)
    assert resp.status_code == 404, resp.get_data(as_text=True)
    assert 'not found' in resp.get_json()['error'].lower()


# ===========================================================================
# ipmitool INSTALL (step 3) — gates fire before the SSH fan-out. The actual
# per-node apt install needs real hardware (like starlvm), so only the gates
# are asserted here: admin-only, proxmox-only, and consent-required.
# ===========================================================================

INSTALL_ROUTE = f'/api/clusters/{CID}/hardware/ipmitool/install'


def test_install_requires_admin_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')  # node.view, not admin.settings
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(user).post(INSTALL_ROUTE, json={'nodes': [NODE]})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_install_without_consent_is_403(api, seed):
    # admin, proxmox cluster, but feature not enabled -> CONSENT_REQUIRED before fan-out.
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': [NODE]})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'CONSENT_REQUIRED'


def test_install_non_proxmox_is_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, cluster_type='vmware'))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': [NODE]})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'proxmox' in resp.get_json()['error'].lower()


def test_install_bad_node_name_is_400(api, seed, monkeypatch):
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': ['bad;rm -rf']})
    assert resp.status_code == 400, resp.get_data(as_text=True)


# ===========================================================================
# Hardening regressions from the adversarial review (input hygiene / fail-closed)
# ===========================================================================

def test_install_non_string_node_is_400_not_500(api, seed, monkeypatch):
    # crafted {"nodes":[123]} used to blow up _reject_bad_node's regex -> 500.
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': [123]})
    assert resp.status_code == 400, resp.get_data(as_text=True)


def test_install_unhashable_node_entry_is_400_not_500(api, seed, monkeypatch):
    # a dict entry used to raise in set() before the loop even ran.
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': [{'x': 1}]})
    assert resp.status_code == 400, resp.get_data(as_text=True)


def test_install_nodes_not_a_list_is_400(api, seed, monkeypatch):
    _consent_on(api, seed, monkeypatch)
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api))
    resp = api.as_user(admin).post(INSTALL_ROUTE, json={'nodes': 'pve1'})
    assert resp.status_code == 400, resp.get_data(as_text=True)


def test_enable_non_int_ack_version_is_400_not_500(api, seed):
    # POST {acknowledge:true, ack_version:'x'} used to raise int('x') -> 500.
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post(CONSENT_ROUTE, json={'acknowledge': True, 'ack_version': 'x'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'ACK_REQUIRED'


def test_corrupt_stored_ack_version_fails_closed(api, seed):
    # a corrupt/crafted settings blob (e.g. via config-restore) with a non-int
    # ack_version must NOT 500 the gate — it fails closed to CONSENT_REQUIRED.
    from pegaprox.api.helpers import save_server_settings
    save_server_settings({'hardware_monitoring': {'enabled': True, 'ack_version': 'abc'}})
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CID, _mgr(api, _get_node_ip='10.0.0.9', _ssh_run_command_output=SAMPLE))
    resp = api.as_user(admin).get(HW_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()['code'] == 'CONSENT_REQUIRED'
