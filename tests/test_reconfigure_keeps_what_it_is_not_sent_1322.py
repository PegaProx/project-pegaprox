"""A re-configure keeps what its body leaves out (#1322).

Re-saving the dialog built the new manager from the body alone. The stored SSH key, the
SSH user and port, the excluded nodes, the VNC tunnel, the SMBIOS settings and the backup
SLA went with the old one, and the export the dialog fills itself from had no HA switch,
API port or node link suffix, so those went back to their defaults too.

MK Nov 2026
"""
import pytest

from pegaprox.utils.ssh import node_login
from test_ha_settings_writers import no_cluster, DIALOG  # noqa: F401
from test_ha_api import ha_env, _admin, ADMIN_PW  # noqa: F401
from test_ha_claim import claimed, pve, me  # noqa: F401


KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
HELD = dict(ssh_user='ops', ssh_key=KEY, ssh_port=2222, fallback_hosts=['10.9.0.2'],
            excluded_nodes=['pve2'], vnc_tunnel=True, latitude=48.2, longitude=16.3,
            location_label='Vienna', backup_sla_max_age_hours=26, smbios_autoconfig={'enabled': True},
            api_port=8443, node_ui_suffix='lab.example', predictive_balancing=True,
            predictive_threshold=70, balance_io_weight=0.5, cpu_baseline='x86-64-v3', enabled=True)
# what the dialog sends: the connection, and an empty key field
BODY = dict(DIALOG, ssh_key='', ssh_disabled=False)


@pytest.fixture
def held(claimed, no_cluster, monkeypatch):
    import pegaprox.api.clusters as clusters_api
    for k, v in HELD.items():
        setattr(claimed.mgr.config, k, v)
    dropped = []
    monkeypatch.setattr(clusters_api, '_drop_node_passwords',
                        lambda cid, name, moved: dropped.append(moved) or [])
    claimed.dropped = dropped
    return claimed


def _reconfigure(env, **body):
    from pegaprox.globals import cluster_managers
    r = _admin(env.api, env.seed).post('/api/clusters/c1/reconfigure', json=dict(BODY, **body))
    assert r.status_code == 200, r.get_data(as_text=True)
    return cluster_managers['c1'].config


def test_a_re_save_keeps_what_the_dialog_does_not_send(held):
    cfg = _reconfigure(held)
    for key, value in HELD.items():
        assert getattr(cfg, key) == value, key
    stored = held.db.get_cluster('c1')
    assert (stored['ssh_user'], stored['ssh_port'], stored['excluded_nodes']) == ('ops', 2222, ['pve2'])
    assert stored['ssh_key'] == KEY
    # the kept port and hosts are no move: the nodes' own passwords stay
    assert held.dropped == []


def test_a_new_key_replaces_the_stored_one(held):
    new = KEY.replace('AAAA', 'BBBB')
    assert _reconfigure(held, ssh_key=new).ssh_key == new


def test_an_ssh_user_the_body_sends_empty_is_root_again(held):
    cfg = _reconfigure(held, ssh_user='')
    assert cfg.ssh_user == '' and node_login(cfg) == 'root'


def test_the_fallback_hosts_stay_only_where_the_cluster_stays(held):
    assert _reconfigure(held).fallback_hosts == ['10.9.0.2']
    assert _reconfigure(held, host='10.70.0.1').fallback_hosts == []


def test_the_export_carries_what_the_dialog_fills_itself_from(held):
    held.mgr.config.ha_enabled = True
    for k, v in dict(ssl_verification=False, migration_threshold=20, check_interval=300,
                     auto_migrate=False, dry_run=False).items():
        setattr(held.mgr.config, k, v)
    r = _admin(held.api, held.seed).get('/api/clusters/c1/config/export')
    assert r.status_code == 200
    got = r.get_json()
    for key in ('api_port', 'node_ui_suffix', 'predictive_balancing', 'predictive_threshold',
                'balance_io_weight', 'cpu_baseline', 'ssh_user'):
        assert got[key] == HELD[key], key
    assert got['ha_enabled'] is True
    assert got['has_ssh_key'] is True and 'ssh_key' not in got and 'pass' not in got
