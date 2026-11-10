"""Re-configuring a cluster keeps the SSH settings the dialog did not touch (#1251).

The new manager is built from the request body alone. The dialog cannot read a stored key
back and sent no SSH user or port at all, so saving it with SSH untouched wiped all three,
and the nodes were then reached under the API user's name with no key.

An empty key field keeps the key, a typed one replaces it, and only ssh_key_remove drops it,
so a key can still be removed. A field with nothing but whitespace in it counts as empty.
The key itself never comes back to the browser.
"""
import types

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.globals as ppglobals

from test_ha_api import ADMIN_PW, _admin

CID = 'c1'
KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nstored\n-----END OPENSSH PRIVATE KEY-----'
NEW_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nnew\n-----END OPENSSH PRIVATE KEY-----'


@pytest.fixture
def reconfigure(api, seed, db, monkeypatch):
    class _NewMgr:
        cluster_type = 'proxmox'
        _token_auto_created = False

        def __init__(self, cid, config):
            self.id, self.config = cid, config

        def connect_to_proxmox(self):
            return True

        def start(self):
            pass

    monkeypatch.setattr(clusters_api, 'PegaProxManager', _NewMgr)
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    old = api.make_fake_manager(CID)
    old.config = types.SimpleNamespace(
        host='10.0.0.1', user='pegaprox@pve', pass_='pw', ssh_user='root', ssh_key=KEY, ssh_port=2222,
        fallback_hosts=[], ssl_verification=False, migration_cooldown=0, transfer_network='', name='lab')
    old.stop = lambda: None
    api.set_manager(CID, old)
    client = _admin(api, seed)

    def send(**body):
        dialog = {'current_password': ADMIN_PW, 'name': 'lab', 'host': '10.0.0.1', 'user': 'pegaprox@pve',
                  'pass': 'typed-again', 'ssl_verification': False, 'ssh_key': ''}
        dialog.update(body)
        r = client.post(f'/api/clusters/{CID}/reconfigure', json=dialog)
        assert r.status_code == 200, r.data
        return ppglobals.cluster_managers[CID].config
    return send


def test_a_save_with_ssh_untouched_keeps_user_key_and_port(reconfigure):
    cfg = reconfigure()
    assert (cfg.ssh_user, cfg.ssh_key, cfg.ssh_port) == ('root', KEY, 2222)


def test_a_typed_key_replaces_the_stored_one(reconfigure):
    assert reconfigure(ssh_key=NEW_KEY).ssh_key == NEW_KEY


def test_the_stored_key_can_be_removed(reconfigure):
    assert reconfigure(ssh_key_remove=True).ssh_key == ''


def test_a_typed_key_wins_over_the_remove_flag(reconfigure):
    assert reconfigure(ssh_key=NEW_KEY, ssh_key_remove=True).ssh_key == NEW_KEY


@pytest.mark.parametrize('flag', [False, 'true', 1, None])
def test_only_a_real_true_removes_the_key(reconfigure, flag):
    assert reconfigure(ssh_key_remove=flag).ssh_key == KEY


@pytest.mark.parametrize('blank', [' ', '\n', ' \t\r\n '])
def test_a_blank_key_field_is_no_key_and_keeps_the_stored_one(reconfigure, blank):
    assert reconfigure(ssh_key=blank).ssh_key == KEY


@pytest.mark.parametrize('blank', [' ', '\n', ' \t\r\n '])
def test_a_blank_key_field_does_not_stop_the_remove_flag(reconfigure, blank):
    assert reconfigure(ssh_key=blank, ssh_key_remove=True).ssh_key == ''


def test_a_blank_key_is_no_credential_for_the_required_check(reconfigure):
    with pytest.raises(AssertionError, match='SSH key is required'):
        reconfigure(ssh_key='\n', **{'pass': ''})


def test_the_remove_flag_is_no_setting(reconfigure):
    assert not hasattr(reconfigure(ssh_key_remove=True), 'ssh_key_remove')


def test_an_ssh_user_in_the_body_is_taken(reconfigure):
    assert reconfigure(ssh_user='backupadmin').ssh_user == 'backupadmin'


def test_an_emptied_ssh_user_field_goes_back_to_the_default(reconfigure):
    assert reconfigure(ssh_user='').ssh_user == ''


def test_an_ssh_port_in_the_body_is_taken(reconfigure):
    assert reconfigure(ssh_port=2200).ssh_port == 2200


def test_a_bad_ssh_user_is_still_refused(api, seed, reconfigure):
    with pytest.raises(AssertionError, match='400|ssh_user'):
        reconfigure(ssh_user='root; reboot')


def test_the_dialog_reads_the_user_and_that_a_key_exists_but_never_the_key(api, seed, reconfigure):
    reconfigure(ssh_key=NEW_KEY, ssh_user='backupadmin')
    got = _admin(api, seed).get(f'/api/clusters/{CID}/config/export')
    assert got.status_code == 200, got.data
    body = got.get_json()
    assert body['ssh_user'] == 'backupadmin' and body['has_ssh_key'] is True
    assert 'PRIVATE KEY' not in got.get_data(as_text=True) and 'ssh_key' not in body


# the stored row, not only the live config: a removed key stays removed after the next save
from test_ha_api import ha_env  # noqa: E402,F401
from test_ha_settings_writers import no_cluster  # noqa: E402,F401
from test_ha_claim import claimed, pve, me  # noqa: E402,F401
from test_reconfigure_keeps_what_it_is_not_sent_1322 import held, _reconfigure  # noqa: E402,F401


def test_a_removed_key_is_gone_from_the_database_and_stays_gone(held):
    assert _reconfigure(held).ssh_key and held.db.get_cluster('c1')['ssh_key']
    assert _reconfigure(held, ssh_key_remove=True).ssh_key == ''
    assert held.db.get_cluster('c1')['ssh_key'] == ''
    assert _reconfigure(held).ssh_key == '' and held.db.get_cluster('c1')['ssh_key'] == ''
