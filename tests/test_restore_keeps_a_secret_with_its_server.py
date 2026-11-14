"""A restore keeps a stored secret for a blank in the backup only while its server stays.

A config export without secrets carries the SMTP, LDAP, OIDC and ACME DNS secrets blank.
An overwrite restore wrote that blank over the stored secret, and a merge restore kept the
stored one for whatever server the backup named, so the next mail, login or DNS update
handed it to that server. The alert channels went the same way: a merge replaces the list
whole, and a blank url replaced the one this instance holds.

Now a blank keeps the stored secret while the server it was typed for stays the same, as
the settings save does, and the answer of the restore names each secret that ends up
empty and is needed. A channel is kept by its id; one this instance does not hold comes
back turned off and named. MK
"""
import io
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

HOOK = 'https://hooks.example/services/T000/B000/HOOKTOKEN'
NTFY_URL = 'https://ntfy.example'
NTFY_TOKEN = 'tk_ntfytoken'
NTFY_TOPIC = 'private-topic'
# the ones with a server, and the Cloudflare token that always goes to Cloudflare
BOUND = ('smtp_password', 'ldap_bind_password', 'oidc_client_secret', 'acme_dns_rfc2136_secret')
SEALED = BOUND + ('acme_dns_cloudflare_token',)
VAPID = 'webpush_vapid_keypair'


@pytest.fixture
def live(api, seed):
    """An instance with every secret of the server settings set, as the save routes seal them."""
    admin = _admin_with_password(api, seed)
    for body in ({'name': 'ops', 'type': 'slack', 'url': HOOK},
                 {'name': 'phone', 'type': 'ntfy', 'url': NTFY_URL, 'topic': NTFY_TOPIC, 'token': NTFY_TOKEN}):
        r = admin.post('/api/alert-channels', json=body)
        assert r.status_code == 200, r.get_data(as_text=True)
    from pegaprox.core.db import get_db
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    db = get_db()
    s = load_server_settings()
    s.update(smtp_host='mail.example', smtp_port=587, smtp_user='alerts', smtp_password=db._encrypt('smtp-pw'),
             ldap_server='ldap.example', ldap_port=389, ldap_bind_dn='cn=pp,dc=example',
             ldap_bind_password=db._encrypt('ldap-pw'),
             oidc_provider='generic', oidc_authority='https://idp.example', oidc_client_id='pegaprox',
             oidc_client_secret=db._encrypt('oidc-secret'),
             acme_dns_provider='rfc2136', acme_dns_rfc2136_nameserver='ns.example',
             acme_dns_rfc2136_secret=db._encrypt('tsig-secret'),
             acme_dns_cloudflare_token=db._encrypt('cf-token'))
    save_server_settings(s)
    from pegaprox.api import push
    push._load_vapid()
    return admin


def _stored():
    from pegaprox.core.db import get_db
    return get_db().get_server_settings()


def _channels(settings):
    return {ch['name']: ch for ch in settings.get('alert_webhooks') or []}


def _without_secrets(blank='', **changes):
    """The server settings of this instance as an export without secrets holds them, each
    secret as `blank`."""
    from pegaprox.api.helpers import load_server_settings
    ss = load_server_settings()
    ss.update({k: blank for k in SEALED})
    ss['alert_webhooks'] = [dict(ch, **{k: blank for k in ('url', 'token', 'topic') if k in ch})
                            for ch in ss['alert_webhooks']]
    ss[VAPID] = dict(ss[VAPID], private_pem=blank)
    ss.update(changes)
    return ss


# what a backup can hold where a secret was left out; none of them is a secret
BLANKS = pytest.mark.parametrize('blank', ['', [], {}, 0], ids=['empty', 'list', 'dict', 'zero'])


def _restore(client, server_settings, mode, dry_run=False):
    import pegaprox.api.settings as settings_api
    data = {'version': 'test', 'export_date': '2026-11-01T10:00:00', 'server_settings': server_settings}
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = client.post('/api/config/restore', content_type='multipart/form-data',
                    data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW, 'mode': mode,
                          'dry_run': 'true' if dry_run else 'false',
                          'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()
    assert res['restored'].get('server_settings') is True and not res['errors'], res
    return res


@BLANKS
@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_without_secrets_restored_here_keeps_every_stored_one(live, mode, blank):
    before = _stored()

    res = _restore(live, _without_secrets(blank), mode)

    after = _stored()
    assert {k: after[k] for k in SEALED} == {k: before[k] for k in SEALED}
    assert _channels(after) == _channels(before)
    assert after[VAPID] == before[VAPID] and after[VAPID]['private_pem']
    assert 'secrets_to_enter' not in res, res


@BLANKS
@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_that_moves_the_servers_takes_no_stored_secret_along(live, mode, blank):
    cloudflare = _stored()['acme_dns_cloudflare_token']

    moved = _without_secrets(blank, smtp_host='mail.other.example', ldap_server='ldap.other.example',
                             oidc_authority='https://idp.other.example',
                             acme_dns_rfc2136_nameserver='ns.other.example')

    res = _restore(live, moved, mode)

    after = _stored()
    assert {k: after[k] for k in BOUND} == {k: '' for k in BOUND}
    assert sorted(s['setting'] for s in res.get('secrets_to_enter', []) if 'setting' in s) == sorted(BOUND)
    # a Cloudflare token has no server of its own to move
    assert after['acme_dns_cloudflare_token'] == cloudflare


def test_another_port_is_another_server(live):
    res = _restore(live, _without_secrets(smtp_port=465, ldap_port=636), 'merge')

    after = _stored()
    assert after['smtp_password'] == '' and after['ldap_bind_password'] == ''
    assert after['oidc_client_secret'] and after['acme_dns_rfc2136_secret']
    assert res.get('secrets_to_enter') == [{'setting': 'smtp_password'}, {'setting': 'ldap_bind_password'}]


def test_the_same_host_written_another_way_is_the_same_server(live):
    """The counterweight: case and a trailing dot do not move a server."""
    before = _stored()

    _restore(live, _without_secrets(smtp_host='MAIL.example.', ldap_server='Ldap.Example'), 'overwrite')

    assert _stored()['smtp_password'] == before['smtp_password']
    assert _stored()['ldap_bind_password'] == before['ldap_bind_password']


def test_a_channel_this_instance_does_not_hold_comes_back_turned_off_and_named(live):
    ss = _without_secrets()
    ss['alert_webhooks'].append({'id': 'feedfeedfeed', 'name': 'pager', 'type': 'generic',
                                 'url': '', 'enabled': True})

    res = _restore(live, ss, 'overwrite')

    rows = _channels(_stored())
    assert rows['pager']['url'] == '' and rows['pager']['enabled'] is False
    assert res.get('secrets_to_enter') == [{'channel': 'pager'}]
    # the channels this instance holds keep what they send with
    assert rows['ops']['url'] == HOOK
    assert (rows['phone']['url'], rows['phone']['token'], rows['phone']['topic']) == (NTFY_URL, NTFY_TOKEN, NTFY_TOPIC)


def test_a_fresh_instance_is_told_every_secret_the_backup_left_out(live):
    ss = _without_secrets()
    # the instance it goes to holds none of them
    from pegaprox.core.db import get_db
    db = get_db()
    for k in SEALED:
        db.save_server_setting(k, '')
    db.save_server_setting('alert_webhooks', [])

    res = _restore(live, ss, 'merge')

    named = res.get('secrets_to_enter', [])
    assert sorted(s['setting'] for s in named if 'setting' in s) == sorted(BOUND)
    assert sorted(s['channel'] for s in named if 'channel' in s) == ['ops', 'phone']
    rows = _channels(_stored())
    assert rows['ops']['enabled'] is False and rows['phone']['enabled'] is False


def test_a_dry_run_names_them_and_changes_nothing(live):
    before = _stored()

    res = _restore(live, _without_secrets(smtp_host='mail.other.example'), 'merge', dry_run=True)

    assert res.get('secrets_to_enter') == [{'setting': 'smtp_password'}]
    assert _stored() == before


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_secret_the_backup_carries_is_stored_as_it_is(live, mode):
    """The counterweight: a backup with the secrets still sets them, for a new server too."""
    from pegaprox.core.db import get_db
    sealed = get_db()._encrypt('new-smtp-pw')
    ss = _without_secrets(smtp_host='mail.other.example', smtp_password=sealed)
    ss['alert_webhooks'][0]['url'] = 'https://hooks.example/services/T000/B000/NEWTOKEN'

    res = _restore(live, ss, mode)

    after = _stored()
    assert after['smtp_password'] == sealed
    assert _channels(after)['ops']['url'] == 'https://hooks.example/services/T000/B000/NEWTOKEN'
    assert {'setting': 'smtp_password'} not in res.get('secrets_to_enter', [])
