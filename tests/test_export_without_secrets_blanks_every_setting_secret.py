"""An export without secrets blanks every secret of the server settings.

It blanked the SMTP password and the two ACME DNS secrets. The LDAP bind password, the
OIDC client secret and the private key of the push keypair went into the archive sealed as
stored, and the alert channels as they are: a Slack, Teams or Discord hook carries its
token in its url, an ntfy channel its token and its topic.

They are blank now. The keys and the channel rows stay, so a restore here keeps what this
instance holds, and a restore on another instance names what to enter again
(tests/test_restore_keeps_a_secret_with_its_server.py). MK
"""
import io
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password
from test_restore_keeps_a_secret_with_its_server import (HOOK, NTFY_TOKEN, NTFY_TOPIC, NTFY_URL, SEALED, VAPID,
                                                         _channels, _stored, live)  # noqa: F401

PLAIN = ('smtp-pw', 'ldap-pw', 'oidc-secret', 'tsig-secret', 'cf-token', 'BEGIN PRIVATE KEY')


def _export(client, **kw):
    import pegaprox.api.settings as settings_api
    r = client.post('/api/config/backup', json=dict(user_password=_ADMIN_PW, backup_password=_BACKUP_PW, **kw))
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_data(), settings_api._decrypt_backup(r.get_data(), _BACKUP_PW)


def test_an_export_without_secrets_holds_no_channel_url_token_or_topic(live):
    _blob, plain = _export(live)
    ss = json.loads(plain)['server_settings']

    # the rows are there: what is missing below was blanked, not lost
    assert [(ch['name'], ch['type']) for ch in ss['alert_webhooks']] == [('ops', 'slack'), ('phone', 'ntfy')]
    assert [(ch['url'], ch.get('token', ''), ch.get('topic', '')) for ch in ss['alert_webhooks']] == [('', '', '')] * 2
    found = [v for v in (HOOK, NTFY_TOKEN, NTFY_TOPIC) if v in plain]
    assert not found, found


def test_an_export_without_secrets_holds_no_sealed_setting(live):
    stored = _stored()
    _blob, plain = _export(live)
    ss = json.loads(plain)['server_settings']

    # blank, the keys stay
    assert {k: ss[k] for k in SEALED} == {k: '' for k in SEALED}
    assert ss[VAPID] == {'private_pem': '', 'public_b64': stored[VAPID]['public_b64']}
    # neither the values nor this instance's sealed form of them
    sealed = [stored[k] for k in SEALED] + [stored[VAPID]['private_pem']]
    found = [v for v in PLAIN + tuple(sealed) if v in plain]
    assert not found, found


def test_with_the_secrets_asked_for_they_are_in(live):
    """The guard: the same export with include_secrets carries every one of them."""
    stored = _stored()
    _blob, plain = _export(live, include_secrets=True)
    ss = json.loads(plain)['server_settings']

    assert _channels(ss) == _channels(stored)
    assert {k: ss[k] for k in SEALED} == {k: stored[k] for k in SEALED}
    assert ss[VAPID] == stored[VAPID]


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_restoring_that_export_here_keeps_them(live, mode):
    before = _stored()
    blob, plain = _export(live)
    assert json.loads(plain)['server_settings']['alert_webhooks'][0]['url'] == ''

    r = live.post('/api/config/restore', content_type='multipart/form-data',
                  data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW, 'mode': mode,
                        'backup_file': (io.BytesIO(blob), 'x.pegabackup')})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'secrets_to_enter' not in r.get_json(), r.get_json()
    after = _stored()
    assert {k: after[k] for k in SEALED} == {k: before[k] for k in SEALED}
    assert _channels(after) == _channels(before)
    assert (_channels(after)['ops']['url'], _channels(after)['phone']['url']) == (HOOK, NTFY_URL)
    assert after[VAPID] == before[VAPID]
