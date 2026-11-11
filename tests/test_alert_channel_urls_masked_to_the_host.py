"""A masked alert channel shows the scheme and host of its url, nothing of the token.

The mask kept the first 24 and the last 6 characters, and a Slack, Teams or Discord hook
carries its token at the end of the path, so the list showed its tail. The settings read
returned the channels unmasked as well. Both now show scheme://host/… and an edit that
sends the masked row back still keeps the stored url. MK Nov 2026
"""
import pytest

SLACK = 'https://hooks.slack.example/services/T01ABC/B02DEF/q7Rz0pLm4XwN9vKs2Ty8'
DISCORD = 'https://discord.example/api/webhooks/1122334455/Zk3-uPq9_wT0rLx'
BASIC = 'https://alerts:s3cr3t-pw@hooks.internal.example'


@pytest.fixture
def store(monkeypatch):
    data = {'alert_webhooks': [
        {'id': 'slack1', 'name': 'ops', 'type': 'slack', 'url': SLACK, 'enabled': True},
        {'id': 'disc1', 'name': 'dev', 'type': 'discord', 'url': DISCORD, 'enabled': True},
        {'id': 'basic1', 'name': 'siem', 'type': 'generic', 'url': BASIC, 'token': 'tk-77a1', 'enabled': True},
    ]}
    import pegaprox.api.helpers as helpers_mod
    import pegaprox.api.settings as settings_mod
    load = lambda: {k: list(v) for k, v in data.items()}
    monkeypatch.setattr(helpers_mod, 'load_server_settings', load)
    monkeypatch.setattr(settings_mod, 'load_server_settings', load)    # imported by name there
    monkeypatch.setattr(helpers_mod, 'save_server_settings', lambda s: data.update(s))
    return data


def _secrets_in(text):
    return [s for s in ('q7Rz0pLm4XwN9vKs2Ty8'[-6:], 'Zk3-uPq9_wT0rLx'[-6:], 's3cr3t-pw', 'tk-77a1',
                        'T01ABC', '1122334455') if s in text]


def test_the_channel_list_shows_scheme_and_host_only(api, db, seed, store):
    r = api.as_user(seed.user('root', role='admin')).get('/api/alert-channels')
    assert r.status_code == 200
    assert _secrets_in(r.get_data(as_text=True)) == []
    rows = {c['id']: c for c in r.get_json()}
    assert rows['slack1']['url'] == 'https://hooks.slack.example/…'
    assert rows['disc1']['url'] == 'https://discord.example/…'
    assert rows['basic1']['url'] == 'https://hooks.internal.example/…'
    assert rows['basic1']['token'] == '********'


def test_the_settings_read_masks_the_channels_the_same_way(api, db, seed, store):
    r = api.as_user(seed.user('root', role='admin')).get('/api/settings/server')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert _secrets_in(r.get_data(as_text=True)) == []
    assert [c['url'] for c in r.get_json()['alert_webhooks']] == [
        'https://hooks.slack.example/…', 'https://discord.example/…', 'https://hooks.internal.example/…']


def test_an_edit_with_the_masked_row_keeps_the_stored_url(api, db, seed, store):
    c = api.as_user(seed.user('root', role='admin'))
    masked = {ch['id']: ch for ch in c.get('/api/alert-channels').get_json()}
    for cid in ('slack1', 'basic1'):
        r = c.put(f'/api/alert-channels/{cid}', json=dict(masked[cid], name=f'{cid} renamed'))
        assert r.status_code == 200, r.get_data(as_text=True)
    kept = {ch['id']: ch for ch in store['alert_webhooks']}
    assert (kept['slack1']['name'], kept['slack1']['url']) == ('slack1 renamed', SLACK)
    assert (kept['basic1']['url'], kept['basic1']['token']) == (BASIC, 'tk-77a1')


def test_an_url_that_does_not_parse_is_masked_whole(api, db, seed, store):
    store['alert_webhooks'].append({'id': 'odd', 'name': 'odd', 'type': 'generic',
                                    'url': 'hooks-without-scheme/abc123secret', 'enabled': True})
    rows = {ch['id']: ch for ch in api.as_user(seed.user('root', role='admin')).get('/api/alert-channels').get_json()}
    assert rows['odd']['url'] == '********'
