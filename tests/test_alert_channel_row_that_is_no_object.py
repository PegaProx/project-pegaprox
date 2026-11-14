"""A channel row that is no object stops no read, no edit and no alert.

A settings row edited by hand can be a bare webhook url, a number or null instead of a
channel object. The mask did dict() on it and raised, so the channel list answered 500,
the edit routes raised on ch.get, and the alert fan-out stopped at that row. The support
bundle let such a row past the mask, a bare url went out with its token. Now the reads
skip what has no id, the bundle masks every row and the channels after it still get the
alert. MK Nov 2026
"""
import io
import json
import zipfile

import pytest

SLACK = 'https://hooks.slack.example/services/T01ABC/B02DEF/strrow-secret'
TOKEN_PARTS = ('strrow-secret', 'T01ABC', 'tk-77a1')


@pytest.fixture
def store(monkeypatch):
    data = {'alert_webhooks': [
        SLACK, 5, None,
        {'id': 'ops1', 'name': 'ops', 'type': 'generic', 'url': 'https://hooks.ops.example/x/y',
         'token': 'tk-77a1', 'enabled': True},
    ]}
    import pegaprox.api.helpers as helpers_mod
    import pegaprox.api.settings as settings_mod
    load = lambda: {k: list(v) if isinstance(v, list) else v for k, v in data.items()}
    monkeypatch.setattr(helpers_mod, 'load_server_settings', load)
    monkeypatch.setattr(settings_mod, 'load_server_settings', load)    # imported by name there
    monkeypatch.setattr(helpers_mod, 'save_server_settings', lambda s: data.update(s))
    return data


@pytest.fixture
def admin(api, db, seed):
    return api.as_user(seed.user('root', role='admin'))


def _token_parts_in(text):
    return [s for s in TOKEN_PARTS if s in text]


@pytest.mark.parametrize('row, shown', [
    (SLACK, {'url': 'https://hooks.slack.example/…'}),
    (5, {'url': '********'}),
    (None, {'url': None}),
    (['https://hooks.example/a/tok-list-1'], {'url': '********'}),
], ids=['url', 'int', 'none', 'list'])
def test_the_mask_takes_a_row_that_is_no_object(row, shown):
    from pegaprox.api.alerts import _mask_channel
    assert _mask_channel(row) == shown


def test_the_channel_list_skips_the_rows_that_are_no_object(admin, store):
    r = admin.get('/api/alert-channels')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert _token_parts_in(r.get_data(as_text=True)) == []
    assert [(c['id'], c['url'], c['token']) for c in r.get_json()] == [
        ('ops1', 'https://hooks.ops.example/…', '********')]


def test_the_edit_test_and_delete_routes_find_the_channel_after_them(admin, store, monkeypatch):
    import pegaprox.utils.webhooks as webhooks_mod
    monkeypatch.setattr(webhooks_mod, 'send_to_channel', lambda ch, alert: (True, 'HTTP 200'))
    r = admin.put('/api/alert-channels/ops1', json={'name': 'ops renamed'})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert store['alert_webhooks'][3]['name'] == 'ops renamed'
    r = admin.post('/api/alert-channels/ops1/test')
    assert r.status_code == 200 and r.get_json()['success'] is True, r.get_data(as_text=True)[:300]
    assert admin.put('/api/alert-channels/nope', json={'name': 'x'}).status_code == 404
    r = admin.delete('/api/alert-channels/ops1')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    # the hand-edited rows stay as they were, only the channel named goes
    assert store['alert_webhooks'] == [SLACK, 5, None]


def test_the_diagnostics_list_the_channels_that_are_objects(admin, store):
    r = admin.get('/api/alerts/diagnostics')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert [c['id'] for c in r.get_json()['webhook_channels']] == ['ops1']


def test_the_alert_still_reaches_the_channels_after_them(store, monkeypatch):
    import pegaprox.utils.webhooks as webhooks_mod
    sent = []
    monkeypatch.setattr(webhooks_mod, 'send_to_channel', lambda ch, alert: sent.append(ch['id']) or (True, 'HTTP 200'))
    webhooks_mod.send_to_channels({'alert_name': 'disk full'})
    assert sent == ['ops1']


def test_the_support_bundle_masks_every_row(admin, store, tmp_path, monkeypatch):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'LOG_DIR', str(tmp_path))
    r = admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith('/server_settings.json'))
        text = zf.read(name).decode()
    assert _token_parts_in(text) == []
    rows = json.loads(text)['alert_webhooks']
    assert [c.get('url') for c in rows] == ['https://hooks.slack.example/…', '********', None,
                                           'https://hooks.ops.example/…']
    assert rows[3]['id'] == 'ops1' and rows[3]['token'] == '********'


def test_the_support_bundle_masks_a_channel_list_that_is_one_url(admin, store, tmp_path, monkeypatch):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'LOG_DIR', str(tmp_path))
    store['alert_webhooks'] = SLACK
    r = admin.get('/api/support-bundle')
    assert r.status_code == 200, r.data[:300]
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith('/server_settings.json'))
        text = zf.read(name).decode()
    assert _token_parts_in(text) == []
    assert json.loads(text)['alert_webhooks'] == [{'url': 'https://hooks.slack.example/…'}]
