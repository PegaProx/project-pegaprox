"""The plugin config editor shows credentials masked and keeps them on a save.

GET /api/plugins/<id>/config returned config.json as stored: the key of the status
page, the ntfy token and the apprise urls of the notification plugin. A value under a
key that names a credential now goes out masked (an url keeps its scheme), and a masked
value that comes back in a save is the stored one again. The file is written for its
owner only. MK Nov 2026
"""
import json
import os
import re
import stat

import pytest

import pegaprox.api.plugins as plugins_api

STATUS = {'auth_key': 'sp-9c2d71f0e4', 'page_title': 'System Status', 'refresh_interval': 30}
NOTIFY = {'ntfy_enabled': True, 'ntfy_url': 'https://ntfy.example', 'ntfy_topic': 'ops',
          'ntfy_token': 'tk_51e0a7', 'ntfy_priority_map': {'critical': 'max'},
          'apprise_enabled': True, 'apprise_urls': ['tgram://123:AAH-bot/987', 'discord://11/wh-token']}


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    for pid, cfg in (('status_page', STATUS), ('notifications', NOTIFY)):
        (tmp_path / pid).mkdir()
        (tmp_path / pid / 'config.json').write_text(json.dumps(cfg))
    client = api.as_user(seed.user('root', role='admin'))
    client.dir = tmp_path
    return client


def _shown(client, pid):
    r = client.get(f'/api/plugins/{pid}/config')
    assert r.status_code == 200, r.get_data(as_text=True)
    return json.loads(r.get_json()['config'])


def _stored(client, pid):
    return json.loads((client.dir / pid / 'config.json').read_text())


def test_the_editor_shows_no_credential(admin):
    assert _shown(admin, 'status_page') == {'auth_key': '********', 'page_title': 'System Status',
                                            'refresh_interval': 30}
    shown = _shown(admin, 'notifications')
    assert shown['ntfy_token'] == '********'
    tg, dc = shown['apprise_urls']
    assert re.fullmatch(r'tgram://\*{8}#[0-9a-f]{32}', tg) and re.fullmatch(r'discord://\*{8}#[0-9a-f]{32}', dc)
    assert shown['ntfy_topic'] == 'ops' and shown['ntfy_priority_map'] == {'critical': 'max'}


def test_saving_what_the_editor_showed_keeps_the_credentials(admin):
    shown = _shown(admin, 'notifications')
    shown['ntfy_topic'] = 'ops-2'
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps(shown)})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin, 'notifications') == dict(NOTIFY, ntfy_topic='ops-2')

    shown = _shown(admin, 'status_page')
    shown['refresh_interval'] = 60
    admin.put('/api/plugins/status_page/config', json={'config': json.dumps(shown)})
    assert _stored(admin, 'status_page') == dict(STATUS, refresh_interval=60)


def test_a_new_value_is_saved_and_a_masked_one_that_names_nothing_is_refused(admin):
    shown = _shown(admin, 'notifications')
    shown['ntfy_token'] = 'tk_new'
    shown['apprise_urls'] = ['mailto://********', 'tgram://********', 'gotify://host/tok']
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps(shown)})
    # a mask without the handle the editor gave its entry names no stored url: the save
    # neither writes it nor drops what is stored
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert r.get_json()['fields'] == ['apprise_urls[0]', 'apprise_urls[1]']
    assert _stored(admin, 'notifications') == NOTIFY

    shown['apprise_urls'] = ['gotify://host/tok']
    admin.put('/api/plugins/notifications/config', json={'config': json.dumps(shown)})
    stored = _stored(admin, 'notifications')
    assert stored['ntfy_token'] == 'tk_new' and stored['apprise_urls'] == ['gotify://host/tok']


def test_an_unchanged_file_without_a_mask_is_written_as_sent(admin):
    raw = '{\n  "page_title": "Status",\n  "auth_key": ""\n}'
    admin.put('/api/plugins/status_page/config', json={'config': raw})
    assert (admin.dir / 'status_page' / 'config.json').read_text() == raw


def test_the_file_is_the_owners_alone(admin):
    path = admin.dir / 'status_page' / 'config.json'
    os.chmod(path, 0o644)
    admin.put('/api/plugins/status_page/config', json={'config': json.dumps(STATUS)})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_file_that_does_not_parse_is_not_shown(admin):
    (admin.dir / 'status_page' / 'config.json').write_text('{"auth_key": "sp-9c2d71f0e4",')
    r = admin.get('/api/plugins/status_page/config')
    assert r.status_code == 200 and 'sp-9c2d71f0e4' not in r.get_data(as_text=True)
