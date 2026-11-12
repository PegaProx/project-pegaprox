"""A masked value in the plugin config editor comes back as the stored value it stood for.

The editor put a masked list entry back by its place: deleting the first of two telegram
urls kept the first one and lost the second, and deleting the first of a telegram and a
discord url lost both. Each masked entry of a list now carries a handle of its own, and a
save finds the stored entry by it wherever it sits. A handle holds in the list and the
plugin it was read from only and until the file is written again, and whether it finds
its entry does not depend on how many copies of the value are stored. A secret-named key
masks everything below it, lists of objects are masked and put back entry by entry, and a
mask that stands for nothing stored is refused instead of written. A config nested too
deeply to go through is refused instead of ending in a 500. MK Nov 2026
"""
import hashlib
import hmac
import json
import re
import types

import pytest

import pegaprox.api.plugins as plugins_api

BOT_A = 'tgram://111111:AAH-bot-a-0f3/987654'
BOT_B = 'tgram://222222:AAH-bot-b-7c1/987654'
DISCORD = 'discord://112233/webhook-token-c4e1'
HANDLE = re.compile(r'^[a-z]+://\*{8}#[0-9a-f]{32}$')

DEEP = {
    'tokens': {'slack': 'xoxb-slack-51e0', 'teams': {'bot': 'teams-bot-9a2d'}},
    'api_keys': [{'name': 'ci', 'secret': 'ci-secret-77f1'}],
    'targets': [{'name': 'ops', 'url': 'https://ops.example', 'token': 'tk-ops-3b8e'},
                {'name': 'dev', 'url': 'https://dev.example', 'token': 'tk-dev-c90a'}],
    'title': 'Alerts',
}
SECRETS = ('AAH-bot', 'webhook-token', 'xoxb-slack', 'teams-bot', 'ci-secret', 'tk-ops', 'tk-dev')


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    (tmp_path / 'demo').mkdir()
    client = api.as_user(seed.user('root', role='admin'))
    client.dir = tmp_path
    return client


def _store(client, cfg):
    (client.dir / 'demo' / 'config.json').write_text(json.dumps(cfg))


def _stored(client):
    return json.loads((client.dir / 'demo' / 'config.json').read_text())


def _shown(client):
    r = client.get('/api/plugins/demo/config')
    assert r.status_code == 200, r.get_data(as_text=True)
    text = r.get_json()['config']
    for s in SECRETS:
        assert s not in text, text
    return json.loads(text)


def _save(client, cfg):
    return client.put('/api/plugins/demo/config', json={'config': json.dumps(cfg)})


def test_each_entry_of_a_list_gets_a_handle_of_its_own(admin):
    _store(admin, {'apprise_urls': [BOT_A, BOT_B, DISCORD], 'auth_key': 'sp-9c2d71f0e4'})
    shown = _shown(admin)
    urls = shown['apprise_urls']
    assert all(HANDLE.match(u) for u in urls), urls
    assert urls[0].startswith('tgram://') and urls[2].startswith('discord://')
    assert len(set(urls)) == 3
    # the handle is keyed: the plain hash of the url is not what is shown
    assert hashlib.sha256(BOT_A.encode()).hexdigest()[:8] not in urls[0]
    # a value of its own keeps the plain mask
    assert shown['auth_key'] == '********'
    # the next read shows new handles, and the ones shown before still find their urls
    again = _shown(admin)['apprise_urls']
    assert not set(again) & set(urls)
    assert _save(admin, dict(shown, apprise_urls=urls[::-1])).status_code == 200
    assert _stored(admin)['apprise_urls'] == [DISCORD, BOT_B, BOT_A]


def test_a_typed_copy_of_a_stored_value_never_shows_its_handle(admin):
    _store(admin, {'apprise_urls': [BOT_A]})
    handle = _shown(admin)['apprise_urls'][0]
    guesses = ['tgram://111111:AAH-bot-a-0f2/987654', BOT_A, 'tgram://111111:AAH-bot-a-0f4/987654']
    assert _save(admin, {'apprise_urls': [handle] + guesses}).status_code == 200
    shown = _shown(admin)['apprise_urls']
    # each handle is new, so none of them tells which guess holds the stored value
    assert len(set(shown)) == 4 and handle not in shown


def test_deleting_the_first_of_two_bots_keeps_the_second(admin):
    _store(admin, {'apprise_urls': [BOT_A, BOT_B]})
    shown = _shown(admin)
    shown['apprise_urls'] = shown['apprise_urls'][1:]
    assert _save(admin, shown).status_code == 200
    assert _stored(admin)['apprise_urls'] == [BOT_B]


def test_deleting_the_first_of_two_services_keeps_the_other(admin):
    _store(admin, {'apprise_urls': [BOT_A, DISCORD]})
    shown = _shown(admin)
    shown['apprise_urls'] = shown['apprise_urls'][1:]
    assert _save(admin, shown).status_code == 200
    assert _stored(admin)['apprise_urls'] == [DISCORD]


def test_reordered_and_added_entries_keep_their_own_values(admin):
    _store(admin, {'apprise_urls': [BOT_A, BOT_B, DISCORD]})
    shown = _shown(admin)
    shown['apprise_urls'] = ['gotify://host/new'] + shown['apprise_urls'][::-1]
    assert _save(admin, shown).status_code == 200
    assert _stored(admin)['apprise_urls'] == ['gotify://host/new', DISCORD, BOT_B, BOT_A]


@pytest.mark.parametrize('extra', [
    'tgram://********#0000000000000000deadbeefdeadbeef',    # a handle no stored entry has
    'tgram://********',                     # an editor opened before the handles
])
def test_a_mask_that_names_no_stored_entry_is_refused(admin, extra):
    _store(admin, {'apprise_urls': [BOT_A, BOT_B]})
    shown = _shown(admin)
    shown['apprise_urls'] = shown['apprise_urls'][1:] + [extra]
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert r.get_json()['fields'] == ['apprise_urls[1]']
    assert _stored(admin) == {'apprise_urls': [BOT_A, BOT_B]}


def test_a_handle_from_before_the_value_changed_is_refused(admin):
    _store(admin, {'apprise_urls': [BOT_A]})
    stale = _shown(admin)
    _store(admin, {'apprise_urls': [BOT_B]})    # saved from another tab meanwhile
    r = _save(admin, stale)
    assert r.status_code == 400 and r.get_json()['fields'] == ['apprise_urls[0]']
    assert _stored(admin) == {'apprise_urls': [BOT_B]}


def test_everything_below_a_secret_name_is_masked(admin):
    _store(admin, DEEP)
    shown = _shown(admin)
    assert shown['tokens'] == {'slack': '********', 'teams': {'bot': '********'}}
    # an entry of a secret list keeps its name, so it can be told from the others
    assert shown['api_keys'] == [{'name': 'ci', 'secret': '********'}]
    # an object list under a plain name shows what is no credential
    assert [(t['name'], t['url'], t['token']) for t in shown['targets']] == [
        ('ops', 'https://ops.example', '********'), ('dev', 'https://dev.example', '********')]
    assert shown['title'] == 'Alerts'


NAMED = {
    'smtp_pass': 'zz-smtp', 'pwd': 'zz-pwd', 'smtpPw': 'zz-camel', 'mqtt': {'pass': 'zz-mqtt'},
    'slack_webhook': 'https://hooks.slack.com/services/T/B/zz-slack', 'webhook_url': 'https://hooks.example/zz-hook',
    'credentials': {'user': 'zz-user', 'pw': 'zz-cred'}, 'auth': 'Basic zz-basic', 'authorization': 'Bearer zz-auth',
    'dsn': 'postgres://u:zz-dsn@db/x', 'bearer': 'zz-bearer', 'session_cookie': 'zz-cookie',
    'api_key': 12345678, 'pin_secret': 987654.5, 'tokens': [11119999, 'zz-tok'],
}


def test_every_name_of_a_credential_is_masked_numbers_too(admin):
    _store(admin, NAMED)
    text = admin.get('/api/plugins/demo/config').get_json()['config']
    for v in ('zz-', '12345678', '987654', '11119999'):
        assert v not in text, text
    shown = json.loads(text)
    assert shown['slack_webhook'] == 'https://********' and shown['dsn'] == 'postgres://********'
    assert shown['api_key'] == '********' and shown['pin_secret'] == '********'
    assert all(re.fullmatch(r'\*{8}#[0-9a-f]{32}', t) for t in shown['tokens'])
    # and the save puts each of them back with its type
    assert _save(admin, dict(shown, tokens=shown['tokens'][::-1])).status_code == 200
    assert _stored(admin) == dict(NAMED, tokens=['zz-tok', 11119999])


def test_an_address_and_a_plain_setting_show_as_they_are(admin):
    cfg = {'auth_url': 'https://idp.example/authorize', 'auth_server': 'idp.example', 'smtp_port': 25,
           'passive_port': 21000, 'pass_host': 'mx.example', 'api_base': 'https://api.example/v2',
           'author': 'ops team', 'keep_days': 7, 'allow_password_change': True}
    _store(admin, cfg)
    assert _shown(admin) == cfg


# a secret word keeps a name masked whatever it ends on
SECRET_ADDRESSES = ('token_url', 'bot_token_url', 'push_token_url', 'secret_url', 'api_key_url', 'key_url',
                    'password_url', 'token_endpoint', 'token_uri', 'private_key_url', 'key_server',
                    'secret_host', 'api_key_host', 'passWordUrl')


def test_a_name_with_a_secret_word_stays_masked_where_it_ends_on_an_address(admin):
    cfg = {n: f'https://idp.example/{n}/zz-{i}' for i, n in enumerate(SECRET_ADDRESSES)}
    cfg['bot_token_url'] = 'https://api.example/bot123:zz-bot/send'
    _store(admin, cfg)
    text = admin.get('/api/plugins/demo/config').get_json()['config']
    assert 'zz-' not in text and 'idp.example' not in text, text
    shown = json.loads(text)
    assert shown == {n: 'https://********' for n in SECRET_ADDRESSES}
    # each mask comes back as the stored value, and a value typed over it is taken
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == cfg
    assert _save(admin, dict(shown, token_url='https://idp.example/new')).status_code == 200
    assert _stored(admin) == dict(cfg, token_url='https://idp.example/new')


def test_saving_what_the_editor_showed_keeps_every_value(admin):
    _store(admin, DEEP)
    shown = _shown(admin)
    shown['title'] = 'Alerts 2'
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin) == dict(DEEP, title='Alerts 2')


def test_an_object_entry_is_found_by_its_name(admin):
    _store(admin, DEEP)
    shown = _shown(admin)
    shown['targets'] = shown['targets'][1:]
    assert _save(admin, shown).status_code == 200
    assert _stored(admin)['targets'] == [DEEP['targets'][1]]


def test_an_object_entry_that_cannot_be_told_apart_is_refused(admin):
    cfg = dict(DEEP, targets=[{'url': 'https://ops.example', 'token': 'tk-ops-3b8e'},
                              {'url': 'https://dev.example', 'token': 'tk-dev-c90a'}])
    _store(admin, cfg)
    shown = _shown(admin)
    shown['targets'] = shown['targets'][1:]
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert r.get_json()['fields'] == ['targets[0].token']
    assert _stored(admin) == cfg


@pytest.mark.parametrize('ids', [('a', 'a'), (True, 1), (1, 1)])
def test_two_entries_of_one_name_save_as_the_editor_showed_them(admin, ids):
    cfg = {'targets': [{'name': ids[0], 'token': 'T1-first'}, {'name': ids[1], 'token': 'T2-second'}]}
    _store(admin, cfg)
    shown = _shown(admin)
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin) == cfg
    # and one of them deleted cannot be told from the other
    if ids[0] == ids[1] and type(ids[0]) is type(ids[1]):
        r = _save(admin, {'targets': shown['targets'][1:]})
        assert r.status_code == 400 and r.get_json()['fields'] == ['targets[0].token']


def test_a_stored_value_that_holds_the_mask_saves_as_it_was(admin):
    cfg = {'banner': '********************', 'note': '********', 'list': ['********'],
           'token': '********', 'apprise_urls': ['tgram://********']}
    _store(admin, cfg)
    shown = _shown(admin)
    assert shown['banner'] == cfg['banner'] and shown['note'] == '********'
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == cfg


@pytest.mark.parametrize('cfg', [
    {'title': 'x', 'auth': {'hint': 'tgram://********#0badf00d'}},
    {'token': '********'},
    {'token': 'abc********'},
    {'db_url': 'postgres://********@db.example/x'},
])
def test_a_mask_that_stands_for_nothing_stored_is_never_written(admin, cfg):
    _store(admin, {'title': 'before'})
    r = _save(admin, cfg)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert _stored(admin) == {'title': 'before'}


@pytest.mark.parametrize('cfg', [{'note': '********'}, ['********'], {'list': ['x ******** y']}])
def test_a_mask_typed_into_a_plain_field_is_saved_as_typed(admin, cfg):
    # the editor masks no plain field without a login, so this one stands for nothing stored
    _store(admin, {'title': 'before'})
    assert _save(admin, cfg).status_code == 200
    assert _stored(admin) == cfg


def test_a_config_that_is_a_list_is_masked_and_put_back(admin):
    cfg = [{'name': 'ops', 'token': 'tk-ops-3b8e'}, {'name': 'dev', 'token': 'tk-dev-c90a'}]
    _store(admin, cfg)
    shown = _shown(admin)
    assert shown == [{'name': 'ops', 'token': '********'}, {'name': 'dev', 'token': '********'}]
    assert _save(admin, shown[::-1]).status_code == 200
    assert _stored(admin) == cfg[::-1]


def test_a_config_that_is_a_number_reads_and_saves(admin):
    _store(admin, 42)
    assert _shown(admin) == 42
    assert _save(admin, 43).status_code == 200
    assert _stored(admin) == 43


def test_equal_values_in_one_list_show_handles_of_their_own(admin):
    _store(admin, {'apprise_urls': [BOT_A, BOT_A, BOT_B]})
    shown = _shown(admin)['apprise_urls']
    assert len(set(shown)) == 3
    assert _save(admin, {'apprise_urls': shown[1:]}).status_code == 200
    assert _stored(admin)['apprise_urls'] == [BOT_A, BOT_B]


def test_a_save_goes_through_a_long_list_once(admin, monkeypatch):
    urls = [f'tgram://{i}:AAH-bot-{i}/1' for i in range(300)]
    _store(admin, {'apprise_urls': urls})
    shown = _shown(admin)['apprise_urls']
    calls = []
    monkeypatch.setattr(plugins_api, 'hmac', types.SimpleNamespace(
        new=lambda *a, **kw: calls.append(1) or hmac.new(*a, **kw), compare_digest=hmac.compare_digest))
    # one print for each stored entry and one pad for each handle
    assert _save(admin, {'apprise_urls': shown[::-1]}).status_code == 200
    assert _stored(admin)['apprise_urls'] == urls[::-1] and len(calls) <= 2 * len(urls)
    # a forged handle costs its pad and nothing more
    shown = _shown(admin)['apprise_urls']
    calls.clear()
    forged = [f'tgram://********#{i:016x}{"0" * 16}' for i in range(300)]
    assert _save(admin, {'apprise_urls': forged + shown}).status_code == 400
    assert len(calls) <= 3 * len(urls)


def _guess_then_an_old_handle(admin, guess):
    _store(admin, {'apprise_urls': [BOT_A]})
    h = _shown(admin)['apprise_urls'][0]
    assert _save(admin, {'apprise_urls': [h, h]}).status_code == 200
    a0, a1 = _shown(admin)['apprise_urls']
    assert _save(admin, {'apprise_urls': [a0, guess, BOT_B]}).status_code == 200
    first = _save(admin, {'apprise_urls': [a0, a1]})
    assert _save(admin, {'apprise_urls': [guess, 'tgram://333333:AAH-bot-c/1']}).status_code == 200
    second = _save(admin, {'apprise_urls': [h]})
    return (first.status_code, first.get_json().get('fields'),
            second.status_code, second.get_json().get('fields'), _stored(admin))


def test_whether_a_guess_is_right_never_changes_the_answer(admin):
    wrong = _guess_then_an_old_handle(admin, 'tgram://111111:AAH-bot-a-0f2/987654')
    right = _guess_then_an_old_handle(admin, BOT_A)
    # a handle read before a write of the file finds nothing after it, whatever the write held
    assert wrong[:4] == right[:4] == (400, ['apprise_urls[0]', 'apprise_urls[1]'], 400, ['apprise_urls[0]'])
    assert right[4] == {'apprise_urls': [BOT_A, 'tgram://333333:AAH-bot-c/1']}


def test_whether_a_guess_is_right_never_changes_the_answer_in_a_list_of_objects(admin):
    answers = []
    for guess in ('tk-a-guess', 'tk-a-51e0'):
        _store(admin, {'targets': [{'name': 'a', 'tokens': ['tk-a-51e0']}]})
        h = _shown(admin)['targets'][0]['tokens'][0]
        r = _save(admin, {'targets': [{'name': 'b', 'tokens': [guess]}, {'name': 'a', 'tokens': [h]}]})
        assert r.status_code == 200, r.get_data(as_text=True)
        a = _shown(admin)['targets'][1]
        # the old handle put where the guess sits now
        r = _save(admin, {'targets': [{'name': 'b', 'tokens': [h]}, a]})
        answers.append((r.status_code, r.get_json().get('fields')))
    assert answers == [(400, ['targets[0].tokens[0]'])] * 2


@pytest.mark.parametrize('opening, closing, depth', [
    ('[', ']', 480), ('[', ']', 900), ('{"a": ', '}', 2000), ('[', ']', 20000), ('{"a": ', '}', 20000),
])
def test_a_config_nested_too_deeply_is_refused(admin, opening, closing, depth):
    _store(admin, {'token': 'tk-deep-1'})
    r = admin.put('/api/plugins/demo/config', json={
        'config': opening * depth + '"********"' + closing * depth})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED' or \
        r.get_json()['error'] == 'The config is nested too deeply'
    assert _stored(admin) == {'token': 'tk-deep-1'}


def _nested(opening, closing, depth, inner):
    return opening * depth + inner + closing * depth


@pytest.mark.parametrize('opening, closing', [('{"a": ', '}'), ('[', ']')])
def test_a_config_nested_deeper_than_the_editor_shows_still_opens(admin, opening, closing):
    """Such a file can be saved through the editor when no mask is in it, and the next GET
    ran out of stack in the mask and the indented dump: a 500, the editor could not load."""
    deep = _nested(opening, closing, 1000, '{"token": "tk-deep-2", "title": "far down"}')
    (admin.dir / 'demo' / 'config.json').write_text('{"token": "tk-deep-1", "title": "Alerts", "deep": %s}' % deep)
    r = admin.get('/api/plugins/demo/config')
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    text = r.get_json()['config']
    assert 'tk-deep-1' not in text and 'tk-deep-2' not in text and 'far down' not in text
    shown = json.loads(text)
    assert shown['token'] == '********' and shown['title'] == 'Alerts'
    # the first levels as they are, the rest masked whole
    levels, o = 0, shown['deep']
    while isinstance(o, (dict, list)):
        o, levels = (o['a'] if isinstance(o, dict) else o[0]), levels + 1
    assert o == '********' and levels == plugins_api._CONFIG_SHOWN_DEPTH - 1, (o, levels)


def test_a_config_nested_deeper_than_the_parser_goes_opens_empty(admin):
    """Like a file that does not parse: the editor starts from an empty object."""
    (admin.dir / 'demo' / 'config.json').write_text(_nested('[', ']', 20000, '"tk-deep-1"'))
    r = admin.get('/api/plugins/demo/config')
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    assert r.get_json()['config'] == ''


def test_saving_what_the_editor_showed_of_a_config_that_deep_is_refused(admin):
    """A mask that stands for a whole object is not put back: the save would write the mask
    in its place."""
    deep = _nested('{"a": ', '}', 200, '{"title": "far down"}')
    stored = '{"token": "tk-deep-1", "title": "Alerts", "deep": %s}' % deep
    (admin.dir / 'demo' / 'config.json').write_text(stored)
    shown = json.loads(admin.get('/api/plugins/demo/config').get_json()['config'])
    shown['title'] = 'Alerts 2'
    r = admin.put('/api/plugins/demo/config', json={'config': json.dumps(shown)})
    assert r.status_code == 400 and r.get_json()['error'] == 'The config is nested too deeply', r.get_json()
    assert (admin.dir / 'demo' / 'config.json').read_text() == stored


@pytest.mark.parametrize('same', [False, True], ids=['other value', 'same value'])
def test_a_handle_holds_only_in_the_list_it_was_read_from(admin, same):
    cfg = {'targets': [{'name': 'a', 'tokens': ['tk-a-51e0']},
                       {'name': 'b', 'tokens': ['tk-a-51e0' if same else 'tk-b-guess']}]}
    _store(admin, cfg)
    shown = _shown(admin)
    # the entries put in another order keep their own lists
    assert _save(admin, dict(shown, targets=shown['targets'][::-1])).status_code == 200
    assert _stored(admin) == {'targets': cfg['targets'][::-1]}
    shown = _shown(admin)
    b, a = shown['targets']
    b['tokens'] = list(a['tokens'])
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['targets[0].tokens[0]'], r.get_data(as_text=True)
    assert _stored(admin) == {'targets': cfg['targets'][::-1]}


def test_a_handle_holds_only_for_the_plugin_it_was_read_from(admin):
    _store(admin, {'apprise_urls': [BOT_A]})
    (admin.dir / 'other').mkdir()
    (admin.dir / 'other' / 'config.json').write_text(json.dumps({'apprise_urls': [BOT_A]}))
    h = _shown(admin)['apprise_urls'][0]
    r = admin.put('/api/plugins/other/config', json={'config': json.dumps({'apprise_urls': [h]})})
    assert r.status_code == 400 and r.get_json()['fields'] == ['apprise_urls[0]']
    assert json.loads((admin.dir / 'other' / 'config.json').read_text()) == {'apprise_urls': [BOT_A]}


def test_the_entries_of_a_secret_list_keep_their_names_and_can_be_deleted(admin):
    cfg = {'credentials': [{'name': 'ops', 'user': 'svc-ops', 'password': 'zz-ops'},
                           {'label': 'dev', 'user': 'svc-dev', 'password': 'zz-dev'},
                           {'id': 7, 'user': 'svc-ci', 'password': 'zz-ci', 'note': {'name': 'zz-note'}}]}
    _store(admin, cfg)
    text = admin.get('/api/plugins/demo/config').get_json()['config']
    assert 'zz-' not in text and 'svc-' not in text, text
    shown = json.loads(text)
    assert shown['credentials'] == [{'name': 'ops', 'user': '********', 'password': '********'},
                                    {'label': 'dev', 'user': '********', 'password': '********'},
                                    {'id': 7, 'user': '********', 'password': '********',
                                     'note': {'name': '********'}}]
    r = _save(admin, {'credentials': shown['credentials'][1:]})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin) == {'credentials': cfg['credentials'][1:]}


def test_an_id_or_label_that_is_a_float_stays_in_clear(admin):
    cfg = {'credentials': [{'label': 1.5, 'user': 'svc-a', 'password': 'zz-a'}, {'id': 2.0, 'password': 'zz-b'}]}
    _store(admin, cfg)
    shown = _shown(admin)
    assert shown['credentials'] == [{'label': 1.5, 'user': '********', 'password': '********'},
                                    {'id': 2.0, 'password': '********'}]
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == cfg
