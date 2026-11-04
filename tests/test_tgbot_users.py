# -*- coding: utf-8 -*-
"""Telegram bot: PegaProx's own users.

The first half drives the bot's screens against a stand-in for PegaProx; the second half
sends the bot's client into the real PegaProx app, so the permission checks that matter
are PegaProx's own."""
import copy

import pytest

from tgbot.bot import Bot
from tgbot.config import Config
from tgbot.pegaprox_client import ApiError, PegaProx
from tgbot.store import Store

TOKEN = 'pgx_ab12_' + 'x' * 43
UID = 4242

PANEL = [{'username': 'nikita', 'role': 'admin', 'enabled': True, 'tenant_id': 'default', 'auth_source': 'local'},
         {'username': 'olga', 'role': 'viewer', 'enabled': True, 'tenant_id': 'default', 'auth_source': 'local',
          'totp_enabled': True}]


class FakeTG:
    def __init__(self):
        self.sent, self.edited, self.deleted = [], [], []

    def send(self, chat, text, keyboard=None, **kw):
        self.sent.append((chat, text, keyboard))
        return {'message_id': len(self.sent)}

    def edit(self, chat, mid, text, keyboard=None):
        self.edited.append((chat, mid, text, keyboard))

    def delete(self, chat, mid):
        self.deleted.append((chat, mid))

    def answer(self, *a, **kw):
        pass

    def set_commands(self, commands):
        pass


class FakeApi:
    def __init__(self, token, calls, deny):
        self.calls, self.deny = calls, deny

    def _rec(self, name, *a):
        self.calls.append((name,) + a)
        if name in self.deny:
            raise ApiError(403, 'Permission denied')

    def me(self):
        return {'role': 'admin', 'permissions': []}

    def clusters(self):
        return [{'id': 'c1', 'name': 'pve', 'display_name': 'Home', 'connected': True}]

    def vms(self, cid):
        return [{'vmid': 101, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'}]

    def panel_users(self):
        self._rec('panel_users')
        return copy.deepcopy(PANEL)

    def panel_roles(self):
        return [{'id': 'admin', 'name': 'Admin'}, {'id': 'user', 'name': 'User'}, {'id': 'viewer', 'name': 'Viewer'}]

    def create_panel_user(self, username, password, role, display_name='', email=''):
        self._rec('create_panel_user', username, password, role)

    def update_panel_user(self, username, fields):
        self._rec('update_panel_user', username, fields)

    def set_panel_password(self, username, password):
        self._rec('set_panel_password', username, password)

    def reset_panel_2fa(self, username):
        self._rec('reset_panel_2fa', username)

    def delete_panel_user(self, username):
        self._rec('delete_panel_user', username)


@pytest.fixture
def env(tmp_path):
    cfg = Config(bot_token='1:x', data_dir=str(tmp_path / 'data'), alert_poll=0)
    tg, calls, deny = FakeTG(), [], set()
    bot = Bot(cfg, tg, Store(cfg.data_dir), api_factory=lambda t: FakeApi(t, calls, deny))
    bot.store.link(UID, TOKEN)
    return bot, tg, calls, deny


def msg(text, chat_type='private', mid=10):
    return {'message': {'message_id': mid, 'from': {'id': UID}, 'chat': {'id': UID, 'type': chat_type}, 'text': text}}


def press(bot, button, chat_type='private'):
    bot.handle_update({'callback_query': {'id': 'q', 'from': {'id': UID}, 'data': button['callback_data'],
                                          'message': {'message_id': 99, 'chat': {'id': UID, 'type': chat_type}}}})


def tap(bot, tg, label):
    _text, kb = current(tg)
    for row in kb or []:
        for b in row:
            if label in b['text']:
                press(bot, b)
                return
    raise AssertionError(f'no button {label!r} in {[b["text"] for row in kb or [] for b in row]}')


def current(tg):
    """The screen the user looks at now: the last thing the bot sent or edited."""
    return tg.last


@pytest.fixture(autouse=True)
def _track(monkeypatch):
    orig_send, orig_edit = FakeTG.send, FakeTG.edit

    def send(self, chat, text, keyboard=None, **kw):
        self.last = (text, keyboard)
        return orig_send(self, chat, text, keyboard, **kw)

    def edit(self, chat, mid, text, keyboard=None):
        self.last = (text, keyboard)
        return orig_edit(self, chat, mid, text, keyboard)

    monkeypatch.setattr(FakeTG, 'send', send)
    monkeypatch.setattr(FakeTG, 'edit', edit)


# --- PegaProx ----------------------------------------------------------------------------

def open_panel(bot, tg):
    bot.handle_update(msg('/users'))


def test_create_a_panel_user(env):
    bot, tg, calls, _ = env
    open_panel(bot, tg)
    tap(bot, tg, 'Create')
    bot.handle_update(msg('Ivan'))
    tap(bot, tg, 'Viewer')
    bot.handle_update(msg('Passw0rd!', mid=31))
    assert (UID, 31) in tg.deleted
    assert ('create_panel_user', 'ivan', 'Passw0rd!', 'viewer') in calls


def test_a_password_sent_in_a_group_is_deleted_and_not_used(env):
    bot, tg, calls, _ = env
    open_panel(bot, tg)
    tap(bot, tg, 'Create')
    bot.handle_update(msg('ivan'))
    tap(bot, tg, 'Viewer')
    bot.handle_update(msg('Passw0rd!', chat_type='group', mid=32))
    assert (UID, 32) in tg.deleted
    assert not any(c[0] == 'create_panel_user' for c in calls)
    assert 'private chat' in tg.sent[-1][1]


def test_user_management_stays_out_of_groups(env):
    bot, tg, calls, _ = env
    bot.handle_update(msg('/users', chat_type='group'))
    assert 'private chat' in tg.sent[-1][1]
    assert not any(c[0] == 'panel_users' for c in calls)


def test_change_role_disable_and_reset_2fa(env):
    bot, tg, calls, _ = env
    open_panel(bot, tg)
    tap(bot, tg, 'olga')
    tap(bot, tg, 'Role')
    tap(bot, tg, 'User')
    assert ('update_panel_user', 'olga', {'role': 'user'}) in calls
    tap(bot, tg, 'Disable')
    assert not any(c[0] == 'update_panel_user' and 'enabled' in c[2] for c in calls)
    tap(bot, tg, 'Yes, disable')
    assert ('update_panel_user', 'olga', {'enabled': False}) in calls
    tap(bot, tg, 'Reset 2FA')
    tap(bot, tg, 'Yes, reset')
    assert ('reset_panel_2fa', 'olga') in calls


def test_panel_refusal_names_the_permission(env):
    bot, tg, _, deny = env
    deny.add('panel_users')
    open_panel(bot, tg)
    assert 'admin.users' in current(tg)[0]


# --- against the real PegaProx ------------------------------------------------------------

class _Resp:
    def __init__(self, r):
        self.status_code = r.status_code
        self._r = r

    def json(self):
        data = self._r.get_json(silent=True)
        if data is None:
            raise ValueError('no json')
        return data


class _FlaskSession:
    def __init__(self, client):
        self.client = client

    def request(self, method, url, json=None, params=None, headers=None, **_kw):
        path = url.split('://', 1)[1].split('/', 1)[1]
        return _Resp(self.client.open('/' + path, method=method, json=json, query_string=params,
                                      headers=headers, base_url='http://localhost'))


def _client(api, token):
    return PegaProx('http://localhost', token, session=_FlaskSession(api.app.test_client()))


def test_panel_users_through_the_bot_client(api, seed):
    from pegaprox.utils.auth import create_api_token
    seed.user('nikita', role='admin')
    token = create_api_token('nikita', 'telegram')['token']
    c = _client(api, token)
    c.create_panel_user('ivan', 'Passw0rd!x', 'viewer')
    assert any(u['username'] == 'ivan' and u['role'] == 'viewer' for u in c.panel_users())
    c.update_panel_user('ivan', {'role': 'user'})
    assert next(u for u in c.panel_users() if u['username'] == 'ivan')['role'] == 'user'
    c.delete_panel_user('ivan')
    assert not any(u['username'] == 'ivan' for u in c.panel_users())


def test_a_viewer_token_cannot_create_panel_users(api, seed):
    from pegaprox.utils.auth import create_api_token
    seed.user('nikita', role='admin')
    token = create_api_token('nikita', 'telegram', role='viewer')['token']
    with pytest.raises(ApiError) as err:
        _client(api, token).create_panel_user('ivan', 'Passw0rd!x', 'admin')
    assert err.value.status == 403
