# -*- coding: utf-8 -*-
"""The bot's client against the real PegaProx app: token auth, the CSRF gate on writes,
and the token owner's permissions deciding what Telegram may do."""
from pegaprox.utils.auth import create_api_token
from tgbot.pegaprox_client import ApiError, PegaProx


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
    """requests.Session look-alike that sends the bot's calls into the Flask test client."""

    def __init__(self, client):
        self.client = client

    def request(self, method, url, json=None, params=None, headers=None, **_kw):
        path = url.split('://', 1)[1].split('/', 1)[1]
        return _Resp(self.client.open('/' + path, method=method, json=json, query_string=params,
                                      headers=headers, base_url='http://localhost'))


def _client(api, token):
    return PegaProx('http://localhost', token, session=_FlaskSession(api.app.test_client()))


def _manager(api):
    m = api.make_fake_manager('c1', vm_action={'success': True, 'data': 'UPID:pve1:00001:start'})
    m.config.name = 'c1'
    return api.set_manager('c1', m)


def test_the_token_signs_the_bot_in_as_its_owner(api, seed):
    seed.user('nikita', role='admin')
    token = create_api_token('nikita', 'telegram')['token']
    me = _client(api, token).me()
    assert me['role'] == 'admin' and 'vm.start' in me['permissions']


def test_a_guest_action_from_telegram_passes_the_csrf_gate(api, seed):
    seed.user('nikita', role='admin')
    token = create_api_token('nikita', 'telegram')['token']
    m = _manager(api)
    res = _client(api, token).vm_action('c1', 'pve1', 'qemu', 101, 'start')
    assert res['data'] == 'UPID:pve1:00001:start'
    m.vm_action.assert_called_once()


def test_a_viewer_token_cannot_start_a_guest_from_telegram(api, seed):
    seed.user('nikita', role='admin')
    token = create_api_token('nikita', 'telegram', role='viewer')['token']
    m = _manager(api)
    try:
        _client(api, token).vm_action('c1', 'pve1', 'qemu', 101, 'start')
        raise AssertionError('a viewer token started a guest')
    except ApiError as err:
        assert err.status == 403
    m.vm_action.assert_not_called()


def test_a_revoked_token_is_refused(api, seed):
    seed.user('nikita', role='admin')
    try:
        _client(api, 'pgx_ab12_' + 'z' * 43).me()
        raise AssertionError('an unknown token was accepted')
    except ApiError as err:
        assert err.status == 401
