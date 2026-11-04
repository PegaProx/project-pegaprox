# -*- coding: utf-8 -*-
"""Telegram bot (tgbot/): linking, permissions passed through, buttons, alerts."""
import os
import re
import stat

import pytest

from tgbot.bot import Bot
from tgbot.config import Config
from tgbot.pegaprox_client import ApiError, PegaProx
from tgbot.store import Store

TOKEN = 'pgx_ab12_' + 'x' * 43
UID = 4242


class FakeTG:
    def __init__(self):
        self.sent, self.edited, self.deleted, self.answers = [], [], [], []

    def send(self, chat, text, keyboard=None, **kw):
        self.sent.append((chat, text, keyboard))
        return {'message_id': len(self.sent)}

    def edit(self, chat, mid, text, keyboard=None):
        self.edited.append((chat, mid, text, keyboard))

    def delete(self, chat, mid):
        self.deleted.append((chat, mid))

    def answer(self, cid, text=None, alert=False):
        self.answers.append((cid, text))

    def set_commands(self, commands):
        pass



class FakeApi:
    """Stands in for PegaProx: records calls, answers like the real endpoints."""

    def __init__(self, token, calls, deny=()):
        self.token = token
        self.calls = calls
        self.deny = deny

    def _rec(self, name, *a):
        self.calls.append((self.token, name) + a)
        if name in self.deny:
            raise ApiError(403, 'Permission denied: vm.power')

    def me(self):
        if self.token != TOKEN:
            raise ApiError(401, 'Invalid token')
        return {'role': 'user', 'effective_role': 'user', 'tenant_id': 'default', 'permissions': ['vm.view', 'vm.power']}

    def clusters(self):
        self._rec('clusters')
        return [{'id': 'c1', 'name': 'pve', 'display_name': 'Home', 'connected': True}]

    def nodes(self, cid):
        self._rec('nodes', cid)
        return [{'node': 'pve1', 'status': 'online', 'cpu': 0.1, 'maxcpu': 8, 'mem': 1, 'maxmem': 4},
                {'node': 'pve2', 'status': 'online', 'cpu': 0.2, 'maxcpu': 8, 'mem': 2, 'maxmem': 4}]

    def vms(self, cid):
        self._rec('vms', cid)
        return [{'vmid': 101, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
                {'vmid': 200, 'name': 'db', 'node': 'pve2', 'type': 'lxc', 'status': 'stopped'}]

    def search(self, q):
        self._rec('search', q)
        if len(q) < 2:
            raise ApiError(400, 'Search query must be at least 2 characters')
        hits = [{'type': 'vm' if x['type'] == 'qemu' else 'ct', 'cluster_id': 'c1', 'cluster_name': 'Home', **{
            k: x[k] for k in ('vmid', 'name', 'node', 'status')}} for x in self.vms('c1') if q in x['name']]
        return hits + [{'type': 'node', 'cluster_id': 'c1', 'cluster_name': 'Home', 'name': 'pve1'}]

    def vm_action(self, cid, node, vtype, vmid, action):
        self._rec('vm_action', cid, node, vtype, vmid, action)
        return {'task': 'UPID:pve1:0001'}

    def migrate(self, cid, node, vtype, vmid, target, online=True):
        self._rec('migrate', cid, node, vtype, vmid, target, online)
        return {'success': True}

    def active_alerts(self, cid):
        self._rec('active_alerts', cid)
        return [{'id': 7, 'severity': 'warning', 'message': 'CPU high', 'target_type': 'node',
                 'target_name': 'pve1', 'metric': 'cpu', 'current_value': 95, 'threshold': 90,
                 'operator': '>', 'triggered_at': '2026-11-01T10:00:00', 'acked_at': None, 'muted_until': None}]

    def ack_alert(self, cid, fid):
        self._rec('ack', cid, fid)
        return {'success': True}

    def create_snapshot(self, cid, node, vtype, vmid, name, description=''):
        self._rec('snapshot', cid, vmid, name)
        return {'message': 'ok'}


@pytest.fixture
def env(tmp_path):
    cfg = Config(bot_token='1:x', data_dir=str(tmp_path / 'data'), alert_poll=0)
    tg = FakeTG()
    calls = []
    deny = set()
    bot = Bot(cfg, tg, Store(cfg.data_dir), api_factory=lambda t: FakeApi(t, calls, deny))
    return bot, tg, calls, deny, cfg


def msg(text, uid=UID, chat_type='private', mid=10):
    return {'message': {'message_id': mid, 'from': {'id': uid, 'username': 'nik'},
                        'chat': {'id': uid, 'type': chat_type}, 'text': text}}


def press(bot, button, uid=UID):
    bot.handle_update({'callback_query': {'id': 'q', 'from': {'id': uid}, 'data': button['callback_data'],
                                          'message': {'message_id': 99, 'chat': {'id': uid}}}})


def buttons(kb):
    return [b for row in (kb or []) for b in row]


def find_button(kb, prefix):
    for b in buttons(kb):
        if b['text'].startswith(prefix) or prefix in b['text']:
            return b
    raise AssertionError(f'no button {prefix!r} in {[b["text"] for b in buttons(kb)]}')


def last_screen(tg):
    """The newest text+keyboard, whether it was sent or edited."""
    return (tg.edited[-1][2], tg.edited[-1][3]) if tg.edited else (tg.sent[-1][1], tg.sent[-1][2])


def link(bot, tg):
    bot.handle_update(msg(f'/login {TOKEN}'))
    tg.edited.clear()


def test_login_links_the_account_and_deletes_the_token_message(env):
    bot, tg, calls, _, cfg = env
    bot.handle_update(msg(f'/login {TOKEN}', mid=55))
    assert (UID, 55) in tg.deleted
    assert bot.store.token(UID) == TOKEN
    assert any('Account linked' in t for _, t, _ in tg.sent)
    # the token is not stored in clear text
    raw = open(os.path.join(cfg.data_dir, 'accounts.json'), encoding='utf-8').read()
    assert TOKEN not in raw
    for name in ('accounts.json', 'secret.key'):
        assert stat.S_IMODE(os.stat(os.path.join(cfg.data_dir, name)).st_mode) == 0o600


def test_a_wrong_token_is_refused(env):
    bot, tg, _, _, _ = env
    bot.handle_update(msg('/login pgx_ab12_' + 'y' * 43))
    assert bot.store.get(UID) is None
    assert 'did not accept the token' in tg.sent[-1][1]


def test_a_token_is_never_taken_in_a_group(env):
    bot, tg, _, _, _ = env
    bot.handle_update(msg(f'/login {TOKEN}', chat_type='group', mid=7))
    assert (UID, 7) in tg.deleted
    assert bot.store.get(UID) is None
    assert 'private chat' in tg.sent[-1][1]


def test_commands_need_a_linked_account(env):
    bot, tg, calls, _, _ = env
    bot.handle_update(msg('/menu'))
    assert 'Link your PegaProx account first' in tg.sent[-1][1]
    assert calls == []


def test_allowlist_keeps_strangers_out(env):
    bot, tg, calls, _, cfg = env
    cfg.allowed_ids = {1}
    bot.handle_update(msg(f'/login {TOKEN}'))
    assert bot.store.get(UID) is None
    assert 'Access to this bot is closed' in tg.sent[-1][1]


def test_menu_to_guest_action_uses_the_users_token(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/menu'))
    text, kb = last_screen(tg)
    press(bot, find_button(kb, 'Home'))
    press(bot, find_button(last_screen(tg)[1], 'VMs and CTs'))
    press(bot, find_button(last_screen(tg)[1], '101 web'))
    text, kb = last_screen(tg)
    assert 'web' in text and 'pve1' in text
    press(bot, find_button(kb, 'Reboot'))
    # a reboot asks first
    assert not any(c[1] == 'vm_action' for c in calls)
    press(bot, find_button(last_screen(tg)[1], 'Yes'))
    act = [c for c in calls if c[1] == 'vm_action']
    assert act == [(TOKEN, 'vm_action', 'c1', 'pve1', 'qemu', 101, 'reboot')]
    assert 'UPID:pve1:0001' in last_screen(tg)[0]


def test_a_refused_permission_is_shown_not_hidden(env):
    bot, tg, calls, deny, _ = env
    link(bot, tg)
    deny.add('vm_action')
    bot.handle_update(msg('/find db'))
    press(bot, find_button(tg.sent[-1][2], '200 db'))
    press(bot, find_button(last_screen(tg)[1], 'Start'))
    assert 'Permission denied' in last_screen(tg)[0]


def test_buttons_of_another_user_do_nothing(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/menu'))
    b = find_button(last_screen(tg)[1], 'Home')
    bot.store.link(777, TOKEN)
    n = len(calls)
    press(bot, b, uid=777)
    assert len(calls) == n
    assert tg.answers[-1][1] == 'This button has expired, open /menu'


def test_migration_goes_live_for_a_running_vm(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/find web'))
    press(bot, find_button(tg.sent[-1][2], '101 web'))
    press(bot, find_button(last_screen(tg)[1], 'Migrate'))
    press(bot, find_button(last_screen(tg)[1], 'pve2'))
    press(bot, find_button(last_screen(tg)[1], 'Migrate'))
    assert [c for c in calls if c[1] == 'migrate'] == [(TOKEN, 'migrate', 'c1', 'pve1', 'qemu', 101, 'pve2', True)]


def test_snapshot_name_typed_in_chat(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/find web'))
    press(bot, find_button(tg.sent[-1][2], '101 web'))
    g = None
    # straight to the "new snapshot" prompt
    for b in buttons(last_screen(tg)[1]):
        if 'Snapshots' in b['text']:
            g = bot.cb.get(b['callback_data'])[2]['g']
    bot.cb_snap_new(UID, UID, None, g)
    bot.handle_update(msg('bad name!'))
    assert 'Latin letters' in tg.sent[-1][1]
    bot.handle_update(msg('before_update'))
    assert [c for c in calls if c[1] == 'snapshot'] == [(TOKEN, 'snapshot', 'c1', 101, 'before_update')]


def test_new_alerts_are_sent_once(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    tg.sent.clear()
    bot.poll_alerts()
    bot.poll_alerts()
    alerts = [t for _, t, _ in tg.sent if t.startswith('🔔')]
    assert len(alerts) == 1 and 'CPU high' in alerts[0]
    press(bot, find_button(tg.sent[-1][2], 'Acknowledge'))
    assert (TOKEN, 'ack', 'c1', 7) in calls


def test_notify_off_stops_alerts(env):
    bot, tg, _, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/notify off'))
    tg.sent.clear()
    bot.poll_alerts()
    assert tg.sent == []


def test_raw_api_command_checks_its_input(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    bot.handle_update(msg('/api GET /etc/passwd'))
    assert 'Usage' in tg.sent[-1][1]


def test_client_sends_the_bearer_token():
    seen = {}

    class Resp:
        status_code = 403

        def json(self):
            return {'error': 'Permission denied'}

    class Session:
        def request(self, method, url, **kw):
            seen.update(method=method, url=url, headers=kw['headers'], redirects=kw['allow_redirects'])
            return Resp()

    api = PegaProx('https://pp:5000/', TOKEN, session=Session())
    with pytest.raises(ApiError) as err:
        api.vm_action('c 1', 'pve1', 'qemu', 101, 'start')
    assert err.value.status == 403 and err.value.message == 'Permission denied'
    assert seen['headers']['Authorization'] == f'Bearer {TOKEN}'
    assert seen['url'] == 'https://pp:5000/api/clusters/c%201/vms/pve1/qemu/101/start'
    assert seen['redirects'] is False


def test_config_from_env_file(tmp_path):
    p = tmp_path / 'bot.env'
    p.write_text('TG_BOT_TOKEN="1:abc"\nTG_ALLOWED_IDS=1, 2\nPEGAPROX_VERIFY_TLS=/etc/ca.pem\n', encoding='utf-8')
    cfg = Config.load(str(p), environ={})
    assert cfg.bot_token == '1:abc' and cfg.allowed_ids == {1, 2} and cfg.verify_tls == '/etc/ca.pem'
    with pytest.raises(SystemExit):
        Config.load(None, environ={})


def test_tls_is_verified_unless_pegaprox_is_on_this_host():
    assert Config.load(None, environ={'TG_BOT_TOKEN': '1:x'}).verify_tls is True
    assert Config.load(None, environ={'TG_BOT_TOKEN': '1:x', 'PEGAPROX_URL': 'https://pp.lan:5000'}).verify_tls is True
    for url in ('https://127.0.0.1:5000', 'https://localhost:5000', 'https://[::1]:5000'):
        cfg = Config.load(None, environ={'TG_BOT_TOKEN': '1:x', 'PEGAPROX_URL': url, 'PEGAPROX_VERIFY_TLS': 'false'})
        assert cfg.verify_tls is False
    # the token goes out with every call: no unverified TLS across a network
    with pytest.raises(SystemExit):
        Config.load(None, environ={'TG_BOT_TOKEN': '1:x', 'PEGAPROX_URL': 'https://10.0.0.5:5000',
                                   'PEGAPROX_VERIFY_TLS': 'false'})


def test_a_token_sent_by_a_stranger_is_deleted_too(env):
    bot, tg, calls, _, cfg = env
    cfg.allowed_ids = {1}
    bot.handle_update(msg(f'here it is {TOKEN}', mid=8))
    assert (UID, 8) in tg.deleted
    assert 'revoke that token' in tg.sent[-1][1]
    assert calls == []


def test_negative_alert_poll_is_refused():
    with pytest.raises(SystemExit):
        Config.load(None, environ={'TG_BOT_TOKEN': '1:x', 'TG_ALERT_POLL': '-5'})
    assert Config.load(None, environ={'TG_BOT_TOKEN': '1:x', 'TG_ALERT_POLL': '0'}).alert_poll == 0


def test_proxy_settings_in_the_env_file_reach_requests(tmp_path, monkeypatch):
    for k in ('HTTPS_PROXY', 'NO_PROXY', 'TG_BOT_TOKEN'):
        monkeypatch.delenv(k, raising=False)
    p = tmp_path / 'bot.env'
    p.write_text('TG_BOT_TOKEN=1:x\nHTTPS_PROXY=http://127.0.0.1:3128\nNO_PROXY=127.0.0.1\n', encoding='utf-8')
    Config.load(str(p))
    assert os.environ['HTTPS_PROXY'] == 'http://127.0.0.1:3128' and os.environ['NO_PROXY'] == '127.0.0.1'


def test_a_key_file_readable_by_others_is_refused(tmp_path):
    Store(str(tmp_path))
    os.chmod(tmp_path / 'secret.key', 0o644)
    with pytest.raises(SystemExit):
        Store(str(tmp_path))


def test_a_redirect_is_an_error_not_an_empty_answer():
    class Resp:
        status_code = 302

        def json(self):
            raise ValueError

    class Session:
        def request(self, method, url, **kw):
            return Resp()

    with pytest.raises(ApiError) as err:
        PegaProx('https://pp:5000', TOKEN, session=Session()).clusters()
    assert err.value.status == 302


def test_api_output_is_escaped_before_it_is_cut(env):
    bot, tg, _, _, _ = env
    link(bot, tg)
    bot.api = lambda uid: type('A', (), {'request': lambda self, *a, **k: {'x': '<&>' * 2000}})()
    bot.handle_update(msg('/api GET /api/clusters'))
    out = tg.sent[-1][1]
    assert out.startswith('<pre>') and out.endswith('</pre>') and '<&>' not in out
    body = out[len('<pre>'):-len('</pre>')]
    assert body.endswith('\n…') and len(body) <= 3802
    assert not re.search(r'&[a-z#0-9]*$', body[:-2])  # no half entity before the ellipsis


def test_find_uses_one_global_search(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    calls.clear()
    bot.handle_update(msg('/find web'))
    assert 'clusters' not in [c[1] for c in calls]
    assert 'Found: 1' in tg.sent[-1][1]
    assert find_button(tg.sent[-1][2], 'web')


def test_find_falls_back_when_search_refuses_the_query(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    calls.clear()
    bot.handle_update(msg('/find b'))
    assert 'clusters' in [c[1] for c in calls]
    assert 'Found: 2' in tg.sent[-1][1]


def test_an_alert_that_did_not_reach_telegram_is_sent_again(env):
    bot, tg, calls, _, _ = env
    link(bot, tg)
    real_send = tg.send
    tg.send = lambda *a, **k: None  # Telegram down
    bot.poll_alerts()
    tg.send = real_send
    before = len(tg.sent)
    bot.poll_alerts()
    assert len(tg.sent) == before + 1 and 'CPU high' in tg.sent[-1][1]


def test_an_alert_read_error_is_not_an_empty_list():
    class Resp:
        status_code = 200

        def json(self):
            return {'active_alerts': [], 'error': 'Alert operation failed'}

    class Session:
        def request(self, method, url, **kw):
            return Resp()

    with pytest.raises(ApiError):
        PegaProx('https://pp:5000', TOKEN, session=Session()).active_alerts('c1')


def test_a_bad_timestamp_is_escaped():
    from tgbot import views
    assert '<' not in views.when('<b>x</b>')
