"""The push notification plugin sends nothing until a topic of the admin's own is set.

The config.json we shipped had ntfy switched on with the topic "pegaprox-test" on
ntfy.sh. Topics there are public, so the moment an admin enabled the plugin every alert
(its name, the guest or node, the message) went to a topic anyone can subscribe to. The
shipped file now has ntfy off and no topic, and since an update keeps config.json, the
old pair without a token counts as not set. MK Nov 2026
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT = {'alert_name': 'CPU high', 'severity': 'warning', 'metric': 'cpu',
         'message': 'vm-db01 on pve3 at 97%'}


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_quiet_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    sent = []
    monkeypatch.setattr(mod, '_send_ntfy', lambda alert, cfg: sent.append(cfg['ntfy_topic']) or (True, None))
    mod.sent = sent
    return mod


def _config(mod, **cfg):
    with open(os.path.join(mod.PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump(cfg, f)


def test_the_shipped_config_has_ntfy_off_and_no_topic():
    with open(os.path.join(ROOT, 'plugins', 'notifications', 'config.json')) as f:
        cfg = json.load(f)
    assert cfg['ntfy_enabled'] is False and cfg['ntfy_topic'] == ''
    assert cfg['apprise_enabled'] is False and cfg['apprise_urls'] == []


def test_the_shipped_file_sends_nothing(plugin):
    with open(os.path.join(ROOT, 'plugins', 'notifications', 'config.json')) as f:
        _config(plugin, **json.load(f))
    plugin._notification_handler(ALERT)
    assert plugin.sent == []


@pytest.mark.parametrize('url', ['https://ntfy.sh', 'https://ntfy.sh/', 'HTTPS://NTFY.SH', None])
def test_an_install_that_kept_the_old_example_sends_nothing(plugin, url):
    cfg = {'ntfy_enabled': True, 'ntfy_topic': 'pegaprox-test', 'ntfy_token': ''}
    if url:
        cfg['ntfy_url'] = url
    _config(plugin, **cfg)
    plugin._notification_handler(ALERT)
    assert plugin.sent == []


def test_the_test_button_says_why(plugin):
    _config(plugin, ntfy_enabled=True, ntfy_url='https://ntfy.sh', ntfy_topic='pegaprox-test')
    plugin._require_admin = lambda: None
    res = plugin._send_test()
    assert res['ntfy']['success'] is False and 'topic of your own' in res['ntfy']['error']
    assert plugin.sent == []


@pytest.mark.parametrize('cfg', [
    {'ntfy_url': 'https://ntfy.sh', 'ntfy_topic': 'acme-ops-7f3c'},
    {'ntfy_url': 'https://ntfy.acme.example', 'ntfy_topic': 'pegaprox-test'},
    {'ntfy_url': 'https://ntfy.sh', 'ntfy_topic': 'pegaprox-test', 'ntfy_token': 'tk_reserved'},
])
def test_a_topic_the_admin_set_is_sent_to(plugin, cfg):
    _config(plugin, ntfy_enabled=True, **cfg)
    plugin._notification_handler(ALERT)
    assert plugin.sent == [cfg['ntfy_topic']]
