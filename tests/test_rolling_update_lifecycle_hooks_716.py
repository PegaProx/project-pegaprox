"""#716 - fire a webhook around a rolling update so the on-call
monitoring can be muted for the duration.

The reporter's actual problem is not "no webhook", it is that a static maintenance
window has to be guessed in advance and then mutes nothing useful when the update
turns out to be a no-op. So the signal has to come from the run itself: one when it
starts, one when it ends, carrying the outcome.

No new credential store and no new URL to guard: the existing Alert Channels already
speak Slack, Discord, Teams, ntfy and plain JSON (which is what n8n wants), and they
are already gated by _guard_url. The run just picks the channels it should talk to.
"""
import ast
import inspect

import pytest


def _settings_src():
    import pegaprox.api.settings as s
    return inspect.getsource(s)


# --- the notifier ------------------------------------------------------------

def test_a_lifecycle_event_reaches_the_configured_channel(monkeypatch):
    from pegaprox.utils import webhooks
    sent = []
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, ids=None: sent.append((alert, ids)))
    webhooks.notify_lifecycle('rolling_update.started', 'Rolling update started',
                              'cluster Testi, 3 nodes', cluster_id='c1', channel_ids=['ch1'])
    assert len(sent) == 1, sent
    alert, ids = sent[0]
    assert ids == ['ch1']
    assert alert['event'] == 'rolling_update.started'
    assert alert['cluster_id'] == 'c1'
    # the Slack/Discord/Teams builders read these two; without them the message is blank
    assert alert['alert_name'] and alert['message']


def test_no_channels_means_no_traffic(monkeypatch):
    """Opt-in. An admin who never asked for this must not suddenly page their team."""
    from pegaprox.utils import webhooks
    sent = []
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, ids=None: sent.append(alert))
    webhooks.notify_lifecycle('x', 'y', 'z', cluster_id='c1', channel_ids=[])
    webhooks.notify_lifecycle('x', 'y', 'z', cluster_id='c1', channel_ids=None)
    assert sent == [], sent


def test_a_broken_webhook_cannot_take_down_the_caller(monkeypatch):
    """This runs inside a thread that evacuates VMs. It may not raise, ever."""
    from pegaprox.utils import webhooks

    def boom(*a, **k):
        raise RuntimeError('channel exploded')
    monkeypatch.setattr(webhooks, 'send_to_channels', boom)
    webhooks.notify_lifecycle('x', 'y', 'z', cluster_id='c1', channel_ids=['ch1'])


# --- the wiring into the run -------------------------------------------------

def test_the_run_announces_its_start_and_its_end():
    src = _settings_src()
    tree = ast.parse(src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'run_rolling_update':
            fn = node
    assert fn is not None, 'run_rolling_update not found'
    calls = [ast.unparse(n) for n in ast.walk(fn)
             if isinstance(n, ast.Call) and 'notify_lifecycle' in ast.unparse(n.func)]
    events = ' '.join(calls)
    assert 'rolling_update.started' in events, 'nothing fires when the run starts'
    assert 'rolling_update.finished' in events, 'nothing fires when the run ends'


def test_the_end_event_says_how_it_went():
    """Muting is only half of it - the un-mute has to know whether to shout."""
    src = _settings_src()
    window = src[src.index('def run_rolling_update'):]
    window = window[:window.index('import threading')]
    finished = window[window.index('rolling_update.finished'):][:700]
    for token in ('completed', 'failed'):
        assert token in finished, f'the finish event does not carry {token}: {finished[:200]}'


def test_the_failure_path_still_reports():
    """A run that dies on an exception is exactly when the on-call wants to hear.

    Walked as a tree, not as text: the function has several inner try/except blocks
    and a substring search after the first `except` would happily match the success
    call further down.
    """
    tree = ast.parse(_settings_src())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == 'run_rolling_update')
    outer = [n for n in fn.body if isinstance(n, ast.Try)]
    assert outer, 'run_rolling_update has no outer try'
    handlers = [h for t in outer for h in t.handlers]
    body = ' '.join(ast.unparse(h) for h in handlers)
    assert 'notify_lifecycle' in body, 'the outer exception handler is silent'
    assert 'critical' in body, 'a crashed run must not announce itself as info'


# --- the request contract ----------------------------------------------------

def test_the_channels_come_from_the_request_and_are_validated(api, seed):
    """Both bodies below answer 400 - the route rejects a nodeless cluster anyway -
    so the status alone proves nothing. The message is what separates rejecting the
    channel list from rejecting everything."""
    root = seed.user('root', role='admin')
    mgr = api.make_fake_manager()
    mgr.get_nodes.return_value = {'success': True, 'nodes': []}
    api.set_manager('cluster_1', mgr)
    c = api.as_user(root)

    bad = c.post('/api/clusters/cluster_1/updates/rolling', json={'notify_channels': 'not-a-list'})
    assert bad.status_code == 400
    assert 'notify_channels' in (bad.get_json() or {}).get('error', ''), bad.data

    good = c.post('/api/clusters/cluster_1/updates/rolling', json={'notify_channels': ['ch1']})
    assert 'notify_channels' not in (good.get_json() or {}).get('error', ''), good.data


def test_a_list_of_non_strings_is_refused_too(api, seed):
    root = seed.user('root', role='admin')
    mgr = api.make_fake_manager()
    mgr.get_nodes.return_value = {'success': True, 'nodes': []}
    api.set_manager('cluster_1', mgr)
    r = api.as_user(root).post('/api/clusters/cluster_1/updates/rolling',
                               json={'notify_channels': [{'id': 'ch1'}]})
    assert 'notify_channels' in (r.get_json() or {}).get('error', ''), r.data


# --- the operator has to be able to pick the channels ------------------------

def test_the_start_dialog_offers_the_channels():
    """A backend-only feature is unreachable: the reporter wants to tick a box, not
    craft a POST."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = open(os.path.join(root, 'web', 'src', 'security.js'), encoding='utf-8').read()
    assert 'notify_channels: notifyChannels' in body, 'the dialog never sends the selection'
    assert "'/api/alert-channels'" in body, 'the dialog has nothing to offer'
    assert 'alertChannels.length > 0' in body, \
        'the picker renders even when no channel is configured'


def test_the_label_exists_in_every_language():
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = open(os.path.join(root, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    assert len(re.findall(r'^\s*notifyChannelsLabel:', body, re.M)) == 9
