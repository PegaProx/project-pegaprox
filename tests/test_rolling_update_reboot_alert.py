"""Regression coverage for rolling-update reboot notifications."""


def test_reboot_event_reaches_the_alert_notification_pipeline(monkeypatch):
    from pegaprox.background import alerts

    delivered = []
    persisted = []
    monkeypatch.setattr(alerts, '_notification_handlers', [delivered.append])
    monkeypatch.setattr(alerts, '_upsert_active_alert', lambda *args: persisted.append(args))
    monkeypatch.setattr(alerts, 'load_alerts_config', lambda: {'alerts': [{
        'id': 'rolling-1', 'name': 'Rolling Updates', 'cluster_id': 'cluster_1',
        'metric': 'rolling_update', 'target_type': 'cluster', 'enabled': True,
        'channels': [],
    }]})

    assert alerts.emit_rolling_update_reboot_event('cluster_1', 'pve-01') is True

    event = delivered[0]
    assert event['alert_name'] == 'Node pve-01 rebooting for rolling update'
    assert event['cluster_id'] == 'cluster_1'
    assert event['target_type'] == 'node'
    assert event['target_name'] == 'pve-01'
    assert event['metric'] == 'rolling_update_reboot'
    assert event['severity'] == 'info'
    assert 'rolling update' in event['message']
    assert persisted[0][0] == 'rolling-1:cluster_1:node:pve-01:rolling_update'
    assert persisted[0][1] == 'rolling-1'
    assert persisted[0][-1] == 'pve-01'


def test_reboot_event_is_silent_without_an_enabled_rolling_update_alarm(monkeypatch):
    from pegaprox.background import alerts

    monkeypatch.setattr(alerts, 'load_alerts_config', lambda: {'alerts': [{
        'id': 'rolling-1', 'cluster_id': 'cluster_1', 'metric': 'rolling_update',
        'enabled': False,
    }]})
    monkeypatch.setattr(alerts, '_upsert_active_alert', lambda *args: (_ for _ in ()).throw(AssertionError()))

    assert alerts.emit_rolling_update_reboot_event('cluster_1', 'pve-01') is False


# NS Sep 2026 - added on merge of #960. The two new strings in the alert dialog were
# written as `t('rollingUpdates') || 'Rolling Updates'`, which reads like a safe
# fallback and is not: t() is `translations[lang]?.[key] || translations['en']?.[key]
# || key`, so a missing key comes back as the KEY, which is truthy, and the `||` never
# fires. Without the entries below the dialog shows the literal `rollingUpdates`.

import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _translations():
    return open(os.path.join(_ROOT, 'web', 'src', 'translations.js'), encoding='utf-8').read()


def test_the_alert_dialog_strings_exist_in_every_language():
    body = _translations()
    for key in ('rollingUpdates', 'rollingUpdateAlarmHelp'):
        found = len(re.findall(rf'^\s*{key}:', body, re.M))
        assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_the_option_reached_the_built_bundle():
    """web/index.html is generated from web/src; a src-only change ships nothing."""
    built = open(os.path.join(_ROOT, 'web', 'index.html'), encoding='utf-8').read()
    # the bundle is Babel output, so the JSX is gone - match the compiled element
    assert 'React.createElement("option",{value:"rolling_update"}' in built


# --- found by the 2026-09-29 scan (CodeAnt, alerts.py:338) -------------------
#
# A rolling-update rule is pinned to operator 'event' / threshold 1, because it is
# fired by the update worker rather than compared against a number. Switching that
# rule to a metric that IS compared left both values in place: the metric poll stops
# skipping it, then evaluates 'event' as if it were a comparison operator, and the
# rule silently never fires again. The UI always sends an operator so it hides this;
# an API client that PATCHes {"metric": "cpu"} alone does not.

def _alert_store(monkeypatch, rule):
    from pegaprox.api import alerts as am
    store = {'cluster_1': [rule]}
    monkeypatch.setattr(am, 'load_cluster_alerts', lambda: store)
    monkeypatch.setattr(am, 'save_cluster_alerts', lambda a: store.update(a))
    return store


def test_switching_away_from_rolling_update_restores_a_usable_comparison(api, seed, monkeypatch):
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', api.make_fake_manager())
    store = _alert_store(monkeypatch, {
        'id': 'a1', 'name': 'RU', 'cluster_id': 'cluster_1', 'enabled': True,
        'metric': 'rolling_update', 'operator': 'event', 'threshold': 1,
        'target_type': 'cluster', 'channels': [],
    })

    r = api.as_user(root).put('/api/clusters/cluster_1/alerts/a1', json={'metric': 'cpu'})
    assert r.status_code == 200, r.data

    rule = store['cluster_1'][0]
    assert rule['metric'] == 'cpu'
    assert rule['operator'] != 'event', (
        "the rule kept operator 'event' on a metric that is compared - it can never fire")
    assert isinstance(rule['threshold'], (int, float)) and rule['threshold'] > 1, rule


def test_an_operator_the_caller_sent_is_kept(api, seed, monkeypatch):
    """A real comparison operator in the request survives - the branch does not
    even run, because the copy loop has already written it."""
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', api.make_fake_manager())
    store = _alert_store(monkeypatch, {
        'id': 'a1', 'name': 'RU', 'cluster_id': 'cluster_1', 'enabled': True,
        'metric': 'rolling_update', 'operator': 'event', 'threshold': 1,
        'target_type': 'cluster', 'channels': [],
    })

    api.as_user(root).put('/api/clusters/cluster_1/alerts/a1',
                          json={'metric': 'memory', 'operator': '<', 'threshold': 5})
    rule = store['cluster_1'][0]
    assert rule['operator'] == '<' and rule['threshold'] == 5, rule


def test_a_rolling_update_rule_is_still_pinned(api, seed, monkeypatch):
    """Counter-check: the pinning that #960 added has to survive this."""
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', api.make_fake_manager())
    store = _alert_store(monkeypatch, {
        'id': 'a1', 'name': 'CPU', 'cluster_id': 'cluster_1', 'enabled': True,
        'metric': 'cpu', 'operator': '>', 'threshold': 80,
        'target_type': 'cluster', 'channels': [],
    })

    api.as_user(root).put('/api/clusters/cluster_1/alerts/a1', json={'metric': 'rolling_update'})
    rule = store['cluster_1'][0]
    assert rule['operator'] == 'event' and rule['threshold'] == 1, rule


def test_a_caller_who_asks_for_event_on_a_compared_metric_is_corrected(api, seed, monkeypatch):
    """The case the `if 'operator' not in data` guard got wrong: 'event' explicitly
    sent alongside a metric that IS compared is still a rule that never fires."""
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', api.make_fake_manager())
    store = _alert_store(monkeypatch, {
        'id': 'a1', 'name': 'RU', 'cluster_id': 'cluster_1', 'enabled': True,
        'metric': 'rolling_update', 'operator': 'event', 'threshold': 1,
        'target_type': 'cluster', 'channels': [],
    })

    api.as_user(root).put('/api/clusters/cluster_1/alerts/a1',
                          json={'metric': 'cpu', 'operator': 'event'})
    rule = store['cluster_1'][0]
    assert rule['operator'] != 'event', rule
