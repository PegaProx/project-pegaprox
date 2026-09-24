"""Drift events never reached the configured webhook channels (#815).

alerts.py does two things when a metric alert fires: it calls every entry in
_notification_handlers — the PLUGIN hook, which in practice is web-push — and it
calls webhooks.send_to_channels, which is the actual webhook delivery. The drift
scanner and the cross-cluster SDN scanner only ever did the first. So a drift event
showed up in push and nowhere else, while the Test button on a channel kept working
because it dispatches straight to send_to_channel. MK
"""
import ast
import io
from unittest.mock import MagicMock, patch

import pytest


def test_the_dispatcher_is_reachable_from_drift():
    """Guards the import path the fix relies on — a rename would silently re-break it."""
    from pegaprox.utils import webhooks
    assert callable(webhooks.send_to_channels)


def _read(path):
    """Read a source file and actually close the handle — a bare open() in a test
    still leaks a descriptor and trips ResourceWarning under -W error."""
    with io.open(path, encoding='utf-8') as fh:
        return fh.read()


def _calls_send_to_channels(path):
    """True iff the module really CALLS send_to_channels.

    A substring search would be happy with the name appearing in a comment or a
    docstring, which is exactly the kind of test that passes while the product is
    broken. Walk the AST and look for the call instead.
    """
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, 'id', None)
            if name == 'send_to_channels':
                return True
    return False


def test_drift_calls_the_webhook_dispatcher():
    assert _calls_send_to_channels('pegaprox/api/drift.py'), \
        "drift never dispatches to webhook channels"


def test_multi_sdn_calls_the_webhook_dispatcher():
    assert _calls_send_to_channels('pegaprox/api/multi_sdn.py'), \
        "SDN drift never dispatches to webhook channels"


def test_the_ast_check_is_not_fooled_by_a_mere_mention(tmp_path):
    """Proves the guard above is worth anything — a comment must not satisfy it."""
    decoy = tmp_path / 'decoy.py'
    decoy.write_text("# TODO: call send_to_channels here one day\nx = 'send_to_channels'\n")
    assert not _calls_send_to_channels(str(decoy))


def test_dispatch_is_nested_inside_the_new_events_guard():
    """A dispatch outside `if new_events:` would fire a webhook on every scan with
    nothing to report — noisy enough that people would turn the channel off again.

    The first version of this compared string offsets, which quietly measured the
    position of the `import send_to_channels` line rather than the call, because the
    import comes first in the file. Ask the tree instead.
    """
    tree = ast.parse(_read('pegaprox/api/drift.py'))
    guards = [n for n in ast.walk(tree)
              if isinstance(n, ast.If)
              and any(isinstance(x, ast.Name) and x.id == 'new_events'
                      for x in ast.walk(n.test))]
    assert guards, "the `if new_events:` guard is gone"
    inside = any(
        isinstance(c, ast.Call)
        and (c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, 'id', None))
            == 'send_to_channels'
        for g in guards for c in ast.walk(g))
    assert inside, "webhook dispatch escaped the new_events guard"


def test_no_channel_filter_is_passed():
    """Drift has no per-event channel picker, so every enabled channel must get it.
    Passing an empty list here would silently deliver nothing — the exact bug again."""
    src = _read('pegaprox/api/drift.py')
    i = src.index('send_to_channels(')
    call = src[i:i + 60]
    assert 'channel_ids' not in call, f"unexpected channel filter on the drift dispatch: {call!r}"


def test_send_to_channels_defaults_to_every_enabled_channel():
    """The contract the fix leans on: channel_ids=None means all, [] means none."""
    import inspect
    from pegaprox.utils import webhooks
    sig = inspect.signature(webhooks.send_to_channels)
    assert sig.parameters['channel_ids'].default is None


def test_a_failing_webhook_cannot_break_the_drift_scan():
    """The scan's job is recording drift; notification is best-effort on top of it."""
    src = _read('pegaprox/api/drift.py')
    i = src.index('send_to_channels(')
    window = src[max(0, i - 200):i + 200]
    assert 'try:' in window and 'except Exception' in window


# ── the behavioural one: actually run a scan that finds drift ──

def test_a_real_drift_scan_dispatches_the_payload(monkeypatch):
    """Source greps above only prove the call exists. This drives _scan_cluster with a
    fake cluster that has drifted and asserts the dispatcher really receives it."""
    import pegaprox.globals as ppglobals
    from pegaprox.api import drift as drift_mod

    mgr = MagicMock()
    mgr.is_connected = True
    ppglobals.cluster_managers['c_drift'] = mgr

    sent = []
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels',
                        lambda payload, **kw: sent.append((payload, kw)))
    # one baseline, and a current state that no longer matches it
    # _fetch_state yields (kind, scope, snapshot); _load_baselines is keyed by that pair
    monkeypatch.setattr(drift_mod, '_fetch_state',
                        lambda m, cid: [('firewall', 'cluster', {'policy_in': 'DROP'})])
    monkeypatch.setattr(drift_mod, '_load_baselines',
                        lambda cid: {('firewall', 'cluster'):
                                     {'snapshot': {'policy_in': 'ACCEPT'}}})
    monkeypatch.setattr(drift_mod, '_record_event', lambda *a, **k: 'evt-1')

    try:
        res = drift_mod._scan_cluster('c_drift')
    finally:
        ppglobals.cluster_managers.pop('c_drift', None)

    assert res.get('events_count', 0) >= 1, f"no drift detected, test setup is wrong: {res}"
    assert sent, "drift was detected but nothing reached the webhook dispatcher"
    payload, kw = sent[0]
    assert payload['alert_name'] == 'Config Drift'
    assert payload['cluster_id'] == 'c_drift'
    assert kw == {}, f"drift must not filter channels, got {kw}"
