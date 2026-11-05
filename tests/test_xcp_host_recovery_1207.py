"""A cached pool master is not proof that a rebooted target is ready."""
from unittest.mock import MagicMock

import pytest

import pegaprox.core.xcpng as xcpng_mod
from pegaprox.core.xcpng import XcpngManager


class _PollingClock:
    """Advance the polling budget without real reboot or sleep."""
    def __init__(self):
        """Start the simulated polling budget at zero."""
        self.now = 0

    def sleep(self, seconds):
        """Advance the polling clock without delaying the test."""
        self.now += seconds

    def time(self):
        """Report the elapsed simulated polling time."""
        return self.now


def _pool(monkeypatch):
    """Keep a pool-master proxy alive while its target host recovers separately."""
    import socket

    api = MagicMock()
    api.host.get_all.return_value = ["master-ref", "target-ref"]
    api.host.get_hostname.side_effect = lambda ref: {"master-ref": "master", "target-ref": "target"}[ref]
    api.host.get_name_label.side_effect = lambda ref: {"master-ref": "master-label", "target-ref": "target-label"}[ref]
    manager = XcpngManager.__new__(XcpngManager)
    manager._api = lambda: api
    manager._get_host_ip = lambda node: "192.0.2.10"
    manager._cached_nodes = ["stale"]
    connect = MagicMock()
    monkeypatch.setattr(socket, "create_connection", connect)
    clock = _PollingClock()
    monkeypatch.setattr(xcpng_mod, "time", clock)
    return manager, api, connect, clock


@pytest.mark.parametrize("ready_after", [None, 1, 2])
def test_recovery_requires_the_target_routed_rpc(monkeypatch, ready_after):
    """An open target port and a responsive master cannot confirm target recovery."""
    manager, api, connect, clock = _pool(monkeypatch)
    calls = []

    def server_time(ref):
        """Model target readiness independently of a responsive pool master."""
        calls.append(ref)
        assert ref == "target-ref"
        if ready_after is None or len(calls) < ready_after:
            raise OSError("target XAPI is not ready")
        return "20261105T00:00:00Z"

    api.host.get_servertime.side_effect = server_time
    online = manager._wait_for_host_online("target", timeout=30)
    assert online is (ready_after is not None)
    assert calls and set(calls) == {"target-ref"}
    connect.assert_called_with(("192.0.2.10", 443), timeout=5)
    assert connect.return_value.close.call_count == connect.call_count
    assert manager._cached_nodes == (None if online else ["stale"])
    if ready_after is None:
        assert len(calls) >= 2


@pytest.mark.parametrize("node_name", ["target", "target-label"])
def test_recovery_resolves_hostname_or_label_to_the_target(monkeypatch, node_name):
    """Both existing host-name forms route the health RPC to the requested host."""
    manager, api, connect, clock = _pool(monkeypatch)
    assert manager._wait_for_host_online(node_name, timeout=30)
    api.host.get_servertime.assert_called_once_with("target-ref")
    assert manager._cached_nodes is None


def test_unresolved_target_cannot_be_replaced_by_master_readiness(monkeypatch):
    """A target absent from the host list stays unconfirmed."""
    manager, api, connect, clock = _pool(monkeypatch)
    assert not manager._wait_for_host_online("missing", timeout=30)
    api.host.get_servertime.assert_not_called()
    assert manager._cached_nodes == ["stale"]


def test_unavailable_pool_api_keeps_recovery_unconfirmed(monkeypatch):
    """TCP readiness alone does not bypass an unavailable XAPI session."""
    manager, api, connect, clock = _pool(monkeypatch)
    manager._api = lambda: None
    assert not manager._wait_for_host_online("target", timeout=30)
    api.host.get_servertime.assert_not_called()
    assert manager._cached_nodes == ["stale"]


def test_closed_target_port_keeps_recovery_unconfirmed(monkeypatch):
    """The target TCP gate still runs before any routed XAPI readiness request."""
    manager, api, connect, clock = _pool(monkeypatch)
    connect.side_effect = OSError("target is down")
    assert not manager._wait_for_host_online("target", timeout=30)
    api.host.get_servertime.assert_not_called()
    connect.return_value.close.assert_not_called()
    assert manager._cached_nodes == ["stale"]
