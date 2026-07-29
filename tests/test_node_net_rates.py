# Live node network-rate state machine — PegaProxManager._get_live_node_net_rates().
#
# SP Jul 2026 (#419 follow-up) — node netin/netout used to come from
# /nodes/{name}/rrddata, which has a 60s RRD step and leaves the last 1-2
# averaging windows null, so the dashboard number froze for a minute at a time
# and was 60-120s behind. The live source is /cluster/metrics/export: cumulative
# (`derive`) net_in/net_out per node, refreshed by pvestatd every 10s. Turning a
# counter into a rate needs two samples and has four cases that all misbehave in
# a different way if you get them wrong:
#
#   1. one sample only          -> no rate yet, caller must fall back to rrddata
#   2. timestamp advanced       -> differentiate over PVE's own timestamps
#   3. timestamp unchanged      -> hold the last rate (we poll faster than 10s;
#                                  dividing by dt=0 or returning 0 makes the UI flap)
#   4. counter went backwards   -> node rebooted, clamp to 0 instead of negative
#
# No network here: the method is driven with a stubbed _api_get.

import pytest

from pegaprox.core.manager import PegaProxManager

MB = 1048576


def _mgr():
    """Bare manager with only the attributes _get_live_node_net_rates touches."""
    m = PegaProxManager.__new__(PegaProxManager)
    m._node_net_counters = {}
    m._node_net_rates = {}
    m._node_net_fetched_at = 0.0
    m.logger = __import__('logging').getLogger('test')
    m._get_api_url = lambda path: 'https://stub' + path
    return m


class _Resp:
    """Real /cluster/metrics/export HTTP shape.

    This endpoint returns an object, so the API's own {"data": ...} envelope
    makes it double-wrapped: {"data": {"data": [ ...rows... ]}}. `pvesh` strips
    the outer layer, which is exactly how the first cut of this patch shipped a
    stub that passed while the live code raised
    "'str' object has no attribute 'get'" (iterating a dict yields its keys).
    """

    def __init__(self, rows, status_code=200, flat=False):
        self.status_code = status_code
        self._rows = rows
        self._flat = flat

    def json(self):
        if self._flat:
            return {'data': self._rows}   # tolerated shape, not what PVE sends
        return {'data': {'data': self._rows}}


def _rows(ts, netin, netout, node='pve1', extra=True):
    rows = [
        {'id': f'node/{node}', 'metric': 'net_in', 'value': netin, 'type': 'derive', 'timestamp': ts},
        {'id': f'node/{node}', 'metric': 'net_out', 'value': netout, 'type': 'derive', 'timestamp': ts},
    ]
    if extra:
        # guest rows and other node metrics share the response — must be ignored
        rows += [
            {'id': 'qemu/100', 'metric': 'net_in', 'value': 999 * MB, 'type': 'derive', 'timestamp': ts},
            {'id': f'node/{node}', 'metric': 'cpu_current', 'value': 0.5, 'type': 'gauge', 'timestamp': ts},
        ]
    return rows


def _feed(m, resp):
    """One poll. Clears the 5s throttle so each call really fetches."""
    m._node_net_fetched_at = 0.0
    m._api_get = lambda url, **kw: resp
    return m._get_live_node_net_rates()


def test_first_sample_yields_no_rate():
    m = _mgr()
    assert _feed(m, _Resp(_rows(1000, 10 * MB, 5 * MB))) == {}
    # counter is remembered so the next poll can differentiate
    assert m._node_net_counters['pve1']['ts'] == 1000


def test_second_sample_gives_bytes_per_second():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 50 * MB)))
    rates = _feed(m, _Resp(_rows(1010, 200 * MB, 100 * MB)))
    netin, netout = rates['pve1']
    assert netin == pytest.approx(10 * MB)   # 100 MB over 10s
    assert netout == pytest.approx(5 * MB)


def test_same_timestamp_holds_last_rate_instead_of_flapping():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 50 * MB)))
    _feed(m, _Resp(_rows(1010, 200 * MB, 100 * MB)))
    # pvestatd has not broadcast a new window yet — same ts, same counters
    held = _feed(m, _Resp(_rows(1010, 200 * MB, 100 * MB)))
    assert held['pve1'][0] == pytest.approx(10 * MB)


def test_counter_reset_clamps_to_zero():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 500 * MB, 500 * MB)))
    # node rebooted: /proc/net/dev counters restart from ~0
    rates = _feed(m, _Resp(_rows(1010, 1 * MB, 1 * MB)))
    assert rates['pve1'] == (0.0, 0.0)
    # and it resyncs on the following window
    after = _feed(m, _Resp(_rows(1020, 21 * MB, 11 * MB)))
    assert after['pve1'][0] == pytest.approx(2 * MB)


def test_guest_and_non_net_rows_are_ignored():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 10 * MB, 10 * MB)))
    rates = _feed(m, _Resp(_rows(1010, 20 * MB, 20 * MB)))
    assert list(rates) == ['pve1']


def test_endpoint_unavailable_keeps_last_known_rates():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)))
    # pve-manager < 8.2.5 (404) or token without Sys.Audit on / (403)
    for code in (403, 404, 500):
        rates = _feed(m, _Resp([], status_code=code))
        assert rates['pve1'][0] == pytest.approx(10 * MB)


def test_flat_payload_shape_is_tolerated():
    # defensive: if a future PVE version drops the inner envelope, still parse
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB), flat=True))
    rates = _feed(m, _Resp(_rows(1010, 200 * MB, 100 * MB), flat=True))
    assert rates['pve1'][0] == pytest.approx(10 * MB)


def test_transport_failure_does_not_raise():
    m = _mgr()
    m._node_net_fetched_at = 0.0

    def boom(url, **kw):
        raise RuntimeError('connection reset')

    m._api_get = boom
    assert m._get_live_node_net_rates() == {}


def test_throttle_skips_refetch_within_the_window():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)))
    calls = []

    def counting(url, **kw):
        calls.append(url)
        return _Resp(_rows(1020, 400 * MB, 400 * MB))

    m._api_get = counting
    # no _node_net_fetched_at reset here — the 5s throttle must hold
    rates = m._get_live_node_net_rates()
    assert calls == []
    assert rates['pve1'][0] == pytest.approx(10 * MB)
