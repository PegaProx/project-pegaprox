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

import logging
import threading

import pytest

from pegaprox.core.manager import PegaProxManager

MB = 1048576


def _mgr():
    """Bare manager with only the attributes _get_live_node_net_rates touches."""
    m = PegaProxManager.__new__(PegaProxManager)
    m._node_net_counters = {}
    m._node_net_rates = {}
    m._node_net_fetched_at = 0.0
    m._node_net_lock = threading.Lock()
    m.logger = logging.getLogger('test')
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


class _RawResp:
    """Arbitrary JSON body, for payload shapes _Resp cannot express.

    Pass an Exception instance to make .json() itself blow up, which is what a
    truncated or HTML error body does.
    """

    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


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


def test_endpoint_unavailable_falls_back_instead_of_serving_a_stale_rate():
    # An earlier cut of this returned the cached rates here. get_node_status()
    # gates its rrddata fallback on `node not in live_net`, so a cached entry
    # suppressed the fallback and the node froze on its last known rate for as
    # long as the endpoint stayed broken - worse than the 60s RRD step this
    # whole change is about. Empty dict must mean "use rrddata".
    for code in (403, 404, 500):
        m = _mgr()
        _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
        assert _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)))['pve1'][0] == pytest.approx(10 * MB)
        assert _feed(m, _Resp([], status_code=code)) == {}


def test_failure_also_clears_the_throttle_window_cache():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)))
    assert _feed(m, _Resp([], status_code=403)) == {}
    # a caller arriving inside the 5s throttle window must not get the pre-failure
    # rate back out of the cache
    assert m._get_live_node_net_rates() == {}


def test_node_dropping_out_of_the_feed_loses_its_live_rate():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    assert 'pve1' in _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)))
    # node gone from the response (offline, or not in --node-list): it must fall
    # back to rrddata rather than keep serving the rate we last computed
    assert _feed(m, _Resp(_rows(1020, 1 * MB, 1 * MB, node='pve2'))) == {}


def test_malformed_rows_are_skipped_not_raised():
    # This used to be outside the try/except, so an AttributeError propagated
    # through get_node_status() and lost EVERY node's status, not just net rates.
    m = _mgr()
    junk = ['a string', None, 42, {'id': None}, {'id': 'node/pve1'},
            {'id': 'node/pve1', 'metric': 'net_in', 'value': 'not-a-number', 'timestamp': 1000},
            {'id': 'node/pve1', 'metric': 'net_in', 'value': 1 * MB, 'timestamp': 'not-a-ts'}]
    assert _feed(m, _Resp(junk)) == {}
    assert _feed(m, _Resp(junk + _rows(1000, 100 * MB, 100 * MB))) == {}
    rates = _feed(m, _Resp(junk + _rows(1010, 200 * MB, 200 * MB)))
    assert rates['pve1'][0] == pytest.approx(10 * MB)


@pytest.mark.parametrize('payload', [
    {},                                     # no envelope at all
    {'data': None},
    {'data': 'oops'},                       # str - iterating it yields characters
    {'data': 42},                           # not iterable at all
    {'data': {}},                           # envelope, no rows
    {'data': {'data': None}},
    {'data': {'data': 'oops'}},
    {'data': {'data': {'node/pve1': 5}}},   # dict - iterating it yields keys, not rows
    ValueError('Expecting value: line 1 column 1'),   # body was not JSON
])
def test_malformed_payload_container_falls_back_instead_of_raising(payload):
    # HTTP 200 with a body we cannot parse. The row loop lives outside the
    # per-row try/except of the old cut, so a container surprise here raised
    # through get_node_status() and lost EVERY node's status. It has to look
    # exactly like "no live answer": empty dict, caller uses rrddata.
    m = _mgr()
    assert _feed(m, _RawResp(payload)) == {}


def test_malformed_container_does_not_wipe_the_counter_history():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    assert _feed(m, _RawResp({'data': {'data': 'oops'}})) == {}
    # counters survive a bad response, so the next good sample differentiates
    # over the longer gap - a cumulative counter makes that a valid average
    rates = _feed(m, _Resp(_rows(1020, 300 * MB, 300 * MB)))
    assert rates['pve1'][0] == pytest.approx(10 * MB)   # 200 MB over 20s


def test_half_a_node_pair_never_produces_a_rate():
    # net_out missing (row dropped, or a partial pvestatd broadcast). Half a
    # pair must not be stored, otherwise the next full sample differentiates
    # net_out against a counter we never saw.
    m = _mgr()
    half = [{'id': 'node/pve1', 'metric': 'net_in', 'value': 100 * MB,
             'type': 'derive', 'timestamp': 1000}]
    assert _feed(m, _Resp(half)) == {}
    assert 'pve1' not in m._node_net_counters
    # so the first complete pair is a first sighting, not a rate
    assert _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB))) == {}
    assert _feed(m, _Resp(_rows(1020, 300 * MB, 300 * MB)))['pve1'][0] == pytest.approx(10 * MB)


def test_a_node_reporting_only_gauge_rows_stays_on_rrddata():
    # never-seen node whose net_in/net_out arrive as `gauge` - already a rate.
    # Two of those must not become counter state and must not be differentiated,
    # or the dashboard shows a number derived from two rates.
    m = _mgr()
    gauge = [
        {'id': 'node/pve2', 'metric': 'net_in', 'value': 5 * MB, 'type': 'gauge', 'timestamp': 1000},
        {'id': 'node/pve2', 'metric': 'net_out', 'value': 5 * MB, 'type': 'gauge', 'timestamp': 1000},
    ]
    assert _feed(m, _Resp(gauge)) == {}
    assert 'pve2' not in m._node_net_counters
    assert _feed(m, _Resp([dict(r, timestamp=1010, value=9 * MB) for r in gauge])) == {}
    assert 'pve2' not in m._node_net_counters


def test_two_nodes_keep_independent_counter_state():
    # state is per node, including the timestamp - a single shared `ts` would
    # divide one node's delta by the other node's interval
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)
                   + _rows(1000, 500 * MB, 500 * MB, node='pve2', extra=False)))
    rates = _feed(m, _Resp(_rows(1010, 200 * MB, 200 * MB)
                           + _rows(1015, 650 * MB, 650 * MB, node='pve2', extra=False)))
    assert rates['pve1'][0] == pytest.approx(10 * MB)          # 100 MB over 10s
    assert rates['pve2'][0] == pytest.approx(150 * MB / 15)    # 150 MB over its own 15s


def test_gauge_rows_never_get_treated_as_a_counter():
    # A `gauge` net_in would be an already-computed rate. Differentiating it
    # produces garbage, so it must not land in the counter state - not even when
    # it arrives after a valid derive row for the same node.
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    poisoned = _rows(1010, 200 * MB, 200 * MB) + [
        {'id': 'node/pve1', 'metric': 'net_in', 'value': 7, 'type': 'gauge', 'timestamp': 1010},
        {'id': 'node/pve1', 'metric': 'net_out', 'value': 7, 'type': 'gauge', 'timestamp': 1010},
    ]
    rates = _feed(m, _Resp(poisoned))
    assert rates['pve1'][0] == pytest.approx(10 * MB)   # not 7, not derived from 7
    assert m._node_net_counters['pve1']['netin'] == 200 * MB
    # and a row with no `type` at all is still accepted (future-proofing)
    untyped = [{k: v for k, v in r.items() if k != 'type'} for r in _rows(1020, 300 * MB, 300 * MB)]
    assert _feed(m, _Resp(untyped))['pve1'][0] == pytest.approx(10 * MB)


def test_out_of_order_sample_does_not_regress_the_baseline():
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))
    _feed(m, _Resp(_rows(1020, 300 * MB, 300 * MB)))     # 200 MB / 20s = 10 MB/s
    # a stale response lands late (retry, or the node's clock stepped back)
    held = _feed(m, _Resp(_rows(1005, 150 * MB, 150 * MB)))
    assert held['pve1'][0] == pytest.approx(10 * MB)      # rate held, not recomputed
    assert m._node_net_counters['pve1']['ts'] == 1020     # baseline NOT regressed
    # next real sample differentiates against 1020, not against the stale 1005
    nxt = _feed(m, _Resp(_rows(1030, 400 * MB, 400 * MB)))
    assert nxt['pve1'][0] == pytest.approx(10 * MB)       # 100 MB / 10s


def test_concurrent_callers_do_not_stampede_the_endpoint():
    # _api_get yields to the gevent hub, so a second caller can arrive mid-fetch.
    # The throttle window is claimed before the request precisely so that caller
    # returns the cache instead of firing its own cluster-wide pull.
    m = _mgr()
    calls = []

    def reentrant(url, **kw):
        calls.append(url)
        assert m._get_live_node_net_rates() == {}   # sees the claimed window
        return _Resp(_rows(1000, 100 * MB, 100 * MB))

    m._api_get = reentrant
    m._get_live_node_net_rates()
    assert len(calls) == 1


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


def test_transport_failure_keeps_counter_history_for_the_next_good_sample():
    # _drop_live_node_net_rates() forgets the RATES so callers fall back, but it
    # must keep the counters. Forgetting those too costs an extra poll cycle with
    # no live rate every time the endpoint hiccups.
    m = _mgr()
    _feed(m, _Resp(_rows(1000, 100 * MB, 100 * MB)))

    def boom(url, **kw):
        raise RuntimeError('connection reset')

    m._node_net_fetched_at = 0.0
    m._api_get = boom
    assert m._get_live_node_net_rates() == {}

    rates = _feed(m, _Resp(_rows(1030, 400 * MB, 400 * MB)))
    assert rates['pve1'][0] == pytest.approx(10 * MB)   # 300 MB over 30s


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
