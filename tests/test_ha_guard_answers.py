"""What a request answers once the exit refused one of its writes (#625 stage 2; the
Testi run of automatic failover).

The routes take the GuardRefused for a failed cluster call: the migration answered 400
with the guard's own words ("POST /nodes/N/qemu/N/migrate refused: no majority
confirmed the lease for this call"), the reboot and the removal of a node 500. Each of
them answers 503 HA_NO_LEASE now, as the write gate does, with Retry-After - a refusal
in a fan-out of the request and one no route caught as well. An answer of a request
whose writes went out, or that sent none, stays as it was.

MK Oct 2026 (#625)
"""
import threading

import pytest
import requests

from pegaprox.core import ha as _ha
from pegaprox.core import ha_transport as hx
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import auto  # noqa: F401
from test_ha_guard_rounds import START, pve

MIGRATE = '/api/clusters/c1/vms/pve1/qemu/101/migrate'


def _mgr():
    m = pve()
    # no guest list for the affinity check: no rule to keep
    m.session = None
    return m


def _pve_answers(monkeypatch, sent, status=200, body=b'{"data": "UPID:pve1:0001:migrate"}'):
    """What PVE answers to whatever reaches the adapter, and what reached it."""
    def send(self, request, **kw):
        sent.append(f'{request.method} {request.url}')
        r = requests.Response()
        r.request, r.encoding = request, 'utf-8'
        r.status_code, r._content = status, body
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)


def _no_lease(r):
    body = r.get_json() or {}
    assert r.status_code == 503, (r.status_code, r.data[:300])
    assert body.get('code') == 'HA_NO_LEASE', body
    # what the caller reads is the gate's text, not the guard's note for the log
    assert 'refused' not in body.get('error', '') and '/nodes/' not in body.get('error', '')
    assert r.headers.get('Retry-After')


@pytest.mark.guard_refusals
def test_a_migration_the_exit_refused_answers_503_no_lease(auto, seed, monkeypatch):
    """The leader is cut off from every voter, its lease still runs: the write gate lets
    the migration in, the round before the POST finds no majority, nothing goes out."""
    from pegaprox.globals import cluster_managers
    auto.form(seed)
    sent = []
    _pve_answers(monkeypatch, sent)
    monkeypatch.setitem(cluster_managers, 'c1', _mgr())
    auto.isolate('a')
    with auto.at('a') as ha:
        assert ha.is_active(), 'as a sees it, its lease runs'
        r = auto.admin.post(MIGRATE, json={'target': 'pve2'})
        said = {why for _a, why in ha._guard_said}
    assert sent == []
    assert _ha.GUARD_UNCONFIRMED in said
    _no_lease(r)


@pytest.mark.guard_refusals
def test_a_migration_after_the_lease_ran_out_answers_503_no_lease(auto, seed, monkeypatch):
    """The lease of 'a' ends between the gate and the exit: refused for want of a lease."""
    from pegaprox.globals import cluster_managers
    auto.form(seed)
    sent = []
    _pve_answers(monkeypatch, sent)
    m = _mgr()
    real = m.migrate_vm_manual

    def lease_gone(*a, **k):
        auto.isolate('a')
        _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
        return real(*a, **k)
    m.migrate_vm_manual = lease_gone
    monkeypatch.setitem(cluster_managers, 'c1', m)
    with auto.at('a') as ha:
        r = auto.admin.post(MIGRATE, json={'target': 'pve2'})
        said = {why for _a, why in ha._guard_said}
    assert sent == []
    assert _ha.GUARD_NO_LEASE in said
    _no_lease(r)


def test_answers_without_a_refusal_stay_as_they_were(auto, seed, monkeypatch):
    """In the same group: a migration without a target is the route's 400, one PVE turns
    down is the route's 400 with PVE's words, one that went out is 200."""
    from pegaprox.globals import cluster_managers
    auto.form(seed)
    sent = []
    monkeypatch.setitem(cluster_managers, 'c1', _mgr())
    with auto.at('a'):
        r = auto.admin.post(MIGRATE, json={})
        assert r.status_code == 400 and 'Target node' in r.get_json()['error']
        _pve_answers(monkeypatch, sent, status=500, body=b'{"errors": {"target": "no such node"}}')
        r = auto.admin.post(MIGRATE, json={'target': 'pve9'})
        assert r.status_code == 400 and 'no such node' in r.get_json()['error']
        _pve_answers(monkeypatch, sent)
        r = auto.admin.post(MIGRATE, json={'target': 'pve2'})
        assert r.status_code == 200, r.data[:300]
    assert len(sent) == 2 and all(s.startswith('POST ') for s in sent)


def test_in_a_manual_group_a_migration_pve_turns_down_is_the_routes_400(api, seed, monkeypatch):
    sent = []
    _pve_answers(monkeypatch, sent, status=500, body=b'{"errors": {"target": "no such node"}}')
    api.set_manager('c1', _mgr())
    r = api.as_user(seed.user('root1', role='admin')).post(MIGRATE, json={'target': 'pve9'})
    assert r.status_code == 400 and 'no such node' in r.get_json()['error']
    assert len(sent) == 1


@pytest.mark.guard_refusals
def test_a_refusal_in_a_fan_out_of_the_request_is_the_requests(auto, seed):
    """A write sent from a worker the request fanned out to (ha.carry): its refusal is
    noted for that request, and the request's error answer turns into 503."""
    auto.form(seed)
    auto.isolate('a')
    app = auto.g.api.app
    out = []
    with auto.at('a') as ha:
        with app.test_request_context('/api/clusters/c1/nodes/pve1/action/reboot', method='POST'):
            from flask import request

            def send():
                try:
                    hx.guard_http('POST', START)
                    out.append('sent')
                except ha.GuardRefused as e:
                    out.append(e.why)
            t = threading.Thread(target=ha.carry(send))
            t.start()
            t.join()
            assert out == [ha.GUARD_UNCONFIRMED]
            resp = app.process_response(app.make_response(({'error': 'Reboot failed'}, 500)))
            assert resp.status_code == 503 and resp.get_json()['code'] == 'HA_NO_LEASE'
            assert request.environ.get(ha.GUARD_REFUSED_ENVIRON) == [ha.GUARD_UNCONFIRMED]


def test_a_refusal_no_route_caught_answers_503(api):
    app = api.app
    with app.test_request_context(MIGRATE, method='POST'):
        try:
            raise _ha.GuardRefused('POST /nodes/N/qemu/N/migrate', _ha.GUARD_NO_LEASE)
        except _ha.GuardRefused as e:
            # without a handler Flask raises it again, and the caller gets a 500
            resp = app.make_response(app.handle_user_exception(e))
    assert resp.status_code == 503 and resp.get_json()['code'] == 'HA_NO_LEASE'
    assert 'refused' not in resp.get_json()['error'] and resp.headers.get('Retry-After')


def test_a_request_with_no_refusal_keeps_its_error_answer(api):
    """The hook looks at the note, not at the role: a 500 elsewhere is a 500."""
    app = api.app
    with app.test_request_context(MIGRATE, method='POST'):
        resp = app.process_response(app.make_response(({'error': 'Migration failed'}, 500)))
    assert resp.status_code == 500 and resp.get_json() == {'error': 'Migration failed'}


def test_a_caller_nobody_checked_hears_nothing_about_the_group(api):
    """The anonymous text of the write gate where no signed-in user stands behind the
    request; a session of the route's gets the full one."""
    from pegaprox.api.ha import guard_refusal
    app = api.app
    with app.test_request_context(MIGRATE, method='POST'):
        resp, status = guard_refusal()
        assert status == 503 and resp.get_json()['error'] == _ha.NO_LEASE_ANON_ERROR
    with app.test_request_context(MIGRATE, method='POST'):
        from flask import request
        request.session = {'user': 'root1'}
        resp, status = guard_refusal()
        assert status == 503 and resp.get_json()['error'] == _ha.NO_LEASE_ERROR


def test_the_fast_path_still_stands_in_for_every_hook(api):
    """The lease calls send nothing through an exit: the new hook is one the fast path
    knows, or it would turn itself off for every renewal."""
    import pegaprox.app as app_mod
    assert 'say_no_lease_after_a_refused_write' in app_mod._STOOD_IN_FOR['after']
    assert app_mod._hooks_known(api.app)
