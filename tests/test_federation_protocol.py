"""The federation protocol under the faults that are easy to get wrong: commits that get
lost, releases that arrive late or overtake a round, a lease that spans two view changes,
an old owner coming back after its cluster moved on, a member that makes things up, and
a voter's tables under a member that asks for junk.

The harness is the one of tests/test_federation.py: several instances in one process,
the network a stand-in that routes each call into the side it names, the lease clock a
stand-in where time has to pass.

MK Nov 2026
"""
import json

import pytest

from pegaprox.core import federation
from pegaprox.core import federation_lease as fl
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _defaults_out_of_the_config_dir, _fresh_budgets, clock,
    Side, URL, _add_cluster, _ask, _code, _cut, _db_of, _enroll, _heal, _join, _owner_at,
    _sides, _sync, _three, _view, _wire, _without, _writes, at, iid, some_key)


def _settle(clock):
    """Past the settle span a view change starts, and past every promise given before."""
    clock.advance(fl.SETTLE_SECONDS + 1)


def _lossy(inner, *, commits=True, releases=True):
    """The commits (and the bare releases) a side sends get lost; its lock asks go
    through."""
    def transport(url, method, path, body, headers):
        if commits and path == federation.MEMBERSHIP_PATH:
            return 0, b'', {}
        if releases and path == federation.LEASE_PATH and body:
            data = json.loads(body)
            if data.get('releases') and not data.get('asks'):
                return 0, b'', {}
        return inner(url, method, path, body, headers)
    return transport


# --- a view change only counts once a majority took it ----------------------------------------

def test_a_lost_commit_changes_nothing_at_the_committer(tmp_path, clock):
    """a removes d, and every commit is lost on the way. a's own view stays as it was - d
    a member, d's mirrors and key kept - so the change b makes later from the same view is
    the only one, and a catches up to it and keeps its lease."""
    a, b, c, d = _sides(tmp_path, 'abcd')
    _enroll(a, 'pve-a')
    _enroll(d, 'pve-d', password='d-secret')
    _sync(a)
    with at(a):
        federation.fetch_field_keys()
        assert federation._peer_key(iid(d)) is not None
    before = _view(a)
    a.runtime['transport'] = _lossy(a.wire)
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.remove_member(iid(d), by='admin:a')
    assert err.value.code == 'FED_NO_QUORUM'
    assert sorted(err.value.extra['not_told']) == sorted([iid(b), iid(c), iid(d)])
    assert _view(a) == before
    assert _owner_at(a, 'pve-d') == iid(d)
    with at(a):
        assert federation._peer_key(iid(d)) is not None
    # a drops off the network; the others go on from the same view
    a.runtime['transport'] = a.wire
    _cut([a, b, c, d], a)
    _settle(clock)
    with at(b):
        federation.remove_member(iid(c), by='admin:b')
    _heal([a, b, c, d])
    with at(a):
        assert federation.catch_up()['adopted'] is True
        assert federation._runtime['view_conflict'] is False
    assert _view(a)[:2] == _view(b)[:2] == _view(d)[:2]
    # the view a just took starts its settle span: no cluster lease until it is over
    with at(a):
        r = fl.lease_round()
    assert r['pve-a']['held'] is False and r['pve-a']['refusals'].get('settling')
    _settle(clock)
    with at(a):
        r = fl.lease_round()
    assert r['pve-a']['held'] is True
    assert _writes(a, 'pve-a') is True


def test_a_change_too_few_took_is_rolled_back(tmp_path, clock):
    """a's removal of e reaches only b: a keeps its view and says so, b holds a view no
    majority holds. b finds that out and goes back; a's next try then goes through
    everywhere."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    base, base_b = _view(a), _view(b)

    def to_b_only(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH and url != URL['b']:
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = to_b_only
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.remove_member(iid(e), by='admin:a')
    assert err.value.code == 'FED_NO_QUORUM'
    assert _view(a) == base
    assert _view(b)[0] == base[0] + 1 and iid(e) not in _view(b)[2]
    a.runtime['transport'] = a.wire
    with at(b):
        out = federation.catch_up()
    assert out.get('rolled_back') is True
    assert _view(b) == base_b
    with at(b):
        # the view it gave up is taken again from a majority only
        assert federation._runtime['dead_views'][-1][0] == base[0] + 1
    with at(a):
        federation.remove_member(iid(e), by='admin:a')
    assert len({_view(s)[:2] for s in (a, b, c, d)}) == 1 and iid(e) not in _view(b)[2]


def test_two_views_of_one_epoch_converge(tmp_path, clock):
    """b holds a's removal of e, which nobody else took. c then removes d from the old
    view with a majority. b holds view N+1 with one member list, the others N+1 with
    another: b goes back and replays the majority's change, signed grants checked."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')

    def to_b_only(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH and url != URL['b']:
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = to_b_only
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.remove_member(iid(e), by='admin:a')
    a.runtime['transport'] = a.wire
    with at(c):
        federation.remove_member(iid(d), by='admin:c')
    va, vb = _view(a), _view(b)
    assert va[0] == vb[0] and va[1] != vb[1]
    with at(b):
        out = federation.catch_up()
    assert out['adopted'] is True
    assert _view(b)[:2] == _view(a)[:2] == _view(c)[:2] == _view(e)[:2]
    assert iid(d) not in _view(b)[2] and iid(e) in _view(b)[2]


# --- no single member makes a view up -------------------------------------------------------

def _forged_view(c_id, real_view, members, epoch=99, tombstones=None, commits=None):
    def view_body():
        body = real_view()
        if federation.instance_id() != c_id:
            return body
        return {'instance_id': c_id, 'view': {'epoch': epoch, 'members': members(body)},
                'tombstones': tombstones or {}, 'commits': commits or []}
    return view_body


def test_one_member_cannot_rewrite_a_view_through_catch_up(tmp_path, monkeypatch):
    """c claims a far newer view without b and with a member of its own, and c alone
    answers a's catch-up. Without a chain of changes signed by a majority, a takes none
    of it - nor c's word that a was removed."""
    a, b, c = _three(tmp_path)
    ia, ib, ic = iid(a), iid(b), iid(c)
    sybil = '5' * 32
    real_view, real_status = federation.peer_view_body, federation.peer_status_body

    def planted(body):
        out = {k: v for k, v in body['view']['members'].items() if k != ib}
        out[sybil] = {'url': URL['h'], 'public_key': some_key(), 'site': 'x',
                      'fingerprints': []}
        return out

    def forged_status():
        body = real_status()
        if federation.instance_id() == ic:
            body['view'] = {'epoch': 99, 'digest': 'x' * 32}
        return body
    # a chain c signs alone, right in every other respect: one grant is no majority of
    # three
    with at(c):
        base, epoch = federation.view_digest(), federation.view_epoch()
        lone = {ic: federation.lock_cert(ic, base, epoch)}
        entries = federation._view_entries(federation.identity())
    entries.pop(ib)
    chain = [{'epoch': epoch + 1, 'base': base, 'digest': federation._digest(entries),
              'by': ic, 'certs': lone, 'change': {'op': 'remove', 'instance_id': ib}}]
    monkeypatch.setattr(federation, 'peer_status_body', forged_status)
    a.runtime['transport'] = _without(a.wire, URL['b'])
    before = _view(a)
    for members, tombs, commits in ((planted, {}, []), (planted, {}, chain),
                                    (lambda body: {ic: body['view']['members'][ic]},
                                     {ia: {'public_key': some_key()}}, [])):
        monkeypatch.setattr(federation, 'peer_view_body',
                            _forged_view(ic, real_view, members, tombstones=tombs,
                                         commits=commits))
        with at(a):
            assert federation.catch_up()['adopted'] is False
        assert _view(a) == before
        with at(a):
            assert federation.identity()['removed'] is None
    # counterproof: the same catch-up path takes a real change, whose chain carries the
    # grants of a majority, from c alone
    monkeypatch.setattr(federation, 'peer_view_body', real_view)
    monkeypatch.setattr(federation, 'peer_status_body', real_status)
    d = Side(tmp_path, 'd')
    _wire([a, b, c, d])
    a.runtime['transport'] = _without(a.wire, URL['b'])
    b.runtime['transport'] = _without(b.wire, URL['a'])
    c.runtime['transport'] = _without(c.wire, URL['a'])
    _join(d, _code(c))
    assert iid(d) not in _view(a)[2]
    with at(a):
        assert federation.catch_up()['adopted'] is True
    assert iid(d) in _view(a)[2] and _view(a)[:2] == _view(c)[:2]


def test_a_member_cannot_squat_the_members_lock(tmp_path, clock):
    """c asks every voter for the members lock again and again. A voter renews it for one
    lock span at most and then makes c wait: a and b, the majority, take c out."""
    a, b, c = _three(tmp_path)
    lock = federation.MEMBERS_LOCK
    for voter in (a, b):
        assert _ask(voter, c, [lock])[1]['votes'][lock]['granted'] is True
    t = 0
    refused = None
    while t < fl.MEMBERS_LOCK_MAX + fl.LEASE_RENEW_AFTER:
        clock.advance(fl.LEASE_RENEW_AFTER)
        t += fl.LEASE_RENEW_AFTER
        v = _ask(a, c, [lock])[1]['votes'][lock]
        _ask(b, c, [lock])
        if not v['granted']:
            refused = v
            break
    assert refused is not None and refused['reason'] == 'busy'
    # while the last renewal still runs, a change waits for it
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.remove_member(iid(c), by='admin:a')
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    # c is in its cool-down: asking again gets it nothing
    assert _ask(a, c, [lock])[1]['votes'][lock]['reason'] == 'busy'
    with at(a):
        federation.remove_member(iid(c), by='admin:a')
    assert iid(c) not in _view(a)[2] and iid(c) not in _view(b)[2]


def test_one_lock_round_with_a_lost_release_still_renews(tmp_path, clock):
    """Counterproof for the bound above: a change right after another one, whose lock
    release did not arrive, renews the lock and goes through."""
    a, b, c, d = _sides(tmp_path, 'abcd')
    a.runtime['transport'] = _lossy(a.wire, commits=False)
    with at(a):
        federation.remove_member(iid(d), by='admin:a')
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        federation.remove_member(iid(c), by='admin:a')
    assert _view(a)[2] == [iid(b)]


# --- the promise table stays bounded ------------------------------------------------------------

def test_the_promise_table_stays_bounded(tmp_path, clock):
    """A member that asks for 256 made-up ids every lease span grows the voter's table to
    MAX_PROMISES and no further. A dead promise of an id the voter holds a row of is the
    last to go: it says whom the voter backed, which its mirror follows."""
    a, b, c = _three(tmp_path)
    _add_cluster(b, 'pve-row', owner=iid(c))
    _settle(clock)
    assert _ask(b, a, ['pve-row'], adopt=True)[1]['votes']['pve-row']['granted'] is True
    for rnd in range(12):
        clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
        ids = [f'z{rnd}-{i}' for i in range(fl.MAX_PROMISES_PER_CANDIDATE)]
        status, answer = _ask(b, a, ids)
        assert status == 200
        assert all(v['granted'] for v in answer['votes'].values())
        with at(b):
            assert len(federation._lease_state()['promises']) <= fl.MAX_PROMISES
    with at(b):
        assert fl.backed_candidates().get('pve-row') == iid(a)
    # the table on disk is bounded with it
    with open(b.lease_file) as fh:
        assert len(json.load(fh)['promises']) <= fl.MAX_PROMISES


# --- an old owner never takes a moved cluster back ----------------------------------------------

def test_an_old_owner_does_not_retake_a_cluster_its_adopter_unenrolled(tmp_path, clock):
    """a is cut off, b adopts a's cluster, c follows, b unenrolls it (b's own now, b and c
    dropped their copies). a comes back with its row still enrolled: the voters' records
    of the dropped rows name b, a's round finds a majority naming b and its row becomes
    b's mirror. Nobody but b writes the cluster."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c)
    _cut([a, b, c], a)
    _settle(clock)
    with at(b):
        fl.adopt_cluster('pve-k')
    _sync(c)
    with at(b):
        fl.unenroll_cluster('pve-k')
    for voter in (b, c):
        with at(voter):
            assert federation.dropped_records().get('pve-k') == iid(b)
    _heal([a, b, c])
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        r = fl.lease_round()['pve-k']
    assert r['held'] is False and r['lost_to'] == iid(b)
    assert _owner_at(a, 'pve-k') == iid(b)
    assert [s.name for s in (a, b, c) if _owner_at(s, 'pve-k') is not None
            and _writes(s, 'pve-k')] == ['b']


def test_without_the_records_the_old_owner_would_retake_it(tmp_path, clock):
    """Counterproof: the same story with the voters' records wiped, and a's round is
    backed again - the records are what stops it."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c)
    _cut([a, b, c], a)
    _settle(clock)
    with at(b):
        fl.adopt_cluster('pve-k')
    _sync(c)
    with at(b):
        fl.unenroll_cluster('pve-k')
    for voter in (b, c):
        with at(voter):
            federation._mutate_identity(lambda ident: ident['dropped'].clear() or True)
    _heal([a, b, c])
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        assert fl.lease_round()['pve-k']['held'] is True


@pytest.mark.parametrize('how', ['removed', 'left'])
def test_a_site_with_old_enrolled_rows_pairs_with_nobody(tmp_path, clock, how):
    """b adopts the cluster of a lost site a and removes it (or a leaves with force). a's
    row stays enrolled and closed: a pairs with no new instance and with nobody of the
    old federation, in either direction, until its admin unenrolls the row with force."""
    a, b, c = _three(tmp_path)
    x = Side(tmp_path, 'd')
    _wire([a, b, c, x])
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c)
    _cut([a, b, c, x], a)
    _settle(clock)
    with at(b):
        fl.adopt_cluster('pve-k')
    if how == 'removed':
        with at(b):
            federation.remove_member(iid(a), by='admin:test')
        _heal([a, b, c, x])
        with at(a):
            federation.catch_up()
            assert federation._check_removed_by() is True
    else:
        with at(a):
            federation.leave(force=True)
        _heal([a, b, c, x])
    with at(a):
        assert federation.members() == {}
        assert federation.cluster_owner('pve-k') == federation.instance_id()
        assert federation._lease_state()['my_leases']['pve-k']['released'] is True
        with pytest.raises(federation.FederationError) as err:
            federation.create_pairing_code(URL['a'])
        assert err.value.code == 'FED_ENROLLED'
    with pytest.raises(federation.FederationError) as err:
        _join(a, _code(b))
    assert err.value.code == 'FED_ENROLLED'
    assert _writes(a, 'pve-k') is False
    # the operator's override: unenrolled with force, the cluster is a's own and a pairs
    with at(a):
        fl.unenroll_cluster('pve-k', force=True)
    _join(x, _code(a))
    assert iid(x) in _view(a)[2]


# --- releases: by pid, and never overtaken by a round ---------------------------------------------

def test_a_release_during_a_round_writes_no_lease(tmp_path, clock, monkeypatch):
    """The admin presses Release while a round is still asking: the round got a majority,
    but its entry was released meanwhile - no lease is written, the promises it got are
    given back, and the voter that adopts is the only writer."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-r', password='r-secret')
    _sync(b, c)
    _settle(clock)
    with at(a):
        assert fl.lease_round()['pve-r']['held'] is True
    monkeypatch.setattr(federation, '_parallel',
                        lambda fn, items, max_workers=None: [fn(i) for i in items])
    asked = []

    def wire(url, method, path, body, headers):
        if path == federation.LEASE_PATH and json.loads(body).get('asks') and len(asked) < 2:
            asked.append(url)
            if len(asked) == 2:
                fl.release('pve-r')
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = wire
    with at(a):
        r = fl.lease_round()['pve-r']
        mine = dict(federation._lease_state()['my_leases']['pve-r'])
    a.runtime['transport'] = a.wire
    assert r['held'] is False and mine['released'] is True
    assert _writes(a, 'pve-r') is False
    # the grants the overtaken round got went back: no voter still backs a
    for voter in (b, c):
        with at(voter):
            assert fl.promised_to('pve-r', iid(a)) is False
    first = {URL['b']: b, URL['c']: c}[asked[0]]
    with at(first):
        assert fl.adopt_cluster('pve-r')['held'] is True
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-r')] == [first.name]


def test_a_late_release_ends_no_newer_promise(tmp_path, clock):
    """a releases, its release calls time out, and a takes the cluster back with an enroll
    at once. The release reaches the voters afterwards: it names the old promises, so it
    ends nothing, and no other site can adopt while a writes."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-l', password='l-secret')
    _sync(b, c)
    _settle(clock)
    held_back = []

    def wire(url, method, path, body, headers):
        if path == federation.LEASE_PATH and json.loads(body).get('releases'):
            held_back.append((url, method, path, body, headers))
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = wire
    with at(a):
        fl.release('pve-l')
        assert fl.enroll_cluster('pve-l')['held'] is True
    a.runtime['transport'] = a.wire
    assert held_back
    for call in held_back:
        status, raw, _h = a.wire(*call)
        assert status == 200 and json.loads(raw)['released'] == []
    for voter in (b, c):
        with at(voter):
            assert fl.promised_to('pve-l', iid(a)) is True
    with at(c):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-l')
    assert err.value.code == 'FED_OWNER_ALIVE'
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-l')] == ['a']


def test_a_release_marks_only_a_row_led_here(tmp_path):
    """A release of a cluster led here that has no lease entry yet (its first round is still
    out) leaves a released one for that round to find; a release of a cluster that is gone
    (a deleted row) leaves nothing behind."""
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'pve-new', owner=iid(a))
    with at(a):
        fl.release('pve-new')
        fl.release('pve-gone')
        held = federation._lease_state()['my_leases']
    assert held['pve-new']['released'] is True and held['pve-new']['rseq'] == 1
    assert 'pve-gone' not in held


def test_a_release_with_the_right_pid_ends_the_promise(tmp_path, clock):
    """Counterproof: the release a holder sends right away names the promise it holds and
    ends it at every voter."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-p')
    with at(a):
        fl.release('pve-p')
    for voter in (b, c):
        with at(voter):
            rec = federation._lease_state()['promises']['pve-p']
            assert rec['released'] is True and rec['candidate'] == iid(a)


# --- a lease never spans two removals -------------------------------------------------------------

def test_a_lease_never_outlives_two_removals(tmp_path, clock):
    """Five sites; a reaches d and e but not b and c, and renews with a, d and e. b removes
    d, then e, and tries to adopt with b and c - a majority of what is left. a's lease from
    the round before is still running: the voters that took the removals back no new
    adoption until every lease counted before them has run out."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c, d, e)
    a.runtime['transport'] = _without(a.wire, URL['b'], URL['c'])
    for s in (b, c):
        s.runtime['transport'] = _without(s.wire, URL['a'])
    _settle(clock)
    with at(a):
        assert fl.lease_round()['pve-k']['held'] is True
    clock.advance(2)
    with at(b):
        federation.remove_member(iid(d), by='admin:test')
        federation.remove_member(iid(e), by='admin:test')
    clock.advance(2)
    with at(b):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-k')
    assert err.value.code == 'FED_NO_QUORUM' and 'changed members' in str(err.value)
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-k')] == ['a']
    # a cannot renew any more (d and e left the view) and its lease runs out; the settle
    # span ends after it, and then b takes the cluster over
    for _ in range(4):
        clock.advance(fl.LEASE_RENEW_AFTER)
        with at(a):
            fl.lease_round()
        writers = [s.name for s in (a, b, c) if _writes(s, 'pve-k')]
        assert len(writers) <= 1, writers
    with at(b):
        assert fl.adopt_cluster('pve-k')['held'] is True
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-k')] == ['b']


# --- a refused enroll keeps the local row --------------------------------------------------------

def test_a_refused_enroll_of_a_taken_id_keeps_the_local_row(tmp_path):
    """b leads pve-x; a has a local cluster under the same id (a copied database, say) and
    tries to enroll it. The federation refuses and says why; a's row keeps its
    credentials, stays a's own and its manager keeps running."""
    from unittest.mock import MagicMock
    from pegaprox import globals as g
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-x', password='b-secret')
    _sync(c)
    _add_cluster(a, 'pve-x', password='a-secret')
    stopped = []
    fake = MagicMock()
    fake.stop.side_effect = lambda: stopped.append('pve-x')
    g.cluster_managers['pve-x'] = fake
    try:
        with at(a):
            with pytest.raises(federation.FederationError) as err:
                fl.enroll_cluster('pve-x')
    finally:
        g.cluster_managers.pop('pve-x', None)
    assert err.value.code == 'FED_NO_QUORUM' and 'unique' in str(err.value)
    row = _db_of(a).conn.execute(
        "SELECT fed_owner, pass_encrypted FROM clusters WHERE id = 'pve-x'").fetchone()
    assert row['fed_owner'] == ''
    assert _db_of(a)._decrypt(row['pass_encrypted']) == 'a-secret'
    assert stopped == []
    with at(a):
        assert 'pve-x' not in federation._lease_state()['my_leases']


def test_a_refused_reenroll_keeps_the_hand_over(tmp_path, clock):
    """a released its cluster and b adopted it. a's admin enrolls it again: the majority
    names b, a's row becomes b's mirror, and the refused enroll does not roll that back
    into a row a leads without credentials."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-m', password='m-secret')
    _sync(b, c)
    with at(a):
        fl.release('pve-m')
    _settle(clock)
    with at(b):
        assert fl.adopt_cluster('pve-m')['held'] is True
    _sync(c)
    with at(a):
        with pytest.raises(federation.FederationError):
            fl.enroll_cluster('pve-m')
    assert _owner_at(a, 'pve-m') == iid(b)
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-m')] == ['b']


# --- a member forced off writes nothing it enrolled ----------------------------------------------

def test_a_forced_off_member_neither_manages_nor_writes_enrolled_rows(tmp_path, clock,
                                                                        monkeypatch):
    """PEGAPROX_FEDERATION=0 on a member: its peer routes answer 404, which the others read
    as a site that is gone, and one of them adopts. The forced-off member reads none of
    the rows a federation owns - no manager starts for them - and a write that asks its
    exit guard anyway is refused."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-off', password='o-secret')
    _enroll(b, 'pve-b', password='b-secret')
    _add_cluster(a, 'local-a', password='plain')
    _sync(a, b, c)
    off_at = iid(a)
    real = federation.forced
    monkeypatch.setattr(federation, 'forced',
                        lambda: 'off' if federation.instance_id() == off_at else real())
    _settle(clock)
    with at(b):
        assert fl.adopt_cluster('pve-off')['held'] is True
    with at(a):
        assert sorted(_db_of(a).get_all_clusters()) == ['local-a']
        assert _db_of(a).get_cluster('pve-off') is None
        with pytest.raises(federation.LeaseRefused):
            federation.guard_exit('pve-off', 'POST /nodes/n1/qemu/100/status/start')
        # the plain cluster of the same site is untouched by any of it
        federation.guard_exit('local-a', 'POST /nodes/n1/qemu/100/status/start')
    assert [s.name for s in (b, c) if _writes(s, 'pve-off')] == ['b']


# --- the parts of the protocol that keep it reachable and bounded ---------------------------------

FP_OLD = ':'.join(['AB'] * 32)
FP_NEW = ':'.join(['CD'] * 32)


def test_a_member_update_changes_the_senders_record_only(tmp_path):
    """A member's word about itself moves its own record at the others - address, site
    label, fingerprints - and nothing else: not another member's record, not the view."""
    a, b, c = _three(tmp_path)
    digest = _view(a)[1]
    with at(b):
        status, _body, _h = federation.call_peer(
            iid(a), 'POST', federation.MEMBER_UPDATE_PATH,
            {'url': 'https://b-moved.example:5000', 'site': 'b-moved',
             'fingerprints': [FP_NEW], 'instance_id': iid(c)})
    assert status == 200
    with at(a):
        rec_b, rec_c = federation.member_record(iid(b)), federation.member_record(iid(c))
    assert (rec_b['url'], rec_b['site'], rec_b['fingerprints']) == \
        ('https://b-moved.example:5000', 'b-moved', [FP_NEW])
    assert rec_c['url'] == URL['c']
    assert _view(a)[1] == digest
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.apply_member_update('9' * 32, {'url': URL['h']})
    assert err.value.code == 'FED_NOT_MEMBER'


def test_the_sync_pushes_a_renewed_certificate_once(tmp_path, monkeypatch):
    """The sync tick tells the members when this instance's certificate changed, once per
    change: a renewed self-signed certificate keeps the federation reachable."""
    a, b, c = _three(tmp_path)
    pushed = []

    def counting(url, method, path, body, headers):
        if path == federation.MEMBER_UPDATE_PATH:
            pushed.append(url)
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = counting
    fps = [FP_OLD]
    monkeypatch.setitem(federation._fp_provider, 'fn', lambda: list(fps))
    with at(a):
        federation._push_self_update()
    assert sorted(pushed) == sorted([URL['b'], URL['c']])
    with at(a):
        federation._push_self_update()
    assert len(pushed) == 2
    fps[:] = [FP_NEW]
    with at(a):
        federation._push_self_update()
    assert len(pushed) == 4
    with at(b):
        assert federation.member_record(iid(a))['fingerprints'] == [FP_NEW]


def test_two_views_of_one_epoch_without_a_majority_are_shown_and_left(tmp_path, monkeypatch):
    """A member answers with the epoch this instance holds and another member list, and no
    majority stands behind either: nothing is taken, and the status shows the conflict."""
    a, b, c = _three(tmp_path)
    ib = iid(b)
    real = federation.peer_status_body

    def other_list():
        body = real()
        if federation.instance_id() == ib:
            body['view'] = dict(body['view'], digest='e' * 32)
        return body
    monkeypatch.setattr(federation, 'peer_status_body', other_list)
    a.runtime['transport'] = _without(a.wire, URL['c'])
    before = _view(a)
    with at(a):
        assert federation.catch_up() == {'adopted': False}
        assert federation._runtime['view_conflict'] is True
    assert _view(a) == before
    # counterproof: the same member answering the view a holds is no conflict
    monkeypatch.setattr(federation, 'peer_status_body', real)
    with at(a):
        federation.catch_up()
        assert federation._runtime['view_conflict'] is False


def test_a_lost_lease_file_holds_while_the_view_has_members(tmp_path):
    """A voter that lost its lease file may have promised before: with other members in
    the view it holds for a lease span. One without members loses nothing by it."""
    import os
    from tests.test_federation import _restart
    a, b, c = _three(tmp_path)
    os.remove(b.lease_file)
    _restart(b)
    v = _ask(b, a, ['x1'])[1]['votes']['x1']
    assert v['granted'] is False and v['reason'] == 'hold'
    lone = Side(tmp_path, 'd')
    _wire([lone])
    with at(lone):
        federation.ensure_identity()
        assert not os.path.exists(lone.lease_file)
        assert fl.hold_left(federation._lease_state()) == 0


def test_the_kept_tables_are_bounded(tmp_path):
    """Tombstones, the kept commits and the records of dropped rows each keep their newest
    entries up to their bound."""
    ident = federation._blank_identity()
    for i in range(federation.MAX_TOMBSTONES + 1):
        federation._tombstone(ident, f'{i:032x}', {'public_key': 'k'}, 'test')
    assert len(ident['tombstones']) == federation.MAX_TOMBSTONES
    assert f'{0:032x}' not in ident['tombstones']
    assert f'{federation.MAX_TOMBSTONES:032x}' in ident['tombstones']
    for e in range(1, federation.MAX_COMMITS + 5):
        federation._record_change(ident, {'epoch': e - 1, 'members': {}},
                                  {'epoch': e, 'base': 'b', 'digest': 'd', 'change': {},
                                   'certs': {}, 'by': 'x'})
    assert [c['epoch'] for c in ident['commits']] == \
        list(range(5, federation.MAX_COMMITS + 5))
    a = Side(tmp_path, 'a')
    _wire([a])
    with at(a):
        federation.ensure_identity()
        federation.note_dropped((f'c{i}', 'f' * 32) for i in range(federation.MAX_DROPPED + 3))
        held = federation.dropped_records()
    assert len(held) == federation.MAX_DROPPED and 'c0' not in held
    assert f'c{federation.MAX_DROPPED + 2}' in held


# --- a commit carries its committer's signature over the change -----------------------------------

def _behind_by_one(tmp_path):
    """Sites a, b and c; d joins through C, the one of a and b whose id sorts last, while c
    is cut off from both, so c misses that one commit. M, the other one, holds the commit
    as a receiver and is asked before C when c catches up."""
    a, b, c = _three(tmp_path)
    d = Side(tmp_path, 'd')
    _wire([a, b, c, d])
    M, C = (a, b) if iid(a) < iid(b) else (b, a)
    for s in (a, b):
        s.runtime['transport'] = _without(s.wire, URL['c'])
    _join(d, _code(C))
    _heal([a, b, c, d])
    return a, b, c, d, M, C


def _hands_on_swapped(monkeypatch, M, C, change_for):
    """M serves C's commit of d's join with another change and the digest that change
    gives, keeping C's grants and C's name on it."""
    real = federation.peer_view_body
    iM, iC = iid(M), iid(C)

    def forged():
        body = real()
        if federation.instance_id() != iM:
            return body
        out = []
        for cm in body['commits']:
            if cm.get('by') == iC and cm['change']['op'] == 'add':
                change, digest = change_for(cm)
                cm = dict(cm, change=change, digest=digest)
            out.append(cm)
        body['commits'] = out
        return body
    monkeypatch.setattr(federation, 'peer_view_body', forged)


def _views_asked(side):
    """The members `side` asks for their whole view, in order."""
    asked = []
    inner = side.runtime['transport']

    def transport(url, method, path, body, headers):
        if path == federation.VIEW_PATH:
            asked.append(url)
        return inner(url, method, path, body, headers)
    side.runtime['transport'] = transport
    return asked


def _swap_for(swap, entries, ic, iC, idd, evil):
    def change_for(cm):
        if swap == 'remove the site behind':
            return ({'op': 'remove', 'instance_id': ic},
                    federation._digest({k: v for k, v in entries.items() if k != ic}))
        if swap == 'remove the committer':
            return ({'op': 'remove', 'instance_id': iC},
                    federation._digest({k: v for k, v in entries.items() if k != iC}))
        return (dict(cm['change'], public_key=evil, url=URL['h']),
                federation._digest(dict(entries, **{idd: evil})))
    return change_for


@pytest.mark.parametrize('swap', ['remove the site behind', 'remove the committer',
                                  'another key'])
def test_a_member_cannot_swap_the_change_of_anothers_commit(tmp_path, monkeypatch, swap):
    """M hands c the commit C made, with C's grants, but with a change of its own: c taken
    out, C taken out (its accounts dropped at c), or d added with a key and an address of
    M's choice. C's signature does not cover that change, so c refuses M's chain and
    replays the real one from C."""
    from tests.test_federation import _add_local_user, _users
    a, b, c, d, M, C = _behind_by_one(tmp_path)
    _add_local_user(C, 'carol')
    _sync(c)
    assert 'carol' in _users(c)
    with at(c):
        entries = federation._view_entries(federation.identity())
    with at(d):
        d_key = federation.public_key()
    ic, iC, idd = iid(c), iid(C), iid(d)
    _hands_on_swapped(monkeypatch, M, C, _swap_for(swap, entries, ic, iC, idd, some_key()))
    asked = _views_asked(c)
    with at(c):
        assert federation.catch_up()['adopted'] is True
    # M's chain was read before C's, and refused
    assert URL[M.name] in asked and asked.index(URL[M.name]) < asked.index(URL[C.name])
    assert _view(c)[:2] == _view(a)[:2] == _view(d)[:2]
    with at(c):
        assert federation.identity()['removed'] is None
        assert iC in federation.members()
        assert federation.member_record(idd)['public_key'] == d_key
        assert federation.member_record(idd)['url'] == URL['d']
    assert 'carol' in _users(c)


def test_without_the_commit_signature_the_swapped_change_would_be_taken(tmp_path,
                                                                         monkeypatch):
    """Counterproof for the test above: with the check of the committer's signature taken
    out, the same swapped chain passes the grants and c takes itself for removed by C.
    The grants alone do not bind the change."""
    a, b, c, d, M, C = _behind_by_one(tmp_path)
    with at(c):
        entries = federation._view_entries(federation.identity())
    _hands_on_swapped(monkeypatch, M, C, _swap_for('remove the site behind', entries,
                                                   iid(c), iid(C), iid(d), some_key()))
    monkeypatch.setattr(federation, '_commit_signed', lambda c_, entries_: True)
    with at(c):
        federation.catch_up()
        assert (federation.identity()['removed'] or {}).get('by') == iid(C)


def test_a_commit_without_its_committers_signature_is_refused(tmp_path):
    """A receiver takes a commit only with the sender's signature over that very change,
    grants of a majority or not."""
    a, b, c = _three(tmp_path)
    with at(b):
        def promise(st):
            st['promises'][federation.MEMBERS_LOCK] = {'candidate': iid(c),
                                                       'until': fl._lease_now() + 30,
                                                       'released': False}
            return True
        federation._mutate_leases(promise)
        base, epoch = federation.view_digest(), federation.view_epoch()
        entries = federation._view_entries(federation.identity())
    rec = {'url': URL['d'], 'public_key': some_key(), 'site': 'd', 'fingerprints': []}
    digest = federation._digest(dict(entries, **{'d' * 32: rec['public_key']}))
    change = {'op': 'add', 'instance_id': 'd' * 32, **rec}
    certs = {}
    for voter in (b, c):
        with at(voter):
            certs[iid(voter)] = federation.lock_cert(iid(c), base, epoch)
    commit = {'epoch': epoch + 1, 'base': base, 'digest': digest, 'change': change,
              'certs': certs, 'by': iid(c)}
    with at(c):
        other = dict(change, url=URL['h'])
        wrong = federation._sign_commit(epoch + 1, base, digest, federation._wire_change(other))
        right = federation._sign_commit(epoch + 1, base, digest, federation._wire_change(change))
    for sig in (None, wrong):
        body = dict(commit, sig=sig) if sig else commit
        with at(c):
            status, answer, _h = federation.call_peer(iid(b), 'POST',
                                                      federation.MEMBERSHIP_PATH, body)
        assert status == 400 and answer['code'] == 'FED_BAD_CHANGE', answer
        assert 'd' * 32 not in _view(b)[2]
    with at(c):
        status, answer, _h = federation.call_peer(iid(b), 'POST', federation.MEMBERSHIP_PATH,
                                                  dict(commit, sig=right))
    assert status == 200, answer
    with at(b):
        assert federation.member_record('d' * 32)['url'] == URL['d']
        assert federation.identity()['commits'][-1]['sig'] == right


# --- a member record comes from its owner or from a signed commit ------------------------------------

FP_EVIL = ':'.join(['EE'] * 32)


def test_a_catch_up_takes_no_record_of_a_third_member_from_its_source(tmp_path, monkeypatch,
                                                                       clock):
    """c misses d's join through T. M serves its view with T listed at an address and a
    certificate of M's own. c replays the chain from M but keeps T's record as T told it;
    d comes with the record its committer signed. Once T sees that c's view moved, it
    tells c its record again. c then holds its lease with three of the four votes."""
    a, b, c = _three(tmp_path)
    d = Side(tmp_path, 'd')
    _wire([a, b, c, d])
    M, T = (a, b) if iid(a) < iid(b) else (b, a)
    iT = iid(T)
    _enroll(c, 'pve-c')
    with at(T):
        federation._push_self_update()
        federation.catch_up()
    with at(c):
        held = federation.member_record(iT)
    assert held['url'] == URL[T.name]
    for s in (a, b):
        s.runtime['transport'] = _without(s.wire, URL['c'])
    _join(d, _code(T))
    _heal([a, b, c, d])
    real = federation.peer_view_body

    def forged():
        body = real()
        if federation.instance_id() == iid(M):
            body['view']['members'][iT] = dict(body['view']['members'][iT], url=URL['h'],
                                               fingerprints=[FP_EVIL])
        return body
    monkeypatch.setattr(federation, 'peer_view_body', forged)
    asked = _views_asked(c)
    with at(c):
        assert federation.catch_up()['adopted'] is True
    # the chain came from M, whose listing names the forged record
    assert asked[-1] == URL[M.name] and URL[T.name] not in asked
    with at(c):
        rec = federation.member_record(iT)
        assert rec['url'] == URL[T.name] and rec['fingerprints'] == held['fingerprints']
        assert federation.member_record(iid(d))['url'] == URL['d']
    pushed = []
    inner = T.runtime['transport']

    def watch(url, method, path, body, headers):
        if path == federation.MEMBER_UPDATE_PATH:
            pushed.append(url)
        return inner(url, method, path, body, headers)
    T.runtime['transport'] = watch
    with at(T):
        federation.catch_up()
        federation._push_self_update()
    assert URL['c'] in pushed
    _settle(clock)
    with at(c):
        r = fl.lease_round(only={'pve-c'})['pve-c']
    assert r['held'] is True and r['votes'] == 4


# --- an unenroll notice records only what the voter saw ------------------------------------------

def _notice(sender, voter, cids):
    with at(sender):
        body = {'candidate': federation.instance_id(), 'view': federation.view_digest(),
                'epoch': federation.view_epoch(), 'asks': [], 'releases': [],
                'unenroll': list(cids)}
        if voter is sender:
            return federation.cast_votes(federation.instance_id(), body)
        return federation.call_peer(iid(voter), 'POST', federation.LEASE_PATH, body)[:2]


def test_an_unenroll_notice_records_nothing_the_sender_never_led(tmp_path):
    """c says it unenrolls a's cluster id, which it never led: the voters acknowledge and
    keep no record naming c, and a enrolls its cluster. Counterproof: a's own unenroll
    later is on record at b, whose row named a, and b refuses c's ask for the id."""
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'pve-a')
    for voter in (a, b, c):
        st, ans = _notice(c, voter, ['pve-a'])
        assert st == 200 and ans['unenrolled'] == ['pve-a']
    for s in (a, b, c):
        with at(s):
            assert 'pve-a' not in federation.dropped_records()
    with at(a):
        assert fl.enroll_cluster('pve-a')['held'] is True
    _sync(b, c)
    with at(a):
        assert fl.unenroll_cluster('pve-a') is True
    with at(b):
        assert federation.dropped_records().get('pve-a') == iid(a)
    v = _ask(b, c, ['pve-a'])[1]['votes']['pve-a']
    assert v['granted'] is False and v['reason'] == 'owner'


def test_a_flood_of_unenroll_notices_keeps_the_real_records(tmp_path):
    """c sends 512 made-up ids as unenroll notices. None of them is recorded, so the
    record of the id a unenrolled stays and b keeps refusing c's ask for it."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-x')
    _sync(b, c)
    with at(a):
        assert fl.unenroll_cluster('pve-x') is True
    for start in (0, 256):
        st, _ans = _notice(c, b, [f'zz{i:04d}' for i in range(start, start + 256)])
        assert st == 200
    with at(b):
        held = federation.dropped_records()
    assert held.get('pve-x') == iid(a) and not [k for k in held if k.startswith('zz')]
    v = _ask(b, c, ['pve-x'])[1]['votes']['pve-x']
    assert v['granted'] is False and v['reason'] == 'owner'


def test_the_linked_view_names_no_cluster_that_is_not_enrolled(tmp_path):
    """The others learn a cluster's id once it is enrolled. A member that read the ids of
    clusters not enrolled yet could claim them first, under a row of its own."""
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'pve-a', name='alpha')
    _enroll(a, 'pve-e')
    with at(c):
        st, body, _h = federation.call_peer(iid(a), 'GET', federation.CLUSTERS_PATH)
    assert st == 200
    rows = {r['name']: r for r in body['clusters']}
    assert 'id' not in rows['alpha'] and rows['pve-e']['id'] == 'pve-e'
    with at(c):
        shown = federation.federation_clusters()['peers'][iid(a)]['clusters']
    assert sorted((r['name'], r.get('id')) for r in shown) == [('alpha', None),
                                                              ('pve-e', 'pve-e')]
    with at(a):
        assert {r['id'] for r in federation.federation_clusters()['self']} == {'pve-a', 'pve-e'}


def test_the_kept_records_go_by_age_and_a_flood_loses_its_own(tmp_path):
    """The identity row is stored with sorted keys, so a dict read back is in id order. The
    bounds go by the time a record was made: the oldest goes, not the smallest id. Past
    the bound of the dropped records, the member named most often loses its own first."""
    a, b, c = _three(tmp_path)
    with at(b):
        federation.note_dropped([('zz-old', iid(a))])
        federation.note_dropped([('aa-newer', iid(a))])
        federation.note_dropped([(f'mm{i:04d}', iid(a))
                                 for i in range(federation.MAX_DROPPED - 1)])
        held = federation.dropped_records()
    assert len(held) == federation.MAX_DROPPED
    assert 'zz-old' not in held and 'aa-newer' in held
    with at(c):
        federation.note_dropped([('pve-x', iid(a))])
        federation.note_dropped([(f'zz{i:04d}', iid(b))
                                 for i in range(federation.MAX_DROPPED + 10)])
        held = federation.dropped_records()
    assert len(held) == federation.MAX_DROPPED and held.get('pve-x') == iid(a)
    assert 'zz0000' not in held and f'zz{federation.MAX_DROPPED + 9:04d}' in held
    ident = federation._blank_identity()
    for i in range(federation.MAX_TOMBSTONES):
        # the first removal has the largest id
        federation._tombstone(ident, f'{federation.MAX_TOMBSTONES - i:032x}',
                              {'public_key': 'k'}, 'test')
    ident = json.loads(json.dumps(ident, sort_keys=True))
    federation._tombstone(ident, 'f' * 32, {'public_key': 'k'}, 'test')
    assert f'{federation.MAX_TOMBSTONES:032x}' not in ident['tombstones']
    assert f'{1:032x}' in ident['tombstones'] and 'f' * 32 in ident['tombstones']


# --- no cluster lease counts in the settle span --------------------------------------------------

def _split(groups):
    every = [s for g in groups for s in g]
    for g in groups:
        others = [URL[s.name] for s in every if s not in g]
        for s in g:
            s.runtime['transport'] = _without(s.wire, *others)


def _one_writer_through(clock, sides, cid, rounds):
    """Lease rounds of every side, one lease tick apart: never two writers of `cid`."""
    for _ in range(rounds):
        clock.advance(fl.LEASE_RENEW_AFTER)
        for s in sides:
            with at(s):
                fl.lease_round()
            writers = [x.name for x in sides if _writes(x, cid)]
            assert len(writers) <= 1, writers


@pytest.mark.parametrize('removals', [1, 2])
def test_the_old_owner_waits_out_the_settle_span(tmp_path, clock, removals):
    """The network splits {a, c} | {b, d, e}; b adopts pve-k with b, d and e. The split
    moves to {a, b, c} | {d, e}, and a removes d (and e). a's next ask as the owner is no
    adoption, yet a and c are in the settle span of the removals, and b's lease from its
    adoption round still runs: they back no cluster ask until it has run out. With one
    removal the overlap of the two majorities stops a anyway (the counterproof)."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c, d, e)
    with at(b):
        federation.fetch_field_keys()
    _split([[a, c], [b, d, e]])
    for _ in range(4):
        clock.advance(fl.LEASE_RENEW_AFTER)
        with at(a):
            fl.lease_round()
    with at(b):
        assert fl.adopt_cluster('pve-k')['held'] is True
    _split([[a, b, c], [d, e]])
    clock.advance(1)
    with at(a):
        federation.remove_member(iid(d), by='admin:a')
        if removals == 2:
            federation.remove_member(iid(e), by='admin:a')
    clock.advance(1)
    with at(a):
        r = fl.lease_round()['pve-k']
    assert r['held'] is False
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-k')] == ['b']
    _one_writer_through(clock, [a, b, c], 'pve-k', 6)


def test_the_old_owners_fresh_grants_wait_out_the_settle_span(tmp_path, clock):
    """As above, but a asks nothing while the network is split, so its promises have run
    out and its later grants at a and c are fresh ones, not renewals."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c, d, e)
    with at(b):
        federation.fetch_field_keys()
    _split([[a, c], [b, d, e]])
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(b):
        assert fl.adopt_cluster('pve-k')['held'] is True
    for _ in range(4):
        clock.advance(fl.LEASE_RENEW_AFTER)
        with at(b):
            assert fl.lease_round()['pve-k']['held'] is True
    for s in (a, c):
        with at(s):
            assert not fl.promised_to('pve-k', iid(a))
    _split([[a, b, c], [d, e]])
    clock.advance(1)
    with at(a):
        federation.remove_member(iid(d), by='admin:a')
        federation.remove_member(iid(e), by='admin:a')
    clock.advance(1)
    with at(a):
        assert fl.lease_round()['pve-k']['held'] is False
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-k')] == ['b']
    _one_writer_through(clock, [a, b, c], 'pve-k', 6)


def test_a_renewal_of_a_failed_adoption_waits_out_the_settle_span(tmp_path, clock):
    """a holds pve-k with a, d and e. b's adoption gets b and c only (2 of 3), and b's
    process dies before it gives the promises back. b removes d, then e: under {a, b, c}
    the live promises at b and c would count as renewals and give b a lease while a's
    still runs. In the settle span they count for nothing."""
    from tests.test_federation import _restart
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c, d, e)
    with at(b):
        federation.fetch_field_keys()
    a.runtime['transport'] = _without(a.wire, URL['b'], URL['c'])
    for s in (b, c):
        s.runtime['transport'] = _without(s.wire, URL['a'])
    _settle(clock)
    with at(a):
        assert fl.lease_round()['pve-k']['held'] is True
    clock.advance(1)
    with at(b):
        r = fl.lease_round(only={'pve-k'}, adopt={'pve-k'})['pve-k']
    assert r['held'] is False and r['votes'] == 2
    _restart(b)
    clock.advance(1)
    with at(b):
        federation.remove_member(iid(d), by='admin:b')
        federation.remove_member(iid(e), by='admin:b')
    clock.advance(1)
    with at(b):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-k')
    assert err.value.code == 'FED_NO_QUORUM' and 'changed members' in str(err.value)
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-k')] == ['a']


# --- a rollback is decided by counting the view before ------------------------------------------

def _settles_down(clock, sides, rounds=5):
    """A few sync and lease ticks everywhere on a healthy network: the removal check and
    the catch-up of the sync tick, then a lease round."""
    for _ in range(rounds):
        clock.advance(federation.SYNC_INTERVAL)
        for s in sides:
            with at(s):
                if not federation._check_removed_by():
                    federation.catch_up()
        for s in sides:
            with at(s):
                fl.lease_round()


def test_two_members_of_a_change_too_few_took_both_roll_back(tmp_path, clock):
    """a removes e; the commit reaches b, and c, whose answer is lost; d and e get none. a
    counts 2 of 3 and keeps its view, while b and c hold the new one. Each sees the other
    holding it, yet a, d and e - a majority of the view before - answer with that view:
    no majority took the change, and both roll back. b leads its cluster again."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(b, 'pve-b', password='b-secret')
    base = _view(a)
    inner = a.wire

    def lossy(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH:
            if url == URL['b']:
                return inner(url, method, path, body, headers)
            if url == URL['c']:
                inner(url, method, path, body, headers)
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = lossy
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.remove_member(iid(e), by='admin:a')
    assert err.value.code == 'FED_NO_QUORUM'
    a.runtime['transport'] = a.wire
    assert _view(a) == base and _view(b)[:2] == _view(c)[:2] != base[:2]
    with at(b):
        assert federation.catch_up().get('rolled_back') is True
    _settles_down(clock, [a, b, c, d, e])
    assert len({_view(s)[:2] for s in (a, b, c, d, e)}) == 1
    assert _view(b)[:2] == base[:2]
    assert _writes(b, 'pve-b') is True


def test_a_view_a_majority_holds_is_not_rolled_back_on_the_makers_word(tmp_path, clock):
    """a removes e; b, c and d apply it, the answers of c and d are lost, so a gives up. 3
    of the 4 members of the new view hold it. b, reaching only a (and e), sees the maker
    answer the old view - that proves nothing, and b keeps the view. Once the network
    heals, every site ends on the new view, a included, and c leads its cluster."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(c, 'pve-c', password='c-secret')
    base = _view(a)
    inner = a.wire

    def lossy(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH:
            if url in (URL['c'], URL['d']):
                inner(url, method, path, body, headers)
                return 0, b'', {}
            if url == URL['e']:
                return 0, b'', {}
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = lossy
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.remove_member(iid(e), by='admin:a')
    assert err.value.code == 'FED_NO_QUORUM'
    a.runtime['transport'] = a.wire
    new = _view(b)[:2]
    assert _view(c)[:2] == _view(d)[:2] == new != base[:2]
    b.runtime['transport'] = _without(b.wire, URL['c'], URL['d'])
    with at(b):
        out = federation.catch_up()
    assert out.get('rolled_back') is not True and _view(b)[:2] == new
    b.runtime['transport'] = b.wire
    _settles_down(clock, [a, b, c, d, e])
    assert {_view(s)[:2] for s in (a, b, c, d)} == {new}
    with at(e):
        assert federation.identity()['removed'] is not None
    assert _writes(c, 'pve-c') is True


# --- one change of the view at a time -------------------------------------------------------------

def test_a_second_change_at_the_same_site_waits_for_the_first(tmp_path, clock, monkeypatch):
    """While a's removal of e builds its commit, a second change at a (another admin, a
    pairing) starts: it would get the members lock as a renewal and commit from the same
    base. It is refused with FED_BUSY, the first one goes through, and the second one goes
    through afterwards."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    real = federation._kept_certs
    seen = {}

    def kept(certs):
        if 'second' not in seen and federation.instance_id() == iid(a):
            seen['second'] = 'started'
            try:
                federation.remove_member(iid(b), by='admin:a-second')
                seen['second'] = 'ok'
            except federation.FederationError as err:
                seen['second'] = err.code
        return real(certs)
    monkeypatch.setattr(federation, '_kept_certs', kept)
    with at(a):
        federation.remove_member(iid(e), by='admin:a-first')
    monkeypatch.setattr(federation, '_kept_certs', real)
    assert seen == {'second': 'FED_BUSY'}
    assert len({_view(s)[:2] for s in (a, b, c, d)}) == 1 and iid(e) not in _view(a)[2]
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        federation.remove_member(iid(b), by='admin:a-second')
    assert len({_view(s)[:2] for s in (a, c, d)}) == 1 and iid(b) not in _view(a)[2]


# --- a join whose answer got lost ----------------------------------------------------------------

def test_a_join_whose_answer_got_lost_finishes_with_the_same_code(tmp_path, clock):
    """a adds d and spends the code, but its answer never reaches d. d asks again with the
    same code and takes the view: a member that never votes would raise the majority, so
    that one of the three real sites down would stop every lease."""
    a, b, c = _three(tmp_path)
    d = Side(tmp_path, 'd')
    _wire([a, b, c, d])
    _enroll(a, 'pve-a')
    code = _code(a)
    inner = d.wire

    def lose_the_answer(url, method, path, body, headers):
        if path == federation.JOIN_PATH:
            inner(url, method, path, body, headers)
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    d.runtime['transport'] = lose_the_answer
    with pytest.raises(federation.FederationError):
        _join(d, code)
    d.runtime['transport'] = d.wire
    assert iid(d) in _view(a)[2] and _view(d)[2] == []
    _join(d, code)
    assert _view(d)[:2] == _view(a)[:2]
    # the spent code answers d alone: another joiner with it is refused
    stranger = Side(tmp_path, 'e')
    _wire([a, b, c, d, stranger])
    with pytest.raises(federation.FederationError):
        _join(stranger, code)
    assert iid(stranger) not in _view(a)[2]
    _cut([a, b, c, d, stranger], c)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(a):
        r = fl.lease_round()['pve-a']
    assert r['held'] is True and r['votes'] == 3 and r['needed'] == 3


# --- the vote budget of a member --------------------------------------------------------------

class _PerVoter:
    """A production budget, one window per voter, as on separate hosts (the harness runs
    every side in one process)."""

    def __init__(self, limit, name):
        self.limit, self.name, self.windows = limit, name, {}

    def allow(self, key):
        from pegaprox.utils.ratelimit import SlidingWindow
        me = federation.instance_id()
        if me not in self.windows:
            self.windows[me] = SlidingWindow(limit=self.limit, window=30, max_keys=256,
                                             name=f'{self.name}-{me[:6]}')
        return self.windows[me].allow(key)


def _production_budgets(monkeypatch):
    from pegaprox.api import federation as api_fed
    monkeypatch.setattr(api_fed, '_lease_votes', _PerVoter(api_fed.LEASE_VOTE_BUDGET, 'v'))
    monkeypatch.setattr(api_fed, '_lease_ticks', _PerVoter(api_fed.LEASE_TICK_BUDGET, 't'))
    monkeypatch.setattr(api_fed, '_lease_returns',
                        _PerVoter(api_fed.LEASE_RETURN_BUDGET, 'r'))


def _many_enrolled(side, n):
    me = iid(side)
    db = _db_of(side)
    for i in range(n):
        db.conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, "
                        "fed_owner, cluster_type) VALUES (?, ?, 'h', 'u', '', ?, 'proxmox')",
                        (f'pve{i:02d}', f'pve{i:02d}', me))
    db.conn.commit()
    with at(side):
        fl.drop_owner_cache()
        r = fl.lease_round()
    assert all(r[f'pve{i:02d}']['held'] for i in range(n))


def test_a_site_with_forty_enrolled_clusters_leaves_within_the_vote_budget(tmp_path, clock,
                                                                          monkeypatch):
    """The unenroll notices and the releases of every cluster go in one call per member,
    which the voters count apart from the votes: a leave of 40 clusters goes through."""
    a, b, c = _three(tmp_path)
    _many_enrolled(a, 40)
    _sync(b, c)
    _production_budgets(monkeypatch)
    with at(a):
        assert federation.leave()['left'] is True
    assert {_owner_at(a, f'pve{i:02d}') for i in range(40)} == {''}
    for s in (b, c):
        assert {_owner_at(s, f'pve{i:02d}') for i in range(40)} == {None}
        assert iid(a) not in _view(s)[2]


def test_a_burst_of_admin_rounds_leaves_the_renewals_alone(tmp_path, clock, monkeypatch):
    """Sixty renewals an admin (or a script) starts use up the budget of admin rounds at
    the voters; the background round has its own and keeps every lease. Counterproof: an
    admin round right after is refused."""
    a, b, c = _three(tmp_path)
    _many_enrolled(a, 40)
    _production_budgets(monkeypatch)
    from pegaprox.api import federation as api_fed
    with at(a):
        for _ in range(api_fed.LEASE_VOTE_BUDGET):
            fl.renew('pve00')
        assert fl.lease_round(only={'pve01'})['pve01']['held'] is False
        r = fl.lease_round(tick=True)
    assert all(r[f'pve{i:02d}']['held'] for i in range(40))


# --- what an HA group decides travels with its identity -------------------------------------------

@pytest.mark.parametrize('host', ['active', 'promoted', 'lease file removed'])
def test_a_handed_over_cluster_stays_handed_over(tmp_path, clock, host):
    """a hands pve-h over. Neither a standby promoted after that nor a host whose lease
    file was removed leases it again, and b adopts it. The active itself is the
    counterproof."""
    import os
    from tests.test_federation import _restart, _standby_of
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-h', password='h')
    _sync(b, c)
    with at(a):
        fl.release('pve-h')
    acting = a
    if host == 'lease file removed':
        os.unlink(a.lease_file)
        _restart(a)
    if host == 'promoted':
        acting = _standby_of(tmp_path, a)
        URL[acting.name] = URL['a']
        _wire([acting, b, c])
    try:
        clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
        with at(acting):
            assert 'pve-h' not in fl.lease_round()
            assert fl.renew('pve-h')['released'] is True
            assert fl.lease_status()['leases'].get('pve-h', {'released': True})['released']
        assert _writes(acting, 'pve-h') is False
        with at(b):
            assert fl.adopt_cluster('pve-h')['held'] is True
    finally:
        URL.pop('a2', None)


@pytest.mark.parametrize('host', ['active', 'promoted', 'lease file removed'])
def test_an_adopted_cluster_stays_adopted(tmp_path, clock, host):
    """a adopts b's pve-y while c, d and e still name b. A standby promoted right after,
    or a host whose lease file was removed, asks with the adoption flag: the round holds
    and the row keeps a as its owner and its credentials. Once a majority of the voters'
    rows name a, the flag goes. The active itself is the counterproof."""
    import os
    from tests.test_federation import _restart, _standby_of
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(b, 'pve-y', password='y-secret')
    _sync(a, c, d, e)
    with at(a):
        federation.fetch_field_keys()
    _cut([a, b, c, d, e], b)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(a):
        assert fl.adopt_cluster('pve-y')['held'] is True
    assert {_owner_at(s, 'pve-y') for s in (c, d, e)} == {iid(b)}
    acting = a
    if host == 'lease file removed':
        os.unlink(a.lease_file)
        _restart(a)
    if host == 'promoted':
        acting = _standby_of(tmp_path, a)
        URL[acting.name] = URL['a']
        _wire([acting, c, d, e])
    try:
        with at(acting):
            r = fl.lease_round()['pve-y']
            assert federation.adopted_from() == {'pve-y': iid(b)}
        assert r['held'] is True
        row = _db_of(acting).conn.execute(
            "SELECT fed_owner, pass_encrypted FROM clusters WHERE id = 'pve-y'").fetchone()
        assert row['fed_owner'] == iid(a) and row['pass_encrypted']
        _sync(c, d, e)
        clock.advance(fl.LEASE_RENEW_AFTER)
        with at(acting):
            assert fl.lease_round()['pve-y']['held'] is True
            assert federation.adopted_from() == {}
    finally:
        URL.pop('a2', None)


# --- a renewal from an older round, delayed on its way ----------------------------------------

def _renewal(voter, sender, cid, mark):
    with at(sender):
        body = {'candidate': federation.instance_id(), 'view': federation.view_digest(),
                'epoch': federation.view_epoch(), 'asks': [{'cluster_id': cid, 'adopt': False}],
                'releases': [], 'round': mark}
    with at(voter):
        return federation.cast_votes(body['candidate'], body)


def _promise_at(voter, cid):
    with at(voter):
        return dict(federation._lease_state()['promises'].get(cid) or {})


def test_a_late_renewal_of_an_older_round_keeps_the_newer_promise(tmp_path, clock):
    """a's round R1 for pve-r is in flight when the admin hands the cluster over and
    enrolls it again: R2 is granted with a new pid. R1's ask then reaches b late. It is
    refused and b's promise keeps R2's pid, so R1, stale at a, gives back nothing that
    backs R2's lease, and neither does a release of the promise b gave before R2."""
    a, b, c = _three(tmp_path)
    st, ans = _renewal(b, a, 'pve-r', 500.0)
    p0 = ans['pids']['pve-r']
    st, ans = _renewal(b, a, 'pve-r', 2000.0)
    assert st == 200 and ans['votes']['pve-r']['granted'] is True
    p2 = ans['pids']['pve-r']
    assert p2 != p0
    st, ans = _renewal(b, a, 'pve-r', 1000.0)
    assert st == 200
    assert ans['votes']['pve-r'] == {'granted': False, 'reason': 'stale'}
    assert 'pids' not in ans
    assert _promise_at(b, 'pve-r')['pid'] == p2
    # the release of the promise before the newer one, late on its way, ends nothing
    with at(a):
        fl._send_releases('pve-r', {iid(b): p0})
    held = _promise_at(b, 'pve-r')
    assert held['pid'] == p2 and held['released'] is False
    # counterproof: the same release by the pid that backs the lease ends it
    with at(a):
        fl._send_releases('pve-r', {iid(b): p2})
    assert _promise_at(b, 'pve-r')['released'] is True


def test_the_round_marks_of_one_instance_grow(tmp_path, clock, monkeypatch):
    """A round that started before a release carries a smaller mark than one after it,
    whatever the wall clock does in between."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-m')
    seen = []
    real = fl.cast_votes

    def spy(sender, body):
        if body.get('asks'):
            seen.append(body.get('round'))
        return real(sender, body)
    monkeypatch.setattr(fl, 'cast_votes', spy)
    monkeypatch.setattr(fl.time, 'time', lambda: 1_000_000.0)
    with at(a):
        fl.lease_round()
        fl.lease_round()
    assert len(seen) == 2 and seen[1] > seen[0]


@pytest.mark.parametrize('kept', [True, False], ids=['kept', 'lost'])
def test_a_restart_after_the_wall_clock_stepped_back_keeps_the_lease(tmp_path, clock,
                                                                     monkeypatch, kept):
    """NTP steps a's wall clock back by five seconds, then a restarts. The last mark of its
    rounds is in the lease file, so the next round goes on from it and every voter grants
    it. Counterproof: without the mark in the file (the 'lost' case) the voters, its own
    included, refuse the round as stale."""
    import time
    from tests.test_federation import _restart
    a, b, c = _three(tmp_path)
    wall = {'t': time.time() + 60}
    monkeypatch.setattr(fl.time, 'time', lambda: wall['t'])
    _enroll(a, 'pve-w')
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        assert fl.lease_round()['pve-w']['held']
    wall['t'] -= 5
    if not kept:
        with open(a.lease_file, encoding='utf-8') as fh:
            st = json.load(fh)
        st.pop('round_mark', None)
        with open(a.lease_file, 'w', encoding='utf-8') as fh:
            json.dump(st, fh)
    _restart(a)
    clock.advance(fl.LEASE_RENEW_AFTER)
    with at(a):
        r = fl.lease_round()['pve-w']
    if kept:
        assert r['held'] and 'stale' not in r['refusals'], r
    else:
        assert not r['held'] and r['refusals'].get('stale') == 3, r


# --- an unenroll notice and an adoption under way ---------------------------------------------

def test_a_voter_backing_an_adoption_does_not_confirm_the_old_owners_unenroll(tmp_path, clock):
    """b adopts a's pve-u while c's row still names a, and c grants it. a's unenroll notice
    then reaches c: c neither drops its row nor confirms, so a does not take the cluster
    as its own beside b's lease. Counterproof: once c's promise to b ran out, it does."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-u')
    _sync(b, c)
    # a's renewals stopped (a split): its promise at c runs out, then b asks to adopt
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    v = _ask(c, b, ['pve-u'], adopt=True)[1]['votes']['pve-u']
    assert v['granted'] is True
    st, ans = _notice(a, c, ['pve-u'])
    assert st == 200 and ans['unenrolled'] == []
    assert _owner_at(c, 'pve-u') == iid(a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    st, ans = _notice(a, c, ['pve-u'])
    assert st == 200 and ans['unenrolled'] == ['pve-u']
    assert _owner_at(c, 'pve-u') is None


def test_a_voter_that_holds_after_a_reboot_confirms_no_unenroll(tmp_path, clock, monkeypatch):
    """A voter in its hold may have forgotten an adoption it backed: it confirms nothing."""
    from tests.test_federation import _reboot
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-v')
    _sync(b, c)
    _reboot(c, monkeypatch)
    with at(c):
        federation._mutate_leases(lambda st: fl.check_clock(st))
    st, ans = _notice(a, c, ['pve-v'])
    assert st == 200 and ans['unenrolled'] == []
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    assert _notice(a, c, ['pve-v'])[1]['unenrolled'] == ['pve-v']


# --- a removal one member took alone -----------------------------------------------------------

def _mapping_of(side, home):
    return [tuple(r) for r in _db_of(side).conn.execute(
        'SELECT kind, home_value, local_value FROM federation_identity_map WHERE home = ?',
        (home,)).fetchall()]


def _mirror_user(side, home, name):
    db = _db_of(side)
    db.conn.execute("INSERT INTO users (username, password_salt, password_hash, role, "
                    "created_at, enabled, fed_home) VALUES (?, 's', 'h', 'user', '2026', 1, ?)",
                    (name, home))
    db.conn.execute("INSERT OR REPLACE INTO federation_identity_map (home, kind, home_value, "
                    "local_value) VALUES (?, 'tenant', 'default', 'default')", (home,))
    db.conn.commit()


def test_a_removal_rolled_back_keeps_the_members_mappings(tmp_path, clock):
    """a's removal of e reaches only b. b takes e out of the view and disables e's accounts
    at once, but keeps them and the mapping an admin made: the change is rolled back, and a
    mapping dropped for it would not come back with the next pull. Once the removal goes
    through everywhere and a majority holds it, b drops them."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _mirror_user(b, iid(e), 'erin')

    def to_b_only(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH and url != URL['b']:
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = to_b_only
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.remove_member(iid(e), by='admin:a')
    a.runtime['transport'] = a.wire
    assert iid(e) not in _view(b)[2]
    assert _mapping_of(b, iid(e)) == [('tenant', 'default', 'default')]
    row = _db_of(b).conn.execute("SELECT enabled FROM users WHERE username = 'erin'").fetchone()
    assert row is not None and row['enabled'] == 0
    with at(b):
        assert federation.catch_up().get('rolled_back') is True
        assert federation.identity()['drop_pending'] == {}
    assert iid(e) in _view(b)[2]
    assert _mapping_of(b, iid(e)) == [('tenant', 'default', 'default')]
    # the removal again, now taken by everyone: b drops e's data once a majority holds it
    with at(a):
        federation.remove_member(iid(e), by='admin:a')
    assert _mapping_of(b, iid(e)) == [('tenant', 'default', 'default')]
    with at(b):
        federation.catch_up()
    assert _mapping_of(b, iid(e)) == []
    assert _db_of(b).conn.execute(
        "SELECT 1 FROM users WHERE username = 'erin'").fetchone() is None


def test_a_rolled_back_removal_brings_the_accounts_back_with_the_next_pull(tmp_path, clock):
    """The same removal that reaches only b, with an account of e that b holds and an
    admin there mapped. b disables it at once; the rollback leaves it disabled, and the
    next pull from e brings it back."""
    from tests.test_federation import _add_local_user, _map, _row
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _add_local_user(e, 'erin', role='user', tenant='default')
    _sync(b)
    _map(b, e, 'tenant', 'default', 'default')
    _sync(b)
    assert _row(b, 'erin')['enabled'] == 1

    def to_b_only(url, method, path, body, headers):
        if path == federation.MEMBERSHIP_PATH and url != URL['b']:
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = to_b_only
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.remove_member(iid(e), by='admin:a')
    a.runtime['transport'] = a.wire
    assert _row(b, 'erin')['enabled'] == 0
    with at(b):
        assert federation.catch_up().get('rolled_back') is True
    # the rollback itself enables nothing: the pull does
    assert _row(b, 'erin')['enabled'] == 0
    _sync(b)
    assert _row(b, 'erin')['enabled'] == 1


def test_a_later_change_settles_a_removal_taken_before(tmp_path, clock):
    """b took a's removal of e; a's next change is made from that view with a majority's
    grants, which shows a majority took the removal: b drops e's data when it applies it."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _mirror_user(b, iid(e), 'erin')
    with at(a):
        federation.remove_member(iid(e), by='admin:a')
    assert _mapping_of(b, iid(e)) == [('tenant', 'default', 'default')]
    _settle(clock)
    with at(a):
        federation.remove_member(iid(d), by='admin:a')
    assert _mapping_of(b, iid(e)) == []


def test_the_sync_tick_keeps_what_a_removal_waiting_for_a_majority_holds(tmp_path, clock):
    """b took a's removal of e, which waits for a majority. e is out of b's view, so the
    orphan sweeps of b's sync tick would take e's account, mapping and cluster row for
    leftovers: they leave them to the settling, which a rollback would otherwise find
    gone. Counterproof: settled, they are gone."""
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _mirror_user(b, iid(e), 'erin')
    db = _db_of(b)
    db.conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner, "
                    "cluster_type) VALUES ('pve-e', 'pve-e', 'h', 'u', '', ?, 'proxmox')",
                    (iid(e),))
    db.conn.commit()
    with at(a):
        federation.remove_member(iid(e), by='admin:a')
    with at(b):
        assert iid(e) in federation.identity()['drop_pending']
        assert federation.drop_orphan_mirrors() == []
        assert federation._sweep_cluster_orphans() == 0
    assert _mapping_of(b, iid(e)) == [('tenant', 'default', 'default')]
    assert db.conn.execute("SELECT 1 FROM users WHERE username = 'erin'").fetchone() is not None
    assert db.conn.execute("SELECT 1 FROM clusters WHERE id = 'pve-e'").fetchone() is not None
    with at(b):
        federation.catch_up()
        assert federation.identity()['drop_pending'] == {}
    assert _mapping_of(b, iid(e)) == []
    assert db.conn.execute("SELECT 1 FROM clusters WHERE id = 'pve-e'").fetchone() is None


def _left_alone(b, home):
    with at(b):
        pending = federation.identity().get('drop_pending') or {}
        blockers = federation.disable_blockers()
    gone = _db_of(b).conn.execute("SELECT 1 FROM users WHERE username = 'anna'").fetchone() is None
    return pending, blockers, gone and _mapping_of(b, home) == []


def test_the_last_other_member_that_leaves_is_dropped_at_once(tmp_path, clock):
    """A federation of two, and a leaves. b is alone in the view: no member is left that
    could roll the removal back, so what b holds of a goes at once - the mirrored account,
    its mapping - and nothing of a keeps b's switch on. Waiting for a majority to show it
    took the removal, b would wait for ever."""
    a, b = _sides(tmp_path, 'ab')
    _mirror_user(b, iid(a), 'anna')
    with at(a):
        federation.leave()
    assert _view(b)[2] == []
    assert _left_alone(b, iid(a)) == ({}, [], True)


def test_a_removal_still_pending_when_alone_settles_at_the_next_catch_up(tmp_path, clock):
    """The same from catch_up, for a removal that waits while b is alone in the view (one
    taken before b ran this code): there is nobody to ask, and it settles. Counterproof:
    pending, it keeps the account and names 'mirrors'."""
    a, b = _sides(tmp_path, 'ab')
    with at(a):
        federation.leave()
    _mirror_user(b, iid(a), 'anna')
    with at(b):
        federation._defer_drop(iid(a), federation.view_epoch())
    pending, blockers, gone = _left_alone(b, iid(a))
    assert iid(a) in pending and blockers == ['mirrors'] and not gone
    with at(b):
        assert federation.catch_up() == {'adopted': False}
    assert _left_alone(b, iid(a)) == ({}, [], True)


# --- what the snapshot carries of a credential that does not open --------------------------------

def test_a_credential_that_does_not_open_at_the_owner_keeps_the_mirrors_copy(tmp_path):
    """a's stored password of pve-w is damaged. a's snapshot carries it as null, and b
    keeps the wrapped copy it holds instead of wiping it: that copy is what an adoption
    opens once a is gone. Counterproof: a credential a really removed is wiped."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-w', password='w-secret')
    _sync(b)

    def held():
        return _db_of(b).conn.execute(
            "SELECT pass_encrypted FROM clusters WHERE id = 'pve-w'").fetchone()[0]
    good = held()
    assert good.startswith(federation.FIELD_PREFIX)
    _db_of(a).conn.execute("UPDATE clusters SET pass_encrypted = 'aes256:broken' "
                           "WHERE id = 'pve-w'")
    _db_of(a).conn.commit()
    with at(a):
        rows = federation.enrolled_cluster_rows()
    assert rows[0]['pass_encrypted'] is None
    _sync(b)
    assert held() == good
    _db_of(a).conn.execute("UPDATE clusters SET pass_encrypted = '' WHERE id = 'pve-w'")
    _db_of(a).conn.commit()
    _sync(b)
    assert held() == ''


# --- one pull of a member at a time ---------------------------------------------------------------

def test_two_pulls_of_one_member_never_apply_out_of_order(monkeypatch):
    """The worker's pull fetched snapshot S1 and stalls; the admin's sync starts meanwhile.
    It waits for the first one and then fetches afresh, so S2 is applied last."""
    import threading
    started, go = threading.Event(), threading.Event()
    fetched, applied = [], []

    def call_peer(sender, method, path, body, extra_headers=None, cap=None):
        n = len(fetched)
        fetched.append(n)
        if n == 0:
            started.set()
            go.wait(5)
        return 200, {'etag': f'e{n}', 'n': n}, {}
    monkeypatch.setattr(federation, 'member_record', lambda s: {'url': 'https://m.example'})
    monkeypatch.setattr(federation, 'sync_state', lambda: {})
    monkeypatch.setattr(federation, 'call_peer', call_peer)
    monkeypatch.setattr(federation, 'apply_identity_snapshot',
                        lambda body, sender: applied.append(body['n']) or {'applied': 1})
    first = threading.Thread(target=federation.pull_identities, args=('m' * 32,))
    first.start()
    assert started.wait(5)
    second = threading.Thread(target=federation.pull_identities, args=('m' * 32,))
    second.start()
    second.join(0.3)
    assert second.is_alive(), 'the second pull ran beside the first'
    go.set()
    first.join(5)
    second.join(5)
    assert applied == [0, 1]


# --- the identity mapping at its bound -------------------------------------------------------------

def test_a_value_replacing_one_at_the_mapping_cap_gets_its_row(tmp_path):
    a, b = _sides(tmp_path, 'ab')
    db = _db_of(a)
    home = 'h' * 32
    held = {}
    for i in range(federation.MAX_MAP_ROWS - 1):
        db.conn.execute("INSERT INTO federation_identity_map (home, kind, home_value, "
                        "local_value, users) VALUES (?, 'tenant', ?, 'default', 1)",
                        (home, f't{i}'))
        held[('tenant', f't{i}')] = ('default', 1)
    db.conn.execute("INSERT INTO federation_identity_map (home, kind, home_value, local_value, "
                    "users) VALUES (?, 'tenant', 'old', '', 1)", (home,))
    held[('tenant', 'old')] = ('', 1)
    seen = {k: 1 for k in held if k != ('tenant', 'old')}
    seen[('tenant', 'new')] = 1
    with at(a):
        federation._note_unmapped(db.conn, home, held, seen)
    db.conn.commit()
    values = {r[0] for r in db.conn.execute(
        'SELECT home_value FROM federation_identity_map WHERE home = ?', (home,))}
    assert 'new' in values and 'old' not in values
    assert len(values) == federation.MAX_MAP_ROWS


# --- a 304 on the wire -------------------------------------------------------------------------------

def test_a_304_on_the_wire_is_the_unchanged_answer(monkeypatch):
    """The conditional identity pull answers 304 when nothing changed. On the wire that is
    no redirect: the status reaches the caller, which confirms the snapshot it holds."""
    class Resp:
        status_code = 304
        headers = {'X-Test': '1'}

        def close(self):
            pass

    class Sess:
        def request(self, *a, **k):
            return Resp()
    monkeypatch.setattr(federation, '_url_ok', lambda url: True)
    monkeypatch.setattr(federation, '_session_for', lambda url, fp: Sess())
    monkeypatch.setattr(federation, '_read_capped', lambda resp, cap: b'')
    status, raw, headers = federation._wire_call('https://m.example:5000', [], 'GET',
                                                 federation.IDENTITIES_PATH, None, {}, 5, 1024)
    assert status == 304 and raw == b'' and headers == {'X-Test': '1'}
    Resp.status_code = 302
    assert federation._wire_call('https://m.example:5000', [], 'GET', '/x', None, {}, 5,
                                 1024)[0] == 0


# --- the pairing secret is not kept --------------------------------------------------------------------

def test_the_lease_file_keeps_no_pairing_secret(tmp_path):
    a, b = _sides(tmp_path, 'ab')
    code = _code(a)
    secret = federation.ha_wire.decode_code(federation.CODE_PREFIX, code)['secret']
    with open(a.lease_file) as fh:
        raw = fh.read()
    assert secret and secret not in raw
    with at(a):
        assert federation.pairing_open() is not None
    # the code still works: c joins with it
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    _join(c, code)
    assert iid(c) in _view(a)[2]
    # spent, the code stays on file for that joiner's retry: by its hash alone
    with open(a.lease_file) as fh:
        raw = fh.read()
    spent = json.loads(raw)['pairing_spent']
    assert spent['joiner'] == iid(c) and spent['secret_hash']
    assert secret not in raw and secret not in json.dumps(spent)


# --- a save over a mirror ------------------------------------------------------------------------------

def test_no_save_writes_over_another_members_mirror(tmp_path):
    """A restore or a late save_config reaches a row b mirrors of a's cluster: get_cluster
    hides it, so it looks new. The save is refused and the wrapped credential stays."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-s', password='s-secret')
    _sync(b)
    db = _db_of(b)
    before = db.conn.execute("SELECT pass_encrypted, fed_owner FROM clusters "
                             "WHERE id = 'pve-s'").fetchone()
    assert before['fed_owner'] == iid(a)
    with at(b):
        assert db.get_cluster('pve-s') is None
        with pytest.raises(ValueError):
            db.save_cluster('pve-s', {'name': 'restored', 'host': 'old-host', 'user': 'root@pam',
                                      'pass': 'from-the-backup'})
    after = db.conn.execute("SELECT pass_encrypted, host FROM clusters "
                            "WHERE id = 'pve-s'").fetchone()
    assert after['pass_encrypted'] == before['pass_encrypted'] and after['host'] != 'old-host'
    # counterproof: a's own enrolled row is saved as before
    with at(a):
        _db_of(a).save_cluster('pve-s', dict(_db_of(a).get_cluster('pve-s'), name='renamed'))
    assert _db_of(a).conn.execute("SELECT name FROM clusters WHERE id = 'pve-s'").fetchone()[0] \
        == 'renamed'


# --- a cluster this instance deleted ----------------------------------------------------------------------

def test_a_deleted_enrolled_cluster_stays_on_record(tmp_path, clock):
    """b led pve-d and went dark; a adopted it and later deletes it. b comes back and asks
    for the id as its owner: a's vote refuses it (the record names a), so b gets no
    majority with c, which refuses as well."""
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-d', password='d-secret')
    _sync(a, c)
    with at(a):
        federation.fetch_field_keys()
    _cut([a, b, c], b)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(a):
        assert fl.adopt_cluster('pve-d')['held'] is True
        owner = federation.cluster_owner('pve-d')
    _db_of(a).delete_cluster('pve-d')
    with at(a):
        federation.forget_deleted_cluster('pve-d', owner)
        assert federation.dropped_records().get('pve-d') == iid(a)
    _heal([a, b, c])
    v = _ask(a, b, ['pve-d'])[1]['votes']['pve-d']
    assert v['granted'] is False and v['reason'] == 'owner'


# --- a clusters table the federation migration did not reach --------------------------------------

def _without_fed_owner(db):
    db.conn.execute('ALTER TABLE clusters DROP COLUMN fed_owner')
    db.conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted) "
                    "VALUES ('pve-old', 'old', 'h', 'u', '')")
    db.conn.commit()
    db._fed_owner_ok = False


@pytest.mark.parametrize('switched_on', [False, True])
def test_a_missing_fed_owner_column_is_added_when_the_clusters_are_read(tmp_path, monkeypatch,
                                                                        switched_on):
    """The migration's ALTER failed at the start (a locked database). The clusters are
    read all the same: the column is added at the first read, and the rows load."""
    if not switched_on:
        monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    a = Side(tmp_path, 'a')
    db = _db_of(a)
    _without_fed_owner(db)
    with at(a):
        assert 'pve-old' in db.get_all_clusters()
        assert db.get_cluster('pve-old')['name'] == 'old'
    cols = [c[1] for c in db.conn.execute('PRAGMA table_info(clusters)')]
    assert 'fed_owner' in cols


def test_a_fed_owner_column_that_cannot_be_added_leaves_every_row_local(tmp_path, monkeypatch):
    """The column cannot be added either (the database takes no writes): every row is this
    instance's own then, as it was before the federation existed, and nothing breaks."""
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    a = Side(tmp_path, 'a')
    db = _db_of(a)
    _without_fed_owner(db)
    db.conn.execute('PRAGMA query_only = ON')
    try:
        with at(a):
            assert 'pve-old' in db.get_all_clusters()
            assert db.get_cluster('pve-old')['name'] == 'old'
    finally:
        db.conn.execute('PRAGMA query_only = OFF')
