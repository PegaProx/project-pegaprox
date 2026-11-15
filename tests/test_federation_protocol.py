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
