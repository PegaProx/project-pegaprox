"""A federation of two sites: the owner writes alone, the other site takes over by hand.

One of two is no majority. The owner of an enrolled cluster holds its lease on its own vote
while the other site gives no signed answer at all (or answers only 'hold'), once that site
granted it the cluster under this view; any other answer stops it. The other site never
adopts on its own: its admin takes a cluster over by hand, refused while the owner answers
or was heard lately, and the signed, numbered ownership record of that takeover makes the
old owner stop at the first contact between the two. With three or more sites a majority
decides as before, and the records act on nothing.

The harness is the one of tests/test_federation.py: several instances in one process, the
network a stand-in that routes each call into the side it names, the lease clock a
stand-in where time has to pass.

MK Nov 2026
"""
import base64
import json
import random
import time
from unittest.mock import MagicMock

import pytest

from pegaprox.core import federation, ha_wire
from pegaprox.core import federation_lease as fl
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _defaults_out_of_the_config_dir, _fresh_budgets, clock,
    Side, URL, _add_cluster, _code, _cut, _db_of, _enroll, _heal, _join, _owner_at,
    _reboot, _restart, _sides, _standby_of, _sync, _view, _wire, _without, _writes, at, iid,
    some_key)
from tests.test_federation_protocol import _settle

FedError = federation.FederationError


@pytest.fixture(autouse=True)
def _managers(monkeypatch):
    """No cluster manager starts here: a takeover or a resume notes the cluster instead."""
    started = []
    monkeypatch.setattr(fl, 'start_manager', lambda cid: started.append(cid) or False)
    return started


@pytest.fixture
def fed_audits(monkeypatch):
    """Every federation entry of the audit log: (instance, action, text)."""
    from pegaprox.utils import audit
    from pegaprox.api import federation as api_fed
    got = []

    def record(user, action, details=None, **kw):
        if action.startswith('federation.'):
            got.append((federation.instance_id(), action, details or ''))
    monkeypatch.setattr(audit, 'log_audit', record)
    monkeypatch.setattr(api_fed, 'log_audit', record)
    return got


def _cut_one_way(sides, frm, to):
    """The calls from `frm` to `to` get no answer; the other way works."""
    for s in sides:
        s.runtime['transport'] = s.wire
    frm.runtime['transport'] = _without(frm.wire, URL[to.name])


def _records(side):
    with at(side):
        return federation.ownership()['records']


def _ok(side):
    with at(side):
        return federation.ownership()['ok']


def _takeover(side, cid, **kw):
    with at(side):
        return fl.take_over_cluster(cid, by='admin:test', **kw)


def _round(side, **kw):
    with at(side):
        return fl.lease_round(**kw)


def _quiet(clock, *sides, seconds=36):
    """`seconds` pass on the lease clock in steps of ten at most, every one of `sides`
    running its lease round at each step."""
    left = seconds
    while left > 0:
        step = min(10, left)
        clock.advance(step)
        left -= step
        for s in sides:
            _round(s)


def _split_and_take(tmp_path, clock, cid='pve-x', password='x-secret'):
    """a enrolled `cid` and b holds its copy. The two are cut apart, a goes on writing
    alone, and after 36 s of silence b's admin takes the cluster over by hand."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, cid, password=password)
    _sync(b)
    _cut([a, b], a)
    _quiet(clock, a)
    out = _takeover(b, cid)
    return a, b, out


def _signed(side, rec):
    """`rec` signed with the key of `side`, whatever its fields say."""
    with at(side):
        rec = dict(rec)
        rec['sig'] = base64.b64encode(
            federation.signing_key().sign(federation._owner_message(rec))).decode()
    return rec


def _lease(side, cid):
    with at(side):
        return dict(federation._lease_state()['my_leases'].get(cid) or {})


# --- the lease rule --------------------------------------------------------------------------

def test_two_sites_enroll_with_both_answering(tmp_path, clock):
    """Two sites enroll a cluster when both grant it, and the enroll leaves a record (gen 1)
    with the note that lets the owner hold it alone later. With the other site silent an
    enroll is refused, a re-enroll after a hand-over too: that site may have adopted it
    meanwhile. Counterproof: enroll without `both` holds the re-enroll alone."""
    a, b = _sides(tmp_path, 'ab')
    lease = _enroll(a, 'pve-x')
    assert lease['held'] is True and lease['votes'] == 2 and lease['needed'] == 2
    assert lease['alone'] is False
    rec = _records(a)['pve-x']
    assert (rec['gen'], rec['kind'], rec['owner'], rec['from']) == (1, 'enroll', iid(a), '')
    assert _ok(a)['pve-x']['gen'] == 1
    # pushed right after the enroll, and echoed
    assert _records(b)['pve-x']['sig'] == rec['sig']
    with at(a):
        assert federation.ownership()['acked'][iid(b)] >= rec['n']
    _cut([a, b], b)
    _add_cluster(a, 'pve-y')
    with at(a):
        with pytest.raises(FedError) as err:
            fl.enroll_cluster('pve-y')
    assert err.value.code == 'FED_NO_QUORUM'
    assert 'enrolling needs both to answer: site-b did not' in str(err.value)
    assert _owner_at(a, 'pve-y') == ''
    assert _lease(a, 'pve-y') == {}
    with at(a):
        fl.release('pve-x')
        with pytest.raises(FedError) as err:
            fl.enroll_cluster('pve-x')
    assert err.value.code == 'FED_NO_QUORUM'
    assert _writes(a, 'pve-x') is False


def test_the_owner_keeps_writing_while_the_other_site_is_silent(tmp_path, clock):
    """b is down for 200 s: a renews alone every round and writes throughout, b never.
    Counterproof: no lease on the own vote, a stops 28 s after the cut."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    _cut([a, b], b)
    for _ in range(20):
        clock.advance(10)
        r = _round(a)['pve-x']
        assert r['held'] is True and r['alone'] is True and r['peer'] == 'silent', r
        assert r['votes'] == 1 and r['needed'] == 2
        _round(b)
        assert _writes(a, 'pve-x') is True
        assert _writes(b, 'pve-x') is False
    with at(a):
        assert fl.lease_status()['leases']['pve-x']['alone'] is True
        assert fl.renew('pve-x')['alone'] is True


def test_a_rebooted_other_site_does_not_stop_the_owner(tmp_path, clock, monkeypatch):
    """b's host rebooted: it answers 'hold' for 35 s and grants nobody. a holds alone
    through it, then with b again. Counterproof: 'hold' counted as a refusal, a stops."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _reboot(b, monkeypatch)
    seen = []
    for _ in range(5):
        clock.advance(10)
        r = _round(a)['pve-x']
        seen.append(r['peer'])
        assert r['held'] is True and _writes(a, 'pve-x') is True, r
    assert seen[:3] == ['hold'] * 3 and seen[-1] == 'granted'


@pytest.mark.parametrize('how', ['view', 'clock', 'table', 'row'])
def test_a_signed_answer_that_is_no_grant_stops_the_owner(tmp_path, clock, monkeypatch, how):
    """b answers, but not with a grant: another member list, a clock too far off, a table
    it cannot read, its row naming b. That is no outage: a's lease runs out and a stops,
    without giving its cluster up. Counterproof: every answer other than 200 taken for
    silence, a goes on writing alone."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    b_id = iid(b)
    if how == 'view':
        with at(b):
            federation._mutate_identity(lambda ident: ident['view']['members'].__setitem__(
                '9' * 32, {'url': 'https://z.example:5000', 'public_key': some_key(),
                           'site': 'z', 'fingerprints': []}) or True)
    elif how == 'clock':
        real = federation.signature_verdict

        def skewed(headers, method, path, body, sender, public_b64, receiver, now, started):
            v = real(headers, method, path, body, sender, public_b64, receiver, now, started)
            return 'window' if receiver == b_id and v == 'ok' else v
        monkeypatch.setattr(federation, 'signature_verdict', skewed)
    elif how == 'table':
        real_map = fl._owner_map

        def owner_map():
            if federation.instance_id() == b_id:
                raise FedError('the clusters table is gone')
            return real_map()
        monkeypatch.setattr(fl, '_owner_map', owner_map)
    else:
        _db_of(b).conn.execute("UPDATE clusters SET fed_owner = ? WHERE id = 'pve-x'", (b_id,))
        _db_of(b).conn.commit()
        with at(b):
            fl.drop_owner_cache()
    for _ in range(3):
        clock.advance(10)
        r = _round(a)['pve-x']
        assert r['held'] is False and r['peer'] == 'veto', r
    assert _writes(a, 'pve-x') is False
    assert _owner_at(a, 'pve-x') == iid(a)


def test_a_call_lost_while_the_other_site_answers_is_no_silence(tmp_path, clock, monkeypatch):
    """A round goes out in more than one call (one ask a call here). b answers the call
    for pve-1, the one for pve-2 gets lost: b runs and reaches a, so pve-2 is not held
    alone. b took pve-2 over and cannot call a, its record would have come back in the
    lost answer: a stops writing pve-2 once its lease runs out. Counterproof: the lost
    call taken for silence, a renews pve-2 alone beside b."""
    monkeypatch.setattr(fl, 'MAX_ASKS_PER_CALL', 1)
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-1')
    _enroll(a, 'pve-2')
    _sync(b)
    _cut([a, b], a)
    _quiet(clock, a)
    with at(b):
        fl.take_over_clusters(iid(a), ['pve-2'], by='admin:test', force=True)
    inner = a.wire

    def lossy(url, method, path, body, headers):
        if url == URL['b'] and path == federation.LEASE_PATH and body and any(
                ask.get('cluster_id') == 'pve-2' for ask in json.loads(body).get('asks') or []):
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = lossy
    b.runtime['transport'] = _without(b.wire, URL['a'])
    for _ in range(4):
        clock.advance(10)
        r = _round(a)
        assert r['pve-1']['held'] is True and r['pve-1']['peer'] == 'granted'
        assert r['pve-2']['held'] is False and r['pve-2']['peer'] == 'veto'
        _round(b)
    assert _writes(a, 'pve-2') is False and _writes(b, 'pve-2') is True
    assert _writes(a, 'pve-1') is True


def test_a_record_of_another_owner_holds_nothing_alone(tmp_path, clock):
    """a leads pve-x with the note to hold it alone, and holds a record that names b as
    its owner but moved no row (b's enroll under the same id, on the same generation and
    later). With b silent a does not hold it alone. Counterproof: the held record not
    looked at, a writes alone."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    mine = _records(a)['pve-x']
    rec = _signed(b, {'cluster_id': 'pve-x', 'gen': mine['gen'], 'kind': 'enroll',
                      'owner': iid(b), 'from': '', 'at': mine['at'] + 100, 'by': 'admin:test'})
    with at(a):
        assert fl.take_records(iid(b), [rec])['fenced'] == {}
    assert _records(a)['pve-x']['owner'] == iid(b) and _owner_at(a, 'pve-x') == iid(a)
    assert _ok(a)['pve-x']['gen'] == mine['gen']
    _cut([a, b], b)
    clock.advance(10)
    r = _round(a)['pve-x']
    assert r['held'] is False and r['alone'] is False and r['peer'] == 'silent'


def test_a_lease_held_alone_does_not_survive_a_restart(tmp_path, clock):
    """A lease both sites backed survives a restart of the service; one held alone is
    closed when the lease file is loaded, and the first round asks the other site first.
    So an old owner that b took over meanwhile never writes once the two reach each other.
    Counterproof: no close on load, a writes right after its restart."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    _restart(a)
    assert _writes(a, 'pve-x') is True
    _cut([a, b], b)
    clock.advance(10)
    assert _round(a)['pve-x']['alone'] is True
    _restart(a)
    assert _writes(a, 'pve-x') is False
    clock.advance(10)
    assert _round(a)['pve-x']['alone'] is True and _writes(a, 'pve-x') is True
    # b takes it over while a is cut off; a restarts with the network back
    _cut([a, b], a)
    _quiet(clock, a)
    _takeover(b, 'pve-x')
    _restart(a)
    _heal([a, b])
    assert _writes(a, 'pve-x') is False
    _round(a)
    assert _writes(a, 'pve-x') is False and _owner_at(a, 'pve-x') == iid(b)


def test_a_shrink_to_two_waits_for_one_grant_per_cluster(tmp_path, clock):
    """Three sites become two (c removed) while b is cut off: a holds nothing alone until b
    granted the cluster once under the new view. Counterproof: no 'ok' check, a holds
    alone at once."""
    a, b, c = _sides(tmp_path, 'abc')
    _enroll(a, 'pve-x')
    _sync(b)
    with at(a):
        federation.remove_member(iid(c), by='admin:test')
    _cut([a, b, c], b)
    _settle(clock)
    for _ in range(3):
        clock.advance(10)
        r = _round(a)['pve-x']
        assert r['held'] is False and r['peer'] == 'silent', r
    assert _writes(a, 'pve-x') is False
    _heal([a, b, c])
    assert _round(a)['pve-x']['votes'] == 2
    _cut([a, b, c], b)
    clock.advance(10)
    assert _round(a)['pve-x']['alone'] is True and _writes(a, 'pve-x') is True


@pytest.mark.parametrize('known', [False, True], ids=['record unknown', 'record known'])
def test_a_dispute_after_a_shrink_never_has_two_writers_and_resolves(tmp_path, clock, known):
    """Three sites: a is cut off and b adopts pve-x with c. Then c leaves with a's grant
    while b is down, and b catches up the view of two from a. Both rows claim the cluster.
    In a split neither writes it; once the two reach each other a gives it up (on b's
    newer record, or, when a held that record already, on b's refusal that shows it), and
    b holds it after a's grant. Counterproofs: no 'ok' check (both write in the split, the
    record unknown); no evidence rule (the record known: it stays closed at both)."""
    a, b, c = _sides(tmp_path, 'abc')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b, c)
    _cut([a, b, c], a)
    _settle(clock)
    with at(b):
        fl.adopt_cluster('pve-x')
    # with three sites b's next round hands the adoption record to c
    _round(b)
    if not known:
        # c never heard of the adoption record: nothing hands it to a
        with at(c):
            federation._reset_ownership()
    _heal([a, b, c])
    _cut([a, b, c], b)
    with at(c):
        federation.leave()
    _heal([a, b, c])
    with at(b):
        federation.catch_up()
    assert _view(a)[1] == _view(b)[1] and len(_view(a)[2]) == 1
    assert _owner_at(a, 'pve-x') == iid(a) and _owner_at(b, 'pve-x') == iid(b)
    held_at_a = _records(a)['pve-x']
    assert (held_at_a['owner'] == iid(b)) is known
    _cut([a, b], a)
    _settle(clock)
    for _ in range(4):
        clock.advance(10)
        _round(a)
        _round(b)
        assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == []
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b)
    assert _round(b)['pve-x']['votes'] == 2
    _cut([a, b], a)
    clock.advance(10)
    assert _round(b)['pve-x']['alone'] is True
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['b']


def test_the_other_site_never_takes_over_on_its_own(tmp_path, clock):
    """a is gone for ten minutes. b runs its rounds and its syncs all along: its row stays
    a's copy, nothing is promised to b, b never writes, and an adoption is told to use the
    manual takeover. Counterproof: without FED_USE_TAKEOVER the adoption runs a round."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    _cut([a, b], a)
    for _ in range(60):
        clock.advance(10)
        with at(b):
            fl.lease_round(tick=True)
            federation._sync_tick()
        assert _owner_at(b, 'pve-x') == iid(a) and _writes(b, 'pve-x') is False
    with at(b):
        assert fl.promised_to('pve-x', iid(b)) is False
        with pytest.raises(FedError) as err:
            fl.adopt_cluster('pve-x')
    assert err.value.code == 'FED_USE_TAKEOVER' and err.value.extra['owner'] == iid(a)
    assert 'Manual takeover' in str(err.value)


def test_a_two_site_round_across_a_view_change_writes_no_lease(tmp_path, clock):
    """A third site joins while a's asks are out: the answer of b was counted for a view of
    two that is gone, so the round writes no lease and gives the promises back. With three
    sites the round writes as before. Counterproof: no guard, the lease is written."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    before = _lease(a, 'pve-x')['expires']
    inner = a.wire
    done = []

    def join_meanwhile(url, method, path, body, headers):
        if path == federation.LEASE_PATH and not done and json.loads(body).get('asks'):
            done.append(1)
            federation._mutate_identity(lambda ident: ident['view']['members'].__setitem__(
                '9' * 32, {'url': 'https://z.example:5000', 'public_key': some_key(),
                           'site': 'z', 'fingerprints': []}) or True)
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = join_meanwhile
    clock.advance(5)
    r = _round(a)['pve-x']
    assert done and r['held'] is False and r['votes'] == 2
    assert _lease(a, 'pve-x')['expires'] == before
    with at(b):
        p = federation._lease_state()['promises']['pve-x']
    assert p['candidate'] == iid(a) and p['released'] is True
    # three sites: a moved view during the round costs nothing, as before
    (tmp_path / 'three').mkdir()
    x, y, z = _sides(tmp_path / 'three', 'abc')
    _enroll(x, 'pve-t')
    inner3 = x.wire
    done.clear()

    def join3(url, method, path, body, headers):
        if path == federation.LEASE_PATH and not done and json.loads(body).get('asks'):
            done.append(1)
            federation._mutate_identity(lambda ident: ident['view']['members'].__setitem__(
                '8' * 32, {'url': 'https://w.example:5000', 'public_key': some_key(),
                           'site': 'w', 'fingerprints': []}) or True)
        return inner3(url, method, path, body, headers)
    x.runtime['transport'] = join3
    clock.advance(5)
    r = _round(x)['pve-t']
    assert done and r['held'] is True


def test_three_sites_are_unchanged(tmp_path, clock):
    """Three sites: one silent member costs no lease and nothing is held alone, an owner
    that is cut off lapses within 28 s, an adoption goes by majority, a takeover by hand and
    a removal as gone are refused, and a record that beats the one held makes nobody give a
    cluster up. Counterproof: records acted on in every view size, a steps down."""
    a, b, c = _sides(tmp_path, 'abc')
    _enroll(a, 'pve-x', password='x')
    _sync(b, c)
    _cut([a, b, c], c)
    clock.advance(10)
    r = _round(a)['pve-x']
    assert r['held'] is True and r['alone'] is False and 'peer' not in r
    _cut([a, b, c], a)
    _quiet(clock, a, seconds=30)
    assert _writes(a, 'pve-x') is False
    clock.advance(6)
    with at(b):
        assert fl.adopt_cluster('pve-x')['held'] is True
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(a), by='admin:test', gone=True)
        assert err.value.code == 'FED_NOT_TWO_SITES'
    with at(c):
        with pytest.raises(FedError) as err:
            fl.take_over_cluster('pve-x', by='admin:test')
        assert err.value.code == 'FED_NOT_TWO_SITES'
    adopted = _records(b)['pve-x']
    assert adopted['kind'] == 'adopt' and adopted['gen'] == 2
    with at(a):
        got = fl.take_records(iid(b), [federation.wire_record(adopted)])
    assert got == {'echo': True, 'fenced': {}}
    assert _records(a)['pve-x']['sig'] == adopted['sig']
    assert _owner_at(a, 'pve-x') == iid(a)


def test_three_sites_send_no_records_inside_an_enroll_or_adoption(tmp_path, clock):
    """With three sites the records act on nothing: an enroll or an adoption makes no
    records-only call while the admin waits, so a site that is down costs the request no
    second timeout; the rounds and the sync carry them. Counterproof: the push to every
    member inside the request."""
    a, b, c = _sides(tmp_path, 'abc')
    pushed = []

    def counted(side):
        inner = side.runtime['transport']

        def transport(url, method, path, body, headers):
            data = json.loads(body) if path == federation.LEASE_PATH and body else {}
            if data.get('records') and not data.get('asks'):
                pushed.append((side.name, url))
            return inner(url, method, path, body, headers)
        side.runtime['transport'] = transport
    _enroll(a, 'pve-x')
    _sync(b, c)
    _cut([a, b, c], c)
    counted(a)
    _enroll(a, 'pve-y')
    assert pushed == []
    _heal([a, b, c])
    _cut([a, b, c], a)
    _quiet(clock, a, seconds=30)
    clock.advance(6)
    counted(b)
    with at(b):
        assert fl.adopt_cluster('pve-x')['held'] is True
    assert pushed == []


# --- the records ------------------------------------------------------------------------------

def test_records_are_signed_ordered_and_bounded(tmp_path, monkeypatch):
    """A record is its signer's word over every field, from a member of the view only. The
    order is generation, then takeover before adoption before enroll, then time, then
    owner, the same at every site. A body carries at most 32, and past 4096 kept the oldest
    go, never one of a row led here, not even when every row is. Counterproofs: comparing
    the generation alone; the bound dropping the oldest row led here."""
    a, b = _sides(tmp_path, 'ab')
    with at(a):
        rec = federation.sign_owner_record('pve-x', 3, 'takeover', iid(b), 'admin:test')
        digest, epoch = federation.view_digest(), federation.view_epoch()
    with at(b):
        assert federation.valid_owner_record(rec) == rec
        for field, other in (('cluster_id', 'pve-y'), ('gen', 4), ('kind', 'adopt'),
                             ('owner', iid(b)), ('from', 'e' * 32), ('at', rec['at'] + 1),
                             ('by', 'admin:else')):
            assert federation.valid_owner_record(dict(rec, **{field: other})) is None, field
        stranger = ha_wire.private_key(ha_wire.new_signing_key())
        alien = dict(rec, owner='e' * 32, sig='')
        alien['sig'] = base64.b64encode(stranger.sign(federation._owner_message(alien))).decode()
        assert federation.valid_owner_record(alien) is None
    beats = federation.record_beats
    assert beats(rec, None)
    assert beats(dict(rec, gen=4, kind='enroll'), rec) and not beats(rec, dict(rec, gen=4))
    assert beats(rec, dict(rec, kind='adopt', at=rec['at'] + 60))
    assert beats(dict(rec, kind='adopt'), dict(rec, kind='enroll', at=rec['at'] + 60))
    assert beats(dict(rec, at=rec['at'] + 1), rec)
    assert beats(dict(rec, owner='f' * 32), dict(rec, owner='0' * 32))
    assert not beats(rec, rec)
    base = {'candidate': iid(a), 'view': digest, 'epoch': epoch, 'asks': [], 'releases': []}
    with at(b):
        for bad in ({'records': [rec] * (fl.MAX_RECORDS_PER_CALL + 1)}, {'records': 'x'},
                    {'records': ['x']}, {'records': [rec], 'records_upto': -1},
                    {'records': [rec], 'records_upto': True}):
            assert federation.cast_votes(iid(a), dict(base, **bad)) == (400, {'reason': 'body'})
        status, answer = federation.cast_votes(iid(a), dict(base, records=[rec],
                                                            records_upto=7))
    assert status == 200 and answer['records_upto'] == 7
    _add_cluster(a, 'kept-0', owner=iid(a))
    with at(a):
        own = federation._blank_ownership()
        conn = _db_of(a).conn
        for i in range(federation.MAX_OWNER_RECORDS + 1):
            federation.store_record(own, dict(rec, cluster_id=f'kept-{i}'), conn)
    assert len(own['records']) == federation.MAX_OWNER_RECORDS
    assert 'kept-0' in own['records'] and 'kept-1' not in own['records']
    monkeypatch.setattr(federation, 'MAX_OWNER_RECORDS', 2)
    for cid in ('led-0', 'led-1', 'led-2'):
        _add_cluster(a, cid, owner=iid(a))
    with at(a):
        own = federation._blank_ownership()
        for cid in ('led-0', 'led-1', 'led-2'):
            federation.store_record(own, dict(rec, cluster_id=cid), conn)
    assert sorted(own['records']) == ['led-0', 'led-1', 'led-2']


@pytest.mark.parametrize('way', ['b to a only', 'a to b only'])
def test_a_record_crosses_a_one_way_split(tmp_path, clock, way):
    """b took a's cluster over, and the link comes back one way only. Either way a hears of
    it and gives the cluster up: in b's call, or in b's answer to its own. Counterproofs:
    no records in the bodies (b to a), none in the answers (a to b)."""
    a, b, _ = _split_and_take(tmp_path, clock)
    if way == 'b to a only':
        _cut_one_way([a, b], a, b)
        _round(b)
    else:
        _cut_one_way([a, b], b, a)
        _round(a)
    assert _owner_at(a, 'pve-x') == iid(b) and _writes(a, 'pve-x') is False


def test_a_fresh_enroll_is_never_turned_into_a_copy_by_a_record(tmp_path, clock):
    """b leads pve-x under the record of its takeover, and a enrolls a local cluster of its
    own under the same id. b refuses naming itself and shows its record, yet the enroll is
    only refused: a's row stays its own with its credentials. Counterproof: neither enroll
    shield, a's own cluster becomes b's copy and its password is gone."""
    a, b = _sides(tmp_path, 'ab')
    _add_cluster(b, 'pve-x', owner=iid(b))
    with at(b):
        rec = federation.sign_owner_record('pve-x', 2, 'takeover', iid(a), 'admin:test')
        federation._mutate_ownership(lambda own: federation.store_record(own, rec) or True)
    _add_cluster(a, 'pve-x', password='mine')
    with at(a):
        with pytest.raises(FedError) as err:
            fl.enroll_cluster('pve-x')
    assert err.value.code == 'FED_NO_QUORUM'
    row = _db_of(a).conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone()
    assert row['fed_owner'] == '' and _db_of(a)._decrypt(row['pass_encrypted']) == 'mine'
    assert _records(a)['pve-x']['owner'] == iid(b)


def test_a_body_whose_records_cannot_be_stored_gets_no_vote(tmp_path, monkeypatch):
    """A voter that cannot store the records of a body gives no vote past them: 503, and
    no promise. Counterproof: the vote given anyway."""
    a, b = _sides(tmp_path, 'ab')
    with at(a):
        rec = federation.sign_owner_record('pve-z', 1, 'enroll', '', 'admin:test')
        body = {'candidate': iid(a), 'view': federation.view_digest(),
                'epoch': federation.view_epoch(), 'releases': [],
                'asks': [{'cluster_id': 'pve-z', 'adopt': False}],
                'records': [rec], 'records_upto': 1}
    b_id = iid(b)
    real = federation._mutate_ownership

    def broken(fn):
        if federation.instance_id() == b_id:
            raise RuntimeError('the disk is full')
        return real(fn)
    monkeypatch.setattr(federation, '_mutate_ownership', broken)
    with at(b):
        assert federation.cast_votes(iid(a), body) == (503, {'reason': 'unavailable'})
        assert 'pve-z' not in federation._lease_state()['promises']


# --- the manual takeover ---------------------------------------------------------------------

def test_a_takeover_needs_the_owner_silent_and_unheard(tmp_path, clock):
    """Refused while a answers, for 35 s after a was last heard, and as long as a's calls
    still reach b in a split one way. After 36 s of silence it goes through: held alone, a
    takeover record one generation past the enroll's, signed by b with the admin's name,
    the credentials open at b, the note to hold it alone, the adoption mark. Counterproof:
    without the probe and the wait, b takes it while a answers."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    clock.advance(36)
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_OWNER_ALIVE' and err.value.extra['owner'] == iid(a)
    assert 'Hand over' in str(err.value) and _owner_at(b, 'pve-x') == iid(a)
    # the probe just heard a
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_OWNER_RECENT' and 33 <= err.value.extra['retry_after'] <= 35
    _cut([a, b], a)
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_OWNER_RECENT'
    _cut_one_way([a, b], b, a)
    _quiet(clock, a, seconds=60)
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_OWNER_RECENT'
    _cut([a, b], a)
    _quiet(clock, a)
    out = _takeover(b, 'pve-x')
    assert out == {'cluster_id': 'pve-x', 'generation': 2, 'owner': iid(a)}
    rec = _records(b)['pve-x']
    assert (rec['gen'], rec['kind'], rec['owner'], rec['from'], rec['by']) == \
        (2, 'takeover', iid(b), iid(a), 'admin:test')
    assert _owner_at(b, 'pve-x') == iid(b) and _writes(b, 'pve-x') is True
    lease = _lease(b, 'pve-x')
    assert lease['alone'] is True and lease['adopted'] is True
    assert _ok(b)['pve-x']['gen'] == 2
    with at(b):
        assert federation.adopted_from() == {'pve-x': iid(a)}
        assert federation.identity()['adopted']['pve-x']['takeover'] == 2
        status = fl.lease_status()['leases']['pve-x']
    assert status['takeover']['from'] == iid(a) and status['takeover']['confirmed_at'] == 0
    row = _db_of(b).conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-x'").fetchone()
    assert _db_of(b)._decrypt(row[0]) == 'x-secret'


def test_an_owner_that_answers_during_the_takeover_round_stops_it(tmp_path, clock):
    """The probe got no answer, but a answers the round itself: refused with
    FED_OWNER_ALIVE, nothing stored, and a never sees a record of it. Counterproof:
    without the check of the round's answer, b takes it over beside a."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    _cut([a, b], a)
    _quiet(clock)
    inner = b.wire

    def probe_lost(url, method, path, body, headers):
        if path == federation.STATUS_PATH:
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    b.runtime['transport'] = probe_lost
    a.runtime['transport'] = a.wire
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_OWNER_ALIVE'
    assert _owner_at(b, 'pve-x') == iid(a) and _records(b)['pve-x']['kind'] == 'enroll'
    assert all(r['kind'] != 'takeover' for r in _records(a).values())
    assert _lease(b, 'pve-x') == {}


def test_a_takeover_is_refused_in_hold_settle_on_a_standby_and_while_busy(tmp_path, clock,
                                                                          monkeypatch):
    from pegaprox.core import ha
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    _cut([a, b], a)
    _quiet(clock)
    with at(b):
        fl.note_view_change()
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_SETTLING' and err.value.extra['retry_after'] > 30
    _settle(clock)
    with monkeypatch.context() as m:
        m.setattr(ha, 'is_standby', lambda: True)
        with pytest.raises(FedError) as err:
            _takeover(b, 'pve-x')
        assert err.value.code == 'FED_STANDBY'
        # Take over all calls the core itself, past the check of the one-cluster wrapper
        with at(b), pytest.raises(FedError) as err:
            fl.take_over_clusters(iid(a), by='admin:test')
    assert err.value.code == 'FED_STANDBY'
    assert federation._change_lock.acquire(blocking=False)
    try:
        with pytest.raises(FedError) as err:
            _takeover(b, 'pve-x')
        assert err.value.code == 'FED_BUSY'
    finally:
        federation._change_lock.release()
    _reboot(b, monkeypatch)
    with pytest.raises(FedError) as err:
        _takeover(b, 'pve-x')
    assert err.value.code == 'FED_HOLD' and err.value.extra['retry_after'] > 30
    assert _owner_at(b, 'pve-x') == iid(a)


def test_a_failed_takeover_changes_nothing(tmp_path, clock, monkeypatch):
    """The credentials do not cross over: row, record and note stay as they were, and the
    lease and the own promise are given back; a retry goes through. Counterproof: the
    record stored outside the takeover's transaction is left behind."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    _cut([a, b], a)
    _quiet(clock, a)
    before = dict(_db_of(b).conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone())
    records, ok = _records(b), _ok(b)
    real = fl._reseat_credentials

    def broken(conn, cid, owner, force):
        real(conn, cid, owner, force)
        raise RuntimeError('the disk is full')
    monkeypatch.setattr(fl, '_reseat_credentials', broken)
    with pytest.raises(FedError):
        _takeover(b, 'pve-x')
    after = dict(_db_of(b).conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone())
    assert after == before and _records(b) == records and _ok(b) == ok
    assert _lease(b, 'pve-x') == {} and _writes(b, 'pve-x') is False
    with at(b):
        p = federation._lease_state()['promises']['pve-x']
    assert p['candidate'] == iid(b) and p['released'] is True
    monkeypatch.setattr(fl, '_reseat_credentials', real)
    assert _takeover(b, 'pve-x')['generation'] == 2


def test_take_over_all_takes_every_cluster_of_the_site(tmp_path, clock):
    """Take over all: every copy of the site in one probe and one round. One whose
    credentials do not open fails with FED_NO_KEY unless forced, the others go through;
    with nothing of the site left, FED_NOTHING_TO_TAKE."""
    a, b = _sides(tmp_path, 'ab')
    for cid in ('pve-1', 'pve-2', 'pve-3'):
        _enroll(a, cid, password=f'{cid}-secret')
    _sync(b)
    db = _db_of(b)
    wrapped = db.conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-3'").fetchone()[0]
    db.conn.execute("UPDATE clusters SET pass_encrypted = ? WHERE id = 'pve-3'",
                    ('fedk1:00000000:' + wrapped.split(':', 2)[2],))
    db.conn.commit()
    _cut([a, b], a)
    _quiet(clock, a)
    calls = []
    cut_off = b.runtime['transport']

    def counted(url, method, path, body, headers):
        if url == URL['a']:
            calls.append((path, bool(body) and bool(json.loads(body).get('asks'))))
        return cut_off(url, method, path, body, headers)
    b.runtime['transport'] = counted
    with at(b):
        out = fl.take_over_clusters(iid(a), by='admin:test')
    assert sorted(t['cluster_id'] for t in out['taken']) == ['pve-1', 'pve-2']
    assert out['failed']['pve-3']['code'] == 'FED_NO_KEY'
    assert calls.count((federation.STATUS_PATH, False)) == 1
    assert calls.count((federation.LEASE_PATH, True)) == 1
    assert _owner_at(b, 'pve-3') == iid(a)
    with at(b):
        out = fl.take_over_clusters(iid(a), ['pve-3'], by='admin:test', force=True)
        assert [t['cluster_id'] for t in out['taken']] == ['pve-3']
        with pytest.raises(FedError) as err:
            fl.take_over_clusters(iid(a), by='admin:test')
    assert err.value.code == 'FED_NOTHING_TO_TAKE'
    assert db.conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-3'").fetchone()[0] == ''
    assert [s.name for s in (a, b) if _writes(s, 'pve-1')] == ['a', 'b']


# --- the fence: the old owner stops at the first contact ------------------------------------

@pytest.mark.parametrize('contact', ['its own round', 'the takers push', 'the takers sync',
                                     'the snapshot'])
def test_the_old_owner_steps_down_at_the_first_contact(tmp_path, clock, monkeypatch,
                                                       fed_audits, contact):
    """While the two cannot reach each other both write: the risk the admin took. At the
    first contact, whichever way it comes, a stops what runs on the cluster before its row
    moves, stops the manager, turns the row into b's copy with no credentials, and drops
    its lease; b sees it confirmed once. From then on only b writes, and a's copy gets b's
    credentials with the next sync. Counterproofs: the row moved before what runs is cut;
    a sync tick of b that pushes no records."""
    from pegaprox import globals as g
    from pegaprox.core import ha_transport
    a, b, out = _split_and_take(tmp_path, clock)
    assert out['generation'] == 2
    _round(a)
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['a', 'b']
    cuts = []
    real_cut = ha_transport.cut_cluster

    def spy(cid):
        cuts.append((cid, _owner_at(a, cid)))
        return real_cut(cid)
    monkeypatch.setattr(ha_transport, 'cut_cluster', spy)
    mgr = MagicMock()
    g.cluster_managers['pve-x'] = mgr
    try:
        _heal([a, b])
        if contact == 'its own round':
            _round(a)
        elif contact == 'the takers push':
            with at(b):
                assert fl.push_records() == [iid(a)]
        elif contact == 'the takers sync':
            with at(b):
                federation._sync_tick()
        else:
            _sync(a)
    finally:
        g.cluster_managers.pop('pve-x', None)
    assert cuts and cuts[0] == ('pve-x', iid(a))
    assert mgr.stop.called
    row = _db_of(a).conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone()
    assert row['fed_owner'] == iid(b) and _lease(a, 'pve-x') == {}
    for col in federation.CLUSTER_ENCRYPTED_COLUMNS:
        assert row[col] == '' or (contact == 'the snapshot' and row[col].startswith('fedk1:'))
    held = _records(a)['pve-x']
    assert held['kind'] == 'takeover' and held['owner'] == iid(b) and held['stopped_at'] > 0
    with at(a):
        assert fl.lease_status()['stepped_down']['pve-x']['owner'] == iid(b)
    steps = [t for i, act, t in fed_audits if act == 'federation.cluster_stepped_down']
    assert len(steps) == 1 and 'taken over by hand' in steps[0] and 'admin:test' in steps[0]
    with at(b):
        fl.push_records()
        fl.push_records()
    assert _records(b)['pve-x']['confirmed_at'] > 0
    confirmed = [(i, t) for i, act, t in fed_audits if act == 'federation.takeover_confirmed']
    assert confirmed == [(iid(b), 'site-a stepped down from cluster pve-x (generation 2)')]
    for _ in range(4):
        clock.advance(10)
        _round(a)
        _round(b)
        assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['b']
    _sync(a)
    with at(b):
        mine = federation.enrolled_cluster_rows()[0]['pass_encrypted']
    row = _db_of(a).conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-x'").fetchone()
    assert row[0] == mine and mine.startswith('fedk1:')


@pytest.mark.parametrize('contact', ['its own round', 'the takers round, one way',
                                     'the takers push, one way'])
def test_a_takeover_of_many_clusters_stops_every_one_at_the_first_contact(tmp_path, clock,
                                                                          contact):
    """b took over all 40 clusters of a, more records than one call carries. The first
    contact stops every one of them at a, not a batch of 32: b's answer to a's round reads
    them all, and with only b able to call a, b's round and b's push send the rest right
    after the first batch, until a echoed them all. Counterproofs: the answer read up to
    one batch; no push after the round; one call per push."""
    a, b = _sides(tmp_path, 'ab')
    cids = [f'pve-{i:02d}' for i in range(40)]
    for cid in cids:
        _enroll(a, cid)
    _sync(b)
    _cut([a, b], a)
    _quiet(clock, a)
    with at(b):
        assert len(fl.take_over_clusters(iid(a), by='admin:test', force=True)['taken']) == 40
    if contact == 'its own round':
        _heal([a, b])
        _round(a)
    else:
        _cut_one_way([a, b], a, b)
        if contact == 'the takers round, one way':
            _round(b)
        else:
            with at(b):
                assert fl.push_records() == [iid(a)]
    assert [c for c in cids if _owner_at(a, c) != iid(b) or _writes(a, c)] == []
    assert all(_writes(b, c) for c in cids)
    if contact != 'its own round':
        assert all(r['confirmed_at'] for r in _records(b).values())


@pytest.mark.parametrize('who', ['old owner', 'taker'])
def test_records_are_taken_during_a_hold(tmp_path, clock, monkeypatch, who):
    """A site in its hold after a reboot grants nothing, but the records still go both
    ways: the old owner takes the taker's push, and the taker answers the old owner's
    round with its record. Counterproof: records left aside while the voter holds."""
    a, b, _ = _split_and_take(tmp_path, clock)
    _reboot(a if who == 'old owner' else b, monkeypatch)
    _heal([a, b])
    if who == 'old owner':
        with at(b):
            fl.push_records()
    else:
        r = _round(a)['pve-x']
        assert r['refusals'] == {'hold': 1}
    with at(a if who == 'old owner' else b):
        assert fl.hold_left() > 0
    assert _owner_at(a, 'pve-x') == iid(b) and _writes(a, 'pve-x') is False


def test_a_restored_old_owner_gives_it_up_again(tmp_path, clock):
    """a's database and lease file come back from a backup taken before it stepped down:
    its row says a again. Its first round with b answering gives the cluster up once more,
    and no lease is written. Counterproof: no records in the answers."""
    a, b, _ = _split_and_take(tmp_path, clock)
    conn = _db_of(a).conn
    row = dict(conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone())
    kv = [tuple(r) for r in conn.execute('SELECT k, v FROM pegaprox_kv').fetchall()]
    with open(a.lease_file) as fh:
        lease_file = fh.read()
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b)
    cols = [c for c in row if c != 'id']
    conn.execute(f'UPDATE clusters SET {", ".join(f"{c} = ?" for c in cols)} WHERE id = ?',
                 [row[c] for c in cols] + ['pve-x'])
    conn.executemany('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)', kv)
    conn.commit()
    with open(a.lease_file, 'w') as fh:
        fh.write(lease_file)
    _restart(a)
    assert _owner_at(a, 'pve-x') == iid(a) and _writes(a, 'pve-x') is False
    r = _round(a)['pve-x']
    assert r['held'] is False and r.get('taken_by') == iid(b)
    assert _owner_at(a, 'pve-x') == iid(b) and _writes(a, 'pve-x') is False


def test_taking_it_back_and_forth(tmp_path, clock):
    """b takes a's cluster over, then a takes it back while b is down: each takeover is one
    generation past the last, and b gives it up at the next contact, while b's older
    record never moves a, not even beside a refusal of b naming itself (a b restored from
    a backup). On an equal generation a takeover beats an enroll the taker never heard of,
    though later in time, at both sites. Counterproofs: a generation that does not grow;
    no rank of the kinds; a beaten record with the refusal taken as evidence, both sites
    give the cluster up."""
    a, b, out = _split_and_take(tmp_path, clock)
    assert out['generation'] == 2
    _heal([a, b])
    _round(a)
    _sync(a)
    with at(a):
        federation.fetch_field_keys()
    old = _records(b)['pve-x']
    _cut([a, b], b)
    _quiet(clock, b)
    assert _takeover(a, 'pve-x')['generation'] == 3
    _heal([a, b])
    _round(b)
    assert _owner_at(b, 'pve-x') == iid(a) and _owner_at(a, 'pve-x') == iid(a)
    with at(a):
        assert fl.take_records(iid(b), [federation.wire_record(old)])['fenced'] == {}
        assert fl.take_records(iid(b), [federation.wire_record(old)],
                               owner_refusals={'pve-x'})['fenced'] == {}
    assert _records(a)['pve-x']['gen'] == 3 and _owner_at(a, 'pve-x') == iid(a)
    # the tie
    _enroll(a, 'pve-y')
    _sync(b)
    with at(a):
        digest, epoch = federation.view_digest(), federation.view_epoch()
    late = _signed(a, {'cluster_id': 'pve-y', 'gen': 2, 'kind': 'enroll', 'owner': iid(a),
                       'from': '', 'at': int(time.time()) + 100, 'by': 'admin:test'})

    def enrolled_again(own):
        federation.store_record(own, late)
        own['ok']['pve-y'] = {'view': digest, 'epoch': epoch, 'gen': 2}
        return True
    with at(a):
        federation._mutate_ownership(enrolled_again)
    _cut([a, b], a)
    _quiet(clock, a)
    assert _takeover(b, 'pve-y')['generation'] == 2
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-y') == iid(b) and _owner_at(b, 'pve-y') == iid(b)
    for s in (a, b):
        assert _records(s)['pve-y']['kind'] == 'takeover', s.name


def test_a_cluster_moved_with_both_answering_is_written_alone_later(tmp_path, clock):
    """a hands its cluster over and b takes it over while both answer: b holds it with both
    votes under an adoption record one generation on, a's row is b's copy at once, and when
    a goes down right after, b writes on alone. Counterproof: the adoption without the note,
    b stops 28 s after a went silent."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    with at(a):
        fl.release('pve-x')
    with at(b):
        out = fl.adopt_cluster('pve-x')
    assert out['held'] is True and out['votes'] == 2 and out['generation'] == 2
    assert _records(b)['pve-x']['kind'] == 'adopt' and _owner_at(a, 'pve-x') == iid(b)
    _cut([a, b], a)
    for _ in range(4):
        clock.advance(10)
        r = _round(b)['pve-x']
        assert r['held'] is True and r['alone'] is True, r
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['b']


def test_a_takeover_lost_to_the_ha_sync_comes_back(tmp_path, clock, monkeypatch):
    """b took a's cluster over and a stepped down; then b's HA group fails over to a standby
    the sync had not carried the takeover to: its row is a's copy again. a's snapshot
    carries the record, the standby leads the cluster again before it looks at the rows,
    and the cluster never vanishes at either site. Counterproof: no records in the
    snapshot, the standby drops the copy a no longer lists."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    b2 = _standby_of(tmp_path, b, name='b2')
    _cut([a, b], a)
    _quiet(clock, a)
    _takeover(b, 'pve-x')
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b)
    URL['b2'] = URL['b']
    try:
        _wire([a, b2])
        monkeypatch.setattr(fl, '_ha_epoch',
                            lambda: 5 if federation._runtime['lease_file'] == b2.lease_file
                            else 0)
        assert _owner_at(b2, 'pve-x') == iid(a)
        _sync(b2)
        assert _owner_at(b2, 'pve-x') == iid(b)
        _sync(a)
        assert _owner_at(a, 'pve-x') == iid(b)
        row = _db_of(b2).conn.execute(
            "SELECT pass_encrypted FROM clusters WHERE id = 'pve-x'").fetchone()
        assert _db_of(b2)._decrypt(row[0]) == 'x-secret'
        _settle(clock)
        for _ in range(3):
            clock.advance(10)
            _round(a)
            _round(b2)
            assert [s.name for s in (a, b2) if _writes(s, 'pve-x')] == ['b2']
    finally:
        URL.pop('b2', None)


def test_a_cluster_handed_on_is_never_resumed(tmp_path, clock, monkeypatch):
    """b took a's cluster over, handed it over again, a adopted it, and b's row became a's
    copy before a's record reached b. Its own old takeover record coming back to b leads
    nothing back to b. Counterproof: a record not newer than the one held resumes it."""
    a, b, _ = _split_and_take(tmp_path, clock)
    _heal([a, b])
    _round(a)
    _round(b)
    _sync(a)
    with at(a):
        federation.fetch_field_keys()
    old = _records(b)['pve-x']
    with at(b):
        fl.release('pve-x')
    a_id = iid(a)
    inner = a.wire

    def records_held_back(url, method, path, body, headers):
        if path == federation.LEASE_PATH and body and json.loads(body).get('records') \
                and not json.loads(body).get('asks'):
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    a.runtime['transport'] = records_held_back
    with at(a):
        assert fl.adopt_cluster('pve-x')['held'] is True
    real_body = federation.identity_snapshot_body

    def without_records():
        body = real_body()
        if federation.instance_id() == a_id:
            body['records'] = []
        return body
    monkeypatch.setattr(federation, 'identity_snapshot_body', without_records)
    _sync(b)
    assert _owner_at(b, 'pve-x') == a_id
    with at(b):
        assert fl.take_records(a_id, [federation.wire_record(old)]) == {'echo': True,
                                                                        'fenced': {}}
    assert _owner_at(b, 'pve-x') == a_id
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['a']


def _fail_the_move_once(monkeypatch):
    """The transaction that moves a row by a record (_step_down, _resume) fails once, as
    with a locked database."""
    real = federation._ownership_in_tx
    left = {'n': 1}

    def flaky(conn, fn):
        if fn.__name__ == 'keep' and left['n']:
            left['n'] -= 1
            raise RuntimeError('database is locked')
        return real(conn, fn)
    monkeypatch.setattr(federation, '_ownership_in_tx', flaky)
    return left


@pytest.mark.parametrize('contact', ['the takers push', 'its own round', 'the snapshot'])
def test_a_step_down_that_fails_is_done_at_the_next_contact(tmp_path, clock, monkeypatch,
                                                            fed_audits, contact):
    """a's row cannot be turned into b's copy at the first contact. a stops writing all the
    same and keeps b's record, but no echo of it: b's takeover stays unconfirmed and the
    snapshot waits. The next contact gives the cluster up, audited once, and b sees it
    confirmed once. Counterproofs: the record echoed, b sees it confirmed while a's row is
    still a's; the record held taken as done, a never gives it up."""
    a, b, _ = _split_and_take(tmp_path, clock)
    _round(a)
    failing = _fail_the_move_once(monkeypatch)
    _heal([a, b])
    if contact == 'the takers push':
        with at(b):
            assert fl.push_records() == []
    elif contact == 'its own round':
        _round(a)
    else:
        _sync(a)
    assert failing['n'] == 0
    assert _owner_at(a, 'pve-x') == iid(a) and _writes(a, 'pve-x') is False
    held = _records(a)['pve-x']
    assert held['owner'] == iid(b) and held['gen'] == 2 and held['stopped_at'] == 0
    assert _records(b)['pve-x']['confirmed_at'] == 0
    moves = ('federation.cluster_stepped_down', 'federation.takeover_confirmed')
    assert [act for _i, act, _t in fed_audits if act in moves] == []
    if contact == 'the takers push':
        with at(b):
            assert fl.push_records() == [iid(a)]
    elif contact == 'its own round':
        _round(b)
    else:
        _sync(a)
    row = _db_of(a).conn.execute("SELECT * FROM clusters WHERE id = 'pve-x'").fetchone()
    assert row['fed_owner'] == iid(b)
    for col in federation.CLUSTER_ENCRYPTED_COLUMNS:
        assert row[col] == '' or (contact == 'the snapshot' and row[col].startswith('fedk1:'))
    assert _records(a)['pve-x']['gen'] == 2 and _records(a)['pve-x']['stopped_at'] > 0
    with at(b):
        fl.push_records()
    assert [act for _i, act, _t in fed_audits if act in moves] == list(moves)
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['b']


def test_a_step_down_that_fails_keeps_the_standby_of_the_old_owner_closed(tmp_path, clock,
                                                                           monkeypatch):
    """a's row cannot be turned into b's copy at the first contact, and then a's HA group
    fails over to a standby that has a's database but not its lease file, while b is cut
    off from it. The standby finds b's record and holds nothing alone; only b writes. At
    the next contact the standby gives the cluster up. Counterproof: the record kept only
    by the step-down, the standby writes after its hold, as b does."""
    a, b, _ = _split_and_take(tmp_path, clock)
    _round(a)
    failing = _fail_the_move_once(monkeypatch)
    _heal([a, b])
    with at(b):
        assert fl.push_records() == []
    assert failing['n'] == 0 and _owner_at(a, 'pve-x') == iid(a)
    a2 = _standby_of(tmp_path, a, name='a2')
    URL['a2'] = URL['a']
    try:
        _wire([a2, b])
        monkeypatch.setattr(fl, '_ha_epoch',
                            lambda: 5 if federation._runtime['lease_file'] == a2.lease_file
                            else 0)
        _cut([a2, b], b)
        _quiet(clock, a2, b, seconds=120)
        assert [s.name for s in (a2, b) if _writes(s, 'pve-x')] == ['b']
        _heal([a2, b])
        _round(a2)
        assert _owner_at(a2, 'pve-x') == iid(b) and _records(a2)['pve-x']['stopped_at'] > 0
    finally:
        URL.pop('a2', None)


def test_a_resume_that_fails_is_done_at_the_next_sync(tmp_path, clock, monkeypatch):
    """The HA standby of b that lost the takeover cannot lead the cluster again at its
    first sync: it keeps a's copy and leaves a's snapshot for the next sync, which leads
    it there. The cluster stays at both sites throughout. Counterproof: the record kept
    and the snapshot taken, the standby drops the copy and then a drops its own."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    b2 = _standby_of(tmp_path, b, name='b2')
    _cut([a, b], a)
    _quiet(clock, a)
    _takeover(b, 'pve-x')
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b)
    URL['b2'] = URL['b']
    try:
        _wire([a, b2])
        monkeypatch.setattr(fl, '_ha_epoch',
                            lambda: 5 if federation._runtime['lease_file'] == b2.lease_file
                            else 0)
        failing = _fail_the_move_once(monkeypatch)
        _sync(b2)
        assert failing['n'] == 0
        assert _owner_at(b2, 'pve-x') == iid(a) and _owner_at(a, 'pve-x') == iid(b)
        _sync(b2)
        assert _owner_at(b2, 'pve-x') == iid(b)
        _sync(a)
        assert _owner_at(a, 'pve-x') == iid(b)
        row = _db_of(b2).conn.execute(
            "SELECT pass_encrypted FROM clusters WHERE id = 'pve-x'").fetchone()
        assert _db_of(b2)._decrypt(row[0]) == 'x-secret'
    finally:
        URL.pop('b2', None)


@pytest.mark.parametrize('step', ['step down', 'resume'])
def test_a_move_by_a_record_keeps_a_newer_one_that_came_in_meanwhile(tmp_path, clock, step):
    """A newer record of the cluster was stored between the look at the records and the
    move: the move stops, the newer record stays and the row stays where it was.
    Counterproof: without the second look the older record replaces the newer one and
    the row moves."""
    a, b, _ = _split_and_take(tmp_path, clock)
    theirs = federation.wire_record(_records(b)['pve-x'])
    if step == 'step down':
        newer = _signed(a, {'cluster_id': 'pve-x', 'gen': 3, 'kind': 'takeover',
                            'owner': iid(a), 'from': iid(b), 'at': int(time.time()),
                            'by': 'admin:test'})
        older, row = theirs, iid(a)
    else:
        _heal([a, b])
        _round(a)
        newer = _signed(b, {'cluster_id': 'pve-x', 'gen': 4, 'kind': 'takeover',
                            'owner': iid(b), 'from': iid(a), 'at': int(time.time()),
                            'by': 'admin:test'})
        older = _signed(a, {'cluster_id': 'pve-x', 'gen': 3, 'kind': 'takeover',
                            'owner': iid(a), 'from': iid(b), 'at': int(time.time()),
                            'by': 'admin:test'})
        row = iid(b)
    assert _owner_at(a, 'pve-x') == row

    def stored(own):
        federation.store_record(own, newer)
        return True
    with at(a):
        federation._mutate_ownership(stored)
        moved = (fl._step_down if step == 'step down' else fl._resume)('pve-x', older)
    assert moved is False
    assert _records(a)['pve-x']['sig'] == newer['sig'] and _owner_at(a, 'pve-x') == row


def test_a_switched_off_owner_is_taken_over_and_gives_it_up_when_on(tmp_path, clock,
                                                                   monkeypatch):
    """a is switched off: it answers every call unsigned, which is silence to b, and b's
    admin takes its cluster over. Switched on again, a gives it up at its first round,
    before any write."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x', password='x-secret')
    _sync(b)
    a_file = a.lease_file
    real = federation.enabled
    monkeypatch.setattr(federation, 'enabled',
                        lambda: federation._runtime.get('lease_file') != a_file and real())
    with at(b):
        assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] == 0
    _quiet(clock)
    _takeover(b, 'pve-x')
    monkeypatch.setattr(federation, 'enabled', real)
    assert _writes(a, 'pve-x') is False
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b) and _writes(a, 'pve-x') is False


def test_a_restart_of_either_side_keeps_the_takeover(tmp_path, clock):
    """The takeover lives in the synced key and the clusters table: a restart of b keeps
    it (its lease held alone waits for the next round), and an old owner that restarts
    before the two meet gives the cluster up at its first round."""
    a, b, _ = _split_and_take(tmp_path, clock)
    _restart(b)
    assert _owner_at(b, 'pve-x') == iid(b) and _records(b)['pve-x']['kind'] == 'takeover'
    assert _writes(b, 'pve-x') is False
    clock.advance(10)
    r = _round(b)['pve-x']
    assert r['held'] is True and r['alone'] is True
    _restart(a)
    assert _writes(a, 'pve-x') is False
    _heal([a, b])
    _round(a)
    assert _owner_at(a, 'pve-x') == iid(b)
    _restart(b)
    clock.advance(10)
    assert _round(b)['pve-x']['held'] is True
    assert [s.name for s in (a, b) if _writes(s, 'pve-x')] == ['b']


# --- changes of the member list -----------------------------------------------------------------

def test_the_member_list_waits_for_an_unconfirmed_takeover(tmp_path, clock):
    """b took a's cluster over and nothing of it reached a yet. A join of c made at a is
    refused: b's refusal 'taken' carries the record, and a gives the cluster up on it. Once
    b's next round got the record confirmed, the join goes through. Counterproof: no
    'taken', the join commits while a never heard of the takeover."""
    a, b, _ = _split_and_take(tmp_path, clock)
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    inner = b.wire

    def records_lost(url, method, path, body, headers):
        if path == federation.LEASE_PATH and body and json.loads(body).get('records'):
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    b.runtime['transport'] = records_lost
    code = _code(a)
    with pytest.raises(FedError) as err:
        _join(c, code)
    assert err.value.code == 'FED_NO_QUORUM'
    assert 'a takeover is not known at every site yet' in str(err.value)
    assert _owner_at(a, 'pve-x') == iid(b)
    b.runtime['transport'] = inner
    _round(b)
    assert _records(b)['pve-x']['confirmed_at'] > 0
    _join(c, code)
    assert len(_view(a)[2]) == 2 and _view(a)[1] == _view(b)[1] == _view(c)[1]


def test_a_third_site_joins_without_two_writers(tmp_path, clock):
    """A third site joins a federation of two while a holds its cluster: second by second,
    every side running its rounds, never more than one writer. Past the settle span the
    lease is two of three; a cut-off b costs nothing; a cut-off a holds nothing alone any
    more, its lease ends within 28 s and b adopts with c. Counterproof: the rule of two
    applied to three sites."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    _join(c, _code(a))
    for step in range(60):
        clock.advance(1)
        for s in (a, b, c):
            _round(s)
        writers = [s.name for s in (a, b, c) if _owner_at(s, 'pve-x') == iid(s)
                   and _writes(s, 'pve-x')]
        assert writers in ([], ['a']), (step, writers)
    _sync(b, c)
    r = _round(a)['pve-x']
    assert r['held'] is True and r['needed'] == 2 and r['alone'] is False
    _cut([a, b, c], b)
    clock.advance(10)
    assert _round(a)['pve-x']['held'] is True
    _cut([a, b, c], a)
    for _ in range(3):
        clock.advance(10)
        assert _round(a)['pve-x']['held'] is False
    assert _writes(a, 'pve-x') is False
    clock.advance(6)
    with at(b):
        assert fl.adopt_cluster('pve-x')['held'] is True
    assert [s.name for s in (a, b, c) if _owner_at(s, 'pve-x') == iid(s)
            and _writes(s, 'pve-x')] == ['b']


def test_a_clean_leave_returns_the_survivor_its_clusters(tmp_path, clock, monkeypatch,
                                                        fed_audits):
    """The other site leaves (or is removed with its agreement): no site is left that could
    hold the survivor's clusters, and they are its own again at once. A crash before that
    is repaired by the next sync tick. A site that left or was removed keeps its own
    enrolled rows closed, as before. Counterproof: no return, the survivor's clusters stay
    closed."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(b, 'pve-b')
    with at(a):
        federation.leave()
    assert _owner_at(b, 'pve-b') == '' and _writes(b, 'pve-b') is True
    assert [t for i, act, t in fed_audits if act == 'federation.clusters_returned'] == \
        ["1 cluster(s) are this instance's own again: no other site is left in the "
         "federation (the last other site left)"]
    real = fl.return_alone
    (tmp_path / 'crash').mkdir()
    c, d = _sides(tmp_path / 'crash', 'ab')
    _enroll(d, 'pve-d')
    monkeypatch.setattr(fl, 'return_alone', lambda reason: [])
    with at(c):
        federation.leave()
    monkeypatch.setattr(fl, 'return_alone', real)
    assert _owner_at(d, 'pve-d') == iid(d)
    # a view of one holds no lease: once the last one ran out the cluster stays closed
    clock.advance(30)
    _round(d)
    assert _writes(d, 'pve-d') is False
    with at(d):
        federation._sync_tick()
    assert _owner_at(d, 'pve-d') == '' and _writes(d, 'pve-d') is True
    (tmp_path / 'removed').mkdir()
    e, f = _sides(tmp_path / 'removed', 'ab')
    _enroll(e, 'pve-e')
    _enroll(f, 'pve-f')
    with at(f):
        federation.remove_member(iid(e), by='admin:test')
    assert _owner_at(f, 'pve-f') == ''
    with at(e):
        assert federation.members() == {} and federation.view_epoch() == 0
        assert fl.return_alone('repair') == []
    assert _owner_at(e, 'pve-e') == iid(e) and _writes(e, 'pve-e') is False


def _net(sides, blocked):
    """Each side's calls to the sides `blocked` names ((from, to) pairs) get no answer."""
    for s in sides:
        def transport(url, method, path, body, headers, s=s):
            to = next((x for x in sides if URL[x.name] == url), None)
            if to is not None and (s.name, to.name) in blocked:
                return 0, b'', {}
            return s.wire(url, method, path, body, headers)
        s.runtime['transport'] = transport


def test_never_two_writers_without_a_takeover(tmp_path, clock, monkeypatch):
    """Three hundred steps of two seconds, both sites with clusters, on a seeded schedule
    of cuts, cuts one way, heals, restarts, reboots, HA promotions and syncs. In the middle
    a third site joins; while a is cut off b adopts one of a's clusters with it, and the
    record of it never reaches the third site; then that site leaves with a's grant while
    b is down, b catches up and a is cut off again past the settle span: both rows claim
    the cluster in the view of two, and neither knows the other's record. No takeover by
    hand, no removal as gone: at every step at most one site writes each cluster.
    Counterproof: no 'ok' check, both write that cluster in the split."""
    from pegaprox.core import ha_vote
    a, b = _sides(tmp_path, 'ab')
    c = Side(tmp_path, 'c')
    sides = (a, b, c)
    _wire(list(sides))
    boots = {s.lease_file: 'boot-0' for s in sides}
    epochs = {s.lease_file: 0 for s in sides}
    monkeypatch.setattr(ha_vote, 'read_boot_id', lambda: boots[federation._runtime['lease_file']])
    monkeypatch.setattr(fl, '_ha_epoch', lambda: epochs[federation._runtime['lease_file']])
    for s in sides:
        _restart(s)
    # a boot id of their own: every site holds once
    for s in (a, b):
        _round(s)
    _settle(clock)
    _enroll(a, 'pa1', password='pa1')
    _enroll(a, 'pa2', password='pa2')
    _enroll(b, 'pb1', password='pb1')
    _sync(a, b)
    ids = {s.name: iid(s) for s in sides}
    cids = ('pa1', 'pa2', 'pb1')
    rng = random.Random(1116)
    blocked = set()

    def cut_off(x, others='abc'):
        return {(x, o) for o in others if o != x} | {(o, x) for o in others if o != x}

    def noise(step):
        roll, x = rng.random(), rng.choice((a, b))
        if roll < 0.12:
            blocked.update(cut_off(x.name))
        elif roll < 0.20:
            blocked.add((x.name, 'b' if x is a else 'a'))
        elif roll < 0.38:
            blocked.clear()
        elif roll < 0.42:
            _restart(x)
        elif roll < 0.45:
            boots[x.lease_file] += '-r'
            _restart(x)
        elif roll < 0.48:
            epochs[x.lease_file] += 1
        elif roll < 0.56:
            with at(x):
                federation._sync_tick()

    def settled_net():
        blocked.clear()
        _net(sides, blocked)
        _settle(clock)
        for s in sides:
            _round(s)
    events = []
    for step in range(300):
        clock.advance(2)
        if step == 100:
            settled_net()
            _join(c, _code(a))
            events.append('joined')
            _sync(a, b, c)
        elif step == 130:
            blocked.clear()
            blocked.update(cut_off('a'))
        elif 130 < step < 160:
            if step >= 150 and _owner_at(b, 'pa1') == ids['a']:
                try:
                    with at(b):
                        fl.adopt_cluster('pa1')
                    events.append('adopted')
                    with at(c):
                        federation._reset_ownership()
                except FedError:
                    pass
        elif step == 160:
            blocked.clear()
            blocked.update(cut_off('b'))
            _net(sides, blocked)
            for _ in range(3):
                try:
                    with at(c):
                        federation.leave(force=True)
                    events.append('left')
                    break
                except FedError:
                    clock.advance(10)
        elif step == 163:
            blocked.clear()
            _net(sides, blocked)
            with at(b):
                federation.catch_up()
            blocked.update(cut_off('a'))
        elif step == 192:
            blocked.clear()
        elif not 100 <= step <= 192:
            noise(step)
        _net(sides, blocked)
        for s in sides:
            _round(s)
        for cid in cids:
            writers = [s.name for s in sides if _owner_at(s, cid) in ('', ids[s.name])
                       and _writes(s, cid)]
            assert len(writers) <= 1, (step, cid, writers)
    assert events == ['joined', 'adopted', 'left'], events


# --- removing the other site as gone for good -------------------------------------------------

def _gone_setup(tmp_path, clock):
    """a leads c1, b leads c2 and c3, b's account bea is mirrored at a. b is cut off for
    good, and a's admin takes c2 over by hand."""
    from tests.test_federation import _add_local_user
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'c1')
    _enroll(b, 'c2', password='c2-secret')
    _enroll(b, 'c3')
    _add_local_user(b, 'bea')
    _sync(a, b)
    with at(a):
        federation.fetch_field_keys()
    _cut([a, b], b)
    _quiet(clock, a, b)
    _takeover(a, 'c2')
    return a, b


def test_a_site_gone_for_good_is_removed_by_the_survivor(tmp_path, clock, monkeypatch,
                                                        fed_audits):
    """a removes b as gone for good: c3, which was not taken over, is named once more and
    dropped only on confirmation. a carries on alone, its clusters its own and written
    throughout, b's accounts gone, an end record kept. b was only cut off: its first call
    to a gets a signed 410 with the end record, b stops c2 before its row goes, drops it,
    keeps c3 as its own and writable, and says so."""
    from pegaprox.core import ha_transport
    from tests.test_federation import _users
    a, b = _gone_setup(tmp_path, clock)
    with at(a):
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(b), by='admin:test', gone=True)
    assert err.value.code == 'FED_GONE_CLUSTERS' and err.value.extra['clusters'] == ['c3']
    with at(a):
        out = federation.remove_member(iid(b), by='admin:test', gone=True, drop_clusters=True)
    assert out['kept'] == ['c1', 'c2'] and out['dropped'] == ['c3'] and out['gone'] is True
    assert (_owner_at(a, 'c1'), _owner_at(a, 'c2'), _owner_at(a, 'c3')) == ('', '', None)
    assert _writes(a, 'c1') is True and _writes(a, 'c2') is True
    assert 'bea' not in _users(a)
    with at(a):
        assert federation.members() == {} and federation.view_epoch() == 2
        ended = federation.identity()['ended'][iid(b)]
        assert ended['told_at'] == 0 and ended['end']['clusters'] == ['c1', 'c2']
        assert federation.ownership()['records'] == {}
    cuts = []
    real_cut = ha_transport.cut_cluster

    def spy(cid):
        cuts.append((cid, _owner_at(b, cid)))
        return real_cut(cid)
    monkeypatch.setattr(ha_transport, 'cut_cluster', spy)
    _heal([a, b])
    assert _round(b) == {}
    assert cuts[0] == ('c2', iid(b))
    assert _owner_at(b, 'c2') is None and _owner_at(b, 'c1') is None
    assert _owner_at(b, 'c3') == '' and _writes(b, 'c3') is True
    with at(b):
        assert federation.members() == {}
        removed = federation.identity()['removed']
    assert removed['ended'] is True and removed['clusters'] == ['c2'] and removed['by'] == iid(a)
    with at(a):
        assert federation.identity()['ended'][iid(b)]['told_at'] > 0
    assert [i for i, act, _t in fed_audits if act == 'federation.ended_by_other_site'] == [iid(b)]
    assert _writes(a, 'c2') is True


def test_an_end_record_is_taken_once_while_its_confirmation_is_on_the_way(tmp_path, clock,
                                                                          monkeypatch,
                                                                          fed_audits):
    """b takes the end record, and while its confirmation to a is on the way, another loop
    of b notes the record again from a 410 and takes it too. That run waits for the first
    and finds nothing left to take: b names c2 as stopped, once. Counterproof: the two
    side by side, the second one says none of the clusters led here were kept."""
    import threading
    a, b = _gone_setup(tmp_path, clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True, drop_clusters=True)
        end = dict(federation.end_for(iid(b)))
    _heal([a, b])
    real = federation.call_peer
    other = []

    def call(peer, method, path, body=None, **kw):
        out = real(peer, method, path, body, **kw)
        if path == federation.END_TAKEN_PATH and not other:
            federation._runtime['ended_by'][peer] = end
            other.append(threading.Thread(target=lambda: other.append(federation.take_end())))
            other[0].start()
            time.sleep(0.05)
        return out
    monkeypatch.setattr(federation, 'call_peer', call)
    with at(b):
        assert real(iid(a), 'GET', federation.STATUS_PATH)[0] == 410
        assert federation.take_end() is True
        other[0].join(5)
        removed = federation.identity()['removed']
    assert other[1:] == [False] and removed['clusters'] == ['c2']
    said = [t for _i, act, t in fed_audits if act == 'federation.ended_by_other_site']
    assert len(said) == 1 and 'keeps c2:' in said[0]


@pytest.mark.parametrize('tamper', ['base', 'epoch', 'sig', 'member', 'clusters', 'at'])
def test_an_end_record_that_does_not_hold_changes_nothing(tmp_path, clock, tamper):
    """The removed site takes an end record only when it is the other member's signed word
    about this very view of two (its digest and its epoch), names this instance and is
    what was signed. Counterproofs: each check left out, or a signed field left out of the
    signature, takes the record."""
    a, b = _gone_setup(tmp_path, clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True, drop_clusters=True)
        end = dict(federation.end_for(iid(b)))
    if tamper == 'sig':
        end['sig'] = base64.b64encode(b'\0' * 64).decode()
    elif tamper == 'clusters':
        end['clusters'] = sorted(set(end['clusters']) | {'c3'})
    elif tamper == 'at':
        end['at'] += 1
    else:
        if tamper == 'epoch':
            end['epoch'] += 1
        else:
            end['base' if tamper == 'base' else 'member'] = '0' * 32
        with at(a):
            end['sig'] = base64.b64encode(
                federation.signing_key().sign(federation._end_message(end))).decode()
    with at(b):
        federation._runtime['ended_by'][iid(a)] = end
        assert federation.take_end() is False
        assert iid(a) in federation.members()
    assert _owner_at(b, 'c2') == iid(b) and _owner_at(b, 'c3') == iid(b)


def test_an_end_record_from_before_a_new_pairing_is_not_taken(tmp_path, clock, monkeypatch):
    """a removed b as gone for good, b left and was paired with a again: the same two sites
    hold the same digest as before. An end record of the old federation that is still
    about at b is not taken, and one noted right before the leave goes with it.
    Counterproofs: without the epoch in the check b leaves the new federation at once;
    with the noted records kept across the leave, one is still there."""
    a, b = _sides(tmp_path, 'ab')
    _cut([a, b], b)
    _quiet(clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True)
        end = dict(federation.end_for(iid(b)))
    real_wipe = federation._wipe_membership

    def noted_meanwhile(reason):
        federation._runtime['ended_by'][iid(a)] = end
        return real_wipe(reason)
    with monkeypatch.context() as m:
        m.setattr(federation, '_wipe_membership', noted_meanwhile)
        with at(b):
            assert federation.leave(force=True)['left'] is True
            assert federation._runtime['ended_by'] == {}
    _heal([a, b])
    _join(b, _code(a))
    with at(b):
        assert federation.view_digest() == end['base']
        federation._runtime['ended_by'][iid(a)] = end
        assert federation.take_end() is False
        assert list(federation.members()) == [iid(a)]
        assert federation.identity()['removed'] is None


@pytest.mark.parametrize('joiner', ['b', 'a'])
def test_an_end_record_is_over_once_the_two_sites_pair_again(tmp_path, clock, joiner):
    """a removed b as gone for good, then both left what was left of the federation and
    paired again, either one joining the other: the same two sites at the same epoch, so
    b's view looks like the one the end record was made at. When a leaves with force while
    b is cut off, b's next call gets no end record, and b stays in its federation. a keeps
    no record for b from the new pairing on, and its switch does not warn. Counterproof:
    the record kept across the new pairing, b takes it and leaves."""
    a, b = _sides(tmp_path, 'ab')
    _cut([a, b], b)
    _quiet(clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True)
        end = dict(federation.end_for(iid(b)))
    for side in (b, a):
        with at(side):
            federation.leave(force=True)
    _heal([a, b])
    if joiner == 'b':
        _join(b, _code(a))
    else:
        _join(a, _code(b))
    with at(b):
        assert (federation.view_digest(), federation.view_epoch()) == (end['base'],
                                                                       end['epoch'])
    _cut([a, b], b)
    with at(a):
        federation.leave(force=True)
    _heal([a, b])
    with at(b):
        assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] != 410
        assert federation.take_end() is False
        assert list(federation.members()) == [iid(a)]
    with at(a):
        assert federation.end_for(iid(b)) is None
        assert 'disable_warnings' not in federation.switch_status()


def test_remove_gone_refuses_an_answering_or_recent_site(tmp_path, clock):
    a, b = _sides(tmp_path, 'ab')
    clock.advance(36)
    with at(a):
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(b), by='admin:test', gone=True)
    assert err.value.code == 'FED_PEER_ANSWERS' and err.value.extra['member'] == iid(b)
    _cut([a, b], b)
    with at(a):
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(b), by='admin:test', gone=True)
    assert err.value.code == 'FED_PEER_RECENT' and err.value.extra['retry_after'] > 30
    clock.advance(36)
    with at(a):
        fl.note_view_change()
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(b), by='admin:test', gone=True)
    assert err.value.code == 'FED_SETTLING'
    (tmp_path / 'three').mkdir()
    x, y, _z = _sides(tmp_path / 'three', 'abc')
    with at(x):
        with pytest.raises(FedError) as err:
            federation.remove_member(iid(y), by='admin:test', gone=True)
    assert err.value.code == 'FED_NOT_TWO_SITES'
    assert iid(b) in _view(a)[2]


def test_the_end_record_is_answered_after_the_survivor_paired_again(tmp_path, clock):
    """The survivor pairs with a new site, which replaces its tombstones. The removed site
    calls all the same and gets the signed 410 with its end record, and stops. Counterproof:
    no 'ended' verdict, the call is answered unsigned and b writes c2 on alone."""
    a, b = _gone_setup(tmp_path, clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True, drop_clusters=True)
    d = Side(tmp_path, 'd')
    _wire([a, b, d])
    _cut([a, b, d], b)
    _join(a, _code(d))
    with at(a):
        assert iid(b) not in federation.tombstones() and list(federation.members()) == [iid(d)]
    _heal([a, b, d])
    _round(b)
    assert _owner_at(b, 'c2') is None and _owner_at(b, 'c3') == ''
    with at(b):
        assert federation.identity()['removed']['ended'] is True


def test_switching_off_with_an_untold_end_asks_once_more(tmp_path, clock, monkeypatch):
    """Switched off, the survivor could no longer tell the removed site: asked once more
    while that site has not confirmed that it was told, and switched off on untold_ok. Once
    it took the end record its 410 brought, the warning is gone."""
    a, b = _sides(tmp_path, 'ab')
    _cut([a, b], b)
    _quiet(clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True)
        assert federation.switch_status()['disable_warnings'] == ['ended_untold']
    with monkeypatch.context() as m:
        m.delenv(federation.ENV_SWITCH)
        _db_of(a).save_server_setting(federation.SETTING_KEY, True)
        with at(a):
            federation._runtime['switch'] = None
            with pytest.raises(FedError) as err:
                federation.set_enabled(False)
            assert err.value.code == 'FED_ENDED_UNTOLD' and err.value.extra['sites'] == [iid(b)]
            assert str(err.value).startswith('site-b has not confirmed that it was told')
            assert federation.enabled() is True
            assert federation.set_enabled(False, untold_ok=True)['enabled'] is False
    _heal([a, b])
    with at(b):
        assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] == 410
    with at(a):
        assert federation.switch_status()['disable_warnings'] == ['ended_untold']
    with at(b):
        assert federation.take_end() is True
    with at(a):
        assert 'disable_warnings' not in federation.switch_status()


@pytest.mark.parametrize('how', ['answer lost', 'record refused', 'forged ack'])
def test_the_removed_site_counts_as_told_only_once_it_took_the_end(tmp_path, clock,
                                                                   monkeypatch, how):
    """The survivor counts the removed site as told only once that site says it took the
    end record and stopped: not when the 410 that carries it is lost on the way back, not
    when the record is refused there, and not for a word about another record, from
    nobody or from a member. Until then the switch warns. The next contact where the
    removed site takes the record counts. Counterproofs: told when the 410 is sent, the
    first two go red; the word taken without its record, the third."""
    a, b = _sides(tmp_path, 'ab')
    sides = [a, b]
    _cut(sides, b)
    _quiet(clock)
    with at(a):
        federation.remove_member(iid(b), by='admin:test', gone=True)
        end = federation.end_for(iid(b))
    _heal(sides)
    if how == 'answer lost':
        inner = b.wire

        def lost(url, method, path, body, headers):
            got = inner(url, method, path, body, headers)
            return (0, b'', {}) if url == URL['a'] else got
        b.runtime['transport'] = lost
        with at(b):
            assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] == 0
            assert federation.take_end() is False
    elif how == 'record refused':
        with monkeypatch.context() as m:
            m.setattr(federation, 'valid_end', lambda rec, sender: False)
            with at(b):
                assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] == 410
                assert federation.take_end() is False
                assert iid(a) in federation.members()
    else:
        with at(b):
            status, data, _h = federation.call_peer(
                iid(a), 'POST', federation.END_TAKEN_PATH,
                {'sig': base64.b64encode(b'\0' * 64).decode()})
        assert status == 409 and data['code'] == 'FED_END_MISMATCH'
        r = a.client.post(federation.END_TAKEN_PATH, json={'sig': end['sig']})
        assert r.status_code == 403 and r.get_json()['code'] == 'FED_NOT_MEMBER'
        d = Side(tmp_path, 'd')
        sides = [a, b, d]
        _wire(sides)
        _join(a, _code(d))
        with at(d):
            status, data, _h = federation.call_peer(iid(a), 'POST', federation.END_TAKEN_PATH,
                                                    {'sig': end['sig']})
        assert status == 403 and data['code'] == 'FED_NOT_ENDED'
    with at(a):
        assert federation.identity()['ended'][iid(b)]['told_at'] == 0
        assert federation.switch_status()['disable_warnings'] == ['ended_untold']
    _heal(sides)
    with at(b):
        assert federation.call_peer(iid(a), 'GET', federation.STATUS_PATH)[0] == 410
        assert federation.take_end() is True
    with at(a):
        assert federation.identity()['ended'][iid(b)]['told_at'] > 0
        assert 'disable_warnings' not in federation.switch_status()


def test_a_promoted_standby_writes_alone_after_its_hold(tmp_path, clock, monkeypatch):
    """a's HA group fails over while b is down. The new acting host holds for 35 s, then
    writes alone: the record and the note come with the synced key, not the lease file,
    which is new on that host."""
    a, b = _sides(tmp_path, 'ab')
    _enroll(a, 'pve-x')
    _sync(b)
    a2 = _standby_of(tmp_path, a)
    URL['a2'] = URL['a']
    try:
        _wire([a2, b])
        monkeypatch.setattr(fl, '_ha_epoch',
                            lambda: 5 if federation._runtime['lease_file'] == a2.lease_file
                            else 0)
        _cut([a2, b], b)
        for _ in range(4):
            clock.advance(10)
            r = _round(a2)['pve-x']
            assert r['held'] is False and _writes(a2, 'pve-x') is False
        clock.advance(10)
        r = _round(a2)['pve-x']
        assert r['held'] is True and r['alone'] is True and _writes(a2, 'pve-x') is True
    finally:
        URL.pop('a2', None)
