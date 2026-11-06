"""The config version, the change journal and what a sync does not carry over (#625,
stage two, slice S2).

  * The active steps cv = (epoch, seq) whenever what it hands out changed, in a segment
    of its own; every snapshot names the history its data went through.
  * A member keeps what it holds and a snapshot does not carry (config/ha_orphans)
    before the snapshot wipes it: when its tables changed since its last cv, or its cv
    is not part of the snapshot's history. In every mode. A copy that cannot be written
    refuses the snapshot, and a copy goes only when an admin dismisses it.
  * A copy is sealed: under a key derived from the master key where the database is
    SQLCipher, under the field key on plain SQLite. What copies hold already is not kept
    a second time: an account that is made again after every sync is one copy. Only a
    copy that still opens counts for that, and none goes while a sync looks at them.
  * A member in step reads and hashes nothing before the wipe: the triggers of the tick
    stay on a member and say whether anything was written between two syncs.
  * "Changed here" is decided on the rows, not on the definition of the tables: a column
    an upgrade adds or a table made on first use changes no row.
  * A member never applies a snapshot older than the one it holds from the same leader.
  * A leader whose state went back is found out: by the member that pulls and says what
    it holds, and by the mark every step of the cv has.
  * A new active names the changes it is missing (change_gap).
  * The leader of an automatic group ticks: triggers count the changes, and the walk of
    the shared tables runs only when the count moved.

Several instances in one process, as in test_ha_core: each has a state file of its own,
all share the one test database. The last part runs on the group of test_ha_members and
on the routes of test_ha_api.

MK Oct 2026
"""
import base64
import copy
import gzip
import json
import os
import stat
import types

import gevent
import pytest

from pegaprox.core import ha
from test_ha_core import env, _write_state, _wire, A, B, C  # noqa: F401
from test_ha_api import (  # noqa: F401  (ha_env is a fixture)
    ha_env, _admin, _audit, _be, _peer, _peer_record, _active_with_standby, GOOD, ADMIN_PW, B_ID,
)
from test_ha_members import group, _built, _sync, _watch, _promote, IDS, URLS  # noqa: F401

URL = {A: 'https://pp1.example:5000', B: 'https://pp2.example:5000', C: 'https://pp3.example:5000'}
D = 'd' * 32
URL[D] = 'https://pp4.example:5000'
SEG_B, SEG_C = 'b' * 16, 'c' * 16
# conftest puts a stand-in there for every test
_JOURNAL_LATER = ha._journal_later
# the master key of the instances that have one here, whatever database the run uses
MASTER = bytes(range(100, 132))


@pytest.fixture
def plain_sqlite(monkeypatch):
    """An instance on plain SQLite: no master key, a copy is sealed under the field key."""
    monkeypatch.setattr(ha, '_master_key', lambda: None)


@pytest.fixture
def master(monkeypatch):
    """An instance on SQLCipher with the master key MASTER. Returns what puts another
    one in its place, as a changed key store would after a restart."""
    held = [MASTER]
    monkeypatch.setattr(ha, '_master_key', lambda: held[0])
    return lambda key: held.__setitem__(0, key)


def _derived(master_key):
    """The key a copy is sealed under with that master key, worked out here."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'pegaprox-ha-orphans').derive(master_key)


def _as(env, who):
    """From here on this process is `who`: its own state file, the shared database."""
    env.mp.setattr(ha, 'STATE_FILE', str(env.tmp / f'{who[0]}.json'))
    ha.reset_for_tests()


def _rec(mid, role_seen, epoch=3, **kw):
    return dict({'url': URL[mid], 'fingerprint': '', 'role_seen': role_seen, 'epoch_seen': epoch,
                 'group_seen': True, 'joined_at': '2026-10-01T10:00:00+00:00'}, **kw)


def _leader(env, me=A, epoch=3, others=(B, C)):
    _as(env, me)
    _write_state(role='active', instance_id=me, epoch=epoch,
                 members={m: _rec(m, 'standby', epoch) for m in others})


def _member(env, me, source=A, epoch=3, **extra):
    """A standby of `source` that joined just now: its first snapshot replaces what it
    holds, as the admin agreed when it joined."""
    _as(env, me)
    others = [m for m in (A, B, C) if m not in (me, source)]
    members = {source: _rec(source, 'active', epoch)}
    members.update({m: _rec(m, 'standby', epoch) for m in others})
    st = dict(role='standby', instance_id=me, epoch=epoch, source=source, members=members,
              cv={'joined': True})
    st.update(extra)
    _write_state(**st)


def _follow(new_source, epoch):
    """This member follows `new_source` from now on, as ha._follow would switch it."""
    with ha._lock:
        st = ha._load()
        ms = dict(st['members'])
        # the member lists of these tests carry no keys, so a sync may have dropped it
        ms[new_source] = dict(ms.get(new_source) or _rec(new_source, 'standby'),
                              role_seen='active', epoch_seen=epoch)
        ha._commit_locked(dict(st, members=ms, source=new_source))


def _handed_on(snap, by, epoch, seg=SEG_B):
    """`snap` as `by` hands it out after it took the lead under `epoch` from exactly that
    data, before it changed anything: the same tables, its segment on the history."""
    out = copy.deepcopy(snap)
    hist = out['hist'] + [[epoch, 0, seg, by]]
    out.update(instance_id=by, epoch=epoch, role='active', hist=hist, cv=hist[-1][:2],
               base_cv=out['cv'])
    out.pop('members', None)
    out.pop('tombstones', None)
    return out


def _next_from_leader(snap, change):
    """The snapshot the same leader hands out next, after `change(tables)` happened
    there: one step on in its segment. (The instances of a test share one database, so
    a snapshot the leader makes later is made from an earlier one.)"""
    out = copy.deepcopy(snap)
    change(out['tables'])
    last = list(out['hist'][-1])
    last[1] += 1
    out.update(hist=out['hist'][:-1] + [last], cv=last[:2],
               steps=out['steps'] + [[last[2], last[1], 'f' * 8]])
    return out


def _state_text():
    with open(ha.STATE_FILE, encoding='utf-8') as fh:
        return fh.read()


def _put_state(text):
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write(text)
    ha.reset_for_tests()


def _drop_users(db, *names):
    for n in names:
        db.conn.execute('DELETE FROM users WHERE username = ?', (n,))
    db.conn.commit()


def _users(db):
    return {r['username'] for r in db.conn.execute('SELECT username FROM users')}


def _copies():
    try:
        return sorted(fn[:-len(ha.ORPHAN_SUFFIX)] for fn in os.listdir(ha.ORPHANS_DIR)
                      if fn.endswith(ha.ORPHAN_SUFFIX))
    except FileNotFoundError:
        return []


def _copy(name):
    """What the copy `name` holds, opened the way the download opens it."""
    assert name, 'no copy was kept'
    return json.loads(gzip.decompress(ha.open_orphan(name)))


def _meta(name):
    with open(os.path.join(ha.ORPHANS_DIR, name + '.meta.json'), encoding='utf-8') as fh:
        return json.load(fh)


def _kept(doc, table='users', column='username'):
    """What the copy holds of `table`, as the values of one column."""
    t = doc['tables'].get(table)
    if not t:
        return set()
    i = t['columns'].index(column)
    return {row[i] for row in t['rows']}


def _etag_at_cv():
    return ha._cv_record(ha._load()).get('etag_at_cv')


def _journal_rows(db):
    try:
        return [tuple(r) for r in db.conn.execute(
            'SELECT user, method, path, via, cv FROM ha_change_journal ORDER BY id')]
    except Exception:
        return []


def _on_another_connection(sql):
    """One committed write through a connection of its own, as a request that was on its
    way would make it."""
    def write():
        from pegaprox.core.db import get_db
        conn = get_db().conn
        conn.execute(sql)
        conn.commit()
    g = gevent.spawn(write)
    g.join()
    assert g.successful(), g.exception


# --- the config version on the active ---------------------------------------------------

def test_the_cv_steps_with_every_change_it_hands_out_and_only_then(env, db, seed):
    _leader(env)
    seed.user('alice')
    first = _wire(ha.build_snapshot())
    assert first['cv'] == [3, 1] and first['base_cv'] == [0, 0]
    seg = first['hist'][-1][2]
    assert first['hist'] == [[3, 1, seg, A]] and first['cv_at']
    assert ha.config_version() == (3, 1) and ha.cv_entry() == [3, 1, seg, A]
    assert _etag_at_cv() == ha._walk_snapshot(body=False)[0]

    # nothing changed, nothing steps; the counterproof is the next one
    assert _wire(ha.build_snapshot())['cv'] == [3, 1]
    seed.user('bob')
    assert _wire(ha.build_snapshot())['hist'] == [[3, 2, seg, A]]

    # a sign-in writes last_login: no change of the configuration
    db.conn.execute("UPDATE users SET last_login = '2026-10-01T11:00:00' WHERE username = 'bob'")
    db.conn.commit()
    assert _wire(ha.build_snapshot())['cv'] == [3, 2]
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'bob'")
    db.conn.commit()
    assert _wire(ha.build_snapshot())['cv'] == [3, 3]
    # a file the snapshot carries counts like a row
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    assert _wire(ha.build_snapshot())['cv'] == [3, 4]


def test_only_an_active_with_members_steps_a_cv(env, db, seed):
    _as(env, A)
    _write_state(role='standalone', instance_id=A, epoch=0)
    assert ha.note_config_etag('x' * 32) is None
    snap = ha.build_snapshot()
    assert 'cv' not in snap and 'hist' not in snap
    _member(env, B)
    assert ha.note_config_etag('x' * 32) is None
    assert ha.config_version() == ha.CV_ZERO and ha.peer_cv() == {}


def test_a_new_leader_writes_a_segment_of_its_own_from_what_it_holds(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    assert ha.cv_entry() == snap['hist'][-1]

    ha.promote()
    ours = _wire(ha.build_snapshot())
    # nothing changed since the sync: the same data, under a segment of its own
    assert ours['hist'][0] == snap['hist'][0]
    assert ours['hist'][1][:2] == [4, 0] and ours['hist'][1][3] == B
    assert ours['hist'][1][2] != snap['hist'][0][2]
    assert ours['base_cv'] == [3, 1] and ours['cv'] == [4, 0]
    seed.user('bob')
    assert _wire(ha.build_snapshot())['cv'] == [4, 1]


def test_a_new_leader_counts_what_it_changed_before_it_led(env, db, seed):
    """The counterproof to 4.0 above: one row of its own since the sync, and its first
    hand-out is a step."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    seed.user('made-on-b')
    ha.promote()
    assert _wire(ha.build_snapshot())['cv'] == [4, 1]


def test_an_instance_promoted_before_its_first_sync_has_no_history(env, db, seed):
    _member(env, B)
    seed.user('alice')
    ha.promote()
    snap = _wire(ha.build_snapshot())
    assert [h[:2] + h[3:] for h in snap['hist']] == [[4, 1, B]] and snap['base_cv'] == [0, 0]


def test_two_actives_under_one_epoch_never_share_a_segment(env, db, seed):
    _leader(env)
    seed.user('alice')
    a = _wire(ha.build_snapshot())
    # B was promoted to the same epoch at the same time (two admins), from A's data
    _as(env, B)
    _write_state(role='active', instance_id=B, epoch=3, members={A: _rec(A, 'standby')},
                 cv={'hist': a['hist'], 'etag_at_cv': None})
    b = _wire(ha.build_snapshot())
    # the count goes on under the same epoch, in a segment of B's own
    assert b['hist'][0] == a['hist'][0]
    assert b['hist'][1][:2] == [3, 2] and b['hist'][1][3] == B
    assert b['hist'][1][2] != a['hist'][0][2]
    # so what A wrote on under that epoch is not taken for part of B's history
    assert ha._covered([3, 2, a['hist'][0][2], A], b['hist']) is False
    assert ha._covered(a['hist'][0], b['hist']) is True


def test_a_leader_whose_state_file_went_back_starts_a_new_segment(env, db, seed):
    _leader(env)
    seed.user('alice')
    seg = _wire(ha.build_snapshot())['hist'][0][2]
    # B says it holds more of A's own segment than A knows of: A's state file came back
    # from a backup, and what B holds may be what A lost. Even with nothing changed
    # here since, what A hands out is a segment of its own, above anything B holds
    ha._note_members({B: {'cv_seen': [3, 9, seg, A]}})
    snap = _wire(ha.build_snapshot())
    assert snap['hist'][0] == [3, 1, seg, A]
    assert snap['hist'][1][:2] == [3, 10] and snap['hist'][1][2] != seg
    assert snap['base_cv'] == [3, 1]
    # B keeps a copy of what it holds of the old segment before it takes that
    assert not ha._covered([3, 9, seg, A], snap['hist'])
    # and it happens once
    assert _wire(ha.build_snapshot())['hist'] == snap['hist']


def test_a_member_behind_in_the_segment_starts_nothing_new(env, db, seed):
    _leader(env)
    seed.user('alice')
    seg = _wire(ha.build_snapshot())['hist'][0][2]
    ha._note_members({B: {'cv_seen': [3, 1, seg, A]}, C: {'cv_seen': [3, 0, seg, A]}})
    seed.user('bob')
    assert _wire(ha.build_snapshot())['hist'] == [[3, 2, seg, A]]


def _went_back(env, db, seed, second_life):
    """A hands out alice at 3.1, bob at 3.2 and carol at 3.3, and B holds 3.3. Then A's
    config directory comes back from the backup made at 3.1 (or its VM from a snapshot)
    and A goes on from there, one step for each name in `second_life`. Returns the
    snapshot B holds; this process is A, in its second life."""
    _leader(env)
    seed.user('alice')
    ha.build_snapshot()
    backup = _state_text()
    seed.user('bob')
    ha.build_snapshot()
    seed.user('carol')
    held = _wire(ha.build_snapshot())
    assert held['cv'] == [3, 3]
    _put_state(backup)
    _drop_users(db, 'bob', 'carol')
    for name in second_life:
        seed.user(name)
        ha.build_snapshot()
    return held


def _b_holds(env, db, held, second_life):
    """B as it was while A went back: the rows of A's first life."""
    _drop_users(db, *second_life)
    _member(env, B)
    ha.apply_snapshot(held)
    assert _users(db) == {'alice', 'bob', 'carol'} and ha.cv_entry() == held['hist'][-1]


@pytest.mark.parametrize('second_life', [('dave', 'erin'), ('dave', 'erin', 'frank', 'gina')],
                         ids=['as far as the member', 'past the member'])
def test_a_number_made_twice_is_told_by_its_mark(env, db, seed, second_life):
    """(#625 review) B was down while A went back and counted on, in the segment it had:
    3.3 now names two contents, and A's history covers what B holds by the numbers. B
    pulls before A's watch has asked it. What it holds of A's first life is the only
    copy left of it, and went with the DELETE unseen."""
    held = _went_back(env, db, seed, second_life)
    seg = held['hist'][-1][2]
    again = _wire(ha.build_snapshot())
    assert again['hist'] == [[3, 1 + len(second_life), seg, A]]
    marks = {(s, n): m for s, n, m in again['steps']}
    assert marks[(seg, 3)] != {(s, n): m for s, n, m in held['steps']}[(seg, 3)]

    _b_holds(env, db, held, second_life)
    summary = ha.apply_snapshot(again)
    doc = _copy(summary['captured'])
    assert 'for other content' in doc['reason'] and _kept(doc) == {'bob', 'carol'}
    assert _users(db) == {'alice', *second_life}
    # from here on B holds the second life, and its next sync keeps nothing
    assert ha.apply_snapshot(again)['captured'] is None


def test_a_member_at_the_point_the_leader_went_back_to_keeps_nothing(env, db, seed):
    """The counterproof: what C holds is where both lives of A come from."""
    _leader(env)
    seed.user('alice')
    common = _wire(ha.build_snapshot())
    backup = _state_text()
    seed.user('bob')
    ha.build_snapshot()
    _put_state(backup)
    _drop_users(db, 'bob')
    seed.user('dave')
    again = _wire(ha.build_snapshot())
    _drop_users(db, 'dave')
    _member(env, C)
    ha.apply_snapshot(common)
    assert ha.apply_snapshot(again)['captured'] is None and _copies() == []


def test_a_member_further_back_than_the_marks_reach_goes_by_the_numbers(env, db, seed, monkeypatch):
    """A snapshot names the marks of its last steps only. A member that was away for
    longer is in its history by the numbers, as before, and keeps no copy of rows the
    leader changed meanwhile."""
    monkeypatch.setattr(ha, 'STEPS_KEEP', 2)
    _leader(env)
    seed.user('alice')
    seed.user('bob')
    one = _wire(ha.build_snapshot())
    seed.user('carol')
    ha.build_snapshot()
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'bob'")
    db.conn.commit()
    ha.build_snapshot()
    seed.user('dave')
    four = _wire(ha.build_snapshot())
    assert four['cv'] == [3, 4] and [s[1] for s in four['steps']] == [3, 4]

    db.conn.execute("UPDATE users SET role = 'user' WHERE username = 'bob'")
    _drop_users(db, 'carol', 'dave')
    _member(env, B)
    ha.apply_snapshot(one)
    assert ha.apply_snapshot(four)['captured'] is None and _copies() == []


def test_the_pull_tells_a_leader_that_went_back_what_the_member_holds(env, db, seed):
    """(#625 review) While A's second life is behind what B holds, every snapshot is
    older than B's by the numbers and B refuses it. A's watch would find out, but it
    asks only every interval, and never a member that paired without an address of its
    own. The pull itself says what B holds, and A goes on in a segment of its own."""
    held = _went_back(env, db, seed, ('dave',))
    seg = held['hist'][-1][2]
    behind = _wire(ha.build_snapshot())
    assert behind['hist'] == [[3, 2, seg, A]]

    # A cannot ask B: no address
    _write_state(**dict(json.loads(_state_text()), members={B: _rec(B, 'standby', url='')}))
    assert ha._ask_members(1) == {} and 'cv_seen' not in ha.member(B)
    # the pull, as the snapshot route takes it: the etag with what B says it holds
    walked = ha._walk_snapshot(body=False)
    assert ha.held_cv(json.dumps(held['hist'][-1])) == held['hist'][-1]
    ha.note_config_etag(walked[0], data=walked[4], held=held['hist'][-1])
    told = _wire(ha.build_snapshot())
    assert told['hist'][0] == [3, 2, seg, A] and told['base_cv'] == [3, 2]
    assert told['hist'][1][:2] == [3, 4] and told['hist'][1][2] != seg
    # once: the next pull of B names a segment that is none of A's any more
    assert _wire(ha.build_snapshot())['hist'] == told['hist']

    _b_holds(env, db, held, ('dave',))
    with pytest.raises(ha.HaError, match='older than the configuration'):
        ha.apply_snapshot(behind)
    doc = _copy(ha.apply_snapshot(told)['captured'])
    assert _kept(doc) == {'bob', 'carol'} and 'does not carry' in doc['reason']
    assert _users(db) == {'alice', 'dave'}


@pytest.mark.parametrize('junk', [None, '', 'x', '[]', '[3, 1]', '{"cv": 1}', '[3, 9, "zz", "a"]',
                                  '[' + '9' * 300 + ']'])
def test_a_header_that_names_no_cv_is_none(junk):
    assert ha.held_cv(junk) is None


def test_a_cv_that_cannot_be_saved_sends_no_snapshot(env, db, seed, monkeypatch):
    _leader(env)
    seed.user('alice')

    def full(st):
        raise OSError(28, 'No space left on device')
    real = ha._write_locked
    monkeypatch.setattr(ha, '_write_locked', full)
    with pytest.raises(ha.HaError, match='could not be saved'):
        ha.build_snapshot()
    assert ha.config_version() == ha.CV_ZERO
    monkeypatch.setattr(ha, '_write_locked', real)
    assert ha.build_snapshot()['cv'] == [3, 1]


@pytest.mark.parametrize('bad', [
    None, [], 'x', [[3, 1, 'a' * 16]], [[3, 1, 'a' * 16, A, 0]], [[3, -1, 'a' * 16, A]],
    [[3, True, 'a' * 16, A]], [[3, 1.0, 'a' * 16, A]], [['3', 1, 'a' * 16, A]],
    [[2 ** 31, 1, 'a' * 16, A]], [[3, 2 ** 53, 'a' * 16, A]], [[3, 1, 'A' * 16, A]],
    [[3, 1, 'a' * 15, A]], [[3, 1, 'a' * 16, 'short']], [{'epoch': 3}],
    pytest.param([[3, 1, 'a' * 16, A], [3, 2, 'a' * 16, A]], id='segment-twice'),
    pytest.param([[4, 1, 'a' * 16, A], [3, 2, 'b' * 16, A]], id='epochs-backwards'),
    pytest.param([[3, i, f'{i:016x}', A] for i in range(ha.LINEAGE_KEEP + 1)], id='too-long'),
])
def test_a_history_that_is_none_is_read_as_none(bad):
    assert ha._clean_hist(bad) is None


def test_a_history_reads_back_as_it_was_written():
    hist = [[3, 5, 'a' * 16, A], [3, 5, 'b' * 16, B], [4, 0, 'c' * 16, C]]
    assert ha._clean_hist(hist) == hist and ha._clean_hist(hist) is not hist
    assert ha._covered([3, 5, 'a' * 16, A], hist) and ha._covered([3, 2, 'a' * 16, A], hist)
    assert not ha._covered([3, 6, 'a' * 16, A], hist)
    assert not ha._covered([3, 5, 'd' * 16, A], hist)


def test_the_history_keeps_the_last_segments_only(env, db, seed):
    _leader(env)
    seed.user('alice')
    old = [[1, i, f'{i:016x}', C] for i in range(ha.LINEAGE_KEEP)]
    _write_state(role='active', instance_id=A, epoch=3, members={B: _rec(B, 'standby')},
                 cv={'hist': old, 'etag_at_cv': None})
    snap = _wire(ha.build_snapshot())
    assert len(snap['hist']) == ha.LINEAGE_KEEP and snap['hist'][-1][:2] == [3, 1]
    # the oldest segment fell off: a member still there keeps a copy at its next sync
    assert snap['hist'][0] == old[1] and not ha._covered(old[0], snap['hist'])


# --- the order guard ---------------------------------------------------------------------

def _two_rounds(env, seed):
    """A hands out alice at 3.1, then alice and bob at 3.2. The database holds the second."""
    _leader(env)
    seed.user('alice')
    one = _wire(ha.build_snapshot())
    seed.user('bob')
    two = _wire(ha.build_snapshot())
    return one, two


def test_a_member_never_applies_an_older_snapshot_of_the_same_leader(env, db, seed):
    one, two = _two_rounds(env, seed)
    _member(env, C)
    ha.apply_snapshot(two)
    assert ha.config_version() == (3, 2)

    with pytest.raises(ha.HaError, match='older than the configuration this instance holds'):
        ha.apply_snapshot(one)
    assert _users(db) >= {'alice', 'bob'} and ha.config_version() == (3, 2)
    assert _copies() == []

    # the same one again is no step back
    assert ha.apply_snapshot(two)['captured'] is None
    assert ha.config_version() == (3, 2)


def test_the_order_guard_holds_within_a_segment_only(env, db, seed):
    one, two = _two_rounds(env, seed)
    _member(env, C)
    ha.apply_snapshot(two)
    # B took the lead from alice alone: its cv is lower, its segment another. Not the
    # guard's case; C's bob is not in B's history, and C keeps it before it follows
    from_b = _handed_on(one, B, 4)
    _follow(B, 4)
    summary = ha.apply_snapshot(from_b)
    assert _kept(_copy(summary['captured'])) == {'bob'}
    assert ha.config_version() == (4, 0)


# --- what a snapshot does not carry over ---------------------------------------------------

def test_a_former_active_keeps_what_it_took_after_its_last_hand_out(env, db, seed):
    """4.11 / C1, the write in the last seconds before the cut: A handed out alice at
    3.1, B synced that and was promoted while A could not be reached; A took carol
    before it heard about B. Nothing walked in between."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    assert 'orphans' not in ha.banner()

    summary = ha.apply_snapshot(from_b)

    name = summary['captured']
    assert name and _copies() == [name]
    doc = _copy(name)
    # the row that would have gone, and only that one
    assert list(doc['tables']) == ['users'] and _kept(doc) == {'carol'}
    assert doc['differences'] == {'users': {'only_here': 1, 'only_there': 0}}
    assert (doc['instance_id'], doc['role'], doc['cv']) == (A, 'standby', snap['hist'][-1])
    assert doc['replaced_by'] == {'instance_id': B, 'epoch': 4, 'cv': from_b['hist'][-1]}
    assert 'changed after it was last synced' in doc['reason']
    assert 'carol' not in _users(db)
    audit = _audit('ha.changes_not_carried_over')
    assert len(audit) == 1 and name in audit[0]['details'] and '"only_here": 1' in audit[0]['details']
    listed = ha.public_status()['orphans']
    assert listed['count'] == 1 and listed['bytes'] > 0 and listed['over_limit'] is False
    assert listed['items'][0]['name'] == name
    assert listed['items'][0]['differences'] == doc['differences']
    assert ha.banner()['orphans'] == 1
    # from now on it holds B's history
    assert ha.cv_entry() == from_b['hist'][-1]


def test_a_former_active_that_changed_nothing_keeps_nothing(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    assert ha.step_down(4, B)

    assert ha.apply_snapshot(from_b)['captured'] is None
    assert _copies() == [] and _audit('ha.changes_not_carried_over') == []
    assert 'orphans' not in ha.banner() and ha.public_status()['orphans']['count'] == 0


def test_a_former_active_keeps_no_copy_of_what_the_new_one_changed(env, db, seed):
    """It changed nothing after its last hand-out, and the new active has moved on by
    the time it pulls: its rows are the older version, not changes of its own."""
    _leader(env)
    for name in ('alice', 'bob', 'carol'):
        seed.user(name)
    snap = _wire(ha.build_snapshot())
    from_b = _next_from_leader(_handed_on(snap, B, 4), _moves_on)
    assert from_b['cv'] == [4, 1]
    assert ha.step_down(4, B)
    assert ha.apply_snapshot(from_b)['captured'] is None and _copies() == []
    assert _users(db) == {'alice', 'bob'}


def test_a_row_this_instance_deleted_and_the_snapshot_brings_back_is_told(env, db, seed):
    """Nothing here would go, and still a change is not carried over: the delete."""
    _leader(env)
    seed.user('alice')
    seed.user('mallory')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    ha.note_write('root', 'DELETE', '/api/users/mallory')
    db.conn.execute("DELETE FROM users WHERE username = 'mallory'")
    db.conn.commit()
    assert ha.step_down(4, B)

    doc = _copy(ha.apply_snapshot(from_b)['captured'])
    assert doc['differences'] == {'users': {'only_here': 0, 'only_there': 1}} and doc['tables'] == {}
    assert [(j['method'], j['path']) for j in doc['journal']] == [('DELETE', '/api/users/mallory')]
    assert 'mallory' in _users(db)


def test_rows_only_the_snapshot_has_make_no_copy(env, db, seed):
    """(#625 review) The counterpart: a member that cannot show where its rows come from
    compares, and the snapshot only has more. Nothing here would go and nobody wrote
    here, so there is nothing to keep: no file with no row in it, no audit, no banner."""
    _leader(env)
    seed.user('alice')
    seed.user('bob')
    snap = _wire(ha.build_snapshot())
    _drop_users(db, 'bob')
    _member(env, B, cv=None)
    assert ha.apply_snapshot(snap)['captured'] is None
    assert _copies() == [] and 'orphans' not in ha.banner()
    assert _audit('ha.changes_not_carried_over') == [] and 'bob' in _users(db)


def test_a_row_changed_here_is_kept_as_it_was_here(env, db, seed):
    _leader(env)
    seed.user('alice', role='admin')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    db.conn.execute("UPDATE users SET role = 'viewer' WHERE username = 'alice'")
    db.conn.commit()
    assert ha.step_down(4, B)
    doc = _copy(ha.apply_snapshot(from_b)['captured'])
    assert doc['differences'] == {'users': {'only_here': 1, 'only_there': 1}}
    assert _kept(doc, 'users', 'role') == {'viewer'}


def test_a_standby_ahead_of_the_promoted_one_keeps_what_it_is_ahead_by(env, db, seed):
    one, two = _two_rounds(env, seed)
    _member(env, C)
    ha.apply_snapshot(two)
    # B was promoted from 3.1 only
    _follow(B, 4)
    summary = ha.apply_snapshot(_handed_on(one, B, 4))
    doc = _copy(summary['captured'])
    assert 'not carry' in doc['reason'] and doc['cv'][:2] == [3, 2]
    assert _kept(doc) == {'bob'} and 'bob' not in _users(db)


def test_a_standby_as_far_as_the_promoted_one_keeps_nothing(env, db, seed):
    one, _two = _two_rounds(env, seed)
    _as(env, A)
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    _member(env, C)
    ha.apply_snapshot(one)
    _follow(B, 4)
    assert ha.apply_snapshot(_handed_on(one, B, 4))['captured'] is None
    assert _copies() == []


def test_a_member_two_leaders_behind_keeps_what_the_history_never_had(env, db, seed):
    """A led to 3.2. B took over from 3.1 and never had bob; C took over from B. D, still
    at A's 3.2, comes back under C. Its cv is below the base C's snapshot names (4.0),
    so a rule on cv and base_cv alone would take it for a part of that history."""
    one, two = _two_rounds(env, seed)
    from_c = _handed_on(_handed_on(one, B, 4), C, 5, seg=SEG_C)
    assert from_c['base_cv'] == [4, 0] and len(from_c['hist']) == 3
    _as(env, D)
    _write_state(role='standby', instance_id=D, epoch=3, source=A,
                 members={A: _rec(A, 'active'), C: _rec(C, 'standby')}, cv={'joined': True})
    ha.apply_snapshot(two)
    assert ha.config_version() == (3, 2) and ha.config_version() <= tuple(from_c['base_cv'])

    _follow(C, 5)
    summary = ha.apply_snapshot(from_c)
    assert _kept(_copy(summary['captured'])) == {'bob'}
    assert ha.config_version() == (5, 0)

    # the counterproof: a member at 3.1, where B left A's segment, is part of it
    _as(env, B)
    _write_state(role='standby', instance_id=B, epoch=3, source=A,
                 members={A: _rec(A, 'active'), C: _rec(C, 'standby')}, cv={'joined': True})
    ha.apply_snapshot(one)
    assert ha.config_version() == (3, 1)
    _follow(C, 5)
    assert ha.apply_snapshot(from_c)['captured'] is None


def test_no_copy_when_the_snapshot_holds_exactly_what_is_here(env, db, seed):
    """A member from before the cv has no record of where its data comes from, and still
    keeps nothing when there is nothing a snapshot would change."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    # a snapshot that carries one of the receiver's own settings never writes it
    settings = snap['tables']['server_settings']
    row = [None] * len(settings['columns'])
    row[settings['columns'].index('key')], row[settings['columns'].index('value')] = 'port', '5999'
    settings['rows'].append(row)
    _member(env, B, cv=None)
    # what a sign-in writes and what belongs to this host is no difference either
    db.conn.execute("UPDATE users SET last_login = 'here, a moment ago'")
    db.conn.commit()
    db.save_server_setting('port', 5001)
    assert ha.apply_snapshot(snap)['captured'] is None
    assert _copies() == [] and db.get_server_setting('port') == 5001
    # the counterproof: one row of its own, and it is kept
    _member(env, C, cv=None)
    seed.user('mallory')
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc) == {'mallory'} and 'no record' in doc['reason']
    # and the setting of this host that the snapshot carries is no difference in it
    assert doc['differences'] == {'users': {'only_here': 1, 'only_there': 0}}


def test_the_first_snapshot_after_joining_replaces_without_a_copy(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    seed.user('standalone-admin')
    _member(env, B)                   # joined: the admin agreed that its configuration goes
    assert ha.apply_snapshot(snap)['captured'] is None
    assert 'standalone-admin' not in _users(db) and ha.cv_entry() == snap['hist'][-1]
    # only the first: from then on what it holds is the group's
    seed.user('made-on-b')
    assert _kept(_copy(ha.apply_snapshot(snap)['captured'])) == {'made-on-b'}


def test_a_member_from_before_the_cv_pulls_on_from_its_active(env, db, seed):
    """No record yet, but the last sync came from this very active under this epoch: what
    it holds came from there."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    seed.user('older-copy')
    synced = {'last_ok_at': '2026-10-01T10:00:00+00:00', 'source_epoch': 3}
    _member(env, B, cv=None, sync=synced)
    assert ha.apply_snapshot(snap)['captured'] is None
    # another epoch since that sync (a failover around the upgrade): a copy
    seed.user('older-copy')
    _member(env, C, cv=None, sync=dict(synced, source_epoch=2))
    assert ha.apply_snapshot(snap)['captured']


def test_a_standby_in_step_with_its_active_never_keeps_a_copy(env, db, seed):
    """Manual mode as it was: rounds of adds, changes and deletes on the active reach the
    standby without a copy. The counterproof: one change made on the standby itself."""
    _leader(env)
    seed.user('alice')
    snaps = [_wire(ha.build_snapshot())]
    seed.user('bob')
    snaps.append(_wire(ha.build_snapshot()))
    db.conn.execute("DELETE FROM users WHERE username = 'alice'")
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'bob'")
    db.conn.commit()
    snaps.append(_wire(ha.build_snapshot()))
    _as(env, A)
    db.conn.execute("DELETE FROM users")
    db.conn.commit()
    _member(env, B)
    for snap in snaps:
        assert ha.apply_snapshot(snap)['captured'] is None
        # what it noted is what its tables and files hash to
        assert _etag_at_cv() == ha._walk_snapshot(body=False)[0]
    assert _users(db) == {'bob'} and _copies() == []

    db.conn.execute("UPDATE users SET role = 'viewer' WHERE username = 'bob'")
    db.conn.commit()
    doc = _copy(ha.apply_snapshot(snaps[-1])['captured'])
    assert _kept(doc, 'users', 'role') == {'viewer'}


def test_the_etag_a_member_notes_takes_in_the_files_the_sync_wrote(env, db, seed):
    """The tables are hashed inside the apply, the files only once they are written. With
    the files as they were before, every sync that brought one would look like a change
    made here at the next."""
    _leader(env)
    seed.user('alice')
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    os.remove(ha.KNOWN_HOSTS_FILE)
    ha.apply_snapshot(snap)
    assert os.path.exists(ha.KNOWN_HOSTS_FILE)
    assert _etag_at_cv() == ha._walk_snapshot(body=False)[0]
    # so the next snapshot of that history finds this member in step
    _as(env, A)
    seed.user('bob')
    two = _wire(ha.build_snapshot())
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    _as(env, B)
    assert ha.apply_snapshot(two)['captured'] is None


def test_what_a_serving_standby_writes_itself_is_no_change(env, db, seed):
    """A sign-in on a standby that serves users writes last_login and a passkey counter, a
    plugin notes its load error at boot: VOLATILE_COLUMNS, no copy for them."""
    _leader(env)
    seed.user('alice')
    db.conn.execute('INSERT INTO webauthn_credentials (username, credential_id, public_key, name, '
                    "user_handle, created_at, sign_count) VALUES ('alice', ?, ?, 'key', ?, '2026-10-01', 1)",
                    (b'\x01cred', b'\x04' + bytes(64), b'\x00h'))
    db.conn.execute("INSERT INTO plugin_state (plugin_id, enabled, error) VALUES ('probe', 1, '')")
    db.conn.commit()
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)

    db.conn.execute("UPDATE webauthn_credentials SET sign_count = 7, last_used_at = 'now'")
    db.conn.execute("UPDATE users SET last_login = 'now'")
    db.conn.execute("UPDATE plugin_state SET error = 'ImportError: no module named x'")
    db.conn.commit()
    assert ha.apply_snapshot(snap)['captured'] is None

    db.conn.execute("UPDATE webauthn_credentials SET name = 'renamed here'")
    db.conn.commit()
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'webauthn_credentials', 'name') == {'renamed here'}


def test_a_write_that_lands_while_the_apply_looks_is_still_seen(env, db, seed, monkeypatch):
    """A request that passed the write gate before this instance stepped down commits
    while the sync is under way: after the look at what is here, before the wipe. The
    apply looks again once it holds the write lock."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    assert ha.step_down(4, B)
    real, late = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        if not late:
            late.append(1)
            _on_another_connection(
                "INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'late')")
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)

    summary = ha.apply_snapshot(from_b)

    assert late and _kept(_copy(summary['captured']), 'vm_tags', 'tag_name') == {'late'}
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 0
    assert len(_audit('ha.changes_not_carried_over')) == 1
    # and what it notes afterwards is what the snapshot left here, nothing later
    assert _etag_at_cv() == ha._walk_snapshot(body=False)[0]


def test_a_write_right_after_the_sync_is_a_change_made_here(env, db, seed, monkeypatch):
    """The other side of the same race: a request commits the moment the sync has. What
    this instance notes as the state of the sync must not take that write in, or the
    next sync would wipe it as part of what the active handed out."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    real = ha._apply_files

    def files(sent):
        _on_another_connection(
            "INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'right-after')")
        return real(sent)
    monkeypatch.setattr(ha, '_apply_files', files)
    ha.apply_snapshot(snap)
    monkeypatch.setattr(ha, '_apply_files', real)
    assert _etag_at_cv() != ha._walk_snapshot(body=False)[0]
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'vm_tags', 'tag_name') == {'right-after'}


@pytest.mark.parametrize('meanwhile', ['promoted with force', 'follows another member', 'left the group'])
def test_a_snapshot_is_not_applied_to_what_is_no_standby_of_its_sender_any_more(
        env, db, seed, monkeypatch, meanwhile):
    """(#625 review) The look at what is here gives the hub away, for seconds on a large
    configuration, and the checks of role, source and epoch were all before it. A
    promotion with force went through meanwhile, and the apply then replaced the
    configuration of the instance that leads now with the snapshot of the leader it
    replaced."""
    _leader(env)
    seed.user('alice')
    one = _wire(ha.build_snapshot())
    seed.user('bob')
    two = _wire(ha.build_snapshot())
    _drop_users(db, 'bob')
    _member(env, B)
    ha.apply_snapshot(one)
    seed.user('made-on-b')
    real, done = ha._in_pool, []

    def look(fn):
        out = real(fn)
        if not done:
            # what the hub served while the worker read and hashed
            done.append(ha.promote() if meanwhile == 'promoted with force'
                        else _follow(C, 3) if meanwhile == 'follows another member' else ha.unpair())
        return out
    monkeypatch.setattr(ha, '_in_pool', look)

    with pytest.raises(ha.HaError, match='changed its role or the member it follows'):
        ha.apply_snapshot(two)
    assert done and _users(db) == {'alice', 'made-on-b'}
    if meanwhile == 'promoted with force':
        assert ha.role() == ha.ROLE_ACTIVE and ha.epoch() == 4
        # and it leads from what it holds: its own row is one step on A's history
        monkeypatch.setattr(ha, '_in_pool', real)
        ours = _wire(ha.build_snapshot())
        assert ours['hist'][0] == one['hist'][-1] and ours['cv'] == [4, 1]


def test_a_promotion_waits_for_the_sync_that_is_under_way(env, db, monkeypatch):
    """The other half: a promotion comes before a sync or after it. With force the route
    took no look at the pull lock at all."""
    _member(env, B)
    done = []
    assert ha._pull_lock.acquire(timeout=1)
    try:
        g = gevent.spawn(lambda: done.append(ha.promote()))
        gevent.sleep(0.05)
        assert done == [] and ha.role() == ha.ROLE_STANDBY
    finally:
        ha._pull_lock.release()
    # a slow one left running would change the role under the next test
    g.join(60)
    assert done == [4] and ha.role() == ha.ROLE_ACTIVE

    # a sync that hangs on a source that is gone does not hold the failover up for good
    _member(env, C)
    monkeypatch.setattr(ha, 'PROMOTE_PULL_WAIT', 0.05)
    assert ha._pull_lock.acquire(timeout=1)
    try:
        assert ha.promote() == 4
    finally:
        ha._pull_lock.release()


def test_a_column_only_this_instance_has_is_no_change_until_something_is_in_it(env, db, seed):
    """A member updated before its active has columns the snapshot cannot carry. At their
    default nothing is lost with them."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    db.conn.execute("ALTER TABLE users ADD COLUMN added_here TEXT DEFAULT 'none'")
    db.conn.execute('ALTER TABLE users ADD COLUMN added_bare TEXT')
    db.conn.commit()
    _member(env, B, cv=None)
    assert ha.apply_snapshot(snap)['captured'] is None

    db.conn.execute("UPDATE users SET added_here = 'set on this instance'")
    db.conn.commit()
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert doc['differences'] == {'users': {'only_here': 1, 'only_there': 1}}
    assert _kept(doc, 'users', 'added_here') == {'set on this instance'}


def test_a_column_only_the_snapshot_has_is_no_change_here(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    users = snap['tables']['users']
    users['columns'].append('added_there')
    users['coldefs']['added_there'] = ['TEXT', None]
    for row in users['rows']:
        row.append('x')
    _member(env, B, cv=None)
    assert ha.apply_snapshot(snap)['captured'] is None


def _moves_on(tables):
    """On the leader, since the last sync: bob became an admin and carol was deleted."""
    t = tables['users']
    u, r = t['columns'].index('username'), t['columns'].index('role')
    t['rows'] = [row for row in t['rows'] if row[u] != 'carol']
    for row in t['rows']:
        if row[u] == 'bob':
            row[r] = 'admin'


def test_a_column_an_upgrade_adds_here_is_no_change_made_here(env, db, seed):
    """(#625 review) A standby in step is upgraded before its active, and the migration
    adds columns to a shared table. No row was changed here. The etag says otherwise, it
    stands for the definition of the tables too, and the compare that followed kept
    every row the LEADER had changed or deleted since as a change made here."""
    _leader(env)
    for name in ('alice', 'bob', 'carol'):
        seed.user(name)
    one = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(one)
    assert ha.apply_snapshot(one)['captured'] is None

    db.conn.execute('ALTER TABLE users ADD COLUMN added_by_the_new_release TEXT')
    db.conn.execute('ALTER TABLE users ADD COLUMN shown INTEGER DEFAULT 1')
    db.conn.commit()
    walked = ha._walk_snapshot(body=False)
    rec = ha._cv_record(ha._load())
    assert walked[0] != rec['etag_at_cv'] and walked[4] == rec['data_at_cv']

    two = _next_from_leader(one, _moves_on)
    assert ha.apply_snapshot(two)['captured'] is None
    assert _copies() == [] and 'orphans' not in ha.banner()
    assert _audit('ha.changes_not_carried_over') == []
    assert {r['username']: r['role'] for r in db.conn.execute('SELECT username, role FROM users')
            } == {'alice': 'user', 'bob': 'admin'}

    # the counterproof: a value in the new column is a change made here
    db.conn.execute("UPDATE users SET added_by_the_new_release = 'set here' WHERE username = 'bob'")
    db.conn.commit()
    doc = _copy(ha.apply_snapshot(two)['captured'])
    assert 'changed after it was last synced' in doc['reason'] and _kept(doc) == {'bob'}


def test_the_digest_of_the_rows_moves_with_a_row_and_with_nothing_else(env, db, seed):
    _leader(env)
    seed.user('alice')
    etag, data = ha._walk_snapshot(body=False)[::4]
    # what an upgrade or a first use does to the schema
    for ddl in ('ALTER TABLE users ADD COLUMN added_bare TEXT',
                "ALTER TABLE users ADD COLUMN added_text TEXT DEFAULT 'none'",
                'ALTER TABLE users ADD COLUMN added_count INTEGER DEFAULT 0',
                'ALTER TABLE users ADD COLUMN added_rate REAL DEFAULT 1',
                'CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)'):
        db.conn.execute(ddl)
    db.conn.commit()
    walked = ha._walk_snapshot(body=False)
    assert walked[4] == data and walked[0] != etag

    seen = {data}
    for sql in ("UPDATE users SET added_bare = 'x'", "UPDATE users SET added_text = 'more'",
                'UPDATE users SET added_count = NULL', 'UPDATE users SET added_rate = 0.5',
                "INSERT INTO pegaprox_kv (k, v) VALUES ('a', 'b')", 'DELETE FROM pegaprox_kv',
                'DELETE FROM users'):
        db.conn.execute(sql)
        db.conn.commit()
        now = ha._walk_snapshot(body=False)[4]
        if sql == 'DELETE FROM pegaprox_kv':
            # empty again, as if it had never been made
            assert now in seen
        else:
            assert now not in seen, sql
        seen.add(now)
    # what a login writes moves neither
    seed.user('bob')
    etag, data = ha._walk_snapshot(body=False)[::4]
    db.conn.execute("UPDATE users SET last_login = 'now'")
    db.conn.commit()
    assert ha._walk_snapshot(body=False)[::4] == (etag, data)


def test_a_table_made_on_first_use_on_a_standby_is_no_change(ha_env, db, seed):
    """(#625 review) No upgrade needed: GET /api/pbs/verify-schedule makes the shared
    table pegaprox_kv the first time it is asked, on a standby as well."""
    admin = _admin(ha_env.api, seed)
    seed.user('bob')
    seed.user('carol')
    _be(ha_env, 'active', instance_id='a' * 32, epoch=1, peer=_peer_record())
    one = _wire(ha.build_snapshot())
    assert one['hist'] and 'pegaprox_kv' not in one['tables']
    _be(ha_env, 'standby', instance_id=B_ID, epoch=1, forward_writes=False,
        peer=_peer_record('a' * 32, 'https://active.example:5000', 'active'), cv={'joined': True})
    ha.apply_snapshot(one)

    r = admin.get('/api/pbs/verify-schedule')
    assert r.status_code == 200, r.data
    assert db.conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'pegaprox_kv'").fetchone()

    assert ha.apply_snapshot(_next_from_leader(one, _moves_on))['captured'] is None
    assert _audit('ha.changes_not_carried_over') == []
    assert admin.get('/api/ha/status').get_json()['orphans']['count'] == 0


def test_a_table_the_sender_does_not_carry_is_kept_before_it_is_emptied(env, db, seed, monkeypatch):
    """(#625 review) The first time SYNC_TABLES grows: B runs the release before the new
    table, A and C the one with it. B is promoted in step and hands out its segment on
    top of A's history. C's cv is in it and C changed nothing, and the sync still
    empties the table B's snapshots never had. A history says what the sender was
    handed, not what its release hands on."""
    _leader(env)
    seed.user('alice')
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    from_a = _wire(ha.build_snapshot())
    assert from_a['tables']['vm_tags']['rows']

    older = tuple(t for t in ha.SYNC_TABLES if t != 'vm_tags')
    _member(env, B)
    monkeypatch.setattr(ha, 'SYNC_TABLES', older)
    ha.apply_snapshot(from_a)
    ha.promote()
    from_b = _wire(ha.build_snapshot())
    assert 'vm_tags' not in from_b['tables'] and from_b['hist'][0] == from_a['hist'][0]
    monkeypatch.setattr(ha, 'SYNC_TABLES', older + ('vm_tags',))

    _member(env, C, source=A)
    ha.apply_snapshot(from_a)
    _follow(B, 4)
    summary = ha.apply_snapshot(from_b)
    doc = _copy(summary['captured'])
    assert doc['reason'] == 'the snapshot carries no vm_tags, and there are rows of it here'
    assert _kept(doc, 'vm_tags', 'tag_name') == {'prod'} and list(doc['tables']) == ['vm_tags']
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 0
    # empty now, and no reason for a copy any more
    assert ha.apply_snapshot(from_b)['captured'] is None and len(_copies()) == 1


def test_files_the_snapshot_would_replace_are_kept_as_they_were(env, db, seed):
    _leader(env)
    seed.user('alice')
    os.makedirs(ha.BRANDING_DIR)
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n10.0.0.12 ssh-ed25519 AAAAC3Nzb\n')
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'\x89PNG the active')
    snap = _wire(ha.build_snapshot())

    # the same pins in another order, and a file the snapshot does not touch: no change
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.12 ssh-ed25519 AAAAC3Nzb\n\n10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    with open(os.path.join(ha.BRANDING_DIR, 'only-here.png'), 'wb') as fh:
        fh.write(b'stays')
    _member(env, B, cv=None)
    assert ha.apply_snapshot(snap)['captured'] is None

    with open(ha.KNOWN_HOSTS_FILE, 'a') as fh:
        fh.write('10.0.0.99 ssh-ed25519 pinned-here\n')
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'\x89PNG this instance')
    _member(env, C, cv=None)
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert doc['differences'] == {'files': ['ssh_known_hosts', 'branding/login-bg.png']}
    assert 'pinned-here' in doc['files']['ssh_known_hosts'] and doc['tables'] == {}
    assert list(doc['files']['branding']) == ['login-bg.png']


def test_an_active_of_an_earlier_release_names_no_history(env, db, seed):
    """Its snapshots carry no hist. A member in step with that very active under that very
    epoch still is; anybody else compares."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    for key in ('hist', 'cv', 'base_cv', 'cv_at'):
        snap.pop(key)
    _member(env, B)
    ha.apply_snapshot(snap)
    rec = ha._cv_record(ha._load())
    assert rec['hist'] == [] and rec['from'] == [A, 3] and ha.config_version() == ha.CV_ZERO
    assert ha.apply_snapshot(snap)['captured'] is None

    # another instance sends the same rows: nothing to compare the histories by, so
    # the rows decide
    other = dict(copy.deepcopy(snap), instance_id=C, epoch=4)
    other.pop('members', None)
    other.pop('tombstones', None)
    seed.user('made-on-b')
    _follow(C, 4)
    doc = _copy(ha.apply_snapshot(other)['captured'])
    assert 'neither side' in doc['reason'] and _kept(doc) == {'made-on-b'}


@pytest.mark.parametrize('claimed', ['of another leader', 'of another epoch'])
def test_a_history_that_does_not_end_with_its_sender_names_nothing(env, db, seed, claimed):
    """C is in step with A at 3.2. B sends alice alone under epoch 4, with a history that
    goes through 3.2 but does not end with a segment of B's own under that epoch. Taken
    at its word, it would wipe bob unseen; it is compared row by row instead. With the
    history as B would really write it, test_a_standby_as_far_as_the_promoted_one_keeps_
    nothing is the counterproof."""
    one, two = _two_rounds(env, seed)
    _member(env, C)
    ha.apply_snapshot(two)
    bad = _handed_on(one, B, 4)
    bad['hist'] = two['hist'] if claimed == 'of another leader' else two['hist'] + [[3, 0, SEG_B, B]]
    _follow(B, 4)
    doc = _copy(ha.apply_snapshot(bad)['captured'])
    assert 'neither side' in doc['reason'] and _kept(doc) == {'bob'}
    assert ha._cv_record(ha._load())['hist'] == []


def test_a_copy_that_cannot_be_written_refuses_the_snapshot(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    # the folder cannot be made: a file stands where it would go
    with open(ha.ORPHANS_DIR, 'w') as fh:
        fh.write('in the way')

    with pytest.raises(ha.HaError, match='could not keep a copy'):
        ha.apply_snapshot(from_b)
    assert 'carol' in _users(db) and ha.cv_entry() == snap['hist'][-1]
    assert len(_audit('ha.changes_not_kept')) == 1 and _audit('ha.changes_not_carried_over') == []

    os.remove(ha.ORPHANS_DIR)
    assert ha.apply_snapshot(from_b)['captured']
    assert 'carol' not in _users(db)


def test_a_copy_that_cannot_be_written_is_audited_once_not_with_every_try(env, db, seed, caplog):
    """(#625 review) The loop tries again every interval and after every note of the
    leader. A config directory that stays full got an audit row each time, about 2900 a
    day, on the disk that is full."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    with open(ha.ORPHANS_DIR, 'w') as fh:
        fh.write('in the way')

    for _ in range(5):
        with pytest.raises(ha.HaError, match='could not keep a copy'):
            ha.apply_snapshot(from_b)
    assert len(_audit('ha.changes_not_kept')) == 1
    # the log still says so every time
    assert sum('no copy of it could be kept' in r.getMessage() for r in caplog.records) == 5

    # said again once a sync went through in between: the same sender, reason and error
    os.remove(ha.ORPHANS_DIR)
    assert ha.apply_snapshot(from_b)['captured']
    seed.user('dave')
    os.rename(ha.ORPHANS_DIR, ha.ORPHANS_DIR + '.aside')
    with open(ha.ORPHANS_DIR, 'w') as fh:
        fh.write('in the way again')
    for _ in range(2):
        with pytest.raises(ha.HaError, match='could not keep a copy'):
            ha.apply_snapshot(from_b)
    assert len(_audit('ha.changes_not_kept')) == 2


def test_a_copy_is_private_and_keeps_sealed_values_sealed(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    sealed = db._encrypt('bmc-password-in-clear')
    db.conn.execute("INSERT INTO node_bmc_endpoints (cluster_id, node, bmc_host, bmc_password_encrypted) "
                    "VALUES ('c1', 'n1', '10.0.0.9', ?)", (sealed,))
    db.conn.commit()
    assert ha.step_down(4, B)
    # the folder is there already, and open to everybody
    os.mkdir(ha.ORPHANS_DIR, 0o755)
    old = os.umask(0)
    try:
        name = ha.apply_snapshot(from_b)['captured']
    finally:
        os.umask(old)

    path = os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.join(ha.ORPHANS_DIR, name + '.meta.json')).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(ha.ORPHANS_DIR).st_mode) == 0o700
    raw = gzip.decompress(ha.open_orphan(name))
    assert b'bmc-password-in-clear' not in raw and sealed.encode() in raw


def _on_disk():
    """Every byte ORPHANS_DIR holds, and the same once more for what is gzip in there."""
    out = b''
    for fn in sorted(os.listdir(ha.ORPHANS_DIR)):
        with open(os.path.join(ha.ORPHANS_DIR, fn), 'rb') as fh:
            data = fh.read()
        out += data
        try:
            out += gzip.decompress(data)
        except OSError:
            pass
    return out


def test_a_copy_is_sealed_on_disk_and_its_meta_holds_no_row(env, db, seed):
    """(#625 review) With SQLCipher the database file holds no readable row. A copy was
    gzip'd JSON next to it: user names, password hashes and salts, and who wrote what."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    db.save_user('marker-user-7f3a', {'password_salt': 'marker-salt-91c2', 'role': 'admin',
                                       'password_hash': 'marker-hash-5be8', 'tenant_id': 'default',
                                       'enabled': True})
    assert ha.note_write('marker-admin-22d1', 'POST', '/api/users/marker-path-c0de', '') is True
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']

    assert sorted(os.listdir(ha.ORPHANS_DIR)) == [name + '.json.gz.enc', name + '.meta.json']
    disk = _on_disk()
    assert disk and b'marker-' not in disk
    with open(os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX), 'rb') as fh:
        assert fh.read().startswith(ha._copy_head(*ha._copy_key()))
    # the download opens it, and everything is in there
    clear = gzip.decompress(ha.open_orphan(name))
    for marker in (b'marker-user-7f3a', b'marker-salt-91c2', b'marker-hash-5be8',
                   b'marker-admin-22d1', b'marker-path-c0de'):
        assert marker in clear
    # the meta file stays readable: where and why, counts and digests
    meta = _meta(name)
    assert set(meta) == set(ha._ORPHAN_META_KEYS) | {'name', 'differences', 'journal_rows', 'bytes',
                                                     'items', 'repeats', 'last_at'}
    assert meta['differences'] == {'users': {'only_here': 1, 'only_there': 0}}
    assert meta['journal_rows'] == 1 and meta['repeats'] == 0 and meta['last_at'] is None
    assert len(meta['items']) == 2 and all(len(i) == 16 for i in meta['items'])
    item = ha.orphan_captures()[0]
    assert item['name'] == name and item['bytes'] == os.path.getsize(
        os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX))


def test_a_copy_opens_only_as_the_file_it_was_written_as(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']
    path = os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX)
    with open(path, 'rb') as fh:
        raw = fh.read()
    assert _kept(_copy(name)) == {'carol'}
    assert ha.open_orphan('1-1-20261001T100000Z-abcdefabcdef') is None

    # under the name of another copy
    other = name[:-1] + ('0' if name[-1] != '0' else '1')
    with open(os.path.join(ha.ORPHANS_DIR, other + ha.ORPHAN_SUFFIX), 'wb') as fh:
        fh.write(raw)
    with pytest.raises(ha.HaError, match='changed or damaged'):
        ha.open_orphan(other)
    # one byte of it changed
    with open(path, 'wb') as fh:
        fh.write(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(ha.HaError, match='changed or damaged'):
        ha.open_orphan(name)
    # cut short, or something else altogether (a copy as it was before they were sealed)
    for junk in (raw[:30], b'', gzip.compress(b'{"tables": {}}')):
        with open(path, 'wb') as fh:
            fh.write(junk)
        with pytest.raises(ha.HaError, match='not a copy as this instance seals them'):
            ha.open_orphan(name)


def test_without_a_field_key_nothing_is_kept_and_nothing_is_wiped(env, db, seed, monkeypatch,
                                                                  plain_sqlite):
    """A copy never goes to disk in the clear: no key, no copy, and the snapshot is
    refused like one whose copy could not be written."""
    monkeypatch.setattr(db, 'aes_key', None)
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    with pytest.raises(ha.HaError, match=r'could not keep a copy of them \(HaError\)'):
        ha.apply_snapshot(from_b)
    assert 'carol' in _users(db) and not os.path.exists(ha.ORPHANS_DIR)
    with pytest.raises(ha.HaError, match='no field key to seal a copy under'):
        ha._field_key()


def test_a_copy_from_before_a_key_rotation_opens_with_the_key_that_was_kept(env, db, seed,
                                                                           plain_sqlite):
    """(#625 review) On plain SQLite a copy is sealed under the field key of its moment.
    After a key rotation it opens with the backup the rotation left next to the key
    file; once that is gone it says which key it wants, in words."""
    import pegaprox.core.db as dbmod
    env.mp.setattr(ha, 'AES_KEY_FILE', os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']
    fp = ha.key_fingerprint()

    stats = db.rotate_encryption_key()
    assert stats.get('success') and ha.key_fingerprint() != fp
    backup = os.path.basename(stats['key_backup'])
    assert ha.orphan_captures()[0]['key'] == {'fp': fp, 'current': False, 'backup': backup}
    assert ha.orphan_captures()[0]['seal'] == {'under': 'field', 'fp': fp, 'current': False,
                                               'backup': backup, 'opens': True}
    assert _kept(_copy(name)) == {'carol'}

    os.rename(os.path.join(dbmod.CONFIG_DIR, backup), os.path.join(dbmod.CONFIG_DIR, 'moved-away'))
    assert ha.orphan_captures()[0]['key'] == {'fp': fp, 'current': False, 'backup': None}
    assert ha.orphan_captures()[0]['seal'] == {'under': 'field', 'fp': fp, 'current': False,
                                               'backup': None, 'opens': False}
    with pytest.raises(ha.HaError, match=f'sealed under an earlier field key .fingerprint {fp}.'):
        ha.open_orphan(name)
    # a file that only has the name of the backup opens nothing
    with open(os.path.join(dbmod.CONFIG_DIR, backup), 'wb') as fh:
        fh.write(bytes(32))
    with pytest.raises(ha.HaError, match='sealed under an earlier field key'):
        ha.open_orphan(name)
    # nor when it was that key a moment ago, as the folder was listed
    with env.mp.context() as mp:
        mp.setattr(ha, '_older_keys', lambda: {fp: backup})
        assert ha._older_key(fp) is None
        with pytest.raises(ha.HaError, match='sealed under an earlier field key'):
            ha.open_orphan(name)
    os.replace(os.path.join(dbmod.CONFIG_DIR, 'moved-away'), os.path.join(dbmod.CONFIG_DIR, backup))
    assert _kept(_copy(name)) == {'carol'}

    # what is kept from now on is under the key in use
    seed.user('dave')
    from_b['key_fp'] = ha.key_fingerprint()
    two = ha.apply_snapshot(from_b)['captured']
    assert two != name and ha.orphan_captures()[0]['key']['current'] is True
    assert ha.orphan_captures()[0]['seal'] == {'under': 'field', 'fp': ha.key_fingerprint(),
                                               'current': True, 'backup': None, 'opens': True}
    assert _kept(_copy(two)) == {'dave'}
    # and a row that goes again is not counted on the copy under the key from before
    seed.user('carol')
    three = ha.apply_snapshot(from_b)['captured']
    assert three not in (name, two) and _meta(name)['repeats'] == 0
    assert _sealed(three).startswith(ha.ORPHAN_MAGIC + ha.key_fingerprint().encode())


def test_a_copy_names_the_key_its_sealed_values_are_under(env, db, seed):
    """(#625 review) A key rotation, or the join into another group, seals the database
    again and leaves the copies as they are. The copy named no key, so nothing said
    which of the dated key backups opens what it kept."""
    import pegaprox.core.db as dbmod
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # the key file is where the database keeps it, as on a real instance
    env.mp.setattr(ha, 'AES_KEY_FILE', os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    db.conn.execute("INSERT INTO node_bmc_endpoints (cluster_id, node, bmc_host, bmc_password_encrypted) "
                    "VALUES ('c1', 'n1', '10.0.0.9', ?)", (db._encrypt('bmc-password-in-clear'),))
    db.conn.commit()
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']
    doc = _copy(name)
    t = doc['tables']['node_bmc_endpoints']
    kept = t['rows'][0][t['columns'].index('bmc_password_encrypted')]
    fp = ha.key_fingerprint()
    assert doc['key_fp'] == fp
    assert ha.orphan_captures()[0]['key'] == {'fp': fp, 'current': True, 'backup': None}

    stats = db.rotate_encryption_key()
    assert stats.get('success') and ha.key_fingerprint() != fp
    with pytest.raises(Exception):
        db._decrypt_with_key(kept, db.aesgcm)
    key = ha.public_status()['orphans']['items'][0]['key']
    assert key == {'fp': fp, 'current': False, 'backup': os.path.basename(stats['key_backup'])}
    # and that file opens what the copy kept
    with open(os.path.join(dbmod.CONFIG_DIR, key['backup']), 'rb') as fh:
        assert db._decrypt_with_key(kept, AESGCM(fh.read())) == 'bmc-password-in-clear'

    # the key a join replaced is kept the same way, under another name
    other = bytes(range(32))
    with open(ha.AES_KEY_FILE + '.pre-ha.20261001-100000', 'wb') as fh:
        fh.write(other)
    assert ha._older_keys()[ha.key_fingerprint(other)] == '.pegaprox_aes256.key.pre-ha.20261001-100000'

    # a copy that names no key says nothing about it
    meta = os.path.join(ha.ORPHANS_DIR, name + '.meta.json')
    with open(meta, encoding='utf-8') as fh:
        told = json.load(fh)
    told.pop('key_fp')
    with open(meta, 'w', encoding='utf-8') as fh:
        json.dump(told, fh)
    assert ha.orphan_captures()[0]['key'] is None


# --- the key a copy is sealed under ------------------------------------------------------------

def _one_copy(env, db, seed, user='carol'):
    """This instance led, made `user` and follows B from here on: (the snapshot of B, the
    name of the copy its first sync kept)."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user(user)
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']
    assert name
    return from_b, name


def _in_step_with_one_copy(env, db, seed):
    """B in step with its leader, with one copy of a row that was made on it and is here
    once more: (the snapshot, the name of the copy)."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    seed.user('made-here')
    one = ha.apply_snapshot(snap)['captured']
    assert _kept(_copy(one)) == {'made-here'}
    seed.user('made-here')
    return snap, one


def _sealed(name):
    with open(os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX), 'rb') as fh:
        return fh.read()


def _put_meta(name, meta):
    with open(os.path.join(ha.ORPHANS_DIR, name + '.meta.json'), 'w', encoding='utf-8') as fh:
        json.dump(meta, fh)


def test_with_sqlcipher_the_key_file_next_to_a_copy_does_not_open_it(env, db, seed, master, caplog):
    """(#625 review) The field key lies in the config directory, where the copies are.
    With SQLCipher the key of the database need not (key store tiers 1 to 5), and whoever
    held that directory alone, a backup of config/ or a disk image, read the account rows
    of a copy and not one row of the database."""
    import pegaprox.core.db as dbmod
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    env.mp.setattr(ha, 'ORPHANS_DIR', os.path.join(dbmod.CONFIG_DIR, 'ha_orphans'))
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    db.save_user('marker-user-7f3a', {'password_salt': 'marker-salt-91c2', 'role': 'admin',
                                       'password_hash': 'marker-hash-5be8', 'tenant_id': 'default',
                                       'enabled': True})
    assert ha.step_down(4, B)
    name = ha.apply_snapshot(from_b)['captured']

    raw, key = _sealed(name), _derived(MASTER)
    cut = len(ha.ORPHAN_MAGIC_MASTER) + 16
    head, nonce, body = raw[:cut], raw[cut:cut + 12], raw[cut + 12:]
    assert head == ha.ORPHAN_MAGIC_MASTER + ha.key_fingerprint(key).encode()
    # the key file as it lies in the config directory opens nothing
    with open(os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'), 'rb') as fh:
        field = fh.read()
    assert field == db.aes_key
    with pytest.raises(InvalidTag):
        AESGCM(field).decrypt(nonce, body, head + name.encode())
    clear = gzip.decompress(AESGCM(key).decrypt(nonce, body, head + name.encode()))
    for marker in (b'marker-user-7f3a', b'marker-salt-91c2', b'marker-hash-5be8'):
        assert marker in clear
    assert clear == gzip.decompress(ha.open_orphan(name))

    # the copy names both keys: the one it is sealed under, and the field key of the
    # sealed values in it
    for told in (json.loads(clear), _meta(name)):
        assert (told['seal'], told['seal_fp']) == ('master', ha.key_fingerprint(key))
        assert told['key_fp'] == ha.key_fingerprint(field) != told['seal_fp']
    item = ha.public_status()['orphans']['items'][0]
    assert item['seal'] == {'under': 'master', 'fp': ha.key_fingerprint(key), 'current': True,
                            'backup': None, 'opens': True}
    assert item['key'] == {'fp': ha.key_fingerprint(field), 'current': True, 'backup': None}
    assert ha.public_status()['orphans']['seal'] == {'under': 'master', 'fp': ha.key_fingerprint(key)}

    # neither the master key nor the key made from it is in a file or in the log
    disk = b''
    for root, _dirs, files in os.walk(dbmod.CONFIG_DIR):
        for fn in files:
            with open(os.path.join(root, fn), 'rb') as fh:
                disk += fh.read()
    assert b'marker-' not in _on_disk()
    for secret in (key, MASTER):
        for form in (secret, secret.hex().encode(), base64.b64encode(secret),
                     base64.urlsafe_b64encode(secret)):
            assert form not in disk and form not in caplog.text.encode()


def test_the_copies_of_this_run_are_under_the_key_of_its_database(env, db, seed, monkeypatch):
    """Nothing stands in for the key here. With SQLCipher it comes from the master key
    the key store holds for this process, and is not read from disk again, in the
    threadpool neither; on plain SQLite it is the field key, and the key store is not
    asked."""
    import pegaprox.core.dbcrypto as dbcrypto
    import pegaprox.core.keystore as keystore
    if dbcrypto.is_encrypted():
        want = ('master', ha.key_fingerprint(_derived(keystore.load_master_key().key_raw)))
        monkeypatch.setattr(keystore, '_resolve', lambda: pytest.fail('the master key was read again'))
    else:
        want = ('field', ha.key_fingerprint())
        monkeypatch.setattr(keystore, 'load_master_key', lambda: pytest.fail('asked the key store'))
    _from_b, name = _one_copy(env, db, seed)
    assert (_meta(name)['seal'], _meta(name)['seal_fp']) == want
    assert _sealed(name).startswith(ha._ORPHAN_MAGICS[want[0]] + want[1].encode())
    assert _kept(_copy(name)) == {'carol'}
    assert ha.orphans_summary()['seal'] == {'under': want[0], 'fp': want[1]}


def test_the_master_key_is_the_one_the_key_store_holds(monkeypatch):
    import pegaprox.core.dbcrypto as dbcrypto
    import pegaprox.core.keystore as keystore
    with monkeypatch.context() as mp:
        mp.setattr(dbcrypto, 'is_encrypted', lambda: False)
        mp.setattr(keystore, 'load_master_key', lambda: pytest.fail('asked the key store'))
        assert ha._master_key() is None
    monkeypatch.setattr(dbcrypto, 'is_encrypted', lambda: True)
    monkeypatch.setattr(keystore, '_CACHED', keystore.MasterKey(
        key_b64=base64.urlsafe_b64encode(MASTER), key_raw=MASTER, source='env:PEGAPROX_DB_KEY'))
    monkeypatch.setattr(keystore, '_resolve', lambda: pytest.fail('the master key was read again'))
    assert ha._master_key() == MASTER
    key, kind = ha._copy_key()
    assert (key, kind) == (_derived(MASTER), 'master') and key != MASTER
    assert ha._copy_key_now() == ('master', ha.key_fingerprint(key))

    # a key store that cannot give one says so, without what it said about the file
    def broken():
        raise RuntimeError('[KEYSTORE] key at /etc/pegaprox/secret.key must decode to 32 bytes')
    monkeypatch.setattr(keystore, '_CACHED', None)
    monkeypatch.setattr(keystore, '_resolve', broken)
    with pytest.raises(ha.HaError, match=r'could not be loaded \(RuntimeError\)') as failed:
        ha._master_key()
    assert 'secret.key' not in str(failed.value)
    assert ha._copy_key_now() == (None, None)


def test_without_a_master_key_nothing_is_kept_and_nothing_is_wiped(env, db, seed, monkeypatch):
    """With SQLCipher there is no falling back to the key file next to the copies."""
    def gone():
        raise ha.HaError('The master key of this instance could not be loaded (RuntimeError)')
    monkeypatch.setattr(ha, '_master_key', gone)
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    with pytest.raises(ha.HaError, match=r'could not keep a copy of them \(HaError\)'):
        ha.apply_snapshot(from_b)
    assert 'carol' in _users(db) and not os.path.exists(ha.ORPHANS_DIR)
    # and the status still answers
    assert ha.public_status()['orphans'] == {'count': 0, 'bytes': 0, 'over_limit': False,
                                             'seal': None, 'items': []}


def test_a_copy_under_another_master_key_says_so_and_stands_for_no_row(env, db, seed, master):
    """The key store changed (another tier with a key of its own), or the copies came
    here with a restore from another host: the copy names a key this instance does not
    run with. It says so, in the status and when it is opened, and a row that goes
    again is kept again instead of counted on a copy nobody can open here."""
    from_b, one = _one_copy(env, db, seed)
    fp = ha.key_fingerprint(_derived(MASTER))
    assert ha.orphan_captures()[0]['seal'] == {'under': 'master', 'fp': fp, 'current': True,
                                               'backup': None, 'opens': True}

    other = bytes(range(32, 64))
    master(other)
    now = ha.key_fingerprint(_derived(other))
    status = ha.public_status()['orphans']
    assert status['seal'] == {'under': 'master', 'fp': now}
    assert status['items'][0]['seal'] == {'under': 'master', 'fp': fp, 'current': False,
                                          'backup': None, 'opens': False}
    # the sealed values in it are under the field key, and that one did not change
    assert status['items'][0]['key'] == {'fp': ha.key_fingerprint(), 'current': True, 'backup': None}
    with pytest.raises(ha.HaError, match=f'sealed under another master key .fingerprint {fp}. than '
                                         'the one this instance runs with'):
        ha.open_orphan(one)

    seed.user('carol')
    two = ha.apply_snapshot(from_b)['captured']
    assert two != one and _kept(_copy(two)) == {'carol'}
    assert (_meta(one)['repeats'], _meta(one)['last_at']) == (0, None)
    assert _meta(two)['seal_fp'] == now and len(_audit('ha.changes_not_carried_over')) == 2
    # the counterproof: under the key in use the row is counted on its copy
    seed.user('carol')
    assert ha.apply_snapshot(from_b)['captured'] == two
    assert (_meta(one)['repeats'], _meta(two)['repeats']) == (0, 1)

    # an instance that runs on plain SQLite has no master key at all
    master(None)
    with pytest.raises(ha.HaError, match=f'sealed under a master key .fingerprint {fp}., and this '
                                         'instance runs without an encrypted database'):
        ha.open_orphan(one)
    assert [i['seal']['opens'] for i in ha.orphan_captures()] == [False, False]
    assert ha.orphans_summary()['seal'] == {'under': 'field', 'fp': ha.key_fingerprint()}
    # and with the key it was sealed under it opens as before
    master(MASTER)
    assert _kept(_copy(one)) == {'carol'}


def test_with_a_master_key_a_copy_opens_whatever_became_of_the_field_key(env, db, seed, master):
    """The two keys of a copy go their own ways. A rotation of the field key, or a join
    that adopts another one, leaves the seal of the copy alone; `key` goes on naming
    the field key of the sealed values in it, and the backup that still holds it."""
    import pegaprox.core.db as dbmod
    env.mp.setattr(ha, 'AES_KEY_FILE', os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    from_b, one = _one_copy(env, db, seed)
    field = ha.key_fingerprint()
    seal = {'under': 'master', 'fp': ha.key_fingerprint(_derived(MASTER)), 'current': True,
            'backup': None, 'opens': True}

    stats = db.rotate_encryption_key()
    assert stats.get('success') and ha.key_fingerprint() != field
    item = ha.orphan_captures()[0]
    assert item['seal'] == seal
    assert item['key'] == {'fp': field, 'current': False, 'backup': os.path.basename(stats['key_backup'])}
    os.remove(stats['key_backup'])
    item = ha.orphan_captures()[0]
    assert item['seal'] == seal and item['key'] == {'fp': field, 'current': False, 'backup': None}
    assert _kept(_copy(one)) == {'carol'}
    # the same row again is in a copy that opens, and is counted there
    from_b['key_fp'] = ha.key_fingerprint()
    seed.user('carol')
    assert ha.apply_snapshot(from_b)['captured'] == one and _meta(one)['repeats'] == 1

    # a copy kept now, and then a join that takes the field key of another group
    seed.user('dave')
    two = ha.apply_snapshot(from_b)['captured']
    rotated = ha.key_fingerprint()
    assert two != one and _meta(two)['key_fp'] == rotated
    ha._install_field_key(bytes(range(32)))
    assert ha.key_fingerprint() != rotated
    items = {i['name']: i for i in ha.orphan_captures()}
    assert items[two]['seal'] == seal and items[one]['seal'] == seal
    assert items[two]['key']['fp'] == rotated and items[two]['key']['current'] is False
    with open(os.path.join(dbmod.CONFIG_DIR, items[two]['key']['backup']), 'rb') as fh:
        assert ha.key_fingerprint(fh.read()) == rotated
    assert _kept(_copy(two)) == {'dave'} and _kept(_copy(one)) == {'carol'}


def test_a_copy_sealed_under_the_field_key_is_listed_and_opens_next_to_a_master_key(
        env, db, seed, monkeypatch):
    """A copy from before the database was encrypted, or from a build of this slice that
    knew the field key only: it begins with the other magic, and its meta file may not
    say what it is sealed under."""
    monkeypatch.setattr(ha, '_master_key', lambda: None)
    from_b, one = _one_copy(env, db, seed)
    fp = ha.key_fingerprint()
    assert _sealed(one).startswith(ha.ORPHAN_MAGIC + fp.encode())
    meta = _meta(one)
    assert (meta.pop('seal'), meta.pop('seal_fp')) == ('field', fp)
    _put_meta(one, meta)

    monkeypatch.setattr(ha, '_master_key', lambda: MASTER)
    assert ha.orphan_captures()[0]['seal'] == {'under': 'field', 'fp': fp, 'current': False,
                                               'backup': None, 'opens': True}
    assert _kept(_copy(one)) == {'carol'}
    # it is not what a copy is sealed under now: the same row is kept again
    seed.user('carol')
    two = ha.apply_snapshot(from_b)['captured']
    assert two != one and _meta(one)['repeats'] == 0 and _meta(two)['seal'] == 'master'
    assert _sealed(two).startswith(ha.ORPHAN_MAGIC_MASTER)

    # whatever a meta file says, the status answers
    for junk in ({'seal': ['x'], 'seal_fp': {'a': 1}, 'key_fp': 7, 'repeats': 'many'},
                 {'seal': 'other', 'seal_fp': 'zz', 'bytes': 'x'}, {'seal': 'master'}, [], 'x'):
        _put_meta(one, junk)
        items = {i['name']: i for i in ha.public_status()['orphans']['items']}
        assert items[one]['seal'] is None and items[one]['key'] is None, junk
        assert items[two]['seal']['opens'] is True
    assert _kept(_copy(one)) == {'carol'}


@pytest.mark.parametrize('damage', ['cut short', 'empty', 'under another key', 'longer', 'no meta file'])
def test_a_copy_that_is_not_whole_stands_for_no_row(env, db, seed, monkeypatch, damage):
    """(#625 review) What is kept already was told by the meta files alone. A copy whose
    sealed file was cut short (a disk that filled up, a bad block) holds nothing an
    admin can get back, and the rows it names went again and were counted on it."""
    class Held(ha.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, 10, 0, 0, tzinfo=tz)
    # every copy of this test is kept within the same second
    monkeypatch.setattr(ha, 'datetime', Held)
    snap, one = _in_step_with_one_copy(env, db, seed)
    path, raw = os.path.join(ha.ORPHANS_DIR, one + ha.ORPHAN_SUFFIX), _sealed(one)
    left = {'cut short': raw[:40], 'empty': b'', 'longer': raw + b'\0',
            # as long as it was, and the head names a key that is not the one in use
            'under another key': raw[:8] + b'0123456789abcdef' + raw[24:]}.get(damage, raw)
    with open(path, 'wb') as fh:
        fh.write(left)
    if damage == 'no meta file':
        os.remove(os.path.join(ha.ORPHANS_DIR, one + '.meta.json'))
    else:
        with pytest.raises(ha.HaError):
            ha.open_orphan(one)

    two = ha.apply_snapshot(snap)['captured']
    assert 'made-here' not in _users(db) and _kept(_copy(two)) == {'made-here'}
    # under a name of its own, although the rows, the cv and the second are the same:
    # the other one stays as it is, for the admin to dismiss
    assert one.split('-')[:2] == two.split('-')[:2] and one.split('-')[3] == two.split('-')[3]
    assert two != one and _copies() == sorted([one, two]) and _sealed(one) == left
    assert len(_audit('ha.changes_not_carried_over')) == 2
    if damage != 'no meta file':
        assert _meta(one)['repeats'] == 0
    # the counterproof: a whole copy is counted on
    seed.user('made-here')
    assert ha.apply_snapshot(snap)['captured'] == two and _meta(two)['repeats'] == 1
    assert len(_copies()) == 2


# --- a copy goes before a sync or after it ---------------------------------------------------------

def test_a_copy_dismissed_while_the_apply_looks_stands_for_no_row(env, db, seed, monkeypatch):
    """(#625 review) The look runs in the threadpool and the hub serves on. It found the
    rows kept already in a copy, the admin dismissed that very copy before the apply
    held the write lock, and the wipe took rows that no copy held."""
    snap, one = _in_step_with_one_copy(env, db, seed)
    real, done = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        if not done and isinstance(out, tuple) and len(out) == 3 and out[0] == one:
            # an apply that runs without the pull lock, as every apply of these tests
            done.append(ha.dismiss_orphan(one, 'root'))
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)
    summary = ha.apply_snapshot(snap)
    monkeypatch.setattr(ha, '_in_pool', real)

    assert done == [True] and 'made-here' not in _users(db)
    # what the apply names is a copy that is there, and the row is in it
    assert _copies() == [summary['captured']]
    assert _kept(_copy(summary['captured'])) == {'made-here'}
    assert _meta(summary['captured'])['repeats'] == 0
    assert len(_audit('ha.changes_not_carried_over')) == 2 and len(_audit('ha.changes_dismissed')) == 1


def test_a_dismiss_does_not_land_inside_a_sync(env, db, seed, monkeypatch):
    """A sync holds the pull lock from its call to the leader to the end of the apply.
    The dismiss waits for it, and says so when the sync takes longer than that."""
    snap, one = _in_step_with_one_copy(env, db, seed)
    monkeypatch.setattr(ha, 'DISMISS_WAIT', 0.05)
    monkeypatch.setattr(ha, '_peer_call',
                        lambda *a, **kw: types.SimpleNamespace(status_code=200, json=lambda: snap))
    real, tried = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        if not tried and isinstance(out, tuple) and len(out) == 3 and out[0] == one:
            # the look found the rows in the copy; the hub serves the admin's dismiss
            with pytest.raises(ha.SyncRunning, match='A sync is running right now'):
                ha.dismiss_orphan(one, 'root')
            tried.append(1)
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)

    assert ha.pull_once() == 'applied'
    assert tried and 'made-here' not in _users(db)
    assert _copies() == [one] and _meta(one)['repeats'] == 1
    assert _kept(_copy(one)) == {'made-here'} and _audit('ha.changes_dismissed') == []
    # the sync is over: the copy goes
    assert ha.dismiss_orphan(one, 'root') is True and _copies() == []
    assert not ha._pull_lock.locked()


def test_a_dismiss_waits_for_the_sync_that_is_under_way(env, db, seed):
    _from_b, one = _one_copy(env, db, seed)
    done = []
    assert ha._pull_lock.acquire(timeout=1)
    try:
        g = gevent.spawn(lambda: done.append(ha.dismiss_orphan(one, 'root')))
        gevent.sleep(0.05)
        assert done == [] and _copies() == [one]
        # a name that is no copy waits for nothing
        assert ha.dismiss_orphan('1-1-20261001T100000Z-abcdefabcdef', 'root') is False
    finally:
        ha._pull_lock.release()
    g.join(5)
    assert done == [True] and _copies() == [] and not ha._pull_lock.locked()
    assert len(_audit('ha.changes_dismissed')) == 1


def test_two_key_rotations_within_one_second_keep_both_keys(env, db, seed, plain_sqlite, monkeypatch):
    """(#625 review) A rotation names the backup of the key by the second and opened it
    with 'wb': the second rotation within that second wrote over the backup of the
    first, and a copy under the key from before opened with nothing."""
    import pegaprox.core.db as dbmod
    env.mp.setattr(ha, 'AES_KEY_FILE', os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    _from_b, one = _one_copy(env, db, seed)
    first = db.aes_key

    class Frozen(dbmod.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, 10, 0, 0, tzinfo=tz)
    keys, stats = [first], []
    with monkeypatch.context() as mp:
        mp.setattr(dbmod, 'datetime', Frozen)
        for _ in range(3):
            stats.append(db.rotate_encryption_key())
            assert stats[-1].get('success'), stats[-1]
            keys.append(db.aes_key)

    base = '.pegaprox_aes256.key.backup.20261002_100000'
    assert [os.path.basename(s['key_backup']) for s in stats] == [base, base + '.1', base + '.2']
    for s, key in zip(stats, keys):
        with open(s['key_backup'], 'rb') as fh:
            assert fh.read() == key
        assert stat.S_IMODE(os.stat(s['key_backup']).st_mode) == 0o600
    assert ha._older_keys() == {ha.key_fingerprint(k): os.path.basename(s['key_backup'])
                                for s, k in zip(stats, keys)}
    assert ha.orphan_captures()[0]['seal'] == {'under': 'field', 'fp': ha.key_fingerprint(first),
                                               'current': False, 'backup': base, 'opens': True}
    assert _kept(_copy(one)) == {'carol'}


def test_an_apply_that_fails_after_the_copy_does_not_pile_up_copies(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    from_b['tables']['power_rates']['sql'] = 'DROP TABLE users'
    db.conn.execute('DROP TABLE power_rates')
    db.conn.commit()
    seed.user('carol')
    assert ha.step_down(4, B)

    for _ in range(3):
        with pytest.raises(ha.HaError, match='Refusing the table definition'):
            ha.apply_snapshot(from_b)
    # kept once and said once, although nothing was applied
    assert len(_copies()) == 1 and len(_audit('ha.changes_not_carried_over')) == 1
    assert 'carol' in _users(db)
    # and nothing went again: the row is still here
    assert _meta(_copies()[0])['repeats'] == 0
    # the counterproof: other rows here, another copy
    seed.user('dave')
    with pytest.raises(ha.HaError):
        ha.apply_snapshot(from_b)
    assert len(_copies()) == 2


def test_copies_go_only_when_an_admin_dismisses_them(env, db, seed, monkeypatch):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    monkeypatch.setattr(ha, 'ORPHANS_ALERT_BYTES', 1)
    first = ha.apply_snapshot(from_b)['captured']
    # past the limit: said once, nothing deleted
    assert len(_audit('ha.orphans_space')) == 1
    assert ha.public_status()['orphans']['over_limit'] is True

    seed.user('dave')
    second = ha.apply_snapshot(from_b)['captured']
    assert second != first and len(_copies()) == 2 and ha.banner()['orphans'] == 2
    assert len(_audit('ha.orphans_space')) == 1
    # syncs that need no copy leave them be
    for _ in range(2):
        assert ha.apply_snapshot(from_b)['captured'] is None
    assert len(_copies()) == 2

    # a name is a name of a copy, and never a way out of the folder
    outside = os.path.join(os.path.dirname(ha.ORPHANS_DIR), 'outside' + ha.ORPHAN_SUFFIX)
    with open(outside, 'wb') as fh:
        fh.write(b'not a copy')
    for bad in ('../outside', '../ha_state', first + ha.ORPHAN_SUFFIX, first + '/../' + first, '', None,
                'x' * 40):
        assert ha.dismiss_orphan(bad, 'root') is False and ha.orphan_path(bad) is None
        assert ha.open_orphan(bad) is None
    assert len(_copies()) == 2 and os.path.exists(outside)
    assert ha.dismiss_orphan(first, 'root') is True
    assert _copies() == [second] and ha.banner()['orphans'] == 1
    assert not os.path.exists(os.path.join(ha.ORPHANS_DIR, first + '.meta.json'))
    assert 'root dismissed' in _audit('ha.changes_dismissed')[0]['details']
    assert ha.dismiss_orphan(first, 'root') is False


# --- what is kept already is not kept again ---------------------------------------------------

def _oidc_sign_in(name='jane', role='viewer'):
    """Steps 5 and 6 of api/auth.py oidc_callback where the row is the instance's own to
    write, and as they ran on a standby too until it took a sign-in in on the synced row
    (tests/test_ha_standby_oidc.py): the sign-in provisions the users row, and the
    callback saves it once more."""
    from datetime import datetime
    from pegaprox.utils.oidc import oidc_provision_user
    from pegaprox.utils.auth import save_single_user
    user = oidc_provision_user({'preferred_username': name, 'email': f'{name}@corp.example',
                                'name': name.title(), 'sub': f'idp-subject-{name}'},
                               {'role': role, '_authoritative': True})
    assert user, 'the sign-in was refused'
    user['last_login'] = datetime.now().isoformat()
    save_single_user(user['username'], user)
    return user['username']


def _one_tag_more(note):
    """An unrelated change on the leader between two syncs."""
    def change(tables):
        t = tables['vm_tags']
        row = {'id': 1000 + len(t['rows']), 'cluster_id': 'c1', 'vmid': 100, 'tag_name': note}
        t['rows'].append([row.get(c) for c in t['columns']])
    return change


def test_an_account_made_again_after_every_sync_is_one_copy(env, db, seed):
    """(#625 review) An OIDC sign-in on a standby provisioned the users row there, until
    the callback stopped writing one on a standby. The next sync replaces such a row and
    keeps a copy, the row is made again with another created_at, and so on: one copy,
    one ERROR and one audit row per round, and only an admin removes a copy. Fifty
    rounds are one copy now."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)

    names = set()
    for round_no in range(50):
        jane = _oidc_sign_in()
        assert jane in _users(db)
        snap = _next_from_leader(snap, _one_tag_more(f'tag-{round_no}'))
        summary = ha.apply_snapshot(snap)
        assert jane not in _users(db)                   # replaced, as it always was
        names.add(summary['captured'])
    assert len(names) == 1 and _copies() == sorted(names)
    name = names.pop()
    assert _kept(_copy(name)) == {'jane'}
    assert len(_audit('ha.changes_not_carried_over')) == 1 and ha.banner()['orphans'] == 1
    # the one copy says how often it went again, and when last
    meta = _meta(name)
    assert meta['repeats'] == 49 and meta['last_at'] > meta['captured_at']
    item = ha.orphan_captures()[0]
    assert (item['repeats'], item['last_at']) == (49, meta['last_at'])

    # once the admin has dismissed it, the next one is kept again
    assert ha.dismiss_orphan(name, 'root') is True
    _oidc_sign_in()
    again = ha.apply_snapshot(_next_from_leader(snap, _one_tag_more('after')))['captured']
    assert again and again != name and _meta(again)['repeats'] == 0
    assert len(_audit('ha.changes_not_carried_over')) == 2


def test_accounts_made_again_in_changing_company_are_kept_once_each(env, db, seed):
    """Who signs in between two syncs changes from one to the next. A copy per set of
    rows would be one per combination, and there is no end to those; a row that some
    copy holds is not kept again, whoever it comes with."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)

    forms = set()

    def a_round(i, who):
        for name in who:
            _oidc_sign_in(name)
        forms.update((r['username'], r['tenant']) for r in db.conn.execute(
            "SELECT username, tenant FROM users WHERE username != 'alice'"))
        nonlocal snap
        snap = _next_from_leader(snap, _one_tag_more(f'tag-{i}'))
        assert ha.apply_snapshot(snap)['captured']
        assert _users(db) == {'alice'}

    def kept_forms():
        out = set()
        for name in _copies():
            t = _copy(name)['tables']['users']
            out.update((row[t['columns'].index('username')], row[t['columns'].index('tenant')])
                       for row in t['rows'])
        return out

    # each alone first, then every combination, three times over
    for i, who in enumerate([('jane',), ('bob',), ('carol',)]):
        a_round(i, who)
    assert len(_copies()) == 3
    combos = [('jane', 'bob'), ('carol', 'jane'), ('bob', 'carol'), ('jane', 'bob', 'carol'),
              ('bob', 'jane'), ('carol',), ('jane',)]
    for i, who in enumerate(combos):
        a_round(10 + i, who)
    # A sign-in saves the rows of the others once more, which settles a column of a row
    # made just before: an account has two forms, and each is kept once
    settled = len(_copies())
    assert 3 < settled <= 6 and kept_forms() == forms
    for i, who in enumerate(combos * 2):
        a_round(100 + i, who)
    assert len(_copies()) == settled == len(_audit('ha.changes_not_carried_over'))
    assert ha.banner()['orphans'] == settled and kept_forms() == forms
    assert sum(_meta(n)['repeats'] for n in _copies()) == 3 + 3 * len(combos) - settled
    assert set().union(*(_kept(_copy(n)) for n in _copies())) == {'jane', 'bob', 'carol'}

    # the counterproof: the same account with another role is another row
    _oidc_sign_in('jane', role='admin')
    name = ha.apply_snapshot(_next_from_leader(snap, _one_tag_more('last')))['captured']
    assert len(_copies()) == settled + 1 and _kept(_copy(name), 'users', 'role') == {'admin'}
    # and one row that no copy holds, next to one that is kept: all of it is kept
    for who in ('bob', 'dave'):
        _oidc_sign_in(who)
    name = ha.apply_snapshot(_next_from_leader(snap, _one_tag_more('very last')))['captured']
    assert len(_copies()) == settled + 2 and _kept(_copy(name)) == {'bob', 'dave'}


def test_what_two_looks_of_one_sync_find_kept_already_is_one_repeat(env, db, seed):
    """An apply looks twice when somebody wrote while it looked. Both looks can end at
    the same copy, and that is one sync that took its rows away again."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    seed.user('made-on-b')
    name = ha.apply_snapshot(snap)['captured']
    found = {'name': name, 'new': False, 'why': 'kept before', 'differences': {}}

    assert ha._say_kept([dict(found), None, dict(found)], snap, 3, wiped=True) == name
    assert _meta(name)['repeats'] == 1
    # an apply that failed took nothing away
    assert ha._say_kept([dict(found)], snap, 3) == name
    assert _meta(name)['repeats'] == 1 and len(_audit('ha.changes_not_carried_over')) == 1
    # a copy whose meta file is gone is no reason to fail
    os.remove(os.path.join(ha.ORPHANS_DIR, name + '.meta.json'))
    assert ha._say_kept([dict(found)], snap, 3, wiped=True) == name


def test_what_makes_two_rows_the_same_row_for_a_copy():
    key = bytes(range(32))

    def of(rows=(), columns=('username', 'role', 'created_at', 'last_login'), files=None, journal=()):
        kept = {'users': {'columns': list(columns), 'rows': [list(r) for r in rows]}} if rows else {}
        return ha._capture_items(kept, files or {}, list(journal), key)
    one = of([('jane', 'viewer', '2026-10-01T10:00:00', None)])
    # when it was made and when it was last used make no other row, nor does the order
    # of the columns
    assert of([('jane', 'viewer', '2026-10-02T11:11:11', '2026-10-02T11:11:12')]) == one
    assert of([('2026-10-02', 'viewer', 'jane', None)],
              columns=('created_at', 'role', 'username', 'last_login')) == one
    # anything else does, and so does another key
    assert of([('jane', 'admin', '2026-10-01T10:00:00', None)]) != one
    assert of([('jane ', 'viewer', '2026-10-01T10:00:00', None)]) != one
    assert ha._capture_items({'users': {'columns': ['username', 'role'], 'rows': [['jane', 'viewer']]}},
                             {}, [], bytes(32)) != one
    # the same values in another table are other rows
    assert ha._capture_items({'tenants': {'columns': ['username', 'role'], 'rows': [['jane', 'viewer']]}},
                             {}, [], key)[0] != one[0]
    # a file and a journal line are items of their own
    line = {'id': 7, 'at': '2026-10-01T10:00:00', 'user': 'root', 'method': 'POST',
            'path': '/api/users', 'via': '', 'cv': None}
    items, tag = of([('jane', 'viewer', 'x', None)], files={'ssh_known_hosts': 'h1 ssh-ed25519 AAAA\n'},
                    journal=[line])
    assert len(items) == 3 and one[0][0] in items and tag != one[1]
    assert of(journal=[dict(line, id=99)]) == of(journal=[line])
    assert of(journal=[dict(line, at='2026-10-01T10:00:01')]) != of(journal=[line])
    assert of(files={'branding': {'logo.png': 'QUJD'}}) != of(files={'branding': {'logo.png': 'QUJE'}})
    assert all(len(i) == 16 for i in items) and len(tag) == 12


def test_a_copy_with_more_rows_than_it_can_name_is_told_by_its_tag(env, db, seed, monkeypatch):
    """Past ORPHAN_ITEMS_MAX the meta file names no single row. The very same rows are
    still one copy; a part of them is kept again."""
    monkeypatch.setattr(ha, 'ORPHAN_ITEMS_MAX', 2)
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)

    def tags(*ids):
        db.conn.executemany("INSERT INTO vm_tags (id, cluster_id, vmid, tag_name) VALUES (?, 'c1', 100, ?)",
                            [(i, f'tag-{i}') for i in ids])
        db.conn.commit()
    tags(1, 2, 3)
    big = ha.apply_snapshot(snap)['captured']
    assert _meta(big)['items'] is None
    tags(1, 2, 3)
    assert ha.apply_snapshot(snap)['captured'] == big and _meta(big)['repeats'] == 1
    tags(1, 2)
    part = ha.apply_snapshot(snap)['captured']
    assert part != big and len(_meta(part)['items']) == 2
    # and what the smaller one names is found there
    tags(2)
    assert ha.apply_snapshot(snap)['captured'] == part and len(_copies()) == 2


def test_the_space_the_copies_take_is_said_again_after_it_was_fine(env, db, seed, monkeypatch):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    monkeypatch.setattr(ha, 'ORPHANS_ALERT_BYTES', 1)
    first = ha.apply_snapshot(from_b)['captured']
    assert ha.dismiss_orphan(first, 'root')
    seed.user('dave')
    assert ha.apply_snapshot(from_b)['captured']
    assert len(_audit('ha.orphans_space')) == 2
    # the other limit: a share of what is free on that disk
    monkeypatch.setattr(ha, 'ORPHANS_ALERT_BYTES', 10 ** 12)
    assert ha.orphans_summary()['over_limit'] is False
    monkeypatch.setattr(ha, 'ORPHANS_ALERT_SHARE', 1e-15)
    assert ha.orphans_summary()['over_limit'] is True


def test_half_a_copy_is_no_copy(env, db, seed, monkeypatch):
    """The rows went to disk and the note next to them did not: nothing stays behind, and
    the snapshot is refused like one whose copy could not be written at all."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    real = ha._write_private

    def full(path, data, mode=0o600):
        if path.endswith('.meta.json'):
            raise OSError(28, 'No space left on device')
        return real(path, data, mode=mode)
    monkeypatch.setattr(ha, '_write_private', full)
    with pytest.raises(ha.HaError, match='could not keep a copy'):
        ha.apply_snapshot(from_b)
    assert os.listdir(ha.ORPHANS_DIR) == [] and 'carol' in _users(db)
    assert 'orphans' not in ha.banner()


def test_an_instance_that_led_from_its_own_data_keeps_it_when_it_steps_down(env, db, seed):
    """It joined, was promoted before its first sync and led with what it had. Stepping
    down to another active, it is no instance that just joined any more."""
    _member(env, B)
    seed.user('made-on-b')
    ha.promote()
    assert ha._load().get('cv') is None
    snap_a = _wire(ha.build_snapshot(meta=dict(ha.snapshot_meta(), instance_id=A, epoch=5)))
    snap_a.pop('members', None)
    snap_a.pop('tombstones', None)
    seed.user('more-on-b')
    assert ha.step_down(5, A)
    doc = _copy(ha.apply_snapshot(snap_a)['captured'])
    assert _kept(doc) == {'more-on-b'}


def test_leaving_the_group_leaves_the_history_behind(env, db, seed):
    _leader(env)
    seed.user('alice')
    ha.build_snapshot()
    assert ha.config_version() == (3, 1)
    ha.unpair()
    st = ha._load()
    assert st.get('cv') is None and st.get('change_gap') is None
    assert ha.config_version() == ha.CV_ZERO


def _trigger_count(db):
    return db.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' "
                           "AND name LIKE 'ha_cv_%'").fetchone()[0]


def test_a_member_keeps_the_triggers_and_a_sync_does_not_count_its_rows(env, db, seed):
    """They would fire for every row a sync deletes and inserts, so the apply drops them
    first. It makes them again at its end: between two syncs they count what is written
    here."""
    _leader(env)
    seed.user('alice')
    assert ha.ensure_change_triggers() > 0
    whole = _trigger_count(db)
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    assert ha.step_down(4, B)
    n = ha._dirty_count()
    ha._tick.update(seen=(n, ()), checked=123.0, schema=7)

    def made(table):
        return db.conn.execute('SELECT rowid FROM sqlite_master WHERE name = ?',
                               (f'ha_cv_{table}_i',)).fetchone()[0]
    before = made('users'), made('xcpng_pools')
    ha.apply_snapshot(from_b)
    assert _trigger_count(db) == whole
    # dropped and made again where rows moved, left alone where there are none
    assert made('users') != before[0] and made('xcpng_pools') == before[1]
    # none of the rows of the sync was counted
    assert ha._dirty_count() == n
    # a tick after the next promotion looks them over at once
    assert ha._tick == {'seen': None, 'checked': None, 'schema': None}
    # what the record notes is what the count, the schema and the files are now
    mark = ha._cv_record(ha._load())['mark']
    assert mark == ha._change_mark() and mark[0] == n
    # the trigger of somebody else stays
    db.conn.execute('CREATE TRIGGER keep_me AFTER INSERT ON vm_tags BEGIN SELECT 1; END')
    db.conn.commit()
    ha.apply_snapshot(from_b)
    assert db.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'keep_me'").fetchone()[0] == 1
    assert _trigger_count(db) == whole and ha._dirty_count() == n

    # a write here moves the count, a sign-in (VOLATILE_COLUMNS) does not
    mark = ha._change_mark()
    db.conn.execute("UPDATE users SET last_login = 'now'")
    db.conn.commit()
    assert ha._change_mark() == mark
    db.conn.execute("UPDATE users SET role = 'admin'")
    db.conn.commit()
    assert ha._change_mark()[0] == n + 1


def test_no_row_of_a_sync_is_counted_whichever_side_holds_them(env, db, seed):
    """Only the triggers of a table whose rows move are dropped for a sync: one that gets
    rows from the snapshot, one that loses the rows it holds."""
    _leader(env)
    seed.user('alice')
    one = _wire(ha.build_snapshot())
    two = _next_from_leader(one, _one_tag_more('prod'))
    _member(env, B)
    ha.apply_snapshot(one)
    n = ha._dirty_count()
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 0
    # rows for a table that holds none
    assert ha.apply_snapshot(two)['captured'] is None and ha._dirty_count() == n
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 1
    # and a table that holds rows and gets none
    three = _next_from_leader(two, lambda tables: tables['vm_tags']['rows'].clear())
    assert ha.apply_snapshot(three)['captured'] is None and ha._dirty_count() == n
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 0
    assert ha._cv_record(ha._load())['mark'] == ha._change_mark()


def test_a_member_that_never_had_the_triggers_gets_them_with_its_first_sync(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    assert _trigger_count(db) == 0 and ha._change_mark() is None
    ha.apply_snapshot(snap)
    shared = [t for t in ha.SYNC_TABLES if t in ha._existing_tables(db.conn.cursor())]
    assert _trigger_count(db) == 3 * len(shared)
    assert ha._cv_record(ha._load())['mark'] == ha._change_mark()


@pytest.fixture
def looks(monkeypatch):
    """What an apply reads and where: 'pool' for every call into the threadpool, 'walk'
    for a walk of the tables on the hub inside the apply's transaction, 'inline' for a
    second look under the write lock, 'files' once the commit is through."""
    seen = []
    real_pool, real_walk = ha._in_pool, ha._walk_tables
    real_keep, real_files = ha._keep_not_carried, ha._apply_files

    def pool(fn):
        seen.append('pool')
        return real_pool(fn)

    def walk(body):
        from pegaprox.core.db import get_db
        if get_db().conn.in_transaction:
            seen.append('walk')
        return real_walk(body)

    def keep(*a, **kw):
        if kw.get('inline'):
            seen.append('inline')
        return real_keep(*a, **kw)

    def files(sent):
        seen.append('files')
        return real_files(sent)
    monkeypatch.setattr(ha, '_in_pool', pool)
    monkeypatch.setattr(ha, '_walk_tables', walk)
    monkeypatch.setattr(ha, '_keep_not_carried', keep)
    monkeypatch.setattr(ha, '_apply_files', files)
    return seen


def test_a_member_in_step_reads_nothing_before_the_wipe(env, db, seed, looks):
    """(#625 review) Every sync walked the shared tables in the threadpool before the
    wipe and once more on the hub inside the transaction: 0.4 s more hub stall per sync
    at 10k VMs. While the count of the triggers, the schema and the files are what the
    last sync left, nothing was changed here and nothing is read; what the sync leaves
    is hashed after the commit, off the hub."""
    _leader(env)
    seed.user('alice')
    snaps = [_wire(ha.build_snapshot())]
    seed.user('bob')
    snaps.append(_wire(ha.build_snapshot()))
    _drop_users(db, 'bob')
    _member(env, B)
    ha.apply_snapshot(snaps[0])
    del looks[:]

    assert ha.apply_snapshot(snaps[1])['captured'] is None
    assert looks == ['files', 'pool']
    assert _users(db) == {'alice', 'bob'}
    rec = ha._cv_record(ha._load())
    assert rec['etag_at_cv'] == ha._walk_snapshot(body=False)[0]
    assert rec['data_at_cv'] == ha._walk_snapshot(body=False)[4] and rec['mark'] == ha._change_mark()

    # a sign-in in between is no change either
    db.conn.execute("UPDATE users SET last_login = 'now'")
    db.conn.commit()
    del looks[:]
    assert ha.apply_snapshot(snaps[1])['captured'] is None and looks == ['files', 'pool']

    # the counterproof: one row changed here, and the look is back
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'bob'")
    db.conn.commit()
    del looks[:]
    assert _kept(_copy(ha.apply_snapshot(snaps[1])['captured']), 'users', 'role') == {'admin'}
    assert looks == ['pool', 'pool', 'files', 'pool']


def test_the_first_sync_of_a_process_reads_the_rows_whatever_the_mark_says(env, db, seed, looks, monkeypatch):
    """A database restored while the instance was down may hold other rows under the same
    count. Once per start the rows are walked (in the threadpool) and held against the
    digest of the last sync, as the stored etag is dropped once per start."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    ha.apply_snapshot(snap)
    # a row that no trigger saw
    ha._drop_change_triggers(db.conn.cursor(), {})
    mark = ha._cv_record(ha._load())['mark']
    db.conn.execute("PRAGMA schema_version = %d" % mark[1])
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'alice'")
    db.conn.commit()
    assert ha._change_mark() == mark

    monkeypatch.setattr(ha, '_mark_checked', False)
    del looks[:]
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'users', 'role') == {'admin'} and looks[0] == 'pool'
    assert ha._mark_checked is True


def test_an_update_of_a_column_no_trigger_can_name_is_counted(env, db, seed):
    """The UPDATE trigger names the columns it watches. A column whose name is no plain
    identifier was left out of its WHEN and went unseen, and the count is what says a
    member is in step."""
    _leader(env)
    seed.user('alice')
    db.conn.execute('ALTER TABLE vm_tags ADD COLUMN "odd ""name" TEXT')
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    assert ha.ensure_change_triggers() > 0
    n = ha._dirty_count()
    db.conn.execute('UPDATE vm_tags SET "odd ""name" = \'x\'')
    db.conn.commit()
    assert ha._dirty_count() == n + 1
    # the counterproof: where every column has a plain name, only a change counts
    db.conn.execute("UPDATE users SET role = role, last_login = 'now'")
    db.conn.commit()
    assert ha._dirty_count() == n + 1


def test_a_file_changed_here_is_seen_without_a_row_written(env, db, seed, looks):
    """No trigger sees a file. The mark takes in the size and the time of every file a
    snapshot carries."""
    _leader(env)
    seed.user('alice')
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    del looks[:]
    assert ha.apply_snapshot(snap)['captured'] is None and looks == ['files', 'pool']

    n = ha._dirty_count()
    with open(ha.KNOWN_HOSTS_FILE, 'a') as fh:
        fh.write('10.0.0.99 ssh-ed25519 pinned-here\n')
    assert ha._dirty_count() == n and ha._change_mark() != ha._cv_record(ha._load())['mark']
    del looks[:]
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert 'pinned-here' in doc['files']['ssh_known_hosts'] and looks[0] == 'pool'


@pytest.mark.parametrize('meanwhile', ['promoted', 'another record'])
def test_the_hashes_go_onto_the_record_of_their_own_sync_only(env, db, seed, monkeypatch, meanwhile):
    """The walk after the commit gives the hub away. What it hashed belongs to the record
    that sync wrote, on a standby: not to an instance that took the lead meanwhile, not
    to a record somebody else wrote."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    real, done = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        if not done:
            if meanwhile == 'promoted':
                done.append(ha.promote())
            else:
                with ha._lock:
                    st = ha._load()
                    ha._commit_locked(dict(st, cv=dict(st['cv'], at='written meanwhile')))
                done.append(1)
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)
    # in step: the only call into the threadpool is the walk after the commit
    assert ha.apply_snapshot(snap)['captured'] is None

    rec = ha._cv_record(ha._load())
    assert done and rec['etag_at_cv'] is None and rec['data_at_cv'] is None
    if meanwhile == 'promoted':
        assert ha.role() == ha.ROLE_ACTIVE
    else:
        assert rec['at'] == 'written meanwhile'


def test_rows_written_again_as_they_were_cost_a_look_and_no_copy(env, db, seed, looks):
    """The count moves with an INSERT OR REPLACE of the very same row (a sign-in saves
    the users back). Then the digest of the rows says nothing changed."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    mark = ha._change_mark()
    row = tuple(db.conn.execute("SELECT * FROM users WHERE username = 'alice'").fetchone())
    db.conn.execute(f"INSERT OR REPLACE INTO users VALUES ({','.join('?' * len(row))})", row)
    db.conn.commit()
    assert ha._change_mark() != mark
    del looks[:]
    assert ha.apply_snapshot(snap)['captured'] is None
    assert looks == ['pool', 'files', 'pool'] and _copies() == []


def test_a_write_to_a_table_of_its_own_while_the_apply_looks_is_no_second_look(env, db, seed, looks,
                                                                              monkeypatch):
    """(#625 review) SQLite's data_version moves with every commit of another connection:
    a log line, a metric, a session. On a member that writes anything while the apply
    looks, the whole look was repeated on the hub, inside the transaction, the copy
    included."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    seed.user('made-on-b')
    monkeypatch.setattr(ha, '_data_version', lambda conn: pytest.fail('the count was not used'))
    real, noise = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        noise.append(1)
        _on_another_connection("INSERT INTO task_users (upid, username, created_at) "
                               f"VALUES ('UPID:{len(noise)}', 'alice', '2026-10-01')")
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)
    del looks[:]

    name = ha.apply_snapshot(snap)['captured']
    assert noise and _kept(_copy(name)) == {'made-on-b'}
    assert 'inline' not in looks and 'walk' not in looks
    assert len(_audit('ha.changes_not_carried_over')) == 1


def test_a_write_to_a_shared_table_while_the_apply_looks_is_counted(env, db, seed, looks, monkeypatch):
    """The other side: the count of the triggers catches what data_version caught, a row
    of a shared table written between the look and the wipe."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    monkeypatch.setattr(ha, '_data_version', lambda conn: pytest.fail('the count was not used'))
    real_keep, late = ha._keep_not_carried, []

    def keep(*a, **kw):
        out = real_keep(*a, **kw)
        if not late:
            # the member was in step, so the look read nothing; the write lands right
            # after it, before the apply holds the write lock
            late.append(1)
            _on_another_connection(
                "INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'late')")
        return out
    monkeypatch.setattr(ha, '_keep_not_carried', keep)
    del looks[:]

    summary = ha.apply_snapshot(snap)
    assert late and looks[0] == 'inline'
    assert _kept(_copy(summary['captured']), 'vm_tags', 'tag_name') == {'late'}
    assert db.conn.execute('SELECT COUNT(*) FROM vm_tags').fetchone()[0] == 0


def test_a_table_made_since_the_last_sync_has_no_trigger_and_is_looked_at(env, db, seed, looks):
    """A shared table the code makes on first use (pegaprox_kv) has no trigger until the
    next sync, and a row in it is not counted. SQLite's schema version says so: the
    count is not taken for an answer, the rows are walked."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    n = ha._dirty_count()
    db.conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    db.conn.execute("INSERT INTO pegaprox_kv (k, v) VALUES ('made-here', '1')")
    db.conn.commit()
    assert ha._dirty_count() == n
    del looks[:]

    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'pegaprox_kv', 'k') == {'made-here'} and looks[0] == 'pool'
    # from this sync on the table has its triggers
    assert db.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'ha_cv_pegaprox_kv_%'"
                           ).fetchone()[0] == 3


def test_a_column_made_since_the_last_sync_is_not_watched_and_is_looked_at(env, db, seed, looks):
    """The same for a column: the UPDATE trigger of the table names the columns it had
    when it was made. What is written into a new one is not counted, and is still a
    change made here that the snapshot cannot carry."""
    _leader(env)
    seed.user('alice')
    snap = _next_from_leader(_wire(ha.build_snapshot()), _one_tag_more('prod'))
    _member(env, B)
    ha.apply_snapshot(snap)
    n = ha._dirty_count()
    db.conn.execute('ALTER TABLE vm_tags ADD COLUMN noted_here TEXT')
    db.conn.execute("UPDATE vm_tags SET noted_here = 'by this instance'")
    db.conn.commit()
    assert ha._dirty_count() == n
    del looks[:]

    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'vm_tags', 'noted_here') == {'by this instance'} and looks[0] == 'pool'
    # the column stays and is watched from this sync on
    db.conn.execute("UPDATE vm_tags SET noted_here = 'again'")
    db.conn.commit()
    assert ha._dirty_count() == n + 1


def test_after_a_schema_step_the_second_look_goes_by_every_commit_again(env, db, seed, looks, monkeypatch):
    """The schema moved since the last sync, so some shared table may have no trigger.
    A write to it while the apply looks does not move the count: until the triggers are
    whole again, any commit of another connection is reason for the second look."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    db.conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    db.conn.commit()
    n = ha._dirty_count()
    real, late = ha._in_pool, []

    def pool(fn):
        out = real(fn)
        if not late:
            late.append(1)
            _on_another_connection("INSERT INTO pegaprox_kv (k, v) VALUES ('late', '1')")
        return out
    monkeypatch.setattr(ha, '_in_pool', pool)
    del looks[:]

    summary = ha.apply_snapshot(snap)
    assert late and ha._dirty_count() == n and 'inline' in looks
    assert _kept(_copy(summary['captured']), 'pegaprox_kv', 'k') == {'late'}


def test_a_write_while_the_sync_is_hashed_leaves_the_record_without_the_hashes(env, db, seed, monkeypatch):
    """What a sync left is hashed after the commit, in the threadpool. A row written
    meanwhile may or may not be in that walk: the hashes are dropped, and the next sync
    compares row by row."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    real = ha._walk_snapshot

    def walk(body):
        out = real(body)
        from pegaprox.core.db import get_db
        conn = get_db().conn
        conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'meanwhile')")
        conn.commit()
        return out
    monkeypatch.setattr(ha, '_walk_snapshot', walk)
    ha.apply_snapshot(snap)
    monkeypatch.setattr(ha, '_walk_snapshot', real)

    rec = ha._cv_record(ha._load())
    assert rec['etag_at_cv'] is None and rec['data_at_cv'] is None and rec['mark'] != ha._change_mark()
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'vm_tags', 'tag_name') == {'meanwhile'}
    # and the sync after that one finds the member in step again
    assert ha._cv_record(ha._load())['data_at_cv'] == real(False)[4]
    assert ha.apply_snapshot(snap)['captured'] is None


def test_without_the_count_a_sync_hashes_inside_its_transaction_as_before(env, db, seed, looks, monkeypatch):
    """The triggers could not be made: no mark, and nothing is taken on trust. The tables
    are hashed before the commit, and the next sync walks them before the wipe."""
    _leader(env)
    seed.user('alice')
    with open(ha.KNOWN_HOSTS_FILE, 'w') as fh:
        fh.write('10.0.0.11 ssh-ed25519 AAAAC3Nza\n')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    os.remove(ha.KNOWN_HOSTS_FILE)

    def broken(cur):
        raise RuntimeError('no triggers today')
    monkeypatch.setattr(ha, '_make_change_triggers', broken)
    ha.apply_snapshot(snap)
    rec = ha._cv_record(ha._load())
    assert 'mark' not in rec and rec['etag_at_cv'] == ha._walk_snapshot(body=False)[0]
    assert rec['data_at_cv'] == ha._walk_snapshot(body=False)[4]
    del looks[:]
    assert ha.apply_snapshot(snap)['captured'] is None
    assert looks == ['pool', 'walk', 'files']
    seed.user('made-on-b')
    assert _kept(_copy(ha.apply_snapshot(snap)['captured'])) == {'made-on-b'}


def test_without_the_count_a_write_right_after_the_sync_is_still_a_change_made_here(env, db, seed,
                                                                                   monkeypatch):
    """Hashed inside the transaction, the tables are what the sync left, and nothing that
    came after the commit."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)

    def broken(cur):
        raise RuntimeError('no triggers today')
    monkeypatch.setattr(ha, '_make_change_triggers', broken)
    real = ha._apply_files

    def files(sent):
        _on_another_connection(
            "INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'right-after')")
        return real(sent)
    monkeypatch.setattr(ha, '_apply_files', files)
    ha.apply_snapshot(snap)
    monkeypatch.setattr(ha, '_apply_files', real)
    doc = _copy(ha.apply_snapshot(snap)['captured'])
    assert _kept(doc, 'vm_tags', 'tag_name') == {'right-after'}


def test_a_leader_that_changed_something_drops_the_mark_of_its_time_as_member(env, db, seed):
    """The mark says what a sync left here. A member that took the lead and changed a row
    holds something else, and its record says so with the hashes of the walk."""
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    assert ha._cv_record(ha._load())['mark']
    assert ha.promote() == 4
    # nothing changed yet: the record is the one of the sync, in a segment of its own
    ha.build_snapshot()
    rec = ha._cv_record(ha._load())
    assert rec['hist'][-1][:2] == [4, 0] and rec['mark'] == ha._change_mark()
    seed.user('made-on-b')
    ha.build_snapshot()
    rec = ha._cv_record(ha._load())
    assert rec['hist'][-1][:2] == [4, 1] and 'mark' not in rec


# --- the change journal --------------------------------------------------------------------

def test_the_copy_carries_the_journal_lines_the_snapshot_does_not(env, db, seed):
    _leader(env)
    assert ha.note_write('alice', 'POST', '/api/users', '') is True
    seed.user('alice')
    assert ha.flush_journal() == 1
    snap = _wire(ha.build_snapshot())          # alice is in 3.1
    assert [(r[0], json.loads(r[4])) for r in _journal_rows(db)] == [('alice', snap['hist'][-1])]

    from_b = _handed_on(snap, B, 4)
    ha.note_write('root', 'PUT', '/api/users/carol', B)
    seed.user('carol')
    ha.flush_journal()
    ha.note_write('root', 'POST', '/api/users/dave')        # still waits in memory
    seed.user('dave')
    with ha._journal_lock:
        waiting = list(ha._journal['pending'])
    assert len(waiting) == 1
    ha._journal['pending'] = waiting
    assert ha.step_down(4, B)
    doc = _copy(ha.apply_snapshot(from_b)['captured'])
    # the line B's history carries stays out, the ones after the last cv are in
    assert [(j['user'], j['path'], j['via'], j['cv']) for j in doc['journal']] == [
        ('root', '/api/users/carol', B, None), ('root', '/api/users/dave', '', None)]
    assert ha.orphan_captures()[0]['journal_rows'] == 2
    # every line is settled by the sync, and the journal starts over
    assert _journal_rows(db) == [] and ha._journal['pending'] == []


def test_a_line_that_still_waits_in_memory_goes_into_the_copy_too(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    from_b = _handed_on(snap, B, 4)
    seed.user('carol')
    assert ha.step_down(4, B)
    # noted by a request that finished after the step-down wrote the journal
    ha._journal['pending'].append(('2026-10-01T10:02:00+00:00', 'root', 'POST', '/api/users', ''))
    doc = _copy(ha.apply_snapshot(from_b)['captured'])
    assert [(j['id'], j['user'], j['path']) for j in doc['journal']] == [(None, 'root', '/api/users')]
    # it is settled with the rest, and does not turn up in the journal of a later lead
    assert ha._journal['pending'] == []


def test_only_an_active_with_members_keeps_a_journal(env, db, seed):
    _member(env, B)
    assert ha.note_write('alice', 'POST', '/api/users') is False
    _as(env, C)
    _write_state(role='standalone', instance_id=C)
    assert ha.note_write('alice', 'POST', '/api/users') is False
    assert ha.flush_journal() == 0 and _journal_rows(db) == []
    _leader(env)
    assert ha.note_write('alice', 'POST', '/api/users') is True


def test_a_burst_of_writes_is_one_flush_a_moment_later(env, db, monkeypatch):
    _leader(env)
    timers = []
    monkeypatch.setattr(ha, '_journal_later', _JOURNAL_LATER)
    monkeypatch.setattr(ha, '_later', lambda delay, fn, name: timers.append((delay, fn, name)))
    for i in range(3):
        ha.note_write('u', 'POST', f'/api/x/{i}')
    assert [(d, n) for d, _fn, n in timers] == [(ha.JOURNAL_DELAY, 'ha-journal')]
    assert _journal_rows(db) == []
    timers.pop()[1]()
    assert [r[2] for r in _journal_rows(db)] == ['/api/x/0', '/api/x/1', '/api/x/2']
    # the next write starts the next one
    ha.note_write('u', 'POST', '/api/x/3')
    assert len(timers) == 1


def test_journal_lines_that_cannot_be_written_wait_for_the_next_flush(env, db, monkeypatch):
    _leader(env)
    for i in range(3):
        ha.note_write('u', 'POST', f'/api/x/{i}')
    real = ha._journal_table

    def broken(cur):
        raise OSError('disk I/O error')
    monkeypatch.setattr(ha, '_journal_table', broken)
    assert ha.flush_journal() == 0
    monkeypatch.setattr(ha, '_journal_table', real)
    assert ha.flush_journal() == 3
    assert [r[2] for r in _journal_rows(db)] == ['/api/x/0', '/api/x/1', '/api/x/2']


def test_the_journal_is_bounded(env, db, monkeypatch):
    _leader(env)
    monkeypatch.setattr(ha, 'JOURNAL_KEEP', 5)
    monkeypatch.setattr(ha, 'JOURNAL_PENDING_MAX', 4)
    for i in range(6):
        ha.note_write('u', 'POST', f'/api/x/{i}')
    # the database did not take them in time: the oldest two went
    assert ha.flush_journal() == 4
    for i in range(6, 9):
        ha.note_write('u', 'POST', f'/api/x/{i}')
    ha.flush_journal()
    assert [r[2] for r in _journal_rows(db)] == [f'/api/x/{i}' for i in (4, 5, 6, 7, 8)]


def test_stepping_down_writes_the_lines_that_still_wait(env, db):
    _leader(env)
    ha.note_write('root', 'POST', '/api/users')
    assert _journal_rows(db) == []
    assert ha.step_down(4, B)
    assert [r[:3] for r in _journal_rows(db)] == [('root', 'POST', '/api/users')]

    _leader(env, me=C, others=(A,))
    ha.note_write('root', 'PUT', '/api/users/x')
    assert ha.step_aside(5, 'every member refused this instance')
    assert [r[1] for r in _journal_rows(db)] == ['POST', 'PUT']

    # and an active that hears it was removed
    _leader(env, me=D, others=(A,))
    ha.note_write('root', 'DELETE', '/api/users/x')
    assert ha._mark_removed(A, 3) == 'active'
    assert [r[1] for r in _journal_rows(db)] == ['POST', 'PUT', 'DELETE']


def test_lines_a_restart_left_without_a_cv_get_the_next_one(env, db, seed):
    _leader(env)
    ha.note_write('root', 'POST', '/api/users')
    seed.user('alice')
    ha.flush_journal()
    # the process restarts before anything walked
    ha._journal.update(pending=[], last_id=None, filled_to=0)
    snap = _wire(ha.build_snapshot())
    assert [json.loads(r[4]) for r in _journal_rows(db)] == [snap['hist'][-1]]


def test_a_line_noted_after_the_walk_began_waits_for_the_next_cv(env, db, seed, monkeypatch):
    _leader(env)
    ha.note_write('root', 'POST', '/api/users/alice')
    seed.user('alice')
    ha.flush_journal()
    real = ha._walk_snapshot

    def walk(body):
        out = real(body)
        # a write that lands while the tables are being read may be in the walk or not
        ha.note_write('root', 'POST', '/api/users/late')
        ha.flush_journal()
        return out
    monkeypatch.setattr(ha, '_walk_snapshot', walk)
    first = _wire(ha.build_snapshot())
    assert [r[4] and json.loads(r[4]) for r in _journal_rows(db)] == [first['hist'][-1], None]
    monkeypatch.setattr(ha, '_walk_snapshot', real)
    seed.user('bob')
    snap = _wire(ha.build_snapshot())
    assert [json.loads(r[4]) for r in _journal_rows(db)] == [first['hist'][-1], snap['hist'][-1]]


# --- the change gap --------------------------------------------------------------------------

def test_change_gap():
    mine = [[3, 4, 'a' * 16, A]]
    assert ha.change_gap(mine, [3, 4, 'a' * 16, A]) is None
    assert ha.change_gap(mine, [3, 2, 'a' * 16, A]) is None
    assert ha.change_gap(mine, None) is None and ha.change_gap(mine, [3, -1, 'a' * 16, A]) is None
    assert ha.change_gap(mine, [3, 9, 'a' * 16, A], '2026-10-01T10:01:58+00:00') == {
        'epoch': 3, 'from': 5, 'to': 9, 'count': 5, 'by': A, 'until': '2026-10-01T10:01:58+00:00'}
    # another line of history: there, but not countable
    assert ha.change_gap(mine, [3, 9, 'd' * 16, C]) == {
        'epoch': 3, 'from': None, 'to': 9, 'count': None, 'by': C, 'until': None}
    # a segment further back in the history counts from where it was left
    assert ha.change_gap([[2, 7, 'e' * 16, C]] + mine, [2, 8, 'e' * 16, C])['count'] == 1


def test_a_promotion_names_the_changes_it_is_missing(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    seg = snap['hist'][0][2]
    _member(env, B)
    ha.apply_snapshot(snap)
    # the active said so with its last note about a change, and never answered the pull
    assert ha.note_leader_cv(A, [3, 4, seg, A], '2026-10-01T10:01:58+00:00') is True

    ha.promote()

    gap = ha.public_status()['change_gap']
    assert gap is not None
    assert (gap['from'], gap['to'], gap['count'], gap['by'], gap['member']) == (2, 4, 3, A, A)
    assert gap['until'] == '2026-10-01T10:01:58+00:00'
    details = _audit('ha.change_gap')[0]['details']
    assert 'changes 3.2 to 3.4' in details and 'until 2026-10-01T10:01:58+00:00' in details


def test_a_promotion_with_everything_here_names_no_gap(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(snap)
    ha.note_leader_cv(A, snap['hist'][-1], snap['cv_at'])
    ha.promote()
    assert ha.public_status()['change_gap'] is None and _audit('ha.change_gap') == []


def test_a_standby_that_holds_more_than_the_promoted_one_shows_in_the_gap(env, db, seed):
    """Not only the old active: C reported 3.2 at the last watch, B was promoted at 3.1."""
    one, two = _two_rounds(env, seed)
    _member(env, B)
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    ha.apply_snapshot(one)
    with ha._lock:
        st = ha._load()
        # the member lists of these tests carry no keys, so the sync dropped C. The old
        # active was last heard at 3.1, where B is too
        ms = dict(st['members'], **{C: _rec(C, 'standby', cv_seen=two['hist'][-1],
                                            cv_seen_at=two['cv_at'])})
        ms[A] = dict(ms[A], cv_seen=one['hist'][-1], cv_seen_at=one['cv_at'])
        ha._commit_locked(dict(st, members=ms))
    ha.promote()
    gap = ha.public_status()['change_gap']
    assert (gap['from'], gap['to'], gap['member']) == (2, 2, C)


def test_the_cv_a_member_reported_only_moves_forward_within_a_segment(env, db):
    _member(env, B)
    seg = 'a' * 16
    assert ha.note_leader_cv(A, [3, 4, seg, A], 'at-4') is True
    # an answer that took long
    assert ha.note_leader_cv(A, [3, 2, seg, A], 'at-2') is False
    assert ha.member(A)['cv_seen'] == [3, 4, seg, A] and ha.member(A)['cv_seen_at'] == 'at-4'
    assert ha.note_leader_cv(A, [3, 4, seg, A], 'again') is False
    # another segment is another history, whatever its numbers
    assert ha.note_leader_cv(A, [3, 1, 'b' * 16, A]) is True
    assert ha.member(A)['cv_seen'] == [3, 1, 'b' * 16, A] and ha.member(A)['cv_seen_at'] is None
    for junk in (None, 'x', [3, 4, seg], [3, -1, seg, A]):
        assert ha.note_leader_cv(A, junk) is False
    assert ha.note_leader_cv(D, [3, 9, seg, A]) is False


def test_the_watch_notes_the_cv_each_member_reports(env, db, monkeypatch):
    _leader(env)
    answers = {
        B: {'instance_id': B, 'role': 'standby', 'epoch': 3, 'group': 1, 'cv': [3, 2, 'a' * 16, A],
            'cv_at': '2026-10-01T10:00:00+00:00'},
        C: {'instance_id': C, 'role': 'standby', 'epoch': 3, 'group': 1, 'cv': [3, -2, 'a' * 16, A]},
    }

    def call(rec, method, path, **kw):
        return types.SimpleNamespace(status_code=200, json=lambda: answers[rec['instance_id']])
    monkeypatch.setattr(ha, 'call_member', call)
    assert ha._ask_members(5) == {B: ('standby', 3), C: ('standby', 3)}
    assert ha.member(B)['cv_seen'] == [3, 2, 'a' * 16, A]
    assert ha.member(B)['cv_seen_at'] == '2026-10-01T10:00:00+00:00'
    assert 'cv_seen' not in ha.member(C)
    # an older answer of the same segment does not put the note back
    answers[B] = dict(answers[B], cv=[3, 1, 'a' * 16, A], cv_at='earlier')
    ha._ask_members(5)
    assert ha.member(B)['cv_seen'] == [3, 2, 'a' * 16, A]


# --- the tick of an automatic leader ----------------------------------------------------------

@pytest.fixture
def walks(monkeypatch):
    seen = []
    real = ha.snapshot_etag

    def counted(*a, **kw):
        seen.append(1)
        return real(*a, **kw)
    monkeypatch.setattr(ha, 'snapshot_etag', counted)
    nudged = []
    monkeypatch.setattr(ha, 'nudge_members', lambda: nudged.append(1) or True)
    return types.SimpleNamespace(seen=seen, nudged=nudged)


def test_the_tick_walks_only_once_the_triggers_counted_a_change(env, db, seed, walks):
    _leader(env)
    seed.user('alice')
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 1)
    assert ha.cv_tick() == 'clean' and len(walks.seen) == 1

    seed.user('bob')
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 2)
    assert len(walks.seen) == 2 and len(walks.nudged) == 2
    # a volatile column is not counted, so no walk at all
    db.conn.execute("UPDATE users SET last_login = 'now' WHERE username = 'bob'")
    db.conn.execute("UPDATE webauthn_credentials SET sign_count = 3")
    db.conn.commit()
    assert ha.cv_tick() == 'clean' and len(walks.seen) == 2
    # a write that leaves every value as it was is not counted either
    db.conn.execute("UPDATE users SET role = role")
    db.conn.commit()
    assert ha.cv_tick() == 'clean'
    db.conn.execute("UPDATE users SET role = 'admin' WHERE username = 'bob'")
    db.conn.commit()
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 3)
    db.conn.execute("DELETE FROM users WHERE username = 'bob'")
    db.conn.commit()
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 4)
    # files the snapshot carries have no trigger: their size and time do
    os.makedirs(ha.BRANDING_DIR, exist_ok=True)
    with open(os.path.join(ha.BRANDING_DIR, 'login-bg.png'), 'wb') as fh:
        fh.write(b'\x89PNG')
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 5)
    assert len(walks.nudged) == 5
    # counted, walked, and nothing a snapshot carries changed: one of this host's settings
    db.save_server_setting('port', 5001)
    assert ha.cv_tick() == 'same' and ha.config_version() == (3, 5) and len(walks.nudged) == 5
    # asked to, it walks whatever the count says
    before = len(walks.seen)
    assert ha.cv_tick() == 'clean' and len(walks.seen) == before
    assert ha.cv_tick(force=True) == 'same' and len(walks.seen) == before + 1


def test_the_tick_gives_the_journal_lines_their_cv(env, db, seed, walks):
    _leader(env)
    ha.note_write('root', 'POST', '/api/users')
    seed.user('alice')
    assert ha.cv_tick() == 'stepped'
    assert [json.loads(r[4]) for r in _journal_rows(db)] == [ha.cv_entry()]


def test_without_the_count_the_tick_walks_every_time(env, db, seed, walks, monkeypatch):
    _leader(env)
    seed.user('alice')

    def broken():
        raise RuntimeError('no such table: ha_cv_dirty')
    monkeypatch.setattr(ha, '_dirty_count', broken)
    assert ha.cv_tick() == 'stepped'
    assert ha.cv_tick() == 'same' and ha.cv_tick() == 'same'
    assert len(walks.seen) == 3 and len(walks.nudged) == 1


def test_the_tick_is_idle_anywhere_but_on_an_active_with_members(env, db, walks):
    _member(env, B)
    assert ha.cv_tick() == 'idle'
    _as(env, C)
    _write_state(role='standalone', instance_id=C)
    assert ha.cv_tick() == 'idle' and walks.seen == []
    assert db.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' "
                           "AND name LIKE 'ha_cv_%'").fetchone()[0] == 0


def test_triggers_come_back_after_a_rebuild_or_a_new_column(env, db, seed):
    _leader(env)
    shared = [t for t in ha.SYNC_TABLES if t in ha._existing_tables(db.conn.cursor())]
    assert ha.ensure_change_triggers() == 3 * len(shared)
    assert ha.ensure_change_triggers() == 0

    db.conn.execute('DROP TRIGGER ha_cv_vm_tags_i')
    db.conn.execute('ALTER TABLE users ADD COLUMN added_later TEXT')
    db.conn.commit()
    assert ha.ensure_change_triggers() == 2
    seed.user('alice')
    n = ha._dirty_count()
    db.conn.execute("UPDATE users SET added_later = 'x' WHERE username = 'alice'")
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    assert ha._dirty_count() == n + 2
    # a trigger of a table no longer shared goes
    db.conn.execute('CREATE TABLE gone_table (x)')
    db.conn.execute('CREATE TRIGGER "ha_cv_gone_table_i" AFTER INSERT ON gone_table BEGIN SELECT 1; END')
    db.conn.commit()
    ha.ensure_change_triggers()
    assert not db.conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'ha_cv_gone_table_i'").fetchone()


def test_the_tick_looks_the_triggers_over_again_after_a_while(env, db, seed, walks, monkeypatch):
    _leader(env)
    seed.user('alice')
    clock = [1000.0]
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(monotonic=lambda: clock[0], time=ha.time.time))
    assert ha.cv_tick() == 'stepped'
    # as if the schema version could not tell
    monkeypatch.setattr(ha, '_schema_version', lambda: 1)
    ha._tick['schema'] = 1
    db.conn.execute('DROP TRIGGER ha_cv_vm_tags_i')
    db.conn.commit()
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    # not counted, so not seen, until the triggers are looked over
    assert ha.cv_tick() == 'clean'
    clock[0] += ha.TRIGGER_CHECK
    # the look made a trigger: one walk whatever the count says, and it finds the row
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 2)
    assert ha.cv_tick() == 'clean'
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 101, 'prod')")
    db.conn.commit()
    assert ha.cv_tick() == 'stepped'


def test_the_tick_catches_up_on_a_table_made_on_first_use(env, db, seed, walks):
    """(#625 review) api_tokens, custom_scripts, update_schedules, balancing_excluded_vms
    and pegaprox_kv are made on first use, and what is written to them before the next
    look at the triggers is not counted. The look made the triggers and then compared
    the same count: clean, for every tick after it, with the change never in the cv."""
    _leader(env)
    seed.user('alice')
    assert ha.cv_tick() == 'stepped' and ha.cv_tick() == 'clean'
    # as api/pbs.py does it
    db.conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    db.conn.execute("INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES ('pbs_verify_schedule', '{}')")
    db.conn.commit()
    # the very next tick: the schema moved, so the triggers are looked over at once
    assert ha.cv_tick() == 'stepped' and ha.config_version() == (3, 2)
    assert db.conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'ha_cv_pegaprox_kv_i'").fetchone()
    assert ha.cv_tick() == 'clean' and len(walks.seen) == 2
    # a column made on first use, and a value in it
    db.conn.execute('ALTER TABLE users ADD COLUMN made_on_first_use TEXT')
    db.conn.execute("UPDATE users SET made_on_first_use = 'x'")
    db.conn.commit()
    assert ha.cv_tick() == 'stepped' and ha.cv_tick() == 'clean'


# --- the routes ------------------------------------------------------------------------------

def test_the_snapshot_route_hands_out_the_cv(ha_env, db):
    _active_with_standby(ha_env)
    api = ha_env.api

    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD)
    snap = json.loads(gzip.decompress(r.get_data()))
    assert r.status_code == 200 and snap['cv'] == [1, 1] and snap['hist'][-1][3] == ha.instance_id()
    status = _peer(api, 'GET', '/api/ha/peer/status', GOOD).get_json()
    assert status['cv'] == snap['hist'][-1] and status['cv_at'] == snap['cv_at']

    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    # the poll steps it too: the etag it worked out stands for the content
    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD, {'If-None-Match': snap['etag']})
    assert r.status_code == 200
    assert json.loads(gzip.decompress(r.get_data()))['cv'] == [1, 2]
    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD, {'If-None-Match': r.headers['ETag']})
    assert r.status_code == 304 and ha.config_version() == (1, 2)


def test_the_snapshot_route_takes_what_the_member_says_it_holds(ha_env, db):
    """(#625 review) X-PegaProx-Peer-Cv with the pull. More of the leader's own segment
    than the leader knows of means its state went back, and it hands out a segment of
    its own from that very pull on, a 304 included."""
    _active_with_standby(ha_env)
    api = ha_env.api

    def pull(held, **headers):
        if held is not None:
            headers[ha.PEER_CV_HEADER] = held if isinstance(held, str) else json.dumps(held)
        return _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD, headers)
    snap = json.loads(gzip.decompress(pull(None).get_data()))
    seg, me = snap['hist'][-1][2], ha.instance_id()
    assert snap['hist'] == [[1, 1, seg, me]] and len(snap['steps']) == 1

    # what it was handed, less of it, another segment, or nothing that is a cv
    for held in ([1, 1, seg, me], [1, 0, seg, me], [1, 9, 'f' * 16, me], 'junk', '[1, 9]'):
        assert json.loads(gzip.decompress(pull(held).get_data()))['hist'] == snap['hist'], held

    r = pull([1, 5, seg, me], **{'If-None-Match': snap['etag']})
    assert r.status_code == 304
    now = ha.cv_entry()
    assert now[:2] == [1, 6] and now[2] != seg and now[3] == me
    got = json.loads(gzip.decompress(pull([1, 5, seg, me]).get_data()))
    assert got['hist'] == [[1, 1, seg, me], now] and got['base_cv'] == [1, 1]
    assert [s[:2] for s in got['steps']] == [[seg, 1], [now[2], 6]]


def test_a_pull_says_what_this_member_holds(env, db, seed):
    _leader(env)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _member(env, B)
    sent = []

    def call(method, base_url, fingerprint, path, json_body=None, auth=None, headers=None, timeout=15):
        sent.append(dict(headers or {}))
        return types.SimpleNamespace(status_code=200, json=lambda: snap)
    env.mp.setattr(ha, '_peer_call', call)
    # joined just now: nothing it could say
    assert ha.pull_once() == 'applied' and sent == [{}]
    assert ha.pull_once() == 'applied'
    assert ha.held_cv(sent[1][ha.PEER_CV_HEADER]) == snap['hist'][-1]
    assert sent[1]['If-None-Match'] == snap['etag']


def test_a_snapshot_whose_cv_cannot_be_saved_is_not_served(ha_env, db, monkeypatch):
    _active_with_standby(ha_env)

    def refused(raw, upto=None, **kw):
        raise ha.HaError('The config version could not be saved: disk full')
    monkeypatch.setattr(ha, 'note_config_etag', refused)
    r = _peer(ha_env.api, 'GET', '/api/ha/peer/snapshot', GOOD)
    assert r.status_code == 500 and 'tables' not in (r.get_json() or {})


def test_a_write_request_on_the_active_leaves_a_journal_line(ha_env, seed):
    _active_with_standby(ha_env)
    admin = _admin(ha_env.api, seed)
    assert admin.get('/api/cluster-groups').status_code == 200
    assert admin.post('/api/cluster-groups', json={}).status_code == 400
    assert admin.put('/api/ha/settings', json={'interval': 60}).status_code == 200
    assert admin.post('/api/sse/token', json={}).status_code == 200
    assert ha._journal['pending'] == []

    r = admin.post('/api/cluster-groups', json={'name': 'Rack 4'})
    assert r.status_code in (200, 201), r.data
    [(at, user, method, path, via)] = ha._journal['pending']
    assert at and (user, method, path, via) == ('root', 'POST', '/api/cluster-groups', '')


def test_a_standalone_instance_keeps_no_journal_of_its_writes(ha_env, seed):
    admin = _admin(ha_env.api, seed)
    r = admin.post('/api/cluster-groups', json={'name': 'Rack 4'})
    assert r.status_code in (200, 201), r.data
    assert ha._journal['pending'] == []


def _a_copy_on_this_instance(ha_env, db, seed):
    """This instance is a standby that kept one copy; returns its name."""
    _be(ha_env, 'standby', instance_id=B_ID, epoch=1, forward_writes=False,
        peer=_peer_record('a' * 32, 'https://active.example:5000', 'active'), cv=None)
    snap = _wire(ha.build_snapshot(meta=dict(ha.snapshot_meta(), instance_id='a' * 32, role='active')))
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'only-here')")
    db.conn.commit()
    name = ha.apply_snapshot(snap)['captured']
    assert name
    return name


def test_an_admin_downloads_a_copy_with_the_password_again(ha_env, db, seed):
    admin = _admin(ha_env.api, seed)
    name = _a_copy_on_this_instance(ha_env, db, seed)
    status = admin.get('/api/ha/status').get_json()
    assert status['orphans']['count'] == 1 and status['orphans']['items'][0]['name'] == name
    assert status['config_version']['cv'] == [0, 0] and status['change_gap'] is None

    path = f'/api/ha/orphans/{name}/download'
    r = admin.post(path, json={})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    r = admin.post(path, json={'user_password': 'not-it'})
    assert r.status_code == 403
    assert _audit('ha.changes_downloaded') == []

    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.mimetype == 'application/gzip'
    assert f'pegaprox-ha-{name}.json.gz' in r.headers['Content-Disposition']
    doc = json.loads(gzip.decompress(r.get_data()))
    assert _kept(doc, 'vm_tags', 'tag_name') == {'only-here'}
    assert name in _audit('ha.changes_downloaded')[0]['details']
    # on disk it is sealed, and the download is what opens it
    with open(os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX), 'rb') as fh:
        sealed = fh.read()
    assert sealed != r.get_data() and b'only-here' not in sealed
    assert sealed[:8] in (ha.ORPHAN_MAGIC, ha.ORPHAN_MAGIC_MASTER)

    for bad in ('nope', '..%2Fha_state', name + 'x'):
        r = admin.post(f'/api/ha/orphans/{bad}/download', json={'user_password': ADMIN_PW})
        assert r.status_code == 404, (bad, r.status_code)

    # a copy that does not open says why, after the password and not before
    with open(os.path.join(ha.ORPHANS_DIR, name + ha.ORPHAN_SUFFIX), 'wb') as fh:
        fh.write(sealed[:-1] + bytes([sealed[-1] ^ 1]))
    assert admin.post(path, json={'user_password': 'not-it'}).status_code == 403
    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 409 and 'changed or damaged' in r.get_json()['error']
    assert len(_audit('ha.changes_downloaded')) == 1


def test_the_download_says_when_a_copy_is_under_a_key_that_is_gone(ha_env, db, seed, monkeypatch,
                                                                   plain_sqlite):
    """(#625 review) On plain SQLite the copy is under the field key from before a
    rotation. With the backup of that key next to the key file the download opens it;
    without, the answer names the key instead of a failed decryption."""
    import pegaprox.core.db as dbmod
    monkeypatch.setattr(ha, 'AES_KEY_FILE', os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'))
    admin = _admin(ha_env.api, seed)
    name = _a_copy_on_this_instance(ha_env, db, seed)
    fp = ha.key_fingerprint()
    stats = db.rotate_encryption_key()
    assert stats.get('success')
    path = f'/api/ha/orphans/{name}/download'

    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 200
    assert _kept(json.loads(gzip.decompress(r.get_data())), 'vm_tags', 'tag_name') == {'only-here'}

    os.remove(stats['key_backup'])
    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 409
    assert f'sealed under an earlier field key (fingerprint {fp})' in r.get_json()['error']
    item = admin.get('/api/ha/status').get_json()['orphans']['items'][0]
    assert item['key'] == {'fp': fp, 'current': False, 'backup': None}
    assert len(_audit('ha.changes_downloaded')) == 1


def test_an_admin_dismisses_a_copy_and_nothing_else_does(ha_env, db, seed):
    admin = _admin(ha_env.api, seed)
    name = _a_copy_on_this_instance(ha_env, db, seed)
    path = f'/api/ha/orphans/{name}/dismiss'
    for body in ({}, {'confirm': 'yes'}, {'confirm': 1}):
        assert admin.post(path, json=body).status_code == 400
    assert _copies() == [name]
    assert admin.post('/api/ha/orphans/1-1-20261001T100000Z-abcdefabcdef/dismiss',
                      json={'confirm': True}).status_code == 404

    r = admin.post(path, json={'confirm': True})
    assert r.status_code == 200 and r.get_json()['orphans']['count'] == 0
    assert _copies() == []
    assert 'root dismissed' in _audit('ha.changes_dismissed')[0]['details']
    assert admin.post(path, json={'confirm': True}).status_code == 404


def test_the_download_says_when_a_copy_is_under_another_master_key(ha_env, db, seed, master):
    """After the password, and in words: not a failed decryption, and not a 500."""
    admin = _admin(ha_env.api, seed)
    name = _a_copy_on_this_instance(ha_env, db, seed)
    fp = ha.key_fingerprint(_derived(MASTER))
    path = f'/api/ha/orphans/{name}/download'
    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 200
    assert _kept(json.loads(gzip.decompress(r.get_data())), 'vm_tags', 'tag_name') == {'only-here'}

    master(bytes(range(32, 64)))
    assert admin.post(path, json={'user_password': 'not-it'}).status_code == 403
    r = admin.post(path, json={'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.mimetype == 'application/json'
    assert f'sealed under another master key (fingerprint {fp})' in r.get_json()['error']
    orphans = admin.get('/api/ha/status').get_json()['orphans']
    assert orphans['items'][0]['seal'] == {'under': 'master', 'fp': fp, 'current': False,
                                           'backup': None, 'opens': False}
    assert orphans['seal'] == {'under': 'master', 'fp': ha.key_fingerprint(_derived(bytes(range(32, 64))))}
    assert len(_audit('ha.changes_downloaded')) == 1


def test_a_dismiss_during_a_sync_is_told_to_try_again(ha_env, db, seed, monkeypatch):
    admin = _admin(ha_env.api, seed)
    name = _a_copy_on_this_instance(ha_env, db, seed)
    monkeypatch.setattr(ha, 'DISMISS_WAIT', 0.05)
    path = f'/api/ha/orphans/{name}/dismiss'
    assert ha._pull_lock.acquire(timeout=1)
    try:
        r = admin.post(path, json={'confirm': True})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_SYNC_RUNNING'
        assert 'try again' in r.get_json()['error'] and int(r.headers['Retry-After']) > 0
        assert _copies() == [name] and _audit('ha.changes_dismissed') == []
        # what is no copy is told so at once, sync or not
        assert admin.post('/api/ha/orphans/1-1-20261001T100000Z-abcdefabcdef/dismiss',
                          json={'confirm': True}).status_code == 404
        assert admin.post(path, json={}).status_code == 400
    finally:
        ha._pull_lock.release()
    r = admin.post(path, json={'confirm': True})
    assert r.status_code == 200 and _copies() == []


# --- on the group ------------------------------------------------------------------------------

def test_the_group_learns_the_cv_with_the_watch_and_with_the_note(group, seed, monkeypatch):
    g = group
    admin = _built(g, seed, 'bc', sync=False)
    # joined, not synced yet: the first snapshot replaces what each of them holds
    assert g.state('b')['cv'] == {'joined': True} and 'cv' not in g.state('a')
    for n in 'bc':
        assert _sync(g, admin, n) == 'applied'
    lead = g.state('a')['cv']['hist'][-1]
    assert lead[0] == 1 and lead[3] == IDS['a']
    # each standby holds what the leader handed out, and says so when asked
    for n in 'bc':
        assert g.state(n)['cv']['hist'] == [lead] and g.state(n)['cv']['from'] == [IDS['a'], 1]
    assert _watch(g, 'a') == 'ok'
    assert g.state('a')['members'][IDS['b']]['cv_seen'] == lead
    assert _watch(g, 'b') in ('ok', 'source switched')
    assert g.state('b')['members'][IDS['a']]['cv_seen'] == lead

    # the note after a write carries the cv the leader is at now
    timers = []
    monkeypatch.setattr(ha, '_later', lambda delay, fn, name: timers.append((g.name(), fn, name)))
    monkeypatch.setattr(ha, '_in_background', lambda fn, name: None)
    with g.at('a'):
        assert admin.post('/api/cluster-groups', json={'name': 'Rack 4'}).status_code in (200, 201)
    [(n, fn, name)] = timers
    assert (n, name) == ('a', 'ha-nudge')
    before = len(g.sent)
    with g.at('a'):
        fn()
    now = g.state('a')['cv']['hist'][-1]
    assert now[:2] == [1, lead[1] + 1]
    notes = [json.loads(body) for _f, _t, _m, path, body, _h in g.sent[before:]
             if path == '/api/ha/peer/changed']
    assert len(notes) == 2 and all(note['cv'] == now and note['cv_at'] for note in notes)
    # the standbys did not pull (nothing runs in the background here) and know they are behind
    assert g.state('b')['members'][IDS['a']]['cv_seen'] == now
    assert g.state('b')['cv']['hist'] == [lead]
    # the journal line of that write has its cv
    with g.at('a'):
        from pegaprox.core.db import get_db
        rows = [tuple(r) for r in get_db().conn.execute('SELECT user, path, cv FROM ha_change_journal')]
    assert [(u, p, json.loads(cv)) for u, p, cv in rows] == [('root', '/api/cluster-groups', now)]

    # b takes the lead without that change, and says which one it is missing
    g.down.add('a')
    r = _promote(g, admin, 'b')
    assert r.status_code == 200, r.data
    gap = g.state('b')['change_gap']
    assert (gap['epoch'], gap['from'], gap['to'], gap['member']) == (1, now[1], now[1], IDS['a'])
    with g.at('b'):
        assert admin.get('/api/ha/status').get_json()['change_gap']['count'] == 1


def test_a_note_from_anybody_but_the_leader_teaches_nothing(group, seed):
    g = group
    _built(g, seed, 'bc')
    lead = g.state('a')['cv']['hist'][-1]
    body = {'etag': 'x' * 32, 'cv': [9, 9, 'f' * 16, IDS['c']], 'cv_at': 'now'}
    with g.at('c') as h:
        r = h.call_member(h.member(IDS['b']), 'POST', '/api/ha/peer/changed', json_body=body)
    assert r.status_code == 200 and r.json()['pull'] is False
    assert 'cv_seen' not in g.state('b')['members'][IDS['c']]
    assert g.state('b')['members'][IDS['a']].get('cv_seen') in (None, lead)


def test_a_write_a_standby_forwards_is_journaled_on_the_leader_with_the_standby(group, seed, monkeypatch):
    g = group
    admin = _built(g, seed, 'b')
    monkeypatch.setattr(ha, '_in_background', lambda fn, name: None)
    with g.at('b'):
        r = admin.post('/api/cluster-groups', json={'name': 'Rack 4'})
    assert r.status_code in (200, 201), r.data
    [(_at, user, method, path, via)] = ha._journal['pending']
    # the standby as the audit trail names it
    assert (user, method, path, via) == ('root', 'POST', '/api/cluster-groups', URLS['b'])


# --- a copy counts as kept only when its seal holds -------------------------------------

def _opens(name):
    try:
        return _kept(_copy(name))
    except ha.HaError:
        return None


def _flip(raw, at):
    return raw[:at] + bytes([raw[at] ^ 0x01]) + raw[at + 1:]


def _sealed_for_another_name(raw, key, kind):
    body = os.urandom(len(raw) - 24 - 12 - 16)
    out = ha._seal_copy('3-1-20260101T000000Z-aaaaaaaaaaaa', body, key, kind)
    assert len(out) == len(raw)
    return out


DAMAGED_AT_ITS_SIZE = {
    'one bit in the body': lambda raw, key, kind: _flip(raw, len(raw) // 2),
    'one bit in the tag': lambda raw, key, kind: _flip(raw, len(raw) - 1),
    'one bit in the nonce': lambda raw, key, kind: _flip(raw, 30),
    'the second half zeroed': lambda raw, key, kind: raw[:len(raw) // 2] + bytes(len(raw) - len(raw) // 2),
    'all but the head zeroed': lambda raw, key, kind: raw[:24] + bytes(len(raw) - 24),
    'the file of another copy': _sealed_for_another_name,
}


@pytest.mark.parametrize('damage', sorted(DAMAGED_AT_ITS_SIZE))
@pytest.mark.parametrize('mode', ['master', 'field'])
def test_a_copy_damaged_at_its_own_size_stands_for_no_row(env, db, seed, monkeypatch, damage, mode):
    """Length and head still fit, the seal does not: the rows are kept anew, in a copy
    that opens, before they are wiped."""
    monkeypatch.setattr(ha, '_master_key', (lambda: MASTER) if mode == 'master' else (lambda: None))
    snap, one = _in_step_with_one_copy(env, db, seed)
    key, kind = ha._copy_key()
    damaged = DAMAGED_AT_ITS_SIZE[damage](_sealed(one), key, kind)
    with open(os.path.join(ha.ORPHANS_DIR, one + ha.ORPHAN_SUFFIX), 'wb') as fh:
        fh.write(damaged)
    assert _opens(one) is None
    two = ha.apply_snapshot(snap)['captured']
    assert 'made-here' not in _users(db)
    assert two != one and _opens(two) == {'made-here'}
    assert _meta(one)['repeats'] == 0


def test_a_whole_copy_still_counts_the_repeat(env, db, seed, monkeypatch):
    """Counterproof: the same rows again, the copy untouched - no second copy."""
    monkeypatch.setattr(ha, '_master_key', lambda: MASTER)
    snap, one = _in_step_with_one_copy(env, db, seed)
    assert ha.apply_snapshot(snap)['captured'] == one
    assert _copies() == [one] and _meta(one)['repeats'] == 1
