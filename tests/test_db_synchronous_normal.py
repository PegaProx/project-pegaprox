"""synchronous=NORMAL on the WAL connections to pegaprox.db, and the commits that stay durable.

FULL, SQLite's default, synced the WAL at every commit: 8 to 9 ms a commit against 0.12 ms,
on the hub. NORMAL syncs at the checkpoints, and a power cut (not a crashed process) can take
the last commits before it. So a commit that something outside the database relies on is
followed by a sync of the WAL before that happens: the audit chain (the anchor beside the
key, the SIEM targets), a key rotation (the new key file is on disk already), the legacy user
file moved aside, the failover replay, the failover marks of a recovery plan, and in an HA
group the config version in the state file and the recovery journal.

The tests watch the order in which things reach the disk: each commit with the level it ran
at, each fsync with its file, and the step that trusts them. A commit under FULL is on disk
when it returns, one under NORMAL once the WAL was synced after it. MK Nov 2026
"""
import os

import gevent
import pytest

from pegaprox.core import dbcrypto, ha
from test_ha_core import env, _write_state, _wire, A, B  # noqa: F401  (env is a fixture)

FULL = 2


class _Watched:
    """A connection that notes its commits (the level they ran at, the journal mode)."""

    def __init__(self, conn, disk):
        object.__setattr__(self, '_conn', conn)
        object.__setattr__(self, '_disk', disk)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        setattr(self._conn, name, value)

    def commit(self):
        if self._conn.in_transaction:
            level = self._conn.execute('PRAGMA synchronous').fetchone()[0]
            mode = self._conn.execute('PRAGMA journal_mode').fetchone()[0]
            self._conn.commit()
            self._disk.events.append(('commit', level, mode))
        else:
            self._conn.commit()


class _Disk:
    """What reached the disk, in order: the commits of the connection this test writes on
    and of every one opened from now on, every fsync with the file it was for, and the
    marks a test sets where something trusts what came before."""

    def __init__(self, monkeypatch, db):
        self.events = []
        self.wal = os.path.realpath(db.db_path) + '-wal'
        real_fsync = os.fsync

        def fsync(fd):
            try:
                name = os.path.realpath(os.readlink(f'/proc/self/fd/{fd}'))
            except OSError:
                name = '?'
            self.events.append(('fsync', name))
            return real_fsync(fd)
        monkeypatch.setattr(os, 'fsync', fsync)
        db._local.conn = _Watched(db.conn, self)
        real_connect = dbcrypto.connect
        monkeypatch.setattr(dbcrypto, 'connect', lambda *a, **kw: _Watched(real_connect(*a, **kw), self))

    def mark(self, what):
        self.events.append(('mark', what))

    def commits(self):
        return [ev[1:] for ev in self.events if ev[0] == 'commit']

    def unsynced_at(self, what):
        """The commits that were not on disk yet when `what` happened first."""
        waiting = []
        for ev in self.events:
            if ev[0] == 'commit' and ev[1] < FULL:
                waiting.append(ev)
            elif ev == ('fsync', self.wal):
                waiting = []
            elif ev == ('mark', what):
                return waiting
        raise AssertionError(f'{what} never happened: {self.events}')


def _add(db, n, prefix='e'):
    for i in range(n):
        db.add_audit_entry('alice', f'test.{prefix}{i}', f'{prefix} {i}', '10.0.0.1', 'c1', 'info')


def _watch_anchor(db, disk, monkeypatch):
    real = db._write_audit_anchor

    def write(a):
        disk.mark('anchor')
        return real(a)
    monkeypatch.setattr(db, '_write_audit_anchor', write)


def _wal_sync_fails(monkeypatch, armed=lambda: True):
    """The disk fails each sync of the WAL while armed() says so. Returns the list of the
    syncs it failed."""
    real = os.fsync
    failed = []

    def fsync(fd):
        if os.readlink(f'/proc/self/fd/{fd}').endswith('-wal') and armed():
            failed.append(fd)
            raise OSError(5, 'Input/output error')
        return real(fd)
    monkeypatch.setattr(os, 'fsync', fsync)
    return failed


def _pragmas(conn):
    return (conn.execute('PRAGMA journal_mode').fetchone()[0],
            conn.execute('PRAGMA synchronous').fetchone()[0])


# --- the setting -------------------------------------------------------------------------

def test_the_main_connection_runs_wal_with_synchronous_normal(db):
    # the fixture's file is new: WAL came only after connect(), and NORMAL with it
    assert _pragmas(db.conn) == ('wal', 1)


def test_every_other_connection_to_the_file_runs_normal_too(db, monkeypatch):
    """The setting is per connection: another greenlet's, and the fresh ones the off-hub
    helpers open, get it as well, and stay in WAL."""
    g = gevent.spawn(lambda: _pragmas(db.conn))
    g.join()
    assert g.value == ('wal', 1)
    assert dbcrypto.run_off_hub(_pragmas, db.db_path) == ('wal', 1)

    disk = _Disk(monkeypatch, db)
    assert dbcrypto.run_heavy_write([("INSERT OR REPLACE INTO server_settings (key, value) "
                                      "VALUES ('probe', '1')", ())])
    dbcrypto.run_off_hub(lambda conn: conn.execute("INSERT OR REPLACE INTO server_settings "
                                                   "(key, value) VALUES ('probe', '2')"),
                         db.db_path, commit=True)
    assert disk.commits() == [(1, 'wal'), (1, 'wal')]
    assert db.get_server_setting('probe') == 2


def test_a_file_in_rollback_journal_mode_keeps_full(tmp_path):
    """NORMAL is not safe against a power cut outside WAL: such a file keeps FULL."""
    path = str(tmp_path / 'other.db')
    conn = dbcrypto.connect(path)
    conn.execute('CREATE TABLE t (a)')
    conn.execute('INSERT INTO t VALUES (1)')
    conn.commit()
    assert _pragmas(conn) == ('delete', FULL)
    conn.close()
    again = dbcrypto.connect(path)
    assert _pragmas(again) == ('delete', FULL)
    again.close()
    # one it cannot ask is left as it is
    assert dbcrypto.wal_normal(again) is False
    assert dbcrypto.sync_wal(path) is False           # no WAL, nothing waits


# --- the audit chain ---------------------------------------------------------------------

def test_why_a_checkpoint_lost_under_its_anchor_reads_as_tampering(db):
    """What a power cut that took the last commit after the anchor was written would leave:
    the anchor names a checkpoint the database does not hold, and the check reports it."""
    _add(db, 3)
    cp = db.audit_checkpoint()
    db.conn.execute('DELETE FROM audit_checkpoints WHERE id = ?', (cp['id'],))
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False and res['chain']['checkpoints_missing'] == 1


def test_a_checkpoint_is_on_disk_before_the_anchor_names_it(db, monkeypatch):
    _add(db, 3)
    disk = _Disk(monkeypatch, db)
    _watch_anchor(db, disk, monkeypatch)
    cp = db.audit_checkpoint()
    assert cp and cp['kind'] == 'periodic'
    assert disk.unsynced_at('anchor') == []
    assert disk.commits() == [(1, 'wal')]            # under NORMAL, the case the sync is for


def test_an_audit_entry_is_on_disk_before_the_siem_targets_get_it(db, monkeypatch):
    """And what was committed before it, the action the entry is about, lands with it."""
    from pegaprox.api import siem
    disk = _Disk(monkeypatch, db)
    monkeypatch.setattr(siem, 'enqueue', lambda event: disk.mark('siem'))
    db.save_server_setting('probe', 'what the entry is about')
    _add(db, 1)
    assert disk.unsynced_at('siem') == []
    assert disk.commits() == [(1, 'wal'), (1, 'wal')]


def test_a_prune_is_on_disk_before_the_anchor_moves(db, monkeypatch):
    """The prune commits on a connection of its own, in the threadpool."""
    _add(db, 4)
    disk = _Disk(monkeypatch, db)
    _watch_anchor(db, disk, monkeypatch)
    cp = db.prune_audit_log('9999-12-31T00:00:00')
    assert cp and cp['kind'] == 'prune' and cp['pruned_rows'] == 4
    assert disk.unsynced_at('anchor') == []
    assert disk.commits() == [(1, 'wal')]
    assert db.verify_audit_log_integrity()['intact'] is True


def test_a_checkpoint_whose_sync_failed_leaves_the_anchor_where_it_was(db, monkeypatch):
    _add(db, 2)
    with open(db._audit_anchor_file) as fh:
        before = fh.read()
    real = os.fsync

    def failing(fd):
        if os.readlink(f'/proc/self/fd/{fd}').endswith('-wal'):
            raise OSError(5, 'Input/output error')
        return real(fd)
    monkeypatch.setattr(os, 'fsync', failing)
    with pytest.raises(OSError):
        db.audit_checkpoint()
    with open(db._audit_anchor_file) as fh:
        assert fh.read() == before


def test_a_database_behind_a_symlink_is_synced_where_sqlite_keeps_the_wal(db, monkeypatch, tmp_path):
    """A config folder moved by hand, with a symlink where the database was (before
    PEGAPROX_CONFIG_DIR): SQLite keeps the WAL beside the file the link points at, and a
    sync that looked beside the link found none and synced nothing."""
    _add(db, 3)
    db.conn.close()
    db._local.conn = None
    assert not os.path.exists(db.db_path + '-wal')
    real = tmp_path / 'pegaprox.db'
    os.replace(db.db_path, real)
    os.symlink(real, db.db_path)
    disk = _Disk(monkeypatch, db)
    _watch_anchor(db, disk, monkeypatch)
    assert db.audit_checkpoint()['kind'] == 'periodic'
    assert os.path.exists(f'{real}-wal') and not os.path.exists(db.db_path + '-wal')
    assert disk.unsynced_at('anchor') == []
    assert disk.commits() == [(1, 'wal')]


# --- the field key and the legacy files --------------------------------------------------

def test_a_key_rotation_has_its_rows_on_disk_before_it_goes_on(db, monkeypatch):
    """The new key file is written and synced before the commit; the rows it opens are on
    disk before the anchor is signed again and before the rotation returns."""
    db.save_cluster('c1', {'name': 'c1', 'host': 'h', 'user': 'root@pam', 'pass': 'clusterpw'})
    _add(db, 2)
    disk = _Disk(monkeypatch, db)
    _watch_anchor(db, disk, monkeypatch)
    stats = db.rotate_encryption_key()
    disk.mark('returned')
    assert stats['success'] is True and not stats['errors'], stats
    assert disk.unsynced_at('anchor') == [] and disk.unsynced_at('returned') == []
    assert disk.commits() == [(1, 'wal')]
    assert db.get_cluster('c1')['pass'] == 'clusterpw'


def test_the_legacy_user_file_moves_aside_once_the_accounts_are_on_disk(db, seed, monkeypatch, tmp_path):
    import pegaprox.core.db as dbmod
    legacy = tmp_path / 'users.enc'
    legacy.write_bytes(b'the old store')
    monkeypatch.setattr(dbmod, 'USERS_FILE_ENCRYPTED', str(legacy))
    disk = _Disk(monkeypatch, db)
    seed.user('alice')
    real = os.replace

    def replace(src, dst, *a, **kw):
        if str(src) == str(legacy):
            disk.mark('moved')
        return real(src, dst, *a, **kw)
    monkeypatch.setattr(os, 'replace', replace)
    db._retire_legacy_users_file()
    assert not legacy.exists() and (tmp_path / 'users.enc.migrated').exists()
    assert disk.unsynced_at('moved') == []
    assert disk.commits() and {c[0] for c in disk.commits()} == {1}


# --- site recovery -----------------------------------------------------------------------

def test_the_failover_replay_is_on_disk_before_it_counts_as_done(db, monkeypatch):
    db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid) VALUES ('r100', 'p1', 100)")
    db.execute("INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, "
               "completed_at, details) VALUES ('e1', 'p1', 'emergency', 'completed', "
               "'2026-11-01T10:00:00', '2026-11-01T10:05:00', '{\"100\": {\"success\": true}}')")
    disk = _Disk(monkeypatch, db)
    monkeypatch.setattr(db, '_sr_replay_owed', True)
    assert db.replay_sr_failover_state() == 1
    disk.mark('done')
    assert db.query_one("SELECT failed_over FROM site_recovery_vms WHERE id = 'r100'")['failed_over'] == 'emergency'
    assert disk.unsynced_at('done') == []
    assert disk.commits() == [(1, 'wal')]


def test_a_failover_mark_is_on_disk_before_the_guest_moves(db, monkeypatch):
    """The replication of a failed-over guest holds off by the mark: lost, its next run
    would stop the guest on the DR site and copy the old source over it."""
    from pegaprox.background import site_recovery as sr
    db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid) VALUES ('r100', 'p1', 100)")
    disk = _Disk(monkeypatch, db)
    sr._mark_guest({'id': 'r100', 'vmid': 100}, 'emergency', dr_vmid=9100)
    disk.mark('step')
    row = db.query_one("SELECT failed_over, failed_over_vmid FROM site_recovery_vms WHERE id = 'r100'")
    assert (row['failed_over'], row['failed_over_vmid']) == ('emergency', 9100)
    assert disk.unsynced_at('step') == []
    assert disk.commits() == [(1, 'wal')]


def test_a_failover_mark_that_did_not_reach_the_disk_is_taken_back(db, monkeypatch):
    """The mark is committed when its sync fails. The guest does not move then, and the
    mark goes again: left, it would hold the replication of a guest that is still at the
    source."""
    from pegaprox.background import site_recovery as sr
    from test_sr_per_guest_failover import SRC, TGT, _mgr, _plan, _state
    _plan(db)
    monkeypatch.setitem(sr.cluster_managers, SRC, _mgr(SRC))
    monkeypatch.setitem(sr.cluster_managers, TGT, _mgr(TGT))
    started = []
    monkeypatch.setattr(sr, '_start_replicated_vm',
                        lambda mgr, vmid, vtype='qemu': started.append(vmid) or (True, ''))
    monkeypatch.setattr(sr, '_source_vm_is_running', lambda mgr, vmid: (False, True))
    monkeypatch.setattr(sr, '_target_vmid_exists', lambda mgr, vmid: False)
    monkeypatch.setattr(sr, '_broadcast_progress', lambda *a, **kw: None)
    monkeypatch.setattr(sr, '_fire_webhook', lambda *a, **kw: None)
    # the disk fails the sync of the mark that goes in before the step, nothing else
    marking = []
    real = sr._mark_guest

    def mark(vm, kind, *a, **kw):
        marking.append(kind)
        try:
            return real(vm, kind, *a, **kw)
        finally:
            marking.pop()
    monkeypatch.setattr(sr, '_mark_guest', mark)
    failed = _wal_sync_fails(monkeypatch, armed=lambda: bool(marking and marking[-1]))
    sr.execute_failover('p1', 'emergency', [101], [101])
    assert len(failed) == 1 and started == []
    assert _state(db) == {100: '', 101: '', 102: ''}


# --- HA ----------------------------------------------------------------------------------

def _rec(role_seen):
    return {'url': 'https://pp.example:5000', 'fingerprint': '', 'role_seen': role_seen,
            'epoch_seen': 3, 'group_seen': True, 'joined_at': '2026-10-01T10:00:00+00:00'}


def _instance(env, who, **st):
    """From here on this process is `who`: a state file of its own, the shared database."""
    env.mp.setattr(ha, 'STATE_FILE', str(env.tmp / f'{who[0]}.json'))
    ha.reset_for_tests()
    _write_state(instance_id=who, epoch=3, **st)


def _watch_cv(disk, monkeypatch):
    """A mark at each write of the state file that carries a config version."""
    real = ha._write_locked

    def write(st, strict=None):
        if isinstance(st.get('cv'), dict) and st['cv'].get('hist'):
            disk.mark('cv')
        return real(st, strict=strict)
    monkeypatch.setattr(ha, '_write_locked', write)


def test_a_leader_has_what_a_cv_names_on_disk_before_it_records_the_cv(env, db, seed, monkeypatch):
    _instance(env, A, role='active', members={B: _rec('standby')})
    disk = _Disk(monkeypatch, db)
    _watch_cv(disk, monkeypatch)
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    assert snap['cv'] == [3, 1]
    assert disk.unsynced_at('cv') == []
    assert disk.commits() and {c[0] for c in disk.commits()} == {1}


def test_a_member_has_the_rows_of_a_snapshot_on_disk_before_it_records_their_cv(env, db, seed, monkeypatch):
    _instance(env, A, role='active', members={B: _rec('standby')})
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _instance(env, B, role='standby', source=A, members={A: _rec('active')}, cv={'joined': True})
    disk = _Disk(monkeypatch, db)
    _watch_cv(disk, monkeypatch)
    ha.apply_snapshot(snap)
    assert ha.cv_entry() == snap['hist'][-1]
    assert disk.unsynced_at('cv') == []
    assert disk.commits() == [(1, 'wal')]


def test_a_step_of_a_node_recovery_is_on_disk_before_it_is_taken(env, db, monkeypatch):
    _instance(env, A, role='active', members={B: _rec('standby')})
    disk = _Disk(monkeypatch, db)
    ha.recovery_step('3.aaaaaaaaaaaa.0001', 'c1', 'pve1', 'fence')
    disk.mark('fence')
    rows = [tuple(r) for r in db.conn.execute('SELECT step, done FROM ha_recovery_journal')]
    assert rows == [('fence', 0)]
    assert disk.unsynced_at('fence') == []
    assert disk.commits() == [(1, 'wal')]


def test_a_member_whose_sync_to_disk_fails_finishes_the_apply_and_records_no_cv(env, db, seed, monkeypatch):
    """The rows are committed when the sync fails, so what follows from them still happens:
    here the sessions of a user whose password the leader reset end. Only the cv is not
    recorded, the next sync compares row by row, and the sync status says why."""
    _instance(env, A, role='active', members={B: _rec('standby')})
    seed.user('alice')
    snap = _wire(ha.build_snapshot())
    _instance(env, B, role='standby', source=A, members={A: _rec('active')}, cv={'joined': True})
    # what this member holds of alice is not what the leader sends
    db.conn.execute("UPDATE users SET password_hash = 'older' WHERE username = 'alice'")
    db.conn.commit()
    held = ha.cv_entry()
    ended = []
    monkeypatch.setattr(ha, '_end_sessions', ended.append)
    failed = _wal_sync_fails(monkeypatch, armed=lambda: not failed)
    try:
        summary = ha.apply_snapshot(snap)
    except OSError:
        summary = None
    assert len(failed) == 1
    assert ended == [['alice']]
    assert summary and any('not synced to disk' in p for p in summary['file_errors']), summary
    assert ha.cv_entry() == held != snap['hist'][-1]


def _stamp(db):
    return db.conn.execute("SELECT last_run FROM scheduled_tasks WHERE id = 't1'").fetchone()[0]


def _zoned_leader(env, db):
    _instance(env, A, role='active', members={B: _rec('standby')}, timezone='Europe/Vienna')
    db.conn.execute("INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, last_run) "
                    "VALUES ('t1', 'c1', 'hourly', 'start', '{}', '2026-10-05T10:15:10')")
    db.conn.commit()


def test_the_stamps_a_new_zone_moved_are_on_disk_before_the_state_file_names_it(env, db, monkeypatch):
    """A power cut that kept the state file and took the stamps would leave them in the old
    zone under the new one, and after a first change nothing says so: an hourly schedule
    would skip the hours between the two zones, or fire again."""
    _zoned_leader(env, db)
    disk = _Disk(monkeypatch, db)
    real = ha._write_locked

    def write(st, strict=None):
        if st.get('timezone') == 'America/New_York':
            disk.mark('zone')
        return real(st, strict=strict)
    monkeypatch.setattr(ha, '_write_locked', write)
    assert ha.set_group_timezone('America/New_York') is True
    assert _stamp(db) == '2026-10-05T04:15:10'
    assert disk.unsynced_at('zone') == []
    assert disk.commits() == [(1, 'wal')]


def test_a_zone_whose_moved_stamps_cannot_be_synced_stays_as_it_was(env, db, monkeypatch):
    _zoned_leader(env, db)
    failed = _wal_sync_fails(monkeypatch, armed=lambda: not failed)
    with pytest.raises(ha.StateNotWritten):
        ha.set_group_timezone('America/New_York')
    assert len(failed) == 1
    assert ha.group_timezone() == 'Europe/Vienna'
    assert _stamp(db) == '2026-10-05T10:15:10'
