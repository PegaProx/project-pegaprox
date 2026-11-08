"""What keeps a member passive when its state file is gone, and what makes the state
file outlast a power cut (#625, stage two S0).

  * MEMBER_MARKER next to the state file while the instance is in a group, and
    MEMBER_SETTING in its database, a local setting that never travels: not with a
    snapshot, not in a config backup. With the state file gone, either one keeps the
    instance a passive standby, as the .pre-ha key backups did for a joined instance
    only (F2). Both go as soon as the instance is standalone again.
  * The state file is fsynced, renamed into place, and then its directory is fsynced:
    without the last step a power cut can bring back the file from before.
  * The reset of stuck DR plans at boot is recover_orphan_runs, behind
    ha.is_active(); main() no longer has a copy that wrote on the role read once.

MK Oct 2026
"""
import ast
import inspect
import io
import json
import os
import stat

import pytest

from pegaprox.core import ha
from test_ha_core import (env, _fake_active, _key_next_to_the_db, _write_state, _wire,  # noqa: F401
                          _set, _settings, _be_active, _be_standby, A, B, C, ZK)
from test_ha_api import _admin, ADMIN_PW


def _marker():
    return os.path.join(os.path.dirname(ha.STATE_FILE), ha.MEMBER_MARKER)


def _in_group(instance=B):
    _write_state(role='standby', instance_id=instance, epoch=3,
                 members={A: {'url': 'https://pp1.example:5000', 'role_seen': 'active',
                              'epoch_seen': 3, 'group_seen': True}}, source=A)


def _gone():
    os.remove(ha.STATE_FILE)
    ha.reset_for_tests()


# --- the marker file ------------------------------------------------------------------

def test_a_member_whose_state_file_is_gone_stays_passive(env):
    """The instance that was active from the start never joined, so it has no .pre-ha
    backup: without its state file it came up as a fresh standalone and acted."""
    _write_state(role='active', instance_id=A, epoch=3,
                 members={B: {'url': 'https://pp2.example:5000', 'role_seen': 'standby'}})
    ha._update(interval=60)
    assert os.path.exists(_marker())

    _gone()

    assert ha.role() == 'standby' and not ha.is_active()
    assert 'missing' in ha.public_status()['broken'] and 'belongs to a group' in ha.public_status()['broken']
    with pytest.raises(ha.HaError):
        ha.promote()
    assert not os.path.exists(ha.STATE_FILE)


def test_unpair_takes_the_marker_along(env):
    _in_group()
    ha._update(interval=60)
    assert os.path.exists(_marker())

    assert ha.unpair() == 'standby'

    assert not os.path.exists(_marker())
    _gone()
    assert ha.role() == 'standalone' and ha.public_status()['broken'] == ''


def test_unpair_is_the_way_out_of_a_missing_state_file(env):
    _in_group()
    ha._update(interval=60)
    _gone()
    assert ha.role() == 'standby'

    ha.unpair()
    ha.reset_for_tests()

    assert ha.role() == 'standalone' and ha.is_active() and not os.path.exists(_marker())


def test_a_standalone_writes_no_marker(env):
    ha.create_pairing_code('https://pp1.example:5000', '')
    ha._update(interval=60)
    assert os.path.exists(ha.STATE_FILE) and not os.path.exists(_marker())


def test_the_marker_is_private(env):
    old = os.umask(0)
    try:
        _in_group()
        ha._update(interval=60)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(_marker()).st_mode) == 0o600
    with open(_marker()) as fh:
        assert fh.read().strip() == B


def test_pairing_marks_both_sides(env, db, monkeypatch):
    # the active
    code, _ = ha.create_pairing_code('https://pp1.example:5000', '')
    ha.accept_pairing(ha.decode_code(code)['secret'], B, 'https://pp2.example', '', ZK)
    me = ha.instance_id()
    assert os.path.exists(_marker())
    assert db.get_server_setting(ha.MEMBER_SETTING) == me

    # the standby: another state file, the same database
    os.remove(ha.STATE_FILE)
    os.remove(_marker())
    db.save_server_setting(ha.MEMBER_SETTING, '')
    ha.reset_for_tests()
    _key_next_to_the_db(env)
    with open(ha.AES_KEY_FILE, 'wb') as fh:
        fh.write(db.aes_key)
    _fake_active(monkeypatch, 's' * 43, os.urandom(32))
    me = ha.instance_id()

    ha.join(ha.encode_code('https://pp1.example:5000', '', 's' * 43, A), 'https://pp2.example', '')

    assert ha.role() == 'standby' and os.path.exists(_marker())
    assert db.get_server_setting(ha.MEMBER_SETTING) == me


# --- the database marker, at boot ---------------------------------------------------------

def test_a_member_paired_before_the_markers_gets_them_at_boot(env, db):
    _in_group()                                   # written by hand: no marker yet
    assert not os.path.exists(_marker())

    assert ha.check_markers_at_boot() == 'member'

    assert os.path.exists(_marker())
    assert db.get_server_setting(ha.MEMBER_SETTING) == B


def test_a_restored_database_without_its_state_file_stays_passive(env, db):
    """A member's database restored onto a fresh config directory: no state file, no
    marker file, no key backup, only the database knows."""
    db.save_server_setting(ha.MEMBER_SETTING, B)

    assert ha.check_markers_at_boot() == 'missing'

    assert ha.role() == 'standby' and not ha.is_active()
    assert 'as its database says' in ha.public_status()['broken']
    with pytest.raises(ha.HaError):
        ha._update(interval=60)
    assert not os.path.exists(ha.STATE_FILE)

    # unpair is the way out, and the next boot drops the database marker
    ha.unpair()
    ha.reset_for_tests()
    assert ha.check_markers_at_boot() == 'standalone'
    assert db.get_server_setting(ha.MEMBER_SETTING) == ''
    assert ha.role() == 'standalone'


def test_a_standalone_that_never_paired_writes_nothing_at_boot(env, db):
    assert ha.check_markers_at_boot() == 'standalone'
    assert db.get_server_setting(ha.MEMBER_SETTING) is None
    assert not os.path.exists(ha.STATE_FILE) and not os.path.exists(_marker())


def test_a_broken_state_file_is_left_as_it_is_at_boot(env, db):
    with open(ha.STATE_FILE, 'w') as fh:
        fh.write('{"role": "act')
    assert ha.check_markers_at_boot() == 'broken'
    assert db.get_server_setting(ha.MEMBER_SETTING) is None


def test_the_database_marker_never_travels(env, db, seed):
    _be_active()
    _set(db, ha.MEMBER_SETTING, json.dumps(A))
    snap = _wire(ha.build_snapshot())
    assert ha.MEMBER_SETTING not in {r[0] for r in snap['tables']['server_settings']['rows']}

    _set(db, ha.MEMBER_SETTING, json.dumps(B))
    _be_standby()
    snap['tables']['server_settings']['rows'].append([ha.MEMBER_SETTING, json.dumps(A)])
    ha.apply_snapshot(snap)

    assert _settings(db)[ha.MEMBER_SETTING] == json.dumps(B)


def test_main_reads_the_markers_before_the_boot_check():
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.main)).body[0]

    def lines(name):
        return [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call)
                and getattr(n.func, 'attr', None) == name]
    assert len(lines('check_markers_at_boot')) == 1
    assert lines('check_markers_at_boot')[0] < lines('check_peer_at_boot')[0]
    assert lines('ensure_db_encrypted')[0] < lines('check_markers_at_boot')[0]


# --- standalone again: the database marker goes at once ---------------------------------

def _active_of(*members):
    _write_state(role='active', instance_id=A, epoch=3,
                 members={m: {'url': f'https://{m[:3]}.example:5000', 'role_seen': 'standby',
                              'epoch_seen': 3, 'group_seen': True} for m in members})


@pytest.mark.parametrize('how', ['unpair', 'last-member-left', 'last-member-removed'])
def test_an_active_that_is_standalone_again_drops_the_database_marker(env, db, how):
    """The unpair route restarts only a former standby, and only the next boot dropped
    the marker, maybe weeks later. A state file removed meanwhile, or a config backup
    taken meanwhile, still said "member". The same for an active whose last member left
    the group or was removed from it."""
    _active_of(B)
    assert ha.check_markers_at_boot() == 'member'

    if how == 'unpair':
        assert ha.unpair() == 'active'
    elif how == 'last-member-left':
        assert ha.forget_peer(B) == 'member'
    else:
        ha.remove_member(B, shut_down=True)

    assert ha.role() == 'standalone'
    assert db.get_server_setting(ha.MEMBER_SETTING) == ''
    _gone()
    assert ha.check_markers_at_boot() == 'standalone' and ha.is_active()


def test_a_member_still_in_its_group_keeps_the_database_marker(env, db):
    """Counterproof: an active one of whose two members left, and a standby whose last
    member left (it stays passive in its group until it is unpaired or promoted)."""
    _active_of(B, C)
    ha.check_markers_at_boot()
    assert ha.forget_peer(B) == 'member'
    assert ha.role() == 'active' and db.get_server_setting(ha.MEMBER_SETTING) == A

    _in_group(B)
    ha.check_markers_at_boot()
    assert ha.forget_peer(A) == 'member'
    assert ha.role() == 'standby' and db.get_server_setting(ha.MEMBER_SETTING) == B


# --- the config backup ------------------------------------------------------------------

BACKUP_PW = 'a-backup-password'


def _backup(admin):
    r = admin.post('/api/config/backup', json={'user_password': ADMIN_PW, 'backup_password': BACKUP_PW})
    assert r.status_code == 200, r.data
    return r.get_data()


def _restore(admin, blob, mode):
    r = admin.post('/api/config/restore', content_type='multipart/form-data',
                   data={'user_password': ADMIN_PW, 'backup_password': BACKUP_PW, 'mode': mode,
                         'backup_file': (io.BytesIO(blob), 'pp.pegabackup')})
    assert r.status_code == 200, r.data
    assert r.get_json()['restored'].get('server_settings') is True, r.get_json()


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_members_config_backup_leaves_a_standalone_standalone(api, seed, db, mode):
    """The backup took load_server_settings() whole, the member marker with it, and the
    restore wrote it back. A standalone that restored a member's backup came up passive
    at its next start, an update days later say, as if its state file were lost."""
    admin = _admin(api, seed)
    db.save_server_setting(ha.MEMBER_SETTING, A)                # the member's database
    blob = _backup(admin)
    from pegaprox.api.settings import _decrypt_backup
    exported = json.loads(_decrypt_backup(blob, BACKUP_PW))['server_settings']
    assert exported and ha.MEMBER_SETTING not in exported

    # the box it goes to: a standalone, nothing in its database
    db.conn.execute('DELETE FROM server_settings WHERE key = ?', (ha.MEMBER_SETTING,))
    db.conn.commit()
    ha.reset_for_tests()
    assert ha.check_markers_at_boot() == 'standalone'

    _restore(admin, blob, mode)

    ha.reset_for_tests()                                        # its next start
    assert ha.check_markers_at_boot() == 'standalone' and ha.is_active()
    assert db.get_server_setting(ha.MEMBER_SETTING) is None


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_that_still_carries_the_marker_is_restored_without_it(api, seed, db, mode):
    """A backup from before the export left the marker out: the restore skips it, and
    a member that restores it keeps its own."""
    from pegaprox.api.settings import _encrypt_backup
    admin = _admin(api, seed)
    old = {'version': '1.2.0', 'export_date': '2026-09-30T10:00:00', 'exported_by': 'root',
           'server_settings': {ha.MEMBER_SETTING: A, 'login_max_attempts': 7}}
    blob = _encrypt_backup(json.dumps(old), BACKUP_PW)

    _restore(admin, blob, mode)

    assert db.get_server_setting('login_max_attempts') == 7       # the rest goes in
    assert db.get_server_setting(ha.MEMBER_SETTING) is None
    ha.reset_for_tests()
    assert ha.check_markers_at_boot() == 'standalone' and ha.is_active()

    db.save_server_setting(ha.MEMBER_SETTING, B)
    _restore(admin, blob, mode)
    assert db.get_server_setting(ha.MEMBER_SETTING) == B


# --- the directory goes to disk too -----------------------------------------------------

def test_the_state_files_directory_is_synced_after_the_rename(env, monkeypatch):
    steps = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        steps.append(('fsync-dir' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'fsync-file',
                      os.path.realpath(f'/proc/self/fd/{fd}')))
        return real_fsync(fd)

    def replace(src, dst):
        steps.append(('replace', os.path.realpath(dst)))
        return real_replace(src, dst)
    monkeypatch.setattr(os, 'fsync', fsync)
    monkeypatch.setattr(os, 'replace', replace)

    ha._update(interval=60)

    folder = os.path.realpath(os.path.dirname(ha.STATE_FILE))
    kinds = [s[0] for s in steps]
    assert kinds[:3] == ['fsync-file', 'replace', 'fsync-dir']
    assert steps[1][1] == os.path.realpath(ha.STATE_FILE) and steps[2][1] == folder


def test_a_directory_that_cannot_be_synced_costs_no_commit(env, monkeypatch):
    real_fsync = os.fsync

    def no_dir_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(22, 'Invalid argument')
        return real_fsync(fd)
    monkeypatch.setattr(os, 'fsync', no_dir_sync)

    ha._update(interval=60)

    assert ha.public_status()['interval'] == 60
    ha.reset_for_tests()
    assert ha.public_status()['interval'] == 60


# --- the DR plans at boot ----------------------------------------------------------------

def test_main_resets_no_dr_plan_itself():
    """recover_orphan_runs (start_heartbeat) resets the stuck plans and asks
    ha.is_active() right before it writes, see tests/test_ha_loop_gates.py. A second
    reset in main() wrote on the role it read once, before the HA loop ever ran."""
    from pegaprox import app as app_mod
    src = inspect.getsource(app_mod.main)
    assert 'site_recovery_plans' not in src
    fn = ast.parse(src).body[0]
    guarded = [n for n in fn.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'not standby']
    assert guarded and 'start_heartbeat' in ast.unparse(guarded[0])
