"""A snapshot policy created with "keep last 0" keeps 0, the same as an edit of it.

The create form sends 0 when "keep last" is cleared. The create route turned that 0 into 7 with `or 7`, so the
operator asked for no count and got 7, while the edit form stored 0 for the same input.
"""
import pytest

PID = 'abcdef012345'
URL = '/api/clusters/cluster_1/snapshot-policies'
BODY = {'name': 'nightly', 'target_type': 'tag', 'target_value': 'prod', 'schedule': 'daily', 'schedule_at': '03:00'}


@pytest.fixture
def admin(api, seed):
    """An admin on a cluster whose one guest carries the tag the policies target."""
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.get_vm_resources.return_value = [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'prod'}]
    api.set_manager('cluster_1', m)
    return api.as_user(seed.user('root', role='admin'))


def _create(admin, **extra):
    r = admin.post(URL, json={**BODY, **extra})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['policy']


def _kept_in_db(db, pid):
    return db.conn.execute('SELECT retention_count FROM snapshot_policies WHERE id=?', (pid,)).fetchone()['retention_count']


def _edit_stored_policy(admin, db, value):
    """Store a policy as the edit route sees it, then send the edit with the keep count."""
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, enabled, "
                    "created_by, created_at) VALUES (?, 'cluster_1', 'edited', 'tag', 'prod', 'daily', 1, 'root', "
                    "'2026-01-01T00:00:00')", (PID,))
    db.conn.commit()
    return admin.put(f'{URL}/{PID}', json={'retention_count': value})


def _outcome(send):
    """What the caller sees: a raised error, or the status code of the answer."""
    try:
        r = send()
    except Exception as e:
        return ('raised', type(e).__name__)
    return ('status', r.status_code)


def test_a_policy_created_with_keep_0_keeps_0(admin, db):
    """With "keep last" cleared on create, the policy shows 0 and stores 0, not a silent 7."""
    pol = _create(admin, retention_count=0)
    assert pol['retention_count'] == 0
    assert _kept_in_db(db, pol['id']) == 0


def test_a_policy_created_without_a_keep_count_keeps_the_default_7(admin, db):
    """A policy created without any keep count still keeps the last 7, as it always has."""
    pol = _create(admin)
    assert pol['retention_count'] == 7
    assert _kept_in_db(db, pol['id']) == 7


def test_a_policy_created_with_an_empty_keep_count_keeps_the_default_7(admin, db):
    """An empty keep count on create is a field left out: the policy keeps the last 7, as before."""
    assert _create(admin, retention_count='')['retention_count'] == 7


def test_a_policy_created_with_keep_5_keeps_5(admin, db):
    """A keep count of 5 on create is shown and stored as 5."""
    pol = _create(admin, retention_count=5)
    assert pol['retention_count'] == 5
    assert _kept_in_db(db, pol['id']) == 5


def test_a_negative_keep_count_on_create_is_stored_as_0(admin, db):
    """A negative keep count on create is stored as 0, so the policy never holds a negative number."""
    pol = _create(admin, retention_count=-3)
    assert pol['retention_count'] == 0
    assert _kept_in_db(db, pol['id']) == 0


def test_a_keep_count_typed_as_text_is_refused_the_same_way_on_create_and_edit(admin, db):
    """Text in the keep count is refused alike on create and on edit, never stored as a guessed number."""
    created = _outcome(lambda: admin.post(URL, json={**BODY, 'retention_count': 'abc'}))
    edited = _outcome(lambda: _edit_stored_policy(admin, db, 'abc'))
    assert created == edited
    assert created != ('status', 200)
    assert db.conn.execute("SELECT COUNT(*) FROM snapshot_policies WHERE name='nightly'").fetchone()[0] == 0


@pytest.mark.parametrize('value', [0, 1, 5, 30])
def test_create_and_edit_show_the_same_keep_count_for_every_value(admin, db, value):
    """Whatever keep count the form sends, the policy shows that same count after create and after an edit."""
    created = _create(admin, retention_count=value)['retention_count']
    edited = _edit_stored_policy(admin, db, value).get_json()['policy']['retention_count']
    assert created == edited == value
