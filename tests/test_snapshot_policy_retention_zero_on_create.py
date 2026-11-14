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


# --- one parser for create and edit -----------------------------------------------------

KEYS = ['retention_count', 'retention_days']
NOT_A_WHOLE_NUMBER = ['abc', '3.5', 2.5, True, False, [], {}, [3]]


def _store(db, count=4, days=9):
    """A stored policy with a keep count and days of its own, for an edit to change or leave."""
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, "
                    "retention_count, retention_days, enabled, created_by, created_at) VALUES "
                    "(?, 'cluster_1', 'stored', 'tag', 'prod', 'daily', ?, ?, 1, 'root', '2026-01-01T00:00:00')",
                    (PID, count, days))
    db.conn.commit()


def _stored(db):
    row = db.conn.execute('SELECT name, retention_count, retention_days FROM snapshot_policies WHERE id=?',
                          (PID,)).fetchone()
    return (row['name'], row['retention_count'], row['retention_days'])


@pytest.mark.parametrize('key', KEYS)
@pytest.mark.parametrize('value', NOT_A_WHOLE_NUMBER, ids=repr)
def test_a_keep_value_that_is_no_whole_number_is_a_400_on_create(admin, db, key, value):
    """Create answers 400 naming the field and stores nothing, not a 500 or a guessed number."""
    r = admin.post(URL, json={**BODY, key: value})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert key in r.get_json()['error']
    assert db.conn.execute("SELECT COUNT(*) FROM snapshot_policies WHERE name='nightly'").fetchone()[0] == 0


@pytest.mark.parametrize('key', KEYS)
@pytest.mark.parametrize('value', NOT_A_WHOLE_NUMBER, ids=repr)
def test_a_keep_value_that_is_no_whole_number_is_a_400_on_edit_and_changes_nothing(admin, db, key, value):
    """Edit answers 400 naming the field, and the rest of the same edit is not stored either."""
    _store(db)
    r = admin.put(f'{URL}/{PID}', json={'name': 'renamed', key: value})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert key in r.get_json()['error']
    assert _stored(db) == ('stored', 4, 9)


@pytest.mark.parametrize('value', [None, ''], ids=repr)
def test_an_empty_keep_value_on_edit_keeps_the_stored_one(admin, db, value):
    """An edit that sends the keep fields empty changes the rest and leaves the stored count and days."""
    _store(db)
    r = admin.put(f'{URL}/{PID}', json={'name': 'renamed', 'retention_count': value, 'retention_days': value})
    assert r.status_code == 200, r.get_data(as_text=True)
    pol = r.get_json()['policy']
    assert (pol['name'], pol['retention_count'], pol['retention_days']) == ('renamed', 4, 9)
    assert _stored(db) == ('renamed', 4, 9)


@pytest.mark.parametrize('key,left', [('retention_count', ('stored', 0, 9)), ('retention_days', ('stored', 4, 0))])
def test_a_negative_keep_value_on_edit_is_stored_as_0_like_on_create(admin, db, key, left):
    """Edit stores a negative count or age as 0, the same as create does."""
    _store(db)
    r = admin.put(f'{URL}/{PID}', json={key: -3})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['policy'][key] == 0
    assert _stored(db) == left


@pytest.mark.parametrize('value,kept', [('', 0), (None, 0), (-2, 0), ('5', 5), (5.0, 5), (12, 12)], ids=repr)
def test_the_keep_days_on_create_take_the_same_rules(admin, db, value, kept):
    """The days take the same rules as the count on create, with 0 as their default."""
    pol = _create(admin, retention_days=value)
    assert pol['retention_days'] == kept
    assert db.conn.execute('SELECT retention_days FROM snapshot_policies WHERE id=?',
                           (pol['id'],)).fetchone()['retention_days'] == kept


@pytest.mark.parametrize('value,kept', [('5', 5), (5.0, 5), (' 6 ', 6)], ids=repr)
def test_a_whole_number_sent_as_text_or_with_a_zero_fraction_is_still_taken(admin, db, value, kept):
    """A count sent as "5" or 5.0 is taken on create and on edit, as before."""
    assert _create(admin, retention_count=value)['retention_count'] == kept
    _store(db)
    assert admin.put(f'{URL}/{PID}', json={'retention_count': value}).get_json()['policy']['retention_count'] == kept
