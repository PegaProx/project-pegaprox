"""An edit of a snapshot policy with a schedule_day that is no number keeps the stored day.

The edit route put 'schedule_day=?' into the UPDATE before int() of the value threw, and the
except left the placeholder without its value. sqlite then refused the statement, the route
answered 500 and nothing of the edit was saved. The create route reads such a day as 1; the
edit now keeps what is stored, as it does for an empty keep value.

MK Nov 2026
"""
import pytest

PID = 'abcdef012345'
URL = '/api/clusters/cluster_1/snapshot-policies'


@pytest.fixture
def admin(api, seed):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.get_vm_resources.return_value = [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'prod'}]
    api.set_manager('cluster_1', m)
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def stored(db):
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, "
                    "schedule_day, enabled, created_by, created_at) VALUES (?, 'cluster_1', 'old', 'tag', 'prod', "
                    "'monthly', 5, 1, 'root', '2026-01-01T00:00:00')", (PID,))
    db.conn.commit()

    def row():
        return dict(db.conn.execute('SELECT name, schedule_day FROM snapshot_policies WHERE id=?', (PID,)).fetchone())
    return row


@pytest.mark.parametrize('day', [None, '', 'x', [3]])
def test_a_day_that_is_no_number_keeps_the_stored_one_and_the_rest_is_saved(admin, stored, day):
    r = admin.put(f'{URL}/{PID}', json={'name': 'renamed', 'schedule_day': day})
    assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
    assert r.get_json()['policy']['schedule_day'] == 5
    assert stored() == {'name': 'renamed', 'schedule_day': 5}


@pytest.mark.parametrize('day,kept', [('12', 12), (31, 31), (40, 31), (0, 1)])
def test_a_day_number_is_stored_within_the_month(admin, stored, day, kept):
    r = admin.put(f'{URL}/{PID}', json={'schedule_day': day})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert stored()['schedule_day'] == kept


def test_a_bad_day_alone_is_nothing_to_update(admin, stored):
    r = admin.put(f'{URL}/{PID}', json={'schedule_day': 'x'})
    assert r.status_code == 400 and r.get_json()['error'] == 'nothing to update'
    assert stored() == {'name': 'old', 'schedule_day': 5}
