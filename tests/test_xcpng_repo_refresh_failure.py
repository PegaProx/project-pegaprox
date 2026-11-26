"""A package list refresh on an XCP-ng host that failed is no success.

POST /api/clusters/<id>/nodes/<node>/repos/refresh runs `yum makecache` on an XCP-ng host
through refresh_node_apt, which answers {'success': False, 'error': ...} when yum or the
SSH login fails. The route dropped that answer and said "Package list refresh started",
and the node page showed it as a green toast.
"""
import pytest

CID = 'cluster_1'
ROUTE = f'/api/clusters/{CID}/nodes/xcp1/repos/refresh'


@pytest.fixture
def admin(api, seed):
    def as_admin(result):
        m = api.make_fake_manager(CID, cluster_type='xcpng', refresh_node_apt=result)
        api.set_manager(CID, m)
        return m, api.as_user(seed.user('root', role='admin'))
    return as_admin


def test_a_failed_refresh_is_an_error(admin):
    m, c = admin({'success': False, 'error': 'yum makecache failed'})
    r = c.post(ROUTE)
    assert r.status_code == 500, r.get_data(as_text=True)
    assert r.get_json()['error'] == 'yum makecache failed'
    m.refresh_node_apt.assert_called_once_with('xcp1')


def test_a_refresh_that_ran_is_reported(admin):
    m, c = admin({'success': True, 'task': None})
    r = c.post(ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True
