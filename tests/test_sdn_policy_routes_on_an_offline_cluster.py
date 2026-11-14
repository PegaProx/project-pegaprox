"""SDN route maps and prefix lists on a cluster that is not connected answer 503 (api/datacenter.py).

_sdn_crud_resource answered (None, error) when get_connected_manager refused, and every
route map and prefix list route handed that pair to Flask, which made a TypeError 500 of
it ("did not return a valid response"). The sibling SDN routes answer the 503 with
offline and connection_error; these do the same now, and an unknown cluster is a 404.
"""
import pytest

CLUSTER = 'cluster_1'
BASE = f'/api/clusters/{CLUSTER}/datacenter/sdn'
ROUTES = [
    ('get', 'routemaps', None), ('post', 'routemaps', {'routemap': 'rm1'}),
    ('put', 'routemaps/rm1', {'action': 'permit'}), ('delete', 'routemaps/rm1', None),
    ('get', 'prefixlists', None), ('post', 'prefixlists', {'prefixlist': 'pl1'}),
    ('put', 'prefixlists/pl1', {'entries': ''}), ('delete', 'prefixlists/pl1', None),
]
IDS = [f'{m}-{p}' for m, p, _b in ROUTES]


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _call(client, method, path, body):
    kw = {'json': body} if body is not None else {}
    return getattr(client, method)(f'{BASE}/{path}', **kw)


@pytest.mark.parametrize('method,path,body', ROUTES, ids=IDS)
def test_a_cluster_that_is_not_connected_is_a_503(api, admin, method, path, body):
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = False
    m.connection_error = 'Failed to connect to any Proxmox host'
    api.set_manager(CLUSTER, m)
    r = _call(admin, method, path, body)
    assert r.status_code == 503, r.get_data(as_text=True)[:300]
    assert r.get_json() == {'error': 'Cluster not connected', 'offline': True,
                            'connection_error': 'Failed to connect to any Proxmox host'}
    m._api_get.assert_not_called()
    m._api_post.assert_not_called()


@pytest.mark.parametrize('method,path,body', ROUTES, ids=IDS)
def test_an_unknown_cluster_is_a_404(api, admin, method, path, body):
    # check_cluster_access lets an admin through to the missing cluster; the helper says so
    r = _call(admin, method, path, body)
    assert r.status_code == 404, r.get_data(as_text=True)[:300]
