"""The status of a storage balancing group that does not exist is a 404 (api/storage.py).

The `sc_config = None` that starts the lookup sat at the end of a comment line, so for an
id that is not there (or a cluster without any group) the route read a name it had never
set and answered 500 with an UnboundLocalError instead of "Storage cluster not found".
"""
import pytest

import pegaprox.api.storage as storage

CLUSTER = 'cluster_1'


@pytest.fixture
def admin(api, seed):
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    api.set_manager(CLUSTER, m)
    yield api.as_user(seed.user('sc-admin', role='admin')), m
    storage.storage_clusters_config.pop(CLUSTER, None)


@pytest.mark.parametrize('groups', [None, [], [{'id': 'other', 'name': 'pool', 'storages': ['a', 'b']}]],
                         ids=['no-groups-for-the-cluster', 'empty-list', 'another-group'])
def test_an_unknown_group_is_a_404(admin, groups):
    client, m = admin
    storage.storage_clusters_config.pop(CLUSTER, None)
    if groups is not None:
        storage.storage_clusters_config[CLUSTER] = {'clusters': groups}
    r = client.get(f'/api/clusters/{CLUSTER}/storage-clusters/nonexistent/status')
    assert r.status_code == 404, r.get_data(as_text=True)[:300]
    assert r.get_json() == {'error': 'Storage cluster not found'}
    m._create_session.assert_not_called()
