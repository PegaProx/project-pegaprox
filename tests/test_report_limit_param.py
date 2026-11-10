"""?limit= on the top-VM rankings and the migration history is a row count, read with care.

The three routes took int() of it as it came: a word was a 500 from the route itself, and a
negative number went into the slice, so ?limit=-1 answered every row but the last one. They
read it through bounded_limit now, like the other list routes: what is no positive whole
number is the default.
"""
import types

import pytest

CID = 'cluster_1'
GUESTS = [{'vmid': 100 + i, 'type': 'qemu', 'status': 'running', 'node': 'pve1', 'name': f'g{i}',
           'cpu': (i + 1) / 10, 'mem': i + 1, 'maxmem': 10} for i in range(3)]
TOP_VMS = [f'/api/clusters/{CID}/reports/top-vms', '/api/reports/top-vms']


@pytest.fixture
def admin(api, seed):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.config = types.SimpleNamespace(name='c1')
    m.get_vm_resources.return_value = [dict(g) for g in GUESTS]
    api.set_manager(CID, m)
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def history(admin):
    from pegaprox.api.history import log_migration
    for vmid in (100, 101, 102):
        log_migration(CID, vmid, f'g{vmid}', 'qemu', 'pve1', 'pve2', 'live', 'completed', user='root')
    return admin


@pytest.mark.parametrize('route', TOP_VMS)
@pytest.mark.parametrize('limit', ['abc', '1.5', ''])
def test_a_limit_that_is_no_number_ranks_with_the_default(admin, route, limit):
    r = admin.get(f'{route}?metric=cpu&limit={limit}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [v['vmid'] for v in r.get_json()] == [102, 101, 100]


@pytest.mark.parametrize('route', TOP_VMS)
@pytest.mark.parametrize('limit', ['-1', '0'])
def test_a_limit_below_one_drops_no_guest(admin, route, limit):
    r = admin.get(f'{route}?metric=cpu&limit={limit}')
    assert [v['vmid'] for v in r.get_json()] == [102, 101, 100]


@pytest.mark.parametrize('route', TOP_VMS)
def test_a_limit_still_cuts_the_ranking(admin, route):
    assert [v['vmid'] for v in admin.get(f'{route}?metric=cpu&limit=2').get_json()] == [102, 101]


@pytest.mark.parametrize('limit', ['abc', '-1', '0'])
def test_the_migration_history_keeps_every_row_for_a_limit_it_cannot_use(history, limit):
    r = history.get(f'/api/migration-history?cluster_id={CID}&limit={limit}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sorted(m['vmid'] for m in r.get_json()) == [100, 101, 102]


def test_the_migration_history_still_takes_a_limit(history):
    assert len(history.get(f'/api/migration-history?cluster_id={CID}&limit=2').get_json()) == 2
