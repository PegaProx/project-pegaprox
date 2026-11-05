"""Malformed optional PBS usage metrics cannot make a successful datastore read."""

import pytest

from test_pbs_datastore_list_upstream_errors import PATH, admin, pbs  # noqa: F401 (fixtures)


@pytest.mark.parametrize('metric', ['used', 'total', 'avail'])
@pytest.mark.parametrize('value', [True, False, 'invalid', '1024', [], {}, 1.5, 0.0, -1, 1 << 64, 1 << 1000,
                                  float('nan'), float('inf'), float('-inf')])
def test_malformed_usage_metric_is_an_upstream_error(admin, pbs, metric, value):
    """A present malformed metric fails before optional enrichment is attempted."""
    pbs.get_datastores.return_value = {'data': [{'name': 'backup'}]}
    pbs.get_datastore_usage.return_value = {'data': [{'store': 'backup', metric: value}]}

    response = admin.get(PATH)

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'
    pbs.get_gc_jobs.assert_not_called()
    pbs.get_datastore_status.assert_not_called()


@pytest.mark.parametrize('metrics', [
    {},
    {'used': None, 'total': None, 'avail': None},
    {'used': 0, 'total': 1024, 'avail': 1024},
    {'used': 128},
    {'used': None, 'total': 1024},
    {'total': (1 << 64) - 1},
])
def test_optional_and_integer_usage_metrics_stay_compatible(admin, pbs, metrics):
    """Keep absent/null namespace metrics and valid u64 byte counts, including the native maximum."""
    pbs.get_datastores.return_value = {'data': [{'name': 'backup', 'path': '/backup'}]}
    pbs.get_datastore_usage.return_value = {'data': [{'store': 'backup', 'error': None, **metrics}]}
    pbs.get_datastore_status.return_value = {'data': {}}

    response = admin.get(PATH)

    assert response.status_code == 200
    assert response.get_json() == [{'name': 'backup', 'path': '/backup', 'store': 'backup',
                                   'error': None, **metrics, 'detail': {}}]
    pbs.get_datastore_status.assert_called_once_with('backup')


def test_a_healthy_store_cannot_hide_a_malformed_metric(admin, pbs):
    """Mixed responses fail as a whole instead of returning partial healthy stores."""
    pbs.get_datastores.return_value = {'data': [{'name': 'healthy'}, {'name': 'backup'}]}
    pbs.get_datastore_usage.return_value = {'data': [
        {'store': 'healthy', 'used': 1, 'total': 4, 'avail': 3},
        {'store': 'backup', 'used': 'invalid', 'total': 4},
    ]}

    response = admin.get(PATH)

    assert response.status_code == 502
    assert response.get_json()['code'] == 'PBS_UPSTREAM'
    pbs.get_gc_jobs.assert_not_called()
    pbs.get_datastore_status.assert_not_called()
