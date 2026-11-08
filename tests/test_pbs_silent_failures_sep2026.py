"""PBS reads that reported success while the server had refused them (#802, #803).

PBSManager.api_get does not raise. On a refusal it returns a dict carrying 'error'
and 'status_code', and the routes then reached for result.get('data', []) — so a
403 left the browser holding an empty 200. In the syslog panel that is
indistinguishable from "not loaded yet", which is why the reporter could press the
button forever with nothing on screen and nothing in the console.

#803 is a separate mistake in the same area: we listed notification targets from
/config/notifications/endpoints, which is an index node (children: gotify,
sendmail, smtp, webhook) and not the list itself. The list lives at
/config/notifications/targets and is the only one carrying name and type. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
from pegaprox.api.pbs import pbs_upstream_error


PBS = 'pbs_a'


@pytest.fixture
def pbs(api):
    m = MagicMock()
    m.linked_clusters = ['cluster_1']
    m.connected = True
    ppglobals.pbs_managers.clear()
    ppglobals.pbs_managers[PBS] = m
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


# ── the classifier ──

def test_success_is_not_an_error():
    assert pbs_upstream_error({'data': [{'n': 1, 't': 'line'}]}) is None


def test_empty_success_is_not_an_error():
    # an empty log is a legitimate answer and must stay a 200
    assert pbs_upstream_error({'data': []}) is None


def test_forbidden_keeps_its_own_status():
    status, payload = pbs_upstream_error({'error': 'HTTP 403', 'status_code': 403})
    assert status == 403
    assert payload['code'] == 'PBS_FORBIDDEN'


def test_other_upstream_failures_become_bad_gateway():
    status, payload = pbs_upstream_error({'error': 'HTTP 500', 'status_code': 500})
    assert status == 502
    assert payload['code'] == 'PBS_UPSTREAM'
    assert payload['upstream_status'] == 500


def test_transport_failure_without_a_status_still_reports():
    # api_get's except branch has no status_code at all
    status, payload = pbs_upstream_error({'error': 'ConnectionError'})
    assert status == 502
    assert payload['code'] == 'PBS_UNREACHABLE'
    assert payload['upstream_status'] is None


def test_the_upstream_exception_text_is_not_reflected_to_the_caller():
    """requests puts host, port and the full URL in that string; it belongs in the log."""
    raw = ("HTTPSConnectionPool(host='10.1.2.3', port=8007): Max retries exceeded "
           "with url: /api2/json/nodes/localhost/syslog")
    _, payload = pbs_upstream_error({'error': raw})
    assert '10.1.2.3' not in payload['error']
    assert 'api2' not in payload['error']


def test_non_dict_is_not_an_error():
    assert pbs_upstream_error([]) is None
    assert pbs_upstream_error(None) is None


# ── #802 syslog ──

def test_syslog_403_reaches_the_browser_as_403(api, pbs, admin):
    pbs.get_syslog.return_value = {'error': 'HTTP 403', 'status_code': 403}
    r = admin.get(f'/api/pbs/{PBS}/syslog')
    assert r.status_code == 403
    assert r.get_json()['code'] == 'PBS_FORBIDDEN'


def test_syslog_403_is_no_longer_an_empty_200(api, pbs, admin):
    """The regression itself: this used to be 200 [] and the panel showed its prompt again."""
    pbs.get_syslog.return_value = {'error': 'HTTP 403', 'status_code': 403}
    r = admin.get(f'/api/pbs/{PBS}/syslog')
    assert not (r.status_code == 200 and r.get_json() == [])


def test_syslog_upstream_500_becomes_502(api, pbs, admin):
    pbs.get_syslog.return_value = {'error': 'HTTP 500', 'status_code': 500}
    r = admin.get(f'/api/pbs/{PBS}/syslog')
    assert r.status_code == 502
    assert r.get_json()['code'] == 'PBS_UPSTREAM'


def test_syslog_success_is_unchanged(api, pbs, admin):
    pbs.get_syslog.return_value = {'data': [{'n': 1, 't': 'starting backup'}]}
    r = admin.get(f'/api/pbs/{PBS}/syslog')
    assert r.status_code == 200
    assert r.get_json() == [{'n': 1, 't': 'starting backup'}]


def test_syslog_genuinely_empty_stays_a_200(api, pbs, admin):
    """A PBS with nothing to report is not a failure — the UI says so separately."""
    pbs.get_syslog.return_value = {'data': []}
    r = admin.get(f'/api/pbs/{PBS}/syslog')
    assert r.status_code == 200
    assert r.get_json() == []


# ── #803 notification targets ──

def test_targets_are_read_from_the_list_not_the_index():
    """/config/notifications/endpoints is an index node; its GET is declared to return null."""
    from pegaprox.core.pbs import PBSManager
    mgr = PBSManager.__new__(PBSManager)
    seen = []
    mgr.api_get = lambda path, **kw: seen.append(path) or {'data': []}
    mgr.get_notification_targets()
    assert seen == ['/config/notifications/targets']


def test_matcher_path_was_already_right():
    from pegaprox.core.pbs import PBSManager
    mgr = PBSManager.__new__(PBSManager)
    seen = []
    mgr.api_get = lambda path, **kw: seen.append(path) or {'data': []}
    mgr.get_notification_matchers()
    assert seen == ['/config/notifications/matchers']


def test_notifications_passes_through_name_and_type(api, pbs, admin):
    """The fields the UI renders. Reading the index node gave us neither, hence 'unknown -'."""
    pbs.get_notification_targets.return_value = {'data': [
        {'name': 'webhook-ops', 'type': 'webhook', 'origin': 'user-created'},
    ]}
    pbs.get_notification_matchers.return_value = {'data': []}
    r = admin.get(f'/api/pbs/{PBS}/notifications')
    assert r.status_code == 200
    body = r.get_json()
    assert body['targets'][0]['name'] == 'webhook-ops'
    assert body['targets'][0]['type'] == 'webhook'


def test_notifications_names_the_list_it_could_not_read(api, pbs, admin):
    pbs.get_notification_targets.return_value = {'error': 'HTTP 403', 'status_code': 403}
    pbs.get_notification_matchers.return_value = {'data': [{'name': 'default-matcher'}]}
    body = admin.get(f'/api/pbs/{PBS}/notifications').get_json()
    assert body['errors']['targets']['code'] == 'PBS_FORBIDDEN'
    assert 'matchers' not in body['errors']
    # the half that worked still comes through
    assert body['matchers'] == [{'name': 'default-matcher'}]


def test_notifications_stay_a_200_so_one_failure_cannot_blank_the_other(api, pbs, admin):
    pbs.get_notification_targets.return_value = {'error': 'HTTP 500', 'status_code': 500}
    pbs.get_notification_matchers.return_value = {'error': 'HTTP 500', 'status_code': 500}
    r = admin.get(f'/api/pbs/{PBS}/notifications')
    assert r.status_code == 200
    assert set(r.get_json()['errors']) == {'targets', 'matchers'}


def test_no_errors_key_when_both_reads_worked(api, pbs, admin):
    pbs.get_notification_targets.return_value = {'data': []}
    pbs.get_notification_matchers.return_value = {'data': []}
    assert 'errors' not in admin.get(f'/api/pbs/{PBS}/notifications').get_json()
