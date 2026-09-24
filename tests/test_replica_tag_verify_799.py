"""The replica tag was written best-effort and read as a hard gate (#799).

_tag_as_replica returned silently on a failed config read and only logged a warning
on a rejected PUT, while _is_replica_of_job — the same tag, one run later — aborts
the job outright. The run that broke the pairing therefore reported success, and the
operator met the problem a day later as a message about a tag nobody had told them
we could not write.

A 200 on the PUT is not proof on its own: PVE queues the config write behind the
guest lock the migration just released, and the guard reads the config rather than
our status code. MK
"""
from unittest.mock import MagicMock

import pytest

from pegaprox.api.vms import _tag_as_replica, _untagged_replica_error, _job_tag


NODE, VMID, JOB = 'pve-node-2', 100, '21374341'


class FakePve:
    """Just enough of a manager: config GET returns whatever tags we say it holds."""

    def __init__(self, tags='', put_status=200, applies=True, get_status=200):
        self.host, self.api_port = '10.0.0.9', 8006
        self.tags = tags
        self.put_status = put_status
        self.applies = applies          # does the accepted write actually land
        self.get_status = get_status
        self.puts = []

    def _api_get(self, url, **kw):
        r = MagicMock()
        r.status_code = self.get_status
        r.json.return_value = {'data': {'tags': self.tags}}
        return r

    def _api_put(self, url, data=None, **kw):
        self.puts.append(data)
        if self.put_status == 200 and self.applies:
            self.tags = data['tags']
        r = MagicMock()
        r.status_code = self.put_status
        r.text = 'nope'
        return r


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr('pegaprox.api.vms.time.sleep', lambda *_: None)


def test_a_clean_write_reports_success():
    mgr = FakePve(tags='')
    ok, detail = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert ok and detail == ''
    assert _job_tag(JOB) in mgr.tags


def test_the_users_own_tags_survive():
    mgr = FakePve(tags='prod;billing')
    ok, _ = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert ok
    assert {'prod', 'billing'} <= set(mgr.tags.split(';'))


def test_already_tagged_is_a_no_op():
    mgr = FakePve(tags=f'pegaprox-replica;{_job_tag(JOB)}')
    ok, _ = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert ok
    assert mgr.puts == []


def test_an_accepted_write_that_does_not_land_is_a_failure():
    """The regression: PVE said 200, the guest never got the tag, we called it done."""
    mgr = FakePve(tags='', applies=False)
    ok, detail = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert not ok
    assert 'not on the guest' in detail


def test_a_rejected_write_is_a_failure_and_names_the_status():
    mgr = FakePve(tags='', put_status=403)
    ok, detail = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert not ok
    assert '403' in detail


def test_an_unreadable_config_is_a_failure_not_a_silent_return():
    mgr = FakePve(get_status=500)
    ok, detail = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert not ok
    assert 'read' in detail


def test_a_transient_lock_is_retried_rather_than_reported():
    """The likely real cause: the guest lock clears on its own a second later."""
    mgr = FakePve(tags='', put_status=500)

    calls = {'n': 0}
    real_put = mgr._api_put

    def flaky(url, data=None, **kw):
        calls['n'] += 1
        if calls['n'] == 1:
            return real_put(url, data=data)
        mgr.put_status = 200
        return real_put(url, data=data)

    mgr._api_put = flaky
    ok, _ = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert ok
    assert calls['n'] == 2


def test_it_gives_up_after_the_attempt_budget():
    mgr = FakePve(tags='', put_status=500)
    ok, _ = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB, attempts=2)
    assert not ok
    assert len(mgr.puts) == 2


def test_an_exception_does_not_escape_to_the_caller():
    mgr = FakePve()
    mgr._api_get = MagicMock(side_effect=OSError('connection reset'))
    ok, detail = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB, attempts=1)
    assert not ok
    assert detail


def test_lxc_uses_the_lxc_config_path():
    mgr = FakePve(tags='')
    seen = []
    orig = mgr._api_put

    def spy(url, data=None, **kw):
        seen.append(url)
        return orig(url, data=data)

    mgr._api_put = spy
    _tag_as_replica(mgr, NODE, VMID, 'lxc', JOB)
    assert '/lxc/100/config' in seen[0]


def test_the_operator_message_says_what_to_do():
    msg = _untagged_replica_error(JOB, VMID, NODE, 'PVE rejected the tag write with HTTP 403')
    assert _job_tag(JOB) in msg          # the exact tag they must apply
    assert str(VMID) in msg and NODE in msg
    assert 'next run' in msg             # why it matters now rather than later
    assert '403' in msg                  # the cause, not just the symptom


def test_the_operators_tag_order_is_left_alone():
    """We append; we do not reshuffle what someone else put there."""
    mgr = FakePve(tags='zeta;alpha;prod')
    ok, _ = _tag_as_replica(mgr, NODE, VMID, 'qemu', JOB)
    assert ok
    assert mgr.tags.split(';')[:3] == ['zeta', 'alpha', 'prod']
