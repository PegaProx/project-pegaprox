"""What PegaProx starts by itself makes the token of a cross-cluster move paced (#1390).

The cross-cluster balancer comes round every interval, a scheduled replication at its
schedule. Into a cluster whose token may make no token (the documented role) each makes
the migration token over a password login of the account, and while the realm's LDAP or
AD server gave no answer every run sent another login that failed. Three within the two
days the fail2ban jail for pveproxy in the Proxmox VE wiki looks back on ban the address
of PegaProx, and the cluster is cut off although its token needs no directory. Both make
the token paced now, as the renewal of the management token does (_account_login: a
second failed login half an hour after the first, a third two days after it, counted for
all of them together, see test_the_management_token_is_renewed_before_it_ends_1390). A
replication run started by hand logs in at once, as before.

MK Nov 2026
"""
import functools
import time
import types

import pytest

import pegaprox.api.vms as vms_api
import pegaprox.background.cross_cluster_replication as xcr
import pegaprox.background.site_recovery as srw
from pegaprox.core import ha

from test_a_move_into_an_older_migration_tunnel_is_refused_up_front import NEW, balance  # noqa: F401
from test_ha_sync_before_step import _Cluster, full  # noqa: F401
from test_sr_per_guest_failover import SRC, TGT, _admin, _job, _mgr


def test_the_balancer_makes_its_token_paced(balance):
    m = balance({'hi': (90.0, NEW), 'lo': (10.0, NEW)})
    assert m['lo'].create_api_token.call_args.kwargs.get('paced') is True
    assert m['hi'].remote_migrate_vm.call_count == 1


class _Stop(Exception):
    pass


def test_the_scheduler_runs_a_replication_paced(db, monkeypatch):
    ran = []
    monkeypatch.setattr(vms_api, '_execute_replication',
                        lambda job, paced=False: ran.append((job['id'], paced)))
    _job(db, 'j100', 100)
    started = []

    class _Thread:
        def __init__(self, target=None, args=(), daemon=None):
            self.args = args

        def start(self):
            started.append(self.args)

    def nap(seconds):
        raise _Stop()
    monkeypatch.setattr(xcr, 'time', types.SimpleNamespace(sleep=nap, time=time.time))
    monkeypatch.setattr(xcr, 'threading', types.SimpleNamespace(Thread=_Thread))
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **kw: True)
    monkeypatch.setattr(srw, 'replay_failover_state', lambda: None)
    monkeypatch.setattr(xcr, '_xcrepl_running', False)
    with pytest.raises(_Stop):
        xcr._xcrepl_loop()

    [(handler, job)] = started
    xcr._tracked_run(handler, job)
    assert ran == [('j100', True)]


def test_a_replication_run_by_hand_logs_in_at_once(api, seed, monkeypatch):
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _job(seed.db, 'j100', 100)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    ran = []
    monkeypatch.setattr(vms_api, '_execute_replication',
                        lambda job, paced=False: ran.append((job['id'], paced)))

    r = _admin(api, seed).post('/api/cross-cluster-replications/j100/run', json={})

    assert r.status_code == 200, r.get_data(as_text=True)
    deadline = time.time() + 5
    while not ran and time.time() < deadline:
        time.sleep(0.02)
    assert ran == [('j100', False)]


@pytest.mark.parametrize('paced', [True, False], ids=['scheduled', 'by-hand'])
def test_a_replication_run_makes_its_token_the_way_it_was_started(full, monkeypatch, paced):
    asked = []

    def create_api_token(self, name, **kw):
        asked.append(kw.get('paced', False))
        return {'success': True, 'token_id': 'root@pam!xcrepl', 'token_value': 'secret'}
    monkeypatch.setattr(_Cluster, 'create_api_token', create_api_token)
    real = vms_api._execute_replication
    monkeypatch.setattr(vms_api, '_execute_replication',
                        functools.partial(real, paced=True) if paced else real)

    full('running')

    assert asked == [paced]
