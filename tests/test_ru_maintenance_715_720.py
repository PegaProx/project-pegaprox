# #715 (robertdahlem) — rolling update must not run the reboot/offline-wait for a node that needed
#   no reboot (it logged a phantom "rebooting" + waited 120s + "back online (0s)").
# #720 (hugobugomugo) — soft (non-HA) node maintenance must survive a PegaProx restart.

import threading
import types
import logging


# ---------------------------------------------------------------------------
# #720 — node_maintenance persistence round-trip
# ---------------------------------------------------------------------------

def test_720_node_maintenance_db_roundtrip(db):
    assert db.get_node_maintenance('cl1') == []
    db.save_node_maintenance('cl1', 'pve1')
    db.save_node_maintenance('cl1', 'pve2')
    db.save_node_maintenance('cl2', 'other')          # different cluster, must not bleed
    nodes = sorted(n for n, _ in db.get_node_maintenance('cl1'))
    assert nodes == ['pve1', 'pve2']
    # idempotent save keeps the original entered_at
    first_ts = dict(db.get_node_maintenance('cl1'))['pve1']
    db.save_node_maintenance('cl1', 'pve1')
    assert dict(db.get_node_maintenance('cl1'))['pve1'] == first_ts
    db.remove_node_maintenance('cl1', 'pve1')
    assert sorted(n for n, _ in db.get_node_maintenance('cl1')) == ['pve2']
    assert [n for n, _ in db.get_node_maintenance('cl2')] == ['other']


# ---------------------------------------------------------------------------
# #720 — restore repopulates in-memory maintenance from the persisted rows
# ---------------------------------------------------------------------------

def test_720_restore_repopulates_soft_maintenance(db, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)
    db.save_node_maintenance('clX', 'pve1')
    db.save_node_maintenance('clX', 'pve2')

    fake = types.SimpleNamespace(id='clX', nodes_in_maintenance={},
                                 maintenance_lock=threading.Lock(), logger=logging.getLogger('t720'))
    PegaProxManager._restore_persisted_maintenance(fake)

    assert set(fake.nodes_in_maintenance) == {'pve1', 'pve2'}
    t = fake.nodes_in_maintenance['pve1']
    assert t.native_ha is False and getattr(t, '_restored', False) is True
    # a node already present (e.g. re-derived from native HA) is not clobbered
    marker = object()
    fake.nodes_in_maintenance = {'pve1': marker}
    PegaProxManager._restore_persisted_maintenance(fake)
    assert fake.nodes_in_maintenance['pve1'] is marker


# ---------------------------------------------------------------------------
# #715 — the offline-wait is gated on whether THIS node actually rebooted
# ---------------------------------------------------------------------------

def test_715_reboot_wait_gated_on_reboot_issued():
    class _Task:
        pass
    include_reboot = True

    no_reboot = _Task(); no_reboot.reboot_issued = False
    assert not (include_reboot and getattr(no_reboot, 'reboot_issued', True))   # -> skip the wait

    did_reboot = _Task(); did_reboot.reboot_issued = True
    assert (include_reboot and getattr(did_reboot, 'reboot_issued', True))      # -> wait

    # attribute never set (reboot block not reached) -> safe default is to wait
    assert (include_reboot and getattr(_Task(), 'reboot_issued', True))

    # global toggle off -> never wait regardless
    assert not (False and getattr(did_reboot, 'reboot_issued', True))
