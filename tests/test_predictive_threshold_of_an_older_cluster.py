"""A cluster saved before predictive_threshold existed keeps the 75 the UI shows.

Its stored threshold read as 0.0 (or NULL, or no key at all), so the balancer compared every
node's score with 0 and called each node above 0 critical. The UI showed 75 the whole time.
"""
import threading
import types

import pytest

from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig

CID = 'cluster_1'
BASE = {'name': 'lab', 'host': 'h', 'user': 'u', 'pass': 'p'}

# how an older cluster row reads back: the column holds 0.0 (what the ALTER default leaves
# in rows that predate the column), NULL, or the key is missing from the stored data
OLDER_ROWS = [(0.0, False), (None, False), (None, True)]
OLDER_IDS = ['column_0', 'column_null', 'key_absent']


def _older_cluster(db, stored, drop_key):
    db.save_cluster(CID, dict(BASE))
    db.execute("UPDATE clusters SET predictive_threshold = ? WHERE id = ?", (stored, CID))
    row = db.get_all_clusters()[CID]
    if drop_key:
        del row['predictive_threshold']
    return row


@pytest.mark.parametrize('stored, drop_key', OLDER_ROWS, ids=OLDER_IDS)
def test_an_older_cluster_loads_the_75_the_ui_shows(db, stored, drop_key):
    """An older cluster row loads with the predictive threshold 75 the UI shows."""
    assert PegaProxConfig(_older_cluster(db, stored, drop_key)).predictive_threshold == 75


def test_a_cluster_saved_at_60_loads_60(db):
    """A cluster saved with a predictive threshold of 60 loads 60."""
    db.save_cluster(CID, dict(BASE, predictive_threshold=60))
    assert PegaProxConfig(db.get_all_clusters()[CID]).predictive_threshold == 60


def test_a_zero_saved_is_stored_as_0_and_loads_as_75(db):
    """A predictive threshold saved as 0 is stored as 0.0 and loads as 75, the UI never offers 0."""
    db.save_cluster(CID, dict(BASE, predictive_threshold=0))
    assert db.get_cluster(CID)['predictive_threshold'] == 0.0
    assert PegaProxConfig(db.get_all_clusters()[CID]).predictive_threshold == 75


@pytest.mark.parametrize('stored, drop_key', OLDER_ROWS, ids=OLDER_IDS)
def test_a_node_at_40_is_not_critical_for_an_older_cluster(db, stored, drop_key):
    """A node at score 40 is not trending to overload on an older cluster with predictive balancing on."""
    row = _older_cluster(db, stored, drop_key)
    row['predictive_balancing'] = True
    m = object.__new__(PegaProxManager)
    m.config = PegaProxConfig(row)
    m._metrics_history_lock = threading.Lock()
    # constant samples of 34.78 give a composite score of 40.0 (34.78 * 1.15)
    m._node_metrics_history = {'pve1': [{'cpu': 34.78, 'mem_pct': 34.78}] * 5}
    ps = m._compute_predictive_score('pve1')
    assert ps['score'] == 40.0
    assert ps['trend'] == 'stable'


@pytest.mark.parametrize('value, runs', [(-5, 75), ('abc', 75), (True, 75), (float('nan'), 75),
                                         (float('inf'), 75), ('60', 60.0)],
                         ids=['negative', 'text', 'bool', 'nan', 'inf', 'number_as_text'])
def test_a_threshold_that_is_no_number_above_0_loads_as_75(value, runs):
    """What cannot be compared with a score runs as 75, a number sent as text as that number."""
    assert PegaProxConfig(dict(BASE, predictive_threshold=value)).predictive_threshold == runs


@pytest.mark.parametrize('stored', [0.0, None, ''], ids=['column_0', 'column_null', 'column_empty'])
def test_a_synced_older_row_leaves_the_75_the_manager_runs(db, monkeypatch, stored):
    """A standby hands the synced row to its managers field by field: the 0.0 or
    NULL of an older row does not replace the 75 the manager was built with."""
    from pegaprox.core import ha
    import pegaprox.globals as g
    db.save_cluster(CID, dict(BASE))
    db.execute("UPDATE clusters SET predictive_threshold = ? WHERE id = ?", (stored, CID))
    cfg = PegaProxConfig(dict(BASE))
    monkeypatch.setitem(g.cluster_managers, CID, types.SimpleNamespace(config=cfg))
    ha._refresh_managers()
    assert cfg.predictive_threshold == 75
    # a threshold the admin set still reaches it
    db.execute("UPDATE clusters SET predictive_threshold = 60 WHERE id = ?", (CID,))
    ha._refresh_managers()
    assert cfg.predictive_threshold == 60
