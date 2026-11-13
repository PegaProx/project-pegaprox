"""The per-cluster gates and the switch of three leader sites (stage 1).

Stage 1: is_active_for(cid) is is_active() when the switch is off. With it
on, the instance must also be the cluster's home in the last adopted homes.
The switch, homes and homes_epoch live in the group state, spread with the
member list, and never enter the DB snapshot.
MK Nov 2026
"""
import json
import os

import pytest

from pegaprox.core import ha


@pytest.fixture
def fresh_ha(tmp_path, monkeypatch):
    """A clean HA state on a temp directory."""
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    monkeypatch.setattr(ha, '_state', None)
    yield ha


def test_switch_off_is_active_for_is_is_active(fresh_ha):
    """With the switch off (the default), the per-cluster gate is exactly
    the existing gate, for any cluster."""
    ha = fresh_ha
    assert not ha.sites_enabled()
    for cid in ('cl-a', 'cl-b', 42, 'unknown'):
        assert ha.is_active_for(cid) == ha.is_active()
        assert ha.takes_writes_for(cid) == ha.takes_writes()


def test_switch_on_home_acts_others_do_not(fresh_ha):
    """With the switch on, only the home site's gate opens; a cluster
    without an entry has the group leader as its home."""
    ha = fresh_ha
    me = ha.instance_id()
    # a standalone is its own group leader and active
    ha._update(ha_sites=True, homes={'cl-a': me, 'cl-b': 'other-site'})
    assert ha.is_active_for('cl-a') is True    # home
    assert ha.is_active_for('cl-b') is False   # other site's home
    assert ha.is_active_for('cl-new') is True  # no entry -> group leader


def test_switch_off_restores_is_active(fresh_ha):
    """Turning the switch off restores the old behavior."""
    ha = fresh_ha
    me = ha.instance_id()
    ha._update(ha_sites=True, homes={'cl-a': 'far-away'})
    assert ha.is_active_for('cl-a') is False
    ha._update(ha_sites=False)
    assert ha.is_active_for('cl-a') is True


def test_the_state_persists_homes_and_epoch(fresh_ha, tmp_path):
    """The fields survive a restart (state file write and read)."""
    ha = fresh_ha
    me = ha.instance_id()
    ha._update(ha_sites=True, homes={'cl-a': me}, homes_epoch=3)
    # drop the in-memory cache, read from disk
    ha._state = None
    st = ha._load()
    assert st['ha_sites'] is True
    assert st['homes'] == {'cl-a': me}
    assert st['homes_epoch'] == 3


def test_voter_count_standalone_is_zero(fresh_ha):
    """A standalone instance has no voters."""
    assert fresh_ha.voter_count() == 0
