"""Source checks for the EVPN prerequisite panel in MultiClusterEvpnView (#1154).

The view is shared by every layout, and the classic corporate layout is
frozen: new features stay out of it. The panel must gate on the layout, must
not fill the peers field on its own (management IPs are not necessarily
underlay addresses), and stale results must go when the cluster selection
changes. LW Nov 2026
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _component():
    src = open(os.path.join(ROOT, 'web', 'src', 'vm_modals.js'), encoding='utf-8').read()
    start = src.index('function MultiClusterEvpnView')
    end = src.index('// MK: Group Overview', start)
    return src[start:end]


def test_the_panel_stays_out_of_the_frozen_corporate_layout():
    comp = _component()
    assert 'const { layout } = useLayout();' in comp
    assert '{canManage && layout !== \'corporate\' && (' in comp


def test_the_peers_field_is_not_filled_silently():
    comp = _component()
    body = comp[comp.index('const runPrereqs'):comp.index('// another cluster selection')]
    assert 'setForm' not in body, 'runPrereqs must only collect results'
    # the fill happens on an explicit click and without duplicates
    assert 'useNodeIps' in comp and 'new Set(' in comp
    assert "t('mcevpnPrereqUseIps')" in comp
    # the management addresses are labeled as such, with the caveat
    assert 'nc.mgmt_ip' in comp and 'nc.underlay_ip' not in comp
    assert "t('mcevpnPrereqMgmtHint')" in comp


def test_a_changed_cluster_selection_drops_the_old_result():
    comp = _component()
    assert re.search(
        r'useEffect\(\(\) => \{ prereqSeq\.current\+\+; setPrereqData\(null\); setPrereqError\(null\); \}, \[form\.cluster_ids\]\);',
        comp)


def test_a_late_response_cannot_land_after_a_selection_change():
    """A check that started before the selection changed must not store its
    result: the panel would show readiness for clusters nobody selected."""
    comp = _component()
    assert 'const prereqSeq = useRef(0);' in comp
    assert 'const mine = ++prereqSeq.current;' in comp
    assert 'if (mine !== prereqSeq.current) return;' in comp
    # the reset bumps the sequence, so an in-flight answer is stale
    assert re.search(r'useEffect\(\(\) => \{ prereqSeq\.current\+\+;'
                     r' setPrereqData\(null\); setPrereqError\(null\); \}, \[form\.cluster_ids\]\);',
                     comp)


def test_unreachable_members_are_shown_not_swallowed():
    comp = _component()
    assert 'prereqData.errors.map' in comp
    assert "t('mcevpnPrereqMemberErr')" in comp


def test_filling_peers_asks_before_overwriting():
    comp = _component()
    assert "t('mcevpnPrereqReplacePeers')" in comp
    assert 'window.confirm' in comp[comp.index('const useNodeIps'):comp.index('const useNodeIps') + 400]
