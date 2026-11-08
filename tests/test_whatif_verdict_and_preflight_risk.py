"""The one-line verdict of a what-if report (core/whatif.py verdict), the risk notes of the
migration preflight (core/preflight.py _risk_checks) and the args every preflight reason
carries so the UI can speak it in its own language.

Same harness as tests/test_whatif_risk.py (a real manager answered from a dict) and
tests/test_migration_preflight.py (the fake Proxmox cluster of the preflight).
NS Oct 2026
"""
import ast
import os
import re
import types

import pytest

from pegaprox.core import preflight as pf
from pegaprox.core import recovery, whatif
from test_whatif import CID, THR, _cfg, _manager, _rows, _vm
from test_whatif_risk import NOW, T_PBS, _forget, _mark_passed, _pve  # noqa: F401 (_forget is a fixture)
from test_migration_preflight import _Pve, _guest, _fresh, GB  # noqa: F401 (_fresh is a fixture)

URL = f'/api/clusters/{CID}/whatif'
LEVELS = ('ready', 'warning', 'blocked')


def _env(api, tags=None, local=(), jobs=None):
    guests, pve = _pve(tags=tags, jobs=jobs if jobs is not None else [])
    configs = {v['vmid']: (_cfg('local-lvm') if v['vmid'] in local else _cfg()) for v in guests}
    guests, pve = _pve(guests=guests, configs=configs, tags=tags, jobs=jobs if jobs is not None else [])
    return api.set_manager(CID, _manager(pve, guests))


def _verdict(mgr, thresholds=None, **body):
    body.setdefault('type', 'maintenance')
    body.setdefault('nodes', ['pve1'])
    return whatif.run(mgr, whatif.parse_scenario(body), dict(thresholds or THR))


def _levels(v):
    return {r['level'] for r in v['reasons']}


@pytest.fixture
def lab(api, monkeypatch):
    # the tenants table is not what these tests are about
    monkeypatch.setattr(whatif, '_tenants', lambda cid: [])
    return api


# --- the verdict -------------------------------------------------------------------------------

def test_a_maintenance_that_moves_everything_and_leaves_nothing_open_is_ready(lab):
    mgr = _env(lab)
    for vmid in (100, 101):
        _mark_passed(vmid)
    r = _verdict(mgr)
    assert r['verdict'] == {'level': 'ready', 'reasons': []}, r['verdict']


def test_a_guest_that_stays_down_blocks(lab):
    mgr = _env(lab, local=(101,))
    r = _verdict(mgr)
    assert _rows(r)[101]['outcome'] == 'down'
    v = r['verdict']
    assert v['level'] == 'blocked' and v['reasons'][0]['code'] == 'guests_down'
    assert v['reasons'][0]['args'] == {'count': 1} and v['reasons'][0]['level'] == 'blocked'
    assert v['reasons'][0]['text'] == '1 guest cannot be placed anywhere and stays down'


def test_a_critical_guest_warns_and_is_named(lab):
    mgr = _env(lab, tags={100: 'critical;web'})
    for vmid in (100, 101):
        _mark_passed(vmid)
    v = _verdict(mgr)['verdict']
    assert v['level'] == 'warning' and [r['code'] for r in v['reasons']] == ['critical_affected']
    assert v['reasons'][0]['args'] == {'count': 1, 'names': 'guest100'}


def test_many_critical_guests_are_cut_to_a_few_names(lab):
    guests = [_vm(v, 'pve1', maxmem=1) for v in range(100, 108)]
    for g in guests:
        g['tags'] = 'critical'
    _g, pve = _pve(guests=guests, configs={g['vmid']: _cfg() for g in guests})
    mgr = lab.set_manager(CID, _manager(pve, guests))
    for g in guests:
        _mark_passed(g['vmid'])
    reason = _verdict(mgr)['verdict']['reasons'][0]
    assert reason['args']['count'] == 8 and reason['args']['names'].endswith('and 3 more')
    assert reason['args']['names'] in reason['text']


def test_a_failing_restore_test_warns_for_any_guest_an_unproven_one_only_for_a_critical(lab):
    # as in the preflight: most installs run no restore tests, a warning on every guest says nothing
    mgr = _env(lab)
    _mark_passed(100)           # 101 was never tested, and is not critical
    assert _verdict(mgr)['verdict'] == {'level': 'ready', 'reasons': []}
    # a failing test is news on any guest
    recovery.note_result({'cluster_id': CID, 'vmid': 101, 'status': 'failed', 'id': 'bad101',
                          'backup_ts': T_PBS, 'measured_seconds': 60.0, 'checks': []}, at=NOW - 60)
    v = _verdict(mgr)['verdict']
    assert v['level'] == 'warning'
    assert [(r['code'], r['args']) for r in v['reasons']] == [('restore_unproven', {'count': 1})]
    _mark_passed(101)
    assert _verdict(mgr)['verdict']['level'] == 'ready'


def test_a_critical_guest_never_tested_warns_for_both(lab):
    mgr = _env(lab, tags={101: 'critical'})
    _mark_passed(100)
    v = _verdict(mgr)['verdict']
    assert [(r['code'], r['args'].get('count')) for r in v['reasons']] == [('critical_affected', 1),
                                                                          ('restore_unproven', 1)]


def test_nodes_pushed_over_the_threshold_warn(lab):
    mgr = _env(lab)
    for vmid in (100, 101):
        _mark_passed(vmid)
    # 16 of 64 GiB in use, 25 percent: a threshold of 20 is crossed by every node
    v = _verdict(mgr, thresholds={'cpu': 80.0, 'memory': 20.0})['verdict']
    assert v['level'] == 'warning' and v['reasons'][0]['code'] == 'over_threshold'
    assert v['reasons'][0]['args']['nodes'] == ['pve2', 'pve3']
    assert 'pve2, pve3' in v['reasons'][0]['text']


def test_tenants_counted_per_cluster_are_an_assumption_that_matters(lab, monkeypatch):
    mgr = _env(lab)
    for vmid in (100, 101):
        _mark_passed(vmid)
    monkeypatch.setattr(whatif, '_tenants', lambda cid: [{'id': 'acme', 'name': 'Acme'}])
    v = _verdict(mgr)['verdict']
    assert v['level'] == 'warning' and v['reasons'][0]['code'] == 'tenants_assumed'
    assert v['reasons'][0]['args'] == {'tenants': ['Acme']}
    # the default tenant counts every cluster and says nothing
    monkeypatch.setattr(whatif, '_tenants', lambda cid: [{'id': 'default', 'name': 'Default'}])
    assert _verdict(mgr)['verdict']['level'] == 'ready'


def test_a_blocked_verdict_lists_its_blocks_before_its_warnings(lab):
    mgr = _env(lab, tags={100: 'critical'}, local=(101,))
    v = _verdict(mgr)['verdict']
    assert v['level'] == 'blocked'
    assert [r['level'] for r in v['reasons']] == sorted((r['level'] for r in v['reasons']),
                                                       key=lambda x: x != 'blocked')


@pytest.mark.parametrize('body', [
    {'type': 'node_failure', 'nodes': ['pve1']},
    {'type': 'maintenance', 'nodes': ['pve1']},
    {'type': 'headroom', 'depth': 1},
    {'type': 'storage_failure', 'storage': 'local-lvm'},
    {'type': 'network_failure', 'bridge': 'vmbr0'},
    {'type': 'pbs_failure', 'storage': 'pbs1'},
])
def test_every_scenario_carries_a_verdict_whose_reasons_say_what_they_hold(lab, body):
    mgr = _env(lab, tags={100: 'critical'})
    v = _verdict(mgr, **body)['verdict']
    assert v['level'] in LEVELS
    assert (v['level'] == 'ready') == (not v['reasons'])
    for reason in v['reasons']:
        assert set(reason) == {'level', 'code', 'args', 'text'} and reason['code'] in whatif.VERDICT_TEXT
        for value in reason['args'].values():
            for part in (value if isinstance(value, list) else [value]):
                assert str(part) in reason['text']


def test_a_node_failure_leaves_the_not_ha_guests_down_and_blocks(lab):
    v = _verdict(_env(lab), type='node_failure', nodes=['pve1'])['verdict']
    assert v['level'] == 'blocked' and v['reasons'][0]['code'] == 'guests_down'


def test_a_headroom_that_cannot_place_a_node_s_guests_blocks_and_one_over_the_threshold_warns():
    placed = {'combinations': [{'unplaced': 0, 'quorate': True}], 'failing': 0}
    assert whatif.verdict({'guests': [], 'nodes': [], 'headroom': placed})['level'] == 'ready'
    stuck = {'combinations': [{'unplaced': 2, 'quorate': True}, {'unplaced': 0, 'quorate': True}], 'failing': 1}
    v = whatif.verdict({'guests': [], 'nodes': [], 'headroom': stuck})
    assert v['level'] == 'blocked' and v['reasons'][0]['args'] == {'count': 1}
    over = {'combinations': [{'unplaced': 0, 'quorate': True}], 'failing': 1}
    v = whatif.verdict({'guests': [], 'nodes': [], 'headroom': over})
    assert v['level'] == 'warning' and v['reasons'][0]['code'] == 'headroom_over'
    lost = {'combinations': [{'unplaced': 0, 'quorate': False}], 'failing': 1}
    assert whatif.verdict({'guests': [], 'nodes': [], 'headroom': lost})['reasons'][0]['code'] == 'headroom_quorum'


def test_the_route_answers_the_verdict_and_names_no_guest_the_caller_may_not_see(lab, seed):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    _env(lab, tags={100: 'critical'}, local=(101,))
    admin = lab.as_user(seed.user('root', role='admin')).post(
        URL, json={'type': 'maintenance', 'nodes': ['pve1']}).get_json()
    assert admin['verdict']['level'] == 'blocked'
    assert 'guest100' in str(admin['verdict'])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {102: ('qemu', 'pool_1')})
    mine = lab.as_user(seed.user('mallory', role='viewer')).post(
        URL, json={'type': 'maintenance', 'nodes': ['pve1']}).get_json()
    assert 'guest100' not in str(mine['verdict']) and 'guest101' not in str(mine['verdict'])
    assert mine['verdict']['level'] in LEVELS


# --- the risk the preflight knows ----------------------------------------------------------------

CFG = {'scsi0': 'ceph:vm-100-disk-0,size=32G', 'net0': 'virtio=AA:BB:CC:00:00:01,bridge=vmbr0'}


def _risk_pve(api, guests):
    return _Pve(api, guests=guests, configs={g['vmid']: CFG for g in guests})


def _proven(monkeypatch, states):
    """Restore marks as the recovery store holds them, {vmid: 'proven' | 'not_proven' | 'failing'};
    the list returned gets one entry per read of the store"""
    reads = []
    now = NOW

    def marks(cluster_id):
        reads.append(cluster_id)
        out = {}
        for vmid, state in states.items():
            if state == 'proven':
                out[vmid] = {'ok_at': now - 3600, 'last_at': now - 3600, 'last_result': 'passed', 'ok_seconds': 60}
            elif state == 'failing':
                out[vmid] = {'last_at': now - 60, 'fail_at': now - 60, 'last_result': 'failed'}
        return out
    monkeypatch.setattr(recovery, 'load_marks', marks)
    return reads


_real_guest_risk = whatif.guest_risk


@pytest.fixture
def real_risk(monkeypatch):
    # the autouse fixture of the preflight tests stubs the risk reader out; these want it
    monkeypatch.setattr(whatif, 'guest_risk', _real_guest_risk)


def _reasons(res, vmid):
    return {r['code']: r for r in {g['vmid']: g for g in res['guests']}[vmid]['reasons']}


def test_a_critical_guest_is_an_info_and_never_a_block(api, monkeypatch, real_risk):
    guests = [_guest(100, tags='critical;web'), _guest(101)]
    m = _risk_pve(api, guests)
    _proven(monkeypatch, {100: 'proven', 101: 'proven'})
    monkeypatch.setattr(whatif, 'critical_tags_for', lambda cid, requested=None: (['critical'], 'default'))
    res = pf.intra('cluster_1', m, [100, 101], 'pve2')
    got = _reasons(res, 100)
    assert got['critical_guest']['level'] == 'info' and got['critical_guest']['args'] == {'tags': 'critical'}
    assert 'restore_not_proven' not in got
    row = {g['vmid']: g for g in res['guests']}
    assert row[100]['verdict'] == 'ready' and 'critical_guest' not in _reasons(res, 101)


def test_a_failing_restore_is_an_info_and_an_unproven_one_says_nothing(api, monkeypatch, real_risk):
    # most installs run no restore tests: "not proven" on every guest of every move is noise,
    # so it is only said for a critical guest (next test). A failed test is news on any guest.
    m = _risk_pve(api, [_guest(100), _guest(101), _guest(102)])
    _proven(monkeypatch, {100: 'not_proven', 101: 'failing', 102: 'proven'})
    res = pf.intra('cluster_1', m, [100, 101, 102], 'pve2')
    assert not {'restore_not_proven', 'restore_failing'} & set(_reasons(res, 100))
    assert _reasons(res, 101)['restore_failing']['level'] == 'info'
    assert not {'restore_not_proven', 'restore_failing'} & set(_reasons(res, 102))
    assert {g['vmid']: g['verdict'] for g in res['guests']} == {100: 'ready', 101: 'ready', 102: 'ready'}


def test_a_critical_guest_without_a_proven_restore_warns(api, monkeypatch, real_risk):
    m = _risk_pve(api, [_guest(100, tags='critical'), _guest(101, tags='critical')])
    _proven(monkeypatch, {100: 'not_proven', 101: 'proven'})
    res = pf.intra('cluster_1', m, [100, 101], 'pve2')
    got = _reasons(res, 100)
    assert got['critical_guest']['level'] == 'warning' and got['restore_not_proven']['level'] == 'warning'
    rows = {g['vmid']: g for g in res['guests']}
    assert rows[100]['verdict'] == 'warning' and rows[101]['verdict'] == 'ready'
    assert pf.moving(rows[100])
    assert _reasons(res, 101)['critical_guest']['level'] == 'info'


def test_the_cross_cluster_preflight_knows_the_risk_too(api, monkeypatch, real_risk):
    src = _Pve(api, guests=[_guest(100, tags='critical')], configs={100: CFG})
    tgt = _Pve(api, cid='cluster_2')
    reads = _proven(monkeypatch, {100: 'failing'})
    res = pf.cross('cluster_1', src, 'cluster_2', tgt, [100], 'pve1', storage_map={'ceph': 'ceph'},
                   bridge_map={'vmbr0': 'vmbr0'}, online=False, force_online=False, delete_source=False)
    got = _reasons(res, 100)
    assert got['critical_guest']['level'] == 'warning' and got['restore_failing']['level'] == 'warning'
    assert reads == ['cluster_1']       # the source cluster's marks, the guest lives there
    assert not any(r['level'] == 'blocked' and r['code'] in ('critical_guest', 'restore_failing')
                   for g in res['guests'] for r in g['reasons'])


def test_the_risk_is_read_once_for_the_whole_set(api, monkeypatch, real_risk):
    guests = [_guest(v, tags='critical') for v in range(100, 140)]
    m = _risk_pve(api, guests)
    reads = _proven(monkeypatch, {g['vmid']: 'proven' for g in guests})
    tags = []
    real = whatif.critical_tags_for
    monkeypatch.setattr(whatif, 'critical_tags_for', lambda *a, **k: tags.append(1) or real(*a, **k))
    res = pf.intra('cluster_1', m, [g['vmid'] for g in guests], 'pve2')
    assert len(res['guests']) == 40 and reads == ['cluster_1'] and len(tags) == 1


def test_a_risk_that_cannot_be_read_costs_a_note_and_nothing_else(api, monkeypatch, real_risk):
    m = _risk_pve(api, [_guest(100, tags='critical')])
    monkeypatch.setattr(whatif, 'guest_risk', lambda *a, **k: 1 / 0)
    res = pf.intra('cluster_1', m, [100], 'pve2')
    assert res['guests'][0]['verdict'] == 'ready'
    # an unreadable store is not a failing restore
    monkeypatch.setattr(whatif, 'guest_risk', _real_guest_risk)
    monkeypatch.setattr(whatif, '_marks', lambda cid: None)
    res = pf.intra('cluster_1', m, [100], 'pve2')
    assert not any(r['code'].startswith('restore_') for r in res['guests'][0]['reasons'])


# --- every reason has a code and args ---------------------------------------------------------------

def _calls():
    src = open(os.path.join(os.path.dirname(pf.__file__), 'preflight.py'), encoding='utf-8').read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in ('block', 'warn', 'info', 'add') \
                and isinstance(f.value, ast.Name) and f.value.id == 'gv':
            yield node, f.attr
        elif isinstance(f, ast.Name) and f.id == '_reason' and node.args:
            yield node, '_reason'


def _is_dicts(node):
    if isinstance(node, ast.IfExp):
        return _is_dicts(node.body) and _is_dicts(node.orelse)
    return isinstance(node, ast.Dict)


def test_every_reason_the_preflight_can_emit_is_made_with_a_code_and_args():
    n = 0
    for node, how in _calls():
        n += 1
        shift = 1 if how in ('add', '_reason') else 0          # the level comes first there
        code = node.args[shift]
        if not isinstance(code, ast.Constant):
            continue        # the plumbing that passes a code on
        assert isinstance(code.value, str), node.lineno
        assert any(k.arg == 'args' and _is_dicts(k.value) for k in node.keywords), \
            f'line {node.lineno}: {code.value} has no args'
    assert n >= 80


# these carry a sentence Proxmox or the manager made up, args hold it whole: no wording of their own
FREE_TEXT = ('large_disk', 'transfer_fallback', 'vmid_range')


def test_the_codes_have_translations_in_every_language():
    root = os.path.dirname(os.path.dirname(pf.__file__))
    root = os.path.dirname(root)
    text = open(os.path.join(root, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    keys = set()
    for node, how in _calls():
        shift = 1 if how in ('add', '_reason') else 0
        if not isinstance(node.args[shift], ast.Constant):
            continue
        code = node.args[shift].value
        keys.add('pf_' + code)
        for k in node.keywords:
            if k.arg == 'variant':
                keys.add('pf_' + code + '_' + k.value.value)
    for key in ('pf_critical_guest', 'pf_restore_failing', 'pf_restore_not_proven'):
        assert key in keys
    # a code the UI would have no wording for falls back to the English text, which is fine for
    # the few scoped variants; everything else has its key in all nine blocks
    for key in sorted(keys - {'pf_' + c for c in FREE_TEXT}):
        assert len(re.findall(rf"\b{key}:", text)) == 9, key
    for code in whatif.VERDICT_TEXT:
        assert len(re.findall(rf"\bwiv_{code}:", text)) == 9, code


def test_a_count_of_one_reads_as_one():
    # "1 guests": every counted line has a wording of its own for one, on the server and in
    # each of the nine languages (where a language has no singular it says the same)
    for code in whatif.VERDICT_TEXT_ONE:
        one = whatif._vreason('warning', code, count=1, names='a', nodes='n', tenants='t')['text']
        many = whatif._vreason('warning', code, count=2, names='a', nodes='n', tenants='t')['text']
        assert one.startswith(('1 ', 'In 1 ')) and one != many.replace('2', '1', 1), (code, one)
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'web', 'src', 'translations.js'), encoding='utf-8').read()
    for key in ("wiv_" + c for c in whatif.VERDICT_TEXT_ONE):
        assert len(re.findall(r"^ +%s_one: '" % key, src, re.M)) == 9, key
    for key in ('maintDlgMoves', 'maintDlgStay', 'maintDlgUnproven'):
        assert len(re.findall(r"^ +%s_one: '" % key, src, re.M)) == 9, key
