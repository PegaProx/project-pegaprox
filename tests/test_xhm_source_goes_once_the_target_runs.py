"""Remove source in the XCP-ng legs: the source goes only once the target runs.

Both legs started the target without reading the answer (one with an async start that
can still fail) and then destroyed the source, also when nothing was started at all.
A target that does not come up then had no source left to go back to.
"""
import ast
import inspect
import types

import pytest

from pegaprox.core import xhm


class _Resp:
    def __init__(self, code, status=None):
        self.status_code = code
        self._status = status

    def json(self):
        return {'data': {'status': self._status}}


def _mgr(answers):
    seen = []

    def get(url, **kw):
        seen.append(url)
        a = answers[min(len(seen), len(answers)) - 1]
        if isinstance(a, Exception):
            raise a
        return a
    return types.SimpleNamespace(host='pve1', api_port=8006, _api_get=get), seen


def test_a_running_target_on_proxmox_is_seen():
    mgr, seen = _mgr([_Resp(200, 'stopped'), _Resp(200, 'running')])
    assert xhm._pve_target_runs(mgr, 'pve1', 120, wait=5, poll=0) is True
    assert seen[0].endswith('/nodes/pve1/qemu/120/status/current')


@pytest.mark.parametrize('answer', [_Resp(200, 'stopped'), _Resp(500), OSError('refused')])
def test_a_target_that_does_not_run_on_proxmox_is_not(answer):
    mgr, _ = _mgr([answer])
    assert xhm._pve_target_runs(mgr, 'pve1', 120, wait=0, poll=0) is False


def _xapi(states):
    calls = []

    def get_power_state(ref):
        calls.append(ref)
        s = states[min(len(calls), len(states)) - 1]
        if isinstance(s, Exception):
            raise s
        return s
    return types.SimpleNamespace(VM=types.SimpleNamespace(get_power_state=get_power_state))


def test_a_running_target_on_xcpng_is_seen():
    assert xhm._xcp_target_runs(_xapi(['Halted', 'Running']), 'OpaqueRef:1', wait=5, poll=0) is True


@pytest.mark.parametrize('state', ['Halted', 'Paused', RuntimeError('gone')])
def test_a_target_that_does_not_run_on_xcpng_is_not(state):
    assert xhm._xcp_target_runs(_xapi([state]), 'OpaqueRef:1', wait=0, poll=0) is False


def _guarded_by(fn, destroy, check):
    """True when every node that destroys the source sits in a branch of an If whose test
    calls check, on the side where that call was true."""
    tree = ast.parse(inspect.getsource(fn))
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    sites = [n for n in ast.walk(tree) if destroy(n)]
    assert sites, 'no source destroy found'
    for site in sites:
        node, ok = site, False
        while node in parents:
            parent = parents[node]
            if isinstance(parent, ast.If) and check in ast.unparse(parent.test):
                negated = 'not' in ast.unparse(parent.test).split(check)[0]
                in_body = any(node is b for b in parent.body)
                if in_body != negated:
                    ok = True
                    break
            node = parent
        if not ok:
            return False
    return True


def test_the_xcpng_to_pve_leg_destroys_the_source_only_for_a_running_target():
    def destroy(n):
        return isinstance(n, ast.Call) and ast.unparse(n.func) == 'api.VM.destroy'
    assert _guarded_by(xhm._run_xcpng_to_pve, destroy, '_pve_target_runs(')


def test_the_pve_to_xcpng_leg_destroys_the_source_only_for_a_running_target():
    def destroy(n):
        return isinstance(n, ast.JoinedStr) and 'qm destroy' in ast.unparse(n)
    assert _guarded_by(xhm._run_pve_to_xcpng, destroy, '_xcp_target_runs(')


def test_the_start_answer_of_proxmox_is_read():
    src = inspect.getsource(xhm._run_xcpng_to_pve)
    start = src.index('/status/start')
    assert 'resp.status_code == 200' in src[start:start + 400]
