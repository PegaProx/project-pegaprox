"""A disk that could not be attached fails the migration, and the source stays.

Between XCP-ng and Proxmox these were warnings: the run went on to destroy the source and said completed, with
a target that had no disk. The volumes were only left behind on the storage.
"""
import ast
import inspect
from types import SimpleNamespace

import pytest

import pegaprox.core.xhm as xhm

VOLS = [{'index': 0, 'vol_id': 'store:vm-200-disk-0'}, {'index': 1, 'vol_id': 'store:vm-200-disk-1'}]


def _attach(answers):
    logs, phases, sent = [], [], []
    seen = iter(answers)

    def post(url, data=None):
        sent.append(data)
        answer = next(seen)
        if isinstance(answer, Exception):
            raise answer
        return SimpleNamespace(status_code=answer)
    mgr = SimpleNamespace(host='pve', api_port=8006, _api_post=post)
    task = SimpleNamespace(target_node='pve1', log=logs.append, set_phase=lambda *a: phases.append(a))
    return xhm._attach_pve_volumes(mgr, task, 200, VOLS), phases, sent


def test_every_disk_attached_goes_on():
    done, phases, sent = _attach([200, 200])
    assert done is True and phases == []
    assert sent == [{'scsi0': 'store:vm-200-disk-0'}, {'scsi1': 'store:vm-200-disk-1'}]


@pytest.mark.parametrize('answers,says', [([200, 500], 'scsi1: HTTP 500'), ([RuntimeError('gone'), 200], 'scsi0: gone')])
def test_one_that_did_not_fails_and_all_are_tried(answers, says):
    done, phases, sent = _attach(answers)
    assert done is False and len(sent) == 2
    assert phases[0][0] == 'failed' and says in phases[0][1] and 'source VM stays' in phases[0][1]


def _body(fn):
    return ast.parse(inspect.getsource(fn))


def _line_of(tree, attr_or_text):
    return [n.lineno for n in ast.walk(tree) if attr_or_text in ast.dump(n) and isinstance(n, ast.Call)]


@pytest.mark.parametrize('fn', [xhm._run_xcpng_to_pve, xhm._run_esxi_to_pve])
def test_the_paths_to_proxmox_stop_on_it(fn):
    tree = _body(fn)
    ifs = [n for n in ast.walk(tree) if isinstance(n, ast.If) and '_attach_pve_volumes' in ast.dump(n.test)]
    assert len(ifs) == 1 and isinstance(ifs[0].body[0], ast.Return), ast.dump(tree)[:200]


def test_the_proxmox_to_xcpng_path_stops_before_it_destroys():
    src = inspect.getsource(xhm._run_pve_to_xcpng)
    assert src.index("attach_failed.append") < src.index("if attach_failed:") < src.index("qm destroy")
