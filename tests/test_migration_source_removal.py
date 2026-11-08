"""Destroying the source guest is a delete, whichever route asks for it.

Both migration paths take a `remove_source` flag that destroys the original once the copy
lands, and both authorized the whole request as a migration. The distinction matters
because vm.delete is deliberately absent from the inherit_role permission set (rbac.py):
a VM-ACL user holds vm.migrate and never vm.delete. So the migration path was the way
around that - copy the guest somewhere, tick the box, and the original is gone.

Aikido ai_pentest 700489002. MK
"""
import re
import inspect

import pytest

import pegaprox.api.xhm as xhm
import pegaprox.api.vmware as vmw
from pegaprox.utils.rbac import ACL_INHERITED_VM_PERMISSIONS


def test_vm_delete_is_not_something_an_acl_confers():
    """The premise: if inherit_role already granted vm.delete, none of this would matter."""
    assert 'vm.delete' not in ACL_INHERITED_VM_PERMISSIONS


def _handler_source(mod, fn):
    src = inspect.getsource(mod)
    i = src.index(f'def {fn}(')
    j = src.index('\n@bp.route', i) if '\n@bp.route' in src[i:] else len(src)
    return src[i:j]


def test_the_xhm_path_requires_vm_delete_for_removal():
    body = _handler_source(xhm, 'xhm_start')
    assert "data.get('remove_source')" in body
    assert "'vm.delete'" in body


def test_the_esxi_path_requires_manage_for_removal():
    body = _handler_source(vmw, 'start_vmware_migration')
    assert "data.get('remove_source')" in body
    assert "'vmware.vm.manage'" in body


def test_the_removal_check_comes_before_the_work_starts():
    """A check after the copy has begun is not a check."""
    body = _handler_source(xhm, 'xhm_start')
    guard = body.index("data.get('remove_source')")
    # the migration is dispatched through a manager or a task; either marker will do
    starts = [m.start() for m in re.finditer(r'cluster_managers\.get|start_migration|_dispatch', body)]
    assert starts, 'could not find where the work is dispatched'
    assert guard < max(starts), 'the removal check runs after the migration is under way'


def test_a_migration_without_removal_is_unaffected():
    """The invariant: the ordinary migrate path must not start demanding delete."""
    body = _handler_source(xhm, 'xhm_start')
    # the vm.delete requirement has to sit inside the remove_source branch, not beside it
    i = body.index("data.get('remove_source')")
    j = body.index("'vm.delete'")
    between = body[i:j]
    assert between.count('if ') <= 2, 'the delete check escaped its branch'
