"""ESXi authority boundaries: power is not destruction, a pool is not a tenant.

Three things in the ESXi path drew the line in the wrong place:

  * DELETE and rename asked for vmware.vm.power, on the route AND in the per-VM check.
    So anyone allowed to switch a guest on and off could destroy or rename it. The
    permission that already means "may change this guest" - vmware.vm.manage - existed
    the whole time.
  * check_vmware_access resolved the caller's clusters WITH pool reach, so holding one
    resource pool on a Proxmox cluster that happens to be linked to an ESXi server handed
    them that server's whole inventory. A pool grant is a claim on VMs inside a cluster,
    not on a server linked to it.
  * save_vmware_server wrote linked_clusters with a default of [], and an empty list means
    "reachable by everyone". An update that never mentioned the field silently handed the
    server to every tenant - the same bug the PBS side had.

Aikido ai_pentest 700487619 / 700487546 / 700489178. MK
"""
import json

import pytest


def _perm_of(fn_name):
    """The permission the route decorator asks for."""
    import inspect
    import pegaprox.api.vmware as vmw
    src = inspect.getsource(vmw)
    i = src.index(f'def {fn_name}(')
    head = src[max(0, i - 400):i]
    import re
    hits = re.findall(r"@require_auth\(perms=\['([a-z.]+)'\]\)", head)
    return hits[-1] if hits else None


def _per_vm_perm(fn_name):
    """The permission the per-VM object check asks for."""
    import inspect
    import re
    import pegaprox.api.vmware as vmw
    src = inspect.getsource(vmw)
    i = src.index(f'def {fn_name}(')
    j = src.index('\n@bp.route', i) if '\n@bp.route' in src[i:] else len(src)
    hits = re.findall(r"user_can_access_vmware_vm\([^,]+, [^,]+, [^,]+, '([a-z.]+)'\)",
                      src[i:j])
    return hits[0] if hits else None


# --- power is not destruction ------------------------------------------------

@pytest.mark.parametrize('handler', ['delete_vmware_vm', 'rename_vmware_vm'])
def test_destructive_handlers_do_not_settle_for_power(handler):
    assert _perm_of(handler) == 'vmware.vm.manage'
    assert _per_vm_perm(handler) == 'vmware.vm.manage'


def test_the_power_handler_still_asks_for_power():
    """The invariant: this fix must not push everything up to manage."""
    assert _perm_of('vmware_vm_power') == 'vmware.vm.power'
    assert _per_vm_perm('vmware_vm_power') == 'vmware.vm.power'


def test_the_route_and_the_object_check_agree_everywhere():
    """They are two halves of one decision; a mismatch is how this bug looked."""
    import inspect, re
    import pegaprox.api.vmware as vmw
    src = inspect.getsource(vmw)
    mismatches = []
    for m in re.finditer(r'^def (\w+)\(vmware_id, vm_id', src, re.M):
        fn = m.group(1)
        route, obj = _perm_of(fn), _per_vm_perm(fn)
        if route and obj and route != obj:
            mismatches.append(f'{fn}: route={route} object={obj}')
    assert not mismatches, 'route and per-VM permission disagree:\n  ' + '\n  '.join(mismatches)


# --- a pool grant is not tenant ownership ------------------------------------

def test_the_vmware_tenant_gate_ignores_pool_reach():
    import inspect
    from pegaprox.api.helpers import check_vmware_access
    src = inspect.getsource(check_vmware_access)
    assert 'include_pools=False' in src


# --- the linkage survives an update that does not mention it -----------------

def test_omitting_linked_clusters_does_not_clear_them(db):
    from pegaprox.core.vmware import save_vmware_server

    save_vmware_server('esxi9', {'name': 'lab', 'host': 'h', 'username': 'root',
                                 'linked_clusters': ['cluster_a']})
    save_vmware_server('esxi9', {'name': 'renamed', 'host': 'h', 'username': 'root'})

    cur = db.conn.cursor()
    cur.execute("SELECT name, linked_clusters FROM vmware_servers WHERE id='esxi9'")
    name, linked = cur.fetchone()
    assert name == 'renamed', 'the update did not apply'
    assert json.loads(linked) == ['cluster_a'], 'the linkage was silently cleared'


def test_an_explicit_empty_list_still_unlinks(db):
    from pegaprox.core.vmware import save_vmware_server

    save_vmware_server('esxi9', {'name': 'lab', 'host': 'h', 'username': 'root',
                                 'linked_clusters': ['cluster_a']})
    save_vmware_server('esxi9', {'name': 'lab', 'host': 'h', 'username': 'root',
                                 'linked_clusters': []})

    cur = db.conn.cursor()
    cur.execute("SELECT linked_clusters FROM vmware_servers WHERE id='esxi9'")
    assert json.loads(cur.fetchone()[0]) == []
