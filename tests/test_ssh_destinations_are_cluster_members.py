"""No SSH destination may be a name the caller supplied.

_ssh_connect presents the CLUSTER's stored root password or key. So whatever host it
dials has to come from that cluster's own membership data — never from a request path
segment, body field, or a stored job row that once held one. The idiom that keeps
reappearing is a resolver with a fall-back to its own argument:

    def resolve(mgr, node):
        ...look the name up in cluster/status...
        return node          # <-- unresolvable name becomes the destination

manager.member_node_ip was written against exactly this and states the contract in its
docstring: None means refuse, never "use the name". datacenter.py was brought in line in
August; _xcincr_node_ip in the cross-cluster replication path still had it, reached
through a replication job's stored target_node.

This is a structural test rather than a behavioural one because the property is about
every call site at once, and the ones that matter are on paths that need two real
clusters and live SSH to exercise. It asserts that each _ssh_connect argument outside
core/ traces back to a member-validating resolver or to the cluster's own configured
host — and it is meant to fail when someone adds a new SSH path, so that the question
gets asked again.

Aikido ai_pentest 700488513. MK
"""
import ast
import io
import os

import pytest

# Resolvers that answer only from a cluster's own membership data, and the
# attributes that ARE the cluster's configured host.
MEMBER_RESOLVERS = {
    'member_node_ip',      # core/manager.py — the canonical one
    '_get_node_ip',        # core/manager.py, cluster API + corosync only
    '_resolve_node_ip',    # api/ceph.py — cluster/status, falls back to raw_host
    '_get_host_ip',
    '_xcincr_node_ip',     # api/vms.py — cluster/status, None when not a member
}
OWN_HOST_ATTRS = {'host', 'raw_host', 'config'}

ROOTS = ('pegaprox', 'plugins')
# the resolvers themselves live here and necessarily handle raw names
EXCLUDED_PREFIX = os.path.join('pegaprox', 'core') + os.sep

# Helpers that receive an ALREADY-resolved IP as a parameter. Their callers are
# checked instead; listing them here keeps the test honest about what it skips.
TAKES_RESOLVED_IP = {
    ('pegaprox/api/ceph.py', '_rbd_cmd'),
    ('pegaprox/api/ceph.py', '_rbd_batch'),
}


def _py_files():
    for base in ROOTS:
        for root, _, files in os.walk(base):
            for fn in files:
                if fn.endswith('.py'):
                    p = os.path.join(root, fn)
                    if not p.startswith(EXCLUDED_PREFIX):
                        yield p


def _mentions_resolver(node):
    """Does this expression get its value from a membership-validating resolver,
    or from the cluster's own configured host?"""
    for m in ast.walk(node):
        if isinstance(m, ast.Call):
            name = getattr(m.func, 'attr', None) or getattr(m.func, 'id', None)
            if name in MEMBER_RESOLVERS:
                return True
        if isinstance(m, ast.Attribute) and m.attr in OWN_HOST_ATTRS:
            return True
    return False


def _ssh_destinations():
    """Yield (path, lineno, func, arg_node, enclosing_func_node)."""
    for path in _py_files():
        src = io.open(path, encoding='utf-8').read()
        if '_ssh_connect' not in src:
            continue
        tree = ast.parse(src)
        for fnode in ast.walk(tree):
            if not isinstance(fnode, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for c in ast.walk(fnode):
                if not (isinstance(c, ast.Call)
                        and getattr(c.func, 'attr', '') == '_ssh_connect' and c.args):
                    continue
                yield path.replace(os.sep, '/'), c.lineno, fnode.name, c.args[0], fnode


def test_every_ssh_destination_comes_from_cluster_membership():
    unexplained = []
    for path, lineno, func, arg, fnode in _ssh_destinations():
        if (path, func) in TAKES_RESOLVED_IP:
            continue
        if not isinstance(arg, ast.Name):
            # an inline call — judge the expression itself
            if not _mentions_resolver(arg):
                unexplained.append(f'{path}:{lineno} {func} -> {ast.unparse(arg)}')
            continue
        assigned = [a.value for a in ast.walk(fnode) if isinstance(a, ast.Assign)
                    for t in a.targets if isinstance(t, ast.Name) and t.id == arg.id]
        if not assigned:
            unexplained.append(f'{path}:{lineno} {func} -> {arg.id} (never assigned here)')
        elif not any(_mentions_resolver(v) for v in assigned):
            unexplained.append(
                f'{path}:{lineno} {func} -> {arg.id} from '
                + ' | '.join(ast.unparse(v)[:60] for v in assigned))

    assert not unexplained, (
        'SSH destination not traceable to cluster membership:\n  '
        + '\n  '.join(unexplained))


def test_the_sweep_actually_looked_at_something():
    """A detector that silently matches nothing proves nothing."""
    found = list(_ssh_destinations())
    assert len(found) >= 20, f'only found {len(found)} _ssh_connect sites — did the sweep break?'


@pytest.mark.parametrize('resolver', sorted(MEMBER_RESOLVERS))
def test_no_resolver_falls_back_to_its_own_argument(resolver):
    """The specific bug shape: `return node` at the end of a name->IP resolver.

    A resolver that hands back the name it was given turns an unresolvable node into
    the SSH destination, which is the whole point of this file.
    """
    for path in list(_py_files()) + ['pegaprox/core/manager.py']:
        src = io.open(path, encoding='utf-8').read()
        if f'def {resolver}' not in src:
            continue
        tree = ast.parse(src)
        for fnode in ast.walk(tree):
            if not isinstance(fnode, ast.FunctionDef) or fnode.name != resolver:
                continue
            params = {a.arg for a in fnode.args.args}
            for r in ast.walk(fnode):
                if isinstance(r, ast.Return) and isinstance(r.value, ast.Name):
                    assert r.value.id not in params, (
                        f'{path}:{r.lineno} {resolver} returns its own argument '
                        f'{r.value.id!r} — an unresolvable name becomes the SSH host')
