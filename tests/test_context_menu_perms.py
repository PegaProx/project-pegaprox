"""The Corporate context menu must not offer what the caller cannot do.

Reported privately (Sep 2026): every entry was built unconditionally. The backend does
gate all of them — that was checked action by action, and it held — but a menu that shows
everything is how a future entry whose endpoint forgot its own check would go unnoticed:
the UI wouldn't hint at anything and the user would just get an error on click.

Each entry now carries the permission its endpoint requires and a wrapper drops the ones
the caller lacks. These hold that table to the two things that can silently rot: an entry
added without a permission, and a permission string that no longer exists. NS
"""
import re

import pytest

DASH = 'web/src/dashboard.js'


@pytest.fixture(scope='module')
def menu_src():
    s = open(DASH, encoding='utf-8').read()
    start = s.index('const buildContextMenuItemsRaw = (type, target) => {')
    end = s.index('const buildContextMenuItems = (type, target) => {', start)
    return s[start:end]


def _known_permissions():
    from pegaprox.models.permissions import ROLE_PERMISSIONS
    known = set()
    for perms in ROLE_PERMISSIONS.values():
        known.update(perms)
    return known


def test_the_wrapper_filters_on_the_callers_permissions():
    s = open(DASH, encoding='utf-8').read()

    assert 'const buildContextMenuItemsRaw' in s, 'the raw builder is gone'
    assert '.filter(i => !i.perm || can(i.perm))' in s, 'entries are no longer filtered'
    # a submenu that loses all its children must not stay behind as a dead parent
    assert 'if (!sub.length) continue;' in s


def test_every_actionable_entry_declares_a_permission(menu_src):
    """Two deliberate exceptions: `Refresh` only reads, and `Power` is a submenu container —
    its three children carry the permissions and the wrapper drops the parent when none of
    them survive, so gating the container as well would just hide it twice."""
    entries = re.findall(r"\{ (?:perm: '([a-z.]+)', )?label: t\('([a-zA-Z]+)'\)", menu_src)
    assert entries, 'no menu entries found — did the builder move?'

    ungated = sorted({label for perm, label in entries if not perm})

    assert ungated == ['power', 'refreshData'], f'entries without a permission: {ungated}'


def test_the_permissions_used_actually_exist(menu_src):
    """A typo here fails open: `can('vm.consle')` is false for everyone, so the entry
    silently disappears for every non-admin instead of erroring."""
    used = set(re.findall(r"perm: '([a-z.]+)'", menu_src))
    known = _known_permissions()

    assert used, 'no permissions declared'
    assert used <= known, f'not real permissions: {sorted(used - known)}'


@pytest.mark.parametrize('label,expected', [
    ('deleteCluster', 'cluster.delete'),
    ('reconfigureCluster', 'cluster.config'),
    ('repinHostKeys', 'cluster.config'),
    ('sshConsole', 'node.shell'),
    ('console', 'vm.console'),
    ('spiceConsole', 'vm.console'),
    ('clone', 'vm.clone'),
    ('snapshot', 'vm.snapshot'),
    ('editSettings', 'vm.config'),
    ('migrate', 'vm.migrate'),
    ('assignToPool', 'pool.assign'),
])
def test_the_entry_matches_the_permission_its_endpoint_requires(menu_src, label, expected):
    """Read off the backend decorators, not guessed. If an endpoint's requirement changes
    and this doesn't, the menu starts lying in one direction or the other."""
    m = re.search(r"\{ perm: '([a-z.]+)', label: t\('%s'\)" % label, menu_src)

    assert m, f'{label} lost its perm declaration'
    assert m.group(1) == expected


def test_the_power_submenu_entries_are_gated_individually(menu_src):
    """Start / Shutdown / Reboot are three different permissions; a user who may start a VM
    but not stop it should see one entry, not all three."""
    for label, perm in (('start', 'vm.start'), ('shutdown', 'vm.stop'), ('reboot', 'vm.restart')):
        assert re.search(r"\{ perm: '%s', label: t\('%s'\)" % (perm, label), menu_src), label
