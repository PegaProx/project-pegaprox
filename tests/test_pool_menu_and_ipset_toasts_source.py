"""Source checks next to the browser tests of #1238 and the guest firewall IP sets.

The browser tests skip where Playwright is missing, CI among them, so these hold the two
fixes there too:
- the guest menu moves a guest into or out of a pool through the members routes, which ask
  pool.assign; the pool edit (PUT with add_members / remove_members) asks admin.users;
- IpsetEntries gets every prop it destructures: without addToast a refused entry threw
  "addToast is not defined" and said nothing.
LW Nov 2026
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src')


def _read(name):
    with open(os.path.join(SRC, name), encoding='utf-8') as fh:
        return fh.read()


def test_the_ui_moves_guests_through_the_members_routes_only():
    for name in sorted(os.listdir(SRC)):
        if name.endswith('.js'):
            src = _read(name)
            assert 'add_members' not in src and 'remove_members' not in src, name
    dash = _read('dashboard.js')
    assert re.search(r"/pools/\$\{[^}]+\}/members`, \{\s*method: 'POST'", dash), 'no POST .../members in the menu'
    assert re.search(r"/pools/\$\{[^}]+\}/members/\$\{[^}]+\}`, \{\s*method: 'DELETE'", dash), 'no DELETE .../members/<vmid>'


# the handlers a dialog hands its parts; none of them is a global in the bundle
PROP_HANDLERS = ('addToast', 'onClose', 'onSaved', 'onSave', 'onRefresh', 'getAuthHeaders')


def test_ipset_entries_calls_only_handlers_it_was_given():
    src = _read('vm_config.js')
    sig = re.search(r'function IpsetEntries\(\{([^}]*)\}\)', src)
    assert sig, 'IpsetEntries signature not found'
    takes = {p.split('=')[0].strip() for p in sig.group(1).split(',') if p.strip()}
    body = src[sig.end():]
    nxt = re.search(r'\n        function \w+\(', body)
    body = body[:nxt.start()] if nxt else body
    called = {h for h in PROP_HANDLERS if re.search(rf'\b{h}\(', body)}
    assert called <= takes, called - takes
    call = re.search(r'<IpsetEntries\b(.*?)/>', src, re.S)
    assert call, 'no <IpsetEntries .../> call'
    given = set(re.findall(r'(\w+)=\{', call.group(1)))
    assert takes <= given, takes - given
