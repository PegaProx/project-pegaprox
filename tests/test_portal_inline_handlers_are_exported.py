"""Every inline handler in the client portal has to exist on `window`.

portal.html wraps its script in an IIFE, so nothing declared inside it is global,
while an `onclick="foo()"` attribute resolves against the global scope and nothing
else. A handler that is never re-exported therefore throws ReferenceError and the
button silently does nothing - no error state in the UI, just a dead control.

It happened with #765 for the container create/destroy buttons and with #810 for
the SSO button, which sat broken from April to September. Writing this test then
found seven more: the close buttons of three portal dialogs, dead since they could
first be opened. Counting the two lists by hand is how it was found each time; this
does the counting.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTAL = os.path.join(ROOT, 'plugins', 'client_portal', 'portal.html')

# `event.stopPropagation()` and `document.getElementById(...)` are browser globals,
# not handlers of ours - they need no export.
_BROWSER_GLOBALS = ('event', 'document', 'window', 'history', 'location', 'console')


def _source():
    """The file with its full-line // comments dropped.

    Both scans below are regexes over the raw text, so a comment explaining a past
    bug would otherwise register as a handler (or, worse, as an export, which would
    make the test pass for a button that is still dead). Only lines that START with
    // are removed, so the https:// inside a string survives."""
    with open(PORTAL, encoding='utf-8') as fh:
        lines = fh.read().splitlines()
    return '\n'.join(l for l in lines if not l.lstrip().startswith('//'))


def _inline_handlers(src):
    found = set()
    for m in re.finditer(r'\son[a-z]+="([A-Za-z_$][\w$]*)\s*[.(]', src):
        name = m.group(1)
        if name not in _BROWSER_GLOBALS:
            found.add(name)
    return found


def _window_exports(src):
    return set(re.findall(r'window\.([A-Za-z_$][\w$]*)\s*=', src))


def test_the_scan_finds_the_handlers_at_all():
    """Counter-check: if the regexes stop matching, the test below passes for the
    wrong reason and the next dead button ships."""
    src = _source()
    handlers = _inline_handlers(src)

    assert len(handlers) >= 15, sorted(handlers)
    assert 'pConsole' in handlers
    assert 'startOidcLogin' in handlers
    assert len(_window_exports(src)) >= 15


def test_every_inline_handler_is_reachable_from_the_global_scope():
    src = _source()

    missing = sorted(_inline_handlers(src) - _window_exports(src))

    assert not missing, (
        'these portal handlers are called from an onclick= but never exported to '
        'window, so clicking them throws ReferenceError: ' + ', '.join(missing))


def test_a_comment_cannot_stand_in_for_an_export():
    """Counter-check for the comment stripping: an export that only exists inside a
    comment must not satisfy the rule."""
    src = "<button onclick=\"pGhost()\">x</button>\n// window.pGhost=pGhost;\n"
    stripped = '\n'.join(l for l in src.splitlines() if not l.lstrip().startswith('//'))

    assert 'pGhost' in _inline_handlers(stripped)
    assert 'pGhost' not in _window_exports(stripped)


def test_the_sso_button_starts_the_flow_it_advertises():
    """#810: the button has to reach the OIDC authorize endpoint and come back to
    the portal, not to the main UI - a portal_only account cannot use the latter."""
    src = _source()

    assert 'onclick="startOidcLogin()"' in src
    assert '/api/auth/oidc/authorize?redirect_after=/portal' in src
