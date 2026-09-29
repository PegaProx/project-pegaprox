"""#727 (nvaert1986) - with the node shell open, a sideways drag pans the whole page
and clips part of the layout off-screen. Firefox only; Chrome does not pan on that
gesture, which is why it looked unreproducible for six weeks.

Measured in Firefox against the running app (the script lives in
~/Schreibtisch/pegaprox-tools/e2e/t_727_shell_page_width.py):

    ohne Fix                         docScrollW= 50000  pan= 4800  sticky top=0
    html, body {overflow-x: hidden}  docScrollW= 50000  pan=    0  sticky top=-314   <- Kopf kaputt
    Messelement position: fixed      docScrollW=  2560  pan=    0  sticky top=0

The cause is xterm 5.3.0: its width cache parks a `position: absolute; top: -50000px;
width: 50000px` measuring div on `document.body` for as long as a terminal lives. It is
out of sight vertically but it makes the DOCUMENT 50000px wide, and a page that wide can
be panned. Taking it out of flow with `position: fixed` removes the overflow at the
source; the div is still laid out at its own width, so xterm measures exactly what it
measured before.

`overflow-x: hidden` is the obvious remedy and the wrong one - the phone block in
index.html.original already says so in prose, and the numbers above are the measurement
behind that sentence.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, 'web', 'index.html.original')
BUILT = os.path.join(ROOT, 'web', 'index.html')

RULE = re.compile(
    r'body\s*>\s*div\[style\*=["\']-50000px["\']\]\s*\{[^}]*position:\s*fixed[^}]*\}',
    re.I | re.S)


@pytest.mark.parametrize('path', [SHELL, BUILT])
def test_the_measuring_div_is_taken_out_of_the_page_flow(path):
    body = open(path, encoding='utf-8').read()
    assert RULE.search(body), (
        f"{os.path.basename(path)} has no rule pinning xterm's 50000px measuring div "
        f"out of flow - with the shell open the page is 50000px wide and pans")


def test_the_page_is_not_nailed_shut_with_overflow_hidden():
    """The remedy that suggests itself kills the sticky header (measured: top -314
    instead of 0). Keep it out of the full-width stylesheet."""
    body = open(SHELL, encoding='utf-8').read()
    # the phone block is a separate, older decision (#189) and uses clip, not hidden
    offenders = re.findall(r'html\s*,?\s*body[^{]*\{[^}]*overflow-x:\s*hidden', body, re.I)
    assert not offenders, f"overflow-x: hidden on the page root breaks the sticky header: {offenders}"
