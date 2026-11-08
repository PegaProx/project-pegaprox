"""The public status page put an admin-controlled URL inside src="..." .

`escapeHtml()` there is the textContent -> innerHTML trick. That is the right tool for
text content and the wrong one for an attribute: the HTML fragment serialiser escapes
&, < and > in a text node and leaves quotes alone, because a text node is not an
attribute value. So a custom_logo_url containing a double quote closed src= and whatever
followed became markup - persistent script on a page served to the public, planted from
the admin settings.

Twenty-two of the twenty-three call sites are text content and were never affected. Only
the logo is in an attribute, so the fix went into the shared helper rather than that one
line: escaping quotes is a no-op for text content and the only thing that matters in an
attribute.

Runs the REAL function out of status.html under node, with a faithful stand-in for the
browser's text-node serialisation (& < > escaped, quotes not). Asserting on the source
text would pass against any file containing "&quot;" and would say nothing about what the
function returns. Aikido ai_pentest 700488446. LW
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

_HTML = pathlib.Path(__file__).resolve().parent.parent / 'plugins' / 'status_page' / 'status.html'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')


def _escape_html(values):
    """Run status.html's own escapeHtml over `values` and return the results."""
    src = _HTML.read_text(encoding='utf-8')
    m = re.search(r'function escapeHtml\(str\) \{.*?\n\}', src, re.S)
    assert m, 'escapeHtml is no longer where this test looks for it'

    shim = r'''
    // Stand-in for the browser: setting textContent and reading innerHTML serialises a
    // TEXT node, which escapes & < > and deliberately does NOT escape quotes.
    global.document = {
      createElement: function () {
        return {
          _t: '',
          set textContent(v) { this._t = String(v); },
          get innerHTML() {
            return this._t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
          }
        };
      }
    };
    '''
    script = shim + m.group(0) + '\nconsole.log(JSON.stringify(' + \
        json.dumps(values) + '.map(escapeHtml)));'
    out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_a_quote_cannot_close_the_src_attribute():
    """The property: after escaping, no bare double quote is left to end the attribute."""
    payload = 'x" onerror="alert(1)'
    escaped, = _escape_html([payload])

    assert '"' not in escaped, f'a bare double quote survived: {escaped}'

    # And the markup that results carries exactly the quotes the template wrote - two for
    # src, two for alt. Any extra pair would mean the value opened an attribute of its own.
    rendered = '<img src="' + escaped + '" alt="">'
    assert rendered.count('"') == 4, rendered


def test_a_single_quote_cannot_close_one_either():
    escaped, = _escape_html(["x' onerror='alert(1)"])
    assert "'" not in escaped, f'a bare single quote survived: {escaped}'


def test_angle_brackets_and_ampersands_still_go():
    """The original job of the helper has to keep working."""
    escaped, = _escape_html(['<script>alert(1)</script> & more'])
    assert '<' not in escaped and '>' not in escaped
    assert '&amp;' in escaped


def test_ordinary_text_is_still_readable():
    """The mirror: escaping quotes must not mangle names that merely contain one."""
    escaped, = _escape_html(["Node pve-01 (Karl's rack)"])
    assert 'Karl' in escaped and 'rack' in escaped
    assert 'pve-01' in escaped


def test_empty_and_missing_values_stay_empty():
    assert _escape_html(['']) == ['']
