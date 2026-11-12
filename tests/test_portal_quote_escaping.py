"""The client portal's esc() has to keep a value inside the attribute it is put in.

esc() is the textContent -> innerHTML trick. That serialises a text node, which escapes
&, < and > and leaves quotes alone, so a guest name, an ISO file name or a logo URL with a
double quote closed the attribute around it and the rest became markup. A guest name on
XCP-ng is free text, so this did not take an admin. esc() escapes both quotes now, the
same way escapeHtml in status.html does.

Runs the REAL helper out of portal.html under node, with the stand-in for the browser's
text-node serialisation from test_status_page_escaping.py (& < > escaped, quotes not).
MK Nov 2026
"""
import html
import json
import pathlib
import re
import shutil
import subprocess

import pytest

_HTML = pathlib.Path(__file__).resolve().parent.parent / 'plugins' / 'client_portal' / 'portal.html'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

_SHIM = r'''
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


def _helper(name):
    src = _HTML.read_text(encoding='utf-8')
    m = re.search(r'^const ' + name + r' = .*;$', src, re.M)
    assert m, f'{name} is no longer where this test looks for it'
    return m.group(0)


def _node(script):
    out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _esc(values):
    return _node(_SHIM + _helper('esc') + '\nconsole.log(JSON.stringify(' + json.dumps(values) + '.map(esc)));')


def test_a_double_quote_cannot_close_the_attribute():
    escaped, = _esc(['web01" style="animation:spin 1s" onanimationstart="alert(1)'])

    assert '"' not in escaped, f'a bare double quote survived: {escaped}'
    rendered = '<input data-name="' + escaped + '" placeholder="">'
    assert rendered.count('"') == 4, rendered


def test_a_single_quote_cannot_close_one_either():
    escaped, = _esc(["x' onerror='alert(1)"])
    assert "'" not in escaped, f'a bare single quote survived: {escaped}'


def test_markup_and_quotes_in_one_value_are_all_escaped():
    """The helper's first job keeps working next to the new one."""
    escaped, = _esc(['<b>"x"</b> & \'y\''])
    assert not set('<>"\'') & set(escaped), escaped
    assert '&amp;' in escaped


@pytest.mark.parametrize('name', ["Müller's \"Büro\" VM", "pve-01 (Karl's rack) & <co>", 'say "hi" 日本語'])
def test_a_real_name_with_quotes_reads_back_as_it_was_written(name):
    """The mirror: nothing bare is left, and what the browser decodes out of the attribute
    is the name itself, umlauts and quotes included."""
    escaped, = _esc([name])
    assert '"' not in escaped and "'" not in escaped, escaped
    assert html.unescape(escaped) == name
