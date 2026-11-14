"""The client portal's esc() has to keep a value inside the attribute it is put in.

esc() is the textContent -> innerHTML trick. That serialises a text node, which escapes
&, < and > and leaves quotes alone, so a guest name, an ISO file name or a logo URL with a
double quote closed the attribute around it and the rest became markup. A guest name on
XCP-ng is free text, so this did not take an admin. esc() escapes both quotes now, the
same way escapeHtml in status.html does.

That is not enough for the action buttons. A value inside onclick="f('...')" is decoded by
the HTML parser before the handler is compiled, so &#39; is a ' again by then and a name
with one still ended the JS string. Those arguments are written by jsArg() now, a JSON
string literal escaped for the attribute, and no handler quotes a value itself.

Runs the REAL helpers out of portal.html under node, with the stand-in for the browser's
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


# --- arguments of inline handlers ---------------------------------------------------------

# the string argument of each button, and the field it is built from
_SITES = {
    'Start': (r"""onclick="pAction\([^"]*?,'start',(.+?)\)">""", 'v.name'),
    'Mount': (r"""onclick="pMountIso\([^"]*?\$\{vm\.vmid\},(.+?)\)">Mount<""", 'iso.volid'),
    'Revert': (r"""onclick="pRollback\([^"]*?\$\{m\.vm\.vmid\},(.+?)\)" title=""", 's.name'),
    'Delete snapshot': (r"""onclick="pDeleteSnap\([^"]*?\$\{m\.vm\.vmid\},(.+?)\)" title=""", 's.name'),
}

NAMES = ["web01');window.__ran=true;//", 'web01" onmouseover="window.__ran=true',
         "Müller's \"Büro\" & <Co>", 'a\\b\\\'c', 'line one\nline two']


def _argument_template(site):
    """The argument as the file writes it, with a precomputed local (jName, escName)
    replaced by what it is assigned."""
    src = _HTML.read_text(encoding='utf-8')
    pattern, field = _SITES[site]
    m = re.search(pattern, src)
    assert m, f'the {site} button is no longer where this test looks for it'

    def resolve(local):
        d = re.search(r'\b' + local.group(1) + r'\s*=\s*([^,;]+)', src)
        assert d, local.group(1)
        return '${' + d.group(1).strip() + '}'
    arg = re.sub(r'\$\{([A-Za-z_]\w*)\}', resolve, m.group(1))
    assert field in arg, (site, arg)
    return arg


def _rendered_argument(site, value):
    src = _HTML.read_text(encoding='utf-8')
    helpers = _helper('esc') + ('\n' + _helper('jsArg') if 'const jsArg = ' in src else '')
    return _node(_SHIM + helpers + '\nconst X=' + json.dumps(value) +
                 ';const v={name:X},iso={volid:X},s={name:X};' +
                 'console.log(JSON.stringify(`' + _argument_template(site) + '`));')


def _call_with(attribute_text):
    """What the handler does in the browser: the attribute is entity-decoded, then compiled
    with this text as the argument of the call."""
    code = 'f(' + html.unescape(attribute_text) + ')'
    return _node('globalThis.window=globalThis;let args=null,error=null;'
                 'try{new Function("f",' + json.dumps(code) + ')(function(){args=[].slice.call(arguments)})}'
                 'catch(e){error=String(e)}'
                 'console.log(JSON.stringify({args:args,ran:!!globalThis.__ran,error:error}));')


@pytest.mark.parametrize('site', sorted(_SITES))
@pytest.mark.parametrize('value', NAMES)
def test_a_button_hands_its_handler_exactly_the_string_it_was_given(site, value):
    attr = _rendered_argument(site, value)

    assert '"' not in attr, f'a bare double quote ends the onclick attribute: {attr}'
    assert _call_with(attr) == {'args': [value], 'ran': False, 'error': None}


def _handlers():
    lines = _HTML.read_text(encoding='utf-8').splitlines()
    src = '\n'.join(l for l in lines if not l.lstrip().startswith('//'))
    return re.findall(r'\son[a-z]+="([^"]*\$\{[^"]*)"', src)


# a guest id is an int on the wire (_get_my_vms only keeps ids from its ACL set)
_ALLOWED = re.compile(r'^(jCid|jName|jsArg\([\w.]+\)|(v|vm|m\.vm)\.vmid)$')


def test_no_inline_handler_puts_a_value_between_quotes_itself():
    """The buttons above are the ones with a free-text argument; this holds every other
    handler to the same rule, so the next one is written the same way."""
    handlers = _handlers()
    assert len(handlers) >= 13, handlers

    for h in handlers:
        assert not re.search(r"""['"]\$\{""", h), f'a value quoted by hand in: {h}'
        for expr in re.findall(r'\$\{([^}]*)\}', h):
            assert _ALLOWED.match(expr), f'{expr} goes into a handler without jsArg: {h}'
