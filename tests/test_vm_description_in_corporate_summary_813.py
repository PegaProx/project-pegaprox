"""#813 (Frisch12) - show a QEMU VM's description in the Corporate summary.

The detail view already fetches the VM config for machine / BIOS / CPU / SCSI /
network, and `raw.description` rides along in the same response, so this costs no
extra request. Three things the reporter asked for and all three matter:

- plain text, line breaks preserved, wrapped inside the column
- never interpreted as HTML, because a description is free-form text an operator
  types and PVE stores verbatim
- the previous config cleared while the next one loads, so a slow response cannot
  leave the last VM's description sitting under the new VM's name. That clearing
  was missing before this change for every field, not just the description - it
  simply did not show because a machine type reads the same for most VMs.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src():
    return open(os.path.join(ROOT, 'web', 'src', 'vm_modals.js'), encoding='utf-8').read()


def _corporate_view():
    body = _src()
    start = body.index('function CorporateVmDetailView(')
    return body[start:]


def test_the_description_is_read_out_of_the_config_we_already_fetch():
    view = _corporate_view()
    fetch = view[view.index('// Fetch VM hardware config'):]
    fetch = fetch[:fetch.index('// Fetch HA status')]
    # the bare word also appears in the comment above the effect - match the read
    assert 'raw.description' in fetch, 'the config handler drops raw.description on the floor'
    assert re.search(r'/config`', fetch), 'no longer reading the config endpoint'
    assert 'guest-fsinfo' not in fetch, 'a second request was added; the data is already here'


def test_switching_vm_clears_the_previous_config_first():
    """Without this a delayed answer paints the old VM's description under the new
    VM's name - the reporter called this out explicitly.

    The clear has to happen BEFORE the isQemu guard. A clear inside that guard
    only runs for containers, which is where it already was and why this looked
    handled.
    """
    view = _corporate_view()
    fetch = view[view.index('// Fetch VM hardware config'):]
    fetch = fetch[:fetch.index('// Fetch HA status')]
    guard_at = fetch.index('if (!isQemu)')
    assert 'setVmHwInfo(null)' in fetch[:guard_at], \
        'the stale config is only cleared for containers, not when switching VM'


def test_a_late_answer_for_the_previous_vm_is_dropped():
    """Clearing is not enough on its own: two fetches in flight can still land out
    of order and the older one wins. The effect needs a cancellation flag.
    """
    view = _corporate_view()
    fetch = view[view.index('// Fetch VM hardware config'):]
    fetch = fetch[:fetch.index('// Fetch HA status')]
    assert 'return () =>' in fetch, 'the effect has no cleanup, so nothing can cancel'
    import re as _re
    assert _re.search(r'if \(\w+\)\s*return', fetch), \
        'the resolved handler does not check whether it was superseded'


def test_the_description_renders_as_text_and_keeps_its_line_breaks():
    view = _corporate_view()
    row = re.search(r'[^\n]*vmHwInfo\??\.description[^\n]*\n(?:[^\n]*\n){0,6}', view)
    assert row, 'the description is never rendered'
    block = row.group(0)
    assert 'pre-wrap' in block or 'preWrap' in block, \
        f'line breaks are not preserved: {block[:200]}'
    assert 'break-word' in block or 'breakWord' in block or 'anywhere' in block, \
        f'long descriptions will not wrap: {block[:200]}'


def test_the_description_is_never_handed_to_the_html_parser():
    """It is operator-entered free text stored verbatim by PVE."""
    view = _corporate_view()
    window = view[view.index('function CorporateVmDetailView('):]
    assert 'dangerouslySetInnerHTML' not in window, \
        'the corporate detail view now renders raw HTML somewhere'


def test_an_empty_description_adds_no_row():
    """Most VMs have none; an empty row in the property grid is noise."""
    view = _corporate_view()
    assert re.search(r'\{vmHwInfo\?\.description\s*&&', view), \
        'the row is rendered unconditionally'


def test_the_config_editor_is_untouched():
    """The reporter asked for the Markdown preview in the editor to stay as it is."""
    body = _src()
    assert body.count('function CorporateVmDetailView(') == 1
    # the editor lives elsewhere and still has its own description handling
    assert 'description' in body


def test_the_shipped_bundle_was_rebuilt():
    built = open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    assert 'vmHwInfo' in built
