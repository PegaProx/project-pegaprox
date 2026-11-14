"""The SMBIOS card of a VM (Options tab, the redesign shows it too) reads and writes smbios1
the way the PVE GUI does (pve-manager Parser.js parseQemuSmbios1 / printQemuSmbios1): every
value but the uuid base64-encoded, with base64=1 when one is set. qemu-server takes only
[A-Za-z0-9+/]+={0,2} in a value unless it is base64.

The card ignored the flag: a value the PVE GUI wrote showed as its encoded text, the next
edit dropped base64=1, and each keystroke stripped everything but A-Za-z0-9, so a space, a
dot or a '=' vanished as it was typed. Editing in PVE and here turned the values back and
forth.

The reader and the writer run in node; the card is checked in its source. LW Nov 2026
"""
import base64
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, 'web', 'src')
UUID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'
EMPTY = {'uuid': '', 'manufacturer': '', 'product': '', 'version': '', 'serial': '', 'sku': '', 'family': ''}
LANGS = ('de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru')


def _read(name):
    with open(os.path.join(WEB, name), encoding='utf-8') as fh:
        return fh.read()


def _b64(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def _helpers():
    """vm_config.js from SMBIOS1_FIELDS to the end of smbios1Value"""
    src = _read('vm_config.js')
    assert 'function parseSmbios1(' in src and 'function smbios1Value(' in src, \
        'the SMBIOS card has no reader and writer that know base64=1'
    start = src.index('const SMBIOS1_FIELDS')
    i = src.index('{', src.index('function smbios1Value('))
    depth = 0
    for j in range(i, len(src)):
        depth += {'{': 1, '}': -1}.get(src[j], 0)
        if depth == 0:
            return src[start:j + 1]
    raise AssertionError('smbios1Value has no end')


def _js(expr):
    js = _helpers() + f'\nconsole.log(JSON.stringify({expr}));'
    out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _card():
    src = _read('vm_config.js')
    start = src.index('const renderSmbiosCard = () => (')
    return src[start:src.index('\n            );\n', start)]


needs_node = pytest.mark.skipif(not shutil.which('node'), reason='needs node')


@needs_node
def test_a_value_the_pve_gui_wrote_reads_as_its_text():
    gui = (f'uuid={UUID},manufacturer={_b64("Dell Inc.")},product={_b64("PowerEdge R740")},'
           f'serial={_b64("ÄÖÜ-123 / x=y")},base64=1')
    assert _js(f'parseSmbios1({json.dumps(gui)})') == dict(
        EMPTY, uuid=UUID, manufacturer='Dell Inc.', product='PowerEdge R740', serial='ÄÖÜ-123 / x=y')
    # without the flag a value is what it says
    assert _js('parseSmbios1("manufacturer=Dell,product=R740")') == dict(EMPTY, manufacturer='Dell', product='R740')
    assert _js('parseSmbios1("")') == EMPTY


@needs_node
def test_the_card_writes_what_the_pve_gui_writes():
    fields = dict(EMPTY, uuid=UUID, manufacturer='Dell Inc.', product='a=b,c', serial=' x ', sku='Ü')
    got = _js(f'smbios1Value({json.dumps(fields)})')
    assert got == (f'uuid={UUID},manufacturer={_b64("Dell Inc.")},product={_b64("a=b,c")},'
                   f'serial={_b64(" x ")},sku={_b64("Ü")},base64=1')
    for part in got.split(','):
        key, value = part.split('=', 1)
        if key not in ('uuid', 'base64'):
            assert re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value), part
    # a uuid alone needs no flag, nothing set is no value
    assert _js(f'smbios1Value({json.dumps(dict(EMPTY, uuid=UUID))})') == f'uuid={UUID}'
    assert _js(f'smbios1Value({json.dumps(EMPTY)})') == ''


@needs_node
def test_what_is_typed_comes_back_as_typed():
    typed = ['Dell ', 'v1.2-beta', 'a,b', 'x=y', 'Müller GmbH', '  ', '+/=']
    rows = [dict(EMPTY, uuid=UUID, manufacturer=v, family=v) for v in typed]
    assert _js(f'{json.dumps(rows)}.map(r => parseSmbios1(smbios1Value(r)))') == rows


def test_the_card_strips_nothing_and_writes_through_the_writer():
    card = _card()
    assert not re.search(r'\.replace\(/\[\^A-Za-z0-9', card), 'the card still strips what is typed'
    assert 'const smbios = parseSmbios1(' in card
    upd = re.search(r'const updateSmbios = \(field, value\) => \{(.*?)\n\s*\};', card, re.S)
    assert upd and 'smbios1Value(newSmbios)' in upd.group(1)
    for field in ('manufacturer', 'product', 'version', 'serial', 'sku', 'family'):
        assert f"onChange={{(e) => updateSmbios('{field}', e.target.value)}}" in card, field
    # the stored value stays on show as it is
    assert re.search(r"<code[^>]*>\s*\{getValue\('options', 'smbios1'\)\}\s*</code>", card)


def test_presets_go_through_the_writer():
    card = _card()
    # no smbios1 string is put together by hand any more
    assert 'manufacturer=' not in card
    presets = re.findall(r"applySmbiosPreset\(\{", card)
    assert len(presets) >= 5, presets
    assert re.search(r'const applySmbiosPreset = \(values\) =>\s*handleChange\(\'options\', \'smbios1\', '
                     r'smbios1Value\(\{ uuid: smbios\.uuid, \.\.\.values \}\)\)', card)


def test_the_format_hint_says_what_the_card_does_in_every_language():
    card = _card()
    assert 'A-Za-z0-9' not in card
    assert "t('smbiosFormatHint')" in card
    src = _read('translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            (\w\w): \{$', src, re.M)]
    assert [lang for lang, _ in starts] == list(LANGS)
    for (lang, at), (_, end) in zip(starts, starts[1:] + [('', len(src))]):
        hint = re.findall(r"^                smbiosFormatHint: '((?:[^'\\]|\\.)*)',$", src[at:end], re.M)
        assert len(hint) == 1, lang
        assert 'A-Za-z0-9' not in hint[0] and 'base64=1' in hint[0], (lang, hint[0])
