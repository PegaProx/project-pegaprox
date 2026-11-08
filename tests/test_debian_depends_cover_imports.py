"""debian/control has to name every library the package imports.

The .deb runs on the system python3 and its python3-* packages, nothing else. A module
pegaprox imports that no Depends entry brings in fails only once its code path runs:
defusedxml (XCP-ng RRD and iSCSI probe parsing) and requests_toolbelt (ISO upload) were
missing that way, both imported inside a function, so the package installed and started.

The scan reads every import in pegaprox/**, pegaprox_multi_cluster.py, the bundled plugins
and the helper scripts vms.py writes out at runtime, top-level or lazy, maps each
third-party module through packaging/apt/deb_imports.py and checks the package against
Depends. A module PegaProx runs without is listed in OPTIONAL there, with the reason; the
smoke test of apt-repo.yml imports the same map on a fresh trixie install.

NS Oct 2026
"""
import ast
import functools
import importlib.util
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTROL = os.path.join(ROOT, 'debian', 'control')
FIRST_PARTY = {'pegaprox', 'plugins'}


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


deb_imports = _load('deb_imports', 'packaging/apt/deb_imports.py')


def _sources():
    yield 'pegaprox_multi_cluster.py'
    for top in ('pegaprox', 'plugins', os.path.join('packaging', 'plugins')):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
            dirnames[:] = sorted(d for d in dirnames if d != '__pycache__')
            for f in sorted(filenames):
                if f.endswith('.py'):
                    yield os.path.relpath(os.path.join(dirpath, f), ROOT)


def _imports_in(tree, where):
    """(module, location) for every absolute import, including those of a script kept in a
    string constant (vms.py writes the SSH WebSocket server out of one and runs it)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split('.')[0], f'{where}:{node.lineno}'
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split('.')[0], f'{where}:{node.lineno}'
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and node.value.startswith('#!/usr/bin/env python')):
            yield from _imports_in(ast.parse(node.value), f'{where}:{node.lineno} (generated script)')


@functools.lru_cache(maxsize=None)
def third_party_imports():
    found = {}
    for rel in _sources():
        with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), rel)
        for mod, loc in _imports_in(tree, rel):
            if mod in sys.stdlib_module_names or mod in FIRST_PARTY:
                continue
            found.setdefault(mod, []).append(loc)
    return found


def depends_of(control_text, package='pegaprox'):
    """The package names in Depends of one binary stanza, alternatives and qualifiers off."""
    for stanza in re.split(r'\n\s*\n', control_text):
        if re.search(rf'^Package:\s*{re.escape(package)}\s*$', stanza, re.M):
            m = re.search(r'^Depends:(.*(?:\n[ \t].*)*)', stanza, re.M)
            names = set()
            for entry in (m.group(1) if m else '').replace('\n', ' ').split(','):
                for alt in entry.split('|'):
                    name = re.sub(r'\(.*?\)|\[.*?\]|<.*?>', '', alt).strip().split(':')[0]
                    if name and not name.startswith('${'):
                        names.add(name)
            return names
    raise AssertionError(f'no stanza for {package} in debian/control')


def problems(imports, depends):
    out = []
    for mod, locs in sorted(imports.items()):
        if mod in deb_imports.OPTIONAL:
            continue
        deb = deb_imports.DEPENDS.get(mod)
        if deb is None:
            out.append(f'{mod} ({locs[0]}) is neither in DEPENDS nor in OPTIONAL of '
                       f'packaging/apt/deb_imports.py')
        elif deb not in depends:
            out.append(f'{mod} ({locs[0]}) needs {deb} in Depends of debian/control')
    return out


def _control():
    with open(CONTROL, encoding='utf-8') as fh:
        return fh.read()


def test_every_import_of_the_package_has_a_depends_entry():
    assert problems(third_party_imports(), depends_of(_control())) == []


def test_without_defusedxml_in_depends_it_goes_red():
    """The counterproof: the gap this file was written for, put back."""
    text = _control()
    assert 'python3-defusedxml' in depends_of(text)
    # drop the entry wherever it sits; as the last one it takes the comma before it along
    without = re.sub(r'^[ \t]+python3-defusedxml,\n', '', text, flags=re.M)
    if without == text:
        without = re.sub(r',\n[ \t]+python3-defusedxml\n', '\n', text)
    assert 'python3-defusedxml' not in depends_of(without)
    found = problems(third_party_imports(), depends_of(without))
    assert len(found) == 1 and found[0].startswith('defusedxml (pegaprox/core/xcpng.py:'), found


def test_an_import_nobody_mapped_is_not_waved_through():
    found = problems({'yaml': ['pegaprox/x.py:1']}, depends_of(_control()))
    assert found == ['yaml (pegaprox/x.py:1) is neither in DEPENDS nor in OPTIONAL of '
                     'packaging/apt/deb_imports.py']


def test_the_scan_sees_lazy_imports_and_the_generated_script():
    imports = third_party_imports()
    # inside a method of the XCP-ng manager, not at module level
    assert any(loc.startswith('pegaprox/core/xcpng.py:') for loc in imports['defusedxml'])
    assert any(loc.startswith('pegaprox/api/vms.py:') for loc in imports['requests_toolbelt'])
    assert any('(generated script)' in loc for loc in imports['websockets'])


def test_the_optional_list_names_only_modules_still_imported():
    stale = sorted(set(deb_imports.OPTIONAL) - set(third_party_imports()))
    assert not stale, f'nothing imports these any more, drop them from OPTIONAL: {stale}'


def test_no_module_is_both_required_and_optional():
    assert not set(deb_imports.DEPENDS) & set(deb_imports.OPTIONAL)


def test_trixie_python3_fido2_stays_out():
    """python3-fido2 in trixie is 1.2. With it installed WebAuthn reports itself available
    and register/begin fails in jsonify (fido2 1.x keeps bytes in its options unless
    webauthn_json_mapping is switched on), so the package does not pull it in."""
    assert 'python3-fido2' not in depends_of(_control())


def test_what_trixie_lacks_is_built_by_the_repo():
    built = {p['deb'] for p in _load('build_python_debs', 'packaging/apt/build-python-debs.py').PACKAGES.values()}
    assert built == {'python3-flask-sock', 'python3-xenapi'}
    assert built <= depends_of(_control())
    with open(os.path.join(ROOT, 'packaging', 'apt', 'python-debs', 'requirements.txt'), encoding='utf-8') as fh:
        pins = fh.read()
    for name in ('flask-sock', 'xenapi'):
        assert re.search(rf'^{name}==\S+ \\\n\s+--hash=sha256:[0-9a-f]{{64}}$', pins, re.M), name
    for deb in built:
        assert os.path.isfile(os.path.join(ROOT, 'packaging', 'apt', 'python-debs', f'{deb}.copyright'))


@pytest.mark.parametrize('entry', ['python3-foo (>= 1.0)', 'python3-foo | python3-bar', 'python3-foo:any'])
def test_depends_parsing_strips_versions_alternatives_and_qualifiers(entry):
    text = f'Source: x\n\nPackage: pegaprox\nDepends: ${{misc:Depends}},\n         {entry}\n'
    assert 'python3-foo' in depends_of(text)
