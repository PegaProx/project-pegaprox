# -*- coding: utf-8 -*-
"""The release SBOM: .github/scripts/release_sbom.py, which .github/workflows/sbom.yml runs on
every published release. The workflow validates the result against the CycloneDX 1.6 schema;
these tests pin what the bill says about PegaProx and its browser libraries."""
import base64
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('release_sbom', ROOT / '.github' / 'scripts' / 'release_sbom.py')
sbom = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sbom)

PY_BOM = {
    'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
    'metadata': {'tools': {'components': [{'type': 'application', 'name': 'cyclonedx-py'}]}},
    'components': [
        {'type': 'library', 'name': 'Flask', 'version': '3.1.3', 'purl': 'pkg:pypi/flask@3.1.3',
         'bom-ref': 'flask==3.1.3'},
        {'type': 'library', 'name': 'pip', 'version': '24.0', 'purl': 'pkg:pypi/pip@24.0',
         'bom-ref': 'pip==24.0'},
    ],
    'dependencies': [{'ref': 'flask==3.1.3', 'dependsOn': []}, {'ref': 'pip==24.0', 'dependsOn': []}],
}


def _bill(tag='v1.4.0'):
    return sbom.build(PY_BOM, tag, ROOT)


def test_pegaprox_is_the_subject_of_the_bill():
    meta = _bill()['metadata']
    c = meta['component']
    assert (c['name'], c['version'], c['type']) == ('pegaprox', '1.4.0', 'application')
    assert c['licenses'] == [{'license': {'id': 'AGPL-3.0-only'}}]
    assert c['purl'] == 'pkg:github/PegaProx/project-pegaprox@v1.4.0'
    refs = {r['type'] for r in c['externalReferences']}
    assert {'vcs', 'security-contact', 'advisories', 'distribution'} <= refs
    assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', meta['timestamp'])


def test_the_browser_libraries_are_listed_at_their_pinned_versions():
    comps = {c['name']: c for c in _bill()['components']}
    assert comps['react']['version'] == '18.3.1' and comps['react']['purl'] == 'pkg:npm/react@18.3.1'
    assert comps['@novnc/novnc']['purl'] == 'pkg:npm/%40novnc/novnc@1.4.0'
    assert comps['html2canvas']['version'] == '1.4.1'
    # "react@18" in a comment of web/index.html is no pin and adds nothing
    assert [c['version'] for c in _bill()['components'] if c['name'] == 'react'] == ['18.3.1']


def test_a_pinned_library_carries_the_hash_the_app_checks():
    app = (ROOT / 'pegaprox' / 'app.py').read_text(encoding='utf-8')
    sri = re.search(r"react@18\.3\.1/umd/react\.production\.min\.js',\s*'sha384-([^']+)'", app).group(1)
    react = next(c for c in _bill()['components'] if c['name'] == 'react')
    assert react['hashes'] == [{'alg': 'SHA-384', 'content': base64.b64decode(sri).hex()}]


def test_the_venv_installer_is_no_dependency():
    bill = _bill()
    assert 'pip' not in {c['name'] for c in bill['components']}
    assert all(d['ref'] != 'pip==24.0' for d in bill['dependencies'])
    subject = bill['metadata']['component']['bom-ref']
    top = next(d for d in bill['dependencies'] if d['ref'] == subject)
    assert 'flask==3.1.3' in top['dependsOn'] and 'pip==24.0' not in top['dependsOn']


@pytest.mark.parametrize('tag', ['', 'latest', "v1.4.0'; rm -rf /", 'v1', 'v1.4.0\n'])
def test_only_a_release_tag_names_a_bill(tag):
    with pytest.raises(ValueError):
        sbom.build(PY_BOM, tag, ROOT)


def _tag_step(tag, tmp_path):
    """Runs the workflow's tag step as bash with the release tag set, returns (rc, output file)."""
    import subprocess
    import textwrap
    # no YAML parser in the CI venv: the `run: |` block under `- id: tag` is cut out by indent
    lines = (ROOT / '.github' / 'workflows' / 'sbom.yml').read_text().splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.strip() == '- id: tag')
    at = next(i for i in range(at, len(lines)) if lines[i].strip() == 'run: |')
    key = len(lines[at]) - len(lines[at].lstrip())
    block = []
    for ln in lines[at + 1:]:
        if ln.strip() and len(ln) - len(ln.lstrip()) <= key:
            break
        block.append(ln)
    script = textwrap.dedent('\n'.join(block))
    assert 'GITHUB_OUTPUT' in script
    out = tmp_path / 'output'
    out.write_text('')
    env = {'PATH': '/usr/bin:/bin', 'RELEASE_TAG_NAME': tag, 'INPUT_TAG': '', 'GITHUB_OUTPUT': str(out)}
    rc = subprocess.run(['bash', '-c', script], env=env, capture_output=True).returncode
    return rc, out.read_text()


def test_the_workflow_hands_on_a_release_tag(tmp_path):
    assert _tag_step('v1.4.0', tmp_path) == (0, 'tag=v1.4.0\n')


def test_a_second_line_in_the_tag_sets_no_output(tmp_path):
    # the line after a valid first one would be read as an output of its own
    rc, written = _tag_step('v1.4.0\ntag=../../outside', tmp_path)
    assert rc != 0
    assert written == ''
