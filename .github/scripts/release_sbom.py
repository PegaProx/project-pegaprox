#!/usr/bin/env python3
"""The software bill of materials of a PegaProx release, CycloneDX JSON.

NS Oct 2026 - for the Cyber Resilience Act duties of those who build PegaProx into a
product of their own. Run by .github/workflows/sbom.yml: cyclonedx-py lists the Python
environment a fresh `pip install -r requirements.txt` gives, this script names PegaProx
itself as the component the bill describes and adds the browser libraries the web UI
loads, taken from the pinned URLs in web/index.html and pegaprox/app.py (both carry the
exact version, app.py the SRI hash too). Informational: no support or warranty comes
with it, the same as with the software.

    release_sbom.py --python-bom py.cdx.json --tag v1.4.0 --root . --out out.cdx.json
"""
import argparse
import base64
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = 'https://github.com/PegaProx/project-pegaprox'
# npm packages on jsdelivr and cdnjs libraries, exact x.y.z versions only ("react@18" in a
# comment is no pin)
_JSDELIVR = re.compile(r"https://cdn\.jsdelivr\.net/npm/((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)@(\d+\.\d+\.\d+)/[^'\"\s)]*")
_CDNJS = re.compile(r"https://cdnjs\.cloudflare\.com/ajax/libs/([a-z0-9._-]+)/(\d+\.\d+\.\d+)/[^'\"\s)]*")
_PINNED = re.compile(r"'(https://cdn\.jsdelivr\.net/npm/[^']+)',\s*'(sha384-[A-Za-z0-9+/=]+)'")
_TAG = re.compile(r'^v?\d+(\.\d+){1,3}([-.][0-9A-Za-z.]+)?$')
_VENV_TOOLING = {'pip', 'setuptools', 'wheel'}


def _purl_npm(name, version):
    # a scoped name keeps its slash, the @ of the scope is encoded
    return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{version}"


def frontend_components(root):
    """[component] of the browser libraries the UI loads, one per name and version."""
    root = Path(root)
    texts = []
    for rel in ('web/index.html', 'pegaprox/app.py'):
        p = root / rel
        if p.exists():
            texts.append(p.read_text(encoding='utf-8', errors='replace'))
    blob = '\n'.join(texts)
    hashes = {}
    for url, sri in _PINNED.findall(blob):
        hashes[url] = base64.b64decode(sri[len('sha384-'):]).hex()
    found = {}
    for m in _JSDELIVR.finditer(blob):
        name, version = m.group(1), m.group(2)
        comp = found.setdefault(('npm', name, version), {
            'type': 'library', 'name': name, 'version': version,
            'purl': _purl_npm(name, version), 'bom-ref': _purl_npm(name, version),
            'properties': [{'name': 'pegaprox:delivery',
                            'value': 'loaded by the web UI, a copy ships in static/'}],
        })
        digest = hashes.get(m.group(0))
        if digest and not comp.get('hashes'):
            comp['hashes'] = [{'alg': 'SHA-384', 'content': digest}]
    for m in _CDNJS.finditer(blob):
        name, version = m.group(1), m.group(2)
        found.setdefault(('cdnjs', name, version), {
            'type': 'library', 'name': name, 'version': version,
            'purl': _purl_npm(name, version), 'bom-ref': f'cdnjs:{name}@{version}',
            'properties': [{'name': 'pegaprox:delivery', 'value': 'loaded by the web UI'}],
        })
    return [found[k] for k in sorted(found)]


def build(python_bom, tag, root, now=None):
    """The release bill: the Python bill with PegaProx as its subject and the browser
    libraries added."""
    if not _TAG.fullmatch(tag or ''):
        raise ValueError(f'not a release tag: {tag!r}')
    version = tag[1:] if tag.startswith('v') else tag
    bom = dict(python_bom)
    bom['bomFormat'] = 'CycloneDX'
    bom['serialNumber'] = f'urn:uuid:{uuid.uuid4()}'
    bom['version'] = 1
    meta = dict(bom.get('metadata') or {})
    meta['timestamp'] = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    subject = {
        'type': 'application', 'name': 'pegaprox', 'version': version,
        'bom-ref': f'pkg:github/PegaProx/project-pegaprox@{tag}',
        'purl': f'pkg:github/PegaProx/project-pegaprox@{tag}',
        'description': 'Multi-cluster management for Proxmox VE and XCP-ng',
        'licenses': [{'license': {'id': 'AGPL-3.0-only'}}],
        'supplier': {'name': 'PegaProx Team', 'url': ['https://pegaprox.com']},
        'externalReferences': [
            {'type': 'vcs', 'url': REPO},
            {'type': 'website', 'url': 'https://pegaprox.com'},
            {'type': 'documentation', 'url': 'https://docs.pegaprox.com'},
            {'type': 'security-contact', 'url': f'{REPO}/blob/main/SECURITY.md'},
            {'type': 'advisories', 'url': f'{REPO}/security/advisories'},
            {'type': 'distribution', 'url': f'{REPO}/releases/tag/{tag}'},
        ],
    }
    meta['component'] = subject
    meta['supplier'] = subject['supplier']
    meta.setdefault('properties', []).append({
        'name': 'pegaprox:scope',
        'value': 'Python packages as resolved from requirements.txt when the release was cut, '
                 'and the browser libraries the web UI loads. Informational, no warranty.'})
    bom['metadata'] = meta
    # the venv's own installer is no dependency of PegaProx
    tooling = {c.get('bom-ref') for c in (bom.get('components') or [])
               if str(c.get('purl', '')).startswith('pkg:pypi/') and c.get('name', '').lower() in _VENV_TOOLING}
    comps = [c for c in (bom.get('components') or []) if c.get('bom-ref') not in tooling]
    bom['dependencies'] = [d for d in (bom.get('dependencies') or []) if d.get('ref') not in tooling]
    for d in bom['dependencies']:
        if d.get('dependsOn'):
            d['dependsOn'] = [r for r in d['dependsOn'] if r not in tooling]
    known = {c.get('purl') for c in comps}
    added = [c for c in frontend_components(root) if c['purl'] not in known]
    bom['components'] = comps + added
    # what PegaProx depends on directly: every component of the bill
    deps = [d for d in (bom.get('dependencies') or []) if d.get('ref') != subject['bom-ref']]
    deps.append({'ref': subject['bom-ref'],
                 'dependsOn': sorted({c['bom-ref'] for c in bom['components'] if c.get('bom-ref')})})
    bom['dependencies'] = deps
    return bom


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--python-bom', required=True)
    ap.add_argument('--tag', required=True)
    ap.add_argument('--root', default='.')
    ap.add_argument('--out', required=True)
    a = ap.parse_args(argv)
    with open(a.python_bom, encoding='utf-8') as fh:
        py = json.load(fh)
    bom = build(py, a.tag, a.root)
    with open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(bom, fh, indent=2, ensure_ascii=False)
        fh.write('\n')
    print(f"{a.out}: {len(bom['components'])} components")
    return 0


if __name__ == '__main__':
    sys.exit(main())
