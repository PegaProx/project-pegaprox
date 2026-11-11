"""release-images.yml attests every image file it attaches to the release.

The publish job attached the ESXi OVAs next to the qcow2 and LXC images, and listed them in
SHA256SUMS.txt, but the provenance step had only the qcow2 and tar.xz globs, so
`gh attestation verify` found nothing for an OVA. Read as text, CI has no PyYAML.

NS Nov 2026
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, '.github', 'workflows', 'release-images.yml')


def _publish():
    with open(WF, encoding='utf-8') as fh:
        text = fh.read()
    m = re.search(r'^  publish:\n(.*?)(?=^  [a-z][\w-]*:$|\Z)', text, re.M | re.S)
    assert m, 'release-images.yml has no publish job'
    return m.group(1)


def _step(name):
    job = _publish()
    start = job.index(f'      - name: {name}\n')
    nxt = re.search(r'^      - (name|uses):', job[start + 1:], re.M)
    return job[start:start + 1 + nxt.start()] if nxt else job[start:]


def _list(step, key):
    """The lines of a `key: |` input of a step."""
    m = re.search(rf'^          {key}: \|\n((?:            \S.*\n)+)', step, re.M)
    assert m, f'no {key} in {step.splitlines()[0]}'
    return {line.strip() for line in m.group(1).splitlines()}


def test_every_image_the_release_gets_is_attested():
    attached = _list(_step('An Release anhängen'), 'files') - {'dist/SHA256SUMS.txt'}
    attested = _list(_step('Herkunft der Images signieren'), 'subject-path')
    assert '.ova' in ' '.join(attached)
    assert attested == attached


def test_the_checksums_and_the_attestations_cover_the_same_kinds_of_file():
    sums = _step('Checksums erzeugen')
    kinds = set(re.findall(r"-name '\*(\.[\w.]+)'", sums))
    attested = _list(_step('Herkunft der Images signieren'), 'subject-path')
    assert {f'dist/**/*{k}' for k in kinds} == attested


def test_the_attestation_comes_before_the_upload():
    job = _publish()
    assert job.index('- name: Herkunft der Images signieren') < job.index('- name: An Release anhängen')
