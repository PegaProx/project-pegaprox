"""requirements.txt goes through a single `pip install -r` in deploy.sh, update.sh and the
in-app updater. One line pip finds no release for fails the whole install, and deploy.sh
hides pip's output and calls the environment ready over an empty venv.

Pillow 13.0 closes a heap overflow in the FlashPix decoder (#1160) and needs Python 3.11.
README and deploy.sh still take 3.10, and the last Pillow with 3.10 wheels is 12.3.0, so 3.10
keeps its own line instead of losing every package.

MK Oct 2026 (#1160)
"""
from pathlib import Path

from packaging.requirements import Requirement

REPO = Path(__file__).resolve().parent.parent


def _pillow_for(python_version):
    env = {'python_version': python_version, 'sys_platform': 'linux', 'platform_machine': 'x86_64'}
    found = []
    for line in (REPO / 'requirements.txt').read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        if req.name.lower() == 'pillow' and (req.marker is None or req.marker.evaluate(env)):
            found.append(req)
    return found


def test_python_3_10_still_gets_a_pillow_that_exists_for_it():
    reqs = _pillow_for('3.10')
    assert reqs, 'no pillow line applies on 3.10'
    assert all(r.specifier.contains('12.3.0') for r in reqs), [str(r) for r in reqs]


def test_python_3_11_and_newer_get_the_fixed_pillow():
    for v in ('3.11', '3.12', '3.13'):
        reqs = _pillow_for(v)
        assert reqs, f'no pillow line applies on {v}'
        for r in reqs:
            assert not r.specifier.contains('12.3.0'), (v, str(r))
            assert r.specifier.contains('13.0.0'), (v, str(r))
