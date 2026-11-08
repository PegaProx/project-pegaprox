"""brotli reaches us only through flask-compress, which takes any version, and deploy.sh,
update.sh and the in-app updater all run a plain `pip install -r`: without a line of our own,
an existing install keeps the brotli it already has. 1.2.0 and older carry an out-of-bounds
write in the decoder (CVE-2026-111497), and urllib3 decodes br replies from every peer we
talk to, so the floor has to be in requirements.txt itself.

MK Oct 2026
"""
from pathlib import Path

from packaging.requirements import Requirement

REPO = Path(__file__).resolve().parent.parent

# every release before the fix, not only the last one: a line like `brotli!=1.2.0`
# shuts out 1.2.0 and still lets an install sit on 1.1.0
BROKEN_BROTLI = ('1.0.9', '1.1.0', '1.2.0')
BROKEN_BROTLICFFI = ('1.0.9.2', '1.1.0.0', '1.2.0.0', '1.2.0.2')


def _lines_for(name, implementation):
    env = {'python_version': '3.12', 'sys_platform': 'linux', 'platform_machine': 'x86_64',
           'platform_python_implementation': implementation}
    found = []
    for line in (REPO / 'requirements.txt').read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        if req.name.lower() == name and (req.marker is None or req.marker.evaluate(env)):
            found.append(req)
    return found


def test_cpython_installs_cannot_stay_on_the_broken_brotli():
    reqs = _lines_for('brotli', 'CPython')
    assert reqs, 'no brotli line applies on CPython'
    for r in reqs:
        for v in BROKEN_BROTLI:
            assert not r.specifier.contains(v), f'{r} still allows {v}'
        assert r.specifier.contains('1.2.1'), str(r)


def test_pypy_installs_cannot_stay_on_the_broken_brotlicffi():
    reqs = _lines_for('brotlicffi', 'PyPy')
    assert reqs, 'no brotlicffi line applies on PyPy'
    for r in reqs:
        for v in BROKEN_BROTLICFFI:
            assert not r.specifier.contains(v), f'{r} still allows {v}'
        assert r.specifier.contains('1.2.1.0'), str(r)
