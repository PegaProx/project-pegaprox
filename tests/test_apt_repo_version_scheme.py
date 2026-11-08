"""The version our APT repository gives a release, against the third-party build of it.

The third-party repo ships release X as "X-1". Until that is settled with its
maintainer, our build of X sorts below that, so a host with both repos keeps the package
it has; SUFFIX in packaging/apt/deb-version.sh is the one switch that turns it around.
Whatever SUFFIX says, the result has no '-' (debian/source/format is 3.0 native), a
pre-release sorts below its release, and a newer release of ours beats an older one of
theirs. dpkg --compare-versions is the judge, as on the host.

NS Oct 2026
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packaging', 'apt', 'deb-version.sh')

pytestmark = pytest.mark.skipif(not shutil.which('dpkg'), reason='needs dpkg --compare-versions')


def _ours(upstream=None, script=SCRIPT):
    out = subprocess.run(['bash', script] + ([upstream] if upstream else []),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def _cmp(a, op, b):
    return subprocess.run(['dpkg', '--compare-versions', a, op, b]).returncode == 0


def _suffix(script=SCRIPT):
    with open(script, encoding='utf-8') as fh:
        return re.search(r'^SUFFIX="([^"]*)"$', fh.read(), re.M).group(1)


def _with_suffix(tmp_path, suffix):
    with open(SCRIPT, encoding='utf-8') as fh:
        text = re.sub(r'^SUFFIX="[^"]*"$', f'SUFFIX="{suffix}"', fh.read(), flags=re.M)
    path = tmp_path / 'deb-version.sh'
    path.write_text(text)
    return str(path)


def test_default_is_the_version_json_release():
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        upstream = json.load(fh)['version']
    assert _ours() == _ours(upstream)


def test_the_committed_switch_does_what_it_says():
    """Empty: ours yields to the third-party "X-1" (the setting until that is settled).
    A "+..." suffix: ours wins. Either way only SUFFIX has to change."""
    suffix = _suffix()
    for upstream in ('1.4.0', '1.0', '0.9.14.1'):
        ours = _ours(upstream)
        assert ours == upstream + suffix
        op = 'lt' if suffix == '' else 'gt'
        assert _cmp(ours, op, f'{upstream}-1') and _cmp(ours, op, f'{upstream}-2'), (ours, op)


def test_a_plus_suffix_wins_over_it(tmp_path):
    script = _with_suffix(tmp_path, '+pegaprox1')
    ours = _ours('1.4.0', script)
    assert ours == '1.4.0+pegaprox1'
    assert _cmp(ours, 'gt', '1.4.0-1') and _cmp(ours, 'gt', '1.4.0-2')
    # and above what the empty suffix gave, so flipping it upgrades our own hosts too
    assert _cmp(ours, 'gt', '1.4.0')


@pytest.mark.parametrize('suffix', ['', '+pegaprox1'])
def test_ordering_that_holds_either_way(tmp_path, suffix):
    script = _with_suffix(tmp_path, suffix)
    v = {u: _ours(u, script) for u in ('1.4.0', '1.4.1', '1.5.0-rc1', '1.5.0-rc2', '1.5.0')}
    assert not any('-' in x for x in v.values()), v
    assert v['1.5.0-rc1'] == f'1.5.0~rc1{suffix}'
    assert _cmp(v['1.4.0'], 'lt', v['1.4.1'])
    assert _cmp(v['1.4.1'], 'gt', '1.4.0-1')
    assert _cmp(v['1.4.1'], 'lt', v['1.5.0-rc1'])
    assert _cmp(v['1.5.0-rc1'], 'lt', v['1.5.0-rc2'])
    assert _cmp(v['1.5.0-rc2'], 'lt', v['1.5.0'])


@pytest.mark.parametrize('bad', ["1.4.0'; id", 'v1.4.0', '1.4.0-1-2', '1.4.0 '])
def test_versions_we_never_cut_are_refused(bad):
    out = subprocess.run(['bash', SCRIPT, bad], capture_output=True, text=True)
    assert out.returncode != 0 and not out.stdout


def test_a_suffix_with_a_revision_is_refused(tmp_path):
    out = subprocess.run(['bash', _with_suffix(tmp_path, '-1'), '1.4.0'], capture_output=True, text=True)
    assert out.returncode != 0 and not out.stdout


def test_the_workflow_takes_its_version_from_the_script():
    with open(os.path.join(ROOT, '.github', 'workflows', 'apt-repo.yml'), encoding='utf-8') as fh:
        assert 'packaging/apt/deb-version.sh' in fh.read()
