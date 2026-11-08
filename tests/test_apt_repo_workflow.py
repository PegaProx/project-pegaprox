"""apt-repo.yml keeps each privilege in its own job.

The signing key signs whatever is in the publish job's checkout and pool, so that job
builds nothing (no dpkg-buildpackage, no pip, no container) and runs only for a published
release or a manual run from main. The build job, which does run pip and a whole Debian
build, never sees a secret; its smoke test signs with a key it makes up on the spot.
Writing to the release, minting an OIDC token and deploying Pages are separate jobs again.
Read as text, CI has no PyYAML.

NS Oct 2026
"""
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'apt-repo.yml')


def _text():
    with open(WORKFLOW, encoding='utf-8') as fh:
        return fh.read()


def _jobs():
    body = _text().split('\njobs:\n', 1)[1]
    heads = list(re.finditer(r'^  ([a-z][a-z0-9_-]*):\n', body, re.M))
    return {m.group(1): body[m.start():heads[i + 1].start() if i + 1 < len(heads) else len(body)]
            for i, m in enumerate(heads)}


def _code(job):
    """A job without its comment lines."""
    return '\n'.join(line for line in job.splitlines() if not line.lstrip().startswith('#'))


def _permissions(job):
    m = re.search(r'^    permissions:\n((?:      .*\n)+)', job, re.M)
    if not m:
        return {}
    return dict(re.findall(r'^      ([a-z-]+):\s*([a-z]+)', m.group(1), re.M))


def test_triggers_are_a_published_release_and_a_manual_run():
    text = _text()
    on = text[text.index('\non:\n'):text.index('\npermissions:\n')]
    assert 'release:\n    types: [published]' in on
    assert 'workflow_dispatch:' in on
    assert 'push:' not in on and 'pull_request' not in on


def test_the_token_is_read_only_unless_a_job_says_otherwise():
    text = _text()
    top = text[text.index('\npermissions:\n'):text.index('\nconcurrency:\n')]
    assert re.findall(r'^  ([a-z-]+): (\w+)', top, re.M) == [('contents', 'read')]
    perms = {name: _permissions(job) for name, job in _jobs().items()}
    assert perms == {
        'build': {'contents': 'read'},
        'publish': {'contents': 'read', 'attestations': 'read'},
        'deploy': {'pages': 'write', 'id-token': 'write'},
        'attach': {'contents': 'write'},
        'attest': {'id-token': 'write', 'attestations': 'write'},
    }


def test_the_signing_key_is_only_in_the_publish_job():
    jobs = _jobs()
    with_secrets = {name for name, job in jobs.items() if 'secrets.' in _code(job)}
    assert with_secrets == {'publish'}
    assert _text().count('secrets.APT_GPG_PRIVATE_KEY') == 1


def test_the_publish_job_builds_nothing():
    publish = _code(_jobs()['publish'])
    for word in ('dpkg-buildpackage', 'pip ', 'pip3', 'docker', 'build-python-debs', 'setup.py'):
        assert word not in publish, word


def test_publish_runs_for_a_release_or_for_main_only():
    publish = _jobs()['publish']
    cond = re.search(r"^    if: >-\n((?:      .*\n)+)", publish, re.M).group(1)
    cond = ' '.join(cond.split())
    assert cond == ("(github.event_name == 'release' && !github.event.release.prerelease) "
                    "|| (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')")
    assert re.search(r'^    needs: build$', publish, re.M)
    deploy = _jobs()['deploy']
    assert re.search(r'^    needs: publish$', deploy, re.M)
    assert '      name: github-pages' in deploy


def test_attach_and_attest_only_on_a_release():
    jobs = _jobs()
    for name in ('attach', 'attest'):
        assert re.search(r"^    if: github.event_name == 'release'$", jobs[name], re.M), name


def test_the_smoke_test_signs_with_a_throwaway_key():
    build = _code(_jobs()['build'])
    assert '--quick-gen-key' in build
    assert 'build-apt-repo.sh "$RUNNER_TEMP/debs" "$smoke/repo" "$fpr"' in build
    # plain trixie plus that repo: the only sources line the smoke install adds
    with open(os.path.join(ROOT, 'packaging', 'apt', 'smoke-install.sh'), encoding='utf-8') as fh:
        smoke = fh.read()
    assert re.findall(r'^echo "deb .*', smoke, re.M) == [
        'echo "deb [signed-by=/etc/apt/keyrings/pegaprox.asc] http://127.0.0.1:8079 trixie main" \\']


def test_the_publish_job_checks_the_key_against_the_committed_one():
    publish = _code(_jobs()['publish'])
    assert 'gpg --show-keys --with-colons packaging/apt/pegaprox-archive-keyring.asc' in publish
    assert '[ "$have" != "$want" ]' in publish
    assert 'gpgv --keyring "$RUNNER_TEMP/pinned.gpg"' in publish


def _bytecode_check():
    """The __pycache__ check of smoke-install.sh, as it runs there (set -euo pipefail)."""
    with open(os.path.join(ROOT, 'packaging', 'apt', 'smoke-install.sh'), encoding='utf-8') as fh:
        smoke = fh.read()
    m = re.search(r'^if [^\n]*__pycache__.*?^fi$', smoke, re.M | re.S)
    assert m, 'the __pycache__ check is gone from smoke-install.sh'
    return smoke.split('\n', 1)[0] + '\nset -euo pipefail\n' + m.group(0) + '\necho clean\n'


@pytest.mark.skipif(not shutil.which('bash') or not shutil.which('find'), reason='needs bash and find')
@pytest.mark.parametrize('dirs', [0, 3, 2000])
def test_the_bytecode_check_finds_any_number_of_pycache_dirs(tmp_path, dirs):
    tree = tmp_path / 'usr' / 'lib' / 'pegaprox'
    tree.mkdir(parents=True)
    for i in range(dirs):
        (tree / f'module_with_a_rather_long_directory_name_{i}' / '__pycache__').mkdir(parents=True)
    script = _bytecode_check().replace('/usr/lib/pegaprox', str(tree))
    p = subprocess.run(['bash', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if dirs:
        assert p.returncode == 1 and b'__pycache__ under' in p.stderr, (p.returncode, p.stdout, p.stderr)
    else:
        assert p.returncode == 0 and p.stdout.strip() == b'clean', (p.returncode, p.stdout, p.stderr)
