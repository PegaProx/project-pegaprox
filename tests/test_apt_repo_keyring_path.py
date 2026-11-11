"""build-apt-repo.sh takes the keyring relative to where it is called from.

The publish job runs it from the checkout with packaging/apt/pegaprox-archive-keyring.asc,
and the script reads the keyring after its cd into the output directory, so gpg looked for
the file under the new repository and every signed publish stopped before index.html. The
path is resolved before the cd now, and a keyring that is not there stops the script before
it builds anything.

The script runs for real here: a throwaway key in its own GNUPGHOME, one Architecture: all
package, and a caller directory laid out like the checkout.

NS Nov 2026
"""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packaging', 'apt', 'build-apt-repo.sh')
KEYRING = os.path.join('packaging', 'apt', 'pegaprox-archive-keyring.asc')

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ('gpg', 'apt-ftparchive', 'dpkg-deb', 'gzip')),
    reason='needs gpg, apt-ftparchive and dpkg-deb')


@pytest.fixture
def repo(tmp_path):
    home = tmp_path / 'gnupg'
    home.mkdir(mode=0o700)
    env = {**os.environ, 'GNUPGHOME': str(home)}
    subprocess.run(['gpg', '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', '',
                    '--quick-gen-key', 'APT test <apt-test@invalid>', 'ed25519', 'sign', '1d'],
                   env=env, check=True, capture_output=True, timeout=60)
    keys = subprocess.run(['gpg', '--list-keys', '--with-colons'], env=env, check=True,
                          capture_output=True, text=True).stdout
    fpr = next(line.split(':')[9] for line in keys.splitlines() if line.startswith('fpr:'))
    checkout = tmp_path / 'checkout'
    (checkout / 'packaging' / 'apt').mkdir(parents=True)
    (checkout / KEYRING).write_bytes(subprocess.run(['gpg', '--armor', '--export', fpr], env=env,
                                                    check=True, capture_output=True).stdout)
    pkg = tmp_path / 'pkg'
    (pkg / 'DEBIAN').mkdir(parents=True)
    (pkg / 'DEBIAN' / 'control').write_text(
        'Package: pegaprox\nVersion: 1.5.0-1\nArchitecture: all\nMaintainer: x <x@invalid>\n'
        'Description: test\n')
    for d in (pkg, pkg / 'DEBIAN'):
        os.chmod(d, 0o755)
    pool = tmp_path / 'pool'
    pool.mkdir()
    subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(pkg), str(pool / 'pegaprox_1.5.0-1_all.deb')],
                   check=True, capture_output=True)

    def run(site, *keyring):
        return subprocess.run(['bash', SCRIPT, str(pool), str(site), fpr, *keyring], cwd=str(checkout),
                              env=env, capture_output=True, text=True, timeout=120)

    yield run, checkout, tmp_path
    if shutil.which('gpgconf'):
        subprocess.run(['gpgconf', '--kill', 'gpg-agent'], env=env, capture_output=True)


def test_the_keyring_as_the_publish_job_passes_it(repo):
    run, checkout, tmp = repo
    site = tmp / 'site'
    p = run(site, KEYRING)
    assert p.returncode == 0, p.stderr
    with open(site / 'pegaprox-archive-keyring.asc', 'rb') as a, open(checkout / KEYRING, 'rb') as b:
        assert a.read() == b.read()
    index = (site / 'index.html').read_text()
    assert '<tr><td>pegaprox</td><td>1.5.0-1</td></tr>' in index
    assert (site / 'dists' / 'trixie' / 'InRelease').is_file()


def test_a_keyring_that_is_not_there_stops_before_the_build(repo):
    run, _checkout, tmp = repo
    site = tmp / 'site'
    p = run(site, 'packaging/apt/nope.asc')
    assert p.returncode != 0
    assert 'packaging/apt/nope.asc' in p.stderr
    assert not site.exists()


def test_without_a_keyring_the_smoke_build_still_signs(repo):
    run, _checkout, tmp = repo
    site = tmp / 'site'
    p = run(site)
    assert p.returncode == 0, p.stderr
    assert (site / 'dists' / 'trixie' / 'Release.gpg').is_file()
    assert not (site / 'index.html').exists()
