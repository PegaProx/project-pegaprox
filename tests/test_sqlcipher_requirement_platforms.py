"""Which platform pip gives full-DB encryption, and never with both SQLCipher packages.

dbcrypto imports the module sqlcipher3, which two packages provide: sqlcipher3-binary
(Linux x86_64 wheels only) and, since 0.6.4, sqlcipher3 with its own wheels for aarch64
Linux, macOS and Windows. Both write sqlcipher3/ into site-packages, so a platform that
got both would break on the first uninstall of either. 32-bit ARM has no wheel of either
and must get none, or `pip install -r requirements.txt` tries to compile SQLCipher there
and the whole install fails. The markers are read from requirements.txt as pip reads them.
MK Nov 2026
"""
import os
import re

import pytest

try:
    from packaging.markers import Marker
except ImportError:  # the CI venv may not carry packaging; pip always vendors it
    try:
        from pip._vendor.packaging.markers import Marker
    except ImportError:  # pragma: no cover
        Marker = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGES = ('sqlcipher3-binary', 'sqlcipher3')

# (sys_platform, platform_machine) as Python reports them there
PLATFORMS = {
    'linux-x86_64': ('linux', 'x86_64'),
    'linux-aarch64': ('linux', 'aarch64'),
    'linux-armv7l': ('linux', 'armv7l'),
    'macos-arm64': ('darwin', 'arm64'),
    'macos-x86_64': ('darwin', 'x86_64'),
    'windows-amd64': ('win32', 'AMD64'),
    'windows-arm64': ('win32', 'ARM64'),
}


def _lines():
    with open(os.path.join(ROOT, 'requirements.txt'), encoding='utf-8') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*[<>=!~][^;]*(?:;\s*(.+))?$', line)
            if m and m.group(1).lower() in PACKAGES:
                yield m.group(1).lower(), m.group(2)


def _installs(platform):
    sys_platform, machine = PLATFORMS[platform]
    env = {'sys_platform': sys_platform, 'platform_machine': machine}
    return sorted(name for name, marker in _lines() if marker is None or Marker(marker).evaluate(env))


pytestmark = pytest.mark.skipif(Marker is None, reason='no packaging module to read the markers with')


def test_both_packages_are_in_the_requirements():
    assert sorted(name for name, _ in _lines()) == sorted(PACKAGES)


@pytest.mark.parametrize('platform', sorted(PLATFORMS))
def test_no_platform_gets_both_packages(platform):
    assert len(_installs(platform)) <= 1, (platform, _installs(platform))


@pytest.mark.parametrize('platform,package', [
    ('linux-x86_64', 'sqlcipher3-binary'),
    ('linux-aarch64', 'sqlcipher3'),
    ('macos-arm64', 'sqlcipher3'),
    ('macos-x86_64', 'sqlcipher3'),
    ('windows-amd64', 'sqlcipher3'),
    ('windows-arm64', 'sqlcipher3'),
])
def test_a_platform_with_wheels_gets_full_db_encryption(platform, package):
    assert _installs(platform) == [package], platform


def test_32_bit_arm_gets_neither_and_stays_installable():
    assert _installs('linux-armv7l') == []
