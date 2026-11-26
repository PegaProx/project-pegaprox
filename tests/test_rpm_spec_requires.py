"""packaging/rpm/pegaprox.spec has to require every library the package imports.

The spec stayed at 0.6.6 while PegaProx grew, and PyJWT and websocket-client went into
requirements.txt and debian/control but never into its Requires. api/vms.py imports
utils/vnc_polling.py, which imports websocket at module level, so an RPM install without
python3-websocket-client does not start at all; without python3-jwt every OIDC login is
refused (utils/oidc.py).

test_debian_depends_cover_imports.py holds debian/control to every import. This file holds
the spec to debian/control: each Depends entry has its Fedora name in DEB_TO_RPM or a reason
in DEB_ONLY, and each name there is a Requires line of the spec.

MK Nov 2026
"""
import datetime
import os
import re

import pytest

from test_debian_depends_cover_imports import deb_imports, depends_of, third_party_imports

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, 'packaging', 'rpm', 'pegaprox.spec')
CONTROL = os.path.join(ROOT, 'debian', 'control')

# Debian package -> the package of the same files in Fedora (checked against Fedora 43 and
# rawhide). flask-sock, gevent-websocket, XenAPI and sqlcipher3 are in neither Fedora nor
# EPEL; the spec names them the way Fedora would and they are built locally.
DEB_TO_RPM = {
    'python3': 'python3',
    'python3-dnspython': 'python3-dns',
    'python3-flask': 'python3-flask',
    'python3-flask-cors': 'python3-flask-cors',
    'python3-flask-sock': 'python3-flask-sock',
    'python3-flask-compress': 'python3-flask-compress',
    'python3-werkzeug': 'python3-werkzeug',
    'python3-jwt': 'python3-jwt',
    'python3-requests': 'python3-requests',
    'python3-requests-toolbelt': 'python3-requests-toolbelt',
    'python3-urllib3': 'python3-urllib3',
    'python3-cryptography': 'python3-cryptography',
    'python3-openssl': 'python3-pyOpenSSL',
    'python3-argon2': 'python3-argon2-cffi',
    'python3-paramiko': 'python3-paramiko',
    'python3-websockets': 'python3-websockets',
    'python3-websocket': 'python3-websocket-client',
    'python3-simple-websocket': 'python3-simple-websocket',
    'python3-wsproto': 'python3-wsproto',
    'python3-gevent': 'python3-gevent',
    'python3-greenlet': 'python3-greenlet',
    'python3-gevent-websocket': 'python3-gevent-websocket',
    'python3-pyotp': 'python3-pyotp',
    'python3-qrcode': 'python3-qrcode',
    'python3-pil': 'python3-pillow',
    'python3-ldap3': 'python3-ldap3',
    'python3-pyvmomi': 'python3-pyvmomi',
    'python3-xenapi': 'python3-xenapi',
    'python3-defusedxml': 'python3-defusedxml',
    'python3-sqlcipher3': 'python3-sqlcipher3',
    'sqlcipher': 'sqlcipher',
}

# Debian package -> the module it brings; in debian/control, imported by nothing
DEB_ONLY = {
    'python3-netifaces': 'netifaces',
    'python3-flask-sockets': 'flask_sockets',
}

_DAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
_MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def requires_of(spec_text):
    """Every name on a Requires line, in order, version constraints and commas off.
    BuildRequires is not a runtime dependency and does not count."""
    names = []
    for m in re.finditer(r'^Requires(?:\([^)]*\))?:[ \t]*(.+)$', spec_text, re.M):
        value = re.sub(r'(?:>=|<=|=|<|>)\s*\S+', '', m.group(1))
        names.extend(tok for tok in re.split(r'[\s,]+', value) if tok)
    return names


def missing_requires(spec_text, control_text):
    requires = set(requires_of(spec_text))
    out = []
    for deb in sorted(depends_of(control_text) - set(DEB_ONLY)):
        rpm = DEB_TO_RPM.get(deb)
        if rpm is None or rpm in requires:
            continue
        mods = sorted(m for m, d in deb_imports.DEPENDS.items() if d == deb)
        out.append(f'{rpm} ({", ".join(mods) if mods else "debian/control, no import"})')
    return out


def test_every_depends_entry_of_the_deb_has_an_rpm_name():
    depends = depends_of(_read(CONTROL))
    unnamed = sorted(depends - set(DEB_TO_RPM) - set(DEB_ONLY))
    assert not unnamed, (f'debian/control depends on {unnamed}: put the Fedora package into '
                         f'DEB_TO_RPM here and a Requires line into packaging/rpm/pegaprox.spec')
    stale = sorted((set(DEB_TO_RPM) | set(DEB_ONLY)) - depends)
    assert not stale, f'no longer in debian/control, drop them here: {stale}'


def test_the_spec_requires_every_package_the_deb_depends_on():
    assert missing_requires(_read(SPEC), _read(CONTROL)) == []


def test_pyjwt_and_websocket_client_are_required():
    """The two that were missing, by name: both are imported, neither was required."""
    imports = third_party_imports()
    assert any(loc.startswith('pegaprox/utils/oidc.py:') for loc in imports['jwt'])
    assert any(loc.startswith('pegaprox/utils/vnc_polling.py:') for loc in imports['websocket'])
    requires = requires_of(_read(SPEC))
    assert 'python3-jwt' in requires
    assert 'python3-websocket-client' in requires


def test_without_a_requires_line_it_goes_red():
    spec = _read(SPEC)
    without = re.sub(r'^Requires:[ \t]*python3-websocket-client[ \t]*\n', '', spec, flags=re.M)
    assert without != spec
    assert missing_requires(without, _read(CONTROL)) == ['python3-websocket-client (websocket)']


def test_what_only_the_deb_names_is_imported_by_nothing():
    imports = third_party_imports()
    for deb, mod in DEB_ONLY.items():
        assert mod not in imports, f'{mod} is imported now: move {deb} into DEB_TO_RPM'
        assert deb not in deb_imports.DEPENDS.values()


def test_the_spec_names_each_requires_once():
    names = requires_of(_read(SPEC))
    twice = sorted({n for n in names if names.count(n) > 1})
    assert not twice, f'named more than once in packaging/rpm/pegaprox.spec: {twice}'


@pytest.mark.parametrize('line', ['Requires:       python3-foo', 'Requires: python3-foo >= 1.0',
                                  'Requires: python3-bar, python3-foo', 'Requires(post): python3-foo'])
def test_requires_parsing(line):
    assert 'python3-foo' in requires_of(f'Name: x\n{line}\n')


def test_build_requires_is_not_a_runtime_dependency():
    assert requires_of('BuildRequires:  python3-devel\nRequires: python3\n') == ['python3']


def _changelog_dates(spec_text):
    body = spec_text.split('\n%changelog\n', 1)[1]
    return [m.groups() for m in re.finditer(r'^\* (\w{3}) (\w{3}) +(\d{1,2}) (\d{4}) ', body, re.M)]


def test_the_changelog_dates_are_real_and_newest_first():
    """rpmbuild warns on a weekday that does not fit the date and stops on entries out of
    order, and a hand-written entry gets both wrong easily."""
    entries = _changelog_dates(_read(SPEC))
    assert entries, 'no %changelog entries in packaging/rpm/pegaprox.spec'
    dates = []
    for day, month, mday, year in entries:
        when = datetime.date(int(year), _MONTHS.index(month) + 1, int(mday))
        assert _DAYS[when.weekday()] == day, f'{day} {month} {mday} {year} is a {_DAYS[when.weekday()]}'
        dates.append(when)
    assert dates == sorted(dates, reverse=True), dates
