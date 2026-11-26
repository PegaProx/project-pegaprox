"""packaging/rpm/pegaprox.spec has to require every library the package imports.

The spec stayed at 0.6.6 while PegaProx grew, and PyJWT and websocket-client went into
requirements.txt and debian/control but never into its Requires. api/vms.py imports
utils/vnc_polling.py, which imports websocket at module level, so an RPM install without
python3-websocket-client does not start at all; without python3-jwt every OIDC login is
refused (utils/oidc.py).

test_debian_depends_cover_imports.py holds debian/control to every import. This file holds
the spec to debian/control: each Depends entry has its Fedora name in DEB_TO_RPM or a reason
in DEB_ONLY or DEB_TOOLS, and each name there is a Requires line of the spec. The other way
round, the spec requires nothing outside those names and RPM_ONLY, its python3-jwt floor
is a PyJWT whose PyJWKClient takes every keyword utils/oidc.py hands it, and its python3
floor is a Python the shipped code runs on (3.10 since utils/vnc_crypto.py, not EL9's 3.9).

MK Nov 2026
"""
import ast
import datetime
import functools
import os
import re

import pytest

from test_debian_depends_cover_imports import (_sources, deb_imports, depends_of,
                                               third_party_imports)

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
}

# Debian package -> the module it brings; in debian/control, imported by nothing
DEB_ONLY = {
    'python3-netifaces': 'netifaces',
    'python3-flask-sockets': 'flask_sockets',
}

# Debian package -> the program it brings; in debian/control, run by nothing. dbcrypto only
# imports sqlcipher3, and python3-sqlcipher3 brings its own SQLCipher. EPEL 10 has no
# sqlcipher, so requiring it only kept the RPM from installing there
DEB_TOOLS = {
    'sqlcipher': 'sqlcipher',
}

# Required by the spec, not named in debian/control: dependencies of the locally built
# flask-compress (backports.zstd below Python 3.14) and qrcode 7 (pypng), not imports of ours
RPM_ONLY = {
    'python3-backports-zstd': 'flask-compress',
    'python3-pypng': 'qrcode',
}

# PyJWKClient keyword -> the first PyJWT that takes it, read off the 2.0.0 to 2.8.0 wheels.
# EPEL 9 has 2.4.0, Fedora 43 and EPEL 10 have 2.8.0
PYJWKCLIENT_SINCE = {
    'cache_keys': (2, 1, 0),
    'max_cached_keys': (2, 1, 0),
    'cache_jwk_set': (2, 5, 0),
    'lifespan': (2, 5, 0),
    'headers': (2, 7, 0),
    'timeout': (2, 7, 0),
    'ssl_context': (2, 8, 0),
}

README = os.path.join(ROOT, 'README.md')

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


_REQ_TOKEN = re.compile(r'([^\s,<>=]+)(?:\s*(>=|<=|=|<|>)\s*([^\s,]+))?')


def requires_floor(spec_text, name):
    """The version a Requires line holds name to at least (>= or =), as a tuple of three, or
    None when the spec names it without one or not at all."""
    for m in re.finditer(r'^Requires(?:\([^)]*\))?:[ \t]*(.+)$', spec_text, re.M):
        for dep, op, ver in _REQ_TOKEN.findall(m.group(1)):
            if dep != name:
                continue
            num = re.match(r'\d+(?:\.\d+)*', ver) if op in ('>=', '=') else None
            if not num:
                return None
            parts = tuple(int(p) for p in num.group(0).split('.'))
            return (parts + (0, 0, 0))[:3]
    return None


def missing_requires(spec_text, control_text):
    requires = set(requires_of(spec_text))
    out = []
    for deb in sorted(depends_of(control_text) - set(DEB_ONLY) - set(DEB_TOOLS)):
        rpm = DEB_TO_RPM.get(deb)
        if rpm is None or rpm in requires:
            continue
        mods = sorted(m for m, d in deb_imports.DEPENDS.items() if d == deb)
        out.append(f'{rpm} ({", ".join(mods) if mods else "debian/control, no import"})')
    return out


def unused_requires(spec_text):
    """Requires names the spec has that nothing here maps to an import or a dependency."""
    known = set(DEB_TO_RPM.values()) | set(RPM_ONLY)
    return sorted(set(requires_of(spec_text)) - known)


def pyjwkclient_calls():
    """(locations, {keyword: [locations]}) of every PyJWKClient(...) in the shipped code."""
    calls, keywords = [], {}
    for rel in _sources():
        with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
            src = fh.read()
        if 'PyJWKClient' not in src:
            continue
        for node in ast.walk(ast.parse(src, rel)):
            if not isinstance(node, ast.Call):
                continue
            if 'PyJWKClient' not in (getattr(node.func, 'id', None), getattr(node.func, 'attr', None)):
                continue
            calls.append(f'{rel}:{node.lineno}')
            for kw in node.keywords:
                # a **mapping cannot be read here, it goes red as '**' until it is spelled out
                keywords.setdefault(kw.arg or '**', []).append(f'{rel}:{node.lineno}')
    return calls, keywords


_EXEC_CALLS = {'run', 'Popen', 'call', 'check_call', 'check_output', 'system', 'popen',
               'which', 'getoutput', 'getstatusoutput', 'execv', 'execvp', 'execlp'}


def _argv0s(tree, where):
    """(program, location) for each argv list or tuple and each exec-like call (subprocess,
    os.system, shutil.which) of a module whose first string names a program."""
    for node in ast.walk(tree):
        first = None
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            first = node.elts[0]
        elif (isinstance(node, ast.Call) and node.args and
              (getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)) in _EXEC_CALLS):
            first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.split():
            yield os.path.basename(first.value.split()[0]), f'{where}:{node.lineno}'


def _python_runs(src, program, where='<src>'):
    return [loc for prog, loc in _argv0s(ast.parse(src), where) if prog == program]


def _shell_runs(src, program, where='<src>'):
    """Locations where a shell script has program in command position."""
    pat = re.compile(r'(?:^|[;&|(`]|\$\(|\b(?:then|do|else|sudo|exec|command|nice|xargs)\s)'
                     rf'\s*(?:\S*/)?{re.escape(program)}(?=[\s;|&)]|$)')
    return [f'{where}:{n}' for n, line in enumerate(src.splitlines(), 1)
            if not line.lstrip().startswith('#') and pat.search(line)]


@functools.lru_cache(maxsize=None)
def _shipped_code():
    """[(path, 'py' or 'sh', text)] of every script the spec copies in, tests aside."""
    out = []
    skip = {'.git', 'tests', 'venv', 'node_modules', '__pycache__'}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for f in sorted(filenames):
            path = os.path.join(dirpath, f)
            try:
                with open(path, encoding='utf-8') as fh:
                    head = fh.readline()
                    if not (f.endswith(('.py', '.sh')) or head.startswith('#!')):
                        continue
                    src = head + fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            kind = 'py' if f.endswith('.py') or (head.startswith('#!') and 'python' in head) else 'sh'
            out.append((os.path.relpath(path, ROOT), kind, src))
    return out


def runs_of(program):
    """Every place the code the package ships runs program."""
    found = []
    for rel, kind, src in _shipped_code():
        if program not in src:
            continue
        if kind == 'sh':
            found += _shell_runs(src, program, rel)
            continue
        try:
            found += _python_runs(src, program, rel)
        except SyntaxError:
            continue
    return found


def test_every_depends_entry_of_the_deb_has_an_rpm_name():
    depends = depends_of(_read(CONTROL))
    unnamed = sorted(depends - set(DEB_TO_RPM) - set(DEB_ONLY) - set(DEB_TOOLS))
    assert not unnamed, (f'debian/control depends on {unnamed}: put the Fedora package into '
                         f'DEB_TO_RPM here and a Requires line into packaging/rpm/pegaprox.spec')
    stale = sorted((set(DEB_TO_RPM) | set(DEB_ONLY) | set(DEB_TOOLS)) - depends)
    assert not stale, f'no longer in debian/control, drop them here: {stale}'


def test_the_spec_requires_every_package_the_deb_depends_on():
    assert missing_requires(_read(SPEC), _read(CONTROL)) == []


def test_the_spec_requires_nothing_the_package_does_not_use():
    """A Requires nobody needs still has to resolve, and stops the install where the
    distribution lacks it: sqlcipher, a CLI nothing runs, did that on EPEL 10."""
    assert unused_requires(_read(SPEC)) == []


def test_what_only_the_deb_runs_is_run_by_nothing():
    for deb, program in DEB_TOOLS.items():
        assert runs_of(program) == [], f'{program} is run now: move {deb} into DEB_TO_RPM'
        assert deb not in deb_imports.DEPENDS.values()
        assert deb not in set(DEB_TO_RPM.values()) | set(RPM_ONLY)


def test_the_run_scan_finds_a_program_run():
    assert _python_runs('import subprocess\nsubprocess.run(["sqlcipher", "x.db"])\n', 'sqlcipher')
    assert _python_runs('cmd = ("/usr/bin/sqlcipher", db)\n', 'sqlcipher')
    assert _python_runs('import shutil\nshutil.which("sqlcipher")\n', 'sqlcipher')
    assert _python_runs('import os\nos.system("sqlcipher x.db < dump.sql")\n', 'sqlcipher')
    assert not _python_runs("BACKEND = 'sqlcipher'\nok = BACKEND == 'sqlcipher'\n", 'sqlcipher')
    assert not _python_runs('import sqlcipher3\n', 'sqlcipher')
    assert _shell_runs('sqlcipher "$db" < dump.sql\n', 'sqlcipher')
    assert _shell_runs('echo "PRAGMA key" | sqlcipher "$db"\n', 'sqlcipher')
    assert _shell_runs('if x; then /usr/bin/sqlcipher "$db"; fi\n', 'sqlcipher')
    assert _shell_runs('out=$(sqlcipher "$db" .tables)\n', 'sqlcipher')
    assert not _shell_runs('apt-get install -y sqlcipher python3-sqlcipher3\n', 'sqlcipher')
    assert not _shell_runs('# sqlcipher "$db"\n', 'sqlcipher')


def test_the_pyjwt_floor_takes_every_keyword_the_jwks_client_is_given():
    """PyJWKClient(..., lifespan=..., ssl_context=...) on a PyJWT that does not know them
    raises TypeError, and oidc_decode_id_token refuses every sign-in on it. EPEL 9's 2.4.0
    knows neither, and an unpinned python3-jwt resolves to it on RHEL 9."""
    calls, keywords = pyjwkclient_calls()
    assert any(loc.startswith('pegaprox/utils/oidc.py:') for loc in calls), calls
    unknown = sorted(set(keywords) - set(PYJWKCLIENT_SINCE))
    assert not unknown, (f'PyJWKClient is given {unknown} ({keywords}): put the first PyJWT '
                         f'that takes each into PYJWKCLIENT_SINCE')
    need = max((PYJWKCLIENT_SINCE[k] for k in keywords), default=(2, 0, 0))
    newest = [f'{k} ({", ".join(keywords[k])})' for k in keywords if PYJWKCLIENT_SINCE[k] == need]
    floor = requires_floor(_read(SPEC), 'python3-jwt')
    want = '.'.join(map(str, need))
    assert floor is not None, (f'packaging/rpm/pegaprox.spec requires python3-jwt with no floor, '
                               f'PyJWKClient gets {newest}: Requires: python3-jwt >= {want}')
    assert floor >= need, (f'packaging/rpm/pegaprox.spec holds python3-jwt to '
                           f'{".".join(map(str, floor))}, PyJWKClient gets {newest}, which '
                           f'PyJWT takes from {want} on')


@pytest.mark.parametrize('line,want', [
    ('Requires: python3-jwt >= 2.8.0', (2, 8, 0)),
    ('Requires:       python3-jwt >= 2.8', (2, 8, 0)),
    ('Requires: python3-jwt>=2.15.1', (2, 15, 1)),
    ('Requires: python3-foo, python3-jwt = 2.10.1-2', (2, 10, 1)),
    ('Requires: python3-jwt', None),
    ('Requires: python3-jwt < 3', None),
    ('Requires: python3-jwt-extra >= 9', None),
    ('BuildRequires: python3-jwt >= 9', None),
])
def test_requires_floor_parsing(line, want):
    assert requires_floor(f'Name: x\n{line}\n', 'python3-jwt') == want


class _EvaluatedAnnotations(ast.NodeVisitor):
    """The annotations Python evaluates when no 'from __future__ import annotations' defers
    them: those of a signature (when the def runs) and those at module and class level.
    The annotation of a local variable is never evaluated."""

    def __init__(self):
        self.found = []
        self._in_function = 0

    def _signature(self, node):
        a = node.args
        for arg in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.found.append(arg.annotation)
        if node.returns is not None:
            self.found.append(node.returns)
        self._in_function += 1
        self.generic_visit(node)
        self._in_function -= 1

    visit_FunctionDef = visit_AsyncFunctionDef = _signature

    def visit_AnnAssign(self, node):
        if not self._in_function:
            self.found.append(node.annotation)
        self.generic_visit(node)


def _needs_python_310(src, where='<src>'):
    """Locations in src that Python 3.9 cannot run: syntax it does not parse (match, ...)
    and an evaluated annotation with X | Y, a TypeError on 3.9 when it is evaluated."""
    try:
        ast.parse(src, feature_version=(3, 9))
    except SyntaxError as e:
        return [f'{where}:{e.lineno} (syntax)']
    tree = ast.parse(src)
    if any(isinstance(n, ast.ImportFrom) and n.module == '__future__'
           and any(a.name == 'annotations' for a in n.names) for n in tree.body):
        return []
    v = _EvaluatedAnnotations()
    v.visit(tree)
    return [f'{where}:{ann.lineno}' for ann in v.found
            if any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr) for n in ast.walk(ann))]


def python_needed():
    """((major, minor, 0), [locations]) of the oldest Python the shipped code runs on."""
    found = []
    for rel in _sources():
        with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
            found += _needs_python_310(fh.read(), rel)
    return ((3, 10, 0) if found else (3, 0, 0)), found


def test_the_python3_floor_is_a_python_the_code_runs_on():
    """RHEL 9's python3 is 3.9, and the spec required python3 with no version.
    utils/vnc_crypto.py has 'bytes | None' in its signatures, a TypeError the moment 3.9
    imports it, so the stable console mode fails there. The floor keeps EL9 out on its own,
    whatever the python3-jwt floor becomes."""
    need, where = python_needed()
    assert any(loc.startswith('pegaprox/utils/vnc_crypto.py:') for loc in where), where
    floor = requires_floor(_read(SPEC), 'python3')
    want = '.'.join(map(str, need[:2]))
    assert floor is not None, (f'packaging/rpm/pegaprox.spec requires python3 with no floor, '
                               f'{where} need {want}: Requires: python3 >= {want}')
    assert floor >= need, (f'packaging/rpm/pegaprox.spec holds python3 to '
                           f'{".".join(map(str, floor[:2]))}, {where} need {want}')


def test_the_python3_floor_is_not_below_the_readme():
    m = re.search(r'^- Python (\d+)\.(\d+) to \d+\.\d+', _read(README), re.M)
    assert m, 'README.md names no supported Python range under Requirements'
    floor = requires_floor(_read(SPEC), 'python3')
    assert floor is not None and floor >= (int(m.group(1)), int(m.group(2)), 0), \
        f'README.md supports Python from {m.group(1)}.{m.group(2)} on, the spec requires {floor}'


@pytest.mark.parametrize('src,needs', [
    ('def f(x) -> bytes | None:\n    pass\n', True),
    ('def f(x: int | None = None):\n    pass\n', True),
    ('async def f(*a: int | str):\n    pass\n', True),
    ('def outer():\n    def inner(x: int | None):\n        pass\n', True),
    ('timeout: float | None = None\n', True),
    ('class A:\n    x: int | None = None\n', True),
    ('match x:\n    case 1:\n        pass\n', True),
    ('from __future__ import annotations\ndef f(x) -> bytes | None:\n    pass\n', False),
    ('def f(x: "bytes | None"):\n    pass\n', False),
    ('def f():\n    y: int | None = None\n', False),
    ('flags = A | B\n', False),
    ('from typing import Optional\ndef f(x) -> Optional[bytes]:\n    pass\n', False),
])
def test_the_python_310_scan(src, needs):
    assert bool(_needs_python_310(src)) is needs


def test_requires_floor_reads_python3_apart_from_its_modules():
    assert requires_floor('Requires: python3-jwt >= 2.8.0\nRequires: python3\n', 'python3') is None
    assert requires_floor('Requires: python3-jwt >= 2.8.0\nRequires: python3 >= 3.10\n',
                          'python3') == (3, 10, 0)


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
