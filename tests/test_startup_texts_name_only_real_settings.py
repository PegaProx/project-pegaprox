"""What --requirements and --help tell an admin to set is something PegaProx reads.

The requirements guide said the main port is "configurable via PEGAPROX_PORT", which nothing
reads (the port is in Settings > Server and --set-port), and offered --ssl-cert/--ssl-key,
which the entry script does not know. Both texts are printed by the real entry script here;
every PEGAPROX_* variable they name has to be read from the environment somewhere in the
code, and every --option they name has to be one the entry script checks for.
"""
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(REPO, 'pegaprox_multi_cluster.py')


def _printed(flag):
    return subprocess.run([sys.executable, ENTRY, flag], cwd=REPO, capture_output=True, text=True,
                          timeout=60, env={**os.environ, 'PEGAPROX_NO_GEVENT': '1'}).stdout


def _sources():
    yield ENTRY
    for base, _dirs, files in os.walk(os.path.join(REPO, 'pegaprox')):
        for f in files:
            if f.endswith('.py'):
                yield os.path.join(base, f)


@pytest.fixture(scope='module')
def code():
    return '\n'.join(open(p, encoding='utf-8', errors='replace').read() for p in _sources())


@pytest.fixture(scope='module', params=['--requirements', '--help'])
def text(request):
    out = _printed(request.param)
    assert 'PEGAPROX_' in out, out[:300]
    return out


def test_every_variable_named_is_read(text, code):
    names = sorted(set(re.findall(r'\bPEGAPROX_[A-Z0-9_]+\b', text)))
    unread = [n for n in names
              if not re.search(rf"""(environ\.get\(|environ\[|getenv\()\s*['"]{n}['"]""", code)]
    assert not unread, f'named but read nowhere: {unread}'


def test_every_option_named_is_handled(text):
    entry = open(ENTRY, encoding='utf-8').read()
    options = sorted(set(re.findall(r'(?<![\w-])--[a-z][a-z0-9-]+', text)))
    unknown = [o for o in options if f"'{o}' in sys.argv" not in entry]
    assert not unknown, f'named but not handled: {unknown}'
