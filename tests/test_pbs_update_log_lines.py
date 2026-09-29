# -*- coding: utf-8 -*-
"""The PBS update log in cluster settings printed [object Object], once per line.

UpdateTask.add_output stores every line as {timestamp, text} and
/api/pbs/<id>/update hands those objects to the UI unchanged. The node views
have always read .text off them. The PBS panel instead did String(line), which
came out of #584: a non-string entry (an exit code) reached .includes() and took
the whole page white, and String() stopped that. It also turned every real log
line into [object Object], so the operator sees seven of those and nothing about
the upgrade that ran.

pbsLogText() now takes the text and keeps the #584 guarantee for anything that
is not a {text} object.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(name):
    with open(os.path.join(ROOT, 'web', 'src', name), encoding='utf-8') as f:
        return f.read()


def _helper_source():
    body = _src('security.js')
    a = body.index('function pbsLogText(')
    b = body.index('\n        }\n', a) + len('\n        }\n')
    return body[a:b]


# --- the contract the UI reads -----------------------------------------------

def test_the_backend_really_stores_an_object_per_line():
    """If add_output ever went back to plain strings, pbsLogText would still be
    right, but the node views reading line.text would not be."""
    from pegaprox.models.tasks import UpdateTask
    task = UpdateTask(node='pbs1')
    task.add_output('[OK] apt dist-upgrade finished')
    assert task.output_lines[0]['text'] == '[OK] apt dist-upgrade finished'
    assert 'timestamp' in task.output_lines[0]


# --- the helper, executed ------------------------------------------------------

@pytest.mark.parametrize('line,expected', [
    ({'timestamp': '2026-09-29T09:00:00', 'text': '[OK] upgrade finished'}, '[OK] upgrade finished'),
    ({'timestamp': '2026-09-29T09:00:00', 'text': '[ERROR] dpkg was interrupted'}, '[ERROR] dpkg was interrupted'),
    ({'timestamp': '2026-09-29T09:00:00', 'text': ''}, ''),
    ('already a string', 'already a string'),
    (0, '0'),                      # the exit code from #584
    (None, ''),
])
def test_a_line_renders_as_its_text(line, expected):
    """Executed, not grepped: this is the function that decides whether the
    operator reads their upgrade log or seven [object Object]."""
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped helper')
    script = (_helper_source() +
              '\nconsole.log(JSON.stringify(pbsLogText(JSON.parse(process.argv[1]).v)));')
    p = subprocess.run(['node', '-e', script, json.dumps({'v': line})],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == expected


def test_an_unexpected_object_never_renders_as_object_object():
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped helper')
    script = (_helper_source() +
              '\nconsole.log(JSON.stringify(pbsLogText({code: 100})));')
    p = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert '[object Object]' not in out
    assert 'code' in out, f'nothing usable came out: {out!r}'


# --- and it is what the panel calls ------------------------------------------

def test_the_pbs_panel_stopped_stringifying_the_whole_line():
    body = _src('security.js')
    panel = body[body.index('function UpdateManagerSection('):]
    assert 'pbsLogText(line)' in panel
    assert not re.search(r'const s = String\(line\);', panel), \
        'the bare String(line) is back, which is the [object Object] bug'


def test_it_reached_the_built_bundle():
    """web/index.html is generated from web/src, a src-only change ships nothing."""
    with open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8') as f:
        built = f.read()
    assert 'function pbsLogText(' in built
    assert 'const s=pbsLogText(line)' in built
