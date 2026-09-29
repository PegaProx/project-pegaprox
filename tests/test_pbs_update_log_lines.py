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


def _function_source(body, name):
    """One function, cut out by matching braces from its opening one.

    Slicing on a fixed indent instead ties the test to the file's formatting: a
    reindent, a nested helper or the minified bundle all break the cut, and the
    failure then reads as if the behaviour broke.
    """
    start = body.index('function %s(' % name)
    depth = 0
    for j in range(body.index('{', start), len(body)):
        if body[j] == '{':
            depth += 1
        elif body[j] == '}':
            depth -= 1
            if depth == 0:
                return body[start:j + 1]
    raise AssertionError('unbalanced braces while cutting out %s()' % name)


def _built():
    with open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8') as f:
        return f.read()


def _helper_sources():
    """The helper as written and as shipped. The bundle is what the browser runs,
    so a stale or half-rebuilt web/index.html has to fail these too."""
    return {'src': _function_source(_src('security.js'), 'pbsLogText'),
            'bundle': _function_source(_built(), 'pbsLogText')}


def _run(helper, argument_json, call='pbsLogText(JSON.parse(process.argv[1]).v)'):
    script = helper + '\nconsole.log(JSON.stringify(%s));' % call
    p = subprocess.run(['node', '-e', script, argument_json],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


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

@pytest.mark.parametrize('where', ['src', 'bundle'])
@pytest.mark.parametrize('line,expected', [
    ({'timestamp': '2026-09-29T09:00:00', 'text': '[OK] upgrade finished'}, '[OK] upgrade finished'),
    ({'timestamp': '2026-09-29T09:00:00', 'text': '[ERROR] dpkg was interrupted'}, '[ERROR] dpkg was interrupted'),
    ({'timestamp': '2026-09-29T09:00:00', 'text': ''}, ''),
    ('already a string', 'already a string'),
    (0, '0'),                      # the exit code from #584
    (None, ''),
])
def test_a_line_renders_as_its_text(where, line, expected):
    """Executed, not grepped: this is the function that decides whether the
    operator reads their upgrade log or seven [object Object]. Run against the
    source AND against the compiled bundle, because the bundle is what ships."""
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped helper')
    assert _run(_helper_sources()[where], json.dumps({'v': line})) == expected


@pytest.mark.parametrize('where', ['src', 'bundle'])
def test_an_unexpected_object_never_renders_as_object_object(where):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped helper')
    out = _run(_helper_sources()[where], '{}', call='pbsLogText({code: 100})')
    assert '[object Object]' not in out
    assert 'code' in out, f'nothing usable came out: {out!r}'


# --- and it is what the panel calls ------------------------------------------

def test_the_pbs_panel_stopped_stringifying_the_whole_line():
    body = _src('security.js')
    panel = body[body.index('function UpdateManagerSection('):]
    assert 'pbsLogText(line)' in panel
    # the colouring has to read the normalised text too. Styling off the raw
    # line would still pass a display-only check, and `[object Object]` never
    # contains [ERROR] or [OK], so every line would render grey.
    assert "s.includes('[ERROR]')" in panel
    assert "s.includes('[OK]')" in panel
    assert not re.search(r'const s = String\(line\);', panel), \
        'the bare String(line) is back, which is the [object Object] bug'


def test_it_reached_the_built_bundle():
    """web/index.html is generated from web/src, a src-only change ships nothing.
    What the helper DOES in the bundle is covered by the executed tests above."""
    built = _built()
    assert 'const s=pbsLogText(line)' in built
    assert "s.includes('[ERROR]')" in built
