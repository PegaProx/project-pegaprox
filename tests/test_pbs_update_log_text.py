"""The PBS update panel shows the text of each line: update tasks keep a line as
{timestamp, text}, and String() of that read '[object Object]' (#964, #971). A plain
string or number entry still shows as it is.

LW Oct 2026
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _expression():
    src = open(os.path.join(ROOT, 'web', 'src', 'security.js'), encoding='utf-8').read()
    block = src[src.index('{(pbsJob.output_lines || []).map((line, i) => {'):]
    return re.search(r'const s = (.+?);\n', block).group(1)


@pytest.mark.skipif(not shutil.which('node'), reason='needs node')
def test_each_line_shows_its_text():
    lines = [{'timestamp': '2026-10-04T08:00:00', 'text': '[OK] apt update'}, 'plain line', 3, None]
    js = f"const out = {json.dumps(lines)}.map(line => {_expression()}); console.log(JSON.stringify(out));"
    got = json.loads(subprocess.run(['node', '-e', js], capture_output=True, text=True, check=True).stdout)
    assert got == ['[OK] apt update', 'plain line', '3', 'null']
