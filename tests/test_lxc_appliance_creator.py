"""misc/proxmox-lxc-appliance-creator.sh takes its options the way its --help shows them.

--help shows `--artifact-dir /path/to/artifacts` and `--TEMPLATE template-name`, but only the
`=` forms were parsed, and the space forms stopped with "Unknown option" before anything was
built. Both forms work now, and an option given without its value says so.

The check that the artifact directory is empty looked at the default /opt/pegaprox-templates
whatever --artifact-dir said. A second run into the same custom directory went on, left two
archives there for the final mv, stopped on it and left CT 999 behind; it now stops before
the container is created. A directory with a space in its name works too.

The script runs here with pct, vzdump and date stubbed on PATH; nothing touches a Proxmox host.

NS Nov 2026
"""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'misc', 'proxmox-lxc-appliance-creator.sh')
DUMP = 'vzdump-lxc-999-2026_11_01-10_00_00'
DAY = '2026-11-01'

STUBS = {
    'pct': '#!/bin/sh\necho "pct $*" >> "$STUB_LOG"\n',
    # the day in the archive name, fixed so a run across midnight still matches
    'date': f'#!/bin/sh\necho {DAY}\n',
    # what vzdump leaves in --dumpdir: the archive and its log
    'vzdump': f"""#!/bin/sh
echo "vzdump $*" >> "$STUB_LOG"
while [ $# -gt 0 ]; do
  [ "$1" = --dumpdir ] && dir=$2
  shift
done
: > "$dir/{DUMP}.tar.zst"
: > "$dir/{DUMP}.log"
""",
}

pytestmark = pytest.mark.skipif(not shutil.which('bash'), reason='needs bash')


@pytest.fixture
def creator(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name, body in STUBS.items():
        (bindir / name).write_text(body)
        os.chmod(bindir / name, 0o755)
    log = tmp_path / 'calls.log'

    def run(*args):
        log.write_text('')
        env = {**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}', 'STUB_LOG': str(log)}
        p = subprocess.run(['bash', SCRIPT, *args], cwd=str(tmp_path), env=env,
                           capture_output=True, text=True, timeout=60)
        return p, log.read_text().splitlines()

    return run, tmp_path


def _built(art):
    return set(os.listdir(art)) == {f'{DUMP}.log', f'pegaprox-template-SNAPSHOT-{DAY}.tar.zst'}


def test_the_space_forms_from_the_help_work(creator):
    run, tmp = creator
    art = tmp / 'art'
    p, calls = run('--artifact-dir', str(art), '--TEMPLATE', 'local:vztmpl/debian-13-test.tar.zst')
    assert p.returncode == 0, p.stdout + p.stderr
    assert calls[0].startswith('pct create 999 local:vztmpl/debian-13-test.tar.zst --hostname ')
    assert calls[-1] == 'pct destroy 999'
    assert _built(art)


def test_the_equals_forms_still_work(creator):
    run, tmp = creator
    art = tmp / 'art'
    p, calls = run(f'--artifact-dir={art}', '--TEMPLATE=local:vztmpl/debian-13-test.tar.zst')
    assert p.returncode == 0, p.stdout + p.stderr
    assert calls[0].startswith('pct create 999 local:vztmpl/debian-13-test.tar.zst ')
    assert _built(art)


@pytest.mark.parametrize('option,says', [('--artifact-dir', 'needs a path'), ('--TEMPLATE', 'needs a template')])
def test_an_option_without_its_value_stops_before_anything_runs(creator, option, says):
    run, _tmp = creator
    p, calls = run(option)
    assert p.returncode != 0
    assert f'{option} {says}' in p.stderr
    assert calls == []


def test_a_second_run_into_the_same_directory_stops_before_the_container(creator):
    run, tmp = creator
    art = tmp / 'art'
    p, _calls = run(f'--artifact-dir={art}')
    assert p.returncode == 0 and _built(art), p.stdout + p.stderr
    p, calls = run(f'--artifact-dir={art}/')
    assert p.returncode == 1
    assert f'Directory {art}/ is not empty!' in p.stdout
    assert calls == []
    assert _built(art)


def test_an_existing_empty_directory_is_used(creator):
    run, tmp = creator
    art = tmp / 'art'
    art.mkdir()
    p, calls = run(f'--artifact-dir={art}')
    assert p.returncode == 0, p.stdout + p.stderr
    assert f'Directory {art} is empty - continuing...' in p.stdout
    assert _built(art)


def test_a_directory_with_a_space(creator):
    run, tmp = creator
    art = tmp / 'my artifacts'
    p, calls = run(f'--artifact-dir={art}')
    assert p.returncode == 0, p.stdout + p.stderr
    assert f'--dumpdir {art}' in calls[-2]
    assert _built(art)
    assert not (tmp / 'my').exists()
