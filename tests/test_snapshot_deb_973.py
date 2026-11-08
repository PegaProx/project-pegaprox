"""The snapshot .deb built from every push to Testing (#973).

The workflow hands its build script to `bash` on stdin (a heredoc into
`docker run -i`). Any command in it that reads stdin reads the rest of the
script, and dch does exactly that when it has warned about something: without
DEBEMAIL in the container it prints "Press RETURN to continue..." and reads a
line. bash then found its input gone, exited 0 after dch, and the upload step
failed on every push with no .deb to upload. The script runs here the same way,
on stdin, with stand-ins for the tools the container installs; the dch one reads
stdin with the same perl line the real one does.

The snapshot version names the time of its commit in UTC, read on the runner from the
checkout (the container has no git), not the time of the build: a re-run of the same
push builds the same version. The job has a time limit, the artifact a retention.

NS Oct 2026 (#973)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'push-create-snapshot-deb-builds.yml')
SHA = '9531a3cabf22a74e229a15106188f312a9e7bb9e'
# the commit time the runner hands the container: 2026-03-01 00:30 at +01:00, in UTC
STAMP = '202602282330'


def _workflow():
    with open(WORKFLOW, encoding='utf-8') as fh:
        return fh.read()


def _container_step():
    """The bash flags, the variables passed with -e and the script of the docker step."""
    text = _workflow()
    m = re.search(r"\n(\s*)docker run (.*?)<<'EOF'\n(.*?)\n\s*EOF\n", text, re.S)
    assert m, 'no docker step with a heredoc script in the workflow'
    head, script = m.group(2), textwrap.dedent(m.group(3)) + '\n'
    bash = re.search(r'\bbash((?:\s+-[\w]+(?:\s+pipefail)?)*)\s*$', head.strip())
    assert bash, head
    passed = re.findall(r'-e (\w+)=', head)
    return bash.group(1).split(), passed, script


def _stub(path, body):
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(body)
    os.chmod(path, 0o755)


def _run(tmp_path, snapshot_time=STAMP):
    if not shutil.which('perl'):
        pytest.skip('perl is needed for the dch stand-in')
    flags, passed, script = _container_step()
    ws = tmp_path / 'workspace'
    (ws / 'debian').mkdir(parents=True)
    shutil.copy(os.path.join(ROOT, 'debian', 'changelog'), ws / 'debian' / 'changelog')
    (ws / 'version.json').write_text(json.dumps({'version': '1.3.0'}))
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    record = tmp_path / 'dch-version'
    _stub(stubs / 'apt-get', '#!/bin/sh\nexit 0\n')
    _stub(stubs / 'jq', '#!%s\nimport json, sys\nprint(json.load(open(sys.argv[-1])).get("version") or "")\n'
          % sys.executable)
    # devscripts' dch: warns without DEBEMAIL/EMAIL, then `my $garbage = <STDIN>;`
    _stub(stubs / 'dch', textwrap.dedent('''\
        #!/bin/sh
        ver=""
        while [ $# -gt 0 ]; do
          case "$1" in --newversion) ver="$2"; shift 2 ;; *) shift ;; esac
        done
        if [ -z "${DEBEMAIL:-}" ] && [ -z "${EMAIL:-}" ]; then
          perl -e 'warn "dch: Did you see that warning?  Press RETURN to continue...\\n"; my $garbage = <STDIN>;'
        fi
        { printf 'pegaprox (%%s) UNRELEASED; urgency=medium\\n\\n  * snapshot\\n\\n -- b <b@b>  Mon, 05 Oct 2026 12:00:00 +0000\\n\\n' "$ver"
          cat debian/changelog; } > debian/changelog.new
        mv debian/changelog.new debian/changelog
        printf '%%s' "$ver" > '%s'
        ''') % record)
    _stub(stubs / 'dpkg-buildpackage', textwrap.dedent('''\
        #!/bin/sh
        ver=$(sed -n '1s/^pegaprox (\\([^)]*\\)).*/\\1/p' debian/changelog)
        : > "../pegaprox_${ver}_all.deb"
        '''))
    # what the container has: the image's PATH, HOME, and what -e hands in
    env = {'PATH': '%s:/usr/local/bin:/usr/bin:/bin' % stubs, 'HOME': str(tmp_path), 'LANG': 'C'}
    step_env = {'COMMIT_SHA': SHA, 'SNAPSHOT_TIME': snapshot_time}
    for name in passed:
        assert name in step_env, 'the test does not know -e %s' % name
        env[name] = step_env[name]
    out = subprocess.run(['bash'] + flags, input=script, cwd=str(ws), env=env,
                         capture_output=True, text=True, timeout=60)
    return out, ws, record


def test_the_script_runs_past_dch_and_leaves_the_deb_for_the_upload(tmp_path):
    out, ws, _record = _run(tmp_path)
    assert out.returncode == 0, out.stderr
    pkg = ws / 'package'
    debs = sorted(os.listdir(pkg)) if pkg.is_dir() else []
    assert len(debs) == 1, 'nothing for the upload step, bash stopped after:\n' + out.stderr[-600:]
    assert re.fullmatch(r'pegaprox_1\.3\.0~snapshot\.\d{12}\.%s_all\.deb' % SHA[:8], debs[0]), debs


def test_a_snapshot_sorts_between_the_last_release_and_the_next(tmp_path):
    if not shutil.which('dpkg'):
        pytest.skip('dpkg is needed to compare versions')
    _out, _ws, record = _run(tmp_path)
    ver = record.read_text()
    assert re.fullmatch(r'1\.3\.0~snapshot\.\d{12}\.%s' % SHA[:8], ver), ver

    def lt(a, b):
        return subprocess.run(['dpkg', '--compare-versions', a, 'lt', b]).returncode == 0

    # the published release packages carry a Debian revision (1.1.0-2), our apt-repo build none
    for older in ('1.2.0', '1.2.0-1', '1.2.0-2'):
        assert lt(older, ver), older
    for newer in ('1.3.0', '1.3.0-1'):
        assert lt(ver, newer), newer
    # an older push sorts below a newer one, whatever its commit hash
    assert lt(re.sub(r'snapshot\.\d{12}\.\w+', 'snapshot.202001010000.ffffffff', ver), ver)


def test_it_only_runs_on_pushes_to_testing_and_only_reads():
    text = _workflow()
    assert re.search(r'^on:\n  push:\n    branches:\n      - Testing\n\n', text, re.M), 'trigger changed'
    for trigger in ('pull_request', 'workflow_dispatch', 'workflow_run', 'schedule'):
        assert trigger not in text, trigger
    assert re.search(r'^permissions:\n  contents: read\n\n', text, re.M)
    assert 'secrets.' not in text
    assert 'persist-credentials: false' in text
    uses = re.findall(r'uses:\s*(\S+)', text)
    assert uses
    for ref in uses:
        assert re.fullmatch(r'[\w.-]+/[\w.-]+@[0-9a-f]{40}', ref), ref


# --- the version of a re-run, the limits ------------------------------------------------

def test_the_version_carries_the_commit_time_it_was_handed(tmp_path):
    out, ws, _record = _run(tmp_path)
    assert out.returncode == 0, out.stderr
    assert os.listdir(ws / 'package') == ['pegaprox_1.3.0~snapshot.%s.%s_all.deb' % (STAMP, SHA[:8])]


@pytest.mark.parametrize('stamp', ['', '2026-02-28', '20260228233'], ids=['none', 'a date', 'too short'])
def test_without_a_commit_time_nothing_is_built(tmp_path, stamp):
    out, ws, record = _run(tmp_path, stamp)
    assert out.returncode != 0
    assert not (ws / 'package').exists() and not record.exists()


def _build_step():
    """The run: block of the build step, as the runner's bash gets it."""
    m = re.search(r'- name: Build Debian package\n.*?\n( +)run: \|\n(.*?)\n\s*- name:', _workflow(), re.S)
    assert m, 'no build step with a run block'
    return textwrap.dedent(m.group(2)) + '\n'


def _git(repo, *args, **env):
    base = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(repo.parent), 'LANG': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    base.update(env)
    return subprocess.run(['git', '-C', str(repo)] + list(args), env=base, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.mark.parametrize('zone', ['UTC', 'Pacific/Kiritimati', 'America/Adak'])
def test_the_runner_hands_over_the_commit_time_in_utc(tmp_path, zone):
    """Committed at 00:30 on 1 March at +01:00, authored months before: the container gets
    202602282330 on a runner in any zone, and on every run of the step."""
    if not shutil.which('git'):
        pytest.skip('git is needed for the checkout')
    repo = tmp_path / 'checkout'
    repo.mkdir()
    _git(repo, 'init', '-q')
    _git(repo, '-c', 'user.name=ci', '-c', 'user.email=ci@example.invalid', 'commit', '-q',
         '--allow-empty', '-m', 'snapshot',
         GIT_AUTHOR_DATE='2025-12-24T18:00:00+01:00', GIT_COMMITTER_DATE='2026-03-01T00:30:00+01:00')
    sha = _git(repo, 'rev-parse', 'HEAD')
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    args = tmp_path / 'docker-args'
    # the docker stand-in: what it was handed, and the script it would run is read and dropped
    _stub(stubs / 'docker', '#!/bin/sh\nprintf "%%s\\n" "$@" > \'%s\'\ncat > /dev/null\n' % args)
    script = tmp_path / 'step.sh'
    script.write_text(_build_step())
    env = {'PATH': '%s:/usr/local/bin:/usr/bin:/bin' % stubs, 'HOME': str(tmp_path), 'LANG': 'C',
           'TZ': zone, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'COMMIT_SHA': sha}
    seen = []
    for _ in range(2):
        # the runner's own shell: bash --noprofile --norc -eo pipefail {0}
        out = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', str(script)],
                             cwd=str(repo), env=env, capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        handed = args.read_text().splitlines()
        seen.append([a for a in handed if a.startswith('SNAPSHOT_TIME=')])
    assert seen == [['SNAPSHOT_TIME=' + STAMP]] * 2
    assert 'COMMIT_SHA=' + sha in handed


def test_a_commit_the_checkout_does_not_hold_stops_the_step(tmp_path):
    if not shutil.which('git'):
        pytest.skip('git is needed for the checkout')
    repo = tmp_path / 'checkout'
    repo.mkdir()
    _git(repo, 'init', '-q')
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    ran = tmp_path / 'docker-ran'
    _stub(stubs / 'docker', '#!/bin/sh\n: > \'%s\'\ncat > /dev/null\n' % ran)
    script = tmp_path / 'step.sh'
    script.write_text(_build_step())
    env = {'PATH': '%s:/usr/local/bin:/usr/bin:/bin' % stubs, 'HOME': str(tmp_path), 'LANG': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'COMMIT_SHA': SHA}
    out = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', str(script)],
                         cwd=str(repo), env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode != 0 and not ran.exists()


def test_the_job_has_a_time_limit_and_the_artifact_a_retention():
    text = _workflow()
    job = re.search(r'^  build-package-debian:\n((?:    .*\n|\n)*)', text, re.M)
    assert job and re.search(r'^    timeout-minutes: 30$', job.group(1), re.M), 'no time limit on the job'
    upload = re.search(r'- name: Upload Debian snapshot package\n((?:        .*\n?)*)', text)
    assert upload, 'no upload step'
    assert re.search(r'^          retention-days: 14$', upload.group(1), re.M), upload.group(1)
