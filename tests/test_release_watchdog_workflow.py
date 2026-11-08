# -*- coding: utf-8 -*-
"""The watchdog's workflow file and baseline, read as text (CI has no YAML parser).

What is pinned here: expressions never sit inside a run block, every action is pinned by
commit, only the act job can write and only on main from the schedule or a manual run, the
sha256 sums in watchdog.yml are those of the script and the baseline, the freeze without the
script stops exactly the baseline's publishers, every workflow of the repo is sorted into
publishers or others, and the URLs the baseline allows are the ones the updater really uses."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WF_DIR = ROOT / '.github' / 'workflows'
WATCHDOG_YML = (WF_DIR / 'watchdog.yml').read_text(encoding='utf-8')
BASELINE = json.loads((ROOT / '.github' / 'watchdog' / 'baseline.json').read_text(encoding='utf-8'))
_spec = importlib.util.spec_from_file_location('release_watchdog_wf', ROOT / '.github' / 'scripts' / 'watchdog.py')
wd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wd)


def run_blocks(text):
    """The text of every run: value, block scalars included, by indentation."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)(?:- )?run:\s*(.*)$', line)
        if not m:
            continue
        indent, value = len(m.group(1)), m.group(2)
        body = [value]
        if value.strip() in ('|', '>', '|-', '>-', ''):
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                body.append(nxt)
        out.append('\n'.join(body))
    return out


def job_block(text, name):
    m = re.search(rf'^  {name}:\n(.*?)(?=^  [A-Za-z_-]+:\n|\Z)', text, re.S | re.M)
    assert m, name
    return m.group(1)


def test_no_expression_inside_a_run_block():
    blocks = run_blocks(WATCHDOG_YML)
    assert len(blocks) == 6
    for b in blocks:
        assert '${{' not in b, b


def _pin_blocks():
    return [b for b in run_blocks(WATCHDOG_YML) if 'sha256sum' in b]


def test_the_pins_are_the_sums_of_the_script_and_the_baseline():
    # after a change to either file: sha256sum .github/scripts/watchdog.py .github/watchdog/baseline.json
    want = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in wd.PINNED}
    blocks = _pin_blocks()
    assert len(blocks) == 2, 'both jobs check the pins'
    for b in blocks:
        assert dict((p, h) for h, p in wd.PIN_LINE.findall(b)) == want
        assert '--strict' in b and "<<'PINS'" in b
    # and the script reads them the same way from the file as a whole
    assert {p: h for h, p in wd.PIN_LINE.findall(WATCHDOG_YML)} == want


def test_a_mismatch_skips_the_script_and_freezes_without_it():
    check, act = job_block(WATCHDOG_YML, 'check'), job_block(WATCHDOG_YML, 'act')
    assert "if: steps.pin.outputs.tampered == 'false'" in check.split('- name: Check')[1].split('run:')[0]
    assert "tampered: ${{ steps.pin.outputs.tampered }}" in check
    assert "needs.check.outputs.tampered == 'true'" in act
    script_step = act.split('- name: Freeze or unfreeze')[1].split('- name:')[0]
    assert "if: steps.pin.outputs.tampered == 'false'" in script_step
    fallback = act.split('- name: Freeze without the script')[1]
    assert "if: steps.pin.outputs.tampered != 'false'" in fallback
    assert 'watchdog.py' not in fallback.split('run: |')[1], 'the fallback must not run the script'
    listed = re.search(r"publishers='([^']+)'", fallback).group(1).split()
    assert sorted(listed) == sorted(BASELINE['workflows']['publishers'])
    assert 'exit 1' in fallback and '/disable' in fallback and '/cancel' in fallback
    # run ids from the API are only used when they are digits
    assert "*[!0-9]*) continue" in fallback


def test_the_run_block_scanner_would_see_one():
    # counterproof for the scanner itself
    sample = 'steps:\n  - name: x\n    run: |\n      echo hi\n      # ${{ inputs.tag }}\n  - run: ok\n'
    assert any('${{' in b for b in run_blocks(sample))


def test_every_action_is_pinned_by_commit():
    uses = re.findall(r'^\s*(?:- )?uses:\s*(\S+)', WATCHDOG_YML, re.M)
    assert uses
    for u in uses:
        assert re.fullmatch(r'[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}', u), u


def test_permissions_are_none_by_default_and_narrow_per_job():
    assert re.search(r'^permissions: \{\}$', WATCHDOG_YML, re.M)
    check, act = job_block(WATCHDOG_YML, 'check'), job_block(WATCHDOG_YML, 'act')
    assert 'write' not in re.search(r'permissions:\n((?:\s{6}.*\n)+)', check).group(1)
    perms = dict(re.findall(r'^\s{6}([a-z-]+): (read|write)',
                            re.search(r'permissions:\n((?:\s{6}.*\n)+)', act).group(1), re.M))
    assert perms == {'actions': 'write', 'contents': 'read'}


def test_only_the_act_job_acts_and_only_on_main_from_schedule_or_dispatch():
    check, act = job_block(WATCHDOG_YML, 'check'), job_block(WATCHDOG_YML, 'act')
    assert 'PEGAPROX_WATCHDOG_ACT' not in check
    assert "PEGAPROX_WATCHDOG_ACT: '1'" in act
    cond = re.search(r'if: >-\n((?:\s{6}.*\n)+)', act).group(1)
    assert "github.ref == 'refs/heads/main'" in cond
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in cond
    assert "'push'" not in cond and '!cancelled()' in cond
    assert 'secrets.' not in check, 'the job that reads shaped data holds no secret'


def test_triggers_and_inputs():
    assert re.search(r"^\s+- cron: '3-59/10 \* \* \* \*'", WATCHDOG_YML, re.M)
    assert re.search(r'^  push:\n    branches: \[main, Testing\]$', WATCHDOG_YML, re.M)
    assert 'options: [check, freeze, unfreeze]' in WATCHDOG_YML and 'default: check' in WATCHDOG_YML
    assert re.search(r'^      confirm:\n', WATCHDOG_YML, re.M)
    # the inputs reach the script through env
    assert 'WATCHDOG_ACTION: ${{ inputs.action }}' in WATCHDOG_YML
    assert 'WATCHDOG_CONFIRM: ${{ inputs.confirm }}' in WATCHDOG_YML
    assert 'pull_request' not in WATCHDOG_YML


# what makes a workflow a publisher: it can write releases, packages or Pages, or it holds a
# key that pushes somewhere else
_PUBLISHING = re.compile(r'\b(contents|packages|pages): write\b|DOCKERHUB_TOKEN|APT_GPG_PRIVATE_KEY')


def test_every_workflow_is_sorted_and_the_sorting_matches_the_file():
    pubs, others = BASELINE['workflows']['publishers'], BASELINE['workflows']['others']
    assert not set(pubs) & set(others)
    files = sorted(p.name for p in WF_DIR.glob('*.y*ml'))
    assert sorted(set(pubs) | set(others)) == files
    for name in files:
        text = (WF_DIR / name).read_text(encoding='utf-8')
        publishes = bool(_PUBLISHING.search(text))
        assert publishes == (name in pubs), f'{name}: publishes={publishes}'
        # the ones that may touch a release: the late-asset check looks for their runs
        attaches = bool(re.search(r'\bcontents: write\b', text))
        assert attaches == (name in BASELINE['workflows']['attach_to_releases']), name
    assert 'watchdog.yml' in others


def test_the_baseline_loads_and_is_complete():
    b = wd.load_baseline(ROOT / '.github' / 'watchdog' / 'baseline.json')
    assert b['default_branch'] == 'main' and b['branches'] == ['main', 'Testing']
    assert {r['id'] for r in b['rulesets']} == {13059997, 25587029, 25587030}
    assert all(r['enforcement'] == 'active' for r in b['rulesets'])
    assert all(re.fullmatch(r'[0-9a-f]{40}', s) for s in b['tags'].values())
    assert {'v1.4.0', 'v1.4.1'} <= set(b['tags'])
    for g in ('.github/workflows/', '.github/scripts/', '.github/watchdog/'):
        assert g in b['guarded_paths']
    # who may move main or change the watchdog is a subset of the team
    assert set(b['release_managers']) <= set(b['allowed_actors'])
    assert set(b['watchdog_maintainers']) <= set(b['release_managers'])
    for name in b['collaborators']:
        assert name in b['allowed_actors'], name
    # the Testing archive never stood in version.json; main must not send installs there
    assert not any('Testing' in u for u in b['update_manifest']['exact']['update_archive'])


def test_the_allowed_update_urls_are_the_updaters_own():
    consts = (ROOT / 'pegaprox' / 'constants.py').read_text(encoding='utf-8')
    url = dict(re.findall(r'^([A-Z_]+_URL) = "([^"]+)"', consts, re.M))
    cfg = BASELINE['update_manifest']
    assert url['GITHUB_ARCHIVE_URL'] in cfg['exact']['update_archive']
    assert url['MIRROR_ARCHIVE_URL'] in cfg['exact']['update_archive']
    assert url['MIRROR_RAW_URL'] in cfg['exact']['update_mirror']
    assert cfg['mirror'] == url['MIRROR_VERSION_URL']
    # and the version.json of this checkout passes
    doc = json.loads((ROOT / 'version.json').read_text(encoding='utf-8'))
    assert wd.judge_manifest(cfg, doc) == []


def test_the_updater_still_reads_update_archive_from_the_manifest():
    # if the updater starts reading another URL field, the baseline has to learn it
    src = (ROOT / 'pegaprox' / 'api' / 'settings.py').read_text(encoding='utf-8')
    fields = set(re.findall(r"remote_version\.get\('([a-z_]+)'", src))
    url_fields = {f for f in fields if 'url' in f or 'archive' in f or 'mirror' in f}
    known = set(BASELINE['update_manifest']['exact']) | set(BASELINE['update_manifest']['prefixes'])
    assert url_fields <= known, url_fields - known


def test_house_rules_in_the_new_files():
    files = [ROOT / '.github' / 'scripts' / 'watchdog.py', WF_DIR / 'watchdog.yml',
             ROOT / '.github' / 'watchdog' / 'baseline.json', ROOT / 'docs' / 'release-watchdog.md',
             Path(__file__), ROOT / 'tests' / 'test_release_watchdog.py']
    # spelled out piecewise, or this file would trip over its own list
    banned = [chr(0x2014), chr(0x2013), 'VM' + 'ware', 'v' + 'Center']
    for p in files:
        text = p.read_text(encoding='utf-8')
        for word in banned:
            assert word not in text, (p.name, word)


def test_the_doc_names_the_limits_and_the_way_back():
    doc = (ROOT / 'docs' / 'release-watchdog.md').read_text(encoding='utf-8')
    for must in ('UNFREEZE', 'WATCHDOG_ACK', 'WATCHDOG_NOTIFY_URL', 'admin', 'not checked'):
        assert must in doc, must
    for name in BASELINE['workflows']['publishers']:
        assert name in doc, name


def test_a_baseline_cannot_freeze_the_watchdog_itself(tmp_path):
    bad = dict(BASELINE)
    bad['workflows'] = {'publishers': {'watchdog.yml': 'x'}, 'others': {}}
    p = tmp_path / 'b.json'
    p.write_text(json.dumps(bad), encoding='utf-8')
    try:
        wd.load_baseline(p)
    except SystemExit as e:
        assert 'cannot be a publisher' in str(e)
    else:
        raise AssertionError('accepted the watchdog as a publisher')
