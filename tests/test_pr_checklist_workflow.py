# -*- coding: utf-8 -*-
"""The PR checklist workflow (pr-template-check.yml), with its github-script run in node.

The script block is cut out of the YAML by indentation (CI has no YAML parser) and run against a
fake github.rest that records every call. PR bodies start from the real PR template. Pinned here:
a closed PR gets nothing, a removed template is still closed, a named AI tool with the AI-assist
box unticked is closed for every external author (drafts too), a huge PR or a large one without a
linked issue is closed unless the author is on the size allowlist, there is only ever one marker
comment, and the nudge still works. Also: a failed comment call doesn't keep a PR open, only the
bot's own marker comment counts, a PR against main is measured against Testing, and the tick and
tool-line reading holds up against wrapped, reworded or bold variants. PR_CHECKLIST_WORKFLOW points
the tests at another copy of the workflow, e.g. the previous one for a counterproof."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WF = Path(os.environ.get('PR_CHECKLIST_WORKFLOW') or ROOT / '.github' / 'workflows' / 'pr-template-check.yml')
WF_TEXT = WF.read_text(encoding='utf-8')
TEMPLATE = (ROOT / '.github' / 'PULL_REQUEST_TEMPLATE.md').read_text(encoding='utf-8')
MARKER = '<!-- pegaprox-pr-checklist -->'
REPO_URL = 'https://github.com/PegaProx/project-pegaprox'
NODE = shutil.which('node')
needs_node = pytest.mark.skipif(not NODE, reason='node is not installed')

R1_TEXT = (
    "Thanks for the work on this. The PR template asks anyone who used an AI assistant to confirm they "
    "read, understood and tested every line themselves, and that box is unticked here while `{tool}` is "
    "named. We don't review generated output its author hasn't gone through, so this PR is closed. If you "
    "go through it line by line, test it against current Testing and tick the box, feel free to reopen it "
    "or open a new one.\n\n*Automated check.*")
HUGE_TEXT = (
    "Thanks for the PR. It changes {lines} lines in {files} files, which usually means it carries history "
    "from another branch or fork rather than one change. Please open a PR from a branch based on current "
    "Testing that holds only your change.\n\n*Automated check.*")
LARGE_TEXT = (
    "Thanks for the PR. It changes {lines} lines in {files} files without a linked issue. For a change this "
    "size we ask for an issue first, so the approach is agreed before anyone reviews a lot of code (see "
    "[CONTRIBUTING]({repo}/blob/main/CONTRIBUTING.md)). Link or open an issue and add `Fixes #<issue>`, then "
    "reopen this PR or open a new one.\n\n*Automated check.*")


def script_block(text):
    """The github-script 'script: |' block, dedented, found by indentation."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)script:\s*\|\s*$', line)
        if not m:
            continue
        indent = len(m.group(1))
        body = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        pad = min(len(b) - len(b.lstrip()) for b in body if b.strip())
        return '\n'.join(b[pad:] for b in body).rstrip() + '\n'
    raise AssertionError('no script: | block in ' + str(WF))


SCRIPT = script_block(WF_TEXT)


def size_allowlist():
    m = re.search(r'const SIZE_ALLOWLIST = \[([^\]]*)\]', SCRIPT)
    return [int(n) for n in re.findall(r'\d+', m.group(1))] if m else []


def listed(i):
    # the account ids, read from the workflow so they are not spelled out here
    ids = size_allowlist()
    return ids[i] if i < len(ids) else 900000000 + i


STRANGER_ID = 987654321


# github-script runs the script as the body of an async function; this does the same with a
# github.rest that only records what it was asked to do
HARNESS = r'''
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const calls = [];
const logs = [];
console.log = (...a) => logs.push(a.join(' '));
// input.fail maps a call name to the HTTP status it fails with
const rec = (name, ret) => async (args) => {
  calls.push([name, args]);
  if (input.fail[name]) {
    const e = new Error('HTTP ' + input.fail[name]);
    e.status = input.fail[name];
    throw e;
  }
  return typeof ret === 'function' ? ret(args) : ret;
};
const github = { rest: {
  issues: {
    // one page per call, like the API
    listComments: rec('listComments', (a) => {
      const per = a.per_page || 30, page = a.page || 1;
      return { data: input.comments.slice((page - 1) * per, page * per) };
    }),
    createComment: rec('createComment', { data: { id: 900 } }),
    updateComment: rec('updateComment', { data: {} }),
  },
  pulls: {
    update: rec('pulls.update', { data: {} }),
    get: rec('pulls.get', { data: Object.assign({}, input.payload.pull_request, input.live) }),
  },
  repos: { compareCommitsWithBasehead: rec('compare', { data: input.compare }) },
} };
github.paginate = async (method, args) => {
  const all = [];
  for (let page = 1; ; page++) {
    const { data } = await method(Object.assign({}, args, { page }));
    all.push(...data);
    if (data.length < (args.per_page || 30)) return all;
  }
};
const core = {
  setFailed: (m) => calls.push(['setFailed', String(m)]),
  info: (m) => logs.push(String(m)),
  warning: (m) => logs.push('warning: ' + String(m)),
};
const context = { payload: input.payload, repo: { owner: 'PegaProx', repo: 'project-pegaprox' } };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
(async () => {
  let error = null;
  try {
    await new AsyncFunction('github', 'context', 'core', 'require', input.script)(github, context, core, require);
  } catch (e) {
    error = String((e && e.stack) || e);
  }
  process.stdout.write(JSON.stringify({ calls, logs, error }));
})();
'''


class Run:
    def __init__(self, out):
        self.calls = out['calls']
        self.logs = out['logs']
        self.error = out['error']

    def named(self, name):
        return [a for n, a in self.calls if n == name]

    @property
    def closed(self):
        return any(a.get('state') == 'closed' for a in self.named('pulls.update'))

    @property
    def comment(self):
        """The one comment body written, created or updated; None if none was."""
        bodies = [a['body'] for a in self.named('createComment') + self.named('updateComment')]
        assert len(bodies) <= 1, bodies
        return bodies[0] if bodies else None

    @property
    def failed(self):
        return self.named('setFailed')


BOT = {'login': 'github-actions[bot]', 'type': 'Bot'}
HEAD_SHA = '3f' * 20


def ours(cid, text='old'):
    """A marker comment written by the workflow's own token."""
    return {'id': cid, 'user': BOT, 'body': MARKER + '\n' + text}


def run(body, *, login='new-contributor', uid=STRANGER_ID, state='open', draft=False, additions=12,
        deletions=3, files=2, comments=(), base='Testing', labels=(), live=None, fail=None, compare=None,
        allow_error=False):
    payload = {
        'pull_request': {
            'number': 4242, 'body': body, 'state': state, 'draft': draft, 'user': {'login': login, 'id': uid},
            'additions': additions, 'deletions': deletions, 'changed_files': files,
            'base': {'ref': base}, 'head': {'sha': HEAD_SHA}, 'labels': [{'name': n} for n in labels],
        },
        'repository': {'html_url': REPO_URL},
    }
    data = {'script': SCRIPT, 'payload': payload, 'comments': list(comments), 'live': live or {},
            'fail': fail or {}, 'compare': compare or {'files': []}}
    p = subprocess.run([NODE, '-e', HARNESS], capture_output=True, text=True, timeout=30,
                       input=json.dumps(data))
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    if not allow_error:
        assert out['error'] is None, out['error']
    return Run(out)


# ---- PR bodies, built from the real template ----

WHAT = 'Adds a retry to the node status poll so a single dropped request no longer marks the node offline.'
TESTED = ('Ran it against a three node PVE 8.3 lab, pulled the network on one node for 20 s, the status '
          'stayed online and came back clean. pytest tests/test_node_status.py passes.')
BASE_TICKS = ('does **one thing**', 'small, obvious fix', 'test suite passes', 'scoped to the title')


def _once(text, old, new):
    assert text.count(old) == 1, f'template anchor moved: {old!r}'
    return text.replace(old, new)


def _tick(text, phrase):
    lines = text.split('\n')
    hits = [i for i, line in enumerate(lines) if '- [ ]' in line and phrase in line]
    assert len(hits) == 1, f'template box moved: {phrase!r}'
    lines[hits[0]] = lines[hits[0]].replace('- [ ]', '- [x]', 1)
    return '\n'.join(lines)


def _drop_ai_box(text):
    """Remove the AI-assist box and its wrapped lines; the tool line stays."""
    lines = text.split('\n')
    i = next(n for n, line in enumerate(lines) if '] If I used an AI assistant' in line)
    j = i + 1
    while lines[j].startswith('      ') and '<!--' not in lines[j] and 'AI tool' not in lines[j]:
        j += 1
    del lines[i:j]
    out = '\n'.join(lines)
    assert 'AI assistant' not in out and 'AI tool / model used:' in out
    return out


def pr_body(*, tool='`none`', ai_box=False, issue=None, ticks=BASE_TICKS, drop_ai_box=False, crlf=False):
    text = _once(TEMPLATE, '<!-- What does this change, and what problem does it solve? -->', WHAT)
    if issue:
        text = _once(text, 'Fixes #<!--', f'Fixes #{issue}<!--')
    text = _once(text, '## How it was tested\n', '## How it was tested\n\n' + TESTED + '\n')
    text = _once(text, 'AI tool / model used: `none`', 'AI tool / model used: ' + tool)
    for phrase in ticks + (('AI assistant',) if ai_box else ()):
        text = _tick(text, phrase)
    if drop_ai_box:
        text = _drop_ai_box(text)
    if crlf:
        text = text.replace('\n', '\r\n')
    return text


def _r1(tool):
    return MARKER + '\n' + R1_TEXT.format(tool=tool)


# ---- the workflow file as text ----

def test_triggers_keep_the_old_types_and_add_synchronize():
    m = re.search(r'^  pull_request_target:\n    types: \[([^\]]*)\]\n    branches: \[Testing, main\]$',
                  WF_TEXT, re.M)
    assert m, 'pull_request_target trigger'
    assert {t.strip() for t in m.group(1).split(',')} == {'opened', 'edited', 'reopened', 'synchronize'}
    assert re.search(r'^on:\n  pull_request_target:\n', WF_TEXT, re.M)


def test_the_job_still_skips_maintainers():
    cond = re.search(r'^    if: >\n((?:      .*\n)+)', WF_TEXT, re.M).group(1)
    for assoc in ('OWNER', 'MEMBER', 'COLLABORATOR'):
        assert f"github.event.pull_request.author_association != '{assoc}'" in cond, assoc
    assert '||' not in cond


def test_no_checkout_and_the_permissions_are_unchanged():
    assert 'actions/checkout' not in WF_TEXT
    assert re.search(r'^permissions:\n  contents: read\n  pull-requests: write\n\n', WF_TEXT, re.M)
    assert WF_TEXT.count('permissions:') == 1, 'no job-level permissions'
    assert len(re.findall(r'\b[a-z-]+: write\b', WF_TEXT)) == 1


def test_the_action_is_pinned_by_commit():
    uses = re.findall(r'^\s*(?:- )?uses:\s*(\S+)', WF_TEXT, re.M)
    assert uses == ['actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b']
    for u in uses:
        assert re.fullmatch(r'[\w.-]+/[\w.-]+@[0-9a-f]{40}', u), u


def test_no_expression_inside_the_script():
    assert WF_TEXT.count('script: |') == 1
    assert '${{' not in SCRIPT
    assert 'const MARKER' in SCRIPT and SCRIPT.rstrip().endswith(';')
    # the only expression in the file is the concurrency group
    assert re.findall(r'\$\{\{.*?\}\}', WF_TEXT, re.S) == ['${{ github.event.pull_request.number }}']


def test_the_concurrency_group_is_kept():
    assert 'group: pr-checklist-${{ github.event.pull_request.number }}' in WF_TEXT
    assert 'cancel-in-progress: true' in WF_TEXT


def test_the_size_allowlist_holds_three_account_ids():
    ids = size_allowlist()
    assert len(ids) == 3 and len(set(ids)) == 3 and all(i > 0 for i in ids), ids
    # ids, not logins: no quoted name may be left in the list
    assert "'" not in re.search(r'const SIZE_ALLOWLIST = \[([^\]]*)\]', SCRIPT).group(1)


def test_the_script_block_scanner_would_see_an_expression():
    # counterproof for the scanner itself
    sample = 'steps:\n  - uses: x/y@z\n    with:\n      script: |\n        a();\n        // ${{ github.x }}\n  - run: ok\n'
    assert '${{' in script_block(sample)
    assert 'run: ok' not in script_block(sample)


def test_house_rules_in_this_file():
    text = Path(__file__).read_text(encoding='utf-8')
    for ch in (chr(0x2014), chr(0x2013)):
        assert ch not in text
    for uid in size_allowlist():
        assert str(uid) not in text, 'no allowlisted account spelled out in the tests'


# ---- a closed PR ----

@needs_node
def test_a_closed_pr_gets_no_call_at_all():
    r = run('', state='closed', additions=30000, files=400,
            comments=[ours(77)])
    assert r.calls == []
    assert any('closed' in line for line in r.logs), r.logs
    r = run(pr_body(tool='Copilot'), state='closed')
    assert r.calls == []


@needs_node
def test_a_bot_is_still_skipped():
    r = run('', login='dependabot[bot]')
    assert r.calls == []


# ---- the template-removed close ----

@needs_node
def test_a_removed_template_is_still_closed():
    r = run('fixed the thing, works on my box')
    assert r.closed
    assert r.comment.startswith(MARKER + '\n') and 'PR template was removed' in r.comment
    assert len(r.failed) == 1 and 'template removed' in r.failed[0]


@needs_node
def test_struck_through_sections_are_still_closed():
    body = pr_body().replace('## How it was tested', '## ~~How it was tested~~')
    r = run(body)
    assert r.closed and 'PR template was removed' in r.comment


@needs_node
def test_a_removed_template_comes_before_the_ai_rule():
    r = run('Wrote this with an assistant.\n\nAI tool / model used: Copilot', additions=30000)
    assert r.closed and 'PR template was removed' in r.comment


# ---- a named AI tool, box not ticked ----

@needs_node
def test_a_named_tool_with_the_box_unticked_is_closed_with_the_exact_text():
    r = run(pr_body(tool='`Copilot Pro 4.1`'))
    assert r.closed
    assert r.comment == _r1('Copilot Pro 4.1')
    assert len(r.named('createComment')) == 1 and r.named('updateComment') == []
    assert r.named('createComment')[0]['issue_number'] == 4242
    assert r.named('pulls.update') == [{'owner': 'PegaProx', 'repo': 'project-pegaprox',
                                        'pull_number': 4242, 'state': 'closed'}]
    assert len(r.failed) == 1


@needs_node
@pytest.mark.parametrize('tool', ['Copilot', '`GitHub Copilot`', '**Gemini 2.5**', 'Gemini, then fixed by hand'])
def test_any_value_that_is_not_none_like_counts_as_named(tool):
    r = run(pr_body(tool=tool))
    assert r.closed
    assert r.comment == _r1(tool.replace('`', ''))


@needs_node
def test_a_named_tool_with_the_box_ticked_is_not_closed():
    r = run(pr_body(tool='`Copilot Pro 4.1`', ai_box=True))
    assert not r.closed
    assert r.comment is None and r.failed == []
    assert 'checklist ok' in r.logs


@needs_node
@pytest.mark.parametrize('tool', [
    '`none`', 'none', '', 'None', 'NONE.', '`none`.', '**none**', '*none*', 'n/a', 'N/A', '`n/a`', 'na',
    'No', 'nothing', 'Nothing.', '-', '`-`', 'not used', 'Not used.', 'no AI', 'No  AI', 'kein', 'Keine',
    'keins.', '`keine`',
    # written other ways by people who used no AI
    'No AI used', 'none used', '(none)', '_none_', "'none'", '"none"', 'none!', 'none,', '--', '---',
    chr(0x2014), chr(0x2013), chr(0x2014) + chr(0x2014), 'nein', 'Nicht verwendet.',
])
def test_a_none_like_value_with_the_box_unticked_is_not_closed(tool):
    r = run(pr_body(tool=tool))
    assert not r.closed
    assert r.comment is None and r.failed == [], r.comment


@needs_node
def test_the_box_line_removed_and_a_tool_named_is_closed():
    r = run(pr_body(tool='GitHub Copilot', drop_ai_box=True))
    assert r.closed and r.comment == _r1('GitHub Copilot')


@needs_node
def test_a_box_ticked_only_inside_an_html_comment_does_not_count():
    body = pr_body(tool='Cursor', drop_ai_box=True).replace(
        'AI tool / model used:', '<!-- - [x] If I used an AI assistant -->\nAI tool / model used:')
    r = run(body)
    assert r.closed and r.comment == _r1('Cursor')


@needs_node
def test_a_draft_is_closed_too():
    r = run(pr_body(tool='Cursor Agent'), draft=True)
    assert r.closed and r.comment == _r1('Cursor Agent')


@needs_node
@pytest.mark.parametrize('i', range(3))
def test_the_ai_rule_has_no_allowlist(i):
    r = run(pr_body(tool='Copilot'), uid=listed(i))
    assert r.closed and r.comment == _r1('Copilot')


@needs_node
def test_the_tool_value_loses_backticks_and_line_breaks():
    # GitHub's web form sends CRLF bodies
    r = run(pr_body(tool='Copilot `Pro` 4', crlf=True))
    assert r.closed and r.comment == _r1('Copilot Pro 4')
    r = run(pr_body(tool='Cursor' + chr(0x2028) + ' agent ``mode``'))
    assert r.closed and r.comment == _r1('Cursor agent mode')


@needs_node
def test_the_tool_value_is_capped_at_80_characters():
    long_value = 'Gemini ' + 'abcdefghij' * 20
    r = run(pr_body(tool='`' + long_value + '`'))
    assert r.closed and r.comment == _r1(long_value[:80])
    shown = re.search(r'while `([^`]*)` is named', r.comment).group(1)
    assert len(shown) == 80


@needs_node
def test_the_ai_rule_comes_before_the_size_brake():
    r = run(pr_body(tool='Copilot'), additions=20000, deletions=1, files=40)
    assert r.closed and r.comment == _r1('Copilot')


# ---- the size brake ----

@needs_node
def test_more_than_20000_lines_closes_a_stranger_even_with_an_issue():
    r = run(pr_body(issue=12), additions=15000, deletions=5001, files=40)
    assert r.closed
    assert r.comment == MARKER + '\n' + HUGE_TEXT.format(lines=20001, files=40)
    assert len(r.failed) == 1


@needs_node
def test_exactly_20000_lines_with_an_issue_is_not_closed():
    r = run(pr_body(issue=12), additions=15000, deletions=5000, files=40)
    assert not r.closed and r.failed == []


@needs_node
@pytest.mark.parametrize('login', ['renamed-account', 'new-contributor'])
@pytest.mark.parametrize('i', range(3))
def test_an_allowlisted_account_skips_the_size_brake_whatever_its_login(i, login):
    r = run(pr_body(), login=login, uid=listed(i), additions=20000, deletions=1, files=40)
    assert not r.closed and r.failed == [], login
    r = run(pr_body(), login=login, uid=listed(i), additions=1001, files=26)
    assert not r.closed and r.failed == [], login


@needs_node
def test_an_account_not_on_the_list_is_braked_whatever_its_login():
    # a login an allowlisted contributor gave up and someone else took: another account id
    r = run(pr_body(), login='taken-over-login', uid=listed(0) + 1, additions=20000, deletions=1, files=40)
    assert r.closed and r.comment == MARKER + '\n' + HUGE_TEXT.format(lines=20001, files=40)
    r = run(pr_body(), uid=None, additions=20000, deletions=1, files=40)
    assert r.closed


@needs_node
@pytest.mark.parametrize('additions,deletions,files', [(1001, 0, 3), (600, 401, 3), (40, 0, 26)],
                         ids=['1001-lines', '1001-lines-mixed', '26-files'])
def test_a_large_pr_without_an_issue_is_closed(additions, deletions, files):
    r = run(pr_body(), additions=additions, deletions=deletions, files=files)
    assert r.closed
    assert r.comment == MARKER + '\n' + LARGE_TEXT.format(
        lines=additions + deletions, files=files, repo=REPO_URL)
    assert len(r.failed) == 1


@needs_node
@pytest.mark.parametrize('additions,files', [(1001, 3), (40, 26)], ids=['1001-lines', '26-files'])
def test_a_large_pr_with_fixes_12_is_not_closed(additions, files):
    r = run(pr_body(issue=12), additions=additions, files=files)
    assert not r.closed and r.failed == []


@needs_node
def test_at_the_limit_without_an_issue_is_not_closed():
    r = run(pr_body(), additions=700, deletions=300, files=25)
    assert not r.closed and r.failed == []


# ---- one marker comment ----

@needs_node
def test_the_marker_comment_is_updated_not_duplicated_on_a_close():
    comments = [{'id': 5, 'user': {'login': 'a-reviewer'}, 'body': 'LGTM, will test tomorrow'}, ours(77, 'old nudge')]
    r = run(pr_body(tool='Copilot'), comments=comments)
    assert r.closed
    assert r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [77]
    assert r.comment == _r1('Copilot')
    r = run(pr_body(), additions=1001, comments=comments)
    assert r.closed and r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [77]


@needs_node
def test_the_nudge_updates_the_existing_marker_comment():
    r = run(TEMPLATE, comments=[ours(77)])
    assert not r.closed and r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [77]


@needs_node
def test_a_removed_template_updates_the_existing_marker_comment():
    r = run('fixed it', comments=[ours(77)])
    assert r.closed and r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [77]


# ---- the nudge ----

@needs_node
def test_the_untouched_template_gets_the_nudge_and_stays_open():
    r = run(TEMPLATE)
    assert not r.closed
    c = r.comment
    assert c.startswith(MARKER + '\n') and 'still need filling in' in c
    assert 'The **How it was tested** section is empty' in c and 'No linked issue' in c
    assert f'[CONTRIBUTING]({REPO_URL}/blob/main/CONTRIBUTING.md)' in c
    assert len(r.failed) == 1 and r.failed[0].startswith('PR checklist incomplete')


@needs_node
def test_a_filled_template_passes_quietly():
    r = run(pr_body())
    assert [n for n, _ in r.calls] == ['pulls.get', 'listComments']
    assert 'checklist ok' in r.logs


@needs_node
def test_a_filled_template_flips_the_old_comment_to_ok():
    r = run(pr_body(issue=12), comments=[ours(77)])
    assert not r.closed and r.failed == []
    assert 'looks filled in' in r.comment


@needs_node
@pytest.mark.parametrize('tool', ['`none`', '', 'n/a', 'Keine.'])
def test_a_ticked_box_with_a_none_like_value_gets_the_ai_nudge(tool):
    r = run(pr_body(tool=tool, ai_box=True))
    assert not r.closed
    assert r.comment and 'You ticked the AI-assist box' in r.comment, r.comment
    assert len(r.failed) == 1


# ---- comment calls, the marker, PRs against main, tick and tool-line shapes ----

AI_BOX = '- [ ] If I used an AI assistant, **I have read, understood and tested every line myself** (this is'
# what a PR against main reports while Testing is ahead of it
MAIN_GAP = dict(additions=152097, deletions=6446, files=397)


def _box_as(text, new):
    return _once(text, AI_BOX, new)


@needs_node
@pytest.mark.parametrize('fail', [{'createComment': 403}, {'createComment': 502}, {'listComments': 502}],
                         ids=['create-403', 'create-502', 'list-502'])
def test_a_failed_comment_call_does_not_keep_the_pr_open(fail):
    r = run(pr_body(tool='Copilot'), fail=fail, allow_error=True)
    assert r.closed and r.error is None
    assert r.failed == ['AI tool named but the AI-assist box is not ticked - auto-closed.']
    r = run(pr_body(issue=12), additions=30000, fail=fail, allow_error=True)
    assert r.closed and r.error is None and len(r.failed) == 1


@needs_node
def test_a_failed_update_of_our_comment_does_not_keep_the_pr_open():
    r = run(pr_body(tool='Copilot'), comments=[ours(77)], fail={'updateComment': 404}, allow_error=True)
    assert [a['comment_id'] for a in r.named('updateComment')] == [77]
    assert r.closed and r.error is None
    assert any(line.startswith('warning:') for line in r.logs), r.logs


@needs_node
def test_a_marker_pasted_by_someone_else_is_not_our_comment():
    planted = {'id': 13, 'user': {'login': 'new-contributor'}, 'body': 'Thanks! ' + MARKER}
    r = run(pr_body(tool='Copilot'), comments=[planted])
    assert r.closed and r.named('updateComment') == []
    assert len(r.named('createComment')) == 1 and r.comment == _r1('Copilot')
    # a passing PR leaves somebody else's comment alone
    r = run(pr_body(issue=12), comments=[dict(planted, user={'login': 'passer-by'})])
    assert r.named('updateComment') == [] and r.named('createComment') == []


@needs_node
def test_our_comment_is_found_past_the_first_page():
    others = [{'id': i, 'user': {'login': 'a-reviewer'}, 'body': 'ping'} for i in range(1, 121)]
    r = run(pr_body(tool='Copilot'), comments=others + [ours(500)])
    assert r.closed and r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [500]
    r = run(TEMPLATE, comments=others + [ours(500)])
    assert r.named('createComment') == []
    assert [a['comment_id'] for a in r.named('updateComment')] == [500]


@needs_node
def test_a_pr_against_main_is_measured_against_testing():
    r = run(pr_body(issue=1234), base='main', compare={'files': [{'additions': 30, 'deletions': 10}]},
            **MAIN_GAP)
    assert not r.closed and r.failed == []
    assert r.named('compare') == [{'owner': 'PegaProx', 'repo': 'project-pegaprox',
                                   'basehead': 'Testing...' + HEAD_SHA}]
    r = run(pr_body(issue=1234), base='main', compare={'files': [{'additions': 700, 'deletions': 10}] * 30},
            **MAIN_GAP)
    assert r.closed and r.comment == MARKER + '\n' + HUGE_TEXT.format(lines=21300, files=30)
    r = run(pr_body(), base='main', compare={'files': [{'additions': 1100, 'deletions': 0}]}, **MAIN_GAP)
    assert r.closed and r.comment == MARKER + '\n' + LARGE_TEXT.format(lines=1100, files=1, repo=REPO_URL)


@needs_node
def test_a_pr_against_main_that_cannot_be_measured_skips_the_size_brake():
    r = run(pr_body(issue=1234), base='main', fail={'compare': 502}, **MAIN_GAP)
    assert not r.closed and r.failed == []
    assert any('size brake skipped' in line for line in r.logs), r.logs


@needs_node
def test_payload_numbers_stay_for_testing_and_for_a_base_main_label():
    r = run(pr_body(issue=12), additions=30000)
    assert r.closed and r.named('compare') == []
    # pr-target-guard leaves a PR labelled base:main on main, so its payload numbers are right
    r = run(pr_body(issue=12), base='main', labels=['base:main'], **MAIN_GAP)
    assert r.closed and r.named('compare') == []
    assert r.comment == MARKER + '\n' + HUGE_TEXT.format(lines=158543, files=397)
    r = run(pr_body(), base='main')
    assert not r.closed and r.named('compare') == []


@needs_node
def test_a_pr_closed_since_the_event_gets_nothing():
    r = run(pr_body(tool='Copilot', ai_box=True, issue=12), live={'state': 'closed'}, comments=[ours(77)])
    assert [n for n, _ in r.calls] == ['pulls.get']
    r = run(pr_body(tool='Copilot'), live={'state': 'closed'})
    assert [n for n, _ in r.calls] == ['pulls.get']


@needs_node
def test_the_event_state_is_used_when_the_current_one_cannot_be_read():
    r = run(pr_body(tool='Copilot'), fail={'pulls.get': 502})
    assert r.closed and r.comment == _r1('Copilot')


@needs_node
def test_control_and_format_characters_are_dropped_from_the_tool():
    rlo, zwsp = chr(0x202E), chr(0x200B)
    r = run(pr_body(tool='Copilot' + rlo + ' edoc' + zwsp))
    assert r.closed and r.comment == _r1('Copilot edoc')
    r = run(pr_body(tool='`none`' + zwsp))
    assert not r.closed and r.failed == [], r.comment


@needs_node
@pytest.mark.parametrize('box', [
    '- [x] If I used an AI\n      assistant, **I have read, understood and tested every line myself** (this is',
    '- [x] If I used\n      an AI assistant, **I have read, understood and tested every line myself** (this is',
    '- [x] If I used an AI-assistant, **I have read, understood and tested every line myself** (this is',
    '+ [x] If I used an AI assistant, **I have read, understood and tested every line myself** (this is',
    '1. [x] If I used an AI assistant, **I have read, understood and tested every line myself** (this is',
    '- [x] I read, understood and tested every line. (this is',
], ids=['wrapped-after-AI', 'wrapped-before-AI', 'hyphen', 'plus-bullet', 'numbered', 'reworded'])
def test_a_ticked_box_in_another_shape_still_counts(box):
    r = run(_box_as(pr_body(tool='`DeepSeek V4`'), box))
    assert not r.closed and r.failed == [], r.comment


@needs_node
def test_a_ticked_line_that_is_not_the_attestation_does_not_count():
    pending = '- [x] Human review of the AI-assisted changes is pending, no attestation is made here. (this is'
    r = run(_box_as(pr_body(tool='`GPT-6`'), pending))
    assert r.closed and r.comment == _r1('GPT-6')
    # a ticked box right above an unticked, indented AI box
    body = _once(pr_body(tool='Copilot'), "- [x] It's scoped", "  - [x] It's scoped")
    r = run(_box_as(body, '  ' + AI_BOX))
    assert r.closed and r.comment == _r1('Copilot')


@needs_node
@pytest.mark.parametrize('tested', [
    'Checked that no `<!--` is left in web/index.html after the build and the footer renders in Firefox.',
    "Ran the build and counted leftovers:\n\n```\n$ grep -c '<!--' web/index.html\n0\n```",
], ids=['code-span', 'fence'])
def test_a_stray_comment_opener_does_not_hide_the_ticked_box(tested):
    placeholder = re.search(r'<!-- Not "the CI is green".*?-->', TEMPLATE, re.S).group(0)
    r = run(_once(pr_body(tool='`Cursor Agent`', ai_box=True, issue=12), placeholder, tested))
    assert not r.closed and r.failed == [], r.comment


@needs_node
def test_every_tool_line_counts():
    r = run(pr_body() + '\nAI tool / model used: Cursor Agent')
    assert r.closed and r.comment == _r1('Cursor Agent')


@needs_node
@pytest.mark.parametrize('line', [
    '**AI tool / model used**: Copilot', '**AI tool / model used:** Copilot', 'AI tool / model: Copilot',
], ids=['bold-colon-outside', 'bold-colon-inside', 'without-used'])
def test_a_bold_or_shortened_label_still_names_the_tool(line):
    r = run(_once(pr_body(), 'AI tool / model used: `none`', line))
    assert r.closed and r.comment == _r1('Copilot')
    # with the box ticked it is not taken for a missing name either
    r = run(_once(pr_body(ai_box=True, issue=12), 'AI tool / model used: `none`', line))
    assert not r.closed and r.failed == [], r.comment


@needs_node
def test_a_full_issue_link_counts_as_linked():
    link = 'https://github.com/PegaProx/project-pegaprox/issues/1253'
    body = _once(pr_body(ticks=('does **one thing**', 'test suite passes', 'scoped to the title')),
                 'Fixes #<!--', f'Fixes {link} <!--')
    r = run(body, additions=1510)
    assert not r.closed and r.failed == [], r.comment


# ---- a maintainer keeps a PR open ----

OVERRIDE = 'checklist-override'


@needs_node
def test_the_override_label_keeps_an_unattested_ai_pr_open():
    r = run(pr_body(tool='Copilot'), labels=(OVERRIDE,))
    assert not r.closed and r.named('pulls.update') == []


@needs_node
def test_the_override_label_keeps_a_large_pr_open():
    r = run(pr_body(), labels=(OVERRIDE,), additions=20000, deletions=1, files=40)
    assert not r.closed
    r = run(pr_body(), labels=(OVERRIDE,), additions=1001, files=26)
    assert not r.closed


@needs_node
def test_the_override_label_keeps_a_template_less_pr_open_but_it_is_still_nudged():
    r = run('Small fix, see title.', labels=(OVERRIDE,))
    assert not r.closed
    assert r.comment is not None and 'Before a maintainer picks it up' in r.comment
    assert len(r.failed) == 1 and 'incomplete' in r.failed[0]


@needs_node
def test_the_override_label_counts_when_only_the_current_pr_has_it():
    # added after the event was sent: pulls.get carries it
    r = run(pr_body(tool='Copilot'), live={'labels': [{'name': OVERRIDE}]})
    assert not r.closed


@needs_node
def test_another_label_does_not_keep_the_pr_open():
    r = run(pr_body(tool='Copilot'), labels=('needs-review', 'base:main'))
    assert r.closed and r.comment == _r1('Copilot')
