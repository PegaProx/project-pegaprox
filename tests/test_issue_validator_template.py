"""issue-validator.yml closes a bug report or feature request that is still the bare template.

Every section of the untouched template has something after its heading already: the HTML
comments, the empty "1." to "3." of the steps and the ** around "PegaProx Version:". The field
checks read the raw body, so they found all three bug fields in the template itself and let an
empty report through, and a feature request passed on its length alone. An issue with no letter
or digit of its own once the template's parts are gone is now closed with every field named. A
report with text of its own keeps the checks it had, in any language and wherever the text sits.
What happens to a flagged issue (a comment, the label incomplete, closed) is unchanged.

The github-script step runs in node with context and github stubbed. The filled reports are
real ones of the tracker, shortened.

NS Nov 2026
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'issue-validator.yml')

pytestmark = pytest.mark.skipif(not shutil.which('node'), reason='needs node')

RUN = r"""
const src = process.argv[1];
const issues = JSON.parse(process.argv[2]);
(async () => {
  const out = [];
  for (const issue of issues) {
    const calls = [];
    const context = { payload: { issue }, repo: { owner: 'o', repo: 'r' } };
    const github = { rest: { issues: {
      createComment: async (a) => calls.push(['comment', a.body]),
      addLabels: async (a) => calls.push(['label', a.labels]),
      update: async (a) => calls.push(['update', a.state]),
    } } };
    const log = console.log;
    console.log = (m) => calls.push(['log', m]);
    try {
      await (new Function('context', 'github', 'return (async () => {' + src + '})()'))(context, github);
    } finally {
      console.log = log;
    }
    out.push(calls);
  }
  process.stdout.write(JSON.stringify(out));
})();
"""


def _script():
    """The script of the github-script step, as the action gets it."""
    with open(WORKFLOW, encoding='utf-8') as fh:
        lines = fh.read().split('\n')
    at = next(i for i, line in enumerate(lines) if line.strip() == 'script: |')
    src = []
    for line in lines[at + 1:]:
        if line.strip() and not line.startswith(' ' * 12):
            break
        src.append(line[12:])
    return '\n'.join(src)


def _validate(*issues):
    p = subprocess.run(['node', '-e', RUN, _script(), json.dumps(list(issues))],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr[-800:]
    return json.loads(p.stdout)


def _issue(body, kind='bug', title=None, assoc='NONE', crlf=False):
    label = {'bug': 'bug', 'feature': 'enhancement'}[kind]
    if crlf:
        body = body.replace('\n', '\r\n')
    return {'number': 7, 'body': body, 'title': title or ('[Bug] ' if kind == 'bug' else '[Feature] '),
            'labels': [{'name': label}], 'author_association': assoc, 'user': {'login': 'someone'}}


def _template(name):
    """The body GitHub fills in from the template: the file without its front matter."""
    with open(os.path.join(ROOT, '.github', 'ISSUE_TEMPLATE', name), encoding='utf-8') as fh:
        text = fh.read()
    return re.sub(r'\A---\n.*?\n---\n', '', text, count=1, flags=re.S)


def _missing(calls):
    """The fields the comment asks for, when the issue was closed."""
    assert [c[0] for c in calls] == ['comment', 'label', 'update', 'log'], calls
    assert calls[1:] == [['label', ['incomplete']], ['update', 'closed'], ['log', 'Issue closed: incomplete template']]
    return re.findall(r'^- \[ \] (.+)$', calls[0][1], re.M)


def _bug_from_template(describe=' A clear description.', steps='1. Open it\n2. Click\n3. See it fail',
                       version=' 1.4.1'):
    """The bug template filled in where the template asks, the way a reporter types into it."""
    body = _template('bug_report.md')
    body = body.replace('<!-- A clear description of what the bug is. -->',
                        '<!-- A clear description of what the bug is. -->' + describe, 1)
    body = body.replace('1. \n2. \n3. ', steps, 1)
    return re.sub(r'(- \*\*PegaProx Version:\*\* <!--.*?-->)', lambda m: m.group(1) + version, body, count=1)


# --- the untouched templates -----------------------------------------------------------------

@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_the_untouched_bug_template_is_closed_with_all_three_fields(crlf):
    [calls] = _validate(_issue(_template('bug_report.md'), crlf=crlf))
    assert _missing(calls) == ['Describe the bug', 'Steps to Reproduce', 'PegaProx Version']
    assert calls[0][1].startswith('\U0001f44b Thanks for reporting a bug!')


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_the_untouched_feature_template_is_closed(crlf):
    [calls] = _validate(_issue(_template('feature_request.md'), kind='feature', crlf=crlf))
    assert _missing(calls) == ['What feature would you like?', 'Why? What problem does it solve?',
                               'Any ideas how it could work?']
    assert calls[0][1].startswith('\U0001f44b Thanks for the feature request!')


def _older_bug_template():
    """The bug template as it was before its checklist got the last two lines."""
    body = _template('bug_report.md')
    return body[:body.index("- [ ] I've put enough in here")]


@pytest.mark.parametrize('body', [
    _template('bug_report.md').replace('- [ ] ', '- [x] '),
    _older_bug_template(),
], ids=['checklist-ticked', 'older-template'])
def test_an_untouched_bug_template_with_a_ticked_or_shorter_checklist_is_closed(body):
    [calls] = _validate(_issue(body, title='[Bug] Migration wizard fails, writes a temp file to local disk'))
    assert _missing(calls) == ['Describe the bug', 'Steps to Reproduce', 'PegaProx Version']


def test_an_untouched_feature_template_with_the_checklist_ticked_is_closed():
    body = _template('feature_request.md').replace('- [ ] ', '- [x] ')
    [calls] = _validate(_issue(body, kind='feature'))
    assert calls[0][1].startswith('\U0001f44b Thanks for the feature request!')
    assert _missing(calls)


# --- filled reports go through ---------------------------------------------------------------

REAL_BUGS = {
    # typed into the template, after its comments
    'after-the-comments': _bug_from_template(
        describe=' When deleting multiple snapshots of a VM from the snapshot overview it fires all '
                 'delete jobs at once on PVE, which ends up in failures.',
        steps='1. Create multiple snapshots on a single VM\n2. List them in PegaProx and try to bulk delete\n'
              '3. Find the failures in the task history'),
    # its own order, the version bold and without a space
    'own-layout': """**PegaProx Version:1.4.1**

Docker image: `ghcr.io/pegaprox/pegaprox:1.4.1`

## Steps to Reproduce

1. Deploy PegaProx using the official Docker image.
2. Configure a Proxmox VE 9.x cluster.
3. Open the VNC console of a VM.
4. Observe that the console fails to connect and closes immediately.

**Expected behavior:**

The VM's VNC console should open normally and display the VM screen.

## Describe the bug

Opening the VNC console of a Proxmox VM through PegaProx 1.4.1 fails. The reverse proxy
establishes the WebSocket with PegaProx (HTTP 101), and the PegaProx log has:

```text
WebSocketBadStatusException:
Handshake status 400 invalid duplicate header
```

## Environment

- PegaProx: 1.4.1
- Proxmox VE: 9.x
- Deployment: Docker
""",
    # no greeting, a build after the version, n/a for logs
    'no-greeting': """## Describe the bug
- The add / reconfigure dialog of a PVE cluster has no field for the SSH user.
- Saving the "Reconfigure cluster" dialog afterwards cleared both `ssh_user` and the stored SSH key.

## Steps to Reproduce
1. Add a PVE cluster with API user `pegaprox@pve` and an SSH key.
2. Set `ssh_user` to `root` via `POST /api/clusters/<id>/reconfigure`.
3. Open "Reconfigure cluster", change nothing related to SSH, save.
4. `ssh_user` and the SSH key are empty again.

## Expected behavior
Saving the dialog keeps SSH values that were not changed.

## Environment
- **PegaProx Version:** 1.4.1 (build 2026.10.24)
- **Installation Method:** Debian package (pegaprox 1.4.1-1)
- **OS:** Debian 13 (trixie)

## Logs
n/a

## Screenshots
n/a
""",
    # the steps are a bold word and bullets under "1."
    'bullets-under-one': """## Describe the bug
**Version:** PegaProx 1.4.1, Proxmox VE 9.2 cluster

**Summary**
With an SSH key set on a PVE cluster, the hourly temperature and in-band BMC probes connect as `root`
while everything else logs in as the API user.

## Steps to Reproduce
1. **Observed**
- sshd on each node: `USER_LOGIN acct=root ... res=failed` from the PegaProx host, about 20 per day.

## Expected behavior
The probes use the same login as `_ssh_connect`.

## Environment
- **PegaProx Version:** PegaProx 1.4.1, Proxmox VE 9.2 cluster
- **Installation Method:** Manual

## Logs
<!-- Paste relevant log output here -->
```

```
""",
    # a code block in the steps
    'code-in-the-steps': """## Describe the bug
"IO Thread (per-disk)" and the cache mode in the Advanced tab of the migration dialog are not applied.

## Steps to Reproduce
1. Migrate any VM from ESXi, Advanced tab: IO Thread on (default).
2. `qm config <vmid> | grep scsi0`

```
scsi0: vm-rbd:vm-100-disk-0,discard=on,size=32G,ssd=1
```
no `iothread=1`.

## Expected behavior
`iothread=1` on the disk, as selected in the dialog.

## Environment
- **PegaProx Version:** 1.4.1 (build 2026.10.24)
- **UI?** Corporate
""",
    # a root shell pasted as the steps: its "# " lines are no headings
    'root-shell-in-the-steps': _bug_from_template(
        steps='```\n# pveversion\npve-manager/9.1.4\n# qm start 100\n```\nThe start never returns.'),
}

REAL_FEATURES = {
    'with-greeting': _template('feature_request.md').replace(
        '<!-- What would you like PegaProx to do? -->',
        'It would be nice to have a mirror for all Debian and Proxmox packages within PegaProx.\n\n'
        '- Built-in Debian package mirror support\n- Configurable synchronization intervals', 1),
    'no-greeting': """## Describe the feature
During ESXi migrations PegaProx installs packages on the target node without asking:

- `sshpass` (auto / live clone)
- for "Prepare VirtIO drivers": `ntfs-3g`, `python3-hivex`, `libhivex-bin`

## Use Case
Our nodes are managed with Ansible. Unplanned packages on hypervisors are not acceptable in production.

## Alternatives considered
Installing the packages beforehand via our own config management.

## How important is this for you?
Would improve my workflow.
""",
}


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_filled_bug_reports_go_through(crlf):
    got = _validate(*[_issue(b, crlf=crlf) for b in REAL_BUGS.values()])
    assert dict(zip(REAL_BUGS, got)) == {name: [['log', 'Issue valid']] for name in REAL_BUGS}


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_filled_feature_requests_go_through(crlf):
    got = _validate(*[_issue(b, kind='feature', crlf=crlf) for b in REAL_FEATURES.values()])
    assert dict(zip(REAL_FEATURES, got)) == {name: [['log', 'Issue valid']] for name in REAL_FEATURES}


# --- a report with text of its own keeps the field checks it had ---------------------------

ABOVE = ('The migration wizard stops at 99 percent and leaves a file named temp on the local disk '
         'of the target node. PegaProx 1.4.1, Debian package.\n\n')

PARTLY_FILLED_BUGS = {
    # steps and version given, the description left out
    'describe-empty': _bug_from_template(describe=''),
    # described, the steps left as the template has them
    'steps-empty': _bug_from_template(steps='1. \n2. \n3. '),
    # a detailed report without the version
    'version-empty': _bug_from_template(version=''),
    # everything written above the template, the template left as it is
    'text-above-the-template': ABOVE + _template('bug_report.md'),
}

OTHER_FORMS_BUGS = {
    'chinese': _bug_from_template(describe=' 点击迁移按钮后页面卡死，没有任何错误提示。',
                                  steps='1. 打开虚拟机列表\n2. 点击迁移\n3. 页面卡死'),
    'russian': _bug_from_template(describe=' После нажатия кнопки миграции страница зависает.',
                                  steps='1. Открыть список ВМ\n2. Нажать миграцию\n3. Страница зависает'),
    'sub-heading': _bug_from_template(
        describe='\n### Summary\nThe migration stops at 99 percent and the task never ends.'),
}

OTHER_FORMS_FEATURES = {
    'only-the-use-case': _template('feature_request.md').replace(
        '<!-- Why do you need this? What problem does it solve for you? -->',
        'We run several clusters and want the same packages everywhere.', 1),
    'text-above-the-template': 'Create VM and LXC buttons at the top of the resources list, next to the '
                               'search.\n\n' + _template('feature_request.md'),
    'chinese': _template('feature_request.md').replace(
        '<!-- What would you like PegaProx to do? -->',
        '希望能够批量迁移虚拟机。', 1),
    'sub-heading': _template('feature_request.md').replace(
        '<!-- What would you like PegaProx to do? -->',
        '#### Bulk migration\nA button to migrate many VMs at once from the list view.', 1),
}


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_a_bug_report_with_text_of_its_own_and_a_field_left_out_goes_through(crlf):
    got = _validate(*[_issue(b, crlf=crlf) for b in PARTLY_FILLED_BUGS.values()])
    assert dict(zip(PARTLY_FILLED_BUGS, got)) == {name: [['log', 'Issue valid']] for name in PARTLY_FILLED_BUGS}


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_a_bug_report_in_another_script_or_with_a_sub_heading_goes_through(crlf):
    got = _validate(*[_issue(b, crlf=crlf) for b in OTHER_FORMS_BUGS.values()])
    assert dict(zip(OTHER_FORMS_BUGS, got)) == {name: [['log', 'Issue valid']] for name in OTHER_FORMS_BUGS}


@pytest.mark.parametrize('crlf', [False, True], ids=['lf', 'crlf'])
def test_a_feature_request_with_its_text_elsewhere_than_describe_the_feature_goes_through(crlf):
    got = _validate(*[_issue(b, kind='feature', crlf=crlf) for b in OTHER_FORMS_FEATURES.values()])
    assert dict(zip(OTHER_FORMS_FEATURES, got)) == {name: [['log', 'Issue valid']] for name in OTHER_FORMS_FEATURES}


def test_a_report_of_its_own_without_the_steps_is_still_asked_for_them():
    body = ('## Describe the bug\nThe backup list of a VM stays empty although PBS has three backups of it.\n\n'
            '## Environment\n- **PegaProx Version:** 1.4.1\n')
    [calls] = _validate(_issue(body))
    assert _missing(calls) == ['Steps to Reproduce']


def test_a_feature_request_typed_into_the_bug_template_is_judged_as_a_bug():
    [calls] = _validate(_issue(_bug_from_template(), title='[Feature] keep the VMID'))
    assert calls == [['log', 'Issue valid']]


def test_a_maintainer_is_not_checked():
    got = _validate(_issue(_template('bug_report.md'), assoc='MEMBER'),
                    _issue(_template('feature_request.md'), kind='feature', assoc='OWNER'))
    assert got == [[['log', 'Issue valid']]] * 2
