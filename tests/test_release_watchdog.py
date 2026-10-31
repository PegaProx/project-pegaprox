# -*- coding: utf-8 -*-
"""The release watchdog, .github/scripts/watchdog.py, against a fake GitHub API.

No network: FakeGitHub answers the API from a small commit graph, so compare, ancestry and
the changed files of a push come out the way GitHub would compute them. Each alarm has a
scenario, and each scenario is run twice: with all checks (the alarm is raised) and without
the check that should raise it (it is gone, so it came from that check and nowhere else)."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('release_watchdog', ROOT / '.github' / 'scripts' / 'watchdog.py')
wd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wd)

REPO = 'PegaProx/project-pegaprox'
NOW = datetime(2026, 10, 31, 2, 0, tzinfo=timezone.utc)
BASELINE = json.loads((ROOT / '.github' / 'watchdog' / 'baseline.json').read_text(encoding='utf-8'))
PUBLISHERS = sorted(BASELINE['workflows']['publishers'])

# the v1.4.1 release as it happened: Testing at c1936aa3, main 9974a0d0 -> ea40c362, a merge
# whose second parent is c1936aa3 and whose tree is that commit's tree
V140 = '9974a0d05fba0b1ed9084e31f93f6aa3256fad87'
T_REL = 'c1936aa354f047f3624a11bdb0ce7e6908d19ffb'
V141 = 'ea40c362c78b8d16f869f07a4d00d3f1a2028e71'
REL_TREE = 'fb2e04f98200a1711b589b9c8a65ef756e33c84f'
V141_TAG_OBJ = BASELINE['tags']['v1.4.1']
T1 = '3fc5d4ea61ac5586555e6ee949b95413e8682670'
T2 = 'b41902c4bf5c7d060fac4eecf73ff97219bb8134'
NS_MAIL = '77726945+MrMasterbay@users.noreply.github.com'
MK_MAIL = 'marcus.kellermann@pegaprox.com'
LW_MAIL = 'laura.weber@pegaprox.com'


def h(n):
    """A made-up commit id."""
    return format(n, '040x')


def ts(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime('%Y-%m-%dT%H:%M:%SZ')


def user(name):
    return {'login': name, 'id': abs(hash(name)) % 10 ** 8, 'type': 'User'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def manifest(version='1.4.1'):
    return {
        'version': version,
        'download_url': 'https://github.com/PegaProx/project-pegaprox/releases/latest',
        'update_archive': 'https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz',
        'update_mirror': 'https://updates.pegaprox.com',
        'update_files': ['pegaprox_multi_cluster.py', 'web/index.html', 'pegaprox/api/settings.py'],
        'changelog': ['fixed a thing, see https://example.org/not-a-field'],
    }


def workflow_text(sums):
    """Just enough of watchdog.yml for the pins check: the sha256sum lines."""
    lines = ['name: Release watchdog', 'jobs:', '  check:', '    steps:', '      - run: |',
             "          if sha256sum --strict --quiet -c - <<'PINS'"]
    lines += [f'          {s}  {p}' for p, s in sums.items()]
    lines += ['          PINS', '          then true; fi', '']
    return '\n'.join(lines).encode()


def mkrun(rid, wf, event, branch, sha, status='in_progress', actor='MrMasterbay', origin=REPO,
          started=5, updated=None):
    return {'id': rid, 'path': f'.github/workflows/{wf}', 'event': event, 'head_branch': branch,
            'head_sha': sha, 'status': status, 'actor': user(actor), 'triggering_actor': user(actor),
            'head_repository': {'full_name': origin} if origin else None,
            'created_at': ts(started), 'run_started_at': ts(started),
            'updated_at': ts(updated if updated is not None else 0)}


class FakeGitHub:
    def __init__(self, baseline):
        self.b = baseline
        self.order, self.commits = [], {}
        self.heads = {}
        self.repo = {'full_name': REPO, 'default_branch': 'main', 'visibility': 'public', 'private': False,
                     'archived': False, 'disabled': False, 'has_pages': True}
        self.activity = []
        self.activity_pages = None          # {ref: [[...], [...]]} to answer in Link pages
        self.tags = {n: ('tag', s) for n, s in baseline['tags'].items()}
        self.tag_objects = {}
        self.releases = []
        self.events = []
        self.rulesets = {r['id']: copy.deepcopy(r) for r in baseline['rulesets']}
        self.show_bypass = True
        self.collaborators = dict(baseline['collaborators'])
        self.runs = []
        self.last_success = ts(5)           # start of the last successful scheduled watchdog run
        self.last_completed = None          # and of the last completed one, if later
        self.watchdog_known = True
        self.wf_state = {wf: 'active' for wf in list(baseline['workflows']['publishers'])
                         + list(baseline['workflows']['others'])}
        names = set(baseline['workflows']['publishers']) | set(baseline['workflows']['others'])
        self.wf_files = {'main': set(names), 'Testing': set(names)}
        self.files = {}
        self.envs = {n: {'name': n, 'deployment_branch_policy': dict(e['deployment_branch_policy']),
                         'protection_rules': [{'id': 1, 'type': 'branch_policy'}], 'can_admins_bypass': True}
                     for n, e in baseline['environments'].items()}
        self.env_policies = {n: [list(p) for p in e['branch_policies']] for n, e in baseline['environments'].items()}
        self.pages = {'cname': 'apt.pegaprox.com', 'build_type': 'workflow', 'https_enforced': False}
        self.manifests = {}
        self.mirror = (200, manifest())
        self.override = {}
        self.testing_list_limit = 100
        self.calls, self.writes = [], []
        self.write_status = {}
        self.notified = []

    # --- the commit graph
    def add(self, sha, parents=(), tree=None, login='MrMasterbay', email=NS_MAIL, files=(), version='1.4.1'):
        self.commits[sha] = {'sha': sha, 'parents': list(parents), 'tree': tree or sha[::-1],
                             'login': login, 'email': email, 'files': list(files), 'version': version}
        self.order.append(sha)
        return sha

    def ancestors(self, sha):
        seen, todo = set(), [sha]
        while todo:
            s = todo.pop()
            if s in seen or s not in self.commits:
                continue
            seen.add(s)
            todo.extend(self.commits[s]['parents'])
        return seen

    @staticmethod
    def file_entry(f):
        # ('new', 'old') stands for a rename
        return {'filename': f[0], 'previous_filename': f[1], 'status': 'renamed'} if isinstance(f, tuple) \
            else {'filename': f}

    def cjson(self, sha, files=True):
        c = self.commits[sha]
        d = {'sha': sha, 'parents': [{'sha': p} for p in c['parents']],
             'author': user(c['login']) if c['login'] else None,
             'commit': {'tree': {'sha': c['tree']}, 'message': 'msg',
                        'author': {'name': c['login'] or 'Laura Weber', 'email': c['email']}}}
        if files:
            d['files'] = [self.file_entry(f) for f in c['files']]
        return d

    def compare(self, a, b):
        if a not in self.commits or b not in self.commits:
            return 404, {'message': 'Not Found'}
        A, B = self.ancestors(a), self.ancestors(b)
        status = 'identical' if a == b else 'ahead' if a in B else 'behind' if b in A else 'diverged'
        new = [s for s in self.order if s in B - A]
        files = {}
        for s in new:
            for f in self.commits[s]['files']:
                files[f if isinstance(f, str) else f[0]] = f
        return 200, {'status': status, 'ahead_by': len(B - A), 'behind_by': len(A - B), 'total_commits': len(new),
                     'commits': [self.cjson(s, files=False) for s in new][:100],
                     'files': [self.file_entry(files[k]) for k in sorted(files)][:300]}

    def resolve(self, ref):
        return self.heads.get(ref, ref)

    def branch_of(self, ref):
        if ref in self.heads:
            return ref
        return next((b for b, s in self.heads.items() if s == ref), ref)

    def deploy(self, branch, script=b'# the release watchdog\n', baseline=None, sums=None):
        """watchdog.yml, watchdog.py and baseline.json on a branch, the pins matching."""
        base = json.dumps(self.b if baseline is None else baseline, indent=2).encode()
        self.files[(branch, wd.SCRIPT_PATH)] = script
        self.files[(branch, wd.BASELINE_PATH)] = base
        pins = {wd.SCRIPT_PATH: sha256(script), wd.BASELINE_PATH: sha256(base)}
        pins.update(sums or {})
        self.files[(branch, wd.WATCHDOG_YML)] = workflow_text(pins)

    # --- scenario helpers
    def push(self, kind, ref, actor, before, after, minutes_ago=10, aid=None):
        self.activity.insert(0, {'id': aid or 9000 + len(self.activity), 'activity_type': kind, 'ref': ref,
                                 'actor': user(actor) if actor else None, 'before': before, 'after': after,
                                 'timestamp': ts(minutes_ago)})

    def event(self, typ, actor, payload, minutes_ago=5, eid=None):
        self.events.insert(0, {'id': str(eid or 70000 + len(self.events)), 'type': typ, 'actor': user(actor),
                               'payload': payload, 'created_at': ts(minutes_ago)})

    # --- the transport
    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers)))
        if not url.startswith(wd.API + '/'):
            if method == 'POST':
                self.notified.append((url, body))
                return 200, {}, b'', ''
            status, data = self.mirror if url == self.b['update_manifest']['mirror'] else (404, None)
            return status, {}, json.dumps(data).encode() if data is not None else b'', ''
        u = urlparse(url)
        path, q = unquote(u.path), {k: v[0] for k, v in parse_qs(u.query).items()}
        if method != 'GET':
            self.writes.append((method, path))
            status = self.write_status.get((method, path), 204 if method == 'PUT' else 202)
            return status, {}, b'', ''
        if path in self.override:
            status, data = self.override[path]
            return status, {'x-ratelimit-remaining': '0'} if status == 403 else {}, json.dumps(data).encode(), ''
        status, data, hdrs = self.route(path, q)
        hdrs = dict(hdrs, **{'x-ratelimit-remaining': '900'})
        return status, hdrs, json.dumps(data).encode(), ''

    def route(self, path, q):
        r = f'/repos/{REPO}'
        nf = (404, {'message': 'Not Found'}, {})
        if path == r:
            return 200, self.repo, {}
        m = re.fullmatch(re.escape(r) + r'/branches/([^/]+)', path)
        if m:
            sha = self.heads.get(m.group(1))
            return (200, {'name': m.group(1), 'commit': {'sha': sha}}, {}) if sha else nf
        if path == r + '/commits':
            out, s = [], self.resolve(q.get('sha', 'main'))
            while s in self.commits and len(out) < min(int(q.get('per_page', 30)), self.testing_list_limit):
                out.append(self.cjson(s, files=False))
                s = (self.commits[s]['parents'] or [None])[0]
            return 200, out, {}
        m = re.fullmatch(re.escape(r) + r'/commits/([0-9a-f]{40})', path)
        if m:
            return (200, self.cjson(m.group(1)), {}) if m.group(1) in self.commits else nf
        m = re.fullmatch(re.escape(r) + r'/compare/([0-9a-f]{40})\.\.\.([0-9a-f]{40})', path)
        if m:
            status, data = self.compare(m.group(1), m.group(2))
            return status, data, {}
        if path == r + '/activity':
            ref = q.get('ref')
            if self.activity_pages is not None:
                pages = self.activity_pages.get(ref, [[]])
                page = int(q.get('page', 0))
                hdrs = {}
                if page + 1 < len(pages):
                    hdrs['link'] = f'<{wd.API}{r}/activity?page={page + 1}&ref={ref}>; rel="next"'
                return 200, pages[page], hdrs
            # like GitHub: newest first, per_page at a time, a Link to the next page
            hits = [a for a in self.activity if ref is None or a['ref'] == ref]
            size, page = int(q.get('per_page', 30)), int(q.get('page', 1))
            hdrs = {}
            if page * size < len(hits):
                hdrs['link'] = f'<{wd.API}{r}/activity?per_page={size}&page={page + 1}&ref={ref or ""}>; rel="next"'
            return 200, hits[(page - 1) * size:page * size], hdrs
        if path == r + '/git/matching-refs/tags/v':
            return 200, [{'ref': f'refs/tags/{n}', 'object': {'type': t, 'sha': s}}
                         for n, (t, s) in sorted(self.tags.items()) if n.startswith('v')], {}
        m = re.fullmatch(re.escape(r) + r'/git/tags/([0-9a-f]{40})', path)
        if m:
            obj = self.tag_objects.get(m.group(1))
            return (200, {'object': obj}, {}) if obj else nf
        m = re.fullmatch(re.escape(r) + r'/contents/(.+)', path)
        if m:
            fpath, ref = m.group(1), q.get('ref', 'main')
            branch, sha = self.branch_of(ref), self.resolve(ref)
            if fpath == 'version.json':
                if ref in self.manifests:
                    doc = self.manifests[ref]
                elif branch in self.manifests:
                    doc = self.manifests[branch]
                elif sha in self.commits:
                    doc = manifest(self.commits[sha]['version'])
                else:
                    return nf
                if doc is None:
                    return nf
                raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
                return 200, {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}, {}
            if fpath == '.github/workflows':
                names = self.wf_files.get(branch)
                return (200, [{'name': n, 'type': 'file'} for n in sorted(names)], {}) if names is not None else nf
            data = self.files.get((branch, fpath))
            if data is None:
                return nf
            return 200, {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(data).decode()}, {}
        if path == r + '/releases':
            return 200, self.releases, {}
        if path == r + '/events':
            return 200, self.events, {}
        if path == r + '/collaborators':
            return 200, [{'login': n, 'role_name': role} for n, role in sorted(self.collaborators.items())], {}
        if path == r + '/rulesets':
            return 200, [{'id': i, 'name': x['name'], 'enforcement': x['enforcement']} for i, x in self.rulesets.items()], {}
        m = re.fullmatch(re.escape(r) + r'/rulesets/(\d+)', path)
        if m:
            x = copy.deepcopy(self.rulesets.get(int(m.group(1))))
            if x is None:
                return nf
            if not self.show_bypass:
                x.pop('bypass_actors', None)
            x.update({'source_type': 'Repository', 'source': REPO, 'node_id': 'RRS_x', '_links': {}})
            return 200, x, {}
        if path == r + '/actions/runs':
            return 200, {'total_count': len(self.runs), 'workflow_runs': self.runs}, {}
        if path == r + '/actions/workflows':
            return 200, {'workflows': [{'path': f'.github/workflows/{n}', 'state': s} for n, s in self.wf_state.items()]}, {}
        if path == r + '/actions/workflows/watchdog.yml/runs' and q.get('event') == 'schedule':
            if not self.watchdog_known:
                return nf
            at = self.last_success if q.get('status') == 'success' else (self.last_completed or self.last_success)
            runs = [] if at is None else [
                {'id': 1, 'status': 'completed', 'conclusion': 'success', 'event': 'schedule',
                 'created_at': at, 'run_started_at': at}]
            return 200, {'total_count': len(runs), 'workflow_runs': runs}, {}
        m = re.fullmatch(re.escape(r) + r'/actions/workflows/([^/]+)', path)
        if m:
            return (200, {'state': self.wf_state[m.group(1)]}, {}) if m.group(1) in self.wf_state else nf
        m = re.fullmatch(re.escape(r) + r'/actions/workflows/([^/]+)/runs', path)
        if m:
            runs = [x for x in self.runs if x['path'].split('@')[0].endswith('/' + m.group(1))
                    and ('status' not in q or x['status'] == q['status'])]
            return 200, {'workflow_runs': runs}, {}
        if path == r + '/environments':
            return 200, {'environments': list(self.envs.values())}, {}
        m = re.fullmatch(re.escape(r) + r'/environments/([^/]+)/deployment-branch-policies', path)
        if m:
            pols = self.env_policies.get(m.group(1), [])
            return 200, {'branch_policies': [{'name': a, 'type': b} for a, b in pols]}, {}
        if path == r + '/pages':
            return (200, self.pages, {}) if self.pages else nf
        return nf


def healthy():
    """Testing a little past the v1.4.1 release, main on the v1.4.1 merge, nothing odd."""
    w = FakeGitHub(copy.deepcopy(BASELINE))
    old = w.add(h(1), version='1.3.0')
    w.add(V140, parents=[old], version='1.4.0')
    w.add(T_REL, parents=[old], tree=REL_TREE)
    w.add(V141, parents=[V140, T_REL], tree=REL_TREE)
    w.add(T1, parents=[T_REL], login='mkellermann97', email=MK_MAIL, files=['pegaprox/core/db.py'])
    w.add(T2, parents=[T1], login='mkellermann97', email=MK_MAIL, files=['web/src/dashboard.js'])
    w.heads = {'main': V141, 'Testing': T2}
    w.deploy('main')
    w.deploy('Testing')
    w.push('push', 'refs/heads/Testing', 'MrMasterbay', T1, T2, minutes_ago=12)
    w.releases = [
        {'id': 1, 'tag_name': 'v1.4.1', 'draft': False, 'author': user('MrMasterbay'),
         'published_at': '2026-10-24T21:55:24Z',
         'assets': [{'id': 11, 'name': 'pegaprox-latest-vm-amd64.ova', 'state': 'uploaded',
                     'uploader': user('github-actions[bot]'), 'created_at': '2026-10-24T22:30:00Z',
                     'updated_at': '2026-10-24T22:30:00Z'}]},
        {'id': 337662652, 'tag_name': '0.9.12.3', 'draft': False, 'author': user('github-actions[bot]'),
         'published_at': '2026-06-11T04:00:00Z',
         'assets': [{'id': 12, 'name': 'pegaprox-vm.qcow2', 'state': 'uploaded',
                     'uploader': user('github-actions[bot]'), 'created_at': '2026-06-11T05:00:00Z',
                     'updated_at': '2026-06-11T05:00:00Z'}]},
    ]
    w.event('IssueCommentEvent', 'somebody', {'action': 'created'}, minutes_ago=400)
    w.event('WatchEvent', 'somebody', {'action': 'started'}, minutes_ago=30)
    w.event('PushEvent', 'MrMasterbay', {'ref': 'refs/heads/Testing', 'head': T2, 'before': T1}, minutes_ago=12)
    w.event('IssueCommentEvent', 'somebody', {'action': 'created'}, minutes_ago=3)
    w.runs = [mkrun(501, 'docker-testing.yml', 'push', 'Testing', T2),
              mkrun(502, 'test.yml', 'push', 'Testing', T2, status='completed', updated=2),
              {'id': 503, 'path': 'dynamic/github-code-scanning/codeql', 'event': 'dynamic', 'head_branch': 'main',
               'head_sha': V141, 'status': 'completed', 'actor': user('MrMasterbay'),
               'triggering_actor': user('MrMasterbay'), 'head_repository': {'full_name': REPO}}]
    return w


def run(w, skip=None, env=None, window=40, events=360):
    ctx = wd.Ctx(wd.Api('test-token', w), w.b, NOW, window, events, env or {})
    wd.run_checks(ctx, [c for c in wd.CHECKS if c[0] != skip])
    return ctx.report


def alarm_keys(rep):
    return [(f.check, f.key) for f in rep.alarms]


def not_checked(rep, check=None):
    return [f.text for f in rep.findings if f.level == wd.NOT_CHECKED and (check is None or f.check == check)]


def notes(rep, check=None):
    return [f.text for f in rep.findings if f.level == wd.NOTE and (check is None or f.check == check)]


# ---------------------------------------------------------------------------------------
# the quiet cases

def test_the_healthy_state_raises_nothing_and_checks_everything():
    rep = run(healthy())
    assert alarm_keys(rep) == []
    assert not_checked(rep) == []
    assert set(rep.checks) == {name for name, _ in wd.CHECKS}
    assert all(rep.status(c) == 'ok' for c in rep.checks), [(c, rep.status(c)) for c in rep.checks]


def test_the_v141_release_as_it_happened_raises_nothing():
    w = healthy()
    # main moves from the v1.4.0 merge to the v1.4.1 merge inside the window, the tag is new
    w.heads['Testing'] = T_REL
    w.activity = []
    w.push('push', 'refs/heads/main', 'MrMasterbay', V140, V141, minutes_ago=20)
    del w.b['tags']['v1.4.1']
    w.tag_objects[V141_TAG_OBJ] = {'type': 'commit', 'sha': V141}
    # Testing's commit list does not reach the release commit: only the merge rule explains main
    w.testing_list_limit = 0
    w.runs = [mkrun(600 + i, wf, ev, 'v1.4.1', V141, started=18)
              for i, (wf, ev) in enumerate([('docker.yml', 'push'), ('release-images.yml', 'release'),
                                            ('apt-repo.yml', 'release'), ('sbom.yml', 'release')])]
    # the SBOM and the .deb land on the release while those runs go
    w.releases[0]['assets'] += [
        {'id': 14, 'name': 'pegaprox-sbom.cdx.json', 'state': 'uploaded', 'uploader': user('github-actions[bot]'),
         'created_at': ts(10), 'updated_at': ts(10)}]
    w.event('CreateEvent', 'MrMasterbay', {'ref': 'v1.4.1', 'ref_type': 'tag'}, minutes_ago=18)
    w.event('ReleaseEvent', 'MrMasterbay', {'action': 'published', 'release': {'tag_name': 'v1.4.1'}}, minutes_ago=18)
    rep = run(w)
    assert alarm_keys(rep) == []
    assert not_checked(rep) == []
    assert any('release merge of Testing commit c1936aa3' in t for t in rep.passed['branches'])
    assert any('new tag v1.4.1' in t for t in rep.passed['tags'])
    assert any('pegaprox-sbom.cdx.json' in t and 'by run 6' in t for t in rep.passed['releases'])


def test_the_normal_testing_push_flow_raises_nothing():
    w = healthy()
    # NS changes a workflow, LW (no account, by mail) the APT tooling, MK merges a contributor PR
    a = w.add(h(10), parents=[T2], files=['.github/workflows/docker.yml'])
    b = w.add(h(11), parents=[a], login=None, email=LW_MAIL, files=['packaging/apt/build-apt-repo.sh'])
    c = w.add(h(12), parents=[b], login='a-contributor', email='x@users.noreply.github.com',
              files=['web/src/translations.js'])
    m = w.add(h(13), parents=[b, c], login='mkellermann97', email=MK_MAIL)
    w.heads['Testing'] = m
    w.push('push', 'refs/heads/Testing', 'MrMasterbay', T2, b, minutes_ago=8)
    w.push('pr_merge', 'refs/heads/Testing', 'mkellermann97', b, m, minutes_ago=4)
    w.runs += [mkrun(510, 'docker-testing.yml', 'push', 'Testing', b, started=8),
               mkrun(511, 'test.yml', 'push', 'Testing', b, started=8, status='completed', updated=4)]
    rep = run(w)
    assert alarm_keys(rep) == []
    assert not_checked(rep) == []
    assert any('2 commit(s) of them looked at' in t for t in rep.passed['workflow-files'])


def test_ns_changes_the_watchdog_on_testing_the_way_it_is_meant_to():
    # watchdog.py, baseline.json and the pins in watchdog.yml in one commit, pushed by NS,
    # and a new workflow that the new baseline (pinned on Testing) lists
    w = healthy()
    new_b = copy.deepcopy(w.b)
    new_b['workflows']['others']['nightly-lint.yml'] = 'lints'
    c = w.add(h(14), parents=[T2], files=[wd.WATCHDOG_YML, wd.SCRIPT_PATH, wd.BASELINE_PATH,
                                          '.github/workflows/nightly-lint.yml'])
    w.heads['Testing'] = c
    w.deploy('Testing', script=b'# the release watchdog, version two\n', baseline=new_b)
    w.wf_files['Testing'].add('nightly-lint.yml')
    w.push('push', 'refs/heads/Testing', 'MrMasterbay', T2, c, minutes_ago=6)
    w.runs.append(mkrun(512, 'nightly-lint.yml', 'push', 'Testing', c, started=6))
    rep = run(w)
    assert alarm_keys(rep) == []
    assert not_checked(rep) == []


def test_old_activity_and_events_are_outside_the_window():
    w = healthy()
    w.push('force_push', 'refs/heads/Testing', 'mallory', T1, T2, minutes_ago=41)
    w.event('MemberEvent', 'mallory', {'action': 'added', 'member': user('mallory')}, minutes_ago=380)
    assert alarm_keys(run(w)) == []
    # a wider window sees both
    keys = {k.split(':')[0] for _, k in alarm_keys(run(w, window=60, events=400))}
    assert {'push', 'event'} <= keys


def test_a_lagging_event_inside_six_hours_still_counts():
    w = healthy()
    w.event('MemberEvent', 'MrMasterbay', {'action': 'added', 'member': user('newcomer')}, minutes_ago=200)
    assert ('events', f'event:{w.events[0]["id"]}') in alarm_keys(run(w))


def test_a_fork_pull_request_cannot_freeze_anything():
    # anyone can fork, add `on: pull_request` to a publisher or a new workflow, and open a PR;
    # GitHub runs it sandboxed (read-only token, no secrets), so it is a note, not an alarm
    w = healthy()
    w.runs += [mkrun(4242, 'sbom.yml', 'pull_request', 'patch-1', h(0x4242), status='completed',
                     actor='random-user', origin='random-user/project-pegaprox'),
               mkrun(4243, 'evil.yml', 'pull_request', 'patch-1', h(0x4242), actor='random-user',
                     origin='random-user/project-pegaprox'),
               mkrun(4244, 'docker.yml', 'pull_request', 'patch-2', h(0x4243), actor='random-user', origin=None)]
    rep = run(w)
    assert alarm_keys(rep) == []
    assert len([t for t in notes(rep, 'workflow-runs') if 'sandboxed' in t]) == 3


def test_a_tag_pushed_a_minute_before_main_is_not_checked_not_an_alarm():
    # git push origin v1.4.2; git push origin main, and a scheduled run in between
    w = healthy()
    t = w.add(h(0x142), parents=[T2], version='1.4.2', files=['version.json'])
    m = w.add(h(0x143), parents=[V141, t], tree=w.commits[t]['tree'], version='1.4.2')
    w.heads['Testing'] = t
    _new_tag(w, 'v1.4.2', m)
    w.releases.insert(0, {'id': 7, 'tag_name': 'v1.4.2', 'draft': False, 'author': user('MrMasterbay'),
                          'published_at': ts(1),
                          'assets': [{'id': 70, 'name': 'pegaprox-v1.4.2.cdx.json', 'state': 'uploaded',
                                      'uploader': user('github-actions[bot]'), 'created_at': ts(1), 'updated_at': ts(1)}]})
    # the release workflows already run on the tag's commit, which is not on main yet
    w.runs += [mkrun(700 + i, wf, ev, 'v1.4.2', m, started=2)
               for i, (wf, ev) in enumerate([('docker.yml', 'push'), ('sbom.yml', 'release')])]
    rep = run(w)
    assert alarm_keys(rep) == []
    assert any('not on main yet' in t for t in not_checked(rep, 'tags'))
    assert any('could not be verified' in t for t in not_checked(rep, 'releases'))
    # and once main is there it passes
    w.heads['main'] = m
    w.push('push', 'refs/heads/main', 'MrMasterbay', V141, m, minutes_ago=1)
    rep = run(w)
    assert alarm_keys(rep) == [] and not_checked(rep) == []


def test_one_failed_read_during_a_release_is_not_an_alarm():
    w = healthy()
    t = w.add(h(0x142), parents=[T2], version='1.4.2', files=['version.json'])
    m = w.add(h(0x143), parents=[V141, t], tree=w.commits[t]['tree'], version='1.4.2')
    w.heads.update(Testing=t, main=m)
    w.push('push', 'refs/heads/main', 'MrMasterbay', V141, m, minutes_ago=15)
    _new_tag(w, 'v1.4.2', m)
    w.releases.insert(0, {'id': 7, 'tag_name': 'v1.4.2', 'draft': False, 'author': user('MrMasterbay'),
                          'published_at': ts(12), 'assets': []})
    assert alarm_keys(run(w)) == []
    real = w.route

    def route(path, q):
        if path == f'/repos/{REPO}/contents/version.json' and q.get('ref') == m:
            return 502, {'message': 'Server Error'}, {}
        return real(path, q)
    w.route = route
    rep = run(w)
    assert alarm_keys(rep) == []
    assert not_checked(rep, 'tags') and not_checked(rep, 'releases')


def test_a_late_reupload_by_a_dispatched_run_is_fine():
    # v1.4.1's VM images went up again 11 hours after the release, from a release-images.yml
    # run dispatched on Testing; that run passes the run check, so the change is explained
    w = healthy()
    w.releases[0]['assets'].append({'id': 15, 'name': 'pegaprox-vm-arm64.qcow2', 'state': 'uploaded',
                                    'uploader': user('github-actions[bot]'), 'created_at': ts(2),
                                    'updated_at': ts(2)})
    w.runs.append(mkrun(40176500158, 'release-images.yml', 'workflow_dispatch', 'Testing', T2, started=20,
                        status='completed', updated=1))
    rep = run(w)
    assert alarm_keys(rep) == []
    assert any('by run 40176500158' in t for t in rep.passed['releases'])


# ---------------------------------------------------------------------------------------
# every alarm, and its counterproof

def _new_main_head(w, files=('pegaprox/app.py',)):
    bad = w.add(h(66), parents=[V141], files=list(files))
    w.heads['main'] = bad
    return bad


def _new_tag(w, name, target, annotated=True):
    if annotated:
        obj = h(0xa0000 + len(w.tag_objects))
        w.tag_objects[obj] = {'type': 'commit', 'sha': target}
        w.tags[name] = ('tag', obj)
    else:
        w.tags[name] = ('commit', target)


def _ruleset(w, rid, **kw):
    w.rulesets[rid].update(kw)


def _env(w, name, **kw):
    w.envs[name].update(kw)


def _testing_commit(w, n, files, login='mkellermann97', email=MK_MAIL, actor='mkellermann97', kind='push'):
    c = w.add(h(n), parents=[w.heads['Testing']], login=login, email=email, files=files)
    w.push(kind, 'refs/heads/Testing', actor, w.heads['Testing'], c, minutes_ago=6)
    w.heads['Testing'] = c
    return c


def _main_push(w, n, version='1.4.1', actor='MrMasterbay', tree_of=None, minutes_ago=5):
    t = w.add(h(n), parents=[w.heads['Testing']], version=version)
    tree = w.commits[tree_of or t]['tree']
    m = w.add(h(n + 1), parents=[w.heads['main'], t], tree=tree, version=version)
    w.push('push', 'refs/heads/main', actor, w.heads['main'], m, minutes_ago=minutes_ago)
    w.heads.update(Testing=t, main=m)
    return m


def _side_branch_run(w, rid, wf, files, event='push', actor='some-autofix[bot]'):
    side = w.add(h(rid), parents=[T1], login=actor, email='bot@invalid', files=files)
    w.runs.append(mkrun(rid, wf, event, 'fix/autofix-security-1', side, actor=actor))
    return side


def _fresh_asset(w, minutes_ago=3):
    w.releases[0]['assets'] = [{'id': 99, 'name': 'pegaprox-latest-vm-amd64.ova', 'state': 'uploaded',
                                'uploader': user('github-actions[bot]'), 'created_at': ts(minutes_ago),
                                'updated_at': ts(minutes_ago)}]


SCENARIOS = {
    # coverage is tested on its own below
    # settings
    'default branch changed': (lambda w: w.repo.update(default_branch='evil'), 'settings', 'settings:default_branch'),
    'repository made private': (lambda w: w.repo.update(visibility='private'), 'settings', 'settings:visibility'),
    'repository archived': (lambda w: w.repo.update(archived=True), 'settings', 'settings:archived'),
    'Pages switched off': (lambda w: w.repo.update(has_pages=False), 'settings', 'settings:has_pages'),
    # collaborators
    'a collaborator added': (lambda w: w.collaborators.update(mallory='write'), 'collaborators',
                             'collaborator:mallory'),
    'a collaborator made admin': (lambda w: w.collaborators.update(Ghoszbust3r='admin'), 'collaborators',
                                  'collaborator:Ghoszbust3r'),
    # branches
    'main moved to a tree that is not on Testing': (
        lambda w: _new_main_head(w), 'branches', 'main-head:'),
    'Testing is gone': (lambda w: w.heads.pop('Testing'), 'branches', 'branch-missing:Testing'),
    'main serves an older version than the newest release tag': (
        lambda w: w.heads.update(main=w.add(h(68), parents=[V141], tree=w.commits[h(1)]['tree'], version='1.3.0')),
        'branches', 'main-version:'),
    # pins
    'watchdog.py on Testing changed without the workflow file': (
        lambda w: w.files.update({('Testing', wd.SCRIPT_PATH): b'# the watchdog, quietly off\n'}),
        'pins', 'pin:Testing:.github/scripts/watchdog.py'),
    'baseline.json on main changed without the workflow file': (
        lambda w: w.files.update({('main', wd.BASELINE_PATH): b'{"allowed_actors": ["mallory"]}'}),
        'pins', 'pin:main:.github/watchdog/baseline.json'),
    'watchdog.yml on Testing no longer pins the baseline': (
        lambda w: w.files.update({('Testing', wd.WATCHDOG_YML): workflow_text(
            {wd.SCRIPT_PATH: sha256(w.files[('Testing', wd.SCRIPT_PATH)])})}),
        'pins', 'pin:Testing:.github/watchdog/baseline.json:none'),
    # pushes
    'force push to Testing': (
        lambda w: w.push('force_push', 'refs/heads/Testing', 'MrMasterbay', T1, T2), 'pushes', 'push:'),
    'push whose new head does not descend from the old one': (
        lambda w: w.push('push', 'refs/heads/Testing', 'MrMasterbay', V140, T2), 'pushes', 'push:'),
    'push to Testing by someone outside the team': (
        lambda w: w.push('push', 'refs/heads/Testing', 'mallory', T1, T2), 'pushes', 'push:'),
    'PR merged into Testing by someone outside the team': (
        lambda w: w.push('pr_merge', 'refs/heads/Testing', 'mallory', T1, T2), 'pushes', 'push:'),
    'push without an actor': (
        lambda w: w.push('push', 'refs/heads/Testing', None, T1, T2), 'pushes', 'push:'),
    'Testing deleted': (
        lambda w: w.push('branch_deletion', 'refs/heads/Testing', 'MrMasterbay', T2, wd.ZERO_SHA), 'pushes', 'push:'),
    'main created again': (
        lambda w: w.push('branch_creation', 'refs/heads/main', 'MrMasterbay', wd.ZERO_SHA, V141), 'pushes', 'push:'),
    'main pushed to an unexplained commit and back': (
        lambda w: w.push('push', 'refs/heads/main', 'MrMasterbay', V141, w.add(h(67), parents=[V141])),
        'pushes', 'push:'),
    'main moved by a team member who is no release manager': (
        lambda w: _main_push(w, 0x300, actor='Ghoszbust3r'), 'pushes', 'push:'),
    'main moved back to an older Testing tree': (
        lambda w: _main_push(w, 0x302, version='1.3.0', tree_of=h(1)), 'pushes', 'push:'),
    # workflow files
    'a workflow changed by an outside author on Testing': (
        lambda w: _testing_commit(w, 20, ['.github/workflows/docker.yml'], login='mallory', email='m@evil.invalid',
                                  actor='MrMasterbay'),
        'workflow-files', 'workflow-file:'),
    'the watchdog itself changed by a bot': (
        lambda w: _testing_commit(w, 21, ['.github/scripts/watchdog.py', '.github/watchdog/baseline.json'],
                                  login='some-app[bot]', email='bot@invalid', actor='MrMasterbay', kind='pr_merge'),
        'workflow-files', 'workflow-file:'),
    'the watchdog changed on Testing by a team member who does not maintain it': (
        lambda w: _testing_commit(w, 22, [wd.SCRIPT_PATH, wd.BASELINE_PATH]), 'workflow-files', 'own-files:'),
    'a contributor PR moves watchdog.yml out of .github/workflows': (
        lambda w: _testing_commit(w, 23, [('.github/watchdog-off/watchdog.yml', wd.WATCHDOG_YML)],
                                  login='a-contributor', email='x@users.noreply.github.com', actor='MrMasterbay',
                                  kind='pr_merge'),
        'workflow-files', 'workflow-file:'),
    'an unknown workflow on main': (
        lambda w: w.wf_files['main'].add('publish-elsewhere.yml'), 'workflow-files', 'workflow-unknown:main:'),
    'an unknown workflow on Testing': (
        lambda w: w.wf_files['Testing'].add('publish-elsewhere.yml'), 'workflow-files', 'workflow-unknown:Testing:'),
    # tags
    'release tag moved': (
        lambda w: w.tags.update({'v1.4.0': ('tag', h(30))}), 'tags', 'tag-moved:v1.4.0'),
    'release tag deleted': (lambda w: w.tags.pop('v1.3.0'), 'tags', 'tag-deleted:v1.3.0'),
    'new tag on a side-branch commit': (
        lambda w: _new_tag(w, 'v1.4.2', w.add(h(32), parents=[T1], version='1.4.2')), 'tags', 'tag-new:v1.4.2'),
    'new tag whose name is not the version there': (
        lambda w: _new_tag(w, 'v1.5.0', V141, annotated=False), 'tags', 'tag-new:v1.5.0'),
    'new tag pointing at a tree': (
        lambda w: w.tags.update({'v1.4.3': ('tree', h(31))}), 'tags', 'tag-new:v1.4.3'),
    # releases
    'release published by someone outside the team': (
        lambda w: w.releases[0].update(author=user('mallory')), 'releases', 'release:1:'),
    'release published by a team member who is no release manager': (
        lambda w: w.releases[0].update(author=user('Ghoszbust3r')), 'releases', 'release:1:'),
    'release for a tag that is no release tag': (
        lambda w: w.releases.insert(0, {'id': 2, 'tag_name': 'v9.9.9', 'draft': False,
                                        'author': user('MrMasterbay'), 'assets': []}), 'releases', 'release:2:'),
    'asset uploaded by a person, not by Actions': (
        lambda w: w.releases[1]['assets'].append({'id': 13, 'name': 'pegaprox-vm.qcow2', 'state': 'uploaded',
                                                  'uploader': user('MrMasterbay'), 'updated_at': ts(5)}),
        'releases', 'release-asset:13'),
    'asset swapped 3 minutes ago with no publisher run behind it': (
        lambda w: _fresh_asset(w), 'releases', 'release-asset:99:'),
    'asset swapped by a publisher run on a side branch': (
        lambda w: (_fresh_asset(w), w.runs.append(mkrun(803, 'release-images.yml', 'workflow_dispatch', 'deps-fix-1',
                                                         w.add(h(803), parents=[T1]), started=9))),
        'releases', 'release-asset:99:'),
    # events
    'a collaborator added, seen in the feed': (
        lambda w: w.event('MemberEvent', 'MrMasterbay', {'action': 'added', 'member': user('x')}), 'events', 'event:'),
    'the repository made public again': (lambda w: w.event('PublicEvent', 'MrMasterbay', {}), 'events', 'event:'),
    'a v tag deleted, seen in the feed': (
        lambda w: w.event('DeleteEvent', 'MrMasterbay', {'ref': 'v1.4.1', 'ref_type': 'tag'}), 'events', 'event:'),
    'Testing deleted, seen in the feed': (
        lambda w: w.event('DeleteEvent', 'MrMasterbay', {'ref': 'Testing', 'ref_type': 'branch'}), 'events', 'event:'),
    'a tag created by an outsider, seen in the feed': (
        lambda w: w.event('CreateEvent', 'mallory', {'ref': 'v2.0.0', 'ref_type': 'tag'}), 'events', 'event:'),
    'a v tag created by a team member who is no release manager': (
        lambda w: w.event('CreateEvent', 'Ghoszbust3r', {'ref': 'v1.4.2', 'ref_type': 'tag'}), 'events', 'event:'),
    'a push to main by an outsider, seen in the feed': (
        lambda w: w.event('PushEvent', 'mallory', {'ref': 'refs/heads/main'}), 'events', 'event:'),
    'a push to main by a team member who is no release manager': (
        lambda w: w.event('PushEvent', 'gyptazy', {'ref': 'refs/heads/main'}), 'events', 'event:'),
    'a release by an outsider, seen in the feed': (
        lambda w: w.event('ReleaseEvent', 'mallory', {'action': 'published', 'release': {'tag_name': 'v1.4.1'}}),
        'events', 'event:'),
    # rulesets
    'ruleset gone': (lambda w: w.rulesets.pop(25587029), 'rulesets', 'ruleset:25587029'),
    'ruleset switched off': (lambda w: _ruleset(w, 25587030, enforcement='disabled'), 'rulesets', 'ruleset:25587030'),
    'ruleset lost its no-force-push rule': (
        lambda w: _ruleset(w, 25587029, rules=[{'type': 'deletion'}]), 'rulesets', 'ruleset:25587029'),
    'ruleset now covers fewer branches': (
        lambda w: _ruleset(w, 25587029, conditions={'ref_name': {'include': ['refs/heads/main'], 'exclude': []}}),
        'rulesets', 'ruleset:25587029'),
    'ruleset got a bypass actor': (
        lambda w: _ruleset(w, 25587030, bypass_actors=[{'actor_type': 'RepositoryRole', 'actor_id': 5,
                                                        'bypass_mode': 'always'}]), 'rulesets', 'ruleset:25587030'),
    'ruleset edited and changed back': (
        lambda w: _ruleset(w, 13059997, updated_at='2026-10-31T01:50:00.000+02:00'), 'rulesets', 'ruleset:13059997'),
    # workflow runs
    'docker.yml started by an outsider': (
        lambda w: w.runs.append(dict(mkrun(777, 'docker.yml', 'workflow_dispatch', 'main', V141),
                                     triggering_actor=user('compromised-app[bot]'))), 'workflow-runs', 'run:777'),
    'publisher run from a fork, not a pull request': (
        lambda w: w.runs.append(mkrun(778, 'sbom.yml', 'workflow_dispatch', 'x', V141,
                                      origin='mallory/project-pegaprox')), 'workflow-runs', 'run:778'),
    'publisher run that names no head repository': (
        lambda w: w.runs.append(mkrun(779, 'sbom.yml', 'workflow_dispatch', 'x', V141, origin=None)),
        'workflow-runs', 'run:779'),
    'a bot runs release-images.yml on its own branch': (
        lambda w: _side_branch_run(w, 37405369089, 'release-images.yml', ['.github/workflows/release-images.yml']),
        'workflow-runs', 'run:37405369089'),
    'a team token dispatches a publisher on a side branch': (
        lambda w: w.runs.append(mkrun(802, 'release-images.yml', 'workflow_dispatch', 'deps-fix-0a1b2c',
                                      w.add(h(802), parents=[T1], files=['pegaprox/app.py']))),
        'workflow-runs', 'run:802'),
    'a run of a workflow nobody knows, on Testing itself': (
        lambda w: w.runs.append(mkrun(805, 'publish-elsewhere.yml', 'push', 'Testing', T2)),
        'workflow-runs', 'run:805'),
    'a side branch brings a workflow nobody knows': (
        lambda w: _side_branch_run(w, 801, 'fix.yml', ['.github/workflows/fix.yml']), 'workflow-runs', 'run:801'),
    'a side branch runs a changed copy of a known workflow': (
        lambda w: _side_branch_run(w, 804, 'test.yml', ['.github/workflows/test.yml'], event='pull_request'),
        'workflow-runs', 'run:804'),
    # update manifest
    'main sends the updater to another archive': (
        lambda w: w.manifests.update(main=dict(manifest(), update_archive='https://evil.invalid/main.tar.gz')),
        'update-manifest', 'manifest:main'),
    'main sends every install to the Testing archive': (
        lambda w: w.manifests.update(main=dict(manifest(), update_archive='https://github.com/PegaProx/project-pegaprox'
                                                                          '/archive/refs/heads/Testing.tar.gz')),
        'update-manifest', 'manifest:main'),
    'Testing links downloads elsewhere': (
        lambda w: w.manifests.update(Testing=dict(manifest(), download_url='https://github.com.evil.invalid/x')),
        'update-manifest', 'manifest:Testing'),
    'download_url climbing out of our repository with ..': (
        lambda w: w.manifests.update(main=dict(manifest(), download_url='https://github.com/PegaProx/project-pegaprox'
                                                                        '/../../mallory/project-pegaprox/releases')),
        'update-manifest', 'manifest:main'),
    'download_url climbing out with %2e%2e': (
        lambda w: w.manifests.update(main=dict(manifest(), download_url='https://github.com/PegaProx/project-pegaprox'
                                                                        '/%2e%2e/%2e%2e/mallory/x')),
        'update-manifest', 'manifest:main'),
    'a new URL field nobody knows': (
        lambda w: w.manifests.update(main=dict(manifest(), update_archive_v2='https://evil.invalid/a.tgz')),
        'update-manifest', 'manifest:main'),
    'a new URL field on a look-alike of the mirror host': (
        lambda w: w.manifests.update(main=dict(manifest(), sbom_url='https://updates.pegaprox.com.evil.invalid/s')),
        'update-manifest', 'manifest:main'),
    'update_files climbing out of the install': (
        lambda w: w.manifests.update(main=dict(manifest(), update_files=['web/index.html', '../../etc/cron.d/x'])),
        'update-manifest', 'manifest:main'),
    'the mirror points somewhere else': (
        lambda w: setattr(w, 'mirror', (200, dict(manifest(), update_mirror='https://updates.evil.invalid'))),
        'update-manifest', 'manifest:mirror'),
    'version.json gone from main': (lambda w: w.manifests.update(main=None), 'update-manifest', 'manifest:main'),
    'a bad manifest on main for six minutes between two runs': (
        lambda w: _transient_manifest(w), 'update-manifest', 'manifest:main'),
    # environments
    'signing environment open to every branch': (
        lambda w: _env(w, 'apt-signing', deployment_branch_policy=None), 'environments', 'environment:apt-signing'),
    'signing environment gained a branch': (
        lambda w: w.env_policies['apt-signing'].append(['Testing', 'branch']), 'environments', 'environment:apt-signing'),
    'signing environment lost its branch rule': (
        lambda w: _env(w, 'apt-signing', protection_rules=[]), 'environments', 'environment:apt-signing'),
    'Pages environment gone': (lambda w: w.envs.pop('github-pages'), 'environments', 'environment:github-pages'),
    'apt.pegaprox.com no longer on this site': (
        lambda w: w.pages.update(cname='apt.evil.invalid'), 'environments', 'pages'),
    # a check that falls over on what it is given
    'a check crashing on odd data': (
        lambda w: w.releases.insert(0, {'id': 3, 'tag_name': 'v1.4.1', 'author': user('MrMasterbay'),
                                        'assets': 5}), 'releases', 'crash:releases'),
}


def _transient_manifest(w):
    # a team token, all between two runs: Testing x with a foreign archive, main merges x,
    # Testing reverts it as y, main merges y. Only the heads in between ever carried it.
    evil = dict(manifest(), update_archive='https://evil.invalid/main.tar.gz')
    x = w.add(h(0x70), parents=[T2], login='mkellermann97', email=MK_MAIL, files=['version.json'])
    m1 = w.add(h(0x71), parents=[V141, x], tree=w.commits[x]['tree'], login='mkellermann97', email=MK_MAIL)
    y = w.add(h(0x72), parents=[x], login='mkellermann97', email=MK_MAIL, files=['version.json'])
    m2 = w.add(h(0x73), parents=[m1, y], tree=w.commits[y]['tree'], login='mkellermann97', email=MK_MAIL)
    w.manifests.update({x: evil, m1: evil})
    w.heads.update(Testing=y, main=m2)
    for aid, (ref, b, a, mins) in enumerate([('Testing', T2, x, 9), ('main', V141, m1, 8),
                                             ('Testing', x, y, 3), ('main', m1, m2, 2)]):
        w.push('push', f'refs/heads/{ref}', 'mkellermann97', b, a, minutes_ago=mins, aid=500 + aid)


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_each_alarm_is_raised_and_comes_from_its_check(name):
    mutate, check, key = SCENARIOS[name]
    w = healthy()
    mutate(w)
    hits = [(c, k) for c, k in alarm_keys(run(w)) if k.startswith(key)]
    assert hits and all(c == check for c, _ in hits), alarm_keys(run(w))
    # counterproof: without that one check the same state raises no such alarm
    assert not [k for _, k in alarm_keys(run(w, skip=check)) if k.startswith(key)]


def test_a_crashing_check_does_not_hide_the_others():
    w = healthy()
    SCENARIOS['a check crashing on odd data'][0](w)
    w.repo['visibility'] = 'private'
    keys = [k for _, k in alarm_keys(run(w))]
    assert any(k.startswith('crash:releases:') for k in keys) and any(k.startswith('settings:visibility') for k in keys)


# ---------------------------------------------------------------------------------------
# the attacks of the review round, end to end

def test_a_repo_token_replacing_the_watchdog_on_main_is_caught_twice():
    # no workflow scope needed for .github/scripts and .github/watchdog: MK's token changes
    # both files on Testing (author MK) and merges that into main the way a release does
    w = healthy()
    x = _testing_commit(w, 0xbad, [wd.SCRIPT_PATH, wd.BASELINE_PATH])
    w.files[('Testing', wd.SCRIPT_PATH)] = b'# quiet\n'
    m = w.add(h(0xbae), parents=[V141, x], tree=w.commits[x]['tree'], login='mkellermann97', email=MK_MAIL)
    w.heads['main'] = m
    w.files[('main', wd.SCRIPT_PATH)] = b'# quiet\n'
    w.push('push', 'refs/heads/main', 'mkellermann97', V141, m, minutes_ago=5)
    keys = [k for _, k in alarm_keys(run(w))]
    assert any(k.startswith('pin:Testing:') for k in keys) and any(k.startswith('pin:main:') for k in keys)
    assert any(k.startswith('own-files:') for k in keys)


def test_the_gap_after_a_late_or_failed_run_is_looked_at():
    # GitHub started no scheduled run for three hours; a force push happened two hours ago
    w = healthy()
    w.last_success = ts(180)
    w.push('push', 'refs/heads/Testing', 'mallory', T1, T2, minutes_ago=120)
    assert ('pushes', 'push:9001') in alarm_keys(run(w))
    assert any('no successful scheduled run since' in t for t in notes(run(w), 'coverage'))
    # counterproof: with the standard window it is out of sight
    assert alarm_keys(run(w, skip='coverage')) == []


def test_a_gap_longer_than_the_cap_fails_one_run_not_all_of_them():
    # the watchdog was off for five days: the first run after it is red
    w = healthy()
    w.last_success = ts(5 * 24 * 60)
    w.last_completed = ts(5 * 24 * 60)
    rep = run(w)
    assert any('before that is a gap' in t and 'no scheduled run' in t for t in not_checked(rep, 'coverage'))
    assert rep.blind
    # the run after it finds that red run and only notes the gap, or no run could ever be
    # green again
    w.last_completed = ts(10)
    rep = run(w)
    assert any('reported it already' in t for t in not_checked(rep, 'coverage'))
    assert not rep.blind and alarm_keys(rep) == []


def test_no_run_history_uses_the_standard_window():
    w = healthy()
    w.watchdog_known = False
    rep = run(w)
    assert alarm_keys(rep) == [] and not_checked(rep) == []
    assert any('standard window' in t for t in notes(rep, 'coverage'))


def test_flooding_other_branches_cannot_push_main_and_testing_out_of_view():
    w = healthy()
    w.push('push', 'refs/heads/Testing', 'compromised-app[bot]', T1, T2, minutes_ago=30, aid=1)
    flood = [{'id': 20000 + i, 'activity_type': 'push', 'ref': 'refs/heads/flood', 'actor': user('MrMasterbay'),
              'before': h(5), 'after': h(6), 'timestamp': ts(1)} for i in range(600)]
    w.activity = flood + w.activity
    assert ('pushes', 'push:1') in alarm_keys(run(w))


def test_more_activity_than_the_pages_read_is_not_checked_and_fails_the_run(tmp_path):
    w = healthy()
    entry = dict(w.activity[0], timestamp=ts(1))
    w.activity_pages = {'refs/heads/Testing': [[dict(entry, id=i)] for i in range(7)]}
    rep = run(w)
    assert any('oldest not looked at' in t for t in not_checked(rep, 'pushes'))
    code, _ = main(w, ['check'], {'GITHUB_TOKEN': 'tok'}, tmp_path)
    assert code == 2 and (tmp_path / 'out').read_text() == 'alarm=false\n'


def test_a_cut_event_feed_is_reported_without_failing_the_run():
    w = healthy()
    w.event('MemberEvent', 'MrMasterbay', {'action': 'added', 'member': user('mallory')}, minutes_ago=120)
    # the feed stops at 300 entries: everything older than these 300 is not served
    w.events = [{'id': str(80000 + i), 'type': 'PushEvent', 'actor': user('MrMasterbay'),
                 'payload': {'ref': 'refs/heads/flood'}, 'created_at': ts(1)} for i in range(300)]
    # one event delivered late, with an old time stamp, somewhere in the middle (seen live)
    w.events[150]['created_at'] = ts(2000)
    rep = run(w)
    hits = [f for f in rep.findings if f.check == 'events' and f.level == wd.NOT_CHECKED]
    assert hits and all(f.soft for f in hits) and 'the event feed ends at' in hits[0].text
    assert not rep.blind


def test_rate_limited_reads_fail_the_run_red_without_a_freeze(tmp_path):
    w = healthy()
    _new_main_head(w)

    def limited(method, url, headers, body):
        w.calls.append((method, url, dict(headers)))
        if url.startswith(wd.API + '/'):
            return 403, {'x-ratelimit-remaining': '0'}, b'{"message": "API rate limit exceeded"}', ''
        return 200, {}, json.dumps(manifest()).encode(), ''
    out = io.StringIO()
    env = {'GITHUB_TOKEN': 'tok', 'GITHUB_OUTPUT': str(tmp_path / 'out'), 'GITHUB_STEP_SUMMARY': str(tmp_path / 's')}
    code = wd.main(['check'], env=env, transport=limited, now=NOW, stdout=out)
    assert code == 2
    assert (tmp_path / 'out').read_text() == 'alarm=false\n'
    assert 'rate limit used up' in out.getvalue() and 'rate limit left 0' in out.getvalue()


def test_an_ack_covers_one_problem_not_the_object():
    # a deliberate new URL field on main is acknowledged ...
    w = healthy()
    w.manifests['main'] = dict(manifest(), sbom_url='https://cdn.example/sbom.json')
    (_, first), = [x for x in alarm_keys(run(w)) if x[1].startswith('manifest:main')]
    # ... and weeks later a foreign archive under the same object still alarms
    w.manifests['main'] = dict(manifest(), sbom_url='https://cdn.example/sbom.json',
                               update_archive='https://evil.invalid/main.tar.gz')
    rep = run(w, env={'WATCHDOG_ACK': first})
    assert [k for _, k in alarm_keys(rep) if k.startswith('manifest:main')]
    # the same for a ruleset: acked after an edit, then switched off
    w = healthy()
    _ruleset(w, 25587029, updated_at='2026-10-31T01:00:00.000Z')
    (_, edited), = alarm_keys(run(w))
    _ruleset(w, 25587029, enforcement='disabled')
    assert [k for _, k in alarm_keys(run(w, env={'WATCHDOG_ACK': edited})) if k.startswith('ruleset:25587029')]


def test_keys_can_be_pasted_back_from_the_summary(tmp_path):
    w = healthy()
    w.repo['has_pages'] = False
    w.wf_files['main'].add('publish_nightly.yml')
    main(w, ['check'], {'GITHUB_TOKEN': 'tok'}, tmp_path)
    shown = [line[3:-1] for line in (tmp_path / 'summary').read_text().splitlines() if line.startswith('- `')]
    assert len(shown) == 2 and all('\\' not in k for k in shown)
    assert alarm_keys(run(w, env={'WATCHDOG_ACK': ' '.join(shown)})) == []


def test_key_parts_are_plain_characters():
    k = wd.key('workflow-unknown', 'main', 'a`b|c d\n::e\u2028.yml')
    assert re.fullmatch(r'[A-Za-z0-9._/@+=:-]+', k), k


# ---------------------------------------------------------------------------------------
# what cannot be read is never a pass

@pytest.mark.parametrize('path, check', [
    (f'/repos/{REPO}/rulesets', 'rulesets'),
    (f'/repos/{REPO}/activity', 'pushes'),
    (f'/repos/{REPO}/events', 'events'),
    (f'/repos/{REPO}/releases', 'releases'),
    (f'/repos/{REPO}/git/matching-refs/tags/v', 'tags'),
    (f'/repos/{REPO}/environments', 'environments'),
    (f'/repos/{REPO}/actions/runs', 'workflow-runs'),
    (f'/repos/{REPO}', 'settings'),
    (f'/repos/{REPO}/actions/workflows/watchdog.yml/runs', 'coverage'),
    (f'/repos/{REPO}/contents/.github/workflows/watchdog.yml', 'pins'),
])
def test_a_forbidden_read_is_reported_as_not_checked(path, check):
    w = healthy()
    w.override[path] = (403, {'message': 'Resource not accessible by integration'})
    rep = run(w)
    assert any('403' in t for t in not_checked(rep, check))
    assert rep.status(check) in ('not checked', 'partly checked')


def test_collaborators_the_token_may_not_list_are_soft():
    w = healthy()
    w.override[f'/repos/{REPO}/collaborators'] = (403, {'message': 'Must have push access'})
    rep = run(w)
    hits = [f for f in rep.findings if f.check == 'collaborators' and f.level == wd.NOT_CHECKED]
    assert hits and all(f.soft for f in hits) and not rep.blind


def test_hidden_bypass_actors_are_not_checked_not_passed():
    # what a non-admin token gets: the rules, but no bypass_actors key at all
    w = healthy()
    w.show_bypass = False
    rep = run(w)
    assert alarm_keys(rep) == []
    assert any('bypass actors' in t and 'Administration' in t for t in not_checked(rep, 'rulesets'))
    assert rep.status('rulesets') == 'partly checked'
    assert not rep.blind


def test_pages_settings_unreadable_is_not_checked():
    w = healthy()
    w.pages = None
    rep = run(w)
    assert any('Pages settings' in t for t in not_checked(rep, 'environments'))
    assert alarm_keys(rep) == []


def test_the_mirror_down_is_not_checked():
    w = healthy()
    w.mirror = (503, None)
    rep = run(w)
    assert any('mirror' in t for t in not_checked(rep, 'update-manifest'))
    assert alarm_keys(rep) == []


def test_watchdog_not_deployed_yet_is_a_note():
    w = healthy()
    w.files = {}
    rep = run(w)
    assert alarm_keys(rep) == [] and not_checked(rep) == []
    assert len([t for t in notes(rep, 'pins') if 'not on' in t]) == 2


def test_a_next_link_off_the_api_host_is_not_followed():
    calls = []

    def transport(method, url, headers, body):
        calls.append(url)
        return 200, {'link': '<https://evil.invalid/steal?x=1>; rel="next"'}, b'[{"a": 1}]', ''
    items, fail = wd.Api('tok', transport).pages('/repos/x/y/activity', max_pages=5)
    assert fail is None and items == [{'a': 1}] and len(calls) == 1


def test_an_acknowledged_alarm_becomes_a_note():
    w = healthy()
    bad = _new_main_head(w)
    rep = run(w, env={'WATCHDOG_ACK': f'something-else main-head:{bad}'})
    assert alarm_keys(rep) == []
    assert any(f.key == f'main-head:{bad}' and f.level == wd.NOTE for f in rep.findings)


# ---------------------------------------------------------------------------------------
# freeze, unfreeze, report-only

ACT_ENV = {'PEGAPROX_WATCHDOG_ACT': '1', 'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': REPO,
           'GITHUB_EVENT_NAME': 'schedule', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_TOKEN': 'tok'}


def main(w, argv, env, tmp_path=None):
    out = io.StringIO()
    env = dict(env)
    if tmp_path is not None:
        env['GITHUB_OUTPUT'] = str(tmp_path / 'out')
        env['GITHUB_STEP_SUMMARY'] = str(tmp_path / 'summary')
    code = wd.main(argv, env=env, transport=w, now=NOW, stdout=out)
    return code, out.getvalue()


def _busy(w):
    w.runs += [mkrun(900 + i, wf, 'release', 'v1.4.1', V141, status=st)
               for i, (wf, st) in enumerate([('docker.yml', 'queued'), ('apt-repo.yml', 'waiting'),
                                             ('test.yml', 'queued')])]


def test_check_writes_nothing_and_says_what_a_freeze_would_do(tmp_path):
    w = healthy()
    _new_main_head(w)
    code, out = main(w, ['check'], {'GITHUB_TOKEN': 'tok'}, tmp_path)
    assert code == 1
    assert w.writes == []
    assert 'would freeze: disable ' + ', '.join(BASELINE['workflows']['publishers']) in out
    assert (tmp_path / 'out').read_text() == 'alarm=true\n'
    assert '| branches | ALARM |' in (tmp_path / 'summary').read_text()


def test_check_without_alarm_exits_clean(tmp_path):
    code, out = main(healthy(), ['check'], {'GITHUB_TOKEN': 'tok'}, tmp_path)
    assert code == 0 and 'would freeze' not in out
    assert (tmp_path / 'out').read_text() == 'alarm=false\n'


def test_a_lone_surrogate_cannot_stop_the_freeze(tmp_path):
    # "1.4.2\ud800" is plain ASCII in the file; json.loads makes a lone surrogate of it,
    # which a strict UTF-8 stdout or summary file cannot take
    w = healthy()
    _new_main_head(w)
    lone = json.loads('"1.4.2\\ud800"')
    w.manifests['Testing'] = dict(manifest(), version=lone, update_archive='https://evil.invalid/a' + lone)
    buf = io.BytesIO()
    strict = io.TextIOWrapper(buf, encoding='utf-8', errors='strict', write_through=True)
    env = {'GITHUB_TOKEN': 'tok', 'GITHUB_ACTIONS': 'true', 'GITHUB_OUTPUT': str(tmp_path / 'out'),
           'GITHUB_STEP_SUMMARY': str(tmp_path / 'summary')}
    code = wd.main(['check'], env=env, transport=w, now=NOW, stdout=strict)
    assert code == 1
    assert (tmp_path / 'out').read_text() == 'alarm=true\n'
    assert '\\ud800' in buf.getvalue().decode('utf-8') and (tmp_path / 'summary').exists()


def test_a_report_that_cannot_be_printed_still_fails_the_run(tmp_path):
    w = healthy()
    _new_main_head(w)

    class Broken(io.StringIO):
        def write(self, s):
            raise OSError('stdout gone')
    env = {'GITHUB_TOKEN': 'tok', 'GITHUB_OUTPUT': str(tmp_path / 'out')}
    code = wd.main(['check'], env=env, transport=w, now=NOW, stdout=Broken())
    assert code == 1 and (tmp_path / 'out').read_text() == 'alarm=true\n'


def test_the_api_refuses_writes_unless_acting():
    api = wd.Api('tok', healthy())
    with pytest.raises(RuntimeError):
        api.request('PUT', f'/repos/{REPO}/actions/workflows/docker.yml/disable')


def test_act_on_an_alarm_freezes_the_publishers_and_cancels_their_runs():
    w = healthy()
    _busy(w)
    code, out = main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true', WATCHDOG_NOTIFY_URL='https://ntfy.example/x'))
    assert code == 0, out
    puts = sorted(p for m, p in w.writes if m == 'PUT')
    assert puts == sorted(f'/repos/{REPO}/actions/workflows/{wf}/disable' for wf in PUBLISHERS)
    cancels = sorted(p for m, p in w.writes if m == 'POST')
    # the queued docker.yml run, the in_progress docker-testing.yml run, the waiting apt-repo.yml
    # run; test.yml is no publisher and is left alone
    assert cancels == sorted(f'/repos/{REPO}/actions/runs/{i}/cancel' for i in (501, 900, 901))
    # all disables come before the first cancel
    kinds = [m for m, _ in w.writes]
    assert kinds == ['PUT'] * len(PUBLISHERS) + ['POST'] * 3
    assert len(w.notified) == 1 and b'frozen' in w.notified[0][1]
    assert 'test.yml' not in ''.join(p for _, p in w.writes)
    assert 'watchdog.yml' not in ''.join(p for _, p in w.writes)


def test_a_freeze_that_is_already_on_sends_no_second_notice():
    w = healthy()
    for wf in PUBLISHERS:
        w.wf_state[wf] = 'disabled_manually'
    main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true', WATCHDOG_NOTIFY_URL='https://ntfy.example/x'))
    assert w.notified == []


def test_no_notify_url_no_request():
    w = healthy()
    main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true'))
    assert w.notified == []
    w2 = healthy()
    main(w2, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true', WATCHDOG_NOTIFY_URL='http://plain.example/x'))
    assert w2.notified == []


def test_act_without_an_alarm_does_nothing():
    w = healthy()
    code, out = main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='false'))
    assert code == 0 and w.writes == [] and 'nothing to do' in out


def test_a_manual_freeze_needs_no_alarm():
    w = healthy()
    code, _ = main(w, ['act'], dict(ACT_ENV, GITHUB_EVENT_NAME='workflow_dispatch', WATCHDOG_ACTION='freeze'))
    assert code == 0
    assert sorted(p for m, p in w.writes if m == 'PUT') == sorted(
        f'/repos/{REPO}/actions/workflows/{wf}/disable' for wf in PUBLISHERS)


@pytest.mark.parametrize('change', [
    {'PEGAPROX_WATCHDOG_ACT': ''},
    {'PEGAPROX_WATCHDOG_ACT': 'true'},
    {'GITHUB_ACTIONS': ''},
    {'GITHUB_EVENT_NAME': 'push'},
    {'GITHUB_EVENT_NAME': 'pull_request_target'},
    {'GITHUB_REF': 'refs/heads/Testing'},
    {'GITHUB_REF': 'refs/tags/v1.4.1'},
    {'GITHUB_REPOSITORY': 'mallory/project-pegaprox'},
])
def test_freeze_is_report_only_anywhere_else(change):
    w = healthy()
    _busy(w)
    code, out = main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true', **change))
    assert code == 0
    assert w.writes == []
    assert 'report-only' in out
    assert 'would disable docker.yml' in out and 'would cancel run 900 of docker.yml (queued)' in out


def test_a_local_freeze_is_report_only():
    w = healthy()
    code, out = main(w, ['freeze'], {'GITHUB_TOKEN': 'tok'})
    assert code == 0 and w.writes == [] and 'would disable' in out


def test_unfreeze_needs_the_word():
    w = healthy()
    code, out = main(w, ['act'], dict(ACT_ENV, GITHUB_EVENT_NAME='workflow_dispatch', WATCHDOG_ACTION='unfreeze',
                                      WATCHDOG_CONFIRM='yes'))
    assert code == 1 and w.writes == []
    code, out = main(w, ['act'], dict(ACT_ENV, GITHUB_EVENT_NAME='workflow_dispatch', WATCHDOG_ACTION='unfreeze',
                                      WATCHDOG_CONFIRM='UNFREEZE', WATCHDOG_ALARM='true'))
    assert code == 0
    assert sorted(p for _, p in w.writes) == sorted(f'/repos/{REPO}/actions/workflows/{wf}/enable' for wf in PUBLISHERS)
    assert 'freezes again' in out


def test_a_cancel_refused_with_409_is_forced():
    w = healthy()
    w.write_status[('POST', f'/repos/{REPO}/actions/runs/501/cancel')] = 409
    w.write_status[('POST', f'/repos/{REPO}/actions/runs/501/force-cancel')] = 202
    code, _ = main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true'))
    assert code == 0
    assert ('POST', f'/repos/{REPO}/actions/runs/501/force-cancel') in w.writes


def test_a_failed_disable_fails_the_run_loudly():
    w = healthy()
    w.write_status[('PUT', f'/repos/{REPO}/actions/workflows/docker.yml/disable')] = 403
    code, out = main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true'))
    assert code == 1
    assert '::error title=release watchdog::disable docker.yml: HTTP 403' in out


def test_the_api_headers_carry_the_token_for_the_api_host_only():
    api = wd.Api('tok', healthy())
    assert api._headers(wd.API + '/repos/x/y')['Authorization'] == 'Bearer tok'
    for url in ('https://evil.invalid/x', 'https://api.github.com.evil.invalid/x', 'https://updates.pegaprox.com/x'):
        assert 'Authorization' not in api._headers(url), url


def test_the_token_goes_to_the_api_only():
    w = healthy()
    main(w, ['check'], {'GITHUB_TOKEN': 'tok'})
    main(w, ['act'], dict(ACT_ENV, WATCHDOG_ALARM='true', WATCHDOG_NOTIFY_URL='https://ntfy.example/x'))
    for _, url, headers in w.calls:
        assert ('Authorization' in headers) == url.startswith(wd.API + '/'), url


# ---------------------------------------------------------------------------------------
# data shaped as commands stays data

EVIL = 'x\n::set-output name=alarm::false\r\n::add-mask::tok `id` $(reboot) <img src=x onerror=alert(1)> | **'


def test_shaped_names_and_payloads_are_inert(tmp_path, monkeypatch):
    import os
    import subprocess

    def boom(*a, **k):
        raise AssertionError('the watchdog started a process')
    monkeypatch.setattr(subprocess, 'Popen', boom)
    monkeypatch.setattr(os, 'system', boom)
    monkeypatch.setattr(os, 'popen', boom)
    w = healthy()
    w.push('push', 'refs/heads/Testing', 'mallory' + EVIL, T1, T2)
    _new_tag(w, 'v1.4.2' + EVIL, T2)
    w.event('DeleteEvent', 'mallory', {'ref': 'v1' + EVIL, 'ref_type': 'tag'})
    w.releases.insert(0, {'id': 4, 'tag_name': EVIL, 'draft': False, 'author': user('mallory' + EVIL), 'assets': []})
    w.manifests['main'] = dict(manifest(), update_archive='https://evil.invalid/' + EVIL)
    w.wf_files['Testing'].add('a' + EVIL + '.yml')
    w.runs.append(dict(mkrun(990, 'b' + EVIL + '.yml', 'push', EVIL, T2), actor=user(EVIL)))
    code, out = main(w, ['check'], dict(ACT_ENV, GITHUB_TOKEN='tok'), tmp_path)
    assert code == 1
    for line in out.splitlines():
        if line.startswith('::'):
            assert line.startswith(('::error title=release watchdog::', '::warning title=release watchdog::')), line
    assert '\r' not in out
    assert (tmp_path / 'out').read_text() == 'alarm=true\n'
    summary = (tmp_path / 'summary').read_text()
    assert '<img' not in summary and '&lt;img' in summary
    rows = [r for r in summary.splitlines() if r.startswith('| ')]
    # every table row keeps its three cells: a | from the data is escaped
    assert all(len(re.findall(r'(?<!\\)\|', r)) == 4 for r in rows), rows
    keys = [line[3:-1] for line in summary.splitlines() if line.startswith('- `')]
    assert keys and all(re.fullmatch(r'[A-Za-z0-9._/@+=:-]+', k) for k in keys), keys
    assert not any(k.startswith('crash:') for _, k in alarm_keys(run(w)))


def test_the_script_never_reaches_for_a_shell():
    src = (ROOT / '.github' / 'scripts' / 'watchdog.py').read_text(encoding='utf-8')
    for bad in ('subprocess', 'os.system', 'os.popen', 'shell=True', 'eval(', 'exec(', 'pickle', '__import__'):
        assert bad not in src, bad


def test_clean_keeps_one_line():
    assert wd.clean('a\nb\rc d\x1b[31m') == 'a b c d [31m'
    assert '\n' not in wd.annotation('error', 'x\n::set-env name=A::1')
    assert wd.annotation('error', '100%').endswith('100%25')
    assert wd.clean(json.loads('"a\\udfffb"')) == 'a\\udfffb'


def test_url_under_is_a_parsed_path_check():
    ok = ['https://github.com/PegaProx/project-pegaprox/']
    assert wd.url_under('https://github.com/PegaProx/project-pegaprox/releases/latest', ok)
    for bad in ('https://github.com/PegaProx/project-pegaprox/../../mallory/x',
                'https://github.com/PegaProx/project-pegaprox/./../mallory',
                'https://github.com/PegaProx/project-pegaprox/%2e%2e/mallory',
                'https://github.com/PegaProx/project-pegaprox-evil/x',
                'https://github.com@evil.invalid/PegaProx/project-pegaprox/x',
                'https://github.com:8443/PegaProx/project-pegaprox/x',
                'http://github.com/PegaProx/project-pegaprox/x',
                'https://github.com/PegaProx/project-pegaprox/x\\..\\..\\y',
                'https://github.com/PegaProx/project-pegaprox/x?next=https://evil.invalid'):
        assert not wd.url_under(bad, ok), bad
