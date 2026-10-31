#!/usr/bin/env python3
"""Release watchdog for PegaProx/project-pegaprox.

NS Oct 2026 - a leaked token, a hijacked integration or a bad merge should not get a release
out unnoticed. Every ten minutes .github/workflows/watchdog.yml runs this. It reads what the
GitHub API says about the repository and holds it against .github/watchdog/baseline.json:

  coverage         looks back to the last successful scheduled run, so a run GitHub started
                   late or skipped leaves no gap (three days at most)
  settings         default branch, visibility, archived, Pages
  collaborators    who has access, with which role
  branches         main and Testing exist, main serves a tree that came from Testing and no
                   older version than the newest release tag
  pins             watchdog.py and baseline.json on main and Testing are the files whose
                   sha256 watchdog.yml pins, so changing them needs the workflow scope
  pushes           no force push or deletion on main/Testing, nobody outside the team, main
                   moved only by a release manager and never to a lower version
  workflow-files   workflows, these scripts and the APT tooling change only by the team, the
                   watchdog's own files only by its maintainers
  tags             release tags never move or vanish; a new one sits on main and matches
                   version.json there
  releases         made by a release manager for a good tag; assets uploaded by Actions, and
                   one changed in the window only while a vetted publisher run was going
  events           the public event feed: collaborators, visibility, tag/branch deletion
  rulesets         the rulesets are there, active and unchanged
  workflow-runs    every run: a workflow the baseline knows, not changed on a side branch;
                   a publisher started by the team, here, on a commit of main or Testing
  update-manifest  version.json on main, Testing, the mirror and at every push in the window
                   sends the updater only to our own archive
  environments     the signing and Pages environments deploy only from main and v* tags

Nothing is stored between runs. Whatever cannot be read is reported as "not checked", never
as passed. Exit 1 on an alarm (the act job freezes), exit 2 when something that matters was
not checked (red, no freeze), 0 otherwise.

Only `act` in the workflow's act job writes anything: it disables or enables the publishing
workflows and cancels their runs, and only on main, from the schedule or a manual run, with
PEGAPROX_WATCHDOG_ACT=1. Anywhere else it prints what it would do.

    watchdog.py check                 run the checks
    watchdog.py act                   freeze or unfreeze as the workflow says (env)
    watchdog.py freeze | unfreeze     the same by hand, report-only outside the workflow
    watchdog.py snapshot              print rulesets, tags and collaborators the way the
                                      baseline has them

Data from the API (branch names, tag names, commit messages, event payloads) is only ever
compared and printed, never handed to a shell. stdlib only, CI has no extra packages.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = 'https://api.github.com'
DEFAULT_BASELINE = Path(__file__).resolve().parent.parent / 'watchdog' / 'baseline.json'
SHA = re.compile(r'^[0-9a-f]{40}$')
ZERO_SHA = '0' * 40
WORKFLOW_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$')
RUN_STATES = ('queued', 'in_progress', 'waiting', 'requested', 'pending')
MAX_COMMITS = 40     # commits of one push looked at one by one
MAX_NEW_TAGS = 10
COVER_MARGIN = timedelta(minutes=10)

# the watchdog's own files. watchdog.yml pins the sha256 of the other two, and changing
# watchdog.yml needs the workflow scope, which a plain repo token does not have
WATCHDOG_YML = '.github/workflows/watchdog.yml'
SCRIPT_PATH = '.github/scripts/watchdog.py'
BASELINE_PATH = '.github/watchdog/baseline.json'
PINNED = (SCRIPT_PATH, BASELINE_PATH)
OWN_FILES = (WATCHDOG_YML,) + PINNED
PIN_LINE = re.compile(r'^\s*([0-9a-f]{64})\s+(\.github/[A-Za-z0-9._/-]+)\s*$', re.M)

ALARM, NOTE, NOT_CHECKED = 'alarm', 'note', 'not checked'


# ---------------------------------------------------------------------------------------
# output hygiene

_CTRL = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029]')
_KEY_BAD = re.compile(r'[^A-Za-z0-9._/@+=-]')


def clean(s, limit=400):
    """One line of plain text. Whatever came from the API can carry newlines, and a line
    that starts with :: is a workflow command to the runner. A lone surrogate (a \\ud800
    escape in a JSON file) cannot be written as UTF-8 at all, so it becomes its escape."""
    s = str(s).encode('utf-8', 'backslashreplace').decode('utf-8')
    s = _CTRL.sub(' ', s)
    return s if len(s) <= limit else s[:limit - 3] + '...'


def v(s):
    """A value from the API inside a message: short and quoted."""
    return "'" + clean(s, 80) + "'"


def md(s):
    s = clean(s)
    for a, b in (('\\', '\\\\'), ('&', '&amp;'), ('<', '&lt;'), ('>', '&gt;'), ('|', '\\|'),
                 ('`', "'"), ('*', '\\*'), ('_', '\\_'), ('[', '\\['), (']', '\\]')):
        s = s.replace(a, b)
    return s


def key(*parts):
    """An alarm key in plain characters, so it can be copied out of the summary into
    WATCHDOG_ACK exactly as it is shown."""
    return ':'.join(_KEY_BAD.sub('-', clean(p, 60)) or '-' for p in parts)


def fp(*parts):
    """A short hash of what exactly is wrong. An acknowledged key covers that one finding;
    another problem with the same object gets another key."""
    raw = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode('utf-8', 'backslashreplace')).hexdigest()[:10]


def annotation(level, text):
    msg = clean(text).replace('%', '%25')
    return f'::{level} title=release watchdog::{msg}'


def login(obj):
    return str((obj or {}).get('login') or '') if isinstance(obj, dict) else ''


def tree_of(commit_json):
    c = commit_json.get('commit') if isinstance(commit_json, dict) else None
    t = (c or {}).get('tree') if isinstance(c, dict) else None
    return t.get('sha') if isinstance(t, dict) else None


def parse_ts(s):
    if not isinstance(s, str) or not s:
        return None
    try:
        t = datetime.fromisoformat(s.replace('Z', '+00:00'))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def hhmm(t):
    return t.strftime('%Y-%m-%d %H:%M UTC')


def version_tuple(s):
    m = re.fullmatch(r'v?(\d{1,6}(?:\.\d{1,6}){0,4})', str(s or '').strip())
    return tuple(int(x) for x in m.group(1).split('.')) if m else None


def vs(t):
    return '.'.join(map(str, t))


# ---------------------------------------------------------------------------------------
# GitHub API, GET by default

class Resp:
    def __init__(self, status, data=None, headers=None, error=''):
        self.status = status
        self.data = data
        self.headers = headers or {}
        self.error = error

    @property
    def ok(self):
        return 200 <= self.status < 300

    def why(self):
        if self.status == 0:
            return f'no answer ({clean(self.error, 120)})'
        if self.status in (403, 429) and self.headers.get('x-ratelimit-remaining') == '0':
            return f'HTTP {self.status}, rate limit used up'
        msg = self.data.get('message') if isinstance(self.data, dict) else ''
        return f'HTTP {self.status}' + (f' ({clean(msg, 120)})' if msg else '')


def urllib_transport(method, url, headers, body):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, {k.lower(): val for k, val in r.headers.items()}, r.read(8 << 20), ''
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): val for k, val in (e.headers or {}).items()}
        return e.code, hdrs, e.read(1 << 16), ''
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {}, b'', str(e)


_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')


def next_link(header):
    for url, rel in _LINK.findall(header or ''):
        if rel == 'next':
            return url
    return None


class Api:
    def __init__(self, token='', transport=None, base=API):
        self.token = token or ''
        self.transport = transport or urllib_transport
        self.base = base
        self.writes_allowed = False
        self.calls = 0
        self.truncated = False
        self.ratelimit = None

    def _headers(self, url):
        h = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
             'User-Agent': 'pegaprox-release-watchdog'}
        # the token goes to the API host and nowhere else
        if self.token and url.startswith(self.base + '/'):
            h['Authorization'] = f'Bearer {self.token}'
        return h

    def request(self, method, path, params=None, body=None):
        if method != 'GET' and not self.writes_allowed:
            raise RuntimeError(f'refused {method} {path}: this run is report-only')
        url = path if path.startswith(self.base + '/') else self.base + path
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
        data = None if body is None else json.dumps(body).encode()
        self.calls += 1
        status, headers, raw, err = self.transport(method, url, self._headers(url), data)
        if (headers or {}).get('x-ratelimit-remaining') is not None:
            self.ratelimit = str(headers['x-ratelimit-remaining'])
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
        return Resp(status, parsed, headers, err)

    def get(self, path, params=None):
        return self.request('GET', path, params)

    def pages(self, path, params=None, max_pages=3, key=None, more=None):
        """A list over its Link pages: (items, None) or (items so far, the failed Resp).
        `more(batch)` says whether the next page is still wanted. `truncated` is set when
        max_pages ran out with pages still to come."""
        items, url, p = [], path, dict(params or {})
        self.truncated = False
        for _ in range(max_pages):
            r = self.get(url, p)
            if not r.ok:
                return items, r
            batch = r.data.get(key) if (key and isinstance(r.data, dict)) else r.data
            if not isinstance(batch, list):
                return items, Resp(0, error=f'unexpected answer from {path}')
            items.extend(batch)
            if more is not None and not more(batch):
                break
            url, p = next_link(r.headers.get('link')), None
            if not url or not url.startswith(self.base + '/'):
                break
        else:
            self.truncated = True
        return items, None

    def fetch_public(self, url):
        """A plain GET outside the API, without the token (the update mirror)."""
        self.calls += 1
        status, headers, raw, err = self.transport(
            'GET', url, {'User-Agent': 'pegaprox-release-watchdog', 'Accept': 'application/json'}, None)
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return Resp(status, parsed, headers, err)


# ---------------------------------------------------------------------------------------
# findings

class Finding:
    __slots__ = ('check', 'level', 'key', 'text', 'soft')

    def __init__(self, check, level, key, text, soft=False):
        self.check, self.level, self.key, self.text, self.soft = check, level, key, text, soft

    def as_dict(self):
        return {'check': self.check, 'level': self.level, 'key': self.key, 'text': clean(self.text),
                'soft': self.soft}


class Report:
    def __init__(self, acks=()):
        self.acks = set(acks)
        self.findings = []
        self.passed = {}
        self.checks = []
        self.current = ''

    def begin(self, name):
        self.current = name
        self.checks.append(name)

    def alarm(self, key_, text):
        if any(f.key == key_ for f in self.findings):
            return
        if key_ in self.acks:
            self.findings.append(Finding(self.current, NOTE, key_, f'{text} (acknowledged in WATCHDOG_ACK)'))
        else:
            self.findings.append(Finding(self.current, ALARM, key_, text))

    def note(self, text, key_=''):
        self.findings.append(Finding(self.current, NOTE, key_, text))

    def not_checked(self, text, soft=False):
        """soft: expected for good or caused from outside at will (the event feed is cut by
        anyone who comments a lot), so it does not turn the run red."""
        self.findings.append(Finding(self.current, NOT_CHECKED, '', text, soft))

    def ok(self, text):
        self.passed.setdefault(self.current, []).append(text)

    @property
    def alarms(self):
        return [f for f in self.findings if f.level == ALARM]

    @property
    def blind(self):
        return [f for f in self.findings if f.level == NOT_CHECKED and not f.soft]

    def of(self, check, level=None):
        return [f for f in self.findings if f.check == check and (level is None or f.level == level)]

    def status(self, check):
        if self.of(check, ALARM):
            return 'ALARM'
        if self.of(check, NOT_CHECKED):
            return 'not checked' if not self.passed.get(check) else 'partly checked'
        return 'ok'


def parse_acks(text):
    return {a for a in re.split(r'[\s,]+', text or '') if a}


# ---------------------------------------------------------------------------------------
# the run

class Ctx:
    def __init__(self, api, baseline, now=None, window_min=40, events_window_min=360, env=None,
                 max_lookback_min=4320):
        self.api = api
        self.b = baseline
        self.repo = baseline['repo']
        self.now = now or datetime.now(timezone.utc)
        self.window = timedelta(minutes=window_min)
        self.events_window = timedelta(minutes=events_window_min)
        self.max_lookback = timedelta(minutes=max(max_lookback_min, window_min, events_window_min))
        self.since = self.now - self.window
        self.events_since = self.now - self.events_window
        self.env = env if env is not None else {}
        self.report = Report(parse_acks(self.env.get('WATCHDOG_ACK', '')))
        self.team = set(baseline['allowed_actors'])
        self.release_managers = set(baseline['release_managers'])
        self.maintainers = set(baseline['watchdog_maintainers'])
        self.main = baseline['default_branch']
        self.watched = {'refs/heads/' + b for b in baseline['branches']}
        self.repo_info = None
        self.heads = {}
        self._fresh = None
        self.tags_live = None
        self.tags_good = set()
        self.tags_unsure = set()
        self.trusted = {}           # branch -> its baseline, when it matches its own pin
        self._commits = {}
        self._compares = {}
        self._explained = {}
        self._manifests = {}
        self._activity = None
        self.activity_cut = False
        self._testing = None
        self._wf_blobs = {}

    # report shortcuts
    def alarm(self, key_, text):
        self.report.alarm(key_, text)

    def note(self, text, key_=''):
        self.report.note(text, key_)

    def not_checked(self, text, soft=False):
        self.report.not_checked(text, soft)

    def ok(self, text):
        self.report.ok(text)

    def rp(self, *parts):
        return '/repos/' + self.repo + ''.join('/' + urllib.parse.quote(str(p), safe='') for p in parts)

    def commit(self, sha):
        if sha not in self._commits:
            self._commits[sha] = self.api.get(self.rp('commits', sha))
        return self._commits[sha]

    def compare(self, base, head):
        k = (base, head)
        if k not in self._compares:
            # base...head in one path segment: both are checked SHAs here
            self._compares[k] = self.api.get(self.rp('compare') + f'/{base}...{head}', {'per_page': 100})
        return self._compares[k]

    def is_ancestor(self, a, b):
        """True when commit a is b or behind it, None when GitHub does not say."""
        if a == b:
            return True
        if not (SHA.match(a or '') and SHA.match(b or '')):
            return None
        r = self.compare(a, b)
        if not r.ok or not isinstance(r.data, dict):
            return None
        return r.data.get('status') in ('ahead', 'identical')

    def head_of(self, branch):
        return (self.heads.get(branch) or {}).get('sha')

    def fresh_heads(self):
        """The heads read once more, for a commit pushed after the branches check ran."""
        if self._fresh is None:
            self._fresh = []
            for b in self.b['branches']:
                r = self.api.get(self.rp('branches', b))
                sha = ((r.data or {}).get('commit') or {}).get('sha', '') if (r.ok and isinstance(r.data, dict)) else ''
                if SHA.match(str(sha)):
                    self._fresh.append(sha)
        return self._fresh

    def on_branches(self, sha):
        """True when the commit is on main or Testing, None when that could not be told."""
        def verdict(heads):
            answers = []
            for h in heads:
                a = self.is_ancestor(sha, h)
                if a:
                    return True
                answers.append(a)
            return None if (None in answers or not answers) else False
        # Testing first: most runs are on it, and main is behind it anyway
        order = sorted(self.b['branches'], key=lambda b: b == self.main)
        first = verdict([h for h in (self.head_of(b) for b in order) if h])
        if first is True:
            return True
        second = verdict(self.fresh_heads())
        if second is True:
            return True
        return None if (first is None or second is None) else False

    def testing_head(self):
        h = self.head_of('Testing')
        if h:
            return h
        r = self.api.get(self.rp('branches', 'Testing'))
        if r.ok and isinstance(r.data, dict):
            sha = (r.data.get('commit') or {}).get('sha', '')
            return sha if SHA.match(sha) else None
        return None

    def testing_commits(self):
        if self._testing is None:
            r = self.api.get(self.rp('commits'), {'sha': 'Testing', 'per_page': 100})
            self._testing = r.data if (r.ok and isinstance(r.data, list)) else False
        return self._testing or None

    def known_workflows(self):
        """Workflow file names the baseline knows: main's, plus those of a branch whose
        baseline matches the pin in its own watchdog.yml (a new workflow on Testing)."""
        names = set()
        for b in [self.b] + list(self.trusted.values()):
            wf = b.get('workflows') if isinstance(b, dict) else None
            if isinstance(wf, dict):
                for part in ('publishers', 'others'):
                    if isinstance(wf.get(part), dict):
                        names |= {str(n) for n in wf[part]}
        return names

    def explain_main(self, sha):
        """(why, verdict) for a main head: True when its content came from Testing, False
        when it did not, None when that could not be read."""
        if sha not in self._explained:
            self._explained[sha] = self._explain_main(sha)
        return self._explained[sha]

    def _explain_main(self, sha):
        if sha in (self.b.get('accepted_main_heads') or {}):
            return 'accepted in the baseline', True
        c = self.commit(sha)
        if not c.ok or not isinstance(c.data, dict):
            return f'commit {sha[:8]} unreadable, {c.why()}', None
        tree = tree_of(c.data)
        parents = [p.get('sha', '') for p in c.data.get('parents') or []]
        recent = self.testing_commits()
        for tc in recent or []:
            if tc.get('sha') == sha:
                return 'a commit of Testing', True
            if tree and tree_of(tc) == tree:
                return f'the tree of Testing commit {tc.get("sha", "")[:8]}', True
        th = self.testing_head()
        # a release: "merge Testing into main", second parent on Testing, same tree
        if len(parents) == 2 and SHA.match(parents[1]):
            p2 = self.commit(parents[1])
            if p2.ok and tree and tree_of(p2.data) == tree:
                anc = self.is_ancestor(parents[1], th) if th else None
                if anc:
                    return f'a release merge of Testing commit {parents[1][:8]}', True
                if anc is None:
                    return f'could not tell whether {parents[1][:8]} is on Testing', None
        if th:
            anc = self.is_ancestor(sha, th)
            if anc:
                return 'a commit of Testing', True
            if anc is None:
                return f'could not tell whether {sha[:8]} is on Testing', None
        if recent is None or not th:
            return 'Testing could not be read', None
        return (f'its tree {str(tree)[:8]} is the tree of none of the last {len(recent)} Testing '
                f'commits, and it is no merge of a Testing commit with the same tree'), False

    def activity(self):
        """Pushes, merges and branch changes of main and Testing since the window start,
        newest first. Read per branch, so pushes to other branches cannot crowd them out."""
        if self._activity is None:
            def more(batch):
                return all((parse_ts(a.get('timestamp')) or self.now) >= self.since
                           for a in batch if isinstance(a, dict))
            keep, fail = [], None
            for b in self.b['branches']:
                ref = 'refs/heads/' + b
                items, f = self.api.pages(self.rp('activity'), {'per_page': 100, 'ref': ref}, max_pages=5, more=more)
                self.activity_cut = self.activity_cut or self.api.truncated
                fail = fail or f
                keep += [a for a in items if isinstance(a, dict) and str(a.get('ref') or '') == ref
                         and (parse_ts(a.get('timestamp')) or self.now) >= self.since]
            keep.sort(key=lambda a: parse_ts(a.get('timestamp')) or self.now, reverse=True)
            self._activity = (keep, fail)
        return self._activity

    def version_at(self, ref):
        """(version tuple or None, why when None)."""
        doc, r = manifest_at(self, ref)
        if doc is None:
            return None, f'version.json at {ref[:12]} unreadable, {r.why()}'
        t = version_tuple(doc.get('version')) if isinstance(doc, dict) else None
        return t, (None if t else f'version.json at {ref[:12]} has no version that reads as one')


def file_at(ctx, path, ref):
    """(bytes or None, Resp) of a file at a ref, through the contents API."""
    r = ctx.api.get(ctx.rp('contents', *path.split('/')), {'ref': ref})
    if not r.ok or not isinstance(r.data, dict):
        return None, r
    if r.data.get('encoding', 'base64') != 'base64':
        return None, Resp(0, error=f'{path} came without its content')
    try:
        return base64.b64decode(r.data.get('content') or ''), r
    except (ValueError, TypeError):
        return None, Resp(0, error=f'{path}: content not base64')


def manifest_at(ctx, ref):
    if ref not in ctx._manifests:
        raw, r = file_at(ctx, 'version.json', ref)
        if raw is None:
            ctx._manifests[ref] = (None, r)
        else:
            try:
                ctx._manifests[ref] = (json.loads(raw), r)
            except ValueError:
                ctx._manifests[ref] = ('unparsable', r)
    return ctx._manifests[ref]


def check_coverage(ctx):
    r = ctx.api.get(ctx.rp('actions', 'workflows', 'watchdog.yml', 'runs'),
                    {'event': 'schedule', 'status': 'success', 'branch': ctx.main, 'per_page': 1})
    if r.status == 404:
        ctx.note('GitHub knows no watchdog.yml yet, so this run looks back the standard window')
        return
    runs = r.data.get('workflow_runs') if (r.ok and isinstance(r.data, dict)) else None
    if not isinstance(runs, list):
        ctx.not_checked(f'the last successful scheduled run is unknown, {r.why()}; a gap before '
                        f'{hhmm(ctx.since)} would go unseen')
        return
    if not runs:
        ctx.note('no successful scheduled run on record yet, so this run looks back the standard window')
        return
    last = parse_ts(runs[0].get('run_started_at')) or parse_ts(runs[0].get('created_at'))
    if not last:
        ctx.not_checked('the last successful scheduled run has no start time')
        return
    # what that run saw ends at its start; the margin covers entries GitHub listed late
    last = min(last, ctx.now)
    start = last - COVER_MARGIN
    floor = ctx.now - ctx.max_lookback
    if start < floor:
        # Red once, not for ever: when scheduled runs did happen meanwhile (and failed), they
        # already reported this time. When none ran at all, the watchdog was off or broken.
        c = ctx.api.get(ctx.rp('actions', 'workflows', 'watchdog.yml', 'runs'),
                        {'event': 'schedule', 'status': 'completed', 'branch': ctx.main, 'per_page': 1})
        done = c.data.get('workflow_runs') if (c.ok and isinstance(c.data, dict)) else None
        prev = (parse_ts(done[0].get('run_started_at')) or parse_ts(done[0].get('created_at'))) \
            if isinstance(done, list) and done and isinstance(done[0], dict) else None
        seen = bool(prev and prev >= floor)
        ctx.not_checked(f'the last successful scheduled run started at {hhmm(last)}; only the time since '
                        f'{hhmm(floor)} is looked at, before that is a gap'
                        + (f' (the failed runs since, the last at {hhmm(prev)}, reported it already)' if seen
                           else ', and no scheduled run happened in between'), soft=seen)
        start = floor
    ctx.since = min(ctx.since, start)
    ctx.events_since = max(floor, min(ctx.events_since, last - ctx.events_window))
    if last < ctx.now - timedelta(minutes=30):
        ctx.note(f'no successful scheduled run since {hhmm(last)} (failed, late or skipped), so this one '
                 f'looks back to {hhmm(ctx.since)}')
    ctx.ok(f'last successful scheduled run {hhmm(last)}, looking back to {hhmm(ctx.since)}')


def check_settings(ctx):
    r = ctx.api.get(ctx.rp())
    if not r.ok or not isinstance(r.data, dict):
        ctx.not_checked(f'repository settings unreadable, {r.why()}')
        return
    d = ctx.repo_info = r.data
    want = ctx.b['settings']
    bad = False
    for field in ('default_branch', 'visibility', 'archived', 'disabled', 'has_pages'):
        if field in want and d.get(field) != want[field]:
            ctx.alarm(key('settings', field, fp(d.get(field))),
                      f'{field} is {v(d.get(field))}, the baseline says {v(want[field])}')
            bad = True
    if not bad:
        ctx.ok(f'default branch {d.get("default_branch")}, {d.get("visibility")}, not archived, Pages on')


def check_collaborators(ctx):
    want = ctx.b.get('collaborators')
    if want is None:
        return
    items, fail = ctx.api.pages(ctx.rp('collaborators'), {'per_page': 100, 'affiliation': 'all'}, max_pages=3)
    if fail:
        perm = fail.status in (401, 403, 404)
        ctx.not_checked(f'collaborators unreadable, {fail.why()}'
                        + ('; the token may not be allowed to list them' if perm else ''), soft=perm)
        return
    if ctx.api.truncated:
        ctx.not_checked(f'more than {len(items)} collaborators, the rest not looked at')
    have = {login(c): str(c.get('role_name') or '') for c in items if isinstance(c, dict) and login(c)}
    # NS Oct 2026 - the workflow token gets a 200 with an empty list here: access that comes
    # through the organization needs Members read, which that token never has. So a name
    # missing from the answer is not a removal. New names and changed roles still alarm.
    gone = sorted(set(want) - set(have))
    if gone:
        ctx.not_checked(f'{len(gone)} of {len(want)} baseline collaborators not in the answer '
                        f'({", ".join(v(n) for n in gone)}); this token may only see direct access', soft=True)
    diff = 0
    for name in sorted(set(have) | set(want)):
        if name in have and have.get(name) != want.get(name):
            diff += 1
            if name not in want:
                text = f'{v(name)} has access as {v(have[name])} and is not in the baseline'
            else:
                text = f'{v(name)} is {v(have[name])} now, the baseline says {v(want[name])}'
            ctx.alarm(key('collaborator', name, fp(have.get(name))), text)
    if not diff and not gone:
        ctx.ok(f'{len(have)} collaborators, as in the baseline')


def check_branches(ctx):
    for b in ctx.b['branches']:
        r = ctx.api.get(ctx.rp('branches', b))
        if r.status == 404:
            ctx.alarm(key('branch-missing', b), f'branch {b} does not exist')
            continue
        if not r.ok or not isinstance(r.data, dict):
            ctx.not_checked(f'branch {b} unreadable, {r.why()}')
            continue
        c = r.data.get('commit') or {}
        sha = c.get('sha', '')
        if not SHA.match(sha):
            ctx.not_checked(f'branch {b}: no commit in the answer')
            continue
        ctx.heads[b] = {'sha': sha}
    head = ctx.heads.get(ctx.main)
    if not head:
        return
    why, verdict = ctx.explain_main(head['sha'])
    if verdict is True:
        ctx.ok(f'{ctx.main} {head["sha"][:8]} is {why}')
    elif verdict is False:
        ctx.alarm(key('main-head', head['sha']), f'{ctx.main} is at {head["sha"][:8]}: {why}')
    else:
        ctx.not_checked(f'{ctx.main} {head["sha"][:8]}: {why}')
    # a rollback: main serves an older version than the newest release tag
    floor = max((t for t in (version_tuple(n) for n in ctx.b['tags']) if t), default=None)
    have, why = ctx.version_at(head['sha'])
    if floor and have is None and 'unreadable' in why:
        ctx.not_checked(f'{ctx.main}: {why}')
    elif floor and (have is None or have < floor):
        ctx.alarm(key('main-version', head['sha']),
                  f'{ctx.main} {head["sha"][:8]} carries version {vs(have) if have else "none"}, older than '
                  f'the release tag v{vs(floor)}')
    elif floor:
        ctx.ok(f'{ctx.main} carries {vs(have)}, not older than v{vs(floor)}')
    if 'Testing' in ctx.heads:
        ctx.ok(f'Testing {ctx.heads["Testing"]["sha"][:8]}')


def check_pins(ctx):
    for branch in ctx.b['branches']:
        ref = ctx.head_of(branch) or branch
        raw, r = file_at(ctx, WATCHDOG_YML, ref)
        if raw is None:
            if r.status == 404:
                ctx.note(f'watchdog.yml is not on {branch} (yet)')
            else:
                ctx.not_checked(f'watchdog.yml on {branch} unreadable, {r.why()}')
            continue
        pins = {p: h for h, p in PIN_LINE.findall(raw.decode('utf-8', 'replace'))}
        bad = 0
        for path in PINNED:
            want = pins.get(path)
            if not want:
                ctx.alarm(key('pin', branch, path, 'none'), f'watchdog.yml on {branch} pins no sha256 for {path}')
                bad += 1
                continue
            data, fr = file_at(ctx, path, ref)
            if data is None:
                ctx.not_checked(f'{path} on {branch} unreadable, {fr.why()}')
                bad += 1
                continue
            got = hashlib.sha256(data).hexdigest()
            if got != want:
                ctx.alarm(key('pin', branch, path, got[:10]),
                          f'{path} on {branch} has sha256 {got[:12]}, the watchdog.yml there pins {want[:12]}: '
                          'changed without the workflow file')
                bad += 1
                continue
            if path == BASELINE_PATH:
                try:
                    doc = json.loads(data)
                except ValueError:
                    doc = None
                if isinstance(doc, dict):
                    ctx.trusted[branch] = doc
        if not bad:
            ctx.ok(f'{branch}: watchdog.py and baseline.json match the pins in watchdog.yml')


def _watched_ref(ctx, ref):
    return ref in ctx.watched or ref.startswith('refs/tags/v')


def check_pushes(ctx):
    items, fail = ctx.activity()
    if fail:
        ctx.not_checked(f'repository activity unreadable, {fail.why()}')
        return
    if ctx.activity_cut:
        ctx.not_checked(f'more activity on main/Testing in the window than 500 entries per branch, '
                        'the oldest not looked at')
    seen = 0
    main_ref = 'refs/heads/' + ctx.main
    for a in items:
        ref = str(a.get('ref') or '')
        if ref not in ctx.watched:
            continue
        seen += 1
        kind = str(a.get('activity_type') or '')
        actor = login(a.get('actor'))
        before, after = str(a.get('before') or ''), str(a.get('after') or '')
        where = f'{kind} to {v(ref)} by {v(actor or "unknown")} at {a.get("timestamp")}'
        problems = []
        if actor not in ctx.team:
            problems.append('the actor is not on the team list')
        elif ref == main_ref and actor not in ctx.release_managers:
            problems.append('only a release manager moves main')
        if kind == 'force_push':
            problems.append('a force push')
        elif kind == 'branch_deletion':
            problems.append('the branch was deleted')
        elif kind == 'branch_creation':
            problems.append('the branch was created again, so it had been deleted')
        if kind in ('push', 'pr_merge', 'merge_queue_merge') and before != ZERO_SHA:
            if not (SHA.match(before) and SHA.match(after)):
                ctx.not_checked(f'{where}: no commit ids in the activity entry')
            else:
                anc = ctx.is_ancestor(before, after)
                if anc is False:
                    problems.append(f'{after[:8]} does not descend from {before[:8]}')
                elif anc is None:
                    ctx.not_checked(f'{where}: could not compare {before[:8]}...{after[:8]}')
        if ref == main_ref and SHA.match(after) and kind != 'branch_deletion':
            why, verdict = ctx.explain_main(after)
            if verdict is False:
                problems.append(f'{ctx.main} moved to {after[:8]}: {why}')
            elif verdict is None:
                ctx.not_checked(f'{where}: {why}')
            if SHA.match(before) and before != ZERO_SHA:
                old, why_old = ctx.version_at(before)
                new, why_new = ctx.version_at(after)
                if old and new and new < old:
                    problems.append(f'the version goes back from {vs(old)} to {vs(new)}')
                elif not (old and new):
                    ctx.not_checked(f'{where}: {why_old or why_new}')
        if problems:
            ctx.alarm(key('push', a.get('id')), f'{where}: ' + '; '.join(problems))
    ctx.ok(f'{seen} pushes, merges and branch changes on main/Testing since {hhmm(ctx.since)}')


def _author(ctx, commit_json):
    login_ = login(commit_json.get('author'))
    email = str((((commit_json.get('commit') or {}).get('author')) or {}).get('email') or '')
    allowed = ctx.b['allowed_authors']
    good = login_ in allowed['logins'] or email.lower() in {e.lower() for e in allowed['emails']}
    return good, login_ or email or 'unknown'


def _paths(entries):
    """File names of a compare or a commit, the old name of a rename included: moving a
    file out of a guarded folder changes the guarded folder."""
    out = []
    for f in entries or []:
        if isinstance(f, dict):
            out += [str(f[k]) for k in ('filename', 'previous_filename') if f.get(k)]
    return out


def check_workflow_files(ctx):
    guarded = tuple(ctx.b['guarded_paths'])
    items, fail = ctx.activity()
    if fail:
        ctx.not_checked(f'repository activity unreadable, {fail.why()}')
        items = []
    touched_pushes = guarded_commits = 0
    maintainers = ', '.join(sorted(ctx.maintainers))
    for a in items:
        ref = str(a.get('ref') or '')
        kind = str(a.get('activity_type') or '')
        before, after = str(a.get('before') or ''), str(a.get('after') or '')
        if ref not in ctx.watched or kind not in ('push', 'pr_merge', 'merge_queue_merge', 'force_push'):
            continue
        if not (SHA.match(before) and SHA.match(after)) or before == ZERO_SHA:
            continue
        actor = login(a.get('actor'))
        where = f'{kind} to {v(ref)} by {v(actor or "unknown")} at {a.get("timestamp")}'
        cmp = ctx.compare(before, after)
        if not cmp.ok or not isinstance(cmp.data, dict):
            ctx.not_checked(f'{where}: the changed files could not be read, {cmp.why()}')
            continue
        entries = cmp.data.get('files') or []
        files = _paths(entries)
        hit = [f for f in files if f.startswith(guarded)]
        if not hit and len(entries) < 300:
            continue
        touched_pushes += 1
        if ref == 'refs/heads/' + ctx.main and ctx.explain_main(after)[1] is True:
            # the same files went through Testing first and were looked at there
            ctx.ok(f'{ctx.main} took {len(hit)} guarded file(s) from Testing ({after[:8]})')
            continue
        own_key = key('own-files', a.get('id'))
        own = sorted({f for f in files if f in OWN_FILES})
        if own and actor not in ctx.maintainers:
            ctx.alarm(own_key, f'{where} changes {", ".join(v(f) for f in own)}; only {maintainers} '
                               'change the watchdog')
        commits = [c for c in cmp.data.get('commits') or [] if SHA.match(str(c.get('sha') or ''))]
        total = cmp.data.get('total_commits', len(commits))
        if not isinstance(total, int) or total > min(len(commits), MAX_COMMITS):
            ctx.not_checked(f'{where}: {total} commits, only the first {min(len(commits), MAX_COMMITS)} looked at')
        for c in commits[:MAX_COMMITS]:
            d = ctx.commit(c['sha'])
            if not d.ok or not isinstance(d.data, dict):
                ctx.not_checked(f'commit {c["sha"][:8]} unreadable, {d.why()}')
                continue
            mine = [f for f in _paths(d.data.get('files')) if f.startswith(guarded)]
            if not mine:
                continue
            guarded_commits += 1
            if actor not in ctx.maintainers and any(f in OWN_FILES for f in mine):
                ctx.alarm(own_key, f'{where} changes the watchdog\'s own files in {c["sha"][:8]}; '
                                   f'only {maintainers} change the watchdog')
            good, who = _author(ctx, d.data)
            if not good:
                ctx.alarm(key('workflow-file', c['sha']),
                          f'{c["sha"][:8]} by {v(who)} changes {", ".join(v(f) for f in mine[:3])}'
                          f'{" and more" if len(mine) > 3 else ""} ({where})')
    ctx.ok(f'{touched_pushes} push(es) touching {", ".join(guarded)} since {hhmm(ctx.since)}, '
           f'{guarded_commits} commit(s) of them looked at one by one')

    known = ctx.known_workflows()
    for branch in ctx.b['branches']:
        r = ctx.api.get(ctx.rp('contents', '.github', 'workflows'), {'ref': ctx.head_of(branch) or branch})
        if not r.ok or not isinstance(r.data, list):
            ctx.not_checked(f'.github/workflows on {branch} unreadable, {r.why()}')
            continue
        names = {str(f.get('name') or '') for f in r.data if isinstance(f, dict) and f.get('type') == 'file'}
        names = {n for n in names if n.endswith(('.yml', '.yaml'))}
        for n in sorted(names - known):
            ctx.alarm(key('workflow-unknown', branch, n),
                      f'{v(n)} on {branch} is in neither list of the baseline (main\'s, or a pinned one on '
                      f'{branch}), so a freeze would not stop it')
        ctx.ok(f'{len(names & known)} known workflow files on {branch}')


def _peel(ctx, otype, sha):
    """(commit, problem, readable) for what a tag ref points at."""
    for _ in range(4):
        if otype != 'tag' or not SHA.match(sha):
            break
        r = ctx.api.get(ctx.rp('git', 'tags', sha))
        if not r.ok or not isinstance(r.data, dict):
            return None, f'tag object {sha[:8]} unreadable, {r.why()}', False
        obj = r.data.get('object') or {}
        otype, sha = obj.get('type'), str(obj.get('sha') or '')
    if otype != 'commit' or not SHA.match(sha):
        return None, f'points at a {v(otype)}, not at a commit', True
    return sha, '', True


def check_tags(ctx):
    items, fail = ctx.api.pages(ctx.rp('git', 'matching-refs', 'tags', 'v'), {'per_page': 100}, max_pages=5)
    if fail or ctx.api.truncated:
        # a cut list would read as deleted tags
        ctx.not_checked(f'tags unreadable, {fail.why()}' if fail else 'more than 500 tags, not checked')
        return
    live = {}
    for it in items:
        ref = str((it or {}).get('ref') or '')
        if ref.startswith('refs/tags/'):
            obj = it.get('object') or {}
            live[ref[len('refs/tags/'):]] = (obj.get('type'), str(obj.get('sha') or ''))
    ctx.tags_live = live
    known = ctx.b['tags']
    for name, sha in sorted(known.items()):
        if name not in live:
            ctx.alarm(key('tag-deleted', name), f'release tag {v(name)} is gone (was {sha[:8]})')
        elif live[name][1] != sha:
            ctx.alarm(key('tag-moved', name, live[name][1][:12]),
                      f'release tag {v(name)} now points at {live[name][1][:8]}, was {sha[:8]}')
        else:
            ctx.tags_good.add(name)
    new = sorted(set(live) - set(known))
    main_head = ctx.head_of(ctx.main)

    def unsure(name, text):
        ctx.tags_unsure.add(name)
        ctx.not_checked(f'new tag {v(name)}: {text}')

    for name in new[:MAX_NEW_TAGS]:
        otype, sha = live[name]
        commit, err, readable = _peel(ctx, otype, sha)
        if commit is None:
            if readable:
                ctx.alarm(key('tag-new', name, fp(otype, sha)), f'new tag {v(name)} {err}')
            else:
                unsure(name, err)
            continue
        tkey = key('tag-new', name, commit[:12])
        if not main_head:
            unsure(name, f'{ctx.main} head unknown')
            continue
        anc = ctx.is_ancestor(commit, main_head)
        if anc is None:
            unsure(name, f'could not tell whether {commit[:8]} is on {ctx.main}')
            continue
        if anc is False:
            why, verdict = ctx.explain_main(commit)
            if verdict is False:
                ctx.alarm(tkey, f'new tag {v(name)} points at {commit[:8]}, which is not on {ctx.main} and '
                                f'did not come from Testing ({why})')
                continue
            if verdict is None:
                unsure(name, f'{commit[:8]} is not on {ctx.main}, and {why}')
                continue
        doc, r = manifest_at(ctx, commit)
        if doc is None:
            unsure(name, f'version.json at {commit[:8]} unreadable, {r.why()}')
            continue
        version = doc.get('version') if isinstance(doc, dict) else None
        if name != f'v{version}':
            ctx.alarm(tkey, f'new tag {v(name)} on {commit[:8]}, but version.json there says {v(version)}')
            continue
        if anc is False:
            # the tag went out before main: fine if main follows within minutes, so no
            # freeze for it, but no pass either (git push --atomic origin main <tag>)
            unsure(name, f'{commit[:8]} is {why} and matches version.json, but is not on {ctx.main} yet')
            continue
        ctx.tags_good.add(name)
        ctx.ok(f'new tag {name} on {commit[:8]} matches version.json')
    if len(new) > MAX_NEW_TAGS:
        ctx.not_checked(f'{len(new) - MAX_NEW_TAGS} more new tags not looked at')
    ctx.ok(f'{len(ctx.tags_good & set(known))} of {len(known)} known release tags unchanged, {len(new)} new')


def vet_run(ctx, run):
    """(problems, doubts) for a run of a publishing workflow."""
    problems, doubts = [], []
    origin = run_origin(run)
    if origin is None:
        problems.append('it names no head repository')
    elif origin != ctx.repo:
        problems.append(f'it comes from {v(origin)}')
    who = {login(run.get('actor')), login(run.get('triggering_actor'))} - {''}
    bad = sorted(w for w in who if w not in ctx.team)
    if bad:
        problems.append('started by ' + ', '.join(v(w) for w in bad))
    elif not who:
        problems.append('no actor')
    sha = str(run.get('head_sha') or '')
    if not SHA.match(sha):
        problems.append('no head commit')
    else:
        on = ctx.on_branches(sha)
        if on is not True:
            # a release merge whose tag went out before main: the tree of a Testing commit,
            # so it builds what was reviewed there
            same = ctx.explain_main(sha)[1]
            on = True if same is True else (None if (same is None or on is None) else False)
        if on is False:
            problems.append(f'its commit {sha[:8]} is on neither main nor Testing and carries no Testing tree')
        elif on is None:
            doubts.append(f'could not tell whether {sha[:8]} is on main or Testing')
    return problems, doubts


def run_origin(run):
    hr = run.get('head_repository')
    return str(hr['full_name']) if isinstance(hr, dict) and hr.get('full_name') else None


def run_span(ctx, run):
    start = parse_ts(run.get('run_started_at')) or parse_ts(run.get('created_at'))
    end = parse_ts(run.get('updated_at')) if run.get('status') == 'completed' else ctx.now
    return start, end


def check_releases(ctx):
    items, fail = ctx.api.pages(ctx.rp('releases'), {'per_page': 100}, max_pages=3)
    if fail:
        ctx.not_checked(f'releases unreadable, {fail.why()}')
        return
    if ctx.api.truncated:
        ctx.not_checked(f'only the newest {len(items)} releases looked at', soft=True)
    accepted = {str(k) for k in (ctx.b.get('accepted_releases') or {})}
    uploaders = set(ctx.b['release_asset_uploaders'])
    assets = drafts = 0
    fresh = []
    if ctx.tags_live is None:
        ctx.not_checked('the tags were not readable, so the release tags are not checked')
    for r in items:
        if not isinstance(r, dict):
            continue
        if r.get('draft'):
            drafts += 1
            continue
        rid, tag, author = str(r.get('id')), str(r.get('tag_name') or ''), login(r.get('author'))
        problems = []
        if rid not in accepted:
            if author not in ctx.release_managers:
                problems.append(f'published by {v(author or "unknown")}, who is no release manager')
            if ctx.tags_live is not None and tag in ctx.tags_unsure:
                ctx.not_checked(f'release {v(tag)}: its tag could not be verified in this run')
            elif ctx.tags_live is not None and tag not in ctx.tags_good:
                problems.append('its tag is no known or verified release tag')
        if problems:
            ctx.alarm(key('release', rid, fp(problems)), f'release {v(tag)}: ' + '; '.join(problems))
        for a in r.get('assets') or []:
            if not isinstance(a, dict) or a.get('state') != 'uploaded':
                continue
            assets += 1
            up = login(a.get('uploader'))
            if up not in uploaders:
                ctx.alarm(key('release-asset', a.get('id')),
                          f'release {v(tag)}: asset {v(a.get("name"))} uploaded by {v(up or "unknown")} at {a.get("updated_at")}')
                continue
            stamps = [t for t in (parse_ts(a.get('created_at')), parse_ts(a.get('updated_at'))) if t]
            if stamps and max(stamps) >= ctx.since:
                fresh.append((tag, a, max(stamps)))
    if fresh:
        _check_fresh_assets(ctx, fresh)
    ctx.ok(f'{len(items) - drafts} releases, {assets} assets, {len(fresh)} changed since {hhmm(ctx.since)}')
    if drafts:
        ctx.note(f'{drafts} draft release(s) not looked at')


def _check_fresh_assets(ctx, fresh):
    """Every workflow uploads as github-actions[bot], so who uploaded says little. An asset
    changed in the window has to fall into a run of a workflow that attaches files to
    releases and passes the run check (team, this repository, a commit of main or Testing).
    A swap through any other workflow, or through a run that deleted itself afterwards, has
    none."""
    runs, errors = [], []
    for wf in ctx.b['workflows'].get('attach_to_releases') or ctx.b['workflows']['publishers']:
        r = ctx.api.get(ctx.rp('actions', 'workflows', wf, 'runs'), {'per_page': 20})
        if r.ok and isinstance(r.data, dict) and isinstance(r.data.get('workflow_runs'), list):
            runs += [x for x in r.data['workflow_runs'] if isinstance(x, dict)]
        else:
            errors.append(f'{wf}: {r.why()}')
    for tag, a, at in fresh:
        what = f'release {v(tag)}: asset {v(a.get("name"))} changed at {hhmm(at)}'
        cover = []
        for run in runs:
            start, end = run_span(ctx, run)
            if start and end and start - timedelta(minutes=1) <= at <= end + timedelta(minutes=5):
                cover.append(run)
        vetted = [run for run in cover if vet_run(ctx, run) == ([], [])]
        if vetted:
            run = vetted[0]
            ctx.ok(f'{clean(what)}, by run {run.get("id")} of {clean(str(run.get("path") or "").rsplit("/", 1)[-1])}')
        elif errors and not cover:
            ctx.not_checked(f'{what}; the publisher runs could not all be read ({"; ".join(errors)})')
        elif any(vet_run(ctx, run)[1] for run in cover):
            ctx.not_checked(f'{what}; the run behind it could not be fully checked')
        else:
            ctx.alarm(key('release-asset', a.get('id'), fp(at)),
                      f'{what}, and no publisher run that passes the run check was going then')


def check_events(ctx):
    since = ctx.events_since

    def more(batch):
        return any((parse_ts(e.get('created_at')) or ctx.now) >= since for e in batch if isinstance(e, dict))
    items, fail = ctx.api.pages(ctx.rp('events'), {'per_page': 100}, max_pages=3, more=more)
    if fail:
        ctx.not_checked(f'event feed unreadable, {fail.why()}')
        return
    # GitHub serves 300 events at most, and anyone can fill them with comments. The feed is
    # not strictly in time order (late events come in between), so what counts is where it
    # ends, not its oldest time stamp
    stamps = [t for t in (parse_ts(e.get('created_at')) for e in items if isinstance(e, dict)) if t]
    tail = parse_ts(items[-1].get('created_at')) if items and isinstance(items[-1], dict) else None
    if not stamps or (tail and tail > since):
        ends = hhmm(tail) if tail else 'nowhere'
        ctx.not_checked(f'the event feed ends at {ends}, the window starts at {hhmm(since)}; the older '
                        'events are not looked at (collaborators are checked on their own)', soft=True)
    seen, counted = set(), 0
    branches = {b for b in ctx.b['branches']}
    for e in items:
        if not isinstance(e, dict):
            continue
        eid = str(e.get('id'))
        if eid in seen:
            continue
        seen.add(eid)
        if (parse_ts(e.get('created_at')) or ctx.now) < since:
            continue
        counted += 1
        typ, actor = str(e.get('type') or ''), login(e.get('actor'))
        p = e.get('payload') if isinstance(e.get('payload'), dict) else {}
        k, at = key('event', eid), f'at {e.get("created_at")}'
        outsider = actor not in ctx.team
        manager = actor in ctx.release_managers
        if typ == 'MemberEvent':
            ctx.alarm(k, f'{v(actor)} {v(p.get("action"))} collaborator {v(login(p.get("member")))} {at}')
        elif typ == 'PublicEvent':
            ctx.alarm(k, f'{v(actor)} made the repository public, so it was private before {at}')
        elif typ == 'PushEvent':
            ref = str(p.get('ref') or '')
            if ref == 'refs/heads/' + ctx.main and not manager:
                ctx.alarm(k, f'push to {v(ref)} by {v(actor)}, who is no release manager {at}')
            elif _watched_ref(ctx, ref) and outsider:
                ctx.alarm(k, f'push to {v(ref)} by {v(actor)} {at}')
        elif typ in ('CreateEvent', 'DeleteEvent'):
            rt, ref = str(p.get('ref_type') or ''), str(p.get('ref') or '')
            if rt == 'branch' and ref in branches:
                what = 'deleted' if typ == 'DeleteEvent' else 'created again'
                ctx.alarm(k, f'branch {v(ref)} {what} by {v(actor)} {at}')
            elif rt == 'tag' and typ == 'DeleteEvent' and ref.startswith('v'):
                ctx.alarm(k, f'tag {v(ref)} deleted by {v(actor)} {at}')
            elif rt == 'tag' and ref.startswith('v') and not manager:
                ctx.alarm(k, f'tag {v(ref)} created by {v(actor)}, who is no release manager {at}')
            elif rt == 'tag' and outsider:
                ctx.alarm(k, f'tag {v(ref)} {"deleted" if typ == "DeleteEvent" else "created"} by {v(actor)} {at}')
        elif typ == 'ReleaseEvent' and not manager:
            rel = p.get('release') if isinstance(p.get('release'), dict) else {}
            ctx.alarm(k, f'release {v(rel.get("tag_name"))} {v(p.get("action"))} by {v(actor)}, '
                         f'who is no release manager {at}')
    ctx.ok(f'{counted} events since {hhmm(since)}')


def norm_ruleset(d):
    def sort_deep(x):
        if isinstance(x, dict):
            return {k: sort_deep(x[k]) for k in sorted(x)}
        if isinstance(x, list):
            items = [sort_deep(i) for i in x]
            return sorted(items, key=lambda i: json.dumps(i, sort_keys=True))
        return x
    out = {k: sort_deep(d.get(k)) for k in ('name', 'target', 'enforcement', 'conditions', 'rules')}
    if 'bypass_actors' in d:
        out['bypass_actors'] = sort_deep([{k: a.get(k) for k in ('actor_type', 'actor_id', 'bypass_mode')}
                                          for a in d.get('bypass_actors') or [] if isinstance(a, dict)])
    return out


def check_rulesets(ctx):
    items, fail = ctx.api.pages(ctx.rp('rulesets'), {'per_page': 100, 'includes_parents': 'true'}, max_pages=2)
    if fail:
        ctx.not_checked(f'rulesets unreadable, {fail.why()}')
        return
    live = {str(r.get('id')): r for r in items if isinstance(r, dict)}
    hidden = []
    for want in ctx.b['rulesets']:
        rid = str(want['id'])
        if rid not in live:
            ctx.alarm(key('ruleset', rid, 'gone'), f'ruleset {v(want["name"])} ({rid}) is gone')
            continue
        r = ctx.api.get(ctx.rp('rulesets', rid))
        if not r.ok or not isinstance(r.data, dict):
            ctx.not_checked(f'ruleset {rid} unreadable, {r.why()}')
            continue
        have = norm_ruleset(r.data)
        diffs = [f for f in ('name', 'target', 'enforcement', 'conditions', 'rules')
                 if have.get(f) != norm_ruleset(want).get(f)]
        if 'bypass_actors' in have:
            if have['bypass_actors'] != norm_ruleset(want).get('bypass_actors', []):
                diffs.append('bypass_actors')
        else:
            hidden.append(rid)
        if diffs:
            ctx.alarm(key('ruleset', rid, fp(have, r.data.get('updated_at'))),
                      f'ruleset {v(want["name"])} differs from the baseline in {", ".join(diffs)}'
                      f' (enforcement now {v(r.data.get("enforcement"))})')
            continue
        edited, known = parse_ts(r.data.get('updated_at')), parse_ts(want.get('updated_at'))
        if edited and known and edited > known + timedelta(seconds=1):
            ctx.alarm(key('ruleset', rid, fp(r.data.get('updated_at'))),
                      f'ruleset {v(want["name"])} was edited at {r.data.get("updated_at")}; '
                      'it equals the baseline again, so it was changed and changed back')
            continue
        ctx.ok(f'{want["name"]}: {have["enforcement"]}, unchanged')
    if hidden:
        ctx.not_checked(f'bypass actors of ruleset(s) {", ".join(hidden)}: GitHub shows them only to '
                        'repository admins; reading them needs a token with Administration read, '
                        'not the workflow token', soft=True)
    for rid in sorted(set(live) - {str(w['id']) for w in ctx.b['rulesets']}):
        ctx.note(f'ruleset {v(live[rid].get("name"))} ({rid}) is not in the baseline')


def _side_change(ctx, sha, wf_path):
    """For a run on a commit off main/Testing: (changed, why). changed is True when that
    commit's branch changed the workflow file the run used, None when unknown."""
    th = ctx.testing_head()
    if not th:
        return None, 'Testing head unknown'
    cmp = ctx.compare(th, sha)
    if not cmp.ok or not isinstance(cmp.data, dict):
        return None, f'could not compare {sha[:8]} with Testing, {cmp.why()}'
    if cmp.data.get('status') in ('behind', 'identical'):
        return False, ''
    entries = cmp.data.get('files') or []
    if wf_path in _paths(entries):
        return True, ''
    if len(entries) >= 300:
        return None, f'{sha[:8]} changes 300 files or more, the workflow file may be among them'
    return False, ''


def check_workflow_runs(ctx):
    pubs = set(ctx.b['workflows']['publishers'])
    known = ctx.known_workflows()
    since = ctx.since.strftime('%Y-%m-%dT%H:%M:%SZ')
    items, fail = ctx.api.pages(ctx.rp('actions', 'runs'), {'per_page': 100, 'created': f'>={since}'},
                                max_pages=3, key='workflow_runs')
    cut = ctx.api.truncated
    if fail:
        ctx.not_checked(f'workflow runs unreadable, {fail.why()}')
    if cut or fail:
        if cut:
            ctx.not_checked(f'more runs in the window than {len(items)}: the publishers are read one by one, '
                            'runs of other workflows beyond that are not looked at')
        for wf in sorted(pubs):
            more_runs, f2 = ctx.api.pages(ctx.rp('actions', 'workflows', wf, 'runs'),
                                          {'per_page': 100, 'created': f'>={since}'}, max_pages=2, key='workflow_runs')
            if f2 or ctx.api.truncated:
                ctx.not_checked(f'runs of {wf} unreadable or too many, {f2.why() if f2 else "more than 200"}')
            items += more_runs
    seen, n_pub, n_other = set(), 0, 0
    for run in items:
        if not isinstance(run, dict) or run.get('id') in seen:
            continue
        seen.add(run.get('id'))
        rid = run.get('id')
        path = str(run.get('path') or '').split('@')[0]
        name = path.rsplit('/', 1)[-1]
        if path.startswith('dynamic/'):
            continue    # GitHub's own: CodeQL, Dependabot, the Pages build
        event = str(run.get('event') or '')
        origin = run_origin(run)
        is_pub = path.startswith('.github/workflows/') and name in pubs
        is_known = path.startswith('.github/workflows/') and name in known
        where = f'{v(name)} run {rid} ({v(event)} on {v(run.get("head_branch"))})'
        if event == 'pull_request' and origin != ctx.repo:
            # a fork's pull request (or one whose fork is gone): read-only token, no secrets,
            # it cannot publish. Anyone can open one, so it must not freeze anything.
            if is_pub or not is_known:
                ctx.note(f'{where} from a fork pull request ({v(origin or "fork deleted")}), sandboxed by GitHub')
            continue
        who = login(run.get('triggering_actor')) or login(run.get('actor')) or 'unknown'
        if not is_known:
            ctx.alarm(key('run', rid), f'{where}: a workflow the baseline does not know, started by {v(who)}')
            continue
        if is_pub:
            n_pub += 1
            problems, doubts = vet_run(ctx, run)
            if problems:
                ctx.alarm(key('run', rid), f'{where}: ' + '; '.join(problems))
            elif doubts:
                ctx.not_checked(f'{where}: ' + '; '.join(doubts))
            continue
        n_other += 1
        # a known workflow that does not publish. pull_request_target runs the file of the
        # base branch, so only the others can run a copy changed on a side branch
        sha = str(run.get('head_sha') or '')
        if event == 'pull_request_target' or origin != ctx.repo or not SHA.match(sha):
            continue
        if sha in (ctx.head_of('Testing'), ctx.head_of(ctx.main)):
            continue
        changed, why = _side_change(ctx, sha, path)
        if changed:
            ctx.alarm(key('run', rid), f'{where}: runs a copy of {v(name)} that its branch changed '
                                       f'(commit {sha[:8]}, started by {v(who)})')
        elif changed is None:
            ctx.not_checked(f'{where}: {why}')
    ctx.ok(f'{n_pub} publisher run(s) and {n_other} other run(s) since {hhmm(ctx.since)}')
    r = ctx.api.get(ctx.rp('actions', 'workflows'), {'per_page': 100})
    if not r.ok or not isinstance(r.data, dict):
        ctx.not_checked(f'workflow states unreadable, {r.why()}')
        return
    states = {str(w.get('path') or '').rsplit('/', 1)[-1]: w.get('state') for w in r.data.get('workflows') or []
              if isinstance(w, dict)}
    off = sorted(p for p in pubs if states.get(p) not in ('active', None))
    for p in sorted(pubs - set(states)):
        ctx.note(f'publisher {p} is not known to GitHub Actions')
    if off:
        ctx.note('frozen or disabled: ' + ', '.join(f'{p} ({states[p]})' for p in off))
    else:
        ctx.ok('all publishing workflows active')


def url_under(value, allowed):
    """value is one of the allowed URLs exactly, or lies below one of them that ends in /.
    Parsed, not a prefix match on the string: /../ or a look-alike host do not get through."""
    if not isinstance(value, str):
        return False
    if value in allowed:
        return True
    if any(ch in value for ch in '\\@%') or any(ch.isspace() for ch in value):
        return False
    try:
        u = urllib.parse.urlsplit(value)
        port = u.port
    except ValueError:
        return False
    segs = u.path.split('/')
    if u.scheme != 'https' or port is not None or u.query or u.fragment or '..' in segs or '.' in segs:
        return False
    for a in allowed:
        if not a.endswith('/'):
            continue
        p = urllib.parse.urlsplit(a)
        if u.netloc.lower() == p.netloc.lower() and u.path.startswith(p.path) and len(u.path) > len(p.path):
            return True
    return False


def judge_manifest(cfg, doc):
    if not isinstance(doc, dict):
        return ['not a JSON object']
    exact, prefixes = cfg['exact'], cfg['prefixes']
    ours = [u for vals in exact.values() for u in vals] + [p for ps in prefixes.values() for p in ps] \
        + list(cfg.get('other_url_prefixes') or [])
    problems = []
    for field, allowed in exact.items():
        if field in doc and doc[field] not in allowed:
            problems.append(f'{field} is {v(doc[field])}')
    for field, allowed in prefixes.items():
        if field in doc and not url_under(doc[field], allowed):
            problems.append(f'{field} is {v(doc[field])}')
    for k, val in doc.items():
        if k in exact or k in prefixes or not isinstance(val, str):
            continue
        if '://' in val and not url_under(val, ours):
            problems.append(f'{v(k)} is {v(val)}')
    files = doc.get('update_files')
    if files is not None:
        if not isinstance(files, list):
            problems.append('update_files is no list')
        else:
            odd = [f for f in files if not isinstance(f, str) or '://' in f or f.startswith(('/', '\\'))
                   or '..' in f.replace('\\', '/').split('/')]
            if odd:
                problems.append(f'update_files has {len(odd)} odd entr{"y" if len(odd) == 1 else "ies"}, '
                                f'first {v(odd[0])}')
    return problems


def check_update_manifest(ctx):
    cfg = ctx.b['update_manifest']
    done = set()

    def judge(branch, ref, where):
        done.add(ref)
        doc, r = manifest_at(ctx, ref)
        if doc is None:
            if r.status == 404:
                ctx.alarm(key('manifest', branch, ref[:12], 'missing'), f'version.json is missing {where}')
            else:
                ctx.not_checked(f'version.json {where} unreadable, {r.why()}')
            return None
        problems = judge_manifest(cfg, doc if doc != 'unparsable' else None)
        if problems:
            ctx.alarm(key('manifest', branch, fp(problems)), f'version.json {where}: ' + '; '.join(problems))
            return None
        return doc

    for branch in cfg['branches']:
        ref = ctx.head_of(branch) or branch
        doc = judge(branch, ref, f'on {branch}')
        if doc is not None:
            ctx.ok(f'{branch}: version {clean(doc.get("version"), 40)}, the URLs are ours')
    # every head main or Testing had in the window: a manifest that lived for five minutes
    # between two runs was still fetched by whoever updated in those minutes
    items, fail = ctx.activity()
    if fail:
        ctx.not_checked(f'repository activity unreadable, {fail.why()}; only the current version.json judged')
    pushed = 0
    for a in items:
        ref = str(a.get('ref') or '')
        after = str(a.get('after') or '')
        branch = ref[len('refs/heads/'):]
        if branch not in cfg['branches'] or not SHA.match(after) or after == ZERO_SHA or after in done:
            continue
        pushed += 1
        judge(branch, after, f'at {after[:8]} (pushed to {branch} at {a.get("timestamp")})')
    if pushed:
        ctx.ok(f'{pushed} earlier head(s) of the window judged as well')
    mirror = cfg.get('mirror')
    if mirror:
        r = ctx.api.fetch_public(mirror)
        if r.status != 200:
            ctx.not_checked(f'mirror {mirror} unreadable, {r.why()}', soft=True)
        else:
            problems = judge_manifest(cfg, r.data)
            if problems:
                ctx.alarm(key('manifest', 'mirror', fp(problems)), f'{mirror}: ' + '; '.join(problems))
            else:
                ctx.ok(f'mirror: version {clean(r.data.get("version"), 40)}, the URLs are ours')


def check_environments(ctx):
    r = ctx.api.get(ctx.rp('environments'), {'per_page': 100})
    if not r.ok or not isinstance(r.data, dict):
        ctx.not_checked(f'environments unreadable, {r.why()}')
    else:
        live = {str(e.get('name')): e for e in r.data.get('environments') or [] if isinstance(e, dict)}
        for name, want in ctx.b['environments'].items():
            e = live.get(name)
            if e is None:
                ctx.alarm(key('environment', name, 'gone'), f'environment {name} is gone, and with it its branch rule')
                continue
            pol = e.get('deployment_branch_policy')
            if pol != want['deployment_branch_policy']:
                ctx.alarm(key('environment', name, fp(pol)),
                          f'environment {name}: deployment branch policy is {v(json.dumps(pol))}')
                continue
            types = {str(p.get('type')) for p in e.get('protection_rules') or [] if isinstance(p, dict)}
            if 'branch_policy' not in types:
                ctx.alarm(key('environment', name, 'no-branch-rule'), f'environment {name} has no branch rule any more')
                continue
            pr = ctx.api.get(ctx.rp('environments', name, 'deployment-branch-policies'), {'per_page': 100})
            if not pr.ok or not isinstance(pr.data, dict):
                ctx.not_checked(f'branch rules of {name} unreadable, {pr.why()}')
                continue
            have = sorted([str(p.get('name')), str(p.get('type'))] for p in pr.data.get('branch_policies') or []
                          if isinstance(p, dict))
            if have != sorted(want['branch_policies']):
                ctx.alarm(key('environment', name, fp(have)),
                          f'environment {name} deploys from {v(", ".join(f"{a} ({b})" for a, b in have))}')
                continue
            ctx.ok(f'{name}: only {", ".join(a for a, _ in have)}')
    want = ctx.b.get('pages')
    if want:
        pg = ctx.api.get(ctx.rp('pages'))
        if pg.status in (403, 404):
            ctx.not_checked(f'Pages settings: {pg.why()}; the workflow token may lack pages: read '
                            '(has_pages is checked under settings)', soft=True)
        elif not pg.ok or not isinstance(pg.data, dict):
            ctx.not_checked(f'Pages settings unreadable, {pg.why()}')
        else:
            bad = [f for f in ('cname', 'build_type') if pg.data.get(f) != want[f]]
            if bad:
                ctx.alarm(key('pages', fp([pg.data.get(f) for f in bad])),
                          'Pages: ' + ', '.join(f'{f} is {v(pg.data.get(f))}' for f in bad))
            else:
                ctx.ok(f'Pages: {want["cname"]}, built by a workflow')


CHECKS = [
    ('coverage', check_coverage),
    ('settings', check_settings),
    ('collaborators', check_collaborators),
    ('branches', check_branches),
    ('pins', check_pins),
    ('pushes', check_pushes),
    ('workflow-files', check_workflow_files),
    ('tags', check_tags),
    ('releases', check_releases),
    ('events', check_events),
    ('rulesets', check_rulesets),
    ('workflow-runs', check_workflow_runs),
    ('update-manifest', check_update_manifest),
    ('environments', check_environments),
]


def run_checks(ctx, checks=None):
    for name, fn in (CHECKS if checks is None else checks):
        ctx.report.begin(name)
        try:
            fn(ctx)
        except Exception as e:
            # an alarm, not "not checked": data shaped to crash a check would switch it off
            traceback.print_exc(file=sys.stderr)
            tb = traceback.extract_tb(e.__traceback__)
            line = tb[-1].lineno if tb else 0
            ctx.report.alarm(key('crash', name, fp(type(e).__name__, line)),
                             f'the check itself failed: {type(e).__name__}: {clean(e, 160)} (line {line})')
    return ctx.report


# ---------------------------------------------------------------------------------------
# baseline

def load_baseline(path):
    b = json.loads(Path(path).read_text(encoding='utf-8'))
    need = ('repo', 'default_branch', 'branches', 'allowed_actors', 'release_managers', 'watchdog_maintainers',
            'allowed_authors', 'guarded_paths', 'release_asset_uploaders', 'workflows', 'rulesets', 'tags',
            'settings', 'update_manifest', 'environments')
    missing = [k for k in need if k not in b]
    if missing:
        raise SystemExit(f'baseline {path}: missing {", ".join(missing)}')
    for wf in b['workflows']['publishers']:
        if not WORKFLOW_NAME.match(wf) or wf == 'watchdog.yml':
            raise SystemExit(f'baseline {path}: {wf!r} cannot be a publisher')
    return b


# ---------------------------------------------------------------------------------------
# freeze / unfreeze

def may_act(env, baseline):
    why = []
    if env.get('PEGAPROX_WATCHDOG_ACT') != '1':
        why.append('PEGAPROX_WATCHDOG_ACT is not 1')
    if env.get('GITHUB_ACTIONS') != 'true':
        why.append('not running in GitHub Actions')
    if env.get('GITHUB_REPOSITORY') != baseline['repo']:
        why.append(f'repository is {env.get("GITHUB_REPOSITORY") or "unset"}')
    if env.get('GITHUB_EVENT_NAME') not in ('schedule', 'workflow_dispatch'):
        why.append(f'event is {env.get("GITHUB_EVENT_NAME") or "unset"}, not schedule or workflow_dispatch')
    if env.get('GITHUB_REF') != 'refs/heads/' + baseline['default_branch']:
        why.append(f'ref is {env.get("GITHUB_REF") or "unset"}, not the default branch')
    return not why, why


def notify(env, text, transport):
    url = str(env.get('WATCHDOG_NOTIFY_URL') or '').strip()
    if not url:
        return 'no WATCHDOG_NOTIFY_URL, nothing sent'
    if not url.startswith('https://'):
        return 'WATCHDOG_NOTIFY_URL is not https, nothing sent'
    status, _, _, err = transport('POST', url, {'Content-Type': 'text/plain; charset=utf-8',
                                                'User-Agent': 'pegaprox-release-watchdog'}, text.encode())
    return f'notification sent ({status})' if 200 <= status < 300 else f'notification failed ({status or err})'


class Freezer:
    def __init__(self, api, baseline, env, out):
        self.api, self.b, self.env, self.out = api, baseline, env, out
        self.repo = baseline['repo']
        self.allowed, self.why = may_act(env, baseline)
        api.writes_allowed = self.allowed
        self.errors = []

    def rp(self, *parts):
        return '/repos/' + self.repo + ''.join('/' + urllib.parse.quote(str(p), safe='') for p in parts)

    def say(self, line):
        self.out.append(clean(line))

    def state(self, wf):
        r = self.api.get(self.rp('actions', 'workflows', wf))
        return r.data.get('state') if (r.ok and isinstance(r.data, dict)) else None

    def _switch(self, verb):
        changed = []
        if not self.allowed:
            self.say('report-only: ' + '; '.join(self.why))
        for wf in self.b['workflows']['publishers']:
            before = self.state(wf)
            if not self.allowed:
                self.say(f'would {verb} {wf} (now {before or "unknown"})')
                continue
            r = self.api.request('PUT', self.rp('actions', 'workflows', wf, verb))
            if r.status == 204:
                self.say(f'{verb}d {wf} (was {before or "unknown"})')
                was_on = before == 'active'
                if was_on if verb == 'disable' else not was_on:
                    changed.append(wf)
            else:
                self.errors.append(f'{verb} {wf}: {r.why()}')
        return changed

    def freeze(self):
        # disable everything first, so nothing new starts while the runs are cancelled
        changed = self._switch('disable')
        for wf in self.b['workflows']['publishers']:
            for status in RUN_STATES:
                runs, fail = self.api.pages(self.rp('actions', 'workflows', wf, 'runs'),
                                            {'status': status, 'per_page': 100}, max_pages=2, key='workflow_runs')
                if fail:
                    (self.errors.append if self.allowed else self.say)(f'{status} runs of {wf} unreadable, {fail.why()}')
                    continue
                for run in runs:
                    rid = run.get('id') if isinstance(run, dict) else None
                    if not isinstance(rid, int):
                        continue
                    if not self.allowed:
                        self.say(f'would cancel run {rid} of {wf} ({status})')
                        continue
                    r = self.api.request('POST', self.rp('actions', 'runs', rid, 'cancel'))
                    if r.status == 409:
                        # GitHub refuses a plain cancel for some states; force it
                        r = self.api.request('POST', self.rp('actions', 'runs', rid, 'force-cancel'))
                    if r.status == 202:
                        self.say(f'cancelled run {rid} of {wf} ({status})')
                    else:
                        self.errors.append(f'cancel run {rid} of {wf}: {r.why()}')
        return changed

    def unfreeze(self):
        return self._switch('enable')


def cmd_freeze(api, baseline, env, out, anns, transport, reason):
    f = Freezer(api, baseline, env, out)
    changed = f.freeze()
    # one message when the freeze is new, not one every ten minutes while it lasts
    if f.allowed and changed:
        out.append(notify(env, 'PegaProx release watchdog: publishing workflows frozen.', transport))
    anns += [('error', e) for e in f.errors]
    out.append(f'freeze ({reason}): {"done" if f.allowed else "report-only, nothing changed"}'
               f'{", " + str(len(f.errors)) + " error(s)" if f.errors else ""}')
    return 1 if f.errors else 0


def cmd_unfreeze(api, baseline, env, out, anns, transport, confirm):
    if confirm != 'UNFREEZE':
        anns.append(('error', 'unfreeze needs the confirm input set to UNFREEZE, nothing changed'))
        out.append('unfreeze refused: confirm is not UNFREEZE')
        return 1
    f = Freezer(api, baseline, env, out)
    changed = f.unfreeze()
    if f.allowed and changed:
        out.append(notify(env, 'PegaProx release watchdog: publishing workflows enabled again.', transport))
    if env.get('WATCHDOG_ALARM') == 'true':
        anns.append(('warning', 'the checks of this run still raise alarms: the next scheduled run freezes '
                                'again unless they are fixed or listed in WATCHDOG_ACK'))
    anns += [('error', e) for e in f.errors]
    out.append(f'unfreeze: {"done" if f.allowed else "report-only, nothing changed"}')
    return 1 if f.errors else 0


# ---------------------------------------------------------------------------------------
# rendering

def render_text(ctx):
    rep = ctx.report
    lines = [f'PegaProx release watchdog for {ctx.repo} at {hhmm(ctx.now)}; pushes since '
             f'{hhmm(ctx.since)}, events since {hhmm(ctx.events_since)}']
    for name in rep.checks:
        lines.append(f'[{rep.status(name)}] {name}')
        for t in rep.passed.get(name, []):
            lines.append(f'    ok: {clean(t)}')
        for f in rep.of(name):
            soft = ' (expected, does not fail the run)' if f.soft else ''
            lines.append(f'    {f.level}{soft}: {clean(f.text)}' + (f'  [key {f.key}]' if f.key else ''))
    a = len(rep.alarms)
    nc = sum(1 for f in rep.findings if f.level == NOT_CHECKED)
    lines.append(f'result: {a} alarm(s), {nc} item(s) not checked ({len(rep.blind)} of them fail the run), '
                 f'{ctx.api.calls} API calls, rate limit left {clean(ctx.api.ratelimit or "unknown", 20)}')
    return lines


def render_summary(ctx):
    rep = ctx.report
    a = rep.alarms
    out = ['## Release watchdog', '',
           f'{len(a)} alarm(s), {len(rep.blind)} gap(s) that fail the run, at {hhmm(ctx.now)}. Pushes since '
           f'{hhmm(ctx.since)}, events since {hhmm(ctx.events_since)}.', '',
           '| check | result | details |', '|---|---|---|']
    for name in rep.checks:
        details = [md(t) for t in rep.passed.get(name, [])]
        details += [f'**{f.level}**: {md(f.text)}' for f in rep.of(name)]
        out.append(f'| {name} | {rep.status(name)} | {"<br>".join(details) or "-"} |')
    if a:
        # keys are plain characters (see key()), shown as they are so they can be pasted back
        out += ['', 'Keys of the alarms (for WATCHDOG_ACK once one is understood):', '']
        out += [f'- `{f.key}`' for f in a]
    return '\n'.join(out) + '\n'


def write_env_file(env, name, text):
    path = env.get(name)
    if path:
        with open(path, 'a', encoding='utf-8', errors='backslashreplace') as fh:
            fh.write(text)


# ---------------------------------------------------------------------------------------

def main(argv=None, env=None, transport=None, now=None, stdout=None):
    env = dict(os.environ) if env is None else env
    stdout = stdout or sys.stdout
    ap = argparse.ArgumentParser(description='PegaProx release watchdog')
    ap.add_argument('cmd', choices=('check', 'act', 'freeze', 'unfreeze', 'snapshot'))
    ap.add_argument('--baseline', default=str(DEFAULT_BASELINE))
    ap.add_argument('--window-min', type=int, default=int(env.get('WATCHDOG_WINDOW_MIN') or 40))
    ap.add_argument('--events-window-min', type=int, default=int(env.get('WATCHDOG_EVENTS_WINDOW_MIN') or 360))
    ap.add_argument('--max-lookback-min', type=int, default=int(env.get('WATCHDOG_MAX_LOOKBACK_MIN') or 4320))
    ap.add_argument('--confirm', default='')
    ap.add_argument('--json', help='also write the findings to this file')
    args = ap.parse_args(argv)

    baseline = load_baseline(args.baseline)
    send = transport or urllib_transport
    api = Api(env.get('GITHUB_TOKEN') or env.get('GH_TOKEN') or '', send)
    in_actions = env.get('GITHUB_ACTIONS') == 'true'

    def emit(lines):
        for line in lines:
            print(line, file=stdout)

    if args.cmd == 'check':
        ctx = Ctx(api, baseline, now, args.window_min, args.events_window_min, env, args.max_lookback_min)
        run_checks(ctx)
        rep = ctx.report
        # first, before anything prints data from the API: the act job decides on this
        write_env_file(env, 'GITHUB_OUTPUT', f'alarm={"true" if rep.alarms else "false"}\n')
        code = 1 if rep.alarms else (2 if rep.blind else 0)
        try:
            emit(render_text(ctx))
            if in_actions:
                emit([annotation('error', f'{f.check}: {f.text}') for f in rep.alarms])
                emit([annotation('warning', f'{f.check} not checked: {f.text}') for f in rep.blind])
            if rep.alarms or env.get('WATCHDOG_ACTION') == 'freeze':
                emit(['would freeze: disable ' + ', '.join(baseline['workflows']['publishers'])
                      + ' and cancel their queued and running runs (the act job does that on '
                      + baseline['default_branch'] + ', from the schedule or a manual run)'])
            if env.get('WATCHDOG_ACTION') == 'unfreeze':
                emit(['would unfreeze: enable ' + ', '.join(baseline['workflows']['publishers'])
                      + ' (the act job does that on ' + baseline['default_branch'] + ' with confirm UNFREEZE)'])
            write_env_file(env, 'GITHUB_STEP_SUMMARY', render_summary(ctx))
            if args.json:
                Path(args.json).write_text(json.dumps([f.as_dict() for f in rep.findings], indent=1) + '\n',
                                           encoding='utf-8')
        except Exception as e:
            # the outcome is already decided and written; a report that cannot be printed
            # must not turn an alarm into a green run
            print(f'release watchdog: writing the report failed ({type(e).__name__})', file=sys.stderr)
            return code or 1
        return code

    out, anns = [], []
    if args.cmd == 'snapshot':
        snap = {'rulesets': [], 'tags': {}, 'collaborators': {}}
        items, fail = api.pages(f'/repos/{baseline["repo"]}/rulesets', {'per_page': 100}, max_pages=2)
        for r in items:
            d = api.get(f'/repos/{baseline["repo"]}/rulesets/{int(r["id"])}')
            if d.ok:
                n = norm_ruleset(d.data)
                n['id'] = d.data['id']
                t = parse_ts(d.data.get('updated_at'))
                n['updated_at'] = t.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' if t else None
                snap['rulesets'].append(n)
        tags, tfail = api.pages(f'/repos/{baseline["repo"]}/git/matching-refs/tags/v', {'per_page': 100}, max_pages=5)
        snap['tags'] = {t['ref'][len('refs/tags/'):]: t['object']['sha'] for t in tags}
        people, cfail = api.pages(f'/repos/{baseline["repo"]}/collaborators', {'per_page': 100, 'affiliation': 'all'},
                                  max_pages=3)
        snap['collaborators'] = {login(c): c.get('role_name') for c in people if isinstance(c, dict)}
        failed = fail or tfail or cfail
        if failed:
            print('incomplete: ' + failed.why(), file=sys.stderr)
        print(json.dumps(snap, indent=2), file=stdout)
        return 1 if failed else 0

    if args.cmd == 'act':
        action = str(env.get('WATCHDOG_ACTION') or 'check').strip()
        if action == 'unfreeze':
            code = cmd_unfreeze(api, baseline, env, out, anns, send, env.get('WATCHDOG_CONFIRM', ''))
        elif action == 'freeze' or env.get('WATCHDOG_ALARM') == 'true':
            code = cmd_freeze(api, baseline, env, out, anns, send, 'by hand' if action == 'freeze' else 'alarm')
        else:
            out.append('no alarm and no freeze asked for, nothing to do')
            code = 0
    elif args.cmd == 'freeze':
        code = cmd_freeze(api, baseline, env, out, anns, send, 'by hand')
    else:
        code = cmd_unfreeze(api, baseline, env, out, anns, send, args.confirm)
    emit(out)
    emit([annotation(level, text) if in_actions else f'{level}: {clean(text)}' for level, text in anns])
    write_env_file(env, 'GITHUB_STEP_SUMMARY', '## Release watchdog: ' + args.cmd + '\n\n'
                   + ''.join(f'- {md(line)}\n' for line in out)
                   + ''.join(f'- **{level}**: {md(text)}\n' for level, text in anns))
    return code


if __name__ == '__main__':
    sys.exit(main())
