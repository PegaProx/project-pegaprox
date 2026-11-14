"""Server side: read deadlines, what a confined caller learns, and the failure answers.

  a) The deadline of the ISO sync status and of the Backup SLA holds for the whole read, also with
     more nodes or stores than workers. The fan-out spawned one job after the other and only the
     last wave was cut off: 24 nodes of 5 s with a 0.6 s deadline took over 10 s. No read starts
     after the deadline and none is given a timeout that reaches past it.
  b) A pool or ACL confined caller of the Backup SLA learns how many stores were not read, not
     their names or nodes; an unconfined one keeps both.
  c) The storage content and PCI routes answer a lost cluster with the common shape: 503,
     code PVE_UNREACHABLE and what could not be read.
  d) The Ceph reads answer every failure as JSON: another requests error is PVE_UNREACHABLE, a
     failure of the session itself a 500 with code READ_FAILED (no HTML error page).

The PVE answers are scripted with the fakes of test_sync_status_and_backup_sla_scale.py and
test_failed_node_reads_are_errors.py. MK Nov 2026
"""
import time

import pytest
import requests

from test_sync_status_and_backup_sla_scale import (CLUSTER, _Pve, _iso_answer, _sla_answer, _sla_cluster, _states,
                                                   _sync_mgr)
from test_failed_node_reads_are_errors import NODE, _url, pve  # noqa: F401 (fixture)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


# --- a) the whole read within its deadline ---------------------------------------------------------

def _record_timeouts(monkeypatch):
    """[(PVE path, timeout)] of every read of the scripted PVE made after this."""
    seen = []
    get = _Pve.get

    def _get(self, url, params=None, timeout=None, **kw):
        seen.append((url.split('/api2/json', 1)[1], timeout))
        return get(self, url, params=params, timeout=timeout, **kw)
    monkeypatch.setattr(_Pve, 'get', _get)
    return seen


def test_the_sync_status_deadline_holds_with_more_nodes_than_workers(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    monkeypatch.setattr(PegaProxManager, 'SYNC_STATUS_DEADLINE', 0.6, raising=False)
    nodes = [f'pve{i}' for i in range(24)]
    m, pve = _sync_mgr(nodes, _iso_answer(slow=tuple(nodes)))
    t0 = time.monotonic()
    status = m.get_content_sync_status('iso')
    took = time.monotonic() - t0
    # three waves of 8 at 5 s each were over 10 s
    assert took < 2.0, f'{took:.1f} s'
    assert status['nodes'] == [] and status['matrix'] == {}
    assert sorted(status['unread']) == sorted(nodes)
    assert all('in time' in why for why in status['unread'].values()), status['unread']
    # only the first wave got a slot before the deadline: nobody else was asked
    assert len([c for c in pve.calls if c.endswith('/storage/local/content')]) <= m.SYNC_STATUS_WORKERS


def test_no_sync_status_request_waits_past_the_deadline(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    monkeypatch.setattr(PegaProxManager, 'SYNC_STATUS_DEADLINE', 0.6, raising=False)
    seen = _record_timeouts(monkeypatch)
    m, _ = _sync_mgr([f'pve{i}' for i in range(4)], _iso_answer())
    status = m.get_content_sync_status('iso')
    assert len(status['nodes']) == 4
    stores = [t for p, t in seen if p.endswith('/content')]
    lists = [t for p, t in seen if p.endswith('/storage')]
    assert len(stores) == 4 and len(lists) == 4, seen
    assert all(t is not None and 0 < t <= 0.6 for _, t in seen), seen


def test_the_backup_scan_deadline_holds_with_more_stores_than_workers(api, admin, monkeypatch):
    from pegaprox.api import clusters
    monkeypatch.setattr(clusters, '_SLA_DEADLINE', 0.8, raising=False)
    nodes = [f'pve{i}' for i in range(24)]
    _sla_cluster(api, nodes, _sla_answer(nodes, slow_store='local'))
    t0 = time.monotonic()
    r = admin.get(f'/api/clusters/{CLUSTER}/backup-sla')
    took = time.monotonic() - t0
    assert r.status_code == 200, r.get_data(as_text=True)
    # 25 stores, 8 at a time, the 24 local ones 5 s each: over 15 s before
    assert took < 2.5, f'{took:.1f} s'
    body = r.get_json()
    late = [u for u in body['unread'] if u['storage'] == 'local']
    assert len(late) == len(nodes), body['unread']
    assert all(u['error'] == 'did not answer in time' for u in late), late
    # the shared store got its slot first and was read
    assert _states(body)['100'] == 'ok'


def test_no_backup_scan_request_waits_past_the_deadline(api, admin, monkeypatch):
    from pegaprox.api import clusters
    monkeypatch.setattr(clusters, '_SLA_DEADLINE', 0.8, raising=False)
    monkeypatch.setattr(clusters, '_SLA_LIST_DEADLINE', 0.5, raising=False)
    nodes = ['pve1', 'pve2', 'pve3']
    seen = _record_timeouts(monkeypatch)
    _sla_cluster(api, nodes, _sla_answer(nodes))
    assert admin.get(f'/api/clusters/{CLUSTER}/backup-sla').status_code == 200
    stores = [t for p, t in seen if p.endswith('/content')]
    lists = [t for p, t in seen if p.endswith('/storage')]
    assert lists and all(0 < t <= 0.5 for t in lists), lists
    assert stores and all(isinstance(t, tuple) and all(0 < x <= 0.8 for x in t) for t in stores), stores


def test_a_whole_fan_out_ends_at_its_timeout_and_starts_nothing_after_it():
    import gevent
    from pegaprox.utils.concurrent import run_per_node
    started = []

    def job(n):
        started.append(n)
        gevent.sleep(1.0)
        return n
    t0 = time.monotonic()
    got = run_per_node({f'n{i}': job for i in range(24)}, max_concurrent=8, timeout=0.5, whole=True)
    took = time.monotonic() - t0
    assert took < 0.9, f'{took:.2f} s'
    assert len(started) == 8, started
    assert set(got) == {f'n{i}' for i in range(24)} and not any(got.values())
    gevent.sleep(0.7)   # the first wave ends; the 16 that waited for a slot still start nothing
    assert len(started) == 8, started


# --- b) the stores a confined caller learns about ----------------------------------------------------

def _scoped(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['backup.view', 'vm.view'])
    seed.vm_acl(CLUSTER, 100, users=['bob'])
    return api.as_user(bob)


def test_a_confined_caller_gets_the_count_of_unread_stores_without_names(api, seed, admin):
    nodes = ['pve1', 'pve2', 'pve3']
    _sla_cluster(api, nodes, _sla_answer(nodes, local_fails_on=('pve1', 'pve2')))
    r = _scoped(api, seed).get(f'/api/clusters/{CLUSTER}/backup-sla')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert [v['vmid'] for v in body['vms']] == ['100']
    assert len(body['unread']) == 2, body['unread']
    assert all(u['storage'] is None and u['node'] is None for u in body['unread']), body['unread']
    # counter-check: an unconfined caller keeps the names
    body = admin.get(f'/api/clusters/{CLUSTER}/backup-sla').get_json()
    assert sorted((u['storage'], u['node']) for u in body['unread']) == [('local', 'pve1'), ('local', 'pve2')]


# --- c) a lost cluster on the content and PCI routes ---------------------------------------------------

def test_a_content_read_that_got_no_answer_says_what_it_could_not_read(admin, pve):  # noqa: F811
    pve.answers[f'/nodes/{NODE}/storage/backup-nfs/content'] = requests.exceptions.ReadTimeout('slow')
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/backup-nfs/content?node={NODE}')
    assert r.status_code == 503, r.get_data(as_text=True)
    body = r.get_json()
    assert (body['code'], body['offline'], body['node'], body['storage']) == ('PVE_UNREACHABLE', True, NODE, 'backup-nfs')
    assert body['error'] == f'Cluster temporarily unreachable: could not read the content of storage backup-nfs on node {NODE}'


def test_a_content_read_whose_node_list_got_no_answer_says_so(admin, pve):  # noqa: F811
    pve.answers['/api2/json/nodes'] = requests.exceptions.ConnectTimeout('timed out')
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/local/content')
    assert r.status_code == 503, r.get_data(as_text=True)
    body = r.get_json()
    assert (body['code'], body['offline']) == ('PVE_UNREACHABLE', True)
    assert body['error'] == 'Cluster temporarily unreachable: could not read the nodes of this cluster'


def test_a_pci_read_that_got_no_answer_says_what_it_could_not_read(admin, pve):  # noqa: F811
    pve.answers[f'/nodes/{NODE}/hardware/pci'] = requests.exceptions.ConnectTimeout('timed out')
    r = admin.get(_url('hardware/pci'))
    assert r.status_code == 503, r.get_data(as_text=True)
    assert r.get_json()['error'] == f'Cluster temporarily unreachable: could not read the PCI devices of node {NODE}'


# --- d) the Ceph reads stay JSON -------------------------------------------------------------------------

@pytest.mark.parametrize('route', ['ceph/status', 'ceph/osd', 'ceph/pool', 'ceph/log'])
@pytest.mark.parametrize('exc', [requests.exceptions.ChunkedEncodingError('broken body'),
                                 requests.exceptions.TooManyRedirects('loop')])
def test_another_requests_error_of_a_ceph_read_is_unreachable(admin, pve, route, exc):  # noqa: F811
    pve.default = exc
    r = admin.get(_url(route))
    assert r.status_code == 503, (r.status_code, r.get_data(as_text=True)[:200])
    assert (r.get_json()['code'], r.get_json()['offline']) == ('PVE_UNREACHABLE', True)


@pytest.mark.parametrize('route', ['ceph/status', 'ceph/osd', 'ceph/mon'])
def test_a_ceph_read_whose_session_failed_is_a_json_error(admin, pve, route):  # noqa: F811
    from pegaprox.globals import cluster_managers

    def _broken():
        raise RuntimeError('login failed')
    cluster_managers[CLUSTER]._create_session = _broken
    r = admin.get(_url(route))
    assert r.status_code == 500, (r.status_code, r.get_data(as_text=True)[:200])
    assert r.is_json and r.get_json()['code'] == 'READ_FAILED'
    assert 'login failed' not in r.get_data(as_text=True)


# --- e) Corporate Redesigned is not called a preview, in no language ------------------------------------

# "this preview" / "the preview" as each language says it of the layout (an "Aperçu" alone is an
# overview in French, a "Vorschau" alone the preview of a move or a description)
_THIS_PREVIEW = {'en': r'\b(?:this|the) preview\b', 'de': r'\b(?:dieser|der) Vorschau\b', 'zh': '此预览',
                 'pl': r'\btym podglądzie\b', 'fr': r'\bcet aperçu\b', 'es': r'\besta vista previa\b',
                 'pt': r'\bnesta prévia\b|\besta prévia\b', 'ko': '이 미리보기', 'it': r'\bquesta anteprima\b',
                 'ru': r'\b(?:это[мт]?|данн\w+) (?:превью|предпросмотр\w*)'}
_PREVIEW_WORD = r'preview|Vorschau|预览|podgląd|aperçu|vista previa|prévia|미리보기|anteprima|превью|предпросмотр'


def _blocks():
    import re
    src = open('web/src/translations.js', encoding='utf-8').read()
    starts = sorted((m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M))
    assert [lang for _, lang in starts] == ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru'], starts
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))] for i, (pos, lang) in enumerate(starts)}


def test_the_file_system_footer_of_a_guest_calls_nothing_a_preview():
    import re
    for lang, block in _blocks().items():
        m = re.search(r'^\s+crVmFsFoot: (["\'])(.*)\1,$', block, re.M)
        assert m, lang
        text = m.group(2)
        assert not re.search(_PREVIEW_WORD, text, re.I), (lang, text)
        assert '{time}' in text and '70' in text and '85' in text, (lang, text)


def test_no_string_of_the_layout_calls_it_this_preview():
    import re
    hits = []
    for lang, block in _blocks().items():
        for m in re.finditer(r'^\s+(cr[A-Z]\w*): (["\'])(.*)\2,$', block, re.M):
            if re.search(_THIS_PREVIEW[lang], m.group(3), re.I):
                hits.append((lang, m.group(1), m.group(3)[:80]))
    assert hits == [], hits


def test_the_style_block_of_the_redesign_calls_it_no_preview():
    import re
    src = open('web/index.html.original', encoding='utf-8').read()
    start = src.index('LW Oct 2026 - Corporate Layout - Redesigned')
    block = src[start:src.index('</style>', start)]
    said = [c[:120] for c in re.findall(r'/\*.*?\*/', block, re.S) if re.search(r'\bpreview\b', c, re.I)]
    # the one left is the dialog of the hardening that previews its change
    assert [c for c in said if 'preview dialog' not in c] == [], said
    assert 'Every rule of the preview' not in src
