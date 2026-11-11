"""A datacenter status that Proxmox did not give is not an empty standalone node.

GET /api/clusters/<id>/datacenter/status reads /cluster/status and /cluster/resources. When
one of them came back with anything but 200 (a 401 after the ticket ran out, a 403 for a
token without Sys.Audit, a 500 from pmxcfs), its list was taken as empty and the route
answered 200 with zero nodes, zero guests, 0 % everywhere and standalone: true. The All
Clusters overview, the cluster group view, the Cloud cards, the Corporate services bar and
the classic Datacenter summary all showed that as the real state of the cluster, with a
fresh "updated" time. A read that failed answers 502 now, and every poller keeps what it had.
The classic Datacenter summary, which kept whatever it had shown last (another cluster's
figures after a switch), says the status was not read.

A status list with several nodes and no cluster entry is incomplete too, and the 502 carries
what Proxmox answered (upstream_status, code UPSTREAM_AUTH for its 401/403). On the overviews a
cluster that was never read shows no figures and no health and stays out of the averages, the
Corporate services bar shows "-" for its quorum instead of a guess, and a 502 that names the
unread reads does not back the poll off.

The runtime tests feed what this route answers into the built bundle (headless Chromium,
the fake server of tests/test_ha_ui.py) and skip where Playwright is not installed.
"""
import os
import types

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401
from test_storage_totals_leave_backups_out_1159 import METRICS as NODE_ROWS

CID = 'c1'
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
GiB = 1024 ** 3

NODES = [{'id': f'node/{n}', 'type': 'node', 'node': n, 'status': 'online',
          'maxcpu': 8, 'cpu': 0.25, 'maxmem': 64 * GiB, 'mem': 16 * GiB} for n in ('pve1', 'pve2')]
GUESTS = [{'id': 'qemu/100', 'type': 'qemu', 'vmid': 100, 'node': 'pve1', 'status': 'running'},
          {'id': 'qemu/101', 'type': 'qemu', 'vmid': 101, 'node': 'pve2', 'status': 'stopped'},
          {'id': 'lxc/200', 'type': 'lxc', 'vmid': 200, 'node': 'pve1', 'status': 'running'}]
STORAGE = [{'id': 'storage/pve1/local-lvm', 'type': 'storage', 'node': 'pve1', 'storage': 'local-lvm',
            'status': 'available', 'plugintype': 'lvmthin', 'shared': 0, 'content': 'images,rootdir',
            'disk': 50 * GiB, 'maxdisk': 200 * GiB}]
CLUSTER_STATUS = [{'type': 'cluster', 'name': 'Testi', 'quorate': 1, 'version': 4},
                  {'type': 'node', 'name': 'pve1', 'online': 1},
                  {'type': 'node', 'name': 'pve2', 'online': 1}]
RESOURCES = NODES + GUESTS + STORAGE


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class _Session:
    def __init__(self, answers):
        self.answers = answers

    def get(self, url, timeout=None, **kw):
        answer = self.answers[url.split('/api2/json', 1)[1]]
        if isinstance(answer, Exception):
            raise answer
        return answer


class _Pve:
    host, api_port, cluster_type = 'pve.example', 8006, 'proxmox'
    is_connected = True

    def __init__(self, status=None, resources=None):
        self.config = types.SimpleNamespace(name='Testi')
        self.answers = {
            '/cluster/status': status if status is not None else _Resp(200, {'data': CLUSTER_STATUS}),
            '/cluster/resources': resources if resources is not None else _Resp(200, {'data': RESOURCES}),
        }
        self.cold, self.reconnects = [], 0

    def _create_session(self):
        return _Session(self.answers)

    def _mark_host_failure(self, host):
        self.cold.append(host)

    def connect_to_proxmox(self):
        self.reconnects += 1


def _get(api, seed, manager, cid=CID):
    api.set_manager(cid, manager)
    return api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{cid}/datacenter/status')


def _refused(code, message=None):
    return _Resp(code, {'data': None, 'message': message or f'error {code}'})


def test_a_normal_answer_is_read_as_it_was_given(api, seed):
    pve = _Pve()
    r = _get(api, seed, pve)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['cluster'] == {'name': 'Testi', 'quorate': True, 'standalone': False, 'version': 4}
    assert body['nodes'] == {'online': 2, 'offline': 0, 'total': 2}
    assert body['guests']['vms'] == {'running': 1, 'stopped': 1, 'total': 2}
    assert body['guests']['containers'] == {'running': 1, 'stopped': 0, 'total': 1}
    assert body['resources']['cpu'] == {'total': 16, 'used': 4.0, 'percent': 25.0}
    assert body['resources']['storage']['total'] == 200 * GiB
    assert pve.cold == [] and pve.reconnects == 0


@pytest.mark.parametrize('code', [401, 403, 500, 596])
def test_a_cluster_status_proxmox_refused_is_no_standalone_node(api, seed, code):
    pve = _Pve(status=_refused(code))
    r = _get(api, seed, pve)
    body = r.get_json()
    assert r.status_code == 502, body
    assert 'cluster/status' in body['error'] and str(code) in body['error']
    # nothing of the answer can be taken for the cluster: no zeros, no standalone
    assert 'cluster' not in body and 'nodes' not in body and 'guests' not in body
    assert body['unread'] == ['cluster/status']


@pytest.mark.parametrize('code', [401, 403, 500])
def test_cluster_resources_proxmox_refused_are_no_empty_cluster(api, seed, code):
    pve = _Pve(resources=_refused(code))
    r = _get(api, seed, pve)
    body = r.get_json()
    assert r.status_code == 502, body
    assert 'cluster/resources' in body['error'] and str(code) in body['error']
    assert 'guests' not in body and 'resources' not in body and 'nodes' not in body
    assert body['unread'] == ['cluster/resources']


def test_both_reads_refused_name_both(api, seed):
    r = _get(api, seed, _Pve(status=_refused(500), resources=_refused(403)))
    body = r.get_json()
    assert r.status_code == 502, body
    assert body['unread'] == ['cluster/status', 'cluster/resources']
    assert '500' in body['error'] and '403' in body['error']


def test_a_status_list_without_any_node_is_not_read_as_standalone(api, seed):
    # a 200 whose list names no node at all is no answer about this cluster either
    for data in ({'data': []}, {'data': None}, {}):
        r = _get(api, seed, _Pve(status=_Resp(200, data)))
        body = r.get_json()
        assert r.status_code == 502, (data, body)
        assert 'cluster' not in body and body['unread'] == ['cluster/status']


def test_several_nodes_without_a_cluster_entry_are_no_standalone_node(api, seed):
    # rolling_runs.quorum_facts reads the same list as status_incomplete: the entry that
    # carries the name and the quorum is missing, so there is nothing to say about either
    nodes_only = [s for s in CLUSTER_STATUS if s['type'] == 'node']
    r = _get(api, seed, _Pve(status=_Resp(200, {'data': nodes_only})))
    body = r.get_json()
    assert r.status_code == 502, body
    assert body['unread'] == ['cluster/status']
    assert 'cluster/status (several nodes but no cluster entry)' in body['error']
    assert 'cluster' not in body and 'nodes' not in body and 'guests' not in body


@pytest.mark.parametrize('status, resources, upstream, code', [
    (_refused(401), None, 401, 'UPSTREAM_AUTH'),
    (_refused(403), None, 403, 'UPSTREAM_AUTH'),
    (_refused(500), None, 500, None),
    (None, _refused(596), 596, None),
    (None, _refused(401), 401, 'UPSTREAM_AUTH'),
    # the refused credentials are what the admin has to fix, whichever read they came with
    (_refused(500), _refused(403), 403, 'UPSTREAM_AUTH'),
    (_Resp(200, {'data': []}), _refused(500), 500, None),
    # Proxmox answered, with a list that said too little
    (_Resp(200, {'data': []}), None, 200, None),
])
def test_the_502_says_what_proxmox_answered(api, seed, status, resources, upstream, code):
    r = _get(api, seed, _Pve(status=status, resources=resources))
    body = r.get_json()
    # still a 502 for every one of them: a Proxmox 401 is no lost PegaProx session (#1142)
    assert r.status_code == 502, body
    assert body['upstream_status'] == upstream, body
    assert body.get('code') == code, body
    assert body['error'].startswith('Proxmox did not answer ')


def test_a_sub_read_that_raises_is_unreachable_and_rolls_over_to_another_host(api, seed):
    import requests
    for which in ('status', 'resources'):
        pve = _Pve(**{which: requests.exceptions.ConnectionError('refused')})
        r = _get(api, seed, pve)
        body = r.get_json()
        assert r.status_code == 503 and body['offline'] is True, body
        assert 'cluster' not in body and 'nodes' not in body
        assert pve.cold == ['pve.example'] and pve.reconnects == 1


def test_an_answer_that_is_no_json_is_an_error_not_a_cluster(api, seed):
    r = _get(api, seed, _Pve(resources=_Resp(200, ValueError('Expecting value'))))
    assert r.status_code == 500
    assert 'cluster' not in r.get_json()


def test_a_real_standalone_node_is_still_standalone(api, seed):
    status = [{'type': 'node', 'name': 'pve-solo', 'online': 1, 'local': 1}]
    resources = [dict(NODES[0], id='node/pve-solo', node='pve-solo')] + [GUESTS[0]] + STORAGE
    r = _get(api, seed, _Pve(status=_Resp(200, {'data': status}), resources=_Resp(200, {'data': resources})))
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['cluster'] == {'name': 'pve-solo', 'quorate': None, 'standalone': True, 'version': 0}
    assert body['nodes'] == {'online': 1, 'offline': 0, 'total': 1}
    assert body['guests']['vms'] == {'running': 1, 'stopped': 0, 'total': 1}


def test_a_cluster_with_an_offline_node_counts_it(api, seed):
    status = CLUSTER_STATUS[:2] + [{'type': 'node', 'name': 'pve2', 'online': 0}]
    r = _get(api, seed, _Pve(status=_Resp(200, {'data': status})))
    assert r.status_code == 200
    assert r.get_json()['nodes'] == {'online': 1, 'offline': 1, 'total': 2}
    assert r.get_json()['cluster']['standalone'] is False


# --- runtime: what the pages make of the answer -------------------------------------------------

BRANCH = dict(CLUSTER, id='c2', name='Branch', display_name='Branch', host='10.0.0.2')
NOT_READ = 'The cluster status could not be read. No figures are shown until a read succeeds.'


def _dc(cid):
    return ('GET', f'/api/clusters/{cid}/datacenter/status')


@pytest.fixture
def answers(api, seed):
    """What the route answers for a cluster PVE gave its status and for one it refused it to."""
    def _one(pve, cid):
        r = _get(api, seed, pve, cid)
        return r.status_code, r.get_json()
    ok = _one(_Pve(), 'c1')
    refused = _one(_Pve(status=_refused(403)), 'c2')
    assert ok[0] == 200, ok
    return {'ok': ok, 'refused': refused}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(status, clusters=(CLUSTER,), clock=False, also=None, **kw):
        extra = dict(SSE_TOKEN)
        extra.update(also or {})
        extra.update({_dc(cid): answer for cid, answer in status.items()})
        app = _App(browser, _FakeServer(role='standalone', clusters=list(clusters), resources=[VM],
                                        extra=extra, **kw), clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _summary(app, layout, cluster='Testi'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text=cluster).first.click()
    else:
        page.get_by_text(cluster).first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.wait_for_function('() => !document.body.innerText.includes("Loading datacenter data")', timeout=10000)
    page.wait_for_timeout(300)
    return page


def _calls(app, cid):
    return [c for c in app.server.calls if c == _dc(cid)]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_datacenter_summary_shows_a_read_status(open_app, answers, layout):
    app = open_app({'c1': answers['ok']}, layout=layout)
    page = _summary(app, layout)
    page.get_by_text('Testi | Quorate: Yes').first.wait_for(timeout=5000)
    assert page.get_by_text(NOT_READ).count() == 0
    _shot(page, f'dc_summary_ok_{layout}.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_datacenter_summary_says_a_status_was_not_read(open_app, answers, layout):
    app = open_app({'c1': answers['refused']}, layout=layout)
    page = _summary(app, layout)
    page.get_by_text(NOT_READ).first.wait_for(timeout=5000)
    text = page.locator('body').inner_text()
    assert 'Proxmox did not answer cluster/status (HTTP 403)' in text
    assert 'Standalone Node' not in text and 'Quorate:' not in text
    _shot(page, f'dc_summary_refused_{layout}.png')
    assert _calls(app, 'c1') and not app.errors, app.errors


def test_runtime_a_switch_to_a_cluster_whose_status_failed_shows_none_of_the_last_one(open_app, answers):
    app = open_app({'c1': answers['ok'], 'c2': answers['refused']}, clusters=(CLUSTER, BRANCH), layout='modern')
    page = _summary(app, 'modern')
    page.get_by_text('Testi | Quorate: Yes').first.wait_for(timeout=5000)
    before = len(_calls(app, 'c2'))
    page.get_by_text('Branch').first.click()
    page.wait_for_function(f'() => document.body.innerText.includes({NOT_READ!r})', timeout=10000)
    assert len(_calls(app, 'c2')) > before
    text = page.locator('body').inner_text()
    assert 'Testi | Quorate: Yes' not in text and 'Standalone Node' not in text
    _shot(page, 'dc_summary_switched.png')
    assert not app.errors, app.errors


CARD_JS = '''(name) => {
    // the card of a cluster on All Clusters (the sidebar has an h3 with the name too)
    const card = Array.from(document.querySelectorAll('h3'))
        .filter(x => x.textContent.trim() === name).map(x => x.closest('.group'))
        .find(c => c && c.innerText.includes('Updated:'));
    if (!card) return null;
    const grid = card.querySelector('.grid-cols-5');
    return {nodes: grid ? grid.querySelector('.text-xl').textContent.trim() : null, text: card.innerText};
}'''


def _card(page):
    return page.evaluate(CARD_JS, 'Testi')


def test_runtime_a_failed_poll_keeps_the_last_reading_on_all_clusters(open_app, answers):
    app = open_app({'c1': answers['ok']}, layout='modern', clock=True)
    page = app.page
    page.wait_for_function(f'() => {{ const c = ({CARD_JS})("Testi"); return c && c.nodes === "2/2"; }}',
                           timeout=10000)
    # the next poll finds the status refused
    app.server.extra[_dc('c1')] = answers['refused']
    before = len(_calls(app, 'c1'))
    page.clock.run_for(31000)
    deadline = 40
    while len(_calls(app, 'c1')) == before and deadline:
        page.wait_for_timeout(250)
        deadline -= 1
    assert len(_calls(app, 'c1')) > before, 'no second status poll'
    page.wait_for_timeout(500)
    card = _card(page)
    assert card['nodes'] == '2/2', card
    assert 'just now' not in card['text'], card['text']
    assert 'Standalone' not in page.locator('body').inner_text()
    _shot(page, 'all_clusters_after_failed_poll.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_status_never_read_is_nowhere_a_standalone_node(open_app, answers, layout):
    app = open_app({'c1': answers['refused']}, layout=layout, metrics=NODE_ROWS)
    page = app.page
    deadline = 40
    while not _calls(app, 'c1') and deadline:
        page.wait_for_timeout(250)
        deadline -= 1
    assert _calls(app, 'c1'), 'the overview did not poll the status'
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('.corp-services-bar').wait_for(timeout=8000)
        page.wait_for_function('() => document.querySelector(".corp-services-bar").innerText.includes("2/2")',
                               timeout=8000)
        bar = page.locator('.corp-services-bar').inner_text()
        # without a status there is no quorum to show: no guess from the node rows, a "-"
        assert 'Standalone' not in bar and 'Quorum OK' not in bar and 'No quorum' not in bar, bar
        assert page.locator('.corp-services-bar .corp-quorum-unread').inner_text().strip() == '-'
    elif layout == 'cloud':
        page.locator('.cloud-shell').get_by_text('Clusters', exact=True).first.click()
        page.locator('.cloud-cluster-card').first.wait_for(timeout=8000)
        card = page.locator('.cloud-cluster-card').first.inner_text()
        assert 'Standalone' not in card, card
    else:
        page.wait_for_function(f'() => ({CARD_JS})("Testi")', timeout=8000)
        card = _card(page)
        # nothing was read: no figures and no health badge, the card says there is no data
        # and that it was never updated
        assert card['nodes'] is None and 'No data available' in card['text'], card
        assert '%' not in card['text'] and 'Updated: -' in card['text'], card['text']
    page.wait_for_timeout(300)
    assert 'Standalone' not in page.locator('body').inner_text()
    _shot(page, f'never_read_{layout}.png')
    assert not app.errors, app.errors


def test_runtime_a_read_status_still_reaches_every_view(open_app, answers):
    app = open_app({'c1': answers['ok']}, layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => { const b = document.querySelector(".corp-services-bar"); '
                           'return b && b.innerText.includes("Quorum OK"); }', timeout=10000)
    assert not app.errors, app.errors


def test_runtime_a_read_status_without_quorate_keeps_the_node_row_guess(open_app, answers):
    # an XCP-ng pool answers a status with quorate None: read, so the bar guesses from the
    # node rows as it always did; only a status that is missing shows "-"
    code, body = answers['ok']
    body = dict(body, cluster={'name': 'Testi', 'quorate': None, 'standalone': False, 'version': 0})
    app = open_app({'c1': (code, body)}, layout='corporate', metrics=NODE_ROWS)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function('() => { const b = document.querySelector(".corp-services-bar"); '
                           'return b && b.innerText.includes("Quorum OK"); }', timeout=10000)
    assert page.locator('.corp-services-bar .corp-quorum-unread').count() == 0
    assert not app.errors, app.errors


GROUPS = [{'id': 'g1', 'name': 'Production', 'color': '#E86F2D', 'sort_order': 0, 'collapsed': 0}]

# the CPU and RAM averages over the clusters: the gauges of Modern, the stats bar of Corporate
AVERAGES_JS = '''() => {
    const out = {};
    for (const lbl of document.querySelectorAll('div.text-sm.font-bold.text-white')) {
        const sub = lbl.nextElementSibling;
        if (!sub || sub.textContent.trim() !== 'Average') continue;
        const v = lbl.closest('.rounded-xl') && lbl.closest('.rounded-xl').querySelector('span.text-xs.font-bold');
        if (v) out[lbl.textContent.trim()] = v.textContent.trim();
    }
    if (!Object.keys(out).length) {
        const text = document.body.innerText;
        for (const k of ['CPU', 'RAM']) {
            const m = text.match(new RegExp(k + ': (\\\\d+)%'));
            if (m) out[k] = m[1] + '%';
        }
    }
    return out;
}'''

# a cluster on the overview: its card (Modern) or its table row (Corporate)
ENTRY_JS = '''([name, layout]) => {
    if (layout === 'corporate') {
        const row = Array.from(document.querySelectorAll('table.corp-datagrid tr'))
            .find(r => r.cells.length && r.cells[0].textContent.trim() === name);
        return row ? {text: row.innerText, figures: row.cells.length > 3} : null;
    }
    const card = Array.from(document.querySelectorAll('h3'))
        .filter(x => x.textContent.trim() === name).map(x => x.closest('.group'))
        .find(c => c && c.innerText.includes('Updated:'));
    return card ? {text: card.innerText, figures: !!card.querySelector('.grid-cols-5')} : null;
}'''


@pytest.mark.parametrize('view', ['all', 'group'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_cluster_never_read_has_no_figures_and_no_share_in_the_averages(open_app, answers, layout, view):
    clusters = (dict(CLUSTER, group_id='g1'), dict(BRANCH, group_id='g1'))
    app = open_app({'c1': answers['ok'], 'c2': answers['refused']}, clusters=clusters, layout=layout,
                   also={('GET', '/api/cluster-groups'): (200, GROUPS)})
    page = app.page
    if view == 'group':
        page.locator('button', has_text='Production').first.click()
    page.wait_for_function(f'() => {{ const e = ({ENTRY_JS})(["Testi", {layout!r}]); '
                           f'return e && e.text.includes("2/2"); }}', timeout=10000)
    assert _calls(app, 'c2'), 'the overview did not poll the refused cluster'
    page.wait_for_timeout(300)
    # the group overview has the group's name as its title (h1 Modern, h2 Corporate), All Clusters
    # names it at most in an h3 over its cards
    assert (page.locator('h1, h2', has_text='Production').count() > 0) == (view == 'group')
    branch = page.evaluate(ENTRY_JS, ['Branch', layout])
    assert branch and not branch['figures'], branch
    assert 'No data available' in branch['text'], branch['text']
    # no 0/0, no 0 %, no green 100 % health
    assert '%' not in branch['text'] and '0/0' not in branch['text'], branch['text']
    testi = page.evaluate(ENTRY_JS, ['Testi', layout])
    assert testi['figures'] and '25%' in testi['text'], testi
    # the average is the one cluster that was read (25 %), not half of it
    averages = page.evaluate(AVERAGES_JS)
    assert averages.get('CPU') == '25%' and averages.get('RAM') == '25%', averages
    _shot(page, f'never_read_{view}_{layout}.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('kind', ['unread', 'other'])
def test_runtime_a_read_proxmox_refused_does_not_back_the_poll_off(open_app, answers, kind):
    # a 502 that names the unread reads came straight back; any other 502 still backs off
    failed = answers['refused'] if kind == 'unread' else (502, {'error': 'Bad gateway'})
    app = open_app({'c1': failed}, layout='modern', clock=True)
    page = app.page
    listing, guests = ('GET', '/api/clusters'), ('GET', '/api/clusters/c1/resources')
    deadline = 40
    while not _calls(app, 'c1') and deadline:
        page.wait_for_timeout(250)
        deadline -= 1
    page.wait_for_timeout(700)
    polls, reads = len(_calls(app, 'c1')), app.server.calls.count(guests)
    rounds = 6
    for _ in range(rounds):
        before = app.server.calls.count(listing)
        page.clock.run_for(31000)
        deadline = 40
        while app.server.calls.count(listing) == before and deadline:
            page.wait_for_timeout(250)
            deadline -= 1
        assert app.server.calls.count(listing) > before, 'no poll round'
        page.wait_for_timeout(700)
    polled = len(_calls(app, 'c1')) - polls
    if kind == 'unread':
        assert polled == rounds, polled
        # and its guests were read every round, so Top Guests never drops them
        assert app.server.calls.count(guests) - reads == rounds
    else:
        assert polled < rounds, polled
    assert not app.errors, app.errors
