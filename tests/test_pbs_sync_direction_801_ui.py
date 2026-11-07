"""The PBS Jobs tab says which way a sync job goes (#801).

Since PBS 3.3 a sync job pulls into its local datastore or pushes out of it, and the
backend now lists both kinds with their sync-direction. The Jobs tab has a Direction column
and one Source -> Target column: a pull reads "remote / remote-store -> store", a push
"store -> remote / remote-store", a job without a remote syncs between two datastores of
the same PBS. Beside a datastore the Type of a sync row names its direction in one phrase
("Pull sync"), not the sync verb some languages use for the button next to it. Runtime tests
drive the built bundle against the fake server of tests/test_ha_ui.py, in every layout
that shows the PBS jobs (the Cloud layout lists the servers only).
"""
import os
import re

import pytest

from test_ha_ui import LANGS, PBS, _App, _FakeServer, _blocks, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ('pbsSyncDirection', 'pbsSyncPull', 'pbsSyncPush', 'pbsSyncPullJob', 'pbsSyncPushJob')

STORES = [
    {'name': 'local1', 'gc-schedule': 'daily', 'detail': {'gc-status': {}}},
    {'name': 'local2', 'gc-schedule': 'weekly', 'detail': {'gc-status': {}}},
]
JOBS = {
    'sync': [
        {'id': 'pull-offsite', 'store': 'local1', 'remote': 'offsite', 'remote-store': 'archive',
         'sync-direction': 'pull', 'schedule': 'daily', 'last-run-endtime': 1780000010,
         'last-run-state': 'OK'},
        {'id': 'push-dr', 'store': 'local1', 'remote': 'dr-site', 'remote-store': 'replica',
         'sync-direction': 'push', 'schedule': 'hourly'},
        {'id': 'pull-local', 'store': 'local2', 'remote-store': 'local1', 'sync-direction': 'pull'},
    ],
    'verify': [],
    'prune': [],
}
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, STORES),
    ('GET', '/api/pbs/p1/jobs'): (200, JOBS),
    ('POST', '/api/pbs/p1/jobs/sync/push-dr/run'): (200, {'data': 'UPID:pbs:00001234:0000ABCD:00000001:65000000:sync:push-dr:root@pam:'}),
}
LAYOUTS = ['modern', 'corporate', 'corporate-redesigned']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _added():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Nov 2026 - since PBS 3.3 a sync job pulls')
    return src[start:src.index('function PbsJobReadError(', start)]


def _sync_table():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index("{t('pbsSyncJobs') || 'Sync Jobs'} ({(pbsJobs.sync")
    return src[start:src.index("{t('pbsNoSyncJobsConfigured')", start)]


# -- source -------------------------------------------------------------------------------------

def test_the_new_keys_exist_once_per_language_and_are_translated():
    blocks = _blocks()
    english = {k: re.search(r'^ +%s: (.*),$' % k, blocks['en'], re.M).group(1) for k in KEYS}
    for lang, block in blocks.items():
        for key in KEYS:
            found = re.findall(r'^ +%s: (.*),$' % key, block, re.M)
            assert len(found) == 1, (lang, key)
            if lang != 'en':
                assert found[0] != english[key], (lang, key, found[0])
    for key in ('source', 'target'):
        assert all(re.search(r'^ +%s: ' % key, b, re.M) for b in blocks.values()), key


def test_the_sync_table_names_the_direction_and_both_ends():
    table = _sync_table()
    assert "t('pbsSyncDirection')" in table
    assert '<PbsSyncDirection direction={job[\'sync-direction\']} />' in table
    assert 'pbsSyncEnds(job)' in table
    # the old "remote / remote-store" cell read as a source for a push job as well
    assert "{job.remote || '-'} / {job['remote-store'] || '-'}" not in table


def test_no_dash_and_every_class_in_the_static_build():
    text = _added() + _sync_table()
    assert '\u2014' not in text and '\u2013' not in text
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    assert not sorted(n for n in _classes(text) if n not in have)


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function PbsSyncDirection(', 'function pbsSyncEnds(', 'data-pbs-sync-direction') + KEYS:
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

def _open_pbs(app, layout):
    page = app.page
    where = page.locator('.cr-sidebar') if layout == 'corporate-redesigned' else page
    where.get_by_text('backup01', exact=True).first.click()
    page.get_by_text('4.0').first.wait_for(timeout=5000)
    return page


def _row(page, job_id):
    return page.locator('tr').filter(has_text=job_id).first


def _cells(row):
    return [' '.join(c.inner_text().split()) for c in row.locator('td').all()]


@pytest.mark.parametrize('layout', LAYOUTS)
def test_the_jobs_tab_shows_each_direction_and_where_the_data_goes(browser, layout):
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=READS))
    try:
        page = _open_pbs(app, layout)
        page.get_by_role('button', name='Jobs').first.click()
        push = _row(page, 'push-dr')
        push.wait_for(timeout=5000)
        table = push.locator('xpath=ancestor::table[1]')
        headers = ' '.join(table.locator('thead').inner_text().split()).lower()
        assert 'direction' in headers and 'source → target' in headers

        pull, local = _row(page, 'pull-offsite'), _row(page, 'pull-local')
        assert _cells(push)[:3] == ['push-dr', 'Push', 'local1 → dr-site / replica']
        assert _cells(pull)[:3] == ['pull-offsite', 'Pull', 'offsite / archive → local1']
        assert _cells(local)[:3] == ['pull-local', 'Pull', 'local1 → local2']
        assert push.locator('[data-pbs-sync-direction]').get_attribute('data-pbs-sync-direction') == 'push'
        assert pull.locator('[data-pbs-sync-direction]').get_attribute('data-pbs-sync-direction') == 'pull'
        # the columns after it stay where they were
        assert _cells(push)[3] == 'hourly' and _cells(pull)[4] != '-'

        push.get_by_role('button', name='Run').click()
        page.get_by_text("sync job 'push-dr' started").wait_for(timeout=5000)
        assert ('POST', '/api/pbs/p1/jobs/sync/push-dr/run') in app.server.calls
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', LAYOUTS)
def test_beside_the_datastore_a_sync_row_says_its_direction(browser, layout):
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=READS))
    try:
        page = _open_pbs(app, layout)
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^local1\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="local1"]')
        table.wait_for(timeout=5000)
        sync = table.locator('[data-pbs-schedule-kind="sync"]')
        assert sync.count() == 2
        assert [_cells(r)[:2] for r in sync.all()] == [['Pull sync', 'pull-offsite'], ['Push sync', 'push-dr']]
        assert [r.locator('[data-pbs-sync-direction]').get_attribute('data-pbs-sync-direction')
                for r in sync.all()] == ['pull', 'push']
        # the GC row has no direction
        assert table.locator('[data-pbs-schedule-kind="gc"] [data-pbs-sync-direction]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_the_jobs_tab_in_german(browser):
    app = _App(browser, _FakeServer(role='standalone', layout='modern', language='de', extra=READS))
    try:
        page = _open_pbs(app, 'modern')
        page.get_by_role('button', name='Jobs').first.click()
        push = _row(page, 'push-dr')
        push.wait_for(timeout=5000)
        headers = ' '.join(push.locator('xpath=ancestor::table[1]').locator('thead').inner_text().split()).lower()
        assert 'richtung' in headers and 'quelle → ziel' in headers
        assert _cells(push)[1] == 'Senden'
        assert _cells(_row(page, 'pull-offsite'))[1] == 'Abrufen'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_beside_the_datastore_the_type_reads_as_one_phrase_in_spanish(browser):
    # es translates the sync button as a verb ("Sincronizar"), the Type has its own label
    app = _App(browser, _FakeServer(role='standalone', layout='modern', language='es', extra=READS))
    try:
        page = _open_pbs(app, 'modern')
        page.get_by_role('button', name='Datastores').first.click()
        page.get_by_role('button', name=re.compile(r'^local1\b')).click()
        table = page.locator('[data-pbs-datastore-schedules="local1"]')
        table.wait_for(timeout=5000)
        sync = table.locator('[data-pbs-schedule-kind="sync"]')
        assert [_cells(r)[0] for r in sync.all()] == ['Sincronización (recepción)', 'Sincronización (envío)']
        assert 'Sincronizar' not in table.inner_text()
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
