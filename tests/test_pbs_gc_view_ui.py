"""The PBS GC card and dedup factor show what PBS sends, in the built bundle.

gc-status (from the usage list) has the counters of the last run, gc-job (from /admin/gc)
when it ran. PBS has no dedup factor field: it is the index size over the bytes on disk.
"""

import re

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


END = 1780000000
STORES = [
    {'name': 'alpha', 'total': 1000, 'used': 400, 'avail': 600,
     'gc-status': {'upid': 'UPID:pbs:0000:0000:0000:6A1B2C00:garbage_collection:alpha:root@pam:',
                   'index-data-bytes': 3500, 'disk-bytes': 1000, 'disk-chunks': 12},
     # PBS writes the task state as it prints it: OK, WARNINGS: n, or the error
     'gc-job': {'store': 'alpha', 'last-run-endtime': END, 'last-run-state': 'OK', 'duration': 75},
     'detail': {}},
    {'name': 'beta', 'total': 1000, 'used': 100, 'avail': 900,
     'gc-job': {'store': 'beta', 'last-run-endtime': END, 'last-run-state': 'TASK ERROR: out of space'},
     'detail': {}},
    {'name': 'gamma', 'total': 1000, 'used': 10, 'avail': 990, 'detail': {}},
]
READS = {
    ('GET', '/api/pbs'): (200, [PBS]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, STORES),
}


def _open_store(page, name):
    page.get_by_text('backup01').first.click()
    page.get_by_role('button', name='Datastores').first.click()
    page.get_by_role('button', name=re.compile(rf'^{name}\b')).click()


def _gc_card(page):
    card = page.locator('div.rounded-xl').filter(has_text='Garbage Collection').filter(has_text='Last GC').last
    card.wait_for(timeout=5000)
    return card.inner_text()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_the_gc_card_shows_the_last_run_and_the_dedup_factor(browser, layout):
    app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=READS))
    try:
        page = app.page
        _open_store(page, 'alpha')
        text = _gc_card(page)
        last = re.search(r'Last GC:\s*(.+)', text).group(1).strip()
        assert last != '-' and re.search(r'\d', last), text
        assert '1m 15s' in text
        assert '3.50x' in text
        assert 'TASK ERROR' not in text
        # a run that went fine is not a status line of its own
        assert 'Status' not in text and 'OK' not in text
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_a_failed_gc_run_says_why(browser):
    app = _App(browser, _FakeServer(role='standalone', extra=READS))
    try:
        page = app.page
        _open_store(page, 'beta')
        text = _gc_card(page)
        assert 'TASK ERROR: out of space' in text
        # no counters from PBS: no made-up factor of 1, no zero chunks
        assert '1.00x' not in text
        assert 'Disk Chunks' not in text and 'Disk Bytes' not in text
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_a_store_without_gc_history_shows_no_card(browser):
    app = _App(browser, _FakeServer(role='standalone', extra=READS))
    try:
        page = app.page
        _open_store(page, 'gamma')
        page.wait_for_timeout(500)
        assert page.locator('div.rounded-xl').filter(has_text='Last GC').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_the_datastore_cards_show_the_dedup_factor(browser):
    app = _App(browser, _FakeServer(role='standalone', extra=READS))
    try:
        page = app.page
        page.get_by_text('backup01').first.click()
        page.get_by_text('3.50x').first.wait_for(timeout=5000)
        assert page.get_by_text('1.00x').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
