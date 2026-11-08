"""The sponsor logo heal is not an open outbound fetcher (#1045).

/images/sponsors/<name> needs no login. When the file was missing, any name matching
sponsor*.png|svg|... cost two outbound fetches (8 s timeout each) while holding a
request slot, and left an entry in a miss cache nothing ever trimmed. Where egress is
dropped, a few requests a second fill the pool; the cache grows with every new name.

Only the names the footer asks for (sponsor1.png to sponsor8.png) are healed now, and
one fetch runs at a time: a request that finds one running gets the 404 it would have
got anyway.
"""
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.api.settings as settings_api


@pytest.fixture
def heal(monkeypatch, tmp_path):
    """No file on disk, an empty miss cache, and a counted stand-in for the network."""
    monkeypatch.setattr(settings_api, 'IMAGES_DIR', str(tmp_path))
    monkeypatch.setattr(settings_api, '_sponsor_heal_misses', {})
    monkeypatch.setattr(settings_api, '_sponsor_mem_cache', {})
    calls = []

    def _get(url, timeout=None):
        calls.append(url)
        return MagicMock(status_code=404, content=b'', headers={})
    monkeypatch.setattr(settings_api.requests, 'get', _get)
    return calls


def test_a_name_the_footer_never_asks_for_is_not_fetched(api, heal):
    for i in range(40):
        assert api.anon().get(f'/images/sponsors/sponsor-x{i}.png').status_code == 404
    assert heal == [], f'{len(heal)} outbound fetches for 40 made-up names'


def test_the_miss_cache_stays_small_whatever_is_asked(api, heal):
    for i in range(40):
        api.anon().get(f'/images/sponsors/sponsor{i}a.svg')
        api.anon().get(f'/images/sponsors/sponsor{i}.png')
    held = len(settings_api._sponsor_heal_misses)
    assert held <= 8, f'80 names left {held} miss entries behind'


def test_a_missing_footer_logo_is_still_healed(api, heal, monkeypatch, tmp_path):
    png = b'\x89PNG\r\n\x1a\n' + b'0' * 32
    monkeypatch.setattr(settings_api.requests, 'get',
                        lambda url, timeout=None: (heal.append(url), MagicMock(
                            status_code=200, content=png, headers={'Content-Type': 'image/png'}))[1])
    r = api.anon().get('/images/sponsors/sponsor7.png')
    assert r.status_code == 200 and r.data == png
    assert (tmp_path / 'sponsors' / 'sponsor7.png').read_bytes() == png
    assert len(heal) == 1


def test_a_known_miss_is_asked_again_only_after_ten_minutes(api, heal):
    api.anon().get('/images/sponsors/sponsor8.png')
    api.anon().get('/images/sponsors/sponsor8.png')
    assert len(heal) == 2, heal      # mirror + GitHub once, then the miss holds


def test_only_one_fetch_runs_at_a_time(heal, monkeypatch):
    state = {'now': 0, 'peak': 0}
    release = threading.Event()

    def _slow(url, timeout=None):
        state['now'] += 1
        state['peak'] = max(state['peak'], state['now'])
        release.wait(5)
        state['now'] -= 1
        return MagicMock(status_code=404, content=b'', headers={})
    monkeypatch.setattr(settings_api.requests, 'get', _slow)

    first = threading.Thread(target=settings_api._get_healed_sponsor, args=('sponsors/sponsor6.png',))
    first.start()
    deadline = time.time() + 5
    while state['now'] == 0 and time.time() < deadline:
        time.sleep(0.01)
    second = threading.Thread(target=settings_api._get_healed_sponsor, args=('sponsors/sponsor7.png',))
    second.start()
    second.join(0.5)
    peak = state['peak']
    release.set()
    first.join(5)
    second.join(5)
    assert peak == 1, f'{peak} heal fetches were in flight at once'
