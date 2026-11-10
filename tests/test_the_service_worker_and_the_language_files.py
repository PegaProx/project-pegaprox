"""The service worker (web/sw.js) and the language files of the page.

The worker caches what the page loads, network first, and answers from that cache offline. Since
every language but English is /i18n/<lang>.json?v=<hash of the build>, its cache name went to v4,
so the copy of a page that still carried every language goes. A language file is cached by its
full URL, the newest build of each language only, and offline it is that very file or nothing:
the page then reads English instead of getting the page itself as its language.

Runs sw.js in node with the worker globals stood in for (skipped without node).
LW Nov 2026
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')

DRIVE = r"""
const vm = require('vm'), fs = require('fs');
const ORIGIN = 'https://pegaprox.test';
const store = new Map();
const cacheOf = (name) => {
  if (!store.has(name)) store.set(name, new Map());
  const m = store.get(name);
  return {
    put: async (req, resp) => { m.set(req.url, resp); },
    add: async (u) => { m.set(ORIGIN + u, { body: 'precached ' + u }); },
    keys: async () => [...m.keys()].map(url => ({ url })),
    delete: async (k) => m.delete(k.url),
  };
};
const caches = {
  open: async (name) => cacheOf(name),
  keys: async () => [...store.keys()],
  delete: async (name) => store.delete(name),
  match: async (req) => {
    const url = typeof req === 'string' ? ORIGIN + req : req.url;
    for (const m of store.values()) if (m.has(url)) return m.get(url);
    return undefined;
  },
};
let online = true;
const fetch = async (req) => {
  if (!online) throw new TypeError('Failed to fetch');
  return { ok: true, type: 'basic', body: 'net ' + req.url.slice(ORIGIN.length), clone() { return this; } };
};
const listeners = {};
const self = { location: { origin: ORIGIN }, addEventListener: (t, fn) => { listeners[t] = fn; },
               skipWaiting() {}, clients: { claim: async () => {} }, registration: {} };
const settle = () => new Promise(r => setTimeout(r, 20));
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'),
                   { self, caches, fetch, URL, Promise, console, setTimeout, clients: self.clients,
                     Response: { error: () => ({ error: true }) } });

async function get(path) {
  let answer;
  listeners.fetch({ request: { url: ORIGIN + path, method: 'GET' }, respondWith: p => { answer = p; } });
  const r = await answer;
  await settle();
  return r && (r.error ? 'network error' : r.body);
}

(async () => {
  const out = {};
  // a browser that ran the worker before: its cache holds the page of an older build
  await cacheOf('pegaprox-shell-v3').put({ url: ORIGIN + '/' }, { body: 'old page with every language' });
  let wait;
  listeners.activate({ waitUntil: p => { wait = p; } });
  await wait;
  out.cachesAfterActivate = [...store.keys()];

  await get('/i18n/de.json?v=1111111111111111');
  await get('/i18n/fr.json?v=2222222222222222');
  await get('/i18n/de.json?v=3333333333333333');
  await get('/');
  out.cached = [...store.values()].flatMap(m => [...m.keys()]).map(u => u.slice(ORIGIN.length)).sort();

  online = false;
  out.offline = {
    sameBuild: await get('/i18n/de.json?v=3333333333333333'),
    otherBuild: await get('/i18n/de.json?v=1111111111111111'),
    neverLoaded: await get('/i18n/it.json?v=4444444444444444'),
    page: await get('/'),
    staticMissing: await get('/static/js/none.js'),
  };
  process.stdout.write(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""


@pytest.fixture(scope='module')
def run():
    out = subprocess.run([shutil.which('node'), '-e', DRIVE, os.path.join(ROOT, 'web', 'sw.js')],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def test_the_cache_of_the_page_with_every_language_goes(run):
    assert 'pegaprox-shell-v3' not in run['cachesAfterActivate']


def test_each_language_keeps_the_newest_build_only(run):
    langs = [u for u in run['cached'] if u.startswith('/i18n/')]
    assert langs == ['/i18n/de.json?v=3333333333333333', '/i18n/fr.json?v=2222222222222222'], run['cached']
    assert '/' in run['cached']


def test_offline_a_language_file_is_that_very_file_or_nothing(run):
    off = run['offline']
    assert off['sameBuild'] == 'net /i18n/de.json?v=3333333333333333'
    # never another build's file, never the page in place of a language
    assert off['otherBuild'] == 'network error'
    assert off['neverLoaded'] == 'network error'
    # the rest stays as it was: the page from the cache, the page for what is not there
    assert off['page'] == 'net /'
    assert off['staticMissing'] == 'net /'
