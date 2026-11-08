"""The cloud-init image catalog, and the check that keeps it from going stale.

The catalog links straight to distribution mirrors. When a release reaches end of life
it leaves them, and the entry keeps sitting in the list: Fedora 40 had been answering
404 long before anyone noticed, Debian 11 and Alpine 3.19 were still offered past their
end of support. scripts/check_image_catalog.py HEADs every image and fails on a dead URL
or a passed eol date; a weekly workflow runs it against the real mirrors.

These tests stay offline: the catalog's shape, the script reading the very list the app
serves, the probe's behaviour against a local HTTP server, and the library rendering the
list in the browser (headless Chromium, the fake server of test_ha_ui.py). MK
"""
import contextlib
import datetime
import http.server
import importlib.util
import os
import re
import threading

import pytest

import pegaprox.api.templates_lib as tpl
from test_ha_ui import CLUSTER, VM, _App, _FakeServer, browser  # noqa: F401  (browser is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        'check_image_catalog', os.path.join(ROOT, 'scripts', 'check_image_catalog.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chk = _load_checker()


# --- the catalog itself ------------------------------------------------------------

_REQUIRED = ('id', 'name', 'distro', 'version', 'image_url', 'default_user',
             'cores', 'memory', 'disk_gb', 'description', 'tags', 'eol')


def test_the_checker_reads_the_list_the_app_serves():
    """No second copy anywhere: what the workflow checks is CATALOG itself."""
    assert chk.load_catalog() == tpl.CATALOG


def test_every_entry_is_complete():
    for entry in tpl.CATALOG:
        missing = [k for k in _REQUIRED if k not in entry]
        assert not missing, f"{entry.get('id')}: missing {missing}"
        assert entry['image_url'].startswith('https://'), entry['id']
        datetime.date.fromisoformat(entry['eol'])


def test_ids_are_unique_and_survive_the_deploy_name_check():
    ids = [e['id'] for e in tpl.CATALOG]
    assert len(ids) == len(set(ids))
    for e in tpl.CATALOG:
        # deploy() builds tpl-<distro>-<version> when no name is given
        assert re.match(r'^[A-Za-z0-9._-]+$', f"tpl-{e['distro']}-{e['version']}".replace('.', ''))


def test_el_images_carry_a_cpu_model_that_starts_them():
    """qm create without --cpu gives kvm64, and EL9/EL10 userland refuses to run on it."""
    from pegaprox.core.manager import PegaProxManager
    for e in tpl.CATALOG:
        if e['distro'] in ('almalinux', 'rocky', 'centos', 'rhel'):
            want = 'x86-64-v3' if int(e['version'].split('.')[0]) >= 10 else 'x86-64-v2-AES'
            assert e.get('cpu') == want, e['id']
        if 'cpu' in e:
            assert e['cpu'] in PegaProxManager._STATIC_CPU_TYPES, e['id']


def test_no_long_dashes_in_what_the_ui_shows():
    for e in tpl.CATALOG:
        for v in (e['name'], e['description'], *e['tags']):
            assert '\u2014' not in v and '\u2013' not in v, e['id']


def test_the_known_dead_and_unsupported_entries_are_gone():
    ids = set(tpl.CATALOG_BY_ID)
    assert not ids & {'fedora-40', 'debian-11', 'alpine-319'}
    assert {'ubuntu-2604', 'debian-13', 'almalinux-10', 'rocky-10'} <= ids


# --- the deploy picks the entry's cpu up ---------------------------------------------

class _Chan:
    def recv_exit_status(self):
        return 0


class _Out:
    channel = _Chan()


class _Ssh:
    def __init__(self):
        self.cmds = []

    def exec_command(self, cmd, **kw):
        self.cmds.append(cmd)
        return None, _Out(), _Out()

    def close(self):
        pass


@pytest.fixture
def deploy_rig(monkeypatch):
    import pegaprox.utils.url_security as us
    from tests.conftest import make_fake_manager
    ssh = _Ssh()
    mgr = make_fake_manager('cl_cat')
    mgr._ssh_connect.return_value = ssh
    mgr._get_node_ip.return_value = '10.0.0.5'
    monkeypatch.setitem(tpl.cluster_managers, 'cl_cat', mgr)
    monkeypatch.setattr(tpl, '_update_dep', lambda *a, **kw: None)
    monkeypatch.setattr(tpl, '_read_capped', lambda f: '')
    monkeypatch.setattr(us, 'sanitize_outbound_url', lambda url, **kw: url)
    return ssh


def _create_cmd(ssh):
    return next(c for c in ssh.cmds if c.startswith('qm create'))


def test_an_el10_deploy_creates_the_vm_with_its_cpu_model(deploy_rig):
    tpl._run_deploy('d1', 'cl_cat', 'pve1', 'rocky-10', 'local-lvm', 9101, 'tpl-rocky-10')
    assert _create_cmd(deploy_rig).endswith('--cpu x86-64-v3')


def test_an_entry_without_a_cpu_keeps_the_node_default(deploy_rig):
    tpl._run_deploy('d2', 'cl_cat', 'pve1', 'debian-13', 'local-lvm', 9102, 'tpl-debian-13')
    assert '--cpu' not in _create_cmd(deploy_rig)
    assert any(c.startswith('qm template 9102') for c in deploy_rig.cmds)


# --- the checker's verdicts ----------------------------------------------------------

TODAY = datetime.date(2026, 10, 4)


@pytest.mark.parametrize('eol, level', [
    ('2026-10-03', 'error'),      # yesterday
    ('2026-11-20', 'warning'),    # inside the 60 days
    ('2030-06-30', None),
    (None, 'error'),
    ('June 2030', 'error'),
])
def test_eol_verdicts(eol, level):
    entry = {'id': 'x'} if eol is None else {'id': 'x', 'eol': eol}
    assert chk.eol_problem(entry, TODAY, 60)[0] == level


def test_a_file_without_a_catalog_is_an_error(tmp_path, monkeypatch):
    p = tmp_path / 'm.py'
    p.write_text('OTHER = []\n')
    monkeypatch.setattr(chk, 'CATALOG_FILE', str(p))
    with pytest.raises(ValueError):
        chk.load_catalog()


# --- the probe, against a local server -----------------------------------------------

class _Mirror(http.server.BaseHTTPRequestHandler):
    seen = []
    flaky_left = {}

    def log_message(self, *a):
        pass

    def _answer(self):
        self.seen.append((self.command, self.path, self.headers.get('Range')))
        p = self.path
        if p == '/redir':
            self.send_response(302)
            self.send_header('Location', '/img')
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return
        if p == '/nohead' and self.command == 'HEAD':
            self.send_response(405)
            self.end_headers()
            return
        if p == '/flaky' and self.flaky_left.get(p, 0) > 0:
            self.flaky_left[p] -= 1
            p = '/gone'
        if p in ('/img', '/nohead', '/flaky'):
            ranged = self.command == 'GET' and self.headers.get('Range')
            self.send_response(206 if ranged else 200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', '1' if ranged else '4096')
            self.end_headers()
            if self.command == 'GET':
                self.wfile.write(b'\0' if ranged else b'\0' * 4096)
            return
        if p == '/html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_HEAD = _answer
    do_GET = _answer


@pytest.fixture
def mirror():
    _Mirror.seen = []
    _Mirror.flaky_left = {}
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Mirror)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f'http://127.0.0.1:{srv.server_address[1]}', _Mirror
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_image_that_answers_passes(mirror):
    base, m = mirror
    assert chk.probe(base + '/img', timeout=5) is None
    assert m.seen == [('HEAD', '/img', None)]


def test_a_redirect_is_followed_without_downloading_the_image(mirror):
    """urllib turns a redirected HEAD into a GET on its own, which here would be a
    whole disk image per entry and week."""
    base, m = mirror
    assert chk.probe(base + '/redir', timeout=5) is None
    assert [s[0] for s in m.seen] == ['HEAD', 'HEAD']
    assert m.seen[-1][1] == '/img'


def test_a_404_is_dead(mirror):
    base, _ = mirror
    assert chk.probe(base + '/gone', timeout=5).startswith('HTTP 404')


def test_a_server_that_refuses_head_is_asked_for_one_byte(mirror):
    base, m = mirror
    assert chk.probe(base + '/nohead', timeout=5) is None
    assert m.seen[-1] == ('GET', '/nohead', 'bytes=0-0')


def test_an_html_page_is_not_an_image(mirror):
    base, _ = mirror
    assert 'HTML page' in chk.probe(base + '/html', timeout=5)


def test_a_host_that_does_not_answer_is_dead():
    with contextlib.closing(__import__('socket').socket()) as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    assert chk.probe(f'http://127.0.0.1:{port}/img', timeout=5) is not None


def test_one_bad_mirror_is_retried_and_a_gone_release_is_not_forgiven(mirror):
    base, m = mirror
    m.flaky_left['/flaky'] = 1
    assert chk.check_url(base + '/flaky', attempts=3, pause=0, timeout=5) is None
    m.seen.clear()
    assert chk.check_url(base + '/gone', attempts=3, pause=0, timeout=5) is not None
    assert len(m.seen) == 3


# --- a whole run --------------------------------------------------------------------

def test_a_run_lists_every_problem_and_fails(mirror, monkeypatch, tmp_path):
    base, _ = mirror
    summary = tmp_path / 'summary.md'
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    catalog = [
        {'id': 'good', 'image_url': base + '/img', 'eol': '2030-01-01'},
        {'id': 'dead', 'image_url': base + '/gone', 'eol': '2030-01-01'},
        {'id': 'old', 'image_url': base + '/img', 'eol': '2026-08-31'},
        {'id': 'soon', 'image_url': base + '/img', 'eol': '2026-11-01'},
    ]
    lines = []
    n = chk.run(catalog, today=TODAY, attempts=1, pause=0, timeout=5, out=lines.append)
    text = '\n'.join(lines)
    assert n == 2
    assert '::error title=Image catalog::dead: HTTP 404' in text
    assert '::error title=Image catalog::old: past its end of life' in text
    assert '::warning title=Image catalog::soon:' in text
    assert 'good' not in text.split('problem(s)')[1]
    written = summary.read_text()
    assert '`dead`' in written and '`old`' in written and '`soon`' in written


def test_a_clean_run_passes(mirror, monkeypatch):
    base, _ = mirror
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.delenv('GITHUB_STEP_SUMMARY', raising=False)
    lines = []
    n = chk.run([{'id': 'good', 'image_url': base + '/img', 'eol': '2030-01-01'}],
                today=TODAY, attempts=1, pause=0, timeout=5, out=lines.append)
    assert n == 0
    assert 'all 1 catalog entries are fine' in lines[-1]


def test_main_offline_exit_codes(tmp_path, monkeypatch):
    monkeypatch.delenv('GITHUB_STEP_SUMMARY', raising=False)
    p = tmp_path / 'cat.py'
    monkeypatch.setattr(chk, 'CATALOG_FILE', str(p))
    p.write_text("CATALOG = [{'id': 'a', 'image_url': 'https://x.invalid/a', 'eol': '2999-01-01'}]\n")
    assert chk.main(['--offline']) == 0
    p.write_text("CATALOG = [{'id': 'a', 'image_url': 'https://x.invalid/a', 'eol': '2000-01-01'}]\n")
    assert chk.main(['--offline']) == 1


# --- runtime: the catalog in the browser, all three layouts --------------------------
#
# The template library renders whatever /api/templates/catalog returns. Driven against the
# fake server of test_ha_ui.py with the real CATALOG as that answer; skips without Playwright.

SHOTS = os.environ.get('PP_CATALOG_SHOTS')   # a directory: keep a screenshot per run


def _library(browser, layout, role):
    reads = {
        ('GET', '/api/templates/catalog'): (200, {'templates': list(tpl.CATALOG)}),
        ('GET', '/api/clusters/c1/templates/deployments'): (200, {'deployments': []}),
        ('GET', '/api/clusters/c1/templates/existing'): (200, {'templates': []}),
        # the Automation tab loads its scripts on the way in
        ('GET', '/api/clusters/c1/scripts'): (200, []),
    }
    app = _App(browser, _FakeServer(role=role, layout=layout, clusters=[CLUSTER], resources=[VM],
                                    extra=reads))
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-shell').get_by_text('Templates', exact=True).first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Automation').first.click()
        page.locator('button', has_text='Cloud-Init Template Library').first.click()
    page.get_by_text('Ubuntu 26.04 LTS (Resolute)').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return app


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=True)


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_current_catalog_renders(browser, layout):
    app = _library(browser, layout, 'active')
    try:
        page = app.page
        for e in tpl.CATALOG:
            assert page.get_by_text(e['name'], exact=True).count() >= 1, e['name']
        for gone in ('Fedora 40 Cloud', 'Debian 11 (Bullseye)', 'Alpine Linux 3.19'):
            assert page.get_by_text(gone).count() == 0
        deploy = page.locator('button', has_text='Deploy')
        assert deploy.count() == len(tpl.CATALOG)
        assert all(deploy.nth(i).is_enabled() for i in range(deploy.count()))
        _shot(page, f'catalog-{layout}.png')
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_standby_shows_the_catalog_but_deploys_nothing(browser):
    app = _library(browser, 'modern', 'standby')
    try:
        page = app.page
        deploy = page.locator('button', has_text='Deploy')
        assert deploy.count() == len(tpl.CATALOG)
        assert not any(deploy.nth(i).is_enabled() for i in range(deploy.count()))
        assert page.locator('button', has_text='Add Custom').count() == 0
        _shot(page, 'catalog-standby.png')
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
