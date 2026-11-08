"""#1134 - a plugin's own page comes from where the plugin is loaded.

/status and /portal checked that the plugin was loaded and then read status.html and
portal.html next to the program files. A package install runs in /var/lib/pegaprox and
loads its plugins from there, so the plugin ran and its page said "not installed".
Both pages now go through plugins.plugin_file: the plugin folder (PLUGINS_DIR), with
the same containment as load_plugin.
"""
import json
import os
import subprocess
import sys
import types

import pytest

import pegaprox.api.plugins as plugins_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAGES = [('/status', 'status_page', 'status.html'),
         ('/portal', 'client_portal', 'portal.html'),
         ('/portal/my-vms', 'client_portal', 'portal.html')]


@pytest.fixture
def live(tmp_path, monkeypatch):
    """A plugin folder away from the code, as /var/lib/pegaprox/plugins is."""
    folder = tmp_path / 'var-lib-pegaprox' / 'plugins'
    folder.mkdir(parents=True)
    monkeypatch.setattr(plugins_mod, 'PLUGINS_DIR', str(folder))
    return folder


def _page(live, plugin, name, body):
    (live / plugin).mkdir(exist_ok=True)
    (live / plugin / name).write_text(body)


@pytest.mark.parametrize('url,plugin,name', PAGES)
def test_the_page_comes_from_the_plugin_folder(api, live, monkeypatch, url, plugin, name):
    monkeypatch.setitem(plugins_mod._loaded_plugins, plugin, types.SimpleNamespace())
    _page(live, plugin, name, f'<html>the copy in the plugin folder: {plugin}</html>')
    r = api.anon().get(url)
    assert r.status_code == 200, (r.status_code, r.data[:200])
    assert f'the copy in the plugin folder: {plugin}'.encode() in r.data


@pytest.mark.parametrize('url,plugin,name', PAGES)
def test_the_copy_next_to_the_code_is_not_what_is_served(api, live, monkeypatch, url, plugin, name):
    """Counterproof: the checkout has the page next to the code, the plugin folder does
    not - which is a package install the other way round. The old code served the copy
    next to the code here, and on a package install found nothing there."""
    assert os.path.isfile(os.path.join(ROOT, 'plugins', plugin, name))
    monkeypatch.setitem(plugins_mod._loaded_plugins, plugin, types.SimpleNamespace())
    (live / plugin).mkdir()
    r = api.anon().get(url)
    assert r.status_code == 404 and b'not installed' in r.data, (r.status_code, r.data[:200])


@pytest.mark.parametrize('url,plugin,name', PAGES)
def test_a_plugin_that_is_not_loaded_has_no_page(api, live, monkeypatch, url, plugin, name):
    monkeypatch.delitem(plugins_mod._loaded_plugins, plugin, raising=False)
    _page(live, plugin, name, 'never served')
    r = api.anon().get(url)
    assert r.status_code == 404 and b'not available' in r.data, (r.status_code, r.data[:200])


@pytest.mark.parametrize('url,plugin,name', PAGES)
def test_a_package_install_serves_the_page_from_its_working_directory(api, monkeypatch, tmp_path, url, plugin,
                                                                      name):
    """With the constant as it is, relative: the unit runs in /var/lib/pegaprox, the code
    lies elsewhere (here: the checkout, which has its own copy). send_file joins a relative
    path onto the code folder, so the page has to go out as an absolute one."""
    state = tmp_path / 'var-lib-pegaprox'
    (state / 'plugins').mkdir(parents=True)
    _page(state / 'plugins', plugin, name, f'<html>{plugin} from the working directory</html>')
    monkeypatch.chdir(state)
    monkeypatch.setattr(plugins_mod, 'PLUGINS_DIR', 'plugins')
    monkeypatch.setitem(plugins_mod._loaded_plugins, plugin, types.SimpleNamespace())
    r = api.anon().get(url)
    assert r.status_code == 200, (r.status_code, r.data[:200])
    assert f'{plugin} from the working directory'.encode() in r.data


def test_a_page_that_leads_out_of_the_plugin_folder_is_not_served(api, live, monkeypatch, tmp_path):
    outside = tmp_path / 'outside.html'
    outside.write_text('<html>a file the page must not reach</html>')
    (live / 'status_page').mkdir()
    (live / 'status_page' / 'status.html').symlink_to(outside)
    monkeypatch.setitem(plugins_mod._loaded_plugins, 'status_page', types.SimpleNamespace())
    r = api.anon().get('/status')
    assert r.status_code == 404 and b'not installed' in r.data
    assert b'must not reach' not in r.data


def test_plugin_file_stays_inside_the_plugin(live, tmp_path):
    pf = plugins_mod.plugin_file
    outside = tmp_path / 'outside.html'
    outside.write_text('x')
    (live / 'status_page').mkdir()
    (live / 'status_page' / 'status.html').symlink_to(outside)
    (live / 'hello_world').mkdir()
    (live / 'hello_world' / 'page.html').write_text('ok')
    assert pf('status_page', 'status.html') is None                  # a symlink out
    assert pf('status_page', '../hello_world/page.html') is None     # into another plugin
    assert pf('status_page', '../../../outside.html') is None
    assert pf('status_page', str(outside)) is None                   # an absolute name
    assert pf('../hello_world', 'page.html') is None                 # a bad id
    assert pf('hello_world', '') is None and pf('hello_world', None) is None
    assert pf('hello_world', 'missing.html') is None
    # a plugin folder that is itself a symlink out of the plugin folder (load_plugin
    # refuses to load it the same way)
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    (elsewhere / 'portal.html').write_text('x')
    (live / 'client_portal').symlink_to(elsewhere, target_is_directory=True)
    assert pf('client_portal', 'portal.html') is None
    # counterproof: a plain file, and a symlink that stays in the plugin's folder
    (live / 'hello_world' / 'alias.html').symlink_to(live / 'hello_world' / 'page.html')
    want = (live / 'hello_world' / 'page.html').resolve()
    assert pf('hello_world', 'page.html') == want
    assert pf('hello_world', 'alias.html') == want
    assert want.is_absolute()      # send_file joins a relative path onto the code folder


def test_nothing_reads_a_plugin_file_next_to_the_code():
    """The two pages were the only places; nothing in the backend goes there again."""
    hits = []
    for base, _dirs, files in os.walk(os.path.join(ROOT, 'pegaprox')):
        for fn in files:
            if not fn.endswith('.py'):
                continue
            with open(os.path.join(base, fn), encoding='utf-8') as fh:
                for no, line in enumerate(fh, 1):
                    if "'plugins'" in line and '__file__' in line:
                        hits.append(f'{fn}:{no}')
    assert not hits, hits


def _constants_with(env, cwd):
    child = dict(os.environ)
    for var in ('PEGAPROX_CONFIG_DIR', 'PEGAPROX_LOG_DIR', 'PEGAPROX_PLUGINS_DIR'):
        child.pop(var, None)
    child.update(env)
    child['PYTHONPATH'] = ROOT
    out = subprocess.run([sys.executable, '-c',
                          'import json, pegaprox.constants as c; print(json.dumps(c.PLUGINS_DIR))'],
                         cwd=str(cwd), env=child, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-1500:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_the_plugin_folder_can_be_moved(tmp_path):
    """The image points it into the config volume, so a plugin's config.json outlasts a
    new image. Unset, every other install keeps plugins/ in its working directory."""
    assert _constants_with({}, tmp_path) == 'plugins'
    assert (tmp_path / 'plugins').is_dir()
    target = tmp_path / 'config' / 'plugins'
    assert _constants_with({'PEGAPROX_PLUGINS_DIR': str(target)}, tmp_path) == str(target)
    assert target.is_dir()
    assert _constants_with({'PEGAPROX_PLUGINS_DIR': '   '}, tmp_path) == 'plugins'
