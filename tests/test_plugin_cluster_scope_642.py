"""#642 (maxilee) - a plugin enabled for a cluster also shows up while a standalone
node is selected, and the other way round.

The reporter runs one cluster plus three standalone PVE nodes in the same PegaProx.
Enabling the Docker or OPNsense plugin for the cluster made its tab appear on the
standalone nodes too, which is confusing and, with links into the wrong host, worse
than confusing.

The scope is stored per plugin as a list of cluster ids. Empty means "everywhere",
which is what every existing installation gets and therefore the only safe default.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(name):
    return open(os.path.join(ROOT, 'web', 'src', name), encoding='utf-8').read()


# --- the store ---------------------------------------------------------------

def test_the_scope_survives_a_round_trip_through_the_database(api, seed):
    """Setter-only tests lie about persistence: the column has to exist and the
    read path has to select it. Write it, read it back through the list route."""
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    r = c.put('/api/plugins/hello_world/clusters', json={'clusters': ['cluster_1', 'cluster_2']})
    assert r.status_code == 200, r.data

    listed = c.get('/api/plugins').get_json()
    entry = next((p for p in listed if p['id'] == 'hello_world'), None)
    assert entry is not None, 'hello_world plugin not discovered'
    assert sorted(entry.get('clusters') or []) == ['cluster_1', 'cluster_2'], entry


def test_an_empty_scope_means_everywhere(api, seed):
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    c.put('/api/plugins/hello_world/clusters', json={'clusters': ['cluster_1']})
    r = c.put('/api/plugins/hello_world/clusters', json={'clusters': []})
    assert r.status_code == 200, r.data
    listed = c.get('/api/plugins').get_json()
    entry = next(p for p in listed if p['id'] == 'hello_world')
    assert (entry.get('clusters') or []) == [], entry


def test_a_plugin_that_was_never_scoped_reports_no_scope(api, seed):
    """Every installation upgrading into this must keep seeing every plugin."""
    root = seed.user('root', role='admin')
    listed = api.as_user(root).get('/api/plugins').get_json()
    for entry in listed:
        assert entry.get('clusters') == [], entry


def test_toggling_the_plugin_does_not_forget_its_scope(api, seed):
    """enable/disable rewrite the same row. Losing the scope there would silently
    put the plugin back on every cluster the next time somebody toggles it."""
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    c.put('/api/plugins/hello_world/clusters', json={'clusters': ['cluster_1']})
    c.post('/api/plugins/hello_world/disable')
    c.post('/api/plugins/hello_world/enable')
    listed = c.get('/api/plugins').get_json()
    entry = next(p for p in listed if p['id'] == 'hello_world')
    assert (entry.get('clusters') or []) == ['cluster_1'], entry


# --- what the route refuses --------------------------------------------------

def test_a_plugin_id_from_the_url_cannot_walk_out_of_the_plugin_dir(api, seed):
    root = seed.user('root', role='admin')
    r = api.as_user(root).put('/api/plugins/..%2F..%2Fetc/clusters', json={'clusters': []})
    assert r.status_code in (400, 404), r.status_code


def test_the_scope_is_not_a_place_to_store_arbitrary_junk(api, seed):
    """It ends up in the frontend's filter and in an audit line; keep it to ids."""
    root = seed.user('root', role='admin')
    r = api.as_user(root).put('/api/plugins/hello_world/clusters',
                              json={'clusters': ['ok_1', {'a': 1}, 'bad id!', 42]})
    assert r.status_code == 400, r.data


def test_a_viewer_cannot_rescope_a_plugin(api, seed):
    seed.user('vera', role='user', permissions=['plugins.view'])
    r = api.as_user({'username': 'vera', 'role': 'user'}).put(
        '/api/plugins/hello_world/clusters', json={'clusters': ['cluster_1']})
    assert r.status_code == 403, r.status_code


# --- the frontend actually hides it ------------------------------------------

def test_the_tab_strip_filters_on_the_selected_cluster():
    """The store is pointless if the tab still renders. Both layouts build their
    own plugin list, so both have to ask."""
    dash = _src('dashboard.js')
    assert 'pluginAppliesToCluster' in dash, 'the modern tab strip ignores the scope'
    cloud = _src('cloud.js')
    assert 'pluginAppliesToCluster' in cloud, 'the cloud plugin list ignores the scope'


@pytest.mark.parametrize('scope,cluster,visible', [
    ([],                 'c1',  True),   # no scope = everywhere, today's behaviour
    ([],                 None,  True),   # ...even before a cluster is picked
    (['c1'],             'c1',  True),
    (['c1'],             'c2',  False),  # the report: cluster plugin on a standalone node
    (['c1', 'c2'],       'c2',  True),
    (['c1'],             None,  False),  # scoped, nothing selected -> not ours to show
])
def test_the_filter_decides_the_way_the_report_asks(scope, cluster, visible):
    """The helper is EXECUTED, not grepped. A one-character inversion of the
    empty-scope branch hides every plugin in the product and a text search would
    not notice."""
    import json
    import shutil
    import subprocess
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped helper')
    body = open(os.path.join(ROOT, 'web', 'src', 'constants.js'), encoding='utf-8').read()
    a = body.index('function pluginAppliesToCluster(')
    b = body.index('\n        }\n', a) + len('\n        }\n')
    script = (body[a:b] +
              '\nconst [scope, cluster] = JSON.parse(process.argv[1]);'
              '\nconsole.log(JSON.stringify(pluginAppliesToCluster({clusters: scope}, cluster)));')
    p = subprocess.run(['node', '-e', script, json.dumps([scope, cluster])],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) is visible, \
        f'scope={scope} cluster={cluster} -> expected visible={visible}'


def test_the_new_label_exists_in_every_language():
    """t() returns the key itself when a string is missing, so a gap shows up as
    the literal 'showOnClusters' next to the cluster buttons."""
    body = open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    assert len(re.findall(r'^\s*showOnClusters:', body, re.M)) == 9


def test_the_picker_is_reachable_from_the_plugin_list():
    """Without a control the column is dead weight - the reporter cannot use it."""
    body = open(os.path.join(ROOT, 'web', 'src', 'settings_modal.js'), encoding='utf-8').read()
    assert '/clusters`' in body and 'showOnClusters' in body


def test_the_shipped_bundle_was_rebuilt():
    built = open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    assert 'pluginAppliesToCluster' in built
