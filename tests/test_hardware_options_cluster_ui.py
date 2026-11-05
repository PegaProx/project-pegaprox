"""The VM config dialog and the Create VM dialog ask for the CPU models of their own cluster.

Both read /api/hardware-options?cluster_id=<cluster> and offer that list: the cluster's PVE
version and its custom models, not those of the first cluster PegaProx has. The Create VM
dialog keeps its built-in list (qemu-server's own) when the read fails. Runs the built bundle
in headless Chromium against the fake server of tests/test_ha_ui.py; the route is tested in
test_hardware_options_cluster.py. Skips where Playwright is not installed.
LW Nov 2026
"""
import pytest

from test_ha_ui import CLUSTER  # noqa: F401
from test_vm_rng_ui import VM, browser, open_app  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab

LIVE = ['host', 'max', 'custom-fleet', 'EPYC-Turin', 'GraniteRapids-v3']
OPTIONS = {'cpu_types': LIVE, 'scsi_controllers': [], 'network_models': [], 'disk_bus_types': [],
           'cache_modes': [], 'machine_types': [{'value': '', 'label': 'Default'}]}


def _asked(app):
    return [u for u in app.server.urls if '/api/hardware-options' in u]


def _select_with(page, name):
    """The options of every select on the page that offers <name>."""
    return page.evaluate('''(name) => Array.from(document.querySelectorAll('select'))
        .map(s => Array.from(s.options).map(o => o.value)).filter(v => v.includes(name))''', name)


def test_runtime_the_config_dialog_offers_its_clusters_models(open_app):
    app = open_app(extra={('GET', '/api/hardware-options'): (200, OPTIONS)})
    _open_config(app, 'web01')
    _tab(app, 'Hardware').click()
    page = app.page
    page.wait_for_function('''() => Array.from(document.querySelectorAll('select option'))
        .some(o => o.value === 'custom-fleet')''', timeout=8000)
    assert _asked(app) and all('cluster_id=c1' in u for u in _asked(app)), _asked(app)
    lists = _select_with(page, 'custom-fleet')
    assert lists and set(LIVE) <= set(lists[0]), lists


def _create_cpu_list(app, name):
    """Open Create VM on Testi and go to the Advanced step, where the CPU type is chosen."""
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.locator('button', has_text='Create new VM').first.click()
    page.get_by_role('button', name='Advanced', exact=True).last.click()
    page.wait_for_function('''(name) => Array.from(document.querySelectorAll('select option'))
        .some(o => o.value === name)''', arg=name, timeout=8000)
    return _select_with(page, name)[0]


def test_runtime_the_create_dialog_offers_its_clusters_models(open_app):
    app = open_app(extra={('GET', '/api/hardware-options'): (200, OPTIONS)})
    offered = _create_cpu_list(app, 'custom-fleet')
    assert offered == LIVE, offered
    assert _asked(app) and all('cluster_id=c1' in u for u in _asked(app)), _asked(app)


def test_runtime_the_create_dialog_falls_back_to_qemu_servers_list(open_app):
    app = open_app(extra={('GET', '/api/hardware-options'): (500, {'error': 'boom'})})
    offered = _create_cpu_list(app, 'EPYC-Turin')
    assert offered[:2] == ['host', 'max'] and 'GraniteRapids-v3' in offered and 'n270' not in offered, offered
    assert 'custom-fleet' not in offered
