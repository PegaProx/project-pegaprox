"""The per-node addresses and ports in the cluster settings.

Under the transfer network sits one row per node with an address, an SSH port and a GUI
port. Empty fields mean "as the cluster" and show the cluster's value as the placeholder,
so a cluster that overrides nothing looks like one that has no overrides. A save that
moves the credential comes back as CREDENTIAL_REQUIRED and the section then asks for the
password rather than losing what was typed. A standby that does not hand writes on shows
the section locked.
"""
import os
import re

import pytest

from test_ha_ui import LANGS, _classes, _read  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS = ['nodeEpTitle', 'nodeEpDesc', 'nodeEpNode', 'nodeEpHost', 'nodeEpSsh', 'nodeEpGui',
        'nodeEpHostAuto', 'nodeEpNoNodes', 'nodeEpBadPort', 'nodeEpCredNeeded',
        'nodeEpCredPlaceholder', 'nodeEpSaved', 'nodeEpUnsaved']


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = sorted((m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M))
    out = {}
    for i, (pos, lang) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        out[lang] = src[pos:end]
    return out


def _component():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// Per-node address and port overrides.')
    return src[start:src.index('// NS: Mar 2026 - Topology View redesign', start)]


def _mount():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('{/* where a node deviates from the cluster')
    return src[start:src.index('{/* HA Section */}', start)]


def _all():
    return _component() + _mount()


# -- translations -------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    blocks = _blocks()
    assert sorted(blocks) == sorted(LANGS)
    for lang, block in blocks.items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_every_new_key_is_used_and_nothing_else_is_new():
    assert set(re.findall(r"'(nodeEp\w*)'", _all())) == set(KEYS)
    others = ''.join(_read('web', 'src', f) for f in os.listdir(os.path.join(ROOT, 'web', 'src'))
                     if f.endswith('.js') and f not in ('translations.js', 'dashboard.js'))
    assert 'nodeEp' not in others


def test_no_dash_in_what_this_change_added():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_all()] + lines:
        assert '—' not in text and '–' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_all()) if n not in have)
    assert missing == [], missing


# -- the component ------------------------------------------------------------------------------

def test_an_empty_field_shows_the_cluster_value_as_the_placeholder():
    comp = _component()
    assert "cluster.ssh_port || 22" in comp
    assert "cluster.api_port || 8006" in comp
    assert "placeholder={String(clusterSsh)}" in comp
    assert "placeholder={String(clusterApi)}" in comp


def test_an_emptied_field_is_removed_rather_than_sent_as_an_empty_string():
    assert "if (!value) delete entry[key];" in _component()


def test_a_node_whose_entry_is_now_empty_is_not_sent():
    comp = _component()
    assert "if (Object.keys(entry).length) next[node] = entry; else delete next[node];" in comp
    assert "if (Object.keys(e).length) out[node] = e;" in comp


def test_a_port_outside_the_range_blocks_the_save():
    comp = _component()
    assert "n >= 1 && n <= 65535" in comp
    assert "disabled={!dirty || !portsOk || saving}" in comp
    assert "t('nodeEpBadPort')" in comp


def test_a_node_with_an_entry_stays_editable_after_it_left_the_cluster():
    assert "Array.from(new Set(names.concat(Object.keys(saved)))).sort()" in _component()


def test_the_node_list_takes_names_or_objects():
    assert "typeof n === 'string' ? n : (n && (n.node || n.name))" in _component()


def test_the_refusal_to_move_the_credential_asks_for_it():
    comp = _component()
    assert "d.code === 'CREDENTIAL_REQUIRED'" in comp
    assert "setNeedsSecret(true)" in comp
    assert "if (secret) body[secretField] = secret;" in comp
    # what was typed stays in the draft: no setDraft(saved) on that path
    refusal = comp[comp.index("CREDENTIAL_REQUIRED"):comp.index("addToast(await PegaProxApiErrors.message")]
    assert 'setDraft' not in refusal


def test_the_save_goes_to_the_live_config_route():
    comp = _component()
    assert "`${API_URL}/clusters/${cluster.id}/config`" in comp
    assert "method: 'PATCH'" in comp
    assert "node_endpoints: clean" in comp


def test_the_section_is_locked_for_a_standby_and_without_the_permission():
    comp = _component()
    assert "fieldset disabled={haReadOnly || !canEdit}" in comp
    assert "data-ha-locked={haReadOnly ? '' : undefined}" in comp


def test_the_section_is_mounted_for_proxmox_clusters_with_cluster_view():
    mount = _mount()
    assert "(selectedCluster.cluster_type || 'proxmox') === 'proxmox' && can('cluster.view')" in mount
    assert "canEdit={can('cluster.config')}" in mount
    assert "nodes={Object.keys(clusterMetrics)}" in mount


def test_a_saved_map_is_put_back_on_the_selected_cluster():
    assert "{...prev, node_endpoints: v}" in _mount()


# -- the Open in Proxmox links --------------------------------------------------------------------

def test_the_link_no_longer_pins_8006():
    tables = _read('web', 'src', 'tables.js')
    assert ':8006/#v1' not in tables
    assert "const port = ep.port || target.api_port || 8006;" in tables


def test_a_node_with_an_address_of_its_own_is_linked_there():
    """The port of an entry goes with the address of that entry, never with the node name."""
    tables = _read('web', 'src', 'tables.js')
    fn = tables[tables.index('function getProxmoxObjectUrl('):]
    assert "const ep = target.node_endpoint || {};" in fn
    assert "const host = ep.host || (" in fn


@pytest.mark.parametrize('component', ['NodeCard', 'NodeCompactRow'])
def test_both_node_rows_carry_the_endpoint(component):
    tables = _read('web', 'src', 'tables.js')
    sig = tables[tables.index('function %s({' % component):]
    assert 'nodeEndpoint' in sig[:sig.index('}')]
    assert 'node_endpoint: nodeEndpoint' in tables


def test_the_endpoint_helper_pairs_the_address_with_its_port():
    src = _read('web', 'src', 'dashboard.js')
    fn = src[src.index('function nodeUiEndpointOf('):]
    fn = fn[:fn.index('\n        }')]
    assert "host: entry.host || ''" in fn
    assert "port: entry.api_port || (cluster && cluster.api_port) || 8006" in fn


def test_every_node_row_is_given_the_endpoint_of_its_own_node():
    src = _read('web', 'src', 'dashboard.js')
    calls = re.findall(r'nodeEndpoint=\{nodeUiEndpointOf\(selectedCluster, (\w+)\)\}', src)
    assert len(calls) == 4
    # the name of the node being rendered, never a handler argument of the same name
    assert set(calls) == {'node', 'nodeName'}


def test_the_migrate_targets_are_the_clusters_nodes_not_the_endpoint_map():
    src = _read('web', 'src', 'dashboard.js')
    assert '<BulkMigrateModal vms={cloudBulkMigrate} nodes={Object.keys(clusterMetrics)}' in src
    assert '<MigrateModal vm={dashMigrateVm} nodes={Object.keys(clusterMetrics)}' in src


def test_the_credential_goes_in_the_field_the_server_names():
    src = _read('web', 'src', 'dashboard.js')
    assert 'body[secretField] = secret' in src and 'body.pass = secret' not in src
    assert 'setSecretField(d.credential_field)' in src


def test_a_poll_of_the_cluster_list_does_not_wipe_what_is_typed():
    src = _read('web', 'src', 'dashboard.js')
    assert '[cluster.id, savedKey]' in src and '[cluster.id, saved]' not in src


def test_a_save_that_drops_node_passwords_says_so():
    src = _read('web', 'src', 'dashboard.js')
    assert 'onSaved(clean, (done && done.node_passwords_cleared) || [])' in src
    assert "if (cleared.length) setNodeCredsNotice(" in src


def test_a_late_save_answer_only_updates_the_cluster_it_saved():
    src = _read('web', 'src', 'dashboard.js')
    assert 'prev && prev.id === selectedCluster.id ? {...prev, node_endpoints: v} : prev' in src
