"""The token of a migration from another site holds what the source node asks of the target.

The remote_migrate handlers of qemu-server and pve-container call GET /cluster/status of
the target with the token before they start the task, which wants Sys.Audit on /. The
token of a linked-mode migration had Sys.Incoming there and nothing else, so Proxmox VE
refused every such migration with "Permission check failed (/, Sys.Audit)". A VM on a
custom CPU model has the source read that model at the target as well (Mapping.Audit on
/mapping/cpu/custom-<name>, the name as the VM config has it), and the target's mtunnel
checks Mapping.Use on /mapping/cpu/<name> when it writes the config. A privileged container
wants Sys.Modify on / of the target, which this token is never given. The token also asked
for eight days, more than the API token policy of a PVE 9.3 cluster may allow.

Now the token holds Sys.Audit on /, both rights on the custom model of the VM, an expire
within the target's policy, and a privileged container is refused before any token is
made. The rights are read back from the roles and ACLs the target cluster was given, the
way PVE adds them up.

MK Nov 2026
"""
import time

from pegaprox.core import federation_migrate as fmig
from pegaprox.core.manager import PegaProxManager
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _defaults_out_of_the_config_dir, _fresh_budgets, at, iid)
from tests.test_federation_migrate import SRC, _Resp, _answer_config, _migrate, pve  # noqa: F401
from tests.test_federation_relay import (  # noqa: F401 - fixtures by name
    CID, MIGRATIONS, _fresh_relay, _session, linked)


def _token_privs(calls, path):
    """The privileges the migration token holds on `path`: its ACLs on the roles made for
    it, an ACL with propagate reaching the paths below it."""
    roles = {d['roleid']: set(d['privs'].split(',')) for p, d in calls['post']
             if p == '/access/roles'}
    held = set()
    for p, d in calls['put']:
        if p != '/access/acl':
            continue
        acl = d['path'].rstrip('/') or '/'
        if path == acl or (d['propagate'] and path.startswith(acl.rstrip('/') + '/')):
            held |= roles[d['roles']]
    return held


def _guest(config):
    from pegaprox import globals as g
    # the answer of PegaProxManager.get_vm_config: PVE's own keys under config.raw
    g.cluster_managers[SRC].get_vm_config.return_value = {'success': True,
                                                         'config': {'raw': config}}


def _source_answers(config):
    """The source cluster of this site reads the guest with the manager's own
    get_vm_config, over a PVE API that answers `config`."""
    from pegaprox import globals as g
    src = g.cluster_managers[SRC]
    src.is_connected, src.host, src.api_port = True, '10.0.0.4', 8006
    src._api_get.return_value = _Resp(200, config)
    src._create_session.return_value.get.return_value = _Resp(200, {'status': 'stopped'})
    for name in ('get_vm_config', '_parse_vm_config', '_parse_disk_string'):
        getattr(src, name).side_effect = (
            lambda *a, _f=getattr(PegaProxManager, name): _f(src, *a))


def _policy(life):
    """The target cluster with an API token policy of `life` seconds at most."""
    from pegaprox import globals as g
    tgt = g.cluster_managers[CID]
    real = tgt._api_get.side_effect

    def get(url, **kw):
        if url.endswith('/cluster/options'):
            return _Resp(200, {'token-policy': {'max-lifetime': life}})
        return real(url, **kw)
    tgt._api_get.side_effect = get


def test_the_token_may_read_the_cluster_status_the_source_asks_for_first(linked, pve):
    a, b = linked
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 200, r.data
    # pve-manager Cluster.pm get_status: ['perm', '/', ['Sys.Audit']]
    assert {'Sys.Audit', 'Sys.Incoming'} <= _token_privs(pve, '/')
    # and no more than that on the root
    assert _token_privs(pve, '/') == {'Sys.Audit', 'Sys.Incoming'}
    assert 'Sys.Audit' not in _token_privs(pve, '/nodes/pve-b1')


def test_a_vm_on_a_custom_cpu_model_may_read_that_model_at_the_target(linked, pve):
    a, b = linked
    _guest({'cores': 2, 'cpu': 'custom-epyc-lab,flags=+aes', 'memory': 4096})
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 200, r.data
    # CustomCPUModels.pm info: Mapping.Audit on '/mapping/cpu/{cputype}', with the cputype
    # as qemu-server's remote_migrate_vm sends it ('custom-epyc-lab')
    assert _token_privs(pve, '/mapping/cpu/custom-epyc-lab') == {'Mapping.Audit'}
    # Qemu.pm check_cpu_model_access, from the mtunnel's config step: Mapping.Use on
    # "/mapping/cpu/$name" with 'custom-' taken off
    assert _token_privs(pve, '/mapping/cpu/epyc-lab') == {'Mapping.Use'}
    assert not _token_privs(pve, '/mapping/cpu/custom-other')
    assert not _token_privs(pve, '/mapping/cpu/other')
    assert not _token_privs(pve, '/mapping/pci/gpu0')


def test_a_vm_on_a_built_in_cpu_model_gets_no_mapping_right(linked, pve):
    a, b = linked
    _guest({'cores': 2, 'cpu': 'cputype=x86-64-v2-AES', 'memory': 4096})
    assert _migrate(a, b, _session(a, 'alice')).status_code == 200
    assert not any(d['path'].startswith('/mapping') for p, d in pve['put'] if p == '/access/acl')


def test_the_custom_model_of_a_vm_at_another_site_is_read_from_its_config(linked, pve, monkeypatch):
    a, b = linked
    from pegaprox import globals as g
    from pegaprox.core import federation_relay as relay
    g.cluster_managers['tgt0'] = g.cluster_managers[CID]
    config = {'raw': {'cores': 2, 'memory': 4096, 'cpu': 'cputype=custom-lab2',
                      'scsi0': 'local:vm-101-disk-0,size=32G'}}
    monkeypatch.setattr(relay, 'relay_call', _answer_config(relay.relay_call, config))
    try:
        r = _migrate(a, b, _session(a, 'alice'), source_cluster=f'{CID}~{iid(b)}',
                     target_cluster='tgt0')
    finally:
        g.cluster_managers.pop('tgt0', None)
    assert r.status_code == 200, r.data
    assert 'Mapping.Audit' in _token_privs(pve, '/mapping/cpu/custom-lab2')
    assert 'Mapping.Use' in _token_privs(pve, '/mapping/cpu/lab2')


def test_a_vm_of_a_cluster_of_this_site_gets_the_rights_of_its_custom_cpu_model(linked, pve):
    """The source cluster at the site that leads the migration: its config is the one
    get_vm_config answers, PVE's keys under config.raw."""
    a, b = linked
    _source_answers({'cores': 2, 'memory': 4096, 'cpu': 'cputype=custom-epyc-lab',
                     'scsi0': 'local-lvm:vm-101-disk-0,size=32G'})
    r = _migrate(a, b, _session(a, 'alice'))
    assert r.status_code == 200, r.data
    assert 'Mapping.Audit' in _token_privs(pve, '/mapping/cpu/custom-epyc-lab')
    assert 'Mapping.Use' in _token_privs(pve, '/mapping/cpu/epyc-lab')


def test_a_privileged_container_of_a_cluster_of_this_site_is_refused_up_front(linked, pve):
    a, b = linked
    _source_answers({'arch': 'amd64', 'cores': 1, 'memory': 512,
                     'rootfs': 'local-lvm:vm-101-disk-0,size=8G'})
    r = _migrate(a, b, _session(a, 'alice'), vm_type='lxc')
    assert r.status_code == 409, r.data
    assert 'privileged' in r.get_json()['error']
    assert pve['post'] == [] and pve['put'] == [] and MIGRATIONS == []


def test_a_privileged_container_is_refused_before_a_token_is_made(linked, pve):
    a, b = linked
    _guest({'arch': 'amd64', 'cores': 1, 'memory': 512, 'rootfs': 'local:101/vm-101-disk-0.raw,size=8G'})
    r = _migrate(a, b, _session(a, 'alice'), vm_type='lxc')
    assert r.status_code == 409
    assert 'privileged' in r.get_json()['error'] and 'Sys.Modify' in r.get_json()['error']
    assert pve['post'] == [] and pve['put'] == [] and MIGRATIONS == []
    # an unprivileged one moves, and Sys.Modify is given to none
    _guest({'arch': 'amd64', 'cores': 1, 'memory': 512, 'unprivileged': 1})
    assert _migrate(a, b, _session(a, 'alice'), vm_type='lxc').status_code == 200
    assert 'Sys.Modify' not in _token_privs(pve, '/')


def test_the_token_ends_within_the_api_token_policy_of_the_target(linked, pve):
    a, b = linked
    _policy(86400)

    assert _migrate(a, b, _session(a, 'alice')).status_code == 200
    (_path, data), = [c for c in pve['post'] if '/token/' in c[0]]
    assert time.time() + 86400 - 300 < data['expire'] <= time.time() + 86400


def test_the_vmid_of_a_token_nobody_dropped_is_held_as_long_as_the_token_lives(linked, pve,
                                                                              monkeypatch):
    a, b = linked
    _policy(86400)
    assert _migrate(a, b, _session(a, 'alice'), target_vmid=300).status_code == 200
    # while the token lives, its VMID is no one else's
    r = _migrate(a, b, _session(a, 'alice'), target_vmid=300)
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_MIGRATE_VMID'

    # two days on: PVE takes the token no more, and the VMID is free again
    class _Later:
        def __getattr__(self, name):
            return getattr(time, name)

        def time(self):
            return time.time() + 2 * 86400
    monkeypatch.setattr(fmig, 'time', _Later())
    assert _migrate(a, b, _session(a, 'alice'), target_vmid=300).status_code == 200


def test_a_cpu_model_name_that_is_no_name_is_refused_at_the_target(linked, pve):
    a, b = linked
    with at(b):
        for bad in ('../../access', 'a b', 7):
            try:
                fmig.mint_target(CID, {'target_node': 'pve-b1', 'vm_type': 'qemu', 'vmid': 101,
                                       'storages': ['x'], 'bridges': ['vmbr0'], 'footprint': {},
                                       'cpu_model': bad},
                                 {'username': 'root', 'role': 'admin'}, 'root')
            except fmig.MigrationRefused as e:
                assert e.status == 400 and 'cpu_model' in e.error
            else:
                raise AssertionError(f'{bad!r} was taken as a CPU model')
    assert pve['post'] == []
