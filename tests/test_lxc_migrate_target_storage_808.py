# #808 - automatic container migration (balancer, anti-affinity, maintenance evacuation) of a
# CT with local volumes sent target-storage as "rootfs=local-zfs,mp0=local-zfs". PVE reads
# target-storage as a storage-pair list, took "rootfs=local-zfs" for one storage ID and
# rejected the whole request ("storage ID 'rootfs=local-zfs' contains illegal characters").

import re
from unittest.mock import MagicMock

from pegaprox.core.manager import PegaProxManager

# pve-storage-id, and the pair rule from PVE::JSONSchema::parse_idmap
_STORAGE_ID = re.compile(r'^[a-z][a-z0-9\-_.]*[a-z0-9]$', re.I)


def _parse_storage_pairs(value):
    """What PVE accepts for target-storage / targetstorage. Raises like PVE would."""
    sources = set()
    for entry in value.split(','):
        if entry == '1':
            continue
        if ':' in entry:
            m = re.match(r'^([^:]+):([^:]+)$', entry)
            assert m, f"entry '{entry}' is not a pair"
            src, dst = m.groups()
            assert _STORAGE_ID.match(src) and _STORAGE_ID.match(dst), f"entry '{entry}' contains invalid ID"
            assert src not in sources, f"duplicate mapping for source '{src}'"
            sources.add(src)
        else:
            assert _STORAGE_ID.match(entry), f"entry '{entry}' contains invalid ID"
    return sources


def _mgr(guest_config):
    m = PegaProxManager.__new__(PegaProxManager)   # skip heavy __init__
    m.current_host = None
    m.config = MagicMock(host='h', api_port=8006, dry_run=False)
    m.logger = MagicMock()
    m.last_migration_log = []
    cfg_resp = MagicMock(status_code=200)
    cfg_resp.json.return_value = {'data': guest_config}
    sess = MagicMock()
    sess.get.return_value = cfg_resp
    sess.put.return_value = MagicMock(status_code=200)
    m._create_session = MagicMock(return_value=sess)
    post_resp = MagicMock(status_code=200)
    post_resp.json.return_value = {'data': 'UPID:pve3:0001:migrate'}
    m._api_post = MagicMock(return_value=post_resp)
    m._wait_for_task = MagicMock(return_value=True)
    return m


_CT_CONFIG = {
    'hostname': 'ct190',
    'rootfs': 'local-zfs:subvol-190-disk-0,size=8G',
    'mp0': 'local-zfs:subvol-190-disk-1,mp=/data,size=4G',
    'mp1': 'local-lvm:vm-190-disk-2,mp=/logs,size=2G',
    'mp2': '/mnt/host-share,mp=/share',          # bind mount, nothing to move
    'net0': 'name=eth0,bridge=vmbr0,ip=dhcp',
}


def test_lxc_local_volumes_are_sent_as_storage_pairs():
    m = _mgr(_CT_CONFIG)
    vm = {'vmid': 190, 'name': 'ct190', 'node': 'pve3', 'type': 'lxc',
          '_has_local_disks': True}
    assert m.migrate_vm(vm, 'pve4', dry_run=False, wait_timeout=30) is True

    url = m._api_post.call_args.args[0]
    data = m._api_post.call_args.kwargs['data']
    assert url.endswith('/nodes/pve3/lxc/190/migrate')
    assert data['target'] == 'pve4'
    # rootfs + mp0 share a storage -> one pair; mp1 on a second storage -> its own pair
    assert data['target-storage'] == 'local-zfs:local-zfs,local-lvm:local-lvm'
    assert '=' not in data['target-storage']
    assert _parse_storage_pairs(data['target-storage']) == {'local-zfs', 'local-lvm'}


def test_lxc_rootfs_only_maps_its_storage_onto_itself():
    m = _mgr({'rootfs': 'local-zfs:subvol-191-disk-0,size=8G', 'hostname': 'ct191'})
    vm = {'vmid': 191, 'name': 'ct191', 'node': 'pve3', 'type': 'lxc', '_has_local_disks': True}
    assert m.migrate_vm(vm, 'pve4', dry_run=False, wait_timeout=30) is True
    data = m._api_post.call_args.kwargs['data']
    assert data['target-storage'] == 'local-zfs:local-zfs'
    _parse_storage_pairs(data['target-storage'])


def test_lxc_and_qemu_branches_send_the_same_shape():
    ct = _mgr(_CT_CONFIG)
    ct.migrate_vm({'vmid': 190, 'name': 'ct', 'node': 'pve3', 'type': 'lxc',
                   '_has_local_disks': True}, 'pve4', dry_run=False, wait_timeout=30)
    qm = _mgr({'scsi0': 'local-zfs:vm-200-disk-0,size=32G',
               'scsi1': 'local-zfs:vm-200-disk-1,size=8G',
               'virtio0': 'local-lvm:vm-200-disk-2,size=8G'})
    qm.migrate_vm({'vmid': 200, 'name': 'vm', 'node': 'pve3', 'type': 'qemu',
                   '_has_local_disks': True}, 'pve4', dry_run=False, wait_timeout=30)
    ct_val = ct._api_post.call_args.kwargs['data']['target-storage']
    qm_val = qm._api_post.call_args.kwargs['data']['targetstorage']
    assert _parse_storage_pairs(ct_val) == _parse_storage_pairs(qm_val)
