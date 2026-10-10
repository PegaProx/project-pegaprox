"""The vzdump restore route hands Proxmox the parameters of the guest type it restores.

qmrestore takes the backup as archive. pct has no archive parameter: a container restore is
a create with the backup as ostemplate and restore set, and an archive sent there was refused.
"""
CID = 'cluster_1'


def _manager(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    started = m._create_session.return_value.post.return_value
    started.status_code = 200
    started.json.return_value = {'data': 'UPID:pve1:restore'}
    return api.set_manager(CID, m)


def _sent(m):
    args, kwargs = m._create_session.return_value.post.call_args
    return args[0], kwargs['data']


def test_a_container_restore_sends_the_backup_as_ostemplate(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    m = _manager(api)
    volid = 'local:backup/vzdump-lxc-101-2026_10_01-00_00_00.tar.zst'
    r = admin.post(f'/api/clusters/{CID}/vms/pve1/lxc/101/backups/restore', json={'volid': volid})
    assert r.status_code == 200, r.data
    url, data = _sent(m)
    assert url.endswith('/nodes/pve1/lxc')
    assert data['ostemplate'] == volid and data['restore'] == 1
    assert 'archive' not in data
    assert data['force'] == 1


def test_a_vm_restore_still_sends_the_archive(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    m = _manager(api)
    volid = 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'
    r = admin.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore',
                   json={'volid': volid, 'target_vmid': 555})
    assert r.status_code == 200, r.data
    url, data = _sent(m)
    assert url.endswith('/nodes/pve1/qemu')
    assert data['archive'] == volid and 'ostemplate' not in data and 'restore' not in data
    assert data['vmid'] == 555 and data['force'] == 0


def test_the_same_vmid_as_text_still_overwrites(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    m = _manager(api)
    volid = 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'
    r = admin.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore',
                   json={'volid': volid, 'target_vmid': '100'})
    assert r.status_code == 200, r.data
    assert _sent(m)[1]['force'] == 1
