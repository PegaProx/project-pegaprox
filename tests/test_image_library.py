"""Central caching, provisioning ownership, and HTTP authorization contracts.

No PVE hosts or upstream image servers are contacted. Remote commands are
checked against storage IDs returned by the fake Proxmox API/config.
"""
import hashlib
import io
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pegaprox.api import image_library as routes
from pegaprox.core import image_library as lib

PREFIX = '/api/clusters/cluster_1/images'
IMAGE = {'id': 'test-image', 'name': 'Test cloud', 'kind': 'cloud', 'default_user': 'debian'}
OPTIONS = {'nodes': ['pve'], 'storages': [
    {'storage': 'local', 'content': 'images,iso', 'avail': 10**12},
    {'storage': 'local-lvm', 'content': 'images', 'avail': 10**12},
], 'bridges': ['vmbr0']}
CONFIG = {'node': 'pve', 'name': 'my-vm', 'cores': 2, 'memory': 2048, 'disk_gb': 20,
          'storage': 'local', 'bridge': 'vmbr0', 'ciuser': 'debian',
          'sshkeys': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBOWuoRiTKRoDz98ROKKCDCu85a7NVEulXaXw8vx/b5v',
          'start': True}


@pytest.fixture(autouse=True)
def slots(monkeypatch):
    # Tests that stop at enqueue must not exhaust another test's worker slots.
    monkeypatch.setattr(lib, 'PROVISION_SLOTS', threading.BoundedSemaphore(2))


def test_upload_is_atomic_and_checks_size_and_digest(db, monkeypatch):
    path = lib.cache_path(IMAGE)
    checksum = hashlib.sha256(b'original').hexdigest()
    assert lib.write_image([b'original'], path, checksum) == (8, checksum)
    with pytest.raises(ValueError, match='SHA-256'):
        lib.write_image([b'wrong'], path, checksum)
    assert path.read_bytes() == b'original'
    monkeypatch.setattr(lib, 'max_image_bytes', lambda: 2)
    with pytest.raises(ValueError, match='exceeds'):
        lib.write_image([b'large'], path)
    assert path.read_bytes() == b'original'
    assert not list(path.parent.glob('.incoming-*'))


def download_session(monkeypatch, responses):
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.side_effect = responses
    monkeypatch.setattr(lib.requests, 'Session', lambda: session)
    return session


def response(status=200, headers=None, content=b'image'):
    result = MagicMock(status_code=status, headers=headers or {})
    result.__enter__.return_value = result
    result.iter_content.return_value = [content]
    return result


def test_url_download_is_cached_once_and_tampering_is_rejected(db, monkeypatch):
    checksum = hashlib.sha256(b'image').hexdigest()
    image = dict(IMAGE, source_url='https://8.8.8.8/image.img', sha256=checksum)
    session = download_session(monkeypatch, [response()])
    first = lib.ensure_cached(image)
    assert lib.ensure_cached(image) == first
    assert session.get.call_count == 1
    assert session.trust_env is False
    assert session.get.call_args.kwargs['allow_redirects'] is False
    first[0].write_bytes(b'corrupted')
    with pytest.raises(ValueError, match='Cached image SHA-256'):
        lib.ensure_cached(image)


def test_private_redirect_never_gets_requested(db, monkeypatch):
    session = download_session(monkeypatch, [response(302, {'Location': 'http://127.0.0.1/admin'})])
    with pytest.raises(ValueError):
        lib.ensure_cached(dict(IMAGE, source_url='https://8.8.8.8/image.img'))
    assert session.get.call_count == 1
    assert not lib.cache_path(IMAGE).exists()


def test_transfer_reuses_matching_iso_and_refuses_corrupt_copy(monkeypatch, tmp_path):
    ssh = MagicMock()
    checksum = hashlib.sha256(b'image').hexdigest()
    command = MagicMock(side_effect=['', checksum + '  /iso/existing.iso'])
    monkeypatch.setattr(lib, 'run_command', command)
    lib.transfer_image(ssh, tmp_path / 'image', '/iso/existing.iso', checksum)
    ssh.open_sftp.assert_not_called()
    command.side_effect = ['', '', '0' * 64 + '  /iso/existing.iso.part']
    with pytest.raises(ValueError, match='Transferred image SHA-256'):
        lib.transfer_image(ssh, tmp_path / 'image', '/iso/existing.iso', checksum)
    sftp = ssh.open_sftp.return_value.__enter__.return_value
    sftp.remove.assert_called_once()
    assert not any(call.args[1].startswith('mv ') for call in command.call_args_list)


def test_command_drains_both_streams_without_echoing_command():
    stdout_chunks, stderr_chunks = [b'out'], [b'failed']
    channel = SimpleNamespace(recv_ready=lambda: bool(stdout_chunks),
                              recv=lambda count: stdout_chunks.pop(0),
                              recv_stderr_ready=lambda: bool(stderr_chunks),
                              recv_stderr=lambda count: stderr_chunks.pop(0),
                              exit_status_ready=lambda: True, recv_exit_status=lambda: 1)
    ssh = SimpleNamespace(exec_command=lambda *args, **kwargs: (None, SimpleNamespace(channel=channel), None))
    with pytest.raises(RuntimeError, match='^failed$'):
        lib.run_command(ssh, 'secret command')
    assert not stdout_chunks and not stderr_chunks


def test_target_lookup_uses_absolute_api_urls_and_rejects_foreign_nodes():
    replies = {'/nodes': [{'node': 'pve', 'status': 'online'}, {'node': 'offline', 'status': 'offline'}],
               '/nodes/pve/storage': [{'storage': 'local', 'content': 'images,iso', 'active': 1},
                                     {'storage': 'disabled', 'content': 'images', 'active': 1, 'enabled': 0}],
               '/nodes/pve/network': [{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'eno1', 'type': 'eth'}]}
    def lookup(url):
        prefix = 'https://pve.example:8006/api2/json'
        assert url.startswith(prefix)
        return SimpleNamespace(status_code=200, json=lambda: {'data': replies[url[len(prefix):]]})
    manager = SimpleNamespace(host='pve.example', api_port=8006, _api_get=lookup)
    assert lib.target_options(manager, 'pve') == {'nodes': ['pve'], 'storages': [
        {'storage': 'local', 'content': 'images,iso', 'avail': 0}], 'bridges': ['vmbr0']}
    with pytest.raises(ValueError, match='does not belong'):
        lib.target_options(manager, 'another-host')


@pytest.mark.parametrize('url', ['http://169.254.169.254/latest/meta-data/',
                                'http://10.0.0.1/file.iso', 'file:///etc/passwd',
                                'https://user:secret@8.8.8.8/image', 'https://8.8.8.8/image#fragment'])
def test_disallowed_sources(url):
    with pytest.raises(ValueError):
        lib.validate_source_url(url)


@pytest.mark.parametrize('updates', [{'name': 'x; reboot'}, {'node': '../pve'}, {'cores': True},
                                    {'memory': 1}, {'storage': 'missing'}, {'bridge': 'missing'},
                                    {'vmid': -1}, {'start': 'yes'}, {'sshkeys': 'not a key'}])
def test_invalid_vm_request(updates):
    with pytest.raises(ValueError):
        lib.validate_vm_request(dict(CONFIG, **updates), IMAGE, OPTIONS)


def insert_job(db, job_id='job-one', image=IMAGE):
    db.conn.execute('''INSERT INTO image_provision_jobs
        (id,cluster_id,node,image_id,image_name,name,started_by,started_at)
        VALUES (?, 'cluster_1', 'pve', ?, ?, 'my-vm', 'admin', ?)''',
                    (job_id, image['id'], image['name'], lib.now()))
    db.conn.commit()
    return job_id


def job_row(db, job_id):
    return dict(db.conn.execute('SELECT * FROM image_provision_jobs WHERE id=?', (job_id,)).fetchone())


def worker_env(db, monkeypatch, volid='local:100/vm-100-disk-0.qcow2', fail_on=None):
    ssh = MagicMock()
    manager = SimpleNamespace(host='pve.example', api_port=8006,
                              _get_node_ip=lambda node: 'pve.example', _ssh_connect=lambda host: ssh)
    local = lib.cache_path(IMAGE)
    lib.write_image([b'image'], local)
    monkeypatch.setattr(lib, 'target_options', lambda *args: OPTIONS)
    monkeypatch.setattr(lib, 'pve_get', lambda *args: '100')
    transfer = MagicMock()
    monkeypatch.setattr(lib, 'transfer_image', transfer)
    commands = []

    def command(client, text):
        assert client is ssh
        commands.append(text)
        if fail_on and fail_on in text:
            raise RuntimeError('simulated node failure')
        if text == 'id -u':
            return '0'
        if text.startswith('pvesm path'):
            return '/mnt/nfs/template/iso/pegaprox-test.iso'
        if text.startswith('qm config'):
            return f'unused0: {volid},size=2G\n'
        return ''

    monkeypatch.setattr(lib, 'run_command', command)
    return manager, ssh, commands, transfer


@pytest.mark.parametrize('storage,volume', [('local', 'local:100/vm-100-disk-0.qcow2'),
                                         ('local-lvm', 'local-lvm:vm-100-disk-0')])
def test_cloud_uses_actual_imported_volume_and_cleans_keys(db, monkeypatch, storage, volume):
    manager, ssh, commands, transfer = worker_env(db, monkeypatch, volid=volume)
    job_id = insert_job(db)
    lib.PROVISION_SLOTS.acquire()
    lib.provision_vm(job_id, manager, IMAGE, dict(CONFIG, storage=storage))
    assert job_row(db, job_id)['status'] == 'completed'
    assert any(f'--scsi0 {volume}' in cmd for cmd in commands)
    assert any('--ipconfig0 ip=dhcp' in cmd for cmd in commands)
    assert 'qm start 100' in commands
    assert not any('qm template' in cmd or 'wget' in cmd for cmd in commands)
    assert any('rm -f -- /tmp/pegaprox-keys-' in cmd for cmd in commands)
    assert any('rm -f -- /tmp/pegaprox-image-' in cmd for cmd in commands)
    assert transfer.call_args.args[1] == lib.cache_path(IMAGE)
    ssh.close.assert_called_once()
    assert lib.PROVISION_SLOTS.acquire(blocking=False)


def test_iso_uses_selected_storage_path_and_creates_blank_disk(db, monkeypatch):
    manager, _, commands, transfer = worker_env(db, monkeypatch)
    image = dict(IMAGE, kind='iso')
    job_id = insert_job(db, image=image)
    lib.PROVISION_SLOTS.acquire()
    lib.provision_vm(job_id, manager, image, dict(CONFIG, iso_storage='local', ostype='l26', start=False))
    assert job_row(db, job_id)['status'] == 'completed'
    assert transfer.call_args.args[2] == '/mnt/nfs/template/iso/pegaprox-test.iso'
    create = next(cmd for cmd in commands if cmd.startswith('qm create'))
    assert '--scsi0 local:20' in create
    assert 'local:iso/pegaprox-' in create and 'media=cdrom' in create
    assert not any('qm importdisk' in cmd or 'qm start' in cmd for cmd in commands)


@pytest.mark.parametrize('failure,owns_vm', [('qm create', False), ('qm importdisk', True)])
def test_rollback_never_destroys_a_preexisting_vmid(db, monkeypatch, failure, owns_vm):
    manager, _, commands, _ = worker_env(db, monkeypatch, fail_on=failure)
    job_id = insert_job(db)
    lib.PROVISION_SLOTS.acquire()
    lib.provision_vm(job_id, manager, IMAGE, dict(CONFIG, vmid=100))
    assert job_row(db, job_id)['status'] == 'failed'
    assert ('qm destroy 100 --purge 1' in commands) is owns_vm


def test_recording_failure_does_not_delete_a_successful_vm(db, monkeypatch):
    manager, ssh, commands, _ = worker_env(db, monkeypatch)
    original = lib.update_job

    def update(job_id, **fields):
        if fields.get('status') == 'completed':
            raise RuntimeError('database unavailable')
        return original(job_id, **fields)

    monkeypatch.setattr(lib, 'update_job', update)
    ssh.close.side_effect = RuntimeError('socket already closed')
    job_id = insert_job(db)
    lib.PROVISION_SLOTS.acquire()
    lib.provision_vm(job_id, manager, IMAGE, CONFIG)
    assert not any(cmd.startswith('qm destroy') for cmd in commands)
    assert 'was created' in job_row(db, job_id)['error']
    assert lib.PROVISION_SLOTS.acquire(blocking=False)


def test_download_error_does_not_persist_signed_source_url(db, monkeypatch):
    manager, _, commands, _ = worker_env(db, monkeypatch)
    def download(image):
        raise lib.requests.ConnectionError('https://example.com/image?signature=secret')
    monkeypatch.setattr(lib, 'ensure_cached', download)
    job_id = insert_job(db)
    lib.PROVISION_SLOTS.acquire()
    lib.provision_vm(job_id, manager, IMAGE, CONFIG)
    assert 'signature' not in job_row(db, job_id)['error']
    assert not commands


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('admin', role='admin'))


def uploaded_image(client, **overrides):
    data = {'name': 'My ISO', 'kind': 'iso', 'file': (io.BytesIO(b'iso data'), 'installer.iso')}
    data.update(overrides)
    return client.post('/api/images/upload', data=data, content_type='multipart/form-data')


def test_http_upload_catalog_redaction_and_delete(admin, db):
    result = uploaded_image(admin)
    assert result.status_code == 201, result.json
    image_id = result.json['id']
    assert result.json['sha256'] == hashlib.sha256(b'iso data').hexdigest()
    listing = admin.get('/api/images').json['images']
    assert all('source_url' not in row and 'image_url' not in row and 'created_by' not in row for row in listing)
    assert next(row for row in listing if row['id'] == image_id)['cached']
    assert admin.delete(f'/api/images/{image_id}').status_code == 200
    assert not lib.cache_path({'id': image_id}).exists()


def test_upload_mismatch_and_extension_leave_no_files(admin, db):
    assert uploaded_image(admin, sha256='0' * 64).status_code == 400
    assert uploaded_image(admin, file=(io.BytesIO(b'zip'), 'installer.zip')).status_code == 400
    assert not list(lib.library_dir().iterdir())


def test_upload_caps_multipart_before_file_spooling(admin, db, monkeypatch):
    monkeypatch.setattr(lib, 'max_image_bytes', lambda: 100)
    result = uploaded_image(admin, file=(io.BytesIO(b'x' * (2 * 1024**2)), 'large.iso'))
    assert result.status_code == 413
    assert not list(lib.library_dir().iterdir())


@pytest.mark.parametrize('path', ['/api/images', '/api/images/upload', PREFIX + '/provision'])
def test_non_admin_cannot_modify_or_provision(api, seed, path):
    client = api.as_user(seed.user('operator', role='user'))
    assert client.post(path, json={}).status_code == 403
    assert api.anon().post(path, json={}).status_code == 401


def prepare_manager(api, monkeypatch):
    manager = api.set_manager('cluster_1', api.make_fake_manager())
    monkeypatch.setattr(lib, 'target_options', lambda *args: OPTIONS)
    queued = []
    monkeypatch.setattr(routes, 'start_job', lambda *args: queued.append(args))
    return manager, queued


def test_http_queue_reuse_two_connections_capacity_and_delete_guard(admin, api, db, monkeypatch):
    manager, queued = prepare_manager(api, monkeypatch)
    api.set_manager('cluster_2', api.make_fake_manager())
    image_id = uploaded_image(admin).json['id']
    payload = dict(CONFIG, image_id=image_id, iso_storage='local')
    one = admin.post(PREFIX + '/provision', json=payload)
    two = admin.post('/api/clusters/cluster_2/images/provision', json=payload)
    assert one.status_code == two.status_code == 202
    assert len(queued) == 2
    assert queued[0][2]['id'] == queued[1][2]['id'] == image_id
    assert queued[0][1] is manager
    assert admin.post(PREFIX + '/provision', json=payload).status_code == 429
    assert admin.delete(f'/api/images/{image_id}').status_code == 409
    jobs = admin.get(PREFIX + '/jobs').json['jobs']
    assert len(jobs) == 1 and jobs[0]['id'] == one.json['job_id']
    assert 'sshkeys' not in jobs[0]


def test_malformed_request_never_starts_job(admin, api, monkeypatch):
    _, queued = prepare_manager(api, monkeypatch)
    assert admin.post(PREFIX + '/provision', json=[]).status_code == 400
    assert admin.post('/api/images', json={'name': 'x', 'kind': 'cloud', 'source_url': 'http://127.0.0.1/image'}).status_code == 400
    assert not queued


def test_downgraded_admin_fails_before_resource_lookup(api, seed):
    seed.tenant('tenant-a', ['cluster_1'])
    user = seed.user('limited-admin', role='admin', tenant_id='tenant-a',
                     tenant_permissions={'tenant-a': {'role': 'viewer'}})
    manager = api.set_manager('cluster_1', api.make_fake_manager())
    client = api.as_user(user)
    assert client.get(PREFIX + '/targets').status_code == 403
    assert client.get(PREFIX + '/jobs').status_code == 403
    manager._api_get.assert_not_called()


def test_admin_owned_viewer_token_cannot_upload_or_provision(api, seed):
    from pegaprox.utils.auth import create_api_token
    seed.user('owner', role='admin')
    token = create_api_token('owner', 'read-only', role='viewer', expires_days=1)['token']
    headers = {'Authorization': 'Bearer ' + token}
    manager = api.set_manager('cluster_1', api.make_fake_manager())
    client = api.anon()
    assert client.get(PREFIX + '/targets', headers=headers).status_code == 403
    assert client.post('/api/images/upload', json={}, headers=headers).status_code == 403
    assert client.post(PREFIX + '/provision', json={}, headers=headers).status_code == 403
    assert client.get('/api/images', headers=headers).status_code == 200
    manager._api_get.assert_not_called()


def test_xcpng_is_refused_before_pve_resource_queries(admin, api):
    manager = api.set_manager('cluster_1', api.make_fake_manager(cluster_type='xcpng'))
    assert admin.get(PREFIX + '/targets').status_code == 400
    manager._api_get.assert_not_called()


def test_start_failure_records_failure_and_releases_slot(admin, api, db, monkeypatch):
    prepare_manager(api, monkeypatch)
    def fail(*args):
        raise RuntimeError('could not start thread')
    monkeypatch.setattr(routes, 'start_job', fail)
    image_id = uploaded_image(admin).json['id']
    result = admin.post(PREFIX + '/provision', json=dict(CONFIG, image_id=image_id, iso_storage='local'))
    assert result.status_code == 500
    assert admin.get(PREFIX + '/jobs').json['jobs'][0]['status'] == 'failed'
    assert lib.PROVISION_SLOTS.acquire(blocking=False)
    assert lib.PROVISION_SLOTS.acquire(blocking=False)


def test_restart_marks_interrupted_jobs_without_replaying(db):
    job_id = insert_job(db)
    routes.recover_interrupted_jobs()
    row = job_row(db, job_id)
    assert row['status'] == 'failed' and 'before retrying' in row['error']
