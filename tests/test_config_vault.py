"""Configuration-vault encryption, redaction and provider regression tests."""

import io
import json
import os

import pytest

from pegaprox.core import config_vault


def test_backup_crypto_round_trip_and_wrong_key():
    payload = {'schema_version': 2, 'hello': '配置保险库'}
    encrypted = config_vault.encrypt_backup(payload, 'correct horse battery staple')

    assert '配置保险库'.encode('utf-8') not in encrypted
    assert json.loads(config_vault.decrypt_backup(
        encrypted, 'correct horse battery staple'
    )) == payload

    with pytest.raises(ValueError, match='Incorrect backup password'):
        config_vault.decrypt_backup(encrypted, 'wrong password')


def test_backup_crypto_reads_legacy_headerless_envelope():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    password = 'legacy recovery password'
    plaintext = json.dumps({'version': 'legacy'})
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100_000, backend=default_backend(),
    ).derive(password.encode())
    legacy = salt + nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), None)

    assert not legacy.startswith(config_vault._BACKUP_MAGIC)
    assert json.loads(config_vault.decrypt_backup(legacy, password)) == {
        'version': 'legacy'
    }


def test_versioned_envelope_and_manifest_integrity(db):
    payload = config_vault.build_backup_data(exported_by='alice')
    encrypted = config_vault.encrypt_backup(payload, 'versioned recovery password')

    assert encrypted.startswith(config_vault._BACKUP_HEADER_V2)
    config_vault.validate_backup_manifest(payload)

    payload['version'] = 'tampered'
    with pytest.raises(ValueError, match='integrity check failed'):
        config_vault.validate_backup_manifest(payload)


def _seed_portable_secrets(db):
    db.save_server_setting('smtp_password', db._encrypt('smtp-secret'))
    db.save_cluster('cluster-1', {
        'name': 'Lab', 'host': 'pve.example', 'user': 'root@pam',
        'pass': 'cluster-secret', 'ssh_key': 'PRIVATE-KEY',
        'api_token_user': 'automation@pve!pegaprox',
        'api_token_secret': 'token-secret',
        'ha_settings': {'fence_password': 'fence-secret', 'mode': 'watch'},
    })
    db.save_user('alice', {
        'password_salt': 'salt', 'password_hash': 'hash', 'role': 'admin',
        'totp_secret': 'TOTP-SECRET', 'totp_pending_secret': 'PENDING-SECRET',
    })


def test_schema_v2_redacts_every_plaintext_secret_by_default(db):
    _seed_portable_secrets(db)
    db.conn.cursor().execute('''
        INSERT INTO custom_scripts
        (id, cluster_id, name, description, content, created_at, updated_at)
        VALUES ('script-1', 'cluster-1', 'deploy', 'token=description-secret',
                'export API_TOKEN=script-secret', 'now', 'now')
    ''')
    db.conn.commit()

    payload = config_vault.build_backup_data(exported_by='alice')
    cluster = payload['clusters']['cluster-1']
    user = payload['users']['alice']

    assert payload['schema_version'] == 2
    assert payload['manifest']['schema_version'] == 2
    assert payload['manifest']['backup_id'] == payload['backup_id']
    assert len(payload['manifest']['content_sha256']) == 64
    assert payload['server_settings']['smtp_password'] == ''
    assert 'pass' not in cluster
    assert 'ssh_key' not in cluster
    assert 'api_token_secret' not in cluster
    assert cluster['ha_settings']['fence_password'] == ''
    assert 'password_hash' not in user
    assert 'password_salt' not in user
    assert 'totp_secret' not in user
    assert 'totp_pending_secret' not in user
    assert payload['custom_scripts'] == []

    serialised = json.dumps(payload)
    for secret in ('smtp-secret', 'cluster-secret', 'PRIVATE-KEY', 'token-secret',
                   'fence-secret', 'TOTP-SECRET', 'PENDING-SECRET',
                   'description-secret', 'script-secret'):
        assert secret not in serialised


def test_schema_v2_secrets_are_portable_inside_outer_envelope(db):
    _seed_portable_secrets(db)

    payload = config_vault.build_backup_data(
        exported_by='alice', include_secrets=True
    )

    assert payload['server_settings']['smtp_password'] == 'smtp-secret'
    assert payload['clusters']['cluster-1']['pass'] == 'cluster-secret'
    assert payload['clusters']['cluster-1']['ssh_key'] == 'PRIVATE-KEY'
    assert payload['clusters']['cluster-1']['api_token_secret'] == 'token-secret'
    assert payload['users']['alice']['totp_secret'] == 'TOTP-SECRET'

    encrypted = config_vault.encrypt_backup(payload, 'portable recovery key')
    assert b'cluster-secret' not in encrypted
    restored = json.loads(config_vault.decrypt_backup(encrypted, 'portable recovery key'))
    assert restored['clusters']['cluster-1']['pass'] == 'cluster-secret'


def test_provider_credentials_are_encrypted_and_never_returned(db):
    config_vault.set_vault_key('a sufficiently long recovery key')
    provider = config_vault.save_provider('webdav', {
        'name': 'NAS',
        'settings': {
            'url': 'https://dav.example/backups',
            'username': 'backup-user',
            'password': 'provider-secret',
        },
    }, 'alice')

    assert provider['settings']['has_password'] is True
    assert 'password' not in provider['settings']
    assert config_vault.get_status()['key_id']

    row = db.conn.cursor().execute(
        'SELECT settings_encrypted FROM config_vault_providers WHERE id = ?', ('webdav',)
    ).fetchone()
    assert 'provider-secret' not in row['settings_encrypted']

    # Blank secret on edit means "keep existing", matching the masked UI field.
    config_vault.save_provider('webdav', {
        'settings': {'url': 'https://dav.example/new', 'password': ''},
    }, 'alice')
    private = config_vault.get_provider('webdav', include_credentials=True)
    assert private['settings']['password'] == 'provider-secret'


def test_string_boolean_provider_options_are_parsed_explicitly(db):
    config_vault.save_provider('webdav', {
        'schedule_enabled': 'false',
        'include_secrets': '0',
        'settings': {
            'url': 'https://93.184.216.34/backups',
            'verify_tls': 'false',
            'allow_private_network': '0',
        },
    }, 'alice')

    provider = config_vault.get_provider('webdav', include_credentials=True)
    assert provider['schedule_enabled'] is False
    assert provider['include_secrets'] is False
    assert provider['settings']['verify_tls'] is False
    assert provider['settings']['allow_private_network'] is False


def test_successful_sync_uploads_encrypted_payload_and_records_history(db, monkeypatch):
    uploaded = {}

    class FakeAdapter:
        def put(self, key, body):
            uploaded['key'] = key
            uploaded['body'] = body

        def list(self, prefix):
            return [{'key': uploaded['key'], 'modified': 'now'}]

        def delete(self, key):
            raise AssertionError('the current/only backup must not be deleted')

    config_vault.set_vault_key('offsite recovery password')
    config_vault.save_provider('webdav', {
        'settings': {'url': 'https://dav.example/backups'},
        'retention_count': 3,
    }, 'alice')
    monkeypatch.setattr(config_vault, '_adapter', lambda provider: FakeAdapter())

    config_vault._run_sync('webdav', 'alice')

    history = config_vault.list_history()
    assert history[0]['status'] == 'ok'
    assert history[0]['size_bytes'] == len(uploaded['body'])
    assert history[0]['sha256']
    assert uploaded['key'].endswith('.pegabackup')
    assert uploaded['key'].count('/') == 1
    assert config_vault.get_status()['key_id'] in uploaded['key']
    decrypted = json.loads(config_vault.decrypt_backup(
        uploaded['body'], 'offsite recovery password'
    ))
    assert decrypted['schema_version'] == 2
    assert decrypted['manifest']['backup_id'] == history[0]['backup_id']
    assert config_vault.get_provider('webdav')['last_status'] == 'ok'


def test_retention_keeps_newest_backups_and_ignores_unrelated_objects():
    deleted = []
    current = 'instance/pegaprox-key-20260810-120000-current.pegabackup'

    class FakeAdapter:
        def list(self, prefix):
            assert prefix == 'instance/'
            return [
                {'key': 'instance/readme.txt', 'modified': '2026-08-10T13:00:00Z'},
                {'key': 'instance/pegaprox-key-20260807-120000-oldest.pegabackup', 'modified': '2026-08-07T12:00:00Z'},
                {'key': current, 'modified': '2026-08-10T12:00:00Z'},
                {'key': 'instance/pegaprox-key-20260809-120000-middle.pegabackup', 'modified': '2026-08-09T12:00:00Z'},
                {'key': 'instance/pegaprox-key-20260808-120000-older.pegabackup', 'modified': '2026-08-08T12:00:00Z'},
            ]

        def delete(self, key):
            deleted.append(key)

    config_vault._retention_cleanup(FakeAdapter(), 'instance/', 3, current)

    assert deleted == [
        'instance/pegaprox-key-20260807-120000-oldest.pegabackup'
    ]


@pytest.mark.parametrize('provider_type', ['webdav', 's3'])
@pytest.mark.parametrize(('url', 'message'), [
    ('https://user:pass@93.184.216.34/backups', 'Credentials must not be embedded'),
    ('https://93.184.216.34/backups?token=x', 'query string or fragment'),
    ('http://93.184.216.34/backups', 'Plain HTTP requires explicit'),
    ('https://127.0.0.1/backups', 'private / loopback'),
])
def test_provider_endpoint_security_rejects_unsafe_urls(provider_type, url, message):
    if provider_type == 'webdav':
        settings = {'url': url}
        factory = config_vault.WebDAVProvider
    else:
        settings = {
            'endpoint_url': url,
            'bucket': 'pegaprox-backups',
            'access_key_id': 'AKIATEST',
            'secret_access_key': 'secret',
            'path_style': True,
        }
        factory = config_vault.S3Provider

    with pytest.raises(ValueError, match=message):
        factory(settings)


def test_webdav_lists_legacy_and_scoped_backups_in_chronological_order(monkeypatch):
    instance_id = '11111111-2222-3333-4444-555555555555'
    base_xml = b'''<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
      <d:response><d:href>/backups/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
      <d:response><d:href>/backups/11111111-2222-3333-4444-555555555555/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
      <d:response><d:href>/backups/pegaprox-oldkey-20260806-120000-legacy.pegabackup</d:href><d:propstat><d:prop><d:getlastmodified>Thu, 06 Aug 2026 12:00:00 GMT</d:getlastmodified><d:getcontentlength>10</d:getcontentlength></d:prop></d:propstat></d:response>
    </d:multistatus>'''
    child_xml = b'''<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
      <d:response><d:href>/backups/11111111-2222-3333-4444-555555555555/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
      <d:response><d:href>/backups/11111111-2222-3333-4444-555555555555/pegaprox-zzzz-20260808-120000-newer.pegabackup</d:href><d:propstat><d:prop><d:getlastmodified>Sat, 08 Aug 2026 12:00:00 GMT</d:getlastmodified><d:getcontentlength>12</d:getcontentlength></d:prop></d:propstat></d:response>
      <d:response><d:href>/backups/11111111-2222-3333-4444-555555555555/pegaprox-aaaa-20260807-120000-older.pegabackup</d:href><d:propstat><d:prop><d:getlastmodified>Fri, 07 Aug 2026 12:00:00 GMT</d:getlastmodified><d:getcontentlength>11</d:getcontentlength></d:prop></d:propstat></d:response>
    </d:multistatus>'''

    class Response:
        status_code = 207

        def __init__(self, content):
            self.content = content

    provider = config_vault.WebDAVProvider({
        'url': 'https://93.184.216.34/backups'
    })
    seen_urls = []

    def fake_request(method, url, **kwargs):
        seen_urls.append(url)
        return Response(child_xml if url.endswith(instance_id) else base_xml)

    monkeypatch.setattr(provider, '_request', fake_request)
    objects = provider.list('')

    assert [item['key'] for item in objects] == [
        f'{instance_id}/pegaprox-zzzz-20260808-120000-newer.pegabackup',
        f'{instance_id}/pegaprox-aaaa-20260807-120000-older.pegabackup',
        'pegaprox-oldkey-20260806-120000-legacy.pegabackup',
    ]
    assert seen_urls == [
        'https://93.184.216.34/backups',
        f'https://93.184.216.34/backups/{instance_id}',
    ]


def test_s3_list_paginates(monkeypatch):
    pages = [
        b'''<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next-token</NextContinuationToken><Contents><Key>prefix/one.pegabackup</Key><LastModified>2026-08-09T00:00:00Z</LastModified><Size>1</Size></Contents></ListBucketResult>''',
        b'''<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>prefix/two.pegabackup</Key><LastModified>2026-08-10T00:00:00Z</LastModified><Size>2</Size></Contents></ListBucketResult>''',
    ]
    params_seen = []

    class Response:
        status_code = 200

        def __init__(self, content):
            self.content = content

    provider = config_vault.S3Provider({
        'endpoint_url': 'https://93.184.216.34',
        'bucket': 'pegaprox-backups',
        'access_key_id': 'AKIATEST',
        'secret_access_key': 'secret',
        'path_style': True,
    })

    def fake_request(method, key='', params=None, **kwargs):
        params_seen.append(dict(params or {}))
        return Response(pages[len(params_seen) - 1])

    monkeypatch.setattr(provider, '_request', fake_request)
    objects = provider.list('prefix/')

    assert [item['key'] for item in objects] == [
        'prefix/two.pegabackup', 'prefix/one.pegabackup'
    ]
    assert params_seen[1]['continuation-token'] == 'next-token'


def test_provider_delete_preserves_history(db):
    config_vault.save_provider('webdav', {
        'settings': {'url': 'https://93.184.216.34/backups'},
    }, 'alice')
    config_vault._history_insert('history-1', 'webdav', 'alice')

    assert config_vault.delete_provider('webdav') is True
    history = config_vault.list_history()
    assert history[0]['id'] == 'history-1'
    assert history[0]['provider_id'] == 'webdav'
    assert history[0]['provider_name'] is None


def test_legacy_cascade_history_schema_is_migrated_without_data_loss(db):
    config_vault.save_provider('webdav', {
        'settings': {'url': 'https://93.184.216.34/backups'},
    }, 'alice')
    cursor = db.conn.cursor()
    cursor.execute('DROP TABLE config_vault_history')
    cursor.execute('''
        CREATE TABLE config_vault_history (
            id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            object_key TEXT DEFAULT '',
            size_bytes INTEGER DEFAULT 0,
            sha256 TEXT DEFAULT '',
            backup_id TEXT DEFAULT '',
            triggered_by TEXT DEFAULT '',
            error TEXT DEFAULT '',
            FOREIGN KEY (provider_id) REFERENCES config_vault_providers(id)
                ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        INSERT INTO config_vault_history
        (id, provider_id, status, started_at, triggered_by)
        VALUES ('legacy-history', 'webdav', 'ok', '2026-08-10T12:00:00', 'alice')
    ''')
    db.conn.commit()

    db._init_db()

    assert db.conn.cursor().execute(
        'PRAGMA foreign_key_list(config_vault_history)'
    ).fetchall() == []
    row = db.conn.cursor().execute(
        'SELECT provider_id FROM config_vault_history WHERE id = ?',
        ('legacy-history',),
    ).fetchone()
    assert row['provider_id'] == 'webdav'


def test_completed_history_is_pruned_per_provider(db, monkeypatch):
    monkeypatch.setattr(config_vault, 'MAX_HISTORY_ROWS_PER_PROVIDER', 3)
    config_vault.save_provider('webdav', {
        'settings': {'url': 'https://93.184.216.34/backups'},
    }, 'alice')
    for index in range(4):
        history_id = f'history-{index}'
        config_vault._history_insert(history_id, 'webdav', 'alice')
        db.conn.cursor().execute(
            'UPDATE config_vault_history SET started_at = ? WHERE id = ?',
            (f'2026-08-10T12:00:0{index}', history_id),
        )
        db.conn.commit()
        config_vault._history_finish(history_id, status='ok')

    history = config_vault.list_history(limit=20)
    assert [item['id'] for item in history] == [
        'history-3', 'history-2', 'history-1'
    ]


def test_status_distinguishes_corrupt_vault_metadata(db):
    db.conn.cursor().execute('''
        INSERT INTO config_vault_metadata (key, value_encrypted, updated_at)
        VALUES ('vault_key', 'aes256:not-valid-base64', 'now')
    ''')
    db.conn.commit()

    status = config_vault.get_status()
    assert status['vault_ready'] is False
    assert 'vault_key' in status['vault_error']


def test_remote_backup_versions_can_be_listed_and_downloaded(db, monkeypatch):
    downloaded = b'encrypted-remote-backup'
    seen = {'prefixes': [], 'downloads': []}

    class FakeAdapter:
        def list(self, prefix):
            seen['prefixes'].append(prefix)
            return [
                {
                    'key': 'pegaprox/instance-old/pegaprox-a1b2c3d4e5f6-20260810-123456-deadbeef.pegabackup',
                    'modified': '2026-08-10T12:35:00Z',
                    'size': len(downloaded),
                },
                {'key': 'pegaprox/instance-old/readme.txt', 'modified': 'now'},
            ]

        def get(self, key):
            seen['downloads'].append(key)
            return downloaded

    config_vault.save_provider('s3', {
        'name': 'Recovery bucket',
        'settings': {
            'endpoint_url': 'https://s3.example',
            'bucket': 'pegaprox-backups',
            'prefix': 'pegaprox',
            'access_key_id': 'AKIATEST',
            'secret_access_key': 'secret',
        },
    }, 'alice')
    monkeypatch.setattr(config_vault, '_adapter', lambda provider: FakeAdapter())

    backups = config_vault.list_remote_backups('s3')

    assert len(backups) == 1
    assert backups[0]['provider_name'] == 'Recovery bucket'
    assert backups[0]['source_instance'] == 'instance-old'
    assert backups[0]['key_id'] == 'a1b2c3d4e5f6'
    assert backups[0]['backup_id'] == 'deadbeef'
    assert backups[0]['created_at'] == '2026-08-10T12:34:56'
    assert seen['prefixes'] == ['pegaprox/']

    body = config_vault.download_remote_backup('s3', backups[0]['object_key'])
    assert body == downloaded
    assert seen['downloads'] == [backups[0]['object_key']]

    with pytest.raises(ValueError, match='not found'):
        config_vault.download_remote_backup('s3', 'pegaprox/other/secret.pegabackup')


def test_s3_sigv4_upload_has_authorization_without_leaking_secret(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        content = b''

    def fake_request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return Response()

    monkeypatch.setattr(config_vault.requests, 'request', fake_request)
    provider = config_vault.S3Provider({
        'endpoint_url': 'https://93.184.216.34',
        'bucket': 'pegaprox-backups',
        'region': 'us-east-1',
        'access_key_id': 'AKIATEST',
        'secret_access_key': 'never-leak-this',
        'path_style': True,
        'verify_tls': True,
    })
    provider.put('instance/backup.pegabackup', b'encrypted-body')

    assert captured['method'] == 'PUT'
    assert captured['url'].endswith('/pegaprox-backups/instance/backup.pegabackup')
    assert captured['headers']['Authorization'].startswith('AWS4-HMAC-SHA256 ')
    assert 'never-leak-this' not in captured['url']
    assert 'never-leak-this' not in json.dumps(captured['headers'])
    assert captured['allow_redirects'] is False


def test_vault_api_requires_admin_reauth_and_redacts_credentials(api, seed, db):
    from pegaprox.utils.auth import hash_password

    admin = seed.user('root', role='admin')
    salt, password_hash = hash_password('local-admin-password')
    db.save_user('root', {
        **admin,
        'password_salt': salt,
        'password_hash': password_hash,
        'role': 'admin',
        'enabled': True,
    })
    client = api.as_user(admin)

    assert api.anon().get('/api/config/vault').status_code == 401
    initial = client.get('/api/config/vault')
    assert initial.status_code == 200
    assert initial.get_json()['vault_ready'] is False

    denied = client.put('/api/config/vault/key', json={
        'user_password': 'wrong',
        'recovery_key': 'a long recovery key',
        'recovery_key_confirmation': 'a long recovery key',
    })
    assert denied.status_code == 401

    saved_key = client.put('/api/config/vault/key', json={
        'user_password': 'local-admin-password',
        'recovery_key': 'a long recovery key',
        'recovery_key_confirmation': 'a long recovery key',
    })
    assert saved_key.status_code == 200, saved_key.get_data(as_text=True)
    assert saved_key.get_json()['vault_ready'] is True

    saved_provider = client.put('/api/config/vault/providers/webdav', json={
        'user_password': 'local-admin-password',
        'name': 'NAS',
        'settings': {
            'url': 'https://dav.example/backups',
            'username': 'vault-user',
            'password': 'webdav-secret',
        },
    })
    assert saved_provider.status_code == 200, saved_provider.get_data(as_text=True)
    public = saved_provider.get_json()['provider']['settings']
    assert public['has_password'] is True
    assert 'password' not in public
    assert 'webdav-secret' not in saved_provider.get_data(as_text=True)


def test_remote_backup_api_lists_and_proxies_encrypted_file(api, seed, monkeypatch):
    from pegaprox.api import settings

    admin = seed.user('root', role='admin')
    client = api.as_user(admin)
    object_key = 'pegaprox-oldkey-20260810-123456-deadbeef.pegabackup'
    monkeypatch.setattr(settings, 'list_vault_remote_backups', lambda provider: [{
        'provider_id': provider,
        'object_key': object_key,
        'filename': object_key,
    }])
    monkeypatch.setattr(
        settings, 'download_vault_remote_backup',
        lambda provider, key: b'encrypted-body' if key == object_key else b'',
    )

    assert api.anon().get('/api/config/vault/providers/webdav/backups').status_code == 401
    listed = client.get('/api/config/vault/providers/webdav/backups')
    assert listed.status_code == 200
    assert listed.get_json()['backups'][0]['object_key'] == object_key

    downloaded = client.get(
        '/api/config/vault/providers/webdav/backups/download',
        query_string={'object_key': object_key},
    )
    assert downloaded.status_code == 200
    assert downloaded.data == b'encrypted-body'
    assert downloaded.headers['Cache-Control'] == 'no-store'
    assert object_key in downloaded.headers['Content-Disposition']


def test_overwrite_restore_preserves_credentials_omitted_from_backup(api, seed, db):
    from pegaprox.utils.auth import hash_password

    admin = seed.user('root', role='admin')
    root_salt, root_hash = hash_password('local-admin-password')
    db.save_user('root', {
        **admin,
        'password_salt': root_salt,
        'password_hash': root_hash,
        'role': 'admin',
        'enabled': True,
    })
    bob_salt, bob_hash = hash_password('bob-password')
    db.save_user('bob', {
        'password_salt': bob_salt,
        'password_hash': bob_hash,
        'totp_secret': 'BOB-TOTP',
        'role': 'user',
        'enabled': True,
    })
    db.save_cluster('cluster-1', {
        'name': 'Lab', 'host': 'pve.example', 'user': 'root@pam',
        'pass': 'cluster-password', 'ssh_key': 'PRIVATE-KEY',
        'api_token_secret': 'TOKEN-SECRET',
        'ha_settings': {'fence_password': 'FENCE-SECRET', 'mode': 'watch'},
    })
    payload = config_vault.build_backup_data(
        exported_by='root', include_secrets=False, include_users=True
    )
    encrypted = config_vault.encrypt_backup(payload, 'backup recovery password')

    response = api.as_user(admin).post('/api/config/restore', data={
        'user_password': 'local-admin-password',
        'backup_password': 'backup recovery password',
        'mode': 'overwrite',
        'restore_users': 'true',
        'dry_run': 'false',
        'backup_file': (io.BytesIO(encrypted), 'backup.pegabackup'),
    }, content_type='multipart/form-data')

    assert response.status_code == 200, response.get_data(as_text=True)
    cluster = db.get_cluster('cluster-1')
    assert cluster['pass'] == 'cluster-password'
    assert cluster['ssh_key'] == 'PRIVATE-KEY'
    assert cluster['api_token_secret'] == 'TOKEN-SECRET'
    assert cluster['ha_settings']['fence_password'] == 'FENCE-SECRET'
    bob = db.get_user('bob')
    assert bob['password_salt'] == bob_salt
    assert bob['password_hash'] == bob_hash
    assert bob['totp_secret'] == 'BOB-TOTP'


def test_restore_treats_malformed_schema_version_as_legacy(api, seed, db):
    from pegaprox.utils.auth import hash_password

    admin = seed.user('root', role='admin')
    salt, password_hash = hash_password('local-admin-password')
    db.save_user('root', {
        **admin,
        'password_salt': salt,
        'password_hash': password_hash,
        'role': 'admin',
        'enabled': True,
    })
    encrypted = config_vault.encrypt_backup({
        'schema_version': '2.0',
        'version': 'legacy',
        'export_date': '2026-08-10T12:00:00',
    }, 'backup recovery password')

    response = api.as_user(admin).post('/api/config/restore', data={
        'user_password': 'local-admin-password',
        'backup_password': 'backup recovery password',
        'mode': 'merge',
        'dry_run': 'true',
        'backup_file': (io.BytesIO(encrypted), 'legacy.pegabackup'),
    }, content_type='multipart/form-data')

    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.get_json()['backup_version'] == 'legacy'
