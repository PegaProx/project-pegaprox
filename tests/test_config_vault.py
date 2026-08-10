"""Configuration-vault encryption, redaction and provider regression tests."""

import json

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

    serialised = json.dumps(payload)
    for secret in ('smtp-secret', 'cluster-secret', 'PRIVATE-KEY', 'token-secret',
                   'fence-secret', 'TOTP-SECRET', 'PENDING-SECRET'):
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
    assert config_vault.get_status()['key_id'] in uploaded['key']
    decrypted = json.loads(config_vault.decrypt_backup(
        uploaded['body'], 'offsite recovery password'
    ))
    assert decrypted['schema_version'] == 2
    assert decrypted['manifest']['backup_id'] == history[0]['backup_id']
    assert config_vault.get_provider('webdav')['last_status'] == 'ok'


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
