# -*- coding: utf-8 -*-
"""Encrypted off-site configuration vault for PegaProx.

This module deliberately implements one-way, versioned backup uploads.  It is
not an active/active database replication system: restores remain an explicit
administrator action through the existing dry-run-first restore endpoint.

Supported providers:
  * WebDAV (including private/self-hosted endpoints when explicitly enabled)
  * Amazon S3 and S3-compatible object storage (SigV4, no boto dependency)
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

import requests
from defusedxml import ElementTree

from pegaprox.constants import PEGAPROX_BUILD, PEGAPROX_VERSION
from pegaprox.core.db import get_db
from pegaprox.api.helpers import load_server_settings
from pegaprox.utils.audit import log_audit
from pegaprox.utils.url_security import sanitize_outbound_url


PROVIDER_TYPES = frozenset({'webdav', 's3'})
MAX_REMOTE_BACKUP_BYTES = 100 * 1024 * 1024
_PROVIDER_SECRET_FIELDS = {
    'webdav': frozenset({'password'}),
    's3': frozenset({'access_key_id', 'secret_access_key', 'session_token'}),
}
_SERVER_SECRET_FIELDS = frozenset({
    'smtp_password', 'ldap_bind_password', 'oidc_client_secret',
    'acme_dns_rfc2136_secret',
})
_USER_SECRET_FIELDS = frozenset({
    'password_hash', 'password_salt', 'totp_secret',
    'totp_pending_secret', 'totp_secret_encrypted',
    'totp_pending_secret_encrypted',
})
_CLUSTER_SECRET_FIELDS = frozenset({
    'pass', 'password', 'password_encrypted', 'pass_encrypted',
    'ssh_key', 'ssh_key_encrypted', 'api_token', 'api_token_encrypted',
    'api_token_secret', 'api_token_secret_encrypted',
})

_sync_guard = threading.Lock()
_active_syncs = set()
_scheduler_guard = threading.Lock()
_scheduler_running = False


def _now() -> str:
    return datetime.now().isoformat(timespec='seconds')


def _json_bytes(data: dict) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str
    ).encode('utf-8')


def _count_section(value) -> int:
    if isinstance(value, (dict, list, tuple)):
        return len(value)
    return 1 if value is not None else 0


def _redact_nested(value):
    """Remove credential-looking values from nested operational settings."""
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        lowered = str(key).lower()
        secretish = (
            lowered in {'pass', 'password', 'secret', 'token', 'private_key', 'api_key'}
            or lowered.endswith(('_password', '_secret', '_token', '_private_key', '_api_key'))
        )
        result[key] = '' if secretish else _redact_nested(item)
    return result


def _portable_server_settings(settings: dict, include_secrets: bool) -> dict:
    settings = copy.deepcopy(settings or {})
    db = get_db()
    for key in _SERVER_SECRET_FIELDS:
        if key not in settings:
            continue
        if not include_secrets:
            settings[key] = ''
            continue
        value = settings.get(key)
        if value and str(value).startswith(('aes256:', 'gAAAA')):
            try:
                settings[key] = db._decrypt(str(value))
            except Exception:
                logging.warning("[config-vault] could not make %s portable; omitted", key)
                settings[key] = ''
    return _redact_nested(settings) if not include_secrets else settings


def build_backup_data(
    *,
    exported_by: str,
    include_secrets: bool = False,
    include_users: bool = True,
    include_audit: bool = False,
) -> dict:
    """Build the portable, JSON-serialisable backup payload.

    The shape remains compatible with schema-v1 restore code (top-level
    ``version`` / ``export_date`` and sections), while the manifest makes new
    backups self-describing and integrity-checkable after decryption.
    """
    db = get_db()
    backup_id = uuid.uuid4().hex
    exported_at = _now()
    payload = {
        'format': 'pegaprox-config-backup',
        'schema_version': 2,
        'version': PEGAPROX_VERSION,
        'build': PEGAPROX_BUILD,
        'export_date': exported_at,
        'exported_by': exported_by or 'system',
        'encrypted': True,
        'backup_id': backup_id,
        'server_settings': _portable_server_settings(
            load_server_settings(), include_secrets
        ),
    }

    clusters = copy.deepcopy(db.get_all_clusters())
    if not include_secrets:
        for cluster in clusters.values():
            if not isinstance(cluster, dict):
                continue
            for key in _CLUSTER_SECRET_FIELDS:
                cluster.pop(key, None)
            if 'ha_settings' in cluster:
                cluster['ha_settings'] = _redact_nested(cluster['ha_settings'])
    payload['clusters'] = clusters

    if include_users:
        users = copy.deepcopy(db.get_all_users())
        if not include_secrets:
            for user in users.values():
                if not isinstance(user, dict):
                    continue
                for key in _USER_SECRET_FIELDS:
                    user.pop(key, None)
        payload['users'] = users

    payload['tenants'] = db.get_all_tenants()
    payload['vm_acls'] = db.get_all_vm_acls()
    payload['affinity_rules'] = db.get_affinity_rules()

    try:
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM cluster_groups')
        payload['cluster_groups'] = [dict(row) for row in cursor.fetchall()]
    except Exception:
        payload['cluster_groups'] = []

    try:
        cursor = db.conn.cursor()
        cursor.execute('PRAGMA table_info(custom_scripts)')
        script_columns = {row['name'] for row in cursor.fetchall()}
        if 'deleted_at' in script_columns:
            cursor.execute('SELECT * FROM custom_scripts WHERE deleted_at IS NULL')
        else:
            cursor.execute('SELECT * FROM custom_scripts')
        scripts = [dict(row) for row in cursor.fetchall()]
        for script in scripts:
            script.pop('last_output', None)
        payload['custom_scripts'] = scripts
    except Exception:
        payload['custom_scripts'] = []

    if include_audit:
        payload['audit_log'] = db.get_audit_log(limit=10000)

    section_names = (
        'server_settings', 'clusters', 'users', 'tenants', 'vm_acls',
        'affinity_rules', 'cluster_groups', 'custom_scripts', 'audit_log',
    )
    section_counts = {
        name: _count_section(payload[name]) for name in section_names if name in payload
    }
    content_hash = hashlib.sha256(_json_bytes(payload)).hexdigest()
    payload['manifest'] = {
        'format': 'pegaprox-config-backup',
        'schema_version': 2,
        'backup_id': backup_id,
        'created_at': exported_at,
        'created_by': exported_by or 'system',
        'app_version': PEGAPROX_VERSION,
        'app_build': PEGAPROX_BUILD,
        'instance_id': get_instance_id(),
        'options': {
            'include_secrets': bool(include_secrets),
            'include_users': bool(include_users),
            'include_audit': bool(include_audit),
        },
        'section_counts': section_counts,
        # Hash of the canonical payload immediately before the manifest is added.
        'content_sha256': content_hash,
    }
    return payload


def encrypt_backup(data, password: str) -> bytes:
    """Encrypt JSON-compatible data with the legacy-compatible AES-GCM format."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if not isinstance(password, str) or len(password) < 8:
        raise ValueError('Backup password must be at least 8 characters')
    plaintext = data if isinstance(data, str) else _json_bytes(data).decode('utf-8')
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend(),
    )
    key = kdf.derive(password.encode('utf-8'))
    return salt + nonce + AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)


def decrypt_backup(encrypted_data: bytes, password: str) -> str:
    """Decrypt the PegaProx backup format used by schema v1 and v2 payloads."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if not isinstance(encrypted_data, (bytes, bytearray)) or len(encrypted_data) < 29:
        raise ValueError('Invalid backup file format - file too short')
    salt = bytes(encrypted_data[:16])
    nonce = bytes(encrypted_data[16:28])
    ciphertext = bytes(encrypted_data[28:])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend(),
    )
    key = kdf.derive(password.encode('utf-8'))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception as exc:
        raise ValueError('Incorrect backup password or corrupted file') from exc


def create_encrypted_backup(*, password: str, exported_by: str, **options):
    payload = build_backup_data(exported_by=exported_by, **options)
    encrypted = encrypt_backup(payload, password)
    return encrypted, payload


def _meta_get(key: str) -> str:
    cursor = get_db().conn.cursor()
    cursor.execute('SELECT value_encrypted FROM config_vault_metadata WHERE key = ?', (key,))
    row = cursor.fetchone()
    if not row:
        return ''
    try:
        return get_db()._decrypt(row['value_encrypted'])
    except Exception:
        logging.exception("[config-vault] metadata decrypt failed for %s", key)
        return ''


def _meta_set(key: str, value: str):
    db = get_db()
    cursor = db.conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO config_vault_metadata (key, value_encrypted, updated_at)
        VALUES (?, ?, ?)
    ''', (key, db._encrypt(value), _now()))
    db.conn.commit()


def get_instance_id() -> str:
    instance_id = _meta_get('instance_id')
    if instance_id:
        return instance_id
    instance_id = str(uuid.uuid4())
    _meta_set('instance_id', instance_id)
    return instance_id


def set_vault_key(password: str):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError('Vault recovery key must be at least 12 characters')
    # Public, random identifier for support/history.  Do not expose a password
    # hash prefix: that would give a stolen admin session an offline verifier.
    key_id = uuid.uuid4().hex[:12]
    db = get_db()
    cursor = db.conn.cursor()
    now = _now()
    cursor.executemany('''
        INSERT OR REPLACE INTO config_vault_metadata (key, value_encrypted, updated_at)
        VALUES (?, ?, ?)
    ''', (
        ('vault_key', db._encrypt(password), now),
        ('vault_key_id', db._encrypt(key_id), now),
    ))
    db.conn.commit()


def get_vault_key() -> str:
    return _meta_get('vault_key')


def vault_key_id() -> str:
    return _meta_get('vault_key_id') if get_vault_key() else ''


def _vault_key_bundle():
    """Read the recovery key and its random ID from one SQLite snapshot."""
    cursor = get_db().conn.cursor()
    cursor.execute('''
        SELECT key, value_encrypted FROM config_vault_metadata
        WHERE key IN ('vault_key', 'vault_key_id')
    ''')
    values = {}
    for row in cursor.fetchall():
        try:
            values[row['key']] = get_db()._decrypt(row['value_encrypted'])
        except Exception:
            values[row['key']] = ''
    return values.get('vault_key', ''), values.get('vault_key_id', '')


def _provider_row(provider_id: str):
    cursor = get_db().conn.cursor()
    cursor.execute('SELECT * FROM config_vault_providers WHERE id = ?', (provider_id,))
    return cursor.fetchone()


def _decode_settings(row) -> dict:
    if not row:
        return {}
    try:
        raw = get_db()._decrypt(row['settings_encrypted'])
        value = json.loads(raw or '{}')
        return value if isinstance(value, dict) else {}
    except Exception:
        logging.exception("[config-vault] provider settings decrypt failed")
        return {}


def _public_settings(provider_type: str, settings: dict) -> dict:
    public = copy.deepcopy(settings or {})
    for key in _PROVIDER_SECRET_FIELDS.get(provider_type, ()):
        value = public.pop(key, None)
        public[f'has_{key}'] = bool(value)
    return public


def _row_to_provider(row) -> dict:
    settings = _decode_settings(row)
    return {
        'id': row['id'],
        'type': row['type'],
        'name': row['name'],
        'enabled': bool(row['enabled']),
        'schedule_enabled': bool(row['schedule_enabled']),
        'interval_hours': int(row['interval_hours'] or 24),
        'retention_count': int(row['retention_count'] or 10),
        'include_secrets': bool(row['include_secrets']),
        'include_users': bool(row['include_users']),
        'include_audit': bool(row['include_audit']),
        'settings': _public_settings(row['type'], settings),
        'last_sync': row['last_sync'],
        'next_sync': row['next_sync'],
        'last_status': row['last_status'] or '',
        'last_error': row['last_error'] or '',
        'last_object_key': row['last_object_key'] or '',
        'syncing': row['id'] in _active_syncs,
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }


def list_providers() -> list:
    cursor = get_db().conn.cursor()
    cursor.execute('SELECT * FROM config_vault_providers ORDER BY type')
    return [_row_to_provider(row) for row in cursor.fetchall()]


def get_provider(provider_id: str, *, include_credentials: bool = False) -> Optional[dict]:
    row = _provider_row(provider_id)
    if not row:
        return None
    result = _row_to_provider(row)
    if include_credentials:
        result['settings'] = _decode_settings(row)
    return result


def _bool(value, default=False) -> bool:
    return default if value is None else bool(value)


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def _normalise_provider_settings(provider_type: str, incoming: dict, existing: dict) -> dict:
    incoming = incoming if isinstance(incoming, dict) else {}
    existing = existing if isinstance(existing, dict) else {}

    if provider_type == 'webdav':
        settings = {
            'url': str(incoming.get('url', existing.get('url', '')) or '').strip()[:1000].rstrip('/'),
            'username': str(incoming.get('username', existing.get('username', '')) or '').strip()[:255],
            'verify_tls': _bool(incoming.get('verify_tls'), existing.get('verify_tls', True)),
            'allow_private_network': _bool(
                incoming.get('allow_private_network'), existing.get('allow_private_network', False)
            ),
            'allow_insecure_http': _bool(
                incoming.get('allow_insecure_http'), existing.get('allow_insecure_http', False)
            ),
        }
        if not settings['url']:
            raise ValueError('WebDAV URL is required')
    elif provider_type == 's3':
        region = str(incoming.get('region', existing.get('region', 'us-east-1')) or 'us-east-1').strip()[:80]
        endpoint = str(incoming.get('endpoint_url', existing.get('endpoint_url', '')) or '').strip()[:1000].rstrip('/')
        if not endpoint:
            endpoint = f'https://s3.{region}.amazonaws.com'
        settings = {
            'endpoint_url': endpoint,
            'bucket': str(incoming.get('bucket', existing.get('bucket', '')) or '').strip()[:255],
            'region': region,
            'prefix': str(incoming.get('prefix', existing.get('prefix', 'pegaprox')) or 'pegaprox').strip('/ ')[:500],
            'path_style': _bool(incoming.get('path_style'), existing.get('path_style', False)),
            'verify_tls': _bool(incoming.get('verify_tls'), existing.get('verify_tls', True)),
            'allow_private_network': _bool(
                incoming.get('allow_private_network'), existing.get('allow_private_network', False)
            ),
            'allow_insecure_http': _bool(
                incoming.get('allow_insecure_http'), existing.get('allow_insecure_http', False)
            ),
        }
        if not settings['bucket']:
            raise ValueError('S3 bucket is required')
    else:
        raise ValueError('Unsupported provider type')

    for key in _PROVIDER_SECRET_FIELDS[provider_type]:
        incoming_value = incoming.get(key)
        if incoming_value not in (None, '', '********'):
            settings[key] = str(incoming_value)
        elif existing.get(key):
            settings[key] = existing[key]
        else:
            settings[key] = ''
    return settings


def save_provider(provider_type: str, data: dict, created_by: str) -> dict:
    if provider_type not in PROVIDER_TYPES:
        raise ValueError('Unsupported provider type')
    row = _provider_row(provider_type)
    existing = _decode_settings(row)
    settings = _normalise_provider_settings(provider_type, data.get('settings') or {}, existing)
    now = _now()
    schedule_enabled = _bool(data.get('schedule_enabled'), bool(row['schedule_enabled']) if row else False)
    interval_hours = _bounded_int(
        data.get('interval_hours'), int(row['interval_hours'] or 24) if row else 24,
        1, 24 * 30,
    )
    next_sync = now if schedule_enabled else None
    name_default = 'WebDAV' if provider_type == 'webdav' else 'S3 Compatible Storage'

    db = get_db()
    cursor = db.conn.cursor()
    cursor.execute('''
        INSERT INTO config_vault_providers
        (id, type, name, enabled, schedule_enabled, interval_hours,
         retention_count, include_secrets, include_users, include_audit,
         settings_encrypted, last_sync, next_sync, last_status, last_error,
         last_object_key, created_at, updated_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            type = excluded.type,
            name = excluded.name,
            enabled = excluded.enabled,
            schedule_enabled = excluded.schedule_enabled,
            interval_hours = excluded.interval_hours,
            retention_count = excluded.retention_count,
            include_secrets = excluded.include_secrets,
            include_users = excluded.include_users,
            include_audit = excluded.include_audit,
            settings_encrypted = excluded.settings_encrypted,
            next_sync = excluded.next_sync,
            updated_at = excluded.updated_at
    ''', (
        provider_type, provider_type,
        str(data.get('name') or (row['name'] if row else name_default))[:80],
        1 if _bool(data.get('enabled'), bool(row['enabled']) if row else True) else 0,
        1 if schedule_enabled else 0,
        interval_hours,
        _bounded_int(
            data.get('retention_count'), int(row['retention_count'] or 10) if row else 10,
            1, 100,
        ),
        1 if _bool(data.get('include_secrets'), bool(row['include_secrets']) if row else False) else 0,
        1 if _bool(data.get('include_users'), bool(row['include_users']) if row else True) else 0,
        1 if _bool(data.get('include_audit'), bool(row['include_audit']) if row else False) else 0,
        db._encrypt(json.dumps(settings, ensure_ascii=False)),
        row['last_sync'] if row else None,
        next_sync,
        row['last_status'] if row else '',
        row['last_error'] if row else '',
        row['last_object_key'] if row else '',
        row['created_at'] if row else now,
        now,
        row['created_by'] if row else (created_by or ''),
    ))
    db.conn.commit()
    return get_provider(provider_type)


def delete_provider(provider_id: str) -> bool:
    with _sync_guard:
        if provider_id in _active_syncs:
            raise ValueError('Wait for the active sync to finish before disconnecting')
    db = get_db()
    cursor = db.conn.cursor()
    cursor.execute('DELETE FROM config_vault_providers WHERE id = ?', (provider_id,))
    changed = cursor.rowcount > 0
    db.conn.commit()
    return changed


def get_status(history_limit: int = 20) -> dict:
    providers = list_providers()
    vault_key, key_id = _vault_key_bundle()
    return {
        'vault_ready': bool(vault_key),
        'key_id': key_id if vault_key else '',
        'instance_id': get_instance_id(),
        'connected_count': len(providers),
        'providers': providers,
        'history': list_history(limit=history_limit),
    }


def _validate_endpoint(settings: dict, url: str) -> str:
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise ValueError('Credentials must not be embedded in the endpoint URL')
    if parsed.query or parsed.fragment:
        raise ValueError('Endpoint URL must not contain a query string or fragment')
    allow_http = bool(settings.get('allow_insecure_http'))
    if parsed.scheme == 'http' and not allow_http:
        raise ValueError('Plain HTTP requires explicit allow_insecure_http opt-in')
    schemes = ('https', 'http') if allow_http else ('https',)
    return sanitize_outbound_url(
        url,
        allowed_schemes=schemes,
        allow_private=bool(settings.get('allow_private_network')),
    )


class WebDAVProvider:
    def __init__(self, settings: dict):
        self.settings = settings
        self.base_url = str(settings.get('url') or '').rstrip('/')
        _validate_endpoint(settings, self.base_url)
        self.auth = None
        if settings.get('username'):
            self.auth = (settings.get('username'), settings.get('password', ''))
        self.verify = bool(settings.get('verify_tls', True))
        if not self.verify:
            logging.warning('[config-vault] WebDAV TLS certificate verification is disabled')

    def _url(self, key: str = '') -> str:
        if not key:
            return self.base_url
        safe_key = '/'.join(quote(part, safe='-_.~') for part in key.strip('/').split('/'))
        url = f'{self.base_url}/{safe_key}'
        _validate_endpoint(self.settings, url)
        return url

    def _request(self, method: str, url: str, **kwargs):
        response = requests.request(
            method, url, auth=self.auth, verify=self.verify, timeout=(10, 60),
            allow_redirects=False, **kwargs
        )
        if 300 <= response.status_code < 400:
            raise RuntimeError('WebDAV redirects are not followed')
        return response

    def test(self):
        response = self._request('PROPFIND', self._url(), headers={'Depth': '0'})
        if response.status_code not in (200, 207):
            raise RuntimeError(f'WebDAV connection failed (HTTP {response.status_code})')

    def put(self, key: str, body: bytes):
        response = self._request(
            'PUT', self._url(key), data=body,
            headers={'Content-Type': 'application/octet-stream'},
        )
        if response.status_code not in (200, 201, 204):
            raise RuntimeError(f'WebDAV upload failed (HTTP {response.status_code})')

    def list(self, prefix: str) -> list:
        response = self._request('PROPFIND', self._url(), headers={'Depth': '1'})
        if response.status_code not in (200, 207):
            raise RuntimeError(f'WebDAV list failed (HTTP {response.status_code})')
        try:
            root = ElementTree.fromstring(response.content)
        except Exception as exc:
            raise RuntimeError('WebDAV returned invalid XML') from exc
        result = []
        for item in root.findall('.//{DAV:}response'):
            href = item.findtext('{DAV:}href') or ''
            name = unquote(href.rstrip('/').rsplit('/', 1)[-1])
            if not name.endswith('.pegabackup'):
                continue
            try:
                size = int(item.findtext('.//{DAV:}getcontentlength') or 0)
            except (TypeError, ValueError):
                size = 0
            result.append({
                'key': name,
                'modified': item.findtext('.//{DAV:}getlastmodified') or '',
                'size': max(0, size),
            })
        return sorted(result, key=lambda item: item['key'], reverse=True)

    def get(self, key: str) -> bytes:
        response = self._request('GET', self._url(key), stream=True)
        if response.status_code != 200:
            response.close()
            raise RuntimeError(f'WebDAV download failed (HTTP {response.status_code})')
        return _read_bounded_response(response)

    def delete(self, key: str):
        response = self._request('DELETE', self._url(key))
        if response.status_code not in (200, 204, 404):
            raise RuntimeError(f'WebDAV delete failed (HTTP {response.status_code})')


def _aws_quote(value: str, safe: str = '-_.~') -> str:
    return quote(str(value), safe=safe)


class S3Provider:
    """Small AWS Signature V4 client for PUT/LIST/DELETE operations."""

    def __init__(self, settings: dict):
        self.settings = settings
        self.endpoint = str(settings.get('endpoint_url') or '').rstrip('/')
        _validate_endpoint(settings, self.endpoint)
        self.bucket = str(settings.get('bucket') or '')
        self.region = str(settings.get('region') or 'us-east-1')
        self.access_key = str(settings.get('access_key_id') or '')
        self.secret_key = str(settings.get('secret_access_key') or '')
        self.session_token = str(settings.get('session_token') or '')
        self.path_style = bool(settings.get('path_style', False))
        self.verify = bool(settings.get('verify_tls', True))
        if not self.verify:
            logging.warning('[config-vault] S3 TLS certificate verification is disabled')
        if not self.bucket or not self.access_key or not self.secret_key:
            raise ValueError('S3 bucket and access credentials are required')
        bucket_pattern = r'[A-Za-z0-9][A-Za-z0-9._-]{0,61}[A-Za-z0-9]'
        if not re.fullmatch(bucket_pattern, self.bucket):
            raise ValueError('S3 bucket contains unsupported characters')

    def _target(self, key: str = ''):
        parsed = urlparse(self.endpoint)
        endpoint_path = parsed.path.rstrip('/')
        encoded_key = '/'.join(_aws_quote(part) for part in key.strip('/').split('/')) if key else ''
        if self.path_style:
            path = f'{endpoint_path}/{_aws_quote(self.bucket)}'
            if encoded_key:
                path += f'/{encoded_key}'
            netloc = parsed.netloc
        else:
            path = endpoint_path or ''
            if encoded_key:
                path += f'/{encoded_key}'
            path = path or '/'
            netloc = f'{self.bucket}.{parsed.netloc}'
        url = urlunparse((parsed.scheme, netloc, path or '/', '', '', ''))
        _validate_endpoint(self.settings, url)
        return url, path or '/'

    def _request(self, method: str, key: str = '', params=None, body: bytes = b'',
                 stream: bool = False):
        params = params or {}
        url, canonical_uri = self._target(key)
        canonical_query = '&'.join(
            f'{_aws_quote(k)}={_aws_quote(v)}' for k, v in sorted(params.items())
        )
        parsed = urlparse(url)
        now = datetime.now(timezone.utc)
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = now.strftime('%Y%m%d')
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            'host': parsed.netloc,
            'x-amz-content-sha256': payload_hash,
            'x-amz-date': amz_date,
        }
        if self.session_token:
            headers['x-amz-security-token'] = self.session_token
        signed_headers = ';'.join(sorted(headers))
        canonical_headers = ''.join(f'{name}:{headers[name].strip()}\n' for name in sorted(headers))
        canonical_request = '\n'.join((
            method, canonical_uri, canonical_query, canonical_headers,
            signed_headers, payload_hash,
        ))
        scope = f'{date_stamp}/{self.region}/s3/aws4_request'
        string_to_sign = '\n'.join((
            'AWS4-HMAC-SHA256', amz_date, scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
        ))

        def sign(key_bytes, message):
            return hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()

        date_key = sign(('AWS4' + self.secret_key).encode('utf-8'), date_stamp)
        region_key = sign(date_key, self.region)
        service_key = sign(region_key, 's3')
        signing_key = sign(service_key, 'aws4_request')
        signature = hmac.new(
            signing_key, string_to_sign.encode('utf-8'), hashlib.sha256
        ).hexdigest()
        request_headers = {name: value for name, value in headers.items() if name != 'host'}
        request_headers['Authorization'] = (
            f'AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )
        full_url = f'{url}?{canonical_query}' if canonical_query else url
        response = requests.request(
            method, full_url, data=body, headers=request_headers,
            verify=self.verify, timeout=(10, 90), allow_redirects=False,
            stream=stream,
        )
        if 300 <= response.status_code < 400:
            raise RuntimeError('S3 redirects are not followed; check region and endpoint')
        return response

    def test(self):
        response = self._request('GET', params={'list-type': '2', 'max-keys': '1'})
        if response.status_code != 200:
            raise RuntimeError(f'S3 connection failed (HTTP {response.status_code})')

    def put(self, key: str, body: bytes):
        response = self._request('PUT', key=key, body=body)
        if response.status_code not in (200, 201, 204):
            raise RuntimeError(f'S3 upload failed (HTTP {response.status_code})')

    def list(self, prefix: str) -> list:
        response = self._request('GET', params={
            'list-type': '2', 'prefix': prefix, 'max-keys': '1000',
        })
        if response.status_code != 200:
            raise RuntimeError(f'S3 list failed (HTTP {response.status_code})')
        try:
            root = ElementTree.fromstring(response.content)
        except Exception as exc:
            raise RuntimeError('S3 returned invalid XML') from exc
        result = []
        for contents in root.findall('.//{*}Contents'):
            key = contents.findtext('{*}Key') or ''
            result.append({
                'key': key,
                'modified': contents.findtext('{*}LastModified') or '',
                'size': _bounded_int(
                    contents.findtext('{*}Size'), 0, 0, MAX_REMOTE_BACKUP_BYTES + 1
                ),
            })
        return sorted(result, key=lambda item: (item['modified'], item['key']), reverse=True)

    def get(self, key: str) -> bytes:
        response = self._request('GET', key=key, stream=True)
        if response.status_code != 200:
            response.close()
            raise RuntimeError(f'S3 download failed (HTTP {response.status_code})')
        return _read_bounded_response(response)

    def delete(self, key: str):
        response = self._request('DELETE', key=key)
        if response.status_code not in (200, 204, 404):
            raise RuntimeError(f'S3 delete failed (HTTP {response.status_code})')


def _adapter(provider: dict):
    if provider['type'] == 'webdav':
        return WebDAVProvider(provider['settings'])
    if provider['type'] == 's3':
        return S3Provider(provider['settings'])
    raise ValueError('Unsupported provider type')


def test_provider(provider_id: str):
    provider = get_provider(provider_id, include_credentials=True)
    if not provider:
        raise ValueError('Provider is not configured')
    _adapter(provider).test()
    return True


def _read_bounded_response(response) -> bytes:
    """Read a streamed provider response without accepting unbounded data."""
    try:
        declared_size = int(response.headers.get('Content-Length') or 0)
    except (TypeError, ValueError):
        declared_size = 0
    if declared_size > MAX_REMOTE_BACKUP_BYTES:
        response.close()
        raise ValueError('Remote backup exceeds the 100 MB safety limit')
    chunks = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_REMOTE_BACKUP_BYTES:
                raise ValueError('Remote backup exceeds the 100 MB safety limit')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        response.close()


_BACKUP_FILENAME_RE = re.compile(
    r'^pegaprox-(?P<key_id>[A-Za-z0-9]+)-(?P<timestamp>\d{8}-\d{6})-'
    r'(?P<backup_id>[A-Za-z0-9]+)\.pegabackup$'
)


def _remote_prefix(provider: dict) -> str:
    if provider['type'] != 's3':
        return ''
    prefix = str(provider['settings'].get('prefix') or 'pegaprox').strip('/')
    return f'{prefix}/' if prefix else ''


def _remote_backup_item(provider: dict, item: dict) -> Optional[dict]:
    object_key = str(item.get('key') or '')
    filename = object_key.rsplit('/', 1)[-1]
    if not object_key or not filename.endswith('.pegabackup'):
        return None
    match = _BACKUP_FILENAME_RE.fullmatch(filename)
    created_at = ''
    key_id = ''
    backup_id = ''
    if match:
        key_id = match.group('key_id')
        backup_id = match.group('backup_id')
        try:
            created_at = datetime.strptime(
                match.group('timestamp'), '%Y%m%d-%H%M%S'
            ).isoformat(timespec='seconds')
        except ValueError:
            created_at = ''

    source_instance = ''
    if provider['type'] == 's3':
        prefix = _remote_prefix(provider)
        relative_key = object_key[len(prefix):] if object_key.startswith(prefix) else object_key
        parts = relative_key.split('/')
        if len(parts) > 1:
            source_instance = parts[0]

    return {
        'provider_id': provider['id'],
        'provider_type': provider['type'],
        'provider_name': provider['name'],
        'object_key': object_key,
        'filename': filename,
        'modified': str(item.get('modified') or ''),
        'created_at': created_at,
        'size_bytes': _bounded_int(
            item.get('size'), 0, 0, MAX_REMOTE_BACKUP_BYTES + 1
        ),
        'key_id': key_id,
        'backup_id': backup_id,
        'source_instance': source_instance,
    }


def list_remote_backups(provider_id: str) -> list:
    """List encrypted backup versions visible through a configured provider."""
    provider = get_provider(provider_id, include_credentials=True)
    if not provider:
        raise ValueError('Provider is not configured')
    objects = _adapter(provider).list(_remote_prefix(provider))
    backups = []
    for item in objects:
        if not isinstance(item, dict):
            continue
        backup = _remote_backup_item(provider, item)
        if backup:
            backups.append(backup)
    return sorted(
        backups,
        key=lambda item: (item['created_at'] or item['modified'], item['object_key']),
        reverse=True,
    )[:1000]


def download_remote_backup(provider_id: str, object_key: str) -> bytes:
    """Download a listed backup object, rejecting arbitrary provider paths."""
    object_key = str(object_key or '')
    if not object_key or len(object_key) > 1500:
        raise ValueError('Backup object key is required')
    provider = get_provider(provider_id, include_credentials=True)
    if not provider:
        raise ValueError('Provider is not configured')
    adapter = _adapter(provider)
    listed = adapter.list(_remote_prefix(provider))
    allowed_keys = {
        str(item.get('key') or '') for item in listed
        if isinstance(item, dict) and str(item.get('key') or '').endswith('.pegabackup')
    }
    if object_key not in allowed_keys:
        raise ValueError('Remote backup was not found')
    body = adapter.get(object_key)
    if len(body) > MAX_REMOTE_BACKUP_BYTES:
        raise ValueError('Remote backup exceeds the 100 MB safety limit')
    return body


def _history_insert(history_id: str, provider_id: str, triggered_by: str):
    db = get_db()
    db.conn.cursor().execute('''
        INSERT INTO config_vault_history
        (id, provider_id, status, started_at, triggered_by)
        VALUES (?, ?, 'running', ?, ?)
    ''', (history_id, provider_id, _now(), triggered_by))
    db.conn.commit()


def _history_finish(history_id: str, *, status: str, object_key: str = '',
                    size_bytes: int = 0, digest: str = '', backup_id: str = '', error: str = ''):
    db = get_db()
    db.conn.cursor().execute('''
        UPDATE config_vault_history
        SET status = ?, completed_at = ?, object_key = ?, size_bytes = ?,
            sha256 = ?, backup_id = ?, error = ?
        WHERE id = ?
    ''', (status, _now(), object_key, size_bytes, digest, backup_id, error[:500], history_id))
    db.conn.commit()


def _provider_result(provider_id: str, *, ok: bool, object_key: str = '', error: str = ''):
    db = get_db()
    row = _provider_row(provider_id)
    interval = int(row['interval_hours'] or 24) if row else 24
    now = datetime.now()
    next_sync = (now + timedelta(hours=interval)).isoformat(timespec='seconds')
    db.conn.cursor().execute('''
        UPDATE config_vault_providers
        SET last_sync = ?, next_sync = ?, last_status = ?, last_error = ?,
            last_object_key = CASE WHEN ? != '' THEN ? ELSE last_object_key END,
            updated_at = ?
        WHERE id = ?
    ''', (
        now.isoformat(timespec='seconds'), next_sync, 'ok' if ok else 'error',
        error[:500], object_key, object_key, _now(), provider_id,
    ))
    db.conn.commit()


def _retention_cleanup(adapter, prefix: str, keep: int, current_key: str):
    try:
        objects = adapter.list(prefix)
        keys = [item['key'] for item in objects if item.get('key') != current_key]
        for key in keys[max(0, keep - 1):]:
            adapter.delete(key)
    except Exception as exc:
        # Upload success is authoritative; retention failure is visible in logs
        # but must not turn a recoverable backup into a reported failure.
        logging.warning("[config-vault] retention cleanup failed: %s", exc)


def _run_sync(provider_id: str, triggered_by: str):
    history_id = uuid.uuid4().hex
    object_key = ''
    history_started = False
    try:
        _history_insert(history_id, provider_id, triggered_by)
        history_started = True
        provider = get_provider(provider_id, include_credentials=True)
        if not provider or not provider.get('enabled'):
            raise ValueError('Provider is disabled or not configured')
        vault_key, key_id = _vault_key_bundle()
        if not vault_key:
            raise ValueError('Vault recovery key is not configured')
        encrypted, payload = create_encrypted_backup(
            password=vault_key,
            exported_by=triggered_by or 'scheduler',
            include_secrets=provider['include_secrets'],
            include_users=provider['include_users'],
            include_audit=provider['include_audit'],
        )
        manifest = payload['manifest']
        instance_id = manifest['instance_id']
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        key_id = key_id or 'legacy'
        filename = f'pegaprox-{key_id}-{timestamp}-{manifest["backup_id"][:8]}.pegabackup'
        if provider['type'] == 's3':
            base_prefix = str(provider['settings'].get('prefix') or 'pegaprox').strip('/')
            object_key = f'{base_prefix}/{instance_id}/{filename}'
            retention_prefix = f'{base_prefix}/{instance_id}/'
        else:
            object_key = filename
            retention_prefix = ''
        adapter = _adapter(provider)
        adapter.put(object_key, encrypted)
        digest = hashlib.sha256(encrypted).hexdigest()
        _history_finish(
            history_id, status='ok', object_key=object_key,
            size_bytes=len(encrypted), digest=digest,
            backup_id=manifest['backup_id'],
        )
        _provider_result(provider_id, ok=True, object_key=object_key)
        _retention_cleanup(
            adapter, retention_prefix, provider['retention_count'], object_key
        )
        log_audit(
            triggered_by or 'scheduler', 'config.vault_sync',
            f'Encrypted configuration uploaded to {provider["type"]} ({len(encrypted)} bytes)',
        )
    except Exception as exc:
        safe_message = str(exc)[:500]
        logging.exception("[config-vault] sync failed for %s", provider_id)
        if history_started:
            _history_finish(history_id, status='error', object_key=object_key, error=safe_message)
        _provider_result(provider_id, ok=False, error=safe_message)
        log_audit(
            triggered_by or 'scheduler', 'config.vault_sync_failed',
            f'Configuration vault sync to {provider_id} failed: {safe_message[:200]}',
        )
    finally:
        with _sync_guard:
            _active_syncs.discard(provider_id)


def start_sync(provider_id: str, triggered_by: str = 'scheduler') -> bool:
    if not _provider_row(provider_id):
        raise ValueError('Provider is not configured')
    with _sync_guard:
        if provider_id in _active_syncs:
            return False
        _active_syncs.add(provider_id)
    thread = threading.Thread(
        target=_run_sync, args=(provider_id, triggered_by), daemon=True,
        name=f'config-vault-{provider_id}',
    )
    thread.start()
    return True


def list_history(limit: int = 50) -> list:
    limit = _bounded_int(limit, 50, 1, 200)
    cursor = get_db().conn.cursor()
    cursor.execute('''
        SELECT h.*, p.name AS provider_name, p.type AS provider_type
        FROM config_vault_history h
        LEFT JOIN config_vault_providers p ON p.id = h.provider_id
        ORDER BY h.started_at DESC LIMIT ?
    ''', (limit,))
    return [dict(row) for row in cursor.fetchall()]


def _due_provider_ids() -> Iterable[str]:
    cursor = get_db().conn.cursor()
    cursor.execute('''
        SELECT id, next_sync FROM config_vault_providers
        WHERE enabled = 1 AND schedule_enabled = 1
    ''')
    now = datetime.now()
    for row in cursor.fetchall():
        try:
            due = not row['next_sync'] or datetime.fromisoformat(row['next_sync']) <= now
        except (TypeError, ValueError):
            due = True
        if due:
            yield row['id']


def _scheduler_loop():
    while _scheduler_running:
        try:
            if get_vault_key():
                for provider_id in list(_due_provider_ids()):
                    try:
                        start_sync(provider_id, 'scheduler')
                    except Exception as exc:
                        logging.warning("[config-vault] could not schedule %s: %s", provider_id, exc)
        except Exception as exc:
            logging.debug("[config-vault] scheduler tick failed: %s", exc)
        time.sleep(60)


def start_scheduler():
    global _scheduler_running
    with _scheduler_guard:
        if _scheduler_running:
            return
        _scheduler_running = True
    threading.Thread(
        target=_scheduler_loop, daemon=True, name='config-vault-scheduler'
    ).start()
    logging.info('[config-vault] scheduler thread started')
