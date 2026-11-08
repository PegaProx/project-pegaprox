# -*- coding: utf-8 -*-
"""
Broadcast banners - MK Oct 2026.

An admin writes a short message in the settings, and every signed-in user it is meant
for sees it as a bar at the top of the page (web/src/dashboard.js BroadcastBanners).
A banner goes to everyone, to the users of some tenants or to some roles, and can run
out at a set time. A user closes it in the browser; a changed text is a new revision
and shows again.

The list is one server setting, so a standby gets it with the sync and shows it (#625).
It is written here and nowhere else: helpers.save_server_settings leaves the key alone,
because some routes save back the whole settings dict they read a while earlier and
would put an older list back. On a standby these writes are refused, not handed on to
the active (app.py), like the rest of the settings page.

Plain text. The browser puts it in as text, never as markup, and what has no place in
one line of text is taken out here: control characters and the bidi overrides that
make a text read differently from how it is stored.

Writing takes admin.settings and an account that is not limited to a tenant or to
specific clusters, the bar the HA routes set. A confined admin writes none, not even
for their own tenant: the list is one object for the whole installation, a role
banner reaches into every tenant, and the admin list names the other tenants.
"""
import re
import logging
import secrets
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from pegaprox.core.db import get_db
from pegaprox.models.permissions import BUILTIN_ROLES
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import acting_user

bp = Blueprint('banners', __name__)

BANNERS_KEY = 'broadcast_banners'
TEXT_MAX = 500
MAX_BANNERS = 20
# tenants or roles one banner names
MAX_TARGETS = 50
SEVERITIES = ('info', 'warning', 'critical')
SCOPES = ('everyone', 'tenants', 'roles')
FIELDS = ('text', 'severity', 'expires_at', 'scope', 'tenants', 'roles')

_ID_RE = re.compile(r'[0-9a-f]{16}')
_NAME_RE = re.compile(r'[^\x00-\x1f\x7f]{1,200}')
# what a line of text has no use for: the C0 and C1 controls, and the bidi marks,
# embeddings, overrides and isolates
_DROP_RE = re.compile('[\x00-\x08\x0e-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]')
_SPACE_RE = re.compile(r'\s+')

_write_lock = threading.Lock()


class _Refused(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(at):
    return at.strftime('%Y-%m-%dT%H:%M:%SZ')


def _user():
    return (getattr(request, 'session', None) or {}).get('user', 'system')


def clean_text(value):
    """One line of plain text, or '' for anything that is not text."""
    if not isinstance(value, str):
        return ''
    return _SPACE_RE.sub(' ', _DROP_RE.sub('', value)).strip()


def parse_expiry(value):
    """None for no expiry, else the time in UTC. ValueError for anything that is not
    an ISO 8601 time with a timezone: a time without one means another hour on every
    instance and in every browser."""
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('expires_at is an ISO 8601 time with a timezone, or empty')
    raw = value.strip()
    if raw[-1:] in ('Z', 'z'):
        raw = raw[:-1] + '+00:00'
    try:
        at = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError('expires_at is an ISO 8601 time with a timezone, or empty')
    if at.tzinfo is None:
        raise ValueError('expires_at needs a timezone, for example 2026-10-06T18:00:00Z')
    return at.astimezone(timezone.utc).replace(microsecond=0)


def _names(value, what):
    if not isinstance(value, list):
        raise _Refused(f'{what} is a list')
    out = []
    for name in value:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise _Refused(f'{what} holds a name that is not one')
        if name not in out:
            out.append(name)
    if len(out) > MAX_TARGETS:
        raise _Refused(f'A banner names at most {MAX_TARGETS} {what}')
    return out


def _known_tenants():
    from pegaprox.utils.rbac import load_tenants, store_unavailable
    tenants = load_tenants()
    if store_unavailable(tenants):
        return None
    return {tid: (t.get('name') or tid) for tid, t in tenants.items()}


def _known_roles():
    """{role id: (display name, [tenants that define it])}, the builtins first. None
    when the custom roles cannot be read."""
    from pegaprox.utils.rbac import load_custom_roles, store_unavailable
    custom = load_custom_roles()
    if store_unavailable(custom):
        return None
    out = {r: (r, []) for r in BUILTIN_ROLES}
    for rid, data in (custom.get('global') or {}).items():
        out.setdefault(rid, ((data or {}).get('name') or rid, []))
    for tid, roles in (custom.get('tenants') or {}).items():
        for rid, data in (roles or {}).items():
            out.setdefault(rid, ((data or {}).get('name') or rid, []))[1].append(tid)
    return out


def _validated(data, *, new_expiry=True):
    """The fields of a banner from a request body, checked. Raises _Refused."""
    text = clean_text(data.get('text'))
    if not text:
        raise _Refused('Enter the text of the banner')
    if len(text) > TEXT_MAX:
        raise _Refused(f'The text is longer than {TEXT_MAX} characters')
    severity = data.get('severity') or 'info'
    if severity not in SEVERITIES:
        raise _Refused('severity is info, warning or critical')
    try:
        expires = parse_expiry(data.get('expires_at'))
    except ValueError as e:
        raise _Refused(str(e))
    if expires is not None and new_expiry and expires <= _now():
        raise _Refused('The expiry time has already passed')
    scope = data.get('scope') or 'everyone'
    if scope not in SCOPES:
        raise _Refused('scope is everyone, tenants or roles')
    tenants, roles = [], []
    if scope == 'tenants':
        tenants = _names(data.get('tenants'), 'tenants')
        if not tenants:
            raise _Refused('Pick at least one tenant')
        known = _known_tenants()
        if known is None:
            raise _Refused('The tenants cannot be read right now - try again', 503)
        unknown = [t for t in tenants if t not in known]
        if unknown:
            raise _Refused('Unknown tenant: ' + ', '.join(unknown[:5]))
    elif scope == 'roles':
        roles = _names(data.get('roles'), 'roles')
        if not roles:
            raise _Refused('Pick at least one role')
        known = _known_roles()
        if known is None:
            raise _Refused('The roles cannot be read right now - try again', 503)
        unknown = [r for r in roles if r not in known]
        if unknown:
            raise _Refused('Unknown role: ' + ', '.join(unknown[:5]))
    return {'text': text, 'severity': severity, 'expires_at': _iso(expires) if expires else None,
            'scope': scope, 'tenants': tenants, 'roles': roles}


def _well_formed(entry):
    """A stored entry as the routes use it, or None. The list comes in with the sync too,
    from whatever version the active runs: what does not read as a banner is shown to
    nobody and dropped at the next write."""
    if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or not _ID_RE.fullmatch(entry['id']):
        return None
    text = clean_text(entry.get('text'))
    if not text or len(text) > TEXT_MAX:
        return None
    if entry.get('severity') not in SEVERITIES or entry.get('scope') not in SCOPES:
        return None
    targets = {}
    for key in ('tenants', 'roles'):
        value = entry.get(key) or []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return None
        targets[key] = value
    expires = entry.get('expires_at')
    if expires is not None and not isinstance(expires, str):
        return None
    rev = entry.get('rev')
    if isinstance(rev, bool) or not isinstance(rev, int) or rev < 1:
        return None
    out = {k: entry.get(k) for k in ('created_at', 'created_by', 'updated_at', 'updated_by')}
    out.update(id=entry['id'], text=text, severity=entry['severity'], scope=entry['scope'],
               expires_at=expires or None, rev=rev, **targets)
    return out


def stored_banners():
    """Every banner as stored, or None when the setting cannot be read (a write must
    not start from an empty list then)."""
    try:
        raw = get_db().get_server_setting(BANNERS_KEY, [])
    except Exception as e:
        logging.warning(f"[Banners] could not read the banners: {e}")
        return None
    if not isinstance(raw, list):
        return []
    return [b for b in (_well_formed(e) for e in raw) if b is not None]


def _save(banners):
    get_db().save_server_setting(BANNERS_KEY, banners)


def _expiry(banner):
    """The expiry of a stored banner, None for none. One that does not parse has run out."""
    try:
        return parse_expiry(banner.get('expires_at')), True
    except ValueError:
        return None, False


def _running(banner, now):
    expires, readable = _expiry(banner)
    return readable and (expires is None or expires > now)


def _applies(banner, tenant, role):
    if banner['scope'] == 'everyone':
        return True
    if banner['scope'] == 'tenants':
        return tenant in banner['tenants']
    if banner['scope'] == 'roles':
        return role in banner['roles']
    return False


def _audience():
    """The tenant and the role the scope of a banner is matched against: the role the
    caller acts with (an API token's own, an override in their own tenant), and the
    tenant that defines a tenant role held from the default tenant, as get_user_clusters
    reads it."""
    from pegaprox.utils.rbac import DEFAULT_TENANT_ID, get_user_effective_role, _tenant_defining_role
    user = acting_user() or {}
    role = user.get('effective_role') or get_user_effective_role(user)
    tenant = _tenant_defining_role(role, user.get('tenant_id') or DEFAULT_TENANT_ID)
    return tenant, role


def _preview(text, n=80):
    return text if len(text) <= n else text[:n - 3] + '...'


def _refuse_confined():
    """403 unless the caller sees every cluster and no tenant override lowers them where
    they live, the rule of the HA routes (api/ha.py). Fails closed."""
    try:
        from pegaprox.api.ha import _unconfined
        session = getattr(request, 'session', None) or {}
        unconfined = _unconfined(build_authz_user(session.get('user', ''), session))
    except Exception as e:
        logging.warning(f"[Banners] could not resolve the caller's cluster scope: {e}")
        unconfined = False
    if not unconfined:
        return jsonify({'error': 'Banners are managed by administrators who are not limited '
                                 'to a tenant or to specific clusters'}), 403
    return None


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _admin_view(banner, now):
    expires, readable = _expiry(banner)
    return dict(banner, expired=not readable or (expires is not None and expires <= now))


_ORDER = {'critical': 0, 'warning': 1, 'info': 2}


@bp.route('/api/banners', methods=['GET'])
@require_auth()
def list_my_banners():
    """The broadcast banners meant for the caller that are still running.

    Critical first, the newest first within a severity. Each carries rev, which goes up
    when the text changes: a banner closed at one revision shows again at the next.
    expires_in is the seconds left, null for a banner without an expiry."""
    banners = stored_banners() or []
    if not banners:
        return jsonify({'banners': []})
    now = _now()
    try:
        tenant, role = _audience()
    except Exception as e:
        logging.warning(f"[Banners] could not resolve the audience of {_user()!r}: {e}")
        tenant, role = None, None
    out = []
    for pos, b in enumerate(banners):
        if not _running(b, now):
            continue
        if b['scope'] != 'everyone' and (tenant is None or not _applies(b, tenant, role)):
            continue
        expires, _ = _expiry(b)
        out.append((_ORDER[b['severity']], -pos, {
            'id': b['id'], 'text': b['text'], 'severity': b['severity'], 'rev': b['rev'],
            'expires_at': b['expires_at'],
            'expires_in': int((expires - now).total_seconds()) if expires else None,
        }))
    out.sort(key=lambda x: (x[0], x[1]))
    return jsonify({'banners': [x[2] for x in out]})


@bp.route('/api/settings/banners', methods=['GET'])
@require_auth(perms=['admin.settings'])
def list_banners():
    """Every broadcast banner with its scope, for the settings page.

    Also the tenants and roles a banner can name. Only for administrators who are not
    limited to a tenant or to specific clusters."""
    refusal = _refuse_confined()
    if refusal:
        return refusal
    banners = stored_banners()
    if banners is None:
        return jsonify({'error': 'The banners cannot be read right now'}), 503
    now = _now()
    tenants = _known_tenants() or {}
    roles = _known_roles() or {}
    return jsonify({
        'banners': [_admin_view(b, now) for b in banners],
        'limits': {'text': TEXT_MAX, 'count': MAX_BANNERS, 'targets': MAX_TARGETS},
        'choices': {
            'tenants': [{'id': tid, 'name': name} for tid, name in sorted(tenants.items())],
            'roles': [{'id': rid, 'name': name, 'tenants': sorted(tids)} for rid, (name, tids) in roles.items()],
        },
    })


@bp.route('/api/settings/banners', methods=['POST'])
@require_auth(perms=['admin.settings'])
def create_banner():
    """Add a broadcast banner.

    Body: text (plain text, at most 500 characters), severity (info, warning, critical),
    expires_at (ISO 8601 with a timezone, or empty for none), scope (everyone, tenants,
    roles) with tenants or roles, the ids it goes to."""
    refusal = _refuse_confined()
    if refusal:
        return refusal
    try:
        fields = _validated(_body())
    except _Refused as e:
        return jsonify({'error': str(e)}), e.status
    user, now = _user(), _now()
    with _write_lock:
        banners = stored_banners()
        if banners is None:
            return jsonify({'error': 'The banners cannot be read right now'}), 503
        if len(banners) >= MAX_BANNERS:
            return jsonify({'error': f'There are already {MAX_BANNERS} banners - delete one first'}), 409
        banner = dict(fields, id=secrets.token_hex(8), rev=1, created_at=_iso(now), created_by=user,
                      updated_at=_iso(now), updated_by=user)
        banners.append(banner)
        try:
            _save(banners)
        except Exception as e:
            logging.error(f"[Banners] could not save the banners: {e}")
            return jsonify({'error': 'The banner could not be saved'}), 500
    log_audit(user, 'settings.banner_created',
              f"Banner {banner['id']} created ({banner['severity']}, {banner['scope']}): {_preview(banner['text'])}")
    return jsonify({'success': True, 'banner': _admin_view(banner, now)}), 201


@bp.route('/api/settings/banners/<banner_id>', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def update_banner(banner_id):
    """Change a broadcast banner. The fields the body leaves out stay as they are; a
    changed text raises rev, so users who closed the banner see it again."""
    refusal = _refuse_confined()
    if refusal:
        return refusal
    if not _ID_RE.fullmatch(banner_id or ''):
        return jsonify({'error': 'Banner not found'}), 404
    data = _body()
    user, now = _user(), _now()
    with _write_lock:
        banners = stored_banners()
        if banners is None:
            return jsonify({'error': 'The banners cannot be read right now'}), 503
        at = next((i for i, b in enumerate(banners) if b['id'] == banner_id), None)
        if at is None:
            return jsonify({'error': 'Banner not found'}), 404
        current = banners[at]
        merged = {k: current[k] for k in FIELDS}
        merged.update({k: data[k] for k in FIELDS if k in data})
        try:
            # an expiry the request leaves alone may have passed already: editing the text
            # of a banner that ran out keeps it out
            fields = _validated(merged, new_expiry='expires_at' in data)
        except _Refused as e:
            return jsonify({'error': str(e)}), e.status
        changed = [k for k in FIELDS if fields[k] != current[k]]
        if not changed:
            return jsonify({'success': True, 'banner': _admin_view(current, now), 'changed': []})
        updated = dict(current, **fields, updated_at=_iso(now), updated_by=user)
        if 'text' in changed:
            updated['rev'] = current['rev'] + 1
        banners[at] = updated
        try:
            _save(banners)
        except Exception as e:
            logging.error(f"[Banners] could not save the banners: {e}")
            return jsonify({'error': 'The banner could not be saved'}), 500
    log_audit(user, 'settings.banner_updated',
              f"Banner {banner_id} changed ({', '.join(changed)}): {_preview(updated['text'])}")
    return jsonify({'success': True, 'banner': _admin_view(updated, now), 'changed': changed})


@bp.route('/api/settings/banners/<banner_id>', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def delete_banner(banner_id):
    """Remove a broadcast banner."""
    refusal = _refuse_confined()
    if refusal:
        return refusal
    if not _ID_RE.fullmatch(banner_id or ''):
        return jsonify({'error': 'Banner not found'}), 404
    user = _user()
    with _write_lock:
        banners = stored_banners()
        if banners is None:
            return jsonify({'error': 'The banners cannot be read right now'}), 503
        gone = next((b for b in banners if b['id'] == banner_id), None)
        if gone is None:
            return jsonify({'error': 'Banner not found'}), 404
        try:
            _save([b for b in banners if b['id'] != banner_id])
        except Exception as e:
            logging.error(f"[Banners] could not save the banners: {e}")
            return jsonify({'error': 'The banner could not be deleted'}), 500
    log_audit(user, 'settings.banner_deleted', f"Banner {banner_id} deleted: {_preview(gone['text'])}")
    return jsonify({'success': True})
