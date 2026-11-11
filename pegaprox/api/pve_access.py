# -*- coding: utf-8 -*-
"""Proxmox VE's own users, groups, roles, permissions (ACL) and realms.

These are the accounts of the cluster itself (what /access of the PVE API holds), not the
users of PegaProx. Every change goes to the cluster with the credentials PegaProx stores
for it, so a change here can hand out any right on the cluster: the routes are for PegaProx
administrators only, and a caller confined to pools or guests is refused (require_unconfined).

Ids arrive from the client and end up in the PVE API path, so each one is checked against
the shape Proxmox itself allows before it is used, and percent-encoded on the way out.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from flask import Blueprint, jsonify, request

from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import (get_connected_manager, check_cluster_access, safe_error,
                                  parse_pve_error, require_unconfined, upstream_failure)

bp = Blueprint('pve_access', __name__)

# user@realm: Proxmox refuses whitespace, ':' and '/' in the name, and names realms like ids.
# \Z, not $: $ also matches before a trailing newline (as in sanitization.py). No ',' or ';'
# either: those separate the entries of a list PVE gets, so 'x,root@pam' would be two users
_USERID = r'[^\s:/@,;]{1,60}@[A-Za-z][A-Za-z0-9._-]{0,31}'
USERID_RE = re.compile(r'^' + _USERID + r'\Z')
TOKENID_RE = re.compile(r'^' + _USERID + r'![A-Za-z][A-Za-z0-9._-]{0,63}\Z')
ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
PRIV_RE = re.compile(r'^[A-Za-z][A-Za-z0-9.]{0,63}\Z')
# /, /vms/100, /storage/local, /pool/x, /sdn/zones/z, /mapping/dir/m ...
PATH_RE = re.compile(r'^/(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?\Z')
TEXT_MAX = 256
PROTECTED_USERS = ('root@pam',)


def _bad(msg, status=400):
    return jsonify({'error': msg}), status


def _manager(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    err = require_unconfined(cluster_id)
    if err:
        return None, err
    manager, err = get_connected_manager(cluster_id)
    if err:
        return None, err
    if getattr(manager, 'cluster_type', 'proxmox') != 'proxmox':
        return None, _bad('Users and permissions of the cluster are a Proxmox VE feature')
    return manager, None


def _url(manager, path):
    return f"https://{manager.host}:{manager.api_port}/api2/json/access/{path}"


def _call(manager, method, path, data=None, params=None):
    """(data, None) on success, else (None, (status, message)). No Flask in here: it also runs
    in the worker threads of the read."""
    session = manager._create_session()
    resp = getattr(session, method)(_url(manager, path), data=data, params=params, timeout=15)
    if resp.status_code != 200:
        msg = parse_pve_error(resp.text, 'Proxmox refused the request')
        # A change PVE refuses (bad parameter, an id that exists) comes back as 400 or 500: the
        # request's fault. A read that fails is the cluster's. 401/403 are the stored credentials
        # (UPSTREAM_AUTH); anything else is a broken upstream.
        code = resp.status_code
        if code in (400, 500):
            code = 502 if method == 'get' else 400
        elif code not in (401, 403):
            code = 502
        return None, (code, msg)
    try:
        body = resp.json()
    except ValueError:
        body = None
    if not isinstance(body, dict) or 'data' not in body:
        return None, (502, 'Proxmox sent an answer that is not the JSON it should be')
    return body['data'], None


def _pve(manager, method, path, data=None, params=None):
    """(data, None) on success, else (None, error response)."""
    data, err = _call(manager, method, path, data=data, params=params)
    return (None, upstream_failure(*err)) if err else (data, None)


def _json():
    """The request body as a dict, or None when it is not a JSON object"""
    data = request.get_json(silent=True)
    if data is None:
        return {}
    return data if isinstance(data, dict) else None


def _flag(data, key, default):
    """(bool, None) for a real true/false (or 1/0) in data[key], else (None, message)"""
    value = data.get(key, default)
    if value is None:
        return default, None
    if value is True or value is False:
        return value, None
    if value in (0, 1, '0', '1') and not isinstance(value, float):
        return str(value) == '1', None
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value.lower() == 'true', None
    return None, f'{key} must be true or false'


def _protected(manager):
    """The users this section must not lock out: root@pam, and the user PegaProx itself signs
    in to the cluster as (its password login or the owner of its API token). Without those the
    cluster, and this section, are out of PegaProx's reach."""
    users, tokens = set(PROTECTED_USERS), set()
    cfg = getattr(manager, 'config', None)
    for value in (getattr(cfg, 'user', None), getattr(cfg, 'api_token_user', None)):
        if isinstance(value, str) and value:
            users.add(value.split('!', 1)[0])
            if '!' in value:
                tokens.add(value)
    return users, tokens


def _text(value, name):
    if value is None:
        return '', None
    if not isinstance(value, str) or len(value) > TEXT_MAX or any(c in value for c in '\r\n\x00'):
        return None, f'{name} must be a single line of at most {TEXT_MAX} characters'
    return value.strip(), None


def _id_list(value, regex, name):
    if value in (None, ''):
        return [], None
    if isinstance(value, str):
        value = [v for v in value.split(',') if v]
    if not isinstance(value, list) or len(value) > 200 or not all(isinstance(v, str) and regex.match(v) for v in value):
        return None, f'Invalid {name}'
    return value, None


def _who():
    return getattr(request, 'session', {}).get('user', 'system')


def _q(part):
    return quote(part, safe='@')


# --- read everything ---------------------------------------------------------------------

@bp.route('/api/clusters/<cluster_id>/pve-access', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_pve_access(cluster_id):
    """The users, groups, roles, permissions (ACL) and realms of a Proxmox VE cluster, and every privilege a role can hold"""
    manager, err = _manager(cluster_id)
    if err:
        return err
    try:
        reads = (('users', 'users', {'full': 1}), ('groups', 'groups', None), ('roles', 'roles', None),
                 ('acl', 'acl', None), ('realms', 'domains', None))
        # five independent reads of the cluster: at once, not one after the other
        with ThreadPoolExecutor(max_workers=len(reads)) as ex:
            done = [ex.submit(_call, manager, 'get', path, None, params) for _key, path, params in reads]
            results = [f.result() for f in done]
        out = {}
        for (key, _path, _params), (data, err) in zip(reads, results):
            if err:
                return upstream_failure(*err)
            if data is None:
                data = []
            if not isinstance(data, list):
                return upstream_failure(502, f'Proxmox sent a list of {key} that is not a list')
            out[key] = data
        protected, _tokens = _protected(manager)
        users = []
        for u in out['users']:
            groups = u.get('groups') or []
            if isinstance(groups, str):
                groups = [g for g in groups.split(',') if g]
            users.append({
                'userid': u.get('userid'), 'enable': int(u.get('enable', 1) or 0),
                'expire': int(u.get('expire') or 0), 'firstname': u.get('firstname') or '',
                'lastname': u.get('lastname') or '', 'email': u.get('email') or '',
                'comment': u.get('comment') or '', 'groups': groups, 'realm_type': u.get('realm-type') or '',
                'tokens': [t.get('tokenid') for t in (u.get('tokens') or []) if t.get('tokenid')],
                'protected': u.get('userid') in protected,
            })
        roles = []
        privileges = set()
        for r in out['roles']:
            privs = r.get('privs') or ''
            privs = sorted(p for p in (privs.split(',') if isinstance(privs, str) else privs) if p)
            privileges.update(privs)
            roles.append({'roleid': r.get('roleid'), 'privs': privs, 'special': bool(int(r.get('special') or 0))})
        roles.sort(key=lambda r: (not r['special'], r['roleid'] or ''))
        acl = [{'path': a.get('path'), 'type': a.get('type'), 'ugid': a.get('ugid'), 'roleid': a.get('roleid'),
                'propagate': int(a.get('propagate', 1) or 0)} for a in out['acl']]
        acl.sort(key=lambda a: (a['path'] or '', a['type'] or '', a['ugid'] or ''))
        groups = [{'groupid': g.get('groupid'), 'comment': g.get('comment') or '',
                   'users': [x for x in (g.get('users') or '').split(',') if x] if isinstance(g.get('users'), str)
                   else (g.get('users') or [])} for g in out['groups']]
        realms = [{'realm': d.get('realm'), 'type': d.get('type'), 'comment': d.get('comment') or '',
                   'default': bool(int(d.get('default') or 0)), 'tfa': d.get('tfa') or ''} for d in out['realms']]
        return jsonify({'users': sorted(users, key=lambda u: u['userid'] or ''), 'groups': groups,
                        'roles': roles, 'acl': acl, 'realms': realms, 'privileges': sorted(privileges)})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to read the users and permissions of the cluster')}), 500


# --- users -------------------------------------------------------------------------------

def _user_fields(data, new):
    if not isinstance(data, dict):
        return None, 'Expected a JSON object'
    out = {}
    if new:
        userid = data.get('userid')
        if not isinstance(userid, str) or not USERID_RE.match(userid):
            return None, 'User id must look like name@realm'
        out['userid'] = userid
        password = data.get('password')
        if password not in (None, ''):
            if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
                return None, 'The password must be 8 to 256 characters'
            out['password'] = password
    for key in ('firstname', 'lastname', 'email', 'comment'):
        if key in data:
            value, why = _text(data.get(key), key)
            if why:
                return None, why
            out[key] = value
    if 'email' in out and out['email'] and not re.match(r'^[^@\s]+@[^@\s]+$', out['email']):
        return None, 'Invalid e-mail address'
    if 'groups' in data:
        groups, why = _id_list(data.get('groups'), ID_RE, 'group list')
        if why:
            return None, why
        out['groups'] = groups
    if 'enable' in data:
        enable, why = _flag(data, 'enable', True)
        if why:
            return None, why
        out['enable'] = 1 if enable else 0
    if 'expire' in data:
        try:
            out['expire'] = max(0, int(data.get('expire') or 0))
        except (TypeError, ValueError, OverflowError):
            return None, 'expire is a Unix time, 0 for never'
    return out, None


@bp.route('/api/clusters/<cluster_id>/pve-access/users', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pve_user(cluster_id):
    """Create a Proxmox VE user: {userid, password, firstname, lastname, email, comment, groups, enable, expire}. A password is set for the pve realm only."""
    manager, err = _manager(cluster_id)
    if err:
        return err
    fields, why = _user_fields(_json(), new=True)
    if why:
        return _bad(why)
    body = {k: v for k, v in fields.items() if k != 'groups' and v not in ('', None)}
    if fields.get('groups'):
        body['groups'] = ','.join(fields['groups'])
    if 'password' in body and not fields['userid'].endswith('@pve'):
        return _bad('A password can be set here for users of the pve realm only; '
                    'other realms check passwords themselves (PAM, LDAP, AD, OpenID)')
    try:
        _data, err = _pve(manager, 'post', 'users', data=body)
        if err:
            return err
        log_audit(_who(), 'pve_access.user_created', f"Proxmox user {fields['userid']}"
                  + (f" in groups {','.join(fields['groups'])}" if fields.get('groups') else ''),
                  cluster=manager.config.name)
        return jsonify({'success': True, 'userid': fields['userid']})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to create the user')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/users/<userid>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_pve_user(cluster_id, userid):
    """Change a Proxmox VE user: {firstname, lastname, email, comment, groups, enable, expire}, each optional. groups replaces the list."""
    if not USERID_RE.match(userid or ''):
        return _bad('Invalid user id')
    manager, err = _manager(cluster_id)
    if err:
        return err
    fields, why = _user_fields(_json(), new=False)
    if why:
        return _bad(why)
    protected, _tokens = _protected(manager)
    if userid in protected and fields.get('enable') == 0:
        return _bad(f'{userid} cannot be disabled from here')
    if userid in protected and fields.get('expire'):
        return _bad(f'{userid} cannot be given an expiry date from here')
    body, delete = {}, []
    for k, v in fields.items():
        if k == 'groups':
            body['groups'] = ','.join(v)
        elif v in ('', None) and k in ('firstname', 'lastname', 'email', 'comment'):
            delete.append(k)
        else:
            body[k] = v
    if delete:
        body['delete'] = ','.join(delete)
    if not body:
        return _bad('Nothing to change')
    try:
        _data, err = _pve(manager, 'put', f'users/{_q(userid)}', data=body)
        if err:
            return err
        log_audit(_who(), 'pve_access.user_changed', f"Proxmox user {userid}: {', '.join(sorted(fields))}",
                  cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to change the user')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/users/<userid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_pve_user(cluster_id, userid):
    """Delete a Proxmox VE user, with its API tokens and its permissions"""
    if not USERID_RE.match(userid or ''):
        return _bad('Invalid user id')
    if userid in PROTECTED_USERS:
        return _bad(f'{userid} cannot be deleted')
    manager, err = _manager(cluster_id)
    if err:
        return err
    if userid in _protected(manager)[0]:
        return _bad(f'{userid} is the user PegaProx signs in to this cluster as and cannot be deleted from here')
    try:
        _data, err = _pve(manager, 'delete', f'users/{_q(userid)}')
        if err:
            return err
        log_audit(_who(), 'pve_access.user_deleted', f'Proxmox user {userid}', cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to delete the user')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/users/<userid>/password', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_pve_user_password(cluster_id, userid):
    """Set the password of a Proxmox VE user of the pve realm: {password}"""
    if not USERID_RE.match(userid or ''):
        return _bad('Invalid user id')
    if not userid.endswith('@pve'):
        return _bad('Only users of the pve realm have a password Proxmox keeps')
    data = _json()
    if data is None:
        return _bad('Expected a JSON object')
    password = data.get('password')
    if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
        return _bad('The password must be 8 to 256 characters')
    manager, err = _manager(cluster_id)
    if err:
        return err
    if userid in _protected(manager)[0]:
        return _bad(f'PegaProx signs in to this cluster as {userid}; its password cannot be changed from here')
    try:
        _data, err = _pve(manager, 'put', 'password', data={'userid': userid, 'password': password})
        if err:
            return err
        log_audit(_who(), 'pve_access.password_set', f'Proxmox user {userid}', cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to set the password')}), 500


# --- groups ------------------------------------------------------------------------------

@bp.route('/api/clusters/<cluster_id>/pve-access/groups', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pve_group(cluster_id):
    """Create a Proxmox VE group: {groupid, comment}"""
    manager, err = _manager(cluster_id)
    if err:
        return err
    data = _json()
    if data is None:
        return _bad('Expected a JSON object')
    groupid = data.get('groupid')
    if not isinstance(groupid, str) or not ID_RE.match(groupid):
        return _bad('Invalid group id: letters, digits, dot, dash and underscore')
    comment, why = _text(data.get('comment'), 'comment')
    if why:
        return _bad(why)
    body = {'groupid': groupid}
    if comment:
        body['comment'] = comment
    try:
        _data, err = _pve(manager, 'post', 'groups', data=body)
        if err:
            return err
        log_audit(_who(), 'pve_access.group_created', f'Proxmox group {groupid}', cluster=manager.config.name)
        return jsonify({'success': True, 'groupid': groupid})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to create the group')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/groups/<groupid>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_pve_group(cluster_id, groupid):
    """Change the comment of a Proxmox VE group: {comment}"""
    if not ID_RE.match(groupid or ''):
        return _bad('Invalid group id')
    manager, err = _manager(cluster_id)
    if err:
        return err
    data = _json()
    if data is None:
        return _bad('Expected a JSON object')
    if 'comment' not in data:
        return _bad('Nothing to change')
    comment, why = _text(data.get('comment'), 'comment')
    if why:
        return _bad(why)
    try:
        _data, err = _pve(manager, 'put', f'groups/{_q(groupid)}', data={'comment': comment})
        if err:
            return err
        log_audit(_who(), 'pve_access.group_changed', f'Proxmox group {groupid}', cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to change the group')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/groups/<groupid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_pve_group(cluster_id, groupid):
    """Delete a Proxmox VE group; its members stay, its permissions go"""
    if not ID_RE.match(groupid or ''):
        return _bad('Invalid group id')
    manager, err = _manager(cluster_id)
    if err:
        return err
    try:
        _data, err = _pve(manager, 'delete', f'groups/{_q(groupid)}')
        if err:
            return err
        log_audit(_who(), 'pve_access.group_deleted', f'Proxmox group {groupid}', cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to delete the group')}), 500


# --- roles -------------------------------------------------------------------------------

def _privs(data):
    if data is None:
        return None, 'Expected a JSON object'
    privs, why = _id_list(data.get('privs'), PRIV_RE, 'privilege list')
    if why:
        return None, why
    return sorted(set(privs)), None


def _builtin_role(manager, roleid):
    """(True when Proxmox ships the role, None) or (None, error response) when it cannot tell:
    then nothing is changed"""
    roles, err = _pve(manager, 'get', 'roles')
    if err:
        return None, err
    for r in roles or []:
        if r.get('roleid') == roleid:
            return bool(int(r.get('special') or 0)), None
    return False, None


@bp.route('/api/clusters/<cluster_id>/pve-access/roles', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pve_role(cluster_id):
    """Create a Proxmox VE role: {roleid, privs: [privilege, ...]}"""
    manager, err = _manager(cluster_id)
    if err:
        return err
    data = _json()
    if data is None:
        return _bad('Expected a JSON object')
    roleid = data.get('roleid')
    if not isinstance(roleid, str) or not ID_RE.match(roleid):
        return _bad('Invalid role id: letters, digits, dot, dash and underscore')
    privs, why = _privs(data)
    if why:
        return _bad(why)
    try:
        _data, err = _pve(manager, 'post', 'roles', data={'roleid': roleid, 'privs': ','.join(privs)})
        if err:
            return err
        log_audit(_who(), 'pve_access.role_created', f"Proxmox role {roleid}: {','.join(privs)}"[:500],
                  cluster=manager.config.name)
        return jsonify({'success': True, 'roleid': roleid})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to create the role')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/roles/<roleid>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_pve_role(cluster_id, roleid):
    """Replace the privileges of a Proxmox VE role of your own: {privs: [privilege, ...]}"""
    if not ID_RE.match(roleid or ''):
        return _bad('Invalid role id')
    manager, err = _manager(cluster_id)
    if err:
        return err
    privs, why = _privs(_json())
    if why:
        return _bad(why)
    try:
        builtin, err = _builtin_role(manager, roleid)
        if err:
            return err
        if builtin:
            return _bad(f'{roleid} is a built-in role of Proxmox and cannot be changed')
        _data, err = _pve(manager, 'put', f'roles/{_q(roleid)}', data={'privs': ','.join(privs)})
        if err:
            return err
        log_audit(_who(), 'pve_access.role_changed', f"Proxmox role {roleid}: {','.join(privs)}"[:500],
                  cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to change the role')}), 500


@bp.route('/api/clusters/<cluster_id>/pve-access/roles/<roleid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_pve_role(cluster_id, roleid):
    """Delete a Proxmox VE role of your own"""
    if not ID_RE.match(roleid or ''):
        return _bad('Invalid role id')
    manager, err = _manager(cluster_id)
    if err:
        return err
    try:
        builtin, err = _builtin_role(manager, roleid)
        if err:
            return err
        if builtin:
            return _bad(f'{roleid} is a built-in role of Proxmox and cannot be deleted')
        _data, err = _pve(manager, 'delete', f'roles/{_q(roleid)}')
        if err:
            return err
        log_audit(_who(), 'pve_access.role_deleted', f'Proxmox role {roleid}', cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to delete the role')}), 500


# --- permissions (ACL) -------------------------------------------------------------------

@bp.route('/api/clusters/<cluster_id>/pve-access/acl', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_pve_acl(cluster_id):
    """Grant or remove a role on a path: {path, roles: [roleid], users: [userid], groups: [groupid], tokens: [userid!token], propagate, delete}"""
    manager, err = _manager(cluster_id)
    if err:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad('Expected a JSON object')
    path = data.get('path')
    if not isinstance(path, str) or not PATH_RE.match(path) or '..' in path.split('/'):
        return _bad('Invalid path: it starts with / like /, /vms/100 or /storage/local')
    roles, why = _id_list(data.get('roles'), ID_RE, 'role list')
    if why or not roles:
        return _bad(why or 'Name at least one role')
    users, why = _id_list(data.get('users'), USERID_RE, 'user list')
    if why:
        return _bad(why)
    groups, why = _id_list(data.get('groups'), ID_RE, 'group list')
    if why:
        return _bad(why)
    tokens, why = _id_list(data.get('tokens'), TOKENID_RE, 'token list')
    if why:
        return _bad(why)
    if not (users or groups or tokens):
        return _bad('Name at least one user, group or API token')
    delete, why = _flag(data, 'delete', False)
    if why:
        return _bad(why)
    propagate, why = _flag(data, 'propagate', True)
    if why:
        return _bad(why)
    if delete and 'root@pam' in users and path == '/':
        return _bad('The permissions of root@pam on / cannot be removed from here')
    if delete:
        protected, own_tokens = _protected(manager)
        own = sorted((set(users) & (protected - set(PROTECTED_USERS))) | (set(tokens) & own_tokens))
        if own:
            return _bad(f"PegaProx signs in to this cluster as {', '.join(own)}; "
                        'its permissions cannot be removed from here')
    body = {'path': path, 'roles': ','.join(roles), 'propagate': 1 if propagate else 0}
    if users:
        body['users'] = ','.join(users)
    if groups:
        body['groups'] = ','.join(groups)
    if tokens:
        body['tokens'] = ','.join(tokens)
    if delete:
        body['delete'] = 1
    try:
        _data, err = _pve(manager, 'put', 'acl', data=body)
        if err:
            return err
        who = ', '.join(users + [f'@{g}' for g in groups] + tokens)
        log_audit(_who(), 'pve_access.acl_removed' if delete else 'pve_access.acl_granted',
                  f"{','.join(roles)} on {path} for {who}"[:500], cluster=manager.config.name)
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f'Proxmox ACL change failed: {e}')
        return jsonify({'error': safe_error(e, 'Failed to change the permissions')}), 500
