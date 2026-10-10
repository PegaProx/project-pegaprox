# -*- coding: utf-8 -*-
"""What a Proxmox VE connection may do, and the role that gives it no more - MK Oct 2026

Two answers from one table, conncheck.PRIVILEGE_NEEDS:

recipe()        the pveum commands for a PegaProx role, a dedicated account and an API
                token with privilege separation. CORE are the API features every
                cluster uses, OPTIONAL what a feature adds on top. What no role can give
                (SSH to the nodes, the changes Proxmox keeps for root@pam) is named, not
                granted.

capabilities()  per feature of PegaProx that depends on the connection, whether it works
                with this cluster and what it needs where it does not. The reasons come
                from the places that refuse today: ssh_blocked_reason for SSH,
                ssh_password_for for the paths that sign in by password only,
                pve_root_access for root@pam, password_login for a stored password that is
                no token secret, and the privileges the connection check read.

The privileges are the answer of one GET /access/permissions, the connection check's own
read (conncheck.check_privileges), kept here per cluster for PRIV_FRESH seconds. A
connection check refreshes them, and so does an admin who asks for it; asking for the
matrix alone sends nothing to the cluster. Nothing here is per guest or per node.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone

from pegaprox.core import conncheck

log = logging.getLogger(__name__)

PRIV_FRESH = 3600

# The API features every cluster uses: the role of the recipe has these whatever is picked
CORE = ('monitoring', 'guests', 'power', 'migration', 'consoles', 'snapshots', 'hardware', 'agent',
        'storage', 'disks', 'create', 'clone', 'backups', 'networks', 'pools')
# What a feature adds, in the order the recipe offers them
OPTIONAL = ('uploads', 'nodeConfig', 'nodePower', 'syslog', 'sdn', 'mappings', 'replication', 'haConfig')

# What a role cannot give, and the features behind each
NOT_BY_ROLE = (
    ('ssh', ('nodeShell', 'rollingUpdates', 'smbios', 'customScripts', 'hardening', 'haAgents',
             'transferCheck', 'fileRestoreCt', 'esxiMigration')),
    ('root_pam', ('rawDevices', 'cephOsd')),
    ('password_login', ('guestTerminal', 'crossCluster', 'siteRecovery')),
)

# id, the PRIVILEGE_NEEDS features it uses, what else it needs:
#   ssh            an SSH login to the nodes (key, the cluster's password or a node's own)
#   ssh_password   an SSH password - the path that takes it never uses the key
#   ssh_on         SSH not switched off for the cluster
#   password_login a user name and password, not a token typed in as the user
#   root           root@pam with a password (pve_root_access)
CAPABILITIES = (
    ('consoles', ('consoles',), ()),
    ('guestTerminal', ('consoles',), ('password_login',)),
    ('nodeShell', (), ('ssh',)),
    ('rollingUpdates', ('migration', 'nodeConfig'), ('ssh',)),
    ('smbios', (), ('ssh',)),
    ('customScripts', (), ('ssh',)),
    ('hardening', (), ('ssh',)),
    ('haAgents', (), ('ssh',)),
    ('mappings', ('mappings',), ()),
    ('rawDevices', (), ('root',)),
    ('cephOsd', (), ('root',)),
    ('backups', ('backups', 'disks'), ()),
    ('replication', ('guests', 'replication'), ()),
    ('crossCluster', ('migration', 'create'), ('password_login',)),
    ('siteRecovery', ('migration', 'create', 'power'), ('password_login',)),
    ('nodeCredentials', (), ('ssh_on',)),
    ('transferCheck', (), ('ssh',)),
    ('fileRestoreVm', ('backups', 'agent'), ()),
    ('fileRestoreCt', ('backups',), ('ssh',)),
    ('esxiMigration', ('create', 'disks'), ('ssh_password',)),
)

PVE_RELEASES = (8, 9)
# the guest agent read: VM.Monitor up to PVE 8, VM.GuestAgent.Audit from PVE 9 on
_AGENT_PRIV = {8: 'VM.Monitor', 9: 'VM.GuestAgent.Audit'}

# what goes into the commands: no quote, space or shell character can pass
_USER_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z][A-Za-z0-9._-]{0,31}')
_TOKEN_RE = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,63}')
_ROLE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')

_cache = {}       # cluster id -> (epoch, user, privileges item)
_locks = {}
_guard = threading.Lock()


def privileges_of(features, pve=9):
    """The privileges of these PRIVILEGE_NEEDS features, in table order, each once. Of a
    pair (the agent read) the name the PVE release knows."""
    wanted = set(features)
    out = []
    for privs, _path, feats in conncheck.PRIVILEGE_NEEDS:
        if not wanted.intersection(feats):
            continue
        name = _AGENT_PRIV.get(pve) if len(privs) > 1 else privs[0]
        if name not in privs:
            name = privs[0]
        if name not in out:
            out.append(name)
    return out


def parse_features(raw):
    """The optional features of a ?features= value: all of them without one or for 'all',
    none for an empty one. Raises ValueError for one the recipe does not know."""
    if raw is None:
        return list(OPTIONAL)
    raw = raw.strip()
    if raw.lower() == 'all':
        return list(OPTIONAL)
    picked = [f.strip() for f in raw.split(',') if f.strip()]
    unknown = [f for f in picked if f not in OPTIONAL]
    if unknown:
        raise ValueError(f"unknown feature: {unknown[0][:40]}")
    return [f for f in OPTIONAL if f in picked]


def recipe(features=None, pve=9, user='pegaprox@pve', token='pegaprox', role='PegaProx'):
    """The role, the account and the token of a least-privilege connection, as data and as
    the commands to paste on one node. Raises ValueError for a name that cannot go into
    them."""
    if pve not in PVE_RELEASES:
        raise ValueError('pve must be 8 or 9')
    # fullmatch: '$' alone lets a trailing line break through, a second command when pasted
    if not isinstance(user, str) or not _USER_RE.fullmatch(user):
        raise ValueError('user must look like name@realm')
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise ValueError('token must start with a letter and hold letters, digits, . _ and - only')
    if not isinstance(role, str) or not _ROLE_RE.fullmatch(role) or role.upper().startswith('PVE'):
        raise ValueError('role must hold letters, digits, . _ and - only and not start with PVE')
    picked = list(OPTIONAL) if features is None else [f for f in OPTIONAL if f in features]
    core = privileges_of(CORE, pve)
    privs = privileges_of(list(CORE) + picked, pve)
    token_id = f'{user}!{token}'
    priv_text = ','.join(privs)
    head = [f'pveum role add {role} --privs "{priv_text}"',
            f'pveum user add {user} --comment "PegaProx"']
    account = head + [f'pveum passwd {user}',
                      f'pveum aclmod / --users {user} --roles {role}']
    # privilege separation: the token holds what both the user and its own ACL allow
    with_token = head + [f'pveum aclmod / --users {user} --roles {role}',
                         f'pveum user token add {user} {token} --privsep 1 --comment "PegaProx"',
                         f"pveum aclmod / --tokens '{token_id}' --roles {role}"]
    return {
        'pve': pve, 'role': role, 'user': user, 'token_id': token_id,
        'core': {'features': list(CORE), 'privileges': core},
        'optional': [{'feature': f, 'privileges': [p for p in privileges_of([f], pve) if p not in core],
                      'selected': f in picked} for f in OPTIONAL],
        'privileges': privs,
        'commands': {'account': account, 'token': with_token,
                     'update_role': f'pveum role modify {role} --privs "{priv_text}"'},
        'not_by_role': [{'need': need, 'features': list(feats)} for need, feats in NOT_BY_ROLE],
    }


# --- the privileges a connection holds ---------------------------------------------------

def _lock(cid):
    with _guard:
        lk = _locks.get(cid)
        if lk is None:
            lk = _locks[cid] = threading.Lock()
        return lk


def _user_of(mgr):
    return str(getattr(getattr(mgr, 'config', None), 'user', '') or '')


def remember(cid, mgr, item, now=None):
    """Keep the privileges item of a connection check (one that read the answer)."""
    if not isinstance(item, dict) or item.get('kind') != 'privileges' or item.get('status') not in ('ok', 'warn'):
        return
    item = dict(item, checked_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
    _cache[cid] = (time.time() if now is None else now, _user_of(mgr), item)


def remember_report(cid, mgr, report):
    for item in (report or {}).get('items') or ():
        if isinstance(item, dict) and item.get('kind') == 'privileges':
            remember(cid, mgr, item)


def forget(cid=None):
    if cid is None:
        _cache.clear()
    else:
        _cache.pop(cid, None)


def privileges(cid, mgr, refresh=False, now=None):
    """(privileges item or None, source). Without refresh what the last connection check (or
    refresh) read, while it is fresh and the cluster still logs in as the same user: 'kept',
    else None with 'not_checked' - no request goes out. With refresh one read now: 'read',
    or None with 'not_connected' or 'unreadable'."""
    with _lock(cid):
        at = time.time() if now is None else now
        hit = _cache.get(cid)
        if not refresh:
            if hit is not None and hit[1] == _user_of(mgr) and 0 <= at - hit[0] < PRIV_FRESH:
                return hit[2], 'kept'
            return None, 'not_checked'
        if not getattr(mgr, 'is_connected', False):
            return None, 'not_connected'
        try:
            item = conncheck.check_privileges(mgr)
        except Exception as e:
            log.debug(f"[pve_access] {cid}: privileges not read: {e}")
            return None, 'unreadable'
        if item.get('status') in ('ok', 'warn'):
            remember(cid, mgr, item, now=at)
            return _cache[cid][2], 'read'
        return None, 'unreadable'


# --- what the connection may do ----------------------------------------------------------

def password_login(config):
    """'' when the cluster signs in with a user name and a stored password, else why not:
    'token_login' (a token id typed in as the user, its secret is no password) or
    'no_password'. The termproxy ticket and a temporary token on a migration target need
    one; vms.get_termproxy_ticket_api refuses on the same question."""
    user = str(getattr(config, 'user', '') or '')
    if '!' in user:
        return 'token_login'
    if not (getattr(config, 'pass_', None) or getattr(config, 'password', None)):
        return 'no_password'
    return ''


def _own_nodes(cid):
    from pegaprox.core import node_creds
    try:
        return sorted(node_creds.secrets_of(cid))
    except Exception:
        return []


def _ssh(mgr, cid):
    from pegaprox.utils.ssh import ssh_blocked_for, ssh_password_for
    blocked = ssh_blocked_for(mgr)
    if blocked == 'SSH_DISABLED':
        return 'no', [{'code': 'ssh_disabled'}]
    if blocked:
        return 'no', [{'code': 'ssh_no_credentials'}]
    cfg = mgr.config
    if getattr(cfg, 'ssh_key', '') or ssh_password_for(cfg):
        return 'yes', []
    # nothing for the cluster as a whole: the nodes with a root password of their own (#1136)
    return 'partial', [{'code': 'ssh_some_nodes', 'nodes': _own_nodes(cid)}]


def _ssh_password(mgr, cid):
    from pegaprox.utils.ssh import ssh_password_for
    cfg = mgr.config
    if bool(getattr(cfg, 'ssh_disabled', False)):
        return 'no', [{'code': 'ssh_disabled'}]
    if ssh_password_for(cfg):
        return 'yes', []
    own = _own_nodes(cid)
    if own:
        return 'partial', [{'code': 'ssh_some_nodes', 'nodes': own}]
    return 'no', [{'code': 'ssh_password', 'key': bool(getattr(cfg, 'ssh_key', ''))}]


def _root(mgr):
    probe = getattr(mgr, 'pve_root_access', None)
    info = probe() if callable(probe) else None
    if not isinstance(info, dict):
        return 'unknown', [{'code': 'root_unknown'}]
    if info.get('root'):
        return 'yes', []
    code = {'token': 'root_token', 'not_root': 'root_only', 'no_password': 'root_password'}.get(
        info.get('reason'), 'root_only')
    return 'no', [{'code': code}]


def _privs(features, missing, state):
    """(status, needs) of the privileges of these features."""
    if state != 'read':
        return 'unknown', [{'code': state}]
    status, needs = 'yes', []
    for m in missing:
        if not set(features).intersection(m.get('features') or ()):
            continue
        needs.append({'code': 'priv', 'privs': list(m.get('privs') or ()), 'path': m.get('path'),
                      'partial': bool(m.get('partial'))})
        if m.get('partial'):
            status = 'partial' if status == 'yes' else status
        else:
            status = 'no'
    return status, needs


_ORDER = {'yes': 0, 'partial': 1, 'unknown': 2, 'no': 3}


def capabilities(cid, mgr, priv_item, source):
    """The matrix for one Proxmox VE cluster. priv_item, source: what privileges() gave."""
    if priv_item is not None and priv_item.get('status') in ('ok', 'warn'):
        state, missing = 'read', list(priv_item.get('missing') or ())
    else:
        state = {'not_checked': 'not_checked', 'not_connected': 'not_connected'}.get(source, 'priv_unread')
        missing = []
    cfg = mgr.config
    checks = {
        'ssh': lambda: _ssh(mgr, cid),
        'ssh_password': lambda: _ssh_password(mgr, cid),
        'ssh_on': lambda: (('no', [{'code': 'ssh_disabled'}])
                           if bool(getattr(cfg, 'ssh_disabled', False)) else ('yes', [])),
        'password_login': lambda: (('no', [{'code': password_login(cfg)}])
                                   if password_login(cfg) else ('yes', [])),
        'root': lambda: _root(mgr),
    }
    done = {}
    rows = []
    for fid, feats, extra in CAPABILITIES:
        parts = []
        if feats:
            parts.append(_privs(feats, missing, state))
        for need in extra:
            if need not in done:
                done[need] = checks[need]()
            parts.append(done[need])
        status = max((p[0] for p in parts), key=_ORDER.get) if parts else 'yes'
        needs = [n for p in parts for n in p[1]]
        via = 'ssh' if any(n.startswith('ssh') for n in extra) else 'api'
        rows.append({'id': fid, 'status': status, 'via': via, 'needs': needs})
    info = conncheck.credential_info(mgr)
    user = info.get('user') or ''
    return {
        'login': {
            'type': info.get('type'), 'user': user, 'token_id': info.get('token_id') or '',
            'realm': user.rsplit('@', 1)[1] if '@' in user else '',
            'root': user == 'root@pam', 'has_password': bool(info.get('has_password')),
            'ssh_key': bool(getattr(cfg, 'ssh_key', '')),
            'ssh_disabled': bool(getattr(cfg, 'ssh_disabled', False)),
            'node_passwords': len(_own_nodes(cid)),
        },
        'privileges': {
            'state': state, 'source': source,
            'checked_at': (priv_item or {}).get('checked_at') if state == 'read' else None,
            'missing': missing,
        },
        'features': rows,
    }


def reset_for_tests():
    _cache.clear()
    _locks.clear()
