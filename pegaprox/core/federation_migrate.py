"""Linked mode: a guest moved between the clusters of two sites.

Proxmox's remote migration does the copy: the source node opens a tunnel to the target
cluster with an API token of it. Here that token is made for the one migration by the site
that leads the target cluster, after its own checks of the user, and with only the rights
the migration needs there: privilege separation, Sys.Incoming on the root, the guest's
VMID, the target storages and the bridges (ACLs of the token, on roles of its own). Never
the full rights of the account PegaProx uses there, which is what a migration between two
clusters of one instance hands the source node.

The site the user works at leads the migration: it asks the target's site for the token
(mint_target, through the relay as the user, or here for a cluster of its own), hands it
to the remote-migrate route of the source cluster (relayed to the site that leads it, or
dispatched here as the user), follows the task and has the target site drop the token
once the task has ended (transfer_net.drop_token_when_done). The drop is the asking
site's, a signed member call: it only takes rights away, and it has to work when the
user's session or sign-in has run out meanwhile. The tokens a site made are kept in a
host-local file, so a restart forgets none. The token never reaches a browser and is
never logged; PVE refuses it on its own after transfer_net.token_expiry() should nobody
get to drop it.

MK Nov 2026
"""
import json
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import quote

from pegaprox.core import federation as fed
from pegaprox.core import federation_relay as relay

log = logging.getLogger('pegaprox.federation')

TOKEN_PREFIX = 'pegaprox-fedmig-'
_TOKEN_NAME_RE = re.compile(r'pegaprox-fedmig-[0-9]{10}-[0-9a-f]{8}')
_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}')
# the roles the token's ACLs name, with their privileges. A remote migration needs
# Sys.Incoming on / and VM.Allocate on the guest's VMID to open its tunnel (qemu-server
# and pve-container, mtunnel); the disks are allocated on the target storages, and the
# config is checked against the bridges it names
ROLES = {
    'PegaProxFedIncoming': 'Sys.Incoming',
    'PegaProxFedGuest': ('VM.Allocate,VM.Audit,VM.PowerMgmt,VM.Config.Disk,VM.Config.CPU,'
                         'VM.Config.Memory,VM.Config.Network,VM.Config.Options,'
                         'VM.Config.HWType,VM.Config.CDROM,VM.Config.Cloudinit'),
    'PegaProxFedStorage': 'Datastore.AllocateSpace,Datastore.Audit',
    'PegaProxFedNet': 'SDN.Use',
}
MAX_TARGETS = 16
DROP_PATH = '/api/federation/peer/migration-drop'

# the tokens this site made for migrations into its clusters: name -> who asked for it,
# kept in a host-local file next to the federation's lease file (_minted_file)
_minted = None
_minted_lock = threading.Lock()


def _minted_file():
    return os.path.join(os.path.dirname(os.path.abspath(fed._runtime['lease_file'])),
                        'federation_migration_tokens.json')


def _held():
    """The table of made tokens, read from its file the first time. Call with the lock."""
    global _minted
    if _minted is None:
        try:
            with open(_minted_file()) as fh:
                got = json.load(fh)
            _minted = {k: v for k, v in got.items()
                       if _TOKEN_NAME_RE.fullmatch(k) and isinstance(v, dict)} \
                if isinstance(got, dict) else {}
        except FileNotFoundError:
            _minted = {}
        except Exception as e:
            log.warning(f'[FED] the migration tokens of this site could not be read: {e}')
            _minted = {}
    return _minted


def _save():
    """Write the table (names, clusters, sites; never a secret). Call with the lock."""
    path = _minted_file()
    tmp = f'{path}.{os.getpid()}.tmp'
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as fh:
            json.dump(_minted or {}, fh)
        os.replace(tmp, path)
    except Exception as e:
        log.warning(f'[FED] the migration tokens of this site could not be kept: {e}')


def reset_for_tests():
    global _minted
    with _minted_lock:
        _minted = None


class MigrationRefused(Exception):
    def __init__(self, status, error, code='FED_MIGRATE'):
        super().__init__(error)
        self.status, self.error, self.code = status, error, code


def _names(value, what):
    """A list of 1 to MAX_TARGETS storage or bridge names."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not 0 < len(value) <= MAX_TARGETS or \
            not all(isinstance(v, str) and _NAME_RE.fullmatch(v) for v in value):
        raise MigrationRefused(400, f'{what} is a list of up to {MAX_TARGETS} names')
    return list(dict.fromkeys(value))


def _vmid(value, what='vmid'):
    # a whole number or its digits: int() would make 100.9 into 100, another guest's VMID
    if isinstance(value, bool) or not isinstance(value, (int, str)) or \
            (isinstance(value, str) and not value.strip().isdigit()):
        raise MigrationRefused(400, f'{what} is a VMID')
    n = int(value)
    if not 100 <= n <= 999999999:
        raise MigrationRefused(400, f'{what} is a VMID')
    return n


def _footprint(value):
    out = {}
    for key, cap in (('cores', 4096), ('memory_gb', 65536), ('disk_gb', 10 ** 7)):
        v = (value or {}).get(key, 0) if isinstance(value, dict) else 0
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= cap:
            raise MigrationRefused(400, 'footprint holds cores, memory_gb and disk_gb')
        out[key] = v
    return out


# --- the target's site -------------------------------------------------------------------------

def mint_target(cluster_id, data, user, username, sender=''):
    """The target half of a migration into `cluster_id` of this site, asked by `username`
    (`user` the identity its rights are judged on) from member `sender`, '' for a migration
    this site leads itself. Checks the user as a
    migration between two clusters of this site would, holds the tenant quota, makes the
    token and answers {endpoint, token_name, target_vmid, transfer_network}, and tunnel, the
    migration tunnel version of the target node, when it could be read. Raises
    MigrationRefused."""
    from pegaprox.globals import cluster_managers
    from pegaprox.utils.sanitization import validate_hostname
    from pegaprox.api.helpers import caller_is_scoped
    from pegaprox.utils.rbac import acts_as_admin, check_tenant_vmid
    if not isinstance(data, dict):
        raise MigrationRefused(400, 'JSON object required')
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        raise MigrationRefused(404, 'Cluster not found')
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        raise MigrationRefused(400, 'Only a Proxmox VE cluster takes a guest from another site')
    if not getattr(mgr, 'is_connected', False):
        raise MigrationRefused(503, 'The target cluster is not connected')
    node = data.get('target_node')
    if not isinstance(node, str) or not validate_hostname(node):
        raise MigrationRefused(400, 'target_node is a node of the target cluster')
    vm_type = data.get('vm_type')
    if vm_type not in ('qemu', 'lxc'):
        raise MigrationRefused(400, 'vm_type is qemu or lxc')
    vmid = _vmid(data.get('target_vmid') or data.get('vmid'))
    # the guest arrives under this VMID: the token's rights on it must not be rights on a
    # guest that is there already
    _vmid_free(mgr, vmid)
    storages = _names(data.get('storages'), 'storages')
    bridges = _names(data.get('bridges'), 'bridges')
    footprint = _footprint(data.get('footprint'))
    source = str(data.get('source') or '')[:120]
    if caller_is_scoped(user, cluster_id):
        # the token acts on any node and storage the body names: reaching the cluster
        # through one guest or pool is no standing to place one there
        raise MigrationRefused(403, 'Access denied to the target cluster')
    if not acts_as_admin(user):
        from pegaprox.utils.rbac import DEFAULT_TENANT_ID
        ok, msg = check_tenant_vmid(user.get('tenant_id') or DEFAULT_TENANT_ID, vmid)
        if not ok:
            raise MigrationRefused(403, msg)
    # MK Nov 2026 - a PVE 9.3 source refuses an older target in the task, once the VMID is
    # reserved here: refused before the token when the asking site sent the source's tunnel
    # version, and ours goes back for the source's site to compare (core/migration_tunnel.py)
    from pegaprox.core import migration_tunnel
    landing = migration_tunnel.landing_nodes(mgr, node)
    why = migration_tunnel.refusal_from(migration_tunnel.known(data.get('source_tunnel')),
                                        f"the source node ({source or 'the other site'})",
                                        vm_type, mgr, landing)
    if why:
        raise MigrationRefused(409, why, migration_tunnel.CODE)
    name = f'{TOKEN_PREFIX}{int(time.time())}-{secrets.token_hex(4)}'
    # Proxmox VE reserves nothing for the nextid answer above: two migrations to the same
    # VMID would both get a token for it, and the second one rights on the first one's guest.
    # A token not dropped holds its VMID until Proxmox VE lets it run out.
    until = _expiry()
    with _minted_lock:
        now = time.time()
        if any(h.get('cluster_id') == cluster_id and h.get('vmid') == vmid
               and (h.get('until') or 0) > now for h in _held().values()):
            raise MigrationRefused(409, f'VMID {vmid} is taken on the target cluster by a '
                                        'migration under way - choose another one',
                                   'FED_MIGRATE_VMID')
        _held()[name] = {'cluster_id': cluster_id, 'vmid': vmid, 'sender': sender,
                         'user': username, 'at': now, 'until': until, 'making': True}
    try:
        granted = _mint(mgr, cluster_id, user, username, name, node, vm_type, vmid, storages,
                        bridges, footprint, source)
    except BaseException:
        with _minted_lock:
            if (_held().get(name) or {}).get('making'):
                _held().pop(name, None)
        raise
    tunnel = migration_tunnel.lowest(mgr, landing, vm_type)
    if tunnel is not None:
        granted['tunnel'] = tunnel
    return granted


def _mint(mgr, cluster_id, user, username, name, node, vm_type, vmid, storages, bridges,
          footprint, source):
    from pegaprox.api.helpers import tenant_quota_gate
    from pegaprox.utils.rbac import landing_adds, quota_tenant
    from pegaprox.core import transfer_net
    # the quota hold goes with the token: released when it is dropped (drop_target)
    qerr, qwarn = tenant_quota_gate(
        user, f'migration of {vm_type} {vmid} from another site',
        lambda: landing_adds(quota_tenant(user), cluster_id, footprint),
        cluster=getattr(mgr.config, 'name', cluster_id),
        hold={'cluster_id': cluster_id, 'vmid': vmid, 'key': f'fedmig:{name}'})
    if qerr:
        body = qerr[0].get_json(silent=True) if isinstance(qerr, tuple) else None
        raise MigrationRefused(403, (body or {}).get('error') or 'The tenant quota refuses it',
                               'QUOTA_EXCEEDED')
    try:
        token = _make_token(mgr, name, vmid, storages, bridges)
    except BaseException:
        _release_hold(name)
        raise
    try:
        route = transfer_net.migration_route(mgr, node)
        if route and route.get('host'):
            where = {'host': route['host'], 'fingerprint': route['fingerprint']}
        else:
            where = mgr.get_cluster_fingerprint()
            if not where.get('success'):
                raise MigrationRefused(502, 'The certificate of the target cluster could not be '
                                            'read: ' + str(where.get('error') or '')[:200])
        transfer_net.report_fallback(route, getattr(mgr, 'logger', None), username)
    except BaseException:
        _drop_token(mgr, name)
        _release_hold(name)
        raise
    with _minted_lock:
        _held()[name].pop('making', None)
        _save()
    from pegaprox.utils.audit import log_audit
    log_audit(username, 'federation.migration_target',
              f'Token {name} made for a migration of {vm_type} {vmid}'
              + (f' from {source}' if source else '') + f' to {node}',
              cluster=getattr(mgr.config, 'name', cluster_id))
    out = {'endpoint': transfer_net.endpoint(token, where['host'], where['fingerprint']),
           'token_name': name, 'target_vmid': vmid,
           'transfer_network': transfer_net.describe(route)}
    if qwarn:
        out['quota_warning'] = qwarn
    return out


def _make_token(mgr, name, vmid, storages, bridges):
    """A privilege-separated API token of the cluster's PegaProx account with the ACLs one
    migration needs; dropped again when any step fails."""
    base = f'https://{mgr.host}:{mgr.api_port}/api2/json'
    for roleid, privs in ROLES.items():
        r = mgr._api_post(f'{base}/access/roles', data={'roleid': roleid, 'privs': privs})
        if r.status_code != 200:
            # there already: its privileges as this release wants them
            r = mgr._api_put(f'{base}/access/roles/{roleid}', data={'privs': privs})
            if r.status_code != 200:
                raise MigrationRefused(502, 'The target cluster refused the roles of a migration '
                                            'token - its PegaProx account needs '
                                            'Permissions.Modify and Sys.Modify: '
                                            + _pve_error(r))
    # the way past PVE's rule that a token makes no token (#1389)
    r, why = mgr._token_request('POST', name, {'privsep': 1, 'expire': _expiry(),
                                               'comment': 'PegaProx migration from another site'})
    if r is None:
        raise MigrationRefused(409, 'The target cluster made no migration token: ' + why)
    if r.status_code != 200:
        raise MigrationRefused(502, 'The target cluster made no migration token: ' + _pve_error(r))
    data = (r.json() or {}).get('data') or {}
    token = {'token_id': data.get('full-tokenid') or f'{mgr._token_owner()}!{name}',
             'token_value': data.get('value') or '', 'token_name': name}
    acls = [('/', 'PegaProxFedIncoming', 0), (f'/vms/{vmid}', 'PegaProxFedGuest', 1)]
    acls += [(path, 'PegaProxFedNet', 1) for path in _bridge_paths(mgr, base, bridges)]
    acls += [(f'/storage/{s}', 'PegaProxFedStorage', 1) for s in storages]
    try:
        for path, role, propagate in acls:
            r = mgr._api_put(f'{base}/access/acl', data={'path': path, 'roles': role,
                                                        'tokens': token['token_id'],
                                                        'propagate': propagate})
            if r.status_code != 200:
                raise MigrationRefused(502, f'The target cluster refused the right {role} on '
                                            f'{path} for the migration token: ' + _pve_error(r))
        if not token['token_value']:
            raise MigrationRefused(502, 'The target cluster made a migration token without '
                                        'its secret')
    except BaseException:
        _drop_token(mgr, name)
        raise
    return token


def _vmid_free(mgr, vmid):
    """MigrationRefused unless Proxmox VE says `vmid` is free on the cluster (its nextid
    call refuses a taken one)."""
    try:
        r = mgr._api_get(f'https://{mgr.host}:{mgr.api_port}/api2/json/cluster/nextid?vmid={vmid}')
    except Exception as e:
        raise MigrationRefused(502, f'The target cluster could not say whether VMID {vmid} is '
                                    f'free: {type(e).__name__}')
    if r.status_code == 400:
        raise MigrationRefused(409, f'VMID {vmid} is taken on the target cluster - choose '
                                    'another one', 'FED_MIGRATE_VMID')
    if r.status_code != 200:
        raise MigrationRefused(502, f'The target cluster could not say whether VMID {vmid} is '
                                    'free: ' + _pve_error(r))


def _bridge_paths(mgr, base, bridges):
    """The ACL paths of the bridges the guest is put on: a vnet of the cluster's SDN in its
    zone, any other bridge in the zone of plain bridges."""
    zones = {}
    try:
        r = mgr._api_get(f'{base}/cluster/sdn/vnets')
        if r.status_code == 200:
            for v in (r.json() or {}).get('data') or []:
                if isinstance(v, dict) and isinstance(v.get('vnet'), str) \
                        and isinstance(v.get('zone'), str) and _NAME_RE.fullmatch(v['zone']):
                    zones[v['vnet']] = v['zone']
    except Exception as e:
        log.info(f'[FED] the SDN vnets of the target cluster could not be read ({e}): plain '
                 'bridges assumed')
    return [f'/sdn/zones/{zones.get(b, "localnetwork")}/{b}' for b in bridges]


def _release_hold(name):
    try:
        from pegaprox.utils.rbac import quota_release_key
        quota_release_key(f'fedmig:{name}')
    except Exception as e:
        log.debug(f'[FED] quota hold of {name}: {e}')


def _expiry():
    from pegaprox.core import transfer_net
    return transfer_net.token_expiry()


def _pve_error(resp):
    try:
        body = resp.json() or {}
        said = body.get('errors') or body.get('message')
    except Exception:
        said = None
    return str(said or getattr(resp, 'text', '') or f'HTTP {resp.status_code}')[:300]


def _drop_token(mgr, name):
    try:
        res = mgr.delete_api_token(name)
    except Exception as e:
        res = {'success': False, 'error': str(e)}
    if not res.get('success'):
        log.warning(f'[FED] migration token {name} could not be dropped: {res.get("error")}')
    return bool(res.get('success'))


def drop_target(cluster_id, name, sender=''):
    """Drop a token mint_target made, for the member that asked for it ('' for this site),
    and the quota hold that came with it. False when there is no such token here (dropped
    already, or never that member's)."""
    from pegaprox.globals import cluster_managers
    if not isinstance(name, str) or not _TOKEN_NAME_RE.fullmatch(name):
        return False
    with _minted_lock:
        rec = _held().get(name)
        if not rec or (rec.get('cluster_id'), rec.get('sender')) != (cluster_id, sender):
            return False
        _minted.pop(name, None)
        _save()
    mgr = cluster_managers.get(cluster_id)
    if mgr is None or not _drop_token(mgr, name):
        with _minted_lock:
            _held()[name] = rec
            _save()
        return False
    _release_hold(name)
    return True


# --- the site the user works at ----------------------------------------------------------------

class _LocalTarget:
    def __init__(self, cluster_id):
        self.cluster_id = cluster_id

    def delete_api_token(self, name):
        ok = drop_target(self.cluster_id, name)
        return {'success': ok, 'error': None if ok else 'not dropped'}


class _RemoteTarget:
    """The target's site, asked by a signed member call to drop the token it made for this
    one: whoever's session it was, a drop only takes rights away."""

    def __init__(self, iid, raw):
        self.iid, self.raw = iid, raw

    def delete_api_token(self, name):
        status, data, _h = fed.call_peer(self.iid, 'POST', DROP_PATH,
                                         {'cluster_id': self.raw, 'token_name': name},
                                         read_timeout=relay.WRITE_TIMEOUT)
        if status == 200:
            return {'success': True}
        return {'success': False, 'error': f'{status}: {str(data)[:200]}'}


class _RemoteSource:
    """The source cluster at another site, its task read through the relay as the user. An
    account signed in here through its home gets its assertion renewed for every read
    (federation_signin.principal); with the session gone the status is not read, and the
    cleanup drops the token after its blind time."""
    cluster_type = 'proxmox'

    def __init__(self, iid, raw, principal, sid=None):
        self.iid, self.raw, self.principal, self.sid = iid, raw, principal, sid
        self.logger = log

    def get_task_status(self, node, upid):
        principal = self.principal
        if principal.get('asr'):
            from pegaprox.core import federation_signin
            principal = federation_signin.principal(self.sid, principal['user'],
                                                    principal.get('ip'))
            if principal is None:
                return None
            self.principal = principal
        kind, status, _h, body = relay.relay_call(
            self.iid, 'GET',
            f'/api/clusters/{self.raw}/nodes/{node}/tasks/{quote(upid, safe=":@!")}/status',
            principal=principal)
        if kind != 'answer' or status != 200:
            return None
        try:
            data = json.loads(body or b'{}')
        except Exception:
            return None
        return data if isinstance(data, dict) else None


def where(cluster_id):
    """(local manager or None, (raw, iid) of a remote one or None)"""
    from pegaprox.globals import cluster_managers
    if isinstance(cluster_id, str) and cluster_id in cluster_managers:
        return cluster_managers[cluster_id], None
    ids = relay.split_remote(cluster_id)
    if ids and ids[1] != fed.instance_id() and fed.member_record(ids[1]) is not None:
        return None, ids
    return None, None


def follow(target, source, name, upid, what):
    """Drop the token once the task has ended, in a job of its own."""
    from pegaprox.core import ha, transfer_net
    threading.Thread(target=ha.as_job(transfer_net.drop_token_when_done, 'token cleanup'),
                     args=(target, source, name, upid, what), daemon=True,
                     name='federation-migrate-token').start()
