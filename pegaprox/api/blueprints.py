# -*- coding: utf-8 -*-
"""
VM blueprints - MK Nov 2026 (#1220).

A blueprint is a library image (api/templates_lib.py, built-in or custom) plus the
hardware and Cloud-Init settings a VM from it gets. Deploying one is a single step onto
any managed PVE cluster: the template the library built from that image on the target
node (or on shared storage) is cloned, or the library builds one there first. The clone
then gets the blueprint's CPU, memory, NICs, Cloud-Init and disk size, and starts if asked.

A PVE template belongs to one cluster. The library image is what every cluster can
fetch, so a blueprint points at the image and each cluster keeps its own template of it.
No password is ever stored in a blueprint; a deploy may send one for that one VM.
"""
import ipaddress
import json
import logging
import re
import secrets
import threading
import uuid
from datetime import datetime
from urllib.parse import quote

from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.audit import log_audit
from pegaprox.utils.sanitization import validate_ssh_user
from pegaprox.api.helpers import check_cluster_access, scope_vm_rows
from pegaprox.core.db import get_db
from pegaprox.api import templates_lib

bp = Blueprint('blueprints', __name__)

NIC_MODELS = ('virtio', 'e1000', 'vmxnet3', 'rtl8139')
IP_MODES = ('dhcp', 'static', 'none')
MAX_NICS = 4

_NAME_CTRL = re.compile(r'[\x00-\x1f\x7f]')
_SAFE = re.compile(r'^[A-Za-z0-9._-]+$')
# what PVE takes as a guest name: a DNS name
_VM_NAME = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$')
# a CPU type only, never the ',flags=' part: the value goes into the cpu option as it is
_CPU = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$')
# Linux keeps interface names to 15 characters
_BRIDGE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,14}$')
_TAG = re.compile(r'^[a-z0-9_][a-z0-9_+.-]{0,31}$')
_DOMAIN = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
                     r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_SSH_KEY = re.compile(r'^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|'
                      r'sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]*)?$')


def _now_iso():
    return datetime.now().isoformat()


def _current_user():
    return templates_lib._current_user()


def _caller():
    return build_authz_user(_current_user(), request.session)


def _is_admin(caller):
    from pegaprox.utils.rbac import acts_as_admin
    return acts_as_admin(caller)


class _Bad(Exception):
    def __init__(self, error, field=None):
        super().__init__(error)
        self.error, self.field = error, field

    def answer(self):
        body = {'error': self.error}
        if self.field:
            body['field'] = self.field
        return jsonify(body), 400


def _int(body, key, low, high, default=None):
    v = body.get(key, default)
    whole = (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, str) and v.strip().isdigit())
    if not whole or not low <= int(v) <= high:
        raise _Bad(f'{key} must be a whole number from {low} to {high}', key)
    return int(v)


def _str(body, key, limit, default=''):
    v = body.get(key, default)
    if v is None:
        v = ''
    if not isinstance(v, str):
        raise _Bad(f'{key} must be text', key)
    v = v.strip()
    if len(v) > limit:
        raise _Bad(f'{key} is longer than {limit} characters', key)
    return v


def _bool(body, key, default=False):
    v = body.get(key, default)
    if not isinstance(v, bool):
        raise _Bad(f'{key} must be true or false', key)
    return v


def _nics(raw):
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_NICS:
        raise _Bad(f'a blueprint has 1 to {MAX_NICS} network devices', 'nics')
    out = []
    for i, nic in enumerate(raw):
        if not isinstance(nic, dict):
            raise _Bad(f'network device {i + 1} is not an object', 'nics')
        bridge = nic.get('bridge')
        if not isinstance(bridge, str) or not _BRIDGE.match(bridge.strip()):
            raise _Bad(f'network device {i + 1}: the bridge is no interface name', 'nics')
        vlan = nic.get('vlan')
        if vlan in ('', None):
            vlan = None
        else:
            if isinstance(vlan, bool):
                raise _Bad(f'network device {i + 1}: the VLAN is a number from 1 to 4094', 'nics')
            try:
                vlan = int(vlan)
            except (TypeError, ValueError):
                raise _Bad(f'network device {i + 1}: the VLAN is a number from 1 to 4094', 'nics')
            if not 1 <= vlan <= 4094:
                raise _Bad(f'network device {i + 1}: the VLAN is a number from 1 to 4094', 'nics')
        model = nic.get('model') or 'virtio'
        if model not in NIC_MODELS:
            raise _Bad(f'network device {i + 1}: the model is one of {", ".join(NIC_MODELS)}', 'nics')
        firewall = nic.get('firewall', False)
        if not isinstance(firewall, bool):
            raise _Bad(f'network device {i + 1}: firewall is true or false', 'nics')
        out.append({'bridge': bridge.strip(), 'vlan': vlan, 'model': model, 'firewall': firewall})
    return out


def _ssh_keys(text):
    keys = [line.strip() for line in text.splitlines() if line.strip()]
    for line in keys:
        if 'PRIVATE KEY' in line:
            raise _Bad('that is a private key; a blueprint takes public keys only', 'sshkeys')
        if not _SSH_KEY.match(line):
            raise _Bad('each line is one OpenSSH public key (ssh-ed25519 AAAA... comment)', 'sshkeys')
    return '\n'.join(keys)


def _nameservers(text):
    parts = text.split()
    if len(parts) > 3:
        raise _Bad('at most three DNS servers', 'nameserver')
    for p in parts:
        try:
            ipaddress.ip_address(p)
        except ValueError:
            raise _Bad(f'{p} is no IP address', 'nameserver')
    return ' '.join(parts)


def _searchdomains(text):
    parts = text.split()
    if len(parts) > 6:
        raise _Bad('at most six search domains', 'searchdomain')
    for p in parts:
        if not _DOMAIN.match(p):
            raise _Bad(f'{p} is no domain name', 'searchdomain')
    return ' '.join(parts)


def _tags(raw):
    if raw in (None, ''):
        return []
    if isinstance(raw, str):
        raw = [t for t in re.split(r'[,;\s]+', raw) if t]
    if not isinstance(raw, list) or len(raw) > 10:
        raise _Bad('at most ten tags', 'tags')
    out = []
    for t in raw:
        if not isinstance(t, str) or not _TAG.match(t.strip().lower()):
            raise _Bad('a tag is lower case letters, digits and _ + . -', 'tags')
        if t.strip().lower() not in out:
            out.append(t.strip().lower())
    return out


def _fields(body):
    """The editable fields of a blueprint from a request body, checked. Raises _Bad."""
    if not isinstance(body, dict):
        raise _Bad('the body is a JSON object')
    name = _str(body, 'name', 64)
    if not name or _NAME_CTRL.search(name):
        raise _Bad('a blueprint needs a name', 'name')
    template_id = body.get('template_id')
    if not isinstance(template_id, str) or not templates_lib._lookup_template(template_id):
        raise _Bad('pick an image from the template library', 'template_id')
    ciuser = _str(body, 'ciuser', 32)
    if ciuser and not validate_ssh_user(ciuser):
        raise _Bad('the Cloud-Init user is letters, digits and ._- only', 'ciuser')
    cpu = _str(body, 'cpu', 64)
    if cpu and not _CPU.match(cpu):
        raise _Bad('the CPU type is a name like host or x86-64-v2-AES', 'cpu')
    ip_mode = body.get('ip_mode', 'dhcp')
    if ip_mode not in IP_MODES:
        raise _Bad('the IP mode is dhcp, static or none', 'ip_mode')
    description = _str(body, 'description', 500)
    if _NAME_CTRL.search(description.replace('\r\n', '\n').replace('\n', ' ')):
        raise _Bad('the description has control characters', 'description')
    return {
        'name': name,
        'description': description,
        'template_id': template_id,
        'cores': _int(body, 'cores', 1, 512, 2),
        'memory': _int(body, 'memory', 64, 4194304, 2048),
        'disk_gb': _int(body, 'disk_gb', 0, 65536, 0),
        'cpu': cpu,
        'nics': _nics(body.get('nics', [{'bridge': 'vmbr0'}])),
        'ciuser': ciuser,
        'sshkeys': _ssh_keys(_str(body, 'sshkeys', 16384)),
        'ip_mode': ip_mode,
        'nameserver': _nameservers(_str(body, 'nameserver', 200)),
        'searchdomain': _searchdomains(_str(body, 'searchdomain', 300)),
        'ciupgrade': _bool(body, 'ciupgrade', True),
        'tags': _tags(body.get('tags')),
        'start': _bool(body, 'start', False),
    }


def _row(r, me='', admin=False):
    tpl = templates_lib._lookup_template(r['template_id'])
    try:
        nics = json.loads(r['nics'] or '[]')
    except ValueError:
        nics = []
    return {
        'id': r['id'],
        'name': r['name'],
        'description': r['description'] or '',
        'template_id': r['template_id'],
        'template_name': tpl['name'] if tpl else '',
        'template_missing': tpl is None,
        'cores': r['cores'],
        'memory': r['memory'],
        'disk_gb': r['disk_gb'],
        'cpu': r['cpu'] or '',
        'nics': nics,
        'ciuser': r['ciuser'] or '',
        'sshkeys': r['sshkeys'] or '',
        'ip_mode': r['ip_mode'] or 'dhcp',
        'nameserver': r['nameserver'] or '',
        'searchdomain': r['searchdomain'] or '',
        'ciupgrade': bool(r['ciupgrade']),
        'tags': [t for t in (r['tags'] or '').split(';') if t],
        'start': bool(r['start']),
        'created_by': r['created_by'] or '',
        'created_at': r['created_at'],
        'updated_at': r['updated_at'],
        'can_edit': bool(me) and ((r['created_by'] or '') == me or admin),
    }


def _get(bp_id):
    return get_db().conn.execute('SELECT * FROM vm_blueprints WHERE id = ?', (bp_id,)).fetchone()


def _store_values(f):
    return (f['name'], f['description'], f['template_id'], f['cores'], f['memory'], f['disk_gb'],
            f['cpu'], json.dumps(f['nics']), f['ciuser'], f['sshkeys'], f['ip_mode'],
            f['nameserver'], f['searchdomain'], int(f['ciupgrade']), ';'.join(f['tags']),
            int(f['start']))


# ──────────────────────────────────────────────────────────────────────────
# Blueprints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/blueprints', methods=['GET'])
@require_auth(perms=['vm.create'])
def list_blueprints():
    """Every blueprint, newest first. One list for every account, like the custom
    images of the template library; editing is the creator's or an admin's."""
    me, admin = _current_user(), _is_admin(_caller())
    rows = get_db().conn.execute('SELECT * FROM vm_blueprints ORDER BY created_at DESC').fetchall()
    return jsonify({'blueprints': [_row(r, me, admin) for r in rows]})


@bp.route('/api/blueprints', methods=['POST'])
@require_auth(perms=['vm.create'])
def create_blueprint():
    """Save a blueprint: template_id (a library image), cores, memory (MB), disk_gb
    (0 keeps the image's size), cpu, nics [{bridge, vlan, model, firewall}], ciuser,
    sshkeys, ip_mode (dhcp/static/none), nameserver, searchdomain, ciupgrade, tags, start."""
    try:
        f = _fields(request.get_json(silent=True))
    except _Bad as e:
        return e.answer()
    base = re.sub(r'[^a-z0-9-]+', '-', f['name'].lower()).strip('-')[:40] or 'bp'
    bp_id = f"bp-{base}-{secrets.token_hex(3)}"
    now = _now_iso()
    db = get_db()
    db.conn.execute('''
        INSERT INTO vm_blueprints
            (name, description, template_id, cores, memory, disk_gb, cpu, nics, ciuser, sshkeys,
             ip_mode, nameserver, searchdomain, ciupgrade, tags, start,
             id, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', _store_values(f) + (bp_id, _current_user(), now, now))
    db.conn.commit()
    log_audit(_current_user(), 'blueprint.created', f"Blueprint '{f['name']}' ({bp_id}) saved")
    return jsonify({'blueprint': _row(_get(bp_id), _current_user(), _is_admin(_caller()))}), 201


def _owned(bp_id):
    """(row, error answer) for a change to blueprint `bp_id` by the caller."""
    row = _get(bp_id)
    if row is None:
        return None, (jsonify({'error': 'not found'}), 404)
    if (row['created_by'] or '') != _current_user() and not _is_admin(_caller()):
        return None, (jsonify({'error': 'only the one who saved this blueprint, or an admin, may change it'}), 403)
    return row, None


@bp.route('/api/blueprints/<bp_id>', methods=['PUT'])
@require_auth(perms=['vm.create'])
def update_blueprint(bp_id):
    """Replace a blueprint's settings (the whole object, as POST takes it)."""
    row, err = _owned(bp_id)
    if err:
        return err
    try:
        f = _fields(request.get_json(silent=True))
    except _Bad as e:
        return e.answer()
    db = get_db()
    db.conn.execute('''
        UPDATE vm_blueprints SET name = ?, description = ?, template_id = ?, cores = ?, memory = ?,
            disk_gb = ?, cpu = ?, nics = ?, ciuser = ?, sshkeys = ?, ip_mode = ?, nameserver = ?,
            searchdomain = ?, ciupgrade = ?, tags = ?, start = ?, updated_at = ?
        WHERE id = ?
    ''', _store_values(f) + (_now_iso(), bp_id))
    db.conn.commit()
    log_audit(_current_user(), 'blueprint.updated', f"Blueprint '{f['name']}' ({bp_id}) changed")
    return jsonify({'blueprint': _row(_get(bp_id), _current_user(), _is_admin(_caller()))})


@bp.route('/api/blueprints/<bp_id>', methods=['DELETE'])
@require_auth(perms=['vm.create'])
def delete_blueprint(bp_id):
    """Remove a blueprint. VMs deployed from it are not touched."""
    row, err = _owned(bp_id)
    if err:
        return err
    db = get_db()
    db.conn.execute('DELETE FROM vm_blueprints WHERE id = ?', (bp_id,))
    db.conn.commit()
    log_audit(_current_user(), 'blueprint.deleted', f"Blueprint '{row['name']}' ({bp_id}) removed")
    return jsonify({'success': True})


# ──────────────────────────────────────────────────────────────────────────
# Where the template comes from
# ──────────────────────────────────────────────────────────────────────────

def _shared_storages(mgr):
    """Storage ids the cluster marks shared; an empty set when that read fails, which
    only means a template gets built on the node itself."""
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/storage")
        if r.status_code == 200:
            return {s.get('storage') for s in (r.json().get('data') or []) if s.get('shared')}
    except Exception as e:
        logging.debug(f"[blueprints] storage list failed: {e}")
    return set()


def find_template(mgr, cluster_id, template_id, node):
    """The template the library built from `template_id` on this cluster that a full
    clone onto `node` can start from: one on that node, else one on shared storage.
    None when there is none, then the deploy builds one on the node first."""
    rows = get_db().conn.execute('''
        SELECT vmid, node, storage FROM cloud_init_deployments
        WHERE cluster_id = ? AND template_id = ? AND status = 'completed' AND vmid IS NOT NULL
        ORDER BY finished_at DESC
    ''', (cluster_id, template_id)).fetchall()
    if not rows:
        return None
    live = {}
    for g in (mgr.get_vm_resources() or []):
        if g.get('type') == 'qemu' and g.get('template') == 1:
            try:
                live[int(g.get('vmid'))] = g
            except (TypeError, ValueError):
                continue
    built = [(r, live[int(r['vmid'])]) for r in rows if int(r['vmid']) in live]
    if not built:
        return None
    shared = None
    for r, g in built:
        if g.get('node') == node:
            if shared is None:
                shared = _shared_storages(mgr)
            return {'vmid': int(r['vmid']), 'node': g.get('node'), 'storage': r['storage'],
                    'shared': r['storage'] in shared}
    shared = _shared_storages(mgr)
    for r, g in built:
        if r['storage'] in shared:
            return {'vmid': int(r['vmid']), 'node': g.get('node'), 'storage': r['storage'], 'shared': True}
    return None


def _pve_cluster(cluster_id):
    """(manager, error answer) for a managed PVE cluster the caller may see."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        return None, (jsonify({'error': 'cluster not found'}), 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, (jsonify({'error': 'blueprints deploy to Proxmox VE clusters only'}), 400)
    return mgr, None


def _member(mgr, node):
    if not isinstance(node, str) or not _SAFE.match(node):
        return False
    nodes = getattr(mgr, 'nodes', None) or {}
    return node in nodes


@bp.route('/api/clusters/<cluster_id>/blueprints/<bp_id>/template', methods=['GET'])
@require_auth(perms=['vm.create'])
def blueprint_template(cluster_id, bp_id):
    """Which template a deploy of this blueprint onto ?node= would clone, or that it
    builds one there first: {template: {vmid, node, storage, shared} | null, build_needed}."""
    mgr, err = _pve_cluster(cluster_id)
    if err:
        return err
    if not _is_admin(_caller()):
        from pegaprox.api.helpers import require_unconfined
        cerr = require_unconfined(cluster_id)
        if cerr:
            return cerr
    row = _get(bp_id)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    node = request.args.get('node', '')
    if not _member(mgr, node):
        return jsonify({'error': 'node is not a member of this cluster', 'field': 'node'}), 400
    found = find_template(mgr, cluster_id, row['template_id'], node)
    return jsonify({'template': found, 'build_needed': found is None})


# ──────────────────────────────────────────────────────────────────────────
# Deploy
# ──────────────────────────────────────────────────────────────────────────

def _ipconfig(raw):
    """A static ipconfig0 as PVE takes it, from ip=<cidr>[,gw=<ip>] and/or
    ip6=<cidr>[,gw6=<ip>]. Raises _Bad."""
    if not isinstance(raw, str) or not raw.strip():
        raise _Bad('a static IP needs an address with prefix, like ip=10.0.0.5/24,gw=10.0.0.1', 'ipconfig0')
    parts = {}
    for item in raw.strip().split(','):
        k, sep, v = item.partition('=')
        if not sep or k not in ('ip', 'gw', 'ip6', 'gw6') or k in parts:
            raise _Bad('ipconfig0 is ip=<address/prefix>[,gw=<address>]', 'ipconfig0')
        parts[k] = v.strip()
    try:
        for fam, ip_key, gw_key in ((4, 'ip', 'gw'), (6, 'ip6', 'gw6')):
            if gw_key in parts and ip_key not in parts:
                raise ValueError
            if ip_key in parts:
                iface = ipaddress.ip_interface(parts[ip_key])
                if iface.version != fam or '/' not in parts[ip_key]:
                    raise ValueError
                if gw_key in parts:
                    gw = ipaddress.ip_address(parts[gw_key])
                    if gw.version != fam or gw not in iface.network:
                        raise ValueError
    except ValueError:
        raise _Bad('ipconfig0 holds an address with prefix and a gateway inside that network', 'ipconfig0')
    if 'ip' not in parts and 'ip6' not in parts:
        raise _Bad('a static IP needs an address with prefix', 'ipconfig0')
    return ','.join(f'{k}={parts[k]}' for k in ('ip', 'gw', 'ip6', 'gw6') if k in parts)


def _free_vmid(mgr, caller, taken_extra=()):
    """The next free VMID: inside the caller's tenant range where one is set, else what
    the cluster hands out. None when the range is full."""
    from pegaprox.utils.rbac import tenant_vmid_range, DEFAULT_TENANT_ID
    start = end = 0
    if not _is_admin(caller):
        start, end = tenant_vmid_range(caller.get('tenant_id') or DEFAULT_TENANT_ID)
    taken = set(taken_extra)
    for g in (mgr.get_vm_resources() or []):
        try:
            taken.add(int(g.get('vmid')))
        except (TypeError, ValueError):
            continue
    if start:
        return next((v for v in range(start, end + 1) if v not in taken), None)
    got = mgr.get_next_vmid()
    if not got.get('success'):
        return None
    vmid = int(got['vmid'])
    while vmid in taken:
        vmid += 1
    return vmid


def _check_vmid(caller, vmid):
    """None, or the 403 answer when a non-admin's VMID leaves their tenant range."""
    if _is_admin(caller):
        return None
    try:
        from pegaprox.utils.rbac import check_tenant_vmid, DEFAULT_TENANT_ID
        ok, msg = check_tenant_vmid(caller.get('tenant_id') or DEFAULT_TENANT_ID, vmid)
    except Exception as e:
        logging.error(f"[vmid-range] blueprint deploy: range check failed, refusing: {e}")
        ok, msg = False, 'Cannot verify the tenant VMID range right now - check the server logs'
    return None if ok else (jsonify({'error': msg}), 403)


def _update(dep_id, **fields):
    sets, vals = [], []
    for key in ('status', 'step', 'progress', 'error', 'template_vmid', 'build_dep_id', 'finished_at'):
        if key in fields:
            sets.append(f'{key} = ?')
            vals.append(fields[key])
    if 'log' in fields:
        sets.append("log = COALESCE(log, '') || ?")
        vals.append(f"[{_now_iso()}] {fields['log']}\n")
    if not sets:
        return
    try:
        db = get_db()
        db.conn.execute(f"UPDATE blueprint_deployments SET {', '.join(sets)} WHERE id = ?", vals + [dep_id])
        db.conn.commit()
    except Exception as e:
        logging.warning(f"[blueprints] deployment update failed: {e}")


def vm_config(bp_row, ipconfig0='', cipassword=''):
    """The config the clone gets from the blueprint, in PVE's parameter names."""
    nics = json.loads(bp_row['nics'] or '[]')
    cfg = {'cores': int(bp_row['cores']), 'memory': int(bp_row['memory'])}
    if bp_row['cpu']:
        cfg['cpu'] = bp_row['cpu']
    for i, nic in enumerate(nics):
        net = f"{nic['model']},bridge={nic['bridge']}"
        if nic.get('vlan'):
            net += f",tag={int(nic['vlan'])}"
        if nic.get('firewall'):
            net += ',firewall=1'
        cfg[f'net{i}'] = net
    if bp_row['ip_mode'] == 'dhcp':
        for i in range(len(nics)):
            cfg[f'ipconfig{i}'] = 'ip=dhcp'
    elif bp_row['ip_mode'] == 'static' and ipconfig0:
        cfg['ipconfig0'] = ipconfig0
    if bp_row['ciuser']:
        cfg['ciuser'] = bp_row['ciuser']
    if bp_row['sshkeys']:
        # PVE takes the keys URL-encoded, a space as %20
        cfg['sshkeys'] = quote(bp_row['sshkeys'] + '\n', safe='')
    if cipassword:
        cfg['cipassword'] = cipassword
    if bp_row['nameserver']:
        cfg['nameserver'] = bp_row['nameserver']
    if bp_row['searchdomain']:
        cfg['searchdomain'] = bp_row['searchdomain']
    if not bp_row['ciupgrade']:
        # PVE upgrades the packages on first boot unless told not to
        cfg['ciupgrade'] = 0
    if bp_row['tags']:
        cfg['tags'] = bp_row['tags']
    return cfg


_SIZE = re.compile(r'(?:^|,)size=(\d+(?:\.\d+)?)([KMGT]?)(?:,|$)')


def disk_gb_of(drive):
    """The size of a drive line ('local-lvm:vm-101-disk-0,size=3584M') in GiB, or None."""
    m = _SIZE.search(drive or '')
    if not m:
        return None
    n = float(m.group(1))
    return n * {'K': 1 / 1048576, 'M': 1 / 1024, 'G': 1, 'T': 1024, '': 1 / 1073741824}[m.group(2)]


def run_deploy(dep_id, cluster_id, bp_row, node, storage, vmid, name, template, build,
               ipconfig0, cipassword, start, user):
    """The deploy job: the template (built first where needed), the full clone, the
    blueprint's settings, the disk size, the start."""
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        _update(dep_id, status='failed', error='cluster not found', finished_at=_now_iso())
        return
    try:
        _update(dep_id, status='running', progress=2)
        if build:
            _update(dep_id, step='template', build_dep_id=build['dep_id'], template_vmid=build['vmid'],
                    log=f"no template of this image on {node} yet: building one as VMID {build['vmid']}")
            templates_lib._run_deploy(build['dep_id'], cluster_id, node, bp_row['template_id'], storage,
                                      build['vmid'], build['name'])
            done = get_db().conn.execute('SELECT status, error FROM cloud_init_deployments WHERE id = ?',
                                         (build['dep_id'],)).fetchone()
            if not done or done['status'] != 'completed':
                raise RuntimeError(f"building the template failed: {(done and done['error']) or 'unknown'}")
            template = {'vmid': build['vmid'], 'node': node, 'storage': storage, 'shared': False}
            _update(dep_id, progress=45, log=f"template {build['vmid']} ready")
        else:
            _update(dep_id, template_vmid=template['vmid'],
                    log=f"cloning template {template['vmid']} on {template['node']}")

        _update(dep_id, step='clone', progress=50)
        res = mgr.clone_vm(node=template['node'], vmid=template['vmid'], vm_type='qemu', newid=vmid,
                           name=name, full=True,
                           target_node=node if template['node'] != node else None,
                           target_storage=storage, description=f"From blueprint {bp_row['name']}")
        if not res.get('success'):
            raise RuntimeError(f"clone refused: {str(res.get('error'))[:300]}")
        upid = res.get('data')
        if upid:
            from pegaprox.api.helpers import register_task_user
            register_task_user(upid, user, cluster_id)
            if not mgr._wait_for_task(template['node'], upid, timeout=3600):
                raise RuntimeError('the clone task did not finish OK, see its task log')
        _update(dep_id, progress=75, log=f"VM {vmid} cloned onto {node}")

        _update(dep_id, step='configure')
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        cfg = vm_config(bp_row, ipconfig0, cipassword)
        r = mgr._api_post(url, data=cfg)
        if r.status_code != 200:
            raise RuntimeError(f"applying the blueprint refused: {r.text[:300]}")
        _update(dep_id, progress=85, log='CPU, memory, network and Cloud-Init set: '
                + ', '.join(k for k in cfg if k != 'cipassword'))

        want = int(bp_row['disk_gb'] or 0)
        if want:
            _update(dep_id, step='resize')
            got = mgr.get_vm_config(node, vmid, 'qemu')
            have = disk_gb_of(((got or {}).get('config') or {}).get('scsi0', '')) if got.get('success') else None
            if have is not None and want > have + 0.01:
                rr = mgr.resize_vm_disk(node, vmid, 'qemu', 'scsi0', f'{want}G')
                if not rr.get('success'):
                    raise RuntimeError(f"growing the disk refused: {str(rr.get('error'))[:300]}")
                _update(dep_id, log=f"disk grown to {want} GB")
            elif have is not None:
                _update(dep_id, log=f"the image is already {have:.1f} GB, the disk stays")
            else:
                _update(dep_id, log='the disk size could not be read, the disk stays as cloned')
        _update(dep_id, progress=92)

        if start:
            _update(dep_id, step='start')
            sr = mgr.vm_action(node, vmid, 'qemu', 'start')
            if not sr.get('success'):
                raise RuntimeError(f"start refused: {str(sr.get('error'))[:300]}")
            _update(dep_id, log=f"VM {vmid} started")
        try:
            from pegaprox.utils.realtime import push_immediate_update
            push_immediate_update(cluster_id, delay=0.5)
        except Exception:
            pass
        _update(dep_id, status='completed', step='done', progress=100,
                log=f"{name} (VMID {vmid}) is ready", finished_at=_now_iso())
    except Exception as e:
        logging.warning(f"[blueprints] deploy {dep_id} failed: {e}")
        _update(dep_id, status='failed', error=str(e)[:500], log=f"FAILED: {e}", finished_at=_now_iso())


@bp.route('/api/blueprints/<bp_id>/deploy', methods=['POST'])
@require_auth(perms=['vm.create'])
def deploy_blueprint(bp_id):
    """One VM from a blueprint. Body: {cluster_id, node, storage, name, vmid?,
    ipconfig0? (only and required with ip_mode static), cipassword?, start?}.
    Clones the library's template of the image on that node or shared storage, or
    builds one on the node first; 202 with the deployment to poll."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'the body is a JSON object'}), 400
    row = _get(bp_id)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    tpl = templates_lib._lookup_template(row['template_id'])
    if tpl is None:
        return jsonify({'error': 'the image of this blueprint is no longer in the template library',
                        'field': 'template_id'}), 409
    cluster_id = body.get('cluster_id')
    if not isinstance(cluster_id, str):
        return jsonify({'error': 'pick a cluster', 'field': 'cluster_id'}), 400
    mgr, err = _pve_cluster(cluster_id)
    if err:
        return err
    node, storage, name = body.get('node'), body.get('storage'), body.get('name')
    if not _member(mgr, node):
        return jsonify({'error': 'node is not a member of this cluster', 'field': 'node'}), 400
    if not isinstance(storage, str) or not _SAFE.match(storage):
        return jsonify({'error': 'invalid storage name', 'field': 'storage'}), 400
    if not isinstance(name, str) or not _VM_NAME.match(name):
        return jsonify({'error': 'the VM name is letters, digits, - and . (a DNS name)', 'field': 'name'}), 400
    try:
        start = _bool(body, 'start', bool(row['start']))
        ipconfig0 = ''
        if row['ip_mode'] == 'static':
            ipconfig0 = _ipconfig(body.get('ipconfig0'))
        elif body.get('ipconfig0'):
            raise _Bad('this blueprint takes its address from DHCP or sets none', 'ipconfig0')
        cipassword = body.get('cipassword') or ''
        if not isinstance(cipassword, str) or len(cipassword) > 128 or _NAME_CTRL.search(cipassword):
            raise _Bad('the password is up to 128 characters, no control characters', 'cipassword')
    except _Bad as e:
        return e.answer()

    caller = _caller()
    # the same two questions the library's deploy and the create route ask: a caller
    # confined to their own guests places none, a tenant's VMID stays in its range
    if not _is_admin(caller):
        from pegaprox.api.helpers import require_unconfined
        cerr = require_unconfined(cluster_id)
        if cerr:
            return cerr
    vmid = body.get('vmid')
    if vmid in (None, ''):
        try:
            vmid = _free_vmid(mgr, caller)
        except Exception as e:
            logging.error(f"[vmid-range] blueprint deploy: no VMID: {e}")
            vmid = None
        if vmid is None:
            return jsonify({'error': 'no free VMID (the tenant range is full or the cluster did not answer)'}), 409
    else:
        if isinstance(vmid, bool) or not isinstance(vmid, (int, str)) or not str(vmid).isdigit() \
                or not 100 <= int(vmid) <= 999999999:
            return jsonify({'error': 'the VMID is a whole number from 100 up', 'field': 'vmid'}), 400
        vmid = int(vmid)
    verr = _check_vmid(caller, vmid)
    if verr:
        return verr
    if any(str(g.get('vmid')) == str(vmid) for g in (mgr.get_vm_resources() or [])):
        return jsonify({'error': f'VMID {vmid} is taken on this cluster', 'field': 'vmid'}), 409

    template = find_template(mgr, cluster_id, row['template_id'], node)
    build = None
    if template is None:
        try:
            tvmid = _free_vmid(mgr, caller, taken_extra=(vmid,))
        except Exception:
            tvmid = None
        if tvmid is None:
            return jsonify({'error': 'no free VMID for the template this cluster needs first'}), 409
        verr = _check_vmid(caller, tvmid)
        if verr:
            return verr
        build = {'dep_id': uuid.uuid4().hex[:12], 'vmid': tvmid,
                 'name': f"tpl-{tpl['distro']}-{tpl['version']}".replace('.', '')}
        if not _SAFE.match(build['name']):
            build['name'] = f"tpl-{tvmid}"

    dep_id = uuid.uuid4().hex[:12]

    def _alive():
        try:
            r = get_db().conn.execute('SELECT status FROM blueprint_deployments WHERE id = ?',
                                      (dep_id,)).fetchone()
            return r is None or r['status'] != 'failed'
        except Exception:
            return True

    # the VM counts as a create does, and a template built on the way as the library's deploy does
    from pegaprox.api.helpers import tenant_quota_gate
    cluster_name = getattr(getattr(mgr, 'config', None), 'name', '') or cluster_id
    adds = {'vms': 1, 'cores': int(row['cores']), 'memory_gb': int(row['memory']) / 1024.0,
            'disk_gb': max(float(row['disk_gb'] or 0), float(tpl.get('disk_gb', 10) or 10))}
    vmids = [vmid]
    if build:
        adds = {'vms': 2, 'cores': adds['cores'] + int(tpl.get('cores', 2)),
                'memory_gb': adds['memory_gb'] + int(tpl.get('memory', 2048)) / 1024.0,
                'disk_gb': adds['disk_gb'] + float(tpl.get('disk_gb', 10))}
        vmids.append(build['vmid'])
    qerr, qwarn = tenant_quota_gate(caller, f"blueprint deploy of {row['name']}", adds, cluster=cluster_name,
                                    hold={'cluster_id': cluster_id, 'vmids': vmids, 'alive': _alive})
    if qerr:
        return qerr

    user = _current_user()
    now = _now_iso()
    db = get_db()
    if build:
        db.conn.execute('''
            INSERT INTO cloud_init_deployments
                (id, cluster_id, node, template_id, template_name, vmid, storage,
                 status, progress, log, error, started_by, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, '', '', ?, ?)
        ''', (build['dep_id'], cluster_id, node, row['template_id'], tpl['name'], build['vmid'],
              storage, user, now))
    db.conn.execute('''
        INSERT INTO blueprint_deployments
            (id, blueprint_id, blueprint_name, cluster_id, node, vmid, name, template_vmid,
             build_dep_id, status, step, progress, log, error, started_by, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, 0, '', '', ?, ?)
    ''', (dep_id, bp_id, row['name'], cluster_id, node, vmid, name,
          (build or template)['vmid'], build['dep_id'] if build else None,
          'template' if build else 'clone', user, now))
    db.conn.commit()

    log_audit(user, 'blueprint.deploy',
              f"Blueprint '{row['name']}' deploying {name} (VMID {vmid}) onto {node}"
              + (f", building template {build['vmid']} first" if build else ''),
              cluster=cluster_name)

    # a user job: in an automatic group each call it sends asks for the lease (#625)
    from pegaprox.core import ha
    threading.Thread(
        target=ha.as_job(run_deploy, f'blueprint deploy {dep_id}'),
        args=(dep_id, cluster_id, dict(row), node, storage, vmid, name, template, build,
              ipconfig0, cipassword, start, user),
        daemon=True, name=f"bp-deploy-{dep_id}",
    ).start()

    return jsonify({'deployment_id': dep_id, 'vmid': vmid, 'name': name, 'status': 'queued',
                    'build_needed': build is not None,
                    **({'quota_warning': qwarn} if qwarn else {})}), 202


_DEP_COLUMNS = ('id, blueprint_id, blueprint_name, cluster_id, node, vmid, name, template_vmid, '
                'build_dep_id, status, step, progress, error, started_by, started_at, finished_at')


@bp.route('/api/blueprints/deployments', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_deployments():
    """Recent blueprint deployments of ?cluster_id=, newest first."""
    cluster_id = request.args.get('cluster_id', '')
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    rows = get_db().conn.execute(
        f'SELECT {_DEP_COLUMNS} FROM blueprint_deployments WHERE cluster_id = ? '
        'ORDER BY started_at DESC LIMIT 50', (cluster_id,)).fetchall()
    return jsonify({'deployments': scope_vm_rows(cluster_id, [dict(r) for r in rows])})


@bp.route('/api/blueprints/deployments/<dep_id>', methods=['GET'])
@require_auth(perms=['cluster.view'])
def deployment(dep_id):
    """One blueprint deployment with its log."""
    r = get_db().conn.execute('SELECT * FROM blueprint_deployments WHERE id = ?', (dep_id,)).fetchone()
    if r is None:
        return jsonify({'error': 'not found'}), 404
    d = dict(r)
    ok, err = check_cluster_access(d.get('cluster_id'))
    if not ok:
        return err
    if not scope_vm_rows(d['cluster_id'], [d]):
        return jsonify({'error': 'not found'}), 404
    return jsonify(d)
