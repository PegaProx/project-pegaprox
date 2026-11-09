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
No password is ever stored in a blueprint; a deploy may send one for that one VM. Its
Cloud-Init user and SSH keys do go into every VM deployed from it, so a blueprint is seen
in the tenant of the account that saved it only; an admin's is seen by everyone.

A blueprint can also start from a template that is already on a cluster (source_kind
'template'), which is how Windows gets in: the library holds Linux cloud images only. The
template is picked per cluster at the first deploy there and remembered. For Windows PVE
writes a configdrive2 that cloudbase-init reads; it drops the Cloud-Init user and the search
domains there and keeps the password in plain text in the VM config, so a Windows blueprint
stores neither user nor keys, and each deploy has to send a password.
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
from pegaprox.utils.auth import require_auth, build_authz_user, load_users
from pegaprox.utils.audit import log_audit
from pegaprox.utils.sanitization import validate_ssh_user
from pegaprox.api.helpers import check_cluster_access, scope_vm_rows
from pegaprox.core.db import get_db
from pegaprox.api import templates_lib

bp = Blueprint('blueprints', __name__)

NIC_MODELS = ('virtio', 'e1000', 'vmxnet3', 'rtl8139')
IP_MODES = ('dhcp', 'static', 'none')
MAX_NICS = 4
SOURCE_KINDS = ('library', 'template')
OS_KINDS = ('linux', 'windows')
# PVE's windows_version list; every other ostype is a Linux (or other) guest to it
WINDOWS_OSTYPES = ('wxp', 'w2k', 'w2k3', 'w2k8', 'wvista', 'win7', 'win8', 'win10', 'win11')
# Cloud-Init for Windows guests works from this qemu-server on
WINDOWS_QEMU_SERVER = (8, 2, 4)
# what Windows keeps of a computer name
NETBIOS_MAX = 15
# config reads per template probe
MAX_TEMPLATE_READS = 50

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


def _digits(v):
    # str.isdigit() also says yes to a superscript two, which int() refuses
    return isinstance(v, str) and v.isascii() and v.isdigit()


def _int(body, key, low, high, default=None):
    v = body.get(key, default)
    whole = (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, str) and _digits(v.strip()))
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


def _nics(raw, low=1):
    if not isinstance(raw, list) or not low <= len(raw) <= MAX_NICS:
        if low == 0:
            raise _Bad(f"a blueprint has up to {MAX_NICS} network devices, none keeps the template's own", 'nics')
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
    source_kind = body.get('source_kind') or 'library'
    if source_kind not in SOURCE_KINDS:
        raise _Bad('the source is library or template', 'source_kind')
    os_kind = body.get('os') or 'linux'
    if os_kind not in OS_KINDS:
        raise _Bad('the OS is linux or windows', 'os')
    template_id = ''
    if source_kind == 'library':
        # the library holds Linux cloud images only
        os_kind = 'linux'
        template_id = body.get('template_id')
        if not isinstance(template_id, str) or not templates_lib._lookup_template(template_id):
            raise _Bad('pick an image from the template library', 'template_id')
    windows = os_kind == 'windows'
    # cloudbase-init sets the password on the administrator account named in its own config
    # (Administrator or Admin) and PVE drops the search domains
    # for Windows, so none of that is kept where nothing would read it
    ciuser = '' if windows else _str(body, 'ciuser', 32)
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
    library = source_kind == 'library'
    return {
        'name': name,
        'description': description,
        'source_kind': source_kind,
        'os': os_kind,
        'template_id': template_id,
        'cores': _int(body, 'cores', 1, 512, 2),
        'memory': _int(body, 'memory', 64, 4194304, 2048),
        'disk_gb': _int(body, 'disk_gb', 0, 65536, 0),
        'cpu': cpu,
        # a template brings NICs of its own, which an empty list keeps
        'nics': _nics(body.get('nics', [{'bridge': 'vmbr0'}] if library else []), 1 if library else 0),
        'ciuser': ciuser,
        'sshkeys': '' if windows else _ssh_keys(_str(body, 'sshkeys', 16384)),
        'ip_mode': ip_mode,
        'nameserver': _nameservers(_str(body, 'nameserver', 200)),
        'searchdomain': '' if windows else _searchdomains(_str(body, 'searchdomain', 300)),
        'ciupgrade': True if windows else _bool(body, 'ciupgrade', True),
        'tags': _tags(body.get('tags')),
        'start': _bool(body, 'start', True),
    }


def _kind(r):
    return (r['source_kind'] if 'source_kind' in r.keys() else '') or 'library'


def _os(r):
    return (r['os'] if 'os' in r.keys() else '') or 'linux'


def _mappings(bp_id=None):
    """{blueprint id: {cluster id: template vmid}}, only the templates the caller may
    clone on a cluster they reach: a blueprint belongs to no one cluster, and a VMID the
    caller may not clone is of no use to them."""
    sql, args = 'SELECT blueprint_id, cluster_id, vmid FROM blueprint_templates', ()
    if bp_id is not None:
        sql, args = sql + ' WHERE blueprint_id = ?', (bp_id,)
    out, reach, caller = {}, {}, None
    for r in get_db().conn.execute(sql, args).fetchall():
        cid = r['cluster_id']
        if cid not in reach:
            reach[cid] = check_cluster_access(cid)[0]
        if not reach[cid]:
            continue
        caller = caller or _caller()
        if _may_clone(caller, cid, int(r['vmid'])):
            out.setdefault(r['blueprint_id'], {})[cid] = int(r['vmid'])
    return out


def _row(r, me='', admin=False, templates=None):
    library = _kind(r) == 'library'
    tpl = templates_lib._lookup_template(r['template_id']) if library else None
    try:
        nics = json.loads(r['nics'] or '[]')
    except ValueError:
        nics = []
    return {
        'id': r['id'],
        'name': r['name'],
        'description': r['description'] or '',
        'source_kind': _kind(r),
        'os': _os(r),
        'templates': {} if library else dict(templates or {}),
        'template_id': r['template_id'] or '',
        'template_name': tpl['name'] if tpl else '',
        'template_missing': library and tpl is None,
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


def _seen_by(caller):
    """Which blueprint rows the caller sees, as a test of a row. A deploy puts the
    blueprint's Cloud-Init user and SSH keys into the new VM, so a blueprint stays in the
    tenant of the account that saved it. An admin's is for everyone (an admin reaches
    every guest anyway) and an admin sees them all. One whose account is gone, or a user
    table that cannot be read, leaves it to the admins."""
    if _is_admin(caller):
        return lambda r: True
    from pegaprox.utils.rbac import acts_as_admin, DEFAULT_TENANT_ID
    me, users = _current_user(), load_users()
    home = caller.get('tenant_id') or DEFAULT_TENANT_ID

    def seen(r):
        by = r['created_by'] or ''
        if by and by == me:
            return True
        owner = users.get(by)
        if not by or not isinstance(owner, dict):
            return False
        if acts_as_admin(dict(owner, username=by)):
            return True
        return (owner.get('tenant_id') or DEFAULT_TENANT_ID) == home
    return seen


def _get_seen(bp_id, caller=None):
    """The blueprint row, or None when there is none or the caller does not see it: to
    them it is not there."""
    row = _get(bp_id)
    if row is None or not _seen_by(caller or _caller())(row):
        return None
    return row


def _store_values(f):
    return (f['name'], f['description'], f['template_id'], f['cores'], f['memory'], f['disk_gb'],
            f['cpu'], json.dumps(f['nics']), f['ciuser'], f['sshkeys'], f['ip_mode'],
            f['nameserver'], f['searchdomain'], int(f['ciupgrade']), ';'.join(f['tags']),
            int(f['start']), f['source_kind'], f['os'])


def _answer(bp_id, code=200):
    return jsonify({'blueprint': _row(_get(bp_id), _current_user(), _is_admin(_caller()),
                                      _mappings(bp_id).get(bp_id))}), code


# ──────────────────────────────────────────────────────────────────────────
# Blueprints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/blueprints', methods=['GET'])
@require_auth(perms=['vm.create'])
def list_blueprints():
    """The blueprints the caller sees, newest first: their own tenant's, the admins', and
    for an admin all of them. Editing is the creator's or an admin's."""
    caller = _caller()
    me, admin, seen = _current_user(), _is_admin(caller), _seen_by(caller)
    rows = [r for r in get_db().conn.execute('SELECT * FROM vm_blueprints ORDER BY created_at DESC').fetchall()
            if seen(r)]
    maps = _mappings() if rows else {}
    return jsonify({'blueprints': [_row(r, me, admin, maps.get(r['id'])) for r in rows]})


@bp.route('/api/blueprints', methods=['POST'])
@require_auth(perms=['vm.create'])
def create_blueprint():
    """Save a blueprint: source_kind (library, or template: an existing PVE template picked
    per cluster at the deploy), os (linux/windows; a library image is linux), template_id (a
    library image, '' for a template source), cores, memory (MB), disk_gb (0 keeps the
    image's size), cpu, nics [{bridge, vlan, model, firewall}] (1 to 4; for a template source
    0 to 4, none keeps the template's own), ciuser, sshkeys, ip_mode (dhcp/static/none),
    nameserver, searchdomain, ciupgrade, tags, start. Windows keeps no ciuser, sshkeys or
    searchdomain, and ciupgrade stays on."""
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
             ip_mode, nameserver, searchdomain, ciupgrade, tags, start, source_kind, os,
             id, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', _store_values(f) + (bp_id, _current_user(), now, now))
    db.conn.commit()
    log_audit(_current_user(), 'blueprint.created', f"Blueprint '{f['name']}' ({bp_id}) saved")
    return _answer(bp_id, 201)


def _owned(bp_id):
    """(row, error answer) for a change to blueprint `bp_id` by the caller."""
    row = _get_seen(bp_id)
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
            searchdomain = ?, ciupgrade = ?, tags = ?, start = ?, source_kind = ?, os = ?,
            updated_at = ?
        WHERE id = ?
    ''', _store_values(f) + (_now_iso(), bp_id))
    # the templates picked so far fit the old source and OS only
    if f['source_kind'] != _kind(row) or f['os'] != _os(row) or f['source_kind'] == 'library':
        db.conn.execute('DELETE FROM blueprint_templates WHERE blueprint_id = ?', (bp_id,))
    db.conn.commit()
    log_audit(_current_user(), 'blueprint.updated', f"Blueprint '{f['name']}' ({bp_id}) changed")
    return _answer(bp_id)


@bp.route('/api/blueprints/<bp_id>', methods=['DELETE'])
@require_auth(perms=['vm.create'])
def delete_blueprint(bp_id):
    """Remove a blueprint. VMs deployed from it are not touched."""
    row, err = _owned(bp_id)
    if err:
        return err
    db = get_db()
    db.conn.execute('DELETE FROM vm_blueprints WHERE id = ?', (bp_id,))
    db.conn.execute('DELETE FROM blueprint_templates WHERE blueprint_id = ?', (bp_id,))
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


def find_template(mgr, cluster_id, template_id, node, storage=None):
    """The template the library built from `template_id` on this cluster that a full
    clone onto `node` can start from: one on that node, else one on shared storage if the
    clone goes into shared `storage` as well (PVE clones onto another node into shared
    storage only). None when there is none, then the deploy builds one on the node first."""
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
    if storage is not None and storage not in shared:
        return None
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


# the config keys that name a volume a guest starts with (unusedN does not)
_VOLUME_KEY = re.compile(r'(?:scsi|virtio|ide|sata)\d+|efidisk\d+|tpmstate\d+')
_DISK_KEY = re.compile(r'(?:scsi|virtio|ide|sata)\d+')
# a Cloud-Init drive, as qemu-server's drive_is_cloudinit tells one
_CLOUDINIT = re.compile(r'.*[:/](?:vm-\d+-)?cloudinit(?:\.\w+)?')


def _volume(line):
    """The volume of a drive line: the part without a key, or file= written out."""
    parts = (line or '').split(',')
    return next((p.split('=', 1)[1] if '=' in p else p for p in parts
                 if '=' not in p or p.startswith(('file=', 'volume='))), '').strip()


def _is_disk(raw, key):
    line = raw.get(key)
    if not isinstance(line, str) or not _DISK_KEY.fullmatch(key or ''):
        return False
    vol = _volume(line)
    return ('media=cdrom' not in line.split(',')[1:] and vol not in ('', 'none', 'cdrom')
            and not _CLOUDINIT.fullmatch(vol))


def boot_disk(raw):
    """The disk a guest boots from: the first of boot: order= that is no CD-ROM and no
    Cloud-Init drive, else bootdisk (the old boot: c form the library writes), else the
    first of scsi0, virtio0, sata0, ide0 there is. None when it has no disk."""
    raw = raw or {}
    m = re.search(r'(?:^|,)order=([^,]+)', str(raw.get('boot') or ''))
    for key in (m.group(1).split(';') if m else []):
        if _is_disk(raw, key.strip()):
            return key.strip()
    if _is_disk(raw, raw.get('bootdisk')):
        return raw['bootdisk']
    return next((k for k in ('scsi0', 'virtio0', 'sata0', 'ide0') if _is_disk(raw, k)), None)


def template_facts(raw, shared_storages):
    """What a deploy needs to know of a template config: its OS, whether it has a
    Cloud-Init drive, its boot disk, the storages of its volumes and whether all of them
    are shared. PVE clones onto another node only then, the Cloud-Init drive and an ISO in
    a CD-ROM drive included."""
    raw = raw or {}
    vols, cloudinit = [], False
    for key, line in raw.items():
        if not isinstance(line, str) or not _VOLUME_KEY.fullmatch(str(key)):
            continue
        vol = _volume(line)
        if vol in ('', 'none', 'cdrom'):
            continue
        if _DISK_KEY.fullmatch(str(key)) and _CLOUDINIT.fullmatch(vol):
            cloudinit = True
        vols.append(vol)
    on_storage = [v.split(':', 1)[0] for v in vols if ':' in v and not v.startswith('/')]
    ostype = str(raw.get('ostype') or 'other')
    boot = boot_disk(raw)
    sizes = [disk_gb_of(raw[k]) or 0 for k in raw if _is_disk(raw, k)]
    return {
        'ostype': ostype,
        'windows': ostype in WINDOWS_OSTYPES,
        'cloudinit': cloudinit,
        'boot_disk': boot,
        'disk_storages': sorted(set(on_storage)),
        'shared': len(on_storage) == len(vols) and all(s in shared_storages for s in on_storage),
        '_boot_gb': (disk_gb_of(raw.get(boot, '')) or 0) if boot else 0,
        '_disk_gb': sum(sizes),
        # the clone keeps them, a blueprint sets the cores only
        '_sockets': max(int(raw['sockets']), 1) if _digits(str(raw.get('sockets', ''))) else 1,
    }


def _read_config(mgr, node, vmid):
    """A guest's config as PVE keeps it, in one read; None when that fails."""
    if not isinstance(node, str) or not _SAFE.match(node):
        return None
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{int(vmid)}/config")
        if r.status_code == 200:
            data = r.json().get('data')
            return data if isinstance(data, dict) else None
        logging.debug(f"[blueprints] config of {vmid} on {node}: HTTP {r.status_code}")
    except Exception as e:
        logging.debug(f"[blueprints] config of {vmid} on {node} failed: {e}")
    return None


def _qemu_templates(mgr):
    out = {}
    for g in (mgr.get_vm_resources() or []):
        if g.get('type') == 'qemu' and g.get('template') == 1:
            try:
                out[int(g.get('vmid'))] = g
            except (TypeError, ValueError):
                continue
    return out


def _mapped(bp_id, cluster_id):
    r = get_db().conn.execute('SELECT vmid FROM blueprint_templates WHERE blueprint_id = ? AND cluster_id = ?',
                              (bp_id, cluster_id)).fetchone()
    return int(r['vmid']) if r else None


def _may_clone(caller, cluster_id, vmid):
    from pegaprox.utils.rbac import user_can_access_vm
    return user_can_access_vm(caller, cluster_id, vmid, 'vm.clone', 'qemu')


def template_choices(mgr, cluster_id, caller, os_kind, node, first=None):
    """The qemu templates of this cluster the caller may clone and whose OS is the
    blueprint's, each with what a deploy onto `node` needs to know. One config read per
    template, at most MAX_TEMPLATE_READS of them; `first` is read whatever the cap."""
    live = _qemu_templates(mgr)
    mine = sorted(v for v in live if _may_clone(caller, cluster_id, v))
    if first in mine:
        mine.remove(first)
        mine.insert(0, first)
    mine = mine[:MAX_TEMPLATE_READS]
    from pegaprox.utils.concurrent import run_concurrent_dict
    configs = run_concurrent_dict({v: (lambda v=v: _read_config(mgr, live[v].get('node'), v)) for v in mine},
                                  timeout=20)
    shared = _shared_storages(mgr) if any(configs.values()) else set()
    out = []
    for v in sorted(mine):
        if not configs.get(v):
            continue
        facts = template_facts(configs[v], shared)
        if facts['windows'] != (os_kind == 'windows'):
            continue
        tnode = live[v].get('node') or ''
        out.append(dict({k: x for k, x in facts.items() if not k.startswith('_')},
                        vmid=v, name=live[v].get('name') or '', node=tnode,
                        usable_on_node=tnode == node or facts['shared']))
    return out


@bp.route('/api/clusters/<cluster_id>/blueprints/<bp_id>/template', methods=['GET'])
@require_auth(perms=['vm.create'])
def blueprint_template(cluster_id, bp_id):
    """What a deploy of this blueprint onto ?node= starts from. A library blueprint:
    {source_kind: 'library', template: {vmid, node, storage, shared} | null, build_needed},
    the template it would clone or that it builds one there first. A template blueprint:
    {source_kind: 'template', mapped: vmid | null, templates: [{vmid, name, node, ostype,
    windows, cloudinit, boot_disk, disk_storages, shared, usable_on_node}]}, the cluster's
    templates the caller may clone whose OS fits (at most 50 read) and the one remembered."""
    mgr, err = _pve_cluster(cluster_id)
    if err:
        return err
    caller = _caller()
    if not _is_admin(caller):
        from pegaprox.api.helpers import require_unconfined
        cerr = require_unconfined(cluster_id)
        if cerr:
            return cerr
    row = _get_seen(bp_id, caller)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    node = request.args.get('node', '')
    if not _member(mgr, node):
        return jsonify({'error': 'node is not a member of this cluster', 'field': 'node'}), 400
    if _kind(row) == 'library':
        found = find_template(mgr, cluster_id, row['template_id'], node)
        return jsonify({'source_kind': 'library', 'template': found, 'build_needed': found is None})
    mapped = _mapped(bp_id, cluster_id)
    if mapped is not None and not _may_clone(caller, cluster_id, mapped):
        mapped = None
    return jsonify({'source_kind': 'template', 'mapped': mapped,
                    'templates': template_choices(mgr, cluster_id, caller, _os(row), node, first=mapped)})


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


def usable_template(mgr, cluster_id, caller, os_kind, vmid, node, storage=None):
    """(template, facts, None) for a PVE template this deploy may clone onto `node` (into
    `storage`), or (None, None, (error, field, code)) saying why not."""
    live = _qemu_templates(mgr).get(vmid)
    if live is None:
        return None, None, (f'VMID {vmid} is no VM template on this cluster', 'template_vmid', 400)
    if not _may_clone(caller, cluster_id, vmid):
        return None, None, (f'you may not clone template {vmid}', 'template_vmid', 400)
    tnode = live.get('node') or ''
    raw = _read_config(mgr, tnode, vmid)
    if raw is None:
        return None, None, (f'the config of template {vmid} could not be read', 'template_vmid', 502)
    shared = _shared_storages(mgr)
    facts = template_facts(raw, shared)
    want = os_kind == 'windows'
    if facts['windows'] != want:
        return None, None, (f"template {vmid} is a {'Windows' if facts['windows'] else 'Linux'} guest "
                            f"(ostype {facts['ostype']}), this blueprint is for "
                            f"{'Windows' if want else 'Linux'}", 'template_vmid', 400)
    if not facts['cloudinit']:
        return None, None, (f'template {vmid} has no Cloud-Init drive', 'template_vmid', 400)
    if tnode != node and not facts['shared']:
        return None, None, (f'template {vmid} is on {tnode} with disks on storage only that node has; '
                            f'deploy onto {tnode}', 'node', 400)
    if tnode != node and storage is not None and storage not in shared:
        # qemu-server: "can't clone to non-shared storage"
        return None, None, (f'template {vmid} is on {tnode}: a clone onto {node} goes to shared storage '
                            f'only, {storage} is not shared', 'storage', 400)
    return {'vmid': vmid, 'node': tnode, 'storage': '', 'shared': facts['shared']}, facts, None


_PKG_VERSION = re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?')


def qemu_server_version(mgr, node):
    """The installed qemu-server on `node` as (major, minor, patch), None when unread."""
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/apt/versions")
        if r.status_code != 200:
            return None
        for p in (r.json().get('data') or []):
            if isinstance(p, dict) and p.get('Package') == 'qemu-server':
                # OldVersion is the installed one; Version is what apt would install next
                m = _PKG_VERSION.match(str(p.get('OldVersion') or ''))
                return tuple(int(x or 0) for x in m.groups()) if m else None
    except Exception as e:
        logging.debug(f"[blueprints] package versions of {node}: {e}")
    return None


def bridge_check(mgr, node, nics):
    """(refusal, warnings) for the bridges the blueprint's NICs name: each one a bridge
    of `node` or an SDN VNet. A read that fails checks nothing and says so."""
    want = []
    for nic in nics:
        if nic['bridge'] not in want:
            want.append(nic['bridge'])
    if not want:
        return None, []
    base = f"https://{mgr.host}:{mgr.api_port}/api2/json"
    try:
        r = mgr._api_get(f"{base}/nodes/{node}/network")
        if r.status_code != 200:
            raise RuntimeError(f'HTTP {r.status_code}')
        have = {i.get('iface') for i in (r.json().get('data') or [])
                if isinstance(i, dict) and i.get('type') in ('bridge', 'OVSBridge')}
    except Exception as e:
        return None, [f"the network of {node} could not be read ({str(e)[:120]}), "
                      f"bridge {', '.join(want)} is not checked"]
    missing = [b for b in want if b not in have]
    if not missing:
        return None, []
    try:
        r = mgr._api_get(f"{base}/cluster/sdn/vnets")
        if r.status_code != 200:
            raise RuntimeError(f'HTTP {r.status_code}')
        vnets = {v.get('vnet') for v in (r.json().get('data') or []) if isinstance(v, dict)}
    except Exception as e:
        return None, [f"the SDN VNets could not be read ({str(e)[:120]}), "
                      f"bridge {', '.join(missing)} is not checked"]
    missing = [b for b in missing if b not in vnets]
    if len(missing) == 1:
        return (f"bridge {missing[0]} is neither a bridge on {node} nor an SDN VNet", 'nics'), []
    if missing:
        return (f"bridges {', '.join(missing)} are neither bridges on {node} nor SDN VNets", 'nics'), []
    return None, []


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
    windows = _os(bp_row) == 'windows'
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
        # no NICs of its own: the template's first one gets the address
        for i in range(max(len(nics), 1)):
            cfg[f'ipconfig{i}'] = 'ip=dhcp'
    elif bp_row['ip_mode'] == 'static' and ipconfig0:
        cfg['ipconfig0'] = ipconfig0
    if bp_row['ciuser'] and not windows:
        cfg['ciuser'] = bp_row['ciuser']
    if bp_row['sshkeys'] and not windows:
        # PVE takes the keys URL-encoded, a space as %20
        cfg['sshkeys'] = quote(bp_row['sshkeys'] + '\n', safe='')
    if cipassword:
        cfg['cipassword'] = cipassword
    if bp_row['nameserver']:
        cfg['nameserver'] = bp_row['nameserver']
    if bp_row['searchdomain'] and not windows:
        cfg['searchdomain'] = bp_row['searchdomain']
    if not bp_row['ciupgrade'] and not windows:
        # PVE upgrades the packages on first boot unless told not to
        cfg['ciupgrade'] = 0
    if bp_row['tags']:
        cfg['tags'] = bp_row['tags']
    return cfg


def surplus_nics(bp_row, raw):
    """The NICs (and their ipconfig) a clone has beyond the blueprint's, to remove. None
    when the blueprint keeps the template's NICs."""
    count = len(json.loads(bp_row['nics'] or '[]'))
    if not count:
        return []
    out = []
    for key in sorted(raw or {}):
        m = re.fullmatch(r'(net|ipconfig)(\d+)', key)
        if m and int(m.group(2)) >= count:
            out.append(key)
    return out


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
        want = int(bp_row['disk_gb'] or 0)
        raw = {}
        if want or json.loads(bp_row['nics'] or '[]'):
            got = mgr.get_vm_config(node, vmid, 'qemu') or {}
            # get_vm_config parses the config and keeps PVE's own keys under 'raw'
            raw = ((got.get('config') or {}).get('raw') or {}) if got.get('success') else {}
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/config"
        cfg = vm_config(bp_row, ipconfig0, cipassword)
        surplus = surplus_nics(bp_row, raw)
        if surplus:
            cfg['delete'] = ','.join(surplus)
        r = mgr._api_post(url, data=cfg)
        if r.status_code != 200:
            raise RuntimeError(f"applying the blueprint refused: {r.text[:300]}")
        _update(dep_id, progress=85, log='CPU, memory, network and Cloud-Init set: '
                + ', '.join(k for k in cfg if k not in ('cipassword', 'delete'))
                + (f"; the template's {', '.join(surplus)} removed" if surplus else ''))

        if want:
            _update(dep_id, step='resize')
            disk = boot_disk(raw)
            have = disk_gb_of(raw.get(disk, '')) if disk else None
            if have is not None and want > have + 0.01:
                rr = mgr.resize_vm_disk(node, vmid, 'qemu', disk, f'{want}G')
                if not rr.get('success'):
                    raise RuntimeError(f"growing the disk refused: {str(rr.get('error'))[:300]}")
                _update(dep_id, log=f"{disk} grown to {want} GB")
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
    ipconfig0? (only and required with ip_mode static), cipassword? (required for Windows),
    start?, template_vmid? (a template blueprint: required until one is remembered for the
    cluster)}. A library blueprint clones the library's template of the image on that node
    or shared storage, or builds one on the node first; a template blueprint clones the PVE
    template, remembered for the cluster when the caller may edit the blueprint. A clone
    from another node goes into shared storage only, as PVE has it. The NIC
    bridges have to be on the node or SDN VNets, a Windows deploy needs qemu-server 8.2.4 on
    it. 202 with the deployment to poll and warnings: [str] (also in its log)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'the body is a JSON object'}), 400
    row = _get_seen(bp_id)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    library, windows = _kind(row) == 'library', _os(row) == 'windows'
    tpl = None
    if library:
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
        if windows and not cipassword:
            # cloudbase-init sets it on the administrator account; without one nobody signs in
            raise _Bad('a Windows VM needs a password for its administrator account', 'cipassword')
        template_vmid = None
        if not library:
            raw_tv = body.get('template_vmid')
            if raw_tv not in (None, ''):
                if isinstance(raw_tv, bool) or not isinstance(raw_tv, (int, str)) or not _digits(str(raw_tv)):
                    raise _Bad('the template is a VMID', 'template_vmid')
                template_vmid = int(raw_tv)
    except _Bad as e:
        return e.answer()
    warnings = []
    if windows and len(name) > NETBIOS_MAX:
        warnings.append(f'Windows keeps the first {NETBIOS_MAX} characters of {name} as its computer name')

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
        if isinstance(vmid, bool) or not isinstance(vmid, (int, str)) or not _digits(str(vmid)) \
                or not 100 <= int(vmid) <= 999999999:
            return jsonify({'error': 'the VMID is a whole number from 100 up', 'field': 'vmid'}), 400
        vmid = int(vmid)
    verr = _check_vmid(caller, vmid)
    if verr:
        return verr
    if any(str(g.get('vmid')) == str(vmid) for g in (mgr.get_vm_resources() or [])):
        return jsonify({'error': f'VMID {vmid} is taken on this cluster', 'field': 'vmid'}), 409

    build, facts = None, None
    if not library:
        if template_vmid is None:
            template_vmid = _mapped(bp_id, cluster_id)
        if template_vmid is None:
            return jsonify({'error': 'pick the template this cluster clones', 'field': 'template_vmid'}), 400
        template, facts, why = usable_template(mgr, cluster_id, caller, _os(row), template_vmid, node, storage)
        if why:
            return jsonify({'error': why[0], 'field': why[1]}), why[2]
    else:
        template = find_template(mgr, cluster_id, row['template_id'], node, storage)
    if library and template is None:
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

    if windows:
        have = qemu_server_version(mgr, node)
        if have is None:
            warnings.append(f'the qemu-server version of {node} could not be read; Cloud-Init for Windows '
                            f'needs {".".join(map(str, WINDOWS_QEMU_SERVER))} or newer')
        elif have < WINDOWS_QEMU_SERVER:
            return jsonify({'error': f'Cloud-Init for Windows needs qemu-server '
                                     f'{".".join(map(str, WINDOWS_QEMU_SERVER))} or newer, {node} has '
                                     f'{".".join(map(str, have))}', 'field': 'node'}), 409
    refusal, more = bridge_check(mgr, node, json.loads(row['nics'] or '[]'))
    if refusal:
        return jsonify({'error': refusal[0], 'field': refusal[1]}), 400
    warnings.extend(more)

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
    if library:
        disk = max(float(row['disk_gb'] or 0), float(tpl.get('disk_gb', 10) or 10))
    else:
        # every disk of the template is copied, the boot disk grown to the blueprint's size
        disk = facts['_disk_gb'] - facts['_boot_gb'] + max(float(row['disk_gb'] or 0), facts['_boot_gb'])
    # vCPUs are sockets x cores, as the other quota counts of a qemu guest have it
    cores = int(row['cores']) * (facts['_sockets'] if facts else 1)
    adds = {'vms': 1, 'cores': cores, 'memory_gb': int(row['memory']) / 1024.0, 'disk_gb': disk}
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, 0, ?, '', ?, ?)
    ''', (dep_id, bp_id, row['name'], cluster_id, node, vmid, name,
          (build or template)['vmid'], build['dep_id'] if build else None,
          'template' if build else 'clone', ''.join(f"[{now}] warning: {w}\n" for w in warnings),
          user, now))
    # the next deploy onto this cluster starts from the same template, if the caller may
    # change the blueprint; anyone else's pick is for this deploy only
    if not library and ((row['created_by'] or '') == user or _is_admin(caller)) \
            and _mapped(bp_id, cluster_id) != template['vmid']:
        db.conn.execute('''
            INSERT OR REPLACE INTO blueprint_templates (blueprint_id, cluster_id, vmid, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (bp_id, cluster_id, template['vmid'], user, now))
    db.conn.commit()

    log_audit(user, 'blueprint.deploy',
              f"Blueprint '{row['name']}' deploying {name} (VMID {vmid}) onto {node}"
              + (f", building template {build['vmid']} first" if build else '')
              + ('' if library else f", cloning template {template['vmid']}"),
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
                    'build_needed': build is not None, 'warnings': warnings,
                    **({'quota_warning': qwarn} if qwarn else {})}), 202


_DEP_COLUMNS = ('id, blueprint_id, blueprint_name, cluster_id, node, vmid, name, template_vmid, '
                'build_dep_id, status, step, progress, error, started_by, started_at, finished_at')


@bp.route('/api/blueprints/deployments', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_deployments():
    """Recent blueprint deployments of ?cluster_id=, newest first (50). Without it the
    ones of every cluster the caller may see (100), each row with its cluster_id."""
    cluster_id = request.args.get('cluster_id', '')
    conn = get_db().conn
    if cluster_id:
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
        rows = conn.execute(
            f'SELECT {_DEP_COLUMNS} FROM blueprint_deployments WHERE cluster_id = ? '
            'ORDER BY started_at DESC LIMIT 50', (cluster_id,)).fetchall()
        return jsonify({'deployments': scope_vm_rows(cluster_id, [dict(r) for r in rows])})
    out = []
    for (cid,) in conn.execute('SELECT DISTINCT cluster_id FROM blueprint_deployments').fetchall():
        if not check_cluster_access(cid)[0]:
            continue
        rows = conn.execute(
            f'SELECT {_DEP_COLUMNS} FROM blueprint_deployments WHERE cluster_id = ? '
            'ORDER BY started_at DESC LIMIT 100', (cid,)).fetchall()
        out.extend(scope_vm_rows(cid, [dict(r) for r in rows]))
    out.sort(key=lambda r: r.get('started_at') or '', reverse=True)
    return jsonify({'deployments': out[:100]})


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
