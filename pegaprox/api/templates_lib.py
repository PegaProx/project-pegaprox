# -*- coding: utf-8 -*-
"""
Cloud-Init Template Library — NS May 2026.

Curated catalog of common cloud images. PegaProx automates the standard
"download → import → cloud-init drive → convert to template" workflow so
admins don't have to ssh into every node and run pvesm/qm by hand.

Workflow per deploy:
  1. SSH to a node
  2. wget the cloud .img into /var/lib/vz/template/iso/  (or /tmp)
  3. qm create <vmid> --name <tmpl-name> --memory 2048 --cores 2 \
        --net0 virtio,bridge=vmbr0 --ostype l26 --agent 1 --serial0 socket
  4. qm importdisk <vmid> /tmp/<img> <storage>
  5. qm set <vmid> --scsihw virtio-scsi-pci --scsi0 <storage>:vm-<vmid>-disk-0
  6. qm set <vmid> --ide2 <storage>:cloudinit
  7. qm set <vmid> --boot c --bootdisk scsi0
  8. qm template <vmid>

Catalog is a dict of presets — image_url, sha256 (optional), default_user,
recommended cores/memory. We don't bake heavy verification — Proxmox-side
qm template either succeeds or doesn't.
"""
import os
import json
import uuid
import shlex
import logging
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.db import get_db

bp = Blueprint('templates_lib', __name__)


# ──────────────────────────────────────────────────────────────────────────
# Catalog
# Curated list — kept small intentionally. Adding entries: image_url must
# be a direct .img / .qcow2 URL the node can wget.
# ──────────────────────────────────────────────────────────────────────────
CATALOG = [
    {
        'id': 'ubuntu-2404',
        'name': 'Ubuntu 24.04 LTS (Noble)',
        'distro': 'ubuntu',
        'version': '24.04',
        'image_url': 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
        'default_user': 'ubuntu',
        'cores': 2, 'memory': 2048, 'disk_gb': 10,
        'description': 'Latest LTS — cloud-init ready.',
        'tags': ['lts', 'general', 'recommended'],
    },
    {
        'id': 'ubuntu-2204',
        'name': 'Ubuntu 22.04 LTS (Jammy)',
        'distro': 'ubuntu',
        'version': '22.04',
        'image_url': 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
        'default_user': 'ubuntu',
        'cores': 2, 'memory': 2048, 'disk_gb': 10,
        'description': 'Previous LTS — broad compatibility.',
        'tags': ['lts', 'general'],
    },
    {
        'id': 'debian-12',
        'name': 'Debian 12 (Bookworm)',
        'distro': 'debian',
        'version': '12',
        'image_url': 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2',
        'default_user': 'debian',
        'cores': 1, 'memory': 1024, 'disk_gb': 8,
        'description': 'Lean Debian generic-cloud image.',
        'tags': ['lean', 'recommended'],
    },
    {
        'id': 'debian-11',
        'name': 'Debian 11 (Bullseye)',
        'distro': 'debian',
        'version': '11',
        'image_url': 'https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2',
        'default_user': 'debian',
        'cores': 1, 'memory': 1024, 'disk_gb': 8,
        'description': 'Older stable Debian.',
        'tags': ['lean'],
    },
    {
        'id': 'almalinux-9',
        'name': 'AlmaLinux 9',
        'distro': 'almalinux',
        'version': '9',
        'image_url': 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2',
        'default_user': 'almalinux',
        'cores': 2, 'memory': 2048, 'disk_gb': 10,
        'description': 'RHEL-compatible drop-in replacement.',
        'tags': ['rhel'],
    },
    {
        'id': 'rocky-9',
        'name': 'Rocky Linux 9',
        'distro': 'rocky',
        'version': '9',
        'image_url': 'https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2',
        'default_user': 'rocky',
        'cores': 2, 'memory': 2048, 'disk_gb': 10,
        'description': 'Community RHEL rebuild.',
        'tags': ['rhel'],
    },
    {
        'id': 'fedora-40',
        'name': 'Fedora 40 Cloud',
        'distro': 'fedora',
        'version': '40',
        'image_url': 'https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2',
        'default_user': 'fedora',
        'cores': 2, 'memory': 2048, 'disk_gb': 10,
        'description': 'Cutting-edge Red Hat upstream.',
        'tags': ['cutting-edge'],
    },
    {
        'id': 'alpine-319',
        'name': 'Alpine Linux 3.19',
        'distro': 'alpine',
        'version': '3.19',
        'image_url': 'https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/nocloud_alpine-3.19.1-x86_64-bios-cloudinit-r0.qcow2',
        'default_user': 'alpine',
        'cores': 1, 'memory': 512, 'disk_gb': 4,
        'description': 'Tiny musl-based — perfect for k3s.',
        'tags': ['minimal', 'container-host'],
    },
]

CATALOG_BY_ID = {t['id']: t for t in CATALOG}


# ──────────────────────────────────────────────────────────────────────────
# Custom templates (user-managed, persisted in custom_cloud_templates)
# ──────────────────────────────────────────────────────────────────────────

def _row_to_template(r):
    """DB row -> catalog dict shape (matching the built-in CATALOG entries)."""
    tags = (r['tags'] or '').strip()
    tag_list = [t.strip() for t in tags.split(',') if t.strip()] if tags else []
    return {
        'id': r['id'],
        'name': r['name'],
        'distro': r['distro'] or 'custom',
        'version': r['version'] or '',
        'image_url': r['image_url'],
        'default_user': r['default_user'] or 'root',
        'cores': r['cores'] or 2,
        'memory': r['memory'] or 2048,
        'disk_gb': r['disk_gb'] or 10,
        'description': r['description'] or '',
        'tags': tag_list + ['custom'],
        'custom': True,
        'created_by': r['created_by'] or '',
    }


def _load_custom_templates():
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM custom_cloud_templates ORDER BY created_at DESC')
        return [_row_to_template(r) for r in c.fetchall()]
    except Exception as e:
        logging.warning(f"[templates_lib] custom load failed: {e}")
        return []


def _lookup_template(template_id):
    """Combined lookup: built-in first, then custom DB-backed."""
    if template_id in CATALOG_BY_ID:
        return CATALOG_BY_ID[template_id]
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM custom_cloud_templates WHERE id = ?', (template_id,))
        r = c.fetchone()
        if r:
            return _row_to_template(r)
    except Exception:
        pass
    return None


def _current_user():
    """Return the logged-in username string. PegaProx stores the username
    directly in request.session['user'] (not a dict like default Flask)."""
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now().isoformat()


def _update_dep(dep_id, **fields):
    """Patch one row in cloud_init_deployments. Caller passes any subset of
    status / progress / log (appended) / error / vmid / finished_at."""
    try:
        db = get_db()
        c = db.conn.cursor()
        sets = []
        vals = []
        if 'status' in fields:
            sets.append('status = ?'); vals.append(fields['status'])
        if 'progress' in fields:
            sets.append('progress = ?'); vals.append(fields['progress'])
        if 'log_append' in fields:
            sets.append("log = COALESCE(log,'') || ?")
            vals.append(f"[{_now_iso()}] {fields['log_append']}\n")
        if 'error' in fields:
            sets.append('error = ?'); vals.append(fields['error'])
        if 'vmid' in fields:
            sets.append('vmid = ?'); vals.append(fields['vmid'])
        if 'finished_at' in fields:
            sets.append('finished_at = ?'); vals.append(fields['finished_at'])
        if not sets:
            return
        vals.append(dep_id)
        c.execute(f"UPDATE cloud_init_deployments SET {', '.join(sets)} WHERE id = ?", vals)
        db.conn.commit()
    except Exception as e:
        logging.warning(f"[templates_lib] update_dep failed: {e}")


def _next_free_vmid(mgr):
    """Ask the cluster for the next free vmid."""
    try:
        resp = mgr._api_get('/cluster/nextid')
        if resp and 'data' in resp:
            return int(resp['data'])
    except Exception:
        pass
    # fallback: pick max+1 from resources
    try:
        used = set()
        for r in (mgr.get_vm_resources() or []):
            try: used.add(int(r.get('vmid') or 0))
            except: pass
        return (max(used) + 1) if used else 9000
    except Exception:
        return 9000


def _run_deploy(dep_id, cluster_id, node, template_id, storage, vmid, vm_name):
    """Background worker: SSH into node, run the qm pipeline."""
    mgr = cluster_managers.get(cluster_id)
    tpl = _lookup_template(template_id)
    if not mgr or not tpl:
        _update_dep(dep_id, status='failed', error='cluster or template missing',
                    finished_at=_now_iso())
        return

    img_basename = tpl['image_url'].rsplit('/', 1)[-1]
    img_path = f"/tmp/pegaprox-ci-{template_id}-{img_basename}"

    # use management IP if we have one, otherwise cluster host
    try:
        node_ip = mgr._get_node_ip(node) if hasattr(mgr, '_get_node_ip') else None
    except Exception:
        node_ip = None
    target_host = node_ip or mgr.host or mgr.config.host

    _update_dep(dep_id, status='running', progress=5,
                log_append=f"deploying {tpl['name']} to {node} ({target_host}) as VMID {vmid}")

    ssh = None
    try:
        ssh = mgr._ssh_connect(target_host)
        if not ssh:
            _update_dep(dep_id, status='failed', error='SSH connect failed',
                        finished_at=_now_iso())
            return

        def run(cmd, label, weight=10):
            _update_dep(dep_id, log_append=f"$ {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=False, timeout=900)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
            if out:
                _update_dep(dep_id, log_append=out[:1000])
            if err and rc != 0:
                _update_dep(dep_id, log_append=f"stderr: {err[:1000]}")
            if rc != 0:
                raise RuntimeError(f"{label} failed (rc={rc}): {err or out}")
            return out

        # NS May 2026 — every interpolated string goes through shlex.quote.
        # Even fields we think are safe (vmid is int-cast, storage matches a
        # narrow whitelist on PVE side) are quoted as defense-in-depth so
        # custom-template URLs / names can't break out of the qm command line.
        vmid_i = int(vmid)
        q_img_path = shlex.quote(img_path)
        q_url = shlex.quote(tpl['image_url'])
        q_vm_name = shlex.quote(vm_name)
        q_storage = shlex.quote(storage)

        # 1. download
        # MK: -nc skip if exists, -q quiet output. show-progress would flood log
        run(f"wget -q -O {q_img_path} {q_url}", 'download')
        _update_dep(dep_id, progress=35, log_append='download done')

        # 2. qm create skeleton
        cores = int(tpl.get('cores', 2))
        memory = int(tpl.get('memory', 2048))
        create_cmd = (
            f"qm create {vmid_i} --name {q_vm_name} "
            f"--memory {memory} --cores {cores} "
            f"--net0 virtio,bridge=vmbr0 --ostype l26 --agent 1 --serial0 socket --vga serial0"
        )
        run(create_cmd, 'qm create')
        _update_dep(dep_id, progress=50, log_append='VM shell created')

        # 3. import disk
        run(f"qm importdisk {vmid_i} {q_img_path} {q_storage}", 'qm importdisk')
        _update_dep(dep_id, progress=70, log_append='disk imported')

        # 4. attach as scsi0 + cloudinit + boot order
        # the volid passed to qm set is built from the (now-quoted) storage
        # plus the vmid integer; quote the whole arg as a unit so a hostile
        # storage value can't escape.
        scsi_arg = shlex.quote(f"{storage}:vm-{vmid_i}-disk-0")
        ide_arg = shlex.quote(f"{storage}:cloudinit")
        run(
            f"qm set {vmid_i} --scsihw virtio-scsi-pci "
            f"--scsi0 {scsi_arg} "
            f"--ide2 {ide_arg} "
            f"--boot c --bootdisk scsi0",
            'qm set'
        )
        _update_dep(dep_id, progress=85, log_append='cloud-init drive attached')

        # 5. convert to template
        run(f"qm template {vmid_i}", 'qm template')
        _update_dep(dep_id, progress=95, log_append='converted to template')

        # 6. cleanup downloaded img
        run(f"rm -f {q_img_path}", 'cleanup', weight=2)

        _update_dep(dep_id, status='completed', progress=100,
                    log_append=f"template {vm_name} (vmid {vmid}) ready",
                    finished_at=_now_iso())
    except Exception as e:
        logging.exception(f"[templates_lib] deploy {dep_id} failed")
        _update_dep(dep_id, status='failed',
                    error=str(e)[:500],
                    log_append=f"FAILED: {e}",
                    finished_at=_now_iso())
    finally:
        try:
            if ssh: ssh.close()
        except: pass


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/templates/catalog', methods=['GET'])
@require_auth()
def catalog():
    """Curated catalog + user-defined custom templates."""
    return jsonify({'templates': list(CATALOG) + _load_custom_templates()})


@bp.route('/api/templates/custom', methods=['POST'])
@require_auth(perms=['vm.create'])
def add_custom_template():
    """Persist a user-defined cloud-init template. Body shape mirrors the
    built-in catalog entries: name, image_url required; the rest gets sane
    defaults if omitted."""
    body = request.get_json(silent=True) or {}
    name = (body.get('name') or '').strip()
    image_url = (body.get('image_url') or '').strip()

    if not name or not image_url:
        return jsonify({'error': 'name and image_url required'}), 400
    # NS May 2026 — parse the URL properly and reject anything that's not a
    # plain http(s) host[:port]/path. Earlier we only checked the prefix, which
    # let strings like "https://x; reboot ;" through and they ended up in a
    # shell command via wget. Now: scheme + netloc + ascii-only chars.
    import urllib.parse
    try:
        u = urllib.parse.urlparse(image_url)
    except Exception:
        u = None
    if (not u or u.scheme not in ('http', 'https') or not u.netloc
            or any(ord(c) < 0x20 or c in (' ', ';', '|', '&', '`', '$', '\n', '\t', '"', "'", '\\') for c in image_url)):
        return jsonify({'error': 'image_url must be a clean http(s) URL'}), 400

    # MK: keep IDs predictable + URL-safe so frontend keys don't break
    import re, secrets
    base = re.sub(r'[^a-z0-9-]+', '-', name.lower()).strip('-')[:40] or 'tpl'
    tpl_id = f"custom-{base}-{secrets.token_hex(3)}"

    try:
        cores = int(body.get('cores') or 2)
        memory = int(body.get('memory') or 2048)
        disk_gb = int(body.get('disk_gb') or 10)
    except Exception:
        return jsonify({'error': 'cores/memory/disk_gb must be integers'}), 400

    tags = body.get('tags', [])
    if isinstance(tags, list):
        tags = ','.join(str(t) for t in tags)
    elif not isinstance(tags, str):
        tags = ''

    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO custom_cloud_templates
                (id, name, description, distro, version, image_url, default_user,
                 cores, memory, disk_gb, tags, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            tpl_id,
            name,
            (body.get('description') or '').strip(),
            (body.get('distro') or 'custom').strip().lower(),
            (body.get('version') or '').strip(),
            image_url,
            (body.get('default_user') or 'root').strip(),
            cores, memory, disk_gb, tags,
            _current_user(),
            datetime.now().isoformat(),
        ))
        get_db().conn.commit()
    except Exception as e:
        return jsonify({'error': f'db insert failed: {e}'}), 500

    # Return the newly-created entry in catalog shape so the UI can splice
    # it into the list without a full reload
    c = get_db().conn.cursor()
    c.execute('SELECT * FROM custom_cloud_templates WHERE id = ?', (tpl_id,))
    row = c.fetchone()
    return jsonify({'template': _row_to_template(row) if row else {'id': tpl_id}})


@bp.route('/api/templates/custom/<tpl_id>', methods=['DELETE'])
@require_auth(perms=['vm.create'])
def delete_custom_template(tpl_id):
    """Remove a user-defined template. Built-in catalog IDs are not touched."""
    if tpl_id in CATALOG_BY_ID:
        return jsonify({'error': 'cannot delete built-in template'}), 400
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM custom_cloud_templates WHERE id = ?', (tpl_id,))
        get_db().conn.commit()
        if c.rowcount == 0:
            return jsonify({'error': 'not found'}), 404
        return jsonify({'ok': True})
    except Exception as e:
        logging.exception('handler error in templates_lib.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/templates/deploy', methods=['POST'])
@require_auth(perms=['vm.create'])
def deploy(cluster_id):
    """Kick off async deployment. Body: {template_id, node, storage, vmid?, name?}."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    mgr = cluster_managers[cluster_id]

    body = request.get_json(silent=True) or {}
    template_id = body.get('template_id')
    node = body.get('node')
    storage = body.get('storage')
    vmid = body.get('vmid')
    name = body.get('name')

    tpl = _lookup_template(template_id)
    if not tpl:
        return jsonify({'error': 'unknown template_id'}), 400
    if not node or not storage:
        return jsonify({'error': 'node and storage required'}), 400

    # NS May 2026 — defense-in-depth: shlex.quote in _run_deploy is the seatbelt,
    # this is the airbag. Reject anything that isn't [a-zA-Z0-9_.-] in node/
    # storage/name before it ever touches the worker thread. Proxmox itself
    # already enforces these patterns so we're not breaking real users.
    import re
    _SAFE = re.compile(r'^[A-Za-z0-9._-]+$')
    if not _SAFE.match(str(node)):
        return jsonify({'error': 'invalid node name'}), 400
    if not _SAFE.match(str(storage)):
        return jsonify({'error': 'invalid storage name'}), 400
    if name and not _SAFE.match(str(name)):
        return jsonify({'error': 'invalid VM name (allowed: [A-Za-z0-9._-])'}), 400

    if not vmid:
        vmid = _next_free_vmid(mgr)
    try:
        vmid = int(vmid)
    except Exception:
        return jsonify({'error': 'vmid must be integer'}), 400

    if not name:
        name = f"tpl-{tpl['distro']}-{tpl['version']}".replace('.', '')

    user = _current_user()

    dep_id = uuid.uuid4().hex[:12]
    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO cloud_init_deployments
                (id, cluster_id, node, template_id, template_name, vmid, storage,
                 status, progress, log, error, started_by, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, '', '', ?, ?)
        ''', (dep_id, cluster_id, node, template_id, tpl['name'], vmid, storage,
              user, _now_iso()))
        get_db().conn.commit()
    except Exception as e:
        return jsonify({'error': f'db insert failed: {e}'}), 500

    t = threading.Thread(
        target=_run_deploy,
        args=(dep_id, cluster_id, node, template_id, storage, vmid, name),
        daemon=True, name=f"ci-deploy-{dep_id}"
    )
    t.start()

    return jsonify({
        'deployment_id': dep_id,
        'vmid': vmid,
        'name': name,
        'status': 'queued',
    })


@bp.route('/api/clusters/<cluster_id>/templates/deployments', methods=['GET'])
@require_auth(perms=['cluster.view'])
def deployments(cluster_id):
    """List recent deployments for a cluster (newest first)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    try:
        c = get_db().conn.cursor()
        c.execute('''
            SELECT id, cluster_id, node, template_id, template_name, vmid, storage,
                   status, progress, error, started_by, started_at, finished_at
            FROM cloud_init_deployments
            WHERE cluster_id = ?
            ORDER BY started_at DESC LIMIT 50
        ''', (cluster_id,))
        rows = [dict(r) for r in c.fetchall()]
        return jsonify({'deployments': rows})
    except Exception as e:
        logging.exception('handler error in templates_lib.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/templates/deployments/<dep_id>', methods=['GET'])
@require_auth(perms=['cluster.view'])
def deployment_status(dep_id):
    """Detailed view including log tail."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM cloud_init_deployments WHERE id = ?', (dep_id,))
        r = c.fetchone()
        if not r:
            return jsonify({'error': 'not found'}), 404
        d = dict(r)
        return jsonify(d)
    except Exception as e:
        logging.exception('handler error in templates_lib.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/templates/existing', methods=['GET'])
@require_auth(perms=['cluster.view'])
def existing_templates(cluster_id):
    """All existing VM templates on the cluster (template=1) so the UI
    can show 'already deployed' status."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    out = []
    try:
        for r in (mgr.get_vm_resources() or []):
            if r.get('type') != 'qemu': continue
            if r.get('template') != 1: continue
            out.append({
                'vmid': r.get('vmid'),
                'name': r.get('name'),
                'node': r.get('node'),
                'maxdisk': r.get('maxdisk'),
                'maxmem': r.get('maxmem'),
            })
    except Exception as e:
        logging.debug(f"[templates_lib] existing list failed: {e}")
    return jsonify({'templates': out})
