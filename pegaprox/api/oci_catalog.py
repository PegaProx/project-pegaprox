# -*- coding: utf-8 -*-
"""
App containers from OCI images - MK Oct 2026.

Proxmox VE 9.1 (released 19 Nov 2025) takes an OCI image as a container template: a
node pulls the image from a registry onto a storage, and the container is created
from that archive like from any other template. Proxmox calls application containers
made this way a technology preview, and so does the page for it.

The calls, as the PVE API viewer (pve-docs/api-viewer/apidoc.js) documents them:

  POST /nodes/{node}/storage/{storage}/oci-registry-pull   reference, filename
      "Pull an OCI image from a registry." Answers with the UPID of the pull. The
      storage needs the content type vztmpl, the archive lands as <filename>.tar and
      a file of that name is never overwritten.
  POST /nodes/{node}/lxc                                   ostemplate=<storage>:vztmpl/<file>.tar
      "Create or restore a container." env is a NUL-separated list of KEY=value.

Pulling takes minutes, so pull and create run as one job in a thread of its own. The
jobs are kept here in memory; the tasks themselves stay in the PVE task log.
"""
import hashlib
import ipaddress
import logging
import re
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import quote

from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.api.helpers import (check_cluster_access, require_unconfined, scope_vm_rows,
                                  register_task_user)

bp = Blueprint('oci_catalog', __name__)

MIN_PVE = (9, 1)

# Kept small on purpose: images that start without any configuration, by a tag that
# keeps getting fixes. A pulled archive is used again for the next container of the
# same reference - delete it from the storage's content to pull a newer build.
CATALOG = [
    {
        'id': 'nginx', 'name': 'nginx',
        'reference': 'docker.io/library/nginx:stable-alpine',
        'description': 'Web server and reverse proxy.',
        'category': 'web', 'ports': [80],
        'cores': 1, 'memory': 256, 'disk_gb': 2,
    },
    {
        'id': 'caddy', 'name': 'Caddy',
        'reference': 'docker.io/library/caddy:2-alpine',
        'description': 'Web server that gets its own certificates.',
        'category': 'web', 'ports': [80, 443],
        'cores': 1, 'memory': 256, 'disk_gb': 2,
    },
    {
        'id': 'redis', 'name': 'Redis',
        'reference': 'docker.io/library/redis:8-alpine',
        'description': 'In-memory key-value store.',
        'category': 'database', 'ports': [6379],
        'cores': 1, 'memory': 512, 'disk_gb': 2,
    },
    {
        'id': 'uptime-kuma', 'name': 'Uptime Kuma',
        'reference': 'docker.io/louislam/uptime-kuma:1',
        'description': 'Uptime monitoring with status pages.',
        'category': 'monitoring', 'ports': [3001],
        'cores': 1, 'memory': 512, 'disk_gb': 4,
    },
    {
        'id': 'grafana', 'name': 'Grafana',
        'reference': 'docker.io/grafana/grafana:latest',
        'description': 'Dashboards for metrics and logs.',
        'category': 'monitoring', 'ports': [3000],
        'cores': 1, 'memory': 512, 'disk_gb': 4,
    },
    {
        'id': 'node-red', 'name': 'Node-RED',
        'reference': 'docker.io/nodered/node-red:4.1',
        'description': 'Flow-based automation in the browser.',
        'category': 'automation', 'ports': [1880],
        'cores': 1, 'memory': 512, 'disk_gb': 4,
    },
    {
        'id': 'whoami', 'name': 'whoami',
        'reference': 'docker.io/traefik/whoami:latest',
        'description': 'Tiny HTTP service that answers with its own address. Good for a first try.',
        'category': 'test', 'ports': [80],
        'cores': 1, 'memory': 64, 'disk_gb': 1,
    },
]


# --- the image reference ------------------------------------------------------------------
#
# PVE checks `reference` against one pattern (apidoc.js, oci-registry-pull). Used as it is
# here it would backtrack for ages on a long near-miss: [a-z\d]+ repeats inside a group
# whose separator [-]* may be empty. Same language, checked a part at a time; the test
# compares the two on generated input.
_PATH_PART = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*', re.ASCII)
_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
_HOST_PART = re.compile(rf'{_LABEL}(?:\.{_LABEL})*(?::[0-9]+)?', re.ASCII)
_TAG = re.compile(r'\w[\w.-]{0,127}', re.ASCII)


def reference_problem(ref):
    """Why PVE would not pull `ref`, or None."""
    if not isinstance(ref, str) or not ref:
        return 'An image reference is required'
    if len(ref) > 255:
        return 'The image reference is too long'
    name, sep, tag = ref.rpartition(':')
    if not sep or '/' in tag or not _TAG.fullmatch(tag):
        return 'The image reference needs a tag, for example docker.io/library/nginx:stable-alpine'
    parts = name.split('/')
    # a first part that reads as a registry is one; the rest are path parts either way
    if len(parts) > 1 and _HOST_PART.fullmatch(parts[0]):
        parts = parts[1:]
    if all(_PATH_PART.fullmatch(p) for p in parts):
        return None
    return 'Not an image reference PVE can pull: [registry/]name:tag, the name in lower case'


def registry_of(ref):
    """The registry a pull of `ref` contacts. The first part names one when it holds a dot,
    a port or is localhost, the way docker references read; else it is Docker Hub."""
    parts = ref.rpartition(':')[0].split('/')
    if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
        return parts[0]
    return 'docker.io'


def registry_problem(ref):
    """The node pulls as root from wherever the reference points. A registry on the LAN is
    fine (a mirror, a Harbor); the node's own loopback and the metadata addresses are not,
    or whoever may type a reference gets them contacted from the node, as with the cloud
    image URLs of templates_lib."""
    host = registry_of(ref)
    if host == 'docker.io':
        return None
    from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError
    try:
        sanitize_outbound_url(f'https://{host}/', allowed_schemes=('https',),
                              allow_private=True, allow_loopback=False)
    except SsrfError as e:
        return f'A node does not pull from {host}: {e}'
    return None


def archive_name(ref):
    """The file name the pull gets, before PVE appends .tar. PVE keeps only what follows
    the last slash and turns anything outside [a-zA-Z0-9_.-] into _ (its
    normalize_content_filename). Doing the slashes here keeps the registry and the path
    in the name, so nginx from two registries are two files.
    
    To prevent collisions where distinct references map to the same filename (e.g.,
    'example.com:5000/team:tag' and 'example.com/5000/team:tag' both becoming
    'example.com_5000_team_tag'), we append a hash of the full reference. This ensures
    each unique reference gets its own cache entry."""
    # Create a human-readable base name
    base = re.sub(r'[^a-zA-Z0-9_.-]', '_', ref)
    # Truncate to leave room for the hash suffix (max filename ~200 chars to be safe)
    if len(base) > 180:
        base = base[:180]
    # Add a hash of the full reference to ensure uniqueness
    ref_hash = hashlib.sha256(ref.encode('utf-8')).hexdigest()[:16]
    return f"{base}_{ref_hash}"


# --- which nodes can do it ----------------------------------------------------------------

def _version_of(pveversion):
    """'pve-manager/9.1.1/42db4a6c' -> ('9.1.1', (9, 1)); ('', None) when unreadable."""
    m = re.search(r'pve-manager/([0-9][0-9.]*)', str(pveversion or ''))
    text = m.group(1) if m else ''
    parts = re.match(r'(\d+)\.(\d+)', text)
    return text, ((int(parts.group(1)), int(parts.group(2))) if parts else None)


_REASONS = {
    'offline': 'The node is offline',
    'unknown_version': 'The Proxmox VE version of the node could not be read',
    'too_old': 'Containers from OCI images need Proxmox VE 9.1 or newer on the node',
}


def node_support(mgr):
    """{node: row} from the node status the manager polls anyway and keeps for a few
    seconds, so opening the page costs no call per node."""
    out = {}
    for name, st in (mgr.get_node_status() or {}).items():
        st = st or {}
        text, ver = _version_of(st.get('pveversion'))
        if st.get('offline') or st.get('status') != 'online':
            reason = 'offline'
        elif ver is None:
            reason = 'unknown_version'
        elif ver < MIN_PVE:
            reason = 'too_old'
        else:
            reason = ''
        out[name] = {'node': name, 'status': st.get('status') or 'unknown', 'pve_version': text,
                     'supported': not reason, 'reason': reason}
    return out


def _proxmox_cluster(cluster_id):
    """(manager, None) for a Proxmox cluster the caller may place guests on, else
    (None, error response). Placing a guest has no per-VM object to ask about yet, so a
    caller confined to pools or single guests gets nothing here, as on template deploy."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    refused = require_unconfined(cluster_id)
    if refused:
        return None, refused
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        return None, (jsonify({'error': 'Cluster not found'}), 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, (jsonify({'error': 'Containers from OCI images need a Proxmox VE cluster'}), 400)
    return mgr, None


# --- the deploy request -------------------------------------------------------------------

_NAME = re.compile(r'[A-Za-z0-9._-]+', re.ASCII)
_NODE = re.compile(_LABEL, re.ASCII)
_STORAGE_ID = re.compile(r'[a-zA-Z][a-zA-Z0-9._-]*[a-zA-Z0-9]', re.ASCII)
# dns-name as pve-common checks it (pve_verify_dns_name)
_HOSTNAME = re.compile(rf'(?:{_LABEL}\.)*{_LABEL}', re.ASCII)
_ENV_KEY = re.compile(r'\w+', re.ASCII)
_ENV_VALUE_BAD = re.compile(r'[\x00-\x08\x0a-\x1f\x7f]')


def _int(body, key, default, lo, hi):
    value = body.get(key)
    if value in (None, ''):
        return default, None
    try:
        # int() would wave through True as 1 and cut 2.9 down to 2
        if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
            raise ValueError
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return None, f'{key} must be a whole number'
    if not lo <= n <= hi:
        return None, f'{key} must be between {lo} and {hi}'
    return n, None


def _env(value):
    """KEY=value pairs as PVE takes them for env (NUL-separated, no control characters
    in a value). A list, or one string with a pair per line."""
    if value in (None, '', []):
        return [], None
    if isinstance(value, str):
        value = [line for line in value.splitlines() if line.strip()]
    if not isinstance(value, list) or len(value) > 64:
        return None, 'env takes at most 64 KEY=value pairs'
    pairs = []
    for item in value:
        key, sep, val = str(item).strip('\r\n').partition('=')
        if not sep or not _ENV_KEY.fullmatch(key):
            return None, f'Not a KEY=value pair: {key[:40]}'
        if _ENV_VALUE_BAD.search(val):
            return None, f'The value of {key} holds a control character'
        pairs.append(f'{key}={val}')
    if sum(len(p) + 1 for p in pairs) > 16384:
        return None, 'The environment is too long'
    return pairs, None


def _default_hostname(ref):
    last = ref.rpartition(':')[0].rsplit('/', 1)[-1]
    return re.sub(r'[^a-zA-Z0-9-]+', '-', last).strip('-')[:63] or 'app'


def parse_deploy(body):
    """(spec, None) or (None, why not). Everything that reaches a PVE parameter is
    checked here against the format the API viewer gives for it."""
    ref = body.get('reference')
    problem = reference_problem(ref)
    if problem:
        return None, problem
    spec = {'reference': ref}
    # pve-node, pve-storage-id (pve-common parse_id) and the bridge pattern of net[n]
    for key, form in (('node', _NODE), ('storage', _STORAGE_ID), ('rootfs_storage', _STORAGE_ID),
                      ('bridge', _NAME)):
        val = body.get(key) or ''
        if key == 'bridge' and not val:
            val = 'vmbr0'
        if not isinstance(val, str) or not form.fullmatch(val) or len(val) > 128:
            return None, f'{key} is missing or not a valid name'
        spec[key] = val
    hostname = body.get('hostname') or _default_hostname(ref)
    # maxLength 255 like the hostname parameter of POST /nodes/{node}/lxc
    if not isinstance(hostname, str) or len(hostname) > 255 or not _HOSTNAME.fullmatch(hostname):
        return None, 'The hostname may hold letters, digits, - and dots'
    spec['hostname'] = hostname
    for key, default, lo, hi in (('vmid', None, 100, 999999999), ('cores', 1, 1, 1024),
                                 ('memory', 512, 16, 4194304), ('swap', 512, 0, 4194304),
                                 ('disk_gb', 4, 1, 65536), ('vlan', None, 1, 4094)):
        spec[key], problem = _int(body, key, default, lo, hi)
        if problem:
            return None, problem
    ip = body.get('ip') or 'dhcp'
    gw = body.get('gw') or ''
    if ip != 'dhcp':
        try:
            if '/' not in str(ip):
                raise ValueError
            ip = str(ipaddress.IPv4Interface(ip))
            gw = str(ipaddress.IPv4Address(gw)) if gw else ''
        except (ValueError, TypeError):
            return None, 'ip is dhcp or an IPv4 address with its prefix length (10.0.0.5/24), gw an IPv4 address'
    elif gw:
        return None, 'A gateway goes with a static address only'
    spec['ip'], spec['gw'] = ip, gw
    spec['env'], problem = _env(body.get('env'))
    if problem:
        return None, problem
    # 0, "0" and "false" mean no as well, not only a JSON false
    spec['start'] = str(body.get('start', True)).strip().lower() not in ('false', '0', 'no', 'off')
    spec['ostemplate'] = f"{spec['storage']}:vztmpl/{archive_name(ref)}.tar"
    if len(spec['ostemplate']) > 255:
        # ostemplate has a maxLength of 255
        return None, 'The image reference is too long for a template name on this storage'
    return spec, None


def create_params(spec, vmid):
    """The body of POST /nodes/{node}/lxc."""
    net = f"name=eth0,bridge={spec['bridge']},ip={spec['ip']}"
    if spec['gw']:
        net += f",gw={spec['gw']}"
    if spec['vlan']:
        net += f",tag={spec['vlan']}"
    data = {
        'vmid': vmid,
        'ostemplate': spec['ostemplate'],
        'hostname': spec['hostname'],
        'cores': spec['cores'],
        'memory': spec['memory'],
        'swap': spec['swap'],
        'rootfs': f"{spec['rootfs_storage']}:{spec['disk_gb']}",
        'net0': net,
        'unprivileged': 1,
        'start': 1 if spec['start'] else 0,
        'description': f"OCI image {spec['reference']}",
    }
    if spec['env']:
        data['env'] = '\0'.join(spec['env'])
    return data


# --- the jobs -----------------------------------------------------------------------------

_jobs = {}
_jobs_lock = threading.Lock()
_KEEP = 100
_POLL_S = 3
_PULL_TIMEOUT_S = 3600
_CREATE_TIMEOUT_S = 1800
# one pull of an archive at a time: a second job for the same file waits and then finds it.
# A fixed set of locks, picked by the archive, so references nobody pulls again leave
# nothing behind; two archives sharing one only wait for each other.
_pull_locks = [threading.Lock() for _ in range(32)]
# and one create at a time per cluster where PegaProx picks the id: the next free id stays
# free until PVE has made the container, so two jobs asking at once would get the same one
_create_locks = [threading.Lock() for _ in range(16)]


class _Failed(Exception):
    pass


def _now():
    return datetime.now().isoformat(timespec='seconds')


def _public(job):
    return {k: v for k, v in job.items() if not k.startswith('_')}


def _set(job, **fields):
    with _jobs_lock:
        job.update(fields)


def _remember(job):
    with _jobs_lock:
        _jobs[job['id']] = job
        done = [j for j in _jobs.values() if j['status'] in ('completed', 'failed')]
        for old in sorted(done, key=lambda j: j['started_at'])[:max(0, len(done) - _KEEP)]:
            _jobs.pop(old['id'], None)


def _stripe(locks, key):
    return locks[hash(key) % len(locks)]


def _next_free_id(mgr):
    """The id PVE would hand out next, or None."""
    nxt = mgr.get_next_vmid()
    if not isinstance(nxt, dict) or not nxt.get('success'):
        return None
    try:
        return int(nxt.get('vmid'))
    except (TypeError, ValueError):
        return None


def _base(mgr):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json"


def _pve_error(resp, what):
    """The message PVE sent, for the job's error line (shown as text, never as markup)."""
    msg = ''
    try:
        body = resp.json() or {}
        msg = str(body.get('message') or '').strip()
        errors = body.get('errors')
        if isinstance(errors, dict) and errors:
            msg = (msg + ' ' + '; '.join(f'{k}: {v}' for k, v in errors.items())).strip()
    except ValueError:
        pass
    msg = ' '.join(msg.split())[:300]
    return f'{what}: {msg}' if msg else f'{what} (HTTP {resp.status_code})'


def _start_task(mgr, job, path, data, what):
    resp = mgr._api_post(_base(mgr) + path, data=data)
    if resp.status_code != 200:
        raise _Failed(_pve_error(resp, what))
    upid = (resp.json() or {}).get('data')
    if not isinstance(upid, str) or not upid.startswith('UPID:'):
        raise _Failed(f'{what}: no task came back')
    register_task_user(upid, job['started_by'], job['cluster_id'])
    return upid


def _task_tail(mgr, node, upid):
    """The last lines of a failed task's log, where skopeo says what went wrong. The log is
    read from its start (limit counts from start), so the limit is set well above what a
    pull or a create ever writes."""
    try:
        resp = mgr._api_get(f"{_base(mgr)}/nodes/{node}/tasks/{quote(upid, safe='')}/log",
                            params={'start': 0, 'limit': 5000})
        lines = [str(row.get('t') or '') for row in ((resp.json() or {}).get('data') or [])
                 if isinstance(row, dict)]
    except Exception:
        return ''
    lines = [ln.strip() for ln in lines if ln.strip() and not ln.startswith('TASK ')]
    return ' / '.join(lines[-3:])[:400]


def _wait(mgr, node, upid, timeout):
    """(ok, exitstatus) of one PVE task, read every few seconds until it stops."""
    url = f"{_base(mgr)}/nodes/{node}/tasks/{quote(upid, safe='')}/status"
    deadline = time.monotonic() + timeout
    while True:
        try:
            resp = mgr._api_get(url)
            if resp.status_code == 200:
                st = (resp.json() or {}).get('data') or {}
                if st.get('status') == 'stopped':
                    status = str(st.get('exitstatus') or '')
                    return status in ('OK', 'WARNINGS'), status
        except Exception as e:
            logging.debug(f"[oci] task status of {upid} not read: {e}")
        if time.monotonic() >= deadline:
            return False, 'no end of the task within the wait'
        time.sleep(_POLL_S)


def _on_storage(mgr, node, storage, volid):
    resp = mgr._api_get(f"{_base(mgr)}/nodes/{node}/storage/{storage}/content",
                        params={'content': 'vztmpl'})
    if resp.status_code != 200:
        raise _Failed(_pve_error(resp, f'The content of {storage} could not be read'))
    return any(isinstance(v, dict) and v.get('volid') == volid
               for v in ((resp.json() or {}).get('data') or []))


def _create(mgr, job, spec):
    """POST /nodes/{node}/lxc and wait for it; the id it was made with."""
    node, vmid = spec['node'], job['vmid']
    if job['_auto_vmid']:
        # minutes may have passed since the id was picked; take what is free now
        nxt = _next_free_id(mgr)
        if nxt is not None and nxt != vmid:
            vmid = nxt
            ok, why = _vmid_in_range(job['_tenant'], vmid)
            if not ok:
                raise _Failed(why)
            _set(job, vmid=vmid)
    _set(job, status='creating')
    upid = _start_task(mgr, job, f'/nodes/{node}/lxc', create_params(spec, vmid),
                       'The container was not created')
    _set(job, create_upid=upid)
    ok, status = _wait(mgr, node, upid, _CREATE_TIMEOUT_S)
    if not ok:
        tail = _task_tail(mgr, node, upid)
        raise _Failed(f'Creating the container failed: {status}' + (f' ({tail})' if tail else ''))
    return vmid


def _run(job_id):
    job = _jobs.get(job_id)
    if job is None:
        return
    spec = job['_spec']
    node, storage = spec['node'], spec['storage']
    mgr = cluster_managers.get(job['cluster_id'])
    try:
        if mgr is None:
            raise _Failed('The cluster is no longer connected to PegaProx')
        with _stripe(_pull_locks, (job['cluster_id'], node, spec['ostemplate'])):
            if _on_storage(mgr, node, storage, spec['ostemplate']):
                _set(job, reused=True)
            else:
                _set(job, status='pulling')
                upid = _start_task(mgr, job, f'/nodes/{node}/storage/{storage}/oci-registry-pull',
                                   {'reference': spec['reference'],
                                    'filename': archive_name(spec['reference'])},
                                   'The pull was refused')
                _set(job, pull_upid=upid)
                ok, status = _wait(mgr, node, upid, _PULL_TIMEOUT_S)
                if not ok:
                    tail = _task_tail(mgr, node, upid)
                    raise _Failed(f'The pull failed: {status}' + (f' ({tail})' if tail else ''))

        if job['_auto_vmid']:
            with _stripe(_create_locks, job['cluster_id']):
                vmid = _create(mgr, job, spec)
        else:
            vmid = _create(mgr, job, spec)
        _set(job, status='completed', finished_at=_now())
        try:
            from pegaprox.utils.realtime import broadcast_action, push_immediate_update
            broadcast_action('create', 'lxc', str(vmid), {'node': node, 'name': spec['hostname']},
                             job['cluster_id'], job['started_by'])
            push_immediate_update(job['cluster_id'], delay=0.5)
        except Exception:
            pass
    except Exception as e:
        if isinstance(e, _Failed):
            error = str(e)
        else:
            logging.exception(f"[oci] job {job_id} failed")
            error = 'Internal error - see the PegaProx log'
        _set(job, status='failed', error=error, finished_at=_now())
        log_audit(job['started_by'], 'container.create_failed',
                  f"CT {job['vmid']} from OCI image {spec['reference']} on {node}: {error}",
                  ip_address=job['_ip'], cluster=job['_cluster_name'])
    finally:
        # the environment may carry secrets; it served its one call
        spec['env'] = []


def _vmid_in_range(tenant_id, vmid):
    """check_tenant_vmid, closed when it cannot run: the range keeps two tenants off
    one id, and a check that did not run cleared nothing."""
    try:
        from pegaprox.utils.rbac import check_tenant_vmid
        return check_tenant_vmid(tenant_id, vmid)
    except Exception as e:
        logging.error(f"[vmid-range] OCI deploy: range check failed, refusing: {e}")
        return False, 'Cannot verify the tenant VMID range right now - check the server logs'


def _spawn(job_id):
    # a user job: in an automatic group each call it sends asks for the lease (#625)
    from pegaprox.core import ha
    threading.Thread(target=ha.as_job(_run, f'oci deploy {job_id}'), args=(job_id,),
                     daemon=True, name=f'oci-deploy-{job_id}').start()


# --- routes -------------------------------------------------------------------------------

@bp.route('/api/oci/catalog', methods=['GET'])
@require_auth()
def catalog():
    """The curated images, and what a node needs to take them."""
    return jsonify({'images': CATALOG, 'min_pve': '.'.join(map(str, MIN_PVE)),
                    'technology_preview': True})


@bp.route('/api/clusters/<cluster_id>/oci/nodes', methods=['GET'])
@require_auth(perms=['vm.create'])
def nodes(cluster_id):
    """Which nodes of the cluster can create containers from OCI images, and why the
    others cannot (offline, version unknown, older than Proxmox VE 9.1)."""
    mgr, err = _proxmox_cluster(cluster_id)
    if err:
        return err
    rows = sorted(node_support(mgr).values(), key=lambda r: r['node'])
    return jsonify({'nodes': rows, 'min_pve': '.'.join(map(str, MIN_PVE))})


@bp.route('/api/clusters/<cluster_id>/oci/deploy', methods=['POST'])
@require_auth(perms=['vm.create'])
def deploy(cluster_id):
    """Pull an OCI image onto a storage of a node and create a container from it.

    Body: reference, node, storage (takes the image), rootfs_storage, disk_gb, hostname,
    vmid (optional), cores, memory, swap, bridge, vlan, ip ('dhcp' or address/prefix),
    gw, env (KEY=value list), start. Answers with the job; its progress is under
    /api/clusters/<cluster_id>/oci/jobs."""
    mgr, err = _proxmox_cluster(cluster_id)
    if err:
        return err
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'The body is a JSON object'}), 400
    spec, problem = parse_deploy(body)
    if not problem:
        problem = registry_problem(spec['reference'])
    if problem:
        return jsonify({'error': problem}), 400
    node = spec['node']

    support = node_support(mgr).get(node)
    if support is None:
        return jsonify({'error': f'{node} is not a node of this cluster'}), 404
    if not support['supported']:
        return jsonify({'error': _REASONS[support['reason']], 'reason': support['reason'],
                        'pve_version': support['pve_version']}), 400

    storages = {s.get('storage'): s for s in (mgr.get_storage_list(node) or []) if isinstance(s, dict)}
    for key, content, label in (('storage', 'vztmpl', 'container templates'),
                                 ('rootfs_storage', 'rootdir', 'container disks')):
        st = storages.get(spec[key])
        if st is None:
            return jsonify({'error': f"{node} has no storage {spec[key]}"}), 400
        if content not in str(st.get('content') or '').split(',') or st.get('enabled') == 0 \
                or st.get('active') == 0:
            return jsonify({'error': f"{spec[key]} on {node} takes no {label}"}), 400

    username = request.session.get('user', '')
    caller = build_authz_user(username, request.session)
    from pegaprox.utils.rbac import check_tenant_quota, DEFAULT_TENANT_ID
    tenant = caller.get('tenant_id') or DEFAULT_TENANT_ID

    # tenant quota, open on a failed check like the container create route
    try:
        quota = check_tenant_quota(tenant, add_cores=spec['cores'], add_mem_gb=spec['memory'] / 1024.0,
                                   add_vms=1, add_disk_gb=spec['disk_gb'])
        if not quota['ok'] and quota.get('enforce') == 'block':
            return jsonify({'error': f"Tenant quota exceeded ({', '.join(quota['violations'])})",
                            'quota': quota}), 403
    except Exception as e:
        logging.debug(f"[quota] OCI deploy pre-flight skipped: {e}")

    vmid, auto_vmid = spec['vmid'], spec['vmid'] is None
    if auto_vmid:
        vmid = _next_free_id(mgr)
        if vmid is None:
            return jsonify({'error': 'No free CT ID could be read from the cluster'}), 502
    ok, why = _vmid_in_range(tenant, vmid)
    if not ok:
        return jsonify({'error': why}), 403

    job = {
        'id': uuid.uuid4().hex[:12], 'cluster_id': cluster_id, 'node': node,
        'reference': spec['reference'], 'storage': spec['storage'], 'vmid': vmid,
        'hostname': spec['hostname'], 'status': 'queued', 'reused': False, 'error': '',
        'pull_upid': '', 'create_upid': '', 'started_by': username,
        'started_at': _now(), 'finished_at': '',
        '_spec': spec, '_auto_vmid': auto_vmid, '_tenant': tenant, '_ip': get_client_ip(),
        '_cluster_name': getattr(mgr.config, 'name', cluster_id),
    }
    _remember(job)
    log_audit(username, 'container.create',
              f"Creating CT {vmid} ({spec['hostname']}) on {node} from OCI image {spec['reference']}",
              cluster=job['_cluster_name'])
    _spawn(job['id'])
    return jsonify({'job': _public(job)})


@bp.route('/api/clusters/<cluster_id>/oci/jobs', methods=['GET'])
@require_auth(perms=['cluster.view'])
def jobs(cluster_id):
    """The recent pulls and creates on this cluster, newest first."""
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    with _jobs_lock:
        rows = [_public(j) for j in _jobs.values() if j['cluster_id'] == cluster_id]
    rows.sort(key=lambda j: j['started_at'], reverse=True)
    # a row names the CT it makes: only callers who may see that CT get it
    return jsonify({'jobs': scope_vm_rows(cluster_id, [dict(r, type='lxc') for r in rows[:50]])})
