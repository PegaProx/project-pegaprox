"""Instance-wide image catalog and direct VM provisioning, without a PVE cluster."""
import logging
import re
import threading
import uuid
from pathlib import Path

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import check_cluster_access, require_unconfined
from pegaprox.api.templates_lib import CATALOG
from pegaprox.core import image_library as library
from pegaprox.core.db import get_db
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import log_audit
from pegaprox.utils.auth import require_auth

bp = Blueprint('image_library', __name__)


def recover_interrupted_jobs():
    # Never replay a create: the VM may already exist on the remote node.
    conn = get_db().conn
    conn.execute("""UPDATE image_provision_jobs SET status='failed', finished_at=?,
        error='PegaProx restarted during provisioning; check the target node and recorded VMID before retrying'
        WHERE status IN ('queued', 'running')""", (library.now(),))
    conn.commit()


bp.record_once(lambda state: recover_interrupted_jobs())


def current_username():
    return request.session['user']


def catalog():
    presets = [dict(item, kind='cloud', source_url=item['image_url'], builtin=True)
               for item in CATALOG]
    custom = [dict(row, builtin=False) for row in get_db().conn.execute(
        'SELECT * FROM image_library ORDER BY created_at DESC').fetchall()]
    return custom + presets


def find_image(image_id):
    return next((image for image in catalog() if image['id'] == image_id), None)


def public_image(image):
    fields = ('id', 'name', 'kind', 'builtin', 'filename', 'default_user', 'cores',
              'memory', 'disk_gb', 'cpu', 'description', 'sha256', 'created_at')
    result = {key: image[key] for key in fields if key in image}
    path = library.cache_path(image)
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        size = 0
    result.update(cached=size > 0, size=size)
    return result


def checked_manager(cluster_id):
    ok, error = check_cluster_access(cluster_id)
    if not ok:
        return None, error
    error = require_unconfined(cluster_id)
    if error:
        return None, error
    manager = cluster_managers.get(cluster_id)
    if manager is None:
        return None, (jsonify({'error': 'Connection not found'}), 404)
    if getattr(manager, 'cluster_type', 'proxmox') != 'proxmox':
        return None, (jsonify({'error': 'Image provisioning requires Proxmox VE'}), 400)
    return manager, None


def image_fields(body):
    if not isinstance(body, dict):
        raise ValueError('Expected an object')
    name, kind = body.get('name'), body.get('kind')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 128 or any(ord(c) < 32 for c in name):
        raise ValueError('Image name must contain 1–128 printable characters')
    if kind not in ('iso', 'cloud'):
        raise ValueError('Image kind must be iso or cloud')
    checksum = body.get('sha256', '')
    if not isinstance(checksum, str) or (checksum and not re.fullmatch(r'[a-fA-F0-9]{64}', checksum)):
        raise ValueError('SHA-256 must contain 64 hexadecimal characters')
    user = body.get('default_user', 'root')
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('Invalid default Cloud-init username')
    return dict(id=uuid.uuid4().hex, name=name.strip(), kind=kind,
                sha256=checksum.lower(), default_user=user,
                created_by=current_username(), created_at=library.now())


def save_image(image):
    fields = tuple(image)
    conn = get_db().conn
    conn.execute(f"INSERT INTO image_library ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                 tuple(image.values()))
    conn.commit()
    log_audit(image['created_by'], 'image.add', f"Added central image {image['name']} ({image['id']})")


@bp.route('/api/images', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_images():
    # Administrators curate a common catalog; source URLs and author identities
    # are deliberately excluded from the user-facing listing.
    return jsonify({'images': [public_image(image) for image in catalog()]})


@bp.route('/api/images', methods=['POST'])
@require_auth(roles=['admin'], perms=['admin.settings'])
def add_url_image():
    try:
        body = request.get_json(silent=True)
        image = image_fields(body)
        url = body.get('source_url')
        if not isinstance(url, str) or len(url) > 4096:
            raise ValueError('A public HTTP(S) image URL is required')
        image['source_url'] = library.validate_source_url(url)
        save_image(image)
        return jsonify(public_image(image)), 201
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@bp.route('/api/images/upload', methods=['POST'])
@require_auth(roles=['admin'], perms=['admin.settings'])
def upload_image():
    image = None
    try:
        # Apply the image-specific cap before Werkzeug spools multipart files.
        request.max_content_length = min(request.max_content_length or float('inf'),
                                         library.max_image_bytes() + 1024 * 1024)
        image = image_fields(request.form.to_dict())
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            raise ValueError('Select an image file')
        suffix = Path(uploaded.filename).suffix.lower()
        if suffix not in (('.iso',) if image['kind'] == 'iso' else ('.img', '.qcow2')):
            raise ValueError('Use .iso for installation media or an uncompressed .img/.qcow2 cloud image')
        image['filename'] = Path(uploaded.filename.replace('\\', '/')).name[:255]
        destination = library.cache_path(image)
        image['size'], image['sha256'] = library.write_image(
            iter(lambda: uploaded.stream.read(1024 * 1024), b''), destination, image['sha256'])
        save_image(image)
        return jsonify(public_image(image)), 201
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    finally:
        # If persistence fails after the file write, do not leave an orphan.
        if image and not get_db().conn.execute('SELECT 1 FROM image_library WHERE id=?',
                                               (image['id'],)).fetchone():
            library.cache_path(image).unlink(missing_ok=True)


@bp.route('/api/images/<image_id>', methods=['DELETE'])
@require_auth(roles=['admin'], perms=['admin.settings'])
def delete_image(image_id):
    image = find_image(image_id)
    if not image:
        return jsonify({'error': 'Image not found'}), 404
    lock = library.cache_lock(image_id)
    if not lock.acquire(blocking=False):
        return jsonify({'error': 'Image cache is in use; try again after its jobs finish'}), 409
    try:
        conn = get_db().conn
        if conn.execute("SELECT 1 FROM image_provision_jobs WHERE image_id=? AND status IN ('queued','running')",
                        (image_id,)).fetchone():
            return jsonify({'error': 'Image is being provisioned; wait for its jobs to finish'}), 409
        library.cache_path(image).unlink(missing_ok=True)
        conn.execute('DELETE FROM image_library WHERE id=?', (image_id,))
        conn.commit()
    finally:
        lock.release()
    log_audit(current_username(), 'image.delete', f'Deleted central image/cache {image_id}')
    # Curated entries remain in the catalog and can be downloaded again.
    return jsonify({'success': True})


def start_job(job_id, manager, image, config):
    from pegaprox.core import ha
    threading.Thread(target=ha.as_job(library.provision_vm, f'image provisioning {job_id}'),
                     args=(job_id, manager, image, config), daemon=True,
                     name=f'image-{job_id}').start()


@bp.route('/api/clusters/<cluster_id>/images/targets', methods=['GET'])
@require_auth(roles=['admin'], perms=['vm.create'])
def get_targets(cluster_id):
    manager, error = checked_manager(cluster_id)
    if error:
        return error
    try:
        return jsonify(library.target_options(manager, request.args.get('node')))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        logging.exception('Could not load central image provisioning targets')
        return jsonify({'error': 'Could not reach the Proxmox connection'}), 502


@bp.route('/api/clusters/<cluster_id>/images/provision', methods=['POST'])
@require_auth(roles=['admin'], perms=['vm.create'])
def create_from_image(cluster_id):
    manager, error = checked_manager(cluster_id)
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'Expected a JSON object'}), 400
    image = find_image(body.get('image_id'))
    if not image:
        return jsonify({'error': 'Image not found'}), 404
    try:
        node = body.get('node')
        if not isinstance(node, str) or not library.SAFE_NAME.fullmatch(node):
            raise ValueError('Invalid node')
        config = library.validate_vm_request(body, image, library.target_options(manager, node))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        logging.exception('Could not validate central image destination')
        return jsonify({'error': 'Could not reach the Proxmox connection'}), 502
    if not library.PROVISION_SLOTS.acquire(blocking=False):
        return jsonify({'error': 'Two image jobs are already running; try again after one finishes'}), 429
    job_id = uuid.uuid4().hex
    try:
        with library.cache_lock(image['id']):
            # A delete may have won while we fetched the target's resources.
            if not find_image(image['id']):
                library.PROVISION_SLOTS.release()
                return jsonify({'error': 'Image was removed'}), 404
            conn = get_db().conn
            conn.execute('''INSERT INTO image_provision_jobs
                (id,cluster_id,node,image_id,image_name,name,vmid,started_by,started_at)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (job_id, cluster_id, config['node'], image['id'], image['name'], config['name'],
                 config.get('vmid'), current_username(), library.now()))
            conn.commit()
            log_audit(current_username(), 'vm.image.provision',
                      f"Queued image {image['id']} to {config['node']} as {config['name']} (job {job_id})",
                      cluster=manager.config.name)
            start_job(job_id, manager, image, config)
    except Exception:
        library.PROVISION_SLOTS.release()
        library.update_job(job_id, status='failed', error='Could not start provisioning', finished_at=library.now())
        logging.exception('Could not queue image provisioning')
        return jsonify({'error': 'Could not start provisioning'}), 500
    return jsonify({'job_id': job_id, 'status': 'queued'}), 202


@bp.route('/api/clusters/<cluster_id>/images/jobs', methods=['GET'])
@require_auth(roles=['admin'], perms=['cluster.view'])
def list_jobs(cluster_id):
    _, error = checked_manager(cluster_id)
    if error:
        return error
    rows = get_db().conn.execute('''SELECT * FROM image_provision_jobs WHERE cluster_id=?
                                   ORDER BY started_at DESC LIMIT 50''', (cluster_id,)).fetchall()
    return jsonify({'jobs': [dict(row) for row in rows]})
