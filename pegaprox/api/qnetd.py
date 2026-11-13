# -*- coding: utf-8 -*-
"""QNetd hosts and the QDevice setup of Proxmox VE clusters (core/qnetd.py) - MK Oct 2026

Every route here is for administrators only: the QDevice routes run root commands on
the nodes and rewrite corosync.conf, the host routes hold an SSH login with root rights on
the QNetd host. A tenant or pool-confined caller reaches none of them (require_unconfined
on top of the role, for the cluster routes).

The reads that ask the QNetd hosts and the nodes are the active's: a standby that forwards
hands them on (ha.FORWARDED_READS), any other standby refuses them, since a 'local' QNetd
host is the machine of the active.
"""

import uuid

from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.core import qnetd
from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.api.helpers import check_cluster_access, require_unconfined

bp = Blueprint('qnetd', __name__)


def _user():
    return request.session.get('user', 'unknown')


def _flag(value):
    return value is True or str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def _standby_refusal():
    from pegaprox.core import ha
    if ha.is_standby():
        return jsonify({'error': 'This is a standby instance: the active one talks to the QNetd hosts'}), 503
    return None


def _host_or_404(host_id, secrets=True):
    rec = qnetd.get_qnetd(host_id, secrets=secrets)
    if rec is None:
        return None, (jsonify({'error': 'QNetd host not found'}), 404)
    return rec, None


def _cluster_or_error(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return None, err
    cerr = require_unconfined(cluster_id)
    if cerr:
        return None, cerr
    mgr = cluster_managers.get(cluster_id)
    if mgr is None:
        return None, (jsonify({'error': 'Cluster not found'}), 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, (jsonify({'error': 'Only a Proxmox VE cluster has a QDevice'}), 400)
    return mgr, None


def _cluster_label(cluster_id):
    mgr = cluster_managers.get(cluster_id)
    return getattr(getattr(mgr, 'config', None), 'name', None) or cluster_id


@bp.route('/api/qnetd/hosts', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def list_qnetd_hosts():
    """The QNetd hosts, the clusters attached to each and their last status"""
    db = get_db()
    by_host = {}
    for a in db.list_qnetd_attachments():
        by_host.setdefault(a['qnetd_id'], []).append(a)
    hosts = [qnetd.public_host(h, by_host.get(h['id'])) for h in db.list_qnetd_hosts()]
    # ha_members: a local or sidecar QNetd host is one member's machine, the wizard warns
    return jsonify({'hosts': hosts, 'protocol': qnetd.PROTOCOL,
                    'transports': qnetd.transports_available(), 'default_port': qnetd.DEFAULT_PORT,
                    'ha_members': qnetd.ha_members()})


@bp.route('/api/qnetd/hosts', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_qnetd_host():
    """Register a QNetd host"""
    fields, password, ssh_key, bad = qnetd.clean_host(request.get_json(silent=True))
    if bad:
        return jsonify({'error': bad}), 400
    db = get_db()
    hosts = db.list_qnetd_hosts()
    if any(h['name'].lower() == fields['name'].lower() for h in hosts):
        return jsonify({'error': 'A QNetd host of that name exists'}), 409
    if fields['kind'] in ('local', 'sidecar') and any(h['kind'] == fields['kind'] for h in hosts):
        return jsonify({'error': f"There is a {fields['kind']} QNetd host already"}), 409
    host_id = uuid.uuid4().hex[:12]
    fields['created_by'] = _user()
    db.save_qnetd_host(host_id, fields, password=password, ssh_key=ssh_key)
    log_audit(_user(), 'qnetd.host_added',
              f"QNetd host {fields['name']} added ({fields['kind']}, {fields['address']}:{fields['port']})")
    return jsonify({'success': True, 'host': qnetd.public_host(db.get_qnetd_host(host_id))}), 201


@bp.route('/api/qnetd/hosts/<host_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_qnetd_host(host_id):
    """Change a QNetd host; password and ssh_key left out stay as they are"""
    old, err = _host_or_404(host_id, secrets=False)
    if err:
        return err
    data = request.get_json(silent=True)
    fields, password, ssh_key, bad = qnetd.clean_host(data, old)
    if bad:
        return jsonify({'error': bad}), 400
    db = get_db()
    attached = db.list_qnetd_attachments(qnetd_id=host_id)
    moved = [k for k in ('kind', 'address', 'port', 'ssh_host', 'ssh_port')
             if str(fields.get(k, '')) != str(old.get(k) or ('' if k != 'ssh_port' else 22))]
    if attached and any(k in moved for k in ('kind', 'address', 'port')):
        return jsonify({'error': 'Clusters vote through this QNetd host at its current address: remove their '
                                 'QDevice first', 'clusters': [a['cluster_name'] for a in attached]}), 409
    # the stored login goes wherever ssh_host/ssh_port point on the next call: moved there, every
    # secret it holds is typed again or cleared in this request, never carried along (as for PBS,
    # the ESXi servers and the clusters - else an edit plus a Check reads the root login out)
    if fields['kind'] == 'ssh' and old.get('kind') == 'ssh' and ('ssh_host' in moved or 'ssh_port' in moved):
        stale = [k for k, held, given in (('password', old.get('has_password'), password),
                                         ('ssh_key', old.get('has_ssh_key'), ssh_key))
                 if held and given is None]
        if stale or not (password or ssh_key):
            return jsonify({'error': 'Enter the SSH password or key again when changing the SSH host or port',
                            'stale': stale}), 400
    if qnetd.busy_with(qnetd_id=host_id):
        return jsonify({'error': 'A QDevice job runs against this QNetd host'}), 409
    hosts = db.list_qnetd_hosts()
    if any(h['id'] != host_id and h['name'].lower() == fields['name'].lower() for h in hosts):
        return jsonify({'error': 'A QNetd host of that name exists'}), 409
    if fields['kind'] in ('local', 'sidecar') and any(h['id'] != host_id and h['kind'] == fields['kind']
                                                      for h in hosts):
        return jsonify({'error': f"There is a {fields['kind']} QNetd host already"}), 409
    db.save_qnetd_host(host_id, fields, password=password, ssh_key=ssh_key)
    # another machine behind the record: whatever CA it has is learnt again
    reset = (isinstance(data, dict) and _flag(data.get('reset_ca_pin'))) or \
        any(k in moved for k in ('kind', 'ssh_host', 'ssh_port'))
    if reset:
        db.set_qnetd_ca_pin(host_id, '')
    qnetd._forget_status(host_id)
    log_audit(_user(), 'qnetd.host_updated', f"QNetd host {fields['name']} changed"
              + (f" ({', '.join(moved)})" if moved else '') + (', CA pin reset' if reset else '')
              + (', password changed' if password is not None and fields['kind'] == 'ssh' else '')
              + (', SSH key changed' if ssh_key is not None and fields['kind'] == 'ssh' else ''))
    return jsonify({'success': True, 'host': qnetd.public_host(db.get_qnetd_host(host_id), attached)})


@bp.route('/api/qnetd/hosts/<host_id>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_qnetd_host(host_id):
    """Forget a QNetd host. Refused while a cluster votes through it"""
    rec, err = _host_or_404(host_id, secrets=False)
    if err:
        return err
    db = get_db()
    attached = db.list_qnetd_attachments(qnetd_id=host_id)
    if attached:
        return jsonify({'error': 'Clusters vote through this QNetd host: remove their QDevice first',
                        'clusters': [a['cluster_name'] for a in attached]}), 409
    if qnetd.busy_with(qnetd_id=host_id):
        return jsonify({'error': 'A QDevice job runs against this QNetd host'}), 409
    db.delete_qnetd_host(host_id)
    qnetd._forget_status(host_id)
    log_audit(_user(), 'qnetd.host_deleted', f"QNetd host {rec['name']} deleted ({rec['address']})")
    return jsonify({'success': True})


@bp.route('/api/qnetd/hosts/<host_id>/check', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def check_qnetd_host(host_id):
    """Make the helper usable and corosync-qnetd run: installs or updates the helper of an
    ssh host where the login may, and runs init unless {"init": false}"""
    rec, err = _host_or_404(host_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'The request body must be a JSON object'}), 400
    if qnetd.busy_with(qnetd_id=host_id):
        return jsonify({'error': 'A QDevice job runs against this QNetd host'}), 409
    result = qnetd.check_host(rec, init=_flag(data.get('init', True)), upgrade=_flag(data.get('upgrade', True)))
    log_audit(_user(), 'qnetd.host_checked', f"QNetd host {rec['name']} checked: "
              + ('ok' if result['ok'] else (result.get('error') or 'not ready'))
              + (', helper installed' if result.get('helper_installed') else ''))
    return jsonify(result)


@bp.route('/api/qnetd/hosts/<host_id>/status', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def qnetd_host_status(host_id):
    """The status of a QNetd host: whether it runs and which clusters are connected
    (corosync-qnetd-tool -l -v), read at most every 30 s. ?cached=1 never asks the host"""
    rec, err = _host_or_404(host_id)
    if err:
        return err
    if _flag(request.args.get('cached')):
        return jsonify({'status': qnetd.public_status(qnetd.cached_status(host_id))})
    refusal = _standby_refusal()
    if refusal:
        return refusal
    return jsonify({'status': qnetd.public_status(qnetd.status(rec))})


@bp.route('/api/clusters/<cluster_id>/qdevice/preflight', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def qdevice_preflight(cluster_id):
    """What a QDevice setup of this cluster against ?qnetd_id= would find"""
    mgr, err = _cluster_or_error(cluster_id)
    if err:
        return err
    rec, err = _host_or_404(request.args.get('qnetd_id', ''))
    if err:
        return err
    refusal = _standby_refusal()
    if refusal:
        return refusal
    report = qnetd.inspect(cluster_id, mgr, rec,
                           install_packages=_flag(request.args.get('install_packages')),
                           confirm_unverified=_flag(request.args.get('confirm_unverified_host')),
                           replace_certificate=_flag(request.args.get('replace_certificate')))
    return jsonify(report)


def _setup_opts(data):
    """The options of a plan or a setup, the same way from a query string and a body: the
    plan's digest covers them, so both have to read them alike."""
    return {'install_packages': _flag(data.get('install_packages')),
            'open_firewall': _flag(data.get('open_firewall')),
            'confirm_unverified_host': _flag(data.get('confirm_unverified_host')),
            'replace_certificate': _flag(data.get('replace_certificate'))}


def _consent_refusal(message, cluster_id=None):
    body = {'error': message, 'code': 'consent_required'}
    if cluster_id is not None:
        body['cluster_id'] = cluster_id
    return jsonify(body), 400


def _digest(value):
    return value if isinstance(value, str) and qnetd.DIGEST_RE.match(value) else None


@bp.route('/api/clusters/<cluster_id>/qdevice/plan', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def qdevice_plan(cluster_id):
    """What a QDevice setup of this cluster against ?qnetd_id= would change, with the digest
    a setup has to agree to. Reads only: nothing is installed or opened anywhere"""
    mgr, err = _cluster_or_error(cluster_id)
    if err:
        return err
    rec, err = _host_or_404(request.args.get('qnetd_id', ''))
    if err:
        return err
    refusal = _standby_refusal()
    if refusal:
        return refusal
    return jsonify(qnetd.plan(cluster_id, mgr, rec, _setup_opts(request.args)))


@bp.route('/api/clusters/<cluster_id>/qdevice/setup', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def qdevice_setup(cluster_id):
    """Set up the QDevice of this cluster against a QNetd host, in the background"""
    mgr, err = _cluster_or_error(cluster_id)
    if err:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'The request body must be a JSON object'}), 400
    rec, err = _host_or_404(str(data.get('qnetd_id') or ''))
    if err:
        return err
    # the admin agrees to the plan of /qdevice/plan; the job reads it again and starts only
    # when it is still the one of this digest
    consent = data.get('consent')
    digest = _digest(consent.get('digest')) if isinstance(consent, dict) and consent.get('accepted') is True \
        else None
    if digest is None:
        return _consent_refusal('Agree to the plan of this cluster first: read it, then start the setup '
                                'with consent {accepted: true, digest}', cluster_id)
    opts = _setup_opts(data)
    opts['consents'] = {cluster_id: digest}
    job = qnetd.Job('setup', rec['id'], [cluster_id], _user(), get_client_ip())
    try:
        qnetd.register(job)
    except qnetd.Busy as e:
        return jsonify({'error': str(e)}), 409
    log_audit(_user(), 'qdevice.setup_started', f"QDevice setup with QNetd host {rec['name']} started "
                                                f"(job {job.id}, plan {digest[:16]})",
              cluster=_cluster_label(cluster_id), cluster_id=cluster_id)
    qnetd.launch(job, qnetd.run_setup, rec, opts)
    return jsonify({'success': True, 'job_id': job.id, 'job': job.view()}), 202


@bp.route('/api/clusters/<cluster_id>/qdevice/remove', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def qdevice_remove(cluster_id):
    """Remove the QDevice of this cluster (pvecm qdevice remove on one node)"""
    mgr, err = _cluster_or_error(cluster_id)
    if err:
        return err
    att = get_db().list_qnetd_attachments(cluster_id=cluster_id)
    job = qnetd.Job('remove', att[0]['qnetd_id'] if att else None, [cluster_id], _user(), get_client_ip())
    try:
        qnetd.register(job)
    except qnetd.Busy as e:
        return jsonify({'error': str(e)}), 409
    log_audit(_user(), 'qdevice.remove_started', f"QDevice removal started (job {job.id})",
              cluster=_cluster_label(cluster_id), cluster_id=cluster_id)
    qnetd.launch(job, qnetd.run_remove)
    return jsonify({'success': True, 'job_id': job.id, 'job': job.view()}), 202


@bp.route('/api/qnetd/hosts/<host_id>/bulk-setup', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def qdevice_bulk_setup(host_id):
    """Set up the QDevice of several clusters against one QNetd host, one after the other.
    One cluster that fails does not stop the rest"""
    rec, err = _host_or_404(host_id)
    if err:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'The request body must be a JSON object'}), 400
    ids = data.get('cluster_ids')
    if not isinstance(ids, list) or not ids or len(ids) > qnetd.BULK_MAX \
            or not all(isinstance(c, str) and 0 < len(c) <= 128 for c in ids):
        return jsonify({'error': f'cluster_ids: a list of 1 to {qnetd.BULK_MAX} cluster ids'}), 400
    ids = list(dict.fromkeys(ids))
    for cid in ids:
        _mgr, cerr = _cluster_or_error(cid)
        if cerr:
            body, code = cerr
            try:
                msg = (body.get_json() or {}).get('error') or 'refused'
            except Exception:
                msg = 'refused'
            return jsonify({'error': f'{cid}: {msg}', 'cluster_id': cid}), code
    # one consent per cluster, for each of them and for nothing else
    consents = data.get('consents')
    if not isinstance(consents, dict):
        return _consent_refusal('consents: the digest of the plan you agreed to, for every cluster', ids[0])
    for cid in ids:
        if _digest(consents.get(cid)) is None:
            return _consent_refusal(f'{cid}: agree to the plan of this cluster first', cid)
    extra = [k for k in consents if k not in ids]
    if extra:
        return _consent_refusal(f'{str(extra[0])[:128]}: a consent for a cluster this run does not set up',
                                str(extra[0])[:128])
    opts = _setup_opts(data)
    opts['consents'] = {cid: consents[cid] for cid in ids}
    job = qnetd.Job('bulk', rec['id'], ids, _user(), get_client_ip())
    try:
        qnetd.register(job)
    except qnetd.Busy as e:
        return jsonify({'error': str(e)}), 409
    log_audit(_user(), 'qdevice.bulk_setup_started',
              f"QDevice bulk setup of {len(ids)} cluster(s) with QNetd host {rec['name']} started (job {job.id})")
    qnetd.launch(job, qnetd.run_bulk, rec, opts)
    return jsonify({'success': True, 'job_id': job.id, 'job': job.view()}), 202


@bp.route('/api/qnetd/jobs', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def list_qdevice_jobs():
    """The QDevice jobs of this instance, newest first, without their step logs"""
    out = []
    for j in qnetd.jobs():
        v = j.view()
        v.pop('steps', None)
        for c in v['clusters'].values():
            c.pop('preflight', None)
        out.append(v)
    return jsonify({'jobs': out})


@bp.route('/api/qnetd/jobs/<job_id>', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_qdevice_job(job_id):
    """One QDevice job with its step log"""
    if not qnetd.JOB_ID_RE.match(job_id or ''):
        return jsonify({'error': 'Job not found'}), 404
    job = qnetd.get_job(job_id)
    if job is None:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job.view())
