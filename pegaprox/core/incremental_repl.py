"""
Incremental cross-cluster replication for storage that supports native
send/receive of snapshot deltas — Ceph RBD (export-diff/import-diff) and ZFS
(send/recv). NS 2026-07-17 (#174 aderumier).

The existing cross-cluster replication (api/vms.py _execute_replication) does a
FULL clone + remote-migrate of the whole disk every cycle — correct for any
storage, but it re-ships every byte, so it does not scale to big VMs. For RBD
and ZFS we can instead ship only the delta between two snapshots.

Data path — PegaProx byte-relay (no direct node-to-node link required):
PegaProx already holds SSH to both clusters, so it runs the exporter on a source
node, the importer on a target node, and relays the bytes between the two SSH
channels itself. This avoids assuming the source node can reach the target node
directly (pve-zsync's model), which rarely holds across separate clusters/sites.

    source node                PegaProx                 target node
    rbd export-diff  --stdout-->  relay  --stdin-->  rbd import-diff

This module is storage-primitive only: it moves one disk's delta and manages the
snapshot chain. The VM-level orchestration (which disks, the snapshot on the
guest, the replica VM config) lives in the replication engine that calls this.
"""

import os
import time
import logging

logger = logging.getLogger(__name__)

# rbd/zfs progress goes to stderr; suppress it so a long transfer can't dead-
# lock the relay by filling an undrained stderr buffer.
_RBD = "rbd --no-progress"


def _relay_pipe(src_ssh, src_cmd, tgt_ssh, tgt_cmd, chunk=4 * 1024 * 1024,
                timeout=14400, log=None):
    """Run src_cmd on the source (its stdout is the data stream) and pipe that
    stream into tgt_cmd's stdin on the target, relaying the bytes through this
    process. Returns dict(ok, bytes, src_rc, tgt_rc, error).

    Both remote commands MUST keep stderr small (we don't drain it until the
    end) — callers use --no-progress / 2>/tmp/... to that effect.
    """
    def _emit(m):
        if log:
            try: log(m)
            except Exception: pass

    # A single-threaded relay must NOT let either remote command write to a
    # stream we don't drain: the exporter's stdout IS the data (we read it) and
    # the importer's stdin IS the data (we write it), but the exporter's stderr
    # and the importer's stdout+stderr would otherwise fill their SSH-channel
    # windows, block the remote process, and deadlock the pipe. Park those
    # streams in files on the respective node and slurp them back at the end.
    tok = f"/tmp/pegaprox-repl-{os.getpid()}-{int(time.time() * 1000) % 100000}"
    full_src = f"{src_cmd} 2>{tok}.serr"
    full_tgt = f"{tgt_cmd} >{tok}.tout 2>{tok}.terr"
    _emit(f"exec[src]: {src_cmd}")
    _si, _so, _se = src_ssh.exec_command(full_src, timeout=timeout)
    _emit(f"exec[tgt]: {tgt_cmd}")
    _ti, _to, _te = tgt_ssh.exec_command(full_tgt, timeout=timeout)

    src_chan = _so.channel          # exporter: read its stdout (the data stream)
    tgt_chan = _ti.channel          # importer: write its stdin (the data stream)
    src_chan.settimeout(timeout)
    tgt_chan.settimeout(timeout)
    total = 0
    relay_err = None
    try:
        while True:
            data = src_chan.recv(chunk)
            if not data:
                break               # source EOF
            tgt_chan.sendall(data)  # loops internally; honours window backpressure
            total += len(data)
    except Exception as e:
        relay_err = f"relay error after {total} bytes: {type(e).__name__}: {e}"
        logger.error(f"[INCR-REPL] {relay_err}")
    finally:
        # Signal EOF to the importer's stdin so it can finish and exit.
        try: tgt_chan.shutdown_write()
        except Exception: pass

    src_rc = src_chan.recv_exit_status()
    tgt_rc = tgt_chan.recv_exit_status()

    def _slurp(ssh, path):
        try:
            _i, o, _e = ssh.exec_command(f"cat {path} 2>/dev/null; rm -f {path}", timeout=20)
            return o.read().decode('utf-8', 'replace').strip()
        except Exception:
            return ''
    src_err = _slurp(src_ssh, f"{tok}.serr")
    tgt_err = _slurp(tgt_ssh, f"{tok}.terr")
    _slurp(tgt_ssh, f"{tok}.tout")   # importer stdout — discard, just clean up

    parts = [p for p in (relay_err, src_err and f"src: {src_err}",
                         tgt_err and f"tgt: {tgt_err}") if p]
    ok = (relay_err is None) and src_rc == 0 and tgt_rc == 0
    return {'ok': ok, 'bytes': total, 'src_rc': src_rc, 'tgt_rc': tgt_rc,
            'error': ' | '.join(parts)}


# ------------------------------------------------------------------ RBD -----

def rbd_snap_exists(ssh, pool, image, snap, timeout=30):
    """True if <pool>/<image>@<snap> exists on the node reached by ssh.
    (Query/management rbd subcommands don't accept the export-only
    --no-progress flag, so they use plain `rbd`.)"""
    cmd = f"rbd snap ls {_q(pool)}/{_q(image)} 2>/dev/null | awk '{{print $2}}'"
    _i, o, _e = ssh.exec_command(cmd, timeout=timeout)
    snaps = o.read().decode('utf-8', 'replace').split()
    return snap in snaps


def rbd_image_exists(ssh, pool, image, timeout=30):
    cmd = f"rbd info {_q(pool)}/{_q(image)} >/dev/null 2>&1 && echo YES || echo NO"
    _i, o, _e = ssh.exec_command(cmd, timeout=timeout)
    return 'YES' in o.read().decode('utf-8', 'replace')


def rbd_replicate_disk(src_ssh, tgt_ssh, src_pool, src_image, tgt_pool, tgt_image,
                       new_snap, base_snap=None, log=None):
    """Replicate one RBD image's state at <new_snap> from source to target.

    Requires the snapshot <src_pool>/<src_image>@<new_snap> to already exist on
    the source (the caller takes it — usually via a guest-level `qm snapshot`).

    - SEED (base_snap is None, or missing on either side, or target image absent):
      ship the full image as a diff-from-zero. `rbd import-diff` CREATES the
      target image and its @new_snap.
    - INCREMENTAL: ship only base_snap..new_snap. The target image MUST already
      carry @base_snap; import-diff fast-forwards it to @new_snap.

    Returns dict(ok, mode, bytes, error).
    """
    if not rbd_snap_exists(src_ssh, src_pool, src_image, new_snap):
        return {'ok': False, 'mode': None, 'bytes': 0,
                'error': f'source snapshot {src_pool}/{src_image}@{new_snap} missing'}

    incremental = bool(base_snap) \
        and rbd_snap_exists(src_ssh, src_pool, src_image, base_snap) \
        and rbd_image_exists(tgt_ssh, tgt_pool, tgt_image) \
        and rbd_snap_exists(tgt_ssh, tgt_pool, tgt_image, base_snap)

    tgt = f"{_q(tgt_pool)}/{_q(tgt_image)}"
    src_snap_ref = f"{_q(src_pool)}/{_q(src_image)}@{_q(new_snap)}"

    if incremental:
        # Only the base_snap..new_snap delta. import-diff fast-forwards the
        # existing target image (which carries @base_snap) and creates @new_snap.
        mode = 'incremental'
        src_cmd = f"{_RBD} export-diff --from-snap {_q(base_snap)} {src_snap_ref} -"
        tgt_cmd = f"{_RBD} import-diff - {tgt}"
        if log: log(f"RBD incremental: {src_pool}/{src_image}@{base_snap}..@{new_snap} -> {tgt_pool}/{tgt_image}")
        res = _relay_pipe(src_ssh, src_cmd, tgt_ssh, tgt_cmd, log=log)
        res['mode'] = mode
        return res

    # SEED: `rbd import-diff` refuses to CREATE a target image ("No such file or
    # directory"), so the first copy is a full `rbd export | rbd import` (which
    # creates the image at the exact size), followed by creating @new_snap on the
    # target so the next run has a base to diff against. A stale/partial target
    # is removed first — a re-seed replaces it wholesale.
    mode = 'seed'
    if rbd_image_exists(tgt_ssh, tgt_pool, tgt_image):
        if log: log(f"RBD seed: removing stale target {tgt_pool}/{tgt_image}")
        _ssh_run(tgt_ssh, f"rbd snap purge {tgt} 2>/dev/null; rbd rm {tgt} 2>/dev/null", timeout=300)
    src_cmd = f"{_RBD} export {src_snap_ref} -"
    tgt_cmd = f"{_RBD} import - {tgt}"
    if log: log(f"RBD seed (full): {src_pool}/{src_image}@{new_snap} -> {tgt_pool}/{tgt_image}")
    res = _relay_pipe(src_ssh, src_cmd, tgt_ssh, tgt_cmd, log=log)
    res['mode'] = mode
    if res['ok']:
        # anchor the incremental chain: snapshot the freshly-seeded target
        _ssh_run(tgt_ssh, f"rbd snap create {tgt}@{_q(new_snap)}", timeout=60)
        if not rbd_snap_exists(tgt_ssh, tgt_pool, tgt_image, new_snap):
            res['ok'] = False
            res['error'] = (res.get('error') or '') + ' | seed copied but base snapshot could not be created on target'
    return res


def rbd_prune_snapshots(ssh, pool, image, keep_snaps, prefix, timeout=60, log=None):
    """Delete replication snapshots (name starts with `prefix`) on <pool>/<image>
    except those in keep_snaps. Keeps the chain bounded on both sides."""
    cmd = f"rbd snap ls {_q(pool)}/{_q(image)} 2>/dev/null | awk '{{print $2}}'"
    _i, o, _e = ssh.exec_command(cmd, timeout=timeout)
    snaps = [s for s in o.read().decode('utf-8', 'replace').split()
             if s.startswith(prefix) and s not in keep_snaps]
    for s in snaps:
        ssh.exec_command(f"rbd snap rm {_q(pool)}/{_q(image)}@{_q(s)} 2>/dev/null")
        if log: log(f"pruned snapshot {pool}/{image}@{s}")
    return snaps


# ------------------------------------------------------------------ ZFS -----
# Analogous to RBD: `zfs send [-i base] pool/vol@snap | zfs recv -F target`.
# Built to mirror the RBD path; NOT lab-verified (no ZFS pool available here).

def zfs_snap_exists(ssh, dataset, snap, timeout=30):
    _i, o, _e = ssh.exec_command(
        f"zfs list -t snapshot -o name -H {_q(dataset)}@{_q(snap)} >/dev/null 2>&1 "
        f"&& echo YES || echo NO", timeout=timeout)
    return 'YES' in o.read().decode('utf-8', 'replace')


def zfs_replicate_dataset(src_ssh, tgt_ssh, src_dataset, tgt_dataset,
                          new_snap, base_snap=None, log=None):
    """Replicate a ZFS dataset's @new_snap from source to target via send/recv.

    SEED: `zfs send src@new_snap | zfs recv -F tgt`.
    INCREMENTAL: `zfs send -i base src@new_snap | zfs recv tgt` (tgt must hold
    @base_snap). Returns dict(ok, mode, bytes, error).
    """
    if not zfs_snap_exists(src_ssh, src_dataset, new_snap):
        return {'ok': False, 'mode': None, 'bytes': 0,
                'error': f'source snapshot {src_dataset}@{new_snap} missing'}
    incremental = bool(base_snap) \
        and zfs_snap_exists(src_ssh, src_dataset, base_snap) \
        and zfs_snap_exists(tgt_ssh, tgt_dataset, base_snap)
    if incremental:
        mode = 'incremental'
        src_cmd = (f"zfs send -i {_q(src_dataset)}@{_q(base_snap)} "
                   f"{_q(src_dataset)}@{_q(new_snap)}")
        tgt_cmd = f"zfs recv {_q(tgt_dataset)}"
    else:
        mode = 'seed'
        src_cmd = f"zfs send {_q(src_dataset)}@{_q(new_snap)}"
        tgt_cmd = f"zfs recv -F {_q(tgt_dataset)}"
    if log: log(f"ZFS {mode}: {src_dataset}@{new_snap} -> {tgt_dataset}")
    res = _relay_pipe(src_ssh, src_cmd, tgt_ssh, tgt_cmd, log=log)
    res['mode'] = mode
    return res


def zfs_prune_snapshots(ssh, dataset, keep_snaps, prefix, timeout=60, log=None):
    """Delete replication snapshots (@<prefix>…) on a ZFS dataset except those in
    keep_snaps — keeps the send/recv base chain bounded on both sides."""
    out = _ssh_run(ssh, f"zfs list -t snapshot -o name -H {_q(dataset)} 2>/dev/null", timeout=timeout)
    pruned = []
    for line in (out or '').split('\n'):
        line = line.strip()
        if not line.startswith(f"{dataset}@"):
            continue
        snap = line.split('@', 1)[1]
        if snap.startswith(prefix) and snap not in keep_snaps:
            _ssh_run(ssh, f"zfs destroy {_q(line)} 2>/dev/null", timeout=timeout)
            pruned.append(snap)
            if log: log(f"pruned zfs snapshot {line}")
    return pruned


# ---------------------------------------------------------------- helpers ---

def _q(s):
    """shell-quote a single token (pool / image / snapshot / dataset name)."""
    import shlex
    return shlex.quote(str(s))


def _ssh_run(ssh, cmd, timeout=60):
    """Run a command over ssh, return combined stdout+stderr (best-effort)."""
    try:
        _i, o, e = ssh.exec_command(cmd, timeout=timeout)
        return (o.read() + e.read()).decode('utf-8', 'replace').strip()
    except Exception as ex:
        return f'ssh-run error: {ex}'
