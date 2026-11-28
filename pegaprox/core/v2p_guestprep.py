# -*- coding: utf-8 -*-
"""The optional Windows preparation of an ESXi migration in the running source guest.

MK Nov 2026 - a Windows guest is prepared without any login by default, offline on the target
node after the copy (core/v2p_winprep.py). With a Windows administrator login typed in per
migration, PegaProx prepares it before the copy as well, over the guest operations of the ESXi
host (core/esxi_guestops.py), with one static PowerShell script (v2p_guestprep.ps1, the same
bytes an admin can download and run by hand): the drivers are in the Driver Store before the
first boot on KVM.

    planning   probe()     read-only checks; the script goes to a private temp folder of the
                           account and, in mode Probe, locks <ProgramData>\\KVMMigration down
                           and writes probe.json there
    pre-gate   prepare()   the target node puts the OS-matching driver folders of the
                           virtio-win.iso, the guest tools installer, the agent package and
                           firstboot.cmd into the guest; mode Start runs the SYSTEM task that
                           does stage 1 (drivers, tools, saved network, the first boot task)
                           and then waits for go.flag or abort.flag; firstboot-data.cmd follows
    cutover    go()        go.flag: the guest releases its static IPv4, uninstalls the ESXi
                           guest tools and shuts down; PegaProx waits for it to be off
    rollback   roll_back() the copy or the switchover failed after that: the source is powered
                           on again in ESXi with the installer of its guest tools mounted, and
                           its first boot task reinstalls them and puts the address back

It never fails a migration: guest tools not running, a login refused, a UAC-filtered token, a
blocking policy, any failure before go.flag (fallback()): PegaProx says why and prepares the
guest offline. The guest password goes into the SOAP calls and nowhere else: not to the node,
not into the guest, not into pegaprox.json, never logged or returned; go() wipes it.
"""

import json
import os
import re
import shlex
import time
from urllib.parse import urlsplit

from pegaprox.core.esxi_guestops import GuestOpsError, GuestSession, pinned_key

WORK_DIR = 'KVMMigration'
SCRIPT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'v2p_guestprep.ps1')
SCRIPT_NAME = 'Prepare-KvmMigration.ps1'
PROBE_SECONDS = 180
START_SECONDS = 60
STAGE1_SECONDS = 1800
POLL_SECONDS = 10
OFF_SECONDS = 900
GO_WAIT_SECONDS = 86400
LOG_CAP = 1024 * 1024
LOG_PREFIX = '[guest] '
MIN_BUILD = 9200
MIN_FREE_MB = 300
UPLOAD_BATCH = 16
# the most the script waits for its go (it reads go_wait_seconds of pegaprox.json)
GO_WAIT_MAX = 40 * 86400
KEEPS_RUNNING = 'The source VM was not changed by it and keeps running.'

# the guest's own ProgramData and SystemRoot: they go into the powershell.exe argument line
_GUEST_PATH_RE = re.compile(r'^[A-Za-z]:\\[A-Za-z0-9 ._()\\-]{0,200}\Z')
# the account's temp folder may carry a short name (ADMINI~1) or letters beyond ASCII; nothing
# that ends the quoted argument or expands in it
_TEMP_PATH_RE = re.compile(r'^[A-Za-z]:\\[^"%\x00-\x1f\x7f]{0,240}\Z')
# a file of the ISO as the node lists it
_REL_RE = re.compile(r'^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,3}\Z')
_NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,128}\Z')
INSTALLERS = ('virtio-win-guest-tools.exe', 'virtio-win-gt-x64.msi')
AGENT_MSI = 'guest-agent/qemu-ga-x86_64.msi'

# (lowest build, folders for a server, folders for a client), first that has a .sys wins.
# The same table is Get-DriverFolders of the script.
DRIVER_TABLE = (
    (22000, ('2k25', '2k22', 'w11'), ('w11', '2k25', '2k22')),
    (20348, ('2k22', 'w11'), ('w11', '2k22')),
    (17763, ('2k19', 'w10', '2k16'), ('w10', '2k19', 'w11')),
    (14393, ('2k16', 'w10', '2k19'), ('w10', '2k16')),
    (10240, ('2k16', 'w10'), ('w10', '2k19', 'w11')),
    (9600, ('2k12R2', 'w8.1'), ('w8.1', '2k12R2')),
    (9200, ('2k12', 'w8'), ('w8', '2k12')),
    (0, ('2k8R2',), ('w7',)),
)

_script = {}


class GuestPrepFailed(Exception):
    """The preparation stopped before anything destructive ran in the guest"""

    def __init__(self, why, step='the check'):
        super().__init__(f'{step}: {why}')
        self.why, self.step = str(why), step


class _StepFailed(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


def script_bytes():
    """The script as it ships, read once. Nothing formats or joins it: the manual download
    and the automatic run hand out the same bytes."""
    if 'b' not in _script:
        with open(SCRIPT_FILE, 'rb') as fh:
            _script['b'] = fh.read()
    return _script['b']


def driver_folders(build, product_type=1):
    """(primary, [fallbacks]) of the virtio-win.iso folders for a Windows build. product_type
    is Win32_OperatingSystem's: 1 a client, 2 and 3 a server. A client and a server build of
    one number take different folders (26100: w11 or 2k25)."""
    try:
        b = int(build or 0)
    except (TypeError, ValueError):
        b = 0
    try:
        server = int(product_type or 1) != 1
    except (TypeError, ValueError):
        server = False
    for lowest, srv, cli in DRIVER_TABLE:
        if b >= lowest:
            names = srv if server else cli
            break
    folders = [f'{n}/amd64' for n in names]
    return folders[0], folders[1:]


def state(task):
    st = getattr(task, '_guest_prep', None)
    if not isinstance(st, dict):
        st = task._guest_prep = {'on': bool(getattr(task, 'guest_prep', False)), 'state': 'off',
                                 'os': '', 'drivers': '', 'why': ''}
    return st


def _session(vmware_mgr, task):
    return GuestSession(vmware_mgr, task.vm_id, getattr(task, 'guest_user', ''),
                        getattr(task, '_guest_password', ''))


def _powershell(st):
    return st['system_root'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'


def _ps_args(script, mode, work):
    return (f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script}" '
            f'-Mode {mode} -WorkDir "{work}"')


def _esxi_port(vmware_mgr):
    try:
        return int(getattr(vmware_mgr, 'port', 443) or 443)
    except (TypeError, ValueError):
        return 443


def guest_state(vmware_mgr, vm_id):
    """vmware_mgr.guest_state()'s data, {} when ESXi did not answer"""
    try:
        res = vmware_mgr.guest_state(vm_id)
    except Exception as e:
        return {'error': str(e)[:200]}
    if not isinstance(res, dict):
        return {}
    if 'error' in res:
        return {'error': str(res['error'])[:200]}
    return res.get('data') or {}


def state_refusal(gs):
    """Why the guest cannot be prepared now, '' when it can"""
    if gs.get('error'):
        return f"ESXi did not say how the guest is ({gs['error']})"
    if gs.get('soap') is False:
        return ('the guest operations are only reachable over the SOAP API of the host, and this '
                'ESXi server is connected over REST')
    if gs.get('power_state') != 'POWERED_ON':
        return (f"the source VM is not running (power state {gs.get('power_state') or 'unknown'}): "
                f"the preparation runs inside the running guest")
    if not gs.get('tools_running'):
        return 'the ESXi guest tools are not running in the guest'
    if not gs.get('ops_ready'):
        return 'the ESXi guest tools do not take guest operations (yet)'
    if gs.get('family') and gs.get('family') != 'windowsGuest':
        return f"the guest is not Windows ({gs.get('full_name') or gs.get('family')})"
    return ''


def plan_view(vmware_mgr, vm_id, vm_detail, data):
    """What the review shows of the in-guest preparation of one guest. What keeps it from
    running is a warning, never an error: the guest is prepared offline then."""
    on = data.get('guest_prep') is True
    view = {'on': on, 'power_state': None, 'tools_running': None, 'ops_ready': None, 'windows': None,
            'os': '', 'soap': None, 'reaches_esxi_443': None, 'errors': [], 'warnings': []}
    if not on:
        return view
    gs = guest_state(vmware_mgr, vm_id)
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    view.update(power_state=gs.get('power_state') or vd.get('power_state'), tools_running=gs.get('tools_running'),
                ops_ready=gs.get('ops_ready'), soap=gs.get('soap'),
                windows=(gs.get('family') == 'windowsGuest') if gs.get('family') else None,
                os=str(gs.get('full_name') or vd.get('guest_OS') or '')[:200])
    why = state_refusal(gs)
    if why:
        view['warnings'].append(f'Prepare Windows in the running guest will fall back to the offline preparation: {why}')
    if str(data.get('net_driver') or '') == 'vmxnet3':
        view['warnings'].append('Prepare Windows uninstalls the ESXi guest tools, which bring the vmxnet3 driver: '
                                'the guest comes up without network on a vmxnet3 NIC. Leave the network model on '
                                'auto (VirtIO) or pick VirtIO.')
    if str(data.get('scsihw') or '') == 'pvscsi':
        view['warnings'].append('Prepare Windows uninstalls the ESXi guest tools, which bring the pvscsi driver: '
                                'leave the SCSI controller on auto (VirtIO SCSI single).')
    # MK Nov 2026 - no Live Mirror warning any more: it boots the prepared guest with the boot
    # disk on SATA first and keeps it there when vioscsi did not bind (v2p_twostage.live_switch)
    return view


# --------------------------------------------------------------------------- planning

def fallback(task, why, step='the check'):
    """The in-guest preparation stops here, before anything destructive ran in the guest: the
    guest is prepared offline after the copy instead. Never raises."""
    from pegaprox.core.v2p import _result_warning
    st = state(task)
    st.update(on=False, state='fallback', why=str(why)[:300])
    task._guest_password, task.guest_user = '', ''
    task.guest_prep = False
    wp = getattr(task, '_winprep', None) or {}
    if wp.get('iso') and not getattr(task, 'install_virtio_drivers', False) and task.transfer_mode != 'sshfs_boot':
        task.install_virtio_drivers = True
        if isinstance(wp, dict):
            wp.update(on=True, state='planned')
    _result_warning(task, f"Windows preparation in the running guest left out at {step}: {why}. The guest is "
                          f"prepared on Proxmox VE after the copy instead. {KEEPS_RUNNING}")


def _refuse(task, why, step='the check'):
    raise GuestPrepFailed(why, step)


def _ops_why(e):
    return e.msg if isinstance(e, (GuestOpsError, _StepFailed)) else str(e)[:300]


def _parse_json(raw, what):
    try:
        obj = json.loads(bytes(raw).decode('utf-8-sig'))
    except (ValueError, UnicodeDecodeError):
        raise _StepFailed(f'{what} is no JSON')
    if not isinstance(obj, dict):
        raise _StepFailed(f'{what} is no JSON object')
    return obj


def probe(vmware_mgr, pve_mgr, task):
    """The checks of the planning step, before a package is installed, a VMID taken or a VM
    created. A guest it cannot prepare falls back to the offline preparation (False)."""
    st = state(task)
    if not st.get('on'):
        return False
    try:
        _probe(vmware_mgr, pve_mgr, task)
        return True
    except GuestPrepFailed as e:
        fallback(task, e.why, e.step)
        return False
    except Exception as e:
        # whatever else went wrong, nothing destructive ran in the guest yet
        fallback(task, f'{type(e).__name__}: {str(e)[:200]}')
        return False


def _probe(vmware_mgr, pve_mgr, task):
    st = state(task)
    from pegaprox.core import v2p
    node = task.target_node
    task.log('Windows preparation: checking the source guest')
    why = state_refusal(guest_state(vmware_mgr, task.vm_id))
    if why:
        _refuse(task, why)
    iso = (getattr(task, '_winprep', None) or {}).get('iso')
    if not iso:
        try:
            iso, searched = v2p._find_virtio_iso(pve_mgr, task)
        except ValueError as e:
            _refuse(task, str(e))
        if not iso:
            _refuse(task, f"no virtio-win.iso on node {node} (searched: {', '.join(searched)})")
    st['iso'] = iso
    ok, missing = v2p._ensure_node_packages(pve_mgr, task, 'guestprep', prefix='[guest prep] ')
    if not ok:
        _refuse(task, f"{' '.join(missing) or 'curl'} is not usable on node {node}, the driver uploads need it")
    port = _esxi_port(vmware_mgr)
    reach = v2p._node_cannot_reach(pve_mgr, node, vmware_mgr.host, port)
    if reach:
        _refuse(task, f'node {node} cannot reach {vmware_mgr.host} on port {port} ({reach}), the driver uploads go that way')
    if reach is None:
        task.log(f'  Could not find out whether {node} reaches {vmware_mgr.host}:{port}, going on')

    sess = _session(vmware_mgr, task)
    tmp = None
    try:
        sess.validate()
        env = sess.env('ProgramData', 'SystemRoot')
        pd, sr = env.get('PROGRAMDATA', ''), env.get('SYSTEMROOT', '')
        if not (_GUEST_PATH_RE.match(pd) and _GUEST_PATH_RE.match(sr)):
            raise _StepFailed('ProgramData or SystemRoot of the guest is no plain local path')
        work = pd.rstrip('\\') + '\\' + WORK_DIR
        st.update(work=work, system_root=sr.rstrip('\\'))
        tmp = sess.temp_dir('pegaprox-')
        if not _TEMP_PATH_RE.match(tmp) or tmp.endswith('\\'):
            raise _StepFailed('the temporary folder of the account is no plain local path')
        script = f'{tmp}\\{SCRIPT_NAME}'
        sess.put(script, script_bytes())
        pid = sess.start(_powershell(st), _ps_args(script, 'Probe', work), tmp)
        code = sess.wait_exit(pid, PROBE_SECONDS)
        if code is None:
            raise _StepFailed(f'the check script did not end within {PROBE_SECONDS}s')
        # MK Nov 2026 - two reasons apart: on the lab a local administrator other than the built-in
        # one got its full token through the guest operations, with UAC on; an account that is no
        # administrator was refused with the UAC text all the same
        if code == 10:
            raise _StepFailed('the account is an administrator of the guest, but the guest operations gave it a '
                              'token UAC filters: take an account they elevate, the built-in Administrator for '
                              'one')
        if code == 11:
            raise _StepFailed('the account is no administrator of the guest (not in its Administrators group)')
        raw = sess.get(work + '\\probe.json', 64 * 1024) if code == 0 else None
        if raw is None:
            raise _StepFailed(f'PowerShell did not run the script (exit code {code}). An execution policy set by '
                              f'group policy (AllSigned) or an application control rule stops it')
        found = _parse_json(raw, 'probe.json')
    except (GuestOpsError, _StepFailed) as e:
        _refuse(task, _ops_why(e))
    finally:
        if tmp:
            sess.remove_dir(tmp)
        sess.close()

    build, arch = found.get('build'), str(found.get('arch') or '')
    if found.get('elevated') is not True:
        _refuse(task, 'the account has no elevated rights in the guest')
    if not isinstance(build, int) or build < MIN_BUILD:
        _refuse(task, f'Windows build {build} is older than Windows 8 / Server 2012 (9200)')
    if arch.upper() != 'AMD64':
        _refuse(task, f'the guest runs {arch or "an unknown architecture"}, the drivers are for 64-bit x86 (AMD64)')
    if not isinstance(found.get('free_mb'), int) or found['free_mb'] < MIN_FREE_MB:
        _refuse(task, f"{found.get('free_mb')} MB free on the system drive, {MIN_FREE_MB} MB are needed")
    if found.get('execution_policy_blocked'):
        _refuse(task, 'group policy sets the execution policy AllSigned, the SYSTEM task could not run the script')
    primary, _fb = driver_folders(build, found.get('product_type'))
    product = ' '.join(str(found.get('product') or 'Windows').split())[:120]
    adapters = [a for a in (found.get('adapters') or []) if isinstance(a, dict)]
    static = [a for a in adapters if a.get('static')]
    if not found.get('tools_uninstall'):
        task.log('  No uninstall entry of the ESXi guest tools was found in the guest, they stay installed')
    if found.get('pending_reboot'):
        task.log('  The guest has a reboot pending, installs in it may wait for that')
    st.update(state='checked', os=f'{product} (build {build})', drivers=primary.split('/')[0], why='',
              build=build, product_type=found.get('product_type'))
    task._guest_probe = {k: found.get(k) for k in ('build', 'ubr', 'product', 'product_type', 'arch', 'ps_version',
                                                   'free_mb', 'tools_uninstall', 'pending_reboot')}
    task._guest_probe['static_adapters'] = len(static)
    task.log(f'Windows preparation checked: {product} (build {build}), {len(static)} adapter(s) with static '
             f'IPv4, drivers from {primary}')


# --------------------------------------------------------------------------- stage 1

def _node_script(iso):
    """The node's half: `list` names the files of the driver folders, `put <cfg> <pin>` runs
    curl on a config of URLs and files. The ISO is loop-mounted read-only as the driver
    injection mounts it, only for the length of one call."""
    from pegaprox.core.v2p import _VIRTIO_DRIVERS
    return (
        "#!/bin/bash\n"
        "set -u\n"
        f"ISO={shlex.quote(iso)}\n"
        "M=$(mktemp -d /run/v2p-guestprep-XXXXXXXXXX) || { echo 'V2P_GP_FAILED mktemp'; exit 2; }\n"
        "trap 'cd /; umount \"$M\" 2>/dev/null; rmdir \"$M\" 2>/dev/null' EXIT\n"
        "mount -t iso9660,udf -o ro,loop \"$ISO\" \"$M\" || { echo 'ISO_MOUNT_FAILED'; exit 3; }\n"
        "cd \"$M\" || exit 3\n"
        "if [ \"$1\" = list ]; then\n"
        "  shift\n"
        f"  for D in {' '.join(_VIRTIO_DRIVERS)}; do\n"
        "    for SUB in \"$@\"; do\n"
        "      if [ -d \"$D/$SUB\" ] && ls \"$D/$SUB\"/*.sys >/dev/null 2>&1; then\n"
        "        echo \"DRIVER $D $SUB\"\n"
        "        find \"$D/$SUB\" -maxdepth 1 -type f -printf 'FILE %s %p\\n'\n"
        "        break\n"
        "      fi\n"
        "    done\n"
        "  done\n"
        f"  for F in {' '.join(INSTALLERS)} {AGENT_MSI}; do\n"
        "    [ -f \"$F\" ] && echo \"FILE $(stat -c %s \"$F\") $F\"\n"
        "  done\n"
        "  echo V2P_GP_LIST_END\n"
        "  exit 0\n"
        "fi\n"
        "curl -sS -K \"$2\" -k --pinnedpubkey \"$3\" --retry 2 --connect-timeout 20 -w 'V2P_PUT %{http_code}\\n'\n"
        "echo \"V2P_CURL_RC=$?\"\n"
    )


def _parse_listing(out, work):
    """[{rel, size, dest}] of what the guest gets and the driver folders' names, from the
    node's listing. Raises _StepFailed on anything that is not a plain name."""
    text = str(out or '')
    if 'V2P_GP_LIST_END' not in text.split():
        raise _StepFailed('the node did not list the ISO: ' + ' '.join(text.split())[-300:])
    drivers, files, installer = {}, [], None
    for line in text.splitlines():
        words = line.split()
        if len(words) == 3 and words[0] == 'DRIVER':
            if not (_NAME_RE.match(words[1]) and _REL_RE.match(words[2])):
                raise _StepFailed(f'the ISO names a driver folder that is no plain name ({line[:80]!r})')
            drivers[words[1]] = words[2]
    for line in text.splitlines():
        words = line.split(' ', 2)
        if len(words) != 3 or words[0] != 'FILE':
            continue
        size, rel = words[1], words[2].strip()
        if not size.isdigit() or not _REL_RE.match(rel) or '..' in rel.split('/'):
            raise _StepFailed(f'the ISO holds a file whose name is no plain path ({rel[:80]!r})')
        parts = rel.split('/')
        if rel in INSTALLERS:
            if installer and installer['rel'] == INSTALLERS[0]:
                continue
            installer = {'rel': rel, 'size': int(size), 'dest': f'{work}\\{rel}'}
            continue
        if rel == AGENT_MSI:
            files.append({'rel': rel, 'size': int(size), 'dest': f'{work}\\{parts[-1]}'})
            continue
        drv = parts[0]
        if drv not in drivers or '/'.join(parts[:-1]) != f'{drv}/{drivers[drv]}':
            raise _StepFailed(f'the node listed a file outside the driver folders ({rel[:80]!r})')
        files.append({'rel': rel, 'size': int(size), 'dest': f'{work}\\drivers\\{drv}\\{parts[-1]}'})
    if installer:
        files.append(installer)
    return files, drivers, installer


def _curl_value(v):
    for ch, esc in (('\\', '\\\\'), ('"', '\\"'), ('\n', '\\n'), ('\r', '\\r'), ('\t', '\\t')):
        v = v.replace(ch, esc)
    return f'"{v}"'


def _upload(vmware_mgr, pve_mgr, task, sess, sf, files):
    """Each file from the node's mounted ISO to its ticket URL, 16 per curl run (the tickets
    do not live long). The URLs go to the node in a secret file over stdin, never on a
    command line, and the file is removed right after its run."""
    from pegaprox.core import v2p
    node = task.target_node
    pins = {}
    for at in range(0, len(files), UPLOAD_BATCH):
        batch = files[at:at + UPLOAD_BATCH]
        cfg, port = [], None
        for f in batch:
            url = sess.upload_ticket(f['dest'], f['size'])
            port = urlsplit(url).port or 443
            cfg.append(f"url = {_curl_value(url)}\nupload-file = {_curl_value(f['rel'])}\noutput = \"/dev/null\"\n")
        if port not in pins:
            try:
                pins[port] = pinned_key(vmware_mgr.host, port, getattr(vmware_mgr, 'ssl_verify', False))
            except Exception as e:
                raise _StepFailed(f'the TLS key of {vmware_mgr.host}:{port} could not be read ({e})')
        path = v2p._node_secret_file(pve_mgr, task, 'guestprep-urls', ''.join(cfg))
        if not path:
            raise _StepFailed(f'the upload list could not be written on node {node}')
        size = sum(f['size'] for f in batch)
        try:
            rc, out, err = v2p._pve_node_exec(
                pve_mgr, node, f"bash {sf} put {shlex.quote(path)} {shlex.quote(pins[port])} 2>&1",
                timeout=300 + size // (1024 * 1024))
        finally:
            v2p._drop_node_secret(pve_mgr, task, path)
        codes = re.findall(r'^V2P_PUT (\d{3})\s*$', str(out or ''), re.M)
        if len(codes) != len(batch) or any(c not in ('200', '201', '204') for c in codes):
            said = ' '.join(str(out or err or '').split())[-300:]
            raise _StepFailed(f'{len(batch)} file(s) sent, the answers were {codes or "none"} ({said or f"exit code {rc}"})')
    task.log(f'  {len(files)} file(s) uploaded into the guest from {node}')


def _config(task, st, drivers, installer, agent):
    from pegaprox.core import v2p_twostage
    go_wait = GO_WAIT_SECONDS
    if getattr(task, 'wait_for_confirmation', False):
        hold = int(getattr(task, '_confirmation_timeout', 86400) or 0)
        go_wait += hold if hold > 0 else 30 * 86400
    return {'version': 1, 'run': str(task.id), 'drivers': sorted(drivers),
            'installer': installer, 'agent_msi': agent,
            'go_wait_seconds': min(go_wait, GO_WAIT_MAX),
            # the two-stage boot and Live Mirror both boot the guest on SATA first
            'sata_first_boot': v2p_twostage.sata_first_boot_planned(task),
            'preserve_mac': bool(getattr(task, 'preserve_mac', False))}


def _copy_log(sess, task, st):
    """The lines of this run's migrate.log not copied yet into the task's log"""
    try:
        raw = sess.get(st['work'] + '\\migrate.log', LOG_CAP)
    except GuestOpsError:
        return
    _take_log_lines(task, st, raw)


def _take_log_lines(task, st, raw):
    if not raw:
        return
    text = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else str(raw)
    lines = text.splitlines()
    head = f'=== run {task.id} ==='
    at = max((i for i, ln in enumerate(lines) if ln.rstrip().endswith(head)), default=None)
    if at is None:
        return
    mine = lines[at + 1:]
    done = int(st.get('copied') or 0)
    for ln in mine[done:]:
        if ln.strip():
            task.log(LOG_PREFIX + ln.rstrip()[:400])
    st['copied'] = len(mine)


def _wait_stage1(sess, task, st):
    deadline = time.monotonic() + STAGE1_SECONDS
    last_err = ''
    while True:
        try:
            raw = sess.get(st['work'] + '\\status.json', 256 * 1024)
            last_err = ''
        except GuestOpsError as e:
            if e.kind in ('login', 'permission'):
                raise
            raw, last_err = None, e.msg
        if raw:
            try:
                status = _parse_json(raw, 'status.json')
            except _StepFailed:
                status = {}     # caught while the script wrote it
            if status.get('run') == str(task.id):
                stage = status.get('stage')
                if stage == 'ready':
                    return status
                if stage in ('failed', 'aborted'):
                    bad = [s for s in (status.get('steps') or []) if isinstance(s, dict) and not s.get('ok')]
                    why = str(status.get('error') or (bad[-1].get('detail') if bad else '') or stage)
                    raise _StepFailed(why[:300])
        if time.monotonic() >= deadline:
            raise _StepFailed(f'stage 1 did not finish within {STAGE1_SECONDS // 60} min'
                              + (f' ({last_err})' if last_err else ''))
        time.sleep(POLL_SECONDS)


def _firstboot_data(pve_mgr, task, sess, st):
    """firstboot-data.cmd from the network the guest saved in stage 1: its own adapters' MACs
    for a migration given up on ESXi, the MACs of the NICs on Proxmox for the first boot there.
    One generator for both paths (v2p_winprep_node.data_cmd)."""
    from pegaprox.core import v2p_winprep, v2p_winprep_node as nh
    raw = sess.get(st['work'] + '\\netconfig.json', 256 * 1024)
    if raw is None:
        raise _StepFailed('the guest saved no netconfig.json')
    j = _parse_json(raw, 'netconfig.json')
    if j.get('run') != str(task.id) or j.get('source') != 'guest':
        raise _StepFailed('netconfig.json is not the one of this run')
    adapters, devs = [], []
    for a in j.get('adapters') or []:
        if not isinstance(a, dict):
            continue
        inst = str(a.get('instance') or '')
        if nh.is_esxi_nic(inst) and inst not in devs:
            devs.append(inst)
        if a.get('dhcp'):
            continue
        ipv4 = [{'ip': x.get('ip'), 'prefix': int(x.get('prefix') or 0)} for x in (a.get('ipv4') or [])
                if isinstance(x, dict) and 0 < int(x.get('prefix') or 0) <= 32]
        adapters.append({'guid': str(a.get('setting_id') or '').upper(), 'mac': nh.norm_mac(a.get('mac')),
                         'instance': inst, 'index': int(a.get('index') or 0), 'ipv4': ipv4,
                         'gateway': [g for g in (a.get('gateway') or []) if isinstance(g, dict)],
                         'dns': [d for d in (a.get('dns') or []) if isinstance(d, str)]})
    moved, _stale = nh.match_nics(adapters, nh.parse_pairs(v2p_winprep.nic_pairs(pve_mgr, task)))
    try:
        data = nh.data_cmd(str(task.id), int(st.get('build') or 0), moved, old_devs=devs)
    except ValueError as e:
        raise _StepFailed(f'the saved network does not make a first boot task ({e})')
    sess.put(st['work'] + '\\firstboot-data.cmd', data)
    st['adapters'] = len(moved)


def prepare(vmware_mgr, pve_mgr, task):
    """Stage 1, while the source still serves where the mode lets it. A failure calls the
    guest off (abort.flag) and falls back to the offline preparation; never raises."""
    st = state(task)
    if not st.get('on') or st.get('state') != 'checked':
        return False
    from pegaprox.core import v2p, v2p_winprep
    node = task.target_node
    work = st['work']
    task.log('=== Windows preparation, stage 1: drivers, guest tools, saved network (the source keeps running) ===')
    sess = _session(vmware_mgr, task)
    sf = None
    step = 'listing the drivers on the ISO'
    try:
        sf = v2p._write_node_script(pve_mgr, node, _node_script(st['iso']), 'guestprep')
        if not sf:
            raise _StepFailed(f'the helper script could not be written on node {node}')
        primary, fallbacks = driver_folders(st.get('build'), st.get('product_type'))
        rc, out, _err = v2p._pve_node_exec(
            pve_mgr, node, f"bash {sf} list {' '.join(shlex.quote(f) for f in [primary] + fallbacks)} 2>&1",
            timeout=60)
        files, drivers, installer = _parse_listing(out, work)
        if 'vioscsi' not in drivers and 'viostor' not in drivers:
            raise _StepFailed(f'the ISO has no VirtIO storage driver for {primary}')
        agent = 'qemu-ga-x86_64.msi' if any(f['rel'] == AGENT_MSI for f in files) else None
        task.log(f"  Drivers from the ISO: {', '.join(f'{d} ({drivers[d]})' for d in sorted(drivers))}; installer "
                 f"{installer['rel'] if installer else 'none'}; guest agent {'yes' if agent else 'not on the ISO'}")
        step = 'creating the driver folders'
        for d in sorted(drivers):
            sess.mkdir(f'{work}\\drivers\\{d}')
        step = 'uploading the drivers'
        _upload(vmware_mgr, pve_mgr, task, sess, sf, files)
        step = 'putting firstboot.cmd into the guest'
        sess.put(work + '\\firstboot.cmd', v2p_winprep.firstboot_bytes())
        step = 'writing pegaprox.json'
        cfg = _config(task, st, drivers, installer['rel'] if installer else None, agent)
        sess.put(work + '\\pegaprox.json', json.dumps(cfg).encode('ascii'))
        step = 'starting the preparation task'
        pid = sess.start(_powershell(st), _ps_args(f'{work}\\{SCRIPT_NAME}', 'Start', work), work)
        code = sess.wait_exit(pid, START_SECONDS)
        if code != 0:
            raise _StepFailed(f'the script did not start its SYSTEM task within {START_SECONDS}s'
                              if code is None else f'the script ended with exit code {code}')
        step = 'stage 1 in the guest'
        status = _wait_stage1(sess, task, st)
        step = 'the data of the first boot task'
        _firstboot_data(pve_mgr, task, sess, st)
    except Exception as e:
        why = _ops_why(e) if isinstance(e, (GuestOpsError, _StepFailed)) else f'{type(e).__name__}: {str(e)[:200]}'
        _put_abort(sess, st, task)
        _copy_log(sess, task, st)
        sess.close()
        fallback(task, f'{why}; drivers already added to its Driver Store stay (harmless)', step)
        return False
    finally:
        if sf:
            try:
                v2p._pve_node_exec(pve_mgr, node, f'rm -f {sf}', timeout=10)
            except Exception:
                pass
    _copy_log(sess, task, st)
    sess.close()
    st['state'] = 'prepared'
    done = [str(s.get('name')) for s in (status.get('steps') or []) if isinstance(s, dict) and s.get('ok')]
    task.log(f"Windows prepared in the guest: {', '.join(done) or 'stage 1 done'}")
    return True


# --------------------------------------------------------------------------- the switchover

def _put_abort(sess, st, task):
    try:
        sess.put(st['work'] + '\\abort.flag', b'abort')
        return True
    except Exception as e:
        task.log(f'  The preparation in the guest could not be called off ({_ops_why(e)}); it calls itself off '
                 f'once its wait for the switchover runs out')
        return False


def abort_if_pending(vmware_mgr, task):
    """A guest that did stage 1 and waits for its go is told to call it off (best effort; the
    script's own deadline is the backstop when this does not reach it)"""
    st = getattr(task, '_guest_prep', None)
    if not isinstance(st, dict) or st.get('state') != 'prepared' or not vmware_mgr:
        return
    sess = _session(vmware_mgr, task)
    try:
        if _put_abort(sess, st, task):
            st['state'] = 'aborted'
            task.log('Windows preparation called off in the guest: its tasks go, the VirtIO drivers and guest '
                     'tools stay (harmless on ESXi)')
    finally:
        sess.close()


def go(vmware_mgr, pve_mgr, task):
    """The cutover: stage 2 in the guest and its shutdown. 'off' once it shut itself down,
    'forced' when it had to be powered off, 'stuck' when it is still not off, 'skipped' when
    the guest was not prepared (or the go did not reach it): the caller stops it as before."""
    st = state(task)
    if not st.get('on'):
        return 'skipped'
    if st.get('state') == 'checked':
        prepare(vmware_mgr, pve_mgr, task)
    if st.get('state') != 'prepared':
        return 'skipped'
    from pegaprox.core import v2p
    sess = _session(vmware_mgr, task)
    try:
        sess.put(st['work'] + '\\go.flag', b'go')
    except Exception as e:
        _put_abort(sess, st, task)
        sess.close()
        fallback(task, f'the go file did not reach the guest ({_ops_why(e)})', 'the switchover')
        return 'skipped'
    sess.close()
    # no guest operation follows: the password is not needed any more
    st['state'] = 'shutting_down'
    task._guest_password, task.guest_user = '', ''
    task.log('=== Windows preparation, stage 2: the guest releases its static IPv4, uninstalls the ESXi guest '
             'tools and shuts down ===')
    t0 = time.monotonic()
    if v2p._wait_power_state(vmware_mgr, task.vm_id, 'POWERED_OFF', OFF_SECONDS, poll=5):
        st.update(state='shut_down', shutdown='off')
        task.log(f'  The guest shut itself down after the preparation ({int(time.monotonic() - t0)}s)')
        return 'off'
    task.log(f'  The guest is not off after {OFF_SECONDS // 60} min, powering it off')
    try:
        vmware_mgr.vm_power_action(task.vm_id, 'stop')
    except Exception as e:
        task.log(f'  Power-off answered: {str(e)[:200]}')
    if v2p._wait_power_state(vmware_mgr, task.vm_id, 'POWERED_OFF', 120):
        st.update(state='shut_down', shutdown='forced')
        v2p._result_warning(task, 'The guest did not shut itself down within 15 min after the preparation and was '
                                  'powered off. Its log on the guest says how far it got.')
        return 'forced'
    return 'stuck'


def ran(task):
    """True once stage 2 started in the guest: its address is released, its tools are going"""
    st = getattr(task, '_guest_prep', None)
    return isinstance(st, dict) and st.get('state') in ('shutting_down', 'shut_down')


# --------------------------------------------------------------------------- the way back

UNMOUNT_WAIT_SECONDS = 1800


def roll_back(vmware_mgr, pve_mgr, task):
    """The run failed after stage 2 ran in the guest: the source is powered on again in ESXi
    (unless the target may run), the installer of the ESXi guest tools is mounted, and the
    guest's first boot task (firstboot.cmd auto) reinstalls them and puts its address back.
    The installer is unmounted once the tools run again, when that can be seen. Best effort."""
    st = getattr(task, '_guest_prep', None)
    if not ran(task) or not vmware_mgr or st.get('rolled_back'):
        return
    st['rolled_back'] = True
    from pegaprox.core import v2p
    if getattr(task, '_source_disks_used', False):
        # MK Nov 2026 - Live Mirror booted the guest from the source's own disks. On a lab run the
        # source powered on again after that came up without network and guest tools: the first
        # boot on Proxmox VE had cleared its addresses, removed its ESXi adapters and the first
        # boot task that would have put them back on ESXi.
        v2p._result_warning(task, "Live Mirror started the guest on Proxmox VE from the disks of the source VM: "
                                  "what it wrote, its first boot there included, is on those disks now. The source "
                                  "VM stays off on ESXi: powered on there after that first boot it has no network "
                                  "and no guest tools. Look at the VM on Proxmox VE first; a backup of the source "
                                  "is the way back to ESXi.")
        return
    try:
        target = v2p._pve_vm_status(pve_mgr, task.target_node, task.proxmox_vmid) if (pve_mgr and task.proxmox_vmid) else None
    except Exception:
        target = None
    if target == 'running':
        task.log('The target VM runs on Proxmox, the source VM stays off on ESXi; its first boot task puts its address '
                 'back when it is powered on there')
        return
    power = v2p._vm_power_state(vmware_mgr, task.vm_id)
    if power == 'POWERED_OFF':
        task.log('Bringing the source VM back on ESXi: the Windows preparation had released its address and '
                 'uninstalled its guest tools')
        res = vmware_mgr.vm_power_action(task.vm_id, 'start')
        if isinstance(res, dict) and res.get('error'):
            v2p._result_warning(task, f"The source VM could not be powered on again ({str(res['error'])[:200]}). "
                                      f"Power it on in ESXi: its first boot task puts its address back.")
            return
        if not v2p._wait_power_state(vmware_mgr, task.vm_id, 'POWERED_ON', 120):
            # MK Nov 2026 - ESXi took the power-on and failed it with FileLocked on a lab run: a copy
            # on the node still read a disk of the source. The run went on and said the source ran
            # again while it was off.
            v2p._result_warning(task, "The source VM did not come back on in ESXi within 2 min: ESXi refuses "
                                      "while a file of it is locked, a copy still reading one of its disks for "
                                      "one. Power it on in ESXi once that is over and mount the installer of its "
                                      "ESXi guest tools within 15 min: its first boot task reinstalls them and "
                                      "puts its address back.")
            return
    res = vmware_mgr.mount_tools_installer(task.vm_id) if hasattr(vmware_mgr, 'mount_tools_installer') else \
        {'error': 'not supported'}
    if isinstance(res, dict) and res.get('error'):
        v2p._result_warning(task, f"The source VM runs on ESXi again, the installer of its guest tools could not be "
                                  f"mounted ({str(res['error'])[:200]}). Install the ESXi guest tools in it; its first "
                                  f"boot task then puts its address back.")
        return
    st['state'] = 'rolled_back'
    task.log('The source VM runs on ESXi again with the installer of its guest tools mounted: its first boot task '
             'reinstalls them and puts the static address back')
    import threading
    from pegaprox.core import ha
    # a user job like the migration it belongs to: in an automatic group the unmount asks for the lease
    threading.Thread(target=ha.as_job(_unmount_when_back, 'ESXi guest tools installer unmount'),
                     args=(vmware_mgr, task), daemon=True).start()


def _unmount_when_back(vmware_mgr, task, wait=None, poll=15, remounts=6):
    deadline = time.monotonic() + (UNMOUNT_WAIT_SECONDS if wait is None else wait)
    while time.monotonic() < deadline:
        gs = guest_state(vmware_mgr, task.vm_id)
        if not gs.get('tools_running') and gs.get('installer_mounted') is False and \
                gs.get('power_state') == 'POWERED_ON' and remounts > 0:
            # MK Nov 2026 - ESXi takes the installer out again when the guest read nothing from it
            # for 5 min ("no guest I/O detected on media"): the first boot task waits longer
            remounts -= 1
            res = vmware_mgr.mount_tools_installer(task.vm_id)
            task.log('ESXi had taken the installer of the guest tools out unused, it is mounted again'
                     if not (isinstance(res, dict) and res.get('error')) else
                     f"ESXi had taken the installer of the guest tools out unused; mounting it again failed "
                     f"({str(res['error'])[:200]})")
        if gs.get('tools_running'):
            if gs.get('installer_mounted') is False:
                # ESXi ends the install itself once its installer ran: on the lab the unmount
                # after it was refused as "not allowed in the current state"
                task.log('The guest tools run again on the source VM, ESXi took their installer out itself')
                return True
            res = vmware_mgr.unmount_tools_installer(task.vm_id)
            if isinstance(res, dict) and res.get('error'):
                task.log(f"The guest tools run again; unmounting their installer failed ({str(res['error'])[:200]})")
            else:
                task.log('The guest tools run again on the source VM, their installer is unmounted')
            return True
        time.sleep(poll)
    task.log('The guest tools did not report back within 30 min; unmount their installer in ESXi once they run')
    return False


# --------------------------------------------------------------------------- after the move

def take_stage2_lines(task, text):
    """The lines stage 2 wrote into migrate.log after stage 1 was copied, up to the first boot"""
    st = getattr(task, '_guest_prep', None)
    if not isinstance(st, dict) or not text or st.get('state') not in ('shut_down',):
        return
    lines = str(text).splitlines()
    head = f'=== run {task.id} ==='
    at = max((i for i, ln in enumerate(lines) if ln.rstrip().endswith(head)), default=None)
    if at is None:
        return
    mine = []
    for ln in lines[at + 1:]:
        if 'first boot on Proxmox VE' in ln and '===' in ln:
            break
        mine.append(ln)
    for ln in mine[int(st.get('copied') or 0):]:
        if ln.strip():
            task.log(LOG_PREFIX + ln.rstrip()[:400])
    st['copied'] = len(mine)
