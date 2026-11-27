# -*- coding: utf-8 -*-
"""The packages an ESXi migration may put on the target Proxmox node, in one place.

MK Nov 2026 (#1252) - the migration installed what it was missing with apt-get at nine
places of core/v2p.py, each with its own list and its own check, and said so in the log
once it was already running. Nodes kept by config management (Ansible and the like) are
not supposed to grow packages nobody planned. Every install now goes through
v2p._ensure_node_packages with a feature of NODE_PACKAGES, and the run may be told not to
install anything (allow_package_install false): a package it needs is then missing, it
stops before it touched ESXi or Proxmox and names the node, the packages and the apt
command. Without one of the optional ones it takes another way, as it always did on a
node without a repository.

The review step and a bulk check ask the target node once which of them it has
(package_report, one SSH call with dpkg-query). Never the migration-plan GET: that one
walks every node of every cluster.

Nothing here talks to a node itself; the callers hand in the node exec.
"""

# feature -> the packages it installs and what for. Only Debian package names that PVE's
# own repositories carry; never qemu-utils, which conflicts with pve-qemu-kvm (#520).
NODE_PACKAGES = {
    'sshfs': {'packages': ('sshfs',),
              'purpose': 'mounting the ESXi datastore over SSHFS'},
    'sshpass': {'packages': ('sshpass',),
                'purpose': 'password logins from the node to ESXi for the SSH copies (a temporary key on ESXi otherwise)'},
    'virtio': {'packages': ('python3-hivex', 'ntfs-3g'),
               'purpose': 'Prepare VirtIO drivers: the registry and the NTFS volume of the boot disk'},
    'virtio_build': {'packages': ('libhivex-bin',),
                     'purpose': 'Prepare VirtIO drivers: reading the Windows build for the driver variant'},
    # libpve-storage-perl depends on ceph-common, so a PVE node has it unless someone took it off
    'rbd': {'packages': ('ceph-common',),
            'purpose': 'Prepare VirtIO drivers on a Ceph RBD boot disk: mapping the image'},
    'lz4': {'packages': ('lz4',),
            'purpose': 'lz4 compression of the SSH copy fallback, when ESXi has lz4'},
    # MK Nov 2026 - the Windows preparation in the running guest: the node PUTs the driver
    # folders of the ISO to the guest file transfer URLs of ESXi
    'guestprep': {'packages': ('curl',),
                  'purpose': 'Prepare Windows in the running guest: uploading the VirtIO drivers from the node'},
    # not a Debian package: the ISO the driver injection and the Windows preparation take the
    # drivers from, downloaded where it is missing (see DOWNLOADS)
    'virtio_iso': {'packages': ('virtio-win.iso',),
                   'purpose': 'Prepare Windows: the VirtIO drivers and the guest agent (virtio-win.iso, '
                              'downloaded from fedorapeople.org into /var/lib/vz/template/iso)'},
}

# MK Nov 2026 - files a feature fetches instead of an apt-get: over HTTPS, the certificate
# checked (curl and wget do by default, nothing here turns that off), written under a
# temporary name and moved into place once complete; its sha256 is printed for the task log
VIRTIO_ISO_URL = 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso'
VIRTIO_ISO_DIR = '/var/lib/vz/template/iso'
DOWNLOADS = {
    'virtio-win.iso': {'url': VIRTIO_ISO_URL, 'dir': VIRTIO_ISO_DIR, 'min_bytes': 100 * 1024 * 1024},
}
# the transfer ends on its own before the caller gives up on the node command (an exec timeout
# of 3600 s), so its own failure path removes the temporary file
DOWNLOAD_MAX_SECONDS = 3300
# a temporary file of a download that was killed (SIGKILL, a node reboot) is this old at least
# before a later download removes it; no running download is older than DOWNLOAD_MAX_SECONDS
DOWNLOAD_STALE_MINUTES = 120

# what tells the run a package is usable, the same test before and after an install
PACKAGE_CHECKS = {
    'sshfs': ('command -v sshfs',),
    'sshpass': ('command -v sshpass',),
    'python3-hivex': ("python3 -c 'import hivex'",),
    'ntfs-3g': ('command -v ntfs-3g', 'command -v ntfsfix'),
    'libhivex-bin': ('command -v hivexsh',),
    'ceph-common': ('command -v rbd',),
    'lz4': ('command -v lz4',),
    'curl': ('command -v curl',),
    # the places the run looks in without a storage of its own (v2p.virtio_iso_candidates)
    'virtio-win.iso': ('test -f /var/lib/vz/template/iso/virtio-win.iso -o -f /var/lib/pegaprox/virtio-win.iso',),
}

# the modes that copy over HTTPS or ssh and take the SSHFS mount only as their last way
# out: they look for sshfs and never install it
SSHFS_OPTIONAL_MODES = ('vmkfstools_clone', 'snapshot_zero')

# what an install or check script prints last
_VERDICTS = ('PRESENT', 'INSTALLED', 'UNVERIFIED', 'FAILED', 'MISSING')
_PROBE_END = 'V2P_PKG_PROBE_END'
APT_INSTALL = 'apt-get install --no-install-recommends'


def packages_of(feature):
    return NODE_PACKAGES[feature]['packages']


def package_plan(transfer_mode='auto', install_virtio_drivers=False, boot_storage_type='', guest_prep=False,
                 virtio_iso=False):
    """[(feature, needed)] of what a migration with these options may install on the target
    node. needed: the run cannot do without it; the others only change the way it copies.

    Live Mirror and Auto may end up in the SSH copy that wants lz4. The driver injection
    runs in every mode but Live Mirror, whose guest already runs on the target.

    MK Nov 2026 - guest_prep: the Windows preparation in the running guest uploads with curl
    (optional: without it the run prepares the guest offline). virtio_iso: the run needs a
    virtio-win.iso and the caller named none of its own, so it may download one; never
    needed, a run without it keeps the controller and NICs of the source."""
    mode = str(transfer_mode or 'auto')
    plan = [('sshfs', mode not in SSHFS_OPTIONAL_MODES), ('sshpass', False)]
    if mode in ('sshfs_boot', 'auto'):
        plan.append(('lz4', False))
    if install_virtio_drivers and mode != 'sshfs_boot':
        plan += [('virtio', True), ('virtio_build', False)]
        if str(boot_storage_type or '').lower() == 'rbd':
            plan.append(('rbd', True))
    if guest_prep:
        plan.append(('guestprep', False))
    if virtio_iso and (guest_prep or (install_virtio_drivers and mode != 'sshfs_boot')):
        plan.append(('virtio_iso', False))
    return plan


def _check(name):
    return ' && '.join(f'{c} >/dev/null 2>&1' for c in PACKAGE_CHECKS[name])


def apt_command(names):
    names = [n for n in names if n not in DOWNLOADS]
    return f"{APT_INSTALL} {' '.join(names)}" if names else ''


def download_hint(names):
    """How to fetch the files of `names` that are no packages, '' when there are none"""
    return '; '.join(f"curl -fL -o {DOWNLOADS[n]['dir']}/{n} {DOWNLOADS[n]['url']}" for n in names if n in DOWNLOADS)


def download_script(name, install=True):
    """The node command for a file of DOWNLOADS, with the verdicts of ensure_script: PRESENT,
    MISSING <name>, INSTALLED <name> or FAILED <name>. Before the verdict: V2P_DL OK <sha256>
    <bytes> <path> once it is in place, or the reason it is not.

    MK Nov 2026 - the temporary file goes on every way out: a trap for the end of the shell and
    for a hang-up or kill of the SSH session, a time limit below the caller's exec timeout, and
    the temporary files of earlier downloads nobody could clean up (SIGKILL) are removed first."""
    d = DOWNLOADS[name]
    path = f"{d['dir']}/{name}"
    have = _check(name)
    if not install:
        return f'{have} && echo PRESENT || echo "MISSING {name}"'
    secs = DOWNLOAD_MAX_SECONDS
    return (
        f'{have} && echo PRESENT || {{ '
        f'find {d["dir"]} -maxdepth 1 -type f -name ".{name}.??????????*" -mmin +{DOWNLOAD_STALE_MINUTES} -delete 2>/dev/null; '
        f'mkdir -p {d["dir"]} && t=$(mktemp {d["dir"]}/.{name}.XXXXXXXXXX) || {{ echo "cannot write to {d["dir"]}"; echo "FAILED {name}"; exit 0; }}; '
        f'trap \'rm -f "$t" "$t.err"\' EXIT; trap \'rm -f "$t" "$t.err"; exit 1\' HUP INT TERM PIPE; '
        f'if command -v curl >/dev/null 2>&1; then '
        f'curl -fsSL --proto =https --proto-redir =https --retry 2 --connect-timeout 30 --max-time {secs} -o "$t" {d["url"]} 2>"$t.err"; rc=$?; '
        f'elif command -v wget >/dev/null 2>&1; then '
        f'timeout {secs} wget -q --https-only -O "$t" {d["url"]} 2>"$t.err"; rc=$?; '
        f'else echo "neither curl nor wget is installed" >"$t.err"; rc=127; fi; '
        f'sz=$(stat -c %s "$t" 2>/dev/null || echo 0); '
        f'if [ $rc -ne 0 ] || [ "$sz" -lt {d["min_bytes"]} ]; then '
        f'echo "the download of {d["url"]} failed (exit code $rc, $sz bytes): $(tail -c 300 "$t.err" | tr "\n" " ")"; '
        f'rm -f "$t" "$t.err"; echo "FAILED {name}"; '
        f'else sum=$(sha256sum "$t" | cut -d" " -f1); chmod 0644 "$t" && mv -f "$t" {path}; rm -f "$t.err"; '
        f'echo "V2P_DL OK $sum $sz {path}"; echo "INSTALLED {name}"; fi; }}'
    )


def parse_download(out):
    """(sha256, bytes, path) of a download_script answer that fetched the file, else None"""
    for line in str(out or '').splitlines():
        w = line.split()
        if len(w) == 5 and w[:2] == ['V2P_DL', 'OK'] and len(w[2]) == 64 and w[3].isdigit():
            return w[2], int(w[3]), w[4]
    return None


def ensure_script(feature, install=True):
    """The one node command for a feature: PRESENT when every package checks out, else
    either MISSING <names> or the apt-get run for the missing ones and then INSTALLED,
    UNVERIFIED <names> (apt-get went through, the check still fails) or FAILED <names>.
    The last 25 lines of apt-get come before that line, a pve-apt-hook refusal is longer
    than five. A list that apt cannot resolve gets one apt-get update and a second try."""
    names = packages_of(feature)
    if len(names) == 1 and names[0] in DOWNLOADS:
        return download_script(names[0], install=install)
    # one && chain, so the command starts with the check of the first package
    have = ' && '.join(_check(n) for n in names)
    which = ' '.join(f'{{ {_check(n)}; }} || m="$m {n}";' for n in names)
    if not install:
        return f'{have} && echo PRESENT || {{ m=""; {which} echo "MISSING$m"; }}'
    still = ' '.join(f'{{ {_check(n)}; }} || s="$s {n}";' for n in names)
    apt = ('apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=60 $m 2>&1')
    return (
        f'{have} && echo PRESENT || {{ m=""; {which} '
        f'export DEBIAN_FRONTEND=noninteractive; '
        f'out=$({apt}); rc=$?; '
        f'if [ $rc -ne 0 ]; then apt-get update -qq >/dev/null 2>&1; out=$({apt}); rc=$?; fi; '
        f's=""; {still} '
        f'printf "%s\\n" "$out" | tail -25; '
        f'if [ -z "$s" ]; then echo "INSTALLED$m"; elif [ $rc -eq 0 ]; then echo "UNVERIFIED$s"; '
        f'else echo "FAILED$s"; fi; }}'
    )


def parse_ensure(rc, out, names):
    """(verdict, packages, apt output) of an ensure_script answer. packages: the ones the
    verdict is about, those installed for INSTALLED, those still missing otherwise.

    MK Nov 2026 - an answer without a verdict line is UNKNOWN, whatever its exit code: the
    script ends with the verdict, so its exit code is the one of an echo, and an answer
    without that line is one whose end got lost. Read by its exit code, a cut answer of
    an apt-get that failed made sshfs count as installed. Installing is never decided
    here: the script holds the apt-get run or it does not."""
    lines = str(out or '').splitlines()
    for i in range(len(lines) - 1, -1, -1):
        words = lines[i].split()
        if words and words[0] in _VERDICTS:
            verdict = words[0]
            if verdict == 'PRESENT':
                return verdict, [], '\n'.join(lines[:i]).strip()
            named = [w for w in words[1:] if w in names] or list(names)
            return verdict, named, '\n'.join(lines[:i]).strip()
    said = ' '.join(str(out or '').split())[:300]
    return 'UNKNOWN', list(names), said or f'no answer (exit code {rc})'


def probe_script(names):
    """One command for the review step: dpkg's status of each package, and whether what
    the run checks for is there anyway (a binary from elsewhere counts as well)."""
    pkgs = ' '.join(names)
    checks = ' '.join(f'{{ {_check(n)}; }} && echo "V2P_BIN {n}";' for n in names)
    return (f"for p in {pkgs}; do s=$(dpkg-query -W -f='${{Status}}' \"$p\" 2>/dev/null); "
            f"echo \"V2P_PKG $p ${{s##* }}\"; done; {checks} echo {_PROBE_END}")


def parse_probe(out, names):
    """{name: installed} from a probe_script answer, None when the probe did not run to
    its end. Never an empty dict for "nothing missing"."""
    text = str(out or '')
    if _PROBE_END not in text.split():
        return None
    status, binaries = {}, set()
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == 'V2P_PKG' and words[1] in names:
            status[words[1]] = len(words) >= 3 and words[2] == 'installed'
        elif len(words) == 2 and words[0] == 'V2P_BIN' and words[1] in names:
            binaries.add(words[1])
    if set(status) != set(names):
        return None
    return {n: status[n] or n in binaries for n in names}


def missing_message(node, items, run=True):
    """The refusal when a needed package is missing and the run may not install it.
    items: [(package, feature)]."""
    names = [p for p, _f in items]
    what = '; '.join(f"{p} ({NODE_PACKAGES[f]['purpose']})" for p, f in items)
    how = '; '.join(x for x in (apt_command(names), download_hint(names)) if x)
    msg = (f"Target node {node} is missing packages this migration needs, and installing packages "
           f"on it is turned off for this migration: {what}. Install them on the node "
           f"({how}) or allow the installs")
    if run:
        return msg + ', then start the migration again. Nothing was changed on ESXi or Proxmox.'
    return msg + '.'


def package_report(node_exec, pve_mgr, node, plan, allow_install=True, timeout=20):
    """What the node has of the packages of `plan` (package_plan), with one call to it.

    {node, checked, error, allow_install, items: [{package, feature, purpose, needed,
    installed}], missing, missing_needed, apt_command}. When the probe did not run,
    checked is False, installed None and missing None: unknown is never "nothing missing"."""
    items = [{'package': p, 'feature': f, 'purpose': NODE_PACKAGES[f]['purpose'], 'needed': bool(needed),
              'installed': None} for f, needed in plan for p in packages_of(f)]
    names = [it['package'] for it in items]
    report = {'node': node, 'checked': False, 'error': None, 'allow_install': bool(allow_install),
              'items': items, 'missing': None, 'missing_needed': None, 'apt_command': ''}
    try:
        rc, out, err = node_exec(pve_mgr, node, probe_script(names), timeout=timeout)
    except Exception as e:
        report['error'] = f'{type(e).__name__}: {str(e)[:160]}'
        return report
    found = parse_probe(out, names)
    if found is None:
        said = ' '.join(str(err or out or '').split())[:200]
        report['error'] = said or f'exit code {rc}'
        return report
    for it in items:
        it['installed'] = found[it['package']]
    report['checked'] = True
    report['missing'] = [it['package'] for it in items if not it['installed']]
    report['missing_needed'] = [it['package'] for it in items if it['needed'] and not it['installed']]
    report['apt_command'] = apt_command(report['missing'])
    return report


def report_problem(report):
    """(error, warning) a package_report adds to a plan: an error when the run would stop
    on it, a warning when it could not be read."""
    if not report:
        return None, None
    if not report['checked']:
        return None, f"the packages on node {report['node']} could not be checked: {report['error']}"
    if report['missing_needed'] and not report['allow_install']:
        items = [(it['package'], it['feature']) for it in report['items']
                 if it['needed'] and not it['installed']]
        return missing_message(report['node'], items, run=False), None
    return None, None
