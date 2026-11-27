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
}

# what tells the run a package is usable, the same test before and after an install
PACKAGE_CHECKS = {
    'sshfs': ('command -v sshfs',),
    'sshpass': ('command -v sshpass',),
    'python3-hivex': ("python3 -c 'import hivex'",),
    'ntfs-3g': ('command -v ntfs-3g', 'command -v ntfsfix'),
    'libhivex-bin': ('command -v hivexsh',),
    'ceph-common': ('command -v rbd',),
    'lz4': ('command -v lz4',),
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


def package_plan(transfer_mode='auto', install_virtio_drivers=False, boot_storage_type=''):
    """[(feature, needed)] of what a migration with these options may install on the target
    node. needed: the run cannot do without it; the others only change the way it copies.

    Live Mirror and Auto may end up in the SSH copy that wants lz4. The driver injection
    runs in every mode but Live Mirror, whose guest already runs on the target."""
    mode = str(transfer_mode or 'auto')
    plan = [('sshfs', mode not in SSHFS_OPTIONAL_MODES), ('sshpass', False)]
    if mode in ('sshfs_boot', 'auto'):
        plan.append(('lz4', False))
    if install_virtio_drivers and mode != 'sshfs_boot':
        plan += [('virtio', True), ('virtio_build', False)]
        if str(boot_storage_type or '').lower() == 'rbd':
            plan.append(('rbd', True))
    return plan


def _check(name):
    return ' && '.join(f'{c} >/dev/null 2>&1' for c in PACKAGE_CHECKS[name])


def apt_command(names):
    return f"{APT_INSTALL} {' '.join(names)}" if names else ''


def ensure_script(feature, install=True):
    """The one node command for a feature: PRESENT when every package checks out, else
    either MISSING <names> or the apt-get run for the missing ones and then INSTALLED,
    UNVERIFIED <names> (apt-get went through, the check still fails) or FAILED <names>.
    The last 25 lines of apt-get come before that line, a pve-apt-hook refusal is longer
    than five. A list that apt cannot resolve gets one apt-get update and a second try."""
    names = packages_of(feature)
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
    msg = (f"Target node {node} is missing packages this migration needs, and installing packages "
           f"on it is turned off for this migration: {what}. Install them on the node "
           f"({apt_command(names)}) or allow the installs")
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
