"""Three defects in the VirtIO injection, all with the same shape: the step reported
something other than what happened. Reported Sep 2026 against 1.1.1, measured on a stock
PVE 9.2.11 node with a Windows Server 2022 guest.

  1. the one-time apt install asked for qemu-utils, which on PVE conflicts with
     pve-qemu-kvm — apt proposes to remove it and takes proxmox-ve along, pve-apt-hook
     aborts the run, and nothing in the list gets installed. `| tail -5` then cut the
     hook's explanation out of the captured output, so the log said
     "✗ apt install failed:" with nothing after the colon.
  2. hivexsh was used by the version probe but never installed and its failure hidden by
     2>/dev/null, so VER_BUILD came back empty, the build table matched nothing, every
     guest got the w11 driver variant, and the step still reported INJECTION_OK.
  3. .cat files were copied next to the .sys instead of into the catalogue store.

The file already knew about (1): the #520 preflight refuses to suggest qemu-utils on PVE
in so many words, 1700 lines further up. That is why the test below reads BOTH sites.
MK
"""
import ast
import pathlib
import re
import subprocess
import shutil

import pytest

_V2P = pathlib.Path(__file__).resolve().parent.parent / 'pegaprox' / 'core' / 'v2p.py'
_SRC = _V2P.read_text(encoding='utf-8')


def _injection_node_script():
    """The shell script _inject_virtio_drivers builds and runs on the Proxmox node.

    Assembled from the literal parts of the `script = (...)` concatenation, which is what
    actually reaches the node; f-string interpolations become PLACEHOLDER.
    """
    tree = ast.parse(_SRC)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == '_inject_virtio_drivers')

    def flatten(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.JoinedStr):
            return ''.join(v.value if isinstance(v, ast.Constant) else 'PLACEHOLDER'
                           for v in n.values)
        if isinstance(n, ast.BinOp):
            return flatten(n.left) + flatten(n.right)
        return ''

    best = ''
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            try:
                txt = flatten(node.value)
            except Exception:
                continue
            if 'WDIR=' in txt and len(txt) > len(best):
                best = txt
    assert best, "could not recover the node script from _inject_virtio_drivers"
    return best


def _node_commands():
    """Every command string _inject_virtio_drivers hands to _pve_node_exec.

    Deliberately the ARGUMENTS, not the surrounding source text: the comments there
    explain what was removed and why, and a test that greps the region would keep
    failing on its own explanation. What matters is what gets run on the node.
    """
    tree = ast.parse(_SRC)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == '_inject_virtio_drivers')
    cmds = []
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == '_pve_node_exec'):
            continue
        for arg in node.args[1:]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                cmds.append(arg.value)
            elif isinstance(arg, ast.BinOp):
                parts = []
                stack = [arg]
                while stack:
                    n = stack.pop()
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        parts.append(n.value)
                    elif isinstance(n, ast.BinOp):
                        stack += [n.right, n.left]
                if parts:
                    cmds.append(''.join(reversed(parts)))
    assert cmds, "no node commands recovered"
    return cmds


def _apt_install_cmds():
    hits = [c for c in _node_commands() if 'apt-get install' in c]
    assert hits, "nothing installs the prerequisites any more"
    return hits


def _required_tool_probe():
    """The probe whose failure is fatal — it decides whether the injection runs at all."""
    hits = [c for c in _node_commands() if "import hivex" in c]
    assert len(hits) == 1, f"expected exactly one required-tool probe, got {len(hits)}"
    return hits[0]


# ── 1) the apt install must be something a Proxmox node can accept ───────────

def test_the_prereq_install_does_not_ask_for_qemu_utils():
    offenders = [c for c in _apt_install_cmds() if 'qemu-utils' in c]
    assert not offenders, (
        "the VirtIO prereq install asks for qemu-utils — on PVE that conflicts with "
        "pve-qemu-kvm, so apt offers to remove proxmox-ve and pve-apt-hook kills the "
        "whole run. qemu-nbd already ships with pve-qemu-kvm.")


def test_the_shared_probe_no_longer_gates_on_qemu_nbd():
    assert 'qemu-nbd' not in _required_tool_probe(), (
        "a missing qemu-nbd here triggers the apt run that takes proxmox-ve down; the "
        "file-based branch checks for it on its own")


def test_the_file_based_branch_still_checks_qemu_nbd_itself():
    """Dropping qemu-nbd from the shared probe is only safe because the one branch that
    needs it tests for it and says so."""
    script = _injection_node_script()
    assert "command -v qemu-nbd >/dev/null || { echo 'qemu-nbd missing'" in script


def test_the_two_places_that_talk_about_qemu_utils_agree():
    """#520 rewrote the preflight to warn against qemu-utils on PVE; this pins that the
    injection path never contradicts it again."""
    assert 'Do NOT run `apt install qemu-utils` on PVE' in _SRC, \
        "the #520 warning is gone — if that was deliberate this test needs rewriting"
    installs = [ln for ln in _SRC.splitlines()
                if 'apt-get install' in ln and 'qemu-utils' in ln]
    assert not installs, f"still installing qemu-utils somewhere: {installs}"


@pytest.mark.parametrize('cmd', _apt_install_cmds())
def test_a_failed_apt_run_keeps_enough_output_to_show_why(cmd):
    m = re.search(r'tail -(\d+)', cmd)
    assert m, "the apt output is no longer tailed at all — fine, but this test assumed it was"
    assert int(m.group(1)) >= 20, (
        f"tail -{m.group(1)} cuts the pve-apt-hook refusal off and the operator gets "
        "'apt install failed:' with nothing after the colon")


# ── 2) the version probe's own tool ──────────────────────────────────────────

def test_hivexsh_is_installed_and_probed_since_the_script_shells_out_to_it():
    assert any('libhivex-bin' in c for c in _apt_install_cmds()), \
        "hivexsh is used but its package is never installed"
    assert any('command -v hivexsh' in c for c in _node_commands()), \
        "nothing checks for hivexsh before relying on it"


def test_a_missing_hivexsh_does_not_abort_a_migration_that_used_to_work():
    """It only feeds the version probe, and the script has a fallback — on a Windows 11
    guest the fallback variant is even the correct one. Gating the fatal probe on it
    would turn an air-gapped node that worked into a failed migration."""
    assert 'hivexsh' not in _required_tool_probe(), (
        "hivexsh is back in the probe whose failure returns False — a node that cannot "
        "reach apt would now fail instead of guessing the variant and saying so")


def test_a_missing_hivexsh_is_reported_instead_of_silently_defaulting():
    script = _injection_node_script()
    assert 'NO_HIVEXSH' in script, (
        "without hivexsh VER_BUILD is empty, the case falls through to the w11 variant "
        "and the step still prints INJECTION_OK — say so instead")


def test_the_build_table_still_maps_the_server_builds():
    """Guard against 'fixing' the probe by deleting the thing it feeds."""
    script = _injection_node_script()
    for build, sub in (('20348', '2k22/amd64'), ('17763', '2k19/amd64'),
                       ('14393', '2k16/amd64')):
        assert build in script and sub in script, f"{build} -> {sub} mapping lost"


# ── 3) catalogues belong in the catalogue store ──────────────────────────────

_CATROOT = 'System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'


def test_catalogues_are_copied_into_the_catalogue_store():
    script = _injection_node_script()
    assert _CATROOT in script, "the driver-package catalogue store is not used"
    assert 'cp -f "$SRC"/*.cat "$CAT_DEST/"' in script, \
        "the .cat copy does not point at the catalogue store"
    assert 'cp -f "$SRC"/*.cat "$DRV_DEST/"' not in script, \
        "still dropping catalogues next to the .sys, where nothing reads them"


def test_the_store_is_created_before_anything_is_copied_into_it():
    script = _injection_node_script()
    mk = script.find('mkdir -p "$INF_DEST" "$CAT_DEST"')
    cp = script.find('cp -f "$SRC"/*.cat')
    assert mk != -1, "nothing creates the catalogue store"
    assert cp != -1, "nothing copies catalogues any more"
    assert mk < cp, "CAT_DEST is used before it is created"


@pytest.mark.skipif(not shutil.which('bash'), reason='no bash')
def test_the_generated_script_is_valid_shell():
    """It runs on a customer's hypervisor — a syntax error there is not a test failure,
    it is a failed migration on somebody else's node."""
    script = _injection_node_script()
    p = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
    assert p.returncode == 0, f"bash -n rejected the node script:\n{p.stderr}"


@pytest.mark.skipif(not shutil.which('bash'), reason='no bash')
def test_the_guid_braces_are_not_brace_expanded(tmp_path):
    """The store's name contains {...}. Inside double quotes bash leaves it alone; this
    pins that the path we build is the path that gets created."""
    script = (
        f'WIN_MNT={tmp_path}\nWDIR=Windows\n'
        'CAT_DEST="$WIN_MNT/$WDIR/' + _CATROOT + '"\n'
        'mkdir -p "$CAT_DEST"\n'
        'printf "%s" "$CAT_DEST"\n'
    )
    p = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
    assert p.returncode == 0, p.stderr
    assert p.stdout.endswith(_CATROOT)
    assert (tmp_path / 'Windows' / 'System32' / 'CatRoot'
            / '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}').is_dir()
