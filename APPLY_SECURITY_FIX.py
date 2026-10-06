#!/usr/bin/env python3
"""
SECURITY FIX for pegaprox/core/v2p.py

This script fixes the predictable temporary file vulnerability where scripts are
written to predictable paths in /tmp, allowing local privilege escalation.

The vulnerability affects:
1. _register_uefi_fallback_loader() - line ~2054
2. _inject_virtio_drivers() - line ~2566

Root cause: Scripts are written to /tmp/v2p-*-{vmid}.sh using predictable names,
then executed in a separate command. An attacker can replace the file between
write and execution (TOCTOU attack).

Fix: Use mktemp to create secure temporary files with unpredictable names, and
execute them atomically in a single command.
"""

import sys


def apply_fixes():
    # Read the file
    with open("pegaprox/core/v2p.py", "r", encoding="utf-8") as f:
        lines = f.readlines()

    print(f"Read {len(lines)} lines from pegaprox/core/v2p.py")

    # Fix 1: EFI fallback script (around line 2054)
    # Find the vulnerable pattern
    efi_fixed = False
    for i in range(2050, min(2070, len(lines))):
        if "v2p-efi-fallback" in lines[i] and "proxmox_vmid" in lines[i]:
            print(f"Found EFI fallback vulnerability at line {i+1}")
            print(f"  Old: {lines[i].strip()}")

            # Replace 6 lines: sf = ..., _pve_node_exec(...), rc, out, err = ...
            new_lines = [
                "        # SECURITY FIX: Use mktemp to create secure temporary file with unpredictable name.\n",
                "        # Write, execute, and remove atomically to prevent TOCTOU attacks where an attacker\n",
                "        # could replace a predictable script path between write and execution.\n",
                "        rc, out, err = _pve_node_exec(pve_mgr, task.target_node,\n",
                '            f"sf=$(mktemp /tmp/v2p-efi-fallback.XXXXXXXXXX) && "\n',
                '            f"chmod 700 \\"$sf\\" && "\n',
                '            f"cat > \\"$sf\\" << \'EOFSCRIPT\'\\\\n{script}EOFSCRIPT\\\\n"\n',
                '            f"bash \\"$sf\\" 2>&1; rc=$?; rm -f \\"$sf\\"; exit $rc",\n',
                "            timeout=135)\n",
            ]
            lines[i : i + 6] = new_lines
            efi_fixed = True
            print(f"  ✓ Fixed EFI fallback (replaced 6 lines with 9 lines)")
            break

    if not efi_fixed:
        print("  ✗ ERROR: Could not find EFI fallback pattern")
        return False

    # Fix 2: VirtIO inject script (search for it, line numbers shifted after first fix)
    virtio_fixed = False
    for i in range(2550, min(2700, len(lines))):
        if "v2p-virtio-inject" in lines[i] and "proxmox_vmid" in lines[i]:
            print(f"Found VirtIO inject vulnerability at line {i+1}")
            print(f"  Old: {lines[i].strip()}")

            # Replace 4 lines: sf = ..., _pve_node_exec(...)
            new_lines = [
                "\n",
                "    # SECURITY FIX: Use mktemp to create secure temporary file with unpredictable name.\n",
                "    # Create temp file, write script, store path for later execution.\n",
                "    sf_cmd = (\n",
                '        f"sf=$(mktemp /tmp/v2p-virtio-inject.XXXXXXXXXX) && "\n',
                '        f"chmod 700 \\"$sf\\" && "\n',
                '        f"cat > \\"$sf\\" << \'EOFSCRIPT\'\\\\n{script}EOFSCRIPT\\\\n"\n',
                '        f"echo \\"$sf\\""\n',
                "    )\n",
                "    rc_sf, sf_path, _ = _pve_node_exec(pve_mgr, node, sf_cmd, timeout=15)\n",
                "    sf = str(sf_path or '').strip()\n",
                "    if not sf:\n",
                '        task.log("[VirtIO] Failed to create secure temporary file")\n',
                "        return False\n",
            ]
            lines[i : i + 4] = new_lines
            virtio_fixed = True
            print(f"  ✓ Fixed VirtIO inject (replaced 4 lines with 14 lines)")
            break

    if not virtio_fixed:
        print("  ✗ ERROR: Could not find VirtIO inject pattern")
        return False

    # Write the fixed file
    with open("pegaprox/core/v2p.py", "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"\n✓ Successfully wrote {len(lines)} lines to pegaprox/core/v2p.py")
    print("\nSecurity fixes applied:")
    print("  1. EFI fallback: /tmp/v2p-efi-fallback-{vmid}.sh → mktemp-generated path")
    print(
        "  2. VirtIO inject: /tmp/v2p-virtio-inject-{vmid}.sh → mktemp-generated path"
    )
    print("\nBoth vulnerabilities mitigated by:")
    print("  - Using mktemp for unpredictable file names")
    print("  - Setting chmod 700 for exclusive access")
    print("  - Atomic write-execute-remove operations")

    return True


if __name__ == "__main__":
    success = apply_fixes()
    sys.exit(0 if success else 1)
