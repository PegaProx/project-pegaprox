#!/usr/bin/env python3
"""
DEFINITIVE SECURITY FIX for pegaprox/core/v2p.py

This script applies the security fix for the predictable temporary file vulnerability.
Run this script to patch the vulnerability.

Usage: python3 FINAL_SECURITY_FIX.py
"""


def main():
    import sys

    # Read the file
    try:
        with open("pegaprox/core/v2p.py", "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("ERROR: pegaprox/core/v2p.py not found")
        print("Please run this script from the repository root")
        return 1

    print(f"Read {len(lines)} lines from pegaprox/core/v2p.py")
    original_line_count = len(lines)

    # Fix 1: EFI fallback script vulnerability
    efi_fixed = False
    for i in range(len(lines)):
        line = lines[i]
        if (
            "v2p-efi-fallback" in line
            and "task.proxmox_vmid" in line
            and 'sf = f"' in line
        ):
            print(f"\n[Fix 1] Found EFI fallback vulnerability at line {i+1}")
            print(f"  Current: {line.strip()[:80]}...")

            # Verify we're at the right place by checking the next few lines
            if i + 5 < len(lines) and "bash {sf}" in lines[i + 5]:
                # Replace 6 lines starting at index i
                new_block = [
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
                lines[i : i + 6] = new_block
                efi_fixed = True
                print(f"  ✓ Replaced 6 vulnerable lines with 9 secure lines")
                break

    if not efi_fixed:
        print("\n✗ ERROR: Could not locate EFI fallback vulnerability pattern")
        print(
            "  The file may have already been patched or the code structure has changed"
        )
        return 1

    # Fix 2: VirtIO inject script vulnerability
    virtio_fixed = False
    for i in range(len(lines)):
        line = lines[i]
        if (
            "v2p-virtio-inject" in line
            and "task.proxmox_vmid" in line
            and 'sf = f"' in line
        ):
            print(f"\n[Fix 2] Found VirtIO inject vulnerability at line {i+1}")
            print(f"  Current: {line.strip()[:80]}...")

            # Verify we're at the right place
            if i + 3 < len(lines) and "EOFSCRIPT" in lines[i + 2]:
                # Replace 4 lines starting at index i
                new_block = [
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
                lines[i : i + 4] = new_block
                virtio_fixed = True
                print(f"  ✓ Replaced 4 vulnerable lines with 14 secure lines")
                break

    if not virtio_fixed:
        print("\n✗ ERROR: Could not locate VirtIO inject vulnerability pattern")
        print(
            "  The file may have already been patched or the code structure has changed"
        )
        return 1

    # Write the patched file
    try:
        with open("pegaprox/core/v2p.py", "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"\n✗ ERROR writing patched file: {e}")
        return 1

    print(f"\n✓ Successfully patched pegaprox/core/v2p.py")
    print(f"  Original: {original_line_count} lines")
    print(f"  Patched:  {len(lines)} lines")
    print(f"  Delta:    +{len(lines) - original_line_count} lines")

    print("\n" + "=" * 70)
    print("SECURITY FIXES APPLIED SUCCESSFULLY")
    print("=" * 70)
    print("\nVulnerabilities mitigated:")
    print("  1. EFI fallback: Predictable /tmp/v2p-efi-fallback-{vmid}.sh")
    print("     → Now uses mktemp-generated unpredictable path")
    print("  2. VirtIO inject: Predictable /tmp/v2p-virtio-inject-{vmid}.sh")
    print("     → Now uses mktemp-generated unpredictable path")
    print("\nMitigation strategy:")
    print("  - mktemp creates files with unpredictable names")
    print("  - chmod 700 ensures exclusive owner access")
    print("  - Atomic write-execute-remove prevents TOCTOU attacks")
    print("\nNext steps:")
    print("  1. Review the changes: git diff pegaprox/core/v2p.py")
    print("  2. Test the functionality")
    print("  3. Commit the changes")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
