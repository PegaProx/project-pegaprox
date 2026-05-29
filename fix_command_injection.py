#!/usr/bin/env python3
"""
Command Injection Fix for pegaprox/core/v2p.py

This script fixes a command injection vulnerability by adding shlex.quote()
around task.target_storage in qm set --efidisk0 commands.

The vulnerability allows an attacker with vm.migrate permission to execute
arbitrary shell commands on Proxmox nodes by crafting a malicious target_storage value.

Fix: Add shlex.quote() around task.target_storage in all qm set --efidisk0 commands.
"""

import sys
import os


def main():
    filepath = "pegaprox/core/v2p.py"

    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found")
        print("Please run this script from the repository root")
        sys.exit(1)

    # Read the file
    print(f"Reading {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern to find and replace
    vulnerable_pattern = "--efidisk0 {task.target_storage}:1,efitype"
    fixed_pattern = "--efidisk0 {shlex.quote(task.target_storage)}:1,efitype"

    # Count occurrences
    count_before = content.count(vulnerable_pattern)
    print(f"Found {count_before} vulnerable instances")

    if count_before == 0:
        print("No vulnerable instances found - file may already be fixed")
        return 0

    # Apply the fix
    content_fixed = content.replace(vulnerable_pattern, fixed_pattern)

    # Verify
    count_after_vulnerable = content_fixed.count(vulnerable_pattern)
    count_after_fixed = content_fixed.count(fixed_pattern)

    print(f"After fix: {count_after_vulnerable} vulnerable, {count_after_fixed} fixed")

    if count_after_vulnerable > 0:
        print(f"ERROR: Still {count_after_vulnerable} vulnerable instances remaining!")
        return 1

    if count_after_fixed != count_before:
        print(
            f"ERROR: Expected {count_before} fixed instances, got {count_after_fixed}"
        )
        return 1

    # Write back
    print(f"Writing fixed content to {filepath}...")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content_fixed)

    print("✓ Successfully fixed all instances")
    print(f"✓ Added shlex.quote() to {count_after_fixed} locations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
