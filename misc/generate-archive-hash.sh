#!/usr/bin/env bash
# ============================================================================
# PegaProx Archive Hash Generator
# ============================================================================
# Generates SHA256 hash for update archives to be added to version.json
#
# Usage:
#   ./generate-archive-hash.sh <archive-file>
#   ./generate-archive-hash.sh https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz
#
# Output format for version.json:
#   "archive_sha256": "a1b2c3d4e5f6..."
#
# Security: This hash is used to verify archive integrity during updates,
# preventing code execution from tampered archives.
# ============================================================================

set -euo pipefail

if [ $# -eq 0 ]; then
    echo "Usage: $0 <archive-file-or-url>"
    echo ""
    echo "Examples:"
    echo "  $0 main.tar.gz"
    echo "  $0 https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz"
    echo ""
    echo "Output: SHA256 hash suitable for version.json 'archive_sha256' field"
    exit 1
fi

INPUT="$1"
TEMP_FILE=""

# Cleanup function
cleanup() {
    if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi
}
trap cleanup EXIT

# Check if input is a URL or local file
if [[ "$INPUT" =~ ^https?:// ]]; then
    echo "Downloading archive from: $INPUT" >&2
    TEMP_FILE=$(mktemp)
    
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$INPUT" -o "$TEMP_FILE"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$INPUT" -O "$TEMP_FILE"
    else
        echo "Error: Neither curl nor wget found. Please install one of them." >&2
        exit 1
    fi
    
    FILE_TO_HASH="$TEMP_FILE"
else
    # Local file
    if [ ! -f "$INPUT" ]; then
        echo "Error: File not found: $INPUT" >&2
        exit 1
    fi
    FILE_TO_HASH="$INPUT"
fi

# Compute SHA256
echo "Computing SHA256 hash..." >&2
HASH=$(sha256sum "$FILE_TO_HASH" | cut -d' ' -f1)

echo "" >&2
echo "============================================================================" >&2
echo "Archive SHA256 Hash:" >&2
echo "============================================================================" >&2
echo "$HASH" >&2
echo "" >&2
echo "Add this to version.json:" >&2
echo "  \"archive_sha256\": \"$HASH\"" >&2
echo "============================================================================" >&2

# Also output just the hash for scripting
echo "$HASH"
