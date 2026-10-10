"""Central SSH host-key verification for every paramiko connection PegaProx makes.

Background
----------
PegaProx connects over SSH to a fleet of hosts (PVE nodes, PBS, ESXi, XCP-ng,
storage boxes) whose host keys are not provisioned ahead of time. The historical
code used ``paramiko.AutoAddPolicy`` / ``WarningPolicy``, which accept an unknown
host key silently — flagged as a critical MitM exposure (an attacker sitting
between the hub and a node could impersonate it and capture credentials/commands).

You cannot simply switch to ``RejectPolicy``: with no pre-seeded known_hosts every
connection would fail, breaking HA fencing, V2P, storage sync, VNC tunnels, etc.

Model
-----
**Trust-on-first-use (TOFU), reject-on-change** — the standard for a fleet tool:

* paramiko itself raises ``BadHostKeyException`` when a host **already in
  known_hosts** presents a *different* key. That is the actual MitM protection,
  and it only works if known_hosts is *loaded* — which several call sites did not
  do. This module makes loading + persisting uniform, so a changed key is rejected
  everywhere on the next connection.
* The *first* time a host is seen (missing key) this policy records the key and
  continues — what a fleet tool needs. It logs every newly-recorded key for audit.
* **Strict mode** (opt-in via ``PEGAPROX_SSH_STRICT_HOST_KEYS=1``) rejects any host
  not already in known_hosts, for high-assurance deployments that seed known_hosts
  out-of-band.

This module imports nothing from ``pegaprox`` so any layer can use it without
circular-import risk. paramiko is passed in by the caller (several call sites
import it lazily).
"""

import os
import logging
import threading

# known_hosts lives in the REAL runtime config dir (the one that holds pegaprox.db),
# i.e. <cwd>/config — NOT pegaprox/config inside the package (which does not exist at
# runtime). Using the wrong path silently no-op'd every save(), so the historical
# "TOFU" never actually persisted a key and thus never rejected a changed one.
try:
    from pegaprox.constants import CONFIG_DIR as _CONFIG_DIR
except Exception:
    _CONFIG_DIR = 'config'
_KNOWN_HOSTS = os.path.abspath(os.path.join(_CONFIG_DIR, '.ssh_known_hosts'))

_persist_lock = threading.Lock()
_log = logging.getLogger('pegaprox.ssh')


def strict_host_keys_enabled() -> bool:
    """Whether unknown host keys should be rejected instead of trusted-on-first-use.

    Opt-in and off by default so existing deployments keep working. High-assurance
    setups can turn it on after seeding config/.ssh_known_hosts out-of-band.
    """
    return os.environ.get('PEGAPROX_SSH_STRICT_HOST_KEYS', '').strip().lower() in (
        '1', 'true', 'yes', 'on')


def pins_host_keys_here() -> bool:
    """False on a warm standby (#625). Its known_hosts is the leader's copy and the next
    sync replaces the file, so a key pinned here would not last, and one pinned through
    a man in the middle would be trusted until then. A standby checks against the keys
    it holds and refuses a host it does not know yet.

    Imported when asked, not at the top: this module stays importable from anywhere."""
    try:
        from pegaprox.core import ha
    except Exception:
        return True
    return not ha.is_standby()


def _not_known_here(address):
    # the leader pins a key under the address it connects to, and a standby looks it up
    # under the one it tried: a member that reaches the node elsewhere (another site or
    # VLAN) finds no key, whatever the leader holds
    return (f"host key of {address} is not known here yet - open a shell to it on the "
            f"leader once. This standby only has the keys the leader pinned; if the leader "
            f"reaches this node at another address than {address}, its key is pinned under "
            "that one")


def _unreadable_refusal(address):
    # NS Oct 2026 - paramiko's load() raises on a truncated entry and drops every line after
    # it, so the pins behind it read as unknown hosts. Trusting those on first use is the
    # MitM window the pins close. The reason is logged; the message stays generic.
    return (f"config/.ssh_known_hosts could not be read, so the host key of {address} cannot "
            "be checked against its pin - refusing to trust it on first use. Repair or remove "
            "the damaged line (see the log) and connect again")


def _unpinned_type_refusal(paramiko, hostname, keytype):
    return paramiko.SSHException(
        f"host {hostname} is known but presented an unpinned key type "
        f"({keytype}) - refusing (possible downgrade/MitM). Remove its "
        "config/.ssh_known_hosts entry to re-pin.")


def cli_hostkey_opts():
    """Host-key options for subprocess ``ssh``/``scp``/``sshfs`` commands.

    Returns ``(strict_value, known_hosts_path)`` to replace the insecure
    ``StrictHostKeyChecking=no`` + ``UserKnownHostsFile=/dev/null`` combo:
    * ``accept-new`` accepts a brand-new host but REJECTS a changed key (MitM),
      upgraded to ``yes`` (reject unknown too) under strict mode;
    * pinned to the SAME known_hosts file the paramiko paths use, so a key learned
      by one path is verified by the other.
    ``yes`` on a standby as well, which pins nothing (pins_host_keys_here).
    """
    hkc = 'yes' if strict_host_keys_enabled() or not pins_host_keys_here() else 'accept-new'
    return hkc, _KNOWN_HOSTS


def _make_policy(paramiko, unreadable=False):
    strict = strict_host_keys_enabled()

    class _TofuHostKeyPolicy(paramiko.MissingHostKeyPolicy):
        """TOFU on first sight; reject-on-change is handled by paramiko itself
        (BadHostKeyException) once the key is in known_hosts."""

        def missing_host_key(self, client, hostname, key):
            fp = ''
            try:
                fp = key.get_fingerprint().hex()
            except Exception:
                pass
            if not pins_host_keys_here():
                raise paramiko.SSHException(_not_known_here(hostname))
            if unreadable:
                raise paramiko.SSHException(_unreadable_refusal(hostname))
            if strict:
                raise paramiko.SSHException(
                    "strict host-key checking: unknown SSH host key for "
                    f"{hostname} ({key.get_name()} {fp}); seed config/.ssh_known_hosts first")
            # TOFU: record the key on the client's in-memory store. The caller
            # persists it via persist_host_keys() so the NEXT connection to this
            # host verifies against it (reject-on-change).
            try:
                client._host_keys.add(hostname, key.get_name(), key)
            except Exception:
                pass
            try:
                _log.info("TOFU: recorded new SSH host key for %s (%s %s)",
                          hostname, key.get_name(), fp)
            except Exception:
                pass

    return _TofuHostKeyPolicy()


def apply_host_key_policy(client, paramiko):
    """Load known_hosts into ``client`` and set the TOFU/strict verifying policy.

    Use in place of ``client.set_missing_host_key_policy(paramiko.AutoAddPolicy())``.
    """
    unreadable = False
    try:
        if os.path.exists(_KNOWN_HOSTS):
            client.load_host_keys(_KNOWN_HOSTS)
    except Exception as e:
        # NS Oct 2026 - the keys loaded before the error still verify; a host that is
        # missing now may be one whose pin sat behind it, so no first use this round
        _log.warning("known_hosts unreadable (%s) - refusing new host keys until it is repaired", e)
        unreadable = True
    client.set_missing_host_key_policy(_make_policy(paramiko, unreadable))
    return client


def pin_as(client, paramiko, hostname, pinned_as, port=22):
    """Let ``client`` accept at ``hostname`` only the host keys pinned for ``pinned_as``.

    For a second address of a host we already know, such as a node's transfer address
    next to its management address: no trust on first use there and no key of its own.
    The client drops every other pin, holds the keys of ``pinned_as`` under ``hostname``
    and refuses anything else, so a different key or key type there ends the connect
    before any credential is sent. False when ``pinned_as`` has no pin to lend or the
    file cannot be read: then do not connect there. The caller persists nothing."""
    try:
        _port = int(port or 22)
    except (TypeError, ValueError):
        _port = 22

    def name(h):
        return h if _port == 22 else '[%s]:%d' % (h, _port)

    pins = paramiko.hostkeys.HostKeys()
    try:
        if os.path.exists(_KNOWN_HOSTS):
            pins.load(_KNOWN_HOSTS)
    except Exception as e:
        _log.warning("known_hosts unreadable (%s) - not lending the pin of %s to %s", e, pinned_as, hostname)
        return False
    entry = pins.lookup(name(pinned_as))
    if not entry:
        return False
    keys = client.get_host_keys()
    keys.clear()
    system = getattr(client, '_system_host_keys', None)
    if system is not None:
        system.clear()
    for keytype in list(entry.keys()):
        keys.add(name(hostname), keytype, entry[keytype])

    class _OnlyThePin(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, host, key):
            raise paramiko.SSHException(
                f"the host key at {host} ({key.get_name()}) is not one pinned for {pinned_as}")

    client.set_missing_host_key_policy(_OnlyThePin())
    return True


def secure_ssh_client(paramiko):
    """Return a fresh ``paramiko.SSHClient`` with known_hosts loaded + policy set.

    Its commands ask the transport guard of an automatic group (#625)."""
    client = paramiko.SSHClient()
    from pegaprox.core import ha_transport
    return ha_transport.guard_client(apply_host_key_policy(client, paramiko))


def persist_host_keys(client):
    """Persist any newly-learned host keys so the next connection verifies against
    them. Best-effort: the config dir may be read-only. Serialized to avoid two
    greenlets clobbering the file.

    MK Sep 2026 - this used to be a bare ``client.save_host_keys()``, which writes the
    set the client loaded when it was BUILT and truncates the file. Anything pinned in
    between was erased: a keyboard-interactive login going through
    verify_transport_host_key, or simply a second client that learned a host first. The
    host then reads as unknown on its next connect and gets trust-on-first-use again -
    silently, and for exactly the hosts that had just been pinned. So merge instead, and
    let the file win wherever it already has a key for that host and type: an entry on
    disk is either a deliberate pin or newer than what this client is carrying.

    Nothing on a standby (pins_host_keys_here).
    """
    if not pins_host_keys_here():
        return
    try:
        import paramiko as _pk
        with _persist_lock:
            merged = _pk.hostkeys.HostKeys()
            try:
                if os.path.exists(_KNOWN_HOSTS):
                    merged.load(_KNOWN_HOSTS)
            except Exception as _le:
                # MK Sep 2026 - this used to carry on with an EMPTY set and save, which
                # replaced the file with just this client's keys. Measured: paramiko's
                # load() raises ValueError on a truncated entry, which is exactly what an
                # interrupted save leaves behind, and it raises for the whole file - one
                # bad line loses every good pin before it. Writing then is the worst of
                # the two outcomes: a lost pin puts that host back on trust-on-first-use,
                # while a key we fail to add just means the next connect pins it. So do
                # not write when we could not read.
                _log.warning("known_hosts unreadable (%s) - not persisting host keys this "
                             "round rather than overwriting pins we cannot see", _le)
                return
            added = 0
            for hostname, keys in (client.get_host_keys() or {}).items():
                on_disk = merged.lookup(hostname)
                for keytype, key in keys.items():
                    if on_disk is not None and keytype in on_disk:
                        continue
                    merged.add(hostname, keytype, key)
                    added += 1
            if added:
                merged.save(_KNOWN_HOSTS)
    except Exception:
        pass  # config dir might not be writable — non-fatal


def _known_hosts_token_host(tok):
    """Extract the bare host from one known_hosts host-field token.

    Handles ``host``, ``192.168.1.2``, the bracketed non-standard-port form
    ``[host]:2222`` / ``[2001:db8::1]:2222`` and a bare IPv6 (``2001:db8::1``).
    A naive ``split(':')[0]`` truncates IPv6 addresses at their first colon, so
    only strip a ``:port`` suffix when the token is in the bracketed form.
    """
    tok = tok.strip()
    if tok.startswith('['):
        rb = tok.rfind(']')
        if rb != -1:
            return tok[1:rb]
    return tok


def remove_host_keys(hostnames):
    """Drop known_hosts entries for the given hosts/IPs.

    Call this when a cluster or node is REMOVED from PegaProx so that re-adding it
    later works cleanly: if the box was reinstalled in the meantime it presents a
    new host key, and without this the stale pinned key would trip reject-on-change
    and block the reconnect. Text-based (handles ``host``, ``h1,h2`` and
    ``[host]:port`` line forms); returns the number of lines removed.
    """
    targets = set(str(h).strip() for h in (hostnames or []) if h and str(h).strip())
    if not targets or not os.path.exists(_KNOWN_HOSTS):
        return 0
    removed = 0
    try:
        with _persist_lock:
            with open(_KNOWN_HOSTS) as f:
                lines = f.readlines()
            kept = []
            for ln in lines:
                if not ln.strip():
                    kept.append(ln)
                    continue
                first = ln.split(None, 1)[0]
                hosts_in_line = [_known_hosts_token_host(h) for h in first.split(',')]
                if any(h in targets for h in hosts_in_line):
                    removed += 1
                else:
                    kept.append(ln)
            if removed:
                with open(_KNOWN_HOSTS, 'w') as f:
                    f.writelines(kept)
                try:
                    _log.info("removed %d known_hosts entr%s for %s",
                              removed, 'y' if removed == 1 else 'ies', sorted(targets))
                except Exception:
                    pass
    except Exception:
        pass
    return removed


def verify_transport_host_key(transport, hostname, paramiko, port=22):
    """Verify the server key of a MANUALLY-built ``paramiko.Transport``.

    Keyboard-interactive auth is done over a Transport we build ourselves
    (``paramiko.Transport(sock); transport.connect()``). paramiko does NOT consult
    the SSHClient missing-host-key policy for that, so those paths had no host-key
    verification at all. Call this **right after ``transport.connect()`` and BEFORE
    sending any credentials** so a changed/unknown key is caught before the password
    is exposed.

    * known host, key matches  -> return (ok)
    * known host, key changed  -> raise BadHostKeyException (MitM protection)
    * unknown host, strict off -> record (TOFU) + persist
    * unknown host, strict on or on a standby -> raise SSHException
    * unknown host, known_hosts unreadable    -> raise SSHException
    """
    try:
        key = transport.get_remote_server_key()
    except Exception as e:
        # A transport that completed key exchange always carries a server key;
        # a failure here is anomalous. Fail CLOSED — never let auth proceed
        # unverified. Every caller wraps this call in its connect try/except, so
        # the raise is handled exactly like a changed/rejected key.
        raise paramiko.SSHException(
            "could not retrieve SSH host key for %s to verify (failing closed): %s"
            % (hostname, e))
    keytype = key.get_name()
    # known_hosts keys a non-standard port as "[host]:port"; port 22 is the bare
    # host. Look up and pin under the same normalized name or a non-22 host would
    # be treated as unknown on every connect (TOFU re-add, never actually pinned).
    try:
        _port = int(port or 22)
    except (TypeError, ValueError):
        _port = 22
    lookup_name = hostname if _port == 22 else '[%s]:%d' % (hostname, _port)
    hostkeys = paramiko.hostkeys.HostKeys()
    unreadable = None
    try:
        if os.path.exists(_KNOWN_HOSTS):
            hostkeys.load(_KNOWN_HOSTS)
    except Exception as e:
        unreadable = e
    entry = hostkeys.lookup(lookup_name)
    if entry is not None:
        # host is already known — the offered key MUST match one of its pinned keys.
        if keytype in entry:
            if entry[keytype] != key:
                raise paramiko.BadHostKeyException(hostname, key, entry[keytype])
            return  # matches a pinned key — good
        # host is known but presented a key of a type we have NOT pinned. Do NOT
        # trust-on-first-use a new key type for an already-known host — an on-path
        # attacker who holds a key of a different type could otherwise downgrade
        # around the pinned key. Reject; an admin can drop the stale entry to re-pin.
        raise _unpinned_type_refusal(paramiko, hostname, keytype)
    # genuinely unknown host — first time we see it at all
    if not pins_host_keys_here():
        raise paramiko.SSHException(_not_known_here(lookup_name))
    if unreadable is not None:
        _log.warning("known_hosts unreadable (%s) - not trusting %s on first use", unreadable, lookup_name)
        raise paramiko.SSHException(_unreadable_refusal(lookup_name))
    if strict_host_keys_enabled():
        raise paramiko.SSHException(
            "strict host-key checking: unknown SSH host key for "
            f"{hostname} ({keytype}); seed config/.ssh_known_hosts first")
    # MK Sep 2026 - the lock used to cover only the save, and `hostkeys` was loaded far
    # above, before the lookup. Adding to that stale copy and writing the whole set back
    # erased any pin another writer recorded in between - and losing a pin puts the host
    # back on the TOFU path, which is the MitM window this function exists to close.
    # persist_host_keys() already does it the right way; do the same here: re-read inside
    # the lock, add only the key we just verified, save that.
    refusal, recorded = None, False
    try:
        with _persist_lock:
            fresh = paramiko.hostkeys.HostKeys()
            try:
                if os.path.exists(_KNOWN_HOSTS):
                    fresh.load(_KNOWN_HOSTS)
            except Exception as _le:
                # Same call persist_host_keys makes, and for the same reason: if the file
                # cannot be read we cannot merge into it, and writing anyway would replace
                # pins we never saw. Skip the write, and (NS Oct 2026) refuse: we cannot
                # see whether somebody pinned this host since the lookup above.
                _log.warning("known_hosts unreadable (%s) - not pinning %s this round",
                             _le, hostname)
                refusal = paramiko.SSHException(_unreadable_refusal(lookup_name))
                raise
            # NS Oct 2026 (#1025) - another first-use connection may have pinned this host
            # since the lookup above, and add() used to replace that pin with our key, so a
            # racing on-path key could swap itself in. The pin on disk wins: the same key needs no
            # write, another key or key type is refused like any pinned host. Decided in
            # here, raised below, outside the best-effort except.
            pinned = fresh.lookup(lookup_name)
            if pinned is None:
                fresh.add(lookup_name, keytype, key)
                fresh.save(_KNOWN_HOSTS)
                recorded = True
            elif keytype not in pinned:
                refusal = _unpinned_type_refusal(paramiko, hostname, keytype)
            elif pinned[keytype] != key:
                refusal = paramiko.BadHostKeyException(hostname, key, pinned[keytype])
    except Exception:
        pass
    if refusal is not None:
        raise refusal
    if recorded:
        try:
            _log.info("TOFU: recorded new SSH host key for %s (%s) via transport", hostname, keytype)
        except Exception:
            pass
