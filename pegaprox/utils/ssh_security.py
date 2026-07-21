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


def cli_hostkey_opts():
    """Host-key options for subprocess ``ssh``/``scp``/``sshfs`` commands.

    Returns ``(strict_value, known_hosts_path)`` to replace the insecure
    ``StrictHostKeyChecking=no`` + ``UserKnownHostsFile=/dev/null`` combo:
    * ``accept-new`` accepts a brand-new host but REJECTS a changed key (MitM),
      upgraded to ``yes`` (reject unknown too) under strict mode;
    * pinned to the SAME known_hosts file the paramiko paths use, so a key learned
      by one path is verified by the other.
    """
    hkc = 'yes' if strict_host_keys_enabled() else 'accept-new'
    return hkc, _KNOWN_HOSTS


def _make_policy(paramiko):
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
    try:
        if os.path.exists(_KNOWN_HOSTS):
            client.load_host_keys(_KNOWN_HOSTS)
    except Exception:
        pass
    client.set_missing_host_key_policy(_make_policy(paramiko))
    return client


def secure_ssh_client(paramiko):
    """Return a fresh ``paramiko.SSHClient`` with known_hosts loaded + policy set."""
    client = paramiko.SSHClient()
    return apply_host_key_policy(client, paramiko)


def persist_host_keys(client):
    """Persist any newly-learned host keys so the next connection verifies against
    them. Best-effort: the config dir may be read-only. Serialized to avoid two
    greenlets clobbering the file."""
    try:
        with _persist_lock:
            client.save_host_keys(_KNOWN_HOSTS)
    except Exception:
        pass  # config dir might not be writable — non-fatal


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
                hosts_in_line = [h.replace('[', '').split(']')[0].split(':')[0]
                                 for h in first.split(',')]
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


def verify_transport_host_key(transport, hostname, paramiko):
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
    * unknown host, strict on  -> raise SSHException
    """
    try:
        key = transport.get_remote_server_key()
    except Exception:
        return  # no key available — nothing to verify against
    keytype = key.get_name()
    hostkeys = paramiko.hostkeys.HostKeys()
    try:
        if os.path.exists(_KNOWN_HOSTS):
            hostkeys.load(_KNOWN_HOSTS)
    except Exception:
        pass
    entry = hostkeys.lookup(hostname)
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
        raise paramiko.SSHException(
            f"host {hostname} is known but presented an unpinned key type "
            f"({keytype}) — refusing (possible downgrade/MitM). Remove its "
            "config/.ssh_known_hosts entry to re-pin.")
    # genuinely unknown host — first time we see it at all
    if strict_host_keys_enabled():
        raise paramiko.SSHException(
            "strict host-key checking: unknown SSH host key for "
            f"{hostname} ({keytype}); seed config/.ssh_known_hosts first")
    hostkeys.add(hostname, keytype, key)
    try:
        with _persist_lock:
            hostkeys.save(_KNOWN_HOSTS)
    except Exception:
        pass
    try:
        _log.info("TOFU: recorded new SSH host key for %s (%s) via transport", hostname, keytype)
    except Exception:
        pass
