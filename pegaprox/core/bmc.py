# -*- coding: utf-8 -*-
"""In-band BMC / hardware health via local `ipmitool` (#609).

CREDENTIAL-FREE by design: instead of storing BMC network credentials and
reaching the BMC over its management network (the "crown-jewels" path — see the
Redfish opt-in phase), we SSH to the PVE node — access PegaProx already has for
lm-sensors / fencing — and run `ipmitool` LOCALLY there. The host talks to its
own BMC over the internal KCS interface (`/dev/ipmi0`) with no username/password
and without bridging the data network to the out-of-band management plane.

Read-only: only `sdr` / `sel` / `fru` / `dcmi` / `chassis status` are issued —
no power / virtual-media / firmware commands. Availability is opportunistic:
if `ipmitool` or `/dev/ipmi0` is absent we return `available=False` and change
nothing on the host (PegaProx never auto-enables the IPMI channel — the optional
install + the compliance acknowledgement are gated at the API layer).

Parsers are pure (text -> dict) so they can be fixture-tested without hardware.
"""

import re

# Markers so the whole read is ONE SSH round-trip; the orchestrator splits on them.
_M_SENS, _M_CHAS, _M_POWER, _M_FRU, _M_SEL = (
    '__PP_SENSORS__', '__PP_CHASSIS__', '__PP_POWER__', '__PP_FRU__', '__PP_SEL__')

# Single shell script run on the node. Bails early (no host mutation) when the
# in-band interface is missing, so we never touch a hardened box that removed it.
INBAND_PROBE_CMD = (
    "if ! command -v ipmitool >/dev/null 2>&1; then echo __PP_NO_IPMITOOL__; exit 0; fi; "
    "if ! ipmitool mc info >/dev/null 2>&1; then echo __PP_NO_BMC__; exit 0; fi; "
    "echo " + _M_SENS + "; ipmitool sdr elist 2>/dev/null; "
    "echo " + _M_CHAS + "; ipmitool chassis status 2>/dev/null; "
    "echo " + _M_POWER + "; ipmitool dcmi power reading 2>/dev/null; "
    "echo " + _M_FRU + "; ipmitool fru print 0 2>/dev/null; "
    "echo " + _M_SEL + "; ipmitool sel elist last 25 2>/dev/null"
)

# ipmitool sdr status tokens -> normalized health
_SDR_STATUS = {'ok': 'ok', 'ns': 'na', 'nc': 'warning', 'cr': 'critical', 'nr': 'critical'}

# --- In-band hardware-monitoring consent (#609) --------------------------------
# The feature must be explicitly enabled with a mandatory compliance acknowledgement
# before any read/install runs. The warning text lives HERE (single source) so the
# audit record can reference an exact version — bump the version when the wording
# materially changes and a stored ack below it re-prompts. (The network-Redfish
# opt-in is a separate, sharper warning with an enforced delay — a later phase.)
HW_CONSENT_VERSION = 1
HW_CONSENT_WARNING = {
    'version': HW_CONSENT_VERSION,
    'require_delay_seconds': 0,   # in-band: mandatory confirm, no forced wait (Redfish will use >0)
    'title': 'Enable in-band hardware monitoring (IPMI)',
    'summary': 'PegaProx will read hardware health directly on each node through its local IPMI interface.',
    'points': [
        'Reads happen on the node over its local IPMI channel (/dev/ipmi0) — no BMC network credentials are stored, and the out-of-band management network is not accessed.',
        'Only read-only IPMI commands are issued (sensors, event log, FRU inventory, power). No power, virtual-media or firmware operations.',
        'If you enable installation, PegaProx will install the "ipmitool" package and may load the IPMI kernel modules on the node.',
        'On strictly hardened systems the local IPMI interface may be intentionally disabled under a least-functionality baseline. Enabling this here does not override that — where the interface is absent, PegaProx reports no data rather than re-enabling it.',
    ],
    'compliance_note': 'Enabling this may be relevant to your least-functionality and BMC-hardening controls (e.g. CMMC / NIST 800-171 3.4.6 and 3.1.5, DISA STIG BMC/OOB guidance). Confirm with your compliance owner. This is not legal advice.',
    'confirm_label': 'I understand, and I accept responsibility for enabling this',
}


def _num(s):
    """First numeric token in a string as float, or None."""
    m = re.search(r'-?\d+(?:\.\d+)?', s or '')
    return float(m.group(0)) if m else None


def parse_sensors(text):
    """`ipmitool sdr elist` -> [{name, kind, value, unit, reading, status}].

    Line shape: ``Name | 01h | ok | 3.1 | 45 degrees C`` (pipe-separated, 5 cols).
    kind is derived from the reading unit (temp / fan / volt / power / other).
    """
    out = []
    for line in (text or '').splitlines():
        if '|' not in line:
            continue
        cols = [c.strip() for c in line.split('|')]
        if len(cols) < 5:
            continue
        name, status_tok, reading = cols[0], cols[2].lower(), cols[4]
        if not name:
            continue
        rl = reading.lower()
        if 'degrees c' in rl or rl.endswith(' c') or 'degree' in rl:
            kind, unit = 'temp', '°C'
        elif 'rpm' in rl:
            kind, unit = 'fan', 'RPM'
        elif 'volt' in rl:
            kind, unit = 'volt', 'V'
        elif 'watt' in rl:
            kind, unit = 'power', 'W'
        elif 'amp' in rl:
            kind, unit = 'current', 'A'
        else:
            kind, unit = 'discrete', ''
        out.append({
            'name': name,
            'kind': kind,
            'value': _num(reading) if kind not in ('discrete',) else None,
            'unit': unit,
            'reading': reading,
            'status': _SDR_STATUS.get(status_tok, status_tok or 'na'),
        })
    return out


def parse_chassis(text):
    """`ipmitool chassis status` -> {power, intrusion, fault, ...}."""
    d = {}
    for line in (text or '').splitlines():
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        k, v = k.strip().lower(), v.strip()
        if k == 'system power':
            d['power'] = v
        elif 'intrusion' in k:
            d['intrusion'] = v
        elif 'fault' in k and v:
            d.setdefault('faults', []).append(f"{k}: {v}")
    return d


def parse_power(text):
    """`ipmitool dcmi power reading` -> instantaneous watts (float) or None."""
    for line in (text or '').splitlines():
        if 'instantaneous power reading' in line.lower():
            return _num(line)
    return None


def parse_fru(text):
    """`ipmitool fru print 0` -> {manufacturer, product, serial, part, board_*}."""
    kv = {}
    for line in (text or '').splitlines():
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        kv[k.strip().lower()] = v.strip()
    g = lambda *keys: next((kv[k] for k in keys if kv.get(k)), '')
    return {
        'manufacturer': g('product manufacturer', 'board mfg', 'chassis manufacturer'),
        'product': g('product name', 'board product'),
        'serial': g('product serial', 'board serial', 'chassis serial'),
        'part': g('product part number', 'board part number'),
    }


def parse_sel(text, limit=25):
    """`ipmitool sel elist` -> recent hardware events (newest first).

    Line shape: ``12 | 07/14/2026 | 21:30:05 | Power Supply PSU2 | Failure detected | Asserted``
    """
    events = []
    for line in (text or '').splitlines():
        if '|' not in line:
            continue
        cols = [c.strip() for c in line.split('|')]
        if len(cols) < 4:
            continue
        # cols: id, date, time, sensor, [description], [state]
        ts = (cols[1] + ' ' + cols[2]).strip() if len(cols) >= 3 else ''
        sensor = cols[3] if len(cols) > 3 else ''
        desc = cols[4] if len(cols) > 4 else ''
        state = cols[5] if len(cols) > 5 else ''
        low = (desc + ' ' + state + ' ' + sensor).lower()
        sev = 'critical' if any(w in low for w in ('fail', 'critical', 'fault', 'error', 'lost')) \
            else 'warning' if any(w in low for w in ('warn', 'non-critical', 'degrad', 'intrusion')) \
            else 'info'
        events.append({'id': cols[0], 'time': ts, 'sensor': sensor,
                       'description': (desc + (' — ' + state if state else '')).strip(' —'),
                       'severity': sev})
    events.reverse()  # newest first
    return events[:limit]


def _health_rollup(sensors, sel, chassis):
    """Overall node hardware health from the parsed pieces: ok / warning / critical."""
    if any(s['status'] == 'critical' for s in sensors) or \
       any(e['severity'] == 'critical' for e in sel) or \
       (chassis.get('intrusion', '').lower() not in ('', 'inactive', 'not present', 'disabled')):
        return 'critical'
    if any(s['status'] == 'warning' for s in sensors) or \
       any(e['severity'] == 'warning' for e in sel):
        return 'warning'
    return 'ok'


def parse_inband(raw):
    """Split the marker-delimited SSH output and parse every section.

    Returns {'available': bool, 'reason'?: str, 'health', 'sensors', 'chassis',
    'power_w', 'fru', 'events'}.
    """
    raw = raw or ''
    if '__PP_NO_IPMITOOL__' in raw:
        return {'available': False, 'reason': 'ipmitool is not installed on this node'}
    if '__PP_NO_BMC__' in raw:
        return {'available': False, 'reason': 'no in-band BMC / IPMI interface (/dev/ipmi0) on this node'}

    def section(marker, nxt):
        try:
            body = raw.split(marker, 1)[1]
        except IndexError:
            return ''
        for m in nxt:
            if m in body:
                body = body.split(m, 1)[0]
        return body

    sensors = parse_sensors(section(_M_SENS, [_M_CHAS, _M_POWER, _M_FRU, _M_SEL]))
    chassis = parse_chassis(section(_M_CHAS, [_M_POWER, _M_FRU, _M_SEL]))
    power_w = parse_power(section(_M_POWER, [_M_FRU, _M_SEL]))
    fru = parse_fru(section(_M_FRU, [_M_SEL]))
    events = parse_sel(section(_M_SEL, []))
    if not (sensors or chassis or events or power_w is not None or any(fru.values())):
        return {'available': False, 'reason': 'in-band BMC returned no data'}
    return {
        'available': True,
        'health': _health_rollup(sensors, sel=events, chassis=chassis),
        'sensors': sensors,
        'chassis': chassis,
        'power_w': power_w,
        'fru': fru,
        'events': events,
    }


def read_node_bmc_inband(mgr, node, timeout=15):
    """Orchestrator: SSH to `node`, run the read-only ipmitool probe, parse it.

    Credential-free (in-band). Returns the parse_inband() dict, or an
    {'available': False, 'reason': ...} on any SSH/resolution failure. Never
    mutates the node. The compliance acknowledgement + optional install are
    enforced by the caller (API layer), not here.
    """
    try:
        ip = mgr._get_node_ip(node)
        if not ip:
            return {'available': False, 'reason': f'no SSH-reachable IP for node {node}'}
        user = getattr(mgr.config, 'ssh_user', None) or 'root'
        raw = mgr._ssh_run_command_output(ip, user, INBAND_PROBE_CMD, timeout=timeout)
        if raw is None or not raw.strip():
            return {'available': False, 'reason': 'no response from node (SSH unavailable?)'}
        return parse_inband(raw)
    except Exception as e:  # noqa: BLE001 — surface as unavailable, never raise into the route
        return {'available': False, 'reason': f'in-band BMC read failed: {e}'}
