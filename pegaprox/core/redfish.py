# -*- coding: utf-8 -*-
"""Out-of-band hardware health via the DMTF Redfish API (#609 phase 3).

The CREDENTIALED, OUT-OF-BAND counterpart to the in-band ipmitool reader
(pegaprox/core/bmc.py). Instead of SSHing to the node and talking to the local
BMC over KCS, this reaches the BMC's management interface over the network with
stored credentials and reads the standard Redfish resources. It is the fallback
when in-band ipmitool is unavailable (no ipmitool, ESXi/foreign nodes, etc.).

Because it crosses the data plane into the out-of-band management plane and uses
stored credentials, it is a SEPARATE, sharper opt-in (redfish_consent_warning in
bmc.py, enforced 5-second delay) and every configured endpoint is admin-gated.

SAFETY:
  * READ-ONLY — only HTTP GET on /Systems, /Chassis/*/Thermal, /Chassis/*/Power,
    and the SEL/event log. No power, virtual-media, BIOS or firmware actions.
  * SSRF-guarded — the admin-supplied BMC host is validated with the same
    is_safe_outbound_url guard used elsewhere (allow_private=True: BMCs live on
    private management LANs; cloud-metadata / loopback stay blocked). Redirects
    are refused so a hostile BMC can't bounce us onto an internal target.
  * Never raises into the caller — any failure returns {'available': False,
    'reason': ...} so it degrades exactly like the in-band reader.

Parsers are pure (Redfish JSON dict -> normalized dict) so they can be
fixture-tested without a BMC. The normalized output matches read_node_bmc_inband
exactly (available/health/sensors/chassis/power_w/fru/events) so callers can't
tell which source produced it.
"""

import json as _json
import logging
from urllib.parse import urljoin, urlparse

try:
    import requests
except Exception:  # pragma: no cover - requests is always present in prod
    requests = None

# Redfish resources are tiny; cap the body so a hostile/buggy BMC can't OOM the
# reader with a multi-GB or deeply-nested document (#609 phase 3 review).
_MAX_REDFISH_BYTES = 4 * 1024 * 1024   # 4 MiB


# Redfish Status.Health -> our sensor/health vocabulary
_RF_HEALTH = {'ok': 'ok', 'warning': 'warning', 'critical': 'critical'}


def _health(h):
    """Redfish Status.Health string -> ok / warning / critical / na."""
    return _RF_HEALTH.get(str(h or '').strip().lower(), 'na')


def _num(v):
    """Coerce a Redfish reading to float, or None."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_thermal(doc):
    """Redfish Thermal resource -> [temp/fan sensor dicts] (bmc.py sensor shape)."""
    out = []
    doc = doc or {}
    for t in (doc.get('Temperatures') or []):
        name = t.get('Name') or t.get('MemberId') or 'Temperature'
        val = _num(t.get('ReadingCelsius'))
        if val is None and t.get('Reading') is not None:
            val = _num(t.get('Reading'))
        out.append({
            'name': name, 'kind': 'temp', 'value': val, 'unit': '°C',
            'reading': (f"{val} degrees C" if val is not None else ''),
            'status': _health((t.get('Status') or {}).get('Health')),
        })
    for f in (doc.get('Fans') or []):
        name = f.get('Name') or f.get('FanName') or f.get('MemberId') or 'Fan'
        val = _num(f.get('Reading'))
        units = f.get('ReadingUnits') or 'RPM'
        out.append({
            'name': name, 'kind': 'fan', 'value': val, 'unit': ('RPM' if 'rpm' in str(units).lower() else units),
            'reading': (f"{val} {units}" if val is not None else ''),
            'status': _health((f.get('Status') or {}).get('Health')),
        })
    return out


def parse_power(doc):
    """Redfish Power resource -> ([volt/PSU sensor dicts], power_w float|None)."""
    out = []
    doc = doc or {}
    power_w = None
    for pc in (doc.get('PowerControl') or []):
        w = _num(pc.get('PowerConsumedWatts'))
        if w is not None:
            power_w = w if power_w is None else power_w + w
    for v in (doc.get('Voltages') or []):
        name = v.get('Name') or v.get('MemberId') or 'Voltage'
        val = _num(v.get('ReadingVolts'))
        out.append({
            'name': name, 'kind': 'volt', 'value': val, 'unit': 'V',
            'reading': (f"{val} Volts" if val is not None else ''),
            'status': _health((v.get('Status') or {}).get('Health')),
        })
    for ps in (doc.get('PowerSupplies') or []):
        name = ps.get('Name') or ps.get('MemberId') or 'Power Supply'
        st = ps.get('Status') or {}
        # a PSU is a discrete presence/health item; surface its output watts as the reading
        w = _num(ps.get('PowerOutputWatts')) or _num(ps.get('LastPowerOutputWatts'))
        out.append({
            'name': name, 'kind': 'power' if w is not None else 'discrete',
            'value': w, 'unit': ('W' if w is not None else ''),
            'reading': (f"{w} Watts" if w is not None else (st.get('State') or 'Present')),
            'status': _health(st.get('Health')),
        })
    return out, power_w


def parse_system(doc):
    """Redfish ComputerSystem resource -> (health_str, fru dict, chassis dict)."""
    doc = doc or {}
    st = doc.get('Status') or {}
    # HealthRollup covers subsystems; fall back to Health
    health = _health(st.get('HealthRollup') or st.get('Health'))
    fru = {
        'manufacturer': doc.get('Manufacturer') or '',
        'product': doc.get('Model') or '',
        'serial': doc.get('SerialNumber') or doc.get('SKU') or '',
        'part': doc.get('PartNumber') or '',
    }
    chassis = {'power': str(doc.get('PowerState') or '').lower() or ''}
    return health, fru, chassis


def parse_sel(members, limit=25):
    """Redfish LogEntry members -> [event dicts] (bmc.py event shape), newest first."""
    events = []
    for m in (members or []):
        sev_raw = str(m.get('Severity') or '').strip().lower()
        sev = 'critical' if sev_raw == 'critical' else 'warning' if sev_raw == 'warning' else 'info'
        events.append({
            'id': str(m.get('Id') or m.get('MemberId') or ''),
            'time': m.get('Created') or '',
            'sensor': m.get('SensorType') or m.get('EntryType') or '',
            'description': (m.get('Message') or '').strip(),
            'severity': sev,
        })
    # Redfish typically returns oldest->newest; show newest first, bounded.
    events.reverse()
    return events[:limit]


def _health_rollup(sensors, events, system_health, chassis):
    """Overall node hardware health: worst of system health, sensor/event status,
    and chassis intrusion (mirrors bmc._health_rollup + the Redfish system rollup)."""
    if system_health == 'critical' or \
       any(s['status'] == 'critical' for s in sensors) or \
       any(e['severity'] == 'critical' for e in events) or \
       (str(chassis.get('intrusion', '')).lower() not in ('', 'inactive', 'not present', 'disabled')):
        return 'critical'
    if system_health == 'warning' or \
       any(s['status'] == 'warning' for s in sensors) or \
       any(e['severity'] == 'warning' for e in events):
        return 'warning'
    return 'ok'


def parse_redfish(system_doc, thermal_doc, power_doc, sel_members):
    """Combine the fetched Redfish resources into the normalized hardware dict
    (same shape as bmc.parse_inband)."""
    health_sys, fru, chassis = parse_system(system_doc)
    sensors = parse_thermal(thermal_doc)
    p_sensors, power_w = parse_power(power_doc)
    sensors = sensors + p_sensors
    events = parse_sel(sel_members)
    if not (sensors or events or power_w is not None or any(fru.values()) or health_sys != 'na'):
        return {'available': False, 'reason': 'Redfish returned no usable data'}
    return {
        'available': True,
        'source': 'redfish',
        'health': _health_rollup(sensors, events, health_sys, chassis),
        'sensors': sensors,
        'chassis': chassis,
        'power_w': power_w,
        'fru': fru,
        'events': events,
    }


# --- HTTP orchestration -------------------------------------------------------

def _validate_host(host):
    """SSRF-validate a BMC host; returns (base_url, None) or (None, reason)."""
    host = (host or '').strip().rstrip('/')
    if not host or len(host) > 253:
        return None, 'missing or over-long BMC host'
    # allow the admin to pass a bare host or a full https URL
    base = host if host.startswith(('http://', 'https://')) else f'https://{host}'
    base = base.rstrip('/')
    try:
        from pegaprox.utils.url_security import is_safe_outbound_url
        ok, why = is_safe_outbound_url(base + '/redfish/v1/', allowed_schemes=('https', 'http'), allow_private=True)
    except Exception as e:  # guard module missing -> fail closed for a network cred call
        return None, f'SSRF guard unavailable: {e}'
    if not ok:
        return None, f'BMC host rejected by SSRF guard: {why}'
    return base, None


def read_node_bmc_redfish(host, user, password, verify_ssl=False, timeout=10):
    """Read out-of-band hardware health from a BMC over Redfish. Read-only,
    SSRF-guarded, basic-auth. Returns the normalized dict (see parse_redfish) or
    {'available': False, 'reason': ...}. Never raises."""
    if requests is None:
        return {'available': False, 'reason': 'requests unavailable'}
    base, why = _validate_host(host)
    if base is None:
        return {'available': False, 'reason': why}

    auth = (user or '', password or '')
    bu = urlparse(base)
    base_origin = (bu.scheme, bu.hostname, bu.port)

    # GET-only; refuse redirects; and CRITICALLY: pin every follow-on request to the
    # validated origin. A hostile BMC's @odata.id (system/chassis/thermal/power/log
    # paths are read from its OWN json) must not steer the credentialed GET off-host
    # via a userinfo/host splice (base + '@evil/...' -> 'https://base@evil/...'), an
    # absolute URL, or a protocol-relative '//evil'. We urljoin against the base and
    # assert the resolved scheme/host/port equals the validated base's.
    def _get(path):
        if not path or not isinstance(path, str):
            return None, 'empty Redfish reference'
        if '@' in path or '://' in path or path.startswith('//'):
            return None, 'off-origin Redfish reference rejected'
        joined = urljoin(base + '/', path)
        ju = urlparse(joined)
        if (ju.scheme, ju.hostname, ju.port) != base_origin:
            return None, 'off-origin Redfish reference rejected'
        r = None
        try:
            r = requests.get(joined, auth=auth, timeout=timeout, allow_redirects=False,
                             verify=bool(verify_ssl), stream=True,
                             headers={'Accept': 'application/json'})
            if r.status_code == 401:
                return None, 'auth failed (401)'
            if r.status_code >= 400:
                return None, f'HTTP {r.status_code}'
            clen = r.headers.get('Content-Length')
            if clen and str(clen).isdigit() and int(clen) > _MAX_REDFISH_BYTES:
                return None, 'Redfish response too large'
            buf = bytearray()
            for chunk in r.iter_content(8192):
                if not chunk:
                    continue
                buf.extend(chunk)
                if len(buf) > _MAX_REDFISH_BYTES:
                    return None, 'Redfish response too large'
            return _json.loads(buf.decode('utf-8', errors='replace')), None
        except Exception as e:  # noqa: BLE001 — surface as unavailable
            return None, str(e)[:120]
        finally:
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass

    # 1) discover a ComputerSystem
    systems, err = _get('/redfish/v1/Systems')
    if systems is None:
        return {'available': False, 'reason': f'Redfish unreachable: {err}'}
    members = systems.get('Members') or []
    if not members:
        return {'available': False, 'reason': 'no Redfish Systems found'}
    sys_path = (members[0] or {}).get('@odata.id')
    if not sys_path:
        return {'available': False, 'reason': 'malformed Redfish Systems collection'}
    system_doc, err = _get(sys_path)
    if system_doc is None:
        return {'available': False, 'reason': f'Redfish system read failed: {err}'}

    # 2) discover a Chassis for Thermal/Power (best-effort)
    thermal_doc = power_doc = None
    chassis_col, _ = _get('/redfish/v1/Chassis')
    cmembers = (chassis_col or {}).get('Members') or []
    if cmembers:
        chassis_path = (cmembers[0] or {}).get('@odata.id')
        if chassis_path:
            chassis_doc, _ = _get(chassis_path)
            cd = chassis_doc or {}
            tref = (cd.get('Thermal') or {}).get('@odata.id') or (chassis_path.rstrip('/') + '/Thermal')
            pref = (cd.get('Power') or {}).get('@odata.id') or (chassis_path.rstrip('/') + '/Power')
            thermal_doc, _ = _get(tref)
            power_doc, _ = _get(pref)

    # 3) event log (best-effort): first LogService's Entries
    sel_members = []
    logs_ref = (system_doc.get('LogServices') or {}).get('@odata.id')
    if logs_ref:
        logs, _ = _get(logs_ref)
        lmembers = (logs or {}).get('Members') or []
        if lmembers:
            first_log = (lmembers[0] or {}).get('@odata.id')
            if first_log:
                svc, _ = _get(first_log)
                entries_ref = ((svc or {}).get('Entries') or {}).get('@odata.id') or (first_log.rstrip('/') + '/Entries')
                entries, _ = _get(entries_ref)
                sel_members = (entries or {}).get('Members') or []

    return parse_redfish(system_doc, thermal_doc, power_doc, sel_members)


def read_node_hardware(mgr, cluster_id, node, inband_ok=True, redfish_ok=False, timeout=10):
    """Unified per-node hardware read: prefer in-band ipmitool, fall back to an
    out-of-band Redfish endpoint when in-band is unavailable AND the node has a
    configured BMC endpoint AND Redfish consent is on. Returns the normalized
    dict (tagged with source='inband'|'redfish'). Never raises.

    inband_ok / redfish_ok are the respective consent flags — the caller passes
    them so this function stays consent-aware without importing the api layer."""
    result = None
    if inband_ok:
        try:
            from pegaprox.core import bmc
            result = bmc.read_node_bmc_inband(mgr, node)
        except Exception:
            result = None
        if result and result.get('available') and 'source' not in result:
            result['source'] = 'inband'
    if (not result or not result.get('available')) and redfish_ok:
        ep = None
        try:
            from pegaprox.core.db import get_db
            ep = get_db().get_bmc_endpoint(cluster_id, node)
        except Exception:
            ep = None
        if ep and ep.get('enabled') and ep.get('host'):
            rf = read_node_bmc_redfish(ep['host'], ep.get('user'), ep.get('password'),
                                       ep.get('verify_ssl', False), timeout=timeout)
            if rf.get('available'):
                return rf
            # in-band gave nothing either → surface the redfish reason
            if not result or not result.get('available'):
                result = result or rf
    return result or {'available': False, 'reason': 'no hardware source available'}
