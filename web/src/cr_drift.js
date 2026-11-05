        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned: config drift - LW Oct 2026
        // DriftTab mounts this and keeps the policy switch (savePolicy). The page reads the
        // three drift routes itself, so every read has a state of its own: a refused, missing,
        // offline or failed read says so and is never drawn as "no findings". Counts are the
        // open findings the server keeps; nothing here scores them. The server writes its times
        // as naive server-local strings: they are printed as server time, no age is worked out.
        // Writes go to the same routes with the same bodies and confirmations as classic.
        // ═══════════════════════════════════════════════════════════

        const CR_DRIFT_LIMIT = 500;   // the most GET .../drift/events hands out, newest first
        const CR_DRIFT_SEV = ['critical', 'warning', 'info'];
        const CR_DRIFT_SEV_TONE = { critical: 'error', warning: 'warning', info: 'info' };
        const CR_DRIFT_ICON = { vm_config: 'Monitor', storage: 'HardDrive', network: 'Network', cluster_options: 'Settings',
                                firewall: 'Shield', ha_rules: 'Activity', backup_jobs: 'Archive', access: 'Users' };
        // stored as a digest by the server (drift.py _SECRET_KEYS); a row from before that may still hold the value
        const CR_DRIFT_SECRET = new Set(['cipassword', 'password', 'smbpassword', 'keyring', 'encryption-key']);
        const crDriftRedacted = (v) => typeof v === 'string' && /^<redacted:[0-9a-f]+>$/.test(v);
        // the keys whose unit Proxmox fixes (MiB) and its 0/1 switches; every other value stays as stored
        const CR_DRIFT_MIB = new Set(['memory', 'balloon', 'swap']);
        const CR_DRIFT_FLAG = new Set(['enable', 'enabled', 'onboot', 'protection', 'template', 'acpi', 'kvm', 'numa', 'tablet',
                                       'shared', 'disable', 'unprivileged', 'nofailback', 'restricted']);
        const crHasKey = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k);
        const crIsDict = (v) => v != null && typeof v === 'object' && !Array.isArray(v);

        function crDriftTime(s) {
            return s && typeof s === 'string' ? s.replace('T', ' ').slice(0, 16) : '';
        }

        // one GET with what came of it: ok, away (#625), forbidden, notfound, limited, error, offline
        async function crDriftRead(authFetch, url) {
            const r = await authFetch(url);
            if (!r) return { state: 'offline' };
            if (await haLeaderAway(r)) return { state: 'away' };
            const body = await r.json().catch(() => null);
            if (r.ok && body && typeof body === 'object' && !body.error) return { state: 'ok', body };
            const msg = body && typeof body.error === 'string' ? body.error : '';
            const state = r.status === 403 ? 'forbidden' : r.status === 404 ? 'notfound' : r.status === 429 ? 'limited' : 'error';
            return { state, code: r.status, msg };
        }

        function crDriftReadText(read, t) {
            if (!read) return '';
            if (read.state === 'offline') return t('crDriftOffline');
            if (read.state === 'limited') return t('crDriftLimited');
            const code = read.code ? `HTTP ${read.code}` : '';
            return [read.msg, code].filter(Boolean).join(' - ') || t('crLoadFailed');
        }

        // the whole object a removed or presence-unknown row is about
        function crDriftWhole(ev) {
            const d = Array.isArray(ev && ev.diff) ? ev.diff : [];
            const w = d.find(x => x && x.path === '*');
            return w && (w.op === 'removed' || w.op === 'unknown') ? w : null;
        }

        // What a finding is about, and where it leads when that is in the inventory this user sees.
        // vm_config and guest firewalls are guests, network and node firewalls nodes, storage a
        // storage; everything else is the whole cluster.
        // where a cluster-wide finding is handled: the Datacenter section of its kind (access has none)
        const CR_DRIFT_DC = { cluster_options: ['options', 'options'], ha_rules: ['ha', 'proxmoxNativeHa'], backup_jobs: ['backup', 'backup'],
                              firewall: ['firewall', 'firewall'] };
        function crDriftDc(kind, cid, t) {
            const dc = CR_DRIFT_DC[kind];
            if (!dc) return {};
            return { go: (nav) => { if (nav.openDatacenter) nav.openDatacenter(cid, dc[0]); }, note: crFill(t('crDriftInDatacenter'), { section: t(dc[1]) }) };
        }

        function crDriftTarget(ev, cid, inv, t) {
            const scope = String(ev.scope || '');
            const read = inv.read || { guests: true, nodes: true };
            const guest = (type, id) => {
                const map = crGuestMap(inv.guests);
                const g = map && map.get(String(id));
                const word = type === 'lxc' ? 'CT' : 'VM';
                if (g) return { what: 'guest', label: g.name ? `${g.name} (${id})` : `${word} ${id}`, go: (nav) => nav.openGuest(cid, g) };
                return { what: 'guest', label: `${word} ${id}`, note: t(read.guests ? 'crDriftNotInInventory' : 'crInvNotLoaded') };
            };
            const node = (name, label) => {
                const known = !!(inv.nodes && crHasKey(inv.nodes, name));
                return { what: 'node', label: label || name, go: known ? (nav) => nav.openNode(cid, name) : null,
                         note: known ? '' : t(read.nodes ? 'crDriftNotInInventory' : 'crInvNotLoaded') };
            };
            if (scope.startsWith('policy:')) {
                const id = scope.slice(7);
                return { what: 'policy', label: crTOr(t, 'driftCheck_' + id, id), cluster: true, ...crDriftDc(ev.kind, cid, t) };
            }
            if (ev.kind === 'vm_config') {
                const m = scope.match(/^(qemu|lxc)\/(\d+)$/);
                if (m) return guest(m[1], m[2]);
            }
            if (ev.kind === 'firewall') {
                const g = scope.match(/^guest\/(qemu|lxc)\/(\d+)$/);
                if (g) return guest(g[1], g[2]);
                const n = scope.match(/^node\/(.+)$/);
                if (n) return node(n[1]);
            }
            if (ev.kind === 'network' && scope.includes('/')) {
                const at = scope.indexOf('/');
                const name = scope.slice(0, at);
                return node(name, `${scope.slice(at + 1)} (${name})`);
            }
            if (ev.kind === 'storage' && scope) {
                const stores = inv.stores;
                let hit = null;
                if (stores) {
                    const shared = (stores.shared || []).find(s => s && s.storage === scope);
                    if (shared) hit = { store: shared, node: null };
                    else {
                        for (const n of Object.keys(stores.local || {}).sort()) {
                            const s = (stores.local[n] || []).find(x => x && x.storage === scope);
                            if (s) { hit = { store: s, node: n }; break; }
                        }
                    }
                }
                return { what: 'storage', label: scope, go: hit ? (nav) => nav.openStorage(cid, hit.store, hit.node) : null,
                         note: hit && hit.node ? crFill(t('crDriftStorageOn'), { node: hit.node }) : '' };
            }
            const dc = crDriftDc(ev.kind, cid, t);
            return { what: 'cluster', label: scope || '-', cluster: true, note: dc.note || t('crDriftWholeCluster'), go: dc.go || null };
        }

        // a violation as the server writes it (English) for the four checks it has, in the user's
        // language; a text of a check this page does not know stays as the server sent it
        function crDriftViol(check, detail, t) {
            const d = typeof detail === 'string' ? detail : detail == null ? '' : JSON.stringify(detail);
            if (check === 'access_admin_role') {
                const m = d.match(/^Administrator on (.+)$/);
                if (m) return crFill(t('crDriftViolAdmin'), { path: m[1] });
            }
            const fixed = { access_token_expiry: ['token never expires', 'crDriftViolToken'],
                            firewall_cluster_enabled: ['the cluster firewall is off', 'crDriftViolFirewall'],
                            backup_none_disabled: ['backup job is disabled', 'crDriftViolBackup'] }[check];
            return fixed && d === fixed[0] ? t(fixed[1]) : d;
        }

        function crDriftChange(ev, t) {
            const d = ev && ev.diff;
            if (!Array.isArray(d)) return d ? t('crDriftDiffUnreadable') : '';
            const whole = crDriftWhole(ev);
            if (whole && whole.op === 'unknown') return crFill(t('crDriftPresenceUnknown'), { node: whole['node-offline'] || '?' });
            if (whole) return t('crDriftObjectRemoved');
            if (d.length && d.every(x => x && x.op === 'violation')) return crFill(t('crDriftOffenders'), { n: d.length });
            const names = d.map(x => x && x.path).filter(Boolean);
            return names.length > 3 ? `${names.slice(0, 3).join(', ')} +${names.length - 3}` : names.join(', ');
        }

        // The rows of the comparison, as the finding stores them: the changed top-level keys only.
        // A nested object (a firewall rule, a user, a backup job) gets one row per field that
        // differs; a whole object that is gone or not verified lists its baseline fields.
        function crDriftRows(diff) {
            const out = [];
            (Array.isArray(diff) ? diff : []).forEach((d, i) => {
                if (!d || typeof d !== 'object') return;
                const op = d.op;
                if (d.path === '*' && (op === 'removed' || op === 'unknown')) {
                    if (crIsDict(d.before)) {
                        Object.keys(d.before).forEach(k => out.push({ key: `${i}:${k}`, path: k, op, before: d.before[k], hasBefore: true, hasAfter: false }));
                    } else {
                        out.push({ key: `${i}`, path: '*', op, before: d.before, hasBefore: d.before != null, hasAfter: false });
                    }
                    return;
                }
                if (op === 'changed' && crIsDict(d.before) && crIsDict(d.after)) {
                    const keys = Array.from(new Set([...Object.keys(d.before), ...Object.keys(d.after)]));
                    let same = 0;
                    keys.forEach(k => {
                        const inB = crHasKey(d.before, k), inA = crHasKey(d.after, k);
                        if (inB && inA && JSON.stringify(d.before[k]) === JSON.stringify(d.after[k])) { same++; return; }
                        out.push({ key: `${i}:${k}`, path: d.path, sub: k, op: inB && inA ? 'changed' : inA ? 'added' : 'removed',
                                   before: d.before[k], after: d.after[k], hasBefore: inB, hasAfter: inA });
                    });
                    if (same) out.push({ key: `${i}:same`, path: d.path, op: 'same', same });
                    return;
                }
                out.push({ key: `${i}`, path: d.path, op, before: d.before, after: d.after,
                           hasBefore: op === 'changed' || op === 'removed',
                           hasAfter: op === 'changed' || op === 'added' || op === 'violation' });
            });
            return out;
        }

        // 'virtio=BC:24:11:..,bridge=vmbr0,tag=10': the parts that differ, so a long option string
        // says where it changed. Only when both sides are such strings
        function crDriftParts(a, b) {
            if (typeof a !== 'string' || typeof b !== 'string' || !a.includes('=') || !b.includes('=')) return null;
            const parse = (s) => {
                const m = new Map();
                s.split(',').forEach((p, i) => {
                    const at = p.indexOf('=');
                    if (at > 0) m.set(p.slice(0, at), p.slice(at + 1)); else m.set(`#${i}`, p);
                });
                return m;
            };
            const x = parse(a), y = parse(b);
            const out = [];
            new Set([...x.keys(), ...y.keys()]).forEach(k => {
                if (x.get(k) !== y.get(k)) out.push({ k, from: x.has(k) ? x.get(k) : null, to: y.has(k) ? y.get(k) : null });
            });
            return out.length ? out : null;
        }

        function CrDriftVal({ name, v, t }) {
            if (CR_DRIFT_SECRET.has(name) || crDriftRedacted(v)) {
                return <span className="cr-drift-hidden" title={t('crDriftHiddenHint')}>{t('crDriftHidden')}</span>;
            }
            if (v === null || v === undefined || v === '') return <span className="cr-drift-absent">{t('crDriftEmpty')}</span>;
            if (typeof v === 'object') return <pre className="cr-drift-pre">{JSON.stringify(v, null, 2)}</pre>;
            const s = String(v);
            if (CR_DRIFT_MIB.has(name) && /^\d+$/.test(s)) {
                const n = Number(s);
                return n >= 1024
                    ? <span className="cr-drift-text">{`${+(n / 1024).toFixed(2)} GiB`} <span className="cr-drift-raw">({s} MiB)</span></span>
                    : <span className="cr-drift-text">{`${s} MiB`}</span>;
            }
            if (CR_DRIFT_FLAG.has(name) && (s === '0' || s === '1')) {
                return <span className="cr-drift-text">{s === '1' ? t('crDriftOn') : t('crDriftOff')} <span className="cr-drift-raw">({s})</span></span>;
            }
            return <span className="cr-drift-text">{s}</span>;
        }

        const CR_DRIFT_OP = { changed: ['crDriftOpChanged', 'warning'], added: ['crDriftOpAdded', 'success'], removed: ['crDriftOpRemoved', 'error'],
                              unknown: ['crDriftOpUnknown', 'neutral'], violation: ['crDriftOpViolation', 'error'] };

        function CrDriftCompare({ ev, t }) {
            const rows = useMemo(() => crDriftRows(ev.diff), [ev]);
            const check = String(ev.scope || '').startsWith('policy:') ? String(ev.scope).slice(7) : '';
            const whole = crDriftWhole(ev);
            if (!Array.isArray(ev.diff)) {
                return <p className="cr-drift-note" data-cr-drift-cmp="unreadable">{t('crDriftDiffUnreadable')}</p>;
            }
            if (!rows.length) return <p className="cr-drift-note" data-cr-drift-cmp="empty">{t('crDriftNoDiff')}</p>;
            const noBase = ev.category === 'policy_violation' || rows.every(r => r.op === 'violation');
            const absentBefore = noBase ? t('crDriftNoBaselineRule') : t('crDriftNotInBaseline');
            const absentAfter = whole && whole.op === 'unknown' ? t('crDriftNotVerified') : t('crDriftNotPresent');
            return (
                <table className="cr-drift-cmp" data-cr-drift-cmp={whole ? whole.op : 'diff'}>
                    <thead>
                        <tr>
                            <th scope="col">{t('property')}</th>
                            <th scope="col">{t('crDriftBaseline')}</th>
                            <th scope="col">{t('crDriftAtDetection')}</th>
                            <th scope="col">{t('crDriftColChange')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map(r => {
                            if (r.op === 'same') {
                                return (
                                    <tr key={r.key} className="cr-drift-op-same">
                                        <td colSpan={4} className="cr-drift-note">{crFill(t('crDriftSameFields'), { n: r.same, path: r.path })}</td>
                                    </tr>
                                );
                            }
                            const name = r.sub || r.path;
                            const secret = CR_DRIFT_SECRET.has(name) || crDriftRedacted(r.before) || crDriftRedacted(r.after);
                            const parts = !secret && r.op === 'changed' ? crDriftParts(r.before, r.after) : null;
                            const [lk, tone] = CR_DRIFT_OP[r.op] || ['crDriftOpChanged', 'neutral'];
                            return (
                                <tr key={r.key} className={`cr-drift-op-${r.op}`} data-cr-drift-prop={name} data-cr-drift-op={r.op}>
                                    <th scope="row" className="cr-drift-prop">
                                        {r.sub ? <><span className="cr-drift-parent">{r.path}</span> {r.sub}</> : (r.path === '*' ? t('crDriftWholeObject') : r.path)}
                                    </th>
                                    <td className="cr-drift-before">
                                        {r.hasBefore ? <CrDriftVal name={name} v={r.before} t={t} /> : <span className="cr-drift-absent">{absentBefore}</span>}
                                    </td>
                                    <td className="cr-drift-after">
                                        {r.hasAfter
                                            ? (secret && r.op === 'changed'
                                                ? <span className="cr-drift-hidden" title={t('crDriftHiddenHint')}>{t('crDriftHiddenChanged')}</span>
                                                : <CrDriftVal name={name} v={r.op === 'violation' && check ? crDriftViol(check, r.after, t) : r.after} t={t} />)
                                            : <span className="cr-drift-absent">{absentAfter}</span>}
                                        {parts && (
                                            <span className="cr-drift-parts" data-cr-drift-parts="">
                                                {parts.map(p => (
                                                    <span key={p.k}>{p.k.startsWith('#') ? '' : `${p.k}: `}{p.from == null ? '-' : p.from} {'→'} {p.to == null ? '-' : p.to}</span>
                                                ))}
                                            </span>
                                        )}
                                    </td>
                                    <td><CrBadge tone={tone} dot={false}>{t(lk)}</CrBadge></td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            );
        }

        // critical, warning and info of one category as one bar; the parts are the counts
        function CrDriftSevBar({ n, label }) {
            const all = n.critical + n.warning + n.info;
            const w = (x) => (all ? `${(x * 100 / all).toFixed(2)}%` : '0%');
            return (
                <span className="cr-drift-sevbar" role="img" aria-label={label}>
                    <span className="cr-drift-sev-critical" style={{ width: w(n.critical) }} />
                    <span className="cr-drift-sev-warning" style={{ width: w(n.warning) }} />
                    <span className="cr-drift-sev-info" style={{ width: w(n.info) }} />
                </span>
            );
        }

        // What the last completed scan could read of a kind and the colour its card takes: grey
        // for anything that was not compared, green only for a kind read in full with no open finding
        function crDriftKind(status, kind) {
            const scanned = !!(status && status.last_scan_at);
            const read = !status ? 'unread' : !scanned ? 'noscan' : ((status.kinds || {})[kind] || 'absent');
            const c = (status && status.by_kind && status.by_kind[kind]) || {};
            const n = { critical: c.critical || 0, warning: c.warning || 0, info: c.info || 0 };
            const total = n.critical + n.warning + n.info;
            const compared = read === 'checked' || read === 'partial';
            const tone = !compared ? 'neutral' : n.critical ? 'error' : n.warning ? 'warning' : n.info ? 'info'
                : read === 'checked' ? 'success' : 'neutral';
            return { read, n, total, tone, cover: (status && status.coverage && status.coverage[kind]) || null };
        }

        function CrDriftKindCard({ kind, s, active, label, onPick, t }) {
            const Ico = Icons[CR_DRIFT_ICON[kind]] || Icons.Shield;
            const readText = { checked: t('crDriftReadChecked'), partial: t('driftPartlyChecked'), no_baseline: t('driftNoBaselineYet'),
                               not_checked: t('driftNotChecked'), absent: t('crDriftReadAbsent'), noscan: t('crDriftNoScanYet'),
                               unread: t('crDriftReadUnknown') }[s.read] || s.read;
            const state = s.tone === 'success' ? t('crDriftNoOpen') : null;
            const sevText = crFill(t('crDriftSevCounts'), { critical: s.n.critical, warning: s.n.warning, info: s.n.info });
            const cover = s.cover ? crFill(t('crDriftBaselinedOf'), { m: s.cover.baselined, n: s.cover.scopes })
                : s.read === 'checked' ? t('crDriftNoObjects') : '';
            return (
                <button type="button" className={`cr-drift-card cr-drift-tone-${s.tone}${active ? ' active' : ''}`} aria-pressed={active}
                    onClick={onPick} data-cr-drift-kind={kind} data-cr-drift-read={s.read} data-cr-drift-tone={s.tone}
                    title={kind === 'firewall' ? t('crDriftFirewallHint') : undefined}>
                    <span className="cr-drift-card-head">
                        <span className="cr-ico" aria-hidden="true"><Ico /></span>
                        <span className="cr-drift-card-name">{label}</span>
                        <span className={`cr-drift-read cr-drift-read-${s.read}`}>{readText}</span>
                    </span>
                    <span className="cr-drift-card-main">
                        <span className="cr-drift-card-n" data-cr-drift-total={s.total}>{s.total}</span>
                        <span className="cr-drift-card-of">{t('crDriftOpenWord')}</span>
                        {state && <span className="cr-drift-card-state">{state}</span>}
                    </span>
                    <CrDriftSevBar n={s.n} label={sevText} />
                    <span className="cr-drift-card-counts">
                        <span className={s.n.critical ? 'cr-drift-c-critical' : ''}>{crFill(t('crDriftNCritical'), { n: s.n.critical })}</span>
                        <span className={s.n.warning ? 'cr-drift-c-warning' : ''}>{crFill(t('crDriftNWarning'), { n: s.n.warning })}</span>
                        <span className={s.n.info ? 'cr-drift-c-info' : ''}>{crFill(t('crDriftNInfo'), { n: s.n.info })}</span>
                    </span>
                    <span className="cr-drift-card-cap">{cover || ' '}</span>
                </button>
            );
        }

        function crPolicyResult(c, t) {
            if (c.status === 'pass') return { key: 'pass', tone: 'success', label: t('driftPolicyPass'), evaluated: true };
            if (c.status === 'fail') {
                return c.severity === 'critical'
                    ? { key: 'fail', tone: 'error', label: t('crDriftResultFailed'), evaluated: true }
                    : { key: 'warning', tone: 'warning', label: t('crDriftResultWarning'), evaluated: true };
            }
            if (c.status === 'disabled') return { key: 'off', tone: 'neutral', label: t('driftPolicyDisabled'), evaluated: false };
            // not_checked, and whatever a later server says: never a pass
            return { key: 'not_evaluated', tone: 'neutral', label: t('crDriftNotEvaluated'), evaluated: false };
        }

        function CrDriftState({ kind, read, t, onRetry }) {
            const text = { away: t('pgHaLeaderAwayView'), forbidden: t('crDriftForbidden'), notfound: t('crDriftNotFound') }[kind] || t('crDriftReadFailed');
            const hint = kind === 'forbidden' ? t('crDriftForbiddenHint') : kind === 'error' ? crDriftReadText(read, t) : '';
            const server = kind === 'forbidden' && read && read.msg ? read.msg : '';
            return (
                <div className={`cr-callout cr-callout-${kind === 'away' ? 'info' : kind === 'error' ? 'error' : 'warning'}`} role={kind === 'error' ? 'alert' : 'status'}
                    data-cr-drift-state={kind}>
                    {kind === 'error' ? <Icons.AlertCircle className="w-4 h-4" /> : kind === 'away' ? <Icons.Info className="w-4 h-4" /> : <Icons.Lock className="w-4 h-4" />}
                    <div>
                        <p className="cr-strong">{text}</p>
                        {hint && <p>{hint}</p>}
                        {server && <p className="cr-muted">{server}</p>}
                    </div>
                    {onRetry && <button type="button" className="cr-btn cr-drift-retry" onClick={onRetry}>{t('retry')}</button>}
                </div>
            );
        }

        function CrDriftActs({ ev, can, busy, onAck, onIncident, compact, t }) {
            const whole = crDriftWhole(ev);
            const ackable = ev.status === 'open' && can.ack && (ev.category !== 'policy_violation' || can.config);
            const promotable = ev.status === 'open' && can.baseline && ev.category !== 'policy_violation' && ev.category !== 'incident';
            const promoteWhy = whole ? t(whole.op === 'unknown' ? 'crDriftPromoteUnknown' : 'crDriftPromoteRemoved') : '';
            const pending = !!(busy[`ack:${ev.id}`] || busy[`inc:${ev.id}`]);
            const stop = (fn) => (e) => { e.stopPropagation(); fn(); };
            const cls = compact ? 'cr-btn cr-btn-xs' : 'cr-btn';
            return (
                <span className="cr-drift-acts">
                    {ackable && (
                        <button type="button" className={cls} disabled={pending} onClick={stop(() => onAck(ev, false))} data-cr-drift-ack={ev.id}>
                            {compact ? t('driftAck') : t('crDriftAcknowledge')}
                        </button>
                    )}
                    {promotable && (
                        <button type="button" className={cls} disabled={pending || !!whole} title={promoteWhy || t('crDriftPromoteHint')}
                            onClick={stop(() => onAck(ev, true))} data-cr-drift-promote={ev.id}>
                            {compact ? t('driftPromote') : t('crDriftPromoteLong')}
                        </button>
                    )}
                    {can.incident && ev.category !== 'incident' && (
                        <button type="button" className={`${cls} cr-btn-danger`} disabled={pending} onClick={stop(() => onIncident(ev, true))}
                            data-cr-drift-incident={ev.id} title={t('driftConfirmIncident')} aria-label={compact ? t('driftConfirmIncident') : undefined}>
                            {compact ? <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span> : t('driftConfirmIncident')}
                        </button>
                    )}
                    {can.incident && ev.category === 'incident' && (
                        <button type="button" className={cls} disabled={pending} onClick={stop(() => onIncident(ev, false))}
                            data-cr-drift-withdraw={ev.id} title={t('driftWithdrawIncident')}>
                            {compact ? t('crDriftWithdrawShort') : t('driftWithdrawIncident')}
                        </button>
                    )}
                    {pending && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                </span>
            );
        }

        const crDriftStatusTone = (s) => ({ open: 'warning', acknowledged: 'neutral', resolved: 'success', superseded: 'neutral' })[s] || 'neutral';

        function CrDriftDetail({ ev, target, can, busy, msg, onAck, onIncident, onGo, kindLabel, catLabel, statusLabel, t }) {
            const whole = crDriftWhole(ev);
            const sevTone = CR_DRIFT_SEV_TONE[ev.severity] || 'neutral';
            const cat = ev.category || 'deviation';
            const row = (k, label, value) => (
                <div className="cr-drift-meta-row" data-cr-drift-meta={k}>
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                </div>
            );
            return (
                <div className="cr-drift-detail" data-cr-drift-detail={ev.id}>
                    <dl className="cr-drift-meta">
                        {row('resource', t('crDriftColResource'), (
                            <>
                                {target.go ? <button type="button" className="cr-link" onClick={onGo} data-cr-drift-go={target.what}>{target.label}</button>
                                    : <span>{target.label}</span>}
                                {target.label !== ev.scope && <span className="cr-muted cr-mono"> {ev.scope}</span>}
                                {target.note && <span className="cr-muted"> ({target.note})</span>}
                            </>
                        ))}
                        {row('kind', t('crDriftColKind'), kindLabel(ev.kind))}
                        {row('severity', t('severity'), <CrBadge tone={sevTone}>{t(ev.severity) || ev.severity}</CrBadge>)}
                        {row('type', t('crDriftColType'), <CrBadge tone={cat === 'incident' ? 'error' : 'neutral'} dot={false}>{catLabel(cat)}</CrBadge>)}
                        {row('status', t('status'), (
                            <>
                                <CrBadge tone={crDriftStatusTone(ev.status)}>{statusLabel(ev.status)}</CrBadge>
                                {ev.change_id && <> <CrBadge tone="success" dot={false} title={ev.change_title}>{chgFill(t, 'driftPlanned', { title: ev.change_title || '' })}</CrBadge></>}
                            </>
                        ))}
                        {row('detected', t('crDriftColDetected'), <span title={ev.detected_at}>{crDriftTime(ev.detected_at)} <span className="cr-muted">({t('crDriftServerTime')})</span></span>)}
                        {row('ack', t('crDriftAckState'), ev.acknowledged_at
                            ? `${ev.acknowledged_by || '?'} - ${crDriftTime(ev.acknowledged_at)}`
                            : <span className="cr-muted">{t('crDriftNotAcked')}</span>)}
                        {row('incident', t('driftCatIncident'), cat === 'incident'
                            ? `${t('driftConfirmedBy')} ${ev.confirmed_by || '?'} - ${crDriftTime(ev.confirmed_at)}`
                            : <span className="cr-muted">{t('crDriftNoIncident')}</span>)}
                    </dl>
                    {whole && whole.op === 'unknown' && (
                        <div className="cr-callout cr-callout-info" data-cr-drift-why="unknown">
                            <Icons.Info className="w-4 h-4" />
                            <p>{crFill(t('crDriftUnknownNote'), { node: whole['node-offline'] || '?' })}</p>
                        </div>
                    )}
                    {whole && whole.op === 'removed' && (
                        <div className="cr-callout cr-callout-warning" data-cr-drift-why="removed">
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <p>{t('crDriftRemovedNote')}</p>
                        </div>
                    )}
                    {cat === 'policy_violation' && (
                        <div className="cr-callout cr-callout-info" data-cr-drift-why="violation">
                            <Icons.Info className="w-4 h-4" />
                            <p>{t('crDriftViolationNote')}</p>
                        </div>
                    )}
                    {ev.status === 'open' && cat !== 'policy_violation' && !whole && (
                        <p className="cr-drift-note" data-cr-drift-why="open">{t('crDriftOpenNote')}</p>
                    )}
                    <h3 className="cr-drift-h">{t('crDriftComparison')}</h3>
                    <CrDriftCompare ev={ev} t={t} />
                    <p className="cr-drift-foot-note">{t('crDriftCompareFoot')}</p>
                    {msg && msg.id === ev.id && (
                        <div className={`cr-callout cr-callout-${msg.tone}`} role={msg.tone === 'error' ? 'alert' : 'status'} data-cr-drift-msg={msg.tone}>
                            <p>{msg.text}</p>
                        </div>
                    )}
                </div>
            );
        }

        function CrDriftPolicy({ read, status, can, busy, open, setOpen, drafts, setDraft, msgs, changed, onSave, kindLabel, t }) {
            const body = read.body || {};
            const checks = Array.isArray(body.checks) ? body.checks : [];
            const at = crDriftTime(body.last_scan_at);
            const kinds = (status && status.kinds) || {};
            const cover = (status && status.coverage) || {};
            const lockWhy = !can.live ? t('crDriftStandbyReadOnly') : !can.baseline ? t('crDriftNeedsConfig') : '';
            return (
                <CrPanel title={t('driftPolicyTitle')} className="cr-drift-policy" data-cr-drift-policy=""
                    actions={read.state === 'ok' && <span className="cr-table-sub" title={t('crDriftServerTimeHint')}>
                        {at ? crFill(t('crDriftPolicyLast'), { time: at }) : t('crDriftPolicyNever')}</span>}>
                    <p className="cr-drift-note">{t('driftPolicyDesc')}</p>
                    {read.state === 'loading' && <p className="cr-drift-note"><span className="cr-spinner" aria-hidden="true" /> {t('loading')}</p>}
                    {read.state !== 'loading' && read.state !== 'ok' && (
                        <CrDriftState kind={read.state === 'forbidden' ? 'forbidden' : read.state === 'away' ? 'away' : 'error'} read={read} t={t} />
                    )}
                    {read.state === 'ok' && !checks.length && <p className="cr-drift-note">{t('crDriftNoChecks')}</p>}
                    {read.state === 'ok' && checks.length > 0 && (
                        <table className="cr-drift-ptable" data-cr-drift-ptable="">
                            <thead>
                                <tr>
                                    <th scope="col"><span className="cr-sr-only">{t('details')}</span></th>
                                    <th scope="col">{t('crDriftCheck')}</th>
                                    <th scope="col">{t('crDriftColKind')}</th>
                                    <th scope="col">{t('severity')}</th>
                                    <th scope="col">{t('crDriftResult')}</th>
                                    <th scope="col" title={t('crDriftServerTimeHint')}>{t('crDriftLastEval')}</th>
                                    <th scope="col">{t('driftPolicyEnabled')}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {checks.map(c => {
                                    const res = crPolicyResult(c, t);
                                    const viol = Array.isArray(c.violations) ? c.violations : [];
                                    const isOpen = !!open[c.id];
                                    const saving = !!busy[`pol:${c.id}`];
                                    const name = crTOr(t, 'driftCheck_' + c.id, c.id);
                                    const detailId = `cr-drift-pd-${c.id}`;
                                    const jobs = c.id === 'backup_none_disabled' && kinds.backup_jobs === 'checked'
                                        ? (cover.backup_jobs ? cover.backup_jobs.scopes : 0) : null;
                                    const draft = drafts[c.id] !== undefined ? drafts[c.id] : (Array.isArray(c.allow) ? c.allow.join(', ') : '');
                                    return (
                                        <React.Fragment key={c.id}>
                                            <tr data-cr-drift-check={c.id} data-cr-drift-result={res.key} className={isOpen ? 'cr-drift-prow-open' : ''}>
                                                <td>
                                                    <button type="button" className="cr-icon-btn cr-drift-expander" aria-expanded={isOpen} aria-controls={isOpen ? detailId : undefined}
                                                        aria-label={crFill(t('crDriftShowDetails'), { name })} data-cr-drift-expand={c.id}
                                                        onClick={() => setOpen(o => ({ ...o, [c.id]: !o[c.id] }))}>
                                                        <span className="cr-ico" aria-hidden="true"><Icons.ChevronRight /></span>
                                                    </button>
                                                </td>
                                                <td className="cr-strong">{name}</td>
                                                <td>{kindLabel(c.kind)}</td>
                                                <td><CrBadge tone={CR_DRIFT_SEV_TONE[c.severity] || 'neutral'} dot={false}>{t(c.severity) || c.severity}</CrBadge></td>
                                                <td>
                                                    <CrBadge tone={res.tone} dot={res.key !== 'off'} title={res.key === 'not_evaluated' ? t('crDriftNotEvalHint') : undefined}>{res.label}</CrBadge>
                                                    {viol.length > 0 && <span className="cr-drift-viol-n">{crFill(t('crDriftViolationsN'), { n: viol.length })}</span>}
                                                    {changed[c.id] && <span className="cr-drift-stale" title={t('crDriftChangedHint')}>{t('crDriftChangedShort')}</span>}
                                                </td>
                                                <td className="cr-mono">{res.evaluated && at ? at : '-'}</td>
                                                <td>
                                                    <label className="cr-switch" title={lockWhy || undefined}>
                                                        <input type="checkbox" role="switch" checked={!!c.enabled} disabled={!!lockWhy || saving}
                                                            aria-label={`${t('driftPolicyEnabled')}: ${name}`} data-cr-drift-enable={c.id}
                                                            onChange={e => onSave(c, { enabled: e.target.checked })} />
                                                        <span>{c.enabled ? t('crDriftOn') : t('crDriftOff')}</span>
                                                    </label>
                                                    {saving && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                                                </td>
                                            </tr>
                                            {isOpen && (
                                                <tr className="cr-drift-pdetail" id={detailId} data-cr-drift-pdetail={c.id}>
                                                    <td />
                                                    <td colSpan={6}>
                                                        <p className="cr-drift-note">
                                                            {res.key === 'not_evaluated' ? t('crDriftNotEvalNote')
                                                                : res.key === 'off' ? t('crDriftOffNote')
                                                                : res.key === 'pass' ? t('crDriftPassNote') : t('crDriftFailNote')}
                                                        </p>
                                                        {jobs != null && (
                                                            <p className="cr-drift-note" data-cr-drift-evaluated={jobs}>
                                                                {jobs ? crFill(t('crDriftJobsRead'), { n: jobs }) : t('crDriftNoJobs')}
                                                            </p>
                                                        )}
                                                        {c.id === 'access_token_expiry' && res.key === 'pass' && (
                                                            <p className="cr-drift-note" data-cr-drift-evaluated="unknown">{t('crDriftTokensUncounted')}</p>
                                                        )}
                                                        {changed[c.id] && (
                                                            <p className="cr-drift-note cr-drift-stale-note" data-cr-drift-changed={c.id}>
                                                                {crFill(t('crDriftChangedNote'), { time: changed[c.id] })}
                                                            </p>
                                                        )}
                                                        {viol.length > 0 && (
                                                            <>
                                                                <p className="cr-drift-note">{crFill(t('crDriftViolationsAll'), { n: viol.length })}</p>
                                                                <ul className="cr-drift-viol" data-cr-drift-violations={viol.length}>
                                                                    {viol.map((v, i) => <li key={i}><span className="cr-mono">{v.path}</span> {crDriftViol(c.id, v.detail, t)}</li>)}
                                                                </ul>
                                                            </>
                                                        )}
                                                        {Array.isArray(c.allow) && (
                                                            <div className="cr-drift-allow">
                                                                <label className="cr-muted" htmlFor={`cr-drift-allow-${c.id}`}>{t('crDriftAllowList')}</label>
                                                                {lockWhy ? (
                                                                    <span className="cr-mono" id={`cr-drift-allow-${c.id}`}>{c.allow.join(', ') || '-'}</span>
                                                                ) : (
                                                                    <>
                                                                        <input id={`cr-drift-allow-${c.id}`} className="cr-input" value={draft} data-cr-drift-allow={c.id}
                                                                            placeholder={t('driftPolicyAllow')} onChange={e => setDraft(c.id, e.target.value)} />
                                                                        <button type="button" className="cr-btn" disabled={saving} data-cr-drift-allow-save={c.id}
                                                                            onClick={() => onSave(c, { allow: draft.split(',').map(x => x.trim()).filter(Boolean) })}>{t('save')}</button>
                                                                    </>
                                                                )}
                                                            </div>
                                                        )}
                                                        {msgs[c.id] && <div className="cr-callout cr-callout-error" role="alert" data-cr-drift-pmsg={c.id}><p>{msgs[c.id]}</p></div>}
                                                    </td>
                                                </tr>
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                            </tbody>
                        </table>
                    )}
                </CrPanel>
            );
        }

        function crDriftScanText(j, t, kindLabel) {
            const parts = [crFill(t('crDriftScanNew'), { n: j.events_count || 0 })];
            if (j.already_open) parts.push(crFill(t('crDriftScanAlready'), { n: j.already_open }));
            if (j.seeded_baselines) parts.push(crFill(t('crDriftScanSeeded'), { n: j.seeded_baselines }));
            if (Array.isArray(j.unread) && j.unread.length) {
                parts.push(crFill(t('crDriftScanUnread'), { kinds: j.unread.map(kindLabel).join(', '), n: j.suppressed_unread || 0 }));
            }
            if (j.suppressed_offline) parts.push(crFill(t('crDriftScanOffline'), { n: j.suppressed_offline }));
            if (Array.isArray(j.not_checked) && j.not_checked.length) {
                parts.push(crFill(t('crDriftScanNotChecked'), { kinds: j.not_checked.map(kindLabel).join(', ') }));
            }
            return parts.join(' ');
        }

        function CrDrift({ clusterId, clusterName, authFetch, addToast, t, savePolicy, kindLabel, catLabel, nav, focus, onFocusDone }) {
            const { user, haReadOnly } = useAuth();
            // what the server asks per route: reads admin.audit, baseline and policy also
            // cluster.config, incidents the admin role; a standby that does not forward acts on nothing
            const can = useMemo(() => {
                const admin = !!user && user.role === 'admin';
                const list = Array.isArray(user && user.permissions) ? user.permissions : [];
                const has = (p) => admin || list.includes(p);
                const live = !haReadOnly;
                return { live, config: has('cluster.config'), scan: live && has('admin.audit'), ack: live && has('admin.audit'),
                         baseline: live && has('admin.audit') && has('cluster.config'), incident: live && admin };
            }, [user, haReadOnly]);
            const fresh = () => ({ status: { state: 'loading' }, events: { state: 'loading' }, policy: { state: 'loading' } });
            const [reads, setReads] = useState(fresh);
            const [filters, setFilters] = useState({ status: 'open', kind: '', category: '' });
            const [openId, setOpenId] = useState(null);
            const [busy, setBusy] = useState({});
            const [msg, setMsg] = useState(null);
            const [pageMsg, setPageMsg] = useState(null);
            const [scanStart, setScanStart] = useState(null);
            const [polOpen, setPolOpen] = useState({});
            const [polMsg, setPolMsg] = useState({});
            const [polChanged, setPolChanged] = useState({});
            const [drafts, setDrafts] = useState({});
            const [focusMiss, setFocusMiss] = useState(null);
            const [, setTick] = useState(0);
            const fetchRef = useRef(authFetch);
            fetchRef.current = authFetch;
            const navRef = useRef(nav);
            navRef.current = nav;
            const cidRef = useRef(clusterId);
            cidRef.current = clusterId;
            const filtersRef = useRef(filters);
            filtersRef.current = filters;
            const genS = useRef(0);
            const genE = useRef(0);
            const pendingFocus = useRef(null);
            const tableRef = useRef(null);

            const eventsUrl = (cid, f) => `${API_URL}/clusters/${cid}/drift/events?status=${encodeURIComponent(f.status)}&limit=${CR_DRIFT_LIMIT}`
                + (f.kind ? `&kind=${encodeURIComponent(f.kind)}` : '') + (f.category ? `&category=${encodeURIComponent(f.category)}` : '');
            const loadEvents = async () => {
                const cid = cidRef.current;
                if (!cid) return;
                const mine = ++genE.current;
                const f = filtersRef.current;
                setReads(r => ({ ...r, events: { ...r.events, loading: true } }));
                const e = await crDriftRead(fetchRef.current, eventsUrl(cid, f));
                if (mine !== genE.current || cid !== cidRef.current) return;
                setReads(r => ({ ...r, events: { ...e, f } }));
            };
            const loadAll = async () => {
                const cid = cidRef.current;
                if (!cid) return;
                const ms = ++genS.current;
                const me = ++genE.current;
                const f = filtersRef.current;
                setReads(r => ({ status: { ...r.status, loading: true }, events: { ...r.events, loading: true }, policy: { ...r.policy, loading: true } }));
                const [s, e, p] = await Promise.all([
                    crDriftRead(fetchRef.current, `${API_URL}/clusters/${cid}/drift/status`),
                    crDriftRead(fetchRef.current, eventsUrl(cid, f)),
                    crDriftRead(fetchRef.current, `${API_URL}/clusters/${cid}/drift/policy`),
                ]);
                if (cid !== cidRef.current) return;
                setReads(r => ({
                    status: ms === genS.current ? s : r.status,
                    policy: ms === genS.current ? p : r.policy,
                    events: me === genE.current ? { ...e, f } : r.events,
                }));
            };

            // a new cluster (or forwarding coming and going) starts from nothing: no row, count or
            // message of the one before stays on screen
            useEffect(() => {
                genS.current++;
                genE.current++;
                setReads(fresh());
                setOpenId(null); setMsg(null); setPageMsg(null); setPolMsg({}); setPolChanged({}); setDrafts({}); setFocusMiss(null);
                loadAll();
            }, [clusterId, haReadOnly]);
            const filterRun = useRef(false);
            useEffect(() => {
                if (!filterRun.current) { filterRun.current = true; return; }
                loadEvents();
            }, [filters.status, filters.kind, filters.category]);
            // the elapsed time of a scan that runs; nothing is asked for it
            useEffect(() => {
                if (!scanStart) return undefined;
                const id = setInterval(() => setTick(x => x + 1), 1000);
                return () => clearInterval(id);
            }, [scanStart]);

            // the timeline asked for one finding: show the list it is in, then open it
            useEffect(() => {
                if (!focus || focus.cluster !== clusterId || focus.id == null) return;
                pendingFocus.current = String(focus.id);
                setFocusMiss(null);
                const want = focus.status === 'open' ? 'open' : 'all';
                setFilters(f => (f.status === want && !f.kind && !f.category ? f : { status: want, kind: '', category: '' }));
                if (onFocusDone) onFocusDone(null);
            }, [focus, clusterId]);
            useEffect(() => {
                const id = pendingFocus.current;
                const er = reads.events;
                if (!id || er.loading || er.state === 'loading') return;
                pendingFocus.current = null;
                if (er.state !== 'ok') return;
                const hit = (er.body.events || []).find(e => String(e.id) === id);
                if (hit) setOpenId(hit.id); else setFocusMiss(id);
            }, [reads.events]);

            const s = reads.status.state === 'ok' ? reads.status.body : null;
            const er = reads.events;
            const events = er.state === 'ok' && Array.isArray(er.body.events) ? er.body.events : [];
            const guests = nav && nav.guestsOf ? nav.guestsOf(clusterId) : null;
            const nodes = nav && nav.nodesOf ? nav.nodesOf(clusterId) : null;
            const stores = nav && nav.storesOf ? nav.storesOf(clusterId) : null;
            const lists = nav && nav.listsRead ? nav.listsRead(clusterId) : null;
            const listsSig = lists ? `${lists.guests}|${lists.nodes}` : '';
            const rows = useMemo(() => {
                const seen = new Set();
                // the server sends the newest first: a later row of the same object marks the older ones
                return events.map(ev => {
                    const k = `${ev.kind}|${ev.scope}`;
                    const older = seen.has(k);
                    seen.add(k);
                    return { ...ev, _t: crDriftTarget(ev, clusterId, { guests, nodes, stores, read: lists }, t), _change: crDriftChange(ev, t), _older: older };
                });
            }, [events, clusterId, guests, nodes, stores, listsSig, t]);
            const openRow = openId != null ? rows.find(r => r.id === openId) : null;
            const sevLabel = (x) => t(x) || x;
            const statusLabel = (x) => ({ open: t('crDriftStOpen'), acknowledged: t('crDriftStAcknowledged'), resolved: t('crDriftStResolved'),
                                          superseded: t('crDriftStSuperseded') })[x] || x;

            const run = async (key, fn) => {
                if (busy[key]) return;
                setBusy(b => ({ ...b, [key]: true }));
                try { await fn(); } finally { setBusy(b => { const n = { ...b }; delete n[key]; return n; }); }
            };
            const refusal = async (r, fallback) => {
                if (!r) return t('crDriftOffline');
                return PegaProxApiErrors.message(r, `${fallback} (HTTP ${r.status})`);
            };
            const post = (url, body) => fetchRef.current(url, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
            });

            const ack = (ev, promote) => run(`ack:${ev.id}`, async () => {
                const cid = clusterId;
                setMsg(null);
                const r = await post(`${API_URL}/drift/events/${ev.id}/acknowledge`, { promote });
                const j = r && r.ok ? await r.clone().json().catch(() => null) : null;
                if (cid !== cidRef.current) return;
                if (j && j.ok) {
                    setMsg({ id: ev.id, tone: 'success', text: t(promote ? 'crDriftPromotedNote' : 'crDriftAckedNote') });
                    addToast(promote ? t('driftPromoted') : t('driftAcknowledged'), 'success');
                    await loadAll();
                } else {
                    setMsg({ id: ev.id, tone: 'error', text: crFill(t('crDriftRefused'), { reason: await refusal(r, t('crDriftActionFailed')) }) });
                }
            });
            const incident = (ev, flag) => run(`inc:${ev.id}`, async () => {
                if (flag && !confirm(t('driftIncidentAsk') || 'Confirm this event as an incident?')) return;
                const cid = clusterId;
                setMsg(null);
                const r = await post(`${API_URL}/drift/events/${ev.id}/incident`, { incident: flag });
                const j = r && r.ok ? await r.clone().json().catch(() => null) : null;
                if (cid !== cidRef.current) return;
                if (j && j.ok) {
                    setMsg({ id: ev.id, tone: 'success', text: flag ? t('driftIncidentConfirmed') : t('driftIncidentWithdrawn') });
                    addToast(flag ? t('driftIncidentConfirmed') : t('driftIncidentWithdrawn'), 'success');
                    await loadAll();
                } else {
                    setMsg({ id: ev.id, tone: 'error', text: crFill(t('crDriftRefused'), { reason: await refusal(r, t('driftIncidentFailed')) }) });
                }
            });
            const scan = () => run(`scan:${clusterId}`, async () => {
                const cid = clusterId;
                // the first baseline is a baseline write: only with cluster.config, as the server asks
                const seed = !!(s && s.baselines === 0 && can.baseline);
                setPageMsg(null);
                setScanStart(Date.now());
                let r = null, j = null;
                try {
                    r = await post(`${API_URL}/clusters/${cid}/drift/scan`, { seed });
                    j = r ? await r.clone().json().catch(() => null) : null;
                } finally { setScanStart(null); }
                if (cid !== cidRef.current) return;
                const at = new Date().toLocaleTimeString(crLocale());
                if (!r) setPageMsg({ tone: 'error', text: t('crDriftOffline') });
                else if (!r.ok) setPageMsg({ tone: 'error', text: crFill(t('crDriftScanRefused'), { reason: await refusal(r, t('driftScanFailed')) }) });
                else if (!j || j.ok !== true) {
                    // HTTP 200 with {error, status: 'skipped'}: nothing was scanned
                    const skipped = !!j && j.status === 'skipped';
                    setPageMsg({ tone: skipped ? 'warning' : 'error', kind: skipped ? 'skipped' : 'failed',
                                 text: crFill(t(skipped ? 'crDriftScanSkipped' : 'crDriftScanNotDone'), { reason: (j && j.error) || '-', time: at }) });
                } else {
                    setPageMsg({ tone: (j.unread && j.unread.length) ? 'warning' : 'success', kind: 'done',
                                 text: `${crFill(t('crDriftScanDone'), { time: at })} ${crDriftScanText(j, t, kindLabel)}` });
                    setPolChanged({});
                    addToast(t('driftScanned'), 'success');
                }
                await loadAll();
            });
            const resetBaseline = () => run(`baseline:${clusterId}`, async () => {
                if (!confirm(t('driftBaselineConfirm') || 'Reset baseline from current cluster state? Outstanding open events will be marked as superseded.')) return;
                const cid = clusterId;
                setPageMsg(null);
                const r = await post(`${API_URL}/clusters/${cid}/drift/baseline`);
                const j = r && r.ok ? await r.clone().json().catch(() => null) : null;
                if (cid !== cidRef.current) return;
                if (j && j.ok) {
                    const kept = Array.isArray(j.unread) && j.unread.length
                        ? ` ${crFill(t('crDriftBaselineKept'), { n: j.kept_unread || 0, kinds: j.unread.map(kindLabel).join(', ') })}` : '';
                    setPageMsg({ tone: kept ? 'warning' : 'success', kind: 'baseline', text: crFill(t('crDriftBaselineNote'), { n: j.baselines || 0 }) + kept });
                    addToast(t('driftBaselineDone'), 'success');
                } else {
                    setPageMsg({ tone: 'error', text: crFill(t('crDriftRefused'), { reason: await refusal(r, t('driftBaselineFailed')) }) });
                }
                await loadAll();
            });
            // the classic handler does the PUT and its toast; this keeps the server's answer
            const savePol = (c, patch) => run(`pol:${c.id}`, async () => {
                const cid = clusterId;
                setPolMsg(m => ({ ...m, [c.id]: null }));
                const r = await savePolicy(c.id, patch);
                if (cid !== cidRef.current) return;
                if (r && r.ok) {
                    const j = await r.clone().json().catch(() => null);
                    if (j && Array.isArray(j.checks)) setReads(x => ({ ...x, policy: { state: 'ok', body: j } }));
                    else {
                        const p = await crDriftRead(fetchRef.current, `${API_URL}/clusters/${cid}/drift/policy`);
                        if (cid === cidRef.current) setReads(x => ({ ...x, policy: p }));
                    }
                    setPolChanged(m => ({ ...m, [c.id]: new Date().toLocaleTimeString(crLocale()) }));
                    if ('allow' in patch) setDrafts(d => { const n = { ...d }; delete n[c.id]; return n; });
                } else {
                    const reason = await refusal(r, t('driftPolicySaveFailed'));
                    setPolOpen(o => ({ ...o, [c.id]: true }));
                    setPolMsg(m => ({ ...m, [c.id]: crFill(t('crDriftRefused'), { reason }) }));
                }
            });

            const go = (target) => { if (target && target.go && navRef.current) target.go(navRef.current); };
            const pick = (k) => setFilters(f => ({ ...f, kind: f.kind === k ? '' : k }));
            const rowEl = (id) => (tableRef.current ? tableRef.current.querySelector(`[data-cr-drift-row="${id}"]`) : null);

            const cols = useMemo(() => [
                { key: 'severity', label: t('severity'), width: 100, sortValue: r => CR_DRIFT_SEV.indexOf(r.severity), text: r => sevLabel(r.severity),
                  render: r => <span data-cr-drift-row={r.id} data-cr-drift-sev={r.severity}><CrBadge tone={CR_DRIFT_SEV_TONE[r.severity] || 'neutral'}>{sevLabel(r.severity)}</CrBadge></span> },
                { key: 'kind', label: t('crDriftColKind'), width: 122, sortValue: r => kindLabel(r.kind), render: r => kindLabel(r.kind) },
                { key: 'resource', label: t('crDriftColResource'), flex: true, min: 190, sortValue: r => r._t.label, text: r => `${r._t.label} ${r.scope}`,
                  render: r => (
                      <span className="cr-drift-res" title={[r._t.label, r.scope, r._t.note].filter(Boolean).join(' - ')}>
                          {r._t.go
                              ? <button type="button" className="cr-link" data-cr-drift-go={r._t.what} onClick={e => { e.stopPropagation(); go(r._t); }}>{r._t.label}</button>
                              : <span className="cr-strong">{r._t.label}</span>}
                          {r._t.label !== r.scope && <span className="cr-drift-scope cr-mono">{r.scope}</span>}
                      </span>
                  ) },
                { key: 'type', label: t('crDriftColType'), width: 128, sortValue: r => r.category || 'deviation', text: r => catLabel(r.category || 'deviation'),
                  render: r => <span data-cr-drift-cat={r.category || 'deviation'}><CrBadge tone={r.category === 'incident' ? 'error' : 'neutral'} dot={false}>{catLabel(r.category || 'deviation')}</CrBadge></span> },
                { key: 'change', label: t('crDriftColChange'), width: 200, sortValue: r => r._change, render: r => <span title={r._change}>{r._change}</span> },
                { key: 'detected', label: t('crDriftColDetected'), width: 142, mono: true, title: t('crDriftServerTimeHint'), sortValue: r => r.detected_at || '',
                  text: r => crDriftTime(r.detected_at), render: r => <span title={r.detected_at}>{crDriftTime(r.detected_at)}</span> },
                { key: 'status', label: t('status'), width: 176, sortValue: r => r.status, text: r => statusLabel(r.status),
                  render: r => (
                      <span className="cr-drift-status" data-cr-drift-status={r.status}>
                          <CrBadge tone={crDriftStatusTone(r.status)}>{statusLabel(r.status)}</CrBadge>
                          {r.change_id && <span data-cr-drift-planned={r.change_id}><CrBadge tone="success" dot={false} title={r.change_title}>{t('crDriftPlannedShort')}</CrBadge></span>}
                          {r._older && <span className="cr-drift-older" title={t('crDriftOlderHint')} data-cr-drift-older="">{t('crDriftOlder')}</span>}
                      </span>
                  ) },
                { key: 'actions', label: '', menuLabel: t('crDriftColActions'), width: 210, sortable: false, resizable: false, text: () => '',
                  render: r => <CrDriftActs ev={r} can={can} busy={busy} onAck={ack} onIncident={incident} compact t={t} /> },
            ], [t, can, busy, kindLabel, catLabel, clusterId]);

            if (!clusterId) {
                return (
                    <div className="cr-dash cr-drift" data-cr-drift="">
                        <div className="cr-panel cr-empty" data-cr-empty=""><Icons.Server className="w-6 h-6" /><p>{t('noClusterSelected')}</p></div>
                    </div>
                );
            }

            const all3 = [reads.status, reads.events, reads.policy];
            const whole = all3.some(r => r.state === 'away') ? 'away'
                : [reads.status, reads.events].some(r => r.state === 'forbidden') ? 'forbidden'
                : [reads.status, reads.events].some(r => r.state === 'notfound') ? 'notfound' : null;
            const refreshing = all3.some(r => r.loading || r.state === 'loading');
            const scanning = !!busy[`scan:${clusterId}`];
            const baselining = !!busy[`baseline:${clusterId}`];
            const scanSecs = scanStart ? Math.max(0, Math.round((Date.now() - scanStart) / 1000)) : 0;

            const header = (
                <CrPageHeader icon={<Icons.Shield />} title={t('driftDetection')} sub={clusterName || clusterId}
                    actions={(
                        <>
                            {!whole && can.baseline && (
                                <button type="button" className="cr-btn" onClick={resetBaseline} disabled={baselining || scanning} data-cr-drift-baseline=""
                                    title={t('crDriftBaselineHint')}>
                                    <span className="cr-ico" aria-hidden="true"><Icons.Database /></span>{t('driftSetBaseline')}
                                </button>
                            )}
                            {!whole && can.scan && (
                                <button type="button" className="cr-btn cr-btn-primary" onClick={scan} disabled={scanning || baselining} data-cr-drift-scan=""
                                    aria-busy={scanning || undefined}>
                                    <span className="cr-ico" aria-hidden="true">{scanning ? <Icons.RotateCw className="animate-spin" /> : <Icons.Search />}</span>
                                    {scanning ? crFill(t('crDriftScanning'), { n: scanSecs }) : t('driftScan')}
                                </button>
                            )}
                            <button type="button" className="cr-btn" onClick={loadAll} disabled={refreshing} data-cr-drift-refresh="">
                                <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>{t('refresh')}
                            </button>
                        </>
                    )} />
            );

            if (whole) {
                return (
                    <div className="cr-dash cr-drift" data-cr-drift="" data-cr-drift-whole={whole}>
                        {header}
                        <CrDriftState kind={whole} read={whole === 'forbidden' ? [reads.events, reads.status].find(r => r.state === 'forbidden') : null} t={t}
                            onRetry={whole === 'away' ? loadAll : undefined} />
                    </div>
                );
            }

            // N loaded of M open: M only where the status counts say it for this filter
            const lf = er.f || filters;
            let openOf = null;
            if (s && lf.status === 'open' && !(lf.kind && lf.category)) {
                if (lf.kind) { const c = (s.by_kind || {})[lf.kind] || {}; openOf = (c.critical || 0) + (c.warning || 0) + (c.info || 0); }
                else if (lf.category) openOf = (s.by_category || {})[lf.category] ?? null;
                else openOf = s.open_total;
            }
            const capped = events.length >= CR_DRIFT_LIMIT;
            const loadedText = er.state !== 'ok' ? '' : openOf != null
                ? crFill(t('crDriftLoadedOf'), { n: events.length, m: openOf })
                : crFill(t('crDriftLoaded'), { n: events.length });
            const allChecked = !!(s && s.last_scan_at && DRIFT_KINDS.every(k => (s.kinds || {})[k] === 'checked'));
            const notRead = s && s.last_scan_at ? DRIFT_KINDS.filter(k => (s.kinds || {})[k] !== 'checked').map(kindLabel) : [];
            const emptyText = lf.status === 'open' && !lf.kind && !lf.category
                ? (!s ? t('crDriftNoOpenUnknown') : !s.last_scan_at ? t('crDriftNoOpenNoScan')
                    : allChecked ? t('crDriftNoOpenAll') : crFill(t('crDriftNoOpenSome'), { kinds: notRead.join(', ') }))
                : t('driftNoEvents');
            const statusChips = [['open', t('crDriftStOpen')], ['acknowledged', t('crDriftStAcknowledged')], ['all', t('all')]];
            const sev = s ? s.by_severity || {} : {};
            const cats = s ? s.by_category || {} : {};

            return (
                <div className="cr-dash cr-drift" data-cr-drift="">
                    {header}
                    {!can.live && (
                        <div className="cr-callout cr-callout-info" data-cr-drift-readonly=""><Icons.Info className="w-4 h-4" /><p>{t('crDriftStandbyReadOnly')}</p></div>
                    )}
                    {pageMsg && (
                        <div className={`cr-callout cr-callout-${pageMsg.tone}`} role={pageMsg.tone === 'error' ? 'alert' : 'status'}
                            data-cr-drift-pagemsg={pageMsg.kind || pageMsg.tone}>
                            {pageMsg.tone === 'success' ? <Icons.CheckCircle className="w-4 h-4" /> : <Icons.AlertTriangle className="w-4 h-4" />}
                            <p>{pageMsg.text}</p>
                            <button type="button" className="cr-icon-btn cr-callout-close" onClick={() => setPageMsg(null)} aria-label={t('close')}>
                                <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                            </button>
                        </div>
                    )}

                    {reads.status.state === 'loading' && !s && (
                        <div className="cr-panel cr-drift-wait" data-cr-drift-wait=""><span className="cr-spinner" aria-hidden="true" /> {t('loading')}</div>
                    )}
                    {reads.status.state !== 'loading' && !s && <CrDriftState kind="error" read={reads.status} t={t} onRetry={loadAll} />}
                    {s && (
                        <>
                            {s.baselines === 0 && (
                                <div className="cr-callout cr-callout-info" data-cr-drift-nobaseline="">
                                    <Icons.Info className="w-4 h-4" />
                                    <p>{t('crDriftNoBaselineNote')}{can.scan && !can.baseline ? ` ${t('crDriftSeedNeedsConfig')}` : ''}</p>
                                </div>
                            )}
                            {!s.last_scan_at && (
                                <div className="cr-callout cr-callout-warning" data-cr-drift-noscan="">
                                    <Icons.AlertTriangle className="w-4 h-4" />
                                    <p>{t('crDriftNoScanNote')}</p>
                                </div>
                            )}
                            <section className="cr-stat-row cr-drift-stats" aria-label={t('crSummary')} data-cr-drift-summary="">
                                <CrStat id="open" label={t('crDriftOpenFindings')} value={s.open_total || 0}
                                    tone={sev.critical ? 'error' : sev.warning ? 'warning' : null}
                                    sub={crFill(t('crDriftSevCounts'), { critical: sev.critical || 0, warning: sev.warning || 0, info: sev.info || 0 })} />
                                <CrStat id="violations" label={t('driftCatPolicy')} value={cats.policy_violation || 0} tone={cats.policy_violation ? 'warning' : null}
                                    sub={t('crDriftOpenWord')} />
                                <CrStat id="incidents" label={t('crDriftIncidents')} value={cats.incident || 0} tone={cats.incident ? 'error' : null}
                                    sub={t('crDriftOpenWord')} />
                                <CrStat id="planned" label={t('crDriftPlannedLabel')} value={s.planned || 0} sub={t('crDriftPlannedSub')} />
                                <CrStat id="baselines" label={t('crDriftBaselines')} value={s.baselines || 0} sub={t('crDriftBaselinesSub')} />
                                <CrStat id="scan" label={t('crDriftLastScan')} value={s.last_scan_at ? crDriftTime(s.last_scan_at) : '-'}
                                    title={t('crDriftLastScanHint')} sub={s.last_scan_at ? t('crDriftServerTime') : t('crDriftNoScanSub')} />
                            </section>
                            <CrPanel title={t('crDriftRiskOverview')} className="cr-drift-overview" data-cr-drift-overview=""
                                actions={filters.kind ? (
                                    <button type="button" className="cr-btn cr-btn-ghost" onClick={() => pick(filters.kind)} data-cr-drift-clear-kind="">
                                        {crFill(t('crDriftClearKind'), { kind: kindLabel(filters.kind) })}
                                    </button>
                                ) : null}>
                                <div className="cr-drift-kinds">
                                    {DRIFT_KINDS.map(k => (
                                        <CrDriftKindCard key={k} kind={k} s={crDriftKind(s, k)} active={filters.kind === k} label={kindLabel(k)}
                                            onPick={() => pick(k)} t={t} />
                                    ))}
                                </div>
                                <p className="cr-drift-note" data-cr-drift-countnote="">{t('crDriftCountNote')}</p>
                            </CrPanel>
                        </>
                    )}

                    <div ref={tableRef} className="cr-drift-findings">
                        {focusMiss && (
                            <div className="cr-callout cr-callout-info" data-cr-drift-focusmiss={focusMiss}>
                                <Icons.Info className="w-4 h-4" /><p>{crFill(t('crDriftFocusMiss'), { id: focusMiss })}</p>
                            </div>
                        )}
                        {msg && !openRow && (
                            <div className={`cr-callout cr-callout-${msg.tone}`} role={msg.tone === 'error' ? 'alert' : 'status'} data-cr-drift-msg={msg.tone}>
                                <p>{crFill(t('crDriftFindingN'), { id: msg.id })}: {msg.text}</p>
                            </div>
                        )}
                        <CrTable id="drift-findings" columns={cols} rows={rows} rowKey={r => r.id} searchable rowHeight={30}
                            loading={!!er.loading || er.state === 'loading'} error={er.state !== 'ok' && er.state !== 'loading' ? `${t('crDriftReadFailed')}: ${crDriftReadText(er, t)}` : null}
                            emptyText={emptyText} maxHeight={520} initialSort={null} ariaLabel={t('crDriftFindings')}
                            selectedKey={openId} onRowClick={r => setOpenId(r.id)} rowClassName={r => (r._older ? 'cr-drift-row-older' : '')}
                            searchPlaceholder={t('crDriftSearch')}
                            toolbar={(
                                <>
                                    <span className="cr-table-title">{t('crDriftFindings')}</span>
                                    <div className="cr-seg" role="group" aria-label={t('status')}>
                                        {statusChips.map(([id, label]) => (
                                            <button key={id} type="button" className={filters.status === id ? 'active' : ''} aria-pressed={filters.status === id}
                                                data-cr-drift-show={id} onClick={() => setFilters(f => ({ ...f, status: id }))}>
                                                {label}{id === 'open' && s && <span className="cr-seg-n">{s.open_total || 0}</span>}
                                            </button>
                                        ))}
                                    </div>
                                    <select className="cr-select" value={filters.kind} aria-label={t('crDriftColKind')} data-cr-drift-filter="kind"
                                        onChange={e => setFilters(f => ({ ...f, kind: e.target.value }))}>
                                        <option value="">{t('driftAllKinds')}</option>
                                        {DRIFT_KINDS.map(k => <option key={k} value={k}>{kindLabel(k)}</option>)}
                                    </select>
                                    <select className="cr-select" value={filters.category} aria-label={t('crDriftColType')} data-cr-drift-filter="category"
                                        onChange={e => setFilters(f => ({ ...f, category: e.target.value }))}>
                                        <option value="">{t('driftAllCategories')}</option>
                                        {['deviation', 'policy_violation', 'incident'].map(c => <option key={c} value={c}>{catLabel(c)}</option>)}
                                    </select>
                                </>
                            )} />
                        {er.state === 'ok' && (
                            <p className="cr-drift-tablenote" data-cr-drift-loaded={events.length} data-cr-drift-of={openOf == null ? '' : openOf}>
                                {loadedText}{(capped || (openOf != null && events.length < openOf)) ? ` ${t('crDriftCapNote')}` : ''} {t('crDriftLocalNote')}
                            </p>
                        )}
                    </div>

                    <CrDriftPolicy read={reads.policy} status={s} can={can} busy={busy} open={polOpen} setOpen={setPolOpen} drafts={drafts}
                        setDraft={(id, v) => setDrafts(d => ({ ...d, [id]: v }))} msgs={polMsg} changed={polChanged} onSave={savePol}
                        kindLabel={kindLabel} t={t} />

                    <CrSidePanel open={!!openRow} id="drift" focusKey={openRow ? openRow.id : null} onClose={() => setOpenId(null)}
                        returnFocus={() => {
                            // the row may be gone (acknowledged out of the open list): then the table takes it
                            const el = openId != null ? rowEl(openId) : null;
                            return el ? el.closest('tr') : (tableRef.current && tableRef.current.querySelector('[data-cr-table="drift-findings"] tbody tr[tabindex="0"]'));
                        }}
                        title={openRow ? `${kindLabel(openRow.kind)}: ${openRow._t.label}` : ''}
                        sub={openRow ? <span className="cr-mono">{`#${openRow.id} · ${openRow.scope}`}</span> : null}
                        footer={openRow && (
                            <div className="cr-drift-foot">
                                <CrDriftActs ev={openRow} can={can} busy={busy} onAck={ack} onIncident={incident} t={t} />
                                {openRow._t.go && (
                                    <button type="button" className="cr-btn cr-btn-ghost" onClick={() => go(openRow._t)} data-cr-drift-foot-go="">
                                        <span className="cr-ico" aria-hidden="true"><Icons.ExternalLink /></span>{t('crDriftOpenResource')}
                                    </button>
                                )}
                            </div>
                        )}>
                        {openRow && (
                            <CrDriftDetail ev={openRow} target={openRow._t} can={can} busy={busy} msg={msg} onAck={ack} onIncident={incident}
                                onGo={() => go(openRow._t)} kindLabel={kindLabel} catLabel={catLabel} statusLabel={statusLabel} t={t} />
                        )}
                    </CrSidePanel>
                </div>
            );
        }
