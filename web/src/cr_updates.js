        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned (Preview): Automation > Updates - LW Nov 2026
        // The update manager of one cluster on the routes the classic section uses. Opening it
        // reads three things: the server's copy of the last check (/updates-overview, it asks no
        // node), the rolling update of the cluster and its schedule. A check runs apt update on
        // every online node, so it only starts from its own button and dialog; nothing installs
        // from this page except a rolling update started in its dialog or armed in the schedule.
        // What the sources do not carry is said so: no security or critical class for Proxmox VE
        // (the list has no suite), no "reboot required" (only "kernel package pending"), no guest
        // packages, no package versions in the history. Unread, failed and missing are states,
        // never a 0.
        // ═══════════════════════════════════════════════════════════

        const CR_UPD = {
            pollActive: 4000,     // the run's status while it runs or waits for Continue
            pollIdle: 60000,      // and otherwise, so a run started elsewhere shows up
            checkTimeout: 240000, // a check waits up to 2 min per node in parallel, 180 s overall on the server
            rows: 500,            // package rows drawn in the side panel before "show all"
        };
        const CR_UPD_OVER = ['completed', 'failed', 'cancelled'];
        const CR_UPD_ACTIVE = ['running', 'paused'];
        const CR_UPD_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
        const CR_UPD_TIMEOUTS = [300, 600, 1200, 1800, 3600, 7200];
        // the words of a phase (rolling_runs.PHASES and the steps around them), a node chip and a node state
        const CR_UPD_PHASE_KEY = { checking: 'crUpdPhaseChecking', maintenance: 'crUpdPhaseMaintenance', evacuating: 'crUpdPhaseEvacuating',
                                   updating: 'crUpdPhaseUpdating', rebooting: 'crUpdPhaseRebooting', finishing: 'crUpdPhaseFinishing',
                                   ceph: 'crUpdPhaseCeph', done: 'crUpdPhaseDone', starting: 'crUpdPhaseStarting', cleanup: 'crUpdPhaseCleanup',
                                   cancelling: 'crUpdPhaseCancelling' };
        const CR_UPD_CHIP_KEY = { done: 'crUpdChipDone', skipped: 'crUpdChipSkipped', failed: 'crUpdChipFailed', current: 'crUpdChipCurrent',
                                  pending: 'crUpdChipPending' };
        const CR_UPD_ST_KEY = { online: 'crUpdStOnline', offline: 'crUpdStOffline', maintenance: 'crUpdStMaintenance',
                                updating: 'crUpdStUpdating', unlisted: 'crUpdStUnlisted', nostatus: 'crUpdStNoStatus' };
        // what the engine checks itself (settings.py run_rolling_update, rolling_runs.quorum_gate) and what it does not
        const CR_UPD_GATES = ['crUpdGateOne', 'crUpdGateQuorum', 'crUpdGateMaint', 'crUpdGateEvac', 'crUpdGateReboot', 'crUpdGateCeph',
                              'crUpdGateFail', 'crUpdGateRecheck'];
        const CR_UPD_NOT_GATES = ['crUpdNotGateCapacity', 'crUpdNotGateHa', 'crUpdNotGateOffline', 'crUpdNotGateWindow',
                                  'crUpdNotGateGuests', 'crUpdNotGateUnread'];
        const crUpdStTone = (st) => (st === 'offline' ? 'error' : st === 'online' ? 'success' : st === 'unlisted' || st === 'nostatus' ? 'neutral' : 'warning');
        const crUpdNames = (list) => (list.length > 3 ? `${list.slice(0, 3).join(', ')} +${list.length - 3}` : list.join(', '));

        // A kernel package by its name, as the server matches it (linux-image, pve-kernel,
        // proxmox-kernel); the helper packages carry the word but no kernel
        function crUpdKernelKind(name) {
            const n = String(name || '');
            if (!['linux-image', 'pve-kernel', 'proxmox-kernel'].some(k => n.includes(k))) return null;
            return /-helper$/.test(n) ? 'helper' : 'image';
        }
        const crUpdNodeNames = (metrics) => (metrics && typeof metrics === 'object'
            ? Object.keys(metrics).filter(k => k !== 'error' && k !== 'offline' && metrics[k] && typeof metrics[k] === 'object') : []);

        // The page's figures from the overview answer (ov: {state, body}) for one cluster, joined
        // with the node list the dashboard holds. state: loading | unread | forbidden | notlisted |
        // confined | unchecked | ok. A host whose check failed counts as not read, a node the check
        // does not list (offline then, or added since) as missing; neither adds a 0 anywhere.
        function crUpdModel({ cluster, metrics, ov, now, nodesRead }) {
            const c = cluster || {};
            const kind = c.cluster_type || 'proxmox';
            const names = crUpdNodeNames(metrics);
            const out = { kind, state: 'loading', entry: null, rows: [], pbs: [], total: null, withUpdates: null, upToDate: null,
                          failed: [], missing: [], kernel: null, security: null, checkedAt: null, stale: false, rolling: null };
            if (kind === 'esxi') out.state = 'unsupported';
            else if (!ov) out.state = 'loading';
            else if (ov.state === 'forbidden') out.state = 'forbidden';
            else if (ov.state !== 'ok' || !ov.body || !Array.isArray(ov.body.hosts) || !Array.isArray(ov.body.clusters)) out.state = 'unread';
            else {
                const entry = ov.body.clusters.find(x => x && x.cluster_id === c.id) || null;
                out.entry = entry;
                out.state = !entry ? 'notlisted' : entry.state === 'confined' ? 'confined' : entry.state === 'unchecked' ? 'unchecked' : 'ok';
                if (entry) out.rolling = entry.rolling || null;
                if (out.state === 'ok') {
                    out.checkedAt = typeof entry.checked_at === 'number' ? entry.checked_at : null;
                    out.stale = !!entry.stale;
                }
            }
            const hosts = out.state === 'ok' ? ov.body.hosts.filter(h => h && h.cluster_id === c.id) : [];
            const byName = {};
            hosts.filter(h => h.kind === 'node').forEach(h => { byName[String(h.name)] = h; });
            out.pbs = hosts.filter(h => h.kind === 'pbs');
            const all = [...names, ...Object.keys(byName).filter(n => !names.includes(n))];
            all.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
            out.rows = all.map(name => {
                const m = names.includes(name) ? metrics[name] : null;
                const h = byName[name] || null;
                // a host the check names that the node list does not: gone since, or the list was never read
                const st = !m ? (nodesRead || names.length ? 'unlisted' : 'nostatus') : (m.offline === true || m.status === 'offline' || m.status === 'unknown') ? 'offline'
                    : m.is_updating ? 'updating' : m.maintenance_mode ? 'maintenance' : 'online';
                let pending;
                if (out.state === 'ok') pending = h ? (h.ok ? 'ok' : 'failed') : 'missing';
                else pending = out.state === 'unchecked' ? 'unchecked' : 'unknown';
                return {
                    name, st, m, h, pending, count: pending === 'ok' ? h.count : null,
                    kernel: pending === 'ok' ? !!h.kernel : null,
                    channel: h ? h.channel || null : null, subscription: h ? h.subscription || null : null,
                    warnings: h && typeof h.repo_warnings === 'number' ? h.repo_warnings : null,
                };
            });
            if (out.state === 'ok') {
                const ok = out.rows.filter(r => r.pending === 'ok');
                out.total = ok.reduce((s, r) => s + (r.count || 0), 0);
                out.withUpdates = ok.filter(r => r.count > 0).length;
                out.upToDate = ok.filter(r => r.count === 0).length;
                out.read = ok.length;
                out.failed = out.rows.filter(r => r.pending === 'failed').map(r => r.name);
                out.missing = out.rows.filter(r => r.pending === 'missing').map(r => r.name);
                out.kernel = ok.filter(r => r.kernel).length;
                // XCP-ng names a security repository; Proxmox VE and PBS give no suite (settings.py _overview_host)
                const sec = ok.map(r => r.h.security);
                out.security = kind === 'xcpng' && sec.every(v => typeof v === 'number') ? sec.reduce((s, v) => s + v, 0) : null;
            }
            out.age = out.checkedAt && now ? Math.max(0, Math.round(now / 1000 - out.checkedAt)) : null;
            return out;
        }

        // What a rolling update says about itself, for the panel and the card. Timestamps of the run are
        // local server time without a zone (rolling_runs._now)
        function crUpdRunView(r) {
            if (!r || typeof r !== 'object') return null;
            const nodes = Array.isArray(r.nodes) ? r.nodes : [];
            const done = Array.isArray(r.completed_nodes) ? r.completed_nodes : [];
            const skipped = Array.isArray(r.skipped_nodes) ? r.skipped_nodes : [];
            const failed = Array.isArray(r.failed_nodes) ? r.failed_nodes.filter(f => f && typeof f === 'object') : [];
            const failedNames = failed.map(f => f.node);
            const ns = r.node_state && typeof r.node_state === 'object' ? r.node_state : null;
            const finished = done.length + skipped.length + failedNames.filter(n => !done.includes(n) && !skipped.includes(n)).length;
            const status = String(r.status || '');
            const current = CR_UPD_ACTIVE.includes(status) ? (r.current_node || null) : null;
            const phase = current ? ((ns && ns[current] && ns[current].phase) || r.current_step || null) : null;
            const chips = nodes.map(n => {
                const s = ns && ns[n];
                const state = failedNames.includes(n) ? 'failed' : done.includes(n) ? 'done' : skipped.includes(n) ? 'skipped'
                    : n === current ? 'current' : 'pending';
                return { node: n, state, phase: s && s.phase ? s.phase : null, at: s && s.phase_at ? s.phase_at : null,
                         moved: s && typeof s.moved_count === 'number' ? s.moved_count : null, rebooted: s ? !!s.rebooted : null };
            });
            return {
                status, nodes, done, skipped, failed, finished, current, phase, chips,
                tone: status === 'running' ? 'info' : status === 'paused' ? 'warning'
                    : status === 'completed' ? (failed.length ? 'warning' : 'success') : status === 'failed' ? 'error' : 'neutral',
                withFailures: status === 'completed' && failed.length > 0,
                cancelling: r.current_step === 'cancelling',
            };
        }

        // the status word of a run, "completed" with failed nodes is no plain success
        function crUpdRunLabel(t, status, failed) {
            if (status === 'completed' && failed > 0) return crFill(t('crUpdDoneWithFailed'), { n: failed });
            return t({ completed: 'rollRunStatusCompleted', failed: 'rollRunStatusFailed', cancelled: 'rollRunStatusCancelled',
                       running: 'rollRunStatusRunning', paused: 'rollRunStatusPaused' }[status] || 'crUpdUnknown');
        }

        function crUpdAge(t, sec) {
            if (sec == null || !Number.isFinite(sec)) return '-';
            if (sec < 60) return t('crUpdAgeNow');
            if (sec < 3600) return crFill(t('crUpdAgeMin'), { n: Math.round(sec / 60) });
            if (sec < 172800) return crFill(t('crUpdAgeHours'), { n: Math.round(sec / 3600) });
            return crFill(t('crUpdAgeDays'), { n: Math.round(sec / 86400) });
        }
        // 'pve-manager/9.0.3/abcd' -> 9.0.3, 'Linux 6.14.8-2-pve #1 SMP ...' -> 6.14.8-2-pve
        const crUpdPve = (v) => { const m = /pve-manager\/([^/\s]+)/.exec(String(v || '')); return m ? m[1] : ''; };
        const crUpdKver = (v) => { const p = String(v || '').trim().split(/\s+/); return p[0] === 'Linux' && p[1] ? p[1] : (p[0] || ''); };
        const crUpdSecs = (s) => (s >= 3600 ? `${s / 3600} h` : `${Math.round(s / 60)} min`);

        // --- what this browser holds for the session: the check answers and the headroom reads -------

        const crUpd = { checks: {}, room: {}, dismissed: {}, subs: new Set() };
        // the package lists of a check belong to the account that ran it (crSessionFor)
        crSessionStore(() => { crUpd.checks = {}; crUpd.room = {}; crUpd.dismissed = {}; });
        function crUpdEmit() { crUpd.subs.forEach(f => { try { f(); } catch (_) {} }); }
        function useCrUpd() {
            const { user } = useAuth();
            crSessionFor(user);
            const [, bump] = useState(0);
            useEffect(() => {
                const f = () => bump(n => n + 1);
                crUpd.subs.add(f);
                return () => { crUpd.subs.delete(f); };
            }, []);
            return crUpd;
        }

        // The check of the classic button, same route and body; one at a time per cluster. The answer
        // stays in memory for this session only: the package lists of 200 nodes do not go into storage
        async function crUpdRunCheck(authFetch, cid, force, after) {
            const cur = crUpd.checks[cid] || {};
            if (cur.busy || !authFetch) return;
            const gen = crSession.gen;
            crUpd.checks[cid] = { ...cur, busy: true, started: Date.now(), force: !!force, error: null };
            crUpdEmit();
            let next;
            const t0 = Date.now();
            try {
                const r = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/updates/check`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force: !!force }), timeout: CR_UPD.checkTimeout,
                });
                // authFetch answers null for an abort (our timeout) and for a lost connection alike
                if (!r) next = { error: { code: 0, msg: '', timeout: Date.now() - t0 >= CR_UPD.checkTimeout - 2000 } };
                else {
                    const body = await r.json().catch(() => null);
                    if (r.ok && body && body.success && body.nodes && typeof body.nodes === 'object') next = { answer: { body, at: Date.now() } };
                    else next = { error: { code: r.status, msg: (body && typeof body.error === 'string' && body.error) || '' } };
                }
            } catch (e) {
                next = { error: { code: 0, msg: String((e && e.message) || e) } };
            }
            if (gen !== crSession.gen) return;
            crUpd.checks[cid] = { ...crUpd.checks[cid], ...next, busy: false, finished: Date.now() };
            crUpdEmit();
            if (after) after();
        }

        // the what-if engine's N+1 headroom of the cluster, on a click: one request, read only
        async function crUpdRunHeadroom(authFetch, cid) {
            const cur = crUpd.room[cid] || {};
            if (cur.busy || !authFetch) return;
            const gen = crSession.gen;
            crUpd.room[cid] = { ...cur, busy: true, error: null };
            crUpdEmit();
            let next;
            try {
                const r = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/whatif`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'headroom', depth: 1, guests: 'all' }), quiet: true,
                });
                const body = r ? await r.json().catch(() => null) : null;
                if (r && r.ok && body && body.headroom) next = { report: body, at: Date.now() };
                else next = { error: { code: r ? r.status : 0, msg: (body && body.error) || '' } };
            } catch (e) {
                next = { error: { code: 0, msg: String((e && e.message) || e) } };
            }
            if (gen !== crSession.gen) return;
            crUpd.room[cid] = { ...crUpd.room[cid], ...next, busy: false };
            crUpdEmit();
        }

        // the list as plain text for a change ticket (#1192), from the check answer of this session
        function crUpdText(t, name, answer) {
            const body = answer.body || {};
            const sum = body.summary || {};
            const table = (rows) => {
                rows = rows.map(r => r.map(String));
                const width = rows[0].map((_, i) => Math.max(...rows.map(r => r[i].length)));
                return rows.map(r => '  ' + r.map((c, i) => (i < r.length - 1 ? c.padEnd(width[i]) : c)).join('  '));
            };
            const out = [t('updCopyHeading').replace('{cluster}', name)];
            if (sum.checked_at) out.push(crFill(t('crUpdCopyChecked'), { time: sum.checked_at }));
            out.push(t('updCopyCopiedAt').replace('{time}', crFmtDate(new Date(), { timeZoneName: 'short' })));
            const nodes = Object.entries(body.nodes || {}).sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }));
            const failed = nodes.filter(([, d]) => !d || d.success === false).length;
            if (failed) out.push(t('updCopyFailedHosts').replace('{n}', failed));
            nodes.forEach(([n, d]) => {
                if (!d || d.success === false) {
                    out.push('', `${n} - ${t('checkFailed')}${d && d.error ? ': ' + d.error : ''}`);
                    return;
                }
                const list = Array.isArray(d.updates) ? d.updates : [];
                out.push('', `${n} - ${list.length} ${t('updates')}`);
                if (list.length) {
                    out.push(...table([[t('package'), t('currentVersion'), t('newVersion'), t('crUpdOrigin')],
                        ...list.map(p => [p.Package || '-', p.OldVersion || '-', p.Version || '-', p.Origin || '-'])]));
                }
            });
            return out.join('\n') + '\n';
        }
        async function crUpdCopy(text) {
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(text);
                    return true;
                }
            } catch (_) { /* refused, the textarea below */ }
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            let ok = false;
            try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
            document.body.removeChild(ta);
            return ok;
        }

        // --- the dialog shell: the pattern of CrSbMoveDialog (portal, focus in and back, Tab kept, Escape) ---

        function CrUpdDialog({ id, title, sub, busy, onCancel, footer, children, wide, sticky }) {
            const { t } = useTranslation();
            const ref = useRef(null);
            const back = useRef(typeof document !== 'undefined' ? document.activeElement : null);
            const [titleId] = useState(() => `cr-upd-dlg-${++crPanelSeq}`);
            useEffect(() => {
                if (ref.current) ref.current.focus({ preventScroll: true });
                return () => crFocusBack(back.current);
            }, []);
            const onKey = (e) => {
                if (e.key === 'Tab') { crKeepTab(e, ref.current); return; }
                if (e.key === 'Escape') {
                    e.preventDefault();
                    e.stopPropagation();
                    if (!busy) onCancel();
                }
            };
            // sticky (start, schedule): many choices in it, a stray click beside it keeps them and the
            // focus stays in the dialog (Escape still closes it)
            const onLayer = (e) => {
                if (e.target !== e.currentTarget) return;
                if (sticky) { e.preventDefault(); return; }
                if (!busy) onCancel();
            };
            return ReactDOM.createPortal(
                <div className="cr-sb-layer" onMouseDown={onLayer}>
                    <div className={`cr-sb-dialog cr-upd-dialog${wide ? ' cr-upd-dialog-wide' : ''}`} role="dialog" aria-modal="true"
                        aria-labelledby={titleId} tabIndex={-1} ref={ref} onKeyDown={onKey} data-cr-upd-dialog={id}>
                        <header className="cr-sp-head">
                            <div className="cr-sp-titles">
                                <h2 className="cr-sp-title" id={titleId}>{title}</h2>
                                {sub && <div className="cr-sp-sub">{sub}</div>}
                            </div>
                            <button type="button" className="cr-icon-btn" onClick={onCancel} disabled={busy} aria-label={t('close')} title={`${t('close')} (Esc)`}>
                                <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                            </button>
                        </header>
                        <div className="cr-sb-dbody">{children}</div>
                        <footer className="cr-sp-foot cr-sb-dfoot">{footer}</footer>
                    </div>
                </div>,
                document.body
            );
        }

        function CrUpdNote({ tone = 'info', id, children }) {
            const Icon = tone === 'error' ? Icons.AlertCircle : tone === 'warning' ? Icons.AlertTriangle : Icons.Info;
            return (
                <div className={`cr-callout cr-callout-${tone}`} role={tone === 'error' ? 'alert' : 'status'} data-cr-upd-note={id || ''}>
                    <Icon className="w-4 h-4" />
                    <div>{children}</div>
                </div>
            );
        }

        // a short "why not" for a disabled control
        function crUpdWhy(t, x) {
            if (x.kind === 'esxi') return t('crUpdWhyEsxi');
            if (x.standby) return t('crUpdWhyStandby');
            if (!x.may) return t('crUpdWhyPerm');
            if (x.confined) return t('crUpdWhyConfined');
            return '';
        }

        // --- the check: its dialog and its card ------------------------------------------------------

        function CrUpdCheckDialog({ cluster, nodes, onCancel, onConfirm }) {
            const { t } = useTranslation();
            // LW Nov 2026 - unticked first: a copy younger than 24 h answers without an apt update on
            // every node; ticking it still asks the nodes now (the classic button always forced)
            const [force, setForce] = useState(false);
            const online = nodes.filter(r => ['online', 'maintenance', 'updating'].includes(r.st)).length;
            const offline = nodes.filter(r => r.st === 'offline').map(r => r.name);
            return (
                <CrUpdDialog id="check" title={crFill(t('crUpdCheckTitle'), { cluster: clusterLabel(cluster) })} onCancel={onCancel}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} data-cr-upd-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" icon={<Icons.RefreshCw />} onClick={() => onConfirm(force)} data-cr-upd-confirm="check">
                                {t('crUpdCheckGo')}
                            </CrButton>
                        </>
                    )}>
                    <p className="cr-upd-text" data-cr-upd-check-what="">{t('crUpdCheckWhat')}</p>
                    <ul className="cr-sb-risks">
                        <li className="cr-sb-risk cr-sb-risk-info">
                            <span className="cr-ico" aria-hidden="true"><Icons.Info /></span>
                            <span>{online ? crFill(t('crUpdCheckNodes'), { n: online }) : t('crUpdCheckNodesAll')}{offline.length ? ` ${crFill(t('crUpdCheckOffline'), { nodes: offline.join(', ') })}` : ''}</span>
                        </li>
                        <li className="cr-sb-risk cr-sb-risk-info">
                            <span className="cr-ico" aria-hidden="true"><Icons.Info /></span>
                            <span>{t('crUpdCheckNoInstall')}</span>
                        </li>
                    </ul>
                    <label className="cr-upd-tick">
                        <input type="checkbox" checked={force} onChange={e => setForce(e.target.checked)} data-cr-upd-force="" />
                        <span>{t('crUpdCheckForce')}</span>
                    </label>
                    {!force && <p className="cr-sb-fine" data-cr-upd-copy-note="">{t('crUpdCheckCopyNote')}</p>}
                </CrUpdDialog>
            );
        }

        function CrUpdCheckResult({ chk, t }) {
            if (!chk) return null;
            if (chk.busy) {
                return (
                    <p className="cr-upd-line" role="status" data-cr-upd-check-state="running">
                        <span className="cr-spinner" aria-hidden="true" /> {crFill(t('crUpdChecking'), { time: crFmtTime(chk.started) })}
                    </p>
                );
            }
            const out = [];
            if (chk.error) {
                const e = chk.error;
                out.push(
                    <p key="e" className="cr-upd-line cr-upd-bad" role="alert" data-cr-upd-check-state="error">
                        {e.timeout ? t('crUpdCheckTimeout') : crFill(t('crUpdCheckFailed'), { why: [e.msg, e.code ? `HTTP ${e.code}` : ''].filter(Boolean).join(' - ') || t('crDcNoAnswer') })}
                    </p>
                );
            }
            if (chk.answer) {
                const b = chk.answer.body;
                const nodes = Object.entries(b.nodes || {});
                const bad = nodes.filter(([, d]) => !d || d.success === false);
                const s = b.summary || {};
                out.push(
                    <div key="a" className="cr-upd-answer" data-cr-upd-check-state={chk.error ? 'old' : 'ok'}>
                        <p className="cr-upd-line">
                            {crFill(t('crUpdCheckAnswer'), { time: crFmtTime(chk.answer.at), server: s.checked_at || '-' })}
                            {b.cached ? <span className="cr-upd-copy" data-cr-upd-cached=""> {crFill(t('crUpdCheckCached'), { age: crUpdAge(t, b.cached_age_sec) })}</span> : null}
                        </p>
                        {nodes.length === 0 ? (
                            <p className="cr-upd-line cr-upd-warn" data-cr-upd-check-empty="">{t('crUpdCheckNoNode')}</p>
                        ) : (
                            <p className="cr-upd-line" data-cr-upd-check-read="">
                                {crFill(t('crUpdCheckRead'), { read: nodes.length - bad.length, total: nodes.length })}
                                {bad.length > 0 && <span className="cr-upd-warn" data-cr-upd-check-bad=""> {crFill(t('crUpdCheckBad'), { nodes: bad.map(([n]) => n).join(', ') })}</span>}
                            </p>
                        )}
                    </div>
                );
            }
            return <>{out}</>;
        }

        // --- the rolling update: the run panel --------------------------------------------------------

        function CrUpdRun({ run, view, t, canAct, canReboot, busy, err, onContinue, onAnyway, onCancel, onDismiss, onHistory }) {
            const r = run;
            const d = r.paused_details && typeof r.paused_details === 'object' ? r.paused_details : null;
            const node = (d && d.node) || r.current_node || '-';
            const reason = r.status === 'paused' ? (r.paused_reason || '') : '';
            const quorumText = () => {
                if (!d) return '';
                if (d.reason === 'status_unreadable') return t('rollQuorumUnread').replace('{node}', node);
                if (d.reason === 'status_incomplete') return t('rollQuorumIncomplete').replace('{node}', node);
                if (d.reason === 'not_quorate') return t('rollQuorumNotQuorate').replace('{node}', node);
                return t('rollQuorumHeld').replace('{node}', node).replace('{after}', String(d.after ?? '-'))
                    .replace('{expected}', String(d.expected ?? '-')).replace('{needed}', String(d.needed ?? '-'));
            };
            const undone = (item) => {
                if (item.kind === 'maintenance') return t('rollRunUndoneMaint').replace('{node}', item.node || '-');
                if (item.kind === 'ha_rules') return t('rollRunUndoneRules').replace('{rules}', (item.rules || []).join(', '));
                if (item.kind === 'guests_stay') return t('rollRunUndoneGuests').replace('{count}', item.count || 0).replace('{node}', item.node || '-');
                return t('rollRunUndoneError');
            };
            const active = CR_UPD_ACTIVE.includes(r.status);
            const over = CR_UPD_OVER.includes(r.status);
            const total = view.nodes.length;
            const pct = (n) => (total ? `${(n * 100 / total).toFixed(2)}%` : '0%');
            // a rebooting run goes on only with node.reboot (settings.py resume)
            const needsReboot = !!r.include_reboot && !canReboot;
            const phaseText = (p) => (p ? (CR_UPD_PHASE_KEY[p] ? t(CR_UPD_PHASE_KEY[p]) : p) : '');
            return (
                <section className={`cr-panel cr-upd-run cr-upd-run-${view.tone}`} data-cr-upd-run={r.status} data-cr-upd-run-id={r.run_id || ''}
                    aria-label={t('crUpdRunTitle')}>
                    <header className="cr-upd-run-head">
                        <span className={`cr-badge cr-badge-${view.tone}`} data-cr-upd-run-status="">{crUpdRunLabel(t, r.status, view.failed.length)}</span>
                        <span className="cr-strong">{t('crUpdRunTitle')}</span>
                        <span className="cr-muted" data-cr-upd-run-started="">
                            {crFill(t('crUpdRunStarted'), { time: r.started_at || '-' })}
                            {r.scheduled ? ` · ${t('crUpdScheduler')}` : r.started_by ? ` · ${crFill(t('rollRunHistoryBy'), { user: r.started_by })}` : ''}
                            {over && r.completed_at ? ` · ${crFill(t('crUpdRunEnded'), { time: r.completed_at })}` : ''}
                        </span>
                        <span className="cr-upd-run-acts">
                            {onHistory && <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={onHistory} data-cr-upd-run-history="">{t('crUpdOpenHistory')}</button>}
                            {over && <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={onDismiss} data-cr-upd-run-dismiss="" title={t('crUpdDismissHint')}>{t('crUpdDismiss')}</button>}
                        </span>
                    </header>
                    <div className="cr-upd-run-facts">
                        {active && (
                            <span data-cr-upd-run-current="">
                                <span className="cr-muted">{t('currentNode')}:</span> <span className="cr-strong cr-mono">{r.current_node || '-'}</span>
                                {view.phase && <> <span className="cr-muted">·</span> <span data-cr-upd-run-phase={view.phase}>{phaseText(view.phase)}</span></>}
                            </span>
                        )}
                        <span data-cr-upd-run-counts="">
                            {crFill(t('crUpdRunCounts'), { done: view.done.length, skipped: view.skipped.length, failed: view.failed.length, total })}
                        </span>
                        <span className="cr-muted">{r.include_reboot ? t('crUpdRunReboots') : t('crUpdRunNoReboot')}</span>
                    </div>
                    <span className="cr-upd-bar" role="img" data-cr-upd-run-bar=""
                        aria-label={crFill(t('crUpdRunBar'), { n: view.finished, total })}>
                        <span className="cr-upd-bar-done" style={{ width: pct(view.done.length + view.skipped.length) }} />
                        <span className="cr-upd-bar-fail" style={{ width: pct(view.failed.length) }} />
                    </span>
                    <p className="cr-sb-fine">{t('crUpdRunBarNote')}</p>
                    {view.chips.length > 0 && (
                        <ul className="cr-upd-chips" aria-label={t('nodes')}>
                            {view.chips.map(ch => (
                                <li key={ch.node} className={`cr-upd-chip cr-upd-chip-${ch.state}`} data-cr-upd-chip={ch.node} data-state={ch.state}
                                    title={[ch.phase ? phaseText(ch.phase) : '', ch.at ? crFmtTime(ch.at) : '', ch.moved != null ? crFill(t('crUpdMoved'), { n: ch.moved }) : ''].filter(Boolean).join(' · ')}>
                                    <span className="cr-mono">{ch.node}</span>
                                    <span className="cr-upd-chip-st">{t(CR_UPD_CHIP_KEY[ch.state])}{ch.state === 'current' && ch.phase ? `: ${phaseText(ch.phase)}` : ''}</span>
                                </li>
                            ))}
                        </ul>
                    )}

                    {r.status === 'paused' && (
                        <div className="cr-callout cr-callout-warning cr-upd-paused" role="status" data-cr-upd-paused={reason || 'unknown'}>
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <div>
                                <p className="cr-strong">{t('rollRunPausedTitle')}</p>
                                {reason === 'interrupted' ? (
                                    <>
                                        <p>{t('rollRunInterrupted').replace('{node}', node).replace('{phase}', (d && d.phase) || (r.resume_at && r.resume_at.phase) || '-')}</p>
                                        <p className="cr-muted">{t('rollRunInterruptedHint').replace('{node}', node)}</p>
                                    </>
                                ) : reason === 'quorum' ? (
                                    <>
                                        <p data-cr-upd-quorum="">{quorumText()}</p>
                                        {d && (d.offline || []).length > 0 && <p>{t('rollQuorumOffline').replace('{nodes}', d.offline.join(', '))}</p>}
                                        {d && d.qdevice && d.qdevice.present && !d.qdevice.connected && (
                                            <p>{(d.qdevice.not_connected || []).length > 0
                                                ? t('rollQuorumQdeviceNodes').replace('{nodes}', d.qdevice.not_connected.join(', ')) : t('rollQuorumQdevice')}</p>
                                        )}
                                        <p className="cr-muted">{t('rollQuorumHint').replace('{node}', node)}</p>
                                    </>
                                ) : d && d.message ? (
                                    <p data-cr-upd-paused-msg="">{crDash(d.message)}</p>
                                ) : (
                                    <p className="cr-muted">{d ? t('crUpdPausedNoText') : t('crUpdPausedHidden')}</p>
                                )}
                                {reason === 'evacuation_failures' && d && Array.isArray(d.failed_vms) && d.failed_vms.length > 0 && (
                                    <ul className="cr-upd-list" data-cr-upd-failed-vms="">
                                        {d.failed_vms.slice(0, 50).map((vm, i) => (
                                            <li key={i}><span className="cr-mono">{vm.name || '-'} ({vm.vmid})</span>{vm.error ? <span className="cr-muted"> - {crDash(vm.error)}</span> : null}</li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        </div>
                    )}
                    {view.cancelling && (
                        <p className="cr-upd-line" role="status" data-cr-upd-cancelling=""><span className="cr-spinner" aria-hidden="true" /> {t('rollRunCancelling')}</p>
                    )}
                    {active && !view.cancelling && (
                        <div className="cr-upd-run-actions" data-cr-upd-run-actions="">
                            {r.status === 'paused' && (
                                <CrButton variant="primary" icon={<Icons.Play />} onClick={onContinue} disabled={!canAct || needsReboot || busy}
                                    title={!canAct ? t('crUpdWhyPerm') : needsReboot ? t('crUpdWhyRebootPerm') : undefined} data-cr-upd-act="continue">
                                    {t('rollRunContinue')}
                                </CrButton>
                            )}
                            {r.status === 'paused' && reason === 'quorum' && (
                                <CrButton icon={<Icons.AlertTriangle />} onClick={onAnyway} disabled={!canAct || needsReboot || busy} data-cr-upd-act="anyway"
                                    title={!canAct ? t('crUpdWhyPerm') : needsReboot ? t('crUpdWhyRebootPerm') : undefined}>
                                    {t('rollQuorumContinueAnyway')}
                                </CrButton>
                            )}
                            <CrButton variant="danger" icon={<Icons.X />} onClick={onCancel} disabled={!canAct || busy} data-cr-upd-act="cancel"
                                title={!canAct ? t('crUpdWhyPerm') : undefined}>
                                {t('rollRunCancel')}
                            </CrButton>
                            {busy && <span className="cr-spinner" aria-hidden="true" />}
                            {needsReboot && r.status === 'paused' && <span className="cr-muted" data-cr-upd-needs-reboot="">{t('crUpdWhyRebootPerm')}</span>}
                        </div>
                    )}
                    {err && <p className="cr-upd-line cr-upd-bad" role="alert" data-cr-upd-act-error="">{crDash(err)}</p>}
                    {r.status === 'completed' && view.failed.length === 0 && <p className="cr-upd-line" data-cr-upd-run-ok="">{t('crUpdRunDoneNote')}</p>}
                    {(view.failed.length > 0 || r.error) && (
                        <div className="cr-upd-failed" data-cr-upd-run-failed="">
                            {r.error && <p className="cr-upd-line cr-upd-bad">{crDash(r.error)}</p>}
                            {view.failed.map((f, i) => (
                                <p key={i} className="cr-upd-line"><span className="cr-mono cr-upd-bad">{f.node}</span>{f.error ? <span className="cr-muted"> - {crDash(f.error)}</span> : null}</p>
                            ))}
                            {over && <p className="cr-sb-fine">{t('crUpdRunMaintNote')}</p>}
                        </div>
                    )}
                    {r.status === 'cancelled' && Array.isArray(r.cancel_report) && r.cancel_report.length > 0 && (
                        <div className="cr-upd-failed" data-cr-upd-cancel-report="">
                            <p className="cr-upd-line cr-upd-warn">{t('rollRunNotUndone')}</p>
                            {r.cancel_report.map((item, i) => <p key={i} className="cr-upd-line" data-kind={item.kind}>{undone(item)}</p>)}
                        </div>
                    )}
                    {over && <p className="cr-sb-fine" data-cr-upd-run-recheck="">{t('crUpdRunRecheck')}</p>}
                    {Array.isArray(r.logs) && r.logs.length > 0 ? (
                        <details className="cr-upd-log" data-cr-upd-log="">
                            <summary>{crFill(t('crUpdLog'), { n: r.logs.length })}</summary>
                            <pre className="cr-hd-pre">{r.logs.slice(-200).map(crDash).join('\n')}</pre>
                        </details>
                    ) : !Array.isArray(r.logs) ? <p className="cr-sb-fine">{t('crUpdLogHidden')}</p> : null}
                </section>
            );
        }

        // --- the start dialog -------------------------------------------------------------------------

        function CrUpdStartDialog({ cluster, model, canReboot, authFetch, holds, onCancel, onStarted }) {
            const { t } = useTranslation();
            const cid = cluster.id;
            const pve = model.kind === 'proxmox';
            const store = useCrUpd();
            const room = store.room[cid] || {};
            const rows = model.rows.filter(r => r.st !== 'unlisted');
            const selectable = (r) => r.st !== 'offline' && r.st !== 'updating';
            const [order, setOrder] = useState(() => rows.map(r => r.name));
            const [picked, setPicked] = useState(() => Object.fromEntries(rows.map(r => [r.name, r.st === 'online'])));
            const [o, setO] = useState({ include_reboot: false, wait_for_reboot: true, skip_up_to_date: true, pause_on_evacuation_error: true,
                                         skip_evacuation: false, allow_local_disks: false, evacuation_timeout: 1800, reboot_timeout: 600,
                                         ceph_health_gate: 'off' });
            const [mt, setMt] = useState(false);
            const [ra, setRa] = useState(false);
            const [ack, setAck] = useState(false);
            const [chosen, setChosen] = useState([]);
            const [channels, setChannels] = useState(null);
            const [ha, setHa] = useState(null);
            const [busy, setBusy] = useState(false);
            const [err, setErr] = useState('');
            const set = (k, v) => setO(p => ({ ...p, [k]: v }));
            // what the dialog reads when it opens: the evacuation plan (classic), the alert channels (classic)
            // and, for an account that may see it, the Proxmox HA resources for the advisory
            const plan = useEvacPlan(`${API_URL}/clusters/${encodeURIComponent(cid)}/updates/rolling/plan`, pve);
            useEffect(() => {
                let gone = false;
                crDcGet(authFetch, `${API_URL}/alert-channels`).then(r => {
                    if (gone) return;
                    const b = r.state === 'ok' ? r.body : null;
                    setChannels(Array.isArray(b) ? b : (b && Array.isArray(b.channels) ? b.channels : []));
                });
                if (pve && holds('ha.view')) {
                    crDcGet(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/proxmox-ha/resources`).then(r => { if (!gone) setHa(r); });
                }
                return () => { gone = true; };
            }, []);
            const byName = Object.fromEntries(rows.map(r => [r.name, r]));
            const list = order.filter(n => byName[n]);
            const selected = list.filter(n => picked[n] && selectable(byName[n]));
            const move = (n, d) => setOrder(prev => {
                const i = prev.indexOf(n), j = i + d;
                if (i < 0 || j < 0 || j >= prev.length) return prev;
                const next = prev.slice();
                [next[i], next[j]] = [next[j], next[i]];
                return next;
            });
            const offline = rows.filter(r => r.st === 'offline').map(r => r.name);
            const maint = rows.filter(r => r.st === 'maintenance').map(r => r.name);
            const updating = rows.filter(r => r.st === 'updating').map(r => r.name);
            const kernelSel = selected.filter(n => byName[n].kernel).length;
            const single = rows.length === 1;
            const blocked = !selected.length || (o.skip_evacuation && !ack) || busy;
            const haCount = ha && ha.state === 'ok' && Array.isArray(ha.body) ? ha.body.length : null;

            const start = async () => {
                if (blocked) return;
                setBusy(true);
                setErr('');
                const body = {
                    include_reboot: !!(o.include_reboot && canReboot), wait_for_reboot: !!o.wait_for_reboot, skip_up_to_date: !!o.skip_up_to_date,
                    skip_evacuation: !!o.skip_evacuation, pause_on_evacuation_error: !!o.pause_on_evacuation_error,
                    allow_local_disks: !!o.allow_local_disks, evacuation_timeout: o.evacuation_timeout, reboot_timeout: o.reboot_timeout,
                    ceph_health_gate: o.ceph_health_gate, notify_channels: chosen.slice(),
                    migrate_templates: !!(mt && !o.skip_evacuation), relax_anti_affinity: !!(ra && !o.skip_evacuation),
                    node_order: selected.slice(),
                };
                const r = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/updates/rolling`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
                });
                const d = r ? await r.json().catch(() => null) : null;
                setBusy(false);
                if (r && r.ok && d && d.success) onStarted();
                else setErr((d && d.error) || (r ? `HTTP ${r.status}` : t('crDcNoAnswer')));
            };
            const tsel = (k, disabled) => (
                <select className="cr-select" value={o[k]} disabled={disabled} onChange={e => set(k, parseInt(e.target.value, 10))} data-cr-upd-opt={k}>
                    {CR_UPD_TIMEOUTS.map(s => <option key={s} value={s}>{crUpdSecs(s)}</option>)}
                </select>
            );
            const tick = (k, label, hint, disabled, title) => (
                <label className={`cr-upd-opt${disabled ? ' cr-upd-opt-off' : ''}`} title={title}>
                    <input type="checkbox" checked={!!o[k] && !disabled} disabled={disabled} onChange={e => set(k, e.target.checked)} data-cr-upd-opt={k} />
                    <span><span className="cr-strong">{label}</span>{hint && <span className="cr-upd-hint">{hint}</span>}</span>
                </label>
            );
            const roomView = () => {
                if (room.busy) return <span role="status"><span className="cr-spinner" aria-hidden="true" /> {t('crUpdRoomRunning')}</span>;
                if (room.error) return <span className="cr-upd-bad">{crFill(t('crUpdRoomFailed'), { why: [room.error.msg, room.error.code ? `HTTP ${room.error.code}` : ''].filter(Boolean).join(' - ') || t('crDcNoAnswer') })}</span>;
                if (!room.report) return <span className="cr-muted">{t('crUpdRoomNotRun')}</span>;
                const h = room.report.headroom || {};
                const bad = (h.combinations || []).filter(x => !x.ok);
                return (
                    <span data-cr-upd-room-result={h.ok ? 'ok' : 'failing'}>
                        {h.ok ? crFill(t('crUpdRoomOk'), { n: h.checked || 0 }) : crFill(t('crUpdRoomBad'), { n: h.failing || bad.length, total: h.checked || 0 })}
                        {bad.slice(0, 5).map(x => (
                            <span key={(x.failed || []).join('+')} className="cr-upd-room-row">
                                {crFill(t('crUpdRoomRow'), { node: (x.failed || []).join(', '), unplaced: x.unplaced ?? '-', over: [...(x.over_mem || []), ...(x.over_cpu || [])].join(', ') || '-' })}
                            </span>
                        ))}
                        <span className="cr-muted"> {crFill(t('crUpdRoomAt'), { time: crFmtTime(room.at) })}</span>
                    </span>
                );
            };
            return (
                <CrUpdDialog id="start" wide sticky busy={busy} title={crFill(t('crUpdStartTitle'), { cluster: clusterLabel(cluster) })}
                    sub={t('crUpdStartSub')} onCancel={onCancel}
                    footer={(
                        <>
                            {o.skip_evacuation && !ack && <span className="cr-sb-blocked" data-cr-upd-needs-ack="">{t('crUpdNeedsAck')}</span>}
                            <CrButton onClick={onCancel} disabled={busy} data-cr-upd-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" icon={busy ? <span className="cr-spinner" /> : <Icons.Play />} disabled={blocked} onClick={start} data-cr-upd-confirm="start">
                                {crFill(t('crUpdStartGo'), { n: selected.length })}
                            </CrButton>
                        </>
                    )}>
                    {err && <CrUpdNote tone="error" id="start-refused"><p>{crDash(err)}</p></CrUpdNote>}
                    <div className="cr-upd-start">
                        <section className="cr-upd-start-nodes" aria-label={t('crUpdOrder')}>
                            <h3 className="cr-hd-h">{t('crUpdOrder')}</h3>
                            <ol className="cr-upd-order" data-cr-upd-order="">
                                {list.map((n, i) => {
                                    const r = byName[n];
                                    const why = r.st === 'offline' ? t('crUpdOrderOffline') : r.st === 'updating' ? t('crUpdOrderUpdating') : '';
                                    return (
                                        <li key={n} className="cr-upd-order-row" data-cr-upd-node={n} data-state={r.st}>
                                            <input type="checkbox" checked={!!picked[n] && selectable(r)} disabled={!selectable(r)}
                                                onChange={e => setPicked(p => ({ ...p, [n]: e.target.checked }))} title={why || undefined}
                                                aria-label={crFill(t('crUpdPickNode'), { node: n })} data-cr-upd-pick={n} />
                                            <span className="cr-mono cr-upd-order-name">{n}</span>
                                            <span className="cr-upd-order-st">
                                                {r.st !== 'online' && <CrBadge tone={crUpdStTone(r.st)}>{t(CR_UPD_ST_KEY[r.st])}</CrBadge>}
                                                {r.pending === 'ok' ? <span className="cr-muted">{r.count > 0 ? crFill(t('crUpdNPkgs'), { n: r.count }) : t('crUpdUpToDate')}</span>
                                                    : r.pending === 'failed' ? <span className="cr-upd-warn">{t('crUpdPendFailed')}</span> : null}
                                                {r.kernel && <span className="cr-muted"> · {t('crUpdKernelShort')}</span>}
                                            </span>
                                            <span className="cr-upd-order-move">
                                                <button type="button" className="cr-icon-btn" disabled={i === 0} onClick={() => move(n, -1)}
                                                    aria-label={crFill(t('crUpdUp'), { node: n })} title={t('crUpdUpShort')} data-cr-upd-up={n}>
                                                    <span className="cr-ico" aria-hidden="true"><Icons.ChevronUp /></span>
                                                </button>
                                                <button type="button" className="cr-icon-btn" disabled={i === list.length - 1} onClick={() => move(n, 1)}
                                                    aria-label={crFill(t('crUpdDown'), { node: n })} title={t('crUpdDownShort')} data-cr-upd-down={n}>
                                                    <span className="cr-ico" aria-hidden="true"><Icons.ChevronDown /></span>
                                                </button>
                                            </span>
                                        </li>
                                    );
                                })}
                            </ol>
                            <p className="cr-sb-fine" data-cr-upd-order-note="">
                                {crFill(t('crUpdOrderNote'), { n: selected.length })} {o.skip_up_to_date ? t('crUpdOrderSkipNote') : ''}
                            </p>
                            {maint.length > 0 && <p className="cr-upd-line cr-upd-warn" data-cr-upd-maint-note="">{crFill(t('crUpdMaintNote'), { nodes: maint.join(', ') })}</p>}
                        </section>
                        <section className="cr-upd-start-opts" aria-label={t('crUpdOptions')}>
                            <h3 className="cr-hd-h">{t('crUpdOptions')}</h3>
                            {tick('include_reboot', t('crUpdReboot'), canReboot ? (kernelSel ? crFill(t('crUpdRebootKernel'), { n: kernelSel }) : t('crUpdRebootHint')) : t('crUpdWhyRebootPerm'),
                                !canReboot, !canReboot ? t('crUpdWhyRebootPerm') : undefined)}
                            {o.include_reboot && canReboot && (
                                <div className="cr-upd-sub">
                                    {tick('wait_for_reboot', t('crUpdWaitReboot'), t('crUpdWaitRebootHint'))}
                                    <label className="cr-upd-field"><span className="cr-muted">{t('crUpdRebootTimeout')}</span>{tsel('reboot_timeout', !o.wait_for_reboot)}</label>
                                    {single && <p className="cr-upd-line cr-upd-bad" data-cr-upd-single="">{t('crUpdSingleReboot')}</p>}
                                </div>
                            )}
                            {tick('skip_up_to_date', t('crUpdSkipUpToDate'), t('crUpdSkipUpToDateHint'))}
                            {tick('pause_on_evacuation_error', t('crUpdPauseEvac'), t('crUpdPauseEvacHint'), o.skip_evacuation)}
                            {tick('allow_local_disks', t('crUpdLocalDisks'), t('crUpdLocalDisksHint'), o.skip_evacuation)}
                            <label className="cr-upd-field"><span className="cr-muted">{t('crUpdEvacTimeout')}</span>{tsel('evacuation_timeout', o.skip_evacuation)}</label>
                            {pve && (
                                <label className="cr-upd-field">
                                    <span className="cr-muted">{t('cephHealthGate')}</span>
                                    <select className="cr-select" value={o.ceph_health_gate} onChange={e => set('ceph_health_gate', e.target.value)} data-cr-upd-opt="ceph_health_gate">
                                        <option value="off">{crDash(t('cephGateOff'))}</option>
                                        <option value="degraded">{crDash(t('cephGateDegraded'))}</option>
                                        <option value="strict">{crDash(t('cephGateStrict'))}</option>
                                    </select>
                                </label>
                            )}
                            {pve && (
                                <div className="cr-upd-evac">
                                    <EvacOptions kind="rolling" plan={plan} skip={o.skip_evacuation} migrateTemplates={mt} setMigrateTemplates={setMt}
                                        relaxAntiAffinity={ra} setRelaxAntiAffinity={setRa} />
                                </div>
                            )}
                            {channels && channels.length > 0 && (
                                <div className="cr-upd-field cr-upd-channels">
                                    <span className="cr-muted">{t('notifyChannelsLabel')}</span>
                                    <span className="cr-upd-chan-list">
                                        {channels.map(ch => {
                                            const on = chosen.includes(ch.id);
                                            return (
                                                <button key={ch.id} type="button" className={`cr-btn cr-btn-xs${on ? ' cr-btn-primary' : ''}`} aria-pressed={on}
                                                    onClick={() => setChosen(p => (on ? p.filter(x => x !== ch.id) : p.concat([ch.id])))} data-cr-upd-channel={ch.id}>
                                                    {ch.name || ch.id}
                                                </button>
                                            );
                                        })}
                                    </span>
                                </div>
                            )}
                            <label className="cr-upd-opt cr-upd-opt-danger">
                                <input type="checkbox" checked={o.skip_evacuation} onChange={e => { set('skip_evacuation', e.target.checked); setAck(false); }} data-cr-upd-opt="skip_evacuation" />
                                <span><span className="cr-strong">{t('crUpdSkipEvac')}</span><span className="cr-upd-hint">{t('crUpdSkipEvacHint')}</span></span>
                            </label>
                            {o.skip_evacuation && (
                                <div className="cr-callout cr-callout-error" data-cr-upd-danger="skip_evacuation">
                                    <Icons.AlertCircle className="w-4 h-4" />
                                    <div>
                                        <p>{o.include_reboot ? t('crUpdSkipEvacDangerReboot') : t('crUpdSkipEvacDanger')}</p>
                                        <label className="cr-hd-tick">
                                            <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} data-cr-upd-ack="skip_evacuation" />
                                            <span>{t('crUpdSkipEvacAck')}</span>
                                        </label>
                                    </div>
                                </div>
                            )}
                            <p className="cr-sb-fine">{t('crUpdUpdateTimeoutNote')}</p>
                        </section>
                    </div>
                    <section className="cr-upd-advice" data-cr-upd-advisory="" aria-label={t('crUpdAdviceTitle')}>
                        <h3 className="cr-hd-h">{t('crUpdAdviceTitle')} <span className="cr-upd-basis" data-cr-upd-basis="">{t('crUpdAdviceBasis')}</span></h3>
                        <ul className="cr-sb-risks">
                            <li className={`cr-sb-risk cr-sb-risk-${offline.length ? 'warn' : 'info'}`} data-cr-upd-advice="offline">
                                <span className="cr-ico" aria-hidden="true">{offline.length ? <Icons.AlertTriangle /> : <Icons.Info />}</span>
                                <span>{offline.length ? crFill(t('crUpdAdvOffline'), { nodes: offline.join(', ') }) : t('crUpdAdvNoOffline')}</span>
                            </li>
                            {maint.length > 0 && (
                                <li className="cr-sb-risk cr-sb-risk-warn" data-cr-upd-advice="maintenance">
                                    <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                    <span>{crFill(t('crUpdAdvMaint'), { nodes: maint.join(', ') })}</span>
                                </li>
                            )}
                            {updating.length > 0 && (
                                <li className="cr-sb-risk cr-sb-risk-warn" data-cr-upd-advice="updating">
                                    <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                    <span>{crFill(t('crUpdAdvUpdating'), { nodes: updating.join(', ') })}</span>
                                </li>
                            )}
                            {pve && (
                                <li className="cr-sb-risk cr-sb-risk-info" data-cr-upd-advice="ha">
                                    <span className="cr-ico" aria-hidden="true"><Icons.Info /></span>
                                    <span>{!holds('ha.view') ? t('crUpdAdvHaNoAccess') : !ha ? t('crUpdAdvHaReading')
                                        : haCount == null ? crFill(t('crUpdAdvHaUnread'), { why: crDcWhy(ha, t) }) : crFill(t('crUpdAdvHa'), { n: haCount })}</span>
                                </li>
                            )}
                            <li className="cr-sb-risk cr-sb-risk-info" data-cr-upd-advice="headroom">
                                <span className="cr-ico" aria-hidden="true"><Icons.Scale /></span>
                                <span className="cr-upd-room">
                                    {holds('cluster.view') ? roomView() : <span className="cr-muted">{t('crUpdRoomNoAccess')}</span>}
                                    {holds('cluster.view') && (
                                        <button type="button" className="cr-btn cr-btn-xs" disabled={!!room.busy} onClick={() => crUpdRunHeadroom(authFetch, cid)} data-cr-upd-room="">
                                            {room.report ? t('crUpdRoomAgain') : t('crUpdRoomRun')}
                                        </button>
                                    )}
                                </span>
                            </li>
                        </ul>
                        <p className="cr-sb-fine">{t('crUpdRoomBasis')}</p>
                    </section>
                    <section className="cr-upd-gates" data-cr-upd-gates="" aria-label={t('crUpdGatesTitle')}>
                        <h3 className="cr-hd-h">{t('crUpdGatesTitle')}</h3>
                        <ul className="cr-upd-gate-list">
                            {CR_UPD_GATES.map(k => <li key={k} data-cr-upd-gate={k}>{t(k)}</li>)}
                        </ul>
                        <h3 className="cr-hd-h">{t('crUpdNotGatesTitle')}</h3>
                        <ul className="cr-upd-gate-list cr-upd-gate-not">
                            {CR_UPD_NOT_GATES.map(k => <li key={k} data-cr-upd-notgate={k}>{t(k)}</li>)}
                        </ul>
                    </section>
                </CrUpdDialog>
            );
        }

        // --- the schedule: card and dialog -------------------------------------------------------------

        function CrUpdScheduleDialog({ cluster, sched, canReboot, pve, authFetch, onCancel, onSaved }) {
            const { t } = useTranslation();
            const s = sched || {};
            const armed = s.enabled === true;
            const [f, setF] = useState(() => ({
                enabled: armed, schedule_type: s.schedule_type === 'once' ? 'once' : 'recurring',
                day: CR_UPD_DAYS.includes(s.day) || s.day === 'daily' ? s.day : 'sunday',
                time: /^\d{2}:\d{2}$/.test(String(s.time || '')) ? s.time : '03:00',
                // an armed schedule keeps what it has; a new or switched off one starts without a reboot
                include_reboot: armed ? s.include_reboot !== false : false,
                skip_evacuation: armed ? s.skip_evacuation === true : false,
                evacuation_timeout: CR_UPD_TIMEOUTS.includes(s.evacuation_timeout) ? s.evacuation_timeout : 1800,
                reboot_timeout: CR_UPD_TIMEOUTS.includes(s.reboot_timeout) ? s.reboot_timeout : 600,
            }));
            const [mt, setMt] = useState(s.migrate_templates === true);
            const [ra, setRa] = useState(s.relax_anti_affinity === true);
            const [ack, setAck] = useState(false);
            const [busy, setBusy] = useState(false);
            const [err, setErr] = useState('');
            const set = (k, v) => setF(p => ({ ...p, [k]: v }));
            const plan = useEvacPlan(`${API_URL}/clusters/${encodeURIComponent(cluster.id)}/updates/rolling/plan`, pve);
            const day = f.schedule_type === 'once' && f.day === 'daily' ? 'sunday' : f.day;
            const rebootOn = f.include_reboot && canReboot;
            // the stored schedule reboots; without node.reboot the server refuses that, so this save drops it
            const dropsReboot = armed && s.include_reboot !== false && !canReboot && f.enabled;
            const blocked = busy || (f.enabled && f.skip_evacuation && !ack);
            const save = async () => {
                if (blocked) return;
                setBusy(true);
                setErr('');
                // every flag explicit: the route defaults include_reboot to true when it is missing
                const body = {
                    enabled: !!f.enabled, schedule_type: f.schedule_type, day, time: f.time,
                    include_reboot: !!rebootOn, skip_evacuation: !!f.skip_evacuation, skip_up_to_date: true, wait_for_reboot: true,
                    evacuation_timeout: f.evacuation_timeout, reboot_timeout: f.reboot_timeout,
                    migrate_templates: !!(mt && !f.skip_evacuation), relax_anti_affinity: !!(ra && !f.skip_evacuation),
                };
                const r = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cluster.id)}/updates/schedule`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
                });
                const d = r ? await r.json().catch(() => null) : null;
                setBusy(false);
                if (r && r.ok && d && d.success) onSaved();
                else setErr((d && d.error) || (r ? `HTTP ${r.status}` : t('crDcNoAnswer')));
            };
            const tsel = (k, disabled) => (
                <select className="cr-select" value={f[k]} disabled={disabled} onChange={e => set(k, parseInt(e.target.value, 10))} data-cr-upd-sopt={k}>
                    {CR_UPD_TIMEOUTS.map(v => <option key={v} value={v}>{crUpdSecs(v)}</option>)}
                </select>
            );
            const when = f.schedule_type === 'once' ? crFill(t('crUpdSchedOnceAt'), { day: t(day), time: f.time })
                : day === 'daily' ? crFill(t('crUpdSchedDailyAt'), { time: f.time }) : crFill(t('crUpdSchedWeeklyAt'), { day: t(day), time: f.time });
            return (
                <CrUpdDialog id="schedule" sticky busy={busy} title={crFill(t('crUpdSchedTitle'), { cluster: clusterLabel(cluster) })}
                    sub={t('crUpdSchedSub')} onCancel={onCancel}
                    footer={(
                        <>
                            {f.enabled && f.skip_evacuation && !ack && <span className="cr-sb-blocked">{t('crUpdNeedsAck')}</span>}
                            <CrButton onClick={onCancel} disabled={busy} data-cr-upd-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" icon={busy ? <span className="cr-spinner" /> : <Icons.Save />} disabled={blocked} onClick={save} data-cr-upd-confirm="schedule">
                                {f.enabled ? t('crUpdSchedArm') : t('crUpdSchedSaveOff')}
                            </CrButton>
                        </>
                    )}>
                    {err && <CrUpdNote tone="error" id="schedule-refused"><p>{crDash(err)}</p></CrUpdNote>}
                    <label className="cr-upd-opt">
                        <input type="checkbox" checked={f.enabled} onChange={e => set('enabled', e.target.checked)} data-cr-upd-sopt="enabled" />
                        <span><span className="cr-strong">{t('crUpdSchedEnable')}</span><span className="cr-upd-hint">{t('crUpdSchedEnableHint')}</span></span>
                    </label>
                    <div className="cr-upd-sched-grid">
                        <label className="cr-upd-field">
                            <span className="cr-muted">{t('scheduleType')}</span>
                            <select className="cr-select" value={f.schedule_type} onChange={e => set('schedule_type', e.target.value)} data-cr-upd-sopt="schedule_type">
                                <option value="recurring">{t('recurring')}</option>
                                <option value="once">{t('runOnce')}</option>
                            </select>
                        </label>
                        <label className="cr-upd-field">
                            <span className="cr-muted">{t('updateDay')}</span>
                            <select className="cr-select" value={day} onChange={e => set('day', e.target.value)} data-cr-upd-sopt="day">
                                {CR_UPD_DAYS.map(d => <option key={d} value={d}>{t(d)}</option>)}
                                {f.schedule_type === 'recurring' && <option value="daily">{t('crUpdDaily')}</option>}
                            </select>
                        </label>
                        <label className="cr-upd-field">
                            <span className="cr-muted">{t('crUpdTimeServer')}</span>
                            <input type="time" className="cr-input" value={f.time} onChange={e => set('time', e.target.value || '03:00')} data-cr-upd-sopt="time" />
                        </label>
                    </div>
                    <label className={`cr-upd-opt${!canReboot ? ' cr-upd-opt-off' : ''}`} title={!canReboot ? t('crUpdWhyRebootPerm') : undefined}>
                        <input type="checkbox" checked={rebootOn} disabled={!canReboot} onChange={e => set('include_reboot', e.target.checked)} data-cr-upd-sopt="include_reboot" />
                        <span><span className="cr-strong">{t('crUpdReboot')}</span><span className="cr-upd-hint">{canReboot ? t('crUpdSchedRebootHint') : t('crUpdWhyRebootPerm')}</span></span>
                    </label>
                    {dropsReboot && <CrUpdNote tone="warning" id="reboot-dropped"><p>{t('crUpdSchedDropsReboot')}</p></CrUpdNote>}
                    <div className="cr-upd-sched-grid">
                        <label className="cr-upd-field"><span className="cr-muted">{t('crUpdEvacTimeout')}</span>{tsel('evacuation_timeout', f.skip_evacuation)}</label>
                        <label className="cr-upd-field"><span className="cr-muted">{t('crUpdRebootTimeout')}</span>{tsel('reboot_timeout', !rebootOn)}</label>
                    </div>
                    {pve && (
                        <div className="cr-upd-evac">
                            <EvacOptions kind="schedule" plan={plan} skip={f.skip_evacuation} migrateTemplates={mt} setMigrateTemplates={setMt}
                                relaxAntiAffinity={ra} setRelaxAntiAffinity={setRa} />
                        </div>
                    )}
                    <label className="cr-upd-opt cr-upd-opt-danger">
                        <input type="checkbox" checked={f.skip_evacuation} onChange={e => { set('skip_evacuation', e.target.checked); setAck(false); }} data-cr-upd-sopt="skip_evacuation" />
                        <span><span className="cr-strong">{t('crUpdSkipEvac')}</span><span className="cr-upd-hint">{t('crUpdSkipEvacHint')}</span></span>
                    </label>
                    {f.enabled && f.skip_evacuation && (
                        <div className="cr-callout cr-callout-error" data-cr-upd-danger="schedule-skip">
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div>
                                <p>{rebootOn ? t('crUpdSkipEvacDangerReboot') : t('crUpdSkipEvacDanger')}</p>
                                <label className="cr-hd-tick">
                                    <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} data-cr-upd-ack="schedule-skip" />
                                    <span>{t('crUpdSkipEvacAck')}</span>
                                </label>
                            </div>
                        </div>
                    )}
                    <CrUpdNote tone="warning" id="scheduled-worker"><p>{t('crUpdSchedWorker')}</p></CrUpdNote>
                    <p className="cr-upd-line" data-cr-upd-sched-summary="">
                        {f.enabled ? crFill(t('crUpdSchedWillArm'), { when, reboot: rebootOn ? t('crUpdWithReboot') : t('crUpdWithoutReboot') }) : t('crUpdSchedWillOff')}
                    </p>
                    <p className="cr-sb-fine">{t('crUpdSchedFoot')}</p>
                </CrUpdDialog>
            );
        }

        function CrUpdSchedCard({ sched, t, canEdit, why, onEdit, onHistory }) {
            const s = sched && sched.state === 'ok' ? sched.body : null;
            const day = (d) => (d === 'daily' ? t('crUpdDaily') : t(d || 'sunday'));
            return (
                <section className="cr-panel cr-upd-card" tabIndex={-1} data-cr-focus-home="" data-cr-upd-card="schedule" aria-label={t('crUpdSchedCard')}>
                    <header className="cr-upd-card-head">
                        <span className="cr-ico" aria-hidden="true"><Icons.Clock /></span>
                        <h3 className="cr-panel-title">{t('crUpdSchedCard')}</h3>
                        {s && <CrBadge tone={s.enabled ? 'info' : 'neutral'}>{s.enabled ? t('crUpdSchedOn') : t('crUpdSchedOff')}</CrBadge>}
                    </header>
                    {!sched ? <p className="cr-upd-line cr-muted" role="status">{t('crUpdReading')}</p>
                        : !s ? <p className="cr-upd-line cr-upd-warn" data-cr-upd-sched-state={sched.state}>{sched.state === 'forbidden' ? t('crUpdSchedNoAccess') : crFill(t('crUpdSchedUnread'), { why: crDcWhy(sched, t) })}</p>
                        : (
                            <dl className="cr-upd-dl" data-cr-upd-sched-state={s.enabled ? 'armed' : 'off'}>
                                {s.enabled ? (
                                    <>
                                        <dt>{t('crUpdSchedWhen')}</dt>
                                        <dd data-cr-upd-sched-when="">{s.schedule_type === 'once' ? crFill(t('crUpdSchedOnceAt'), { day: day(s.day), time: s.time })
                                            : s.day === 'daily' ? crFill(t('crUpdSchedDailyAt'), { time: s.time }) : crFill(t('crUpdSchedWeeklyAt'), { day: day(s.day), time: s.time })}</dd>
                                        <dt>{t('crUpdSchedNext')}</dt>
                                        <dd data-cr-upd-sched-next="">{s.next_run ? `${s.next_run} ${t('crUpdServerTime')}` : <span className="cr-muted">{t('crUpdSchedNoNext')}</span>}</dd>
                                        <dt>{t('crUpdRebootCol')}</dt>
                                        <dd>{s.include_reboot ? t('yes') : t('no')}{s.skip_evacuation ? <span className="cr-upd-bad"> · {t('crUpdSkipEvac')}</span> : null}</dd>
                                    </>
                                ) : (
                                    <>
                                        <dt>{t('crUpdSchedState')}</dt>
                                        <dd>{t('crUpdSchedOffText')}</dd>
                                    </>
                                )}
                                <dt>{t('crUpdSchedLast')}</dt>
                                <dd data-cr-upd-sched-last="">
                                    {/* the server clears last_run on every save of the schedule: no value is no proof it never ran */}
                                    {s.last_run ? crFill(t('crUpdSchedLastStart'), { time: s.last_run }) : <span className="cr-muted" data-cr-upd-sched-nolast="">{t('crUpdSchedNever')}</span>}
                                    {onHistory && <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={onHistory} data-cr-upd-sched-history="">{t('crUpdOpenHistory')}</button>}
                                </dd>
                            </dl>
                        )}
                    {s && s.enabled && <p className="cr-sb-fine cr-upd-warn" data-cr-upd-sched-worker="" title={t('crUpdSchedWorker')}>{t('crUpdSchedWorkerShort')}</p>}
                    <div className="cr-upd-card-foot">
                        <CrButton icon={<Icons.Edit />} onClick={onEdit} disabled={!canEdit || !s} title={why || undefined} data-cr-upd-open="schedule">
                            {t('crUpdSchedEdit')}
                        </CrButton>
                        {why && <span className="cr-muted cr-upd-why">{why}</span>}
                    </div>
                </section>
            );
        }

        // --- the side panel of a node: its packages -----------------------------------------------------

        function CrUpdNodeDetail({ row, chk, model, kind, may, authFetch, cid, nav, t }) {
            const held = chk && chk.answer && chk.answer.body && chk.answer.body.nodes ? chk.answer.body.nodes[row.name] : null;
            const [live, setLive] = useState(null);
            const [all, setAll] = useState(false);
            const canFetch = may && !held && row.st !== 'offline' && row.st !== 'unlisted' && model.state !== 'confined' && kind !== 'esxi';
            useEffect(() => {
                if (!canFetch) return undefined;
                let gone = false;
                setLive({ busy: true });
                crDcGet(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/nodes/${encodeURIComponent(row.name)}/apt/updates`)
                    .then(r => { if (!gone) setLive({ r, at: Date.now() }); });
                return () => { gone = true; };
            }, [row.name, !!held]);
            const m = row.m || {};
            let src = null, list = null, why = '';
            if (held) {
                src = 'check';
                if (held.success === false) why = held.error || t('checkFailed');
                else list = Array.isArray(held.updates) ? held.updates : [];
            } else if (live && live.r) {
                src = 'node';
                if (live.r.state === 'ok' && Array.isArray(live.r.body)) list = live.r.body;
                else why = live.r.state === 'forbidden' ? t('crUpdPkgNoAccess') : crDcWhy(live.r, t);
            }
            const shown = list ? (all ? list : list.slice(0, CR_UPD.rows)) : [];
            const proxmox = list ? list.filter(p => p && p.Origin === 'Proxmox').length : 0;
            const kernels = list ? list.filter(p => crUpdKernelKind(p && p.Package) === 'image').length : 0;
            return (
                <div className="cr-upd-detail" data-cr-upd-detail={row.name}>
                    <dl className="cr-hd-dl">
                        <dt>{t('status')}</dt>
                        <dd><CrBadge tone={crUpdStTone(row.st)}>{t(CR_UPD_ST_KEY[row.st])}</CrBadge></dd>
                        {kind === 'proxmox' && <><dt>{t('crUpdPveVersion')}</dt><dd className="cr-mono">{m.pveversion || <span className="cr-muted">{t('crUpdNotReported')}</span>}</dd></>}
                        <dt>{t('crUpdRunningKernel')}</dt>
                        <dd className="cr-mono" title={t('crUpdRunningKernelHint')}>{m.kversion || <span className="cr-muted">{t('crUpdNotReported')}</span>}</dd>
                        <dt>{t('allUpdatesRepo')}</dt>
                        <dd>{row.channel ? crUpdChannel(t, row.channel) : <span className="cr-muted">{t('crUpdNotReported')}</span>}
                            {row.warnings > 0 && <span className="cr-upd-warn"> · {t('allUpdatesRepoWarnings').replace('{n}', row.warnings)}</span>}</dd>
                        <dt>{t('allUpdatesSubscription')}</dt>
                        <dd>{row.subscription ? crUpdSub(t, row.subscription) : <span className="cr-muted">{t('crUpdNotReported')}</span>}
                            {row.channel === 'enterprise' && row.subscription && row.subscription !== 'active' && <span className="cr-upd-warn"> · {t('allUpdatesEnterpriseNoSub')}</span>}</dd>
                        <dt>{t('crUpdPendingCol')}</dt>
                        <dd data-cr-upd-detail-pending={row.pending}>{crUpdPendingText(t, row, model)}</dd>
                        <dt>{t('crUpdSecurityCol')}</dt>
                        <dd className="cr-muted">{kind === 'xcpng' && row.h && typeof row.h.security === 'number' ? crFill(t('crUpdSecXcp'), { n: row.h.security }) : t('crUpdSecNotReported')}</dd>
                    </dl>
                    <h3 className="cr-hd-h">{t('crUpdPackages')}</h3>
                    <p className="cr-sb-fine" data-cr-upd-pkg-source={src || 'none'}>
                        {src === 'check' ? crFill(t('crUpdPkgFromCheck'), { time: crFmtTime(chk.answer.at), server: (chk.answer.body.summary || {}).checked_at || '-' })
                            : src === 'node' ? crFill(t('crUpdPkgFromNode'), { time: crFmtTime(live.at) })
                            : row.st === 'offline' ? t('crUpdPkgOffline') : model.state === 'confined' ? t('crUpdWhyConfined')
                            : !may ? t('crUpdPkgNoAccess') : live && live.busy ? t('crUpdReading') : t('crUpdPkgNone')}
                    </p>
                    {why && <p className="cr-upd-line cr-upd-bad" role="alert" data-cr-upd-pkg-error="">{crDash(why)}</p>}
                    {list && (list.length === 0 ? (
                        <p className="cr-upd-line" data-cr-upd-pkg-empty="">{src === 'check' ? t('crUpdPkgEmptyCheck') : t('crUpdPkgEmptyNode')}</p>
                    ) : (
                        <>
                            <p className="cr-upd-line" data-cr-upd-pkg-counts="">{crFill(t('crUpdPkgCounts'), { n: list.length, pve: proxmox, kernel: kernels })}</p>
                            <div className="cr-upd-pkgs-wrap">
                                <table className="cr-upd-pkgs" data-cr-upd-pkgs="">
                                    <thead>
                                        <tr>
                                            <th scope="col">{t('package')}</th>
                                            <th scope="col">{t('currentVersion')}</th>
                                            <th scope="col">{t('newVersion')}</th>
                                            <th scope="col">{t('crUpdOrigin')}</th>
                                            <th scope="col">{t('crUpdKind')}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {shown.map((p, i) => {
                                            const k = crUpdKernelKind(p && p.Package);
                                            return (
                                                <tr key={`${p.Package}-${i}`} data-cr-upd-pkg={p.Package || ''}>
                                                    <td className="cr-mono">{p.Package || '-'}</td>
                                                    <td className="cr-mono cr-upd-ver">{p.OldVersion || <span className="cr-muted" title={t('crUpdNewPkgHint')}>{t('crUpdNewPkg')}</span>}</td>
                                                    <td className="cr-mono cr-upd-ver">{p.Version || '-'}</td>
                                                    <td>{p.Origin || '-'}</td>
                                                    <td>
                                                        {k === 'image' && <span data-cr-upd-flag="kernel"><CrBadge tone="warning" dot={false} title={t('crUpdKernelHint')}>{t('crUpdKernelShort')}</CrBadge></span>}
                                                        {k === 'helper' && <span data-cr-upd-flag="helper"><CrBadge tone="neutral" dot={false}>{t('crUpdKernelHelper')}</CrBadge></span>}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                            {list.length > shown.length && (
                                <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={() => setAll(true)} data-cr-upd-pkg-all="">
                                    {crFill(t('crUpdPkgAll'), { n: list.length })}
                                </button>
                            )}
                            <p className="cr-sb-fine">{t('crUpdPkgFoot')}</p>
                        </>
                    ))}
                    {nav && nav.openNode && row.st !== 'unlisted' && (
                        <div className="cr-upd-card-foot">
                            <CrButton icon={<Icons.Server />} onClick={() => nav.openNode(cid, row.name)} data-cr-upd-open-node={row.name}>{t('crUpdOpenNode')}</CrButton>
                        </div>
                    )}
                </div>
            );
        }

        function crUpdChannel(t, c) {
            return { enterprise: t('allUpdatesEnterprise'), 'no-subscription': t('allUpdatesNoSubscription'), test: t('allUpdatesTest'),
                     mixed: t('allUpdatesMixed'), none: t('allUpdatesNoRepo') }[c] || c;
        }
        function crUpdSub(t, s) {
            return { active: t('allUpdatesSubActive'), notfound: t('allUpdatesSubNone'), new: t('allUpdatesSubNew'), invalid: t('allUpdatesSubInvalid'),
                     expired: t('allUpdatesSubExpired'), suspended: t('allUpdatesSubSuspended'), unknown: t('allUpdatesSubUnknown') }[s] || s;
        }
        function crUpdPendingText(t, r, model) {
            if (r.pending === 'ok') return r.count > 0 ? String(r.count) : t('crUpdUpToDate');
            if (r.pending === 'failed') return t('crUpdPendFailed');
            if (r.pending === 'missing') return t('crUpdPendMissing');
            if (r.pending === 'unchecked') return t('crUpdPendUnchecked');
            return model.state === 'confined' ? t('crUpdWhyConfined') : '-';
        }

        // --- the page ----------------------------------------------------------------------------------

        function CrUpdates({ cluster, metrics, nav, authFetch }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const { holds, can } = crVmCan();
            const store = useCrUpd();
            const c = cluster || {};
            const cid = c.id;
            const kind = c.cluster_type || 'proxmox';
            const canView = holds('node.view');
            const [ov, setOv] = useState(null);
            const [run, setRun] = useState(null);
            const [sched, setSched] = useState(null);
            const [hist, setHist] = useState(null);
            const [tab, setTab] = useState('nodes');
            const [openNode, setOpenNode] = useState(null);
            const [dlg, setDlg] = useState(null);
            const [act, setAct] = useState({ busy: false, err: '' });
            const [copyMsg, setCopyMsg] = useState('');
            const [refreshing, setRefreshing] = useState(false);
            const now = Date.now();
            const base = `${API_URL}/clusters/${encodeURIComponent(cid)}`;

            const readOverview = async () => {
                if (!canView) { setOv({ state: 'forbidden' }); return; }
                const r = await crDcGet(authFetch, `${API_URL}/updates-overview`);
                setOv({ ...r, at: Date.now() });
            };
            const readSchedule = async () => {
                if (!holds('cluster.view')) { setSched({ state: 'forbidden' }); return; }
                setSched(await crDcGet(authFetch, `${base}/updates/schedule`));
            };
            const readHistory = async () => {
                if (!canView) { setHist({ state: 'forbidden' }); return; }
                setHist(h => (h ? { ...h, busy: true } : { busy: true }));
                const r = await crDcGet(authFetch, `${base}/updates/rolling/history`);
                setHist({ ...r, at: Date.now() });
            };

            // the status of the run: often while one runs or waits, once a minute otherwise, never in a
            // hidden window. It takes the place of the classic section's 3 s poll, which the variant no
            // longer mounts
            const poll = useRef({ timer: null, gone: false, busy: false, active: false });
            const readStatus = async () => {
                if (!canView || poll.current.busy) return null;
                poll.current.busy = true;
                const r = await crDcGet(authFetch, `${base}/updates/status`);
                poll.current.busy = false;
                if (poll.current.gone) return null;
                const at = Date.now();
                if (r.state === 'ok') {
                    const cur = r.body.rolling_update || null;
                    poll.current.active = !!(cur && CR_UPD_ACTIVE.includes(cur.status));
                    setRun({ state: 'ok', run: cur, at });
                    return cur;
                }
                // a failed read keeps what was shown (a node may be rebooting) and says since when
                setRun(prev => ({ ...(prev || {}), state: r.state, code: r.code, msg: r.msg, failedAt: at }));
                return undefined;
            };
            const loop = async () => {
                const p = poll.current;
                clearTimeout(p.timer);
                if (p.gone || (typeof document !== 'undefined' && document.hidden)) return;
                await readStatus();
                if (p.gone) return;
                clearTimeout(p.timer);
                p.timer = setTimeout(loop, p.active ? CR_UPD.pollActive : CR_UPD.pollIdle);
            };
            useEffect(() => {
                const p = poll.current;
                p.gone = false;
                readOverview();
                readSchedule();
                if (canView) loop(); else setRun({ state: 'forbidden' });
                const onVis = () => { if (!document.hidden) loop(); };
                document.addEventListener('visibilitychange', onVis);
                return () => { p.gone = true; clearTimeout(p.timer); document.removeEventListener('visibilitychange', onVis); };
            }, []);

            const refresh = async () => {
                if (refreshing) return;
                setRefreshing(true);
                await Promise.all([readOverview(), readSchedule(), canView ? loop() : null, tab === 'history' ? readHistory() : null]);
                setRefreshing(false);
            };

            const nodesRead = !!(nav && nav.listsRead && nav.listsRead(cid).nodes);
            const model = useMemo(() => crUpdModel({ cluster: c, metrics, ov, now, nodesRead }),
                [c.id, c.cluster_type, metrics, ov, nodesRead, Math.floor(now / 60000)]);
            const chk = store.checks[cid] || null;
            const confined = model.state === 'confined';
            const standby = !!haReadOnly;
            const gate = (p) => ({ kind, standby, may: holds(p), confined });
            const mayUpdate = can('node.update') && !confined && kind !== 'esxi';
            const canReboot = can('node.reboot');
            const whyUpdate = mayUpdate ? '' : crUpdWhy(t, gate('node.update'));
            const r = run && run.run ? run.run : null;
            const view = crUpdRunView(r);
            const activeRun = !!(r && CR_UPD_ACTIVE.includes(r.status));
            const showRun = !!(r && !(CR_UPD_OVER.includes(r.status) && store.dismissed[`${cid}|${r.run_id || r.started_at}`]));
            // a run that just ended: the history is read again the next time it is shown
            const lastStatus = useRef(null);
            useEffect(() => {
                const st = r ? r.status : null;
                if (lastStatus.current && CR_UPD_ACTIVE.includes(lastStatus.current) && st !== lastStatus.current && tab === 'history') readHistory();
                else if (lastStatus.current && CR_UPD_ACTIVE.includes(lastStatus.current) && st !== lastStatus.current) setHist(null);
                lastStatus.current = st;
            }, [r ? r.status : null]);
            useEffect(() => { if (tab === 'history' && !hist) readHistory(); }, [tab]);

            const write = async (method, path, body) => {
                if (act.busy) return;
                setAct({ busy: true, err: '' });
                const opts = { method };
                if (body) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(body); }
                const res = await authFetch(`${base}${path}`, opts);
                const d = res ? await res.json().catch(() => null) : null;
                const ok = !!(res && res.ok && d && d.success);
                setAct({ busy: false, err: ok ? '' : ((d && d.error) || (res ? `HTTP ${res.status}` : t('crDcNoAnswer'))) });
                loop();
            };
            const cont = () => write('POST', '/updates/rolling/resume');
            const anyway = () => { setDlg(null); write('POST', '/updates/rolling/resume', { accept_quorum_risk: true }); };
            const cancel = () => { setDlg(null); write('DELETE', '/updates/rolling'); };

            const copyText = async () => {
                if (!chk || !chk.answer) return;
                const ok = await crUpdCopy(crUpdText(t, clusterLabel(c), chk.answer));
                setCopyMsg(ok ? t('updCopyDone') : t('updCopyFailed'));
            };

            const tiles = (() => {
                const st = model.state;
                const why = { loading: t('crUpdReading'), unread: crFill(t('crUpdOvUnread'), { why: ov ? crDcWhy(ov, t) : '-' }),
                              forbidden: t('crUpdOvNoAccess'), notlisted: t('crUpdOvNotListed'), confined: t('crUpdWhyConfined'),
                              unchecked: t('crUpdNoCheckYet'), unsupported: t('crUpdWhyEsxi') }[st];
                const dash = (id, label, title) => <CrStat key={id} id={id} label={label} value="-" sub={why} title={title} />;
                const secTile = kind === 'xcpng' && model.security != null
                    ? <CrStat key="upd-security" id="upd-security" label={t('crUpdSecTile')} value={model.security} sub={t('crUpdSecXcpSub')} />
                    : <CrStat key="upd-security" id="upd-security" label={t('crUpdSecTile')} value={t('crUpdNotReported')} sub={t('crUpdSecSub')} title={t('allUpdatesSecurityUnknown')} />;
                if (st !== 'ok') {
                    return [dash('upd-total', t('crUpdTotalTile')), secTile, dash('upd-nodes', t('crUpdNodesTile')),
                            dash('upd-unread', t('crUpdUnreadTile')), dash('upd-kernel', t('crUpdKernelTile'), t('crUpdKernelHint')),
                            <CrStat key="upd-checked" id="upd-checked" label={t('crUpdCheckedTile')} value="-" sub={why} />];
                }
                const unread = model.failed.length + model.missing.length;
                const unreadSub = [model.failed.length ? crFill(t('crUpdUnreadFailed'), { nodes: crUpdNames(model.failed) }) : '',
                                   model.missing.length ? crFill(t('crUpdUnreadMissing'), { nodes: crUpdNames(model.missing) }) : ''].filter(Boolean).join(' · ');
                return [
                    <CrStat key="upd-total" id="upd-total" label={t('crUpdTotalTile')} value={model.total}
                        sub={unread ? crFill(t('crUpdTotalPartial'), { n: unread }) : crFill(t('crUpdTotalSub'), { n: model.read })} tone={unread ? 'warning' : null} />,
                    secTile,
                    <CrStat key="upd-nodes" id="upd-nodes" label={t('crUpdNodesTile')} value={model.withUpdates}
                        sub={crFill(t('crUpdNodesSub'), { read: model.read, up: model.upToDate })} />,
                    <CrStat key="upd-unread" id="upd-unread" label={t('crUpdUnreadTile')} value={unread} tone={unread ? 'warning' : null}
                        sub={unreadSub || t('crUpdUnreadNone')} />,
                    <CrStat key="upd-kernel" id="upd-kernel" label={t('crUpdKernelTile')} value={model.kernel} sub={t('crUpdKernelSub')} title={t('crUpdKernelHint')} />,
                    <CrStat key="upd-checked" id="upd-checked" label={t('crUpdCheckedTile')} value={model.checkedAt ? crFill(t('crUpdAge'), { age: crUpdAge(t, model.age) }) : '-'}
                        tone={model.stale ? 'warning' : null}
                        sub={model.checkedAt ? `${crFmtDate(model.checkedAt)}${model.stale ? ` · ${t('crUpdStale')}` : ''}` : '-'} />,
                ];
            })();

            const columns = [
                { key: 'name', label: t('node'), flex: true, min: 110, text: r => r.name,
                  render: r => <span className="cr-strong cr-mono" data-cr-upd-row={r.name}>{r.name}</span> },
                { key: 'st', label: t('status'), width: 112, sortValue: r => ({ offline: 0, unlisted: 1, nostatus: 1, updating: 2, maintenance: 3, online: 4 }[r.st]), text: r => t(CR_UPD_ST_KEY[r.st]),
                  render: r => <span data-cr-upd-st={r.st}><CrBadge tone={crUpdStTone(r.st)}>{t(CR_UPD_ST_KEY[r.st])}</CrBadge></span> },
                { key: 'pending', label: t('crUpdPendingCol'), width: 132, align: 'right',
                  sortValue: r => (r.pending === 'ok' ? r.count : r.pending === 'failed' ? 1e9 : null),
                  text: r => crUpdPendingText(t, r, model),
                  render: r => (
                      <span data-cr-upd-pending={r.pending} className={r.pending === 'failed' || r.pending === 'missing' ? 'cr-upd-warn' : r.pending === 'ok' && r.count > 0 ? 'cr-strong' : 'cr-muted'}
                          title={r.pending === 'failed' && chk && chk.answer && chk.answer.body.nodes[r.name] ? crDash(chk.answer.body.nodes[r.name].error || '') : r.pending === 'missing' ? t('crUpdPendMissingHint') : undefined}>
                          {crUpdPendingText(t, r, model)}
                      </span>
                  ) },
                { key: 'kernel', label: t('crUpdKernelCol'), width: 128, sortValue: r => (r.kernel == null ? null : r.kernel ? 1 : 0),
                  text: r => (r.kernel ? t('crUpdKernelShort') : ''),
                  render: r => (r.kernel ? <span data-cr-upd-kernel={r.name}><CrBadge tone="warning" dot={false} title={t('crUpdKernelHint')}>{t('crUpdKernelShort')}</CrBadge></span>
                      : r.kernel === false ? <span className="cr-muted">-</span> : '') },
                kind === 'proxmox' && { key: 'ver', label: t('crUpdPveVersion'), width: 112, mono: true, text: r => crUpdPve(r.m && r.m.pveversion),
                  render: r => <span title={(r.m && r.m.pveversion) || ''}>{crUpdPve(r.m && r.m.pveversion) || <span className="cr-muted">-</span>}</span> },
                { key: 'kver', label: t('crUpdRunningKernel'), width: 140, mono: true, text: r => crUpdKver(r.m && r.m.kversion),
                  render: r => <span title={(r.m && r.m.kversion) || ''}>{crUpdKver(r.m && r.m.kversion) || <span className="cr-muted">-</span>}</span> },
                { key: 'channel', label: t('allUpdatesRepo'), width: 128, text: r => (r.channel ? crUpdChannel(t, r.channel) : ''),
                  render: r => (r.channel ? <span title={r.warnings > 0 ? t('allUpdatesRepoWarnings').replace('{n}', r.warnings) : undefined}>
                      {crUpdChannel(t, r.channel)}{r.warnings > 0 && <span className="cr-upd-warn"> ({r.warnings})</span>}</span> : <span className="cr-muted">-</span>) },
                { key: 'sub', label: t('allUpdatesSubscription'), width: 110, text: r => (r.subscription ? crUpdSub(t, r.subscription) : ''),
                  render: r => (r.subscription ? <span className={r.channel === 'enterprise' && r.subscription !== 'active' ? 'cr-upd-warn' : ''}
                      title={r.channel === 'enterprise' && r.subscription !== 'active' ? t('allUpdatesEnterpriseNoSub') : undefined}>{crUpdSub(t, r.subscription)}</span> : <span className="cr-muted">-</span>) },
            ].filter(Boolean);

            const histRows = hist && hist.state === 'ok' && Array.isArray(hist.body && hist.body.runs) ? hist.body.runs : null;
            const [openRuns, setOpenRuns] = useState({});
            const histCols = [
                { key: 'started_at', label: t('crUpdStarted'), width: 156, mono: true, text: h => h.started_at || '' },
                { key: 'completed_at', label: t('crUpdEnded'), width: 156, mono: true, text: h => h.completed_at || '',
                  render: h => h.completed_at || <span className="cr-muted">-</span> },
                { key: 'by', label: t('crUpdBy'), width: 130, text: h => (h.scheduled ? t('crUpdScheduler') : h.started_by || ''),
                  render: h => (h.scheduled ? <span data-cr-upd-hist-scheduled="">{t('crUpdScheduler')}</span> : h.started_by || <span className="cr-muted">-</span>) },
                { key: 'status', label: t('status'), width: 176, sortValue: h => h.status,
                  text: h => crUpdRunLabel(t, h.status, h.failed || 0),
                  render: h => {
                      const tone = h.status === 'completed' ? ((h.failed || 0) > 0 ? 'warning' : 'success') : h.status === 'failed' ? 'error'
                          : h.status === 'running' ? 'info' : h.status === 'paused' ? 'warning' : 'neutral';
                      return <span data-cr-upd-hist-status={h.status} data-failed={h.failed || 0}><CrBadge tone={tone}>{crUpdRunLabel(t, h.status, h.failed || 0)}</CrBadge></span>;
                  } },
                { key: 'nodes', label: t('nodes'), flex: true, min: 200, sortValue: h => h.nodes,
                  text: h => crFill(t('crUpdRunCounts'), { done: h.completed || 0, skipped: h.skipped || 0, failed: h.failed || 0, total: h.nodes || 0 }),
                  render: h => <span data-cr-upd-hist-counts="">{crFill(t('crUpdRunCounts'), { done: h.completed || 0, skipped: h.skipped || 0, failed: h.failed || 0, total: h.nodes || 0 })}</span> },
                { key: 'reboot', label: t('crUpdRebootCol'), width: 92, text: h => (h.include_reboot ? t('yes') : t('no')),
                  render: h => (h.include_reboot ? t('yes') : <span className="cr-muted">{t('no')}</span>) },
            ];
            const histDetail = (h) => (
                <div className="cr-upd-hist-detail" data-cr-upd-hist-detail={h.run_id}>
                    {h.error && <p className="cr-upd-line cr-upd-bad">{crDash(h.error)}</p>}
                    {h.paused_reason && <p className="cr-upd-line">{crFill(t('crUpdHistPaused'), { reason: h.paused_reason })}</p>}
                    {(h.failed_nodes || []).map((f, i) => (
                        <p key={i} className="cr-upd-line" data-cr-upd-hist-failed={f.node}><span className="cr-mono cr-upd-bad">{f.node}</span>{f.error ? <span className="cr-muted"> - {crDash(f.error)}</span> : null}</p>
                    ))}
                    {(h.cancel_report || []).length > 0 && <p className="cr-upd-line cr-upd-warn">{t('rollRunNotUndone')}: {h.cancel_report.map(i => i.node || (i.rules || []).join(', ') || i.kind).join('; ')}</p>}
                    {h.cancelled_by && <p className="cr-upd-line cr-muted">{crFill(t('crUpdCancelledBy'), { user: h.cancelled_by })}</p>}
                    {(h.logs || []).length > 0 ? <pre className="cr-hd-pre">{h.logs.map(crDash).join('\n')}</pre> : <p className="cr-muted">{t('crUpdHistNoLog')}</p>}
                </div>
            );

            const openRow = openNode ? model.rows.find(x => x.name === openNode) : null;
            const tabs = [
                { id: 'upd-nodes', label: crFill(t('crUpdTabNodes'), { n: model.rows.length }), icon: <Icons.Server /> },
                { id: 'upd-history', label: t('crUpdTabHistory'), icon: <Icons.Clock /> },
                { id: 'upd-guests', label: t('crUpdTabGuests'), icon: <Icons.Monitor /> },
            ];
            const tabId = { nodes: 'upd-nodes', history: 'upd-history', guests: 'upd-guests' }[tab];
            const pickTab = (id) => setTab({ 'upd-nodes': 'nodes', 'upd-history': 'history', 'upd-guests': 'guests' }[id] || 'nodes');
            const goHistory = () => { pickTab('upd-history'); setTimeout(() => { const el = document.querySelector('[data-cr-tab="upd-history"]'); if (el) el.focus(); }, 0); };

            if (kind === 'esxi') {
                return (
                    <div className="cr-dash cr-upd" data-cr-updates="" data-cr-upd-state="unsupported">
                        <CrPageHeader icon={<Icons.Download />} title={t('updateManager')} sub={clusterLabel(c)} />
                        <div className="cr-panel cr-empty"><Icons.Download className="w-6 h-6" /><p>{t('crUpdWhyEsxi')}</p></div>
                    </div>
                );
            }

            const runNote = run && run.state && run.state !== 'ok' && run.failedAt;
            // a check runs apt update on every online node, also on the one a running run is upgrading
            // (a paused run holds no apt lock); a start waits for a status that was read (one run per cluster)
            const upgrading = !!(r && r.status === 'running');
            const whyCheck = whyUpdate || (upgrading ? t('crUpdCheckDuringRun') : '');
            const whyStart = whyUpdate || (activeRun ? t('crUpdOneRun')
                : run && run.state && run.state !== 'ok' && run.state !== 'forbidden' ? t('crUpdStartNeedsStatus') : '');
            return (
                <div className="cr-dash cr-upd" data-cr-updates="" data-cr-upd-state={model.state}>
                    <CrPageHeader icon={<Icons.Download />} title={t('updateManager')} sub={clusterLabel(c)}
                        actions={(
                            <>
                                <CrButton icon={<Icons.ClipboardList />} onClick={copyText} disabled={!chk || !chk.answer}
                                    title={chk && chk.answer ? t('updCopyHint') : t('crUpdCopyNeedsCheck')} data-cr-upd-copy="">{t('updCopyButton')}</CrButton>
                                <CrButton icon={refreshing ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={refresh} disabled={refreshing}
                                    title={t('crUpdRefreshHint')} data-cr-upd-refresh="">{t('crUpdRefresh')}</CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crUpdIntro')}</p>
                    {copyMsg && <p className="cr-upd-line" role="status" data-cr-upd-copy-msg="">{copyMsg}</p>}

                    {standby && <CrUpdNote id="standby"><p>{t('crUpdStandby')}</p></CrUpdNote>}
                    {model.state === 'forbidden' && <CrUpdNote tone="warning" id="forbidden"><p>{t('crUpdOvNoAccess')}</p></CrUpdNote>}
                    {model.state === 'unread' && <CrUpdNote tone="error" id="unread"><p>{crFill(t('crUpdOvUnread'), { why: crDcWhy(ov, t) })}</p></CrUpdNote>}
                    {model.state === 'confined' && <CrUpdNote tone="warning" id="confined"><p>{t('crUpdConfined')}</p></CrUpdNote>}
                    {model.state === 'notlisted' && <CrUpdNote tone="warning" id="notlisted"><p>{t('crUpdOvNotListed')}</p></CrUpdNote>}
                    {model.state === 'unchecked' && <CrUpdNote tone="warning" id="unchecked"><p>{t('crUpdUnchecked')}</p></CrUpdNote>}
                    {model.state === 'ok' && model.stale && <CrUpdNote tone="warning" id="stale"><p>{crFill(t('crUpdStaleNote'), { age: crUpdAge(t, model.age) })}</p></CrUpdNote>}

                    <section className="cr-stat-row cr-upd-tiles" aria-label={t('crSummary')} data-cr-upd-tiles="">{tiles}</section>
                    <p className="cr-sb-fine" data-cr-upd-basis="tiles">{t('crUpdBasis')}</p>

                    <div className="cr-upd-cards">
                        <section className="cr-panel cr-upd-card" tabIndex={-1} data-cr-focus-home="" data-cr-upd-card="check" aria-label={t('crUpdCheckCard')}>
                            <header className="cr-upd-card-head">
                                <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>
                                <h3 className="cr-panel-title">{t('crUpdCheckCard')}</h3>
                            </header>
                            <p className="cr-upd-line cr-muted">{t('crUpdCheckCardText')}</p>
                            <CrUpdCheckResult chk={chk} t={t} />
                            <div className="cr-upd-card-foot">
                                <CrButton icon={chk && chk.busy ? <span className="cr-spinner" /> : <Icons.RefreshCw />} onClick={() => setDlg({ kind: 'check' })}
                                    disabled={!mayUpdate || !!(chk && chk.busy) || upgrading} title={whyCheck || undefined} data-cr-upd-open="check">
                                    {chk && chk.busy ? t('checking') : t('crUpdCheckNow')}
                                </CrButton>
                                {whyCheck && <span className="cr-muted cr-upd-why" data-cr-upd-why="check">{whyCheck}</span>}
                            </div>
                        </section>
                        <section className="cr-panel cr-upd-card" tabIndex={-1} data-cr-focus-home="" data-cr-upd-card="rolling" aria-label={t('crUpdRollCard')}>
                            <header className="cr-upd-card-head">
                                <span className="cr-ico" aria-hidden="true"><Icons.Play /></span>
                                <h3 className="cr-panel-title">{t('crUpdRollCard')}</h3>
                                {r && <span data-cr-upd-roll-state={r.status}><CrBadge tone={view.tone}>{crUpdRunLabel(t, r.status, view.failed.length)}</CrBadge></span>}
                            </header>
                            <p className="cr-upd-line cr-muted">{t('crUpdRollCardText')}</p>
                            {!run ? <p className="cr-upd-line cr-muted" role="status">{t('crUpdReading')}</p>
                                : run.state === 'forbidden' && !r ? <p className="cr-upd-line cr-upd-warn" data-cr-upd-status="forbidden">{t('crUpdStatusNoAccess')}</p>
                                : run.state !== 'ok' && !run.at ? <p className="cr-upd-line cr-upd-warn" data-cr-upd-status="unread">{crFill(t('crUpdStatusUnread'), { why: crDcWhy(run, t) })}</p>
                                : !r ? <p className="cr-upd-line" data-cr-upd-status="none">{crFill(t('crUpdNoRun'), { time: crFmtTime(run.at) })}</p>
                                : <p className="cr-upd-line" data-cr-upd-status={r.status}>{activeRun ? crFill(t('crUpdRunLine'), { node: r.current_node || '-', n: view.finished, total: view.nodes.length })
                                    : crFill(t('crUpdRunEndedLine'), { time: r.completed_at || '-' })}</p>}
                            {runNote && <p className="cr-upd-line cr-upd-warn" data-cr-upd-status-stale="">{crFill(t('crUpdStatusStale'), { time: crFmtTime(run.failedAt), why: crDcWhy(run, t) })}</p>}
                            <div className="cr-upd-card-foot">
                                <CrButton variant="primary" icon={<Icons.Play />} onClick={() => setDlg({ kind: 'start' })}
                                    disabled={!mayUpdate || activeRun || !run || run.state !== 'ok'}
                                    title={whyStart || undefined} data-cr-upd-open="start">
                                    {t('crUpdStart')}
                                </CrButton>
                                {whyStart && <span className="cr-muted cr-upd-why" data-cr-upd-why="start">{whyStart}</span>}
                            </div>
                        </section>
                        <CrUpdSchedCard sched={sched} t={t} canEdit={mayUpdate} why={whyUpdate} onEdit={() => setDlg({ kind: 'schedule' })} onHistory={canView ? goHistory : null} />
                    </div>

                    {showRun && (
                        <CrUpdRun run={r} view={view} t={t} canAct={mayUpdate} canReboot={canReboot} busy={act.busy} err={act.err}
                            onContinue={cont} onAnyway={() => setDlg({ kind: 'anyway', node: (r.paused_details && r.paused_details.node) || r.current_node || '-' })}
                            onCancel={() => setDlg({ kind: 'cancel' })} onHistory={canView ? goHistory : null}
                            onDismiss={() => { crUpd.dismissed[`${cid}|${r.run_id || r.started_at}`] = true; crUpdEmit(); }} />
                    )}

                    <CrTabs id="upd" label={t('updateManager')} tabs={tabs} active={tabId} onChange={pickTab} />
                    {tab === 'nodes' && (
                        <div className="cr-upd-tab" role="tabpanel" data-cr-upd-tab="nodes">
                            <CrTable id="upd-nodes" columns={columns} rows={model.rows} rowKey={x => x.name} searchable={model.rows.length > 12}
                                onRowClick={x => setOpenNode(x.name)} selectedKey={openNode} ariaLabel={t('crUpdNodesTable')} maxHeight={520}
                                emptyText={!canView ? t('crUpdOvNoAccess') : t('crUpdNoNodes')} initialSort={{ key: 'name', dir: 'asc' }} />
                            {model.pbs.length > 0 && (
                                <p className="cr-sb-fine" data-cr-upd-pbs="">
                                    {crFill(t('crUpdPbs'), { list: model.pbs.map(p => `${p.name}: ${p.ok ? crFill(t('crUpdNPkgs'), { n: p.count }) : t('crUpdPendFailed')}`).join(', ') })}
                                </p>
                            )}
                            <p className="cr-sb-fine">{t('crUpdNodesFoot')}</p>
                            <p className="cr-sb-fine" data-cr-upd-not-here="">{t('crUpdNotHere')}</p>
                        </div>
                    )}
                    {tab === 'history' && (
                        <div className="cr-upd-tab" role="tabpanel" data-cr-upd-tab="history">
                            {!hist || (hist.busy && !hist.state) ? <p className="cr-upd-line cr-muted" role="status">{t('crUpdReading')}</p>
                                : hist.state === 'forbidden' ? <CrUpdNote tone="warning" id="history-denied"><p>{t('crUpdHistNoAccess')}</p></CrUpdNote>
                                : !histRows ? <CrUpdNote tone="error" id="history-unread"><p>{crFill(t('crUpdHistUnread'), { why: crDcWhy(hist, t) })}</p></CrUpdNote>
                                : (
                                    <CrTable id="upd-history" columns={histCols} rows={histRows} rowKey={h => h.run_id || h.started_at} maxHeight={480}
                                        ariaLabel={t('crUpdTabHistory')} emptyText={t('rollRunHistoryEmpty')}
                                        expanded={openRuns} renderExpanded={histDetail}
                                        onRowClick={h => setOpenRuns(o => ({ ...o, [h.run_id || h.started_at]: !o[h.run_id || h.started_at] }))}
                                        actions={<button type="button" className="cr-btn cr-btn-ghost" onClick={readHistory} disabled={!!hist.busy} data-cr-upd-hist-reload="">{t('crUpdReload')}</button>} />
                                )}
                            <p className="cr-sb-fine" data-cr-upd-hist-foot="">{t('crUpdHistFoot')}</p>
                        </div>
                    )}
                    {tab === 'guests' && (
                        <div className="cr-panel cr-empty cr-upd-guests" role="tabpanel" data-cr-upd-tab="guests" data-cr-upd-guests="no-source">
                            <Icons.Monitor className="w-6 h-6" />
                            <p className="cr-strong">{t('crUpdGuestsTitle')}</p>
                            <p className="cr-muted">{t('crUpdGuestsText')}</p>
                        </div>
                    )}

                    <CrSidePanel open={!!openRow} id="updates-node" title={openRow ? openRow.name : ''} sub={openRow ? clusterLabel(c) : ''}
                        onClose={() => setOpenNode(null)} focusKey={openNode}
                        returnFocus={() => document.querySelector('[data-cr-table="upd-nodes"] tbody tr[tabindex="0"]')}>
                        {openRow && <CrUpdNodeDetail key={openRow.name} row={openRow} chk={chk} model={model} kind={kind} may={canView}
                            authFetch={authFetch} cid={cid} nav={nav} t={t} />}
                    </CrSidePanel>

                    {dlg && dlg.kind === 'check' && (
                        <CrUpdCheckDialog cluster={c} nodes={model.rows} onCancel={() => setDlg(null)}
                            onConfirm={(force) => { setDlg(null); crUpdRunCheck(authFetch, cid, force, readOverview); }} />
                    )}
                    {dlg && dlg.kind === 'start' && (
                        <CrUpdStartDialog cluster={c} model={model} canReboot={canReboot} authFetch={authFetch} holds={holds}
                            onCancel={() => setDlg(null)} onStarted={() => { setDlg(null); loop(); }} />
                    )}
                    {dlg && dlg.kind === 'schedule' && (
                        <CrUpdScheduleDialog cluster={c} sched={sched && sched.body} canReboot={canReboot} pve={kind === 'proxmox'} authFetch={authFetch}
                            onCancel={() => setDlg(null)} onSaved={() => { setDlg(null); readSchedule(); }} />
                    )}
                    {dlg && (dlg.kind === 'cancel' || dlg.kind === 'anyway') && (
                        <CrUpdDialog id={dlg.kind} title={dlg.kind === 'cancel' ? t('crUpdCancelTitle') : t('rollQuorumContinueAnyway')}
                            onCancel={() => setDlg(null)}
                            footer={(
                                <>
                                    <CrButton onClick={() => setDlg(null)} data-cr-upd-cancel="">{t('crUpdBack')}</CrButton>
                                    <CrButton variant="danger" icon={dlg.kind === 'cancel' ? <Icons.X /> : <Icons.AlertTriangle />}
                                        onClick={dlg.kind === 'cancel' ? cancel : anyway} data-cr-upd-confirm={dlg.kind}>
                                        {dlg.kind === 'cancel' ? t('rollRunCancel') : t('rollQuorumContinueAnyway')}
                                    </CrButton>
                                </>
                            )}>
                            <p className="cr-upd-text">{dlg.kind === 'cancel' ? t('crUpdCancelText') : crDash(t('rollQuorumContinueConfirm').replace('{node}', dlg.node))}</p>
                        </CrUpdDialog>
                    )}
                </div>
            );
        }

        // In the variant the Settings tab only points to the Automation sub tab: mounting the classic
        // section there would start a check by itself
        function CrUpdatesLink({ onOpen }) {
            const { t } = useTranslation();
            return (
                <section className="cr-panel cr-upd-link" data-cr-upd-link="">
                    <span className="cr-ico" aria-hidden="true"><Icons.Download /></span>
                    <div>
                        <h3 className="cr-panel-title">{t('updateManager')}</h3>
                        <p className="cr-muted">{t('crUpdLinkText')}</p>
                        <p className="cr-muted" data-cr-upd-link-missing="">{t('crUpdNotHere')}</p>
                    </div>
                    <CrButton icon={<Icons.ArrowRight />} onClick={onOpen} data-cr-upd-link-open="">{t('crUpdLinkOpen')}</CrButton>
                </section>
            );
        }
