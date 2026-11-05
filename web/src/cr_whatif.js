        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: Reports > What-if - LW Oct 2026
        // Mounted instead of the classic WhatIfTab, in the redesign only. The same three routes:
        // the options on open, a scenario and the ranking only on a click, one at a time. The
        // engine's report is shown as it comes, each statement with what it rests on; a report
        // with guests it could not judge or configs it did not read says it is incomplete,
        // whatever its verdict. The capacity panel beside the picker reads the Insights forecast
        // and right-sizing: measured and forecast figures, kept apart from the simulation.
        // ═══════════════════════════════════════════════════════════

        const CR_WI_KINDS = [
            { id: 'node_failure', label: 'whatifNodeFailure', desc: 'whatifNodeFailureDesc' },
            { id: 'maintenance', label: 'whatifMaintenance', desc: 'whatifMaintenanceDesc' },
            { id: 'headroom', label: 'whatifHeadroom', desc: 'whatifHeadroomDesc' },
            { id: 'storage_failure', label: 'whatifStorageFailure', desc: 'whatifStorageFailureDesc' },
            { id: 'network_failure', label: 'whatifNetworkFailure', desc: 'whatifNetworkFailureDesc' },
            { id: 'pbs_failure', label: 'whatifPbsFailure', desc: 'whatifPbsFailureDesc' },
        ];
        // the engine refuses more nodes than this in one run (core/whatif.py MAX_NODES_PICKED)
        const CR_WI_MAX_NODES = 16;
        // above this many nodes the picker gets a filter
        const CR_WI_NODE_FILTER = 12;
        const CR_WI_OUTCOMES = [
            { id: 'down', label: 'whatifDown', tone: 'error' },
            { id: 'degraded', label: 'whatifDegraded', tone: 'warning' },
            { id: 'restarted', label: 'whatifRestarted', tone: 'info' },
            { id: 'moved', label: 'whatifMoved', tone: 'success' },
            { id: 'unknown', label: 'whatifUnknown', tone: 'neutral' },
        ];
        // limits that say part of the cluster was not read: the report is incomplete then
        const CR_WI_GAPS = ['configs_unread', 'ha_unreadable', 'storage_unknown', 'pbs_points_unread', 'pbs_jobs_unread', 'pbs_inactive'];
        const CR_WI_BASIS = { known: ['whatifKnown', 'info'], calculated: ['whatifCalculated', 'neutral'], assumed: ['whatifAssumed', 'warning'] };
        // the restore test behind the engine's restore state (recovery.guest_row, whatif._RESTORE_OF)
        const CR_WI_RESTORE = { ok: ['crVmRtPassed', 'success'], rto_missed: ['crVmRtRtoMissed', 'warning'], stale: ['crVmRtStale', 'warning'],
                                never: ['crVmRtNever', 'neutral'], failing: ['crVmRtFailing', 'error'] };
        const CR_WI_STATES = { up: ['whatifStateUp', 'success'], failed: ['whatifStateFailed', 'error'], maintenance: ['whatifStateMaintenance', 'warning'],
                               reset: ['whatifStateReset', 'error'], offline: ['whatifStateOffline', 'neutral'] };
        const CR_WI_RANK_KINDS = { node: 'whatifKindNode', storage: 'whatifKindStorage', pbs: 'whatifKindPbs', bridge: 'whatifKindBridge' };
        const crWiNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const CR_WI_NONE = {};
        // a monotonic clock for the elapsed seconds of a run (the wall clock can jump)
        const crWiClock = () => (typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now());

        // a key filled with the engine's args; on a missing key the server's English stands in
        function crWiSay(t, key, args, fallback) {
            const raw = key ? t(key) : '';
            let text = raw && raw !== key ? raw : (fallback || '');
            Object.entries(args || {}).forEach(([k, v]) => {
                text = text.split(`{${k}}`).join(Array.isArray(v) ? v.join(', ') : String(v));
            });
            return text;
        }
        const crWiReason = (t, r) => crWiSay(t, r && r.reason ? WHATIF_REASONS[r.reason.code] : '', r && r.reason ? r.reason.args : null, r && r.text);
        const crWiLimit = (t, l) => crWiSay(t, WHATIF_LIMITS[l.code], l.args, l.text);
        const crWiAssume = (t, a) => crWiSay(t, WHATIF_ASSUMPTIONS[a.code], a.args, a.text);

        // a read of the simulator: like crVmRead, plus what only these routes answer (a cluster
        // type it does not cover, a scenario it refuses, a cluster it cannot read)
        async function crWiRead(authFetch, url, opts) {
            let r = null;
            try { r = await authFetch(url, opts); } catch (_) { r = null; }
            const at = Date.now();
            if (!r) return { state: 'unreachable', at };
            if (await haLeaderAway(r)) return { state: 'away', code: r.status, at };
            const body = await r.json().catch(() => null);
            if (r.ok && body && typeof body === 'object' && !Array.isArray(body) && !body.error) {
                return { state: body.supported === false ? 'unsupported' : 'ok', body, code: r.status, at };
            }
            const msg = body && typeof body.error === 'string' ? body.error : '';
            const c = r.status;
            const state = c === 400 ? 'invalid' : c === 403 ? 'forbidden' : c === 404 ? 'notfound' : c === 429 ? 'limited'
                : c === 503 ? (body && body.offline ? 'offline' : 'unreadable') : (r.ok ? 'malformed' : 'error');
            return { state, code: c, msg, why: body && body.code, at };
        }

        // why a read did not come back as a report, in words
        function crWiWhy(read, t, what) {
            const m = read.msg ? `: ${read.msg}` : '';
            switch (read.state) {
                case 'unsupported': return t('whatifNotSupported');
                case 'forbidden': return crFill(t('crWiForbidden'), { what }) + m;
                case 'offline': return t('crWiOffline');
                case 'unreadable': return t('crWiUnreadable') + m;
                case 'invalid': return t('crWiInvalid') + m;
                case 'malformed': return t('crWiMalformed');
                case 'notfound': return t('crVmNotFound') + m;
                case 'away': return t('crVmLeaderAway');
                case 'limited': return t('crDriftLimited');
                case 'unreachable': return t('crDriftOffline');
                default: return t('crVmReadFailed') + (read.msg ? `: ${read.msg}` : read.code ? ` (HTTP ${read.code})` : '');
            }
        }

        // the headline of a report: the server's verdict, and on the client whether the report is
        // complete. A guest the engine could not judge, a config it did not read or a part of the
        // cluster it could not read makes it incomplete; a blocked verdict stays blocked
        function crWiHeadline(rep, t) {
            const v = rep.verdict && typeof rep.verdict === 'object' ? rep.verdict : null;
            const level = v && ['ready', 'warning', 'blocked'].includes(v.level) ? v.level : null;
            const gaps = [];
            const unknown = rep.summary && crWiNum(rep.summary.unknown) ? rep.summary.unknown : 0;
            const unread = rep.reads && crWiNum(rep.reads.configs_unread) ? rep.reads.configs_unread : 0;
            if (unknown > 0) gaps.push({ code: 'unknown', text: crFill(t('crWiGapUnknown'), { n: unknown }) });
            (rep.limits || []).forEach(l => {
                if (!CR_WI_GAPS.includes(l.code)) return;
                if (l.code === 'configs_unread' && unread > 0) return;
                gaps.push({ code: l.code, text: crWiLimit(t, l) });
            });
            if (unread > 0) gaps.push({ code: 'configs_unread', text: crFill(t('crWiGapUnread'), { n: unread }) });
            if (rep.risk === null) gaps.push({ code: 'risk', text: t('crWiGapRisk') });
            if (rep.pbs && rep.pbs.marks_read === false) gaps.push({ code: 'pbs_marks', text: t('crWiGapMarks') });
            const state = level === 'blocked' ? 'blocked' : gaps.length ? 'incomplete' : level || 'none';
            const tone = state === 'blocked' ? 'error' : state === 'ready' ? 'success' : state === 'none' ? 'neutral' : 'warning';
            const notes = [];
            const h = rep.headroom;
            if (h) {
                const shown = Array.isArray(h.combinations) ? h.combinations.length : 0;
                const totals = (h.combinations || []).filter(c => c.checked === 'totals').length;
                if (crWiNum(h.checked) && shown < h.checked) notes.push({ code: 'shown', text: crFill(t('crWiHrShown'), { n: shown, total: h.checked }) });
                if (totals > 0) notes.push({ code: 'totals', text: crFill(t('crWiHrTotals'), { n: totals, total: shown }) });
                const asm = (rep.assumptions || []).find(a => a.code === 'headroom_no_storage');
                if (asm) notes.push({ code: 'headroom_no_storage', text: crWiAssume(t, asm) });
                const pairs = (rep.assumptions || []).find(a => a.code === 'headroom_pairs');
                if (pairs) notes.push({ code: 'headroom_pairs', text: crWiAssume(t, pairs) });
            }
            return { state, tone, level, reasons: v && Array.isArray(v.reasons) ? v.reasons : [], gaps, notes };
        }

        // what the server ran, in words (the report echoes the scenario it parsed)
        function crWiScenario(sc, t) {
            if (!sc || !sc.type) return '-';
            const kind = CR_WI_KINDS.find(k => k.id === sc.type);
            const name = kind ? t(kind.label) : sc.type;
            const where = sc.node ? crFill(t('crWiOnNode'), { node: sc.node }) : t('crWiOnAll');
            if (sc.type === 'node_failure' || sc.type === 'maintenance') return `${name}: ${(sc.nodes || []).join(', ')}`;
            if (sc.type === 'headroom') return `${t(sc.depth === 2 ? 'whatifN2' : 'whatifN1')} · ${t(sc.guests === 'ha' ? 'whatifGuestsHa' : 'whatifGuestsAll')}`;
            if (sc.type === 'storage_failure') return `${name}: ${sc.storage} ${where}`;
            if (sc.type === 'pbs_failure') return `${name}: ${sc.storage}`;
            if (sc.type === 'network_failure') {
                const net = [sc.bridge, sc.vnet].filter(Boolean).join(', ') + (crWiNum(sc.vlan) ? ` VLAN ${sc.vlan}` : '');
                return `${name}: ${net} ${where}`;
            }
            return name;
        }

        // the colour of a node's figure against the threshold the report used for it
        const crWiTone = (v, thr) => (!crWiNum(v) ? 'neutral' : (v > 100 || (crWiNum(thr) && v > thr)) ? 'error' : 'success');

        function CrWiBasis({ b }) {
            const { t } = useTranslation();
            const [key, tone] = CR_WI_BASIS[b] || CR_WI_BASIS.assumed;
            return <span className="cr-wi-basis" data-cr-wi-basis={b || 'assumed'}><CrBadge tone={tone} dot={false} title={t('whatifBasisHelp')}>{t(key)}</CrBadge></span>;
        }

        function CrWiNote({ tone = 'info', id, children, onRetry }) {
            const { t } = useTranslation();
            const icon = tone === 'error' || tone === 'warning' ? <Icons.AlertTriangle /> : <Icons.Info />;
            return (
                <div className={`cr-callout cr-callout-${tone}`} data-cr-wi-note={id} role={tone === 'error' ? 'alert' : undefined}>
                    <span className="cr-ico" aria-hidden="true">{icon}</span>
                    <div>{children}</div>
                    {onRetry && <CrButton className="cr-btn-xs" onClick={onRetry} data-cr-wi-retry={id}>{t('retry')}</CrButton>}
                </div>
            );
        }

        // a guest, node or storage of the report: a link where the inventory this user sees has
        // it, else its name and why it is not one
        function crWiInv(nav, cid) {
            const guests = crGuestMap(nav && nav.guestsOf ? nav.guestsOf(cid) : null);
            const nodes = nav && nav.nodesOf ? nav.nodesOf(cid) : null;
            const stores = nav && nav.storesOf ? nav.storesOf(cid) : null;
            const read = nav && nav.listsRead ? nav.listsRead(cid) : { guests: true, nodes: true, stores: true };
            return { guests, nodes, stores, read };
        }
        function CrWiGuest({ g, inv, nav, cid }) {
            const { t } = useTranslation();
            const hit = inv.guests ? inv.guests.get(String(g.vmid)) : null;
            const label = g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}`;
            return (
                <span className="cr-rp-guest">
                    <span className={`cr-ico cr-guest-ico cr-guest-${g.type}`} aria-hidden="true">{g.type === 'lxc' ? <Icons.Box /> : <Icons.Monitor />}</span>
                    {hit && nav && nav.openGuest
                        ? <button type="button" className="cr-link" data-cr-wi-go={`guest:${g.vmid}`} onClick={e => { e.stopPropagation(); nav.openGuest(cid, hit); }}>{label}</button>
                        : <span className="cr-strong" title={t(inv.read && !inv.read.guests ? 'crInvNotLoaded' : 'crDriftNotInInventory')} data-cr-wi-nolink="guest">{label}</span>}
                    <span className="cr-muted cr-mono">{g.vmid}</span>
                </span>
            );
        }
        function CrWiNode({ name, inv, nav, cid }) {
            const { t } = useTranslation();
            if (!name) return <span className="cr-muted">-</span>;
            const known = !!(inv.nodes && Object.prototype.hasOwnProperty.call(inv.nodes, name));
            return known && nav && nav.openNode
                ? <button type="button" className="cr-link" data-cr-wi-go={`node:${name}`} onClick={e => { e.stopPropagation(); nav.openNode(cid, name); }}>{name}</button>
                : <span title={t(inv.read && !inv.read.nodes ? 'crInvNotLoaded' : 'crDriftNotInInventory')} data-cr-wi-nolink="node">{name}</span>;
        }
        function CrWiStore({ name, node, inv, nav, cid }) {
            const { t } = useTranslation();
            const hit = crFindStore(inv.stores, name, node || null);
            return hit && nav && nav.openStorage
                ? <button type="button" className="cr-link" data-cr-wi-go={`storage:${name}`} onClick={e => { e.stopPropagation(); nav.openStorage(cid, hit.store, hit.node); }}>{name}</button>
                : <span title={t('crWiStoreNoLink')}>{name}</span>;
        }

        // --- the page ----------------------------------------------------------------

        const crWiFresh = () => ({ kind: 'node_failure', nodes: [], allowLocal: false, relax: false, depth: 1, guests: 'all', storage: '', where: '',
                                   netKind: 'bridge', bridge: '', vnet: '', vlan: '', pbs: '', memory: 'configured', cpu: '', mem: '', tags: '' });
        const crWiTags = (s) => [...new Set(String(s || '').split(/[\s,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean))];

        function CrWhatIf({ cluster, authFetch, nav, onSub }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const [opts, setOpts] = useState({ state: 'loading' });
            const [view, setView] = useState('scenario');
            const [pick, setPick] = useState(crWiFresh);
            const [run, setRun] = useState(null);
            const [rank, setRank] = useState(null);
            const [, setTick] = useState(0);
            const seqO = useRef(0);
            const seqS = useRef(0);
            const seqK = useRef(0);
            const alive = useRef(true);
            const inFlight = useRef({ run: false, rank: false });
            const rootRef = useRef(null);
            // below this width the wide tables start with fewer columns (the column menu brings them back)
            const narrow = crRpNarrow(rootRef, 1180);
            useEffect(() => () => { alive.current = false; }, []);

            const readOpts = useCallback(async () => {
                if (!cid) return;
                const mine = ++seqO.current;
                setOpts({ state: 'loading' });
                const r = await crWiRead(authFetch, `${API_URL}/clusters/${cid}/whatif/options`);
                if (!alive.current || mine !== seqO.current) return;
                if (r.state === 'ok' && !Array.isArray(r.body.nodes)) { setOpts({ ...r, state: 'malformed' }); return; }
                setOpts(r);
                if (r.state === 'ok') {
                    const b = r.body;
                    setPick(p => ({ ...p,
                        cpu: b.thresholds && crWiNum(b.thresholds.cpu) ? String(b.thresholds.cpu) : '',
                        mem: b.thresholds && crWiNum(b.thresholds.memory) ? String(b.thresholds.memory) : '',
                        tags: ((b.critical_tags && b.critical_tags.tags) || []).join(', ') }));
                }
            }, [authFetch, cid]);
            useEffect(() => { readOpts(); }, [cid]);

            // the elapsed time of a run or a ranking: a UI timer only while one is in flight, nothing is asked
            const busy = (run && run.state === 'running') || (rank && rank.state === 'running');
            useEffect(() => {
                if (!busy) return undefined;
                const id = setInterval(() => setTick(x => x + 1), 1000);
                return () => clearInterval(id);
            }, [busy]);

            const o = opts.state === 'ok' ? opts.body : null;
            const tagsChanged = (p) => {
                const was = [...(((o && o.critical_tags) || {}).tags || [])].sort().join(',');
                return crWiTags(p.tags).sort().join(',') !== was;
            };
            const body = (p) => {
                const out = { type: p.kind, memory: p.memory };
                if (tagsChanged(p)) out.critical_tags = crWiTags(p.tags);
                const thr = {};
                const c = parseFloat(p.cpu), m = parseFloat(p.mem);
                if (o && o.thresholds && !isNaN(c) && c !== o.thresholds.cpu) thr.cpu = c;
                if (o && o.thresholds && !isNaN(m) && m !== o.thresholds.memory) thr.memory = m;
                if (Object.keys(thr).length) out.thresholds = thr;
                if (p.kind === 'node_failure' || p.kind === 'maintenance') out.nodes = p.nodes;
                if (p.kind === 'maintenance') { out.allow_local_disks = p.allowLocal; out.relax_anti_affinity = p.relax; }
                if (p.kind === 'headroom') { out.depth = p.depth; out.guests = p.guests; }
                if (p.kind === 'storage_failure') { out.storage = p.storage; if (p.where) out.node = p.where; }
                if (p.kind === 'pbs_failure') out.storage = p.pbs;
                if (p.kind === 'network_failure') {
                    if (p.netKind === 'bridge') out.bridge = p.bridge; else out.vnet = p.vnet;
                    if (p.vlan !== '' && !isNaN(parseInt(p.vlan, 10))) out.vlan = parseInt(p.vlan, 10);
                    if (p.where) out.node = p.where;
                }
                return out;
            };
            // what keeps the run button off, said next to it
            const missing = (p) => {
                if (!o) return '';
                const pct = (v) => v === '' || (/^\d+(\.\d+)?$/.test(String(v).trim()) && parseFloat(v) >= 1 && parseFloat(v) <= 100);
                if ((p.kind === 'node_failure' || p.kind === 'maintenance') && !p.nodes.length) return t('whatifPickNode');
                if ((p.kind === 'node_failure' || p.kind === 'maintenance') && p.nodes.length > CR_WI_MAX_NODES) return crFill(t('crWiTooMany'), { n: CR_WI_MAX_NODES });
                if (p.kind === 'storage_failure' && !p.storage) return t('whatifPickStorage');
                if (p.kind === 'pbs_failure' && !(o.pbs || []).length) return t('crWiNoPbs');
                if (p.kind === 'pbs_failure' && !p.pbs) return t('whatifPickPbs');
                if (p.kind === 'network_failure' && !(p.netKind === 'bridge' ? p.bridge : p.vnet)) return t('whatifPickNetwork');
                if (p.kind === 'network_failure' && p.vlan !== '' && !(/^\d+$/.test(String(p.vlan).trim()) && +p.vlan >= 1 && +p.vlan <= 4094)) return t('crWiBadVlan');
                if (!pct(p.cpu) || !pct(p.mem)) return t('crWiBadThreshold');
                if (crWiTags(p.tags).some(x => !/^[\w.+-]{1,64}$/.test(x))) return t('crWiBadTags');
                return '';
            };

            // one run and one ranking at a time: the server does not dedupe them, and each walks every guest
            const send = async (sent) => {
                if (!o || inFlight.current.run) return;
                inFlight.current.run = true;
                const mine = ++seqS.current;
                setRun({ state: 'running', started: crWiClock(), sent });
                try {
                    const r = await crWiRead(authFetch, `${API_URL}/clusters/${cid}/whatif`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sent), quiet: true,
                    });
                    if (!alive.current || mine !== seqS.current) return;
                    const ok = r.state === 'ok' && r.body.summary && typeof r.body.summary === 'object'
                        && Array.isArray(r.body.guests) && Array.isArray(r.body.nodes);
                    setRun(r.state === 'ok' && !ok ? { ...r, state: 'malformed', sent } : { ...r, sent });
                } finally { inFlight.current.run = false; }
            };
            const simulate = (p) => { if (o && !missing(p)) send(body(p)); };
            const runRanking = async () => {
                if (!o || inFlight.current.rank) return;
                inFlight.current.rank = true;
                const sent = tagsChanged(pick) ? { critical_tags: crWiTags(pick.tags) } : {};
                const mine = ++seqK.current;
                setRank({ state: 'running', started: crWiClock() });
                try {
                    const r = await crWiRead(authFetch, `${API_URL}/clusters/${cid}/whatif/ranking`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sent), quiet: true,
                    });
                    if (!alive.current || mine !== seqK.current) return;
                    const ok = r.state === 'ok' && Array.isArray(r.body.ranking);
                    setRank(r.state === 'ok' && !ok ? { ...r, state: 'malformed' } : r);
                } finally { inFlight.current.rank = false; }
            };
            // a row of the ranking as a scenario of its own: the picker takes it and runs it
            const simulateCandidate = (row) => {
                const sc = row && row.scenario;
                if (!sc || !sc.type) return;
                const next = { ...pick, kind: sc.type, where: '', memory: sc.memory || pick.memory,
                    nodes: Array.isArray(sc.nodes) ? sc.nodes : pick.nodes,
                    storage: sc.type === 'storage_failure' ? sc.storage : pick.storage,
                    pbs: sc.type === 'pbs_failure' ? sc.storage : pick.pbs,
                    netKind: sc.bridge ? 'bridge' : sc.vnet ? 'vnet' : pick.netKind,
                    bridge: sc.bridge || pick.bridge, vnet: sc.vnet || pick.vnet, vlan: '' };
                setPick(next);
                setView('scenario');
                simulate(next);
            };
            const openInsights = onSub ? () => onSub('insights') : null;

            const inv = crWiInv(nav, cid);
            const elapsed = (x) => (x && x.started ? Math.max(0, Math.round((crWiClock() - x.started) / 1000)) : 0);
            const blocked = opts.state !== 'ok' && opts.state !== 'loading';

            return (
                <div className="cr-wi" data-cr-wi={opts.state} data-cr-wi-narrow={narrow ? '1' : '0'} ref={rootRef}>
                    <CrPageHeader icon={<Icons.Scale />} title={t('whatifTitle')} sub={clusterLabel(cluster)}
                        actions={(
                            <div className="cr-seg" role="group" aria-label={t('crWiView')}>
                                {[['scenario', 'whatifViewScenario'], ['ranking', 'crWiViewRanking']].map(([id, label]) => (
                                    <button key={id} type="button" className={view === id ? 'active' : ''} aria-pressed={view === id}
                                        data-cr-wi-view={id} onClick={() => setView(id)}>{t(label)}</button>
                                ))}
                            </div>
                        )} />
                    <p className="cr-wi-intro">{t('crWiIntro')}</p>

                    {opts.state === 'unsupported' && <CrWiNote tone="info" id="opts-unsupported">{t('whatifNotSupported')}</CrWiNote>}
                    {blocked && opts.state !== 'unsupported' && (
                        <CrWiNote tone="error" id={`opts-${opts.state}`} onRetry={opts.state === 'forbidden' ? null : readOpts}>
                            {crFill(t('crWiOptsFailed'), { why: crWiWhy(opts, t, t('crWiWhatSim')) })}
                        </CrWiNote>
                    )}

                    <div className="cr-wi-top">
                        {view === 'scenario'
                            ? <CrWiPicker opts={opts} pick={pick} setPick={setPick} missing={missing(pick)} run={run} elapsed={elapsed(run)}
                                onRun={() => simulate(pick)} />
                            : <CrWiRankPicker opts={opts} pick={pick} setPick={setPick} rank={rank} elapsed={elapsed(rank)} onRun={runRanking} />}
                        <CrWiCapacity cid={cid} authFetch={authFetch} nav={nav} inv={inv} onInsights={openInsights} connected={!!(cluster && cluster.connected)} />
                    </div>

                    {view === 'scenario'
                        ? <CrWiRun run={run} elapsed={elapsed(run)} inv={inv} nav={nav} cid={cid} onRetry={() => run && run.sent && send(run.sent)}
                            onInsights={openInsights} narrow={narrow} />
                        : <CrWiRanking rank={rank} elapsed={elapsed(rank)} inv={inv} nav={nav} cid={cid} onRetry={runRanking} narrow={narrow}
                            onSimulate={simulateCandidate} running={!!(run && run.state === 'running')} />}
                </div>
            );
        }

        // --- the picker --------------------------------------------------------------

        function CrWiField({ label, hint, children, wide }) {
            return (
                <label className={`cr-wi-field${wide ? ' cr-wi-field-wide' : ''}`}>
                    <span className="cr-wi-label">{label}{hint && <span className="cr-muted"> ({hint})</span>}</span>
                    {children}
                </label>
            );
        }

        function CrWiNodePick({ nodes, picked, onToggle }) {
            const { t } = useTranslation();
            const [q, setQ] = useState('');
            const online = nodes.filter(n => n.status === 'online');
            const offline = nodes.length - online.length;
            const shown = q ? online.filter(n => n.name.toLowerCase().includes(q.trim().toLowerCase())) : online;
            const full = picked.length >= CR_WI_MAX_NODES;
            return (
                <fieldset className="cr-wi-nodes" data-cr-wi-nodes="">
                    <legend className="cr-wi-label">
                        {t('whatifNodes')} <span className="cr-muted" data-cr-wi-picked="">{crFill(t('crWiPicked'), { n: picked.length, max: CR_WI_MAX_NODES })}</span>
                    </legend>
                    {online.length > CR_WI_NODE_FILTER && (
                        <input type="search" className="cr-input cr-wi-nodefilter" value={q} onChange={e => setQ(e.target.value)}
                            placeholder={t('crWiFilterNodes')} aria-label={t('crWiFilterNodes')} data-cr-wi-nodefilter="" />
                    )}
                    <div className="cr-wi-chips">
                        {shown.map(n => {
                            const on = picked.includes(n.name);
                            return (
                                <label key={n.name} className={`cr-wi-chip${on ? ' active' : ''}`} title={full && !on ? crFill(t('crWiTooMany'), { n: CR_WI_MAX_NODES }) : undefined}>
                                    <input type="checkbox" checked={on} disabled={full && !on} onChange={() => onToggle(n.name)} data-cr-wi-node={n.name} />
                                    <span>{n.name}</span>
                                    {n.maintenance && <CrBadge tone="warning" dot={false}>{t('whatifStateMaintenance')}</CrBadge>}
                                </label>
                            );
                        })}
                        {!shown.length && <span className="cr-muted">{online.length ? t('crWiNoNodeMatch') : t('crWiNoOnline')}</span>}
                    </div>
                    {offline > 0 && <p className="cr-wi-hint" data-cr-wi-offline="">{crFill(t('crWiOfflineNodes'), { n: offline })}</p>}
                </fieldset>
            );
        }

        function CrWiCommon({ o, pick, set }) {
            const { t } = useTranslation();
            const thrSrc = (s) => (s === 'alert_rule' ? t('whatifThrFromRule') : s === 'request' ? t('whatifThrFromRun') : t('whatifThrDefault'));
            const tagSrc = (s) => (s === 'request' ? t('whatifTagsRequest') : s === 'recovery' ? t('whatifTagsRecovery') : t('whatifTagsDefault'));
            return (
                <div className="cr-wi-common" data-cr-wi-common="">
                    <CrWiField label={t('whatifMemoryBasis')}>
                        <select className="cr-select" value={pick.memory} onChange={e => set({ memory: e.target.value })} data-cr-wi-field="memory">
                            <option value="configured">{t('whatifMemConfigured')}</option>
                            <option value="current">{t('whatifMemCurrent')}</option>
                        </select>
                    </CrWiField>
                    <CrWiField label={t('whatifCpuThreshold')} hint={thrSrc(o.thresholds && o.thresholds.cpu_source)}>
                        <input type="number" min="1" max="100" className="cr-input" value={pick.cpu} onChange={e => set({ cpu: e.target.value })} data-cr-wi-field="cpu" />
                    </CrWiField>
                    <CrWiField label={t('whatifMemThreshold')} hint={thrSrc(o.thresholds && o.thresholds.memory_source)}>
                        <input type="number" min="1" max="100" className="cr-input" value={pick.mem} onChange={e => set({ mem: e.target.value })} data-cr-wi-field="mem" />
                    </CrWiField>
                    <CrWiField label={t('whatifCriticalTags')} hint={tagSrc(o.critical_tags && o.critical_tags.source)} wide>
                        <input type="text" className="cr-input" value={pick.tags} onChange={e => set({ tags: e.target.value })} data-cr-wi-field="tags"
                            title={t('whatifCriticalTagsHint')} />
                    </CrWiField>
                </div>
            );
        }

        function CrWiRunButton({ label, busyLabel, busy, disabled, elapsed, onRun, id }) {
            const { t } = useTranslation();
            return (
                <CrButton variant="primary" icon={busy ? <span className="cr-spinner" aria-hidden="true" /> : <Icons.Play />}
                    onClick={onRun} disabled={disabled || busy} data-cr-wi-run={id} aria-busy={busy ? 'true' : undefined}>
                    {busy ? `${busyLabel} ${crFill(t('crWiSeconds'), { n: elapsed })}` : label}
                </CrButton>
            );
        }

        function CrWiPicker({ opts, pick, setPick, missing, run, elapsed, onRun }) {
            const { t } = useTranslation();
            const o = opts.state === 'ok' ? opts.body : null;
            const set = (patch) => setPick(p => ({ ...p, ...patch }));
            const kind = CR_WI_KINDS.find(k => k.id === pick.kind) || CR_WI_KINDS[0];
            const store = o ? (o.storages || []).find(s => s.storage === pick.storage) : null;
            const bridge = o ? (o.bridges || []).find(b => b.name === pick.bridge) : null;
            const onlineNames = o ? (o.nodes || []).filter(n => n.status === 'online').map(n => n.name) : [];
            const running = !!(run && run.state === 'running');
            return (
                <CrPanel title={t('whatifScenario')} className="cr-wi-picker" data-cr-wi-picker="">
                    <div className="cr-seg cr-wi-kinds" role="group" aria-label={t('whatifScenario')}>
                        {CR_WI_KINDS.map(k => (
                            <button key={k.id} type="button" className={pick.kind === k.id ? 'active' : ''} aria-pressed={pick.kind === k.id}
                                data-cr-wi-kind={k.id} onClick={() => set({ kind: k.id, where: '' })}>{t(k.label)}</button>
                        ))}
                    </div>
                    <p className="cr-wi-hint">{t(kind.desc)}</p>
                    {opts.state === 'loading' && <p className="cr-wi-hint" data-cr-wi-loading=""><span className="cr-spinner" aria-hidden="true" />{t('whatifLoading')}</p>}
                    {o && (
                        <>
                            {(pick.kind === 'node_failure' || pick.kind === 'maintenance') && (
                                <>
                                    <CrWiNodePick nodes={o.nodes || []} picked={pick.nodes}
                                        onToggle={(n) => set({ nodes: pick.nodes.includes(n) ? pick.nodes.filter(x => x !== n) : [...pick.nodes, n] })} />
                                    {pick.kind === 'maintenance' && (
                                        <div className="cr-wi-row">
                                            <label className="cr-switch"><input type="checkbox" checked={pick.allowLocal} onChange={e => set({ allowLocal: e.target.checked })} data-cr-wi-field="local" /><span>{t('whatifAllowLocal')}</span></label>
                                            <label className="cr-switch"><input type="checkbox" checked={pick.relax} onChange={e => set({ relax: e.target.checked })} data-cr-wi-field="relax" /><span>{t('whatifRelaxApart')}</span></label>
                                        </div>
                                    )}
                                </>
                            )}
                            {pick.kind === 'headroom' && (
                                <div className="cr-wi-row">
                                    <CrWiField label={t('whatifDepth')}>
                                        <select className="cr-select" value={pick.depth} onChange={e => set({ depth: parseInt(e.target.value, 10) })} data-cr-wi-field="depth">
                                            <option value={1}>{t('whatifN1')}</option>
                                            <option value={2}>{t('whatifN2')}</option>
                                        </select>
                                    </CrWiField>
                                    <CrWiField label={t('whatifGuestsLabel')}>
                                        <select className="cr-select" value={pick.guests} onChange={e => set({ guests: e.target.value })} data-cr-wi-field="guests">
                                            <option value="all">{t('whatifGuestsAll')}</option>
                                            <option value="ha">{t('whatifGuestsHa')}</option>
                                        </select>
                                    </CrWiField>
                                </div>
                            )}
                            {pick.kind === 'storage_failure' && (
                                <div className="cr-wi-row">
                                    <CrWiField label={t('whatifStorage')}>
                                        <select className="cr-select" value={pick.storage} onChange={e => set({ storage: e.target.value, where: '' })} data-cr-wi-field="storage">
                                            <option value="">-</option>
                                            {(o.storages || []).map(s => <option key={s.storage} value={s.storage}>{s.storage} ({s.shared ? t('whatifShared') : t('whatifLocal')})</option>)}
                                        </select>
                                    </CrWiField>
                                    <CrWiField label={t('whatifWhere')}>
                                        <select className="cr-select" value={pick.where} onChange={e => set({ where: e.target.value })} data-cr-wi-field="where">
                                            <option value="">{t('whatifEverywhere')}</option>
                                            {((store && store.nodes) || []).map(n => <option key={n} value={n}>{n}</option>)}
                                        </select>
                                    </CrWiField>
                                </div>
                            )}
                            {pick.kind === 'pbs_failure' && (
                                <div className="cr-wi-row">
                                    <CrWiField label={t('whatifPbsStorage')}>
                                        <select className="cr-select" value={pick.pbs} onChange={e => set({ pbs: e.target.value })} data-cr-wi-field="pbs" disabled={!(o.pbs || []).length}>
                                            <option value="">-</option>
                                            {(o.pbs || []).map(p => <option key={p.storage} value={p.storage}>{p.storage}</option>)}
                                        </select>
                                    </CrWiField>
                                </div>
                            )}
                            {pick.kind === 'network_failure' && (
                                <div className="cr-wi-row">
                                    <CrWiField label={t('whatifNetKind')}>
                                        <select className="cr-select" value={pick.netKind} onChange={e => set({ netKind: e.target.value, where: '' })} data-cr-wi-field="netkind">
                                            <option value="bridge">{t('whatifBridge')}</option>
                                            <option value="vnet" disabled={!(o.vnets || []).length}>{t('whatifVnet')}</option>
                                        </select>
                                    </CrWiField>
                                    {pick.netKind === 'bridge' ? (
                                        <CrWiField label={t('whatifBridge')}>
                                            <select className="cr-select" value={pick.bridge} onChange={e => set({ bridge: e.target.value, where: '' })} data-cr-wi-field="bridge">
                                                <option value="">-</option>
                                                {(o.bridges || []).map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
                                            </select>
                                        </CrWiField>
                                    ) : (
                                        <CrWiField label={t('whatifVnet')}>
                                            <select className="cr-select" value={pick.vnet} onChange={e => set({ vnet: e.target.value })} data-cr-wi-field="vnet">
                                                <option value="">-</option>
                                                {(o.vnets || []).map(v => <option key={v.vnet} value={v.vnet}>{v.vnet}{v.tag ? ` (${v.tag})` : ''}</option>)}
                                            </select>
                                        </CrWiField>
                                    )}
                                    <CrWiField label={t('whatifVlan')}>
                                        <input type="number" min="1" max="4094" className="cr-input cr-wi-vlan" value={pick.vlan} onChange={e => set({ vlan: e.target.value })} data-cr-wi-field="vlan" />
                                    </CrWiField>
                                    <CrWiField label={t('whatifWhere')}>
                                        <select className="cr-select" value={pick.where} onChange={e => set({ where: e.target.value })} data-cr-wi-field="where">
                                            <option value="">{t('whatifEverywhere')}</option>
                                            {(pick.netKind === 'bridge' && bridge ? bridge.nodes : onlineNames).map(n => <option key={n} value={n}>{n}</option>)}
                                        </select>
                                    </CrWiField>
                                </div>
                            )}
                            <CrWiCommon o={o} pick={pick} set={set} />
                        </>
                    )}
                    <div className="cr-wi-actions">
                        <CrWiRunButton id="scenario" label={t('whatifRun')} busyLabel={t('whatifRunning')} busy={running} disabled={!o || !!missing}
                            elapsed={elapsed} onRun={onRun} />
                        {o && missing && <span className="cr-wi-hint" data-cr-wi-missing="">{missing}</span>}
                        {o && !missing && <span className="cr-wi-hint">{t('crWiReadsOnly')}</span>}
                    </div>
                    <p className="cr-wi-hint cr-wi-notsim" data-cr-wi-notsim="">{t('crWiNotSimulated')}</p>
                </CrPanel>
            );
        }

        function CrWiRankPicker({ opts, pick, setPick, rank, elapsed, onRun }) {
            const { t } = useTranslation();
            const o = opts.state === 'ok' ? opts.body : null;
            const tagSrc = (s) => (s === 'request' ? t('whatifTagsRequest') : s === 'recovery' ? t('whatifTagsRecovery') : t('whatifTagsDefault'));
            const running = !!(rank && rank.state === 'running');
            return (
                <CrPanel title={t('crWiRankTitle')} className="cr-wi-picker" data-cr-wi-rankpicker="">
                    <p className="cr-wi-hint">{t('whatifRankIntro')}</p>
                    {opts.state === 'loading' && <p className="cr-wi-hint"><span className="cr-spinner" aria-hidden="true" />{t('whatifLoading')}</p>}
                    {o && (
                        <div className="cr-wi-common">
                            <CrWiField label={t('whatifCriticalTags')} hint={tagSrc(o.critical_tags && o.critical_tags.source)} wide>
                                <input type="text" className="cr-input" value={pick.tags} onChange={e => setPick(p => ({ ...p, tags: e.target.value }))}
                                    data-cr-wi-field="tags" title={t('whatifCriticalTagsHint')} />
                            </CrWiField>
                        </div>
                    )}
                    <div className="cr-wi-actions">
                        <CrWiRunButton id="ranking" label={t('whatifRankRun')} busyLabel={t('whatifRankRunning')} busy={running} disabled={!o}
                            elapsed={elapsed} onRun={onRun} />
                        <span className="cr-wi-hint">{t('crWiRankCost')}</span>
                    </div>
                </CrPanel>
            );
        }

        // --- a run and its report --------------------------------------------------------

        function CrWiRun({ run, elapsed, inv, nav, cid, onRetry, onInsights, narrow }) {
            const { t } = useTranslation();
            if (!run) {
                return <div className="cr-wi-idle" data-cr-wi-run-state="idle">{t('crWiIdle')}</div>;
            }
            if (run.state === 'running') {
                return (
                    <div className="cr-wi-idle" data-cr-wi-run-state="running" role="status">
                        <span className="cr-spinner" aria-hidden="true" />{crFill(t('crWiRunningFor'), { n: elapsed })}
                    </div>
                );
            }
            if (run.state !== 'ok') {
                return (
                    <div data-cr-wi-run-state={run.state}>
                        <CrWiNote tone={run.state === 'unsupported' ? 'info' : 'error'} id={`run-${run.state}`}
                            onRetry={['forbidden', 'unsupported', 'invalid'].includes(run.state) ? null : onRetry}>
                            {crFill(t('crWiRunFailed'), { why: crWiWhy(run, t, t('crWiWhatSim')) })}
                        </CrWiNote>
                    </div>
                );
            }
            return <CrWiReport key={run.at} rep={run.body} inv={inv} nav={nav} cid={cid} onInsights={onInsights} narrow={narrow} />;
        }

        function CrWiHeadline({ h }) {
            const { t } = useTranslation();
            const title = { blocked: 'crWiVerdictBlocked', incomplete: 'crWiVerdictIncomplete', warning: 'crWiVerdictWarning',
                            ready: 'crWiVerdictReady', none: 'crWiVerdictNone' }[h.state];
            return (
                <div className={`cr-callout cr-callout-${h.tone} cr-wi-verdict`} data-cr-wi-verdict={h.state} data-cr-wi-server={h.level || 'none'}
                    role={h.state === 'blocked' ? 'alert' : undefined}>
                    <span className="cr-ico" aria-hidden="true">{h.state === 'ready' ? <Icons.CheckCircle /> : <Icons.AlertTriangle />}</span>
                    <div>
                        <div className="cr-wi-verdict-title">{t(title)}</div>
                        {h.level && h.state !== h.level && h.state !== 'blocked' && (
                            <div className="cr-wi-verdict-server" data-cr-wi-serverline="">{crFill(t('crWiServerSaid'), { level: t('wiv_level_' + h.level) })}</div>
                        )}
                        {(h.reasons.length > 0 || h.gaps.length > 0 || h.notes.length > 0) && (
                            <ul className="cr-wi-verdict-list">
                                {h.gaps.map(g => <li key={`gap-${g.code}`} data-cr-wi-gap={g.code}>{g.text}</li>)}
                                {h.reasons.map(r => <li key={`r-${r.code}`} data-cr-wi-reason={r.code}>{sayReason(t, 'wiv_', r)}</li>)}
                                {h.notes.map(n => <li key={`n-${n.code}`} data-cr-wi-hrnote={n.code}>{n.text}</li>)}
                            </ul>
                        )}
                        <div className="cr-wi-verdict-basis">{t('crWiVerdictBasis')}</div>
                    </div>
                </div>
            );
        }

        function CrWiReport({ rep, inv, nav, cid, onInsights, narrow }) {
            const { t } = useTranslation();
            const [filter, setFilter] = useState('all');
            const h = useMemo(() => crWiHeadline(rep, t), [rep, t]);
            const s = rep.summary || {};
            const sc = rep.scenario || {};
            const when = rep.generated_at ? Date.parse(rep.generated_at) : NaN;
            const hr = rep.headroom || null;
            const stoppedNote = (rep.assumptions || []).find(a => a.code === 'stopped_guests' || a.code === 'stopped_backups');
            const tile = (o) => {
                const n = crWiNum(s[o.id]) ? s[o.id] : null;
                const on = filter === o.id;
                return (
                    <button key={o.id} type="button" className={`cr-stat cr-stat-click cr-wi-tile cr-wi-tone-${o.tone}${on ? ' active' : ''}`} aria-pressed={on}
                        data-cr-wi-count={o.id} onClick={() => setFilter(on ? 'all' : o.id)} title={t('crWiTileTitle')}>
                        <span className="cr-stat-label">{t(o.label)}</span>
                        <span className="cr-stat-value">{n == null ? '-' : n}</span>
                    </button>
                );
            };
            return (
                <div className="cr-wi-report" data-cr-wi-report={sc.type || ''}>
                    <div className="cr-wi-report-head">
                        <span className="cr-wi-report-title" data-cr-wi-scenario="">{crWiScenario(sc, t)}</span>
                        <span className="cr-muted" title={Number.isFinite(when) ? new Date(when).toLocaleString(crLocale()) : ''}>
                            {Number.isFinite(when) ? crFill(t('crWiGenerated'), { time: crVmWhen(when) }) : ''}
                        </span>
                        <CrWiBasis b="calculated" />
                        <span className="cr-muted">{t('crWiNotMeasured')}</span>
                    </div>
                    <CrWiHeadline h={h} />

                    {!hr && (
                        <section className="cr-stat-row cr-wi-tiles" aria-label={t('crWiOutcomes')}>
                            {CR_WI_OUTCOMES.map(tile)}
                            <div className="cr-stat" data-cr-wi-count="unaffected" title={t('crWiUnaffectedTitle')}>
                                <span className="cr-stat-label">{t('whatifUnaffected')}</span>
                                <span className="cr-stat-value">{crWiNum(s.unaffected) ? s.unaffected : '-'}</span>
                                <span className="cr-stat-sub">{t('crWiRunningOnly')}</span>
                            </div>
                            <div className="cr-stat" data-cr-wi-count="stopped" title={stoppedNote ? crWiAssume(t, stoppedNote) : ''}>
                                <span className="cr-stat-label">{t('stopped')}</span>
                                <span className="cr-stat-value">{crWiNum(s.stopped) ? s.stopped : '-'}</span>
                                <span className="cr-stat-sub">{crWiNum(rep.stopped_affected) && rep.stopped_affected > 0
                                    ? crFill(t('crWiStoppedHit'), { n: rep.stopped_affected }) : t('crWiNotCounted')}</span>
                            </div>
                        </section>
                    )}

                    {hr && <CrWiHeadroom hr={hr} inv={inv} nav={nav} cid={cid} />}
                    <CrWiExtra rep={rep} inv={inv} nav={nav} cid={cid} />

                    <div className="cr-rp-grid2">
                        <CrWiLimits rep={rep} />
                        <CrWiRisk rep={rep} />
                    </div>

                    <CrWiNodes rep={rep} inv={inv} nav={nav} cid={cid} onInsights={onInsights} narrow={narrow} />
                    {!hr && <CrWiGuests rep={rep} inv={inv} nav={nav} cid={cid} filter={filter} setFilter={setFilter} narrow={narrow} />}
                    <CrWiAssumptions rep={rep} />
                </div>
            );
        }

        function CrWiLimits({ rep }) {
            const { t } = useTranslation();
            const list = Array.isArray(rep.limits) ? rep.limits : [];
            const pbs = rep.scenario && rep.scenario.type === 'pbs_failure';
            return (
                <CrPanel title={t(pbs ? 'whatifLimitsPbs' : 'whatifLimits')} className="cr-wi-panel" data-cr-wi-limits="">
                    {!list.length && <p className="cr-wi-hint" data-cr-wi-nolimit="">{t('crWiNoLimit')}</p>}
                    {list.length > 0 && (
                        <ul className="cr-wi-list">
                            {list.map(l => (
                                <li key={l.code} data-cr-wi-limit={l.code}>
                                    <span>{crWiLimit(t, l)}</span>
                                    <CrWiBasis b={l.basis} />
                                </li>
                            ))}
                        </ul>
                    )}
                </CrPanel>
            );
        }

        function CrWiRisk({ rep }) {
            const { t } = useTranslation();
            const r = rep.risk;
            if (!r) {
                return (
                    <CrPanel title={t('whatifRiskTitle')} className="cr-wi-panel" data-cr-wi-risk="none">
                        <p className="cr-wi-hint">{t('crWiGapRisk')}</p>
                    </CrPanel>
                );
            }
            const crit = r.critical || {};
            const restore = r.restore || {};
            const tenants = (r.tenants && r.tenants.items) || [];
            const tagSrc = (s) => (s === 'request' ? t('whatifTagsRequest') : s === 'recovery' ? t('whatifTagsRecovery') : t('whatifTagsDefault'));
            return (
                <CrPanel title={t('whatifRiskTitle')} className="cr-wi-panel" data-cr-wi-risk="">
                    <dl className="cr-ins-kv cr-wi-kv">
                        <dt>{t('whatifColCritical')}</dt>
                        <dd data-cr-wi-risk-critical="">
                            {crWiSay(t, 'whatifRiskCritical', { n: crit.affected ?? '-', total: crit.in_cluster ?? '-', down: crit.down ?? '-' })} <CrWiBasis b={crit.basis} />
                            <div className="cr-muted">{crWiSay(t, 'whatifRiskTagsFrom', { tags: (crit.tags || []).join(', ') || '-', source: tagSrc(crit.source) })}</div>
                        </dd>
                        <dt>{t('crWiRestoreTests')}</dt>
                        <dd data-cr-wi-risk-restore="">
                            <span className="cr-wi-counts">
                                <span>{t('crVmRtPassed')}: {restore.proven ?? 0}</span>
                                <span>{t('crWiNoPass')}: {restore.not_proven ?? 0}</span>
                                <span>{t('crVmRtFailing')}: {restore.failing ?? 0}</span>
                                <span>{t('crWiMarksUnread')}: {restore.unknown ?? 0}</span>
                            </span> <CrWiBasis b={restore.basis} />
                        </dd>
                        <dt>{t('whatifRiskTenants')}</dt>
                        <dd data-cr-wi-risk-tenants="">
                            {!tenants.length && <span className="cr-muted">{r.tenants && r.tenants.readable === false ? t('crWiTenantsUnread') : t('whatifRiskNoTenants')}</span>}
                            {tenants.map(x => <div key={x.id} data-cr-wi-tenant={x.id}><span className="cr-strong">{x.name}</span>: {crWiSay(t, 'whatifRiskTenantRow', { n: x.affected, down: x.down, critical: x.critical })}</div>)}
                            <CrWiBasis b={(r.tenants && r.tenants.basis) || 'assumed'} /> <span className="cr-muted">{t('crWiTenantsPerCluster')}</span>
                        </dd>
                        {r.weight && (
                            <>
                                <dt>{t('whatifRankWeight')}</dt>
                                <dd data-cr-wi-risk-weight="" title={crWiSay(t, 'whatifRankWeighting', Object.assign({ factor: r.weight.critical_factor }, r.weight.outcomes))}>
                                    <span className="cr-mono">{r.weight.value}</span> <CrWiBasis b={r.weight.basis} /> <span className="cr-muted">{t('crWiWeightNote')}</span>
                                </dd>
                            </>
                        )}
                    </dl>
                </CrPanel>
            );
        }

        // what only one scenario answers: the storage, the network or the backup storage
        function CrWiExtra({ rep, inv, nav, cid }) {
            const { t } = useTranslation();
            if (rep.storage) {
                const st = rep.storage;
                return (
                    <CrPanel title={t('whatifStorage')} className="cr-wi-panel" data-cr-wi-extra="storage">
                        <dl className="cr-ins-kv cr-wi-kv">
                            <dt>{t('whatifStorage')}</dt>
                            <dd><CrWiStore name={st.storage} node={(st.nodes || []).length === 1 ? st.nodes[0] : null} inv={inv} nav={nav} cid={cid} /> <span className="cr-muted">{st.type || ''} · {st.shared ? t('whatifShared') : t('whatifLocal')}</span></dd>
                            <dt>{t('nodes')}</dt>
                            <dd>{(st.nodes || []).join(', ') || '-'}</dd>
                        </dl>
                    </CrPanel>
                );
            }
            if (rep.network) {
                const nw = rep.network;
                return (
                    <CrPanel title={t('whatifNetKind')} className="cr-wi-panel" data-cr-wi-extra="network">
                        <dl className="cr-ins-kv cr-wi-kv">
                            <dt>{t('crWiNets')}</dt><dd>{(nw.names || []).join(', ') || '-'}</dd>
                            <dt>{t('whatifVnet')}</dt><dd>{(nw.sdn_vnets || []).join(', ') || '-'}</dd>
                            <dt>{t('nodes')}</dt><dd>{(nw.nodes || []).join(', ') || '-'}</dd>
                        </dl>
                    </CrPanel>
                );
            }
            if (rep.pbs) {
                const p = rep.pbs;
                return (
                    <CrPanel title={crWiSay(t, 'whatifPbsTitle', { storage: p.storage })} className="cr-wi-panel" data-cr-wi-extra="pbs"
                        actions={<CrWiBasis b={p.basis} />}>
                        {p.active === false && <CrWiNote tone="warning" id="pbs-inactive">{crWiSay(t, 'whatifLimPbsInactive', { storage: p.storage })}</CrWiNote>}
                        <dl className="cr-ins-kv cr-wi-kv">
                            <dt>{t('crWiJobs')}</dt>
                            <dd data-cr-wi-pbs-jobs="">
                                {p.jobs_read === false ? <span className="cr-muted">{t('crWiJobsUnread')}</span>
                                    : !(p.jobs || []).length ? <span className="cr-muted">{t('whatifPbsNoJobs')}</span>
                                    : (p.jobs || []).map(j => <div key={j.id}>{crWiSay(t, 'whatifPbsJobRow', { id: j.id, schedule: j.schedule || '-', n: j.guests })}</div>)}
                            </dd>
                            <dt>{t('crWiRestorePoints')}</dt>
                            <dd data-cr-wi-pbs-counts="">{p.points_read === false ? <span className="cr-muted">{t('crWiPointsUnread')}</span>
                                : crWiSay(t, 'whatifPbsCounts', { all: p.guests_all_lost, some: p.guests_some_lost, job: p.guests_job_only })}</dd>
                            <dt>{t('crWiRestoreTests')}</dt>
                            <dd data-cr-wi-pbs-tests="">{crWiSay(t, 'whatifPbsTests', { n: p.tests_lost, unmatched: p.tests_unmatched })}</dd>
                        </dl>
                    </CrPanel>
                );
            }
            return null;
        }

        function CrWiHeadroom({ hr, inv, nav, cid }) {
            const { t } = useTranslation();
            const combos = Array.isArray(hr.combinations) ? hr.combinations : [];
            const pct = (v) => (crWiNum(v) ? `${v.toFixed(1)}%` : '-');
            const columns = useMemo(() => [
                { key: 'failed', label: t('whatifFailedNodes'), flex: true, min: 150, sortValue: c => (c.failed || []).join('+'),
                  render: c => <span className="cr-wi-nodelist">{(c.failed || []).map((n, i) => <React.Fragment key={n}>{i > 0 && ' + '}<CrWiNode name={n} inv={inv} nav={nav} cid={cid} /></React.Fragment>)}</span> },
                { key: 'ok', label: t('status'), width: 136, sortValue: c => (c.ok ? 1 : 0),
                  render: c => <span data-cr-wi-combo={c.ok ? 'ok' : 'failing'}><CrBadge tone={c.ok ? 'success' : 'error'}>{c.ok ? t('crWiWithin') : t('crWiOverloads')}</CrBadge></span> },
                { key: 'quorum', label: t('whatifQuorum'), width: 84, sortValue: c => (c.quorate ? 1 : 0),
                  render: c => (c.quorate ? t('whatifQuorumOk') : <span className="cr-tone-text cr-tone-error">{t('whatifNoQuorum')}</span>) },
                { key: 'guests', label: t('crWiGuestsMoved'), width: 90, align: 'right', mono: true, sortValue: c => c.guests, render: c => (crWiNum(c.guests) ? c.guests : '-') },
                { key: 'mem', label: t('whatifWorstMem'), width: 110, align: 'right', mono: true, sortValue: c => c.worst_mem_pct,
                  render: c => (c.checked === 'totals' ? <span className="cr-muted">{t('whatifByTotals')}</span> : pct(c.worst_mem_pct)) },
                { key: 'cpu', label: t('whatifWorstCpu'), width: 100, align: 'right', mono: true, sortValue: c => c.worst_cpu_pct, render: c => (c.checked === 'totals' ? '-' : pct(c.worst_cpu_pct)) },
                { key: 'over', label: t('whatifOverloaded'), width: 130, sortValue: c => [...new Set([...(c.over_mem || []), ...(c.over_cpu || [])])].join(', ') || null,
                  render: c => [...new Set([...(c.over_mem || []), ...(c.over_cpu || [])])].join(', ') || '-' },
                { key: 'unplaced', label: t('whatifUnplaced'), width: 80, align: 'right', mono: true, sortValue: c => c.unplaced,
                  title: t('crWiUnplacedTitle'), render: c => (c.unplaced == null ? '-' : c.unplaced) },
                { key: 'reserve', label: t('crWiMemReserve'), width: 120, align: 'right', mono: true, sortValue: c => c.mem_reserve, render: c => crBytes(c.mem_reserve) },
                { key: 'checked', label: t('crWiChecked'), width: 124, sortValue: c => c.checked,
                  render: c => <span data-cr-wi-checked={c.checked}><CrBadge tone="neutral" dot={false}>{c.checked === 'totals' ? t('whatifByTotals') : t('crWiPlaced')}</CrBadge></span> },
            ], [t, inv, nav, cid]);
            return (
                <CrPanel title={t('whatifHeadroomTitle')} className="cr-wi-panel" data-cr-wi-headroom={hr.ok ? 'ok' : 'failing'}>
                    <div className="cr-wi-hrhead">
                        <span data-cr-wi-hrline="">{hr.ok ? t('whatifHeadroomOk') : crWiSay(t, 'whatifHeadroomFailing', { n: hr.failing, total: hr.checked })}</span>
                        <span className="cr-muted" data-cr-wi-shown="">{crFill(t('crWiHrShown'), { n: combos.length, total: hr.checked ?? combos.length })}</span>
                    </div>
                    <CrTable id="wi-headroom" columns={columns} rows={combos} rowKey={c => (c.failed || []).join('+')} ariaLabel={t('whatifHeadroomTitle')}
                        rowHeight={30} showCount={false} maxHeight={360} emptyText={t('crWiNoCombos')} />
                </CrPanel>
            );
        }

        function CrWiNodes({ rep, inv, nav, cid, onInsights, narrow }) {
            const { t } = useTranslation();
            const nodes = Array.isArray(rep.nodes) ? rep.nodes : [];
            const thr = rep.thresholds || CR_WI_NONE;
            const src = (s) => (s === 'alert_rule' ? t('whatifThrFromRule') : s === 'request' ? t('whatifThrFromRun') : s === 'default' ? t('whatifThrDefault') : '');
            const meter = (v, limit, title) => <CrMeter value={crWiNum(v) ? v : null} digits={1} tone={crWiTone(v, limit)} title={title} />;
            const columns = useMemo(() => [
                { key: 'node', label: t('whatifNode'), flex: true, min: 110, sortValue: n => n.node,
                  render: n => (
                      <span className="cr-wi-nodecell">
                          <CrWiNode name={n.node} inv={inv} nav={nav} cid={cid} />
                          {n.worst_when && <span className="cr-muted">{crWiSay(t, 'whatifWorstWhen', { nodes: n.worst_when })}</span>}
                      </span>
                  ) },
                { key: 'state', label: t('whatifState'), width: 96, sortValue: n => n.state,
                  render: n => { const [k, tone] = CR_WI_STATES[n.state] || [null, 'neutral']; return <span data-cr-wi-nstate={n.state}><CrBadge tone={tone}>{k ? t(k) : (n.state || '-')}</CrBadge></span>; } },
                { key: 'cpuB', label: `${t('whatifCpu')} ${t('whatifBefore')}`, width: 106, sortValue: n => n.cpu_before, title: t('crWiBeforeTitle'),
                  render: n => meter(n.cpu_before, n.cpu_threshold) },
                { key: 'cpuA', label: `${t('whatifCpu')} ${t('whatifAfter')}`, width: 106, sortValue: n => n.cpu_after, title: t('crWiAfterTitle'),
                  render: n => <span data-cr-wi-over={n.over_cpu ? 'cpu' : ''}>{meter(n.cpu_after, n.cpu_threshold)}</span> },
                { key: 'memB', label: `${t('whatifMem')} ${t('whatifBefore')}`, width: 124, sortValue: n => n.mem_before, title: t('crWiBeforeTitle'),
                  render: n => meter(n.mem_before, n.mem_threshold) },
                { key: 'memA', label: `${t('whatifMem')} ${t('whatifAfter')}`, width: 124, sortValue: n => n.mem_after, title: t('crWiAfterTitle'),
                  render: n => <span data-cr-wi-over={n.over_mem ? 'mem' : ''}>{meter(n.mem_after, n.mem_threshold,
                      crWiNum(n.mem_used_after) ? crFill(t('crUsedOf'), { used: crBytes(n.mem_used_after), total: crBytes(n.mem_total) }) : undefined)}</span> },
                { key: 'thr', label: t('whatifThresholds'), width: narrow ? 120 : 158, align: 'right', mono: true, sortable: false,
                  title: [src(thr.cpu_source), src(thr.memory_source)].filter(Boolean).join(' / ') || undefined,
                  render: n => `${crWiNum(n.cpu_threshold) ? n.cpu_threshold : '-'} / ${crWiNum(n.mem_threshold) ? n.mem_threshold : '-'} %` },
                { key: 'moved', label: t('whatifGuestsMoved'), width: 118, hidden: narrow, align: 'right', mono: true, sortValue: n => (n.guests_in || 0) - (n.guests_out || 0),
                  render: n => `+${n.guests_in ?? 0} / -${n.guests_out ?? 0}` },
                { key: 'flag', label: t('crWiFlag'), width: 120, sortValue: n => (n.overcommitted ? 2 : (n.over_cpu || n.over_mem) ? 1 : 0),
                  render: n => (n.overcommitted ? <CrBadge tone="error">{t('crWiOvercommitted')}</CrBadge>
                      : (n.over_cpu || n.over_mem) ? <CrBadge tone="error">{t('crWiOverThreshold')}</CrBadge> : '') },
            ], [t, inv, nav, cid, thr, narrow]);
            return (
                <CrPanel title={t('whatifNodesTitle')} className="cr-wi-panel" data-cr-wi-nodes-panel=""
                    actions={onInsights ? <CrButton variant="ghost" className="cr-btn-xs" icon={<Icons.Zap />} onClick={onInsights} data-cr-wi-insights="nodes"
                        title={t('crWiInsightsTitle')}>{t('crWiOpenInsights')}</CrButton> : null}>
                    <div className="cr-wi-basisline">
                        <span>{t('whatifBefore')}</span> <CrWiBasis b="known" /> <span className="cr-muted">{t('crWiBeforeNote')}</span>
                        <span className="cr-wi-sep" aria-hidden="true">·</span>
                        <span>{t('whatifAfter')}</span> <CrWiBasis b="calculated" />
                    </div>
                    <CrTable id="wi-nodes" columns={columns} rows={nodes} rowKey={n => n.node} ariaLabel={t('whatifNodesTitle')}
                        rowHeight={30} showCount={false} maxHeight={420} emptyText={t('crWiNoNodes')} />
                    {rep.reserve && (
                        <dl className="cr-wi-reserve" data-cr-wi-reserve="">
                            <div><dt>{t('crWiMemToThr')}</dt><dd className="cr-mono">{crBytes(rep.reserve.mem_to_threshold)}</dd></div>
                            <div><dt>{t('crWiMemToFull')}</dt><dd className="cr-mono">{crBytes(rep.reserve.mem_to_full)}</dd></div>
                            <div><dt>{t('crWiCpuToThr')}</dt><dd className="cr-mono">{rep.reserve.cpu_to_threshold ?? '-'}</dd></div>
                            <div><dt>{t('crWiCpuToFull')}</dt><dd className="cr-mono">{rep.reserve.cpu_to_full ?? '-'}</dd></div>
                            <div className="cr-wi-reserve-basis"><CrWiBasis b={rep.reserve.basis} /> <span className="cr-muted">{t('crWiReserveNote')}</span></div>
                        </dl>
                    )}
                </CrPanel>
            );
        }

        function CrWiGuests({ rep, inv, nav, cid, filter, setFilter, narrow }) {
            const { t } = useTranslation();
            const rows = Array.isArray(rep.guests) ? rep.guests : [];
            const tenantName = useMemo(() => {
                const m = {};
                (((rep.risk || {}).tenants || {}).items || []).forEach(x => { m[x.id] = x.name; });
                return m;
            }, [rep]);
            const counts = useMemo(() => {
                const c = {};
                rows.forEach(g => { c[g.outcome] = (c[g.outcome] || 0) + 1; });
                return c;
            }, [rows]);
            const outcome = (id) => CR_WI_OUTCOMES.find(o => o.id === id) || { id, label: id, tone: 'neutral' };
            const restore = (r) => {
                if (!r) return <span className="cr-muted">-</span>;
                if (r.state === 'unknown') return <span data-cr-wi-restore="unknown"><CrBadge tone="neutral" dot={false}>{t('crWiMarksUnread')}</CrBadge></span>;
                const [key, tone] = CR_WI_RESTORE[r.detail] || (r.state === 'failing' ? CR_WI_RESTORE.failing : r.state === 'proven' ? CR_WI_RESTORE.ok : CR_WI_RESTORE.never);
                return <span data-cr-wi-restore={r.detail || r.state}><CrBadge tone={tone} dot={false}>{t(key)}</CrBadge></span>;
            };
            const columns = useMemo(() => [
                { key: 'guest', label: t('whatifGuest'), width: 200, sortValue: g => g.name || String(g.vmid), text: g => `${g.name || ''} ${g.vmid}`,
                  render: g => (
                      <span className="cr-wi-guestcell">
                          <CrWiGuest g={g} inv={inv} nav={nav} cid={cid} />
                          {g.critical && <span data-cr-wi-critical=""><CrBadge tone="error" dot={false}>{t('whatifCriticalBadge')}</CrBadge></span>}
                      </span>
                  ) },
                { key: 'node', label: t('whatifNode'), width: 100, sortValue: g => g.node, render: g => <CrWiNode name={g.node} inv={inv} nav={nav} cid={cid} /> },
                { key: 'outcome', label: t('whatifOutcome'), width: 104, sortValue: g => CR_WI_OUTCOMES.findIndex(o => o.id === g.outcome), text: g => t(outcome(g.outcome).label),
                  render: g => <span data-cr-wi-outcome={g.outcome}><CrBadge tone={outcome(g.outcome).tone}>{t(outcome(g.outcome).label)}</CrBadge></span> },
                { key: 'target', label: t('whatifTarget'), width: 140, sortValue: g => g.target || null,
                  render: g => (g.target ? (
                      <span className="cr-wi-target">
                          <CrWiNode name={g.target} inv={inv} nav={nav} cid={cid} />
                          {g.target_basis && <CrWiBasis b={g.target_basis} />}
                          {g.risk === 'overcommitted' && <span title={t('whatifRiskOvercommitted')}><CrBadge tone="error" dot={false}>{t('crWiOvercommitted')}</CrBadge></span>}
                      </span>
                  ) : <span className="cr-muted">-</span>) },
                { key: 'why', label: t('whatifReason'), flex: true, min: 170, sortValue: g => (g.reason && g.reason.code) || null, text: g => crWiReason(t, g),
                  render: g => {
                      const why = crWiReason(t, g);
                      return <span className="cr-wi-why" title={why}>{why}{g.restore_test_lost ? ` · ${t('whatifRestoreTestLost')}` : ''}</span>;
                  } },
                { key: 'restore', label: t('crWiRestoreTest'), width: 128, sortValue: g => (g.restore ? g.restore.detail || g.restore.state : null),
                  title: t('crWiRestoreTitle'), render: g => restore(g.restore) },
                { key: 'tenants', label: t('whatifColTenant'), width: 130, hidden: true, title: t('crWiTenantsPerCluster'),
                  sortValue: g => (g.tenants || []).map(id => tenantName[id] || id).join(', ') || null,
                  render: g => (g.tenants || []).map(id => tenantName[id] || id).join(', ') || '-' },
                { key: 'basis', label: t('whatifBasis'), width: 96, hidden: narrow, sortValue: g => g.basis, render: g => <CrWiBasis b={g.basis} /> },
            ], [t, inv, nav, cid, tenantName, narrow]);
            const flt = useMemo(() => (filter === 'all' ? null : g => g.outcome === filter), [filter]);
            const shownN = filter === 'all' ? rows.length : (counts[filter] || 0);
            const affected = CR_WI_OUTCOMES.reduce((n, o) => n + (crWiNum((rep.summary || {})[o.id]) ? rep.summary[o.id] : 0), 0);
            return (
                <CrPanel title={t('whatifGuestsTitle')} className="cr-wi-panel" data-cr-wi-guests="">
                    <CrTable id="wi-guests" columns={columns} rows={rows} rowKey={g => g.vmid} filter={flt} searchable ariaLabel={t('whatifGuestsTitle')}
                        rowHeight={30} maxHeight={480} emptyText={rows.length ? t('crWiNoGuestFilter') : t('whatifNoGuests')}
                        toolbar={(
                            <>
                                <div className="cr-seg" role="group" aria-label={t('whatifOutcome')}>
                                    <button type="button" className={filter === 'all' ? 'active' : ''} aria-pressed={filter === 'all'} data-cr-wi-filter="all"
                                        onClick={() => setFilter('all')}>{t('all')}<span className="cr-seg-n">{rows.length}</span></button>
                                    {CR_WI_OUTCOMES.filter(o => counts[o.id]).map(o => (
                                        <button key={o.id} type="button" className={filter === o.id ? 'active' : ''} aria-pressed={filter === o.id}
                                            data-cr-wi-filter={o.id} onClick={() => setFilter(o.id)}>{t(o.label)}<span className="cr-seg-n">{counts[o.id]}</span></button>
                                    ))}
                                </div>
                                <span className="cr-table-sub" data-cr-wi-listed="">{crFill(t('crWiListed'), { n: shownN, total: affected })}</span>
                            </>
                        )} />
                    {(rep.guests_hidden > 0 || rep.guests_truncated > 0) && (
                        <ul className="cr-rp-foot">
                            {rep.guests_truncated > 0 && <li data-cr-wi-truncated="">{crFill(t('crWiTruncated'), { n: rows.length, total: rows.length + rep.guests_truncated })}</li>}
                            {rep.guests_hidden > 0 && <li data-cr-wi-hidden="">{crWiSay(t, 'whatifHidden', { n: rep.guests_hidden })}</li>}
                        </ul>
                    )}
                </CrPanel>
            );
        }

        function CrWiAssumptions({ rep }) {
            const { t } = useTranslation();
            const list = Array.isArray(rep.assumptions) ? rep.assumptions : [];
            const reads = rep.reads;
            return (
                <CrPanel title={t('whatifAssumptions')} className="cr-wi-panel" data-cr-wi-assumptions="">
                    <ul className="cr-wi-list">
                        {list.map(a => (
                            <li key={a.code} data-cr-wi-assumption={a.code}>
                                <span>{crWiAssume(t, a)}</span>
                                <CrWiBasis b="assumed" />
                            </li>
                        ))}
                    </ul>
                    <ul className="cr-rp-foot">
                        {reads && <li data-cr-wi-reads="">{crWiSay(t, 'whatifReads', { read: reads.configs_read ?? '-', cached: reads.configs_cached ?? '-', unread: reads.configs_unread ?? '-' })}</li>}
                        <li>{t('whatifBasisHelp')}</li>
                    </ul>
                </CrPanel>
            );
        }

        // --- the ranking: single points of failure ------------------------------------------

        function CrWiRanking({ rank, elapsed, inv, nav, cid, onRetry, onSimulate, running, narrow }) {
            const { t } = useTranslation();
            const body = rank && rank.state === 'ok' ? rank.body : null;
            const list = body ? body.ranking : [];
            const columns = useMemo(() => [
                { key: 'n', label: '#', width: 36, align: 'right', mono: true, sortable: false, resizable: false, render: r => list.indexOf(r) + 1 },
                { key: 'kind', label: t('whatifRankKind'), width: 108, sortValue: r => r.kind, render: r => t(CR_WI_RANK_KINDS[r.kind] || 'whatifRankKind') },
                { key: 'name', label: t('whatifRankName'), flex: true, min: 130, sortValue: r => r.name,
                  render: r => (r.kind === 'node' ? <CrWiNode name={r.name} inv={inv} nav={nav} cid={cid} />
                      : r.kind === 'storage' || r.kind === 'pbs' ? <CrWiStore name={r.name} inv={inv} nav={nav} cid={cid} /> : <span>{r.name}</span>) },
                { key: 'affected', label: t('whatifRankAffected'), width: 84, align: 'right', mono: true, sortValue: r => r.affected },
                { key: 'down', label: t('whatifDown'), width: 70, align: 'right', mono: true, sortValue: r => r.down },
                { key: 'deg', label: `${t('whatifDegraded')} / ${t('whatifUnknown')}`, width: 130, align: 'right', mono: true, sortValue: r => (r.degraded || 0) + (r.unknown || 0),
                  render: r => `${r.degraded ?? 0} / ${r.unknown ?? 0}` },
                { key: 'restarted', label: t('whatifRestarted'), width: 88, hidden: narrow, align: 'right', mono: true, sortValue: r => r.restarted },
                { key: 'critical', label: t('whatifRankCritical'), width: 92, align: 'right', mono: true, sortValue: r => r.critical_affected, title: t('crWiCritTitle'),
                  render: r => <span className={r.critical_affected ? 'cr-tone-text cr-tone-error' : 'cr-muted'}>{r.critical_affected ?? 0}{r.critical_down ? ` (${r.critical_down} ${t('whatifDown').toLowerCase()})` : ''}</span> },
                { key: 'weight', label: t('whatifRankWeight'), width: 76, align: 'right', mono: true, sortValue: r => r.weight, title: t('crWiWeightNote') },
                { key: 'unread', label: t('crWiUnread'), width: 84, align: 'right', mono: true, sortValue: r => r.unread, title: t('crWiUnreadTitle'),
                  render: r => (r.unread ? <span className="cr-tone-text cr-tone-warning">{r.unread}</span> : <span className="cr-muted">0</span>) },
                // every candidate is calculated, the head of the result says so: shown on demand
                { key: 'basis', label: t('whatifBasis'), width: 96, hidden: true, sortValue: r => r.basis, render: r => <CrWiBasis b={r.basis} /> },
                { key: 'act', label: '', menuLabel: t('crWiSimulate'), width: 104, sortable: false, resizable: false,
                  render: r => <CrButton className="cr-btn-xs" icon={<Icons.Play />} disabled={running} onClick={e => { e.stopPropagation(); onSimulate(r); }}
                      data-cr-wi-sim={`${r.kind}:${r.name}`} title={t('crWiSimulateTitle')}>{t('crWiSimulate')}</CrButton> },
            ], [t, inv, nav, cid, list, running, onSimulate, narrow]);

            if (!rank) return <div className="cr-wi-idle" data-cr-wi-rank="idle">{t('crWiRankIdle')}</div>;
            if (rank.state === 'running') {
                return <div className="cr-wi-idle" data-cr-wi-rank="running" role="status"><span className="cr-spinner" aria-hidden="true" />{crFill(t('crWiRankingFor'), { n: elapsed })}</div>;
            }
            if (rank.state === 'forbidden') {
                return (
                    <div data-cr-wi-rank="denied">
                        <CrWiNote tone="warning" id="rank-denied">{t('crWiRankDenied')}{rank.msg ? ` (${rank.msg})` : ''}</CrWiNote>
                    </div>
                );
            }
            if (rank.state !== 'ok') {
                return (
                    <div data-cr-wi-rank={rank.state}>
                        <CrWiNote tone={rank.state === 'unsupported' ? 'info' : 'error'} id={`rank-${rank.state}`} onRetry={rank.state === 'unsupported' ? null : onRetry}>
                            {crFill(t('crWiRankFailed'), { why: crWiWhy(rank, t, t('crWiWhatRank')) })}
                        </CrWiNote>
                    </div>
                );
            }
            const g = body.guests || {};
            const when = body.generated_at ? Date.parse(body.generated_at) : NaN;
            const tagSrc = (s) => (s === 'request' ? t('whatifTagsRequest') : s === 'recovery' ? t('whatifTagsRecovery') : t('whatifTagsDefault'));
            const notes = (body.assumptions || []).filter(a => a.code !== 'rank_weighting');
            return (
                <div className="cr-wi-report" data-cr-wi-rank="ok">
                    <div className="cr-wi-report-head">
                        <span className="cr-wi-report-title">{t('crWiRankTitle')}</span>
                        <span className="cr-muted">{Number.isFinite(when) ? crFill(t('crWiGenerated'), { time: crVmWhen(when) }) : ''}</span>
                        <CrWiBasis b="calculated" />
                        <span className="cr-muted" data-cr-wi-rank-guests="">{crFill(t('crWiRankGuests'), { total: g.total ?? '-', running: g.running ?? '-', stopped: g.stopped ?? '-', critical: g.critical ?? '-' })}</span>
                    </div>
                    {(body.capped || []).map(c => (
                        <CrWiNote key={c.kind} tone="warning" id={`capped-${c.kind}`}>{crWiSay(t, 'whatifRankCapped', { kind: t(CR_WI_RANK_KINDS[c.kind] || 'whatifRankKind'), cap: c.cap, total: c.total })}</CrWiNote>
                    ))}
                    {(body.skipped || []).length > 0 && (
                        <CrWiNote tone="warning" id="skipped">{crWiSay(t, 'whatifRankSkipped', { names: body.skipped.map(x => `${x.name} (${x.code})`) })}</CrWiNote>
                    )}
                    {body.stopped && <CrWiNote tone="warning" id="stopped">{crWiSay(t, 'whatifRankStopped', body.stopped)}</CrWiNote>}
                    {body.configs_unread > 0 && <CrWiNote tone="warning" id="unread">{crWiSay(t, 'whatifRankUnread', { n: body.configs_unread })}</CrWiNote>}
                    <CrPanel title={t('crWiSpofTitle')} className="cr-wi-panel" data-cr-wi-spof="">
                        <CrTable id="wi-rank" columns={columns} rows={list} rowKey={r => `${r.kind}:${r.name}`} ariaLabel={t('crWiSpofTitle')}
                            rowHeight={30} maxHeight={480} showCount={false}
                            emptyText={body.considered ? t('crWiRankNone') : t('whatifRankEmpty')}
                            toolbar={<span className="cr-table-sub" data-cr-wi-ranked="">{crFill(t('crWiRanked'), { n: list.length, total: body.considered ?? list.length })}</span>} />
                        <ul className="cr-rp-foot">
                            {body.weighting && (
                                <li data-cr-wi-weighting="">{crWiSay(t, 'whatifRankWeighting', Object.assign({ factor: body.weighting.critical_factor }, body.weighting.outcomes))} {t('crWiWeightNote')}</li>
                            )}
                            <li>{crWiSay(t, 'whatifRiskTagsFrom', { tags: (body.critical_tags || []).join(', ') || '-', source: tagSrc(body.critical_tags_source) })}</li>
                        </ul>
                    </CrPanel>
                    {notes.length > 0 && (
                        <CrPanel title={t('whatifAssumptions')} className="cr-wi-panel" data-cr-wi-assumptions="rank">
                            <ul className="cr-wi-list">
                                {notes.map(a => <li key={a.code} data-cr-wi-assumption={a.code}><span>{crWiAssume(t, a)}</span><CrWiBasis b="assumed" /></li>)}
                            </ul>
                        </CrPanel>
                    )}
                </div>
            );
        }

        // --- capacity: what Insights measured and projects, next to the simulation -------------

        function CrWiCapacity({ cid, authFetch, nav, inv, onInsights, connected }) {
            const { t } = useTranslation();
            const [fc, setFc] = useState({ state: 'loading' });
            const [rs, setRs] = useState({ state: 'loading' });
            const seqF = useRef(0);
            const seqR = useRef(0);
            const readFc = useCallback(async () => {
                if (!cid) return;
                const mine = ++seqF.current;
                setFc({ state: 'loading' });
                const r = await crVmRead(authFetch, `${API_URL}/clusters/${cid}/insights/forecast?days=30`);
                if (mine === seqF.current) setFc(r);
            }, [authFetch, cid]);
            const readRs = useCallback(async () => {
                if (!cid) return;
                const mine = ++seqR.current;
                setRs(prev => (prev.state === 'ok' ? { ...prev, busy: true } : { state: 'loading' }));
                const r = await crVmRead(authFetch, `${API_URL}/clusters/${cid}/insights/right-sizing?days=30`);
                if (mine === seqR.current) setRs(r);
            }, [authFetch, cid]);
            useEffect(() => { readFc(); readRs(); }, [cid]);
            // the server builds right-sizing off the hub and says when it is still at it
            useReportFollowUp(rs.state === 'ok' ? rs.body : null, readRs, [cid]);

            const f = fc.state === 'ok' ? fc.body : null;
            const list = f && f.enough_data && Array.isArray(f.forecasts) ? f.forecasts : [];
            const cl = (m) => list.find(x => x.metric === m);
            // storages the forecast sees crossing within the window, or already warning or above
            const stores = list.filter(x => x.kind === 'storage' && (['warning', 'critical', 'over_threshold'].includes(x.status) || (crInsEtaOk(x) && x.eta_days <= (f.window_days || 30))))
                .sort((a, b) => (crInsEtaOk(a) ? a.eta_days : -1) - (crInsEtaOk(b) ? b.eta_days : -1));
            // the node figures the dashboard polls; none at all is not read, never "no node is busy".
            // A cluster that is not connected keeps old or zero figures there: not shown as now
            const nodeMap = connected ? (inv.nodes || {}) : {};
            const named = Object.keys(nodeMap).filter(n => nodeMap[n] && typeof nodeMap[n] === 'object' && typeof nodeMap[n].status === 'string');
            const hot = named.length ? named.filter(n => nodeMap[n].status === 'online' && nodeMap[n].offline !== true)
                .map(n => ({ n, cpu: nodeMap[n].cpu_percent, mem: nodeMap[n].mem_percent }))
                .filter(x => (crWiNum(x.cpu) && x.cpu > CR_WARN) || (crWiNum(x.mem) && x.mem > CR_WARN))
                .sort((a, b) => Math.max(b.cpu || 0, b.mem || 0) - Math.max(a.cpu || 0, a.mem || 0)) : null;
            const r = rs.state === 'ok' ? rs.body : null;
            const recs = r && Array.isArray(r.recommendations) ? r.recommendations : [];
            const sum = (r && r.summary) || {};
            const flagged = (k) => recs.filter(x => (x.flags || []).some(fl => fl.kind.startsWith(k))).length;

            const fcRow = (x, label) => (
                <div className="cr-wi-caprow" key={x ? x.metric : String(label)} data-cr-wi-capm={x ? x.metric : ''}>
                    <span className="cr-wi-capname">{label}</span>
                    {x ? (
                        <>
                            <CrMeter value={crWiNum(x.current_pct) ? x.current_pct : null} digits={1} tone={x.kind === 'storage' ? crStoreTone(x.current_pct) : undefined}
                                title={t('crInsMeasuredTitle')} />
                            <span className="cr-mono cr-wi-capslope" title={t('crInsTrendTitle')}>{crWiNum(x.slope_per_day_pct) ? `${x.slope_per_day_pct >= 0 ? '+' : ''}${x.slope_per_day_pct.toFixed(2)}/d` : '-'}</span>
                            <span className="cr-wi-capeta">{crInsEta(x, t)}</span>
                        </>
                    ) : <span className="cr-muted">{t('crWiNoForecast')}</span>}
                </div>
            );
            return (
                <CrPanel title={t('crWiCapTitle')} className="cr-wi-cap" data-cr-wi-cap=""
                    actions={onInsights ? <CrButton variant="ghost" className="cr-btn-xs" icon={<Icons.Zap />} onClick={onInsights} data-cr-wi-insights="cap">{t('crWiOpenInsights')}</CrButton> : null}>
                    <p className="cr-wi-hint" data-cr-wi-capbasis="">{t('crWiCapBasis')}</p>

                    <div className="cr-wi-capsec" data-cr-wi-cap-fc={f ? (f.enough_data ? 'ok' : 'notenough') : fc.state}>
                        <div className="cr-wi-capsec-head"><span>{t('capacityForecast')}</span><CrBadge tone="info" dot={false}>{t('crWiForecastBadge')}</CrBadge></div>
                        {fc.state === 'loading' && <p className="cr-wi-hint"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</p>}
                        {fc.state !== 'loading' && fc.state !== 'ok' && (
                            <CrWiNote tone="error" id={`cap-fc-${fc.state}`} onRetry={fc.state === 'forbidden' ? null : readFc}>{crFill(t('crInsReadFailed'), { what: t('capacityForecast'), why: crRpWhy(fc, t) })}</CrWiNote>
                        )}
                        {f && !f.enough_data && <p className="cr-wi-hint" data-cr-wi-capnote="notenough">{crFill(t('crInsNotEnoughN'), { n: f.snapshots_in_window || 0 })}</p>}
                        {f && f.enough_data && (
                            <>
                                {fcRow(cl('cluster_cpu'), t('clusterCpu'))}
                                {fcRow(cl('cluster_memory'), t('clusterMemory'))}
                                {stores.slice(0, 4).map(x => fcRow(x, <CrWiStore name={x.storage || x.metric} inv={inv} nav={nav} cid={cid} />))}
                                {!stores.length && <p className="cr-wi-hint" data-cr-wi-capnote="nostore">{t('crWiNoStoreSoon')}</p>}
                                {stores.length > 4 && <p className="cr-wi-hint">{crFill(t('crWiMoreInInsights'), { n: stores.length - 4 })}</p>}
                                <p className="cr-wi-hint">{crFill(t('crWiFcWindow'), { d: f.window_days, n: f.snapshots_in_window ?? '-' })}</p>
                            </>
                        )}
                    </div>

                    <div className="cr-wi-capsec" data-cr-wi-cap-nodes={!connected ? 'offline' : hot == null ? 'unread' : hot.length ? 'hot' : 'none'}>
                        <div className="cr-wi-capsec-head"><span>{crFill(t('crWiNodesNow'), { pct: CR_WARN })}</span><CrBadge tone="neutral" dot={false}>{t('crWiNowBadge')}</CrBadge></div>
                        {!connected && <p className="cr-wi-hint" data-cr-wi-capnote="offline">{t('crWiNodesOffline')}</p>}
                        {connected && hot == null && <p className="cr-wi-hint">{t('crWiNodesUnread')}</p>}
                        {hot && !hot.length && <p className="cr-wi-hint">{crFill(t('crWiNoHotNode'), { pct: CR_WARN })}</p>}
                        {hot && hot.slice(0, 4).map(x => (
                            <div className="cr-wi-caprow" key={x.n} data-cr-wi-hot={x.n}>
                                <span className="cr-wi-capname"><CrWiNode name={x.n} inv={inv} nav={nav} cid={cid} /></span>
                                <span className="cr-mono">{t('cpu')} {crPct(x.cpu, 0)}</span>
                                <span className="cr-mono">{t('ram')} {crPct(x.mem, 0)}</span>
                            </div>
                        ))}
                        {hot && hot.length > 4 && <p className="cr-wi-hint">{crFill(t('crWiMoreNodes'), { n: hot.length - 4 })}</p>}
                    </div>

                    <div className="cr-wi-capsec" data-cr-wi-cap-rs={rs.state}>
                        <div className="cr-wi-capsec-head"><span>{t('rightSizing')}</span><CrBadge tone="neutral" dot={false}>{t('crWiMeasuredBadge')}</CrBadge></div>
                        {rs.state === 'loading' && <p className="cr-wi-hint"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</p>}
                        {rs.state !== 'loading' && rs.state !== 'ok' && (
                            <CrWiNote tone="error" id={`cap-rs-${rs.state}`} onRetry={rs.state === 'forbidden' ? null : readRs}>{crFill(t('crInsReadFailed'), { what: t('rightSizing'), why: crRpWhy(rs, t) })}</CrWiNote>
                        )}
                        {r && (
                            <div className="cr-ins-counts" data-cr-wi-rscounts="">
                                <span>{crFill(t('crWiRsEvaluated'), { n: recs.length + (sum.ok || 0) })}</span>
                                <span>{crFill(t('crWiRsUnder'), { n: flagged('undersized') })}</span>
                                <span>{crFill(t('crWiRsOver'), { n: flagged('oversized') })}</span>
                                <span>{crFill(t('crWiRsNoData'), { n: sum.no_data || 0 })}</span>
                            </div>
                        )}
                    </div>
                </CrPanel>
            );
        }
