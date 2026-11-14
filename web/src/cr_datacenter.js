        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned: Datacenter > Summary - LW Nov 2026
        // The state of one cluster at a glance, from what the page holds already: the datacenter
        // status the dashboard polls every 30 s (kept per cluster, so a cluster switch never shows
        // the one before), the node list and the guests of the selected cluster (stream and 15 s
        // poll), its datastores and its QDevice. On open it reads three small things itself: the
        // hardware rollup (a cache on the server), the active alerts and the health score the
        // header pill shares. Quorum and infrastructure are two answers: a cluster keeps its
        // quorum with nodes offline. The state of nodes and resources comes from the dashboard's
        // alert rules over the status (an offline node and a lost quorum are critical); the active
        // alerts are listed beside it, not judged in it. A figure
        // nothing reported is "-" with the reason, never a 0. The votes are read from a node only
        // when asked (an SSH call); the page itself never changes anything.
        // ═══════════════════════════════════════════════════════════

        const CR_DC = {
            stale: 75000,        // a status older than two polls of the dashboard and some is not current
            unreadAfter: 45000,  // no status this long after the page came up: say so instead of "reading"
            reasons: 4,          // reasons spelled out under the infrastructure state
        };
        // the order of the state column: what wants a look first
        const CR_DC_RANK = { offline: 0, nodata: 1, maintenance: 2, updating: 3, online: 4 };
        const CR_DC_OFF = new Set(['offline', 'unknown']);
        const crDcNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const crDcOn = (v) => !(v === 0 || v === false || v === '0');

        // What the status of this cluster is, and how old: the newest answer of the dashboard's poll
        // and of a refresh here. read: what the Datacenter tab's own read on open answered ({cid,
        // code, at}). A failed read after the answer makes the answer "not current"; an answer
        // without nodes is Proxmox not delivering its cluster status (vms.py answers zeros then),
        // so it counts as not read, never as an empty cluster.
        function crDcStatus(x) {
            const c = x.cluster || {};
            if (c.cluster_type === 'esxi') return { state: 'unsupported' };
            if (!x.canStatus) return { state: 'forbidden' };
            if (c.connected === false) return { state: 'disconnected', error: c.connection_error || '' };
            const answers = [];
            if (x.entry && x.entry.data) answers.push({ data: x.entry.data, at: new Date(x.entry.lastUpdate).getTime() || 0 });
            if (x.own && x.own.data) answers.push({ data: x.own.data, at: x.own.at });
            answers.sort((a, b) => b.at - a.at);
            const best = answers[0] || null;
            const failed = [x.read, x.own].filter(r => r && r.cid === c.id && r.code !== 200).sort((a, b) => b.at - a.at)[0] || null;
            if (best) {
                const after = failed && failed.at > best.at ? failed : null;
                if (!best.data.nodes || !(best.data.nodes.total > 0)) return { state: 'empty', at: best.at, failed: after };
                const old = x.now - best.at > CR_DC.stale || !!after;
                return { state: old ? 'stale' : 'ok', data: best.data, at: best.at, failed: after };
            }
            if (failed) return { state: 'failed', failed };
            return { state: x.now - x.openedAt > CR_DC.unreadAfter ? 'unread' : 'loading' };
        }

        // the quorum as the status says it; a single node and an XCP-ng pool have none to tell
        function crDcQuorum(st, cluster) {
            if (!st || !st.data) return { state: 'unknown' };
            const cl = st.data.cluster || {};
            if ((cluster && cluster.cluster_type === 'xcpng') || cl.cluster_type === 'xcpng') return { state: 'na' };
            if (cl.standalone === true) return st.data.nodes.total > 1 ? { state: 'unknown', why: 'nocluster' } : { state: 'standalone' };
            if (cl.quorate === true) return { state: 'quorate' };
            if (cl.quorate === false) return { state: 'lost' };
            return { state: 'unknown' };
        }

        // the QDevice of the cluster as the dashboard last read it (null: no corosync to have one)
        function crDcQdevice(q, x) {
            const c = x.cluster || {};
            const cl = x.data && x.data.cluster;
            if (c.cluster_type === 'xcpng' || c.cluster_type === 'esxi' || (cl && cl.standalone === true)) return null;
            if (!x.canNode) return { state: 'forbidden' };
            if (!q) return { state: 'unread' };
            if (q.refused) return { state: 'forbidden' };
            if (!q.present) return { state: 'none' };
            const answered = (q.nodes || []).filter(n => n && n.answered);
            return { state: q.stale ? 'stale' : 'present', tone: qdeviceTone(q), up: answered.filter(n => n.connected).length,
                     answered: answered.length, host: q.qnetd_host || '', algorithm: q.algorithm || '', at: q.read_at || '' };
        }

        // Votes worked out from the corosync node list of the Datacenter tab (quorum_votes, online)
        // and the QDevice: a calculation, labelled as one. Only the fifty-fifty split gives a QDevice
        // one vote; with another algorithm, or a QDevice not known, nothing is worked out.
        function crDcVotes(list, q, canNode) {
            if (!Array.isArray(list) || !list.length) return { state: 'nolist' };
            const votes = list.map(n => parseInt(n && n.quorum_votes, 10));
            if (votes.some(v => !Number.isFinite(v)) || list.some(n => !n || (n.online !== 0 && n.online !== 1))) return { state: 'novotes' };
            let configured = votes.reduce((a, b) => a + b, 0);
            let present = list.reduce((a, n, i) => a + (n.online === 1 ? votes[i] : 0), 0);
            let qdevice = false;
            if (!canNode || !q || q.refused) return { state: 'noqdevice' };
            if (q.present) {
                if (!/fifty|ffsplit/i.test(q.algorithm || '')) return { state: 'algorithm', algorithm: q.algorithm || '' };
                configured += 1;
                qdevice = true;
                if (qdeviceTone(q) === 'ok') present += 1;
            }
            return { state: 'ok', present, configured, needed: Math.floor(configured / 2) + 1, qdevice };
        }

        // VMs and containers of the guest list: templates on their own, stopped without them, and
        // "other" for paused, suspended and whatever else a row says, so the parts add up to the total
        function crDcGuests(rows) {
            const blank = () => ({ total: 0, running: 0, stopped: 0, templates: 0, other: 0 });
            const out = { vms: blank(), cts: blank(), byNode: new Map() };
            (rows || []).forEach(r => {
                if (!r || (r.type !== 'qemu' && r.type !== 'lxc')) return;
                const g = r.type === 'qemu' ? out.vms : out.cts;
                const tpl = r.template === 1 || r.template === true || r.template === '1';
                g.total++;
                if (tpl) g.templates++;
                else if (r.status === 'running') g.running++;
                else if (r.status === 'stopped') g.stopped++;
                else g.other++;
                if (!tpl && r.node) {
                    const n = out.byNode.get(r.node) || { running: 0, total: 0 };
                    n.total++;
                    if (r.status === 'running') n.running++;
                    out.byNode.set(r.node, n);
                }
            });
            return out;
        }

        // Healthy / Degraded / Critical from the dashboard's alert rules (crAlerts) over this status;
        // the hardware rollup read here replaces the status's short copy of it. Without a current
        // status there is no verdict: "not current" keeps the last one only as a note.
        function crDcInfra(x) {
            const c = x.cluster;
            if (!c) return { level: 'unknown', items: [] };
            if (c.connected === false) {
                const { per } = crInventory([c], {});
                return { level: 'critical', items: crAlerts([c], per, x.t) };
            }
            if (!x.st || !x.st.data) return { level: 'unknown', items: [] };
            const live = { ...c, connected: true };
            const { per } = crInventory([live], { [c.id]: { data: x.st.data, lastUpdate: x.st.at } });
            let items = crAlerts([live], per, x.t);
            const hw = x.hw && x.hw.state === 'ok' ? x.hw.body : null;
            if (hw && hw.available) {
                items = items.filter(a => a.kind !== 'hardware');
                if (hw.health === 'warning' || hw.health === 'critical') {
                    items.push({ id: `${c.id}:hardware`, sev: hw.health === 'critical' ? 'error' : 'warning', kind: 'hardware', cluster: c,
                                 name: clusterLabel(c), text: crFill(x.t('crAlertHardware'), { n: (hw.degraded || []).length }) });
                }
            }
            items.sort((a, b) => (a.sev === 'error' ? 0 : 1) - (b.sev === 'error' ? 0 : 1));
            const level = items.some(a => a.sev === 'error') ? 'critical' : items.length ? 'degraded' : 'healthy';
            return { level: x.st.state === 'stale' ? 'stale' : level, last: level, items };
        }

        // the storages of one node that take guest disks (shared ones are the cluster's), active ones
        function crDcLocal(stores, node, state) {
            if (state !== 'ok') return { state };
            const list = ((stores && stores.local) || {})[node] || [];
            const mine = list.filter(s => s && holdsGuestDisks(s) && !s.node_offline && crDcOn(s.active) && crDcOn(s.enabled) && s.total > 0);
            if (!mine.length) return { state: 'none' };
            const used = mine.reduce((a, s) => a + (s.used || 0), 0);
            const total = mine.reduce((a, s) => a + s.total, 0);
            return { state: 'ok', used, total, pct: used / total * 100, names: mine.map(s => s.storage) };
        }

        // One row per node. A row without figures (offline, a status read that failed: mem_total 0,
        // an HA cache stub) gets no CPU, RAM or root file system: those fields are 0 there.
        function crDcNodeRow(name, n, x) {
            const off = n.offline === true || CR_DC_OFF.has(n.status);
            const figures = !off && !n.from_ha_cache && !n.listed && n.mem_total > 0;
            const state = off ? 'offline' : !figures ? 'nodata' : n.maintenance_mode ? 'maintenance' : n.is_updating ? 'updating' : 'online';
            const mem = figures ? { pct: crDcNum(n.mem_percent) ? n.mem_percent : n.mem_used / n.mem_total * 100, used: n.mem_used, total: n.mem_total } : null;
            const root = figures && n.disk_total > 0 ? { pct: n.disk_used / n.disk_total * 100, used: n.disk_used, total: n.disk_total } : null;
            const g = x.guests ? (x.guests.get(name) || { running: 0, total: 0 }) : null;
            return {
                name, state, off, listed: !!n.listed, maint: !!n.maintenance_mode, maintTask: n.maintenance_task || null,
                updating: !!n.is_updating, update: n.update_task || null,
                cpu: figures && crDcNum(n.cpu_percent) ? n.cpu_percent : null, mem, root,
                local: crDcLocal(x.stores, name, x.storesState), guests: g,
                hw: x.hw ? (x.hw.get(name) || null) : undefined, inc: x.incidents ? (x.incidents.get(name) || []) : undefined,
                lastSeen: n.last_seen || null,
            };
        }

        // the node list of the page plus the nodes only the corosync list names (once the list came)
        function crDcNodeRows(x) {
            const m = x.metrics && typeof x.metrics === 'object' ? x.metrics : {};
            const names = Object.keys(m).filter(k => k !== 'error' && k !== 'offline' && m[k] && typeof m[k] === 'object');
            const rows = names.map(n => crDcNodeRow(n, m[n], x));
            if (!names.length) return rows;
            const seen = new Set(names);
            (Array.isArray(x.info) ? x.info : []).forEach(i => {
                const n = i && (i.name || i.node);
                if (!n || seen.has(n)) return;
                seen.add(n);
                rows.push(crDcNodeRow(n, { status: i.online === 0 ? 'offline' : 'online', offline: i.online === 0, listed: true }, x));
            });
            return rows;
        }

        // the warnings of a node row, each from a signal that was read; unknown: what was not
        function crDcWarnings(r, x, t) {
            const out = [];
            const pct = (v) => crPct(v);
            if (r.maint) {
                const mt = r.maintTask;
                const p = mt && crDcNum(mt.progress_percent) && mt.total_vms > 0 ? ` ${crPct(mt.progress_percent)}` : '';
                out.push({ key: 'maint', tone: 'info', text: t('maintenance') + p, title: mt && mt.status ? `${t('maintenance')}: ${mt.status}` : t('maintenance') });
            }
            if (r.updating || (r.update && r.update.status === 'failed')) {
                const failed = r.update && r.update.status === 'failed';
                out.push({ key: 'update', tone: failed ? 'error' : 'info', text: failed ? t('crDcUpdateFailed') : t('crDcUpdating'),
                           title: [r.update && r.update.status, r.update && r.update.phase].filter(Boolean).join(' - ') });
            }
            if (r.cpu != null && crTone(r.cpu) !== 'success') out.push({ key: 'cpu', tone: crTone(r.cpu), text: `CPU ${pct(r.cpu)}`, title: x.cpuScale });
            if (r.mem && crTone(r.mem.pct) !== 'success') out.push({ key: 'mem', tone: crTone(r.mem.pct), text: `RAM ${pct(r.mem.pct)}`, title: x.cpuScale });
            if (r.root && crStoreTone(r.root.pct) !== 'success') out.push({ key: 'root', tone: crStoreTone(r.root.pct), text: `${t('crDcRootFs')} ${pct(r.root.pct)}`, title: x.storeScale });
            if (r.local.state === 'ok' && crStoreTone(r.local.pct) !== 'success') {
                out.push({ key: 'local', tone: crStoreTone(r.local.pct), text: `${t('crDcLocalShort')} ${pct(r.local.pct)}`, title: `${r.local.names.join(', ')} - ${x.storeScale}` });
            }
            if (r.hw && (r.hw.health === 'warning' || r.hw.health === 'critical')) {
                out.push({ key: 'hw', tone: r.hw.health === 'critical' ? 'error' : 'warning', text: t('crDcHwChip'),
                           title: (r.hw.reasons || []).join('; ') || r.hw.health });
            }
            if (r.inc && r.inc.length) {
                const worst = r.inc.some(i => i.severity === 'critical') ? 'error' : r.inc.some(i => i.severity === 'warning') ? 'warning' : 'info';
                out.push({ key: 'inc', tone: worst, text: crFill(t(r.inc.length === 1 ? 'crDcAlert1' : 'crDcAlertN'), { n: r.inc.length }),
                           title: r.inc.map(i => `${i.severity}: ${i.message}${i.acked_by ? ` (${crFill(t('crDcAcked'), { who: i.acked_by })})` : ''}`).join('\n') });
            }
            // the worst first: a narrow column shows the first ones, the cell's title lists them all
            const rank = { error: 0, warning: 1, info: 2 };
            out.sort((a, b) => rank[a.tone] - rank[b.tone]);
            const unknown = [];
            if (r.off || r.state === 'nodata') unknown.push(t('crDcUnknownFigures'));
            if (r.hw === undefined && x.hwWhy) unknown.push(`${t('crDcHardware')} (${x.hwWhy})`);
            if (r.inc === undefined) unknown.push(x.incWhy);
            if (r.local.state !== 'ok' && r.local.state !== 'none') unknown.push(t('crDcUnknownLocal'));
            return { chips: out, unknown: unknown.filter(Boolean) };
        }

        // one GET with what came of it; a 200 that carries an error (active-alerts does that) is no answer
        async function crDcGet(authFetch, url) {
            try {
                const r = await authFetch(url, { quiet: true });
                if (!r) return { state: 'offline', code: 0 };
                if (await haLeaderAway(r)) return { state: 'away', code: 503 };
                const body = await r.json().catch(() => null);
                const msg = body && typeof body.error === 'string' ? body.error : '';
                if (r.ok && body && typeof body === 'object') return { state: body.error ? 'error' : 'ok', code: r.status, body, msg };
                return { state: r.status === 403 ? 'forbidden' : r.status === 404 ? 'notfound' : 'error', code: r.status, msg,
                         errCode: (body && body.code) || '' };
            } catch (e) {
                return { state: 'offline', code: 0 };
            }
        }
        const crDcWhy = (r, t) => (r.state === 'offline' ? t('crDcNoAnswer') : r.state === 'away' ? t('crDcLeaderAway')
            : [r.msg, r.code && r.code !== 200 ? `HTTP ${r.code}` : ''].filter(Boolean).join(' - ') || t('crDcNoAnswer'));

        // The votes read from one node over SSH (pvecm status), kept per cluster while the page is
        // open elsewhere: a remount shows it again and a second click waits for the first.
        const crDcVotesRead = { by: {}, subs: new Set() };
        crSessionStore(() => { crDcVotesRead.by = {}; });
        function useCrDcVotes(cid) {
            const { user } = useAuth();
            crSessionFor(user);
            const [, bump] = useState(0);
            useEffect(() => {
                const f = () => bump(n => n + 1);
                crDcVotesRead.subs.add(f);
                return () => { crDcVotesRead.subs.delete(f); };
            }, []);
            return crDcVotesRead.by[cid] || null;
        }
        function crDcVotesSet(cid, v) {
            crDcVotesRead.by[cid] = v;
            crDcVotesRead.subs.forEach(f => { try { f(); } catch (_) {} });
        }

        // --- the parts of the page ----------------------------------------------------

        function CrDcCell({ id, label, icon, state, tone, value, children }) {
            return (
                <div className="cr-dc-cell" role="group" aria-label={label} data-cr-dc-cell={id} data-cr-dc-value={state}>
                    <div className="cr-dc-cell-head">
                        <span className="cr-ico cr-dc-cell-ico" aria-hidden="true">{icon}</span>
                        <span className="cr-dc-label">{label}</span>
                    </div>
                    <div className={`cr-dc-cell-state cr-dc-tone-${tone}`} data-cr-dc-verdict="">
                        <span className={tone === 'neutral' ? 'cr-dot' : `cr-dot cr-dot-${tone}`} aria-hidden="true" />
                        <span>{value}</span>
                    </div>
                    <div className="cr-dc-cell-body">{children}</div>
                </div>
            );
        }

        function CrDcLine({ id, tone, title, children }) {
            return (
                <p className="cr-dc-line" data-cr-dc-line={id} title={title}>
                    {tone && <span className={`cr-dot cr-dot-${tone}`} aria-hidden="true" />}
                    <span>{children}</span>
                </p>
            );
        }

        function CrDcTile({ id, icon, label, value, tone, bar, barTone, rows, basis, title }) {
            return (
                <div className="cr-dc-tile" role="group" aria-label={label} data-cr-dc-tile={id} title={title}>
                    <div className="cr-dc-tile-head">
                        <span className="cr-ico cr-dc-tile-ico" aria-hidden="true">{icon}</span>
                        <span className="cr-dc-label">{label}</span>
                        <span className={`cr-dc-tile-value${tone ? ' cr-dc-tone-' + tone : ''}`} data-cr-dc-value="">{value}</span>
                    </div>
                    {bar !== undefined && (
                        <span className={`cr-dc-bar cr-tone-${bar == null ? 'neutral' : barTone}`} aria-hidden="true">
                            <span style={{ width: `${bar == null ? 0 : Math.min(100, Math.max(0, bar))}%` }} />
                        </span>
                    )}
                    <dl className="cr-dc-kv">
                        {rows.filter(Boolean).map(r => (
                            <div key={r.key} data-cr-dc-kv={r.key} className={r.tone ? `cr-dc-tone-${r.tone}` : undefined}>
                                <dt>{r.label}</dt><dd>{r.value}</dd>
                            </div>
                        ))}
                    </dl>
                    {basis && <p className="cr-dc-basis">{basis}</p>}
                </div>
            );
        }

        function CrDcSummary({ clusterId, cluster, entry, metrics, guests, stores, qdevice, nav, read, clusterNodes, nodesLoading }) {
            const { t } = useTranslation();
            const { user } = useAuth();
            const { holds } = crVmCan();
            const authFetch = nav && nav.authFetch;
            const c = cluster || { id: clusterId };
            const kind = c.cluster_type || 'proxmox';
            const live = c.connected !== false && kind !== 'esxi';
            const canStatus = holds('cluster.view');
            const canNode = holds('node.view');
            const canStore = holds('storage.view');
            const opened = useRef(Date.now());
            const now = Date.now();

            // the three reads of this page, again on Refresh together with the status itself. The active
            // alerts come through the store the alert strip shares (cr_alerts.js): a fresh answer of the
            // strip is taken as it is, Refresh asks again
            const [hw, setHw] = useState(null);
            const incHeld = crUseAlertsStore(live ? clusterId : null);
            const inc = incHeld ? { ...incHeld.res, at: incHeld.at } : null;
            const [score, setScore] = useState(null);
            const [own, setOwn] = useState(null);
            const [busy, setBusy] = useState(false);
            const run = useRef({ gen: 0, busy: false });
            const load = async (withStatus) => {
                if (!authFetch || run.current.busy) return;
                const gen = ++run.current.gen;
                run.current.busy = true;
                setBusy(true);
                const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}`;
                const mine = (fn) => (v) => { if (gen === run.current.gen) fn(v); };
                const jobs = [];
                if (live && kind === 'proxmox' && canNode) jobs.push(crDcGet(authFetch, `${base}/hardware/health`).then(mine(setHw)));
                if (live) jobs.push(crAlertsRead(authFetch, clusterId, withStatus));
                if (live && canStatus) {
                    jobs.push(readClusterHealth(clusterId, authFetch, API_URL, (user && user.username) || '')
                        .then(mine(d => setScore({ body: d, at: Date.now() })), mine(() => setScore({ body: null, at: Date.now() }))));
                    if (withStatus) {
                        jobs.push(crDcGet(authFetch, `${base}/datacenter/status`).then(mine(r => setOwn({
                            cid: clusterId, code: r.state === 'ok' ? 200 : r.code, at: Date.now(), data: r.state === 'ok' ? r.body : null, msg: r.msg }))));
                    }
                }
                await Promise.all(jobs);
                if (gen === run.current.gen) {
                    run.current.busy = false;
                    setBusy(false);
                }
            };
            useEffect(() => {
                load(false);
                return () => { run.current.gen++; };
            }, []);

            // the votes from one node, only on a click (SSH, up to 12 s)
            const votesRead = useCrDcVotes(clusterId);
            const readVotes = async (node) => {
                const cur = crDcVotesRead.by[clusterId];
                if (!authFetch || (cur && cur.busy)) return;
                const gen = crSession.gen;
                crDcVotesSet(clusterId, { busy: true, node });
                const r = await crDcGet(authFetch, `${API_URL}/clusters/${encodeURIComponent(clusterId)}/nodes/${encodeURIComponent(node)}/cluster-health`);
                if (gen === crSession.gen) crDcVotesSet(clusterId, { busy: false, node, at: Date.now(), r });
            };

            // when the node list last changed in this page (a new object per frame and per poll)
            const seen = useRef({ m: null, at: 0, g: null, gat: 0 });
            if (seen.current.m !== metrics) Object.assign(seen.current, { m: metrics, at: now });
            if (seen.current.g !== guests) Object.assign(seen.current, { g: guests, gat: now });
            const read$ = nav && nav.listsRead ? nav.listsRead(clusterId) : { guests: false, nodes: false, stores: false };
            const nodeKeys = metrics && typeof metrics === 'object' ? Object.keys(metrics).filter(k => k !== 'error' && k !== 'offline') : [];
            const nodesRead = canStatus && (nodeKeys.length > 0 || read$.nodes);
            const guestsRead = Array.isArray(guests) && (guests.length > 0 || read$.guests);
            const storesState = !canStore ? 'forbidden' : read$.stores ? 'ok' : 'unread';

            const st = crDcStatus({ cluster: c, entry, read, own, canStatus, now, openedAt: opened.current });
            const data = st.data || null;
            const q = crDcQuorum(st, c);
            const qd = crDcQdevice(qdevice, { cluster: c, data, canNode, t });
            const votes = crDcVotes(clusterNodes, qdevice, canNode);
            const infra = crDcInfra({ cluster: c, st, hw, t });
            const g = useMemo(() => (guestsRead ? crDcGuests(guests) : null), [guests, guestsRead]);

            const hwBody = hw && hw.state === 'ok' ? hw.body : null;
            const hwMap = useMemo(() => {
                if (!hwBody || !hwBody.available) return null;
                const m = new Map();
                (hwBody.degraded || []).forEach(d => { if (d && d.node) m.set(d.node, d); });
                return m;
            }, [hwBody]);
            // an answer without the list is no answer either
            const incOk = !!(inc && inc.state === 'ok' && inc.body && Array.isArray(inc.body.active_alerts));
            const incRows = incOk ? inc.body.active_alerts : null;
            // node incidents reach only an account that may see the nodes (alerts.py drops them otherwise)
            const incMap = useMemo(() => {
                if (!incRows || !canNode) return null;
                const m = new Map();
                incRows.forEach(i => { if (i && i.target_type === 'node' && i.target_name) m.set(i.target_name, [...(m.get(i.target_name) || []), i]); });
                return m;
            }, [incRows, canNode]);
            const cpuScale = crFill(t('crDcCpuScale'), { warn: CR_WARN, crit: CR_CRIT });
            const storeScale = crStoreScale(t);
            const infraRules = crFill(t('crDcInfraRules'), { warn: CR_WARN, crit: CR_CRIT, swarn: CR_STORE_WARN, scrit: CR_STORE_CRIT });
            const hwWhy = kind !== 'proxmox' ? '' : !canNode ? t('crDcHwNoAccess') : !hw ? t('crDcHwReading')
                : hw.state === 'forbidden' && hw.errCode === 'CONSENT_REQUIRED' ? t('crDcHwOff')
                : hw.state === 'ok' && !(hwBody && hwBody.available) ? t('crDcHwNone') : hw.state !== 'ok' ? t('crDcHwUnread') : '';
            const incWhy = !canNode ? t('crDcIncNoAccess') : !inc ? t('crDcIncReading') : !incOk ? t('crDcIncUnread') : '';
            const rows = useMemo(() => (nodesRead ? crDcNodeRows({
                metrics, info: clusterNodes, stores, storesState, guests: g ? g.byNode : null, hw: hwMap, incidents: incMap,
            }) : []), [metrics, clusterNodes, stores, storesState, g, hwMap, incMap, nodesRead]);

            const tx = { cpuScale, storeScale, hwWhy, incWhy };
            const open = (name) => { if (nav && nav.openNode) nav.openNode(clusterId, name); };
            const clock = (ms) => crAlClock(ms) || '-';

            // --- the status area: connection, quorum, infrastructure ---
            const cl = data && data.cluster;
            const conn = (
                <CrDcCell id="connection" label={t('crDcConnection')} icon={<Icons.Link />}
                    state={kind === 'esxi' ? 'unsupported' : c.connected === false ? 'disconnected' : 'connected'}
                    tone={c.connected === false ? 'error' : kind === 'esxi' ? 'neutral' : 'success'}
                    value={c.connected === false ? t('crDcNotConnected') : t('crDcConnected')}>
                    <CrDcLine id="conn-basis">{t('crDcConnBasis')}</CrDcLine>
                    {c.connected === false && c.connection_error && <CrDcLine id="conn-error" tone="error">{c.connection_error}</CrDcLine>}
                    {cl && cl.standalone === true && st.data.nodes.total === 1 && <CrDcLine id="conn-kind">{crFill(t('crDcStandaloneNode'), { name: cl.name || '' })}</CrDcLine>}
                    {cl && cl.standalone === false && kind === 'proxmox' && cl.name && <CrDcLine id="conn-kind">{`${t('crPveCluster')}: ${cl.name}`}</CrDcLine>}
                    {kind === 'xcpng' && <CrDcLine id="conn-kind">{t('crDcXcpPool')}</CrDcLine>}
                </CrDcCell>
            );

            const qText = { quorate: t('crDcQuorate'), lost: t('crDcNotQuorate'), standalone: t('crDcNoQuorumSingle'),
                            na: t('crDcNotApplicable'), unknown: t('crDcNotRead') }[q.state];
            const qTone = { quorate: 'success', lost: 'error' }[q.state] || 'neutral';
            const qdTone = qd && qd.state === 'present' ? ({ ok: 'success', warn: 'warning', bad: 'error' }[qd.tone] || 'neutral') : null;
            const qdText = !qd ? null
                : qd.state === 'forbidden' ? t('crDcQdNoAccess')
                : qd.state === 'unread' ? t('crDcQdUnread')
                : qd.state === 'none' ? t('crDcQdNone')
                : qd.state === 'stale' ? t('qdeviceStale')
                : crFill(t('crDcQdPresent'), { up: qd.up, n: qd.answered }) + (qd.host ? ` (${qd.host})` : '');
            const firstOnline = rows.filter(r => r.state !== 'offline' && r.state !== 'nodata' && !r.listed).map(r => r.name).sort()[0] || null;
            const mayReadVotes = canNode && live && kind === 'proxmox' && q.state !== 'standalone' && q.state !== 'na' && !!firstOnline;
            const vr = votesRead && votesRead.r;
            const pvecm = vr && vr.state === 'ok' ? vr.body.pvecm : null;
            const quorum = (
                <CrDcCell id="quorum" label={t('crDcQuorum')} icon={<Icons.Scale />} state={q.state} tone={qTone} value={qText}>
                    <CrDcLine id="q-basis">
                        {q.state === 'standalone' ? t('crDcQuorumSingleWhy') : q.state === 'na' ? t('crDcQuorumXcpWhy')
                            : q.why === 'nocluster' ? t('crDcQuorumNoCluster')
                            : data ? crFill(t('crDcQuorumBasis'), { time: clock(st.at) }) : t('crDcQuorumUnread')}
                    </CrDcLine>
                    {q.state === 'quorate' && data.nodes.offline > 0 && (
                        <CrDcLine id="q-held" tone="warning">{crFill(t('crDcQuorumHeld'), { n: data.nodes.offline })}</CrDcLine>
                    )}
                    {qd && (
                        <CrDcLine id="qdevice" tone={qdTone} title={qd.at ? `${t('qdeviceReadAt')} ${clock(new Date(qd.at).getTime())}` : undefined}>
                            {`${t('qdeviceTitle')}: ${qdText}`}
                            {(qd.state === 'present' || qd.state === 'stale') && nav && nav.openQdevice && (
                                <> <button type="button" className="cr-link" data-cr-dc-open="qdevice" onClick={() => nav.openQdevice(clusterId)}>{t('crDcOpen')}</button></>
                            )}
                        </CrDcLine>
                    )}
                    {qd && q.state !== 'unknown' && (
                        <CrDcLine id="votes" title={t('crDcVotesBasis')}>
                            {votes.state === 'ok'
                                ? crFill(t(votes.qdevice ? 'crDcVotesCalcQd' : 'crDcVotesCalc'), { present: votes.present, total: votes.configured, need: votes.needed })
                                : votes.state === 'algorithm' ? crFill(t('crDcVotesAlgo'), { algo: votes.algorithm || '-' })
                                : votes.state === 'noqdevice' ? t('crDcVotesNoQd')
                                : votes.state === 'novotes' ? t('crDcVotesNoVotes')
                                : nodesLoading ? t('crDcVotesWaiting') : t('crDcVotesNoList')}
                        </CrDcLine>
                    )}
                    {votes.state === 'ok' && ((q.state === 'quorate' && votes.present < votes.needed) || (q.state === 'lost' && votes.present >= votes.needed)) && (
                        <CrDcLine id="votes-mismatch" tone="warning">{t('crDcVotesMismatch')}</CrDcLine>
                    )}
                    {mayReadVotes && (
                        <div className="cr-dc-votes" data-cr-dc-votes={votesRead ? (votesRead.busy ? 'running' : vr ? vr.state : '') : ''}>
                            <button type="button" className="cr-btn cr-btn-xs" data-cr-dc-readvotes=""
                                disabled={!!(votesRead && votesRead.busy)} onClick={() => readVotes(firstOnline)} title={t('crDcReadVotesHint')}>
                                {votesRead && votesRead.busy ? <span className="cr-spinner" aria-hidden="true" /> : null}
                                {crFill(t(votesRead && votesRead.busy ? 'crDcReadingVotes' : 'crDcReadVotes'), { node: (votesRead && votesRead.node) || firstOnline })}
                            </button>
                            {vr && !votesRead.busy && (
                                <span className="cr-dc-votes-out" data-cr-dc-votes-out="">
                                    {vr.state !== 'ok' ? crFill(t('crDcVotesFailed'), { why: crDcWhy(vr, t) })
                                        : vr.body.ssh_unavailable ? crFill(t('crDcVotesNoSsh'), { node: votesRead.node })
                                        : pvecm && (crDcNum(pvecm.expected_votes) || crDcNum(pvecm.total_votes))
                                            ? crFill(t('crDcVotesRead'), { node: votesRead.node, time: clock(votesRead.at),
                                                expected: crDcNum(pvecm.expected_votes) ? pvecm.expected_votes : '-',
                                                total: crDcNum(pvecm.total_votes) ? pvecm.total_votes : '-', quorate: pvecm.quorate || '-' })
                                            : crFill(t('crDcVotesNone'), { node: votesRead.node })}
                                </span>
                            )}
                        </div>
                    )}
                </CrDcCell>
            );

            const lvl = infra.level;
            const iText = { healthy: t('crDcHealthy'), degraded: t('crDcDegraded'), critical: t('crDcCritical'),
                            stale: t('crDcNotCurrent'), unknown: t('crDcUnknown') }[lvl];
            const iTone = { healthy: 'success', degraded: 'warning', critical: 'error' }[lvl] || 'neutral';
            const hwLine = kind === 'xcpng' ? t('crDcHwXcp') : kind !== 'proxmox' ? null
                : hwWhy ? hwWhy
                : crFill(t('crDcHwChecked'), { checked: hwBody.checked || 0, total: data ? data.nodes.total : '-', n: (hwBody.degraded || []).length });
            const hwTone = hwBody && hwBody.available ? (hwBody.health === 'critical' ? 'error' : hwBody.health === 'warning' ? 'warning' : 'success') : null;
            const incCount = incRows ? { all: incRows.length, crit: incRows.filter(i => i.severity === 'critical').length } : null;
            const sb = score && score.body;
            // readClusterHealth turns a 503 into a score of 0 with no factors and no time: that is no measurement
            const scoreLine = !canStatus || !live ? null : !score ? t('crDcScoreReading')
                : !sb ? t('crDcScoreUnread')
                : (!Array.isArray(sb.factors) || !sb.factors.length) ? (sb.computed_at === undefined && sb.score === 0 ? t('crDcScoreUnreachable') : t('crDcScoreNoBasis'))
                : crFill(t('crDcScore'), { score: sb.score, band: sb.band || '-' });
            const scoreTitle = sb && Array.isArray(sb.factors) && sb.factors.length
                ? [t('crDcScoreBasis'), ...sb.factors.map(f => `${f.label}: ${f.delta < 0 ? f.delta : 'ok'}`)].join('\n') : t('crDcScoreBasis');
            const infraCell = (
                <CrDcCell id="infra" label={t('crDcInfra')} icon={<Icons.Activity />} state={lvl} tone={iTone} value={iText}>
                    {lvl === 'stale' && <CrDcLine id="i-last">{crFill(t('crDcLastVerdict'), { verdict: { healthy: t('crDcHealthy'), degraded: t('crDcDegraded'), critical: t('crDcCritical') }[infra.last], time: clock(st.at) })}</CrDcLine>}
                    {lvl !== 'unknown' && infra.items.slice(0, CR_DC.reasons).map(a => (
                        <CrDcLine key={a.id} id={`reason-${a.kind}`} tone={a.sev === 'error' ? 'error' : 'warning'}>{a.text}</CrDcLine>
                    ))}
                    {infra.items.length > CR_DC.reasons && <CrDcLine id="reason-more">{crFill(t('crDcMoreReasons'), { n: infra.items.length - CR_DC.reasons })}</CrDcLine>}
                    {(lvl === 'healthy' || lvl === 'degraded' || lvl === 'critical') && <CrDcLine id="i-basis" title={`${infraRules}\n${cpuScale}\n${storeScale}`}>{t('crDcInfraBasis')}</CrDcLine>}
                    {lvl === 'unknown' && <CrDcLine id="i-basis">{t('crDcInfraUnknown')}</CrDcLine>}
                    {hwLine && live && <CrDcLine id="hardware" tone={hwTone} title={hwBody ? t('crDcHwAge') : undefined}>{`${t('crDcHardware')}: ${hwLine}`}</CrDcLine>}
                    {live && (
                        <CrDcLine id="alerts" tone={incCount && incCount.all ? (incCount.crit ? 'error' : 'warning') : null}>
                            {`${t('crDcActiveAlerts')}: `}
                            {!inc ? t('crDcReading') : !incOk ? crFill(t('crDcIncFailed'), { why: crDcWhy(inc, t) })
                                : incCount.all ? crFill(t('crDcIncN'), { n: incCount.all, crit: incCount.crit }) : t('crDcIncNone')}
                            {!canNode && incOk ? ` ${t('crDcIncNoNodes')}` : ''}
                            {nav && nav.openAlerts && incOk && incCount.all > 0 && (
                                <> <button type="button" className="cr-link" data-cr-dc-open="alerts" onClick={() => nav.openAlerts(clusterId)}>{t('crDcOpen')}</button></>
                            )}
                        </CrDcLine>
                    )}
                    {scoreLine && <CrDcLine id="score" title={scoreTitle}>{scoreLine}</CrDcLine>}
                </CrDcCell>
            );

            // --- nodes, guests, resources ---
            const offRows = rows.filter(r => r.state === 'offline').length;
            const maintRows = rows.filter(r => r.maint).length;
            const nodesTile = (() => {
                const from = rows.length ? 'list' : data ? 'status' : null;
                const total = from === 'list' ? rows.length : from === 'status' ? data.nodes.total : null;
                const off = from === 'list' ? offRows : from === 'status' ? data.nodes.offline : null;
                const on = total != null ? total - off : null;
                const differs = from === 'list' && data && (data.nodes.total !== rows.length || data.nodes.offline !== offRows);
                return (
                    <CrDcTile id="nodes" icon={<Icons.Server />} label={t('nodes')} value={total == null ? '-' : total}
                        rows={[
                            { key: 'online', label: t('online'), value: on == null ? '-' : on },
                            { key: 'offline', label: t('offline'), value: off == null ? '-' : off, tone: off > 0 ? 'error' : null },
                            from === 'list' && { key: 'maintenance', label: t('maintenance'), value: maintRows, tone: maintRows > 0 ? 'info' : null },
                        ]}
                        basis={from === 'list' ? (differs ? crFill(t('crDcNodesDiffer'), { on: data.nodes.online, off: data.nodes.offline, time: clock(st.at) })
                                                          : crFill(t('crDcNodesFromList'), { time: clock(seen.current.at) }))
                            : from === 'status' ? crFill(t('crDcNodesFromStatus'), { time: clock(st.at) })
                            : !canStatus ? t('crDcNoAccess') : t('crDcNotReadYet')} />
                );
            })();
            const guestTile = (id, icon, label, part, statusPart) => {
                if (id === 'cts' && kind === 'xcpng') {
                    return <CrDcTile id={id} icon={icon} label={label} value="-" rows={[]} basis={t('crDcNoCtsXcp')} />;
                }
                const p = g ? g[part] : null;
                const sp = data && data.guests ? data.guests[statusPart] : null;
                const differs = p && sp && crDcNum(sp.total) && sp.total !== p.total;
                return (
                    <CrDcTile id={id} icon={icon} label={label} value={p ? p.total : '-'}
                        rows={p ? [
                            { key: 'running', label: t('running'), value: p.running, tone: p.running > 0 ? 'success' : null },
                            { key: 'stopped', label: t('crDcStopped'), value: p.stopped },
                            { key: 'templates', label: t('crDcTemplates'), value: p.templates },
                            { key: 'other', label: t('crDcOther'), value: p.other, tone: p.other > 0 ? 'warning' : null },
                        ] : []}
                        title={t('crDcGuestsWhat')}
                        basis={!p ? (guestsRead ? t('crDcNotReadYet') : t('crDcGuestsUnread'))
                            : differs ? crFill(t('crDcGuestsDiffer'), { n: sp.total, time: clock(st.at) }) : crFill(t('crDcGuestsBasis'), { time: clock(seen.current.gat) })} />
                );
            };
            const res = data && data.resources ? data.resources : {};
            const resTile = (id, icon, label, r, how) => {
                const known = r && r.total > 0 && crDcNum(r.used) && !(id === 'cpu' && kind === 'xcpng');
                const pct = known ? r.used / r.total * 100 : null;
                const tone = pct == null ? null : id === 'storage' ? crStoreTone(pct) : crTone(pct);
                const fmt = id === 'cpu' ? (v) => `${(Math.round(v * 10) / 10).toFixed(1)} ${t('crDcCpus')}` : crBytes;
                const why = !data ? (st.state === 'forbidden' ? t('crDcNoAccess') : t('crDcNotReadYet'))
                    : id === 'cpu' && kind === 'xcpng' ? t('crDcCpuXcp')
                    : !(r && r.total > 0) ? t(id === 'storage' ? 'crDcStorageNone' : 'crDcNoneReported') : '';
                return (
                    <CrDcTile id={id} icon={icon} label={label} value={pct == null ? '-' : crPct(pct, 1)} tone={tone && tone !== 'success' ? tone : null}
                        bar={pct} barTone={tone} title={id === 'storage' ? storeScale : cpuScale}
                        rows={known ? [
                            { key: 'used', label: t('crDcUsed'), value: fmt(r.used) },
                            { key: 'total', label: t('crDcTotal'), value: id === 'cpu' ? `${r.total} ${t('crDcCpus')}` : crBytes(r.total) },
                            { key: 'free', label: t('crDcFree'), value: fmt(Math.max(0, r.total - r.used)) },
                        ] : []}
                        basis={why || crFill(how, { time: clock(st.at) })} />
                );
            };

            // --- the node table ---
            const columns = useMemo(() => [
                { key: 'name', label: t('node'), flex: true, min: 100, sortValue: r => r.name,
                  render: r => <span className="cr-strong cr-dc-node" data-cr-dc-node={r.name}>{r.name}</span> },
                { key: 'state', label: t('status'), width: 100, sortValue: r => CR_DC_RANK[r.state] * 10 + (r.maint ? 1 : 0), text: r => r.state,
                  render: r => r.state === 'nodata'
                      ? <span title={r.listed ? t('crDcListedOnly') : t('crDcNoDataHint')}><CrBadge tone="neutral">{r.listed ? t('crDcListed') : t('crDcNoData')}</CrBadge></span>
                      : r.state === 'updating' ? <CrBadge tone="info">{t('crDcUpdating')}</CrBadge>
                      : <span title={r.off && r.lastSeen ? crFill(t('crDcLastSeen'), { time: crDriftTime(r.lastSeen) }) : undefined}><CrStateBadge state={r.state} /></span> },
                { key: 'cpu', label: t('cpu'), width: 84, align: 'right', sortValue: r => r.cpu, title: cpuScale,
                  render: r => <CrMeter value={r.cpu} title={cpuScale} /> },
                { key: 'mem', label: t('ram'), width: 84, align: 'right', sortValue: r => (r.mem ? r.mem.pct : null), title: cpuScale,
                  render: r => <CrMeter value={r.mem ? r.mem.pct : null} title={r.mem ? crFill(t('crUsedOf'), { used: crBytes(r.mem.used), total: crBytes(r.mem.total) }) : undefined} /> },
                { key: 'root', label: t('crDcRootFs'), width: 84, align: 'right', sortValue: r => (r.root ? r.root.pct : null), title: t('crDcRootFsHint'),
                  render: r => <CrMeter value={r.root ? r.root.pct : null} tone={r.root ? crStoreTone(r.root.pct) : undefined}
                      title={r.root ? crFill(t('crUsedOf'), { used: crBytes(r.root.used), total: crBytes(r.root.total) }) : undefined} /> },
                { key: 'local', label: t('crDcLocal'), width: 112, align: 'right', sortValue: r => (r.local.state === 'ok' ? r.local.pct : null), title: t('crDcLocalHint'),
                  render: r => (r.local.state === 'ok'
                      ? <CrMeter value={r.local.pct} tone={crStoreTone(r.local.pct)} title={`${r.local.names.join(', ')}: ${crFill(t('crUsedOf'), { used: crBytes(r.local.used), total: crBytes(r.local.total) })}`} />
                      : <span className="cr-muted" title={{ none: t('crDcLocalNone'), forbidden: t('crDcLocalNoAccess'), unread: t('crDcNotReadYet') }[r.local.state]}>-</span>) },
                { key: 'guests', label: t('guests'), width: 80, align: 'right', sortValue: r => (r.guests ? r.guests.total : null), title: t('crDcNodeGuestsHint'),
                  render: r => (r.guests ? <span className="cr-mono">{`${r.guests.running} / ${r.guests.total}`}</span> : <span className="cr-muted">-</span>) },
                { key: 'warn', label: t('crDcWarnings'), flex: true, min: 110, sortable: false,
                  render: r => {
                      const w = crDcWarnings(r, tx, t);
                      if (w.chips.length) {
                          return (
                              <span className="cr-dc-chips" data-cr-dc-warn={w.chips.map(x => x.key).join(' ')}
                                  title={w.chips.map(x => (x.title && x.title !== x.text ? `${x.text}: ${x.title}` : x.text)).join('\n')}>
                                  {w.chips.map(x => <CrBadge key={x.key} tone={x.tone} title={x.title}>{x.text}</CrBadge>)}
                              </span>
                          );
                      }
                      return w.unknown.length
                          ? <span className="cr-muted" data-cr-dc-warn="unknown" title={crFill(t('crDcWarnUnknown'), { what: w.unknown.join('; ') })}>-</span>
                          : <span className="cr-muted" data-cr-dc-warn="none">{t('crDcWarnNone')}</span>;
                  } },
            ], [t, cpuScale, storeScale, hwWhy, incWhy]);

            // --- what is wrong with the status read, above everything ---
            const callout = (() => {
                const box = (tone, Icon, text, sub) => (
                    <div className={`cr-callout cr-callout-${tone}`} role={tone === 'error' ? 'alert' : undefined} data-cr-dc-callout={st.state}>
                        <Icon className="w-4 h-4" />
                        <div><p>{text}</p>{sub && <p className="cr-muted">{sub}</p>}</div>
                    </div>
                );
                const why = st.failed ? crDcWhy({ state: st.failed.code ? 'error' : 'offline', code: st.failed.code, msg: st.failed.msg }, t) : '';
                switch (st.state) {
                    case 'forbidden': return box('info', Icons.Info, t('crDcForbidden'));
                    case 'unsupported': return box('info', Icons.Info, t('crDcUnsupported'));
                    case 'disconnected': return box('error', Icons.AlertCircle, t('crDcDisconnected'), c.connection_error || '');
                    case 'failed': return box('error', Icons.AlertCircle, crFill(t('crDcFailed'), { why }));
                    case 'empty': return box('warning', Icons.AlertTriangle, t('crDcEmpty'), crFill(t('crDcAnsweredAt'), { time: clock(st.at) }));
                    case 'unread': return box('warning', Icons.AlertTriangle, t('crDcUnread'));
                    case 'stale': return box('warning', Icons.AlertTriangle, crFill(t('crDcStale'), { time: clock(st.at) }), st.failed ? crFill(t('crDcStaleFailed'), { why }) : '');
                    default: return null;
                }
            })();

            const nodesState = !canStatus ? t('crDcNodesNoAccess') : !live ? t('crDcNodesOffline') : t('crDcNodesUnread');
            return (
                <div className="cr-dc" data-cr-dc-sum="" data-cr-dc-state={st.state}>
                    <div className="cr-dc-top">
                        <span className="cr-dc-asof" data-cr-dc-asof="">
                            {st.state === 'loading' && <span className="cr-spinner" aria-hidden="true" />}
                            {data ? crFill(t('crDcAsOf'), { time: clock(st.at) }) : st.state === 'loading' ? t('crDcReadingStatus') : t('crDcNoStatus')}
                        </span>
                        {st.state === 'stale' && <CrBadge tone="warning">{t('crDcNotCurrent')}</CrBadge>}
                        <span className="cr-dc-top-gap" />
                        <button type="button" className="cr-btn cr-btn-xs" data-cr-dc-refresh="" onClick={() => load(true)}
                            disabled={busy || !live} title={t('crDcRefreshHint')} aria-busy={busy || undefined}>
                            {busy ? <span className="cr-spinner" aria-hidden="true" /> : <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>}
                            {t('refresh')}
                        </button>
                    </div>
                    {callout}
                    <section className="cr-panel cr-dc-status" aria-label={t('crDcStatusArea')}>
                        {conn}
                        {quorum}
                        {infraCell}
                    </section>
                    <section className="cr-dc-tiles" aria-label={t('crDcInventory')}>
                        {nodesTile}
                        {guestTile('vms', <Icons.Monitor />, t('virtualMachines'), 'vms', 'vms')}
                        {guestTile('cts', <Icons.Box />, t('containers'), 'cts', 'containers')}
                        {resTile('cpu', <Icons.Cpu />, t('cpu'), res.cpu, t('crDcCpuBasis'))}
                        {resTile('mem', <Icons.MemoryStick />, t('ram'), res.memory, t('crDcMemBasis'))}
                        {resTile('storage', <Icons.HardDrive />, t('crDcStorage'), res.storage, t('crDcStorageBasis'))}
                    </section>
                    <section className="cr-panel cr-dc-nodes" data-cr-dc-nodes="" aria-label={t('crDcNodesTable')}>
                        <CrTable id="dc-nodes" columns={columns} rows={rows} rowKey={r => r.name} rowHeight={30}
                            toolbar={(
                                <>
                                    <h3 className="cr-panel-title">{t('nodes')}</h3>
                                    {rows.length > 0 && <span className="cr-muted cr-dc-nodes-basis">{crFill(t('crDcNodesBasis'), { time: clock(seen.current.at) })}</span>}
                                </>
                            )}
                            initialSort={{ key: 'state', dir: 'asc' }} onRowClick={r => open(r.name)}
                            rowClassName={r => (r.state === 'offline' ? 'cr-dc-row-off' : r.state === 'nodata' ? 'cr-dc-row-nodata' : '')}
                            loading={nodesRead ? false : canStatus && live && now - opened.current < CR_DC.unreadAfter}
                            emptyText={nodesState} searchable={rows.length > 12} ariaLabel={t('crDcNodesTable')} />
                    </section>
                </div>
            );
        }
