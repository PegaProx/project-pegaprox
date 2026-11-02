        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview) - the alert strip under the header. LW Nov 2026
        // One strip in the page flow, in place of the red node banner, the yellow Corporate banner
        // and the "live updates disconnected" overlay of the variant. It reads nothing new: the
        // cluster list and the datacenter status the dashboard polls, the node list of the selected
        // cluster (and of a cluster the sidebar keeps open), the offline nodes of the PegaProx HA
        // monitor, and the active alerts of the selected cluster on the beat of the cluster list.
        // The severity is the one PegaProx gives already: a cluster that is not connected, a lost
        // quorum and an offline node are critical, an offline node in maintenance is information,
        // hardware is what the server's rollup says, an active alert keeps its own. Dismiss hides a
        // line in this browser and for this user only; it never acknowledges anything.
        // Mounted only by the Dashboard in the variant.
        // ═══════════════════════════════════════════════════════════

        const CR_AL = {
            stale: 75000,           // a datacenter status older than two polls of 30 s (and some) is not current
            unreadAfter: 45000,     // a cluster without any status this long after the strip came up says so
            incidentsEvery: 60000,  // the selected cluster's active alerts, read again at most this often
            names: 3,               // names spelled out in a line before "and n more"
            detailNames: 50,        // ... and in the list below it
            keep: 600000,           // a dismissal is forgotten once its condition was gone this long
            liveAfter: 4000,        // the stream is called down after this long, as the classic banner did
        };
        const CR_AL_SEVS = ['critical', 'warning', 'info', 'state'];
        const CR_AL_KINDS = ['disconnected', 'quorum', 'nodes', 'incident', 'hardware', 'maint',
                             'live', 'noaccess', 'unread', 'empty', 'stale', 'alertsunread', 'oddsev'];
        const CR_AL_TONE = { critical: 'error', warning: 'warning', info: 'info', state: 'neutral' };
        const CR_AL_OFF = new Set(['offline', 'unknown']);

        // what the strip says, from the data the page holds; pure, so a test can feed it
        // x: clusters, status (cid -> {data, lastUpdate}), selectedId, nodeMaps (cid -> name -> node),
        //    nodesAt (cid -> ms), haAlerts (nodeAlerts), incidents ({cid, rows, at, state, code}),
        //    canStatus, canNames, live (false once the stream is down long enough), listAt, openedAt, now
        function crAlertItems(x) {
            const out = [];
            const now = x.now;
            const state = { unread: [], stale: [], empty: [] };
            (x.clusters || []).forEach(c => {
                if (!c || !c.id) return;
                const name = clusterLabel(c);
                const base = { cid: c.id, cname: name };
                if (c.connected === false) {
                    out.push({ ...base, sev: 'critical', kind: 'disconnected', at: x.listAt || null, basis: 'list',
                               detail: c.connection_error || '' });
                    return;
                }
                // an ESXi connection has no datacenter status and no nodes of this kind
                if (c.cluster_type === 'esxi') return;
                const e = x.status ? x.status[c.id] : null;
                const at = e && e.lastUpdate ? new Date(e.lastUpdate).getTime() : 0;
                const fresh = e && at && now - at <= CR_AL.stale ? e.data : null;
                // LW Nov 2026 - an answer without any node is Proxmox VE not delivering its cluster status
                // (vms.py answers zeros then), the Datacenter page says the same: not read, never quiet
                const empty = !!fresh && (!fresh.nodes || !(fresh.nodes.total > 0));
                const d = empty ? null : fresh;
                if (e && at && !fresh) state.stale.push({ ...base, at, last: crAlLastKnown(e.data) });
                else if (empty) state.empty.push({ ...base, at });
                else if (!e && x.canStatus && now - x.openedAt > CR_AL.unreadAfter) state.unread.push(base);
                if (d && d.cluster && d.cluster.standalone === false && d.cluster.quorate === false) {
                    out.push({ ...base, sev: 'critical', kind: 'quorum', at, basis: 'status' });
                }
                // offline nodes: the node list names them (and knows maintenance), else the status counts them
                const map = x.nodeMaps ? x.nodeMaps[c.id] : null;
                const names = map && typeof map === 'object' ? Object.keys(map) : [];
                if (names.length) {
                    const off = new Set(names.filter(n => {
                        const m = map[n] || {};
                        return CR_AL_OFF.has(m.status) || m.offline === true;
                    }));
                    let ha = false;
                    if (c.id === x.selectedId) {
                        Object.keys(x.haAlerts || {}).forEach(n => {
                            const a = x.haAlerts[n];
                            if (a && a.cluster_id === c.id && a.status === 'offline' && map[n] && !off.has(n)) { off.add(n); ha = true; }
                        });
                    }
                    const maint = [...off].filter(n => map[n] && map[n].maintenance_mode).sort();
                    const down = [...off].filter(n => !(map[n] && map[n].maintenance_mode)).sort();
                    const nat = (x.nodesAt && x.nodesAt[c.id]) || null;
                    const show = (list) => (x.canNames ? list : null);
                    if (down.length) out.push({ ...base, sev: 'critical', kind: 'nodes', nodes: show(down), count: down.length, at: nat, basis: ha ? 'nodes+ha' : 'nodes' });
                    if (maint.length) out.push({ ...base, sev: 'info', kind: 'maint', nodes: show(maint), count: maint.length, at: nat, basis: 'nodes' });
                } else if (d && d.nodes && d.nodes.offline > 0) {
                    // counts only: whether one of them is in maintenance is not known here
                    out.push({ ...base, sev: 'critical', kind: 'nodes', nodes: null, count: d.nodes.offline, total: d.nodes.total, at, basis: 'status' });
                }
                const hw = d && d.hardware;
                // the server's rollup is a cache of the 5 minute collector, its entries up to 30 minutes old
                if (hw && (hw.health === 'warning' || hw.health === 'critical')) {
                    out.push({ ...base, sev: hw.health, kind: 'hardware', count: hw.degraded || 0, total: hw.checked || 0, at, basis: 'status' });
                }
            });
            // the active alerts of the selected cluster, each with the severity it was stored with
            const inc = x.incidents;
            const sel = (x.clusters || []).find(c => c && c.id === x.selectedId);
            if (inc && sel && inc.cid === sel.id) {
                const base = { cid: sel.id, cname: clusterLabel(sel) };
                if (inc.state === 'ok') {
                    const by = {};
                    const odd = [];
                    (inc.rows || []).forEach(r => {
                        if (!r) return;
                        // a severity PegaProx does not know (the rule API takes any word) is not made info here
                        if (!['critical', 'warning', 'info'].includes(r.severity)) { odd.push(r); return; }
                        (by[r.severity] = by[r.severity] || []).push(r);
                    });
                    Object.keys(by).forEach(sev => out.push({ ...base, sev, kind: 'incident', count: by[sev].length,
                                                              rows: by[sev], at: inc.at, basis: 'alerts' }));
                    if (odd.length) out.push({ ...base, sev: 'state', kind: 'oddsev', count: odd.length, rows: odd, at: inc.at, basis: 'alerts' });
                } else if (inc.state) {
                    out.push({ ...base, sev: 'state', kind: 'alertsunread', at: inc.at || null, basis: 'alerts', reason: inc.state, code: inc.code || 0 });
                }
            }
            if (x.live === false) out.push({ cid: '', cname: '', sev: 'state', kind: 'live', at: null, basis: 'live' });
            if (!x.canStatus && (x.clusters || []).some(c => c && c.connected !== false && c.cluster_type !== 'esxi')) {
                out.push({ cid: '', cname: '', sev: 'state', kind: 'noaccess', at: null, basis: 'status' });
            }
            state.unread.forEach(b => out.push({ ...b, sev: 'state', kind: 'unread', at: null, basis: 'status' }));
            state.empty.forEach(b => out.push({ ...b, sev: 'state', kind: 'empty', at: b.at, basis: 'status' }));
            state.stale.forEach(b => out.push({ ...b, sev: 'state', kind: 'stale', at: b.at, basis: 'status' }));
            out.forEach(it => { it.sig = crAlertSig(it); });
            return out;
        }

        // what an old status said last: kept as words for its line, never as a verdict of now
        function crAlLastKnown(d) {
            if (!d || !d.cluster) return [];
            const out = [];
            if (d.cluster.standalone === false && d.cluster.quorate === false) out.push('quorum');
            if (d.nodes && d.nodes.offline > 0) out.push({ nodes: d.nodes.offline });
            if (d.hardware && (d.hardware.health === 'warning' || d.hardware.health === 'critical')) out.push('hardware');
            return out;
        }

        // what an item showed: the same condition with more nodes (or another set of alerts) is a new one
        function crAlertSig(it) {
            const what = it.nodes ? it.nodes.join(',') : it.rows ? it.rows.map(r => r.id).sort().join(',') : (it.count != null ? String(it.count) : '');
            return [it.sev, it.kind, it.cid, what, it.kind === 'hardware' ? it.total : ''].join('|');
        }

        // per severity, per kind: the lines the strip draws
        function crAlertRows(items) {
            const rows = [];
            CR_AL_SEVS.forEach(sev => {
                const mine = items.filter(it => it.sev === sev);
                if (!mine.length) return;
                const segs = [];
                CR_AL_KINDS.forEach(kind => {
                    const list = mine.filter(it => it.kind === kind).sort((a, b) => a.cname.localeCompare(b.cname));
                    if (list.length) segs.push({ kind, items: list });
                });
                const times = mine.map(it => it.at).filter(Boolean);
                rows.push({ sev, items: mine, segs, at: times.length ? Math.min(...times) : null });
            });
            return rows;
        }

        function crAlNames(list, max, t) {
            if (list.length <= max) return list.join(', ');
            return t('crAlAndMore').replace('{names}', list.slice(0, max).join(', ')).replace('{n}', list.length - max);
        }
        // fmtTime in the UI language (cr.js), the 12h setting read without throwing
        function crAlClock(ms) {
            if (!ms) return '';
            return crFmtTime(new Date(ms));
        }

        // the words of one item (detail: the full list below the strip, else the short form in a line)
        function crAlItemText(it, t, detail) {
            const max = detail ? CR_AL.detailNames : CR_AL.names;
            const nodes = () => (it.nodes ? crAlNames(it.nodes, max, t)
                : (it.count === 1 ? t('crAlOneNode') : t('crAlNNodes').replace('{n}', it.count)));
            switch (it.kind) {
                case 'disconnected': return t('crAlDisconnectedOne').replace('{cluster}', it.cname);
                case 'quorum': return t('crAlQuorumOne').replace('{cluster}', it.cname);
                case 'nodes': return t('crAlNodesOne').replace('{nodes}', nodes()).replace('{cluster}', it.cname);
                case 'maint': return t('crAlMaintOne').replace('{nodes}', nodes()).replace('{cluster}', it.cname);
                case 'hardware': return t('crAlHardwareOne').replace('{n}', it.count).replace('{m}', it.total).replace('{cluster}', it.cname);
                case 'incident': return (it.count === 1 ? t('crAlIncident1') : t('crAlIncidentN').replace('{n}', it.count)).replace('{cluster}', it.cname);
                case 'unread': return t('crAlUnreadOne').replace('{cluster}', it.cname);
                case 'empty': return t('crAlEmptyOne').replace('{cluster}', it.cname);
                case 'oddsev': return (it.count === 1 ? t('crAlOddSev1') : t('crAlOddSevN').replace('{n}', it.count)).replace('{cluster}', it.cname);
                case 'stale': return t('crAlStaleOne').replace('{cluster}', it.cname).replace('{time}', crAlClock(it.at));
                case 'alertsunread': return t('crAlAlertsUnread').replace('{cluster}', it.cname);
                case 'live': return t('crAlLive');
                case 'noaccess': return t('crAlNoAccess');
                default: return '';
            }
        }

        // the words of a kind in a line: one cluster speaks for itself, several are listed after the kind
        function crAlSegText(seg, t) {
            const list = seg.items;
            if (list.length === 1) return crAlItemText(list[0], t, false);
            const names = crAlNames(list.map(it => it.cname), CR_AL.names, t);
            const sum = list.reduce((n, it) => n + (it.count || 0), 0);
            switch (seg.kind) {
                case 'disconnected': return t('crAlDisconnectedN').replace('{clusters}', names);
                case 'quorum': return t('crAlQuorumN').replace('{clusters}', names);
                case 'nodes': return t('crAlNodesN').replace('{n}', sum).replace('{clusters}', names);
                case 'maint': return t('crAlMaintN').replace('{n}', sum).replace('{clusters}', names);
                case 'hardware': return t('crAlHardwareN').replace('{clusters}', names);
                case 'incident': return t('crAlIncidentN').replace('{n}', sum).replace('{cluster}', names);
                case 'unread': return t('crAlUnreadN').replace('{clusters}', names);
                case 'empty': return t('crAlEmptyN').replace('{clusters}', names);
                case 'stale': return t('crAlStaleN').replace('{clusters}', names);
                default: return list.map(it => crAlItemText(it, t, false)).join(', ');
            }
        }

        // where an item came from, and when that was read
        function crAlBasis(it, t) {
            const time = crAlClock(it.at);
            const key = { list: 'crAlBasisList', status: 'crAlBasisStatus', nodes: 'crAlBasisNodes', 'nodes+ha': 'crAlBasisNodesHa',
                          alerts: 'crAlBasisAlerts', live: 'crAlBasisLive' }[it.basis];
            if (it.kind === 'alertsunread') {
                return it.reason === 'away' ? t('crAlAlertsAway')
                    : t('crAlAlertsFailed').replace('{code}', it.code ? `HTTP ${it.code}` : t('crAlNoAnswer'));
            }
            if (it.kind === 'unread') return t('crAlUnreadWhy');
            if (it.kind === 'empty') return t('crAlEmptyWhy').replace('{time}', time || '-');
            if (it.kind === 'stale') {
                const said = crAlLastText(it.last, t);
                return said ? t('crAlStaleLast').replace('{time}', time || '-').replace('{what}', said) : '';
            }
            if (it.kind === 'oddsev') {
                const sevs = [...new Set(it.rows.map(r => String(r.severity == null ? '-' : r.severity)))].join(', ');
                return t('crAlOddSevWhy').replace('{sevs}', sevs).replace('{time}', time || '-');
            }
            if (it.kind === 'nodes' && !it.nodes && it.basis === 'status') return t('crAlBasisCounts').replace('{time}', time);
            const base = key ? t(key).replace('{time}', time || '-') : '';
            if (it.kind === 'hardware') return `${base} ${t('crAlHardwareAge')}`;
            if (it.kind === 'incident' && it.rows) {
                const acked = it.rows.filter(r => r.acked_at).length;
                const muted = it.rows.filter(r => r.muted_until).length;
                const note = [acked ? t('crAlAckedN').replace('{n}', acked) : '', muted ? t('crAlMutedN').replace('{n}', muted) : ''].filter(Boolean).join(', ');
                return note ? `${base} ${t('crAlCountedToo').replace('{what}', note)}` : base;
            }
            return base;
        }
        function crAlLastText(last, t) {
            return (last || []).map(w => (w === 'quorum' ? t('crAlLastQuorum') : w === 'hardware' ? t('crAlLastHardware')
                : w && w.nodes ? (w.nodes === 1 ? t('crAlOneNode') : t('crAlNNodes').replace('{n}', w.nodes)) + ' ' + t('crAlLastOffline') : '')).filter(Boolean).join(', ');
        }

        // --- the active alerts of a cluster, one store for the preview --------------------

        // LW Nov 2026 - the strip, the Datacenter page and Automation > Alerts read the active alerts of a
        // cluster through this store: an answer younger than CR_AL.incidentsEvery is handed out again, a
        // read on its way is shared, and after an ack or a mute the next read goes out at once (force).
        // The store keeps the whole answer ({state, code, body, msg} as crDcGet tells it); each view reads
        // it the way it read its own request before. Per account: alerts.py scopes the rows, so a logout
        // empties it and an answer for the account before is dropped
        const crAlStore = { by: {}, wait: {}, subs: new Set(), seq: 0, gen: 0 };
        crSessionStore(() => { crAlStore.by = {}; crAlStore.wait = {}; crAlStore.gen++; });

        async function crAlStoreGet(authFetch, cid) {
            try {
                const r = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/active-alerts`, { quiet: true });
                if (!r) return { state: 'offline', code: 0, body: null, msg: '' };
                if (await haLeaderAway(r)) return { state: 'away', code: 503, body: null, msg: '' };
                const body = await r.json().catch(() => null);
                const msg = body && typeof body.error === 'string' ? body.error : '';
                // a 200 that carries an error (alerts.py does that) is no answer for the Datacenter page
                if (r.ok && body && typeof body === 'object') return { state: body.error ? 'error' : 'ok', code: r.status, body, msg };
                return { state: r.status === 403 ? 'forbidden' : r.status === 404 ? 'notfound' : 'error', code: r.status, body, msg,
                         errCode: (body && body.code) || '' };
            } catch (e) {
                return { state: 'offline', code: 0, body: null, msg: '' };
            }
        }

        // the store's answer for cid: the held one while it is fresh, else one read (shared while it runs).
        // Resolves to {cid, at, res, seq}, or null for an answer that came back for the account before
        function crAlertsRead(authFetch, cid, force) {
            if (!cid || !authFetch) return Promise.resolve(null);
            const held = crAlStore.by[cid];
            if (!force && held && Date.now() - held.at < CR_AL.incidentsEvery) return Promise.resolve(held);
            const busy = crAlStore.wait[cid];
            if (!force && busy) return busy.p;
            const gen = crAlStore.gen;
            const seq = ++crAlStore.seq;
            const p = crAlStoreGet(authFetch, cid).then(res => {
                if (crAlStore.wait[cid] && crAlStore.wait[cid].seq === seq) delete crAlStore.wait[cid];
                if (gen !== crAlStore.gen) return null;
                const cur = crAlStore.by[cid];
                // a read that went out later (after a write) has answered already: it stands
                if (cur && cur.seq > seq) return cur;
                const e = { cid, at: Date.now(), res, seq };
                crAlStore.by[cid] = e;
                crAlStore.subs.forEach(fn => { try { fn(cid); } catch (_) {} });
                return e;
            });
            crAlStore.wait[cid] = { seq, p };
            return p;
        }

        // what the store holds for cid, as a view may take it: an answer that was already older than
        // CR_AL.incidentsEvery when the view came to this cluster is not taken (the view reads instead,
        // as it did on its own); anything read later is. Draws again when the store gets a new one for cid
        function crUseAlertsStore(cid) {
            const { user } = useAuth();
            crSessionFor(user);
            const pick = useRef({ cid: null, since: 0 });
            if (pick.current.cid !== cid) pick.current = { cid, since: Date.now() };
            const [, bump] = useState(0);
            const drawn = useRef(null);
            const held = cid ? crAlStore.by[cid] || null : null;
            const e = held && held.at >= pick.current.since - CR_AL.incidentsEvery ? held : null;
            drawn.current = held;
            useEffect(() => {
                if (!cid) return undefined;
                const fn = (id) => { if (id === cid) bump(n => n + 1); };
                crAlStore.subs.add(fn);
                // an answer that came between the draw and this subscription
                if ((crAlStore.by[cid] || null) !== drawn.current) bump(n => n + 1);
                return () => { crAlStore.subs.delete(fn); };
            }, [cid]);
            return e;
        }

        // the store's answer as the strip reads it ({cid, rows, at, state, code}): rows from a 2xx answer
        // with the list and no error (a failed read in alerts.py also answers 200, with an empty list), else not read
        function crAlStripView(e) {
            if (!e) return null;
            const r = e.res;
            if (r.state === 'ok' && r.body && Array.isArray(r.body.active_alerts)) {
                return { cid: e.cid, rows: r.body.active_alerts, at: e.at, state: 'ok' };
            }
            return { cid: e.cid, rows: null, at: e.at, state: r.state === 'away' ? 'away' : 'error', code: r.code || 0 };
        }

        // ... as Automation > Alerts reads it: the leader away, else the rows of a 2xx answer or none
        function crAlAutomationView(e) {
            const r = e.res;
            return { away: r.state === 'away', rows: r.code >= 200 && r.code < 300 && r.body ? (r.body.active_alerts || []) : [] };
        }

        // --- the strip --------------------------------------------------------------

        // LW Nov 2026 - what the strip last read of the selected cluster's active alerts, for the node
        // summary (cr_node.js), which asks nothing itself: {cid, rows, at, state} or null
        const crAlSeen = { now: null, subs: new Set() };
        function crAlShare(next) {
            crAlSeen.now = next;
            crAlSeen.subs.forEach(fn => fn(next));
        }
        function crUseAlertsSeen(cid) {
            const [now, setNow] = useState(crAlSeen.now);
            useEffect(() => {
                const fn = (n) => setNow(n);
                crAlSeen.subs.add(fn);
                setNow(crAlSeen.now);
                return () => { crAlSeen.subs.delete(fn); };
            }, []);
            return now && cid && now.cid === cid ? now : null;
        }

        function CrAlertStrip({ clusters, status, selectedId, nodes, sideData, haAlerts, live, nav }) {
            const { t } = useTranslation();
            const { user } = useAuth();
            const { holds } = crVmCan();
            const navRef = useRef(nav);
            navRef.current = nav;
            const authFetch = nav && nav.authFetch;
            const opened = useRef(Date.now());

            // when a node list or the cluster list came: the identity changes with every answer and frame
            const seen = useRef({ maps: new Map(), list: null, listAt: 0 });
            const nodeMaps = useMemo(() => {
                const out = {};
                Object.keys(sideData || {}).forEach(cid => { if (sideData[cid] && sideData[cid].metrics) out[cid] = sideData[cid].metrics; });
                if (selectedId && nodes && Object.keys(nodes).length) out[selectedId] = nodes;
                return out;
            }, [sideData, nodes, selectedId]);
            const nodesAt = {};
            Object.keys(nodeMaps).forEach(cid => {
                const was = seen.current.maps.get(cid);
                if (!was || was.map !== nodeMaps[cid]) seen.current.maps.set(cid, { map: nodeMaps[cid], at: Date.now() });
                nodesAt[cid] = seen.current.maps.get(cid).at;
            });
            if (seen.current.list !== clusters) { seen.current.list = clusters; seen.current.listAt = Date.now(); }

            // the stream: called down once it stayed down a moment, as the classic banner did
            const [down, setDown] = useState(false);
            useEffect(() => {
                if (live) { setDown(false); return undefined; }
                const id = setTimeout(() => setDown(true), CR_AL.liveAfter);
                return () => clearTimeout(id);
            }, [live]);

            // the selected cluster's active alerts: on a pick, then on the beat of the cluster list, through
            // the store (a fresh answer of the Datacenter page or of Automation > Alerts asks nothing)
            const held = crUseAlertsStore(selectedId || null);
            const incidents = useMemo(() => crAlStripView(held), [held]);
            useEffect(() => { crAlShare(incidents); }, [incidents]);
            useEffect(() => {
                if (selectedId) crAlertsRead(authFetch, selectedId);
            }, [selectedId]);
            useEffect(() => () => crAlShare(null), []);
            useEffect(() => {
                if (selectedId) crAlertsRead(authFetch, selectedId);
            }, [clusters]);

            // a figure turns stale by the clock alone: draw again now and then (no request)
            const [, redraw] = React.useReducer(n => n + 1, 0);
            useEffect(() => {
                const id = setInterval(redraw, 15000);
                return () => clearInterval(id);
            }, []);

            const now = Date.now();
            const items = crAlertItems({
                clusters, status, selectedId, nodeMaps, nodesAt, haAlerts, incidents,
                canStatus: holds('cluster.view'), canNames: holds('cluster.view'),
                live: live || !down, listAt: seen.current.listAt, openedAt: opened.current, now,
            });

            // dismissed lines, per user in this browser: signature -> when its condition was last seen
            const dkey = `cr-alerts-dismissed:${(user && user.username) || ''}`;
            const [dismissed, setDismissed] = useState(() => crReadJson(dkey) || {});
            useEffect(() => { setDismissed(crReadJson(dkey) || {}); }, [dkey]);
            const wrote = useRef(0);
            const keepDismissed = (next) => { crWrite(dkey, Object.keys(next).length ? JSON.stringify(next) : null); wrote.current = Date.now(); };
            useEffect(() => {
                const sigs = Object.keys(dismissed);
                if (!sigs.length) return;
                const present = new Set(items.map(it => it.sig));
                const next = {};
                let dropped = false;
                let seenNow = false;
                sigs.forEach(sig => {
                    if (present.has(sig)) { next[sig] = now; seenNow = true; return; }
                    const at = Number(dismissed[sig]) || 0;
                    if (now - at > CR_AL.keep) { dropped = true; return; }
                    next[sig] = at;
                });
                // a forgotten one goes at once, the time a condition was last seen now and then
                if (dropped || (seenNow && now - wrote.current > 60000)) {
                    setDismissed(next);
                    keepDismissed(next);
                }
            });

            const rows = crAlertRows(items);
            const isHidden = (row) => row.items.every(it => dismissed[it.sig] != null);
            const hiddenCritical = rows.find(r => r.sev === 'critical' && isHidden(r));
            const shown = rows.filter(r => !isHidden(r));

            const rootRef = useRef(null);
            const dismiss = (row) => {
                const next = { ...dismissed };
                row.items.forEach(it => { next[it.sig] = Date.now(); });
                setDismissed(next);
                keepDismissed(next);
                // the focus stays in the strip: on what is left of it, else on the page
                setTimeout(() => {
                    const root = rootRef.current;
                    const a = document.activeElement;
                    if (a && a !== document.body && a.isConnected) return;
                    const first = root && root.querySelector('button');
                    if (first) first.focus({ preventScroll: true });
                    else { const main = document.getElementById('cr-main'); if (main) main.focus({ preventScroll: true }); }
                }, 0);
            };
            const restore = (row) => {
                const next = { ...dismissed };
                row.items.forEach(it => { delete next[it.sig]; });
                setDismissed(next);
                keepDismissed(next);
            };

            const [open, setOpen] = useState(false);
            const anyShown = shown.length > 0 || !!hiddenCritical;
            useEffect(() => { if (!anyShown) setOpen(false); }, [anyShown]);

            // the room it takes, for the views that size themselves to the window
            useEffect(() => {
                const el = rootRef.current;
                if (!el) return undefined;
                const put = () => document.body.style.setProperty('--cr-alerts-h', `${Math.round(el.getBoundingClientRect().height)}px`);
                put();
                const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(put) : null;
                if (ro) ro.observe(el);
                return () => { if (ro) ro.disconnect(); document.body.style.removeProperty('--cr-alerts-h'); };
            }, []);

            // where an item leads, and its history where the Timeline keeps one
            const go = (it) => {
                const n = navRef.current;
                if (!n || !it.cid) return null;
                if (it.kind === 'quorum') return n.openDatacenter ? () => n.openDatacenter(it.cid) : null;
                if (it.kind === 'incident' || it.kind === 'alertsunread' || it.kind === 'oddsev') return n.openAlerts ? () => n.openAlerts(it.cid) : null;
                if ((it.kind === 'nodes' || it.kind === 'maint') && it.nodes && it.nodes.length === 1 && n.openNode) return () => n.openNode(it.cid, it.nodes[0]);
                return n.openCluster ? () => n.openCluster(it.cid) : null;
            };
            const history = (it) => {
                const n = navRef.current;
                if (!n || !n.openTimeline || !it.cid || !holds('cluster.view')) return null;
                if (['nodes', 'maint', 'quorum'].includes(it.kind) && holds('node.view')) return () => n.openTimeline(it.cid, { kind: 'node' });
                if (it.kind === 'incident') return () => n.openTimeline(it.cid, { kind: 'alert', severity: it.sev });
                return null;
            };
            const segClick = (seg) => {
                const target = seg.items.length === 1 ? go(seg.items[0]) : null;
                if (target) target();
                else setOpen(true);
            };

            const sevLabel = { critical: t('crAlCritical'), warning: t('crAlWarning'), info: t('crAlInfo'), state: t('crAlState') };
            const sevIcon = { critical: <Icons.AlertCircle />, warning: <Icons.AlertTriangle />, info: <Icons.Info />, state: <Icons.WifiOff /> };
            const detailRows = rows.filter(r => !isHidden(r) || r.sev === 'critical');
            // one switch for the list: on the first line, or beside the chip when every line is dismissed
            const detailsSwitch = (
                <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs cr-al-more" aria-expanded={open}
                    aria-controls={open ? 'cr-al-detail' : undefined} onClick={() => setOpen(o => !o)} data-cr-al-details="">
                    {open ? t('crAlHideDetails') : t('crAlDetails')}
                </button>
            );

            return (
                <div ref={rootRef} className="cr-alerts" role="region" aria-label={t('crAlRegion')} data-cr-alerts="">
                    {hiddenCritical && (
                        <div className="cr-al-row cr-al-row-chip">
                            <button type="button" className="cr-al-chip" onClick={() => restore(hiddenCritical)} data-cr-al-chip=""
                                title={t('crAlChipHint')}>
                                <span className="cr-ico" aria-hidden="true"><Icons.AlertCircle /></span>
                                {t('crAlChip').replace('{n}', hiddenCritical.items.length)}
                            </button>
                            {!shown.length && detailsSwitch}
                        </div>
                    )}
                    {shown.map((row, i) => (
                        <div key={row.sev} className={`cr-al-row cr-al-${row.sev}`} data-cr-al-row={row.sev}>
                            <span className="cr-al-sev">
                                <span className="cr-ico cr-al-ico" aria-hidden="true">{sevIcon[row.sev]}</span>
                                <span className="cr-al-label">{sevLabel[row.sev]}</span>
                                {row.sev !== 'state' && <span className="cr-al-n" data-cr-al-n="">{row.items.length}</span>}
                            </span>
                            <span className="cr-al-segs">
                                {row.segs.map(seg => (
                                    <button key={seg.kind} type="button" className="cr-al-seg" onClick={() => segClick(seg)}
                                        data-cr-al-seg={seg.kind} title={seg.items.map(it => [crAlItemText(it, t, true), it.kind === 'stale' ? crAlBasis(it, t) : ''].filter(Boolean).join(' - ')).join('\n')}>
                                        {crAlSegText(seg, t)}
                                    </button>
                                ))}
                            </span>
                            {row.at && <span className="cr-al-asof" data-cr-al-asof="">{t('crAlAsOf').replace('{time}', crAlClock(row.at))}</span>}
                            {i === 0 ? detailsSwitch : <span className="cr-al-more-gap" aria-hidden="true" />}
                            <button type="button" className="cr-icon-btn cr-al-dismiss" onClick={() => dismiss(row)}
                                aria-label={t('crAlDismissRow').replace('{what}', sevLabel[row.sev])} title={row.sev === 'critical' ? t('crAlDismissCritical') : t('crAlDismissHint')}
                                data-cr-al-dismiss={row.sev}>
                                <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                            </button>
                        </div>
                    ))}
                    {open && anyShown && (
                        <div className="cr-al-detail" id="cr-al-detail" data-cr-al-detail="">
                            {detailRows.map(row => (
                                <div key={row.sev} className="cr-al-group" role="group" aria-label={sevLabel[row.sev]}>
                                    {row.items.map(it => {
                                        const open1 = go(it);
                                        const hist = history(it);
                                        return (
                                            <div key={it.sig} className="cr-al-line" data-cr-al-item={`${it.kind}|${it.cid}`}>
                                                <span className={`cr-dot cr-dot-${CR_AL_TONE[it.sev]}`} aria-hidden="true" />
                                                <span className="cr-al-line-text">
                                                    <span className="cr-strong">{crAlItemText(it, t, true)}</span>
                                                    {it.detail && <span className="cr-muted"> ({it.detail})</span>}
                                                    {it.rows && (
                                                        <span className="cr-al-msgs">
                                                            {it.rows.slice(0, 5).map(r => (
                                                                <span key={r.id} className="cr-al-msg" data-cr-al-msg={r.id}>
                                                                    {r.message || r.metric || ''}
                                                                    {r.acked_at ? ` (${t('crAlAcked').replace('{who}', r.acked_by || '-')})` : ''}
                                                                    {r.muted_until ? ` (${t('crAlMuted')})` : ''}
                                                                </span>
                                                            ))}
                                                            {it.rows.length > 5 && <span className="cr-muted">{t('crAlMoreRows').replace('{n}', it.rows.length - 5)}</span>}
                                                        </span>
                                                    )}
                                                    <span className="cr-al-basis">{crAlBasis(it, t)}</span>
                                                </span>
                                                {open1 && <button type="button" className="cr-btn cr-btn-xs" onClick={open1} data-cr-al-open="">{t('crAlOpen')}</button>}
                                                {hist && <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={hist} data-cr-al-history="">{t('crAlHistory')}</button>}
                                            </div>
                                        );
                                    })}
                                </div>
                            ))}
                            <p className="cr-al-foot">{t('crAlFoot')}</p>
                        </div>
                    )}
                </div>
            );
        }
