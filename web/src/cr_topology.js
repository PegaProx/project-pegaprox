        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned (Preview): the topology - LW Oct 2026
        // TopologyView hands over its frozen snapshot and the answers it already reads
        // (networks, datastores, affinity rules); this draws them for the preview. A cluster
        // box holds its nodes, a node card the guests placed on it, a backup server sits in
        // the box of a cluster it is linked to. Storage, bridge and affinity lines are drawn
        // only where an answer names them. A node with many guests folds them into one row,
        // so 200 nodes with 10k guests stay a few thousand SVG elements.
        // ═══════════════════════════════════════════════════════════

        const CR_TOPO = {
            nodeW: 204, headH: 58, rowH: 18, gap: 12, boxPad: 12, boxHead: 34, boxGap: 28,
            chipW: 156, chipH: 32, foldW: 320, foldH: 62, minBoxW: 340,
            guestCap: 16,     // a node with more guests than this starts folded
            shownMax: 2000,   // and with more guest rows than this in view, every node does
            kMin: 0.03, kMax: 4, kFit: 1.25, far: 0.55,
        };

        // the cr tokens as plain colours: an export draws the SVG without the stylesheet
        const CR_TOPO_COLORS = {
            dark: { canvas: '#17242c', box: '#1c2c35', boxLine: '#344954', card: '#20333e', cardLine: '#3b525e',
                    row: '#1a2b34', text: '#e3edf2', soft: '#9aadb8', muted: '#93a7b2', accent: '#55b6d0',
                    ok: '#64b94a', warn: '#e5b83d', bad: '#f38181', track: '#132028', qemu: '#55b6d0', lxc: '#a383c9' },
            light: { canvas: '#eef2f5', box: '#f7f9fb', boxLine: '#c9d4db', card: '#ffffff', cardLine: '#c9d4db',
                     row: '#f2f5f8', text: '#17242c', soft: '#46596a', muted: '#5a6b78', accent: '#0b6f99',
                     ok: '#2f7d1c', warn: '#8a6100', bad: '#b73535', track: '#e3e9ee', qemu: '#0b6f99', lxc: '#7d4fa8' },
        };
        const CR_TOPO_FONT = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

        const crCut = (s, n) => {
            const v = String(s == null ? '' : s);
            return v.length > n ? v.slice(0, n - 1) + '…' : v;
        };
        const crGuestLabel = (g) => g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}`;
        const crNum = (n) => (Number.isFinite(n) ? n.toLocaleString(crLocale()) : '-');

        // what the snapshot says about a node; a node the global view only knows from the
        // guest list (_derived) has a real name but no reported state
        function crTopoNode(n) {
            const derived = !!n._derived;
            const online = n.status !== 'offline' && (n.status === 'online' || n.cpu !== undefined || n.cpu_percent !== undefined);
            const live = online && !derived;
            const memTotal = n.mem_total || n.maxmem || null;
            const memUsed = n.mem_used != null ? n.mem_used : (n.mem != null ? n.mem : null);
            const cpu = !live ? null : n.cpu_percent != null ? n.cpu_percent : (n.cpu != null ? n.cpu * 100 : null);
            const ram = !live ? null : n.mem_percent != null ? n.mem_percent
                : (memTotal && memUsed != null ? memUsed / memTotal * 100 : null);
            return {
                name: n.name,
                state: derived ? 'unknown' : !online ? 'offline' : n.maintenance_mode ? 'maintenance' : 'online',
                cpu, ram, disk: live && n.disk_percent != null ? n.disk_percent : null,
                memUsed: live ? memUsed : null, memTotal: live ? memTotal : null,
                uptime: live ? n.uptime || null : null,
                cpus: (n.cpuinfo && n.cpuinfo.cpus) || n.maxcpu || null,
                version: n.pveversion || null,
                guests: [],
            };
        }

        function crTopoModel(src) {
            return src.map(cl => {
                const raw = cl.nodes || [];
                // the global view invents node-1..n while nothing is cached: tell, draw none
                const unknown = raw.length > 0 && raw.every(n => n._placeholder) ? raw.length : 0;
                const seen = {};
                const nodes = [];
                if (!unknown) {
                    raw.forEach(n => {
                        if (!n || !n.name || seen[n.name] || n._placeholder) return;
                        seen[n.name] = crTopoNode(n);
                        nodes.push(seen[n.name]);
                    });
                }
                nodes.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
                let guests = 0, running = 0, unplaced = 0, qemu = 0;
                (cl.resources || []).forEach(g => {
                    if (!g || (g.type !== 'qemu' && g.type !== 'lxc')) return;
                    guests++;
                    if (g.type === 'qemu') qemu++;
                    if (g.status === 'running') running++;
                    if (seen[g.node]) seen[g.node].guests.push(g);
                    else unplaced++;
                });
                nodes.forEach(n => n.guests.sort((a, b) =>
                    (b.status === 'running') - (a.status === 'running') || Number(a.vmid) - Number(b.vmid)));
                return {
                    id: cl.id, name: cl.name || cl.id, nodes, guests, running, unplaced, unknown, qemu, lxc: guests - qemu,
                    unknownOnline: unknown ? raw.filter(n => n.status === 'online').length : 0,
                    online: nodes.filter(n => n.state === 'online' || n.state === 'maintenance').length,
                    pbs: cl.pbs || cl.pbsServers || [],
                };
            });
        }

        // Cards go into the shortest column, so a node that shows its guests only makes its
        // own column longer. Returns the height the columns reach
        function crTopoStack(heights, cols, place) {
            const T = CR_TOPO;
            const ys = new Array(cols).fill(0);
            heights.forEach((h, i) => {
                let j = 0;
                for (let c = 1; c < cols; c++) if (ys[c] < ys[j] - 0.5) j = c;
                if (place) place(i, j, ys[j]);
                ys[j] += h + T.gap;
            });
            return Math.max(0, ...ys) - T.gap;
        }

        // The column count that lets the cards fit a canvas of this shape largest. It is
        // worked out from the default heights, so opening one node never re-flows the rest
        function crTopoCols(heights, aspect) {
            const T = CR_TOPO;
            const n = heights.length;
            if (n < 2) return n;
            let best = 1, bestK = 0;
            for (let cols = 1; cols <= Math.min(n, 64); cols++) {
                const k = Math.min(aspect / (cols * (T.nodeW + T.gap)), 1 / (crTopoStack(heights, cols) + T.gap));
                if (k > bestK) { bestK = k; best = cols; }
            }
            return best;
        }

        // chips in rows inside a box; returns the height they take
        function crTopoChips(list, kind, label, x0, y0, innerW, push) {
            if (!list.length) return 0;
            const T = CR_TOPO;
            const per = Math.max(1, Math.floor((innerW + T.gap) / (T.chipW + T.gap)));
            push({ kind: 'label', key: `l:${kind}:${y0}`, x: x0, y: y0, text: label });
            list.forEach((s, i) => {
                push({ kind, key: s.key, x: x0 + (i % per) * (T.chipW + T.gap),
                       y: y0 + 18 + Math.floor(i / per) * (T.chipH + 8), w: T.chipW, h: T.chipH, data: s });
            });
            return 18 + Math.ceil(list.length / per) * (T.chipH + 8) + 4;
        }

        // Positions for everything, in diagram units. Node cards sit in a grid whose shape
        // follows the canvas, boxes are packed in rows the same way
        function crTopoLayout(model, o) {
            const T = CR_TOPO;
            let wouldShow = 0;
            model.forEach(cl => cl.nodes.forEach(n => {
                const k = n.guests.filter(g => o.show[g.type]).length;
                if (k <= T.guestCap) wouldShow += k;
            }));
            const auto = wouldShow <= T.shownMax;
            const boxes = model.map(cl => {
                const box = { cl, key: `c:${cl.id}`, parts: [], folded: !!(o.multi && o.folded[cl.id]) };
                if (box.folded) {
                    box.w = T.foldW;
                    box.h = box.h0 = T.foldH;
                    return box;
                }
                const tall = (k, open) => T.headH + (k ? T.rowH * (open ? k + 1 : 1) + 6 : 0);
                const cards = cl.nodes.map(n => {
                    const gs = n.guests.filter(g => o.show[g.type]);
                    const key = `n:${cl.id}:${n.name}`;
                    const pick = o.open[key];
                    const usual = gs.length > 0 && auto && gs.length <= T.guestCap;
                    const open = gs.length > 0 && (pick != null ? !!pick : usual);
                    return { key, n, gs, open, w: T.nodeW, h: tall(gs.length, open), h0: tall(gs.length, usual) };
                });
                const n = cards.length;
                const cols = crTopoCols(cards.map(x => x.h0), o.multi ? Math.min(o.aspect, 1.4) : o.aspect);
                const gridW = cols ? cols * T.nodeW + (cols - 1) * T.gap : 0;
                const innerW = Math.max(gridW, T.minBoxW - 2 * T.boxPad);
                let y = T.boxHead + 4;
                const push = (p) => box.parts.push(p);
                if (cl.unknown) {
                    push({ kind: 'note', key: `u:${cl.id}`, x: T.boxPad, y: y + 14, tone: 'muted', what: 'unknown' });
                    y += 30;
                } else if (!n) {
                    push({ kind: 'note', key: `e:${cl.id}`, x: T.boxPad, y: y + 14, tone: 'muted', what: 'empty' });
                    y += 30;
                }
                let y0 = y;
                if (n) {
                    const top = y;
                    y0 += crTopoStack(cards.map(x => x.h0), cols) + T.gap;
                    y += crTopoStack(cards.map(x => x.h), cols, (i, col, at) =>
                        push({ kind: 'node', ...cards[i], x: T.boxPad + col * (T.nodeW + T.gap), y: top + at })) + T.gap;
                }
                const below = y;
                if (cl.unplaced) {
                    push({ kind: 'note', key: `x:${cl.id}`, x: T.boxPad, y: y + 10, tone: 'warn', what: 'unplaced' });
                    y += 26;
                }
                if (o.show.pbs) {
                    y += crTopoChips(cl.pbs.map(p => ({ key: `p:${cl.id}:${p.id}`, p })), 'pbs', 'pbs', T.boxPad, y, innerW, push);
                }
                if (!o.multi) {
                    y += crTopoChips(o.storages.map(s => ({ key: `s:${s.name}`, s })), 'storage', 'storage', T.boxPad, y, innerW, push);
                    y += crTopoChips(o.networks.map(b => ({ key: `b:${b.name}`, b })), 'bridge', 'bridge', T.boxPad, y, innerW, push);
                }
                box.w = innerW + 2 * T.boxPad;
                box.h = Math.max(y + T.boxPad - T.gap, T.boxHead + 40);
                // the height with every node as it starts: the packing goes by it, so opening a
                // node pushes the boxes under it down but never reshuffles them
                box.h0 = Math.max(y0 + (y - below) + T.boxPad - T.gap, T.boxHead + 40);
                return box;
            });
            // pack the boxes in rows, about as wide as the canvas shape asks for
            const shelf = (limit, put) => {
                let x = 0, y = 0, rowH = 0, W = 0;
                boxes.forEach(b => {
                    if (x > 0 && x + b.w > limit) { x = 0; y += rowH + T.boxGap; rowH = 0; }
                    if (put) { b.x = x; b.y = y; }
                    x += b.w + T.boxGap;
                    rowH = Math.max(rowH, put ? b.h : b.h0);
                    W = Math.max(W, x - T.boxGap);
                });
                return { W, H: y + rowH };
            };
            let best = null;
            let run = 0;
            boxes.forEach(b => {
                run += b.w + (run ? T.boxGap : 0);
                const r = shelf(run);
                const k = Math.min(o.aspect / r.W, 1 / r.H);
                if (!best || k > best.k) best = { k, limit: run };
            });
            const { W, H } = shelf(best ? best.limit : 0, true);
            const items = new Map();
            boxes.forEach(b => {
                items.set(b.key, { kind: 'cluster', key: b.key, cl: b.cl, x: b.x, y: b.y, w: b.w, h: b.folded ? b.h : T.boxHead, box: b });
                b.parts.forEach(p => {
                    p.ax = b.x + p.x;
                    p.ay = b.y + p.y;
                    if (p.kind === 'node') {
                        items.set(p.key, { kind: 'node', key: p.key, cl: b.cl, n: p.n, card: p, x: p.ax, y: p.ay, w: p.w, h: p.h });
                        if (p.gs.length) {
                            items.set(`f:${p.key.slice(2)}`, { kind: 'fold', key: `f:${p.key.slice(2)}`, node: p.key, cl: b.cl, n: p.n,
                                                               x: p.ax, y: p.ay + T.headH, w: p.w, h: T.rowH });
                        }
                        if (p.open) {
                            p.gs.forEach((g, i) => {
                                const key = `g:${b.cl.id}:${g.vmid}`;
                                items.set(key, { kind: 'guest', key, cl: b.cl, n: p.n, g, node: p.key,
                                                 x: p.ax, y: p.ay + T.headH + T.rowH * (i + 1), w: p.w, h: T.rowH });
                            });
                        }
                    } else if (p.kind === 'pbs' || p.kind === 'storage' || p.kind === 'bridge') {
                        items.set(p.key, { kind: p.kind, key: p.key, cl: b.cl, data: p.data, x: p.ax, y: p.ay, w: p.w, h: p.h });
                    }
                });
            });
            return { boxes, items, W, H };
        }

        // what a search finds: clusters, nodes and guests by name, guests by VMID too
        function crTopoFind(model, q) {
            const keys = new Set();
            const inNode = {};
            const inCluster = {};
            if (!q) return { q, keys, inNode, inCluster, count: 0 };
            model.forEach(cl => {
                let hits = 0;
                if (String(cl.name).toLowerCase().includes(q)) { keys.add(`c:${cl.id}`); hits++; }
                cl.nodes.forEach(n => {
                    const nk = `n:${cl.id}:${n.name}`;
                    let inside = 0;
                    if (n.name.toLowerCase().includes(q)) { keys.add(nk); hits++; }
                    n.guests.forEach(g => {
                        if (String(g.vmid).includes(q) || (g.name || '').toLowerCase().includes(q)) {
                            keys.add(`g:${cl.id}:${g.vmid}`);
                            inside++;
                        }
                    });
                    if (inside) { inNode[nk] = inside; hits += inside; }
                });
                if (hits) inCluster[cl.id] = hits;
            });
            return { q, keys, inNode, inCluster, count: keys.size };
        }

        // the small glyphs, drawn at (0,0)
        function CrTopoGlyph({ kind, color }) {
            if (kind === 'lxc') {
                return <path d="M0 -4.5 L4.5 -2.2 L4.5 2.6 L0 4.8 L-4.5 2.6 L-4.5 -2.2 Z" fill="none" stroke={color} strokeWidth={1.2} />;
            }
            if (kind === 'qemu') {
                return <g fill="none" stroke={color} strokeWidth={1.2}><rect x={-5} y={-4} width={10} height={7} rx={1} /><path d="M-2 5 H2" /></g>;
            }
            if (kind === 'cluster') {
                return (
                    <g fill="none" stroke={color} strokeWidth={1.3}>
                        <rect x={-7} y={-7} width={14} height={4} rx={1} />
                        <rect x={-7} y={-2} width={14} height={4} rx={1} />
                        <rect x={-7} y={3} width={14} height={4} rx={1} />
                    </g>
                );
            }
            if (kind === 'pbs' || kind === 'storage') {
                return (
                    <g fill="none" stroke={color} strokeWidth={1.2}>
                        <ellipse cx={0} cy={-4} rx={6} ry={2.2} />
                        <path d="M-6 -4 V4 A6 2.2 0 0 0 6 4 V-4" />
                    </g>
                );
            }
            return (
                <g fill="none" stroke={color} strokeWidth={1.2}>
                    <circle cx={0} cy={0} r={5} /><path d="M-5 0 H5 M0 -5 V5" />
                </g>
            );
        }

        // CPU and RAM by CR_WARN/CR_CRIT, a storage (store) by the storage pair of the preview
        function crTopoBar(x, y, w, pct, c, store) {
            const v = Math.max(0, Math.min(100, pct));
            const tn = store ? crStoreTone(v) : crTone(v);
            const tone = tn === 'error' ? c.bad : tn === 'warning' ? c.warn : c.ok;
            return (
                <>
                    <rect x={x} y={y} width={w} height={4} rx={2} fill={c.track} />
                    <rect x={x} y={y} width={Math.max(1, w * v / 100)} height={4} rx={2} fill={tone} />
                </>
            );
        }

        // Everything the camera moves. Memoised: panning and zooming only touch the
        // transform of the group around it, never this
        const CrTopoScene = React.memo(function CrTopoScene({ lay, c, hit, multi, t }) {
            const T = CR_TOPO;
            const q = hit.q;
            const stateColor = (s) => (s === 'online' ? c.ok : s === 'offline' ? c.bad : s === 'maintenance' ? c.warn : c.muted);
            const stateText = (s) => (s === 'offline' ? t('offline') : s === 'maintenance' ? t('maintenance') : s === 'unknown' ? t('crTopoNotReported') : t('online'));
            const dim = (lit) => (q && !lit ? 0.28 : 1);
            const node = (p, cl, clLit) => {
                const n = p.n;
                const lit = clLit || hit.keys.has(p.key) || !!hit.inNode[p.key];
                const own = hit.keys.has(p.key);
                const running = p.gs.filter(g => g.status === 'running').length;
                const label = `${n.name}, ${stateText(n.state)}${n.cpu != null ? `, CPU ${n.cpu.toFixed(0)}%` : ''}${n.ram != null ? `, RAM ${n.ram.toFixed(0)}%` : ''}, ${n.guests.length} ${t('guests').toLowerCase()}`;
                const fold = p.key.slice(2);
                return (
                    <g key={p.key} transform={`translate(${p.ax},${p.ay})`} opacity={dim(lit)}>
                        <g data-cr-topo="node" data-k={p.key} data-state={n.state} tabIndex={0} role="button" aria-label={label}>
                            <rect className="cr-topo-frame" width={p.w} height={p.h} rx={3} fill={c.card}
                                stroke={own ? c.accent : c.cardLine} strokeWidth={own ? 2 : 1} />
                            <rect width={3} height={p.h} fill={stateColor(n.state)} />
                            <circle className="cr-topo-dot" cx={14} cy={15} r={3.5} fill={stateColor(n.state)} />
                            <text className="cr-topo-detail" x={24} y={19} fontSize={12} fontWeight={600} fill={c.text}>{crCut(n.name, 21)}</text>
                            <text className="cr-topo-farname" x={30} y={38} fontSize={24} fontWeight={600} fill={c.text}>{crCut(n.name, 11)}</text>
                            {n.state !== 'online' && (
                                <text className="cr-topo-detail" x={p.w - 8} y={19} textAnchor="end" fontSize={10} fontWeight={600}
                                    fill={n.state === 'offline' ? c.bad : n.state === 'maintenance' ? c.warn : c.muted}>
                                    {n.state === 'unknown' ? '?' : crCut(stateText(n.state).toUpperCase(), 12)}
                                </text>
                            )}
                            {n.cpu != null || n.ram != null ? (
                                <g className="cr-topo-detail">
                                    <text x={12} y={37} fontSize={10} fill={c.muted}>CPU</text>
                                    {n.cpu != null && crTopoBar(42, 31, p.w - 92, n.cpu, c)}
                                    <text x={p.w - 10} y={37} textAnchor="end" fontSize={10} fill={c.soft}>{n.cpu != null ? `${n.cpu.toFixed(0)}%` : '-'}</text>
                                    <text x={12} y={51} fontSize={10} fill={c.muted}>RAM</text>
                                    {n.ram != null && crTopoBar(42, 45, p.w - 92, n.ram, c)}
                                    <text x={p.w - 10} y={51} textAnchor="end" fontSize={10} fill={c.soft}>{n.ram != null ? `${n.ram.toFixed(0)}%` : '-'}</text>
                                </g>
                            ) : (
                                <text className="cr-topo-detail" x={12} y={42} fontSize={10.5} fill={n.state === 'offline' ? c.bad : c.muted}>
                                    {n.state === 'unknown' ? t('crTopoNotReported') : stateText(n.state)}
                                </text>
                            )}
                        </g>
                        {p.gs.length > 0 && (
                            <g data-cr-topo="fold" data-k={`f:${fold}`} tabIndex={0} role="button" aria-expanded={p.open}
                                aria-label={`${p.open ? t('crTopoHideGuests') : t('crTopoShowGuests')}: ${n.name}`}>
                                <rect className="cr-topo-frame" x={4} y={T.headH} width={p.w - 8} height={T.rowH} rx={2} fill={c.row} />
                                <path d={p.open ? `M12 ${T.headH + 7} l4 4 l4 -4` : `M13 ${T.headH + 5} l4 4 l-4 4`} fill="none" stroke={c.soft} strokeWidth={1.3} />
                                <text className="cr-topo-detail" x={26} y={T.headH + 13} fontSize={10.5} fill={c.soft}>
                                    {crFill(p.gs.length === 1 ? t('crTopoGuestSummary') : t('crTopoGuestsSummary'), { n: crNum(p.gs.length), running: crNum(running) })}
                                </text>
                                {hit.inNode[p.key] > 0 && (
                                    <text x={p.w - 10} y={T.headH + 13} textAnchor="end" fontSize={10} fontWeight={600} fill={c.accent}>
                                        {crFill(t('crTopoMatches'), { n: hit.inNode[p.key] })}
                                    </text>
                                )}
                            </g>
                        )}
                        {p.open && p.gs.map((g, i) => {
                            const key = `g:${cl.id}:${g.vmid}`;
                            const gl = !q || lit && (own || clLit || hit.keys.has(key));
                            const y = T.headH + T.rowH * (i + 1);
                            const on = g.status === 'running';
                            const name = crGuestLabel(g);
                            return (
                                <g key={key} data-cr-topo="guest" data-k={key} transform={`translate(0,${y})`} tabIndex={0} role="button"
                                    aria-label={`${name}, ${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}, ${on ? t('running') : t(g.status) || g.status}`}
                                    opacity={q && !gl ? 0.35 : 1}>
                                    <rect className="cr-topo-frame" x={4} width={p.w - 8} height={T.rowH} rx={2}
                                        fill={hit.keys.has(key) ? c.row : 'transparent'} stroke={hit.keys.has(key) ? c.accent : 'none'} />
                                    <circle cx={12} cy={9} r={2.6} fill={on ? c.ok : g.status === 'paused' ? c.warn : c.muted} />
                                    <g transform="translate(24,9)"><CrTopoGlyph kind={g.type} color={g.type === 'lxc' ? c.lxc : c.qemu} /></g>
                                    <text className="cr-topo-detail" x={34} y={13} fontSize={11} fill={on ? c.text : c.soft}>{crCut(name, 21)}</text>
                                    <text className="cr-topo-detail" x={p.w - 10} y={13} textAnchor="end" fontSize={10} fill={c.muted}
                                        fontFamily="var(--font-mono), monospace">{g.vmid}</text>
                                </g>
                            );
                        })}
                    </g>
                );
            };
            const chip = (p, cl) => {
                const kind = p.kind;
                const d = p.data;
                let title = '', sub = '', pct = null, label = '';
                if (kind === 'pbs') {
                    title = d.p.name || d.p.host;
                    sub = t('backupServers');
                    label = `${title}, ${sub}, ${d.p.status || ''}`;
                } else if (kind === 'storage') {
                    title = d.s.label;
                    sub = `${d.s.type} · ${d.s.kind === 'shared' ? t('sharedStorage') : t('localStorage')}`;
                    pct = d.s.used_fraction != null ? d.s.used_fraction * 100 : null;
                    label = `${title}, ${sub}${pct != null ? `, ${pct.toFixed(0)}%` : ''}`;
                } else {
                    title = d.b.name;
                    sub = `${d.b.type || 'bridge'}${d.b.cidr ? ' · ' + d.b.cidr : ''}`;
                    label = `${title}, ${sub}`;
                }
                return (
                    <g key={p.key} data-cr-topo={kind} data-k={p.key} transform={`translate(${p.ax},${p.ay})`} tabIndex={0} role="img" aria-label={label}>
                        <rect className="cr-topo-frame" width={p.w} height={p.h} rx={3} fill={c.row}
                            stroke={kind === 'bridge' ? c.lxc : c.boxLine} strokeDasharray={kind === 'pbs' ? '4 3' : undefined} />
                        <g transform="translate(14,16)">
                            <CrTopoGlyph kind={kind} color={kind === 'pbs' ? c.ok : kind === 'bridge' ? c.lxc : c.accent} />
                        </g>
                        <text x={28} y={14} fontSize={11.5} fontWeight={600} fill={c.text}>{crCut(title, 17)}</text>
                        <text className="cr-topo-detail" x={28} y={26} fontSize={9.5} fill={c.muted}>{crCut(sub, 22)}</text>
                        {pct != null && crTopoBar(p.w - 40, 24, 32, pct, c, kind === 'storage')}
                    </g>
                );
            };
            const label = (p) => {
                const text = p.text === 'pbs' ? t('crTopoLinkedBackup') : p.text === 'storage' ? t('storage') : t('network');
                return <text key={p.key} x={p.ax} y={p.ay + 11} fontSize={10} fontWeight={600} letterSpacing={0.8} fill={c.muted}>{text.toUpperCase()}</text>;
            };
            const note = (p, cl) => {
                const text = p.what === 'unknown'
                    ? crFill(t('crTopoNotLoaded'), { n: cl.unknown, online: cl.unknownOnline })
                    : p.what === 'unplaced' ? crFill(t('crTopoUnplaced'), { n: cl.unplaced }) : t('crTopoNoNodes');
                return <text key={p.key} x={p.ax} y={p.ay} fontSize={11.5} fill={p.tone === 'warn' ? c.warn : c.muted} data-cr-topo-note={p.what}>{text}</text>;
            };
            return (
                <g>
                    {lay.boxes.map(b => {
                        const cl = b.cl;
                        const clLit = hit.keys.has(b.key);
                        const inside = hit.inCluster[cl.id] || 0;
                        const counts = cl.unknown
                            ? crFill(t('crTopoScopeOne'), { nodes: crNum(cl.unknown), guests: crNum(cl.guests) })
                            : crFill(t('crTopoScopeOne'), { nodes: `${crNum(cl.online)}/${crNum(cl.nodes.length)}`, guests: crNum(cl.guests) });
                        const nameMax = Math.max(12, Math.floor((b.w - 150) / 7.4));
                        return (
                            <g key={b.key} data-cr-topo-box={cl.id} data-folded={b.folded ? '1' : '0'} opacity={dim(clLit || inside > 0)}>
                                <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={4} fill={c.box} stroke={clLit ? c.accent : c.boxLine} strokeWidth={clLit ? 2 : 1} />
                                <g data-cr-topo="cluster" data-k={b.key} tabIndex={0} role={multi ? 'button' : 'img'}
                                    aria-label={`${cl.name}, ${counts}`}>
                                    <rect className="cr-topo-frame" x={b.x} y={b.y} width={b.w - (multi ? 34 : 0)} height={T.boxHead} rx={4} fill="transparent" />
                                    <g transform={`translate(${b.x + 20},${b.y + 17})`}><CrTopoGlyph kind="cluster" color={c.accent} /></g>
                                    <text className="cr-topo-detail" x={b.x + 36} y={b.y + 22} fontSize={13} fontWeight={600} fill={c.text}>{crCut(cl.name, nameMax)}</text>
                                    <text className="cr-topo-farname" x={b.x + 36} y={b.y + 29} fontSize={28} fontWeight={600} fill={c.text}>
                                        {crCut(cl.name, Math.max(6, Math.floor((b.w - 80) / 17)))}
                                    </text>
                                    {!b.folded && (
                                        <text className="cr-topo-detail" x={b.x + b.w - (multi ? 40 : 12)} y={b.y + 22} textAnchor="end" fontSize={10.5} fill={c.muted}>{counts}</text>
                                    )}
                                </g>
                                {multi && (
                                    <g data-cr-topo="cluster-fold" data-k={`cf:${cl.id}`} tabIndex={0} role="button" aria-expanded={!b.folded}
                                        aria-label={crFill(b.folded ? t('crExpandNamed') : t('crCollapseNamed'), { name: cl.name })}>
                                        <rect className="cr-topo-frame" x={b.x + b.w - 32} y={b.y + 5} width={24} height={24} rx={3} fill="transparent" />
                                        <path d={b.folded ? `M${b.x + b.w - 23} ${b.y + 12} l5 5 l-5 5` : `M${b.x + b.w - 25} ${b.y + 14} l5 5 l5 -5`}
                                            fill="none" stroke={c.soft} strokeWidth={1.5} />
                                    </g>
                                )}
                                {b.folded && (
                                    <g>
                                        <text x={b.x + 14} y={b.y + 50} fontSize={11} fill={c.soft}>
                                            {counts} · {crFill(t('crTopoRunningN'), { n: crNum(cl.running) })}
                                        </text>
                                        {inside > 0 && (
                                            <text x={b.x + b.w - 12} y={b.y + 50} textAnchor="end" fontSize={10.5} fontWeight={600} fill={c.accent}>
                                                {crFill(t('crTopoMatches'), { n: inside })}
                                            </text>
                                        )}
                                    </g>
                                )}
                                {b.parts.map(p => (p.kind === 'node' ? node(p, cl, clLit) : p.kind === 'label' ? label(p)
                                    : p.kind === 'note' ? note(p, cl) : chip(p, cl)))}
                            </g>
                        );
                    })}
                </g>
            );
        });

        // The lines for the item under the pointer or in focus, plus the affinity rules when
        // they are switched on. Only what an answer names: active_on and the bridge's nodes,
        // the storage and bridge lists of a guest, the guests of a rule
        const CrTopoLinks = React.memo(function CrTopoLinks({ lay, focus, c, vmStorages, vmBridges, affinity }) {
            const items = lay.items;
            const pairs = [];
            const it = focus ? items.get(focus) : null;
            const guestOf = (cid, vmid) => items.get(`g:${cid}:${vmid}`);
            const nodeOf = (cid, name) => items.get(`n:${cid}:${name}`);
            if (it && it.cl) {
                const cid = it.cl.id;
                const all = Array.from(items.values());
                const storagesOf = (vmid, node) => (vmStorages[String(vmid)] || []).map(name =>
                    all.find(x => x.kind === 'storage' && x.data.s.label === name && (x.data.s.kind === 'shared' || x.data.s.active_on[0] === node))).filter(Boolean);
                const bridgesOf = (vmid) => (vmBridges[String(vmid)] || []).map(name => items.get(`b:${name}`)).filter(Boolean);
                if (it.kind === 'node') {
                    all.forEach(x => {
                        if (x.kind === 'storage' && x.data.s.active_on.includes(it.n.name)) pairs.push([it, x, 'storage']);
                        if (x.kind === 'bridge' && (x.data.b.nodes || []).includes(it.n.name)) pairs.push([it, x, 'bridge']);
                    });
                } else if (it.kind === 'guest') {
                    storagesOf(it.g.vmid, it.g.node).forEach(x => pairs.push([it, x, 'storage']));
                    bridgesOf(it.g.vmid).forEach(x => pairs.push([it, x, 'bridge']));
                } else if (it.kind === 'storage') {
                    it.data.s.active_on.forEach(name => { const n = nodeOf(cid, name); if (n) pairs.push([n, it, 'storage']); });
                    Object.keys(vmStorages).forEach(vmid => {
                        const g = guestOf(cid, vmid);
                        if (g && storagesOf(vmid, g.g.node).includes(it)) pairs.push([g, it, 'storage']);
                    });
                } else if (it.kind === 'bridge') {
                    (it.data.b.nodes || []).forEach(name => { const n = nodeOf(cid, name); if (n) pairs.push([n, it, 'bridge']); });
                    (it.data.b.vms || []).forEach(v => { const g = v && guestOf(cid, v.vmid); if (g) pairs.push([g, it, 'bridge']); });
                }
            }
            const aff = [];
            (affinity || []).forEach(rule => {
                const ids = (rule.vms || rule.vm_ids || []).map(String);
                const cid = lay.boxes[0] && lay.boxes[0].cl.id;
                for (let i = 0; i < ids.length; i++) {
                    for (let j = i + 1; j < ids.length; j++) {
                        const a = guestOf(cid, ids[i]);
                        const b = guestOf(cid, ids[j]);
                        if (a && b) aff.push([a, b, rule.type === 'separate', `${rule.id}:${ids[i]}:${ids[j]}`]);
                    }
                }
            });
            if (!pairs.length && !aff.length) return null;
            // a line leaves its node or guest to the left, drops through the gap next to that
            // column and runs along the gap above the row of its storage or bridge, so it never
            // crosses the text of a card
            const route = (a, b, kind) => {
                const ya = a.kind === 'node' ? a.y + 15 : a.y + a.h / 2;
                const gx = a.x - (kind === 'bridge' ? 8 : 4);
                return `M${a.x} ${ya} H${gx} V${b.y - 4} H${b.x + (kind === 'bridge' ? 18 : 12)} V${b.y}`;
            };
            return (
                <g pointerEvents="none" data-cr-topo-links={pairs.length}>
                    {aff.map(([a, b, apart, k]) => {
                        const [x1, y1] = [a.x + a.w - 4, a.y + a.h / 2];
                        const [x2, y2] = [b.x + b.w - 4, b.y + b.h / 2];
                        // guests of one node: a bow in the gap right of the card; else straight
                        const d = a.x === b.x ? `M${x1} ${y1} C${x1 + 20} ${y1}, ${x2 + 20} ${y2}, ${x2} ${y2}` : `M${x1} ${y1} L${x2} ${y2}`;
                        return <path key={`a:${k}`} data-cr-topo-affinity={apart ? 'separate' : 'together'} d={d} fill="none"
                            stroke={apart ? c.bad : c.ok} strokeWidth={1.4} strokeDasharray={apart ? '5 4' : undefined} opacity={0.8} />;
                    })}
                    {pairs.map(([a, b, kind], i) => {
                        return (
                            <g key={i}>
                                <path d={route(a, b, kind)} fill="none"
                                    stroke={kind === 'bridge' ? c.lxc : c.accent} strokeWidth={1.5} strokeDasharray="4 3" opacity={0.9} />
                                <rect x={b.x - 1} y={b.y - 1} width={b.w + 2} height={b.h + 2} rx={3} fill="none"
                                    stroke={kind === 'bridge' ? c.lxc : c.accent} strokeWidth={1.5} />
                            </g>
                        );
                    })}
                </g>
            );
        });

        // the details of an item for the hover card: [label, value] pairs, empty ones dropped
        function crTopoTip(it, t, ctx) {
            if (!it) return null;
            const pct = (v) => (v != null && Number.isFinite(v) ? `${v.toFixed(0)}%` : null);
            const rows = (title, list) => ({ title, rows: list.filter(r => r && r[1] != null && r[1] !== '') });
            if (it.kind === 'cluster') {
                const cl = it.cl;
                return rows(cl.name, [
                    [t('nodes'), cl.unknown ? `${crNum(cl.unknown)} (${t('crTopoNotReported')})` : `${crNum(cl.online)} / ${crNum(cl.nodes.length)} ${t('online').toLowerCase()}`],
                    [t('guests'), `${crNum(cl.running)} / ${crNum(cl.guests)} ${t('running').toLowerCase()}`],
                    [t('backupServers'), cl.pbs.length || null],
                ]);
            }
            if (it.kind === 'node' || it.kind === 'fold') {
                const n = it.n;
                const st = n.state === 'unknown' ? t('crTopoNotReported') : n.state === 'offline' ? t('offline') : n.state === 'maintenance' ? t('maintenance') : t('online');
                return rows(n.name, [
                    [t('cluster'), ctx.multi ? it.cl.name : null],
                    [t('status'), st],
                    [t('cpu'), pct(n.cpu) && `${pct(n.cpu)}${n.cpus ? ` · ${n.cpus} ${t('cores').toLowerCase()}` : ''}`],
                    [t('ram'), pct(n.ram) && `${pct(n.ram)}${n.memTotal ? ` · ${crBytes(n.memUsed)} / ${crBytes(n.memTotal)}` : ''}`],
                    [t('disk'), pct(n.disk)],
                    [t('uptime'), n.uptime ? crUptime(n.uptime) : null],
                    [t('guests'), `${crNum(n.guests.filter(g => g.status === 'running').length)} / ${crNum(n.guests.length)} ${t('running').toLowerCase()}`],
                    [t('version'), n.version],
                ]);
            }
            if (it.kind === 'guest') {
                const g = it.g;
                const on = g.status === 'running';
                return rows(crGuestLabel(g), [
                    [t('type'), g.type === 'lxc' ? t('container') : 'VM'],
                    [t('vmid'), String(g.vmid)],
                    [t('node'), g.node],
                    [t('status'), g.status],
                    [t('cpu'), on && g.cpu != null ? `${(g.cpu * 100).toFixed(0)}%` : null],
                    [t('ram'), on && g.maxmem ? `${crBytes(g.mem || 0)} / ${crBytes(g.maxmem)}` : null],
                    [t('uptime'), on && g.uptime ? crUptime(g.uptime) : null],
                    [t('network'), (ctx.vmBridges[String(g.vmid)] || []).join(', ')],
                    [t('storage'), (ctx.vmStorages[String(g.vmid)] || []).join(', ')],
                ]);
            }
            if (it.kind === 'storage') {
                const s = it.data.s;
                return rows(s.label, [
                    [t('type'), `${s.type} · ${s.kind === 'shared' ? t('sharedStorage') : t('localStorage')}`],
                    [t('crTopoUsed'), s.used_fraction != null ? `${(s.used_fraction * 100).toFixed(0)}%${s.total ? ` · ${crBytes(s.used)} / ${crBytes(s.total)}` : ''}` : null],
                    [t('activeOn'), s.active_on.join(', ')],
                ]);
            }
            if (it.kind === 'bridge') {
                const b = it.data.b;
                return rows(b.name, [
                    [t('type'), b.type || 'bridge'],
                    ['CIDR', b.cidr],
                    [t('gateway'), b.gateway],
                    [t('bridgePorts'), b.bridge_ports],
                    [t('guests'), Array.isArray(b.vms) ? b.vms.length : null],
                ]);
            }
            if (it.kind === 'pbs') {
                const p = it.data.p;
                return rows(p.name || p.host, [
                    [t('type'), t('backupServers')],
                    [t('status'), p.status],
                    [t('host'), p.host],
                ]);
            }
            return null;
        }

        // draws the diagram as it is on screen into a PNG, JPG or the PDF template
        function crTopoExport(svg, lay, c, format, clusterName) {
            if (!svg) return;
            const m = 24;
            const W = Math.ceil(lay.W + 2 * m), H = Math.ceil(lay.H + 2 * m);
            const clone = svg.cloneNode(true);
            clone.setAttribute('viewBox', `${-m} ${-m} ${W} ${H}`);
            clone.setAttribute('width', W);
            clone.setAttribute('height', H);
            clone.removeAttribute('class');
            clone.removeAttribute('style');
            const cam = clone.querySelector('[data-cr-camera]');
            if (cam) cam.removeAttribute('transform');
            // only the stylesheet hides the big names of the zoomed-out view, and a picture has none
            clone.querySelectorAll('.cr-topo-farname').forEach(e => e.remove());
            const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            bg.setAttribute('x', -m); bg.setAttribute('y', -m);
            bg.setAttribute('width', W); bg.setAttribute('height', H);
            bg.setAttribute('fill', c.canvas);
            clone.insertBefore(bg, clone.firstChild);
            const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(clone)], { type: 'image/svg+xml;charset=utf-8' }));
            const img = new Image();
            const name = `topology-${clusterName || 'pegaprox'}`;
            img.onload = () => {
                const s = Math.max(0.25, Math.min(2, 8000 / Math.max(W, H)));
                const canvas = document.createElement('canvas');
                canvas.width = Math.round(W * s);
                canvas.height = Math.round(H * s);
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = c.canvas;
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                URL.revokeObjectURL(url);
                const save = (blob, ext) => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = `${name}.${ext}`;
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(() => { a.remove(); URL.revokeObjectURL(a.href); }, 150);
                };
                if (format === 'png') canvas.toBlob(b => b && save(b, 'png'), 'image/png');
                else if (format === 'jpg') canvas.toBlob(b => b && save(b, 'jpg'), 'image/jpeg', 0.92);
                else {
                    generatePegaProxPDF({
                        title: 'Cluster Topology', clusterName, filename: `${name}.pdf`,
                        orientation: canvas.width > canvas.height ? 'landscape' : 'portrait',
                        content: [{ type: 'image', dataUrl: canvas.toDataURL('image/jpeg', 0.92), width: canvas.width, height: canvas.height }],
                    });
                }
            };
            img.src = url;
        }

        function CrTopology({ multi, clusterId, clusterName, frozenNodes, frozenResources, frozenPbs, frozenMultiCluster,
                              revision, onRefresh, networkData, storageData, buildStorages, vmStorages, vmBridges,
                              showStorage, onToggleStorage, showNetwork, onToggleNetwork,
                              affinityRules, setAffinityRules, showAffinity, setShowAffinity,
                              onVmClick, onNodeClick, onClusterClick }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const T = CR_TOPO;
            const rootRef = useRef(null);
            const canvasRef = useRef(null);
            const svgRef = useRef(null);
            const camRef = useRef(null);
            const cam = useRef({ k: 1, x: 0, y: 0 });
            const fitK = useRef(1);
            const autoFit = useRef(true);
            const wantFit = useRef(true);
            const frame = useRef(0);
            const drag = useRef(null);
            const swallowClick = useRef(false);
            const [zoomPct, setZoomPct] = useState(100);
            const [aspect, setAspect] = useState(1.8);
            const aspectRef = useRef(1.8);
            const [grabbing, setGrabbing] = useState(false);
            const [full, setFull] = useState(false);
            const [query, setQuery] = useState('');
            const [q, setQ] = useState('');
            const [focus, setFocus] = useState(null);
            const [tip, setTip] = useState(null);
            const [open, setOpen] = useState({});
            const [exportOpen, setExportOpen] = useState(false);
            const [legend, setLegend] = useState(() => crRead('cr-topo-legend') === '1');
            const [show, setShow] = useState(() => ({ qemu: true, lxc: true, pbs: true, ...(crReadJson('cr-topo-show') || {}) }));
            const [folded, setFolded] = useState(() => crReadJson('cr-topo-folded') || {});
            const handlers = useRef({});
            handlers.current = { onVmClick, onNodeClick, onClusterClick };

            const light = typeof document !== 'undefined' && document.body.dataset.corpTheme === 'light';
            const c = light ? CR_TOPO_COLORS.light : CR_TOPO_COLORS.dark;

            useEffect(() => {
                const id = setTimeout(() => setQ(query.trim().toLowerCase()), 140);
                return () => clearTimeout(id);
            }, [query]);

            const model = useMemo(() => {
                if (multi) return crTopoModel(frozenMultiCluster || []);
                const pbs = (frozenPbs || []).filter(p => p.status !== 'disconnected' && (p.linked_clusters || []).includes(clusterId));
                return crTopoModel([{ id: clusterId || '', name: clusterName, nodes: frozenNodes, resources: frozenResources, pbs }]);
            }, [multi, frozenMultiCluster, frozenNodes, frozenResources, frozenPbs, clusterId, clusterName]);
            const storages = useMemo(() => (!multi && showStorage && storageData ? buildStorages(storageData) : []),
                // buildStorages is a fresh closure on every render of TopologyView and pure
                [multi, showStorage, storageData]);
            const networks = useMemo(() => (!multi && showNetwork && Array.isArray(networkData)
                ? networkData.filter(n => n && typeof n.name === 'string' && n.name.length) : []), [multi, showNetwork, networkData]);
            const lay = useMemo(() => crTopoLayout(model, { multi, folded, open, show, aspect, storages, networks }),
                [model, multi, folded, open, show, aspect, storages, networks]);
            const layRef = useRef(lay);
            layRef.current = lay;
            const hit = useMemo(() => crTopoFind(model, q), [model, q]);

            const totals = useMemo(() => model.reduce((s, cl) => ({
                nodes: s.nodes + (cl.unknown || cl.nodes.length), online: s.online + cl.online,
                guests: s.guests + cl.guests, qemu: s.qemu + cl.qemu, lxc: s.lxc + cl.lxc,
                pbs: s.pbs + cl.pbs.length,
            }), { nodes: 0, online: 0, guests: 0, qemu: 0, lxc: 0, pbs: 0 }), [model]);

            // --- camera ---
            const apply = useCallback(() => {
                if (frame.current) return;
                frame.current = requestAnimationFrame(() => {
                    frame.current = 0;
                    const { k, x, y } = cam.current;
                    if (camRef.current) camRef.current.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)}) scale(${k.toFixed(4)})`);
                    if (svgRef.current) svgRef.current.classList.toggle('cr-topo-far', k < T.far);
                    setZoomPct(Math.round(k * 100));
                });
            }, []);
            useEffect(() => () => { if (frame.current) cancelAnimationFrame(frame.current); }, []);
            const fitBox = useCallback((box) => {
                const el = canvasRef.current;
                if (!el || !box || !(box.w > 0) || !(box.h > 0)) return false;
                const vw = el.clientWidth, vh = el.clientHeight;
                if (!vw || !vh) return false;
                const m = 24;
                const k = crClamp(Math.min((vw - 2 * m) / box.w, (vh - 2 * m) / box.h), 0.005, T.kFit);
                cam.current = { k, x: (vw - box.w * k) / 2 - box.x * k, y: (vh - box.h * k) / 2 - box.y * k };
                apply();
                return k;
            }, [apply]);
            const fitAll = useCallback(() => {
                const l = layRef.current;
                const k = fitBox({ x: 0, y: 0, w: l.W, h: l.H });
                if (k) { fitK.current = k; autoFit.current = true; }
                return k;
            }, [fitBox]);
            const zoomAt = useCallback((f, cx, cy) => {
                const c0 = cam.current;
                const k = crClamp(c0.k * f, Math.min(T.kMin, fitK.current * 0.5), T.kMax);
                const r = k / c0.k;
                cam.current = { k, x: cx - (cx - c0.x) * r, y: cy - (cy - c0.y) * r };
                autoFit.current = false;
                apply();
            }, [apply]);
            const zoomCenter = (f) => {
                const el = canvasRef.current;
                if (el) zoomAt(f, el.clientWidth / 2, el.clientHeight / 2);
            };
            const actualSize = () => {
                const el = canvasRef.current;
                if (el) zoomAt(1 / cam.current.k, el.clientWidth / 2, el.clientHeight / 2);
            };
            const pan = (dx, dy) => {
                const c0 = cam.current;
                cam.current = { ...c0, x: c0.x + dx, y: c0.y + dy };
                autoFit.current = false;
                apply();
            };

            // the first real layout, a refresh and the fold-all buttons fit the view again
            useEffect(() => { wantFit.current = true; setFocus(null); setTip(null); }, [revision]);
            // new data refits too while nobody has moved the camera; opening a node does not
            const fitModel = useRef(null);
            useEffect(() => {
                if (!(lay.W > 0)) return;
                const fresh = fitModel.current !== model;
                if ((wantFit.current || (fresh && autoFit.current)) && fitAll()) wantFit.current = false;
                fitModel.current = model;
            }, [lay, revision, fitAll]);
            useEffect(() => {
                const el = canvasRef.current;
                if (!el || typeof ResizeObserver === 'undefined') return;
                const ro = new ResizeObserver(() => {
                    const w = el.clientWidth, h = el.clientHeight;
                    if (!w || !h) return;
                    // a new shape lays the boxes out again (the layout effect fits then),
                    // the same shape at another size only needs the fit
                    const a = Math.round(crClamp(w / h, 0.8, 3) * 10) / 10;
                    if (a !== aspectRef.current) {
                        aspectRef.current = a;
                        if (autoFit.current) wantFit.current = true;
                        setAspect(a);
                    } else if ((autoFit.current || wantFit.current) && fitAll()) {
                        wantFit.current = false;
                    }
                });
                ro.observe(el);
                return () => ro.disconnect();
            }, [fitAll]);
            // the wheel zooms at the pointer; it has to be non-passive to keep the page still
            useEffect(() => {
                const el = canvasRef.current;
                if (!el) return;
                const onWheel = (e) => {
                    e.preventDefault();
                    const r = el.getBoundingClientRect();
                    const d = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
                    zoomAt(Math.exp(-crClamp(d, -120, 120) * 0.0022), e.clientX - r.left, e.clientY - r.top);
                };
                el.addEventListener('wheel', onWheel, { passive: false });
                return () => el.removeEventListener('wheel', onWheel);
            }, [zoomAt]);

            // --- full screen: the Fullscreen API where it works, else the canvas covers the page ---
            useEffect(() => {
                const onChange = () => { if (!document.fullscreenElement) setFull(f => (f === 'api' ? false : f)); };
                document.addEventListener('fullscreenchange', onChange);
                return () => document.removeEventListener('fullscreenchange', onChange);
            }, []);
            useEffect(() => {
                if (full !== 'css') return;
                const onKey = (e) => { if (e.key === 'Escape') setFull(false); };
                document.addEventListener('keydown', onKey);
                return () => document.removeEventListener('keydown', onKey);
            }, [full]);
            const toggleFull = () => {
                autoFit.current = true;
                if (full) {
                    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
                    setFull(false);
                    return;
                }
                const el = rootRef.current;
                if (el && el.requestFullscreen) {
                    el.requestFullscreen().then(() => setFull('api')).catch(() => setFull('css'));
                } else {
                    setFull('css');
                }
            };

            // --- what the pointer and the keyboard do on the canvas ---
            const keyOf = (target) => {
                const el = target && target.closest ? target.closest('[data-k]') : null;
                return el ? el.getAttribute('data-k') : null;
            };
            const activate = (key) => {
                const h = handlers.current;
                if (key.startsWith('f:')) {
                    const nk = `n:${key.slice(2)}`;
                    const card = layRef.current.items.get(nk);
                    setOpen(o => ({ ...o, [nk]: !(card && card.card.open) }));
                    return;
                }
                if (key.startsWith('cf:')) {
                    const id = key.slice(3);
                    setFolded(f => {
                        const next = { ...f };
                        if (next[id]) delete next[id]; else next[id] = true;
                        crWrite('cr-topo-folded', Object.keys(next).length ? JSON.stringify(next) : null);
                        return next;
                    });
                    return;
                }
                const it = layRef.current.items.get(key);
                if (!it) return;
                if (it.kind === 'guest' && h.onVmClick) h.onVmClick({ ...it.g, _clusterId: it.cl.id });
                else if (it.kind === 'node' && h.onNodeClick) h.onNodeClick(it.cl.id, it.n.name);
                else if (it.kind === 'cluster' && multi && h.onClusterClick) h.onClusterClick(it.cl.id);
            };
            const place = (el, key) => {
                const box = canvasRef.current && canvasRef.current.getBoundingClientRect();
                const r = el.getBoundingClientRect();
                if (!box) return;
                const left = r.right - box.left + 10;
                setTip({ key, x: left + 250 > box.width ? Math.max(6, r.left - box.left - 256) : left,
                         y: crClamp(r.top - box.top, 6, Math.max(6, box.height - 170)) });
            };
            const onOver = (e) => {
                if (drag.current && drag.current.moved) return;
                const key = keyOf(e.target);
                if (!key || key.startsWith('cf:')) return;
                const real = key.startsWith('f:') ? `n:${key.slice(2)}` : key;
                if (tip && tip.key === real) return;
                setFocus(real);
                place(e.target.closest('[data-k]'), real);
            };
            const onOut = (e) => {
                const to = e.relatedTarget;
                if (to && canvasRef.current && canvasRef.current.contains(to) && keyOf(to)) return;
                setFocus(null);
                setTip(null);
            };
            const onFocusIn = (e) => {
                const key = keyOf(e.target);
                if (!key || key.startsWith('cf:')) return;
                const real = key.startsWith('f:') ? `n:${key.slice(2)}` : key;
                setFocus(real);
                place(e.target.closest('[data-k]'), real);
                // the camera follows the keyboard: an item out of view is brought in
                const it = layRef.current.items.get(real);
                const el = canvasRef.current;
                if (it && el) {
                    const { k, x, y } = cam.current;
                    const sx = it.x * k + x, sy = it.y * k + y;
                    if (sx < 0 || sy < 0 || sx + it.w * k > el.clientWidth || sy + it.h * k > el.clientHeight) {
                        cam.current = { k, x: el.clientWidth / 2 - (it.x + it.w / 2) * k, y: el.clientHeight / 2 - (it.y + it.h / 2) * k };
                        autoFit.current = false;
                        apply();
                    }
                }
            };
            const onFocusOut = (e) => {
                if (e.relatedTarget && canvasRef.current && canvasRef.current.contains(e.relatedTarget)) return;
                setFocus(null);
                setTip(null);
            };
            const onPointerDown = (e) => {
                if (e.button !== 0) return;
                drag.current = { x: e.clientX, y: e.clientY, cx: cam.current.x, cy: cam.current.y, moved: false, id: e.pointerId };
            };
            const onPointerMove = (e) => {
                const d = drag.current;
                if (!d) return;
                const dx = e.clientX - d.x, dy = e.clientY - d.y;
                if (!d.moved) {
                    if (Math.abs(dx) + Math.abs(dy) < 5) return;
                    d.moved = true;
                    try { canvasRef.current.setPointerCapture(d.id); } catch (_) {}
                    setGrabbing(true);
                    setTip(null);
                }
                cam.current = { ...cam.current, x: d.cx + dx, y: d.cy + dy };
                autoFit.current = false;
                apply();
            };
            const onPointerUp = () => {
                const d = drag.current;
                drag.current = null;
                if (d && d.moved) {
                    swallowClick.current = true;
                    setTimeout(() => { swallowClick.current = false; }, 0);
                    setGrabbing(false);
                }
            };
            const onClick = (e) => {
                if (swallowClick.current) return;
                const key = keyOf(e.target);
                if (key) activate(key);
            };
            const onKeyDown = (e) => {
                const key = keyOf(e.target);
                if (key && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); activate(key); return; }
                if (e.altKey || e.ctrlKey || e.metaKey) return;
                if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomCenter(1.25); }
                else if (e.key === '-' || e.key === '_') { e.preventDefault(); zoomCenter(0.8); }
                else if (e.key === '0') { e.preventDefault(); fitAll(); }
                else if (e.key === 'ArrowUp') { e.preventDefault(); pan(0, 60); }
                else if (e.key === 'ArrowDown') { e.preventDefault(); pan(0, -60); }
                else if (e.key === 'ArrowLeft') { e.preventDefault(); pan(60, 0); }
                else if (e.key === 'ArrowRight') { e.preventDefault(); pan(-60, 0); }
            };

            // --- toolbar actions ---
            const zoomToHits = () => {
                const l = layRef.current;
                let box = null;
                const grow = (it) => {
                    if (!it) return;
                    box = box ? { x1: Math.min(box.x1, it.x), y1: Math.min(box.y1, it.y), x2: Math.max(box.x2, it.x + it.w), y2: Math.max(box.y2, it.y + it.h) }
                        : { x1: it.x, y1: it.y, x2: it.x + it.w, y2: it.y + it.h };
                };
                hit.keys.forEach(k => {
                    if (l.items.has(k)) return grow(l.items.get(k));
                    const [kind, cid, rest] = [k[0], k.split(':')[1], k.split(':').slice(2).join(':')];
                    // a guest in a folded node: its node, a node in a folded cluster: the box
                    if (kind === 'g') {
                        const cl = model.find(x => x.id === cid);
                        const n = cl && cl.nodes.find(x => x.guests.some(g => String(g.vmid) === rest));
                        if (n && l.items.has(`n:${cid}:${n.name}`)) return grow(l.items.get(`n:${cid}:${n.name}`));
                    }
                    grow(l.items.get(`c:${cid}`));
                });
                if (box && fitBox({ x: box.x1, y: box.y1, w: box.x2 - box.x1, h: box.y2 - box.y1 })) autoFit.current = false;
            };
            const toggleShow = (kind) => setShow(s => {
                const next = { ...s, [kind]: !s[kind] };
                crWrite('cr-topo-show', JSON.stringify(next));
                return next;
            });
            const foldAll = (on) => {
                const next = {};
                if (on) model.forEach(cl => { next[cl.id] = true; });
                crWrite('cr-topo-folded', on ? JSON.stringify(next) : null);
                setFolded(next);
                wantFit.current = true;
            };
            const toggleAffinity = () => {
                if (!showAffinity && !(affinityRules || []).length && clusterId) {
                    fetch(`${API_URL}/clusters/${clusterId}/affinity-rules`, { headers: getAuthHeaders(), credentials: 'include' })
                        .then(r => (r.ok ? r.json() : null))
                        .then(d => setAffinityRules(Array.isArray(d) ? d : (d && d.rules) || []))
                        .catch(() => {});
                }
                setShowAffinity(v => !v);
            };
            const toggleLegend = () => setLegend(v => { crWrite('cr-topo-legend', v ? '0' : '1'); return !v; });

            const allFolded = multi && model.length > 0 && model.every(cl => folded[cl.id]);
            const quorum = (() => {
                if (multi || !model[0]) return null;
                const total = model[0].nodes.length;
                const online = model[0].online;
                if (total < 3 || online === total) return null;
                return online * 2 <= total
                    ? <CrBadge tone="error">{t('quorumAtRisk')}</CrBadge>
                    : <CrBadge tone="warning">{total - online}/{total} {t('nodesOffline')}</CrBadge>;
            })();
            const scope = multi && model.length !== 1
                ? crFill(t('crTopoScope'), { clusters: crNum(model.length), nodes: crNum(totals.nodes), guests: crNum(totals.guests) })
                : crFill(t('crTopoScopeOne'), { nodes: crNum(totals.nodes), guests: crNum(totals.guests) });
            const empty = model.length === 0 || model.every(cl => !cl.nodes.length && !cl.unknown && !cl.guests);
            const tipData = tip ? crTopoTip(lay.items.get(tip.key), t, { multi, vmBridges: vmBridges || {}, vmStorages: vmStorages || {} }) : null;
            const chip = (id, label, on, onToggle, n) => (
                <button key={id} type="button" className={on ? 'active' : ''} aria-pressed={on} data-cr-topo-show={id} onClick={onToggle}>
                    {label}{n != null && <span className="cr-seg-n">{crNum(n)}</span>}
                </button>
            );
            const iconBtn = (icon, label, fn, extra = {}) => (
                <button type="button" className="cr-icon-btn" onClick={fn} aria-label={label} title={label} {...extra}>
                    <span className="cr-ico" aria-hidden="true">{icon}</span>
                </button>
            );

            return (
                <div ref={rootRef} className={`cr-topo${full ? ' cr-topo-full' : ''}`} data-cr-topo-root={multi ? 'multi' : 'single'}
                    data-cr-full={full || undefined}>
                    <div className="cr-topo-bar" role="toolbar" aria-label={t('topologyView')}>
                        <div className="cr-topo-bar-left">
                            <span className="cr-topo-scope" data-cr-topo-scope="">{scope}</span>
                            {quorum}
                            <div className="cr-search-box">
                                <Icons.Search className="cr-search-ico" />
                                <input type="search" className="cr-input" value={query} data-cr-topo-search=""
                                    placeholder={t('crTopoSearch')} aria-label={t('crTopoSearch')}
                                    onChange={e => setQuery(e.target.value)}
                                    onKeyDown={e => {
                                        if (e.key === 'Enter') { e.preventDefault(); setQ(query.trim().toLowerCase()); setTimeout(zoomToHits, 0); }
                                        else if (e.key === 'Escape' && query) { e.stopPropagation(); setQuery(''); }
                                    }} />
                            </div>
                            {q && (
                                <span className="cr-table-count" aria-live="polite" data-cr-topo-hits={hit.count}>
                                    {hit.count ? crFill(t('crTopoMatches'), { n: crNum(hit.count) }) : t('crNoMatch')}
                                </span>
                            )}
                            {q && hit.count > 0 && (
                                <button type="button" className="cr-btn cr-btn-ghost" onClick={zoomToHits} data-cr-topo-zoomhits="">{t('crTopoZoomHits')}</button>
                            )}
                            <div className="cr-seg" role="group" aria-label={t('filter')}>
                                {chip('qemu', t('vms'), show.qemu, () => toggleShow('qemu'), totals.qemu)}
                                {chip('lxc', t('containers'), show.lxc, () => toggleShow('lxc'), totals.lxc)}
                                {totals.pbs > 0 && chip('pbs', t('backupServers'), show.pbs, () => toggleShow('pbs'), totals.pbs)}
                                {!multi && chip('storage', t('storage'), !!showStorage, onToggleStorage)}
                                {!multi && chip('network', t('network'), !!showNetwork, onToggleNetwork)}
                                {!multi && chip('affinity', t('affinity'), !!showAffinity, toggleAffinity)}
                            </div>
                        </div>
                        <div className="cr-topo-bar-right">
                            {multi && (
                                <button type="button" className="cr-btn cr-btn-ghost" onClick={() => foldAll(!allFolded)} data-cr-topo-foldall={allFolded ? 'open' : 'fold'}>
                                    {allFolded ? t('crTopoUnfoldAll') : t('crTopoFoldAll')}
                                </button>
                            )}
                            <div className="cr-seg cr-topo-zoom" role="group" aria-label={t('crTopoZoom')}>
                                <button type="button" onClick={() => zoomCenter(0.8)} aria-label={t('zoomOut')} title={t('zoomOut')} data-cr-topo-zoom="out"><Icons.ZoomOut /></button>
                                <button type="button" onClick={actualSize} title={t('crTopoActualSize')} aria-label={t('crTopoActualSize')} data-cr-topo-zoom="pct">
                                    <span className="cr-topo-pct" data-cr-topo-pct={zoomPct}>{zoomPct}%</span>
                                </button>
                                <button type="button" onClick={() => zoomCenter(1.25)} aria-label={t('zoomIn')} title={t('zoomIn')} data-cr-topo-zoom="in"><Icons.ZoomIn /></button>
                                <button type="button" onClick={fitAll} data-cr-topo-fit="">{t('crTopoFit')}</button>
                            </div>
                            {iconBtn(<Icons.RefreshCw />, t('refreshData'), onRefresh, { 'data-cr-topo-refresh': '' })}
                            {iconBtn(<Icons.Info />, t('legend'), toggleLegend, { 'aria-pressed': legend, 'data-cr-topo-legend': '' })}
                            <div className="cr-menu-anchor">
                                {iconBtn(<Icons.Download />, t('export'), () => setExportOpen(o => !o), { 'aria-haspopup': 'true', 'aria-expanded': exportOpen, 'data-cr-topo-export': '' })}
                                {exportOpen && (
                                    <>
                                        <div className="cr-click-away" onClick={() => setExportOpen(false)} />
                                        <div className="cr-menu" role="menu" onKeyDown={e => { if (e.key === 'Escape') setExportOpen(false); }}>
                                            {[['png', t('exportAsPng')], ['jpg', t('exportAsJpg')], ['pdf', t('exportAsPdf')]].map(([f, label]) => (
                                                <button key={f} type="button" role="menuitem" className="cr-menu-item" data-cr-topo-format={f}
                                                    onClick={() => { setExportOpen(false); crTopoExport(svgRef.current, lay, c, f, clusterName); }}>{label}</button>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                            {iconBtn(full ? <Icons.Minimize /> : <Icons.Maximize />, full ? t('exitFullscreen') : t('fullscreen'), toggleFull,
                                { 'aria-pressed': !!full, 'data-cr-topo-full': '' })}
                        </div>
                    </div>
                    <div ref={canvasRef} className={`cr-topo-canvas${grabbing ? ' cr-topo-grabbing' : ''}`} style={{ background: c.canvas }}
                        tabIndex={0} role="group" aria-label={t('crTopoDiagram')} aria-describedby="cr-topo-hint"
                        onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerCancel={onPointerUp}
                        onPointerOver={onOver} onPointerOut={onOut} onFocus={onFocusIn} onBlur={onFocusOut}
                        onClick={onClick} onKeyDown={onKeyDown}>
                        <span id="cr-topo-hint" className="cr-sr-only">{t('crTopoHint')}</span>
                        {empty ? (
                            <div className="cr-empty cr-topo-empty" data-cr-topo-empty="">
                                <Icons.Network className="w-6 h-6" />
                                <p>{t('crTopoEmpty')}</p>
                                <button type="button" className="cr-btn" onClick={onRefresh}>{t('refreshData')}</button>
                            </div>
                        ) : (
                            <svg ref={svgRef} className="cr-topo-svg" xmlns="http://www.w3.org/2000/svg" fontFamily={CR_TOPO_FONT}
                                width="100%" height="100%">
                                <g ref={camRef} data-cr-camera="">
                                    <CrTopoScene lay={lay} c={c} hit={hit} multi={multi} t={t} />
                                    <CrTopoLinks lay={lay} focus={focus} c={c} vmStorages={vmStorages || {}} vmBridges={vmBridges || {}}
                                        affinity={!multi && showAffinity ? affinityRules : null} />
                                </g>
                            </svg>
                        )}
                        {tipData && (
                            <div className="cr-topo-tip" style={{ left: tip.x, top: tip.y }} role="tooltip" data-cr-topo-tip={tip.key}>
                                <div className="cr-topo-tip-title">{tipData.title}</div>
                                <dl>
                                    {tipData.rows.map(([k, v]) => (
                                        <div key={k}><dt>{k}</dt><dd>{v}</dd></div>
                                    ))}
                                </dl>
                            </div>
                        )}
                        {legend && (
                            <div className="cr-topo-legend" data-cr-topo-legend-box="">
                                <div><span className="cr-dot cr-dot-success" />{t('legendOnline')}</div>
                                <div><span className="cr-dot cr-dot-error" />{t('legendOffline')}</div>
                                <div><span className="cr-dot" />{t('crTopoNotReported')}</div>
                                <div><span className="cr-topo-key cr-topo-key-vm" />VM</div>
                                <div><span className="cr-topo-key cr-topo-key-ct" />{t('container')}</div>
                                <div><span className="cr-topo-key cr-topo-key-pbs" />{t('crTopoLinkedBackup')}</div>
                                {!multi && (showStorage || showNetwork) && <div className="cr-topo-legend-note">{t('crTopoLinksHint')}</div>}
                                {!multi && showAffinity && (
                                    <>
                                        <div><span className="cr-topo-key cr-topo-key-aff" />{t('legendAff')}</div>
                                        <div><span className="cr-topo-key cr-topo-key-anti" />{t('legendAntiAff')}</div>
                                    </>
                                )}
                                <div className="cr-topo-legend-note">{t('crTopoHint')}</div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }
