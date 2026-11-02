        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): Reports - the summary and Infrastructure Insights - LW Oct 2026
        // Mounted instead of the classic summary body and InsightsTab, in the preview only. The
        // summary reads through the dashboard's loadReportSummary (period, or from/to for the two
        // presets the endpoint cannot name and for the zoom); the rankings, guest counts, top
        // talkers and rollups come from the guest lists the dashboard already holds, the node disks
        // from its /metrics poll. Insights reads the forecast and the right-sizing apart, each
        // with its own state. A figure no read carried stays a dash, and a forecast is never
        // shown as a measurement.
        // ═══════════════════════════════════════════════════════════

        // the presets of the summary: three the endpoint names (period), two it takes as from/to
        const CR_RP_RANGES = [
            { id: 'hour', period: 'hour', secs: 3600, label: 'crRange1h' },
            { id: '6h', secs: 6 * 3600, label: 'crRpRange6h' },
            { id: 'day', period: 'day', secs: 86400, label: 'crRange24h' },
            { id: 'week', period: 'week', secs: 7 * 86400, label: 'crRange7d' },
            { id: '30d', secs: 30 * 86400, label: 'crRange30d' },
        ];
        const CR_RP_TOP = 10;
        // the collector stores one snapshot every 5 minutes (background/metrics.py)
        const CR_RP_STEP = 300;
        const crRpNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const crRpGuest = (g) => !!g && (g.type === 'qemu' || g.type === 'lxc');
        const crRpWhen = (sec) => (crRpNum(sec) ? crVmWhen(sec * 1000) : '');
        const crRpRate = (bps) => (crRpNum(bps) ? `${formatBytes(bps)}/s` : '-');
        const crRpName = (g) => g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}`;

        // what a loadReportSummary answer ({ ok, status, body }) came to, in the words of crVmRead
        function crRpRead(res) {
            const at = Date.now();
            if (!res || !res.status) return { state: 'unreachable', at };
            const body = res.body;
            if (res.ok && body && typeof body === 'object' && !body.error) return { state: 'ok', body, code: res.status, at };
            const msg = body && typeof body.error === 'string' ? body.error : '';
            const code = res.status;
            if (code === 503 && body && body.code === 'HA_ACTIVE_UNREACHABLE') return { state: 'away', code, at };
            const state = code === 403 ? 'forbidden' : code === 404 ? 'notfound' : code === 503 ? 'offline'
                : code === 429 ? 'limited' : 'error';
            return { state, code, msg, at };
        }

        // why a read did not come back ok, without the "could not be read" the sentence around it says
        function crRpWhy(read, t) {
            if (read && read.state === 'error') return read.msg || (read.code ? `HTTP ${read.code}` : t('crVmReadFailed'));
            return crVmReadText(read, t);
        }

        // The report as chart series: seconds, one slot per snapshot. A metric with fewer samples
        // than snapshots (a snapshot with every node offline adds a time but no figure) cannot be
        // placed in time and is left out. A stretch without any snapshot (the cluster was not
        // connected, PegaProx was not running) gets one empty slot, so the line breaks there.
        function crRpSeries(d) {
            if (!d || !Array.isArray(d.timestamps)) return null;
            const ts = d.timestamps.map(x => { const ms = new Date(x).getTime(); return Number.isFinite(ms) ? ms / 1000 : null; });
            const n = ts.length;
            const pick = (m) => (m && Array.isArray(m.samples) && m.samples.length === n ? m.samples : null);
            const src = { cpu: pick(d.cpu), memory: pick(d.memory), guests: d.scoped ? null : pick(d.vms_running) };
            const skew = {};
            ['cpu', 'memory'].forEach(k => {
                const a = d[k] && Array.isArray(d[k].samples) ? d[k].samples : [];
                if (!src[k] && n > 0) skew[k] = { have: a.length, of: n };
            });
            const deltas = [];
            for (let i = 1; i < n; i++) if (ts[i] != null && ts[i - 1] != null && ts[i] > ts[i - 1]) deltas.push(ts[i] - ts[i - 1]);
            deltas.sort((a, b) => a - b);
            const step = deltas.length ? deltas[Math.floor(deltas.length / 2)] : null;
            const metrics = { cpu: src.cpu ? [] : null, memory: src.memory ? [] : null, guests: src.guests ? [] : null };
            const out = { timestamps: [], metrics, step, gaps: 0, skew, points: n, first: null, last: null };
            for (let i = 0; i < n; i++) {
                if (ts[i] == null) continue;
                const prev = out.timestamps.length ? out.timestamps[out.timestamps.length - 1] : null;
                if (prev != null && step && ts[i] - prev > Math.max(2.5 * step, 2 * CR_RP_STEP)) {
                    out.timestamps.push((prev + ts[i]) / 2);
                    Object.keys(metrics).forEach(k => { if (metrics[k]) metrics[k].push(null); });
                    out.gaps++;
                }
                out.timestamps.push(ts[i]);
                Object.keys(metrics).forEach(k => { if (metrics[k]) metrics[k].push(crRpNum(src[k][i]) ? src[k][i] : null); });
                if (out.first == null) out.first = ts[i];
                out.last = ts[i];
            }
            return out;
        }

        // guests of a list by state; templates apart (PVE lists them as stopped)
        function crRpCount(rows) {
            const c = { vm: { running: 0, stopped: 0, other: 0, total: 0 }, ct: { running: 0, stopped: 0, other: 0, total: 0 }, templates: 0 };
            (rows || []).forEach(g => {
                if (!crRpGuest(g)) return;
                if (g.template) { c.templates++; return; }
                const b = g.type === 'lxc' ? c.ct : c.vm;
                b.total++;
                if (g.status === 'running') b.running++;
                else if (g.status === 'stopped') b.stopped++;
                else b.other++;
            });
            return c;
        }

        // true while the element is narrower than px: the wide tables then start with fewer columns
        // (the column menu brings them back)
        function crRpNarrow(ref, px) {
            const [narrow, setNarrow] = useState(false);
            useEffect(() => {
                const el = ref.current;
                if (!el || typeof ResizeObserver === 'undefined') return undefined;
                const ro = new ResizeObserver(() => setNarrow(el.clientWidth < px));
                ro.observe(el);
                setNarrow(el.clientWidth < px);
                return () => ro.disconnect();
            }, [ref, px]);
            return narrow;
        }

        // a callout of the reports: tone, an id for the tests, an optional retry
        function CrRpNote({ tone = 'info', id, children, onRetry }) {
            const { t } = useTranslation();
            const icon = tone === 'error' || tone === 'warning' ? <Icons.AlertTriangle /> : <Icons.Info />;
            return (
                <div className={`cr-callout cr-callout-${tone}`} data-cr-rp-note={id} role={tone === 'error' ? 'alert' : undefined}>
                    <span className="cr-ico" aria-hidden="true">{icon}</span>
                    <div>{children}</div>
                    {onRetry && <CrButton className="cr-btn-xs" onClick={onRetry} data-cr-rp-retry={id}>{t('retry')}</CrButton>}
                </div>
            );
        }

        // one tile: a value now, what the history says under it, and the basis of both
        function CrRpStat({ id, label, value, unit, meter, tone, sub, basis, title }) {
            return (
                <div className={`cr-stat${tone ? ' cr-stat-' + tone : ''}`} data-cr-rp-stat={id} title={title}>
                    <span className="cr-stat-label">{label}</span>
                    <span className="cr-stat-value">{value}{unit && <span className="cr-stat-unit">{unit}</span>}</span>
                    {meter != null && (
                        <span className={`cr-stat-bar cr-tone-${crTone(meter)}`} aria-hidden="true">
                            <span style={{ width: `${Math.min(100, Math.max(0, meter))}%` }} />
                        </span>
                    )}
                    {sub && <span className="cr-stat-sub" data-cr-rp-sub={id}>{sub}</span>}
                    {basis && <span className="cr-stat-sub cr-rp-basis" data-cr-rp-basis={id}>{basis}</span>}
                </div>
            );
        }

        // the guest of a row as a link when the inventory holds it, else its name
        function CrRpGuestCell({ g, cid, nav, cluster }) {
            const label = crRpName(g);
            const can = nav && typeof nav.openGuest === 'function' && cid;
            return (
                <span className="cr-rp-guest">
                    <span className={`cr-ico cr-guest-ico cr-guest-${g.type}`} aria-hidden="true">{g.type === 'lxc' ? <Icons.Box /> : <Icons.Monitor />}</span>
                    {can ? (
                        <button type="button" className="cr-link cr-rp-go" data-cr-rp-go={`${cid}:${g.vmid}`}
                            onClick={e => { e.stopPropagation(); nav.openGuest(cid, g); }}>{label}</button>
                    ) : <span className="cr-strong">{label}</span>}
                    <span className="cr-muted cr-mono">{g.vmid}</span>
                    {cluster && <span className="cr-muted">{cluster}</span>}
                </span>
            );
        }

        // html2canvas of a part of the page, on the background the theme draws (classic loads it the same way)
        function crRpPng(el, name) {
            return new Promise(resolve => {
                if (!el) return resolve(false);
                let bg = null;
                try { bg = getComputedStyle(document.body).getPropertyValue('--cr-bg-primary').trim() || getComputedStyle(document.body).backgroundColor; } catch (_) {}
                const go = () => window.html2canvas(el, { backgroundColor: bg || null, scale: 2, useCORS: true }).then(canvas => {
                    const a = document.createElement('a');
                    a.download = name;
                    a.href = canvas.toDataURL('image/png');
                    a.click();
                    resolve(true);
                }).catch(() => resolve(false));
                if (window.html2canvas) return go();
                const s = document.createElement('script');
                s.src = '/static/js/html2canvas.min.js';
                s.onload = go;
                s.onerror = () => {
                    const airGap = (() => { try { return localStorage.getItem('pegaprox-air-gap') === '1'; } catch (_) { return false; } })();
                    if (airGap) return resolve(false);
                    const s2 = document.createElement('script');
                    s2.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
                    s2.onload = go;
                    s2.onerror = () => resolve(false);
                    document.head.appendChild(s2);
                };
                document.head.appendChild(s);
            });
        }

        // jsPDF's Helvetica is WinAnsi only: arrows and the like as ASCII, nothing it cannot draw
        const CR_RP_MIN_FS = 1024 * 1024;
        function crRpSafe(s) {
            if (s == null) return '';
            return String(s).replace(/→/g, '->').replace(/≥/g, '>=').replace(/≤/g, '<=').replace(/²/g, '2')
                .replace(/[^\x20-\x7e\xa0-\xff]/g, '');
        }

        // --- the summary ------------------------------------------------------------

        function CrReportsSummary({ cluster, load, guests, guestsRead, nodes, nav, onSub, onTab }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const [range, setRange] = useState(() => {
                const v = crRead('cr-reports-range');
                return CR_RP_RANGES.some(r => r.id === v) ? v : 'day';
            });
            const [read, setRead] = useState(null);
            const [busy, setBusy] = useState(false);
            const [more, setMore] = useState(false);
            const [exporting, setExporting] = useState('');
            const [exportMsg, setExportMsg] = useState('');
            const seq = useRef(0);
            const loadRef = useRef(load);
            loadRef.current = load;
            const bodyRef = useRef(null);
            const key = `${cid}|${range}`;

            const ask = useCallback(() => {
                if (!cid || typeof loadRef.current !== 'function') return;
                const mine = ++seq.current;
                const rng = CR_RP_RANGES.find(r => r.id === range) || CR_RP_RANGES[2];
                const now = Date.now() / 1000;
                const asked = { from: now - rng.secs, to: now };
                setBusy(true);
                // a refresh of the same range keeps what is shown until the answer is in
                setRead(prev => (prev && prev.key === key && prev.state === 'ok' ? prev : { key, state: 'loading' }));
                Promise.resolve(rng.period ? loadRef.current(rng.period, cid) : loadRef.current(null, cid, asked))
                    .catch(() => null).then(res => {
                        if (mine !== seq.current) return;
                        setBusy(false);
                        setRead({ ...crRpRead(res), key, asked, period: rng.period || null });
                    });
            }, [cid, range, key]);
            useEffect(() => { ask(); }, [ask]);

            const pickRange = (id) => { setRange(id); crWrite('cr-reports-range', id); };
            const connected = !!(cluster && cluster.connected);
            const current = read && read.key === key ? read : { state: 'loading' };
            const body = current.state === 'ok' ? current.body : null;
            const series = useMemo(() => (body ? crRpSeries(body) : null), [body]);
            const zoom = useChartZoom({
                preset: range, loaded: series, resetKey: cid,
                loadRange: (from, to) => Promise.resolve(loadRef.current(null, cid, { from, to })).catch(() => null)
                    .then(res => { const r = crRpRead(res); return r.state === 'ok' ? crRpSeries(r.body) : null; }),
            });

            // live figures only when an online node answered: a cluster that is not connected
            // (or whose nodes all failed to answer) comes back with zeros and no flag
            const live = body && connected && body.live && crRpNum(body.live.mem_total) && body.live.mem_total > 0 ? body.live : null;
            const scoped = !!(body && body.scoped);
            const hist = (k) => {
                const m = body && body[k];
                const n = m && Array.isArray(m.samples) ? m.samples.length : 0;
                return n > 0 && body.data_points > 0 ? { avg: m.avg, min: m.min, max: m.max, n } : null;
            };
            const cpuHist = hist('cpu');
            const memHist = hist('memory');
            const counts = useMemo(() => (Array.isArray(guests) ? crRpCount(guests) : null), [guests]);
            const haveGuests = connected && guestsRead && counts;

            // a cluster that is not connected keeps its last lists in the dashboard: not shown as now
            const ranked = useMemo(() => {
                if (!Array.isArray(guests) || !connected) return null;
                const run = guests.filter(g => crRpGuest(g) && g.status === 'running' && !g.template);
                const by = (f) => run.map(g => ({ g, v: f(g) })).filter(x => x.v != null).sort((a, b) => b.v - a.v)
                    .slice(0, CR_RP_TOP).map((x, i) => ({ ...x, rank: i + 1 }));
                return {
                    running: run.length,
                    cpu: by(g => (crRpNum(g.cpu) ? g.cpu * 100 : null)),
                    ram: by(g => (crRpNum(g.mem) && g.maxmem > 0 ? g.mem / g.maxmem * 100 : null)),
                };
            }, [guests, connected]);

            const nodeRows = useMemo(() => (connected ? Object.keys(nodes || {}) : []).filter(n => nodes[n] && typeof nodes[n] === 'object' && typeof nodes[n].status === 'string')
                .map(name => {
                    const m = nodes[name];
                    // a node status without rootfs comes as 0 of 1 byte (manager.py): no root file system has less than 1 MiB
                    const known = crRpNum(m.disk_total) && m.disk_total >= CR_RP_MIN_FS && crRpNum(m.disk_used);
                    const online = m.status === 'online' && m.offline !== true;
                    return { name, m, online, maint: !!m.maintenance_mode, known,
                             pct: known ? m.disk_used / m.disk_total * 100 : null,
                             used: known ? m.disk_used : null, total: known ? m.disk_total : null,
                             free: known ? Math.max(0, m.disk_total - m.disk_used) : null };
                }), [nodes, connected]);

            const rangeLabel = t((CR_RP_RANGES.find(r => r.id === range) || {}).label || 'crRange24h');
            const stepMin = series && series.step ? Math.max(1, Math.round(series.step / 60)) : null;

            // what the range covers: the server's clamp to its retention, or where the stored history starts
            let clamp = null;
            if (body && current.asked) {
                const from = crRpNum(body.from) ? body.from : null;
                if (from != null && from - current.asked.from > 3600) clamp = { kind: 'kept', at: from };
                else if (series && series.first != null && series.first - current.asked.from > Math.max(1800, 3 * (series.step || CR_RP_STEP))) {
                    clamp = { kind: 'oldest', at: series.first };
                }
            }

            const failed = current.state !== 'ok' && current.state !== 'loading';
            const errText = failed ? crVmReadText(current, t) : '';
            const perfState = current.state === 'loading' ? 'loading' : current.state !== 'ok' ? 'error'
                : !series || series.points === 0 ? 'empty' : 'ready';
            const colors = crSeriesColors();
            const charts = [
                { id: 'cpu', label: t('crRpCpuChart'), series: zoom.series('cpu'), color: colors.cpu, unit: '%', yMin: 0, yMax: 100,
                  formatValue: v => v.toFixed(1), none: series && series.skew.cpu ? t('crRpSkewChart') : undefined },
                { id: 'memory', label: t('crRpMemChart'), series: zoom.series('memory'), color: colors.ram, unit: '%', yMin: 0, yMax: 100,
                  formatValue: v => v.toFixed(1), none: series && series.skew.memory ? t('crRpSkewChart') : undefined },
            ];
            if (body && !scoped) {
                charts.push({ id: 'guests', label: t('crRpGuestsChart'), series: zoom.series('guests'), color: colors.disk, unit: ' ', yMin: 0,
                              formatValue: v => (Number.isInteger(v) ? String(v) : v.toFixed(1)), wide: true });
            }
            const footer = perfState === 'ready' ? (
                <ul className="cr-rp-foot" data-cr-rp-foot="">
                    <li data-cr-rp-history="">{crFill(t('crRpHistoryBasis'), { n: series.points, m: stepMin || 5 })}</li>
                    {series.gaps > 0 && <li data-cr-rp-gaps={series.gaps}>{crFill(t('crRpGaps'), { n: series.gaps })}</li>}
                    {clamp && clamp.kind === 'kept' && <li data-cr-rp-clamp="kept">{crFill(t('crRpClampKept'), { asked: rangeLabel, at: crRpWhen(clamp.at) })}</li>}
                    {clamp && clamp.kind === 'oldest' && <li data-cr-rp-clamp="oldest">{crFill(t('crRpClampOldest'), { asked: rangeLabel, at: crRpWhen(clamp.at) })}</li>}
                    {Object.keys(series.skew).map(k => (
                        <li key={k} data-cr-rp-skew={k}>{crFill(t('crRpSkew'), { what: k === 'cpu' ? t('cpu') : t('memory'), n: series.skew[k].have, m: series.skew[k].of })}</li>
                    ))}
                    {!scoped && charts.length > 2 && <li>{t('crRpGuestsCaveat')}</li>}
                </ul>
            ) : null;

            const cpuNow = live ? live.cpu_percent : null;
            const memNow = live ? live.mem_percent : null;
            const histSub = (h) => (h ? crFill(t('crRpAvgMinMax'), { avg: crPct(h.avg, 1), min: crPct(h.min, 1), max: crPct(h.max, 1) }) : null);
            const histBasis = (h) => (h ? crFill(t('crRpOfSnapshots'), { n: h.n }) : (body ? t('crRpNoSnapshots') : null));
            const guestTile = (b, label, id) => {
                if (!haveGuests) {
                    return <CrRpStat id={id} label={label} value="-" sub={!connected ? t('crRpNotConnected') : t('crRpGuestsUnread')} />;
                }
                const sub = (
                    <>
                        {crFill(t('crRpStoppedN'), { n: b.stopped })}
                        {b.other > 0 && <> · <span className="cr-tone-text cr-tone-warning" data-cr-rp-other={b.other}>{crFill(t('crRpOtherN'), { n: b.other })}</span></>}
                    </>
                );
                return <CrRpStat id={id} label={label} value={b.running} unit={`/ ${b.total}`}
                    sub={sub} basis={t('crRpGuestBasis')}
                    title={crFill(t('crRpGuestTitle'), { n: counts.templates })} />;
            };

            const exportPdf = async () => {
                if (typeof generatePegaProxPDF !== 'function' || exporting) return;
                setExporting('pdf'); setExportMsg('');
                try {
                    const dash = (v) => (v == null || v === '' ? '-' : v);
                    const content = [
                        { type: 'stats', data: [
                            { label: crRpSafe(t('crRpCpuNow')), value: crPct(cpuNow, 1), color: '#2b8aa5' },
                            { label: crRpSafe(t('crRpMemNow')), value: crPct(memNow, 1), color: '#7a5aa6' },
                            { label: crRpSafe(t('crVmsRunning')), value: haveGuests ? `${counts.vm.running}/${counts.vm.total}` : '-', color: '#333333' },
                            { label: crRpSafe(t('crCtsRunning')), value: haveGuests ? `${counts.ct.running}/${counts.ct.total}` : '-', color: '#333333' },
                        ] },
                        { type: 'text', value: crRpSafe(body ? crFill(t('crRpPdfBasis'), { n: body.data_points || 0, range: rangeLabel }) : errText || t('crRpNoSnapshots')) },
                        { type: 'table', title: crRpSafe(t('crRpPdfHistory')), columns: ['', crRpSafe(t('crRpAvg')), 'Min', 'Max', crRpSafe(t('crRpSnapshots'))],
                          rows: [[t('cpu'), cpuHist], [t('memory'), memHist]].map(([l, h]) => [crRpSafe(l), h ? crPct(h.avg, 1) : '-', h ? crPct(h.min, 1) : '-', h ? crPct(h.max, 1) : '-', h ? String(h.n) : '0']) },
                    ];
                    if (ranked) {
                        const rows = (list, f) => list.map(x => [String(x.rank), crRpSafe(crRpName(x.g)), String(x.g.vmid), crRpSafe(dash(x.g.node)), f(x)]);
                        content.push({ type: 'table', title: crRpSafe(t('crRpTopCpu')), columns: ['#', crRpSafe(t('name')), 'ID', crRpSafe(t('node')), 'CPU'], rows: rows(ranked.cpu, x => crPct(x.v, 1)) });
                        content.push({ type: 'table', title: crRpSafe(t('crRpTopRam')), columns: ['#', crRpSafe(t('name')), 'ID', crRpSafe(t('node')), 'RAM'], rows: rows(ranked.ram, x => crPct(x.v, 1)) });
                    }
                    if (nodeRows.length) {
                        content.push({ type: 'table', title: crRpSafe(t('crRpRootFs')), columns: [crRpSafe(t('node')), crRpSafe(t('status')), crRpSafe(t('crRpUse')), crRpSafe(t('crRpUsed')), crRpSafe(t('crRpSize'))],
                            rows: nodeRows.map(r => [crRpSafe(r.name), crRpSafe(r.online ? t('online') : t('offline')), r.known ? crPct(r.pct, 1) : '-', r.known ? crBytes(r.used) : '-', r.known ? crBytes(r.total) : '-']) });
                    }
                    await generatePegaProxPDF({
                        title: crRpSafe(t('crRpTitle')), subtitle: crRpSafe(rangeLabel), clusterName: crRpSafe(clusterLabel(cluster)),
                        filename: `pegaprox-report-${(cluster && cluster.name) || 'cluster'}-${new Date().toISOString().slice(0, 10)}.pdf`, content,
                    });
                } catch (e) {
                    setExportMsg(t('crRpExportFailed'));
                } finally { setExporting(''); }
            };
            const exportPng = async () => {
                if (exporting) return;
                setExporting('png'); setExportMsg('');
                const ok = await crRpPng(bodyRef.current, `pegaprox-report-${(cluster && cluster.name) || 'cluster'}-${new Date().toISOString().slice(0, 10)}.png`);
                setExporting('');
                if (!ok) setExportMsg(t('crRpExportFailed'));
            };

            const rankCols = (kind) => [
                { key: 'rank', label: '#', width: 34, align: 'right', mono: true, sortValue: x => x.rank, render: x => x.rank },
                { key: 'name', label: t('name'), flex: true, min: 150, sortValue: x => crRpName(x.g),
                  render: x => <CrRpGuestCell g={x.g} cid={cid} nav={nav} /> },
                { key: 'node', label: t('node'), width: 96, sortValue: x => x.g.node || null, render: x => x.g.node || '-' },
                kind === 'cpu'
                    ? { key: 'v', label: t('crRpCpuNowCol'), width: 118, sortValue: x => x.v, render: x => <CrMeter value={x.v} digits={1} title={crFill(t('crRpCoresOf'), { n: x.g.maxcpu || '-' })} /> }
                    : { key: 'v', label: t('crRpRamNowCol'), width: 118, sortValue: x => x.v,
                        render: x => <CrMeter value={x.v} digits={1} title={crFill(t('crUsedOf'), { used: crBytes(x.g.mem), total: crBytes(x.g.maxmem) })} /> },
            ];
            const cpuCols = useMemo(() => rankCols('cpu'), [t, cid, nav]);
            const ramCols = useMemo(() => rankCols('ram'), [t, cid, nav]);
            const nodeCols = useMemo(() => [
                { key: 'name', label: t('node'), flex: true, min: 120, sortValue: r => r.name,
                  render: r => (nav && nav.openNode
                      ? <button type="button" className="cr-link" data-cr-rp-node={r.name} onClick={e => { e.stopPropagation(); nav.openNode(cid, r.name); }}>{r.name}</button>
                      : r.name) },
                { key: 'state', label: t('status'), width: 112, sortValue: r => (r.online ? 1 : 0),
                  render: r => (r.online
                      ? (r.maint ? <CrBadge tone="warning">{t('maintenance')}</CrBadge> : <CrBadge tone="success">{t('online')}</CrBadge>)
                      : <CrBadge tone="error">{t('offline')}</CrBadge>) },
                { key: 'pct', label: t('crRpUse'), width: 128, sortValue: r => r.pct,
                  render: r => (r.known
                      ? <span data-cr-rp-fs={r.name} data-cr-rp-fstone={crStoreTone(r.pct)}><CrMeter value={r.pct} digits={1} tone={crStoreTone(r.pct)} title={crStoreScale(t)} /></span>
                      : <span className="cr-muted" data-cr-rp-fs={r.name} data-cr-rp-fstone="unknown" title={t('crRpFsUnknownTitle')}>{r.online ? t('crRpNotReported') : t('crRpOfflineNoFigure')}</span>) },
                { key: 'used', label: t('crRpUsed'), width: 96, align: 'right', mono: true, sortValue: r => r.used, render: r => (r.known ? crBytes(r.used) : '-') },
                { key: 'free', label: t('crRpFree'), width: 96, align: 'right', mono: true, sortValue: r => r.free, render: r => (r.known ? crBytes(r.free) : '-') },
                { key: 'total', label: t('crRpSize'), width: 96, align: 'right', mono: true, sortValue: r => r.total, render: r => (r.known ? crBytes(r.total) : '-') },
            ], [t, cid, nav]);
            const nearFull = nodeRows.filter(r => r.known && r.pct >= CR_STORE_WARN).length;
            const nodeNames = nodeRows.map(r => r.name).sort((a, b) => a.localeCompare(b));

            return (
                <div className="cr-rp" data-cr-rp={current.state} data-cr-rp-range={range}>
                    <CrPageHeader icon={<Icons.BarChart />} title={t('crRpTitle')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <CrButton icon={<Icons.RotateCw />} onClick={ask} disabled={busy} data-cr-rp-refresh="">{t('refresh')}</CrButton>
                                <CrButton icon={<Icons.Image />} onClick={exportPng} disabled={!!exporting || current.state === 'loading'} data-cr-rp-export="png"
                                    title={t('exportPng')}>PNG</CrButton>
                                <CrButton icon={<Icons.Download />} onClick={exportPdf} disabled={!!exporting || current.state === 'loading'} data-cr-rp-export="pdf"
                                    title={t('exportPdf')}>PDF</CrButton>
                            </>
                        )} />
                    {exportMsg && <CrRpNote tone="error" id="export">{exportMsg}</CrRpNote>}
                    {!connected && <CrRpNote tone="warning" id="offline">{t('crRpOfflineNote')}</CrRpNote>}
                    {connected && body && !live && <CrRpNote tone="warning" id="nolive">{t('crRpNoLiveNote')}</CrRpNote>}
                    {scoped && <CrRpNote tone="info" id="scoped">{t('crRpScopedNote')}</CrRpNote>}
                    {failed && <CrRpNote tone="error" id={`read-${current.state}`} onRetry={ask}>{crFill(t('crRpReadFailed'), { why: crRpWhy(current, t) })}</CrRpNote>}

                    <div className="cr-rp-body" ref={bodyRef}>
                        <section className="cr-stat-row cr-rp-stats" aria-label={t('crRpKpis')} data-cr-rp-stats="">
                            <CrRpStat id="cpu" label={t('crRpCpuNow')} value={crPct(cpuNow, 1)} meter={cpuNow}
                                tone={cpuNow != null && cpuNow > CR_CRIT ? 'error' : cpuNow != null && cpuNow > CR_WARN ? 'warning' : null}
                                sub={histSub(cpuHist)} basis={histBasis(cpuHist)} title={t('crRpCpuTitle')} />
                            <CrRpStat id="memory" label={t('crRpMemNow')} value={crPct(memNow, 1)} meter={memNow}
                                tone={memNow != null && memNow > CR_CRIT ? 'error' : memNow != null && memNow > CR_WARN ? 'warning' : null}
                                sub={histSub(memHist)} basis={histBasis(memHist)} title={t('crRpMemTitle')} />
                            {guestTile(counts && counts.vm, t('crVmsRunning'), 'vms')}
                            {guestTile(counts && counts.ct, t('crCtsRunning'), 'cts')}
                            <CrRpStat id="history" label={t('crRpHistory')} value={body ? (body.data_points || 0) : '-'} unit={body ? t('crRpSnapshots') : ''}
                                sub={series && series.first != null ? crFill(t('crRpFromTo'), { from: crRpWhen(series.first), to: crRpWhen(series.last) }) : (body ? t('crRpNoSnapshots') : null)}
                                basis={rangeLabel} title={t('crRpHistoryTitle')} />
                        </section>

                        <CrPerfPanel title={t('crRpOverTime')} range={range} onRange={pickRange} zoom={zoom} state={perfState}
                            busy={busy || zoom.busy} onRetry={ask} errorText={errText} charts={charts} footer={footer}
                            ranges={CR_RP_RANGES.map(r => [r.id, t(r.label)])}
                            emptyText={t('crRpEmptyRange')} />

                        <div className="cr-rp-grid2">
                            {[['cpu', t('crRpTopCpu'), cpuCols], ['ram', t('crRpTopRam'), ramCols]].map(([kind, title, cols]) => (
                                <CrTable key={kind} id={`rp-top-${kind}`} columns={cols} rows={ranked ? ranked[kind] : []} rowKey={x => String(x.g.vmid)}
                                    ariaLabel={title} initialSort={{ key: 'rank', dir: 'asc' }} showCount={false} rowHeight={28}
                                    loading={connected && !guestsRead} emptyText={!connected ? t('crRpNotConnected') : t('crNoRunningGuests')}
                                    onRowClick={x => nav && nav.openGuest && nav.openGuest(cid, x.g)}
                                    toolbar={(
                                        <>
                                            <span className="cr-table-title">{title}</span>
                                            <span className="cr-table-sub" data-cr-rp-rankof={kind}>
                                                {ranked && guestsRead ? crFill(t('crRpRankOf'), { n: ranked[kind].length, total: ranked.running }) : ''}
                                            </span>
                                        </>
                                    )} />
                            ))}
                        </div>
                        <p className="cr-rp-caption">{t('crRpRankBasis')}</p>

                        <CrTable id="rp-rootfs" columns={nodeCols} rows={nodeRows} rowKey={r => r.name} ariaLabel={t('crRpRootFs')}
                            initialSort={{ key: 'pct', dir: 'desc' }} showCount={false} rowHeight={28}
                            emptyText={connected ? t('crRpNodesUnread') : t('crRpNotConnected')}
                            onRowClick={r => nav && nav.openNode && nav.openNode(cid, r.name)}
                            toolbar={(
                                <>
                                    <span className="cr-table-title">{t('crRpRootFs')}</span>
                                    {nearFull > 0 && <CrBadge tone="warning">{crFill(t('crRpNearFull'), { n: nearFull, warn: CR_STORE_WARN })}</CrBadge>}
                                    {onTab && <button type="button" className="cr-link cr-rp-tolink" data-cr-rp-datastores="" onClick={() => onTab('datastore')}>{t('crRpToDatastores')}</button>}
                                </>
                            )} />
                        <p className="cr-rp-caption">{t('crRpRootFsBasis')}</p>

                        <section className="cr-panel cr-rp-more">
                            <button type="button" className="cr-rp-more-head" aria-expanded={more} aria-controls={more ? 'cr-rp-more-body' : undefined}
                                data-cr-rp-more="" onClick={() => setMore(m => !m)}>
                                <span className="cr-ico" aria-hidden="true">{more ? <Icons.ChevronDown /> : <Icons.ChevronRight />}</span>
                                <span className="cr-panel-title">{t('crRpMoreTitle')}</span>
                                <span className="cr-muted">{t('crRpMoreSub')}</span>
                            </button>
                            {more && (
                                <div className="cr-panel-body cr-rp-more-body" id="cr-rp-more-body" data-cr-rp-more-body="">
                                    <p>{t('crRpMoreIo')}</p>
                                    {nodeNames.length > 0 && (
                                        <div className="cr-rp-chips">
                                            {nodeNames.slice(0, 12).map(n => (
                                                <button key={n} type="button" className="cr-btn cr-btn-xs" onClick={() => nav && nav.openNode && nav.openNode(cid, n)}>{n}</button>
                                            ))}
                                            {nodeNames.length > 12 && <span className="cr-muted">{crFill(t('crRpMoreN'), { n: nodeNames.length - 12 })}</span>}
                                        </div>
                                    )}
                                    <p>{t('crRpMoreStorage')}</p>
                                    {onSub && <CrButton className="cr-btn-xs" onClick={() => onSub('insights')} data-cr-rp-insights="">{t('crRpOpenInsights')}</CrButton>}
                                </div>
                            )}
                        </section>
                    </div>
                </div>
            );
        }

        // --- Infrastructure Insights -------------------------------------------------

        const CR_INS_DAYS = [7, 14, 30, 90];
        const CR_INS_TOP = 20;
        // the server's own gate for an ETA it calls warning or critical (insights.py, #374)
        const crInsGate = (f) => crRpNum(f.r_squared) && f.r_squared >= 0.5 && crRpNum(f.slope_per_day_pct)
            && crRpNum(f.current_pct) && f.slope_per_day_pct >= 0.01 * f.current_pct;
        // whether a date is shown: warning and critical passed that gate on the server; trending up
        // with a crossing inside 30 days failed it there; beyond 30 days the server did not ask, so
        // the same rule is applied here
        function crInsEtaOk(f) {
            if (!crRpNum(f.eta_days)) return false;
            if (f.status === 'critical' || f.status === 'warning') return true;
            if (f.status === 'trending_up' && f.eta_days < 30) return false;
            return crInsGate(f);
        }
        const CR_INS_STATUS = { critical: 'error', over_threshold: 'error', warning: 'warning', trending_up: 'warning', decreasing: 'success', stable: 'neutral' };
        const CR_INS_FLAG = { undersized_cpu: 'error', undersized_mem: 'error', oversized_cpu: 'info', oversized_mem: 'info', idle: 'neutral' };
        const CR_INS_METRICS = ['cpu', 'mem', 'disk', 'dio', 'nio', 'dioRate', 'nioRate'];

        // one guest of a list as top talkers rank it (the server's fields, insights.py top_talkers)
        function crInsTalker(g, c) {
            const pct = (p, used, max) => (crRpNum(p) ? p : crRpNum(used) && max > 0 ? used / max * 100 : null);
            // a VM without guest agent data reports a disk use of 0: unknown, not empty
            const disk = g.type === 'qemu' && !(g.disk > 0) ? null : pct(g.disk_percent, g.disk, g.maxdisk);
            const sum = (a, b) => (crRpNum(a) && crRpNum(b) ? a + b : null);
            const dio = sum(g.diskread, g.diskwrite);
            const nio = sum(g.netin, g.netout);
            const up = crRpNum(g.uptime) && g.uptime > 0 ? g.uptime : null;
            return { g, c, cpu: crRpNum(g.cpu_percent) ? g.cpu_percent : crRpNum(g.cpu) ? g.cpu * 100 : null,
                     mem: pct(g.mem_percent, g.mem, g.maxmem), disk, dio, nio, up,
                     dioRate: dio != null && up ? dio / up : null, nioRate: nio != null && up ? nio / up : null };
        }

        // a stable id per list, so a memo knows when a guest list really changed
        const crInsListIds = new WeakMap();
        let crInsListSeq = 0;
        const crInsListId = (l) => {
            if (!Array.isArray(l)) return 'x';
            if (!crInsListIds.has(l)) crInsListIds.set(l, ++crInsListSeq);
            return crInsListIds.get(l);
        };

        // the guest lists of the scope: this cluster, or every connected one (an ESXi connection has
        // none); null = not read yet. A cluster that is not connected has only an old list: left out
        function crInsLists(scope, cluster, clusters, nav) {
            const pick = scope === 'all' ? (clusters || []).filter(c => c && c.connected && c.cluster_type !== 'esxi') : [cluster];
            return pick.filter(Boolean).map(c => ({ c, offline: !c.connected, list: c.connected && nav && nav.guestsOf ? nav.guestsOf(c.id) : null }));
        }

        function CrInsights({ cluster, clusters, authFetch, addToast, isAdmin, nav, onOpenConfig }) {
            const { t } = useTranslation();
            const { haStandby } = useAuth();
            const { can } = crVmCan();
            // the snapshot writes this instance's own metrics: the classic rule (#625)
            const canSnap = isAdmin && !haStandby;
            const cid = cluster && cluster.id;
            const [days, setDays] = useState(30);
            const [fc, setFc] = useState(null);
            const [rs, setRs] = useState(null);
            const [snap, setSnap] = useState(null);
            const [exporting, setExporting] = useState(false);
            const seqF = useRef(0);
            const seqR = useRef(0);
            const rootRef = useRef(null);
            const narrow = crRpNarrow(rootRef, 1180);
            const key = `${cid}|${days}`;

            const readFc = useCallback(async () => {
                if (!cid) return;
                const mine = ++seqF.current;
                setFc(prev => (prev && prev.key === key && prev.state === 'ok' ? { ...prev, busy: true } : { key, state: 'loading' }));
                const r = await crVmRead(authFetch, `${API_URL}/clusters/${cid}/insights/forecast?days=${days}`);
                if (mine === seqF.current) setFc({ ...r, key });
            }, [authFetch, cid, days, key]);
            const readRs = useCallback(async () => {
                if (!cid) return;
                const mine = ++seqR.current;
                setRs(prev => (prev && prev.key === key && prev.state === 'ok' ? { ...prev, busy: true } : { key, state: 'loading' }));
                const r = await crVmRead(authFetch, `${API_URL}/clusters/${cid}/insights/right-sizing?days=${days}`);
                if (mine === seqR.current) setRs({ ...r, key });
            }, [authFetch, cid, days, key]);
            useEffect(() => { readFc(); readRs(); }, [cid, days]);
            // the server builds the report off the hub and says when it is still at it: the
            // classic follow-up asks again a few times
            useReportFollowUp(rs && rs.state === 'ok' && rs.key === key ? rs.body : null, readRs, [cid, days]);

            const takeSnap = async () => {
                if (!canSnap || (snap && snap.state === 'running')) return;
                setSnap({ state: 'running' });
                const r = await crVmRead(authFetch, `${API_URL}/insights/force-snapshot`, { method: 'POST' });
                if (r.state === 'ok' && r.body.ok !== false) {
                    setSnap({ state: 'ok', at: r.at });
                    if (addToast) addToast(t('insightsSnapshotTaken'), 'success');
                    readFc(); readRs();
                } else {
                    setSnap({ state: 'error', text: crRpWhy(r, t) });
                }
            };

            const [tt, setTt] = useState({ metric: 'cpu', scope: 'this', node: '' });
            const [ru, setRu] = useState({ by: 'tag', running: false, scope: 'this' });

            const fcNow = fc && fc.key === key ? fc : { state: 'loading' };
            const rsNow = rs && rs.key === key ? rs : { state: 'loading' };

            const exportPdf = async () => {
                if (typeof generatePegaProxPDF !== 'function' || exporting) return;
                setExporting(true);
                try {
                    const blocks = [];
                    const f = fcNow.state === 'ok' ? fcNow.body : null;
                    if (f && f.enough_data && Array.isArray(f.forecasts)) {
                        blocks.push({ type: 'table', title: crRpSafe(crFill(t('crInsPdfForecast'), { d: f.window_days })),
                            columns: [crRpSafe(t('crInsResource')), crRpSafe(t('crInsMeasured')), crRpSafe(t('crInsTrendDay')), 'R2', crRpSafe(t('crInsSamples')), crRpSafe(t('crInsCrossing'))],
                            rows: f.forecasts.map(x => [crRpSafe(crInsMetric(x, t)), crPct(x.current_pct, 1), crRpNum(x.slope_per_day_pct) ? `${x.slope_per_day_pct >= 0 ? '+' : ''}${x.slope_per_day_pct.toFixed(2)}` : '-',
                                crRpNum(x.r_squared) ? x.r_squared.toFixed(2) : '-', String(x.samples ?? '-'),
                                crRpSafe(crInsEtaOk(x) ? crFill(t('crInsEtaDays'), { d: x.eta_days }) : '-')]) });
                    } else {
                        blocks.push({ type: 'text', value: crRpSafe(f ? t('crInsNotEnough') : crFill(t('crInsNotRead'), { what: t('capacityForecast') })) });
                    }
                    const r = rsNow.state === 'ok' ? rsNow.body : null;
                    if (r) {
                        const recs = Array.isArray(r.recommendations) ? r.recommendations : [];
                        const s = r.summary || {};
                        blocks.push({ type: 'text', value: crRpSafe(crFill(t('crInsRsCounts'), { e: recs.length + (s.ok || 0), n: s.no_data || 0, f: recs.length, min: r.min_samples_required || 24 })) });
                        if (recs.length) {
                            blocks.push({ type: 'table', title: crRpSafe(t('rightSizing')), columns: ['ID', crRpSafe(t('name')), crRpSafe(t('node')), crRpSafe(t('crInsFinding')), crRpSafe(t('crInsSuggestion')), crRpSafe(t('crInsSamples'))],
                                rows: recs.map(x => [String(x.vmid), crRpSafe(x.name || ''), crRpSafe(x.node || ''), crRpSafe((x.flags || []).map(fl => crInsFlagLabel(fl.kind, t)).join(', ')),
                                    crRpSafe((x.flags || []).map(fl => crInsSuggest(fl, t)).filter(Boolean).join('; ') || '-'), String(x.samples ?? '-')]) });
                        }
                    } else {
                        blocks.push({ type: 'text', value: crRpSafe(crFill(t('crInsNotRead'), { what: t('rightSizing') })) });
                    }
                    await generatePegaProxPDF({
                        title: crRpSafe(t('crInsTitle')), subtitle: crRpSafe(crFill(t('crInsWindowN'), { d: days })), clusterName: crRpSafe(clusterLabel(cluster)),
                        filename: `pegaprox-insights-${cid || 'cluster'}-${new Date().toISOString().slice(0, 10)}.pdf`, content: blocks,
                    });
                } catch (e) {
                    if (addToast) addToast(t('crRpExportFailed'), 'error');
                } finally { setExporting(false); }
            };

            return (
                <div className="cr-ins" data-cr-ins="" data-cr-ins-narrow={narrow ? '1' : '0'} ref={rootRef}>
                    <CrPageHeader icon={<Icons.Zap />} title={t('crInsTitle')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <label className="cr-ins-window">
                                    <span>{t('crInsWindow')}</span>
                                    <select className="cr-select" value={days} onChange={e => setDays(Number(e.target.value))} data-cr-ins-days="">
                                        {CR_INS_DAYS.map(d => <option key={d} value={d}>{crFill(t('crInsDaysN'), { d })}</option>)}
                                    </select>
                                </label>
                                <CrButton icon={<Icons.RotateCw />} onClick={() => { readFc(); readRs(); }} data-cr-ins-refresh=""
                                    disabled={fcNow.state === 'loading' && rsNow.state === 'loading'}>{t('refresh')}</CrButton>
                                {canSnap && (
                                    <CrButton icon={<Icons.Camera />} onClick={takeSnap} disabled={!!(snap && snap.state === 'running')} data-cr-ins-snap=""
                                        title={t('crInsSnapTitle')}>{snap && snap.state === 'running' ? t('crInsSnapRunning') : t('insightsTakeSnapshot')}</CrButton>
                                )}
                                <CrButton icon={<Icons.Download />} onClick={exportPdf} disabled={exporting} data-cr-ins-export="">PDF</CrButton>
                                {nav && nav.openReports && (
                                    <CrButton variant="ghost" icon={<Icons.Scale />} onClick={() => nav.openReports(cid, 'whatif')} data-cr-ins-whatif=""
                                        title={t('crInsWhatIfTitle')}>{t('whatifTitle')}</CrButton>
                                )}
                            </>
                        )} />
                    {snap && snap.state === 'error' && <CrRpNote tone="error" id="snap">{crFill(t('crInsSnapFailed'), { why: snap.text })}</CrRpNote>}
                    {snap && snap.state === 'ok' && <CrRpNote tone="success" id="snap-ok">{crFill(t('crInsSnapDone'), { at: crVmWhen(snap.at) })}</CrRpNote>}

                    <CrInsForecast read={fcNow} cid={cid} nav={nav} onRetry={readFc} narrow={narrow} />
                    <CrInsRightSizing read={rsNow} cid={cid} nav={nav} can={can} onOpenConfig={onOpenConfig} onRetry={readRs} narrow={narrow} />
                    <CrInsTalkers opts={tt} setOpts={setTt} cluster={cluster} clusters={clusters} nav={nav} narrow={narrow} />
                    <CrInsRollups opts={ru} setOpts={setRu} cluster={cluster} clusters={clusters} nav={nav} narrow={narrow} />
                </div>
            );
        }

        const crInsMetric = (f, t) => (f.metric === 'cluster_cpu' ? t('clusterCpu') : f.metric === 'cluster_memory' ? t('clusterMemory') : String(f.storage || f.metric));
        const crInsFlagLabel = (k, t) => ({ oversized_cpu: t('oversizedCpu'), oversized_mem: t('oversizedMem'), undersized_cpu: t('undersizedCpu'),
                                            undersized_mem: t('undersizedMem'), idle: t('idle') }[k] || k);
        function crInsSuggest(fl, t) {
            if (fl.recommended != null) return crFill(t('crInsSuggestCpu'), { from: fl.current, to: fl.recommended });
            if (fl.recommended_gb != null) return crFill(t('crInsSuggestRam'), { from: fl.current_gb, to: fl.recommended_gb });
            return '';
        }

        // the bar of a forecast row: solid up to the measured value, hatched to where the fitted
        // line is at the horizon, a tick at the threshold. Drawn only from the server's figures
        function CrInsProjection({ f, horizon, t }) {
            const now = f.current_pct;
            if (!crRpNum(now)) return <span className="cr-muted">-</span>;
            const slope = crRpNum(f.slope_per_day_pct) ? f.slope_per_day_pct : null;
            const proj = slope != null ? Math.max(0, Math.min(100, now + slope * horizon)) : null;
            const lo = proj != null ? Math.min(now, proj) : now;
            const hi = proj != null ? Math.max(now, proj) : now;
            const weak = !(crRpNum(f.r_squared) && f.r_squared >= 0.5);
            const label = proj == null ? crFill(t('crInsProjNone'), { now: crPct(now, 1) })
                : crFill(t('crInsProjLabel'), { now: crPct(now, 1), proj: crPct(proj, 1), d: horizon });
            return (
                <span className={`cr-ins-proj${weak ? ' cr-ins-proj-weak' : ''}`} role="img" aria-label={label} title={label}
                    data-cr-ins-proj={proj != null ? proj.toFixed(1) : 'none'}>
                    <span className="cr-ins-proj-track">
                        <span className="cr-ins-proj-now" style={{ width: `${Math.min(100, Math.max(0, now))}%` }} />
                        {proj != null && hi > lo && <span className="cr-ins-proj-ahead" style={{ left: `${lo}%`, width: `${hi - lo}%` }} />}
                        {crRpNum(f.threshold_pct) && <span className="cr-ins-proj-limit" style={{ left: `${Math.min(100, f.threshold_pct)}%` }} />}
                    </span>
                    {proj != null && <span className="cr-ins-proj-val">{crPct(proj, 0)}</span>}
                </span>
            );
        }

        function CrInsForecast({ read, cid, nav, onRetry, narrow }) {
            const { t } = useTranslation();
            const body = read.state === 'ok' ? read.body : null;
            const list = body && body.enough_data && Array.isArray(body.forecasts) ? body.forecasts : [];
            const horizon = body && crRpNum(body.window_days) ? body.window_days : 30;
            const snaps = body && crRpNum(body.snapshots_in_window) ? body.snapshots_in_window : null;
            const stores = nav && nav.storesOf ? nav.storesOf(cid) : null;
            const columns = useMemo(() => [
                { key: 'what', label: t('crInsResource'), flex: true, min: 150, sortValue: f => crInsMetric(f, t),
                  render: f => {
                      const name = crInsMetric(f, t);
                      if (f.kind !== 'storage') return <span className="cr-strong">{name}</span>;
                      const hit = crFindStore(stores, f.storage || f.metric);
                      return hit && nav && nav.openStorage
                          ? <button type="button" className="cr-link" data-cr-ins-store={name} onClick={e => { e.stopPropagation(); nav.openStorage(cid, hit.store, hit.node); }}>{name}</button>
                          : <span title={t('crInsStoreLocal')}>{name}</span>;
                  } },
                { key: 'kind', label: t('type'), width: 76, hidden: narrow, sortValue: f => f.kind, render: f => (f.kind === 'storage' ? t('storage') : t('cluster')) },
                { key: 'status', label: t('status'), width: 118, sortValue: f => f.status,
                  render: f => <span data-cr-ins-status={f.status}><CrBadge tone={CR_INS_STATUS[f.status] || 'neutral'}>{crInsStatus(f.status, t)}</CrBadge></span> },
                { key: 'now', label: t('crInsMeasured'), width: 110, sortValue: f => f.current_pct, title: t('crInsMeasuredTitle'),
                  render: f => <CrMeter value={crRpNum(f.current_pct) ? f.current_pct : null} digits={1}
                      tone={f.kind === 'storage' ? crStoreTone(f.current_pct) : undefined} /> },
                { key: 'slope', label: t('crInsTrendDay'), width: 100, align: 'right', mono: true, sortValue: f => f.slope_per_day_pct, title: t('crInsTrendTitle'),
                  render: f => (crRpNum(f.slope_per_day_pct) ? `${f.slope_per_day_pct >= 0 ? '+' : ''}${f.slope_per_day_pct.toFixed(2)}` : '-') },
                { key: 'fit', label: t('crInsFit'), width: 112, sortValue: f => f.r_squared, title: t('crInsFitTitle'),
                  render: f => (
                      <span className="cr-ins-fit" data-cr-ins-fit={crRpNum(f.r_squared) && f.r_squared >= 0.5 ? 'ok' : 'weak'}>
                          <span className="cr-mono">{crRpNum(f.r_squared) ? f.r_squared.toFixed(2) : '-'}</span>
                          {!(crRpNum(f.r_squared) && f.r_squared >= 0.5) && <CrBadge tone="neutral" dot={false}>{t('crInsWeak')}</CrBadge>}
                      </span>
                  ) },
                { key: 'samples', label: t('crInsSamples'), width: 84, align: 'right', mono: true, hidden: narrow, sortValue: f => f.samples,
                  title: t('crInsSamplesTitle'), render: f => (snaps ? `${f.samples ?? '-'}/${snaps}` : String(f.samples ?? '-')) },
                { key: 'proj', label: crFill(t('crInsProjCol'), { d: horizon }), width: 140, sortable: false, title: t('crInsProjTitle'),
                  render: f => <CrInsProjection f={f} horizon={horizon} t={t} /> },
                { key: 'eta', label: crFill(t('crInsCrossingAt'), { pct: crRpNum(body && body.threshold_pct) ? body.threshold_pct : 90 }), width: 190,
                  sortValue: f => (crInsEtaOk(f) ? f.eta_days : null), title: t('crInsCrossingTitle'),
                  render: f => crInsEta(f, t) },
            ], [t, cid, nav, stores, horizon, snaps, body, narrow]);

            let note = null;
            if (read.state === 'loading') note = null;
            else if (read.state !== 'ok') note = <CrRpNote tone="error" id={`fc-${read.state}`} onRetry={onRetry}>{crFill(t('crInsReadFailed'), { what: t('capacityForecast'), why: crRpWhy(read, t) })}</CrRpNote>;
            else if (!body.enough_data) note = <CrRpNote tone="warning" id="fc-notenough">{crFill(t('crInsNotEnoughN'), { n: body.snapshots_in_window || 0 })}</CrRpNote>;
            return (
                <CrPanel title={t('capacityForecast')} className="cr-ins-panel" data-cr-ins-fc={read.state === 'ok' ? (body.enough_data ? 'ok' : 'notenough') : read.state}
                    actions={read.busy ? <span className="cr-spinner" role="status" aria-label={t('loading')} /> : null}>
                    {note}
                    {(read.state === 'loading' || (body && body.enough_data)) && (
                        <CrTable id="ins-forecast" columns={columns} rows={list} rowKey={f => String(f.metric)} ariaLabel={t('capacityForecast')}
                            loading={read.state === 'loading'} emptyText={t('crInsFcEmpty')} showCount={false} rowHeight={30}
                            initialSort={{ key: 'eta', dir: 'asc' }}
                            toolbar={body ? <span className="cr-table-sub" data-cr-ins-fcwin="">{crFill(t('crInsWindowBasis'), { d: body.window_days, n: snaps ?? '-' })}</span> : null} />
                    )}
                    {body && body.enough_data && (
                        <p className="cr-rp-caption" data-cr-ins-fc-basis="">
                            {crFill(t('crInsFcBasis'), { d: body.window_days, n: snaps ?? '-' })}
                        </p>
                    )}
                </CrPanel>
            );
        }

        const crInsStatus = (s, t) => ({ critical: t('statusCritical'), warning: t('statusWarning'), trending_up: t('statusTrendingUp'),
                                         over_threshold: t('statusOverThreshold'), decreasing: t('statusDecreasing'), stable: t('statusStable') }[s] || s || '-');

        // the threshold crossing: an estimate only where the server's own gate passed
        function crInsEta(f, t) {
            if (f.status === 'over_threshold') return <span data-cr-ins-eta="over">{t('crInsEtaOver')}</span>;
            if (!crRpNum(f.eta_days)) return <span className="cr-muted" data-cr-ins-eta="none">{t('crInsEtaNone')}</span>;
            if (!crInsEtaOk(f)) return <span className="cr-muted" data-cr-ins-eta="weak" title={t('crInsEtaWeakTitle')}>{t('crInsEtaWeak')}</span>;
            let when = '';
            if (f.eta_iso) { const d = new Date(f.eta_iso); if (Number.isFinite(d.getTime())) when = d.toLocaleDateString(crLocale()); }
            return (
                <span data-cr-ins-eta="estimate" title={t('crInsEtaTitle')}>
                    {crFill(t('crInsEtaDays'), { d: f.eta_days })}{when && <span className="cr-muted"> ({when})</span>}
                </span>
            );
        }

        function CrInsRightSizing({ read, cid, nav, can, onOpenConfig, onRetry, narrow }) {
            const { t } = useTranslation();
            const [pick, setPick] = useState(null);
            const body = read.state === 'ok' ? read.body : null;
            const recs = body && Array.isArray(body.recommendations) ? body.recommendations : [];
            const s = (body && body.summary) || {};
            const evaluated = recs.length + (s.ok || 0);
            const noData = s.no_data || 0;
            const snaps = body && crRpNum(body.snapshots_in_window) ? body.snapshots_in_window : null;
            const minS = (body && body.min_samples_required) || 24;
            const guestMap = crGuestMap(nav && nav.guestsOf ? nav.guestsOf(cid) : null);
            const rowOf = (r) => (guestMap ? guestMap.get(String(r.vmid)) : null);
            const coverage = (r) => (snaps && crRpNum(r.samples) ? Math.min(1, r.samples / snaps) : null);
            const risks = (r) => {
                const out = [];
                const kinds = (r.flags || []).map(f => f.kind);
                if (kinds.some(k => k === 'oversized_cpu' || k === 'oversized_mem')) out.push(t('crInsRiskPeaks'));
                const cov = coverage(r);
                if (cov != null && cov < 0.5) out.push(t('crInsRiskShort'));
                if (kinds.some(k => k === 'oversized_mem' || k === 'undersized_mem')) out.push(t('crInsRiskRam'));
                if (kinds.includes('idle')) out.push(t('crInsRiskIdle'));
                return out;
            };
            const columns = useMemo(() => [
                { key: 'guest', label: t('crInsGuest'), flex: true, min: 150, sortValue: r => r.name || String(r.vmid),
                  render: r => {
                      const g = rowOf(r);
                      return g ? <CrRpGuestCell g={g} cid={cid} nav={nav} />
                          : <span title={t('crInsNotInInventory')}>{r.name || r.vmid} <span className="cr-muted cr-mono">{r.vmid}</span></span>;
                  } },
                { key: 'node', label: t('node'), width: 90, hidden: narrow, sortValue: r => r.node || null, render: r => r.node || '-' },
                { key: 'flags', label: t('crInsFinding'), width: 220, sortValue: r => (r.flags || []).map(f => f.kind).join(','),
                  render: r => <span className="cr-ins-flags">{(r.flags || []).map((f, i) => (
                      <span key={i} data-cr-ins-flag={f.kind}><CrBadge tone={CR_INS_FLAG[f.kind] || 'neutral'}>{crInsFlagLabel(f.kind, t)}</CrBadge></span>
                  ))}</span> },
                { key: 'suggest', label: t('crInsSuggestion'), width: 220, sortable: false, title: t('crInsSuggestionTitle'),
                  render: r => <span className="cr-mono" data-cr-ins-suggest="">{(r.flags || []).map(f => crInsSuggest(f, t)).filter(Boolean).join(' · ') || '-'}</span> },
                { key: 'cpu', label: t('crInsCpuAvgP95'), width: 128, align: 'right', mono: true, sortValue: r => r.cpu_p95,
                  render: r => `${crPct(r.cpu_avg, 1)} / ${crPct(r.cpu_p95, 1)}` },
                { key: 'ram', label: t('crInsRamAvgMax'), width: 128, align: 'right', mono: true, hidden: narrow, sortValue: r => r.mem_max,
                  render: r => `${crPct(r.mem_avg, 1)} / ${crPct(r.mem_max, 1)}` },
                { key: 'cov', label: t('crInsCoverage'), width: 96, align: 'right', mono: true, sortValue: r => coverage(r), title: t('crInsCoverageTitle'),
                  render: r => { const c = coverage(r); return <span data-cr-ins-cov={c != null ? Math.round(c * 100) : 'none'}>{c != null ? crPct(c * 100, 0) : '-'}</span>; } },
                { key: 'risks', label: t('crInsRisks'), width: 80, align: 'right', sortValue: r => risks(r).length,
                  render: r => { const k = risks(r); return k.length ? <span title={k.join('\n')}><CrBadge tone="warning">{k.length}</CrBadge></span> : '-'; } },
            ], [t, cid, nav, guestMap, snaps, narrow]);

            const open = pick && recs.find(r => String(r.vmid) === pick);
            const g = open ? rowOf(open) : null;
            const mayConfig = !!(g && onOpenConfig && can && can('vm.config'));
            return (
                <CrPanel title={t('rightSizing')} className="cr-ins-panel" data-cr-ins-rs={read.state}
                    actions={(
                        <>
                            {read.busy && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                            {body && body.computed_at && (
                                <span className="cr-muted cr-ins-stamp" data-cr-ins-stamp="">
                                    {crFill(t('reportAsOf'), { time: crVmWhen(new Date(body.computed_at).getTime()) })}
                                    {body.refreshing ? ` · ${t('reportUpdating')}` : ''}
                                </span>
                            )}
                        </>
                    )}>
                    {read.state !== 'ok' && read.state !== 'loading' && (
                        <CrRpNote tone="error" id={`rs-${read.state}`} onRetry={onRetry}>{crFill(t('crInsReadFailed'), { what: t('rightSizing'), why: crRpWhy(read, t) })}</CrRpNote>
                    )}
                    {body && (
                        <div className="cr-ins-counts" data-cr-ins-counts="">
                            <span data-cr-ins-evaluated={evaluated}>{crFill(t('crInsEvaluated'), { n: evaluated })}</span>
                            <span data-cr-ins-nodata={noData}>{crFill(t('crInsNoDataN'), { n: noData, min: minS })}</span>
                            <span data-cr-ins-flagged={recs.length}>{crFill(t('crInsFlaggedN'), { n: recs.length })}</span>
                        </div>
                    )}
                    {body && recs.length === 0 && (
                        evaluated === 0
                            ? <CrRpNote tone="warning" id="rs-none-evaluated">{crFill(t('crInsNoneEvaluated'), { n: noData, min: minS })}</CrRpNote>
                            : <CrRpNote tone="info" id="rs-none-flagged">{crFill(noData ? t('crInsNoneFlaggedSome') : t('crInsNoneFlagged'), { n: evaluated, k: noData })}</CrRpNote>
                    )}
                    {(read.state === 'loading' || recs.length > 0) && (
                        <CrTable id="ins-rightsizing" columns={columns} rows={recs} rowKey={r => String(r.vmid)} ariaLabel={t('rightSizing')}
                            loading={read.state === 'loading'} showCount={false} rowHeight={30} maxHeight={420}
                            onRowClick={r => setPick(String(r.vmid))} selectedKey={pick}
                            toolbar={body ? <span className="cr-table-sub">{crFill(t('crInsWindowBasis'), { d: body.window_days, n: snaps ?? '-' })}</span> : null} />
                    )}
                    {body && <p className="cr-rp-caption">{t('crInsRsBasis')}</p>}
                    <CrSidePanel open={!!open} id="ins-rs" title={open ? (open.name || String(open.vmid)) : ''}
                        sub={open ? `${open.type === 'lxc' ? 'CT' : 'VM'} ${open.vmid} · ${open.node || '-'}` : ''}
                        onClose={() => setPick(null)} focusKey={pick}
                        footer={open ? (
                            <div className="cr-ins-sp-foot">
                                {mayConfig
                                    ? <CrButton variant="primary" icon={<Icons.Settings />} onClick={() => onOpenConfig(g)} data-cr-ins-config="">{t('crInsOpenConfig')}</CrButton>
                                    : <span className="cr-muted" data-cr-ins-noconfig="">{g ? t('crInsNeedsConfig') : t('crInsNotInInventory')}</span>}
                                <span className="cr-muted">{t('crInsNeverApplied')}</span>
                            </div>
                        ) : null}>
                        {open && (
                            <div className="cr-ins-sp" data-cr-ins-detail={String(open.vmid)}>
                                <dl className="cr-ins-kv">
                                    <dt>{t('crInsObserved')}</dt>
                                    <dd>{crFill(t('crInsObservedCpu'), { avg: crPct(open.cpu_avg, 1), p95: crPct(open.cpu_p95, 1), n: open.maxcpu ?? '-' })}</dd>
                                    <dt />
                                    <dd>{crFill(t('crInsObservedRam'), { avg: crPct(open.mem_avg, 1), max: crPct(open.mem_max, 1), gb: open.maxmem_gb ?? '-' })}</dd>
                                    <dt>{t('crInsWindow')}</dt>
                                    <dd>{crFill(t('crInsWindowBasis'), { d: body ? body.window_days : '-', n: snaps ?? '-' })}</dd>
                                    <dt>{t('crInsSamples')}</dt>
                                    <dd data-cr-ins-detail-cov="">{coverage(open) != null
                                        ? crFill(t('crInsSamplesCov'), { n: open.samples, pct: crPct(coverage(open) * 100, 0) })
                                        : String(open.samples ?? '-')}</dd>
                                </dl>
                                {(open.flags || []).map((f, i) => (
                                    <div key={i} className="cr-ins-flag" data-cr-ins-detail-flag={f.kind}>
                                        <CrBadge tone={CR_INS_FLAG[f.kind] || 'neutral'}>{crInsFlagLabel(f.kind, t)}</CrBadge>
                                        <span className="cr-mono">{f.detail}</span>
                                        {crInsSuggest(f, t) && <span>{crFill(t('crInsSuggested'), { what: crInsSuggest(f, t) })}</span>}
                                        {f.rationale && <span className="cr-muted">{t('crInsServerRule')}: {String(f.rationale).replace(/\u2014/g, '-')}</span>}
                                    </div>
                                ))}
                                {risks(open).length > 0 && (
                                    <ul className="cr-ins-risks" data-cr-ins-risks="">
                                        {risks(open).map((k, i) => <li key={i}>{k}</li>)}
                                    </ul>
                                )}
                                <p className="cr-muted">{t('crInsRsHow')}</p>
                            </div>
                        )}
                    </CrSidePanel>
                </CrPanel>
            );
        }

        // the scope and node pickers the two guest-list cards share
        function CrInsScope({ id, opts, setOpts, cluster, nodes, withNode }) {
            const { t } = useTranslation();
            return (
                <>
                    <select className="cr-select" value={opts.scope} aria-label={t('cluster')} data-cr-ins-scope={id}
                        onChange={e => setOpts(o => ({ ...o, scope: e.target.value, node: '' }))}>
                        <option value="this">{clusterLabel(cluster)}</option>
                        <option value="all">{t('crInsAllClusters')}</option>
                    </select>
                    {withNode && opts.scope === 'this' && (
                        <select className="cr-select" value={opts.node} aria-label={t('node')} data-cr-ins-node={id}
                            onChange={e => setOpts(o => ({ ...o, node: e.target.value }))}>
                            <option value="">{t('crInsAllNodes')}</option>
                            {nodes.map(n => <option key={n} value={n}>{n}</option>)}
                        </select>
                    )}
                </>
            );
        }

        function CrInsTalkers({ opts, setOpts, cluster, clusters, nav, narrow }) {
            const { t } = useTranslation();
            const lists = crInsLists(opts.scope, cluster, clusters, nav);
            const listRef = useRef(lists);
            listRef.current = lists;
            const sig = lists.map(x => `${x.c.id}:${crInsListId(x.list)}`).join('|');
            const data = useMemo(() => {
                const all = [];
                let unread = 0;
                const nodeSet = new Set();
                listRef.current.forEach(({ c, list }) => {
                    if (!Array.isArray(list)) { unread++; return; }
                    for (let i = 0; i < list.length; i++) {
                        const g = list[i];
                        if (!crRpGuest(g) || g.template || g.status !== 'running') continue;
                        if (g.node) nodeSet.add(g.node);
                        if (opts.node && g.node !== opts.node) continue;
                        all.push(crInsTalker(g, c));
                    }
                });
                const k = opts.metric;
                const top = all.filter(x => x[k] != null).sort((a, b) => b[k] - a[k]).slice(0, CR_INS_TOP).map((x, i) => ({ ...x, rank: i + 1 }));
                return { top, total: all.length, unknown: all.length - all.filter(x => x[k] != null).length, unread, nodes: [...nodeSet].sort() };
            }, [sig, opts.metric, opts.node]);
            const many = opts.scope === 'all';
            const metricLabel = {
                cpu: t('cpuPercent'), mem: t('memoryPercent'), disk: t('diskUsagePercent'),
                dio: t('crInsByDiskIo'), nio: t('crInsByNetIo'), dioRate: t('crInsByDiskAvg'), nioRate: t('crInsByNetAvg'),
            };
            const columns = useMemo(() => [
                { key: 'rank', label: '#', width: 34, align: 'right', mono: true, sortValue: x => x.rank, render: x => x.rank },
                { key: 'guest', label: t('crInsGuest'), flex: true, min: 150, sortValue: x => crRpName(x.g),
                  render: x => <CrRpGuestCell g={x.g} cid={x.c.id} nav={nav} /> },
                { key: 'cluster', label: t('cluster'), width: 100, hidden: !many, sortValue: x => clusterLabel(x.c), render: x => clusterLabel(x.c) },
                { key: 'node', label: t('node'), width: 86, hidden: narrow, sortValue: x => x.g.node || null, render: x => x.g.node || '-' },
                { key: 'cpu', label: t('cpu'), width: 100, sortValue: x => x.cpu, render: x => <CrMeter value={x.cpu} digits={1} /> },
                { key: 'mem', label: t('ram'), width: 100, sortValue: x => x.mem, render: x => <CrMeter value={x.mem} digits={1} /> },
                { key: 'disk', label: t('disk'), width: 96, hidden: narrow, sortValue: x => x.disk,
                  render: x => (x.disk != null ? <CrMeter value={x.disk} digits={1} tone={crStoreTone(x.disk)} />
                      : <span className="cr-muted" data-cr-ins-disk="unknown" title={t('crInsDiskUnknown')}>{t('crRpNotReported')}</span>) },
                { key: 'dio', label: t('crInsDiskIoTotal'), width: 112, align: 'right', mono: true, sortValue: x => x.dio, title: t('crInsTotalTitle'), render: x => crBytes(x.dio) },
                { key: 'dioRate', label: t('crInsDiskIoAvg'), width: 124, align: 'right', mono: true, sortValue: x => x.dioRate, title: t('crInsAvgTitle'), render: x => crRpRate(x.dioRate) },
                { key: 'nio', label: t('crInsNetIoTotal'), width: 112, align: 'right', mono: true, sortValue: x => x.nio, title: t('crInsTotalTitle'), render: x => crBytes(x.nio) },
                { key: 'nioRate', label: t('crInsNetIoAvg'), width: 124, align: 'right', mono: true, sortValue: x => x.nioRate, title: t('crInsAvgTitle'), render: x => crRpRate(x.nioRate) },
                { key: 'up', label: t('uptime'), width: 90, align: 'right', mono: true, hidden: true, sortValue: x => x.up, render: x => (x.up ? crUptime(x.up) : '-') },
            ], [t, nav, many, narrow]);
            const thisList = lists.length === 1 ? lists[0].list : null;
            const empty = !many && lists[0] && lists[0].offline ? t('crRpNotConnected')
                : !many && !Array.isArray(thisList) ? t('crRpGuestsUnread') : opts.node ? t('crInsNoneOnNode') : t('crNoRunningGuests');
            return (
                <CrPanel title={t('topTalkers')} className="cr-ins-panel" data-cr-ins-tt={opts.metric}>
                    <CrTable key={`${opts.metric}|${many}`} id="ins-talkers" columns={columns} rows={data.top} rowKey={x => `${x.c.id}:${x.g.vmid}`}
                        ariaLabel={t('topTalkers')} initialSort={{ key: 'rank', dir: 'asc' }} showCount={false} rowHeight={28}
                        emptyText={empty} onRowClick={x => nav && nav.openGuest && nav.openGuest(x.c.id, x.g)}
                        toolbar={(
                            <>
                                <select className="cr-select" value={opts.metric} aria-label={t('sortBy')} data-cr-ins-metric=""
                                    onChange={e => setOpts(o => ({ ...o, metric: e.target.value }))}>
                                    {CR_INS_METRICS.map(m => <option key={m} value={m}>{metricLabel[m]}</option>)}
                                </select>
                                <CrInsScope id="tt" opts={opts} setOpts={setOpts} cluster={cluster} nodes={data.nodes} withNode />
                                <span className="cr-table-sub" data-cr-ins-ttof="">{crFill(t('crInsTopOf'), { n: data.top.length, total: data.total })}</span>
                            </>
                        )} />
                    {data.unread > 0 && many && <p className="cr-rp-caption" data-cr-ins-unread="">{crFill(t('crInsListsUnread'), { n: data.unread })}</p>}
                    {data.unknown > 0 && <p className="cr-rp-caption">{crFill(t('crInsUnknownLeftOut'), { n: data.unknown })}</p>}
                    <p className="cr-rp-caption" data-cr-ins-tthint="">{t('topTalkersHint')} {t('crInsAvgHint')}</p>
                </CrPanel>
            );
        }

        // tag (several per guest, each counted) or pool groups of the guest rows, with their members
        const CR_INS_NONE = '(none)';
        function crInsGroups(lists, by, runningOnly) {
            const groups = new Map();
            let guests = 0, tagged = 0, unread = 0;
            lists.forEach(({ c, list }) => {
                if (!Array.isArray(list)) { unread++; return; }
                for (let i = 0; i < list.length; i++) {
                    const g = list[i];
                    if (!crRpGuest(g)) continue;
                    const run = g.status === 'running';
                    if (runningOnly && !run) continue;
                    guests++;
                    // the group of the guests without a pool or a tag: Proxmox allows no "(" in either name
                    let keys;
                    if (by === 'pool') keys = [g.pool || CR_INS_NONE];
                    else {
                        keys = String(g.tags || '').replace(/,/g, ';').split(';').map(s => s.trim()).filter(Boolean);
                        if (keys.length) tagged++; else keys = [CR_INS_NONE];
                    }
                    keys.forEach(k => {
                        let x = groups.get(k);
                        if (!x) {
                            x = { key: k, none: k === CR_INS_NONE, members: [], count: 0, running: 0, vcpu: 0, cores: 0, memUsed: 0, memRun: 0, memAlloc: 0, diskAlloc: 0, nio: 0, clusters: new Set() };
                            groups.set(k, x);
                        }
                        x.members.push({ g, c });
                        x.count++;
                        x.clusters.add(c.id);
                        x.vcpu += crRpNum(g.maxcpu) ? g.maxcpu : 0;
                        x.memAlloc += crRpNum(g.maxmem) ? g.maxmem : 0;
                        x.diskAlloc += crRpNum(g.maxdisk) ? g.maxdisk : 0;
                        if (crRpNum(g.netin)) x.nio += g.netin;
                        if (crRpNum(g.netout)) x.nio += g.netout;
                        if (run) {
                            x.running++;
                            if (crRpNum(g.cpu) && crRpNum(g.maxcpu)) x.cores += g.cpu * g.maxcpu;
                            if (crRpNum(g.mem)) x.memUsed += g.mem;
                            if (crRpNum(g.maxmem)) x.memRun += g.maxmem;
                        }
                    });
                }
            });
            const rows = [...groups.values()].map(x => ({ ...x, memPct: x.memRun > 0 ? x.memUsed / x.memRun * 100 : null }));
            return { rows, guests, tagged, unread };
        }

        function CrInsRollups({ opts, setOpts, cluster, clusters, nav, narrow }) {
            const { t } = useTranslation();
            const groupName = (x) => (x.none ? t(opts.by === 'pool' ? 'crInsNoPool' : 'crInsUntagged') : x.key);
            const [open, setOpen] = useState({});
            const lists = crInsLists(opts.scope, cluster, clusters, nav);
            const listRef = useRef(lists);
            listRef.current = lists;
            const sig = lists.map(x => `${x.c.id}:${crInsListId(x.list)}`).join('|');
            const data = useMemo(() => crInsGroups(listRef.current, opts.by, opts.running), [sig, opts.by, opts.running]);
            const many = opts.scope === 'all';
            useEffect(() => { setOpen({}); }, [opts.by, opts.running, opts.scope]);
            const toggle = (k) => setOpen(o => ({ ...o, [k]: !o[k] }));
            const columns = useMemo(() => [
                { key: 'exp', label: '', menuLabel: t('crInsMembers'), width: 30, resizable: false, sortable: false,
                  render: x => (
                      <button type="button" className="cr-icon-btn cr-ins-exp" aria-expanded={!!open[x.key]} data-cr-ins-expand={x.key}
                          aria-label={crFill(t('crInsShowMembers'), { k: groupName(x) })} onClick={e => { e.stopPropagation(); toggle(x.key); }}>
                          <span className="cr-ico" aria-hidden="true">{open[x.key] ? <Icons.ChevronDown /> : <Icons.ChevronRight />}</span>
                      </button>
                  ) },
                { key: 'key', label: opts.by === 'pool' ? t('pool') : t('tag'), flex: true, min: 130, sortValue: x => x.key, text: groupName,
                  render: x => <span className={x.none ? 'cr-muted' : 'cr-strong'} data-cr-ins-group={x.key}>{groupName(x)}</span> },
                { key: 'count', label: t('guests'), width: 78, align: 'right', mono: true, sortValue: x => x.count, render: x => x.count },
                { key: 'running', label: t('running'), width: 84, align: 'right', mono: true, sortValue: x => x.running, render: x => x.running },
                { key: 'vcpu', label: t('crInsVcpu'), width: 74, hidden: narrow, align: 'right', mono: true, sortValue: x => x.vcpu, title: t('crInsVcpuTitle'), render: x => x.vcpu },
                { key: 'cores', label: t('crInsCoresNow'), width: 108, align: 'right', mono: true, sortValue: x => x.cores, title: t('crInsCoresTitle'),
                  render: x => (x.running ? x.cores.toFixed(1) : '-') },
                { key: 'mem', label: t('crInsRamRunning'), width: 156, sortValue: x => x.memPct, title: t('crInsRamRunningTitle'),
                  render: x => <CrMeter value={x.memPct} digits={0} title={x.memRun ? crFill(t('crUsedOf'), { used: crBytes(x.memUsed), total: crBytes(x.memRun) }) : undefined} /> },
                { key: 'memAlloc', label: t('crInsRamAlloc'), width: 116, align: 'right', mono: true, sortValue: x => x.memAlloc, render: x => crBytes(x.memAlloc) },
                { key: 'diskAlloc', label: t('crInsDiskAlloc'), width: 116, hidden: narrow, align: 'right', mono: true, sortValue: x => x.diskAlloc, render: x => crBytes(x.diskAlloc) },
                { key: 'nio', label: t('crInsNetIoTotal'), width: 116, align: 'right', mono: true, sortValue: x => x.nio, title: t('crInsTotalTitle'), render: x => crBytes(x.nio) },
            ], [t, open, opts.by, narrow]);
            const memberCols = useMemo(() => [
                { key: 'guest', label: t('crInsGuest'), flex: true, min: 150, sortValue: m => crRpName(m.g), render: m => <CrRpGuestCell g={m.g} cid={m.c.id} nav={nav} /> },
                { key: 'cluster', label: t('cluster'), width: 100, hidden: !many, sortValue: m => clusterLabel(m.c), render: m => clusterLabel(m.c) },
                { key: 'node', label: t('node'), width: 86, sortValue: m => m.g.node || null, render: m => m.g.node || '-' },
                { key: 'status', label: t('status'), width: 90, sortValue: m => m.g.status,
                  render: m => <CrBadge tone={m.g.status === 'running' ? 'success' : 'neutral'}>{m.g.status === 'running' ? t('running') : m.g.status === 'stopped' ? t('stopped') : String(m.g.status || '-')}</CrBadge> },
                { key: 'cpu', label: t('cpu'), width: 96, sortValue: m => (m.g.status === 'running' && crRpNum(m.g.cpu) ? m.g.cpu * 100 : null),
                  render: m => (m.g.status === 'running' ? <CrMeter value={crRpNum(m.g.cpu) ? m.g.cpu * 100 : null} digits={1} /> : '-') },
                { key: 'ram', label: t('ram'), width: 96, sortValue: m => (m.g.status === 'running' && m.g.maxmem > 0 ? m.g.mem / m.g.maxmem * 100 : null),
                  render: m => (m.g.status === 'running' && m.g.maxmem > 0 ? <CrMeter value={m.g.mem / m.g.maxmem * 100} digits={1} /> : '-') },
            ], [t, nav, many]);
            const lone = lists.length === 1 ? lists[0].list : null;
            const empty = !many && lists[0] && lists[0].offline ? t('crRpNotConnected')
                : !many && !Array.isArray(lone) ? t('crRpGuestsUnread') : opts.running ? t('crNoRunningGuests') : t('crInsNoGuests');
            return (
                <CrPanel title={t('rollups')} className="cr-ins-panel" data-cr-ins-ru={opts.by}>
                    <CrTable id="ins-rollups" columns={columns} rows={data.rows} rowKey={x => x.key} ariaLabel={t('rollups')}
                        initialSort={{ key: 'count', dir: 'desc' }} rowHeight={28} maxHeight={520} emptyText={empty}
                        searchable searchPlaceholder={opts.by === 'pool' ? t('pool') : t('tag')}
                        expanded={open} onRowClick={x => toggle(x.key)}
                        renderExpanded={x => (
                            <div className="cr-ins-members" data-cr-ins-members={x.key}>
                                <CrTable id="ins-rollup-members" columns={memberCols} rows={x.members} rowKey={m => `${m.c.id}:${m.g.vmid}`}
                                    ariaLabel={crFill(t('crInsMembersOf'), { k: groupName(x) })} initialSort={{ key: 'guest', dir: 'asc' }}
                                    rowHeight={26} maxHeight={240} columnMenu={false}
                                    onRowClick={m => nav && nav.openGuest && nav.openGuest(m.c.id, m.g)} />
                            </div>
                        )}
                        toolbar={(
                            <>
                                <div className="cr-seg" role="group" aria-label={t('crInsGroupBy')}>
                                    {[['tag', t('byTag')], ['pool', t('byPool')]].map(([id, label]) => (
                                        <button key={id} type="button" className={opts.by === id ? 'active' : ''} aria-pressed={opts.by === id}
                                            data-cr-ins-by={id} onClick={() => setOpts(o => ({ ...o, by: id }))}>{label}</button>
                                    ))}
                                </div>
                                <label className="cr-switch">
                                    <input type="checkbox" checked={opts.running} data-cr-ins-running=""
                                        onChange={e => setOpts(o => ({ ...o, running: e.target.checked }))} />
                                    <span>{t('crInsRunningOnly')}</span>
                                </label>
                                <CrInsScope id="ru" opts={opts} setOpts={setOpts} cluster={cluster} nodes={[]} />
                            </>
                        )} />
                    {opts.by === 'tag' && data.guests > 0 && data.tagged === 0 && (
                        <CrRpNote tone="info" id="ru-untagged">{t('crInsNoTags')}</CrRpNote>
                    )}
                    {data.unread > 0 && many && <p className="cr-rp-caption">{crFill(t('crInsListsUnread'), { n: data.unread })}</p>}
                    <p className="cr-rp-caption" data-cr-ins-ruhint="">{crFill(t('crInsRollupBasis'), { n: data.guests })}</p>
                </CrPanel>
            );
        }
