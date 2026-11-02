        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): the performance metrics of a node and a guest - LW Nov 2026
        // The Performance panel of the node's and the guest's Monitor tab: the figures above the
        // charts, the time of the newest sample and the gaps under them, three groups a user opens
        // (pressure stall, the period before, the interface counters of a node) and what the loaded
        // range says against a threshold PegaProx already has. Every figure comes from a read the
        // view makes anyway or from one the user asks for; what no source delivers is not drawn.
        // ═══════════════════════════════════════════════════════════

        const crPfNum = (v) => typeof v === 'number' && Number.isFinite(v);
        // the pressure stall series of PVE 9: [id, some, full]
        const CR_PF_PSI = [['cpu', 'pressurecpusome', 'pressurecpufull'], ['memory', 'pressurememorysome', 'pressurememoryfull'],
                           ['io', 'pressureiosome', 'pressureiofull']];
        // what the XCP-ng adapter fills with a constant 0 (xcpng.py get_node_rrddata): left out, not drawn
        const CR_PF_XCP_DROP = ['iowait', 'swap', 'rootfs', 'loadavg', 'net_in', 'net_out'];
        // the names of the interfaces of guests and of the firewall bridges on a Proxmox VE node
        const CR_PF_VIRT_IF = /^(?:tap|veth|fwbr|fwpr|fwln)\d/;
        // the year before a year is never stored (retention is 365 days at most, metrics.py)
        const CR_PF_MAX_KEEP = 365 * 86400;

        // the median distance between two slots, in seconds
        function crPfStep(ts) {
            const d = [];
            for (let i = 1; i < (ts || []).length; i++) if (ts[i] > ts[i - 1]) d.push(ts[i] - ts[i - 1]);
            d.sort((a, b) => a - b);
            return d.length ? d[Math.floor(d.length / 2)] : null;
        }

        // What the view draws from a metrics answer. null when nothing came; {error} for an answer that
        // says it failed (the node route answers HTTP 200 with it); the XCP-ng wrapper unwrapped, with
        // the series its adapter fills with zeros left out; a stretch without any slot (the stored
        // snapshots have no row while PegaProx did not collect) gets one empty slot, so the line breaks
        function crPfPrep(answer, kind) {
            if (answer == null) return answer;
            if (typeof answer !== 'object') return { error: '' };
            let a = answer;
            if (a.success === true && a.data && typeof a.data === 'object') a = a.data;
            if (!a.metrics || !Array.isArray(a.timestamps)) return { error: typeof a.error === 'string' ? a.error : '' };
            const ts = a.timestamps;
            const keys = Object.keys(a.metrics).filter(k => Array.isArray(a.metrics[k]) && a.metrics[k].length === ts.length
                && !(kind === 'xcpng' && CR_PF_XCP_DROP.includes(k)));
            const step = crPfStep(ts);
            const out = { ...a, metrics: {}, timestamps: [], step, holes: 0, xcp: kind === 'xcpng' };
            keys.forEach(k => { out.metrics[k] = []; });
            for (let i = 0; i < ts.length; i++) {
                const prev = out.timestamps.length ? out.timestamps[out.timestamps.length - 1] : null;
                if (prev != null && step && ts[i] - prev > Math.max(2.5 * step, 2 * HISTORY_STEP)) {
                    out.timestamps.push(Math.round((prev + ts[i]) / 2));
                    keys.forEach(k => out.metrics[k].push(null));
                    out.holes++;
                }
                out.timestamps.push(ts[i]);
                keys.forEach(k => { const v = a.metrics[k][i]; out.metrics[k].push(crPfNum(v) ? v : null); });
            }
            return out;
        }

        // last, average, peak and low of one series; times in seconds
        function crPfStats(ts, vals) {
            let n = 0, sum = 0, max = null, maxAt = null, min = null, last = null, lastAt = null;
            (vals || []).forEach((v, i) => {
                if (!crPfNum(v)) return;
                n++; sum += v;
                if (max == null || v > max) { max = v; maxAt = ts[i]; }
                if (min == null || v < min) min = v;
                last = v; lastAt = ts[i];
            });
            return n ? { n, avg: sum / n, max, maxAt, min, last, lastAt } : null;
        }

        // the newest sample, its age, the gaps and the step of the series the panel draws
        function crPfQuality(p, keys, nowSec) {
            if (!p || !p.metrics || !Array.isArray(p.timestamps) || !p.timestamps.length) return null;
            const ts = p.timestamps;
            const series = keys.map(k => p.metrics[k]).filter(Array.isArray);
            const has = ts.map((_, i) => series.some(s => crPfNum(s[i])));
            const firstI = has.indexOf(true), lastI = has.lastIndexOf(true);
            if (lastI < 0) return null;
            const step = p.step || crPfStep(ts);
            // a stretch runs from the slot after the sample before it (or the start of the range) to
            // the sample after it; the empty slots after the newest sample are counted apart
            const stretches = [];
            for (let i = 0; i <= lastI; i++) {
                if (has[i]) continue;
                let j = i;
                while (j + 1 <= lastI && !has[j + 1]) j++;
                const lead = i === 0, after = ts[j + 1];
                const from = lead ? ts[0] : ts[i - 1] + (step || 0);
                stretches.push({ from, secs: Math.max(step || 0, after - from), lead });
                i = j;
            }
            const longest = stretches.filter(x => !x.lead).reduce((m, x) => (!m || x.secs > m.secs ? x : m), null);
            const lastAt = ts[lastI];
            const age = Math.max(0, nowSec - lastAt);
            return { lastAt, age, step, stale: age > Math.max(3 * (step || 60), 300), stretches, longest,
                     trailing: ts.length - 1 - lastI, slots: ts.length, firstAt: ts[firstI], holes: p.holes || 0 };
        }

        // the runs of samples a test matches: how many, the longest in seconds and where it began
        function crPfRuns(ts, vals, test, step) {
            let n = 0, m = 0, run = 0, runFrom = null, best = { secs: 0, from: null };
            (vals || []).forEach((v, i) => {
                if (!crPfNum(v)) { run = 0; return; }
                m++;
                if (test(v)) {
                    n++;
                    if (run === 0) runFrom = ts[i];
                    run++;
                    const secs = run * (step || 0);
                    if (secs > best.secs) best = { secs, from: runFrom };
                } else run = 0;
            });
            return { n, m, longest: best };
        }

        const CR_PF_OPS = { '>': (v, x) => v > x, '<': (v, x) => v < x, '>=': (v, x) => v >= x, '<=': (v, x) => v <= x };
        // the enabled alert rules that watch this one node or guest for one metric (a cluster rule
        // watches the cluster's average, background/alerts.py, so it is not this object's line)
        function crPfObjectRules(store, type, id, metric) {
            if (!store || store.state !== 'ok') return [];
            return (store.rules || []).filter(r => r && r.enabled !== false && r.metric === metric && r.target_type === type
                && String(r.target_id) === String(id) && CR_PF_OPS[r.operator || '>'] && crPfNum(Number(r.threshold)));
        }

        // the alert rules of a cluster, read once per cluster and kept 5 minutes (one GET, never per node)
        const crPfRuleStore = {};
        function crPfUseRules(authFetch, cid) {
            const { user } = useAuth();
            crSessionFor(user);
            const [, bump] = useState(0);
            useEffect(() => {
                if (!cid) return undefined;
                const e = crPfRuleStore[cid] || (crPfRuleStore[cid] = { state: 'idle', subs: new Set() });
                const fn = () => bump(n => n + 1);
                e.subs.add(fn);
                const fresh = (e.state === 'ok' || e.state === 'forbidden') && Date.now() - e.at < 300000;
                if (!fresh && e.state !== 'loading') {
                    e.state = 'loading';
                    crVmRead(authFetch, `${API_URL}/clusters/${cid}/alerts`)
                        .catch(() => ({ state: 'unreachable', at: Date.now() }))
                        .then(r => {
                            const list = r.state === 'ok' && Array.isArray(r.body.alerts) ? r.body.alerts : null;
                            Object.assign(e, list ? { state: 'ok', rules: list } : { state: r.state === 'ok' ? 'error' : r.state, code: r.code, msg: r.msg },
                                          { at: r.at || Date.now() });
                            e.subs.forEach(f => f());
                        });
                }
                return () => { e.subs.delete(fn); };
            }, [cid]);
            return (cid && crPfRuleStore[cid]) || { state: 'idle' };
        }

        // a token of the theme as hex, for the canvas
        function crPfColor(name, fallback) {
            try {
                const v = getComputedStyle(document.body).getPropertyValue(name).trim();
                return /^#[0-9a-f]{6}$/i.test(v) ? v : fallback;
            } catch (_) { return fallback; }
        }
        const crPfTone = (sev) => (sev === 'critical' ? 'error' : sev === 'warning' ? 'warning' : sev === 'info' ? 'info' : 'neutral');

        // the dashed lines of a CPU or memory chart: the alert rules of the object when there are any,
        // else the display scale of this view (80 / 90, the colour of its meters). scale(): % to the unit
        function crPfLines(rules, t, scale) {
            const conv = scale || (v => v);
            const col = { warning: crPfColor('--cr-warning', '#e5b83d'), error: crPfColor('--cr-error', '#f38181'),
                          info: crPfColor('--cr-info', '#55b6d0'), neutral: crPfColor('--cr-text-muted', '#93a7b2') };
            if (rules.length) {
                return {
                    kind: 'rule',
                    lines: rules.map(r => ({ value: conv(Number(r.threshold)), color: col[crPfTone(r.severity)],
                                             label: `${r.operator || '>'} ${Number(r.threshold)}%` })),
                    caption: crFill(t('crPfCapRule'), { rules: rules.map(r => `${r.name || r.id} (${r.operator || '>'} ${Number(r.threshold)}%${r.severity ? ', ' + r.severity : ''})`).join('; ') }),
                };
            }
            return {
                kind: 'scale',
                lines: [{ value: conv(CR_WARN), color: col.warning, label: `${CR_WARN}%` }, { value: conv(CR_CRIT), color: col.error, label: `${CR_CRIT}%` }],
                caption: crFill(t('crPfCapScale'), { warn: CR_WARN, crit: CR_CRIT }),
            };
        }

        function crPfAgo(secs, t) {
            if (!crPfNum(secs)) return '';
            if (secs < 90) return crFill(t('crPfAgoS'), { n: Math.round(secs) });
            if (secs < 90 * 60) return crFill(t('crPfAgoM'), { n: Math.round(secs / 60) });
            if (secs < 48 * 3600) return crFill(t('crPfAgoH'), { n: Math.round(secs / 3600) });
            return crFill(t('crPfAgoD'), { n: Math.round(secs / 86400) });
        }
        function crPfDur(secs, t) {
            if (!crPfNum(secs) || secs <= 0) return '';
            if (secs < 90 * 60) return crFill(t('crPfMin'), { n: Math.max(1, Math.round(secs / 60)) });
            if (secs < 48 * 3600) return crFill(t('crPfHours'), { n: Math.round(secs / 360) / 10 });
            return crFill(t('crPfDays'), { n: Math.round(secs / 8640) / 10 });
        }
        // a preset as its button says it (1h, 24h, ...)
        const CR_PF_RANGE_KEYS = { hour: 'crRange1h', day: 'crRange24h', week: 'crRange7d', month: 'crRange30d', year: 'crRange1y' };
        const crPfRange = (range, t) => t(CR_PF_RANGE_KEYS[range] || 'crRange1h');
        // a sample time: the clock today, with its day otherwise
        const crPfAt = (sec) => (crPfNum(sec) ? crVmWhen(sec * 1000) : '');
        const crPfRate = (v) => (crPfNum(v) ? `${formatBytes(v)}/s` : '-');
        // what one step of the answer is, in words
        function crPfStepText(step, t) {
            if (!crPfNum(step)) return '';
            return step < 3600 ? crFill(t('crPfMin'), { n: Math.round(step / 60) }) : step < 86400 ? crFill(t('crPfHours'), { n: Math.round(step / 360) / 10 })
                : crFill(t('crPfDays'), { n: Math.round(step / 8640) / 10 });
        }

        // one series of the period before laid under this one: each slot takes the sample of the
        // period before that lies within half a step of it (moved forward by the length of the range)
        function crPfAlign(cur, prev, shift, key) {
            const out = [];
            const pts = [];
            (prev.timestamps || []).forEach((x, i) => { const v = prev.metrics[key] && prev.metrics[key][i]; if (crPfNum(v)) pts.push([x + shift, v]); });
            const half = (crPfStep(prev.timestamps) || HISTORY_STEP) / 2;
            let j = 0;
            (cur.timestamps || []).forEach(x => {
                while (j + 1 < pts.length && Math.abs(pts[j + 1][0] - x) <= Math.abs(pts[j][0] - x)) j++;
                out.push(pts.length && Math.abs(pts[j][0] - x) <= half ? pts[j][1] : null);
            });
            return out;
        }

        const crPfCompact = (n) => {
            if (!crPfNum(n)) return '-';
            try { return new Intl.NumberFormat(crLocale(), { notation: 'compact', maximumFractionDigits: 1 }).format(n); } catch (_) { return String(n); }
        };
        const CR_PF_NIC_KEYS = ['rx_bytes', 'rx_packets', 'rx_errs', 'rx_drop', 'tx_bytes', 'tx_packets', 'tx_errs', 'tx_drop'];
        // what one interface changed by between two reads: null without the read before, 'reset' when a
        // counter went down (the node rebooted, the counter wrapped)
        function crPfNicDelta(prev, cur) {
            if (!prev) return null;
            const out = {};
            CR_PF_NIC_KEYS.forEach(k => {
                const a = prev[k], b = cur[k];
                out[k] = crPfNum(a) && crPfNum(b) ? (b < a ? 'reset' : b - a) : null;
            });
            return out;
        }

        // a value now with its basis, every number from one read the view holds
        function CrPfTile({ tile }) {
            const { id, label, value, unit, meter, tone, sub, basis, title, state } = tile;
            return (
                <div className={`cr-stat cr-pf-tile${tone && tone !== 'success' && tone !== 'neutral' ? ' cr-stat-' + tone : ''}`}
                    data-cr-pf-kpi={id} data-cr-pf-state={state || 'ok'} title={title}>
                    <span className="cr-stat-label">{label}</span>
                    <span className="cr-stat-value">{value}{unit && <span className="cr-stat-unit">{unit}</span>}</span>
                    {crPfNum(meter) && (
                        <span className={`cr-stat-bar cr-tone-${tone || crTone(meter)}`} aria-hidden="true">
                            <span style={{ width: `${Math.min(100, Math.max(0, meter))}%` }} />
                        </span>
                    )}
                    {sub && <span className="cr-stat-sub">{sub}</span>}
                    {basis && <span className="cr-pf-basis" data-cr-pf-basis="">{basis}</span>}
                </div>
            );
        }

        function CrPfKpis({ tiles, label }) {
            if (!tiles.length) return null;
            return (
                <section className="cr-stat-row cr-pf-kpis" aria-label={label} data-cr-pf-kpis="">
                    {tiles.map(x => <CrPfTile key={x.id} tile={x} />)}
                </section>
            );
        }

        // the newest sample and its age, the step, the gaps; under the charts
        function CrPfQuality({ q, range, fromHistory, xcp, t }) {
            if (!q) return null;
            const lead = q.stretches.filter(s => s.lead);
            const inner = q.stretches.filter(s => !s.lead);
            return (
                <div className="cr-pf-quality" data-cr-pf-quality="" data-cr-pf-stale={q.stale ? '1' : '0'} data-cr-pf-gaps={inner.length}>
                    <p className="cr-pf-qline">
                        <span data-cr-pf-last="">{crFill(t('crPfNewest'), { time: crPfAt(q.lastAt), age: crPfAgo(q.age, t) })}</span>
                        {q.stale && <CrBadge tone="warning">{t('crPfStale')}</CrBadge>}
                        <span className="cr-muted" data-cr-pf-step="">
                            {crFill(t('crPfSourceRrd'), { step: crPfStepText(q.step, t), n: q.slots, range })}
                        </span>
                    </p>
                    {q.stale && <p className="cr-pf-qline cr-tone-text cr-tone-warning" data-cr-pf-stale-why="">{crFill(t('crPfStaleWhy'), { age: crPfAgo(q.age, t) })}</p>}
                    <p className="cr-pf-qline cr-muted" data-cr-pf-gaptext="">
                        {inner.length === 0 ? t('crPfNoGaps')
                            : crFill(t(inner.length === 1 ? 'crPfGapsOne' : 'crPfGaps'), { n: inner.length, long: crPfDur(q.longest.secs, t), from: crPfAt(q.longest.from) })}
                        {lead.length > 0 && <> {crFill(t('crPfLead'), { time: crPfAt(q.firstAt) })}</>}
                        {q.trailing > 0 && <> {crFill(t(q.trailing === 1 ? 'crPfTrailOne' : 'crPfTrail'), { n: q.trailing })}</>}
                        {q.holes > 0 && <> {crFill(t('crPfHoles'), { n: q.holes })}</>}
                    </p>
                    {fromHistory && <p className="cr-pf-qline cr-muted" data-cr-pf-history="">{t('crPfZoomHistory')}</p>}
                    {xcp && <p className="cr-pf-qline cr-tone-text cr-tone-warning" data-cr-pf-xcp="">{t('crPfXcp')}</p>}
                    <p className="cr-pf-qline cr-muted">{t('crPfTimesHere')}</p>
                </div>
            );
        }

        // --- the groups a user opens ----------------------------------------------

        function CrPfPsi({ prepped, zoom, colors, t, base }) {
            const m = (prepped && prepped.metrics) || {};
            const present = CR_PF_PSI.filter(([, some, full]) => crHasSamples(m[some]) || crHasSamples(m[full]));
            if (!present.length) {
                return <p className="cr-pf-note" data-cr-pf-psi-none="">{t('crPfPsiNone')}</p>;
            }
            const names = { cpu: t('crPfPsiCpu'), memory: t('crPfPsiMem'), io: t('crPfPsiIo') };
            return (
                <>
                    <p className="cr-pf-note">{t('crPfPsiAbout')}</p>
                    <div className="cr-chart-grid">
                        {present.map(([id, some, full]) => {
                            const src = zoom ? zoom.source(some, full) : prepped;
                            return (
                                <CrChart key={id} id={`psi-${id}`} label={names[id]} timestamps={src.timestamps}
                                    unit="%" formatValue={v => v.toFixed(2)} toggles {...base}
                                    datasets={[{ label: t('crPfSome'), data: src.metrics && src.metrics[some], color: colors.net },
                                               { label: t('crPfFull'), data: src.metrics && src.metrics[full], color: colors.cpu }]} />
                            );
                        })}
                    </div>
                </>
            );
        }

        function CrPfCompare({ range, histUrl, objKey, authFetch, colors, t, base }) {
            const span = CHART_PRESET_SECONDS[range] || 3600;
            const [st, setSt] = useState({ state: 'idle' });
            const seq = useRef(0);
            const busy = useRef(false);
            // another range or object drops what was read for the one before
            useEffect(() => { seq.current++; busy.current = false; setSt({ state: 'idle' }); }, [range, objKey]);
            const never = 2 * span > CR_PF_MAX_KEEP;
            const read = () => {
                if (busy.current || never) return;
                busy.current = true;
                const my = ++seq.current;
                const now = Math.floor(Date.now() / 1000);
                const want = { cur: [now - span, now], prev: [now - 2 * span, now - span] };
                setSt({ state: 'loading' });
                Promise.all([crVmRead(authFetch, histUrl(...want.cur)), crVmRead(authFetch, histUrl(...want.prev))])
                    .catch(() => [{ state: 'unreachable' }, { state: 'unreachable' }])
                    .then(([c, p]) => {
                        if (my !== seq.current) return;
                        busy.current = false;
                        const bad = [c, p].find(x => x.state !== 'ok' || !x.body || !x.body.metrics);
                        if (bad) { setSt({ state: 'error', read: bad }); return; }
                        setSt({ state: 'ok', cur: crPfPrep(c.body), prev: crPfPrep(p.body), want, at: Date.now(),
                                prevFrom: p.body.from, curFrom: c.body.from });
                    });
            };
            const rangeLabel = crPfRange(range, t);
            let body = null;
            if (st.state === 'loading') body = <p className="cr-pf-note" role="status"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</p>;
            else if (st.state === 'error') body = <p className="cr-pf-note cr-tone-text cr-tone-error" role="alert" data-cr-pf-cmp-error="">{crFill(t('crPfCmpFailed'), { why: crRpWhy(st.read, t) })}</p>;
            else if (st.state === 'ok') {
                const { cur, prev, want } = st;
                const prevStats = crPfStats(prev.timestamps, prev.metrics.cpu) || crPfStats(prev.timestamps, prev.metrics.memory);
                const cut = crPfNum(st.prevFrom) && st.prevFrom > want.prev[0] + 2 * HISTORY_STEP;
                const notStored = !prevStats;
                const lines = ['cpu', 'memory'].map(k => {
                    const a = crPfStats(cur.timestamps, cur.metrics[k]), b = crPfStats(prev.timestamps, prev.metrics[k]);
                    return { k, a, b };
                });
                body = (
                    <>
                        <p className="cr-pf-note" data-cr-pf-cmp-basis="">{crFill(t('crPfCmpBasis'), { range: rangeLabel })}</p>
                        {notStored ? (
                            <p className="cr-pf-note cr-tone-text cr-tone-warning" data-cr-pf-cmp-none="">{crFill(t('crPfCmpNotStored'), { range: rangeLabel })}</p>
                        ) : cut ? (
                            <p className="cr-pf-note cr-tone-text cr-tone-warning" data-cr-pf-cmp-cut="">{crFill(t('crPfCmpCut'), { time: crPfAt(st.prevFrom) })}</p>
                        ) : null}
                        <ul className="cr-pf-cmp-avgs">
                            {lines.map(({ k, a, b }) => (
                                <li key={k} data-cr-pf-cmp-avg={k}>
                                    {crFill(t('crPfCmpAvg'), { what: k === 'cpu' ? t('cpu') : t('memory'), now: a ? crPct(a.avg, 1) : '-', before: b ? crPct(b.avg, 1) : '-',
                                                               n: a ? a.n : 0, m: b ? b.n : 0 })}
                                </li>
                            ))}
                        </ul>
                        <div className="cr-chart-grid">
                            {['cpu', 'memory'].map(k => (
                                <CrChart key={k} id={`cmp-${k}`} label={k === 'cpu' ? t('cpu') : t('memory')} timestamps={cur.timestamps}
                                    unit="%" yMin={0} yMax={100} formatValue={v => v.toFixed(1)} toggles {...base}
                                    none={t('crPfCmpNoSamples')}
                                    datasets={[{ label: t('crPfThisPeriod'), data: cur.metrics[k], color: k === 'cpu' ? colors.cpu : colors.ram },
                                               { label: crFill(t('crPfPrevPeriod'), { range: rangeLabel }), data: crPfAlign(cur, prev, span, k),
                                                 color: crPfColor('--cr-text-muted', '#93a7b2'), dash: [4, 3], fill: false }]} />
                            ))}
                        </div>
                    </>
                );
            }
            return (
                <div className="cr-pf-group-body" data-cr-pf-cmp={st.state}>
                    <p className="cr-pf-note">{t('crPfCmpAbout')}</p>
                    <div className="cr-pf-acts">
                        <CrButton icon={<Icons.BarChart />} onClick={read} disabled={st.state === 'loading' || never} data-cr-pf-cmp-read=""
                            aria-describedby={never ? 'cr-pf-cmp-never' : undefined}>
                            {st.state === 'ok' ? t('crPfCmpAgain') : crFill(t('crPfCmpRead'), { range: rangeLabel })}
                        </CrButton>
                        {never && <span id="cr-pf-cmp-never" className="cr-muted" data-cr-pf-cmp-never="">{t('crPfCmpNever')}</span>}
                        {!never && 2 * span > 30 * 86400 && <span className="cr-muted" data-cr-pf-cmp-keep="">{crFill(t('crPfCmpKeep'), { days: Math.round(2 * span / 86400) })}</span>}
                    </div>
                    {body}
                </div>
            );
        }

        // the counters of every interface since the node booted, over SSH, on a click only
        function CrPfNics({ url, authFetch, t, xcp }) {
            const [st, setSt] = useState({ state: 'idle' });
            const [all, setAll] = useState(false);
            const busy = useRef(false);
            const seq = useRef(0);
            useEffect(() => { seq.current++; busy.current = false; setSt({ state: 'idle' }); }, [url]);
            const read = () => {
                if (busy.current || xcp) return;
                busy.current = true;
                const my = ++seq.current;
                setSt(s => ({ ...s, loading: true }));
                crVmRead(authFetch, url).catch(() => ({ state: 'unreachable', at: Date.now() })).then(r => {
                    if (my !== seq.current) return;
                    busy.current = false;
                    if (r.state === 'ok' && Array.isArray(r.body.interfaces)) {
                        setSt(s => ({ state: 'ok', cur: { at: r.at, list: r.body.interfaces }, prev: s.cur || null }));
                    } else {
                        setSt(s => ({ ...s, loading: false, failed: r }));
                    }
                });
            };
            if (xcp) return <p className="cr-pf-note" data-cr-pf-nics-xcp="">{t('crPfNicsXcp')}</p>;
            const cur = st.cur, prev = st.state === 'ok' ? st.prev : null;
            const rows = cur ? cur.list.filter(x => x && typeof x.iface === 'string') : [];
            const virt = rows.filter(x => CR_PF_VIRT_IF.test(x.iface) || x.iface === 'lo');
            const shown = (all ? rows : rows.filter(x => !virt.includes(x))).slice().sort((a, b) => a.iface.localeCompare(b.iface));
            const prevBy = {};
            (prev ? prev.list : []).forEach(x => { if (x && x.iface) prevBy[x.iface] = x; });
            const withErr = rows.filter(x => ['rx_errs', 'rx_drop', 'tx_errs', 'tx_drop'].some(k => crPfNum(x[k]) && x[k] > 0)).length;
            const f = st.failed;
            const cell = (x, d, k, bytes) => {
                const v = x[k];
                const dv = d ? d[k] : null;
                const strong = !bytes && /errs|drop/.test(k) && crPfNum(v) && v > 0;
                return (
                    <td className={strong ? 'cr-strong' : ''} title={crPfNum(v) ? String(v) : ''}>
                        {bytes ? (crPfNum(v) ? formatBytes(v) : '-') : (/packets/.test(k) ? crPfCompact(v) : (crPfNum(v) ? String(v) : '-'))}
                        {dv === 'reset' ? <span className="cr-pf-delta" data-cr-pf-delta="reset">{t('crPfNicReset')}</span>
                            : crPfNum(dv) ? <span className="cr-pf-delta" data-cr-pf-delta={dv}>+{bytes ? formatBytes(dv) : crPfCompact(dv)}</span> : null}
                    </td>
                );
            };
            return (
                <div className="cr-pf-group-body" data-cr-pf-nics={st.loading ? 'loading' : st.state} data-cr-pf-nics-rows={shown.length}>
                    <p className="cr-pf-note">{t('crPfNicsAbout')}</p>
                    <div className="cr-pf-acts">
                        <CrButton icon={<Icons.RefreshCw />} onClick={read} disabled={!!st.loading} data-cr-pf-nics-read="">
                            {cur ? t('crPfNicsAgain') : t('crPfNicsRead')}
                        </CrButton>
                        {st.loading && <span className="cr-muted" role="status"><span className="cr-spinner" aria-hidden="true" />{t('crPfNicsReading')}</span>}
                        {cur && <span className="cr-muted" data-cr-pf-nics-at="">{crFill(t('crPfNicsAt'), { time: crVmClock(cur.at) })}</span>}
                        {prev && <span className="cr-muted" data-cr-pf-nics-since="">{crFill(t('crPfNicsSince'), { time: crVmClock(prev.at), dur: crPfDur((cur.at - prev.at) / 1000, t) || crFill(t('crPfAgoS'), { n: Math.round((cur.at - prev.at) / 1000) }) })}</span>}
                    </div>
                    {f && (
                        <p className="cr-pf-note cr-tone-text cr-tone-error" role="alert" data-cr-pf-nics-error={f.code || f.state}>
                            {f.code === 502 ? crFill(t('crPfNicsSsh'), { why: f.msg || 'HTTP 502' })
                                : f.state === 'forbidden' ? t('crPfNicsDenied') : crFill(t('crPfNicsFailed'), { why: crRpWhy(f, t) })}
                        </p>
                    )}
                    {cur && (
                        <>
                            <div className="cr-pf-acts">
                                <span className="cr-muted" data-cr-pf-nics-count="">{crFill(t('crPfNicsCount'), { n: rows.length, e: withErr })}</span>
                                {virt.length > 0 && (
                                    <label className="cr-pf-check">
                                        <input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)} data-cr-pf-nics-all="" />
                                        {crFill(t('crPfNicsVirt'), { n: virt.length })}
                                    </label>
                                )}
                            </div>
                            {shown.length === 0 ? <p className="cr-pf-note">{rows.length ? t('crPfNicsOnlyVirt') : t('crPfNicsEmpty')}</p> : (
                                <table className="cr-pf-nics" data-cr-pf-nics-table="">
                                    <thead>
                                        <tr>
                                            <th scope="col">{t('crPfNicIface')}</th>
                                            <th scope="col">{t('crPfNicRx')}</th><th scope="col">{t('crPfNicRxPk')}</th>
                                            <th scope="col">{t('crPfNicRxErr')}</th><th scope="col">{t('crPfNicRxDrop')}</th>
                                            <th scope="col">{t('crPfNicTx')}</th><th scope="col">{t('crPfNicTxPk')}</th>
                                            <th scope="col">{t('crPfNicTxErr')}</th><th scope="col">{t('crPfNicTxDrop')}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {shown.map(x => {
                                            const d = crPfNicDelta(prevBy[x.iface], x);
                                            return (
                                                <tr key={x.iface} data-cr-pf-nic={x.iface}>
                                                    <th scope="row">{x.iface}</th>
                                                    {cell(x, d, 'rx_bytes', true)}{cell(x, d, 'rx_packets')}{cell(x, d, 'rx_errs')}{cell(x, d, 'rx_drop')}
                                                    {cell(x, d, 'tx_bytes', true)}{cell(x, d, 'tx_packets')}{cell(x, d, 'tx_errs')}{cell(x, d, 'tx_drop')}
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                            <p className="cr-pf-note cr-muted">{t('crPfNicsZero')}</p>
                        </>
                    )}
                </div>
            );
        }

        // the switch of the groups: one open at a time, a second click closes it
        function CrPfMore({ groups, t, id }) {
            const [open, setOpen] = useState(null);
            const cur = groups.find(g => g.id === open) || null;
            return (
                <div className="cr-pf-more" data-cr-pf-more={open || ''}>
                    <div className="cr-pf-more-bar">
                        <span className="cr-pf-more-label" id={`${id}-more`}>{t('crPfMore')}</span>
                        <div className="cr-seg" role="group" aria-labelledby={`${id}-more`}>
                            {groups.map(g => (
                                <button key={g.id} type="button" className={open === g.id ? 'active' : ''} aria-expanded={open === g.id}
                                    aria-controls={open === g.id ? `${id}-group` : undefined} data-cr-pf-group={g.id}
                                    onClick={() => setOpen(o => (o === g.id ? null : g.id))}>{g.label}</button>
                            ))}
                        </div>
                    </div>
                    {cur && <div id={`${id}-group`} className="cr-pf-group" data-cr-pf-open={cur.id} role="region" aria-label={cur.label}>{cur.render()}</div>}
                </div>
            );
        }

        // --- what the loaded range says -------------------------------------------

        // One line per measure with the value, the window and the source. A verdict only against a
        // threshold PegaProx has: the alert rules of this object, else the display scale 80 / 90 of this
        // view for CPU and memory. I/O wait, pressure and swap: the measured values, no verdict
        function crPfObservations(x, t) {
            const { p, rules, type, id, swap } = x;
            const out = [];
            if (!p || !p.metrics) return out;
            const ts = p.timestamps, step = p.step || crPfStep(ts);
            const peak = (s, fmt) => crFill(t('crPfPeakAt'), { v: fmt(s.max), time: crPfAt(s.maxAt) });
            const pct = (v) => crPct(v, 1);
            ['cpu', 'memory'].forEach(metric => {
                const s = crPfStats(ts, p.metrics[metric]);
                if (!s) return;
                const what = metric === 'cpu' ? t('cpu') : t('memory');
                const own = crPfObjectRules(rules, type, id, metric);
                if (own.length) {
                    own.forEach(r => {
                        const op = r.operator || '>', thr = Number(r.threshold);
                        const runs = crPfRuns(ts, p.metrics[metric], v => CR_PF_OPS[op](v, thr), step);
                        out.push({ id: `${metric}-rule-${r.id}`, tone: runs.n ? crPfTone(r.severity) : 'neutral',
                                   text: runs.n ? crFill(t('crPfObsRuleHit'), { what, rule: r.name || r.id, op, thr, n: runs.n, m: runs.m,
                                                                                long: crPfDur(runs.longest.secs, t), from: crPfAt(runs.longest.from) })
                                       : crFill(t('crPfObsRuleNo'), { what, rule: r.name || r.id, op, thr, m: runs.m }),
                                   more: peak(s, pct), basis: t('crPfObsRuleBasis') });
                    });
                    return;
                }
                const crit = crPfRuns(ts, p.metrics[metric], v => v > CR_CRIT, step);
                const warn = crPfRuns(ts, p.metrics[metric], v => v > CR_WARN, step);
                const hit = crit.n ? { r: crit, lim: CR_CRIT, tone: 'error' } : warn.n ? { r: warn, lim: CR_WARN, tone: 'warning' } : null;
                out.push({ id: metric, tone: hit ? hit.tone : 'neutral',
                           text: hit ? crFill(t('crPfObsScaleHit'), { what, lim: hit.lim, n: hit.r.n, m: hit.r.m, long: crPfDur(hit.r.longest.secs, t), from: crPfAt(hit.r.longest.from) })
                               : crFill(t('crPfObsScaleNo'), { what, lim: CR_WARN, m: warn.m }),
                           more: peak(s, pct), basis: crFill(t('crPfObsScaleBasis'), { warn: CR_WARN, crit: CR_CRIT }) });
            });
            const io = crPfStats(ts, p.metrics.iowait);
            if (io) out.push({ id: 'iowait', tone: 'neutral', text: crFill(t('crPfObsMeasured'), { what: t('crIoWait'), avg: pct(io.avg), m: io.n }),
                               more: peak(io, pct), basis: t('crPfObsNoThreshold') });
            CR_PF_PSI.forEach(([k, some, full]) => {
                const f = crPfStats(ts, p.metrics[full]), sm = crPfStats(ts, p.metrics[some]);
                if (!f && !sm) return;
                const what = k === 'cpu' ? t('crPfPsiCpu') : k === 'memory' ? t('crPfPsiMem') : t('crPfPsiIo');
                out.push({ id: `psi-${k}`, tone: 'neutral',
                           text: crFill(t('crPfObsPsi'), { what, some: sm ? pct(sm.avg) : '-', full: f ? pct(f.avg) : '-', m: (f || sm).n }),
                           more: f ? peak(f, pct) : peak(sm, pct), basis: t('crPfObsNoThreshold') });
            });
            if (swap) {
                if (swap.state === 'none') out.push({ id: 'swap', tone: 'neutral', text: t('crPfObsSwapNone'), basis: swap.basis });
                else if (swap.state === 'ok') out.push({ id: 'swap', tone: 'neutral', text: crFill(t('crPfObsSwap'), { pct: pct(swap.pct), used: formatBytes(swap.used), total: formatBytes(swap.total) }),
                                                         basis: `${swap.basis}. ${t('crPfObsNoThreshold')}` });
            }
            return out;
        }

        function CrPfInsights({ items, window, rulesNote, t }) {
            if (!items.length) return null;
            return (
                <CrPanel title={t('crPfObsTitle')} className="cr-pf-insights" data-cr-pf-insights=""
                    actions={<span className="cr-muted cr-pf-window" data-cr-pf-window="">{window}</span>}>
                    <ul className="cr-pf-obs">
                        {items.map(o => (
                            <li key={o.id} className={`cr-pf-obs-row cr-pf-obs-${o.tone}`} data-cr-pf-obs={o.id} data-cr-pf-tone={o.tone}>
                                <span className={`cr-pf-dot cr-tone-${o.tone}`} aria-hidden="true" />
                                <span className="cr-pf-obs-text">
                                    <span>{o.text}</span>
                                    {o.more && <span className="cr-muted"> {o.more}</span>}
                                    {o.basis && <span className="cr-pf-obs-basis">{o.basis}</span>}
                                </span>
                            </li>
                        ))}
                    </ul>
                    {rulesNote && <p className="cr-pf-note cr-muted" data-cr-pf-rules="">{rulesNote}</p>}
                </CrPanel>
            );
        }

        function crPfRulesNote(store, own, t, whatObj) {
            if (!store || store.state === 'idle' || store.state === 'loading') return t('crPfRulesReading');
            if (store.state === 'forbidden') return t('crPfRulesDenied');
            if (store.state !== 'ok') return crFill(t('crPfRulesFailed'), { why: crRpWhy(store, t) });
            return own ? crFill(t('crPfRulesOwn'), { n: own, what: whatObj }) : crFill(t('crPfRulesNone'), { what: whatObj });
        }

        // the state of the panel from the answer it holds
        function crPfState(p, loading) {
            if (p === undefined || (p == null && loading)) return 'loading';
            if (p == null || p.error !== undefined) return 'error';
            return crAnySamples(p) ? 'ready' : 'empty';
        }

        // re-draws every 30 s so the age of the newest sample moves on; asks nothing
        function crPfUseTick() {
            const [, setN] = useState(0);
            useEffect(() => { const h = setInterval(() => setN(n => n + 1), 30000); return () => clearInterval(h); }, []);
            return Date.now();
        }

        // when an object last changed identity in this browser (a live push, a read)
        function crPfUseSeen(obj) {
            const ref = useRef({ obj: undefined, at: 0 });
            if (ref.current.obj !== obj) ref.current = { obj, at: Date.now() };
            return ref.current.at;
        }

        // the list of metrics nobody delivers, said once
        function CrPfNotCollected({ text }) {
            return <p className="cr-pf-note cr-muted cr-pf-notcollected" data-cr-pf-notcollected="">{text}</p>;
        }

        // --- the node -------------------------------------------------------------

        // p: the answer of the view's read as crPfPrep made it (the same the zoom of the view holds)
        // the rules read for one account are not the next one's (crSessionFor in crPfUseRules)
        crSessionStore(() => { Object.keys(crPfRuleStore).forEach(k => { delete crPfRuleStore[k]; }); });

        function CrNodePerf({ node, clusterId, kind, live, summary, p, loading, range, onRange, onReload, zoom, authFetch }) {
            const { t } = useTranslation();
            const now = crPfUseTick();
            const xcp = kind === 'xcpng';
            const state = crPfState(p, loading);
            const rules = crPfUseRules(authFetch, clusterId);
            const liveAt = crPfUseSeen(live);
            const sumAt = crPfUseSeen(summary);
            const c = crSeriesColors();
            const rangeLabel = crPfRange(range, t);
            const ts = (p && p.timestamps) || [];
            const st = (k) => (state === 'ready' || state === 'empty' ? crPfStats(ts, p.metrics[k]) : null);
            const rrdBasis = (s) => crFill(t('crPfBasisRrd'), { step: crPfStepText(p && p.step, t), time: crPfAt(s.lastAt) });
            const notRead = state === 'loading' ? t('loading') : state === 'error' ? t('crPerfFailed') : t('crPfNoSample');
            const lv = live || {};
            const liveOk = !!live && lv.status !== 'offline' && lv.status !== 'unknown' && !lv.offline;
            const liveBasis = crFill(t('crPfBasisLive'), { time: crVmClock(liveAt) });
            const liveRange = (s) => (s ? `${liveBasis} · ${t('crPfBasisRangeRrd')}` : liveBasis);
            const avgPeak = (s, fmt) => (s ? crFill(t('crPfAvgPeak'), { avg: fmt(s.avg), peak: fmt(s.max), range: rangeLabel }) : '');
            const pct1 = (v) => crPct(v, 1);
            const tiles = [];
            // CPU: live, with the loaded range under it
            const cpuS = st('cpu');
            if (liveOk && crPfNum(lv.cpu_percent)) {
                tiles.push({ id: 'cpu', label: t('cpu'), value: pct1(lv.cpu_percent), meter: lv.cpu_percent, tone: crTone(lv.cpu_percent),
                             sub: avgPeak(cpuS, pct1), basis: liveRange(cpuS) });
            } else if (cpuS) {
                tiles.push({ id: 'cpu', label: t('cpu'), value: pct1(cpuS.last), meter: cpuS.last, tone: crTone(cpuS.last), sub: avgPeak(cpuS, pct1), basis: rrdBasis(cpuS) });
            } else tiles.push({ id: 'cpu', label: t('cpu'), value: '-', state: 'none', sub: live && !liveOk ? t('crPfNodeOffline') : notRead });
            // load: the three averages of the node's status, only when all three are numbers
            const load = !xcp && liveOk && Array.isArray(lv.loadavg) && lv.loadavg.length === 3
                ? lv.loadavg.map(x => (typeof x === 'string' && x.trim() !== '' ? Number(x) : x)) : null;
            if (load && load.every(crPfNum)) {
                const cpus = lv.cpuinfo && crPfNum(lv.cpuinfo.cpus) ? lv.cpuinfo.cpus : null;
                tiles.push({ id: 'load', label: t('loadAverage'), value: load.map(v => v.toFixed(2)).join(' / '),
                             sub: cpus ? crFill(t('crPfLoadSubCpus'), { n: cpus }) : t('crPfLoadSub'), basis: liveBasis });
            }
            if (!xcp) {
                const io = st('iowait');
                tiles.push(io ? { id: 'iowait', label: t('crIoWait'), value: pct1(io.last), sub: avgPeak(io, pct1), basis: rrdBasis(io), title: t('crPfNoThresholdTip') }
                    : { id: 'iowait', label: t('crIoWait'), value: '-', state: 'none', sub: notRead });
            }
            // memory: used of total as the node reports it; free is total minus used, not MemAvailable
            const memOk = liveOk && crPfNum(lv.mem_used) && crPfNum(lv.mem_total) && lv.mem_total > 1024 * 1024;
            const memS = st('memory');
            if (memOk) {
                const pctM = lv.mem_used / lv.mem_total * 100;
                tiles.push({ id: 'memory', label: t('memory'), value: pct1(pctM), meter: pctM, tone: crTone(pctM),
                             sub: crFill(t('crPfMemSub'), { used: formatBytes(lv.mem_used), total: formatBytes(lv.mem_total), free: formatBytes(Math.max(0, lv.mem_total - lv.mem_used)) }),
                             basis: liveBasis, title: t('crPfMemFreeTip') });
            } else if (memS) {
                tiles.push({ id: 'memory', label: t('memory'), value: pct1(memS.last), meter: memS.last, tone: crTone(memS.last), sub: avgPeak(memS, pct1), basis: rrdBasis(memS) });
            } else tiles.push({ id: 'memory', label: t('memory'), value: '-', state: 'none', sub: live && !liveOk ? t('crPfNodeOffline') : notRead });
            // swap from the node summary the view read on open
            let swap = null;
            if (!xcp) {
                const sw = summary && summary.swap;
                const sumBasis = crFill(t('crPfBasisSummary'), { time: crVmClock(sumAt) });
                if (summary === undefined) tiles.push({ id: 'swap', label: t('swap'), value: '-', state: 'none', sub: t('loading') });
                else if (summary === null) tiles.push({ id: 'swap', label: t('swap'), value: '-', state: 'none', sub: t('crPfSummaryFailed') });
                else if (!sw || !crPfNum(sw.total) || !crPfNum(sw.used)) tiles.push({ id: 'swap', label: t('swap'), value: '-', state: 'none', sub: t('crPfSummaryNoSwap') });
                else if (sw.total === 0) {
                    swap = { state: 'none', basis: sumBasis };
                    tiles.push({ id: 'swap', label: t('swap'), value: t('crPfSwapNone'), state: 'none', sub: t('crPfSwapNoneSub'), basis: sumBasis });
                } else {
                    swap = { state: 'ok', used: sw.used, total: sw.total, pct: sw.used / sw.total * 100, basis: sumBasis };
                    tiles.push({ id: 'swap', label: t('swap'), value: pct1(swap.pct), sub: crFill(t('crUsedOf'), { used: formatBytes(sw.used), total: formatBytes(sw.total) }),
                                 basis: sumBasis, title: t('crPfNoThresholdTip') });
                }
                ['net_in', 'net_out'].forEach(k => {
                    const s = st(k);
                    const label = k === 'net_in' ? t('networkIn') : t('networkOut');
                    // the node route sends KB/s
                    tiles.push(s ? { id: k, label, value: crPfRate(s.last * 1024), sub: crFill(t('crPfPeak'), { peak: crPfRate(s.max * 1024), range: rangeLabel }), basis: rrdBasis(s) }
                        : { id: k, label, value: '-', state: 'none', sub: notRead });
                });
                const rootOk = liveOk && crPfNum(lv.disk_used) && crPfNum(lv.disk_total) && lv.disk_total > 1024 * 1024;
                if (rootOk) {
                    const pr = lv.disk_used / lv.disk_total * 100;
                    tiles.push({ id: 'rootfs', label: t('crRootFs'), value: pct1(pr), meter: pr, tone: crStoreTone(pr),
                                 sub: crFill(t('crUsedOf'), { used: formatBytes(lv.disk_used), total: formatBytes(lv.disk_total) }), basis: liveBasis, title: crStoreScale(t) });
                }
            }
            // the charts: the same seven in the same order, straight lines, the thresholds of CPU and memory
            const cpuLines = crPfLines(crPfObjectRules(rules, 'node', node, 'cpu'), t);
            const memLines = crPfLines(crPfObjectRules(rules, 'node', node, 'memory'), t);
            const base = { tension: 0, markGaps: true, resize: true };
            const net = zoom.source('net_in', 'net_out');
            const toRate = (a) => (Array.isArray(a) ? a.map(v => (crPfNum(v) ? v * 1024 : v)) : a);
            const netIn = useMemo(() => toRate(net.metrics && net.metrics.net_in), [net.metrics && net.metrics.net_in]);
            const netOut = useMemo(() => toRate(net.metrics && net.metrics.net_out), [net.metrics && net.metrics.net_out]);
            const xcpNone = xcp ? t('crPfXcpNone') : undefined;
            const charts = [
                { id: 'cpu', label: t('cpu'), series: zoom.series('cpu'), color: c.cpu, unit: '%', yMin: 0, yMax: 100, thresholds: cpuLines.lines, caption: cpuLines.caption, ...base },
                { id: 'memory', label: t('memory'), series: zoom.series('memory'), color: c.ram, unit: '%', yMin: 0, yMax: 100, thresholds: memLines.lines, caption: memLines.caption, ...base },
                { id: 'iowait', label: t('crIoWait'), series: zoom.series('iowait'), color: c.net, unit: '%', formatValue: v => v.toFixed(1), none: xcpNone, caption: xcp ? null : t('crPfNoThresholdCap'), ...base },
                { id: 'loadavg', label: crFill(t('crPfLoad1'), { what: t('loadAverage') }), series: zoom.series('loadavg'), color: c.disk, unit: ' ', formatValue: v => v.toFixed(2), none: xcpNone, ...base },
                { id: 'net', label: t('network'), wide: true, unit: '/s', formatValue: formatBytes, timestamps: net.timestamps, toggles: true, none: xcpNone, ...base,
                  datasets: [{ label: t('networkIn'), data: netIn, color: c.cpu }, { label: t('networkOut'), data: netOut, color: c.ram }] },
                { id: 'swap', label: t('swap'), series: zoom.series('swap'), color: c.ram, unit: '%', yMin: 0, yMax: 100, none: xcpNone,
                  caption: swap && swap.state === 'none' ? t('crPfSwapNoneSub') : null, ...base },
                { id: 'rootfs', label: t('crRootFs'), series: zoom.series('rootfs'), color: c.disk, unit: '%', yMin: 0, yMax: 100, none: xcpNone, ...base },
            ];
            const q = state === 'ready' ? crPfQuality(p, ['cpu', 'memory'], now / 1000) : null;
            const groups = [
                { id: 'psi', label: t('crPfGroupPsi'), render: () => <CrPfPsi prepped={p} zoom={state === 'ready' ? zoom : null} colors={c} t={t} base={base} /> },
                { id: 'compare', label: t('crPfGroupCompare'), render: () => (
                    <CrPfCompare range={range} authFetch={authFetch} colors={c} t={t} base={base} objKey={`${clusterId}/${node}`}
                        histUrl={(from, to) => `${API_URL}/clusters/${clusterId}/nodes/${node}/metrics-history?from=${Math.floor(from)}&to=${Math.ceil(to)}`} />) },
                { id: 'nics', label: t('crPfGroupNics'), render: () => (
                    <CrPfNics url={`${API_URL}/clusters/${clusterId}/nodes/${node}/netstats`} authFetch={authFetch} t={t} xcp={xcp} />) },
            ];
            const own = crPfObjectRules(rules, 'node', node, 'cpu').length + crPfObjectRules(rules, 'node', node, 'memory').length;
            const obs = state === 'ready' ? crPfObservations({ p, rules, type: 'node', id: node, swap }, t) : [];
            const window = q ? crFill(t('crPfWindow'), { range: rangeLabel, n: q.slots, step: crPfStepText(q.step, t) }) : '';
            return (
                <div className="cr-pf" data-cr-pf="node">
                    <CrPfKpis tiles={tiles} label={t('crPfKpis')} />
                    <CrPerfPanel title={t('performance')} range={range} onRange={onRange} zoom={zoom}
                        state={state} busy={loading} onRetry={onReload}
                        errorText={p && p.error ? crFill(t('crPfFailedWhy'), { why: p.error }) : null}
                        tools={<CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading} data-cr-pf-refresh="" title={t('crPfRefreshTip')}>{t('refresh')}</CrButton>}
                        quality={<CrPfQuality q={q} range={rangeLabel} fromHistory={zoom.fromHistory} xcp={xcp} t={t} />}
                        more={<CrPfMore groups={groups} t={t} id="cr-pf-node" />}
                        footer={<CrPfNotCollected text={t('crPfNotCollectedNode')} />}
                        charts={charts} />
                    <CrPfInsights items={obs} window={window} t={t} rulesNote={crPfRulesNote(rules, own, t, t('crPfThisNode'))} />
                </div>
            );
        }

        // --- the guest ------------------------------------------------------------

        // p: the answer of the view's read as crPfPrep made it; the guest route answers a failure with an error status
        function CrGuestPerf({ vm, clusterId, kind, isRunning, p, loading, failed, range, onRange, onReload, zoom, authFetch }) {
            const { t } = useTranslation();
            const now = crPfUseTick();
            const xcp = kind === 'xcpng';
            const state = !isRunning ? 'empty' : failed && !loading ? 'error' : p == null ? 'loading'
                : p.error !== undefined ? 'error' : crAnySamples(p) ? 'ready' : loading ? 'loading' : 'empty';
            // a stopped guest draws nothing a rule could apply to: no read
            const rules = crPfUseRules(authFetch, isRunning ? clusterId : null);
            const c = crSeriesColors();
            const rangeLabel = crPfRange(range, t);
            const ts = (p && p.timestamps) || [];
            const st = (k) => (isRunning && (state === 'ready' || state === 'empty') ? crPfStats(ts, p.metrics[k]) : null);
            const rrdBasis = (s) => crFill(t('crPfBasisRrd'), { step: crPfStepText(p && p.step, t), time: crPfAt(s.lastAt) });
            const notRead = state === 'loading' ? t('loading') : state === 'error' ? t('crPerfFailed') : t('crPfNoSample');
            const pct1 = (v) => crPct(v, 1);
            const maxMemGB = vm.maxmem ? vm.maxmem / (1024 * 1024 * 1024) : 0;
            const tiles = [];
            if (isRunning) {
                const cpu = st('cpu');
                tiles.push(cpu ? { id: 'cpu', label: t('cpu'), value: pct1(cpu.last), meter: cpu.last, tone: crTone(cpu.last),
                                   sub: crFill(t('crPfAvgPeak'), { avg: pct1(cpu.avg), peak: pct1(cpu.max), range: rangeLabel }), basis: rrdBasis(cpu),
                                   title: t('crPfGuestCpuTip') }
                    : { id: 'cpu', label: t('cpu'), value: '-', state: 'none', sub: notRead });
                const mem = st('memory');
                tiles.push(mem ? { id: 'memory', label: t('memory'), value: pct1(mem.last), meter: mem.last, tone: crTone(mem.last),
                                   sub: vm.maxmem ? crFill(t('crPfGuestMemSub'), { used: formatBytes(mem.last / 100 * vm.maxmem), total: formatBytes(vm.maxmem) }) : '',
                                   basis: rrdBasis(mem), title: t('crPfGuestMemTip') }
                    : { id: 'memory', label: t('memory'), value: '-', state: 'none', sub: notRead });
                [['disk_read', t('crVmDiskRead')], ['disk_write', t('crVmDiskWrite')], ['net_in', t('networkIn')], ['net_out', t('networkOut')]].forEach(([k, label]) => {
                    const s = st(k);
                    tiles.push(s ? { id: k, label, value: crPfRate(s.last), sub: crFill(t('crPfPeak'), { peak: crPfRate(s.max), range: rangeLabel }), basis: rrdBasis(s) }
                        : { id: k, label, value: '-', state: 'none', sub: notRead });
                });
            }
            const cpuLines = crPfLines(crPfObjectRules(rules, 'vm', vm.vmid, 'cpu'), t);
            const memLines = crPfLines(crPfObjectRules(rules, 'vm', vm.vmid, 'memory'), t, maxMemGB ? (v => v / 100 * maxMemGB) : null);
            const base = { tension: 0, markGaps: true, resize: true };
            const mem = zoom.series('memory');
            const memGB = useMemo(() => (Array.isArray(mem.data) && maxMemGB ? mem.data.map(v => (crPfNum(v) ? v / 100 * maxMemGB : null)) : []),
                                  [mem.data, maxMemGB]);
            const disk = zoom.source('disk_read', 'disk_write');
            const net = zoom.source('net_in', 'net_out');
            const charts = [
                { id: 'cpu', label: t('cpu'), series: zoom.series('cpu'), color: c.cpu, unit: '%', yMin: 0, yMax: 100, thresholds: cpuLines.lines, caption: cpuLines.caption, ...base },
                { id: 'memory', label: t('memory'), series: { data: memGB, timestamps: mem.timestamps }, color: c.ram, unit: ' GB', yMin: 0, yMax: maxMemGB,
                  formatValue: v => v.toFixed(2), thresholds: maxMemGB ? memLines.lines : [], caption: maxMemGB ? `${memLines.caption} ${t('crPfGuestMemTip')}` : null, ...base },
                { id: 'disk', label: t('crDiskIo'), timestamps: disk.timestamps, unit: '/s', formatValue: formatBytes, toggles: true, ...base,
                  datasets: [{ label: t('crRead'), data: disk.metrics.disk_read, color: c.disk }, { label: t('crWrite'), data: disk.metrics.disk_write, color: c.net }] },
                { id: 'net', label: t('network'), timestamps: net.timestamps, unit: '/s', formatValue: formatBytes, toggles: true, ...base,
                  datasets: [{ label: t('networkIn'), data: net.metrics.net_in, color: c.cpu }, { label: t('networkOut'), data: net.metrics.net_out, color: c.ram }] },
            ];
            const q = state === 'ready' ? crPfQuality(p, ['cpu', 'memory'], now / 1000) : null;
            const groups = [
                { id: 'psi', label: t('crPfGroupPsi'), render: () => <CrPfPsi prepped={isRunning ? p : null} zoom={state === 'ready' ? zoom : null} colors={c} t={t} base={base} /> },
                { id: 'compare', label: t('crPfGroupCompare'), render: () => (
                    <CrPfCompare range={range} authFetch={authFetch} colors={c} t={t} base={base} objKey={`${clusterId}/${vm.vmid}`}
                        histUrl={(from, to) => `${API_URL}/clusters/${clusterId}/vms/${vm.vmid}/metrics-history?from=${Math.floor(from)}&to=${Math.ceil(to)}`} />) },
            ];
            const own = crPfObjectRules(rules, 'vm', vm.vmid, 'cpu').length + crPfObjectRules(rules, 'vm', vm.vmid, 'memory').length;
            const obs = state === 'ready' ? crPfObservations({ p, rules, type: 'vm', id: vm.vmid }, t) : [];
            const window = q ? crFill(t('crPfWindow'), { range: rangeLabel, n: q.slots, step: crPfStepText(q.step, t) }) : '';
            return (
                <div className="cr-pf" data-cr-pf="guest">
                    <CrPfKpis tiles={tiles} label={t('crPfKpis')} />
                    <CrPerfPanel title={t('performanceMetrics')} range={range} onRange={onRange} zoom={zoom}
                        state={state} busy={loading} emptyText={isRunning ? null : t('crPerfNotRunning')} onRetry={onReload}
                        tools={isRunning ? <CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading} data-cr-pf-refresh="" title={t('crPfRefreshTip')}>{t('refresh')}</CrButton> : null}
                        quality={<CrPfQuality q={q} range={rangeLabel} fromHistory={zoom.fromHistory} xcp={xcp} t={t} />}
                        more={isRunning ? <CrPfMore groups={groups} t={t} id="cr-pf-guest" /> : null}
                        footer={isRunning ? <CrPfNotCollected text={t('crPfNotCollectedGuest')} /> : null}
                        charts={charts} />
                    <CrPfInsights items={obs} window={window} t={t} rulesNote={crPfRulesNote(rules, own, t, t('crPfThisGuest'))} />
                </div>
            );
        }
