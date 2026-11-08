        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned - the task center. LW Oct 2026
        // It draws the task data the app already has and keeps no tracker of its own: the
        // TaskBar's list of the selected cluster, the SSE task frames of every cluster the
        // stream carries, one read per cluster without a fresh list when the list opens for
        // all clusters, and the two job registries that know what still waits to start.
        // Mounted only by TaskBar (dashboard.js) in the variant.
        // LW Nov 2026 - the bar is the header: collapsed it sits on the status bar, open it sits on
        // top of the drawer, and a click on it outside its own controls closes it again
        // ═══════════════════════════════════════════════════════════

        const CR_TC = {
            minH: 160,          // the drawer without the bar
            maxPart: 0.8,
            defPart: 0.45,
            fresh: 15000,       // a list younger than this is not read again when the drawer opens
            parallel: 4,        // reads in flight at most
            settle: 400,        // feed changes are drawn at most this often
            logEvery: 2000,     // the open task's log while it runs, the beat of the backup progress pane
            logLimit: 5000,
        };

        // --- what a task says ---------------------------------------------------

        // The text a finished task ended with. The server hands PVE's exit text over in status
        // today and never sets exitstatus; a fixed server (#590) says stopped/failed plus
        // exitstatus. XCP-ng says completed or failed.
        function crTaskResult(task) {
            if (!task) return '';
            const ex = task.exitstatus;
            if (ex != null && String(ex).trim() !== '') return String(ex).trim();
            return task.status == null ? '' : String(task.status).trim();
        }
        const CR_TASK_OK = new Set(['', 'ok', 'stopped', 'completed', 'success']);
        const crStateMemo = new WeakMap();
        function crTaskState(task) {
            if (!task) return 'done';
            const hit = crStateMemo.get(task);
            if (hit) return hit;
            const st = task.status;
            const r = crTaskResult(task);
            let s;
            if (st === 'running' || (st == null && !task.endtime)) s = 'running';
            else if (st === 'queued') s = 'queued';
            else if (st === 'cancelled' || /^interrupted by signal/i.test(r)) s = 'cancelled';
            // "WARNINGS: n" did its job and left something worth a look in the log
            else if (/^WARNINGS/i.test(r)) s = 'done';
            else if (st === 'failed' || st === 'error' || st === 'failure') s = 'failed';
            else s = CR_TASK_OK.has(r.toLowerCase()) ? 'done' : 'failed';
            crStateMemo.set(task, s);
            return s;
        }
        const crTaskWarned = (task) => crTaskState(task) === 'done' && /^WARNINGS/i.test(crTaskResult(task));
        const CR_TASK_TONE = { running: 'info', queued: 'neutral', done: 'success', failed: 'error', cancelled: 'warning' };
        function crTaskTone(task) {
            const s = crTaskState(task);
            return s === 'done' && crTaskWarned(task) ? 'warning' : CR_TASK_TONE[s];
        }
        function crTaskLabel(state, t) {
            return ({ running: t('running'), queued: t('crTaskQueued'), done: t('done'),
                      failed: t('failed'), cancelled: t('crTaskCancelled') })[state];
        }
        // the status filter: Completed is every task that ended without failing, warnings included
        const CR_TC_BUCKET = { running: 'running', queued: 'queued', done: 'completed', failed: 'failed', cancelled: 'cancelled' };
        const CR_TC_ORDER = { running: 0, queued: 1, failed: 2, cancelled: 3, done: 4 };
        const crTaskKey = (task) => `${task.cluster_id || ''}|${task.upid || ''}`;

        function crTaskCounts(list) {
            const c = { running: 0, queued: 0, done: 0, failed: 0, cancelled: 0, warned: 0 };
            for (let i = 0; i < list.length; i++) {
                const s = crTaskState(list[i]);
                c[s]++;
                if (s === 'done' && crTaskWarned(list[i])) c.warned++;
            }
            return c;
        }

        // The last progress line PVE writes into a task log: a backup "INFO:  12% (3.8 GiB of
        // 32.0 GiB) in 5s", a disk copy or mirror "... (3.44%)", a restore "progress 12% (read ...)".
        // Nothing else is read as a percentage.
        const CR_TC_PCT = [/^INFO:\s+(\d{1,3}(?:\.\d+)?)%\s/, /\((\d{1,3}(?:\.\d+)?)%\)/, /\bprogress (\d{1,3}(?:\.\d+)?)%/];
        function crParseProgress(lines) {
            const list = Array.isArray(lines) ? lines : String(lines || '').split('\n');
            for (let i = list.length - 1; i >= 0 && i >= list.length - 400; i--) {
                const line = String(list[i] || '');
                for (const re of CR_TC_PCT) {
                    const m = re.exec(line);
                    if (m) {
                        const v = parseFloat(m[1]);
                        if (v >= 0 && v <= 100) return v;
                    }
                }
            }
            return null;
        }

        // fmtDate and fmtTime in the UI language (cr.js); they read the 12h setting without throwing
        function crDate(sec) {
            return crFmtDate(sec * 1000);
        }
        function crTcClock(sec) {
            return crFmtTime(sec * 1000);
        }

        function crDurationText(task, fmt) {
            if (!task || !task.starttime || !fmt) return '-';
            const s = crTaskState(task);
            if (s === 'running') return fmt(task.starttime);
            if (s === 'queued') return '-';
            // a finished task without an end (XCP-ng) has no duration to show
            return task.endtime ? fmt(task.starttime, task.endtime) : '-';
        }

        // --- the feed: what the stream and the reads brought, per cluster ------------

        const crTaskFeed = (() => {
            let users = 0;
            let version = 0;
            let seq = 0;
            let timer = null;
            let lists = {};     // cid -> { list, at, via: sse|read, state: ok|error|denied, code, pending, seq, asked }
            let jobs = {};      // bulk|restore -> { runs, at, state, code }
            let marks = {};     // cid|upid -> patch until the cluster reports the task finished
            const subs = new Set();
            const changed = () => {
                if (timer) return;
                timer = setTimeout(() => {
                    timer = null;
                    version++;
                    subs.forEach(fn => fn());
                }, CR_TC.settle);
            };
            // asked: the seq of the last answer to a read. An SSE frame is no answer: the stream sends []
            // for a cluster in cooldown or out of reach as well as for one without tasks
            const entry = (cid) => lists[cid] || (lists[cid] = { list: null, at: 0, via: '', state: '', code: 0, pending: false, seq: 0, asked: 0 });
            return {
                get active() { return users > 0; },
                get seq() { return seq; },
                // the dashboard holds one while the variant is on, so a hidden bar keeps what was read;
                // the task center holds its own
                attach() {
                    users++;
                    return () => {
                        users = Math.max(0, users - 1);
                        if (!users) { lists = {}; jobs = {}; marks = {}; }
                    };
                },
                // an SSE frame, kept by reference. An empty one (a disconnected cluster sends [] too)
                // never replaces a list that is there, nor the answer of a refused read
                push(cid, list) {
                    if (!users || !cid || !Array.isArray(list)) return;
                    const e = entry(cid);
                    if (!list.length && ((e.list && e.list.length) || e.state === 'error' || e.state === 'denied')) return;
                    Object.assign(e, { list, at: Date.now(), via: 'sse', state: 'ok', code: 0, seq: ++seq });
                    changed();
                },
                loaded(cid, list) {
                    if (!users || !cid || !Array.isArray(list)) return;
                    seq++;
                    Object.assign(entry(cid), { list, at: Date.now(), via: 'read', state: 'ok', code: 0, pending: false, seq, asked: seq });
                    changed();
                },
                failed(cid, code) {
                    if (!users || !cid) return;
                    seq++;
                    Object.assign(entry(cid), { state: code === 403 || code === 404 ? 'denied' : 'error', code: code || 0,
                                                pending: false, failedAt: Date.now(), seq, asked: seq });
                    changed();
                },
                pending(cid, on) {
                    if (!users || !cid) return;
                    const e = entry(cid);
                    if (e.pending === on) return;
                    e.pending = on;
                    changed();
                },
                mark(cid, upid, patch) {
                    if (!users || !cid || !upid) return;
                    marks = { ...marks, [`${cid}|${upid}`]: patch };
                    changed();
                },
                jobs(kind, runs, code) {
                    if (!users) return;
                    const was = jobs[kind];
                    jobs = { ...jobs, [kind]: Array.isArray(runs) ? { runs, at: Date.now(), state: 'ok' }
                        : { runs: was ? was.runs : null, at: was ? was.at : 0, state: code === 403 ? 'denied' : 'error', code: code || 0 } };
                    changed();
                },
                get: (cid) => lists[cid] || null,
                job: (kind) => jobs[kind] || null,
                marks: () => marks,
                version: () => version,
                subscribe: (fn) => { subs.add(fn); return () => subs.delete(fn); },
            };
        })();

        // the finished tasks "Clear completed" took away, for this page session
        const crTaskDismissed = new Set();
        crSessionStore(() => crTaskDismissed.clear());

        // a cluster's list with its id on every row; the tagged copy lives as long as the list
        const crTagMemo = new WeakMap();
        function crTagged(cid, list) {
            let byCid = crTagMemo.get(list);
            if (byCid && byCid.cid === cid) return byCid.rows;
            const rows = [];
            for (let i = 0; i < list.length; i++) {
                const x = list[i];
                if (!x || !x.upid) continue;
                rows.push(x.cluster_id === cid ? x : { ...x, cluster_id: cid });
            }
            crTagMemo.set(list, { cid, rows });
            return rows;
        }

        // A bulk migration or batch restore that still has guests waiting is one queued row.
        // The guests on their way are real PVE tasks already and are not counted twice.
        function crJobRows(kind, job) {
            if (!job || !Array.isArray(job.runs)) return [];
            const out = [];
            job.runs.forEach(r => {
                const c = (r && r.counts) || {};
                if (!r || r.state !== 'running' || !(c.wait > 0)) return;
                const total = r.total || 0;
                out.push({
                    upid: `${kind}:${r.id}`, _job: kind, _run: r, status: 'queued',
                    type: kind === 'bulk' ? 'bulkmigrate' : 'batchrestore',
                    cluster_id: r.cluster_id, node: r.node || '', pegaprox_user: r.user || '', starttime: r.created || null,
                    _wait: c.wait, _total: total,
                    _over: Math.max(0, total - c.wait - (Array.isArray(r.current) ? r.current.length : 0)),
                });
            });
            return out;
        }

        // guests by VMID, per inventory list
        const crGuestMemo = new WeakMap();
        function crGuestMap(list) {
            if (!Array.isArray(list)) return null;
            let m = crGuestMemo.get(list);
            if (!m) {
                m = new Map();
                list.forEach(g => { if (g && g.vmid != null) m.set(String(g.vmid), g); });
                crGuestMemo.set(list, m);
            }
            return m;
        }
        function crFindStore(stores, name, node) {
            if (!stores || !name) return null;
            const shared = (stores.shared || []).find(s => s && s.storage === name);
            if (shared) return { store: shared, node: null };
            const local = (stores.local || {})[node] || [];
            const hit = local.find(s => s && s.storage === name);
            return hit ? { store: hit, node } : null;
        }

        // What a row is about, and whether that exists in the inventory the user sees: a guest
        // (vmid), a storage (the task id names one), or the node of a node task
        function crTaskTarget(row, nav) {
            if (!row || !nav) return null;
            const cid = row.cluster_id;
            if (row._job) {
                const r = row._run || {};
                return { kind: 'text', label: row._job === 'bulk' ? (r.target ? `→ ${r.target}` : '') : (r.storage || '') };
            }
            // the portal rows of the audit log carry vmid 0 for "no guest"; classic shows a VMID only when it is set
            const raw = row.vmid ? row.vmid : row.id;
            const id = raw == null || String(raw) === '0' ? '' : String(raw);
            if (/^\d+$/.test(id)) {
                const g = crGuestMap(nav.guestsOf && nav.guestsOf(cid));
                const guest = g && g.get(id);
                return guest ? { kind: 'guest', guest, label: guest.name ? `${guest.name} (${id})` : id, text: `${guest.name || ''} ${id}` }
                    : { kind: 'text', label: id, text: id };
            }
            if (id) {
                const s = crFindStore(nav.storesOf && nav.storesOf(cid), id, row.node);
                return s ? { kind: 'storage', store: s.store, node: s.node, label: id, text: id } : { kind: 'text', label: id, text: id };
            }
            if (row.node) {
                const nodes = nav.nodesOf && nav.nodesOf(cid);
                const known = !!(nodes && Object.prototype.hasOwnProperty.call(nodes, row.node));
                return known ? { kind: 'node', name: row.node, label: row.node, text: row.node } : { kind: 'text', label: row.node, text: row.node };
            }
            return null;
        }

        // --- reads ------------------------------------------------------------------

        // Every read of the task center goes through here: at most CR_TC.parallel in flight, the
        // rest waits; a job whose signal ended before its turn is dropped
        const crTcQueue = (() => {
            let busy = 0;
            const waiting = [];
            const pump = () => {
                while (busy < CR_TC.parallel && waiting.length) {
                    const { job, signal, done } = waiting.shift();
                    if (signal.aborted) { done(); continue; }
                    busy++;
                    Promise.resolve().then(job).catch(() => {}).then(() => { busy--; done(); pump(); });
                }
            };
            return { run: (job, signal) => new Promise(done => { waiting.push({ job, signal, done }); pump(); }) };
        })();

        function crReadTasksJob(authFetch, cid, signal) {
            return async () => {
                crTaskFeed.pending(cid, true);
                const res = await authFetch(`${API_URL}/clusters/${cid}/tasks`, { signal });
                if (signal.aborted) { crTaskFeed.pending(cid, false); return; }
                const data = res && res.ok ? await res.json().catch(() => null) : null;
                if (signal.aborted) { crTaskFeed.pending(cid, false); return; }
                if (Array.isArray(data)) crTaskFeed.loaded(cid, data);
                else crTaskFeed.failed(cid, res ? res.status : 0);
            };
        }

        function crReadJobsJob(authFetch, kind, signal) {
            return async () => {
                const res = await authFetch(`${API_URL}/${kind === 'bulk' ? 'bulk-migrations' : 'batch-restores'}`, { signal });
                if (signal.aborted) return;
                const data = res && res.ok ? await res.json().catch(() => null) : null;
                if (signal.aborted) return;
                crTaskFeed.jobs(kind, data && Array.isArray(data.runs) ? data.runs : null, res ? res.status : 0);
            };
        }

        // The log of the one task that is open (the pane or the dialog): read once when it opens,
        // and while the task runs the new lines every 2 s with ?start=, as the backup pane does
        function crUseTaskLog(row, on, authFetch, t) {
            const key = row ? crTaskKey(row) : null;
            const running = !!row && crTaskState(row) === 'running';
            const [st, setSt] = useState({ key: null, lines: [], loading: false, error: '' });
            const [again, setAgain] = useState(0);
            const kept = useRef({ key: null, lines: [] });
            const rowRef = useRef(row);
            rowRef.current = row;
            useEffect(() => {
                const r = rowRef.current;
                if (!on || !r || !r.node || !r.upid || !r.cluster_id || r._job || !authFetch) return undefined;
                if (kept.current.key !== key) kept.current = { key, lines: [] };
                let gone = false;
                let timer = null;
                const ctrl = new AbortController();
                setSt({ key, lines: kept.current.lines, loading: !kept.current.lines.length, error: '' });
                const read = async () => {
                    const url = `${API_URL}/clusters/${r.cluster_id}/nodes/${r.node}/tasks/${encodeURIComponent(r.upid)}/log`
                        + `?start=${kept.current.lines.length}&limit=${CR_TC.logLimit}`;
                    const res = await authFetch(url, { signal: ctrl.signal });
                    if (gone) return;
                    if (!res || !res.ok) {
                        setSt(s => ({ ...s, key, loading: false, error: res && res.status === 403 ? t('crTaskNoAccess') : t('errorLoadingLog') }));
                        return;
                    }
                    const data = await res.json().catch(() => null);
                    if (gone) return;
                    let arr = data && Array.isArray(data.lines) ? data.lines
                        : (data && typeof data.log === 'string' && data.log ? data.log.split('\n') : []);
                    arr = arr.map(l => (l && l.t !== undefined ? l.t : String(l)));
                    // Proxmox answers an empty log with one 'no content' line
                    if (arr.length === 1 && arr[0] === 'no content') arr = [];
                    if (arr.length) kept.current = { key, lines: kept.current.lines.concat(arr) };
                    setSt({ key, lines: kept.current.lines, loading: false, error: '' });
                };
                const loop = async () => {
                    await read();
                    if (!gone && running) timer = setTimeout(loop, CR_TC.logEvery);
                };
                loop();
                return () => { gone = true; clearTimeout(timer); ctrl.abort(); };
            }, [key, on, running, again, authFetch]);
            const mine = st.key === key;
            return {
                lines: mine ? st.lines : [],
                loading: mine ? st.loading : !!on,
                error: mine ? st.error : '',
                reload: () => { kept.current = { key: null, lines: [] }; setAgain(n => n + 1); },
            };
        }

        // --- small pieces -------------------------------------------------------------

        // one 1 s beat for every live duration on screen; it stops with the last one
        const crTick = { subs: new Set(), timer: null };
        function crUseTick(on) {
            const [, bump] = React.useReducer(x => x + 1, 0);
            useEffect(() => {
                if (!on) return undefined;
                crTick.subs.add(bump);
                if (!crTick.timer) crTick.timer = setInterval(() => crTick.subs.forEach(fn => fn()), 1000);
                return () => {
                    crTick.subs.delete(bump);
                    if (!crTick.subs.size && crTick.timer) { clearInterval(crTick.timer); crTick.timer = null; }
                };
            }, [on]);
        }

        function CrDuration({ task, fmt }) {
            crUseTick(crTaskState(task) === 'running' && !!task.starttime);
            return <span>{crDurationText(task, fmt)}</span>;
        }

        function CrTaskProgress({ task, pct, t }) {
            if (task._job) {
                const v = task._total ? Math.round(task._over * 100 / task._total) : 0;
                const label = t('crUsedOf').replace('{used}', task._over).replace('{total}', task._total);
                return (
                    <span className="cr-tc-progress">
                        <span className="cr-tc-meter" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
                            <span style={{ width: `${v}%` }} />
                        </span>
                        <span className="cr-tc-pct">{label}</span>
                    </span>
                );
            }
            if (crTaskState(task) !== 'running') return null;
            if (pct == null) {
                return (
                    <span className="cr-tc-progress" data-cr-tc-busy="">
                        <span className="cr-tc-meter cr-tc-meter-busy" role="progressbar" aria-label={t('crTaskNoPercent')}><span /></span>
                    </span>
                );
            }
            const v = Math.round(pct * 10) / 10;
            return (
                <span className="cr-tc-progress" data-cr-tc-pct={v}>
                    <span className="cr-tc-meter" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={t('progress')}>
                        <span style={{ width: `${v}%` }} />
                    </span>
                    <span className="cr-tc-pct">{v}%</span>
                </span>
            );
        }

        // Tab and Shift+Tab inside a modal box: the next or previous control in it, round at the ends
        function crKeepTab(e, box) {
            if (!box) return;
            const list = Array.from(box.querySelectorAll('button, [href], input, select, textarea, [tabindex]'))
                .filter(el => el.tabIndex >= 0 && !el.disabled && el.getClientRects().length);
            e.preventDefault();
            if (!list.length) return;
            const a = document.activeElement;
            const after = (el) => !!(a.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);
            let next;
            if (!a || !box.contains(a)) next = e.shiftKey ? list[list.length - 1] : list[0];
            else if (e.shiftKey) next = list.filter(el => el !== a && !after(el)).pop() || list[list.length - 1];
            else next = list.find(el => el !== a && after(el)) || list[0];
            next.focus({ preventScroll: true });
        }

        // --- the log pane in the drawer -------------------------------------------------

        // LW Nov 2026 - mark: {tone, label} of a view that reads the state its own way (the node's task
        // list keeps Warning apart); without onDetails there is no Details button
        function CrTaskLogPane({ row, log, title, fmt, onClose, onDetails, mark, t }) {
            const pre = useRef(null);
            const state = crTaskState(row);
            const tone = mark ? mark.tone : crTaskTone(row);
            const pct = state === 'running' ? crParseProgress(log.lines) : null;
            const text = log.lines.join('\n');
            // a running task's log follows its end
            useEffect(() => {
                if (state === 'running' && pre.current) pre.current.scrollTop = pre.current.scrollHeight;
            }, [text, state]);
            const result = crTaskResult(row);
            return (
                <aside className="cr-tc-log" aria-label={t('crTaskLogOf').replace('{task}', title)} data-cr-tc-log={crTaskKey(row)}>
                    <div className="cr-tc-log-head">
                        <span className={`cr-dot cr-dot-${tone}`} aria-hidden="true" />
                        <span className="cr-strong cr-tc-log-title">{title}</span>
                        <CrBadge tone={tone}>{mark ? mark.label : crTaskLabel(state, t)}</CrBadge>
                        <span className="cr-tc-grow" />
                        {onDetails && <button type="button" className="cr-btn cr-btn-ghost" onClick={onDetails} data-cr-tc-details="">{t('crTaskDetails')}</button>}
                        <button type="button" className="cr-icon-btn" onClick={log.reload} aria-label={t('refresh')} title={t('refresh')}>
                            <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>
                        </button>
                        <button type="button" className="cr-icon-btn" onClick={onClose} aria-label={t('crTaskHideLog')} title={t('crTaskHideLog')} data-cr-tc-log-close="">
                            <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                        </button>
                    </div>
                    <div className="cr-tc-log-meta">
                        {row.node && <span>{t('node')}: {row.node}</span>}
                        <span>{t('duration')}: <CrDuration task={row} fmt={fmt} /></span>
                        {state !== 'running' && result && <span className={`cr-tc-result cr-tc-result-${tone}`} title={result}>{result}</span>}
                    </div>
                    {state === 'running' && (
                        <div className="cr-tc-log-progress">
                            <CrTaskProgress task={row} pct={pct} t={t} />
                            {pct == null && <span className="cr-muted">{t('crTaskNoPercent')}</span>}
                        </div>
                    )}
                    {log.error ? (
                        <div className="cr-tc-log-body cr-state-error" role="alert">{log.error}</div>
                    ) : log.loading ? (
                        <div className="cr-tc-log-body cr-muted"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</div>
                    ) : (
                        <pre ref={pre} className="cr-tc-log-body" tabIndex={0} aria-label={t('taskOutput')}>{text || t('noOutput')}</pre>
                    )}
                </aside>
            );
        }

        // --- the task center ----------------------------------------------------------

        function crTcHeight() {
            const max = Math.round(window.innerHeight * CR_TC.maxPart);
            const n = parseInt(crRead('cr-tc-h'), 10);
            return Number.isFinite(n) ? crClamp(n, CR_TC.minH, Math.max(CR_TC.minH, max)) : Math.round(window.innerHeight * CR_TC.defPart);
        }
        const CR_TC_STATUSES = ['all', 'running', 'queued', 'completed', 'failed', 'cancelled'];
        function crTcFilters() {
            const f = crReadJson('cr-tc-filters') || {};
            return {
                status: CR_TC_STATUSES.includes(f.status) ? f.status : 'all',
                type: typeof f.type === 'string' ? f.type : '',
                cluster: typeof f.cluster === 'string' ? f.cluster : '',
                q: typeof f.q === 'string' ? f.q : '',
                today: f.today === true,
            };
        }
        // LW Nov 2026 - the classic "Today's tasks": started since midnight in this browser
        function crTaskToday(r, dayStart) {
            return !!r.starttime && r.starttime * 1000 >= dayStart;
        }

        // The bar and the drawer. TaskBar keeps the selected cluster's list, the open state (its
        // auto-expand of #738 included) and the classic detail dialog; everything else is here.
        function CrTaskCenter({ tasks, expanded, setExpanded, clusterId, clusterName, onRefresh, onCancel,
                                formatTaskType, formatDuration, renderDetail, nav }) {
            const { t } = useTranslation();
            // what "Clear completed" took away belongs to this account (the user is read again below)
            crSessionFor(useAuth().user);
            const navRef = useRef(nav);
            navRef.current = nav;
            const fmtRef = useRef({ type: formatTaskType, dur: formatDuration });
            fmtRef.current = { type: formatTaskType, dur: formatDuration };
            const authFetch = nav && nav.authFetch;
            const clusters = nav && Array.isArray(nav.clusters) ? nav.clusters : [];
            const ids = clusters.map(c => c.id).join(',');

            const ver = React.useSyncExternalStore(crTaskFeed.subscribe, crTaskFeed.version);
            useEffect(() => crTaskFeed.attach(), []);
            // the page makes room for the bar while it is there (CSS)
            useEffect(() => {
                document.body.dataset.crTasks = '1';
                return () => { delete document.body.dataset.crTasks; };
            }, []);

            // scope: the pick holds until the cluster changes
            const [scopePick, setScopePick] = useState(null);
            useEffect(() => { setScopePick(null); }, [clusterId]);
            const scope = scopePick || (clusterId ? 'cluster' : 'all');
            // when the selected cluster's list was asked for: after a switch the list is loading until the next
            // answer. On mount an answer the feed already holds counts (the feed outlives a hidden bar)
            const switched = useRef(null);
            if (!switched.current) switched.current = { cid: clusterId, seq: 0 };
            else if (switched.current.cid !== clusterId) switched.current = { cid: clusterId, seq: crTaskFeed.seq };
            const switchSeq = switched.current.seq;

            const [cleared, setCleared] = useState(0);
            const { list: rows, clearedN } = useMemo(() => {
                let list = [];
                const add = (cid, src) => {
                    if (!cid || !Array.isArray(src)) return;
                    const tagged = crTagged(cid, src);
                    for (let i = 0; i < tagged.length; i++) list.push(tagged[i]);
                };
                if (scope === 'cluster') add(clusterId, tasks);
                else {
                    if (clusterId) add(clusterId, tasks);
                    ids.split(',').forEach(cid => {
                        if (!cid || cid === clusterId) return;
                        const e = crTaskFeed.get(cid);
                        if (e && e.list) add(cid, e.list);
                    });
                }
                const marks = crTaskFeed.marks();
                if (Object.keys(marks).length) {
                    list = list.map(r => {
                        const m = marks[crTaskKey(r)];
                        return m && crTaskState(r) === 'running' ? { ...r, ...m } : r;
                    });
                }
                ['bulk', 'restore'].forEach(kind => crJobRows(kind, crTaskFeed.job(kind)).forEach(r => {
                    if (scope === 'all' || r.cluster_id === clusterId) list.push(r);
                }));
                const all = list.length;
                if (crTaskDismissed.size) {
                    list = list.filter(r => !crTaskDismissed.has(crTaskKey(r)) || ['running', 'queued'].includes(crTaskState(r)));
                }
                list.sort((a, b) => (b.starttime || 0) - (a.starttime || 0) || String(a.upid).localeCompare(String(b.upid)));
                return { list, clearedN: all - list.length };
            }, [scope, clusterId, tasks, ver, ids, cleared]);
            const counts = useMemo(() => crTaskCounts(rows), [rows]);

            // --- reads on open and on refresh, never on a timer ---
            const coverage = useMemo(() => {
                const out = [];
                clusters.forEach(c => {
                    const e = crTaskFeed.get(c.id);
                    let st;
                    if (c.connected === false) st = 'offline';
                    else if (c.id === clusterId) st = 'live';
                    else if (e && e.pending) st = 'loading';
                    else if (e && e.list && e.state === 'ok') st = e.via === 'sse' && Date.now() - e.at < CR_TC.fresh ? 'live' : 'read';
                    else if (e && (e.state === 'error' || e.state === 'denied')) st = e.state;
                    else st = 'none';
                    // the selected cluster: its list comes from the page; a refused or failed read with no
                    // row is no list (an empty one is the answer of a cluster without tasks)
                    if (st === 'live' && c.id === clusterId && !tasks.length && e && e.asked > switchSeq
                        && (e.state === 'error' || e.state === 'denied')) st = e.state;
                    out.push({ c, st, at: e ? e.at : 0, hasList: c.id === clusterId ? st === 'live' : !!(e && e.list) });
                });
                return out;
            }, [ids, ver, clusterId, clusters, tasks, switchSeq]);
            const connected = coverage.filter(x => x.st !== 'offline');
            const covered = connected.filter(x => x.hasList).length;

            const may = (p) => !!(nav && nav.may && nav.may(p));
            // what waits to start: the two job registries, each only for a user who may read it
            const readJobs = (signal) => {
                if (!authFetch) return;
                if (may('vm.view')) crTcQueue.run(crReadJobsJob(authFetch, 'bulk', signal), signal);
                if (may('backup.view')) crTcQueue.run(crReadJobsJob(authFetch, 'restore', signal), signal);
            };
            // the other clusters: nothing for one the stream keeps live, or (on open) one read a moment ago
            const readClusters = (signal, onOpen) => {
                if (!authFetch) return;
                const now = Date.now();
                ((navRef.current && navRef.current.clusters) || []).forEach(c => {
                    if (!c || c.connected === false || c.id === clusterId) return;
                    const e = crTaskFeed.get(c.id);
                    if (e && e.list && now - e.at < CR_TC.fresh && (e.via === 'sse' || onOpen)) return;
                    crTcQueue.run(crReadTasksJob(authFetch, c.id, signal), signal);
                });
            };
            const jobsCtrl = useRef(null);
            const listsCtrl = useRef(null);
            const restart = (ref) => {
                if (ref.current) ref.current.abort();
                ref.current = new AbortController();
                return ref.current.signal;
            };
            const stop = (ref) => { if (ref.current) { ref.current.abort(); ref.current = null; } };
            useEffect(() => {
                if (!expanded) return undefined;
                readJobs(restart(jobsCtrl));
                return () => stop(jobsCtrl);
            }, [expanded]);
            useEffect(() => {
                if (!expanded || scope !== 'all') return undefined;
                readClusters(restart(listsCtrl), true);
                return () => stop(listsCtrl);
            }, [expanded, scope]);
            const refresh = () => {
                if (scope === 'cluster' && onRefresh) onRefresh();
                readJobs(restart(jobsCtrl));
                if (scope === 'all') readClusters(restart(listsCtrl), false);
            };

            // --- filters ---
            const [filters, setFilters] = useState(crTcFilters);
            const keepFilters = (patch) => setFilters(f => {
                const next = { ...f, ...patch };
                crWrite('cr-tc-filters', JSON.stringify(next));
                return next;
            });
            // LW Oct 2026 - a page of the redesign hands over a task it started: the drawer opens on its
            // guest (the resource filter), in the scope of its cluster. Only for now: the filters the
            // user keeps are not overwritten by it
            useEffect(() => {
                const onOpen = (e) => {
                    const d = (e && e.detail) || {};
                    setScopePick(d.cluster && d.cluster !== clusterId ? 'all' : null);
                    setFilters(f => ({ ...f, status: 'all', type: '', cluster: '', today: false, q: d.q != null ? String(d.q) : '' }));
                    setExpanded(true);
                };
                window.addEventListener('cr-tc-open', onOpen);
                return () => window.removeEventListener('cr-tc-open', onOpen);
            }, [clusterId]);
            const types = useMemo(() => {
                const seen = new Map();
                rows.forEach(r => { if (r.type && !seen.has(r.type)) seen.set(r.type, crOpLabel(r)); });
                if (filters.type && !seen.has(filters.type)) seen.set(filters.type, crOpLabel({ type: filters.type }));
                return Array.from(seen.entries()).sort((a, b) => a[1].localeCompare(b[1]));
            }, [rows, filters.type, t]);
            // a remembered cluster that is not there any more is left out
            const fCluster = scope === 'all' && filters.cluster && ids.split(',').includes(filters.cluster) ? filters.cluster : '';
            const q = filters.q.trim().toLowerCase();
            const day = new Date().toDateString();
            const dayStart = useMemo(() => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime(); }, [day]);
            const matchBase = useMemo(() => (r) => {
                if (filters.type && r.type !== filters.type) return false;
                if (fCluster && r.cluster_id !== fCluster) return false;
                if (q) {
                    const tg = crTaskTarget(r, navRef.current);
                    const hay = `${tg ? tg.text || tg.label : ''} ${r.vmid || ''} ${r.node || ''} ${r.id || ''}`.toLowerCase();
                    if (!hay.includes(q)) return false;
                }
                return true;
            }, [filters.type, fCluster, q]);
            const match = useMemo(() => (filters.today ? (r) => matchBase(r) && crTaskToday(r, dayStart) : matchBase),
                [matchBase, filters.today, dayStart]);
            const stripCounts = useMemo(() => {
                const shown = rows.filter(match);
                return { ...crTaskCounts(shown), all: shown.length };
            }, [rows, match]);
            const todayCount = useMemo(() => rows.filter(r => matchBase(r) && crTaskToday(r, dayStart)).length, [rows, matchBase, dayStart]);
            const tableFilter = useMemo(() => {
                const want = filters.status;
                return (r) => (want === 'all' || CR_TC_BUCKET[crTaskState(r)] === want) && match(r);
            }, [filters.status, match]);
            const activeFilters = (filters.status !== 'all' ? 1 : 0) + (filters.type ? 1 : 0) + (fCluster ? 1 : 0) + (q ? 1 : 0) + (filters.today ? 1 : 0);

            // --- the open task: the log pane, the classic dialog ---
            const [logKey, setLogKey] = useState(null);
            const [dialogKey, setDialogKey] = useState(null);
            const byKey = (k) => (k ? rows.find(r => crTaskKey(r) === k) || null : null);
            // the last row seen keeps the pane and the dialog up when a frame drops the task
            const lastRow = useRef({});
            const live = (k) => {
                if (!k) return null;
                const r = byKey(k);
                if (r) lastRow.current[k] = r;
                return r || lastRow.current[k] || null;
            };
            const logRow = live(logKey);
            const dialogRow = live(dialogKey);
            // the pane belongs to the open drawer and to the scope on screen; it reads nothing otherwise
            const paneRow = logRow && expanded && (scope === 'all' || logRow.cluster_id === clusterId) ? logRow : null;
            const paneLog = crUseTaskLog(paneRow, !!paneRow && !dialogRow, authFetch, t);
            const dialogLog = crUseTaskLog(dialogRow, !!dialogRow, authFetch, t);
            const pctOf = (r) => {
                if (crTaskState(r) !== 'running') return null;
                const k = crTaskKey(r);
                if (k === dialogKey) return crParseProgress(dialogLog.lines);
                if (paneRow && k === logKey) return crParseProgress(paneLog.lines);
                return null;
            };
            // ... and closes with the drawer, a cluster switch and a scope switch
            useEffect(() => {
                setLogKey(null);
                const keep = dialogKey && lastRow.current[dialogKey];
                lastRow.current = keep ? { [dialogKey]: keep } : {};
            }, [expanded, clusterId, scope]);
            const pctRef = useRef(pctOf);
            pctRef.current = pctOf;
            const backTo = useRef(null);
            const openDialog = (r) => {
                if (!r || r._job) return;
                backTo.current = document.activeElement;
                setDialogKey(crTaskKey(r));
            };
            const closeDialog = () => {
                setDialogKey(null);
                const el = backTo.current;
                backTo.current = null;
                if (el && el.isConnected && el.focus) el.focus({ preventScroll: true });
            };
            const openRow = (r) => {
                if (r._job === 'bulk' && nav && nav.openBulkRun) {
                    // the run's own dialog sits under the drawer
                    setExpanded(false);
                    nav.openBulkRun(r._run.id);
                    return;
                }
                openDialog(r);
            };

            // --- open, close, resize ---
            const hitRef = useRef(null);
            const barRef = useRef(null);
            const rootRef = useRef(null);
            const layerRef = useRef(null);
            // LW Nov 2026 - open or closed is kept per user in this browser (the preference API has
            // no field for it). Only the user's own toggle writes it: the auto-expand of #738 and a
            // page that hands a task over open the drawer for now and leave the choice as it was
            const { user } = useAuth();
            const openKey = `cr-tc-open:${(user && user.username) || ''}`;
            const toggle = (next) => {
                setExpanded(next);
                crWrite(openKey, next ? '1' : null);
            };
            React.useLayoutEffect(() => {
                if (crRead(openKey) === '1') setExpanded(true);
            }, [openKey]);
            const close = () => {
                toggle(false);
                if (hitRef.current) hitRef.current.focus({ preventScroll: true });
            };
            // a click on the bar beside its own controls toggles; the end of a drag or of a text
            // selection in it does not (the resize grip is no part of the bar, so it never gets here)
            const downAt = useRef(null);
            const onBarDown = (e) => { downAt.current = e.button === 0 ? { x: e.clientX, y: e.clientY } : null; };
            const pressed = (e) => {
                const d = downAt.current;
                downAt.current = null;
                if (e.detail === 0) return true;
                if (!d || Math.abs(e.clientX - d.x) > 4 || Math.abs(e.clientY - d.y) > 4) return false;
                const sel = window.getSelection ? window.getSelection() : null;
                return !(sel && !sel.isCollapsed && barRef.current && sel.anchorNode && barRef.current.contains(sel.anchorNode));
            };
            const onBarClick = (e) => {
                if (e.target && e.target.closest && e.target.closest('button, a, input, select, textarea, [data-cr-tc-ctl] *, .cr-click-away')) return;
                if (!pressed(e)) return;
                // closing takes the drawer the focus may be in: the bar keeps it
                if (expanded) close();
                else toggle(true);
            };
            const onHitClick = (e) => {
                e.stopPropagation();
                if (pressed(e)) toggle(!expanded);
            };
            const [coverOpen, setCoverOpen] = useState(false);
            const [menu, setMenu] = useState(null);
            const [h, setH] = useState(crTcHeight);
            const hRef = useRef(h);
            hRef.current = h;
            const maxH = () => Math.max(CR_TC.minH, Math.round(window.innerHeight * CR_TC.maxPart));
            const keepH = (v) => { const n = crClamp(Math.round(v), CR_TC.minH, maxH()); setH(n); crWrite('cr-tc-h', n); };
            const startDrag = (e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                const grip = e.currentTarget;
                const y0 = e.clientY;
                const h0 = hRef.current;
                let v = h0;
                try { grip.setPointerCapture(e.pointerId); } catch (_) {}
                document.body.classList.add('cr-tc-resizing');
                const move = (ev) => { v = crClamp(h0 + (y0 - ev.clientY), CR_TC.minH, maxH()); setH(v); };
                const up = () => {
                    grip.removeEventListener('pointermove', move);
                    grip.removeEventListener('pointerup', up);
                    grip.removeEventListener('pointercancel', up);
                    document.body.classList.remove('cr-tc-resizing');
                    keepH(v);
                };
                grip.addEventListener('pointermove', move);
                grip.addEventListener('pointerup', up);
                grip.addEventListener('pointercancel', up);
            };
            const keyResize = (e) => {
                const step = { ArrowUp: 16, ArrowDown: -16, PageUp: 64, PageDown: -64 }[e.key];
                if (step) { e.preventDefault(); keepH(hRef.current + step); }
                else if (e.key === 'Home') { e.preventDefault(); keepH(CR_TC.minH); }
                else if (e.key === 'End') { e.preventDefault(); keepH(maxH()); }
            };
            const resetH = () => { crWrite('cr-tc-h', null); setH(Math.round(window.innerHeight * CR_TC.defPart)); };
            useEffect(() => {
                const fit = () => setH(v => crClamp(v, CR_TC.minH, maxH()));
                window.addEventListener('resize', fit);
                return () => window.removeEventListener('resize', fit);
            }, []);

            // Escape: the dialog first, then the cluster list, the log pane, then the drawer.
            // The dialog is modal, so Tab stays in it
            const escRef = useRef(null);
            escRef.current = (e) => {
                if (e.defaultPrevented) return;
                if (e.key === 'Tab' && dialogKey) { crKeepTab(e, layerRef.current); return; }
                if (e.key !== 'Escape') return;
                if (dialogKey) { e.preventDefault(); closeDialog(); return; }
                // a menu of the table closes itself on the same key
                if (e.target && e.target.closest && e.target.closest('.cr-menu, [role="menu"]')) return;
                if (!expanded) return;
                const a = document.activeElement;
                const mine = rootRef.current && a && rootRef.current.contains(a);
                if (!mine && a && a !== document.body) return;
                if (a && a.tagName === 'INPUT' && a.value) return;
                e.preventDefault();
                if (coverOpen) { setCoverOpen(false); return; }
                if (paneRow) { setLogKey(null); return; }
                close();
            };
            useEffect(() => {
                if (!expanded && !dialogKey) return undefined;
                const onKey = (e) => escRef.current && escRef.current(e);
                document.addEventListener('keydown', onKey);
                return () => document.removeEventListener('keydown', onKey);
            }, [expanded, !!dialogKey]);
            // the dialog takes the keyboard while it is open
            useEffect(() => {
                if (!dialogKey || !layerRef.current) return;
                const b = layerRef.current.querySelector('button');
                if (b) b.focus({ preventScroll: true });
            }, [dialogKey]);
            useEffect(() => { if (!expanded) { setCoverOpen(false); setMenu(null); } }, [expanded]);

            // --- the table ---
            function crOpLabel(r) {
                if (r._job === 'bulk') return t('crTaskQueuedBulk');
                if (r._job === 'restore') return t('crTaskQueuedRestore');
                return fmtRef.current.type ? fmtRef.current.type(r.type) : (r.type || '');
            }
            const clusterNameOf = (cid) => {
                const c = (navRef.current && navRef.current.clusters || []).find(x => x.id === cid);
                return c ? clusterLabel(c) : (cid || '');
            };
            const who = (r) => r.pegaprox_user || (r.user ? String(r.user).split('@')[0] : '');
            const go = (fn) => (e) => { e.stopPropagation(); fn(); };
            const openTarget = (r, tg) => {
                const n = navRef.current;
                if (!n || !tg) return;
                if (tg.kind === 'guest' && n.openGuest) n.openGuest(r.cluster_id, tg.guest);
                else if (tg.kind === 'node' && n.openNode) n.openNode(r.cluster_id, tg.name);
                else if (tg.kind === 'storage' && n.openStorage) n.openStorage(r.cluster_id, tg.store, tg.node);
            };
            const resultOf = (r) => {
                if (r._job) return t('crTaskWaiting').replace('{n}', r._wait).replace('{total}', r._total);
                const s = crTaskState(r);
                return s === 'running' || s === 'queued' ? '' : crTaskResult(r);
            };
            const showLog = (r) => setLogKey(k => (k === crTaskKey(r) ? k : crTaskKey(r)));
            const columns = useMemo(() => [
                { key: 'state', label: t('status'), width: 104, sortValue: r => CR_TC_ORDER[crTaskState(r)],
                  text: r => crTaskLabel(crTaskState(r), t),
                  render: r => {
                      const tone = crTaskTone(r);
                      return (
                          <span data-cr-tc-key={crTaskKey(r)}>
                              <CrBadge tone={tone} title={tone === 'warning' && crTaskState(r) === 'done' ? crTaskResult(r) : undefined}>{crTaskLabel(crTaskState(r), t)}</CrBadge>
                          </span>
                      );
                  } },
                { key: 'type', label: t('crTaskOperation'), flex: true, min: 130, sortValue: r => crOpLabel(r), text: r => crOpLabel(r),
                  render: r => <span className="cr-strong" title={r.type}>{crOpLabel(r)}</span> },
                { key: 'resource', label: t('crTaskResource'), width: 150,
                  sortValue: r => { const tg = crTaskTarget(r, navRef.current); return tg ? tg.label : null; },
                  render: r => {
                      const tg = crTaskTarget(r, navRef.current);
                      if (!tg) return null;
                      if (tg.kind === 'text') return <span title={tg.label}>{tg.label}</span>;
                      return (
                          <button type="button" className="cr-tc-link" tabIndex={-1} onClick={go(() => openTarget(r, tg))}
                              title={t('crTaskOpenTarget').replace('{name}', tg.label)} data-cr-tc-target={tg.kind}>{tg.label}</button>
                      );
                  } },
                { key: 'cluster', label: t('cluster'), width: 120, hidden: scope === 'cluster',
                  sortValue: r => clusterNameOf(r.cluster_id),
                  render: r => {
                      const n = navRef.current;
                      const known = n && (n.clusters || []).some(c => c.id === r.cluster_id);
                      const name = clusterNameOf(r.cluster_id);
                      return known && n.openCluster ? (
                          <button type="button" className="cr-tc-link" tabIndex={-1} onClick={go(() => n.openCluster(r.cluster_id))}
                              title={t('crTaskOpenTarget').replace('{name}', name)} data-cr-tc-target="cluster">{name}</button>
                      ) : <span>{name}</span>;
                  } },
                { key: 'node', label: t('node'), width: 90 },
                { key: 'user', label: t('user'), width: 90, sortValue: who,
                  render: r => <span title={r.pegaprox_user ? `PegaProx: ${r.pegaprox_user}\nProxmox: ${r.user || '-'}` : (r.user || '')}>{who(r)}</span> },
                { key: 'starttime', label: t('startTime'), width: 160, mono: true, sortValue: r => r.starttime || null,
                  render: r => (r.starttime ? crDate(r.starttime) : '') },
                { key: 'endtime', label: t('endTime'), width: 160, mono: true, sortValue: r => (crTaskState(r) === 'running' ? null : r.endtime || null),
                  render: r => (r.endtime && crTaskState(r) !== 'running' ? crDate(r.endtime) : '') },
                { key: 'duration', label: t('duration'), width: 88, mono: true, align: 'right',
                  sortValue: r => (!r.starttime ? null : crTaskState(r) === 'running' ? Date.now() / 1000 - r.starttime : (r.endtime ? r.endtime - r.starttime : null)),
                  render: r => <CrDuration task={r} fmt={fmtRef.current.dur} /> },
                { key: 'progress', label: t('progress'), width: 112, sortable: false,
                  render: r => <CrTaskProgress task={r} pct={pctRef.current(r)} t={t} /> },
                { key: 'result', label: t('crTaskResult'), flex: true, min: 150, sortValue: r => resultOf(r) || null, text: resultOf,
                  render: r => {
                      const text = resultOf(r);
                      const s = crTaskState(r);
                      const tone = crTaskTone(r);
                      const logged = !r._job && r.node && r.upid && (s === 'failed' || s === 'cancelled' || tone === 'warning');
                      return (
                          <span className="cr-tc-resultcell">
                              {text && <span className={`cr-tc-result cr-tc-result-${r._job ? 'neutral' : tone}`} title={text}>{text}</span>}
                              {logged && (
                                  <button type="button" className="cr-tc-link cr-tc-showlog" tabIndex={-1} onClick={go(() => showLog(r))}
                                      data-cr-tc-showlog="">{t('crTaskShowLog')}</button>
                              )}
                          </span>
                      );
                  } },
            ], [t, scope]);

            const openMenu = (r, e) => {
                const items = [];
                if (!r._job) items.push({ label: t('crTaskDetails'), icon: <Icons.Info className="w-3.5 h-3.5" />, onClick: () => openDialog(r) });
                if (!r._job && r.node && r.upid) items.push({ label: t('crTaskShowLog'), icon: <Icons.FileText className="w-3.5 h-3.5" />, onClick: () => showLog(r) });
                if (r._job === 'bulk' && nav && nav.openBulkRun) items.push({ label: t('crOpen'), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: () => openRow(r) });
                const tg = crTaskTarget(r, navRef.current);
                if (tg && tg.kind !== 'text') {
                    items.push({ separator: true });
                    items.push({ label: t('crTaskOpenTarget').replace('{name}', tg.label), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: () => openTarget(r, tg) });
                }
                if (scope === 'all' && nav && nav.openCluster && clusters.some(c => c.id === r.cluster_id)) {
                    items.push({ label: t('crTaskOpenTarget').replace('{name}', clusterNameOf(r.cluster_id)), icon: <Icons.Server className="w-3.5 h-3.5" />, onClick: () => nav.openCluster(r.cluster_id) });
                }
                if (!items.length) return;
                setMenu({ back: document.activeElement, position: { x: e.clientX, y: e.clientY }, items });
            };

            // --- what the bar says ---
            // LW Nov 2026 - the task that runs now, newest first; with none running the newest one, said as the last
            const running = rows.filter(r => !r._job && crTaskState(r) === 'running');
            const latest = running[0] || rows.find(r => !r._job) || null;
            const latestRuns = !!running[0];
            const scopeText = scope === 'cluster' ? (clusterName || '') : t('allClusters');
            // Queued is what the two job registries said: a number only once one of them was read
            const jobKinds = [['bulk', 'vm.view'], ['restore', 'backup.view']].filter(([, p]) => may(p)).map(([k]) => k);
            const jobsRead = jobKinds.map(k => crTaskFeed.job(k)).filter(j => j && j.state === 'ok');
            const jobsState = !jobKinds.length ? 'denied' : jobsRead.length ? 'read' : 'unread';
            const queuedHint = t('crTaskQueuedHint') + ' ' + (jobsState === 'denied' ? t('crTcJobsNoAccess')
                : jobsState === 'read'
                    ? t('crTaskJobsReadAt').replace('{time}', new Date(Math.max(...jobsRead.map(j => j.at || 0))).toLocaleTimeString(crLocale()))
                        + (jobsRead.length < jobKinds.length || jobKinds.length < 2 ? ' ' + t('crTcJobsPart') : '')
                    : t('crTaskJobsNotRead'));
            const coverText = scope === 'all' && connected.length
                ? t('crTaskReadOf').replace('{n}', covered).replace('{m}', connected.length) : '';
            const anyPending = scope === 'all' && coverage.some(x => x.st === 'loading');
            const own = clusterId ? crTaskFeed.get(clusterId) : null;
            const ownAnswered = !!(own && own.asked > switchSeq);
            const loading = scope === 'cluster' ? (!!clusterId && !tasks.length && !ownAnswered) : anyPending;
            // no list in scope came yet (or the one cluster is not connected, whose list the server answers
            // empty): the counts are not known, not zero
            const ownOffline = !!clusterId && clusters.some(c => c.id === clusterId && c.connected === false);
            // LW Nov 2026 - a refused or failed read of the cluster's list is no count of zero either
            const ownFailed = ownAnswered && (own.state === 'denied' || own.state === 'error');
            const countsUnread = scope === 'all' ? covered === 0 : (!!clusterId && !tasks.length && (!ownAnswered || ownOffline || ownFailed));
            const known = (v) => (countsUnread ? null : v);
            const barCounts = [
                ['running', known(counts.running), t('running'), 'info'],
                ['queued', jobsState === 'read' ? counts.queued : null, t('crTaskQueued'), 'neutral', queuedHint],
                // the warned ones are counted here and named in the tooltip; their rows carry the warning tone
                ['completed', known(counts.done), t('crTaskCompleted'), 'success',
                    counts.warned ? t('crTaskWarnedN').replace('{n}', counts.warned) : undefined],
                ['failed', known(counts.failed), t('failed'), 'error'],
                // PVE has no cancelled state: the exit text or a cancel from here says it
                ['cancelled', known(counts.cancelled), t('crTaskCancelled'), 'warning', t('crTcCancelledHint')],
            ];
            // what the counts are counted over: the last 50 tasks a cluster lists, the clusters read (the open
            // drawer has its own button for that), the cleared ones
            const failText = !tasks.length && ownFailed
                ? crFill(t(own.state === 'denied' ? 'crTcReadDenied' : 'crTcReadFailed'), { code: own.code ? `HTTP ${own.code}` : t('crTcNoAnswer'), cluster: clusterName || '' })
                : '';
            const windowText = [countsUnread ? (scope === 'cluster' && failText ? failText : t('crTcNotRead')) : t('crTcWindow'),
                                scope === 'all' ? failText : '', expanded ? '' : coverText,
                                clearedN ? t('crTcCleared').replace('{n}', clearedN) : '']
                .filter(Boolean).join(' · ');

            let error = null;
            if (!rows.length) {
                if (scope === 'cluster' && ownAnswered && own.state !== 'ok') error = own.state === 'denied' ? t('crTaskNoAccess') : t('crLoadFailed');
                if (scope === 'all' && connected.length && connected.every(x => x.st === 'error' || x.st === 'denied')) error = t('crLoadFailed');
            }
            const emptyText = scope === 'cluster' && !clusterId ? t('crTasksNoCluster') : t('noTasks');

            const coverState = (x) => ({
                live: t('crTaskLive'), loading: t('loading'), offline: t('offline'), none: t('crTaskNotRead'),
                error: t('crTaskReadFailed'), denied: t('crTaskNoAccess'),
                read: t('crTaskReadAt').replace('{time}', new Date(x.at).toLocaleTimeString(crLocale())),
            })[x.st];

            const statusChips = [['all', t('all'), stripCounts.all], ['running', t('running'), stripCounts.running],
                ['queued', t('crTaskQueued'), stripCounts.queued], ['completed', t('crTaskCompleted'), stripCounts.done],
                ['failed', t('failed'), stripCounts.failed], ['cancelled', t('crTaskCancelled'), stripCounts.cancelled]];

            const dialogTitle = (r) => `${crOpLabel(r)}${r.vmid ? ` (${r.vmid})` : ''}`;
            const dialog = dialogRow && renderDetail && renderDetail({ ...dialogRow, status: crTaskState(dialogRow) === 'running' ? 'running' : dialogRow.status }, {
                log: dialogLog.error || dialogLog.lines.join('\n'),
                loading: dialogLog.loading,
                refresh: dialogLog.reload,
                close: closeDialog,
                cancel: (task) => onCancel && onCancel(task, task.cluster_id),
                tone: crTaskTone(dialogRow),
                statusText: (() => {
                    const label = crTaskLabel(crTaskState(dialogRow), t);
                    const raw = crTaskResult(dialogRow);
                    return raw && raw.toLowerCase() !== String(label).toLowerCase() && raw !== 'running' ? `${label} (${raw})` : label;
                })(),
                duration: <CrDuration task={dialogRow} fmt={fmtRef.current.dur} />,
                progress: crTaskState(dialogRow) === 'running' ? (
                    <div className="cr-tc-dialog-progress" data-cr-tc-dialog-progress="">
                        <CrTaskProgress task={dialogRow} pct={crParseProgress(dialogLog.lines)} t={t} />
                    </div>
                ) : null,
            });

            const latestPct = latest && latestRuns ? pctOf(latest) : null;
            const hitLabel = expanded ? t('crHideTasks') : t('crShowTasks');
            return (
                <div ref={rootRef} className={`pp-taskbar cr-taskcenter${expanded ? ' cr-tc-open' : ''}`}
                    role="region" aria-label={t('crTaskCenter')} data-cr-tc-scope={scope}>
                    {/* the grip is no part of the bar: a drag or a click on it resizes and never toggles */}
                    {expanded && (
                        <div className="cr-tc-grip" role="separator" aria-orientation="horizontal" tabIndex={0}
                            aria-label={t('crTaskResize')} aria-valuenow={h} aria-valuemin={CR_TC.minH} aria-valuemax={maxH()}
                            onPointerDown={startDrag} onKeyDown={keyResize} onDoubleClick={resetH} data-cr-tc-grip="" />
                    )}
                    <div ref={barRef} className="cr-tc-bar" onPointerDown={onBarDown} onClick={onBarClick} data-cr-tc-bar="">
                        {/* the name stays short; the counts, their window and the running task describe it */}
                        <button type="button" ref={hitRef} className="cr-tc-hit" id="cr-tc-hit" aria-expanded={expanded}
                            aria-controls={expanded ? 'cr-tc-drawer' : undefined} aria-label={hitLabel} title={hitLabel}
                            aria-describedby={['cr-tc-counts', 'cr-tc-window', !expanded && latest ? 'cr-tc-latest' : ''].filter(Boolean).join(' ')}
                            onClick={onHitClick} data-cr-tc-toggle="">
                            <span className="cr-ico cr-tc-chev" aria-hidden="true">{expanded ? <Icons.ChevronDown /> : <Icons.ChevronUp />}</span>
                            <span className="cr-tc-title">{t('tasks')}</span>
                            <span className="cr-tc-scope" data-cr-tc-scopetext="">{scopeText}</span>
                            <span className="cr-tc-counts" id="cr-tc-counts" data-cr-tc-counts="">
                                {barCounts.map(([id, n, label, tone, hint]) => (
                                    <span key={id} className={`cr-tc-count cr-tc-count-${tone}${n ? '' : ' cr-tc-zero'}`} data-cr-tc-count={id}
                                        data-n={n == null ? undefined : n} data-cr-tc-unread={n == null ? '' : undefined} title={hint}>
                                        <b>{n == null ? '-' : n}</b> {label}
                                    </span>
                                ))}
                            </span>
                            <span className="cr-tc-window" id="cr-tc-window" data-cr-tc-window="">{windowText}</span>
                            {!expanded && latest && (
                                <span className="cr-tc-latest" id="cr-tc-latest" data-cr-tc-latest="" data-cr-tc-latest-state={latestRuns ? 'running' : 'last'}>
                                    <span className={`cr-dot cr-dot-${crTaskTone(latest)}`} aria-hidden="true" />
                                    {!latestRuns && <span className="cr-muted">{t('crTcLast')}</span>}
                                    <span className="cr-strong">{crOpLabel(latest)}{latest.vmid ? ` (${latest.vmid})` : ''}</span>
                                    {latest.node && <span className="cr-muted">{latest.node}</span>}
                                    <span className="cr-muted" data-cr-tc-latest-cluster="">{clusterNameOf(latest.cluster_id)}</span>
                                    {/* a start time, not a live duration: the collapsed bar keeps no 1 s beat */}
                                    {latestRuns
                                        ? (latest.starttime ? <span className="cr-muted" data-cr-tc-since="">{t('crTcSince').replace('{time}', crTcClock(latest.starttime))}</span> : null)
                                        : <span className="cr-muted">{crTaskLabel(crTaskState(latest), t)}</span>}
                                    {latestRuns && latestPct != null && <span className="cr-tc-latest-pct"><CrTaskProgress task={latest} pct={latestPct} t={t} /></span>}
                                    {!latestRuns && latest.starttime && <span className="cr-muted cr-mono">{crDate(latest.starttime)}</span>}
                                    {running.length > 1 && <span className="cr-muted" data-cr-tc-more="">{t('crTcMoreRunning').replace('{n}', running.length - 1)}</span>}
                                </span>
                            )}
                        </button>
                        {expanded && (
                            <div className="cr-tc-ctl" data-cr-tc-ctl="">
                                <div className="cr-seg" role="group" aria-label={t('crTaskScope')}>
                                    <button type="button" className={scope === 'cluster' ? 'active' : ''} aria-pressed={scope === 'cluster'}
                                        disabled={!clusterId} title={clusterName || t('crTasksNoCluster')} data-cr-tc-scope-pick="cluster"
                                        onClick={() => setScopePick('cluster')}>{t('crTaskScopeCluster')}</button>
                                    <button type="button" className={scope === 'all' ? 'active' : ''} aria-pressed={scope === 'all'}
                                        data-cr-tc-scope-pick="all" onClick={() => setScopePick('all')}>{t('allClusters')}</button>
                                </div>
                                {scope === 'all' && (
                                    <div className="cr-menu-anchor cr-tc-cover-anchor">
                                        <button type="button" className="cr-btn cr-btn-ghost cr-tc-cover" aria-haspopup="true" aria-expanded={coverOpen}
                                            onClick={() => setCoverOpen(o => !o)} data-cr-tc-coverage="">
                                            {anyPending && <span className="cr-spinner" aria-hidden="true" />}
                                            {coverText}
                                        </button>
                                        {coverOpen && (
                                            <>
                                                <div className="cr-click-away" onClick={() => setCoverOpen(false)} />
                                                <div className="cr-menu cr-tc-cover-list" role="group" aria-label={t('crTaskLastReadTitle')}>
                                                    <div className="cr-tc-cover-title">{t('crTaskLastReadTitle')}</div>
                                                    {coverage.map(x => (
                                                        <div key={x.c.id} className="cr-tc-cover-row" data-cr-tc-cover={x.c.id} data-st={x.st}>
                                                            <span className={`cr-dot cr-dot-${x.st === 'live' || x.st === 'read' ? 'success' : x.st === 'error' || x.st === 'denied' ? 'error' : x.st === 'loading' ? 'info' : 'neutral'}`} aria-hidden="true" />
                                                            <span className="cr-strong">{clusterLabel(x.c)}</span>
                                                            <span className="cr-muted">{coverState(x)}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </>
                                        )}
                                    </div>
                                )}
                                <button type="button" className="cr-icon-btn" onClick={refresh} aria-label={t('refresh')} title={t('refresh')} data-cr-tc-refresh="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>
                                </button>
                                <button type="button" className="cr-btn cr-btn-ghost" data-cr-tc-clear="" onClick={() => {
                                    rows.forEach(r => { const s = crTaskState(r); if (s !== 'running' && s !== 'queued') crTaskDismissed.add(crTaskKey(r)); });
                                    if (logKey && crTaskDismissed.has(logKey)) setLogKey(null);
                                    setCleared(n => n + 1);
                                }}>{t('clearCompleted')}</button>
                            </div>
                        )}
                    </div>
                    {expanded && (
                        <div className="cr-tc-drawer" id="cr-tc-drawer" role="group" aria-label={t('tasks')}
                            style={{ height: h, '--cr-tc-room': `${Math.max(120, h - 52)}px` }}>
                            <div className="cr-tc-body">
                                <div className="cr-tc-main">
                                    <CrTable id="tasks" columns={columns} rows={rows} filter={tableFilter} rowKey={crTaskKey}
                                        selectedKey={(paneRow && logKey) || dialogKey || undefined}
                                        onRowClick={openRow} onRowContextMenu={openMenu} ariaLabel={t('tasks')}
                                        loading={loading} error={error} emptyText={emptyText}
                                        toolbar={(
                                            <div className="cr-tc-filters">
                                                <div className="cr-seg" role="group" aria-label={t('status')} data-cr-tc-strip="">
                                                    {statusChips.map(([id, label, n]) => (
                                                        <button key={id} type="button" className={filters.status === id ? 'active' : ''} aria-pressed={filters.status === id}
                                                            data-cr-filter={id} title={id === 'queued' ? queuedHint : undefined}
                                                            onClick={() => keepFilters({ status: id })}>
                                                            {label}<span className="cr-seg-n">{n}</span>
                                                        </button>
                                                    ))}
                                                </div>
                                                <div className="cr-seg" role="group" aria-label={t('todaysTasks')}>
                                                    <button type="button" className={filters.today ? 'active' : ''} aria-pressed={filters.today}
                                                        data-cr-tc-today="" title={t('todaysTasks')} onClick={() => keepFilters({ today: !filters.today })}>
                                                        {t('crTaskToday')}<span className="cr-seg-n">{todayCount}</span>
                                                    </button>
                                                </div>
                                                <select className="cr-select" value={filters.type} aria-label={t('crTaskOperation')} data-cr-tc-type=""
                                                    onChange={e => keepFilters({ type: e.target.value })}>
                                                    <option value="">{t('crTaskAllTypes')}</option>
                                                    {types.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                                                </select>
                                                {scope === 'all' && (
                                                    <select className="cr-select" value={fCluster} aria-label={t('cluster')} data-cr-tc-cluster=""
                                                        onChange={e => keepFilters({ cluster: e.target.value })}>
                                                        <option value="">{t('allClusters')}</option>
                                                        {clusters.map(c => <option key={c.id} value={c.id}>{clusterLabel(c)}</option>)}
                                                    </select>
                                                )}
                                                <div className="cr-search-box">
                                                    <Icons.Search className="cr-search-ico" />
                                                    <input type="search" className="cr-input" value={filters.q} data-cr-tc-q=""
                                                        placeholder={t('crTaskResourceFilter')} aria-label={t('crTaskResourceFilter')}
                                                        onChange={e => keepFilters({ q: e.target.value })} />
                                                </div>
                                                {activeFilters > 0 && (
                                                    <button type="button" className="cr-btn cr-btn-ghost" data-cr-tc-clearfilters=""
                                                        onClick={() => keepFilters({ status: 'all', type: '', cluster: '', q: '', today: false })}>
                                                        {t('crTaskClearFilters').replace('{n}', activeFilters)}
                                                    </button>
                                                )}
                                            </div>
                                        )} />
                                </div>
                                {paneRow && (
                                    <CrTaskLogPane row={paneRow} log={paneLog} title={dialogTitle(paneRow)} fmt={fmtRef.current.dur} t={t}
                                        onClose={() => setLogKey(null)} onDetails={() => openDialog(paneRow)} />
                                )}
                            </div>
                        </div>
                    )}
                    {menu && (
                        <ContextMenu items={menu.items} position={menu.position} onClose={() => {
                            const back = menu.back;
                            setMenu(null);
                            if (back && back.isConnected && back.focus) back.focus({ preventScroll: true });
                        }} />
                    )}
                    {/* on the page, not in the bar: above the drawer, the bar and the overlays it pads */}
                    {dialog && ReactDOM.createPortal(
                        <div ref={layerRef} className="cr-tc-layer" role="dialog" aria-modal="true" aria-label={dialogTitle(dialogRow)} data-cr-tc-dialog="">
                            {dialog}
                        </div>, document.body)}
                </div>
            );
        }
