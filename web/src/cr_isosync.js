        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the ISO Sync of a cluster - LW Nov 2026
        // Which ISO images and container templates lie on which node, and copying them to the nodes
        // that lack them. The writes are the classic ones of DatastoreTab, passed in: triggerSync for
        // one file and triggerSyncAll for every missing copy, the same routes and bodies. The page
        // reads the sync status once per content type and the last result the server keeps; the
        // nodes and their storages come from the datastores read the tab already holds. Nothing is
        // read per file or per node.
        // ═══════════════════════════════════════════════════════════

        // the server reports a copy only once its file is done, so a request of this page is
        // watched for this long: often at first, then less often (scp may take an hour per node)
        const CR_ISO_POLL_FAST = 5000;
        const CR_ISO_POLL_SLOW = 15000;
        const CR_ISO_FAST_FOR = 120000;
        const CR_ISO_WAIT = 2 * 3600 * 1000;
        // the state a file is listed under, the most urgent first
        const CR_ISO_ORDER = ['running', 'pending', 'failed', 'missing', 'synced', 'unknown'];
        const CR_ISO_TONE = { running: 'info', pending: 'neutral', failed: 'error', missing: 'warning', synced: 'success', unknown: 'neutral' };
        const CR_ISO_WORD = { running: 'crIsoRunning', pending: 'crIsoPending', failed: 'crIsoFailed', missing: 'crIsoMissing',
                              synced: 'crIsoSynced', unknown: 'crIsoUnknown' };
        // one file on one node
        const CR_ISO_CELL_TONE = { present: 'success', missing: 'warning', nostore: 'neutral', running: 'info', pending: 'neutral',
                                   failed: 'error', offline: 'neutral', unlisted: 'neutral', unread: 'error' };
        const CR_ISO_CELL_WORD = { present: 'crIsoCellPresent', missing: 'crIsoCellMissing', nostore: 'crIsoCellNoStore',
                                   running: 'crIsoRunning', pending: 'crIsoPending', failed: 'crIsoFailed',
                                   offline: 'crIsoCellOffline', unlisted: 'crIsoCellUnlisted', unread: 'crIsoCellUnread' };
        const CR_ISO_LACK = ['missing', 'nostore', 'running', 'pending', 'failed'];
        const CR_ISO_TILES = ['synced', 'missing', 'pending', 'running', 'failed'];
        const CR_ISO_CHIPS = ['all', 'attention', 'synced', 'missing', 'pending', 'running', 'failed'];

        // what this browser session asked the server to copy, per cluster, and the time of the last
        // result it saw: kept while the sub tab is closed, gone at sign-out. The server keeps no
        // list of the copies that run
        const crIso = { runs: {}, seen: {}, n: 0 };
        crSessionStore(() => { crIso.runs = {}; crIso.seen = {}; });

        const crIsoNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const crIsoKey = (f) => `${f.storage}:${f.name}`;
        // the server writes the time of a result on its own clock, without a zone
        const crIsoAt = (s, t) => (s ? `${crDriftTime(String(s))} (${t('crDriftServerTime')})` : '');
        const crIsoHas = (s, ct) => String((s && s.content) || '').split(',').map(x => x.trim()).includes(ct);

        // The nodes of the cluster: the ones the status lists (online, read), then the others the
        // datastores read knows (offline or not in the answer). stores: the storages of the node a
        // copy can go to, as the server picks them (the content type, not shared, active); null
        // when the datastores read does not cover the node
        function crIsoNodes(status, ds, ct) {
            const listed = Array.isArray(status && status.nodes) ? status.nodes : [];
            const known = ds && Array.isArray(ds.nodes) ? ds.nodes : [];
            const offline = new Set(ds && Array.isArray(ds.offline_nodes) ? ds.offline_nodes : []);
            const local = ds && ds.local && typeof ds.local === 'object' ? ds.local : null;
            const on = new Set(listed);
            // LW Nov 2026 - an online node the server could not read, with its reason; it is left out of the matrix
            const unread = status && status.unread && typeof status.unread === 'object' && !Array.isArray(status.unread) ? status.unread : {};
            const names = [...known, ...listed.filter(n => !known.includes(n))];
            Object.keys(unread).forEach(n => { if (!names.includes(n)) names.push(n); });
            return names.map(name => {
                const list = local && Array.isArray(local[name]) ? local[name] : null;
                const fit = list ? list.filter(s => s && !s.shared && crIsoHas(s, ct)) : null;
                // the tab keeps the storages of an offline node marked node_offline (its sorted copy
                // of the answer drops offline_nodes)
                const away = offline.has(name) || (!!list && list.length > 0 && list.every(s => s && s.node_offline));
                return { name, state: on.has(name) ? 'listed' : crHas(unread, name) ? 'unread' : away ? 'offline' : 'unlisted',
                         why: crHas(unread, name) ? String(unread[name] || '') : '',
                         stores: fit ? fit.filter(s => !!s.active && !s.node_offline).map(s => s.storage) : null,
                         idle: fit ? fit.filter(s => !s.active || s.node_offline).map(s => s.storage) : [] };
            });
        }

        // the copy of a file to a node a request of this session waits for: running (that file),
        // pending (a sync of all, which copies one file after the other)
        function crIsoTracked(runs, ct, key, node) {
            for (const r of runs) {
                if (r.state !== 'open' || r.ct !== ct) continue;
                if (r.kind === 'file' && r.key === key && r.nodes.includes(node)) return 'running';
                if (r.kind === 'all' && r.keys[key] && !r.done[key] && r.keys[key].includes(node)) return 'pending';
            }
            return null;
        }

        // the copies the last result of the server failed: node -> error. It names the file, not
        // its storage, and it is the result of the last file only
        function crIsoFails(last) {
            const m = new Map();
            if (!last || !last.filename || !Array.isArray(last.results)) return { name: null, m };
            last.results.forEach(r => { if (r && r.success === false && r.node) m.set(r.node, r.error || ''); });
            return { name: last.filename, m };
        }

        // one row per file of the status: every node with what it holds, the nodes it lacks, the
        // node a copy starts from (the first listed one that has it, as the classic Sync picks it)
        function crIsoRows(status, nodes, runs, last, ct) {
            const listed = nodes.filter(n => n.state === 'listed');
            const order = Array.isArray(status && status.nodes) ? status.nodes : [];
            const fails = crIsoFails(last);
            const files = Array.isArray(status && status.files) ? status.files : [];
            return files.filter(f => f && f.name).map(f => {
                const key = crIsoKey(f);
                const map = (status.matrix && status.matrix[key]) || {};
                const failed = fails.name === f.name ? fails.m : null;
                const cells = nodes.map(n => {
                    let st;
                    if (n.state !== 'listed') st = n.state;
                    else if (map[n.name] === true) st = 'present';
                    else {
                        st = crIsoTracked(runs, ct, key, n.name)
                            || (failed && failed.has(n.name) ? 'failed' : null)
                            || (n.stores && !n.stores.includes(f.storage) ? 'nostore' : 'missing');
                    }
                    return { node: n.name, state: st, error: st === 'failed' ? failed.get(n.name) : '' };
                });
                const lack = cells.filter(c => CR_ISO_LACK.includes(c.state)).map(c => c.node);
                const has = (s) => cells.some(c => c.state === s);
                const state = !listed.length ? 'unknown' : has('running') ? 'running' : has('pending') ? 'pending'
                    : has('failed') ? 'failed' : lack.length ? 'missing' : 'synced';
                const size = crIsoNum(f.size) ? f.size : null;
                return { key, name: f.name, storage: f.storage, size, cells, lack, state,
                         on: cells.filter(c => c.state === 'present').length, listed: listed.length,
                         source: order.find(n => map[n] === true) || null };
            });
        }

        function crIsoCounts(rows) {
            const n = { all: rows.length, attention: 0, bytes: 0, sizeless: 0, copies: 0, copyBytes: 0, bulk: 0, bulkCopies: 0, bulkBytes: 0 };
            CR_ISO_ORDER.forEach(k => { n[k] = 0; });
            rows.forEach(r => {
                n[r.state] += 1;
                if (r.state === 'missing' || r.state === 'failed') {
                    n.attention += 1;
                    if (r.source) {
                        n.bulk += 1;
                        n.bulkCopies += r.lack.length;
                        if (r.size != null) n.bulkBytes += r.size * r.lack.length;
                    }
                }
                if (r.size != null) n.bytes += r.size; else n.sizeless += 1;
                n.copies += r.lack.length;
                if (r.size != null) n.copyBytes += r.size * r.lack.length;
            });
            return n;
        }
        const crIsoMatch = (key) => (r) => (key === 'all' ? true
            : key === 'attention' ? (r.state === 'missing' || r.state === 'failed') : r.state === key);

        // per node: how many of the files it holds and lacks, and their size
        function crIsoNodeRows(nodes, rows) {
            return nodes.map((n, i) => {
                let here = 0, lack = 0, bytes = 0;
                rows.forEach(r => {
                    const c = r.cells[i];
                    if (c.state === 'present') { here += 1; if (r.size != null) bytes += r.size; }
                    else if (CR_ISO_LACK.includes(c.state)) lack += 1;
                });
                return { ...n, here, lack, bytes };
            });
        }

        // a result the server reports (one file, at its end) ends the request of this session that
        // waits for that file; the requests it ended
        function crIsoTake(cid, res) {
            const ended = [];
            (crIso.runs[cid] || []).forEach(r => {
                if (r.state !== 'open') return;
                if (r.kind === 'file') {
                    if (r.name === res.filename) { r.state = 'done'; r.result = res; ended.push(r); }
                    return;
                }
                const ks = Object.keys(r.keys).filter(k => !r.done[k] && k.slice(k.indexOf(':') + 1) === res.filename);
                if (!ks.length) return;
                ks.forEach(k => { r.done[k] = res; });
                r.last = res;
                ended.push(r);
                if (Object.keys(r.keys).every(k => r.done[k])) r.state = 'done';
            });
            return ended;
        }

        // A sync of all: a file the status now shows on every node it lacked is done, also when the
        // next file overwrote its result before this page read it
        function crIsoSettle(cid, ct, status) {
            const matrix = status && status.matrix;
            if (!matrix) return;
            (crIso.runs[cid] || []).forEach(r => {
                if (r.state !== 'open' || r.kind !== 'all' || r.ct !== ct) return;
                Object.keys(r.keys).forEach(k => {
                    if (!r.done[k] && matrix[k] && r.keys[k].every(node => matrix[k][node] === true)) r.done[k] = { seen: true };
                });
                if (Object.keys(r.keys).every(k => r.done[k])) r.state = 'done';
            });
        }

        // a request with no result in CR_ISO_WAIT is no longer drawn as running or pending
        function crIsoAge(cid, now) {
            (crIso.runs[cid] || []).forEach(r => { if (r.state === 'open' && now - r.at > CR_ISO_WAIT) r.state = 'stale'; });
        }

        // the outcome of a request of this session, for the activity table
        function crIsoRunState(r) {
            if (r.state === 'open') return r.kind === 'file' ? 'running' : 'pending';
            if (r.state === 'stale' || r.state === 'dropped') return r.state;
            const res = r.kind === 'file' ? [r.result] : Object.values(r.done);
            return res.some(x => x && x.failed > 0) ? 'failed' : 'done';
        }
        const CR_ISO_RUN_TONE = { running: 'info', pending: 'neutral', failed: 'error', done: 'success', stale: 'warning', dropped: 'neutral' };
        const CR_ISO_RUN_WORD = { running: 'crIsoRunning', pending: 'crIsoPending', failed: 'crIsoFailed', done: 'crIsoDone',
                                  stale: 'crIsoStale', dropped: 'crIsoDropped' };

        // what one result of the server says of one node
        function crIsoOutcome(r, t) {
            if (!r) return '';
            if (r.success && r.skipped) return t('crIsoOutThere');
            if (r.success) return crFill(t('crIsoOutCopied'), { how: r.method === 'sftp' ? t('crIsoViaRelay') : t('crIsoViaNode') });
            return t('crIsoFailed');
        }

        // --- the parts -----------------------------------------------------------------------------

        function CrIsoState({ state }) {
            const { t } = useTranslation();
            return <span data-cr-iso-state={state}><CrBadge tone={CR_ISO_TONE[state] || 'neutral'}>{t(CR_ISO_WORD[state] || 'crIsoUnknown')}</CrBadge></span>;
        }

        function crIsoCellWord(c, row, t) {
            return c.state === 'nostore' ? crFill(t('crIsoCellNoStore'), { s: row.storage }) : t(CR_ISO_CELL_WORD[c.state] || 'crIsoUnknown');
        }

        // a file opened in the table: every node with what it holds
        function CrIsoCells({ row }) {
            const { t } = useTranslation();
            return (
                <div className="cr-iso-detail" data-cr-iso-nodes={row.key}>
                    <ul className="cr-iso-cells" aria-label={crFill(t('crIsoCellsLabel'), { name: row.name })}>
                        {row.cells.map(c => (
                            <li key={c.node} className="cr-iso-cell" data-cr-iso-cell={c.node} data-state={c.state}>
                                <span className="cr-mono cr-iso-cell-node">{c.node}</span>
                                <CrBadge tone={CR_ISO_CELL_TONE[c.state] || 'neutral'}>{crIsoCellWord(c, row, t)}</CrBadge>
                                {c.error && <span className="cr-iso-err" title={c.error}>{c.error}</span>}
                            </li>
                        ))}
                    </ul>
                    <p className="cr-iso-fine">
                        {row.source ? crFill(t('crIsoSourceLine'), { node: row.source, storage: row.storage }) : t('crIsoNoSource')}
                        {row.cells.some(c => c.state === 'nostore') && <> {crFill(t('crIsoNoStoreNote'), { s: row.storage })}</>}
                    </p>
                </div>
            );
        }

        // what this session asked for, and the last result the server keeps
        function CrIsoActivity({ runs, last, lastErr, onDrop }) {
            const { t } = useTranslation();
            const rows = runs.slice().reverse().map(r => ({ ...r, show: crIsoRunState(r) }));
            const cols = [
                { key: 'what', label: t('crIsoColWhat'), flex: true, min: 150, render: r => (
                    <span className="cr-iso-file" data-cr-iso-run={r.kind} title={r.kind === 'file' ? r.name : undefined}>
                        {r.kind === 'file' ? r.name : crFill(t('crIsoRunAll'), { n: Object.keys(r.keys).length })}
                    </span>) },
                { key: 'ct', label: t('type'), width: 90, render: r => t(r.ct === 'vztmpl' ? 'crIsoTemplates' : 'crIsoIsos') },
                { key: 'at', label: t('crIsoColStarted'), width: 80, render: r => crFmtTime(r.at) },
                { key: 'state', label: t('crIsoColState'), width: 110, render: r => (
                    <span data-cr-iso-run-state={r.show}><CrBadge tone={CR_ISO_RUN_TONE[r.show]}>{t(CR_ISO_RUN_WORD[r.show])}</CrBadge></span>) },
                { key: 'progress', label: t('crIsoColProgress'), flex: true, min: 130, render: r => {
                    if (r.kind === 'all') {
                        const total = Object.keys(r.keys).length;
                        return crFill(t('crIsoFilesDone'), { n: Object.keys(r.done).length, total });
                    }
                    if (r.result) return crFill(t('crIsoResultLine'), { ok: r.result.ok || 0, failed: r.result.failed || 0 });
                    return r.state === 'open' ? t('crIsoWaitResult') : '';
                } },
                { key: 'act', label: '', width: 110, render: r => (r.state === 'open'
                    ? <CrButton className="cr-btn-xs" onClick={() => onDrop(r.id)} title={t('crIsoDropTitle')} data-cr-iso-drop="">{t('crIsoDrop')}</CrButton>
                    : null) },
            ];
            const res = last && Array.isArray(last.results) ? last.results : [];
            return (
                <CrNcSection id="iso-activity" title={t('crIsoActivityTitle')} desc={t('crIsoActivityDesc')}>
                    {rows.length ? (
                        <CrTable id="iso-runs" columns={cols} rows={rows} rowKey={r => r.id} ariaLabel={t('crIsoActivityTitle')} rowHeight={30}
                            columnMenu={false} showCount={false} />
                    ) : <p className="cr-iso-fine" data-cr-iso-noruns="">{t('crIsoNoRuns')}</p>}
                    <h3 className="cr-iso-sub">{t('crIsoLastTitle')}</h3>
                    {last === undefined ? <CrNcState id="iso-last" kind="loading" />
                        : last === null ? <CrNcState id="iso-last" kind="error" data-cr-iso-last-error="">{crFill(t('crIsoLastFailedWhy'), { reason: lastErr || '-' })}</CrNcState>
                        : !last.filename ? <p className="cr-iso-fine" data-cr-iso-last="none">{t('crIsoLastNone')}</p>
                        : (
                            <div data-cr-iso-last={last.filename}>
                                <CrNcKv id="iso-last" label={t('crIsoLastTitle')} rows={[
                                    { k: 'file', label: t('crIsoColFile'), value: last.filename, mono: true, wide: true },
                                    { k: 'at', label: t('crIsoFinished'), value: last.timestamp ? crIsoAt(last.timestamp, t) : '' },
                                    { k: 'ok', label: t('crIsoCopiedN'), value: String(res.filter(r => r && r.success && !r.skipped).length) },
                                    { k: 'there', label: t('crIsoThereN'), value: String(res.filter(r => r && r.success && r.skipped).length) },
                                    { k: 'failed', label: t('crIsoFailedN'), value: String(res.filter(r => r && r.success === false).length) },
                                ]} />
                                {res.length > 0 && (
                                    <ul className="cr-iso-results" aria-label={t('crIsoLastTitle')}>
                                        {res.map((r, i) => (
                                            <li key={`${r && r.node}-${i}`} data-cr-iso-result={(r && r.node) || ''} data-state={r && r.success ? 'ok' : 'failed'}>
                                                <span className="cr-mono">{(r && r.node) || '-'}</span>
                                                <CrBadge tone={r && r.success ? 'success' : 'error'}>{crIsoOutcome(r, t)}</CrBadge>
                                                {r && r.error && <span className="cr-iso-err" title={r.error}>{r.error}</span>}
                                            </li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}
                    <p className="cr-iso-fine">{t('crIsoLastNote')}</p>
                </CrNcSection>
            );
        }

        // Auto-sync after an upload: the flag of the classic checkbox, kept in this browser. With it on,
        // an ISO or template uploaded from the Datastore tab of this layout to the storage of one node
        // is copied to the other nodes once its upload task ended well (DatastoreTab crQueueAutoSync);
        // the server has no such setting. The copy is the Sync of one file, so it takes storage.upload
        function CrIsoAuto({ clusterId, canSync, why, waiting }) {
            const { t } = useTranslation();
            const key = `autosync-${clusterId}`;
            const [on, setOn] = useState(() => { try { return localStorage.getItem(key) === 'true'; } catch (_) { return false; } });
            const [kept, setKept] = useState(true);
            const flip = (v) => {
                try { localStorage.setItem(key, String(v)); setOn(v); setKept(true); } catch (_) { setKept(false); }
            };
            return (
                <CrNcSection id="iso-auto" title={t('crIsoAutoTitle')} desc={t('crIsoAutoDescOn')}
                    badge={<CrBadge tone={on ? 'info' : 'neutral'} dot={false}><span data-cr-iso-auto-state={on ? 'on' : 'off'}>{on ? t('crIsoOn') : t('crIsoOff')}</span></CrBadge>}>
                    <label className={`cr-upd-opt${!canSync ? ' cr-upd-opt-off' : ''}`} title={!canSync ? why : undefined}>
                        <input type="checkbox" checked={on} disabled={!canSync} onChange={e => flip(e.target.checked)} data-cr-iso-auto="" />
                        <span><span className="cr-strong">{t('crIsoAutoTitle')}</span><span className="cr-upd-hint">{t('crIsoAutoHow')}</span></span>
                    </label>
                    {!canSync && <p className="cr-iso-fine" data-cr-iso-auto-why="">{why}</p>}
                    {waiting && <p className="cr-iso-fine" role="status" data-cr-iso-auto-waiting="">{t('crIsoAutoWaitingNote')}</p>}
                    {!kept && <p className="cr-iso-fine cr-tone-text cr-tone-error" role="alert" data-cr-iso-auto-unsaved="">{t('crIsoAutoNotKept')}</p>}
                    <p className="cr-iso-fine">{t('crIsoAutoScope')}</p>
                </CrNcSection>
            );
        }

        // --- the page ------------------------------------------------------------------------------

        // dsFail: the last read of the datastore list failed ({ msg, hasData }); the storages of the nodes come from it
        function CrIsoSync({ clusterId, call, datastores, dsLoading, dsFail, onDsRetry, autoSyncWaiting, contentType, onContentType, canSync, onSync, onSyncAll, addToast }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const ct = contentType === 'vztmpl' ? 'vztmpl' : 'iso';
            const base = `${API_URL}/clusters/${clusterId}`;
            const [read, setRead] = useState({ ct: null, body: null, at: 0, loading: true, error: '' });
            const [last, setLast] = useState(undefined);
            const [lastErr, setLastErr] = useState('');
            const [tick, setTick] = useState(0);
            const [filter, setFilter] = useState('all');
            const [nodeFilter, setNodeFilter] = useState('');
            const [open, setOpen] = useState({});
            const [busy, setBusy] = useState('');
            const seq = useRef(0);
            const lastSeq = useRef(0);
            const callRef = useRef(call);
            callRef.current = call;
            const ctRef = useRef(ct);
            ctRef.current = ct;
            const tableRef = useRef(null);
            const bump = () => setTick(x => x + 1);
            // the newest handlers of DatastoreTab: triggerSync sends the content type of its last render
            const live = useRef({});
            live.current = { t, addToast, onSync, onSyncAll };
            const say = (msg, kind) => { if (live.current.addToast) live.current.addToast(msg, kind); };

            // the read of the classic sub tab, for one content type; the newest request wins
            const loadStatus = useCallback(async (want) => {
                const mine = ++seq.current;
                setRead(r => ({ ...r, loading: true, error: '' }));
                const res = await callRef.current(`${base}/iso-sync/status?content=${want}`);
                if (mine !== seq.current) return;
                let body = null;
                let error = '';
                if (!res) error = t('crIsoNoAnswer');
                else if (res.ok) {
                    body = await res.json().catch(() => null);
                    if (!body || typeof body !== 'object' || body.error) { error = (body && body.error) || t('crIsoNoAnswer'); body = null; }
                } else error = await PegaProxApiErrors.message(res, t('crIsoReadFailedShort'));
                if (mine !== seq.current) return;
                if (body) {
                    crIsoSettle(clusterId, want, body);
                    setRead({ ct: want, body, at: Date.now(), loading: false, error: '' });
                } else setRead(r => ({ ...r, loading: false, error }));
            }, [base, clusterId]);  // eslint-disable-line react-hooks/exhaustive-deps

            const loadLast = useCallback(async () => {
                const mine = ++lastSeq.current;
                const res = await callRef.current(`${base}/iso-sync/last-result`);
                if (mine !== lastSeq.current) return undefined;
                if (!res || !res.ok) {
                    const msg = res ? await PegaProxApiErrors.message(res, t('crIsoLastFailed')) : t('crIsoNoAnswer');
                    if (mine === lastSeq.current) { setLast(null); setLastErr(msg); }
                    return undefined;
                }
                const body = await res.json().catch(() => null);
                if (mine !== lastSeq.current) return undefined;
                const d = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
                setLast(d);
                setLastErr('');
                return d;
            }, [base]);  // eslint-disable-line react-hooks/exhaustive-deps

            // The last result again: a new one (its time changed) ends the request waiting for its
            // file and has the status read again. The first read of the session only notes the time
            const check = useCallback(async () => {
                const d = await loadLast();
                crIsoAge(clusterId, Date.now());
                if (d === undefined) { bump(); return; }
                const ts = d.timestamp || '';
                const was = crIso.seen[clusterId];
                crIso.seen[clusterId] = ts;
                if (was === undefined || ts === was || !d.filename) { bump(); return; }
                const tt = live.current.t;
                crIsoTake(clusterId, d).forEach(r => {
                    if (r.kind === 'all' && r.state === 'open' && !(d.failed > 0)) return;
                    const copied = (d.results || []).filter(x => x && x.success && !x.skipped).length;
                    const there = (d.results || []).filter(x => x && x.success && x.skipped).length;
                    if (d.failed > 0) say(crFill(tt('crIsoToastFailed'), { name: d.filename, n: d.failed, total: (d.results || []).length }), 'error');
                    else if (r.kind === 'all') say(crFill(tt('crIsoToastAllDone'), { n: Object.keys(r.keys).length }), 'success');
                    else say(crFill(tt('crIsoToastDone'), { name: d.filename, n: copied, there }), 'success');
                });
                bump();
                await loadStatus(ctRef.current);
                bump();
            }, [clusterId, loadLast, loadStatus]);  // eslint-disable-line react-hooks/exhaustive-deps

            useEffect(() => { loadStatus(ctRef.current); check(); }, [clusterId]);  // eslint-disable-line react-hooks/exhaustive-deps

            const runs = crIso.runs[clusterId] || [];
            const openRuns = runs.filter(r => r.state === 'open');
            // while a request of this page waits for its result: one read of the last result per turn
            const pollKey = openRuns.map(r => r.id).join(',');
            const [turn, setTurn] = useState(0);
            useEffect(() => {
                if (!openRuns.length) return undefined;
                const first = Math.min(...openRuns.map(r => r.at));
                const id = setTimeout(async () => { await check(); setTurn(x => x + 1); },
                    Date.now() - first < CR_ISO_FAST_FOR ? CR_ISO_POLL_FAST : CR_ISO_POLL_SLOW);
                return () => clearTimeout(id);
            }, [pollKey, turn]);  // eslint-disable-line react-hooks/exhaustive-deps

            const mine = read.ct === ct && read.body ? read.body : null;
            const nodes = useMemo(() => crIsoNodes(mine, datastores, ct), [mine, datastores, ct]);
            const listed = nodes.filter(n => n.state === 'listed').length;
            const usable = !!mine && listed > 0;
            const rows = useMemo(() => (usable ? crIsoRows(mine, nodes, runs, last, ct) : []),
                [usable, mine, nodes, runs, last, ct, tick]);  // eslint-disable-line react-hooks/exhaustive-deps
            const n = useMemo(() => crIsoCounts(rows), [rows]);
            const nodeRows = useMemo(() => crIsoNodeRows(nodes, rows), [nodes, rows]);
            const shared = useMemo(() => ((datastores && Array.isArray(datastores.shared) ? datastores.shared : [])
                .filter(s => s && crIsoHas(s, ct)).map(s => s.storage)), [datastores, ct]);
            const offline = nodes.length - listed;
            const allOpen = openRuns.some(r => r.kind === 'all' && r.ct === ct);
            const why = haReadOnly ? t('crIsoStandbyWhy') : t('crIsoNeedsPerm');
            const rowFilter = useMemo(() => {
                if (filter === 'all' && !nodeFilter) return undefined;
                const m = crIsoMatch(filter);
                return (r) => m(r) && (!nodeFilter || r.lack.includes(nodeFilter));
            }, [filter, nodeFilter]);

            const pick = (k, scroll) => {
                setFilter(f => (f === k && k !== 'all' ? 'all' : k));
                if (scroll && tableRef.current) tableRef.current.scrollIntoView({ block: 'start', behavior: 'smooth' });
            };
            const pickNode = (name) => {
                setNodeFilter(x => (x === name ? '' : name));
                setFilter('all');
                if (tableRef.current) tableRef.current.scrollIntoView({ block: 'start', behavior: 'smooth' });
            };
            const switchTo = (v) => {
                if (v === ct) return;
                onContentType(v);
                setFilter('all');
                setNodeFilter('');
                setOpen({});
                loadStatus(v);
            };
            const refresh = () => { loadStatus(ct); check(); };
            const remember = (run) => {
                crIso.n += 1;
                (crIso.runs[clusterId] = crIso.runs[clusterId] || []).push({ id: `r${crIso.n}`, at: Date.now(), state: 'open', ...run });
            };
            // the time of the last result is known before a request goes out, so a result that was
            // there already is never taken for its answer
            const ready = async () => { if (crIso.seen[clusterId] === undefined) await check(); };

            const syncOne = async (r) => {
                if (busy || !canSync) return;
                setBusy(r.key);
                try {
                    await ready();
                    const lack = r.lack.slice();
                    if (await live.current.onSync(r.source, r.storage, r.name, true) === true) {
                        remember({ kind: 'file', ct, key: r.key, name: r.name, storage: r.storage, nodes: lack, result: null });
                    }
                } finally { setBusy(''); bump(); }
            };
            const syncAll = async () => {
                if (busy || !canSync) return;
                setBusy('_all');
                try {
                    await ready();
                    const keys = {};
                    rows.forEach(r => { if (r.source && r.lack.length) keys[r.key] = r.lack.slice(); });
                    if (await live.current.onSyncAll(true) === true) remember({ kind: 'all', ct, keys, done: {} });
                } finally { setBusy(''); bump(); }
            };
            const drop = (id) => {
                const r = runs.find(x => x.id === id);
                if (r && r.state === 'open') r.state = 'dropped';
                bump();
            };

            const word = (k) => t({ all: 'all', attention: 'crIsoAttention', ...CR_ISO_WORD }[k]);
            const spin = <span className="cr-spinner" role="status" aria-label={t('loading')} />;
            const tileVal = (k) => (!usable ? (read.loading ? spin : <CrNcMissing />) : n[k]);
            const tileSub = (k) => {
                if (!usable) return '';
                if (k === 'synced') return t('crIsoSubSynced');
                if (k === 'missing') return crFill(t('crIsoSubMissing'), { n: n.copies, size: crBytes(n.copyBytes) });
                if (k === 'pending') return t('crIsoSubPending');
                if (k === 'running') return t('crIsoSubRunning');
                return last === null ? t('crIsoSubFailedUnread') : t('crIsoSubFailed');
            };
            const tileTone = (k) => (!usable || !n[k] ? undefined
                : k === 'failed' ? 'error' : k === 'missing' ? 'warning' : k === 'running' ? 'info' : undefined);

            const cols = useMemo(() => [
                { key: 'file', label: t('crIsoColFile'), flex: true, min: 150, sortValue: r => r.name.toLowerCase(), text: r => r.name,
                  render: r => (
                      <span className="cr-iso-file" data-cr-iso-row={r.key} title={r.name}>
                          <span className="cr-iso-caret" aria-hidden="true">{open[r.key] ? <Icons.ChevronDown /> : <Icons.ChevronRight />}</span>
                          <span className="cr-mono cr-iso-name">{r.name}</span>
                      </span>
                  ) },
                { key: 'storage', label: t('crIsoColStorage'), width: 78, render: r => <span className="cr-mono">{r.storage}</span> },
                { key: 'size', label: t('crIsoColSize'), width: 80, sortValue: r => r.size,
                  render: r => (r.size != null ? crBytes(r.size) : <CrNcMissing />) },
                { key: 'state', label: t('crIsoColState'), width: 122, sortValue: r => CR_ISO_ORDER.indexOf(r.state), text: r => t(CR_ISO_WORD[r.state]),
                  render: r => <CrIsoState state={r.state} /> },
                { key: 'on', label: t('crIsoColOn'), width: 88, sortValue: r => (r.listed ? r.on / r.listed : null),
                  render: r => (
                      <span className="cr-iso-dist" data-cr-iso-on={`${r.on}/${r.listed}`} title={crFill(t('crIsoOnTitle'), { n: r.on, total: r.listed })}>
                          <span className="cr-iso-dist-bar" aria-hidden="true"><span style={{ width: `${r.listed ? (r.on / r.listed) * 100 : 0}%` }} /></span>
                          <span>{crFill(t('crIsoOnOf'), { n: r.on, total: r.listed })}</span>
                      </span>
                  ) },
                { key: 'lack', label: t('crIsoColLack'), flex: true, min: 100, sortValue: r => r.lack.length || null, text: r => r.lack.join(' '),
                  render: r => (r.lack.length
                      ? <span className="cr-iso-lack" title={r.lack.join(', ')}>{r.lack.slice(0, 3).join(', ')}
                          {r.lack.length > 3 && <span className="cr-muted"> {crFill(t('crIsoMoreN'), { n: r.lack.length - 3 })}</span>}</span>
                      : <span className="cr-muted">{t('crIsoNone')}</span>) },
                { key: 'source', label: t('crIsoColSource'), width: 100, hidden: true, render: r => r.source || '' },
                { key: 'act', label: t('actions'), width: 80, render: r => {
                    if (r.state === 'synced') return <span className="cr-muted" data-cr-iso-synced="">{t('synced') || 'Synced'}</span>;
                    if (!r.source || !r.lack.length) return null;
                    const going = r.state === 'running' || r.state === 'pending';
                    return (
                        <CrButton className="cr-btn-xs" icon={<Icons.RefreshCw />} disabled={!canSync || !!busy || going}
                            title={!canSync ? why : going ? t('crIsoBusyTitle') : crFill(t('crIsoSyncTitle'), { node: r.source, n: r.lack.length })}
                            onClick={(e) => { e.stopPropagation(); syncOne(r); }} data-cr-iso-sync={r.key}>
                            {busy === r.key ? t('crIsoSending') : (t('sync') || 'Sync')}
                        </CrButton>
                    );
                } },
            ], [t, open, canSync, busy, why, rows]);  // eslint-disable-line react-hooks/exhaustive-deps

            const nodeCols = useMemo(() => [
                { key: 'name', label: t('node'), flex: true, min: 110, render: r => <span className="cr-mono" data-cr-iso-node={r.name}>{r.name}</span> },
                { key: 'state', label: t('crIsoColNodeState'), width: 130, sortValue: r => (r.state === 'listed' ? 0 : 1),
                  render: r => (r.state === 'listed' ? <CrBadge tone="success">{t('crIsoNodeListed')}</CrBadge>
                      : r.state === 'unread' ? <CrBadge tone="error" title={r.why || undefined}><span data-cr-iso-node-unread={r.name}>{t('crIsoCellUnread')}</span></CrBadge>
                      : <CrBadge tone="neutral">{t(r.state === 'offline' ? 'crIsoCellOffline' : 'crIsoCellUnlisted')}</CrBadge>) },
                { key: 'here', label: t('crIsoColHere'), width: 90, sortValue: r => (r.state === 'listed' ? r.here : null),
                  render: r => (r.state === 'listed' ? crFill(t('crIsoOnOf'), { n: r.here, total: rows.length }) : <CrNcMissing />) },
                { key: 'lack', label: t('crIsoColNodeLack'), width: 90, sortValue: r => (r.state === 'listed' ? r.lack : null),
                  render: r => (r.state !== 'listed' ? <CrNcMissing /> : r.lack ? (
                      <button type="button" className={`cr-link${nodeFilter === r.name ? ' cr-strong' : ''}`} aria-pressed={nodeFilter === r.name}
                          onClick={() => pickNode(r.name)} title={crFill(t('crIsoShowLack'), { node: r.name })} data-cr-iso-node-lack={r.name}>
                          {r.lack}
                      </button>) : <span className="cr-muted">0</span>) },
                { key: 'bytes', label: t('crIsoColHeld'), width: 90, sortValue: r => (r.state === 'listed' ? r.bytes : null),
                  render: r => (r.state === 'listed' ? crBytes(r.bytes) : '') },
                { key: 'stores', label: t('crIsoColStores'), flex: true, min: 140, text: r => (r.stores || []).join(' '),
                  render: r => (r.stores == null ? <CrNcMissing />
                      : (
                          <span className="cr-iso-lack" data-cr-iso-stores={r.name}>
                              {r.stores.length ? r.stores.join(', ') : <span className="cr-muted">{t('crIsoNoStores')}</span>}
                              {r.idle.length > 0 && <span className="cr-muted"> {crFill(t('crIsoIdle'), { s: r.idle.join(', ') })}</span>}
                          </span>
                      )) },
            ], [t, rows, nodeFilter]);  // eslint-disable-line react-hooks/exhaustive-deps

            const kindWord = t(ct === 'vztmpl' ? 'crIsoTemplates' : 'crIsoIsos');
            const emptyText = !mine ? (read.error || t('crIsoNotRead')) : !listed ? t('crIsoUnlistedShort')
                : crFill(t('crIsoNoFiles'), { kind: kindWord });

            return (
                <div className="cr-iso" data-cr-iso={clusterId} data-cr-iso-ct={ct}>
                    <CrPageHeader icon={<Icons.RefreshCw />} title={t('isoSync') || 'ISO Sync'} sub={t('crIsoSub')}
                        actions={(
                            <>
                                <div className="cr-seg" role="group" aria-label={t('crIsoContent')} data-cr-iso-content-seg="">
                                    {['iso', 'vztmpl'].map(v => (
                                        <button key={v} type="button" className={ct === v ? 'active' : ''} aria-pressed={ct === v}
                                            onClick={() => switchTo(v)} data-cr-iso-content={v}>
                                            {t(v === 'vztmpl' ? 'crIsoTemplates' : 'crIsoIsos')}
                                        </button>
                                    ))}
                                </div>
                                {read.loading && mine && spin}
                                <button type="button" className="cr-icon-btn" onClick={refresh} disabled={read.loading}
                                    aria-label={t('refresh')} title={t('refresh')} data-cr-iso-refresh="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>
                                </button>
                            </>
                        )} />
                    {haReadOnly && <CrNcState id="iso-standby" kind="info" data-cr-iso-standby="">{t('crIsoStandby')}</CrNcState>}
                    {read.error && (
                        <CrNcState id="iso-read" kind="error" onRetry={() => loadStatus(ct)} retryDisabled={read.loading} data-cr-iso-error="">
                            {crFill(t(mine ? 'crIsoReadFailedOld' : 'crIsoReadFailed'), { reason: read.error })}
                        </CrNcState>
                    )}
                    {mine && !listed && (
                        <CrNcState id="iso-read" kind="warning" onRetry={() => loadStatus(ct)} retryDisabled={read.loading} data-cr-iso-unlisted="">
                            {t('crIsoUnlisted')}
                        </CrNcState>
                    )}
                    {mine && nodes.some(x => x.state === 'unread') && (
                        <CrNcState id="iso-unread" kind="error" onRetry={() => loadStatus(ct)} retryDisabled={read.loading} data-cr-iso-unread-nodes="">
                            {crFill(t('crIsoUnreadNodes'), { n: nodes.filter(x => x.state === 'unread').length,
                                list: nodes.filter(x => x.state === 'unread').map(x => `${x.name}${x.why ? ` (${x.why})` : ''}`).join('; ') })}
                        </CrNcState>
                    )}
                    {dsFail && (
                        <CrNcState id="iso-ds" kind={dsFail.hasData ? 'warning' : 'error'} onRetry={onDsRetry} data-cr-iso-ds-failed={dsFail.hasData ? 'stale' : 'unread'}>
                            {crFill(t(dsFail.hasData ? 'crIsoDsStale' : 'crIsoDsFailed'), { why: dsFail.msg || '-' })}
                        </CrNcState>
                    )}

                    <h2 className="cr-iso-h">{t('crIsoSecOverview')}</h2>
                    <div className="cr-stat-row cr-iso-stats" role="group" aria-label={t('crIsoSecOverview')}>
                        <CrStat id="iso-files" label={crFill(t('crIsoFilesN'), { kind: kindWord })} value={tileVal('all')}
                            sub={usable ? crFill(t('crIsoFilesSub'), { size: crBytes(n.bytes) }) : ''} title={t('crIsoFilesTitleTile')} />
                        {CR_ISO_TILES.map(k => (
                            <CrStat key={k} id={`iso-${k}`} label={word(k)} value={tileVal(k)} sub={tileSub(k)} tone={tileTone(k)}
                                title={[word(k), tileSub(k)].filter(Boolean).join(': ')}
                                onClick={usable ? () => pick(k, true) : undefined} pressed={usable ? filter === k : undefined} />
                        ))}
                        <CrStat id="iso-nodes" label={t('crIsoNodesTile')}
                            value={!mine ? tileVal('nodes') : nodes.length ? crFill(t('crIsoOnOf'), { n: listed, total: nodes.length }) : <CrNcMissing />}
                            sub={!mine ? '' : offline > 0 ? crFill(t('crIsoNodesOff'), { n: offline }) : t('crIsoNodesAll')}
                            tone={mine && offline > 0 ? 'warning' : undefined} />
                    </div>
                    {mine && (
                        <p className="cr-iso-fine" data-cr-iso-basis="">
                            {crFill(t('crIsoBasis'), { at: crFmtTime(read.at), kind: kindWord })}
                            {shared.length > 0 && <span data-cr-iso-shared=""> {crFill(t('crIsoSharedNote'), { s: shared.join(', ') })}</span>}
                            {n.sizeless > 0 && <> {crFill(t('crIsoSizeless'), { n: n.sizeless })}</>}
                        </p>
                    )}

                    <h2 className="cr-iso-h">{t('crIsoSecActivity')}</h2>
                    <div className="cr-iso-cols">
                        <CrIsoActivity runs={runs} last={last} lastErr={lastErr} onDrop={drop} />
                        <CrIsoAuto clusterId={clusterId} canSync={canSync && !haReadOnly} why={why} waiting={!!autoSyncWaiting} />
                    </div>

                    <h2 className="cr-iso-h" ref={tableRef}>{t('crIsoSecFiles')}</h2>
                    <CrNcSection id="iso-files" title={crFill(t('crIsoFilesTitle'), { kind: kindWord })} desc={t('crIsoFilesDesc')}
                        actions={(
                            <CrButton variant="primary" icon={<Icons.RefreshCw />} onClick={syncAll}
                                disabled={!canSync || !!busy || !usable || !n.bulk || allOpen}
                                title={!canSync ? why : allOpen ? t('crIsoAllBusy') : !n.bulk ? t('crIsoNothingToSync')
                                    : crFill(t('crIsoBulkSum'), { files: n.bulk, n: n.bulkCopies, size: crBytes(n.bulkBytes) })}
                                data-cr-iso-syncall="">
                                {busy === '_all' ? t('crIsoSending') : (t('syncAll') || 'Sync All Missing')}
                            </CrButton>
                        )}>
                        {usable && (
                            <p className="cr-iso-fine" data-cr-iso-bulk="">
                                {n.bulk ? crFill(t('crIsoBulkSum'), { files: n.bulk, n: n.bulkCopies, size: crBytes(n.bulkBytes) }) : t('crIsoNothingToSync')}
                                {!canSync && <span data-cr-iso-readonly=""> {why}</span>}
                            </p>
                        )}
                        <CrTable id="iso-files" columns={cols} rows={rows} rowKey={r => r.key} ariaLabel={crFill(t('crIsoFilesTitle'), { kind: kindWord })}
                            rowHeight={30} filter={rowFilter} searchable searchPlaceholder={t('crIsoSearch')}
                            loading={read.loading && !mine} error={!mine && read.error ? read.error : null} emptyText={emptyText}
                            initialSort={{ key: 'state', dir: 'asc' }} maxHeight={560}
                            expanded={open} onRowClick={r => setOpen(o => ({ ...o, [r.key]: !o[r.key] }))}
                            renderExpanded={r => <CrIsoCells row={r} />}
                            toolbar={(
                                <div className="cr-iso-tools">
                                    <div className="cr-seg" role="group" aria-label={t('filter')} data-cr-iso-chips="">
                                        {CR_ISO_CHIPS.map(k => (
                                            <button key={k} type="button" className={filter === k ? 'active' : ''} aria-pressed={filter === k}
                                                onClick={() => pick(k, false)} data-cr-iso-chip={k}>
                                                {word(k)}{usable && <> <span className="cr-seg-n">{n[k]}</span></>}
                                            </button>
                                        ))}
                                    </div>
                                    {nodeFilter && (
                                        <div className="cr-seg" role="group" aria-label={t('crIsoNodeFilter')}>
                                            <button type="button" className="active cr-iso-nodefilter" aria-pressed="true" onClick={() => setNodeFilter('')}
                                                data-cr-iso-node-filter={nodeFilter} title={t('crIsoClearNode')}>
                                                {crFill(t('crIsoLackOn'), { node: nodeFilter })} <Icons.X />
                                            </button>
                                        </div>
                                    )}
                                </div>
                            )} />
                    </CrNcSection>

                    <h2 className="cr-iso-h">{t('crIsoSecNodes')}</h2>
                    <CrNcSection id="iso-nodes" title={t('crIsoNodesTitle')} desc={t('crIsoNodesDesc')}>
                        <CrTable id="iso-node-table" columns={nodeCols} rows={usable ? nodeRows : []} rowKey={r => r.name} ariaLabel={t('crIsoNodesTitle')}
                            rowHeight={30} searchable searchPlaceholder={t('crIsoSearchNode')} maxHeight={480}
                            loading={(read.loading && !mine) || (dsLoading && !nodes.length)} error={!mine && read.error ? read.error : null}
                            emptyText={!mine ? (read.error || t('crIsoNotRead')) : t('crIsoUnlistedShort')} />
                    </CrNcSection>
                </div>
            );
        }
        try {
            window.PegaProxCrIsoSync = CrIsoSync;
            window.PegaProxCrIso = { crIsoNodes, crIsoRows, crIsoCounts, crIsoNodeRows, crIsoTake, crIsoSettle, crIsoTracked };
        } catch (_) {}
