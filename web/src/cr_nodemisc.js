        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the timeline, the node shell and the node subscription - LW Nov 2026
        // The timeline is the one list TimelineView (dashboard.js) reads for a cluster, a node and a
        // guest: the view keeps its reads, its filters and its pages and hands them here, so all three
        // places draw the same table with the task center's badges. The shell wraps the one
        // NodeShellTerminal (its socket, its login) with a bar that says what the session is doing.
        // The subscription is what the node reports, read once per visit like the classic grid; an
        // answer without a field says "not reported", never a dash or a state.
        // ═══════════════════════════════════════════════════════════

        // --- the timeline ---------------------------------------------------------------------------

        // the severity of an event in the task center's tones
        const CR_TL_TONE = { critical: 'error', warning: 'warning', info: 'neutral' };
        const crTlTone = (sev) => CR_TL_TONE[sev] || 'neutral';
        const crTlRowClass = (sev) => (sev === 'critical' ? 'cr-nt-row-failed' : sev === 'warning' ? 'cr-nt-row-warn' : '');
        // an event has something to open: its details or what happened shortly before it
        const crTlHasMore = (e) => !!(e && (e.details || (Array.isArray(e.shortly_before) && e.shortly_before.length)));

        function CrTlKind({ k, tl, t }) {
            const known = tl.kinds[k];
            return <span data-tl-badge={k}><CrBadge tone="neutral" dot={false}>{known ? t(known[0]) : (k || '-')}</CrBadge></span>;
        }

        // TimelineView's state in Corporate Redesigned's table. scope is cluster, node or guest; tl carries the
        // view's kinds, ranges, linked views and texts (dashboard.js), so both draw the same words
        function CrTimeline({ scope, node, hours, kind, severity, onHours, onKind, onSeverity, rows, next, sources, linkWindow,
                              loaded, failed, loading, leaderAway, open, onToggle, onRefresh, onMore, compact, evidence,
                              onOpenGuest, onOpenNode, onOpenTab, tl }) {
            const { t } = useTranslation();
            const fill = (key, vals) => tl.fill(t, key, vals);
            const sevLabel = (s) => t(s === 'critical' ? 'tlSevCritical' : s === 'warning' ? 'tlSevWarning' : 'tlSevInfo');
            const hidden = Object.keys(sources || {}).filter(k => tl.kinds[k] && sources[k] && sources[k].shown === false);
            const guestLabel = (e) => (e.guest_name ? `${e.guest_name} (${e.guest})` : String(e.guest));
            const before = (s) => (s >= 60 ? fill('tlMinBefore', { m: Math.round(s / 60) }) : fill('tlSecBefore', { s }));
            const read = leaderAway ? 'away' : failed ? 'error' : !loaded ? 'loading' : rows.length ? 'ok' : 'empty';
            const stop = (fn) => (ev) => { ev.stopPropagation(); fn(); };

            const columns = useMemo(() => {
                const cols = [
                    { key: 'more', label: '', menuLabel: t('crTlMore'), width: 46, sortable: false, resizable: false,
                      render: e => {
                          if (!crTlHasMore(e)) return null;
                          const n = (e.shortly_before || []).length;
                          return (
                              <button type="button" className="cr-tl-toggle" tabIndex={-1} aria-expanded={!!open[e.id]}
                                  title={n ? fill('tlShortlyBefore', { n }) : t('crTlMore')} data-cr-tl-toggle={e.id}
                                  onClick={stop(() => onToggle(e.id))}>
                                  {open[e.id] ? <Icons.ChevronDown className="w-3 h-3" /> : <Icons.ChevronRight className="w-3 h-3" />}
                                  {n > 0 && <span className="cr-tl-n">{n}</span>}
                              </button>
                          );
                      } },
                    { key: 'severity', label: t('tlFilterSeverity'), width: 92,
                      sortValue: e => ['critical', 'warning', 'info'].indexOf(e.severity in CR_TL_TONE ? e.severity : 'info'),
                      text: e => sevLabel(e.severity),
                      render: e => <span data-tl-sev={e.severity}><CrBadge tone={crTlTone(e.severity)}>{sevLabel(e.severity)}</CrBadge></span> },
                    { key: 'time', label: t('time'), width: 156, mono: true, sortValue: e => { const v = Date.parse(e.time); return isNaN(v) ? null : v; },
                      render: e => <span title={e.time || ''}>{crFmtDate(e.time) || e.time || ''}</span> },
                    { key: 'kind', label: t('crTlKind'), width: 116, sortValue: e => (tl.kinds[e.kind] ? t(tl.kinds[e.kind][0]) : e.kind),
                      render: e => <CrTlKind k={e.kind} tl={tl} t={t} /> },
                    { key: 'event', label: t('crTlEvent'), flex: true, min: 200, sortValue: e => tl.text(e, t),
                      render: e => {
                          const text = tl.text(e, t);
                          const view = onOpenTab && tl.views[e.kind];
                          const tone = crTlTone(e.severity);
                          return (
                              <span className="cr-tl-event">
                                  <span className={`cr-tl-text${tone !== 'neutral' ? ` cr-tc-result-${tone}` : ''}`} title={e.details ? `${text}\n${e.details}` : text} data-tl-text="">{text}</span>
                                  {view && (
                                      <button type="button" className="cr-tc-link cr-tl-open" tabIndex={-1} data-tl-open-view={view}
                                          onClick={stop(() => onOpenTab(view, e))}>{t('tlOpenView')}</button>
                                  )}
                              </span>
                          );
                      } },
                    // on a node's page the column is that node; the column menu shows it again
                    { key: 'node', label: t('node'), width: 110, hidden: scope === 'node', sortValue: e => e.node || null,
                      render: e => {
                          if (!e.node) return <span className="cr-muted">-</span>;
                          if (e.node === node || !onOpenNode) return <span className={e.node === node ? 'cr-muted' : undefined}>{e.node}</span>;
                          return (
                              <button type="button" className="cr-tc-link" tabIndex={-1} data-tl-open-node={e.node}
                                  onClick={stop(() => onOpenNode(e.node))}>{e.node}</button>
                          );
                      } },
                ];
                if (scope !== 'guest') {
                    cols.push({ key: 'guest', label: t('crNtGuest'), width: 140, sortValue: e => (e.guest != null ? guestLabel(e) : null),
                        render: e => {
                            if (e.guest == null) return <span className="cr-muted">-</span>;
                            if (!onOpenGuest) return <span>{guestLabel(e)}</span>;
                            return (
                                <button type="button" className="cr-tc-link" tabIndex={-1} data-tl-open-guest={e.guest}
                                    onClick={stop(() => onOpenGuest(e.guest))}>{guestLabel(e)}</button>
                            );
                        } });
                }
                return cols;
            }, [t, scope, node, open, onOpenGuest, onOpenNode, onOpenTab, tl]);

            const renderMore = (e) => {
                const links = e.shortly_before || [];
                return (
                    <div className="cr-tl-detail" data-cr-tl-detail={e.id}>
                        {e.details && <p className="cr-tl-details" data-tl-details="">{e.details}</p>}
                        {links.length > 0 && (
                            <div className="cr-tl-links" data-tl-links="">
                                <p className="cr-muted cr-ns-basis" data-tl-links-note="">{fill('tlShortlyBeforeNote', { min: linkWindow })}</p>
                                <ul>
                                    {links.map(x => (
                                        <li key={x.id} data-tl-link={x.id}>
                                            <span className="cr-mono cr-muted cr-tl-ago">{before(x.seconds_before)}</span>
                                            <CrTlKind k={x.kind} tl={tl} t={t} />
                                            <span className="cr-tl-link-text">{tl.text(x, t)}</span>
                                            {x.node && <span className="cr-muted">{x.node}</span>}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>
                );
            };

            const expanded = useMemo(() => {
                const o = {};
                rows.forEach(e => { if (open[e.id] && crTlHasMore(e)) o[e.id] = true; });
                return o;
            }, [rows, open]);
            const filtered = !!(kind || severity);
            const desc = scope === 'guest' ? 'tlDescGuest' : scope === 'node' ? 'tlDescNode' : 'tlDesc';
            return (
                <div className="cr-nn cr-tl" data-timeline={scope} data-cr-tl={scope} data-cr-tl-read={read}>
                    <div className="cr-nn-bar">
                        <h3 className="cr-nn-title">{t('tlTitle')}</h3>
                        <span className="cr-muted cr-nn-count cr-tl-desc">{t(desc)}</span>
                        <div className="cr-nn-acts">
                            <CrButton icon={<Icons.RotateCw />} onClick={onRefresh} disabled={loading} data-tl-refresh="">{t('refresh')}</CrButton>
                        </div>
                    </div>
                    {evidence}
                    {leaderAway && <CrNcState id="timeline" kind="warning" data-tl-leader-away="">{t('pgHaLeaderAwayView')}</CrNcState>}
                    {failed && <CrNcState id="timeline" kind="error" onRetry={onRefresh} retryDisabled={loading} data-tl-error="">{t('tlLoadError')}</CrNcState>}
                    {loaded && hidden.length > 0 && (
                        <p className="cr-muted cr-ns-basis" data-tl-hidden="">{fill('tlHidden', { kinds: hidden.map(k => t(tl.kinds[k][0])).join(', ') })}</p>
                    )}
                    {!leaderAway && <CrTable id={`timeline-${scope}`} columns={columns} rows={failed ? [] : rows} rowKey={e => e.id}
                        ariaLabel={t('tlTitle')} maxHeight={compact ? 384 : 560} loading={!failed && (!loaded || loading)}
                        error={failed ? t('tlLoadError') : null}
                        emptyText={<span data-tl-empty="">{t(filtered ? 'tlNoMatch' : 'tlNone')}</span>}
                        rowClassName={e => crTlRowClass(e.severity)} expanded={expanded} renderExpanded={renderMore}
                        onRowClick={e => { if (crTlHasMore(e)) onToggle(e.id); }}
                        toolbar={(
                            <div className="cr-tc-filters cr-tl-filters">
                                <select value={hours} onChange={e => onHours(Number(e.target.value))} className="cr-select" data-tl-range=""
                                    aria-label={t('tlFilterRange')}>
                                    {tl.ranges.map(([key, h]) => <option key={h} value={h}>{t(key)}</option>)}
                                </select>
                                <select value={kind} onChange={e => onKind(e.target.value)} className="cr-select" data-tl-filter-kind=""
                                    aria-label={t('tlFilterKind')}>
                                    <option value="">{t('tlAllKinds')}</option>
                                    {Object.keys(tl.kinds).map(k => <option key={k} value={k}>{t(tl.kinds[k][0])}</option>)}
                                </select>
                                <select value={severity} onChange={e => onSeverity(e.target.value)} className="cr-select" data-tl-filter-severity=""
                                    aria-label={t('tlFilterSeverity')}>
                                    <option value="">{t('tlAllSeverities')}</option>
                                    {['critical', 'warning', 'info'].map(s => <option key={s} value={s}>{sevLabel(s)}</option>)}
                                </select>
                                {filtered && (
                                    <button type="button" className="cr-btn cr-btn-ghost" data-cr-tl-clear="" onClick={() => { onKind(''); onSeverity(''); }}>
                                        {t('crNgClear')}
                                    </button>
                                )}
                            </div>
                        )} />}
                    {next && !failed && !leaderAway && (
                        <div className="cr-tl-foot">
                            <CrButton onClick={() => onMore(next)} disabled={loading} data-tl-more="">{t('tlLoadMore')}</CrButton>
                            <span className="cr-muted cr-ns-basis">{crNnT(t, 'crTlPaged', { n: rows.length })}</span>
                        </div>
                    )}
                </div>
            );
        }

        // --- the node shell ---------------------------------------------------------------------------

        // what NodeShellTerminal says about its session, as a badge
        const CR_SH_STATE = {
            loading: ['neutral', 'crShLoading'], connecting: ['neutral', 'crShConnecting'], login: ['warning', 'crShLogin'],
            connected: ['success', 'crShConnected'], error: ['error', 'crShError'], disconnected: ['neutral', 'crShDisconnected'],
        };
        const CR_SH_START = { status: 'loading', ip: '', port: null, user: '' };

        // The one terminal of the tab with a bar above it: the session's state, where it logs in, a
        // new session once this one ended, and the window filled the way NodeShellPanel does it (same
        // tree in both states, so the terminal and its session stay; Escape stays the shell's)
        function CrNodeShell({ node, clusterId, addToast }) {
            const { t } = useTranslation();
            const [run, setRun] = useState(0);
            const [st, setSt] = useState(CR_SH_START);
            const [full, setFull] = useState(false);
            // a socket that closes before the login went through never was a session: not connected, not ended
            const [had, setHad] = useState(false);
            useEffect(() => { if (st.status === 'connected') setHad(true); }, [st.status]);
            const reconnect = () => { setSt(CR_SH_START); setHad(false); setRun(n => n + 1); };
            const shown = st.status === 'disconnected' && !had ? 'error' : st.status;
            const [tone, key] = CR_SH_STATE[shown] || ['neutral', ''];
            const ended = shown === 'error' || shown === 'disconnected';
            return (
                <div className={`cr-nn cr-nsh${full ? ' cr-nsh-full' : ''}`} data-cr-nsh={full ? 'window' : 'tab'} data-cr-nsh-state={shown}>
                    <div className="cr-nn-bar">
                        <h3 className="cr-nn-title">{full ? crNnT(t, 'crShTitleNode', { node }) : t('crShTitle')}</h3>
                        <span data-cr-nsh-badge={shown}><CrBadge tone={tone}>{key ? t(key) : shown}</CrBadge></span>
                        <span className="cr-muted cr-nn-count cr-nsh-meta" data-cr-nsh-meta="">
                            {st.ip ? <span className="cr-mono" data-cr-nsh-at="">{st.user ? `${st.user}@${st.ip}` : st.ip}</span>
                                : <span data-cr-nsh-at="">{t('crShAddrServer')}</span>}
                            {st.port != null && <span data-cr-nsh-port={st.port}>{crNnT(t, 'crShPort', { port: st.port })}</span>}
                        </span>
                        <div className="cr-nn-acts">
                            {shown !== 'connected' && shown !== 'loading' && (
                                <CrButton icon={<Icons.RotateCw />} onClick={reconnect} title={t('crShReconnectTitle')} data-cr-nsh-reconnect="">
                                    {t('crShReconnect')}
                                </CrButton>
                            )}
                            <CrButton icon={full ? <Icons.Minimize /> : <Icons.Maximize />} onClick={() => setFull(f => !f)}
                                aria-pressed={full} data-cr-nsh-full="">{full ? t('exitFullscreen') : t('fullscreen')}</CrButton>
                        </div>
                    </div>
                    {ended && <p className="cr-muted cr-ns-basis" data-cr-nsh-ended={shown}>{t(shown === 'error' ? 'crShFailedNote' : 'crShEnded')}</p>}
                    {/* clip, not hidden (#727): Firefox's selection autoscroll cannot scroll a clipped box */}
                    <div className="cr-nsh-term" data-cr-nsh-term="">
                        <NodeShellTerminal key={run} node={node} clusterId={clusterId} addToast={addToast} onStatus={setSt} />
                    </div>
                </div>
            );
        }

        // --- the node subscription ----------------------------------------------------------------------

        const CR_SUB_STATUS = {
            active: ['success', 'crSubActive'], new: ['neutral', 'crSubNew'], notfound: ['neutral', 'crSubNotFound'],
            expired: ['error', 'crSubExpired'], invalid: ['error', 'crSubInvalid'], suspended: ['error', 'crSubSuspended'],
        };
        const CR_SUB_LEVEL = { c: 'crSubLevelC', b: 'crSubLevelB', s: 'crSubLevelS', p: 'crSubLevelP' };

        // the key with its middle hidden: the prefix up to the dash and the last four characters
        function crSubMask(key) {
            const k = String(key == null ? '' : key);
            if (!k) return '';
            const dash = k.indexOf('-');
            const head = dash > 0 && dash < k.length - 5 ? k.slice(0, dash + 1) : '';
            return k.length <= 6 ? '•'.repeat(6) : `${head}${'•'.repeat(6)}${k.slice(-4)}`;
        }

        // a date the node reports as YYYY-MM-DD (and a time): that calendar day, not shifted by a zone
        function crSubDay(v) {
            if (typeof v !== 'string') return null;
            const m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(v.trim());
            if (!m) return null;
            const d = new Date(+m[1], +m[2] - 1, +m[3]);
            return isNaN(d) || d.getMonth() !== +m[2] - 1 ? null : d;
        }

        // the answer of GET .../subscription (or why it failed) as what the page shows
        function crSubModel(read) {
            if (read === undefined) return { state: 'loading' };
            const fail = crNdFail(read);
            if (fail) return { state: 'error', fail };
            if (!read || typeof read !== 'object' || Array.isArray(read)) return { state: 'error', fail: { status: 200, error: '', code: 'NOT_JSON' } };
            const has = (k) => read[k] !== undefined && read[k] !== null && read[k] !== '';
            if (!Object.keys(read).some(has)) return { state: 'empty' };
            const raw = has('status') ? String(read.status) : '';
            const status = raw.toLowerCase();
            const known = CR_SUB_STATUS[status];
            const check = typeof read.checktime === 'number' ? read.checktime
                : (typeof read.checktime === 'string' && /^\d+$/.test(read.checktime) ? +read.checktime : null);
            const url = has('url') && /^https:\/\//i.test(String(read.url)) ? String(read.url) : '';
            return {
                state: 'ok', raw, status: known ? status : (raw ? 'other' : 'none'), tone: known ? known[0] : 'neutral',
                label: known ? known[1] : '', level: has('level') ? String(read.level) : '', levelKey: CR_SUB_LEVEL[String(read.level || '').toLowerCase()] || '',
                product: has('productname') ? String(read.productname) : '', serverid: has('serverid') ? String(read.serverid) : '',
                key: has('key') ? String(read.key) : '', mask: crSubMask(read.key),
                regdate: has('regdate') ? String(read.regdate) : '', reg: crSubDay(read.regdate),
                nextdue: has('nextduedate') ? String(read.nextduedate) : '', due: crSubDay(read.nextduedate),
                checktime: check, sockets: has('sockets') ? read.sockets : null,
                message: has('message') ? String(read.message) : '', url, none: status === 'notfound',
            };
        }
        window.PegaProxNodeMisc = Object.freeze({ subModel: crSubModel, subMask: crSubMask, subDay: crSubDay, tlTone: crTlTone, tlHasMore: crTlHasMore });

        function CrNodeSubscription({ node, read, loading, onReload }) {
            const { t } = useTranslation();
            const [show, setShow] = useState(false);
            const m = crSubModel(read);
            const day = (d, rawText) => (d ? crFmtDate(d, { hour: undefined, minute: undefined, second: undefined }) : rawText);
            const badge = m.state === 'ok' ? (
                <span data-cr-sub-status={m.status}>
                    <CrBadge tone={m.tone}>{m.label ? t(m.label) : m.raw || t('crNsNotReported')}</CrBadge>
                </span>
            ) : null;
            let body;
            if (m.state === 'loading') body = <CrNcState id="subscription" kind="loading" />;
            else if (m.state === 'error') {
                body = <CrNcState id="subscription" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crSubFailed', { why: crNdWhy(t, m.fail) })}</CrNcState>;
            } else if (m.state === 'empty') {
                body = <CrNcState id="subscription" kind="warning" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crSubEmpty', { node })}</CrNcState>;
            } else {
                const key = m.key ? (
                    <span className="cr-sub-key">
                        <span className="cr-mono" data-cr-sub-key={show ? 'shown' : 'masked'}>{show ? m.key : m.mask}</span>
                        <button type="button" className="cr-btn cr-btn-xs cr-btn-ghost" aria-pressed={show} data-cr-sub-reveal=""
                            onClick={() => setShow(v => !v)}>{t(show ? 'crSubHide' : 'crSubShow')}</button>
                    </span>
                ) : '';
                // the status is the badge beside the title, in the node's own word where it is not a known one
                const rows = m.none ? [
                    { k: 'serverid', label: t('crSubServerId'), value: m.serverid, mono: true },
                    { k: 'checked', label: t('crSubChecked'), value: m.checktime != null ? crFmtDate(m.checktime) : '' },
                ] : [
                    { k: 'level', label: t('crSubLevel'), value: m.level ? (m.levelKey ? `${t(m.levelKey)} (${m.level})` : m.level) : '' },
                    { k: 'product', label: t('product'), value: m.product, wide: true },
                    { k: 'serverid', label: t('crSubServerId'), value: m.serverid, mono: true },
                    { k: 'key', label: t('subscriptionKey'), value: key },
                    m.sockets != null && { k: 'sockets', label: t('crSubSockets'), value: String(m.sockets) },
                    { k: 'registered', label: t('crSubRegistered'), value: m.regdate ? day(m.reg, m.regdate) : '' },
                    { k: 'nextdue', label: t('crSubNextDue'), value: m.nextdue ? day(m.due, m.nextdue) : '' },
                    { k: 'checked', label: t('crSubChecked'), value: m.checktime != null ? crFmtDate(m.checktime) : '' },
                ];
                body = (
                    <>
                        <CrNcKv id="subscription" rows={rows} label={t('subscriptionInfo')} />
                        {m.message && <p className="cr-nn-mgmt-line" data-cr-sub-message="">{m.message}</p>}
                        {m.url && (
                            <p className="cr-nn-mgmt-line" data-cr-sub-url="">
                                <a className="cr-tc-link" href={m.url} target="_blank" rel="noopener noreferrer">{t('crSubUrl')}</a>
                            </p>
                        )}
                    </>
                );
            }
            return (
                <div className="cr-nc-page" data-cr-sub="" data-cr-sub-state={m.state}>
                    <CrNcSection id="subscription" title={t('subscriptionInfo')} desc={t('crSubDesc')}
                        badge={<>{badge}<CrNcUpdating on={loading && read !== undefined} /></>}
                        actions={<CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading} data-cr-sub-reload="">{t('refresh')}</CrButton>}>
                        {body}
                    </CrNcSection>
                </div>
            );
        }
