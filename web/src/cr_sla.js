        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the Backup SLA of a cluster - LW Nov 2026
        // How old the newest backup of a guest may be, and which guests are within that, close to
        // it, past it or without any backup at all. The read, the target and its Save are the ones
        // of the classic sub tab, passed in from DatastoreTab (refreshSla, saveSlaConfig and the
        // draft they share): GET backup-sla and PUT backup-sla/config with the same body. Beside it
        // one read of the backup jobs (GET /backup-coverage, the read of the guest list) says which
        // guests no job selects. Nothing is read per guest.
        // ═══════════════════════════════════════════════════════════

        // the server calls a guest at risk from this share of the target on (get_backup_sla in
        // pegaprox/api/clusters.py). Its answer does not carry it, so the page only says it and
        // never decides a state with it
        const CR_SLA_WARN_SHARE = 0.8;
        // the state a guest is listed under, the most urgent first (the order the server sorts in)
        const CR_SLA_ORDER = ['breached', 'missing', 'warning', 'ok', 'off', 'unknown'];
        const CR_SLA_TONE = { breached: 'error', missing: 'error', warning: 'warning', ok: 'success', off: 'neutral', unknown: 'neutral' };
        const CR_SLA_WORD = { breached: 'crSlaExpired', missing: 'crSlaMissing', warning: 'crSlaAtRisk', ok: 'crSlaCompliant',
                              off: 'crSlaNoTarget', unknown: 'crSlaUnknown' };
        const CR_SLA_TILES = ['ok', 'warning', 'breached', 'missing', 'nojob'];
        const CR_SLA_CHIPS = ['all', 'attention', 'ok', 'warning', 'breached', 'missing', 'nojob'];
        // the states that only exist once a target is set
        const CR_SLA_NEEDS_TARGET = ['ok', 'warning', 'breached'];

        const crSlaNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const crSlaHours = (h, t) => crFill(t('crSlaHoursN'), { n: Number(h).toLocaleString(crLocale(), { maximumFractionDigits: 1 }) });

        // With a target the server decides the state (sla_status). Without one it only says whether
        // a backup was found at all, so a guest is missing or has no target, never compliant
        function crSlaState(v, enabled) {
            if (!enabled) return v.last_backup_ts ? 'off' : 'missing';
            return { ok: 'ok', warning: 'warning', breached: 'breached', 'no-backup': 'missing' }[v.sla_status] || 'unknown';
        }

        // which guests of this cluster no backup job selects: the guests /backup-coverage lists for
        // it once its read of the cluster is ok. Anything else is a reason, never "all covered"
        function crSlaJobs(cov, clusterId) {
            if (cov === undefined) return { state: 'loading', ids: null };
            if (!cov || !Array.isArray(cov.clusters)) return { state: 'failed', ids: null };
            const c = cov.clusters.find(x => x && x.cluster_id === clusterId);
            if (!c) return { state: 'absent', ids: null };
            if (c.state !== 'ok') return { state: c.state, ids: null };
            const ids = new Set((cov.guests || []).filter(g => g && g.cluster_id === clusterId).map(g => String(g.vmid)));
            return { state: 'ok', ids, at: c.checked_at };
        }

        // one row per guest of the answer: its state, the hours left until it expires (negative:
        // past it) and what the backup jobs say of it (null: not read)
        function crSlaRows(data, jobIds, templates) {
            const enabled = !!(data && data.enabled);
            const max = data && crSlaNum(data.max_age_hours) ? data.max_age_hours : 0;
            return ((data && data.vms) || []).map(v => {
                const id = String(v.vmid);
                const left = enabled && max > 0 && crSlaNum(v.age_hours) ? Math.round((max - v.age_hours) * 10) / 10 : null;
                return { ...v, id, key: `${v.type}-${id}`, state: crSlaState(v, enabled), left,
                         job: jobIds ? (jobIds.has(id) ? 'none' : 'in') : null, template: templates ? templates.has(id) : null };
            });
        }

        function crSlaCounts(rows) {
            const n = { all: rows.length, attention: 0, nojob: 0, found: 0, pbs: 0, local: 0, template: 0 };
            CR_SLA_ORDER.forEach(k => { n[k] = 0; });
            rows.forEach(r => {
                n[r.state] += 1;
                if (r.state === 'breached' || r.state === 'missing' || r.state === 'warning') n.attention += 1;
                if (r.job === 'none') n.nojob += 1;
                if (r.last_backup_ts) n.found += 1;
                if (r.backup_source === 'pbs') n.pbs += 1;
                else if (r.backup_source === 'local') n.local += 1;
                if (r.template) n.template += 1;
            });
            return n;
        }
        const crSlaMatch = (key) => (r) => (key === 'all' ? true
            : key === 'attention' ? (r.state === 'breached' || r.state === 'missing' || r.state === 'warning')
            : key === 'nojob' ? r.job === 'none' : r.state === key);

        function crSlaJobsWhy(jobs, err, t) {
            return { loading: t('loading'), failed: crFill(t('crSlaJobsFailed'), { reason: err || '-' }), absent: t('crSlaJobsAbsent'),
                     offline: t('crSlaJobsOffline'), denied: t('crSlaJobsDenied'), unreadable: t('crSlaJobsUnreadable') }[jobs.state]
                || t('crSlaJobsUnreadable');
        }

        // --- cells ---------------------------------------------------------------------------------

        function CrSlaState({ state }) {
            const { t } = useTranslation();
            return <span data-cr-sla-state={state}><CrBadge tone={CR_SLA_TONE[state] || 'neutral'}>{t(CR_SLA_WORD[state] || 'crSlaUnknown')}</CrBadge></span>;
        }

        function crSlaLeft(r, t) {
            if (r.left == null) return '';
            if (r.left >= 0) {
                return <span className={r.state === 'warning' ? 'cr-tone-text cr-tone-warning' : undefined} data-cr-sla-left="">
                    {crFill(t('crSlaLeftN'), { t: crVmAge(r.left, t) })}</span>;
            }
            return <span className="cr-tone-text cr-tone-error" data-cr-sla-left="">{crFill(t('crSlaOverN'), { t: crVmAge(-r.left, t) })}</span>;
        }

        // --- the target ----------------------------------------------------------------------------

        // One target for the whole cluster, edited in place. The field is the draft DatastoreTab keeps
        // for its classic Save, so what the edit bar lists is what that Save sends: parseInt of the
        // field, 0 (off) when it is not a number
        function CrSlaTarget({ data, editing, draft, saving, loading, canEdit, why, onEdit, onDraft, onCancel, onSave }) {
            const { t } = useTranslation();
            const stored = data ? (crSlaNum(data.max_age_hours) ? data.max_age_hours : 0) : null;
            const next = parseInt(draft, 10) || 0;
            const word = (h) => (h > 0 ? crSlaHours(h, t) : t('crSlaOffWord'));
            const changed = editing && stored != null && next !== stored;
            const diff = changed ? [{ k: 'max_age_hours', label: t('crSlaMaxAge'), from: word(stored), to: word(next) }] : [];
            const raw = String(draft == null ? '' : draft).trim();
            const odd = raw !== '' && !(/^\d+$/.test(raw) && Number(raw) <= 8760);
            const hint = odd ? crFill(t('crSlaRange'), { n: word(next) }) : t('crSlaZeroOff');
            const note = next > 0 ? crFill(t('crSlaEditNote'), { w: crSlaHours(next * CR_SLA_WARN_SHARE, t), h: crSlaHours(next, t) })
                : t('crSlaEditNoteOff');
            const on = stored > 0;

            let body;
            if (!data) body = loading ? <CrNcState id="sla-target" kind="loading" /> : <CrNcMissing />;
            else if (editing) {
                body = (
                    <div className="cr-nc-form" data-cr-sla-form="">
                        <CrNcField id="sla-max" label={t('crSlaMaxAgeHours')} changed={changed} was={word(stored)}
                            hint={hint} hintTone={odd ? 'warning' : undefined}>
                            <input id="cr-nc-sla-max" type="number" min="0" max="8760" step="1" className="cr-input" value={draft}
                                onChange={e => onDraft(e.target.value)} data-cr-sla-field="max" />
                        </CrNcField>
                    </div>
                );
            } else {
                body = (
                    <CrNcKv id="sla-target" label={t('crSlaTargetTitle')} rows={[
                        { k: 'max', label: t('crSlaMaxAge'), value: word(stored) },
                        { k: 'warn', label: t('crSlaAtRiskFrom'), value: on ? crSlaHours(stored * CR_SLA_WARN_SHARE, t) : '',
                          missing: t('crSlaNotEvaluated'), note: on ? t('crSlaWarnNote') : '' },
                        { k: 'breached', label: t('crSlaExpiredFrom'), value: on ? crSlaHours(stored, t) : '', missing: t('crSlaNotEvaluated') },
                        { k: 'missing', label: t('crSlaMissing'), value: t('crSlaMissingRule'), wide: true },
                        { k: 'scope', label: t('crSlaAppliesTo'), value: t('crSlaAppliesAll'), wide: true },
                    ]} />
                );
            }
            return (
                <CrNcSection id="sla-target" data-cr-sla-target={on ? 'on' : 'off'} title={t('crSlaTargetTitle')} desc={t('crSlaTargetDesc')}
                    editing={editing}
                    badge={editing ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : <CrNcUpdating on={loading && !!data} />}
                    actions={!editing && (
                        <CrButton icon={<Icons.Edit />} onClick={onEdit} disabled={!canEdit || !data} title={!canEdit ? why : undefined} data-cr-sla-edit="">
                            {t('edit')}
                        </CrButton>
                    )}
                    foot={editing && (
                        <CrNcEditBar id="sla-target" count={diff.length} saving={saving} canSave={diff.length > 0} readOnly={!canEdit}
                            onCancel={onCancel} onSave={onSave} note={note}>
                            {diff.length > 0 && <CrNcChanges id="sla-target" rows={diff} />}
                        </CrNcEditBar>
                    )}>
                    {body}
                    {!canEdit && why && <p className="cr-sla-fine" data-cr-sla-readonly="">{why}</p>}
                </CrNcSection>
            );
        }

        // --- the coverage --------------------------------------------------------------------------

        function CrSlaCoverage({ data, n, jobs, jobsErr, loading }) {
            const { t } = useTranslation();
            const pct = (a, b) => (b ? crPct((a / b) * 100, a === b || a === 0 ? 0 : 1) : '-');
            let body;
            if (!data) body = loading ? <CrNcState id="sla-coverage" kind="loading" /> : <CrNcMissing />;
            else {
                body = (
                    <CrNcKv id="sla-coverage" label={t('crSlaCoverageTitle')} rows={[
                        { k: 'guests', label: t('crSlaGuests'), value: String(n.all) },
                        { k: 'found', label: t('crSlaWithBackup'), value: n.all ? `${n.found} (${pct(n.found, n.all)})` : '0' },
                        { k: 'missing', label: t('crSlaNoneFound'), value: String(n.missing) },
                        { k: 'nojob', label: t('crSlaNoJob'), value: jobs.state === 'ok' ? String(n.nojob) : '',
                          missing: crSlaJobsWhy(jobs, jobsErr, t) },
                        { k: 'where', label: t('crSlaNewestOn'), value: n.found ? crFill(t('crSlaWhere'), { pbs: n.pbs, local: n.local }) : '',
                          missing: t('crSlaNoneYet') },
                        n.template > 0 && { k: 'template', label: t('crSlaTemplates'), value: String(n.template), note: t('crSlaTemplatesNote') },
                        { k: 'read', label: t('crSlaReadAt'), value: crSlaNum(data.now) ? crFmtDate(data.now) : '', note: t('crSlaServerClock') },
                        { k: 'jobsat', label: t('crSlaJobsAt'), value: jobs.state === 'ok' && jobs.at ? crFmtDate(jobs.at) : '' },
                    ]} />
                );
            }
            return (
                <CrNcSection id="sla-coverage" title={t('crSlaCoverageTitle')} desc={t('crSlaCoverageDesc')}>
                    {body}
                </CrNcSection>
            );
        }

        // --- the page ------------------------------------------------------------------------------

        function CrBackupSla({ clusterId, data, loading, error, saving, draft, onDraft, onSave, onRefresh, canConfig, guests, onOpenGuest }) {
            const { t } = useTranslation();
            const { getAuthHeaders, haReadOnly } = useAuth();
            const headers = useRef(getAuthHeaders);
            headers.current = getAuthHeaders;
            const [cov, setCov] = useState(undefined);
            const [covErr, setCovErr] = useState('');
            // a Refresh keeps the answer on screen (and a filter on it) until the new one is in
            const [covBusy, setCovBusy] = useState(false);
            const [filter, setFilter] = useState('all');
            const [editing, setEditing] = useState(false);
            const covSeq = useRef(0);
            const tableRef = useRef(null);

            // the read of the guest list's backup coverage panel; Refresh asks it to read anew
            const loadJobs = useCallback(async (refresh) => {
                const mine = ++covSeq.current;
                if (refresh) setCovBusy(true);
                else setCov(undefined);
                setCovErr('');
                try {
                    const res = await fetch(`${API_URL}/backup-coverage${refresh ? '?refresh=1' : ''}`,
                        { credentials: 'include', headers: headers.current() });
                    if (mine !== covSeq.current) return;
                    if (res.ok) {
                        const body = await res.json();
                        if (mine === covSeq.current) setCov(body || null);
                    } else {
                        const msg = await PegaProxApiErrors.message(res, t('crSlaJobsFailedShort'));
                        if (mine === covSeq.current) { setCov(null); setCovErr(msg); }
                    }
                } catch (e) {
                    if (mine === covSeq.current) { setCov(null); setCovErr(t('crSlaJobsFailedShort')); }
                } finally {
                    if (mine === covSeq.current) setCovBusy(false);
                }
            }, []);  // eslint-disable-line react-hooks/exhaustive-deps
            useEffect(() => { loadJobs(false); }, [loadJobs]);

            // an answer of another cluster (the tab kept it from before) is not this one's
            const mine = data && String(data.cluster_id) === String(clusterId) ? data : null;
            const guestMap = useMemo(() => (Array.isArray(guests)
                ? new Map(guests.filter(g => g && (g.type === 'qemu' || g.type === 'lxc')).map(g => [String(g.vmid), g])) : null), [guests]);
            const templates = useMemo(() => (guestMap
                ? new Set([...guestMap.values()].filter(g => g.template).map(g => String(g.vmid))) : null), [guestMap]);
            const jobs = useMemo(() => crSlaJobs(cov, clusterId), [cov, clusterId]);
            const rows = useMemo(() => crSlaRows(mine, jobs.ids, templates), [mine, jobs, templates]);
            const n = useMemo(() => crSlaCounts(rows), [rows]);
            const enabled = !!(mine && mine.enabled);
            const max = mine && crSlaNum(mine.max_age_hours) ? mine.max_age_hours : 0;
            const rowFilter = useMemo(() => (filter === 'all' ? undefined : crSlaMatch(filter)), [filter]);
            const canEdit = !!canConfig && !haReadOnly;
            const why = haReadOnly ? t('crNcReadOnly') : t('crSlaNeedsPerm');

            // a filter the answer cannot serve (no target, the jobs not read) is lifted
            useEffect(() => {
                if ((!enabled && CR_SLA_NEEDS_TARGET.includes(filter)) || (filter === 'nojob' && jobs.state !== 'ok')) setFilter('all');
            }, [enabled, jobs.state]);  // eslint-disable-line react-hooks/exhaustive-deps

            const pick = (k, scroll) => {
                setFilter(f => (f === k && k !== 'all' ? 'all' : k));
                if (scroll && tableRef.current) tableRef.current.scrollIntoView({ block: 'start', behavior: 'smooth' });
            };
            const refresh = () => { onRefresh(); loadJobs(true); };
            const edit = () => { onDraft(String(max)); setEditing(true); };
            const cancel = () => { onDraft(String(max)); setEditing(false); };
            const save = async () => { if (await onSave()) setEditing(false); };
            const usable = (k) => !!mine && (!CR_SLA_NEEDS_TARGET.includes(k) || enabled) && (k !== 'nojob' || jobs.state === 'ok');

            const tileVal = (k) => {
                if (!mine) return loading ? <span className="cr-spinner" role="status" aria-label={t('loading')} /> : <CrNcMissing />;
                if (CR_SLA_NEEDS_TARGET.includes(k) && !enabled) return <CrNcMissing text={t('crSlaNotConfigured')} />;
                if (k === 'nojob' && jobs.state !== 'ok') return jobs.state === 'loading'
                    ? <span className="cr-spinner" role="status" aria-label={t('loading')} /> : <CrNcMissing />;
                return n[k];
            };
            const tileSub = (k) => {
                if (!mine) return '';
                if (CR_SLA_NEEDS_TARGET.includes(k) && !enabled) return t('crSlaSetTarget');
                if (k === 'ok') return crFill(t('crSlaSubOk'), { h: crSlaHours(max, t) });
                if (k === 'warning') return crFill(t('crSlaSubWarn'), { w: crSlaHours(max * CR_SLA_WARN_SHARE, t) });
                if (k === 'breached') return crFill(t('crSlaSubExpired'), { h: crSlaHours(max, t) });
                if (k === 'missing') return t('crSlaNoneFoundShort');
                return jobs.state === 'ok' ? t('crSlaSubNoJob') : jobs.state === 'loading' ? '' : crSlaJobsWhy(jobs, covErr, t);
            };
            const tileTone = (k) => (!mine || !n[k] || !usable(k) ? undefined
                : k === 'breached' || k === 'missing' ? 'error' : k === 'warning' || k === 'nojob' ? 'warning' : undefined);
            const word = (k) => t({ ok: 'crSlaCompliant', warning: 'crSlaAtRisk', breached: 'crSlaExpired', missing: 'crSlaMissing',
                                    nojob: 'crSlaNoJob', all: 'all', attention: 'crSlaAttention' }[k]);
            const pctVal = mine && enabled && crSlaNum(mine.summary && mine.summary.compliance_pct) ? mine.summary.compliance_pct : null;
            const measured = n.all - n.off;

            const cols = useMemo(() => [
                { key: 'guest', label: t('crSlaColGuest'), width: 190, sortValue: r => Number(r.vmid), text: r => `${r.vmid} ${r.name || ''}`,
                  render: r => {
                      // the guest of the page's list with this vmid, if it is the same kind
                      const g0 = guestMap && onOpenGuest ? guestMap.get(r.id) || null : null;
                      const g = g0 && (g0.type === 'lxc') === (r.type === 'ct') ? g0 : null;
                      return (
                          <span className="cr-sla-guest" data-cr-sla-row={r.vmid}>
                              <span className="cr-mono cr-muted">{r.vmid}</span>{' '}
                              {g ? <button type="button" className="cr-link" title={crFill(t('crTaskOpenTarget'), { name: r.name || r.vmid })}
                                      onClick={(e) => { e.stopPropagation(); onOpenGuest(g); }}>{r.name || '-'}</button>
                                 : <span className="cr-strong">{r.name || '-'}</span>}
                              {r.template && <CrBadge tone="neutral" dot={false}>{t('crSlaTemplate')}</CrBadge>}
                          </span>
                      );
                  } },
                { key: 'state', label: t('crSlaColState'), width: 130, sortValue: r => CR_SLA_ORDER.indexOf(r.state), text: r => t(CR_SLA_WORD[r.state]),
                  render: r => <CrSlaState state={r.state} /> },
                { key: 'type', label: t('type'), width: 58, text: r => r.type, render: r => (r.type === 'ct' ? 'CT' : 'VM') },
                { key: 'node', label: t('node'), width: 90, render: r => r.node || '' },
                { key: 'last', label: t('crSlaColLast'), width: 150, sortValue: r => (r.last_backup_ts ? r.last_backup_ts : null),
                  text: r => (r.last_backup_ts ? crFmtDate(r.last_backup_ts) : ''),
                  render: r => (r.last_backup_ts ? crFmtDate(r.last_backup_ts) : <span className="cr-muted">{t('crSlaNoneFoundShort')}</span>) },
                { key: 'age', label: t('crSlaColAge'), width: 84, sortValue: r => r.age_hours,
                  render: r => (crSlaNum(r.age_hours) ? <span title={crSlaHours(r.age_hours, t)}>{crVmAge(r.age_hours, t)}</span> : '') },
                { key: 'left', label: t('crSlaColLeft'), width: 116, sortValue: r => r.left, render: r => crSlaLeft(r, t) },
                { key: 'source', label: t('crSlaColSource'), width: 112, text: r => r.backup_source || '',
                  render: r => (r.backup_source === 'pbs' ? t('crSlaSrcServer') : r.backup_source === 'local'
                      ? <span title={t('crSlaWhereNote')}>{t('crSlaSrcStorage')}</span> : '') },
                { key: 'job', label: t('crSlaColJob'), width: 120, sortValue: r => (r.job == null ? null : r.job === 'none' ? 0 : 1),
                  text: r => (r.job === 'none' ? t('crSlaNoJob') : ''),
                  render: r => (r.job == null ? <span data-cr-sla-job=""><CrNcMissing /></span>
                      : r.job === 'none' ? <span data-cr-sla-job="none"><CrBadge tone="warning">{t('crSlaNoJobShort')}</CrBadge></span>
                      : <span className="cr-muted" data-cr-sla-job="in">{t('crSlaInJob')}</span>) },
                { key: 'status', label: t('crSlaColPower'), width: 84, hidden: true, render: r => r.status || '' },
            ], [t, guestMap, onOpenGuest]);  // eslint-disable-line react-hooks/exhaustive-deps

            return (
                <div className="cr-sla" data-cr-sla={clusterId}>
                    <CrPageHeader icon={<Icons.Shield />} title={t('backupSla') || 'Backup SLA'} sub={t('crSlaSub')}
                        actions={(
                            <>
                                {((loading && mine) || covBusy) && <span className="cr-spinner" role="status" aria-label={t('loading')} data-cr-sla-busy="" />}
                                <button type="button" className="cr-icon-btn" onClick={refresh} disabled={editing}
                                    aria-label={t('refresh')} title={editing ? t('crSlaRefreshEditing') : t('refresh')} data-cr-sla-refresh="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>
                                </button>
                            </>
                        )} />
                    {haReadOnly && <CrNcState id="sla-standby" kind="info">{t('crSlaStandby')}</CrNcState>}
                    {error && (
                        <CrNcState id="sla-read" kind="error" onRetry={onRefresh} retryDisabled={loading} data-cr-sla-error="">
                            {crFill(t(mine ? 'crSlaReadFailedOld' : 'crSlaReadFailed'), { reason: error })}
                        </CrNcState>
                    )}
                    {!mine && !loading && !error && (
                        <CrNcState id="sla-read" kind="info" onRetry={onRefresh} data-cr-sla-unread="">{t('crSlaNotRead')}</CrNcState>
                    )}
                    {/* LW Nov 2026 - storages the server could not read: their guests may show no backup or an older one */}
                    {mine && Array.isArray(mine.unread) && mine.unread.length > 0 && (() => {
                        // a confined account gets the count without names
                        const named = mine.unread.filter(u => u && typeof u === 'object' && (u.storage || u.node));
                        return (
                            <CrNcState id="sla-stores" kind="warning" onRetry={onRefresh} retryDisabled={loading} data-cr-sla-unread-stores={mine.unread.length}>
                                {named.length
                                    ? crFill(t('crSlaUnreadStores'), { n: mine.unread.length,
                                        list: named.map(u => `${u.storage || '-'}${u.node ? ` (${u.node})` : ''}`).join(', ') })
                                    : crFill(t('crSlaUnreadStoresCount'), { n: mine.unread.length })}
                            </CrNcState>
                        );
                    })()}
                    {mine && !enabled && <CrNcState id="sla-off" kind="info" data-cr-sla-off="">{t('crSlaOffHint')}</CrNcState>}

                    <h2 className="cr-sla-h">{t('crSlaSecOverview')}</h2>
                    <div className="cr-stat-row cr-sla-stats" role="group" aria-label={t('crSlaSecOverview')}>
                        <CrStat id="sla-compliance" label={t('compliance') || 'Compliance'} title={t('crSlaComplianceTitle')}
                            value={!mine ? (loading ? <span className="cr-spinner" role="status" aria-label={t('loading')} /> : <CrNcMissing />)
                                : !enabled ? <CrNcMissing text={t('crSlaNotConfigured')} /> : pctVal == null ? '-' : crPct(pctVal, pctVal % 1 ? 1 : 0)}
                            sub={!mine ? '' : !enabled ? t('crSlaSetTarget') : crFill(t('crSlaOkOf'), { ok: n.ok, total: measured })}
                            meter={pctVal} meterTone="info" />
                        <CrStat id="sla-found" label={t('crSlaWithBackup')} title={t('crSlaFoundTitle')}
                            value={!mine ? <CrNcMissing /> : n.all ? crPct((n.found / n.all) * 100, n.found === n.all || !n.found ? 0 : 1) : '-'}
                            sub={mine ? crFill(t('crSlaFoundOf'), { n: n.found, total: n.all }) : ''}
                            meter={mine && n.all ? (n.found / n.all) * 100 : null} meterTone="info" />
                        {CR_SLA_TILES.map(k => (
                            <CrStat key={k} id={`sla-${k}`} label={word(k)} value={tileVal(k)} sub={tileSub(k)} tone={tileTone(k)}
                                title={[word(k), tileSub(k)].filter(Boolean).join(': ')}
                                onClick={usable(k) ? () => pick(k, true) : undefined} pressed={usable(k) ? filter === k : undefined} />
                        ))}
                    </div>
                    {mine && (
                        <p className="cr-sla-fine" data-cr-sla-basis="">
                            {crFill(t('crSlaBasis'), { at: crSlaNum(mine.now) ? crFmtDate(mine.now) : '-' })}
                            {n.template > 0 && <> {crFill(t('crSlaTemplatesCounted'), { n: n.template })}</>}
                        </p>
                    )}

                    <h2 className="cr-sla-h">{t('crSlaSecTarget')}</h2>
                    <div className="cr-sla-cols">
                        <CrSlaTarget data={mine} editing={editing} draft={draft} saving={saving} loading={loading} canEdit={canEdit} why={why}
                            onEdit={edit} onDraft={onDraft} onCancel={cancel} onSave={save} />
                        <CrSlaCoverage data={mine} n={n} jobs={jobs} jobsErr={covErr} loading={loading} />
                    </div>

                    <h2 className="cr-sla-h" ref={tableRef}>{t('crSlaSecGuests')}</h2>
                    <CrNcSection id="sla-guests" title={t('crSlaGuestsTitle')} desc={t('crSlaGuestsDesc')}>
                        <CrTable id="sla-guests" columns={cols} rows={rows} rowKey={r => r.key} ariaLabel={t('crSlaGuestsTitle')} rowHeight={30}
                            filter={rowFilter} searchable searchPlaceholder={t('crSlaSearch')}
                            loading={loading && !mine} error={!mine && error ? error : null} emptyText={t('crSlaNoGuests')}
                            initialSort={{ key: 'state', dir: 'asc' }} maxHeight={560}
                            toolbar={(
                                <div className="cr-seg" role="group" aria-label={t('filter')} data-cr-sla-chips="">
                                    {CR_SLA_CHIPS.filter(k => k === 'all' || k === 'attention' || usable(k)).map(k => (
                                        <button key={k} type="button" className={filter === k ? 'active' : ''} aria-pressed={filter === k}
                                            onClick={() => pick(k, false)} data-cr-sla-chip={k}>
                                            {word(k)} <span className="cr-seg-n">{n[k]}</span>
                                        </button>
                                    ))}
                                </div>
                            )} />
                    </CrNcSection>
                </div>
            );
        }
        try { window.PegaProxCrBackupSla = CrBackupSla; window.PegaProxCrSla = { crSlaState, crSlaRows, crSlaCounts, crSlaJobs }; } catch (_) {}
