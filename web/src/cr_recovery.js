        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the restore tests of a cluster - LW Nov 2026
        // The Datastore sub tab in five parts: the recovery figures, the weekly run and what a
        // test does, the critical guests and the rules per guest and tag, what runs right now,
        // and the results with the evidence. Every read and write is the one RestoreTestsPanel
        // and RecoveryAssurance (ui.js) send: the same routes, methods and bodies, and the weekly
        // run is still edited in VerifyScheduleModal with its consent. One read of the report and
        // one of the assurance for the whole cluster; the tests of a guest once it is opened.
        // ═══════════════════════════════════════════════════════════

        const CR_RT_DAYS = [7, 14, 30, 60, 90];
        // while a test runs, the weekly run and the live tests are read again this often
        const CR_RT_POLL = 10000;
        // the state a guest is listed under, the most urgent first. One per guest, so the tiles add
        // up to the guests of the cluster
        const CR_RT_ORDER = ['running', 'failed', 'missing', 'never', 'rto_missed', 'stale', 'incomplete', 'passed', 'unknown'];
        const CR_RT_TONE = { running: 'info', failed: 'error', missing: 'error', never: 'neutral', rto_missed: 'warning',
                             stale: 'warning', incomplete: 'warning', passed: 'success', unknown: 'neutral' };
        const CR_RT_WORD = { running: 'crRtRunning', failed: 'crRtFailed', missing: 'crRtMissing', never: 'rtestStateNever',
                             rto_missed: 'rtestStateRto', stale: 'rtestStateStale', incomplete: 'crRtIncomplete', passed: 'crRtPassed',
                             unknown: 'crRtUnknown' };
        const CR_RT_TILES = ['passed', 'failed', 'running', 'never', 'missing', 'incomplete'];
        const CR_RT_CHIPS = ['all', 'attention', 'critical', 'stale', 'rto_missed', 'rpo'];
        const CR_RT_RUN_TONE = { done: 'success', running: 'info', starting: 'info', stopped: 'warning', missed: 'warning', error: 'error' };
        const CR_RT_RESULT_TONE = { passed: 'success', failed: 'error', error: 'error', skipped: 'warning', running: 'info',
                                    queued: 'neutral', open: 'neutral' };
        const CR_RT_PHASE = { restoring: 'restoring', booting: 'booting', verifying: 'verifying', cleanup: 'cleaningUp' };

        const crRtNum = (v) => typeof v === 'number' && Number.isFinite(v);
        // a time the server keeps without a zone, on its own clock, as it wrote it
        const crRtAt = (s, t) => (s ? `${crDriftTime(String(s))} (${t('crDriftServerTime')})` : '');
        const crRtKey = (cid, vmid, volid) => `${cid}|${vmid}|${volid == null ? '*' : volid}`;

        // The guests of this cluster in the weekly run and in the live tests. The weekly run tests
        // its picks one after another, so while it runs the first pick without a result is the one
        // being tested and the rest wait. A pick it did not get to (stopped) stays "open". The live
        // tests come from the verification registry (manual ones and the weekly ones alike).
        function crRtRuns(status, active, clusterId) {
            const map = new Map();
            const plan = [];
            const last = status && status.last_run;
            const weekly = !!(status && status.running && last && (last.state === 'running' || last.state === 'starting'));
            if (last) {
                const done = new Map();
                (last.results || []).forEach(r => { if (r) done.set(crRtKey(r.cluster_id, r.vmid, r.volid), r); });
                const used = new Set();
                let first = true;
                (last.picked || []).forEach(p => {
                    if (!p) return;
                    const k = crRtKey(p.cluster_id, p.vmid, p.volid);
                    const kk = done.has(k) ? k : crRtKey(p.cluster_id, p.vmid, null);
                    const res = done.get(kk) || null;
                    let state;
                    if (res) { state = res.status || 'skipped'; used.add(kk); }
                    else if (weekly) { state = first ? 'running' : 'queued'; first = false; }
                    else state = 'open';
                    if (p.cluster_id !== clusterId) return;
                    plan.push({ key: `p:${k}`, vmid: p.vmid, name: (res && res.name) || p.name || '', state, res, pick: p });
                    const id = String(p.vmid);
                    if (state === 'running') map.set(id, { kind: 'running', source: 'schedule' });
                    else if (state === 'queued' && !map.has(id)) map.set(id, { kind: 'queued', source: 'schedule' });
                });
                // what the run left out before it started (size cap, size unknown) is no pick
                (last.results || []).forEach((r, i) => {
                    if (!r || r.cluster_id !== clusterId) return;
                    const k = crRtKey(r.cluster_id, r.vmid, r.volid);
                    if (used.has(k)) return;
                    plan.push({ key: `r:${k}:${i}`, vmid: r.vmid, name: r.name || '', state: r.status || 'skipped', res: r, pick: null });
                });
            }
            Object.keys(active || {}).forEach(k => {
                const v = active[k];
                if (!v || typeof v !== 'object' || v.status !== 'running') return;
                if (v.cluster_id != null && v.cluster_id !== clusterId) return;
                map.set(String(v.vmid), { kind: 'running', source: v.source || 'manual', phase: v.phase, started_at: v.started_at, id: k });
            });
            return { map, plan, weekly };
        }

        // one row per guest of the report, with what the assurance says of it (null: not read) and
        // the one state it is listed under
        function crRtRows(report, assurance, runs, critTags) {
            const ag = new Map();
            ((assurance && assurance.guests) || []).forEach(g => { if (g) ag.set(String(g.vmid), g); });
            const crit = Array.isArray(critTags) ? new Set(critTags) : null;
            const map = (runs && runs.map) || new Map();
            return ((report && report.guests) || []).map(r => {
                const id = String(r.vmid);
                const a = assurance ? (ag.get(id) || null) : null;
                const inPeriod = r.state === 'ok' || r.state === 'rto_missed';
                const evidence = !a ? null : a.proof === 'proven' ? 'proven' : inPeriod ? 'incomplete' : 'none';
                const run = map.get(id) || null;
                const status = run && run.kind === 'running' ? 'running'
                    : r.state === 'failing' ? 'failed'
                    : r.rpo_state === 'no_backup' ? 'missing'
                    : r.state === 'never' ? 'never'
                    : r.state === 'rto_missed' ? 'rto_missed'
                    : r.state === 'stale' ? 'stale'
                    : r.state === 'ok' ? (evidence === 'incomplete' ? 'incomplete' : 'passed')
                    : 'unknown';
                const critical = a ? !!a.critical : crit ? (r.tags || []).some(x => crit.has(x)) : null;
                return { ...r, id, a, run, evidence, status, critical };
            });
        }

        function crRtCounts(rows) {
            const n = { all: rows.length, attention: 0, critical: 0, rpo: 0 };
            CR_RT_ORDER.forEach(k => { n[k] = 0; });
            rows.forEach(r => {
                n[r.status] += 1;
                if (r.status !== 'passed') n.attention += 1;
                if (r.critical) n.critical += 1;
                if (r.rpo_state === 'breached') n.rpo += 1;
            });
            return n;
        }
        const crRtMatch = (key) => (r) => (key === 'all' ? true : key === 'attention' ? r.status !== 'passed'
            : key === 'critical' ? !!r.critical : key === 'rpo' ? r.rpo_state === 'breached' : r.status === key);

        // the defaults form as RestoreTestsPanel keeps it, and the body its Save sends
        function crRtDraft(c) {
            return { rto: c.rto_minutes ?? '', isolation: c.isolation || 'link_down', bridge: c.test_bridge || '',
                     storage: c.test_storage || '', boot: c.boot_timeout ?? '', agent: c.agent || 'auto',
                     ports: (c.ports || []).join(', '), command: c.command || '' };
        }
        function crRtDefaultsBody(d) {
            return {
                rto_minutes: d.rto === '' ? null : Number(d.rto), isolation: d.isolation,
                test_bridge: d.isolation === 'bridge' ? String(d.bridge).trim() : null, test_storage: String(d.storage).trim() || null,
                boot_timeout: d.boot === '' ? null : Number(d.boot), agent: d.agent,
                ports: rtPorts(d.ports), command: String(d.command).trim() || null,
            };
        }
        // the counts of a run as the server's audit line adds them up (restore_tests.py): the run
        // itself stores none, only its picks and results
        function crRtRunCounts(last) {
            if (last.counts) return last.counts;
            const done = last.results || [];
            const passed = done.filter(r => r && r.status === 'passed').length;
            const failed = done.filter(r => r && (r.status === 'failed' || r.status === 'error')).length;
            return { picked: (last.picked || []).length, passed, failed, skipped: done.length - passed - failed };
        }
        const crRtTags = (text) => String(text || '').split(',').map(s => s.trim()).filter(Boolean);

        try { window.PegaProxCrRecovery = Object.freeze({ runs: crRtRuns, rows: crRtRows, counts: crRtCounts, draft: crRtDraft, body: crRtDefaultsBody }); } catch (_) {}

        // --- cells ---------------------------------------------------------------------------------

        function CrRtStatus({ status }) {
            const { t } = useTranslation();
            return <span data-cr-rt-status={status}><CrBadge tone={CR_RT_TONE[status] || 'neutral'}>{t(CR_RT_WORD[status] || 'crRtUnknown')}</CrBadge></span>;
        }

        function crRtTook(r, t) {
            if (!crRtNum(r.measured_seconds)) return '';
            const took = crVmSecs(r.measured_seconds);
            if (!r.rto_seconds) return <span>{took} <span className="cr-muted">({t('rtestNoRto')})</span></span>;
            const tone = r.rto_state === 'missed' ? 'error' : r.rto_state === 'met' ? 'success' : '';
            return <span className={tone ? `cr-tone-text cr-tone-${tone}` : undefined}>{crFill(t('rtestVsRto'), { took, rto: crVmSecs(r.rto_seconds) })}</span>;
        }

        function crRtBackup(r, t) {
            if (r.rpo_state === 'no_backup') return <span data-cr-rt-backup="no_backup"><CrBadge tone="error">{t('crRtMissing')}</CrBadge></span>;
            if (r.rpo_state === 'unknown' || !crRtNum(r.newest_backup_age_hours)) {
                return <span data-cr-rt-backup="unknown" title={t('rtestBackupsUnreadable')}><CrNcMissing /></span>;
            }
            const tone = r.rpo_state === 'breached' ? 'error' : r.rpo_state === 'warning' ? 'warning' : '';
            const age = crFill(t('rtestAgo'), { t: crVmAge(r.newest_backup_age_hours, t) });
            return (
                <span className={tone ? `cr-tone-text cr-tone-${tone}` : undefined} data-cr-rt-backup={r.rpo_state}
                    title={`${crRtAt(r.newest_backup_at, t)}${r.backup_count != null ? ` - ${crFill(t('crRtBackupsN'), { n: r.backup_count })}` : ''}`}>
                    {age}{r.sla_hours && r.rpo_state !== 'disabled' ? ` / ${crFill(t('rtestSlaOf'), { h: r.sla_hours })}` : ''}
                </span>
            );
        }

        function crRtMissingText(a, t) {
            const m = (a && a.missing) || [];
            return [m.includes('agent_check') && t('crRtMissAgent'), m.includes('application_check') && t('crRtMissApp')].filter(Boolean).join(', ');
        }

        function crRtEvidenceCell(r, t) {
            const conf = r.a && r.a.confirmation;
            const mark = conf ? <span className="cr-rt-conf" title={conf.text}><CrBadge tone="neutral" dot={false}>{t('crRtConfirmedMark')}</CrBadge></span> : null;
            if (r.evidence == null) return <span data-cr-rt-evidence=""><CrNcMissing /></span>;
            if (r.evidence === 'proven') return <span data-cr-rt-evidence="proven"><CrBadge tone="success">{t('rasrProven')}</CrBadge>{mark}</span>;
            if (r.evidence === 'incomplete') {
                return (
                    <span data-cr-rt-evidence="incomplete" title={r.type === 'lxc' ? t('crVmRtCtProof') : undefined}>
                        <CrBadge tone="warning">{t('crRtIncomplete')}</CrBadge>
                        <span className="cr-rt-miss">{crRtMissingText(r.a, t)}</span>{mark}
                    </span>
                );
            }
            return <span data-cr-rt-evidence="none"><span className="cr-muted">{t('crRtEvNone')}</span>{mark}</span>;
        }

        // --- the weekly run ------------------------------------------------------------------------

        function CrRtSchedule({ status, canEdit, why, onEdit }) {
            const { t } = useTranslation();
            const p = (status && status.policy) || {};
            const on = !!p.enabled;
            const body = () => {
                if (status === undefined) return <CrNcState id="rt-schedule" kind="loading" />;
                if (status === null) return <CrNcState id="rt-schedule" kind="warning">{t('crRtScheduleFailed')}</CrNcState>;
                const when = `${String(p.day || 'sun').toUpperCase()} ${String(p.hour ?? 4).padStart(2, '0')}:00`;
                return (
                    <CrNcKv id="rt-schedule" label={t('rtestSchedule')} rows={[
                        { k: 'next', label: t('crRtNextRun'), value: !on ? t('rtestScheduleOff')
                            : status.running ? t('rtestRunning')
                            : status.next_run ? `${crDriftTime(status.next_run)}${status.timezone ? ` (${status.timezone})` : ''}` : '' },
                        { k: 'when', label: t('crRtWhen'), value: `${when}${status.timezone ? ` (${status.timezone})` : ''}` },
                        { k: 'count', label: t('crRtPerRun'), value: crFill(t('crRtGuestsN'), { n: p.weekly_count ?? 5 }) },
                        { k: 'size', label: t('crRtMaxSize'), value: `${p.max_backup_gb ?? 32} GB` },
                        { k: 'age', label: t('crRtMaxAge'), value: crFill(t('crVmAgeD'), { n: p.max_age_days ?? 30 }) },
                        { k: 'scope', label: t('scope'), value: p.scope === 'all' ? t('pbsAllSnapshotsInPool') : t('pbsLatestSnapshotPerVm') },
                        { k: 'consent', label: t('crRtConsent'), value: crRtNum(p.confirmed_at) ? crFmtDate(p.confirmed_at) : '', missing: t('crRtConsentNone') },
                    ]} />
                );
            };
            return (
                <CrNcSection id="rt-schedule" data-rtest-schedule={on ? 'on' : 'off'} title={t('rtestSchedule')} desc={t('crRtScheduleDesc')}
                    badge={status ? <CrBadge tone={on ? 'success' : 'neutral'}><span data-cr-rt-schedule-on={on ? '1' : '0'}>{on ? t('enabled') : t('crSbOff')}</span></CrBadge> : null}
                    actions={canEdit !== null && (
                        <CrButton icon={<Icons.Clock />} onClick={onEdit} disabled={!canEdit} title={!canEdit ? why : undefined} data-rtest-edit-schedule="">
                            {t('rtestScheduleEdit')}
                        </CrButton>
                    )}>
                    {body()}
                    {on && <p className="cr-rt-fine" data-rtest-limits="">{crFill(t('rtestScheduleLimits'), { n: p.weekly_count ?? 5, gb: p.max_backup_gb ?? 32 })}. {t('crRtConsentNote')}</p>}
                </CrNcSection>
            );
        }

        // --- what a test does ----------------------------------------------------------------------

        function CrRtDefaults({ settings, error, canEdit, why, busy, onSave, onRetry }) {
            const { t } = useTranslation();
            const [form, setForm] = useState(null);
            const c = settings && settings.cluster;
            const full = !!(c && 'isolation' in c);
            const stored = full ? crRtDraft(c) : null;
            const isoText = (v) => (v === 'bridge' ? t('rtestIsoBridge') : t('rtestIsoLinkDown'));
            const agentText = (v) => ({ auto: t('rtestAgentAuto'), require: t('rtestAgentRequire'), off: t('rtestAgentOff') })[v] || v || '';
            const label = { rto_minutes: t('rtestRtoDefault'), isolation: t('rtestIsolation'), test_bridge: t('rtestBridgeName'),
                            test_storage: t('rtestStorage'), boot_timeout: t('rtestBootTimeout'), agent: t('rtestAgentMode'),
                            ports: t('rtestPorts'), command: t('rtestCommand') };
            const show = (k, v) => (v == null ? '' : k === 'isolation' ? isoText(v) : k === 'agent' ? agentText(v)
                : k === 'ports' ? v.join(', ') : String(v));
            const diff = form && stored ? (() => {
                const a = crRtDefaultsBody(stored), b = crRtDefaultsBody(form);
                return Object.keys(label).filter(k => JSON.stringify(a[k]) !== JSON.stringify(b[k]))
                    .map(k => ({ k, label: label[k], from: show(k, a[k]), to: show(k, b[k]) }));
            })() : [];
            const changed = (k) => form && stored && String(form[k]) !== String(stored[k]);
            const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
            const out = (v, lo, hi) => v !== '' && !(Number(v) >= lo && Number(v) <= hi && Number.isInteger(Number(v)));
            const save = async () => { if (await onSave(crRtDefaultsBody(form))) setForm(null); };

            const body = () => {
                if (settings === undefined) return <CrNcState id="rt-defaults" kind="loading" />;
                if (settings === null) return <CrNcState id="rt-defaults" kind="error" onRetry={onRetry}>{error || t('crRtSettingsFailed')}</CrNcState>;
                if (!full) {
                    return (
                        <>
                            <CrNcKv id="rt-defaults" rows={[{ k: 'rto', label: t('rtestRtoDefault'), value: c && c.rto_minutes != null ? `${c.rto_minutes} min` : '', missing: t('crNcNotSet') }]} />
                            <p className="cr-rt-fine" data-cr-rt-confined="">{t('crRtConfinedNote')}</p>
                        </>
                    );
                }
                if (form) {
                    return (
                        <div className="cr-nc-form" data-cr-rt-form="defaults">
                            <CrNcField id="rt-rto" label={label.rto_minutes} changed={changed('rto')} was={stored.rto}
                                hint={out(form.rto, 1, 10080) ? t('crRtRtoRange') : ''} hintTone={out(form.rto, 1, 10080) ? 'warning' : undefined}>
                                <input id="cr-nc-rt-rto" type="number" min="1" max="10080" className="cr-input" value={form.rto} onChange={set('rto')} data-rtest-field="rto" />
                            </CrNcField>
                            <CrNcField id="rt-isolation" label={label.isolation} changed={changed('isolation')} was={isoText(stored.isolation)}>
                                <select id="cr-nc-rt-isolation" className="cr-select" value={form.isolation} onChange={set('isolation')} data-rtest-field="isolation">
                                    <option value="link_down">{t('rtestIsoLinkDown')}</option>
                                    <option value="bridge">{t('rtestIsoBridge')}</option>
                                </select>
                            </CrNcField>
                            {form.isolation === 'bridge' && (
                                <CrNcField id="rt-bridge" label={label.test_bridge} changed={changed('bridge')} was={stored.bridge}>
                                    <input id="cr-nc-rt-bridge" className="cr-input cr-nc-mono-input" value={form.bridge} maxLength={32} placeholder="vmbr99" onChange={set('bridge')} data-rtest-field="bridge" />
                                </CrNcField>
                            )}
                            <CrNcField id="rt-storage" label={label.test_storage} changed={changed('storage')} was={stored.storage} hint={t('crRtStorageHint')}>
                                <input id="cr-nc-rt-storage" className="cr-input cr-nc-mono-input" value={form.storage} maxLength={64} placeholder={t('rtestStorageHint')} onChange={set('storage')} data-rtest-field="storage" />
                            </CrNcField>
                            <CrNcField id="rt-boot" label={label.boot_timeout} changed={changed('boot')} was={stored.boot}
                                hint={out(form.boot, 30, 1800) ? t('crRtBootRange') : ''} hintTone={out(form.boot, 30, 1800) ? 'warning' : undefined}>
                                <input id="cr-nc-rt-boot" type="number" min="30" max="1800" className="cr-input" value={form.boot} placeholder="180" onChange={set('boot')} data-rtest-field="boot" />
                            </CrNcField>
                            <CrNcField id="rt-agent" label={label.agent} changed={changed('agent')} was={agentText(stored.agent)}>
                                <select id="cr-nc-rt-agent" className="cr-select" value={form.agent} onChange={set('agent')} data-rtest-field="agent">
                                    <option value="auto">{t('rtestAgentAuto')}</option>
                                    <option value="require">{t('rtestAgentRequire')}</option>
                                    <option value="off">{t('rtestAgentOff')}</option>
                                </select>
                            </CrNcField>
                            <CrNcField id="rt-ports" label={label.ports} changed={changed('ports')} was={stored.ports}>
                                <input id="cr-nc-rt-ports" className="cr-input cr-nc-mono-input" value={form.ports} placeholder={t('rtestPortsHint')} onChange={set('ports')} data-rtest-field="ports" />
                            </CrNcField>
                            <CrNcField id="rt-command" label={label.command} changed={changed('command')} was={stored.command} wide>
                                <input id="cr-nc-rt-command" className="cr-input cr-nc-mono-input" value={form.command} maxLength={500}
                                    placeholder={c.command_set ? '***' : 'systemctl is-active nginx'} onChange={set('command')} data-rtest-field="command" />
                            </CrNcField>
                        </div>
                    );
                }
                return (
                    <CrNcKv id="rt-defaults" label={t('rtestSettings')} rows={[
                        { k: 'rto', label: label.rto_minutes, value: c.rto_minutes != null ? `${c.rto_minutes} min` : '', missing: t('crNcNotSet') },
                        { k: 'isolation', label: label.isolation, value: `${isoText(c.isolation)}${c.isolation === 'bridge' && c.test_bridge ? ` (${c.test_bridge})` : ''}` },
                        { k: 'storage', label: label.test_storage, value: c.test_storage || '', mono: true, missing: t('rtestStorageHint') },
                        { k: 'boot', label: label.boot_timeout, value: c.boot_timeout != null ? `${c.boot_timeout} s` : '', missing: t('crRtDefault') },
                        { k: 'agent', label: label.agent, value: agentText(c.agent || 'auto') },
                        { k: 'ports', label: label.ports, value: (c.ports || []).join(', '), mono: true, missing: t('crNcNotSet') },
                        { k: 'command', label: label.command, value: c.command || (c.command_set ? '***' : ''), mono: true, missing: t('crNcNotSet') },
                    ]} />
                );
            };
            return (
                <CrNcSection id="rt-defaults" data-rtest-settings="" title={t('rtestSettings')} desc={t('crRtDefaultsDesc')} editing={!!form}
                    badge={form ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : null}
                    actions={!form && full && (
                        <CrButton icon={<Icons.Edit />} onClick={() => setForm(stored)} disabled={!canEdit} title={!canEdit ? why : undefined} data-cr-rt-edit="defaults">{t('edit')}</CrButton>
                    )}
                    foot={form && (
                        <CrNcEditBar id="rt-defaults" count={diff.length} saving={busy} canSave={diff.length > 0} readOnly={!canEdit}
                            onCancel={() => setForm(null)} onSave={save} note={t('crRtDefaultsNote')}>
                            {diff.length > 0 && <CrNcChanges id="rt-defaults" rows={diff} />}
                        </CrNcEditBar>
                    )}>
                    {body()}
                    {full && !form && <p className="cr-rt-fine">{t('rtestIsoNote')}</p>}
                    {full && !canEdit && why && <p className="cr-rt-fine" data-rtest-readonly="">{why}</p>}
                </CrNcSection>
            );
        }

        // --- critical guests -----------------------------------------------------------------------

        function CrRtCritical({ tags, count, coverage, canEdit, why, busy, onSave }) {
            const { t } = useTranslation();
            const [text, setText] = useState(null);
            const now = Array.isArray(tags) ? tags.join(', ') : '';
            const next = text == null ? null : crRtTags(text).join(', ');
            const diff = text != null && next !== now ? [{ k: 'tags', label: t('rasrCriticalTags'), from: now, to: next }] : [];
            const cov = coverage || {};
            const save = async () => { if (await onSave({ critical_tags: crRtTags(text) })) setText(null); };
            return (
                <CrNcSection id="rt-critical" title={t('rasrCritical')} desc={t('crRtCriticalDesc')} editing={text != null}
                    badge={text != null ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : null}
                    actions={text == null && Array.isArray(tags) && (
                        <CrButton icon={<Icons.Edit />} onClick={() => setText(now)} disabled={!canEdit} title={!canEdit ? why : undefined} data-cr-rt-edit="critical">{t('edit')}</CrButton>
                    )}
                    foot={text != null && (
                        <CrNcEditBar id="rt-critical" count={diff.length} saving={busy} canSave={diff.length > 0} readOnly={!canEdit}
                            onCancel={() => setText(null)} onSave={save} note={t('crRtCriticalNote')}>
                            {diff.length > 0 && <CrNcChanges id="rt-critical" rows={diff} />}
                        </CrNcEditBar>
                    )}>
                    {text != null ? (
                        <div className="cr-nc-form">
                            <CrNcField id="rt-tags" label={t('rasrCriticalTags')} changed={diff.length > 0} was={now} hint={t('rasrCriticalTagsHint')} wide>
                                <input id="cr-nc-rt-tags" className="cr-input cr-nc-mono-input" value={text} onChange={e => setText(e.target.value)} data-rasr-tags="" />
                            </CrNcField>
                        </div>
                    ) : (
                        <CrNcKv id="rt-critical" rows={[
                            { k: 'tags', label: t('rasrCriticalTags'), missing: Array.isArray(tags) ? t('crNcNotSet') : undefined,
                              value: Array.isArray(tags) && tags.length ? <span className="cr-rt-tags">{tags.map(x => <CrBadge key={x} tone="neutral" dot={false}>{x}</CrBadge>)}</span> : '' },
                            { k: 'count', label: t('crRtCriticalCount'), value: count == null ? '' : String(count) },
                            { k: 'proven', label: t('rasrProven'), value: cov.total ? crFill(t('rasrProvenOf'), { proven: cov.proven, total: cov.total })
                                : cov.total === 0 ? t('rasrNoCritical') : '' },
                        ]} />
                    )}
                    {!canEdit && why && Array.isArray(tags) && <p className="cr-rt-fine">{why}</p>}
                </CrNcSection>
            );
        }

        // --- rules per guest and per tag -----------------------------------------------------------

        const CR_RT_RULE0 = { scope: 'guest', key: '', rto: '', agent: '', ports: '', command: '' };

        function CrRtRules({ settings, canEdit, why, busy, onAdd, onRemove }) {
            const { t } = useTranslation();
            const [form, setForm] = useState(null);
            const full = !!(settings && settings.cluster && 'isolation' in settings.cluster);
            const rows = useMemo(() => (settings ? [...(settings.guests || []), ...(settings.tags || [])] : [])
                .map(r => ({ ...r, key: `${r.scope}:${r.scope_key}` })), [settings]);
            const agentText = (v) => ({ auto: t('rtestAgentAuto'), require: t('rtestAgentRequire'), off: t('rtestAgentOff') })[v] || v;
            const cols = useMemo(() => [
                { key: 'scope', label: t('scope'), width: 78, render: r => (r.scope === 'guest' ? t('rtestScopeGuest') : t('rtestScopeTag')) },
                { key: 'scope_key', label: t('rtestRuleKey'), width: 112, mono: true,
                  render: r => <span data-rtest-rule={r.key}>{r.scope_key}</span> },
                { key: 'rto_minutes', label: 'RTO', width: 70, render: r => (r.rto_minutes != null ? `${r.rto_minutes} min` : <span className="cr-muted">{t('rtestInherit')}</span>) },
                { key: 'agent', label: t('rtestAgentMode'), width: 110, render: r => (r.agent ? agentText(r.agent) : <span className="cr-muted">{t('rtestInherit')}</span>) },
                { key: 'ports', label: t('crRtColPorts'), width: 72, mono: true, text: r => (r.ports || []).join(', '),
                  render: r => (r.ports && r.ports.length ? r.ports.join(', ') : <span className="cr-muted">{t('rtestInherit')}</span>) },
                { key: 'command', label: t('rtestCheckCommand'), flex: true, min: 100, mono: true, text: r => r.command || '',
                  render: r => (r.command || r.command_set ? (r.command || '***') : <span className="cr-muted">{t('rtestInherit')}</span>) },
                { key: 'act', label: '', menuLabel: t('crRtColActions'), width: 44, sortable: false, resizable: false,
                  render: r => (canEdit ? (
                      <CrButton variant="danger" className="cr-btn-xs cr-rt-ico" icon={<Icons.Trash />} title={t('rtestRemoveRule')} aria-label={t('rtestRemoveRule')}
                          disabled={busy} onClick={e => { e.stopPropagation(); onRemove(r); }} data-rtest-rule-remove={r.key} />
                  ) : null) },
            ], [t, canEdit, busy, onRemove]);  // eslint-disable-line react-hooks/exhaustive-deps
            // the body of the classic addRule; the guest agent is one more choice of the same body
            const add = async () => {
                const body = { scope: form.scope, key: form.scope === 'guest' ? Number(form.key) || form.key : form.key.trim() };
                if (form.rto !== '') body.rto_minutes = Number(form.rto);
                if (form.agent) body.agent = form.agent;
                if (form.ports.trim()) body.ports = rtPorts(form.ports);
                if (form.command.trim()) body.command = form.command.trim();
                if (await onAdd(body)) setForm(null);
            };
            if (!full) return null;
            return (
                <CrNcSection id="rt-rules" title={t('rtestRules')} desc={t('crRtRulesDesc')} editing={!!form}
                    badge={<CrBadge tone="neutral" dot={false}>{rows.length}</CrBadge>}
                    actions={!form && (
                        <CrButton icon={<Icons.Plus />} onClick={() => setForm({ ...CR_RT_RULE0 })} disabled={!canEdit} title={!canEdit ? why : undefined} data-cr-rt-add-rule="">
                            {t('rtestAddRule')}
                        </CrButton>
                    )}>
                    {form && (
                        <div className="cr-rt-ruleform" data-rtest-rule-form="">
                            <label className="cr-rt-lab"><span>{t('scope')}</span>
                                <select className="cr-select" value={form.scope} onChange={e => setForm({ ...form, scope: e.target.value })} data-rtest-rule-field="scope">
                                    <option value="guest">{t('rtestScopeGuest')}</option>
                                    <option value="tag">{t('rtestScopeTag')}</option>
                                </select>
                            </label>
                            <label className="cr-rt-lab"><span>{t('rtestRuleKey')}</span>
                                <input className="cr-input cr-nc-mono-input" value={form.key} onChange={e => setForm({ ...form, key: e.target.value })} data-rtest-rule-field="key" />
                            </label>
                            <label className="cr-rt-lab"><span>{t('rtestRtoDefault')}</span>
                                <input type="number" min="1" max="10080" className="cr-input" value={form.rto} onChange={e => setForm({ ...form, rto: e.target.value })} data-rtest-rule-field="rto" />
                            </label>
                            <label className="cr-rt-lab"><span>{t('rtestAgentMode')}</span>
                                <select className="cr-select" value={form.agent} onChange={e => setForm({ ...form, agent: e.target.value })} data-rtest-rule-field="agent">
                                    <option value="">{t('rtestInherit')}</option>
                                    <option value="auto">{t('rtestAgentAuto')}</option>
                                    <option value="require">{t('rtestAgentRequire')}</option>
                                    <option value="off">{t('rtestAgentOff')}</option>
                                </select>
                            </label>
                            <label className="cr-rt-lab"><span>{t('rtestPorts')}</span>
                                <input className="cr-input cr-nc-mono-input" value={form.ports} placeholder={t('rtestPortsHint')} onChange={e => setForm({ ...form, ports: e.target.value })} data-rtest-rule-field="ports" />
                            </label>
                            <label className="cr-rt-lab cr-rt-lab-wide"><span>{t('rtestCommand')}</span>
                                <input className="cr-input cr-nc-mono-input" value={form.command} maxLength={500} onChange={e => setForm({ ...form, command: e.target.value })} data-rtest-rule-field="command" />
                            </label>
                            <div className="cr-rt-ruleacts">
                                <CrButton onClick={() => setForm(null)} disabled={busy}>{t('cancel')}</CrButton>
                                <CrButton variant="primary" icon={<Icons.Plus />} onClick={add} disabled={busy || !form.key.trim() || !canEdit} data-rtest-rule-add="">{t('rtestAddRule')}</CrButton>
                            </div>
                        </div>
                    )}
                    <CrTable id="rt-rules" columns={cols} rows={rows} rowKey={r => r.key} ariaLabel={t('rtestRules')} rowHeight={30}
                        emptyText={t('rtestNoRules')} columnMenu={false} showCount={false} />
                    {!canEdit && why && <p className="cr-rt-fine">{why}</p>}
                </CrNcSection>
            );
        }

        // --- execution and progress ----------------------------------------------------------------

        function CrRtExec({ status, runs, live, onOpen, nameOf }) {
            const { t } = useTranslation();
            const last = status && status.last_run;
            const runText = (s) => ({ done: t('rtestRunDone'), running: t('rtestRunRunning'), starting: t('rtestRunRunning'),
                stopped: t('rtestRunStopped'), missed: t('rtestRunMissed'), error: t('rtestRunError') })[s] || s;
            const resText = (s) => ({ passed: t('crRtPassed'), failed: t('crRtFailed'), error: t('rtestRunError'), skipped: t('crRtSkipped'),
                running: t('crRtRunning'), queued: t('crRtQueued'), open: t('crRtNotReached') })[s] || s;
            const gb = (n) => (n == null ? '?' : (n / 1073741824).toFixed(1));
            const skipText = (r) => (r.reason === 'too_large' ? bkpFill(t('rtestSkipTooLarge'), { size: gb(r.size), max: r.limit_gb ?? '?' })
                : r.reason === 'size_unknown' ? t('rtestSkipSizeUnknown')
                : r.reason === 'no_space' ? bkpFill(t('rtestSkipNoSpace'), { storage: r.storage || '?', free: gb(r.free), size: gb(r.size) })
                : r.reason === 'space_unknown' ? t('rtestSkipSpaceUnknown') + (r.storage ? ` (${r.storage})` : '')
                : (r.cause || ''));
            const plan = runs.plan;
            const picks = plan.filter(p => p.pick);
            const doneN = picks.filter(p => p.res).length;
            const planCols = useMemo(() => [
                { key: 'guest', label: t('rtestColGuest'), width: 180, sortValue: r => r.vmid, text: r => `${r.vmid} ${r.name}`,
                  render: r => <span className="cr-rt-guest" data-rtest-result={r.vmid} data-state={r.state}><span className="cr-mono cr-muted">{r.vmid}</span> {r.name || nameOf(r.vmid)}</span> },
                { key: 'state', label: t('status'), width: 110, text: r => resText(r.state),
                  render: r => <CrBadge tone={CR_RT_RESULT_TONE[r.state] || 'neutral'}>{resText(r.state)}</CrBadge> },
                { key: 'took', label: t('rtestColDuration'), width: 130, sortValue: r => (r.res ? r.res.measured_seconds : null),
                  render: r => (r.res && crRtNum(r.res.measured_seconds)
                      ? <span className={r.res.rto_met === false ? 'cr-tone-text cr-tone-error' : r.res.rto_met ? 'cr-tone-text cr-tone-success' : undefined}>{crVmSecs(r.res.measured_seconds)}</span> : '') },
                { key: 'why', label: t('crRtColDetail'), flex: true, min: 200, text: r => (r.res ? (r.state === 'skipped' ? skipText(r.res) : r.res.cause || '') : ''),
                  render: r => (r.res ? <span className={r.state === 'skipped' ? 'cr-tone-text cr-tone-warning' : r.res.cause ? 'cr-tone-text cr-tone-error' : undefined}
                      data-cr-rt-reason={r.res.reason || ''} title={r.res.cause || ''}>{r.state === 'skipped' ? skipText(r.res) : r.res.cause || ''}</span> : '') },
            ], [t]);  // eslint-disable-line react-hooks/exhaustive-deps
            const liveCols = useMemo(() => [
                { key: 'guest', label: t('rtestColGuest'), width: 180, sortValue: r => Number(r.vmid), text: r => `${r.vmid} ${r.vm_name || ''}`,
                  render: r => <span className="cr-rt-guest" data-cr-rt-live={r.vmid}><span className="cr-mono cr-muted">{r.vmid}</span> {r.vm_name || ''}</span> },
                { key: 'status', label: t('status'), width: 100, text: r => resText(r.status),
                  render: r => <CrBadge tone={CR_RT_RESULT_TONE[r.status] || 'neutral'}>{resText(r.status)}</CrBadge> },
                { key: 'phase', label: t('crRtColPhase'), width: 130, render: r => (CR_RT_PHASE[r.phase] ? t(CR_RT_PHASE[r.phase]) : (r.phase || '')) },
                { key: 'source', label: t('source'), width: 100, render: r => (r.source === 'schedule' ? t('rtestFromSchedule') : t('rtestByHand')) },
                { key: 'started', label: t('crRtColStarted'), flex: true, min: 140, sortValue: r => r.started_at || '',
                  render: r => <span title={t('crDriftServerTime')}>{crDriftTime(r.started_at)}</span> },
            ], [t]);  // eslint-disable-line react-hooks/exhaustive-deps

            let liveBody;
            if (live === undefined) liveBody = <CrNcState id="rt-live" kind="loading" />;
            else if (live.state === 'forbidden') liveBody = <CrNcState id="rt-live" kind="info">{t('crRtLiveForbidden')}</CrNcState>;
            else if (live.state !== 'ok') liveBody = <CrNcState id="rt-live" kind="warning">{t('crRtLiveFailed')}</CrNcState>;
            else {
                const rows = Object.keys(live.body).map(k => ({ ...live.body[k], key: k })).filter(v => v && v.vmid != null);
                liveBody = <CrTable id="rt-live" columns={liveCols} rows={rows} rowKey={r => r.key} ariaLabel={t('crRtLive')} rowHeight={30}
                    toolbar={<span className="cr-table-title">{t('crRtLive')}</span>} emptyText={t('crRtLiveNone')} columnMenu={false}
                    initialSort={{ key: 'started', dir: 'desc' }} onRowClick={r => onOpen(String(r.vmid))} />;
            }
            const going = runs.weekly;
            return (
                <CrNcSection id="rt-exec" data-cr-rt-exec={going ? 'running' : 'idle'} title={t('crRtExecTitle')} desc={t('crRtExecDesc')}
                    badge={last ? <span data-cr-rt-runstate={last.state}><CrBadge tone={CR_RT_RUN_TONE[last.state] || 'neutral'}>{runText(last.state)}</CrBadge></span> : null}>
                    {status === undefined ? <CrNcState id="rt-run" kind="loading" />
                        : status === null ? <CrNcState id="rt-run" kind="warning">{t('crRtScheduleFailed')}</CrNcState>
                        : !last ? <CrNcState id="rt-run" kind="empty" data-rtest-last="">{t('rtestNoRunYet')}</CrNcState>
                        : (
                            <>
                                <div data-rtest-last="">
                                    <CrNcKv id="rt-run" label={t('crRtLastRun')} rows={[
                                        { k: 'slot', label: t('crRtRunSlot'), value: last.slot ? `${crDriftTime(last.slot)}${status.timezone ? ` (${status.timezone})` : ''}` : '' },
                                        { k: 'started', label: t('crRtColStarted'), value: crRtNum(last.started_at) ? crFmtDate(last.started_at) : '' },
                                        { k: 'finished', label: t('crRtFinished'), value: crRtNum(last.finished_at) ? crFmtDate(last.finished_at) : (going ? t('crRtStillRunning') : '') },
                                        { k: 'counts', label: t('crRtCounts'), value: bkpFill(t('rtestLastRunCounts'), crRtRunCounts(last)) },
                                        last.reason ? { k: 'reason', label: t('crRtReason'), value: last.reason } : null,
                                    ]} />
                                </div>
                                {going && picks.length > 0 && (
                                    <div className="cr-rt-prog" data-cr-rt-progress={`${doneN}/${picks.length}`}>
                                        <span>{crFill(t('crRtProgress'), { done: doneN, total: picks.length })}</span>
                                        <CrMeter value={(100 * doneN) / picks.length} tone="info" />
                                    </div>
                                )}
                                {going && !picks.length && <p className="cr-rt-fine">{t('crRtNoPickHere')}</p>}
                                {plan.length > 0 ? (
                                    <CrTable id="rt-plan" columns={planCols} rows={plan} rowKey={r => r.key} ariaLabel={t('crRtPlan')} rowHeight={30}
                                        toolbar={<span className="cr-table-title">{t('crRtPlan')}</span>} columnMenu={false}
                                        onRowClick={r => onOpen(String(r.vmid))} />
                                ) : !going && <p className="cr-rt-fine">{t('crRtNothingHere')}</p>}
                            </>
                        )}
                    {liveBody}
                    <p className="cr-rt-fine">{t('crRtNoTestNow')}</p>
                </CrNcSection>
            );
        }

        // --- a guest on its own --------------------------------------------------------------------

        function CrRtGuestPanel({ row, detail, canWrite, busy, onClose, onConfirm, onWithdraw }) {
            const { t } = useTranslation();
            const a = row.a;
            const conf = a && a.confirmation;
            const d = detail;
            const checkText = (c) => (c.check === 'agent' ? t('rtestCheckAgent') : c.check === 'port' ? bkpFill(t('rtestCheckPort'), { port: c.target })
                : c.check === 'booted' ? t('rtestCheckBooted') : `${t('rtestCheckCommand')}: ${c.target || '***'}`);
            const histCols = useMemo(() => [
                { key: 'started_at', label: t('crRtColStarted'), width: 116, render: h => crDriftTime(h.started_at) },
                { key: 'status', label: t('status'), width: 92, render: h => <span data-rtest-history={h.id}><CrBadge tone={CR_RT_RESULT_TONE[h.status] || 'error'}>{({ passed: t('crRtPassed'), failed: t('crRtFailed'), error: t('rtestRunError'), running: t('crRtRunning') })[h.status] || h.status}</CrBadge></span> },
                { key: 'source', label: t('source'), width: 84, render: h => (h.source === 'schedule' ? t('rtestFromSchedule') : t('rtestByHand')) },
                { key: 'took', label: t('crRtColTook'), width: 64, sortValue: h => h.measured_seconds,
                  render: h => (crRtNum(h.measured_seconds) ? <span className={h.rto_met === false ? 'cr-tone-text cr-tone-error' : undefined}>{crVmSecs(h.measured_seconds)}</span> : '') },
                { key: 'cause', label: t('crRtColDetail'), flex: true, min: 100, render: h => (h.cause ? <span className="cr-tone-text cr-tone-error" title={h.cause}>{h.cause}</span> : '') },
            ], [t]);  // eslint-disable-line react-hooks/exhaustive-deps
            const plan = d && d.data ? d.data.checks || {} : null;
            const g = d && d.data ? d.data.guest || {} : null;
            return (
                <CrSidePanel open id="rt-guest" focusKey={row.id} onClose={onClose} title={`${row.vmid} ${row.name || ''}`.trim()}
                    sub={<span className="cr-rt-sub"><CrRtStatus status={row.status} /> <span className="cr-muted">{row.node || ''}{row.type ? ` - ${row.type === 'lxc' ? 'CT' : 'VM'}` : ''}</span></span>}>
                    <div className="cr-rt-panel" data-cr-rt-panel={row.vmid} data-rtest-detail={row.vmid}>
                        <CrNcGroup id="rt-state" title={t('crRtPanelTest')}>
                            <CrNcKv id="rt-state" rows={[
                                { k: 'last', label: t('crRtLastTest'), value: crRtAt(row.last_test_at, t), missing: t('rtestNever') },
                                { k: 'passed', label: t('rtestColPassed'), value: crRtAt(row.last_success_at, t), missing: t('rtestNever') },
                                { k: 'point', label: t('rtestColPoint'), value: crRtAt(row.tested_backup_at, t), missing: '-' },
                                { k: 'rto', label: t('rtestColDuration'), value: crRtTook(row, t) || '', missing: '-' },
                                { k: 'failure', label: t('rtestColFailure'), value: row.last_failure_cause ? `${row.last_failure_cause} (${crDriftTime(row.last_failure_at)})` : '', missing: '-' },
                                row.run ? { k: 'run', label: t('crRtLive'), value: row.run.kind === 'queued' ? t('crRtQueued')
                                    : `${t('crRtRunning')}${row.run.phase ? `: ${CR_RT_PHASE[row.run.phase] ? t(CR_RT_PHASE[row.run.phase]) : row.run.phase}` : ''}` } : null,
                            ]} />
                        </CrNcGroup>
                        <CrNcGroup id="rt-backup" title={t('crRtPanelBackup')}>
                            <CrNcKv id="rt-backup" rows={[
                                { k: 'newest', label: t('rtestColRpo'), value: crRtBackup(row, t) },
                                { k: 'at', label: t('crRtNewestAt'), value: crRtAt(row.newest_backup_at, t), missing: row.rpo_state === 'no_backup' ? t('rtestNoBackup') : undefined },
                                { k: 'count', label: t('crRtBackupCount'), value: row.backup_count != null ? String(row.backup_count) : '' },
                                { k: 'sla', label: t('crRtSla'), value: row.sla_hours ? `${row.sla_hours} h` : '', missing: t('crNcNotSet') },
                            ]} />
                        </CrNcGroup>
                        <CrNcGroup id="rt-evidence" title={t('crRtColEvidence')}>
                            <CrNcKv id="rt-evidence" rows={[
                                { k: 'proof', label: t('crRtProof'), value: crRtEvidenceCell({ ...row, a: a && { ...a, confirmation: null } }, t) },
                                { k: 'critical', label: t('crRtColCritical'), value: row.critical == null ? '' : row.critical ? t('yes') : t('no') },
                                { k: 'tags', label: t('crRtColTags'), value: (row.tags || []).join(', '), missing: t('crNcNotSet') },
                                a ? { k: 'gaps', label: t('rasrGaps'), value: (a.gaps || []).map(k => t(rasrKindKey(k))).join(', '), missing: t('rasrNoGaps') } : null,
                            ]} />
                            {row.type === 'lxc' && <p className="cr-rt-fine">{t('crVmRtCtProof')}</p>}
                            {conf ? (
                                <div className="cr-rt-confline" data-rasr-confirmation={row.vmid}>
                                    <span className="cr-strong">{t('rasrConfirmTitle')}:</span> <span>{conf.text}</span>
                                    <span className="cr-muted"> {bkpFill(t('rasrConfirmBy'), { who: conf.confirmed_by, when: crDriftTime(conf.confirmed_at) })}
                                        {conf.expires_at ? ` ${bkpFill(t('rasrConfirmUntil'), { when: crDriftTime(conf.expires_at) })}` : ''}</span>
                                    {canWrite && <CrButton variant="danger" className="cr-btn-xs" onClick={() => onWithdraw(conf, row.vmid)} disabled={busy} data-rasr-withdraw={row.vmid}>{t('rasrWithdraw')}</CrButton>}
                                </div>
                            ) : (canWrite && a && (
                                <div><CrButton className="cr-btn-xs" icon={<Icons.Check />} onClick={() => onConfirm({ vmid: row.vmid, name: row.name })} data-rasr-confirm-open={row.vmid}>{t('rasrConfirm')}</CrButton></div>
                            ))}
                        </CrNcGroup>
                        <CrNcGroup id="rt-checks" title={t('rtestChecks')}>
                            {!d || d.loading ? <CrNcState id="rt-checks" kind="loading" />
                                : d.error ? <CrNcState id="rt-checks" kind="error">{d.error}</CrNcState>
                                : (
                                    <>
                                        <p className="cr-rt-fine">
                                            {[`${t('rtestAgentMode')}: ${plan.agent || '-'}`, plan.ports && plan.ports.length ? `${t('rtestPorts')}: ${plan.ports.join(', ')}` : null,
                                              plan.command || plan.command_set ? `${t('rtestCheckCommand')}: ${plan.command || '***'}` : null,
                                              plan.rto_seconds ? `RTO ${crVmSecs(plan.rto_seconds)}` : null].filter(Boolean).join(' - ')}
                                        </p>
                                        {(g.last_checks || []).length ? (
                                            <ul className="cr-rt-checks">
                                                {(g.last_checks || []).map((c, i) => (
                                                    <li key={i} data-rtest-check={c.check}>
                                                        <CrBadge tone={c.ok === true ? 'success' : c.ok === false ? 'error' : 'neutral'} dot={false}>
                                                            {c.ok === true ? 'OK' : c.ok === false ? t('crRtCheckBad') : t('rtestCheckSkipped')}
                                                        </CrBadge>
                                                        <span>{checkText(c)}</span>
                                                        {c.detail && <span className="cr-muted cr-rt-trunc" title={c.detail}>{c.detail}</span>}
                                                    </li>
                                                ))}
                                            </ul>
                                        ) : <p className="cr-rt-fine">{t('crRtNoChecks')}</p>}
                                    </>
                                )}
                        </CrNcGroup>
                        <CrNcGroup id="rt-history" title={t('rtestHistory')}>
                            {d && d.data && (
                                <CrTable id="rt-history" columns={histCols} rows={d.data.history || []} rowKey={h => h.id} ariaLabel={t('rtestHistory')}
                                    emptyText={t('rtestNoRunYet')} columnMenu={false} showCount={false} rowHeight={28} />
                            )}
                            {d && d.data && (d.data.backups || []).length > 0 && (
                                <ul className="cr-rt-checks" aria-label={t('crRtBackups')} data-cr-rt-backups="">
                                    {(d.data.backups || []).map(b => (
                                        <li key={b.volid}><span className="cr-muted">{crRtNum(b.ctime) ? crFmtDate(b.ctime) : ''}</span>
                                            <span className="cr-mono cr-rt-trunc" title={b.volid}>{b.volid}</span></li>
                                    ))}
                                </ul>
                            )}
                        </CrNcGroup>
                    </div>
                </CrSidePanel>
            );
        }

        // --- the gaps, the manual confirmations and the evidence -----------------------------------

        function CrRtGaps({ assurance, canWrite, onConfirm }) {
            const { t } = useTranslation();
            const [kind, setKind] = useState('all');
            const rows = useMemo(() => [...(assurance.gaps || []),
                ...(assurance.plan_gaps || []).map(p => ({ kind: p.kind, vmid: p.vmid, name: p.name || '', plan: p.plan, plan_id: p.plan_id, critical: false }))]
                .map((g, i) => ({ ...g, key: `${g.kind}-${g.plan_id || ''}-${g.vmid}-${i}` })), [assurance]);
            const counts = assurance.gap_counts || {};
            const kinds = RASR_KINDS.filter(k => counts[k]);
            const cols = useMemo(() => [
                { key: 'vmid', label: t('rtestColGuest'), width: 180, text: g => `${g.vmid ?? ''} ${g.name || ''} ${g.plan || ''}`,
                  render: g => <span className="cr-rt-guest" data-rasr-gap={g.kind} data-vmid={g.vmid ?? ''}><span className="cr-mono cr-muted">{g.vmid ?? '-'}</span> {g.name || ''}{g.plan ? ` ${bkpFill(t('rasrPlanOf'), { plan: g.plan })}` : ''}</span> },
                { key: 'kind', label: t('crRtColGap'), flex: true, min: 150, text: g => t(rasrKindKey(g.kind)), render: g => <span className="cr-tone-text cr-tone-warning">{t(rasrKindKey(g.kind))}</span> },
                { key: 'critical', label: t('crRtColCritical'), width: 80, sortValue: g => (g.critical ? 0 : 1), render: g => (g.critical ? <CrBadge tone="neutral" dot={false}>{t('crRtCritical')}</CrBadge> : '') },
                { key: 'act', label: '', menuLabel: t('crRtColActions'), width: 150, sortable: false, resizable: false,
                  render: g => (canWrite && g.vmid != null ? <button type="button" className="cr-link" onClick={e => { e.stopPropagation(); onConfirm({ vmid: g.vmid, name: g.name }); }}
                      data-rasr-confirm-open={g.vmid}>{t('rasrConfirm')}</button> : '') },
            ], [t, canWrite]);  // eslint-disable-line react-hooks/exhaustive-deps
            return (
                <CrNcSection id="rt-gaps" data-rasr-gaps={rows.length} title={t('rasrGaps')} desc={t('crRtGapsDesc')}
                    badge={<CrBadge tone={rows.length ? 'warning' : 'success'} dot={false}>{rows.length}</CrBadge>}
                    actions={(
                        <select className="cr-select" value={kind} onChange={e => setKind(e.target.value)} aria-label={t('crRtColGap')} data-cr-rt-gapkind="">
                            <option value="all">{t('all')} ({rows.length})</option>
                            {kinds.map(k => <option key={k} value={k}>{t(rasrKindKey(k))} ({counts[k]})</option>)}
                        </select>
                    )}>
                    <CrTable id="rt-gaps" columns={cols} rows={rows} rowKey={g => g.key} ariaLabel={t('rasrGaps')} rowHeight={28}
                        filter={kind === 'all' ? undefined : (g => g.kind === kind)} searchable emptyText={t('rasrNoGaps')} maxHeight={320} />
                    {assurance.gaps_truncated && <p className="cr-rt-fine">{t('crRtGapsTruncated')}</p>}
                </CrNcSection>
            );
        }

        function CrRtConfirmations({ assurance, canWrite, busy, onWithdraw }) {
            const { t } = useTranslation();
            const rows = useMemo(() => (assurance.guests || []).filter(g => g && g.confirmation), [assurance]);
            const cols = useMemo(() => [
                { key: 'vmid', label: t('rtestColGuest'), width: 150, text: g => `${g.vmid} ${g.name || ''}`,
                  render: g => <span className="cr-rt-guest" data-rasr-confirmation={g.vmid} data-proof={g.proof}><span className="cr-mono cr-muted">{g.vmid}</span> {g.name || ''}</span> },
                { key: 'text', label: t('rasrConfirmText'), flex: true, min: 140, text: g => g.confirmation.text, render: g => <span title={g.confirmation.text}>{g.confirmation.text}</span> },
                { key: 'by', label: t('crRtColBy'), width: 170, text: g => g.confirmation.confirmed_by,
                  render: g => bkpFill(t('rasrConfirmBy'), { who: g.confirmation.confirmed_by, when: crDriftTime(g.confirmation.confirmed_at) }) },
                { key: 'until', label: t('crRtColUntil'), width: 120, render: g => (g.confirmation.expires_at ? crDriftTime(g.confirmation.expires_at) : <span className="cr-muted">{t('crRtNoExpiry')}</span>) },
                { key: 'proof', label: t('crRtProof'), width: 100, render: g => <CrBadge tone={g.proof === 'proven' ? 'success' : 'warning'}>{g.proof === 'proven' ? t('rasrProven') : t('rasrNotProven')}</CrBadge> },
                { key: 'act', label: '', menuLabel: t('crRtColActions'), width: 96, sortable: false, resizable: false,
                  render: g => (canWrite ? <CrButton variant="danger" className="cr-btn-xs" onClick={e => { e.stopPropagation(); onWithdraw(g.confirmation, g.vmid); }}
                      disabled={busy} data-rasr-withdraw={g.vmid}>{t('rasrWithdraw')}</CrButton> : '') },
            ], [t, canWrite, busy]);  // eslint-disable-line react-hooks/exhaustive-deps
            return (
                <CrNcSection id="rt-confirmations" data-rasr-confirmations={rows.length} title={t('rasrConfirmations')} desc={t('rasrConfirmNote')}
                    badge={<CrBadge tone="neutral" dot={false}>{rows.length}</CrBadge>}>
                    <CrTable id="rt-confirmations" columns={cols} rows={rows} rowKey={g => g.vmid} ariaLabel={t('rasrConfirmations')} rowHeight={30}
                        emptyText={t('crRtNoConfirmations')} columnMenu={false} maxHeight={320} />
                </CrNcSection>
            );
        }

        function CrRtEvidence({ base, days, onVerify, verdict }) {
            const { t } = useTranslation();
            return (
                <CrNcSection id="rt-evidence-doc" title={t('crRtEvidenceTitle')} desc={t('crRtEvidenceDesc')}
                    actions={(
                        <>
                            <a className="cr-btn cr-btn-default" href={`${base}/recovery-evidence?days=${days}&format=json`} download data-rasr-export="json">
                                <span className="cr-ico" aria-hidden="true"><Icons.Download /></span>{t('rasrExportJson')}
                            </a>
                            <a className="cr-btn cr-btn-default" href={`${base}/recovery-evidence?days=${days}&format=csv`} download data-rasr-export="csv">
                                <span className="cr-ico" aria-hidden="true"><Icons.Download /></span>{t('rasrExportCsv')}
                            </a>
                            <label className="cr-btn cr-btn-default cr-rt-file">
                                <span className="cr-ico" aria-hidden="true"><Icons.Check /></span>{t('rasrVerify')}
                                <input type="file" accept="application/json,.json" data-rasr-verify=""
                                    onChange={e => { onVerify(e.target.files && e.target.files[0]); e.target.value = ''; }} />
                            </label>
                        </>
                    )}>
                    {verdict ? (
                        <div className={`cr-callout cr-callout-${verdict.bad ? 'error' : 'success'}`} role="status" data-rasr-verdict={verdict.bad ? 'bad' : 'ok'}>
                            {verdict.bad ? <Icons.AlertCircle className="w-4 h-4" /> : <Icons.CheckCircle className="w-4 h-4" />}
                            <div>{verdict.text}</div>
                        </div>
                    ) : <p className="cr-rt-fine">{crFill(t('crRtEvidencePeriod'), { n: days })}</p>}
                </CrNcSection>
            );
        }

        function CrRtConfirmDialog({ dialog, busy, onChange, onCancel, onSave }) {
            const { t } = useTranslation();
            return (
                <CrUpdDialog id="rt-confirm" title={t('rasrConfirmTitle')} busy={busy} onCancel={onCancel}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy}>{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={onSave} disabled={busy || !dialog.text.trim()} data-rasr-save-confirm="">{busy ? t('crNcSaving') : t('save')}</CrButton>
                        </>
                    )}>
                    <div className="cr-nc-form" data-rasr-dialog="">
                        <p className="cr-rt-fine cr-nc-field-wide">{t('rasrConfirmNote')}</p>
                        <CrNcField id="rt-cf-vmid" label={t('rasrConfirmGuest')}>
                            <input id="cr-nc-rt-cf-vmid" className="cr-input cr-nc-mono-input" value={dialog.vmid} onChange={e => onChange({ ...dialog, vmid: e.target.value })} data-rasr-field="vmid" />
                        </CrNcField>
                        <CrNcField id="rt-cf-days" label={t('rasrConfirmExpiry')}>
                            <input id="cr-nc-rt-cf-days" type="number" min="1" max="3650" className="cr-input" value={dialog.days} onChange={e => onChange({ ...dialog, days: e.target.value })} data-rasr-field="days" />
                        </CrNcField>
                        <CrNcField id="rt-cf-text" label={t('rasrConfirmText')} wide hint={`${dialog.text.length} / 500`}>
                            <textarea id="cr-nc-rt-cf-text" className="cr-input cr-rt-textarea" value={dialog.text} maxLength={500} rows={3} onChange={e => onChange({ ...dialog, text: e.target.value })} data-rasr-field="text" />
                        </CrNcField>
                    </div>
                </CrUpdDialog>
            );
        }

        // --- the page ------------------------------------------------------------------------------

        function CrRestoreTests({ clusterId, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders, isAdmin, haReadOnly, haServing } = useAuth();
            const headers = useRef(getAuthHeaders);
            headers.current = getAuthHeaders;
            // the fetch of RestoreTestsPanel: the same credentials and headers
            const call = useCallback((url, opts = {}) => fetch(url, { ...opts, credentials: 'include',
                headers: { ...(opts.headers || {}), ...headers.current() } }), []);
            const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}`;
            const [days, setDays] = useState(30);
            const [report, setReport] = useState(null);
            const [rep, setRep] = useState({ loading: true, error: '' });
            const [assur, setAssur] = useState(null);
            const [assurErr, setAssurErr] = useState('');
            const [settings, setSettings] = useState(undefined);
            const [settingsErr, setSettingsErr] = useState('');
            const [status, setStatus] = useState(undefined);
            const [live, setLive] = useState(undefined);
            const [filter, setFilter] = useState('all');
            const [busy, setBusy] = useState('');
            const [editSchedule, setEditSchedule] = useState(false);
            const [openId, setOpenId] = useState(null);
            const [details, setDetails] = useState({});
            const [dialog, setDialog] = useState(null);
            const [verdict, setVerdict] = useState(null);
            const look = useRef(0);
            const lookA = useRef(0);
            const tableRef = useRef(null);
            const say = (msg, kind) => { if (addToast) addToast(msg, kind); };

            const loadReport = useCallback(async (refresh) => {
                const mine = ++look.current;
                setRep(s => ({ ...s, loading: true, error: '' }));
                try {
                    const res = await call(`${base}/recovery-report?days=${days}${refresh ? '&refresh=1' : ''}`);
                    if (mine !== look.current) return;
                    if (res.ok) {
                        const body = await res.json();
                        if (mine === look.current) { setReport(body); setRep({ loading: false, error: '' }); }
                    } else {
                        const msg = await PegaProxApiErrors.message(res, t('rtestLoadFailed'));
                        if (mine === look.current) { setReport(null); setRep({ loading: false, error: msg }); }
                    }
                } catch (e) {
                    if (mine === look.current) setRep({ loading: false, error: t('rtestLoadFailed') });
                }
            }, [base, days, call]);  // eslint-disable-line react-hooks/exhaustive-deps
            const loadAssurance = useCallback(async () => {
                const mine = ++lookA.current;
                try {
                    const res = await call(`${base}/recovery-assurance?days=${days}`);
                    if (mine !== lookA.current) return;
                    if (res.ok) {
                        const body = await res.json();
                        if (mine === lookA.current) { setAssur(body && typeof body === 'object' ? body : null); setAssurErr(''); }
                    } else {
                        const msg = await PegaProxApiErrors.message(res, t('rtestLoadFailed'));
                        if (mine === lookA.current) { setAssur(null); setAssurErr(msg); }
                    }
                } catch (e) { if (mine === lookA.current) { setAssur(null); setAssurErr(t('rtestLoadFailed')); } }
            }, [base, days, call]);  // eslint-disable-line react-hooks/exhaustive-deps
            const loadSettings = useCallback(async () => {
                try {
                    const res = await call(`${base}/recovery-settings`);
                    if (res.ok) { setSettings(await res.json()); setSettingsErr(''); }
                    else { setSettingsErr(await PegaProxApiErrors.message(res, t('crRtSettingsFailed'))); setSettings(null); }
                } catch (e) { setSettingsErr(t('connectionError')); setSettings(null); }
            }, [base, call]);  // eslint-disable-line react-hooks/exhaustive-deps
            const loadStatus = useCallback(async () => {
                try {
                    const res = await call(`${API_URL}/pbs/verify-schedule/status`);
                    setStatus(res.ok ? await res.json() : null);
                } catch (e) { setStatus(null); }
            }, [call]);
            // the live tests: vm.backup, not backup.view. A caller without it gets a 403, said as
            // "not reported", never as "nothing runs"
            const loadLive = useCallback(async () => {
                try {
                    const res = await call(`${base}/backup-verify/active`);
                    if (res.ok) {
                        const body = await res.json();
                        setLive({ state: 'ok', body: body && typeof body === 'object' && !Array.isArray(body) ? body : {} });
                    } else setLive({ state: res.status === 403 ? 'forbidden' : 'error', code: res.status });
                } catch (e) { setLive({ state: 'error' }); }
            }, [base, call]);
            useEffect(() => { loadReport(false); loadAssurance(); }, [loadReport, loadAssurance]);
            useEffect(() => { loadStatus(); loadSettings(); loadLive(); }, [loadStatus, loadSettings, loadLive]);
            const refresh = () => { loadReport(true); loadAssurance(); loadStatus(); loadSettings(); loadLive(); };
            const closeSchedule = useCallback(() => { setEditSchedule(false); loadStatus(); }, [loadStatus]);

            const runs = useMemo(() => crRtRuns(status, live && live.state === 'ok' ? live.body : null, clusterId), [status, live, clusterId]);
            const liveGoing = !!(live && live.state === 'ok' && Object.keys(live.body).some(k => live.body[k] && live.body[k].status === 'running'));
            const going = runs.weekly || liveGoing;
            // while a test runs: the run and the live tests again, the report once it is over
            useEffect(() => {
                if (!going) return undefined;
                const id = setInterval(() => { if (!document.hidden) { loadStatus(); loadLive(); } }, CR_RT_POLL);
                return () => clearInterval(id);
            }, [going, loadStatus, loadLive]);
            const wasGoing = useRef(false);
            useEffect(() => {
                if (going) { wasGoing.current = true; return; }
                if (wasGoing.current) { wasGoing.current = false; loadReport(false); loadAssurance(); }
            }, [going]);  // eslint-disable-line react-hooks/exhaustive-deps

            const write = async (key, method, url, body, done) => {
                setBusy(key);
                let ok = false;
                try {
                    const res = await call(url, { method, headers: { 'Content-Type': 'application/json' },
                                                  body: body === undefined ? undefined : JSON.stringify(body) });
                    if (res.ok) {
                        ok = true;
                        say(done, 'success');
                        await loadSettings();
                        loadReport(false);
                        loadAssurance();
                    } else say(await bkpError(res, t, haServing), 'error');
                } catch (e) { say(t('connectionError'), 'error'); }
                setBusy('');
                return ok;
            };
            const verifyFile = async (file) => {
                setVerdict(null);
                if (!file) return;
                try {
                    const res = await call(`${API_URL}/recovery-evidence/verify`, { method: 'POST',
                        headers: { 'Content-Type': 'application/json' }, body: await file.text() });
                    if (!res.ok) { setVerdict({ bad: true, text: t('rasrVerifyFailed') }); return; }
                    const v = await res.json();
                    setVerdict(!v.signature_valid ? { bad: true, text: t('rasrVerifyBad') }
                        : v.audit_chain === 'absent' ? { bad: true, text: t('rasrVerifyChainAbsent') }
                        : { bad: false, text: t('rasrVerifyOk') });
                } catch (e) { setVerdict({ bad: true, text: t('rasrVerifyFailed') }); }
            };
            const saveConfirm = async () => {
                const body = { vmid: Number(dialog.vmid) || dialog.vmid, text: dialog.text.trim() };
                if (String(dialog.days).trim() !== '') body.expires_days = Number(dialog.days);
                if (await write('confirm', 'POST', `${base}/recovery-confirmations`, body, t('rasrConfirmSaved'))) setDialog(null);
            };
            const withdraw = (conf) => write('revoke', 'DELETE', `${base}/recovery-confirmations/${conf.id}`, undefined, t('rasrWithdrawn'));
            const removeRule = (r) => write('rule', 'DELETE', `${base}/recovery-settings/rules/${r.scope}/${encodeURIComponent(r.scope_key)}`, undefined, t('rtestSaved'));

            const open = async (vmid) => {
                setOpenId(vmid);
                if (details[vmid] && details[vmid].data) return;
                setDetails(d => ({ ...d, [vmid]: { loading: true } }));
                try {
                    const res = await call(`${base}/recovery-report/${vmid}`);
                    const entry = res.ok ? { data: await res.json() } : { error: await PegaProxApiErrors.message(res, t('rtestLoadFailed')) };
                    setDetails(d => ({ ...d, [vmid]: entry }));
                } catch (e) { setDetails(d => ({ ...d, [vmid]: { error: t('rtestLoadFailed') } })); }
            };

            const canWrite = isAdmin && !haReadOnly;
            const canEdit = !!(settings && settings.can_edit) && canWrite;
            const why = haReadOnly ? t('crNcReadOnly') : t('rtestReadOnly');
            const critTags = assur && Array.isArray(assur.critical_tags) ? assur.critical_tags
                : settings && settings.cluster && Array.isArray(settings.cluster.critical_tags) ? settings.cluster.critical_tags : null;
            const rows = useMemo(() => crRtRows(report, assur, runs, critTags), [report, assur, runs, critTags]);
            const n = useMemo(() => crRtCounts(rows), [rows]);
            const cov = (assur && assur.coverage) || null;
            const openRow = openId != null ? rows.find(r => r.id === openId) || null : null;
            const rowFilter = useMemo(() => (filter === 'all' ? undefined : crRtMatch(filter)), [filter]);
            // a guest of the run or of the live tests that the report does not list (a template, a
            // test copy) has no row to open
            const openKnown = (id) => { if (rows.some(r => r.id === id)) open(id); };
            const names = useMemo(() => new Map(rows.map(r => [r.id, r.name || ''])), [rows]);
            const nameOf = (vmid) => names.get(String(vmid)) || '';
            const pick = (k, scroll) => {
                setFilter(f => (f === k && k !== 'all' ? 'all' : k));
                if (scroll && tableRef.current) tableRef.current.scrollIntoView({ block: 'start', behavior: 'smooth' });
            };

            const chipText = (k) => ({ all: t('all'), attention: t('crRtAttention'), critical: t('crRtCritical'), stale: t('rtestStateStale'),
                rto_missed: t('rtestStateRto'), rpo: t('rtestTileRpo') })[k] || t(CR_RT_WORD[k] || k);
            const cols = useMemo(() => [
                { key: 'guest', label: t('rtestColGuest'), width: 170, sortValue: r => r.vmid, text: r => `${r.vmid} ${r.name || ''}`,
                  render: r => <span className="cr-rt-guest" data-rtest-row={r.vmid} data-state={r.state}><span className="cr-mono cr-muted">{r.vmid}</span> <span className="cr-strong">{r.name || '-'}</span></span> },
                { key: 'status', label: t('crRtColStatus'), width: 144, sortValue: r => CR_RT_ORDER.indexOf(r.status), text: r => t(CR_RT_WORD[r.status]),
                  render: r => <CrRtStatus status={r.status} /> },
                { key: 'critical', label: t('crRtColCritical'), width: 78, sortValue: r => (r.critical == null ? null : r.critical ? 0 : 1),
                  render: r => (r.critical == null ? <CrNcMissing /> : r.critical ? <CrBadge tone="neutral" dot={false}>{t('crRtCritical')}</CrBadge> : '') },
                { key: 'node', label: t('node'), width: 80, render: r => r.node || '' },
                { key: 'type', label: t('type'), width: 56, hidden: true, text: r => r.type, render: r => (r.type === 'lxc' ? 'CT' : 'VM') },
                { key: 'passed', label: t('rtestColPassed'), width: 100, sortValue: r => r.last_success_age_days,
                  render: r => (r.last_success_age_days != null
                      ? <span title={crRtAt(r.last_success_at, t)}>{crFill(t('rtestAgo'), { t: crVmAge(r.last_success_age_days * 24, t) })}</span>
                      : <span className="cr-muted">{t('rtestNever')}</span>) },
                { key: 'point', label: t('rtestColPoint'), width: 110, hidden: true, sortValue: r => r.tested_backup_age_hours,
                  render: r => (crRtNum(r.tested_backup_age_hours) ? <span title={crRtAt(r.tested_backup_at, t)}>{crFill(t('rtestAgo'), { t: crVmAge(r.tested_backup_age_hours, t) })}</span> : '') },
                { key: 'rto', label: t('rtestColDuration'), width: 156, sortValue: r => r.measured_seconds, render: r => crRtTook(r, t) },
                { key: 'backup', label: t('rtestColRpo'), width: 144, sortValue: r => (r.rpo_state === 'no_backup' ? -1 : r.newest_backup_age_hours),
                  render: r => crRtBackup(r, t) },
                { key: 'evidence', label: t('crRtColEvidence'), width: 190, sortValue: r => (r.evidence == null ? null : ['none', 'incomplete', 'proven'].indexOf(r.evidence)),
                  text: r => (r.evidence ? `${r.evidence} ${crRtMissingText(r.a, t)}` : ''), render: r => crRtEvidenceCell(r, t) },
                { key: 'failure', label: t('rtestColFailure'), flex: true, min: 130, text: r => r.last_failure_cause || '',
                  render: r => (r.last_failure_cause ? <span className="cr-tone-text cr-tone-error" title={`${crRtAt(r.last_failure_at, t)}: ${r.last_failure_cause}`}>{r.last_failure_cause}</span> : '') },
                { key: 'tags', label: t('crRtColTags'), width: 120, hidden: true, text: r => (r.tags || []).join(' '), render: r => (r.tags || []).join(', ') },
            ], [t]);  // eslint-disable-line react-hooks/exhaustive-deps

            const tileTone = (k) => (!n[k] ? undefined : k === 'failed' || k === 'missing' ? 'error' : k === 'incomplete' ? 'warning' : undefined);
            const tileVal = (k) => {
                if (!report) return rep.loading ? <span className="cr-spinner" role="status" aria-label={t('loading')} /> : <CrNcMissing />;
                if (k === 'incomplete' && !assur) return <CrNcMissing />;
                return n[k];
            };
            const tileSub = (k) => {
                if (!report) return '';
                if (k === 'running') {
                    if (!live || live.state === 'ok') return runs.weekly ? t('crRtSubWeekly') : t('crRtSubNow');
                    return t('crRtSubManualUnknown');
                }
                if (k === 'missing' && report.backups_state && report.backups_state !== 'ok') return t('crRtSubAnswered');
                return t({ passed: 'crRtSubPassed', failed: 'crRtSubFailed', never: 'crRtSubNever', missing: 'crRtSubMissing',
                           incomplete: 'crRtSubIncomplete' }[k]);
            };
            const covTile = (id, label, c) => (
                <CrStat id={id} label={label} title={t('rasrDesc')}
                    value={!assur ? <CrNcMissing /> : c && c.percent != null ? crPct(c.percent, c.percent % 1 ? 1 : 0) : '-'}
                    sub={!assur ? '' : c && c.total ? crFill(t('rasrProvenOf'), { proven: c.proven, total: c.total }) : id === 'rt-cov-critical' ? t('rasrNoCritical') : ''}
                    meter={assur && c && c.percent != null ? c.percent : null} meterTone="info" />
            );

            const backupsNote = report && report.backups_state && report.backups_state !== 'ok';
            return (
                <div className="cr-rt" data-cr-rt={clusterId} data-rtest-panel={clusterId}>
                    <CrPageHeader icon={<Icons.LifeBuoy />} title={t('rtestTitle')} sub={t('crRtSub')}
                        actions={(
                            <>
                                <label className="cr-rt-period">
                                    <span>{t('rtestWithin')}</span>
                                    <select className="cr-select" value={days} onChange={e => setDays(parseInt(e.target.value, 10))} data-rtest-days="">
                                        {CR_RT_DAYS.map(d => <option key={d} value={d}>{bkpFill(t('bkpRunsDays'), { n: d })}</option>)}
                                    </select>
                                </label>
                                <a className="cr-btn cr-btn-default" href={`${base}/recovery-report?days=${days}&format=csv`} download data-rtest-csv="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.Download /></span>{t('rtestExportCsv')}
                                </a>
                                {rep.loading && report && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                                <button type="button" className="cr-icon-btn" onClick={refresh} aria-label={t('refresh')} title={t('refresh')} data-rtest-refresh="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>
                                </button>
                            </>
                        )} />
                    {haReadOnly && <CrNcState id="rt-standby" kind="info">{t('crRtStandby')}</CrNcState>}
                    {rep.error && <CrNcState id="rt-report" kind="error" onRetry={() => loadReport(false)} data-rtest-error="">{rep.error}</CrNcState>}
                    {backupsNote && <CrNcState id="rt-backups" kind="warning" data-rtest-backups-note="">{report.backups_state === 'unreadable' ? t('rtestBackupsUnreadable') : t('rtestBackupsPartial')}</CrNcState>}
                    {assurErr && <CrNcState id="rt-assurance" kind="warning" data-rasr-error="">{crFill(t('crRtAssurFailed'), { reason: assurErr })}</CrNcState>}

                    <h2 className="cr-rt-h">{t('crRtSecOverview')}</h2>
                    <div className="cr-stat-row cr-rt-stats" role="group" aria-label={t('crRtSecOverview')} data-rasr-panel={clusterId}>
                        {covTile('rt-cov-critical', t('rasrCritical'), cov && cov.critical)}
                        {covTile('rt-cov-all', t('rasrAll'), cov && cov.all)}
                        {CR_RT_TILES.map(k => (
                            <CrStat key={k} id={`rt-${k}`} label={t(CR_RT_WORD[k])} value={tileVal(k)} sub={tileSub(k)} tone={tileTone(k)}
                                title={[t(CR_RT_WORD[k]), tileSub(k)].filter(Boolean).join(': ')}
                                onClick={report ? () => pick(k, true) : undefined} pressed={report ? filter === k : undefined} />
                        ))}
                    </div>
                    {report && <p className="cr-rt-fine" data-cr-rt-basis="">{crFill(t('crRtBasis'), { n: days, at: crRtAt(report.backups_read_at, t) || '-' })}</p>}

                    <h2 className="cr-rt-h">{t('crRtSecConfig')}</h2>
                    <div className="cr-rt-cols">
                        <CrRtSchedule status={status} canEdit={isAdmin ? !haReadOnly : null} why={why} onEdit={() => setEditSchedule(true)} />
                        <CrRtDefaults settings={settings} error={settingsErr} canEdit={canEdit} why={why} busy={busy === 'settings'}
                            onSave={(body) => write('settings', 'PUT', `${base}/recovery-settings`, body, t('rtestSaved'))} onRetry={loadSettings} />
                    </div>

                    <h2 className="cr-rt-h">{t('crRtSecPolicies')}</h2>
                    <div className="cr-rt-cols">
                        <CrRtCritical tags={critTags} count={critTags ? n.critical : null} coverage={cov && cov.critical} canEdit={canEdit} why={why}
                            busy={busy === 'tags'} onSave={(body) => write('tags', 'PUT', `${base}/recovery-settings`, body, t('rtestSaved'))} />
                        <CrRtRules settings={settings} canEdit={canEdit} why={why} busy={busy === 'rule'}
                            onAdd={(body) => write('rule', 'PUT', `${base}/recovery-settings/rules`, body, t('rtestSaved'))} onRemove={removeRule} />
                    </div>

                    <h2 className="cr-rt-h">{t('crRtSecExec')}</h2>
                    <CrRtExec status={status} runs={runs} live={live} onOpen={openKnown} nameOf={nameOf} />

                    <h2 className="cr-rt-h" ref={tableRef}>{t('crRtSecResults')}</h2>
                    <CrNcSection id="rt-guests" title={t('crRtGuestsTitle')} desc={t('crRtGuestsDesc')}>
                        <CrTable id="rt-guests" columns={cols} rows={rows} rowKey={r => r.id} ariaLabel={t('crRtGuestsTitle')} rowHeight={30}
                            filter={rowFilter} searchable searchPlaceholder={t('crRtSearch')}
                            loading={rep.loading} error={!report && rep.error ? rep.error : null} emptyText={t('rtestNoGuests')}
                            selectedKey={openId} onRowClick={r => open(r.id)} initialSort={{ key: 'status', dir: 'asc' }} maxHeight={560}
                            toolbar={(
                                <div className="cr-seg" role="group" aria-label={t('filter')} data-cr-rt-chips="">
                                    {[...CR_RT_CHIPS, ...(CR_RT_TILES.includes(filter) ? [filter] : [])].map(k => (
                                        <button key={k} type="button" className={filter === k ? 'active' : ''} aria-pressed={filter === k}
                                            onClick={() => pick(k, false)} data-rtest-tile={k === 'all' ? 'all' : k} data-rtest-filter={filter === k ? k : undefined}>
                                            {chipText(k)} <span className="cr-seg-n">{k === 'critical' && !critTags ? '-' : n[k]}</span>
                                        </button>
                                    ))}
                                </div>
                            )} />
                    </CrNcSection>
                    {assur && (
                        <div className="cr-rt-cols">
                            <CrRtGaps assurance={assur} canWrite={canWrite} onConfirm={g => setDialog({ vmid: g.vmid, name: g.name, text: '', days: '' })} />
                            <CrRtConfirmations assurance={assur} canWrite={canWrite} busy={busy === 'revoke'} onWithdraw={withdraw} />
                        </div>
                    )}
                    <CrRtEvidence base={base} days={days} onVerify={verifyFile} verdict={verdict} />

                    {openRow && (
                        <CrRtGuestPanel row={openRow} detail={details[openRow.id]} canWrite={canWrite} busy={busy === 'revoke'}
                            onClose={() => setOpenId(null)} onWithdraw={withdraw}
                            onConfirm={g => setDialog({ vmid: g.vmid, name: g.name, text: '', days: '' })} />
                    )}
                    {dialog && <CrRtConfirmDialog dialog={dialog} busy={busy === 'confirm'} onChange={setDialog} onCancel={() => setDialog(null)} onSave={saveConfirm} />}
                    {editSchedule && <VerifyScheduleModal authFetch={call} apiUrl={API_URL} onClose={closeSchedule} />}
                </div>
            );
        }
        try { window.PegaProxCrRestoreTests = CrRestoreTests; } catch (_) {}
