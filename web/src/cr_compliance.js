        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned (Preview): the compliance dashboard - LW Oct 2026
        // ComplianceDashboardTab keeps the reads, the profiles, the framework mapping and the
        // report; this draws what came back. A control without a result is "not checked": it
        // is never added to the passed ones and no score or rate divides by it. There is no
        // server time for a check, so "last check" is when this browser got the answers.
        // ═══════════════════════════════════════════════════════════

        const CR_CMP_TONE = { failed: 'error', partly: 'warning', unchecked: 'neutral', passed: 'success' };

        // a few classic titles and notes carry a long dash; the preview shows a hyphen
        const crDash = (s) => String(s == null ? '' : s).replace(/\s*\u2014\s*/g, ' - ');

        function crScoreTone(s) {
            return s == null ? null : s >= 90 ? 'success' : s >= 70 ? 'warning' : 'error';
        }

        // the control results of one cluster, one row per control and the sums over the nodes
        function crComplianceRows(perNode, verdictOf, titles, frameworks) {
            const nodes = Object.entries(perNode || {}).filter(([k]) => k !== '_cluster');
            const answered = nodes.filter(([, i]) => i && i.controls);
            const rows = {};
            let passed = 0, checked = 0, notChecked = 0;
            answered.forEach(([node, info]) => {
                Object.entries(info.controls).forEach(([id, raw]) => {
                    const v = verdictOf(raw);
                    const r = rows[id] || (rows[id] = { id, title: crDash(titles[id] || id), passed: [], failed: [], unchecked: [], evidence: '' });
                    if (v === null) { r.unchecked.push(node); notChecked++; return; }
                    checked++;
                    if (v) { r.passed.push(node); passed++; } else r.failed.push(node);
                    const ev = raw && typeof raw === 'object' ? (raw.actual || raw.output || raw.evidence || '') : '';
                    if (ev && !r.evidence) r.evidence = String(ev);
                });
            });
            const list = Object.values(rows).map(r => ({
                ...r,
                state: r.failed.length ? 'failed' : !r.passed.length ? 'unchecked' : r.unchecked.length ? 'partly' : 'passed',
                fws: frameworks.filter(fw => fw.controls.includes(r.id)).map(fw => fw.id),
            }));
            return { nodes, answered, list, passed, failed: checked - passed, checked, notChecked };
        }

        // passed, failed and not checked as one bar; the parts are the counts, nothing scaled
        function CrCmpBar({ passed, failed, notChecked, label }) {
            const all = passed + failed + notChecked;
            const w = (n) => (all ? `${(n * 100 / all).toFixed(2)}%` : '0%');
            return (
                <span className="cr-cmp-bar" role="img" aria-label={label}>
                    <span className="cr-cmp-bar-pass" style={{ width: w(passed) }} />
                    <span className="cr-cmp-bar-fail" style={{ width: w(failed) }} />
                    <span className="cr-cmp-bar-none" style={{ width: w(notChecked) }} />
                </span>
            );
        }

        function CrFrameworkCard({ fw, s, custom, canReport, onReport, onShow, t }) {
            const tone = s.total ? crScoreTone(s.score) : null;
            const failed = s.total - s.passed;
            const label = crFill(t('crCmpBarLabel'), { passed: s.passed, failed, notChecked: s.notChecked });
            return (
                <div className={`cr-fw${custom ? ' cr-fw-custom' : ''}`} data-cr-fw={custom ? 'custom' : fw.id}
                    {...(custom ? { 'data-hp-score': '' } : {})}>
                    <div className="cr-fw-head">
                        <span className="cr-fw-name" title={fw.description || fw.name}>
                            {custom ? <><span className="cr-muted">{t('hpCustomProfile')}:</span> {fw.name}</> : fw.name}
                        </span>
                        {fw.informational && <CrBadge tone="info" dot={false} title={crDash(fw.note)}>{t('crCmpIndicator')}</CrBadge>}
                        {fw.region && <span className="cr-fw-region">{fw.region}</span>}
                    </div>
                    <div className="cr-fw-main">
                        <span className={`cr-fw-score${tone ? ' cr-tone-text cr-tone-' + tone : ''}`} data-cr-fw-score={s.score == null ? '' : s.score}>
                            {s.score == null ? '-' : `${s.score}%`}
                        </span>
                        <span className="cr-fw-of">
                            {s.total ? crFill(t('crCmpPassedOf'), { passed: s.passed, total: s.total }) : t('crCmpNoChecked')}
                        </span>
                    </div>
                    <CrCmpBar passed={s.passed} failed={failed} notChecked={s.notChecked} label={label} />
                    <div className="cr-fw-counts">
                        <span className="cr-cmp-n cr-cmp-n-pass">{crFill(t('crCmpPassedN'), { n: s.passed })}</span>
                        <span className={`cr-cmp-n${failed ? ' cr-cmp-n-fail' : ''}`}>{crFill(t('crCmpFailedN'), { n: failed })}</span>
                        <span className={`cr-cmp-n${s.notChecked ? ' cr-cmp-n-none' : ''}`} title={t('hardenNotCheckedHint')} data-cr-fw-notchecked={s.notChecked}>
                            {crFill(t('crCmpNotCheckedN'), { n: s.notChecked })}
                        </span>
                    </div>
                    {fw.note && <p className="cr-fw-note" title={crDash(fw.note)}>{crDash(fw.note)}</p>}
                    <div className="cr-fw-actions">
                        <button type="button" className="cr-btn cr-btn-ghost" onClick={onShow} data-cr-fw-show="">
                            <span className="cr-ico" aria-hidden="true"><Icons.List /></span>{t('crCmpShowControls')}
                        </button>
                        {onReport && (
                            <button type="button" className="cr-btn" onClick={onReport} disabled={!canReport} data-cr-fw-report=""
                                title={fw.informational ? crDash(fw.note) : undefined}>
                                <span className="cr-ico" aria-hidden="true"><Icons.Download /></span>{t('crCmpReport')}
                            </button>
                        )}
                    </div>
                </div>
            );
        }

        function CrCompliance({ t, selectedCluster, profile, setProfile, customProfiles, customSel, perNode, loading, checkedAt,
                                frameworks, frameworkScore, verdictOf, sshReason, titles, overallScore, onRefresh, onReport,
                                auditCounts }) {
            const [show, setShow] = useState('all');
            const [fwPick, setFwPick] = useState('');
            const tableRef = useRef(null);
            const data = useMemo(() => crComplianceRows(perNode, verdictOf, titles, frameworks),
                // the framework list is a fixed table rebuilt on every render; the titles change
                // only with the language, and t changes with it
                [perNode, profile, t]);
            const clusterErr = perNode && perNode._cluster;
            const fwById = useMemo(() => {
                const m = {};
                frameworks.forEach(fw => { m[fw.id] = fw; });
                return m;
            }, [profile]);
            const coverage = data.checked + data.notChecked ? Math.round(data.checked * 100 / (data.checked + data.notChecked)) : null;
            const unavailable = data.nodes.length - data.answered.length;
            const scoreTone = crScoreTone(overallScore);

            const pick = (id) => {
                setFwPick(id);
                setShow('all');
                const el = tableRef.current;
                if (el) {
                    el.scrollIntoView({ block: 'start' });
                    const sel = el.querySelector('[data-cr-cmp-fw]');
                    if (sel) sel.focus({ preventScroll: true });
                }
            };
            const scope = fwPick === 'custom' && customSel ? customSel.controls : fwPick && fwById[fwPick] ? fwById[fwPick].controls : null;
            const filter = useMemo(() => {
                const inScope = scope ? new Set(scope) : null;
                return (r) => (!inScope || inScope.has(r.id)) && (show === 'all' || (show === 'failed' && r.state === 'failed')
                    || (show === 'unchecked' && (r.state === 'unchecked' || r.state === 'partly')) || (show === 'passed' && r.state === 'passed'));
            }, [scope, show]);
            const counts = useMemo(() => {
                const inScope = scope ? new Set(scope) : null;
                const c = { all: 0, failed: 0, unchecked: 0, passed: 0 };
                data.list.forEach(r => {
                    if (inScope && !inScope.has(r.id)) return;
                    c.all++;
                    if (r.state === 'failed') c.failed++;
                    else if (r.state === 'passed') c.passed++;
                    else c.unchecked++;
                });
                return c;
            }, [data, scope]);
            const hasEvidence = data.list.some(r => r.evidence);
            const stateLabel = (s) => ({ failed: t('failed'), passed: t('passed'), unchecked: t('crCmpNotChecked'), partly: t('crCmpPartly') })[s];
            const nodeList = (a) => (a.length > 4 ? `${a.slice(0, 4).join(', ')} +${a.length - 4}` : a.join(', '));

            const controlCols = useMemo(() => [
                { key: 'dot', label: '', menuLabel: t('status'), width: 30, resizable: false, sortValue: r => ['failed', 'partly', 'unchecked', 'passed'].indexOf(r.state),
                  render: r => <span className={`cr-dot cr-dot-${CR_CMP_TONE[r.state] === 'neutral' ? 'none' : CR_CMP_TONE[r.state]}`} aria-hidden="true" /> },
                { key: 'title', label: t('control'), flex: true, min: 200, sortValue: r => r.title,
                  render: r => <span className="cr-strong" title={r.title}>{r.title}</span> },
                { key: 'id', label: 'ID', width: 170, mono: true, sortValue: r => r.id, render: r => <span title={r.id}>{r.id}</span> },
                { key: 'state', label: t('status'), width: 150, sortValue: r => ['failed', 'partly', 'unchecked', 'passed'].indexOf(r.state),
                  render: r => <span data-cr-cmp-state={r.state}><CrBadge tone={CR_CMP_TONE[r.state]}>{stateLabel(r.state)}</CrBadge></span> },
                { key: 'passed', label: t('passed'), width: 76, align: 'right', mono: true, sortValue: r => r.passed.length, render: r => r.passed.length },
                { key: 'failed', label: t('failed'), width: 76, align: 'right', mono: true, sortValue: r => r.failed.length,
                  render: r => (r.failed.length ? <span className="cr-tone-text cr-tone-error">{r.failed.length}</span> : 0) },
                { key: 'unchecked', label: t('crCmpNotChecked'), width: 118, align: 'right', mono: true, sortValue: r => r.unchecked.length,
                  title: t('hardenNotCheckedHint'), render: r => r.unchecked.length },
                { key: 'reason', label: t('crCmpReason'), width: 240, sortValue: r => r.failed.join(',') || r.unchecked.join(','),
                  render: r => {
                      const text = r.failed.length ? crFill(t('crCmpFailedOn'), { nodes: nodeList(r.failed) })
                          : r.unchecked.length ? crFill(t('crCmpNoResultFrom'), { nodes: nodeList(r.unchecked) }) : '';
                      return <span title={[...r.failed, ...r.unchecked].join(', ')}>{text}</span>;
                  } },
                { key: 'fws', label: t('crCmpFrameworks'), width: 150, sortValue: r => r.fws.length,
                  render: r => <span title={r.fws.map(id => fwById[id] && fwById[id].name).join('\n')}>{r.fws.length ? r.fws.map(id => id.toUpperCase()).join(', ') : '-'}</span> },
                { key: 'evidence', label: t('crCmpEvidence'), width: 220, hidden: !hasEvidence, sortValue: r => r.evidence || null,
                  render: r => <span className="cr-mono" title={r.evidence}>{r.evidence}</span> },
            ], [t, hasEvidence, fwById]);

            const nodeRows = useMemo(() => data.nodes.map(([name, info]) => ({ name, info })), [data]);
            const nodeCols = useMemo(() => [
                { key: 'dot', label: '', menuLabel: t('status'), width: 30, resizable: false, sortValue: x => (x.info.controls ? 1 : 0),
                  render: x => <span className={`cr-dot cr-dot-${x.info.controls ? (crScoreTone(x.info.score) || 'none') : 'warning'}`} aria-hidden="true" /> },
                { key: 'name', label: t('node'), flex: true, min: 140, sortValue: x => x.name, render: x => <span className="cr-strong">{x.name}</span> },
                { key: 'score', label: t('crCmpScore'), width: 90, align: 'right', mono: true, sortValue: x => (x.info.controls ? x.info.score : null),
                  render: x => (x.info.controls && x.info.score != null
                      ? <span className={`cr-tone-text cr-tone-${crScoreTone(x.info.score)}`}>{x.info.score}%</span> : '-') },
                { key: 'passed', label: t('passed'), width: 80, align: 'right', mono: true, sortValue: x => (x.info.controls ? x.info.passed : null),
                  render: x => (x.info.controls ? x.info.passed : '-') },
                { key: 'failed', label: t('failed'), width: 80, align: 'right', mono: true, sortValue: x => (x.info.controls ? x.info.total - x.info.passed : null),
                  render: x => (x.info.controls ? x.info.total - x.info.passed : '-') },
                { key: 'unchecked', label: t('crCmpNotChecked'), width: 118, align: 'right', mono: true, sortValue: x => (x.info.controls ? x.info.notChecked : null),
                  render: x => (x.info.controls ? x.info.notChecked : '-') },
                { key: 'state', label: t('status'), width: 300, sortValue: x => (x.info.controls ? '' : 'z'),
                  render: x => (x.info.controls
                      ? <CrBadge tone="success">{t('crCmpAnswered')}</CrBadge>
                      : <span title={crDash(sshReason(x.info)[1])}><CrBadge tone="warning">{t('unavailable')}</CrBadge> <span className="cr-muted">{crDash(sshReason(x.info)[0]) || `HTTP ${x.info.error}`}</span></span>) },
            ], [t]);

            const profileLabel = customSel ? customSel.name : profile === 'vs-nfd' ? 'VS-NfD (BSI Grundschutz)' : profile.toUpperCase();
            const chips = [['all', t('all')], ['failed', t('failed')], ['unchecked', t('crCmpNotChecked')], ['passed', t('passed')]];
            return (
                <div className="cr-dash cr-cmp" data-cr-compliance="">
                    <CrPageHeader icon={<Icons.Lock />} title={t('complianceDashboard')}
                        sub={selectedCluster ? `${clusterLabel(selectedCluster)} · ${profileLabel}` : null}
                        actions={(
                            <>
                                <label className="cr-cmp-profile">
                                    <span className="cr-muted">{t('crCmpProfile')}</span>
                                    <select className="cr-select" value={profile} onChange={e => setProfile(e.target.value)} data-cr-cmp-profile="">
                                        <option value="cis-l1">CIS Level 1 (default)</option>
                                        <option value="vs-nfd">VS-NfD (BSI Grundschutz)</option>
                                        <option value="dr">Diffusion Restreinte (ANSSI II 901)</option>
                                        <option value="rgs">RGS (ANSSI-BP-028)</option>
                                        {(customProfiles || []).length > 0 && (
                                            <optgroup label={t('hpCustomProfiles')}>
                                                {customProfiles.map(p => <option key={p.id} value={`custom:${p.id}`}>{p.name}</option>)}
                                            </optgroup>
                                        )}
                                    </select>
                                </label>
                                <button type="button" className="cr-btn" onClick={onRefresh} data-cr-cmp-refresh="">
                                    <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>{t('refresh')}
                                </button>
                                <button type="button" className="cr-btn cr-btn-ghost"
                                    onClick={() => window.dispatchEvent(new CustomEvent('open-settings', { detail: { tab: 'compliance' } }))}>
                                    <span className="cr-ico" aria-hidden="true"><Icons.Settings /></span>{t('openSettingsCompliance')}
                                </button>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('complianceDashboardHint')}</p>
                    {!selectedCluster ? (
                        <div className="cr-panel cr-empty" data-cr-empty="">
                            <Icons.Server className="w-6 h-6" />
                            <p>{t('noClusterSelected')}</p>
                        </div>
                    ) : (
                        <>
                            {clusterErr && (
                                <div className="cr-callout cr-callout-warning" role="alert" data-cr-cmp-cluster-error="">
                                    <Icons.AlertTriangle className="w-4 h-4" />
                                    <div>
                                        <p className="cr-strong">{t('complianceUnavailable')}</p>
                                        <p>{crDash(sshReason(clusterErr)[0])}</p>
                                        {sshReason(clusterErr)[1] && <p className="cr-muted">{crDash(sshReason(clusterErr)[1])}</p>}
                                    </div>
                                </div>
                            )}
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-cmp-summary="">
                                <CrStat id="score" label={t('overallScore')} value={overallScore == null ? '-' : `${overallScore}%`}
                                    tone={scoreTone === 'error' ? 'error' : scoreTone === 'warning' ? 'warning' : null}
                                    sub={overallScore == null ? t('crCmpNothingChecked') : crFill(t('crCmpScoreSub'), { n: data.answered.length })} />
                                <CrStat id="passed" label={t('passed')} value={data.passed}
                                    sub={crFill(t('crCmpOfChecked'), { n: data.checked })} />
                                <CrStat id="failed" label={t('failed')} value={data.failed} tone={data.failed ? 'error' : null}
                                    sub={crFill(t('crCmpOfChecked'), { n: data.checked })} />
                                <CrStat id="unchecked" label={t('crCmpNotChecked')} value={data.notChecked} tone={data.notChecked ? 'warning' : null}
                                    sub={t('crCmpNotCounted')} title={t('hardenNotCheckedHint')} />
                                <CrStat id="coverage" label={t('coverage')} value={coverage == null ? '-' : `${coverage}%`}
                                    sub={crFill(t('crCmpCoverageSub'), { checked: data.checked, total: data.checked + data.notChecked })} />
                                <CrStat id="nodes" label={t('nodes')} value={data.answered.length} unit={`/ ${data.nodes.length}`}
                                    tone={unavailable ? 'warning' : null}
                                    sub={unavailable ? crFill(t('crCmpUnavailableN'), { n: unavailable }) : (data.nodes.length ? t('crCmpAllAnswered') : '-')} />
                                <CrStat id="checked" label={t('lastCheck')} value={checkedAt ? crFmtTime(checkedAt) : '-'}
                                    sub={loading ? t('loading') : t('crCmpThisSession')} />
                            </section>

                            {[{ region: 'EU', label: t('regionEU') }, { region: 'US', label: t('regionUS') }].map(group => (
                                <CrPanel key={group.region} title={group.label} className="cr-fw-panel" data-cr-fw-group={group.region}>
                                    <div className="cr-fw-grid">
                                        {group.region === 'EU' && customSel && (
                                            <CrFrameworkCard fw={customSel} s={frameworkScore(customSel)} custom t={t} onShow={() => pick('custom')} />
                                        )}
                                        {frameworks.filter(fw => fw.region === group.region).map(fw => {
                                            const s = frameworkScore(fw);
                                            return (
                                                <CrFrameworkCard key={fw.id} fw={fw} s={s} t={t} onShow={() => pick(fw.id)}
                                                    canReport={s.total > 0 && !!selectedCluster && !fw.informational} onReport={() => onReport(fw)} />
                                            );
                                        })}
                                    </div>
                                </CrPanel>
                            ))}

                            <div ref={tableRef} className="cr-cmp-controls">
                                <CrTable id="cmp-controls" columns={controlCols} rows={data.list} rowKey={r => r.id} filter={filter} searchable
                                    loading={loading} ariaLabel={t('crCmpControls')} maxHeight={480} initialSort={{ key: 'state', dir: 'asc' }}
                                    emptyText={t('noData')}
                                    toolbar={(
                                        <>
                                            <span className="cr-table-title">{t('crCmpControls')}</span>
                                            <select className="cr-select" value={fwPick} onChange={e => setFwPick(e.target.value)}
                                                aria-label={t('crCmpFrameworks')} data-cr-cmp-fw="">
                                                <option value="">{t('crCmpAllControls')}</option>
                                                {customSel && <option value="custom">{customSel.name}</option>}
                                                {frameworks.map(fw => <option key={fw.id} value={fw.id}>{fw.name}</option>)}
                                            </select>
                                            <div className="cr-seg" role="group" aria-label={t('filter')}>
                                                {chips.map(([id, label]) => (
                                                    <button key={id} type="button" className={show === id ? 'active' : ''} aria-pressed={show === id}
                                                        data-cr-cmp-show={id} onClick={() => setShow(id)}>
                                                        {label}<span className="cr-seg-n">{counts[id]}</span>
                                                    </button>
                                                ))}
                                            </div>
                                        </>
                                    )} />
                            </div>
                            <CrTable id="cmp-nodes" columns={nodeCols} rows={nodeRows} rowKey={x => x.name} loading={loading}
                                ariaLabel={t('nodes')} maxHeight={360} initialSort={{ key: 'name', dir: 'asc' }}
                                emptyText={t('noData')} toolbar={<span className="cr-table-title">{t('nodes')}</span>} />
                        </>
                    )}
                    {auditCounts && (
                        <CrPanel title={t('auditActivity')} data-cr-cmp-audit=""
                            actions={<span className="cr-table-sub">{t('lastEntries')}</span>}>
                            <div className="cr-stat-row cr-stat-row-flat">
                                {[['auth', 'Auth/Login'], ['rbac', 'RBAC'], ['vm', 'VM ops'], ['settings', 'Settings'], ['other', 'Other']].map(([k, label]) => (
                                    <CrStat key={k} id={`audit-${k}`} label={label} value={auditCounts[k]} />
                                ))}
                            </div>
                        </CrPanel>
                    )}
                </div>
            );
        }
