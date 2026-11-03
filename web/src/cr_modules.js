        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the Reports modules CVE Scanner, Cost Dashboard, Power & Carbon,
        // Network Topology and API Health - LW Nov 2026
        // The CVE page gets the dashboard's scan state and its two POSTs; costs, power and the
        // topology are drawn from the classic tab's own state and handlers (every read and write is
        // the classic one, the tab hands them over); API health reads the same route the classic
        // page polls. A figure the answer does not carry says so, an answer that never came is
        // not drawn as zero.
        // ═══════════════════════════════════════════════════════════

        const CR_MD_CUR = { EUR: '€', USD: '$', GBP: '£', CHF: 'CHF', JPY: '¥', BRL: 'R$' };
        const crMdNum = (v) => typeof v === 'number' && Number.isFinite(v);
        // a figure in the UI language with a fixed number of digits; null when there is none
        function crMdFix(v, digits = 0) {
            const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
            if (!crMdNum(n)) return null;
            return n.toLocaleString(crLocale(), { minimumFractionDigits: digits, maximumFractionDigits: digits });
        }
        const crMdMoney = (v, cur) => { const s = crMdFix(v, 2); return s == null ? null : `${CR_MD_CUR[cur] || cur || ''} ${s}`.trim(); };
        const crMdDay = (d) => crFmtDate(d, { hour: undefined, minute: undefined, second: undefined });
        const crMdShare = (part, whole) => (crMdNum(part) && crMdNum(whole) && whole > 0 ? (part / whole) * 100 : null);

        // why a read of a classic tab failed ({ why } it hands over), never an empty reason
        const crMdWhy = (e, t) => (e && e.why) || t('crDcNoAnswer');
        // a value the answer leaves out, as the node pages say it
        const crMdOr = (v, miss) => (v == null || v === '' ? <CrNcMissing text={miss} /> : v);

        // "as of" of a kept report (computed_at, refreshing), the way ReportStamp says it
        function CrMdStamp({ report }) {
            const { t } = useTranslation();
            if (!report || !report.computed_at) return null;
            const ms = new Date(report.computed_at).getTime();
            if (!Number.isFinite(ms)) return null;
            return (
                <span className="cr-md-stamp" data-cr-md-stamp="">
                    {crFill(t('reportAsOf'), { time: crVmWhen(ms) })}
                    {report.refreshing && <> <CrBadge tone="info" dot={false}>{t('reportUpdating')}</CrBadge></>}
                </span>
            );
        }

        // the window select of the costs and the power page
        function CrMdDays({ value, options, onChange, id }) {
            const { t } = useTranslation();
            const label = { 1: t('lastDay'), 7: t('last7Days'), 14: t('last14Days'), 30: t('last30Days') };
            return (
                <label className="cr-ins-window">
                    <span>{t('crInsWindow')}</span>
                    <select className="cr-select" value={value} onChange={e => onChange(parseInt(e.target.value, 10))} data-cr-md-days={id}>
                        {options.map(d => <option key={d} value={d}>{label[d] || crFill(t('crInsDaysN'), { d })}</option>)}
                    </select>
                </label>
            );
        }

        // the read of a classic report tab: loading before the first answer, failed (no summary
        // came, or the last refresh did not), not enough history, or ok
        function crMdReport(summary, loading, readErr, seen) {
            if (summary && !readErr) return summary.enough_data ? 'ok' : 'notenough';
            if (summary && readErr) return summary.enough_data ? 'stale' : 'notenough';
            if (loading || !seen) return 'loading';
            return 'error';
        }
        // true once the tab has started a read: before that an empty page is not a failed one
        function useCrMdSeen(loading) {
            const seen = useRef(false);
            if (loading) seen.current = true;
            return seen.current;
        }

        // the guest of a row as a link when the inventory of the cluster holds it; one lookup map per
        // guest list, so a table of 10k rows does not walk the list for every row it draws
        const crMdGuestMaps = new WeakMap();
        function crMdGuestOf(list, vmid) {
            if (!Array.isArray(list)) return null;
            let m = crMdGuestMaps.get(list);
            if (!m) { m = new Map(list.map(x => [String(x.vmid), x])); crMdGuestMaps.set(list, m); }
            return m.get(String(vmid)) || null;
        }
        function CrMdGuest({ cid, vmid, name, type, nav }) {
            const list = nav && nav.guestsOf ? nav.guestsOf(cid) : null;
            const g = crMdGuestOf(list, vmid);
            const label = name || g && g.name || `${type === 'lxc' ? 'CT' : 'VM'} ${vmid}`;
            return g && nav.openGuest
                ? <button type="button" className="cr-link" data-cr-md-guest={vmid} onClick={e => { e.stopPropagation(); nav.openGuest(cid, g); }}>{label}</button>
                : <span className="cr-strong">{label}</span>;
        }
        function CrMdNode({ cid, name, nav }) {
            if (!name) return <CrNcMissing />;
            return nav && nav.openNode
                ? <button type="button" className="cr-link" data-cr-md-node={name} onClick={e => { e.stopPropagation(); nav.openNode(cid, name); }}>{name}</button>
                : <span>{name}</span>;
        }

        // --- CVE Scanner ---------------------------------------------------------------------------

        const CR_CVE_URG = { high: 0, medium: 1, low: 2, unimportant: 3 };
        const CR_CVE_URG_TONE = { high: 'error', medium: 'warning', low: 'neutral', unimportant: 'neutral' };
        const CR_CVE_PKG_TONE = { critical: 'error', security: 'warning', normal: 'neutral' };

        // the scan answer, counted: per node its state, and what the whole cluster comes to
        function crCveModel(res) {
            if (!res || !Array.isArray(res.nodes)) return null;
            const s = res.summary || {};
            const rows = res.nodes.filter(n => n && typeof n === 'object').map(n => {
                const cves = Array.isArray(n.cves) ? n.cves : [];
                const pkgs = Array.isArray(n.packages) ? n.packages : [];
                const high = cves.filter(c => c.urgency === 'high').length;
                const failed = !!n.error;
                const state = failed ? 'failed'
                    : (n.cve_count || 0) > 0 && high > 0 ? 'vulnerable'
                    : (n.security_count || 0) > 0 || (n.cve_count || 0) > 0 ? 'security'
                    : (n.total_count || 0) > 0 ? 'updates' : 'clean';
                return { ...n, cves, pkgs, high, failed, state };
            });
            const ok = rows.filter(r => !r.failed);
            const withDebsecan = ok.filter(r => r.debsecan_available).length;
            return {
                rows, total: rows.length, ok: ok.length, failed: rows.length - ok.length,
                cves: crMdNum(s.total_cves) ? s.total_cves : ok.reduce((a, r) => a + (r.cve_count || 0), 0),
                high: ok.reduce((a, r) => a + r.high, 0),
                security: crMdNum(s.total_security) ? s.total_security : ok.reduce((a, r) => a + (r.security_count || 0), 0),
                updates: crMdNum(s.total_updates) ? s.total_updates : ok.reduce((a, r) => a + (r.total_count || 0), 0),
                clean: ok.filter(r => r.state === 'clean').length,
                reboot: ok.filter(r => r.reboot_required).length,
                debsecan: !!s.debsecan_available, withDebsecan,
                at: res.scanned_at || null,
            };
        }
        const crCveSort = (list) => [...list].sort((a, b) => ((CR_CVE_URG[a.urgency] ?? 4) - (CR_CVE_URG[b.urgency] ?? 4)) || String(a.cve).localeCompare(String(b.cve)));
        const crCvePkgSort = (list) => [...list].sort((a, b) => (({ critical: 0, security: 1 })[a.severity] ?? 2) - (({ critical: 0, security: 1 })[b.severity] ?? 2) || String(a.name).localeCompare(String(b.name)));

        function crCveStateBadge(r, t) {
            const map = { failed: ['error', t('crCveStFailed')], vulnerable: ['error', t('crCveStVulnerable')],
                          security: ['warning', t('crCveStSecurity')], updates: ['info', t('crCveStUpdates')], clean: ['success', t('upToDate')] };
            const [tone, text] = map[r.state];
            return <span data-cr-cve-state={r.state}><CrBadge tone={tone}>{text}</CrBadge></span>;
        }

        function CrCveNodeDetail({ r, cid, nav, onOpenUpdates }) {
            const { t } = useTranslation();
            const fix = (c) => (c.fix_type === 'apt' ? ['success', t('fixAvailable')] : c.fix_type === 'pve_upgrade' ? ['warning', t('crCveFixPve')] : ['neutral', t('noFix')]);
            if (r.failed) {
                return <div className="cr-md-detail" data-cr-cve-detail={r.node}><CrNcState id={`cve-${r.node}`} kind="error">{crFill(t('crCveNodeFailed'), { why: r.error })}</CrNcState></div>;
            }
            return (
                <div className="cr-md-detail" data-cr-cve-detail={r.node}>
                    <CrNcKv id={`cve-${r.node}`} rows={[
                        { k: 'os', label: t('crCveOs'), value: r.os },
                        { k: 'kernel', label: t('crCveKernel'), value: r.kernel, mono: true },
                        { k: 'pve', label: t('crCvePve'), value: crUpdPve(r.pve_version) || (r.pve_version && r.pve_version !== 'N/A' ? r.pve_version : ''), mono: true },
                        { k: 'suite', label: t('crCveSuite'), value: r.suite, missing: r.debsecan_available ? undefined : t('crCveNoDebsecanShort') },
                        { k: 'mode', label: t('crCveMode'), value: r.cve_mode === 'fixed' ? t('crCveModeFixed') : r.cve_mode ? t('crCveModeAll') : '',
                          missing: r.debsecan_available ? undefined : t('crCveNoDebsecanShort') },
                        { k: 'at', label: t('scannedAt'), value: r.timestamp ? crFmtDate(r.timestamp) : '' },
                    ]} />
                    {r.cve_truncated && (
                        <CrNcState id={`cve-cut-${r.node}`} kind="warning">{crFill(t('crCveTruncated'), { n: r.cves.length, total: crMdNum(r.cve_total) ? r.cve_total : '?' })}</CrNcState>
                    )}
                    {!r.debsecan_available && <p className="cr-sb-fine" data-cr-cve-nodebsecan={r.node}>{t('crCveNodeNoDebsecan')}</p>}
                    {r.cves.length > 0 && (
                        <div className="cr-md-sub">
                            <h4 className="cr-nn-sub">{crFill(t('crCveListTitle'), { n: r.cves.length })}</h4>
                            <div className="cr-md-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table cr-md-table" data-cr-cve-cves={r.node}>
                                    <thead><tr><th>CVE</th><th>{t('packageName')}</th><th>{t('crCveUrgency')}</th><th>{t('crCveNotes')}</th><th>{t('firstDetected')}</th><th>{t('crCveFix')}</th></tr></thead>
                                    <tbody>
                                        {crCveSort(r.cves).map((c, i) => {
                                            const [tone, text] = fix(c);
                                            return (
                                                <tr key={`${c.cve}|${c.package}|${i}`} data-cr-cve-id={c.cve}>
                                                    <td className="cr-mono"><a className="cr-link" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve)}`} target="_blank" rel="noopener noreferrer">{c.cve}</a></td>
                                                    <td className="cr-mono">{c.package}</td>
                                                    <td><CrBadge tone={CR_CVE_URG_TONE[c.urgency] || 'neutral'} dot={false}>{c.urgency && c.urgency !== 'unknown' ? c.urgency : t('crNsNotReported')}</CrBadge></td>
                                                    <td className="cr-md-flags">
                                                        {c.remote && <CrBadge tone="warning" dot={false}>{t('crCveRemote')}</CrBadge>}
                                                        {c.obsolete && <CrBadge tone="neutral" dot={false}>{t('crCveObsolete')}</CrBadge>}
                                                        {!c.remote && !c.obsolete && <span className="cr-muted">-</span>}
                                                    </td>
                                                    <td>{c.first_seen ? crMdDay(c.first_seen) : <CrNcMissing />}</td>
                                                    <td data-cr-cve-fix={c.fix_type || 'none'}><CrBadge tone={tone} dot={false}>{text}</CrBadge></td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {r.pkgs.length > 0 && (
                        <div className="cr-md-sub">
                            <h4 className="cr-nn-sub">{crFill(t('crCvePkgTitle'), { n: r.pkgs.length })}</h4>
                            <div className="cr-md-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table cr-md-table" data-cr-cve-pkgs={r.node}>
                                    <thead><tr><th>{t('packageName')}</th><th>{t('installed')}</th><th>{t('available')}</th><th>{t('crCveOrigin')}</th><th>{t('type')}</th></tr></thead>
                                    <tbody>
                                        {crCvePkgSort(r.pkgs).map((p, i) => (
                                            <tr key={`${p.name}|${i}`} data-cr-cve-pkg={p.name}>
                                                <td className="cr-mono">{p.name}</td>
                                                <td className="cr-mono cr-muted">{crMdOr(p.current)}</td>
                                                <td className="cr-mono">{crMdOr(p.available)}</td>
                                                <td className="cr-md-origin">{crMdOr(p.source)}</td>
                                                <td><CrBadge tone={CR_CVE_PKG_TONE[p.severity] || 'neutral'} dot={false}>
                                                    {p.severity === 'critical' ? t('crCvePkgCritical') : p.severity === 'security' ? t('security') : t('update')}
                                                </CrBadge></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {r.pkgs.length === 0 && r.cves.length === 0 && <p className="cr-md-line" data-cr-cve-clean={r.node}><CrBadge tone="success">{t('allPkgsUpToDate')}</CrBadge></p>}
                    {(r.cve_count > 0 || r.total_count > 0) && onOpenUpdates && (
                        <div className="cr-md-foot">
                            <span className="cr-muted">{t('cveApplyHint')}</span>
                            <CrButton icon={<Icons.Download />} onClick={onOpenUpdates} data-cr-cve-updates={r.node}>{t('openUpdateManager')}</CrButton>
                        </div>
                    )}
                </div>
            );
        }

        function CrCveScan({ cluster, results, loading, installing, readOnly, onScan, onInstall, onOpenUpdates, nav }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const m = useMemo(() => crCveModel(results), [results]);
            const [open, setOpen] = useState({});
            const [exporting, setExporting] = useState(false);
            const rootRef = useRef(null);
            const narrow = crRpNarrow(rootRef, 940);
            useEffect(() => { setOpen({}); }, [results]);
            const toggle = (r) => setOpen(o => ({ ...o, [r.node]: !o[r.node] }));
            const none = t('crNsNotReported');
            const columns = useMemo(() => [
                { key: 'node', label: t('node'), flex: true, min: 120, sortValue: r => r.node,
                  render: r => <span className="cr-md-name" data-cr-cve-row={r.node}><CrMdNode cid={cid} name={r.node} nav={nav} /></span> },
                { key: 'state', label: t('status'), width: 150, sortValue: r => ({ failed: 0, vulnerable: 1, security: 2, updates: 3, clean: 4 })[r.state],
                  render: r => crCveStateBadge(r, t) },
                { key: 'cves', label: 'CVEs', width: 76, align: 'right', mono: true, sortValue: r => (r.failed || !r.debsecan_available ? null : r.cve_count || 0),
                  render: r => (r.failed ? '-' : r.debsecan_available ? String(r.cve_count || 0) : <span className="cr-muted" title={t('crCveNodeNoDebsecan')}>{none}</span>) },
                { key: 'high', label: t('crCveHigh'), width: 64, align: 'right', mono: true, hidden: narrow, sortValue: r => (r.failed || !r.debsecan_available ? null : r.high),
                  render: r => (r.failed || !r.debsecan_available ? '-' : String(r.high)) },
                { key: 'sec', label: t('securityUpdates'), width: 136, align: 'right', mono: true, sortValue: r => (r.failed ? null : r.security_count || 0),
                  render: r => (r.failed ? '-' : String(r.security_count || 0)) },
                { key: 'upd', label: t('totalUpdates'), width: 120, align: 'right', mono: true, hidden: narrow, sortValue: r => (r.failed ? null : r.total_count || 0),
                  render: r => (r.failed ? '-' : String(r.total_count || 0)) },
                { key: 'reboot', label: t('crCveReboot'), width: 120, sortValue: r => (r.failed ? null : r.reboot_required ? 1 : 0),
                  render: r => (r.failed ? '-' : r.reboot_required ? <CrBadge tone="warning">{t('crCveRebootNeeded')}</CrBadge> : <span className="cr-muted">{t('crCveNoReboot')}</span>) },
                { key: 'kernel', label: t('crCveKernel'), width: 130, mono: true, hidden: true, sortValue: r => r.kernel || null, render: r => r.kernel || '-' },
                { key: 'pve', label: t('crCvePve'), width: 112, mono: true, hidden: narrow, sortValue: r => crUpdPve(r.pve_version) || null, render: r => crUpdPve(r.pve_version) || '-' },
                { key: 'err', label: t('crCveWhy'), width: 180, hidden: true, sortValue: r => r.error || null, render: r => r.error || '' },
            ], [t, cid, nav, narrow]);

            const exportPdf = async () => {
                if (!m || typeof generatePegaProxPDF !== 'function' || exporting) return;
                setExporting(true);
                try {
                    const blocks = [{ type: 'stats', data: [
                        { label: 'CVEs', value: m.withDebsecan ? String(m.cves) : '-', color: '#dc3232' },
                        { label: crRpSafe(t('securityUpdates')), value: String(m.security), color: '#c89600' },
                        { label: crRpSafe(t('totalUpdates')), value: String(m.updates), color: '#c89600' },
                        { label: crRpSafe(t('nodesScanned')), value: `${m.ok}/${m.total}`, color: '#3c82c8' },
                    ] }, { type: 'spacer', height: 4 }];
                    m.rows.forEach(r => {
                        if (r.failed) { blocks.push({ type: 'text', value: crRpSafe(`${r.node}: ${r.error}`) }); return; }
                        if (r.cves.length) {
                            blocks.push({ type: 'table', title: crRpSafe(`${r.node} - ${r.cve_count || 0} CVEs, ${r.total_count || 0} ${t('updates')}`),
                                columns: ['CVE', crRpSafe(t('packageName')), crRpSafe(t('crCveUrgency')), crRpSafe(t('crCveFix'))],
                                rows: crCveSort(r.cves).map(c => [crRpSafe(c.cve), crRpSafe(c.package), crRpSafe(c.urgency || '-'),
                                    crRpSafe(c.fix_type === 'apt' ? t('fixAvailable') : c.fix_type === 'pve_upgrade' ? t('crCveFixPve') : t('noFix'))]) });
                        } else if (r.pkgs.length) {
                            blocks.push({ type: 'table', title: crRpSafe(`${r.node} - ${r.total_count || 0} ${t('updates')}`),
                                columns: [crRpSafe(t('packageName')), crRpSafe(t('installed')), crRpSafe(t('available')), crRpSafe(t('type'))],
                                rows: crCvePkgSort(r.pkgs).map(p => [crRpSafe(p.name), crRpSafe(p.current), crRpSafe(p.available), crRpSafe(p.severity)]) });
                        }
                    });
                    await generatePegaProxPDF({ title: 'CVE Security Report', subtitle: crRpSafe(m.at ? crFmtDate(m.at) : ''), clusterName: crRpSafe(clusterLabel(cluster)),
                        filename: `pegaprox-cve-${clusterLabel(cluster) || 'cluster'}.pdf`, content: blocks });
                } catch (_) {} finally { setExporting(false); }
            };
            const png = () => crRpPng(rootRef.current && rootRef.current.querySelector('[data-cr-cve-report]'),
                `pegaprox-cve-report-${clusterLabel(cluster) || 'cluster'}-${new Date().toISOString().slice(0, 10)}.png`);

            const state = loading ? 'scanning' : m ? 'ok' : 'none';
            const allFailed = m && m.total > 0 && m.ok === 0;
            const dash = (v) => (allFailed ? '-' : v);
            return (
                <div className="cr-ins cr-md" data-cr-cve={state} ref={rootRef}>
                    <CrPageHeader icon={<Icons.Shield />} title={t('cveScanner')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                {m && !loading && <CrButton icon={<Icons.Download />} onClick={png} data-cr-cve-png="">PNG</CrButton>}
                                {m && !loading && <CrButton icon={<Icons.Download />} onClick={exportPdf} disabled={exporting} data-cr-cve-pdf="">PDF</CrButton>}
                                <CrButton variant="primary" icon={loading ? <span className="cr-spinner" /> : <Icons.Shield />} onClick={() => onScan()}
                                    disabled={loading || readOnly} title={readOnly ? t('crMdStandby') : undefined} data-cr-cve-scan="">
                                    {loading ? t('scanning') : t('scanAllNodes')}
                                </CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('cveScanDesc')} {t('crCveOnDemand')}</p>
                    {readOnly && <CrRpNote tone="info" id="cve-standby">{t('crMdStandby')}</CrRpNote>}

                    {state === 'scanning' && <CrNcState id="cve" kind="loading">{t('scanRunning')} {t('scanTakesMinute')}</CrNcState>}
                    {state === 'none' && (
                        <CrNcSection id="cve-none" title={t('noScanResults')} desc={t('crCveNoneDesc')} />
                    )}
                    {state === 'ok' && (
                        <div className="cr-md-report" data-cr-cve-report="">
                            {!m.debsecan && (
                                <CrNcSection id="cve-debsecan" title={t('debsecanNotInstalled')} desc={t('debsecanExplain')}
                                    badge={<CrBadge tone="warning">{t('crCveNoCveIds')}</CrBadge>}
                                    actions={!readOnly ? (
                                        <CrButton icon={installing ? <span className="cr-spinner" /> : <Icons.Download />} onClick={() => onInstall()}
                                            disabled={installing || loading} data-cr-cve-install="">{installing ? t('installing') : t('installDebsecan')}</CrButton>
                                    ) : null}>
                                    <p className="cr-sb-fine">{t('debsecanInstallInfo')}</p>
                                </CrNcSection>
                            )}
                            {m.debsecan && m.withDebsecan < m.ok && (
                                <CrRpNote tone="warning" id="cve-partial">{crFill(t('crCvePartial'), { n: m.ok - m.withDebsecan, total: m.ok })}</CrRpNote>
                            )}
                            {allFailed && <CrRpNote tone="error" id="cve-allfailed">{t('crCveAllFailed')}</CrRpNote>}
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-cve-tiles="">
                                <CrRpStat id="nodes" label={t('nodesScanned')} value={`${m.ok}/${m.total}`} tone={m.failed ? 'warning' : undefined}
                                    sub={m.failed ? crFill(t('crCveNFailed'), { n: m.failed }) : t('crCveAllAnswered')} />
                                <CrRpStat id="cves" label="CVEs" value={m.withDebsecan ? dash(String(m.cves)) : none}
                                    tone={!allFailed && m.withDebsecan && m.high > 0 ? 'error' : undefined}
                                    sub={m.withDebsecan ? (allFailed ? '' : crFill(t('crCveNHigh'), { n: m.high })) : t('crCveNoDebsecanShort')} />
                                <CrRpStat id="security" label={t('securityUpdates')} value={dash(String(m.security))}
                                    tone={!allFailed && m.security > 0 ? 'warning' : undefined} />
                                <CrRpStat id="updates" label={t('totalUpdates')} value={dash(String(m.updates))} />
                                <CrRpStat id="clean" label={t('nodesClean')} value={dash(`${m.clean}/${m.ok}`)} />
                                <CrRpStat id="reboot" label={t('crCveReboot')} value={dash(String(m.reboot))} tone={!allFailed && m.reboot > 0 ? 'warning' : undefined}
                                    sub={t('crCveRebootSub')} />
                            </section>
                            <p className="cr-sb-fine" data-cr-cve-basis="">{crFill(t('crCveBasis'), { time: m.at ? crFmtDate(m.at) : '-' })}</p>
                            <CrPanel title={t('crCveNodes')} className="cr-ins-panel" data-cr-cve-nodes="">
                                <CrTable id="cve-nodes" columns={columns} rows={m.rows} rowKey={r => r.node} ariaLabel={t('crCveNodes')}
                                    expanded={open} renderExpanded={r => <CrCveNodeDetail r={r} cid={cid} nav={nav} onOpenUpdates={onOpenUpdates} />}
                                    onRowClick={toggle} initialSort={{ key: 'state', dir: 'asc' }} emptyText={t('crCveNoNodes')} rowHeight={30}
                                    searchable={m.rows.length > 12} maxHeight={720} />
                                <p className="cr-rp-caption">{t('crCveRowHint')}</p>
                            </CrPanel>
                        </div>
                    )}
                </div>
            );
        }

        // --- API Health ----------------------------------------------------------------------------

        const crLatTone = (ms) => (!crMdNum(ms) ? undefined : ms > CR_LAT_CRIT ? 'error' : ms > CR_LAT_WARN ? 'warning' : undefined);
        const crErrTone = (pct) => (!crMdNum(pct) ? undefined : pct > CR_ERR_CRIT ? 'error' : pct > CR_ERR_WARN ? 'warning' : undefined);
        // what an api-latency answer comes to: none (the route answers zeros without a sample),
        // the newest call's age (the server falls back to the last 50 calls when none is newer than
        // its window), the chart series
        function crApiModel(body, nowMs) {
            if (!body || typeof body !== 'object') return null;
            const n = crMdNum(body.samples) ? body.samples : 0;
            const recent = Array.isArray(body.recent) ? body.recent.filter(r => r && crMdNum(r.ts) && crMdNum(r.duration_ms)) : [];
            const newest = recent.length ? Math.max(...recent.map(r => r.ts)) : null;
            const win = crMdNum(body.window_seconds) ? body.window_seconds : 300;
            const age = newest != null ? Math.max(0, Math.round(nowMs / 1000 - newest)) : null;
            return {
                none: n === 0, n, win, age, old: age != null && age > win,
                ts: recent.map(r => r.ts), ms: recent.map(r => r.duration_ms), errs: recent.filter(r => !r.status || r.status >= 400).length,
                endpoints: Array.isArray(body.by_endpoint) ? body.by_endpoint : [],
            };
        }

        function CrApiHealth({ cluster, authFetch }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const [read, setRead] = useState({ state: 'loading' });
            const [auto, setAuto] = useState(true);
            const seq = useRef(0);
            const load = useCallback(async () => {
                if (!cid) return;
                const mine = ++seq.current;
                setRead(prev => (prev.body ? { ...prev, busy: true } : { state: 'loading' }));
                const r = await crVmRead(authFetch, `${API_URL}/clusters/${cid}/api-latency`);
                if (mine !== seq.current) return;
                // a failed read keeps the last answer and says so beside it
                setRead(prev => (r.state === 'ok' ? r : prev.body ? { ...prev, busy: false, fail: r } : r));
            }, [authFetch, cid]);
            useEffect(() => { setRead({ state: 'loading' }); load(); }, [cid]);
            useEffect(() => {
                if (!auto) return undefined;
                const id = setInterval(load, 10000);
                return () => clearInterval(id);
            }, [load, auto]);
            const body = read.body || null;
            const m = useMemo(() => crApiModel(body, read.at || Date.now()), [body, read.at]);
            const colors = crSeriesColors();
            const ms = (v) => { const s = crMdFix(v, 1); return s == null ? null : s; };
            const columns = useMemo(() => [
                { key: 'endpoint', label: t('crApiEndpoint'), flex: true, min: 220, mono: true, sortValue: e => e.endpoint,
                  render: e => <span className="cr-md-ep" title={e.endpoint} data-cr-api-ep={e.endpoint}>{e.endpoint}</span> },
                { key: 'count', label: t('crApiCalls'), width: 80, align: 'right', mono: true, sortValue: e => e.count },
                { key: 'avg', label: t('crApiAvg'), width: 96, align: 'right', mono: true, sortValue: e => e.avg_ms,
                  render: e => <span className={crLatTone(e.avg_ms) ? `cr-tone-text cr-tone-${crLatTone(e.avg_ms)}` : undefined}>{ms(e.avg_ms) ?? '-'}</span> },
                { key: 'max', label: t('crApiMax'), width: 96, align: 'right', mono: true, sortValue: e => e.max_ms,
                  render: e => <span className={crLatTone(e.max_ms) ? `cr-tone-text cr-tone-${crLatTone(e.max_ms)}` : undefined}>{ms(e.max_ms) ?? '-'}</span> },
                { key: 'total', label: t('crApiTotal'), width: 104, align: 'right', mono: true, sortValue: e => e.total_ms, render: e => ms(e.total_ms) ?? '-' },
                { key: 'errors', label: t('crApiErrors'), width: 80, align: 'right', sortValue: e => e.errors || 0,
                  render: e => (e.errors > 0 ? <CrBadge tone="error" dot={false}>{String(e.errors)}</CrBadge> : <span className="cr-muted">0</span>) },
            ], [t]);
            const tile = (id, label, v, sub) => (
                <CrRpStat id={id} label={label} sub={sub} value={m && !m.none && ms(v) != null ? ms(v) : t('crNsNotReported')} unit={m && !m.none && ms(v) != null ? 'ms' : undefined}
                    tone={m && !m.none ? crLatTone(v) : undefined} />
            );
            return (
                <div className="cr-ins cr-md" data-cr-api={read.state === 'ok' || read.body ? (m && m.none ? 'none' : 'ok') : read.state}>
                    <CrPageHeader icon={<Icons.Activity />} title={t('apiHealth')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <CrButton icon={auto ? <Icons.Pause /> : <Icons.Play />} onClick={() => setAuto(a => !a)} aria-pressed={auto}
                                    data-cr-api-auto={auto ? 'on' : 'off'} title={auto ? t('crApiAutoOnTitle') : t('crApiAutoOffTitle')}>
                                    {auto ? t('crApiAutoOn') : t('crApiAutoOff')}
                                </CrButton>
                                <CrButton icon={read.busy ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={load} disabled={!!read.busy} data-cr-api-refresh="">{t('refresh')}</CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crApiIntro')}</p>
                    {read.state === 'loading' && !read.body && <CrNcState id="api" kind="loading" />}
                    {!read.body && read.state !== 'loading' && (
                        <CrNcState id="api" kind="error" onRetry={load}>{crFill(t('crMdReadFailed'), { why: crRpWhy(read, t) })}</CrNcState>
                    )}
                    {read.fail && <CrRpNote tone="warning" id="api-stale" onRetry={load}>{crFill(t('crMdStale'), { time: crVmWhen(read.at), why: crRpWhy(read.fail, t) })}</CrRpNote>}
                    {m && m.none && <CrNcState id="api-none" kind="info" data-cr-api-none="">{t('crApiNone')}</CrNcState>}
                    {m && !m.none && (
                        <>
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-api-tiles="">
                                {tile('p50', 'P50', body.p50, ms(body.avg) != null ? crFill(t('crApiAvgSub'), { v: ms(body.avg) }) : '')}
                                {tile('p95', 'P95', body.p95)}
                                {tile('p99', 'P99', body.p99)}
                                {tile('max', t('crApiMaxTile'), body.max)}
                                <CrRpStat id="samples" label={t('crApiCalls')} value={crMdFix(m.n) ?? '-'}
                                    sub={m.old ? t('crApiOldSub') : crFill(t('crApiWindowSub'), { m: Math.round(m.win / 60) })} />
                                <CrRpStat id="errors" label={t('crApiErrRate')} value={crMdFix(body.error_rate, 1) ?? '-'} unit="%" tone={crErrTone(body.error_rate)} />
                            </section>
                            {m.old && <CrRpNote tone="info" id="api-old">{crFill(t('crApiOld'), { age: crUpdAge(t, m.age), m: Math.round(m.win / 60) })}</CrRpNote>}
                            <p className="cr-sb-fine" data-cr-api-basis="">{crFill(t('crApiBasis'), { m: Math.round(m.win / 60) })}</p>
                            <CrPanel title={t('crApiRecent')} className="cr-ins-panel" data-cr-api-recent="">
                                <CrChart id="api-recent" label={t('crApiRecentLabel')} timestamps={m.ts} unit="ms" formatValue={v => v.toFixed(0)}
                                    datasets={[{ label: t('crApiRecentLabel'), data: m.ms, color: colors.cpu }]} wide none={t('crApiRecentNone')} tension={0} />
                                <p className="cr-rp-caption" data-cr-api-recent-basis="">{crFill(t('crApiRecentBasis'), { n: m.ms.length, e: m.errs })}</p>
                            </CrPanel>
                            <CrPanel title={t('crApiEndpoints')} className="cr-ins-panel" data-cr-api-endpoints="">
                                <CrTable id="api-endpoints" columns={columns} rows={m.endpoints} rowKey={e => e.endpoint} ariaLabel={t('crApiEndpoints')}
                                    initialSort={{ key: 'total', dir: 'desc' }} emptyText={t('crApiNoEndpoints')} showCount={false} />
                                <p className="cr-rp-caption">{t('crApiEndpointsBasis')}</p>
                            </CrPanel>
                        </>
                    )}
                </div>
            );
        }

        // --- Cost Dashboard ------------------------------------------------------------------------

        // the rates form: fields and what each was when the dialog opened
        function CrMdRatesDialog({ id, title, fields, form, setForm, saving, onCancel, onSave, currencies, note, hint }) {
            const { t } = useTranslation();
            const [was] = useState(() => ({ ...form }));
            const same = (k) => String(form[k] ?? '') === String(was[k] ?? '');
            const changed = fields.filter(f => !same(f.k)).length + (same('currency') ? 0 : 1) + (same('notes') ? 0 : 1);
            return (
                <CrUpdDialog id={`md-${id}`} title={title} busy={saving} onCancel={onCancel}
                    footer={(
                        <>
                            <span className="cr-muted cr-md-count" data-cr-md-changed={changed}>{changed ? crFill(t(changed === 1 ? 'crNcPendingOne' : 'crNcPendingN'), { n: changed }) : t('crNcPendingNone')}</span>
                            <CrButton onClick={onCancel} disabled={saving} data-cr-md-cancel={id}>{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={onSave} disabled={saving} data-cr-md-save={id}>{saving ? t('crNcSaving') : t('save')}</CrButton>
                        </>
                    )}>
                    <div className="cr-md-form" data-cr-md-form={id}>
                        {note}
                        {fields.map(f => (
                            <CrNcField key={f.k} id={`md-${f.k}`} label={f.label} changed={!same(f.k)} was={String(was[f.k] ?? '')} hint={f.hint}>
                                <input id={`cr-nc-md-${f.k}`} type="number" step={f.step} min={f.min} className="cr-input" value={form[f.k] ?? ''}
                                    onChange={e => setForm({ ...form, [f.k]: e.target.value })} disabled={saving} data-cr-md-field={f.k} />
                            </CrNcField>
                        ))}
                        <CrNcField id="md-currency" label={t('currency')} changed={!same('currency')} was={was.currency}>
                            <select id="cr-nc-md-currency" className="cr-select" value={form.currency || 'EUR'} disabled={saving}
                                onChange={e => setForm({ ...form, currency: e.target.value })} data-cr-md-field="currency">
                                {currencies.map(c => <option key={c} value={c}>{CR_MD_CUR[c] && CR_MD_CUR[c] !== c ? `${c} (${CR_MD_CUR[c]})` : c}</option>)}
                            </select>
                        </CrNcField>
                        <CrNcField id="md-notes" label={t('notes')} changed={!same('notes')} was={was.notes || ''} wide>
                            <input id="cr-nc-md-notes" type="text" className="cr-input" value={form.notes || ''} placeholder={t('optional')} disabled={saving}
                                onChange={e => setForm({ ...form, notes: e.target.value })} data-cr-md-field="notes" />
                        </CrNcField>
                        {hint && <p className="cr-sb-fine cr-md-wide">{hint}</p>}
                    </div>
                </CrUpdDialog>
            );
        }

        // where the rates the dialog shows come from: the cluster's own, the global default, or
        // (a failed read) the built-in values the classic form falls back to
        function crMdRateSource(form, cid) {
            if (!form || !form.cluster_id) return 'builtin';
            return form.cluster_id === cid ? 'own' : 'default';
        }
        function CrMdRateNote({ form, cid }) {
            const { t } = useTranslation();
            const src = crMdRateSource(form, cid);
            if (src === 'own') return null;
            return <CrNcState id={`rates-${src}`} kind={src === 'builtin' ? 'warning' : 'info'} data-cr-md-rate-src={src}>{t(src === 'builtin' ? 'crMdRatesBuiltin' : 'crMdRatesDefault')}</CrNcState>;
        }

        function CrMdReadState({ id, state, readErr, onRetry, noData }) {
            const { t } = useTranslation();
            if (state === 'loading') return <CrNcState id={id} kind="loading" />;
            if (state === 'error') return <CrNcState id={id} kind="error" onRetry={onRetry}>{crFill(t('crMdReadFailed'), { why: crMdWhy(readErr, t) })}</CrNcState>;
            if (state === 'notenough') return <CrNcState id={id} kind="warning" data-cr-md-notenough="">{noData}</CrNcState>;
            return null;
        }

        function CrCosts({ cluster, summary, rows, loading, readErr, days, onDays, canAct, onRefresh, onRates, rateForm, setRateForm,
                           showRates, onCloseRates, onSaveRates, savingRates, onCsv, onPdf, nav }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const seen = useCrMdSeen(loading);
            const state = crMdReport(summary, loading, readErr, seen);
            const ok = state === 'ok' || state === 'stale';
            const rootRef = useRef(null);
            const narrow = crRpNarrow(rootRef, 940);
            const cur = summary && summary.rates ? summary.rates.currency || 'EUR' : 'EUR';
            const money = (v) => crMdMoney(v, cur) ?? '-';
            const mb = (summary && summary.monthly_breakdown) || {};
            const total = summary && summary.monthly_total;
            const low = (rows || []).filter(r => r.low_data).length;
            const rates = summary && summary.rates;
            const src = rates ? crMdRateSource(rates, cid) : null;
            const byNode = useMemo(() => Object.entries((summary && summary.by_node) || {}).map(([node, v]) => ({ node, v })), [summary]);
            const nodeCols = useMemo(() => [
                { key: 'node', label: t('node'), flex: true, min: 110, sortValue: r => r.node, render: r => <CrMdNode cid={cid} name={r.node === 'unknown' ? '' : r.node} nav={nav} /> },
                { key: 'v', label: t('costMonthly'), width: 120, align: 'right', mono: true, sortValue: r => r.v, render: r => money(r.v) },
                { key: 'share', label: t('crMdShare'), width: 150, sortValue: r => crMdShare(r.v, total), sortable: true,
                  render: r => { const p = crMdShare(r.v, total); return p == null ? '-' : <span className="cr-md-share"><span className="cr-md-share-bar" aria-hidden="true"><span style={{ width: `${Math.min(100, p)}%` }} /></span><span className="cr-mono">{crMdFix(p, 1)}%</span></span>; } },
            ], [t, cid, nav, cur, total]);
            const cols = useMemo(() => [
                { key: 'name', label: t('name'), flex: true, min: 150, sortValue: r => r.name || String(r.vmid),
                  render: r => (
                      <span className="cr-md-name" data-cr-cost-row={r.vmid}>
                          <CrMdGuest cid={cid} vmid={r.vmid} name={r.name} type={r.type} nav={nav} />
                          {r.low_data && <span data-cr-md-low=""><CrBadge tone="warning" dot={false} title={t('crMdLowTitle')}>{t('crMdLow')}</CrBadge></span>}
                      </span>
                  ) },
                { key: 'vmid', label: 'ID', width: 70, mono: true, hidden: narrow, sortValue: r => Number(r.vmid) || null },
                { key: 'node', label: t('node'), width: 96, sortValue: r => r.node || null, render: r => <CrMdNode cid={cid} name={r.node} nav={nav} /> },
                { key: 'cpu', label: t('crMdAvgCpu'), width: 96, hidden: narrow, sortValue: r => r.avg_cpu_pct, render: r => <CrMeter value={crMdNum(r.avg_cpu_pct) ? r.avg_cpu_pct : null} digits={1} /> },
                { key: 'mem', label: t('crMdAvgMem'), width: 96, hidden: narrow, sortValue: r => r.avg_mem_pct, render: r => <CrMeter value={crMdNum(r.avg_mem_pct) ? r.avg_mem_pct : null} digits={1} /> },
                { key: 'cores', label: t('crMdCores'), width: 60, align: 'right', mono: true, hidden: true, sortValue: r => r.cores },
                { key: 'memgb', label: t('crMdMemGb'), width: 80, align: 'right', mono: true, hidden: true, sortValue: r => r.memory_gb, render: r => crMdFix(r.memory_gb, 1) ?? '-' },
                { key: 'disk', label: t('crMdDiskGb'), width: 80, align: 'right', mono: true, hidden: true, sortValue: r => r.disk_gb, render: r => crMdFix(r.disk_gb, 1) ?? '-' },
                { key: 'ccpu', label: t('costCpu'), width: 96, align: 'right', mono: true, sortValue: r => r.cost_cpu, render: r => money(r.cost_cpu) },
                { key: 'cmem', label: t('costMemory'), width: 96, align: 'right', mono: true, sortValue: r => r.cost_memory, render: r => money(r.cost_memory) },
                { key: 'csto', label: t('costStorage'), width: 96, align: 'right', mono: true, sortValue: r => r.cost_storage, render: r => money(r.cost_storage) },
                { key: 'window', label: crFill(t('crMdWindowCol'), { d: days }), width: 104, align: 'right', mono: true, hidden: days >= 30, sortValue: r => r.cost_total, render: r => money(r.cost_total) },
                { key: 'monthly', label: t('costMonthly'), width: 104, align: 'right', mono: true, sortValue: r => r.monthly_total ?? r.cost_total,
                  render: r => <span className="cr-strong">{money(r.monthly_total ?? r.cost_total)}</span> },
            ], [t, cid, nav, cur, days, narrow]);
            return (
                <div className="cr-ins cr-md" data-cr-cost={state} ref={rootRef}>
                    <CrPageHeader icon={<Icons.DollarSign />} title={t('costDashboard')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <CrMdDays id="cost" value={days} options={[1, 7, 14, 30]} onChange={onDays} />
                                {canAct && <CrButton icon={<Icons.Settings />} onClick={onRates} data-cr-cost-rates="">{t('costRates')}</CrButton>}
                                <CrButton icon={<Icons.Download />} onClick={onCsv} disabled={!(rows && rows.length)} data-cr-cost-csv="">CSV</CrButton>
                                <CrButton icon={<Icons.Download />} onClick={onPdf} disabled={!summary || !summary.enough_data} data-cr-cost-pdf="">PDF</CrButton>
                                <CrButton icon={loading ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={onRefresh} disabled={loading} data-cr-cost-refresh="">{t('refresh')}</CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crMdCostIntro')} <CrMdStamp report={summary} /></p>
                    {state === 'stale' && <CrRpNote tone="warning" id="cost-stale" onRetry={onRefresh}>{crFill(t('crMdStaleShort'), { why: crMdWhy(readErr, t) })}</CrRpNote>}
                    <CrMdReadState id="cost" state={state} readErr={readErr} onRetry={onRefresh} noData={t('costNoData')} />
                    {ok && (
                        <>
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-cost-tiles="">
                                <CrRpStat id="monthly" label={t('costMonthlyTotal')} value={money(total)}
                                    sub={summary.days < 30 ? crFill(t('crMdExtrapolated'), { d: summary.days, v: money(summary.total_window) }) : crFill(t('crMdWindowTotal'), { d: summary.days })} />
                                <CrRpStat id="cpu" label={t('costCpu')} value={money(mb.cpu)} sub={crMdShare(mb.cpu, total) != null ? crFill(t('crMdOfTotal'), { p: crMdFix(crMdShare(mb.cpu, total), 0) }) : ''} />
                                <CrRpStat id="memory" label={t('costMemory')} value={money(mb.memory)} sub={crMdShare(mb.memory, total) != null ? crFill(t('crMdOfTotal'), { p: crMdFix(crMdShare(mb.memory, total), 0) }) : ''} />
                                <CrRpStat id="storage" label={t('costStorage')} value={money(mb.storage)} sub={crMdShare(mb.storage, total) != null ? crFill(t('crMdOfTotal'), { p: crMdFix(crMdShare(mb.storage, total), 0) }) : ''} />
                                <CrRpStat id="guests" label={t('crMdGuests')} value={crMdFix(summary.vm_count) ?? '-'}
                                    sub={low ? crFill(t('crMdNLow'), { n: low }) : crFill(t('crMdSnaps'), { n: crMdFix(summary.snapshots_count) ?? '-' })} />
                            </section>
                            {rates && (
                                <p className="cr-sb-fine" data-cr-cost-basis={src}>
                                    {crFill(t('crMdCostRates'), { cpu: crMdFix(rates.cpu_per_core_h, 4), mem: crMdFix(rates.mem_per_gb_h, 4), sto: crMdFix(rates.storage_per_gb_month, 2), cur })}
                                    {' '}{t(src === 'own' ? 'crMdRatesOwnShort' : 'crMdRatesDefaultShort')}
                                    {src === 'own' && rates.updated_by ? ` ${crFill(t('crMdRatesBy'), { who: rates.updated_by, at: rates.updated_at || '-' })}` : ''}
                                </p>
                            )}
                            <div className="cr-md-two">
                                <CrPanel title={t('costByNode')} className="cr-ins-panel" data-cr-cost-nodes="">
                                    <CrTable id="cost-nodes" columns={nodeCols} rows={byNode} rowKey={r => r.node} ariaLabel={t('costByNode')} showCount={false}
                                        initialSort={{ key: 'v', dir: 'desc' }} emptyText={t('crMdNoNodes')} columnMenu={false} />
                                    <p className="cr-rp-caption">{t('crMdByNodeBasis')}</p>
                                </CrPanel>
                                <CrPanel title={t('crMdHowTitle')} className="cr-ins-panel" data-cr-cost-how="">
                                    <ul className="cr-md-list">
                                        <li>{t('crMdCostHowCpu')}</li>
                                        <li>{t('crMdCostHowMem')}</li>
                                        <li>{t('crMdCostHowSto')}</li>
                                        <li>{t('crMdCostHowMonth')}</li>
                                    </ul>
                                </CrPanel>
                            </div>
                            <CrPanel title={t('crMdPerGuest')} className="cr-ins-panel" data-cr-cost-guests="">
                                <CrTable id="cost-guests" columns={cols} rows={rows || []} rowKey={r => String(r.vmid)} ariaLabel={t('crMdPerGuest')}
                                    searchable initialSort={{ key: 'monthly', dir: 'desc' }} emptyText={t('noVmsFound')} maxHeight={560} />
                            </CrPanel>
                        </>
                    )}
                    {showRates && rateForm && (
                        <CrMdRatesDialog id="cost" title={crFill(t('crMdCostRatesTitle'), { cluster: clusterLabel(cluster) })} form={rateForm} setForm={setRateForm}
                            saving={savingRates} onCancel={onCloseRates} onSave={onSaveRates} currencies={['EUR', 'USD', 'GBP', 'CHF', 'JPY', 'BRL']}
                            note={<CrMdRateNote form={rateForm} cid={cid} />} hint={t('costRatesHint')}
                            fields={[
                                { k: 'cpu_per_core_h', label: t('costCpuRate'), step: '0.0001' },
                                { k: 'mem_per_gb_h', label: t('costMemRate'), step: '0.0001' },
                                { k: 'storage_per_gb_month', label: t('costStorageRate'), step: '0.01' },
                            ]} />
                    )}
                </div>
            );
        }

        // --- Power & Carbon ------------------------------------------------------------------------

        function CrPowerHostsDialog({ hosts, setHost, saving, onCancel, onSave }) {
            const { t } = useTranslation();
            const changed = hosts.filter(h => h.own !== h.wasOwn || (h.own && h.was !== `${parseFloat(h.idle)}|${parseFloat(h.max)}|${h.notes || ''}`)).length;
            return (
                <CrUpdDialog id="md-hosts" title={t('powerHostProfiles')} busy={saving} onCancel={onCancel} wide
                    footer={(
                        <>
                            <span className="cr-muted cr-md-count" data-cr-md-changed={changed}>{changed ? crFill(t(changed === 1 ? 'crNcPendingOne' : 'crNcPendingN'), { n: changed }) : t('crNcPendingNone')}</span>
                            <CrButton onClick={onCancel} disabled={saving} data-cr-md-cancel="hosts">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={onSave} disabled={saving} data-cr-md-save="hosts">{saving ? t('crNcSaving') : t('save')}</CrButton>
                        </>
                    )}>
                    <p className="cr-upd-text">{t('powerHostProfilesHint')}</p>
                    <div className="cr-md-scroll">
                        <table className="corp-datagrid cr-table cr-nn-table cr-md-table" data-cr-power-hostform="">
                            <thead><tr><th>{t('node')}</th><th>{t('powerProfileHost')}</th><th>{t('powerHostIdleW')}</th><th>{t('powerHostMaxW')}</th><th>{t('notes')}</th></tr></thead>
                            <tbody>
                                {hosts.map(h => {
                                    const off = saving || !h.own || !h.in_cluster;
                                    const dirty = h.own !== h.wasOwn || (h.own && h.was !== `${parseFloat(h.idle)}|${parseFloat(h.max)}|${h.notes || ''}`);
                                    return (
                                        <tr key={h.node} data-cr-power-host={h.node} className={dirty ? 'cr-nn-row-pending' : undefined}>
                                            <td>
                                                <span className="cr-strong">{h.node}</span>
                                                {dirty && <span className="cr-nn-pend" data-cr-nc-mark="">{t('crNcChanged')}</span>}
                                                <span className="cr-md-cellsub">{h.in_cluster ? `${h.cores} CPU · ${crMdFix(h.memory_gb, 0) ?? '-'} GB · ${h.status}` : t('powerHostGone')}</span>
                                            </td>
                                            <td><input type="checkbox" checked={!!h.own} disabled={saving || (!h.in_cluster && !h.own)} aria-label={`${h.node}: ${t('powerProfileHost')}`}
                                                onChange={e => setHost(h.node, { own: e.target.checked })} data-cr-power-own={h.node} /></td>
                                            <td><input type="number" min="0" step="1" className="cr-input cr-md-num" value={h.idle} disabled={off} aria-label={`${h.node}: ${t('powerHostIdleW')}`}
                                                onChange={e => setHost(h.node, { idle: e.target.value })} data-cr-power-idle={h.node} /></td>
                                            <td><input type="number" min="0" step="1" className="cr-input cr-md-num" value={h.max} disabled={off} aria-label={`${h.node}: ${t('powerHostMaxW')}`}
                                                onChange={e => setHost(h.node, { max: e.target.value })} data-cr-power-max={h.node} /></td>
                                            <td><input type="text" maxLength={500} className="cr-input" value={h.notes || ''} disabled={off} aria-label={`${h.node}: ${t('notes')}`}
                                                onChange={e => setHost(h.node, { notes: e.target.value })} data-cr-power-notes={h.node} /></td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                    <p className="cr-sb-fine">{t('crMdHostsSaveNote')}</p>
                </CrUpdDialog>
            );
        }

        function CrPower({ cluster, summary, rows, loading, readErr, days, onDays, canAct, onRefresh, onRates, rateForm, setRateForm, showRates,
                           onCloseRates, onSaveRates, savingRates, onHosts, hostForm, setHost, onCloseHosts, onSaveHosts, savingHosts, onCsv, onPdf, nav }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const seen = useCrMdSeen(loading);
            const state = crMdReport(summary, loading, readErr, seen);
            const ok = state === 'ok' || state === 'stale';
            const cur = summary && summary.rates ? summary.rates.currency || 'EUR' : 'EUR';
            const money = (v) => crMdMoney(v, cur) ?? '-';
            const kwh = (v) => { const s = crMdFix(v, 1); return s == null ? '-' : `${s} kWh`; };
            const co2 = (v) => { const s = crMdFix(v, 1); return s == null ? '-' : `${s} kg`; };
            const mo = (summary && summary.monthly) || {};
            const cov = (summary && summary.coverage) || {};
            const covPct = crMdShare(cov.covered_h, cov.window_h);
            const rootRef = useRef(null);
            const narrow = crRpNarrow(rootRef, 940);
            const low = (rows || []).filter(r => r.low_data).length;
            const hosts = summary && Array.isArray(summary.hosts) ? summary.hosts : [];
            const byNode = useMemo(() => Object.entries((summary && summary.by_node) || {}).map(([node, v]) => ({ node, ...(v || {}) })), [summary]);
            const hostCols = useMemo(() => [
                { key: 'node', label: t('node'), flex: true, min: 110, sortValue: h => h.node,
                  render: h => (
                      <span className="cr-md-name" data-cr-power-row={h.node}>
                          <CrMdNode cid={cid} name={h.node} nav={nav} />
                          {h.status !== 'online' && <CrBadge tone={h.status === 'offline' ? 'error' : 'neutral'} dot={false}>{h.status || t('crNsNotReported')}</CrBadge>}
                      </span>
                  ) },
                { key: 'profile', label: t('powerProfile'), width: 124, sortValue: h => h.profile,
                  render: h => <span data-cr-power-profile={h.profile}><CrBadge tone={h.profile === 'host' ? 'success' : 'neutral'} dot={false}>{h.profile === 'host' ? t('powerProfileHost') : t('powerProfileCluster')}</CrBadge></span> },
                { key: 'w', label: t('crMdIdleMax'), width: 100, hidden: narrow, align: 'right', mono: true, sortValue: h => h.max_w, render: h => `${crMdFix(h.idle_w) ?? '-'} / ${crMdFix(h.max_w) ?? '-'}` },
                { key: 'online', label: t('powerOnlineH'), width: 84, hidden: true, align: 'right', mono: true, sortValue: h => h.online_h, render: h => crMdFix(h.online_h, 1) ?? '-' },
                { key: 'avg', label: t('powerAvgW'), width: 104, hidden: narrow, align: 'right', mono: true, sortValue: h => h.avg_w, render: h => crMdFix(h.avg_w, 1) ?? '-' },
                { key: 'kwh', label: t('powerMonthlyKwh'), width: 110, align: 'right', mono: true, sortValue: h => h.monthly && h.monthly.kwh, render: h => kwh(h.monthly && h.monthly.kwh) },
                { key: 'cost', label: t('powerMonthlyCost'), width: 110, align: 'right', mono: true, sortValue: h => h.monthly && h.monthly.cost, render: h => <span className="cr-strong">{money(h.monthly && h.monthly.cost)}</span> },
                { key: 'co2', label: t('powerMonthlyCo2'), width: 100, hidden: narrow, align: 'right', mono: true, sortValue: h => h.monthly && h.monthly.kg_co2, render: h => co2(h.monthly && h.monthly.kg_co2) },
                { key: 'unalloc', label: t('powerUnallocated'), width: 172, align: 'right', mono: true, title: t('powerUnallocatedHint'),
                  sortValue: h => h.monthly_unallocated && h.monthly_unallocated.kwh,
                  render: h => <span title={t('powerUnallocatedHint')}>{kwh(h.monthly_unallocated && h.monthly_unallocated.kwh)} · {money(h.monthly_unallocated && h.monthly_unallocated.cost)}</span> },
            ], [t, cid, nav, cur, narrow]);
            const nodeCols = useMemo(() => [
                { key: 'node', label: t('node'), flex: true, min: 110, sortValue: r => r.node, render: r => <CrMdNode cid={cid} name={r.node} nav={nav} /> },
                { key: 'kwh', label: t('powerMonthlyKwh'), width: 120, align: 'right', mono: true, sortValue: r => r.kwh, render: r => kwh(r.kwh) },
                { key: 'cost', label: t('powerMonthlyCost'), width: 120, align: 'right', mono: true, sortValue: r => r.cost, render: r => money(r.cost) },
                { key: 'co2', label: t('powerMonthlyCo2'), width: 110, align: 'right', mono: true, sortValue: r => r.kg_co2, render: r => co2(r.kg_co2) },
            ], [t, cid, nav, cur]);
            const cols = useMemo(() => [
                { key: 'name', label: t('name'), flex: true, min: 150, sortValue: r => r.name || String(r.vmid),
                  render: r => (
                      <span className="cr-md-name" data-cr-power-guest={r.vmid}>
                          <CrMdGuest cid={cid} vmid={r.vmid} name={r.name} type={r.type} nav={nav} />
                          {r.low_data && <span data-cr-md-low=""><CrBadge tone="warning" dot={false} title={t('crMdLowTitle')}>{t('crMdLow')}</CrBadge></span>}
                      </span>
                  ) },
                { key: 'vmid', label: 'ID', width: 70, mono: true, hidden: narrow, sortValue: r => Number(r.vmid) || null },
                { key: 'node', label: t('crMdHost'), width: 150, sortValue: r => r.node || null,
                  render: r => {
                      const more = Object.keys(r.by_node || {}).length;
                      return (
                          <span className="cr-md-nowrap">
                              {r.node ? <CrMdNode cid={cid} name={r.node} nav={nav} />
                                  : <span className="cr-nc-missing" data-cr-power-nohost="" title={t('powerNoHost')}>{t('crMdNoHost')}</span>}
                              {more > 1 && <span className="cr-muted" data-cr-power-moved="" title={`${t('powerMigrated')}: ${Object.entries(r.by_node).map(([n, k]) => `${n} ${k} kWh`).join(', ')}`}>+{more - 1}</span>}
                              {r.node_estimated && r.node && <span data-cr-power-guessed=""><CrBadge tone="neutral" dot={false} title={t('powerNodeGuessed')}>{t('crMdGuessed')}</CrBadge></span>}
                          </span>
                      );
                  } },
                { key: 'cpu', label: t('crMdAvgCpu'), width: 96, hidden: narrow, sortValue: r => r.avg_cpu_pct, render: r => <CrMeter value={crMdNum(r.avg_cpu_pct) ? r.avg_cpu_pct : null} digits={1} /> },
                { key: 'mem', label: t('crMdAvgMem'), width: 110, sortValue: r => r.avg_mem_pct,
                  render: r => (
                      <span className="cr-md-nowrap">
                          <CrMeter value={crMdNum(r.avg_mem_pct) ? r.avg_mem_pct : null} digits={1} />
                          {r.avg_mem_pct > 100 && <span data-cr-power-memover="" title={t('powerMemOverAssigned')}><Icons.Info className="w-3 h-3" /></span>}
                      </span>
                  ) },
                { key: 'run', label: t('powerHoursRunning'), width: 90, hidden: true, align: 'right', mono: true, sortValue: r => r.running_h, render: r => crMdFix(r.running_h, 1) ?? '-' },
                { key: 'kwh', label: crFill(t('crMdKwhWindow'), { d: days }), width: 104, hidden: true, align: 'right', mono: true, sortValue: r => r.kwh, render: r => kwh(r.kwh) },
                { key: 'mkwh', label: t('powerMonthlyKwh'), width: 110, align: 'right', mono: true, sortValue: r => r.monthly_kwh, render: r => kwh(r.monthly_kwh) },
                { key: 'mcost', label: t('powerMonthlyCost'), width: 110, align: 'right', mono: true, sortValue: r => r.monthly_cost, render: r => <span className="cr-strong">{money(r.monthly_cost)}</span> },
                { key: 'mco2', label: t('powerMonthlyCo2'), width: 104, hidden: narrow, align: 'right', mono: true, sortValue: r => r.monthly_co2, render: r => co2(r.monthly_co2) },
            ], [t, cid, nav, cur, days, narrow]);
            const r = summary && summary.rates;
            return (
                <div className="cr-ins cr-md" data-cr-power={state} ref={rootRef}>
                    <CrPageHeader icon={<Icons.Zap />} title={t('powerTitle')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <CrMdDays id="power" value={days} options={[1, 7, 30]} onChange={onDays} />
                                {canAct && <CrButton icon={<Icons.Settings />} onClick={onRates} data-cr-power-rates="">{t('powerRates')}</CrButton>}
                                {canAct && <CrButton icon={<Icons.Server />} onClick={onHosts} data-cr-power-hosts="">{t('powerHostProfiles')}</CrButton>}
                                <CrButton icon={<Icons.Download />} onClick={onCsv} disabled={!(rows && rows.length)} data-cr-power-csv="">CSV</CrButton>
                                <CrButton icon={<Icons.Download />} onClick={onPdf} disabled={!summary || !summary.enough_data} data-cr-power-pdf="">PDF</CrButton>
                                <CrButton icon={loading ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={onRefresh} disabled={loading} data-cr-power-refresh="">{t('refresh')}</CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crMdPowerIntro')} <CrMdStamp report={summary} /></p>
                    {state === 'stale' && <CrRpNote tone="warning" id="power-stale" onRetry={onRefresh}>{crFill(t('crMdStaleShort'), { why: crMdWhy(readErr, t) })}</CrRpNote>}
                    <CrMdReadState id="power" state={state} readErr={readErr} onRetry={onRefresh} noData={t('powerNoData')} />
                    {ok && (
                        <>
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-power-tiles="">
                                <CrRpStat id="kwh" label={t('powerMonthlyKwh')} value={kwh(mo.kwh)} sub={crFill(t('crMdWindowKwh'), { d: summary.days, v: kwh(summary.window && summary.window.kwh) })} />
                                <CrRpStat id="cost" label={t('powerMonthlyCost')} value={money(mo.cost)} />
                                <CrRpStat id="co2" label={t('powerMonthlyCo2')} value={co2(mo.kg_co2)} />
                                <CrRpStat id="guests" label={t('powerVmCount')} value={crMdFix(summary.vm_count) ?? '-'} sub={low ? crFill(t('crMdNLow'), { n: low }) : ''} />
                                <CrRpStat id="coverage" label={t('crMdCoverage')} value={covPct != null ? crMdFix(covPct, 0) : t('crNsNotReported')} unit={covPct != null ? '%' : undefined}
                                    meter={covPct} tone={cov.missing_h > 0 ? 'warning' : undefined}
                                    sub={crMdNum(cov.covered_h) ? crFill(t('crMdCoverageSub'), { c: crMdFix(cov.covered_h, 0), w: crMdFix(cov.window_h, 0) }) : ''} />
                            </section>
                            {r && (
                                <p className="cr-sb-fine" data-cr-power-basis="">
                                    {crFill(t('crMdPowerRates'), { idle: crMdFix(r.node_idle_w), max: crMdFix(r.node_max_w), mem: crMdFix(r.mem_w_per_gb, 2),
                                        pue: crMdFix(r.pue, 2), price: crMdFix(r.kwh_price, 2), co2: crMdFix(r.kg_co2_per_kwh, 2), cur })}
                                </p>
                            )}
                            {(summary.unallocated || cov.missing_h > 0 || cov.node_estimated_vms > 0 || summary.scoped) && (
                                <div className="cr-md-notes" data-cr-power-notes="">
                                    {summary.unallocated && (
                                        <CrRpNote tone="info" id="power-split">
                                            <span title={t('powerUnallocatedHint')}>{crFill(t('crMdPowerSplit'), {
                                                g: `${kwh(summary.allocated && summary.allocated.monthly && summary.allocated.monthly.kwh)} · ${money(summary.allocated && summary.allocated.monthly && summary.allocated.monthly.cost)}`,
                                                u: `${kwh(summary.unallocated.monthly && summary.unallocated.monthly.kwh)} · ${money(summary.unallocated.monthly && summary.unallocated.monthly.cost)}` })}</span>
                                        </CrRpNote>
                                    )}
                                    {cov.missing_h > 0 && <CrRpNote tone="warning" id="power-coverage">{crFill(t('powerCoverage'), { covered: cov.covered_h ?? 0, window: cov.window_h ?? 0 })}</CrRpNote>}
                                    {cov.node_estimated_vms > 0 && <CrRpNote tone="info" id="power-estimated">{crFill(t('powerNodeEstimated'), { count: cov.node_estimated_vms })}</CrRpNote>}
                                    {summary.scoped && <CrRpNote tone="info" id="power-scoped">{t('powerScopedNote')}</CrRpNote>}
                                </div>
                            )}
                            {hosts.length > 0 ? (
                                <CrPanel title={t('powerPerHost')} className="cr-ins-panel" data-cr-power-hosttable="">
                                    <CrTable id="power-hosts" columns={hostCols} rows={hosts} rowKey={h => h.node} ariaLabel={t('powerPerHost')} showCount={false}
                                        initialSort={{ key: 'kwh', dir: 'desc' }} emptyText={t('crMdNoNodes')} />
                                </CrPanel>
                            ) : byNode.length > 0 ? (
                                <CrPanel title={t('powerByNode')} className="cr-ins-panel" data-cr-power-nodetable="">
                                    <CrTable id="power-nodes" columns={nodeCols} rows={byNode} rowKey={x => x.node} ariaLabel={t('powerByNode')} showCount={false}
                                        initialSort={{ key: 'kwh', dir: 'desc' }} emptyText={t('crMdNoNodes')} columnMenu={false} />
                                </CrPanel>
                            ) : null}
                            <CrPanel title={t('crMdPerGuest')} className="cr-ins-panel" data-cr-power-guests="">
                                <CrTable id="power-guests" columns={cols} rows={rows || []} rowKey={x => String(x.vmid)} ariaLabel={t('crMdPerGuest')}
                                    searchable initialSort={{ key: 'mkwh', dir: 'desc' }} emptyText={t('noVmsFound')} maxHeight={560} />
                            </CrPanel>
                        </>
                    )}
                    {showRates && rateForm && (
                        <CrMdRatesDialog id="power" title={t('powerRatesTitle')} form={rateForm} setForm={setRateForm} saving={savingRates}
                            onCancel={onCloseRates} onSave={onSaveRates} currencies={['EUR', 'USD', 'GBP', 'CHF']}
                            note={<CrMdRateNote form={rateForm} cid={cid} />} hint={t('powerRatesHint')}
                            fields={[
                                { k: 'node_idle_w', label: t('powerNodeIdleW'), step: '1' },
                                { k: 'node_max_w', label: t('powerNodeMaxW'), step: '1' },
                                { k: 'mem_w_per_gb', label: t('powerMemWPerGb'), step: '0.1' },
                                { k: 'pue', label: t('powerPue'), step: '0.05' },
                                { k: 'kwh_price', label: t('powerKwhPrice'), step: '0.01' },
                                { k: 'kg_co2_per_kwh', label: t('powerCo2PerKwh'), step: '0.01' },
                            ]} />
                    )}
                    {hostForm && <CrPowerHostsDialog hosts={hostForm} setHost={setHost} saving={savingHosts} onCancel={onCloseHosts} onSave={onSaveHosts} />}
                </div>
            );
        }

        // --- Network Topology (the Reports tab) ----------------------------------------------------

        // the graph of GET .../topology as nodes with their interfaces, the SDN VNets, and the
        // guests on each; a guest without an 'attached' link is listed apart
        function crNetModel(graph) {
            if (!graph || !Array.isArray(graph.nodes)) return null;
            const items = graph.nodes.filter(n => n && n.id);
            const links = Array.isArray(graph.links) ? graph.links : [];
            const byId = new Map(items.map(n => [n.id, n]));
            const guests = items.filter(n => n.kind === 'vm' || n.kind === 'ct');
            const on = new Map();
            links.forEach(l => {
                if (l.kind !== 'attached' || !byId.has(l.source) || !byId.has(l.target)) return;
                if (!on.has(l.target)) on.set(l.target, []);
                if (!on.get(l.target).includes(byId.get(l.source))) on.get(l.target).push(byId.get(l.source));
            });
            const linked = new Set();
            on.forEach(list => list.forEach(g => linked.add(g.id)));
            const iface = (n) => {
                const list = on.get(n.id) || [];
                const m = n.meta || {};
                return { id: n.id, kind: n.kind, name: n.label || n.id, node: n.kind === 'sdn_vnet' ? '' : String(n.parent_id || '').replace(/^node:/, ''),
                         address: m.address || '', ports: m.ports || '', vlan: !!m.vlan_aware, type: m.type || '', zone: m.zone || '', tag: m.tag ?? null,
                         alias: m.alias || '', guests: list, vms: list.filter(g => g.kind === 'vm').length, cts: list.filter(g => g.kind === 'ct').length,
                         running: list.filter(g => g.meta && g.meta.status === 'running').length };
            };
            const ifaces = items.filter(n => n.kind === 'bridge' || n.kind === 'bond').map(iface);
            const vnets = items.filter(n => n.kind === 'sdn_vnet').map(iface);
            const nodes = items.filter(n => n.kind === 'node').map(n => ({
                id: n.id, name: n.label, meta: n.meta || {}, ifaces: ifaces.filter(i => `node:${i.node}` === n.id),
                guests: guests.filter(g => g.parent_id === n.id).length,
            }));
            const c = graph.counts || {};
            return {
                nodes, ifaces, vnets, all: [...ifaces, ...vnets], orphans: guests.filter(g => !linked.has(g.id)),
                count: { nodes: crMdNum(c.nodes) ? c.nodes : nodes.length, online: nodes.filter(n => n.meta.status === 'online').length,
                         bridges: ifaces.filter(i => i.kind === 'bridge').length, bonds: ifaces.filter(i => i.kind === 'bond').length,
                         vnets: vnets.length, vms: crMdNum(c.vms) ? c.vms : guests.filter(g => g.kind === 'vm').length,
                         cts: crMdNum(c.cts) ? c.cts : guests.filter(g => g.kind === 'ct').length },
            };
        }

        function CrNetChip({ i, selected, onPick }) {
            const { t } = useTranslation();
            const n = i.guests.length;
            return (
                <button type="button" className={`cr-md-chip cr-md-chip-${i.kind}${selected ? ' cr-md-chip-on' : ''}`} aria-pressed={selected}
                    data-cr-net-chip={i.id} onClick={() => onPick(selected ? null : i.id)}
                    title={[i.name, i.address, i.ports && `${t('crNetPorts')}: ${i.ports}`].filter(Boolean).join(' · ')}>
                    <span className="cr-md-chip-kind">{i.kind === 'bond' ? t('crNetBond') : i.kind === 'sdn_vnet' ? 'VNet' : t('crNetBridge')}</span>
                    <span className="cr-mono cr-md-chip-name">{i.name}</span>
                    {i.vlan && <span className="cr-md-chip-tag">VLAN</span>}
                    {i.kind === 'sdn_vnet' && i.tag != null && <span className="cr-md-chip-tag">{`tag ${i.tag}`}</span>}
                    <span className={`cr-md-chip-n${n ? '' : ' cr-muted'}`}>{n}</span>
                </button>
            );
        }

        function CrNetDetail({ i, cid, nav, onClose }) {
            const { t } = useTranslation();
            const kind = i.kind === 'bond' ? t('crNetBond') : i.kind === 'sdn_vnet' ? t('crNetVnet') : t('crNetBridge');
            return (
                <CrNcSection id="net-detail" data-cr-net-detail={i.id} title={`${i.name}${i.node ? ` · ${i.node}` : ''}`} badge={<CrBadge tone="info" dot={false}>{kind}</CrBadge>}
                    actions={<CrButton variant="ghost" icon={<Icons.X />} onClick={onClose} data-cr-net-close="">{t('close')}</CrButton>}>
                    <CrNcKv id="net-detail" rows={i.kind === 'sdn_vnet' ? [
                        { k: 'zone', label: t('crNetZone'), value: i.zone },
                        { k: 'tag', label: t('crNetTag'), value: i.tag != null ? String(i.tag) : '' },
                        { k: 'alias', label: t('crNetAlias'), value: i.alias },
                    ] : [
                        { k: 'node', label: t('node'), value: i.node },
                        { k: 'type', label: t('type'), value: i.type, mono: true },
                        { k: 'address', label: t('crNetAddress'), value: i.address, mono: true, missing: t('crNetNoAddress') },
                        { k: 'ports', label: i.kind === 'bond' ? t('crNetSlaves') : t('crNetPorts'), value: i.ports, mono: true, missing: t('crNetNoPorts') },
                        { k: 'vlan', label: t('crNetVlanAware'), value: i.kind === 'bridge' ? (i.vlan ? t('yes') : t('no')) : '' },
                    ]} />
                    <h4 className="cr-nn-sub">{crFill(t('crNetGuestsOn'), { n: i.guests.length })}</h4>
                    {i.guests.length === 0 ? <p className="cr-sb-fine">{t('crNetNoGuests')}</p> : (
                        <ul className="cr-md-guests" data-cr-net-guests={i.id}>
                            {i.guests.map(g => (
                                <li key={g.id}>
                                    <CrStateBadge state={g.meta && g.meta.status} />
                                    <CrMdGuest cid={cid} vmid={g.meta && g.meta.vmid} name={g.label} type={g.kind === 'ct' ? 'lxc' : 'qemu'} nav={nav} />
                                    <span className="cr-muted cr-mono">{g.meta && g.meta.vmid}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </CrNcSection>
            );
        }

        function CrNetTopo({ cluster, graph, loading, readErr, onRefresh, nav }) {
            const { t } = useTranslation();
            const cid = cluster && cluster.id;
            const seen = useCrMdSeen(loading);
            const m = useMemo(() => crNetModel(graph), [graph]);
            const [pick, setPick] = useState(null);
            const [showOrphans, setShowOrphans] = useState(false);
            const rootRef = useRef(null);
            const narrow = crRpNarrow(rootRef, 940);
            useEffect(() => { setPick(null); }, [cid]);
            const state = m && !readErr ? 'ok' : m ? 'stale' : loading || !seen ? 'loading' : 'error';
            const picked = m && pick ? m.all.find(i => i.id === pick) : null;
            const columns = useMemo(() => [
                { key: 'name', label: t('crNetIface'), width: 120, mono: true, sortValue: i => i.name,
                  render: i => <span data-cr-net-row={i.id}>{i.name}</span> },
                { key: 'node', label: t('node'), width: 110, sortValue: i => i.node || null, render: i => (i.node ? <CrMdNode cid={cid} name={i.node} nav={nav} /> : <span className="cr-muted">{t('crNetClusterWide')}</span>) },
                { key: 'kind', label: t('type'), width: 84, hidden: narrow, sortValue: i => i.kind,
                  render: i => <CrBadge tone="neutral" dot={false}>{i.kind === 'bond' ? t('crNetBond') : i.kind === 'sdn_vnet' ? 'VNet' : t('crNetBridge')}</CrBadge> },
                { key: 'address', label: t('crNetAddress'), width: 128, mono: true, sortValue: i => i.address || null, render: i => i.address || <span className="cr-muted">-</span> },
                { key: 'ports', label: t('crNetPorts'), flex: true, min: 100, mono: true, sortValue: i => i.ports || null,
                  render: i => (i.kind === 'sdn_vnet' ? <span className="cr-muted">{[i.zone && `${t('crNetZone')} ${i.zone}`, i.tag != null && `tag ${i.tag}`].filter(Boolean).join(' · ') || '-'}</span> : i.ports || <span className="cr-muted">-</span>) },
                { key: 'vlan', label: 'VLAN', width: 70, hidden: narrow, sortValue: i => (i.kind === 'bridge' ? (i.vlan ? 1 : 0) : null),
                  render: i => (i.kind !== 'bridge' ? <span className="cr-muted">-</span> : i.vlan ? <CrBadge tone="info" dot={false}>{t('crNetAware')}</CrBadge> : <span className="cr-muted">{t('no')}</span>) },
                { key: 'guests', label: t('crNetGuests'), width: 136, align: 'right', sortValue: i => i.guests.length,
                  render: i => <span className="cr-mono" data-cr-net-n={i.guests.length} title={crFill(t('crNetVmCt'), { vm: i.vms, ct: i.cts })}>{crFill(t('crNetGuestsCell'), { n: i.guests.length, run: i.running })}</span> },
            ], [t, cid, nav, narrow]);
            return (
                <div className="cr-ins cr-md" data-cr-net={state} ref={rootRef}>
                    <CrPageHeader icon={<Icons.Network />} title={t('topologyTitle')} sub={clusterLabel(cluster)}
                        actions={<CrButton icon={loading ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={onRefresh} disabled={loading} data-cr-net-refresh="">{t('refresh')}</CrButton>} />
                    <p className="cr-cmp-hint">{t('crNetIntro')}</p>
                    {state === 'loading' && <CrNcState id="net" kind="loading" />}
                    {state === 'error' && <CrNcState id="net" kind="error" onRetry={onRefresh}>{crFill(t('crMdReadFailed'), { why: crMdWhy(readErr, t) })}</CrNcState>}
                    {state === 'stale' && <CrRpNote tone="warning" id="net-stale" onRetry={onRefresh}>{crFill(t('crMdStaleShort'), { why: crMdWhy(readErr, t) })}</CrRpNote>}
                    {m && (
                        <>
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-net-tiles="">
                                <CrRpStat id="nodes" label={t('nodes')} value={String(m.count.nodes)} sub={crFill(t('crNetOnline'), { n: m.count.online })} />
                                <CrRpStat id="bridges" label={t('crNetBridges')} value={String(m.count.bridges)} />
                                <CrRpStat id="bonds" label={t('crNetBonds')} value={String(m.count.bonds)} />
                                <CrRpStat id="vnets" label={t('crNetVnets')} value={String(m.count.vnets)} />
                                <CrRpStat id="guests" label={t('crNetGuests')} value={String(m.count.vms + m.count.cts)} sub={crFill(t('crNetVmCt'), { vm: m.count.vms, ct: m.count.cts })} />
                                <CrRpStat id="orphans" label={t('crNetUnlinked')} value={String(m.orphans.length)} tone={m.orphans.length ? 'warning' : undefined} sub={t('crNetUnlinkedSub')} />
                            </section>
                            <CrPanel title={t('crNetMap')} className="cr-ins-panel" data-cr-net-map="">
                                {m.nodes.length === 0 && m.vnets.length === 0 ? <p className="cr-sb-fine">{t('crNetEmpty')}</p> : (
                                    <div className="cr-md-map" role="list">
                                        {m.nodes.map(n => (
                                            <div key={n.id} className="cr-md-lane" role="listitem" data-cr-net-lane={n.name}>
                                                <div className="cr-md-lane-head">
                                                    <CrMdNode cid={cid} name={n.name} nav={nav} />
                                                    <CrBadge tone={n.meta.status === 'online' ? 'success' : n.meta.status === 'offline' ? 'error' : 'neutral'} dot>{n.meta.status || t('crNsNotReported')}</CrBadge>
                                                    <span className="cr-muted cr-md-lane-sub">{crFill(t('crNetLaneSub'), { cpu: crMdFix(n.meta.cpu_pct, 0) ?? '-', mem: crMdFix(n.meta.mem_pct, 0) ?? '-', g: n.guests })}</span>
                                                </div>
                                                <div className="cr-md-chips">
                                                    {n.ifaces.length === 0 ? <span className="cr-sb-fine">{t('crNetNoIfaces')}</span>
                                                        : n.ifaces.map(i => <CrNetChip key={i.id} i={i} selected={pick === i.id} onPick={setPick} />)}
                                                </div>
                                            </div>
                                        ))}
                                        {m.vnets.length > 0 && (
                                            <div className="cr-md-lane" role="listitem" data-cr-net-lane="sdn">
                                                <div className="cr-md-lane-head"><span className="cr-strong">{t('crNetVnets')}</span><span className="cr-muted cr-md-lane-sub">{t('crNetClusterWide')}</span></div>
                                                <div className="cr-md-chips">{m.vnets.map(i => <CrNetChip key={i.id} i={i} selected={pick === i.id} onPick={setPick} />)}</div>
                                            </div>
                                        )}
                                    </div>
                                )}
                                <p className="cr-rp-caption">{t('crNetMapHint')}</p>
                            </CrPanel>
                            {picked && <CrNetDetail i={picked} cid={cid} nav={nav} onClose={() => setPick(null)} />}
                            <CrPanel title={t('crNetIfaces')} className="cr-ins-panel" data-cr-net-ifaces="">
                                <CrTable id="net-ifaces" columns={columns} rows={m.all} rowKey={i => i.id} ariaLabel={t('crNetIfaces')} selectedKey={pick}
                                    onRowClick={i => setPick(p => (p === i.id ? null : i.id))} searchable={m.all.length > 12} initialSort={{ key: 'node', dir: 'asc' }}
                                    emptyText={t('crNetEmpty')} maxHeight={520} />
                            </CrPanel>
                            {m.orphans.length > 0 && (
                                <CrNcSection id="net-orphans" data-cr-net-orphans={m.orphans.length} title={crFill(t('crNetUnlinkedTitle'), { n: m.orphans.length })} desc={t('crNetUnlinkedDesc')}
                                    actions={<CrButton variant="ghost" onClick={() => setShowOrphans(v => !v)} aria-expanded={showOrphans} data-cr-net-orphans-toggle="">{showOrphans ? t('crNetHide') : t('crNetShow')}</CrButton>}>
                                    {showOrphans && (
                                        <ul className="cr-md-guests">
                                            {m.orphans.map(g => (
                                                <li key={g.id} data-cr-net-orphan={g.meta && g.meta.vmid}>
                                                    <CrStateBadge state={g.meta && g.meta.status} />
                                                    <CrMdGuest cid={cid} vmid={g.meta && g.meta.vmid} name={g.label} type={g.kind === 'ct' ? 'lxc' : 'qemu'} nav={nav} />
                                                    <span className="cr-muted cr-mono">{g.meta && g.meta.vmid}</span>
                                                    <span className="cr-muted">{String(g.parent_id || '').replace(/^node:/, '')}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </CrNcSection>
                            )}
                        </>
                    )}
                </div>
            );
        }

        // --- Resources > Snapshot overview ----------------------------------------------
        // The oldest snapshots of the cluster as POST /snapshots/overview lists them (the server reads
        // every guest's list, keeps the oldest 200). The dashboard holds the list, its read, the date
        // filter, the selection and the two deletes (POST /snapshots/delete with their confirm); this
        // only draws them. Age is counted from snapshot_ts, so "5 h" sorts before "3 days".
        const CR_SNAP_LIMIT = 200;    // vms.snapshots_overview filter_limit default

        function crSnapModel(rows, nowMs) {
            const list = Array.isArray(rows) ? rows.filter(s => s && typeof s === 'object') : [];
            const ts = list.map(s => s.snapshot_ts).filter(crMdNum);
            const oldest = list.reduce((o, s) => (crMdNum(s.snapshot_ts) && (!o || s.snapshot_ts < o.snapshot_ts) ? s : o), null);
            return {
                list,
                guests: new Set(list.map(s => `${s.vm_type}:${s.vmid}`)).size,
                nodes: new Set(list.map(s => s.node).filter(Boolean)).size,
                oldest,
                oldestAge: oldest ? Math.max(0, Math.round(nowMs / 1000 - oldest.snapshot_ts)) : null,
                cut: list.length >= CR_SNAP_LIMIT,
                undated: list.length - ts.length,
            };
        }

        function CrSnapOverview({ cluster, rows, loading, readErr, filterDate, onFilterDate, onFilter, onRefresh, canDelete, selected, onSelect,
                                  keyOf, onDelete, onDeleteSelected, nav }) {
            const { t } = useTranslation();
            const cid = cluster.id;
            const now = Date.now();
            const m = useMemo(() => crSnapModel(rows, now), [rows, Math.floor(now / 60000)]);
            const sel = selected || {};
            // the date of the last Filter: Refresh reads every snapshot again (the classic request has no date)
            // and so empties the field, the deletes read again with what the field holds
            const [applied, setApplied] = useState('');
            const filter = () => { setApplied(filterDate || ''); onFilter(); };
            const refresh = () => { setApplied(''); onFilterDate(''); onRefresh(); };
            const nSel = m.list.filter(s => sel[keyOf(s)]).length;
            const toggle = (s) => onSelect(p => { const n = { ...p }; if (n[keyOf(s)]) delete n[keyOf(s)]; else n[keyOf(s)] = true; return n; });
            const failed = !loading && readErr;
            const state = loading ? 'loading' : failed ? 'error' : m.list.length ? 'ok' : 'empty';
            const ageOf = (s) => (crMdNum(s.snapshot_ts) ? Math.max(0, Math.round(now / 1000 - s.snapshot_ts)) : null);
            const cols = [
                canDelete && { key: 'sel', label: t('crSnapSel'), width: 64, text: s => (sel[keyOf(s)] ? '1' : ''),
                  render: s => (
                      <input type="checkbox" className="cr-snap-check" checked={!!sel[keyOf(s)]} aria-label={crFill(t('crSnapSelOne'), { name: s.snapshot_name })}
                          onClick={e => e.stopPropagation()} onChange={() => toggle(s)} data-cr-snap-sel={keyOf(s)} />
                  ) },
                { key: 'guest', label: t('crSnapGuest'), flex: true, min: 150, text: s => `${s.vm_name || ''} ${s.vmid}`,
                  render: s => <span className="cr-snap-guest"><CrMdGuest cid={cid} vmid={s.vmid} name={s.vm_name} type={s.vm_type} nav={nav} /><span className="cr-muted cr-mono">{s.vmid}</span></span> },
                { key: 'type', label: t('type'), width: 64, text: s => (s.vm_type === 'lxc' ? 'CT' : 'VM'),
                  render: s => <CrBadge tone="neutral" dot={false}>{s.vm_type === 'lxc' ? 'CT' : 'VM'}</CrBadge> },
                { key: 'node', label: t('node'), width: 110, text: s => s.node || '', render: s => <CrMdNode cid={cid} name={s.node} nav={nav} /> },
                { key: 'name', label: t('crSnapName'), width: 180, mono: true, text: s => s.snapshot_name || '',
                  render: s => <span data-cr-snap-name="">{s.snapshot_name || <CrNcMissing />}</span> },
                { key: 'created', label: t('crSnapCreated'), width: 168, sortValue: s => (crMdNum(s.snapshot_ts) ? s.snapshot_ts : null),
                  text: s => (crMdNum(s.snapshot_ts) ? crFmtDate(s.snapshot_ts) : s.snapshot_date || ''),
                  render: s => (crMdNum(s.snapshot_ts) ? crFmtDate(s.snapshot_ts) : s.snapshot_date || <CrNcMissing />) },
                { key: 'age', label: t('crSnapAge'), width: 96, align: 'right', sortValue: s => ageOf(s),
                  text: s => (ageOf(s) == null ? s.age || '' : crUpdAge(t, ageOf(s))),
                  render: s => <span data-cr-snap-age={ageOf(s) == null ? '' : ageOf(s)}>{ageOf(s) == null ? (s.age || <CrNcMissing />) : crUpdAge(t, ageOf(s))}</span> },
                canDelete && { key: 'act', label: t('crSnapAction'), width: 86, align: 'right', text: () => '',
                  render: s => (
                      <button type="button" className="cr-btn cr-btn-danger cr-btn-xs" onClick={e => { e.stopPropagation(); onDelete(s); }}
                          title={crFill(t('crSnapDeleteOne'), { name: s.snapshot_name, vmid: s.vmid })} data-cr-snap-del={keyOf(s)}>
                          <span className="cr-ico" aria-hidden="true"><Icons.Trash /></span>{t('delete')}
                      </button>
                  ) },
            ].filter(Boolean);
            return (
                <div className="cr-ins cr-md cr-snap" data-cr-snap={state}>
                    <CrPageHeader icon={<Icons.Camera />} title={t('snapshotsOverview')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <label className="cr-snap-date">
                                    <span className="cr-muted">{t('crSnapBefore')}</span>
                                    <input type="date" className="cr-input" value={filterDate || ''} onChange={e => onFilterDate(e.target.value)} data-cr-snap-date="" />
                                </label>
                                <CrButton icon={<Icons.Filter />} onClick={filter} disabled={!filterDate || loading} data-cr-snap-filter="">{t('filter')}</CrButton>
                                <CrButton icon={loading ? <span className="cr-spinner" /> : <Icons.RotateCw />} onClick={refresh} disabled={loading}
                                    title={t('crSnapRefreshHint')} data-cr-snap-refresh="">{t('crUpdRefresh')}</CrButton>
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crSnapIntro')}</p>
                    {failed && (
                        <div className="cr-callout cr-callout-error" role="alert" data-cr-snap-error="">
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div><p>{crFill(t('crMdReadFailed'), { why: crMdWhy(readErr, t) })}</p>
                                <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={refresh} data-cr-snap-retry="">{t('crSnapRetry')}</button></div>
                        </div>
                    )}
                    {!failed && (
                        <section className="cr-stat-row cr-snap-tiles" aria-label={t('crSummary')} data-cr-snap-tiles="">
                            <CrStat id="snap-count" label={t('crSnapCount')} value={loading ? '-' : m.list.length}
                                sub={loading ? t('crUpdReading') : m.cut ? crFill(t('crSnapCut'), { n: CR_SNAP_LIMIT }) : applied ? crFill(t('crSnapBeforeSub'), { date: applied }) : t('crSnapAllSub')}
                                tone={m.cut ? 'warning' : null} />
                            <CrStat id="snap-guests" label={t('crSnapGuests')} value={loading ? '-' : m.guests} sub={loading ? '' : crFill(t('crSnapNodesSub'), { n: m.nodes })} />
                            <CrStat id="snap-oldest" label={t('crSnapOldest')} value={loading || m.oldestAge == null ? '-' : crUpdAge(t, m.oldestAge)}
                                sub={m.oldest && !loading ? `${m.oldest.vm_name || m.oldest.vmid} · ${m.oldest.snapshot_name}` : ''} />
                        </section>
                    )}
                    {canDelete && nSel > 0 && (
                        <div className="cr-snap-bar" role="status" data-cr-snap-bar="">
                            <span className="cr-strong">{crFill(t('crSnapNSel'), { n: nSel })}</span>
                            <CrButton variant="danger" icon={<Icons.Trash />} onClick={onDeleteSelected} data-cr-snap-del-sel="">{t('crSnapDelSel')}</CrButton>
                            <CrButton onClick={() => onSelect({})} data-cr-snap-sel-clear="">{t('clear')}</CrButton>
                        </div>
                    )}
                    {!failed && (
                        <CrTable id="res-snapshots" columns={cols} rows={m.list} rowKey={keyOf} loading={loading && !m.list.length}
                            ariaLabel={t('snapshotsOverview')} maxHeight={560} searchable={m.list.length > 12} initialSort={{ key: 'created', dir: 'asc' }}
                            onRowClick={canDelete ? toggle : undefined}
                            emptyText={applied ? crFill(t('crSnapNoneBefore'), { date: applied }) : t('crSnapNone')}
                            actions={canDelete && m.list.length > 0 ? (
                                <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" data-cr-snap-sel-all=""
                                    onClick={() => onSelect(() => { const all = {}; m.list.forEach(s => { all[keyOf(s)] = true; }); return all; })}>{t('crSnapSelAll')}</button>
                            ) : null} />
                    )}
                    <p className="cr-sb-fine" data-cr-snap-foot="">{canDelete ? t('crSnapFoot') : t('crSnapFootRead')}</p>
                </div>
            );
        }

        // --- Automation > Affinity rules ------------------------------------------------
        // The rules of the cluster as GET .../affinity-rules lists them (read when the sub tab opens).
        // New Rule opens the classic dialog, Delete is the classic DELETE. LW Nov 2026 - round 10:
        // Delete asks first (the rule, its type and its guests); the DELETE goes only after that.
        // A guest id the cluster does not list is said so; a failed read is an error, not "no rules".
        function CrAffinity({ cluster, rules, readErr, loading, canEdit, onNew, onDelete, onRefresh, nav }) {
            const { t } = useTranslation();
            const cid = cluster.id;
            const list = Array.isArray(rules) ? rules.filter(r => r && typeof r === 'object') : [];
            const guests = nav && nav.guestsOf ? nav.guestsOf(cid) : null;
            const [busy, setBusy] = useState({});
            const [err, setErr] = useState('');
            const [ask, setAsk] = useState(null);   // the rule the confirmation is open for
            const del = async (r) => {
                setBusy(b => ({ ...b, [r.id]: true }));
                setErr('');
                const ok = await onDelete(r.id);
                setBusy(b => ({ ...b, [r.id]: false }));
                setAsk(null);
                if (!ok) setErr(crFill(t('crAffDelFailed'), { name: r.name || r.id }));
            };
            const ids = (r) => (Array.isArray(r.vm_ids) ? r.vm_ids : Array.isArray(r.vms) ? r.vms : []);
            const typeText = (r) => (r.type === 'together' ? t('together') : t('separate'));
            const state = readErr ? 'error' : loading && !list.length ? 'loading' : list.length ? 'ok' : 'empty';
            const cols = [
                { key: 'name', label: t('crAffRule'), flex: true, min: 140, text: r => r.name || r.id,
                  render: r => <span className="cr-strong" data-cr-aff-rule={r.id}>{r.name || r.id}</span> },
                { key: 'type', label: t('type'), width: 196, text: r => (r.type === 'together' ? t('together') : t('separate')),
                  render: r => <span data-cr-aff-type={r.type}><CrBadge tone={r.type === 'together' ? 'info' : 'neutral'} dot={false}>{r.type === 'together' ? t('together') : t('separate')}</CrBadge></span> },
                { key: 'enforce', label: t('crAffEnforce'), width: 104, text: r => (r.enforce ? t('enforced') : ''),
                  render: r => (r.enforce ? <span data-cr-aff-enforced=""><CrBadge tone="warning" dot={false}>{t('enforced')}</CrBadge></span> : <span className="cr-muted">{t('no')}</span>) },
                { key: 'guests', label: t('crAffGuests'), width: 260, text: r => ids(r).join(', '),
                  render: r => (
                      <span className="cr-aff-guests">
                          {ids(r).map(v => (crMdGuestOf(guests, v)
                              ? <CrMdGuest key={v} cid={cid} vmid={v} nav={nav} />
                              : <span key={v} className="cr-upd-warn" title={t('crAffGuestGone')} data-cr-aff-gone={v}>{v}</span>))}
                          {!ids(r).length && <CrNcMissing />}
                      </span>
                  ) },
                { key: 'state', label: t('status'), width: 96, text: r => (r.enabled === false ? t('crAffOff') : t('crAffOn')),
                  render: r => (r.enabled === false ? <CrBadge tone="neutral">{t('crAffOff')}</CrBadge> : <span className="cr-muted">{t('crAffOn')}</span>) },
                { key: 'created', label: t('crSnapCreated'), width: 150, sortValue: r => r.created_at || '',
                  text: r => crUpdStamp(r.created_at), render: r => (r.created_at ? <span className="cr-mono">{crUpdStamp(r.created_at)}</span> : <CrNcMissing />) },
                canEdit && { key: 'act', label: t('crSnapAction'), width: 86, align: 'right', text: () => '',
                  render: r => (
                      <button type="button" className="cr-btn cr-btn-danger cr-btn-xs" disabled={!!busy[r.id]}
                          onClick={e => { e.stopPropagation(); setAsk(r); }} data-cr-aff-del={r.id}>
                          <span className="cr-ico" aria-hidden="true">{busy[r.id] ? <span className="cr-spinner" /> : <Icons.Trash />}</span>{t('delete')}
                      </button>
                  ) },
            ].filter(Boolean);
            return (
                <div className="cr-ins cr-md cr-aff" data-cr-aff={state}>
                    <CrPageHeader icon={<Icons.Link />} title={t('affinityRules')} sub={clusterLabel(cluster)}
                        actions={(
                            <>
                                <CrButton icon={<Icons.RotateCw />} onClick={onRefresh} data-cr-aff-refresh="">{t('crUpdRefresh')}</CrButton>
                                {canEdit && <CrButton variant="primary" icon={<Icons.Plus />} onClick={onNew} data-cr-aff-new="">{t('newRule')}</CrButton>}
                            </>
                        )} />
                    <p className="cr-cmp-hint">{t('crAffIntro')}</p>
                    {readErr && (
                        <div className="cr-callout cr-callout-error" role="alert" data-cr-aff-error="">
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div><p>{crFill(t('crMdReadFailed'), { why: crMdWhy(readErr, t) })}</p>
                                <button type="button" className="cr-btn cr-btn-ghost cr-btn-xs" onClick={onRefresh} data-cr-aff-retry="">{t('crSnapRetry')}</button></div>
                        </div>
                    )}
                    {err && <p className="cr-upd-line cr-upd-bad" role="alert" data-cr-aff-del-error="">{err}</p>}
                    {!readErr && (
                        <CrTable id="auto-affinity" columns={cols} rows={list} rowKey={r => r.id} loading={!!loading && !list.length}
                            ariaLabel={t('affinityRules')} maxHeight={520} searchable={list.length > 12}
                            emptyText={t('noAffinityCluster')} initialSort={{ key: 'name', dir: 'asc' }} />
                    )}
                    <p className="cr-sb-fine" data-cr-aff-foot="">{canEdit ? t('crAffFootAsk') : t('crAffFootRead')}</p>
                    {ask && (
                        <CrNcConfirm id="aff-del" title={crFill(t('crAffDelTitle'), { name: ask.name || ask.id })} goLabel={t('delete')}
                            busyLabel={t('crAffDeleting')} busy={!!busy[ask.id]} onCancel={() => setAsk(null)} onConfirm={() => del(ask)}>
                            <CrNcKv id="aff-del" rows={[
                                { k: 'rule', label: t('crAffRule'), value: ask.name || ask.id },
                                { k: 'type', label: t('type'), value: ask.enforce ? `${typeText(ask)}, ${t('enforced')}` : typeText(ask) },
                                { k: 'guests', label: t('crAffGuests'), value: ids(ask).length ? (
                                    <span className="cr-aff-guests" data-cr-aff-del-guests="">
                                        {ids(ask).map(v => {
                                            const g = crMdGuestOf(guests, v);
                                            return g
                                                ? <span key={v} data-cr-aff-del-guest={v}><span className="cr-strong">{g.name || v}</span> <span className="cr-muted cr-mono">{v}</span></span>
                                                : <span key={v} className="cr-upd-warn" title={t('crAffGuestGone')} data-cr-aff-del-guest={v}>{v}</span>;
                                        })}
                                    </span>
                                ) : '' },
                            ]} />
                            <p data-cr-aff-del-what="">{t(ask.type === 'together' ? 'crAffDelWhatTogether' : 'crAffDelWhatApart')}</p>
                        </CrNcConfirm>
                    )}
                </div>
            );
        }

        window.PegaProxModules = Object.freeze({ cveModel: crCveModel, apiModel: crApiModel, netModel: crNetModel, report: crMdReport,
                                                 rateSource: crMdRateSource, money: crMdMoney, snapModel: crSnapModel });
