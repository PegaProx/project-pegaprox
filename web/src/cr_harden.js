        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned: Automation > Harden PVE Node - LW Nov 2026
        // The three routes of the classic tab with the same request bodies: the check (one
        // node, always verbose so the detail panel has the evidence), the apply (one POST per
        // control, force only for sshd_hardening after the red tick) and the rollback. What
        // it draws differently: a passing check is "Passed", never "Applied"; what an apply or
        // a rollback answered stays for this session until it is dismissed, the check after
        // it does not wipe it; Apply and Rollback each have their own selection and dialog;
        // the preview says what the control declares and "not declared" for the rest.
        // ═══════════════════════════════════════════════════════════

        // the controls whose apply asks for the access tick: the list of the classic tab
        // (HARDEN_ACCESS_CONTROLS in dashboard.js), a test keeps the two in step
        const CR_HD_ACCESS = ['sshd_hardening', 'ssh_perms', 'ssh_crypto', 'pam_faillock'];
        // these can cut someone off as well (blank passwords, session cap, idle accounts, bans)
        const CR_HD_LOGIN = ['pam_nullok_removal', 'session_limit', 'inactive_accounts', 'pve_fail2ban'];
        // the two SSH controls save the same file at their first apply
        const CR_HD_SSH_PAIR = ['ssh_crypto', 'sshd_hardening'];
        const CR_HD_SRC = { cis: 'CIS', lynis: 'Lynis', stig: 'STIG', pega: 'PegaProx', vsnfd: 'VS-NfD' };
        // their apply changes nothing on the node (an alias, or a report only)
        const crHdAuditOnly = (id) => id === 'net_protocols' || String(id).startsWith('vsnfd_');
        const crHdStatus = (v) => {
            const s = v && typeof v === 'object' ? v.status : v;
            return s === true ? true : s === false ? false : null;
        };

        // What this browser knows, outside the tab so a sub tab switch keeps it: the last check
        // per cluster, node and profile, a run in progress and the answers of apply and rollback
        // per cluster and node. A reload forgets all of it, which is what "this session" says.
        const crHd = { reads: {}, runs: {}, outcomes: {}, last: {}, subs: new Set(), seq: 0 };
        // another account starts empty (crSessionFor); a run of the one before stops at its next control
        crSessionStore(() => { crHd.reads = {}; crHd.runs = {}; crHd.outcomes = {}; crHd.last = {}; });
        const crHdKey = (...parts) => parts.map(p => String(p == null ? '' : p)).join('\u0001');
        function crHdEmit() { crHd.subs.forEach(f => { try { f(); } catch (_) {} }); }
        function useCrHd() {
            const { user } = useAuth();
            crSessionFor(user);
            const [, bump] = useState(0);
            useEffect(() => {
                const f = () => bump(n => n + 1);
                crHd.subs.add(f);
                return () => { crHd.subs.delete(f); };
            }, []);
            return crHd;
        }
        async function crHdError(resp) {
            const body = resp ? await resp.json().catch(() => ({})) : {};
            return { status: resp ? resp.status : 0, error: (body && body.error) || '', code: (body && body.code) || '',
                     hint: (body && body.hint) || '' };
        }

        async function crHdCheck(authFetch, cid, node, profile) {
            const key = crHdKey(cid, node, profile);
            const gen = crSession.gen;
            const prev = crHd.reads[key] || {};
            if (prev.loading) return;
            crHd.reads[key] = { ...prev, loading: true };
            crHdEmit();
            const qs = new URLSearchParams({ verbose: 'true' });
            if (profile) qs.set('profile', profile);
            let next;
            try {
                const resp = await authFetch(`${API_URL}/clusters/${cid}/nodes/${encodeURIComponent(node)}/hardening?${qs}`);
                if (resp && resp.ok) {
                    const data = await resp.json().catch(() => null);
                    next = data && data.controls && typeof data.controls === 'object'
                        ? { data, at: Date.now(), error: null }
                        : { ...prev, error: { status: resp.status, error: '', code: 'SHAPE' } };
                } else {
                    next = { ...prev, error: await crHdError(resp) };
                }
            } catch (e) {
                next = { ...prev, error: { status: 0, error: String((e && e.message) || e), code: '' } };
            }
            if (gen !== crSession.gen) return;
            crHd.reads[key] = { ...next, loading: false };
            crHdEmit();
        }

        function crHdNote(rk, id, kind, error) {
            const out = crHd.outcomes[rk] || (crHd.outcomes[rk] = {});
            // seq orders the answers; two can carry the same clock time
            out[id] = { kind, error: error ? String(error) : '', at: Date.now(), seq: ++crHd.seq };
        }

        // one control after the other, as classic does: the request body is the classic one
        async function crHdApply({ authFetch, cid, node, profile, params }, ids, force) {
            const rk = crHdKey(cid, node);
            if (crHd.runs[rk]) return;
            const gen = crSession.gen;
            const run = { mode: 'apply', ids: ids.slice(), current: null, done: [], started: Date.now() };
            crHd.runs[rk] = run;
            crHdEmit();
            let ok = 0;
            for (const id of ids) {
                if (gen !== crSession.gen) return;
                run.current = id;
                crHdEmit();
                let r;
                try {
                    const resp = await authFetch(`${API_URL}/clusters/${cid}/nodes/${encodeURIComponent(node)}/hardening`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            controls: [id],
                            params: params && params[id] ? { [id]: params[id] } : {},
                            ...(id === 'sshd_hardening' && force ? { force: true } : {}),
                        }),
                    });
                    if (resp && resp.ok) {
                        const data = await resp.json().catch(() => null);
                        r = (data && data.results && data.results[id]) || { success: false, error: 'no result' };
                    } else {
                        const e = await crHdError(resp);
                        r = { success: false, error: e.error || `HTTP ${e.status || '-'}` };
                    }
                } catch (e) {
                    r = { success: false, error: String((e && e.message) || e) };
                }
                if (gen !== crSession.gen) return;
                if (r.success) ok++;
                crHdNote(rk, id, r.success ? 'applied' : r.blocked ? 'blocked' : 'apply-failed', r.success ? '' : r.error);
                run.done.push(id);
                crHdEmit();
            }
            delete crHd.runs[rk];
            crHd.last[rk] = { mode: 'apply', ok, total: ids.length, at: Date.now() };
            crHdEmit();
            await crHdCheck(authFetch, cid, node, profile);
        }

        // one POST with the list in the order given, as classic sends it
        async function crHdRollback({ authFetch, cid, node, profile }, ids) {
            const rk = crHdKey(cid, node);
            if (crHd.runs[rk]) return;
            const gen = crSession.gen;
            crHd.runs[rk] = { mode: 'rollback', ids: ids.slice(), current: null, done: [], started: Date.now() };
            crHdEmit();
            let ok = 0;
            try {
                const resp = await authFetch(`${API_URL}/clusters/${cid}/nodes/${encodeURIComponent(node)}/hardening/rollback`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ controls: ids }),
                });
                if (gen !== crSession.gen) return;
                if (resp && resp.ok) {
                    const data = await resp.json().catch(() => null);
                    const results = (data && data.results) || {};
                    ids.forEach(id => {
                        const r = results[id] || { success: false, error: 'no result' };
                        if (r.success) ok++;
                        crHdNote(rk, id, r.success ? 'rolled-back' : 'rollback-failed', r.success ? '' : r.error);
                    });
                } else {
                    const e = await crHdError(resp);
                    ids.forEach(id => crHdNote(rk, id, 'rollback-failed', e.error || `HTTP ${e.status || '-'}`));
                }
            } catch (e) {
                if (gen !== crSession.gen) return;
                ids.forEach(id => crHdNote(rk, id, 'rollback-failed', String((e && e.message) || e)));
            }
            delete crHd.runs[rk];
            crHd.last[rk] = { mode: 'rollback', ok, total: ids.length, at: Date.now() };
            crHdEmit();
            await crHdCheck(authFetch, cid, node, profile);
        }

        // the text of a failed check: the SSH reasons of the server, a 403 as such
        function crHdReadError(t, e) {
            if (!e) return null;
            const ssh = { SSH_NO_CREDENTIALS: ['sshNoCredentials', 'sshNoCredentialsHint'], NODE_BACKOFF: ['sshNodeBackoff', 'sshNodeBackoffHint'],
                          SSH_FAILED: ['sshFailed', 'sshFailedHint'] }[e.code];
            if (ssh) return { title: t(ssh[0]), text: crDash(e.error), hint: t(ssh[1]), kind: 'ssh' };
            if (e.code === 'SHAPE') return { title: t('crHdErrShape'), text: '', hint: '', kind: 'error' };
            if (e.status === 403) return { title: t('crHdErr403'), text: crDash(e.error), hint: '', kind: 'denied' };
            if (e.status === 503) return { title: t('crHdErr503'), text: crDash(e.error), hint: crDash(e.hint), kind: 'offline' };
            if (e.status === 412 || e.status === 502) return { title: t('crHdErrSsh'), text: crDash(e.error), hint: crDash(e.hint), kind: 'ssh' };
            return { title: t('crHdErrOther'), text: crDash(e.error) || (e.status ? `HTTP ${e.status}` : t('crHdErrNoAnswer')), hint: crDash(e.hint), kind: 'error' };
        }

        const CR_HD_OUT = {
            applied: { tone: 'info', key: 'crHdOutApplied' },
            'apply-failed': { tone: 'error', key: 'crHdOutApplyFailed' },
            blocked: { tone: 'warning', key: 'crHdOutBlocked' },
            'rolled-back': { tone: 'info', key: 'crHdOutRolledBack' },
            'rollback-failed': { tone: 'error', key: 'crHdOutRollbackFailed' },
        };

        function CrHdCheckBadge({ st, pending, t }) {
            if (pending === 'running') return <CrBadge tone="info">{t('crHdRunning')}</CrBadge>;
            if (pending === 'queued') return <CrBadge tone="neutral" dot={false}>{t('queued')}</CrBadge>;
            if (st === true) return <CrBadge tone="success">{t('passed')}</CrBadge>;
            if (st === false) return <CrBadge tone="error">{t('failed')}</CrBadge>;
            return <CrBadge tone="neutral" title={t('hardenNotCheckedHint')}>{t('hardenNotCheckedBadge')}</CrBadge>;
        }

        function CrHdOutBadge({ out, t }) {
            if (!out) return null;
            const o = CR_HD_OUT[out.kind];
            if (!o) return null;
            return <CrBadge tone={o.tone} title={`${crFmtTime(out.at)}${out.error ? ` - ${crDash(out.error)}` : ''}`}>{t(o.key)}</CrBadge>;
        }

        // the flags a control declares; nothing here is read from the node
        function crHdFlags(id, info, rollback) {
            return {
                audit: crHdAuditOnly(id),
                access: CR_HD_ACCESS.includes(id),
                login: CR_HD_LOGIN.includes(id),
                reboot: !!(info && info.reboot),
                rollback: rollback == null ? null : rollback.has(id),
            };
        }

        function CrHdFlagChips({ f, t }) {
            return (
                <span className="cr-hd-flags">
                    {f.audit && <span data-cr-hd-flag="audit"><CrBadge tone="neutral" dot={false} title={t('crHdAuditOnlyHint')}>{t('crHdAuditOnly')}</CrBadge></span>}
                    {(f.access || f.login) && <span data-cr-hd-flag={f.access ? 'access' : 'login'}><CrBadge tone="warning" dot={false} title={t(f.access ? 'crHdAccessHint' : 'crHdLoginHint')}>{t('crHdAccess')}</CrBadge></span>}
                    {f.reboot && <span data-cr-hd-flag="reboot"><CrBadge tone="warning" dot={false} title={t('crHdRebootHint')}>{t('crHdReboot')}</CrBadge></span>}
                    {f.rollback && <span data-cr-hd-flag="rollback"><CrBadge tone="info" dot={false} title={t('crHdRollbackHint')}>{t('crHdRollbackFlag')}</CrBadge></span>}
                </span>
            );
        }

        // --- the confirmation with the change preview ------------------------------------------

        function CrHdConfirm({ mode, ids, rows, node, nodeState, params, catalog, flagsOf, hasKey, orderNote, onCancel, onConfirm }) {
            const { t } = useTranslation();
            const ref = useRef(null);
            const back = useRef(typeof document !== 'undefined' ? document.activeElement : null);
            const [titleId] = useState(() => `cr-hd-dlg-${++crPanelSeq}`);
            const [accessAck, setAccessAck] = useState(false);
            const [lockoutAck, setLockoutAck] = useState(false);
            useEffect(() => {
                if (ref.current) ref.current.focus({ preventScroll: true });
                return () => crFocusBack(back.current);
            }, []);
            const onKey = (e) => {
                if (e.key === 'Tab') { crKeepTab(e, ref.current); return; }
                if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onCancel(); }
            };
            const apply = mode === 'apply';
            const list = ids.map(id => rows[id]).filter(Boolean);
            const fl = list.map(r => [r, flagsOf(r.id)]);
            const needsAccess = apply && fl.some(([, f]) => f.access);
            // the red tick of classic: sshd_hardening on a cluster PegaProx reaches without a key
            const needsLockout = apply && ids.includes('sshd_hardening') && hasKey === false;
            const noRollback = fl.filter(([, f]) => f.rollback !== true).length;
            const reboot = fl.filter(([, f]) => f.reboot).map(([r]) => r.title);
            const login = fl.filter(([, f]) => f.login).map(([r]) => r.title);
            const sshPair = !apply && CR_HD_SSH_PAIR.every(id => ids.includes(id));
            const blocked = (needsAccess && !accessAck) || (needsLockout && !lockoutAck);
            const valuesOf = (id) => {
                const c = catalog && catalog[id];
                const keys = c && Array.isArray(c.param_keys) ? c.param_keys : [];
                if (!keys.length) return null;
                const vals = (params && params[id]) || {};
                return keys.map(k => `${k} = ${String(vals[k] ?? (c.defaults || {})[k] ?? '') || t('crHdEmpty')}`).join(', ');
            };
            const yes = (on, text) => (on ? <span className="cr-hd-yes">{text || t('yes')}</span> : <span className="cr-muted">-</span>);
            return ReactDOM.createPortal(
                <div className="cr-sb-layer" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
                    <div className="cr-sb-dialog cr-hd-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref}
                        onKeyDown={onKey} data-cr-hd-dialog={mode}>
                        <header className="cr-sp-head">
                            <div className="cr-sp-titles">
                                <h2 className="cr-sp-title" id={titleId}>{crFill(t(apply ? 'crHdApplyTitle' : 'crHdRollbackTitle'), { n: ids.length, node })}</h2>
                                <div className="cr-sp-sub" data-cr-hd-declared="">{t('crHdDeclared')}</div>
                            </div>
                            <button type="button" className="cr-icon-btn" onClick={onCancel} aria-label={t('close')} title={`${t('close')} (Esc)`}>
                                <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                            </button>
                        </header>
                        <div className="cr-sb-dbody">
                            <p className="cr-hd-intro">{t(apply ? 'crHdApplyIntro' : 'crHdRollbackIntro')}</p>
                            <div className="cr-hd-ptable-wrap">
                                <table className="cr-hd-ptable" data-cr-hd-plan="">
                                    <thead>
                                        <tr>
                                            <th scope="col">{t('control')}</th>
                                            <th scope="col">{t('crHdSshLogin')}</th>
                                            <th scope="col">{t('crHdReboot')}</th>
                                            <th scope="col">{t('crHdRollbackCol')}</th>
                                            <th scope="col">{t('crHdFiles')}</th>
                                            <th scope="col">{t('crHdCluster')}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {fl.map(([r, f], i) => {
                                            const vals = apply ? valuesOf(r.id) : null;
                                            return (
                                                <tr key={r.id} data-cr-hd-plan-row={r.id}>
                                                    <td>
                                                        <span className="cr-hd-plan-ref cr-mono">{!apply && ids.length > 1 ? `${i + 1}. ` : ''}{r.ref}</span>
                                                        <span className="cr-strong">{r.title}</span>
                                                        {apply && <span className="cr-hd-plan-what">{r.desc}</span>}
                                                        {vals && <span className="cr-hd-plan-what cr-mono" data-cr-hd-plan-values={r.id}>{crFill(t('crHdValuesSent'), { values: vals })}</span>}
                                                    </td>
                                                    <td>{yes(f.access || f.login, f.access ? t('crHdYesTick') : t('yes'))}</td>
                                                    <td>{yes(f.reboot, t('crHdYesReboot'))}</td>
                                                    <td data-cr-hd-plan-rollback={f.rollback === true ? 'yes' : f.rollback === false ? 'no' : 'unknown'}>
                                                        {f.rollback === true ? t('crHdRollbackYes') : f.rollback === false ? <span className="cr-muted">{t('crHdRollbackNo')}</span>
                                                            : <span className="cr-muted">{t('crHdUnknown')}</span>}
                                                    </td>
                                                    <td className="cr-muted">{t('crHdNotDeclared')}</td>
                                                    <td className="cr-muted">{t('crHdNotDeclared')}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                            <ul className="cr-sb-risks" aria-label={t('crSbRisks')}>
                                {/* what the node list says about the node now; the routes do not look */}
                                {(nodeState || []).map(k => (
                                    <li key={k} className="cr-sb-risk cr-sb-risk-warn" data-cr-hd-risk={`node-${k}`}>
                                        <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                        <span>{crFill(t({ maintenance: 'crHdRiskMaint', updating: 'crHdRiskUpdating', offline: 'crHdRiskOffline' }[k]), { node })}</span>
                                    </li>
                                ))}
                                {apply && noRollback > 0 && (
                                    <li className="cr-sb-risk cr-sb-risk-warn" data-cr-hd-risk="no-rollback">
                                        <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                        <span>{crFill(t('crHdRiskNoRollback'), { n: noRollback, total: ids.length })}</span>
                                    </li>
                                )}
                                {apply && reboot.length > 0 && (
                                    <li className="cr-sb-risk cr-sb-risk-info" data-cr-hd-risk="reboot">
                                        <span className="cr-ico" aria-hidden="true"><Icons.Info /></span>
                                        <span>{crFill(t('crHdRiskReboot'), { names: reboot.join(', ') })}</span>
                                    </li>
                                )}
                                {apply && login.length > 0 && (
                                    <li className="cr-sb-risk cr-sb-risk-warn" data-cr-hd-risk="login">
                                        <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                        <span>{crFill(t('crHdRiskLogin'), { names: login.join(', ') })}</span>
                                    </li>
                                )}
                                {apply && (
                                    <li className="cr-sb-risk cr-sb-risk-info" data-cr-hd-risk="order">
                                        <span className="cr-ico" aria-hidden="true"><Icons.Info /></span>
                                        <span>{t('crHdRiskOneByOne')}</span>
                                    </li>
                                )}
                                {!apply && (
                                    <li className="cr-sb-risk cr-sb-risk-warn" data-cr-hd-risk="whole-files">
                                        <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                        <span>{t('crHdRiskWholeFiles')}</span>
                                    </li>
                                )}
                                {!apply && ids.some(id => CR_HD_SSH_PAIR.includes(id)) && (
                                    <li className="cr-sb-risk cr-sb-risk-warn" data-cr-hd-risk="sshd-restart">
                                        <span className="cr-ico" aria-hidden="true"><Icons.AlertTriangle /></span>
                                        <span>{t('crHdRiskSshRestart')}</span>
                                    </li>
                                )}
                                {sshPair && (
                                    <li className={`cr-sb-risk cr-sb-risk-${orderNote.known ? 'info' : 'warn'}`} data-cr-hd-risk={orderNote.known ? 'ssh-order' : 'ssh-order-unknown'}>
                                        <span className="cr-ico" aria-hidden="true">{orderNote.known ? <Icons.Info /> : <Icons.AlertTriangle />}</span>
                                        <span>{orderNote.known ? crFill(t('crHdRiskOrderKnown'), { first: orderNote.first, second: orderNote.second })
                                            : t('crHdRiskOrderUnknown')}</span>
                                    </li>
                                )}
                            </ul>
                            {needsLockout && (
                                <div className="cr-callout cr-callout-error" data-cr-hd-lockout="">
                                    <Icons.AlertCircle className="w-4 h-4" />
                                    <div>
                                        <p>{crDash(t('cmSshdRootLockoutNote'))}</p>
                                        <label className="cr-hd-tick">
                                            <input type="checkbox" checked={lockoutAck} onChange={e => setLockoutAck(e.target.checked)} data-cr-hd-ack="lockout" />
                                            <span>{crDash(t('hardenLockoutAck'))}</span>
                                        </label>
                                    </div>
                                </div>
                            )}
                            {needsAccess && (
                                <label className="cr-hd-tick cr-hd-tick-warn">
                                    <input type="checkbox" checked={accessAck} onChange={e => setAccessAck(e.target.checked)} data-cr-hd-ack="access" />
                                    <span>{crDash(t('hardenAccessAck'))}</span>
                                </label>
                            )}
                            <p className="cr-sb-fine">{t(apply ? 'crHdApplyFoot' : 'crHdRollbackFoot')}</p>
                        </div>
                        <footer className="cr-sp-foot cr-sb-dfoot">
                            {blocked && <span className="cr-sb-blocked" data-cr-hd-needs-tick="">{t('crHdNeedsTick')}</span>}
                            <CrButton onClick={onCancel} data-cr-hd-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant={apply ? 'primary' : 'danger'} disabled={blocked} data-cr-hd-confirm=""
                                icon={apply ? <Icons.Shield /> : <Icons.RotateCcw />}
                                onClick={() => onConfirm(needsLockout && lockoutAck)}>
                                {crFill(t(apply ? 'crHdApplyN' : 'crHdRollbackN'), { n: ids.length })}
                            </CrButton>
                        </footer>
                    </div>
                </div>,
                document.body
            );
        }

        // --- the detail of one control ---------------------------------------------------------

        function CrHdDetail({ row, node, at, flags, params, setParams, catalog, canEdit, hasKey, onDismiss, t }) {
            const v = row.raw && typeof row.raw === 'object' ? row.raw : null;
            const c = catalog && catalog[row.id];
            const keys = c && Array.isArray(c.param_keys) ? c.param_keys : [];
            const vals = (params && params[row.id]) || {};
            const o = row.out && CR_HD_OUT[row.out.kind];
            return (
                <div className="cr-hd-detail" data-cr-hd-detail={row.id}>
                    <dl className="cr-hd-dl">
                        <dt>{t('crHdCheckResult')}</dt>
                        <dd data-cr-hd-detail-check="">
                            <CrHdCheckBadge st={row.st} pending={row.pending} t={t} />
                            <span className="cr-muted"> {at ? crFill(t('crHdCheckedAt'), { time: crFmtTime(at), node }) : t('crHdNotCheckedYet')}</span>
                            {row.st == null && v && v.not_checked && <span className="cr-hd-why">{crDash(v.not_checked)}</span>}
                        </dd>
                        <dt>{t('description')}</dt>
                        <dd>{row.desc}</dd>
                        <dt>{t('crHdCurrent')}</dt>
                        <dd>
                            {v && v.evidence
                                ? <pre className="cr-hd-pre" data-cr-hd-evidence="">{v.evidence}</pre>
                                : <span className="cr-muted" data-cr-hd-no-evidence="">{t('crHdNoEvidence')}</span>}
                        </dd>
                        <dt>{t('checkCommand')}</dt>
                        <dd>
                            {v && v.command ? <pre className="cr-hd-pre cr-hd-cmd" data-cr-hd-command="">{v.command}</pre>
                                : <span className="cr-muted">{t('crHdNoCommand')}</span>}
                        </dd>
                        <dt>{t('crHdExpected')}</dt>
                        <dd>
                            <span className="cr-muted">{t('crHdExpectedNote')}</span>
                            {keys.length > 0 && (
                                <span className="cr-hd-params" data-cr-hd-params={row.id}>
                                    {keys.map(k => (
                                        <label key={k} className="cr-hd-param">
                                            <span className="cr-muted cr-mono">{k}</span>
                                            <input type="text" className="cr-input" value={vals[k] ?? ''} disabled={!canEdit}
                                                placeholder={String((c.defaults || {})[k] ?? '') || t('crHdEmpty')}
                                                onChange={e => { const val = e.target.value; setParams(p => ({ ...p, [row.id]: { ...(p[row.id] || {}), [k]: val } })); }}
                                                data-cr-hd-param={k} />
                                        </label>
                                    ))}
                                    {['pam_faillock', 'pw_aging', 'session_limit', 'inactive_accounts'].includes(row.id) && (
                                        <span className="cr-muted">{t('crHdAlwaysExempt')}</span>
                                    )}
                                </span>
                            )}
                        </dd>
                        <dt>{t('pveImpact')}</dt>
                        <dd>
                            {row.impact}
                            {row.id === 'default_umask' && <span className="cr-hd-note">{crDash(t('cmUmaskToolingNote'))}</span>}
                            {row.id === 'sshd_hardening' && hasKey === false && <span className="cr-hd-note cr-hd-note-error">{crDash(t('cmSshdRootLockoutNote'))}</span>}
                        </dd>
                    </dl>
                    <h3 className="cr-hd-h">{t('crHdDeclared')}</h3>
                    <dl className="cr-hd-dl" data-cr-hd-declared-list="">
                        <dt>{t('crHdSshLogin')}</dt>
                        <dd>{flags.access ? t('crHdDeclAccess') : flags.login ? t('crHdDeclLogin') : t('crHdNotDeclared')}</dd>
                        <dt>{t('crHdReboot')}</dt>
                        <dd>{flags.reboot ? t('crHdDeclReboot') : t('crHdDeclNoReboot')}</dd>
                        <dt>{t('crHdRollbackCol')}</dt>
                        <dd data-cr-hd-decl-rollback="">{flags.rollback === true ? t('crHdDeclRollback') : flags.rollback === false ? t('crHdDeclNoRollback') : t('crHdUnknown')}</dd>
                        <dt>{t('crHdFiles')}</dt>
                        <dd className="cr-muted">{t('crHdNotDeclared')}</dd>
                        <dt>{t('crHdCluster')}</dt>
                        <dd className="cr-muted">{t('crHdNotDeclared')}</dd>
                        {flags.audit && <><dt>{t('crHdAuditOnly')}</dt><dd>{t('crHdAuditOnlyHint')}</dd></>}
                    </dl>
                    <h3 className="cr-hd-h">{t('crHdHistory')}</h3>
                    <dl className="cr-hd-dl">
                        <dt>{t('crHdThisSession')}</dt>
                        <dd data-cr-hd-detail-out="">
                            {o ? (
                                <>
                                    <CrHdOutBadge out={row.out} t={t} />
                                    <span className="cr-muted"> {crFmtTime(row.out.at)}</span>
                                    {row.out.error && <span className="cr-hd-why" data-cr-hd-out-error="">{crDash(row.out.error)}</span>}
                                    {row.out.kind === 'applied' && row.st === false && <span className="cr-hd-why">{t('crHdStillFails')}</span>}
                                    <button type="button" className="cr-btn cr-btn-ghost cr-hd-dismiss" onClick={onDismiss} data-cr-hd-dismiss={row.id}>{t('crHdDismiss')}</button>
                                </>
                            ) : <span className="cr-muted">{t('crHdNoSessionAction')}</span>}
                        </dd>
                        <dt>{t('crHdEarlier')}</dt>
                        <dd className="cr-muted" data-cr-hd-history="not-recorded">{t('crHdNotRecorded')}</dd>
                    </dl>
                </div>
            );
        }

        // --- the tab ---------------------------------------------------------------------------

        function CrHarden({ selectedCluster, nodes, metrics, node, setNode, profile, pickProfile, profiles, canManage, onManage,
                            onSaveSelection, params, setParams, authFetch, dialogs }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const may = crVmCan().holds('node.maintenance');
            const store = useCrHd();
            const cid = selectedCluster && selectedCluster.id;
            const xcp = !!selectedCluster && (selectedCluster.cluster_type === 'xcpng' || selectedCluster.type === 'xcpng');
            const live = !haReadOnly && !xcp;
            const nodeOk = node && (nodes || []).includes(node) ? node : '';
            const [modePick, setMode] = useState('apply');
            // Profile: the pick of Save selection as profile, any control of the catalog (classic ticks any)
            const mode = modePick === 'profile' && !canManage ? 'apply' : modePick;
            const [sel, setSel] = useState({ apply: {}, rollback: {}, profile: {} });
            const [show, setShow] = useState('all');
            const [src, setSrc] = useState('');
            const [openId, setOpenId] = useState(null);
            const [dlg, setDlg] = useState(null);
            const [exportMsg, setExportMsg] = useState('');
            const reportRef = useRef(null);

            const rk = crHdKey(cid, nodeOk);
            const read = (cid && nodeOk && store.reads[crHdKey(cid, nodeOk, profile)]) || {};
            const run = store.runs[rk] || null;
            const outcomes = store.outcomes[rk] || {};
            const last = store.last[rk] || null;
            const data = read.data || null;
            const err = crHdReadError(t, read.error);

            // a new node, profile or cluster starts with nothing picked
            useEffect(() => { setSel({ apply: {}, rollback: {}, profile: {} }); setOpenId(null); setDlg(null); }, [cid, nodeOk, profile]);

            const info = useMemo(() => {
                const all = hardeningControlInfo(t);
                const m = {};
                all.groups.forEach((g, gi) => Object.entries(g.ctrls).forEach(([id, x], i) => {
                    m[id] = { ...x, src: g.src, order: gi * 100 + i };
                }));
                return m;
            }, [t]);
            const catalog = useMemo(() => {
                if (!profiles || !Array.isArray(profiles.catalog)) return null;
                const m = {};
                profiles.catalog.forEach(c => { if (c && c.id) m[c.id] = c; });
                return m;
            }, [profiles]);
            const rollbackSet = useMemo(() => (catalog ? new Set(Object.values(catalog).filter(c => c.rollback === true).map(c => c.id)) : null), [catalog]);
            const flagsOf = (id) => crHdFlags(id, info[id], rollbackSet);

            const rows = useMemo(() => {
                const controls = (data && data.controls) || {};
                return Object.keys(controls).map(id => {
                    const x = info[id] || {};
                    const source = x.src ? CR_HD_SRC[x.src] : '';
                    return {
                        id, raw: controls[id], st: crHdStatus(controls[id]), src: x.src || '', order: x.order != null ? x.order : 9999,
                        ref: `${source}${source && x.ref ? ' ' : ''}${x.ref || ''}` || id,
                        title: crDash(x.title || id), desc: crDash(x.desc || ''), impact: crDash(x.impact || ''),
                    };
                }).sort((a, b) => a.order - b.order);
            }, [data, info]);
            const pendingOf = (id) => (run && run.ids.includes(id) && !run.done.includes(id)
                ? (run.current === id || run.mode === 'rollback' ? 'running' : 'queued') : null);
            // the run and the outcomes change in place in the store, which only bumps a render: what
            // reads them is worked out on every render (one node, 50 rows at most)
            const shown = rows.map(r => ({ ...r, out: outcomes[r.id] || null, pending: pendingOf(r.id) }));
            const byId = Object.fromEntries(shown.map(r => [r.id, r]));

            const counts = useMemo(() => {
                const c = { total: rows.length, passed: 0, failed: 0, unchecked: 0 };
                rows.forEach(r => { if (r.st === true) c.passed++; else if (r.st === false) c.failed++; else c.unchecked++; });
                c.checked = c.passed + c.failed;
                return c;
            }, [rows]);
            const pending = run ? run.ids.length - run.done.length : 0;
            // a value typed for a templated control that is not its default: a passed control has
            // something to apply again then (the check itself takes no values)
            const keysOf = (id) => (catalog && catalog[id] && Array.isArray(catalog[id].param_keys) ? catalog[id].param_keys : []);
            const edited = (id) => keysOf(id).some(k => {
                const v = String((params && params[id] && params[id][k]) ?? '').trim();
                return v !== '' && v !== String(((catalog[id] && catalog[id].defaults) || {})[k] ?? '');
            });
            const why = (m, r) => {
                if (!live) return xcp ? 'crHdWhyXcp' : 'crHdWhyStandby';
                if (!may) return 'crHdNoPerm';
                if (m === 'profile') return catalog && catalog[r.id] ? null : 'crHdWhyNoCatalog';
                if (m === 'apply') {
                    if (crHdAuditOnly(r.id)) return 'crHdWhyAuditOnly';
                    if (r.st === true && !edited(r.id)) return keysOf(r.id).length ? 'crHdWhyPassedValue' : 'crHdWhyPassed';
                    return null;
                }
                if (!rollbackSet) return 'crHdWhyNoCatalog';
                return rollbackSet.has(r.id) ? null : 'crHdWhyNoRollback';
            };
            const eligible = {
                apply: rows.filter(r => !why('apply', r)).map(r => r.id),
                rollback: rows.filter(r => !why('rollback', r)).map(r => r.id),
                profile: rows.filter(r => !why('profile', r)).map(r => r.id),
            };
            const picked = (m) => eligible[m].filter(id => sel[m][id]);
            const toggle = (m, id, on) => setSel(s => ({ ...s, [m]: { ...s[m], [id]: on } }));

            const filter = (r) => (!src || r.src === src)
                && (show === 'all' || (show === 'failed' && r.st === false) || (show === 'passed' && r.st === true)
                    || (show === 'unchecked' && r.st == null) || (show === 'session' && !!outcomes[r.id]));
            const showCounts = { all: 0, failed: 0, unchecked: 0, passed: 0, session: 0 };
            rows.forEach(r => {
                if (src && r.src !== src) return;
                showCounts.all++;
                if (r.st === false) showCounts.failed++; else if (r.st === true) showCounts.passed++; else showCounts.unchecked++;
                if (outcomes[r.id]) showCounts.session++;
            });

            const check = () => { if (cid && nodeOk && may && !read.loading) crHdCheck(authFetch, cid, nodeOk, profile); };
            const ctx = { authFetch, cid, node: nodeOk, profile, params };
            // newest first for the two SSH controls, when this session saw both applied
            const orderFor = (ids) => {
                const pair = CR_HD_SSH_PAIR.filter(id => ids.includes(id));
                if (pair.length < 2) return { ids, note: { known: true } };
                const at = (id) => (outcomes[id] && outcomes[id].kind === 'applied' ? outcomes[id].seq : null);
                if (at(pair[0]) == null || at(pair[1]) == null) return { ids, note: { known: false } };
                const [newer, older] = at(pair[0]) >= at(pair[1]) ? [pair[0], pair[1]] : [pair[1], pair[0]];
                const rest = ids.filter(id => !pair.includes(id));
                return { ids: [newer, older, ...rest], note: { known: true, first: byId[newer].title, second: byId[older].title } };
            };
            const openConfirm = (m) => {
                if (!live || !may || run || m === 'profile') return;
                const list = picked(m);
                if (!list.length) return;
                const o = m === 'rollback' ? orderFor(list) : { ids: list, note: { known: true } };
                setDlg({ mode: m, ids: o.ids, note: o.note });
            };
            // what the node list says about the node now: the apply and rollback routes check none of it
            const nm = (metrics && nodeOk && metrics[nodeOk]) || null;
            const nodeState = nm ? [nm.maintenance_mode && 'maintenance', nm.is_updating && 'updating',
                                    (nm.offline === true || nm.status === 'offline') && 'offline'].filter(Boolean) : [];
            const go = (force) => {
                const c = dlg;
                setDlg(null);
                if (!c) return;
                setSel(s => ({ ...s, [c.mode]: {} }));
                if (c.mode === 'apply') crHdApply(ctx, c.ids, force);
                else crHdRollback(ctx, c.ids);
            };
            const dismiss = (id) => {
                const o = crHd.outcomes[rk];
                if (!o) return;
                if (id) delete o[id]; else crHd.outcomes[rk] = {};
                if (id == null) delete crHd.last[rk];
                crHdEmit();
            };

            // Save selection as profile, as classic builds it: the controls picked in the Profile mode
            // (passed and audit only ones too) and the values typed in for them, a default stays out
            const saveSelection = () => {
                const ids = picked('profile').filter(id => catalog && catalog[id]);
                if (!ids.length) return;
                const vals = {};
                ids.forEach(id => (catalog[id].param_keys || []).forEach(key => {
                    const v = String((params && params[id] && params[id][key]) ?? '').trim();
                    if (v && v !== String((catalog[id].defaults || {})[key] ?? '')) vals[id] = { ...(vals[id] || {}), [key]: v };
                }));
                onSaveSelection({ name: '', description: '', controls: ids, params: vals });
            };

            const exportPng = async () => {
                setExportMsg('');
                const ok = await crRpPng(reportRef.current, `pegaprox-hardening-${nodeOk || 'node'}-${new Date().toISOString().slice(0, 10)}.png`);
                if (!ok) setExportMsg(t('crRpExportFailed'));
            };
            const exportPdf = () => {
                const label = (r) => (r.st === true ? t('passed') : r.st === false ? t('failed') : t('hardenNotCheckedBadge'));
                const blocks = [
                    { type: 'stats', data: [
                        { label: t('passed'), value: String(counts.passed), color: '#808080' },
                        { label: t('failed'), value: String(counts.failed), color: counts.failed ? '#dc3232' : '#808080' },
                        { label: t('hardenNotCheckedBadge'), value: String(counts.unchecked), color: '#808080' },
                        { label: t('coverage'), value: `${counts.checked}/${counts.total}`, color: '#808080' },
                    ] },
                    { type: 'text', value: crRpSafe(crFill(t('crHdPdfBasis'), { time: read.at ? crFmtTime(read.at) : '-', node: nodeOk })) },
                    { type: 'spacer', height: 4 },
                ];
                ['cis', 'lynis', 'stig', 'pega', 'vsnfd', ''].forEach(s => {
                    const part = shown.filter(r => r.src === s);
                    if (!part.length) return;
                    blocks.push({
                        type: 'table', title: crRpSafe(s ? CR_HD_SRC[s] : t('crHdOther')),
                        columns: [t('reference'), t('control'), t('crHdCheckResult'), t('crHdThisSession'), t('pveImpact')],
                        rows: part.map(r => [crRpSafe(r.ref), crRpSafe(r.title), crRpSafe(label(r)),
                            crRpSafe(r.out && CR_HD_OUT[r.out.kind] ? t(CR_HD_OUT[r.out.kind].key) : '-'), crRpSafe(r.impact.slice(0, 90))]),
                    });
                });
                const ev = shown.filter(r => r.raw && typeof r.raw === 'object' && (r.raw.evidence || r.raw.command));
                if (ev.length) {
                    blocks.push({ type: 'spacer', height: 4 });
                    blocks.push({ type: 'table', title: t('auditEvidence'), columns: [t('control'), t('checkCommand'), t('actualState')],
                        rows: ev.map(r => [crRpSafe(r.title.slice(0, 40)), crRpSafe(String(r.raw.command || '').slice(0, 160)),
                            crRpSafe(String(r.raw.evidence || '').slice(0, 220))]) });
                }
                generatePegaProxPDF({
                    title: t('hardenReportTitle') || 'Node Hardening Report', subtitle: nodeOk, clusterName: selectedCluster && selectedCluster.name,
                    filename: `pegaprox-hardening-${nodeOk || 'node'}-${new Date().toISOString().slice(0, 10)}.pdf`, content: blocks,
                });
            };

            const columns = [
                { key: 'pick', label: '', menuLabel: t({ apply: 'crHdColApply', rollback: 'crHdColRollback', profile: 'crHdColProfile' }[mode]), width: 34, resizable: false, sortable: false,
                  text: () => '',
                  render: r => {
                      const reason = why(mode, r);
                      const on = !reason && !!sel[mode][r.id];
                      return (
                          <input type="checkbox" checked={on} disabled={!!reason || !!run}
                              aria-label={crFill(t({ apply: 'crHdPickApply', rollback: 'crHdPickRollback', profile: 'crHdPickProfile' }[mode]), { name: r.title })}
                              title={reason ? t(reason) : undefined} data-cr-hd-pick={r.id} data-cr-hd-mode={mode}
                              onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}
                              onChange={e => toggle(mode, r.id, e.target.checked)} />
                      );
                  } },
                { key: 'ref', label: t('reference'), width: 170, sortValue: r => r.order, text: r => r.ref,
                  render: r => <span className={`cr-hd-ref cr-hd-src-${r.src || 'none'}`} title={r.ref}>{r.ref}</span> },
                { key: 'title', label: t('control'), flex: true, min: 240, sortValue: r => r.title, text: r => `${r.title} ${r.desc} ${r.id}`,
                  render: r => (
                      <span className="cr-hd-ctl" title={r.desc}>
                          <span className="cr-strong">{r.title}</span>
                          <span className="cr-hd-desc">{r.desc}</span>
                      </span>
                  ) },
                { key: 'check', label: t('crHdCheckCol'), width: 112, sortValue: r => (r.st === false ? 0 : r.st == null ? 1 : 2),
                  text: r => (r.st === true ? t('passed') : r.st === false ? t('failed') : t('hardenNotCheckedBadge')),
                  render: r => <span data-cr-hd-check={r.id} data-cr-hd-state={r.pending || (r.st === true ? 'passed' : r.st === false ? 'failed' : 'unchecked')}>
                      <CrHdCheckBadge st={r.st} pending={r.pending} t={t} /></span> },
                { key: 'session', label: t('crHdSessionCol'), width: 156, sortValue: r => (r.out ? r.out.kind : null),
                  text: r => (r.out && CR_HD_OUT[r.out.kind] ? t(CR_HD_OUT[r.out.kind].key) : ''),
                  render: r => (r.out ? <span data-cr-hd-out={r.id} data-cr-hd-kind={r.out.kind}><CrHdOutBadge out={r.out} t={t} /></span> : '') },
                { key: 'flags', label: t('crHdFlagsCol'), width: 196, sortable: false, text: () => '',
                  render: r => <CrHdFlagChips f={flagsOf(r.id)} t={t} /> },
            ];

            const nApply = picked('apply').length;
            const nRoll = picked('rollback').length;
            const nProfile = picked('profile').length;
            const n = mode === 'apply' ? nApply : mode === 'rollback' ? nRoll : nProfile;
            const openRow = openId && byId[openId];
            const sessionKinds = {};
            Object.values(outcomes).forEach(o => { sessionKinds[o.kind] = (sessionKinds[o.kind] || 0) + 1; });
            const anyOutcome = Object.keys(outcomes).length > 0;
            const profileName = data && data.profile_name;
            const coverage = counts.total ? Math.round(counts.checked * 100 / counts.total) : null;

            const head = (
                <CrPageHeader icon={<Icons.Shield />} title={t('hardenNode')}
                    sub={selectedCluster ? [clusterLabel(selectedCluster), nodeOk].filter(Boolean).join(' · ') : null}
                    actions={(
                        <>
                            {canManage && (
                                <CrButton icon={<Icons.Settings />} onClick={onManage} data-hp-manage="">{t('hpManage')}</CrButton>
                            )}
                            {canManage && (
                                <CrButton icon={<Icons.Save />} onClick={saveSelection} disabled={!nProfile || !!run || !catalog}
                                    title={nProfile ? t('hpSaveSelectionHint') : t('crHdSaveNeedsPicks')} data-hp-save-selection="">{t('hpSaveSelection')}</CrButton>
                            )}
                            <CrButton icon={<Icons.Image />} onClick={exportPng} disabled={!data} title={t('exportPng')} data-cr-hd-export="png">PNG</CrButton>
                            <CrButton icon={<Icons.Download />} onClick={exportPdf} disabled={!data} title={t('exportPdf')} data-cr-hd-export="pdf">PDF</CrButton>
                        </>
                    )} />
            );

            return (
                <div className="cr-dash cr-hd" data-cr-harden="">
                    {head}
                    <p className="cr-cmp-hint">{t('hardenDesc')} {t('hardenCisRef')}</p>
                    {exportMsg && <p className="cr-hd-dropped" role="status" data-cr-hd-export-msg="">{exportMsg}</p>}
                    <div className="cr-hd-bar" data-cr-hd-bar="">
                        <label className="cr-hd-field">
                            <span className="cr-muted">{t('node')}</span>
                            <select className="cr-select" value={nodeOk} onChange={e => setNode(e.target.value)} data-cr-hd-node="">
                                <option value="">{t('selectNode')}</option>
                                {(nodes || []).map(nm => <option key={nm} value={nm}>{nm}</option>)}
                            </select>
                        </label>
                        <label className="cr-hd-field">
                            <span className="cr-muted">{t('crCmpProfile')}</span>
                            <select className="cr-select" value={profile} onChange={e => pickProfile(e.target.value)} title={t('hardenProfileHint')} data-cr-hd-profile="">
                                <option value="">{t('hardenProfileAll')}</option>
                                <optgroup label={t('regionEU')}>
                                    <option value="bsi">BSI IT-Grundschutz</option>
                                    <option value="iso">ISO 27001 (Annex A)</option>
                                    <option value="nis2">NIS2 / KRITIS</option>
                                    <option value="vs-nfd">VS-NfD (BSI)</option>
                                </optgroup>
                                <optgroup label={crTOr(t, 'regionFR', 'EU / France')}>
                                    <option value="dr">Diffusion Restreinte (ANSSI II 901)</option>
                                    <option value="rgs">RGS (ANSSI-BP-028)</option>
                                </optgroup>
                                <optgroup label={t('regionUS')}>
                                    <option value="cmmc1">CMMC L1 (FAR 52.204-21)</option>
                                    <option value="cmmc2">CMMC L2 / NIST 800-171</option>
                                    <option value="nist53">NIST 800-53 (Mod)</option>
                                    <option value="stig">DISA STIG</option>
                                </optgroup>
                                {((profiles && profiles.custom) || []).length > 0 && (
                                    <optgroup label={t('hpCustomProfiles')}>
                                        {profiles.custom.map(p => <option key={p.id} value={`custom:${p.id}`}>{p.name}</option>)}
                                    </optgroup>
                                )}
                            </select>
                        </label>
                        <CrButton variant="primary" icon={read.loading ? <span className="cr-spinner" /> : <Icons.Shield />} onClick={check}
                            disabled={!nodeOk || !may || !!read.loading || !!run} data-cr-hd-check-btn=""
                            title={!may ? t('crHdNoPerm') : undefined}>
                            {read.loading ? t('checking') : t('checkStatus')}
                        </CrButton>
                        {read.loading && <span className="cr-muted" role="status" data-cr-hd-loading="">{crFill(t('crHdChecking'), { node: nodeOk })}</span>}
                    </div>

                    {!may && (
                        <div className="cr-callout cr-callout-info" role="status" data-cr-hd-state="no-permission">
                            <Icons.Info className="w-4 h-4" /><div><p>{t('crHdNoPerm')}</p></div>
                        </div>
                    )}
                    {xcp && (
                        <div className="cr-callout cr-callout-info" role="status" data-cr-hd-state="xcpng">
                            <Icons.Info className="w-4 h-4" /><div><p>{t('crHdXcp')}</p></div>
                        </div>
                    )}
                    {haReadOnly && !xcp && (
                        <div className="cr-callout cr-callout-info" role="status" data-cr-hd-state="standby">
                            <Icons.Info className="w-4 h-4" /><div><p>{t('crHdStandby')}</p></div>
                        </div>
                    )}
                    {err && (
                        <div className={`cr-callout cr-callout-${err.kind === 'denied' ? 'warning' : 'error'}`} role="alert" data-cr-hd-error={err.kind}>
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div>
                                <p className="cr-strong">{err.title}</p>
                                {err.text && <p>{err.text}</p>}
                                {err.hint && <p className="cr-muted">{err.hint}</p>}
                                {data && read.at && <p className="cr-muted" data-cr-hd-stale="">{crFill(t('crHdStale'), { time: crFmtTime(read.at) })}</p>}
                            </div>
                        </div>
                    )}
                    {run && (
                        <div className="cr-callout cr-callout-info" role="status" data-cr-hd-run={run.mode}>
                            <span className="cr-spinner" aria-hidden="true" />
                            <div>
                                <p className="cr-strong">{crFill(t(run.mode === 'apply' ? 'crHdRunApply' : 'crHdRunRollback'),
                                    { done: run.done.length, total: run.ids.length, current: run.current ? ((byId[run.current] && byId[run.current].title) || run.current) : '' })}</p>
                                <p className="cr-muted">{t(run.mode === 'apply' ? 'crHdRunKeepOpen' : 'crHdRunRollbackNote')}</p>
                            </div>
                        </div>
                    )}
                    {!run && last && (
                        <div className={`cr-callout cr-callout-${last.ok === last.total ? 'success' : 'warning'}`} role="status" data-cr-hd-last={last.mode}>
                            <Icons.Info className="w-4 h-4" />
                            <div>
                                <p>{crFill(t(last.mode === 'apply' ? 'crHdLastApply' : 'crHdLastRollback'), { ok: last.ok, total: last.total, time: crFmtTime(last.at) })}</p>
                                <p className="cr-muted">{t('crHdLastNote')}</p>
                            </div>
                        </div>
                    )}

                    {!nodeOk ? (
                        <div className="cr-panel cr-empty" data-cr-hd-empty="no-node">
                            <Icons.Shield className="w-6 h-6" />
                            <p>{t('crHdPickNode')}</p>
                            <p className="cr-muted">{t('crHdPickNodeHint')}</p>
                        </div>
                    ) : !data ? (
                        !err && !read.loading && (
                            <div className="cr-panel cr-empty" data-cr-hd-empty="not-checked">
                                <Icons.Shield className="w-6 h-6" />
                                <p>{t('crHdNotCheckedYet')}</p>
                                <p className="cr-muted">{t('crHdRunCheckHint')}</p>
                            </div>
                        )
                    ) : (
                        <div ref={reportRef} className="cr-hd-report" tabIndex={-1} data-cr-focus-home="" data-cr-hd-report="">
                            <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-hd-summary="">
                                <CrStat id="hd-passed" label={t('passed')} value={counts.passed}
                                    sub={counts.checked ? crFill(t('crCmpOfChecked'), { n: counts.checked }) : t('crHdNothingChecked')} title={t('crHdPassedHint')} />
                                <CrStat id="hd-failed" label={t('failed')} value={counts.failed} tone={counts.failed ? 'error' : null}
                                    sub={counts.checked ? crFill(t('crCmpOfChecked'), { n: counts.checked }) : t('crHdNothingChecked')} />
                                <CrStat id="hd-unchecked" label={t('hardenNotCheckedBadge')} value={counts.unchecked} tone={counts.unchecked ? 'warning' : null}
                                    sub={t('crCmpNotCounted')} title={t('hardenNotCheckedHint')} />
                                <CrStat id="hd-pending" label={t('crHdPending')} value={pending}
                                    sub={run ? t(run.mode === 'apply' ? 'crHdPendingApply' : 'crHdPendingRollback') : t('crHdPendingNone')} />
                                <CrStat id="hd-coverage" label={t('coverage')} value={coverage == null ? '-' : `${coverage}%`}
                                    sub={crFill(t('crCmpCoverageSub'), { checked: counts.checked, total: counts.total })} />
                                <CrStat id="hd-at" label={t('lastCheck')} value={read.at ? crFmtTime(read.at) : '-'} sub={t('crCmpThisSession')} />
                            </section>
                            <div className="cr-hd-progress" data-cr-hd-progress={counts.checked ? 'checked' : 'none'}>
                                <CrCmpBar passed={counts.passed} failed={counts.failed} notChecked={counts.unchecked}
                                    label={crFill(t('crCmpBarLabel'), { passed: counts.passed, failed: counts.failed, notChecked: counts.unchecked })} />
                                <span className="cr-hd-progress-text">
                                    {counts.checked
                                        ? crFill(t('crHdProgress'), { passed: counts.passed, checked: counts.checked, total: counts.total })
                                        : t('crHdNothingChecked')}
                                </span>
                                {profileName && <span className="cr-hd-profile" data-hp-ran="">{profileName}</span>}
                            </div>
                            {(data.dropped_controls || []).length > 0 && (
                                <p className="cr-hd-dropped" data-hp-dropped="">{fillText(t('hpDroppedNote'), { ids: data.dropped_controls.join(', ') })}</p>
                            )}
                            {anyOutcome && (
                                <div className="cr-callout cr-callout-info" data-cr-hd-session="">
                                    <Icons.Info className="w-4 h-4" />
                                    <div>
                                        <p>{crFill(t('crHdSessionLine'), { node: nodeOk })} {Object.keys(CR_HD_OUT).filter(k => sessionKinds[k]).map(k => (
                                            <span key={k} className="cr-hd-session-n" data-cr-hd-session-kind={k}>{t(CR_HD_OUT[k].key)}: {sessionKinds[k]}</span>
                                        ))}</p>
                                        <p className="cr-muted">{t('crHdSessionNote')}</p>
                                    </div>
                                    <button type="button" className="cr-btn cr-btn-xs" onClick={() => dismiss(null)} disabled={!!run} data-cr-hd-dismiss-all="">{t('crHdDismissAll')}</button>
                                </div>
                            )}
                            <CrTable id="hd-controls" columns={columns} rows={shown} rowKey={r => r.id} filter={filter} searchable
                                onRowClick={r => setOpenId(r.id)} selectedKey={openId} ariaLabel={t('crHdControls')} maxHeight={560}
                                emptyText={t('crHdNoControls')} initialSort={{ key: 'ref', dir: 'asc' }}
                                toolbar={(
                                    <>
                                        <div className="cr-seg" role="group" aria-label={t('crHdMode')} data-cr-hd-modes="">
                                            {[['apply', t('crHdModeApply'), eligible.apply.length], ['rollback', t('crHdModeRollback'), eligible.rollback.length],
                                              ...(canManage ? [['profile', t('crHdModeProfile'), eligible.profile.length]] : [])].map(([id, label, k]) => (
                                                <button key={id} type="button" className={mode === id ? 'active' : ''} aria-pressed={mode === id}
                                                    disabled={!live || !may} data-cr-hd-mode-btn={id} onClick={() => setMode(id)}
                                                    title={crFill(t('crHdEligible'), { n: k })}>
                                                    {label}<span className="cr-seg-n">{k}</span>
                                                </button>
                                            ))}
                                        </div>
                                        <div className="cr-seg" role="group" aria-label={t('filter')}>
                                            {[['all', t('all')], ['failed', t('failed')], ['unchecked', t('hardenNotCheckedBadge')], ['passed', t('passed')],
                                              ...(anyOutcome ? [['session', t('crHdThisSession')]] : [])].map(([id, label]) => (
                                                <button key={id} type="button" className={show === id ? 'active' : ''} aria-pressed={show === id}
                                                    data-cr-hd-show={id} onClick={() => setShow(id)}>
                                                    {label}<span className="cr-seg-n">{showCounts[id]}</span>
                                                </button>
                                            ))}
                                        </div>
                                        <select className="cr-select" value={src} onChange={e => setSrc(e.target.value)} aria-label={t('crHdSource')} data-cr-hd-src="">
                                            <option value="">{t('crHdAllSources')}</option>
                                            {Object.keys(CR_HD_SRC).filter(s => rows.some(r => r.src === s)).map(s => <option key={s} value={s}>{CR_HD_SRC[s]}</option>)}
                                        </select>
                                    </>
                                )}
                                actions={live && may ? (
                                    <>
                                        <button type="button" className="cr-btn cr-btn-ghost" disabled={!!run || !eligible[mode].length}
                                            onClick={() => setSel(s => ({ ...s, [mode]: Object.fromEntries(eligible[mode].filter(id => {
                                                const r = byId[id];
                                                return r && filter(r);
                                            }).map(id => [id, true])) }))} data-cr-hd-pick-all="">{t('crHdPickShown')}</button>
                                        <button type="button" className="cr-btn cr-btn-ghost" disabled={!!run || !n}
                                            onClick={() => setSel(s => ({ ...s, [mode]: {} }))} data-cr-hd-clear="">{t('crHdClear')}</button>
                                        {mode === 'profile' ? (
                                            <CrButton variant="primary" disabled={!n || !!run || !catalog} icon={<Icons.Save />}
                                                onClick={saveSelection} title={t('hpSaveSelectionHint')} data-cr-hd-go="profile">
                                                {crFill(t('crHdProfileSel'), { n })}
                                            </CrButton>
                                        ) : (
                                            <CrButton variant={mode === 'apply' ? 'primary' : 'danger'} disabled={!n || !!run}
                                                icon={mode === 'apply' ? <Icons.Shield /> : <Icons.RotateCcw />}
                                                onClick={() => openConfirm(mode)} data-cr-hd-go={mode}>
                                                {crFill(t(mode === 'apply' ? 'crHdApplySel' : 'crHdRollbackSel'), { n })}
                                            </CrButton>
                                        )}
                                    </>
                                ) : null} />
                            <p className="cr-sb-fine" data-cr-hd-foot="">{t('crHdFoot')}</p>
                        </div>
                    )}

                    <CrSidePanel open={!!openRow} id="harden-control" title={openRow ? openRow.title : ''}
                        sub={openRow ? `${openRow.ref} · ${nodeOk}` : ''} onClose={() => setOpenId(null)} focusKey={openId}
                        returnFocus={() => document.querySelector('[data-cr-table="hd-controls"] tbody tr[tabindex="0"]')}>
                        {openRow && (
                            <CrHdDetail row={openRow} node={nodeOk} at={read.at} flags={flagsOf(openRow.id)} params={params} setParams={setParams}
                                catalog={catalog} canEdit={live && may && !run} hasKey={selectedCluster ? selectedCluster.has_ssh_key : undefined}
                                onDismiss={() => dismiss(openRow.id)} t={t} />
                        )}
                    </CrSidePanel>
                    {dlg && (
                        <CrHdConfirm mode={dlg.mode} ids={dlg.ids} rows={byId} node={nodeOk} nodeState={nodeState} params={params} catalog={catalog}
                            flagsOf={flagsOf} hasKey={selectedCluster ? selectedCluster.has_ssh_key : undefined} orderNote={dlg.note}
                            onCancel={() => setDlg(null)} onConfirm={go} />
                    )}
                    {dialogs}
                </div>
            );
        }
