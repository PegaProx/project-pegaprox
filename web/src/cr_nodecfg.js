        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): the configuration of a node - LW Nov 2026
        // The parts every section of the node pages is built from: the section card (title,
        // description, actions), the key value grid, the form field, the edit bar with what a Save
        // changes, the danger zone, the states of a read and the short confirmation. Then the system
        // information of the summary and the sub tabs DNS, Hosts File, Time, Certificates and Syslog
        // of a Proxmox VE node. CorporateNodeDetailView (node_modals.js) keeps the reads and the
        // saves: every write here calls its handler with the classic arguments.
        // ═══════════════════════════════════════════════════════════

        const crNcEmpty = (v) => v === undefined || v === null || v === '' || (typeof v === 'number' && !Number.isFinite(v));

        // a value nobody reported, in a neutral style (never a dash that reads like a value)
        function CrNcMissing({ text }) {
            const { t } = useTranslation();
            return <span className="cr-nc-missing" data-cr-nc-missing="">{text || t('crNsNotReported')}</span>;
        }

        // beside the title while the node is read again (after a Save, a Refresh or a Retry): what the
        // card shows is the last read until the new answer is in
        function CrNcUpdating({ on }) {
            const { t } = useTranslation();
            if (!on) return null;
            return <span data-cr-nc-updating=""><CrBadge tone="neutral" dot={false} title={t('crNcUpdatingTitle')}>{t('crNcUpdating')}</CrBadge></span>;
        }

        // the card of one section: title, an optional badge beside it, a line on what it is, the
        // actions on the right; editing frames it in the accent colour
        function CrNcSection({ id, title, desc, badge, actions, editing, foot, children, className = '', bodyClassName = '', ...rest }) {
            return (
                <section className={`cr-nc-sec${editing ? ' cr-nc-editing' : ''} ${className}`} data-cr-nc-sec={id}
                    data-cr-nc-editing={editing ? '' : undefined} {...rest}>
                    <header className="cr-nc-head">
                        <div className="cr-nc-titles">
                            <div className="cr-nc-titleline"><h3 className="cr-nc-title">{title}</h3>{badge}</div>
                            {desc && <p className="cr-nc-desc">{desc}</p>}
                        </div>
                        {actions && <div className="cr-nc-acts">{actions}</div>}
                    </header>
                    {children != null && children !== false && <div className={`cr-nc-body ${bodyClassName}`}>{children}</div>}
                    {foot}
                </section>
            );
        }

        // a group of rows inside a card, under a small heading
        function CrNcGroup({ id, title, children }) {
            return (
                <div className="cr-nc-group" data-cr-nc-group={id}>
                    {title && <h4 className="cr-nn-sub">{title}</h4>}
                    {children}
                </div>
            );
        }

        // rows: { k, label, value, mono, wide, note, missing } - an empty value is said as missing
        function CrNcKv({ id, rows, label }) {
            return (
                <dl className="cr-nc-kv" data-cr-nc-kv={id || ''} aria-label={label}>
                    {rows.filter(Boolean).map(r => (
                        <div key={r.k} className={`cr-nc-kv-row${r.wide ? ' cr-nc-kv-wide' : ''}`} data-cr-nc-k={r.k}>
                            <dt>{r.label}</dt>
                            <dd className={r.mono && !crNcEmpty(r.value) ? 'cr-mono' : undefined}>
                                {crNcEmpty(r.value) ? <CrNcMissing text={r.missing} /> : r.value}
                                {r.note && <span className="cr-nc-kv-note">{r.note}</span>}
                            </dd>
                        </div>
                    ))}
                </dl>
            );
        }

        // one input with its label; a changed one is marked and says what it was
        function CrNcField({ id, label, hint, hintTone, changed, was, wide, children }) {
            const { t } = useTranslation();
            return (
                <div className={`cr-nc-field${changed ? ' cr-nc-field-changed' : ''}${wide ? ' cr-nc-field-wide' : ''}`}
                    data-cr-nc-field={id} data-cr-nc-changed={changed ? '' : undefined}>
                    <div className="cr-nc-label-row">
                        <label className="cr-nc-label" htmlFor={`cr-nc-${id}`}>{label}</label>
                        {changed && <span className="cr-nn-pend" data-cr-nc-mark="">{t('crNcChanged')}</span>}
                    </div>
                    {children}
                    {changed && was !== undefined && (
                        <p className="cr-nc-was">{crNnT(t, 'crNcWas', { v: was === '' || was == null ? t('crNcEmptyValue') : was })}</p>
                    )}
                    {hint && <p className={`cr-nc-hint${hintTone ? ` cr-nc-hint-${hintTone}` : ''}`} data-cr-nc-hint={hintTone || 'info'}>{hint}</p>}
                </div>
            );
        }

        // what a Save would change, one row per field: the stored value, then the new one
        function CrNcChanges({ id, rows }) {
            const { t } = useTranslation();
            const show = (v) => (v === '' || v == null ? <span className="cr-nc-missing">{t('crNcEmptyValue')}</span> : v);
            return (
                <ul className="cr-nc-changes" data-cr-nc-changes={id || ''} aria-label={t('crNcPendingTitle')}>
                    {rows.map(r => (
                        <li key={r.k} data-cr-nc-change={r.k}>
                            <span className="cr-nc-ch-label">{r.label}</span>
                            <span className={`cr-nc-ch-from${r.from === '' || r.from == null ? ' cr-nc-ch-none' : ''}`}>{show(r.from)}</span>
                            <span className="cr-nc-ch-arrow" aria-label={t('crNcChangesTo')}><Icons.ArrowRight className="w-3 h-3" /></span>
                            <span className="cr-nc-ch-to">{show(r.to)}</span>
                        </li>
                    ))}
                </ul>
            );
        }

        // the bar under a section being edited: how many changes wait, what they are, Cancel and Save.
        // danger: the Save replaces a file or restarts a service, in the danger style
        function CrNcEditBar({ id, count, title, saving, canSave, readOnly, danger, note, saveLabel, onCancel, onSave, children }) {
            const { t } = useTranslation();
            return (
                <div className={`cr-nc-editbar${danger ? ' cr-nc-editbar-danger' : ''}`} data-cr-nc-editbar={id} role="region" aria-label={t('crNcPendingTitle')}>
                    <div className="cr-nc-editbar-main">
                        <p className="cr-nc-editbar-title" data-cr-nc-count={count}>
                            <Icons.Edit className="w-3.5 h-3.5" />
                            <span>{!count ? t('crNcPendingNone') : title || crNnT(t, count === 1 ? 'crNcPendingOne' : 'crNcPendingN', { n: count })}</span>
                        </p>
                        {children}
                        {note && <p className="cr-nc-editbar-note" data-cr-nc-note="">{note}</p>}
                    </div>
                    <div className="cr-nc-editbar-acts">
                        <CrButton onClick={onCancel} disabled={saving} data-cr-nc-cancel={id}>{t('cancel')}</CrButton>
                        <CrButton variant={danger ? 'danger' : 'primary'} onClick={onSave} disabled={saving || !canSave || readOnly} data-cr-nc-save={id}>
                            {saving ? t('crNcSaving') : (saveLabel || t('save'))}
                        </CrButton>
                    </div>
                </div>
            );
        }

        // an action that deletes, overwrites a whole file, restarts a service or can cut access:
        // set apart from the normal actions, with what it does
        function CrNcDanger({ id, title, desc, children }) {
            return (
                <div className="cr-nc-danger" data-cr-nc-danger={id}>
                    <div className="cr-nc-danger-text">
                        <h4 className="cr-nc-danger-title"><Icons.AlertTriangle className="w-3.5 h-3.5" /> {title}</h4>
                        {desc && <p className="cr-nc-danger-desc">{desc}</p>}
                    </div>
                    <div className="cr-nc-danger-acts">{children}</div>
                </div>
            );
        }

        // the state of a read: loading, not read, empty (with what that can mean), failed with why
        // (extra props such as data-* go on the element)
        function CrNcState({ id, kind, children, onRetry, retryDisabled, ...rest }) {
            const { t } = useTranslation();
            if (kind === 'loading') {
                return <div className="cr-nn-state" role="status" data-cr-nc-state="loading" data-cr-nc-for={id} {...rest}><Icons.RotateCw className="w-4 h-4 animate-spin" /> {children || t('crNcReading')}</div>;
            }
            const tone = kind === 'error' ? ' cr-callout-error' : kind === 'warning' ? ' cr-callout-warning' : '';
            const Icon = kind === 'error' ? Icons.AlertCircle : kind === 'warning' ? Icons.AlertTriangle : Icons.Info;
            return (
                <div className={`cr-callout cr-nc-callout${tone}`} role={kind === 'error' ? 'alert' : 'status'} data-cr-nc-state={kind} data-cr-nc-for={id} {...rest}>
                    <Icon className="w-4 h-4" />
                    <div>{children}</div>
                    {onRetry && <button type="button" className="cr-btn cr-btn-xs" onClick={onRetry} disabled={retryDisabled} data-cr-nc-retry={id}>{t('retry')}</button>}
                </div>
            );
        }

        // the short confirmation of a write that replaces a whole file or restarts a service
        function CrNcConfirm({ id, title, goLabel, busy, onCancel, onConfirm, children }) {
            const { t } = useTranslation();
            return (
                <CrUpdDialog id={`nc-${id}`} title={title} busy={busy} onCancel={onCancel}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy} data-cr-nc-confirm-cancel={id}>{t('cancel')}</CrButton>
                            <CrButton variant="danger" onClick={onConfirm} disabled={busy} data-cr-nc-confirm-go={id}>{busy ? t('crNcSaving') : goLabel}</CrButton>
                        </>
                    )}>
                    <div className="cr-nc-confirm" data-cr-nc-confirm={id}>{children}</div>
                </CrUpdDialog>
            );
        }

        // --- unsaved edits -------------------------------------------------------------------------

        // tells the view whether a card holds edits that are not saved; a card that goes is clean
        function useCrNcDirty(onDirty, id, on) {
            useEffect(() => { if (onDirty) onDirty(id, !!on); }, [onDirty, id, !!on]);
            useEffect(() => () => { if (onDirty) onDirty(id, false); }, [onDirty, id]);
        }

        const CR_NC_DIRTY_NAMES = { dns: 'dns', hosts: 'hostsFile', time: 'timeConfig', certs: 'certificates', repos: 'repositories' };

        // the question before unsaved edits are dropped: keep editing (nothing happens) or discard
        // and go on with what was clicked
        function CrNcLeave({ node, ids, onKeep, onDiscard }) {
            const { t } = useTranslation();
            const what = (ids || []).map(id => t(CR_NC_DIRTY_NAMES[id] || id)).join(', ');
            return (
                <CrUpdDialog id="nc-leave" title={t('crNcLeaveTitle')} onCancel={onKeep}
                    footer={(
                        <>
                            <CrButton variant="primary" onClick={onKeep} data-cr-nc-leave-keep="">{t('crNcLeaveKeep')}</CrButton>
                            <CrButton variant="danger" onClick={onDiscard} data-cr-nc-leave-discard="">{t('crNcLeaveDiscard')}</CrButton>
                        </>
                    )}>
                    <div className="cr-nc-confirm" data-cr-nc-leave={(ids || []).join(' ')}><p>{crNnT(t, 'crNcLeaveBody', { what, node })}</p></div>
                </CrUpdDialog>
            );
        }

        // While a card holds unsaved edits, a click that can take the user out of the node view is held
        // and asked about first: one outside the view on the tree, a tab, a link, a button or a menu
        // entry. Not held: a click in a dialog, on a toggle that only opens something (aria-haspopup,
        // aria-expanded), with a modifier key or another button. ask(go): go() sends the same click
        // again once the user chose to discard. Inside the view the node tabs, the configure sub nav
        // and Back ask through the view itself
        const CR_NC_LEAVE_SEL = 'a[href], button, [role="button"], [role="tab"], [role="treeitem"], [role="menuitem"], [role="option"], '
                              + '[role="link"], .corp-tree-item, .corp-tree-child, .cursor-pointer';
        let crNcPass = false;
        function crNcRedo(el) {
            crNcPass = true;
            try { el.click(); } finally { crNcPass = false; }
        }
        function crNcLeaveTarget(target, root) {
            if (!target || typeof target.closest !== 'function') return null;
            if (root && root.contains(target)) return null;
            if (target.closest('[role="dialog"], [role="alertdialog"], [aria-modal="true"]')) return null;
            const el = target.closest(CR_NC_LEAVE_SEL);
            if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return null;
            if (el.hasAttribute('aria-haspopup') || el.hasAttribute('aria-expanded')) return null;
            return el;
        }
        function useCrNcLeaveGuard(on, rootRef, ask) {
            const askRef = useRef(ask);
            askRef.current = ask;
            useEffect(() => {
                if (!on) return undefined;
                const onClick = (e) => {
                    if (crNcPass || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
                    const el = crNcLeaveTarget(e.target, rootRef.current);
                    if (!el) return;
                    e.preventDefault();
                    e.stopPropagation();
                    askRef.current(() => crNcRedo(el));
                };
                document.addEventListener('click', onClick, true);
                return () => document.removeEventListener('click', onClick, true);
            }, [on]);
        }
        // the configure sub nav (shared markup): a click on another entry is held the same way
        function crNcSubnavHold(e, dirty, ask) {
            if (crNcPass || !dirty()) return;
            const el = e.target && e.target.closest ? e.target.closest('.corp-subnav-item') : null;
            if (!el || el.classList.contains('active')) return;
            e.preventDefault();
            e.stopPropagation();
            ask(() => crNcRedo(el));
        }

        // --- rules ---------------------------------------------------------------------------------

        // the lines of a file before and after an edit, in the shape CrNnDiffView draws: removed and
        // added lines with two unchanged ones around each change. A change too long to compare line
        // by line (a hosts file with a block list) is counted as removed and added as a whole
        const CR_NC_DIFF_CELLS = 250000;
        function crNcLineDiff(before, after) {
            const split = (x) => { const l = String(x == null ? '' : x).split('\n'); if (l.length && l[l.length - 1] === '') l.pop(); return l; };
            const a = split(before), b = split(after);
            const out = { lines: [], added: 0, removed: 0, same: String(before == null ? '' : before) === String(after == null ? '' : after), eolOnly: false, big: false };
            if (out.same) return out;
            let p = 0;
            while (p < a.length && p < b.length && a[p] === b[p]) p++;
            let s = 0;
            while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
            const am = a.slice(p, a.length - s), bm = b.slice(p, b.length - s);
            if (!am.length && !bm.length) { out.eolOnly = true; return out; }
            const ops = [];
            for (let i = 0; i < p; i++) ops.push({ kind: 'ctx', text: a[i], ai: i, bi: i });
            if (am.length * bm.length > CR_NC_DIFF_CELLS) {
                out.big = true;
                am.forEach((x, i) => ops.push({ kind: 'del', text: x, ai: p + i, bi: p }));
                bm.forEach((x, i) => ops.push({ kind: 'add', text: x, ai: p + am.length, bi: p + i }));
            } else {
                // longest common subsequence of the middle, walked from the front
                const n = am.length, m = bm.length, w = m + 1;
                const L = new Int32Array((n + 1) * w);
                for (let i = n - 1; i >= 0; i--) {
                    for (let j = m - 1; j >= 0; j--) {
                        L[i * w + j] = am[i] === bm[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
                    }
                }
                let i = 0, j = 0;
                while (i < n || j < m) {
                    if (i < n && j < m && am[i] === bm[j]) { ops.push({ kind: 'ctx', text: am[i], ai: p + i, bi: p + j }); i++; j++; }
                    // a removed line before the one that takes its place, as diff prints it
                    else if (i < n && (j >= m || L[(i + 1) * w + j] >= L[i * w + j + 1])) { ops.push({ kind: 'del', text: am[i], ai: p + i, bi: p + j }); i++; }
                    else { ops.push({ kind: 'add', text: bm[j], ai: p + i, bi: p + j }); j++; }
                }
            }
            for (let k = s; k > 0; k--) ops.push({ kind: 'ctx', text: a[a.length - k], ai: a.length - k, bi: b.length - k });
            const near = ops.map(() => false);
            ops.forEach((o, k) => { if (o.kind !== 'ctx') for (let d = -2; d <= 2; d++) if (ops[k + d]) near[k + d] = true; });
            let last = -2;
            ops.forEach((o, k) => {
                if (!near[k]) return;
                if (k !== last + 1) out.lines.push({ kind: 'hunk', text: `@@ -${o.ai + 1} +${o.bi + 1} @@` });
                last = k;
                if (o.kind === 'add') out.added += 1;
                if (o.kind === 'del') out.removed += 1;
                out.lines.push({ kind: o.kind, text: (o.kind === 'add' ? '+' : o.kind === 'del' ? '-' : ' ') + o.text });
            });
            return out;
        }

        // an IPv4 or IPv6 literal: the only thing the node takes as a name server. A hint, never a block
        function crNcIsIp(v) {
            const x = String(v == null ? '' : v).trim();
            if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(x)) return true;
            if (!x.includes(':') || !/^[0-9a-f:.]+$/i.test(x) || (x.match(/::/g) || []).length > 1) return false;
            const parts = x.split(':');
            const tail = parts[parts.length - 1];
            if (tail.includes('.') && !crNcIsIp(tail)) return false;
            return parts.length <= 8 && parts.every((g, i) => (i === parts.length - 1 && g.includes('.')) || /^[0-9a-f]{0,4}$/i.test(g));
        }

        // when a certificate runs out, from its notafter (epoch seconds) and the time now
        function crNcExpiry(notafter, now) {
            const end = Number(notafter);
            if (!Number.isFinite(end) || end <= 0) return { state: 'none' };
            const days = Math.floor((end * 1000 - now) / 86400000);
            if (end * 1000 <= now) return { state: 'expired', days: Math.max(0, Math.floor((now - end * 1000) / 86400000)) };
            return { state: days < 30 ? 'soon' : 'ok', days };
        }

        // the certificates in a pasted PEM text
        const crNcPemCount = (text) => (String(text || '').match(/-----BEGIN CERTIFICATE-----/g) || []).length;

        // the field-by-field changes of the DNS form against what the node sent
        const CR_NC_DNS_KEYS = ['search', 'dns1', 'dns2', 'dns3'];
        function crNcDnsChanges(dns, form) {
            if (!form) return [];
            return CR_NC_DNS_KEYS.filter(k => (form[k] || '') !== ((dns && dns[k]) || '')).map(k => ({ k, from: (dns && dns[k]) || '', to: form[k] || '' }));
        }

        window.PegaProxNodeCfg = Object.freeze({ lineDiff: crNcLineDiff, isIp: crNcIsIp, expiry: crNcExpiry,
                                                 pemCount: crNcPemCount, dnsChanges: crNcDnsChanges });

        const crNcDate = (sec) => (Number(sec) > 0 ? new Date(Number(sec) * 1000).toLocaleDateString(crLocale()) : '');

        // --- the summary: system information and the guests of the node -----------------------------

        // the processor rows of the summary read (cpuinfo), for the Summary and the Hardware tab
        function crNcCpu(t, ci, miss) {
            const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : null));
            const mhz = num(ci.mhz);
            const hvm = ci.hvm === undefined || ci.hvm === null || ci.hvm === '' ? null : (ci.hvm === true || String(ci.hvm) === '1');
            return {
                rows: [
                    { k: 'model', label: t('cpuModel'), value: ci.model, missing: miss },
                    { k: 'sockets', label: t('cpuSockets'), value: num(ci.sockets) != null ? String(num(ci.sockets)) : '', missing: miss },
                    { k: 'cores', label: t('cores'), value: num(ci.cores) != null ? String(num(ci.cores)) : '', missing: miss },
                    { k: 'cpus', label: t('logicalProcessors'), value: num(ci.cpus) != null ? String(num(ci.cpus)) : '', missing: miss },
                    { k: 'mhz', label: t('crNcCpuClock'), value: mhz > 0 ? crNnT(t, 'crNcMhz', { v: Math.round(mhz) }) : '', missing: miss },
                    { k: 'hvm', label: t('crNcHvm'), value: hvm == null ? '' : t(hvm ? 'crNcHvmYes' : 'crNcHvmNo'), missing: miss },
                ],
                flags: typeof ci.flags === 'string' ? ci.flags.split(/\s+/).filter(Boolean) : [],
            };
        }

        function CrNcCpuFlags({ flags }) {
            const { t } = useTranslation();
            if (!flags || !flags.length) return null;
            return (
                <details className="cr-nc-fold" data-cr-nsi-flags={flags.length}>
                    <summary>{crNnT(t, 'crNcCpuFlags', { n: flags.length })}</summary>
                    <p className="cr-mono cr-nc-flags">{flags.join(' ')}</p>
                </details>
            );
        }

        // what the page already holds about the node: the summary read, the live metrics, the
        // address /ip gave, the interface list once Configure > Network read it, the cluster
        // resources. Status and uptime are in the header and the health card, and not again here
        function CrNodeSysInfo({ node, summary, metrics, nodeIp, nodeIpSource, network, guests, onOpenNetwork, onOpenGuests }) {
            const { t } = useTranslation();
            const sum = crNsSummaryState(summary);
            const s = sum === 'ok' ? summary : null;
            const ci = s && s.cpuinfo && typeof s.cpuinfo === 'object' ? s.cpuinfo : {};
            const miss = sum === 'loading' ? t('crNcReadingShort') : sum === 'error' ? t('crNcSumFailedShort') : undefined;
            const cpu = crNcCpu(t, ci, miss);
            const standIn = /_fallback$/.test(nodeIpSource || '');
            const nics = Array.isArray(network) ? network.length : null;
            const list = Array.isArray(guests) ? guests : [];
            const count = (f) => list.filter(f).length;
            const pve = (s && s.pveversion) || (metrics && metrics.pveversion) || '';
            return (
                <div className="cr-nc-cols cr-nc-sum-cols">
                    <CrNcSection id="sysinfo" data-cr-nsi="" data-cr-nsi-sum={sum} title={t('systemInfo')} desc={t('crNcSysDesc')} className="cr-nc-wide">
                        <div className="cr-nc-groups">
                            <CrNcGroup id="software" title={t('crNcGrpSoftware')}>
                                <CrNcKv id="software" rows={[
                                    { k: 'node', label: t('crNcNodeName'), value: node, mono: true },
                                    { k: 'pve', label: t('pveVersion'), value: pve, missing: miss },
                                    { k: 'kernel', label: t('kernelVersion'), value: s && s.kversion, mono: true, missing: miss },
                                ]} />
                            </CrNcGroup>
                            <CrNcGroup id="cpu" title={t('crNcGrpCpu')}>
                                <CrNcKv id="cpu" rows={cpu.rows} />
                                <CrNcCpuFlags flags={cpu.flags} />
                            </CrNcGroup>
                            <CrNcGroup id="net" title={t('network')}>
                                <CrNcKv id="net" rows={[
                                    { k: 'ip', label: t('crNcNodeAddress'), value: nodeIp, mono: true, note: nodeIp && standIn ? t('crNcIpStandIn') : '' },
                                    { k: 'nics', label: t('networkInterfaces'),
                                      value: nics != null ? String(nics) : '',
                                      missing: network === null ? t('crNcNicsFailed') : t('crNcNicsUnread'),
                                      note: <button type="button" className="cr-nn-link cr-nc-inline-link" onClick={onOpenNetwork} data-cr-nsi-open-net="">{t(nics != null ? 'crNcOpenNetwork' : 'crNcReadNetwork')}</button> },
                                ]} />
                            </CrNcGroup>
                        </div>
                    </CrNcSection>
                    <CrNcSection id="guests" data-cr-nsi-guests="" title={t('crNcGuestsTitle')} desc={t('crNcGuestsDesc')}
                        actions={<CrButton className="cr-btn-xs" onClick={onOpenGuests} data-cr-nsi-open-guests="">{t('crNcOpenGuests')}</CrButton>}>
                        <CrNcKv id="guests" rows={[
                            { k: 'qemu', label: t('crNcGuestsVms'), value: String(count(g => g.type === 'qemu')) },
                            { k: 'lxc', label: t('crNcGuestsCts'), value: String(count(g => g.type === 'lxc')) },
                            { k: 'running', label: t('running'), value: String(count(g => g.status === 'running')) },
                            { k: 'stopped', label: t('crNgStopped'), value: String(count(g => g.status === 'stopped')) },
                        ]} />
                    </CrNcSection>
                </div>
            );
        }

        // --- DNS -------------------------------------------------------------------------------------

        // dns as loadTabData keeps it: undefined not read, null failed (dnsError says why), {} none set
        function CrNodeDns({ node, dns, dnsError, loading, saving, readOnly, onSave, onRetry, onDirty }) {
            const { t } = useTranslation();
            const [form, setForm] = useState(null);
            useEffect(() => { setForm(null); }, [node]);
            const label = { search: t('crNcDnsSearch'), dns1: crNnT(t, 'crNcDnsServer', { n: 1 }),
                            dns2: crNnT(t, 'crNcDnsServer', { n: 2 }), dns3: crNnT(t, 'crNcDnsServer', { n: 3 }) };
            const changes = crNcDnsChanges(dns, form).map(c => ({ ...c, label: label[c.k] }));
            // the same object the classic form sends: these four keys in this order, empty ones as ''
            const start = () => setForm({ search: dns?.search || '', dns1: dns?.dns1 || '', dns2: dns?.dns2 || '', dns3: dns?.dns3 || '' });
            const save = async () => { const ok = await onSave(form); if (ok) setForm(null); };
            const editing = !!form && !!dns;
            useCrNcDirty(onDirty, 'dns', editing && changes.length > 0);
            const body = () => {
                if (dns === undefined) return <CrNcState id="dns" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                if (dns === null) return <CrNcState id="dns" kind="error" onRetry={onRetry} retryDisabled={loading}>{t('dnsReadFailed').replace('{reason}', dnsError || t('connectionError'))}</CrNcState>;
                if (editing) {
                    return (
                        <div className="cr-nc-form">
                            {CR_NC_DNS_KEYS.map(k => {
                                const v = form[k];
                                const ipHint = k !== 'search' && v.trim() !== '' && !crNcIsIp(v);
                                return (
                                    <CrNcField key={k} id={`dns-${k}`} label={label[k]} changed={v !== (dns[k] || '')} was={dns[k] || ''}
                                        hint={ipHint ? t('crNcDnsNotIp') : k === 'search' ? t('crNcDnsSearchHint') : ''} hintTone={ipHint ? 'warning' : undefined}>
                                        <input id={`cr-nc-dns-${k}`} className={`cr-input${k === 'search' ? '' : ' cr-nc-mono-input'}`} value={v} spellCheck={false}
                                            autoComplete="off" onChange={e => setForm({ ...form, [k]: e.target.value })} disabled={readOnly} data-cr-nc-input={k} />
                                    </CrNcField>
                                );
                            })}
                        </div>
                    );
                }
                return (
                    <CrNcKv id="dns" label={t('dns')} rows={CR_NC_DNS_KEYS.map(k => ({ k, label: label[k], value: dns[k] || '', mono: k !== 'search', missing: t('crNcNotSet') }))} />
                );
            };
            return (
                <CrNcSection id="dns" data-cr-nc-dns="" title={t('dns')} desc={t('crNcDnsDesc')} editing={editing}
                    badge={editing ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : <CrNcUpdating on={loading && dns !== undefined} />}
                    actions={!editing && <CrButton icon={<Icons.Edit />} onClick={start} disabled={dns == null || readOnly} title={readOnly ? t('crNcReadOnly') : undefined} data-cr-nc-edit="dns">{t('edit')}</CrButton>}
                    foot={editing && (
                        <CrNcEditBar id="dns" count={changes.length} saving={saving} canSave={changes.length > 0} readOnly={readOnly}
                            onCancel={() => setForm(null)} onSave={save} note={t('crNcDnsSaveNote')}>
                            {changes.length > 0 && <CrNcChanges id="dns" rows={changes} />}
                        </CrNcEditBar>
                    )}>
                    {body()}
                </CrNcSection>
            );
        }

        // --- hosts file ------------------------------------------------------------------------------

        function crNcHasName(text, node) {
            if (!node) return true;
            const esc = String(node).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return new RegExp(`(^|\\s)${esc}(\\s|\\.|$)`, 'm').test(String(text || '').split('\n').filter(l => !/^\s*#/.test(l)).join('\n'));
        }

        function CrNcLines({ id, text, lines, log }) {
            const list = lines || String(text || '').replace(/\n$/, '').split('\n');
            return (
                <div className={`cr-nc-linebox${log ? ' cr-nc-log' : ''}`} data-cr-nc-lines={id} tabIndex={0}>
                    <ol className="cr-nc-lines">
                        {list.map((l, i) => <li key={i} className={/^\s*#/.test(l) ? 'cr-nc-line-comment' : undefined}>{l === '' ? ' ' : l}</li>)}
                    </ol>
                </div>
            );
        }

        // hosts: undefined not read, null failed (fail is the kept answer), '' an empty file
        function CrNodeHosts({ node, hosts, fail, loading, saving, readOnly, onSave, onRetry, onDirty }) {
            const { t } = useTranslation();
            const [text, setText] = useState(null);
            const [confirm, setConfirm] = useState(false);
            useEffect(() => { setText(null); setConfirm(false); }, [node]);
            const editing = text !== null && typeof hosts === 'string';
            const diff = useMemo(() => (editing ? crNcLineDiff(hosts, text) : null), [editing, hosts, text]);
            const count = diff && !diff.same ? Math.max(1, diff.added + diff.removed) : 0;
            const lostName = editing && crNcHasName(hosts, node) && !crNcHasName(text, node);
            useCrNcDirty(onDirty, 'hosts', !!diff && !diff.same);
            const save = async () => { const ok = await onSave(text); setConfirm(false); if (ok) setText(null); };
            const why = fail ? crNdWhy(t, fail) : '';
            const body = () => {
                if (hosts === undefined) return <CrNcState id="hosts" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                if (hosts === null) return <CrNcState id="hosts" kind="error" onRetry={onRetry} retryDisabled={loading}>{t('hostsReadFailed')}{why ? ` (${why})` : ''}</CrNcState>;
                if (editing) {
                    return (
                        <CrNcField id="hosts-text" label={t('crNcHostsEditLabel')} wide changed={!diff.same}
                            hint={lostName ? crNnT(t, 'crNcHostsLostName', { node }) : t('crNcHostsEditHint')} hintTone={lostName ? 'warning' : undefined}>
                            <textarea id="cr-nc-hosts-text" className="cr-input cr-nc-textarea" value={text} rows={14} spellCheck={false}
                                onChange={e => setText(e.target.value)} disabled={readOnly} data-cr-nc-input="hosts" />
                        </CrNcField>
                    );
                }
                if (hosts === '') return <CrNcState id="hosts" kind="empty">{t('crNcHostsEmpty')}</CrNcState>;
                return <CrNcLines id="hosts" text={hosts} />;
            };
            const lineCount = typeof hosts === 'string' && hosts !== '' ? hosts.replace(/\n$/, '').split('\n').length : 0;
            return (
                <CrNcSection id="hosts" data-cr-nc-hosts="" title={t('hostsFile')} desc={t('crNcHostsDesc')} editing={editing}
                    badge={editing ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : (
                        <>
                            {lineCount ? <span className="cr-muted cr-nn-count">{crNnT(t, 'crNcLineCount', { n: lineCount })}</span> : null}
                            <CrNcUpdating on={loading && hosts !== undefined} />
                        </>
                    )}
                    actions={!editing && <CrButton icon={<Icons.Edit />} onClick={() => setText(hosts || '')} disabled={hosts == null || readOnly} title={readOnly ? t('crNcReadOnly') : undefined} data-cr-nc-edit="hosts">{t('edit')}</CrButton>}
                    foot={editing && (
                        <CrNcEditBar id="hosts" count={count} title={t('crNcPendingTitle')} saving={saving} canSave={!diff.same} readOnly={readOnly} danger
                            saveLabel={t('crNcHostsSave')} note={t('crNcHostsSaveNote')} onCancel={() => setText(null)} onSave={() => setConfirm(true)}>
                            {!diff.same && (
                                <p className="cr-nc-diffsum" data-cr-nc-diffsum="">
                                    {diff.eolOnly ? t('crNcEolOnly') : crNnT(t, 'crNcLinesChanged', { a: diff.added, r: diff.removed })}
                                </p>
                            )}
                            {!diff.same && !diff.eolOnly && <CrNnDiffView diff={diff} />}
                        </CrNcEditBar>
                    )}>
                    {body()}
                    {confirm && editing && (
                        <CrNcConfirm id="hosts" title={crNnT(t, 'crNcHostsConfirmTitle', { node })} goLabel={t('crNcHostsConfirmGo')} busy={saving}
                            onCancel={() => { if (!saving) setConfirm(false); }} onConfirm={save}>
                            <p>{crNnT(t, 'crNcHostsConfirmBody', { node })}</p>
                            <p className="cr-nc-diffsum">{diff.eolOnly ? t('crNcEolOnly') : crNnT(t, 'crNcLinesChanged', { a: diff.added, r: diff.removed })}</p>
                            {lostName && <p className="cr-nc-warn" data-cr-nc-confirm-warn="">{crNnT(t, 'crNcHostsLostName', { node })}</p>}
                            <p>{t('crNcHostsConfirmRisk')}</p>
                        </CrNcConfirm>
                    )}
                </CrNcSection>
            );
        }

        // --- time ------------------------------------------------------------------------------------

        // time: undefined not read, {} the answer of a failed read on the node as well as of a node
        // that sent nothing (the route cannot tell them apart); fail is a refused or failed request
        function CrNodeTime({ node, time, fail, loading, saving, readOnly, onSave, onRetry, onDirty }) {
            const { t } = useTranslation();
            const [tz, setTz] = useState(null);
            useEffect(() => { setTz(null); }, [node]);
            const cur = time && typeof time.timezone === 'string' ? time.timezone : '';
            const editing = tz !== null && time !== undefined && !fail;
            const zones = useMemo(() => (cur && !TIMEZONES.includes(cur) ? [cur, ...TIMEZONES] : TIMEZONES), [cur]);
            const fmt = (sec) => (Number(sec) > 0 ? new Date(Number(sec) * 1000).toLocaleString(crLocale(), { timeZone: 'UTC' }) : '');
            const changed = editing && tz !== '' && tz !== cur;
            useCrNcDirty(onDirty, 'time', changed);
            const save = async () => { const ok = await onSave(tz); if (ok) setTz(null); };
            const body = () => {
                if (time === undefined) return <CrNcState id="time" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                if (fail) return <CrNcState id="time" kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, fail) })}</CrNcState>;
                return (
                    <>
                        {!cur && <CrNcState id="time" kind="warning" onRetry={onRetry} retryDisabled={loading}>{t('crNcTimeNoZone')}</CrNcState>}
                        {editing ? (
                            <div className="cr-nc-form">
                                <CrNcField id="time-tz" label={t('crNcTimezone')} changed={changed} was={cur} hint={t('crNcTimeHint')}>
                                    <select id="cr-nc-time-tz" className="cr-select cr-nc-select" value={tz} onChange={e => setTz(e.target.value)} disabled={readOnly} data-cr-nc-input="timezone">
                                        {!cur && <option value="">{t('crNcTimezonePick')}</option>}
                                        {zones.map(z => <option key={z} value={z}>{z}</option>)}
                                    </select>
                                </CrNcField>
                            </div>
                        ) : (
                            <CrNcKv id="time" rows={[
                                { k: 'tz', label: t('crNcTimezone'), value: cur },
                                { k: 'local', label: t('crNcLocalTime'), value: fmt(time.localtime) },
                                { k: 'utc', label: t('crNcUtcTime'), value: fmt(time.time) },
                            ]} />
                        )}
                        {!editing && (time.localtime || time.time) ? <p className="cr-muted cr-nc-note">{t('crNcTimeAsRead')}</p> : null}
                    </>
                );
            };
            return (
                <CrNcSection id="time" data-cr-nc-time="" title={t('timeConfig')} desc={t('crNcTimeDesc')} editing={editing}
                    badge={editing ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : <CrNcUpdating on={loading && time !== undefined} />}
                    actions={!editing && <CrButton icon={<Icons.Edit />} onClick={() => setTz(cur)} disabled={time === undefined || !!fail || readOnly} title={readOnly ? t('crNcReadOnly') : undefined} data-cr-nc-edit="time">{t('edit')}</CrButton>}
                    foot={editing && (
                        <CrNcEditBar id="time" count={changed ? 1 : 0} saving={saving} canSave={changed} readOnly={readOnly}
                            onCancel={() => setTz(null)} onSave={save} note={t('crNcTimeSaveNote')}>
                            {changed && <CrNcChanges id="time" rows={[{ k: 'timezone', label: t('crNcTimezone'), from: cur, to: tz }]} />}
                        </CrNcEditBar>
                    )}>
                    {body()}
                </CrNcSection>
            );
        }

        // --- certificates ----------------------------------------------------------------------------

        const CR_NC_EXP_TONE = { expired: 'error', soon: 'warning', ok: 'neutral', none: 'neutral' };

        function CrNcCert({ cert, now }) {
            const { t } = useTranslation();
            const ex = crNcExpiry(cert.notafter, now);
            const san = Array.isArray(cert.san) ? cert.san.filter(Boolean) : [];
            const bits = Number(cert['public-key-bits']);
            const key = [cert['public-key-type'], Number.isFinite(bits) && bits > 0 ? crNnT(t, 'crNcBits', { n: bits }) : ''].filter(Boolean).join(', ');
            const exLabel = ex.state === 'none' ? t('crNcCertNoExpiry')
                : ex.state === 'expired' ? crNnT(t, ex.days === 0 ? 'crNcCertExpiredToday' : ex.days === 1 ? 'crNcCertExpiredOne' : 'crNcCertExpired', { n: ex.days })
                : crNnT(t, ex.days === 0 ? 'crNcCertToday' : ex.days === 1 ? 'crNcCertOneDay' : 'crNcCertDays', { n: ex.days });
            return (
                <li className="cr-nc-item" data-cr-nc-cert={cert.filename || ''} data-cr-nc-expiry={ex.state}>
                    <div className="cr-nc-item-head">
                        <span className="cr-mono cr-nc-item-name">{cert.filename || t('crNcCertNoName')}</span>
                        <CrBadge tone={CR_NC_EXP_TONE[ex.state]} dot={ex.state === 'expired' || ex.state === 'soon'}>{exLabel}</CrBadge>
                    </div>
                    <CrNcKv id={`cert-${cert.filename || ''}`} rows={[
                        { k: 'subject', label: t('crNcCertSubject'), value: cert.subject, mono: true },
                        { k: 'issuer', label: t('crNcCertIssuer'), value: cert.issuer, mono: true },
                        cert.notbefore != null ? { k: 'from', label: t('crNcCertFrom'), value: crNcDate(cert.notbefore) } : null,
                        { k: 'until', label: t('crNcCertUntil'), value: crNcDate(cert.notafter) },
                        san.length ? { k: 'san', label: t('crNcCertSan'), value: <span className="cr-nc-chips">{san.map(n => <span key={n} className="cr-nn-chip">{n}</span>)}</span> } : null,
                        key ? { k: 'key', label: t('crNcCertKey'), value: key } : null,
                        cert.fingerprint ? { k: 'fp', label: t('crNcCertFp'), value: cert.fingerprint, mono: true } : null,
                    ]} />
                </li>
            );
        }

        // certs: undefined not read, [] what the route answers for none as well as for a failed read on
        // the node; fail is a refused or failed request. The upload form keeps the view's state, so
        // handleCertUpload sends what is typed here
        function CrNodeCerts({ node, certs, fail, loading, saving, readOnly, open, setOpen, form, setForm, onUpload, onRetry, onDirty }) {
            const { t } = useTranslation();
            const [confirm, setConfirm] = useState(false);
            useEffect(() => { setConfirm(false); }, [node]);
            const now = Date.now();
            const list = Array.isArray(certs) ? certs.filter(c => c && typeof c === 'object') : [];
            const custom = list.find(c => c.filename === 'pveproxy-ssl.pem');
            // the form state lives in the view and outlasts a sub tab change: a failed read shows no form
            const editing = !!open && certs !== undefined && !fail;
            useCrNcDirty(onDirty, 'certs', editing && !!(form.cert || form.key));
            const n = crNcPemCount(form.cert);
            const certHint = form.cert && !n ? t('crNcCertNoPem') : n > 1 ? crNnT(t, 'crNcCertChain', { n }) : '';
            const keyHint = form.key && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(form.key) ? t('crNcKeyNoPem') : '';
            const cancel = () => { setOpen(false); setForm({ cert: '', key: '', restart: true }); };
            const upload = async () => { await onUpload(); setConfirm(false); };
            // LW Nov 2026 - every upload asks first: it replaces the custom certificate, with or without the restart
            const go = () => setConfirm(true);
            const pending = [
                { k: 'custom', label: t('crNcCertCustom'), from: custom ? crNnT(t, 'crNcCertCustomHas', { d: crNcDate(custom.notafter) || '?' }) : t('crNcCertCustomNone'),
                  to: form.cert ? crNnT(t, 'crNcCertCustomNew', { n }) : '' },
            ];
            const body = () => {
                if (certs === undefined) return <CrNcState id="certs" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                if (fail) return <CrNcState id="certs" kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, fail) })}</CrNcState>;
                return (
                    <>
                        {list.length === 0 ? (
                            <CrNcState id="certs" kind="empty" onRetry={onRetry} retryDisabled={loading}>{t('crNcCertsEmpty')}</CrNcState>
                        ) : (
                            <>
                                <ul className="cr-nc-items">{list.map((c, i) => <CrNcCert key={c.filename || i} cert={c} now={now} />)}</ul>
                                <p className="cr-muted cr-nc-note">{t('crNcCertsServed')}</p>
                            </>
                        )}
                        {editing ? (
                            <div className="cr-nc-form cr-nc-form-wide" data-cr-nc-certform="">
                                <CrNcField id="cert-pem" label={t('crNcCertPem')} wide hint={certHint} hintTone={form.cert && !n ? 'warning' : undefined}>
                                    <textarea id="cr-nc-cert-pem" className="cr-input cr-nc-textarea" rows={6} spellCheck={false} value={form.cert} disabled={readOnly}
                                        placeholder="-----BEGIN CERTIFICATE-----" onChange={e => setForm({ ...form, cert: e.target.value })} data-cr-nc-input="cert" />
                                </CrNcField>
                                <CrNcField id="cert-key" label={t('crNcKeyPem')} wide hint={keyHint} hintTone={keyHint ? 'warning' : undefined}>
                                    <textarea id="cr-nc-cert-key" className="cr-input cr-nc-textarea" rows={6} spellCheck={false} value={form.key} disabled={readOnly}
                                        placeholder="-----BEGIN PRIVATE KEY-----" onChange={e => setForm({ ...form, key: e.target.value })} data-cr-nc-input="key" />
                                </CrNcField>
                                <label className="cr-nn-ack cr-nc-field-wide" data-cr-nc-restart="">
                                    <input type="checkbox" checked={form.restart} disabled={readOnly} onChange={e => setForm({ ...form, restart: e.target.checked })} />
                                    <span>{t('crNcCertRestart')}</span>
                                </label>
                            </div>
                        ) : (
                            <CrNcDanger id="cert-upload" title={t('crNcCertUploadTitle')} desc={t('crNcCertUploadDesc')}>
                                <CrButton variant="danger" icon={<Icons.Upload />} onClick={() => setOpen(true)} disabled={readOnly} title={readOnly ? t('crNcReadOnly') : undefined} data-cr-nc-cert-open="">
                                    {t('crNcCertUploadGo')}
                                </CrButton>
                            </CrNcDanger>
                        )}
                    </>
                );
            };
            return (
                <CrNcSection id="certs" data-cr-nc-certs="" title={t('certificates')} desc={t('crNcCertsDesc')} editing={editing}
                    badge={editing ? <CrBadge tone="info" dot={false}>{t('crNcEditing')}</CrBadge> : (
                        <>
                            {list.length ? <span className="cr-muted cr-nn-count">{list.length}</span> : null}
                            <CrNcUpdating on={loading && certs !== undefined} />
                        </>
                    )}
                    foot={editing && (
                        <CrNcEditBar id="certs" count={form.cert || form.key ? 1 : 0} saving={saving} canSave={!!form.cert && !!form.key} readOnly={readOnly} danger
                            saveLabel={t(form.restart ? 'crNcCertUploadRestart' : 'crNcCertUpload')} onCancel={cancel} onSave={go}
                            note={t(form.restart ? 'crNcCertRestartNote' : 'crNcCertNoRestartNote')}>
                            {(form.cert || form.key) ? <CrNcChanges id="certs" rows={pending} /> : null}
                        </CrNcEditBar>
                    )}>
                    {body()}
                    {confirm && editing && (
                        <CrNcConfirm id="certs" title={crNnT(t, form.restart ? 'crNcCertConfirmTitle' : 'crNcCertConfirmTitleUpload', { node })}
                            goLabel={t(form.restart ? 'crNcCertUploadRestart' : 'crNcCertUpload')} busy={saving}
                            onCancel={() => { if (!saving) setConfirm(false); }} onConfirm={upload}>
                            <p data-cr-nc-confirm-replace="">{crNnT(t, 'crNcCertConfirmBody', { node })}</p>
                            <p data-cr-nc-confirm-restart={form.restart ? 'on' : 'off'}>{t(form.restart ? 'crNcCertConfirmRestart' : 'crNcCertNoRestartNote')}</p>
                            <p>{t('crNcCertConfirmRisk')}</p>
                        </CrNcConfirm>
                    )}
                </CrNcSection>
            );
        }

        // --- syslog ----------------------------------------------------------------------------------

        // lines: undefined not read, [] for no lines as well as for a failed read on the node; fail is
        // a refused request (the route refuses a caller confined to a pool) or a failed one
        function CrNodeSyslog({ node, lines, fail, loading, onRefresh }) {
            const { t } = useTranslation();
            const [q, setQ] = useState('');
            useEffect(() => { setQ(''); }, [node]);
            const all = Array.isArray(lines) ? lines.map(l => (l && typeof l === 'object' ? String(l.t ?? l.n ?? '') : String(l))) : [];
            const needle = q.trim().toLowerCase();
            const shown = needle ? all.filter(l => l.toLowerCase().includes(needle)) : all;
            const body = () => {
                if (lines === undefined) return <CrNcState id="syslog" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRefresh}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                if (fail) return <CrNcState id="syslog" kind="error" onRetry={onRefresh} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, fail) })}</CrNcState>;
                if (!all.length) return <CrNcState id="syslog" kind="empty">{t('crNcSyslogEmpty')}</CrNcState>;
                return (
                    <>
                        <div className="cr-nc-toolbar">
                            <div className="cr-search-box">
                                <Icons.Search className="cr-search-ico" />
                                <input type="search" className="cr-input" value={q} placeholder={t('crNcSyslogFilter')} aria-label={t('crNcSyslogFilter')}
                                    onChange={e => setQ(e.target.value)} data-cr-nc-syslog-q="" />
                            </div>
                            <span className="cr-muted cr-nn-count" data-cr-nc-syslog-count={shown.length}>
                                {needle ? crNnT(t, 'crNcSyslogShown', { n: shown.length, m: all.length }) : crNnT(t, 'crNcSyslogCount', { n: all.length })}
                            </span>
                        </div>
                        {shown.length ? <CrNcLines id="syslog" lines={shown} log /> : <CrNcState id="syslog-filter" kind="empty">{t('crNcSyslogNoMatch')}</CrNcState>}
                    </>
                );
            };
            return (
                <CrNcSection id="syslog" data-cr-nc-syslog="" title={t('syslog')} desc={t('crNcSyslogDesc')}
                    badge={<CrNcUpdating on={loading && lines !== undefined} />}
                    actions={<CrButton icon={<Icons.RefreshCw />} onClick={onRefresh} disabled={loading} data-cr-nc-refresh="syslog">{t('refresh')}</CrButton>}>
                    {body()}
                </CrNcSection>
            );
        }

        // the five sub tabs of Configure > System, each from the one system read of the view
        function CrNodeSystemCfg({ tab, node, data, loading, saving, readOnly, onRetry, onSaveDns, onSaveHosts, onSaveTime, cert, onDirty }) {
            const fail = data.sysFail || {};
            return (
                <div className="cr-nc-page" data-cr-nc-tab={tab}>
                    {tab === 'dns' && <CrNodeDns node={node} dns={data.dns} dnsError={data.dnsError} loading={loading} saving={saving} readOnly={readOnly} onSave={onSaveDns} onRetry={onRetry} onDirty={onDirty} />}
                    {tab === 'hosts' && <CrNodeHosts node={node} hosts={data.hosts} fail={fail.hosts} loading={loading} saving={saving} readOnly={readOnly} onSave={onSaveHosts} onRetry={onRetry} onDirty={onDirty} />}
                    {tab === 'time' && <CrNodeTime node={node} time={data.time} fail={fail.time} loading={loading} saving={saving} readOnly={readOnly} onSave={onSaveTime} onRetry={onRetry} onDirty={onDirty} />}
                    {tab === 'certs' && <CrNodeCerts node={node} certs={data.certificates} fail={fail.certificates} loading={loading} saving={saving} readOnly={readOnly}
                        open={cert.open} setOpen={cert.setOpen} form={cert.form} setForm={cert.setForm} onUpload={cert.upload} onRetry={onRetry} onDirty={onDirty} />}
                    {tab === 'syslog' && <CrNodeSyslog node={node} lines={data.syslog} fail={fail.syslog} loading={loading} onRefresh={onRetry} />}
                </div>
            );
        }
