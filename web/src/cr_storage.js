        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: storage balancing - LW Oct 2026
        // The Storage Balancing sub tab of a cluster's Datastore tab. A storage cluster is a
        // named group of shared storages PegaProx balances disks between; it has no nodes of
        // its own. The overview is worked out from the group list and the datastores that
        // DatastoreTab already holds, so opening the tab asks nothing per group. The balancing
        // status (a PVE read, plus a guest scan when the group is out of balance) is read for
        // the picked group only. A member that is unavailable, missing or unread is said to be,
        // and stays out of the spread; a failed read is never "balanced". Writes go to the
        // classic routes with the classic bodies, the page waits for the answer and shows a
        // refusal instead of the new value. One disk per approval, never a batch.
        // ═══════════════════════════════════════════════════════════

        const CR_SB_STEPS = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];   // the classic slider
        // run_auto_storage_balance waits for threshold + tolerance; 5 is what the server takes
        // for a group stored without one. The tolerance select offers the classic slider's range
        const CR_SB_MARGIN = 5;
        const CR_SB_TOL_STEPS = Array.from({ length: 21 }, (_, i) => i);
        // the PVE task types of a disk move: qm move-disk and pct move-volume
        const CR_SB_MOVES = new Set(['qmmove', 'move_volume']);
        const CR_SB_CHIPS = 8;
        const CR_SB_RECENT = 10;

        const crSbNames = (v) => (Array.isArray(v) ? v.filter(x => typeof x === 'string' && x) : []);
        const crSbTrue = (v) => !!v && !crOff(v);
        // the status route reads a missing flag as on, the worker as off
        const crSbOn = (g) => !g || g.enabled == null || crSbTrue(g.enabled);
        const crSbArmed = (g) => !!g && crSbTrue(g.enabled) && crSbTrue(g.auto_balance);
        const crSbPts = (v, t) => (Number.isFinite(v) ? crFill(t('crSbPoints'), { n: v.toFixed(1) }) : '-');
        const crSbMargin = (g) => (g && g.tolerance != null && g.tolerance !== '' && Number.isFinite(Number(g.tolerance)) ? Number(g.tolerance) : CR_SB_MARGIN);

        function crSbEvery(sec) {
            const n = Number(sec);
            if (!Number.isFinite(n) || n <= 0) return '';
            if (n % 3600 === 0) return `${n / 3600} h`;
            if (n % 60 === 0) return `${n / 60} min`;
            return `${n} s`;
        }

        // a server error as text: a string, or the field map PVE sends back
        function crSbError(body, code, t) {
            const e = body && body.error;
            let text = typeof e === 'string' ? e : '';
            if (!text && e && typeof e === 'object') text = Object.keys(e).map(k => `${k}: ${e[k]}`).join('; ');
            return [text, code ? `HTTP ${code}` : ''].filter(Boolean).join(' - ') || t('crLoadFailed');
        }

        async function crSbRead(authFetch, url) {
            const r = await authFetch(url);
            if (!r) return { state: 'offline' };
            const body = await r.json().catch(() => null);
            if (r.ok) {
                // a status always carries its member list, also an empty one
                if (!body || typeof body !== 'object' || Array.isArray(body) || !Array.isArray(body.storages)) return { state: 'malformed', code: r.status };
                return { state: 'ok', body };
            }
            const state = r.status === 403 ? 'forbidden' : r.status === 404 ? 'notfound' : r.status === 429 ? 'limited' : 'error';
            return { state, code: r.status, body };
        }

        async function crSbWrite(authFetch, url, method, data) {
            const opts = { method };
            if (data !== undefined) {
                opts.headers = { 'Content-Type': 'application/json' };
                opts.body = JSON.stringify(data);
            }
            const r = await authFetch(url, opts);
            if (!r) return { ok: false, offline: true };
            const body = await r.json().catch(() => null);
            return { ok: r.ok, code: r.status, body };
        }

        // --- members, as the datastore list sees them ------------------------------------

        // unread: the datastore list was never read, so a member is not judged against it
        function crSbMember(name, shared, localNames, unread) {
            const def = shared.get(name) || null;
            const st = def ? crStorageState(def) : null;
            let why = '';
            if (!def) why = unread ? 'listunread' : localNames.has(name) ? 'local' : 'missing';
            else if (st.offline) why = 'offline';
            else if (st.disabled) why = 'disabled';
            else if (st.inactive) why = 'inactive';
            else if (st.pct == null) why = 'nousage';
            const content = def && typeof def.content === 'string' ? def.content.split(',').map(x => x.trim()).filter(Boolean) : null;
            return {
                name, def, st, why, usable: !why, type: (def && def.type) || '', content,
                on: def && Array.isArray(def.active_on) ? def.active_on : null,
                off: def && Array.isArray(def.inactive_on) ? def.inactive_on : null,
            };
        }

        function crSbSum(members) {
            const readable = members.filter(m => m.usable);
            let total = 0, used = 0, avail = 0, availAll = true;
            readable.forEach(m => {
                total += m.st.total;
                used += m.st.used;
                if (m.st.avail == null) availAll = false; else avail += m.st.avail;
            });
            const pcts = readable.map(m => m.st.pct);
            const on = new Set();
            const off = new Set();
            // a node is partial when a member that is in use here is not mounted on it
            members.forEach(m => { (m.on || []).forEach(n => on.add(n)); if (m.usable) (m.off || []).forEach(n => off.add(n)); });
            return {
                readable: readable.length, bad: members.length - readable.length,
                total: readable.length ? total : null, used: readable.length ? used : null,
                avail: readable.length && availAll ? avail : null, pct: total > 0 ? used / total * 100 : null,
                spread: pcts.length >= 2 ? Math.max(...pcts) - Math.min(...pcts) : null,
                types: Array.from(new Set(members.map(m => m.type).filter(Boolean))).sort(),
                on, off, partial: members.filter(m => m.usable && m.st.partial).length,
                // LW Nov 2026 - a member the list knows only as a node's own storage is "not shared", as the detail says
                missing: members.filter(m => m.why === 'missing').length,
                local: members.filter(m => m.why === 'local').length,
                listunread: members.filter(m => m.why === 'listunread').length,
            };
        }

        // A member of the status the server could read. It says so itself (usable), and leaves the
        // others out of its spread and its recommendations (storage.py _member_stats); an answer
        // without the flag counts by its figures
        const crSbSrvUsable = (s) => !!s && (typeof s.usable === 'boolean' ? s.usable : Number(s.total) > 0)
            && Number(s.total) > 0 && Number.isFinite(Number(s.used));

        // What the balancer works with (the status read) where there is one, the list where not.
        // A member the status lists is judged by the server: its figures or its state, also a
        // storage of one node the server read on that node (shared false)
        function crSbFigures(members, status) {
            const srv = status && status.state === 'ok' ? status.body.storages : null;
            return members.map(m => {
                const s = srv ? srv.find(x => x && x.storage === m.name) || null : null;
                let total = null, used = null, avail = null, from = null;
                if (crSbSrvUsable(s)) {
                    total = Number(s.total); used = Number(s.used);
                    avail = Number.isFinite(Number(s.avail)) ? Number(s.avail) : null;
                    from = 'server';
                } else if (m.usable && !s) {
                    total = m.st.total; used = m.st.used; avail = m.st.avail; from = 'list';
                }
                const pct = total > 0 ? used / total * 100 : null;
                const why = !s ? m.why : from === 'server' ? '' : (typeof s.state === 'string' && s.state) || 'unreadable';
                return {
                    ...m, srv: s, total, used, avail, pct, from, why, whySrv: !!s && !!why,
                    type: m.type || (s && typeof s.type === 'string' ? s.type : ''),
                    usable: pct != null,
                    localOn: from === 'server' && s.shared === false ? String(s.node || '-') : null,
                    unread: !!srv && !s,
                };
            });
        }

        function crSbSpread(rows) {
            const p = rows.filter(r => r.usable).map(r => r.pct);
            return p.length >= 2 ? Math.max(...p) - Math.min(...p) : null;
        }

        // the server's state words are the classic ones (storage.js memberStateText)
        const CR_SB_SRV_WHY = { missing: 'sbMemberMissing', disabled: 'sbMemberDisabled', inactive: 'sbMemberInactive',
                                unavailable: 'sbMemberUnavailable', no_size: 'sbMemberNoSize', unreadable: 'sbMemberUnreadable' };
        const crSbWhy = (m, t) => {
            if (m.whySrv) {
                const text = t(CR_SB_SRV_WHY[m.why] || 'sbMemberUnreadable').replace('{node}', (m.srv && m.srv.node) || '-');
                return text.charAt(0).toUpperCase() + text.slice(1);
            }
            return {
                missing: t('crSbWhyMissing'), local: t('crSbWhyLocal'), offline: t('crDsNodeOffline'), disabled: t('crDsDisabled'),
                inactive: t('crDsInactive'), nousage: t('storageRawNoUsage'), listunread: t('crSbWhyListUnread'),
            }[m.why] || '';
        };
        const crSbWhyTone = (m) => (m.whySrv ? (m.why === 'disabled' || m.why === 'no_size' ? 'neutral' : 'error')
            : m.why === 'missing' || m.why === 'local' || m.why === 'inactive' || m.why === 'offline' ? 'error' : 'neutral');

        // --- one move, worked out from the figures on screen -------------------------------

        function crSbPlan(rec, rows, guest, t) {
            const src = rows.find(r => r.name === rec.source) || null;
            const tgt = rows.find(r => r.name === rec.target) || null;
            const size = Number(rec.disk_size) > 0 ? Number(rec.disk_size) : null;
            const ct = (guest && guest.type === 'lxc') || /^(rootfs|mp\d+)$/.test(String(rec.disk || ''));
            const risks = [];
            const add = (level, key, vars) => risks.push({ level, key, text: crFill(t(key), vars || {}) });
            // a move the server marks as one it refuses (a running container), with its reason
            const refused = rec.movable === false;
            const refusedWhy = !refused ? '' : rec.blocked === 'ct_running' ? t('sbCtRunning')
                : (typeof rec.blocked_reason === 'string' && rec.blocked_reason) || t('crSbNotMovable');
            if (refused) add('block', 'crSbRiskRefused', { why: refusedWhy });
            if (!tgt || !tgt.usable) {
                add('block', 'crSbRiskTargetDown', { target: rec.target, why: tgt ? (crSbWhy(tgt, t) || t('crSbWhyNoFigures')) : t('crSbWhyMissing') });
            }
            if (src && tgt && src.type && tgt.type && src.type !== tgt.type) add('warn', 'crSbRiskTypes', { from: src.type, to: tgt.type });
            if (tgt && tgt.content && !tgt.content.includes(ct ? 'rootdir' : 'images')) {
                add('warn', ct ? 'crSbRiskContentCt' : 'crSbRiskContentVm', { target: rec.target, content: tgt.content.join(', ') });
            }
            if (size == null) add('warn', 'crSbRiskSize');
            else if (tgt && tgt.avail != null && tgt.avail < size) add('warn', 'crSbRiskFree', { free: crBytes(tgt.avail), size: crBytes(size) });
            if (guest && guest.node && tgt && Array.isArray(tgt.off) && tgt.off.includes(guest.node)) {
                add('warn', 'crSbRiskNode', { target: rec.target, node: guest.node });
            }
            // a running container is one the server refuses, said above
            if (rec.vm_status === 'running' && !ct) add('info', 'crSbRiskRunning');
            if (!guest) add('info', 'crSbRiskNoGuest');

            let after = null;
            if (size != null && src && tgt && src.usable && tgt.usable) {
                // the declared size, not what the disk takes: on thin storage it can be more than the
                // source uses at all. Then the figures are bounds: the source frees at most what it uses
                const thin = size > src.used;
                const s2 = Math.max(0, src.used - size) / src.total * 100;
                const t2 = (tgt.used + size) / tgt.total * 100;
                const moved = rows.map(r => (r.name === src.name ? { ...r, pct: s2 } : r.name === tgt.name ? { ...r, pct: t2 } : r));
                after = { src: s2, tgt: t2, spread: crSbSpread(moved), thin };
                if (thin) add('info', 'crSbRiskThin', { size: crBytes(size), source: src.name, used: crBytes(src.used) });
            }
            return { src, tgt, size, ct, risks, after, refused, refusedWhy, blocked: risks.some(r => r.level === 'block'), spread: crSbSpread(rows) };
        }

        // --- the parts ---------------------------------------------------------------------

        function CrSbCallout({ tone = 'info', id, children, onRetry }) {
            const { t } = useTranslation();
            const icon = tone === 'error' ? <Icons.AlertCircle className="w-4 h-4" /> : tone === 'warning' ? <Icons.AlertTriangle className="w-4 h-4" />
                : tone === 'success' ? <Icons.CheckCircle className="w-4 h-4" /> : <Icons.Info className="w-4 h-4" />;
            return (
                <div className={`cr-callout cr-callout-${tone}`} role={tone === 'error' ? 'alert' : 'status'} data-cr-sb-note={id || ''}>
                    {icon}
                    <div>{children}</div>
                    {onRetry && <button type="button" className="cr-btn cr-drift-retry" onClick={onRetry}>{t('retry')}</button>}
                </div>
            );
        }

        // the nodes that mount a storage, and the ones it is configured for but not active on
        function CrSbNodes({ m }) {
            const { t } = useTranslation();
            const on = m.on || [];
            const off = m.off || [];
            if (!on.length && !off.length) return null;
            const few = on.length + off.length <= CR_SB_CHIPS;
            const shownOff = off.slice(0, CR_SB_CHIPS);
            return (
                <span className="cr-sb-chips" data-cr-sb-nodes={`${on.length}/${on.length + off.length}`}
                    title={`${t('activeOn')}: ${on.join(', ') || '-'}${off.length ? `; ${t('unreachableFrom')}: ${off.join(', ')}` : ''}`}>
                    {few
                        ? on.map(n => <span key={n} className="cr-sb-chip cr-sb-chip-on" data-cr-sb-node={n}>{n}</span>)
                        : <span className="cr-sb-chip cr-sb-chip-on">{crFill(t('crSbMountedOn'), { n: on.length })}</span>}
                    {shownOff.map(n => <span key={`x${n}`} className="cr-sb-chip cr-sb-chip-off" data-cr-sb-node-off={n}>{n}</span>)}
                    {off.length > shownOff.length && <span className="cr-sb-chip cr-sb-chip-off">+{off.length - shownOff.length}</span>}
                </span>
            );
        }

        function CrSbPrereq({ ok, children }) {
            return (
                <li className={`cr-sb-pre cr-sb-pre-${ok ? 'ok' : 'no'}`} data-cr-sb-pre={ok ? 'ok' : 'no'}>
                    <span className="cr-ico" aria-hidden="true">{ok ? <Icons.CheckCircle /> : <Icons.XCircle />}</span>
                    <span>{children}</span>
                </li>
            );
        }

        function CrSbEmpty({ datastores, dsLoading, listUnread, may, standby, onCreate }) {
            const { t } = useTranslation();
            const shared = (datastores && datastores.shared) || [];
            const usable = shared.filter(s => { const st = crStorageState(s); return st && !st.unavailable; }).length;
            const twoShared = !listUnread && shared.length >= 2;
            const canConfig = may('storage.config');
            const ready = twoShared && canConfig && !standby;
            const why = listUnread ? t('crSbPreSharedUnread') : !twoShared ? t('crSbNeedTwo') : standby ? t('crSbStandbyShort') : !canConfig ? t('crSbNeedConfig') : '';
            return (
                <section className="cr-sb-empty" data-cr-sb-empty="" aria-labelledby="cr-sb-empty-title">
                    <span className="cr-sb-empty-ico" aria-hidden="true"><Icons.Layers /></span>
                    <div className="cr-sb-empty-body">
                        <h2 className="cr-sb-empty-title" id="cr-sb-empty-title">{t('noStorageClusters')}</h2>
                        <p className="cr-sb-empty-text">{t('crSbEmptyText')}</p>
                        <ul className="cr-sb-pres" aria-label={t('crSbPrereqs')}>
                            <CrSbPrereq ok={twoShared}>
                                {listUnread ? t('crSbPreSharedUnread') : dsLoading && !shared.length ? t('crSbPreSharedLoading')
                                    : crFill(t('crSbPreShared'), { n: shared.length, ok: usable })}
                            </CrSbPrereq>
                            <CrSbPrereq ok={canConfig && !standby}>{standby ? t('crSbStandbyShort') : t('crSbPreConfig')}</CrSbPrereq>
                        </ul>
                        <p className="cr-sb-empty-note">{t('crSbPreTenant')}</p>
                        <div className="cr-sb-empty-act">
                            <CrButton variant="primary" icon={<Icons.Plus />} onClick={onCreate} disabled={!ready}
                                data-cr-sb-create="" title={why || undefined}>
                                {t('createStorageCluster')}
                            </CrButton>
                            {!ready && <span className="cr-muted" data-cr-sb-create-why="">{why}</span>}
                        </div>
                    </div>
                </section>
            );
        }

        // one member: its bar, figures and state; an unusable one says why and draws no bar
        function CrSbMemberRow({ r, mean, canEdit, canRemove, busy, onRemove }) {
            const { t } = useTranslation();
            const tone = r.usable ? crStoreTone(r.pct) : 'neutral';
            const dev = r.usable && mean != null ? r.pct - mean : null;
            return (
                <li className={`cr-sb-member${r.usable ? '' : ' cr-sb-member-off'}`} data-cr-sb-member={r.name}
                    data-cr-sb-usable={r.usable ? '1' : '0'} data-cr-sb-tone={tone}>
                    <div className="cr-sb-mline">
                        <span className="cr-sb-mname">{r.name}</span>
                        {r.type && <span className="cr-ds-type">{r.type}</span>}
                        {r.why && <CrBadge tone={crSbWhyTone(r)}>
                            <span data-cr-sb-why={r.why} data-cr-sb-from={r.whySrv ? 'server' : 'list'}>{crSbWhy(r, t)}</span>
                        </CrBadge>}
                        {!r.why && r.unread && <CrBadge tone="warning" title={t('crSbNotInStatusHint')}><span data-cr-sb-why="unread">{t('crSbUnread')}</span></CrBadge>}
                        {r.st && r.st.partial && <CrBadge tone="warning"><span data-cr-sb-why="partial">{r.st.partial.on.length}/{r.st.partial.on.length + r.st.partial.off.length} {t('nodes')}</span></CrBadge>}
                        <span className="cr-sb-mside">
                            {r.usable && <span className="cr-mono" data-cr-sb-pct={r.pct.toFixed(1)}>{crPct(r.pct, 1)}</span>}
                            {dev != null && <span className={`cr-sb-dev${Math.abs(dev) >= 0.05 ? '' : ' cr-muted'}`} data-cr-sb-dev={dev.toFixed(1)}
                                title={t('crSbDevHint')}>{dev >= 0 ? '+' : ''}{dev.toFixed(1)}</span>}
                            {canEdit && canRemove && (
                                <button type="button" className="cr-icon-btn cr-icon-danger cr-sb-rm" disabled={!!busy}
                                    aria-label={crFill(t('crSbRemoveMember'), { name: r.name })} title={crFill(t('crSbRemoveMember'), { name: r.name })}
                                    data-cr-sb-remove={r.name} onClick={() => onRemove(r.name)}>
                                    <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                                </button>
                            )}
                        </span>
                    </div>
                    {r.usable ? (
                        <div className={`cr-sb-bar cr-tone-${tone}`} aria-hidden="true">
                            <span style={{ width: `${Math.min(100, Math.max(0, r.pct))}%` }} />
                            {mean != null && <i style={{ left: `${Math.min(100, Math.max(0, mean))}%` }} />}
                        </div>
                    ) : (
                        <div className="cr-sb-bar cr-sb-bar-none" aria-hidden="true" />
                    )}
                    <div className="cr-sb-mline cr-sb-mfig">
                        {r.usable ? (
                            <span className="cr-mono" data-cr-sb-used="">
                                {crFill(t('crUsedOf'), { used: crBytes(r.used), total: crBytes(r.total) })}
                                {r.avail != null && <>, {crBytes(r.avail)} {t('free')}</>}
                                {r.localOn && <span className="cr-muted" data-cr-sb-local={r.localOn}> - {t('sbMemberLocal').replace('{node}', r.localOn)}</span>}
                            </span>
                        ) : (
                            <span className="cr-muted" data-cr-sb-nofig="">{t('crSbLeftOut')}</span>
                        )}
                        <CrSbNodes m={r} />
                    </div>
                </li>
            );
        }

        function CrSbMoveDialog({ rec, plan, guest, busy, error, onCancel, onConfirm }) {
            const { t } = useTranslation();
            const ref = useRef(null);
            const back = useRef(typeof document !== 'undefined' ? document.activeElement : null);
            const [titleId] = useState(() => `cr-sb-move-${++crPanelSeq}`);
            useEffect(() => {
                if (ref.current) ref.current.focus({ preventScroll: true });
                return () => {
                    const el = back.current;
                    if (el && el.isConnected && el.focus) el.focus({ preventScroll: true });
                };
            }, []);
            const onKey = (e) => {
                if (e.key === 'Tab') { crKeepTab(e, ref.current); return; }
                if (e.key === 'Escape') {
                    e.preventDefault();
                    e.stopPropagation();
                    if (!busy) onCancel();
                }
            };
            const name = guest ? (guest.name || `${plan.ct ? 'CT' : 'VM'} ${rec.vmid}`) : (rec.vm_name || `${plan.ct ? 'CT' : 'VM'} ${rec.vmid}`);
            const bar = (pct) => (
                <span className={`cr-sb-pbar cr-tone-${crStoreTone(pct)}`} aria-hidden="true"><span style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} /></span>
            );
            const side = (label, r, to) => (
                <tr data-cr-sb-plan={label}>
                    <th scope="row">{label === 'src' ? t('crSbFrom') : t('crSbTo')}</th>
                    <td><span className="cr-strong">{r ? r.name : (label === 'src' ? rec.source : rec.target)}</span>{r && r.type ? <span className="cr-ds-type"> {r.type}</span> : null}</td>
                    <td className="cr-mono" data-cr-sb-before="">{r && r.usable ? <>{bar(r.pct)} {crPct(r.pct, 1)}</> : <span className="cr-muted">{t('crSbNoFigures')}</span>}</td>
                    <td className="cr-mono" data-cr-sb-after="">{to != null ? <>{bar(to)} {plan.after && plan.after.thin ? `${t(label === 'src' ? 'crSbAtLeast' : 'crSbAtMost')} ` : ''}{crPct(to, 1)}</> : <span className="cr-muted">{t('crSbUnknown')}</span>}</td>
                </tr>
            );
            return ReactDOM.createPortal(
                <div className="cr-sb-layer" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onCancel(); }}>
                    <div className="cr-sb-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref}
                        onKeyDown={onKey} data-cr-sb-dialog="">
                        <header className="cr-sp-head">
                            <div className="cr-sp-titles">
                                <h2 className="cr-sp-title" id={titleId}>{crFill(t('crSbMoveTitle'), { disk: rec.disk, name })}</h2>
                                <div className="cr-sp-sub" data-cr-sb-calc="">{t('crSbCalcNote')}</div>
                            </div>
                            <button type="button" className="cr-icon-btn" onClick={onCancel} disabled={busy} aria-label={t('close')} title={`${t('close')} (Esc)`}>
                                <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                            </button>
                        </header>
                        <div className="cr-sb-dbody">
                            <dl className="cr-sb-facts">
                                <dt>{t('crSbGuest')}</dt>
                                <dd data-cr-sb-fact="guest">{name} <span className="cr-muted cr-mono">{plan.ct ? 'CT' : 'VM'} {rec.vmid}</span>
                                    {guest && guest.node ? <span className="cr-muted"> - {crFill(t('crSbOnNode'), { node: guest.node })}</span> : null}
                                    {rec.vm_status ? <span className="cr-muted"> - {rec.vm_status}</span> : null}</dd>
                                <dt>{t('crSbDisk')}</dt>
                                <dd className="cr-mono" data-cr-sb-fact="disk">{rec.disk}</dd>
                                <dt>{t('crSbSize')}</dt>
                                <dd data-cr-sb-fact="size">{plan.size != null ? <>{crBytes(plan.size)} <span className="cr-muted">{t('crSbSizeNote')}</span></> : <span className="cr-muted">{t('crSbUnknown')}</span>}</dd>
                            </dl>
                            <table className="cr-sb-ptable">
                                <thead><tr><th scope="col" /><th scope="col">{t('storage')}</th><th scope="col">{t('crSbNow')}</th><th scope="col">{t('crSbAfter')}</th></tr></thead>
                                <tbody>
                                    {side('src', plan.src, plan.after ? plan.after.src : null)}
                                    {side('tgt', plan.tgt, plan.after ? plan.after.tgt : null)}
                                    <tr data-cr-sb-plan="spread">
                                        <th scope="row">{t('crSbSpread')}</th>
                                        <td className="cr-muted">{t('crSbSpreadOf')}</td>
                                        <td className="cr-mono">{crSbPts(plan.spread, t)}</td>
                                        <td className="cr-mono">{plan.after ? crSbPts(plan.after.spread, t) : <span className="cr-muted">{t('crSbUnknown')}</span>}</td>
                                    </tr>
                                </tbody>
                            </table>
                            <p className="cr-sb-fine">{t('crSbCalcFoot')}</p>
                            {plan.risks.length > 0 && (
                                <ul className="cr-sb-risks" aria-label={t('crSbRisks')}>
                                    {plan.risks.map(r => (
                                        <li key={r.key} className={`cr-sb-risk cr-sb-risk-${r.level}`} data-cr-sb-risk={r.key} data-cr-sb-level={r.level}>
                                            <span className="cr-ico" aria-hidden="true">{r.level === 'block' ? <Icons.XCircle /> : r.level === 'warn' ? <Icons.AlertTriangle /> : <Icons.Info />}</span>
                                            <span>{r.text}</span>
                                        </li>
                                    ))}
                                </ul>
                            )}
                            <p className="cr-sb-fine" data-cr-sb-checks="">{t('crSbServerChecks')}</p>
                            <p className="cr-sb-fine">{t('crSbDeletesSource')}</p>
                            {error && <CrSbCallout tone="error" id="move-error"><p>{error}</p></CrSbCallout>}
                        </div>
                        <footer className="cr-sp-foot cr-sb-dfoot">
                            {plan.blocked && <span className="cr-sb-blocked" data-cr-sb-blocked="">{t('crSbBlocked')}</span>}
                            <CrButton onClick={onCancel} disabled={busy} data-cr-sb-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={onConfirm} disabled={busy || plan.blocked} data-cr-sb-confirm=""
                                icon={busy ? <span className="cr-spinner" /> : <Icons.HardDrive />}>
                                {busy ? t('crSbStarting') : t('crSbMoveOne')}
                            </CrButton>
                        </footer>
                    </div>
                </div>,
                document.body
            );
        }

        // --- the page ------------------------------------------------------------------------

        // dsFail: the last read of the datastore list failed ({ msg, hasData }); without data from an
        // earlier read the members are not judged against it
        function CrStorageBalancing({ clusterId, authFetch, datastores, dsLoading, dsFail, onDsRetry, list, listRead, setList, reloadList, may, standby,
                                      guests, onOpenGuest, tasks, onCreate }) {
            const { t } = useTranslation();
            const [selId, setSelId] = useState(null);
            const [status, setStatus] = useState(null);
            const [busy, setBusy] = useState({});
            const [msg, setMsg] = useState(null);
            const [started, setStarted] = useState({});    // rec key -> { upid, vmid, at }
            const [dialog, setDialog] = useState(null);    // the rec in the preview
            const [moveBusy, setMoveBusy] = useState(false);
            const [moveErr, setMoveErr] = useState('');
            const [narrow, setNarrow] = useState(false);
            const rootRef = useRef(null);
            const seq = useRef(0);
            const base = `${API_URL}/clusters/${clusterId}`;
            const canEdit = may('storage.config');

            useEffect(() => {
                const el = rootRef.current;
                if (!el || typeof ResizeObserver === 'undefined') return undefined;
                const ro = new ResizeObserver(() => setNarrow(el.clientWidth < 1100));
                ro.observe(el);
                setNarrow(el.clientWidth < 1100);
                return () => ro.disconnect();
            }, []);

            const shared = useMemo(() => {
                const m = new Map();
                ((datastores && datastores.shared) || []).forEach(s => { if (s && s.storage) m.set(s.storage, s); });
                return m;
            }, [datastores]);
            // the names of local storages, once per datastore answer (200 nodes hold many)
            const localNames = useMemo(() => {
                const out = new Set();
                const local = (datastores && datastores.local) || {};
                Object.keys(local).forEach(n => (local[n] || []).forEach(s => { if (s && s.storage) out.add(s.storage); }));
                return out;
            }, [datastores]);
            const groups = Array.isArray(list) ? list : [];
            const listUnread = !!dsFail && !dsFail.hasData;
            const rows = useMemo(() => groups.filter(g => g && g.id != null).map(g => {
                const members = crSbNames(g.storages).map(n => crSbMember(n, shared, localNames, listUnread));
                return { id: g.id, g, members, sum: crSbSum(members) };
            }), [groups, shared, localNames, listUnread]);
            const sel = rows.find(r => r.id === selId) || null;
            const guestMap = useMemo(() => crGuestMap(Array.isArray(guests) ? guests : []), [guests]);

            const listState = (listRead && listRead.state) || 'loading';
            const listOk = listState === 'ok';

            // --- reads ---
            const readStatus = async (id) => {
                const n = ++seq.current;
                setStatus({ id, state: 'loading' });
                const res = await crSbRead(authFetch, `${base}/storage-clusters/${encodeURIComponent(id)}/status`);
                if (n !== seq.current) return;
                setStatus({ id, ...res, at: Date.now() });
            };
            const pick = (r) => {
                if (!r) return;
                setMsg(null);
                setSelId(r.id);
                readStatus(r.id);
            };
            const st = status && sel && status.id === sel.id ? status : null;

            // --- writes: the classic routes and bodies; the list changes only on an answer that says so ---
            const work = async (key, fn) => {
                if (busy[key]) return null;
                setBusy(b => ({ ...b, [key]: true }));
                try { return await fn(); } finally { setBusy(b => { const n = { ...b }; delete n[key]; return n; }); }
            };
            const refusal = (res) => (res.offline ? t('crDriftOffline') : crSbError(res.body, res.code, t));
            const put = (g, patch, key, reread) => work(key, async () => {
                const res = await crSbWrite(authFetch, `${base}/storage-clusters/${encodeURIComponent(g.id)}`, 'PUT', patch);
                if (!res.ok) {
                    setMsg({ tone: 'error', id: g.id, text: crFill(t('crSbRefused'), { msg: refusal(res) }) });
                    return false;
                }
                const back = res.body && typeof res.body === 'object' && !Array.isArray(res.body) && res.body.id === g.id ? res.body : {};
                setList(prev => (Array.isArray(prev) ? prev.map(x => (x && x.id === g.id ? { ...x, ...patch, ...back } : x)) : prev));
                setMsg({ tone: 'success', id: g.id, text: t('crSbSaved') });
                if (reread) readStatus(g.id);
                return true;
            });
            const setEnabled = (g, on) => put(g, { enabled: on }, 'enabled', true);
            const setAuto = (g, on) => {
                if (on) {
                    const ask = crFill(t('crSbArmAsk'), {
                        every: crSbEvery(g.check_interval == null ? 3600 : g.check_interval) || '-',
                        trigger: (Number(g.threshold == null ? 20 : g.threshold) || 0) + crSbMargin(g),
                    });
                    if (!confirm(ask)) return;
                }
                put(g, { auto_balance: on }, 'auto', false);
            };
            const setThreshold = (g, v) => put(g, { threshold: v }, 'threshold', true);
            // LW Nov 2026 - the server keeps the tolerance now and the worker acts above threshold + tolerance
            const setTolerance = (g, v) => put(g, { tolerance: v }, 'tolerance', false);
            const addMember = (g, name) => put(g, { storages: crSbNames(g.storages).concat([name]) }, 'members', true);
            const removeMember = (g, name) => {
                const now = crSbNames(g.storages);
                if (now.length <= 2) return;
                put(g, { storages: now.filter(s => s !== name) }, 'members', true);
            };
            const remove = (g) => {
                if (!confirm(t('confirmDeleteCluster') || 'Delete this storage cluster?')) return;
                work('delete', async () => {
                    const res = await crSbWrite(authFetch, `${base}/storage-clusters/${encodeURIComponent(g.id)}`, 'DELETE');
                    if (!res.ok) {
                        setMsg({ tone: 'error', id: g.id, text: crFill(t('crSbRefused'), { msg: refusal(res) }) });
                        return;
                    }
                    setList(prev => (Array.isArray(prev) ? prev.filter(x => !(x && x.id === g.id)) : prev));
                    setSelId(null);
                    setStatus(null);
                    setMsg({ tone: 'success', id: null, text: crFill(t('crSbDeleted'), { name: g.name || g.id }) });
                });
            };

            // --- one move per approval ---
            const recKey = (rec) => `${rec.vmid}|${rec.disk}|${rec.target}`;
            const openMove = (rec) => { setMoveErr(''); setDialog(rec); };
            const closeMove = () => { if (!moveBusy) setDialog(null); };
            const confirmMove = async () => {
                const rec = dialog;
                if (!rec || moveBusy) return;
                setMoveBusy(true);
                setMoveErr('');
                const res = await crSbWrite(authFetch, `${base}/storage-balancing/migrate`, 'POST',
                    { vmid: rec.vmid, disk: rec.disk, target: rec.target });
                setMoveBusy(false);
                if (!res.ok || (res.body && res.body.success === false)) {
                    setMoveErr(crFill(t('crSbNotStarted'), { msg: refusal(res) }));
                    return;
                }
                const upid = res.body && typeof res.body.upid === 'string' ? res.body.upid : '';
                setStarted(s => ({ ...s, [recKey(rec)]: { upid, vmid: rec.vmid, at: Date.now() } }));
                setDialog(null);
                setMsg({ tone: 'success', id: sel ? sel.id : null, upid, vmid: rec.vmid,
                         text: crFill(t(upid ? 'crSbMoveStarted' : 'crSbMoveStartedNoId'), { disk: rec.disk, target: rec.target }) });
            };
            const openTasks = (vmid) => {
                try { window.dispatchEvent(new CustomEvent('cr-tc-open', { detail: { cluster: clusterId, q: vmid != null ? String(vmid) : '' } })); } catch (_) {}
            };

            // --- the overview table ---
            const columns = useMemo(() => [
                { key: 'name', label: t('name'), flex: true, min: 140, sortValue: r => r.g.name || '', text: r => r.g.name || '',
                  render: r => (
                      <span className="cr-sb-gname">
                          <span className={`cr-dot${crSbOn(r.g) ? ' cr-dot-success' : ''}`} aria-hidden="true" />
                          <span className="cr-strong">{r.g.name || r.id}</span>
                          {!crSbOn(r.g) && <CrBadge tone="neutral"><span data-cr-sb-off="">{t('crSbOff')}</span></CrBadge>}
                      </span>
                  ) },
                { key: 'members', label: t('crSbColStorages'), width: 150, sortValue: r => r.members.length,
                  text: r => r.members.map(m => m.name).join(' '),
                  render: r => (
                      <span className="cr-sb-mlist" title={r.members.map(m => `${m.name}${m.type ? ` (${m.type})` : ''}`).join(', ')}>
                          <span className="cr-mono">{r.members.length}</span>
                          <span className="cr-muted">{r.members.map(m => m.name).join(', ')}</span>
                          {r.sum.types.length > 1 && (
                              <span className="cr-ds-warn cr-tone-text cr-tone-warning" role="img" data-cr-sb-mixed=""
                                  aria-label={crFill(t('crSbMixed'), { types: r.sum.types.join(', ') })} title={crFill(t('crSbMixed'), { types: r.sum.types.join(', ') })}>
                                  <Icons.AlertTriangle />
                              </span>
                          )}
                      </span>
                  ) },
                { key: 'nodes', label: t('crSbColNodes'), width: 112, hidden: narrow, title: t('crSbColNodesHint'),
                  sortValue: r => r.sum.on.size, text: r => Array.from(r.sum.on).join(' '),
                  render: r => (r.sum.on.size || r.sum.off.size ? (
                      <span title={`${t('activeOn')}: ${Array.from(r.sum.on).join(', ') || '-'}${r.sum.off.size ? `; ${t('unreachableFrom')}: ${Array.from(r.sum.off).join(', ')}` : ''}`}
                          data-cr-sb-gnodes={r.sum.on.size}>
                          {crFill(t('crSbNodesN'), { n: r.sum.on.size })}
                          {r.sum.off.size > 0 && <span className="cr-tone-text cr-tone-warning"> ({crFill(t('crSbNodesOff'), { n: r.sum.off.size })})</span>}
                      </span>
                  ) : <span className="cr-muted">-</span>) },
                { key: 'use', label: t('crSbColUse'), width: 104, title: crStoreScale(t), sortValue: r => r.sum.pct,
                  render: r => <span data-cr-sb-use={r.sum.pct != null ? r.sum.pct.toFixed(1) : ''}><CrMeter value={r.sum.pct} tone={crStoreTone(r.sum.pct)} digits={0}
                      title={r.sum.pct != null ? `${crPct(r.sum.pct, 1)}. ${crStoreScale(t)}` : t('crSbNoReadable')} /></span> },
                { key: 'cap', label: t('crSbColCapacity'), width: 140, mono: true, sortValue: r => r.sum.total,
                  render: r => (r.sum.total != null ? `${crBytes(r.sum.used)} / ${crBytes(r.sum.total)}` : '') },
                { key: 'free', label: t('crSbColFree'), width: 84, align: 'right', mono: true, sortValue: r => r.sum.avail,
                  render: r => (r.sum.avail != null ? <span data-cr-sb-free="">{crBytes(r.sum.avail)}</span> : '') },
                { key: 'spread', label: t('crSbColSpread'), width: 112, title: t('crSbColSpreadHint'), sortValue: r => r.sum.spread,
                  render: r => {
                      if (r.sum.spread == null) return <span className="cr-muted" data-cr-sb-spread="">-</span>;
                      const thr = r.g.threshold == null || r.g.threshold === '' ? NaN : Number(r.g.threshold);
                      const over = Number.isFinite(thr) && r.sum.spread > thr;
                      return (
                          <span className={over ? 'cr-tone-text cr-tone-warning' : ''} data-cr-sb-spread={r.sum.spread.toFixed(1)} data-cr-sb-over={over ? '1' : '0'}>
                              <span className="cr-mono">{r.sum.spread.toFixed(1)}</span>
                              {Number.isFinite(thr) && <span className="cr-muted"> / {thr} {t('crSbPtsShort')}</span>}
                          </span>
                      );
                  } },
                { key: 'auto', label: t('autoBalance'), width: 118, sortValue: r => (crSbArmed(r.g) ? 2 : crSbTrue(r.g.auto_balance) ? 1 : 0),
                  render: r => (crSbArmed(r.g) ? <CrBadge tone="warning"><span data-cr-sb-auto="armed">{t('crSbArmed')}</span></CrBadge>
                      : crSbTrue(r.g.auto_balance) ? <span className="cr-muted" data-cr-sb-auto="idle" title={t('crSbAutoIdleHint')}>{t('crSbAutoIdle')}</span>
                      : <span className="cr-muted" data-cr-sb-auto="off">{t('crSbAutoOff')}</span>) },
                { key: 'last', label: t('crSbColLastCheck'), width: 164, mono: true, hidden: narrow, title: t('crSbLastHint'),
                  sortValue: r => r.g.last_auto_run || null,
                  render: r => (r.g.last_auto_run ? <span title={`${r.g.last_auto_run} (${t('crDriftServerTime')})`}>{crDriftTime(r.g.last_auto_run)}</span> : '') },
                { key: 'state', label: t('crSbColMembers'), width: 136, title: t('crSbColMembersHint'), sortValue: r => r.sum.bad,
                  render: r => {
                      const n = r.members.length;
                      if (r.sum.listunread) return <CrBadge tone="neutral"><span data-cr-sb-state="unread">{t('crSbStateListUnread')}</span></CrBadge>;
                      if (r.sum.missing || r.sum.local) {
                          // one badge each, side by side or one under the other in the narrow column
                          return (
                              <span className="cr-sb-states">
                                  {r.sum.missing > 0 && <CrBadge tone="error"><span data-cr-sb-state="missing">{crFill(t('crSbStateMissing'), { n: r.sum.missing })}</span></CrBadge>}
                                  {r.sum.local > 0 && <CrBadge tone="error"><span data-cr-sb-state="local">{crFill(t('crSbStateLocal'), { n: r.sum.local })}</span></CrBadge>}
                              </span>
                          );
                      }
                      if (r.sum.bad) return <CrBadge tone="error"><span data-cr-sb-state="bad">{crFill(t('crSbStateBad'), { n: r.sum.bad, of: n })}</span></CrBadge>;
                      if (r.sum.partial) return <CrBadge tone="warning"><span data-cr-sb-state="partial">{t('crSbStatePartial')}</span></CrBadge>;
                      return <CrBadge tone="success"><span data-cr-sb-state="ok">{crFill(t('crSbStateOk'), { n })}</span></CrBadge>;
                  } },
            ], [t, narrow]);

            // --- the detail ---
            const detail = sel ? (() => {
                const g = sel.g;
                const figs = crSbFigures(sel.members, st);
                const readable = figs.filter(r => r.usable);
                const mean = readable.length >= 2 ? readable.reduce((a, r) => a + r.pct, 0) / readable.length : null;
                const spread = crSbSpread(figs);
                const body = st && st.state === 'ok' ? st.body : null;
                // the members the server could read; it lists the others with their state
                const srvN = body ? body.storages.filter(crSbSrvUsable).length : 0;
                // null is no figure (Number(null) would be 0)
                const fig = (v) => (v == null || v === '' ? NaN : Number(v));
                const thr = body && Number.isFinite(fig(body.threshold)) ? fig(body.threshold) : fig(g.threshold);
                const imb = body && Number.isFinite(fig(body.imbalance)) ? fig(body.imbalance) : null;
                // why no member could be read (the node list refused, no node online), as the server says it
                const readError = body && typeof body.read_error === 'string' && body.read_error ? body.read_error : '';
                let verdict = 'unread', judge = '';
                if (st && st.state === 'loading') verdict = 'loading';
                else if (body) {
                    // a status without the server's spread or threshold (an older server, a proxy) cannot be judged
                    judge = srvN < 2 || readable.length < 2 ? 'members' : imb == null ? 'imbalance' : !Number.isFinite(thr) ? 'threshold' : '';
                    verdict = judge ? 'unknown' : imb > thr ? 'above' : 'within';
                }
                const recs = body && Array.isArray(body.recommendations) ? body.recommendations.filter(x => x && x.vmid != null) : [];
                const totals = crSbSum(sel.members);
                const tot = readable.reduce((a, r) => ({ total: a.total + r.total, used: a.used + r.used, avail: r.avail == null || a.avail == null ? null : a.avail + r.avail }),
                    { total: 0, used: 0, avail: 0 });
                const capPct = tot.total > 0 ? tot.used / tot.total * 100 : null;
                const shown = readable.length ? tot : null;
                const addable = ((datastores && datastores.shared) || []).filter(s => s && s.storage && !crSbNames(g.storages).includes(s.storage));
                const thrNow = fig(g.threshold);
                const steps = CR_SB_STEPS.includes(thrNow) || !Number.isFinite(thrNow) ? CR_SB_STEPS : CR_SB_STEPS.concat([thrNow]).sort((a, b) => a - b);
                const every = crSbEvery(g.check_interval == null ? 3600 : g.check_interval);
                const margin = crSbMargin(g);
                const tolSteps = CR_SB_TOL_STEPS.includes(margin) ? CR_SB_TOL_STEPS : CR_SB_TOL_STEPS.concat([margin]).sort((a, b) => a - b);
                const trig = Number.isFinite(thrNow) ? thrNow + margin : null;
                const lock = !canEdit ? (standby ? t('crSbStandbyShort') : t('crSbNeedConfig')) : '';
                const myMsg = msg && (msg.id === g.id || msg.id == null) ? msg : null;
                const movesHere = (Array.isArray(tasks) ? tasks : []);
                const keptUpids = new Set(Object.values(started).map(s => s.upid).filter(Boolean));
                const recent = movesHere.filter(x => x && x.upid && (CR_SB_MOVES.has(x.type) || keptUpids.has(x.upid)))
                    .sort((a, b) => (b.starttime || 0) - (a.starttime || 0));

                const recRows = recs.map((rec, i) => {
                    const guest = guestMap ? guestMap.get(String(rec.vmid)) || null : null;
                    return { key: `${recKey(rec)}#${i}`, rec, guest, plan: crSbPlan(rec, figs, guest, t), started: started[recKey(rec)] || null };
                });
                const refusedRows = recRows.filter(r => r.plan.refused);
                const refusedWhy = Array.from(new Set(refusedRows.map(r => r.plan.refusedWhy))).join('; ');
                const recCols = [
                    { key: 'guest', label: t('crSbGuest'), flex: true, min: 150, sortValue: r => (r.guest && r.guest.name) || r.rec.vm_name || '',
                      text: r => `${(r.guest && r.guest.name) || r.rec.vm_name || ''} ${r.rec.vmid}`,
                      render: r => {
                          const label = (r.guest && r.guest.name) || r.rec.vm_name || `${r.plan.ct ? 'CT' : 'VM'} ${r.rec.vmid}`;
                          return (
                              <span className="cr-ds-owner">
                                  {r.guest && onOpenGuest
                                      ? <button type="button" className="cr-link" data-cr-sb-guest={String(r.rec.vmid)}
                                          title={crFill(t('crTaskOpenTarget'), { name: label })} onClick={(e) => { e.stopPropagation(); onOpenGuest(r.guest); }}>{label}</button>
                                      : <span title={t('crDsNotInInventory')}>{label}</span>}
                                  <span className="cr-muted cr-mono">{r.plan.ct ? 'CT' : 'VM'} {r.rec.vmid}</span>
                              </span>
                          );
                      } },
                    { key: 'node', label: t('node'), width: 84, sortValue: r => (r.guest && r.guest.node) || null, render: r => (r.guest && r.guest.node) || '' },
                    { key: 'disk', label: t('crSbDisk'), width: 72, mono: true, render: r => r.rec.disk },
                    { key: 'move', label: t('crSbColMove'), width: 190, text: r => `${r.rec.source} ${r.rec.target}`,
                      render: r => (
                          <span className="cr-sb-move">
                              <span>{r.rec.source}</span>
                              <span className="cr-muted" aria-hidden="true"><Icons.ArrowRight /></span>
                              <span className="cr-sr-only">{t('crSbTo')}</span>
                              <span>{r.rec.target}</span>
                          </span>
                      ) },
                    { key: 'size', label: t('crSbSize'), width: 84, align: 'right', mono: true, sortValue: r => r.plan.size,
                      render: r => (r.plan.size != null ? crBytes(r.plan.size) : <span className="cr-muted" title={t('crSbRiskSize')}>{t('crSbUnknown')}</span>) },
                    { key: 'impact', label: t('crSbColImpact'), width: 168, title: t('crSbCalcNote'),
                      render: r => (r.plan.after
                          ? <span className="cr-mono" data-cr-sb-impact={`${r.plan.after.src.toFixed(1)}|${r.plan.after.tgt.toFixed(1)}`}>
                              {crPct(r.plan.src.pct, 0)}&rarr;{r.plan.after.thin ? '\u2265' : ''}{crPct(r.plan.after.src, 0)} / {crPct(r.plan.tgt.pct, 0)}&rarr;{r.plan.after.thin ? '\u2264' : ''}{crPct(r.plan.after.tgt, 0)}
                            </span>
                          : <span className="cr-muted">{t('crSbUnknown')}</span>) },
                    { key: 'risks', label: t('crSbRisks'), width: 92, sortValue: r => r.plan.risks.filter(x => x.level !== 'info').length,
                      render: r => {
                          const n = r.plan.risks.filter(x => x.level !== 'info').length;
                          const tip = r.plan.risks.map(x => x.text).join('\n');
                          if (r.plan.blocked) return <CrBadge tone="error" title={tip}><span data-cr-sb-risk-n="blocked">{t('crSbBlockedShort')}</span></CrBadge>;
                          return n ? <CrBadge tone="warning" title={tip}><span data-cr-sb-risk-n={n}>{crFill(t('crSbRiskN'), { n })}</span></CrBadge>
                              : <span className="cr-muted" title={tip}>{t('crSbRiskNone')}</span>;
                      } },
                    { key: 'act', label: '', menuLabel: t('crSbColAction'), width: 140, resizable: false, sortable: false, text: () => '',
                      render: r => (r.started
                          ? <span className="cr-sb-started">
                                <CrBadge tone="info"><span data-cr-sb-started={r.started.upid || ''}>{t('crSbStarted')}</span></CrBadge>
                                <button type="button" className="cr-link" onClick={(e) => { e.stopPropagation(); openTasks(r.rec.vmid); }} data-cr-sb-tasks="">{t('crSbOpenTasks')}</button>
                            </span>
                          : r.plan.refused
                              ? <span className="cr-muted" data-cr-sb-refused={r.rec.blocked || 'server'} title={r.plan.refusedWhy}>{t('crSbNotMovable')}</span>
                          : canEdit
                              ? <CrButton className="cr-btn-xs" icon={<Icons.Eye />} data-cr-sb-preview={recKey(r.rec)}
                                  onClick={(e) => { e.stopPropagation(); openMove(r.rec); }}>{t('crSbPreview')}</CrButton>
                              : <span className="cr-muted" title={lock}>{t('crSbReadOnly')}</span>) },
                ];
                const recentCols = [
                    { key: 'state', label: t('status'), width: 96, sortValue: r => crTaskState(r),
                      render: r => <CrBadge tone={crTaskTone(r)}><span data-cr-sb-tstate={crTaskState(r)}>{crTaskLabel(crTaskState(r), t)}</span></CrBadge> },
                    { key: 'op', label: t('crSbColOp'), width: 130, render: r => (r.type === 'move_volume' ? t('crSbMoveCt') : r.type === 'qmmove' ? t('crSbMoveVm') : r.type) },
                    { key: 'guest', label: t('crSbGuest'), flex: true, min: 120, sortValue: r => r.vmid || '',
                      render: r => {
                          const g2 = guestMap ? guestMap.get(String(r.vmid)) || null : null;
                          if (g2 && onOpenGuest) return <button type="button" className="cr-link" onClick={(e) => { e.stopPropagation(); onOpenGuest(g2); }}>{g2.name || r.vmid}</button>;
                          return <span className="cr-mono">{r.vmid || ''}</span>;
                      } },
                    { key: 'node', label: t('node'), width: 84, render: r => r.node || '' },
                    { key: 'start', label: t('startTime'), width: 150, mono: true, sortValue: r => r.starttime || null, render: r => (r.starttime ? crDate(r.starttime) : '') },
                    { key: 'who', label: t('user'), width: 100, render: r => r.pegaprox_user || (r.user ? String(r.user).split('@')[0] : '') },
                    { key: 'here', label: '', menuLabel: t('crSbStartedHere'), width: 110, sortable: false, resizable: false, text: () => '',
                      render: r => (keptUpids.has(r.upid) ? <CrBadge tone="info" dot={false}><span data-cr-sb-here="">{t('crSbStartedHere')}</span></CrBadge> : '') },
                ];

                return (
                    <section className="cr-sb-detail" data-cr-sb-detail={g.id} aria-labelledby="cr-sb-dtitle">
                        <div className="cr-sb-dhead">
                            <div className="cr-sb-dhead-main">
                                <span className="cr-ico cr-pagehead-ico" aria-hidden="true"><Icons.Layers /></span>
                                <h2 className="cr-sb-dtitle" id="cr-sb-dtitle">{g.name || g.id}</h2>
                                {crSbOn(g) ? <CrBadge tone="success"><span data-cr-sb-enabled="1">{t('enabled')}</span></CrBadge>
                                    : <CrBadge tone="neutral"><span data-cr-sb-enabled="0">{t('crSbOff')}</span></CrBadge>}
                                {crSbArmed(g) && <CrBadge tone="warning"><span data-cr-sb-armed="">{t('crSbArmed')}</span></CrBadge>}
                                <span className="cr-muted">{crFill(t('crSbMembersN'), { n: sel.members.length })}</span>
                                {g.created && <span className="cr-muted" title={`${g.created} (${t('crDriftServerTime')})`}>{crFill(t('crSbCreated'), { at: crDriftTime(g.created) })}</span>}
                            </div>
                            <div className="cr-sb-dhead-act">
                                <CrButton icon={<span className={st && st.state === 'loading' ? 'cr-ds-spin' : ''}><Icons.RotateCw /></span>}
                                    onClick={() => readStatus(g.id)} disabled={!!(st && st.state === 'loading')} data-cr-sb-refresh="">
                                    {t('crSbRead')}
                                </CrButton>
                                {canEdit && (
                                    <CrButton variant="danger" icon={<Icons.Trash />} onClick={() => remove(g)} disabled={!!busy.delete} data-cr-sb-delete="">
                                        {t('delete')}
                                    </CrButton>
                                )}
                            </div>
                        </div>

                        {myMsg && (
                            <CrSbCallout tone={myMsg.tone} id={`msg-${myMsg.tone}`}>
                                <p data-cr-sb-msg={myMsg.tone}>{myMsg.text}</p>
                                {myMsg.upid && <p className="cr-mono cr-sb-upid" data-cr-sb-upid="">{myMsg.upid}</p>}
                                {myMsg.vmid != null && (
                                    <p><button type="button" className="cr-link" onClick={() => openTasks(myMsg.vmid)} data-cr-sb-tasks="">{t('crSbOpenTasks')}</button>
                                        <span className="cr-muted"> - {t('crSbStatusBefore')}</span></p>
                                )}
                            </CrSbCallout>
                        )}

                        <div className="cr-sb-settings" data-cr-sb-settings="">
                            <label className="cr-switch" title={lock || undefined}>
                                <input type="checkbox" checked={busy.enabled ? !crSbOn(g) : crSbOn(g)} disabled={!canEdit || !!busy.enabled}
                                    onChange={e => setEnabled(g, e.target.checked)} data-cr-sb-toggle="enabled" />
                                <span>{t('enabled')}</span>
                            </label>
                            <label className="cr-switch" title={lock || t('crSbAutoHint')}>
                                <input type="checkbox" checked={busy.auto ? !crSbTrue(g.auto_balance) : crSbTrue(g.auto_balance)} disabled={!canEdit || !!busy.auto}
                                    onChange={e => setAuto(g, e.target.checked)} data-cr-sb-toggle="auto" />
                                <span>{t('autoBalance')}</span>
                            </label>
                            <label className="cr-sb-field" title={lock || t('thresholdDesc')}>
                                <span>{t('balancingThreshold')}</span>
                                <select className="cr-select" value={Number.isFinite(thrNow) ? String(thrNow) : ''} disabled={!canEdit || !!busy.threshold}
                                    onChange={e => setThreshold(g, Number(e.target.value))} data-cr-sb-threshold="">
                                    {!Number.isFinite(thrNow) && <option value="">-</option>}
                                    {steps.map(v => <option key={v} value={String(v)}>{crFill(t('crSbPoints'), { n: v })}</option>)}
                                </select>
                            </label>
                            <label className="cr-sb-field" title={lock || t('storageToleranceDesc')}>
                                <span>{t('migrationTolerance')}</span>
                                <select className="cr-select" value={String(margin)} disabled={!canEdit || !!busy.tolerance}
                                    onChange={e => setTolerance(g, Number(e.target.value))} data-cr-sb-tolerance="">
                                    {tolSteps.map(v => <option key={v} value={String(v)}>{crFill(t('crSbPoints'), { n: v })}</option>)}
                                </select>
                            </label>
                            {canEdit && addable.length > 0 && (
                                <label className="cr-sb-field">
                                    <select className="cr-select" value="" disabled={!!busy.members} data-cr-sb-add="" aria-label={t('crSbAddMember')}
                                        onChange={e => { if (e.target.value) addMember(g, e.target.value); }}>
                                        <option value="">{t('addStorage') || '+ Add Storage'}</option>
                                        {addable.map(s => <option key={s.storage} value={s.storage}>{s.storage}{s.type ? ` (${s.type})` : ''}</option>)}
                                    </select>
                                </label>
                            )}
                            <span className="cr-sb-facts-line" data-cr-sb-cadence="">
                                {crFill(t('crSbCadence'), { every: every || '-', n: Number(g.max_concurrent) > 0 ? g.max_concurrent : 1 })}
                                {trig != null && <> {crFill(t('crSbTrigger'), { n: trig })}</>}
                            </span>
                            <span className="cr-sb-facts-line" data-cr-sb-last="" title={t('crSbLastHint')}>
                                {t('crSbColLastCheck')}: {g.last_auto_run ? <span className="cr-mono">{crDriftTime(g.last_auto_run)} <span className="cr-muted">({t('crDriftServerTime')})</span></span>
                                    : <span className="cr-muted">{t('crSbNever')}</span>}
                            </span>
                        </div>
                        {crSbArmed(g) && (
                            <CrSbCallout tone="warning" id="armed"><p>{crFill(t('crSbArmedNote'), { every: every || '-', n: trig != null ? trig : '-' })}</p>
                                {standby && <p>{t('crSbArmedStandby')}</p>}</CrSbCallout>
                        )}
                        {!crSbOn(g) && <CrSbCallout tone="info" id="off"><p>{t('crSbOffNote')}</p></CrSbCallout>}

                        <div className="cr-stat-row cr-sb-stats" role="group" aria-label={t('crSbCapacity')}>
                            <CrStat id="sb-total" label={t('crSbTotal')} value={shown ? crBytes(shown.total) : '-'} />
                            <CrStat id="sb-used" label={t('crSbUsed')} value={shown ? crBytes(shown.used) : '-'} />
                            <CrStat id="sb-free" label={t('free')} value={shown && shown.avail != null ? crBytes(shown.avail) : '-'} />
                            <CrStat id="sb-use" label={t('crSbColUse')} value={capPct != null ? crPct(capPct, 1) : '-'} title={crStoreScale(t)}
                                tone={capPct != null ? crStoreTone(capPct) : undefined} />
                            <CrStat id="sb-readable" label={t('crSbReadable')} value={`${readable.length} / ${sel.members.length}`}
                                sub={readable.length < sel.members.length ? t('crSbReadableSub') : ''} />
                        </div>
                        <p className="cr-sb-fine" data-cr-sb-basis="">
                            {body ? t('crSbBasisServer') : t('crSbBasisList')} {t('crSbHealthNote')}
                        </p>

                        <div className="cr-sb-grid">
                            <CrPanel title={t('crSbDistribution')} className="cr-sb-dist" data-cr-sb-dist="">
                                <ul className="cr-sb-members" aria-label={t('crSbDistribution')}>
                                    {figs.map(r => (
                                        <CrSbMemberRow key={r.name} r={r} mean={mean} canEdit={canEdit} canRemove={sel.members.length > 2}
                                            busy={busy.members} onRemove={(name) => removeMember(g, name)} />
                                    ))}
                                </ul>
                                {totals.types.length > 1 && (
                                    <CrSbCallout tone="warning" id="mixed"><p>{crFill(t('crSbMixedNote'), { types: totals.types.join(', ') })}</p></CrSbCallout>
                                )}
                                <p className="cr-sb-fine">{t('crSbMeanNote')} {crStoreScale(t)}</p>
                            </CrPanel>

                            <CrPanel title={t('crSbImbalance')} className="cr-sb-imb" data-cr-sb-imb="">
                                <div className={`cr-sb-verdict cr-sb-verdict-${verdict}`} data-cr-sb-verdict={verdict} data-cr-sb-why={judge || undefined} role="status">
                                    {verdict === 'loading' ? <><span className="cr-spinner" aria-hidden="true" />{t('crSbReading')}</>
                                        : verdict === 'above' ? <><Icons.AlertTriangle className="w-4 h-4" />{t('crSbAbove')}</>
                                        : verdict === 'within' ? <><Icons.CheckCircle className="w-4 h-4" />{t('crSbWithin')}</>
                                        : verdict === 'unknown' ? <><Icons.Info className="w-4 h-4" />{t({ imbalance: 'crSbNoImbalance', threshold: 'crSbNoThreshold' }[judge] || 'crSbCannotJudge')}</>
                                        : <><Icons.AlertCircle className="w-4 h-4" />{t('crSbUnreadVerdict')}</>}
                                </div>
                                {readError && verdict === 'unknown' && (
                                    <CrSbCallout tone="error" id="read-error" onRetry={() => readStatus(g.id)}>
                                        <p data-cr-sb-read-error="">{crFill(t('crSbServerSays'), { why: readError })}</p>
                                    </CrSbCallout>
                                )}
                                {st && st.state !== 'ok' && st.state !== 'loading' && (
                                    <CrSbCallout tone={st.state === 'forbidden' || st.state === 'notfound' ? 'warning' : 'error'} id={`status-${st.state}`}
                                        onRetry={() => readStatus(g.id)}>
                                        <p className="cr-strong">{t({ forbidden: 'crSbStatusForbidden', notfound: 'crSbStatusGone', limited: 'crDriftLimited',
                                                                      offline: 'crDriftOffline', malformed: 'crSbStatusMalformed' }[st.state] || 'crSbStatusFailed')}</p>
                                        {st.state !== 'offline' && st.state !== 'malformed' && st.state !== 'limited' && <p className="cr-muted">{crSbError(st.body, st.code, t)}</p>}
                                    </CrSbCallout>
                                )}
                                {body && (
                                    <dl className="cr-sb-kv" data-cr-sb-kv="">
                                        <dt>{t('crSbServerSpread')}</dt>
                                        <dd className="cr-mono" data-cr-sb-imbalance={imb != null ? imb.toFixed(1) : ''}>{imb != null ? crSbPts(imb, t) : '-'}</dd>
                                        <dt>{t('balancingThreshold')}</dt>
                                        <dd className="cr-mono" data-cr-sb-thr={thr}>{Number.isFinite(thr) ? crSbPts(thr, t) : '-'}</dd>
                                        <dt>{t('crSbAutoActs')}</dt>
                                        <dd><span className="cr-mono">{trig != null ? crSbPts(trig, t) : '-'}</span> <span className="cr-muted">{crFill(t('crSbAutoActsNote'), { m: margin })}</span></dd>
                                        {spread != null && (imb == null || Math.abs(spread - imb) >= 0.1) && <>
                                            <dt>{t('crSbReadableSpread')}</dt>
                                            <dd className="cr-mono" data-cr-sb-own={spread.toFixed(1)}>{crSbPts(spread, t)}</dd>
                                        </>}
                                    </dl>
                                )}
                                {body && srvN < 2 && <CrSbCallout tone="warning" id="few"><p>{crFill(t('crSbServerFewOf'), { n: srvN, total: sel.members.length })}</p></CrSbCallout>}
                                {body && figs.some(r => r.unread && !r.why) && (
                                    <CrSbCallout tone="info" id="unread"><p>{crFill(t('crSbUnreadNote'), { names: figs.filter(r => r.unread && !r.why).map(r => r.name).join(', ') })}</p></CrSbCallout>
                                )}
                                {body && body.rate_limited && <CrSbCallout tone="warning" id="ratelimited"><p>{t('crSbRateLimited')}</p></CrSbCallout>}
                                {body && verdict === 'above' && !recs.length && !body.rate_limited && crSbOn(g) && (
                                    <p className="cr-sb-fine" data-cr-sb-norecs="">{crFill(t('crSbNoRecs'), { source: (figs.filter(r => r.srv).sort((a, b) => (b.pct || 0) - (a.pct || 0))[0] || {}).name || '-' })}</p>
                                )}
                                {body && verdict === 'within' && <p className="cr-sb-fine" data-cr-sb-nomove="">{t('crSbNoMove')}</p>}
                            </CrPanel>
                        </div>

                        {recRows.length > 0 && (
                            <div className="cr-sb-recs" data-cr-sb-recs="">
                                <CrTable id="sb-recs" columns={recCols} rows={recRows} rowKey={r => r.key} ariaLabel={t('crSbRecs')}
                                    toolbar={<span className="cr-table-title">{t('crSbRecs')}</span>} rowHeight={30}
                                    actions={<span className="cr-table-sub" title={t('crSbRecsHint')}>{t('crSbRecsSub')}</span>} />
                                {refusedRows.length > 0 && (
                                    <p className="cr-sb-fine" data-cr-sb-refused-note={refusedRows.length}>
                                        {crFill(t('crSbRefusedNote'), { n: refusedRows.length, why: refusedWhy })}
                                    </p>
                                )}
                                <p className="cr-sb-fine">{t('crSbRecsFoot')}</p>
                            </div>
                        )}

                        {recent.length > 0 && (
                            <div className="cr-sb-recent" data-cr-sb-recent="">
                                <CrTable id="sb-recent" columns={recentCols} rows={recent.slice(0, CR_SB_RECENT)} rowKey={r => r.upid} ariaLabel={t('crSbRecent')}
                                    toolbar={<span className="cr-table-title">{t('crSbRecent')}</span>} initialSort={{ key: 'start', dir: 'desc' }}
                                    actions={<span className="cr-table-sub">{recent.length > CR_SB_RECENT ? crFill(t('crSbRecentMore'), { n: recent.length - CR_SB_RECENT }) : ''}</span>} />
                                <p className="cr-sb-fine">{t('crSbRecentFoot')}</p>
                            </div>
                        )}

                        {dialog && (
                            <CrSbMoveDialog rec={dialog} guest={guestMap ? guestMap.get(String(dialog.vmid)) || null : null}
                                plan={crSbPlan(dialog, figs, guestMap ? guestMap.get(String(dialog.vmid)) || null : null, t)}
                                busy={moveBusy} error={moveErr} onCancel={closeMove} onConfirm={confirmMove} />
                        )}
                    </section>
                );
            })() : null;

            const createBtn = canEdit && (
                <CrButton variant="primary" icon={<Icons.Plus />} onClick={onCreate} data-cr-sb-create=""
                    disabled={listUnread || ((datastores && datastores.shared) || []).length < 2}
                    title={listUnread ? t('crSbPreSharedUnread') : ((datastores && datastores.shared) || []).length < 2 ? t('crSbNeedTwo') : undefined}>
                    {t('createStorageCluster')}
                </CrButton>
            );
            const pageMsg = msg && msg.id == null && !sel ? msg : null;

            return (
                <div className="cr-sb" ref={rootRef} data-cr-sb="" data-cr-sb-list={listState}>
                    <CrPageHeader icon={<Icons.Zap />} title={t('crSbTitle')} sub={t('crSbSub')}
                        actions={<>
                            {listRead && listRead.pending && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                            <button type="button" className="cr-icon-btn" onClick={reloadList} aria-label={t('refresh')} title={t('refresh')} data-cr-sb-reload="">
                                <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>
                            </button>
                            {listOk && groups.length > 0 && createBtn}
                        </>} />
                    <p className="cr-sb-fine cr-sb-exp" data-cr-sb-experimental="">
                        <span className="cr-badge cr-badge-warning cr-badge-plain">{t('experimentalFeature')}</span> {t('crSbExperimental')}
                    </p>
                    {standby && <CrSbCallout tone="info" id="standby"><p>{t('crSbStandby')}</p></CrSbCallout>}
                    {dsFail && (
                        <CrSbCallout tone={dsFail.hasData ? 'warning' : 'error'} id="ds-failed" onRetry={onDsRetry}>
                            <p>{crFill(t(dsFail.hasData ? 'crSbDsStale' : 'crSbDsFailed'), { why: dsFail.msg || '-' })}</p>
                        </CrSbCallout>
                    )}
                    {pageMsg && <CrSbCallout tone={pageMsg.tone} id={`msg-${pageMsg.tone}`}><p data-cr-sb-msg={pageMsg.tone}>{pageMsg.text}</p></CrSbCallout>}

                    {listState === 'loading' ? (
                        <div className="cr-drift-wait" data-cr-sb-loading=""><span className="cr-spinner" aria-hidden="true" />{t('crSbListLoading')}</div>
                    ) : !listOk ? (
                        <CrSbCallout tone={listState === 'forbidden' ? 'warning' : 'error'} id={`list-${listState}`} onRetry={reloadList}>
                            <p className="cr-strong">{listState === 'forbidden' ? t('crSbListForbidden') : t('crSbListFailed')}</p>
                            <p className="cr-muted">{listState === 'offline' ? t('crDriftOffline')
                                : listState === 'malformed' ? t('crSbStatusMalformed') : crSbError({ error: listRead.msg }, listRead.code, t)}</p>
                        </CrSbCallout>
                    ) : !rows.length ? (
                        <CrSbEmpty datastores={datastores} dsLoading={dsLoading} listUnread={listUnread} may={may} standby={standby} onCreate={onCreate} />
                    ) : (
                        <>
                            <CrTable id="sb-groups" columns={columns} rows={rows} rowKey={r => r.id} selectedKey={selId}
                                onRowClick={pick} ariaLabel={t('crSbGroups')} rowHeight={30}
                                toolbar={<span className="cr-table-title">{t('crSbGroups')}</span>}
                                actions={<span className="cr-table-sub" title={t('crSbColSpreadHint')}>{t('crSbListBasis')}</span>}
                                initialSort={{ key: 'name', dir: 'asc' }} />
                            {!sel && <p className="cr-sb-fine" data-cr-sb-pickhint="">{t('crSbPickHint')}</p>}
                        </>
                    )}
                    {listOk && detail}
                </div>
            );
        }
