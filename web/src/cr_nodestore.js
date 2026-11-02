        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): storage, repositories and Ceph of a node - LW Nov 2026
        // Configure > LVM, LVM-Thin and ZFS of a Proxmox VE node from the one disks read the view
        // already makes (disks, disks/lvm, disks/lvmthin, disks/zfs, kept by loadTabData with the
        // reason of a failed read), Repositories from the repos read and Ceph from its four reads.
        // Built from the section parts of cr_nodecfg.js. The pool detail is the shared
        // ZfsPoolDetail; a repository switch and apt update go through the handlers of
        // CorporateNodeDetailView with the classic requests. A value the node did not report says
        // so in a neutral style, never as a dash or as healthy.
        // ═══════════════════════════════════════════════════════════

        // a number PVE sent as a number or a numeric string, else null
        const crNvNum = (v) => {
            if (typeof v === 'number') return Number.isFinite(v) ? v : null;
            if (typeof v === 'string' && /^\s*-?\d+(\.\d+)?\s*$/.test(v)) return parseFloat(v);
            return null;
        };
        const crNvBytes = (v) => { const n = crNvNum(v); return n != null && n >= 0 ? formatBytes(n) : null; };
        // the share of two byte counts in percent; null when one is missing or the total is 0
        const crNvPct = (used, total) => {
            const u = crNvNum(used), s = crNvNum(total);
            return u != null && s != null && s > 0 && u >= 0 ? Math.min(100, (u * 100) / s) : null;
        };

        // one answer of a read the view keeps as a list: not read yet, failed (with why) or the body
        function crNvSlot(read, i) {
            if (!Array.isArray(read)) return { state: 'unread' };
            const f = crNdFail(read[i]);
            return f ? { state: 'failed', fail: f } : { state: 'ok', body: read[i] };
        }

        // --- rules ---------------------------------------------------------------------------------

        // the volume groups of disks/lvm. PVE answers a tree {leaf, children: [vg {name, size, free,
        // lvcount, children: [pv {name, size, free}]}]}; the route answers [] when the read on the
        // node failed, so a tree without groups is "none" and [] is "empty or failed"
        function crNvLvm(body, thins) {
            const tree = !!body && typeof body === 'object' && !Array.isArray(body);
            const list = tree ? (Array.isArray(body.children) ? body.children : []) : (Array.isArray(body) ? body : []);
            const vgs = list.filter(v => v && typeof v === 'object' && (v.name || v.vg)).map(v => {
                const name = String(v.name || v.vg);
                const size = crNvNum(v.size), free = crNvNum(v.free);
                const used = size != null && free != null && free >= 0 && free <= size ? size - free : null;
                return {
                    name, size, free, used, lvcount: crNvNum(v.lvcount),
                    pvs: (Array.isArray(v.children) ? v.children : []).filter(p => p && typeof p === 'object' && p.name)
                        .map(p => ({ name: String(p.name), size: crNvNum(p.size), free: crNvNum(p.free) })),
                    thin: (thins || []).filter(x => x.vg === name).map(x => x.lv),
                };
            });
            return { tree, vgs, state: vgs.length ? 'ok' : tree ? 'none' : 'empty' };
        }

        // the thin pools of disks/lvmthin: data and metadata usage where PVE sent both numbers
        function crNvThin(body) {
            const list = Array.isArray(body) ? body : [];
            return list.filter(x => x && typeof x === 'object' && x.lv).map(x => ({
                lv: String(x.lv), vg: x.vg == null ? '' : String(x.vg),
                size: crNvNum(x.lv_size), used: crNvNum(x.used),
                metaSize: crNvNum(x.metadata_size), metaUsed: crNvNum(x.metadata_used),
            }));
        }

        const CR_NV_ZFS_TONE = { ONLINE: 'success', DEGRADED: 'warning', FAULTED: 'error', UNAVAIL: 'error',
                                 REMOVED: 'error', SUSPENDED: 'error', OFFLINE: 'warning' };
        // the pools of disks/zfs: name, size, alloc, free, frag (percent), dedup (ratio), health
        function crNvZfs(body) {
            const list = Array.isArray(body) ? body : [];
            return list.filter(p => p && typeof p === 'object' && p.name).map(p => {
                const health = p.health == null ? '' : String(p.health).trim();
                return {
                    name: String(p.name), size: crNvNum(p.size), alloc: crNvNum(p.alloc), free: crNvNum(p.free),
                    frag: crNvNum(p.frag), dedup: crNvNum(p.dedup), health,
                    tone: health ? (CR_NV_ZFS_TONE[health.toUpperCase()] || 'neutral') : 'none',
                };
            });
        }

        // the repositories of get_node_repos: enabled, disabled, and the known ones the node does
        // not have (exists false); the update channel of Proxmox VE from its two known entries
        const crNrKey = (r) => String(r.id || `${r.file || ''}#${r.index}`);
        function crNrLine(content) {
            if (!content || typeof content !== 'object') return '';
            const part = (k) => (Array.isArray(content[k]) ? content[k].join(' ') : content[k] == null ? '' : String(content[k]));
            return ['Types', 'URIs', 'Suites', 'Components'].map(part).filter(Boolean).join(' ');
        }
        function crNrModel(list) {
            const rows = (Array.isArray(list) ? list : []).filter(r => r && typeof r === 'object').map(r => ({
                repo: r, key: crNrKey(r), name: String(r.name || r.id || ''), enabled: !!r.enabled, exists: r.exists !== false,
                line: crNrLine(r.content), file: r.actual_file || r.file || '', index: crNvNum(r.index),
                sub: !!r.requires_subscription, other: !!r.is_other,
            }));
            const ent = rows.find(r => r.repo.id === 'pve-enterprise');
            const free = rows.find(r => r.repo.id === 'pve-no-subscription');
            const on = (r) => !!r && r.exists && r.enabled;
            const channel = !ent && !free ? 'unknown' : on(ent) && on(free) ? 'both' : on(ent) ? 'enterprise' : on(free) ? 'free' : 'none';
            // the route matches every known entry by a part of its address, so one line of the node
            // can stand under two names (the enterprise Ceph line under its release and under Ceph Enterprise)
            const seen = {};
            for (const r of rows) {
                if (!r.exists || !r.file || r.index == null) continue;
                const k = `${r.file}#${r.index}`;
                (seen[k] = seen[k] || []).push(r.name);
            }
            const twice = Object.keys(seen).filter(k => seen[k].length > 1).map(k => seen[k]);
            return {
                rows, ent, free, channel, twice,
                groups: { on: rows.filter(r => r.exists && r.enabled), off: rows.filter(r => r.exists && !r.enabled),
                          absent: rows.filter(r => !r.exists) },
            };
        }

        const CR_NX_TONE = { HEALTH_OK: 'success', HEALTH_WARN: 'warning', HEALTH_ERR: 'error' };
        const CR_NX_SEV = { HEALTH_ERR: 3, HEALTH_WARN: 2 };
        // Ceph from ceph/status (ceph -s), ceph/osd, ceph/mon, ceph/pool. The status route answers
        // {available: false} for a PVE 501 and a PVE 500 alike, so for a node without Ceph as well as
        // for an installed Ceph whose cluster did not answer, and {} when the request failed; the
        // three lists come back [] for none as well as for a failed read
        function crNxModel(read) {
            const st = crNvSlot(read, 0);
            if (st.state !== 'ok') return { state: st.state, fail: st.fail };
            const s = st.body;
            if (!s || typeof s !== 'object' || Array.isArray(s)) return { state: 'blank' };
            if (s.available === false) return { state: 'none' };
            if (!Object.keys(s).length) return { state: 'blank' };
            const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
            const health = obj(s.health);
            const status = String(health.status || health.overall_status || '');
            const checks = Object.keys(obj(health.checks)).map(name => {
                const c = obj(health.checks[name]);
                return { name, severity: String(c.severity || ''), message: String(obj(c.summary).message || ''), muted: !!c.muted };
            }).sort((a, b) => (CR_NX_SEV[b.severity] || 0) - (CR_NX_SEV[a.severity] || 0) || a.name.localeCompare(b.name));
            let osdmap = obj(s.osdmap);
            if (osdmap.osdmap && typeof osdmap.osdmap === 'object') osdmap = osdmap.osdmap;  // before Quincy one level deeper
            const pgmap = obj(s.pgmap);
            const monmap = obj(s.monmap);
            const states = (Array.isArray(pgmap.pgs_by_state) ? pgmap.pgs_by_state : []).filter(x => x && typeof x === 'object')
                .map(x => ({ state: String(x.state_name || ''), count: crNvNum(x.count) })).filter(x => x.state && x.count != null)
                .sort((a, b) => b.count - a.count);
            const quorum = Array.isArray(s.quorum_names) ? s.quorum_names.map(String) : null;
            const list = (i) => {
                const x = crNvSlot(read, i);
                if (x.state === 'failed') return { state: 'failed', fail: x.fail, rows: [] };
                const rows = Array.isArray(x.body) ? x.body.filter(r => r && typeof r === 'object') : [];
                return { state: rows.length ? 'ok' : 'empty', rows };
            };
            return {
                state: 'ok', status, tone: CR_NX_TONE[status] || (status ? 'neutral' : 'none'), checks,
                osds: { total: crNvNum(osdmap.num_osds), up: crNvNum(osdmap.num_up_osds), in: crNvNum(osdmap.num_in_osds) },
                pgs: { total: crNvNum(pgmap.num_pgs), states,
                       clean: states.length ? states.filter(x => x.state.split('+').includes('active') && x.state.split('+').includes('clean')).reduce((n, x) => n + x.count, 0) : null },
                bytes: { used: crNvNum(pgmap.bytes_used), avail: crNvNum(pgmap.bytes_avail), total: crNvNum(pgmap.bytes_total) },
                mons: { total: crNvNum(monmap.num_mons) ?? (Array.isArray(monmap.mons) ? monmap.mons.length : null), quorum },
                osd: list(1), mon: list(2), pool: list(3),
            };
        }

        window.PegaProxNodeStore = Object.freeze({ lvm: crNvLvm, thin: crNvThin, zfs: crNvZfs, repos: crNrModel, ceph: crNxModel });

        // --- parts ---------------------------------------------------------------------------------

        // how much of a total is used: a bar and "X of Y (Z%)"; a missing number says so.
        // tone: 'auto' by the storage pair of the preview (crStoreTone: from 70 % warning, above 85 %
        // error), 'info' for a plain share
        function CrNvUsage({ id, used, total, tone = 'auto', label }) {
            const { t } = useTranslation();
            const pct = crNvPct(used, total);
            if (pct == null) return <CrNcMissing />;
            const tn = tone === 'auto' ? crStoreTone(pct) : tone;
            return (
                <span className={`cr-nv-usage cr-nv-tone-${tn}`} data-cr-nv-usage={id} data-cr-nv-pct={pct.toFixed(1)} data-cr-nv-tone={tn}
                    title={tone === 'auto' ? crStoreScale(t) : undefined}>
                    <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
                    <span className="cr-nv-usage-text">{crNnT(t, label || 'crNvUsedOf', { used: formatBytes(crNvNum(used)), total: formatBytes(crNvNum(total)), pct: pct.toFixed(1) })}</span>
                </span>
            );
        }

        // the read states every list of these sections shares: not read yet, failed with why,
        // and an empty answer that can also be a failed read
        function crNvReadState(t, { id, slot, loading, onRetry, emptyText }) {
            if (slot.state === 'unread') {
                return <CrNcState id={id} kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
            }
            if (slot.state === 'failed') {
                return <CrNcState id={id} kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, slot.fail) })}</CrNcState>;
            }
            if (emptyText) return <CrNcState id={id} kind="empty" onRetry={onRetry} retryDisabled={loading}>{emptyText}</CrNcState>;
            return null;
        }

        function CrNvRefresh({ id, loading, onClick }) {
            const { t } = useTranslation();
            return <CrButton icon={<Icons.RotateCw />} onClick={onClick} disabled={loading} data-cr-nv-refresh={id}>{t('refresh')}</CrButton>;
        }

        // --- LVM ----------------------------------------------------------------------------------

        function CrNodeLvm({ read, loading, onReload }) {
            const { t } = useTranslation();
            const slot = crNvSlot(read, 1);
            const thinSlot = crNvSlot(read, 2);
            const thins = thinSlot.state === 'ok' ? crNvThin(thinSlot.body) : [];
            const m = slot.state === 'ok' ? crNvLvm(slot.body, thins) : null;
            const body = () => {
                const st = crNvReadState(t, { id: 'lvm', slot, loading, onRetry: onReload,
                    emptyText: m && m.state === 'empty' ? t('crNvLvmEmpty') : m && m.state === 'none' ? t('crNvLvmNone') : '' });
                if (st) return st;
                return (
                    <ul className="cr-nc-items" aria-label={t('crNvVgs')}>
                        {m.vgs.map(vg => (
                            <li key={vg.name} className="cr-nc-item" data-cr-nv-vg={vg.name}>
                                <div className="cr-nc-item-head">
                                    <Icons.Layers className="w-3.5 h-3.5 cr-muted" />
                                    <span className="cr-mono cr-nc-item-name">{vg.name}</span>
                                    {vg.lvcount != null && <CrBadge tone="neutral" dot={false}>{crNnT(t, vg.lvcount === 1 ? 'crNvLvOne' : 'crNvLvN', { n: vg.lvcount })}</CrBadge>}
                                </div>
                                <CrNcKv id={`vg-${vg.name}`} rows={[
                                    { k: 'size', label: t('crNvSize'), value: crNvBytes(vg.size) },
                                    { k: 'free', label: t('crNvFree'), value: crNvBytes(vg.free) },
                                    { k: 'alloc', label: t('crNvAllocated'), value: <CrNvUsage id={`vg-${vg.name}`} used={vg.used} total={vg.size} tone="info" label="crNvAllocOf" /> },
                                    thinSlot.state === 'ok' ? { k: 'thin', label: t('crNvThinPools'), value: vg.thin.length ? <span className="cr-nc-chips">{vg.thin.map(n => <span key={n} className="cr-nn-chip cr-mono">{n}</span>)}</span> : null, missing: t('crNvNone') } : null,
                                    { k: 'pvs', label: t('crNvPvs'), value: vg.pvs.length ? (
                                        <ul className="cr-nv-pvs">
                                            {vg.pvs.map(pv => (
                                                <li key={pv.name} data-cr-nv-pv={pv.name}>
                                                    <span className="cr-mono">{pv.name}</span>
                                                    <span className="cr-muted">{crNnT(t, 'crNvPvSize', { size: crNvBytes(pv.size) || t('crNsNotReported'), free: crNvBytes(pv.free) || t('crNsNotReported') })}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    ) : null },
                                ]} />
                            </li>
                        ))}
                    </ul>
                );
            };
            return (
                <CrNcSection id="lvm" title={t('lvmStorage')} desc={t('crNvLvmDesc')}
                    badge={m && m.vgs.length ? <span className="cr-muted cr-nn-count">{crNnT(t, m.vgs.length === 1 ? 'crNvVgOne' : 'crNvVgN', { n: m.vgs.length })}</span> : null}
                    actions={<CrNvRefresh id="lvm" loading={loading} onClick={onReload} />}>
                    {body()}
                    {m && m.vgs.length > 0 && <p className="cr-nc-note cr-muted" data-cr-nv-note="lvm">{t('crNvAllocNote')}</p>}
                </CrNcSection>
            );
        }

        // --- LVM-Thin -----------------------------------------------------------------------------

        function CrNodeLvmThin({ read, loading, onReload }) {
            const { t } = useTranslation();
            const slot = crNvSlot(read, 2);
            const pools = slot.state === 'ok' ? crNvThin(slot.body) : null;
            const body = () => {
                const st = crNvReadState(t, { id: 'lvmthin', slot, loading, onRetry: onReload,
                    emptyText: pools && !pools.length ? t('crNvThinEmpty') : '' });
                if (st) return st;
                return (
                    <ul className="cr-nc-items" aria-label={t('crNvThinPools')}>
                        {pools.map(p => (
                            <li key={`${p.vg}/${p.lv}`} className="cr-nc-item" data-cr-nv-thin={`${p.vg}/${p.lv}`}>
                                <div className="cr-nc-item-head">
                                    <Icons.Database className="w-3.5 h-3.5 cr-muted" />
                                    <span className="cr-mono cr-nc-item-name">{p.lv}</span>
                                    {p.vg && <span className="cr-muted">{crNnT(t, 'crNvInVg', { vg: p.vg })}</span>}
                                </div>
                                <CrNcKv id={`thin-${p.vg}-${p.lv}`} rows={[
                                    { k: 'size', label: t('crNvSize'), value: crNvBytes(p.size) },
                                    { k: 'data', label: t('crNvThinData'), value: <CrNvUsage id={`thin-${p.lv}`} used={p.used} total={p.size} /> },
                                    { k: 'meta', label: t('crNvThinMeta'), value: <CrNvUsage id={`thin-${p.lv}-meta`} used={p.metaUsed} total={p.metaSize} /> },
                                ]} />
                            </li>
                        ))}
                    </ul>
                );
            };
            return (
                <CrNcSection id="lvmthin" title={t('lvmThinStorage')} desc={t('crNvThinDesc')}
                    badge={pools && pools.length ? <span className="cr-muted cr-nn-count">{crNnT(t, pools.length === 1 ? 'crNvPoolOne' : 'crNvPoolN', { n: pools.length })}</span> : null}
                    actions={<CrNvRefresh id="lvmthin" loading={loading} onClick={onReload} />}>
                    {body()}
                    {pools && pools.length > 0 && <p className="cr-nc-note cr-muted" data-cr-nv-note="lvmthin">{t('crNvThinNote')}</p>}
                </CrNcSection>
            );
        }

        // --- ZFS ----------------------------------------------------------------------------------

        function CrNodeZfs({ clusterId, node, read, loading, onReload, pool, onPool }) {
            const { t } = useTranslation();
            const slot = crNvSlot(read, 3);
            const pools = slot.state === 'ok' ? crNvZfs(slot.body) : null;
            const bad = pools ? pools.filter(p => p.tone === 'warning' || p.tone === 'error').length : 0;
            const body = () => {
                const st = crNvReadState(t, { id: 'zfs', slot, loading, onRetry: onReload,
                    emptyText: pools && !pools.length ? t('crNvZfsEmpty') : '' });
                if (st) return st;
                return (
                    <ul className="cr-nc-items" aria-label={t('zfsStorage')}>
                        {pools.map(p => {
                            const open = pool === p.name;
                            return (
                                <li key={p.name} className={`cr-nc-item${open ? ' cr-nv-open' : ''}`} data-cr-nv-pool={p.name}>
                                    <div className="cr-nc-item-head">
                                        <Icons.HardDrive className="w-3.5 h-3.5 cr-muted" />
                                        <span className="cr-mono cr-nc-item-name">{p.name}</span>
                                        <span data-cr-nv-health={p.tone}>
                                            {p.health
                                                ? <CrBadge tone={p.tone} dot={p.tone !== 'neutral'}>{p.health}</CrBadge>
                                                : <CrBadge tone="neutral" dot={false}>{t('crNvHealthNone')}</CrBadge>}
                                        </span>
                                        <span className="cr-nv-item-acts">
                                            <CrButton className="cr-btn-xs" onClick={() => onPool(open ? null : p.name)} data-zfs-open={p.name}
                                                aria-pressed={open} title={t('zfsPoolDetails')}>
                                                {open ? t('crNvHideDetails') : t('details')}
                                            </CrButton>
                                        </span>
                                    </div>
                                    <CrNcKv id={`zfs-${p.name}`} rows={[
                                        { k: 'size', label: t('crNvSize'), value: crNvBytes(p.size) },
                                        { k: 'alloc', label: t('crNvAllocated'), value: <CrNvUsage id={`zfs-${p.name}`} used={p.alloc} total={p.size} label="crNvAllocOf" /> },
                                        { k: 'free', label: t('crNvFree'), value: crNvBytes(p.free) },
                                        { k: 'frag', label: t('crNvFrag'), value: p.frag != null ? `${p.frag}%` : null },
                                        { k: 'dedup', label: t('crNvDedup'), value: p.dedup != null ? `${p.dedup.toFixed(2)}x` : null },
                                    ]} />
                                </li>
                            );
                        })}
                    </ul>
                );
            };
            return (
                <CrNcSection id="zfs" title={t('zfsStorage')} desc={t('crNvZfsDesc')}
                    badge={pools && pools.length ? (
                        <>
                            <span className="cr-muted cr-nn-count">{crNnT(t, pools.length === 1 ? 'crNvPoolOne' : 'crNvPoolN', { n: pools.length })}</span>
                            {bad > 0 && <span data-cr-nv-zfs-bad=""><CrBadge tone="warning">{crNnT(t, 'crNvZfsBad', { n: bad })}</CrBadge></span>}
                        </>
                    ) : null}
                    actions={<CrNvRefresh id="zfs" loading={loading} onClick={onReload} />}>
                    {body()}
                    {/* the pool picked above, in full: the shared detail view (its own read per click) */}
                    {pool && <ZfsPoolDetail corporate clusterId={clusterId} node={node} pool={pool} onClose={() => onPool(null)} />}
                </CrNcSection>
            );
        }

        // --- Repositories -------------------------------------------------------------------------

        // the reason no switch is offered for an entry that is not set up, said once above that group
        const CR_NR_WHY_ID = 'cr-nr-why-absent';

        // pending: the state the switch asks for, undefined when nothing waits for this one
        function CrNrItem({ r, pending, readOnly, busy, onFlip }) {
            const { t } = useTranslation();
            const waits = pending !== undefined;
            const state = !r.exists ? 'absent' : r.enabled ? 'on' : 'off';
            const label = state === 'absent' ? t('crNrAbsent') : state === 'on' ? t('crNrOn') : t('crNrOff');
            // LW Nov 2026 - the node refuses to switch an entry it does not have (400, manual setup), so
            // no switch is offered for one; one that already waits can still be undone
            const noSwitch = state === 'absent' && !waits;
            return (
                <li className={`cr-nc-item${waits ? ' cr-nv-pending' : ''}`} data-cr-nr-repo={r.key} data-cr-nr-state={state}
                    data-cr-nr-pending={waits ? '' : undefined}>
                    <div className="cr-nc-item-head">
                        <Icons.Package className="w-3.5 h-3.5 cr-muted" />
                        <span className="cr-nc-item-name">{r.name || <CrNcMissing />}</span>
                        <CrBadge tone={state === 'on' ? 'success' : 'neutral'} dot={state === 'on'}>{label}</CrBadge>
                        {r.sub && <span className="cr-nn-chip" data-cr-nr-sub="">{t('crNrNeedsSub')}</span>}
                        {r.other && <span className="cr-nn-chip" data-cr-nr-other="">{t('crNrOther')}</span>}
                        {waits && <span className="cr-nn-pend" data-cr-nr-will="">{t(pending ? 'crNrWillEnable' : 'crNrWillDisable')}</span>}
                        <span className="cr-nv-item-acts">
                            <CrButton className="cr-btn-xs" onClick={onFlip} disabled={readOnly || busy || noSwitch} data-cr-nr-flip={r.key}
                                title={noSwitch ? t('crNrAbsentNoSwitch') : undefined} aria-describedby={noSwitch ? CR_NR_WHY_ID : undefined}>
                                {waits ? t('crNrUndo') : r.enabled ? t('disable') : t('enable')}
                            </CrButton>
                        </span>
                    </div>
                    <CrNcKv id={`repo-${r.key}`} rows={[
                        r.repo.description ? { k: 'desc', label: t('crNrAbout'), value: String(r.repo.description) } : null,
                        r.exists ? { k: 'line', label: t('crNrLine'), value: r.line, mono: true } : null,
                        r.exists ? { k: 'file', label: t('crNrFile'), value: r.file, mono: true,
                                     note: r.index != null ? crNnT(t, 'crNrEntry', { n: r.index + 1 }) : '' } : null,
                        !r.exists ? { k: 'line', label: t('crNrLine'), value: null, missing: t('crNrAbsentLine') } : null,
                    ]} />
                </li>
            );
        }

        // repos: the list the view read (data.repos), fail a refused or failed read. A switch waits
        // here until Save; Save sends each one through the view's handler, one after the other
        function CrNodeRepos({ node, repos, fail, loading, saving, readOnly, onToggle, onAptUpdate, onReload, onDirty }) {
            const { t } = useTranslation();
            const [pending, setPending] = useState({});
            const [busy, setBusy] = useState(false);
            const [apt, setApt] = useState(false);
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);
            useEffect(() => { setPending({}); }, [node]);
            const m = useMemo(() => crNrModel(repos), [repos]);
            // pending keeps the state each switch asks for (true enabled), taken when it was clicked; one
            // the node already has (a switch that went through and was read again) is not waiting
            const has = (p, r) => Object.prototype.hasOwnProperty.call(p, r.key) && p[r.key] !== r.enabled;
            const waiting = m.rows.filter(r => has(pending, r));
            useCrNcDirty(onDirty, 'repos', waiting.length > 0);
            const flip = (r) => setPending(p => {
                const next = { ...p };
                if (has(p, r)) delete next[r.key]; else next[r.key] = !r.enabled;
                return next;
            });
            const save = async () => {
                if (busy || !waiting.length) return;
                setBusy(true);
                const left = {};
                for (const r of waiting) {
                    let ok = false;
                    try { ok = await onToggle(r.repo); } catch (e) { ok = false; }
                    if (!ok) left[r.key] = pending[r.key];
                }
                if (!alive.current) return;
                setPending(left);
                setBusy(false);
            };
            const runApt = async () => {
                setApt(true);
                try { await onAptUpdate(); } finally { if (alive.current) setApt(false); }
            };
            const absentWaiting = waiting.filter(r => !r.exists);
            const chanBadge = (r) => {
                if (!r) return null;
                const s = !r.exists ? 'absent' : r.enabled ? 'on' : 'off';
                return <CrBadge tone={s === 'on' ? 'success' : 'neutral'} dot={s === 'on'}>{s === 'absent' ? t('crNrAbsent') : s === 'on' ? t('crNrOn') : t('crNrOff')}</CrBadge>;
            };
            const channelText = { enterprise: 'crNrChanEnt', free: 'crNrChanFree', both: 'crNrChanBoth', none: 'crNrChanNone' }[m.channel];
            const group = (id, title, rows) => (rows.length ? (
                <CrNcGroup id={id} title={`${title} (${rows.length})`}>
                    {id === 'absent' && <p className="cr-nc-note cr-muted" id={CR_NR_WHY_ID} data-cr-nr-why="">{t('crNrAbsentNoSwitch')}</p>}
                    <ul className="cr-nc-items">
                        {rows.map(r => <CrNrItem key={r.key} r={r} pending={has(pending, r) ? pending[r.key] : undefined} readOnly={readOnly} busy={busy || saving} onFlip={() => flip(r)} />)}
                    </ul>
                </CrNcGroup>
            ) : null);
            const body = () => {
                if (repos === undefined) {
                    return <CrNcState id="repos" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onReload}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                }
                if (fail) return <CrNcState id="repos" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, fail) })}</CrNcState>;
                if (!m.rows.length) return <CrNcState id="repos" kind="empty" onRetry={onReload} retryDisabled={loading}>{t('crNrEmpty')}</CrNcState>;
                return (
                    <>
                        {m.channel !== 'unknown' && (
                            <div className="cr-nv-channel" data-cr-nr-channel={m.channel}>
                                <CrNcKv id="channel" label={t('crNrChannel')} rows={[
                                    m.ent ? { k: 'ent', label: m.ent.name, value: chanBadge(m.ent) } : null,
                                    m.free ? { k: 'free', label: m.free.name, value: chanBadge(m.free) } : null,
                                ]} />
                                <CrNcState id="channel" kind={m.channel === 'both' || m.channel === 'none' ? 'warning' : 'empty'}>{t(channelText)}</CrNcState>
                            </div>
                        )}
                        {m.twice.map(names => (
                            <CrNcState key={names.join('|')} id="repos-twice" kind="warning">{crNnT(t, 'crNrTwice', { names: names.join(', ') })}</CrNcState>
                        ))}
                        {readOnly && <p className="cr-nc-note cr-muted" data-cr-nr-ro="">{t('crNcReadOnly')}</p>}
                        <div className="cr-nc-groups cr-nv-groups">
                            {group('on', t('crNrOn'), m.groups.on)}
                            {group('off', t('crNrOff'), m.groups.off)}
                            {group('absent', t('crNrAbsentGroup'), m.groups.absent)}
                        </div>
                    </>
                );
            };
            return (
                <CrNcSection id="repos" title={t('repositories')} desc={t('crNrDesc')} editing={waiting.length > 0}
                    badge={m.rows.length ? <span className="cr-muted cr-nn-count">{crNnT(t, 'crNrCount', { on: m.groups.on.length, n: m.rows.length })}</span> : null}
                    actions={(
                        <>
                            <CrNvRefresh id="repos" loading={loading} onClick={onReload} />
                            <span className="cr-nc-acts-sep" aria-hidden="true" />
                            <CrButton icon={<Icons.Download />} onClick={runApt} disabled={readOnly || apt} data-cr-nr-apt="" title={t('crNrAptHint')}>
                                {apt ? t('crNrAptRunning') : t('crNrApt')}
                            </CrButton>
                        </>
                    )}
                    foot={waiting.length > 0 && (
                        <CrNcEditBar id="repos" count={waiting.length} saving={busy || saving} canSave={waiting.length > 0} readOnly={readOnly}
                            note={t('crNrSaveNote')} onCancel={() => setPending({})} onSave={save}>
                            <CrNcChanges id="repos" rows={waiting.map(r => ({ k: r.key, label: r.name,
                                from: r.enabled ? t('crNrOn') : t('crNrOff'), to: pending[r.key] ? t('crNrOn') : t('crNrOff') }))} />
                            {absentWaiting.length > 0 && (
                                <p className="cr-nc-hint cr-nc-hint-warning" data-cr-nc-hint="warning">
                                    {crNnT(t, 'crNrAbsentHint', { names: absentWaiting.map(r => r.name).join(', ') })}
                                </p>
                            )}
                        </CrNcEditBar>
                    )}>
                    {body()}
                </CrNcSection>
            );
        }

        // --- Ceph ---------------------------------------------------------------------------------

        function CrNxList({ id, list, count, loading, onRetry, emptyKey, children }) {
            const { t } = useTranslation();
            if (list.state === 'failed') {
                return <CrNcState id={id} kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, list.fail) })}</CrNcState>;
            }
            if (list.state === 'empty') {
                // the status counts some, the list came back without them: that list read failed
                if (count != null && count > 0) return <CrNcState id={id} kind="warning" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNxListMissing', { n: count })}</CrNcState>;
                return <CrNcState id={id} kind="empty">{t(emptyKey)}</CrNcState>;
            }
            return children;
        }

        function CrNodeCeph({ read, loading, onReload }) {
            const { t } = useTranslation();
            const m = useMemo(() => crNxModel(read), [read]);
            const refresh = <CrNvRefresh id="ceph" loading={loading} onClick={onReload} />;
            if (m.state !== 'ok') {
                let st;
                if (m.state === 'unread') st = <CrNcState id="ceph" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onReload}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                else if (m.state === 'failed') st = <CrNcState id="ceph" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, m.fail) })}</CrNcState>;
                // not said as "no Ceph": the same answer comes from a Ceph whose monitors are down
                else if (m.state === 'none') st = <CrNcState id="ceph" kind="warning" onRetry={onReload} retryDisabled={loading}>{t('crNxNone')}</CrNcState>;
                else st = <CrNcState id="ceph" kind="warning" onRetry={onReload} retryDisabled={loading}>{t('crNxBlank')}</CrNcState>;
                return <CrNcSection id="ceph" data-cr-nx-state={m.state} title="Ceph" desc={t('crNxDesc')} actions={refresh}>{st}</CrNcSection>;
            }
            const yes = t('crNxYes'), no = t('crNxNo');
            const inQuorum = (mon) => {
                if (mon.quorum != null) return mon.quorum === true || mon.quorum === 1 || mon.quorum === '1';
                return m.mons.quorum ? m.mons.quorum.includes(String(mon.name)) : null;
            };
            const osdLine = m.osds.total != null ? crNnT(t, 'crNxOsdLine', { up: m.osds.up ?? '?', in: m.osds.in ?? '?', n: m.osds.total }) : null;
            return (
                <>
                    <CrNcSection id="ceph" data-cr-nx-state="ok" title={t('crNxStatus')} desc={t('crNxDesc')} actions={refresh}
                        badge={<span data-cr-nx-health={m.tone}>{m.status ? <CrBadge tone={m.tone} dot={m.tone !== 'neutral'}>{m.status}</CrBadge> : <CrBadge tone="neutral" dot={false}>{t('crNvHealthNone')}</CrBadge>}</span>}>
                        {m.checks.length > 0 && (
                            <ul className="cr-nv-checks" aria-label={t('crNxChecks')}>
                                {m.checks.map(c => (
                                    <li key={c.name} data-cr-nx-check={c.name}>
                                        <CrBadge tone={CR_NX_TONE[c.severity] || 'neutral'} dot={false}>{c.severity || t('crNsNotReported')}</CrBadge>
                                        <span className="cr-mono">{c.name}</span>
                                        <span>{c.message}</span>
                                        {c.muted && <span className="cr-muted">{t('crNxMuted')}</span>}
                                    </li>
                                ))}
                            </ul>
                        )}
                        <div className="cr-nc-groups">
                            <CrNcGroup id="capacity" title={t('crNxCapacity')}>
                                <CrNcKv id="ceph-capacity" rows={[
                                    { k: 'used', label: t('crNxUsed'), value: <CrNvUsage id="ceph" used={m.bytes.used} total={m.bytes.total} /> },
                                    { k: 'avail', label: t('crNxAvail'), value: crNvBytes(m.bytes.avail) },
                                ]} />
                            </CrNcGroup>
                            <CrNcGroup id="pgs" title={t('crNxPgs')}>
                                <CrNcKv id="ceph-pgs" rows={[
                                    { k: 'pgs', label: t('crNxPgTotal'), value: m.pgs.total },
                                    { k: 'clean', label: t('crNxPgClean'), value: m.pgs.clean },
                                    m.pgs.states.length ? { k: 'states', label: t('crNxPgStates'), value: <span className="cr-nc-chips">{m.pgs.states.map(s => <span key={s.state} className="cr-nn-chip cr-mono">{s.state}: {s.count}</span>)}</span> } : null,
                                ]} />
                            </CrNcGroup>
                            <CrNcGroup id="counts" title={t('crNxDaemons')}>
                                <CrNcKv id="ceph-counts" rows={[
                                    { k: 'osds', label: 'OSDs', value: osdLine },
                                    { k: 'mons', label: t('crNxMons'), value: m.mons.total != null ? crNnT(t, 'crNxMonLine', { n: m.mons.total, q: m.mons.quorum ? m.mons.quorum.length : '?' }) : null },
                                    { k: 'pools', label: t('crNxPools'), value: m.pool.state === 'ok' ? m.pool.rows.length : null, missing: m.pool.state === 'failed' ? t('crNxNotRead') : undefined },
                                ]} />
                            </CrNcGroup>
                        </div>
                    </CrNcSection>
                    <CrNcSection id="ceph-osd" title="OSDs" desc={t('crNxOsdDesc')}
                        badge={osdLine ? <span className="cr-muted cr-nn-count">{osdLine}</span> : null}>
                        <CrNxList id="ceph-osd" list={m.osd} count={m.osds.total} loading={loading} onRetry={onReload} emptyKey="crNxOsdEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label="OSDs">
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxHost')}</th><th>{t('status')}</th><th>{t('crNxIn')}</th><th>{t('crNxClass')}</th><th>{t('crNxUsed')}</th></tr></thead>
                                    <tbody>
                                        {m.osd.rows.map((o, i) => {
                                            const up = o.status == null ? null : String(o.status).toLowerCase() === 'up';
                                            const isIn = o.in == null ? null : o.in === 1 || o.in === true || o.in === '1';
                                            const pct = crNvNum(o.percent_used);
                                            return (
                                                <tr key={o.name || o.id || i} data-cr-nx-osd={o.name || o.id}>
                                                    <td className="cr-mono">{o.name || (o.id != null ? `osd.${o.id}` : <CrNcMissing />)}</td>
                                                    <td>{o.host || <CrNcMissing />}</td>
                                                    <td>{up == null ? <CrNcMissing /> : <CrBadge tone={up ? 'success' : 'error'}>{String(o.status)}</CrBadge>}</td>
                                                    <td>{isIn == null ? <CrNcMissing /> : isIn ? t('crNxInYes') : <span className="cr-nc-warn">{t('crNxOut')}</span>}</td>
                                                    <td>{o.device_class || <CrNcMissing />}</td>
                                                    <td>{pct != null && pct >= 0 ? (
                                                        <span className={`cr-nv-usage cr-nv-tone-${crStoreTone(pct)}`} data-cr-nv-usage={`osd-${o.name || o.id}`} title={crStoreScale(t)}>
                                                            <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${Math.min(100, pct)}%` }} /></span>
                                                            <span className="cr-nv-usage-text">{pct.toFixed(1)}%</span>
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                    <CrNcSection id="ceph-mon" title={t('crNxMons')} desc={t('crNxMonDesc')}>
                        <CrNxList id="ceph-mon" list={m.mon} count={m.mons.total} loading={loading} onRetry={onReload} emptyKey="crNxMonEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('crNxMons')}>
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxHost')}</th><th>{t('crNxAddr')}</th><th>{t('crNxQuorum')}</th></tr></thead>
                                    <tbody>
                                        {m.mon.rows.map((mon, i) => {
                                            const q = inQuorum(mon);
                                            return (
                                                <tr key={mon.name || i} data-cr-nx-mon={mon.name || ''}>
                                                    <td className="cr-mono">{mon.name || <CrNcMissing />}</td>
                                                    <td>{mon.host || <CrNcMissing />}</td>
                                                    <td className="cr-mono">{mon.addr || <CrNcMissing />}</td>
                                                    <td data-cr-nx-quorum={q == null ? 'none' : q ? 'yes' : 'no'}>{q == null ? <CrNcMissing /> : q ? <CrBadge tone="success">{yes}</CrBadge> : <CrBadge tone="warning">{no}</CrBadge>}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                    <CrNcSection id="ceph-pool" title={t('crNxPools')} desc={t('crNxPoolDesc')}>
                        <CrNxList id="ceph-pool" list={m.pool} count={null} loading={loading} onRetry={onReload} emptyKey="crNxPoolEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('crNxPools')}>
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxReplicas')}</th><th>{t('crNxPgTotal')}</th><th>{t('crNxApp')}</th><th>{t('crNxStored')}</th><th>{t('crNxUsedPct')}</th></tr></thead>
                                    <tbody>
                                        {m.pool.rows.map((p, i) => {
                                            const size = crNvNum(p.size), min = crNvNum(p.min_size);
                                            const frac = crNvNum(p.percent_used);
                                            const pct = frac != null && frac >= 0 ? Math.min(100, frac * 100) : null;
                                            const apps = p.application_metadata && typeof p.application_metadata === 'object' ? Object.keys(p.application_metadata) : [];
                                            return (
                                                <tr key={p.pool_name || i} data-cr-nx-pool={p.pool_name || ''}>
                                                    <td className="cr-mono">{p.pool_name || <CrNcMissing />}</td>
                                                    <td>{size != null ? (
                                                        <span className={size < 2 ? 'cr-nc-warn' : undefined} data-cr-nx-repl={size}>
                                                            {crNnT(t, 'crNxReplLine', { n: size, min: min != null ? min : '?' })}
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                    <td>{crNvNum(p.pg_num) != null ? crNvNum(p.pg_num) : <CrNcMissing />}</td>
                                                    <td>{apps.length ? apps.join(', ') : <CrNcMissing />}</td>
                                                    <td>{crNvBytes(p.bytes_used) || <CrNcMissing />}</td>
                                                    <td>{pct != null ? (
                                                        <span className={`cr-nv-usage cr-nv-tone-${crStoreTone(pct)}`} data-cr-nv-usage={`pool-${p.pool_name}`} title={crStoreScale(t)}>
                                                            <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
                                                            <span className="cr-nv-usage-text">{pct < 0.1 && pct > 0 ? '<0.1%' : `${pct.toFixed(1)}%`}</span>
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                </>
            );
        }

        // the storage, repository and Ceph sub tabs of Configure, each from the read the view keeps
        function CrNodeStoreCfg({ tab, node, clusterId, data, loading, saving, readOnly, zfsPool, onZfsPool,
                                  onReloadDisks, onReloadRepos, onReloadCeph, onToggleRepo, onAptUpdate, onDirty }) {
            return (
                <div className="cr-nc-page" data-cr-nc-tab={tab}>
                    {tab === 'lvm' && <CrNodeLvm read={data.disksRead} loading={loading} onReload={onReloadDisks} />}
                    {tab === 'lvmthin' && <CrNodeLvmThin read={data.disksRead} loading={loading} onReload={onReloadDisks} />}
                    {tab === 'zfs' && <CrNodeZfs clusterId={clusterId} node={node} read={data.disksRead} loading={loading} onReload={onReloadDisks}
                        pool={zfsPool} onPool={onZfsPool} />}
                    {tab === 'repos' && <CrNodeRepos node={node} repos={data.reposRead === undefined ? undefined : data.repos} fail={crNdFail(data.reposRead)}
                        loading={loading} saving={saving} readOnly={readOnly} onToggle={onToggleRepo} onAptUpdate={onAptUpdate} onReload={onReloadRepos} onDirty={onDirty} />}
                    {tab === 'ceph' && <CrNodeCeph read={data.cephRead} loading={loading} onReload={onReloadCeph} />}
                </div>
            );
        }
