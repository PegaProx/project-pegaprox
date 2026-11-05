        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the datastores - LW Oct 2026
        // The Browse tab of a cluster's Datastore tab (the storages grouped by node on
        // the left, the content of the picked one on the right) and the rows of the
        // datastore view in the sidebar. DatastoreTab keeps its state, its handlers and
        // every dialog; this only draws them and calls the same setters, so a permission,
        // a confirmation or a request is the one classic has. A field the API did not
        // send is not shown.
        // ═══════════════════════════════════════════════════════════

        // rowH/groupH/noteH: fixed heights of the virtual list; foldFrom: above this many nodes
        // only the shared group and the node on screen start open
        const CR_DS = { rowH: 44, groupH: 28, noteH: 30, overscan: 8, foldFrom: 12, minH: 320, gap: 8 };
        // the storage types classic offers a rescan for (DatastoreTab)
        const CR_DS_RESCAN = ['iscsi', 'iscsidirect', 'lvm', 'lvmthin', 'zfspool', 'zfs', 'starlvm'];
        // the content types of PVE, in the order the chips show them
        const CR_DS_TYPES = ['images', 'rootdir', 'backup', 'iso', 'vztmpl', 'snippets', 'import'];
        // the order and the primary one of the storage actions, as classic lines them up
        const CR_DS_ACTIONS = ['templates', 'url', 'upload', 'rescan', 'restore', 'recent'];
        const CR_DS_PRIMARY = ['upload', 'restore', 'url', 'templates'];

        const crHas = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k);
        const crOff = (v) => v === 0 || v === false || v === '0';

        // the storage limits (CR_STORE_WARN/CR_STORE_CRIT, crStoreTone) live beside CR_WARN in cr_views.js

        // What a storage of /datastores says about itself, from the fields that are there.
        // Unavailable is classic's rule (active 0 or enabled 0), told apart into disabled and
        // inactive, plus the offline node the server marks. Usage only with a total above 0.
        function crStorageState(s) {
            if (!s) return null;
            const offline = s.node_offline === true;
            const disabled = !offline && crHas(s, 'enabled') && crOff(s.enabled);
            const inactive = !offline && !disabled && crHas(s, 'active') && crOff(s.active);
            const unavailable = offline || disabled || inactive;
            const on = Array.isArray(s.active_on) ? s.active_on : null;
            const off = Array.isArray(s.inactive_on) ? s.inactive_on : null;
            const partial = !unavailable && on && off && on.length > 0 && off.length > 0 ? { on, off } : null;
            const total = Number(s.total);
            const used = Number(s.used);
            const known = !unavailable && Number.isFinite(total) && total > 0 && Number.isFinite(used);
            const raw = !unavailable && crHas(s, 'total') && crHas(s, 'used') && total === 0 && used === 0;
            const pct = known ? used / total * 100 : null;
            const avail = known && crHas(s, 'avail') && Number.isFinite(Number(s.avail)) ? Number(s.avail) : null;
            return {
                offline, disabled, inactive, unavailable, partial, raw, pct, avail,
                used: known ? used : null, total: known ? total : null,
                tone: pct == null ? null : crStoreTone(pct),
                active: crHas(s, 'active') && !unavailable && !crOff(s.active),
                shared: crHas(s, 'shared') ? (!!s.shared && !crOff(s.shared)) : null,
            };
        }
        const crDsBad = (st) => !!st && (st.unavailable || !!st.partial || st.tone === 'warning' || st.tone === 'error');

        // the definition classic looks up for the storage on screen: a shared one first, then the node's
        function crStorageDef(datastores, sel) {
            if (!sel || !datastores) return null;
            return (datastores.shared || []).find(s => s.storage === sel.name)
                || ((datastores.local || {})[sel.node] || []).find(s => s.storage === sel.name) || null;
        }

        // the buttons classic puts in the head of the storage on screen, under exactly its conditions
        function crStorageActions(def, content, may, canUploadTo) {
            const list = Array.isArray(content) ? content : [];
            const out = [];
            if (def?.content?.includes('vztmpl') && may('storage.upload')) out.push('templates');
            if (def?.content?.includes('iso') && may('storage.upload')) out.push('url');
            if (may('storage.upload') && canUploadTo(def)) out.push('upload');
            if (CR_DS_RESCAN.includes(def?.type) && may('storage.config')) out.push('rescan');
            if (may('vm.backup') && list.some(i => i.content === 'backup' && i.vmid)) out.push('restore');
            if (may('backup.view') && list.some(i => i.content === 'backup')) out.push('recent');
            return out;
        }

        // classic's trash button: any backup, and an ISO or template that no guest owns
        const crDeletable = (item, mayDelete) => mayDelete && !!item
            && (item.content === 'backup' || (!item.vmid && (item.content === 'iso' || item.content === 'vztmpl')));

        // the name of a volume without its storage and its content folder
        function crVolName(volid) {
            const v = String(volid || '');
            const at = v.indexOf(':');
            let rest = at >= 0 ? v.slice(at + 1) : v;
            const dir = rest.match(/^(iso|vztmpl|snippets|import|backup)\//);
            if (dir) rest = rest.slice(dir[0].length);
            return rest || v;
        }

        function crDsIcon(content) {
            const c = String(content || '');
            if (c.includes('iso')) return <Icons.Disc />;
            if (c.includes('images')) return <Icons.HardDrive />;
            if (c.includes('rootdir')) return <Icons.Box />;
            if (c.includes('backup')) return <Icons.Archive />;
            if (c.includes('vztmpl')) return <Icons.Package />;
            if (c.includes('snippets')) return <Icons.FileText />;
            if (c.includes('import')) return <Icons.FolderInput />;
            return <Icons.Database />;
        }

        // a backup time to the minute (fmtDate's parts, its 12h setting); the title keeps the seconds
        function crDsDate(sec) {
            return crFmtDate(sec, { second: undefined });
        }

        function crDsTypeLabel(t, c) {
            switch (c) {
                case 'images': return t('crDsCtImages');
                case 'rootdir': return t('crDsCtRootdir');
                case 'backup': return t('backup');
                case 'iso': return t('crDsCtIso');
                case 'vztmpl': return t('crDsCtVztmpl');
                case 'snippets': return t('crDsCtSnippets');
                case 'import': return t('import');
                default: return c || '';
            }
        }

        // one sentence for the title of a storage: what it is, where, and how full
        function crStoreTitle(s, st, t, node) {
            const parts = [`${s.storage}${s.type ? ` (${s.type})` : ''}${node ? ` - ${node}` : ''}`];
            if (st.offline) parts.push(t('crDsNodeOffline'));
            else if (st.disabled) parts.push(t('crDsDisabled'));
            else if (st.inactive) parts.push(t('crDsInactiveHint'));
            if (st.partial) parts.push(`${t('activeOn')}: ${st.partial.on.join(', ')}; ${t('unreachableFrom')}: ${st.partial.off.join(', ')}`);
            if (st.raw) parts.push(t('storageRawNoUsage'));
            if (st.pct != null) {
                const free = st.avail != null ? `, ${crBytes(st.avail)} ${t('free')}` : '';
                parts.push(`${crPct(st.pct, 1)} - ${crFill(t('crUsedOf'), { used: crBytes(st.used), total: crBytes(st.total) })}${free}`);
            }
            return parts.join('. ');
        }

        // --- small pieces -----------------------------------------------------------

        function CrDsWarn({ st }) {
            const { t } = useTranslation();
            if (!st || (st.tone !== 'warning' && st.tone !== 'error')) return null;
            const text = crFill(t('crDsHighUse'), { pct: crPct(st.pct) });
            return (
                <span className={`cr-ds-warn cr-tone-text cr-tone-${st.tone}`} role="img" aria-label={text} title={text}
                    data-cr-ds-warn={st.tone}>
                    <Icons.AlertTriangle />
                </span>
            );
        }

        // the capacity of a storage, the same meter in every row and in the head
        function CrDsCap({ st, wide = false }) {
            const { t } = useTranslation();
            if (!st || st.unavailable) return null;
            if (st.raw) return <span className="cr-ds-nostats" data-cr-ds-cap="raw">{t('storageRawNoUsage')}</span>;
            if (st.pct == null) return null;
            const text = crFill(t('crUsedOf'), { used: crBytes(st.used), total: crBytes(st.total) });
            return (
                <span className={`cr-ds-cap${wide ? ' cr-ds-cap-wide' : ''}`} data-cr-ds-cap={st.pct.toFixed(2)}>
                    <CrMeter value={st.pct} tone={st.tone} title={`${crPct(st.pct, 1)} - ${text}. ${crStoreScale(t)}`} />
                    <span className="cr-ds-cap-text" data-cr-ds-used="">{wide ? text : `${crBytes(st.used)} / ${crBytes(st.total)}`}</span>
                    {wide && st.avail != null && <span className="cr-ds-cap-free">{crBytes(st.avail)} {t('free')}</span>}
                </span>
            );
        }

        // what PVE says is left, as it reports it (avail: thin pools and ZFS differ from total minus used)
        // (the narrow sidebar row shows the figure alone; its title and the row's name say what it is)
        function CrDsFree({ st, short = false }) {
            const { t } = useTranslation();
            if (!st || st.unavailable || st.avail == null) return null;
            const text = `${crBytes(st.avail)} ${t('free')}`;
            return <span className={short ? 'cr-ds-node-free' : 'cr-ds-free'} data-cr-ds-free={String(st.avail)} title={text}>{short ? crBytes(st.avail) : text}</span>;
        }

        // /datastores tells whether a storage is enabled and active, nothing about the state of its data
        function CrDsHealth() {
            const { t } = useTranslation();
            return (
                <span className="cr-ds-health" data-cr-ds-health="unreported" title={t('crStoreHealthHint')}>
                    {t('crStoreHealthUnreported')}
                </span>
            );
        }

        function CrDsBadges({ st, head = false }) {
            const { t } = useTranslation();
            if (!st) return null;
            const out = [];
            if (st.offline) out.push(<CrBadge key="off" tone="error"><span data-cr-ds-state="offline">{t('crDsNodeOffline')}</span></CrBadge>);
            else if (st.disabled) out.push(<CrBadge key="dis" tone="neutral"><span data-cr-ds-state="disabled">{t('crDsDisabled')}</span></CrBadge>);
            else if (st.inactive) out.push(<CrBadge key="ina" tone="error" title={t('crDsInactiveHint')}><span data-cr-ds-state="inactive">{t('crDsInactive')}</span></CrBadge>);
            else if (head && st.active) out.push(<CrBadge key="act" tone="success"><span data-cr-ds-state="active">{t('active')}</span></CrBadge>);
            if (st.partial) {
                const n = st.partial.on.length;
                const all = n + st.partial.off.length;
                out.push(
                    <CrBadge key="part" tone="warning"
                        title={`${t('activeOn')}: ${st.partial.on.join(', ')}; ${t('unreachableFrom')}: ${st.partial.off.join(', ')}`}>
                        <span data-cr-ds-state="partial">{n}/{all} {t('nodes')}</span>
                    </CrBadge>
                );
            }
            if (head && st.shared) out.push(<CrBadge key="sh" tone="info" dot={false}><span data-cr-ds-state="shared">{t('shared')}</span></CrBadge>);
            return out.length ? <span className="cr-ds-badges">{out}</span> : null;
        }

        // --- the left panel: one virtual list of groups and storages ------------------

        // Groups (shared, one per node, the ESXi hosts last as classic) with their storages under
        // them. A filter or "problems only" shows every group with a hit, open.
        function crStorageRows(datastores, esxiHosts, opts) {
            const { query, problems, isOpen, t, esxiErr } = opts;
            const q = (query || '').trim().toLowerCase();
            const narrowed = !!q || problems;
            const out = [];
            const hit = (s, node) => !q || [s.storage, s.type, node, s.content].some(v => v && String(v).toLowerCase().includes(q));
            const group = (id, label, list, node, extra) => {
                const items = [];
                list.forEach(s => {
                    if (!hit(s, node)) return;
                    const st = crStorageState(s);
                    if (problems && !crDsBad(st)) return;
                    items.push({ kind: 'store', key: `s:${s.storage}@${node || ''}`, h: CR_DS.rowH, s, st,
                                 node: node || null, group: `g:${id}` });
                });
                if (narrowed && !items.length) return;
                const open = narrowed || isOpen(id);
                out.push({ kind: 'group', key: `g:${id}`, id, h: CR_DS.groupH, label, count: list.length,
                           shown: narrowed ? items.length : null, open, ...extra });
                if (open) items.forEach(r => out.push(r));
            };
            const shared = (datastores && datastores.shared) || [];
            if (shared.length) group('shared', t('sharedStorage'), shared, null, { icon: 'shared' });
            ((datastores && datastores.nodes) || []).forEach(n => {
                const list = ((datastores.local || {})[n]) || [];
                group(`n:${n}`, n, list, n, { icon: 'node', offline: list.length > 0 && list.every(s => s.node_offline) });
            });
            const hosts = Array.isArray(esxiHosts) ? esxiHosts : [];
            const hostHits = hosts.filter(h => !q || String(h.host || '').toLowerCase().includes(q));
            if (!problems && (!q || hostHits.length)) {
                const open = !!q || isOpen('esxi');
                // a host list that could not be read has no count and is not "no hosts"
                const failed = !!esxiErr && !hosts.length;
                out.push({ kind: 'group', key: 'g:esxi', id: 'esxi', h: CR_DS.groupH, label: t('esxiHosts'), count: failed ? '-' : hosts.length, open, icon: 'esxi' });
                if (open) {
                    if (!hostHits.length) out.push({ kind: 'note', key: 'note:esxi', h: CR_DS.noteH, text: failed ? t('crDsEsxiNotRead') : t('noEsxiHosts'), group: 'g:esxi' });
                    hostHits.forEach(h => out.push({ kind: 'esxi', key: `e:${h.id}`, h: CR_DS.noteH, host: h, group: 'g:esxi' }));
                }
            }
            return out;
        }

        function CrStorageList({ rows, selectedKey, onActivate, onToggle, onMenu, label }) {
            const { t } = useTranslation();
            const ref = useRef(null);
            const [scrollTop, setScrollTop] = useState(0);
            const [viewH, setViewH] = useState(400);
            const [focusKey, setFocusKey] = useState(null);
            const wantFocus = useRef(null);  // the row key a keyboard move still has to focus

            const layout = useMemo(() => {
                const tops = new Array(rows.length);
                const nav = [];
                const pos = {};
                let y = 0;
                let n = 0;
                const sizes = {};
                rows.forEach(r => { if (r.group) sizes[r.group] = (sizes[r.group] || 0) + (r.kind === 'note' ? 0 : 1); });
                const groups = rows.filter(r => r.kind === 'group').length;
                let gi = 0;
                for (let i = 0; i < rows.length; i++) {
                    const r = rows[i];
                    tops[i] = y;
                    y += r.h;
                    if (r.kind !== 'note') nav.push(i);
                    if (r.kind === 'group') { gi++; n = 0; pos[r.key] = [gi, groups]; }
                    else if (r.kind !== 'note') { n++; pos[r.key] = [n, sizes[r.group] || 1]; }
                }
                return { tops, total: y, nav, pos };
            }, [rows]);

            const measure = () => {
                const el = ref.current;
                if (!el) return;
                setScrollTop(el.scrollTop);
                if (el.clientHeight) setViewH(el.clientHeight);
            };
            useEffect(() => {
                measure();
                if (typeof ResizeObserver === 'undefined' || !ref.current) return;
                const ro = new ResizeObserver(() => measure());
                ro.observe(ref.current);
                return () => ro.disconnect();
            }, []);

            const keys = useMemo(() => rows.map(r => r.key), [rows]);
            const indexOf = (k) => (k == null ? -1 : keys.indexOf(k));
            let fi = indexOf(focusKey);
            if (fi < 0 || rows[fi].kind === 'note') fi = indexOf(selectedKey);
            if (fi < 0 && layout.nav.length) fi = layout.nav[0];

            // the same as CrTable: the target from the ref, a pending effect of an earlier render
            // may run after the key. A row that is gone falls back to this render's one. A layout
            // effect, so the next key (Enter right after ArrowDown) reaches the row it moved to
            React.useLayoutEffect(() => {
                const want = wantFocus.current;
                if (want == null || !ref.current) return;
                const k = keys.includes(want) ? want : (fi >= 0 ? rows[fi].key : null);
                if (k == null) return;
                const el = ref.current.querySelector(`[data-cr-ds-row="${CSS.escape(k)}"]`);
                if (el) {
                    el.focus({ preventScroll: true });
                    wantFocus.current = null;
                }
            });

            // the rows in view and a margin, plus the one that holds the focus
            const { tops, total, nav, pos } = layout;
            const lo = scrollTop - CR_DS.overscan * CR_DS.rowH;
            const hi = scrollTop + viewH + CR_DS.overscan * CR_DS.rowH;
            let a = 0;
            let b = rows.length;
            while (a < b) { const m = (a + b) >> 1; if (tops[m] + rows[m].h <= lo) a = m + 1; else b = m; }
            const start = a;
            let end = start;
            while (end < rows.length && tops[end] < hi) end++;
            const shown = [];
            for (let i = start; i < end; i++) shown.push(i);
            if (fi >= 0 && (fi < start || fi >= end)) shown.push(fi);

            const moveTo = (i) => {
                if (i < 0 || i >= rows.length) return;
                setFocusKey(rows[i].key);
                wantFocus.current = rows[i].key;
                const el = ref.current;
                if (!el) return;
                if (tops[i] < el.scrollTop) el.scrollTop = tops[i];
                else if (tops[i] + rows[i].h > el.scrollTop + el.clientHeight) el.scrollTop = tops[i] + rows[i].h - el.clientHeight;
                measure();
            };
            const step = (i, d) => {
                const at = nav.indexOf(i);
                const next = nav[crClamp(at + d, 0, nav.length - 1)];
                if (next != null) moveTo(next);
            };
            const onKey = (e, r, i) => {
                const k = e.key;
                if (k === 'ArrowDown') { e.preventDefault(); step(i, 1); }
                else if (k === 'ArrowUp') { e.preventDefault(); step(i, -1); }
                else if (k === 'Home') { e.preventDefault(); moveTo(nav[0]); }
                else if (k === 'End') { e.preventDefault(); moveTo(nav[nav.length - 1]); }
                else if (k === 'PageDown' || k === 'PageUp') {
                    e.preventDefault();
                    step(i, (k === 'PageDown' ? 1 : -1) * Math.max(1, Math.floor(viewH / CR_DS.rowH) - 1));
                } else if (k === 'Enter' || k === ' ') {
                    e.preventDefault();
                    if (r.kind === 'group') onToggle(r); else onActivate(r);
                } else if (k === 'ArrowRight' && r.kind === 'group') {
                    e.preventDefault();
                    if (!r.open) onToggle(r); else step(i, 1);
                } else if (k === 'ArrowLeft') {
                    e.preventDefault();
                    if (r.kind === 'group') { if (r.open) onToggle(r); }
                    else moveTo(indexOf(r.group));
                } else if (k === 'ContextMenu' || (e.shiftKey && k === 'F10')) {
                    e.preventDefault();
                    const box = e.currentTarget.getBoundingClientRect();
                    onMenu(r, { clientX: box.left + 24, clientY: box.bottom });
                }
            };

            return (
                <div className="cr-ds-list" ref={ref} onScroll={measure} data-cr-ds-list="">
                    <div className="cr-ds-list-in" role="tree" aria-label={label} style={{ height: total }}>
                        {shown.map(i => {
                            const r = rows[i];
                            const style = { top: tops[i], height: r.h };
                            if (r.kind === 'note') {
                                return <div key={r.key} className="cr-ds-row cr-ds-note" style={style} role="presentation">{r.text}</div>;
                            }
                            const tab = i === fi ? 0 : -1;
                            const [p, n] = pos[r.key] || [1, 1];
                            const common = {
                                style, tabIndex: tab, 'data-cr-ds-row': r.key,
                                'aria-posinset': p, 'aria-setsize': n,
                                onKeyDown: (e) => onKey(e, r, i),
                                onFocus: () => { if (focusKey !== r.key) setFocusKey(r.key); },
                            };
                            if (r.kind === 'group') {
                                return (
                                    <div key={r.key} {...common} role="treeitem" aria-level={1} aria-expanded={r.open}
                                        className={`cr-ds-row cr-ds-group${r.offline ? ' cr-ds-group-off' : ''}`} data-cr-ds-group={r.id}
                                        onClick={() => { setFocusKey(r.key); onToggle(r); }}>
                                        <Icons.ChevronRight className={`cr-ds-chev${r.open ? ' cr-ds-chev-open' : ''}`} aria-hidden="true" />
                                        <span className="cr-ico" aria-hidden="true">
                                            {r.icon === 'shared' ? <Icons.Globe /> : r.icon === 'esxi' ? <Icons.Cloud /> : <Icons.Server />}
                                        </span>
                                        <span className="cr-ds-group-name">{r.label}</span>
                                        {r.offline && <span className="cr-ds-group-flag">{t('offline')}</span>}
                                        <span className="cr-ds-group-n" data-cr-ds-group-n="">{r.shown != null ? `${r.shown}/${r.count}` : r.count}</span>
                                    </div>
                                );
                            }
                            const sel = r.key === selectedKey;
                            if (r.kind === 'esxi') {
                                const h = r.host;
                                return (
                                    <div key={r.key} {...common} role="treeitem" aria-level={2} aria-selected={sel}
                                        className={`cr-ds-row cr-ds-host${sel ? ' cr-ds-sel' : ''}`}
                                        onClick={() => { setFocusKey(r.key); onActivate(r); }}
                                        onContextMenu={(e) => { e.preventDefault(); setFocusKey(r.key); onMenu(r, e); }}>
                                        <span className={`cr-dot cr-dot-${h.connected ? 'success' : 'error'}`} aria-hidden="true" />
                                        <span className="cr-ds-name">{h.host}</span>
                                        {!h.connected && <span className="cr-ds-group-flag">{t('offline')}</span>}
                                    </div>
                                );
                            }
                            const s = r.s;
                            const st = r.st;
                            const tip = crStoreTitle(s, st, t, r.node);
                            return (
                                <div key={r.key} {...common} role="treeitem" aria-level={2} aria-selected={sel} aria-label={tip} title={tip}
                                    className={`cr-ds-row cr-ds-store${sel ? ' cr-ds-sel' : ''}${st.unavailable ? ' cr-ds-unavail' : ''}`}
                                    onClick={() => { setFocusKey(r.key); onActivate(r); }}
                                    onContextMenu={(e) => { e.preventDefault(); setFocusKey(r.key); onMenu(r, e); }}>
                                    <span className="cr-ds-line">
                                        <span className="cr-ico cr-ds-ico" aria-hidden="true">{crDsIcon(s.content)}</span>
                                        <span className="cr-ds-name">{s.storage}</span>
                                        <span className="cr-ds-type">{s.type}</span>
                                        <CrDsBadges st={st} />
                                        <CrDsWarn st={st} />
                                        <CrDsFree st={st} />
                                    </span>
                                    <span className="cr-ds-line cr-ds-line2">
                                        <CrDsCap st={st} />
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            );
        }

        // --- the right panel ----------------------------------------------------------

        function CrStorageHead({ sel, def, st, datastores, count, loading, actions, run, onRefresh, onPick }) {
            const { t } = useTranslation();
            const shared = (datastores.shared || []).find(s => s.storage === sel.name);
            const activeOn = Array.isArray(shared?.active_on) ? shared.active_on : [];
            const inactiveOn = Array.isArray(shared?.inactive_on) ? shared.inactive_on : [];
            // classic's switch: a shared storage that more than one node mounts, or not every node
            const viewFrom = activeOn.length > 0 && (activeOn.length > 1 || inactiveOn.length > 0);
            const primary = CR_DS_PRIMARY.find(id => actions.includes(id));
            const label = {
                templates: t('crDsTemplates'), url: t('fromUrl'), upload: t('upload'), rescan: t('rescan'),
                restore: t('batchRestoreButton'), recent: t('batchRestoreRecent'),
            };
            const icon = {
                templates: <Icons.Download />, url: <Icons.Link />, upload: <Icons.Upload />, rescan: <Icons.RefreshCw />,
                restore: <Icons.RotateCcw />, recent: <Icons.ClipboardList />,
            };
            const hint = { url: t('downloadFromUrl'), rescan: t('rescanStorageTooltip'), templates: t('downloadTemplates') };
            const hooks = { restore: { 'data-br-open': '' }, recent: { 'data-br-recent-open': '' } };
            return (
                <div className="cr-ds-head" data-cr-ds-head="">
                    <div className="cr-ds-head-main">
                        <span className="cr-ico cr-ds-head-ico" aria-hidden="true">{crDsIcon(def?.content)}</span>
                        <h2 className="cr-ds-title" data-cr-ds-title="">{sel.name}</h2>
                        {def?.type && <span className="cr-ds-type">{def.type}</span>}
                        {!shared && sel.node && <span className="cr-ds-where">{crFill(t('crDsOnNode'), { node: sel.node })}</span>}
                        {viewFrom && (
                            <label className="cr-ds-where">
                                <span>{t('viewFromNode')}</span>
                                <select className="cr-select" value={sel.node || activeOn[0]} data-cr-ds-viewfrom=""
                                    aria-label={t('viewFromNode')} onChange={e => onPick(sel.name, e.target.value)}>
                                    {activeOn.map(n => <option key={n} value={n}>{n}</option>)}
                                    {inactiveOn.map(n => <option key={n} value={n} disabled>{n} ({t('storageUnreachable')})</option>)}
                                </select>
                            </label>
                        )}
                        <CrDsBadges st={st} head />
                        {def && <CrDsHealth />}
                        {!loading && count != null && <span className="cr-ds-count">{crFill(t('crDsEntries'), { n: count })}</span>}
                    </div>
                    <div className="cr-ds-head-side">
                        {st && (
                            <span className="cr-ds-head-cap">
                                <CrDsCap st={st} wide />
                                <CrDsWarn st={st} />
                            </span>
                        )}
                        <span className="cr-ds-actions">
                            {CR_DS_ACTIONS.filter(id => actions.includes(id)).map(id => (
                                <CrButton key={id} variant={id === primary ? 'primary' : 'default'} icon={icon[id]}
                                    data-cr-ds-action={id} title={hint[id]} onClick={run[id]} {...(hooks[id] || {})}>
                                    {label[id]}
                                </CrButton>
                            ))}
                            <button type="button" className="cr-icon-btn" onClick={onRefresh} data-cr-ds-action="refresh"
                                aria-label={t('refresh')} title={t('refresh')}>
                                <span className={`cr-ico${loading ? ' cr-ds-spin' : ''}`} aria-hidden="true"><Icons.RotateCw /></span>
                            </button>
                        </span>
                    </div>
                </div>
            );
        }

        // The content of a storage. Columns only for fields the rows have; the owner is a link
        // when the guest is in the inventory the user sees, else its id.
        function CrStorageContent({ rows, loading, error, mayDelete, guests, onOpenGuest, actions, run, storeKey, narrow }) {
            const { t } = useTranslation();
            const [type, setType] = useState('all');
            const [menu, setMenu] = useState(null);
            const cb = useRef(null);
            cb.current = { run, onOpenGuest };
            const list = Array.isArray(rows) ? rows : [];
            const byVmid = useMemo(() => {
                const m = new Map();
                (Array.isArray(guests) ? guests : []).forEach(g => {
                    if (g && g.vmid != null && (g.type === 'qemu' || g.type === 'lxc')) m.set(String(g.vmid), g);
                });
                return m;
            }, [guests]);
            const info = useMemo(() => {
                const counts = {};
                const has = { ctime: false, notes: false, protected: false, verification: false, vmid: false, format: false };
                for (let i = 0; i < list.length; i++) {
                    const r = list[i];
                    counts[r.content] = (counts[r.content] || 0) + 1;
                    if (r.ctime != null) has.ctime = true;
                    if (r.notes) has.notes = true;
                    if (crHas(r, 'protected')) has.protected = true;
                    if (r.verification && r.verification.state) has.verification = true;
                    if (r.vmid != null && r.vmid !== '') has.vmid = true;
                    if (r.format) has.format = true;
                }
                return { counts, has };
            }, [list]);
            const h = info.has;
            const types = useMemo(() => {
                const seen = Object.keys(info.counts);
                return CR_DS_TYPES.filter(k => info.counts[k]).concat(seen.filter(k => k && !CR_DS_TYPES.includes(k)).sort());
            }, [info]);
            const picked = type === 'all' || info.counts[type] ? type : 'all';
            const filter = useMemo(() => (picked === 'all' ? null : (r => r.content === picked)), [picked]);

            const guestOf = (r) => (r.vmid != null ? byVmid.get(String(r.vmid)) || null : null);
            const columns = useMemo(() => {
                const cols = [
                    { key: 'name', label: t('name'), flex: true, min: 160, sortValue: r => crVolName(r.volid), text: r => r.volid,
                      render: r => (
                          <span className="cr-ds-vol" title={r.volid}>
                              <span className="cr-ico" aria-hidden="true">{crDsIcon(r.content)}</span>
                              <span className="cr-mono cr-ds-volname">{crVolName(r.volid)}</span>
                          </span>
                      ) },
                    { key: 'content', label: t('type'), width: 100, sortValue: r => crDsTypeLabel(t, r.content),
                      text: r => `${crDsTypeLabel(t, r.content)} ${r.content || ''}`,
                      render: r => <span data-cr-ds-ct={r.content || ''} title={r.content || ''}>{crDsTypeLabel(t, r.content)}</span> },
                ];
                if (h.vmid) {
                    cols.push({ key: 'owner', label: t('crDsOwner'), width: 112,
                        sortValue: r => (r.vmid != null && r.vmid !== '' ? Number(r.vmid) : null),
                        text: r => { const g = guestOf(r); return r.vmid != null ? `${g && g.name ? g.name + ' ' : ''}${r.vmid}` : ''; },
                        render: r => {
                            if (r.vmid == null || r.vmid === '') return '';
                            const g = guestOf(r);
                            if (g && cb.current.onOpenGuest) {
                                return (
                                    <span className="cr-ds-owner">
                                        <button type="button" className="cr-link" data-cr-ds-owner={String(r.vmid)}
                                            title={crFill(t('crTaskOpenTarget'), { name: g.name || r.vmid })}
                                            onClick={(e) => { e.stopPropagation(); cb.current.onOpenGuest(g); }}>
                                            {g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${r.vmid}`}
                                        </button>
                                        <span className="cr-muted cr-mono">{r.vmid}</span>
                                    </span>
                                );
                            }
                            return <span className="cr-mono" data-cr-ds-owner-plain={String(r.vmid)} title={t('crDsNotInInventory')}>{r.vmid}</span>;
                        } });
                }
                // a narrow panel starts without format and notes (the column menu brings them back)
                if (h.format) cols.push({ key: 'format', label: t('format'), width: 76, mono: true, hidden: narrow, render: r => r.format || '' });
                cols.push({ key: 'size', label: t('size'), width: 84, align: 'right', mono: true,
                    sortValue: r => (Number.isFinite(Number(r.size)) && r.size != null ? Number(r.size) : null),
                    text: r => r.size_human || '',
                    render: r => (
                        <span data-cr-ds-size="">
                            {r.size_is_approx && <span className="cr-muted" title={t('crDsApprox')}>~</span>}
                            {r.size_human || crBytes(r.size)}
                        </span>
                    ) });
                if (h.ctime) {
                    cols.push({ key: 'created', label: t('crDsCreated'), width: 140, mono: true,
                        sortValue: r => (r.ctime != null ? Number(r.ctime) : null), text: r => (r.ctime != null ? crDsDate(r.ctime) : ''),
                        render: r => (r.ctime != null ? <span title={crDate(r.ctime)}>{crDsDate(r.ctime)}</span> : '') });
                }
                if (h.notes) cols.push({ key: 'notes', label: t('notes'), width: 140, hidden: narrow, render: r => <span title={r.notes || ''}>{r.notes || ''}</span> });
                if (h.protected) {
                    cols.push({ key: 'protected', label: '', menuLabel: t('protected'), width: 30, resizable: false,
                        sortValue: r => (r.protected && !crOff(r.protected) ? 1 : null), text: r => (r.protected && !crOff(r.protected) ? t('protected') : ''),
                        render: r => (r.protected && !crOff(r.protected) ? (
                            <span className="cr-ds-lock" role="img" aria-label={t('protected')} title={t('protected')} data-cr-ds-protected="">
                                <Icons.Lock />
                            </span>
                        ) : '') });
                }
                if (h.verification) {
                    cols.push({ key: 'verify', label: t('crDsVerified'), width: 90, sortValue: r => (r.verification && r.verification.state) || null,
                        render: r => {
                            const s = r.verification && r.verification.state;
                            if (!s) return '';
                            return <CrBadge tone={s === 'ok' ? 'success' : s === 'failed' ? 'error' : 'neutral'}>{s}</CrBadge>;
                        } });
                }
                if (mayDelete) {
                    cols.push({ key: 'del', label: '', menuLabel: t('delete'), width: 40, resizable: false, sortable: false, text: () => '',
                        render: r => (crDeletable(r, mayDelete) ? (
                            <button type="button" className="cr-icon-btn cr-ds-del" data-cr-ds-del=""
                                aria-label={crFill(t('crDsDeleteNamed'), { name: crVolName(r.volid) })} title={t('delete')}
                                onClick={(e) => { e.stopPropagation(); cb.current.run.remove(r); }}>
                                <span className="cr-ico" aria-hidden="true"><Icons.Trash /></span>
                            </button>
                        ) : '') });
                }
                return cols;
            }, [t, h.vmid, h.format, h.ctime, h.notes, h.protected, h.verification, mayDelete, byVmid, narrow]);

            const openMenu = (r, e) => {
                const items = [];
                const g = guestOf(r);
                if (g && cb.current.onOpenGuest) items.push({ label: t('crDsOpenGuest'), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: () => cb.current.onOpenGuest(g) });
                if (r.content === 'backup' && actions.includes('restore')) items.push({ label: t('batchRestoreButton'), icon: <Icons.RotateCcw className="w-3.5 h-3.5" />, onClick: () => cb.current.run.restore() });
                if (r.content === 'backup' && actions.includes('recent')) items.push({ label: t('batchRestoreRecent'), icon: <Icons.ClipboardList className="w-3.5 h-3.5" />, onClick: () => cb.current.run.recent() });
                if (crDeletable(r, mayDelete)) {
                    if (items.length) items.push({ separator: true });
                    items.push({ label: t('delete'), danger: true, icon: <Icons.Trash className="w-3.5 h-3.5" />, onClick: () => cb.current.run.remove(r) });
                }
                if (!items.length) return;
                setMenu({ back: document.activeElement, position: { x: e.clientX, y: e.clientY }, items });
            };

            const chips = [['all', t('all'), list.length]].concat(types.map(k => [k, crDsTypeLabel(t, k), info.counts[k]]));
            return (
                <>
                    <CrTable key={`${storeKey}${h.ctime ? ':t' : ''}`} id="ds-content" columns={columns} rows={list}
                        rowKey={r => r.volid} filter={filter} searchable onRowContextMenu={openMenu}
                        loading={loading} error={error} emptyText={t('storageEmpty')} ariaLabel={t('content')}
                        initialSort={h.ctime ? { key: 'created', dir: 'desc' } : { key: 'name', dir: 'asc' }}
                        toolbar={list.length > 0 ? (
                            <div className="cr-seg cr-ds-chips" role="group" aria-label={t('crDsContentType')}>
                                {chips.map(([id, label, n]) => (
                                    <button key={id} type="button" className={picked === id ? 'active' : ''} aria-pressed={picked === id}
                                        data-cr-ds-type={id} title={id === 'all' ? undefined : id} onClick={() => setType(id)}>
                                        {label}<span className="cr-seg-n">{n}</span>
                                    </button>
                                ))}
                            </div>
                        ) : null} />
                    {menu && (
                        <ContextMenu items={menu.items} position={menu.position} onClose={() => {
                            const back = menu.back;
                            setMenu(null);
                            if (back && back.isConnected && back.focus) back.focus({ preventScroll: true });
                        }} />
                    )}
                </>
            );
        }

        // error: why the VM list of this host could not be read (never the list of another host)
        function CrEsxiVms({ host, vms, loading, error, isAdmin, onClose, onDisconnect, onRetry }) {
            const { t } = useTranslation();
            const columns = useMemo(() => [
                { key: 'name', label: t('name'), flex: true, min: 160, render: v => <span className="cr-strong">{v.name}</span> },
                { key: 'os', label: t('crDsGuestOs'), width: 180, sortValue: v => (v.guest_os && v.guest_os !== 'Unknown' ? v.guest_os : null),
                  render: v => (v.guest_os && v.guest_os !== 'Unknown' ? v.guest_os : '') },
                { key: 'cpu', label: 'vCPU', width: 70, align: 'right', mono: true, sortValue: v => (v.num_cpu > 0 ? v.num_cpu : null),
                  render: v => (v.num_cpu > 0 ? v.num_cpu : '') },
                { key: 'ram', label: t('ram'), width: 90, align: 'right', mono: true, sortValue: v => (v.memory_mb > 0 ? v.memory_mb : null),
                  render: v => (v.memory_mb > 0 ? `${Math.round(v.memory_mb / 1024)} GB` : '') },
                { key: 'volid', label: t('crDsVolume'), width: 240, mono: true, sortValue: v => v.volid || v.id, render: v => v.volid || v.id },
            ], [t]);
            return (
                <>
                    <div className="cr-ds-head" data-cr-ds-head="esxi">
                        <div className="cr-ds-head-main">
                            <span className="cr-ico cr-ds-head-ico" aria-hidden="true"><Icons.Cloud /></span>
                            <h2 className="cr-ds-title" data-cr-ds-title="">{t('esxiVms')}</h2>
                            <span className="cr-ds-where">{host ? host.host : ''}</span>
                            <span className="cr-ds-count">{t('esxiExperimental')}</span>
                        </div>
                        <div className="cr-ds-head-side">
                            <span className="cr-ds-actions">
                                <span className="cr-ds-count">{t('crDsEsxiHint')}</span>
                                {isAdmin && host && (
                                    <CrButton variant="danger" icon={<Icons.X />} onClick={() => onDisconnect(host.id)} data-cr-ds-action="disconnect">
                                        {t('esxiDisconnect')}
                                    </CrButton>
                                )}
                                <button type="button" className="cr-icon-btn" onClick={onClose} aria-label={t('close')} title={t('close')}>
                                    <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                                </button>
                            </span>
                        </div>
                    </div>
                    {error && !loading ? (
                        <CrNcState id="ds-esxi" kind="error" onRetry={onRetry} data-cr-ds-esxi-error="">
                            {crFill(t('crDsEsxiVmsFailed'), { why: error })}
                        </CrNcState>
                    ) : (
                        <CrTable id="ds-esxi" columns={columns} rows={vms} rowKey={v => v.id} searchable loading={loading}
                            emptyText={t('esxiNoVms')} ariaLabel={t('esxiVms')} initialSort={{ key: 'name', dir: 'asc' }} />
                    )}
                </>
            );
        }

        // --- the Browse tab -------------------------------------------------------------

        // dsFail: the last read of the datastore list failed ({ msg, hasData }), said with a retry
        function CrStorageBrowse({ datastores, dsFail, onDsRetry, selected, content, loading, error, onPick, may, canUploadTo, isAdmin,
                                   guests, onOpenGuest, run, esxi }) {
            const { t } = useTranslation();
            const [query, setQuery] = useState('');
            const [problems, setProblems] = useState(false);
            const [fold, setFold] = useState({});
            const [menu, setMenu] = useState(null);
            const [shownFor, setShownFor] = useState(null);
            const [narrow, setNarrow] = useState(false);
            const rootRef = useRef(null);
            const probeRef = useRef(null);
            const mainRef = useRef(null);
            const data = datastores || { shared: [], local: {}, nodes: [] };
            const nodes = data.nodes || [];
            const many = nodes.length > CR_DS.foldFrom;
            const selNode = selected && selected.node;

            // the two panels end above the task bar; each scrolls inside, the page does not
            React.useLayoutEffect(() => {
                const fit = () => {
                    const el = rootRef.current;
                    if (!el) return;
                    if (window.matchMedia && window.matchMedia('(max-width: 820px)').matches) {
                        if (el.style.height) el.style.height = '';
                        return;
                    }
                    const top = el.getBoundingClientRect().top + window.scrollY;
                    const bottom = probeRef.current ? probeRef.current.offsetHeight : 0;
                    const h = Math.max(CR_DS.minH, Math.floor(window.innerHeight - top - bottom - CR_DS.gap));
                    if (el.style.height !== `${h}px`) el.style.height = `${h}px`;
                };
                // below 900 px the content starts with fewer columns, so its delete column stays in view
                const width = () => { if (mainRef.current) setNarrow(mainRef.current.clientWidth < 900); };
                fit();
                width();
                window.addEventListener('resize', fit);
                let ro = null;
                let rm = null;
                if (typeof ResizeObserver !== 'undefined') {
                    ro = new ResizeObserver(fit);
                    ro.observe(document.body);
                    if (mainRef.current) { rm = new ResizeObserver(width); rm.observe(mainRef.current); }
                }
                return () => { window.removeEventListener('resize', fit); if (ro) ro.disconnect(); if (rm) rm.disconnect(); };
            }, []);

            const selKey = esxi.selected ? `e:${esxi.selected}`
                : selected ? ((((data.local || {})[selected.node]) || []).some(s => s.storage === selected.name)
                    && !(data.shared || []).some(s => s.storage === selected.name)
                    ? `s:${selected.name}@${selected.node}` : `s:${selected.name}@`) : null;
            // the content on screen belongs to the storage picked once its read has landed
            React.useLayoutEffect(() => { if (!loading) setShownFor(selected ? `${selected.name}@${selected.node || ''}` : null); },
                [loading, selected && selected.name, selNode]);
            const storeKey = selected ? `${selected.name}@${selected.node || ''}` : '';
            const fresh = !!selected && shownFor === storeKey;

            const isOpen = (id) => (crHas(fold, id) ? fold[id] : (id === 'esxi' ? false : (!many || id === 'shared' || id === `n:${selNode}`)));
            const rows = useMemo(() => crStorageRows(data, esxi.hosts, { query, problems, isOpen, t, esxiErr: esxi.hostsErr }),
                [data, esxi.hosts, esxi.hostsErr, query, problems, fold, many, selNode, t]);
            const listUnread = !!dsFail && !dsFail.hasData;

            const def = crStorageDef(data, selected);
            const st = crStorageState(def);
            const shownContent = fresh ? content : [];
            const actions = useMemo(() => (selected ? crStorageActions(def, shownContent, may, canUploadTo) : []),
                [def, shownContent, selected, may, canUploadTo]);
            const mayDelete = may('storage.delete');

            const pickRow = (r) => {
                if (r.kind === 'esxi') { esxi.pick(r.host.id); return; }
                if (r.kind !== 'store') return;
                if (esxi.selected) esxi.close();
                const s = r.s;
                // a shared row reads through a node that mounts it, as classic does
                const node = r.node || (Array.isArray(s.active_on) && s.active_on.length > 0 ? s.active_on[0] : null);
                onPick(s.storage, node);
            };
            const toggle = (r) => setFold(f => ({ ...f, [r.id]: !r.open }));
            const rowMenu = (r, e) => {
                const items = [];
                if (r.kind === 'esxi') {
                    items.push({ label: t('crOpen'), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: () => pickRow(r) });
                    if (isAdmin) {
                        items.push({ separator: true });
                        items.push({ label: t('esxiDisconnect'), danger: true, icon: <Icons.X className="w-3.5 h-3.5" />, onClick: () => esxi.disconnect(r.host.id) });
                    }
                } else if (r.kind === 'store') {
                    const s = r.s;
                    const node = r.node || (Array.isArray(s.active_on) && s.active_on.length > 0 ? s.active_on[0] : null);
                    const on = selKey === r.key;
                    // a storage that is not on screen is picked first, so the dialog works on it
                    const first = (fn) => () => { if (!on) pickRow(r); fn(); };
                    const rowDef = crStorageDef(data, { name: s.storage, node });
                    const ids = crStorageActions(rowDef, [], may, canUploadTo);
                    const label = { templates: t('crDsTemplates'), url: t('fromUrl'), upload: t('upload'), rescan: t('rescan') };
                    items.push({ label: t('crOpen'), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: () => pickRow(r) });
                    if (ids.length) items.push({ separator: true });
                    ids.forEach(id => items.push({ label: label[id], onClick: first(run[id]) }));
                } else return;
                setMenu({ back: document.activeElement, position: { x: e.clientX, y: e.clientY }, items });
            };

            const storeCount = (data.shared || []).length + nodes.reduce((n, x) => n + (((data.local || {})[x]) || []).length, 0);
            return (
                <div className="cr-ds" ref={rootRef} data-cr-ds="">
                    <span className="cr-ds-probe" ref={probeRef} aria-hidden="true" />
                    <section className="cr-ds-side" aria-label={t('datastores')}>
                        <div className="cr-ds-side-head">
                            <span className="cr-table-title">{t('datastores')}</span>
                            <span className="cr-ds-count">{listUnread ? '-' : storeCount}</span>
                            <button type="button" className={`cr-ds-toggle${problems ? ' active' : ''}`} aria-pressed={problems}
                                data-cr-ds-problems="" title={crFill(t('crStoreProblemsHint'), { warn: CR_STORE_WARN })} onClick={() => setProblems(v => !v)}>
                                <Icons.AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />{t('crDsProblems')}
                            </button>
                        </div>
                        <div className="cr-ds-side-filter">
                            <div className="cr-search-box">
                                <Icons.Search className="cr-search-ico" />
                                <input type="search" className="cr-input" value={query} onChange={e => setQuery(e.target.value)}
                                    placeholder={t('crDsFilter')} aria-label={t('crDsFilter')} data-cr-ds-filter="" />
                            </div>
                        </div>
                        {dsFail && (
                            <CrNcState id="ds-list" kind={listUnread ? 'error' : 'warning'} onRetry={onDsRetry} data-cr-ds-list-failed={listUnread ? 'unread' : 'stale'}>
                                {crFill(t(listUnread ? 'crDsListFailed' : 'crDsListStale'), { why: dsFail.msg || '-' })}
                            </CrNcState>
                        )}
                        {esxi.hostsErr && (
                            <CrNcState id="ds-esxi-hosts" kind="error" onRetry={esxi.retryHosts} data-cr-ds-esxi-hosts-failed="">
                                {crFill(t('crDsEsxiHostsFailed'), { why: esxi.hostsErr })}
                            </CrNcState>
                        )}
                        {rows.length ? (
                            <CrStorageList rows={rows} selectedKey={selKey} onActivate={pickRow} onToggle={toggle}
                                onMenu={rowMenu} label={t('datastores')} />
                        ) : (
                            <div className="cr-ds-list cr-ds-none" data-cr-ds-list="">{query || problems ? t('crNoMatch') : listUnread ? t('crDsListNotRead') : t('noDatastores')}</div>
                        )}
                        {isAdmin && (
                            <div className="cr-ds-side-foot">
                                <CrButton variant="ghost" icon={<Icons.Plus />} onClick={esxi.connect} data-cr-ds-action="connect-esxi">
                                    {t('connectEsxi')}
                                </CrButton>
                            </div>
                        )}
                    </section>
                    <section className="cr-ds-main" aria-label={t('content')} ref={mainRef}>
                        {esxi.selected ? (
                            <CrEsxiVms host={(esxi.hosts || []).find(h => h.id === esxi.selected)} vms={esxi.vms} loading={esxi.loading}
                                error={esxi.vmsErr} onRetry={() => esxi.pick(esxi.selected)}
                                isAdmin={isAdmin} onClose={esxi.close} onDisconnect={esxi.disconnect} />
                        ) : !selected ? (
                            <div className="cr-ds-empty" data-cr-ds-empty="">
                                <Icons.Database aria-hidden="true" />
                                <span>{t('clickStorageToView')}</span>
                            </div>
                        ) : (
                            <>
                                <CrStorageHead sel={selected} def={def} st={st} datastores={data}
                                    count={fresh && !error ? (Array.isArray(content) ? content.length : 0) : null}
                                    loading={loading} actions={actions} run={run} onPick={onPick}
                                    onRefresh={() => onPick(selected.name, selected.node)} />
                                <CrStorageContent key={storeKey} storeKey={storeKey} rows={shownContent} loading={loading || !fresh}
                                    error={fresh ? error : null} mayDelete={mayDelete} guests={guests} onOpenGuest={onOpenGuest}
                                    actions={actions} run={run} narrow={narrow} />
                            </>
                        )}
                    </section>
                    {menu && (
                        <ContextMenu items={menu.items} position={menu.position} onClose={() => {
                            const back = menu.back;
                            setMenu(null);
                            if (back && back.isConnected && back.focus) back.focus({ preventScroll: true });
                        }} />
                    )}
                </div>
            );
        }

        // --- the datastore view of the sidebar --------------------------------------------

        // the same rows as classic (shared first, then per node without the shared names), each
        // with the meter, a state dot and the warning; Enter and click open it as before. fail: the
        // last read of the list failed ({ msg }), said above the rows of an earlier read if any
        function CrDsTree({ shared, local, skip, picked, clusterId, onOpen, fail, onRetry }) {
            const { t } = useTranslation();
            const walk = (e) => {
                if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
                const tree = e.currentTarget.closest('.cr-ds-tree');
                const list = tree ? Array.from(tree.querySelectorAll('.cr-ds-node')) : [];
                const next = list[list.indexOf(e.currentTarget) + (e.key === 'ArrowDown' ? 1 : -1)];
                if (next) { e.preventDefault(); next.focus(); }
            };
            const row = (s, node) => {
                const on = !!picked && picked.name === s.storage && picked.node === (node || null) && picked.clusterId === clusterId;
                return <CrDsRow key={`ds-${clusterId}-${s.storage}-${node || 's'}`} s={s} node={node} selected={on}
                    onOpen={() => onOpen(s, node)} onWalk={walk} />;
            };
            return (
                <div className="ml-5 corp-inline-tree cr-ds-tree" data-cr-ds-tree={clusterId}>
                    {fail && (
                        <div className="py-1 text-[12px] cr-tone-text cr-tone-error" role="alert" title={fail.msg || undefined}
                            data-cr-ds-tree-failed={shared.length || local.length ? 'stale' : 'unread'}>
                            {t(shared.length || local.length ? 'crDsTreeStale' : 'crDsTreeFailed')}{' '}
                            {onRetry && <button type="button" className="cr-link" onClick={onRetry} data-cr-ds-tree-retry="">{t('retry')}</button>}
                        </div>
                    )}
                    {shared.length > 0 && (
                        <>
                            <div className="cr-ds-tree-head"><Icons.Globe className="w-3 h-3 flex-shrink-0" /><span>{t('shared')}</span></div>
                            <div className="ml-2">{shared.map(s => row(s, null))}</div>
                        </>
                    )}
                    {local.map(([node, stores]) => {
                        const list = stores.filter(s => !skip.has(s.storage)).sort((a, b) => (a.storage || '').localeCompare(b.storage || ''));
                        if (!list.length) return null;
                        const off = list.every(s => s.node_offline);
                        return (
                            <React.Fragment key={`dsn-${clusterId}-${node}`}>
                                <div className={`cr-ds-tree-head${off ? ' cr-ds-tree-off' : ''}`}>
                                    <Icons.Server className="w-3 h-3 flex-shrink-0" /><span>{node}</span>
                                    {off && <span className="cr-ds-group-flag">{t('offline')}</span>}
                                </div>
                                <div className="ml-2">{list.map(s => row(s, node))}</div>
                            </React.Fragment>
                        );
                    })}
                </div>
            );
        }

        function CrDsRow({ s, node, selected, onOpen, onWalk }) {
            const { t } = useTranslation();
            const st = crStorageState(s);
            const tip = crStoreTitle(s, st, t, node);
            const dot = st.offline || st.inactive ? 'error' : st.disabled ? '' : st.partial ? 'warning' : st.active ? 'success' : '';
            return (
                <div className={`corp-tree-child cr-ds-node${selected ? ' cr-ds-node-sel' : ''}${st.unavailable ? ' cr-ds-node-off' : ''}`}
                    tabIndex={0} title={tip} aria-label={tip} aria-current={selected ? 'true' : undefined}
                    data-cr-ds-node={`${s.storage}@${node || ''}`}
                    onClick={onOpen} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); onOpen(); } else onWalk(e); }}>
                    <span className={`cr-dot${dot ? ` cr-dot-${dot}` : ''}`} aria-hidden="true" />
                    <span className="cr-ds-node-name">{s.storage}</span>
                    {st.offline ? <span className="cr-ds-group-flag">{t('offline')}</span>
                        : st.disabled ? <span className="cr-ds-node-flag">{t('crDsDisabled')}</span>
                        : st.inactive ? <span className="cr-ds-group-flag">{t('crDsInactive')}</span> : null}
                    <CrDsWarn st={st} />
                    <CrDsFree st={st} short />
                    {st.pct != null && <span className="cr-ds-mini"><CrMeter value={st.pct} tone={st.tone} /></span>}
                </div>
            );
        }
