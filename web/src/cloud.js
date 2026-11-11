        // ═══════════════════════════════════════════════
        // PegaProx — Cloud console skin (Preview)
        // Modern resource-first console: collapsible grouped nav, KPI dashboard,
        // data tables w/ bulk + per-row actions, full detail views with tabs.
        // self-contained: only React + global Icons + props passed from dashboard. -- LW
        // ═══════════════════════════════════════════════

        const CLOUD_PAGE_SIZE = 25;

        // small local formatters so we don't drag in anything global -- LW
        function cloudFmtBytes(b) {
            const n = Number(b);
            if (!n || n < 0 || !isFinite(n)) return '0 B';
            const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
            let i = 0, v = n;
            while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
            return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
        }

        function cloudBytesToGiB(b) {
            const n = Number(b);
            if (!n || n < 0 || !isFinite(n)) return 0;
            return n / (1024 * 1024 * 1024);
        }

        function cloudFmtUptime(sec) {
            const s = Number(sec);
            if (!s || s <= 0 || !isFinite(s)) return '—';
            const d = Math.floor(s / 86400);
            const h = Math.floor((s % 86400) / 3600);
            const m = Math.floor((s % 3600) / 60);
            const parts = [];
            if (d) parts.push(d + 'd');
            if (h) parts.push(h + 'h');
            if (m || (!d && !h)) parts.push(m + 'm');
            return parts.join(' ');
        }

        // clamp a 0..1 fraction to a 0..100 percent int
        function cloudPct(frac) {
            const f = Number(frac);
            if (!f || f < 0 || !isFinite(f)) return 0;
            return Math.min(100, Math.round(f * 100));
        }

        // a VM/CT row exposes either a server-computed *_percent (preferred) or raw values
        function cloudCpuPct(r) {
            if (r && r.cpu_percent != null && isFinite(r.cpu_percent)) return Math.min(100, Math.round(r.cpu_percent));
            return cloudPct(r && r.cpu);  // cpu is a 0..1 fraction
        }
        function cloudMemPct(r) {
            if (r && r.mem_percent != null && isFinite(r.mem_percent)) return Math.min(100, Math.round(r.mem_percent));
            const mx = Number(r && r.maxmem) || 0;
            return mx > 0 ? Math.round((Number(r.mem) || 0) / mx * 100) : 0;
        }

        function cloudRelTime(epoch) {
            const t = Number(epoch);
            if (!t || !isFinite(t)) return '—';
            const now = Date.now() / 1000;
            const d = Math.max(0, now - t);
            if (d < 60) return Math.floor(d) + 's ago';
            if (d < 3600) return Math.floor(d / 60) + 'm ago';
            if (d < 86400) return Math.floor(d / 3600) + 'h ago';
            return Math.floor(d / 86400) + 'd ago';
        }

        function cloudClusterTypeLabel(ct) {
            switch (ct) {
                case 'esxi': return 'ESXi';
                case 'xcpng': return 'XCP-ng';
                default: return 'Proxmox';
            }
        }
        function cloudTagList(tags) {
            if (Array.isArray(tags)) return tags.filter(Boolean);
            if (typeof tags === 'string' && tags) return tags.split(/[;,\s]+/).filter(Boolean);
            return [];
        }

        // status -> token colour (used by mini-meters / fallbacks)
        function cloudStatusColor(status) {
            switch (status) {
                case 'running': return 'var(--cloud-success)';
                case 'stopped': return 'var(--cloud-text-muted)';
                case 'paused':
                case 'suspended': return 'var(--cloud-warning)';
                default: return 'var(--cloud-info)';
            }
        }

        // status -> filled-chip palette (text + tinted bg + border). rgba literals so the
        // tint reads right on both the dark and light cloud themes. -- MK
        function cloudStatusMeta(status) {
            switch (status) {
                case 'running':   return { label: 'Running',   color: '#1bbf8a', bg: 'rgba(45,212,167,0.16)',  border: 'rgba(45,212,167,0.42)' };
                case 'stopped':   return { label: 'Stopped',   color: '#8aa4b8', bg: 'rgba(138,164,184,0.14)', border: 'rgba(138,164,184,0.30)' };
                case 'paused':    return { label: 'Paused',    color: '#e0a82e', bg: 'rgba(245,185,69,0.16)',  border: 'rgba(245,185,69,0.42)' };
                case 'suspended': return { label: 'Suspended', color: '#e0a82e', bg: 'rgba(245,185,69,0.16)',  border: 'rgba(245,185,69,0.42)' };
                default: {
                    const s = (status || 'unknown');
                    return { label: s.charAt(0).toUpperCase() + s.slice(1), color: '#2f9fe0', bg: 'rgba(56,189,248,0.14)', border: 'rgba(56,189,248,0.36)' };
                }
            }
        }

        // ── primitives ─────────────────────────────────────────────
        function CloudPill({ color, bg, border, dot, children }) {
            return (
                <span className="cloud-chip cloud-chip-status" style={{ color, background: bg, borderColor: border }}>
                    {dot && <span className="cloud-status-dot" style={{ background: color }} />}
                    {children}
                </span>
            );
        }

        function CloudStatusChip({ status }) {
            const m = cloudStatusMeta(status);
            return <CloudPill color={m.color} bg={m.bg} border={m.border} dot>{m.label}</CloudPill>;
        }

        function CloudConnChip({ connected, t }) {
            return connected
                ? <CloudPill color="#1bbf8a" bg="rgba(45,212,167,0.16)" border="rgba(45,212,167,0.42)" dot>{(t && t('cloud.online')) || 'Online'}</CloudPill>
                : <CloudPill color="#e0686c" bg="rgba(248,113,113,0.14)" border="rgba(248,113,113,0.36)" dot>{(t && t('cloud.offline')) || 'Offline'}</CloudPill>;
        }

        // circular conic gauge
        function CloudGauge({ pct, label, color, sub }) {
            const safePct = Math.min(100, Math.max(0, Number(pct) || 0));
            const c = color || 'var(--cloud-accent)';
            return (
                <div className="cloud-gauge-wrap">
                    <div className="cloud-gauge" style={{ background: `conic-gradient(${c} ${safePct * 3.6}deg, var(--cloud-gauge-track) 0)` }}>
                        <div className="cloud-gauge-inner">
                            <span className="cloud-gauge-num">{Math.round(safePct)}%</span>
                        </div>
                    </div>
                    <div className="cloud-gauge-label">{label}</div>
                    {sub && <div className="cloud-gauge-sub">{sub}</div>}
                </div>
            );
        }

        // inline meter used in table cells
        function CloudMiniMeter({ pct, color }) {
            const p = Math.min(100, Math.max(0, Number(pct) || 0));
            return (
                <div className="cloud-cell-meter">
                    <div className="cloud-meter"><div style={{ width: p + '%', background: color || 'var(--cloud-accent)' }} /></div>
                    <span className="cloud-cell-meter-num">{Math.round(p)}%</span>
                </div>
            );
        }

        // labelled horizontal usage bar (storage / node capacity)
        function CloudUsageBar({ pct, color, leftLabel, rightLabel }) {
            const p = Math.min(100, Math.max(0, Number(pct) || 0));
            const c = color || (p >= 90 ? 'var(--cloud-error)' : p >= 75 ? 'var(--cloud-warning)' : 'var(--cloud-accent)');
            return (
                <div className="cloud-usage">
                    <div className="cloud-usage-head">
                        <span>{leftLabel}</span>
                        <span className="cloud-usage-right">{rightLabel}</span>
                    </div>
                    <div className="cloud-meter cloud-meter-lg"><div style={{ width: p + '%', background: c }} /></div>
                </div>
            );
        }

        // colourful KPI tile for the dashboard
        function CloudKpiCard({ icon, value, label, accent, sub, onClick }) {
            const Ico = Icons[icon] || Icons.Box;
            return (
                <div
                    className={'cloud-kpi' + (onClick ? ' cloud-kpi-click' : '')}
                    style={{ '--kpi-accent': accent || 'var(--cloud-accent)' }}
                    onClick={onClick || undefined}
                    role={onClick ? 'button' : undefined}
                >
                    <div className="cloud-kpi-icon"><Ico /></div>
                    <div className="cloud-kpi-body">
                        <div className="cloud-kpi-value">{value}</div>
                        <div className="cloud-kpi-label">{label}</div>
                        {sub != null && <div className="cloud-kpi-sub">{sub}</div>}
                    </div>
                </div>
            );
        }

        // small icon button
        function CloudIconBtn({ icon, title, onClick, danger }) {
            const Ico = Icons[icon] || Icons.Box;
            return (
                <button type="button" className={'cloud-icon-btn' + (danger ? ' cloud-icon-btn-danger' : '')} title={title} onClick={onClick}>
                    <Ico />
                </button>
            );
        }

        // kebab dropdown — fixed-position so it never gets clipped by the table scroll. -- NS
        function CloudActionMenu({ items, label, triggerLabel, triggerNode }) {
            const [open, setOpen] = React.useState(false);
            const [pos, setPos] = React.useState({ top: 0, left: 0 });
            const btnRef = React.useRef(null);
            const menuRef = React.useRef(null);
            React.useEffect(() => {
                if (!open) return;
                const onDoc = (e) => {
                    if (menuRef.current && !menuRef.current.contains(e.target) &&
                        btnRef.current && !btnRef.current.contains(e.target)) setOpen(false);
                };
                // a short window scrolls the menu itself, which must not close it
                const onScroll = (e) => {
                    if (menuRef.current && e.target instanceof Node && menuRef.current.contains(e.target)) return;
                    setOpen(false);
                };
                document.addEventListener('mousedown', onDoc);
                window.addEventListener('scroll', onScroll, true);
                window.addEventListener('resize', onScroll);
                return () => {
                    document.removeEventListener('mousedown', onDoc);
                    window.removeEventListener('scroll', onScroll, true);
                    window.removeEventListener('resize', onScroll);
                };
            }, [open]);
            // the items are as tall as half a screen: the lower rows of a list open it upwards as far as needed
            React.useLayoutEffect(() => {
                if (!open || !menuRef.current) return;
                const room = window.innerHeight - menuRef.current.offsetHeight - 8;
                setPos(p => (p.top > room ? { ...p, top: Math.max(8, room) } : p));
            }, [open]);
            const toggle = (e) => {
                e.stopPropagation();
                if (!open && btnRef.current) {
                    const r = btnRef.current.getBoundingClientRect();
                    setPos({ top: r.bottom + 4, left: Math.max(8, r.right - 210) });
                }
                setOpen(o => !o);
            };
            // the menu is the last thing on the page now, Tab would jump past it from the button
            const onTriggerKey = (e) => {
                if (!open || e.key !== 'Tab' || e.shiftKey || !menuRef.current) return;
                const first = menuRef.current.querySelector('button:not(:disabled)');
                if (first) { e.preventDefault(); first.focus(); }
            };
            const onMenuKey = (e) => {
                if (e.key !== 'Tab') return;
                const btns = menuRef.current.querySelectorAll('button:not(:disabled)');
                if (e.target !== (e.shiftKey ? btns[0] : btns[btns.length - 1])) return;
                e.preventDefault();
                if (btnRef.current) btnRef.current.focus();
                if (!e.shiftKey) setOpen(false);
            };
            const visible = (items || []).filter(Boolean);
            return (
                <>
                    {triggerNode ? (
                        <button type="button" ref={btnRef} className="cloud-menu-trigger-plain" onClick={toggle} onKeyDown={onTriggerKey} title={label || 'Actions'}>
                            {triggerNode}
                        </button>
                    ) : triggerLabel ? (
                        <button type="button" ref={btnRef} className="cloud-btn" onClick={toggle} onKeyDown={onTriggerKey} title={label || 'Actions'}>
                            {triggerLabel} <Icons.ChevronDown />
                        </button>
                    ) : (
                        <button type="button" ref={btnRef} className="cloud-icon-btn" onClick={toggle} onKeyDown={onTriggerKey} title={label || 'Actions'}>
                            <Icons.MoreVertical />
                        </button>
                    )}
                    {/* JB Nov 2026 - on the body: a hovered .cloud-card has a transform, which turns the card into
                        what fixed means, and the overflow of the table card then cut this menu off */}
                    {open && ReactDOM.createPortal(
                        <div ref={menuRef} className="cloud-menu cloud-menu-fixed" style={{ top: pos.top, left: pos.left, maxHeight: 'calc(100vh - 16px)', overflowY: 'auto' }} onClick={(e) => e.stopPropagation()} onKeyDown={onMenuKey}>
                            {visible.map((it, i) => it.divider ? <div className="cloud-menu-sep" key={'s' + i} /> : (
                                <button
                                    type="button"
                                    key={i}
                                    className={'cloud-menu-item' + (it.danger ? ' cloud-menu-item-danger' : '')}
                                    disabled={it.disabled}
                                    onClick={() => { setOpen(false); it.onClick && it.onClick(); }}
                                >
                                    {it.icon && <span className="cloud-menu-icon">{React.createElement(Icons[it.icon] || Icons.Box)}</span>}
                                    <span>{it.label}</span>
                                </button>
                            ))}
                        </div>,
                        document.body
                    )}
                </>
            );
        }

        // search input used in list toolbars
        function CloudSearch({ value, onChange, placeholder }) {
            return (
                <div className="cloud-search">
                    <span className="cloud-search-icon"><Icons.Search /></span>
                    <input type="text" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder || 'Search…'} />
                    {value && <button type="button" className="cloud-search-clear" onClick={() => onChange('')} aria-label="Clear"><Icons.X /></button>}
                </div>
            );
        }

        // compact pager
        function CloudPager({ page, pageSize, total, onPage }) {
            const pages = Math.max(1, Math.ceil(total / pageSize));
            if (total <= pageSize) return null;
            const from = total === 0 ? 0 : page * pageSize + 1;
            const to = Math.min(total, (page + 1) * pageSize);
            return (
                <div className="cloud-pager">
                    <span className="cloud-pager-text">{from}–{to} of {total}</span>
                    <button type="button" className="cloud-icon-btn" disabled={page <= 0} onClick={() => onPage(page - 1)} title="Previous"><Icons.ChevronLeft /></button>
                    <button type="button" className="cloud-icon-btn" disabled={page >= pages - 1} onClick={() => onPage(page + 1)} title="Next"><Icons.ChevronRight /></button>
                </div>
            );
        }

        function CloudEmpty({ icon, title, text, action }) {
            const Ico = Icons[icon] || Icons.Box;
            return (
                <div className="cloud-empty-state">
                    <div className="cloud-empty-icon"><Ico /></div>
                    <div className="cloud-empty-title">{title}</div>
                    {text && <div className="cloud-empty-text">{text}</div>}
                    {action && <div className="cloud-empty-action">{action}</div>}
                </div>
            );
        }

        function CloudPageHeader({ title, sub, children }) {
            return (
                <div className="cloud-page-header">
                    <div>
                        <h1 className="cloud-page-title">{title}</h1>
                        {sub != null && <div className="cloud-page-sub">{sub}</div>}
                    </div>
                    {children && <div className="cloud-page-header-actions">{children}</div>}
                </div>
            );
        }

        function CloudSectionTitle({ children, right }) {
            return (
                <div className="cloud-section-row">
                    <div className="cloud-section-title">{children}</div>
                    {right}
                </div>
            );
        }

        // simple horizontal bar chart (top consumers)
        function CloudBarChart({ rows, color, t }) {
            const max = Math.max(1, ...rows.map(r => Number(r.value) || 0));
            return (
                <div className="cloud-barchart">
                    {rows.length === 0 && <div className="cloud-empty">{t('cloud.noData') || 'No data.'}</div>}
                    {rows.map((r, i) => (
                        <div className="cloud-bar-row" key={i}>
                            <span className="cloud-bar-label" title={r.label}>{r.label}</span>
                            <div className="cloud-bar-track"><div className="cloud-bar-fill" style={{ width: ((Number(r.value) || 0) / max * 100) + '%', background: color || 'var(--cloud-accent)' }} /></div>
                            <span className="cloud-bar-val">{r.display != null ? r.display : r.value}</span>
                        </div>
                    ))}
                </div>
            );
        }

        // ── build VM/CT action menu items (shared by list kebab + detail bar) ──
        function cloudVmActionItems(r, act, t) {
            const running = r.status === 'running';
            const paused = r.status === 'paused' || r.status === 'suspended';
            const isCt = r.type === 'lxc';
            // a standby hands over metrics and config only (#625), the rest is not offered
            const has = (k) => !act.has || act.has(k);
            const power = has('vmAction');
            const items = [
                power && (!running && !paused) && { label: t('start') || 'Start', icon: 'Play', onClick: () => act.vmAction(r, 'start') },
                power && paused && { label: t('resume') || 'Resume', icon: 'PlayCircle', onClick: () => act.vmAction(r, 'resume') },
                power && running && { label: t('shutdown') || 'Shutdown', icon: 'Power', onClick: () => act.vmAction(r, 'shutdown') },
                power && running && { label: t('reboot') || 'Reboot', icon: 'RotateCw', onClick: () => act.vmAction(r, 'reboot') },
                power && (running && !isCt) && { label: t('suspend') || 'Suspend', icon: 'Pause', onClick: () => act.vmAction(r, 'suspend') },
                power && running && { label: t('stop') || 'Stop', icon: 'Square', onClick: () => act.vmAction(r, 'stop') },
                has('forceStop') && running && { label: t('forceStop') || 'Force stop', icon: 'StopCircle', danger: true, onClick: () => act.forceStop(r) },
                { divider: true },
                has('openConsole') && { label: t('console') || 'Console', icon: 'Monitor', onClick: () => act.openConsole(r) },
                // a standby never runs a console; this opens the guest's console on the active (#625)
                act.consoleOnActive && { label: t('pgHaOpenOnActive'), icon: 'ExternalLink', onClick: () => act.consoleOnActive(r) },
                has('openSpice') && (running && !isCt) && { label: t('spiceConsole') || 'SPICE', icon: 'ExternalLink', onClick: () => act.openSpice(r) },
                has('openLxcShell') && isCt && { label: t('shell') || 'Shell', icon: 'Terminal', onClick: () => act.openLxcShell(r) },
                has('snapshot') && { label: t('snapshots') || 'Snapshot', icon: 'Camera', onClick: () => act.snapshot(r) },
                { label: t('metrics') || 'Metrics', icon: 'BarChart', onClick: () => act.openMetrics(r) },
                { divider: true },
                { label: t('edit') || 'Edit / Hardware', icon: 'Cog', onClick: () => act.openConfig(r) },
                has('migrate') && { label: t('migrate') || 'Migrate', icon: 'Send', onClick: () => act.migrate(r) },
                has('crossMigrate') && act.multiCluster && { label: t('cloud.crossMigrate') || 'Migrate to cluster…', icon: 'Send', onClick: () => act.crossMigrate(r) },
                has('clone') && { label: t('clone') || 'Clone', icon: 'Copy', onClick: () => act.clone(r) },
                { divider: true },
                has('del') && { label: t('delete') || 'Delete', icon: 'Trash2', danger: true, onClick: () => act.del(r) },
            ].filter(Boolean);
            // no divider at either end, or two in a row, once entries are gone
            const out = [];
            for (const it of items) {
                if (it.divider && (!out.length || out[out.length - 1].divider)) continue;
                out.push(it);
            }
            while (out.length && out[out.length - 1].divider) out.pop();
            return out;
        }

        // ── side nav (collapsible, grouped) ────────────────────────
        function CloudSideNav({ active, onSelect, isAdmin, canAutoInstall, canChanges, collapsed, onToggle }) {
            const { t } = useTranslation();
            const groups = [
                { label: t('cloudNavDashboard'), items: [{ id: 'overview', label: t('overview'), icon: 'Grid' }] },
                { label: t('cloudNavCompute'), items: [
                    { id: 'vms', label: t('virtualMachines'), icon: 'Server' },
                    { id: 'containers', label: t('containers'), icon: 'Box' },
                    // LW Oct 2026 - containers from OCI images
                    { id: 'apps', label: t('ociTabLabel'), icon: 'Container' },
                ] },
                { label: t('storage'), items: [
                    { id: 'datastores', label: t('datastores'), icon: 'Database' },
                    { id: 'swexplorer', label: t('cloud.swExplorer') || 'Storage Explorer', icon: 'FolderOpen' },
                    { id: 'swiso', label: t('cloud.swIso') || 'ISO & Templates', icon: 'Disc' },
                    { id: 'swsla', label: t('cloud.swSla') || 'Backup-SLA', icon: 'ShieldCheck' },
                    { id: 'storage', label: t('cloudNavStorageConfig'), icon: 'HardDrive' },
                    { id: 'pools', label: t('cloudNavResourcePools'), icon: 'Layers' },
                    { id: 'ceph', label: t('ceph'), icon: 'Database' },
                ] },
                { label: t('network'), items: [
                    { id: 'networks', label: t('cloudNavNetworks'), icon: 'Network' },
                    { id: 'sdn', label: t('sdn'), icon: 'Globe' },
                    { id: 'firewall', label: t('firewall'), icon: 'Lock' },
                    { id: 'topology', label: t('topologyView'), icon: 'Share2' },
                ] },
                { label: t('cloudNavDataProtection'), items: [
                    { id: 'backups', label: t('backups'), icon: 'Archive' },
                    { id: 'replication', label: t('replication'), icon: 'Copy' },
                    { id: 'pbs', label: t('backupServers'), icon: 'Server' },
                    { id: 'siterecovery', label: t('siteRecovery'), icon: 'LifeBuoy' },
                ] },
                { label: t('automation'), items: [
                    { id: 'schedules', label: t('schedules'), icon: 'Clock' },
                    { id: 'scripts', label: t('cloudNavScripts'), icon: 'Terminal' },
                    { id: 'snapshotpolicies', label: t('cloudNavSnapshotPolicies'), icon: 'Camera' },
                    // LW Nov 2026 (#1220) - the blueprints sit above the library there
                    { id: 'templates', label: t('bpNavTab'), icon: 'Copy' },
                    { id: 'alerts', label: t('alertChannels'), icon: 'Bell' },
                ] },
                { label: t('cloudNavInfrastructure'), items: [
                    { id: 'clusters', label: t('cloudNavClusters'), icon: 'Cloud' },
                    { id: 'nodes', label: t('hosts'), icon: 'Cpu' },
                    ...(canAutoInstall ? [{ id: 'autoinstall', label: t('cloudNavAutoInstall'), icon: 'Disc' }] : []),
                    // LW Oct 2026 - directory, PCI and USB mappings of the selected cluster
                    { id: 'mappings', label: t('rmTitle'), icon: 'Link' },
                    { id: 'ha', label: t('cloudNavHa'), icon: 'Shield' },
                    { id: 'updates', label: t('updateManager'), icon: 'Download' },
                ] },
                { label: t('cloudNavMonitoring'), items: [{ id: 'monitoring', label: t('cloudNavMonitoring'), icon: 'Activity' }] },
                { label: t('reports'), items: [
                    { id: 'insights', label: t('insights'), icon: 'Zap' },
                    { id: 'costs', label: t('cloudNavCosts'), icon: 'DollarSign' },
                    { id: 'power', label: t('powerTitle'), icon: 'Zap' },
                    // LW Oct 2026 - what-if simulator of the selected cluster
                    { id: 'whatif', label: t('whatifTitle'), icon: 'Scale' },
                    { id: 'apihealth', label: t('apiHealth'), icon: 'Activity' },
                    { id: 'cve', label: t('cveScanner'), icon: 'Shield' },
                ] },
                { label: t('cloudNavActivity'), items: [
                    { id: 'tasks', label: t('tasks'), icon: 'ClipboardList' },
                    // LW Oct 2026 - the flight recorder of the selected cluster
                    { id: 'timeline', label: t('tlTab'), icon: 'Clock' },
                    // NS Oct 2026 - change plans of the selected cluster, for whoever may see them
                    ...(canChanges ? [{ id: 'changes', label: t('chgTab'), icon: 'ClipboardList' }] : []),
                ] },
            ];
            if (isAdmin) {
                groups.push({ label: t('cloudNavGovernance'), items: [
                    { id: 'compliance', label: t('compliance'), icon: 'Shield' },
                    { id: 'drift', label: t('cloudNavConfigDrift'), icon: 'Activity' },
                    { id: 'siem', label: 'SIEM', icon: 'AlertTriangle' },
                ] });
                groups.push({ label: t('cloudNavSystem'), items: [
                    { id: 'plugins', label: t('plugins'), icon: 'Box' },
                    { id: 'users', label: t('users'), icon: 'Users' },
                    { id: 'settings', label: t('settings'), icon: 'Settings' },
                ] });
            }
            return (
                <nav className={'cloud-nav' + (collapsed ? ' cloud-nav-collapsed' : '')}>
                    <div className="cloud-nav-brand">
                        {/* NS 2026-07: real PegaProx pegasus logo (was a generic Cloud icon).
                            Cloud-theme-aware: white pegasus on the dark shell, dark pegasus on
                            the light theme. Falls back to the Cloud icon if the asset 404s. */}
                        <span className="cloud-nav-brand-mark">
                            <img
                                src={(typeof document !== 'undefined' && document.body && document.body.dataset.cloudTheme === 'light')
                                    ? '/images/pegaprox-logo-light.png'
                                    : '/images/pegaprox-logo-dark.png'}
                                alt="PegaProx"
                                onError={(e) => { e.target.style.display = 'none'; const s = e.target.nextSibling; if (s) s.style.display = 'inline-flex'; }}
                            />
                            <span className="cloud-nav-brand-fallback" style={{ display: 'none' }}><Icons.Cloud /></span>
                        </span>
                        {!collapsed && <span className="cloud-nav-brand-text">PegaProx</span>}
                        {!collapsed && <span className="cloud-chip cloud-chip-preview">PREVIEW</span>}
                    </div>
                    <div className="cloud-nav-scroll">
                        {groups.map(group => (
                            <div className="cloud-nav-group" key={group.label}>
                                {!collapsed && <div className="cloud-nav-group-label">{group.label}</div>}
                                {group.items.map(item => {
                                    const Ico = Icons[item.icon] || Icons.Box;
                                    const isActive = active === item.id;
                                    return (
                                        <button
                                            type="button"
                                            key={item.id}
                                            className={'cloud-nav-item' + (isActive ? ' cloud-nav-item-active' : '')}
                                            onClick={() => onSelect(item.id)}
                                            title={collapsed ? item.label : undefined}
                                        >
                                            <span className="cloud-nav-item-icon"><Ico /></span>
                                            {!collapsed && <span className="cloud-nav-item-label">{item.label}</span>}
                                        </button>
                                    );
                                })}
                            </div>
                        ))}
                    </div>
                    <button type="button" className="cloud-nav-collapse" onClick={onToggle} title={collapsed ? 'Expand' : 'Collapse'}>
                        {collapsed ? <Icons.ChevronRight /> : <Icons.ChevronLeft />}
                    </button>
                    {/* the nav is the one piece of chrome on screen in every cloud view */}
                    {!collapsed && <LegalNotice style={{padding: '8px 6px'}} />}
                </nav>
            );
        }

        // ── top bar (masthead) ─────────────────────────────────────
        function CloudTopbar({ crumbs, clusters, selectedCluster, setSelectedCluster, theme, onToggleTheme, onRefresh, onExitCloud, onOpenSettings, onOpenProfile, onOpenApiReference, onLogout, isAdmin, currentUser, t }) {
            const safe = Array.isArray(clusters) ? clusters : [];
            const selId = selectedCluster && (selectedCluster.id != null ? selectedCluster.id : selectedCluster.name);
            const onChange = (e) => {
                const val = e.target.value;
                const match = safe.find(c => String(c && (c.id != null ? c.id : c.name)) === String(val));
                if (match && typeof setSelectedCluster === 'function') setSelectedCluster(match);
            };
            const uname = (currentUser && (currentUser.username || currentUser.name)) || 'User';
            const initial = (uname[0] || 'U').toUpperCase();
            // the switcher draws nothing while the language is pinned, and an empty box would still take a gap
            const { languageLocked } = useTranslation();
            const userMenu = [
                { label: t('cloud.profile') || 'Profile & preferences', icon: 'User', onClick: () => onOpenProfile && onOpenProfile() },
                isAdmin && { label: t('cloud.settings') || 'Settings', icon: 'Settings', onClick: () => onOpenSettings && onOpenSettings() },
                (typeof onOpenApiReference === 'function') && { label: t('apiRefTitle'), icon: 'Book', onClick: onOpenApiReference },
                { divider: true },
                (typeof onExitCloud === 'function') && { label: t('cloud.exit') || 'Exit Cloud (Modern view)', icon: 'Grid', onClick: onExitCloud },
                (typeof onLogout === 'function') && { label: t('logout') || 'Sign out', icon: 'LogOut', danger: true, onClick: onLogout },
            ].filter(Boolean);

            return (
                <div className="cloud-topbar">
                    <div className="cloud-breadcrumb">
                        {(crumbs || []).map((c, i) => (
                            <React.Fragment key={i}>
                                {i > 0 && <span className="cloud-breadcrumb-sep"><Icons.ChevronRight /></span>}
                                <span className={i === crumbs.length - 1 ? 'cloud-breadcrumb-leaf' : 'cloud-breadcrumb-root'}>{c}</span>
                            </React.Fragment>
                        ))}
                    </div>
                    <div className="cloud-topbar-actions">
                        {safe.length > 0 && (
                            <div className="cloud-cluster-pick">
                                <Icons.Cloud />
                                <select className="cloud-cluster-select" value={selId != null ? String(selId) : ''} onChange={onChange}>
                                    {safe.map(c => {
                                        const cid = c && (c.id != null ? c.id : c.name);
                                        return <option key={String(cid)} value={String(cid)}>{(c && (c.display_name || c.name)) || 'cluster'}</option>;
                                    })}
                                </select>
                            </div>
                        )}
                        {!languageLocked && <div className="cloud-lang"><LanguageSwitcher /></div>}
                        <CloudIconBtn icon={theme === 'light' ? 'Moon' : 'Sun'} title={theme === 'light' ? 'Dark theme' : 'Light theme'} onClick={onToggleTheme} />
                        <CloudIconBtn icon="RefreshCw" title={t('cloud.refresh') || 'Refresh'} onClick={onRefresh} />
                        {isAdmin && <CloudIconBtn icon="Settings" title={t('cloud.settings') || 'Settings'} onClick={() => onOpenSettings && onOpenSettings()} />}
                        <CloudActionMenu
                            items={userMenu}
                            label={uname}
                            triggerNode={
                                <span className="cloud-user-btn">
                                    <span className="cloud-user-avatar">{initial}</span>
                                    <span className="cloud-user-name">{uname}</span>
                                    <Icons.ChevronDown />
                                </span>
                            }
                        />
                    </div>
                </div>
            );
        }

        // ── overview / dashboard ───────────────────────────────────
        function cloudThresholdColor(pct) {
            const p = Number(pct) || 0;
            return p >= 90 ? 'var(--cloud-error)' : p >= 75 ? 'var(--cloud-warning)' : 'var(--cloud-accent)';
        }

        function cloudWidgetTitle(id, t) {
            const map = {
                kpi: [t('cloud.wKpi'), 'Infrastructure'],
                utilization: [t('cloud.utilization'), 'Cluster utilization'],
                consumers: [t('cloud.topConsumers'), 'Top resource consumers'],
                activity: [t('cloud.recentTasks'), 'Recent activity'],
                clusterhealth: [t('cloud.wClusterHealth'), 'Cluster health'],
                gueststatus: [t('cloud.wGuestStatus'), 'Guest status'],
                datastores: [t('cloud.wDatastores'), 'Datastore usage'],
            };
            const e = map[id] || [null, id];
            return e[0] || e[1];
        }

        // stacked status bar + legend (guest counts straight from the resource list)

        function CloudMeterRow({ label, sub, val, pct }) {
            const p = Math.min(100, Math.max(0, Number(pct) || 0));
            const c = cloudThresholdColor(p);
            return (
                <div className="cloud-meter-row">
                    <div className="cloud-meter-row-top">
                        <span className="cloud-meter-row-label">
                            {label}
                            {sub && <span className="cloud-meter-row-sub">{sub}</span>}
                        </span>
                        <span className="cloud-meter-row-val">{val ? <strong>{val}</strong> : null}{val ? ' · ' : ''}{Math.round(p)}%</span>
                    </div>
                    <div className="cloud-meter"><div style={{ width: p + '%', background: c }} /></div>
                </div>
            );
        }

        // top resource consumers with a RAM / CPU / Disk metric switch - all values
        // straight from the cluster resource list (mem, cpu, disk), nothing invented.
        // `metric` seeds the switch (widget config); internal state keeps the last click.

        function CloudWidgetCard({ title, icon, actions, custom, children }) {
            const Ico = icon ? (Icons[icon] || Icons.Box) : null;
            return (
                <div className={'cloud-card cloud-widget' + (custom && custom.dragging ? ' cloud-widget-dragging' : '') + (custom && custom.dropTarget ? ' cloud-widget-drop-target' : '')}
                    ref={custom && custom.cardRef} data-widget={custom && custom.id}>
                    <div
                        className="cloud-widget-head"
                        draggable={!!(custom && custom.onDragStart)}
                        onDragStart={custom && custom.onDragStart}
                        onDragEnd={custom && custom.onDragEnd}
                        onDragOver={custom && custom.onDragOver}
                        onDrop={custom && custom.onDrop}
                        onDragLeave={custom && custom.onDragLeave}
                    >
                        <div className="cloud-widget-title">
                            {Ico && <span className="cloud-widget-title-icon"><Ico /></span>}
                            <span>{title}</span>
                            {custom && custom.badge != null && <span className="cloud-chip cloud-chip-soft">{custom.badge}</span>}
                        </div>
                        <div className="cloud-widget-actions">
                            {actions}
                            {custom && custom.onCycleSize && (
                                <CloudIconBtn icon={custom.size === 'sm' ? 'Minimize' : 'Maximize'} title={custom.sizeTitle} onClick={custom.onCycleSize} />
                            )}
                            {custom && custom.onRemove && (
                                <CloudIconBtn icon="X" danger title={custom.removeTitle} onClick={custom.onRemove} />
                            )}
                        </div>
                    </div>
                    <div className="cloud-widget-body">{children}</div>
                </div>
            );
        }

        // simple horizontal bar chart (top consumers)

        function CloudTopConsumers({ rows, t, metric }) {
            const [sel, setSel] = React.useState(metric || 'mem');
            const m = sel; const setMetric = setSel;
            const guests = (Array.isArray(rows) ? rows : []).filter(r => r && r.status === 'running');
            const pick = (r) => {
                if (metric === 'cpu') return { v: cloudCpuPct(r), display: cloudCpuPct(r) + '%', pct: cloudCpuPct(r) };
                if (metric === 'disk') return { v: Number(r.disk) || 0, display: cloudFmtBytes(Number(r.disk) || 0), pct: 0 };
                return { v: Number(r.mem) || 0, display: cloudFmtBytes(Number(r.mem) || 0), pct: 0 };
            };
            const scored = guests.map(r => ({ r, ...pick(r) })).sort((a, b) => b.v - a.v).slice(0, 6);
            const max = Math.max(1, ...scored.map(s => s.v));
            const segs = [
                { id: 'mem', label: t('cloud.metricRam') || 'RAM' },
                { id: 'cpu', label: t('cloud.metricCpu') || 'CPU' },
                { id: 'disk', label: t('cloud.metricDisk') || 'Disk' },
            ];
            return (
                <div>
                    <div className="cloud-segment" style={{ margin: '2px 0 4px' }}>
                        {segs.map(s => (
                            <button key={s.id} type="button" className={'cloud-segment-btn' + (metric === s.id ? ' is-active' : '')} onClick={() => setMetric(s.id)}>{s.label}</button>
                        ))}
                    </div>
                    <div className="cloud-topcons">
                        {scored.length === 0 ? (
                            <div className="cloud-topcons-note">{t('cloud.noRunning') || 'No running guests.'}</div>
                        ) : metric === 'disk' && scored.every(s => !s.v) ? (
                            <div className="cloud-topcons-note">{t('cloud.noDiskData') || 'No disk usage reported - only containers and guests with the QEMU guest agent report it.'}</div>
                        ) : scored.map(s => (
                            <div className="cloud-topcons-row" key={(s.r.vmid != null ? s.r.vmid : '') + '-' + (s.r.name || '')}>
                                <span className="cloud-topcons-name" title={s.r.name || ('guest-' + s.r.vmid)}>
                                    {s.r.name || ('guest-' + s.r.vmid)}
                                    <span>{s.r.type === 'lxc' ? 'CT' : 'VM'}</span>
                                </span>
                                <div className="cloud-topcons-track"><div style={{ width: (s.v / max * 100) + '%', background: metric === 'cpu' ? cloudThresholdColor(s.v) : 'var(--cloud-accent)' }} /></div>
                                <span className="cloud-topcons-val">{s.display}</span>
                            </div>
                        ))}
                    </div>
                </div>
            );
        }

        // activity timeline: status icon + type + target + node + relative time.
        // status classes follow the task rows: running → info, OK → success, else error

        function CloudActivityList({ tasks, t, max }) {
            const limit = Math.max(1, Math.min(20, Number(max) || 8));
            const list = (Array.isArray(tasks) ? tasks : []).slice(0, limit);
            const meta = (s) => s === 'running' ? { cls: 'is-run', icon: 'Loader', label: t('cloud.taskRunning') || 'RUNNING' }
                : s === 'OK' ? { cls: 'is-ok', icon: 'Check', label: t('cloud.taskOk') || 'OK' }
                : { cls: 'is-err', icon: 'X', label: t('cloud.taskErr') || 'FAILED' };
            return (
                <div className="cloud-act">
                    {list.length === 0 && <div className="cloud-empty">{t('cloud.noRecentTasks') || 'No recent tasks.'}</div>}
                    {list.map((tk, i) => {
                        const m = meta(tk && tk.status);
                        const Ico = Icons[m.icon] || Icons.Clock;
                        return (
                            <div className="cloud-act-row" key={tk && (tk.upid || i)}>
                                <span className={'cloud-act-icon ' + m.cls} title={m.label}><Ico /></span>
                                <span className="cloud-act-type">{(tk && tk.type) || 'task'}</span>
                                {(tk && tk.id) && <span className="cloud-act-target" title={tk.id}>{tk.id}</span>}
                                {(tk && tk.node) && <span className="cloud-act-node">{tk.node}</span>}
                                <span className="cloud-act-time">{cloudRelTime(tk && tk.starttime)}</span>
                            </div>
                        );
                    })}
                </div>
            );
        }

        // ── build VM/CT action menu items (shared by list kebab + detail bar) ──

        function CloudKpiRow({ ctx, t }) {
            const { vms, cts, running, connected, safeClusters, nodeNames, vcpu, ramAllocB, dcMem, safeRes } = ctx;
            const kpis = [
                { icon: 'Server', value: vms.length, label: t('cloud.vms') || 'Virtual Machines', sub: `${vms.filter(v => v.status === 'running').length} ${t('cloud.runningUnit') || 'running'}`, nav: 'vms' },
                { icon: 'Box', value: cts.length, label: t('cloud.containers') || 'Containers', sub: `${cts.filter(v => v.status === 'running').length} ${t('cloud.runningUnit') || 'running'}`, nav: 'containers' },
                { icon: 'Cpu', value: nodeNames.length, label: t('cloud.hosts') || 'Hosts', sub: `${connected}/${safeClusters.length} ${t('cloud.clustersUnit') || 'clusters'}`, nav: 'nodes' },
                { icon: 'Activity', value: running.length, label: t('cloud.runningGuests') || 'Running guests', sub: `${safeRes.length} ${t('cloud.totalUnit') || 'total'}`, nav: null },
                { icon: 'Cpu', value: vcpu, label: t('cloud.vcpuAllocated') || 'vCPU allocated', sub: `${safeRes.length} ${t('cloud.guestsUnit') || 'guests'}`, nav: null },
                { icon: 'MemoryStick', value: cloudBytesToGiB(ramAllocB).toFixed(1) + ' GiB', label: t('cloud.ramAllocated') || 'RAM allocated', sub: (dcMem && Number(dcMem.total)) ? `${t('cloud.of') || 'of'} ${cloudBytesToGiB(dcMem.total).toFixed(0)} GiB ${t('cloud.hostsUnit') || 'hosts'}` : null, nav: null },
            ];
            return (
                <div className="cloud-kpi-grid">
                    {kpis.map((k, i) => (
                        <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} sub={k.sub}
                            onClick={k.nav ? () => ctx.onNav(k.nav) : undefined} />
                    ))}
                </div>
            );
        }

        function CloudUtilizationBody({ ctx, t }) {
            const dcRes = ctx.dcStatus && ctx.dcStatus.resources;
            const dcStore = dcRes && dcRes.storage;
            const dcMem = dcRes && dcRes.memory;
            const dcCpu = dcRes && dcRes.cpu;
            // the cluster-wide percents the server already computed win; the
            // node-map average is the fallback while that answer is in flight
            const cpuPct = (dcCpu && dcCpu.percent != null && isFinite(Number(dcCpu.percent))) ? Number(dcCpu.percent) : ctx.cpuAvg;
            const memPct = (dcMem && dcMem.percent != null && isFinite(Number(dcMem.percent))) ? Number(dcMem.percent) : ctx.memAvg;
            const storePct = (dcStore && Number(dcStore.total)) ? (Number(dcStore.used) || 0) / Number(dcStore.total) * 100 : null;
            return (
                <div className="cloud-util-body">
                    <div className="cloud-meter-rows">
                        <CloudMeterRow label={t('cloud.avgCpu') || 'Avg CPU'} sub={`${ctx.nodeNames.length} ${t('cloud.hostsUnit') || 'hosts'}`} pct={cpuPct} />
                        <CloudMeterRow
                            label={t('cloud.avgRam') || 'Avg RAM'}
                            sub={(dcMem && Number(dcMem.total)) ? `${cloudFmtBytes(dcMem.used)} / ${cloudFmtBytes(dcMem.total)}` : null}
                            pct={memPct} />
                        {storePct != null && (
                            <CloudMeterRow
                                label={t('cloud.storage') || 'Storage'}
                                sub={`${cloudFmtBytes(dcStore.used)} / ${cloudFmtBytes(dcStore.total)}`}
                                pct={storePct} />
                        )}
                    </div>
                    <div className="cloud-util-breakdown">
                        <div className="cloud-util-row"><span>{t('cloud.running') || 'Running'}</span><span>{ctx.running.length} / {ctx.safeRes.length}</span></div>
                        <div className="cloud-util-row"><span>{t('cloud.vcpuAllocated') || 'vCPU allocated'}</span><span>{ctx.vcpu}</span></div>
                        <div className="cloud-util-row"><span>{t('cloud.ramAllocated') || 'RAM allocated'}</span><span>{cloudBytesToGiB(ctx.ramAllocB).toFixed(1)} GiB</span></div>
                        <div className="cloud-util-row"><span>{t('cloud.hosts') || 'Hosts'}</span><span>{ctx.nodeNames.length}</span></div>
                    </div>
                </div>
            );
        }

        function CloudGuestStatusWidget({ ctx, t }) {
            const rows = ctx.resources;
            const counts = { running: 0, stopped: 0, paused: 0, other: 0 };
            rows.forEach(r => {
                if (!r) return;
                if (r.status === 'running') counts.running++;
                else if (r.status === 'stopped') counts.stopped++;
                else if (r.status === 'paused' || r.status === 'suspended') counts.paused++;
                else counts.other++;
            });
            const total = Math.max(1, rows.length);
            const segs = [
                { k: 'running', label: t('cloud.wsRunning') || 'Running', color: 'var(--cloud-success)' },
                { k: 'stopped', label: t('cloud.wsStopped') || 'Stopped', color: 'var(--cloud-text-muted)' },
                { k: 'paused', label: t('cloud.wsPaused') || 'Paused', color: 'var(--cloud-warning)' },
                { k: 'other', label: t('cloud.wsOther') || 'Other', color: 'var(--cloud-info)' },
            ].filter(s => counts[s.k] > 0);
            return (
                <div>
                    <div className="cloud-gs-bar" role="img" aria-label={t('cloud.wGuestStatus') || 'Guest status'}>
                        {segs.map(s => <div key={s.k} className="cloud-gs-seg" style={{ width: (counts[s.k] / total * 100) + '%', background: s.color }} />)}
                    </div>
                    <div className="cloud-gs-legend">
                        {segs.map(s => (
                            <span key={s.k} className="cloud-gs-item">
                                <span className="cloud-gs-dot" style={{ background: s.color }} />
                                {s.label} <strong>{counts[s.k]}</strong>
                            </span>
                        ))}
                        <span className="cloud-gs-item cloud-cell-muted">{rows.length} {t('cloud.guestsUnit') || 'guests'}</span>
                    </div>
                </div>
            );
        }

        // one tile per cluster: connection, node quorum and cpu/mem/storage meters
        // from the datacenter status each cluster already reports

        function CloudClusterHealthWidget({ ctx, t }) {
            const clusters = ctx.clusters || [];
            if (clusters.length === 0) return <div className="cloud-empty">{t('cloud.noClusters') || 'No clusters configured.'}</div>;
            return (
                <div className="cloud-ch-grid">
                    {clusters.map(c => {
                        const cid = c && (c.id != null ? c.id : c.name);
                        const st = (ctx.allData && ctx.allData[cid] && ctx.allData[cid].data) || null;
                        const res = (st && st.resources) || null;
                        const nodes = (st && st.nodes) || null;
                        const cpuP = res && res.cpu ? Number(res.cpu.percent) || 0 : null;
                        const memP = res && res.memory ? Number(res.memory.percent) || 0 : null;
                        const storeP = res && res.storage ? Number(res.storage.percent) || 0 : null;
                        return (
                            <div className={'cloud-ch-tile' + (c.connected ? '' : ' is-off')} key={String(cid)}>
                                <div className="cloud-ch-name">
                                    <span className={'cloud-cluster-dot ' + (c.connected ? 'is-on' : 'is-off')} />
                                    <span className="cloud-table-name-text">{(c && (c.display_name || c.name)) || 'cluster'}</span>
                                    <span className="cloud-ch-type">{cloudClusterTypeLabel(c && c.type)}</span>
                                </div>
                                <div className="cloud-ch-meta">
                                    {nodes ? `${nodes.online}/${nodes.total} ${t('cloud.hostsUnit') || 'hosts'}` : (t('cloud.noData') || 'No data')}
                                    {st && st.cluster && st.cluster.standalone === false && st.cluster.quorate === false
                                        ? <span className="cloud-ch-warn">{t('cloud.noQuorum') || 'no quorum'}</span> : null}
                                </div>
                                {cpuP != null && <div className="cloud-meter cloud-ch-meter"><div style={{ width: cpuP + '%', background: cloudThresholdColor(cpuP) }} /></div>}
                                {cpuP == null && <div className="cloud-cell-muted">{t('cloud.offline') || 'offline'}</div>}
                            </div>
                        );
                    })}
                </div>
            );
        }

        // top datastores by usage - shared + local lists flattened, same fields
        // the Datastores page table reads (storage, used, total)

        function CloudDatastoresWidget({ ctx, t }) {
            const ds = ctx.datastores || { shared: [], local: {} };
            const list = [];
            (Array.isArray(ds.shared) ? ds.shared : []).forEach(d => list.push({ ...d, scope: 'shared' }));
            const local = ds.local && typeof ds.local === 'object' ? ds.local : {};
            Object.keys(local).forEach(node => (Array.isArray(local[node]) ? local[node] : []).forEach(d => list.push({ ...d, scope: 'local', _node: node })));
            const rows = list
                .filter(d => Number(d.total) > 0)
                .map(d => ({ name: d.storage || d._node || 'store', pct: Math.min(100, (Number(d.used) || 0) / Number(d.total) * 100), right: `${cloudBytesToGiB(d.used).toFixed(1)} / ${cloudBytesToGiB(d.total).toFixed(1)} GiB`, scope: d.scope }))
                .sort((a, b) => b.pct - a.pct).slice(0, 6);
            if (rows.length === 0) return <div className="cloud-empty">{t('cloud.noDatastores') || 'No datastores reported.'}</div>;
            return (
                <div className="cloud-topcons">
                    {rows.map(r => (
                        <div className="cloud-topcons-row" key={r.name + r.scope}>
                            <span className="cloud-topcons-name" title={r.name}>{r.name}</span>
                            <div className="cloud-topcons-track"><div style={{ width: r.pct + '%', background: cloudThresholdColor(r.pct) }} /></div>
                            <span className="cloud-topcons-val">{Math.round(r.pct)}%</span>
                        </div>
                    ))}
                </div>
            );
        }

        const CLOUD_WIDGETS = {
            kpi: { icon: 'Grid', sizes: ['full'], render: (ctx, cfg, t) => <CloudKpiRow ctx={ctx} t={t} /> },
            utilization: { icon: 'Cpu', sizes: ['lg', 'full'], render: (ctx, cfg, t) => <CloudUtilizationBody ctx={ctx} t={t} /> },
            consumers: { icon: 'Layers', sizes: ['md', 'lg', 'full'], cfg: { metric: 'mem' }, render: (ctx, cfg, t) => <CloudTopConsumers rows={ctx.resources} t={t} metric={cfg.metric} /> },
            activity: { icon: 'Clock', sizes: ['md', 'lg', 'full'], cfg: { max: 8 }, render: (ctx, cfg, t) => <CloudActivityList tasks={ctx.tasks} t={t} max={cfg.max} /> },
            clusterhealth: { icon: 'Cloud', sizes: ['md', 'lg', 'full'], render: (ctx, cfg, t) => <CloudClusterHealthWidget ctx={ctx} t={t} /> },
            gueststatus: { icon: 'Activity', sizes: ['sm', 'md', 'lg', 'full'], render: (ctx, cfg, t) => <CloudGuestStatusWidget ctx={ctx} t={t} /> },
            datastores: { icon: 'Database', sizes: ['md', 'lg', 'full'], render: (ctx, cfg, t) => <CloudDatastoresWidget ctx={ctx} t={t} /> },
        };

        const CLOUD_DASHBOARD_DEFAULT = { v: 1, widgets: [
            { id: 'kpi', size: 'full' },
            { id: 'utilization', size: 'lg' },
            { id: 'gueststatus', size: 'sm' },
            { id: 'consumers', size: 'md' },
            { id: 'activity', size: 'md' },
            { id: 'clusterhealth', size: 'full' },
        ] };

        // stored layout → renderable layout: unknown ids dropped, sizes coerced to
        // the widget's allowed set, missing cfg filled from the registry defaults

        function cloudWidgetLayoutNormalize(saved) {
            const out = { v: 1, widgets: [] };
            if (saved && saved.v === 1 && Array.isArray(saved.widgets)) {
                saved.widgets.forEach(w => {
                    const reg = w && CLOUD_WIDGETS[w.id];
                    if (!reg) return;
                    const size = reg.sizes.includes(w.size) ? w.size : reg.sizes[0];
                    out.widgets.push({ id: w.id, size, cfg: Object.assign({}, reg.cfg || {}, (w.cfg && typeof w.cfg === 'object') ? w.cfg : {}) });
                });
            }
            if (out.widgets.length === 0) return JSON.parse(JSON.stringify(CLOUD_DASHBOARD_DEFAULT));
            return out;
        }

        function useCloudApi(authFetch, url, deps) {
            const [state, setState] = React.useState({ loading: !!url, data: null, error: null });
            const [tick, setTick] = React.useState(0);
            React.useEffect(() => {
                let alive = true;
                if (!authFetch || !url) { setState({ loading: false, data: null, error: null }); return () => { alive = false; }; }
                setState(s => ({ ...s, loading: true, error: null }));
                authFetch(url)
                    .then(async r => {
                        if (!alive) return;
                        if (r && r.ok) {
                            const j = await r.json().catch(() => null);
                            if (alive) setState({ loading: false, data: j, error: null });
                        } else {
                            const j = r ? await r.json().catch(() => ({})) : {};
                            const code = r ? r.status : 0;
                            if (alive) setState({ loading: false, data: null, error: (j && j.error) || (code === 403 ? 'Permission denied' : 'HTTP ' + code) });
                        }
                    })
                    .catch(e => { if (alive) setState({ loading: false, data: null, error: String((e && e.message) || e) }); });
                return () => { alive = false; };
            }, deps.concat([url, tick]));
            const reload = React.useCallback(() => setTick(x => x + 1), []);
            return { ...state, reload };
        }

        // unified operational state model. A missing proof is never a pass:
        // no data → unknown, not relevant → na.

        function CloudDashboard({ clusters, resources, metrics, dcStatus, tasks, datastores, allData, onNav, t, authFetch }) {
            const safeClusters = Array.isArray(clusters) ? clusters : [];
            const safeRes = Array.isArray(resources) ? resources : [];
            const vms = safeRes.filter(r => r && r.type === 'qemu');
            const cts = safeRes.filter(r => r && r.type === 'lxc');
            const running = safeRes.filter(r => r && r.status === 'running');
            const connected = safeClusters.filter(c => c && c.connected).length;
            const nodeMap = (metrics && typeof metrics === 'object') ? metrics : {};
            const nodeNames = Object.keys(nodeMap);

            // aggregates
            const vcpu = safeRes.reduce((a, r) => a + (Number(r && r.maxcpu) || 0), 0);
            const ramAllocB = safeRes.reduce((a, r) => a + (Number(r && r.maxmem) || 0), 0);

            // node-level utilisation (avg across nodes)
            let cpuAvg = 0, memAvg = 0, n = 0;
            nodeNames.forEach(k => {
                const m = nodeMap[k]; if (!m) return;
                cpuAvg += Number(m.cpu_percent) || 0;
                memAvg += Number(m.mem_percent) || 0;
                n++;
            });
            if (n) { cpuAvg /= n; memAvg /= n; }

            const dcRes = dcStatus && dcStatus.resources;
            const dcMem = dcRes && dcRes.memory;

            // everything a widget may read, in one bag - no prop drilling per widget
            const ctx = {
                safeClusters, safeRes, vms, cts, running, connected, nodeNames, nodeMap,
                vcpu, ramAllocB, cpuAvg, memAvg, dcStatus, dcMem,
                clusters: safeClusters, resources: safeRes, metrics: nodeMap,
                tasks, datastores, allData, onNav,
            };

            // ── personal layout: load once, save debounced ──
            const [layout, setLayout] = React.useState(null);
            const [customizing, setCustomizing] = React.useState(false);
            const [drag, setDrag] = React.useState(null);
            const saveTimer = React.useRef(null);

            React.useEffect(() => {
                let alive = true;
                (async () => {
                    let saved = null;
                    try {
                        const r = await authFetch(`${API_URL}/user/preferences`);
                        if (r && r.ok) saved = (await r.json()).cloud_dashboard || null;
                    } catch (e) { /* offline → localStorage */ }
                    if (!saved) { try { const ls = localStorage.getItem('pegaprox-cloud-dashboard'); if (ls) saved = JSON.parse(ls); } catch (e) {} }
                    if (alive) setLayout(cloudWidgetLayoutNormalize(saved));
                })();
                return () => { alive = false; };
            }, []);

            const persist = React.useCallback((next) => {
                if (saveTimer.current) clearTimeout(saveTimer.current);
                saveTimer.current = setTimeout(() => {
                    if (!authFetch) return;
                    authFetch(`${API_URL}/user/preferences`, {
                        method: 'PUT', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ cloud_dashboard: next }),
                    }).then(r => { if (!r || !r.ok) throw new Error('save failed'); })
                      .catch(() => { try { localStorage.setItem('pegaprox-cloud-dashboard', JSON.stringify(next)); } catch (e) {} });
                }, 600);
            }, [authFetch]);

            const mutate = (fn) => setLayout(prev => { const next = fn(prev); persist(next); return next; });

            const addWidget = (id) => mutate(p => ({ v: 1, widgets: p.widgets.concat([{ id, size: CLOUD_WIDGETS[id].sizes[0], cfg: Object.assign({}, CLOUD_WIDGETS[id].cfg || {}) }]) }));
            const removeWidget = (id) => mutate(p => ({ v: 1, widgets: p.widgets.filter(w => w.id !== id) }));
            const cycleSize = (id) => mutate(p => ({
                v: 1,
                widgets: p.widgets.map(w => {
                    if (w.id !== id) return w;
                    const sizes = CLOUD_WIDGETS[w.id].sizes;
                    return { ...w, size: sizes[(sizes.indexOf(w.size) + 1) % sizes.length] };
                }),
            }));
            const setCfg = (id, patch) => mutate(p => ({
                v: 1,
                widgets: p.widgets.map(w => w.id !== id ? w : { ...w, cfg: Object.assign({}, w.cfg, patch) }),
            }));
            const restoreDefaults = () => mutate(() => JSON.parse(JSON.stringify(CLOUD_DASHBOARD_DEFAULT)));
            const reorder = (dragId, targetId) => mutate(p => {
                const from = p.widgets.findIndex(w => w.id === dragId);
                const to = p.widgets.findIndex(w => w.id === targetId);
                if (from < 0 || to < 0 || from === to) return p;
                const copy = p.widgets.slice();
                const [it] = copy.splice(from, 1);
                copy.splice(to, 0, it);
                return { v: 1, widgets: copy };
            });

            const mounted = new Set((layout && layout.widgets || []).map(w => w.id));
            const addable = Object.keys(CLOUD_WIDGETS)
                .filter(id => !mounted.has(id))
                .map(id => ({ label: cloudWidgetTitle(id, t), icon: CLOUD_WIDGETS[id].icon, onClick: () => addWidget(id) }));
            if (addable.length === 0) addable.push({ label: t('cloud.allMounted') || 'All widgets are on the dashboard', icon: 'Check', disabled: true });

            const body = layout == null ? null : (
                <div className="cloud-widget-grid">
                    {layout.widgets.map(w => {
                        const reg = CLOUD_WIDGETS[w.id];
                        if (!reg) return null;
                        const custom = customizing ? {
                            id: w.id,
                            size: w.size,
                            sizeTitle: t('cloud.wResize') || 'Change size',
                            removeTitle: t('cloud.wRemove') || 'Remove widget',
                            onCycleSize: reg.sizes.length > 1 ? () => cycleSize(w.id) : undefined,
                            onRemove: w.id === 'kpi' ? undefined : () => removeWidget(w.id),
                            dragging: drag && drag.id === w.id,
                            dropTarget: drag && drag.over === w.id && drag.id !== w.id,
                            onDragStart: (e) => { e.dataTransfer.effectAllowed = 'move'; try { e.dataTransfer.setData('text/plain', w.id); } catch (er) {} setDrag({ id: w.id, over: null }); },
                            onDragEnd: () => setDrag(null),
                            onDragOver: (e) => { if (drag && drag.id !== w.id) { e.preventDefault(); if (drag.over !== w.id) setDrag({ ...drag, over: w.id }); } },
                            onDragLeave: () => setDrag(d => (d && d.over === w.id ? { ...d, over: null } : d)),
                            onDrop: (e) => { e.preventDefault(); const from = drag && drag.id; setDrag(null); if (from && from !== w.id) reorder(from, w.id); },
                        } : null;
                        const cfgUi = customizing && w.id === 'consumers' ? (
                            <select className="cloud-cust-select" value={(w.cfg && w.cfg.metric) || 'mem'} onChange={(e) => setCfg(w.id, { metric: e.target.value })}>
                                <option value="mem">{t('cloud.metricRam') || 'RAM'}</option>
                                <option value="cpu">{t('cloud.metricCpu') || 'CPU'}</option>
                                <option value="disk">{t('cloud.metricDisk') || 'Disk'}</option>
                            </select>
                        ) : customizing && w.id === 'activity' ? (
                            <select className="cloud-cust-select" value={(w.cfg && w.cfg.max) || 8} onChange={(e) => setCfg(w.id, { max: Number(e.target.value) })}>
                                {[4, 8, 12].map(v => <option key={v} value={v}>{v}</option>)}
                            </select>
                        ) : null;
                        return (
                            <div key={w.id} className={'cloud-widget-cell cloud-widget-span-' + w.size}>
                                <CloudWidgetCard title={cloudWidgetTitle(w.id, t)} icon={reg.icon} custom={custom} actions={cfgUi}>
                                    {reg.render(ctx, w.cfg || {}, t)}
                                </CloudWidgetCard>
                            </div>
                        );
                    })}
                </div>
            );

            return (
                <div className="cloud-body">
                    <CloudPageHeader
                        title={t('cloud.overview') || 'Overview'}
                        sub={`${connected} / ${safeClusters.length} ${t('cloud.clustersConnected') || 'clusters connected'} · ${safeRes.length} ${t('cloud.guestsUnit') || 'guests'}`}
                    >
                        <button type="button" className={customizing ? 'cloud-btn cloud-btn-primary' : 'cloud-btn'} onClick={() => setCustomizing(v => !v)}>
                            {customizing ? (t('cloud.done') || 'Done') : (t('cloud.customize') || 'Customize')}
                        </button>
                    </CloudPageHeader>

                    {customizing && (
                        <div className="cloud-customize-bar">
                            <span className="cloud-cust-hint">{t('cloud.custHint') || 'Drag a widget onto another to reorder. Resize or remove with the icons in a widget header. Your layout is saved to your account.'}</span>
                            <CloudActionMenu items={addable} label={t('cloud.addWidget') || 'Add widget'} />
                            <button type="button" className="cloud-btn" onClick={restoreDefaults}>
                                <Icons.RotateCcw /> {t('cloud.restoreDefaults') || 'Restore defaults'}
                            </button>
                        </div>
                    )}

                    {layout == null ? (
                        <div className="cloud-empty">{t('cloud.loading') || 'Loading…'}</div>
                    ) : layout.widgets.length === 0 ? (
                        <CloudEmpty
                            icon="Grid"
                            title={t('cloud.noWidgets') || 'No widgets'}
                            text={t('cloud.noWidgetsText') || 'Your dashboard is empty. Add widgets or restore the default layout.'}
                            action={<button type="button" className="cloud-btn cloud-btn-primary" onClick={restoreDefaults}>{t('cloud.restoreDefaults') || 'Restore defaults'}</button>}
                        />
                    ) : body}
                </div>
            );
        }

        // ── instances list (VMs / Containers) ──────────────────────

        function cloudDsFlatten(ds) {
            const out = [];
            if (!ds) return out;
            (Array.isArray(ds.shared) ? ds.shared : Object.values(ds.shared || {})).forEach(d => { if (d) out.push({ ...d, scope: 'shared' }); });
            const local = ds.local && typeof ds.local === 'object' ? ds.local : {};
            Object.keys(local).forEach(node => (Array.isArray(local[node]) ? local[node] : []).forEach(d => { if (d) out.push({ ...d, scope: 'local', _node: node }); }));
            return out;
        }

        function cloudDsState(d) {
            if (d.active === 0 || d.active === false || d.enabled === 0) return 'unreachable';
            if (!Number(d.total)) return 'rawblock';
            if (Array.isArray(d.active_on) && Array.isArray(d.inactive_on) && d.inactive_on.length > 0) return 'partial';
            return 'ok';
        }

        // ── Explorer ────────────────────────────────────────────────

        function CloudSwDialog({ title, onClose, children, wide }) {
            return (
                <div className="cloud-oci-overlay" onClick={onClose}>
                    <div className={'cloud-oci-dialog' + (wide ? ' cloud-sw-wide' : '')} onClick={(e) => e.stopPropagation()}>
                        <div className="cloud-cfg-head" style={{ gridArea: 'auto' }}>
                            <div className="cloud-cfg-head-left"><div className="cloud-cfg-head-title"><h2>{title}</h2></div></div>
                            <div className="cloud-cfg-head-actions">
                                <button type="button" className="cloud-icon-btn" onClick={onClose}><Icons.X /></button>
                            </div>
                        </div>
                        <div className="cloud-sw-dialog-body">{children}</div>
                    </div>
                </div>
            );
        }

        // flatten the datastores response into one list with scope/node

        function CloudSwRescan({ clusterId, sel, authFetch, addToast, t, onClose, onDone }) {
            const [deep, setDeep] = React.useState(false);
            const [pvresize, setPvresize] = React.useState(false);
            const [busy, setBusy] = React.useState(false);
            const run = async () => {
                setBusy(true);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/storage/${encodeURIComponent(sel.name)}/rescan`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ deep_scan: deep, pvresize }),
                    });
                    const j = r ? await r.json().catch(() => ({})) : {};
                    if (r && r.ok) { addToast(t('cloud.taskStarted') || 'Task started', 'success'); onDone(); onClose(); }
                    else addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
                } finally { setBusy(false); }
            };
            return (
                <CloudSwDialog title={(t('rescan') || 'Rescan') + ' · ' + sel.name} onClose={onClose}>
                    <div className="cloud-sw-form">
                        <label className="cloud-cell-muted" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                            <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} /> {t('deepScan') || 'Deep scan'}
                        </label>
                        <label className="cloud-cell-muted" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                            <input type="checkbox" checked={pvresize} onChange={(e) => setPvresize(e.target.checked)} /> pvresize
                        </label>
                        <div className="cloud-sw-form-actions">
                            <button type="button" className="cloud-btn" onClick={onClose} disabled={busy}>{t('cancel')}</button>
                            <button type="button" className="cloud-btn cloud-btn-primary" disabled={busy} onClick={run}>{t('rescan') || 'Rescan'}</button>
                        </div>
                    </div>
                </CloudSwDialog>
            );
        }


        // ── Storage Balancing ─────────────────────────────────────

        function CloudStorageExplorer({ clusterId, authFetch, addToast, isAdmin, holdsPerm, t, sharedDatastores }) {
            const listQ = useCloudData(clusterId != null ? `${API_URL}/clusters/${clusterId}/datastores` : null);
            const datastores = listQ.data || sharedDatastores || null;
            const list = React.useMemo(() => cloudDsFlatten(datastores), [datastores]);

            const [query, setQuery] = React.useState('');
            const [typeF, setTypeF] = React.useState('all');
            const [scopeF, setScopeF] = React.useState('all');
            const [selKey, setSelKey] = React.useState(null);     // {storage, scope, node}
            const [nodeView, setNodeView] = React.useState('');   // shared: content node switcher
            const [detTab, setDetTab] = React.useState('overview'); // overview | content | details
            const [contentFilter, setContentFilter] = React.useState('');

            const q = query.trim().toLowerCase();
            const types = React.useMemo(() => [...new Set(list.map(d => d.type).filter(Boolean))].sort(), [list]);
            const view = list.filter(d =>
                (typeF === 'all' || d.type === typeF) &&
                (scopeF === 'all' || d.scope === scopeF) &&
                (!q || (d.storage || '').toLowerCase().includes(q) || (d.type || '').toLowerCase().includes(q)));

            const sel = selKey ? (() => {
                const s = list.find(d => d.storage === selKey.storage && d.scope === selKey.scope && (d.scope === 'shared' || d._node === selKey.node));
                return s || null;
            })() : null;
            const selNode = sel ? (sel.scope === 'shared' ? (nodeView || (Array.isArray(sel.active_on) && sel.active_on[0]) || '') : (sel._node || '')) : '';
            React.useEffect(() => { setNodeView(''); }, [selKey && selKey.storage]);

            const contentUrl = (sel && clusterId != null)
                ? `${API_URL}/clusters/${clusterId}/datastores/${encodeURIComponent(sel.storage)}/content${selNode ? '?node=' + encodeURIComponent(selNode) : ''}`
                : null;
            const contentQ = useCloudData(contentUrl);
            const content = Array.isArray(contentQ.data) ? contentQ.data : [];
            const filteredContent = contentFilter ? content.filter(c => c.content === contentFilter) : content;
            const can = (p) => isAdmin || (holdsPerm && holdsPerm(p));

            // dialogs
            const [dlg, setDlg] = React.useState(null);           // 'upload' | 'url' | 'templates' | 'rescan'
            const [batchRestore, setBatchRestore] = React.useState(null);

            

            // overview (no selection): honest cluster-wide storage summary
            const overview = React.useMemo(() => {
                if (!list.length) return null;
                const withCap = list.filter(d => Number(d.total) > 0);
                const total = withCap.reduce((a, d) => a + Number(d.total) || 0, 0);
                const used = withCap.reduce((a, d) => a + Number(d.used) || 0, 0);
                const nodes = new Set(); list.forEach(d => d.scope === 'local' && d._node && nodes.add(d._node));
                (Array.isArray(datastores && datastores.nodes) ? datastores.nodes : []).forEach(n => nodes.add(n));
                const byType = {}; list.forEach(d => { if (d.type) byType[d.type] = (byType[d.type] || 0) + 1; });
                const top = withCap.map(d => ({ name: d.storage, scope: d.scope, pct: Math.round((Number(d.used) || 0) / Number(d.total) * 100) }))
                    .sort((a, b) => b.pct - a.pct).slice(0, 6);
                return { count: list.length, shared: list.filter(d => d.scope === 'shared').length, local: list.filter(d => d.scope === 'local').length, nodes: nodes.size, total, used, avail: total - used, byType, top };
            }, [list, datastores]);

            const Row = ({ d }) => {
                const st = cloudDsState(d);
                const pct = Number(d.total) ? Math.round((Number(d.used) || 0) / Number(d.total) * 100) : null;
                const active = sel && sel.storage === d.storage && sel.scope === d.scope && (d.scope === 'shared' || sel._node === d._node);
                return (
                    <button type="button" className={'cloud-sw-row' + (active ? ' is-active' : '')} onClick={() => setSelKey({ storage: d.storage, scope: d.scope, node: d._node || '' })}>
                        <span className="cloud-sw-row-top">
                            <span className="cloud-sw-row-name" title={d.storage}>{d.storage}</span>
                            <span className="cloud-chip cloud-chip-soft">{d.scope === 'shared' ? 'shared' : (d._node || 'local')}</span>
                        </span>
                        <span className="cloud-sw-row-sub">
                            <span className="cloud-cell-muted">{d.type || ' - '}</span>
                            {Number(d.total) > 0 && <span className="cloud-cell-muted" style={{ fontSize: '0.64rem' }}>{cloudFmtBytes(d.used)} / {cloudFmtBytes(d.total)}</span>}
                            {pct != null && <span className="cloud-sw-row-bar"><span style={{ width: pct + '%', background: cloudThresholdColor(pct) }} /></span>}
                            {st === 'unreachable' && <span className="cloud-hc-badge is-critical">OFFLINE</span>}
                            {st === 'rawblock' && <span className="cloud-hc-badge is-na">RAW</span>}
                            {st === 'partial' && <span className="cloud-hc-badge is-warning">{(d.active_on || []).length}/{(d.active_on || []).length + (d.inactive_on || []).length}</span>}
                        </span>
                    </button>
                );
            };

            return (
                <div className="cloud-sw-layout">
                    <div className="cloud-sw-list">
                        <CloudSearch value={query} onChange={(v) => setQuery(v)} placeholder={t('cloud.searchStorage') || 'Search storage…'} />
                        <div className="cloud-segment" style={{ marginTop: 8 }}>
                            {['all', 'shared', 'local'].map(s => (
                                <button type="button" key={s} className={'cloud-segment-btn' + (scopeF === s ? ' is-active' : '')} onClick={() => setScopeF(s)}>{s === 'all' ? (t('cloud.all') || 'All') : s}</button>
                            ))}
                        </div>
                        {types.length > 1 && (
                            <select className="cloud-input cloud-sw-typef" value={typeF} onChange={(e) => setTypeF(e.target.value)}>
                                <option value="all">{t('cloud.allTypes') || 'All types'}</option>
                                {types.map(ty => <option key={ty} value={ty}>{ty}</option>)}
                            </select>
                        )}
                        <CloudSectionState loading={listQ.loading && !datastores} err={listQ.err && !datastores ? listQ.err : null} empty={!view.length} t={t}
                            emptyIcon="Database" emptyTitle={t('cloud.noDatastores') || 'No datastores'} emptyText={q || typeF !== 'all' ? (t('cloud.noMatch') || 'No matches') : null}>
                            <div className="cloud-sw-groups">
                                {['shared', 'local'].map(scope => {
                                    const rows = view.filter(d => d.scope === scope);
                                    if (!rows.length) return null;
                                    return (
                                        <div className="cloud-sw-group" key={scope}>
                                            <div className="cloud-sw-group-label">{scope === 'shared' ? (t('cloud.sharedStorage') || 'Shared storage') : (t('cloud.localStorage') || 'Local storage')}</div>
                                            {rows.map((d, i) => <Row d={d} key={(d.storage || '') + '-' + (d._node || '') + '-' + i} />)}
                                        </div>
                                    );
                                })}
                            </div>
                        </CloudSectionState>
                    </div>
                    <div className="cloud-sw-main">
                        {!sel ? (
                            overview && (
                                <>
                                    <div className="cloud-stat-grid">
                                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Database /></span><div><div className="cloud-stat-num">{overview.count}</div><div className="cloud-stat-lb">{t('cloud.datastores') || 'datastores'} · {overview.shared} shared / {overview.local} local</div></div></div>
                                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Cpu /></span><div><div className="cloud-stat-num">{overview.nodes}</div><div className="cloud-stat-lb">{t('cloud.hosts') || 'Hosts'}</div></div></div>
                                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.HardDrive /></span><div><div className="cloud-stat-num">{cloudFmtBytes(overview.total)}</div><div className="cloud-stat-lb">{t('cloud.total') || 'Total capacity'}</div></div></div>
                                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Activity /></span><div><div className="cloud-stat-num">{cloudFmtBytes(overview.used)}</div><div className="cloud-stat-lb">{t('cloud.used') || 'Used'} · {overview.total ? Math.round(overview.used / overview.total * 100) : 0}% · {t('cloud.free') || 'free'} {cloudFmtBytes(overview.avail)}</div></div></div>
                                    </div>
                                    <div className="cloud-sw-cols">
                                        <div className="cloud-card">
                                            {cloudHead({ icon: <Icons.BarChart />, title: t('cloud.topUsage') || 'Highest utilization' })}
                                            <div className="cloud-card-pad">
                                                {overview.top.map(x => (
                                                    <div className="cloud-topcons-row" key={x.name}>
                                                        <span className="cloud-topcons-name">{x.name}</span>
                                                        <div className="cloud-topcons-track"><div style={{ width: x.pct + '%', background: cloudThresholdColor(x.pct) }} /></div>
                                                        <span className="cloud-topcons-val">{x.pct}%</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        <div className="cloud-card">
                                            {cloudHead({ icon: <Icons.Layers />, title: t('cloud.byType') || 'By type' })}
                                            <div className="cloud-card-pad cloud-sw-types">
                                                {Object.entries(overview.byType).sort((a, b) => b[1] - a[1]).map(([ty, n]) => (
                                                    <span key={ty} className="cloud-chip cloud-chip-soft">{ty} · {n}</span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </>
                            )
                        ) : (
                            <>
                                <div className="cloud-card">
                                    <div className="cloud-sw-detail-head">
                                        <div>
                                            <div className="cloud-sw-detail-name">{sel.storage}</div>
                                            <div className="cloud-detail-meta">
                                                <span className="cloud-chip cloud-chip-soft">{sel.type || ' - '}</span>
                                                <span className="cloud-detail-id">{sel.scope === 'shared' ? (t('cloud.sharedStorage') || 'Shared') : (t('cloud.localStorage') || 'Local') + (sel._node ? ' · ' + sel._node : '')}{selNode ? ' · ' + (t('cloud.viewNode') || 'view') + ': ' + selNode : ''}</span>
                                                {sel.content && String(sel.content).split(',').filter(Boolean).slice(0, 5).map(c => <span key={c} className="cloud-chip cloud-chip-tag" style={{ fontSize: '0.58rem' }}>{c.trim()}</span>)}
                                            </div>
                                        </div>
                                        <div className="cloud-sw-detail-actions">
                                            {can('cluster.config') && <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => setDlg('rescan')} title={t('rescanStorageTooltip') || 'Rescan storage'}><Icons.RefreshCw /> {t('rescan') || 'Rescan'}</button>}
                                            {can('vm.backup') && content.some(i => i.content === 'backup' && i.vmid) && (
                                                <button type="button" className="cloud-btn cloud-btn-sm cloud-btn-primary" data-br-open onClick={() => setBatchRestore('pick')}><Icons.RotateCcw /> {t('batchRestoreButton') || 'Batch restore'}</button>
                                            )}
                                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => { listQ.reload(); contentQ.reload(); }}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                                        </div>
                                    </div>
                                    {Number(sel.total) > 0 ? (
                                        <div className="cloud-sw-cap">
                                            <CloudUsageBar pct={Math.round((Number(sel.used) || 0) / Number(sel.total) * 100)}
                                                leftLabel={`${t('cloud.used') || 'Used'} ${cloudFmtBytes(sel.used)}`} rightLabel={`${cloudFmtBytes(sel.avail)} ${t('cloud.free') || 'free'} · ${cloudFmtBytes(sel.total)}`} />
                                        </div>
                                    ) : (
                                        <div className="cloud-table-note">{cloudDsState(sel) === 'rawblock' ? (t('cloud.rawBlockNote') || 'Raw block storage - capacity is managed by the VM disks on it.') : (t('cloud.noCapacityData') || 'No capacity reported.')}</div>
                                    )}
                                    {sel.scope === 'shared' && Array.isArray(sel.active_on) && sel.active_on.length > 1 && (
                                        <div className="cloud-sw-nodeview">
                                            <span className="cloud-cell-muted">{t('cloud.viewNode') || 'View'}:</span>
                                            <div className="cloud-segment">
                                                {sel.active_on.map(n => (
                                                    <button type="button" key={n} className={'cloud-segment-btn' + ((nodeView || sel.active_on[0]) === n ? ' is-active' : '')} onClick={() => setNodeView(n)}>{n}</button>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    <div className="cloud-segment" style={{ marginTop: 10, padding: '0 var(--space-md) var(--space-sm)' }}>
                                        {[['overview', t('cloud.detOverview') || 'Overview'], ['content', t('cloud.detContent') || 'Content'], ['details', t('cloud.detDetails') || 'Details']].map(([id, lb]) => (
                                            <button type="button" key={id} className={'cloud-segment-btn' + (detTab === id ? ' is-active' : '')} onClick={() => setDetTab(id)}>{lb}</button>
                                        ))}
                                    </div>
                                </div>
                                {detTab === 'overview' && Number(sel.total) > 0 && (
                                    <div className="cloud-card">
                                        {cloudHead({ icon: <Icons.BarChart />, title: t('cloud.utilization') || 'Utilization' })}
                                        <div className="cloud-card-pad">
                                            <CloudMeterRow label={t('cloud.used') || 'Used'} sub={cloudFmtBytes(sel.used)} pct={Math.round((Number(sel.used) || 0) / Number(sel.total) * 100)} />
                                            <CloudMeterRow label={t('cloud.free') || 'Free'} sub={cloudFmtBytes(sel.avail)} pct={100 - Math.round((Number(sel.used) || 0) / Number(sel.total) * 100)} />
                                        </div>
                                    </div>
                                )}
                                {detTab === 'details' && (
                                    <div className="cloud-card">
                                        {cloudHead({ icon: <Icons.Settings />, title: t('cloud.detDetails') || 'Details' })}
                                        <div className="cloud-card-pad">
                                            <CloudKVRow label={t('cloud.dsType') || 'Type'} value={sel.type} />
                                            <CloudKVRow label={t('cloud.colContent') || 'Content types'} value={<span className="cloud-sw-types">{String(sel.content || '').split(',').filter(Boolean).map(c => <span key={c} className="cloud-chip cloud-chip-soft">{c.trim()}</span>)}</span>} />
                                            <CloudKVRow label={t('cloud.dsScope') || 'Scope'} value={sel.scope === 'shared' ? 'shared' : 'local' + (sel._node ? ' · ' + sel._node : '')} />
                                            {sel.scope === 'shared' && Array.isArray(sel.active_on) && sel.active_on.length > 0 && <CloudKVRow label={t('cloud.activeOn') || 'Active on'} value={sel.active_on.join(', ')} />}
                                            {Array.isArray(sel.inactive_on) && sel.inactive_on.length > 0 && <CloudKVRow label={t('cloud.inactiveOn') || 'Inactive on'} value={<span className="cloud-ch-warn">{sel.inactive_on.join(', ')}</span>} />}
                                            {sel.path && <CloudKVRow label="Path" value={<span className="cloud-table-mono">{sel.path}</span>} />}
                                        </div>
                                    </div>
                                )}
                                {detTab === 'content' && (
                                <div className="cloud-card cloud-table-card">
                                    {cloudHead({ icon: <Icons.FolderOpen />, title: t('cloud.contentBrowser') || 'Content', count: filteredContent.length, right: contentQ.loading ? <span className="cloud-cell-muted">{t('cloud.loading') || 'Loading…'}</span> : null })}
                                        {(() => {
                                            const kinds = [...new Set(content.map(c => c.content).filter(Boolean))];
                                            if (kinds.length < 2) return null;
                                            return (
                                                <div className="cloud-filterchips" style={{ padding: '8px var(--space-md)' }}>
                                                    {kinds.map(k => (
                                                        <span key={k} className={'cloud-filterchip' + (contentFilter === k ? ' is-active' : '')} style={{ cursor: 'pointer' }} onClick={() => setContentFilter(contentFilter === k ? '' : k)}>
                                                            {k} · {content.filter(c => c.content === k).length}
                                                        </span>
                                                    ))}
                                                </div>
                                            );
                                        })()}
                                    <CloudSectionState loading={contentQ.loading} err={contentQ.err} empty={!filteredContent.length} t={t}
                                        emptyIcon="FolderOpen" emptyTitle={t('cloud.dsEmpty') || 'Empty'} emptyText={t('cloud.dsEmptyText') || 'No content reported on this datastore.'}>
                                        <div className="cloud-table-scroll">
                                            <table className="cloud-table">
                                                <thead><tr><th>{t('cloud.file') || 'Volume'}</th><th>{t('cloud.kind') || 'Kind'}</th><th>{t('cloud.colSize') || 'Size'}</th><th>Format</th><th>{t('cloud.colId') || 'Guest'}</th><th className="cloud-th-actions"></th></tr></thead>
                                                <tbody>
                                                    {filteredContent.map((it, i) => (
                                                        <tr className="cloud-table-row cloud-table-row-static" key={it.volid || i}>
                                                            <td className="cloud-table-mono" title={it.volid}>{String(it.volid || '').split(':').pop() || it.volid}</td>
                                                            <td><span className="cloud-chip cloud-chip-soft">{it.content || ' - '}</span></td>
                                                            <td>{it.size_human || (it.size ? (it.size_is_approx ? '~' : '') + cloudFmtBytes(it.size) : ' - ')}</td>
                                                            <td>{it.format || ' - '}</td>
                                                            <td>{it.vmid != null ? ('#' + it.vmid) : ' - '}</td>
                                                            <td className="cloud-td-actions" onClick={(e) => e.stopPropagation()}>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </CloudSectionState>
                                </div>
                                )}
                            </>
                        )}
                    </div>

                    {dlg === 'rescan' && sel && <CloudSwRescan clusterId={clusterId} sel={{ name: sel.storage }} authFetch={authFetch} addToast={addToast} t={t} onClose={() => setDlg(null)} onDone={() => setTimeout(() => { listQ.reload(); contentQ.reload(); }, 2000)} />}
                    {batchRestore && sel && (
                        <BatchRestoreModal clusterId={clusterId} storage={sel.storage}
                            items={batchRestore === 'pick' ? content.filter(i => i.content === 'backup') : null}
                            nodes={(datastores && datastores.nodes) || []} datastores={datastores}
                            defaultNode={selNode || ((content.find(i => i.content === 'backup') || {}).node)}
                            onClose={() => setBatchRestore(null)} />
                    )}
                </div>
            );
        }

        // upload with real XHR progress (same endpoint as the classic tab)

        function CloudIsoSync({ clusterId, authFetch, addToast, t }) {
            const [ct, setCt] = React.useState('iso');   // iso | vztmpl
            const statusQ = useCloudData(`${API_URL}/clusters/${clusterId}/iso-sync/status?content=${ct}`);
            const st = statusQ.data && !statusQ.err ? statusQ.data : null;
            const [busyFile, setBusyFile] = React.useState('');
            const [busyAll, setBusyAll] = React.useState(false);
            const [last, setLast] = React.useState(null);
            const pollRef = React.useRef(null);
            React.useEffect(() => () => clearInterval(pollRef.current), []);
            const pollLast = () => {
                clearInterval(pollRef.current);
                pollRef.current = setInterval(async () => {
                    try {
                        const r = await authFetch(`${API_URL}/clusters/${clusterId}/iso-sync/last-result`);
                        if (r && r.ok) {
                            const d = await r.json();
                            setLast(d);
                            if (d && (d.done || d.status === 'done' || d.status === 'completed' || d.status === 'error')) { clearInterval(pollRef.current); statusQ.reload(); }
                        }
                    } catch (e) { /* keep */ }
                }, 2500);
            };
            const syncOne = async (f) => {
                const src = (st.nodes || []).find(n => st.matrix && st.matrix[(f.storage || '') + ':' + f.name] && st.matrix[(f.storage || '') + ':' + f.name][n]);
                setBusyFile(f.name);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/iso-sync`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ source_node: src || (st.nodes || [])[0], storage: f.storage, filename: f.name, content_type: ct }),
                    });
                    const j = r ? await r.json().catch(() => ({})) : {};
                    if (r && r.ok) { addToast(t('cloud.taskStarted') || 'Sync started', 'success'); pollLast(); }
                    else addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
                } finally { setBusyFile(''); }
            };
            const syncAll = async () => {
                setBusyAll(true);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/iso-sync/all`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content_type: ct }),
                    });
                    const j = r ? await r.json().catch(() => ({})) : {};
                    if (r && r.ok) { addToast(t('cloud.taskStarted') || 'Sync started', 'success'); pollLast(); }
                    else addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
                } finally { setBusyAll(false); }
            };
            const files = (st && Array.isArray(st.files)) ? st.files : [];
            const nodes = (st && Array.isArray(st.nodes)) ? st.nodes : [];
            const unread = (st && st.unread) || {};
            const missing = files.reduce((a, f) => a + nodes.filter(n => !(st.matrix && st.matrix[(f.storage || '') + ':' + f.name] && st.matrix[(f.storage || '') + ':' + f.name][n])).length, 0);
            return (
                <>
                    <div className="cloud-toolbar">
                        <div className="cloud-toolbar-left">
                            <div className="cloud-segment">
                                {[['iso', 'ISO'], ['vztmpl', t('cloud.templates') || 'Templates']].map(([id, lb]) => (
                                    <button type="button" key={id} className={'cloud-segment-btn' + (ct === id ? ' is-active' : '')} onClick={() => setCt(id)}>{lb}</button>
                                ))}
                            </div>
                        </div>
                        <div className="cloud-toolbar-right">
                            <button type="button" className="cloud-btn cloud-btn-sm cloud-btn-primary" disabled={busyAll || !missing} onClick={syncAll}><Icons.RefreshCw /> {t('syncAllMissing') || 'Sync all missing'}</button>
                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={statusQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                        </div>
                    </div>
                    {last && last.results && (
                        <div className="cloud-card cloud-sw-lastsync">
                            <div className="cloud-chart-head">
                                <span className="cloud-chart-title">{t('cloud.lastSync') || 'Last sync'}</span>
                                <span className="cloud-cell-muted">{String(last.timestamp || '').replace('T', ' ').slice(0, 16)} · {last.filename || ''}</span>
                                <span className="cloud-hc-badge is-healthy">{last.ok}✓</span>
                                {last.failed > 0 && <span className="cloud-hc-badge is-critical">{last.failed}✗</span>}
                            </div>
                            <div className="cloud-sw-syncnodes">
                                {(last.results || []).map((r, i) => (
                                    <span key={i} className="cloud-sw-syncnode" title={r.error || r.method || ''}>
                                        <span className={'cloud-sync-dot ' + (r.success ? (r.skipped ? 'is-ok' : 'is-ok') : 'is-miss')}>{r.success ? (r.skipped ? '∘' : '✓') : '✗'}</span>
                                        {r.node}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                    <div className="cloud-stat-grid">
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.File /></span><div><div className="cloud-stat-num">{files.length}</div><div className="cloud-stat-lb">{t('cloud.files') || 'files'}</div></div></div>
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.CheckCircle /></span><div><div className="cloud-stat-num">{files.filter(f => nodes.every(n => st.matrix && st.matrix[(f.storage || '') + ':' + f.name] && st.matrix[(f.storage || '') + ':' + f.name][n])).length}</div><div className="cloud-stat-lb">{t('cloud.syncComplete') || 'fully synced'}</div></div></div>
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Copy /></span><div><div className="cloud-stat-num">{missing}</div><div className="cloud-stat-lb">{t('cloud.missingCopies') || 'missing copies'}</div></div></div>
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Cpu /></span><div><div className="cloud-stat-num">{nodes.length}</div><div className="cloud-stat-lb">{t('cloud.hostsUnit') || 'nodes'}</div></div></div>
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.Eye /></span><div><div className="cloud-stat-num">{Object.keys(unread).length}</div><div className="cloud-stat-lb">{t('cloud.unreadNodes') || 'unreadable nodes'}</div></div></div>
                    </div>
                    {Object.keys(unread).length > 0 && (
                        <div className="cloud-card cloud-hc-note cloud-hc-note-warn"><Icons.Eye />
                            <span>{Object.entries(unread).map(([n, why]) => n + ': ' + why).join(' · ')}</span>
                        </div>
                    )}
                    <div className="cloud-card cloud-table-card">
                        {cloudHead({ icon: <Icons.File />, title: t('cloud.availability') || 'Availability', count: files.length })}
                        <CloudSectionState loading={statusQ.loading} err={statusQ.err} empty={!files.length} t={t}
                            emptyIcon="File" emptyTitle={t('noFilesFound') || 'No files found'}>
                            <div className="cloud-table-scroll"><table className="cloud-table cloud-sync-matrix">
                                <thead><tr><th>{t('cloud.colName') || 'File'}</th><th>{t('cloud.datastores') || 'Storage'}</th><th>{t('cloud.colSize') || 'Size'}</th>
                                    {nodes.map(n => <th key={n} className="cloud-sync-node">{n}</th>)}<th className="cloud-th-actions"></th></tr></thead>
                                <tbody>{files.map((f, i) => {
                                    const key = (f.storage || '') + ':' + f.name;
                                    return (
                                        <tr className="cloud-table-row cloud-table-row-static" key={key || i}>
                                            <td className="cloud-table-mono" title={f.name}>{f.name}</td>
                                            <td>{f.storage || ' - '}</td>
                                            <td>{f.size ? cloudFmtBytes(f.size) : ' - '}</td>
                                            {nodes.map(n => {
                                                const ok = st.matrix && st.matrix[key] && st.matrix[key][n];
                                                return <td key={n} className="cloud-sync-cell"><span className={'cloud-sync-dot ' + (ok ? 'is-ok' : 'is-miss')} title={n + ': ' + (ok ? 'available' : 'missing')}>{ok ? '✓' : '✗'}</span></td>;
                                            })}
                                            <td className="cloud-td-actions" onClick={(e) => e.stopPropagation()}>
                                                <button type="button" className="cloud-btn cloud-btn-sm" disabled={busyFile === f.name || nodes.every(n => st.matrix && st.matrix[key] && st.matrix[key][n])} onClick={() => syncOne(f)}>
                                                    <Icons.RefreshCw /> {t('cloud.syncOne') || 'Sync'}
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}</tbody>
                            </table></div>
                        </CloudSectionState>
                    </div>
                </>
            );
        }

        // ── Backup SLA ────────────────────────────────────────────

        function CloudBackupSla({ clusterId, authFetch, addToast, t }) {
            const slaQ = useCloudData(`${API_URL}/clusters/${clusterId}/backup-sla`);
            const sla = slaQ.data && !slaQ.err ? slaQ.data : null;
            const [filter, setFilter] = React.useState('all');
            const [cfgH, setCfgH] = React.useState('');
            const [busy, setBusy] = React.useState(false);
            const vms = (sla && Array.isArray(sla.vms)) ? sla.vms : [];
            const sum = (sla && sla.summary) || {};
            const view = filter === 'all' ? vms : vms.filter(v => v.sla_status === filter);
            const save = async () => {
                setBusy(true);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/backup-sla/config`, {
                        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ max_age_hours: Number(cfgH) }),
                    });
                    if (r && r.ok) { addToast(t('cloud.saved') || 'Saved', 'success'); slaQ.reload(); }
                    else { const j = await r.json().catch(() => ({})); addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error'); }
                } finally { setBusy(false); }
            };
            const Tile = ({ id, label, tone }) => (
                <button type="button" className={'cloud-sla-tile' + (filter === id ? ' is-active' : '')} onClick={() => setFilter(filter === id ? 'all' : id)}>
                    <div className={'cloud-hc-badge ' + tone}>{sum[id] != null ? sum[id] : (id === 'compliance' ? ' - ' : 0)}</div>
                    <span>{label}</span>
                </button>
            );
            return (
                <>
                    <div className="cloud-toolbar">
                        <div className="cloud-toolbar-left">
                            {sla && (
                                <span style={{ display: 'inline-flex', gap: 10, alignItems: 'center' }}>
                                    <span className={'cloud-hc-badge ' + (sla.enabled ? 'is-healthy' : 'is-na')}>{sla.enabled ? (t('cloud.slaOn') || 'SLA active') : (t('cloud.slaOff') || 'SLA disabled')}</span>
                                    <span className="cloud-input" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', width: 'auto', padding: '4px 8px' }}>
                                        {t('cloud.slaMaxAge') || 'Backup age limit'}
                                        <input type="number" min="0" style={{ width: 64, background: 'transparent', border: 'none', outline: 'none', color: 'inherit' }}
                                            value={cfgH !== '' ? cfgH : (sla.max_age_hours != null ? sla.max_age_hours : '')}
                                            onChange={(e) => setCfgH(e.target.value)} /> h
                                    </span>
                                    <button type="button" className="cloud-btn cloud-btn-sm" disabled={busy || cfgH === ''} onClick={save}><Icons.Save /> {t('save') || 'Save'}</button>
                                </span>
                            )}
                        </div>
                        <div className="cloud-toolbar-right">
                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={slaQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                        </div>
                    </div>
                    <div className="cloud-stat-grid cloud-sla-tiles">
                        <Tile id="ok" label={t('cloud.slaOk') || 'OK'} tone="is-healthy" />
                        <Tile id="warning" label={t('cloud.slaWarn') || 'Warning'} tone="is-warning" />
                        <Tile id="breached" label={t('cloud.slaBreached') || 'Breached'} tone="is-critical" />
                        <Tile id="no_backup" label={t('cloud.slaNoBackup') || 'No backup'} tone="is-critical" />
                        <Tile id="disabled" label={t('cloud.slaDisabled') || 'Disabled'} tone="is-na" />
                        <div className="cloud-stat"><span className="cloud-stat-ico"><Icons.CheckCircle /></span>
                            <div>
                                <div className="cloud-stat-num">{sum.compliance_pct != null ? Math.round(sum.compliance_pct) + '%' : <span className="cloud-hc-badge is-na">{t('cloud.slaNotEvaluated') || 'NOT EVALUATED'}</span>}</div>
                                <div className="cloud-stat-lb">{t('cloud.slaCompliance') || 'compliance'}</div>
                            </div></div>
                    </div>
                    {sla && sla.enabled === false && (
                        <div className="cloud-card cloud-hc-note cloud-hc-note-warn"><Icons.Eye />
                            <span>{t('cloud.slaOffNote') || 'SLA checks are disabled - guests are not evaluated. Nothing is counted as compliant or breached.'}</span>
                        </div>
                    )}
                    <div className="cloud-card cloud-table-card">
                        {cloudHead({ icon: <Icons.Archive />, title: t('cloud.slaGuests') || 'Guests', count: view.length, right: filter !== 'all' && <button type="button" className="cloud-link-btn" onClick={() => setFilter('all')}>{t('cloud.clear') || 'Clear filter'}</button> })}
                        <CloudSectionState loading={slaQ.loading} err={slaQ.err} empty={!view.length} t={t}
                            emptyIcon="Archive" emptyTitle={t('cloud.noData') || 'No data'} emptyText={sla && sla.enabled === false ? (t('cloud.slaOffNote') || 'SLA checks are disabled - nothing is counted as compliant.') : null}>
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colId') || 'VMID'}</th><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colNode') || 'Host'}</th><th>{t('cloud.hcLastBackup') || 'Last backup'}</th><th>{t('cloud.age') || 'Age'}</th><th>{t('cloud.source') || 'Source'}</th><th>{t('cloud.colStatus') || 'Status'}</th></tr></thead>
                                <tbody>{view.map((v, i) => (
                                    <tr className="cloud-table-row cloud-table-row-static" key={(v.vmid != null ? v.vmid : i)}>
                                        <td className="cloud-table-mono">{v.vmid}</td>
                                        <td className="cloud-table-name"><span className="cloud-table-name-text">{v.name || ' - '}</span></td>
                                        <td>{v.node || ' - '}</td>
                                        <td className="cloud-table-mono cloud-cell-muted">{v.last_backup_ts ? cloudFmtTs(v.last_backup_ts) : ' - '}</td>
                                        <td>{v.age_hours != null ? (v.age_hours < 48 ? Math.round(v.age_hours) + ' h' : Math.round(v.age_hours / 24) + ' d') : ' - '}</td>
                                        <td>{v.backup_source || ' - '}</td>
                                        <td><span className={'cloud-hc-badge ' + (v.sla_status === 'ok' ? 'is-healthy' : v.sla_status === 'warning' ? 'is-warning' : v.sla_status === 'disabled' ? 'is-na' : 'is-critical')}>{v.sla_status === 'disabled' ? (t('cloud.slaNotEvaluated') || 'NOT EVALUATED') : String(v.sla_status || ' - ').toUpperCase()}</span></td>
                                    </tr>
                                ))}</tbody>
                            </table></div>
                        </CloudSectionState>
                    </div>
                </>
            );
        }

        // translate technical gap kinds into administrator-readable messages;
        // group by kind so 'no_backup × 4' reads as one finding, not four rows of noise

        function CloudInstanceList({ rows, kind, clusterId, act, onOpen, onCreate, onBlueprints, t }) {
            const safe = Array.isArray(rows) ? rows : [];
            const [query, setQuery] = React.useState('');
            const [statusFilter, setStatusFilter] = React.useState('all');
            const [checked, setChecked] = React.useState({});
            const [page, setPage] = React.useState(0);
            const [sort, setSort] = React.useState({ key: 'vmid', dir: 'asc' });

            // reset transient state when the list identity changes — kind OR cluster.
            // (without clusterId here a same-VMID guest in another cluster would inherit the selection)
            React.useEffect(() => { setChecked({}); setPage(0); }, [kind, clusterId]);

            const title = kind === 'lxc' ? (t('cloud.containers') || 'Containers') : (t('cloud.vms') || 'Virtual Machines');
            const RowIcon = kind === 'lxc' ? (Icons.Box || Icons.Container) : Icons.Server;

            const q = query.trim().toLowerCase();
            let view = safe.filter(r => r && (statusFilter === 'all' || (statusFilter === 'running' ? r.status === 'running' : r.status !== 'running')));
            if (q) view = view.filter(r => (r.name || '').toLowerCase().includes(q) || String(r.vmid != null ? r.vmid : '').includes(q) || (r.node || '').toLowerCase().includes(q));
            view = view.slice().sort((a, b) => {
                const k = sort.key; let av = a[k], bv = b[k];
                if (k === 'cpu') { av = cloudCpuPct(a); bv = cloudCpuPct(b); }
                if (k === 'mem') { av = cloudMemPct(a); bv = cloudMemPct(b); }
                if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv || '').toLowerCase(); }
                if (av == null) av = 0; if (bv == null) bv = 0;
                const r = av < bv ? -1 : av > bv ? 1 : 0;
                return sort.dir === 'asc' ? r : -r;
            });

            const total = view.length;
            // clamp the page so a shrinking list (poll/bulk/cluster switch) can't strand
            // the user on a blank page with no pager to climb back. -- NS
            const maxPage = Math.max(0, Math.ceil(total / CLOUD_PAGE_SIZE) - 1);
            const safePage = Math.min(page, maxPage);
            React.useEffect(() => { if (page > maxPage) setPage(maxPage); }, [maxPage, page]);
            const pageRows = view.slice(safePage * CLOUD_PAGE_SIZE, (safePage + 1) * CLOUD_PAGE_SIZE);
            // scope the key by cluster so a stale VMID can't pre-check a same-id guest elsewhere
            const rowKey = (r) => `${clusterId || r._clusterId || ''}-${r.vmid != null ? r.vmid : r.name}`;
            const selectedRows = view.filter(r => checked[rowKey(r)]);  // only act on what's visible
            const selCount = selectedRows.length;
            const pageAllOn = pageRows.length > 0 && pageRows.every(r => checked[rowKey(r)]);

            const toggleAllPage = () => {
                setChecked(prev => {
                    const n = Object.assign({}, prev);
                    if (pageAllOn) pageRows.forEach(r => { delete n[rowKey(r)]; });
                    else pageRows.forEach(r => { n[rowKey(r)] = true; });
                    return n;
                });
            };
            const toggleOne = (k) => setChecked(prev => { const n = Object.assign({}, prev); if (n[k]) delete n[k]; else n[k] = true; return n; });
            const setSortKey = (k) => setSort(s => s.key === k ? { key: k, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: 'asc' });
            const SortTh = ({ k, children, cls }) => (
                <th className={cls} onClick={() => setSortKey(k)} style={{ cursor: 'pointer' }}>
                    {children}{sort.key === k && <span className="cloud-sort-arrow">{sort.dir === 'asc' ? ' ▲' : ' ▼'}</span>}
                </th>
            );

            // LW Oct 2026 - one dialog for the selection: one confirmation, a few requests at a
            // time and a line per guest, instead of a prompt and a request per row at once
            const bulk = (action) => act.has('bulkGuests') ? act.bulkGuests(selectedRows, action)
                : selectedRows.forEach(r => act.vmAction(r, action));
            const canCreate = act.has('createVm');
            const canPower = act.has('vmAction');

            return (
                <div className="cloud-body">
                    <CloudPageHeader title={title} sub={`${safe.length} ${kind === 'lxc' ? (t('cloud.containersUnit') || 'containers') : (t('cloud.vmsUnit') || 'virtual machines')}`}>
                        {/* LW Nov 2026 (#1220) - to the blueprints of this cluster */}
                        {onBlueprints && kind !== 'lxc' && (
                            <button type="button" className="cloud-btn" onClick={onBlueprints} data-bp-nav="cloud-vms">
                                <Icons.Template /> {t('crBpNavDeploy')}
                            </button>
                        )}
                        {canCreate && (
                            <button type="button" className="cloud-btn cloud-btn-primary" onClick={() => onCreate(kind === 'lxc' ? 'lxc' : 'qemu')}>
                                <Icons.Plus /> {kind === 'lxc' ? (t('newContainer') || 'New Container') : (t('newVm') || 'New VM')}
                            </button>
                        )}
                    </CloudPageHeader>

                    <div className="cloud-card cloud-table-card">
                        <div className="cloud-toolbar">
                            <div className="cloud-toolbar-left">
                                {selCount > 0 && canPower ? (
                                    <div className="cloud-bulkbar">
                                        <span className="cloud-sel-note">{selCount} {t('cloud.selected') || 'selected'}</span>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('start')}><Icons.Play /> {t('start') || 'Start'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('shutdown')}><Icons.Power /> {t('shutdown') || 'Shutdown'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('reboot')}><Icons.RotateCw /> {t('reboot') || 'Reboot'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm cloud-btn-danger" onClick={() => bulk('stop')}><Icons.Square /> {t('stop') || 'Stop'}</button>
                                        {act.has('bulkGuests') && (<>
                                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('snapshot')}><Icons.Camera /> {t('snapshot')}</button>
                                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('tags')}><Icons.Tag /> {t('tags')}</button>
                                        </>)}
                                        {/* LW Oct 2026 (#952) - one dialog, one at a time unless picked otherwise */}
                                        {act.has('bulkMigrate') && (
                                            <button type="button" className="cloud-btn cloud-btn-sm" data-bulk="migrate" onClick={() => act.bulkMigrate(selectedRows)}><Icons.ArrowRight /> {t('migrate')}</button>
                                        )}
                                        <button type="button" className="cloud-sel-clear" onClick={() => setChecked({})}>{t('cloud.clear') || 'Clear'}</button>
                                    </div>
                                ) : (
                                    <>
                                        <span className="cloud-count-chip">{total}</span>
                                        <div className="cloud-segment">
                                            {['all', 'running', 'stopped'].map(s => (
                                                <button type="button" key={s} className={'cloud-segment-btn' + (statusFilter === s ? ' is-active' : '')} onClick={() => { setStatusFilter(s); setPage(0); }}>
                                                    {s === 'all' ? (t('cloud.all') || 'All') : s === 'running' ? (t('cloud.running') || 'Running') : (t('cloud.stopped') || 'Stopped')}
                                                </button>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                            <div className="cloud-toolbar-right">
                                <CloudSearch value={query} onChange={(v) => { setQuery(v); setPage(0); }} placeholder={t('cloud.searchGuests') || 'Search name, ID, host…'} />
                            </div>
                        </div>

                        {(q || statusFilter !== 'all') && (
                            <div className="cloud-filterchips">
                                {statusFilter !== 'all' && (
                                    <span className="cloud-filterchip">
                                        {(t('cloud.colStatus') || 'Status')}: {statusFilter === 'running' ? (t('cloud.running') || 'Running') : (t('cloud.stopped') || 'Stopped')}
                                        <button type="button" onClick={() => { setStatusFilter('all'); setPage(0); }} aria-label={t('cloud.removeFilter') || 'Remove filter'}><Icons.X /></button>
                                    </span>
                                )}
                                {q && (
                                    <span className="cloud-filterchip">
                                        {(t('cloud.search') || 'Search')}: “{query}”
                                        <button type="button" onClick={() => { setQuery(''); setPage(0); }} aria-label={t('cloud.removeFilter') || 'Remove filter'}><Icons.X /></button>
                                    </span>
                                )}
                                <button type="button" className="cloud-clearfilters" onClick={() => { setStatusFilter('all'); setQuery(''); setPage(0); }}>{t('cloud.clearFilters') || 'Clear all filters'}</button>
                            </div>
                        )}

                        {total === 0 ? (
                            <CloudEmpty
                                icon={kind === 'lxc' ? 'Box' : 'Server'}
                                title={(q || statusFilter !== 'all') ? (t('cloud.noMatch') || 'No matches') : (kind === 'lxc' ? (t('cloud.noContainers') || 'No containers yet') : (t('cloud.noVms') || 'No virtual machines yet'))}
                                text={(q || statusFilter !== 'all') ? (t('cloud.adjustFilters') || 'Try adjusting your search or filters.') : null}
                                action={!(q || statusFilter !== 'all') && canCreate ? (
                                    <button type="button" className="cloud-btn cloud-btn-primary" onClick={() => onCreate(kind === 'lxc' ? 'lxc' : 'qemu')}>
                                        <Icons.Plus /> {kind === 'lxc' ? (t('newContainer') || 'New Container') : (t('newVm') || 'New VM')}
                                    </button>
                                ) : null}
                            />
                        ) : (
                            <div className="cloud-table-scroll">
                                <table className="cloud-table cloud-table-selectable">
                                    <thead>
                                        <tr>
                                            <th className="cloud-th-check"><input type="checkbox" checked={pageAllOn} onChange={toggleAllPage} aria-label={t('cloud.selectPage') || 'Select page'} /></th>
                                            <SortTh k="name">{t('cloud.colName') || 'Name'}</SortTh>
                                            <SortTh k="vmid">{t('cloud.colId') || 'ID'}</SortTh>
                                            <SortTh k="status">{t('cloud.colStatus') || 'Status'}</SortTh>
                                            <SortTh k="node">{t('cloud.colNode') || 'Host'}</SortTh>
                                            <SortTh k="cpu">{t('cloud.colCpu') || 'CPU'}</SortTh>
                                            <SortTh k="mem">{t('cloud.colRam') || 'RAM'}</SortTh>
                                            <th className="cloud-th-actions"></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {pageRows.map((r) => {
                                            if (!r) return null;
                                            const id = r.vmid != null ? r.vmid : r.name;
                                            const k = rowKey(r);
                                            const isChecked = !!checked[k];
                                            return (
                                                <tr key={k} className={'cloud-table-row' + (isChecked ? ' cloud-table-row-checked' : '')} onClick={() => onOpen(r)}>
                                                    <td className="cloud-td-check" onClick={(e) => { e.stopPropagation(); toggleOne(k); }}>
                                                        <input type="checkbox" checked={isChecked} onChange={() => {}} tabIndex={-1} aria-label={t('cloud.selectRow') || 'Select'} />
                                                    </td>
                                                    <td>
                                                        <span className="cloud-table-name">
                                                            <span className="cloud-table-name-icon"><RowIcon /></span>
                                                            <span className="cloud-table-name-text">{r.name || ('guest-' + id)}</span>
                                                        </span>
                                                    </td>
                                                    <td className="cloud-table-mono">{r.vmid != null ? r.vmid : '—'}</td>
                                                    <td><CloudStatusChip status={r.status} /></td>
                                                    <td>{r.node || '—'}</td>
                                                    <td><CloudMiniMeter pct={cloudCpuPct(r)} color="var(--cloud-accent)" /></td>
                                                    <td><CloudMiniMeter pct={cloudMemPct(r)} color="#a855f7" /></td>
                                                    <td className="cloud-td-actions" onClick={(e) => e.stopPropagation()}>
                                                        <CloudActionMenu items={cloudVmActionItems(r, act, t)} />
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        <div className="cloud-table-foot">
                            <CloudPager page={safePage} pageSize={CLOUD_PAGE_SIZE} total={total} onPage={setPage} />
                        </div>
                    </div>
                </div>
            );
        }

        // label/value row + titled panel — module-level so they don't remount each render
        function CloudKVRow({ label, value }) {
            return <div className="cloud-kv-row"><span className="cloud-kv-key">{label}</span><span className="cloud-kv-val">{(value === 0 || value) ? value : '—'}</span></div>;
        }
        function CloudKVPanel({ title, children }) {
            return <div className="cloud-kv-panel"><div className="cloud-kv-title">{title}</div>{children}</div>;
        }

        // ── instance detail (full view with tabs) ──────────────────
        function cloudFmtRate(v) {
            const n = Number(v) || 0;
            if (n >= 1024 ** 3) return (n / 1024 ** 3).toFixed(1) + ' GiB/s';
            if (n >= 1024 ** 2) return (n / 1024 ** 2).toFixed(1) + ' MiB/s';
            if (n >= 1024) return (n / 1024).toFixed(1) + ' KiB/s';
            return Math.round(n) + ' B/s';
        }

        function cloudFmtTs(epoch) {
            const n = Number(epoch);
            if (!n || !isFinite(n)) return null;
            const d = new Date(n * 1000);
            return d.toLocaleString();
        }

        // one metric chart + its stats row (current/avg/min/max, last update).
        // Colors are hex, not CSS vars - a canvas cannot resolve var(--…).
        // formatValue + label flow into LineChart so the y-axis AND the tooltip
        // speak the metric's unit (a missing label made tooltips say "undefined").

        const CLOUD_HC = {
            healthy:  { cls: 'is-healthy',  label: 'HEALTHY' },
            warning:  { cls: 'is-warning',  label: 'WARNING' },
            critical: { cls: 'is-critical', label: 'CRITICAL' },
            unknown:  { cls: 'is-unknown',  label: 'UNKNOWN' },
            na:       { cls: 'is-na',       label: 'N/A' },
        };

        const CLOUD_HC_ORDER = { critical: 0, warning: 1, healthy: 2, unknown: 3, na: 4 };

        function cloudHcMeaning(id, t) {
            const m = {
                backup: t('cloud.hcMeaningBackup') || 'Proof: a current, restorable backup exists.',
                sla: t('cloud.hcMeaningSla') || 'Proof: backups arrive within the defined recovery objective.',
                restore: t('cloud.hcMeaningRestore') || 'Proof: a restore has actually been tested and timed.',
                agent: t('cloud.hcMeaningAgent') || 'In-guest facts (IPs, filesystems, clean shutdowns).',
                ha: t('cloud.hcMeaningHa') || 'Automatic restart on node failure.',
                migrate: t('cloud.hcMeaningMigrate') || 'Readiness to move this guest to another node.',
                audit: t('cloud.hcMeaningAudit') || 'Traceable change history, verified installation-wide.',
            };
            return m[id] || null;
        }

        // overview right rail: collapsed = one line, expanded = meaning/impact/action/proof

        function CloudHcBadge({ state }) {
            const tone = CLOUD_HC[state] || CLOUD_HC.unknown;
            return <span className={'cloud-hc-badge ' + tone.cls}>{tone.label}</span>;
        }
        // what each check PROVES - one sentence per id, shown in the rail and the
        // full state tab so a badge alone never has to carry the meaning

        function CloudHcRow({ title, state, desc, checked, action, impact, meaning, children }) {
            const tone = CLOUD_HC[state] || CLOUD_HC.unknown;
            return (
                <div className={'cloud-hc-row ' + tone.cls}>
                    <div className="cloud-hc-head">
                        <span className="cloud-hc-title">{title}</span>
                        <CloudHcBadge state={state} />
                    </div>
                    {meaning && <div className="cloud-hc-meaning">{meaning}</div>}
                    {desc && <div className="cloud-hc-desc">{desc}</div>}
                    {impact && <div className={'cloud-hc-impact' + (state === 'critical' ? ' is-critical' : '')}>{impact}</div>}
                    {checked && <div className="cloud-hc-checked">{checked}</div>}
                    {children}
                    {action && <div className="cloud-hc-action">{action}</div>}
                </div>
            );
        }

        // bytes/s → readable rate (metrics come back as bytes per second)

        function CloudHcRailRow({ row, open, onToggle, t, meaning, extraAction }) {
            const tone = CLOUD_HC[row.state] || CLOUD_HC.unknown;
            return (
                <div className={'cloud-hc-rail-row ' + tone.cls + (open ? ' is-open' : '')}>
                    <button type="button" className="cloud-hc-rail-head" onClick={onToggle} aria-expanded={open}>
                        <span className={'cloud-hc-rail-dot ' + tone.cls}></span>
                        <span className="cloud-hc-rail-name">{row.title}</span>
                        <span className="cloud-hc-rail-find">{row.desc}</span>
                        <CloudHcBadge state={row.state} />
                        <span className="cloud-hc-rail-chev">{open ? '▾' : '▸'}</span>
                    </button>
                    {open && (
                        <div className="cloud-hc-rail-body">
                            {meaning && <div className="cloud-hc-rail-meaning">{meaning}</div>}
                            {row.impact && <div className={'cloud-hc-impact' + (row.state === 'critical' ? ' is-critical' : '')}>{row.impact}</div>}
                            {(row.checked || extraAction) && (
                                <div className="cloud-hc-rail-foot">
                                    {row.checked && <span className="cloud-hc-checked">{t('cloud.hcLastProof') || 'Last proof'}: {row.checked}</span>}
                                    {extraAction}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            );
        }

        // one resource tile for the overview panel: value, meter, optional real trend

        function CloudResTile({ label, value, sub, pct, spark, sparkColor, sparkTitle, foot }) {
            return (
                <div className="cloud-res-tile">
                    <div className="cloud-res-tile-top">
                        <span className="cloud-res-tile-label">{label}</span>
                        <span className="cloud-res-tile-value">{value}</span>
                    </div>
                    {pct != null && (
                        <div className="cloud-meter cloud-res-tile-meter"><div style={{ width: Math.min(100, pct) + '%', background: cloudThresholdColor(pct) }} /></div>
                    )}
                    <div className="cloud-res-tile-bottom">
                        {sub && <span className="cloud-res-tile-sub">{sub}</span>}
                        {spark && <span className="cloud-res-tile-spark" title={sparkTitle}><Sparkline data={spark} color={sparkColor} width={150} height={34} /></span>}
                        {foot && !spark && <span className="cloud-res-tile-sub">{foot}</span>}
                    </div>
                </div>
            );
        }

        function CloudMetricChart({ title, data, timestamps, fmt, color, sub }) {
            const clean = (data || []).map(v => (v == null || !isFinite(Number(v)) ? null : Number(v)));
            const vals = clean.filter(v => v != null);
            const has = vals.length > 0;
            const cur = has ? vals[vals.length - 1] : null;
            const avg = has ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
            const min = has ? Math.min(...vals) : null;
            const max = has ? Math.max(...vals) : null;
            const lastTs = cloudFmtTs((timestamps || []).filter(Boolean).slice(-1)[0]);
            const fmtV = fmt || (v => String(Math.round(v * 100) / 100));
            return (
                <div className="cloud-card cloud-chart-card">
                    <div className="cloud-chart-head">
                        <span className="cloud-chart-title">{title}{sub ? <span className="cloud-chart-sub"> · {sub}</span> : null}</span>
                        {has ? (
                            <span className="cloud-chart-stats">
                                <span>cur <b>{fmtV(cur)}</b></span>
                                <span>ø <b>{fmtV(avg)}</b></span>
                                <span>min <b>{fmtV(min)}</b></span>
                                <span>max <b>{fmtV(max)}</b></span>
                            </span>
                        ) : <span className="cloud-chart-stats cloud-cell-muted">no data</span>}
                    </div>
                    {has ? (
                        <>
                            <LineChart label={title} data={clean} timestamps={timestamps} color={color || '#22d3ee'} formatValue={fmtV} unit=" " markGaps />
                            {lastTs && <div className="cloud-chart-upd">{lastTs}</div>}
                        </>
                    ) : (
                        <div className="cloud-chart-empty">{timestamps && timestamps.length ? 'No samples in this window.' : 'No history recorded for this guest.'}</div>
                    )}
                </div>
            );
        }

        // Betriebszustand: every row needs real evidence - see the phase brief.
        // Anything without a source renders unknown/na, never healthy.

        function cloudGuestHealthRows({ r, isCt, cfg, guest, backupStatus, recovery, ha, migrate, t, onMigrateCheck, migrateChecking, compact }) {
            const rows = [];
            const ageTxt = (h) => (h == null ? null : (h < 48 ? Math.round(h) + ' h ago' : Math.round(h / 24) + ' d ago'));

            // Backup (from the cluster's per-VM backup status)
            const bs = backupStatus && backupStatus[r.vmid];
            if (!backupStatus) {
                rows.push({ id: 'backup', title: t('cloud.hcBackup') || 'Backup', state: 'unknown', desc: t('cloud.hcNoData') || 'Backup status not available.' });
            } else if (!bs) {
                rows.push({ id: 'backup', title: t('cloud.hcBackup') || 'Backup', state: 'unknown', desc: t('cloud.hcNoEntry') || 'No backup record for this guest.', link: 'backups' });
            } else {
                const st = bs.status === 'ok' ? 'healthy' : (bs.status === 'warn' ? 'warning' : (bs.status === 'no-backup' ? 'critical' : 'warning'));
                const bits = [];
                if (bs.last_backup_age_hours != null) bits.push((t('cloud.hcLastBackup') || 'Last backup') + ': ' + (ageTxt(bs.last_backup_age_hours) || ' - '));
                if (bs.count_30d != null) bits.push('30d: ' + bs.count_30d);
                if (bs.encrypted) bits.push(t('cloud.hcEncrypted') || 'encrypted');
                if (bs.last_verify_age_hours != null) bits.push((t('cloud.hcVerified') || 'verified') + ' ' + ageTxt(bs.last_verify_age_hours));
                rows.push({ id: 'backup', title: t('cloud.hcBackup') || 'Backup', state: st, desc: bits.join(' · '), checked: bs.last_backup_ts ? cloudFmtTs(bs.last_backup_ts) : null, link: 'backups',
                                            impact: st === 'critical' ? (t('cloud.hcImpBackupC') || 'No current backup - data loss on failure.') : st === 'warning' ? (t('cloud.hcImpBackupW') || 'Backup protection degraded.') : null });
            }

            // Backup SLA (recovery report carries rpo_state per guest)
            const g = recovery && recovery.guest;
            if (recovery && g) {
                const m = { ok: 'healthy', warning: 'warning', breached: 'critical', no_backup: 'critical', disabled: 'na', unknown: 'unknown' };
                const bits = [];
                if (g.sla_hours != null) bits.push('SLA ≤ ' + g.sla_hours + ' h');
                if (g.newest_backup_age_hours != null) bits.push((t('cloud.hcNewest') || 'newest backup') + ' ' + ageTxt(g.newest_backup_age_hours));
                if (g.backup_count != null) bits.push(g.backup_count + ' ' + (t('cloud.hcBackups') || 'backups'));
                rows.push({ id: 'sla', title: t('cloud.hcSla') || 'Backup SLA', state: m[g.rpo_state] || 'unknown', desc: bits.join(' · '), checked: g.newest_backup_at ? cloudFmtTs(g.newest_backup_at) : null, link: 'backups',
                                            impact: (g.rpo_state === 'breached' || g.rpo_state === 'no_backup') ? (t('cloud.hcImpSlaC') || 'Defined recovery objective is not met.') : g.rpo_state === 'warning' ? (t('cloud.hcImpSlaW') || 'Recovery objective at risk.') : null });
            } else {
                rows.push({ id: 'sla', title: t('cloud.hcSla') || 'Backup SLA', state: 'unknown', desc: t('cloud.hcNoRecoveryData') || 'SLA evaluation not available.' });
            }

            // Restore tests (documented recovery evidence)
            if (recovery && g) {
                const m = { ok: 'healthy', stale: 'warning', rto_missed: 'warning', failing: 'critical', never: 'warning' };
                const bits = [];
                if (g.last_success_at) bits.push((t('cloud.hcLastTest') || 'last success') + ' ' + cloudFmtTs(g.last_success_at));
                if (g.measured_seconds != null && g.rto_seconds != null) bits.push('RTO ' + g.measured_seconds + '/' + g.rto_seconds + 's');
                if (g.state === 'never') bits.push(t('cloud.hcNeverTested') || 'No restore test documented.');
                if (g.last_failure_at) bits.push((t('cloud.hcLastFailure') || 'last failure') + ' ' + cloudFmtTs(g.last_failure_at));
                rows.push({ id: 'restore', title: t('cloud.hcRestore') || 'Restore test', state: m[g.state] || 'unknown', desc: bits.join(' · '), checked: g.last_test_at ? cloudFmtTs(g.last_test_at) : null, link: 'backups',
                                            impact: g.state === 'failing' ? (t('cloud.hcImpRestC') || 'Restore failed - backups may not be usable.') : g.state === 'never' || g.state === 'stale' ? (t('cloud.hcImpRestW') || 'Restore capability is unproven.') : null });
            } else {
                rows.push({ id: 'restore', title: t('cloud.hcRestore') || 'Restore test', state: 'unknown', desc: t('cloud.hcNoRecoveryData') || 'SLA evaluation not available.' });
            }

            // Guest agent (qemu only - an LXC guest has no qemu-guest-agent by design)
            if (isCt) {
                rows.push({ id: 'agent', title: t('cloud.hcAgent') || 'Guest agent', state: 'na', desc: t('cloud.hcAgentLxc') || 'Not applicable: LXC guests report without a QEMU guest agent.' });
            } else if (!cfg && !guest) {
                rows.push({ id: 'agent', title: t('cloud.hcAgent') || 'Guest agent', state: 'unknown', desc: t('cloud.hcNoData') || 'Guest data not available.' });
            } else {
                const enabled = !!(cfg && (cfg.options && cfg.options.agent || (cfg.raw && cfg.raw.agent)));
                if (guest && guest.agent_running) {
                    rows.push({ id: 'agent', title: t('cloud.hcAgent') || 'Guest agent', state: 'healthy', desc: (guest.os_pretty_name || 'agent') + ' · ' + (t('cloud.hcAgentReachable') || 'reachable, reporting data') });
                } else if (enabled) {
                    rows.push({ id: 'agent', title: t('cloud.hcAgent') || 'Guest agent', state: guest ? 'warning' : 'unknown', desc: guest ? (t('cloud.hcAgentEnabledNotRunning') || 'Enabled in the config but not reachable (guest off or agent not installed).') : (t('cloud.hcNoData') || 'Guest data not available.'), impact: guest ? (t('cloud.hcImpAgent') || 'No in-guest facts (IPs, filesystems); some actions are limited.') : null });
                } else {
                    rows.push({ id: 'agent', title: t('cloud.hcAgent') || 'Guest agent', state: 'na', desc: t('cloud.hcAgentDisabled') || 'Not enabled in the VM configuration.' });
                }
            }

            // Proxmox HA (guest HA resources; unconfigured is a valid na)
            if (!ha) {
                rows.push({ id: 'ha', title: 'HA', state: 'unknown', desc: t('cloud.hcNoData') || 'Guest data not available.' });
            } else {
                const mine = ha.find(h => h && h.sid === (isCt ? 'ct:' : 'vm:') + r.vmid);
                if (!mine) {
                    rows.push({ id: 'ha', title: 'HA', state: 'na', desc: t('cloud.hcHaNone') || 'Not configured for Proxmox HA.' });
                } else {
                    const st = (mine.state === 'started' || mine.state === 'stopped') ? 'healthy'
                        : (mine.state === 'ignored' || mine.state === 'disabled') ? 'na'
                        : (mine.state === 'error') ? 'critical' : 'warning';
                    const haImpact = mine.state === 'error' ? (t('cloud.hcImpHaC') || 'No automatic restart on node failure.') : (st === 'warning') ? (t('cloud.hcImpHaW') || 'HA is reconfiguring - protection temporarily reduced.') : null;
                    const bits = [mine.state];
                    if (mine.group) bits.push((t('cloud.hcHaGroup') || 'group') + ' ' + mine.group);
                    if (mine.node) bits.push('@' + mine.node);
                    rows.push({ id: 'ha', title: 'HA', state: st, desc: bits.join(' · '), impact: haImpact });
                }
            }

            // Migration readiness - only judged when a check actually ran
            if (!migrate) {
                rows.push({
                    id: 'migrate', title: t('cloud.hcMigrate') || 'Migration', state: 'unknown',
                    desc: t('cloud.hcMigrateIdle') || 'Not checked yet.',
                    action: compact ? null : (
                    <button type="button" className="cloud-btn cloud-btn-sm" onClick={onMigrateCheck} disabled={migrateChecking}>
                        <Icons.ArrowRight /> {migrateChecking ? (t('cloud.hcChecking') || 'Checking…') : (t('cloud.hcCheckNow') || 'Run check')}
                    </button>),
                });
            } else if (migrate.error) {
                rows.push({ id: 'migrate', title: t('cloud.hcMigrate') || 'Migration', state: 'unknown', desc: migrate.error, action: compact ? null : <button type="button" className="cloud-btn cloud-btn-sm" onClick={onMigrateCheck}><Icons.ArrowRight /> {t('cloud.hcCheckNow') || 'Run check'}</button> });
            } else if (migrate.supported === false) {
                rows.push({ id: 'migrate', title: t('cloud.hcMigrate') || 'Migration', state: 'critical', desc: t('cloud.hcMigrateUnsupported') || 'Migration not supported for this guest.' });
            } else {
                const snapN = Number(migrate.snapshot_count) || 0;
                rows.push({
                    id: 'migrate', title: t('cloud.hcMigrate') || 'Migration',
                    state: snapN > 0 ? 'warning' : 'healthy',
                    desc: snapN > 0
                        ? (t('cloud.hcMigrateSnaps') || 'Possible, but {n} snapshot(s) restrict online migration.').replace('{n}', snapN)
                        : (t('cloud.hcMigrateOk') || 'No blocking conditions found.'),
                    checked: t('cloud.hcMigrateCheckedNow') || 'just checked',
                    impact: snapN > 0 ? (t('cloud.hcImpMigrate') || 'Online migration may not be possible.') : null,
                });
            }

            // Audit chain integrity is installation-wide; there is no per-guest
            // proof, so this stays honestly n/a instead of green.
            rows.push({ id: 'audit', title: t('cloud.hcAudit') || 'Audit integrity', state: 'na', desc: t('cloud.hcAuditNa') || 'Verified installation-wide in the audit log, not per guest.' });

            rows.sort((a, b) => (CLOUD_HC_ORDER[a.state] ?? 9) - (CLOUD_HC_ORDER[b.state] ?? 9));
            return rows;
        }

        function CloudInstanceDetail({ resource, act, onBack, t, authFetch, clusterName, holdsPerm, addToast }) {
            const [tab, setTab] = React.useState('overview');
            const [protSub, setProtSub] = React.useState('snapshots');   // Schutz-Tab: Snapshots | Backups | Replication
            const [hcOpen, setHcOpen] = React.useState({});   // overview rail: which rows are expanded
            React.useEffect(() => { setTab('overview'); setProtSub('snapshots'); setMigrate(null); }, [resource && resource.vmid, resource && resource._clusterId]);
            const [migrate, setMigrate] = React.useState(null);
            const [migrChecking, setMigrChecking] = React.useState(false);
            if (!resource) return null;
            const r = resource;
            const isCt = r.type === 'lxc';
            const running = r.status === 'running';
            const cpuP = cloudCpuPct(r);
            const memP = cloudMemPct(r);
            const memMax = Number(r.maxmem) || 0, memUse = Number(r.mem) || 0;
            const diskMax = Number(r.maxdisk) || 0, diskUse = Number(r.disk) || 0;
            const tags = cloudTagList(r.tags);
            const can = (p) => !holdsPerm || !!holdsPerm(p);

            const cid = r._clusterId;
            const base = (authFetch && cid != null && r.node) ? `${API_URL}/clusters/${cid}/vms/${encodeURIComponent(r.node)}/${r.type}/${r.vmid}` : null;

            // ── live data, lazy per tab. A null url means "not on this tab". ──
            const cfgQ = useCloudApi(authFetch, base ? `${base}/config` : null, [base]);
            const guestQ = useCloudApi(authFetch, base ? `${base}/guest-info` : null, [base]);
            const bsQ = useCloudApi(authFetch, (tab === 'health' || (tab === 'protection' && protSub === 'backups') || tab === 'overview') && base ? `${API_URL}/clusters/${cid}/vms-backup-status` : null, [base, tab]);
            const recQ = useCloudApi(authFetch, (tab === 'health' || tab === 'overview') && base ? `${API_URL}/clusters/${cid}/recovery-report/${r.vmid}` : null, [base, tab]);
            const replQ = useCloudApi(authFetch, tab === 'protection' && protSub === 'replication' && base ? `${API_URL}/clusters/${cid}/replication?vmid=${r.vmid}` : null, [base, tab]);
            // pending config changes (apply on reboot) - the honest "needs restart" source
            const pendQ = useCloudApi(authFetch, ['hardware', 'config', 'disks', 'network'].includes(tab) && base ? `${base}/pending` : null, [base, tab]);
            const haQ = useCloudApi(authFetch, (tab === 'health' || tab === 'overview') && base ? `${API_URL}/clusters/${cid}/proxmox-ha/resources` : null, [base, tab]);
            const [tf, setTf] = React.useState('hour');
            const rrdQ = useCloudApi(authFetch, tab === 'monitor' && base ? `${base}/rrd/${tf}` : null, [base, tab, tf]);
            // Design-Sprint: live hour trend for the overview resource card (same source as Monitoring)
            const sparkQ = useCloudApi(authFetch, tab === 'overview' && base ? `${base}/rrd/hour` : null, [base, tab]);
            const snapQ = useCloudApi(authFetch, tab === 'protection' && protSub === 'snapshots' && base ? `${base}/snapshots` : null, [base, tab, protSub]);
            const bakQ = useCloudApi(authFetch, tab === 'protection' && protSub === 'backups' && base ? `${base}/backups` : null, [base, tab, protSub]);
            const dsQ = useCloudApi(authFetch, ((tab === 'protection' && protSub === 'backups') || tab === 'disks') && base ? `${API_URL}/clusters/${cid}/datastores` : null, [base, tab]);
            const taskQ = useCloudApi(authFetch, (tab === 'tasks' || tab === 'overview') && base ? `${API_URL}/clusters/${cid}/nodes/${encodeURIComponent(r.node)}/tasks?vmid=${r.vmid}&limit=200` : null, [base, tab]);

            const runMigrateCheck = async () => {
                if (!base || !authFetch) return;
                setMigrChecking(true);
                try {
                    const resp = await authFetch(`${base}/migrate-check`);
                    if (resp && resp.ok) setMigrate(await resp.json().catch(() => ({})));
                    else setMigrate({ error: resp && resp.status === 403 ? 'Permission denied' : 'HTTP ' + (resp ? resp.status : 0) });
                } catch (e) { setMigrate({ error: String((e && e.message) || e) }); }
                setMigrChecking(false);
            };

            // console preview: real screendump via the API, honest when absent
            const [shot, setShot] = React.useState({ state: 'idle' });
            React.useEffect(() => {
                let alive = true; let url = null;
                if (tab !== 'overview' || isCt || !running || !base || !authFetch) { setShot({ state: 'idle' }); return () => { alive = false; }; }
                setShot({ state: 'loading' });
                authFetch(`${base}/screenshot?fresh=1`)
                    .then(async resp => {
                        if (!alive) return;
                        if (resp && resp.ok) { const blob = await resp.blob(); url = URL.createObjectURL(blob); if (alive) setShot({ state: 'ok', url }); }
                        else if (alive) setShot({ state: 'err' });
                    })
                    .catch(() => { if (alive) setShot({ state: 'err' }); });
                return () => { alive = false; if (url) URL.revokeObjectURL(url); };
            }, [tab, base, running, isCt]);

            // snapshot actions (confirm → API → toast), permissions enforced server-side too
            const snapAct = async (snap, what) => {
                const q = what === 'rollback'
                    ? (t('cloud.snapRollbackQ') || 'Roll the guest back to snapshot')
                    : (t('cloud.snapDeleteQ') || 'Permanently delete snapshot');
                if (!window.confirm(`${q} "${snap.name}"?`)) return;
                const resp = await authFetch(`${base}/snapshots/${encodeURIComponent(snap.name)}`, { method: what === 'rollback' ? 'POST' : 'DELETE' });
                const j = resp ? await resp.json().catch(() => ({})) : {};
                if (resp && resp.ok) { addToast && addToast(j.message || (t('cloud.taskStarted') || 'Task started'), 'success'); snapQ.reload(); }
                else addToast && addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
            };

            // backup create (real vzdump start) + restore wizard + delete
            const [bForm, setBForm] = React.useState({ storage: '', mode: 'snapshot', notes: '' });
            const [bBusy, setBBusy] = React.useState(false);
            const [wiz, setWiz] = React.useState(null);
            const backupStorages = React.useMemo(() => {
                const d = dsQ.data; if (!d) return [];
                const out = [];
                const shared = Array.isArray(d.shared) ? d.shared : Object.values(d.shared || {});
                shared.forEach(s => { if (s && String(s.content || '').includes('backup')) out.push(s.storage || s.name); });
                const local = d.local || {};
                Object.keys(local).forEach(n => (Array.isArray(local[n]) ? local[n] : []).forEach(s => { if (s && String(s.content || '').includes('backup')) out.push((s.storage || s.name) + ' (' + n + ')'); }));
                return out.filter(Boolean);
            }, [dsQ.data]);
            const backupAbsStorage = (pick) => String(pick || '').split(' (')[0];
            const createBackup = async () => {
                if (!bForm.storage) return;
                setBBusy(true);
                try {
                    const resp = await authFetch(`${base}/backups/create`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ storage: backupAbsStorage(bForm.storage), mode: bForm.mode, notes: bForm.notes || '' }),
                    });
                    const j = resp ? await resp.json().catch(() => ({})) : {};
                    if (resp && resp.ok) { addToast && addToast(t('cloud.taskStarted') || 'Task started', 'success'); bakQ.reload(); setBForm(f => ({ ...f, notes: '' })); }
                    else addToast && addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
                } finally { setBBusy(false); }
            };
            const delBackup = async (b) => {
                if (!window.confirm((t('cloud.bakDeleteQ') || 'Permanently delete backup') + ' ' + (b.filename || b.volid) + '?')) return;
                const resp = await authFetch(`${base}/backups/${encodeURIComponent(b.volid)}`, { method: 'DELETE' });
                const j = resp ? await resp.json().catch(() => ({})) : {};
                if (resp && resp.ok) { addToast && addToast(t('cloud.taskStarted') || 'Task started', 'success'); bakQ.reload(); }
                else addToast && addToast(j.error || (t('cloud.actionFailed') || 'Action failed'), 'error');
            };

            // datastore lookup (type/health/usage for the storage tab)
            const dsFind = (name) => {
                const d = dsQ.data; if (!d || !name) return null;
                const shared = Array.isArray(d.shared) ? d.shared : Object.values(d.shared || {});
                let hit = shared.find(x => x && (x.storage === name || x.name === name));
                if (hit) return hit;
                const local = d.local || {};
                for (const k of Object.keys(local)) {
                    hit = (Array.isArray(local[k]) ? local[k] : []).find(x => x && x.storage === name);
                    if (hit) return hit;
                }
                return null;
            };

            const cfg = cfgQ.data;
            const hw = (cfg && cfg.hardware) || {};
            const opts = (cfg && cfg.options) || {};
            const disks = (cfg && cfg.disks) || [];
            const nets = (cfg && cfg.networks) || [];
            const raw = (cfg && cfg.raw) || {};
            const guest = guestQ.data && !guestQ.error ? guestQ.data : null;
            // the endpoint answers a list; index it by vmid once, an array
            // subscript would read the wrong guest's posture
            const bsMap = Array.isArray(bsQ.data)
                ? Object.fromEntries(bsQ.data.map(b => [b.vmid, b])) : (bsQ.data || null);
            const bs = !bsQ.error ? (bsMap && bsMap[r.vmid]) || null : null;
            const recovery = recQ.data && !recQ.error ? recQ.data : null;
            const haList = haQ.error ? null : (haQ.data || null);

            // 8 areas in 4 clusters; protection bundles snapshots/backups/replication
            const tabs = [
                { id: 'overview', icon: 'Grid', label: t('cloud.tabInfo') || 'Overview', group: 0 },
                { id: 'health', icon: 'Activity', label: t('cloud.tabHealth') || 'Operational state', group: 1 },
                { id: 'monitor', icon: 'BarChart', label: t('cloud.tabMonitor') || 'Monitoring', group: 1 },
                { id: 'tasks', icon: 'Clock', label: t('cloud.tabTasks') || 'Tasks & Events', group: 1 },
                { id: isCt ? 'config' : 'hardware', icon: 'Cog', label: isCt ? (t('cloud.tabConfig') || 'Configuration') : (t('cloud.tabHardware') || 'Hardware'), group: 2 },
                { id: 'disks', icon: 'HardDrive', label: t('cloud.tabDisks') || 'Disks', group: 2 },
                { id: 'network', icon: 'Network', label: t('cloud.tabNetwork') || 'Network', group: 2 },
                { id: 'protection', icon: 'Shield', label: t('cloud.tabProtection') || 'Protection', group: 3 },
            ];
            // legacy tab ids still used by links: route them into the protection sub-view
            const goto = (id) => {
                if (['snapshots', 'backups', 'replication'].includes(id)) { setTab('protection'); setProtSub(id); }
                else setTab(id);
            };
            const tabActive = (id) => tab === id || (id === 'protection' && tab === 'protection');

            // primary action buttons in the bar (contextual) + full kebab
            const primary = !act.has('vmAction') ? [] : running
                ? [
                    { label: t('shutdown') || 'Shutdown', icon: 'Power', onClick: () => act.vmAction(r, 'shutdown') },
                    { label: t('reboot') || 'Reboot', icon: 'RotateCw', onClick: () => act.vmAction(r, 'reboot') },
                ]
                : [{ label: t('start') || 'Start', icon: 'Play', primary: true, onClick: () => act.vmAction(r, 'start') }];

            const MeterCard = ({ label, pct, sub, color }) => (
                <div className="cloud-meter-block">
                    <div className="cloud-meter-label">{label} · {pct}%</div>
                    <div className="cloud-meter cloud-meter-lg"><div style={{ width: Math.min(100, pct) + '%', background: color || cloudThresholdColor(pct) }} /></div>
                    <div className="cloud-meter-sub">{sub}</div>
                </div>
            );
            const diskPct = diskMax > 0 ? Math.round(diskUse / diskMax * 100) : 0;

            const TaskMiniRow = ({ tk }) => (
                <tr className="cloud-table-row">
                    <td><span className={'cloud-task-dot ' + (tk.status === 'running' ? 'is-run' : tk.exitstatus === 'OK' || tk.status === 'OK' ? 'is-ok' : 'is-err')} /></td>
                    <td>{tk.type || 'task'}</td>
                    <td className="cloud-table-mono">{tk.id || ''}</td>
                    <td>{tk.pegaprox_user || tk.user || ''}</td>
                    <td className="cloud-table-mono cloud-cell-muted">{tk.starttime ? cloudFmtTs(tk.starttime) : ''}</td>
                </tr>
            );

            return (
                <div className="cloud-body">
                    <div className={'cloud-detail-head is-' + (r.status || 'unknown')}>
                        <button type="button" className="cloud-icon-btn cloud-back-btn" onClick={onBack} title={t('cloud.back') || 'Back'}><Icons.ArrowLeft /></button>
                        <span className="cloud-detail-icon">{isCt ? <Icons.Box /> : <Icons.Server />}</span>
                        <div className="cloud-detail-titlewrap">
                            <h1 className="cloud-detail-title">{r.name || ('guest-' + (r.vmid != null ? r.vmid : ''))}</h1>
                            <div className="cloud-detail-meta">
                                <CloudStatusChip status={r.status} />
                                <span className="cloud-detail-id">#{r.vmid} · {isCt ? 'Container' : 'VM'} · {clusterName || cid || ' - '} · {r.node || ' - '}{running && r.uptime ? ' · ' + cloudFmtUptime(r.uptime) : ''}</span>
                                {tags.length > 0 && (
                                    <span className="cloud-detail-tags">
                                        {tags.slice(0, 4).map(tg => <span className="cloud-chip cloud-chip-tag" key={tg}>{tg}</span>)}
                                        {tags.length > 4 && <span className="cloud-table-tags-more">+{tags.length - 4}</span>}
                                    </span>
                                )}
                                <span className="cloud-detail-res">
                                    <span className="cloud-res-chip" title="vCPU">{Number(r.maxcpu) || 0} vCPU</span>
                                    {memMax > 0 && <span className="cloud-res-chip" title={t('cloud.ram') || 'Memory'}>{cloudFmtBytes(memUse)} / {cloudFmtBytes(memMax)}
                                        <span className="cloud-res-chip-bar"><div style={{ width: memP + '%', background: cloudThresholdColor(memP) }} /></span></span>}
                                    {diskMax > 0 && <span className="cloud-res-chip" title={t('cloud.disk') || 'Disk'}>{cloudFmtBytes(diskUse)} / {cloudFmtBytes(diskMax)}
                                        <span className="cloud-res-chip-bar"><div style={{ width: Math.round(diskUse / diskMax * 100) + '%', background: cloudThresholdColor(Math.round(diskUse / diskMax * 100)) }} /></span></span>}
                                </span>
                            </div>
                        </div>
                        <div className="cloud-detail-actions">
                            {primary.map((b, i) => (
                                <button type="button" key={i} className={'cloud-btn' + (b.primary ? ' cloud-btn-primary' : '')} onClick={b.onClick}>
                                    {React.createElement(Icons[b.icon] || Icons.Box)} {b.label}
                                </button>
                            ))}
                            {act.has('openConsole') && (
                                <button type="button" className="cloud-btn" onClick={() => act.openConsole(r)}><Icons.Monitor /> {t('console') || 'Console'}</button>
                            )}
                            {act.has('openSpice') && r.status === 'running' && r.type === 'qemu' && (
                                <button type="button" className="cloud-btn" onClick={() => act.openSpice(r)} title={t('spiceConsoleHint') || 'Download a virt-viewer file (audio / USB / multi-monitor)'}><Icons.ExternalLink /> {t('spiceConsole') || 'SPICE'}</button>
                            )}
                            {act.consoleOnActive && <HaOnActiveLink vm={r} className="cloud-btn" />}
                            <CloudActionMenu items={cloudVmActionItems(r, act, t)} triggerLabel={t('cloud.actions') || 'Actions'} label="Actions" />
                        </div>
                    </div>

                    <div className="cloud-tabs">
                        {tabs.map((tb, i) => {
                            const TI = Icons[tb.icon] || Icons.Box;
                            const prev = tabs[i - 1];
                            return (
                                <React.Fragment key={tb.id}>
                                    {prev && prev.group !== tb.group && <span className="cloud-tabs-sep" aria-hidden="true"></span>}
                                    <button type="button" className={'cloud-tab' + (tab === tb.id ? ' cloud-tab-active' : '')} onClick={() => { setTab(tb.id); if (tb.id !== 'protection') setProtSub('snapshots'); }}>
                                        <TI /> {tb.label}
                                    </button>
                                </React.Fragment>
                            );
                        })}
                    </div>

                    {/* ── Overview: operations center (resources left, health rail right) ── */}
                    {tab === 'overview' && (() => {
                        const sm = (sparkQ.data && sparkQ.data.metrics) || {};
                        const has = (a) => Array.isArray(a) && a.some(v => v != null && isFinite(Number(v)));
                        const rows = cloudGuestHealthRows({ r, isCt, cfg, guest, backupStatus: bsQ.error ? null : bsMap, recovery, ha: haList, migrate, t, onMigrateCheck: runMigrateCheck, migrateChecking: migrChecking, compact: true });
                        const worst = rows.reduce((w, x) => (CLOUD_HC_ORDER[x.state] ?? 9) < (CLOUD_HC_ORDER[w.state] ?? 9) ? x : w, rows[0]);
                        const cnt = (s) => rows.filter(x => x.state === s).length;
                        const consoleState = !running
                            ? (t('cloud.consoleOff') || 'Console is available while the guest is running.')
                            : isCt ? (t('cloud.consoleLxc') || 'An LXC console is a terminal session.')
                            : shot.state === 'ok' ? (t('cloud.consoleLive') || 'Live preview')
                            : (t('cloud.consoleNoPreviewShort') || 'No live preview available right now.');
                        return (
                            <div className="cloud-ov-layout">
                                <div className="cloud-ov-left">
                                    <div className="cloud-card cloud-res-panel">
                                        <div className="cloud-chart-head">
                                            <span className="cloud-chart-title">{t('cloud.resources') || 'Resources'}</span>
                                            <div className="cloud-chart-stats">
                                                <button type="button" className="cloud-link-btn" onClick={() => setTab('monitor')}>{t('cloud.tabMonitor') || 'Monitoring'} →</button>
                                            </div>
                                        </div>
                                        <div className="cloud-res-tiles">
                                            <CloudResTile label={t('cloud.colCpu') || 'CPU'} value={cpuP + '%'} sub={`${Number(r.maxcpu) || 0} vCPU`}
                                                pct={cpuP} spark={has(sm.cpu) ? sm.cpu : null} sparkColor="#22d3ee" sparkTitle={(t('cloud.colCpu') || 'CPU') + ' · 1h'} />
                                            <CloudResTile label={t('cloud.ram') || 'Memory'} value={memP + '%'} sub={memMax ? `${cloudFmtBytes(memUse)} / ${cloudFmtBytes(memMax)}` : null}
                                                pct={memP} spark={has(sm.memory) ? sm.memory : null} sparkColor="#a855f7" sparkTitle={(t('cloud.ram') || 'Memory') + ' · 1h'} />
                                            <CloudResTile label={t('cloud.disk') || 'Storage'} value={(diskMax > 0 ? Math.round(diskUse / diskMax * 100) : 0) + '%'}
                                                sub={diskMax > 0 ? `${cloudFmtBytes(diskUse)} / ${cloudFmtBytes(diskMax)}` : null} pct={diskMax > 0 ? Math.round(diskUse / diskMax * 100) : null}
                                                foot={t('cloud.seeDisks') || 'per-disk view: Disks'} />
                                            <CloudResTile label={t('cloud.network') || 'Network'} value={`↓ ${cloudFmtRate(r.netin)} · ↑ ${cloudFmtRate(r.netout)}`}
                                                sub={has(sm.net_in) || has(sm.net_out) ? null : (t('cloud.noTrend') || 'no trend data')}
                                                spark={has(sm.net_in) ? sm.net_in : null} sparkColor="#2dd4bf" sparkTitle={t('cloud.netIn') || 'Network in'} foot={has(sm.net_out) ? null : null}
                                                pct={null} />
                                        </div>
                                    </div>
                                    <div className="cloud-card cloud-console-strip">
                                        {shot.state === 'ok'
                                            ? <img className="cloud-console-thumb" src={shot.url} alt="console" onClick={() => act.has('openConsole') && act.openConsole(r)} />
                                            : <span className="cloud-console-ico"><Icons.Monitor /></span>}
                                        <div className="cloud-console-txt">
                                            <b>{t('console') || 'Console'}</b>
                                            <span className="cloud-cell-muted">{consoleState}</span>
                                        </div>
                                        <div className="cloud-console-actions">
                                            {act.has('openConsole') && <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openConsole(r)}><Icons.Monitor /> {t('console') || 'Console'}</button>}
                                            {act.has('openLxcShell') && isCt && <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openLxcShell(r)}><Icons.Terminal /> {t('shell') || 'Shell'}</button>}
                                            {act.has('openSpice') && running && !isCt && <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openSpice(r)}><Icons.ExternalLink /> {t('spiceConsole') || 'SPICE'}</button>}
                                        </div>
                                    </div>
                                    <div className="cloud-card cloud-table-card">
                                        <div className="cloud-toolbar">
                                            <div className="cloud-toolbar-left"><span className="cloud-toolbar-title">{t('cloud.recentActivity') || 'Recent activity'}</span></div>
                                            <div className="cloud-toolbar-right">
                                                <button type="button" className="cloud-link-btn" onClick={() => goto('tasks')}>{t('cloud.viewAll') || 'View all'}</button>
                                            </div>
                                        </div>
                                        {taskQ.loading ? <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                            : (taskQ.data && Array.isArray(taskQ.data) ? taskQ.data : []).length === 0
                                                ? <div className="cloud-empty">{t('cloud.noRecentTasks') || 'No recent tasks.'}</div>
                                                : <div className="cloud-table-scroll"><table className="cloud-table"><thead><tr><th></th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colId') || 'Target'}</th><th>{t('cloud.colUser') || 'User'}</th><th>{t('cloud.colWhen') || 'When'}</th></tr></thead>
                                                    <tbody>{(taskQ.data || []).slice(0, 6).map((tk, i) => <TaskMiniRow tk={tk} key={tk.upid || i} />)}</tbody></table></div>}
                                    </div>
                                </div>
                                <div className="cloud-ov-right">
                                    <div className="cloud-card cloud-hc-rail">
                                        <div className="cloud-hc-rail-top">
                                            <span className="cloud-chart-title">{t('cloud.tabHealth') || 'Operational state'}</span>
                                            {worst && <span className={'cloud-hc-badge ' + (CLOUD_HC[worst.state] || CLOUD_HC.unknown).cls}>{(CLOUD_HC[worst.state] || CLOUD_HC.unknown).label}</span>}
                                            <button type="button" className="cloud-link-btn" onClick={() => goto('health')}>{t('cloud.railDetails') || 'All details'}</button>
                                        </div>
                                        <div className="cloud-hc-band" aria-hidden="true">
                                            {['critical', 'warning', 'healthy', 'unknown', 'na'].map(st => cnt(st) > 0 && (
                                                <div key={st} className={'seg-' + st} style={{ width: (cnt(st) / rows.length * 100) + '%' }} />
                                            ))}
                                        </div>
                                        {rows.map((row, i) => (
                                            <CloudHcRailRow key={row.id} row={row} t={t} meaning={row.id === 'agent' && guest && guest.os_pretty_name ? `${cloudHcMeaning(row.id, t)} · ${guest.os_pretty_name}${guest.kernel_version ? ' · ' + guest.kernel_version : ''}` : cloudHcMeaning(row.id, t)}
                                                open={hcOpen[row.id] != null ? hcOpen[row.id] : (worst && row.id === worst.id && worst.state !== 'healthy' && worst.state !== 'na')}
                                                onToggle={() => setHcOpen(o => ({ ...o, [row.id]: !(hcOpen[row.id] != null ? hcOpen[row.id] : (worst && row.id === worst.id && worst.state !== 'healthy' && worst.state !== 'na')) }))}
                                                extraAction={row.link && <button type="button" className="cloud-link-btn" onClick={() => goto(row.link)}>{t('cloud.openTab') || 'Open'}</button>} />
                                        ))}
                                    </div>
                                </div>
                            </div>
                        );
                    })()}

                    {/* ── Betriebszustand ──────────────────────────────── */}
                    {tab === 'health' && (() => {
                        const rows = cloudGuestHealthRows({ r, isCt, cfg, guest, backupStatus: bsQ.error ? null : bsMap, recovery, ha: haList, migrate, t, onMigrateCheck: runMigrateCheck, migrateChecking: migrChecking });
                        const cnt = (s) => rows.filter(x => x.state === s).length;
                        return (
                            <>
                                <div className="cloud-hc-summary">
                                    <div className="cloud-hc-band" aria-hidden="true">
                                        {['critical', 'warning', 'healthy', 'unknown', 'na'].map(st => cnt(st) > 0 && (
                                            <div key={st} className={'seg-' + st} style={{ width: (cnt(st) / rows.length * 100) + '%' }} />
                                        ))}
                                    </div>
                                    <span className="cloud-hc-badge is-critical">{cnt('critical')} CRITICAL</span>
                                    <span className="cloud-hc-badge is-warning">{cnt('warning')} WARNING</span>
                                    <span className="cloud-hc-badge is-healthy">{cnt('healthy')} HEALTHY</span>
                                    <span className="cloud-hc-badge is-unknown">{cnt('unknown')} UNKNOWN</span>
                                    <span className="cloud-hc-badge is-na">{cnt('na')} N/A</span>
                                </div>
                                <div className="cloud-hc-list">{rows.map(row => (
                                    <CloudHcRow key={row.id} title={row.title} state={row.state} desc={row.desc} checked={row.checked} impact={row.impact} meaning={cloudHcMeaning(row.id, t)}
                                        action={
                                            <span className="cloud-hc-actions">
                                                {row.action}
                                                {row.link && <button type="button" className="cloud-link-btn" onClick={() => goto(row.link)}>{t('cloud.openTab') || 'Open'}</button>}
                                            </span>
                                        } />
                                ))}</div>
                                <div className="cloud-card cloud-hc-legend cloud-cell-muted">
                                    HEALTHY {t('cloud.hcL1') || '= proof present and passing'} · WARNING {t('cloud.hcL2') || '= deviation, not immediately critical'} · CRITICAL {t('cloud.hcL3') || '= failed or missing where required'} · UNKNOWN {t('cloud.hcL4') || '= no (current) data'} · N/A {t('cloud.hcL5') || '= not relevant for this guest'}
                                </div>
                            </>
                        );
                    })()}

                    {/* ── Monitoring ───────────────────────────────────── */}
                    {tab === 'monitor' && (
                        <>
                            <div className="cloud-toolbar">
                                <div className="cloud-toolbar-left">
                                    <div className="cloud-segment">
                                        {[['hour', '1h'], ['day', '24h'], ['week', '7d'], ['month', '30d']].map(([id, lb]) => (
                                            <button type="button" key={id} className={'cloud-segment-btn' + (tf === id ? ' is-active' : '')} onClick={() => setTf(id)}>{lb}</button>
                                        ))}
                                    </div>
                                </div>
                                <div className="cloud-toolbar-right">
                                    <button type="button" className="cloud-btn cloud-btn-sm" onClick={rrdQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                                    {act.has('openMetrics') && <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openMetrics(r)}><Icons.BarChart /> {t('cloud.openMetrics') || 'Detailed metrics'}</button>}
                                </div>
                            </div>
                            {rrdQ.loading ? <div className="cloud-card cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                : rrdQ.error ? <div className="cloud-card cloud-table-note">{rrdQ.error}</div>
                                    : (() => {
                                        const m = (rrdQ.data && rrdQ.data.metrics) || {};
                                        const ts = (rrdQ.data && rrdQ.data.timestamps) || [];
                                        const pctF = v => Math.round(v) + '%';
                                        return (
                                            <div className="cloud-chart-grid">
                                                <CloudMetricChart title={t('cloud.colCpu') || 'CPU'} data={m.cpu} timestamps={ts} fmt={pctF} color="#22d3ee" />
                                                <CloudMetricChart title={t('cloud.ram') || 'Memory'} data={m.memory} timestamps={ts} fmt={pctF} color="#a855f7"
                                                    sub={(memUse && memMax) ? `${cloudFmtBytes(memUse)} / ${cloudFmtBytes(memMax)}` : null} />
                                                <CloudMetricChart title={t('cloud.diskRead') || 'Disk read'} data={m.disk_read} timestamps={ts} fmt={cloudFmtRate} color="#38bdf8" />
                                                <CloudMetricChart title={t('cloud.diskWrite') || 'Disk write'} data={m.disk_write} timestamps={ts} fmt={cloudFmtRate} color="#818cf8" />
                                                <CloudMetricChart title={t('cloud.netIn') || 'Network in'} data={m.net_in} timestamps={ts} fmt={cloudFmtRate} color="#2dd4bf" />
                                                <CloudMetricChart title={t('cloud.netOut') || 'Network out'} data={m.net_out} timestamps={ts} fmt={cloudFmtRate} color="#a3e635" />
                                            </div>
                                        );
                                    })()}
                        </>
                    )}

                    {/* ── Hardware (VM) / Configuration (CT) ────────────── */}
                    {(tab === 'hardware' || tab === 'config') && (cfgQ.loading ? <div className="cloud-card cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                        : cfgQ.error ? <div className="cloud-card cloud-table-note">{cfgQ.error}</div>
                            : !isCt ? (
                                <div className="cloud-kv-grid">
                                    {(pendQ.data && Array.isArray(pendQ.data.pending) ? pendQ.data.pending.filter(p => p && p.pending) : []).length > 0 && (
                                        <div className="cloud-card cloud-hc-note cloud-hc-note-warn cloud-hw-wide">
                                            <Icons.AlertTriangle />
                                            <span>
                                                <b>{t('cloud.pendingChanges') || 'Pending configuration changes'}:</b>{' '}
                                                {(pendQ.data.pending || []).filter(p => p && p.pending).map(p => p.key).join(', ')}
                                                {' '}{t('cloud.pendingHint') || '(applied on next reboot)'}
                                            </span>
                                        </div>
                                    )}
                                    <CloudKVPanel title={t('cloud.hwGeneral') || 'General'}>
                                        <CloudKVRow label={t('cloud.colName') || 'Name'} value={(cfg && cfg.general && (cfg.general.name || cfg.general.hostname)) || r.name || ' - '} />
                                        <CloudKVRow label={t('cloud.description') || 'Description'} value={(cfg && cfg.general && cfg.general.description) || ' - '} />
                                        {tags.length > 0 && <CloudKVRow label={t('cloud.tags') || 'Tags'} value={<span className="cloud-table-tags">{tags.map(tg => <span className="cloud-chip cloud-chip-tag" key={tg}>{tg}</span>)}</span>} />}
                                        <CloudKVRow label={t('cloud.colStatus') || 'Status'} value={<CloudStatusChip status={r.status} />} />
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.hwCpu') || 'CPU'}>
                                        <CloudKVRow label={t('cloud.vcpu') || 'vCPUs'} value={hw.cores != null ? hw.cores : ' - '} />
                                        <CloudKVRow label="Sockets" value={hw.sockets != null ? hw.sockets : ' - '} />
                                        <CloudKVRow label={t('cloud.cpuType') || 'CPU type'} value={hw.cpu || ' - '} />
                                        {hw.numa != null && <CloudKVRow label="NUMA" value={hw.numa ? 'on' : 'off'} />}
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.ram') || 'Memory'}>
                                        <CloudKVRow label={t('cloud.allocated') || 'Allocated'} value={hw.memory != null ? hw.memory + ' MiB' : ' - '} />
                                        <CloudKVRow label="Ballooning" value={hw.balloon != null ? (hw.balloon > 0 ? hw.balloon + ' MiB' : 'off') : ' - '} />
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.firmware') || 'Firmware'}>
                                        <CloudKVRow label="BIOS / EFI" value={hw.bios || 'seabios (default)'} />
                                        {hw.machine && <CloudKVRow label={t('cloud.machine') || 'Machine'} value={hw.machine} />}
                                        {hw.vga && <CloudKVRow label="Display" value={hw.vga} />}
                                        {raw.efidisk0 && <CloudKVRow label="EFI disk" value={<span className="cloud-table-mono">{raw.efidisk0}</span>} />}
                                        {raw.tpmstate0 && <CloudKVRow label="TPM" value={<span className="cloud-table-mono">{raw.tpmstate0}</span>} />}
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.hwVirtio') || 'Virtualization'}>
                                        {hw.scsihw && <CloudKVRow label="SCSI controller" value={hw.scsihw} />}
                                        <CloudKVRow label={t('cloud.hcAgent') || 'Guest agent'} value={opts.agent ? 'enabled' : 'disabled'} />
                                        {Object.keys(raw).some(k => /^ciuser|cipassword|sshkeys|cloud-init/.test(k)) && <CloudKVRow label="Cloud-Init" value={<span className="cloud-cell-muted">{t('cloud.cloudInitCfg') || 'configured'}</span>} />}
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.hwOptions') || 'Options'}>
                                        <CloudKVRow label={t('cloud.bootOrder') || 'Boot order'} value={opts.boot || ' - '} />
                                        {opts.bootdisk && <CloudKVRow label="Boot disk" value={opts.bootdisk} />}
                                        <CloudKVRow label={t('cloud.startOnBoot') || 'Start on boot'} value={opts.onboot ? 'yes' : 'no'} />
                                        <CloudKVRow label={t('cloud.hcAgent') || 'Guest agent'} value={opts.agent ? 'enabled' : 'disabled'} />
                                        {opts.protection != null && <CloudKVRow label={t('cloud.protection') || 'Protection'} value={opts.protection ? 'on' : 'off'} />}
                                    </CloudKVPanel>
                                    {Object.keys(raw).some(k => /^(hostpci|usb)/.test(k)) && (
                                        <CloudKVPanel title={t('cloud.hwPassthrough') || 'Passthrough'}>
                                            {Object.keys(raw).filter(k => /^(hostpci|usb)/.test(k)).map(k => <CloudKVRow key={k} label={k} value={<span className="cloud-table-mono">{String(raw[k])}</span>} />)}
                                        </CloudKVPanel>
                                    )}
                                    {act.has('openConfig') && <div className="cloud-hw-wide"><button type="button" className="cloud-btn" onClick={() => act.openConfig(r)}><Icons.Cog /> {t('cloud.editHardware') || 'Edit hardware'}</button></div>}
                                </div>
                            ) : (
                                <div className="cloud-kv-grid">
                                    {(pendQ.data && Array.isArray(pendQ.data.pending) ? pendQ.data.pending.filter(p => p && p.pending) : []).length > 0 && (
                                        <div className="cloud-card cloud-hc-note cloud-hc-note-warn cloud-hw-wide">
                                            <Icons.AlertTriangle />
                                            <span>
                                                <b>{t('cloud.pendingChanges') || 'Pending configuration changes'}:</b>{' '}
                                                {(pendQ.data.pending || []).filter(p => p && p.pending).map(p => p.key).join(', ')}
                                                {' '}{t('cloud.pendingHint') || '(applied on next reboot)'}
                                            </span>
                                        </div>
                                    )}
                                    <CloudKVPanel title={t('cloud.hwGeneral') || 'General'}>
                                        <CloudKVRow label={t('cloud.colName') || 'Name'} value={(cfg && cfg.general && (cfg.general.hostname || cfg.general.name)) || r.name || ' - '} />
                                        <CloudKVRow label={t('cloud.description') || 'Description'} value={(cfg && cfg.general && cfg.general.description) || ' - '} />
                                        {tags.length > 0 && <CloudKVRow label={t('cloud.tags') || 'Tags'} value={<span className="cloud-table-tags">{tags.map(tg => <span className="cloud-chip cloud-chip-tag" key={tg}>{tg}</span>)}</span>} />}
                                        <CloudKVRow label={t('cloud.colStatus') || 'Status'} value={<CloudStatusChip status={r.status} />} />
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.hwCpu') || 'CPU'}>
                                        <CloudKVRow label={t('cloud.vcpu') || 'Cores'} value={hw.cores != null ? hw.cores : ' - '} />
                                        <CloudKVRow label="CPU limit" value={hw.cpulimit || ' - '} />
                                        <CloudKVRow label="CPU units" value={hw.cpuunits || ' - '} />
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.ram') || 'Memory'}>
                                        <CloudKVRow label={t('cloud.allocated') || 'Memory'} value={hw.memory != null ? hw.memory + ' MiB' : ' - '} />
                                        <CloudKVRow label="Swap" value={hw.swap != null ? hw.swap + ' MiB' : ' - '} />
                                    </CloudKVPanel>
                                    <CloudKVPanel title={t('cloud.ctMode') || 'Mode'}>
                                        <CloudKVRow label="Unprivileged" value={opts.unprivileged ? 'yes' : 'no'} />
                                        {opts.features && <CloudKVRow label="Features" value={<span className="cloud-table-mono">{String(opts.features)}</span>} />}
                                        <CloudKVRow label={t('cloud.startOnBoot') || 'Start on boot'} value={opts.onboot ? 'yes' : 'no'} />
                                        {opts.startup && <CloudKVRow label="Startup order" value={<span className="cloud-table-mono">{String(opts.startup)}</span>} />}
                                        {opts.protection != null && <CloudKVRow label={t('cloud.protection') || 'Protection'} value={opts.protection ? 'on' : 'off'} />}
                                    </CloudKVPanel>
                                    <div className="cloud-card cloud-table-card cloud-hw-wide">
                                        <div className="cloud-toolbar"><div className="cloud-toolbar-left"><span className="cloud-toolbar-title">{t('cloud.ctMounts') || 'Root filesystem & mount points'}</span></div></div>
                                        <div className="cloud-table-scroll"><table className="cloud-table">
                                            <thead><tr><th>{t('cloud.hwDevice') || 'Device'}</th><th>{t('cloud.datastores') || 'Datastore'}</th><th>{t('cloud.colSize') || 'Size'}</th><th>Content</th></tr></thead>
                                            <tbody>{disks.map(d => (
                                                <tr className="cloud-table-row" key={d.id}>
                                                    <td className="cloud-table-mono">{d.id}</td>
                                                    <td>{d.storage || ' - '}</td>
                                                    <td>{d.size || ' - '}</td>
                                                    <td className="cloud-table-mono cloud-cell-muted">{d.volume || d.value || ''}</td>
                                                </tr>
                                            ))}</tbody>
                                        </table></div>
                                        {disks.length === 0 && <div className="cloud-empty">{t('cloud.noDisks') || 'No mount points reported.'}</div>}
                                    </div>
                                    <div className="cloud-card cloud-table-card cloud-hw-wide">
                                        <div className="cloud-toolbar"><div className="cloud-toolbar-left"><span className="cloud-toolbar-title">{t('cloud.hwNics') || 'Network'}</span></div></div>
                                        <div className="cloud-table-scroll"><table className="cloud-table">
                                            <thead><tr><th>{t('cloud.hwDevice') || 'Device'}</th><th>Bridge</th><th>VLAN</th><th>MAC</th><th>Firewall</th></tr></thead>
                                            <tbody>{nets.map(n => (
                                                <tr className="cloud-table-row" key={n.id}>
                                                    <td className="cloud-table-mono">{n.id}</td>
                                                    <td>{n.bridge || ' - '}</td>
                                                    <td>{n.tag || ' - '}</td>
                                                    <td className="cloud-table-mono">{n.mac || ' - '}</td>
                                                    <td>{n.firewall ? 'on' : 'off'}</td>
                                                </tr>
                                            ))}</tbody>
                                        </table></div>
                                    </div>
                                    {act.has('openConfig') && <div className="cloud-hw-wide"><button type="button" className="cloud-btn" onClick={() => act.openConfig(r)}><Icons.Cog /> {t('cloud.tabConfig') || 'Configure'}</button></div>}
                                </div>
                            ))}

                    {/* ── Storage ──────────────────────────────────────── */}
                    {tab === 'disks' && (
                        <>
                            <div className="cloud-card">
                                <div className="cloud-meter-block">
                                    <div className="cloud-meter-label">{t('cloud.disk') || 'Guest storage (root)'} · {diskPct}%</div>
                                    <div className="cloud-meter cloud-meter-lg"><div style={{ width: diskPct + '%', background: cloudThresholdColor(diskPct) }} /></div>
                                    <div className="cloud-meter-sub">{t('cloud.storageHint') || 'Used'}: {cloudFmtBytes(diskUse)} · {t('cloud.allocated') || 'Allocated'}: {cloudFmtBytes(diskMax)}</div>
                                </div>
                                <div className="cloud-table-note">{t('cloud.storageNote') || 'Used = actual usage reported for the guest root; allocated = virtual size. Per-disk usage is not reported by the cluster.'}</div>
                            </div>
                            <div className="cloud-card cloud-table-card">
                                <div className="cloud-toolbar">
                                    <div className="cloud-toolbar-left">
                                        <span className="cloud-toolbar-title">{isCt ? (t('cloud.ctMounts') || 'Root filesystem & mount points') : (t('cloud.hwDisks') || 'Virtual disks')}</span>
                                        {dsQ.loading && <span className="cloud-cell-muted">{t('cloud.loading') || 'Loading…'}</span>}
                                    </div>
                                    {act.has('openConfig') && (
                                        <div className="cloud-toolbar-right">
                                            <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openConfig(r)}><Icons.Cog /> {t('edit') || 'Edit'}</button>
                                        </div>
                                    )}
                                </div>
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.hwDevice') || 'Device'}</th><th>{t('cloud.bus') || 'Bus'}</th><th>{t('cloud.datastores') || 'Datastore'}</th><th>{t('cloud.dsType') || 'Type'}</th><th>{t('cloud.colSize') || 'Size'}</th><th>Format</th><th>Cache</th><th>IO thread</th><th>{t('cloud.dsHealth') || 'Datastore'}</th></tr></thead>
                                    <tbody>{(cfg ? disks : []).map(d => {
                                        const ds = dsFind(d.storage);
                                        return (
                                            <tr className="cloud-table-row" key={d.id}>
                                                <td className="cloud-table-mono">{d.id}</td>
                                                <td>{String(d.id || '').replace(/\d+$/, '') || ' - '}</td>
                                                <td>{d.storage || ' - '}</td>
                                                <td>{ds ? (ds.type || ' - ') : (dsQ.data ? ' - ' : '')}</td>
                                                <td>{d.size || ' - '}</td>
                                                <td>{d.format || ' - '}</td>
                                                <td>{d.cache || 'default'}</td>
                                                <td>{d.iothread ? 'on' : ' - '}</td>
                                                <td>{ds ? (ds.active !== false && ds.enabled !== 0 ? <span className="cloud-hc-badge is-healthy">ACTIVE</span> : <span className="cloud-hc-badge is-critical">OFFLINE</span>) : <span className="cloud-cell-muted"> - </span>}</td>
                                            </tr>
                                        );
                                    })}</tbody>
                                </table></div>
                                {cfgQ.loading && <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>}
                                {cfg && disks.length === 0 && <div className="cloud-empty">{t('cloud.noDisks') || 'No disks reported.'}</div>}
                            </div>
                            {(() => {
                                const names = [...new Set(disks.map(d => d.storage).filter(Boolean))];
                                const cards = names.map(n => ({ name: n, ds: dsFind(n) })).filter(x => x.ds);
                                if (!cards.length) return null;
                                return (
                                    <div className="cloud-hc-list">
                                        {cards.map(({ name, ds }) => {
                                            const pct = ds.used_fraction != null ? Math.round(Number(ds.used_fraction) * 100) : (ds.total ? Math.round((ds.used || 0) / ds.total * 100) : null);
                                            return (
                                                <div className="cloud-card cloud-ds-mini" key={name}>
                                                    <div className="cloud-chart-head">
                                                        <span className="cloud-chart-title">{name}</span>
                                                        <span className="cloud-cell-muted">{ds.type || ''}{ds.shared ? ' · shared' : ''}</span>
                                                    </div>
                                                    {pct != null && (
                                                        <div className="cloud-meter-block">
                                                            <div className="cloud-meter-label">{pct}%</div>
                                                            <div className="cloud-meter"><div style={{ width: pct + '%', background: cloudThresholdColor(pct) }} /></div>
                                                            <div className="cloud-meter-sub">{cloudFmtBytes(ds.used)} / {cloudFmtBytes(ds.total)} · {t('cloud.free') || 'free'} {cloudFmtBytes(ds.avail)}</div>
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                );
                            })()}
                        </>
                    )}

                    {/* ── Network ──────────────────────────────────────── */}
                    {tab === 'network' && (
                        <>
                            <div className="cloud-card cloud-table-card">
                                <div className="cloud-toolbar">
                                    <div className="cloud-toolbar-left"><span className="cloud-toolbar-title">{t('cloud.hwNics') || 'Interfaces'}</span></div>
                                    {act.has('openConfig') && <div className="cloud-toolbar-right"><button type="button" className="cloud-btn cloud-btn-sm" onClick={() => act.openConfig(r)}><Icons.Cog /> {t('cloud.editHardware') || 'Edit'}</button></div>}
                                </div>
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.hwDevice') || 'Device'}</th><th>Model</th><th>Bridge</th><th>VLAN</th><th>MAC</th><th>Firewall</th></tr></thead>
                                    <tbody>{(cfg ? nets : []).map(n => (
                                        <tr className="cloud-table-row" key={n.id}>
                                            <td className="cloud-table-mono">{n.id}</td>
                                            <td>{n.model || ' - '}</td>
                                            <td>{n.bridge || ' - '}</td>
                                            <td>{n.tag || ' - '}</td>
                                            <td className="cloud-table-mono">{n.mac || ' - '}</td>
                                            <td>{n.firewall ? 'on' : 'off'}</td>
                                        </tr>
                                    ))}</tbody>
                                </table></div>
                                {cfgQ.loading && <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>}
                                {cfg && nets.length === 0 && <div className="cloud-empty">{t('cloud.noNics') || 'No network cards reported.'}</div>}
                            </div>
                            <div className="cloud-card">
                                <div className="cloud-chart-head"><span className="cloud-chart-title">{t('cloud.ipAddresses') || 'IP addresses'}</span></div>
                                {guest && Array.isArray(guest.interfaces) && guest.interfaces.length > 0 ? (
                                    <div className="cloud-table-scroll"><table className="cloud-table">
                                        <thead><tr><th>{t('cloud.iface') || 'Interface'}</th><th>MAC</th><th>IP</th></tr></thead>
                                        <tbody>{guest.interfaces.map((n, i) => (
                                            <tr className="cloud-table-row" key={i}>
                                                <td>{n.name || ' - '}</td>
                                                <td className="cloud-table-mono">{n.mac || ' - '}</td>
                                                <td className="cloud-table-mono">{(n.ips || []).map(ip => ip.address).join(', ') || ' - '}</td>
                                            </tr>
                                        ))}</tbody>
                                    </table></div>
                                ) : guest && Array.isArray(guest.ip_addresses) && guest.ip_addresses.length > 0 ? (
                                    <div className="cloud-table-mono">{guest.ip_addresses.join(', ')}</div>
                                ) : (
                                    <div className="cloud-empty">{isCt ? (t('cloud.noIpLxc') || 'No IPs reported by the cluster for this container.') : (t('cloud.noIp') || 'Not reported (guest agent required)')}</div>
                                )}
                            </div>
                        </>
                    )}

                    {/* ── Schutz (Snapshots / Backups / Replication) ───── */}
                    {tab === 'protection' && (
                        <div className="cloud-toolbar" style={{ marginBottom: 'var(--space-sm)' }}>
                            <div className="cloud-toolbar-left">
                                <div className="cloud-segment">
                                    {[['snapshots', t('cloud.tabSnapshots') || 'Snapshots'], ['backups', t('cloud.tabBackups') || 'Backups'], ['replication', t('cloud.tabReplication') || 'Replication']].map(([id, lb]) => (
                                        <button type="button" key={id} className={'cloud-segment-btn' + (protSub === id ? ' is-active' : '')} onClick={() => setProtSub(id)}>{lb}</button>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                    {tab === 'protection' && protSub === 'snapshots' && (
                        <div className="cloud-card cloud-table-card">
                            <div className="cloud-toolbar">
                                <div className="cloud-toolbar-left">
                                    <span className="cloud-toolbar-title">{t('cloud.tabSnapshots') || 'Snapshots'}</span>
                                    {snapQ.data && Array.isArray(snapQ.data) && <span className="cloud-count-chip">{snapQ.data.length}</span>}
                                </div>
                                <div className="cloud-toolbar-right">
                                    {act.has('snapshot') && <button type="button" className="cloud-btn cloud-btn-sm cloud-btn-primary" onClick={() => act.snapshot(r)}><Icons.Camera /> {t('cloud.snapCreate') || 'Create snapshot'}</button>}
                                    <button type="button" className="cloud-btn cloud-btn-sm" onClick={snapQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                                </div>
                            </div>
                            {snapQ.loading ? <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                : snapQ.error ? <div className="cloud-table-note">{snapQ.error}</div>
                                    : (snapQ.data || []).length === 0 ? <CloudEmpty icon="Camera" title={t('cloud.snapNone') || 'No snapshots'} text={t('cloud.snapNoneText') || 'Snapshots of this guest will appear here.'} />
                                        : <div className="cloud-table-scroll"><table className="cloud-table">
                                            <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.description') || 'Description'}</th><th>{t('cloud.created') || 'Created'}</th><th>RAM</th><th>{t('cloud.colSize') || 'Size'}</th><th className="cloud-th-actions"></th></tr></thead>
                                            <tbody>{(snapQ.data || []).map(sn => (
                                                <tr className="cloud-table-row" key={sn.name}>
                                                    <td className="cloud-table-name"><span className="cloud-table-name-text">{sn.name}</span></td>
                                                    <td className="cloud-cell-muted">{sn.description || ' - '}</td>
                                                    <td className="cloud-table-mono cloud-cell-muted">{cloudFmtTs(sn.snaptime) || ' - '}</td>
                                                    <td>{sn.vmstate ? 'included' : ' - '}</td>
                                                    <td>{sn.disk_size ? cloudFmtBytes(sn.disk_size) : ' - '}</td>
                                                    <td className="cloud-td-actions" onClick={(e) => e.stopPropagation()}>
                                                        {can('vm.snapshot') && (
                                                            <CloudActionMenu items={[
                                                                { label: t('cloud.snapRollback') || 'Rollback', icon: 'RotateCcw', onClick: () => snapAct(sn, 'rollback') },
                                                                { label: t('cloud.snapDelete') || 'Delete', icon: 'Trash2', onClick: () => snapAct(sn, 'delete'), danger: true },
                                                            ]} label="Snapshot actions" />
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}</tbody>
                                        </table></div>}
                        </div>
                    )}

                    {/* ── Backups ──────────────────────────────────────── */}
                    {tab === 'protection' && protSub === 'backups' && (
                        <>
                            {bs && (
                                <div className="cloud-card">
                                    <div className="cloud-chart-head"><span className="cloud-chart-title">{t('cloud.hcBackup') || 'Backup status'}</span></div>
                                    <div className="cloud-bak-summary">
                                        <span className={'cloud-hc-badge ' + (bs.status === 'ok' ? 'is-healthy' : bs.status === 'warn' ? 'is-warning' : 'is-critical')}>{String(bs.status || ' - ').toUpperCase()}</span>
                                        {bs.last_backup_ts && <span>{t('cloud.hcLastBackup') || 'Last backup'}: {cloudFmtTs(bs.last_backup_ts)}</span>}
                                        {bs.count_30d != null && <span>30d: {bs.count_30d}</span>}
                                        {bs.encrypted && <span>{t('cloud.hcEncrypted') || 'encrypted'}</span>}
                                        {bs.last_verify_ts && <span>{t('cloud.hcVerified') || 'verified'}: {cloudFmtTs(bs.last_verify_ts)}</span>}
                                    </div>
                                </div>
                            )}
                            {can('backup.create') && backupStorages.length > 0 && (
                                <div className="cloud-card cloud-bak-create">
                                    <div className="cloud-chart-head"><span className="cloud-chart-title">{t('cloud.bakCreate') || 'Create backup'}</span></div>
                                    <div className="cloud-bak-form">
                                        <label className="cloud-oci-label">{t('cloud.datastores') || 'Storage'}</label>
                                        <select className="cloud-input" value={bForm.storage} onChange={e => setBForm(f => ({ ...f, storage: e.target.value }))}>
                                            <option value=""> - </option>
                                            {backupStorages.map(s => <option key={s} value={s}>{s}</option>)}
                                        </select>
                                        <label className="cloud-oci-label">{t('cloud.bakMode') || 'Mode'}</label>
                                        <select className="cloud-input" value={bForm.mode} onChange={e => setBForm(f => ({ ...f, mode: e.target.value }))}>
                                            <option value="snapshot">snapshot</option>
                                            <option value="suspend">suspend</option>
                                            <option value="stop">stop</option>
                                        </select>
                                        <label className="cloud-oci-label">{t('cloud.bakNotes') || 'Notes'}</label>
                                        <input className="cloud-input" value={bForm.notes} onChange={e => setBForm(f => ({ ...f, notes: e.target.value }))} placeholder={t('cloud.bakNotesPh') || 'optional'} />
                                        <button type="button" className="cloud-btn cloud-btn-primary" disabled={!bForm.storage || bBusy} onClick={createBackup}>
                                            <Icons.Archive /> {bBusy ? (t('cloud.hcChecking') || 'Working…') : (t('cloud.bakStart') || 'Start backup')}
                                        </button>
                                    </div>
                                </div>
                            )}
                            <div className="cloud-card cloud-table-card">
                                <div className="cloud-toolbar">
                                    <div className="cloud-toolbar-left">
                                        <span className="cloud-toolbar-title">{t('cloud.bakHistory') || 'Backup history'}</span>
                                        {bakQ.data && Array.isArray(bakQ.data) && <span className="cloud-count-chip">{bakQ.data.length}</span>}
                                    </div>
                                    <div className="cloud-toolbar-right">
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={bakQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                                    </div>
                                </div>
                                {bakQ.loading ? <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                    : bakQ.error ? <div className="cloud-table-note">{bakQ.error}</div>
                                        : (bakQ.data || []).length === 0 ? <CloudEmpty icon="Archive" title={t('cloud.bakNone') || 'No backups'} text={t('cloud.bakNoneText') || 'Created backups of this guest will appear here.'} />
                                            : <div className="cloud-table-scroll"><table className="cloud-table">
                                                <thead><tr><th>{t('cloud.created') || 'Created'}</th><th>{t('cloud.bakTarget') || 'Target'}</th><th>{t('cloud.file') || 'File'}</th><th>{t('cloud.colSize') || 'Size'}</th><th>Format</th><th className="cloud-th-actions"></th></tr></thead>
                                                <tbody>{(bakQ.data || []).map((b, i) => (
                                                    <tr className="cloud-table-row" key={b.volid || i}>
                                                        <td className="cloud-table-mono cloud-cell-muted">{cloudFmtTs(b.ctime) || ' - '}</td>
                                                        <td>{b.storage || ' - '}</td>
                                                        <td className="cloud-table-mono" title={b.filename}>{b.filename || b.volid}</td>
                                                        <td>{b.size ? cloudFmtBytes(b.size) : ' - '}</td>
                                                        <td>{b.format || ' - '}</td>
                                                        <td className="cloud-td-actions" onClick={(e) => e.stopPropagation()}>
                                                            <CloudActionMenu items={[
                                                                ...(can('backup.restore') ? [{ label: t('cloud.bakRestore') || 'Restore…', icon: 'RotateCcw', onClick: () => setWiz(b) }] : []),
                                                                ...(can('backup.delete') ? [{ label: t('cloud.bakDelete') || 'Delete', icon: 'Trash2', danger: true, onClick: () => delBackup(b) }] : []),
                                                            ]} label="Backup actions" />
                                                        </td>
                                                    </tr>
                                                ))}</tbody>
                                            </table></div>}
                            </div>
                        </>
                    )}

                    {/* ── Replication ─────────────────────────────────── */}
                    {tab === 'protection' && protSub === 'replication' && (
                        <div className="cloud-card cloud-table-card">
                            <div className="cloud-toolbar">
                                <div className="cloud-toolbar-left">
                                    <span className="cloud-toolbar-title">{t('cloud.tabReplication') || 'Replication'}</span>
                                    {replQ.data && Array.isArray(replQ.data) && <span className="cloud-count-chip">{replQ.data.length}</span>}
                                </div>
                                <div className="cloud-toolbar-right">
                                    <button type="button" className="cloud-btn cloud-btn-sm" onClick={replQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                                </div>
                            </div>
                            {replQ.loading ? <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                : replQ.error ? <div className="cloud-table-note">{replQ.error}</div>
                                    : (replQ.data || []).length === 0 ? (
                                        <CloudEmpty icon="Copy" title={t('cloud.replNone') || 'No replication jobs'}
                                            text={t('cloud.replNoneText') || 'This guest has no storage replication jobs. They are managed in the cluster Replication area.'} />
                                    ) : <div className="cloud-table-scroll"><table className="cloud-table">
                                        <thead><tr><th>{t('cloud.colJob') || 'Job'}</th><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colSchedule') || 'Schedule'}</th><th>{t('cloud.lastSync') || 'Last sync'}</th><th>{t('cloud.nextSync') || 'Next sync'}</th><th>{t('cloud.colStatus') || 'Status'}</th></tr></thead>
                                        <tbody>{(replQ.data || []).map(j => (
                                            <tr className="cloud-table-row cloud-table-row-static" key={j.id}>
                                                <td className="cloud-table-mono">{j.id}</td>
                                                <td>{j.target || ' - '}</td>
                                                <td>{j.schedule || ' - '}{j.disabled ? <span className="cloud-cell-muted"> ({t('cloud.disabled') || 'disabled'})</span> : ''}</td>
                                                <td className="cloud-table-mono cloud-cell-muted">{cloudFmtTs(j.last_sync) || ' - '}</td>
                                                <td className="cloud-table-mono cloud-cell-muted">{cloudFmtTs(j.next_sync) || ' - '}</td>
                                                <td>
                                                    {j.state === 'error' || j.last_state === 'error' ? <span className="cloud-hc-badge is-critical">ERROR</span>
                                                        : (j.state === 'syncing' || j.last_state === 'syncing') ? <span className="cloud-hc-badge is-unknown">SYNCING</span>
                                                        : (j.state === 'ok' || j.last_state === 'ok') ? <span className="cloud-hc-badge is-healthy">OK</span>
                                                        : <span className="cloud-hc-badge is-unknown">{String(j.state || j.last_state || ' - ').toUpperCase()}</span>}
                                                </td>
                                            </tr>
                                        ))}</tbody>
                                    </table></div>}
                            <div className="cloud-table-note">{t('cloud.replNote') || 'Jobs are created and managed centrally in the cluster Replication area.'}</div>
                        </div>
                    )}

                    {/* ── Tasks & Events ───────────────────────────────── */}
                    {tab === 'tasks' && (
                        <div className="cloud-card cloud-table-card">
                            <div className="cloud-toolbar">
                                <div className="cloud-toolbar-left"><span className="cloud-toolbar-title">{t('cloud.tabTasks') || 'Tasks & Events'}</span></div>
                                <div className="cloud-toolbar-right">
                                    <button type="button" className="cloud-btn cloud-btn-sm" onClick={taskQ.reload}><Icons.RotateCw /> {t('refresh') || 'Refresh'}</button>
                                </div>
                            </div>
                            {taskQ.loading ? <div className="cloud-table-note">{t('cloud.loading') || 'Loading…'}</div>
                                : taskQ.error ? <div className="cloud-table-note">{taskQ.error}</div>
                                    : (taskQ.data || []).length === 0 ? <CloudEmpty icon="Clock" title={t('cloud.noRecentTasks') || 'No recent tasks'} text={t('cloud.tasksNoneText') || 'Actions performed on this guest will appear here.'} />
                                        : <div className="cloud-table-scroll"><table className="cloud-table">
                                            <thead><tr><th></th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colId') || 'Target'}</th><th>{t('cloud.colNode') || 'Host'}</th><th>{t('cloud.colUser') || 'User'}</th><th>{t('cloud.colWhen') || 'When'}</th><th>{t('cloud.colResult') || 'Result'}</th></tr></thead>
                                            <tbody>{(taskQ.data || []).map((tk, i) => (
                                                <tr className="cloud-table-row" key={tk.upid || i}>
                                                    <td><span className={'cloud-task-dot ' + (tk.status === 'running' ? 'is-run' : tk.exitstatus === 'OK' || tk.status === 'OK' ? 'is-ok' : 'is-err')} /></td>
                                                    <td>{tk.type || 'task'}</td>
                                                    <td className="cloud-table-mono">{tk.id || ''}</td>
                                                    <td>{tk.node || ''}</td>
                                                    <td>{tk.pegaprox_user || tk.user || ''}</td>
                                                    <td className="cloud-table-mono cloud-cell-muted">{tk.starttime ? cloudFmtTs(tk.starttime) : ''}</td>
                                                    <td className="cloud-cell-muted">{tk.exitstatus || (tk.status === 'running' ? (t('cloud.running') || 'running') : ' - ')}</td>
                                                </tr>
                                            ))}</tbody>
                                        </table></div>}
                            <div className="cloud-table-note">{t('cloud.tasksNote') || 'Cluster task log filtered to this guest. Events beyond the retained task window live in the timeline.'}</div>
                        </div>
                    )}

                    {wiz && (
                        <BackupRestoreWizard
                            clusterId={cid} snapshot={wiz} datastoreName={wiz.storage}
                            nodes={[r.node]} storages={backupStorages.map(backupAbsStorage)}
                            authFetch={authFetch} apiUrl={API_URL}
                            onClose={() => setWiz(null)}
                            onStarted={() => { setWiz(null); addToast && addToast(t('cloud.taskStarted') || 'Task started', 'success'); }}
                        />
                    )}
                </div>
            );
        }

        // ── datastores ─────────────────────────────────────────────
        // datastore detail: capacity, contents, assigned guests - everything from the
        // real content endpoint; guests are matched by the vmid encoded in the volid.
        function CloudDatastores({ datastores, t }) {
            const ds = datastores || { shared: [], local: {} };
            const list = [];
            (Array.isArray(ds.shared) ? ds.shared : []).forEach(d => list.push({ ...d, scope: 'shared' }));
            const local = ds.local && typeof ds.local === 'object' ? ds.local : {};
            Object.keys(local).forEach(node => (Array.isArray(local[node]) ? local[node] : []).forEach(d => list.push({ ...d, scope: 'local', _node: node })));

            const [query, setQuery] = React.useState('');
            const q = query.trim().toLowerCase();
            const view = q ? list.filter(d => (d.storage || '').toLowerCase().includes(q) || (d.type || '').toLowerCase().includes(q)) : list;

            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.datastores') || 'Datastores'} sub={`${list.length} ${t('cloud.datastores') || 'datastores'}`} />
                    <div className="cloud-card cloud-table-card">
                        <div className="cloud-toolbar">
                            <div className="cloud-toolbar-left"><span className="cloud-toolbar-icon"><Icons.Database /></span><span className="cloud-toolbar-title">{t('cloud.datastores') || 'Datastores'}</span><span className="cloud-count-chip">{view.length}</span></div>
                            <div className="cloud-toolbar-right"><CloudSearch value={query} onChange={setQuery} placeholder={t('cloud.searchStorage') || 'Search storage…'} /></div>
                        </div>
                        {view.length === 0 ? <CloudEmpty icon="Database" title={t('cloud.noDatastores') || 'No datastores'} /> : (
                            <div className="cloud-table-scroll">
                                <table className="cloud-table">
                                    <thead><tr>
                                        <th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colScope') || 'Scope'}</th>
                                        <th>{t('cloud.colContent') || 'Content'}</th><th>{t('cloud.colUsage') || 'Usage'}</th><th>{t('cloud.colStatus') || 'Status'}</th>
                                    </tr></thead>
                                    <tbody>
                                        {view.map((d, i) => {
                                            const pct = d.used_fraction != null ? Math.round(d.used_fraction * 100) : (Number(d.total) ? Math.round(Number(d.used) / Number(d.total) * 100) : 0);
                                            return (
                                                <tr className="cloud-table-row cloud-table-row-static" key={(d.storage || 'ds') + '-' + i}>
                                                    <td><span className="cloud-table-name"><span className="cloud-table-name-icon"><Icons.HardDrive /></span>{d.storage || '—'}</span></td>
                                                    <td className="cloud-table-mono">{d.type || '—'}</td>
                                                    <td>{d.scope === 'shared' ? <span className="cloud-chip cloud-chip-soft">Shared</span> : <span className="cloud-chip cloud-chip-soft">{d._node || 'local'}</span>}</td>
                                                    <td className="cloud-cell-muted">{d.content || '—'}</td>
                                                    <td style={{ minWidth: 220 }}>
                                                        {Number(d.total) > 0 ? <CloudUsageBar pct={pct} leftLabel={cloudFmtBytes(d.used)} rightLabel={cloudFmtBytes(d.total)} /> : <span className="cloud-cell-muted">—</span>}
                                                    </td>
                                                    <td>{(d.active === 1 || d.active === true || d.enabled === 1) ? <CloudConnChip connected={true} t={t} /> : <CloudConnChip connected={false} t={t} />}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // ── networks ───────────────────────────────────────────────
        function CloudNetworks({ networks, t }) {
            const list = Array.isArray(networks) ? networks : [];
            const [query, setQuery] = React.useState('');
            const q = query.trim().toLowerCase();
            const view = q ? list.filter(n => (n.name || '').toLowerCase().includes(q) || (n.type || '').toLowerCase().includes(q)) : list;
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.networks') || 'Networks'} sub={`${list.length} ${t('cloud.networks') || 'networks'}`} />
                    <div className="cloud-card cloud-table-card">
                        <div className="cloud-toolbar">
                            <div className="cloud-toolbar-left"><span className="cloud-toolbar-icon"><Icons.Network /></span><span className="cloud-toolbar-title">{t('cloud.networks') || 'Networks'}</span><span className="cloud-count-chip">{view.length}</span></div>
                            <div className="cloud-toolbar-right"><CloudSearch value={query} onChange={setQuery} placeholder={t('cloud.searchNet') || 'Search bridge…'} /></div>
                        </div>
                        {view.length === 0 ? <CloudEmpty icon="Network" title={t('cloud.noNetworks') || 'No networks'} /> : (
                            <div className="cloud-table-scroll">
                                <table className="cloud-table">
                                    <thead><tr>
                                        <th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colCidr') || 'CIDR'}</th>
                                        <th>{t('cloud.colGateway') || 'Gateway'}</th><th>{t('cloud.colGuests') || 'Guests'}</th><th>{t('cloud.colNodes') || 'Hosts'}</th><th>{t('cloud.colStatus') || 'Status'}</th>
                                    </tr></thead>
                                    <tbody>
                                        {view.map((nw, i) => (
                                            <tr className="cloud-table-row cloud-table-row-static" key={(nw.name || 'nw') + '-' + i}>
                                                <td><span className="cloud-table-name"><span className="cloud-table-name-icon"><Icons.Network /></span>{nw.name || '—'}</span></td>
                                                <td className="cloud-table-mono">{nw.type || 'bridge'}</td>
                                                <td className="cloud-table-mono">{nw.cidr || nw.address || '—'}</td>
                                                <td className="cloud-table-mono">{nw.gateway || '—'}</td>
                                                <td>{Array.isArray(nw.vms) ? nw.vms.length : 0}</td>
                                                <td className="cloud-cell-muted">{Array.isArray(nw.nodes) ? nw.nodes.join(', ') : '—'}</td>
                                                <td>{nw.active ? <CloudConnChip connected={true} t={t} /> : <CloudConnChip connected={false} t={t} />}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // ── clusters ───────────────────────────────────────────────
        function CloudClusters({ clusters, resources, allClusterMetrics, t }) {
            const safe = Array.isArray(clusters) ? clusters : [];
            const res = Array.isArray(resources) ? resources : [];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.clustersTitle') || 'Clusters'} sub={`${safe.filter(c => c.connected).length} / ${safe.length} ${t('cloud.online') || 'online'}`} />
                    {safe.length === 0 ? <div className="cloud-card"><CloudEmpty icon="Cloud" title={t('cloud.noClusters') || 'No clusters configured'} /></div> : (
                        <div className="cloud-card-grid">
                            {safe.map(c => {
                                const cid = c && (c.id != null ? c.id : c.name);
                                const dc = allClusterMetrics && allClusterMetrics[cid] && allClusterMetrics[cid].data;
                                // clusterResources only carries the SELECTED cluster's guests (and unstamped),
                                // so per-card counts come from the cluster's datacenter-status payload. -- NS
                                const dcGuests = (dc && dc.guests) ? (dc.guests.vms.running + dc.guests.vms.stopped + dc.guests.containers.running + dc.guests.containers.stopped) : null;
                                const nodes = dc?.nodes;
                                return (
                                    <div className="cloud-card cloud-cluster-card" key={String(cid)}>
                                        <div className="cloud-cluster-head">
                                            <span className="cloud-cluster-name"><Icons.Cloud /> {(c && (c.display_name || c.name)) || 'cluster'}</span>
                                            <CloudConnChip connected={!!(c && c.connected)} t={t} />
                                        </div>
                                        <div className="cloud-cluster-host">{(c && c.host) || '—'}</div>
                                        <div className="cloud-cluster-badges">
                                            <span className="cloud-chip cloud-chip-soft">{cloudClusterTypeLabel(c && c.cluster_type)}</span>
                                            {dc?.cluster?.quorate === true && <span className="cloud-chip cloud-chip-soft">Quorate</span>}
                                            {dc?.cluster?.quorate === false && <span className="cloud-chip cloud-chip-warn">No quorum</span>}
                                            {dc?.cluster?.standalone && <span className="cloud-chip cloud-chip-soft">Standalone</span>}
                                            {dc?.hardware?.health === 'critical' && <span className="cloud-chip cloud-chip-err">{(t && t('degradedHardware')) || 'Degraded HW'}{dc.hardware.degraded ? ` (${dc.hardware.degraded})` : ''}</span>}
                                            {dc?.hardware?.health === 'warning' && <span className="cloud-chip cloud-chip-warn">{(t && t('degradedHardware')) || 'Degraded HW'}{dc.hardware.degraded ? ` (${dc.hardware.degraded})` : ''}</span>}
                                        </div>
                                        <div className="cloud-cluster-stats">
                                            <div><span className="cloud-cluster-stat-num">{nodes ? nodes.online : '—'}{nodes ? `/${nodes.total}` : ''}</span><span className="cloud-cluster-stat-lbl">{t('cloud.hosts') || 'Hosts'}</span></div>
                                            <div><span className="cloud-cluster-stat-num">{dcGuests != null ? dcGuests : '—'}</span><span className="cloud-cluster-stat-lbl">{t('cloud.guestsShort') || 'Guests'}</span></div>
                                            {dc?.resources?.memory && <div><span className="cloud-cluster-stat-num">{Math.round(dc.resources.memory.percent)}%</span><span className="cloud-cluster-stat-lbl">{t('cloud.ram') || 'RAM'}</span></div>}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            );
        }

        // ── nodes / hosts ──────────────────────────────────────────
        function CloudNodes({ metrics, act, isAdmin, t }) {
            const map = (metrics && typeof metrics === 'object') ? metrics : {};
            const names = Object.keys(map).sort();
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.hosts') || 'Hosts'} sub={`${names.length} ${t('cloud.hostsUnit') || 'hosts'}`} />
                    {names.length === 0 ? <div className="cloud-card"><CloudEmpty icon="Cpu" title={t('cloud.noNodes') || 'No host data'} text={t('cloud.selectCluster') || 'Select a connected cluster.'} /></div> : (
                        <div className="cloud-card-grid cloud-card-grid-wide">
                            {names.map(name => {
                                const m = map[name] || {};
                                const online = m.status === 'online' || (!m.offline && m.status !== 'offline');
                                const cpuP = Math.round(Number(m.cpu_percent) || 0);
                                const memP = Math.round(Number(m.mem_percent) || 0);
                                const diskP = Math.round(Number(m.disk_percent) || 0);
                                const maint = m.maintenance_mode;
                                // a standby keeps Manage host only (#625)
                                const nodeActions = !isAdmin ? [] : !act.has('nodeAction') ? [
                                    { label: t('cloud.manageHost') || 'Manage host', icon: 'Cog', onClick: () => act.configNode(name) },
                                ] : [
                                    { label: t('cloud.manageHost') || 'Manage host', icon: 'Cog', onClick: () => act.configNode(name) },
                                    { divider: true },
                                    maint
                                        ? { label: t('disableMaintenance') || 'Disable maintenance', icon: 'Wrench', onClick: () => act.maintenanceToggle(name, false) }
                                        : { label: t('startingMaintenanceMode') || 'Maintenance mode', icon: 'Wrench', onClick: () => act.maintenanceToggle(name, true) },
                                    { label: t('cloud.update') || 'Update (apt)', icon: 'Download', onClick: () => act.startUpdate(name, false) },
                                    { divider: true },
                                    { label: t('rebootNode') || 'Reboot', icon: 'RotateCw', danger: true, onClick: () => act.nodeAction(name, 'reboot') },
                                    { label: t('shutdownNode') || 'Shutdown', icon: 'Power', danger: true, onClick: () => act.nodeAction(name, 'shutdown') },
                                ];
                                return (
                                    <div className="cloud-card cloud-node-card" key={name}>
                                        <div className="cloud-node-head">
                                            <span className="cloud-node-name"><Icons.Cpu /> {name}</span>
                                            <div className="cloud-node-head-right">
                                                {maint ? <span className="cloud-chip cloud-chip-warn">Maintenance</span> : null}
                                                <CloudConnChip connected={online} t={t} />
                                                {isAdmin && <CloudActionMenu items={nodeActions} />}
                                            </div>
                                        </div>
                                        <div className="cloud-node-meters">
                                            <CloudUsageBar pct={cpuP} leftLabel={`${t('cloud.colCpu') || 'CPU'}`} rightLabel={`${cpuP}%`} />
                                            <CloudUsageBar pct={memP} color="#a855f7" leftLabel={`${t('cloud.ram') || 'RAM'}`} rightLabel={m.mem_total ? `${cloudFmtBytes(m.mem_used)} / ${cloudFmtBytes(m.mem_total)}` : `${memP}%`} />
                                            {m.disk_total ? <CloudUsageBar pct={diskP} color="#0ea5e9" leftLabel={`${t('cloud.disk') || 'Disk'}`} rightLabel={`${cloudFmtBytes(m.disk_used)} / ${cloudFmtBytes(m.disk_total)}`} /> : null}
                                        </div>
                                        <div className="cloud-node-foot">
                                            {m.uptime ? <span><Icons.Clock /> {cloudFmtUptime(m.uptime)}</span> : null}
                                            {m.cpuinfo?.cpus ? <span><Icons.Cpu /> {m.cpuinfo.cpus} cores</span> : null}
                                            {m.loadavg ? <span><Icons.Activity /> {Array.isArray(m.loadavg) ? m.loadavg[0] : m.loadavg}</span> : null}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            );
        }

        // ── resource pools ─────────────────────────────────────────
        function CloudPools({ pools, t }) {
            const list = Array.isArray(pools) ? pools : [];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.pools') || 'Resource Pools'} sub={`${list.length} ${t('cloud.pools') || 'pools'}`} />
                    {list.length === 0 ? <div className="cloud-card"><CloudEmpty icon="Layers" title={t('cloud.noPools') || 'No resource pools'} /></div> : (
                        <div className="cloud-card-grid">
                            {list.map((p, i) => (
                                <div className="cloud-card cloud-pool-card" key={(p.poolid || 'pool') + '-' + i}>
                                    <div className="cloud-cluster-head"><span className="cloud-cluster-name"><Icons.Layers /> {p.poolid || '—'}</span></div>
                                    {p.comment ? <div className="cloud-cluster-host" style={{ fontFamily: 'inherit' }}>{p.comment}</div> : null}
                                    <div className="cloud-cluster-stats">
                                        <div><span className="cloud-cluster-stat-num">{p.vms != null ? p.vms : 0}</span><span className="cloud-cluster-stat-lbl">{t('cloud.guestsShort') || 'Guests'}</span></div>
                                        <div><span className="cloud-cluster-stat-num">{p.storage != null ? p.storage : 0}</span><span className="cloud-cluster-stat-lbl">{t('cloud.storage') || 'Storage'}</span></div>
                                        <div><span className="cloud-cluster-stat-num">{p.member_count != null ? p.member_count : (Array.isArray(p.members) ? p.members.length : 0)}</span><span className="cloud-cluster-stat-lbl">{t('cloud.members') || 'Members'}</span></div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            );
        }

        // ── tasks ──────────────────────────────────────────────────
        function CloudTasks({ tasks, t }) {
            const list = Array.isArray(tasks) ? tasks : [];
            const [query, setQuery] = React.useState('');
            const q = query.trim().toLowerCase();
            const view = q ? list.filter(tk => (tk.type || '').toLowerCase().includes(q) || (tk.id || '').toLowerCase().includes(q) || (tk.node || '').toLowerCase().includes(q)) : list;
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.tasks') || 'Tasks'} sub={`${list.length} ${t('cloud.recent') || 'recent'}`} />
                    <div className="cloud-card cloud-table-card">
                        <div className="cloud-toolbar">
                            <div className="cloud-toolbar-left"><span className="cloud-toolbar-icon"><Icons.ClipboardList /></span><span className="cloud-toolbar-title">{t('cloud.tasks') || 'Tasks'}</span><span className="cloud-count-chip">{view.length}</span></div>
                            <div className="cloud-toolbar-right"><CloudSearch value={query} onChange={setQuery} placeholder={t('cloud.searchTasks') || 'Search task…'} /></div>
                        </div>
                        {view.length === 0 ? <CloudEmpty icon="ClipboardList" title={t('cloud.noTasks') || 'No tasks'} /> : (
                            <div className="cloud-table-scroll">
                                <table className="cloud-table">
                                    <thead><tr>
                                        <th>{t('cloud.colStatus') || 'Status'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colTarget') || 'Target'}</th>
                                        <th>{t('cloud.colNode') || 'Host'}</th><th>{t('cloud.colUser') || 'User'}</th><th>{t('cloud.colTime') || 'Started'}</th>
                                    </tr></thead>
                                    <tbody>
                                        {view.map((tk, i) => {
                                            const ok = tk.status === 'OK';
                                            const run = tk.status === 'running';
                                            return (
                                                <tr className="cloud-table-row cloud-table-row-static" key={tk.upid || i}>
                                                    <td>{run ? <CloudPill color="#2f9fe0" bg="rgba(56,189,248,0.14)" border="rgba(56,189,248,0.36)" dot>Running</CloudPill>
                                                        : ok ? <CloudPill color="#1bbf8a" bg="rgba(45,212,167,0.16)" border="rgba(45,212,167,0.42)" dot>OK</CloudPill>
                                                        : <CloudPill color="#e0686c" bg="rgba(248,113,113,0.14)" border="rgba(248,113,113,0.36)" dot>{tk.exitstatus || tk.status || 'Error'}</CloudPill>}</td>
                                                    <td className="cloud-table-mono">{tk.type || '—'}</td>
                                                    <td className="cloud-table-mono">{tk.id || '—'}</td>
                                                    <td>{tk.node || '—'}</td>
                                                    <td className="cloud-cell-muted">{tk.pegaprox_user || tk.user || '—'}</td>
                                                    <td className="cloud-cell-muted">{cloudRelTime(tk.starttime)}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // honest launcher for sections that live in the classic layout
        function CloudClassicLauncher({ title, icon, text, onExit, t }) {
            const Ico = Icons[icon] || Icons.Box;
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={title} />
                    <div className="cloud-card cloud-launcher">
                        <div className="cloud-launcher-icon"><Ico /></div>
                        <div className="cloud-launcher-text">{text}</div>
                        {typeof onExit === 'function' && (
                            <button type="button" className="cloud-btn cloud-btn-primary" onClick={onExit}><Icons.ExternalLink /> {t('cloud.openClassic') || 'Open in classic layout'}</button>
                        )}
                    </div>
                </div>
            );
        }

        // ── shell (top-level entry) ────────────────────────────────
        // ── cloud-native feature sections (phase 2) ────────────────
        // NS 2026-06-11 — per-cluster feature parity with the classic layout, in
        // cloud card-grid style. Each section self-fetches the same /api it always
        // used; read-first, management actions follow once the look is signed off.
        function useCloudData(path) {
            const { getAuthHeaders } = useAuth();
            const [data, setData] = React.useState(null);
            const [loading, setLoading] = React.useState(true);
            const [err, setErr] = React.useState(null);
            // LW Oct 2026 (#828) - only the newest request for the current path may answer: a
            // slow one for the cluster shown before must not replace the data, set an error
            // or end the load
            const seqRef = React.useRef(0);
            const pathRef = React.useRef(path);      // whose data is held
            const currentRef = React.useRef(path);
            currentRef.current = path;
            const reload = React.useCallback(() => {
                // the reload a mutation kept from before the switch
                if (currentRef.current !== path) return;
                const seq = ++seqRef.current;
                if (pathRef.current !== path) { pathRef.current = path; setData(null); }
                if (!path) { setLoading(false); setErr(null); return; }
                setLoading(true); setErr(null);
                fetch(path, { headers: getAuthHeaders() })
                    .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))
                    .then(d => { if (seq !== seqRef.current) return; setData(d); setLoading(false); })
                    .catch(e => { if (seq !== seqRef.current) return; setErr(String(e && e.message || e)); setLoading(false); });
            }, [path]);
            React.useEffect(() => { reload(); return () => { seqRef.current++; }; }, [reload]);
            return { data, loading, err, reload };
        }
        function CloudSectionState({ loading, err, empty, emptyIcon, emptyTitle, emptyText, t, children }) {
            if (loading) return <div className="cloud-card"><div className="cloud-empty">{t('loading') || 'Loading…'}</div></div>;
            if (err) return <div className="cloud-card"><CloudEmpty icon="AlertTriangle" title={t('cloud.loadFail') || 'Could not load'} text={err} /></div>;
            if (empty) return <div className="cloud-card"><CloudEmpty icon={emptyIcon || 'Box'} title={emptyTitle} text={emptyText} /></div>;
            return children;
        }
        function cloudHead(p) { return <div className="cloud-toolbar"><div className="cloud-toolbar-left"><span className="cloud-toolbar-icon">{p.icon}</span><span className="cloud-toolbar-title">{p.title}</span><span className="cloud-count-chip">{p.count}</span></div>{p.right ? <div className="cloud-toolbar-right">{p.right}</div> : null}</div>; }
        // NS 2026-06-11 — mutation helper for the cloud sections (phase 3). POST/PUT/
        // DELETE with auth, optional confirm() for destructive ops, reload on success.
        // #625: `acts` is false on a standby, and the pages show their changing buttons
        // only with it; a refusal that still comes back says why, in the user's language.
        // True again on a standby that forwards; the active out of reach says so too.
        // A member that serves users names the leader in both.
        function useCloudMutate(reload) {
            const { getAuthHeaders, haReadOnly, haServing } = useAuth();
            const { t } = useTranslation();
            const [busy, setBusy] = React.useState('');
            const run = React.useCallback((key, method, path, body, confirmMsg) => {
                if (confirmMsg && !window.confirm(confirmMsg)) return;
                setBusy(key);
                const opts = { method, headers: Object.assign({}, getAuthHeaders(), { 'Content-Type': 'application/json' }) };
                if (body !== undefined) opts.body = JSON.stringify(body);
                fetch(path, opts)
                    .then(r => r.ok ? r.json().catch(() => ({})) : r.json().catch(() => ({})).then(b => Promise.reject(
                        new Error(b && b.code === 'HA_STANDBY' ? (haServing ? t('pgHaServingRefused') : t('pgHaStandbyRefused'))
                            : b && b.code === 'HA_ACTIVE_UNREACHABLE' ? (haServing ? t('pgHaLeaderUnreachable') : t('pgHaActiveUnreachable'))
                            : 'HTTP ' + r.status))))
                    .then(() => { setBusy(''); if (reload) reload(); })
                    .catch(e => { setBusy(''); window.alert('Action failed: ' + (e && e.message || e)); });
            }, [reload, t, haServing]);
            return { busy, run, acts: !haReadOnly };
        }
        function CloudRowActions({ children }) { return <td><div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>{children}</div></td>; }

        // ── Backups (vzdump jobs) ──────────────────────────────────
        // LW Oct 2026 - the restore tests of the cluster under its backup jobs: how many guests
        // passed one recently, and the ones that did not. Read only; the schedule and what the
        // tests check are set in the classic views.
        const CLOUD_RT_PAGE = 25;
        function CloudRestoreTests({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/recovery-report` : null);
            // LW Oct 2026 - the share of critical and of all guests proven recoverable, from the assurance read
            const asr = useCloudData(clusterId ? `/api/clusters/${clusterId}/recovery-assurance` : null);
            const cov = (asr.data && asr.data.coverage) || null;
            const gapTotal = asr.data ? Object.values(asr.data.gap_counts || {}).reduce((x, y) => x + y, 0) : 0;
            const [page, setPage] = React.useState(0);
            const rows = ((data && data.guests) || []).filter(g => g.state !== 'ok');
            const sum = (data && data.summary) || {};
            const stateText = (s) => ({ stale: t('rtestStateStale'), failing: t('rtestStateFailing'), never: t('rtestStateNever'),
                rto_missed: t('rtestStateRto') })[s] || s;
            const chip = (s) => (s === 'failing' ? 'cloud-chip-err' : s === 'never' || s === 'stale' ? 'cloud-chip-warn' : 'cloud-chip-soft');
            const safePage = Math.min(page, Math.max(0, Math.ceil(rows.length / CLOUD_RT_PAGE) - 1));
            const kpis = [
                { icon: 'LifeBuoy', value: sum.total ?? 0, label: t('rtestTileTotal'), accent: '#6366f1' },
                { icon: 'CheckCircle', value: sum.ok ?? 0, label: t('rtestStateOk'), accent: '#22c55e' },
                { icon: 'XCircle', value: sum.failing ?? 0, label: t('rtestStateFailing'), accent: sum.failing ? '#ef4444' : '#14b8a6' },
                { icon: 'AlertTriangle', value: (sum.never ?? 0) + (sum.stale ?? 0), label: t('rtestCloudNotRecent'), accent: '#f59e0b' },
                ...(cov ? [
                    { icon: 'Shield', value: cov.critical.percent == null ? '-' : `${cov.critical.percent}%`, label: t('rasrCloudCritical'), accent: cov.critical.percent == null ? '#6b7280' : cov.critical.percent >= 90 ? '#22c55e' : '#ef4444', attr: 'critical' },
                    { icon: 'AlertTriangle', value: gapTotal, label: t('rasrCloudGaps'), accent: gapTotal ? '#f59e0b' : '#14b8a6', attr: 'gaps' },
                ] : []),
            ];
            return (
                <div data-rtest-cloud={clusterId}>
                    <CloudSectionTitle right={<span style={{ display: 'flex', gap: 8 }}>
                        <a className="cloud-link-btn" href={`/api/clusters/${clusterId}/recovery-report?format=csv`} download data-rtest-csv><Icons.Download /> {t('rtestExportCsv')}</a>
                        <a className="cloud-link-btn" href={`/api/clusters/${clusterId}/recovery-evidence`} download data-rasr-export="json"><Icons.Download /> {t('rasrExportJson')}</a>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </span>}>{t('rtestTitle')}</CloudSectionTitle>
                    <CloudSectionState loading={loading} err={err} empty={!!data && !(data.guests || []).length} emptyIcon="LifeBuoy" emptyTitle={t('rtestNoGuests')} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <div key={i} style={{ display: 'contents' }} data-rasr-cloud-kpi={k.attr || ''}><CloudKpiCard icon={k.icon} value={k.value} label={k.label} accent={k.accent} /></div>)}</div>
                        {rows.length > 0 && (
                            <div className="cloud-card cloud-table-card">
                                {cloudHead({ icon: <Icons.LifeBuoy />, title: t('rtestCloudAttention'), count: rows.length })}
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('rtestColGuest')}</th><th>{t('rtestColState')}</th><th>{t('rtestColPassed')}</th><th>{t('rtestColFailure')}</th></tr></thead>
                                    <tbody>{rows.slice(safePage * CLOUD_RT_PAGE, (safePage + 1) * CLOUD_RT_PAGE).map(g => (
                                        <tr className="cloud-table-row cloud-table-row-static" key={g.vmid} data-rtest-row={g.vmid} data-state={g.state}>
                                            <td><span className="cloud-table-mono">{g.vmid}</span> {g.name || ''}</td>
                                            <td><span className={`cloud-chip ${chip(g.state)}`}>{stateText(g.state)}</span></td>
                                            <td className="cloud-cell-muted">{g.last_success_at ? new Date(g.last_success_at).toLocaleString() : t('rtestNever')}</td>
                                            <td className="cloud-cell-muted">{g.last_failure_cause || ''}</td>
                                        </tr>
                                    ))}</tbody>
                                </table></div>
                                <CloudPager page={safePage} pageSize={CLOUD_RT_PAGE} total={rows.length} onPage={setPage} />
                            </div>
                        )}
                    </CloudSectionState>
                </div>
            );
        }

        function CloudBackups({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/backup` : null);
            const mut = useCloudMutate(reload);
            const [runsOf, setRunsOf] = React.useState(null);
            // LW Oct 2026 - Proxmox hands no last-run status with a job; the newest run of each
            // comes from the job history (.../last-runs), after the list itself and again
            // after every reload of it (Refresh, Run now)
            const listedAt = React.useMemo(() => (Array.isArray(data) && data.length ? Date.now() : 0), [data]);
            const last = useCloudData(clusterId && listedAt ? `/api/clusters/${clusterId}/datacenter/backup/last-runs?at=${listedAt}` : null);
            const lastRuns = (last.data && last.data.jobs) || {};
            const jobs = Array.isArray(data) ? data : [];
            const active = jobs.filter(j => Number(j.enabled) === 1 || j.enabled === true).length;
            const failed = jobs.filter(j => (lastRuns[j.id] || {}).state === 'failed').length;
            const runChip = (run) => {
                if (!run) return <span className="cloud-cell-muted">{last.loading ? '…' : '-'}</span>;
                const label = { ok: t('bkpRunsStateOk'), warning: t('bkpRunsStateWarning'), failed: t('failed'), running: t('bkpRunsStateRunning') }[run.state] || run.state;
                const cls = run.state === 'ok' ? 'cloud-chip-ok' : run.state === 'failed' ? 'cloud-chip-err' : 'cloud-chip-soft';
                const when = run.start ? new Date(run.start * 1000).toLocaleString() : '';
                return <span className={`cloud-chip ${cls}`} title={when} data-last-run={run.state}>{label}</span>;
            };
            const kpis = [
                { icon: 'Archive', value: jobs.length, label: t('cloud.bkpJobs') || 'Backup jobs', accent: '#6366f1' },
                { icon: 'CheckCircle', value: active, label: t('cloud.bkpActive') || 'Enabled', accent: '#22c55e' },
                { icon: failed ? 'XCircle' : 'Shield', value: failed, label: t('cloud.bkpFailed') || 'Failed last run', accent: failed ? '#ef4444' : '#14b8a6' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.backups') || 'Backups'} sub={t('cloud.backupsSub') || 'Scheduled backup jobs'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!jobs.length} emptyIcon="Archive" emptyTitle={t('cloud.noBackups') || 'No backup jobs configured'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Archive />, title: t('cloud.backups') || 'Backups', count: jobs.length })}
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colSchedule') || 'Schedule'}</th><th>{t('cloud.colGuests') || 'Guests'}</th><th>{t('cloud.colStorage') || 'Storage'}</th><th>{t('cloud.colMode') || 'Mode'}</th><th>{t('cloud.colStatus') || 'Status'}</th><th>{t('cloud.colState') || 'State'}</th><th style={{ textAlign: 'right' }}>{t('cloud.colActions') || ''}</th></tr></thead>
                                <tbody>{jobs.map((j, i) => {
                                    return (<tr className="cloud-table-row cloud-table-row-static" key={j.id || i}>
                                        <td className="cloud-table-mono">{j.schedule || '—'}</td>
                                        <td>{(Number(j.all) === 1) ? <span className="cloud-chip cloud-chip-soft">{t('cloud.allGuests') || 'All guests'}</span> : <span className="cloud-table-mono">{j.vmid || '—'}</span>}</td>
                                        <td>{j.storage || '—'}</td>
                                        <td className="cloud-cell-muted">{j.mode || 'snapshot'}{j.compress && j.compress !== '0' ? ' · ' + j.compress : ''}</td>
                                        <td>{runChip(lastRuns[j.id])}</td>
                                        <td>{(Number(j.enabled) === 1 || j.enabled === true) ? <CloudConnChip connected={true} t={t} /> : <CloudConnChip connected={false} t={t} />}</td>
                                        <CloudRowActions>
                                            {mut.acts && (<>
                                            <CloudIconBtn icon="Play" title={t('cloud.runNow') || 'Run now'} onClick={() => mut.run('r' + j.id, 'POST', `/api/clusters/${clusterId}/datacenter/backup/${j.id}/run`)} />
                                            <CloudIconBtn icon="Power" title={(Number(j.enabled) === 1 || j.enabled === true) ? (t('disable') || 'Disable') : (t('enable') || 'Enable')} onClick={() => mut.run('t' + j.id, 'PUT', `/api/clusters/${clusterId}/datacenter/backup/${j.id}`, { enabled: (Number(j.enabled) === 1 || j.enabled === true) ? 0 : 1 })} />
                                            <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + j.id, 'DELETE', `/api/clusters/${clusterId}/datacenter/backup/${j.id}`, undefined, (t('cloud.confirmDelBackup') || 'Delete this backup job?'))} />
                                            </>)}
                                            <CloudIconBtn icon="Clock" title={t('bkpRunsHistory') || 'Run history'} onClick={() => setRunsOf(j)} />
                                        </CloudRowActions>
                                    </tr>);
                                })}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
                    <CloudRestoreTests clusterId={clusterId} t={t} />
                    {runsOf && <BackupJobRunsModal clusterId={clusterId} job={runsOf} onClose={() => setRunsOf(null)} />}
                </div>
            );
        }

        // ── Firewall (datacenter rules) ────────────────────────────
        function CloudFirewall({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/firewall/rules` : null);
            const mut = useCloudMutate(reload);
            const rules = Array.isArray(data) ? data : (data && Array.isArray(data.rules) ? data.rules : []);
            const inn = rules.filter(r => (r.type || '').toLowerCase() === 'in').length;
            const out = rules.filter(r => (r.type || '').toLowerCase() === 'out').length;
            const kpis = [
                { icon: 'Shield', value: rules.length, label: t('cloud.fwRules') || 'Rules', accent: '#6366f1' },
                { icon: 'Lock', value: inn, label: t('cloud.fwIn') || 'Inbound', accent: '#0ea5e9' },
                { icon: 'Globe', value: out, label: t('cloud.fwOut') || 'Outbound', accent: '#a855f7' },
            ];
            const actChip = a => { const u = (a || '').toUpperCase(); const cls = u === 'ACCEPT' ? 'cloud-chip-ok' : (u === 'DROP' || u === 'REJECT') ? 'cloud-chip-err' : 'cloud-chip-soft'; return <span className={'cloud-chip ' + cls}>{u || '—'}</span>; };
            const [showNew, setShowNew] = React.useState(false);
            const [form, setForm] = React.useState({ type: 'in', action: 'ACCEPT', proto: '', dport: '', source: '', dest: '', comment: '' });
            const submitNew = () => {
                if (!clusterId) { window.alert(t('cloud.noClusterSel') || 'No cluster selected.'); return; }
                const body = { type: form.type, action: form.action, enable: 1 };
                ['proto', 'dport', 'source', 'dest', 'comment'].forEach(k => { if (String(form[k]).trim()) body[k] = String(form[k]).trim(); });
                // Guard against an unconstrained ACCEPT rule (no proto/port/source/dest = allow-all).
                const constrained = ['proto', 'dport', 'source', 'dest'].some(k => body[k]);
                if (form.action === 'ACCEPT' && !constrained) {
                    if (!window.confirm(t('cloud.fwAllowAllWarn') || 'This ACCEPT rule matches ALL traffic (no protocol, port, source or destination set). Create this allow-all rule anyway?')) return;
                }
                mut.run('newrule', 'POST', `/api/clusters/${clusterId}/datacenter/firewall/rules`, body);
                setShowNew(false); setForm({ type: 'in', action: 'ACCEPT', proto: '', dport: '', source: '', dest: '', comment: '' });
            };
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.firewall') || 'Firewall'} sub={t('cloud.firewallSub') || 'Datacenter firewall rules'}>
                        {mut.acts && <button type="button" className="cloud-link-btn" onClick={() => setShowNew(true)}><Icons.Plus /> {t('cloud.newRule') || 'New rule'}</button>}
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!rules.length} emptyIcon="Shield" emptyTitle={t('cloud.noFwRules') || 'No datacenter firewall rules'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Shield />, title: t('cloud.firewall') || 'Firewall', count: rules.length })}
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>#</th><th>{t('cloud.colDir') || 'Dir'}</th><th>{t('cloud.colAction') || 'Action'}</th><th>{t('cloud.colProto') || 'Proto'}</th><th>{t('cloud.colPort') || 'Port'}</th><th>{t('cloud.colSource') || 'Source'}</th><th>{t('cloud.colDest') || 'Dest'}</th><th>{t('cloud.colComment') || 'Comment'}</th><th>{t('cloud.colState') || 'State'}</th><th style={{ textAlign: 'right' }}>{t('cloud.colActions') || ''}</th></tr></thead>
                                <tbody>{rules.map((r, i) => (<tr className="cloud-table-row cloud-table-row-static" key={r.pos != null ? r.pos : i}>
                                    <td className="cloud-cell-muted">{r.pos != null ? r.pos : i}</td>
                                    <td><span className="cloud-chip cloud-chip-soft">{(r.type || '').toUpperCase() || '—'}</span></td>
                                    <td>{actChip(r.action)}</td>
                                    <td className="cloud-table-mono">{r.proto || '—'}</td>
                                    <td className="cloud-table-mono">{r.dport || '—'}</td>
                                    <td className="cloud-table-mono">{r.source || '—'}</td>
                                    <td className="cloud-table-mono">{r.dest || '—'}</td>
                                    <td className="cloud-cell-muted">{r.comment || ''}</td>
                                    <td>{(Number(r.enable) === 1 || r.enable === true) ? <CloudConnChip connected={true} t={t} /> : <CloudConnChip connected={false} t={t} />}</td>
                                    <CloudRowActions>
                                        {mut.acts && (<>
                                        <CloudIconBtn icon="Power" title={(Number(r.enable) === 1 || r.enable === true) ? (t('disable') || 'Disable') : (t('enable') || 'Enable')} onClick={() => mut.run('t' + r.pos, 'PUT', `/api/clusters/${clusterId}/datacenter/firewall/rules/${r.pos}`, { enable: (Number(r.enable) === 1 || r.enable === true) ? 0 : 1 })} />
                                        <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + r.pos, 'DELETE', `/api/clusters/${clusterId}/datacenter/firewall/rules/${r.pos}`, undefined, (t('cloud.confirmDelRule') || 'Delete this firewall rule?'))} />
                                        </>)}
                                    </CloudRowActions>
                                </tr>))}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
                    {showNew && (
                        <CloudModal title={t('cloud.newRule') || 'New firewall rule'} onClose={() => setShowNew(false)} onSubmit={submitNew} submitLabel={t('create') || 'Create'} t={t}>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('cloud.colDir') || 'Direction'}><select className="cloud-input" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}><option value="in">in</option><option value="out">out</option></select></CloudField>
                                <CloudField label={t('cloud.colAction') || 'Action'}><select className="cloud-input" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>{['ACCEPT', 'DROP', 'REJECT'].map(a => <option key={a} value={a}>{a}</option>)}</select></CloudField>
                            </div>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('cloud.colProto') || 'Protocol'}><input className="cloud-input" value={form.proto} onChange={e => setForm({ ...form, proto: e.target.value })} placeholder="tcp" /></CloudField>
                                <CloudField label={t('cloud.colPort') || 'Dest port'}><input className="cloud-input" value={form.dport} onChange={e => setForm({ ...form, dport: e.target.value })} placeholder="22" /></CloudField>
                            </div>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('cloud.colSource') || 'Source'}><input className="cloud-input" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} placeholder="0.0.0.0/0" /></CloudField>
                                <CloudField label={t('cloud.colDest') || 'Dest'}><input className="cloud-input" value={form.dest} onChange={e => setForm({ ...form, dest: e.target.value })} /></CloudField>
                            </div>
                            <CloudField label={t('cloud.colComment') || 'Comment'}><input className="cloud-input" value={form.comment} onChange={e => setForm({ ...form, comment: e.target.value })} /></CloudField>
                        </CloudModal>
                    )}
                </div>
            );
        }

        // ── Storage (datacenter config) ────────────────────────────
        function CloudStorage({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/storage` : null);
            const list = Array.isArray(data) ? data : [];
            const shared = list.filter(s => Number(s.shared) === 1 || s.shared === true).length;
            const types = new Set(list.map(s => s.type).filter(Boolean));
            const kpis = [
                { icon: 'Database', value: list.length, label: t('cloud.stStorages') || 'Storages', accent: '#6366f1' },
                { icon: 'Layers', value: shared, label: t('cloud.stShared') || 'Shared', accent: '#14b8a6' },
                { icon: 'HardDrive', value: types.size, label: t('cloud.stTypes') || 'Types', accent: '#a855f7' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.storageConfig') || 'Storage'} sub={t('cloud.storageConfigSub') || 'Datacenter storage configuration'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!list.length} emptyIcon="Database" emptyTitle={t('cloud.noStorage') || 'No storage configured'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Database />, title: t('cloud.storageConfig') || 'Storage', count: list.length })}
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colContent') || 'Content'}</th><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colShared') || 'Shared'}</th><th>{t('cloud.colState') || 'State'}</th></tr></thead>
                                <tbody>{list.map((s, i) => (<tr className="cloud-table-row cloud-table-row-static" key={s.storage || i}>
                                    <td><span className="cloud-table-name"><span className="cloud-table-name-icon"><Icons.HardDrive /></span>{s.storage || '—'}</span></td>
                                    <td className="cloud-table-mono">{s.type || '—'}</td>
                                    <td className="cloud-cell-muted">{s.content || '—'}</td>
                                    <td className="cloud-table-mono">{s.path || s.export || s.target || s.pool || s.server || '—'}</td>
                                    <td>{(Number(s.shared) === 1 || s.shared === true) ? <span className="cloud-chip cloud-chip-soft">Shared</span> : <span className="cloud-cell-muted">local</span>}</td>
                                    <td>{(Number(s.disable) === 1 || s.disable === true) ? <CloudConnChip connected={false} t={t} /> : <CloudConnChip connected={true} t={t} />}</td>
                                </tr>))}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
                </div>
            );
        }

        // ── PBS (backup servers) ───────────────────────────────────
        function CloudPBS({ t }) {
            const { data, loading, err, reload } = useCloudData('/api/pbs');
            const list = Array.isArray(data) ? data : [];
            const online = list.filter(p => p.connected).length;
            const kpis = [
                { icon: 'Server', value: list.length, label: t('cloud.pbsServers') || 'PBS servers', accent: '#6366f1' },
                { icon: online === list.length && list.length ? 'CheckCircle' : 'AlertTriangle', value: `${online}/${list.length}`, label: t('cloud.pbsOnline') || 'Online', accent: online === list.length ? '#22c55e' : '#f59e0b' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.pbs') || 'Backup Servers'} sub={t('cloud.pbsSub') || 'Proxmox Backup Server targets'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!list.length} emptyIcon="Server" emptyTitle={t('cloud.noPbs') || 'No backup servers configured'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        <div className="cloud-card-grid">{list.map((p, i) => (
                            <div className="cloud-card" key={p.id || i}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                                    <span style={{ display: 'inline-flex' }}><Icons.Server /></span>
                                    <strong>{p.name || p.host || 'PBS'}</strong>
                                    <span style={{ marginLeft: 'auto' }}><CloudConnChip connected={!!p.connected} t={t} /></span>
                                </div>
                                <div className="cloud-util-breakdown">
                                    <div className="cloud-util-row"><span>{t('cloud.colHost') || 'Host'}</span><span className="cloud-table-mono">{p.host || '—'}:{p.port || 8007}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.colClusters') || 'Linked clusters'}</span><span>{Array.isArray(p.linked_clusters) ? p.linked_clusters.length : (p.linked_clusters || 0)}</span></div>
                                    {p.last_error ? <div className="cloud-util-row"><span>{t('cloud.colError') || 'Last error'}</span><span className="cloud-cell-muted" style={{ color: '#ef4444' }}>{String(p.last_error).slice(0, 60)}</span></div> : null}
                                </div>
                            </div>
                        ))}</div>
                    </CloudSectionState>
                </div>
            );
        }

        // ── Site Recovery (DR plans) ───────────────────────────────
        function CloudSiteRecovery({ t }) {
            const { data, loading, err, reload } = useCloudData('/api/site-recovery/plans');
            const list = Array.isArray(data) ? data : [];
            const auto = list.filter(p => p.auto_failover).length;
            const kpis = [
                { icon: 'LifeBuoy', value: list.length, label: t('cloud.srPlans') || 'Recovery plans', accent: '#6366f1' },
                { icon: 'RefreshCw', value: auto, label: t('cloud.srAuto') || 'Auto-failover', accent: '#f59e0b' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.siteRecovery') || 'Site Recovery'} sub={t('cloud.siteRecoverySub') || 'Disaster-recovery plans'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!list.length} emptyIcon="LifeBuoy" emptyTitle={t('cloud.noSrPlans') || 'No recovery plans'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        <div className="cloud-card-grid">{list.map((p, i) => (
                            <div className="cloud-card" key={p.id || i}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                                    <span style={{ display: 'inline-flex' }}><Icons.LifeBuoy /></span>
                                    <strong>{p.name || ('plan-' + i)}</strong>
                                    {p.auto_failover ? <span className="cloud-chip cloud-chip-soft" style={{ marginLeft: 'auto' }}>{t('cloud.srAuto') || 'Auto'}</span> : null}
                                </div>
                                <div className="cloud-util-breakdown">
                                    <div className="cloud-util-row"><span>{t('cloud.colSource') || 'Source'}</span><span className="cloud-table-mono">{p.source_cluster || '—'}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.srTimeout') || 'Failover timeout'}</span><span>{p.failover_timeout != null ? p.failover_timeout + 's' : '—'}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.srLastTest') || 'Last test'}</span><span>{p.last_test ? cloudRelTime(p.last_test) : (t('cloud.never') || 'never')}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.srLastFailover') || 'Last failover'}</span><span>{p.last_failover ? cloudRelTime(p.last_failover) : (t('cloud.never') || 'never')}</span></div>
                                </div>
                            </div>
                        ))}</div>
                    </CloudSectionState>
                </div>
            );
        }

        // ── Ceph ───────────────────────────────────────────────────
        function CloudCeph({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/ceph` : null);
            const c = data || {};
            const notAvail = !c.available;
            const mons = Array.isArray(c.mon) ? c.mon : [];
            const osds = Array.isArray(c.osd) ? c.osd : [];
            const pools = Array.isArray(c.pools) ? c.pools : [];
            // #735 (mdobprv-lab) — flattened CRUSH-tree OSD entries carry status:"up", not a boolean
            // up; the node/datacenter Ceph UIs already key on o.status. Count that, keep o.up fallback.
            const osdUp = osds.filter(o => String(o.status || '').toLowerCase() === 'up' || o.up === 1 || o.up === true).length;
            // #735 — Proxmox /ceph/status returns health as an OBJECT ({status:"HEALTH_OK",...}); pull the
            // scalar out first, or String(health) renders as "[object Object]".
            const _healthRaw = (c.status && (c.status.health || c.status.health_status)) || c.health || 'unknown';
            const health = (_healthRaw && typeof _healthRaw === 'object') ? (_healthRaw.status || _healthRaw.health_status || 'unknown') : _healthRaw;
            const kpis = [
                { icon: 'Heart', value: String(health).toUpperCase(), label: t('cloud.cephHealth') || 'Health', accent: /ok|healthy/i.test(String(health)) ? '#22c55e' : '#f59e0b' },
                { icon: 'Database', value: mons.length, label: t('cloud.cephMons') || 'Monitors', accent: '#6366f1' },
                { icon: 'HardDrive', value: `${osdUp}/${osds.length}`, label: t('cloud.cephOsds') || 'OSDs up', accent: '#0ea5e9' },
                { icon: 'Layers', value: pools.length, label: t('cloud.cephPools') || 'Pools', accent: '#a855f7' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.ceph') || 'Ceph'} sub={t('cloud.cephSub') || 'Distributed storage'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err || (c.read_failed ? t('cephReadFailedDesc') : null)} empty={notAvail} emptyIcon="Database" emptyTitle={t('cloud.cephNA') || 'Ceph is not configured on this cluster'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        {pools.length ? (
                            <div className="cloud-card cloud-table-card">
                                {cloudHead({ icon: <Icons.Layers />, title: t('cloud.cephPools') || 'Pools', count: pools.length })}
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colSize') || 'Size'}</th><th>PG</th><th>{t('cloud.colUsage') || 'Usage'}</th></tr></thead>
                                    <tbody>{pools.map((p, i) => (<tr className="cloud-table-row cloud-table-row-static" key={p.pool_name || p.name || i}>
                                        <td>{p.pool_name || p.name || '—'}</td>
                                        <td className="cloud-table-mono">{p.size != null ? p.size : '—'}</td>
                                        <td className="cloud-table-mono">{p.pg_num != null ? p.pg_num : '—'}</td>
                                        <td>{Number(p.bytes_total) > 0 ? <CloudUsageBar pct={Math.round(Number(p.bytes_used) / Number(p.bytes_total) * 100)} leftLabel={cloudFmtBytes(p.bytes_used)} rightLabel={cloudFmtBytes(p.bytes_total)} /> : <span className="cloud-cell-muted">—</span>}</td>
                                    </tr>))}</tbody>
                                </table></div>
                            </div>
                        ) : null}
                    </CloudSectionState>
                </div>
            );
        }

        // ── SDN ────────────────────────────────────────────────────
        // simple centered modal used by the cloud-native CRUD views
        function CloudModal({ title, onClose, onSubmit, submitLabel, children, t }) {
            return (
                <div className="cloud-modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 70, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.55)' }} onClick={onClose}>
                    <div className="cloud-card" style={{ width: 'min(460px,92vw)', padding: 0 }} onClick={e => e.stopPropagation()}>
                        {cloudHead({ icon: <Icons.Plus />, title, right: <CloudIconBtn icon="X" title={t('close') || 'Close'} onClick={onClose} /> })}
                        <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }}>
                            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>{children}</div>
                            <div className="cloud-modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, padding: '12px 16px', borderTop: '1px solid var(--cloud-divider)' }}>
                                <button type="button" className="cloud-link-btn" onClick={onClose}>{t('cancel') || 'Cancel'}</button>
                                <button type="submit" className="cloud-btn-primary">{submitLabel || (t('create') || 'Create')}</button>
                            </div>
                        </form>
                    </div>
                </div>
            );
        }
        function CloudField({ label, children }) {
            return <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem', color: 'var(--cloud-text-secondary)' }}>{label}{children}</label>;
        }

        function CloudSDN({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/sdn` : null);
            const mut = useCloudMutate(reload);
            const s = data || {};
            const base = `/api/clusters/${clusterId}/datacenter/sdn`;
            const zones = Array.isArray(s.zones) ? s.zones : [];
            const vnets = Array.isArray(s.vnets) ? s.vnets : [];
            const subnets = Array.isArray(s.subnets) ? s.subnets : [];
            const controllers = Array.isArray(s.controllers) ? s.controllers : [];
            const notAvail = !s.available && !zones.length && !vnets.length;
            const [modal, setModal] = React.useState(null); // 'zone' | 'vnet'
            const [zForm, setZForm] = React.useState({ zone: '', type: 'vlan', bridge: '', peers: '', controller: '' });
            const [vForm, setVForm] = React.useState({ vnet: '', zone: '' });
            const submitZone = () => {
                if (!clusterId) { window.alert(t('cloud.noClusterSel') || 'No cluster selected.'); return; }
                const body = { zone: zForm.zone.trim(), type: zForm.type };
                if (zForm.type === 'vlan' || zForm.type === 'qinq') body.bridge = zForm.bridge.trim();
                if (zForm.type === 'vxlan') body.peers = zForm.peers.trim();
                if (zForm.type === 'evpn') body.controller = zForm.controller.trim();
                if (!body.zone) return;
                mut.run('addzone', 'POST', `${base}/zones`, body); setModal(null); setZForm({ zone: '', type: 'vlan', bridge: '', peers: '', controller: '' });
            };
            const submitVnet = () => {
                if (!clusterId) { window.alert(t('cloud.noClusterSel') || 'No cluster selected.'); return; }
                if (!vForm.vnet.trim() || !vForm.zone) return;
                mut.run('addvnet', 'POST', `${base}/vnets`, { vnet: vForm.vnet.trim(), zone: vForm.zone }); setModal(null); setVForm({ vnet: '', zone: '' });
            };
            const [sForm, setSForm] = React.useState({ vnet: '', subnet: '', gateway: '', dhcp: 'none', snat: false });
            const submitSubnet = () => {
                if (!clusterId) { window.alert(t('cloud.noClusterSel') || 'No cluster selected.'); return; }
                if (!sForm.vnet || !sForm.subnet.trim()) return;
                const body = { subnet: sForm.subnet.trim(), snat: sForm.snat ? 1 : 0 };
                if (sForm.gateway.trim()) body.gateway = sForm.gateway.trim();
                if (sForm.dhcp && sForm.dhcp !== 'none') body.dhcp = sForm.dhcp;
                mut.run('addsubnet', 'POST', `${base}/vnets/${sForm.vnet}/subnets`, body); setModal(null); setSForm({ vnet: '', subnet: '', gateway: '', dhcp: 'none', snat: false });
            };
            const kpis = [
                { icon: 'Globe', value: zones.length, label: t('cloud.sdnZones') || 'Zones', accent: '#6366f1' },
                { icon: 'Network', value: vnets.length, label: t('cloud.sdnVnets') || 'VNets', accent: '#14b8a6' },
                { icon: 'Layers', value: subnets.length, label: t('cloud.sdnSubnets') || 'Subnets', accent: '#a855f7' },
                { icon: 'Settings', value: controllers.length, label: t('cloud.sdnControllers') || 'Controllers', accent: '#0ea5e9' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.sdn') || 'SDN'} sub={t('cloud.sdnSub') || 'Software-defined networking'}>
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={notAvail} emptyIcon="Network" emptyTitle={t('cloud.sdnNA') || 'SDN is not configured on this cluster'} t={t}>
                        {s.pending && mut.acts ? (
                            <div className="cloud-card" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 10, borderLeft: '3px solid #eab308' }}>
                                <Icons.AlertTriangle />
                                <span style={{ flex: 1 }}>{t('cloud.sdnPending') || 'You have unapplied SDN changes.'}</span>
                                <button type="button" className="cloud-btn-primary" onClick={() => mut.run('apply', 'POST', `${base}/apply`)}>{t('cloud.applySDN') || 'Apply'}</button>
                            </div>
                        ) : null}
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>

                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Globe />, title: t('cloud.sdnZones') || 'Zones', count: zones.length, right: mut.acts ? <button type="button" className="cloud-link-btn" onClick={() => setModal('zone')}><Icons.Plus /> {t('cloud.addZone') || 'Add zone'}</button> : null })}
                            {zones.length ? <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>MTU</th><th>{t('cloud.colNodes') || 'Nodes'}</th><th>{t('cloud.colState') || 'State'}</th><th style={{ textAlign: 'right' }}></th></tr></thead>
                                <tbody>{zones.map((z, i) => (<tr className="cloud-table-row cloud-table-row-static" key={z.zone || i}>
                                    <td>{z.zone || z.name || '—'}</td><td className="cloud-table-mono">{z.type || '—'}</td><td className="cloud-cell-muted">{z.mtu || '—'}</td><td className="cloud-cell-muted">{z.nodes || '—'}</td>
                                    <td><span className="cloud-chip cloud-chip-soft">{z.state || z.status || 'ok'}</span></td>
                                    <CloudRowActions>{mut.acts && (<><CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('dz' + (z.zone), 'DELETE', `${base}/zones/${z.zone}`, undefined, (t('cloud.confirmDelZone') || 'Delete this zone?'))} /></>)}</CloudRowActions>
                                </tr>))}</tbody>
                            </table></div> : <div className="cloud-empty" style={{ padding: 14 }}>{t('cloud.noZones') || 'No zones.'}</div>}
                        </div>

                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Network />, title: t('cloud.sdnVnets') || 'VNets', count: vnets.length, right: mut.acts ? <button type="button" className="cloud-link-btn" onClick={() => setModal('vnet')}><Icons.Plus /> {t('cloud.addVnet') || 'Add VNet'}</button> : null })}
                            {vnets.length ? <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.sdnZone') || 'Zone'}</th><th>{t('cloud.colTag') || 'Tag'}</th><th>{t('cloud.colAlias') || 'Alias'}</th><th style={{ textAlign: 'right' }}></th></tr></thead>
                                <tbody>{vnets.map((v, i) => (<tr className="cloud-table-row cloud-table-row-static" key={v.vnet || i}>
                                    <td>{v.vnet || '—'}</td><td className="cloud-cell-muted">{v.zone || '—'}</td><td className="cloud-table-mono">{v.tag || '—'}</td><td className="cloud-cell-muted">{v.alias || '—'}</td>
                                    <CloudRowActions>{mut.acts && (<><CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('dv' + v.vnet, 'DELETE', `${base}/vnets/${v.vnet}`, undefined, (t('cloud.confirmDelVnet') || 'Delete this VNet?'))} /></>)}</CloudRowActions>
                                </tr>))}</tbody>
                            </table></div> : <div className="cloud-empty" style={{ padding: 14 }}>{t('cloud.noVnets') || 'No VNets.'}</div>}
                        </div>

                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Layers />, title: t('cloud.sdnSubnets') || 'Subnets', count: subnets.length, right: vnets.length && mut.acts ? <button type="button" className="cloud-link-btn" onClick={() => setModal('subnet')}><Icons.Plus /> {t('cloud.addSubnet') || 'Add subnet'}</button> : null })}
                            {subnets.length ? <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>CIDR</th><th>{t('cloud.colGateway') || 'Gateway'}</th><th>DHCP</th><th>SNAT</th><th>{t('cloud.sdnVnet') || 'VNet'}</th><th style={{ textAlign: 'right' }}></th></tr></thead>
                                    <tbody>{subnets.map((sn, i) => (<tr className="cloud-table-row cloud-table-row-static" key={(sn.subnet || i)}>
                                        <td className="cloud-table-mono">{sn.subnet || sn.cidr || '—'}</td><td className="cloud-cell-muted">{sn.gateway || '—'}</td><td className="cloud-cell-muted">{sn.dhcp || 'none'}</td>
                                        <td>{(Number(sn.snat) === 1 || sn.snat === true) ? <span className="cloud-chip cloud-chip-ok">on</span> : <span className="cloud-cell-muted">off</span>}</td>
                                        <td className="cloud-cell-muted">{sn.vnet || '—'}</td>
                                        <CloudRowActions>{mut.acts && (<>{sn.vnet ? <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('ds' + (sn.subnet), 'DELETE', `${base}/vnets/${sn.vnet}/subnets/${encodeURIComponent(sn.subnet)}`, undefined, (t('cloud.confirmDelSubnet') || 'Delete this subnet?'))} /> : null}</>)}</CloudRowActions>
                                    </tr>))}</tbody>
                                </table></div> : <div className="cloud-empty" style={{ padding: 14 }}>{vnets.length ? (t('cloud.noSubnets') || 'No subnets.') : (t('cloud.subnetsNeedVnet') || 'Create a VNet first.')}</div>}
                        </div>
                    </CloudSectionState>

                    {modal === 'zone' && (
                        <CloudModal title={t('cloud.addZone') || 'Add zone'} onClose={() => setModal(null)} onSubmit={submitZone} submitLabel={t('create') || 'Create'} t={t}>
                            <CloudField label={t('cloud.zoneName') || 'Zone ID'}><input className="cloud-input" value={zForm.zone} onChange={e => setZForm({ ...zForm, zone: e.target.value })} placeholder="zone1" maxLength={8} /></CloudField>
                            <CloudField label={t('cloud.colType') || 'Type'}><select className="cloud-input" value={zForm.type} onChange={e => setZForm({ ...zForm, type: e.target.value })}>{['simple', 'vlan', 'qinq', 'vxlan', 'evpn'].map(x => <option key={x} value={x}>{x}</option>)}</select></CloudField>
                            {(zForm.type === 'vlan' || zForm.type === 'qinq') && <CloudField label={t('cloud.zoneBridge') || 'Bridge'}><input className="cloud-input" value={zForm.bridge} onChange={e => setZForm({ ...zForm, bridge: e.target.value })} placeholder="vmbr0" /></CloudField>}
                            {zForm.type === 'vxlan' && <CloudField label={t('cloud.zonePeers') || 'Peers (comma-sep IPs)'}><input className="cloud-input" value={zForm.peers} onChange={e => setZForm({ ...zForm, peers: e.target.value })} placeholder="10.0.0.1,10.0.0.2" /></CloudField>}
                            {zForm.type === 'evpn' && <CloudField label={t('cloud.zoneController') || 'Controller'}><input className="cloud-input" value={zForm.controller} onChange={e => setZForm({ ...zForm, controller: e.target.value })} /></CloudField>}
                        </CloudModal>
                    )}
                    {modal === 'vnet' && (
                        <CloudModal title={t('cloud.addVnet') || 'Add VNet'} onClose={() => setModal(null)} onSubmit={submitVnet} submitLabel={t('create') || 'Create'} t={t}>
                            <CloudField label={t('cloud.vnetName') || 'VNet ID'}><input className="cloud-input" value={vForm.vnet} onChange={e => setVForm({ ...vForm, vnet: e.target.value })} placeholder="vnet1" maxLength={8} /></CloudField>
                            <CloudField label={t('cloud.sdnZone') || 'Zone'}><select className="cloud-input" value={vForm.zone} onChange={e => setVForm({ ...vForm, zone: e.target.value })}><option value="">—</option>{zones.map(z => <option key={z.zone} value={z.zone}>{z.zone}</option>)}</select></CloudField>
                        </CloudModal>
                    )}
                    {modal === 'subnet' && (
                        <CloudModal title={t('cloud.addSubnet') || 'Add subnet'} onClose={() => setModal(null)} onSubmit={submitSubnet} submitLabel={t('create') || 'Create'} t={t}>
                            <CloudField label={t('cloud.sdnVnet') || 'VNet'}><select className="cloud-input" value={sForm.vnet} onChange={e => setSForm({ ...sForm, vnet: e.target.value })}><option value="">—</option>{vnets.map(v => <option key={v.vnet} value={v.vnet}>{v.vnet}</option>)}</select></CloudField>
                            <CloudField label={'CIDR'}><input className="cloud-input" value={sForm.subnet} onChange={e => setSForm({ ...sForm, subnet: e.target.value })} placeholder="10.0.10.0/24" /></CloudField>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('cloud.colGateway') || 'Gateway'}><input className="cloud-input" value={sForm.gateway} onChange={e => setSForm({ ...sForm, gateway: e.target.value })} placeholder="10.0.10.1" /></CloudField>
                                <CloudField label={'DHCP'}><select className="cloud-input" value={sForm.dhcp} onChange={e => setSForm({ ...sForm, dhcp: e.target.value })}>{['none', 'dnsmasq'].map(x => <option key={x} value={x}>{x}</option>)}</select></CloudField>
                            </div>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '.85rem', color: 'var(--cloud-text-secondary)' }}><input type="checkbox" checked={sForm.snat} onChange={e => setSForm({ ...sForm, snat: e.target.checked })} /> SNAT</label>
                        </CloudModal>
                    )}
                </div>
            );
        }

        // ── Monitoring (health + metric servers) ───────────────────
        function CloudMonitoring({ clusterId, t }) {
            const health = useCloudData(clusterId ? `/api/clusters/${clusterId}/health` : null);
            const servers = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/metric-servers` : null);
            const h = health.data || {};
            const srv = Array.isArray(servers.data) ? servers.data : [];
            const score = h.score != null ? Math.round(h.score) : null;
            const band = h.band || '';
            const issues = Array.isArray(h.issues) ? h.issues : [];
            const kpis = [
                { icon: 'Heart', value: score != null ? score + '%' : '—', label: (t('cloud.healthScore') || 'Health score') + (band ? ' · ' + band : ''), accent: score == null ? '#64748b' : score >= 85 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444' },
                { icon: 'AlertTriangle', value: issues.length, label: t('cloud.healthIssues') || 'Issues', accent: issues.length ? '#f59e0b' : '#14b8a6' },
                { icon: 'BarChart', value: srv.length, label: t('cloud.metricServers') || 'Metric servers', accent: '#6366f1' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.monitoring') || 'Monitoring'} sub={t('cloud.monitoringSub') || 'Cluster health & metric export'}>
                        <button type="button" className="cloud-link-btn" onClick={() => { health.reload(); servers.reload(); }}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={health.loading} err={health.err} empty={false} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        {issues.length ? (
                            <div className="cloud-card">
                                <CloudSectionTitle>{t('cloud.healthIssues') || 'Health issues'}</CloudSectionTitle>
                                <div className="cloud-util-breakdown">{issues.slice(0, 12).map((iss, i) => (
                                    <div className="cloud-util-row" key={i}><span>{(iss && (iss.message || iss.title || iss.factor)) || String(iss)}</span><span className="cloud-cell-muted">{iss && (iss.severity || iss.impact) || ''}</span></div>
                                ))}</div>
                            </div>
                        ) : null}
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.BarChart />, title: t('cloud.metricServers') || 'Metric servers', count: srv.length })}
                            {srv.length === 0 ? <CloudEmpty icon="BarChart" title={t('cloud.noMetricServers') || 'No external metric servers configured'} /> : (
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colTarget') || 'Target'}</th></tr></thead>
                                    <tbody>{srv.map((m, i) => (<tr className="cloud-table-row cloud-table-row-static" key={m.id || i}>
                                        <td>{m.id || m.name || '—'}</td>
                                        <td className="cloud-table-mono">{m.type || '—'}</td>
                                        <td className="cloud-table-mono">{(m.server || '') + (m.port ? ':' + m.port : '')}</td>
                                    </tr>))}</tbody>
                                </table></div>
                            )}
                        </div>
                    </CloudSectionState>
                </div>
            );
        }

        // ── Replication (native + cross-cluster) ───────────────────
        function CloudReplication({ clusterId, t }) {
            const native = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/replication` : null);
            const cross = useCloudData('/api/cross-cluster-replications');
            const mut = useCloudMutate(native.reload);
            const njobs = Array.isArray(native.data) ? native.data : [];
            const cjobs = Array.isArray(cross.data) ? cross.data : [];
            const failing = njobs.filter(j => Number(j.fail_count) > 0 || (j.error && String(j.error).trim())).length;
            const kpis = [
                { icon: 'Copy', value: njobs.length, label: t('cloud.replNative') || 'Native jobs', accent: '#6366f1' },
                { icon: 'Cloud', value: cjobs.length, label: t('cloud.replCross') || 'Cross-cluster', accent: '#14b8a6' },
                { icon: failing ? 'XCircle' : 'CheckCircle', value: failing, label: t('cloud.replFailing') || 'Failing', accent: failing ? '#ef4444' : '#22c55e' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.replication') || 'Replication'} sub={t('cloud.replicationSub') || 'Storage replication jobs'}>
                        <button type="button" className="cloud-link-btn" onClick={() => { native.reload(); cross.reload(); }}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={native.loading} err={native.err} empty={!njobs.length && !cjobs.length} emptyIcon="Copy" emptyTitle={t('cloud.noRepl') || 'No replication jobs'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        {njobs.length ? (
                            <div className="cloud-card cloud-table-card">
                                {cloudHead({ icon: <Icons.Copy />, title: t('cloud.replNative') || 'Native replication', count: njobs.length })}
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.colJob') || 'Job'}</th><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colSchedule') || 'Schedule'}</th><th>{t('cloud.colLastSync') || 'Last sync'}</th><th>{t('cloud.colState') || 'State'}</th><th style={{ textAlign: 'right' }}>{t('cloud.colActions') || ''}</th></tr></thead>
                                    <tbody>{njobs.map((j, i) => (<tr className="cloud-table-row cloud-table-row-static" key={j.id || i}>
                                        <td className="cloud-table-mono">{j.id || '—'}</td>
                                        <td className="cloud-table-mono">{j.target || '—'}</td>
                                        <td className="cloud-table-mono">{j.schedule || '—'}</td>
                                        <td>{j.last_sync ? cloudRelTime(j.last_sync) : '—'}</td>
                                        <td>{(j.error && String(j.error).trim()) ? <span className="cloud-chip cloud-chip-err">error</span> : (Number(j.disable) === 1 ? <CloudConnChip connected={false} t={t} /> : <CloudConnChip connected={true} t={t} />)}</td>
                                        <CloudRowActions>
                                            {mut.acts && (<>
                                            <CloudIconBtn icon="Play" title={t('cloud.runNow') || 'Run now'} onClick={() => mut.run('r' + j.id, 'POST', `/api/clusters/${clusterId}/replication/${j.id}/run`)} />
                                            </>)}
                                        </CloudRowActions>
                                    </tr>))}</tbody>
                                </table></div>
                            </div>
                        ) : null}
                        {cjobs.length ? (
                            <div className="cloud-card cloud-table-card">
                                {cloudHead({ icon: <Icons.Cloud />, title: t('cloud.replCross') || 'Cross-cluster', count: cjobs.length })}
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colSource') || 'Source'}</th><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colSchedule') || 'Schedule'}</th><th>{t('cloud.colStatus') || 'Status'}</th></tr></thead>
                                    <tbody>{cjobs.map((j, i) => (<tr className="cloud-table-row cloud-table-row-static" key={j.id || i}>
                                        <td>{j.name || j.id || '—'}</td>
                                        <td className="cloud-table-mono">{j.source_cluster || '—'}</td>
                                        <td className="cloud-table-mono">{j.target_cluster || '—'}</td>
                                        <td className="cloud-table-mono">{j.schedule || '—'}</td>
                                        <td><span className="cloud-chip cloud-chip-soft">{j.status || (j.enabled ? 'enabled' : 'disabled')}</span></td>
                                    </tr>))}</tbody>
                                </table></div>
                            </div>
                        ) : null}
                    </CloudSectionState>
                </div>
            );
        }

        // ── High Availability (cloud-native) ───────────────────────
        // NS 2026-06-11 — Cloud-skin per-cluster feature parity, phase 1. Reads the
        // same /ha/status the classic layout uses, rendered as cloud cards + the
        // fence-strategy banner. Self-fetches (HA isn't in the shell's prop bundle).
        function CloudHA({ clusterId, t }) {
            const { getAuthHeaders } = useAuth();
            const [ha, setHa] = React.useState(null);
            const [loading, setLoading] = React.useState(true);
            const [err, setErr] = React.useState(null);
            const load = React.useCallback(() => {
                if (!clusterId) { setLoading(false); return; }
                setLoading(true); setErr(null);
                fetch(`/api/clusters/${clusterId}/ha/status`, { headers: getAuthHeaders() })
                    .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))
                    .then(d => { setHa(d); setLoading(false); })
                    .catch(e => { setErr(String(e && e.message || e)); setLoading(false); });
            }, [clusterId]);
            React.useEffect(() => { load(); }, [load]);

            const sbp = (ha && ha.split_brain_prevention) || {};
            const fs = sbp.fence_strategy || {};
            const strat = fs.strategy || 'unknown';
            const enabled = !!(ha && ha.enabled);
            const health = (ha && ha.cluster_health) || {};
            const installed = !!(ha && ha.self_fence_installed);
            const bannerStyle = strat === 'wait'
                ? { borderLeft: '3px solid #f59e0b', background: 'rgba(245,158,11,0.08)' }
                : strat === 'quorum'
                    ? { borderLeft: '3px solid #14b8a6', background: 'rgba(20,184,166,0.08)' }
                    : { borderLeft: '3px solid #64748b', background: 'rgba(100,116,139,0.08)' };
            const stratIcon = strat === 'wait' ? <Icons.AlertTriangle /> : strat === 'quorum' ? <Icons.Shield /> : <Icons.Activity />;
            const kpis = [
                { icon: enabled ? 'Shield' : 'XCircle', value: enabled ? (t('haEnabled') || 'Enabled') : (t('haDisabled') || 'Disabled'), label: t('cloud.haState') || 'HA state', accent: enabled ? '#22c55e' : '#64748b' },
                { icon: sbp.have_quorum ? 'CheckCircle' : 'XCircle', value: sbp.have_quorum ? (t('quorumOk') || 'Quorum OK') : (t('quorumLost') || 'No quorum'), label: t('cloud.quorum') || 'Quorum', accent: sbp.have_quorum ? '#14b8a6' : '#ef4444' },
                { icon: 'Server', value: installed ? (t('running') || 'Installed') : (t('notInstalled') || 'Not installed'), label: t('cloud.fenceAgents') || 'Self-fence agents', accent: installed ? '#6366f1' : '#f59e0b' },
                { icon: 'Activity', value: `${health.online_nodes != null ? health.online_nodes : '—'} / ${health.total_nodes != null ? health.total_nodes : '—'}`, label: t('cloud.nodesOnline') || 'Hosts online', accent: '#0ea5e9' },
            ];
            return (
                <div className="cloud-body">
                    <CloudPageHeader
                        title={t('cloud.ha') || 'High Availability'}
                        sub={enabled ? (t('cloud.haOn') || 'Split-brain protection active') : (t('cloud.haOff') || 'High availability is disabled for this cluster')}
                    >
                        <button type="button" className="cloud-link-btn" onClick={load}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    {loading ? (
                        <div className="cloud-card"><div className="cloud-empty">{t('loading') || 'Loading…'}</div></div>
                    ) : err ? (
                        <div className="cloud-card"><CloudEmpty icon="AlertTriangle" title={t('cloud.haLoadFail') || 'Could not load HA status'} text={err} /></div>
                    ) : (
                        <React.Fragment>
                            {(fs.strategy || fs.reason) && (
                                <div className="cloud-card" style={bannerStyle}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                        <span style={{ display: 'inline-flex' }}>{stratIcon}</span>
                                        <strong>{t('fenceStrategyLabel') || 'Fence strategy'}: <span style={{ textTransform: 'uppercase' }}>{strat}</span></strong>
                                        {fs.expected_votes != null && <span style={{ marginLeft: 'auto', opacity: 0.7, fontSize: 12 }}>{fs.expected_votes} votes · qdevice: {fs.has_qdevice ? 'yes' : 'no'}</span>}
                                    </div>
                                    {sbp.fence_strategy_warning && <p style={{ fontSize: 13, margin: '4px 0' }}>{sbp.fence_strategy_warning}</p>}
                                    {fs.reason && <p style={{ fontSize: 12, opacity: 0.8, margin: '2px 0' }}>{fs.reason}</p>}
                                    {fs.detected_at && <p style={{ fontSize: 12, opacity: 0.7, margin: '2px 0' }}>{t('detectedAt') || 'Detected at'}: {fs.detected_at}</p>}
                                </div>
                            )}
                            <div className="cloud-kpi-grid">
                                {kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}
                            </div>
                            <div className="cloud-card">
                                <CloudSectionTitle>{t('cloud.haConfig') || 'Configuration'}</CloudSectionTitle>
                                <div className="cloud-util-breakdown">
                                    <div className="cloud-util-row"><span>{t('quorumEnabled') || 'Quorum check'}</span><span>{sbp.quorum_enabled ? (t('enabled') || 'Enabled') : (t('disabled') || 'Disabled')}</span></div>
                                    <div className="cloud-util-row"><span>{t('selfFence') || 'Self-fencing'}</span><span>{sbp.self_fence_enabled ? (t('enabled') || 'Enabled') : (t('disabled') || 'Disabled')}</span></div>
                                    <div className="cloud-util-row"><span>{t('twoNodeMode') || '2-node mode'}</span><span>{sbp.two_node_mode ? 'Yes' : 'No'}</span></div>
                                    <div className="cloud-util-row"><span>{t('storageHeartbeat') || 'Storage heartbeat'}</span><span>{sbp.storage_heartbeat_enabled ? (sbp.storage_heartbeat_path || (t('enabled') || 'Enabled')) : (t('disabled') || 'Disabled')}</span></div>
                                    <div className="cloud-util-row"><span>{t('recoveryDelay') || 'Recovery delay'}</span><span>{sbp.recovery_delay != null ? sbp.recovery_delay + 's' : '—'}</span></div>
                                    {sbp.pegaprox_vmid ? <div className="cloud-util-row"><span>PegaProx VM</span><span>#{sbp.pegaprox_vmid}</span></div> : null}
                                </div>
                            </div>
                        </React.Fragment>
                    )}
                </div>
            );
        }

        // LW Oct 2026 (#625) - the HA page of this layout shows the Proxmox HA groups
        // (ProxmoxHaSection, since aed792d CloudHA above is no longer mounted). What the
        // node HA settings of the cluster warn about gets one line each on top of it: an
        // agent of an earlier PegaProx on a node, and unsafe two-node recovery. Nothing at
        // all when neither applies, or the server does not report them.
        function CloudHaNodeNotes({ clusterId, t, authFetch }) {
            const [ha, setHa] = React.useState(null);
            React.useEffect(() => {
                let gone = false;
                setHa(null);
                if (!clusterId || !authFetch) return undefined;
                authFetch(`${API_URL}/clusters/${clusterId}/ha/status`)
                    .then(r => (r && r.ok ? r.json() : null))
                    .then(d => { if (!gone) setHa(d); })
                    .catch(() => {});
                return () => { gone = true; };
            }, [clusterId]);
            if (!ha || !ha.enabled) return null;
            const sbp = ha.split_brain_prevention || {};
            const fa = ha.fence_agent || {};
            const outdated = Array.isArray(fa.outdated) ? fa.outdated : [];
            const unsafe = sbp.unsafe_two_node_recovery === true;
            // LW Oct 2026 (#625) - guests an interrupted recovery left moved or held: started or
            // dismissed in the HA settings of the other layouts, this one only says so
            const left = [...new Set((Array.isArray(ha.interrupted_recoveries) ? ha.interrupted_recoveries : [])
                .flatMap(r => [...(r.moved || []), ...(r.held || []), ...(r.guests_open || [])]))];
            if (!outdated.length && !unsafe && !left.length) return null;
            const line = { display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 };
            return (
                <div className="cloud-card" data-ha-node-cloud
                    style={{ marginBottom: 16, borderLeft: `3px solid ${unsafe ? '#f87171' : '#f59e0b'}` }}>
                    {unsafe && (
                        <div data-ha-node-cloud-line="unsafe" title={sbp.unsafe_two_node_warning || undefined}
                            style={{ ...line, color: 'var(--cloud-error, #f87171)' }}>
                            <span style={{ display: 'inline-flex' }}><Icons.AlertTriangle /></span>
                            <span><strong>{t('haNodeUnsafeSwitch')}</strong>: {t('enabled')}</span>
                        </div>
                    )}
                    {outdated.length > 0 && (
                        <div data-ha-node-cloud-line="outdated" title={fa.outdated_warning || undefined}
                            style={{ ...line, color: 'var(--cloud-warning, #e0a82e)', marginTop: unsafe ? 6 : 0 }}>
                            <span style={{ display: 'inline-flex' }}><Icons.AlertTriangle /></span>
                            <span><strong>{t('haNodeCloudOutdated')}</strong>: {outdated.join(', ')}</span>
                        </div>
                    )}
                    {left.length > 0 && (
                        <div data-ha-node-cloud-line="interrupted" title={t('haNodeIrCloudHint')}
                            style={{ ...line, color: 'var(--cloud-warning, #e0a82e)', marginTop: unsafe || outdated.length ? 6 : 0 }}>
                            <span style={{ display: 'inline-flex' }}><Icons.AlertTriangle /></span>
                            <span><strong>{t('haNodeIrTitle')}</strong>: {left.join(', ')} - {t('haNodeIrCloudHint')}</span>
                        </div>
                    )}
                </div>
            );
        }

        // NS 2026-06-11 — sponsors show in every layout, Cloud included. Same slots
        // + OC button as the classic footer, just sized for the cloud content area.
        // Reuses the global SponsorSlot so the mirror/GitHub self-heal applies here too.
        function CloudSponsorFooter({ t }) {
            const label = (typeof t === 'function' && t('thanksToSponsors')) || 'Thanks to our Sponsors';
            return (
                <footer className="cloud-sponsors" style={{ marginTop: 28, paddingTop: 18, borderTop: '1px solid rgba(127,127,127,0.18)', textAlign: 'center' }}>
                    <div style={{ fontSize: 12, opacity: 0.65, marginBottom: 12 }}>❤️ {label}</div>
                    <div style={{ display: 'flex', justifyContent: 'center', gap: 12, flexWrap: 'wrap' }}>
                        {[1, 2, 3, 4, 5, 6, 7, 8].map(num => <SponsorSlot key={num} num={num} />)}
                    </div>
                    <div style={{ marginTop: 14 }}>
                        <a href="https://opencollective.com/pegaprox" target="_blank" rel="noopener noreferrer" title="Contribute on Open Collective">
                            <img src="/images/oc_contribute_button.png" alt="Contribute on Open Collective" style={{ height: 26, opacity: 0.9 }} />
                        </a>
                    </div>
                    <LegalNotice style={{marginTop: 12}} />
                </footer>
            );
        }

        // ═══ NS 2026-07 — cloud-native parity views (features that are inline in
        //     dashboard.js with no mountable component). Same useCloudData/useCloudMutate
        //     pattern as CloudBackups; list + core actions (create/edit → follow-up). ═══
        function CloudPlugins({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData('/api/plugins');
            const mut = useCloudMutate(reload);
            // a process loads its own plugins: no standby rescans, reloads or switches them,
            // forwarding or not (#625)
            const { haStandby } = useAuth();
            // #642 - a plugin limited to other clusters has nothing to say about this one
            const list = (Array.isArray(data) ? data : [])
                .filter(p => p && p.enabled)
                .filter(p => pluginAppliesToCluster(p, clusterId));
            const [sel, setSel] = React.useState(null);
            const cur = list.find(p => p.id === sel) || null;
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('plugins') || 'Plugins'} sub={list.length + ' ' + (t('plugins') || 'plugins')}>
                        {!haStandby && <button type="button" className="cloud-link-btn" onClick={() => mut.run('rescan', 'POST', '/api/plugins/rescan')}><Icons.Search /> {t('rescan') || 'Rescan'}</button>}
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!list.length} emptyIcon="Box" emptyTitle={t('noPlugins') || 'No plugins enabled'} emptyText={t('cloud.pluginsHint') || 'Enable plugins in Settings → Plugins.'} t={t}>
                        <div className="cloud-kpi-grid">
                            {list.map(p => (
                                <CloudKpiCard key={p.id} icon="Box" value={p.name || p.id}
                                    label={'v' + (p.version || '?') + (p.author ? ' · ' + p.author : '')}
                                    sub={p.loaded ? (t('loaded') || 'Loaded') : (p.error ? (t('error') || 'Error') : (t('unloaded') || 'Unloaded'))}
                                    accent={(cur && cur.id === p.id) ? 'var(--cloud-accent)' : (p.loaded ? '#22c55e' : '#ef4444')}
                                    onClick={() => setSel(p.id)} />
                            ))}
                        </div>
                        {cur && (
                            <div className="cloud-card cloud-table-card" style={{ padding: 0, overflow: 'hidden' }}>
                                {cloudHead({ icon: <Icons.Box />, title: cur.name || cur.id, count: (cur.routes && cur.routes.length) || null, right: !haStandby && (
                                    <div style={{ display: 'flex', gap: 4 }}>
                                        <CloudIconBtn icon="RotateCw" title={t('reload') || 'Reload'} onClick={() => mut.run('rl' + cur.id, 'POST', `/api/plugins/${cur.id}/reload`)} />
                                        <CloudIconBtn icon="Power" danger title={t('disable') || 'Disable'} onClick={() => mut.run('ds' + cur.id, 'POST', `/api/plugins/${cur.id}/disable`)} />
                                    </div>
                                ) })}
                                {cur.has_frontend && cur.frontend_route
                                    ? <iframe title={cur.name || cur.id} src={cur.frontend_route + (cur.frontend_route.indexOf('?') >= 0 ? '&' : '?') + 'cluster=' + encodeURIComponent(clusterId || '')} style={{ width: '100%', height: '70vh', border: 'none', background: '#fff', display: 'block' }} sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-modals allow-downloads" referrerPolicy="same-origin" />
                                    : <div style={{ padding: 16 }}>
                                        {cur.description && <p className="cloud-cell-muted" style={{ marginBottom: 8 }}>{cur.description}</p>}
                                        {cur.error && <div className="cloud-chip cloud-chip-err" style={{ marginBottom: 8 }}>{cur.error}</div>}
                                        <div className="cloud-cell-muted" style={{ fontSize: '.8rem' }}>{(cur.routes || []).length ? 'Routes: ' + cur.routes.join(', ') : (t('cloud.pluginNoUi') || 'This plugin has no frontend UI.')}</div>
                                    </div>}
                            </div>
                        )}
                    </CloudSectionState>
                </div>
            );
        }

        function CloudScripts({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/scripts` : null);
            const mut = useCloudMutate(reload);
            const rows = Array.isArray(data) ? data : (data && Array.isArray(data.scripts) ? data.scripts : []);
            const [out, setOut] = React.useState(null);
            const [showNew, setShowNew] = React.useState(false);
            const [form, setForm] = React.useState({ name: '', description: '', type: 'bash', target_nodes: 'all', content: '' });
            const [runFor, setRunFor] = React.useState(null);
            const [pw, setPw] = React.useState('');
            const viewOutput = (s) => {
                fetch(`/api/clusters/${clusterId}/scripts/${s.id}/output`).then(r => r.ok ? r.json() : null)
                    .then(d => setOut({ name: s.name, text: (d && (d.output || d.stdout || d.result)) || '(no output)' }))
                    .catch(() => setOut({ name: s.name, text: 'Failed to load output.' }));
            };
            const submitNew = () => {
                if (!form.name.trim() || !form.content.trim()) return;
                mut.run('newscript', 'POST', `/api/clusters/${clusterId}/scripts`, { name: form.name.trim(), description: form.description.trim(), type: form.type, target_nodes: form.target_nodes.trim() || 'all', content: form.content });
                setShowNew(false); setForm({ name: '', description: '', type: 'bash', target_nodes: 'all', content: '' });
            };
            const submitRun = () => { if (!pw) return; mut.run('run' + runFor.id, 'POST', `/api/clusters/${clusterId}/scripts/${runFor.id}/run`, { password: pw }); setRunFor(null); setPw(''); };
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('customScripts') || 'Scripts'} sub={t('cloud.scriptsSub') || 'Custom cluster scripts'}>
                        {mut.acts && <button type="button" className="cloud-link-btn" onClick={() => setShowNew(true)}><Icons.Plus /> {t('cloud.newScript') || 'New script'}</button>}
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!rows.length} emptyIcon="Terminal" emptyTitle={t('cloud.noScripts') || 'No scripts'} t={t}>
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Terminal />, title: t('customScripts') || 'Scripts', count: rows.length })}
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('name') || 'Name'}</th><th>{t('type') || 'Type'}</th><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colLastRun') || 'Last run'}</th><th>{t('cloud.colStatus') || 'Status'}</th><th style={{ textAlign: 'right' }}></th></tr></thead>
                                <tbody>{rows.map((s, i) => {
                                    const st = String(s.last_status || '').toLowerCase();
                                    const ok = st.indexOf('ok') >= 0 || st.indexOf('success') >= 0;
                                    return (<tr className="cloud-table-row cloud-table-row-static" key={s.id || i}>
                                        <td>{s.name}{s.description ? <div className="cloud-cell-muted" style={{ fontSize: '.75rem' }}>{s.description}</div> : null}</td>
                                        <td><span className="cloud-chip cloud-chip-soft">{s.type || 'bash'}</span></td>
                                        <td className="cloud-cell-muted">{s.target_nodes || 'all'}</td>
                                        <td className="cloud-cell-muted">{s.last_run || '—'}</td>
                                        <td>{s.last_status ? (ok ? <span className="cloud-chip cloud-chip-ok">{s.last_status}</span> : <span className="cloud-chip cloud-chip-err">{s.last_status}</span>) : <span className="cloud-cell-muted">—</span>}</td>
                                        <CloudRowActions>
                                            {mut.acts && <CloudIconBtn icon="Play" title={t('cloud.runNow') || 'Run'} onClick={() => setRunFor(s)} />}
                                            <CloudIconBtn icon="FileText" title={t('cloud.viewOutput') || 'Output'} onClick={() => viewOutput(s)} />
                                            {mut.acts && <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + s.id, 'DELETE', `/api/clusters/${clusterId}/scripts/${s.id}`, undefined, (t('cloud.confirmDelScript') || 'Delete this script?'))} />}
                                        </CloudRowActions>
                                    </tr>);
                                })}</tbody>
                            </table></div>
                        </div>
                        {out && (
                            <div className="cloud-card" style={{ padding: 12 }}>
                                <CloudSectionTitle right={<CloudIconBtn icon="X" title="Close" onClick={() => setOut(null)} />}>{out.name} — {t('cloud.output') || 'Output'}</CloudSectionTitle>
                                <pre style={{ whiteSpace: 'pre-wrap', fontSize: '.8rem', maxHeight: '40vh', overflow: 'auto', background: 'var(--cloud-surface-2)', padding: 10, borderRadius: 6, marginTop: 8 }}>{out.text}</pre>
                            </div>
                        )}
                    </CloudSectionState>
                    {showNew && (
                        <CloudModal title={t('cloud.newScript') || 'New script'} onClose={() => setShowNew(false)} onSubmit={submitNew} submitLabel={t('create') || 'Create'} t={t}>
                            <CloudField label={t('name') || 'Name'}><input className="cloud-input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="cleanup-logs" /></CloudField>
                            <CloudField label={t('description') || 'Description'}><input className="cloud-input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} /></CloudField>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('type') || 'Type'}><select className="cloud-input" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}><option value="bash">bash</option><option value="python">python</option></select></CloudField>
                                <CloudField label={t('cloud.colTarget') || 'Target nodes'}><input className="cloud-input" value={form.target_nodes} onChange={e => setForm({ ...form, target_nodes: e.target.value })} placeholder="all" /></CloudField>
                            </div>
                            <CloudField label={t('cloud.scriptContent') || 'Script'}><textarea className="cloud-input" style={{ minHeight: 140, fontFamily: 'monospace' }} value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} placeholder={form.type === 'python' ? '#!/usr/bin/env python3' : '#!/bin/bash'} /></CloudField>
                        </CloudModal>
                    )}
                    {runFor && (
                        <CloudModal title={(t('cloud.runNow') || 'Run') + ' — ' + runFor.name} onClose={() => { setRunFor(null); setPw(''); }} onSubmit={submitRun} submitLabel={t('cloud.runNow') || 'Run'} t={t}>
                            <div className="cloud-cell-muted" style={{ fontSize: '.8rem' }}>{t('cloud.runScriptHint') || 'Runs on the target nodes over SSH. Confirm with the node root password.'}</div>
                            <CloudField label={t('password') || 'Node password'}><input className="cloud-input" type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus /></CloudField>
                        </CloudModal>
                    )}
                </div>
            );
        }

        function CloudSchedules({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData('/api/schedules');
            const mut = useCloudMutate(reload);
            const all = Array.isArray(data) ? data : (data && Array.isArray(data.schedules) ? data.schedules : []);
            const rows = clusterId ? all.filter(s => !s.cluster_id || String(s.cluster_id) === String(clusterId)) : all;
            const isOn = (s) => Number(s.enabled) === 1 || s.enabled === true;
            const [showNew, setShowNew] = React.useState(false);
            const [form, setForm] = React.useState({ vmid: '', vm_type: 'qemu', action: 'start', schedule_type: 'daily', time: '03:00', date: '' });
            const submitNew = () => {
                if (!String(form.vmid).trim() || !form.time) return;
                const body = { cluster_id: clusterId, vmid: Number(form.vmid), vm_type: form.vm_type, action: form.action, schedule_type: form.schedule_type, time: form.time };
                if (form.schedule_type === 'once' && form.date) body.date = form.date;
                // JB Nov 2026 - weekly was on offer with nothing to pick the days with, and the route wants them
                if (form.schedule_type === 'weekly') {
                    if (!(form.days || []).length) return;
                    body.days = form.days;
                }
                mut.run('newsched', 'POST', '/api/schedules', body);
                setShowNew(false); setForm({ vmid: '', vm_type: 'qemu', action: 'start', schedule_type: 'daily', time: '03:00', date: '' });
            };
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('scheduledActions') || 'Schedules'} sub={t('cloud.schedulesSub') || 'Time-based VM actions'}>
                        {mut.acts && <button type="button" className="cloud-link-btn" onClick={() => setShowNew(true)}><Icons.Plus /> {t('cloud.newSchedule') || 'New schedule'}</button>}
                        <button type="button" className="cloud-link-btn" onClick={reload}><Icons.RefreshCw /> {t('refresh') || 'Refresh'}</button>
                    </CloudPageHeader>
                    <CloudSectionState loading={loading} err={err} empty={!rows.length} emptyIcon="Clock" emptyTitle={t('cloud.noSchedules') || 'No schedules'} t={t}>
                        <div className="cloud-card cloud-table-card">
                            {cloudHead({ icon: <Icons.Clock />, title: t('scheduledActions') || 'Schedules', count: rows.length })}
                            <div className="cloud-table-scroll"><table className="cloud-table">
                                <thead><tr><th>{t('cloud.colTarget') || 'Target'}</th><th>{t('cloud.colAction') || 'Action'}</th><th>{t('cloud.colWhen') || 'When'}</th><th>{t('cloud.colLastRun') || 'Last run'}</th><th>{t('cloud.colState') || 'State'}</th><th style={{ textAlign: 'right' }}></th></tr></thead>
                                <tbody>{rows.map((s, i) => (
                                    <tr className="cloud-table-row cloud-table-row-static" key={s.id || i}>
                                        <td className="cloud-table-mono">{s.vmid ? '#' + s.vmid : (s.target || '—')}{s.vm_type ? ' · ' + s.vm_type : ''}</td>
                                        <td><span className="cloud-chip cloud-chip-soft">{s.action || '—'}</span></td>
                                        <td className="cloud-cell-muted">{[s.schedule_type, s.time, s.date, s.cron].filter(Boolean).join(' ') || '—'}</td>
                                        <td className="cloud-cell-muted">{s.last_run || s.last_run_at || '—'}</td>
                                        <td><CloudConnChip connected={isOn(s)} t={t} /></td>
                                        <CloudRowActions>
                                            {mut.acts && (<>
                                            <CloudIconBtn icon="Power" title={isOn(s) ? (t('disable') || 'Disable') : (t('enable') || 'Enable')} onClick={() => mut.run('t' + s.id, 'PUT', `/api/schedules/${s.id}`, { enabled: isOn(s) ? 0 : 1 })} />
                                            <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + s.id, 'DELETE', `/api/schedules/${s.id}`, undefined, (t('cloud.confirmDelSchedule') || 'Delete this schedule?'))} />
                                            </>)}
                                        </CloudRowActions>
                                    </tr>
                                ))}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
                    {showNew && (
                        <CloudModal title={t('cloud.newSchedule') || 'New schedule'} onClose={() => setShowNew(false)} onSubmit={submitNew} submitLabel={t('create') || 'Create'} t={t}>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={'VMID'}><input className="cloud-input" type="number" value={form.vmid} onChange={e => setForm({ ...form, vmid: e.target.value })} placeholder="100" /></CloudField>
                                <CloudField label={t('type') || 'Type'}><select className="cloud-input" value={form.vm_type} onChange={e => setForm({ ...form, vm_type: e.target.value })}><option value="qemu">qemu</option><option value="lxc">lxc</option></select></CloudField>
                            </div>
                            <CloudField label={t('cloud.colAction') || 'Action'}><select className="cloud-input" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>{['start', 'stop', 'shutdown', 'reboot', 'snapshot'].map(a => <option key={a} value={a}>{a}</option>)}</select></CloudField>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <CloudField label={t('cloud.colWhen') || 'Schedule'}><select className="cloud-input" value={form.schedule_type} onChange={e => setForm({ ...form, schedule_type: e.target.value })}>{['once', 'daily', 'weekly', 'weekdays', 'weekends'].map(x => <option key={x} value={x}>{x}</option>)}</select></CloudField>
                                <CloudField label={t('cloud.colTime') || 'Time'}><input className="cloud-input" type="time" value={form.time} onChange={e => setForm({ ...form, time: e.target.value })} /></CloudField>
                            </div>
                            {/* not a CloudField: a wrapping label would hand every click on the caption or gap to the first checkbox */}
                            {form.schedule_type === 'weekly' && <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '.8rem', color: 'var(--cloud-text-secondary)' }}>
                                <span>{t('days') || 'Days'}</span>
                                <div data-cloud-sched-days="" style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                                    {['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'].map(d => (
                                        <label key={d} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                            <input type="checkbox" data-cloud-sched-day={d} checked={(form.days || []).includes(d)}
                                                onChange={e => setForm({ ...form, days: e.target.checked ? [...(form.days || []), d] : (form.days || []).filter(x => x !== d) })} />
                                            {t(d)}
                                        </label>
                                    ))}
                                </div>
                            </div>}
                            {form.schedule_type === 'once' && <CloudField label={t('cloud.colDate') || 'Date'}><input className="cloud-input" type="date" value={form.date} onChange={e => setForm({ ...form, date: e.target.value })} /></CloudField>}
                        </CloudModal>
                    )}
                </div>
            );
        }

        function CloudCVE({ clusterId, t }) {
            const { haReadOnly } = useAuth();
            const [res, setRes] = React.useState(null);
            const [busy, setBusy] = React.useState(false);
            const [err, setErr] = React.useState(null);
            const scan = () => {
                setBusy(true); setErr(null);
                fetch(`/api/clusters/${clusterId}/reports/cve-scan`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }, body: '{}' })
                    .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))
                    .then(d => { setRes(d); setBusy(false); })
                    .catch(e => { setErr(String(e && e.message || e)); setBusy(false); });
            };
            const nodes = React.useMemo(() => {
                if (!res) return [];
                if (Array.isArray(res.results)) return res.results;
                if (Array.isArray(res.nodes)) return res.nodes;
                if (res.nodes && typeof res.nodes === 'object') return Object.entries(res.nodes).map(([node, v]) => ({ node, ...(v || {}) }));
                return [];
            }, [res]);
            // JB Nov 2026 - packages is always there and holds pending updates, so an empty one hid the CVEs behind it and a
            // node with CVEs read as clean. Without debsecan the security updates are the closest there is
            const nodeVulns = (n) => (n.cves && n.cves.length ? n.cves
                : (n.vulnerabilities && n.vulnerabilities.length ? n.vulnerabilities
                : (n.debsecan_available ? [] : (n.packages || []).filter(p => p.security))));
            const totalVulns = nodes.reduce((a, n) => a + (nodeVulns(n).length || Number(n.count) || 0), 0);
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cveScanner') || 'CVE Scanner'} sub={t('cloud.cveSub') || 'Package vulnerability scan (debsecan)'}>
                        {!haReadOnly && <button type="button" className="cloud-btn-primary" onClick={scan} disabled={busy}>{busy ? (t('cloud.scanning') || 'Scanning…') : (t('cloud.runScan') || 'Run scan')}</button>}
                    </CloudPageHeader>
                    {err && <div className="cloud-card"><CloudEmpty icon="AlertTriangle" title={t('cloud.scanFailed') || 'Scan failed'} text={err} /></div>}
                    {!res && !busy && !err && <div className="cloud-card"><CloudEmpty icon="Shield" title={t('cloud.cveIdle') || 'No scan yet'} text={t('cloud.cveHint') || 'Run a scan to check node packages for known CVEs (needs debsecan on the nodes).'} /></div>}
                    {busy && <div className="cloud-card"><div className="cloud-empty">{t('cloud.scanning') || 'Scanning nodes…'}</div></div>}
                    {res && !busy && (
                        <React.Fragment>
                            <div className="cloud-kpi-grid">
                                <CloudKpiCard icon="Cpu" value={nodes.length} label={t('cloud.colNodes') || 'Nodes'} accent="#6366f1" />
                                <CloudKpiCard icon={totalVulns ? 'AlertTriangle' : 'Shield'} value={totalVulns} label={t('cloud.cveVulns') || 'Vulnerabilities'} accent={totalVulns ? '#ef4444' : '#22c55e'} />
                            </div>
                            {nodes.map((n, i) => {
                                const pkgs = nodeVulns(n);
                                return (
                                    <div className="cloud-card cloud-table-card" key={n.node || i}>
                                        {cloudHead({ icon: <Icons.Cpu />, title: n.node || ('node ' + i), count: pkgs.length })}
                                        {n.error ? <div className="cloud-empty" style={{ padding: 14 }}>{n.error}</div> : (pkgs.length ? <div className="cloud-table-scroll"><table className="cloud-table">
                                            <thead><tr><th>{t('cloud.colPackage') || 'Package'}</th><th>{t('cloud.colInstalled') || 'Installed'}</th><th>CVE</th><th>{t('cloud.colSeverity') || 'Severity'}</th></tr></thead>
                                            <tbody>{pkgs.slice(0, 200).map((p, j) => { const level = p.severity || p.urgency; const sev = String(level || '').toLowerCase(); return (<tr className="cloud-table-row cloud-table-row-static" key={j}>
                                                <td className="cloud-table-mono">{p.package || p.pkg || p.name || '—'}</td>
                                                <td className="cloud-cell-muted">{p.installed || p.version || p.current || '—'}</td>
                                                <td className="cloud-table-mono">{p.cve || p.id || '—'}</td>
                                                <td>{level ? <span className={'cloud-chip ' + (sev.indexOf('high') >= 0 || sev.indexOf('crit') >= 0 ? 'cloud-chip-err' : 'cloud-chip-soft')}>{level}</span> : <span className="cloud-cell-muted">—</span>}</td>
                                            </tr>); })}</tbody>
                                        </table></div> : <div className="cloud-empty" style={{ padding: 14 }}>{t('cloud.cveClean') || 'No known vulnerabilities.'}</div>)}
                                    </div>
                                );
                            })}
                        </React.Fragment>
                    )}
                </div>
            );
        }

        function CloudShell({ clusters, selectedCluster, setSelectedCluster, clusterResources, clusterMetrics, allClusterMetrics, clusterDatastores, clusterNetworks, clusterPools, tasks, knownNodes, actions, isAdmin, currentUser, t, authFetch, addToast, onExitCloud, onOpenSettings, onOpenProfile, onOpenApiReference, onLogout }) {
            const [section, setSection] = React.useState('overview');
            const [detailRes, setDetailRes] = React.useState(null);
            const [collapsed, setCollapsed] = React.useState(false);
            const [theme, setTheme] = React.useState(() => {
                try { return localStorage.getItem('pegaprox-cloud-theme') === 'light' ? 'light' : 'dark'; } catch (_) { return 'dark'; }
            });

            // keep the cloud token scope active + the theme attribute while mounted
            React.useEffect(() => {
                const prevLayout = document.body.getAttribute('data-layout');
                document.body.setAttribute('data-layout', 'cloud');
                return () => { if (prevLayout != null) document.body.setAttribute('data-layout', prevLayout); else document.body.removeAttribute('data-layout'); };
            }, []);
            React.useEffect(() => {
                document.body.setAttribute('data-cloud-theme', theme);
                try { localStorage.setItem('pegaprox-cloud-theme', theme); } catch (_) {}
                return () => { document.body.removeAttribute('data-cloud-theme'); };
            }, [theme]);

            // cloud mode bypasses the tree sidebar's auto-select -> pick the first
            // connected cluster so data populates. -- NS
            React.useEffect(() => {
                if (!selectedCluster && typeof setSelectedCluster === 'function') {
                    const arr = Array.isArray(clusters) ? clusters : [];
                    const first = arr.find(c => c && c.connected) || arr[0];
                    if (first) setSelectedCluster(first);
                }
            }, [selectedCluster, clusters]);

            const safeClusters = Array.isArray(clusters) ? clusters : [];
            const safeResources = Array.isArray(clusterResources) ? clusterResources : [];
            // server-computed, already false for tenant/cluster-confined users; a standby
            // installs nothing (#625), like the sidebar entry in the other two layouts. Not
            // even a forwarding one: the answer URL it would show is this instance's own.
            const { ha, haStandby, haConsolesElsewhere, haReadOnly } = useAuth();
            const canAutoInstall = !!(currentUser && currentUser.autoinstall_access) && !haStandby;
            const holdsPerm = (perm) => !!isAdmin || (Array.isArray(currentUser && currentUser.permissions) && currentUser.permissions.includes(perm));
            const canChanges = holdsPerm('changes.view');
            // LW Nov 2026 (#1220) - the blueprints (blueprints.js) read with vm.create, a standby lists them and changes nothing
            const canBp = holdsPerm('vm.create');

            // PegaProx t() ECHOES the key back on a miss, so `t('cloud.x') || 'Fallback'`
            // would render the raw key. treat key-echo as "no translation". -- NS
            const tx = React.useCallback((k) => {
                const v = (typeof t === 'function') ? t(k) : undefined;
                return (v && v !== k) ? v : undefined;
            }, [t]);
            // wrapper that yields the english fallback literal for the inline `|| '...'`
            const T = (k) => tx(k);

            // stamp _clusterId before any action so cross-cluster handlers resolve correctly
            const cid = selectedCluster && selectedCluster.id;
            const stamp = (r) => ({ ...r, _clusterId: (r && r._clusterId) || cid });
            const act = React.useMemo(() => ({
                vmAction: (r, a) => actions?.vmAction?.(stamp(r), a),
                forceStop: (r) => actions?.forceStop?.(stamp(r)),
                openConsole: (r) => actions?.openConsole?.(stamp(r)),
                openSpice: (r) => actions?.openSpice?.(stamp(r)),
                openLxcShell: (r) => actions?.openLxcShell?.(stamp(r)),
                openConfig: (r) => actions?.openConfig?.(stamp(r)),
                openMetrics: (r) => actions?.openMetrics?.(stamp(r)),
                migrate: (r) => actions?.migrate?.(stamp(r)),
                clone: (r) => actions?.clone?.(stamp(r)),
                del: (r) => actions?.del?.(stamp(r)),
                crossMigrate: (r) => actions?.crossMigrate?.(stamp(r)),
                snapshot: (r) => actions?.snapshot?.(stamp(r)),
                bulkGuests: (rows, a) => actions?.bulkGuests?.(rows.map(stamp), a),
                bulkMigrate: (rows) => actions?.bulkMigrate?.(rows.map(stamp)),
                createVm: (type) => actions?.createVm?.(type),
                nodeAction: (n, a) => actions?.nodeAction?.(n, a),
                maintenanceToggle: (n, e) => actions?.maintenanceToggle?.(n, e),
                startUpdate: (n, r) => actions?.startUpdate?.(n, r),
                configNode: (n) => actions?.configNode?.(n),
                multiCluster: safeClusters.length > 1,   // gate the cross-cluster migrate item
                // what the dashboard handed over; a standby leaves out everything that acts (#625)
                has: (k) => typeof actions?.[k] === 'function',
                // a standby leaves out the consoles too, forwarding or not, unless it serves
                // users; this opens the guest's console on the active in their place
                consoleOnActive: haConsolesElsewhere ? (r) => haOpenOnActive(ha && ha.peer_url, haConsoleSearch(stamp(r))) : null,
            }), [actions, cid, safeClusters.length, haConsolesElsewhere, ha && ha.peer_url]);

            const vms = safeResources.filter(r => r && r.type === 'qemu');
            const cts = safeResources.filter(r => r && r.type === 'lxc');
            const dcStatus = (allClusterMetrics && cid != null && allClusterMetrics[cid]) ? allClusterMetrics[cid].data : null;

            // keep the open detail row fresh from live polling (status/cpu/mem/uptime/ip).
            // match by vmid+type; keep the last-known object if the guest vanishes. -- NS
            React.useEffect(() => {
                if (!detailRes) return;
                const arr = Array.isArray(clusterResources) ? clusterResources : [];
                const fresh = arr.find(r => r && r.vmid === detailRes.vmid && r.type === detailRes.type);
                if (fresh) setDetailRes(prev => ({ ...fresh, _clusterId: (prev && prev._clusterId) || cid }));
            }, [clusterResources]);

            const sectionLabels = {
                overview: T('cloud.overview') || 'Overview',
                vms: T('cloud.vms') || 'Virtual Machines',
                containers: T('cloud.containers') || 'Containers',
                apps: T('ociTabLabel') || 'App Containers',
                datastores: T('cloud.datastores') || 'Datastores',
                pools: T('cloud.pools') || 'Resource Pools',
                networks: T('cloud.networks') || 'Networks',
                clusters: T('cloud.clustersTitle') || 'Clusters',
                nodes: T('cloud.hosts') || 'Hosts',
                mappings: T('rmTitle') || 'Resource Mappings',
                ha: T('cloud.ha') || 'High Availability',
                storage: T('cloud.storageConfig') || 'Storage',
                ceph: T('cloud.ceph') || 'Ceph',
                sdn: T('cloud.sdn') || 'SDN',
                firewall: T('cloud.firewall') || 'Firewall',
                backups: T('cloud.backups') || 'Backups',
                replication: T('cloud.replication') || 'Replication',
                pbs: T('cloud.pbs') || 'Backup Servers',
                siterecovery: T('cloud.siteRecovery') || 'Site Recovery',
                monitoring: T('cloud.monitoring') || 'Monitoring',
                topology: T('topology') || 'Topology',
                compliance: T('compliance') || 'Compliance',
                snapshotpolicies: T('snapshotPolicies') || 'Snapshot Policies',
                templates: T('bpNavTab') || 'Blueprints & Templates',
                insights: T('insights') || 'Insights',
                costs: T('costDashboard') || 'Costs',
                power: T('powerTitle') || 'Power & Carbon',
                whatif: T('whatifTitle') || 'What-if',
                apihealth: T('apiHealth') || 'API Health',
                drift: T('configDrift') || 'Config Drift',
                siem: T('siem') || 'SIEM',
                alerts: T('alertChannels') || 'Alert Channels',
                updates: T('updateManager') || 'Update Manager',
                autoinstall: T('autoInstall') || 'Automated Installations',
                plugins: T('plugins') || 'Plugins',
                scripts: T('customScripts') || 'Scripts',
                schedules: T('scheduledActions') || 'Schedules',
                cve: T('cveScanner') || 'CVE Scanner',
                tasks: T('cloud.tasks') || 'Tasks',
                timeline: T('tlTab') || 'Timeline',
                changes: T('chgTab') || 'Changes',
                users: T('cloud.users') || 'Users',
                settings: T('cloud.settings') || 'Settings',
            };

            // LW Nov 2026 (#1220) - a guest of a blueprint deploy on another cluster: it opens once the first
            // list of that cluster has it, else that list says it is gone. Leaving the page or the cluster drops it
            const [bpWant, setBpWant] = React.useState(null);
            const bpGone = (vmid) => addToast && addToast(String(T('guestNotInClusterList') || 'Guest {id} is not in the list of this cluster').replace('{id}', vmid), 'warning');
            React.useEffect(() => {
                if (!bpWant) return undefined;
                if (bpWant.cid !== cid) { setBpWant(null); return undefined; }
                const onFrame = (e) => {
                    const d = (e && e.detail) || {};
                    if (d.cluster_id !== bpWant.cid || !Array.isArray(d.rows)) return;
                    const hit = d.rows.find(r => r && r.vmid === bpWant.vmid && r.type === bpWant.type);
                    setBpWant(null);
                    if (hit) setDetailRes({ ...hit, _clusterId: bpWant.cid });
                    else bpGone(bpWant.vmid);
                };
                window.addEventListener('pegaprox-resources-frame', onFrame);
                return () => window.removeEventListener('pegaprox-resources-frame', onFrame);
            }, [bpWant, cid]);

            const selectSection = (id) => {
                // Settings + Users open the full admin modal (same one classic uses) rather
                // than a placeholder page — keep the current content underneath. -- NS
                if (id === 'settings' || id === 'users') { onOpenSettings && onOpenSettings(); return; }
                setSection(id);
                setDetailRes(null);
                setBpWant(null);
            };
            const openDetail = (r) => setDetailRes(r);
            // where the blueprints lead: the guest a deploy made opens on the VMs page of its cluster,
            // and the editor suggests the bridges of a node of this one. A guest this cluster does not list
            // (deleted since) is said, not drawn as a guest of unknown state with a Start button
            const bpNav = {
                nodesOf: (id) => (id === cid ? clusterMetrics : null),
                openGuest: (id, guest) => {
                    const cl = safeClusters.find(c => c && c.id === id);
                    if (!cl || !guest) return;
                    if (id === cid) {
                        const known = safeResources.find(r => r && r.vmid === guest.vmid && r.type === guest.type);
                        if (!known) { bpGone(guest.vmid); return; }
                        setSection('vms');
                        setDetailRes({ ...known, _clusterId: id });
                        return;
                    }
                    setSelectedCluster(cl);
                    setSection('vms');
                    setDetailRes(null);
                    setBpWant({ cid: id, vmid: guest.vmid, type: guest.type });
                },
            };
            const pveCluster = !!selectedCluster && (!selectedCluster.cluster_type || selectedCluster.cluster_type === 'proxmox');
            const toBlueprints = canBp && !haReadOnly && pveCluster ? () => selectSection('templates') : undefined;

            // detail crumb when open
            const crumbs = ['Cloud', sectionLabels[section] || 'Overview'];
            if (detailRes && (section === 'vms' || section === 'containers')) crumbs.push(detailRes.name || ('#' + detailRes.vmid));

            let body;
            if (detailRes && (section === 'vms' || section === 'containers')) {
                body = <CloudInstanceDetail resource={stamp(detailRes)} act={act} onBack={() => setDetailRes(null)} t={T}
                    authFetch={authFetch} clusterName={selectedCluster ? (selectedCluster.display_name || selectedCluster.name) : null}
                    holdsPerm={holdsPerm} addToast={addToast} />;
            } else {
                switch (section) {
                    case 'overview':
                        body = <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} datastores={clusterDatastores} allData={allClusterMetrics} onNav={selectSection} t={T} authFetch={authFetch} />;
                        break;
                    case 'vms':
                        body = <CloudInstanceList rows={vms} kind="qemu" clusterId={cid} act={act} onOpen={openDetail} onCreate={act.createVm} onBlueprints={toBlueprints} t={T} />;
                        break;
                    case 'containers':
                        body = <CloudInstanceList rows={cts} kind="lxc" clusterId={cid} act={act} onOpen={openDetail} onCreate={act.createVm} t={T} />;
                        break;
                    case 'apps':
                        // raw t: every string of the tab is translated, and it fills {placeholders} in
                        body = <div className="cloud-mounted"><OciCatalogTab clusters={safeClusters} clusterId={cid} authFetch={authFetch} addToast={addToast} t={t} /></div>;
                        break;
                    case 'datastores':
                        body = <CloudDatastores datastores={clusterDatastores} t={T} />;
                        break;
                    case 'swexplorer':
                        body = <CloudStorageExplorer clusterId={cid} authFetch={authFetch} addToast={addToast} isAdmin={isAdmin} holdsPerm={holdsPerm} t={T} sharedDatastores={clusterDatastores} />;
                        break;
                    case 'swiso':
                        body = <CloudIsoSync clusterId={cid} authFetch={authFetch} addToast={addToast} t={T} />;
                        break;
                    case 'swsla':
                        body = <CloudBackupSla clusterId={cid} authFetch={authFetch} addToast={addToast} t={T} />;
                        break;
                    case 'pools':
                        body = <CloudPools pools={clusterPools} t={T} />;
                        break;
                    case 'networks':
                        body = <div className="cloud-mounted"><NetworkTab clusterId={cid} addToast={addToast} /></div>;
                        break;
                    case 'clusters':
                        body = <CloudClusters clusters={safeClusters} resources={safeResources} allClusterMetrics={allClusterMetrics} t={T} />;
                        break;
                    case 'nodes':
                        body = <CloudNodes metrics={clusterMetrics} act={act} isAdmin={isAdmin} t={T} />;
                        break;
                    case 'ha':
                        body = <div className="cloud-mounted"><CloudHaNodeNotes clusterId={cid} t={t} authFetch={authFetch} /><ProxmoxHaSection clusterId={cid} /></div>;
                        break;
                    case 'storage':
                        body = <div className="cloud-mounted"><DatastoreTab clusterId={cid} addToast={addToast} sharedDatastoreData={clusterDatastores} /></div>;
                        break;
                    case 'mappings':
                        body = <div className="cloud-mounted">{cid && <ResourceMappingsSection clusterId={cid} addToast={addToast} />}</div>;
                        break;
                    case 'ceph':
                        body = <CloudCeph clusterId={cid} t={T} />;
                        break;
                    case 'sdn':
                        // NOTE: Corporate's SDN CRUD lives inside the monolithic DatacenterTab
                        // hub (Cluster/Storage/SDN/Backup/…), which would duplicate the flat
                        // cloud nav + mislabel under "SDN". Keep the scoped cloud view for now;
                        // a cloud-native scoped SDN CRUD is a follow-up. -- NS
                        body = <CloudSDN clusterId={cid} t={T} />;
                        break;
                    case 'firewall':
                        body = <CloudFirewall clusterId={cid} t={T} />;
                        break;
                    case 'backups':
                        body = <CloudBackups clusterId={cid} t={T} />;
                        break;
                    case 'replication':
                        body = <CloudReplication clusterId={cid} t={T} />;
                        break;
                    case 'pbs':
                        body = <CloudPBS t={T} />;
                        break;
                    case 'siterecovery':
                        body = <div className="cloud-mounted"><SiteRecoveryTab clusters={safeClusters} selectedCluster={selectedCluster} authFetch={authFetch} addToast={addToast} t={T} isCorporate={false} srProgress={{}} user={currentUser} /></div>;
                        break;
                    case 'monitoring':
                        body = <CloudMonitoring clusterId={cid} t={T} />;
                        break;
                    // NS 2026-07: parity with Corporate — mount the SAME real components
                    // (defined in dashboard.js, hoisted into the shared script scope) inside
                    // a cloud content frame so the functionality is identical, not a re-impl.
                    case 'topology':
                        body = (
                            <div className="cloud-mounted">
                                <TopologyTab clusterId={cid} authFetch={authFetch} addToast={addToast} t={T} />
                            </div>
                        );
                        break;
                    case 'compliance':
                        body = (
                            <div className="cloud-mounted">
                                <ComplianceDashboardTab clusters={safeClusters} selectedCluster={selectedCluster} authFetch={authFetch} addToast={addToast} t={T} isCorporate={false} user={currentUser} />
                            </div>
                        );
                        break;
                    case 'snapshotpolicies':
                        body = (
                            <div className="cloud-mounted">
                                <SnapshotPoliciesTab clusterId={cid} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} />
                            </div>
                        );
                        break;
                    case 'templates':
                        body = (
                            <div className="cloud-mounted cloud-body">
                                {/* the blueprints above the library, as in Modern */}
                                {cid && (
                                    <Blueprints key={cid} cluster={selectedCluster} clusters={safeClusters} authFetch={authFetch} addToast={addToast}
                                        canRead={canBp} canWrite={canBp && !haReadOnly} nav={bpNav} cloud />
                                )}
                                <TemplatesLibraryTab clusterId={cid} clusterName={selectedCluster && selectedCluster.name} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} isCorporate={false} />
                            </div>
                        );
                        break;
                    case 'insights':
                        body = <div className="cloud-mounted"><InsightsTab clusterId={cid} clusterName={selectedCluster && selectedCluster.name} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} /></div>;
                        break;
                    case 'costs':
                        body = <div className="cloud-mounted"><CostDashboardTab clusterId={cid} clusterName={selectedCluster && selectedCluster.name} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} /></div>;
                        break;
                    case 'power':
                        body = <div className="cloud-mounted"><PowerCarbonTab clusterId={cid} clusterName={selectedCluster && selectedCluster.name} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} /></div>;
                        break;
                    case 'whatif':
                        body = <div className="cloud-mounted">{cid && <WhatIfTab clusterId={cid} authFetch={authFetch} />}</div>;
                        break;
                    case 'apihealth':
                        body = <div className="cloud-mounted"><ApiLatencyDashboard clusterId={cid} authFetch={authFetch} apiUrl={API_URL} t={T} /></div>;
                        break;
                    case 'timeline':
                        body = <div className="cloud-mounted"><TimelineView key={cid} clusterId={cid} authFetch={authFetch} t={t} /></div>;
                        break;
                    case 'changes':
                        body = canChanges
                            ? <div className="cloud-mounted"><ChangesTab clusterId={cid} authFetch={authFetch} addToast={addToast} t={t} canRequest={holdsPerm('changes.request')} /></div>
                            : <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} onNav={selectSection} t={T} />;
                        break;
                    case 'drift':
                        body = <div className="cloud-mounted"><DriftTab clusterId={cid} clusterName={selectedCluster && selectedCluster.name} authFetch={authFetch} addToast={addToast} t={T} isAdmin={isAdmin} /></div>;
                        break;
                    case 'siem':
                        body = <div className="cloud-mounted"><SIEMTab addToast={addToast} t={T} getAuthHeaders={() => ({})} /></div>;
                        break;
                    case 'alerts':
                        body = <div className="cloud-mounted"><AlertChannelsPanel t={T} addToast={addToast} getAuthHeaders={() => ({})} /></div>;
                        break;
                    case 'autoinstall':
                        // raw t on purpose: T gives undefined on a miss, and the panel strings
                        // t() results together into confirms and labels
                        body = canAutoInstall
                            ? <div className="cloud-mounted"><AutoInstallPanel t={t} addToast={addToast} getAuthHeaders={() => ({})} clusters={safeClusters} /></div>
                            : <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} onNav={selectSection} t={T} />;
                        break;
                    case 'updates':
                        body = <div className="cloud-mounted"><UpdateManagerSection clusterId={cid} clusterName={selectedCluster && (selectedCluster.display_name || selectedCluster.name)} addToast={addToast} /></div>;
                        break;
                    case 'plugins':
                        body = <CloudPlugins clusterId={cid} t={T} />;
                        break;
                    case 'scripts':
                        body = <CloudScripts clusterId={cid} t={T} />;
                        break;
                    case 'schedules':
                        body = <CloudSchedules clusterId={cid} t={T} />;
                        break;
                    case 'cve':
                        body = <CloudCVE clusterId={cid} t={T} />;
                        break;
                    case 'tasks':
                        body = <CloudTasks tasks={tasks} t={T} />;
                        break;
                    case 'users':
                        body = <CloudClassicLauncher title={T('cloud.users') || 'Users'} icon="Users" text={T('cloud.usersClassic') || 'User, group and ACL management is available in the classic PegaProx layout.'} onExit={onExitCloud} t={T} />;
                        break;
                    case 'settings':
                        body = <CloudClassicLauncher title={T('cloud.settings') || 'Settings'} icon="Settings" text={T('cloud.settingsClassic') || 'Full settings (auth, backups, monitoring, integrations) live in the classic PegaProx layout.'} onExit={onExitCloud} t={T} />;
                        break;
                    default:
                        body = <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} datastores={clusterDatastores} allData={allClusterMetrics} onNav={selectSection} t={T} authFetch={authFetch} />;
                }
            }

            return (
                <div className="cloud-shell">
                    <CloudSideNav active={section} onSelect={selectSection} isAdmin={!!isAdmin} canAutoInstall={canAutoInstall} canChanges={canChanges} collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
                    <div className="cloud-content">
                        <CloudTopbar
                            crumbs={crumbs}
                            clusters={safeClusters}
                            selectedCluster={selectedCluster}
                            setSelectedCluster={setSelectedCluster}
                            theme={theme}
                            onToggleTheme={() => setTheme(th => th === 'light' ? 'dark' : 'light')}
                            onRefresh={() => actions?.refresh?.()}
                            onExitCloud={onExitCloud}
                            onOpenSettings={onOpenSettings}
                            onOpenProfile={onOpenProfile}
                            onOpenApiReference={onOpenApiReference}
                            onLogout={onLogout}
                            isAdmin={isAdmin}
                            currentUser={currentUser}
                            t={T}
                        />
                        <BroadcastBanners cloud />
                        {/* #625 - same banner as the classic layouts, in the shell's colours */}
                        <HaStandbyBanner cloud onOpenHa={() => {
                            onOpenSettings && onOpenSettings();
                            window.dispatchEvent(new CustomEvent('pegaprox-navigate-ha'));
                        }} />
                        <HaCopiesBanner cloud onOpenHa={() => {
                            onOpenSettings && onOpenSettings();
                            window.dispatchEvent(new CustomEvent('pegaprox-navigate-ha'));
                        }} />
                        <HaLeaderBanner cloud onOpenHa={() => {
                            onOpenSettings && onOpenSettings();
                            window.dispatchEvent(new CustomEvent('pegaprox-navigate-ha'));
                        }} />
                        <div className="cloud-content-scroll">
                            {body}
                            <CloudSponsorFooter t={T} />
                        </div>
                    </div>
                </div>
            );
        }
