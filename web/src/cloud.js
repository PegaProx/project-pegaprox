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
                const onScroll = () => setOpen(false);
                document.addEventListener('mousedown', onDoc);
                window.addEventListener('scroll', onScroll, true);
                window.addEventListener('resize', onScroll);
                return () => {
                    document.removeEventListener('mousedown', onDoc);
                    window.removeEventListener('scroll', onScroll, true);
                    window.removeEventListener('resize', onScroll);
                };
            }, [open]);
            const toggle = (e) => {
                e.stopPropagation();
                if (!open && btnRef.current) {
                    const r = btnRef.current.getBoundingClientRect();
                    setPos({ top: r.bottom + 4, left: Math.max(8, r.right - 210) });
                }
                setOpen(o => !o);
            };
            const visible = (items || []).filter(Boolean);
            return (
                <>
                    {triggerNode ? (
                        <button type="button" ref={btnRef} className="cloud-menu-trigger-plain" onClick={toggle} title={label || 'Actions'}>
                            {triggerNode}
                        </button>
                    ) : triggerLabel ? (
                        <button type="button" ref={btnRef} className="cloud-btn" onClick={toggle} title={label || 'Actions'}>
                            {triggerLabel} <Icons.ChevronDown />
                        </button>
                    ) : (
                        <button type="button" ref={btnRef} className="cloud-icon-btn" onClick={toggle} title={label || 'Actions'}>
                            <Icons.MoreVertical />
                        </button>
                    )}
                    {open && (
                        <div ref={menuRef} className="cloud-menu cloud-menu-fixed" style={{ top: pos.top, left: pos.left }} onClick={(e) => e.stopPropagation()}>
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
                        </div>
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
        function CloudBarChart({ rows, color }) {
            const max = Math.max(1, ...rows.map(r => Number(r.value) || 0));
            return (
                <div className="cloud-barchart">
                    {rows.length === 0 && <div className="cloud-empty">No data.</div>}
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
            return [
                (!running && !paused) && { label: t('start') || 'Start', icon: 'Play', onClick: () => act.vmAction(r, 'start') },
                paused && { label: t('resume') || 'Resume', icon: 'PlayCircle', onClick: () => act.vmAction(r, 'resume') },
                running && { label: t('shutdown') || 'Shutdown', icon: 'Power', onClick: () => act.vmAction(r, 'shutdown') },
                running && { label: t('reboot') || 'Reboot', icon: 'RotateCw', onClick: () => act.vmAction(r, 'reboot') },
                (running && !isCt) && { label: t('suspend') || 'Suspend', icon: 'Pause', onClick: () => act.vmAction(r, 'suspend') },
                running && { label: t('stop') || 'Stop', icon: 'Square', onClick: () => act.vmAction(r, 'stop') },
                running && { label: t('forceStop') || 'Force stop', icon: 'StopCircle', danger: true, onClick: () => act.forceStop(r) },
                { divider: true },
                { label: t('console') || 'Console', icon: 'Monitor', onClick: () => act.openConsole(r) },
                isCt && { label: t('shell') || 'Shell', icon: 'Terminal', onClick: () => act.openLxcShell(r) },
                { label: t('snapshots') || 'Snapshot', icon: 'Camera', onClick: () => act.snapshot(r) },
                { label: t('metrics') || 'Metrics', icon: 'BarChart', onClick: () => act.openMetrics(r) },
                { divider: true },
                { label: t('edit') || 'Edit / Hardware', icon: 'Cog', onClick: () => act.openConfig(r) },
                { label: t('migrate') || 'Migrate', icon: 'Send', onClick: () => act.migrate(r) },
                act.multiCluster && { label: t('cloud.crossMigrate') || 'Migrate to cluster…', icon: 'Send', onClick: () => act.crossMigrate(r) },
                { label: t('clone') || 'Clone', icon: 'Copy', onClick: () => act.clone(r) },
                { divider: true },
                { label: t('delete') || 'Delete', icon: 'Trash2', danger: true, onClick: () => act.del(r) },
            ].filter(Boolean);
        }

        // ── side nav (collapsible, grouped) ────────────────────────
        function CloudSideNav({ active, onSelect, isAdmin, collapsed, onToggle }) {
            const groups = [
                { label: 'DASHBOARD', items: [{ id: 'overview', label: 'Overview', icon: 'Grid' }] },
                { label: 'COMPUTE', items: [
                    { id: 'vms', label: 'Virtual Machines', icon: 'Server' },
                    { id: 'containers', label: 'Containers', icon: 'Box' },
                ] },
                { label: 'STORAGE', items: [
                    { id: 'datastores', label: 'Datastores', icon: 'Database' },
                    { id: 'storage', label: 'Storage Config', icon: 'HardDrive' },
                    { id: 'pools', label: 'Resource Pools', icon: 'Layers' },
                    { id: 'ceph', label: 'Ceph', icon: 'Database' },
                ] },
                { label: 'NETWORK', items: [
                    { id: 'networks', label: 'Networks', icon: 'Network' },
                    { id: 'sdn', label: 'SDN', icon: 'Globe' },
                    { id: 'firewall', label: 'Firewall', icon: 'Lock' },
                    { id: 'topology', label: 'Topology', icon: 'Share2' },
                ] },
                { label: 'DATA PROTECTION', items: [
                    { id: 'backups', label: 'Backups', icon: 'Archive' },
                    { id: 'replication', label: 'Replication', icon: 'Copy' },
                    { id: 'pbs', label: 'Backup Servers', icon: 'Server' },
                    { id: 'siterecovery', label: 'Site Recovery', icon: 'LifeBuoy' },
                ] },
                { label: 'AUTOMATION', items: [
                    { id: 'snapshotpolicies', label: 'Snapshot Policies', icon: 'Camera' },
                    { id: 'templates', label: 'Templates', icon: 'Copy' },
                ] },
                { label: 'INFRASTRUCTURE', items: [
                    { id: 'clusters', label: 'Clusters', icon: 'Cloud' },
                    { id: 'nodes', label: 'Hosts', icon: 'Cpu' },
                    { id: 'ha', label: 'High Availability', icon: 'Shield' },
                ] },
                { label: 'MONITORING', items: [{ id: 'monitoring', label: 'Monitoring', icon: 'Activity' }] },
                { label: 'REPORTS', items: [
                    { id: 'insights', label: 'Insights', icon: 'Zap' },
                    { id: 'costs', label: 'Costs', icon: 'DollarSign' },
                    { id: 'power', label: 'Power & Carbon', icon: 'Zap' },
                    { id: 'apihealth', label: 'API Health', icon: 'Activity' },
                ] },
                { label: 'ACTIVITY', items: [{ id: 'tasks', label: 'Tasks', icon: 'ClipboardList' }] },
            ];
            if (isAdmin) {
                groups.push({ label: 'GOVERNANCE', items: [
                    { id: 'compliance', label: 'Compliance', icon: 'Shield' },
                ] });
                groups.push({ label: 'SYSTEM', items: [
                    { id: 'users', label: 'Users', icon: 'Users' },
                    { id: 'settings', label: 'Settings', icon: 'Settings' },
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
                </nav>
            );
        }

        // ── top bar (masthead) ─────────────────────────────────────
        function CloudTopbar({ crumbs, clusters, selectedCluster, setSelectedCluster, theme, onToggleTheme, onRefresh, onExitCloud, onOpenSettings, onOpenProfile, onLogout, isAdmin, currentUser, t }) {
            const safe = Array.isArray(clusters) ? clusters : [];
            const selId = selectedCluster && (selectedCluster.id != null ? selectedCluster.id : selectedCluster.name);
            const onChange = (e) => {
                const val = e.target.value;
                const match = safe.find(c => String(c && (c.id != null ? c.id : c.name)) === String(val));
                if (match && typeof setSelectedCluster === 'function') setSelectedCluster(match);
            };
            const uname = (currentUser && (currentUser.username || currentUser.name)) || 'User';
            const initial = (uname[0] || 'U').toUpperCase();
            const userMenu = [
                { label: t('cloud.profile') || 'Profile & preferences', icon: 'User', onClick: () => onOpenProfile && onOpenProfile() },
                isAdmin && { label: t('cloud.settings') || 'Settings', icon: 'Settings', onClick: () => onOpenSettings && onOpenSettings() },
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
                        <div className="cloud-lang"><LanguageSwitcher /></div>
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
        function CloudDashboard({ clusters, resources, metrics, dcStatus, tasks, onNav, t }) {
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

            // top RAM consumers among running guests
            const topMem = running
                .map(r => ({ label: r.name || ('guest-' + r.vmid), value: Number(r.mem) || 0 }))
                .sort((a, b) => b.value - a.value).slice(0, 6)
                .map(r => ({ ...r, display: cloudFmtBytes(r.value) }));

            const recentTasks = (Array.isArray(tasks) ? tasks : []).slice(0, 6);

            const kpis = [
                { icon: 'Server', value: vms.length, label: t('cloud.vms') || 'Virtual Machines', accent: '#6366f1', sub: `${vms.filter(v => v.status === 'running').length} running`, nav: 'vms' },
                { icon: 'Box', value: cts.length, label: t('cloud.containers') || 'Containers', accent: '#14b8a6', sub: `${cts.filter(v => v.status === 'running').length} running`, nav: 'containers' },
                { icon: 'Cpu', value: nodeNames.length, label: t('cloud.hosts') || 'Hosts', accent: '#a855f7', sub: `${connected}/${safeClusters.length} clusters`, nav: 'nodes' },
                { icon: 'Activity', value: running.length, label: t('cloud.running') || 'Running guests', accent: '#22c55e', sub: `${safeRes.length} total`, nav: null },
                { icon: 'Cpu', value: vcpu, label: t('cloud.vcpu') || 'vCPU allocated', accent: '#0ea5e9', sub: null, nav: null },
                { icon: 'MemoryStick', value: cloudBytesToGiB(ramAllocB).toFixed(1) + ' GiB', label: t('cloud.ram') || 'RAM allocated', accent: '#f59e0b', sub: null, nav: null },
            ];

            return (
                <div className="cloud-body">
                    <CloudPageHeader
                        title={t('cloud.overview') || 'Overview'}
                        sub={`${connected} / ${safeClusters.length} ${t('cloud.clustersConnected') || 'clusters connected'} · ${safeRes.length} ${t('cloud.guestsShort') || 'guests'}`}
                    />
                    <div className="cloud-kpi-grid">
                        {kpis.map((k, i) => (
                            <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} sub={k.sub}
                                onClick={k.nav ? () => onNav(k.nav) : undefined} />
                        ))}
                    </div>

                    <div className="cloud-dash-grid">
                        <div className="cloud-card cloud-util-card">
                            <CloudSectionTitle>{t('cloud.utilization') || 'Cluster utilization'}</CloudSectionTitle>
                            <div className="cloud-util-body">
                                <div className="cloud-util-gauges">
                                    <CloudGauge pct={cpuAvg} color="var(--cloud-accent)" label={t('cloud.avgCpu') || 'Avg CPU'} sub={`${nodeNames.length} hosts`} />
                                    <CloudGauge pct={memAvg} color="#a855f7" label={t('cloud.avgRam') || 'Avg RAM'} sub={dcStatus?.resources?.memory ? cloudFmtBytes(dcStatus.resources.memory.used) : null} />
                                </div>
                                <div className="cloud-util-breakdown">
                                    <div className="cloud-util-row"><span>{t('cloud.running') || 'Running'}</span><span>{running.length} / {safeRes.length}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.vcpu') || 'vCPU allocated'}</span><span>{vcpu}</span></div>
                                    <div className="cloud-util-row"><span>{t('cloud.ram') || 'RAM allocated'}</span><span>{cloudBytesToGiB(ramAllocB).toFixed(1)} GiB</span></div>
                                    {dcStatus?.resources?.storage && (
                                        <div className="cloud-util-row"><span>{t('cloud.storage') || 'Storage used'}</span><span>{cloudFmtBytes(dcStatus.resources.storage.used)} / {cloudFmtBytes(dcStatus.resources.storage.total)}</span></div>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="cloud-card">
                            <CloudSectionTitle>{t('cloud.topMem') || 'Top memory consumers'}</CloudSectionTitle>
                            <CloudBarChart rows={topMem} color="#6366f1" />
                        </div>
                    </div>

                    <div className="cloud-card">
                        <CloudSectionTitle right={<button type="button" className="cloud-link-btn" onClick={() => onNav('tasks')}>{t('cloud.viewAll') || 'View all'}</button>}>
                            {t('cloud.recentTasks') || 'Recent activity'}
                        </CloudSectionTitle>
                        {recentTasks.length === 0 ? (
                            <div className="cloud-empty">{t('cloud.noTasks') || 'No recent tasks.'}</div>
                        ) : (
                            <div className="cloud-tasklist">
                                {recentTasks.map((tk, i) => (
                                    <div className="cloud-task-row" key={tk.upid || i}>
                                        <span className={'cloud-task-dot ' + (tk.status === 'running' ? 'is-run' : tk.status === 'OK' ? 'is-ok' : 'is-err')} />
                                        <span className="cloud-task-type">{tk.type || 'task'}</span>
                                        <span className="cloud-task-target">{tk.id || ''}</span>
                                        <span className="cloud-task-node">{tk.node || ''}</span>
                                        <span className="cloud-task-time">{cloudRelTime(tk.starttime)}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // ── instances list (VMs / Containers) ──────────────────────
        function CloudInstanceList({ rows, kind, clusterId, act, onOpen, onCreate, t }) {
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

            const bulk = (action) => selectedRows.forEach(r => act.vmAction(r, action));

            return (
                <div className="cloud-body">
                    <CloudPageHeader title={title} sub={`${safe.length} ${kind === 'lxc' ? (t('cloud.containers') || 'containers') : (t('cloud.vms') || 'virtual machines')}`}>
                        <button type="button" className="cloud-btn cloud-btn-primary" onClick={() => onCreate(kind === 'lxc' ? 'lxc' : 'qemu')}>
                            <Icons.Plus /> {kind === 'lxc' ? (t('newContainer') || 'New Container') : (t('newVm') || 'New VM')}
                        </button>
                    </CloudPageHeader>

                    <div className="cloud-card cloud-table-card">
                        <div className="cloud-toolbar">
                            <div className="cloud-toolbar-left">
                                {selCount > 0 ? (
                                    <div className="cloud-bulkbar">
                                        <span className="cloud-sel-note">{selCount} {t('cloud.selected') || 'selected'}</span>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('start')}><Icons.Play /> {t('start') || 'Start'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('shutdown')}><Icons.Power /> {t('shutdown') || 'Shutdown'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm" onClick={() => bulk('reboot')}><Icons.RotateCw /> {t('reboot') || 'Reboot'}</button>
                                        <button type="button" className="cloud-btn cloud-btn-sm cloud-btn-danger" onClick={() => bulk('stop')}><Icons.Square /> {t('stop') || 'Stop'}</button>
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
                                        <button type="button" onClick={() => { setStatusFilter('all'); setPage(0); }} aria-label="Remove filter"><Icons.X /></button>
                                    </span>
                                )}
                                {q && (
                                    <span className="cloud-filterchip">
                                        {(t('cloud.search') || 'Search')}: “{query}”
                                        <button type="button" onClick={() => { setQuery(''); setPage(0); }} aria-label="Remove filter"><Icons.X /></button>
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
                                action={!(q || statusFilter !== 'all') ? (
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
                                            <th className="cloud-th-check"><input type="checkbox" checked={pageAllOn} onChange={toggleAllPage} aria-label="Select page" /></th>
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
                                                        <input type="checkbox" checked={isChecked} onChange={() => {}} tabIndex={-1} aria-label="Select" />
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
        function CloudInstanceDetail({ resource, act, onBack, t }) {
            const [tab, setTab] = React.useState('info');
            React.useEffect(() => { setTab('info'); }, [resource && resource.vmid, resource && resource._clusterId]);
            if (!resource) return null;
            const r = resource;
            const isCt = r.type === 'lxc';
            const running = r.status === 'running';
            const cpuP = cloudCpuPct(r);
            const memP = cloudMemPct(r);
            const memMax = Number(r.maxmem) || 0, memUse = Number(r.mem) || 0;
            const diskMax = Number(r.maxdisk) || 0, diskUse = Number(r.disk) || 0;
            const tags = cloudTagList(r.tags);

            const tabs = [
                { id: 'info', label: t('cloud.tabInfo') || 'Info' },
                { id: 'capacity', label: t('cloud.tabCapacity') || 'Capacity' },
                { id: 'network', label: t('cloud.tabNetwork') || 'Network' },
            ];

            // primary action buttons in the bar (contextual) + full kebab
            const primary = running
                ? [
                    { label: t('shutdown') || 'Shutdown', icon: 'Power', onClick: () => act.vmAction(r, 'shutdown') },
                    { label: t('reboot') || 'Reboot', icon: 'RotateCw', onClick: () => act.vmAction(r, 'reboot') },
                ]
                : [{ label: t('start') || 'Start', icon: 'Play', primary: true, onClick: () => act.vmAction(r, 'start') }];

            return (
                <div className="cloud-body">
                    <div className="cloud-detail-head">
                        <button type="button" className="cloud-icon-btn cloud-back-btn" onClick={onBack} title={t('cloud.back') || 'Back'}><Icons.ArrowLeft /></button>
                        <span className="cloud-detail-icon">{isCt ? <Icons.Box /> : <Icons.Server />}</span>
                        <div className="cloud-detail-titlewrap">
                            <h1 className="cloud-detail-title">{r.name || ('guest-' + (r.vmid != null ? r.vmid : ''))}</h1>
                            <div className="cloud-detail-meta">
                                <CloudStatusChip status={r.status} />
                                <span className="cloud-detail-id">#{r.vmid} · {isCt ? 'Container' : 'VM'} · {r.node || '—'}</span>
                            </div>
                        </div>
                        <div className="cloud-detail-actions">
                            {primary.map((b, i) => (
                                <button type="button" key={i} className={'cloud-btn' + (b.primary ? ' cloud-btn-primary' : '')} onClick={b.onClick}>
                                    {React.createElement(Icons[b.icon] || Icons.Box)} {b.label}
                                </button>
                            ))}
                            <button type="button" className="cloud-btn" onClick={() => act.openConsole(r)}><Icons.Monitor /> {t('console') || 'Console'}</button>
                            <CloudActionMenu items={cloudVmActionItems(r, act, t)} triggerLabel={t('cloud.actions') || 'Actions'} label="Actions" />
                        </div>
                    </div>

                    <div className="cloud-tabs">
                        {tabs.map(tb => (
                            <button type="button" key={tb.id} className={'cloud-tab' + (tab === tb.id ? ' cloud-tab-active' : '')} onClick={() => setTab(tb.id)}>{tb.label}</button>
                        ))}
                    </div>

                    {tab === 'info' && (
                        <div className="cloud-kv-grid">
                            <CloudKVPanel title={t('cloud.information') || 'Information'}>
                                <CloudKVRow label={t('cloud.colId') || 'ID'} value={r.vmid} />
                                <CloudKVRow label={t('cloud.colName') || 'Name'} value={r.name} />
                                <CloudKVRow label={t('cloud.type') || 'Type'} value={isCt ? 'Container (LXC)' : 'Virtual Machine'} />
                                <CloudKVRow label={t('cloud.colStatus') || 'Status'} value={<CloudStatusChip status={r.status} />} />
                                <CloudKVRow label={t('cloud.colNode') || 'Host'} value={r.node} />
                                <CloudKVRow label={t('cloud.uptime') || 'Uptime'} value={cloudFmtUptime(r.uptime)} />
                                {r.pool && <CloudKVRow label={t('cloud.pool') || 'Pool'} value={r.pool} />}
                                {r.template ? <CloudKVRow label={t('cloud.template') || 'Template'} value="Yes" /> : null}
                            </CloudKVPanel>
                            <CloudKVPanel title={t('cloud.tabCapacity') || 'Capacity'}>
                                <CloudKVRow label={t('cloud.vcpu') || 'vCPU'} value={Number(r.maxcpu) || '—'} />
                                <CloudKVRow label={t('cloud.colCpu') || 'CPU usage'} value={cpuP + '%'} />
                                <CloudKVRow label={t('cloud.ram') || 'Memory'} value={memMax ? cloudFmtBytes(memMax) : '—'} />
                                <CloudKVRow label={t('cloud.ramInUse') || 'Memory used'} value={`${cloudFmtBytes(memUse)} (${memP}%)`} />
                                {diskMax > 0 && <CloudKVRow label={t('cloud.disk') || 'Disk'} value={`${cloudFmtBytes(diskUse)} / ${cloudFmtBytes(diskMax)}`} />}
                            </CloudKVPanel>
                            <CloudKVPanel title={t('cloud.tabNetwork') || 'Network'}>
                                <CloudKVRow label={t('cloud.ip') || 'IP address'} value={r.ip || (Array.isArray(r.ip_addresses) ? r.ip_addresses[0] : null)} />
                                <CloudKVRow label={t('cloud.colNode') || 'Host'} value={r.node} />
                            </CloudKVPanel>
                            {tags.length > 0 && (
                                <CloudKVPanel title={t('cloud.tags') || 'Tags'}>
                                    <div className="cloud-tag-wrap">
                                        {tags.map((tg, i) => <span className="cloud-chip cloud-chip-tag" key={i}><Icons.Tag /> {tg}</span>)}
                                    </div>
                                </CloudKVPanel>
                            )}
                        </div>
                    )}

                    {tab === 'capacity' && (
                        <div className="cloud-card">
                            <div className="cloud-meter-block">
                                <div className="cloud-meter-label">{t('cloud.colCpu') || 'CPU'} · {cpuP}%</div>
                                <div className="cloud-meter cloud-meter-lg"><div style={{ width: cpuP + '%', background: 'var(--cloud-accent)' }} /></div>
                                <div className="cloud-meter-sub">{Number(r.maxcpu) || 0} {t('cloud.cores') || 'vCPU'}</div>
                            </div>
                            <div className="cloud-meter-block">
                                <div className="cloud-meter-label">{t('cloud.ram') || 'Memory'} · {memP}%</div>
                                <div className="cloud-meter cloud-meter-lg"><div style={{ width: memP + '%', background: '#a855f7' }} /></div>
                                <div className="cloud-meter-sub">{cloudFmtBytes(memUse)} / {cloudFmtBytes(memMax)}</div>
                            </div>
                            {diskMax > 0 && (
                                <div className="cloud-meter-block">
                                    <div className="cloud-meter-label">{t('cloud.disk') || 'Disk'} · {Math.round(diskUse / diskMax * 100)}%</div>
                                    <div className="cloud-meter cloud-meter-lg"><div style={{ width: Math.round(diskUse / diskMax * 100) + '%', background: '#0ea5e9' }} /></div>
                                    <div className="cloud-meter-sub">{cloudFmtBytes(diskUse)} / {cloudFmtBytes(diskMax)}</div>
                                </div>
                            )}
                            <button type="button" className="cloud-btn" onClick={() => act.openMetrics(r)} style={{ marginTop: 'var(--space-md)' }}><Icons.BarChart /> {t('cloud.openMetrics') || 'Open detailed metrics'}</button>
                        </div>
                    )}

                    {tab === 'network' && (
                        <div className="cloud-card">
                            <div className="cloud-kv-panel">
                                <CloudKVRow label={t('cloud.ip') || 'IP address'} value={r.ip || (t('cloud.noIp') || 'Not reported (guest agent required)')} />
                                {Array.isArray(r.ip_addresses) && r.ip_addresses.length > 1 && (
                                    <CloudKVRow label={t('cloud.allIps') || 'All IPs'} value={r.ip_addresses.join(', ')} />
                                )}
                                <CloudKVRow label={t('cloud.colNode') || 'Host'} value={r.node} />
                            </div>
                            <button type="button" className="cloud-btn" onClick={() => act.openConfig(r)} style={{ marginTop: 'var(--space-md)' }}><Icons.Cog /> {t('cloud.editHardware') || 'Edit network hardware'}</button>
                        </div>
                    )}
                </div>
            );
        }

        // ── datastores ─────────────────────────────────────────────
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
                    <CloudPageHeader title={t('cloud.hosts') || 'Hosts'} sub={`${names.length} ${t('cloud.hosts') || 'hosts'}`} />
                    {names.length === 0 ? <div className="cloud-card"><CloudEmpty icon="Cpu" title={t('cloud.noNodes') || 'No host data'} text={t('cloud.selectCluster') || 'Select a connected cluster.'} /></div> : (
                        <div className="cloud-card-grid cloud-card-grid-wide">
                            {names.map(name => {
                                const m = map[name] || {};
                                const online = m.status === 'online' || (!m.offline && m.status !== 'offline');
                                const cpuP = Math.round(Number(m.cpu_percent) || 0);
                                const memP = Math.round(Number(m.mem_percent) || 0);
                                const diskP = Math.round(Number(m.disk_percent) || 0);
                                const maint = m.maintenance_mode;
                                const nodeActions = isAdmin ? [
                                    { label: t('cloud.manageHost') || 'Manage host', icon: 'Cog', onClick: () => act.configNode(name) },
                                    { divider: true },
                                    maint
                                        ? { label: t('disableMaintenance') || 'Disable maintenance', icon: 'Wrench', onClick: () => act.maintenanceToggle(name, false) }
                                        : { label: t('startingMaintenanceMode') || 'Maintenance mode', icon: 'Wrench', onClick: () => act.maintenanceToggle(name, true) },
                                    { label: t('cloud.update') || 'Update (apt)', icon: 'Download', onClick: () => act.startUpdate(name, false) },
                                    { divider: true },
                                    { label: t('rebootNode') || 'Reboot', icon: 'RotateCw', danger: true, onClick: () => act.nodeAction(name, 'reboot') },
                                    { label: t('shutdownNode') || 'Shutdown', icon: 'Power', danger: true, onClick: () => act.nodeAction(name, 'shutdown') },
                                ] : [];
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
                                                        : <CloudPill color="#e0686c" bg="rgba(248,113,113,0.14)" border="rgba(248,113,113,0.36)" dot>{tk.status || 'Error'}</CloudPill>}</td>
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
            const reload = React.useCallback(() => {
                if (!path) { setLoading(false); return; }
                setLoading(true); setErr(null);
                fetch(path, { headers: getAuthHeaders() })
                    .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))
                    .then(d => { setData(d); setLoading(false); })
                    .catch(e => { setErr(String(e && e.message || e)); setLoading(false); });
            }, [path]);
            React.useEffect(() => { reload(); }, [reload]);
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
        function useCloudMutate(reload) {
            const { getAuthHeaders } = useAuth();
            const [busy, setBusy] = React.useState('');
            const run = React.useCallback((key, method, path, body, confirmMsg) => {
                if (confirmMsg && !window.confirm(confirmMsg)) return;
                setBusy(key);
                const opts = { method, headers: Object.assign({}, getAuthHeaders(), { 'Content-Type': 'application/json' }) };
                if (body !== undefined) opts.body = JSON.stringify(body);
                fetch(path, opts)
                    .then(r => r.ok ? r.json().catch(() => ({})) : Promise.reject(new Error('HTTP ' + r.status)))
                    .then(() => { setBusy(''); if (reload) reload(); })
                    .catch(e => { setBusy(''); window.alert('Action failed: ' + (e && e.message || e)); });
            }, [reload]);
            return { busy, run };
        }
        function CloudRowActions({ children }) { return <td><div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>{children}</div></td>; }

        // ── Backups (vzdump jobs) ──────────────────────────────────
        function CloudBackups({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/backup` : null);
            const mut = useCloudMutate(reload);
            const jobs = Array.isArray(data) ? data : [];
            const active = jobs.filter(j => Number(j.enabled) === 1 || j.enabled === true).length;
            const failed = jobs.filter(j => (j['last-run-status'] || '').toLowerCase().indexOf('err') >= 0).length;
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
                                    const st = (j['last-run-status'] || '').toLowerCase();
                                    const ok = st === 'ok' || st === 'OK'.toLowerCase();
                                    return (<tr className="cloud-table-row cloud-table-row-static" key={j.id || i}>
                                        <td className="cloud-table-mono">{j.schedule || '—'}</td>
                                        <td>{(Number(j.all) === 1) ? <span className="cloud-chip cloud-chip-soft">{t('cloud.allGuests') || 'All guests'}</span> : <span className="cloud-table-mono">{j.vmid || '—'}</span>}</td>
                                        <td>{j.storage || '—'}</td>
                                        <td className="cloud-cell-muted">{j.mode || 'snapshot'}{j.compress && j.compress !== '0' ? ' · ' + j.compress : ''}</td>
                                        <td>{st ? (ok ? <span className="cloud-chip cloud-chip-ok">OK</span> : <span className="cloud-chip cloud-chip-err">{j['last-run-status']}</span>) : <span className="cloud-cell-muted">—</span>}</td>
                                        <td>{(Number(j.enabled) === 1 || j.enabled === true) ? <CloudConnChip connected={true} t={t} /> : <CloudConnChip connected={false} t={t} />}</td>
                                        <CloudRowActions>
                                            <CloudIconBtn icon="Play" title={t('cloud.runNow') || 'Run now'} onClick={() => mut.run('r' + j.id, 'POST', `/api/clusters/${clusterId}/datacenter/backup/${j.id}/run`)} />
                                            <CloudIconBtn icon="Power" title={(Number(j.enabled) === 1 || j.enabled === true) ? (t('disable') || 'Disable') : (t('enable') || 'Enable')} onClick={() => mut.run('t' + j.id, 'PUT', `/api/clusters/${clusterId}/datacenter/backup/${j.id}`, { enabled: (Number(j.enabled) === 1 || j.enabled === true) ? 0 : 1 })} />
                                            <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + j.id, 'DELETE', `/api/clusters/${clusterId}/datacenter/backup/${j.id}`, undefined, (t('cloud.confirmDelBackup') || 'Delete this backup job?'))} />
                                        </CloudRowActions>
                                    </tr>);
                                })}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
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
            return (
                <div className="cloud-body">
                    <CloudPageHeader title={t('cloud.firewall') || 'Firewall'} sub={t('cloud.firewallSub') || 'Datacenter firewall rules'}>
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
                                        <CloudIconBtn icon="Power" title={(Number(r.enable) === 1 || r.enable === true) ? (t('disable') || 'Disable') : (t('enable') || 'Enable')} onClick={() => mut.run('t' + r.pos, 'PUT', `/api/clusters/${clusterId}/datacenter/firewall/rules/${r.pos}`, { enable: (Number(r.enable) === 1 || r.enable === true) ? 0 : 1 })} />
                                        <CloudIconBtn icon="Trash2" danger title={t('delete') || 'Delete'} onClick={() => mut.run('d' + r.pos, 'DELETE', `/api/clusters/${clusterId}/datacenter/firewall/rules/${r.pos}`, undefined, (t('cloud.confirmDelRule') || 'Delete this firewall rule?'))} />
                                    </CloudRowActions>
                                </tr>))}</tbody>
                            </table></div>
                        </div>
                    </CloudSectionState>
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
            const osdUp = osds.filter(o => o.up === 1 || o.up === true).length;
            const health = (c.status && (c.status.health || c.status.health_status)) || c.health || 'unknown';
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
                    <CloudSectionState loading={loading} err={err} empty={notAvail} emptyIcon="Database" emptyTitle={t('cloud.cephNA') || 'Ceph is not configured on this cluster'} t={t}>
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
        function CloudSDN({ clusterId, t }) {
            const { data, loading, err, reload } = useCloudData(clusterId ? `/api/clusters/${clusterId}/datacenter/sdn` : null);
            const s = data || {};
            const notAvail = !s.available;
            const zones = Array.isArray(s.zones) ? s.zones : [];
            const vnets = Array.isArray(s.vnets) ? s.vnets : [];
            const subnets = Array.isArray(s.subnets) ? s.subnets : [];
            const controllers = Array.isArray(s.controllers) ? s.controllers : [];
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
                    <CloudSectionState loading={loading} err={err} empty={notAvail && !zones.length && !vnets.length} emptyIcon="Network" emptyTitle={t('cloud.sdnNA') || 'SDN is not configured on this cluster'} t={t}>
                        <div className="cloud-kpi-grid">{kpis.map((k, i) => <CloudKpiCard key={i} icon={k.icon} value={k.value} label={k.label} accent={k.accent} />)}</div>
                        {zones.length ? (
                            <div className="cloud-card cloud-table-card">
                                {cloudHead({ icon: <Icons.Globe />, title: t('cloud.sdnZones') || 'Zones', count: zones.length })}
                                <div className="cloud-table-scroll"><table className="cloud-table">
                                    <thead><tr><th>{t('cloud.colName') || 'Name'}</th><th>{t('cloud.colType') || 'Type'}</th><th>{t('cloud.colState') || 'State'}</th></tr></thead>
                                    <tbody>{zones.map((z, i) => (<tr className="cloud-table-row cloud-table-row-static" key={z.zone || z.name || i}>
                                        <td>{z.zone || z.name || '—'}</td>
                                        <td className="cloud-table-mono">{z.type || '—'}</td>
                                        <td><span className="cloud-chip cloud-chip-soft">{z.state || z.status || 'ok'}</span></td>
                                    </tr>))}</tbody>
                                </table></div>
                            </div>
                        ) : null}
                    </CloudSectionState>
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
                                            <CloudIconBtn icon="Play" title={t('cloud.runNow') || 'Run now'} onClick={() => mut.run('r' + j.id, 'POST', `/api/clusters/${clusterId}/replication/${j.id}/run`)} />
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
                </footer>
            );
        }

        function CloudShell({ clusters, selectedCluster, setSelectedCluster, clusterResources, clusterMetrics, allClusterMetrics, clusterDatastores, clusterNetworks, clusterPools, tasks, knownNodes, actions, isAdmin, currentUser, t, authFetch, addToast, onExitCloud, onOpenSettings, onOpenProfile, onLogout }) {
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
                openLxcShell: (r) => actions?.openLxcShell?.(stamp(r)),
                openConfig: (r) => actions?.openConfig?.(stamp(r)),
                openMetrics: (r) => actions?.openMetrics?.(stamp(r)),
                migrate: (r) => actions?.migrate?.(stamp(r)),
                clone: (r) => actions?.clone?.(stamp(r)),
                del: (r) => actions?.del?.(stamp(r)),
                crossMigrate: (r) => actions?.crossMigrate?.(stamp(r)),
                snapshot: (r) => actions?.snapshot?.(stamp(r)),
                createVm: (type) => actions?.createVm?.(type),
                nodeAction: (n, a) => actions?.nodeAction?.(n, a),
                maintenanceToggle: (n, e) => actions?.maintenanceToggle?.(n, e),
                startUpdate: (n, r) => actions?.startUpdate?.(n, r),
                configNode: (n) => actions?.configNode?.(n),
                multiCluster: safeClusters.length > 1,   // gate the cross-cluster migrate item
            }), [actions, cid, safeClusters.length]);

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
                datastores: T('cloud.datastores') || 'Datastores',
                pools: T('cloud.pools') || 'Resource Pools',
                networks: T('cloud.networks') || 'Networks',
                clusters: T('cloud.clustersTitle') || 'Clusters',
                nodes: T('cloud.hosts') || 'Hosts',
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
                templates: T('templatesLibrary') || 'Templates',
                insights: T('insights') || 'Insights',
                costs: T('costDashboard') || 'Costs',
                power: T('powerTitle') || 'Power & Carbon',
                apihealth: T('apiHealth') || 'API Health',
                tasks: T('cloud.tasks') || 'Tasks',
                users: T('cloud.users') || 'Users',
                settings: T('cloud.settings') || 'Settings',
            };

            const selectSection = (id) => {
                // Settings + Users open the full admin modal (same one classic uses) rather
                // than a placeholder page — keep the current content underneath. -- NS
                if (id === 'settings' || id === 'users') { onOpenSettings && onOpenSettings(); return; }
                setSection(id);
                setDetailRes(null);
            };
            const openDetail = (r) => setDetailRes(r);

            // detail crumb when open
            const crumbs = ['Cloud', sectionLabels[section] || 'Overview'];
            if (detailRes && (section === 'vms' || section === 'containers')) crumbs.push(detailRes.name || ('#' + detailRes.vmid));

            let body;
            if (detailRes && (section === 'vms' || section === 'containers')) {
                body = <CloudInstanceDetail resource={stamp(detailRes)} act={act} onBack={() => setDetailRes(null)} t={T} />;
            } else {
                switch (section) {
                    case 'overview':
                        body = <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} onNav={selectSection} t={T} />;
                        break;
                    case 'vms':
                        body = <CloudInstanceList rows={vms} kind="qemu" clusterId={cid} act={act} onOpen={openDetail} onCreate={act.createVm} t={T} />;
                        break;
                    case 'containers':
                        body = <CloudInstanceList rows={cts} kind="lxc" clusterId={cid} act={act} onOpen={openDetail} onCreate={act.createVm} t={T} />;
                        break;
                    case 'datastores':
                        body = <CloudDatastores datastores={clusterDatastores} t={T} />;
                        break;
                    case 'pools':
                        body = <CloudPools pools={clusterPools} t={T} />;
                        break;
                    case 'networks':
                        body = <CloudNetworks networks={clusterNetworks} t={T} />;
                        break;
                    case 'clusters':
                        body = <CloudClusters clusters={safeClusters} resources={safeResources} allClusterMetrics={allClusterMetrics} t={T} />;
                        break;
                    case 'nodes':
                        body = <CloudNodes metrics={clusterMetrics} act={act} isAdmin={isAdmin} t={T} />;
                        break;
                    case 'ha':
                        body = <CloudHA clusterId={cid} t={T} />;
                        break;
                    case 'storage':
                        body = <CloudStorage clusterId={cid} t={T} />;
                        break;
                    case 'ceph':
                        body = <CloudCeph clusterId={cid} t={T} />;
                        break;
                    case 'sdn':
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
                        body = <CloudSiteRecovery t={T} />;
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
                            <div className="cloud-mounted">
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
                    case 'apihealth':
                        body = <div className="cloud-mounted"><ApiLatencyDashboard clusterId={cid} authFetch={authFetch} apiUrl={API_URL} t={T} /></div>;
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
                        body = <CloudDashboard clusters={safeClusters} resources={safeResources} metrics={clusterMetrics} dcStatus={dcStatus} tasks={tasks} onNav={selectSection} t={T} />;
                }
            }

            return (
                <div className="cloud-shell">
                    <CloudSideNav active={section} onSelect={selectSection} isAdmin={!!isAdmin} collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
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
                            onLogout={onLogout}
                            isAdmin={isAdmin}
                            currentUser={currentUser}
                            t={T}
                        />
                        <div className="cloud-content-scroll">
                            {body}
                            <CloudSponsorFooter t={T} />
                        </div>
                    </div>
                </div>
            );
        }
