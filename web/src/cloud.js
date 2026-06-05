        // ═══════════════════════════════════════════════
        // PegaProx - Cloud console skin (Preview)
        // Grouped nav + data tables + slide-in detail panel
        // self-contained: only React + Icons + passed props -- LW
        // ═══════════════════════════════════════════════

        // small local formatters so we don't drag in anything global -- LW
        function cloudFmtBytes(b) {
            const n = Number(b);
            if (!n || n < 0 || !isFinite(n)) return '0 B';
            const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
            let i = 0, v = n;
            while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
            return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
        }

        // bytes -> GiB number (for sums / tiles)
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

        // status -> token colour. unknown states fall back to muted
        function cloudStatusColor(status) {
            switch (status) {
                case 'running': return 'var(--cloud-success)';
                case 'stopped': return 'var(--cloud-text-muted)';
                case 'paused':
                case 'suspended': return 'var(--cloud-warning)';
                default: return 'var(--cloud-info)';
            }
        }

        // status -> filled-chip palette (text + tinted bg + border). The tinted
        // background is what gives the table that "console" feel vs plain coloured
        // text -- MK. rgba literals (not the css vars) so the tint reads right.
        function cloudStatusMeta(status) {
            switch (status) {
                case 'running':   return { label: 'Running',   color: '#34e2b6', bg: 'rgba(45,212,167,0.15)',  border: 'rgba(45,212,167,0.38)' };
                case 'stopped':   return { label: 'Stopped',   color: '#9fb4c6', bg: 'rgba(138,164,184,0.12)', border: 'rgba(138,164,184,0.26)' };
                case 'paused':    return { label: 'Paused',    color: '#f5b945', bg: 'rgba(245,185,69,0.15)',  border: 'rgba(245,185,69,0.38)' };
                case 'suspended': return { label: 'Suspended', color: '#f5b945', bg: 'rgba(245,185,69,0.15)',  border: 'rgba(245,185,69,0.38)' };
                default: {
                    const s = (status || 'unknown');
                    return { label: s.charAt(0).toUpperCase() + s.slice(1), color: '#56c7f5', bg: 'rgba(56,189,248,0.13)', border: 'rgba(56,189,248,0.32)' };
                }
            }
        }

        // small reusable filled pill (dot optional). used for VM status + cluster reachability
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

        // online/offline reachability chip (cluster + node level)
        function CloudConnChip({ connected, t }) {
            return connected
                ? <CloudPill color="#34e2b6" bg="rgba(45,212,167,0.15)" border="rgba(45,212,167,0.38)" dot>{(t && t('cloud.online')) || 'Online'}</CloudPill>
                : <CloudPill color="#f4868a" bg="rgba(248,113,113,0.13)" border="rgba(248,113,113,0.34)" dot>{(t && t('cloud.offline')) || 'Offline'}</CloudPill>;
        }

        // ─── side nav ──────────────────────────────────────────────
        // MK: section ids drive both nav highlight and which body renders
        function CloudSideNav({ active, onSelect, isAdmin }) {
            const groups = [
                { label: 'DASHBOARD', items: [
                    { id: 'overview', label: 'Overview', icon: 'Grid' },
                ] },
                { label: 'INSTANCES', items: [
                    { id: 'vms', label: 'Virtual Machines', icon: 'Server' },
                    { id: 'containers', label: 'Containers', icon: 'Box' },
                ] },
                { label: 'STORAGE', items: [
                    { id: 'datastores', label: 'Datastores', icon: 'Database' },
                ] },
                { label: 'NETWORK', items: [
                    { id: 'networks', label: 'Networks', icon: 'Network' },
                ] },
                { label: 'INFRASTRUCTURE', items: [
                    { id: 'clusters', label: 'Clusters', icon: 'Layers' },
                    { id: 'nodes', label: 'Nodes', icon: 'Cpu' },
                ] },
            ];
            if (isAdmin) {
                groups.push({ label: 'SYSTEM', items: [
                    { id: 'users', label: 'Users', icon: 'Users' },
                    { id: 'settings', label: 'Settings', icon: 'Settings' },
                ] });
            }

            return (
                <nav className="cloud-nav">
                    <div className="cloud-nav-brand">
                        <span className="cloud-nav-brand-mark"><Icons.Cloud /></span>
                        <span className="cloud-nav-brand-text">PegaProx Cloud</span>
                        <span className="cloud-chip cloud-chip-preview">PREVIEW</span>
                    </div>
                    {groups.map(group => (
                        <div className="cloud-nav-group" key={group.label}>
                            <div className="cloud-nav-group-label">{group.label}</div>
                            {group.items.map(item => {
                                const Ico = Icons[item.icon] || Icons.Box;
                                const isActive = active === item.id;
                                return (
                                    <button
                                        type="button"
                                        key={item.id}
                                        className={'cloud-nav-item' + (isActive ? ' cloud-nav-item-active' : '')}
                                        onClick={() => onSelect(item.id)}
                                    >
                                        <span className="cloud-nav-item-icon"><Ico /></span>
                                        <span className="cloud-nav-item-label">{item.label}</span>
                                    </button>
                                );
                            })}
                        </div>
                    ))}
                </nav>
            );
        }

        // ─── circular gauge (conic-gradient) ───────────────────────
        function CloudGauge({ pct, label, color }) {
            const p = cloudPct((Number(pct) || 0) / 100); // pct comes in as 0..100 already
            const safePct = Math.min(100, Math.max(0, Number(pct) || 0));
            const c = color || 'var(--cloud-accent)';
            return (
                <div className="cloud-gauge-wrap">
                    <div
                        className="cloud-gauge"
                        style={{ background: `conic-gradient(${c} ${safePct * 3.6}deg, var(--cloud-border-medium) 0)` }}
                    >
                        <div className="cloud-gauge-inner">
                            <span className="cloud-gauge-num">{Math.round(safePct)}%</span>
                        </div>
                    </div>
                    <div className="cloud-gauge-label">{label}</div>
                </div>
            );
        }

        // mini inline meter used in table cells
        function CloudMiniMeter({ pct, color }) {
            const p = Math.min(100, Math.max(0, Number(pct) || 0));
            return (
                <div className="cloud-cell-meter">
                    <div className="cloud-meter">
                        <div style={{ width: p + '%', background: color || 'var(--cloud-accent)' }} />
                    </div>
                    <span className="cloud-cell-meter-num">{Math.round(p)}%</span>
                </div>
            );
        }

        // ─── overview body ─────────────────────────────────────────
        function CloudOverview({ clusters, resources, t }) {
            const safeClusters = Array.isArray(clusters) ? clusters : [];
            const safeRes = Array.isArray(resources) ? resources : [];

            const connected = safeClusters.filter(c => c && c.connected).length;
            const distinctNodes = new Set(safeRes.map(r => r && r.node).filter(Boolean));
            const running = safeRes.filter(r => r && r.status === 'running');

            const vcpuSum = safeRes.reduce((acc, r) => acc + (Number(r && r.maxcpu) || 0), 0);
            const ramBytesSum = safeRes.reduce((acc, r) => acc + (Number(r && r.maxmem) || 0), 0);
            const ramGiB = cloudBytesToGiB(ramBytesSum);

            // avg cpu of running guests (cpu is 0..1 fraction)
            let avgCpu = 0;
            if (running.length) {
                const cpuTotal = running.reduce((acc, r) => acc + (Number(r && r.cpu) || 0), 0);
                avgCpu = (cpuTotal / running.length) * 100;
            }
            // ram used / allocated across running guests
            let memUsed = 0, memAlloc = 0;
            running.forEach(r => {
                memUsed += Number(r && r.mem) || 0;
                memAlloc += Number(r && r.maxmem) || 0;
            });
            const ramPct = memAlloc > 0 ? (memUsed / memAlloc) * 100 : 0;

            const tiles = [
                { icon: 'Layers', num: `${connected}/${safeClusters.length}`, label: t('cloud.clusters') || 'Clusters connected' },
                { icon: 'Cpu', num: distinctNodes.size, label: t('cloud.nodes') || 'Nodes' },
                { icon: 'Server', num: safeRes.length, label: t('cloud.guests') || 'VMs & Containers' },
                { icon: 'PlayCircle', num: running.length, label: t('cloud.running') || 'Running' },
                { icon: 'Activity', num: vcpuSum, label: t('cloud.vcpu') || 'vCPU allocated' },
                { icon: 'MemoryStick', num: `${ramGiB.toFixed(1)} GiB`, label: t('cloud.ram') || 'RAM allocated' },
            ];

            return (
                <div className="cloud-body">
                    <div className="cloud-page-header">
                        <div>
                            <h1 className="cloud-page-title">{t('cloud.overview') || 'Overview'}</h1>
                            <div className="cloud-page-sub">
                                {connected} / {safeClusters.length} {t('cloud.clustersConnected') || 'clusters connected'} · {safeRes.length} {t('cloud.guestsShort') || 'guests'}
                            </div>
                        </div>
                    </div>
                    <div className="cloud-stat-grid">
                        {tiles.map(tile => {
                            const Ico = Icons[tile.icon] || Icons.Box;
                            return (
                                <div className="cloud-stat" key={tile.label}>
                                    <div className="cloud-stat-icon"><Ico /></div>
                                    <div>
                                        <div className="cloud-stat-num">{tile.num}</div>
                                        <div className="cloud-stat-label">{tile.label}</div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    <div className="cloud-section-title">{t('cloud.utilization') || 'Utilization'}</div>
                    <div className="cloud-card cloud-util-card">
                        <div className="cloud-util-gauges">
                            <CloudGauge pct={avgCpu} color="var(--cloud-accent)" label={t('cloud.avgCpu') || 'Avg CPU (running)'} />
                            <CloudGauge pct={ramPct} color="var(--cloud-info)" label={t('cloud.ramUsed') || 'RAM used / allocated'} />
                        </div>
                        <div className="cloud-util-breakdown">
                            <div className="cloud-util-row"><span>{t('cloud.running') || 'Running'}</span><span>{running.length} / {safeRes.length}</span></div>
                            <div className="cloud-util-row"><span>{t('cloud.vcpu') || 'vCPU allocated'}</span><span>{vcpuSum}</span></div>
                            <div className="cloud-util-row"><span>{t('cloud.ram') || 'RAM allocated'}</span><span>{ramGiB.toFixed(1)} GiB</span></div>
                            <div className="cloud-util-row"><span>{t('cloud.ramInUse') || 'RAM in use'}</span><span>{cloudFmtBytes(memUsed)}</span></div>
                        </div>
                    </div>

                    <div className="cloud-section-title">{t('cloud.clustersTitle') || 'Clusters'}</div>
                    {safeClusters.length === 0 ? (
                        <div className="cloud-card cloud-empty">{t('cloud.noClusters') || 'No clusters configured.'}</div>
                    ) : (
                        <div className="cloud-card-grid">
                            {safeClusters.map(c => {
                                const cid = (c && (c.id != null ? c.id : c.name));
                                const guestsHere = safeRes.filter(r => r && (r._clusterId === cid)).length;
                                return (
                                    <div className="cloud-card cloud-cluster-card" key={String(cid)}>
                                        <div className="cloud-cluster-head">
                                            <span className="cloud-cluster-name">{(c && (c.display_name || c.name)) || 'cluster'}</span>
                                            <CloudConnChip connected={!!(c && c.connected)} t={t} />
                                        </div>
                                        <div className="cloud-cluster-host">{(c && c.host) || '—'}</div>
                                        {guestsHere > 0 && (
                                            <div className="cloud-cluster-meta">{guestsHere} {t('cloud.guestsShort') || 'guests'}</div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            );
        }

        // ─── resource data table (VMs / Containers) ────────────────
        const CLOUD_TABLE_LIMIT = 200;

        function CloudResourceTable({ rows, kind, onRowClick, selectedId, t }) {
            const safe = Array.isArray(rows) ? rows : [];
            const [query, setQuery] = React.useState('');
            const [checked, setChecked] = React.useState({});

            // clear transient table state when we flip between VMs/containers
            React.useEffect(() => { setChecked({}); setQuery(''); }, [kind]);

            const RowIcon = kind === 'lxc' ? (Icons.Box || Icons.Container) : Icons.Server;
            const title = kind === 'lxc' ? (t('cloud.containers') || 'Containers') : (t('cloud.vms') || 'Virtual Machines');

            const q = query.trim().toLowerCase();
            const filtered = q
                ? safe.filter(r => r && (
                    (r.name || '').toLowerCase().includes(q) ||
                    String(r.vmid != null ? r.vmid : '').includes(q) ||
                    (r.node || '').toLowerCase().includes(q)))
                : safe;
            const truncated = filtered.length > CLOUD_TABLE_LIMIT;
            const view = truncated ? filtered.slice(0, CLOUD_TABLE_LIMIT) : filtered;

            const rowKey = (r, idx) => `${r._clusterId || ''}-${r.vmid != null ? r.vmid : idx}`;
            const selCount = view.reduce((n, r, idx) => n + (checked[rowKey(r, idx)] ? 1 : 0), 0);
            const allOn = view.length > 0 && selCount === view.length;

            const toggleAll = () => {
                if (allOn) { setChecked({}); return; }
                const next = {};
                view.forEach((r, idx) => { next[rowKey(r, idx)] = true; });
                setChecked(next);
            };
            const toggleOne = (k) => setChecked(prev => {
                const n = Object.assign({}, prev);
                if (n[k]) delete n[k]; else n[k] = true;
                return n;
            });

            // toolbar: title + live count + (selection note) on the left, search on the right
            const toolbar = (
                <div className="cloud-toolbar">
                    <div className="cloud-toolbar-left">
                        <span className="cloud-toolbar-icon"><RowIcon /></span>
                        <span className="cloud-toolbar-title">{title}</span>
                        <span className="cloud-count-chip">{filtered.length}{(q && filtered.length !== safe.length) ? ` / ${safe.length}` : ''}</span>
                        {selCount > 0 && (
                            <span className="cloud-sel-note">
                                {selCount} {t('cloud.selected') || 'selected'}
                                <button type="button" className="cloud-sel-clear" onClick={() => setChecked({})}>{t('cloud.clear') || 'Clear'}</button>
                            </span>
                        )}
                    </div>
                    <div className="cloud-toolbar-right">
                        <div className="cloud-search">
                            <span className="cloud-search-icon"><Icons.Search /></span>
                            <input
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                placeholder={t('cloud.searchGuests') || 'Search name, ID or node…'}
                            />
                            {q && <button type="button" className="cloud-search-clear" onClick={() => setQuery('')} aria-label="Clear search"><Icons.X /></button>}
                        </div>
                    </div>
                </div>
            );

            if (safe.length === 0) {
                const word = kind === 'lxc' ? (t('cloud.noContainers') || 'No containers found.') : (t('cloud.noVms') || 'No virtual machines found.');
                return (
                    <div className="cloud-card cloud-table-card">
                        {toolbar}
                        <div className="cloud-empty">{word}</div>
                    </div>
                );
            }

            return (
                <div className="cloud-card cloud-table-card">
                    {toolbar}
                    {filtered.length === 0 ? (
                        <div className="cloud-empty">{t('cloud.noMatch') || 'No guests match your search.'}</div>
                    ) : (
                        <div className="cloud-table-scroll">
                            <table className="cloud-table cloud-table-selectable">
                                <thead>
                                    <tr>
                                        <th className="cloud-th-check">
                                            <input type="checkbox" checked={allOn} onChange={toggleAll} aria-label="Select all" />
                                        </th>
                                        <th>{t('cloud.colName') || 'Name'}</th>
                                        <th>{t('cloud.colId') || 'ID'}</th>
                                        <th>{t('cloud.colStatus') || 'Status'}</th>
                                        <th>{t('cloud.colNode') || 'Node'}</th>
                                        <th>{t('cloud.colCpu') || 'CPU'}</th>
                                        <th>{t('cloud.colRam') || 'RAM'}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {view.map((r, idx) => {
                                        if (!r) return null;
                                        const id = r.vmid != null ? r.vmid : idx;
                                        const k = rowKey(r, idx);
                                        const cpuP = cloudPct(r.cpu);
                                        const memMax = Number(r.maxmem) || 0;
                                        const memUse = Number(r.mem) || 0;
                                        const ramP = memMax > 0 ? Math.round((memUse / memMax) * 100) : 0;
                                        const isSel = selectedId != null && String(selectedId) === String(id);
                                        const isChecked = !!checked[k];
                                        return (
                                            <tr
                                                key={k}
                                                className={'cloud-table-row' + (isSel ? ' cloud-table-row-active' : '') + (isChecked ? ' cloud-table-row-checked' : '')}
                                                onClick={() => onRowClick && onRowClick(r)}
                                            >
                                                <td className="cloud-td-check" onClick={(e) => { e.stopPropagation(); toggleOne(k); }}>
                                                    <input type="checkbox" checked={isChecked} onChange={() => {}} tabIndex={-1} aria-label={'Select ' + (r.name || id)} />
                                                </td>
                                                <td>
                                                    <span className="cloud-table-name">
                                                        <span className="cloud-table-name-icon"><RowIcon /></span>
                                                        {r.name || ('guest-' + id)}
                                                    </span>
                                                </td>
                                                <td className="cloud-table-mono">{r.vmid != null ? r.vmid : '—'}</td>
                                                <td><CloudStatusChip status={r.status} /></td>
                                                <td>{r.node || '—'}</td>
                                                <td><CloudMiniMeter pct={cpuP} color="var(--cloud-accent)" /></td>
                                                <td><CloudMiniMeter pct={ramP} color="var(--cloud-info)" /></td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {truncated && (
                        <div className="cloud-table-note">
                            {t('cloud.truncated') || `Showing first ${CLOUD_TABLE_LIMIT} of ${filtered.length} — refine with the search above.`}
                        </div>
                    )}
                </div>
            );
        }

        // ─── clusters / nodes tables ───────────────────────────────
        function CloudClustersTable({ clusters, resources, t }) {
            const safe = Array.isArray(clusters) ? clusters : [];
            const res = Array.isArray(resources) ? resources : [];
            if (safe.length === 0) {
                return <div className="cloud-card cloud-empty">{t('cloud.noClusters') || 'No clusters configured.'}</div>;
            }
            return (
                <div className="cloud-card cloud-table-card">
                    <table className="cloud-table">
                        <thead>
                            <tr>
                                <th>{t('cloud.colName') || 'Name'}</th>
                                <th>{t('cloud.colStatus') || 'Status'}</th>
                                <th>{t('cloud.colHost') || 'Host'}</th>
                                <th>{t('cloud.colGuests') || 'Guests'}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {safe.map(c => {
                                const cid = c && (c.id != null ? c.id : c.name);
                                const count = res.filter(r => r && r._clusterId === cid).length;
                                return (
                                    <tr className="cloud-table-row" key={String(cid)}>
                                        <td>
                                            <span className="cloud-table-name">
                                                <span className="cloud-table-name-icon"><Icons.Layers /></span>
                                                {(c && (c.display_name || c.name)) || 'cluster'}
                                            </span>
                                        </td>
                                        <td><CloudConnChip connected={!!(c && c.connected)} t={t} /></td>
                                        <td className="cloud-table-mono">{(c && c.host) || '—'}</td>
                                        <td>{count}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            );
        }

        function CloudNodesTable({ resources, t }) {
            const res = Array.isArray(resources) ? resources : [];
            // build distinct node map with guest counts -- MK
            const nodeMap = {};
            res.forEach(r => {
                if (!r || !r.node) return;
                if (!nodeMap[r.node]) nodeMap[r.node] = { node: r.node, total: 0, running: 0 };
                nodeMap[r.node].total += 1;
                if (r.status === 'running') nodeMap[r.node].running += 1;
            });
            const nodes = Object.values(nodeMap).sort((a, b) => a.node.localeCompare(b.node));

            if (nodes.length === 0) {
                return <div className="cloud-card cloud-empty">{t('cloud.noNodes') || 'No node data available.'}</div>;
            }
            return (
                <div className="cloud-card cloud-table-card">
                    <table className="cloud-table">
                        <thead>
                            <tr>
                                <th>{t('cloud.colNode') || 'Node'}</th>
                                <th>{t('cloud.colGuests') || 'Guests'}</th>
                                <th>{t('cloud.running') || 'Running'}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {nodes.map(n => (
                                <tr className="cloud-table-row" key={n.node}>
                                    <td>
                                        <span className="cloud-table-name">
                                            <span className="cloud-table-name-icon"><Icons.Cpu /></span>
                                            {n.node}
                                        </span>
                                    </td>
                                    <td>{n.total}</td>
                                    <td>{n.running}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            );
        }

        // honest placeholder for sections not wired into Cloud yet
        function CloudPlaceholder({ title, icon, t }) {
            const Ico = Icons[icon] || Icons.Box;
            return (
                <div className="cloud-card cloud-placeholder">
                    <div className="cloud-placeholder-icon"><Ico /></div>
                    <div className="cloud-placeholder-title">{title}</div>
                    <div className="cloud-placeholder-text">
                        {t('cloud.placeholder') || 'Managed in the classic layout for now — coming to Cloud in a later Preview build.'}
                    </div>
                </div>
            );
        }

        // ─── slide-in detail panel ─────────────────────────────────
        function CloudDetailPanel({ resource, open, onClose, t }) {
            const [tab, setTab] = React.useState('info');
            // reset to info whenever a new resource is opened -- LW
            React.useEffect(() => { setTab('info'); }, [resource && resource.vmid, resource && resource._clusterId]);

            if (!open || !resource) return null;

            const r = resource;
            const cpuP = cloudPct(r.cpu);
            const memMax = Number(r.maxmem) || 0;
            const memUse = Number(r.mem) || 0;
            const ramP = memMax > 0 ? Math.round((memUse / memMax) * 100) : 0;
            const tags = (typeof r.tags === 'string' && r.tags) ? r.tags.split(/[;,\s]+/).filter(Boolean)
                : (Array.isArray(r.tags) ? r.tags : []);

            const tabs = [
                { id: 'info', label: t('cloud.tabInfo') || 'Info' },
                { id: 'capacity', label: t('cloud.tabCapacity') || 'Capacity' },
                { id: 'network', label: t('cloud.tabNetwork') || 'Network' },
            ];

            const Row = ({ label, value }) => (
                <div className="cloud-panel-row">
                    <span className="cloud-panel-row-key">{label}</span>
                    <span className="cloud-panel-row-val">{(value === 0 || value) ? value : '—'}</span>
                </div>
            );

            return (
                <div className="cloud-panel">
                    <div className="cloud-panel-header">
                        <div className="cloud-panel-title">
                            <span className="cloud-panel-title-icon">
                                {r.type === 'lxc' ? <Icons.Box /> : <Icons.Server />}
                            </span>
                            <span className="cloud-panel-title-text">{r.name || ('guest-' + (r.vmid != null ? r.vmid : ''))}</span>
                        </div>
                        <button type="button" className="cloud-panel-close" onClick={onClose} aria-label="Close">
                            <Icons.X />
                        </button>
                    </div>

                    <div className="cloud-panel-tabs">
                        {tabs.map(tb => (
                            <button
                                type="button"
                                key={tb.id}
                                className={'cloud-panel-tab' + (tab === tb.id ? ' cloud-panel-tab-active' : '')}
                                onClick={() => setTab(tb.id)}
                            >
                                {tb.label}
                            </button>
                        ))}
                    </div>

                    <div className="cloud-panel-body">
                        {tab === 'info' && (
                            <div>
                                <Row label={t('cloud.colId') || 'ID'} value={r.vmid != null ? r.vmid : '—'} />
                                <Row label={t('cloud.type') || 'Type'} value={r.type === 'lxc' ? 'Container' : 'Virtual Machine'} />
                                <Row
                                    label={t('cloud.colStatus') || 'Status'}
                                    value={<CloudStatusChip status={r.status} />}
                                />
                                <Row label={t('cloud.colNode') || 'Node'} value={r.node || '—'} />
                                <Row label={t('cloud.uptime') || 'Uptime'} value={cloudFmtUptime(r.uptime)} />
                                {tags.length > 0 && (
                                    <div className="cloud-panel-row cloud-panel-row-tags">
                                        <span className="cloud-panel-row-key">{t('cloud.tags') || 'Tags'}</span>
                                        <span className="cloud-panel-tags">
                                            {tags.map((tg, i) => <span className="cloud-chip cloud-chip-tag" key={i}><Icons.Tag /> {tg}</span>)}
                                        </span>
                                    </div>
                                )}
                            </div>
                        )}

                        {tab === 'capacity' && (
                            <div>
                                <div className="cloud-panel-meter-block">
                                    <div className="cloud-panel-meter-label">{t('cloud.colCpu') || 'CPU'} · {cpuP}%</div>
                                    <div className="cloud-meter"><div style={{ width: cpuP + '%', background: 'var(--cloud-accent)' }} /></div>
                                    <div className="cloud-panel-meter-sub">{(Number(r.maxcpu) || 0)} {t('cloud.cores') || 'vCPU'}</div>
                                </div>
                                <div className="cloud-panel-meter-block">
                                    <div className="cloud-panel-meter-label">{t('cloud.colRam') || 'RAM'} · {ramP}%</div>
                                    <div className="cloud-meter"><div style={{ width: ramP + '%', background: 'var(--cloud-info)' }} /></div>
                                    <div className="cloud-panel-meter-sub">{cloudFmtBytes(memUse)} / {cloudFmtBytes(memMax)}</div>
                                </div>
                            </div>
                        )}

                        {tab === 'network' && (
                            <div>
                                <Row label={t('cloud.ip') || 'IP address'} value={r.ip || (t('cloud.noIp') || 'Not reported')} />
                                <Row label={t('cloud.colNode') || 'Node'} value={r.node || '—'} />
                                <div className="cloud-panel-hint">
                                    {t('cloud.netHint') || 'Detailed NIC configuration is available in the classic layout.'}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // ─── topbar (breadcrumb + cluster selector + refresh) ──────
        function CloudTopbar({ sectionLabel, clusters, selectedCluster, setSelectedCluster, t, onExitCloud }) {
            const safe = Array.isArray(clusters) ? clusters : [];
            const selId = selectedCluster && (selectedCluster.id != null ? selectedCluster.id : selectedCluster.name);

            const onChange = (e) => {
                const val = e.target.value;
                const match = safe.find(c => String(c && (c.id != null ? c.id : c.name)) === String(val));
                if (match && typeof setSelectedCluster === 'function') setSelectedCluster(match);
            };

            return (
                <div className="cloud-topbar">
                    <div className="cloud-breadcrumb">
                        <Icons.Cloud />
                        <span className="cloud-breadcrumb-root">Cloud</span>
                        <span className="cloud-breadcrumb-sep"><Icons.ChevronRight /></span>
                        <span className="cloud-breadcrumb-leaf">{sectionLabel}</span>
                    </div>
                    <div className="cloud-topbar-actions">
                        {safe.length > 0 && (
                            <select className="cloud-cluster-select" value={selId != null ? String(selId) : ''} onChange={onChange}>
                                {safe.map(c => {
                                    const cid = c && (c.id != null ? c.id : c.name);
                                    return <option key={String(cid)} value={String(cid)}>{(c && (c.display_name || c.name)) || 'cluster'}</option>;
                                })}
                            </select>
                        )}
                        <button type="button" className="cloud-btn cloud-btn-icon" title={t('cloud.refresh') || 'Refresh'}>
                            <Icons.RefreshCw />
                        </button>
                        {typeof onExitCloud === 'function' && (
                            <button type="button" className="cloud-btn" onClick={onExitCloud} title={t('cloud.exit') || 'Exit Preview'}>
                                <Icons.X /> {t('cloud.exit') || 'Exit Preview'}
                            </button>
                        )}
                    </div>
                </div>
            );
        }

        // ─── shell ─────────────────────────────────────────────────
        // top-level entry. owns nav-section + selected-row + panel state
        function CloudShell({ clusters, selectedCluster, setSelectedCluster, clusterResources, clusterMetrics, allClusterMetrics, t, isAdmin, onExitCloud }) {
            const [section, setSection] = React.useState('overview');
            const [selectedRes, setSelectedRes] = React.useState(null);
            const [panelOpen, setPanelOpen] = React.useState(false);

            // NS: guarantee the cloud token scope (body[data-layout="cloud"]) is active
            // while the shell is mounted — don't rely on useLayout's effect timing.
            React.useEffect(() => {
                const prev = document.body.getAttribute('data-layout');
                document.body.setAttribute('data-layout', 'cloud');
                return () => { if (prev != null) document.body.setAttribute('data-layout', prev); };
            }, []);

            // NS: cloud mode bypasses the tree-sidebar's auto-select, so on a fresh
            // login nothing loads resources -> overview/tables read all-zeros. Pick the
            // first connected cluster so its resources populate (the dashboard's
            // selectedCluster effect does the fetch).
            React.useEffect(() => {
                if (!selectedCluster && typeof setSelectedCluster === 'function') {
                    const arr = Array.isArray(clusters) ? clusters : [];
                    const first = arr.find(c => c && c.connected) || arr[0];
                    if (first) setSelectedCluster(first);
                }
            }, [selectedCluster, clusters]);

            // never trust these to be arrays
            const safeClusters = Array.isArray(clusters) ? clusters : [];
            const safeResources = Array.isArray(clusterResources) ? clusterResources : [];

            // i18n helper that always yields a string -- LW
            // NS: PegaProx's t() ECHOES the key back when a translation is missing
            // (it does not return undefined), so `t('cloud.x') || 'Fallback'` was
            // rendering raw keys like "cloud.clustersTitle". Treat key-echo as no
            // translation so the English fallbacks kick in. (Cloud is Preview/EN-first.)
            const tx = (k) => {
                const v = (typeof t === 'function') ? t(k) : undefined;
                return (v && v !== k) ? v : undefined;
            };

            const vms = safeResources.filter(r => r && r.type === 'qemu');
            const cts = safeResources.filter(r => r && r.type === 'lxc');

            const sectionLabels = {
                overview: tx('cloud.overview') || 'Overview',
                vms: tx('cloud.vms') || 'Virtual Machines',
                containers: tx('cloud.containers') || 'Containers',
                datastores: tx('cloud.datastores') || 'Datastores',
                networks: tx('cloud.networks') || 'Networks',
                clusters: tx('cloud.clustersTitle') || 'Clusters',
                nodes: tx('cloud.nodesTitle') || 'Nodes',
                users: tx('cloud.users') || 'Users',
                settings: tx('cloud.settings') || 'Settings',
            };

            const openRow = (r) => {
                setSelectedRes(r);
                setPanelOpen(true);
            };
            const closePanel = () => setPanelOpen(false);

            // switching section clears any open detail panel -- avoid stale row
            const selectSection = (id) => {
                setSection(id);
                setPanelOpen(false);
                setSelectedRes(null);
            };

            const selId = selectedRes && selectedRes.vmid;

            let body;
            switch (section) {
                case 'overview':
                    body = <CloudOverview clusters={safeClusters} resources={safeResources} t={tx} />;
                    break;
                case 'vms':
                    body = <CloudResourceTable rows={vms} kind="qemu" onRowClick={openRow} selectedId={panelOpen ? selId : null} t={tx} />;
                    break;
                case 'containers':
                    body = <CloudResourceTable rows={cts} kind="lxc" onRowClick={openRow} selectedId={panelOpen ? selId : null} t={tx} />;
                    break;
                case 'datastores':
                    body = <CloudPlaceholder title={tx('cloud.datastores') || 'Datastores'} icon="Database" t={tx} />;
                    break;
                case 'networks':
                    body = <CloudPlaceholder title={tx('cloud.networks') || 'Networks'} icon="Network" t={tx} />;
                    break;
                case 'clusters':
                    body = <CloudClustersTable clusters={safeClusters} resources={safeResources} t={tx} />;
                    break;
                case 'nodes':
                    body = <CloudNodesTable resources={safeResources} t={tx} />;
                    break;
                case 'users':
                    body = isAdmin ? <CloudPlaceholder title={tx('cloud.users') || 'Users'} icon="Users" t={tx} />
                        : <CloudPlaceholder title={tx('cloud.overview') || 'Overview'} icon="Grid" t={tx} />;
                    break;
                case 'settings':
                    body = isAdmin ? <CloudPlaceholder title={tx('cloud.settings') || 'Settings'} icon="Settings" t={tx} />
                        : <CloudPlaceholder title={tx('cloud.overview') || 'Overview'} icon="Grid" t={tx} />;
                    break;
                default:
                    body = <CloudOverview clusters={safeClusters} resources={safeResources} t={tx} />;
            }

            return (
                <div className="cloud-shell">
                    <CloudSideNav active={section} onSelect={selectSection} isAdmin={!!isAdmin} />
                    <div className="cloud-content">
                        <CloudTopbar
                            sectionLabel={sectionLabels[section] || 'Overview'}
                            clusters={safeClusters}
                            selectedCluster={selectedCluster}
                            setSelectedCluster={setSelectedCluster}
                            t={tx}
                            onExitCloud={onExitCloud}
                        />
                        {/* main region is the panel's positioning context so the slide-in
                            sits *under* the topbar, not over it -- LW */}
                        <div className="cloud-content-main">
                            <div className="cloud-content-scroll">
                                {body}
                            </div>
                            <CloudDetailPanel resource={selectedRes} open={panelOpen} onClose={closePanel} t={tx} />
                        </div>
                    </div>
                </div>
            );
        }
