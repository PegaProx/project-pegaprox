        // LW 2026-04-24 — grouped permissions grid for Create/Edit Role dialogs.
        // Old version was a flat 4-column checkbox grid of raw keys (vm.start, pbs.datastore.gc, ...).
        // That's ~150 entries with no structure. Now: group by the dot-prefix, human-readable
        // group headers, per-group "select all", description tooltips, and a search box.
        const PERMISSION_CATEGORY_META = {
            vm:            { order: 10, title: 'Virtual Machines',      icon: '🖥️' },
            cluster:       { order: 20, title: 'Cluster',               icon: '🔗' },
            node:          { order: 30, title: 'Nodes',                 icon: '🏠' },
            storage:       { order: 40, title: 'Storage',               icon: '💾' },
            backup:        { order: 50, title: 'Backup Jobs',           icon: '📦' },
            ha:            { order: 60, title: 'High Availability',     icon: '⚡' },
            firewall:      { order: 70, title: 'Firewall',              icon: '🛡️' },
            pool:          { order: 80, title: 'Resource Pools',        icon: '🗂️' },
            replication:   { order: 90, title: 'Replication',           icon: '🔁' },
            ceph:          { order: 100, title: 'Ceph',                 icon: '🐙' },
            sdn:           { order: 110, title: 'Software-Defined Net', icon: '🌐' },
            alert:         { order: 120, title: 'Alerts',               icon: '🔔' },
            site_recovery: { order: 130, title: 'Site Recovery',        icon: '🚨' },
            pbs:           { order: 140, title: 'Proxmox Backup Server',icon: '🗄️' },
            vmware:        { order: 150, title: 'ESXi',       icon: '📡' },
            xapi:          { order: 160, title: 'XCP-ng',               icon: '🔶' },
            plugins:       { order: 170, title: 'Plugins',              icon: '🧩' },
            autoinstall:   { order: 175, title: 'Automated Installs',   icon: '💿' },
            metrics:       { order: 180, title: 'Telemetry',            icon: '📈' },
            admin:         { order: 999, title: 'Administration',       icon: '⚙️' },
        };

        function PermissionsGrid({ allPermissions, selected, onChange, t }) {
            const [filter, setFilter] = useState('');
            // category collapsed state; admin category collapsed by default (less-used)
            const [collapsed, setCollapsed] = useState({ admin: true });
            const groups = React.useMemo(() => {
                const q = filter.trim().toLowerCase();
                const byCat = {};
                (allPermissions || []).forEach(p => {
                    if (q && !(p.permission.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q))) return;
                    const c = p.category || p.permission.split('.')[0];
                    (byCat[c] = byCat[c] || []).push(p);
                });
                // sort by meta.order; unknown categories go to the end alphabetically
                return Object.keys(byCat)
                    .sort((a, b) => {
                        const oa = PERMISSION_CATEGORY_META[a]?.order ?? 500;
                        const ob = PERMISSION_CATEGORY_META[b]?.order ?? 500;
                        if (oa !== ob) return oa - ob;
                        return a.localeCompare(b);
                    })
                    .map(c => ({ cat: c, perms: byCat[c].sort((x, y) => x.permission.localeCompare(y.permission)) }));
            }, [allPermissions, filter]);

            const selSet = new Set(selected || []);
            const toggleOne = (perm, on) => {
                const next = new Set(selected || []);
                if (on) next.add(perm); else next.delete(perm);
                onChange(Array.from(next));
            };
            const toggleGroup = (perms, on) => {
                const next = new Set(selected || []);
                perms.forEach(p => on ? next.add(p.permission) : next.delete(p.permission));
                onChange(Array.from(next));
            };

            return (
                <div className="bg-proxmox-darker border border-proxmox-border rounded-lg overflow-hidden">
                    <div className="flex items-center gap-2 p-2 border-b border-proxmox-border bg-proxmox-dark/40">
                        <Icons.Search className="w-4 h-4 text-gray-500 ml-1" />
                        <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                            placeholder={t('filterPermissions') || 'Filter permissions…'}
                            className="flex-1 bg-transparent outline-none text-sm text-white placeholder:text-gray-500" />
                        <span className="text-xs text-gray-500 mr-2">{(selected || []).length} / {(allPermissions || []).length}</span>
                        <button type="button" onClick={() => onChange([])} className="text-xs px-2 py-0.5 text-gray-400 hover:text-white" title={t('clearAll') || 'Clear all'}>
                            {t('clearAll') || 'Clear'}
                        </button>
                    </div>
                    <div className="max-h-80 overflow-y-auto p-2 space-y-2" style={{scrollbarWidth: 'thin'}}>
                        {groups.length === 0 && (
                            <div className="text-center text-sm text-gray-500 py-6">{t('noMatchingPermissions') || 'No permissions match your filter.'}</div>
                        )}
                        {groups.map(({ cat, perms }) => {
                            const meta = PERMISSION_CATEGORY_META[cat] || { title: cat, icon: '•' };
                            const checkedCount = perms.filter(p => selSet.has(p.permission)).length;
                            const allChecked = checkedCount === perms.length && perms.length > 0;
                            const someChecked = checkedCount > 0 && !allChecked;
                            const isCollapsed = !!collapsed[cat];
                            return (
                                <div key={cat} className="bg-proxmox-dark/40 border border-proxmox-border/60 rounded-md">
                                    <div className="flex items-center gap-2 px-2 py-1.5 cursor-pointer select-none"
                                        onClick={() => setCollapsed(c => ({...c, [cat]: !c[cat]}))}>
                                        <Icons.ChevronDown className={`w-3.5 h-3.5 text-gray-400 transition-transform ${isCollapsed ? '-rotate-90' : ''}`} />
                                        <span className="text-base">{meta.icon}</span>
                                        <span className="text-sm font-medium text-white flex-1">{meta.title}</span>
                                        <span className={`text-xs ${allChecked ? 'text-green-400' : someChecked ? 'text-yellow-400' : 'text-gray-500'}`}>
                                            {checkedCount}/{perms.length}
                                        </span>
                                        <button type="button" onClick={(e) => { e.stopPropagation(); toggleGroup(perms, !allChecked); }}
                                            className="text-xs px-1.5 py-0.5 rounded bg-proxmox-darker hover:bg-proxmox-hover text-gray-300">
                                            {allChecked ? (t('deselectAll') || 'None') : (t('selectAll') || 'All')}
                                        </button>
                                    </div>
                                    {!isCollapsed && (
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-3 gap-y-1 px-3 pb-2 pt-1">
                                            {perms.map(p => (
                                                <label key={p.permission} className="flex items-start gap-2 text-xs text-gray-300 cursor-pointer hover:text-white py-0.5">
                                                    <input type="checkbox" checked={selSet.has(p.permission)}
                                                        onChange={e => toggleOne(p.permission, e.target.checked)}
                                                        className="rounded border-gray-600 mt-0.5" />
                                                    <div className="flex-1 min-w-0">
                                                        <div className="font-medium leading-tight">{p.description || p.permission}</div>
                                                        <div className="text-[10px] text-gray-500 font-mono truncate" title={p.permission}>{p.permission}</div>
                                                        {/* MK Sep 2026 (#818) - a permission whose reach is wider than its
                                                            name suggests says so here, where somebody is about to tick it.
                                                            metrics.view and the two autoinstall ones carry one; the server
                                                            sends '' for the rest, so nothing else grows a line. */}
                                                        {p.warning && (
                                                            <div className="mt-1 flex items-start gap-1 text-[10px] leading-snug text-yellow-400/90">
                                                                <Icons.AlertTriangle className="w-3 h-3 flex-shrink-0 mt-px" />
                                                                <span>{p.warning}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                </label>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            );
        }

        // MK Apr 2026 — Webhook alert channels (Slack/Discord/Teams/ntfy/generic).
        // Lives in the Alerts card as a sub-section. Urls come back masked from the
        // server on GET; when editing an entry we re-fetch with ?full=1 so the form
        // shows the real URL (stays in the browser, never logged).
        function AlertChannelsPanel({ t, addToast, getAuthHeaders }) {
            const [channels, setChannels] = useState([]);
            const [editing, setEditing] = useState(null);   // null | new-template | existing
            const [loading, setLoading] = useState(false);
            const [testing, setTesting] = useState({});

            const load = async () => {
                setLoading(true);
                try {
                    const r = await fetch(`${API_URL}/alert-channels`, { credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) setChannels(await r.json());
                } catch(e) { console.error('channels load:', e); }
                setLoading(false);
            };
            useEffect(() => { load(); }, []);

            const newChannel = () => setEditing({ id: null, name: '', type: 'slack', url: '', token: '', topic: '', enabled: true });

            const startEdit = async (ch) => {
                // Refetch full list to get unmasked secrets for this row
                try {
                    const r = await fetch(`${API_URL}/alert-channels?full=1`, { credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) {
                        const full = await r.json();
                        const row = full.find(c => c.id === ch.id) || ch;
                        setEditing({...row});
                        return;
                    }
                } catch(e) {}
                setEditing({...ch});
            };

            const save = async () => {
                const body = {...editing};
                try {
                    const isNew = !editing.id;
                    const r = await fetch(
                        isNew ? `${API_URL}/alert-channels` : `${API_URL}/alert-channels/${editing.id}`,
                        { method: isNew ? 'POST' : 'PUT', credentials: 'include',
                          headers: {...getAuthHeaders(), 'Content-Type': 'application/json'},
                          body: JSON.stringify(body) }
                    );
                    if (r.ok) {
                        addToast?.(t('channelSaved') || 'Channel saved', 'success');
                        setEditing(null); load();
                    } else {
                        const e = await r.json().catch(() => ({}));
                        addToast?.(e.error || 'Save failed', 'error');
                    }
                } catch(e) { addToast?.(e.message || 'Save failed', 'error'); }
            };

            const del = async (ch) => {
                if (!window.confirm((t('confirmDeleteChannel') || 'Delete channel') + ' "' + (ch.name || ch.id) + '"?')) return;
                const r = await fetch(`${API_URL}/alert-channels/${ch.id}`, {
                    method: 'DELETE', credentials: 'include', headers: getAuthHeaders()
                });
                if (r.ok) { addToast?.(t('channelDeleted') || 'Channel deleted', 'success'); load(); }
                else addToast?.('Delete failed', 'error');
            };

            const test = async (ch) => {
                setTesting({...testing, [ch.id]: true});
                try {
                    const r = await fetch(`${API_URL}/alert-channels/${ch.id}/test`, {
                        method: 'POST', credentials: 'include', headers: getAuthHeaders()
                    });
                    const d = await r.json().catch(() => ({}));
                    if (d.success) addToast?.(`✓ ${ch.name}: ${d.detail || 'OK'}`, 'success');
                    else addToast?.(`✗ ${ch.name}: ${d.detail || 'failed'}`, 'error');
                } catch(e) { addToast?.(`Test failed: ${e.message}`, 'error'); }
                setTesting({...testing, [ch.id]: false});
            };

            const typeLabel = (tp) => ({slack: 'Slack', discord: 'Discord', teams: 'Microsoft Teams', ntfy: 'ntfy', generic: 'Generic JSON'}[tp] || tp);

            return (
                <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                        <h4 className="font-medium text-white flex items-center gap-2">
                            <Icons.Bell className="w-4 h-4" />
                            {t('alertChannels') || 'Alert Channels'}
                            <span className="text-xs text-gray-500 ml-1">({channels.length})</span>
                        </h4>
                        <button onClick={newChannel} className="flex items-center gap-1 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">
                            <Icons.Plus className="w-3.5 h-3.5" /> {t('addChannel') || 'Add Channel'}
                        </button>
                    </div>
                    <p className="text-xs text-gray-500">{t('alertChannelsDesc') || 'Send alerts to Slack, Discord, Teams, ntfy, or any JSON webhook. Channels fire in addition to email.'}</p>

                    {loading && channels.length === 0 ? (
                        <div className="text-center py-4"><Icons.RotateCw className="w-4 h-4 animate-spin text-gray-400 mx-auto" /></div>
                    ) : channels.length === 0 ? (
                        <p className="text-sm text-gray-500 text-center py-3">{t('noChannels') || 'No channels configured yet.'}</p>
                    ) : (
                        <div className="space-y-2">
                            {channels.map(ch => (
                                <div key={ch.id} className={`flex items-center gap-3 p-3 rounded-lg border ${ch.enabled === false ? 'border-proxmox-border opacity-60' : 'border-proxmox-border'} bg-proxmox-secondary`}>
                                    <div className={`p-1.5 rounded ${ch.enabled === false ? 'bg-gray-500/10' : 'bg-blue-500/10'}`}>
                                        <Icons.Bell className={`w-4 h-4 ${ch.enabled === false ? 'text-gray-400' : 'text-blue-400'}`} />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className="text-white text-sm font-medium">{ch.name || ch.id}</span>
                                            <span className="text-xs px-1.5 py-0.5 rounded bg-gray-500/20 text-gray-300">{typeLabel(ch.type)}</span>
                                            {ch.enabled === false && <span className="text-xs text-gray-500">{t('disabled') || 'disabled'}</span>}
                                        </div>
                                        <div className="text-xs text-gray-500 font-mono truncate">{ch.url}</div>
                                    </div>
                                    <button onClick={() => test(ch)} disabled={!!testing[ch.id]} className="px-2 py-1 text-xs bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 rounded flex items-center gap-1 disabled:opacity-50">
                                        {testing[ch.id] ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : <Icons.Play />}
                                        {t('testChannel') || 'Test'}
                                    </button>
                                    <button onClick={() => startEdit(ch)} className="px-2 py-1 text-xs bg-proxmox-dark text-gray-300 hover:bg-proxmox-hover rounded">
                                        <Icons.Edit /> {t('edit') || 'Edit'}
                                    </button>
                                    <button onClick={() => del(ch)} className="px-2 py-1 text-xs bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded">
                                        <Icons.Trash />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}

                    {editing && (
                        <div className="mt-2 p-3 bg-proxmox-darker border border-proxmox-border rounded-lg space-y-3">
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                    <input type="text" value={editing.name}
                                        onChange={e => setEditing({...editing, name: e.target.value})}
                                        placeholder="Ops Slack"
                                        className="w-full px-3 py-1.5 bg-proxmox-secondary border border-proxmox-border rounded text-white text-sm" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                    <select value={editing.type}
                                        onChange={e => setEditing({...editing, type: e.target.value})}
                                        className="w-full px-3 py-1.5 bg-proxmox-secondary border border-proxmox-border rounded text-white text-sm">
                                        <option value="slack">Slack</option>
                                        <option value="discord">Discord</option>
                                        <option value="teams">Microsoft Teams</option>
                                        <option value="ntfy">ntfy</option>
                                        <option value="generic">Generic JSON</option>
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label className="block text-xs text-gray-400 mb-1">Webhook URL</label>
                                <input type="text" value={editing.url}
                                    onChange={e => setEditing({...editing, url: e.target.value})}
                                    placeholder="https://hooks.slack.com/services/…"
                                    className="w-full px-3 py-1.5 bg-proxmox-secondary border border-proxmox-border rounded text-white text-sm font-mono" />
                            </div>
                            {editing.type === 'ntfy' && (
                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('topic') || 'Topic'}</label>
                                        <input type="text" value={editing.topic || ''}
                                            onChange={e => setEditing({...editing, topic: e.target.value})}
                                            placeholder="pegaprox-alerts"
                                            className="w-full px-3 py-1.5 bg-proxmox-secondary border border-proxmox-border rounded text-white text-sm font-mono" />
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('token') || 'Access token'}</label>
                                        <input type="password" value={editing.token || ''}
                                            onChange={e => setEditing({...editing, token: e.target.value})}
                                            placeholder={t('optional') || '(optional)'}
                                            className="w-full px-3 py-1.5 bg-proxmox-secondary border border-proxmox-border rounded text-white text-sm font-mono" />
                                    </div>
                                </div>
                            )}
                            <label className="flex items-center gap-2 cursor-pointer select-none">
                                <input type="checkbox" checked={editing.enabled !== false}
                                    onChange={e => setEditing({...editing, enabled: e.target.checked})}
                                    className="w-4 h-4" />
                                <span className="text-sm text-white">{t('enabled') || 'Enabled'}</span>
                            </label>
                            <div className="flex justify-end gap-2">
                                <button onClick={() => setEditing(null)} className="px-3 py-1.5 text-sm text-gray-300 hover:text-white">
                                    {t('cancel') || 'Cancel'}
                                </button>
                                <button onClick={save} disabled={!editing.url} className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded text-sm disabled:opacity-50">
                                    {t('save') || 'Save'}
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // MK May 2026 — SIEM Forwarder admin panel inside the Settings modal.
        // Lists configured targets, lets you add/edit/delete/test them.
        function SIEMTab({ addToast, t, getAuthHeaders }) {
            const [targets, setTargets] = React.useState([]);
            const [types, setTypes] = React.useState([]);
            const [loading, setLoading] = React.useState(false);
            const [editing, setEditing] = React.useState(null); // null | {id?, ...form}
            const [saving, setSaving] = React.useState(false);

            const refresh = async () => {
                setLoading(true);
                try {
                    const [tg, tp] = await Promise.all([
                        fetch(`${API_URL}/siem/targets`, { credentials: 'include', headers: getAuthHeaders() }).then(r => r.ok ? r.json() : { targets: [] }),
                        fetch(`${API_URL}/siem/types`, { credentials: 'include', headers: getAuthHeaders() }).then(r => r.ok ? r.json() : { types: [] }),
                    ]);
                    setTargets(tg.targets || []);
                    setTypes(tp.types || []);
                } finally { setLoading(false); }
            };
            React.useEffect(() => { refresh(); /* eslint-disable-line */ }, []);

            const newTarget = () => setEditing({
                name: '', type: 'syslog_udp', endpoint: '', enabled: true, settings: {},
            });

            const save = async () => {
                if (!editing.name?.trim() || !editing.endpoint?.trim()) {
                    addToast(t('siemRequiredFields') || 'name and endpoint are required', 'error');
                    return;
                }
                setSaving(true);
                try {
                    const isUpdate = !!editing.id;
                    const url = isUpdate ? `${API_URL}/siem/targets/${editing.id}` : `${API_URL}/siem/targets`;
                    const r = await fetch(url, {
                        method: isUpdate ? 'PUT' : 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({
                            name: editing.name.trim(),
                            type: editing.type,
                            endpoint: editing.endpoint.trim(),
                            enabled: !!editing.enabled,
                            settings: editing.settings || {},
                        }),
                    });
                    if (r.ok) {
                        addToast(t('siemSaved') || 'Target saved', 'success');
                        setEditing(null);
                        await refresh();
                    } else {
                        const d = await r.json().catch(() => ({}));
                        addToast(d.error || (t('siemSaveFailed') || 'save failed'), 'error');
                    }
                } finally { setSaving(false); }
            };

            const remove = async (tid) => {
                if (!confirm(t('siemDeleteConfirm') || 'Delete this SIEM target?')) return;
                const r = await fetch(`${API_URL}/siem/targets/${tid}`, {
                    method: 'DELETE', credentials: 'include', headers: getAuthHeaders(),
                });
                if (r.ok) { addToast(t('siemDeleted') || 'Deleted', 'success'); refresh(); }
            };

            const testTarget = async (tid) => {
                const r = await fetch(`${API_URL}/siem/targets/${tid}/test`, {
                    method: 'POST', credentials: 'include', headers: getAuthHeaders(),
                });
                if (r.ok) {
                    const d = await r.json();
                    addToast(d.ok ? (t('siemTestOk') || 'Test event delivered') : (t('siemTestFailed') || 'Test failed'),
                             d.ok ? 'success' : 'error');
                    refresh();
                } else {
                    addToast(t('siemTestFailed') || 'Test failed', 'error');
                }
            };

            const currentTypeMeta = types.find(tt => tt.id === editing?.type) || {};

            return (
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-semibold text-white">{t('siemTitle') || 'SIEM Forwarder'}</h3>
                            <p className="text-xs text-gray-500 mt-0.5">
                                {t('siemDesc') || 'Forward audit events to syslog / Splunk / Elastic / Loki / generic webhooks. Multiple targets supported.'}
                            </p>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={refresh} disabled={loading}
                                className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border text-gray-300 hover:text-white rounded-lg text-sm flex items-center gap-1.5">
                                <Icons.RefreshCw className="w-3.5 h-3.5" />
                                {t('refresh') || 'Refresh'}
                            </button>
                            <button onClick={newTarget}
                                className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white flex items-center gap-1.5">
                                <Icons.Plus className="w-3.5 h-3.5" />
                                {t('siemAddTarget') || 'Add target'}
                            </button>
                        </div>
                    </div>

                    {targets.length === 0 ? (
                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-8 text-center text-sm text-gray-500">
                            {t('siemNoTargets') || 'No targets configured yet. Audit events stay in the database only.'}
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {targets.map(tg => (
                                <div key={tg.id} className="bg-proxmox-dark border border-proxmox-border rounded-xl p-3">
                                    <div className="flex items-center justify-between gap-2">
                                        <div className="min-w-0 flex-1">
                                            <div className="flex items-center gap-2">
                                                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                                                    !tg.enabled ? 'bg-gray-500' :
                                                    tg.last_status === 'error' ? 'bg-red-500' :
                                                    tg.last_status === 'ok' ? 'bg-green-500' : 'bg-yellow-500'
                                                }`}></span>
                                                <span className="text-sm font-medium text-white">{tg.name}</span>
                                                <span className="text-[10px] px-1.5 py-0.5 bg-proxmox-darker border border-proxmox-border rounded text-gray-400 uppercase">{tg.type}</span>
                                                {!tg.enabled && (
                                                    <span className="text-[10px] px-1.5 py-0.5 bg-gray-500/15 text-gray-400 rounded">{t('disabled') || 'disabled'}</span>
                                                )}
                                            </div>
                                            <div className="text-[11px] text-gray-500 font-mono mt-1 truncate">{tg.endpoint}</div>
                                            <div className="text-[10px] text-gray-600 mt-1">
                                                {tg.sent_count} {t('siemSent') || 'sent'}, {tg.error_count} {t('siemErrors') || 'errors'}
                                                {tg.last_ok_at && ` · ${t('siemLastOk') || 'last ok'} ${(tg.last_ok_at || '').replace('T', ' ').slice(0, 16)}`}
                                                {tg.last_error && ` · ${t('siemLastError') || 'last err'}: `}
                                                {tg.last_error && <span className="text-red-400">{tg.last_error.slice(0, 80)}</span>}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-1.5 flex-shrink-0">
                                            <button onClick={() => testTarget(tg.id)}
                                                className="px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-xs text-gray-300 hover:text-white">
                                                {t('test') || 'Test'}
                                            </button>
                                            <button onClick={() => setEditing({ ...tg, enabled: !!tg.enabled })}
                                                className="px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-xs text-gray-300 hover:text-white">
                                                {t('edit') || 'Edit'}
                                            </button>
                                            <button onClick={() => remove(tg.id)}
                                                className="px-2 py-1 bg-red-500/15 border border-red-500/30 rounded text-xs text-red-400 hover:bg-red-500/25">
                                                <Icons.Trash className="w-3 h-3" />
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {editing && (
                        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => !saving && setEditing(null)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-5 w-full max-w-lg max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                                <h3 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
                                    <Icons.Send className="w-4 h-4 text-proxmox-orange" />
                                    {editing.id ? (t('siemEditTarget') || 'Edit SIEM target') : (t('siemAddTarget') || 'Add SIEM target')}
                                </h3>
                                <div className="space-y-3">
                                    <div>
                                        <label className="text-xs text-gray-400 block mb-1">{t('name') || 'Name'} *</label>
                                        <input type="text" value={editing.name || ''}
                                            onChange={e => setEditing({...editing, name: e.target.value})}
                                            className="w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-gray-400 block mb-1">{t('siemType') || 'Type'}</label>
                                        <select value={editing.type}
                                            onChange={e => setEditing({...editing, type: e.target.value, settings: {}})}
                                            className="w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white">
                                            {types.map(tt => <option key={tt.id} value={tt.id}>{tt.label}</option>)}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="text-xs text-gray-400 block mb-1">
                                            {t('siemEndpoint') || 'Endpoint'} *
                                            <span className="text-gray-600 ml-2">{currentTypeMeta.endpoint_hint}</span>
                                        </label>
                                        <input type="text" value={editing.endpoint || ''}
                                            onChange={e => setEditing({...editing, endpoint: e.target.value})}
                                            placeholder={currentTypeMeta.endpoint_hint || ''}
                                            className="w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white font-mono" />
                                    </div>

                                    {/* per-type settings */}
                                    {(currentTypeMeta.settings_fields || []).map(field => (
                                        <div key={field}>
                                            {field === 'verify_tls' ? (
                                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                                    <input type="checkbox"
                                                        checked={editing.settings?.verify_tls !== false}
                                                        onChange={e => setEditing({...editing, settings: {...editing.settings, verify_tls: e.target.checked}})} />
                                                    {t('siemVerifyTls') || 'Verify TLS certificate'}
                                                    <span className="text-xs text-gray-500 ml-2">{t('siemVerifyTlsHint') || '(disable only for self-signed SIEMs you trust)'}</span>
                                                </label>
                                            ) : field === 'headers' ? (
                                                <>
                                                <label className="text-xs text-gray-400 block mb-1">{field}</label>
                                                <textarea
                                                    value={JSON.stringify(editing.settings?.headers || {}, null, 2)}
                                                    onChange={e => {
                                                        try {
                                                            const v = JSON.parse(e.target.value || '{}');
                                                            setEditing({...editing, settings: {...editing.settings, headers: v}});
                                                        } catch (_) { /* swallow until valid JSON */ }
                                                    }}
                                                    rows={3}
                                                    placeholder='{"Authorization": "Bearer ..."}'
                                                    className="w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-xs text-white font-mono"
                                                />
                                                </>
                                            ) : (
                                                <>
                                                <label className="text-xs text-gray-400 block mb-1">{field}</label>
                                                <input type={field === 'password' || field === 'token' ? 'password' : 'text'}
                                                    value={editing.settings?.[field] || ''}
                                                    onChange={e => setEditing({...editing, settings: {...editing.settings, [field]: e.target.value}})}
                                                    className="w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white" />
                                                </>
                                            )}
                                        </div>
                                    ))}

                                    <label className="flex items-center gap-2 text-sm text-gray-300">
                                        <input type="checkbox" checked={!!editing.enabled}
                                            onChange={e => setEditing({...editing, enabled: e.target.checked})} />
                                        {t('enabled') || 'Enabled'}
                                    </label>
                                </div>
                                <div className="flex justify-end gap-2 mt-5">
                                    <button onClick={() => setEditing(null)} disabled={saving}
                                        className="px-3 py-1.5 text-sm text-gray-400 hover:text-white">
                                        {t('cancel') || 'Cancel'}
                                    </button>
                                    <button onClick={save} disabled={saving}
                                        className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 text-white text-sm rounded flex items-center gap-1.5">
                                        {saving ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.Check className="w-3.5 h-3.5" />}
                                        {t('save') || 'Save'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }


        // LW Sep 2026 - Automated installations. PegaProx serves answer files to the
        // Proxmox auto-installer and lists the machines that fetched one. The server
        // hands the token out once, so the reveal box carries the finished prepare-iso
        // command rather than the bare token.
        const AUTOINSTALL_TEMPLATE = [
            '[global]',
            'keyboard = "de"',
            'country = "de"',
            'fqdn = "pve01.example.com"',
            'mailto = "root@example.com"',
            'timezone = "Europe/Berlin"',
            '# the hash button above the editor writes this line (or: mkpasswd -m sha-512)',
            'root-password-hashed = "$6$...replace me..."',
            '',
            '[network]',
            'source = "from-dhcp"',
            '',
            '[disk-setup]',
            'filesystem = "ext4"',
            'disk-list = ["sda"]',
            ''
        ].join('\n');

        // What the installer itself accepts. These mirror the checks in
        // pegaprox/api/auto_install.py (keep them in step - the patterns below are the
        // same regexes); the server repeats all of it, this only saves a round trip.
        const AUTOINSTALL_KEYBOARDS = [
            ['de', 'German'], ['de-ch', 'Swiss-German'], ['dk', 'Danish'], ['en-gb', 'United Kingdom'],
            ['en-us', 'U.S. English'], ['es', 'Spanish'], ['fi', 'Finnish'], ['fr', 'French'],
            ['fr-be', 'Belgium-French'], ['fr-ca', 'Canada-French'], ['fr-ch', 'Swiss-French'],
            ['hu', 'Hungarian'], ['is', 'Icelandic'], ['it', 'Italian'], ['jp', 'Japanese'],
            ['lt', 'Lithuanian'], ['mk', 'Macedonian'], ['nl', 'Dutch'], ['no', 'Norwegian'],
            ['pl', 'Polish'], ['pt', 'Portuguese'], ['pt-br', 'Portuguese (Brazil)'], ['se', 'Swedish'],
            ['si', 'Slovenian'], ['tr', 'Turkish']
        ];
        // ISO 3166-1 alpha-2, lowercase like the installer wants it
        const AUTOINSTALL_COUNTRIES = (
            'ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt ' +
            'bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh ' +
            'er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht ' +
            'hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls ' +
            'lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni ' +
            'nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg ' +
            'sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug ' +
            'um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'
        ).split(' ');
        // minimum disk count per level, same table as the backend
        const AUTOINSTALL_RAID_MIN = {
            zfs: { raid0: 1, raid1: 2, raid10: 4, 'raidz-1': 3, 'raidz-2': 4, 'raidz-3': 5 },
            btrfs: { raid0: 1, raid1: 2, raid10: 4 }
        };
        const AUTOINSTALL_DISK_KEYS = ['ID_SERIAL', 'ID_SERIAL_SHORT', 'ID_WWN', 'ID_MODEL', 'DEVNAME'];
        // sha-512, sha-256, yescrypt, bcrypt. The charset also keeps ':' and newlines
        // out, which would break the chpasswd line the installer writes.
        const AUTOINSTALL_CRYPT_RE = [
            /^\$6\$(rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$/,
            /^\$5\$(rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$/,
            /^\$y\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{1,86}\$[./0-9A-Za-z]{43}$/,
            /^\$2[aby]\$[0-9]{2}\$[./0-9A-Za-z]{53}$/
        ];
        const AUTOINSTALL_CTRL_RE = /[\x00-\x1f\x7f]/;
        const AUTOINSTALL_SSH_KEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^\x00-\x1f\x7f]*)?$/;
        const AUTOINSTALL_GLOB_RE = /^[A-Za-z0-9_.:+\-\/*?\[\]!]{1,128}$/;
        const AUTOINSTALL_DISK_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.:\-\/]{0,63}$/;
        // disk-list wants the installer's raw names; a by-id path never matches (_is_disk_path)
        const aiDiskNameOk = (n) => AUTOINSTALL_DISK_NAME_RE.test(n) && !n.startsWith('disk/');

        const aiCryptOk = (v) => AUTOINSTALL_CRYPT_RE.some(re => re.test(v || ''));

        // returns a translation key, '' when fine. domainOnly = the DHCP fallback domain
        function aiFqdnError(v, domainOnly) {
            const s = String(v || '');
            if (s.length > 253) return 'autoInstallErrFqdnLong';
            const labels = s.split('.');
            if (!domainOnly && labels.length < 2) return 'autoInstallErrFqdnDomain';
            if (labels.some(l => !/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l))) return 'autoInstallErrFqdnLabel';
            if (!domainOnly && /^[0-9]+$/.test(labels[0])) return 'autoInstallErrFqdnDigits';
            return '';
        }

        const aiIpv4 = (v) => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(v);
        // 4, 6 or 0. The URL parser is the cheapest full IPv6 check a browser has.
        function aiIpFamily(v) {
            const s = String(v || '');
            if (aiIpv4(s)) return 4;
            if (!s.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(s)) return 0;
            try { new URL(`http://[${s}]/`); return 6; } catch (e) { return 0; }
        }

        function aiCidrError(v) {
            const m = String(v || '').match(/^([^/\s]+)\/(\d{1,3})$/);
            if (!m) return 'autoInstallErrCidr';
            const fam = aiIpFamily(m[1]);
            const max = fam === 4 ? 32 : (fam === 6 ? 128 : -1);
            if (max < 0 || Number(m[2]) > max || (m[2].length > 1 && m[2][0] === '0')) return 'autoInstallErrCidr';
            return '';
        }

        // bit string of an address, only used for the gateway-in-subnet hint
        function aiIpBits(v) {
            if (aiIpv4(v)) return v.split('.').map(o => Number(o).toString(2).padStart(8, '0')).join('');
            const h = new URL(`http://[${v}]/`).hostname.slice(1, -1);
            const [head, tail] = h.split('::');
            const a = head ? head.split(':') : [];
            const b = tail ? tail.split(':') : [];
            const groups = tail === undefined ? a : a.concat(Array(8 - a.length - b.length).fill('0'), b);
            return groups.map(g => parseInt(g, 16).toString(2).padStart(16, '0')).join('');
        }
        const aiSameNet = (cidr, ip) => {
            try {
                const [addr, pfx] = cidr.split('/');
                const n = Number(pfx);
                return aiIpBits(addr).slice(0, n) === aiIpBits(ip).slice(0, n);
            } catch (e) { return true; }
        };

        // the HTML5 type=email pattern, which is what the installer checks against
        const aiMailOk = (v) => /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(v || '')
            && v !== 'mail@example.invalid';
        // the installer only knows its own zone table plus the literal UTC, so Etc/UTC fails at the rack
        const aiTimezoneOk = (v) => /^[A-Za-z][A-Za-z0-9_+\-]*(?:\/[A-Za-z0-9_+\-]+){0,2}$/.test(v || '') && !v.startsWith('Etc/');

        // datetime-local speaks browser time, the server stores UTC
        const utcToLocalInput = (iso) => {
            if (!iso) return '';
            const d = new Date(iso);
            if (isNaN(d.getTime())) return '';
            const pad = (n) => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        };
        const localInputToUtc = (v) => {
            if (!v) return '';
            const d = new Date(v);
            return isNaN(d.getTime()) ? v : d.toISOString();
        };

        function autoInstallPrepareCmd(token, fp) {
            const answerUrl = `${window.location.origin}/api/auto-install/answer`;
            return [
                'proxmox-auto-install-assistant prepare-iso proxmox-ve.iso',
                '    --fetch-from http',
                `    --url '${answerUrl}'`,
                `    --answer-auth-token 'pegaprox:${token}'`
            ].concat(fp ? [`    --cert-fingerprint '${fp}'`] : []).join(' \\\n');
        }

        // Drops every root password line in [global] and puts the hash right under the
        // header. Deliberately line based, a TOML round trip would eat the user's comments.
        function aiSetRootHash(answer, hash) {
            const line = `root-password-hashed = "${hash}"`;
            const out = [];
            let inGlobal = false, at = -1;
            for (const raw of String(answer || '').split('\n')) {
                const s = raw.trim();
                if (s.startsWith('[')) {
                    inGlobal = /^\[\s*global\s*\]/.test(s);
                    out.push(raw);
                    if (inGlobal && at < 0) at = out.length;
                    continue;
                }
                if (inGlobal && /^root[-_]password([-_]hashed)?\s*=/.test(s)) continue;
                out.push(raw);
            }
            if (at < 0) return `[global]\n${line}\n\n` + out.join('\n');
            out.splice(at, 0, line);
            return out.join('\n');
        }

        // The one-time token plus the finished prepare-iso command. Shared by the
        // editor's reveal box and the wizard's last page so both print the same thing.
        // CopyButton has the textarea fallback, so this also copies over plain http.
        function AutoInstallTokenBox({ t, reveal, onCopied, onDismiss }) {
            const cmd = autoInstallPrepareCmd(reveal.token, reveal.fp);
            const copyBtn = (value) => (
                <span className="shrink-0 inline-flex" onClickCapture={() => onCopied && onCopied()}>
                    <CopyButton value={value} size="md" title={t('copy')}
                        className="w-8 h-8 border border-proxmox-border hover:border-gray-500" />
                </span>
            );
            return (
                <div className="bg-yellow-500/10 border border-yellow-500/40 rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                        <h4 className="font-medium text-yellow-200 flex items-center gap-2">
                            <Icons.Key className="w-4 h-4" />
                            {t('autoInstallTokenOnce')}
                        </h4>
                        {onDismiss && (
                            <button onClick={onDismiss} aria-label={t('close')} className="text-gray-400 hover:text-white">
                                <Icons.X />
                            </button>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        <code className="flex-1 px-3 py-2 bg-black/40 rounded text-sm text-yellow-200 break-all">{reveal.token}</code>
                        {copyBtn(reveal.token)}
                    </div>
                    <div>
                        <div className="text-xs text-gray-400 mb-1">{t('autoInstallPrepareIso')}</div>
                        <div className="flex items-start gap-2">
                            <pre className="flex-1 px-3 py-2 bg-black/40 rounded text-xs text-gray-200 overflow-x-auto whitespace-pre">{cmd}</pre>
                            {copyBtn(cmd)}
                        </div>
                        <div className="text-[11px] text-gray-500 mt-1">{t('autoInstallOldIsoHint')}</div>
                    </div>
                </div>
            );
        }

        function AutoInstallPanel({ t, addToast, getAuthHeaders, clusters, heading = true, intent, onIntentConsumed }) {
            const [profiles, setProfiles] = useState([]);
            const [canManage, setCanManage] = useState(false);
            const [runs, setRuns] = useState([]);
            const [loading, setLoading] = useState(false);
            const [loadError, setLoadError] = useState('');
            const [editing, setEditing] = useState(null);
            const [check, setCheck] = useState(null);      // {valid, errors, warnings}
            const [reveal, setReveal] = useState(null);    // {token, name, fp}, shown once
            const [busy, setBusy] = useState(false);
            const [loaded, setLoaded] = useState(false);
            const [wizardOpen, setWizardOpen] = useState(false);
            const [wizardPreset, setWizardPreset] = useState(null);
            const [hashOpen, setHashOpen] = useState(false);
            const [hashPw, setHashPw] = useState('');
            const [hashPw2, setHashPw2] = useState('');
            const [hashMsg, setHashMsg] = useState(null);  // {ok, text}

            const load = async () => {
                setLoading(true);
                try {
                    const [p, r] = await Promise.all([
                        fetch(`${API_URL}/auto-install/profiles`, { credentials: 'include', headers: getAuthHeaders() }),
                        fetch(`${API_URL}/auto-install/runs`, { credentials: 'include', headers: getAuthHeaders() })
                    ]);
                    if (p.ok) {
                        const data = await p.json();
                        setProfiles(data.profiles || []);
                        setCanManage(!!data.can_manage);
                        setLoadError('');
                    } else {
                        // a 403 here is not "no profiles yet" - saying so invites
                        // somebody to create duplicates of what already exists
                        const e = await p.json().catch(() => ({}));
                        setLoadError(e.error || t('autoInstallLoadFailed'));
                    }
                    if (r.ok) setRuns(await r.json());
                } catch (e) {
                    setLoadError(t('autoInstallLoadFailed'));
                }
                setLoading(false);
                setLoaded(true);
            };
            useEffect(() => { load(); }, []);

            // poll while something is installing; an install takes minutes
            useEffect(() => {
                if (!runs.some(r => r.status === 'installing')) return;
                const h = setInterval(load, 15000);
                return () => clearInterval(h);
            }, [runs]);

            // a shortcut elsewhere asked for the wizard. Wait for the first load, a
            // view-only reader just lands on the page.
            useEffect(() => {
                if (!intent || !loaded) return;
                if (intent.wizard && canManage) {
                    setWizardPreset({ target_cluster_id: intent.target_cluster_id || '' });
                    setWizardOpen(true);
                }
                onIntentConsumed?.();
            }, [intent, loaded, canManage]);

            const openWizard = () => { setWizardPreset(null); setWizardOpen(true); };

            // a typed password must not outlive the form it was typed into
            const editingKey = editing ? (editing.id || 'new') : '';
            useEffect(() => {
                setHashOpen(false); setHashPw(''); setHashPw2(''); setHashMsg(null);
            }, [editingKey]);

            // wizard -> editor. expires_local, not expires_at: the form reads the local one
            const openInEditor = (d, res) => {
                setWizardOpen(false);
                setReveal(null);
                setCheck(res ? { valid: !!res.valid, errors: res.errors || [], warnings: res.warnings || [] } : null);
                setEditing({ id: null, name: d.name || '', description: d.description || '',
                             answer: (res && res.answer) || AUTOINSTALL_TEMPLATE,
                             target_cluster_id: d.target_cluster_id || '', callback_url: d.callback_url || '',
                             max_uses: d.max_uses || 0, expires_local: d.expires_local || '',
                             enabled: d.enabled !== false });
            };

            const hashIntoAnswer = async () => {
                setHashMsg(null);
                const bytes = new TextEncoder().encode(hashPw).length;
                if (hashPw.length < 8 || hashPw.length > 64 || bytes < 8 || AUTOINSTALL_CTRL_RE.test(hashPw)) {
                    setHashMsg({ ok: false, text: t('autoInstallErrPwLength') });
                    return;
                }
                if (hashPw !== hashPw2) {
                    setHashMsg({ ok: false, text: t('passwordsDoNotMatch') });
                    return;
                }
                setBusy(true);
                try {
                    const r = await fetch(`${API_URL}/auto-install/password-hash`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: hashPw })
                    });
                    const data = await r.json().catch(() => ({}));
                    if (r.ok && aiCryptOk(data.hash)) {
                        setEditing(ed => ed && ({ ...ed, answer: aiSetRootHash(ed.answer, data.hash) }));
                        setCheck(null);
                        setHashPw(''); setHashPw2('');
                        setHashMsg({ ok: true, text: t('autoInstallHashInserted') });
                    } else {
                        setHashMsg({ ok: false, text: data.error || t('autoInstallHashFailed') });
                    }
                } catch (e) {
                    setHashMsg({ ok: false, text: t('autoInstallHashFailed') });
                }
                setBusy(false);
            };

            const startNew = () => {
                setCheck(null);
                setEditing({ id: null, name: '', description: '', answer: AUTOINSTALL_TEMPLATE,
                             target_cluster_id: '', callback_url: '', max_uses: 0,
                             expires_at: '', enabled: true });
            };

            const openProfile = async (p, readOnly) => {
                setCheck(null);
                try {
                    const r = await fetch(`${API_URL}/auto-install/profiles/${p.id}`,
                                          { credentials: 'include', headers: getAuthHeaders() });
                    const data = await r.json().catch(() => ({}));
                    if (!r.ok) {
                        addToast?.(data.error || t('autoInstallLoadFailed'), 'error');
                        return;
                    }
                    setEditing({ ...data, readOnly: !!readOnly,
                                 expires_local: utcToLocalInput(data.expires_at) });
                } catch (e) {
                    addToast?.(e.message || t('autoInstallLoadFailed'), 'error');
                }
            };

            const validate = async () => {
                try {
                    const r = await fetch(`${API_URL}/auto-install/validate`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ answer: editing.answer })
                    });
                    if (r.ok) setCheck(await r.json());
                } catch (e) { addToast?.(e.message, 'error'); }
            };

            const save = async () => {
                setBusy(true);
                const isNew = !editing.id;
                const body = {
                    name: editing.name, description: editing.description,
                    target_cluster_id: editing.target_cluster_id,
                    callback_url: editing.callback_url,
                    max_uses: Number(editing.max_uses) || 0,
                    expires_at: localInputToUtc(editing.expires_local || ''),
                    enabled: !!editing.enabled
                };
                // a blanked file came back from the server; sending it would write
                // "********" over the real root password
                if (!editing.answer_redacted) body.answer = editing.answer;
                try {
                    const r = await fetch(
                        isNew ? `${API_URL}/auto-install/profiles` : `${API_URL}/auto-install/profiles/${editing.id}`,
                        { method: isNew ? 'POST' : 'PUT', credentials: 'include',
                          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                          body: JSON.stringify(body) });
                    const data = await r.json().catch(() => ({}));
                    if (r.ok) {
                        if (data.token) setReveal({ token: data.token, name: data.name, fp: data.fetch_fingerprint || '' });
                        setEditing(null); setCheck(null); load();
                        addToast?.(t('autoInstallSaved'), 'success');
                    } else {
                        addToast?.(data.error || t('autoInstallSaveFailed'), 'error');
                    }
                } catch (e) { addToast?.(e.message || t('autoInstallSaveFailed'), 'error'); }
                setBusy(false);
            };

            const rotate = async (p) => {
                if (!window.confirm(t('autoInstallRotateConfirm'))) return;
                try {
                    const r = await fetch(`${API_URL}/auto-install/profiles/${p.id}/token`,
                                          { method: 'POST', credentials: 'include', headers: getAuthHeaders() });
                    const data = await r.json().catch(() => ({}));
                    if (r.ok) { setReveal({ token: data.token, name: p.name, fp: data.fetch_fingerprint || '' }); load(); }
                    else addToast?.(data.error || t('autoInstallRotateFailed'), 'error');
                } catch (e) { addToast?.(e.message || t('autoInstallRotateFailed'), 'error'); }
            };

            const remove = async (p) => {
                if (!window.confirm(`${t('autoInstallDeleteConfirm')} "${p.name}"?`)) return;
                try {
                    const r = await fetch(`${API_URL}/auto-install/profiles/${p.id}`,
                                          { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) { addToast?.(t('autoInstallDeleted'), 'success'); load(); }
                    else {
                        const e = await r.json().catch(() => ({}));
                        addToast?.(e.error || t('autoInstallDeleteFailed'), 'error');
                    }
                } catch (e) { addToast?.(e.message || t('autoInstallDeleteFailed'), 'error'); }
            };

            const clearRun = async (run) => {
                try {
                    const r = await fetch(`${API_URL}/auto-install/runs/${run.id}`,
                                          { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) load();
                    else addToast?.(t('autoInstallDeleteFailed'), 'error');
                } catch (e) { addToast?.(e.message || t('autoInstallDeleteFailed'), 'error'); }
            };

            const STATUS_STYLE = {
                installing: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
                installed: 'bg-green-500/20 text-green-300 border-green-500/30',
                failed: 'bg-red-500/20 text-red-300 border-red-500/30'
            };
            const statusLabel = (s) => ({
                installing: t('autoInstallStatusInstalling'),
                installed: t('autoInstallStatusInstalled'),
                failed: t('autoInstallStatusFailed')
            }[s] || s);

            const when = (iso) => {
                if (!iso) return '-';
                const d = new Date(iso);
                return isNaN(d.getTime()) ? iso : d.toLocaleString();
            };

            const readOnly = !!(editing && editing.readOnly);

            return (
                <div className="space-y-4">
                    <div className="flex flex-wrap items-start justify-between gap-4">
                        <div>
                            {heading && (
                                <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-1">
                                    <Icons.Disc className="w-5 h-5" />
                                    {t('autoInstall')}
                                </h3>
                            )}
                            <p className="text-sm text-gray-400 max-w-3xl">{t('autoInstallIntro')}</p>
                        </div>
                        {canManage && (
                            <div className="flex flex-wrap items-center gap-2">
                                <button onClick={openWizard}
                                    className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-proxmox-orange/90 rounded-lg text-sm font-medium transition-colors whitespace-nowrap">
                                    <Icons.Plus />
                                    {t('autoInstallGuided')}
                                </button>
                                <button onClick={startNew}
                                    className="flex items-center gap-2 px-4 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-sm text-gray-300 hover:border-gray-500 whitespace-nowrap">
                                    <Icons.FileText />
                                    {t('autoInstallEditor')}
                                </button>
                            </div>
                        )}
                    </div>

                    {loadError && (
                        <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 flex items-center gap-2">
                            <Icons.AlertTriangle className="w-4 h-4" />
                            {loadError}
                        </div>
                    )}

                    {reveal && <AutoInstallTokenBox t={t} reveal={reveal} onDismiss={() => setReveal(null)} />}

                    {editing && (
                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                            <h4 className="font-medium text-white">
                                {readOnly ? editing.name : (editing.id ? t('autoInstallEditProfile') : t('autoInstallNewProfile'))}
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('name')}</label>
                                    <input value={editing.name} disabled={readOnly} onChange={e => setEditing({ ...editing, name: e.target.value })}
                                        className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('description')}</label>
                                    <input value={editing.description || ''} disabled={readOnly} onChange={e => setEditing({ ...editing, description: e.target.value })}
                                        className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('autoInstallTargetCluster')}</label>
                                    <select value={editing.target_cluster_id || ''} disabled={readOnly} onChange={e => setEditing({ ...editing, target_cluster_id: e.target.value })}
                                        className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50">
                                        <option value="">-</option>
                                        {(clusters || []).map(c => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
                                    </select>
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('autoInstallMaxUses')}</label>
                                        <input type="number" min="0" value={editing.max_uses || 0} disabled={readOnly}
                                            onChange={e => setEditing({ ...editing, max_uses: e.target.value })}
                                            className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50" />
                                        <div className="text-[11px] text-gray-500 mt-1">{t('autoInstallUnlimited')}</div>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('autoInstallExpires')}</label>
                                        <input type="datetime-local" value={editing.expires_local || ''} disabled={readOnly}
                                            onChange={e => setEditing({ ...editing, expires_local: e.target.value })}
                                            className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50" />
                                    </div>
                                </div>
                            </div>

                            <div>
                                <div className="flex items-center justify-between mb-1">
                                    <label className="text-xs text-gray-400">{t('autoInstallAnswerFile')}</label>
                                    {!readOnly && (
                                        <div className="flex items-center gap-2">
                                            {!editing.answer_redacted && (
                                                <button onClick={() => { setHashOpen(!hashOpen); setHashMsg(null); }} aria-expanded={hashOpen}
                                                    className="text-xs px-2 py-1 bg-proxmox-card border border-proxmox-border rounded hover:border-gray-500 text-gray-300 flex items-center gap-1">
                                                    <Icons.Lock className="w-3.5 h-3.5" />
                                                    {t('autoInstallHashPassword')}
                                                </button>
                                            )}
                                            <button onClick={validate} className="text-xs px-2 py-1 bg-proxmox-card border border-proxmox-border rounded hover:border-gray-500 text-gray-300">
                                                {t('autoInstallValidate')}
                                            </button>
                                        </div>
                                    )}
                                </div>
                                {hashOpen && !readOnly && !editing.answer_redacted && (
                                    // the clear password goes to the server once and only the hash comes back into the file
                                    // a div, not a form: a submitted form that then clears or goes away is what makes
                                    // browsers offer to save the node's root password as the PegaProx login
                                    <div className="mb-2 p-3 bg-proxmox-card border border-proxmox-border rounded-lg space-y-2"
                                        onKeyDown={e => { if (e.key === 'Enter' && !e.defaultPrevented && e.target.tagName === 'INPUT') { e.preventDefault(); if (!busy && hashPw) hashIntoAnswer(); } }}>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                            <input type="password" autoComplete="new-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" value={hashPw} placeholder={t('password')}
                                                aria-label={t('password')} onChange={e => { setHashPw(e.target.value); setHashMsg(null); }}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white" />
                                            <input type="password" autoComplete="new-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" value={hashPw2} placeholder={t('confirmPassword')}
                                                aria-label={t('confirmPassword')} onChange={e => { setHashPw2(e.target.value); setHashMsg(null); }}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white" />
                                        </div>
                                        <div className="flex flex-wrap items-center justify-between gap-2">
                                            <span className="text-[11px] text-gray-500">{t('autoInstallPwHint')}</span>
                                            <button type="button" onClick={() => hashIntoAnswer()} disabled={busy || !hashPw}
                                                className="text-xs px-3 py-1.5 bg-proxmox-orange hover:bg-proxmox-orange/90 rounded disabled:opacity-50 flex items-center gap-1.5">
                                                {busy && <Icons.RotateCw />}
                                                {t('autoInstallHashInsert')}
                                            </button>
                                        </div>
                                        {hashMsg && (
                                            <div className={`text-xs ${hashMsg.ok ? 'text-green-400' : 'text-red-400'}`}>{hashMsg.text}</div>
                                        )}
                                    </div>
                                )}
                                {editing.answer_redacted && (
                                    <div className="mb-2 text-xs text-yellow-300 flex items-center gap-1.5">
                                        <Icons.Lock className="w-3.5 h-3.5" />
                                        {t('autoInstallRedacted')}
                                    </div>
                                )}
                                <textarea rows={14} spellCheck={false} disabled={readOnly || !!editing.answer_redacted}
                                    value={editing.answer || ''} onChange={e => { setEditing({ ...editing, answer: e.target.value }); setCheck(null); }}
                                    className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded font-mono text-xs text-white disabled:opacity-50" />
                            </div>

                            {check && (
                                <div className={`rounded-lg p-3 text-xs border ${check.valid ? 'bg-green-500/10 border-green-500/30 text-green-300' : 'bg-red-500/10 border-red-500/30 text-red-200'}`}>
                                    <div className="font-medium mb-1">
                                        {check.valid ? t('autoInstallAnswerOk') : t('autoInstallAnswerBad')}
                                    </div>
                                    {(check.errors || []).map((e, i) => <div key={`e${i}`}>• {e}</div>)}
                                    {(check.warnings || []).map((w, i) => <div key={`w${i}`} className="text-yellow-300">• {w}</div>)}
                                </div>
                            )}

                            {!readOnly && (
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('autoInstallCallbackUrl')}</label>
                                    <input value={editing.callback_url || ''} placeholder={editing.callback_effective_url || ''}
                                        onChange={e => setEditing({ ...editing, callback_url: e.target.value })}
                                        className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white" />
                                    <div className="text-[11px] text-gray-500 mt-1">{t('autoInstallCallbackHint')}</div>
                                </div>
                            )}

                            <div className="flex items-center justify-between pt-1">
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                    <input type="checkbox" checked={!!editing.enabled} disabled={readOnly}
                                        onChange={e => setEditing({ ...editing, enabled: e.target.checked })} />
                                    {t('enabled')}
                                </label>
                                <div className="flex gap-2">
                                    <button onClick={() => { setEditing(null); setCheck(null); }}
                                        className="px-4 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-sm text-gray-300 hover:border-gray-500">
                                        {readOnly ? t('close') : t('cancel')}
                                    </button>
                                    {!readOnly && (
                                        <button onClick={save} disabled={busy || !editing.name}
                                            className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium disabled:opacity-50">
                                            {t('save')}
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                        <table className="w-full text-sm">
                            <thead className="bg-proxmox-card/50 text-gray-400 text-xs uppercase">
                                <tr>
                                    <th className="text-left px-4 py-2">{t('name')}</th>
                                    <th className="text-left px-4 py-2">{t('autoInstallTargetCluster')}</th>
                                    <th className="text-left px-4 py-2">{t('autoInstallToken')}</th>
                                    <th className="text-left px-4 py-2">{t('autoInstallUses')}</th>
                                    <th className="text-right px-4 py-2"></th>
                                </tr>
                            </thead>
                            <tbody>
                                {profiles.length === 0 && !loadError && (canManage && !editing && !loading ? (
                                    // first visit: offer both ways in instead of an empty table
                                    <tr><td colSpan="5" className="p-4">
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <button onClick={openWizard}
                                                className="text-left p-4 rounded-xl border border-proxmox-border bg-proxmox-card hover:border-proxmox-orange transition-colors">
                                                <div className="flex items-center gap-2 text-white font-medium">
                                                    <Icons.Disc className="w-5 h-5 text-proxmox-orange" />
                                                    {t('autoInstallChoiceGuided')}
                                                </div>
                                                <div className="text-xs text-gray-400 mt-1">{t('autoInstallChoiceGuidedHint')}</div>
                                            </button>
                                            <button onClick={startNew}
                                                className="text-left p-4 rounded-xl border border-proxmox-border bg-proxmox-card hover:border-gray-500 transition-colors">
                                                <div className="flex items-center gap-2 text-white font-medium">
                                                    <Icons.FileText />
                                                    {t('autoInstallChoiceEditor')}
                                                </div>
                                                <div className="text-xs text-gray-400 mt-1">{t('autoInstallChoiceEditorHint')}</div>
                                            </button>
                                        </div>
                                        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
                                            <span className="text-gray-400 font-medium">{t('autoInstallHowItWorks')}:</span>
                                            <span>1. {t('autoInstallHow1')}</span>
                                            <span>2. {t('autoInstallHow2')}</span>
                                            <span>3. {t('autoInstallHow3')}</span>
                                        </div>
                                    </td></tr>
                                ) : (
                                    <tr><td colSpan="5" className="px-4 py-6 text-center text-gray-500">
                                        {loading ? t('loading') : t('autoInstallNoProfiles')}
                                    </td></tr>
                                ))}
                                {profiles.map(p => (
                                    <tr key={p.id} className="border-t border-proxmox-border/50">
                                        <td className="px-4 py-2">
                                            <div className="text-white flex items-center gap-2">
                                                {p.name}
                                                {!p.enabled && <span className="text-[10px] px-1.5 py-0.5 border border-gray-600 text-gray-400 rounded">{t('disabled')}</span>}
                                            </div>
                                            {p.description && <div className="text-xs text-gray-500">{p.description}</div>}
                                        </td>
                                        <td className="px-4 py-2 text-gray-300">{p.target_cluster_name || p.target_cluster_id || '-'}</td>
                                        <td className="px-4 py-2 font-mono text-xs text-gray-400">{p.token_hint}...</td>
                                        <td className="px-4 py-2 text-gray-300">
                                            {p.uses}{p.max_uses ? ` / ${p.max_uses}` : ''}
                                        </td>
                                        <td className="px-4 py-2">
                                            <div className="flex items-center justify-end gap-1">
                                                {canManage ? (
                                                    <>
                                                        <button onClick={() => openProfile(p, false)} title={t('edit')}
                                                            className="p-1.5 text-gray-400 hover:text-white"><Icons.Edit className="w-4 h-4" /></button>
                                                        <button onClick={() => rotate(p)} title={t('autoInstallRotate')}
                                                            className="p-1.5 text-gray-400 hover:text-white"><Icons.RefreshCw className="w-4 h-4" /></button>
                                                        <button onClick={() => remove(p)} title={t('delete')}
                                                            className="p-1.5 text-gray-400 hover:text-red-400"><Icons.Trash2 className="w-4 h-4" /></button>
                                                    </>
                                                ) : (
                                                    <button onClick={() => openProfile(p, true)} title={t('autoInstallView')}
                                                        className="p-1.5 text-gray-400 hover:text-white"><Icons.Eye className="w-4 h-4" /></button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    <div>
                        <h4 className="font-medium text-white mb-2 flex items-center gap-2">
                            <Icons.Activity className="w-4 h-4" />
                            {t('autoInstallRuns')}
                        </h4>
                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                            <table className="w-full text-sm">
                                <thead className="bg-proxmox-card/50 text-gray-400 text-xs uppercase">
                                    <tr>
                                        <th className="text-left px-4 py-2">{t('autoInstallMachine')}</th>
                                        <th className="text-left px-4 py-2">{t('profile')}</th>
                                        <th className="text-left px-4 py-2">{t('status')}</th>
                                        <th className="text-left px-4 py-2">{t('autoInstallStarted')}</th>
                                        <th className="text-right px-4 py-2"></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {runs.length === 0 && !loadError && (
                                        <tr><td colSpan="5" className="px-4 py-6 text-center text-gray-500">
                                            {t('autoInstallNoRuns')}
                                        </td></tr>
                                    )}
                                    {runs.map(r => (
                                        <tr key={r.id} className="border-t border-proxmox-border/50">
                                            <td className="px-4 py-2">
                                                <div className="text-white">{r.hostname || r.product || r.fingerprint || '-'}</div>
                                                <div className="text-[11px] text-gray-500 font-mono">
                                                    {[r.product && r.hostname ? r.product : '', r.fingerprint || r.client_ip].filter(Boolean).join(' · ')}
                                                </div>
                                            </td>
                                            <td className="px-4 py-2 text-gray-300">{r.profile_name || '-'}</td>
                                            <td className="px-4 py-2">
                                                <span className={`px-2 py-0.5 text-xs rounded-full border ${STATUS_STYLE[r.status] || 'border-gray-600 text-gray-400'}`}>
                                                    {statusLabel(r.status)}
                                                </span>
                                                {r.message && <div className="text-[11px] text-gray-500 mt-0.5">{r.message}</div>}
                                            </td>
                                            <td className="px-4 py-2 text-gray-400 text-xs">{when(r.started_at)}</td>
                                            <td className="px-4 py-2 text-right">
                                                {canManage && (
                                                    <button onClick={() => clearRun(r)} title={t('clear')}
                                                        className="p-1.5 text-gray-400 hover:text-red-400"><Icons.X /></button>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {wizardOpen && (
                        <AutoInstallWizard isOpen onClose={() => setWizardOpen(false)} onCreated={load}
                            onOpenInEditor={openInEditor} clusters={clusters} addToast={addToast}
                            initialTargetClusterId={wizardPreset?.target_cluster_id} />
                    )}
                </div>
            );
        }

        // LW Sep 2026 - the guided way to a profile. Six short steps collect the fields,
        // the server writes the TOML from them (/compose) and Create goes through the
        // same POST /profiles as the editor. Whatever the wizard does not ask for
        // (lvm/zfs tuning, filter-match, first-boot...) is one click away in the editor.
        function AutoInstallWizard({ isOpen, onClose, onCreated, onOpenInEditor, clusters, addToast, initialTargetClusterId }) {
            const { t, language } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const { isCorporate, isCloud } = useLayout();

            const [activeStep, setActiveStep] = useState(0);
            // the Corporate stepper scrolls sideways with a hidden scrollbar; keep the
            // current step in view so the last ones never look cut off
            const stepperRef = useRef(null);
            useEffect(() => {
                const cur = stepperRef.current && stepperRef.current.querySelector('.corp-vm-step.active');
                if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: 'nearest', inline: 'nearest' });
            }, [activeStep]);
            const [stepErrors, setStepErrors] = useState({});
            const [draft, setDraft] = useState(() => {
                // guess keyboard and country from the browser, the admin mostly sits
                // in front of the same kind of keyboard the rack has
                const langs = (navigator.languages && navigator.languages.length) ? navigator.languages : [navigator.language || ''];
                const kbAlias = { da: 'dk', ja: 'jp', sv: 'se', sl: 'si', nb: 'no', nn: 'no', en: 'en-us' };
                let keyboard = '', country = '';
                for (const raw of langs) {
                    const l = String(raw || '').toLowerCase();
                    const base = l.split('-')[0];
                    if (!keyboard) keyboard = [l, kbAlias[base] || base].find(k => AUTOINSTALL_KEYBOARDS.some(x => x[0] === k)) || '';
                    const m = l.match(/^[a-z]{2,3}(?:-[a-z]{4})?-([a-z]{2})(?:-|$)/);
                    if (!country && m && AUTOINSTALL_COUNTRIES.includes(m[1])) country = m[1];
                }
                let tz = '';
                try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
                return {
                    name: '', description: '', target_cluster_id: initialTargetClusterId || '',
                    servers: 'one', several: '5', expires_local: '',
                    country, keyboard: keyboard || 'en-us', timezone: aiTimezoneOk(tz) ? tz : 'UTC',
                    host_mode: 'fixed', host_touched: false, fqdn: '', dhcp_domain: '', mailto: '',
                    pw_mode: 'set', root_password_hashed: '', pasted_hash: '', ssh_keys: '',
                    net_mode: 'dhcp', cidr: '', gateway: '', dns: '', nic_by: 'mac', nic_mac: '', nic_name: '',
                    filesystem: 'ext4', raid: '', disk_by: 'name', disks: [], filter_key: 'ID_SERIAL', filter_glob: '',
                    wipe_ack: false, enabled: true, callback_url: ''
                };
            });
            const [dirty, setDirty] = useState(false);
            // the clear password lives here and nowhere else, and only until Next
            const [pw, setPw] = useState('');
            const [pw2, setPw2] = useState('');
            const [diskInput, setDiskInput] = useState('');
            const [compose, setCompose] = useState(null);   // server result + the fields it was built from
            const [composeError, setComposeError] = useState('');
            const [createError, setCreateError] = useState('');
            const [busy, setBusy] = useState(false);
            const [creating, setCreating] = useState(false);
            const [result, setResult] = useState(null);     // {token, name, fp}
            const [copied, setCopied] = useState(false);
            const [showAdvanced, setShowAdvanced] = useState(false);
            const composeSeq = useRef(0);

            const countryOptions = useMemo(() => {
                let dn = null;
                try { dn = new Intl.DisplayNames([language || 'en', 'en'], { type: 'region' }); } catch (e) { dn = null; }
                return AUTOINSTALL_COUNTRIES.map(c => {
                    let name = '';
                    try { name = dn ? dn.of(c.toUpperCase()) : ''; } catch (e) { name = ''; }
                    return [c, name && name.toLowerCase() !== c ? `${name} (${c})` : c];
                }).sort((a, b) => a[1].localeCompare(b[1]));
            }, [language]);

            const steps = [t('general'), t('autoInstallStepSystem'), t('autoInstallStepRoot'), t('network'), t('disks'), t('summary')];
            const lastStep = steps.length - 1;
            const multi = draft.servers !== 'one';
            const zfsLike = draft.filesystem === 'zfs' || draft.filesystem === 'btrfs';
            const maxUses = (d) => d.servers === 'one' ? 1 : (d.servers === 'unlimited' ? 0 : (parseInt(d.several, 10) || 0));
            const sshLines = (txt) => String(txt || '').split('\n').map(s => s.trim()).filter(Boolean);
            const macHex = (v) => String(v || '').trim().replace(/[:\-]/g, '').toLowerCase();

            const set = (patch) => {
                setDraft(d => ({ ...d, ...patch }));
                setDirty(true);
                const hit = Object.keys(patch).filter(k => stepErrors[k]);
                if (hit.length) setStepErrors(e => { const n = { ...e }; hit.forEach(k => delete n[k]); return n; });
            };
            // switching a card makes the old field errors meaningless
            const pick = (patch) => { set(patch); setStepErrors({}); };
            const clearErr = (...keys) => {
                if (keys.some(k => stepErrors[k])) setStepErrors(e => { const n = { ...e }; keys.forEach(k => delete n[k]); return n; });
            };
            const pickServers = (v) => pick({ servers: v, ...(draft.host_touched ? {} : { host_mode: v === 'one' ? 'fixed' : 'dhcp' }) });

            // the /compose body. Nothing in here is ever the clear password.
            const buildFields = (d) => {
                const g = {
                    keyboard: d.keyboard, country: d.country, timezone: d.timezone.trim(), mailto: d.mailto.trim(),
                    fqdn: d.host_mode === 'fixed' ? d.fqdn.trim()
                        : (d.dhcp_domain.trim() ? { source: 'from-dhcp', domain: d.dhcp_domain.trim() } : { source: 'from-dhcp' }),
                    root_password_hashed: d.pw_mode === 'paste' ? d.pasted_hash.trim() : d.root_password_hashed
                };
                const keys = sshLines(d.ssh_keys);
                if (keys.length) g.root_ssh_keys = keys;
                // from-dhcp must carry nothing else, the installer refuses unknown fields there
                const network = d.net_mode === 'dhcp' ? { source: 'from-dhcp' } : {
                    source: 'from-answer', cidr: d.cidr.trim(), gateway: d.gateway.trim(), dns: d.dns.trim(),
                    filter: d.nic_by === 'mac' ? { ID_NET_NAME_MAC: '*' + macHex(d.nic_mac) } : { ID_NET_NAME: d.nic_name.trim() }
                };
                const disk = { filesystem: d.filesystem };
                if (d.filesystem === 'zfs' || d.filesystem === 'btrfs') disk.raid = d.raid;
                if (d.disk_by === 'name') disk.disk_list = d.disks;
                else disk.filter = { [d.filter_key]: d.filter_glob.trim() };
                return { global: g, network, disk };
            };

            // same idea as CreateVmModal: check on Next only, mark the field, clear on change
            const validateStep = (step, d = draft) => {
                const errs = {};
                const ctrl = (k, v) => { if (!errs[k] && AUTOINSTALL_CTRL_RE.test(v || '')) errs[k] = t('autoInstallErrControl'); };
                if (step === 0) {
                    const name = d.name.trim();
                    if (!name) errs.name = t('required');
                    else if (name.length > 120) errs.name = t('autoInstallErrTooLong').replace('{n}', '120');
                    ctrl('name', d.name);
                    if (d.description.trim().length > 500) errs.description = t('autoInstallErrTooLong').replace('{n}', '500');
                    ctrl('description', d.description);
                    if (d.servers === 'several') {
                        const s = String(d.several).trim();
                        if (!/^\d+$/.test(s) || Number(s) < 2 || Number(s) > 10000) errs.several = t('autoInstallErrServers');
                    }
                    if (d.expires_local) {
                        const when = new Date(d.expires_local).getTime();
                        if (isNaN(when) || when <= Date.now()) errs.expires_local = t('autoInstallErrExpiry');
                    }
                }
                if (step === 1) {
                    if (!AUTOINSTALL_COUNTRIES.includes(d.country)) errs.country = d.country ? t('autoInstallErrCountry') : t('required');
                    if (!AUTOINSTALL_KEYBOARDS.some(k => k[0] === d.keyboard)) errs.keyboard = t('autoInstallErrKeyboard');
                    const tz = d.timezone.trim();
                    if (!tz) errs.timezone = t('required');
                    else if (!aiTimezoneOk(tz)) errs.timezone = t('autoInstallErrTimezone');
                    if (d.host_mode === 'fixed') {
                        const f = d.fqdn.trim();
                        if (!f) errs.fqdn = t('required');
                        else if (aiFqdnError(f)) errs.fqdn = t(aiFqdnError(f));
                    } else if (d.dhcp_domain.trim() && aiFqdnError(d.dhcp_domain.trim(), true)) {
                        errs.dhcp_domain = t(aiFqdnError(d.dhcp_domain.trim(), true));
                    }
                    const mail = d.mailto.trim();
                    if (!mail) errs.mailto = t('required');
                    else if (!aiMailOk(mail)) errs.mailto = t('autoInstallErrMail');
                }
                if (step === 2) {
                    if (d.pw_mode === 'paste') {
                        const h = d.pasted_hash.trim();
                        if (!h) errs.pasted_hash = t('required');
                        else if (!aiCryptOk(h)) errs.pasted_hash = t('autoInstallErrHash');
                    } else if (!(d.root_password_hashed && !pw && !pw2)) {
                        const bytes = new TextEncoder().encode(pw).length;
                        if (!pw) errs.pw = t('required');
                        else if (pw.length < 8 || pw.length > 64 || bytes < 8) errs.pw = t('autoInstallErrPwLength');
                        else if (AUTOINSTALL_CTRL_RE.test(pw)) errs.pw = t('autoInstallErrControl');
                        else if (pw !== pw2) errs.pw2 = t('passwordsDoNotMatch');
                    }
                    const lines = String(d.ssh_keys || '').split('\n');
                    const bad = lines.findIndex(l => l.trim() && !AUTOINSTALL_SSH_KEY_RE.test(l.trim()));
                    if (sshLines(d.ssh_keys).length > 50) errs.ssh_keys = t('autoInstallErrSshCount');
                    else if (bad >= 0) errs.ssh_keys = t('autoInstallErrSshKey').replace('{n}', String(bad + 1));
                }
                if (step === 3 && d.net_mode === 'static') {
                    const cidr = d.cidr.trim();
                    const fam = cidr && !aiCidrError(cidr) ? aiIpFamily(cidr.split('/')[0]) : 0;
                    if (!cidr) errs.cidr = t('required');
                    else if (!fam) errs.cidr = t('autoInstallErrCidr');
                    const ipCheck = (k, v) => {
                        if (!v) errs[k] = t('required');
                        else if (!aiIpFamily(v)) errs[k] = t('autoInstallErrIp');
                        else if (fam && aiIpFamily(v) !== fam) errs[k] = t('autoInstallErrFamily');
                    };
                    ipCheck('gateway', d.gateway.trim());
                    ipCheck('dns', d.dns.trim());
                    if (d.nic_by === 'mac') {
                        if (!d.nic_mac.trim()) errs.nic_mac = t('required');
                        else if (!/^[0-9a-f]{12}$/.test(macHex(d.nic_mac))) errs.nic_mac = t('autoInstallErrMac');
                    } else {
                        const g = d.nic_name.trim();
                        if (!g) errs.nic_name = t('required');
                        else if (!AUTOINSTALL_GLOB_RE.test(g)) errs.nic_name = t('autoInstallErrPattern');
                    }
                }
                if (step === 4) {
                    const levels = AUTOINSTALL_RAID_MIN[d.filesystem];
                    if (levels && !levels[d.raid]) errs.raid = t('autoInstallErrRaid');
                    if (d.disk_by === 'name') {
                        const list = d.disks;
                        const min = levels && levels[d.raid] ? levels[d.raid] : 1;
                        const bad = list.find(x => !aiDiskNameOk(x));
                        const dup = list.find((x, i) => list.indexOf(x) !== i);
                        if (!list.length) errs.disks = t('required');
                        else if (bad) errs.disks = `${bad}: ${t('autoInstallErrDiskName')}`;
                        else if (dup) errs.disks = t('autoInstallErrDiskDup').replace('{name}', dup);
                        else if (!levels && list.length !== 1) errs.disks = t('autoInstallErrDiskOne');
                        else if (levels && list.length < min) errs.disks = t('autoInstallErrDiskFew').replace('{n}', String(min));
                        else if (d.raid === 'raid10' && list.length % 2) errs.disks = t('autoInstallErrDiskEven');
                    } else {
                        const g = d.filter_glob.trim();
                        if (!AUTOINSTALL_DISK_KEYS.includes(d.filter_key)) errs.filter_key = t('required');
                        if (!g) errs.filter_glob = t('required');
                        else if (!AUTOINSTALL_GLOB_RE.test(g)) errs.filter_glob = t('autoInstallErrPattern');
                        if (levels && !d.wipe_ack) errs.wipe_ack = t('autoInstallErrAck');
                    }
                }
                setStepErrors(errs);
                return Object.keys(errs).length === 0;
            };

            // chips: Enter, space or comma adds. /dev/ is dropped, by-id paths are not
            // what the installer matches on, so those stay an error.
            const addDisks = (d = draft) => {
                const names = diskInput.split(/[\s,]+/).map(s => s.replace(/^\/dev\//, '')).filter(Boolean);
                if (!names.length) return d;
                const bad = names.find(n => !aiDiskNameOk(n));
                if (bad) {
                    setStepErrors(e => ({ ...e, disks: `${bad}: ${t('autoInstallErrDiskName')}` }));
                    return null;
                }
                const next = { ...d, disks: d.disks.concat(names.filter((n, i) => !d.disks.includes(n) && names.indexOf(n) === i)) };
                setDraft(next);
                setDirty(true);
                setDiskInput('');
                clearErr('disks');
                return next;
            };

            const hashPassword = async () => {
                setBusy(true);
                try {
                    const r = await fetch(`${API_URL}/auto-install/password-hash`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: pw })
                    });
                    const data = await r.json().catch(() => ({}));
                    if (r.ok && aiCryptOk(data.hash)) {
                        setDraft(d => ({ ...d, root_password_hashed: data.hash }));
                        setPw(''); setPw2('');
                        return data.hash;
                    }
                    setStepErrors({ pw: data.error || t('autoInstallHashFailed') });
                } catch (e) {
                    setStepErrors({ pw: t('autoInstallHashFailed') });
                } finally {
                    setBusy(false);
                }
                return '';
            };

            const runCompose = async (d) => {
                const fields = buildFields(d);
                const seq = ++composeSeq.current;
                setCompose(null); setComposeError(''); setCreateError('');
                setBusy(true);
                try {
                    const r = await fetch(`${API_URL}/auto-install/compose`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ fields })
                    });
                    const data = await r.json().catch(() => ({}));
                    if (seq !== composeSeq.current) return;
                    if (r.ok && typeof data.answer === 'string') setCompose({ ...data, key: JSON.stringify(fields) });
                    else setComposeError(data.error || t('autoInstallRenderFailed'));
                } catch (e) {
                    if (seq === composeSeq.current) setComposeError(t('autoInstallRenderFailed'));
                } finally {
                    if (seq === composeSeq.current) setBusy(false);
                }
            };

            const goNext = async () => {
                if (busy || result || activeStep >= lastStep) return;
                let d = draft;
                if (activeStep === 4 && diskInput.trim()) {
                    d = addDisks(d);
                    if (!d) return;
                }
                if (!validateStep(activeStep, d)) return;
                if (activeStep === 2 && d.pw_mode === 'set' && pw) {
                    const hash = await hashPassword();
                    if (!hash) return;
                    d = { ...d, root_password_hashed: hash };
                }
                setActiveStep(activeStep + 1);
                setStepErrors({});
                if (activeStep + 1 === lastStep) runCompose(d);
            };
            const goTo = (i) => {
                if (busy || i < 0 || i > activeStep) return;
                setActiveStep(i);
                setStepErrors({});
            };

            // compose field_errors come back keyed like 'global.fqdn'; this is where each one lives
            const fieldTarget = (key) => ({
                'global.keyboard': [1, 'keyboard'], 'global.country': [1, 'country'], 'global.timezone': [1, 'timezone'],
                'global.mailto': [1, 'mailto'], 'global.fqdn': [1, draft.host_mode === 'fixed' ? 'fqdn' : 'dhcp_domain'],
                'global.root_password_hashed': [2, draft.pw_mode === 'paste' ? 'pasted_hash' : 'pw'],
                'global.root_ssh_keys': [2, 'ssh_keys'],
                'network.source': [3, 'net_mode'], 'network.cidr': [3, 'cidr'], 'network.gateway': [3, 'gateway'],
                'network.dns': [3, 'dns'], 'network.filter': [3, draft.nic_by === 'mac' ? 'nic_mac' : 'nic_name'],
                'disk.filesystem': [4, 'filesystem'], 'disk.raid': [4, 'raid'], 'disk.disk_list': [4, 'disks'],
                'disk.filter': [4, 'filter_glob']
            })[key] || null;
            const fieldErrors = (compose && compose.field_errors) || {};
            const badSteps = new Set(Object.keys(fieldErrors).map(k => (fieldTarget(k) || [])[0]).filter(i => i !== undefined));
            const fixField = (key) => {
                const tg = fieldTarget(key);
                if (!tg) return;
                setActiveStep(tg[0]);
                setStepErrors({ [tg[1]]: fieldErrors[key] });
            };

            // anything changed after the render means the file on screen is not what Create would save
            const stale = !!compose && activeStep === lastStep && compose.key !== JSON.stringify(buildFields(draft));
            const canCreate = !!compose && compose.valid && !stale && !busy;

            const profileDraft = () => ({
                name: draft.name.trim(), description: draft.description.trim(),
                target_cluster_id: draft.target_cluster_id, callback_url: draft.callback_url.trim(),
                max_uses: maxUses(draft), expires_local: draft.expires_local, enabled: !!draft.enabled
            });

            const create = async () => {
                if (!canCreate) return;
                const cb = draft.callback_url.trim();
                if (cb && (!/^https?:\/\//.test(cb) || cb.length > 500 || AUTOINSTALL_CTRL_RE.test(cb))) {
                    setShowAdvanced(true);
                    setStepErrors({ callback_url: t('autoInstallCallbackBad') });
                    return;
                }
                setBusy(true); setCreating(true); setCreateError('');
                try {
                    const r = await fetch(`${API_URL}/auto-install/profiles`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: draft.name.trim(), description: draft.description.trim(), answer: compose.answer,
                            target_cluster_id: draft.target_cluster_id, callback_url: cb, max_uses: maxUses(draft),
                            expires_at: localInputToUtc(draft.expires_local), enabled: !!draft.enabled
                        })
                    });
                    const data = await r.json().catch(() => ({}));
                    if (r.ok) {
                        // the hash and the rendered file have done their job
                        setDraft(d => ({ ...d, root_password_hashed: '', pasted_hash: '' }));
                        setCompose(null);
                        onCreated && onCreated();
                        if (data.token) {
                            setResult({ token: data.token, name: data.name || draft.name.trim(), fp: data.fetch_fingerprint || '' });
                        } else {
                            addToast?.(t('autoInstallSaved'), 'success');
                            onClose();
                        }
                    } else {
                        setCreateError(data.error || t('autoInstallSaveFailed'));
                    }
                } catch (e) {
                    setCreateError(e.message || t('autoInstallSaveFailed'));
                }
                setBusy(false); setCreating(false);
            };

            // X, Cancel, Done and Escape all come through here. The token cannot be
            // shown again (only rotated, which kills every ISO built so far), so ask.
            const requestClose = () => {
                if (creating) return;
                if (result) {
                    if (!copied && !window.confirm(t('autoInstallTokenNotCopied'))) return;
                } else if (dirty && !window.confirm(t('autoInstallDiscard'))) {
                    return;
                }
                onClose();
            };
            const closeRef = useRef(requestClose);
            closeRef.current = requestClose;
            useEffect(() => {
                if (!isOpen) return;
                // capture phase: the dialog stops keydown from bubbling (the dashboard's
                // single-key shortcuts), so a bubbling listener would never see Escape
                const onKey = (e) => {
                    if (e.key !== 'Escape') return;
                    e.preventDefault();
                    e.stopPropagation();
                    closeRef.current();
                };
                window.addEventListener('keydown', onKey, true);
                return () => window.removeEventListener('keydown', onKey, true);
            }, [isOpen]);

            if (!isOpen) return null;

            const labelCls = 'block text-sm text-gray-400 mb-1';
            const inputCls = (k) => `w-full px-3 py-2 bg-proxmox-dark border rounded-lg text-white ${stepErrors[k] ? 'border-red-500' : 'border-proxmox-border'}`;
            const aria = (k) => stepErrors[k] ? { 'aria-invalid': true, 'aria-describedby': `aiw-err-${k}` } : {};
            const errLine = (k) => stepErrors[k] ? <p id={`aiw-err-${k}`} className="text-xs text-red-400 mt-1">{stepErrors[k]}</p> : null;
            const hint = (text) => <p className="text-xs text-gray-500 mt-1">{text}</p>;
            const warn = (text, action, onAction) => (
                <div className="rounded-lg p-3 text-xs border bg-yellow-500/10 border-yellow-500/30 text-yellow-300 flex items-start gap-2">
                    <Icons.AlertTriangle />
                    <div className="flex-1">
                        {text}
                        {action && <button type="button" onClick={onAction} className="ml-2 font-medium underline hover:text-white">{action}</button>}
                    </div>
                </div>
            );
            const choice = (on, onPick, title, sub, key) => (
                <button key={key} type="button" onClick={onPick} aria-pressed={on}
                    className={`text-left p-3 rounded-lg border transition-colors ${on ? 'border-proxmox-orange bg-proxmox-orange/10' : 'border-proxmox-border bg-proxmox-dark hover:border-gray-500'}`}>
                    <div className={`text-sm font-medium ${on ? 'text-white' : 'text-gray-300'}`}>{title}</div>
                    {sub && <div className="text-xs text-gray-500 mt-0.5">{sub}</div>}
                </button>
            );
            const countryLabel = (c) => (countryOptions.find(x => x[0] === c) || [c, c])[1];

            const renderStepContent = () => {
                switch (activeStep) {
                    case 0:
                        return (
                            <div className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label htmlFor="aiw-name" className={labelCls}>{t('name')}</label>
                                        <input id="aiw-name" autoFocus value={draft.name} placeholder="rack-a"
                                            onChange={e => set({ name: e.target.value })} className={inputCls('name')} {...aria('name')} />
                                        {errLine('name')}
                                    </div>
                                    <div>
                                        <label htmlFor="aiw-cluster" className={labelCls}>{t('autoInstallTargetCluster')}</label>
                                        <select id="aiw-cluster" value={draft.target_cluster_id}
                                            onChange={e => set({ target_cluster_id: e.target.value })} className={inputCls('target_cluster_id')}>
                                            <option value="">-</option>
                                            {(clusters || []).map(c => <option key={c.id} value={c.id}>{c.display_name || c.name || c.id}</option>)}
                                            {/* a preset for a cluster that is not in the list yet */}
                                            {draft.target_cluster_id && !(clusters || []).some(c => c.id === draft.target_cluster_id) && (
                                                <option value={draft.target_cluster_id}>{draft.target_cluster_id}</option>
                                            )}
                                        </select>
                                    </div>
                                </div>
                                <div>
                                    <label htmlFor="aiw-desc" className={labelCls}>{t('description')}</label>
                                    <input id="aiw-desc" value={draft.description} onChange={e => set({ description: e.target.value })}
                                        className={inputCls('description')} {...aria('description')} />
                                    {errLine('description')}
                                </div>
                                <div>
                                    <div className={labelCls}>{t('autoInstallHowMany')}</div>
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                        {choice(draft.servers === 'one', () => pickServers('one'), t('autoInstallOneServer'), t('autoInstallOneServerHint'))}
                                        {choice(draft.servers === 'several', () => pickServers('several'), t('autoInstallSeveralServers'), t('autoInstallSeveralHint'))}
                                        {choice(draft.servers === 'unlimited', () => pickServers('unlimited'), t('autoInstallUnlimitedServers'), t('autoInstallUnlimitedHint'))}
                                    </div>
                                    {draft.servers === 'several' && (
                                        <div className="mt-2 max-w-xs">
                                            <label htmlFor="aiw-several" className={labelCls}>{t('autoInstallServerCount')}</label>
                                            <input id="aiw-several" type="number" min="2" max="10000" value={draft.several}
                                                onChange={e => set({ several: e.target.value })} className={inputCls('several')} {...aria('several')} />
                                            {errLine('several')}
                                        </div>
                                    )}
                                </div>
                                <div>
                                    <label htmlFor="aiw-expires" className={labelCls}>{t('autoInstallExpires')}</label>
                                    <div className="flex flex-wrap items-center gap-2">
                                        <input id="aiw-expires" type="datetime-local" value={draft.expires_local}
                                            onChange={e => set({ expires_local: e.target.value })}
                                            className={`px-3 py-2 bg-proxmox-dark border rounded-lg text-white ${stepErrors.expires_local ? 'border-red-500' : 'border-proxmox-border'}`}
                                            {...aria('expires_local')} />
                                        {[[0, t('none')], [24, `24 ${t('hours')}`], [24 * 7, `7 ${t('days')}`], [24 * 30, `30 ${t('days')}`]].map(([h, label]) => (
                                            <button key={h} type="button"
                                                onClick={() => set({ expires_local: h ? utcToLocalInput(new Date(Date.now() + h * 3600000).toISOString()) : '' })}
                                                className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${!h && !draft.expires_local ? 'border-proxmox-orange text-white' : 'border-proxmox-border text-gray-300 hover:border-gray-500'}`}>
                                                {label}
                                            </button>
                                        ))}
                                    </div>
                                    {errLine('expires_local')}
                                </div>
                                {draft.servers === 'unlimited' && !draft.expires_local && warn(t('autoInstallNoLimitWarn'))}
                            </div>
                        );
                    case 1:
                        return (
                            <div className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label htmlFor="aiw-country" className={labelCls}>{t('autoInstallCountry')}</label>
                                        <select id="aiw-country" autoFocus value={draft.country}
                                            onChange={e => set({ country: e.target.value })} className={inputCls('country')} {...aria('country')}>
                                            <option value="">-</option>
                                            {countryOptions.map(([code, label]) => <option key={code} value={code}>{label}</option>)}
                                        </select>
                                        {errLine('country') || hint(t('autoInstallCountryHint'))}
                                    </div>
                                    <div>
                                        <label htmlFor="aiw-kb" className={labelCls}>{t('autoInstallKeyboard')}</label>
                                        <select id="aiw-kb" value={draft.keyboard}
                                            onChange={e => set({ keyboard: e.target.value })} className={inputCls('keyboard')} {...aria('keyboard')}>
                                            {AUTOINSTALL_KEYBOARDS.map(([code, label]) => <option key={code} value={code}>{label} ({code})</option>)}
                                        </select>
                                        {errLine('keyboard')}
                                    </div>
                                    <div>
                                        <label htmlFor="aiw-tz" className={labelCls}>{t('timezone')}</label>
                                        <input id="aiw-tz" list="aiw-tz-list" value={draft.timezone}
                                            onChange={e => set({ timezone: e.target.value })} className={inputCls('timezone')} {...aria('timezone')} />
                                        <datalist id="aiw-tz-list">
                                            {TIMEZONES.map(z => <option key={z} value={z} />)}
                                        </datalist>
                                        {errLine('timezone')}
                                    </div>
                                    <div>
                                        <label htmlFor="aiw-mail" className={labelCls}>{t('autoInstallMailto')}</label>
                                        <input id="aiw-mail" type="email" value={draft.mailto} placeholder="root@example.com"
                                            onChange={e => set({ mailto: e.target.value })} className={inputCls('mailto')} {...aria('mailto')} />
                                        {errLine('mailto')}
                                    </div>
                                </div>
                                <div>
                                    <div className={labelCls}>{t('autoInstallHostName')}</div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                        {choice(draft.host_mode === 'fixed', () => pick({ host_mode: 'fixed', host_touched: true }), t('autoInstallHostFixed'), t('autoInstallHostFixedHint'))}
                                        {choice(draft.host_mode === 'dhcp', () => pick({ host_mode: 'dhcp', host_touched: true }), t('autoInstallHostDhcp'), t('autoInstallHostDhcpHint'))}
                                    </div>
                                    <div className="mt-2">
                                        {draft.host_mode === 'fixed' ? (
                                            <>
                                                <label htmlFor="aiw-fqdn" className={labelCls}>{t('autoInstallFqdn')}</label>
                                                <input id="aiw-fqdn" value={draft.fqdn} placeholder="pve01.example.com"
                                                    onChange={e => set({ fqdn: e.target.value })} className={inputCls('fqdn')} {...aria('fqdn')} />
                                                {errLine('fqdn')}
                                            </>
                                        ) : (
                                            <>
                                                <label htmlFor="aiw-domain" className={labelCls}>{t('autoInstallDhcpDomain')}</label>
                                                <input id="aiw-domain" value={draft.dhcp_domain} placeholder="example.com"
                                                    onChange={e => set({ dhcp_domain: e.target.value })} className={inputCls('dhcp_domain')} {...aria('dhcp_domain')} />
                                                {errLine('dhcp_domain') || hint(t('autoInstallDhcpNameHint'))}
                                            </>
                                        )}
                                    </div>
                                </div>
                                {draft.host_mode === 'fixed' && multi &&
                                    warn(t('autoInstallSameNameWarn'), t('autoInstallUseDhcp'), () => pick({ host_mode: 'dhcp', host_touched: true }))}
                            </div>
                        );
                    case 2:
                        return (
                            <div className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {choice(draft.pw_mode === 'set', () => pick({ pw_mode: 'set' }), t('autoInstallSetPassword'), t('autoInstallPwHint'))}
                                    {choice(draft.pw_mode === 'paste', () => pick({ pw_mode: 'paste' }), t('autoInstallPasteHash'), t('autoInstallPasteHashHint'))}
                                </div>
                                {draft.pw_mode === 'paste' ? (
                                    <div>
                                        <label htmlFor="aiw-hash" className={labelCls}>{t('autoInstallHashLabel')}</label>
                                        <input id="aiw-hash" autoFocus spellCheck={false} value={draft.pasted_hash} placeholder="$6$..."
                                            onChange={e => set({ pasted_hash: e.target.value })}
                                            className={`${inputCls('pasted_hash')} font-mono text-xs`} {...aria('pasted_hash')} />
                                        {errLine('pasted_hash')}
                                    </div>
                                ) : draft.root_password_hashed ? (
                                    // only the hash is kept; coming back never shows the password
                                    <div>
                                        <div className="flex items-center gap-2 text-sm text-green-400">
                                            <Icons.CheckCircle />
                                            <span>{t('autoInstallPwSet')}</span>
                                            <span className="text-gray-500">·</span>
                                            <button type="button" onClick={() => set({ root_password_hashed: '' })}
                                                className="text-proxmox-orange hover:underline">{t('autoInstallPwChange')}</button>
                                        </div>
                                        {errLine('pw')}
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label htmlFor="aiw-pw" className={labelCls}>{t('password')}</label>
                                            <input id="aiw-pw" type="password" autoFocus autoComplete="new-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" value={pw}
                                                onChange={e => { setPw(e.target.value); setDirty(true); clearErr('pw', 'pw2'); }}
                                                className={inputCls('pw')} {...aria('pw')} />
                                            {errLine('pw')}
                                        </div>
                                        <div>
                                            <label htmlFor="aiw-pw2" className={labelCls}>{t('confirmPassword')}</label>
                                            <input id="aiw-pw2" type="password" autoComplete="new-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" value={pw2}
                                                onChange={e => { setPw2(e.target.value); clearErr('pw2'); }}
                                                className={inputCls('pw2')} {...aria('pw2')} />
                                            {errLine('pw2')}
                                        </div>
                                        {/[^\x00-\x7f]/.test(pw) && <div className="md:col-span-2">{warn(t('autoInstallPwNonAscii'))}</div>}
                                    </div>
                                )}
                                <div>
                                    <label htmlFor="aiw-ssh" className={labelCls}>{t('autoInstallSshKeys')}</label>
                                    <textarea id="aiw-ssh" rows={3} spellCheck={false} value={draft.ssh_keys}
                                        placeholder="ssh-ed25519 AAAA... admin@laptop"
                                        onChange={e => set({ ssh_keys: e.target.value })}
                                        className={`${inputCls('ssh_keys')} font-mono text-xs`} {...aria('ssh_keys')} />
                                    {errLine('ssh_keys') || hint(t('autoInstallSshKeysHint'))}
                                </div>
                            </div>
                        );
                    case 3: {
                        const cidr = draft.cidr.trim(), gw = draft.gateway.trim();
                        const fam = cidr && !aiCidrError(cidr) ? aiIpFamily(cidr.split('/')[0]) : 0;
                        const gwOutside = fam && aiIpFamily(gw) === fam && !aiSameNet(cidr, gw);
                        return (
                            <div className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {choice(draft.net_mode === 'dhcp', () => pick({ net_mode: 'dhcp' }), t('autoInstallNetDhcp'), t('autoInstallNetDhcpHint'))}
                                    {choice(draft.net_mode === 'static', () => pick({ net_mode: 'static' }), t('autoInstallNetStatic'), t('autoInstallNetStaticHint'))}
                                </div>
                                {errLine('net_mode')}
                                {draft.net_mode === 'static' && (
                                    <>
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                            <div>
                                                <label htmlFor="aiw-cidr" className={labelCls}>{t('autoInstallCidr')}</label>
                                                <input id="aiw-cidr" autoFocus value={draft.cidr} placeholder="192.168.1.10/24"
                                                    onChange={e => set({ cidr: e.target.value })} className={inputCls('cidr')} {...aria('cidr')} />
                                                {errLine('cidr')}
                                            </div>
                                            <div>
                                                <label htmlFor="aiw-gw" className={labelCls}>{t('gateway')}</label>
                                                <input id="aiw-gw" value={draft.gateway} placeholder="192.168.1.1"
                                                    onChange={e => set({ gateway: e.target.value })} className={inputCls('gateway')} {...aria('gateway')} />
                                                {errLine('gateway')}
                                            </div>
                                            <div>
                                                <label htmlFor="aiw-dns" className={labelCls}>{t('dnsServer')}</label>
                                                <input id="aiw-dns" value={draft.dns} placeholder="192.168.1.1"
                                                    onChange={e => set({ dns: e.target.value })} className={inputCls('dns')} {...aria('dns')} />
                                                {errLine('dns') || hint(t('autoInstallDnsHint'))}
                                            </div>
                                        </div>
                                        {gwOutside && warn(t('autoInstallGatewayOutside'))}
                                        <div>
                                            <div className={labelCls}>{t('autoInstallNic')}</div>
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                {choice(draft.nic_by === 'mac', () => pick({ nic_by: 'mac' }), t('autoInstallNicByMac'))}
                                                {choice(draft.nic_by === 'name', () => pick({ nic_by: 'name' }), t('autoInstallNicByName'))}
                                            </div>
                                            <div className="mt-2">
                                                {draft.nic_by === 'mac' ? (
                                                    <>
                                                        <input id="aiw-mac" value={draft.nic_mac} placeholder="3c:ec:ef:12:34:56" aria-label={t('autoInstallNicByMac')}
                                                            onChange={e => set({ nic_mac: e.target.value })}
                                                            className={`${inputCls('nic_mac')} font-mono`} {...aria('nic_mac')} />
                                                        {errLine('nic_mac')}
                                                    </>
                                                ) : (
                                                    <>
                                                        <input id="aiw-nic" value={draft.nic_name} placeholder="enp1s0*" aria-label={t('autoInstallNicByName')}
                                                            onChange={e => set({ nic_name: e.target.value })}
                                                            className={`${inputCls('nic_name')} font-mono`} {...aria('nic_name')} />
                                                        {errLine('nic_name') || hint(t('autoInstallNicNameHint'))}
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                        {multi && warn(t('autoInstallSameIpWarn'), t('autoInstallSwitchDhcp'), () => pick({ net_mode: 'dhcp' }))}
                                    </>
                                )}
                            </div>
                        );
                    }
                    case 4: {
                        const levels = AUTOINSTALL_RAID_MIN[draft.filesystem];
                        const need = levels && levels[draft.raid];
                        return (
                            <div className="space-y-4">
                                <div>
                                    <div className={labelCls}>{t('autoInstallFilesystem')}</div>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                        {[['ext4', 'ext4'], ['xfs', 'xfs'], ['zfs', 'ZFS'], ['btrfs', 'Btrfs']].map(([fs, label]) => choice(
                                            draft.filesystem === fs,
                                            // keep the raid level when it exists on the other filesystem too
                                            () => pick({ filesystem: fs, raid: AUTOINSTALL_RAID_MIN[fs] && AUTOINSTALL_RAID_MIN[fs][draft.raid] ? draft.raid : '' }),
                                            label, null, fs))}
                                    </div>
                                    {errLine('filesystem')}
                                </div>
                                {levels && (
                                    <div className="max-w-xs">
                                        <label htmlFor="aiw-raid" className={labelCls}>{t('autoInstallRaid')}</label>
                                        <select id="aiw-raid" value={draft.raid} onChange={e => set({ raid: e.target.value })}
                                            className={inputCls('raid')} {...aria('raid')}>
                                            <option value="">-</option>
                                            {Object.keys(levels).map(l => <option key={l} value={l}>{`${l} (≥${levels[l]})`}</option>)}
                                        </select>
                                        {errLine('raid') || (need ? hint((draft.raid === 'raid10' ? t('autoInstallRaidNeedsEven') : t('autoInstallRaidNeeds')).replace('{n}', String(need))) : null)}
                                    </div>
                                )}
                                <div>
                                    <div className={labelCls}>{t('autoInstallTargetDisks')}</div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                        {choice(draft.disk_by === 'name', () => pick({ disk_by: 'name' }), t('autoInstallDisksByName'), t('autoInstallDisksByNameHint'))}
                                        {choice(draft.disk_by === 'filter', () => pick({ disk_by: 'filter' }), t('autoInstallDisksByFilter'), t('autoInstallDisksByFilterHint'))}
                                    </div>
                                    <div className="mt-2">
                                        {draft.disk_by === 'name' ? (
                                            <>
                                                <div className={`flex flex-wrap items-center gap-2 px-2 py-1.5 bg-proxmox-dark border rounded-lg ${stepErrors.disks ? 'border-red-500' : 'border-proxmox-border'}`}>
                                                    {draft.disks.map(n => (
                                                        <span key={n} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-proxmox-card border border-proxmox-border text-xs text-white font-mono">
                                                            {n}
                                                            <button type="button" aria-label={`${t('remove')} ${n}`}
                                                                onClick={() => set({ disks: draft.disks.filter(x => x !== n) })}
                                                                className="text-gray-400 hover:text-red-400">&times;</button>
                                                        </span>
                                                    ))}
                                                    <input id="aiw-disk" autoFocus value={diskInput} placeholder={draft.disks.length ? '' : 'sda'}
                                                        aria-label={t('autoInstallDisksByName')} {...aria('disks')}
                                                        onChange={e => { setDiskInput(e.target.value); clearErr('disks'); }}
                                                        onKeyDown={e => {
                                                            // Enter on an empty input still means Next
                                                            if (!['Enter', ' ', ','].includes(e.key)) return;
                                                            if (diskInput.trim()) { e.preventDefault(); addDisks(); }
                                                            else if (e.key !== 'Enter') e.preventDefault();
                                                        }}
                                                        className="flex-1 py-1 bg-transparent text-sm text-white font-mono focus:outline-none" style={{ minWidth: '6rem' }} />
                                                    <button type="button" onClick={() => addDisks()} disabled={!diskInput.trim()}
                                                        className="text-xs px-2 py-1 border border-proxmox-border rounded text-gray-300 hover:border-gray-500 disabled:opacity-50">
                                                        {t('add')}
                                                    </button>
                                                </div>
                                                {errLine('disks')}
                                            </>
                                        ) : (
                                            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                                <div>
                                                    <select value={draft.filter_key} aria-label={t('autoInstallFilterKey')}
                                                        onChange={e => set({ filter_key: e.target.value })} className={inputCls('filter_key')} {...aria('filter_key')}>
                                                        {AUTOINSTALL_DISK_KEYS.map(k => <option key={k} value={k}>{k}</option>)}
                                                    </select>
                                                    {errLine('filter_key')}
                                                </div>
                                                <div className="md:col-span-2">
                                                    <input id="aiw-glob" autoFocus value={draft.filter_glob} placeholder="Samsung_SSD_870*"
                                                        aria-label={t('autoInstallFilterGlob')}
                                                        onChange={e => set({ filter_glob: e.target.value })}
                                                        className={`${inputCls('filter_glob')} font-mono`} {...aria('filter_glob')} />
                                                    {errLine('filter_glob')}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                                {zfsLike && draft.disk_by === 'filter' && (
                                    <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 space-y-2">
                                        <div className="flex items-start gap-2">
                                            <Icons.AlertTriangle />
                                            <span>{t('autoInstallWipeWarn')}</span>
                                        </div>
                                        <label className="flex items-center gap-2 cursor-pointer">
                                            <input type="checkbox" checked={draft.wipe_ack} onChange={e => set({ wipe_ack: e.target.checked })} {...aria('wipe_ack')} />
                                            <span>{t('autoInstallWipeAck')}</span>
                                        </label>
                                        {errLine('wipe_ack')}
                                    </div>
                                )}
                                {hint(t('autoInstallTuneInEditor'))}
                            </div>
                        );
                    }
                    default:
                        return renderReview();
                }
            };

            const summaryRows = () => {
                const d = draft;
                const cl = (clusters || []).find(c => c.id === d.target_cluster_id);
                const servers = d.servers === 'one' ? t('autoInstallOneServer')
                    : (d.servers === 'unlimited' ? t('autoInstallUnlimitedServers') : `${t('autoInstallServerCount')}: ${d.several}`);
                const kb = (AUTOINSTALL_KEYBOARDS.find(k => k[0] === d.keyboard) || [d.keyboard, d.keyboard])[1];
                const keys = sshLines(d.ssh_keys).length;
                return [
                    [0, [d.name.trim(), servers, cl ? (cl.display_name || cl.name || cl.id) : d.target_cluster_id,
                         d.expires_local ? `${t('autoInstallExpires')} ${new Date(d.expires_local).toLocaleString()}` : '']],
                    [1, [countryLabel(d.country), kb, d.timezone.trim(),
                         d.host_mode === 'fixed' ? d.fqdn.trim() : `${t('autoInstallHostDhcp')}${d.dhcp_domain.trim() ? ` (${d.dhcp_domain.trim()})` : ''}`,
                         d.mailto.trim()]],
                    [2, [d.pw_mode === 'paste' ? t('autoInstallPasteHash') : t('autoInstallPwSet'),
                         keys ? t('autoInstallSshKeyCount').replace('{n}', String(keys)) : '']],
                    [3, d.net_mode === 'dhcp' ? [t('autoInstallNetDhcp')]
                        : [d.cidr.trim(), `${t('gateway')} ${d.gateway.trim()}`, `${t('dnsServer')} ${d.dns.trim()}`,
                           d.nic_by === 'mac' ? `MAC ${d.nic_mac.trim()}` : d.nic_name.trim()]],
                    [4, [({ ext4: 'ext4', xfs: 'xfs', zfs: 'ZFS', btrfs: 'Btrfs' })[d.filesystem] + (zfsLike ? ` ${d.raid}` : ''),
                         d.disk_by === 'name' ? d.disks.join(', ') : `${d.filter_key} = ${d.filter_glob.trim()}`]]
                ];
            };

            const renderReview = () => {
                const fieldMsgs = Object.values(fieldErrors);
                return (
                    <div className="space-y-4">
                        {busy && !compose && (
                            <div className="flex items-center gap-2 text-sm text-gray-400">
                                <Icons.RotateCw />
                                {t('autoInstallRendering')}
                            </div>
                        )}
                        {composeError && (
                            <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 flex flex-wrap items-center justify-between gap-2">
                                <span>{composeError}</span>
                                <button type="button" onClick={() => runCompose(draft)} disabled={busy} className="text-xs underline hover:text-white">
                                    {t('autoInstallRenderAgain')}
                                </button>
                            </div>
                        )}
                        {compose && (
                            <div className={`rounded-lg p-3 text-xs border ${compose.valid ? 'bg-green-500/10 border-green-500/30 text-green-300' : 'bg-red-500/10 border-red-500/30 text-red-200'}`}>
                                <div className="font-medium mb-1">
                                    {compose.valid ? t('autoInstallAnswerOk') : t('autoInstallAnswerBad')}
                                </div>
                                {Object.keys(fieldErrors).map(k => (
                                    <div key={`f${k}`} className="flex flex-wrap items-center gap-2">
                                        <span>• {fieldErrors[k]}</span>
                                        {fieldTarget(k) && (
                                            <button type="button" onClick={() => fixField(k)} className="font-medium underline hover:text-white">
                                                {t('autoInstallFix')}
                                            </button>
                                        )}
                                    </div>
                                ))}
                                {(compose.errors || []).filter(e => !fieldMsgs.includes(e)).map((e, i) => <div key={`e${i}`}>• {e}</div>)}
                                {(compose.warnings || []).map((w, i) => <div key={`w${i}`} className="text-yellow-300">• {w}</div>)}
                            </div>
                        )}
                        {stale && (
                            <div className="rounded-lg p-3 text-xs border bg-yellow-500/10 border-yellow-500/30 text-yellow-300 flex flex-wrap items-center justify-between gap-2">
                                <span>{t('autoInstallRenderStale')}</span>
                                <button type="button" onClick={() => runCompose(draft)} className="font-medium underline hover:text-white">
                                    {t('autoInstallRenderAgain')}
                                </button>
                            </div>
                        )}

                        <dl className="border border-proxmox-border rounded-lg">
                            {summaryRows().map(([i, parts]) => (
                                <div key={i} className={`flex items-start gap-3 px-3 py-2 text-sm ${i ? 'border-t border-proxmox-border' : ''}`}>
                                    <dt className={`w-28 shrink-0 ${badSteps.has(i) ? 'text-red-400' : 'text-gray-400'}`}>{steps[i]}</dt>
                                    <dd className="flex-1 min-w-0 text-white break-all">{parts.filter(Boolean).join(' · ')}</dd>
                                    <button type="button" onClick={() => goTo(i)} disabled={busy}
                                        className="text-xs text-proxmox-orange hover:underline disabled:opacity-50">{t('edit')}</button>
                                </div>
                            ))}
                        </dl>

                        {compose && compose.answer && (
                            <div>
                                <div className="text-xs text-gray-400 mb-1">{t('autoInstallAnswerFile')}</div>
                                <pre className="max-h-64 overflow-auto px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-xs text-gray-200 font-mono">{compose.answer}</pre>
                            </div>
                        )}

                        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                            <input type="checkbox" checked={!!draft.enabled} onChange={e => set({ enabled: e.target.checked })} />
                            {t('enabled')}
                        </label>

                        <div>
                            <button type="button" onClick={() => setShowAdvanced(!showAdvanced)} aria-expanded={showAdvanced}
                                className="flex items-center gap-1 text-xs text-gray-400 hover:text-white">
                                <Icons.ChevronRight className={`w-3.5 h-3.5 transition-transform ${showAdvanced ? 'rotate-90' : ''}`} />
                                {t('advanced')}
                            </button>
                            {showAdvanced && (
                                <div className="mt-2">
                                    <label htmlFor="aiw-cb" className={labelCls}>{t('autoInstallCallbackUrl')}</label>
                                    <input id="aiw-cb" value={draft.callback_url} placeholder="https://"
                                        onChange={e => set({ callback_url: e.target.value })} className={inputCls('callback_url')} {...aria('callback_url')} />
                                    {errLine('callback_url') || hint(t('autoInstallCallbackHint'))}
                                </div>
                            )}
                        </div>

                        <p className="flex items-center gap-2 text-xs text-gray-500">
                            <Icons.Info />
                            {t('autoInstallIsoMin')}
                        </p>

                        {createError && (
                            <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 flex items-center gap-2">
                                <Icons.AlertTriangle />
                                {createError}
                            </div>
                        )}
                    </div>
                );
            };

            const renderResult = () => (
                <div className="space-y-4">
                    <div className="flex items-center gap-2 text-sm text-green-400 font-medium">
                        <Icons.CheckCircle />
                        <span>{t('autoInstallCreated')}: <span className="text-white">{result.name}</span></span>
                    </div>
                    <AutoInstallTokenBox t={t} reveal={result} onCopied={() => setCopied(true)} />
                    <div>
                        <h4 className="text-sm font-medium text-white mb-2">{t('autoInstallNextSteps')}</h4>
                        <ol className="space-y-2 text-sm text-gray-300">
                            {[t('autoInstallNextStep1'), t('autoInstallNextStep2'), t('autoInstallNextStep3')].map((s, i) => (
                                <li key={i} className="flex items-start gap-2">
                                    <span className="w-5 h-5 shrink-0 rounded-full bg-proxmox-orange/20 text-proxmox-orange text-xs flex items-center justify-center">{i + 1}</span>
                                    <span>{s}</span>
                                </li>
                            ))}
                        </ol>
                    </div>
                </div>
            );

            // Enter in a field means Next. Deliberately not a <form>: the root step holds a
            // password pair, and a submitted form that disappears makes browsers offer to
            // save it as the PegaProx login. Textareas (SSH keys) keep their newlines.
            const body = result ? renderResult() : (
                <div onKeyDown={e => {
                    // a field that handled Enter itself (the disk chips) called preventDefault,
                    // which is also what stops a real form from submitting
                    if (e.key === 'Enter' && !e.defaultPrevented && e.target.tagName === 'INPUT'
                            && e.target.type !== 'checkbox' && e.target.type !== 'radio') {
                        e.preventDefault();
                        goNext();
                    }
                }}>
                    {renderStepContent()}
                </div>
            );
            const stepMeta = result ? result.name : `${t('step')} ${activeStep + 1} / ${steps.length}`;
            // clicks and keys stay inside: React bubbles through portals, and the
            // dashboard has single-letter shortcuts on document
            const contain = { onClick: e => e.stopPropagation(), onKeyDown: e => e.stopPropagation() };

            if (isCorporate) {
                return ReactDOM.createPortal(
                    <div className="corp-vm-modal-overlay" style={{ zIndex: 70 }} {...contain}>
                        <div className="corp-vm-modal" style={{ maxWidth: '820px' }} role="dialog" aria-modal="true" aria-labelledby="aiw-title">
                            <div className="corp-vm-modal-header">
                                <div className="corp-vm-modal-header-left">
                                    <span className="corp-vm-type-pill">PVE</span>
                                    <div className="corp-vm-modal-title-block">
                                        <h2 id="aiw-title" className="corp-vm-modal-title">{t('autoInstallGuided')}</h2>
                                        <div className="corp-vm-modal-meta">
                                            <span>{t('autoInstall')}</span>
                                            <span className="corp-meta-sep">·</span>
                                            <span>{stepMeta}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="corp-vm-modal-actions">
                                    <button onClick={requestClose} disabled={creating} className="corp-vm-btn corp-vm-btn-ghost">
                                        {t('close')}
                                    </button>
                                </div>
                            </div>

                            {!result && (
                                <div className="corp-vm-stepper" ref={stepperRef}>
                                    {steps.map((s, i) => {
                                        const cls = i === activeStep ? 'active' : (i < activeStep ? 'done' : 'todo');
                                        const bad = badSteps.has(i) && i !== activeStep;
                                        return (
                                            <button key={i} type="button" onClick={() => goTo(i)} className={`corp-vm-step ${cls}`}
                                                disabled={i > activeStep} aria-current={i === activeStep ? 'step' : undefined}>
                                                <span className="corp-vm-step-num"
                                                    style={bad ? { background: '#c92100', borderColor: '#c92100', color: '#fff' } : undefined}>
                                                    {bad ? '!' : (i < activeStep ? '✓' : i + 1)}
                                                </span>
                                                <span className="corp-vm-step-label">{s}</span>
                                                {i < steps.length - 1 && <span className="corp-vm-step-line" />}
                                            </button>
                                        );
                                    })}
                                </div>
                            )}

                            <div className="corp-vm-modal-body" style={{ minHeight: '320px' }}>
                                {body}
                            </div>

                            <div className="corp-vm-modal-footer">
                                {result ? <span /> : (
                                    <button onClick={requestClose} disabled={creating} className="corp-vm-btn corp-vm-btn-ghost">
                                        {t('cancel')}
                                    </button>
                                )}
                                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                    {result ? (
                                        <button onClick={requestClose} className="corp-vm-btn corp-vm-btn-primary">{t('done')}</button>
                                    ) : (
                                        <>
                                            <button onClick={() => goTo(activeStep - 1)} disabled={activeStep === 0 || busy}
                                                className="corp-vm-btn corp-vm-btn-ghost">
                                                {t('back')}
                                            </button>
                                            {activeStep < lastStep ? (
                                                <button onClick={goNext} disabled={busy} className="corp-vm-btn corp-vm-btn-primary">
                                                    {busy && <Icons.RotateCw />}
                                                    {t('next')}
                                                </button>
                                            ) : (
                                                <>
                                                    <button onClick={() => onOpenInEditor(profileDraft(), compose)} disabled={!compose || !compose.answer || stale || busy}
                                                        className="corp-vm-btn corp-vm-btn-ghost">
                                                        {t('autoInstallOpenInEditor')}
                                                    </button>
                                                    <button onClick={create} disabled={!canCreate} className="corp-vm-btn corp-vm-btn-create">
                                                        {creating && <Icons.RotateCw />}
                                                        {t('autoInstallCreateProfile')}
                                                    </button>
                                                </>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>,
                    document.body
                );
            }

            return ReactDOM.createPortal(
                <div className={`fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/80${isCloud ? ' cloud-mounted' : ''}`} {...contain}>
                    <div className="w-full max-w-2xl max-h-[90vh] flex flex-col bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl overflow-hidden"
                        role="dialog" aria-modal="true" aria-labelledby="aiw-title">
                        <div className="flex items-center justify-between border-b border-proxmox-border bg-proxmox-dark px-6 py-4">
                            <div className="flex items-center gap-3 min-w-0">
                                <div className="p-2 rounded-lg bg-proxmox-orange/10 text-proxmox-orange">
                                    <Icons.Disc className="w-5 h-5" />
                                </div>
                                <div className="min-w-0">
                                    <h2 id="aiw-title" className="font-semibold text-white">{t('autoInstallGuided')}</h2>
                                    <div className="text-xs text-gray-500 truncate">{stepMeta}</div>
                                </div>
                            </div>
                            <button onClick={requestClose} disabled={creating} aria-label={t('close')}
                                className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white">
                                <Icons.X />
                            </button>
                        </div>

                        {!result && (
                            <div className="flex border-b border-proxmox-border bg-proxmox-dark/50 overflow-x-auto">
                                {steps.map((s, i) => (
                                    <button key={i} type="button" onClick={() => goTo(i)} disabled={i > activeStep}
                                        aria-current={i === activeStep ? 'step' : undefined}
                                        className={`flex-1 px-3 py-3 text-xs font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed ${
                                            i === activeStep
                                                ? 'text-proxmox-orange border-b-2 border-proxmox-orange'
                                                : (badSteps.has(i) ? 'text-red-400' : (i < activeStep ? 'text-gray-300 hover:text-white' : 'text-gray-500'))
                                        }`}>
                                        {i + 1}. {s}
                                    </button>
                                ))}
                            </div>
                        )}

                        <div className="flex-1 overflow-y-auto p-6 min-h-[300px]">
                            {body}
                        </div>

                        <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-proxmox-border bg-proxmox-dark">
                            {result ? <span /> : (
                                <button onClick={requestClose} disabled={creating} className="px-4 py-2 text-gray-300 hover:text-white">
                                    {t('cancel')}
                                </button>
                            )}
                            <div className="flex flex-wrap justify-end gap-3">
                                {result ? (
                                    <button onClick={requestClose}
                                        className="px-4 py-2 bg-proxmox-orange hover:bg-proxmox-orange/90 rounded-lg text-white">
                                        {t('done')}
                                    </button>
                                ) : (
                                    <>
                                        <button onClick={() => goTo(activeStep - 1)} disabled={activeStep === 0 || busy}
                                            className="px-4 py-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed">
                                            {t('back')}
                                        </button>
                                        {activeStep < lastStep ? (
                                            <button onClick={goNext} disabled={busy}
                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-proxmox-orange/90 rounded-lg text-white disabled:opacity-50">
                                                {busy && <Icons.RotateCw />}
                                                {t('next')}
                                            </button>
                                        ) : (
                                            <>
                                                <button onClick={() => onOpenInEditor(profileDraft(), compose)} disabled={!compose || !compose.answer || stale || busy}
                                                    className="px-4 py-2 border border-proxmox-border rounded-lg text-gray-300 hover:text-white hover:border-gray-500 disabled:opacity-50">
                                                    {t('autoInstallOpenInEditor')}
                                                </button>
                                                <button onClick={create} disabled={!canCreate}
                                                    className="flex items-center gap-2 px-4 py-2 bg-green-600 rounded-lg text-white hover:bg-green-700 disabled:opacity-50">
                                                    {creating && <Icons.RotateCw />}
                                                    {t('autoInstallCreateProfile')}
                                                </button>
                                            </>
                                        )}
                                    </>
                                )}
                            </div>
                        </div>
                    </div>
                </div>,
                document.body
            );
        }

        // ═══════════════════════════════════════════════
        // PegaProx - Settings Modal
        // PegaProxSettingsModal (Server, SSL, SMTP, RBAC, Audit, Tenants)
        // ═══════════════════════════════════════════════
        // PegaProx Settings Modal with User Management and Audit Log
        function PegaProxSettingsModal({ isOpen, onClose, addToast, onGroupsChanged }) {
            const { t } = useTranslation();
            // haStandby: the saves below that no standby carries out, forwarding or not (#625)
            const { getAuthHeaders, user: currentUser, isAdmin, haStandby } = useAuth();
            const { isCorporate } = useLayout(); // LW: Feb 2026 - Corporate styling
            const [activeTab, setActiveTab] = useState('users');
            const [users, setUsers] = useState([]);
            const [auditLogs, setAuditLogs] = useState([]);
            const [loading, setLoading] = useState(false);
            const [showAddUser, setShowAddUser] = useState(false);
            const [editingUser, setEditingUser] = useState(null);
            const [userFilter, setUserFilter] = useState('');
            const [userFolders, setUserFolders] = useState([]);
            const [showAddFolder, setShowAddFolder] = useState(false);
            const [newFolderName, setNewFolderName] = useState('');
            const [userPage, setUserPage] = useState(0);
            const usersPerPage = 15;
            const [actionFilter, setActionFilter] = useState('');
            const [passwordResetUser, setPasswordResetUser] = useState(null);
            const [newPasswordValue, setNewPasswordValue] = useState('');
            
            // tenant state - NS
            const [tenants, setTenants] = useState([]);
            const [showAddTenant, setShowAddTenant] = useState(false);
            const [newTenant, setNewTenant] = useState({ name: '', clusters: [], groups: [] });
            const [tenantUsage, setTenantUsage] = useState(null);  // NS #502 — live usage for the edit modal
            const [chargeback, setChargeback] = useState(null);  // NS #502b — chargeback statement data
            const [chargebackTenant, setChargebackTenant] = useState(null);  // NS #502b — tenant being viewed
            const [editingTenant, setEditingTenant] = useState(null);
            const [clusters, setClusters] = useState([]);  // for tenant cluster dropdown
            
            // Cluster Groups state - NS Jan 2026
            const [clusterGroups, setClusterGroups] = useState([]);
            const [showAddGroup, setShowAddGroup] = useState(false);
            const [newGroup, setNewGroup] = useState({ name: '', description: '', color: '#E86F2D' });
            const [editingGroup, setEditingGroup] = useState(null);
            const [renamingCluster, setRenamingCluster] = useState(null);
            const [renameValue, setRenameValue] = useState('');
            
            // MK: Feb 2026 - LDAP/AD settings
            const [ldapConfig, setLdapConfig] = useState({
                ldap_enabled: false,
                ldap_server: '', ldap_port: 389,
                ldap_use_ssl: false, ldap_use_starttls: false,
                ldap_bind_dn: '', ldap_bind_password: '',
                ldap_base_dn: '',
                ldap_user_filter: '(&(objectClass=person)(sAMAccountName={username}))',
                ldap_username_attribute: 'sAMAccountName',
                ldap_email_attribute: 'mail',
                ldap_display_name_attribute: 'displayName',
                ldap_group_base_dn: '',
                ldap_group_filter: '(&(objectClass=group)(member={user_dn}))',
                ldap_admin_group: '', ldap_user_group: '', ldap_viewer_group: '',
                ldap_default_role: 'viewer',
                ldap_auto_create_users: true,
                ldap_verify_tls: false,
                ldap_group_mappings: [],  // LW: [{group_dn, role, tenant, tenant_role, permissions}]
            });
            const [ldapTesting, setLdapTesting] = useState(false);
            const [ldapTestResult, setLdapTestResult] = useState(null);
            const [ldapTestUser, setLdapTestUser] = useState('');
            
            // NS: Feb 2026 - OIDC / Entra ID state
            const [oidcConfig, setOidcConfig] = useState({
                oidc_enabled: false,
                oidc_provider: 'entra',
                oidc_cloud_environment: 'commercial',  // NS: GCC High/DoD support
                oidc_client_id: '',
                oidc_client_secret: '',
                oidc_tenant_id: '',
                oidc_authority: '',
                oidc_scopes: 'openid profile email',
                oidc_redirect_uri: '',
                oidc_admin_group_id: '',
                oidc_user_group_id: '',
                oidc_viewer_group_id: '',
                oidc_default_role: 'viewer',
                oidc_auto_create_users: true,
                oidc_button_text: 'Sign in with Microsoft',
                oidc_group_mappings: [],
                oidc_skip_jwt_verification: false,
                oidc_skip_ssl_verify: false,
                oidc_allow_private_ip: false,   // MK May 2026 (#412)
                oidc_audiences: '',             // NS May 2026 (PVE 9.2 parity)
            });
            const [oidcTesting, setOidcTesting] = useState(false);
            const [oidcTestResult, setOidcTestResult] = useState(null);
            
            // permissions state - LW: this got complex fast
            const [allPermissions, setAllPermissions] = useState([]);
            const [rolePermissions, setRolePermissions] = useState({});
            const [selectedUser, setSelectedUser] = useState(null);
            const [userPermissions, setUserPermissions] = useState(null);
            
            // custom roles state - NS: Dec 2025
            const [allRoles, setAllRoles] = useState([]);
            // SPEC-2026-010 P3: per-user granted (extra) tenant roles
            const [grantedRoles, setGrantedRoles] = useState({});
            // SPEC-2026-011 P2b: picker state (pcBusy shared by role row buttons)
            const [pcBusy, setPcBusy] = useState(false);
            // SPEC-2026-011 P5: multi-tenant memberships per user
            const [userTenants, setUserTenants] = useState({});
            const [showAddRole, setShowAddRole] = useState(false);
            const [newRole, setNewRole] = useState({ id: '', name: '', permissions: [], tenant_id: '' });
            const [editingRole, setEditingRole] = useState(null);
            const [selectedTenantForPerms, setSelectedTenantForPerms] = useState('');  // for per-tenant user perms
            
            // Pool Permissions state - MK Jan 2026
            const [permSubTab, setPermSubTab] = useState('users');  // users, vms, pools
            const [pools, setPools] = useState([]);
            const [selectedPoolCluster, setSelectedPoolCluster] = useState('');
            const [selectedPool, setSelectedPool] = useState(null);
            const [poolPermissions, setPoolPermissions] = useState([]);
            const [showPoolPermModal, setShowPoolPermModal] = useState(false);
            const [poolPermForm, setPoolPermForm] = useState({ subject_type: 'user', subject_id: '', permissions: [] });
            const [availablePoolPerms, setAvailablePoolPerms] = useState([]);
            
            // Pool Management state - NS Jan 2026
            const [showPoolManager, setShowPoolManager] = useState(false);
            const [showCreatePool, setShowCreatePool] = useState(false);
            const [newPoolForm, setNewPoolForm] = useState({ poolid: '', comment: '' });
            const [editingPool, setEditingPool] = useState(null);
            const [poolManagerLoading, setPoolManagerLoading] = useState(false);
            const [vmsWithoutPool, setVmsWithoutPool] = useState([]);
            const [showAddVmToPool, setShowAddVmToPool] = useState(null); // pool_id when open
            
            const [filterDate, setFilterDate] = useState('');
            const [snapshotsSubTab, setSnapshotsTab] = useState('overview');
            const [snapshots, setSnapshots] = useState([]);
            
            // Server settings state
            const [serverSettings, setServerSettings] = useState({
                domain: '',
                port: 5000,
                http_redirect_port: 0,  // NS: 0=auto, -1=disabled, >0=specific port
                ssl_enabled: false,
                ssl_cert: '',
                ssl_key: '',
                ssl_cert_file: null,
                ssl_key_file: null,
                acme_enabled: false,
                acme_provider: 'letsencrypt',
                acme_email: '',
                acme_staging: false,
                acme_challenge_type: 'http-01',
                acme_dns_provider: 'manual',
                acme_dns_rfc2136_nameserver: '',
                acme_dns_rfc2136_port: 53,
                acme_dns_rfc2136_zone: '',
                acme_dns_rfc2136_key_name: '',
                acme_dns_rfc2136_secret: '',
                acme_dns_rfc2136_algorithm: 'hmac-sha512',
                acme_dns_rfc2136_ttl: 60,
                acme_dns_propagation_seconds: 30,
                acme_dns_cloudflare_token: '',
                acme_dns_cloudflare_zone: '',
                acme_dns_cloudflare_zone_id: '',
                acme_dns_cloudflare_account_id: '',
                acme_directory_url: '',
                acme_allow_private_ca: false,
                cert_info: null,
                reverse_proxy_enabled: false,
                // NS Apr 2026 — compliance / hardened-environment settings
                audit_retention_days: 90,
                air_gap_mode: false,
                trusted_proxies: '',
                proxy_bind_address: '',
                logo_url: '',
                app_name: 'PegaProx',
                default_theme: 'proxmoxDark',  // NS: Default theme for new users - Jan 2026
                login_background: '',
                // NS: SMTP Settings - Dec 2025
                smtp_enabled: false,
                smtp_host: '',
                smtp_port: 587,
                smtp_user: '',
                smtp_password: '',
                smtp_from_email: '',
                smtp_from_name: 'PegaProx Alerts',
                smtp_tls: true,
                smtp_ssl: false,
                alert_email_recipients: [],
                alert_cooldown: 300,
                alert_update_available: false,
                syslog_filter_by_selected_cluster: false,
                syslog_enabled: true,
            });
            const [serverLoading, setServerLoading] = useState(false);
            const [showRestartConfirm, setShowRestartConfirm] = useState(false);
            const [restartLoading, setRestartLoading] = useState(false);
            const [testEmailLoading, setTestEmailLoading] = useState(false);
            // MK: Mar 2026 - ACME state (#96)
            const [acmeLoading, setAcmeLoading] = useState(false);
            const [acmeResult, setAcmeResult] = useState(null);
            const [testEmailAddress, setTestEmailAddress] = useState('');
            const [loginBgFile, setLoginBgFile] = useState(null);
            const [loginBgError, setLoginBgError] = useState(null);
            const [discoveredPlugins, setDiscoveredPlugins] = useState([]);
            const [editingPluginConfig, setEditingPluginConfig] = useState(null); // {id, name, config}

            // Password policy state - NS Jan 2026
            const [passwordPolicy, setPasswordPolicy] = useState({
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special: false
            });
            
            // update checker
            const [updateInfo, setUpdateInfo] = useState(null);
            const [updateLoading, setUpdateLoading] = useState(false);
            const [updateError, setUpdateError] = useState(null);
            const [updateProgress, setUpdateProgress] = useState(null); // { status: 'downloading'|'installing'|'restarting', message: '' }
            const [availableBackups, setAvailableBackups] = useState([]);
            const [showRollbackModal, setShowRollbackModal] = useState(false);
            
            // New user form - MK: added tenant_id for multi-tenant support
            const [newUser, setNewUser] = useState({
                username: '',
                password: '',
                display_name: '',
                email: '',
                role: 'user',
                tenant_id: 'default',
                portal_only: false
            });
            
            useEffect(() => {
                if (isOpen) {
                    fetchUsers();
                    fetchAuditLogs();
                    fetchServerSettings();
                    fetchPlugins();
                    fetchTenants();
                    fetchMyTenants();
                    fetchPermissions();
                    fetchClusters();
                    fetchClusterGroups();
                    fetchRoles();
                    fetchTemplates();
                    fetchPasswordPolicy();
                }
            }, [isOpen]);
            
            // NS: Listen for navigate-to-updates event from update notification modal
            useEffect(() => {
                const handleNavigateUpdates = () => {
                    setActiveTab('updates');
                    checkForUpdates();
                };
                window.addEventListener('pegaprox-navigate-updates', handleNavigateUpdates);
                return () => window.removeEventListener('pegaprox-navigate-updates', handleNavigateUpdates);
            }, []);

            // the standby banner opens us on the HA tab
            useEffect(() => {
                const toHa = () => setActiveTab('ha');
                window.addEventListener('pegaprox-navigate-ha', toHa);
                return () => window.removeEventListener('pegaprox-navigate-ha', toHa);
            }, []);
            
            // Fetch password policy - NS Jan 2026
            const fetchPasswordPolicy = async () => {
                try {
                    const r = await fetch(`${API_URL}/password-policy`, { credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) {
                        const data = await r.json();
                        setPasswordPolicy(data);
                    }
                } catch (e) {
                    console.error('fetchPasswordPolicy error:', e);
                }
            };
            
            // Generate password policy hint from fetched policy - NS Jan 2026
            const getSettingsPasswordPolicyHint = () => {
                const hints = [];
                hints.push(`${t('minChars') || 'Min.'} ${passwordPolicy.min_length || 8} ${t('characters') || 'characters'}`);
                if (passwordPolicy.require_uppercase !== false) hints.push(t('uppercase') || 'uppercase');
                if (passwordPolicy.require_lowercase !== false) hints.push(t('lowercase') || 'lowercase');
                if (passwordPolicy.require_numbers !== false) hints.push(t('numbers') || 'number');
                if (passwordPolicy.require_special) hints.push(t('specialChar') || 'special char');
                return hints.join(', ');
            };
            
            // fetch tenants - NS
            // LW: added error logging after it silently failed once during testing
            const fetchTenants = async () => {
                try {
                    const r = await fetch(`${API_URL}/tenants`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setTenants(await r.json());
                    else console.warn('Failed to fetch tenants:', r.status);
                } catch(e) { console.error('fetchTenants error:', e); }
            };

            // NS Sep 2026 — which tenants this account actually acts in: its own plus any it was
            // delegated into via tenant_permissions. /api/tenants cannot answer that (it lists
            // what you may SEE, and for a non-admin that is home + default), so someone delegated
            // into a second tenant had no way to find out they were. Display only — the backend
            // keeps deriving the acting tenant from the session, this changes no permission.
            const [myTenants, setMyTenants] = useState({ tenants: [], home: '' });
            const fetchMyTenants = async () => {
                try {
                    const r = await fetch(`${API_URL}/me/tenants`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setMyTenants(await r.json());
                } catch(e) { /* display-only, a failure just hides the line */ }
            };
            
            // fetch clusters for tenant assignment
            const fetchClusters = async () => {
                try {
                    const r = await fetch(`${API_URL}/clusters`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setClusters(await r.json());
                } catch(e) {}
            };
            
            // fetch cluster groups - NS Jan 2026
            const fetchClusterGroups = async () => {
                try {
                    const r = await fetch(`${API_URL}/cluster-groups`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setClusterGroups(await r.json());
                } catch(e) { console.error('fetchClusterGroups error:', e); }
            };
            
            // rename cluster - NS Mar 2026
            const handleRenameCluster = async () => {
                if (!renamingCluster) return;
                const newName = renameValue.trim();
                const confirmMsg = newName
                    ? `${t('confirmRename') || 'Rename cluster to'} "${newName}"?`
                    : `${t('confirmResetName') || 'Reset cluster name to original'}?`;
                if (!confirm(confirmMsg)) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${renamingCluster.id}/rename`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ display_name: newName })
                    });
                    if (r.ok) {
                        addToast(newName ? `Cluster renamed to "${newName}"` : 'Cluster name reset', 'success');
                        setRenamingCluster(null);
                        fetchClusters();
                        onGroupsChanged?.();
                    } else {
                        const err = await r.json().catch(() => ({}));
                        addToast(err.error || 'Rename failed', 'error');
                    }
                } catch(e) { addToast('Rename failed', 'error'); }
            };

            // fetch all roles (builtin + custom) - NS
            const fetchRoles = async () => {
                // SPEC-2026-011 P3: loud failure on BOTH paths (network + !ok), 1 retry
                for (let attempt = 0; attempt < 2; attempt++) {
                    try {
                        const r = await fetch(`${API_URL}/roles`, { credentials: 'include', headers: getAuthHeaders() });
                        if (r.ok) { setAllRoles(await r.json()); return; }
                    } catch(e) {}
                    if (attempt === 0) addToast(t('rolesLoadRetry'), 'error');
                }
                addToast(t('rolesLoadFailed'), 'error');
            };
            
            // check for updates on component mount
            const checkForUpdates = async () => {
                setUpdateLoading(true);
                setUpdateError(null);
                try {
                    const r = await fetch(`${API_URL}/pegaprox/check-update`, { credentials: 'include', headers: getAuthHeaders() });
                    const data = await r.json();
                    setUpdateInfo(data);
                    // Show error if present but still have version info
                    if (data.error) {
                        setUpdateError(data.error);
                    }
                } catch (e) {
                    setUpdateError('Network error checking for updates');
                } finally {
                    setUpdateLoading(false);
                }
            };
            
            // Perform update
            const performUpdate = async () => {
                if (!confirm(t('confirmUpdate') || 'This will download and install the update. A backup will be created. The server will restart automatically. Continue?')) return;
                setUpdateLoading(true);
                setUpdateProgress({ status: 'downloading', message: t('downloadingUpdate') || 'Downloading update...' });
                try {
                    const r = await fetch(`${API_URL}/pegaprox/update`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({})
                    });
                    const data = await r.json();
                    if (r.ok && data.success) {
                        if (data.restarting) {
                            setUpdateProgress({ status: 'restarting', message: t('serverRestarting') || `Server restarting in ${data.restart_delay || 3} seconds...` });
                            addToast(t('updateSuccessRestarting') || 'Update installed! Server is restarting...', 'success');
                            
                            // Wait and then try to reconnect
                            setTimeout(() => {
                                setUpdateProgress({ status: 'reconnecting', message: t('reconnecting') || 'Reconnecting...' });
                                // Poll until server is back
                                const pollInterval = setInterval(async () => {
                                    try {
                                        const healthCheck = await fetch(`${API_URL}/pegaprox/version`, { 
                                            credentials: 'include',
                                            headers: getAuthHeaders() 
                                        });
                                        if (healthCheck.ok) {
                                            clearInterval(pollInterval);
                                            setUpdateProgress(null);
                                            addToast(t('updateComplete') || 'Update complete! Please refresh the page.', 'success');
                                            // Refresh page after short delay
                                            setTimeout(() => window.location.reload(), 2000);
                                        }
                                    } catch (e) {
                                        // Server still restarting
                                    }
                                }, 2000);
                                
                                // Stop polling after 60 seconds
                                setTimeout(() => clearInterval(pollInterval), 60000);
                            }, (data.restart_delay || 3) * 1000 + 2000);
                        } else {
                            addToast(t('updatePrepared') || 'Update prepared! Check instructions below.', 'success');
                            setUpdateInfo(prev => ({ ...prev, instructions: data.instructions, backup_path: data.backup_path }));
                            setUpdateProgress(null);
                        }
                    } else if (data.message === 'Already up to date') {
                        addToast(t('alreadyUpToDate') || 'Already up to date!', 'info');
                        setUpdateProgress(null);
                    } else if (data.error === 'in_app_update_not_supported') {
                        // NS: apt/docker install — the in-app updater must not run here.
                        addToast(data.message || t('updateManagedExternally') || 'This install is updated outside the app (apt / docker).', 'info');
                        setUpdateProgress(null);
                    } else {
                        addToast(data.error || t('updateFailed') || 'Update failed', 'error');
                        setUpdateProgress(null);
                    }
                } catch (e) {
                    addToast(t('errorPerformingUpdate') || 'Error performing update', 'error');
                    setUpdateProgress(null);
                } finally {
                    setUpdateLoading(false);
                }
            };
            
            // NS: Load available backups for rollback - Jan 2026
            const loadBackups = async () => {
                try {
                    const r = await fetch(`${API_URL}/pegaprox/update/rollback`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({})
                    });
                    const data = await r.json();
                    if (data.backups) {
                        setAvailableBackups(data.backups);
                    }
                } catch (e) {
                    console.error('Error loading backups:', e);
                }
            };
            
            // NS: Perform rollback - Jan 2026
            const performRollback = async (backupName) => {
                if (!confirm(t('confirmRollback') || `This will restore PegaProx from backup "${backupName}". The server will restart. Continue?`)) return;
                setUpdateLoading(true);
                setUpdateProgress({ status: 'restoring', message: t('restoringBackup') || 'Restoring from backup...' });
                try {
                    const r = await fetch(`${API_URL}/pegaprox/update/rollback`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ backup: backupName })
                    });
                    const data = await r.json();
                    if (r.ok && data.success) {
                        setShowRollbackModal(false);
                        addToast(t('rollbackSuccess') || 'Rollback successful! Server is restarting...', 'success');
                        setUpdateProgress({ status: 'restarting', message: t('serverRestarting') || 'Server restarting...' });
                        
                        // Poll for reconnection
                        setTimeout(() => {
                            const pollInterval = setInterval(async () => {
                                try {
                                    const healthCheck = await fetch(`${API_URL}/pegaprox/version`, { 
                                        credentials: 'include',
                                        headers: getAuthHeaders() 
                                    });
                                    if (healthCheck.ok) {
                                        clearInterval(pollInterval);
                                        setUpdateProgress(null);
                                        setTimeout(() => window.location.reload(), 2000);
                                    }
                                } catch (e) { }
                            }, 2000);
                            setTimeout(() => clearInterval(pollInterval), 60000);
                        }, 5000);
                    } else {
                        addToast(data.error || t('rollbackFailed') || 'Rollback failed', 'error');
                        setUpdateProgress(null);
                    }
                } catch (e) {
                    addToast(t('errorRollback') || 'Error performing rollback', 'error');
                    setUpdateProgress(null);
                } finally {
                    setUpdateLoading(false);
                }
            };
            
            // create custom role
            const handleCreateRole = async (e) => {
                e && e.preventDefault();
                try {
                    const r = await fetch(`${API_URL}/roles`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify(newRole)
                    });
                    if(r.ok) {
                        setShowAddRole(false);
                        setNewRole({ id: '', name: '', permissions: [], tenant_id: '' });
                        fetchRoles();
                        addToast(t('roleCreated') || 'Role created', 'success');
                    } else {
                        const err = await r.json();
                        addToast(err.error || 'Failed', 'error');
                    }
                } catch(e) { addToast('Error creating role', 'error'); }
            };
            
            // update custom role
            const handleUpdateRole = async (roleId, data) => {
                console.log('[ROLE] Saving role:', roleId, data);
                try {
                    const r = await fetch(`${API_URL}/roles/${roleId}`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    console.log('[ROLE] Response:', r.status, r.statusText);
                    if(r.ok) {
                        setEditingRole(null);
                        fetchRoles();
                        addToast(t('roleSaved') || 'Role saved', 'success');
                    } else {
                        const err = await r.json().catch(() => ({}));
                        console.log('[ROLE] Error response:', err);
                        addToast(err.error || `Failed to update role (${r.status})`, 'error');
                    }
                } catch(e) {
                    console.error('[ROLE] Network error:', e);
                    addToast('Network error: ' + e.message, 'error');
                }
            };
            
            // delete custom role
            const handleDeleteRole = async (roleId, tenantId) => {
                if(!confirm(t('confirmDeleteRole') || 'Delete this role?')) return;
                try {
                    let url = `${API_URL}/roles/${roleId}`;
                    if(tenantId) url += `?tenant_id=${tenantId}`;
                    const r = await fetch(url, { method: 'DELETE', headers: getAuthHeaders() });
                    if(r.ok) {
                        fetchRoles();
                        addToast(t('roleDeleted') || 'Role deleted', 'success');
                    }
                } catch(e) {}
            };
            
            
            // role templates state - NS
            const [roleTemplates, setRoleTemplates] = useState([]);
            const [showTemplateModal, setShowTemplateModal] = useState(false);
            const [selectedTemplate, setSelectedTemplate] = useState(null);
            const [templateConfig, setTemplateConfig] = useState({ role_id: '', name: '', tenant_id: '' });
            
            // fetch role templates
            const fetchTemplates = async () => {
                try {
                    const r = await fetch(`${API_URL}/roles/templates`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setRoleTemplates(await r.json());
                } catch(e) {}
            };
            
            // apply template
            const handleApplyTemplate = async () => {
                if(!selectedTemplate) return;
                try {
                    const r = await fetch(`${API_URL}/roles/templates/${selectedTemplate.id}/apply`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify(templateConfig)
                    });
                    if(r.ok) {
                        setShowTemplateModal(false);
                        setSelectedTemplate(null);
                        setTemplateConfig({ role_id: '', name: '', tenant_id: '' });
                        fetchRoles();
                        addToast(t('roleCreatedFromTemplate') || 'Role created from template', 'success');
                    } else {
                        const err = await r.json();
                        addToast(err.error || 'Failed', 'error');
                    }
                } catch(e) { addToast('Error', 'error'); }
            };
            
            // VM ACL state - NS: Dec 2025
            // AI-assisted: Claude helped with the ACL data structure
            const [vmAcls, setVmAcls] = useState([]);
            const [selectedVmForAcl, setSelectedVmForAcl] = useState(null);
            const [showVmAclModal, setShowVmAclModal] = useState(false);
            const [vmAclUsers, setVmAclUsers] = useState([]);
            const [vmAclPerms, setVmAclPerms] = useState([]);
            const [vmAclInherit, setVmAclInherit] = useState(true);
            const [availableVms, setAvailableVms] = useState([]);
            const [selectedClusterForAcl, setSelectedClusterForAcl] = useState('');
            
            // fetch VMs for ACL management - LW: Dec 2025
            const fetchVmsForAcl = async (clusterId) => {
                if(!clusterId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/vms`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) {
                        const data = await r.json();
                        setAvailableVms(data.vms || []);
                    }
                } catch(e) { /* silently fail, user will see empty list */ }
            };
            
            // fetch VM ACLs for a cluster
            const fetchVmAcls = async (clusterId) => {
                if(!clusterId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/vm-acls`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setVmAcls(await r.json());
                } catch(e) {}
            };
            
            // save VM ACL
            const saveVmAcl = async () => {
                if(!selectedClusterForAcl || !selectedVmForAcl) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedClusterForAcl}/vm-acls/${selectedVmForAcl}`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            users: vmAclUsers,
                            permissions: vmAclPerms,
                            inherit_role: vmAclInherit
                        })
                    });
                    if(r.ok) {
                        setShowVmAclModal(false);
                        fetchVmAcls(selectedClusterForAcl);
                        addToast(t('vmAclSaved') || 'VM permissions saved', 'success');
                    }
                } catch(e) { addToast('Error', 'error'); }
            };
            
            // delete VM ACL
            const deleteVmAcl = async (vmid) => {
                if(!selectedClusterForAcl) return;
                if(!confirm(t('confirmDeleteVmAcl') || 'Remove custom permissions for this VM?')) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedClusterForAcl}/vm-acls/${vmid}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if(r.ok) {
                        fetchVmAcls(selectedClusterForAcl);
                        addToast(t('vmAclDeleted') || 'VM permissions removed', 'success');
                    }
                } catch(e) {}
            };
            
            // Pool Permissions functions - MK Jan 2026
            const fetchPools = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/pools`, { 
                        credentials: 'include',
                        headers: getAuthHeaders() 
                    });
                    if (r.ok) {
                        const data = await r.json();
                        setPools(data);
                    }
                } catch(e) {
                    console.error('Failed to fetch pools:', e);
                }
            };
            
            const fetchPoolPermissions = async (clusterId, poolId) => {
                if (!clusterId || !poolId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/pools/${poolId}/permissions`, { 
                        credentials: 'include',
                        headers: getAuthHeaders() 
                    });
                    if (r.ok) {
                        const data = await r.json();
                        setPoolPermissions(data.permissions || []);
                        setAvailablePoolPerms(data.available_permissions || []);
                    }
                } catch(e) {
                    console.error('Failed to fetch pool permissions:', e);
                }
            };
            
            const savePoolPermission = async () => {
                if (!selectedPoolCluster || !selectedPool || !poolPermForm.subject_id) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${selectedPool}/permissions`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify(poolPermForm)
                    });
                    if (r.ok) {
                        setShowPoolPermModal(false);
                        fetchPoolPermissions(selectedPoolCluster, selectedPool);
                        addToast(t('poolPermSaved') || 'Pool permission saved', 'success');
                        setPoolPermForm({ subject_type: 'user', subject_id: '', permissions: [] });
                    } else {
                        const err = await r.json();
                        addToast(err.error || 'Error saving permission', 'error');
                    }
                } catch(e) {
                    addToast('Error saving permission', 'error');
                }
            };
            
            const deletePoolPermission = async (subjectType, subjectId) => {
                if (!selectedPoolCluster || !selectedPool) return;
                if (!confirm(t('confirmDeletePoolPerm') || `Remove permission for ${subjectId}?`)) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${selectedPool}/permissions/${subjectType}/${subjectId}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if (r.ok) {
                        fetchPoolPermissions(selectedPoolCluster, selectedPool);
                        addToast(t('poolPermDeleted') || 'Pool permission removed', 'success');
                    }
                } catch(e) {}
            };
            
            // MK: Refresh pool cache from Proxmox
            const refreshPoolCache = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/pools/refresh-cache`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if (r.ok) {
                        const data = await r.json();
                        addToast(data.message || 'Pool cache refreshed', 'success');
                        // Refresh pools list
                        fetchPools(clusterId);
                    } else {
                        addToast('Failed to refresh pool cache', 'error');
                    }
                } catch(e) {
                    addToast('Failed to refresh pool cache', 'error');
                }
            };
            
            // ================================================================
            // Pool Management Functions - NS Jan 2026
            // ================================================================
            
            const createPool = async () => {
                if (!selectedPoolCluster || !newPoolForm.poolid.trim()) {
                    addToast(t('poolIdRequired') || 'Pool ID is required', 'error');
                    return;
                }
                
                setPoolManagerLoading(true);
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            poolid: newPoolForm.poolid.trim(),
                            comment: newPoolForm.comment.trim()
                        })
                    });
                    
                    const data = await r.json();
                    if (r.ok) {
                        addToast(data.message || t('poolCreated') || 'Pool created successfully', 'success');
                        setShowCreatePool(false);
                        setNewPoolForm({ poolid: '', comment: '' });
                        // Small delay to let Proxmox process the change
                        setTimeout(() => fetchPools(selectedPoolCluster), 300);
                    } else {
                        addToast(data.error || 'Failed to create pool', 'error');
                    }
                } catch(e) {
                    addToast('Failed to create pool', 'error');
                } finally {
                    setPoolManagerLoading(false);
                }
            };
            
            const updatePool = async () => {
                if (!selectedPoolCluster || !editingPool) return;
                
                setPoolManagerLoading(true);
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${editingPool.poolid}`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            comment: editingPool.comment || ''
                        })
                    });
                    
                    const data = await r.json();
                    if (r.ok) {
                        addToast(data.message || t('poolUpdated') || 'Pool updated successfully', 'success');
                        setEditingPool(null);
                        setTimeout(() => fetchPools(selectedPoolCluster), 300);
                    } else {
                        addToast(data.error || 'Failed to update pool', 'error');
                    }
                } catch(e) {
                    addToast('Failed to update pool', 'error');
                } finally {
                    setPoolManagerLoading(false);
                }
            };
            
            const deletePool = async (poolId) => {
                if (!selectedPoolCluster || !poolId) return;
                if (!confirm(t('confirmDeletePool') || `Are you sure you want to delete pool "${poolId}"? This cannot be undone.`)) return;
                
                setPoolManagerLoading(true);
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${poolId}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    
                    const data = await r.json();
                    if (r.ok) {
                        addToast(data.message || t('poolDeleted') || 'Pool deleted successfully', 'success');
                        if (selectedPool === poolId) {
                            setSelectedPool(null);
                            setPoolPermissions([]);
                        }
                        setTimeout(() => fetchPools(selectedPoolCluster), 300);
                    } else {
                        addToast(data.error || 'Failed to delete pool', 'error');
                    }
                } catch(e) {
                    addToast('Failed to delete pool', 'error');
                } finally {
                    setPoolManagerLoading(false);
                }
            };
            
            const fetchVmsWithoutPool = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const r = await fetch(`${API_URL}/clusters/${clusterId}/vms-without-pool`, { credentials: 'include', headers: getAuthHeaders()
                    });
                    if (r.ok) {
                        const data = await r.json();
                        setVmsWithoutPool(data);
                    }
                } catch(e) {
                    console.error('Failed to fetch VMs without pool:', e);
                }
            };
            
            const addVmToPool = async (poolId, vmid) => {
                if (!selectedPoolCluster || !poolId || !vmid) return;
                
                setPoolManagerLoading(true);
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${poolId}/members`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ vmid: vmid })
                    });
                    
                    const data = await r.json();
                    if (r.ok) {
                        addToast(data.message || t('vmAddedToPool') || 'VM added to pool', 'success');
                        setTimeout(() => {
                            fetchPools(selectedPoolCluster);
                            fetchVmsWithoutPool(selectedPoolCluster);
                        }, 300);
                    } else {
                        addToast(data.error || 'Failed to add VM to pool', 'error');
                    }
                } catch(e) {
                    addToast('Failed to add VM to pool', 'error');
                } finally {
                    setPoolManagerLoading(false);
                }
            };
            
            const removeVmFromPool = async (poolId, vmid) => {
                if (!selectedPoolCluster || !poolId || !vmid) return;
                if (!confirm(t('confirmRemoveVmFromPool') || `Remove VM ${vmid} from pool "${poolId}"?`)) return;
                
                setPoolManagerLoading(true);
                try {
                    const r = await fetch(`${API_URL}/clusters/${selectedPoolCluster}/pools/${poolId}/members/${vmid}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    
                    const data = await r.json();
                    if (r.ok) {
                        addToast(data.message || t('vmRemovedFromPool') || 'VM removed from pool', 'success');
                        setTimeout(() => fetchPools(selectedPoolCluster), 300);
                    } else {
                        addToast(data.error || 'Failed to remove VM from pool', 'error');
                    }
                } catch(e) {
                    addToast('Failed to remove VM from pool', 'error');
                } finally {
                    setPoolManagerLoading(false);
                }
            };
            
            // fetch all permissions
            const fetchPermissions = async () => {
                try {
                    const [permsRes, rolesRes] = await Promise.all([
                        fetch(`${API_URL}/permissions`, { credentials: 'include', headers: getAuthHeaders() }),
                        fetch(`${API_URL}/permissions/roles`, { credentials: 'include', headers: getAuthHeaders() })
                    ]);
                    if(permsRes.ok) setAllPermissions(await permsRes.json());
                    if(rolesRes.ok) setRolePermissions(await rolesRes.json());
                } catch(e) {}
            };
            
            // fetch user permissions
            const fetchUserPermissions = async (username) => {
                try {
                    const r = await fetch(`${API_URL}/users/${username}/permissions`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setUserPermissions(await r.json());
                } catch(e) {}
            };
            
            const fetchServerSettings = async () => {
                try {
                    const response = await fetch(`${API_URL}/settings/server`, {
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        const acmeCertificate = data.acme_certificate || {};
                        const acmeDnsConfig = acmeCertificate.dns_config || {};
                        setServerSettings(prev => ({
                            ...prev,
                            // Server settings
                            domain: data.domain || '',
                            port: data.port || 5000,
                            ssl_enabled: data.ssl_enabled || false,
                            // MK Apr 2026 (#354) — placeholders were hardcoded in German;
                            // surfaced on English UIs too. Wrap in t() with English fallback.
                            ssl_cert: data.ssl_cert_exists ? (t('certPresentPlaceholder') || '(certificate uploaded)') : '',
                            ssl_key: data.ssl_key_exists ? (t('keyPresentPlaceholder') || '(private key uploaded)') : '',
                            acme_enabled: data.acme_enabled || false,
                            acme_provider: acmeCertificate.provider || data.acme_provider || 'letsencrypt',
                            acme_email: acmeCertificate.email || data.acme_email || '',
                            acme_directory_url: acmeCertificate.directory_url || data.acme_directory_url || '',
                            acme_allow_private_ca: data.acme_allow_private_ca ?? false,
                            acme_staging: acmeCertificate.staging ?? data.acme_staging ?? false,
                            acme_challenge_type: acmeCertificate.challenge_type || data.acme_challenge_type || 'http-01',
                            acme_dns_provider: acmeCertificate.dns_provider || data.acme_dns_provider || 'manual',
                            acme_dns_rfc2136_nameserver: acmeDnsConfig.nameserver || data.acme_dns_rfc2136_nameserver || '',
                            acme_dns_rfc2136_port: acmeDnsConfig.port || data.acme_dns_rfc2136_port || 53,
                            acme_dns_rfc2136_zone: acmeDnsConfig.zone || data.acme_dns_rfc2136_zone || '',
                            acme_dns_rfc2136_key_name: acmeDnsConfig.key_name || data.acme_dns_rfc2136_key_name || '',
                            acme_dns_rfc2136_secret: acmeDnsConfig.secret || data.acme_dns_rfc2136_secret || '',
                            acme_dns_rfc2136_algorithm: acmeDnsConfig.algorithm || data.acme_dns_rfc2136_algorithm || 'hmac-sha512',
                            acme_dns_rfc2136_ttl: acmeDnsConfig.ttl || data.acme_dns_rfc2136_ttl || 60,
                            acme_dns_propagation_seconds: acmeDnsConfig.propagation_seconds || data.acme_dns_propagation_seconds || 30,
                            acme_dns_cloudflare_token: data.acme_dns_cloudflare_token || '',
                            acme_dns_cloudflare_zone: acmeDnsConfig.cloudflare_zone || data.acme_dns_cloudflare_zone || '',
                            acme_dns_cloudflare_zone_id: acmeDnsConfig.zone_id || data.acme_dns_cloudflare_zone_id || '',
                            acme_dns_cloudflare_account_id: acmeDnsConfig.account_id || data.acme_dns_cloudflare_account_id || '',
                            cert_info: data.cert_info || null,
                            http_redirect_port: data.http_redirect_port || 0,
                            reverse_proxy_enabled: data.reverse_proxy_enabled || false,
                            audit_retention_days: data.audit_retention_days || 90,
                            air_gap_mode: data.air_gap_mode || false,
                            trusted_proxies: data.trusted_proxies || '',
                            proxy_bind_address: data.proxy_bind_address || '',
                            default_theme: data.default_theme || 'proxmoxDark',
                            login_background: data.login_background || '',
                            // SMTP settings
                            smtp_enabled: data.smtp_enabled || false,
                            smtp_host: data.smtp_host || '',
                            smtp_port: data.smtp_port || 587,
                            smtp_user: data.smtp_user || '',
                            smtp_password: data.smtp_password || '',
                            smtp_from_email: data.smtp_from_email || '',
                            smtp_from_name: data.smtp_from_name || 'PegaProx Alerts',
                            smtp_tls: data.smtp_tls !== false,
                            smtp_ssl: data.smtp_ssl || false,
                            // Alert settings
                            alert_email_recipients: data.alert_email_recipients || [],
                            alert_cooldown: data.alert_cooldown || 300,
                            alert_update_available: !!data.alert_update_available,
                            syslog_filter_by_selected_cluster: !!data.syslog_filter_by_selected_cluster,
                            syslog_enabled: data.syslog_enabled !== false,  // default on
                            // Security settings
                            login_max_attempts: data.login_max_attempts || 5,
                            login_lockout_time: data.login_lockout_time || 300,
                            login_attempt_window: data.login_attempt_window || 300,
                            // Password policy
                            password_min_length: data.password_min_length || 8,
                            password_require_uppercase: data.password_require_uppercase || false,
                            password_require_lowercase: data.password_require_lowercase || false,
                            password_require_numbers: data.password_require_numbers || false,
                            password_require_special: data.password_require_special || false,
                            // Password expiry
                            password_expiry_enabled: data.password_expiry_enabled || false,
                            password_expiry_days: data.password_expiry_days || 90,
                            password_expiry_warning_days: data.password_expiry_warning_days || 14,
                            password_expiry_email_enabled: data.password_expiry_email_enabled !== false,
                            password_expiry_include_admins: data.password_expiry_include_admins || false,
                            force_2fa: data.force_2fa || false,
                            force_2fa_exclude_admins: data.force_2fa_exclude_admins || false,
                            // Session
                            session_timeout: data.session_timeout || 86400
                        }));
                        // MK: Feb 2026 - Load LDAP settings
                        setLdapConfig(prev => ({
                            ...prev,
                            ldap_enabled: data.ldap_enabled || false,
                            ldap_server: data.ldap_server || '',
                            ldap_port: data.ldap_port || 389,
                            ldap_use_ssl: data.ldap_use_ssl || false,
                            ldap_use_starttls: data.ldap_use_starttls || false,
                            ldap_bind_dn: data.ldap_bind_dn || '',
                            ldap_bind_password: data.ldap_bind_password ? '********' : '',
                            ldap_base_dn: data.ldap_base_dn || '',
                            ldap_user_filter: data.ldap_user_filter || '(&(objectClass=person)(sAMAccountName={username}))',
                            ldap_username_attribute: data.ldap_username_attribute || 'sAMAccountName',
                            ldap_email_attribute: data.ldap_email_attribute || 'mail',
                            ldap_display_name_attribute: data.ldap_display_name_attribute || 'displayName',
                            ldap_group_base_dn: data.ldap_group_base_dn || '',
                            ldap_group_filter: data.ldap_group_filter || '(&(objectClass=group)(member={user_dn}))',
                            ldap_admin_group: data.ldap_admin_group || '',
                            ldap_user_group: data.ldap_user_group || '',
                            ldap_viewer_group: data.ldap_viewer_group || '',
                            ldap_default_role: data.ldap_default_role || 'viewer',
                            ldap_auto_create_users: data.ldap_auto_create_users !== false,
                            ldap_verify_tls: data.ldap_verify_tls || false,
                            ldap_group_mappings: data.ldap_group_mappings || [],
                        }));
                        
                        // NS: Load OIDC / Entra ID settings
                        setOidcConfig(prev => ({
                            ...prev,
                            oidc_enabled: data.oidc_enabled || false,
                            oidc_provider: data.oidc_provider || 'entra',
                            oidc_cloud_environment: data.oidc_cloud_environment || 'commercial',
                            oidc_client_id: data.oidc_client_id || '',
                            oidc_client_secret: '',  // Never returned from server
                            oidc_tenant_id: data.oidc_tenant_id || '',
                            oidc_authority: data.oidc_authority || '',
                            oidc_scopes: data.oidc_scopes || 'openid profile email',
                            oidc_redirect_uri: data.oidc_redirect_uri || '',
                            oidc_admin_group_id: data.oidc_admin_group_id || '',
                            oidc_user_group_id: data.oidc_user_group_id || '',
                            oidc_viewer_group_id: data.oidc_viewer_group_id || '',
                            oidc_default_role: data.oidc_default_role || 'viewer',
                            oidc_auto_create_users: data.oidc_auto_create_users !== false,
                            oidc_button_text: data.oidc_button_text || 'Sign in with Microsoft',
                            oidc_skip_jwt_verification: data.oidc_skip_jwt_verification || false,
                            oidc_skip_ssl_verify: data.oidc_skip_ssl_verify || false,
                            oidc_allow_private_ip: data.oidc_allow_private_ip || false,
                            oidc_audiences: data.oidc_audiences || '',
                            oidc_group_mappings: data.oidc_group_mappings || [],
                        }));
                    }
                } catch (err) {
                    console.error('fetching server settings:', err);
                }
            };

            // NS: Mar 2026 - Plugin management
            const fetchPlugins = async () => {
                try {
                    const res = await fetch(`${API_URL}/plugins`, { credentials: 'include', headers: getAuthHeaders() });
                    if (res && res.ok) setDiscoveredPlugins(await res.json());
                } catch (e) { console.warn('plugins fetch:', e); }
            };
            const togglePlugin = async (pluginId, enabled) => {
                try {
                    const action = enabled ? 'disable' : 'enable';
                    const res = await fetch(`${API_URL}/plugins/${pluginId}/${action}`, {
                        method: 'POST', credentials: 'include', headers: getAuthHeaders()
                    });
                    if (res && res.ok) {
                        const data = await res.json().catch(() => ({}));
                        addToast(data.message || `Plugin ${action}d`, 'success');
                        fetchPlugins();
                    } else {
                        const err = await res.json().catch(() => ({}));
                        addToast(err.error || `Failed to ${action} plugin`, 'error');
                    }
                } catch (e) { addToast('Network error', 'error'); }
            };

            // LW: Feb 2026 - LDAP save and test functions
            const saveLdapSettings = async () => {
                setLoading(true);
                try {
                    const res = await fetch(`${API_URL}/settings/server`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(ldapConfig)
                    });
                    if (res.ok) {
                        const result = await res.json();
                        addToast('LDAP settings saved', 'success');
                        // NS: Feb 2026 - Show warnings if LDAP config is incomplete
                        if (result.warnings && result.warnings.length > 0) {
                            result.warnings.forEach(w => addToast(`⚠️ ${w}`, 'warning'));
                        }
                        fetchServerSettings();
                    } else {
                        const err = await res.json();
                        addToast(err.error || 'Failed to save', 'error');
                    }
                } catch (e) { addToast('Network error', 'error'); }
                finally { setLoading(false); }
            };
            
            const testLdapConnection = async () => {
                setLdapTesting(true);
                setLdapTestResult(null);
                try {
                    const res = await fetch(`${API_URL}/settings/ldap/test`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ ...ldapConfig, test_username: ldapTestUser })
                    });
                    const data = await res.json();
                    setLdapTestResult(data);
                    if (data.success) addToast('LDAP connection successful!', 'success');
                    else addToast(data.error || 'Connection failed', 'error');
                } catch (e) { addToast('Network error', 'error'); }
                finally { setLdapTesting(false); }
            };
            
            // NS: Feb 2026 - OIDC / Entra ID save and test
            const saveOidcSettings = async () => {
                setLoading(true);
                try {
                    // MK: Auto-detect redirect URI if not set
                    const configToSave = { ...oidcConfig };
                    if (!configToSave.oidc_redirect_uri) {
                        configToSave.oidc_redirect_uri = `${window.location.origin}/oidc/callback`;
                    }
                    if (!configToSave.oidc_client_secret) {
                        configToSave.oidc_client_secret = '********';  // Don't overwrite
                    }
                    const res = await fetch(`${API_URL}/settings/server`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(configToSave)
                    });
                    if (res.ok) addToast('OIDC settings saved', 'success');
                    else addToast('Failed to save OIDC settings', 'error');
                } catch (e) { addToast('Network error', 'error'); }
                finally { setLoading(false); }
            };
            
            const testOidcConnection = async () => {
                setOidcTesting(true);
                setOidcTestResult(null);
                try {
                    const res = await fetch(`${API_URL}/settings/oidc/test`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(oidcConfig)
                    });
                    const data = await res.json();
                    setOidcTestResult(data);
                    if (data.success) addToast('OIDC endpoints reachable!', 'success');
                    else addToast('Some checks failed', 'warning');
                } catch (e) { addToast('Network error', 'error'); }
                finally { setOidcTesting(false); }
            };
            
            const handleSaveServerSettings = async () => {
                setServerLoading(true);
                try {
                    const formData = new FormData();
                    formData.append('domain', serverSettings.domain);
                    formData.append('port', serverSettings.port);
                    formData.append('http_redirect_port', serverSettings.http_redirect_port || 0);
                    formData.append('ssl_enabled', serverSettings.ssl_enabled);
                    formData.append('acme_enabled', serverSettings.acme_enabled ? 'true' : 'false');
                    formData.append('acme_provider', serverSettings.acme_provider || 'letsencrypt');
                    formData.append('acme_email', serverSettings.acme_email || '');
                    formData.append('acme_staging', serverSettings.acme_staging ? 'true' : 'false');
                    formData.append('acme_challenge_type', serverSettings.acme_challenge_type || 'http-01');
                    formData.append('acme_dns_provider', serverSettings.acme_dns_provider || 'manual');
                    formData.append('acme_dns_rfc2136_nameserver', serverSettings.acme_dns_rfc2136_nameserver || '');
                    formData.append('acme_dns_rfc2136_port', serverSettings.acme_dns_rfc2136_port || 53);
                    formData.append('acme_dns_rfc2136_zone', serverSettings.acme_dns_rfc2136_zone || '');
                    formData.append('acme_dns_rfc2136_key_name', serverSettings.acme_dns_rfc2136_key_name || '');
                    formData.append('acme_dns_rfc2136_secret', serverSettings.acme_dns_rfc2136_secret || '');
                    formData.append('acme_dns_rfc2136_algorithm', serverSettings.acme_dns_rfc2136_algorithm || 'hmac-sha512');
                    formData.append('acme_dns_rfc2136_ttl', serverSettings.acme_dns_rfc2136_ttl || 60);
                    formData.append('acme_dns_propagation_seconds', serverSettings.acme_dns_propagation_seconds || 30);
                    formData.append('acme_dns_cloudflare_token', serverSettings.acme_dns_cloudflare_token || '');
                    formData.append('acme_dns_cloudflare_zone', serverSettings.acme_dns_cloudflare_zone || '');
                    formData.append('acme_dns_cloudflare_zone_id', serverSettings.acme_dns_cloudflare_zone_id || '');
                    formData.append('acme_dns_cloudflare_account_id', serverSettings.acme_dns_cloudflare_account_id || '');
                    formData.append('acme_directory_url', serverSettings.acme_provider === 'custom' ? (serverSettings.acme_directory_url || '') : '');
                    formData.append('acme_allow_private_ca', serverSettings.acme_allow_private_ca ? 'true' : 'false');
                    formData.append('reverse_proxy_enabled', serverSettings.reverse_proxy_enabled);
                    formData.append('audit_retention_days', String(serverSettings.audit_retention_days || 90));
                    formData.append('air_gap_mode', serverSettings.air_gap_mode ? 'true' : 'false');
                    formData.append('trusted_proxies', serverSettings.trusted_proxies || '');
                    formData.append('proxy_bind_address', serverSettings.proxy_bind_address || '');
                    formData.append('default_theme', serverSettings.default_theme || 'proxmoxDark');
                    // NS: alert recipients live in the same tab - must send them too (#131)
                    formData.append('alert_email_recipients', JSON.stringify(serverSettings.alert_email_recipients || []));
                    if (serverSettings.alert_cooldown) {
                        formData.append('alert_cooldown', serverSettings.alert_cooldown);
                    }
                    formData.append('alert_update_available', serverSettings.alert_update_available ? 'true' : 'false');
                    formData.append('syslog_filter_by_selected_cluster', serverSettings.syslog_filter_by_selected_cluster ? 'true' : 'false');
                    formData.append('syslog_enabled', serverSettings.syslog_enabled ? 'true' : 'false');

                    if (serverSettings.ssl_cert_file) {
                        formData.append('ssl_cert', serverSettings.ssl_cert_file);
                    }
                    if (serverSettings.ssl_key_file) {
                        formData.append('ssl_key', serverSettings.ssl_key_file);
                    }
                    if (loginBgFile) {
                        formData.append('login_background', loginBgFile);
                    }
                    
                    const response = await fetch(`${API_URL}/settings/server`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'X-Requested-With': 'XMLHttpRequest' },
                        body: formData
                    });
                    
                    if (response && response.ok) {
                        const data = await response.json();
                        addToast(t('serverSettingsSaved'), 'success');
                        if (data.restart_required) {
                            addToast(t('restartRequired'), 'info');
                        }
                        setLoginBgFile(null);
                        fetchServerSettings();
                    } else {
                        const err = await response.json();
                        addToast(err.error || t('errorSavingSettings'), 'error');
                    }
                } catch (err) {
                    addToast(t('errorSavingSettings'), 'error');
                }
                setServerLoading(false);
            };
            
            const handleCertFileChange = (e, type) => {
                const file = e.target.files[0];
                if (file) {
                    if (type === 'cert') {
                        setServerSettings(prev => ({ ...prev, ssl_cert_file: file, ssl_cert: file.name }));
                    } else {
                        setServerSettings(prev => ({ ...prev, ssl_key_file: file, ssl_key: file.name }));
                    }
                }
            };
            
            // MK: Mar 2026 - ACME cert request handler (#96)
            const handleAcmeRequest = async () => {
                if (!serverSettings.domain) {
                    addToast(t('domain') + ' required', 'error');
                    return;
                }
                if (serverSettings.acme_provider === 'letsencrypt' && !serverSettings.acme_email) {
                    addToast(t('acmeEmail') + ' required', 'error');
                    return;
                }
                if (serverSettings.acme_provider === 'custom' && !serverSettings.acme_directory_url) {
                    addToast('ACME Directory URL required', 'error');
                    return;
                }
                setAcmeLoading(true);
                setAcmeResult(null);
                try {
                    const resp = await fetch(`${API_URL}/settings/acme/request`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({
                            domain: serverSettings.domain,
                            provider: serverSettings.acme_provider || 'letsencrypt',
                            email: serverSettings.acme_email,
                            staging: serverSettings.acme_staging,
                            challenge_type: serverSettings.acme_challenge_type || 'http-01',
                            dns_provider: serverSettings.acme_dns_provider || 'manual',
                            acme_dns_provider: serverSettings.acme_dns_provider || 'manual',
                            acme_dns_rfc2136_nameserver: serverSettings.acme_dns_rfc2136_nameserver || '',
                            acme_dns_rfc2136_port: serverSettings.acme_dns_rfc2136_port || 53,
                            acme_dns_rfc2136_zone: serverSettings.acme_dns_rfc2136_zone || '',
                            acme_dns_rfc2136_key_name: serverSettings.acme_dns_rfc2136_key_name || '',
                            acme_dns_rfc2136_secret: serverSettings.acme_dns_rfc2136_secret || '',
                            acme_dns_rfc2136_algorithm: serverSettings.acme_dns_rfc2136_algorithm || 'hmac-sha512',
                            acme_dns_rfc2136_ttl: serverSettings.acme_dns_rfc2136_ttl || 60,
                            acme_dns_propagation_seconds: serverSettings.acme_dns_propagation_seconds || 30,
                            acme_dns_cloudflare_token: serverSettings.acme_dns_cloudflare_token || '',
                            acme_dns_cloudflare_zone: serverSettings.acme_dns_cloudflare_zone || '',
                            acme_dns_cloudflare_zone_id: serverSettings.acme_dns_cloudflare_zone_id || '',
                            acme_dns_cloudflare_account_id: serverSettings.acme_dns_cloudflare_account_id || '',
                            directory_url: serverSettings.acme_provider === 'custom' ? serverSettings.acme_directory_url : '',
                            acme_allow_private_ca: !!serverSettings.acme_allow_private_ca,
                        })
                    });
                    const data = await resp.json();
                    setAcmeResult(data);
                    if (data.pending_dns) {
                        addToast(t('acmeDnsPrepared') || 'DNS challenge prepared', 'success');
                    } else if (data.success) {
                        addToast(t('acmeSuccess'), 'success');
                        fetchServerSettings();
                    } else {
                        addToast(data.message || data.error || 'ACME failed', 'error');
                    }
                } catch (err) {
                    addToast('ACME request failed: ' + err.message, 'error');
                }
                setAcmeLoading(false);
            };

            const handleAcmeDnsComplete = async () => {
                if (!acmeResult?.challenge_id) return;
                setAcmeLoading(true);
                try {
                    const resp = await fetch(`${API_URL}/settings/acme/dns/complete`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ challenge_id: acmeResult.challenge_id })
                    });
                    const data = await resp.json();
                    setAcmeResult(data);
                    if (data.success) {
                        addToast(t('acmeSuccess'), 'success');
                        fetchServerSettings();
                    } else {
                        addToast(data.message || data.error || 'DNS-01 validation failed', 'error');
                    }
                } catch (err) {
                    addToast('DNS-01 validation failed: ' + err.message, 'error');
                }
                setAcmeLoading(false);
            };

            // Save SMTP Settings - NS Jan 2026
            const [smtpLoading, setSmtpLoading] = useState(false);
            
            const handleSaveSMTPSettings = async () => {
                setSmtpLoading(true);
                try {
                    const response = await fetch(`${API_URL}/settings/server`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            smtp_enabled: serverSettings.smtp_enabled,
                            smtp_host: serverSettings.smtp_host,
                            smtp_port: serverSettings.smtp_port,
                            smtp_user: serverSettings.smtp_user,
                            smtp_password: serverSettings.smtp_password,
                            smtp_from_email: serverSettings.smtp_from_email,
                            smtp_from_name: serverSettings.smtp_from_name,
                            smtp_tls: serverSettings.smtp_tls,
                            smtp_ssl: serverSettings.smtp_ssl,
                            alert_email_recipients: serverSettings.alert_email_recipients,
                            alert_cooldown: serverSettings.alert_cooldown,
                            alert_update_available: !!serverSettings.alert_update_available,
                        })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('smtpSettingsSaved') || 'SMTP settings saved!', 'success');
                        fetchServerSettings();
                    } else {
                        const err = await response.json();
                        addToast(err.error || t('errorSavingSettings'), 'error');
                    }
                } catch (err) {
                    console.error('Save SMTP error:', err);
                    addToast(t('errorSavingSettings'), 'error');
                }
                setSmtpLoading(false);
            };
            
            // Test Email Function - NS Jan 2026
            const handleTestEmail = async () => {
                if (!testEmailAddress) {
                    addToast(t('enterEmailAddress') || 'Please enter an email address', 'error');
                    return;
                }
                
                // Validate required SMTP fields before sending
                if (!serverSettings.smtp_host) {
                    addToast(t('smtpHostRequired') || 'SMTP host is required', 'error');
                    return;
                }
                if (!serverSettings.smtp_from_email) {
                    addToast(t('smtpFromEmailRequired') || 'From email address is required', 'error');
                    return;
                }
                
                setTestEmailLoading(true);
                try {
                    const response = await fetch(`${API_URL}/settings/smtp/test`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            email: testEmailAddress,
                            // Include current SMTP settings in case they haven't been saved yet
                            smtp_host: serverSettings.smtp_host,
                            smtp_port: serverSettings.smtp_port || 587,
                            smtp_user: serverSettings.smtp_user || '',
                            smtp_password: serverSettings.smtp_password || '',
                            smtp_from_email: serverSettings.smtp_from_email,
                            smtp_from_name: serverSettings.smtp_from_name || 'PegaProx Alerts',
                            smtp_tls: serverSettings.smtp_tls !== false,
                            smtp_ssl: serverSettings.smtp_ssl || false
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        addToast(data.message || t('testEmailSuccess') || 'Test email sent!', 'success');
                    } else {
                        addToast(data.error || t('testEmailFailed') || 'Failed to send test email', 'error');
                    }
                } catch (err) {
                    console.error('Test email error:', err);
                    addToast(t('testEmailFailed') || 'Failed to send test email', 'error');
                }
                setTestEmailLoading(false);
            };
            
            const handleRestartServer = async () => {
                setRestartLoading(true);
                try {
                    const response = await fetch(`${API_URL}/settings/server/restart`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    
                    if (response && response.ok) {
                        addToast(t('restartInitiated'), 'success');
                        setShowRestartConfirm(false);
                        // Show reconnecting message after a short delay
                        setTimeout(() => {
                            addToast(t('reconnecting'), 'info');
                        }, 2000);
                        // Try to reconnect after server restart
                        setTimeout(() => {
                            window.location.reload();
                        }, 5000);
                    } else {
                        const err = await response.json();
                        addToast(err.error || t('restartFailed'), 'error');
                    }
                } catch (err) {
                    // Expected - server is restarting
                    addToast(t('restartInitiated'), 'success');
                    setShowRestartConfirm(false);
                    setTimeout(() => {
                        window.location.reload();
                    }, 5000);
                }
                setRestartLoading(false);
            };
            
            const fetchUsers = async () => {
                try {
                    const response = await fetch(`${API_URL}/users`, { credentials: 'include', headers: getAuthHeaders()
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        // SPEC-2026-010 P3: keep granted (extra) roles for chips/checkboxes
                        const gmap = {};
                        (data || []).forEach(uu => { gmap[uu.username] = uu.granted_roles || []; });
                        setGrantedRoles(gmap);
                        // SPEC-2026-011 P5: hydrate tenant memberships
                        const tmap = {};
                        (data || []).forEach(uu => { tmap[uu.username] = uu.granted_tenants || []; });
                        setUserTenants(tmap);
                        setUsers(data);
                    }
                } catch (err) {
                    console.error('fetching users:', err);
                }
                // LW: also fetch user folders
                try {
                    const fr = await fetch(`${API_URL}/user-folders`, { credentials: 'include', headers: getAuthHeaders() });
                    if (fr.ok) setUserFolders(await fr.json());
                } catch(e) {}
            };
            
            // MK May 2026 — server-side filters via /api/audit/search
            const [auditFrom, setAuditFrom] = useState('');
            const [auditTo, setAuditTo] = useState('');
            const [auditQuery, setAuditQuery] = useState('');
            const [auditSev, setAuditSev] = useState('');
            const [auditClusterFilter, setAuditClusterFilter] = useState('');
            const [auditIp, setAuditIp] = useState('');
            const [auditOffset, setAuditOffset] = useState(0);
            const [auditTotal, setAuditTotal] = useState(0);
            const auditPageSize = 100;

            const fetchAuditLogs = async (offsetOverride = null) => {
                try {
                    const off = offsetOverride !== null ? offsetOverride : auditOffset;
                    const params = new URLSearchParams();
                    if (auditQuery) params.set('q', auditQuery);
                    if (auditSev) params.set('severity', auditSev);
                    if (auditClusterFilter) params.set('cluster', auditClusterFilter);
                    if (auditIp) params.set('ip', auditIp);
                    if (auditFrom) params.set('date_from', auditFrom);
                    if (auditTo) params.set('date_to', auditTo);
                    params.set('offset', String(off));
                    params.set('limit', String(auditPageSize));
                    const response = await fetch(`${API_URL}/audit/search?${params.toString()}`, {
                        credentials: 'include', headers: getAuthHeaders(),
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        setAuditLogs(data.entries || []);
                        setAuditTotal(data.total || 0);
                        setAuditOffset(data.offset || 0);
                    } else if (response && response.status === 404) {
                        // backend without /audit/search — fall back to legacy /audit
                        const legacy = await fetch(`${API_URL}/audit`, { credentials: 'include', headers: getAuthHeaders() });
                        if (legacy && legacy.ok) {
                            const list = await legacy.json();
                            setAuditLogs(list);
                            setAuditTotal(list.length);
                        }
                    }
                } catch (err) {
                    console.error('fetching audit logs:', err);
                }
            };
            
            
            const fetchSnapshots = async (body = null) => {
                try {
                    const res = await fetch(`${API_URL}/snapshots/overview`, {
                        method: body ? 'POST' : 'GET',
                        headers: body ? { 'Content-Type': 'application/json', ...getAuthHeaders() } : getAuthHeaders(),
                        credentials: 'include',
                        body: body ? JSON.stringify(body) : undefined
                    });
                    if (!res.ok) {
                        throw new Error(`HTTP ${res.status}`);
                    }
                    const data = await res.json();
                    setSnapshots(data.snapshots ?? data ?? []);
                } catch (err) {
                    console.error('Snapshot fetch failed:', err);
                    setSnapshots([]);
                }
            };
            
            const applySnapshotFilter = async () => {
                await fetchSnapshots({
                    date: filterDate,
                    tab: snapshotsSubTab
                });
            };
            
            const deleteSnapshot = async (snap) => {
                if (!window.confirm(`Delete snapshot "${snap.snapshot_name}" from VM ${snap.vmid}?`)) {
                    return;
                }
                try {
                    await fetch(`${API_URL}/snapshots/delete`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        credentials: 'include',
                        body: JSON.stringify({ snapshots: [snap] })
                    });
                    addToast('Snapshot deleted', 'success');
                    await fetchSnapshots(filterDate ? { date: filterDate, tab: snapshotsSubTab } : null);
                } catch (err) {
                    console.error('Snapshot delete failed:', err);
                    addToast('Failed to delete snapshot', 'error');
                }
            };
            
            const handleResetPassword = async (username) => {
                if (!newPasswordValue || newPasswordValue.length < 4) {
                    addToast(t('passwordTooShort'), 'error');
                    return;
                }
                
                try {
                    const response = await fetch(`${API_URL}/users/${username}/password`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify({ password: newPasswordValue })
                    });
                    
                    if (response && response.ok) {
                        const data = await response.json().catch(() => ({}));
                        setPasswordResetUser(null);
                        setNewPasswordValue('');
                        fetchAuditLogs();
                        // NS 2026-04-24 — if admin reset their OWN password, the backend
                        // killed their session — redirect to login.
                        if (data.relogin_required) {
                            addToast(t('passwordChangedReloginRequired') || 'Password changed — please sign in again.', 'success');
                            setTimeout(() => { window.location.href = '/'; }, 1200);
                        } else {
                            addToast(t('passwordResetSuccess'), 'success');
                        }
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error resetting password', 'error');
                    }
                } catch (err) {
                    addToast('Error resetting password', 'error');
                }
            };
            
            const handleDisable2FA = async (username) => {
                if (!confirm(`${t('disable2FA')} für ${username}?`)) return;
                
                try {
                    const response = await fetch(`${API_URL}/users/${username}/2fa`, {
                        method: 'DELETE',
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: getAuthHeaders()
                    });
                    
                    if (response && response.ok) {
                        addToast(t('twoFactorDisabled'), 'success');
                        fetchUsers();
                        fetchAuditLogs();
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error disabling 2FA', 'error');
                    }
                } catch (err) {
                    addToast('Error disabling 2FA', 'error');
                }
            };
            
            const handleCreateUser = async (e) => {
                e.preventDefault();
                setLoading(true);
                try {
                    const response = await fetch(`${API_URL}/users`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify(newUser)
                    });
                    
                    if (response && response.ok) {
                        addToast(t('userCreated'), 'success');
                        setShowAddUser(false);
                        setNewUser({ username: '', password: '', display_name: '', email: '', role: 'user', tenant_id: 'default', portal_only: false });
                        fetchUsers();
                        fetchAuditLogs();
                        fetchTenants(); // LW: refresh tenant user counts
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error creating user', 'error');
                    }
                } catch (err) {
                    addToast('Error creating user', 'error');
                }
                setLoading(false);
            };
            
            const handleUpdateUser = async (username, updates) => {
                try {
                    const response = await fetch(`${API_URL}/users/${username}`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify(updates)
                    });
                    
                    if (response && response.ok) {
                        addToast(t('userUpdated'), 'success');
                        setEditingUser(null);
                        fetchUsers();
                        fetchAuditLogs();
                        fetchTenants(); // NS: refresh tenant user counts
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error updating user', 'error');
                    }
                } catch (err) {
                    console.error('Error updating user:', err);
                    addToast('Error updating user', 'error');
                }
            };
            
            const handleDeleteUser = async (username) => {
                if (!confirm(t('deleteUserConfirm'))) return;
                
                try {
                    const response = await fetch(`${API_URL}/users/${username}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    
                    if (response && response.ok) {
                        addToast(t('userDeleted'), 'success');
                        fetchUsers();
                        fetchAuditLogs();
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error deleting user', 'error');
                    }
                } catch (err) {
                    addToast('Error deleting user', 'error');
                }
            };
            
            const exportAuditLog = () => {
                const csv = [
                    ['Timestamp', 'User', 'Cluster', 'Action', 'Details', 'IP Address'].join(','),
                    ...filteredLogs.map(log => [
                        log.timestamp,
                        log.user,
                        log.cluster || '',
                        log.action,
                        `"${(log.details || '').replace(/"/g, '""')}"`,
                        log.ip_address || ''
                    ].join(','))
                ].join('\n');
                
                const blob = new Blob([csv], { type: 'text/csv' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `pegaprox-audit-${new Date().toISOString().split('T')[0]}.csv`;
                a.click();
                URL.revokeObjectURL(url);
            };
            
            const getActionLabel = (action) => {
                const labels = {
                    'user.login': t('userLogin'),
                    'user.logout': t('userLogout'),
                    'user.created': t('userCreated'),
                    'user.updated': t('userUpdated'),
                    'user.deleted': t('userDeleted'),
                    'user.password_changed': t('passwordChanged'),
                    'cluster.added': t('clusterAdded'),
                    'cluster.deleted': t('clusterDeleted'),
                    'cluster.config_changed': t('clusterConfigChanged'),
                    'vm.started': t('vmStarted'),
                    'vm.stopped': t('vmStopped'),
                    'vm.restarted': t('vmRestarted'),
                    'vm.created': t('vmCreated'),
                    'vm.deleted': t('vmDeleted'),
                    'vm.cloned': t('vmCloned'),
                    'vm.migrated': t('vmMigrated'),
                    'vm.bulk_migrated': t('vmBulkMigrated'),
                    'vm.config_changed': t('vmConfigChanged'),
                    'vm.suspended': t('vmSuspended'),
                    'vm.resumed': t('vmResumed'),
                    'vm.disk_added': t('vmDiskAdded'),
                    'vm.disk_removed': t('vmDiskRemoved'),
                    'vm.disk_resized': t('vmDiskResized'),
                    'vm.disk_moved': t('vmDiskMoved'),
                    'vm.network_added': t('vmNetworkAdded'),
                    'vm.network_removed': t('vmNetworkRemoved'),
                    'vm.network_updated': t('vmNetworkUpdated'),
                    'snapshot.created': t('snapshotCreated'),
                    'snapshot.deleted': t('snapshotDeleted'),
                    'snapshot.restored': t('snapshotRestored'),
                    'replication.created': t('replicationCreated'),
                    'replication.deleted': t('replicationDeleted'),
                    'replication.triggered': t('replicationTriggered'),
                    'ha.enabled': t('haEnabled'),
                    'ha.disabled': t('haDisabled'),
                    'ha.vm_added': t('haVmAdded'),
                    'ha.vm_removed': t('haVmRemoved'),
                    'node.maintenance_entered': t('nodeMaintenanceEntered'),
                    'node.maintenance_exited': t('nodeMaintenanceExited'),
                    'node.update_started': t('nodeUpdateStarted'),
                };
                return labels[action] || action;
            };
            
            const uniqueUsers = [...new Set(auditLogs.map(log => log.user))];
            const uniqueActions = [...new Set(auditLogs.map(log => log.action))];
            
            const filteredLogs = auditLogs.filter(log => {
                if (userFilter && log.user !== userFilter) return false;
                if (actionFilter && log.action !== actionFilter) return false;
                return true;
            });
            
            if (!isOpen) return null;
            
            return (
                <>
                <div
                    className={isCorporate ? "corp-vm-modal-overlay" : "fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80"}
                    onClick={onClose}
                >
                    <div
                        className={isCorporate
                            ? 'corp-vm-modal'
                            : 'w-full max-w-[120rem] max-h-[90vh] bg-proxmox-card border border-proxmox-border overflow-hidden flex flex-col rounded-2xl shadow-2xl'}
                        style={isCorporate ? {maxWidth: '2200px', width: '100%'} : undefined}
                        onClick={e => e.stopPropagation()}
                    >
                        {/* Header - LW: corporate uses unified corporate chrome (matches VM Configure) */}
                        {isCorporate ? (
                        <div className="corp-vm-modal-header">
                            <div className="flex items-center gap-3 min-w-0 flex-1">
                                <Icons.Settings className="w-5 h-5" style={{color:'var(--corp-accent, #49afd9)'}} />
                                <div className="min-w-0">
                                    <div className="corp-vm-modal-title truncate">{t('pegaproxSettings')}</div>
                                    <div className="corp-vm-modal-meta">PegaProx {PEGAPROX_VERSION}</div>
                                </div>
                            </div>
                            <div className="corp-vm-modal-actions">
                                <button onClick={onClose} className="corp-vm-btn corp-vm-btn-ghost" title={t('close') || 'Close'}>
                                    <Icons.X />
                                </button>
                            </div>
                        </div>
                        ) : (
                        <div className="border-b border-proxmox-border flex items-center justify-between p-6">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-proxmox-orange/20 flex items-center justify-center">
                                    <Icons.Settings />
                                </div>
                                <div>
                                    <h2 className="text-xl font-bold text-white">
                                        {t('pegaproxSettings')}
                                    </h2>
                                    <p className="text-sm text-gray-400">PegaProx {PEGAPROX_VERSION}</p>
                                </div>
                            </div>
                            <button onClick={onClose} className="p-1.5 hover:bg-proxmox-dark text-gray-400 hover:text-white">
                                <Icons.X />
                            </button>
                        </div>
                        )}
                        
                        {/* Settings tabs */}
                        {/* Multi-tenancy was requested on r/selfhosted - turns out MSPs really need this */}
                        {/* NS: Changed to flex-wrap so tabs wrap to multiple lines instead of scrolling */}
                        <div className="flex flex-wrap border-b border-proxmox-border">
                            <button
                                onClick={() => setActiveTab('users')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'users'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Users className="w-4 h-4" />
                                <span className="hidden sm:inline">{t('userManagement')}</span>
                                <span className="sm:hidden">{t('users') || 'Users'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('tenants')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'tenants'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Building className="w-4 h-4" />
                                <span>{t('tenants') || 'Tenants'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('groups')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'groups'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Folder className="w-4 h-4" />
                                <span className="hidden sm:inline">{t('clusterGroups') || 'Cluster Groups'}</span>
                                <span className="sm:hidden">{t('groups') || 'Groups'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('permissions')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'permissions'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Key className="w-4 h-4" />
                                <span>{t('permissions') || 'Permissions'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('roles')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'roles'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Shield className="w-4 h-4" />
                                <span>{t('roles') || 'Roles'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('security')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'security'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Lock className="w-4 h-4" />
                                <span className="hidden sm:inline">{t('securitySettings')}</span>
                                <span className="sm:hidden">{t('security') || 'Security'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('ldap')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'ldap'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Users className="w-4 h-4" />
                                LDAP / AD
                            </button>
                            <button
                                onClick={() => setActiveTab('oidc')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'oidc'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Shield className="w-4 h-4" />
                                OIDC / Entra ID
                            </button>
                            <button
                                onClick={() => setActiveTab('compliance')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'compliance'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Check className="w-4 h-4" />
                                <span className="hidden sm:inline">{t('compliance') || 'Compliance'}</span>
                                <span className="sm:hidden">HIPAA</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('server')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'server'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Server className="w-4 h-4" />
                                <span>{t('server') || 'Server'}</span>
                            </button>
                            {isAdmin && (
                            <button
                                onClick={() => setActiveTab('ha')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'ha'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Layers className="w-4 h-4" />
                                <span>{t('pgHaTab')}</span>
                            </button>
                            )}
                            <button
                                onClick={() => setActiveTab('syslog')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'syslog'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.FileText className="w-4 h-4" />
                                <span>{t('syslogServer') || 'Syslog Server'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('audit')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'audit'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.ClipboardList className="w-4 h-4" />
                                <span className="hidden sm:inline">{t('auditLog')}</span>
                                <span className="sm:hidden">Audit</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('siem')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'siem'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Send className="w-4 h-4" />
                                <span>SIEM</span>
                            </button>
                            <button
                                onClick={() => { setActiveTab('updates'); checkForUpdates(); }}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'updates'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Download className="w-4 h-4" />
                                <span>Updates</span>
                                {updateInfo?.update_available && (
                                    <span className="px-1.5 py-0.5 text-xs bg-green-500 text-white rounded-full">NEW</span>
                                )}
                            </button>
                            <button
                                onClick={() => setActiveTab('about')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'about'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.Info className="w-4 h-4" />
                                <span>{t('about') || 'About'}</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('support')}
                                className={`flex items-center gap-2 ${isCorporate ? 'px-3 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm'} font-medium transition-colors whitespace-nowrap ${
                                    activeTab === 'support'
                                        ? (isCorporate ? 'text-white border-b-2 border-[#49afd9] font-medium' : 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50')
                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                }`}
                            >
                                <Icons.LifeBuoy className="w-4 h-4" />
                                <span>{t('support') || 'Support'}</span>
                            </button>
                        </div>
                        
                        {/* Content - LW: corporate uses corp-vm-modal-body wrapper */}
                        <div className={isCorporate ? 'corp-vm-modal-body' : 'flex-1 overflow-auto p-6'}>
                            {activeTab === 'users' && (
                                <div className="space-y-4">
                                    {/* Add User Button + Folder Management */}
                                    <div className="flex justify-between items-center">
                                        <h3 className="text-lg font-semibold text-white">{t('users')}</h3>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => setShowAddFolder(!showAddFolder)}
                                                className="flex items-center gap-1.5 px-3 py-2 bg-proxmox-card border border-proxmox-border hover:border-gray-500 rounded-lg text-sm text-gray-400 hover:text-white transition-colors"
                                                title="Manage Folders"
                                            >
                                                <Icons.Folder className="w-4 h-4" />
                                                {t('folders') || 'Folders'}
                                            </button>
                                            <button
                                                onClick={() => setShowAddUser(true)}
                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors"
                                            >
                                                <Icons.UserPlus />
                                                {t('addUser')}
                                            </button>
                                        </div>
                                    </div>

                                    {/* Folder Management Panel */}
                                    {showAddFolder && (
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-lg p-4 space-y-3">
                                            <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                                                <Icons.Folder className="w-4 h-4" />
                                                {t('userFolders') || 'User Folders'}
                                            </h4>
                                            <div className="flex gap-2">
                                                <input
                                                    value={newFolderName}
                                                    onChange={e => setNewFolderName(e.target.value)}
                                                    placeholder={t('folderName') || 'New folder name...'}
                                                    className="flex-1 px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-white"
                                                    onKeyDown={e => {
                                                        if (e.key === 'Enter' && newFolderName.trim()) {
                                                            fetch(`${API_URL}/user-folders`, { method: 'POST', credentials: 'include', headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ name: newFolderName.trim() }) })
                                                                .then(r => r.json()).then(d => { if (d.success) { setNewFolderName(''); fetchUsers(); } });
                                                        }
                                                    }}
                                                />
                                                <button
                                                    onClick={() => {
                                                        if (!newFolderName.trim()) return;
                                                        fetch(`${API_URL}/user-folders`, { method: 'POST', credentials: 'include', headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ name: newFolderName.trim() }) })
                                                            .then(r => r.json()).then(d => { if (d.success) { setNewFolderName(''); fetchUsers(); } });
                                                    }}
                                                    className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors"
                                                >{t('add') || 'Add'}</button>
                                            </div>
                                            {userFolders.length > 0 && (
                                                <div className="space-y-1">
                                                    {userFolders.map(f => (
                                                        <div key={f.id} className="flex items-center justify-between px-3 py-2 bg-proxmox-dark rounded-lg">
                                                            <div className="flex items-center gap-2">
                                                                <div className="w-3 h-3 rounded" style={{background: f.color || '#6b7280'}} />
                                                                <span className="text-sm text-gray-300">{f.name}</span>
                                                                <span className="text-xs text-gray-600">{users.filter(u => u.user_folder === f.id).length} users</span>
                                                            </div>
                                                            <button
                                                                onClick={() => {
                                                                    if (!confirm(`Delete folder "${f.name}"?`)) return;
                                                                    fetch(`${API_URL}/user-folders/${f.id}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() })
                                                                        .then(r => r.json()).then(d => { if (d.success) fetchUsers(); });
                                                                }}
                                                                className="text-red-400/60 hover:text-red-400 transition-colors"
                                                            ><Icons.Trash2 className="w-3.5 h-3.5" /></button>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Folder filter tabs */}
                                    {userFolders.length > 0 && (
                                        <div className="flex gap-1 flex-wrap">
                                            <button
                                                onClick={() => { setUserFilter(''); setUserPage(0); }}
                                                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${!userFilter ? 'bg-proxmox-orange/20 text-proxmox-orange' : 'text-gray-500 hover:text-gray-300'}`}
                                            >{t('all') || 'All'}</button>
                                            <button
                                                onClick={() => { setUserFilter('__none__'); setUserPage(0); }}
                                                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${userFilter === '__none__' ? 'bg-gray-500/20 text-gray-300' : 'text-gray-500 hover:text-gray-300'}`}
                                            >{t('unfiled') || 'Unfiled'}</button>
                                            {userFolders.map(f => (
                                                <button
                                                    key={f.id}
                                                    onClick={() => { setUserFilter(f.id); setUserPage(0); }}
                                                    className={`px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1 ${userFilter === f.id ? 'bg-proxmox-orange/20 text-proxmox-orange' : 'text-gray-500 hover:text-gray-300'}`}
                                                >
                                                    <div className="w-2 h-2 rounded" style={{background: f.color || '#6b7280'}} />
                                                    {f.name}
                                                </button>
                                            ))}
                                        </div>
                                    )}
                                    
                                    {/* Add User Form */}
                                    {showAddUser && (
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <h4 className="text-white font-medium mb-4">{t('addUser')}</h4>
                                            <form onSubmit={handleCreateUser} className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('usernameLabel')}</label>
                                                    <input
                                                        type="text"
                                                        value={newUser.username}
                                                        onChange={e => setNewUser({...newUser, username: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                        required
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('passwordLabel')}</label>
                                                    <input
                                                        type="password"
                                                        value={newUser.password}
                                                        onChange={e => setNewUser({...newUser, password: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                        required
                                                    />
                                                    <p className="text-xs text-gray-500 mt-1">
                                                        {getSettingsPasswordPolicyHint()}
                                                    </p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('displayName')}</label>
                                                    <input
                                                        type="text"
                                                        value={newUser.display_name}
                                                        onChange={e => setNewUser({...newUser, display_name: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('email')}</label>
                                                    <input
                                                        type="email"
                                                        value={newUser.email}
                                                        onChange={e => setNewUser({...newUser, email: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('role')}</label>
                                                    <select
                                                        value={newUser.role}
                                                        onChange={e => {
                                                            const selectedRole = e.target.value;
                                                            // NS: Auto-select tenant when tenant-specific role is chosen
                                                            const roleObj = allRoles.find(r => r.id === selectedRole);
                                                            if (roleObj && roleObj.scope === 'tenant' && roleObj.tenant_id) {
                                                                setNewUser({...newUser, role: selectedRole, tenant_id: roleObj.tenant_id});
                                                            } else {
                                                                setNewUser({...newUser, role: selectedRole});
                                                            }
                                                        }}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    >
                                                        <optgroup label={t('builtinRole') || 'Builtin Roles'}>
                                                            <option value="admin">{t('roleAdmin')}</option>
                                                            <option value="user">{t('roleUser')}</option>
                                                            <option value="viewer">{t('roleViewer')}</option>
                                                        </optgroup>
                                                        {allRoles.filter(r => !r.builtin && r.scope === 'global').length > 0 && (
                                                            <optgroup label={t('customRoles') || 'Custom Roles (Global)'}>
                                                                {allRoles.filter(r => !r.builtin && r.scope === 'global').map(r => (
                                                                    <option key={r.id} value={r.id}>{r.name || r.id}</option>
                                                                ))}
                                                            </optgroup>
                                                        )}
                                                        {/* NS: Show tenant-specific roles grouped by tenant */}
                                                        {tenants.filter(t => t.id !== 'default').map(tenant => {
                                                            const tenantRoles = allRoles.filter(r => !r.builtin && r.scope === 'tenant' && r.tenant_id === tenant.id);
                                                            if (tenantRoles.length === 0) return null;
                                                            return (
                                                                <optgroup key={tenant.id} label={`${tenant.name} Roles`}>
                                                                    {tenantRoles.map(r => (
                                                                        <option key={r.id} value={r.id}>{r.name || r.id}</option>
                                                                    ))}
                                                                </optgroup>
                                                            );
                                                        })}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('tenant') || 'Tenant'}</label>
                                                    <select
                                                        value={newUser.tenant_id || 'default'}
                                                        onChange={e => setNewUser({...newUser, tenant_id: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    >
                                                        {tenants.map(t => (
                                                            <option key={t.id} value={t.id}>{t.name}</option>
                                                        ))}
                                                    </select>
                                                    <p className="text-xs text-gray-500 mt-1">{t('tenantAutoHint') || 'Auto-set when using tenant role'}</p>
                                                </div>
                                                {newUser.role !== 'admin' && (
                                                <div className="flex items-center gap-3 pt-5">
                                                    <label className="flex items-center gap-3 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={newUser.portal_only || false}
                                                            onChange={e => setNewUser({...newUser, portal_only: e.target.checked})}
                                                            className="w-4 h-4 rounded border-proxmox-border bg-proxmox-darker text-proxmox-orange focus:ring-proxmox-orange"
                                                        />
                                                        <span className="text-sm text-gray-300">{t('portalOnly') || 'Portal Only'}</span>
                                                    </label>
                                                    <p className="text-xs text-gray-500">{t('portalOnlyHint') || 'User can only log in via /portal'}</p>
                                                </div>
                                                )}
                                                <div className="flex items-end gap-2">
                                                    <button
                                                        type="submit"
                                                        disabled={loading}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                                                    >
                                                        {t('create')}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => setShowAddUser(false)}
                                                        className="px-4 py-2 bg-proxmox-border hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                                                    >
                                                        {t('cancel')}
                                                    </button>
                                                </div>
                                            </form>
                                        </div>
                                    )}
                                    
                                    {/* Users Table */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                                        <table className="w-full" style={{tableLayout:'fixed'}}>
                                            <thead>
                                                <tr className="border-b border-proxmox-border">
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'12%'}}>{t('usernameLabel')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'12%'}}>{t('displayName')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'26%'}}>{t('role')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'12%'}}>{t('tenant') || 'Tenant'}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'5%'}}>2FA</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'12%'}}>{t('lastLogin')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'6%'}}>{t('status')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'6%'}}>{t('portal') || 'Portal'}</th>
                                                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width:'9%'}}>{t('actions')}</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(() => {
                                                    const filtered = users.filter(u => {
                                                        if (!userFilter) return true;
                                                        if (userFilter === '__none__') return !u.user_folder;
                                                        return u.user_folder === userFilter;
                                                    });
                                                    const totalPages = Math.ceil(filtered.length / usersPerPage);
                                                    // LW: reset page if filter changes and page is out of bounds
                                                    if (userPage >= totalPages && totalPages > 0 && userPage > 0) setUserPage(0);
                                                    return filtered.slice(userPage * usersPerPage, (userPage + 1) * usersPerPage);
                                                })().map(user => (
                                                    <tr key={user.username} className="border-b border-gray-700/50 hover:bg-proxmox-hover">
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <UserAvatar user={user} sizeClass="w-8 h-8" textClass="text-sm" />
                                                                <div>
                                                                    <span className="text-white font-medium truncate block" style={{maxWidth:'min(180px, 15vw)'}} title={user.username}>{user.username}</span>
                                                                    {editingUser === user.username && userFolders.length > 0 ? (
                                                                        <select
                                                                            value={user.user_folder || ''}
                                                                            onChange={e => handleUpdateUser(user.username, { user_folder: e.target.value })}
                                                                            className="block mt-1 text-xs bg-proxmox-dark border border-proxmox-border rounded px-1.5 py-0.5 text-gray-400"
                                                                        >
                                                                            <option value="">— No folder —</option>
                                                                            {userFolders.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                                                                        </select>
                                                                    ) : user.user_folder && userFolders.find(f => f.id === user.user_folder) ? (
                                                                        <span className="block text-xs mt-0.5" style={{color: userFolders.find(f => f.id === user.user_folder)?.color || '#6b7280'}}>
                                                                            {userFolders.find(f => f.id === user.user_folder)?.name}
                                                                        </span>
                                                                    ) : null}
                                                                </div>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3 text-gray-300"><span className="truncate block" style={{maxWidth:'min(160px, 12vw)'}} title={user.display_name}>{user.display_name || '-'}</span></td>
                                                        <td className="px-4 py-3">
                                                            {editingUser === user.username ? (
                                                                <div>
                                                                {/* MK #950 review (UI regression): legacy single-role <select> restored
                                                                    as the PRIMARY-role control. The junction editor below only covers
                                                                    tenant-scoped customs — without this there was no way to promote to
                                                                    admin, demote to viewer, or set a global custom role, and a vanilla
                                                                    install (zero custom roles) rendered an empty role cell. Setting a
                                                                    custom role here moves the scalar primary; per-tenant extras stay in
                                                                    the editor underneath. */}
                                                                <select
                                                                    defaultValue={user.role}
                                                                    disabled={pcBusy}
                                                                    onChange={e => handleUpdateUser(user.username, { role: e.target.value })}
                                                                    className="px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-xs text-white mb-1.5"
                                                                    data-spec010="primary-role-select"
                                                                >
                                                                    {['admin', 'user', 'viewer'].map(b => (
                                                                        <option key={'b' + b} value={b}>{b === 'admin' ? t('roleAdmin') : b === 'user' ? t('roleUser') : t('roleViewer')}</option>
                                                                    ))}
                                                                    {allRoles.filter(r => !r.builtin && r.scope !== 'tenant').map(r => (
                                                                        <option key={'g' + r.id} value={r.id}>{r.name || r.id}</option>
                                                                    ))}
                                                                    {allRoles.filter(r => !r.builtin && r.scope === 'tenant' && r.tenant_id && (new Set([user.tenant_id || 'default'].concat(userTenants[user.username] || []))).has(r.tenant_id)).map(r => (
                                                                        <option key={'t' + r.id} value={r.id}>{(tenants.find(x => x.id === r.tenant_id) || {}).name || r.tenant_id}: {r.name || r.id}</option>
                                                                    ))}
                                                                </select>
                                                                {/* SPEC-2026-010 P3: additional tenant roles (union model) */}
                                                                {allRoles.filter(r => !r.builtin).length > 0 && (
                                                                    <div className="mt-1.5 space-y-0.5" data-spec010="granted-roles-editor">
                                                                        {(() => {
                                                                            // SPEC-2026-011 P2b (Ray feedback 09-09): flat home-tenant role list.
                                                                            // Tenant column drives scope; embedded tenant/role add-selector REMOVED.
                                                                            // Multi-tenant selection in tenant column = D6/P5 (backend pending).
                                                                            const custom = allRoles.filter(r => !r.builtin && r.scope === 'tenant' && r.tenant_id);
                                                                            // SPEC-2026-011 P5: role cell scope = tenant column's home UNION memberships
                                                                            const effTenants = new Set([user.tenant_id || 'default'].concat(userTenants[user.username] || []));
                                                                            const home = custom.filter(r => effTenants.has(r.tenant_id));
                                                                            const other = custom.filter(r => !effTenants.has(r.tenant_id) && ((grantedRoles[user.username] || []).includes(r.id) || user.role === r.id));
                                                                            const eff = (grantedRoles[user.username] || []).concat(custom.some(r => r.id === user.role) ? [user.role] : []);
                                                                            const tName = tid => (tenants.find(x => x.id === tid) || {}).name || tid;
                                                                            const doRevoke = (r, isScalar) => {
                                                                                const revoke = () => {
                                                                                    setPcBusy(true);
                                                                                    fetch(`${API_URL}/users/${user.username}/roles`, {
                                                                                        method: 'DELETE', credentials: 'include',
                                                                                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                        body: JSON.stringify({ role: r.id })
                                                                                    }).then(resp => {
                                                                                        if (resp && resp.ok) {
                                                                                            setGrantedRoles(p => ({ ...p, [user.username]: (p[user.username] || []).filter(x => x !== r.id) }));
                                                                                            addToast(t('roleRevoked'), 'success');
                                                                                            if (isScalar) {
                                                                                                const remaining = (grantedRoles[user.username] || []).filter(x => x !== r.id);
                                                                                                const customRemaining = remaining.map(x => allRoles.find(ar => ar.id === x && !ar.builtin)).filter(Boolean)
                                                                                                    .sort((a, b) => (a.granted_at || '').localeCompare(b.granted_at || '') || a.id.localeCompare(b.id));
                                                                                                const nxt = customRemaining[0];
                                                                                                const upd = nxt && nxt.scope === 'tenant' && nxt.tenant_id ? { role: nxt.id, tenant_id: nxt.tenant_id } : { role: (nxt && nxt.id) || 'viewer' };
                                                                                                fetch(`${API_URL}/users/${user.username}`, {
                                                                                                    method: 'PUT', credentials: 'include',
                                                                                                    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                                    body: JSON.stringify(upd)
                                                                                                }).then(resp2 => {
                                                                                                    if (resp2 && resp2.ok) { fetchUsers(); }
                                                                                                    else { addToast(t('roleSyncFailed'), 'error'); }
                                                                                                }).catch(() => addToast(t('roleSyncFailed'), 'error'));
                                                                                            }
                                                                                        } else {
                                                                                            resp.json().then(d => addToast(d.error || t('rolesUpdateError'), 'error')).catch(() => addToast(t('rolesUpdateError'), 'error'));
                                                                                        }
                                                                                    }).catch(() => addToast(t('rolesUpdateError'), 'error')).finally(() => setPcBusy(false));
                                                                                };
                                                                                if (isScalar && (grantedRoles[user.username] || []).length === 0) {
                                                                                    if (!confirm(t('lastRoleFallbackConfirm'))) return;
                                                                                }
                                                                                revoke();
                                                                            };
                                                                            const doGrant = r => {
                                                                                if ((grantedRoles[user.username] || []).includes(r.id) || user.role === r.id) return;
                                                                                setPcBusy(true);
                                                                                fetch(`${API_URL}/users/${user.username}/roles`, {
                                                                                    method: 'PUT', credentials: 'include',
                                                                                    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                    body: JSON.stringify({ role: r.id })
                                                                                }).then(resp => {
                                                                                    if (resp && resp.ok) {
                                                                                        setGrantedRoles(p => ({ ...p, [user.username]: [...(p[user.username] || []), r.id] }));
                                                                                        addToast(t('roleGranted'), 'success');
                                                                                    } else {
                                                                                        resp.json().then(d => addToast(d.error || t('rolesUpdateError'), 'error')).catch(() => addToast(t('rolesUpdateError'), 'error'));
                                                                                    }
                                                                                }).catch(() => addToast(t('rolesUpdateError'), 'error')).finally(() => setPcBusy(false));
                                                                            };
                                                                            return (
                                                                                <div data-spec011="picker-home">
                                                                                    {home.map(r => {
                                                                                        const isScalar = user.role === r.id;
                                                                                        const isGranted = eff.includes(r.id);
                                                                                        return (
                                                                                            <div key={'g' + r.id} className="flex items-center gap-1.5 text-xs text-gray-300">
                                                                                                <span className="truncate" title={r.id}>{r.name || r.id}</span>
                                                                                                {isScalar && <span className="px-1 rounded bg-blue-500/10 text-blue-400 text-[10px] shrink-0">{t('primaryRoleBadge')}</span>}
                                                                                                {isGranted && !isScalar ? (
                                                                                                    <button type="button" disabled={pcBusy} className="ml-auto px-1.5 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-40 shrink-0" onClick={() => doRevoke(r, isScalar)}>×</button>
                                                                                                ) : !isScalar ? (
                                                                                                    <button type="button" disabled={pcBusy} className="ml-auto px-1.5 rounded text-green-400 hover:bg-green-500/10 disabled:opacity-40 shrink-0" onClick={() => doGrant(r)}>+</button>
                                                                                                ) : null}
                                                                                            </div>
                                                                                        );
                                                                                    })}
                                                                                    {other.length > 0 && (
                                                                                        <div className="mt-1 pt-1 border-t border-gray-700/50" data-spec011="picker-other">
                                                                                            <div className="text-[10px] text-gray-500">{t('grantsOtherTenants')}</div>
                                                                                            {other.map(r => {
                                                                                                const isScalar = user.role === r.id;
                                                                                                return (
                                                                                                    <div key={'go' + r.id} className="flex items-center gap-1.5 text-xs text-gray-500">
                                                                                                        <span className="truncate">{tName(r.tenant_id)}: {r.name || r.id}</span>
                                                                                                        {isScalar && <span className="px-1 rounded bg-blue-500/10 text-blue-400/70 text-[10px] shrink-0">{t('primaryRoleBadge')}</span>}
                                                                                                        {!isScalar && <button type="button" disabled={pcBusy} className="ml-auto px-1.5 rounded text-red-400/70 hover:bg-red-500/10 disabled:opacity-40 shrink-0" onClick={() => doRevoke(r, isScalar)}>×</button>}
                                                                                                    </div>
                                                                                                );
                                                                                            })}
                                                                                        </div>
                                                                                    )}
                                                                                    {home.length === 0 && other.length === 0 && (
                                                                                        <div className="text-xs text-gray-500">{t('noTenantRolesForUser')}</div>
                                                                                    )}
                                                                                </div>
                                                                            );
                                                                        })()}
                                                                    </div>
                                                                )}
                                                                </div>
                                                            ) : (
                                                                /* LW Sep 2026 (#795) - these were bare inline siblings, so a custom role id
                                                                   long enough to fill the 10% column pushed the source badge into a mid-word
                                                                   break and it read as if it belonged to the tenant next door. */
                                                                <div className="flex flex-wrap items-center gap-1">
                                                                <span className={`px-2 py-1 rounded text-xs font-medium whitespace-nowrap ${
                                                                    user.role === 'admin' ? 'bg-red-500/10 text-red-400' :
                                                                    user.role === 'user' ? 'bg-blue-500/10 text-blue-400' :
                                                                    user.role === 'viewer' ? 'bg-gray-500/10 text-gray-400' :
                                                                    'bg-purple-500/10 text-purple-400'
                                                                }`}>
                                                                    {user.role === 'admin' ? t('roleAdmin') : 
                                                                     user.role === 'user' ? t('roleUser') : 
                                                                     user.role === 'viewer' ? t('roleViewer') :
                                                                     user.role}
                                                                </span>
                                                                {user.auth_source === 'ldap' && (
                                                                    <span className="px-1.5 py-0.5 rounded text-xs whitespace-nowrap bg-blue-500/10 text-blue-400 border border-blue-500/20">LDAP</span>
                                                                )}
                                                                {user.auth_source === 'entra' && (
                                                                    <span className="px-1.5 py-0.5 rounded text-xs whitespace-nowrap bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Entra ID</span>
                                                                )}
                                                                {user.auth_source === 'oidc' && (
                                                                    <span className="px-1.5 py-0.5 rounded text-xs whitespace-nowrap bg-purple-500/10 text-purple-400 border border-purple-500/20">OIDC</span>
                                                                )}
                                                                {/* SPEC-2026-011 P2 (D2): tenant-grouped chips — tenant badge + union chips */}
                                                                {(() => {
                                                                    const extras = (grantedRoles[user.username] || []).filter(rid => rid !== user.role);
                                                                    const uRole = allRoles.find(r => r.id === user.role);
                                                                    const byT = {};
                                                                    if (extras.length === 0 && !(uRole && uRole.scope === 'tenant' && uRole.tenant_id)) return null;
                                                                    if (uRole && uRole.scope === 'tenant' && uRole.tenant_id) byT[uRole.tenant_id] = [];
                                                                    extras.forEach(rid => {
                                                                        const ro = allRoles.find(r => r.id === rid);
                                                                        const tid = (ro && ro.tenant_id) || '?';
                                                                        (byT[tid] = byT[tid] || []).push(rid);
                                                                    });
                                                                    return Object.keys(byT).map(tid => (
                                                                        <span key={'tg' + tid} className="inline-flex items-center gap-0.5">
                                                                            <span className="px-1 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{(tenants.find(x => x.id === tid) || {}).name || tid}</span>
                                                                            {(tid === (uRole && uRole.tenant_id) ? [user.role] : []).concat(byT[tid]).map(rid => (
                                                                                <span key={'x' + tid + rid} className="px-1.5 py-0.5 rounded text-xs bg-purple-500/10 text-purple-400" data-spec011="role-chip">{rid}</span>
                                                                            ))}
                                                                        </span>
                                                                    ));
                                                                })()}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3 text-gray-400 text-sm">
                                                            {/* NS: Show tenant name - editable when in edit mode */}
                                                            {editingUser === user.username ? (
                                                                <select
                                                                    defaultValue={user.tenant_id || 'default'}
                                                                    onChange={e => handleUpdateUser(user.username, { tenant_id: e.target.value })}
                                                                    className="px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                                                >
                                                                    {tenants.map(t => (
                                                                        <option key={t.id} value={t.id}>{t.name}</option>
                                                                    ))}
                                                                </select>
                                                            ) : (
                                                                <div className="flex flex-wrap items-center gap-1" data-spec011="tenant-multi">
                                                                    <span className="px-2 py-1 rounded text-xs bg-cyan-500/10 text-cyan-400" title={t('membershipHomeTitle')}>
                                                                        {tenants.find(t => t.id === user.tenant_id)?.name || user.tenant_id || 'Default'}
                                                                    </span>
                                                                    {(userTenants[user.username] || []).filter(tid => tid !== user.tenant_id).map(tid => (
                                                                        <span key={'mt' + tid} className="inline-flex items-center gap-0.5 px-1.5 py-1 rounded text-xs bg-cyan-500/10 text-cyan-400">
                                                                            {tenants.find(t => t.id === tid)?.name || tid}
                                                                            <button type="button" className="text-cyan-400/70 hover:text-red-400 ml-0.5" title={t('membershipRemoveTitle')}
                                                                                onClick={() => {
                                                                                    fetch(`${API_URL}/users/${user.username}/tenants`, {
                                                                                        method: 'DELETE', credentials: 'include',
                                                                                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                        body: JSON.stringify({ tenant_id: tid })
                                                                                    }).then(resp => {
                                                                                        if (resp && resp.ok) {
                                                                                            setUserTenants(p => ({ ...p, [user.username]: (p[user.username] || []).filter(x => x !== tid) }));
                                                                                            addToast(t('tenantRemoved') || 'Tenant removed', 'success');
                                                                                            fetchUsers();
                                                                                        } else {
                                                                                            resp.json().then(d => addToast(d.error || t('tenantRemoveError'), 'error')).catch(() => addToast(t('tenantRemoveError'), 'error'));
                                                                                        }
                                                                                    }).catch(() => addToast(t('tenantRemoveError'), 'error'));
                                                                                }}>×</button>
                                                                        </span>
                                                                    ))}
                                                                    <select className="px-1 py-0.5 rounded text-xs bg-proxmox-darker border border-proxmox-border text-gray-300" value="" title={t('membershipAddTitle')}
                                                                        onChange={e => {
                                                                            const tid = e.target.value;
                                                                            if (!tid) return;
                                                                            e.target.value = '';
                                                                            fetch(`${API_URL}/users/${user.username}/tenants`, {
                                                                                method: 'PUT', credentials: 'include',
                                                                                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                body: JSON.stringify({ tenant_id: tid })
                                                                            }).then(resp => {
                                                                                if (resp && resp.ok) {
                                                                                    setUserTenants(p => ({ ...p, [user.username]: [...(p[user.username] || []), tid] }));
                                                                                    addToast(t('tenantAdded') || 'Tenant added', 'success');
                                                                                    fetchUsers();
                                                                                } else {
                                                                                    resp.json().then(d => addToast(d.error || t('tenantAddError'), 'error')).catch(() => addToast(t('tenantAddError'), 'error'));
                                                                                }
                                                                            }).catch(() => addToast(t('tenantAddError'), 'error'));
                                                                        }}>
                                                                        <option value="">{t('tenantAddPrompt')}</option>
                                                                        {tenants.filter(t => t.id !== user.tenant_id && !(userTenants[user.username] || []).includes(t.id)).map(t => (
                                                                            <option key={'at' + t.id} value={t.id}>{t.name || t.id}</option>
                                                                        ))}
                                                                    </select>
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                                                                user.totp_enabled ? 'bg-green-500/10 text-green-400' : 'bg-gray-500/10 text-gray-500'
                                                            }`}>
                                                                {user.totp_enabled ? '✓ 2FA' : '-'}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3 text-gray-400 text-sm">
                                                            {user.last_login ? new Date(user.last_login).toLocaleString() : t('never')}
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                                                                user.enabled ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
                                                            }`}>
                                                                {user.enabled ? t('enabled') : t('disabled')}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            {editingUser === user.username && user.role !== 'admin' ? (
                                                                <button
                                                                    onClick={() => handleUpdateUser(user.username, { portal_only: !user.portal_only })}
                                                                    className={`px-2 py-1 rounded text-xs font-medium cursor-pointer transition-colors ${
                                                                        user.portal_only ? 'bg-orange-500/10 text-orange-400 hover:bg-orange-500/20' : 'bg-gray-500/10 text-gray-500 hover:bg-gray-500/20'
                                                                    }`}
                                                                >
                                                                    {user.portal_only ? (t('portalOnly') || 'Portal') : '-'}
                                                                </button>
                                                            ) : (
                                                                <span className={`px-2 py-1 rounded text-xs font-medium ${
                                                                    user.portal_only ? 'bg-orange-500/10 text-orange-400' : 'text-gray-500'
                                                                }`}>
                                                                    {user.portal_only ? (t('portalOnly') || 'Portal') : '-'}
                                                                </span>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3 text-right">
                                                            <div className="flex items-center justify-end gap-1">
                                                                {/* Password Reset */}
                                                                {passwordResetUser === user.username ? (
                                                                    <div className="flex items-center gap-1">
                                                                        <input
                                                                            type="password"
                                                                            value={newPasswordValue}
                                                                            onChange={e => setNewPasswordValue(e.target.value)}
                                                                            placeholder={t('newPassword')}
                                                                            title={getSettingsPasswordPolicyHint()}
                                                                            className="w-24 px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                                                        />
                                                                        <button
                                                                            onClick={() => handleResetPassword(user.username)}
                                                                            className="p-1.5 rounded bg-green-500/20 text-green-400 hover:bg-green-500/30"
                                                                            title="Save"
                                                                        >
                                                                            <Icons.Check />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => { setPasswordResetUser(null); setNewPasswordValue(''); }}
                                                                            className="p-1.5 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30"
                                                                            title="Cancel"
                                                                        >
                                                                            <Icons.X />
                                                                        </button>
                                                                    </div>
                                                                ) : (
                                                                    <>
                                                                        <button
                                                                            onClick={() => setPasswordResetUser(user.username)}
                                                                            className="p-1.5 rounded hover:bg-proxmox-border text-gray-400 hover:text-yellow-400"
                                                                            title={t('resetPassword')}
                                                                        >
                                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                                                            </svg>
                                                                        </button>
                                                                        {user.totp_enabled && (
                                                                            <button
                                                                                onClick={() => handleDisable2FA(user.username)}
                                                                                className="p-1.5 rounded hover:bg-proxmox-border text-gray-400 hover:text-orange-400"
                                                                                title={t('disable2FA')}
                                                                            >
                                                                                <Icons.Shield />
                                                                            </button>
                                                                        )}
                                                                        <button
                                                                            onClick={() => setEditingUser(editingUser === user.username ? null : user.username)}
                                                                            className="p-1.5 rounded hover:bg-proxmox-border text-gray-400 hover:text-white"
                                                                            title={t('editUser')}
                                                                        >
                                                                            <Icons.Edit />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => handleUpdateUser(user.username, { enabled: !user.enabled })}
                                                                            className={`p-1.5 rounded hover:bg-proxmox-border ${user.enabled ? 'text-green-400' : 'text-red-400'}`}
                                                                            title={user.enabled ? t('disable') : t('enable')}
                                                                        >
                                                                            {user.enabled ? <Icons.Check /> : <Icons.X />}
                                                                        </button>
                                                                        {user.username !== currentUser?.username && (
                                                                            <button
                                                                                onClick={() => handleDeleteUser(user.username)}
                                                                                className="p-1.5 rounded hover:bg-red-500/10 text-gray-400 hover:text-red-400"
                                                                                title={t('deleteUser')}
                                                                            >
                                                                                <Icons.Trash />
                                                                            </button>
                                                                        )}
                                                                    </>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>

                                        {/* LW: pagination */}
                                        {(() => {
                                            const filtered = users.filter(u => {
                                                if (!userFilter) return true;
                                                if (userFilter === '__none__') return !u.user_folder;
                                                return u.user_folder === userFilter;
                                            });
                                            const totalPages = Math.ceil(filtered.length / usersPerPage);
                                            if (totalPages <= 1) return null;
                                            return (
                                                <div className="flex items-center justify-between px-4 py-3 border-t border-proxmox-border">
                                                    <span className="text-xs text-gray-500">
                                                        {t('showingUsers') || 'Showing'} {userPage * usersPerPage + 1}–{Math.min((userPage + 1) * usersPerPage, filtered.length)} {t('of') || 'of'} {filtered.length}
                                                    </span>
                                                    <div className="flex gap-1">
                                                        <button
                                                            onClick={() => setUserPage(Math.max(0, userPage - 1))}
                                                            disabled={userPage === 0}
                                                            className="px-2.5 py-1 rounded text-xs border border-proxmox-border text-gray-400 hover:text-white hover:border-gray-500 disabled:opacity-30 disabled:cursor-not-allowed"
                                                        >←</button>
                                                        {Array.from({length: totalPages}, (_, i) => (
                                                            <button
                                                                key={i}
                                                                onClick={() => setUserPage(i)}
                                                                className={`px-2.5 py-1 rounded text-xs border ${i === userPage ? 'bg-proxmox-orange/20 border-proxmox-orange text-proxmox-orange' : 'border-proxmox-border text-gray-400 hover:text-white hover:border-gray-500'}`}
                                                            >{i + 1}</button>
                                                        ))}
                                                        <button
                                                            onClick={() => setUserPage(Math.min(totalPages - 1, userPage + 1))}
                                                            disabled={userPage >= totalPages - 1}
                                                            className="px-2.5 py-1 rounded text-xs border border-proxmox-border text-gray-400 hover:text-white hover:border-gray-500 disabled:opacity-30 disabled:cursor-not-allowed"
                                                        >→</button>
                                                    </div>
                                                </div>
                                            );
                                        })()}
                                    </div>
                                </div>
                            )}

                            {/* Tenants Tab */}
                            {/* This whole section was added after Reddit feedback */}
                            {/* MSPs really wanted separate customer views */}
                            {activeTab === 'tenants' && (
                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <h3 className="text-lg font-semibold text-white">{t('tenants') || 'Tenants'}</h3>
                                        <button
                                            onClick={() => setShowAddTenant(true)}
                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors"
                                        >
                                            <Icons.Plus />
                                            {t('addTenant') || 'Add Tenant'}
                                        </button>
                                    </div>
                                    
                                    <p className="text-sm text-gray-400">
                                        {t('tenantsDesc') || 'Tenants allow you to separate users and restrict access to specific clusters.'}
                                    </p>
                                    
                                    {/* Add tenant form */}
                                    {showAddTenant && (
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <h4 className="text-white font-medium mb-4">{t('addTenant') || 'Add Tenant'}</h4>
                                            <div className="space-y-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Name</label>
                                                    <input
                                                        type="text"
                                                        value={newTenant.name}
                                                        onChange={e => setNewTenant({...newTenant, name: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        placeholder="Company Name"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('clusters') || 'Clusters'}</label>
                                                    <p className="text-xs text-gray-500 mb-2">Select clusters this tenant can access (empty = none)</p>
                                                    <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                                                        {clusters.map(c => (
                                                            <label key={c.id} className="flex items-center gap-2 p-2 bg-proxmox-darker rounded cursor-pointer hover:bg-proxmox-hover">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={newTenant.clusters.includes(c.id)}
                                                                    onChange={e => {
                                                                        if(e.target.checked) {
                                                                            setNewTenant({...newTenant, clusters: [...newTenant.clusters, c.id]});
                                                                        } else {
                                                                            setNewTenant({...newTenant, clusters: newTenant.clusters.filter(x => x !== c.id)});
                                                                        }
                                                                    }}
                                                                    className="rounded"
                                                                />
                                                                <span className="text-sm text-white">{clusterLabel(c)}</span>
                                                            </label>
                                                        ))}
                                                    </div>
                                                </div>
                                                <div className="flex gap-2">
                                                    <button
                                                        onClick={async () => {
                                                            try {
                                                                const r = await fetch(`${API_URL}/tenants`, {
                                                                    method: 'POST',
                                                                    credentials: 'include',
                                                                    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                    body: JSON.stringify(newTenant)
                                                                });
                                                                if(r.ok) {
                                                                    addToast('Tenant created', 'success');
                                                                    setShowAddTenant(false);
                                                                    setNewTenant({ name: '', clusters: [] });
                                                                    fetchTenants();
                                                                } else {
                                                                    const err = await r.json();
                                                                    addToast(err.error || 'Error', 'error');
                                                                }
                                                            } catch(e) { addToast('Error', 'error'); }
                                                        }}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                                    >
                                                        {t('create') || 'Create'}
                                                    </button>
                                                    <button
                                                        onClick={() => { setShowAddTenant(false); setNewTenant({ name: '', clusters: [] }); }}
                                                        className="px-4 py-2 bg-proxmox-dark border border-proxmox-border hover:bg-proxmox-hover rounded-lg text-sm text-gray-300"
                                                    >
                                                        {t('cancel')}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Tenants list */}
                                    {/* NS Sep 2026 — which tenant this account is acting in, and which others it has
                                        been delegated into. Only rendered when there is more than one, which is the
                                        only case where it tells anyone anything. Display only. */}
                                    {(myTenants.tenants || []).length > 1 && (
                                        <div className="mb-3 px-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-xs text-gray-400 flex items-center gap-2 flex-wrap">
                                            <Icons.Building className="w-3.5 h-3.5 flex-shrink-0" />
                                            <span>{t('actingInTenant') || 'Acting in'}:</span>
                                            {(myTenants.tenants || []).map(mt => (
                                                <span key={mt.id}
                                                    className={`px-2 py-0.5 rounded whitespace-nowrap ${mt.is_home
                                                        ? 'bg-proxmox-orange/20 text-proxmox-orange'
                                                        : 'bg-proxmox-darker text-gray-400'}`}
                                                    title={`${mt.id} — ${mt.effective_role}`}>
                                                    {mt.name}{mt.is_home ? '' : ` (${mt.effective_role})`}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                                        <table className="w-full">
                                            <thead>
                                                <tr className="border-b border-proxmox-border bg-proxmox-darker">
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Name</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('clusters')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('users')}</th>
                                                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">{t('actions')}</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-proxmox-border">
                                                {tenants.map(tenant => (
                                                    <tr key={tenant.id} className="hover:bg-proxmox-hover/50">
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <Icons.Building className="w-4 h-4 text-gray-400" />
                                                                <span className="text-white font-medium">{tenant.name}</span>
                                                                {tenant.id === 'default' && (
                                                                    <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded">Default</span>
                                                                )}
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3 text-sm text-gray-400">
                                                            {tenant.clusters.length === 0 ? 'All clusters' : tenant.clusters.length + ' clusters'}
                                                            {(tenant.quota_max_vms > 0 || tenant.quota_max_cores > 0 || tenant.quota_max_memory_gb > 0 || tenant.quota_max_disk_gb > 0) && (
                                                                <div className="text-xs text-gray-600 mt-0.5">
                                                                    {t('quota') || 'Quota'}: {tenant.quota_max_vms > 0 ? `${tenant.quota_max_vms} VMs ` : ''}{tenant.quota_max_cores > 0 ? `${tenant.quota_max_cores}c ` : ''}{tenant.quota_max_memory_gb > 0 ? `${tenant.quota_max_memory_gb}GB RAM ` : ''}{tenant.quota_max_disk_gb > 0 ? `${tenant.quota_max_disk_gb}GB disk` : ''}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-4 py-3 text-sm text-gray-400">{tenant.user_count || 0}</td>
                                                        <td className="px-4 py-3 text-right">
                                                            <div className="flex items-center justify-end gap-2">
                                                                <button
                                                                    onClick={async () => {
                                                                        setChargebackTenant(tenant);  // NS #502b — open chargeback
                                                                        setChargeback(null);
                                                                        try {
                                                                            const r = await fetch(`${API_URL}/tenants/${tenant.id}/chargeback?days=30`, { credentials: 'include', headers: getAuthHeaders() });
                                                                            if (r.ok) setChargeback(await r.json());
                                                                        } catch (e) { /* best-effort */ }
                                                                    }}
                                                                    className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-border rounded"
                                                                    title={t('chargeback') || 'Chargeback'}
                                                                >
                                                                    <Icons.DollarSign className="w-4 h-4" />
                                                                </button>
                                                                <button
                                                                    onClick={async () => {
                                                                        setEditingTenant({...tenant});
                                                                        setTenantUsage(null);  // NS #502 — load live usage
                                                                        try {
                                                                            const r = await fetch(`${API_URL}/tenants/${tenant.id}/quota`, { credentials: 'include', headers: getAuthHeaders() });
                                                                            if (r.ok) setTenantUsage(await r.json());
                                                                        } catch (e) { /* usage is best-effort */ }
                                                                    }}
                                                                    className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-border rounded"
                                                                    title={t('edit') || 'Edit'}
                                                                >
                                                                    <Icons.Edit className="w-4 h-4" />
                                                                </button>
                                                                {tenant.id !== 'default' && (
                                                                    <button
                                                                        onClick={async () => {
                                                                            if(!confirm(`Delete tenant "${tenant.name}"?`)) return;
                                                                            try {
                                                                                const r = await fetch(`${API_URL}/tenants/${tenant.id}`, {
                                                                                    method: 'DELETE',
                                                                                    credentials: 'include',
                                                                                    headers: getAuthHeaders()
                                                                                });
                                                                                if(r.ok) {
                                                                                    addToast('Tenant deleted', 'success');
                                                                                    fetchTenants();
                                                                                } else {
                                                                                    const err = await r.json();
                                                                                    addToast(err.error || 'Error', 'error');
                                                                                }
                                                                            } catch(e) {}
                                                                        }}
                                                                        className="p-1.5 text-red-400 hover:bg-red-500/20 rounded"
                                                                    >
                                                                        <Icons.Trash className="w-4 h-4" />
                                                                    </button>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                    
                                    {/* Edit Tenant Modal - NS: Dec 2025 */}
                                    {/* MK: Modal layout generated with Claude, tweaked the styling */}
                                    {editingTenant && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-lg">
                                                <h3 className="text-lg font-semibold text-white mb-4">
                                                    {t('editTenant') || 'Edit Tenant'}: {editingTenant.name}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Name</label>
                                                        <input
                                                            type="text"
                                                            value={editingTenant.name}
                                                            onChange={e => setEditingTenant({...editingTenant, name: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('clusters') || 'Clusters'}</label>
                                                        <p className="text-xs text-gray-500 mb-2">{t('tenantClustersHint') || 'Select which clusters this tenant can access (empty = none)'}</p>
                                                        <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto bg-proxmox-dark rounded-lg p-3">
                                                            {clusters.map(c => (
                                                                <label key={c.id} className="flex items-center gap-2 p-2 hover:bg-proxmox-hover rounded cursor-pointer">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={editingTenant.clusters?.includes(c.id)}
                                                                        onChange={e => {
                                                                            if(e.target.checked) {
                                                                                setEditingTenant({...editingTenant, clusters: [...(editingTenant.clusters || []), c.id]});
                                                                            } else {
                                                                                setEditingTenant({...editingTenant, clusters: (editingTenant.clusters || []).filter(x => x !== c.id)});
                                                                            }
                                                                        }}
                                                                        className="rounded border-gray-600"
                                                                    />
                                                                    <span className="text-sm text-white">{clusterLabel(c)}</span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    </div>
                                                    {/* NS #502 — resource quotas (0 = unlimited) */}
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('quotas') || 'Resource Quotas'} <span className="text-xs text-gray-600">({t('quotaZeroHint') || '0 = unlimited'})</span></label>
                                                        {tenantUsage && tenantUsage.usage && tenantUsage.usage.vms !== undefined && (
                                                            <p className="text-xs text-gray-500 mb-2">{t('currentUsage') || 'Current usage'}: {tenantUsage.usage.vms} VMs · {tenantUsage.usage.cores} {t('cores') || 'cores'} · {tenantUsage.usage.memory_gb} GB</p>
                                                        )}
                                                        <div className="grid grid-cols-3 gap-2">
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('maxVms') || 'Max VMs'}</label>
                                                                <input type="number" min="0" value={editingTenant.quota_max_vms || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, quota_max_vms: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('maxCores') || 'Max Cores'}</label>
                                                                <input type="number" min="0" value={editingTenant.quota_max_cores || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, quota_max_cores: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('maxMemoryGb') || 'Max RAM (GB)'}</label>
                                                                <input type="number" min="0" value={editingTenant.quota_max_memory_gb || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, quota_max_memory_gb: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('maxDiskGb') || 'Max Disk (GB)'}</label>
                                                                <input type="number" min="0" value={editingTenant.quota_max_disk_gb || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, quota_max_disk_gb: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                        </div>
                                                        {/* NS Sep 2026 — VMID slice. 0/0 leaves numbering to the cluster, which is
                                                            what every install does until it has more than one customer on a node. */}
                                                        <div className="grid grid-cols-2 gap-3 mt-2">
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('vmidRangeStart') || 'VMID from'}</label>
                                                                <input type="number" min="0" placeholder="0 = any" value={editingTenant.vmid_range_start || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, vmid_range_start: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-500 mb-1">{t('vmidRangeEnd') || 'VMID to'}</label>
                                                                <input type="number" min="0" placeholder="0 = any" value={editingTenant.vmid_range_end || 0}
                                                                    onChange={e => setEditingTenant({...editingTenant, vmid_range_end: parseInt(e.target.value) || 0})}
                                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                            </div>
                                                        </div>
                                                        <div className="mt-2">
                                                            <label className="block text-xs text-gray-500 mb-1">{t('quotaEnforcement') || 'When exceeded'}</label>
                                                            <select value={editingTenant.quota_enforcement || 'block'}
                                                                onChange={e => setEditingTenant({...editingTenant, quota_enforcement: e.target.value})}
                                                                className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                                <option value="block">{t('quotaBlock') || 'Block new VMs'}</option>
                                                                <option value="warn">{t('quotaWarn') || 'Warn only (allow)'}</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                </div>

                                                <div className="flex gap-2 mt-6">
                                                    <button
                                                        onClick={async () => {
                                                            try {
                                                                const r = await fetch(`${API_URL}/tenants/${editingTenant.id}`, {
                                                                    method: 'PUT',
                                                                    credentials: 'include',
                                                                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify({
                                                                        name: editingTenant.name,
                                                                        clusters: editingTenant.clusters || [],
                                                                        quota_max_vms: editingTenant.quota_max_vms || 0,
                                                                        quota_max_cores: editingTenant.quota_max_cores || 0,
                                                                        quota_max_memory_gb: editingTenant.quota_max_memory_gb || 0,
                                                                        quota_max_disk_gb: editingTenant.quota_max_disk_gb || 0,
                                                                        quota_enforcement: editingTenant.quota_enforcement || 'block',
                                                                        vmid_range_start: editingTenant.vmid_range_start || 0,
                                                                        vmid_range_end: editingTenant.vmid_range_end || 0
                                                                    })
                                                                });
                                                                if(r.ok) {
                                                                    addToast(t('tenantSaved') || 'Tenant saved', 'success');
                                                                    setEditingTenant(null);
                                                                    fetchTenants();
                                                                } else {
                                                                    const err = await r.json();
                                                                    addToast(err.error || 'Error', 'error');
                                                                }
                                                            } catch(e) { addToast('Error', 'error'); }
                                                        }}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                                    >
                                                        {t('save') || 'Save'}
                                                    </button>
                                                    <button
                                                        onClick={() => setEditingTenant(null)}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    {/* NS #502b — chargeback statement modal */}
                                    {chargebackTenant && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setChargebackTenant(null)}>
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-2xl max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                                                <div className="flex justify-between items-start mb-4">
                                                    <div>
                                                        <h3 className="text-lg font-semibold text-white">{t('chargeback') || 'Chargeback'}: {chargebackTenant.name}</h3>
                                                        {chargeback && (
                                                            <p className="text-sm text-gray-400">{t('monthlyEstimate') || 'Monthly estimate'}: <span className="text-proxmox-orange font-semibold">{chargeback.monthly_total} {chargeback.currency}</span> <span className="text-xs text-gray-600">({t('basedOnLast') || 'based on last'} {chargeback.days}d)</span></p>
                                                        )}
                                                    </div>
                                                    <button onClick={() => setChargebackTenant(null)} className="p-1 text-gray-400 hover:text-white"><Icons.X className="w-5 h-5" /></button>
                                                </div>
                                                {!chargeback ? (
                                                    <p className="text-sm text-gray-500 py-6 text-center">{t('loading') || 'Loading...'}</p>
                                                ) : (
                                                    <div className="space-y-4">
                                                        <div className="space-y-1">
                                                            {(chargeback.by_cluster || []).map(c => (
                                                                <div key={c.cluster_id} className="flex justify-between text-sm bg-proxmox-dark rounded px-3 py-2">
                                                                    <span className="text-gray-300">{c.cluster_name} <span className="text-xs text-gray-500">({c.vm_count} VMs{c.enough_data ? '' : ' · ' + (t('noData') || 'no data')})</span></span>
                                                                    <span className="text-gray-200">{c.monthly_subtotal} {chargeback.currency}/mo</span>
                                                                </div>
                                                            ))}
                                                            {(chargeback.by_cluster || []).length === 0 && <p className="text-sm text-gray-500">{t('noClustersForTenant') || 'No clusters assigned to this tenant.'}</p>}
                                                        </div>
                                                        {(chargeback.rows || []).length > 0 && (
                                                            <div>
                                                                <div className="text-xs text-gray-500 uppercase mb-1">{t('topVmsByCost') || 'Top VMs by cost'}</div>
                                                                <table className="w-full text-sm">
                                                                    <tbody className="divide-y divide-proxmox-border">
                                                                        {(chargeback.rows || []).slice(0, 10).map(r => (
                                                                            <tr key={r.cluster_id + ':' + r.vmid}>
                                                                                <td className="py-1.5 text-gray-300">{r.name || r.vmid} <span className="text-xs text-gray-600">{r.cluster_name}</span></td>
                                                                                <td className="py-1.5 text-right text-gray-400">{r.monthly_total} {chargeback.currency}/mo</td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        )}
                                                        <div className="flex justify-end gap-2 pt-2">
                                                            <a href={`${API_URL}/tenants/${chargebackTenant.id}/chargeback?days=30&format=csv`} target="_blank" rel="noopener" className="px-4 py-2 bg-proxmox-dark border border-proxmox-border hover:bg-proxmox-hover rounded-lg text-sm text-gray-300">{t('downloadCsv') || 'Download CSV'}</a>
                                                            <button onClick={() => setChargebackTenant(null)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">{t('close') || 'Close'}</button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Cluster Groups Tab - NS Jan 2026 */}
                            {activeTab === 'groups' && (
                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <div>
                                            <h3 className="text-lg font-semibold text-white">{t('clusterGroups') || 'Cluster Groups'}</h3>
                                            <p className="text-sm text-gray-400 mt-1">{t('clusterGroupsDesc')}</p>
                                        </div>
                                        <button
                                            onClick={() => setShowAddGroup(true)}
                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                        >
                                            <Icons.Plus className="w-4 h-4" />
                                            {t('addGroup') || 'Add Group'}
                                        </button>
                                    </div>
                                    
                                    {/* Groups List */}
                                    <div className="space-y-3">
                                        {clusterGroups.length === 0 ? (
                                            <div className="text-center py-8 text-gray-500">
                                                <Icons.Folder className="w-12 h-12 mx-auto mb-3 opacity-50" />
                                                <p>{t('noGroupsYet')}</p>
                                                <p className="text-sm mt-1">{t('createGroupFirst')}</p>
                                            </div>
                                        ) : (
                                            clusterGroups.map(group => {
                                                const groupClusters = clusters.filter(c => c.group_id === group.id);
                                                const tenant = tenants.find(t => t.id === group.tenant_id);
                                                return (
                                                    <div key={group.id} className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-3">
                                                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: group.color || '#E86F2D' }} />
                                                                <div>
                                                                    <h4 className="font-medium text-white">{group.name}</h4>
                                                                    {group.description && <p className="text-xs text-gray-500">{group.description}</p>}
                                                                </div>
                                                            </div>
                                                            <div className="flex items-center gap-4">
                                                                {tenant && (
                                                                    <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                                                                        Tenant: {tenant.name}
                                                                    </span>
                                                                )}
                                                                <span className="text-sm text-gray-400">{groupClusters.length} cluster(s)</span>
                                                                <div className="flex items-center gap-1">
                                                                    <button
                                                                        onClick={() => setEditingGroup(group)}
                                                                        className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-hover rounded"
                                                                    >
                                                                        <Icons.Edit className="w-4 h-4" />
                                                                    </button>
                                                                    <button
                                                                        onClick={async () => {
                                                                            if(!confirm(`Delete group "${group.name}"?`)) return;
                                                                            try {
                                                                                const r = await fetch(`${API_URL}/cluster-groups/${group.id}`, {
                                                                                    method: 'DELETE',
                                                                                    credentials: 'include',
                                                                                    headers: getAuthHeaders()
                                                                                });
                                                                                if(r.ok) {
                                                                                    addToast('Group deleted', 'success');
                                                                                    fetchClusterGroups();
                                                                                    onGroupsChanged?.();
                                                                                } else {
                                                                                    const err = await r.json();
                                                                                    addToast(err.error || 'Error', 'error');
                                                                                }
                                                                            } catch(e) {}
                                                                        }}
                                                                        className="p-1.5 text-red-400 hover:bg-red-500/20 rounded"
                                                                    >
                                                                        <Icons.Trash className="w-4 h-4" />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        {/* Clusters in this group */}
                                                        {groupClusters.length > 0 && (
                                                            <div className="mt-3 pt-3 border-t border-proxmox-border">
                                                                <div className="flex flex-wrap gap-2">
                                                                    {groupClusters.map(c => (
                                                                        <span key={c.id} className="px-2 py-1 bg-proxmox-card border border-proxmox-border rounded text-xs text-gray-300">
                                                                            {c.display_name || c.name || c.host}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })
                                        )}
                                    </div>
                                    
                                    {/* All Clusters — rename + group assignment */}
                                    <div className="mt-6">
                                        <h3 className="text-lg font-semibold text-white mb-3">{t('allClusters') || 'All Clusters'}</h3>
                                        <div className="space-y-2">
                                            {clusters.length === 0 ? (
                                                <p className="text-gray-500 text-sm py-4 text-center">{t('noClustersAdded') || 'No clusters added yet'}</p>
                                            ) : clusters.map(c => {
                                                const grp = clusterGroups.find(g => g.id === c.group_id);
                                                return (
                                                    <div key={c.id} className="flex items-center justify-between bg-proxmox-dark border border-proxmox-border rounded-lg px-4 py-3">
                                                        <div className="flex items-center gap-3 min-w-0">
                                                            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${c.enabled !== false ? 'bg-green-500' : 'bg-gray-500'}`} />
                                                            <div className="min-w-0">
                                                                <div className="text-sm font-medium text-white truncate">
                                                                    {c.display_name || c.name || c.host}
                                                                    {c.display_name && c.display_name !== c.name && (
                                                                        <span className="ml-2 text-xs text-gray-500">({c.name})</span>
                                                                    )}
                                                                </div>
                                                                <div className="text-xs text-gray-500 flex items-center gap-2">
                                                                    <span>{c.host}</span>
                                                                    {grp && <span className="px-1.5 py-0.5 rounded text-xs" style={{ backgroundColor: (grp.color || '#E86F2D') + '30', color: grp.color }}>{grp.name}</span>}
                                                                    {c.cluster_type && c.cluster_type !== 'proxmox' && <span className="text-yellow-500">{c.cluster_type.toUpperCase()}</span>}
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <button
                                                            onClick={() => { setRenamingCluster(c); setRenameValue(c.display_name || c.name || ''); }}
                                                            className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-hover rounded flex-shrink-0"
                                                            title={t('renameCluster') || 'Rename cluster'}
                                                        >
                                                            <Icons.Edit className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>

                                    {/* Rename Cluster Modal */}
                                    {renamingCluster && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setRenamingCluster(null)}>
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
                                                <h3 className="text-lg font-semibold mb-1">{t('renameCluster') || 'Rename Cluster'}</h3>
                                                <p className="text-sm text-gray-400 mb-4">{renamingCluster.name} ({renamingCluster.host})</p>
                                                <div className="space-y-3">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('displayName') || 'Display Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={renameValue}
                                                            onChange={e => setRenameValue(e.target.value)}
                                                            onKeyDown={e => { if(e.key === 'Enter' && renameValue.trim()) handleRenameCluster(); }}
                                                            placeholder={renamingCluster.name}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                            autoFocus
                                                        />
                                                        <p className="text-xs text-gray-500 mt-1">{t('renameHint') || 'Leave empty to reset to original name'}</p>
                                                    </div>
                                                </div>
                                                <div className="flex justify-end gap-3 mt-5">
                                                    <button onClick={() => setRenamingCluster(null)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                    <button
                                                        onClick={handleRenameCluster}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                                    >
                                                        {t('rename') || 'Rename'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Add/Edit Group Modal */}
                                    {(showAddGroup || editingGroup) && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md p-6">
                                                <h3 className="text-lg font-semibold mb-4">{editingGroup ? 'Edit Group' : 'Add Cluster Group'}</h3>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Name *</label>
                                                        <input
                                                            type="text"
                                                            value={editingGroup ? editingGroup.name : newGroup.name}
                                                            onChange={e => editingGroup ? setEditingGroup({...editingGroup, name: e.target.value}) : setNewGroup({...newGroup, name: e.target.value})}
                                                            placeholder="Production Clusters"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Description</label>
                                                        <input
                                                            type="text"
                                                            value={editingGroup ? editingGroup.description : newGroup.description}
                                                            onChange={e => editingGroup ? setEditingGroup({...editingGroup, description: e.target.value}) : setNewGroup({...newGroup, description: e.target.value})}
                                                            placeholder="Production environment clusters"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Color</label>
                                                        <div className="flex items-center gap-2">
                                                            <input
                                                                type="color"
                                                                value={editingGroup ? editingGroup.color : newGroup.color}
                                                                onChange={e => editingGroup ? setEditingGroup({...editingGroup, color: e.target.value}) : setNewGroup({...newGroup, color: e.target.value})}
                                                                className="w-10 h-10 rounded cursor-pointer"
                                                            />
                                                            <span className="text-sm text-gray-400">{editingGroup ? editingGroup.color : newGroup.color}</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Assign to Tenant (optional)</label>
                                                        <select
                                                            value={editingGroup ? (editingGroup.tenant_id || '') : (newGroup.tenant_id || '')}
                                                            onChange={e => editingGroup ? setEditingGroup({...editingGroup, tenant_id: e.target.value || null}) : setNewGroup({...newGroup, tenant_id: e.target.value || null})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="">No tenant (visible to all)</option>
                                                            {tenants.filter(t => t.id !== 'default').map(t => (
                                                                <option key={t.id} value={t.id}>{t.name}</option>
                                                            ))}
                                                        </select>
                                                        <p className="text-xs text-gray-500 mt-1">If assigned, only this tenant can see clusters in this group</p>
                                                    </div>
                                                </div>
                                                <div className="flex justify-end gap-3 mt-6">
                                                    <button
                                                        onClick={() => { setShowAddGroup(false); setEditingGroup(null); setNewGroup({ name: '', description: '', color: '#E86F2D' }); }}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        Cancel
                                                    </button>
                                                    <button
                                                        onClick={async () => {
                                                            const data = editingGroup || newGroup;
                                                            if(!data.name) { addToast('Name required', 'error'); return; }
                                                            try {
                                                                const url = editingGroup ? `${API_URL}/cluster-groups/${editingGroup.id}` : `${API_URL}/cluster-groups`;
                                                                const r = await fetch(url, {
                                                                    method: editingGroup ? 'PUT' : 'POST',
                                                                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify(data)
                                                                });
                                                                if(r.ok) {
                                                                    addToast(editingGroup ? 'Group updated' : 'Group created', 'success');
                                                                    setShowAddGroup(false);
                                                                    setEditingGroup(null);
                                                                    setNewGroup({ name: '', description: '', color: '#E86F2D' });
                                                                    fetchClusterGroups();
                                                                    onGroupsChanged?.();
                                                                } else {
                                                                    const err = await r.json();
                                                                    addToast(err.error || 'Error', 'error');
                                                                }
                                                            } catch(e) { addToast('Error', 'error'); }
                                                        }}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                    >
                                                        {editingGroup ? 'Save' : 'Create'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                            
                            {/* Permissions Tab - LW: granular access control */}
                            {activeTab === 'permissions' && (
                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <h3 className="text-lg font-semibold text-white">{t('permissions') || 'Permissions'}</h3>
                                    </div>
                                    
                                    {/* Sub-tabs for permissions */}
                                    {isCorporate ? (
                                    <div className="corp-tab-strip">
                                        <button onClick={() => setPermSubTab('users')} className={permSubTab === 'users' ? 'active' : ''}>
                                            <Icons.User style={{width: 14, height: 14, display: 'inline', marginRight: 6}} />
                                            {t('userPermissions') || 'User Permissions'}
                                        </button>
                                        <button onClick={() => setPermSubTab('vms')} className={permSubTab === 'vms' ? 'active' : ''}>
                                            <Icons.VM style={{width: 14, height: 14, display: 'inline', marginRight: 6}} />
                                            {t('vmPermissions') || 'VM Permissions'}
                                        </button>
                                        <button onClick={() => setPermSubTab('pools')} className={permSubTab === 'pools' ? 'active' : ''}>
                                            <Icons.Layers style={{width: 14, height: 14, display: 'inline', marginRight: 6}} />
                                            {t('poolPermissions') || 'Pool Permissions'}
                                        </button>
                                    </div>
                                    ) : (
                                    <div className="flex gap-2 border-b border-proxmox-border pb-2">
                                        <button
                                            onClick={() => setPermSubTab('users')}
                                            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
                                                permSubTab === 'users'
                                                    ? 'bg-proxmox-orange text-white'
                                                    : 'bg-proxmox-dark text-gray-400 hover:text-white'
                                            }`}
                                        >
                                            <div className="flex items-center gap-2">
                                                <Icons.User />
                                                {t('userPermissions') || 'User Permissions'}
                                            </div>
                                        </button>
                                        <button
                                            onClick={() => setPermSubTab('vms')}
                                            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
                                                permSubTab === 'vms'
                                                    ? 'bg-proxmox-orange text-white'
                                                    : 'bg-proxmox-dark text-gray-400 hover:text-white'
                                            }`}
                                        >
                                            <div className="flex items-center gap-2">
                                                <Icons.VM />
                                                {t('vmPermissions') || 'VM Permissions'}
                                            </div>
                                        </button>
                                        <button
                                            onClick={() => setPermSubTab('pools')}
                                            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
                                                permSubTab === 'pools'
                                                    ? 'bg-proxmox-orange text-white'
                                                    : 'bg-proxmox-dark text-gray-400 hover:text-white'
                                            }`}
                                        >
                                            <div className="flex items-center gap-2">
                                                <Icons.Layers />
                                                {t('poolPermissions') || 'Pool Permissions'}
                                            </div>
                                        </button>
                                    </div>
                                    )}
                                    
                                    {/* User Permissions Sub-Tab */}
                                    {permSubTab === 'users' && (
                                    <div>
                                    <p className="text-sm text-gray-400 mb-4">
                                        {t('permissionsDesc') || 'Configure granular permissions for users. Role-based defaults can be overridden per user.'}
                                    </p>
                                    
                                    <div className="grid grid-cols-3 gap-4">
                                        {/* User selector */}
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <h4 className="font-medium text-white mb-3">{t('selectUser') || 'Select User'}</h4>
                                            <div className="space-y-2 max-h-96 overflow-y-auto">
                                                {users.map(u => (
                                                    <button
                                                        key={u.username}
                                                        onClick={() => { setSelectedUser(u.username); fetchUserPermissions(u.username); }}
                                                        className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                                                            selectedUser === u.username
                                                                ? 'bg-proxmox-orange text-white'
                                                                : 'bg-proxmox-darker text-gray-300 hover:bg-proxmox-hover'
                                                        }`}
                                                    >
                                                        <div className="font-medium">{u.display_name || u.username}</div>
                                                        <div className="text-xs opacity-70">{u.role}</div>
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                        
                                        {/* Permissions editor */}
                                        <div className="col-span-2 bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            {selectedUser && userPermissions ? (
                                                <div className="space-y-4">
                                                    <div className="flex justify-between items-center">
                                                        <h4 className="font-medium text-white">
                                                            Permissions for {selectedUser}
                                                            <span className="ml-2 text-xs text-gray-400">({userPermissions.role})</span>
                                                        </h4>
                                                        <button
                                                            onClick={async () => {
                                                                try {
                                                                    const r = await fetch(`${API_URL}/users/${selectedUser}/permissions`, {
                                                                        method: 'PUT',
                                                                        credentials: 'include',
                                                                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                        body: JSON.stringify({
                                                                            permissions: userPermissions.extra_permissions,
                                                                            denied_permissions: userPermissions.denied_permissions
                                                                        })
                                                                    });
                                                                    if(r.ok) {
                                                                        addToast('Permissions saved', 'success');
                                                                        fetchUserPermissions(selectedUser);
                                                                    }
                                                                } catch(e) {}
                                                            }}
                                                            className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded text-sm font-medium"
                                                        >
                                                            {t('save')}
                                                        </button>
                                                    </div>
                                                    
                                                    <div className="text-xs text-gray-500 mb-2">
                                                        ✓ = granted by role | + = extra permission | ✗ = denied
                                                    </div>
                                                    
                                                    <div className="grid grid-cols-2 gap-4 max-h-80 overflow-y-auto">
                                                        {Object.entries(
                                                            allPermissions.reduce((acc, p) => {
                                                                const cat = p.category;
                                                                if(!acc[cat]) acc[cat] = [];
                                                                acc[cat].push(p);
                                                                return acc;
                                                            }, {})
                                                        ).map(([category, perms]) => (
                                                            <div key={category} className="bg-proxmox-darker rounded-lg p-3">
                                                                <h5 className="text-sm font-medium text-white mb-2 capitalize">{category}</h5>
                                                                <div className="space-y-1">
                                                                    {perms.map(p => {
                                                                        const fromRole = userPermissions.role_permissions?.includes(p.permission);
                                                                        const extra = userPermissions.extra_permissions?.includes(p.permission);
                                                                        const denied = userPermissions.denied_permissions?.includes(p.permission);
                                                                        const effective = userPermissions.effective_permissions?.includes(p.permission);
                                                                        
                                                                        return(
                                                                            <div key={p.permission} className="flex items-center justify-between py-1">
                                                                                <span className={`text-xs ${effective ? 'text-green-400' : 'text-gray-500'}`}>
                                                                                    {p.permission.split('.')[1]}
                                                                                </span>
                                                                                <div className="flex items-center gap-1">
                                                                                    {fromRole && <span className="text-xs text-blue-400">✓</span>}
                                                                                    <button
                                                                                        onClick={() => {
                                                                                            if(extra) {
                                                                                                setUserPermissions({
                                                                                                    ...userPermissions,
                                                                                                    extra_permissions: userPermissions.extra_permissions.filter(x => x !== p.permission)
                                                                                                });
                                                                                            } else {
                                                                                                setUserPermissions({
                                                                                                    ...userPermissions,
                                                                                                    extra_permissions: [...(userPermissions.extra_permissions || []), p.permission],
                                                                                                    denied_permissions: (userPermissions.denied_permissions || []).filter(x => x !== p.permission)
                                                                                                });
                                                                                            }
                                                                                        }}
                                                                                        className={`px-1.5 py-0.5 text-xs rounded ${extra ? 'bg-green-500/20 text-green-400' : 'bg-proxmox-dark text-gray-500 hover:text-green-400'}`}
                                                                                    >
                                                                                        +
                                                                                    </button>
                                                                                    <button
                                                                                        onClick={() => {
                                                                                            if(denied) {
                                                                                                setUserPermissions({
                                                                                                    ...userPermissions,
                                                                                                    denied_permissions: userPermissions.denied_permissions.filter(x => x !== p.permission)
                                                                                                });
                                                                                            } else {
                                                                                                setUserPermissions({
                                                                                                    ...userPermissions,
                                                                                                    denied_permissions: [...(userPermissions.denied_permissions || []), p.permission],
                                                                                                    extra_permissions: (userPermissions.extra_permissions || []).filter(x => x !== p.permission)
                                                                                                });
                                                                                            }
                                                                                        }}
                                                                                        className={`px-1.5 py-0.5 text-xs rounded ${denied ? 'bg-red-500/20 text-red-400' : 'bg-proxmox-dark text-gray-500 hover:text-red-400'}`}
                                                                                    >
                                                                                        ✗
                                                                                    </button>
                                                                                </div>
                                                                            </div>
                                                                        );
                                                                    })}
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="flex items-center justify-center h-64 text-gray-500">
                                                    {t('selectUserToEdit') || 'Select a user to edit permissions'}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    </div>
                                    )}
                                    
                                    {/* VM Permissions Sub-Tab */}
                                    {permSubTab === 'vms' && (
                                    <div>
                                    {/* VM-Level Access Control Section - NS: Dec 2025 */}
                                    <div className="pt-2">
                                        <div className="flex justify-between items-center mb-4">
                                            <div>
                                                <h4 className="text-md font-semibold text-white flex items-center gap-2">
                                                    <Icons.Shield />
                                                    {t('vmAcl') || 'VM Access Control'}
                                                </h4>
                                                <p className="text-xs text-gray-500 mt-1">{t('vmAclDesc') || 'Grant specific users access to individual VMs'}</p>
                                            </div>
                                        </div>
                                        
                                        <div className="grid grid-cols-3 gap-4">
                                            {/* Cluster selector */}
                                            <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                                <label className="block text-sm text-gray-400 mb-2">{t('selectCluster') || 'Select Cluster'}</label>
                                                <select
                                                    value={selectedClusterForAcl}
                                                    onChange={e => {
                                                        setSelectedClusterForAcl(e.target.value);
                                                        fetchVmAcls(e.target.value);
                                                        fetchVmsForAcl(e.target.value);
                                                    }}
                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                >
                                                    <option value="">{t('select') || '-- Select --'}</option>
                                                    {clusters.map(c => (
                                                        <option key={c.id} value={c.id}>{clusterLabel(c)}</option>
                                                    ))}
                                                </select>
                                                
                                                {selectedClusterForAcl && (
                                                    <button
                                                        onClick={() => {
                                                            setSelectedVmForAcl(null);
                                                            setVmAclUsers([]);
                                                            setVmAclPerms([]);
                                                            setVmAclInherit(true);
                                                            setShowVmAclModal(true);
                                                        }}
                                                        className="mt-3 w-full px-3 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                                                    >
                                                        <Icons.Plus />
                                                        {t('addVmAcl') || 'Add VM Permission'}
                                                    </button>
                                                )}
                                            </div>
                                            
                                            {/* VM ACLs list */}
                                            <div className="col-span-2 bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                                <h4 className="font-medium text-white mb-3">{t('vmPermissions') || 'VM Permissions'}</h4>
                                                {selectedClusterForAcl ? (
                                                    vmAcls.length > 0 ? (
                                                        <div className="space-y-2 max-h-64 overflow-y-auto">
                                                            {vmAcls.map(acl => {
                                                                const vm = availableVms.find(v => v.vmid === acl.vmid);
                                                                return (
                                                                    <div key={acl.vmid} className="flex items-center justify-between p-3 bg-proxmox-darker rounded-lg">
                                                                        <div>
                                                                            <div className="text-white text-sm font-medium">
                                                                                {vm?.name || `VM ${acl.vmid}`}
                                                                                <span className="ml-2 text-xs text-gray-500">({acl.vmid})</span>
                                                                            </div>
                                                                            <div className="text-xs text-gray-400 mt-1">
                                                                                {acl.users?.length || 0} users • 
                                                                                {acl.inherit_role ? ' Inherits role permissions' : ` ${acl.permissions?.length || 0} custom permissions`}
                                                                            </div>
                                                                        </div>
                                                                        <div className="flex items-center gap-2">
                                                                            <button
                                                                                onClick={() => {
                                                                                    setSelectedVmForAcl(acl.vmid);
                                                                                    setVmAclUsers(acl.users || []);
                                                                                    setVmAclPerms(acl.permissions || []);
                                                                                    setVmAclInherit(acl.inherit_role !== false);
                                                                                    setShowVmAclModal(true);
                                                                                }}
                                                                                className="px-2 py-1 text-xs bg-proxmox-border hover:bg-gray-600 rounded"
                                                                            >
                                                                                {t('edit') || 'Edit'}
                                                                            </button>
                                                                            <button
                                                                                onClick={() => deleteVmAcl(acl.vmid)}
                                                                                className="px-2 py-1 text-xs bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded"
                                                                            >
                                                                                {t('delete') || 'Delete'}
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    ) : (
                                                        <div className="text-center py-8 text-gray-500">
                                                            {t('noVmAcls') || 'No VM-specific permissions configured. All VMs follow role-based access.'}
                                                        </div>
                                                    )
                                                ) : (
                                                    <div className="text-center py-8 text-gray-500">
                                                        {t('selectClusterFirst') || 'Select a cluster to manage VM permissions'}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* VM ACL Modal */}
                                    {showVmAclModal && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-lg">
                                                <h3 className="text-lg font-semibold text-white mb-4">
                                                    {selectedVmForAcl ? t('editVmAcl') || 'Edit VM Permission' : t('addVmAcl') || 'Add VM Permission'}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    {/* VM selector (only for new) */}
                                                    {!selectedVmForAcl && (
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">{t('selectVm') || 'Select VM'}</label>
                                                            <select
                                                                value={selectedVmForAcl || ''}
                                                                onChange={e => {
                                                                    const val = e.target.value;
                                                                    setSelectedVmForAcl(val ? parseInt(val) : null);
                                                                }}
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                            >
                                                                <option value="">-- {t('selectVm') || 'Select VM'} --</option>
                                                                {availableVms.map(vm => (
                                                                    <option key={vm.vmid} value={vm.vmid}>
                                                                        {vm.name || `VM ${vm.vmid}`} ({vm.vmid}) - {vm.status}
                                                                    </option>
                                                                ))}
                                                            </select>
                                                            {availableVms.length === 0 && (
                                                                <p className="text-xs text-yellow-500 mt-1">{t('noVmsInCluster') || 'No VMs found in this cluster'}</p>
                                                            )}
                                                        </div>
                                                    )}
                                                    
                                                    {/* Users with access */}
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('usersWithAccess') || 'Users with Access'}</label>
                                                        <div className="max-h-40 overflow-y-auto bg-proxmox-dark rounded-lg p-2">
                                                            {users.map(u => (
                                                                <label key={u.username} className="flex items-center gap-2 p-2 hover:bg-proxmox-darker rounded cursor-pointer">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={vmAclUsers.includes(u.username)}
                                                                        onChange={e => {
                                                                            if(e.target.checked) {
                                                                                setVmAclUsers([...vmAclUsers, u.username]);
                                                                            } else {
                                                                                setVmAclUsers(vmAclUsers.filter(x => x !== u.username));
                                                                            }
                                                                        }}
                                                                        className="rounded border-gray-600"
                                                                    />
                                                                    <span className="text-sm text-white">{u.display_name || u.username}</span>
                                                                    <span className="text-xs text-gray-500">({u.role})</span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    </div>
                                                    
                                                    {/* Inherit role permissions */}
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={vmAclInherit}
                                                            onChange={e => setVmAclInherit(e.target.checked)}
                                                            className="rounded border-gray-600"
                                                        />
                                                        <span className="text-sm text-gray-300">{t('inheritRolePerms') || 'Use role-based permissions'}</span>
                                                    </label>
                                                    
                                                    {/* Custom permissions (if not inheriting) */}
                                                    {!vmAclInherit && (
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">{t('customPermissions') || 'Custom Permissions'}</label>
                                                            <div className="grid grid-cols-2 gap-1 max-h-40 overflow-y-auto bg-proxmox-dark rounded-lg p-2">
                                                                {allPermissions.filter(p => p.permission.startsWith('vm.')).map(p => (
                                                                    <label key={p.permission} className="flex items-center gap-2 p-1 text-xs text-gray-300 cursor-pointer hover:text-white">
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={vmAclPerms.includes(p.permission)}
                                                                            onChange={e => {
                                                                                if(e.target.checked) {
                                                                                    setVmAclPerms([...vmAclPerms, p.permission]);
                                                                                } else {
                                                                                    setVmAclPerms(vmAclPerms.filter(x => x !== p.permission));
                                                                                }
                                                                            }}
                                                                            className="rounded border-gray-600"
                                                                        />
                                                                        {p.permission}
                                                                    </label>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                                
                                                <div className="flex gap-2 mt-6">
                                                    <button
                                                        onClick={saveVmAcl}
                                                        disabled={!selectedVmForAcl || vmAclUsers.length === 0}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium"
                                                    >
                                                        {t('save') || 'Save'}
                                                    </button>
                                                    <button
                                                        onClick={() => setShowVmAclModal(false)}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    </div>
                                    )}
                                    
                                    {/* Pool Permissions Sub-Tab - MK Jan 2026 */}
                                    {permSubTab === 'pools' && (
                                    <div>
                                    <p className="text-sm text-gray-400 mb-4">
                                        {t('poolPermissionsDesc') || 'Grant users or groups access to Proxmox resource pools. Permissions apply to all VMs within the pool.'}
                                    </p>
                                    
                                    <div className="grid grid-cols-3 gap-4">
                                        {/* Cluster & Pool Selector */}
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <label className="block text-sm text-gray-400 mb-2">{t('selectCluster') || 'Select Cluster'}</label>
                                            <div className="flex gap-2">
                                                <select
                                                    value={selectedPoolCluster}
                                                    onChange={e => {
                                                        setSelectedPoolCluster(e.target.value);
                                                        setSelectedPool(null);
                                                        setPoolPermissions([]);
                                                        if (e.target.value) fetchPools(e.target.value);
                                                    }}
                                                    className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                >
                                                    <option value="">{t('select') || '-- Select --'}</option>
                                                    {clusters.map(c => (
                                                        <option key={c.id} value={c.id}>{clusterLabel(c)}</option>
                                                    ))}
                                                </select>
                                                {selectedPoolCluster && !haStandby && (
                                                    <button
                                                        onClick={() => refreshPoolCache(selectedPoolCluster)}
                                                        className="px-3 py-2 bg-proxmox-border hover:bg-gray-600 rounded-lg text-sm"
                                                        title={t('refreshPools') || 'Refresh pools from Proxmox'}
                                                    >
                                                        <Icons.Refresh className="w-4 h-4" />
                                                    </button>
                                                )}
                                                {selectedPoolCluster && (
                                                    <button
                                                        onClick={() => {
                                                            setShowPoolManager(true);
                                                            fetchVmsWithoutPool(selectedPoolCluster);
                                                        }}
                                                        className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"
                                                        title={t('managePools') || 'Manage Pools'}
                                                    >
                                                        <Icons.Settings className="w-4 h-4" />
                                                    </button>
                                                )}
                                            </div>
                                            
                                            {selectedPoolCluster && pools.length > 0 && (
                                                <div className="mt-4">
                                                    <label className="block text-sm text-gray-400 mb-2">{t('selectPool') || 'Select Pool'}</label>
                                                    <div className="space-y-2 max-h-64 overflow-y-auto">
                                                        {pools.map(pool => (
                                                            <button
                                                                key={pool.poolid}
                                                                onClick={() => {
                                                                    setSelectedPool(pool.poolid);
                                                                    fetchPoolPermissions(selectedPoolCluster, pool.poolid);
                                                                }}
                                                                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                                                                    selectedPool === pool.poolid
                                                                        ? 'bg-proxmox-orange text-white'
                                                                        : 'bg-proxmox-darker text-gray-300 hover:bg-proxmox-hover'
                                                                }`}
                                                            >
                                                                <div className="font-medium flex items-center gap-2">
                                                                    <Icons.Layers className="w-4 h-4" />
                                                                    {pool.poolid}
                                                                </div>
                                                                <div className="text-xs opacity-70 mt-1">
                                                                    {pool.vms || 0} VMs • {pool.comment || t('noDescription') || 'No description'}
                                                                </div>
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {selectedPoolCluster && pools.length === 0 && (
                                                <div className="mt-4 text-sm text-gray-500 text-center py-4">
                                                    {t('noPools') || 'No resource pools found in this cluster'}
                                                </div>
                                            )}
                                        </div>
                                        
                                        {/* Pool Permissions List */}
                                        <div className="col-span-2 bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <div className="flex justify-between items-center mb-3">
                                                <h4 className="font-medium text-white">
                                                    {selectedPool ? `${t('permissionsFor') || 'Permissions for'} "${selectedPool}"` : t('poolPermissions') || 'Pool Permissions'}
                                                </h4>
                                                {selectedPool && (
                                                    <button
                                                        onClick={() => {
                                                            setPoolPermForm({ subject_type: 'user', subject_id: '', permissions: [] });
                                                            setShowPoolPermModal(true);
                                                        }}
                                                        className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium flex items-center gap-2"
                                                    >
                                                        <Icons.Plus className="w-4 h-4" />
                                                        {t('addPermission') || 'Add Permission'}
                                                    </button>
                                                )}
                                            </div>
                                            
                                            {selectedPool ? (
                                                poolPermissions.length > 0 ? (
                                                    <div className="space-y-2 max-h-80 overflow-y-auto">
                                                        {poolPermissions.map((perm, idx) => (
                                                            <div key={idx} className="flex items-center justify-between p-3 bg-proxmox-darker rounded-lg">
                                                                <div>
                                                                    <div className="text-white text-sm font-medium flex items-center gap-2">
                                                                        {perm.subject_type === 'user' ? <Icons.User className="w-4 h-4" /> : <Icons.Users className="w-4 h-4" />}
                                                                        {perm.subject_id}
                                                                        <span className="text-xs px-1.5 py-0.5 rounded bg-gray-700 text-gray-400">
                                                                            {perm.subject_type}
                                                                        </span>
                                                                    </div>
                                                                    <div className="flex flex-wrap gap-1 mt-2">
                                                                        {perm.permissions.map((p, i) => (
                                                                            <span key={i} className="px-1.5 py-0.5 text-xs rounded bg-blue-500/20 text-blue-400">
                                                                                {p.replace('pool.', '').replace('vm.', '')}
                                                                            </span>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    <button
                                                                        onClick={() => {
                                                                            setPoolPermForm({
                                                                                subject_type: perm.subject_type,
                                                                                subject_id: perm.subject_id,
                                                                                permissions: perm.permissions
                                                                            });
                                                                            setShowPoolPermModal(true);
                                                                        }}
                                                                        className="px-2 py-1 text-xs bg-proxmox-border hover:bg-gray-600 rounded"
                                                                    >
                                                                        {t('edit') || 'Edit'}
                                                                    </button>
                                                                    <button
                                                                        onClick={() => deletePoolPermission(perm.subject_type, perm.subject_id)}
                                                                        className="px-2 py-1 text-xs bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded"
                                                                    >
                                                                        {t('delete') || 'Delete'}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                ) : (
                                                    <div className="text-center py-8 text-gray-500">
                                                        {t('noPoolPerms') || 'No permissions configured for this pool'}
                                                    </div>
                                                )
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    {t('selectPoolFirst') || 'Select a cluster and pool to manage permissions'}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    
                                    {/* Pool Permission Modal */}
                                    {showPoolPermModal && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-lg">
                                                <h3 className="text-lg font-semibold text-white mb-4">
                                                    {poolPermForm.subject_id ? t('editPoolPerm') || 'Edit Pool Permission' : t('addPoolPerm') || 'Add Pool Permission'}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    {/* Subject Type */}
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('subjectType') || 'Subject Type'}</label>
                                                        <select
                                                            value={poolPermForm.subject_type}
                                                            onChange={e => setPoolPermForm({...poolPermForm, subject_type: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            <option value="user">{t('user') || 'User'}</option>
                                                            <option value="group">{t('group') || 'Group'}</option>
                                                        </select>
                                                    </div>
                                                    
                                                    {/* Subject ID */}
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">
                                                            {poolPermForm.subject_type === 'user' ? t('selectUser') || 'Select User' : t('groupName') || 'Group Name'}
                                                        </label>
                                                        {poolPermForm.subject_type === 'user' ? (
                                                            <select
                                                                value={poolPermForm.subject_id}
                                                                onChange={e => setPoolPermForm({...poolPermForm, subject_id: e.target.value})}
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                            >
                                                                <option value="">{t('select') || '-- Select --'}</option>
                                                                {users.map(u => (
                                                                    <option key={u.username} value={u.username}>
                                                                        {u.display_name || u.username} ({u.role})
                                                                    </option>
                                                                ))}
                                                            </select>
                                                        ) : (
                                                            <input
                                                                type="text"
                                                                value={poolPermForm.subject_id}
                                                                onChange={e => setPoolPermForm({...poolPermForm, subject_id: e.target.value})}
                                                                placeholder="developers"
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                            />
                                                        )}
                                                    </div>
                                                    
                                                    {/* Permissions */}
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-2">{t('permissions') || 'Permissions'}</label>
                                                        <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto bg-proxmox-dark p-3 rounded-lg border border-proxmox-border">
                                                            {availablePoolPerms.map(perm => (
                                                                <label key={perm} className="flex items-center gap-2 text-sm cursor-pointer hover:bg-proxmox-hover p-1 rounded">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={poolPermForm.permissions.includes(perm)}
                                                                        onChange={e => {
                                                                            if (e.target.checked) {
                                                                                setPoolPermForm({
                                                                                    ...poolPermForm,
                                                                                    permissions: [...poolPermForm.permissions, perm]
                                                                                });
                                                                            } else {
                                                                                setPoolPermForm({
                                                                                    ...poolPermForm,
                                                                                    permissions: poolPermForm.permissions.filter(p => p !== perm)
                                                                                });
                                                                            }
                                                                        }}
                                                                        className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange"
                                                                    />
                                                                    <span className={poolPermForm.permissions.includes(perm) ? 'text-white' : 'text-gray-400'}>
                                                                        {perm.replace('pool.', '').replace('vm.', '')}
                                                                    </span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                        
                                                        {/* Quick select buttons */}
                                                        <div className="flex gap-2 mt-2">
                                                            <button
                                                                type="button"
                                                                onClick={() => setPoolPermForm({
                                                                    ...poolPermForm,
                                                                    permissions: ['pool.view', 'vm.start', 'vm.stop', 'vm.console']
                                                                })}
                                                                className="px-2 py-1 text-xs bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 rounded"
                                                            >
                                                                Operator
                                                            </button>
                                                            <button
                                                                type="button"
                                                                onClick={() => setPoolPermForm({
                                                                    ...poolPermForm,
                                                                    permissions: ['pool.view', 'vm.start', 'vm.stop', 'vm.console', 'vm.config', 'vm.snapshot', 'vm.backup']
                                                                })}
                                                                className="px-2 py-1 text-xs bg-green-500/20 text-green-400 hover:bg-green-500/30 rounded"
                                                            >
                                                                Power User
                                                            </button>
                                                            <button
                                                                type="button"
                                                                onClick={() => setPoolPermForm({
                                                                    ...poolPermForm,
                                                                    permissions: ['pool.admin']
                                                                })}
                                                                className="px-2 py-1 text-xs bg-proxmox-orange/20 text-proxmox-orange hover:bg-proxmox-orange/30 rounded"
                                                            >
                                                                Admin
                                                            </button>
                                                            <button
                                                                type="button"
                                                                onClick={() => setPoolPermForm({...poolPermForm, permissions: []})}
                                                                className="px-2 py-1 text-xs bg-gray-500/20 text-gray-400 hover:bg-gray-500/30 rounded"
                                                            >
                                                                Clear
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <div className="flex gap-3 mt-6">
                                                    <button
                                                        onClick={savePoolPermission}
                                                        disabled={!poolPermForm.subject_id || poolPermForm.permissions.length === 0}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium"
                                                    >
                                                        {t('save') || 'Save'}
                                                    </button>
                                                    <button
                                                        onClick={() => setShowPoolPermModal(false)}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Pool Manager Modal - NS Jan 2026 */}
                                    {showPoolManager && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
                                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                                        <Icons.Layers />
                                                        {t('managePools') || 'Manage Pools'}
                                                    </h3>
                                                    <button onClick={() => setShowPoolManager(false)} className="p-1 hover:bg-proxmox-dark rounded">
                                                        <Icons.X />
                                                    </button>
                                                </div>
                                                
                                                <div className="flex-1 overflow-auto p-4">
                                                    {/* Create Pool Button */}
                                                    <div className="flex justify-between items-center mb-4">
                                                        <p className="text-sm text-gray-400">
                                                            {t('poolManagerDesc') || 'Create, edit, and delete resource pools. Assign VMs to pools for organized permission management.'}
                                                        </p>
                                                        <button
                                                            onClick={() => setShowCreatePool(true)}
                                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                                        >
                                                            <Icons.Plus className="w-4 h-4" />
                                                            {t('createPool') || 'Create Pool'}
                                                        </button>
                                                    </div>
                                                    
                                                    {/* Pools List */}
                                                    <div className="space-y-3">
                                                        {pools.length === 0 ? (
                                                            <div className="text-center py-12 text-gray-500">
                                                                <Icons.Layers className="w-12 h-12 mx-auto mb-3 opacity-50" />
                                                                <p>{t('noPoolsYet') || 'No pools yet'}</p>
                                                                <p className="text-sm mt-1">{t('createFirstPool') || 'Create your first pool to organize VMs'}</p>
                                                            </div>
                                                        ) : (
                                                            pools.map(pool => (
                                                                <div key={pool.poolid} className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                                                    <div className="flex items-start justify-between">
                                                                        <div className="flex-1">
                                                                            <div className="flex items-center gap-3">
                                                                                <Icons.Layers className="w-5 h-5 text-blue-400" />
                                                                                <h4 className="font-semibold text-white">{pool.poolid}</h4>
                                                                                <span className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-400">
                                                                                    {pool.members?.length || 0} {t('members') || 'members'}
                                                                                </span>
                                                                            </div>
                                                                            {pool.comment && (
                                                                                <p className="text-sm text-gray-500 mt-1 ml-8">{pool.comment}</p>
                                                                            )}
                                                                            
                                                                            {/* Pool Members (VMs) */}
                                                                            {pool.members && pool.members.length > 0 && (
                                                                                <div className="mt-3 ml-8">
                                                                                    <p className="text-xs text-gray-500 mb-2">{t('poolMembers') || 'Members'}:</p>
                                                                                    <div className="flex flex-wrap gap-2">
                                                                                        {pool.members.filter(m => m.type === 'qemu' || m.type === 'lxc').map(member => (
                                                                                            <div key={member.id} className="flex items-center gap-1 px-2 py-1 bg-proxmox-darker rounded text-xs">
                                                                                                {member.type === 'qemu' ? (
                                                                                                    <Icons.Monitor className="w-3 h-3 text-blue-400" />
                                                                                                ) : (
                                                                                                    <Icons.Box className="w-3 h-3 text-yellow-400" />
                                                                                                )}
                                                                                                <span className="text-gray-300">{member.vmid} - {member.name || 'unnamed'}</span>
                                                                                                <button
                                                                                                    onClick={() => removeVmFromPool(pool.poolid, member.vmid)}
                                                                                                    className="ml-1 text-red-400 hover:text-red-300"
                                                                                                    title={t('removeFromPool') || 'Remove from pool'}
                                                                                                >
                                                                                                    <Icons.X className="w-3 h-3" />
                                                                                                </button>
                                                                                            </div>
                                                                                        ))}
                                                                                    </div>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Actions */}
                                                                        <div className="flex items-center gap-2">
                                                                            <button
                                                                                onClick={() => setShowAddVmToPool(pool.poolid)}
                                                                                className="px-3 py-1.5 bg-green-600 hover:bg-green-700 rounded text-xs flex items-center gap-1"
                                                                                title={t('addVmToPool') || 'Add VM to pool'}
                                                                            >
                                                                                <Icons.Plus className="w-3 h-3" />
                                                                                VM
                                                                            </button>
                                                                            <button
                                                                                onClick={() => setEditingPool({ poolid: pool.poolid, comment: pool.comment || '' })}
                                                                                className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-hover rounded"
                                                                                title={t('edit') || 'Edit'}
                                                                            >
                                                                                <Icons.Edit className="w-4 h-4" />
                                                                            </button>
                                                                            <button
                                                                                onClick={() => deletePool(pool.poolid)}
                                                                                className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded"
                                                                                title={t('delete') || 'Delete'}
                                                                            >
                                                                                <Icons.Trash className="w-4 h-4" />
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            ))
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Create Pool Modal */}
                                    {showCreatePool && (
                                        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60]">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                                    <Icons.Plus />
                                                    {t('createPool') || 'Create Pool'}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('poolId') || 'Pool ID'} *</label>
                                                        <input
                                                            type="text"
                                                            value={newPoolForm.poolid}
                                                            onChange={e => setNewPoolForm({...newPoolForm, poolid: e.target.value.replace(/[^a-zA-Z0-9_-]/g, '')})}
                                                            placeholder="my-pool"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                        <p className="text-xs text-gray-500 mt-1">{t('poolIdHint') || 'Letters, numbers, dashes and underscores only'}</p>
                                                    </div>
                                                    
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('comment') || 'Description'}</label>
                                                        <input
                                                            type="text"
                                                            value={newPoolForm.comment}
                                                            onChange={e => setNewPoolForm({...newPoolForm, comment: e.target.value})}
                                                            placeholder={t('optionalDescription') || 'Optional description...'}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                </div>
                                                
                                                <div className="flex gap-3 mt-6">
                                                    <button
                                                        onClick={createPool}
                                                        disabled={poolManagerLoading || !newPoolForm.poolid.trim()}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                                                    >
                                                        {poolManagerLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                        {t('create') || 'Create'}
                                                    </button>
                                                    <button
                                                        onClick={() => { setShowCreatePool(false); setNewPoolForm({ poolid: '', comment: '' }); }}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Edit Pool Modal */}
                                    {editingPool && (
                                        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60]">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                                    <Icons.Edit />
                                                    {t('editPool') || 'Edit Pool'}: {editingPool.poolid}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('poolId') || 'Pool ID'}</label>
                                                        <input
                                                            type="text"
                                                            value={editingPool.poolid}
                                                            disabled
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-500 text-sm cursor-not-allowed"
                                                        />
                                                        <p className="text-xs text-gray-500 mt-1">{t('poolIdCannotChange') || 'Pool ID cannot be changed'}</p>
                                                    </div>
                                                    
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('comment') || 'Description'}</label>
                                                        <input
                                                            type="text"
                                                            value={editingPool.comment}
                                                            onChange={e => setEditingPool({...editingPool, comment: e.target.value})}
                                                            placeholder={t('optionalDescription') || 'Optional description...'}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                </div>
                                                
                                                <div className="flex gap-3 mt-6">
                                                    <button
                                                        onClick={updatePool}
                                                        disabled={poolManagerLoading}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                                                    >
                                                        {poolManagerLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                        {t('save') || 'Save'}
                                                    </button>
                                                    <button
                                                        onClick={() => setEditingPool(null)}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Add VM to Pool Modal */}
                                    {showAddVmToPool && (
                                        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60]">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-lg max-h-[70vh] flex flex-col">
                                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                                    <Icons.Plus />
                                                    {t('addVmToPool') || 'Add VM to Pool'}: {showAddVmToPool}
                                                </h3>
                                                
                                                <div className="flex-1 overflow-auto">
                                                    {vmsWithoutPool.length === 0 ? (
                                                        <div className="text-center py-8 text-gray-500">
                                                            <Icons.Check className="w-12 h-12 mx-auto mb-2 opacity-50" />
                                                            <p>{t('allVmsInPools') || 'All VMs are already in pools'}</p>
                                                        </div>
                                                    ) : (
                                                        <div className="space-y-2">
                                                            <p className="text-sm text-gray-400 mb-3">{t('selectVmToAdd') || 'Select a VM to add to this pool'}:</p>
                                                            {vmsWithoutPool.map(vm => (
                                                                <button
                                                                    key={vm.vmid}
                                                                    onClick={() => {
                                                                        addVmToPool(showAddVmToPool, vm.vmid);
                                                                        setShowAddVmToPool(null);
                                                                    }}
                                                                    className="w-full flex items-center gap-3 p-3 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-left transition-colors"
                                                                >
                                                                    {vm.type === 'qemu' ? (
                                                                        <Icons.Monitor className="w-5 h-5 text-blue-400" />
                                                                    ) : (
                                                                        <Icons.Box className="w-5 h-5 text-yellow-400" />
                                                                    )}
                                                                    <div className="flex-1">
                                                                        <div className="font-medium text-white">{vm.vmid} - {vm.name}</div>
                                                                        <div className="text-xs text-gray-500">{vm.node} • {vm.type === 'qemu' ? 'VM' : 'Container'}</div>
                                                                    </div>
                                                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                                                        vm.status === 'running' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                                                                    }`}>
                                                                        {vm.status}
                                                                    </span>
                                                                </button>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                                
                                                <div className="mt-4 pt-4 border-t border-proxmox-border">
                                                    <button
                                                        onClick={() => setShowAddVmToPool(null)}
                                                        className="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('close') || 'Close'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    </div>
                                    )}
                                </div>
                            )}
                            
                            {/* Roles Tab - NS: Dec 2025 */}
                            {activeTab === 'roles' && (
                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <h3 className="text-lg font-semibold text-white">{t('customRoles') || 'Custom Roles'}</h3>
                                        <button
                                            onClick={() => setShowAddRole(true)}
                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                        >
                                            <Icons.Plus />
                                            {t('createRole') || 'Create Role'}
                                        </button>
                                    </div>
                                    
                                    <p className="text-sm text-gray-400">{t('rolesDesc') || 'Create custom roles with specific permissions. Roles can be global or tenant-specific.'}</p>
                                    
                                    {/* Add Role Form */}
                                    {showAddRole && (
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                            <h4 className="text-white font-medium mb-4">{t('createRole') || 'Create Role'}</h4>
                                            <form onSubmit={handleCreateRole} className="space-y-4">
                                                <div className="grid grid-cols-3 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('roleId') || 'Role ID'}</label>
                                                        <input
                                                            type="text"
                                                            value={newRole.id}
                                                            onChange={e => setNewRole({...newRole, id: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '')})}
                                                            placeholder="operator"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                            required
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('roleName') || 'Display Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={newRole.name}
                                                            onChange={e => setNewRole({...newRole, name: e.target.value})}
                                                            placeholder="Operator"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('scope') || 'Scope'}</label>
                                                        <select
                                                            value={newRole.tenant_id}
                                                            onChange={e => setNewRole({...newRole, tenant_id: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            <option value="">{t('global') || 'Global'}</option>
                                                            {tenants.map(t => (
                                                                <option key={t.id} value={t.id}>{t.name}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                </div>
                                                
                                                {/* Permission checkboxes — grouped with search */}
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-2">{t('permissions') || 'Permissions'}</label>
                                                    <PermissionsGrid
                                                        t={t}
                                                        allPermissions={allPermissions}
                                                        selected={newRole.permissions}
                                                        onChange={(next) => setNewRole({...newRole, permissions: next})}
                                                    />
                                                </div>
                                                
                                                <div className="flex gap-2">
                                                    <button type="submit" className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">
                                                        {t('create') || 'Create'}
                                                    </button>
                                                    <button type="button" onClick={() => setShowAddRole(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </form>
                                        </div>
                                    )}
                                    
                                    {/* Roles List */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                                        <table className="w-full">
                                            <thead className="bg-proxmox-darker">
                                                <tr>
                                                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">{t('role') || 'Role'}</th>
                                                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">{t('scope') || 'Scope'}</th>
                                                    <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">{t('permissions') || 'Permissions'}</th>
                                                    <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">{t('actions') || 'Actions'}</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-proxmox-border">
                                                {allRoles.map(role => (
                                                    <tr key={`${role.id}-${role.tenant_id || 'global'}`} className="hover:bg-proxmox-darker/50">
                                                        <td className="px-4 py-3">
                                                            <div className="font-medium text-white">{role.name || role.id}</div>
                                                            <div className="text-xs text-gray-500">{role.id}</div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={`px-2 py-1 text-xs rounded ${
                                                                role.builtin ? 'bg-blue-500/20 text-blue-400' :
                                                                role.scope === 'global' ? 'bg-purple-500/20 text-purple-400' :
                                                                'bg-green-500/20 text-green-400'
                                                            }`}>
                                                                {role.builtin ? 'Builtin' : role.scope === 'global' ? 'Global' : `Tenant: ${role.tenant_id}`}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3 text-sm text-gray-400">
                                                            {role.permissions?.length || 0} permissions
                                                        </td>
                                                        <td className="px-4 py-3 text-right">
                                                            {!role.builtin && (
                                                                <div className="flex gap-2 justify-end">
                                                                    <button onClick={() => setEditingRole({...role})} className="text-blue-400 hover:text-blue-300 text-sm">{t('edit') || 'Edit'}</button>
                                                                    <button onClick={() => handleDeleteRole(role.id, role.tenant_id)} className="text-red-400 hover:text-red-300 text-sm">{t('delete') || 'Delete'}</button>
                                                                </div>
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>


                                    {/* Edit Role Form - #167 */}
                                    {editingRole && (
                                        <div className="bg-proxmox-dark border border-blue-500/30 rounded-xl p-4 space-y-4 mt-4">
                                            <h4 className="font-medium text-white">{t('editRole') || 'Edit Role'}: {editingRole.name || editingRole.id}</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                                    <input value={editingRole.name || ''} onChange={e => setEditingRole({...editingRole, name: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('scope') || 'Scope'}</label>
                                                    <select value={editingRole.tenant_id || ''} onChange={e => setEditingRole({...editingRole, tenant_id: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm">
                                                        <option value="">{t('global') || 'Global'}</option>
                                                        {tenants.map(t => (<option key={t.id} value={t.id}>{t.name}</option>))}
                                                    </select>
                                                </div>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-2">{t('permissions') || 'Permissions'}</label>
                                                <PermissionsGrid
                                                    t={t}
                                                    allPermissions={allPermissions}
                                                    selected={editingRole.permissions || []}
                                                    onChange={(next) => setEditingRole({...editingRole, permissions: next})}
                                                />
                                            </div>
                                            <div className="flex gap-2">
                                                <button onClick={() => handleUpdateRole(editingRole.id, { name: editingRole.name, permissions: editingRole.permissions, tenant_id: editingRole.tenant_id })}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">{t('save') || 'Save'}</button>
                                                <button onClick={() => setEditingRole(null)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">{t('cancel') || 'Cancel'}</button>
                                            </div>
                                        </div>
                                    )}

                                    {/* Role Templates Section */}
                                    <div className="mt-6">
                                        <h4 className="text-md font-semibold text-white mb-3 flex items-center gap-2">
                                            <Icons.FileText />
                                            {t('roleTemplates') || 'Role Templates'}
                                        </h4>
                                        <p className="text-sm text-gray-400 mb-4">{t('roleTemplatesDesc') || 'Quick-start templates for common role configurations'}</p>
                                        
                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                            {roleTemplates.map(tpl => (
                                                <div 
                                                    key={tpl.id}
                                                    className="bg-proxmox-dark border border-proxmox-border rounded-lg p-4 hover:border-proxmox-orange/50 cursor-pointer transition-colors"
                                                    onClick={() => {
                                                        setSelectedTemplate(tpl);
                                                        setTemplateConfig({ role_id: tpl.id, name: tpl.name, tenant_id: '' });
                                                        setShowTemplateModal(true);
                                                    }}
                                                >
                                                    <div className="font-medium text-white text-sm">{tpl.name}</div>
                                                    <div className="text-xs text-gray-500 mt-1">{tpl.description}</div>
                                                    <div className="text-xs text-proxmox-orange mt-2">{tpl.permission_count} {t('permissions') || 'permissions'}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                    
                                    {/* Template Apply Modal */}
                                    {showTemplateModal && selectedTemplate && (
                                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                                            <div className="bg-proxmox-darker border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                                <h3 className="text-lg font-semibold text-white mb-4">
                                                    {t('createFromTemplate') || 'Create from Template'}: {selectedTemplate.name}
                                                </h3>
                                                
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('roleId') || 'Role ID'}</label>
                                                        <input
                                                            type="text"
                                                            value={templateConfig.role_id}
                                                            onChange={e => setTemplateConfig({...templateConfig, role_id: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '')})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('roleName') || 'Display Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={templateConfig.name}
                                                            onChange={e => setTemplateConfig({...templateConfig, name: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('scope') || 'Scope'}</label>
                                                        <select
                                                            value={templateConfig.tenant_id}
                                                            onChange={e => setTemplateConfig({...templateConfig, tenant_id: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            <option value="">{t('global') || 'Global'}</option>
                                                            {tenants.map(t => (
                                                                <option key={t.id} value={t.id}>{t.name}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    
                                                    <div className="bg-proxmox-dark rounded-lg p-3 max-h-40 overflow-y-auto">
                                                        <div className="text-xs text-gray-400 mb-2">{t('includedPermissions') || 'Included Permissions'}:</div>
                                                        <div className="flex flex-wrap gap-1">
                                                            {selectedTemplate.permissions.map(p => (
                                                                <span key={p} className="px-2 py-0.5 bg-proxmox-darker text-xs text-gray-300 rounded">{p}</span>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <div className="flex gap-2 mt-6">
                                                    <button
                                                        onClick={handleApplyTemplate}
                                                        className="flex-1 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium"
                                                    >
                                                        {t('create') || 'Create'}
                                                    </button>
                                                    <button
                                                        onClick={() => { setShowTemplateModal(false); setSelectedTemplate(null); }}
                                                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
                                                    >
                                                        {t('cancel') || 'Cancel'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                            
                            {/* Security Settings Tab */}
                            {activeTab === 'security' && (
                                <SecuritySettingsSection addToast={addToast} />
                            )}
                            
                            {/* Compliance Tab (HIPAA/ISO 27001) */}
                            {activeTab === 'compliance' && (
                                <ComplianceSection addToast={addToast} />
                            )}
                            
                            {/* MK: Feb 2026 - LDAP / Active Directory Tab */}
                            {activeTab === 'ldap' && (
                                <div className="space-y-6">
                                    <div className="flex items-center justify-between">
                                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                            <Icons.Users className="w-5 h-5 text-blue-400" />
                                            LDAP / Active Directory
                                        </h3>
                                        <label className="flex items-center gap-2 cursor-pointer">
                                            <span className="text-sm text-gray-400">Enable LDAP</span>
                                            <input type="checkbox" checked={ldapConfig.ldap_enabled} onChange={e => setLdapConfig(prev => ({...prev, ldap_enabled: e.target.checked}))}
                                                className="w-4 h-4 rounded accent-proxmox-orange" />
                                        </label>
                                    </div>
                                    
                                    {/* Connection Settings */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="text-white font-medium">Connection</h4>
                                        <div className="grid grid-cols-3 gap-3">
                                            <div className="col-span-2">
                                                <label className="block text-sm text-gray-400 mb-1">Server (hostname or IP)</label>
                                                <input type="text" value={ldapConfig.ldap_server} onChange={e => setLdapConfig(prev => ({...prev, ldap_server: e.target.value}))} placeholder="ldap.example.com" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Port</label>
                                                <input type="number" value={ldapConfig.ldap_port} onChange={e => setLdapConfig(prev => ({...prev, ldap_port: parseInt(e.target.value) || 389}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                            </div>
                                        </div>
                                        <div className="flex gap-4">
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox" checked={ldapConfig.ldap_use_ssl} onChange={e => setLdapConfig(prev => ({...prev, ldap_use_ssl: e.target.checked, ldap_port: e.target.checked ? 636 : 389}))} className="w-4 h-4 accent-proxmox-orange" />
                                                <span className="text-sm text-gray-300">SSL (LDAPS, port 636)</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox" checked={ldapConfig.ldap_use_starttls} onChange={e => setLdapConfig(prev => ({...prev, ldap_use_starttls: e.target.checked}))} className="w-4 h-4 accent-proxmox-orange" />
                                                <span className="text-sm text-gray-300">STARTTLS</span>
                                            </label>
                                            {(ldapConfig.ldap_use_ssl || ldapConfig.ldap_use_starttls) && (
                                                <label className="flex items-center gap-2 cursor-pointer">
                                                    <input type="checkbox" checked={ldapConfig.ldap_verify_tls} onChange={e => setLdapConfig(prev => ({...prev, ldap_verify_tls: e.target.checked}))} className="w-4 h-4 accent-proxmox-orange" />
                                                    <span className="text-sm text-gray-300">Verify TLS Certificate</span>
                                                </label>
                                            )}
                                        </div>
                                    </div>
                                    
                                    {/* Bind Credentials */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="text-white font-medium">Service Account (Bind)</h4>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Bind DN</label>
                                            <input type="text" value={ldapConfig.ldap_bind_dn} onChange={e => setLdapConfig(prev => ({...prev, ldap_bind_dn: e.target.value}))} placeholder="CN=svc-pegaprox,OU=Service Accounts,DC=example,DC=com" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Bind Password</label>
                                            <input type="password" value={ldapConfig.ldap_bind_password} onChange={e => setLdapConfig(prev => ({...prev, ldap_bind_password: e.target.value}))} placeholder="Service account password" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                    </div>
                                    
                                    {/* Search Settings */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="text-white font-medium">User Search</h4>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Base DN</label>
                                            <input type="text" value={ldapConfig.ldap_base_dn} onChange={e => setLdapConfig(prev => ({...prev, ldap_base_dn: e.target.value}))} placeholder="DC=example,DC=com" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">User Filter <span className="text-gray-600">({'{username}'} = login name)</span></label>
                                            <input type="text" value={ldapConfig.ldap_user_filter} onChange={e => setLdapConfig(prev => ({...prev, ldap_user_filter: e.target.value}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                        </div>
                                        <div className="grid grid-cols-3 gap-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Username Attr</label>
                                                <input type="text" value={ldapConfig.ldap_username_attribute} onChange={e => setLdapConfig(prev => ({...prev, ldap_username_attribute: e.target.value}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Email Attr</label>
                                                <input type="text" value={ldapConfig.ldap_email_attribute} onChange={e => setLdapConfig(prev => ({...prev, ldap_email_attribute: e.target.value}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Display Name Attr</label>
                                                <input type="text" value={ldapConfig.ldap_display_name_attribute} onChange={e => setLdapConfig(prev => ({...prev, ldap_display_name_attribute: e.target.value}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* NS: Feb 2026 - Unified Group-Role Mapping */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium">Group ↑ Role Mapping</h4>
                                            <button onClick={() => setLdapConfig(prev => ({...prev, ldap_group_mappings: [...prev.ldap_group_mappings, {group_dn: '', role: 'viewer'}]}))}
                                                className="px-2 py-1 bg-proxmox-secondary border border-proxmox-border rounded text-xs text-gray-300 hover:text-white hover:bg-proxmox-hover flex items-center gap-1">
                                                <Icons.Plus className="w-3 h-3" /> Add Mapping
                                            </button>
                                        </div>
                                        <p className="text-xs text-gray-500">Map AD/LDAP groups to PegaProx roles (including custom roles). Use full Distinguished Name (DN).</p>
                                        
                                        {ldapConfig.ldap_group_mappings.length === 0 ? (
                                            <p className="text-gray-600 text-sm text-center py-4 border border-dashed border-proxmox-border rounded-lg">No group mappings configured. Click "Add Mapping" to map an AD group to a role.</p>
                                        ) : (
                                            <div className="space-y-2">
                                                {ldapConfig.ldap_group_mappings.map((mapping, idx) => (
                                                    <div key={idx} className="flex items-center gap-2 p-2 bg-proxmox-secondary rounded-lg border border-proxmox-border">
                                                        <div className="flex-1">
                                                            <input type="text" value={mapping.group_dn} placeholder="CN=DevOps,OU=Groups,DC=example,DC=com"
                                                                onChange={e => { const m = [...ldapConfig.ldap_group_mappings]; m[idx] = {...m[idx], group_dn: e.target.value}; setLdapConfig(prev => ({...prev, ldap_group_mappings: m})); }}
                                                                className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm font-mono" />
                                                        </div>
                                                        <Icons.ArrowRight className="w-4 h-4 text-gray-500 shrink-0" />
                                                        <div className="w-44 shrink-0">
                                                            <select value={mapping.role || 'viewer'}
                                                                onChange={e => { const m = [...ldapConfig.ldap_group_mappings]; m[idx] = {...m[idx], role: e.target.value}; setLdapConfig(prev => ({...prev, ldap_group_mappings: m})); }}
                                                                className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                                <optgroup label="Built-in">
                                                                    <option value="admin">Admin</option>
                                                                    <option value="user">User</option>
                                                                    <option value="viewer">Viewer</option>
                                                                </optgroup>
                                                                {allRoles.filter(r => !r.builtin).length > 0 && (
                                                                    <optgroup label="Custom Roles">
                                                                        {allRoles.filter(r => !r.builtin).map(r => (
                                                                            <option key={r.id} value={r.id}>{r.name}</option>
                                                                        ))}
                                                                    </optgroup>
                                                                )}
                                                            </select>
                                                        </div>
                                                        <button onClick={() => { const m = [...ldapConfig.ldap_group_mappings]; m.splice(idx, 1); setLdapConfig(prev => ({...prev, ldap_group_mappings: m})); }}
                                                            className="p-1.5 text-red-400 hover:bg-red-500/10 rounded shrink-0"><Icons.Trash className="w-4 h-4" /></button>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        
                                        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-proxmox-border">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Default Role (no group match)</label>
                                                <select value={ldapConfig.ldap_default_role} onChange={e => setLdapConfig(prev => ({...prev, ldap_default_role: e.target.value}))} className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm">
                                                    <option value="viewer">Viewer</option>
                                                    <option value="user">User</option>
                                                    <option value="admin">Admin</option>
                                                    {allRoles.filter(r => !r.builtin).map(r => (
                                                        <option key={r.id} value={r.id}>{r.name}</option>
                                                    ))}
                                                </select>
                                            </div>
                                            <div className="flex items-end pb-1">
                                                <label className="flex items-center gap-2 cursor-pointer">
                                                    <input type="checkbox" checked={ldapConfig.ldap_auto_create_users} onChange={e => setLdapConfig(prev => ({...prev, ldap_auto_create_users: e.target.checked}))} className="w-4 h-4 accent-proxmox-orange" />
                                                    <span className="text-sm text-gray-300">Auto-create users on first login</span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Test Connection */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <h4 className="text-white font-medium">Test Connection</h4>
                                        <div className="flex items-end gap-3">
                                            <div className="flex-1">
                                                <label className="block text-sm text-gray-400 mb-1">Test Username (optional)</label>
                                                <input type="text" value={ldapTestUser} onChange={e => setLdapTestUser(e.target.value)} placeholder="e.g. jdoe" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                            </div>
                                            <button onClick={testLdapConnection} disabled={ldapTesting || !ldapConfig.ldap_server} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-white text-sm flex items-center gap-2 shrink-0">
                                                {ldapTesting ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Zap className="w-4 h-4" />}
                                                Test
                                            </button>
                                        </div>
                                        
                                        {ldapTestResult && (
                                            <div className={`p-3 rounded-lg border ${ldapTestResult.success ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                                                <p className={`font-medium text-sm ${ldapTestResult.success ? 'text-green-400' : 'text-red-400'}`}>
                                                    {ldapTestResult.success ? '✓ Connection Successful' : `✗ ${ldapTestResult.error}`}
                                                </p>
                                                {ldapTestResult.steps && (
                                                    <div className="mt-2 space-y-1">
                                                        {ldapTestResult.steps.map((step, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs">
                                                                <span className={step.status === 'ok' ? 'text-green-400' : step.status === 'warning' ? 'text-yellow-400' : 'text-red-400'}>
                                                                    {step.status === 'ok' ? '✓' : step.status === 'warning' ? '⚠' : '✗'}
                                                                </span>
                                                                <span className="text-gray-400">{step.step}</span>
                                                                {step.detail && typeof step.detail === 'string' && <span className="text-gray-500 font-mono">{step.detail}</span>}
                                                                {step.detail && typeof step.detail === 'object' && <span className="text-gray-500 font-mono">{step.detail.dn} ({step.detail.groups} groups)</span>}
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Save Button */}
                                    <div className="flex justify-end gap-3">
                                        {haStandby ? <HaSettingsOnActive /> : (
                                        <button onClick={saveLdapSettings} disabled={loading} className="px-6 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-white font-medium flex items-center gap-2">
                                            {loading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Save className="w-4 h-4" />}
                                            Save LDAP Settings
                                        </button>
                                        )}
                                    </div>
                                </div>
                            )}
                            
                            {/* NS: Feb 2026 - OIDC / Entra ID Tab */}
                            {activeTab === 'oidc' && (
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                            <Icons.Shield className="w-5 h-5" /> OIDC / Entra ID Authentication
                                        </h3>
                                    </div>
                                    <p className="text-sm text-gray-400">
                                        Configure OpenID Connect authentication with Microsoft Entra ID (Azure AD), Okta, Auth0, Keycloak, or any OIDC provider.
                                    </p>
                                    
                                    {/* Enable + Provider */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium">Connection</h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox" checked={oidcConfig.oidc_enabled} onChange={e => setOidcConfig(prev => ({...prev, oidc_enabled: e.target.checked}))}
                                                    className="w-4 h-4 rounded bg-proxmox-secondary border-proxmox-border" />
                                                <span className="text-sm text-gray-300">Enable OIDC</span>
                                            </label>
                                        </div>
                                        <div className="grid grid-cols-2 gap-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Provider</label>
                                                <select value={oidcConfig.oidc_provider} onChange={e => setOidcConfig(prev => ({...prev, oidc_provider: e.target.value}))}
                                                    className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm">
                                                    <option value="entra">Microsoft Entra ID (Azure AD)</option>
                                                    <option value="okta">Okta</option>
                                                    <option value="generic">Generic OIDC</option>
                                                </select>
                                            </div>
                                            {oidcConfig.oidc_provider === 'entra' ? (
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Tenant ID</label>
                                                    <input type="text" value={oidcConfig.oidc_tenant_id} onChange={e => setOidcConfig(prev => ({...prev, oidc_tenant_id: e.target.value}))}
                                                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                                </div>
                                            ) : (
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Authority / Issuer URL</label>
                                                    <input type="text" value={oidcConfig.oidc_authority} onChange={e => setOidcConfig(prev => ({...prev, oidc_authority: e.target.value}))}
                                                        placeholder="https://login.example.com/realms/master" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                                </div>
                                            )}
                                        </div>
                                        {oidcConfig.oidc_provider === 'entra' && (
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Cloud Environment</label>
                                                <select value={oidcConfig.oidc_cloud_environment || 'commercial'} onChange={e => setOidcConfig(prev => ({...prev, oidc_cloud_environment: e.target.value}))}
                                                    className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm">
                                                    <option value="commercial">Commercial (Global)</option>
                                                    <option value="gcc">GCC (Government Community Cloud)</option>
                                                    <option value="gcc_high">GCC High (US Government)</option>
                                                    <option value="dod">DoD (Department of Defense)</option>
                                                </select>
                                                {oidcConfig.oidc_cloud_environment && oidcConfig.oidc_cloud_environment !== 'commercial' && oidcConfig.oidc_cloud_environment !== 'gcc' && (
                                                    <p className="text-xs text-yellow-400 mt-1">⚠️ {oidcConfig.oidc_cloud_environment === 'gcc_high' ? 'GCC High' : 'DoD'} uses sovereign endpoints: login.microsoftonline.us / {oidcConfig.oidc_cloud_environment === 'dod' ? 'dod-graph.microsoft.us' : 'graph.microsoft.us'}</p>
                                                )}
                                            </div>
                                        )}
                                        <div className="grid grid-cols-2 gap-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Client ID (Application ID)</label>
                                                <input type="text" value={oidcConfig.oidc_client_id} onChange={e => setOidcConfig(prev => ({...prev, oidc_client_id: e.target.value}))}
                                                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Client Secret</label>
                                                <input type="password" value={oidcConfig.oidc_client_secret} onChange={e => setOidcConfig(prev => ({...prev, oidc_client_secret: e.target.value}))}
                                                    placeholder="••••••••" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-2 gap-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Scopes</label>
                                                <input type="text" value={oidcConfig.oidc_scopes} onChange={e => setOidcConfig(prev => ({...prev, oidc_scopes: e.target.value}))}
                                                    placeholder="openid profile email" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Redirect URI</label>
                                                <input type="text" value={oidcConfig.oidc_redirect_uri || `${window.location.origin}/oidc/callback`} onChange={e => setOidcConfig(prev => ({...prev, oidc_redirect_uri: e.target.value}))}
                                                    className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                                <p className="text-xs text-gray-600 mt-1">Register this URL in your identity provider</p>
                                            </div>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Login Button Text</label>
                                            <input type="text" value={oidcConfig.oidc_button_text} onChange={e => setOidcConfig(prev => ({...prev, oidc_button_text: e.target.value}))}
                                                placeholder="Sign in with Microsoft" className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                    </div>

                                    {/* NS: Mar 2026 - JWT verification toggle for broken JWKS environments */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium flex items-center gap-2">
                                                <Icons.Shield />
                                                {t('jwtVerification') || 'JWT Signature Verification'}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox"
                                                    checked={oidcConfig.oidc_skip_jwt_verification}
                                                    onChange={e => setOidcConfig(prev => ({...prev, oidc_skip_jwt_verification: e.target.checked}))}
                                                    className="rounded border-proxmox-border bg-proxmox-darker" />
                                                <span className="text-sm text-gray-300">{t('disableJwtVerification') || 'Disable Verification'}</span>
                                            </label>
                                        </div>
                                        {oidcConfig.oidc_skip_jwt_verification && (
                                            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                                <p className="text-sm text-red-400 font-medium mb-1">⚠ {t('securityWarning') || 'Security Warning'}</p>
                                                <p className="text-xs text-red-400/80">{t('jwtVerificationWarning') || 'Disabling JWT signature verification allows tokens to be accepted without cryptographic proof. This makes your login vulnerable to token forgery. Only disable this if your identity provider has a broken or unreachable JWKS endpoint and you understand the risk.'}</p>
                                            </div>
                                        )}
                                        {!oidcConfig.oidc_skip_jwt_verification && (
                                            <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                                                <p className="text-xs text-green-400">✓ {t('jwtVerificationEnabled') || 'JWT signatures are verified via JWKS endpoint. This is the recommended setting.'}</p>
                                            </div>
                                        )}
                                    </div>

                                    {/* NS Apr 2026 (#188): TLS verify toggle for self-hosted Authentik / Keycloak with self-signed certs */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium flex items-center gap-2">
                                                <Icons.Lock />
                                                {t('oidcTlsVerification') || 'IdP TLS Verification'}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox"
                                                    checked={oidcConfig.oidc_skip_ssl_verify}
                                                    onChange={e => setOidcConfig(prev => ({...prev, oidc_skip_ssl_verify: e.target.checked}))}
                                                    className="rounded border-proxmox-border bg-proxmox-darker" />
                                                <span className="text-sm text-gray-300">{t('skipTlsVerification') || 'Skip TLS verify'}</span>
                                            </label>
                                        </div>
                                        {oidcConfig.oidc_skip_ssl_verify ? (
                                            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                                <p className="text-sm text-red-400 font-medium mb-1">⚠ {t('securityWarning') || 'Security Warning'}</p>
                                                <p className="text-xs text-red-400/80">{t('oidcTlsWarning') || 'TLS certificate validation against the OIDC provider is disabled. Use only for self-hosted IdPs (Authentik, Keycloak) with self-signed certs in trusted networks. Anyone on the path can MITM the OIDC handshake.'}</p>
                                            </div>
                                        ) : (
                                            <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                                                <p className="text-xs text-green-400">✓ {t('oidcTlsEnabled') || 'TLS certificates from the OIDC provider are validated against system CA bundle. Required for production.'}</p>
                                            </div>
                                        )}
                                        <p className="text-[11px] text-gray-500 leading-snug">
                                            {t('oidcTlsHint') || 'Affects: discovery (.well-known/openid-configuration) and authorization-endpoint reachability checks. Token-exchange and JWKS calls also honor this flag.'}
                                        </p>
                                    </div>

                                    {/* MK May 2026 (#412 SeeJayEmm): opt-in private-IP allowlist for internal IdPs */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium flex items-center gap-2">
                                                <Icons.Globe />
                                                {t('oidcAllowPrivateIp') || 'Internal IdP / Private Network'}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input type="checkbox"
                                                    checked={oidcConfig.oidc_allow_private_ip}
                                                    onChange={e => setOidcConfig(prev => ({...prev, oidc_allow_private_ip: e.target.checked}))}
                                                    className="rounded border-proxmox-border bg-proxmox-darker" />
                                                <span className="text-sm text-gray-300">{t('allowPrivateIp') || 'Allow private IPs'}</span>
                                            </label>
                                        </div>
                                        {oidcConfig.oidc_allow_private_ip ? (
                                            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                <p className="text-sm text-yellow-400 font-medium mb-1">⚠ {t('oidcPrivateIpOptIn') || 'Opt-in active'}</p>
                                                <p className="text-xs text-yellow-300/80">{t('oidcPrivateIpWarning') || 'SSRF guard relaxed for OIDC discovery. Cloud metadata endpoints (169.254.x.x, fd00:ec2::, etc.) are still blocked. Make sure your IdP host is one you actually own.'}</p>
                                            </div>
                                        ) : (
                                            <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                                                <p className="text-xs text-green-400">✓ {t('oidcPrivateIpDisabled') || 'SSRF guard active — private/loopback IPs rejected. Turn on only if your IdP runs on an internal network (10.x / 192.168.x / 172.16-31.x).'}</p>
                                            </div>
                                        )}
                                        <p className="text-[11px] text-gray-500 leading-snug">
                                            {t('oidcPrivateIpHint') || 'Affects: the /.well-known/openid-configuration discovery call only. Other outbound paths (webhooks, plugin upstreams, SAML metadata) keep the strict guard.'}
                                        </p>
                                    </div>

                                    {/* NS May 2026 (PVE 9.2 parity) — extra audiences accepted on JWT verify */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-2">
                                        <h4 className="text-white font-medium flex items-center gap-2">
                                            <Icons.Key />
                                            {t('oidcAudiences') || 'Accepted Audiences'}
                                        </h4>
                                        <input type="text"
                                            value={oidcConfig.oidc_audiences || ''}
                                            onChange={e => setOidcConfig(prev => ({...prev, oidc_audiences: e.target.value}))}
                                            placeholder="comma-separated, e.g. pegaprox-prod, pegaprox-staging"
                                            className="w-full bg-proxmox-darker border border-proxmox-border rounded p-2 text-sm font-mono text-white" />
                                        <p className="text-[11px] text-gray-500 leading-snug">
                                            {t('oidcAudiencesHint') || 'Additional audience values accepted on the JWT verify alongside the client_id. Useful when one logical audience is shared across multiple deployments.'}
                                        </p>
                                    </div>

                                    {/* NS: Feb 2026 - Unified Group-Role Mapping */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-white font-medium">Group ↑ Role Mapping</h4>
                                            <button onClick={() => setOidcConfig(prev => ({...prev, oidc_group_mappings: [...prev.oidc_group_mappings, {group_id: '', role: 'viewer'}]}))}
                                                className="px-2 py-1 bg-proxmox-secondary border border-proxmox-border rounded text-xs text-gray-300 hover:text-white hover:bg-proxmox-hover flex items-center gap-1">
                                                <Icons.Plus className="w-3 h-3" /> Add Mapping
                                            </button>
                                        </div>
                                        <p className="text-xs text-gray-500">{oidcConfig.oidc_provider === 'entra' ? 'Map Entra groups to PegaProx roles. Use group Object IDs (Azure Portal ↑ Groups ↑ Overview).' : 'Map provider groups to PegaProx roles (including custom roles).'}</p>
                                        
                                        {oidcConfig.oidc_group_mappings.length === 0 ? (
                                            <p className="text-gray-600 text-sm text-center py-4 border border-dashed border-proxmox-border rounded-lg">No group mappings configured. Click "Add Mapping" to map a group to a role.</p>
                                        ) : (
                                            <div className="space-y-2">
                                                {oidcConfig.oidc_group_mappings.map((mapping, idx) => (
                                                    <div key={idx} className="flex items-center gap-2 p-2 bg-proxmox-secondary rounded-lg border border-proxmox-border">
                                                        <div className="flex-1">
                                                            <input type="text" value={mapping.group_id} placeholder={oidcConfig.oidc_provider === 'entra' ? 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' : 'GroupName'}
                                                                onChange={e => { const m = [...oidcConfig.oidc_group_mappings]; m[idx] = {...m[idx], group_id: e.target.value}; setOidcConfig(prev => ({...prev, oidc_group_mappings: m})); }}
                                                                className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm font-mono" />
                                                        </div>
                                                        <Icons.ArrowRight className="w-4 h-4 text-gray-500 shrink-0" />
                                                        <div className="w-44 shrink-0">
                                                            <select value={mapping.role || 'viewer'}
                                                                onChange={e => { const m = [...oidcConfig.oidc_group_mappings]; m[idx] = {...m[idx], role: e.target.value}; setOidcConfig(prev => ({...prev, oidc_group_mappings: m})); }}
                                                                className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                                <optgroup label="Built-in">
                                                                    <option value="admin">Admin</option>
                                                                    <option value="user">User</option>
                                                                    <option value="viewer">Viewer</option>
                                                                </optgroup>
                                                                {allRoles.filter(r => !r.builtin).length > 0 && (
                                                                    <optgroup label="Custom Roles">
                                                                        {allRoles.filter(r => !r.builtin).map(r => (
                                                                            <option key={r.id} value={r.id}>{r.name}</option>
                                                                        ))}
                                                                    </optgroup>
                                                                )}
                                                            </select>
                                                        </div>
                                                        <button onClick={() => { const m = [...oidcConfig.oidc_group_mappings]; m.splice(idx, 1); setOidcConfig(prev => ({...prev, oidc_group_mappings: m})); }}
                                                            className="p-1.5 text-red-400 hover:bg-red-500/10 rounded shrink-0"><Icons.Trash className="w-4 h-4" /></button>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        
                                        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-proxmox-border">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Default Role (no group match)</label>
                                                <select value={oidcConfig.oidc_default_role} onChange={e => setOidcConfig(prev => ({...prev, oidc_default_role: e.target.value}))}
                                                    className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm">
                                                    <option value="viewer">Viewer</option>
                                                    <option value="user">User</option>
                                                    <option value="admin">Admin</option>
                                                    {allRoles.filter(r => !r.builtin).map(r => (
                                                        <option key={r.id} value={r.id}>{r.name}</option>
                                                    ))}
                                                </select>
                                            </div>
                                            <div className="flex items-end pb-1">
                                                <label className="flex items-center gap-2 cursor-pointer">
                                                    <input type="checkbox" checked={oidcConfig.oidc_auto_create_users} onChange={e => setOidcConfig(prev => ({...prev, oidc_auto_create_users: e.target.checked}))}
                                                        className="w-4 h-4 rounded bg-proxmox-secondary border-proxmox-border" />
                                                    <span className="text-sm text-gray-300">Auto-create users on first login</span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Test Connection */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <h4 className="text-white font-medium">Test Configuration</h4>
                                        <button onClick={testOidcConnection} disabled={oidcTesting || !oidcConfig.oidc_client_id} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-white text-sm flex items-center gap-2">
                                            {oidcTesting ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Zap className="w-4 h-4" />}
                                            Test Endpoints
                                        </button>
                                        {oidcTestResult && (
                                            <div className="space-y-1.5">
                                                {oidcTestResult.results && oidcTestResult.results.map((r, i) => (
                                                    <div key={i} className={`flex items-center gap-2 text-sm ${r.status === 'ok' ? 'text-green-400' : r.status === 'warning' ? 'text-yellow-400' : 'text-red-400'}`}>
                                                        {r.status === 'ok' ? <Icons.Check className="w-4 h-4" /> : r.status === 'warning' ? <Icons.AlertTriangle className="w-4 h-4" /> : <Icons.X className="w-4 h-4" />}
                                                        <span className="font-medium">{r.step}:</span> <span className="text-gray-400 truncate">{r.detail}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Entra Setup Guide */}
                                    {oidcConfig.oidc_provider === 'entra' && (
                                        <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 space-y-2">
                                            <h4 className="text-blue-400 font-medium flex items-center gap-2"><Icons.Info className="w-4 h-4" /> Entra ID Setup Guide</h4>
                                            <ol className="text-sm text-gray-400 space-y-1 list-decimal list-inside">
                                                <li>Azure Portal ↑ Entra ID ↑ App registrations ↑ New registration</li>
                                                <li>Set Redirect URI to: <code className="text-blue-300 bg-proxmox-dark px-1 rounded">{oidcConfig.oidc_redirect_uri || `${window.location.origin}/oidc/callback`}</code></li>
                                                <li>Copy Application (client) ID ↑ paste as Client ID above</li>
                                                <li>Certificates & secrets ↑ New client secret ↑ paste above</li>
                                                <li>API permissions ↑ Add: <code className="text-blue-300 bg-proxmox-dark px-1 rounded">openid, profile, email, User.Read, GroupMember.Read.All</code></li>
                                                <li>Token configuration ↑ Add groups claim (Security groups)</li>
                                                <li>Copy Directory (tenant) ID ↑ paste as Tenant ID above</li>
                                            </ol>
                                        </div>
                                    )}
                                    
                                    {/* Save */}
                                    <div className="flex justify-end pt-2">
                                        {haStandby ? <HaSettingsOnActive /> : (
                                        <button onClick={saveOidcSettings} disabled={loading} className="px-6 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-white font-medium flex items-center gap-2">
                                            {loading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Save className="w-4 h-4" />}
                                            Save OIDC Settings
                                        </button>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* Syslog Server Settings Tab */}
                            {activeTab === 'syslog' && (
                                <div className="space-y-6">
                                    <h3 className="text-lg font-semibold text-white">{t('syslogServer') || 'Syslog Server'}</h3>

                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <div className="flex items-center justify-between gap-4">
                                            <div>
                                                <h4 className="font-medium text-white flex items-center gap-2">
                                                    <Icons.FileText />
                                                    {t('syslogEnabled') || 'Syslog receiver'}
                                                </h4>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('syslogEnabledDesc') || 'Listen for syslog messages on UDP/TCP port 1514. Disable to close the port if PegaProx does not ingest syslog from your nodes.'}
                                                </p>
                                            </div>
                                            <label className="flex items-center gap-2 cursor-pointer shrink-0">
                                                <input
                                                    type="checkbox"
                                                    checked={!!serverSettings.syslog_enabled}
                                                    onChange={e => setServerSettings({...serverSettings, syslog_enabled: e.target.checked})}
                                                    className="rounded border-proxmox-border bg-proxmox-darker"
                                                />
                                                <span className="text-sm text-gray-300">{t('enabled') || 'Enabled'}</span>
                                            </label>
                                        </div>

                                        <div className="flex items-center justify-between gap-4 border-t border-proxmox-border pt-4">
                                            <div>
                                                <h4 className="font-medium text-white flex items-center gap-2">
                                                    <Icons.FileText />
                                                    {t('syslogClusterFilter') || 'Cluster-scoped syslog viewer'}
                                                </h4>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('syslogClusterFilterDesc') || 'When enabled, the Syslog chapter only shows log rows whose hostname belongs to the selected cluster or one of its nodes.'}
                                                </p>
                                            </div>
                                            <label className="flex items-center gap-2 cursor-pointer shrink-0">
                                                <input
                                                    type="checkbox"
                                                    checked={!!serverSettings.syslog_filter_by_selected_cluster}
                                                    onChange={e => setServerSettings({...serverSettings, syslog_filter_by_selected_cluster: e.target.checked})}
                                                    className="rounded border-proxmox-border bg-proxmox-darker"
                                                />
                                                <span className="text-sm text-gray-300">{t('enabled') || 'Enabled'}</span>
                                            </label>
                                        </div>

                                        <div className="pt-3 flex justify-end border-t border-proxmox-border">
                                            {haStandby ? <HaSettingsOnActive own /> : (
                                            <button
                                                onClick={async () => {
                                                    setServerLoading(true);
                                                    try {
                                                        const response = await fetch(`${API_URL}/settings/server`, {
                                                            method: 'POST',
                                                            credentials: 'include',
                                                            headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                            body: JSON.stringify({
                                                                syslog_filter_by_selected_cluster: !!serverSettings.syslog_filter_by_selected_cluster,
                                                                syslog_enabled: !!serverSettings.syslog_enabled
                                                            })
                                                        });
                                                        if (response && response.ok) {
                                                            addToast(t('settingsSaved') || 'Settings saved', 'success');
                                                            fetchServerSettings();
                                                        } else {
                                                            const err = await response.json().catch(() => ({}));
                                                            addToast(err.error || t('errorSavingSettings') || 'Error saving settings', 'error');
                                                        }
                                                    } catch (err) {
                                                        addToast(t('errorSavingSettings') || 'Error saving settings', 'error');
                                                    }
                                                    setServerLoading(false);
                                                }}
                                                disabled={serverLoading}
                                                className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                                            >
                                                {serverLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                {t('saveSettings') || t('save') || 'Save'}
                                            </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Server Settings Tab */}
                            {activeTab === 'server' && (
                                <div className="space-y-6">
                                    <h3 className="text-lg font-semibold text-white">{t('serverSettings')}</h3>
                                    
                                    {/* Default Theme for New Users */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="font-medium text-white flex items-center gap-2">
                                            <Icons.Palette />
                                            {t('defaultTheme') || 'Default Theme'}
                                        </h4>
                                        <p className="text-sm text-gray-400">
                                            {t('defaultThemeDesc') || 'Set the default theme for new users. Users can change their theme in My Profile.'}
                                        </p>
                                        
                                        <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 gap-2">
                                            {Object.entries(PEGAPROX_THEMES).map(([key, theme]) => {
                                                const isActive = (serverSettings.default_theme || 'proxmoxDark') === key;
                                                return (
                                                    <button
                                                        key={key}
                                                        onClick={() => setServerSettings({...serverSettings, default_theme: key})}
                                                        className={`p-2 rounded-lg border-2 transition-all hover:scale-105 ${
                                                            isActive 
                                                                ? 'border-proxmox-orange ring-2 ring-proxmox-orange/30' 
                                                                : 'border-proxmox-border hover:border-gray-500'
                                                        }`}
                                                        title={theme.name}
                                                    >
                                                        <div 
                                                            className="h-8 rounded mb-1 relative overflow-hidden"
                                                            style={{ 
                                                                background: theme.colors.darker,
                                                                border: `1px solid ${theme.colors.border}`
                                                            }}
                                                        >
                                                            <div 
                                                                className="absolute inset-1 rounded"
                                                                style={{ background: theme.colors.card }}
                                                            >
                                                                <div 
                                                                    className="w-1/2 h-1 rounded-full m-1"
                                                                    style={{ background: theme.colors.primary }}
                                                                />
                                                            </div>
                                                            {isActive && (
                                                                <div className="absolute top-0 right-0 bg-proxmox-orange rounded-full p-0.5">
                                                                    <Icons.Check className="w-2 h-2 text-white" />
                                                                </div>
                                                            )}
                                                        </div>
                                                        <div className="text-center text-xs truncate">
                                                            {theme.icon}
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                        <p className="text-xs text-gray-500">
                                            {t('currentDefault') || 'Current default'}: {PEGAPROX_THEMES[serverSettings.default_theme || 'proxmoxDark']?.name || 'Proxmox Dark'}
                                        </p>
                                    </div>

                                    {/* Login Background - NS Mar 2026 */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3">
                                        <h4 className="font-medium text-white flex items-center gap-2">
                                            <Icons.Image />
                                            {t('loginBackground')}
                                        </h4>
                                        <p className="text-sm text-gray-400">{t('loginBackgroundDesc')}</p>

                                        {serverSettings.login_background && (
                                            <div className="flex items-center gap-3">
                                                <img src={serverSettings.login_background} alt="Login bg" className="h-16 rounded border border-proxmox-border object-cover" />
                                                <button
                                                    onClick={async () => {
                                                        try {
                                                            const r = await fetch(`${API_URL}/settings/login-background`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                                                            if (r.ok) {
                                                                addToast(t('loginBackgroundDeleted'), 'success');
                                                                setServerSettings(prev => ({...prev, login_background: ''}));
                                                            }
                                                        } catch(e) { addToast('Error', 'error'); }
                                                    }}
                                                    className="px-3 py-1.5 bg-red-500/20 text-red-400 rounded-lg text-sm hover:bg-red-500/30 transition-colors"
                                                >
                                                    {t('removeBackground')}
                                                </button>
                                            </div>
                                        )}

                                        <input
                                            type="file"
                                            accept=".png,.jpg,.jpeg,.webp,.svg"
                                            onChange={e => {
                                                const file = e.target.files[0];
                                                if (file && file.size > 2 * 1024 * 1024) {
                                                    setLoginBgError(t('loginBackgroundTooLarge'));
                                                    e.target.value = '';
                                                    setLoginBgFile(null);
                                                } else {
                                                    setLoginBgError(null);
                                                    setLoginBgFile(file || null);
                                                }
                                            }}
                                            className="block w-full text-sm text-gray-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-sm file:bg-proxmox-orange/20 file:text-proxmox-orange hover:file:bg-proxmox-orange/30 file:cursor-pointer"
                                        />
                                        {loginBgError && (
                                            <p className="text-xs text-red-400">{loginBgError}</p>
                                        )}
                                        {loginBgFile && (
                                            <p className="text-xs text-green-400">{loginBgFile.name} ({(loginBgFile.size / 1024).toFixed(0)} KB)</p>
                                        )}
                                    </div>

                                    {/* Domain & Port */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="font-medium text-white flex items-center gap-2">
                                            <Icons.Globe />
                                            {t('networkSettings')}
                                        </h4>
                                        
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('domain')}</label>
                                                <input
                                                    type="text"
                                                    value={serverSettings.domain}
                                                    onChange={e => setServerSettings({...serverSettings, domain: e.target.value})}
                                                    placeholder="pegaprox.example.com"
                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                />
                                                <p className="text-xs text-gray-500 mt-1">{t('domainHint')}</p>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('port')}</label>
                                                <input
                                                    type="number"
                                                    value={serverSettings.port}
                                                    onChange={e => setServerSettings({...serverSettings, port: parseInt(e.target.value)})}
                                                    min="1"
                                                    max="65535"
                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                />
                                                <p className="text-xs text-gray-500 mt-1">{t('portHint')}</p>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('httpRedirectPort') || 'HTTP Redirect Port'}</label>
                                                <input
                                                    type="number"
                                                    value={serverSettings.http_redirect_port || 0}
                                                    onChange={e => setServerSettings({...serverSettings, http_redirect_port: parseInt(e.target.value)})}
                                                    min="-1"
                                                    max="65535"
                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                />
                                                <p className="text-xs text-gray-500 mt-1">{t('httpRedirectPortHint') || '0 = auto (80 if root), -1 = disabled'}</p>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Reverse Proxy */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <div className="flex items-center justify-between">
                                            <h4 className="font-medium text-white flex items-center gap-2">
                                                <Icons.Shield />
                                                {t('reverseProxy')}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={serverSettings.reverse_proxy_enabled}
                                                    onChange={e => setServerSettings({...serverSettings, reverse_proxy_enabled: e.target.checked})}
                                                    className="rounded border-proxmox-border bg-proxmox-darker"
                                                />
                                                <span className="text-sm text-gray-300">{t('reverseProxyEnabled')}</span>
                                            </label>
                                        </div>

                                        {serverSettings.reverse_proxy_enabled && (
                                            <div className="space-y-3 pt-1">
                                                <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                                                    <p className="text-sm text-blue-400">{t('reverseProxyHint')}</p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('trustedProxies')}</label>
                                                    <input
                                                        type="text"
                                                        value={serverSettings.trusted_proxies}
                                                        onChange={e => setServerSettings({...serverSettings, trusted_proxies: e.target.value})}
                                                        placeholder="10.0.0.1, 172.16.0.0/12"
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    />
                                                    <p className="text-xs text-gray-500 mt-1">{t('trustedProxiesHint')}</p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('proxyBindAddress')}</label>
                                                    <input
                                                        type="text"
                                                        value={serverSettings.proxy_bind_address}
                                                        onChange={e => setServerSettings({...serverSettings, proxy_bind_address: e.target.value})}
                                                        placeholder="127.0.0.1"
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                    />
                                                    <p className="text-xs text-gray-500 mt-1">{t('proxyBindAddressHint')}</p>
                                                </div>
                                                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                    <p className="text-sm text-yellow-400">{t('reverseProxyWarning')}</p>
                                                </div>
                                            </div>
                                        )}
                                    </div>

                                    {/* SSL/TLS Settings */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <div className="flex items-center justify-between">
                                            <h4 className="font-medium text-white flex items-center gap-2">
                                                <Icons.Shield />
                                                {t('sslSettings')}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={serverSettings.ssl_enabled}
                                                    onChange={e => setServerSettings({...serverSettings, ssl_enabled: e.target.checked})}
                                                    className="rounded border-proxmox-border bg-proxmox-darker"
                                                />
                                                <span className="text-sm text-gray-300">{t('enableSsl')}</span>
                                            </label>
                                        </div>
                                        {/* LW Sep 2026 (#638) - the label reads like a master switch for TLS and
                                            isn't one: since the fail-closed work HTTPS is served either way, and
                                            unchecking this only means "no certificate of my own". Someone read the
                                            code expecting the off position to do something and filed a bug about
                                            it, which is fair — a toggle shouldn't need the source to understand. */}
                                        <p className="text-xs text-gray-500 -mt-2">{t('sslAlwaysOnNote') || 'HTTPS is always on. This switch only controls whether your own certificate is used.'}</p>
                                        
                                        {serverSettings.ssl_enabled && (
                                            <div className="space-y-4 pt-2">
                                                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                    <p className="text-sm text-yellow-400">
                                                        ⚠️ {t('sslWarning')}
                                                    </p>
                                                </div>
                                                
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('sslCertificate')} (.pem, .crt)</label>
                                                    <div className="flex gap-2">
                                                        <input
                                                            type="text"
                                                            value={serverSettings.ssl_cert}
                                                            readOnly
                                                            placeholder={t('noCertSelected')}
                                                            className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                        <label className="px-4 py-2 bg-proxmox-hover hover:bg-proxmox-border rounded-lg text-sm cursor-pointer transition-colors">
                                                            <input
                                                                type="file"
                                                                accept=".pem,.crt,.cer"
                                                                onChange={e => handleCertFileChange(e, 'cert')}
                                                                className="hidden"
                                                            />
                                                            {t('browse')}
                                                        </label>
                                                    </div>
                                                </div>
                                                
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('sslKey')} (.pem, .key)</label>
                                                    <div className="flex gap-2">
                                                        <input
                                                            type="text"
                                                            value={serverSettings.ssl_key}
                                                            readOnly
                                                            placeholder={t('noKeySelected')}
                                                            className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                        <label className="px-4 py-2 bg-proxmox-hover hover:bg-proxmox-border rounded-lg text-sm cursor-pointer transition-colors">
                                                            <input
                                                                type="file"
                                                                accept=".pem,.key"
                                                                onChange={e => handleCertFileChange(e, 'key')}
                                                                className="hidden"
                                                            />
                                                            {t('browse')}
                                                        </label>
                                                    </div>
                                                </div>
                                                
                                                <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                                                    <p className="text-sm text-blue-400">
                                                        💡 {t('sslHint')}
                                                    </p>
                                                </div>
                                            </div>
                                        )}

                                        {/* MK: Mar 2026 - ACME / Let's Encrypt section (#96) */}
                                        <div className="mt-4 pt-4 border-t border-proxmox-border">
                                            <h4 className="font-medium text-white flex items-center gap-2 mb-3">
                                                🔒 {t('acmeTitle')}
                                            </h4>

                                            {/* cert status */}
                                            {serverSettings.cert_info && (
                                                <div className={`p-3 rounded-lg mb-3 ${serverSettings.cert_info.is_self_signed ? 'bg-yellow-500/10 border border-yellow-500/30' : serverSettings.cert_info.days_left > 30 ? 'bg-emerald-500/10 border border-emerald-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                                                    <div className="text-sm space-y-1">
                                                        <div className="flex justify-between">
                                                            <span className="text-gray-400">{t('acmeIssuer')}:</span>
                                                            <span className={serverSettings.cert_info.is_self_signed ? 'text-yellow-400' : 'text-white'}>{serverSettings.cert_info.is_self_signed ? t('acmeSelfSigned') : serverSettings.cert_info.issuer}</span>
                                                        </div>
                                                        {!serverSettings.cert_info.is_self_signed && (
                                                            <>
                                                                <div className="flex justify-between">
                                                                    <span className="text-gray-400">{t('acmeExpires')}:</span>
                                                                    <span className="text-white">{new Date(serverSettings.cert_info.expires).toLocaleDateString()}</span>
                                                                </div>
                                                                <div className="flex justify-between">
                                                                    <span className="text-gray-400">{t('acmeDaysLeft')}:</span>
                                                                    <span className={serverSettings.cert_info.days_left > 30 ? 'text-emerald-400' : 'text-red-400'}>{serverSettings.cert_info.days_left}</span>
                                                                </div>
                                                            </>
                                                        )}
                                                        {serverSettings.cert_info.is_letsencrypt && serverSettings.acme_enabled && (
                                                            <div className="text-emerald-400 text-xs mt-1">✓ {t('acmeAutoRenew')}</div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            <div className="space-y-3">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('acmeProvider') || 'ACME Provider'}</label>
                                                    <select
                                                        value={serverSettings.acme_provider || 'letsencrypt'}
                                                        onChange={e => setServerSettings({...serverSettings, acme_provider: e.target.value, acme_directory_url: e.target.value === 'custom' ? serverSettings.acme_directory_url : ''})}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="letsencrypt">Let's Encrypt</option>
                                                        <option value="custom">{t('acmeProviderCustom') || 'Custom ACME CA'}</option>
                                                    </select>
                                                </div>

                                                {serverSettings.acme_provider === 'custom' && (
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('acmeDirectoryUrl') || 'ACME Directory URL'}</label>
                                                        <input
                                                            type="url"
                                                            value={serverSettings.acme_directory_url || ''}
                                                            onChange={e => setServerSettings({...serverSettings, acme_directory_url: e.target.value})}
                                                            placeholder="https://step-ca.example.com/acme/acme/directory"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                        <p className="text-xs text-gray-500 mt-1">{t('acmeDirectoryUrlHint') || 'ACME directory endpoint of your CA (must be HTTPS)'}</p>
                                                        <label className="flex items-center gap-2 cursor-pointer mt-2">
                                                            <input
                                                                type="checkbox"
                                                                checked={!!serverSettings.acme_allow_private_ca}
                                                                onChange={e => setServerSettings({...serverSettings, acme_allow_private_ca: e.target.checked})}
                                                                className="rounded border-proxmox-border bg-proxmox-darker"
                                                            />
                                                            <span className="text-sm text-gray-300">{t('acmeAllowPrivateCa') || 'Allow private/internal ACME CA'}</span>
                                                            <span className="text-xs text-gray-500">({t('acmeAllowPrivateCaHint') || 'permit an RFC1918/loopback directory, e.g. an internal StepCA'})</span>
                                                        </label>
                                                    </div>
                                                )}

                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('acmeEmail')}</label>
                                                    <input
                                                        type="email"
                                                        value={serverSettings.acme_email}
                                                        onChange={e => setServerSettings({...serverSettings, acme_email: e.target.value})}
                                                        placeholder="admin@example.com"
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    />
                                                    <p className="text-xs text-gray-500 mt-1">{serverSettings.acme_provider === 'letsencrypt' ? t('acmeEmailHint') : (t('acmeEmailOptionalHint') || 'Optional for custom ACME servers')}</p>
                                                </div>

                                                {serverSettings.acme_provider === 'letsencrypt' && (
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={serverSettings.acme_staging}
                                                            onChange={e => setServerSettings({...serverSettings, acme_staging: e.target.checked})}
                                                            className="rounded border-proxmox-border bg-proxmox-darker"
                                                        />
                                                        <span className="text-sm text-gray-300">{t('acmeStaging')}</span>
                                                        <span className="text-xs text-gray-500">({t('acmeStagingHint')})</span>
                                                    </label>
                                                )}

                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('acmeChallengeType') || 'Challenge Type'}</label>
                                                    <select
                                                        value={serverSettings.acme_challenge_type || 'http-01'}
                                                        onChange={e => {
                                                            setServerSettings({...serverSettings, acme_challenge_type: e.target.value});
                                                            setAcmeResult(null);
                                                        }}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="http-01">{t('acmeChallengeHttp') || 'HTTP-01'}</option>
                                                        <option value="dns-01">{t('acmeChallengeDns') || 'DNS-01'}</option>
                                                    </select>
                                                </div>

                                                {(serverSettings.acme_challenge_type || 'http-01') === 'dns-01' && (
                                                    <>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">{t('acmeDnsProvider') || 'DNS Provider'}</label>
                                                            <select
                                                                value={serverSettings.acme_dns_provider || 'manual'}
                                                                onChange={e => setServerSettings({...serverSettings, acme_dns_provider: e.target.value})}
                                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                            >
                                                                <option value="manual">{t('acmeDnsProviderManual') || 'Manual TXT Record'}</option>
                                                                <option value="rfc2136">{t('acmeDnsProviderRfc2136') || 'RFC 2136 Dynamic DNS'}</option>
                                                                <option value="cloudflare">{t('acmeDnsProviderCloudflare') || 'Cloudflare'}</option>
                                                            </select>
                                                        </div>

                                                        {(serverSettings.acme_dns_provider || 'manual') === 'rfc2136' && (
                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsNameserver') || 'Nameserver'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_rfc2136_nameserver || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_nameserver: e.target.value})}
                                                                        placeholder="192.0.2.53"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsPort') || 'Port'}</label>
                                                                    <input
                                                                        type="number"
                                                                        min="1"
                                                                        max="65535"
                                                                        value={serverSettings.acme_dns_rfc2136_port || 53}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_port: parseInt(e.target.value) || 53})}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsZone') || 'Zone'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_rfc2136_zone || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_zone: e.target.value})}
                                                                        placeholder="example.com"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsKeyName') || 'TSIG Key Name'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_rfc2136_key_name || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_key_name: e.target.value})}
                                                                        placeholder="mein-certbot-key"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsAlgorithm') || 'TSIG Algorithm'}</label>
                                                                    <select
                                                                        value={serverSettings.acme_dns_rfc2136_algorithm || 'hmac-sha512'}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_algorithm: e.target.value})}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    >
                                                                        <option value="hmac-sha512">hmac-sha512</option>
                                                                        <option value="hmac-sha384">hmac-sha384</option>
                                                                        <option value="hmac-sha256">hmac-sha256</option>
                                                                        <option value="hmac-sha224">hmac-sha224</option>
                                                                        <option value="hmac-sha1">hmac-sha1</option>
                                                                        <option value="hmac-md5">hmac-md5</option>
                                                                    </select>
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsSecret') || 'TSIG Secret'}</label>
                                                                    <input
                                                                        type="password"
                                                                        value={serverSettings.acme_dns_rfc2136_secret || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_secret: e.target.value})}
                                                                        placeholder="IHR_GENERIERTER_BASE64_SECRET_STRING"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsTtl') || 'TXT TTL'}</label>
                                                                    <input
                                                                        type="number"
                                                                        min="1"
                                                                        max="86400"
                                                                        value={serverSettings.acme_dns_rfc2136_ttl || 60}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_rfc2136_ttl: parseInt(e.target.value) || 60})}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsPropagation') || 'Propagation Wait (seconds)'}</label>
                                                                    <input
                                                                        type="number"
                                                                        min="0"
                                                                        max="600"
                                                                        value={serverSettings.acme_dns_propagation_seconds || 30}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_propagation_seconds: parseInt(e.target.value) || 0})}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                            </div>
                                                        )}

                                                        {(serverSettings.acme_dns_provider || 'manual') === 'cloudflare' && (
                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                                <div className="md:col-span-2">
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsCloudflareToken') || 'API Token'}</label>
                                                                    <input
                                                                        type="password"
                                                                        value={serverSettings.acme_dns_cloudflare_token || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_cloudflare_token: e.target.value})}
                                                                        placeholder="Cloudflare API token"
                                                                        autoComplete="off"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                    <p className="text-xs text-gray-500 mt-1">{t('acmeDnsCloudflareTokenHint') || 'Scoped token: Zone → DNS → Edit on the target zone. Zone → Zone → Read is needed for auto-detect; otherwise set the Zone ID.'}</p>
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsCloudflareZone') || 'Zone (optional)'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_cloudflare_zone || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_cloudflare_zone: e.target.value})}
                                                                        placeholder={t('acmeDnsCloudflareZonePlaceholder') || 'Auto-detect from domain'}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsCloudflareZoneId') || 'Zone ID (optional)'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_cloudflare_zone_id || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_cloudflare_zone_id: e.target.value})}
                                                                        placeholder="32-character zone id"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm font-mono"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsCloudflareAccountId') || 'Account ID (optional)'}</label>
                                                                    <input
                                                                        type="text"
                                                                        value={serverSettings.acme_dns_cloudflare_account_id || ''}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_cloudflare_account_id: e.target.value})}
                                                                        placeholder="If auto-detect is ambiguous"
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm font-mono"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsPropagation') || 'Propagation Wait (seconds)'}</label>
                                                                    <input
                                                                        type="number"
                                                                        min="0"
                                                                        max="600"
                                                                        value={serverSettings.acme_dns_propagation_seconds || 30}
                                                                        onChange={e => setServerSettings({...serverSettings, acme_dns_propagation_seconds: parseInt(e.target.value) || 0})}
                                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                    />
                                                                </div>
                                                            </div>
                                                        )}
                                                    </>
                                                )}

                                                <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                                                    <p className="text-xs text-blue-400">
                                                        {(serverSettings.acme_challenge_type || 'http-01') === 'dns-01'
                                                            ? ((serverSettings.acme_dns_provider || 'manual') === 'rfc2136'
                                                                ? (t('acmeDnsRfc2136Hint') || 'RFC 2136 will create and remove the _acme-challenge TXT record automatically using TSIG.')
                                                                : ((serverSettings.acme_dns_provider || 'manual') === 'cloudflare'
                                                                    ? (t('acmeDnsCloudflareHint') || 'Cloudflare will create and remove the _acme-challenge TXT record automatically via the DNS API.')
                                                                    : (t('acmeDnsHint') || 'DNS-01 requires a TXT record at _acme-challenge for this request. The record value is shown after preparing the challenge.')))
                                                            : t('acmePort80')}
                                                    </p>
                                                </div>

                                                {acmeResult?.pending_dns && !haStandby && (
                                                    <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg space-y-3">
                                                        <p className="text-sm text-amber-300">{t('acmeDnsInstructions') || 'Create this TXT record, wait for DNS propagation, then continue validation.'}</p>
                                                        <div>
                                                            <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsName') || 'TXT Name'}</label>
                                                            <input
                                                                readOnly
                                                                value={acmeResult.dns_name || ''}
                                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm font-mono"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-xs text-gray-400 mb-1">{t('acmeDnsValue') || 'TXT Value'}</label>
                                                            <textarea
                                                                readOnly
                                                                value={acmeResult.dns_value || ''}
                                                                rows="2"
                                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm font-mono resize-none"
                                                            />
                                                        </div>
                                                        <button
                                                            onClick={handleAcmeDnsComplete}
                                                            disabled={acmeLoading}
                                                            className="w-full px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
                                                        >
                                                            {acmeLoading ? t('acmeRequesting') : (t('acmeDnsContinue') || 'Continue DNS Validation')}
                                                        </button>
                                                    </div>
                                                )}

                                                {acmeResult && !acmeResult.success && !acmeResult.pending_dns && (
                                                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                                        <p className="text-sm text-red-400">{acmeResult.message}</p>
                                                    </div>
                                                )}

                                                {haStandby ? <HaSettingsOnActive own /> : (
                                                <button
                                                    onClick={handleAcmeRequest}
                                                    disabled={acmeLoading || !serverSettings.domain || (serverSettings.acme_provider === 'letsencrypt' && !serverSettings.acme_email) || (serverSettings.acme_provider === 'custom' && !serverSettings.acme_directory_url) || ((serverSettings.acme_challenge_type || 'http-01') === 'dns-01' && (serverSettings.acme_dns_provider || 'manual') === 'rfc2136' && (!serverSettings.acme_dns_rfc2136_nameserver || !serverSettings.acme_dns_rfc2136_zone || !serverSettings.acme_dns_rfc2136_key_name || !serverSettings.acme_dns_rfc2136_secret)) || ((serverSettings.acme_challenge_type || 'http-01') === 'dns-01' && (serverSettings.acme_dns_provider || 'manual') === 'cloudflare' && !serverSettings.acme_dns_cloudflare_token)}
                                                    className="w-full px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
                                                >
                                                    {acmeLoading ? t('acmeRequesting') : ((serverSettings.acme_challenge_type || 'http-01') === 'dns-01' && (serverSettings.acme_dns_provider || 'manual') === 'manual' ? (t('acmeDnsPrepare') || 'Prepare DNS Challenge') : t('acmeRequest'))}
                                                </button>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* NS: SMTP Settings - Dec 2025 */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <div className="flex items-center justify-between">
                                            <h4 className="font-medium text-white flex items-center gap-2">
                                                <Icons.Mail />
                                                {t('smtpSettings')}
                                            </h4>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={serverSettings.smtp_enabled}
                                                    onChange={e => setServerSettings({...serverSettings, smtp_enabled: e.target.checked})}
                                                    className="rounded border-proxmox-border bg-proxmox-darker"
                                                />
                                                <span className="text-sm text-gray-300">{t('enabled')}</span>
                                            </label>
                                        </div>
                                        
                                        {serverSettings.smtp_enabled && (
                                            <div className="space-y-4 pt-2">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpHost')}</label>
                                                        <input
                                                            type="text"
                                                            value={serverSettings.smtp_host}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_host: e.target.value})}
                                                            placeholder="smtp.gmail.com"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpPort')}</label>
                                                        <input
                                                            type="number"
                                                            value={serverSettings.smtp_port}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_port: parseInt(e.target.value)})}
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                </div>
                                                
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpUser')}</label>
                                                        <input
                                                            type="text"
                                                            value={serverSettings.smtp_user}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_user: e.target.value})}
                                                            placeholder="user@example.com"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpPassword')}</label>
                                                        <input
                                                            type="password"
                                                            value={serverSettings.smtp_password}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_password: e.target.value})}
                                                            placeholder="••••••••"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                </div>
                                                
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpFromEmail')}</label>
                                                        <input
                                                            type="email"
                                                            value={serverSettings.smtp_from_email}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_from_email: e.target.value})}
                                                            placeholder="noreply@example.com"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('smtpFromName')}</label>
                                                        <input
                                                            type="text"
                                                            value={serverSettings.smtp_from_name}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_from_name: e.target.value})}
                                                            placeholder="PegaProx Alerts"
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                    </div>
                                                </div>
                                                
                                                <div className="flex gap-6">
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={serverSettings.smtp_tls}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_tls: e.target.checked, smtp_ssl: e.target.checked ? false : serverSettings.smtp_ssl})}
                                                            className="rounded"
                                                        />
                                                        <span className="text-sm text-gray-300">{t('smtpTls')} (STARTTLS)</span>
                                                    </label>
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={serverSettings.smtp_ssl}
                                                            onChange={e => setServerSettings({...serverSettings, smtp_ssl: e.target.checked, smtp_tls: e.target.checked ? false : serverSettings.smtp_tls})}
                                                            className="rounded"
                                                        />
                                                        <span className="text-sm text-gray-300">{t('smtpSsl')} (SSL/TLS)</span>
                                                    </label>
                                                </div>
                                                
                                                {/* Test Email */}
                                                <div className="pt-3 border-t border-proxmox-border">
                                                    <label className="block text-sm text-gray-400 mb-1">{t('testEmail')}</label>
                                                    <div className="flex gap-2">
                                                        <input
                                                            type="email"
                                                            value={testEmailAddress}
                                                            onChange={e => setTestEmailAddress(e.target.value)}
                                                            placeholder="test@example.com"
                                                            className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        />
                                                        <button
                                                            onClick={handleTestEmail}
                                                            disabled={testEmailLoading || !serverSettings.smtp_host}
                                                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                                                        >
                                                            {testEmailLoading ? '...' : t('testEmail')}
                                                        </button>
                                                    </div>
                                                </div>
                                                
                                                {/* Save SMTP Button */}
                                                <div className="pt-3 flex justify-end">
                                                    {haStandby ? <HaSettingsOnActive /> : (
                                                    <button
                                                        onClick={handleSaveSMTPSettings}
                                                        disabled={smtpLoading}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                                                    >
                                                        {smtpLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                        {t('saveSmtpSettings') || 'Save SMTP Settings'}
                                                    </button>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                        
                                        {/* Save SMTP Button - always visible when disabled to allow enabling */}
                                        {!serverSettings.smtp_enabled && (
                                            <div className="pt-3 flex justify-end border-t border-proxmox-border mt-3">
                                                <p className="text-xs text-gray-500 mr-auto my-auto">
                                                    {t('enableSmtpHint') || 'Enable SMTP to configure email settings'}
                                                </p>
                                                {haStandby ? <HaSettingsOnActive /> : (
                                                <button
                                                    onClick={handleSaveSMTPSettings}
                                                    disabled={smtpLoading}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                                                >
                                                    {smtpLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                    {t('save') || 'Save'}
                                                </button>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Alert Email Recipients */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <h4 className="font-medium text-white flex items-center gap-2">
                                            <Icons.Bell />
                                            {t('emailRecipients')}
                                        </h4>
                                        <p className="text-sm text-gray-400">{t('alertsDesc')}</p>
                                        
                                        <div className="space-y-2">
                                            {(serverSettings.alert_email_recipients || []).map((email, idx) => (
                                                <div key={idx} className="flex items-center gap-2">
                                                    <span className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm">{email}</span>
                                                    <button
                                                        onClick={() => setServerSettings({
                                                            ...serverSettings,
                                                            alert_email_recipients: serverSettings.alert_email_recipients.filter((_, i) => i !== idx)
                                                        })}
                                                        className="p-2 text-red-400 hover:text-red-300"
                                                    >
                                                        <Icons.Trash />
                                                    </button>
                                                </div>
                                            ))}
                                            
                                            <div className="flex gap-2">
                                                <input
                                                    type="email"
                                                    id="newRecipientEmail"
                                                    placeholder="admin@example.com"
                                                    className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                />
                                                <button
                                                    onClick={() => {
                                                        const input = document.getElementById('newRecipientEmail');
                                                        if (input.value && input.value.includes('@')) {
                                                            setServerSettings({
                                                                ...serverSettings,
                                                                alert_email_recipients: [...(serverSettings.alert_email_recipients || []), input.value]
                                                            });
                                                            input.value = '';
                                                        }
                                                    }}
                                                    className="px-4 py-2 bg-proxmox-hover hover:bg-proxmox-border rounded-lg text-sm"
                                                >
                                                    {t('addRecipient')}
                                                </button>
                                            </div>
                                        </div>
                                        
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('alertCooldown')}</label>
                                            <input
                                                type="number"
                                                value={serverSettings.alert_cooldown}
                                                onChange={e => setServerSettings({...serverSettings, alert_cooldown: parseInt(e.target.value)})}
                                                min="60"
                                                className="w-32 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                            />
                                            <span className="text-xs text-gray-500 ml-2">(min 60s)</span>
                                        </div>

                                        {/* NS Apr 2026 (#331) — update-available email toggle.
                                            Uses the same recipients list; dedup handled server-side. */}
                                        <div className="pt-2 border-t border-proxmox-border">
                                            <label className="flex items-center gap-2 cursor-pointer select-none">
                                                <input
                                                    type="checkbox"
                                                    checked={!!serverSettings.alert_update_available}
                                                    onChange={e => setServerSettings({...serverSettings, alert_update_available: e.target.checked})}
                                                    className="w-4 h-4"
                                                />
                                                <span className="text-sm text-white">{t('alertUpdateAvailable') || 'Email me when a PegaProx update is available'}</span>
                                            </label>
                                            <p className="text-xs text-gray-500 mt-1 ml-6">{t('alertUpdateAvailableDesc') || 'Polled once a day. Notifies once per new version to the recipients listed above.'}</p>
                                        </div>
                                    </div>

                                    {/* MK Apr 2026 — webhook alert channels */}
                                    <AlertChannelsPanel t={t} addToast={addToast} getAuthHeaders={getAuthHeaders} />
                                    
                                    {/* NS: Plugin Management */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-4">
                                        <div className="flex items-center justify-between">
                                            <h4 className="font-medium text-white flex items-center gap-2">
                                                <Icons.Package className="w-4 h-4" />
                                                {t('plugins') || 'Plugins'}
                                            </h4>
                                            {/* a process loads its own plugins: a standby does not switch, rescan
                                                or delete them, forwarding or not (#625) */}
                                            {!haStandby && <button onClick={async () => {
                                                try {
                                                    await fetch(`${API_URL}/plugins/rescan`, { method: 'POST', credentials: 'include', headers: getAuthHeaders() });
                                                    fetchPlugins();
                                                    addToast('Plugins rescanned', 'success');
                                                } catch (e) {}
                                            }} className="text-xs text-gray-400 hover:text-white flex items-center gap-1">
                                                <Icons.RefreshCw className="w-3 h-3" />
                                                Rescan
                                            </button>}
                                        </div>
                                        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                                            <p className="text-xs text-yellow-400">
                                                {t('pluginDisclaimer') || 'PegaProx takes no responsibility or liability for community plugins. Administrators should always review and scan plugin code before enabling. Only install plugins from trusted sources.'}
                                            </p>
                                        </div>
                                        {discoveredPlugins.length === 0 ? (
                                            <p className="text-sm text-gray-500">{t('noPlugins') || 'No plugins detected. Place plugin folders in the plugins/ directory.'}</p>
                                        ) : (
                                            <div className="space-y-2">
                                                {discoveredPlugins.map(plugin => (
                                                    <div key={plugin.id} className="flex items-center justify-between p-3 bg-proxmox-darker rounded-lg border border-proxmox-border">
                                                        <div className="flex-1 min-w-0 mr-3">
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-medium text-white text-sm">{plugin.name}</span>
                                                                <span className="text-xs text-gray-500">v{plugin.version}</span>
                                                            </div>
                                                            {plugin.author && <p className="text-xs text-gray-500">{t('pluginAuthor') || 'by'} {plugin.author}</p>}
                                                            {plugin.description && <p className="text-xs text-gray-400 mt-0.5">{plugin.description}</p>}
                                                            {plugin.error && <p className="text-xs text-red-400 mt-0.5">{plugin.error}</p>}
                                                            {/* MK Sep 2026 (#642) - which clusters this plugin belongs to.
                                                                Nothing ticked = every cluster, which is where plugins start and
                                                                what the reporter's standalone nodes were seeing. */}
                                                            {clusters.length > 1 && (
                                                                <div className="mt-1.5 flex items-center gap-2 flex-wrap">
                                                                    <span className="text-xs text-gray-500">
                                                                        {t('showOnClusters') || 'Show on'}:
                                                                    </span>
                                                                    {(plugin.clusters || []).length === 0 && (
                                                                        <span className="text-xs text-gray-400">
                                                                            {t('allClusters') || 'All clusters'}
                                                                        </span>
                                                                    )}
                                                                    {clusters.map(c => {
                                                                        const on = (plugin.clusters || []).indexOf(c.id) >= 0;
                                                                        return (
                                                                            <button key={c.id} type="button"
                                                                                onClick={async () => {
                                                                                    const cur = plugin.clusters || [];
                                                                                    const next = on ? cur.filter(x => x !== c.id) : cur.concat([c.id]);
                                                                                    try {
                                                                                        const r = await fetch(`${API_URL}/plugins/${plugin.id}/clusters`, {
                                                                                            method: 'PUT', credentials: 'include',
                                                                                            headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                                            body: JSON.stringify({ clusters: next })
                                                                                        });
                                                                                        if (r && r.ok) fetchPlugins();
                                                                                        else addToast((await r.json().catch(() => ({}))).error || 'Failed', 'error');
                                                                                    } catch (e) { addToast('Error', 'error'); }
                                                                                }}
                                                                                className={`text-xs px-1.5 py-0.5 rounded border transition-colors ${
                                                                                    on ? 'border-proxmox-orange text-proxmox-orange'
                                                                                       : 'border-proxmox-border text-gray-500 hover:text-gray-300'}`}>
                                                                                {c.name || c.id}
                                                                            </button>
                                                                        );
                                                                    })}
                                                                </div>
                                                            )}
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className={`toggle-switch ${plugin.enabled ? 'active' : ''} ${haStandby ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                                onClick={haStandby ? undefined : () => togglePlugin(plugin.id, plugin.enabled)} />
                                                            <button onClick={async () => {
                                                                try {
                                                                    const r = await fetch(`${API_URL}/plugins/${plugin.id}/config`, { credentials: 'include', headers: getAuthHeaders() });
                                                                    if (r && r.ok) {
                                                                        const d = await r.json();
                                                                        let cfgText = d.config || '{}';
                                                                        try { cfgText = JSON.stringify(JSON.parse(cfgText), null, 4); } catch(e) {}
                                                                        setEditingPluginConfig({ id: plugin.id, name: plugin.name, config: cfgText });
                                                                    } else {
                                                                        const e = await r.json().catch(() => ({}));
                                                                        addToast(e.error || 'No config found', 'info');
                                                                    }
                                                                } catch (e) { addToast('Error loading config', 'error'); }
                                                            }} className="text-gray-400/50 hover:text-proxmox-orange transition-colors" title="Edit config.json">
                                                                <Icons.Edit className="w-4 h-4" />
                                                            </button>
                                                            {!haStandby && <button onClick={async () => {
                                                                if (!confirm(`Delete plugin "${plugin.name}"? This removes all plugin files.`)) return;
                                                                try {
                                                                    const r = await fetch(`${API_URL}/plugins/${plugin.id}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                                                                    if (r && r.ok) { addToast('Plugin deleted', 'success'); fetchPlugins(); }
                                                                    else { const e = await r.json().catch(() => ({})); addToast(e.error || 'Failed', 'error'); }
                                                                } catch (e) { addToast('Error', 'error'); }
                                                            }} className="text-red-400/50 hover:text-red-400 transition-colors" title="Delete plugin">
                                                                <Icons.Trash2 className="w-4 h-4" />
                                                            </button>}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>

                                    {/* Plugin Config Editor — uses high z-index to overlay everything */}
                                    {editingPluginConfig && (
                                        <div style={{position:'fixed',inset:0,zIndex:99999,display:'flex',alignItems:'center',justifyContent:'center',padding:'24px',background:'rgba(0,0,0,0.85)'}} onClick={() => setEditingPluginConfig(null)}>
                                            <div className="w-full max-w-4xl bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden shadow-2xl" style={{maxHeight: '90vh', display: 'flex', flexDirection: 'column'}} onClick={e => e.stopPropagation()}>
                                                <div className="flex items-center justify-between p-4 border-b border-proxmox-border flex-shrink-0">
                                                    <div>
                                                        <h3 className="text-white font-semibold text-base">{editingPluginConfig.name} — config.json</h3>
                                                        <p className="text-xs text-gray-500 mt-0.5">Edit plugin configuration (JSON)</p>
                                                    </div>
                                                    <button onClick={() => setEditingPluginConfig(null)} className="p-2 hover:bg-proxmox-border rounded"><Icons.X /></button>
                                                </div>
                                                <div className="p-4 flex-1 overflow-hidden">
                                                    <textarea
                                                        value={editingPluginConfig.config}
                                                        onChange={e => setEditingPluginConfig({...editingPluginConfig, config: e.target.value})}
                                                        className="w-full h-full px-4 py-3 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange resize-none"
                                                        spellCheck="false"
                                                        style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', tabSize: 4, minHeight: '50vh' }}
                                                    />
                                                </div>
                                                <div className="flex items-center justify-between p-4 border-t border-proxmox-border flex-shrink-0">
                                                    <button onClick={() => {
                                                        try {
                                                            const formatted = JSON.stringify(JSON.parse(editingPluginConfig.config), null, 4);
                                                            setEditingPluginConfig({...editingPluginConfig, config: formatted});
                                                        } catch (e) { addToast('Invalid JSON — cannot format', 'error'); }
                                                    }} className="px-3 py-1.5 text-xs bg-proxmox-border hover:bg-gray-600 rounded-lg transition-colors">
                                                        Format JSON
                                                    </button>
                                                    <div className="flex gap-2">
                                                        <button onClick={() => setEditingPluginConfig(null)} className="px-4 py-2 bg-proxmox-border hover:bg-gray-600 rounded-lg text-sm transition-colors">
                                                            {t('cancel')}
                                                        </button>
                                                        <button onClick={async () => {
                                                            try {
                                                                JSON.parse(editingPluginConfig.config);
                                                            } catch (e) {
                                                                addToast('Invalid JSON: ' + e.message, 'error');
                                                                return;
                                                            }
                                                            try {
                                                                const r = await fetch(`${API_URL}/plugins/${editingPluginConfig.id}/config`, {
                                                                    method: 'PUT', credentials: 'include',
                                                                    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                                                                    body: JSON.stringify({ config: editingPluginConfig.config })
                                                                });
                                                                if (r && r.ok) {
                                                                    addToast('Config saved. Restart plugin to apply changes.', 'success');
                                                                    setEditingPluginConfig(null);
                                                                } else {
                                                                    const e = await r.json().catch(() => ({}));
                                                                    addToast(e.error || 'Save failed', 'error');
                                                                }
                                                            } catch (e) { addToast('Error saving config', 'error'); }
                                                        }} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors">
                                                            {t('saveSettings')}
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Save Button */}
                                    <div className="flex justify-end gap-3">
                                        {haStandby ? <HaSettingsOnActive own /> : (
                                        <button
                                            onClick={handleSaveServerSettings}
                                            disabled={serverLoading}
                                            className="flex items-center gap-2 px-6 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                                        >
                                            {serverLoading ? <Icons.RotateCw /> : <Icons.Save />}
                                            {t('saveSettings')}
                                        </button>
                                        )}
                                    </div>

                                    {/* Restart Server Section */}
                                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <h4 className="font-medium text-white flex items-center gap-2">
                                                    <Icons.RefreshCw />
                                                    {t('restartServer')}
                                                </h4>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('restartServerDesc')}
                                                </p>
                                            </div>
                                            <button
                                                onClick={() => setShowRestartConfirm(true)}
                                                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium transition-colors"
                                            >
                                                <Icons.Power />
                                                {t('restartNow')}
                                            </button>
                                        </div>
                                    </div>
                                    
                                    {/* Info Box */}
                                    <div className="p-4 bg-proxmox-dark border border-proxmox-border rounded-xl">
                                        <h4 className="font-medium text-white mb-2">{t('restartInfo')}</h4>
                                        <p className="text-sm text-gray-400">
                                            {t('restartInfoDesc')}
                                        </p>
                                    </div>
                                </div>
                            )}
                            
                            {/* Restart Confirmation Modal */}
                            {showRestartConfirm && (
                                <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/80">
                                    <div className="w-full max-w-md bg-proxmox-card border border-red-500/30 rounded-xl overflow-hidden animate-scale-in">
                                        <div className="p-6 border-b border-red-500/30 bg-red-500/10">
                                            <div className="flex items-center gap-3">
                                                <div className="p-3 rounded-full bg-red-500/20">
                                                    <Icons.AlertTriangle />
                                                </div>
                                                <div>
                                                    <h3 className="text-lg font-semibold text-white">{t('confirmRestart')}</h3>
                                                    <p className="text-sm text-red-400">{t('restartWarning')}</p>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div className="p-6">
                                            <p className="text-gray-300 mb-4">{t('restartConfirmText')}</p>
                                            <ul className="text-sm text-gray-400 space-y-1 mb-4">
                                                <li>• {t('restartEffect1')}</li>
                                                <li>• {t('restartEffect2')}</li>
                                                <li>• {t('restartEffect3')}</li>
                                            </ul>
                                        </div>
                                        
                                        <div className="flex items-center justify-end gap-3 p-4 border-t border-proxmox-border bg-proxmox-dark">
                                            <button 
                                                onClick={() => setShowRestartConfirm(false)} 
                                                className="px-4 py-2 text-gray-300 hover:text-white"
                                            >
                                                {t('cancel')}
                                            </button>
                                            <button
                                                onClick={handleRestartServer}
                                                disabled={restartLoading}
                                                className="flex items-center gap-2 px-4 py-2 bg-red-600 rounded-lg text-white hover:bg-red-700 disabled:opacity-50"
                                            >
                                                {restartLoading ? (
                                                    <>
                                                        <Icons.RotateCw />
                                                        {t('restarting')}
                                                    </>
                                                ) : (
                                                    <>
                                                        <Icons.Power />
                                                        {t('yesRestart')}
                                                    </>
                                                )}
                                            </button>
                                        </div>
                                    </div>

                                </div>
                            )}

                            {activeTab === 'audit' && (
                                <div className="space-y-4">
                                    {/* MK May 2026 — server-side rich search */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-3 space-y-2">
                                        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                                            <input
                                                type="text" value={auditQuery}
                                                onChange={e => setAuditQuery(e.target.value)}
                                                onKeyDown={e => { if (e.key === 'Enter') fetchAuditLogs(0); }}
                                                placeholder={t('auditSearchQuery') || 'Search…'}
                                                className="col-span-2 px-3 py-1.5 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                            />
                                            <input
                                                type="datetime-local" value={auditFrom}
                                                onChange={e => setAuditFrom(e.target.value)}
                                                title={t('auditDateFrom') || 'From'}
                                                className="px-3 py-1.5 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                            />
                                            <input
                                                type="datetime-local" value={auditTo}
                                                onChange={e => setAuditTo(e.target.value)}
                                                title={t('auditDateTo') || 'To'}
                                                className="px-3 py-1.5 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                            />
                                            <select
                                                value={auditSev}
                                                onChange={e => setAuditSev(e.target.value)}
                                                className="px-3 py-1.5 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white">
                                                <option value="">{t('auditAnySeverity') || 'any severity'}</option>
                                                <option value="info">info</option>
                                                <option value="warning">warning</option>
                                                <option value="critical">critical</option>
                                            </select>
                                            <input
                                                type="text" value={auditIp}
                                                onChange={e => setAuditIp(e.target.value)}
                                                onKeyDown={e => { if (e.key === 'Enter') fetchAuditLogs(0); }}
                                                placeholder="IP"
                                                className="px-3 py-1.5 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                            />
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <div className="text-xs text-gray-500">
                                                {auditTotal > 0
                                                    ? `${auditOffset + 1}–${Math.min(auditOffset + auditLogs.length, auditTotal)} ${t('of') || 'of'} ${auditTotal}`
                                                    : (t('noAuditLogs') || 'no entries')}
                                            </div>
                                            <div className="flex gap-2">
                                                <button onClick={() => { setAuditQuery(''); setAuditFrom(''); setAuditTo(''); setAuditSev(''); setAuditIp(''); setAuditClusterFilter(''); setAuditOffset(0); setTimeout(() => fetchAuditLogs(0), 0); }}
                                                    className="px-3 py-1 text-xs text-gray-400 hover:text-white">
                                                    {t('clearFilters') || 'clear'}
                                                </button>
                                                <button onClick={() => fetchAuditLogs(0)}
                                                    className="px-3 py-1 bg-proxmox-orange hover:bg-orange-600 text-white text-xs rounded">
                                                    {t('search') || 'Search'}
                                                </button>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Filters and Export */}
                                    <div className="flex items-center justify-between gap-4">
                                        <div className="flex items-center gap-3">
                                            <select
                                                value={userFilter}
                                                onChange={e => setUserFilter(e.target.value)}
                                                className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-white focus:outline-none focus:border-proxmox-orange"
                                            >
                                                <option value="">{t('allUsers')}</option>
                                                {uniqueUsers.map(u => (
                                                    <option key={u} value={u}>{u}</option>
                                                ))}
                                            </select>
                                            <select
                                                value={actionFilter}
                                                onChange={e => setActionFilter(e.target.value)}
                                                className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-white focus:outline-none focus:border-proxmox-orange"
                                            >
                                                <option value="">{t('allActions')}</option>
                                                {uniqueActions.map(a => (
                                                    <option key={a} value={a}>{getActionLabel(a)}</option>
                                                ))}
                                            </select>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={fetchAuditLogs}
                                                className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-gray-300 hover:text-white hover:border-proxmox-orange transition-colors"
                                            >
                                                <Icons.RefreshCw />
                                                {t('refreshAuditLog')}
                                            </button>
                                            <button
                                                onClick={exportAuditLog}
                                                className="flex items-center gap-2 px-3 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors"
                                                title={t('exportFilteredHint') || 'Export the rows you see (with current filter applied)'}
                                            >
                                                <Icons.Download />
                                                {t('exportAuditLog')}
                                            </button>
                                            {/* NS Apr 2026 — full server-side CSV export for compliance archives.
                                                Differs from the button above in two ways: no client filter applied,
                                                and higher row cap (server honours ?limit=10000). */}
                                            <a
                                                href={`${API_URL}/audit?format=csv&limit=10000`}
                                                download
                                                className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-sm font-medium transition-colors"
                                                title={t('exportFullCsvHint') || 'Server-side CSV with all entries (up to 10000)'}
                                            >
                                                <Icons.Download />
                                                {t('exportFullCsv') || 'Export Full CSV'}
                                            </a>
                                        </div>
                                    </div>
                                    
                                    <p className="text-sm text-gray-400">{t('auditLogDescription')}</p>
                                    
                                    {/* Audit Log Table */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                                        <div className="max-h-[400px] overflow-auto">
                                            <table className="w-full">
                                                <thead className="sticky top-0 bg-proxmox-dark">
                                                    <tr className="border-b border-proxmox-border">
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('timestamp')}</th>
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('usernameLabel')}</th>
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('cluster')}</th>
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('action')}</th>
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('details')}</th>
                                                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{t('ipAddress')}</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {filteredLogs.length === 0 ? (
                                                        <tr>
                                                            <td colSpan="6" className="px-4 py-8 text-center text-gray-400">
                                                                {t('noAuditLogs')}
                                                            </td>
                                                        </tr>
                                                    ) : (
                                                        filteredLogs.map((log, idx) => (
                                                            <tr key={idx} className="border-b border-gray-700/50 hover:bg-proxmox-hover">
                                                                <td className="px-4 py-3 text-gray-400 text-sm whitespace-nowrap">
                                                                    {new Date(log.timestamp).toLocaleString()}
                                                                </td>
                                                                <td className="px-4 py-3 text-white font-medium">{log.user}</td>
                                                                <td className="px-4 py-3 text-sm">
                                                                    {log.cluster ? (
                                                                        <span className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border text-proxmox-orange text-xs">
                                                                            {log.cluster}
                                                                        </span>
                                                                    ) : (
                                                                        <span className="text-gray-500">-</span>
                                                                    )}
                                                                </td>
                                                                <td className="px-4 py-3">
                                                                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                                                                        log.action.includes('login') ? 'bg-green-500/10 text-green-400' :
                                                                        log.action.includes('logout') ? 'bg-yellow-500/10 text-yellow-400' :
                                                                        log.action.includes('delete') ? 'bg-red-500/10 text-red-400' :
                                                                        log.action.includes('create') || log.action.includes('added') ? 'bg-blue-500/10 text-blue-400' :
                                                                        'bg-gray-500/10 text-gray-400'
                                                                    }`}>
                                                                        {getActionLabel(log.action)}
                                                                    </span>
                                                                </td>
                                                                <td className="px-4 py-3 text-gray-300 text-sm max-w-xs truncate" title={log.details}>
                                                                    {log.details || '-'}
                                                                </td>
                                                                <td className="px-4 py-3 text-gray-400 text-sm font-mono">
                                                                    {log.ip_address || '-'}
                                                                </td>
                                                            </tr>
                                                        ))
                                                    )}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>

                                    {/* MK May 2026 — pagination */}
                                    {auditTotal > auditPageSize && (
                                        <div className="flex items-center justify-between text-xs text-gray-400">
                                            <span>{auditOffset + 1}–{Math.min(auditOffset + auditLogs.length, auditTotal)} {t('of') || 'of'} {auditTotal}</span>
                                            <div className="flex gap-2">
                                                <button onClick={() => fetchAuditLogs(Math.max(0, auditOffset - auditPageSize))}
                                                    disabled={auditOffset <= 0}
                                                    className="px-3 py-1 bg-proxmox-dark border border-proxmox-border rounded disabled:opacity-50 hover:text-white">
                                                    ← {t('prev') || 'Prev'}
                                                </button>
                                                <button onClick={() => fetchAuditLogs(auditOffset + auditPageSize)}
                                                    disabled={(auditOffset + auditLogs.length) >= auditTotal}
                                                    className="px-3 py-1 bg-proxmox-dark border border-proxmox-border rounded disabled:opacity-50 hover:text-white">
                                                    {t('next') || 'Next'} →
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* LW Sep 2026 (#625) - warm standby for PegaProx itself */}
                            {activeTab === 'ha' && isAdmin && (
                                <HaPanel t={t} addToast={addToast} getAuthHeaders={getAuthHeaders} />
                            )}

                            {/* MK May 2026 — SIEM Forwarder Tab */}
                            {activeTab === 'siem' && (
                                <SIEMTab addToast={addToast} t={t} getAuthHeaders={getAuthHeaders} />
                            )}

                            {/* Updates Tab */}
                            {activeTab === 'updates' && (
                                <div className="space-y-6">
                                    {/* Current Version */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                                    <Icons.Package />
                                                    Current Version
                                                </h3>
                                                <div className="mt-2 space-y-1">
                                                    <p className="text-2xl font-bold text-proxmox-orange">
                                                        PegaProx {updateInfo?.current_version || PEGAPROX_VERSION}
                                                    </p>
                                                    <p className="text-sm text-gray-400">
                                                        Build: {updateInfo?.current_build || '2026.01'}
                                                    </p>
                                                </div>
                                            </div>
                                            <button
                                                onClick={checkForUpdates}
                                                disabled={updateLoading}
                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                                            >
                                                {updateLoading ? (
                                                    <Icons.Loader className="animate-spin" />
                                                ) : (
                                                    <Icons.RefreshCw />
                                                )}
                                                Check for Updates
                                            </button>
                                        </div>
                                    </div>
                                    
                                    {/* Error */}
                                    {updateError && (
                                        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
                                            <Icons.AlertTriangle className="text-red-400" />
                                            <span className="text-red-400">{updateError}</span>
                                        </div>
                                    )}
                                    
                                    {/* Update Available */}
                                    {updateInfo?.update_available && (
                                        <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                                            <div className="flex items-start justify-between">
                                                <div>
                                                    <h3 className="text-lg font-semibold text-green-400 flex items-center gap-2">
                                                        <Icons.Download />
                                                        {t('updateAvailable') || 'Update Available!'}
                                                    </h3>
                                                    <p className="text-2xl font-bold text-white mt-2">
                                                        Version {updateInfo.latest_version}
                                                    </p>
                                                    <p className="text-sm text-gray-400 mt-1">
                                                        {t('released') || 'Released'}: {updateInfo.release_date || 'Unknown'}
                                                    </p>
                                                </div>
                                                {/* NS 2026-08-11 — apt/docker installs must not use the in-app file updater;
                                                    show the correct path instead of the Install button. */}
                                                {updateInfo.in_app_update_supported === false ? (
                                                    <div className="max-w-xs text-right">
                                                        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-xs font-medium">
                                                            <Icons.AlertTriangle />
                                                            {updateInfo.install_method === 'docker' ? (t('dockerInstall') || 'Docker install') : (t('aptInstall') || 'APT / package install')}
                                                        </div>
                                                        <p className="text-xs text-gray-400 mt-2 whitespace-pre-line">
                                                            {updateInfo.managed_update_hint || (t('updateManagedExternally') || 'Update this instance through its package manager or image, not the in-app updater.')}
                                                        </p>
                                                        {updateInfo.managed_update_command && (
                                                            <div className="mt-2 flex items-center gap-2 justify-end">
                                                                <code className="px-2 py-1 rounded bg-black/40 border border-proxmox-border text-[11px] text-green-300 font-mono select-all">
                                                                    {updateInfo.managed_update_command}
                                                                </code>
                                                                <button
                                                                    onClick={() => { try { navigator.clipboard.writeText(updateInfo.managed_update_command); addToast(t('copied') || 'Copied', 'success'); } catch (e) {} }}
                                                                    className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border hover:border-gray-500 text-gray-400 text-[11px] shrink-0"
                                                                >
                                                                    {t('copy') || 'Copy'}
                                                                </button>
                                                            </div>
                                                        )}
                                                    </div>
                                                ) : !haStandby && (
                                                    <button
                                                        onClick={performUpdate}
                                                        disabled={updateLoading || updateProgress}
                                                        className="flex items-center gap-2 px-6 py-3 bg-green-500 hover:bg-green-600 disabled:bg-gray-600 rounded-lg font-medium transition-colors"
                                                    >
                                                        {updateLoading ? (
                                                            <Icons.Loader className="animate-spin" />
                                                        ) : (
                                                            <Icons.Download />
                                                        )}
                                                        {t('installUpdate') || 'Install Update'}
                                                    </button>
                                                )}
                                            </div>
                                            
                                            {/* Changelog */}
                                            {updateInfo.changelog && updateInfo.changelog.length > 0 && (
                                                <div className="mt-4 pt-4 border-t border-green-500/30">
                                                    <h4 className="text-sm font-medium text-gray-300 mb-2">{t('whatsNew') || "What's New"}:</h4>
                                                    <ul className="space-y-1">
                                                        {updateInfo.changelog.map((item, idx) => (
                                                            <li key={idx} className="text-sm text-gray-400 flex items-start gap-2">
                                                                <span className="text-green-400 mt-1">•</span>
                                                                {item}
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                            
                                            {/* Breaking Changes */}
                                            {updateInfo.breaking_changes && updateInfo.breaking_changes.length > 0 && (
                                                <div className="mt-4 pt-4 border-t border-yellow-500/30 bg-yellow-500/5 rounded-lg p-3">
                                                    <h4 className="text-sm font-medium text-yellow-400 mb-2 flex items-center gap-2">
                                                        <Icons.AlertTriangle />
                                                        {t('breakingChanges') || 'Breaking Changes'}:
                                                    </h4>
                                                    <ul className="space-y-1">
                                                        {updateInfo.breaking_changes.map((item, idx) => (
                                                            <li key={idx} className="text-sm text-yellow-300">{item}</li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    
                                    {/* Update Progress */}
                                    {updateProgress && (
                                        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
                                            <div className="flex items-center gap-4">
                                                <div className="relative">
                                                    <Icons.Loader className="w-8 h-8 text-blue-400 animate-spin" />
                                                </div>
                                                <div>
                                                    <h3 className="text-lg font-semibold text-blue-400">
                                                        {updateProgress.status === 'downloading' && (t('downloadingUpdate') || 'Downloading Update...')}
                                                        {updateProgress.status === 'installing' && (t('installingUpdate') || 'Installing Update...')}
                                                        {updateProgress.status === 'restarting' && (t('serverRestarting') || 'Server Restarting...')}
                                                        {updateProgress.status === 'reconnecting' && (t('reconnecting') || 'Reconnecting...')}
                                                        {updateProgress.status === 'restoring' && (t('restoringBackup') || 'Restoring from Backup...')}
                                                    </h3>
                                                    <p className="text-sm text-gray-400 mt-1">{updateProgress.message}</p>
                                                </div>
                                            </div>
                                            <div className="mt-4 w-full bg-proxmox-dark rounded-full h-2 overflow-hidden">
                                                <div className="h-full bg-blue-500 animate-pulse" style={{ width: '100%' }} />
                                            </div>
                                            <p className="text-xs text-gray-500 mt-2">
                                                {t('doNotCloseWindow') || 'Please do not close this window...'}
                                            </p>
                                        </div>
                                    )}
                                    
                                    {/* No Update Available - only show if no error */}
                                    {updateInfo && !updateInfo.update_available && !updateInfo.error && (
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6 text-center">
                                            <Icons.CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3" />
                                            <h3 className="text-lg font-semibold text-white">You're up to date!</h3>
                                            <p className="text-gray-400 mt-1">
                                                PegaProx {updateInfo.current_version} is the latest version.
                                            </p>
                                        </div>
                                    )}
                                    
                                    {/* Rollback Section - NS Jan 2026. Not on a standby: its route refuses
                                        there, the listing (an empty POST) as well (#625) */}
                                    {!haStandby && (
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                                    <Icons.RotateCcw />
                                                    {t('rollback') || 'Rollback'}
                                                </h3>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('rollbackDesc') || 'Restore a previous version from backup'}
                                                </p>
                                            </div>
                                            <button
                                                onClick={() => { loadBackups(); setShowRollbackModal(true); }}
                                                disabled={updateLoading || updateProgress}
                                                className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                                            >
                                                <Icons.RotateCcw />
                                                {t('viewBackups') || 'View Backups'}
                                            </button>
                                        </div>
                                    </div>
                                    )}

                                    {/* Update Instructions */}
                                    {updateInfo?.instructions && (
                                        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
                                            <h3 className="text-lg font-semibold text-blue-400 flex items-center gap-2 mb-4">
                                                <Icons.FileText />
                                                Update Instructions
                                            </h3>
                                            <div className="bg-proxmox-dark rounded-lg p-4 font-mono text-sm">
                                                {updateInfo.instructions.map((line, idx) => (
                                                    <p key={idx} className={`${line.startsWith('#') ? 'text-gray-500' : 'text-gray-300'} ${line === '' ? 'h-4' : ''}`}>
                                                        {line || '\u00A0'}
                                                    </p>
                                                ))}
                                            </div>
                                            {updateInfo.backup_path && (
                                                <p className="text-sm text-gray-400 mt-3">
                                                    ✓ Backup created: <code className="text-green-400">{updateInfo.backup_path}</code>
                                                </p>
                                            )}
                                            {updateInfo.download_url && (
                                                <a
                                                    href={updateInfo.download_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center gap-2 mt-4 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-sm font-medium transition-colors"
                                                >
                                                    <Icons.ExternalLink />
                                                    Open GitHub Release
                                                </a>
                                            )}
                                        </div>
                                    )}
                                    
                                    {/* GitHub Link */}
                                    <div className="text-center text-sm text-gray-500">
                                        <a 
                                            href="https://github.com/PegaProx/project-pegaprox" 
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="hover:text-proxmox-orange transition-colors inline-flex items-center gap-1"
                                        >
                                            <Icons.Github />
                                            View on GitHub
                                        </a>
                                    </div>
                                </div>
                            )}
                            
                            {/* Support Tab - NS Feb 2026 */}
                            {activeTab === 'support' && (
                                <div className="space-y-6">
                                    {/* Support Bundle */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.Package className="w-5 h-5 text-proxmox-orange" />
                                            {t('supportBundle') || 'Support Bundle'}
                                        </h3>
                                        <p className="text-gray-400 text-sm mb-4">
                                            {t('supportBundleDesc') || 'Generate a diagnostic bundle containing logs, configuration, and system information for troubleshooting. Sensitive data (passwords, tokens, secrets) is automatically redacted.'}
                                        </p>
                                        <div className="bg-proxmox-darker rounded-lg p-4 mb-4">
                                            <h4 className="text-white font-medium mb-2">{t('bundleContents') || 'Bundle Contents'}:</h4>
                                            <ul className="text-sm text-gray-400 space-y-1">
                                                <li>• {t('bundleSystemInfo') || 'System information (version, platform, Python)'}</li>
                                                <li>• {t('bundleClusterStatus') || 'Cluster connection status'}</li>
                                                <li>• {t('bundleAuditLogs') || 'Recent audit log entries (last 500)'}</li>
                                                <li>• {t('bundleAppLogs') || 'Application logs (last 1000 lines)'}</li>
                                                <li>• {t('bundleDbSchema') || 'Database schema and statistics'}</li>
                                                <li>• {t('bundleServerSettings') || 'Server settings (passwords redacted)'}</li>
                                                <li>• {t('bundleUserList') || 'User list (no sensitive data)'}</li>
                                                <li>• {t('bundleRecentTasks') || 'Recent Proxmox tasks'}</li>
                                                <li>• {t('bundleSseStats') || 'SSE/SSH connection statistics'}</li>
                                            </ul>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <button
                                                onClick={async () => {
                                                    try {
                                                        addToast(t('generatingBundle') || 'Generating support bundle...', 'info');
                                                        const response = await fetch(`${API_URL}/support-bundle`, {
                                                            method: 'GET',
                                                            credentials: 'include'
                                                        });
                                                        if (response.ok) {
                                                            const blob = await response.blob();
                                                            const url = window.URL.createObjectURL(blob);
                                                            const a = document.createElement('a');
                                                            const disposition = response.headers.get('Content-Disposition');
                                                            const filename = disposition 
                                                                ? disposition.split('filename=')[1]?.replace(/"/g, '') 
                                                                : `pegaprox_support_${new Date().toISOString().slice(0,10)}.zip`;
                                                            a.href = url;
                                                            a.download = filename;
                                                            document.body.appendChild(a);
                                                            a.click();
                                                            window.URL.revokeObjectURL(url);
                                                            a.remove();
                                                            addToast(t('bundleDownloaded') || 'Support bundle downloaded successfully', 'success');
                                                        } else {
                                                            // Try to parse JSON error, but handle text/HTML responses too
                                                            try {
                                                                const err = await response.json();
                                                                addToast(err.error || 'Failed to generate bundle', 'error');
                                                            } catch {
                                                                addToast(`Server error: ${response.status} ${response.statusText}`, 'error');
                                                            }
                                                        }
                                                    } catch (e) {
                                                        console.error('Support bundle error:', e);
                                                        addToast(t('bundleError') || 'Failed to generate support bundle', 'error');
                                                    }
                                                }}
                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors"
                                            >
                                                <Icons.Download className="w-4 h-4" />
                                                {t('downloadBundle') || 'Download Support Bundle'}
                                            </button>
                                            <span className="text-xs text-gray-500">
                                                {t('bundleSize') || 'Typical size: 50-500 KB'}
                                            </span>
                                        </div>
                                    </div>
                                    
                                    {/* Support Links */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.LifeBuoy className="w-5 h-5 text-blue-400" />
                                            {t('supportResources') || 'Support Resources'}
                                        </h3>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <a 
                                                href="https://github.com/PegaProx/project-pegaprox/issues" 
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="flex items-center gap-3 p-4 bg-proxmox-darker rounded-lg hover:bg-proxmox-border/50 transition-colors"
                                            >
                                                <div className="w-10 h-10 rounded-lg bg-gray-500/20 flex items-center justify-center">
                                                    <Icons.Github className="w-5 h-5 text-gray-400" />
                                                </div>
                                                <div>
                                                    <h4 className="font-medium text-white">{t('reportIssue') || 'Report an Issue'}</h4>
                                                    <p className="text-sm text-gray-400">GitHub Issues</p>
                                                </div>
                                                <Icons.ExternalLink className="w-4 h-4 text-gray-500 ml-auto" />
                                            </a>
                                            {/* MK 2026-06-02 (#519 Thermal-spearhead): "Discussions" tile pointed at
                                                github.com/.../discussions, which 404'd because we never enabled the
                                                Discussions feature on the repo. Removed the tile entirely — "Report
                                                an Issue" already covers the Q&A use case and Nico answers there.
                                                If we ever turn Discussions on, restore from git history. */}
                                            <a
                                                href="https://github.com/PegaProx/project-pegaprox/wiki"
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="flex items-center gap-3 p-4 bg-proxmox-darker rounded-lg hover:bg-proxmox-border/50 transition-colors"
                                            >
                                                <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                                                    <Icons.Book className="w-5 h-5 text-green-400" />
                                                </div>
                                                <div>
                                                    <h4 className="font-medium text-white">{t('documentation') || 'Documentation'}</h4>
                                                    <p className="text-sm text-gray-400">Wiki & Guides</p>
                                                </div>
                                                <Icons.ExternalLink className="w-4 h-4 text-gray-500 ml-auto" />
                                            </a>
                                            <a 
                                                href="https://github.com/PegaProx/project-pegaprox/releases" 
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="flex items-center gap-3 p-4 bg-proxmox-darker rounded-lg hover:bg-proxmox-border/50 transition-colors"
                                            >
                                                <div className="w-10 h-10 rounded-lg bg-proxmox-orange/20 flex items-center justify-center">
                                                    <Icons.Download className="w-5 h-5 text-proxmox-orange" />
                                                </div>
                                                <div>
                                                    <h4 className="font-medium text-white">{t('releases') || 'Releases'}</h4>
                                                    <p className="text-sm text-gray-400">Download & Changelog</p>
                                                </div>
                                                <Icons.ExternalLink className="w-4 h-4 text-gray-500 ml-auto" />
                                            </a>
                                        </div>
                                    </div>
                                    
                                    {/* System Information */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.Info className="w-5 h-5 text-blue-400" />
                                            {t('quickSystemInfo') || 'Quick System Info'}
                                        </h3>
                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                            <div className="bg-proxmox-darker rounded-lg p-3">
                                                <p className="text-gray-400">{t('version') || 'Version'}</p>
                                                <p className="text-white font-medium">{PEGAPROX_VERSION}</p>
                                            </div>
                                            <div className="bg-proxmox-darker rounded-lg p-3">
                                                <p className="text-gray-400">{t('clusters') || 'Clusters'}</p>
                                                <p className="text-white font-medium">{clusters?.length || 0}</p>
                                            </div>
                                            <div className="bg-proxmox-darker rounded-lg p-3">
                                                <p className="text-gray-400">{t('users')}</p>
                                                <p className="text-white font-medium">{users?.length || 0}</p>
                                            </div>
                                            <div className="bg-proxmox-darker rounded-lg p-3">
                                                <p className="text-gray-400">{t('browser') || 'Browser'}</p>
                                                <p className="text-white font-medium truncate" title={navigator.userAgent}>
                                                    {navigator.userAgent.includes('Chrome') ? 'Chrome' : 
                                                     navigator.userAgent.includes('Firefox') ? 'Firefox' :
                                                     navigator.userAgent.includes('Safari') ? 'Safari' :
                                                     navigator.userAgent.includes('Edge') ? 'Edge' : 'Other'}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                            
                            {/* About Tab - LW styled this */}
                            {activeTab === 'about' && (
                                <div className="space-y-6">
                                    {/* Version Info */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6 text-center">
                                        <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl mb-4">
                                            <img src={getLogoSrc()} alt="PegaProx" className="w-20 h-20 object-contain" />
                                        </div>
                                        <h2 className="text-3xl font-bold text-white">PegaProx</h2>
                                        <p className="text-xl text-proxmox-orange mt-1">{PEGAPROX_VERSION}</p>
                                        <p className="text-sm text-gray-400 mt-2">Multi-Cluster Proxmox Management</p>
                                        <p className="text-xs text-gray-500 mt-1">© 2025-2026 PegaProx Team</p>
                                    </div>
                                    
                                    {/* Team */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.Users />
                                            {t('developmentTeam') || 'Development Team'}
                                        </h3>
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                            <div className="bg-proxmox-darker rounded-lg p-4 text-center">
                                                <div className="w-12 h-12 rounded-full bg-proxmox-orange/20 flex items-center justify-center mx-auto mb-2">
                                                    <span className="text-proxmox-orange font-bold">NS</span>
                                                </div>
                                                <h4 className="font-medium text-white">Nico Schmidt</h4>
                                                <p className="text-sm text-gray-400">Lead Developer & Founder</p>
                                            </div>
                                            <div className="bg-proxmox-darker rounded-lg p-4 text-center">
                                                <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center mx-auto mb-2">
                                                    <span className="text-blue-400 font-bold">MK</span>
                                                </div>
                                                <h4 className="font-medium text-white">Marcus Kellermann</h4>
                                                <p className="text-sm text-gray-400">Backend Developer</p>
                                            </div>
                                            <div className="bg-proxmox-darker rounded-lg p-4 text-center">
                                                <div className="w-12 h-12 rounded-full bg-pink-500/20 flex items-center justify-center mx-auto mb-2">
                                                    <span className="text-pink-400 font-bold">LW</span>
                                                </div>
                                                <h4 className="font-medium text-white">Laura Weber</h4>
                                                <p className="text-sm text-gray-400">Frontend Developer</p>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Credits & Acknowledgments */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.Heart />
                                            {t('creditsAcknowledgments') || 'Credits & Acknowledgments'}
                                        </h3>
                                        <div className="space-y-4">
                                            {/* ProxLB Credit */}
                                            <div className="bg-proxmox-darker rounded-lg p-4">
                                                <div className="flex items-start gap-4">
                                                    <div className="w-12 h-12 rounded-lg bg-green-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Icons.Scale />
                                                    </div>
                                                    <div>
                                                        <h4 className="font-medium text-white">{t('proxlbCredit') || 'ProxLB by gyptazy'}</h4>
                                                        <p className="text-sm text-gray-400 mt-1">
                                                            {t('proxlbCreditDesc') || 'Our load balancing functionality is based on the excellent work from ProxLB. Special thanks to gyptazy for creating and open-sourcing this amazing tool!'}
                                                        </p>
                                                        <a 
                                                            href="https://github.com/gyptazy/ProxLB" 
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="inline-flex items-center gap-1 text-sm text-proxmox-orange hover:underline mt-2"
                                                        >
                                                            <Icons.Github className="w-4 h-4" />
                                                            github.com/gyptazy/ProxLB
                                                            <Icons.ExternalLink className="w-3 h-3" />
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {/* ProxSnap Credit */}
                                            <div className="bg-proxmox-darker rounded-lg p-4">
                                                <div className="flex items-start gap-4">
                                                    <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Icons.Camera />
                                                    </div>
                                                    <div>
                                                        <h4 className="font-medium text-white">ProxSnap by gyptazy</h4>
                                                        <p className="text-sm text-gray-400 mt-1">
                                                            The snapshot overview feature was inspired by ProxSnap - a powerful CLI tool 
                                                            for managing Proxmox snapshots. Thanks to gyptazy for the great contribution!
                                                        </p>
                                                        <a 
                                                            href="https://github.com/gyptazy/ProxSnap" 
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="inline-flex items-center gap-1 text-sm text-proxmox-orange hover:underline mt-2"
                                                        >
                                                            <Icons.Github className="w-4 h-4" />
                                                            github.com/gyptazy/ProxSnap
                                                            <Icons.ExternalLink className="w-3 h-3" />
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {/* Translations */}
                                            <div className="bg-proxmox-darker rounded-lg p-4">
                                                <div className="flex items-start gap-4">
                                                    <div className="w-12 h-12 rounded-lg bg-yellow-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Icons.Globe className="w-6 h-6 text-yellow-400" />
                                                    </div>
                                                    <div>
                                                        <h4 className="font-medium text-white">Community Translations</h4>
                                                        <p className="text-sm text-gray-400 mt-1">
                                                            Thanks to community contributors for helping translate PegaProx into multiple languages.
                                                        </p>
                                                        <div className="flex flex-wrap gap-2 mt-2 text-[12px]">
                                                            <a href="https://github.com/ColombianJoker" target="_blank" rel="noopener noreferrer"
                                                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-proxmox-dark text-gray-300 hover:text-white transition-colors">
                                                                <Icons.Github className="w-3 h-3" />
                                                                <strong>ColombianJoker</strong> — Spanish (Latin America)
                                                            </a>
                                                            <a href="https://github.com/IMNotMax" target="_blank" rel="noopener noreferrer"
                                                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-proxmox-dark text-gray-300 hover:text-white transition-colors">
                                                                <Icons.Github className="w-3 h-3" />
                                                                <strong>IMNotMax</strong> — French
                                                            </a>
                                                            <a href="https://github.com/FernandoRD" target="_blank" rel="noopener noreferrer"
                                                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-proxmox-dark text-gray-300 hover:text-white transition-colors">
                                                                <Icons.Github className="w-3 h-3" />
                                                                <strong>FernandoRD</strong> — Portuguese
                                                            </a>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Other Credits */}
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center text-sm">
                                                <div className="bg-proxmox-darker rounded-lg p-3">
                                                    <p className="text-gray-400">Proxmox VE</p>
                                                    <p className="text-white font-medium">API Integration</p>
                                                </div>
                                                <div className="bg-proxmox-darker rounded-lg p-3">
                                                    <p className="text-gray-400">noVNC</p>
                                                    <p className="text-white font-medium">Console Access</p>
                                                </div>
                                                <div className="bg-proxmox-darker rounded-lg p-3">
                                                    <p className="text-gray-400">xterm.js</p>
                                                    <p className="text-white font-medium">Terminal Emulator</p>
                                                </div>
                                                <div className="bg-proxmox-darker rounded-lg p-3">
                                                    <p className="text-gray-400">React</p>
                                                    <p className="text-white font-medium">UI Framework</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* Links */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                            <Icons.Link />
                                            {t('links') || 'Links'}
                                        </h3>
                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                            <a href="https://pegaprox.com" target="_blank" rel="noopener noreferrer"
                                                className="flex items-center gap-2 p-3 bg-proxmox-darker rounded-lg hover:bg-proxmox-hover transition-colors">
                                                <Icons.Globe className="text-proxmox-orange" />
                                                <span className="text-sm text-gray-300">pegaprox.com</span>
                                            </a>
                                            <a href="https://github.com/PegaProx/project-pegaprox" target="_blank" rel="noopener noreferrer"
                                                className="flex items-center gap-2 p-3 bg-proxmox-darker rounded-lg hover:bg-proxmox-hover transition-colors">
                                                <Icons.Github className="text-gray-400" />
                                                <span className="text-sm text-gray-300">GitHub</span>
                                            </a>
                                            <a href="https://docs.pegaprox.com" target="_blank" rel="noopener noreferrer"
                                                className="flex items-center gap-2 p-3 bg-proxmox-darker rounded-lg hover:bg-proxmox-hover transition-colors">
                                                <Icons.Book className="text-blue-400" />
                                                <span className="text-sm text-gray-300">Documentation</span>
                                            </a>
                                            <a href="mailto:sponsor@pegaprox.com"
                                                className="flex items-center gap-2 p-3 bg-proxmox-darker rounded-lg hover:bg-proxmox-hover transition-colors">
                                                <Icons.Heart className="text-pink-400" />
                                                <span className="text-sm text-gray-300">Sponsor</span>
                                            </a>
                                        </div>
                                        {/* LW Apr 2026: OpenCollective contribute button — prefer this over the mailto for recurring support */}
                                        <div className="mt-4 flex justify-center">
                                            <a href="https://opencollective.com/pegaprox"
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                title="Contribute on Open Collective">
                                                <img src="/images/oc_contribute_button.png"
                                                    alt="Contribute to our Collective"
                                                    className="h-9 w-auto hover:opacity-90 transition-opacity" />
                                            </a>
                                        </div>
                                    </div>

                                    {/* REQUIRED LEGAL NOTICE — do not remove, hide, disable or alter.
                                        This is the full "Appropriate Legal Notices" block the short
                                        LegalNotice line throughout the UI points at: copyright, the
                                        absence of warranty, the right to convey under this License,
                                        how to read it, and the §13 source offer. Together with the
                                        NOTICE file at the repository root it is a required author
                                        attribution under AGPL-3.0 §7(b). English on purpose — it
                                        refers to an English-language license. NS Sep 2026 */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-6 text-sm text-gray-400 space-y-3">
                                        <p className="text-gray-300 font-medium">© 2025-2026 PegaProx Team</p>
                                        <p>
                                            PegaProx is free software: you can redistribute it and/or modify it
                                            under the terms of the GNU Affero General Public License, version 3,
                                            as published by the Free Software Foundation.{' '}
                                            <a href="https://github.com/PegaProx/project-pegaprox/blob/main/LICENSE"
                                                target="_blank" rel="noopener noreferrer"
                                                className="text-proxmox-orange hover:underline">Read the license</a>.
                                        </p>
                                        <p>
                                            This program is distributed in the hope that it will be useful, but
                                            WITHOUT ANY WARRANTY — without even the implied warranty of
                                            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the license
                                            for details.
                                        </p>
                                        <p>
                                            If you run a modified version of PegaProx and make it available to
                                            users over a network, section 13 of the license requires you to offer
                                            those users the complete source of your modified version.{' '}
                                            <a href="https://github.com/PegaProx/project-pegaprox"
                                                target="_blank" rel="noopener noreferrer"
                                                className="text-proxmox-orange hover:underline">Source code</a>{' · '}
                                            <a href="https://github.com/PegaProx/project-pegaprox/blob/main/NOTICE"
                                                target="_blank" rel="noopener noreferrer"
                                                className="text-proxmox-orange hover:underline">NOTICE</a>
                                        </p>
                                        <p className="text-center text-gray-500 pt-1">Made with ❤️ in Austria and Germany</p>
                                    </div>
                                </div>
                            )}
                            
                        </div>
                    </div>
                </div>
                    
                    {/* Rollback Modal - NS Jan 2026 */}
                    {showRollbackModal && (
                        <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/80" onClick={() => setShowRollbackModal(false)}>
                            <div 
                                className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl overflow-hidden"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                        <Icons.RotateCcw className="text-yellow-400" />
                                        {t('selectBackup') || 'Select Backup to Restore'}
                                    </h3>
                                    <button onClick={() => setShowRollbackModal(false)} className="p-1 hover:bg-proxmox-dark rounded">
                                        <Icons.X />
                                    </button>
                                </div>
                                <div className="p-4 max-h-[400px] overflow-y-auto">
                                    {availableBackups.length === 0 ? (
                                        <div className="text-center py-8 text-gray-500">
                                            <Icons.Archive className="w-12 h-12 mx-auto mb-2 opacity-50" />
                                            <p>{t('noBackupsFound') || 'No backups found'}</p>
                                        </div>
                                    ) : (
                                        <div className="space-y-2">
                                            {availableBackups.map((backup, idx) => (
                                                <div 
                                                    key={idx}
                                                    className="bg-proxmox-dark border border-proxmox-border rounded-lg p-4 hover:border-yellow-500/50 transition-colors"
                                                >
                                                    <div className="flex items-center justify-between">
                                                        <div>
                                                            <p className="font-medium text-white">{backup.name}</p>
                                                            <p className="text-xs text-gray-500 mt-1">
                                                                {t('created') || 'Created'}: {new Date(backup.created).toLocaleString()}
                                                            </p>
                                                            <p className="text-xs text-gray-500">
                                                                {t('files') || 'Files'}: {backup.files?.join(', ') || 'unknown'}
                                                            </p>
                                                        </div>
                                                        <button
                                                            onClick={() => performRollback(backup.name)}
                                                            disabled={updateLoading}
                                                            className="px-3 py-1.5 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
                                                        >
                                                            {t('restore') || 'Restore'}
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                                <div className="p-4 border-t border-proxmox-border bg-proxmox-dark/50">
                                    <p className="text-xs text-gray-500 text-center">
                                        {t('rollbackWarning') || '⚠️ Rollback will restart the server. Make sure you have saved any unsaved work.'}
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                </>
            );
        }

        // ═══════════════════════════════════════════════
        // PegaProx - High Availability (#625)
        // HaPanel (settings tab), HaRestartOverlay, haRelTime
        // v2: the live view switch and the restart a changed cluster setup needs
        // v3: groups of up to four - the members table, Remove, more standbys from the active
        // v4: confirmed standbys and member keys, a second step to remove one that is not
        //     confirmed, whether a removed member was told, the note on a removed instance
        // v5: the switch that has a standby carry out what is done on it through the active
        // v6: the switch that has a standby serve users as an active instance; the active is
        //     the leader, the one that runs the automation
        // v7: the words for the three kinds, the leader, a member that serves users and a plain
        //     standby; read-only only where it is
        // v8: who is active is set on the leader, per member, up to three with the leader.
        //     The switch of v6 is gone; a member shows what the leader made it
        // ═══════════════════════════════════════════════

        // "3 minutes ago" in the UI language. Intl speaks all nine, so no keys for it.
        // A server clock a little ahead of the browser must not read "in 5 seconds".
        function haRelTime(iso, language) {
            if (!iso) return '';
            const ts = new Date(iso).getTime();
            if (isNaN(ts)) return '';
            const sec = Math.min(0, Math.round((ts - Date.now()) / 1000));
            const abs = Math.abs(sec);
            const [n, unit] = abs < 60 ? [sec, 'second']
                : abs < 3600 ? [Math.round(sec / 60), 'minute']
                : abs < 86400 ? [Math.round(sec / 3600), 'hour']
                : [Math.round(sec / 86400), 'day'];
            try {
                return new Intl.RelativeTimeFormat(language || undefined, { numeric: 'auto' }).format(n, unit);
            } catch (_) {
                return fmtDate(iso);
            }
        }

        const HA_ROLE_STYLE = {
            standalone: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
            active: 'bg-green-500/20 text-green-300 border-green-500/30',
            serving: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
            pending: 'bg-blue-500/10 text-blue-300 border-blue-500/30 border-dashed',
            standby: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
        };

        // the active is the leader, it runs the automation. A standby that serves users is
        // an active instance to them and shows as one, every other standby as a standby.
        // pending: the leader made it active, and it has not said yet that it serves
        function HaRoleBadge({ role, serving = false, pending = false, t }) {
            const shown = role === 'standby' && serving ? (pending ? 'pending' : 'serving') : role;
            const label = { standalone: t('pgHaRoleStandalone'), active: t('pgHaRoleLeader'), serving: t('pgHaRoleActive'),
                            pending: t('pgHaRoleActivePending'), standby: t('pgHaRoleStandby') }[shown] || role || '-';
            return (
                <span data-ha-badge={shown || undefined} title={shown === 'pending' ? t('pgHaRoleActivePendingHint') : undefined}
                    className={`px-2 py-0.5 rounded-full border text-xs font-medium ${HA_ROLE_STYLE[shown] || HA_ROLE_STYLE.standalone}`}>
                    {label}
                </span>
            );
        }

        // Covers the page while the process restarts into its new role, then reloads.
        // The old process keeps answering for a second or two after the request, so a
        // plain "it answers" is not enough: wait until it was gone and came back, or it
        // answers in the new role after a while. After 120 s reload regardless.
        function HaRestartOverlay({ t, expectRole }) {
            useEffect(() => {
                const started = Date.now();
                let seenDown = false, stop = false, timer = null;
                const tick = async () => {
                    let up = false, role = null;
                    try {
                        const r = await fetch(`${API_URL}/auth/check?t=${Date.now()}`, { credentials: 'include', cache: 'no-store' });
                        if (r.status >= 502) {
                            seenDown = true;  // a reverse proxy in front answers for the dead backend
                        } else {
                            up = true;
                            const d = await r.json().catch(() => ({}));
                            role = d.ha_role || (d.ha && d.ha.role) || null;
                        }
                    } catch (_) {
                        seenDown = true;
                    }
                    if (stop) return;
                    const elapsed = Date.now() - started;
                    if (elapsed >= 120000 || (up && seenDown) || (up && elapsed >= 10000 && role === expectRole)) {
                        window.location.reload();
                        return;
                    }
                    timer = setTimeout(tick, 2000);
                };
                timer = setTimeout(tick, 2000);
                return () => { stop = true; clearTimeout(timer); };
            }, []);
            return ReactDOM.createPortal(
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4" role="alertdialog" aria-live="assertive">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 max-w-md w-full text-center space-y-3">
                        <div className="flex justify-center py-2 text-proxmox-orange" style={{ transform: 'scale(1.75)' }}>
                            <span className="inline-flex animate-spin"><Icons.RefreshCw /></span>
                        </div>
                        <div className="text-lg font-semibold text-white">{t('pgHaRestarting')}</div>
                        <div className="text-sm text-gray-400">{t('pgHaRestartingHint')}</div>
                    </div>
                </div>,
                document.body
            );
        }

        function HaPanel({ t, addToast, getAuthHeaders }) {
            const { language } = useTranslation();
            const { refreshHa, user, logout } = useAuth();
            const [status, setStatus] = useState(null);
            const [loadError, setLoadError] = useState('');
            const [busy, setBusy] = useState('');
            const [ownUrl, setOwnUrl] = useState('');
            const [code, setCode] = useState(null);          // {code, expires_at}, shown once
            const [now, setNow] = useState(Date.now());
            const [joinCode, setJoinCode] = useState('');
            const [joinUrl, setJoinUrl] = useState('');
            const [joinConfirm, setJoinConfirm] = useState(false);
            const [joinError, setJoinError] = useState('');
            const [interval, setIntervalValue] = useState('');
            const [confirmAction, setConfirmAction] = useState(null);   // 'promote' | 'unpair' | 'remove'
            const [removing, setRemoving] = useState(null);             // the member a 'remove' is about
            const [typed, setTyped] = useState('');
            const [restarting, setRestarting] = useState(null);         // role we restart into
            const [passwords, setPasswords] = useState({ code: '', join: '', confirm: '' });
            const [reauth, setReauth] = useState(null);                 // {form, code, error} of a refused re-auth
            const [unconfirmed, setUnconfirmed] = useState(false);      // the remove was refused as HA_REMOVE_UNCONFIRMED
            const [shutDown, setShutDown] = useState(false);            // the admin ticked "shut down for good"
            const [promoteSync, setPromoteSync] = useState(false);      // the promote was refused as HA_PROMOTE_SYNC
            const [forcePromote, setForcePromote] = useState(false);    // the admin ticked "promote without it"
            const [lastRemoval, setLastRemoval] = useState(null);       // {name, told} of the last removal

            // Every status request gets a number. One that left before a code was made cannot
            // know about it, so only a later answer may say the code is gone.
            const loadSeq = useRef(0);
            const load = async () => {
                const seq = ++loadSeq.current;
                try {
                    const r = await fetch(`${API_URL}/ha/status`, { credentials: 'include', headers: getAuthHeaders() });
                    if (!r.ok) {
                        setLoadError(await PegaProxApiErrors.message(r, t('pgHaLoadFailed')));
                        return;
                    }
                    const data = await r.json();
                    // a code the server no longer reports open was spent (a member that was
                    // already listed re-paired with it, the count stays) or replaced from another
                    // tab. An expired one stays, the box says so itself.
                    setCode(c => c && seq > c.seq && data.pairing_open_until !== c.expires_at
                        && c.expires_at * 1000 > Date.now() ? null : c);
                    setStatus(data);
                    setLoadError('');
                    // prefill once, never over something typed
                    setOwnUrl(v => v || data.suggested_url || '');
                    setJoinUrl(v => v || data.suggested_url || '');
                    setIntervalValue(v => v === '' ? String(data.interval || 30) : v);
                } catch (e) {
                    setLoadError(t('pgHaLoadFailed'));
                }
            };
            useEffect(() => { load(); }, []);

            // last contact and sync move on their own; the active also learns here that
            // a standby took its code
            useEffect(() => {
                if (restarting) return;
                const h = setInterval(load, 10000);
                return () => clearInterval(h);
            }, [restarting]);

            useEffect(() => {
                if (!code) return;
                const h = setInterval(() => setNow(Date.now()), 1000);
                return () => clearInterval(h);
            }, [code]);

            const role = status?.role || 'standalone';
            // a standby that serves users is an active instance to them and gets its own words:
            // consoles open here, a promote makes it the leader
            const serving = role === 'standby' && status?.serving === true;
            // up to four instances: the active and the standbys that follow it. members is
            // everyone but this instance, so the count adds one for it
            const members = Array.isArray(status?.members) ? status.members : [];
            const maxMembers = status?.max_members || 4;
            const standbyCount = status?.standby_count || 0;
            const groupFull = standbyCount >= maxMembers - 1;
            // who is active is set on the leader, per member: the leader and up to two members
            // (the limit counts the leader). Every member gets the list with serve in it.
            const activeLimit = status?.active_limit || 3;
            const actives = typeof status?.actives === 'number' ? status.actives
                : 1 + members.filter(m => m.serve === true).length;
            const activesFull = actives >= activeLimit;
            const memberName = (m) => m.url || (m.instance_id || '').slice(0, 8);
            // the code on screen is spent once someone pairs with it: this instance turns active,
            // or its group grows. A removal hides it as well, and the open-code note shows instead.
            useEffect(() => { setCode(null); }, [role, standbyCount]);

            // POST/PUT to /api/ha/*; the error text comes from the server as is, the
            // code tells a refused re-auth apart from everything else
            const send = async (method, path, body, fallback) => {
                const r = await fetch(`${API_URL}/ha/${path}`, {
                    method, credentials: 'include',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify(body || {})
                });
                if (!r.ok) {
                    const code = (await r.clone().json().catch(() => null))?.code || '';
                    return { ok: false, code, error: await PegaProxApiErrors.message(r, fallback || t('pgHaActionFailed')) };
                }
                return { ok: true, data: await r.json().catch(() => ({})) };
            };

            // Pairing, joining, promoting and unpairing hand the deployment over or take
            // it over, so the server asks for the account's own password once more. SSO
            // accounts have none here; for them it checks how fresh the sign-in is.
            const sso = ['oidc', 'entra'].includes(user?.auth_source);
            const setPassword = (form, value) => setPasswords(p => ({ ...p, [form]: value }));
            const needsPassword = (form) => !sso && !passwords[form];
            const withPassword = (form, body) => sso ? body : { ...body, user_password: passwords[form] };
            // a refused re-auth stays next to its field, and the field is emptied for the next try
            const reauthRefused = (form, res) => {
                if (res.code !== 'HA_REAUTH' && res.code !== 'HA_REAUTH_RECENT') return false;
                setReauth({ form, code: res.code, error: res.error });
                setPassword(form, '');
                return true;
            };

            const run = async (name, fn) => {
                setBusy(name);
                try { await fn(); }
                catch (e) { addToast?.(e.message || t('pgHaActionFailed'), 'error'); }
                setBusy('');
            };

            const createCode = () => run('code', async () => {
                setReauth(null);
                const url = ownUrl.trim();
                if (!url.startsWith('https://')) { addToast?.(t('pgHaUrlHttps'), 'error'); return; }
                const res = await send('POST', 'pairing-code', withPassword('code', { url }));
                if (!res.ok) { if (!reauthRefused('code', res)) addToast?.(res.error, 'error'); return; }
                setPassword('code', '');
                setCode({ code: res.data.code, expires_at: res.data.expires_at, seq: loadSeq.current });
                setNow(Date.now());
                load();
            });

            const join = () => run('join', async () => {
                setJoinError('');
                setReauth(null);
                const url = joinUrl.trim();
                if (!url.startsWith('https://')) { setJoinError(t('pgHaUrlHttps')); return; }
                const res = await send('POST', 'join', withPassword('join', { code: joinCode.trim(), own_url: url, confirm: true }));
                if (!res.ok) { if (!reauthRefused('join', res)) setJoinError(res.error); return; }
                setJoinCode('');
                setPassword('join', '');
                if (res.data.restarting) setRestarting('standby');
                else load();
            });

            const syncNow = () => run('sync', async () => {
                const res = await send('POST', 'sync-now', {}, t('pgHaSyncFailed'));
                if (!res.ok) { addToast?.(res.error, 'error'); return; }
                if (res.data.status) setStatus(s => ({ ...(s || {}), ...res.data.status }));
                const result = res.data.result;
                if (result === 'applied') addToast?.(t('pgHaSyncApplied'), 'success');
                else if (result === 'unchanged') addToast?.(t('pgHaSyncUnchanged'), 'info');
                else addToast?.((res.data.status?.sync?.last_error) || t('pgHaSyncFailed'), 'error');
                refreshHa?.();
            });

            const saveInterval = () => run('interval', async () => {
                const n = Number(interval);
                if (!Number.isInteger(n) || n < 5 || n > 3600) { addToast?.(t('pgHaIntervalRange'), 'error'); return; }
                const res = await send('PUT', 'settings', { interval: n });
                if (!res.ok) { addToast?.(res.error, 'error'); return; }
                setIntervalValue(String(res.data.interval || n));
                addToast?.(t('pgHaIntervalSaved'), 'success');
                load();
            });

            // Live view is this instance's own setting, never synced. A standby restarts to
            // connect or disconnect; elsewhere it is only stored for when it becomes one.
            const liveView = status?.live_view !== false;
            const setLiveView = (on) => run('live', async () => {
                const res = await send('PUT', 'settings', { live_view: on });
                if (!res.ok) { addToast?.(res.error, 'error'); return; }
                if (res.data.restarting) { setRestarting('standby'); return; }
                addToast?.(t('pgHaLiveViewSaved'), 'success');
                load();
            });

            // Forwarding is this instance's own setting too, and takes effect at once: on, a
            // standby carries out what its users do through the active; off, it only shows.
            // status.forwarding says whether it does so right now (the active may be away).
            const forwardWrites = status?.forward_writes !== false;
            const setForwardWrites = (on) => run('forward', async () => {
                const res = await send('PUT', 'settings', { forward_writes: on });
                if (!res.ok) { addToast?.(res.error, 'error'); return; }
                if (res.data.restarting) { setRestarting('standby'); return; }
                addToast?.(t(on ? 'pgHaForwardOn' : 'pgHaForwardOff'), 'success');
                load();
                // the banner and every button follow the new value
                refreshHa?.();
            });

            // The leader makes a member active (or a standby again); the member follows at its
            // next sync, with its live view and forwarding on, and says so in serving_seen.
            // Past the limit the server refuses (HA_ACTIVE_LIMIT), its words go to the toast.
            const setMemberServe = (m, on) => run('serve', async () => {
                const res = await send('PUT', `members/${encodeURIComponent(m.instance_id)}/serve`, { serve: on });
                if (!res.ok) { addToast?.(res.error, 'error'); load(); return; }
                const serve = res.data.serve === true;
                setStatus(s => ({
                    ...(s || {}),
                    ...(typeof res.data.actives === 'number' ? { actives: res.data.actives } : {}),
                    members: (s?.members || []).map(x => x.instance_id === m.instance_id ? { ...x, serve } : x),
                }));
                addToast?.(t(serve ? 'pgHaMemberServeOn' : 'pgHaMemberServeOff').replace('{name}', memberName(m)), 'success');
                load();
            });

            // a live view switched since this standby started waits for a restart, this does
            // it now. A changed cluster connection is rebuilt in place without one, and a
            // waiting one is rebuilt at once; either way the answer says which it was.
            const applyNow = () => run('apply', async () => {
                const res = await send('POST', 'apply-config', {});
                if (!res.ok) { addToast?.(res.error, 'error'); return; }
                if (res.data.restarting) { setRestarting('standby'); return; }
                addToast?.(t(res.data.reloaded ? 'pgHaReloaded' : 'pgHaNothingToApply'), res.data.reloaded ? 'success' : 'info');
                load();
            });

            const WORD = { promote: 'PROMOTE', unpair: 'UNPAIR', remove: 'REMOVE' };
            // null closes the box; either way nothing typed survives into the next one.
            // A remove names the member it is about.
            const openConfirm = (what, member = null) => {
                setConfirmAction(what);
                setRemoving(member);
                setTyped('');
                setPassword('confirm', '');
                setReauth(null);
                setUnconfirmed(false);
                setShutDown(false);
                setPromoteSync(false);
                setForcePromote(false);
                setLastRemoval(null);
            };
            const confirmed = () => run(confirmAction, async () => {
                const what = confirmAction;
                const target = removing;
                setReauth(null);
                const path = what === 'remove' ? `members/${encodeURIComponent(target.instance_id)}/remove` : what;
                // shut_down only goes out as the second step, after the server asked for it and
                // the admin ticked the box
                const shutDownNow = what === 'remove' && unconfirmed && shutDown;
                // force likewise: only after the server said the pull before promoting failed
                const forceNow = what === 'promote' && promoteSync && forcePromote;
                const body = { confirm: WORD[what], ...(shutDownNow ? { shut_down: true } : {}), ...(forceNow ? { force: true } : {}) };
                const res = await send('POST', path, withPassword('confirm', body));
                if (!res.ok) {
                    if (reauthRefused('confirm', res)) return;
                    // never seen as a standby under this epoch: it may still run as an active that
                    // nobody can tell any more. Ask once more instead of reporting an error.
                    if (what === 'remove' && res.code === 'HA_REMOVE_UNCONFIRMED') {
                        setUnconfirmed(true);
                        return;
                    }
                    // the active answers but the last configuration could not be fetched first
                    if (what === 'promote' && res.code === 'HA_PROMOTE_SYNC') {
                        setPromoteSync(true);
                        return;
                    }
                    addToast?.(res.error, 'error');
                    return;
                }
                openConfirm(null);
                if (res.data.restarting) {
                    setRestarting(what === 'promote' ? 'active' : 'standalone');
                } else if (what === 'remove') {
                    // the row goes at once; the next status brings the count and the pairing card along
                    if (Array.isArray(res.data.members)) setStatus(s => ({ ...(s || {}), members: res.data.members }));
                    // told is true only when the member answered and let go of the group
                    const told = typeof res.data.told === 'boolean' ? res.data.told : null;
                    setLastRemoval({ name: target.url || target.instance_id.slice(0, 8), told });
                    addToast?.(t('pgHaMemberRemoved'), told === false ? 'info' : 'success');
                    load();
                } else {
                    addToast?.(t('pgHaUnpaired'), 'success');
                    load();
                }
            });

            const when = (iso) => iso ? <span title={fmtDate(iso)}>{haRelTime(iso, language)}</span> : <span className="text-gray-500">{t('pgHaNever')}</span>;
            const countdown = (() => {
                if (!code) return '';
                const left = Math.max(0, Math.floor(code.expires_at - now / 1000));
                return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
            })();
            const codeExpired = code && code.expires_at * 1000 <= now;

            const card = 'bg-proxmox-dark border border-proxmox-border rounded-xl p-4 space-y-3';
            const field = 'px-3 py-2 bg-proxmox-card border border-proxmox-border rounded text-sm text-white disabled:opacity-50';
            const input = `w-full ${field}`;
            const btn = 'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed';
            const btnGhost = `${btn} bg-proxmox-card border border-proxmox-border text-gray-300 hover:text-white hover:border-gray-500`;
            const row = (label, value) => (
                <div className="flex items-start justify-between gap-4 text-sm">
                    <span className="text-gray-400 whitespace-nowrap">{label}</span>
                    <span className="text-gray-200 text-right min-w-0 break-all">{value}</span>
                </div>
            );

            const sync = status?.sync || {};
            const skipped = Object.entries(sync.skipped_columns || {}).filter(([, cols]) => cols && cols.length);
            // an unreadable state file: the server refuses promote and the interval (409),
            // so the panel offers neither and says why in the red note
            const broken = !!status?.broken;

            const passwordInput = (form, id) => !sso && (
                <div>
                    <label className="block text-xs text-gray-400 mb-1" htmlFor={id}>{t('pgHaPassword')}</label>
                    <input id={id} type="password" autoComplete="current-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true"
                        value={passwords[form]} onChange={e => setPassword(form, e.target.value)}
                        aria-invalid={reauth?.form === form ? 'true' : undefined}
                        aria-describedby={reauth?.form === form ? `${id}-error` : undefined} className={input} />
                </div>
            );
            const reauthNote = (form, id) => reauth?.form === form && (
                <div id={`${id}-error`} data-ha-reauth={reauth.code}
                    className="rounded-lg p-2 text-sm border bg-red-500/10 border-red-500/30 text-red-300 space-y-2">
                    <div className="break-all">{reauth.error}</div>
                    {reauth.code === 'HA_REAUTH_RECENT' && (
                        <button onClick={() => logout()} className={btnGhost}>
                            <Icons.LogOut />
                            {t('pgHaSignInAgain')}
                        </button>
                    )}
                </div>
            );

            // Everyone else in the group, as this instance knows them: on the active its
            // standbys, each with Remove; on a standby the active and the other standbys, with
            // the one it pulls from marked as its source. The leader also sets who is active.
            const cell = 'py-2 pr-4';
            const canRemove = role === 'active';
            const canSetActive = role === 'active';
            // the leader is always active; a member is what the leader made it, and "pending"
            // until it said it serves. One never reached yet shows what it was made too.
            const memberRole = (m) => m.role_seen === 'active' ? 'active' : m.serve === true ? 'standby' : m.role_seen;
            const membersCard = (
                <div className={card} data-ha-members={members.length}>
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <h4 className="font-medium text-white flex items-center gap-2">
                            <Icons.Users />
                            {t('pgHaMembers')}
                        </h4>
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                            {canSetActive && (
                                <span className={`text-xs ${activesFull ? 'text-yellow-300' : 'text-gray-400'}`} data-ha-actives={actives}>
                                    {t('pgHaActiveCount').replace('{n}', actives).replace('{max}', activeLimit)}
                                </span>
                            )}
                            <span className="text-xs text-gray-400" data-ha-count>
                                {t('pgHaMemberCount').replace('{n}', members.length + 1).replace('{max}', maxMembers)}
                            </span>
                        </div>
                    </div>
                    {members.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="text-left text-xs text-gray-500 border-b border-proxmox-border">
                                        <th className={`${cell} font-medium`}>{t('pgHaInstanceId')}</th>
                                        <th className={`${cell} font-medium`}>{t('pgHaPeerUrl')}</th>
                                        <th className={`${cell} font-medium`}>{t('pgHaPeerSeen')}</th>
                                        <th className={`${cell} font-medium`}>{t('pgHaEpoch')}</th>
                                        <th className={`${cell} font-medium`}>{t('pgHaKey')}</th>
                                        <th className={`${cell} font-medium whitespace-nowrap`}>{t('pgHaLastContact')}</th>
                                        <th className={`${cell} font-medium whitespace-nowrap`}>{t('pgHaLastError')}</th>
                                        {canSetActive && <th className={`${cell} font-medium`} title={t('pgHaActiveHint')}>{t('pgHaRoleActive')}</th>}
                                        {canRemove && <th className="py-2" />}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-proxmox-border">
                                    {members.map(m => (
                                        <tr key={m.instance_id} data-ha-member={m.instance_id} data-ha-source={m.is_source ? '' : undefined}
                                            data-ha-confirmed={typeof m.confirmed_standby === 'boolean' ? String(m.confirmed_standby) : undefined}>
                                            <td className={`${cell} whitespace-nowrap`}>
                                                <span className="font-mono text-xs text-gray-200" title={m.instance_id}>{(m.instance_id || '').slice(0, 8)}</span>
                                                {m.is_source && (
                                                    <span title={t('pgHaSourceHint')}
                                                        className="ml-2 px-1.5 py-0.5 rounded-full border text-[11px] bg-blue-500/20 text-blue-300 border-blue-500/30">
                                                        {t('pgHaSource')}
                                                    </span>
                                                )}
                                            </td>
                                            <td className={`${cell} font-mono text-xs text-gray-200 whitespace-nowrap`}>{m.url || '-'}</td>
                                            <td className={`${cell} whitespace-nowrap`}>
                                                {memberRole(m)
                                                    ? <HaRoleBadge role={memberRole(m)} serving={m.serve === true} pending={m.serving_seen !== true} t={t} />
                                                    : '-'}
                                                {/* confirmed: a standby under the current epoch. Only the active warns
                                                    about the others, since a removal there needs the second step */}
                                                {m.confirmed_standby === true && (
                                                    <span title={t('pgHaConfirmedHint')} className="ml-2 text-[11px] text-green-300">{t('pgHaConfirmed')}</span>
                                                )}
                                                {m.confirmed_standby === false && canRemove && (
                                                    <span title={t('pgHaUnconfirmedHint')}
                                                        className="ml-2 px-1.5 py-0.5 rounded-full border text-[11px] bg-yellow-500/20 text-yellow-300 border-yellow-500/40">
                                                        {t('pgHaUnconfirmed')}
                                                    </span>
                                                )}
                                            </td>
                                            <td className={`${cell} text-gray-200`}>{m.epoch_seen ?? '-'}</td>
                                            <td className={`${cell} whitespace-nowrap`} data-ha-key={m.key_fingerprint ? 'key' : m.key_fingerprint === '' ? 'secret' : undefined}>
                                                {m.key_fingerprint
                                                    ? <span className="font-mono text-xs text-gray-200" title={m.key_fingerprint}>{m.key_fingerprint}</span>
                                                    : m.key_fingerprint === ''
                                                        ? <span className="text-xs text-yellow-300" title={t('pgHaOldSecretHint')}>{t('pgHaOldSecret')}</span>
                                                        : <span className="text-gray-500">-</span>}
                                            </td>
                                            <td className={`${cell} text-gray-200 whitespace-nowrap`}>{when(m.last_contact)}</td>
                                            <td className={`${cell} text-xs max-w-xs`}>
                                                {m.last_error
                                                    ? <span className="text-red-300 break-all">{m.last_error}</span>
                                                    : <span className="text-gray-500">-</span>}
                                            </td>
                                            {canSetActive && (
                                                <td className={cell}>
                                                    {/* a standby can only be made active while there is room; off always works */}
                                                    <button type="button" role="switch" aria-checked={m.serve === true}
                                                        aria-label={t('pgHaServeMember').replace('{name}', memberName(m))}
                                                        title={activesFull && m.serve !== true ? t('pgHaActiveLimit').replace('{max}', activeLimit) : undefined}
                                                        onClick={() => setMemberServe(m, m.serve !== true)}
                                                        disabled={!!busy || broken || (activesFull && m.serve !== true)}
                                                        data-ha-serve={m.serve === true ? 'on' : 'off'}
                                                        className={`toggle-switch flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed ${m.serve === true ? 'active' : ''}`} />
                                                </td>
                                            )}
                                            {canRemove && (
                                                <td className="py-2 text-right">
                                                    <button onClick={() => openConfirm('remove', m)} disabled={!!busy} className={`${btnGhost} ml-auto`}>
                                                        <Icons.UserX />
                                                        {t('pgHaRemove')}
                                                    </button>
                                                </td>
                                            )}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <p className="text-sm text-gray-400">{t('pgHaNoMembers')}</p>
                    )}
                    {canSetActive && members.length > 0 && (
                        <div className="space-y-1">
                            <p className="text-xs text-gray-500">{t('pgHaActiveHint')}</p>
                            {activesFull && (
                                <p className="text-xs text-yellow-300" data-ha-active-limit>
                                    {t('pgHaActiveLimit').replace('{max}', activeLimit)}
                                </p>
                            )}
                        </div>
                    )}
                </div>
            );

            const intervalCard = (
                <div className={card}>
                    <label className="block text-sm font-medium text-white" htmlFor="pgha-interval">{t('pgHaInterval')}</label>
                    <div className="flex items-center gap-2">
                        <input id="pgha-interval" type="number" min="5" max="3600" value={interval} disabled={broken}
                            onChange={e => setIntervalValue(e.target.value)} className={`w-32 ${field}`} />
                        <button onClick={saveInterval} disabled={!!busy || broken} className={btnGhost}>{t('save')}</button>
                    </div>
                    <p className="text-xs text-gray-500">{t('pgHaIntervalHint')}</p>
                </div>
            );

            // the running managers only differ from the switch until the restart that follows
            const standby = role === 'standby';
            const pending = sync.restart_pending || null;
            const liveMismatch = standby && typeof status?.managers_running === 'boolean'
                && status.managers_running !== liveView;
            // a changed cluster connection is rebuilt in place, a few seconds after the sync
            // that brought it; what the last rebuild could not build stays disconnected here
            const reloadPending = standby && sync.reload_pending ? sync.reload_pending : null;
            const lastReload = standby && sync.last_reload && typeof sync.last_reload === 'object' ? sync.last_reload : null;
            const reloadFailed = Array.isArray(lastReload?.failed)
                ? lastReload.failed.map(f => typeof f === 'string' ? f : (f?.name || f?.key || f?.id || '')).filter(Boolean)
                : [];

            const liveViewCard = (
                <div className={card} data-ha-live-view={liveView ? 'on' : 'off'}>
                    <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                            <label className="block text-sm font-medium text-white" htmlFor="pgha-live-view">{t('pgHaLiveView')}</label>
                            <p className="text-xs text-gray-500 mt-1">{t('pgHaLiveViewHint')}</p>
                        </div>
                        <button id="pgha-live-view" type="button" role="switch" aria-checked={liveView}
                            onClick={() => setLiveView(!liveView)} disabled={!!busy || broken}
                            className={`toggle-switch flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed ${liveView ? 'active' : ''}`} />
                    </div>
                    {standby && (
                        <>
                            {row(t('pgHaManagers'), status.managers_running
                                ? <span className="text-green-300">{t(serving ? 'pgHaManagersServing' : 'pgHaManagersRunning')}</span>
                                : <span className="text-gray-400">{t('pgHaManagersOff')}</span>)}
                            {lastReload && row(t('pgHaLastReload'), (
                                <span data-ha-last-reload>
                                    {when(lastReload.at)}
                                    {lastReload.reason && <span className="block text-xs text-gray-500">{lastReload.reason}</span>}
                                </span>
                            ))}
                            {reloadPending && (
                                <div className="space-y-2" data-ha-reload-pending>
                                    <p className="text-xs text-yellow-300">
                                        {t('pgHaReloadPending')}
                                        {reloadPending.reason && <span className="block text-gray-400 break-all">{reloadPending.reason}</span>}
                                    </p>
                                    <button onClick={applyNow} disabled={!!busy} className={btnGhost}>
                                        <Icons.RefreshCw />
                                        {t('pgHaApplyNow')}
                                    </button>
                                </div>
                            )}
                            {reloadFailed.length > 0 && (
                                <div className="rounded-lg p-2 text-xs border bg-red-500/10 border-red-500/30 text-red-300 space-y-1" data-ha-reload-failed>
                                    <div>{t('pgHaReloadFailed')}</div>
                                    <ul className="font-mono break-all">
                                        {reloadFailed.map(f => <li key={f}>{f}</li>)}
                                    </ul>
                                </div>
                            )}
                            <p className="text-xs text-yellow-300">{t('pgHaLiveViewRestart')}</p>
                        </>
                    )}
                </div>
            );

            // next to the live view in every role; a standby also says when it is on but has
            // no active to hand things to. A serving member keeps its consoles then, only the
            // changes wait
            const forwardPaused = standby && forwardWrites && status?.forwarding === false;
            const forwardCard = (
                <div className={card} data-ha-forward={forwardWrites ? 'on' : 'off'}>
                    <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                            <label className="block text-sm font-medium text-white" htmlFor="pgha-forward">{t('pgHaForwardWrites')}</label>
                            <p className="text-xs text-gray-500 mt-1">{t('pgHaForwardWritesHint')}</p>
                        </div>
                        <button id="pgha-forward" type="button" role="switch" aria-checked={forwardWrites}
                            onClick={() => setForwardWrites(!forwardWrites)} disabled={!!busy || broken}
                            className={`toggle-switch flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed ${forwardWrites ? 'active' : ''}`} />
                    </div>
                    {forwardPaused && (
                        <p className="text-xs text-yellow-300" data-ha-forward-paused={serving ? 'serving' : 'standby'}>
                            {t(serving ? 'pgHaForwardPausedServing' : 'pgHaForwardPaused')}
                        </p>
                    )}
                </div>
            );

            // On a member, below the two it needs: whether the leader made it active. Read only,
            // the leader sets it. Made active without either of the two, it serves nobody, and says so.
            const assigned = status?.serve_assigned === true;
            const assignedIdle = assigned && (!liveView || !forwardWrites);
            const assignedCard = !status?.removed && (
                <div className={`${card} md:col-span-2`} data-ha-assigned={assigned ? 'on' : 'off'}>
                    <h4 className="font-medium text-white flex items-center gap-2">
                        <Icons.Users />
                        {t('pgHaAssignedTitle')}
                    </h4>
                    <p className="text-sm text-gray-300">{t(assigned ? 'pgHaAssignedOn' : 'pgHaAssignedOff')}</p>
                    {assignedIdle && (
                        <p className="text-xs text-yellow-300" data-ha-serve-idle>{t('pgHaAssignedNeeds')}</p>
                    )}
                    <p className="text-xs text-gray-500 flex items-start gap-2">
                        <span className="flex-shrink-0"><Icons.Lock className="w-4 h-4" /></span>
                        <span>{t('pgHaAssignedHint')}</span>
                    </p>
                </div>
            );

            const restartNote = standby && (pending || liveMismatch) && (
                <div className="rounded-xl p-4 space-y-2 border bg-yellow-500/10 border-yellow-500/40" data-ha-restart-pending>
                    <div className="flex items-start gap-2 text-sm text-yellow-200">
                        <span className="mt-0.5 flex-shrink-0"><Icons.AlertTriangle /></span>
                        <span>{t('pgHaRestartPending')}</span>
                    </div>
                    {pending && (pending.reason || pending.since) && (
                        <div className="text-xs text-gray-400 break-all">
                            {pending.reason}{pending.reason && pending.since ? ' · ' : ''}{pending.since && when(pending.since)}
                        </div>
                    )}
                    <button onClick={applyNow} disabled={!!busy} className={`${btn} bg-yellow-600 hover:bg-yellow-700 text-white`}>
                        <Icons.RefreshCw />
                        {t('pgHaApplyNow')}
                    </button>
                </div>
            );

            // a poll can report the file unreadable while the promote box is open, or the member
            // gone (or this instance no longer active) while its remove box is
            const removeStale = confirmAction === 'remove'
                && (role !== 'active' || !members.some(m => m.instance_id === removing?.instance_id));
            // the server refused the remove as unconfirmed: the same box asks once more
            const needShutDown = confirmAction === 'remove' && unconfirmed;
            const needForce = confirmAction === 'promote' && promoteSync;
            const typedBox = confirmAction && !(confirmAction === 'promote' && broken) && !removeStale && (
                <div className="rounded-xl p-4 space-y-3 border bg-red-500/10 border-red-500/30" data-ha-confirm={confirmAction}>
                    <p className="text-sm text-red-300">
                        {confirmAction === 'promote' ? (serving ? t('pgHaPromoteLeaderDesc') : `${t('pgHaPromoteDesc')} ${t('pgHaPromoteSyncFirst')}`)
                            : confirmAction === 'remove' ? t('pgHaRemoveDesc').replace('{name}', removing.url || removing.instance_id.slice(0, 8))
                            : role === 'standby' ? t('pgHaUnpairStandbyDesc') : t('pgHaUnpairActiveDesc')}
                    </p>
                    {needForce && (
                        <div className="rounded-lg p-3 space-y-2 border bg-yellow-500/10 border-yellow-500/40" data-ha-promote-sync>
                            <div className="flex items-start gap-2 text-sm text-yellow-200">
                                <span className="mt-0.5 flex-shrink-0"><Icons.AlertTriangle /></span>
                                <span>{t(serving ? 'pgHaPromoteLeaderSyncFailed' : 'pgHaPromoteSyncFailed')}</span>
                            </div>
                            <label className="flex items-start gap-2 text-sm text-gray-200 cursor-pointer">
                                <input type="checkbox" checked={forcePromote} onChange={e => setForcePromote(e.target.checked)} className="mt-0.5" />
                                <span>{t('pgHaPromoteForce')}</span>
                            </label>
                        </div>
                    )}
                    {needShutDown && (
                        <div className="rounded-lg p-3 space-y-2 border bg-yellow-500/10 border-yellow-500/40" data-ha-unconfirmed>
                            <div className="flex items-start gap-2 text-sm text-yellow-200">
                                <span className="mt-0.5 flex-shrink-0"><Icons.AlertTriangle /></span>
                                <span>{t('pgHaRemoveUnconfirmed')}</span>
                            </div>
                            <label className="flex items-start gap-2 text-sm text-gray-200 cursor-pointer">
                                <input type="checkbox" checked={shutDown} onChange={e => setShutDown(e.target.checked)} className="mt-0.5" />
                                <span>{t('pgHaShutDownConfirm')}</span>
                            </label>
                        </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-xl">
                        <div>
                            <label className="block text-xs text-gray-400 mb-1" htmlFor="pgha-typed">
                                {t('pgHaTypeToConfirm').replace('{word}', WORD[confirmAction])}
                            </label>
                            <input id="pgha-typed" value={typed} onChange={e => setTyped(e.target.value)} autoComplete="off"
                                spellCheck={false} className={`${input} font-mono`} placeholder={WORD[confirmAction]} />
                        </div>
                        {passwordInput('confirm', 'pgha-confirm-password')}
                    </div>
                    {reauthNote('confirm', 'pgha-confirm-password')}
                    <div className="flex flex-wrap items-center gap-2">
                        <button onClick={confirmed} disabled={typed !== WORD[confirmAction] || needsPassword('confirm') || (needShutDown && !shutDown) || (needForce && !forcePromote) || !!busy}
                            className={`${btn} bg-red-600 hover:bg-red-700 text-white`}>
                            {confirmAction === 'promote' ? t(serving ? 'pgHaPromoteLeader' : 'pgHaPromote')
                                : confirmAction === 'remove' ? (needShutDown ? t('pgHaRemoveAnyway') : t('pgHaRemove'))
                                : t('pgHaUnpair')}
                        </button>
                        <button onClick={() => openConfirm(null)} className={btnGhost}>{t('cancel')}</button>
                    </div>
                </div>
            );

            // What the last removal reached, until the next action. The toast is gone after a few
            // seconds, and a member that was not told has to be unpaired by hand over there.
            const removalNote = lastRemoval && (
                <div data-ha-removal={lastRemoval.told === true ? 'told' : lastRemoval.told === false ? 'not-reached' : 'unknown'}
                    className={`rounded-xl p-4 border flex items-start gap-2 text-sm ${lastRemoval.told === false
                        ? 'bg-yellow-500/10 border-yellow-500/40 text-yellow-200'
                        : 'bg-green-500/10 border-green-500/30 text-green-300'}`}>
                    <span className="mt-0.5 flex-shrink-0">{lastRemoval.told === false ? <Icons.AlertTriangle /> : <Icons.Check />}</span>
                    <span className="flex-1 min-w-0" style={{ overflowWrap: 'anywhere' }}>
                        {lastRemoval.told === true ? t('pgHaRemovedTold').replace('{name}', lastRemoval.name)
                            : lastRemoval.told === false ? t('pgHaRemovedNotReached').replace('{name}', lastRemoval.name)
                            : t('pgHaMemberRemoved')}
                    </span>
                    <button onClick={() => setLastRemoval(null)} title={t('close')} aria-label={t('close')}
                        className="flex-shrink-0 text-gray-400 hover:text-white">
                        <Icons.X />
                    </button>
                </div>
            );

            // This instance learned that the active took it out of the group. It acts on nothing
            // and receives nothing until an admin unpairs it here.
            const removedHere = status?.removed;
            const removedNote = removedHere && role !== 'standalone' && (
                <div className="rounded-xl p-4 space-y-2 border bg-red-500/10 border-red-500/30" data-ha-removed>
                    <div className="flex items-start gap-2 text-sm text-red-300">
                        <span className="mt-0.5 flex-shrink-0"><Icons.AlertTriangle /></span>
                        <span>{t('pgHaRemovedHere')}</span>
                    </div>
                    <div className="text-xs text-gray-400">
                        <span title={removedHere.by || ''}>
                            {t('pgHaRemovedBy').replace('{by}', (removedHere.by || '-').slice(0, 8)).replace('{epoch}', removedHere.epoch ?? '-')}
                        </span>
                        {removedHere.at && <> · {when(removedHere.at)}</>}
                    </div>
                    <p className="text-sm text-gray-300">{t('pgHaRemovedHereNext')}</p>
                </div>
            );

            // A standalone's first code makes it the active. The active hands out one code per
            // further standby until the group is full; the server refuses a fourth standby too.
            const adding = role === 'active';
            const pairingCard = (
                <div className={card} data-ha-pairing={adding && groupFull ? 'full' : 'open'}>
                    <h4 className="font-medium text-white flex items-center gap-2">
                        {adding ? <Icons.UserPlus /> : <Icons.Key />}
                        {adding ? t('pgHaAddStandbyTitle') : t('pgHaMakeActiveTitle')}
                    </h4>
                    {adding && groupFull ? (
                        <p className="text-sm text-yellow-300">{t('pgHaGroupFull').replace('{max}', maxMembers)}</p>
                    ) : (
                        <>
                            <p className="text-sm text-gray-400">{adding ? t('pgHaAddStandbyDesc') : t('pgHaMakeActiveDesc')}</p>
                            <div>
                                <label className="block text-xs text-gray-400 mb-1" htmlFor="pgha-own-url">{t('pgHaOwnUrl')}</label>
                                <input id="pgha-own-url" value={ownUrl} onChange={e => setOwnUrl(e.target.value)}
                                    placeholder="https://pegaprox-a.example:5000" className={`${input} font-mono`} />
                                <div className="text-[11px] text-gray-500 mt-1">{t('pgHaOwnUrlHint')}</div>
                            </div>
                            {passwordInput('code', 'pgha-code-password')}
                            {reauthNote('code', 'pgha-code-password')}
                            {status?.pairing_open_until && !code && (
                                <p className="text-xs text-yellow-300">
                                    {t('pgHaCodeOpen').replace('{time}', fmtDate(status.pairing_open_until))}
                                </p>
                            )}
                            <button onClick={createCode} disabled={needsPassword('code') || !!busy}
                                className={`${btn} bg-proxmox-orange hover:bg-proxmox-orange/90 text-white`}>
                                <Icons.Key />
                                {t('pgHaCreateCode')}
                            </button>
                            {code && (
                                <div className="bg-yellow-500/10 border border-yellow-500/40 rounded-xl p-3 space-y-2" data-ha-code>
                                    <div className="text-xs font-medium text-yellow-200">{t('pgHaCodeOnce')}</div>
                                    {codeExpired ? (
                                        <p className="text-sm text-red-300">{t('pgHaCodeExpired')}</p>
                                    ) : (
                                        <>
                                            <div className="flex items-start gap-2">
                                                <code className="flex-1 px-3 py-2 bg-black/40 rounded text-xs text-yellow-200 break-all font-mono select-all">{code.code}</code>
                                                <span className="shrink-0 inline-flex">
                                                    <CopyButton value={code.code} size="md" title={t('copy')}
                                                        className="w-8 h-8 border border-proxmox-border hover:border-gray-500" />
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-2 text-xs text-gray-400">
                                                <Icons.Clock />
                                                <span>{t('pgHaCodeExpiresIn').replace('{time}', countdown)}</span>
                                            </div>
                                            <p className="text-xs text-gray-400">{t('pgHaCodeNext')}</p>
                                        </>
                                    )}
                                </div>
                            )}
                        </>
                    )}
                </div>
            );

            if (!status) {
                return (
                    <div className="space-y-4">
                        {loadError ? (
                            <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 flex items-center gap-2">
                                <Icons.AlertTriangle />
                                {loadError}
                            </div>
                        ) : (
                            <div className="text-sm text-gray-400 flex items-center gap-2">
                                <span className="inline-flex animate-spin"><Icons.RefreshCw /></span>
                                {t('loading')}
                            </div>
                        )}
                    </div>
                );
            }

            // what this instance is in its group: the leader, a member that serves users, or a
            // plain standby. A removed one waits for nothing, the note below says what it is
            const roleDesc = role === 'active' ? t('pgHaRoleDescLeader')
                : serving ? t('pgHaRoleDescActive')
                : role === 'standby' && !status.removed ? t('pgHaRoleDescStandby') : '';

            return (
                <div className="space-y-4" data-ha-role={role}>
                    {restarting && <HaRestartOverlay t={t} expectRole={restarting} />}

                    <div className={card}>
                        <div className="flex flex-wrap items-center justify-between gap-3">
                            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                <Icons.Layers />
                                {t('pgHaTab')}
                            </h3>
                            <HaRoleBadge role={role} serving={status.serving === true} t={t} />
                        </div>
                        <p className="text-sm text-gray-400 max-w-3xl">{t('pgHaIntro')}</p>
                        {role !== 'standalone' && (
                            <p className="text-xs text-gray-400 max-w-3xl flex items-start gap-2" data-ha-automation={serving ? 'serving' : role}>
                                <span className="flex-shrink-0"><Icons.Zap /></span>
                                <span>{roleDesc ? `${roleDesc} ${t('pgHaAutomationLeader')}` : t('pgHaAutomationLeader')}</span>
                            </p>
                        )}
                        <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-400">
                            <span>{t('pgHaEpoch')}: <span className="text-gray-200">{status.epoch}</span></span>
                            <span>{t('pgHaInstanceId')}: <span className="font-mono text-gray-200" title={status.instance_id}>{(status.instance_id || '').slice(0, 8)}</span></span>
                        </div>
                        {broken && (
                            <div className="rounded-lg p-3 text-sm border bg-red-500/10 border-red-500/30 text-red-300 space-y-1" data-ha-broken>
                                <div>{t('pgHaBroken')} <span className="font-mono text-xs">{status.broken}</span></div>
                                <div className="text-xs">{t('pgHaBrokenLocked')}</div>
                            </div>
                        )}
                        {loadError && <div className="text-xs text-red-400">{loadError}</div>}
                    </div>

                    {removedNote}
                    {removalNote}

                    {role === 'standalone' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {pairingCard}

                            <div className={card}>
                                <h4 className="font-medium text-white flex items-center gap-2">
                                    <Icons.Link />
                                    {t('pgHaJoinTitle')}
                                </h4>
                                <p className="text-sm text-gray-400">{t('pgHaJoinDesc')}</p>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1" htmlFor="pgha-join-code">{t('pgHaCode')}</label>
                                    <textarea id="pgha-join-code" value={joinCode} onChange={e => setJoinCode(e.target.value)} rows={3}
                                        spellCheck={false} autoComplete="off" placeholder="pgxha1_..."
                                        className={`${input} font-mono text-xs break-all`} />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1" htmlFor="pgha-join-url">{t('pgHaOwnUrl')}</label>
                                    <input id="pgha-join-url" value={joinUrl} onChange={e => setJoinUrl(e.target.value)}
                                        placeholder="https://pegaprox-b.example:5000" className={`${input} font-mono`} />
                                </div>
                                <div className="rounded-lg p-3 text-sm border bg-yellow-500/10 border-yellow-500/40 text-yellow-200 flex items-start gap-2">
                                    <span className="mt-0.5 flex-shrink-0"><Icons.AlertTriangle /></span>
                                    <span>{t('pgHaJoinWarning')}</span>
                                </div>
                                <label className="flex items-start gap-2 text-sm text-gray-300 cursor-pointer">
                                    <input type="checkbox" checked={joinConfirm} onChange={e => setJoinConfirm(e.target.checked)} className="mt-0.5" />
                                    <span>{t('pgHaJoinConfirm')}</span>
                                </label>
                                {passwordInput('join', 'pgha-join-password')}
                                {reauthNote('join', 'pgha-join-password')}
                                {joinError && (
                                    <div className="rounded-lg p-2 text-sm border bg-red-500/10 border-red-500/30 text-red-300 break-all">{joinError}</div>
                                )}
                                <button onClick={join} disabled={!joinConfirm || !joinCode.trim() || needsPassword('join') || !!busy}
                                    className={`${btn} bg-yellow-600 hover:bg-yellow-700 text-white`}>
                                    <Icons.Link />
                                    {busy === 'join' ? t('pgHaJoining') : t('pgHaJoin')}
                                </button>
                            </div>
                            {liveViewCard}
                            {forwardCard}
                        </div>
                    )}

                    {role === 'active' && (
                        <>
                            {membersCard}
                            {confirmAction === 'remove' && typedBox}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {pairingCard}
                                {intervalCard}
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {liveViewCard}
                                {forwardCard}
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <button onClick={() => openConfirm('unpair')} disabled={!!busy} className={btnGhost}>
                                    <Icons.Unlink />
                                    {t('pgHaUnpair')}
                                </button>
                            </div>
                            {confirmAction !== 'remove' && typedBox}
                        </>
                    )}

                    {role === 'standby' && (
                        <>
                            {restartNote}
                            {membersCard}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className={card}>
                                    <h4 className="font-medium text-white flex items-center gap-2">
                                        <Icons.RefreshCw />
                                        {t('pgHaSync')}
                                    </h4>
                                    <div className="space-y-1.5">
                                        {row(t('pgHaLastSync'), when(sync.last_ok_at))}
                                        {row(t('pgHaLastAttempt'), when(sync.last_attempt_at))}
                                        {sync.rows != null && row(t('pgHaSyncContent'),
                                            t('pgHaRowsTables').replace('{rows}', sync.rows).replace('{tables}', sync.tables ?? 0))}
                                    </div>
                                    {sync.last_error && (
                                        <div className="rounded-lg p-2 text-xs border bg-red-500/10 border-red-500/30 text-red-300 break-all">
                                            {t('pgHaLastError')}: {sync.last_error}
                                        </div>
                                    )}
                                    {skipped.length > 0 && (
                                        <div className="rounded-lg p-2 text-xs border bg-yellow-500/10 border-yellow-500/40 text-yellow-200 space-y-1">
                                            <div>{t('pgHaSkippedColumns')}</div>
                                            <ul className="font-mono">
                                                {skipped.map(([table, cols]) => <li key={table}>{table}: {cols.join(', ')}</li>)}
                                            </ul>
                                        </div>
                                    )}
                                </div>
                                {intervalCard}
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {liveViewCard}
                                {forwardCard}
                                {assignedCard}
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <button onClick={syncNow} disabled={!!busy}
                                    className={`${btn} bg-proxmox-orange hover:bg-proxmox-orange/90 text-white`}>
                                    <span className={`inline-flex ${busy === 'sync' ? 'animate-spin' : ''}`}><Icons.RefreshCw /></span>
                                    {t('pgHaSyncNow')}
                                </button>
                                {!broken && !status?.removed && (
                                    <button onClick={() => openConfirm('promote')} disabled={!!busy}
                                        className={`${btn} bg-yellow-600 hover:bg-yellow-700 text-white`}>
                                        <Icons.Zap />
                                        {t(serving ? 'pgHaPromoteLeader' : 'pgHaPromote')}
                                    </button>
                                )}
                                <button onClick={() => openConfirm('unpair')} disabled={!!busy} className={btnGhost}>
                                    <Icons.Unlink />
                                    {t('pgHaUnpair')}
                                </button>
                            </div>
                            {typedBox}
                        </>
                    )}
                </div>
            );
        }
