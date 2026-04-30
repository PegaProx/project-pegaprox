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
            vmware:        { order: 150, title: 'ESXi / vCenter',       icon: '📡' },
            xapi:          { order: 160, title: 'XCP-ng',               icon: '🔶' },
            plugins:       { order: 170, title: 'Plugins',              icon: '🧩' },
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

        // ═══════════════════════════════════════════════
        // PegaProx - Settings Modal
        // PegaProxSettingsModal (Server, SSL, SMTP, RBAC, Audit, Tenants)
        // ═══════════════════════════════════════════════
        // PegaProx Settings Modal with User Management and Audit Log
        function PegaProxSettingsModal({ isOpen, onClose, addToast, onGroupsChanged }) {
            const { t } = useTranslation();
            const { getAuthHeaders, user: currentUser } = useAuth();
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
                acme_directory_url: '',
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
                try {
                    const r = await fetch(`${API_URL}/roles`, { credentials: 'include', headers: getAuthHeaders() });
                    if(r.ok) setAllRoles(await r.json());
                } catch(e) {}
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
                            acme_provider: data.acme_provider || 'letsencrypt',
                            acme_email: data.acme_email || '',
                            acme_directory_url: data.acme_directory_url || '',
                            acme_staging: data.acme_staging || false,
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
                            directory_url: serverSettings.acme_provider === 'custom' ? serverSettings.acme_directory_url : '',
                        })
                    });
                    const data = await resp.json();
                    setAcmeResult(data);
                    if (data.success) {
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
            
            const fetchAuditLogs = async () => {
                try {
                    const response = await fetch(`${API_URL}/audit`, { credentials: 'include', headers: getAuthHeaders()
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        setAuditLogs(data);
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
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80" onClick={onClose}>
                    <div
                        className={`w-full max-w-5xl max-h-[90vh] bg-proxmox-card border border-proxmox-border overflow-hidden flex flex-col ${
                            isCorporate ? 'shadow-lg' : 'rounded-2xl shadow-2xl'
                        }`}
                        onClick={e => e.stopPropagation()}
                    >
                        {/* Header - LW: Feb 2026 - compact in corporate mode */}
                        {isCorporate ? (
                        <div className="corp-modal-header">
                            <span className="corp-modal-title" style={{display:'flex',alignItems:'center',gap:'8px'}}>
                                <Icons.Settings className="w-4 h-4" style={{color:'#728b9a'}} />
                                {t('pegaproxSettings')}
                            </span>
                            <button className="corp-modal-close" onClick={onClose}><Icons.X className="w-4 h-4" /></button>
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
                        
                        {/* Content - LW: Feb 2026 - denser in corporate */}
                        <div className={`flex-1 overflow-auto ${isCorporate ? 'p-4' : 'p-6'}`}>
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
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'18%'}}>{t('usernameLabel')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'15%'}}>{t('displayName')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'10%'}}>{t('role')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'10%'}}>{t('tenant') || 'Tenant'}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'5%'}}>2FA</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'12%'}}>{t('lastLogin')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'7%'}}>{t('status')}</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width:'7%'}}>{t('portal') || 'Portal'}</th>
                                                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width:'16%'}}>{t('actions')}</th>
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
                                                                <select
                                                                    defaultValue={user.role}
                                                                    onChange={e => {
                                                                        const selectedRole = e.target.value;
                                                                        // LW: Auto-include tenant_id for tenant roles
                                                                        const roleObj = allRoles.find(r => r.id === selectedRole);
                                                                        if (roleObj && roleObj.scope === 'tenant' && roleObj.tenant_id) {
                                                                            handleUpdateUser(user.username, { role: selectedRole, tenant_id: roleObj.tenant_id });
                                                                        } else {
                                                                            handleUpdateUser(user.username, { role: selectedRole });
                                                                        }
                                                                    }}
                                                                    className="px-2 py-1 bg-proxmox-darker border border-proxmox-border rounded text-sm text-white"
                                                                >
                                                                    <optgroup label={t('builtinRole') || 'Builtin'}>
                                                                        <option value="admin">{t('roleAdmin')}</option>
                                                                        <option value="user">{t('roleUser')}</option>
                                                                        <option value="viewer">{t('roleViewer')}</option>
                                                                    </optgroup>
                                                                    {allRoles.filter(r => !r.builtin).length > 0 && (
                                                                        <optgroup label={t('customRoles') || 'Custom'}>
                                                                            {allRoles.filter(r => !r.builtin).map(r => (
                                                                                <option key={r.id} value={r.id}>{r.name || r.id}</option>
                                                                            ))}
                                                                        </optgroup>
                                                                    )}
                                                                </select>
                                                            ) : (
                                                                <>
                                                                <span className={`px-2 py-1 rounded text-xs font-medium ${
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
                                                                    <span className="px-1.5 py-0.5 rounded text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20">LDAP</span>
                                                                )}
                                                                {user.auth_source === 'entra' && (
                                                                    <span className="px-1.5 py-0.5 rounded text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Entra ID</span>
                                                                )}
                                                                {user.auth_source === 'oidc' && (
                                                                    <span className="px-1.5 py-0.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20">OIDC</span>
                                                                )}
                                                                </>
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
                                                                <span className="px-2 py-1 rounded text-xs bg-cyan-500/10 text-cyan-400">
                                                                    {tenants.find(t => t.id === user.tenant_id)?.name || user.tenant_id || 'Default'}
                                                                </span>
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
                                                    <p className="text-xs text-gray-500 mb-2">Select clusters this tenant can access (empty = all)</p>
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
                                                                <span className="text-sm text-white">{c.name}</span>
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
                                                        </td>
                                                        <td className="px-4 py-3 text-sm text-gray-400">{tenant.user_count || 0}</td>
                                                        <td className="px-4 py-3 text-right">
                                                            <div className="flex items-center justify-end gap-2">
                                                                <button
                                                                    onClick={() => setEditingTenant({...tenant})}
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
                                                        <p className="text-xs text-gray-500 mb-2">{t('tenantClustersHint') || 'Select which clusters this tenant can access (empty = all)'}</p>
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
                                                                    <span className="text-sm text-white">{c.name}</span>
                                                                </label>
                                                            ))}
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
                                                                        clusters: editingTenant.clusters || []
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
                                                        <option key={c.id} value={c.id}>{c.name}</option>
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
                                                        <option key={c.id} value={c.id}>{c.name}</option>
                                                    ))}
                                                </select>
                                                {selectedPoolCluster && (
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
                                        <button onClick={saveLdapSettings} disabled={loading} className="px-6 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-white font-medium flex items-center gap-2">
                                            {loading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Save className="w-4 h-4" />}
                                            Save LDAP Settings
                                        </button>
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
                                        <button onClick={saveOidcSettings} disabled={loading} className="px-6 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-white font-medium flex items-center gap-2">
                                            {loading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Save className="w-4 h-4" />}
                                            Save OIDC Settings
                                        </button>
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

                                                <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                                                    <p className="text-xs text-blue-400">{t('acmePort80')}</p>
                                                </div>

                                                {acmeResult && !acmeResult.success && (
                                                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                                        <p className="text-sm text-red-400">{acmeResult.message}</p>
                                                    </div>
                                                )}

                                                <button
                                                    onClick={handleAcmeRequest}
                                                    disabled={acmeLoading || !serverSettings.domain || (serverSettings.acme_provider === 'letsencrypt' && !serverSettings.acme_email) || (serverSettings.acme_provider === 'custom' && !serverSettings.acme_directory_url)}
                                                    className="w-full px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
                                                >
                                                    {acmeLoading ? t('acmeRequesting') : t('acmeRequest')}
                                                </button>
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
                                                    <button
                                                        onClick={handleSaveSMTPSettings}
                                                        disabled={smtpLoading}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                                                    >
                                                        {smtpLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                        {t('saveSmtpSettings') || 'Save SMTP Settings'}
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                        
                                        {/* Save SMTP Button - always visible when disabled to allow enabling */}
                                        {!serverSettings.smtp_enabled && (
                                            <div className="pt-3 flex justify-end border-t border-proxmox-border mt-3">
                                                <p className="text-xs text-gray-500 mr-auto my-auto">
                                                    {t('enableSmtpHint') || 'Enable SMTP to configure email settings'}
                                                </p>
                                                <button
                                                    onClick={handleSaveSMTPSettings}
                                                    disabled={smtpLoading}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                                                >
                                                    {smtpLoading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                                    {t('save') || 'Save'}
                                                </button>
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
                                            <button onClick={async () => {
                                                try {
                                                    await fetch(`${API_URL}/plugins/rescan`, { method: 'POST', credentials: 'include', headers: getAuthHeaders() });
                                                    fetchPlugins();
                                                    addToast('Plugins rescanned', 'success');
                                                } catch (e) {}
                                            }} className="text-xs text-gray-400 hover:text-white flex items-center gap-1">
                                                <Icons.RefreshCw className="w-3 h-3" />
                                                Rescan
                                            </button>
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
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className={`toggle-switch ${plugin.enabled ? 'active' : ''}`} onClick={() => togglePlugin(plugin.id, plugin.enabled)} />
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
                                                            <button onClick={async () => {
                                                                if (!confirm(`Delete plugin "${plugin.name}"? This removes all plugin files.`)) return;
                                                                try {
                                                                    const r = await fetch(`${API_URL}/plugins/${plugin.id}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                                                                    if (r && r.ok) { addToast('Plugin deleted', 'success'); fetchPlugins(); }
                                                                    else { const e = await r.json().catch(() => ({})); addToast(e.error || 'Failed', 'error'); }
                                                                } catch (e) { addToast('Error', 'error'); }
                                                            }} className="text-red-400/50 hover:text-red-400 transition-colors" title="Delete plugin">
                                                                <Icons.Trash2 className="w-4 h-4" />
                                                            </button>
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
                                        <button
                                            onClick={handleSaveServerSettings}
                                            disabled={serverLoading}
                                            className="flex items-center gap-2 px-6 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                                        >
                                            {serverLoading ? <Icons.RotateCw /> : <Icons.Save />}
                                            {t('saveSettings')}
                                        </button>
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
                                </div>
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
                                    
                                    {/* Rollback Section - NS Jan 2026 */}
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
                                            <a 
                                                href="https://github.com/PegaProx/project-pegaprox/discussions" 
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="flex items-center gap-3 p-4 bg-proxmox-darker rounded-lg hover:bg-proxmox-border/50 transition-colors"
                                            >
                                                <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
                                                    <Icons.MessageSquare className="w-5 h-5 text-blue-400" />
                                                </div>
                                                <div>
                                                    <h4 className="font-medium text-white">{t('discussions') || 'Discussions'}</h4>
                                                    <p className="text-sm text-gray-400">Community Forum</p>
                                                </div>
                                                <Icons.ExternalLink className="w-4 h-4 text-gray-500 ml-auto" />
                                            </a>
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
                                            <img src="/images/pegaprox.png" alt="PegaProx" className="w-20 h-20 object-contain" />
                                        </div>
                                        <h2 className="text-3xl font-bold text-white">PegaProx</h2>
                                        <p className="text-xl text-proxmox-orange mt-1">{PEGAPROX_VERSION}</p>
                                        <p className="text-sm text-gray-400 mt-2">Multi-Cluster Proxmox Management</p>
                                        <p className="text-xs text-gray-500 mt-1">Build 2026.02 • © 2025-2026 PegaProx Team</p>
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

                                    {/* License */}
                                    <div className="text-center text-sm text-gray-500 space-y-1">
                                        <p>PegaProx is open source software licensed under the AGPL-3.0 License.</p>
                                        <p>Made with ❤️ in Austria and Germany</p>
                                        <p>© 2025-2026 PegaProx Team</p>
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
