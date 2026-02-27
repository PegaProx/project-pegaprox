        // ═══════════════════════════════════════════════
        // PegaProx - VM Modals
        // Delete, Clone, Detail, Migrate, Snapshots, Replication
        // ═══════════════════════════════════════════════
        // Delete VM Modal Component
        // NS: Added confirmation input after someone accidentally deleted prod VM
        // Better safe than sorry...
        function DeleteVmModal({ vm, clusterId, onDelete, onClose }) {
            const { t } = useTranslation();
            const [confirmName, setConfirmName] = useState('');
            const [purge, setPurge] = useState(false);
            const [destroyUnreferenced, setDestroyUnreferenced] = useState(false);
            const [loading, setLoading] = useState(false);

            const isQemu = vm.type === 'qemu';
            const displayName = vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`;
            const canDelete = confirmName === vm.vmid.toString();

            const handleDelete = async () => {
                if (!canDelete) return;
                setLoading(true);
                await onDelete(vm, { purge, destroyUnreferenced });
                setLoading(false);
                onClose();
            };

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80">
                    <div className="w-full max-w-md bg-proxmox-card border border-red-500/30 rounded-xl overflow-hidden animate-scale-in">
                        <div className="p-6 border-b border-red-500/30 bg-red-500/10">
                            <div className="flex items-center gap-3">
                                <div className="p-3 rounded-full bg-red-500/20">
                                    <Icons.Trash />
                                </div>
                                <div>
                                    <h3 className="text-lg font-semibold text-white">
                                        {isQemu ? 'VM' : 'Container'} {t('delete')}
                                    </h3>
                                    <p className="text-sm text-red-400">{t('deleteCannotBeUndone')}</p>
                                </div>
                            </div>
                        </div>
                        
                        <div className="p-6 space-y-4">
                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                <div className="flex items-center gap-3">
                                    <div className={`p-2 rounded-lg ${isQemu ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                        {isQemu ? <Icons.VM /> : <Icons.Container />}
                                    </div>
                                    <div>
                                        <div className="font-medium text-white">{displayName}</div>
                                        <div className="text-xs text-gray-500">ID: {vm.vmid} · Node: {vm.node}</div>
                                    </div>
                                    <span className={`ml-auto px-2 py-1 rounded text-xs ${
                                        vm.status === 'running' 
                                            ? 'bg-green-500/10 text-green-400' 
                                            : 'bg-red-500/10 text-red-400'
                                    }`}>
                                        {vm.status}
                                    </span>
                                </div>
                            </div>

                            {vm.status === 'running' && (
                                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm text-yellow-400">
                                    ⚠️ {isQemu ? t('vmStillRunning') : t('ctStillRunning')}
                                </div>
                            )}

                            <div className="space-y-3">
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={purge}
                                        onChange={(e) => setPurge(e.target.checked)}
                                        className="rounded"
                                    />
                                    {t('purgeDisks')}
                                </label>
                                {isQemu && (
                                    <label className="flex items-center gap-2 text-sm text-gray-300">
                                        <input
                                            type="checkbox"
                                            checked={destroyUnreferenced}
                                            onChange={(e) => setDestroyUnreferenced(e.target.checked)}
                                            className="rounded"
                                        />
                                        {t('destroyUnreferencedDisks')}
                                    </label>
                                )}
                            </div>

                            <div>
                                <label className="block text-sm text-gray-400 mb-2">
                                    {t('enterToConfirm')} <span className="font-mono text-red-400">{vm.vmid}</span>:
                                </label>
                                <input
                                    type="text"
                                    value={confirmName}
                                    onChange={(e) => setConfirmName(e.target.value)}
                                    placeholder={vm.vmid.toString()}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-red-500"
                                    autoFocus
                                />
                            </div>
                        </div>

                        <div className="flex items-center justify-end gap-3 p-4 border-t border-proxmox-border bg-proxmox-dark">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                {t('cancel')}
                            </button>
                            <button
                                onClick={handleDelete}
                                disabled={loading || !canDelete}
                                className="flex items-center gap-2 px-4 py-2 bg-red-600 rounded-lg text-white hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {loading && <Icons.RotateCw />}
                                <Icons.Trash />
                                {t('deletePermanently')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Clone VM Modal
        // LW: Supports both linked clones and full clones
        // Full clone takes longer but is independent from source
        function CloneVmModal({ vm, nodes, clusterId, onClone, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            
            // NS: same pattern as everywhere else, maybe extract to hook someday
            async function authFetch(url, opts) {
                try { return await fetch(url, { ...opts, headers: { ...opts?.headers, ...getAuthHeaders() } }) }
                catch(e) { console.error(e); return null }
            }
            
            const [cloneConfig, setCloneConfig] = useState({
                name: `${vm.name || vm.vmid}-clone`,
                newid: '',
                full: true,  // default to full clone
                target_node: vm.node,
                description: '',
            });
            const [loading, setLoading] = useState(false);
            const [loadingVmid, setLoadingVmid] = useState(true);

            const isQemu = vm.type === 'qemu';

            // Get next available VMID on mount
            useEffect(() => {
                (async () => {
                    try {
                        const r = await authFetch(`${API_URL}/clusters/${clusterId}/nextid`);
                        if (r?.ok) {
                            const d = await r.json();
                            setCloneConfig(prev => ({ ...prev, newid: d.vmid.toString() }));
                        }
                    } catch (err) {
                        console.error('to get next VMID:', err);
                    }
                    setLoadingVmid(false);
                })();
            }, [clusterId]);

            const handleClone = async () => {
                if (!cloneConfig.newid) return;
                setLoading(true);
                await onClone(vm, cloneConfig);
                setLoading(false);
            };

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80">
                    <div className="w-full max-w-lg bg-proxmox-card border border-blue-500/30 rounded-xl overflow-hidden animate-scale-in">
                        <div className="p-6 border-b border-blue-500/30 bg-blue-500/10">
                            <div className="flex items-center gap-3">
                                <div className="p-3 rounded-full bg-blue-500/20">
                                    <Icons.Copy />
                                </div>
                                <div>
                                    <h3 className="text-lg font-semibold text-white">
                                        {isQemu ? 'VM' : 'Container'} {t('clone')}
                                    </h3>
                                    <p className="text-sm text-blue-400">
                                        {vm.name || vm.vmid} {t('willBeCloned')}
                                    </p>
                                </div>
                            </div>
                        </div>
                        
                        <div className="p-6 space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('newVmId')}</label>
                                    <input
                                        type="number"
                                        value={cloneConfig.newid}
                                        onChange={(e) => setCloneConfig({...cloneConfig, newid: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                        placeholder={loadingVmid ? t('loading') : 'VMID'}
                                        disabled={loadingVmid}
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('name')}</label>
                                    <input
                                        type="text"
                                        value={cloneConfig.name}
                                        onChange={(e) => setCloneConfig({...cloneConfig, name: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                        placeholder="clone-name"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-xs text-gray-400 mb-1">{t('targetNode')}</label>
                                <select
                                    value={cloneConfig.target_node}
                                    onChange={(e) => setCloneConfig({...cloneConfig, target_node: e.target.value})}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                >
                                    {(nodes || []).map(node => {
                                        const nodeName = typeof node === 'string' ? node : node.name;
                                        const isSameNode = nodeName === vm.node;
                                        return(
                                            <option key={nodeName} value={nodeName}>
                                                {nodeName} {isSameNode ? `(${t('sameNode')})` : ''}
                                            </option>
                                        );
                                    })}
                                </select>
                                {cloneConfig.target_node !== vm.node && (
                                    <p className="text-xs text-yellow-400 mt-1">
                                        ⚠️ {t('crossNodeCloneWarning')}
                                    </p>
                                )}
                            </div>

                            <div>
                                <label className="block text-xs text-gray-400 mb-2">{t('cloneMode')}</label>
                                <div className="grid grid-cols-2 gap-3">
                                    <button
                                        onClick={() => setCloneConfig({...cloneConfig, full: true})}
                                        className={`p-3 rounded-lg border text-left transition-all ${
                                            cloneConfig.full
                                                ? 'border-blue-500 bg-blue-500/10'
                                                : 'border-proxmox-border hover:border-gray-600'
                                        }`}
                                    >
                                        <div className="font-medium text-white text-sm">{t('fullClone')}</div>
                                        <div className="text-xs text-gray-500 mt-1">{t('fullCloneDesc')}</div>
                                    </button>
                                    <button
                                        onClick={() => setCloneConfig({...cloneConfig, full: false})}
                                        disabled={!isQemu}
                                        className={`p-3 rounded-lg border text-left transition-all ${
                                            !cloneConfig.full
                                                ? 'border-blue-500 bg-blue-500/10'
                                                : 'border-proxmox-border hover:border-gray-600'
                                        } ${!isQemu ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    >
                                        <div className="font-medium text-white text-sm">{t('linkedClone')}</div>
                                        <div className="text-xs text-gray-500 mt-1">
                                            {isQemu ? t('linkedCloneDesc') : t('onlyForVms')}
                                        </div>
                                    </button>
                                </div>
                            </div>

                            <div>
                                <label className="block text-xs text-gray-400 mb-1">{t('description')} ({t('optional')})</label>
                                <textarea
                                    value={cloneConfig.description}
                                    onChange={(e) => setCloneConfig({...cloneConfig, description: e.target.value})}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm resize-none"
                                    rows="2"
                                    placeholder={t('cloneNotes')}
                                />
                            </div>
                        </div>

                        <div className="flex items-center justify-end gap-3 p-4 border-t border-proxmox-border bg-proxmox-dark">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                {t('cancel')}
                            </button>
                            <button
                                onClick={handleClone}
                                disabled={loading || !cloneConfig.newid}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700 disabled:opacity-50"
                            >
                                {loading && <Icons.RotateCw />}
                                <Icons.Copy />
                                {t('startClone')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // VM Detail Modal Component
        function VmDetailModal({ vm, clusterId, onAction, onOpenConsole, onOpenConfig, onMigrate, onClone, onForceStop, onDelete, onClose }) {
            const [loading, setLoading] = useState({});
            const isQemu = vm.type === 'qemu';
            const displayName = vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`;
            const [guestInfo, setGuestInfo] = useState(null);
            const [vmHwInfo, setVmHwInfo] = useState(null);

            // copypaste from somewhere else lol
            function formatBytes(bytes) {
                if (!bytes) return '0 B';
                const k = 1024;
                const s = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return(bytes / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
            }

            const handleAction = async (action) => {
                setLoading(prev => ({...prev, [action]: true}));
                await onAction(vm, action);
                setLoading(prev => ({...prev, [action]: false}));
            };

            // TODO: this is also duplicated somewhere
            const formatUptime = (uptime) => {
                if (!uptime) return '-';
                const d = Math.floor(uptime / 86400);
                const h = Math.floor((uptime % 86400) / 3600);
                const m = Math.floor((uptime % 3600) / 60);
                if (d > 0) return `${d}d ${h}h ${m}m`;
                if (h > 0) return `${h}h ${m}m`;
                return `${m}m`;
            };

            // Fetch VM config for hardware info + guest agent
            useEffect(() => {
                if (!isQemu) return;
                const doFetch = async (url) => {
                    try { const r = await fetch(url, { credentials: 'include', headers: getAuthHeaders() }); return r.ok ? r.json() : null; }
                    catch { return null; }
                };
                // Hardware info
                doFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`)
                    .then(cfg => {
                        if (!cfg) return;
                        const raw = cfg.raw || cfg;
                        setVmHwInfo({
                            machine: raw.machine || 'i440fx',
                            bios: raw.bios || 'seabios',
                            cpu: raw.cpu || 'kvm64',
                            scsihw: raw.scsihw || 'lsi',
                            cores: raw.cores || 1,
                            sockets: raw.sockets || 1,
                            ostype: raw.ostype,
                            net: (() => { const nk = Object.keys(raw).find(k => k.startsWith('net')); return nk ? raw[nk].split(',')[0].split('=')[0] : null; })(),
                            agent: raw.agent,
                        });
                    });
                // Guest agent info
                if (vm.status === 'running') {
                    doFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/guest-info`)
                        .then(data => { if (data && data.agent_running) setGuestInfo(data); });
                }
            }, [vm.vmid, vm.status, clusterId]);

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80" onClick={onClose}>
                    <div 
                        className="w-full max-w-2xl bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden animate-scale-in"
                        onClick={e => e.stopPropagation()}
                    >
                        {/* Header */}
                        <div className="p-6 border-b border-proxmox-border bg-gradient-to-r from-proxmox-dark to-proxmox-card">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className={`p-3 rounded-xl ${isQemu ? 'bg-blue-500/20' : 'bg-purple-500/20'}`}>
                                        {isQemu ? <Icons.VM /> : <Icons.Container />}
                                    </div>
                                    <div>
                                        <h2 className="text-xl font-bold text-white">{displayName}</h2>
                                        <div className="flex items-center gap-3 text-sm text-gray-400">
                                            <span>ID: {vm.vmid}</span>
                                            <span>•</span>
                                            <span>{isQemu ? 'QEMU VM' : 'LXC Container'}</span>
                                            <span>•</span>
                                            <span>{vm.node}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className={`px-3 py-1.5 rounded-full text-sm font-medium ${
                                        vm.status === 'running' 
                                            ? 'bg-green-500/20 text-green-400' 
                                            : 'bg-red-500/20 text-red-400'
                                    }`}>
                                        {vm.status === 'running' ? t('running') || 'Running' : t('stopped') || 'Stopped'}
                                    </span>
                                    <button onClick={onClose} className="p-2 hover:bg-proxmox-dark rounded-lg text-gray-400 hover:text-white">
                                        <Icons.X />
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Stats Grid */}
                        <div className="p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="bg-proxmox-dark rounded-lg p-4">
                                <div className="text-xs text-gray-500 mb-1">CPU</div>
                                <div className="text-lg font-bold text-white">{(vm.cpu_percent || 0).toFixed(1)}%</div>
                                <div className="text-xs text-gray-500">{vm.maxcpu || 1} Cores</div>
                                <div className="mt-2 h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                    <div 
                                        className="h-full rounded-full transition-all"
                                        style={{
                                            width: `${Math.min(vm.cpu_percent || 0, 100)}%`,
                                            background: (vm.cpu_percent || 0) < 50 ? '#3b82f6' : (vm.cpu_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                        }}
                                    />
                                </div>
                            </div>
                            <div className="bg-proxmox-dark rounded-lg p-4">
                                <div className="text-xs text-gray-500 mb-1">RAM</div>
                                <div className="text-lg font-bold text-white">{(vm.mem_percent || 0).toFixed(1)}%</div>
                                <div className="text-xs text-gray-500">{formatBytes(vm.mem)} / {formatBytes(vm.maxmem)}</div>
                                <div className="mt-2 h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                    <div 
                                        className="h-full rounded-full transition-all"
                                        style={{
                                            width: `${vm.mem_percent || 0}%`,
                                            background: (vm.mem_percent || 0) < 50 ? '#22c55e' : (vm.mem_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                        }}
                                    />
                                </div>
                            </div>
                            <div className="bg-proxmox-dark rounded-lg p-4">
                                <div className="text-xs text-gray-500 mb-1">Disk</div>
                                <div className="text-lg font-bold text-white">{formatBytes(vm.disk || 0)}</div>
                                <div className="text-xs text-gray-500">von {formatBytes(vm.maxdisk || 0)}</div>
                            </div>
                            <div className="bg-proxmox-dark rounded-lg p-4">
                                <div className="text-xs text-gray-500 mb-1">Uptime</div>
                                <div className="text-lg font-bold text-white">{formatUptime(vm.uptime)}</div>
                                <div className="text-xs text-gray-500">{vm.status === 'running' ? t('sinceStart') : t('offline')}</div>
                            </div>
                        </div>

                        {/* Hardware Info Badges */}
                        {isQemu && vmHwInfo && (
                            <div className="px-6 pb-2">
                                <div className="flex flex-wrap gap-2">
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.Cpu className="w-3 h-3 text-blue-400" />
                                        <span className="text-gray-400">CPU:</span>
                                        <span className="text-white font-medium">{vmHwInfo.cpu}</span>
                                        <span className="text-gray-500">({vmHwInfo.sockets}s/{vmHwInfo.cores}c)</span>
                                    </span>
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.Monitor className="w-3 h-3 text-amber-400" />
                                        <span className="text-gray-400">Machine:</span>
                                        <span className="text-white font-medium">{vmHwInfo.machine}</span>
                                    </span>
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.HardDrive className="w-3 h-3 text-emerald-400" />
                                        <span className="text-gray-400">BIOS:</span>
                                        <span className="text-white font-medium">{vmHwInfo.bios === 'ovmf' ? 'UEFI (OVMF)' : 'SeaBIOS'}</span>
                                    </span>
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.Database className="w-3 h-3 text-purple-400" />
                                        <span className="text-gray-400">SCSI:</span>
                                        <span className="text-white font-medium">{vmHwInfo.scsihw}</span>
                                    </span>
                                    {vmHwInfo.net && (
                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                            <Icons.Globe className="w-3 h-3 text-cyan-400" />
                                            <span className="text-gray-400">NIC:</span>
                                            <span className="text-white font-medium">{vmHwInfo.net}</span>
                                        </span>
                                    )}
                                    {vmHwInfo.ostype && (
                                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                            <Icons.Network className="w-3 h-3 text-orange-400" />
                                            <span className="text-gray-400">OS:</span>
                                            <span className="text-white font-medium">{vmHwInfo.ostype}</span>
                                        </span>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Guest Agent Info */}
                        {isQemu && vm.status === 'running' && guestInfo && (
                            <div className="px-6 pb-2">
                                <div className="bg-proxmox-dark rounded-lg p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                                    {guestInfo.hostname && (
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 rounded-lg bg-cyan-500/10">
                                                <Icons.Monitor className="w-4 h-4 text-cyan-400" />
                                            </div>
                                            <div>
                                                <div className="text-xs text-gray-500">Hostname</div>
                                                <div className="text-sm font-semibold text-white font-mono">{guestInfo.hostname}</div>
                                            </div>
                                        </div>
                                    )}
                                    {guestInfo.os_pretty_name && (
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 rounded-lg bg-emerald-500/10">
                                                <Icons.Cpu className="w-4 h-4 text-emerald-400" />
                                            </div>
                                            <div>
                                                <div className="text-xs text-gray-500">{t('osVersion')}</div>
                                                <div className="text-sm font-semibold text-white">{guestInfo.os_pretty_name}</div>
                                            </div>
                                        </div>
                                    )}
                                    {guestInfo.os_kernel && (
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 rounded-lg bg-purple-500/10">
                                                <Icons.Terminal className="w-4 h-4 text-purple-400" />
                                            </div>
                                            <div>
                                                <div className="text-xs text-gray-500">Kernel</div>
                                                <div className="text-sm font-semibold text-gray-300 font-mono">{guestInfo.os_kernel}</div>
                                            </div>
                                        </div>
                                    )}
                                    <div className="flex items-center gap-1.5 md:col-span-3 pt-2 border-t border-gray-700/30">
                                        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                                        <span className="text-xs text-cyan-400/70">QEMU Guest Agent</span>
                                    </div>
                                </div>
                            </div>
                        )}
                        {isQemu && vm.status === 'running' && !guestInfo && (
                            <div className="px-6 pb-2">
                                <div className="bg-proxmox-dark rounded-lg p-3 flex items-center gap-3">
                                    <div className="p-1.5 rounded-lg bg-yellow-500/10">
                                        <Icons.AlertTriangle className="w-4 h-4 text-yellow-500" />
                                    </div>
                                    <div className="flex-1">
                                        <div className="text-sm text-yellow-400">{t('guestAgentNotInstalled')}</div>
                                        <div className="text-xs text-gray-500">{t('guestAgentInstallHint')}</div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Quick Actions */}
                        <div className="px-6 pb-6">
                            <div className="text-xs text-gray-500 mb-3">{t('quickActions')}</div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {vm.status === 'stopped' ? (
                                    <button
                                        onClick={() => handleAction('start')}
                                        disabled={loading.start}
                                        className="flex items-center justify-center gap-2 p-3 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 rounded-lg text-green-400 transition-all disabled:opacity-50"
                                    >
                                        {loading.start ? <Icons.RotateCw /> : <Icons.PlayCircle />}
                                        {t('start')}
                                    </button>
                                ) : (
                                    <>
                                        <button
                                            onClick={() => handleAction('shutdown')}
                                            disabled={loading.shutdown}
                                            className="flex items-center justify-center gap-2 p-3 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30 rounded-lg text-yellow-400 transition-all disabled:opacity-50"
                                        >
                                            {loading.shutdown ? <Icons.RotateCw /> : <Icons.Power />}
                                            Shutdown
                                        </button>
                                        <button
                                            onClick={() => handleAction('reboot')}
                                            disabled={loading.reboot}
                                            className="flex items-center justify-center gap-2 p-3 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 rounded-lg text-orange-400 transition-all disabled:opacity-50"
                                        >
                                            {loading.reboot ? <Icons.RotateCw /> : <Icons.RefreshCw />}
                                            Reboot
                                        </button>
                                    </>
                                )}
                                <button
                                    onClick={() => { onClose(); onOpenConsole(vm); }}
                                    className="flex items-center justify-center gap-2 p-3 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 rounded-lg text-blue-400 transition-all"
                                >
                                    <Icons.Monitor />
                                    Konsole
                                </button>
                                <button
                                    onClick={() => { onClose(); onOpenConfig(vm); }}
                                    className="flex items-center justify-center gap-2 p-3 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-gray-300 transition-all"
                                >
                                    <Icons.Cog />
                                    Konfiguration
                                </button>
                            </div>
                        </div>

                        {/* More Actions */}
                        <div className="px-6 pb-6">
                            <div className="text-xs text-gray-500 mb-3">{t('moreActions')}</div>
                            <div className="flex flex-wrap gap-2">
                                <button
                                    onClick={() => { onClose(); onMigrate(vm); }}
                                    className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-sm text-gray-300 transition-all"
                                >
                                    <Icons.ArrowRight />
                                    Migrieren
                                </button>
                                <button
                                    onClick={() => { onClose(); onClone(vm); }}
                                    className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-sm text-gray-300 transition-all"
                                >
                                    <Icons.Copy />
                                    Klonen
                                </button>
                                {vm.status === 'running' && (
                                    <>
                                        {/* Force Reset - QEMU only */}
                                        {isQemu && (
                                            <button
                                                onClick={() => onAction(vm, 'reset')}
                                                className="flex items-center gap-2 px-3 py-2 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 rounded-lg text-sm text-orange-400 transition-all"
                                            >
                                                <Icons.Zap />
                                                {t('forceReset')}
                                            </button>
                                        )}
                                        <button
                                            onClick={() => onForceStop(vm)}
                                            className="flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-sm text-red-400 transition-all"
                                        >
                                            <Icons.XCircle />
                                            {t('forceStop')}
                                        </button>
                                    </>
                                )}
                                <button
                                    onClick={() => { onClose(); onDelete(vm); }}
                                    className="flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-sm text-red-400 transition-all"
                                >
                                    <Icons.Trash />
                                    {t('delete')}
                                </button>
                            </div>
                        </div>

                        {/* Tags */}
                        {vm.tags && (
                            <div className="px-6 pb-6">
                                <div className="text-xs text-gray-500 mb-2">Tags</div>
                                <div className="flex flex-wrap gap-2">
                                    {vm.tags.split(';').map(tag => (
                                        <span key={tag} className="px-2 py-1 bg-proxmox-dark rounded text-xs text-gray-400">
                                            {tag}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // VM Detail Panel Component (inline, not modal)
        // LW: this shows when you click a VM in detail view mode
        function VmDetailPanel({ vm, clusterId, onAction, onOpenConsole, onOpenConfig, onMigrate, onClone, onForceStop, onDelete, onCrossClusterMigrate, showCrossCluster, actionLoading, onShowMetrics, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            
            // some quick helpers
            const isQemu = vm.type === 'qemu';
            const displayName = vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`;
            
            const [haEnabled, setHaEnabled] = useState(false);
            const [haLoading, setHaLoading] = useState(false);
            const [haResources, setHaResources] = useState([]);
            
            // NS: Lock status for VMs
            const [lockInfo, setLockInfo] = useState({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
            const [unlockLoading, setUnlockLoading] = useState(false);
            const [showUnlockConfirm, setShowUnlockConfirm] = useState(false);
            
            // NS: Issue #50 - Guest Agent info
            const [guestInfo, setGuestInfo] = useState(null);

            // LW: inline arrow fn, less boilerplate
            const authFetch = async (url, opts = {}) => {
                try { return await fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } }); }
                catch(e) { console.error(e); return null; }
            };

            // LW: these could be extracted to utils but w/e
            const formatBytes = b => {
                if(!b) return '0 B';
                const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(b) / Math.log(k));
                return `${(b / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
            };

            const formatUptime = (uptime) => {
                if(!uptime) return '-';
                const days = Math.floor(uptime / 86400);
                const hours = Math.floor((uptime % 86400) / 3600);
                const mins = Math.floor((uptime % 3600) / 60);
                if(days > 0) return `${days}d ${hours}h ${mins}m`;
                if(hours > 0) return `${hours}h ${mins}m`;
                return `${mins}m`;
            };

            const handleAction = async (action) => {
                await onAction(vm, action);
            };
            
            // NS: Fetch lock status
            const fetchLockStatus = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/lock`);
                    if (response && response.ok) {
                        const data = await response.json();
                        // NS: Ensure we have valid data structure
                        setLockInfo({
                            locked: data.locked || false,
                            lock_reason: data.lock_reason || null,
                            lock_description: data.lock_description || null,
                            unlock_command: data.unlock_command || null
                        });
                    } else {
                        // API error - assume not locked
                        setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
                    }
                } catch (error) {
                    console.error('Error fetching lock status:', error);
                    // On error, assume not locked
                    setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
                }
            };
            
            // NS: Unlock VM
            const handleUnlock = async () => {
                setUnlockLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/unlock`, {
                        method: 'POST'
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        if (addToast) addToast(t('vmUnlocked') || `VM ${vm.vmid} unlocked successfully`, 'success');
                        setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
                        setShowUnlockConfirm(false);
                    } else {
                        const err = await response.json();
                        if (addToast) addToast(err.error || 'Unlock failed', 'error');
                    }
                } catch (error) {
                    if (addToast) addToast('Unlock failed', 'error');
                }
                setUnlockLoading(false);
            };
            
            // Fetch lock status on mount
            useEffect(() => {
                fetchLockStatus();
            }, [vm.vmid, clusterId]);

            // NS: Issue #50 - Fetch guest agent info
            useEffect(() => {
                if (!isQemu || vm.status !== 'running') { setGuestInfo(null); return; }
                authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/guest-info`)
                    .then(r => r && r.ok ? r.json() : null)
                    .then(data => { if (data && data.agent_running) setGuestInfo(data); else setGuestInfo(null); })
                    .catch(() => setGuestInfo(null));
            }, [vm.vmid, vm.status, clusterId]);

            // NS: Fetch VM config for hardware info (machine type, BIOS, SCSI, CPU model)
            const [vmHwInfo, setVmHwInfo] = useState(null);
            useEffect(() => {
                if (!isQemu) { setVmHwInfo(null); return; }
                authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`)
                    .then(r => r && r.ok ? r.json() : null)
                    .then(cfg => {
                        if (!cfg) { setVmHwInfo(null); return; }
                        const raw = cfg.raw || cfg;
                        setVmHwInfo({
                            machine: raw.machine || 'i440fx',
                            bios: raw.bios || 'seabios',
                            cpu: raw.cpu || 'kvm64',
                            scsihw: raw.scsihw || 'lsi',
                            cores: raw.cores || 1,
                            sockets: raw.sockets || 1,
                            ostype: raw.ostype,
                            net: (() => { const nk = Object.keys(raw).find(k => k.startsWith('net')); return nk ? raw[nk].split(',')[0].split('=')[0] : null; })(),
                            agent: raw.agent,
                        });
                    })
                    .catch(() => setVmHwInfo(null));
            }, [vm.vmid, clusterId]);

            // Check HA status for this VM
            useEffect(() => {
                const checkHaStatus = async () => {
                    try {
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`);
                        if(response && response.ok) {
                            const resources = await response.json();
                            setHaResources(resources);
                            const vmType = isQemu ? 'vm' : 'ct';
                            const isInHa = resources.some(r => r.sid === `${vmType}:${vm.vmid}`);
                            setHaEnabled(isInHa);
                        }
                    } catch (error) {
                        console.error('checking HA status:', error);
                    }
                };
                checkHaStatus();
            }, [vm.vmid, clusterId]);

            const toggleProxmoxHa = async () => {
                setHaLoading(true);
                try {
                    const vmType = isQemu ? 'vm' : 'ct';
                    if(haEnabled) {
                        // Remove from HA
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources/${vmType}:${vm.vmid}`, {
                            method: 'DELETE'
                        });
                        if(response && response.ok) {
                            setHaEnabled(false);
                        }
                    }else{
                        // Add to HA
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                vmid: vm.vmid,
                                type: vmType,
                                max_restart: 3,
                                max_relocate: 3
                            })
                        });
                        if(response && response.ok) {
                            setHaEnabled(true);
                        }
                    }
                } catch (error) {
                    console.error('toggling HA:', error);
                } finally {
                    setHaLoading(false);
                }
            };

            return (
                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                    {/* Header */}
                    <div className="p-6 border-b border-proxmox-border bg-gradient-to-r from-proxmox-dark to-proxmox-card">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className={`p-3 rounded-xl ${isQemu ? 'bg-blue-500/20' : 'bg-purple-500/20'}`}>
                                    {isQemu ? <Icons.VM /> : <Icons.Container />}
                                </div>
                                <div>
                                    <h2 className="text-xl font-bold text-white">{displayName}</h2>
                                    <div className="flex items-center gap-3 text-sm text-gray-400">
                                        <span>ID: {vm.vmid}</span>
                                        <span>•</span>
                                        <span>{isQemu ? 'QEMU VM' : 'LXC Container'}</span>
                                        <span>•</span>
                                        <span>{vm.node}</span>
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {/* MK: Lock indicator */}
                                {lockInfo?.locked && (
                                    <span 
                                        className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1 cursor-pointer hover:bg-red-500/30 transition-colors"
                                        onClick={() => setShowUnlockConfirm(true)}
                                        title={lockInfo?.lock_description || 'Locked'}
                                    >
                                        <Icons.Lock />
                                        {lockInfo?.lock_reason || 'Locked'}
                                    </span>
                                )}
                                {haEnabled && (
                                    <span className="px-2 py-1 rounded-full text-xs font-medium bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 flex items-center gap-1">
                                        <Icons.Shield />
                                        HA
                                    </span>
                                )}
                                <span className={`px-3 py-1.5 rounded-full text-sm font-medium ${
                                    vm.status === 'running' 
                                        ? 'bg-green-500/20 text-green-400' 
                                        : 'bg-red-500/20 text-red-400'
                                }`}>
                                    {vm.status === 'running' ? '● ' + t('running') : '○ ' + t('stopped')}
                                </span>
                            </div>
                        </div>
                    </div>
                    
                    {/* MK: Unlock Confirmation Modal */}
                    {showUnlockConfirm && lockInfo?.locked && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={() => setShowUnlockConfirm(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 max-w-md w-full mx-4" onClick={e => e.stopPropagation()}>
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="p-2 rounded-lg bg-red-500/20">
                                        <Icons.AlertTriangle className="text-red-400" />
                                    </div>
                                    <h3 className="text-lg font-bold text-white">{t('unlockVm') || 'Unlock VM'}</h3>
                                </div>
                                
                                <div className="space-y-4">
                                    <div className="bg-proxmox-dark rounded-lg p-4">
                                        <div className="text-sm text-gray-400 mb-2">{t('lockReason') || 'Lock Reason'}:</div>
                                        <div className="text-white font-medium">{lockInfo?.lock_description || 'Unknown'}</div>
                                        <div className="text-xs text-gray-500 mt-1">({lockInfo?.lock_reason || 'unknown'})</div>
                                    </div>
                                    
                                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                                        <div className="flex items-start gap-2">
                                            <Icons.AlertTriangle className="text-yellow-400 mt-0.5 flex-shrink-0" />
                                            <div className="text-sm text-yellow-300">
                                                {t('unlockWarning') || 'Warning: Unlocking a VM during an active operation may cause data corruption or other issues. Only proceed if you are sure the operation has failed or been cancelled.'}
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div className="bg-proxmox-dark rounded-lg p-3">
                                        <div className="text-xs text-gray-500 mb-1">CLI {t('command') || 'Command'}:</div>
                                        <code className="text-sm text-green-400 font-mono">{lockInfo?.unlock_command || `qm unlock ${vm.vmid}`}</code>
                                    </div>
                                </div>
                                
                                <div className="flex gap-3 mt-6">
                                    <button
                                        onClick={() => setShowUnlockConfirm(false)}
                                        className="flex-1 px-4 py-2 bg-proxmox-dark text-gray-300 rounded-lg hover:bg-proxmox-hover transition-colors"
                                    >
                                        {t('cancel')}
                                    </button>
                                    <button
                                        onClick={handleUnlock}
                                        disabled={unlockLoading}
                                        className="flex-1 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                                    >
                                        {unlockLoading ? <Icons.RotateCw className="animate-spin" /> : <Icons.Unlock />}
                                        {t('unlock') || 'Unlock'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Stats Grid */}
                    <div className="p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="bg-proxmox-dark rounded-lg p-4">
                            <div className="text-xs text-gray-500 mb-1">CPU</div>
                            <div className="text-lg font-bold text-white">{(vm.cpu_percent || 0).toFixed(1)}%</div>
                            <div className="text-xs text-gray-500">{vm.maxcpu || 1} {t('cores')}</div>
                            <div className="mt-2 h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                <div 
                                    className="h-full rounded-full transition-all"
                                    style={{
                                        width: `${Math.min(vm.cpu_percent || 0, 100)}%`,
                                        background: (vm.cpu_percent || 0) < 50 ? '#3b82f6' : (vm.cpu_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                    }}
                                />
                            </div>
                        </div>
                        <div className="bg-proxmox-dark rounded-lg p-4">
                            <div className="text-xs text-gray-500 mb-1">RAM</div>
                            <div className="text-lg font-bold text-white">{(vm.mem_percent || 0).toFixed(1)}%</div>
                            <div className="text-xs text-gray-500">{formatBytes(vm.mem)} / {formatBytes(vm.maxmem)}</div>
                            <div className="mt-2 h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                <div 
                                    className="h-full rounded-full transition-all"
                                    style={{
                                        width: `${vm.mem_percent || 0}%`,
                                        background: (vm.mem_percent || 0) < 50 ? '#22c55e' : (vm.mem_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                    }}
                                />
                            </div>
                        </div>
                        <div className="bg-proxmox-dark rounded-lg p-4">
                            <div className="text-xs text-gray-500 mb-1">Disk</div>
                            <div className="text-lg font-bold text-white">{formatBytes(vm.disk || 0)}</div>
                            <div className="text-xs text-gray-500">{t('of')} {formatBytes(vm.maxdisk || 0)}</div>
                        </div>
                        <div className="bg-proxmox-dark rounded-lg p-4">
                            <div className="text-xs text-gray-500 mb-1">{t('uptime')}</div>
                            <div className="text-lg font-bold text-white">{formatUptime(vm.uptime)}</div>
                            <div className="text-xs text-gray-500">{vm.status === 'running' ? t('sinceStart') : t('offline')}</div>
                        </div>
                    </div>

                    {/* NS: Hardware info from VM config */}
                    {isQemu && vmHwInfo && (
                        <div className="px-6 pb-2">
                            <div className="flex flex-wrap gap-2">
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                    <Icons.Cpu className="w-3 h-3 text-blue-400" />
                                    <span className="text-gray-400">CPU:</span>
                                    <span className="text-white font-medium">{vmHwInfo.cpu}</span>
                                    <span className="text-gray-500">({vmHwInfo.sockets}s/{vmHwInfo.cores}c)</span>
                                </span>
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                    <Icons.Monitor className="w-3 h-3 text-amber-400" />
                                    <span className="text-gray-400">Machine:</span>
                                    <span className="text-white font-medium">{vmHwInfo.machine}</span>
                                </span>
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                    <Icons.HardDrive className="w-3 h-3 text-emerald-400" />
                                    <span className="text-gray-400">BIOS:</span>
                                    <span className="text-white font-medium">{vmHwInfo.bios === 'ovmf' ? 'UEFI (OVMF)' : 'SeaBIOS'}</span>
                                </span>
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                    <Icons.Database className="w-3 h-3 text-purple-400" />
                                    <span className="text-gray-400">SCSI:</span>
                                    <span className="text-white font-medium">{vmHwInfo.scsihw}</span>
                                </span>
                                {vmHwInfo.net && (
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.Globe className="w-3 h-3 text-cyan-400" />
                                        <span className="text-gray-400">NIC:</span>
                                        <span className="text-white font-medium">{vmHwInfo.net}</span>
                                    </span>
                                )}
                                {vmHwInfo.ostype && (
                                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-proxmox-dark border border-proxmox-border text-xs">
                                        <Icons.Network className="w-3 h-3 text-orange-400" />
                                        <span className="text-gray-400">OS:</span>
                                        <span className="text-white font-medium">{vmHwInfo.ostype}</span>
                                    </span>
                                )}
                            </div>
                        </div>
                    )}

                    {/* NS: Issue #50 - Guest Agent Info */}
                    {isQemu && vm.status === 'running' && guestInfo && (
                        <div className="px-6 pb-2">
                            <div className="bg-proxmox-dark rounded-lg p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                                {guestInfo.hostname && (
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded-lg bg-cyan-500/10">
                                            <Icons.Monitor className="w-4 h-4 text-cyan-400" />
                                        </div>
                                        <div>
                                            <div className="text-xs text-gray-500">Hostname</div>
                                            <div className="text-sm font-semibold text-white font-mono">{guestInfo.hostname}</div>
                                        </div>
                                    </div>
                                )}
                                {guestInfo.os_pretty_name && (
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded-lg bg-emerald-500/10">
                                            <Icons.Cpu className="w-4 h-4 text-emerald-400" />
                                        </div>
                                        <div>
                                            <div className="text-xs text-gray-500">{t('osVersion')}</div>
                                            <div className="text-sm font-semibold text-white">{guestInfo.os_pretty_name}</div>
                                        </div>
                                    </div>
                                )}
                                {guestInfo.os_kernel && (
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded-lg bg-purple-500/10">
                                            <Icons.Terminal className="w-4 h-4 text-purple-400" />
                                        </div>
                                        <div>
                                            <div className="text-xs text-gray-500">Kernel</div>
                                            <div className="text-sm font-semibold text-gray-300 font-mono">{guestInfo.os_kernel}</div>
                                        </div>
                                    </div>
                                )}
                                <div className="flex items-center gap-1.5 md:col-span-3 pt-2 border-t border-gray-700/30">
                                    <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                                    <span className="text-xs text-cyan-400/70">QEMU Guest Agent</span>
                                </div>
                            </div>
                        </div>
                    )}
                    {isQemu && vm.status === 'running' && !guestInfo && (
                        <div className="px-6 pb-2">
                            <div className="bg-proxmox-dark rounded-lg p-3 flex items-center gap-3">
                                <div className="p-1.5 rounded-lg bg-yellow-500/10">
                                    <Icons.AlertTriangle className="w-4 h-4 text-yellow-500" />
                                </div>
                                <div className="flex-1">
                                    <div className="text-sm text-yellow-400">{t('guestAgentNotInstalled')}</div>
                                    <div className="text-xs text-gray-500">{t('guestAgentInstallHint')}</div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Quick Actions */}
                    <div className="px-6 pb-6">
                        <div className="text-xs text-gray-500 mb-3">{t('quickActions')}</div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {vm.status === 'stopped' ? (
                                <button
                                    onClick={() => handleAction('start')}
                                    disabled={actionLoading?.[`${vm.vmid}-start`]}
                                    className="flex items-center justify-center gap-2 p-3 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 rounded-lg text-green-400 transition-all disabled:opacity-50"
                                >
                                    {actionLoading?.[`${vm.vmid}-start`] ? <Icons.RotateCw /> : <Icons.PlayCircle />}
                                    {t('start')}
                                </button>
                            ) : (
                                <>
                                    <button
                                        onClick={() => handleAction('shutdown')}
                                        disabled={actionLoading?.[`${vm.vmid}-shutdown`]}
                                        className="flex items-center justify-center gap-2 p-3 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30 rounded-lg text-yellow-400 transition-all disabled:opacity-50"
                                    >
                                        {actionLoading?.[`${vm.vmid}-shutdown`] ? <Icons.RotateCw /> : <Icons.Power />}
                                        {t('shutdown')}
                                    </button>
                                    <button
                                        onClick={() => handleAction('reboot')}
                                        disabled={actionLoading?.[`${vm.vmid}-reboot`]}
                                        className="flex items-center justify-center gap-2 p-3 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 rounded-lg text-orange-400 transition-all disabled:opacity-50"
                                    >
                                        {actionLoading?.[`${vm.vmid}-reboot`] ? <Icons.RotateCw /> : <Icons.RefreshCw />}
                                        {t('reboot')}
                                    </button>
                                </>
                            )}
                            <button
                                onClick={() => onOpenConsole(vm)}
                                className="flex items-center justify-center gap-2 p-3 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 rounded-lg text-blue-400 transition-all"
                            >
                                <Icons.Monitor />
                                {t('console')}
                            </button>
                            <button
                                onClick={() => onOpenConfig(vm)}
                                className="flex items-center justify-center gap-2 p-3 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-gray-300 transition-all"
                            >
                                <Icons.Cog />
                                {t('configuration')}
                            </button>
                        </div>
                    </div>

                    {/* More Actions */}
                    <div className="px-6 pb-6">
                        <div className="text-xs text-gray-500 mb-3">{t('moreActions')}</div>
                        <div className="flex flex-wrap gap-2">
                            <button
                                onClick={() => onShowMetrics && onShowMetrics(vm)}
                                className="flex items-center gap-2 px-3 py-2 bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/30 rounded-lg text-sm text-indigo-400 transition-all"
                            >
                                <Icons.BarChart />
                                {t('performanceMetrics')}
                            </button>
                            <button
                                onClick={onMigrate}
                                className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-sm text-gray-300 transition-all"
                            >
                                <Icons.ArrowRight />
                                {t('migrate')}
                            </button>
                            {showCrossCluster && (
                                <button
                                    onClick={() => onCrossClusterMigrate(vm)}
                                    className="flex items-center gap-2 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 rounded-lg text-sm text-cyan-400 transition-all"
                                >
                                    <Icons.Globe />
                                    {t('crossClusterMigrate')}
                                </button>
                            )}
                            <button
                                onClick={onClone}
                                className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-border border border-proxmox-border rounded-lg text-sm text-gray-300 transition-all"
                            >
                                <Icons.Copy />
                                {t('clone')}
                            </button>
                            {vm.status === 'running' && (
                                <>
                                    {/* Force Reset - QEMU only (LXC doesn't support it) */}
                                    {isQemu && (
                                        <button
                                            onClick={() => handleAction('reset')}
                                            disabled={actionLoading?.[`${vm.vmid}-reset`]}
                                            className="flex items-center gap-2 px-3 py-2 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 rounded-lg text-sm text-orange-400 transition-all disabled:opacity-50"
                                        >
                                            {actionLoading?.[`${vm.vmid}-reset`] ? <Icons.RotateCw className="animate-spin" /> : <Icons.Zap />}
                                            {t('forceReset') || 'Force Reset'}
                                        </button>
                                    )}
                                    <button
                                        onClick={() => onForceStop(vm)}
                                        className="flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-sm text-red-400 transition-all"
                                    >
                                        <Icons.XCircle />
                                        {t('forceStop')}
                                    </button>
                                </>
                            )}
                            <button
                                onClick={onDelete}
                                className="flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-sm text-red-400 transition-all"
                            >
                                <Icons.Trash />
                                {t('delete')}
                            </button>
                        </div>
                    </div>

                    {/* Proxmox HA Section */}
                    <div className="px-6 pb-6">
                        <div className="text-xs text-gray-500 mb-3">{t('proxmoxHa')}</div>
                        <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className={`p-2 rounded-lg ${haEnabled ? 'bg-green-500/20' : 'bg-gray-500/20'}`}>
                                        <Icons.Shield />
                                    </div>
                                    <div>
                                        <div className="text-sm font-medium text-white">
                                            {t('proxmoxHa')} {haEnabled ? t('active') : t('haInactive').replace('Proxmox HA ', '')}
                                        </div>
                                        <div className="text-xs text-gray-500">
                                            {haEnabled 
                                                ? t('haMonitorDesc').split('.')[0] 
                                                : t('enableNativeHa')}
                                        </div>
                                    </div>
                                </div>
                                <button
                                    onClick={toggleProxmoxHa}
                                    disabled={haLoading}
                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50 ${
                                        haEnabled
                                            ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30'
                                            : 'bg-green-500/20 hover:bg-green-500/30 text-green-400 border border-green-500/30'
                                    }`}
                                >
                                    {haLoading ? (
                                        <Icons.RotateCw />
                                    ) : haEnabled ? (
                                        t('disable') + ' HA'
                                    ) : (
                                        t('haActivate')
                                    )}
                                </button>
                            </div>
                            {haEnabled && (
                                <div className="mt-3 pt-3 border-t border-gray-700/50 grid grid-cols-2 gap-4 text-xs">
                                    <div>
                                        <span className="text-gray-500">Max. Restarts:</span>
                                        <span className="ml-2 text-white">3</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500">Max. Relocate:</span>
                                        <span className="ml-2 text-white">3</span>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Tags */}
                    {vm.tags && (
                        <div className="px-6 pb-6">
                            <div className="text-xs text-gray-500 mb-2">Tags</div>
                            <div className="flex flex-wrap gap-2">
                                {vm.tags.split(';').map(tag => (
                                    <span key={tag} className="px-2 py-1 bg-proxmox-dark rounded text-xs text-gray-400">
                                        {tag}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // LW: Feb 2026 - Corporate VM Detail View (experimental)
        function CorporateVmDetailView({ vm, clusterId, onAction, onOpenConsole, onOpenConfig, onBack, onMigrate, onClone, onForceStop, onDelete, onCrossClusterMigrate, showCrossCluster, actionLoading, onShowMetrics, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [activeDetailTab, setActiveDetailTab] = useState('summary');
            const [showActionsMenu, setShowActionsMenu] = useState(false);

            const isQemu = vm.type === 'qemu';
            const displayName = vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`;
            const isRunning = vm.status === 'running';

            // Reuse same fetch pattern as VmDetailPanel
            const authFetch = async (url, opts = {}) => {
                try { return await fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } }); }
                catch(e) { console.error(e); return null; }
            };

            const formatBytes = b => {
                if(!b) return '0 B';
                const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(b) / Math.log(k));
                return `${(b / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
            };

            const formatUptime = (uptime) => {
                if(!uptime) return '-';
                const days = Math.floor(uptime / 86400);
                const hours = Math.floor((uptime % 86400) / 3600);
                const mins = Math.floor((uptime % 3600) / 60);
                if(days > 0) return `${days}d ${hours}h ${mins}m`;
                if(hours > 0) return `${hours}h ${mins}m`;
                return `${mins}m`;
            };

            const handleAction = async (action) => { await onAction(vm, action); };

            // State for fetched data
            const [haEnabled, setHaEnabled] = useState(false);
            const [haLoading, setHaLoading] = useState(false);
            const [haResources, setHaResources] = useState([]);
            const [lockInfo, setLockInfo] = useState({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
            const [unlockLoading, setUnlockLoading] = useState(false);
            const [showUnlockConfirm, setShowUnlockConfirm] = useState(false);
            const [guestInfo, setGuestInfo] = useState(null);
            const [vmHwInfo, setVmHwInfo] = useState(null);

            // Close actions menu on outside click
            useEffect(() => {
                if (!showActionsMenu) return;
                const close = () => setShowActionsMenu(false);
                document.addEventListener('click', close);
                return () => document.removeEventListener('click', close);
            }, [showActionsMenu]);

            // Fetch lock status
            const fetchLockStatus = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/lock`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setLockInfo({ locked: data.locked || false, lock_reason: data.lock_reason || null, lock_description: data.lock_description || null, unlock_command: data.unlock_command || null });
                    } else {
                        setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
                    }
                } catch (error) { setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null }); }
            };
            useEffect(() => { fetchLockStatus(); }, [vm.vmid, clusterId]);

            // Unlock VM
            const handleUnlock = async () => {
                setUnlockLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/unlock`, { method: 'POST' });
                    if (response && response.ok) {
                        if (addToast) addToast(t('vmUnlocked') || `VM ${vm.vmid} unlocked successfully`, 'success');
                        setLockInfo({ locked: false, lock_reason: null, lock_description: null, unlock_command: null });
                        setShowUnlockConfirm(false);
                    } else {
                        const err = await response.json();
                        if (addToast) addToast(err.error || 'Unlock failed', 'error');
                    }
                } catch (error) { if (addToast) addToast('Unlock failed', 'error'); }
                setUnlockLoading(false);
            };

            // Fetch guest agent info
            useEffect(() => {
                if (!isQemu || vm.status !== 'running') { setGuestInfo(null); return; }
                authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/guest-info`)
                    .then(r => r && r.ok ? r.json() : null)
                    .then(data => { if (data && data.agent_running) setGuestInfo(data); else setGuestInfo(null); })
                    .catch(() => setGuestInfo(null));
            }, [vm.vmid, vm.status, clusterId]);

            // Fetch VM hardware config
            useEffect(() => {
                if (!isQemu) { setVmHwInfo(null); return; }
                authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`)
                    .then(r => r && r.ok ? r.json() : null)
                    .then(cfg => {
                        if (!cfg) { setVmHwInfo(null); return; }
                        const raw = cfg.raw || cfg;
                        setVmHwInfo({
                            machine: raw.machine || 'i440fx', bios: raw.bios || 'seabios',
                            cpu: raw.cpu || 'kvm64', scsihw: raw.scsihw || 'lsi',
                            cores: raw.cores || 1, sockets: raw.sockets || 1,
                            ostype: raw.ostype,
                            net: (() => { const nk = Object.keys(raw).find(k => k.startsWith('net')); return nk ? raw[nk].split(',')[0].split('=')[0] : null; })(),
                            agent: raw.agent,
                        });
                    })
                    .catch(() => setVmHwInfo(null));
            }, [vm.vmid, clusterId]);

            // Fetch HA status
            useEffect(() => {
                authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`)
                    .then(r => r && r.ok ? r.json() : null)
                    .then(resources => {
                        if (resources) {
                            setHaResources(resources);
                            const vmType = isQemu ? 'vm' : 'ct';
                            setHaEnabled(resources.some(r => r.sid === `${vmType}:${vm.vmid}`));
                        }
                    })
                    .catch(() => {});
            }, [vm.vmid, clusterId]);

            // Toggle HA
            const toggleProxmoxHa = async () => {
                setHaLoading(true);
                try {
                    const vmType = isQemu ? 'vm' : 'ct';
                    if (haEnabled) {
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources/${vmType}:${vm.vmid}`, { method: 'DELETE' });
                        if (response && response.ok) setHaEnabled(false);
                    } else {
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ vmid: vm.vmid, type: vmType, max_restart: 3, max_relocate: 3 })
                        });
                        if (response && response.ok) setHaEnabled(true);
                    }
                } catch (error) { console.error('toggling HA:', error); }
                finally { setHaLoading(false); }
            };

            const cpuPercent = vm.maxcpu ? ((vm.cpu || 0) * 100).toFixed(1) : 0;
            const ramPercent = vm.maxmem ? ((vm.mem / vm.maxmem) * 100).toFixed(1) : 0;

            return (
                <div className="space-y-0">
                    {/* Unlock Confirmation Modal */}
                    {showUnlockConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border p-5">
                                <h3 className="text-[14px] font-semibold text-white mb-3">{t('unlockVm') || 'Unlock VM'}</h3>
                                <p className="text-[13px] text-gray-400 mb-2">{t('unlockVmConfirm') || `Are you sure you want to unlock ${displayName}?`}</p>
                                {lockInfo.lock_description && <p className="text-[12px] mb-2" style={{color: '#efc006'}}>{lockInfo.lock_description}</p>}
                                {lockInfo.unlock_command && <code className="block text-[11px] text-gray-500 bg-proxmox-dark p-2 mb-3 font-mono">{lockInfo.unlock_command}</code>}
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowUnlockConfirm(false)} className="px-3 py-1.5 text-[13px] text-gray-400 border border-proxmox-border hover:text-white">{t('cancel')}</button>
                                    <button onClick={handleUnlock} disabled={unlockLoading} className="px-3 py-1.5 text-[13px] text-white border disabled:opacity-50" style={{background: '#efc006', borderColor: '#d4a905'}}>
                                        {unlockLoading ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : t('unlock') || 'Unlock'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Header Bar - Clarity dark theme */}
                    <div className="flex items-center justify-between px-4 py-2 border-b border-proxmox-border" style={{background: '#22343c'}}>
                        <div className="flex items-center gap-2">
                            <button onClick={onBack} className="p-1 hover:text-white" style={{color: '#adbbc4'}} title={t('backToList')}>
                                <Icons.ChevronLeft className="w-4 h-4" />
                            </button>
                            <Icons.Monitor className={`w-4 h-4 ${vm.type === 'lxc' ? 'text-cyan-400' : isRunning ? 'text-green-400' : ''}`} style={!vm.type === 'lxc' && !isRunning ? {color: '#728b9a'} : {}} />
                            <span className="text-[14px] font-medium" style={{color: '#e9ecef'}}>{displayName}</span>
                            <span className="text-[11px]" style={{color: '#728b9a'}}>({vm.vmid})</span>
                            <span className={`corp-badge ${isRunning ? 'corp-badge-running' : 'corp-badge-stopped'}`}>
                                {isRunning ? t('running') : t('stopped')}
                            </span>
                            {haEnabled && <span className="corp-badge corp-badge-ha">HA</span>}
                            {lockInfo.locked && <span className="corp-badge corp-badge-locked flex items-center gap-1"><Icons.Lock className="w-2.5 h-2.5" />{t('locked')}</span>}
                        </div>
                        <div className="corp-toolbar flex items-center gap-1">
                            {!isRunning && (
                                <button onClick={() => handleAction('start')} disabled={actionLoading?.[`${vm.vmid}-start`]}>
                                    {actionLoading?.[`${vm.vmid}-start`] ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : <Icons.PlayCircle className="w-3 h-3" style={{color: '#60b515'}} />} {t('start')}
                                </button>
                            )}
                            {isRunning && (
                                <>
                                    <button onClick={() => handleAction('shutdown')} disabled={actionLoading?.[`${vm.vmid}-shutdown`]}>
                                        {actionLoading?.[`${vm.vmid}-shutdown`] ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : <Icons.Power className="w-3 h-3" style={{color: '#f54f47'}} />} {t('shutdown')}
                                    </button>
                                    <button onClick={() => handleAction('reboot')} disabled={actionLoading?.[`${vm.vmid}-reboot`]}>
                                        {actionLoading?.[`${vm.vmid}-reboot`] ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : <Icons.RefreshCw className="w-3 h-3" style={{color: '#efc006'}} />} {t('reboot')}
                                    </button>
                                </>
                            )}
                            {isQemu && isRunning && (
                                <button onClick={() => onOpenConsole(vm)}>
                                    <Icons.Terminal className="w-3 h-3" /> {t('console')}
                                </button>
                            )}
                            <button onClick={() => onOpenConfig(vm)}>
                                <Icons.Settings className="w-3 h-3" /> {t('configure')}
                            </button>
                            {/* Actions Dropdown */}
                            <div className="relative">
                                <button onClick={(e) => { e.stopPropagation(); setShowActionsMenu(!showActionsMenu); }}>
                                    {t('actions')} <Icons.ChevronDown className="w-3 h-3" />
                                </button>
                                {showActionsMenu && (
                                    <div className="corp-dropdown absolute right-0 top-full mt-1 w-52 z-50 py-1" onClick={(e) => e.stopPropagation()}>
                                        {onShowMetrics && (
                                            <button onClick={() => { onShowMetrics(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                                <Icons.BarChart className="w-3.5 h-3.5" /> {t('performanceMetrics')}
                                            </button>
                                        )}
                                        <button onClick={() => { onMigrate(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.ArrowRight className="w-3.5 h-3.5" /> {t('migrate')}
                                        </button>
                                        {showCrossCluster && (
                                            <button onClick={() => { onCrossClusterMigrate(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                                <Icons.Globe className="w-3.5 h-3.5" /> {t('crossClusterMigrate')}
                                            </button>
                                        )}
                                        <button onClick={() => { onClone(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.Copy className="w-3.5 h-3.5" /> {t('clone')}
                                        </button>
                                        {isRunning && isQemu && (
                                            <button onClick={() => { handleAction('reset'); setShowActionsMenu(false); }} disabled={actionLoading?.[`${vm.vmid}-reset`]} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#efc006'}}>
                                                <Icons.Zap className="w-3.5 h-3.5" /> {t('forceReset') || 'Force Reset'}
                                            </button>
                                        )}
                                        {isRunning && (
                                            <button onClick={() => { onForceStop(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#f54f47'}}>
                                                <Icons.XCircle className="w-3.5 h-3.5" /> {t('forceStop')}
                                            </button>
                                        )}
                                        <div className="my-1" style={{borderTop: '1px solid #485764'}}></div>
                                        <button onClick={() => { onDelete(vm); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#f54f47'}}>
                                            <Icons.Trash className="w-3.5 h-3.5" /> {t('delete')}
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Tab Strip - Clarity style */}
                    <div className="corp-tab-strip px-4" style={{background: '#22343c'}}>
                        <button className={activeDetailTab === 'summary' ? 'active' : ''} onClick={() => setActiveDetailTab('summary')}>
                            {t('summary')}
                        </button>
                        <button onClick={() => onOpenConfig(vm)}>
                            {t('configure')}
                        </button>
                        {/* LW: Feb 2026 - console tab for QEMU (VNC) and LXC (xterm.js) */}
                        {isRunning && (
                            <button onClick={() => onOpenConsole(vm)}>
                                <Icons.Terminal className="w-3 h-3 inline mr-1" />{t('console')}
                            </button>
                        )}
                    </div>

                    {/* LW: Feb 2026 - summary tab, corporate layout */}
                    {activeDetailTab === 'summary' && (
                        <div className="p-4 space-y-4">
                            {/* console preview + vm info */}
                            <div className="flex gap-5">
                                {/* Left: Console Preview Area */}
                                <div className="flex-shrink-0" style={{width: '280px'}}>
                                    <div className="flex items-center justify-center" style={{height: '180px', background: '#17242b', border: '1px solid #485764'}}>
                                        <div className="text-center">
                                            {isQemu
                                                ? <Icons.Monitor className="w-12 h-12 mx-auto mb-2" style={{color: '#485764'}} />
                                                : <Icons.Box className="w-12 h-12 mx-auto mb-2" style={{color: '#485764'}} />
                                            }
                                            <div className="text-[11px]" style={{color: '#728b9a'}}>{isRunning ? t('consoleAvailable') || 'Console available' : t('vmStopped') || 'VM is powered off'}</div>
                                        </div>
                                    </div>
                                    {isRunning && (
                                        <button onClick={() => onOpenConsole(vm)} className="w-full mt-1.5 py-1.5 text-[12px] font-medium uppercase tracking-wider flex items-center justify-center gap-1.5" style={{background: '#22343c', border: '1px solid #485764', color: '#49afd9'}}>
                                            <Icons.Terminal className="w-3.5 h-3.5" />
                                            {t('launchWebConsole') || 'Launch Web Console'}
                                        </button>
                                    )}
                                </div>

                                {/* Right: VM Properties + Quick Stats */}
                                <div className="flex-1 min-w-0">
                                    <table className="corp-property-grid">
                                        <tbody>
                                            <tr><td>{t('guestOs') || 'Guest OS'}</td><td>{guestInfo?.os_pretty_name || vmHwInfo?.ostype || (isQemu ? 'QEMU Virtual Machine' : 'LXC Container')}</td></tr>
                                            <tr><td>{t('type')}</td><td>{isQemu ? 'QEMU/KVM' : 'LXC'} - {vmHwInfo ? `${vmHwInfo.machine} / ${vmHwInfo.bios === 'ovmf' ? 'UEFI' : 'SeaBIOS'}` : vm.vmid}</td></tr>
                                            <tr><td>{t('qemuAgent') || 'QEMU Agent'}</td><td className="flex items-center gap-1.5">{isQemu && isRunning ? (guestInfo ? <><span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: '#60b515'}}></span> {t('running')}</> : <><span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: '#f54f47'}}></span> {t('notInstalled') || 'Not installed'}</>) : <span style={{color: '#728b9a'}}>-</span>}</td></tr>
                                            <tr><td>IP</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{guestInfo?.ip_addresses?.join(', ') || '-'}</td></tr>
                                            {guestInfo?.hostname && <tr><td>{t('hostname')}</td><td>{guestInfo.hostname}</td></tr>}
                                            {vm.tags && <tr><td>Tags</td><td><div className="flex flex-wrap gap-1">{vm.tags.split(';').map(tag => (
                                                <span key={tag} className="px-1.5 py-0.5 text-[11px]" style={{background: 'rgba(73, 175, 217, 0.12)', color: '#49afd9', border: '1px solid rgba(73, 175, 217, 0.25)'}}>{tag}</span>
                                            ))}</div></td></tr>}
                                        </tbody>
                                    </table>
                                    {/* stats */}
                                    <div className="mt-3 flex gap-4">
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2 h-2 rounded-full" style={{background: '#49afd9'}}></div>
                                            <span className="text-[12px]" style={{color: '#adbbc4'}}>{t('cpuUsage')}</span>
                                            <span className="text-[12px] font-medium" style={{color: '#e9ecef'}}>{cpuPercent}%</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2 h-2 rounded-full" style={{background: '#9b59b6'}}></div>
                                            <span className="text-[12px]" style={{color: '#adbbc4'}}>{t('ramUsage')}</span>
                                            <span className="text-[12px] font-medium" style={{color: '#e9ecef'}}>{formatBytes(vm.mem)}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2 h-2 rounded-full" style={{background: '#60b515'}}></div>
                                            <span className="text-[12px]" style={{color: '#adbbc4'}}>Disk</span>
                                            <span className="text-[12px] font-medium" style={{color: '#e9ecef'}}>{formatBytes(vm.maxdisk)}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2 h-2 rounded-full" style={{background: '#efc006'}}></div>
                                            <span className="text-[12px]" style={{color: '#adbbc4'}}>{t('uptime')}</span>
                                            <span className="text-[12px] font-medium" style={{color: '#e9ecef'}}>{formatUptime(vm.uptime)}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* warnings */}
                            {lockInfo.locked && (
                                <div className="flex items-center justify-between px-3 py-2" style={{background: 'rgba(239, 192, 6, 0.08)', borderLeft: '3px solid #efc006'}}>
                                    <div className="flex items-center gap-2">
                                        <Icons.Lock className="w-4 h-4" style={{color: '#efc006'}} />
                                        <span className="text-[13px]" style={{color: '#efc006'}}>{t('vmLocked') || 'This virtual machine is locked'}: {lockInfo.lock_reason || 'unknown'}</span>
                                    </div>
                                    <button onClick={() => setShowUnlockConfirm(true)} className="px-2 py-1 text-[12px] font-medium" style={{color: '#49afd9'}}>
                                        {t('unlock') || 'Unlock'}
                                    </button>
                                </div>
                            )}
                            {isQemu && isRunning && !guestInfo && (
                                <div className="flex items-center gap-2 px-3 py-2" style={{background: 'rgba(239, 192, 6, 0.08)', borderLeft: '3px solid #efc006'}}>
                                    <Icons.AlertTriangle className="w-4 h-4 flex-shrink-0" style={{color: '#efc006'}} />
                                    <span className="text-[13px]" style={{color: '#efc006'}}>{t('guestAgentNotInstalled')}</span>
                                    <a href="https://pve.proxmox.com/wiki/Qemu-guest-agent" target="_blank" rel="noopener noreferrer" className="text-[12px] ml-1" style={{color: '#49afd9'}}>{t('installGuestAgent') || 'Install QEMU Guest Agent...'}</a>
                                </div>
                            )}

                            {/* hardware + related */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {/* Left: VM Hardware */}
                                <div style={{border: '1px solid #485764'}}>
                                    <div className="px-3 py-2 flex items-center justify-between" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('vmHardware') || 'VM Hardware'}</span>
                                    </div>
                                    <div className="p-3 space-y-2">
                                        {/* CPU */}
                                        <div className="flex items-center gap-2 text-[12px]">
                                            <Icons.Cpu className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                            <span style={{color: '#adbbc4', width: '60px'}}>CPU</span>
                                            <div className="flex-1">
                                                <div className="flex items-center gap-2">
                                                    <div className="flex-1 h-1.5 overflow-hidden" style={{background: '#1b2a32'}}>
                                                        <div className="h-full" style={{width: `${Math.min(cpuPercent, 100)}%`, background: '#49afd9'}}></div>
                                                    </div>
                                                    <span style={{color: '#e9ecef', minWidth: '35px'}}>{cpuPercent}%</span>
                                                </div>
                                                <div className="text-[11px] mt-0.5" style={{color: '#728b9a'}}>{vm.maxcpu} {t('cores')} {vmHwInfo ? `• ${vmHwInfo.cpu}` : ''}</div>
                                            </div>
                                        </div>
                                        {/* Memory */}
                                        <div className="flex items-center gap-2 text-[12px]">
                                            <Icons.MemoryStick className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#9b59b6'}} />
                                            <span style={{color: '#adbbc4', width: '60px'}}>{t('memory') || 'Memory'}</span>
                                            <div className="flex-1">
                                                <div className="flex items-center gap-2">
                                                    <div className="flex-1 h-1.5 overflow-hidden" style={{background: '#1b2a32'}}>
                                                        <div className="h-full" style={{width: `${Math.min(ramPercent, 100)}%`, background: '#9b59b6'}}></div>
                                                    </div>
                                                    <span style={{color: '#e9ecef', minWidth: '35px'}}>{ramPercent}%</span>
                                                </div>
                                                <div className="text-[11px] mt-0.5" style={{color: '#728b9a'}}>{formatBytes(vm.mem)} / {formatBytes(vm.maxmem)}</div>
                                            </div>
                                        </div>
                                        {/* Disk */}
                                        {vm.maxdisk && (
                                            <div className="flex items-center gap-2 text-[12px]">
                                                <Icons.HardDrive className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#60b515'}} />
                                                <span style={{color: '#adbbc4', width: '60px'}}>Disk</span>
                                                <span style={{color: '#e9ecef'}}>{formatBytes(vm.maxdisk)}</span>
                                            </div>
                                        )}
                                        {/* Network */}
                                        {vmHwInfo?.net && (
                                            <div className="flex items-center gap-2 text-[12px]">
                                                <Icons.Network className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#efc006'}} />
                                                <span style={{color: '#adbbc4', width: '60px'}}>{t('network') || 'Network'}</span>
                                                <span style={{color: '#e9ecef'}}>{vmHwInfo.net}</span>
                                            </div>
                                        )}
                                        {/* BIOS/Machine */}
                                        {vmHwInfo && (
                                            <div className="flex items-center gap-2 text-[12px]">
                                                <Icons.Settings className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#728b9a'}} />
                                                <span style={{color: '#adbbc4', width: '60px'}}>{t('biosType') || 'BIOS'}</span>
                                                <span style={{color: '#e9ecef'}}>{vmHwInfo.bios === 'ovmf' ? 'UEFI (OVMF)' : 'SeaBIOS'} • {vmHwInfo.machine} • {vmHwInfo.scsihw}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Right: Related Objects + HA */}
                                <div className="space-y-4">
                                    {/* related objects */}
                                    <div style={{border: '1px solid #485764'}}>
                                        <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                            <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('relatedObjects') || 'Related Objects'}</span>
                                        </div>
                                        <table className="corp-property-grid">
                                            <tbody>
                                                <tr><td>{t('node')}</td><td className="flex items-center gap-1.5"><Icons.Server className="w-3 h-3" style={{color: '#49afd9'}} /> {vm.node}</td></tr>
                                                <tr><td>{t('status')}</td><td className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{background: isRunning ? '#60b515' : '#728b9a'}}></span> {isRunning ? t('running') : t('stopped')}</td></tr>
                                                <tr><td>VMID</td><td>{vm.vmid}</td></tr>
                                                <tr><td>{t('uptime')}</td><td>{formatUptime(vm.uptime)}</td></tr>
                                                {vmHwInfo?.net && <tr><td>{t('network') || 'Network'}</td><td>{vmHwInfo.net}</td></tr>}
                                            </tbody>
                                        </table>
                                    </div>

                                    {/* Guest Agent Info (if available) */}
                                    {isQemu && isRunning && guestInfo && (
                                        <div style={{border: '1px solid #485764'}}>
                                            <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                                <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('guestAgentInfo')}</span>
                                            </div>
                                            <table className="corp-property-grid">
                                                <tbody>
                                                    {guestInfo.hostname && <tr><td>{t('hostname')}</td><td>{guestInfo.hostname}</td></tr>}
                                                    {guestInfo.os_pretty_name && <tr><td>{t('osVersion')}</td><td>{guestInfo.os_pretty_name}</td></tr>}
                                                    {guestInfo.kernel_version && <tr><td>{t('kernel')}</td><td>{guestInfo.kernel_version}</td></tr>}
                                                    {guestInfo.ip_addresses && guestInfo.ip_addresses.length > 0 && (
                                                        <tr><td>IP</td><td style={{fontFamily: 'monospace', fontSize: '11px'}}>{guestInfo.ip_addresses.join(', ')}</td></tr>
                                                    )}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}

                                    {/* HA config */}
                                    <div style={{border: '1px solid #485764'}}>
                                        <div className="px-3 py-2 flex items-center justify-between" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                            <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('proxmoxHa') || 'Proxmox HA'}</span>
                                            <button
                                                onClick={toggleProxmoxHa}
                                                disabled={haLoading}
                                                className="text-[11px] px-2 py-0.5 disabled:opacity-50"
                                                style={haEnabled
                                                    ? {color: '#f54f47', border: '1px solid rgba(245, 79, 71, 0.3)'}
                                                    : {color: '#60b515', border: '1px solid rgba(96, 181, 21, 0.3)'}
                                                }
                                            >
                                                {haLoading ? <Icons.RotateCw className="w-3 h-3 animate-spin" /> : haEnabled ? t('disable') : t('haActivate') || 'Enable'}
                                            </button>
                                        </div>
                                        <div className="px-3 py-2 flex items-center gap-2">
                                            <Icons.Shield className="w-4 h-4" style={{color: haEnabled ? '#60b515' : '#728b9a'}} />
                                            <div>
                                                <div className="text-[12px]" style={{color: '#e9ecef'}}>{haEnabled ? t('active') : t('disabled')}</div>
                                                {haEnabled && <div className="text-[11px]" style={{color: '#728b9a'}}>Max Restart: 3 | Max Relocate: 3</div>}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // Proxmox Native HA Section for Settings
        function ProxmoxHaSection({ clusterId }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [resources, setResources] = useState([]);
            const [loading, setLoading] = useState(true);

            // Local authFetch helper
            const authFetch = async (url, options = {}) => {
                try {
                    return await fetch(url, {
                        ...options,
                        credentials: 'include',
                        headers: { ...options.headers, ...getAuthHeaders() }
                    });
                } catch (err) {
                    console.error('Auth fetch error:', err);
                    return null;
                }
            };

            useEffect(() => {
                const fetchData = async () => {
                    try {
                        const response = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`);
                        if(response && response.ok) {
                            setResources(await response.json());
                        }
                    } catch (error) {
                        console.error('fetching HA data:', error);
                    } finally {
                        setLoading(false);
                    }
                };
                fetchData();
            }, [clusterId]);

            const removeFromHa = async (sid) => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources/${sid}`, {
                        method: 'DELETE'
                    });
                    if(res && res.ok) {
                        setResources(resources.filter(r => r.sid !== sid));
                    }
                } catch(e) {
                    console.error('removing from HA:', e);
                }
            };

            if(loading) {
                return (
                    <div className="flex items-center gap-2 text-gray-500 text-sm">
                        <Icons.RotateCw />
                        {t('loading')}
                    </div>
                );
            }

            return (
                <div className="space-y-3">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-400">{resources.length} {t('vmsWithHa')}</span>
                    </div>
                    
                    {resources.length === 0 ? (
                        <div className="text-xs text-gray-600 p-3 bg-proxmox-dark rounded-lg">
                            {t('noVmsWithHa')}
                        </div>
                    ) : (
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                            {resources.map(resource => {
                                const [type, vmid] = (resource.sid || '').split(':');
                                return (
                                    <div key={resource.sid} className="flex items-center justify-between p-2 bg-proxmox-dark rounded-lg text-sm">
                                        <div className="flex items-center gap-2">
                                            <span className={type === 'vm' ? 'text-blue-400' : 'text-purple-400'}>
                                                {type === 'vm' ? 'VM' : 'CT'} {vmid}
                                            </span>
                                            <span className="text-xs text-gray-500">
                                                Max Restart: {resource.max_restart || 3}
                                            </span>
                                        </div>
                                        <button
                                            onClick={() => removeFromHa(resource.sid)}
                                            className="p-1 rounded hover:bg-red-500/20 text-gray-500 hover:text-red-400"
                                            title={t('removeFromHa')}
                                        >
                                            <Icons.X />
                                        </button>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            );
        }

        // Migrate Modal Component
        // LW: This thing was a nightmare to debug. ISO detection finally works now!
        // See also: CrossClusterMigrateModal below (similar logic)
        function MigrateModal({ vm, nodes, clusterId, onMigrate, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [targetNode, setTargetNode] = useState('');
            const [targetStorage, setTargetStorage] = useState('');
            const [online, setOnline] = useState(true);
            const [withLocalDisks, setWithLocalDisks] = useState(false);
            const [forceConntrack, setForceConntrack] = useState(false);
            const [loading, setLoading] = useState(false);
            const [storages, setStorages] = useState([]);
            const [loadingStorages, setLoadingStorages] = useState(false);
            const [hasLocalDisks, setHasLocalDisks] = useState(false);
            const [hasCdDvd, setHasCdDvd] = useState(false);
            const [detectedIsos, setDetectedIsos] = useState([]);
            const [bootOrderIssues, setBootOrderIssues] = useState([]);

            const availableNodes = nodes.filter(n => n !== vm.node);
            const isContainer = vm.type === 'lxc';

            // check if VM has local disks, CD/DVD, and boot order issues on mount
            // NS: Now listens to SSE events for live updates
            useEffect(() => {
                if(!vm || !vm.node || !clusterId) return;
                
                const processVmConfig = (data) => {
                    const config = data.raw || data;
                    
                    // Check all disk entries for local storage
                    const diskKeys = Object.keys(config).filter(k => 
                        k.match(/^(scsi|sata|virtio|ide|mp|rootfs)\d*$/)
                    );
                    const hasLocal = diskKeys.some(key => {
                        const diskValue = config[key];
                        if(typeof diskValue === 'string') {
                            return diskValue.includes('shared=0') || 
                                   diskValue.startsWith('local:') ||
                                   diskValue.startsWith('local-lvm:') ||
                                   diskValue.startsWith('local-zfs:');
                        }
                        return false;
                    });
                    setHasLocalDisks(hasLocal);
                    if(hasLocal) {
                        setWithLocalDisks(true);
                    }
                    
                    // Check for CD/DVD drives with ISO mounted
                    const cdDvdKeys = Object.keys(config).filter(k => 
                        k.match(/^(ide|sata|scsi)\d*$/)
                    );
                    const foundIsos = [];
                    cdDvdKeys.forEach(key => {
                        const value = config[key];
                        if(typeof value === 'string' && value.includes('media=cdrom')) {
                            const isoMatch = value.match(/^([^,]+)/);
                            if(isoMatch && isoMatch[1] && !isoMatch[1].includes('none')) {
                                const isoPath = isoMatch[1];
                                const isLocalStorage = isoPath.startsWith('local:') || 
                                    isoPath.startsWith('local-lvm:') ||
                                    isoPath.startsWith('local-zfs:');
                                foundIsos.push({ device: key, iso: isoPath, isLocal: isLocalStorage });
                            }
                        }
                    });
                    setHasCdDvd(foundIsos.length > 0);
                    setDetectedIsos(foundIsos);
                    
                    // Check boot order for non-existent disks
                    const bootOrder = config.boot || '';
                    const bootDevices = bootOrder.includes('order=') 
                        ? bootOrder.split('order=')[1].split(';')[0].split(',')
                        : [];
                    const issues = [];
                    bootDevices.forEach(device => {
                        if(device && !config[device] && device !== 'net0') {
                            issues.push(device);
                        }
                    });
                    setBootOrderIssues(issues);
                };
                
                const checkVmConfig = async () => {
                    try {
                        const response = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                            credentials: 'include',
                            headers: getAuthHeaders()
                        });
                        if(response && response.ok) {
                            const data = await response.json();
                            processVmConfig(data);
                        }
                    } catch (err) {
                        console.error('checking VM config:', err);
                    }
                };
                
                checkVmConfig();
                
                // NS: Listen to SSE vm_config events for live updates
                const handleVmConfigUpdate = (event) => {
                    const { vmid: eventVmid, vm_type, config: newConfig, cluster_id } = event.detail;
                    if (eventVmid === vm.vmid && vm_type === vm.type && cluster_id === clusterId) {
                        console.log('SSE: Updating MigrateModal config for', vm.vmid);
                        processVmConfig(newConfig);
                    }
                };
                
                window.addEventListener('pegaprox-vm-config', handleVmConfigUpdate);
                return () => window.removeEventListener('pegaprox-vm-config', handleVmConfigUpdate);
            }, [vm, clusterId]);

            // Fetch storages when target node changes
            useEffect(() => {
                if(targetNode) {
                    fetchStorages(targetNode);
                }else{
                    setStorages([]);
                    setTargetStorage('');
                }
            }, [targetNode]);

            const fetchStorages = async (node) => {
                setLoadingStorages(true);
                try {
                    const response = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/storage`, { credentials: 'include', headers: getAuthHeaders()
                    });
                    if(response && response.ok) {
                        const data = await response.json();
                        // Filter storages that can hold VM/CT images
                        const validStorages = data.filter(s => 
                            s.content && (s.content.includes('images') || s.content.includes('rootdir'))
                        );
                        setStorages(validStorages);
                    }
                } catch (err) {
                    console.error('fetching storages:', err);
                }
                setLoadingStorages(false);
            };

            const handleMigrate = async () => {
                if(!targetNode) return;
                setLoading(true);
                
                const options = {
                    online,
                    targetStorage: targetStorage || null,
                    withLocalDisks,
                    forceConntrack: isContainer ? forceConntrack : null
                };
                
                await onMigrate(vm, targetNode, online, options);
                setLoading(false);
                onClose();
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('migrateVm')}</h3>
                        <div className="space-y-4">
                            <div className="p-3 bg-proxmox-dark rounded-lg">
                                <div className="flex items-center gap-3">
                                    {vm.type === 'qemu' ? <Icons.VM /> : <Icons.Container />}
                                    <div>
                                        <div className="font-medium text-white">{vm.name || `VM ${vm.vmid}`}</div>
                                        <div className="text-xs text-gray-400">ID {vm.vmid} {t('on')} {vm.node}</div>
                                    </div>
                                </div>
                            </div>
                            
                            {/* Migration Warnings */}
                            {(hasCdDvd || bootOrderIssues.length > 0) && (
                                <div className="space-y-2">
                                    {hasCdDvd && (
                                        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                            <div className="flex items-start gap-2">
                                                <span className="text-red-400 text-lg">💿</span>
                                                <div className="flex-1">
                                                    <p className="text-red-400 font-medium text-sm">{t('isoMounted') || 'ISO/CD-ROM Mounted'}</p>
                                                    <p className="text-red-300/70 text-xs mt-1">
                                                        {t('isoMigrationWarning') || 'Migration may fail if the ISO is not available on the target node. Eject the CD/DVD or ensure the ISO exists on shared storage.'}
                                                    </p>
                                                    {detectedIsos && detectedIsos.length > 0 && (
                                                        <div className="mt-2 space-y-1">
                                                            {detectedIsos.map((iso, idx) => (
                                                                <div key={idx} className="flex items-center gap-2 text-xs flex-wrap">
                                                                    <span className="text-gray-400">{iso.device}:</span>
                                                                    <code className="text-red-300 bg-red-500/10 px-1 rounded break-all">{iso.iso}</code>
                                                                    {iso.isLocal && (
                                                                        <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px]">
                                                                            {t('localStorage') || 'Local'}
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    {bootOrderIssues.length > 0 && (
                                        <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-start gap-2">
                                            <span className="text-yellow-400 text-lg">⚠️</span>
                                            <div>
                                                <p className="text-yellow-400 font-medium text-sm">{t('bootOrderIssue') || 'Boot Order Issue'}</p>
                                                <p className="text-yellow-300/70 text-xs">
                                                    {t('bootOrderWarning') || 'Boot order references non-existent disks'}: <code className="bg-yellow-500/10 px-1 rounded">{bootOrderIssues.join(', ')}</code>
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                            
                            {/* Target Node */}
                            <div>
                                <label className="block text-sm text-gray-400 mb-2">{t('targetNode')}</label>
                                <select
                                    value={targetNode}
                                    onChange={(e) => setTargetNode(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                >
                                    <option value="">{t('selectNode')}...</option>
                                    {availableNodes.map(node => (
                                        <option key={node} value={node}>{node}</option>
                                    ))}
                                </select>
                            </div>
                            
                            {/* Target Storage */}
                            <div>
                                <label className="block text-sm text-gray-400 mb-2">{t('targetStorage')}</label>
                                <select
                                    value={targetStorage}
                                    onChange={(e) => setTargetStorage(e.target.value)}
                                    disabled={!targetNode || loadingStorages}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white disabled:opacity-50"
                                >
                                    <option value="">{t('sameAsSource')}</option>
                                    {storages.map(storage => (
                                        <option key={storage.storage} value={storage.storage}>
                                            {storage.storage} ({storage.type}) - {Math.round((storage.avail || 0) / 1073741824)} GB {t('free')}
                                        </option>
                                    ))}
                                </select>
                                {loadingStorages && (
                                    <p className="text-xs text-gray-500 mt-1">{t('loadingStorages')}...</p>
                                )}
                            </div>
                            
                            {/* Migration Options */}
                            <div className="space-y-3 pt-2 border-t border-proxmox-border">
                                <label className="flex items-center gap-3 text-sm text-gray-300 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={online}
                                        onChange={(e) => setOnline(e.target.checked)}
                                        className="w-4 h-4 rounded"
                                    />
                                    <div>
                                        <span>{t('liveMigration')}</span>
                                        {isContainer && (
                                            <p className="text-xs text-yellow-500 mt-0.5">⚠️ {t('containerNoLiveMigration')}</p>
                                        )}
                                    </div>
                                </label>
                                
                                {/* Local Disks Warning */}
                                {hasLocalDisks && (
                                    <div className="p-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                        <p className="text-xs text-yellow-400">
                                            ⚠️ {t('localDisksDetected') || 'This VM has local disks. Migration requires copying disk data.'}
                                        </p>
                                    </div>
                                )}
                                
                                <label className="flex items-center gap-3 text-sm text-gray-300 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={withLocalDisks}
                                        onChange={(e) => setWithLocalDisks(e.target.checked)}
                                        className="w-4 h-4 rounded"
                                    />
                                    <div>
                                        <span>{t('withLocalDisks')}</span>
                                        <p className="text-xs text-gray-500">{t('withLocalDisksDesc')}</p>
                                        {hasLocalDisks && <p className="text-xs text-yellow-400">{t('requiredForThisVm') || 'Required for this VM'}</p>}
                                    </div>
                                </label>
                                
                                {isContainer && (
                                    <label className="flex items-center gap-3 text-sm text-gray-300 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={forceConntrack}
                                            onChange={(e) => setForceConntrack(e.target.checked)}
                                            className="w-4 h-4 rounded"
                                        />
                                        <div>
                                            <span>{t('forceConntrack')}</span>
                                            <p className="text-xs text-gray-500">{t('forceConntrackDesc')}</p>
                                        </div>
                                    </label>
                                )}
                            </div>
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button
                                onClick={handleMigrate}
                                disabled={!targetNode || loading}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700 disabled:opacity-50"
                            >
                                {loading && <Icons.RotateCw />}
                                {t('migrate')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Bulk Migrate Modal Component
        // NS: For evacuating nodes before maintenance
        // Migrations run sequentially to avoid overloading the network
        function BulkMigrateModal({ vms, nodes, clusterId, onMigrate, onClose }) {
            const { t } = useTranslation();  // MK: Fix missing translation hook
            const [targetNode, setTargetNode] = useState('');
            const [online, setOnline] = useState(true);
            const [loading, setLoading] = useState(false);

            // Get all unique current nodes
            const currentNodes = [...new Set(vms.map(v => v.node))];
            const availableNodes = nodes.filter(n => !currentNodes.includes(n) || currentNodes.length > 1);

            const handleMigrate = async () => {
                if(!targetNode) return;
                setLoading(true);
                await onMigrate(vms, targetNode, online);
                setLoading(false);
                onClose();
            };

            return(
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
                    <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('bulkMigration')}</h3>
                        <div className="space-y-4">
                            <div className="p-3 bg-proxmox-dark rounded-lg max-h-48 overflow-y-auto">
                                <div className="text-sm text-gray-400 mb-2">{vms.length} {t('vmsSelected')}:</div>
                                <div className="space-y-1">
                                    {vms.map(vm => (
                                        <div key={vm.vmid} className="flex items-center gap-2 text-sm">
                                            <span className="text-proxmox-orange font-mono">{vm.vmid}</span>
                                            <span className="text-white">{vm.name || '-'}</span>
                                            <span className="text-gray-500">({vm.node})</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-2">{t('targetNode')}</label>
                                <select
                                    value={targetNode}
                                    onChange={(e) => setTargetNode(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                >
                                    <option value="">{t('selectNode')}</option>
                                    {availableNodes.map(node => (
                                        <option key={node} value={node}>{node}</option>
                                    ))}
                                </select>
                            </div>
                            <label className="flex items-center gap-3 text-sm text-gray-300">
                                <input
                                    type="checkbox"
                                    checked={online}
                                    onChange={(e) => setOnline(e.target.checked)}
                                    className="w-4 h-4 rounded"
                                />
                                {t('liveMigration')}
                            </label>
                            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm text-yellow-400">
                                {t('bulkMigrationNote') || 'Migrations will be performed sequentially. This may take some time.'}
                            </div>
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button
                                onClick={handleMigrate}
                                disabled={!targetNode || loading}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700 disabled:opacity-50"
                            >
                                {loading && <Icons.RotateCw />}
                                {vms.length} {t('migrateVms')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Cross-Cluster Migration Modal
        // NS: The big one - SSH tunnel based migration between clusters
        // Uses same ISO detection logic as MigrateModal (copy-paste, I know...)
        function CrossClusterMigrateModal({ vm, sourceCluster, clusters, onMigrate, onClose }) {
            const { getAuthHeaders } = useAuth();
            const { t } = useTranslation();
            const [targetCluster, setTargetCluster] = useState('');
            const [targetNode, setTargetNode] = useState('');
            const [targetStorage, setTargetStorage] = useState('');
            const [targetBridge, setTargetBridge] = useState('vmbr0');
            const [targetVmid, setTargetVmid] = useState('');
            const [online, setOnline] = useState(true);
            const [forceOnline, setForceOnline] = useState(false);  // Force online migration for large disks
            const [deleteSource, setDeleteSource] = useState(true);
            const [loading, setLoading] = useState(false);
            const [targetNodes, setTargetNodes] = useState([]);
            const [targetStorages, setTargetStorages] = useState([]);
            const [targetBridges, setTargetBridges] = useState([]);
            const [loadingTarget, setLoadingTarget] = useState(false);
            const [hasCdDvd, setHasCdDvd] = useState(false);
            const [detectedIsos, setDetectedIsos] = useState([]);
            const [bootOrderIssues, setBootOrderIssues] = useState([]);
            const [estimatedDiskGb, setEstimatedDiskGb] = useState(0);  // Track disk size for warnings

            const availableClusters = clusters.filter(c => c.id !== sourceCluster.id);
            const isQemu = vm.type === 'qemu';
            
            // Local authFetch helper
            const authFetch = async (url, options = {}) => {
                try {
                    const response = await fetch(url, {
                        ...options,
                        credentials: 'include',
                        headers: {
                            ...options.headers,
                            ...getAuthHeaders()
                        }
                    });
                    return response;
                } catch (err) {
                    console.error('Auth fetch error:', err);
                    return null;
                }
            };
            
            // Check for CD/DVD and boot order issues
            // NS: Now uses SSE events for live updates
            useEffect(() => {
                const processVmConfig = (config) => {
                    // Check for CD/DVD drives with ISO mounted
                    const cdDvdKeys = Object.keys(config).filter(k => 
                        k.match(/^(ide|sata|scsi)\d*$/)
                    );
                    const foundIsos = [];
                    cdDvdKeys.forEach(key => {
                        const value = config[key];
                        if(typeof value === 'string' && value.includes('media=cdrom')) {
                            const isoMatch = value.match(/^([^,]+)/);
                            if(isoMatch && isoMatch[1] && !isoMatch[1].includes('none')) {
                                const isoPath = isoMatch[1];
                                const isLocal = isoPath.startsWith('local:') || 
                                               isoPath.startsWith('local-lvm:') ||
                                               isoPath.startsWith('local-zfs:');
                                foundIsos.push({ device: key, iso: isoPath, isLocal });
                            }
                        }
                    });
                    setHasCdDvd(foundIsos.length > 0);
                    setDetectedIsos(foundIsos);
                    
                    // Check boot order for non-existent disks
                    const bootOrder = config.boot || '';
                    const bootDevices = bootOrder.includes('order=') 
                        ? bootOrder.split('order=')[1].split(';')[0].split(',')
                        : [];
                    const issues = [];
                    bootDevices.forEach(device => {
                        if(device && !config[device] && device !== 'net0') {
                            issues.push(device);
                        }
                    });
                    setBootOrderIssues(issues);
                    
                    // Calculate total disk size for large VM warning
                    let totalDiskGb = 0;
                    Object.keys(config).forEach(key => {
                        if(key.match(/^(scsi|virtio|sata|ide)\d+$/) && typeof config[key] === 'string') {
                            const sizeMatch = config[key].match(/size=(\d+)([GMT])/);
                            if(sizeMatch) {
                                const sizeVal = parseInt(sizeMatch[1]);
                                const sizeUnit = sizeMatch[2];
                                if(sizeUnit === 'G') totalDiskGb += sizeVal;
                                else if(sizeUnit === 'T') totalDiskGb += sizeVal * 1024;
                                else if(sizeUnit === 'M') totalDiskGb += sizeVal / 1024;
                            }
                        }
                    });
                    setEstimatedDiskGb(totalDiskGb);
                };
                
                const checkVmConfig = async () => {
                    try {
                        const response = await authFetch(`${API_URL}/clusters/${sourceCluster.id}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`);
                        if(response && response.ok) {
                            const data = await response.json();
                            const config = data.raw || data;
                            processVmConfig(config);
                        }
                    } catch (err) {
                        console.error('checking VM config:', err);
                    }
                };
                checkVmConfig();
                
                // NS: Listen to SSE vm_config events for live updates
                const handleVmConfigUpdate = (event) => {
                    const { vmid: eventVmid, vm_type, config: newConfig, cluster_id } = event.detail;
                    if (eventVmid === vm.vmid && vm_type === vm.type && cluster_id === sourceCluster.id) {
                        console.log('SSE: Updating CrossClusterMigrateModal for', vm.vmid);
                        const config = newConfig.raw || newConfig;
                        processVmConfig(config);
                    }
                };
                
                window.addEventListener('pegaprox-vm-config', handleVmConfigUpdate);
                return () => window.removeEventListener('pegaprox-vm-config', handleVmConfigUpdate);
            }, [vm, sourceCluster.id]);

            // Load target cluster nodes when cluster selected
            useEffect(() => {
                if(targetCluster) {
                    loadTargetNodes();
                }else{
                    setTargetNodes([]);
                    setTargetNode('');
                }
            }, [targetCluster]);

            // Load target node resources when node selected
            useEffect(() => {
                if(targetCluster && targetNode) {
                    loadTargetResources();
                }else{
                    setTargetStorages([]);
                    setTargetBridges([]);
                }
            }, [targetNode]);

            const loadTargetNodes = async () => {
                setLoadingTarget(true);
                try {
                    const nodesRes = await authFetch(`${API_URL}/clusters/${targetCluster}/nodes`);
                    if(nodesRes && nodesRes.ok) {
                        const nodes = await nodesRes.json();
                        setTargetNodes(nodes);
                        // Auto-select first online node
                        const onlineNode = nodes.find(n => n.status === 'online');
                        if(onlineNode) {
                            setTargetNode(onlineNode.node);
                        }
                    }
                } catch (error) {
                    console.error('to load target nodes:', error);
                }
                setLoadingTarget(false);
            };

            const loadTargetResources = async () => {
                setLoadingTarget(true);
                try {
                    // Get storage list for selected node
                    const storageRes = await authFetch(`${API_URL}/clusters/${targetCluster}/nodes/${targetNode}/storage`);
                    if(storageRes && storageRes.ok) {
                        setTargetStorages(await storageRes.json());
                    }
                    
                    // Get network list for selected node (including SDN VNets)
                    const networkRes = await authFetch(`${API_URL}/clusters/${targetCluster}/nodes/${targetNode}/networks`);
                    if(networkRes && networkRes.ok) {
                        const networks = await networkRes.json();
                        // Include local bridges AND SDN VNets
                        setTargetBridges(networks.filter(n => n.type === 'bridge' || n.type === 'OVSBridge' || n.source === 'sdn'));
                    }
                } catch (error) {
                    console.error('to load target resources:', error);
                }
                setLoadingTarget(false);
            };

            const handleMigrate = async () => {
                if (!targetCluster || !targetNode || !targetStorage || !targetBridge) return;
                setLoading(true);
                await onMigrate({
                    source_cluster: sourceCluster.id,
                    target_cluster: targetCluster,
                    vmid: vm.vmid,
                    vm_type: vm.type,
                    source_node: vm.node,
                    target_node: targetNode,
                    target_storage: targetStorage,
                    target_bridge: targetBridge,
                    target_vmid: targetVmid ? parseInt(targetVmid) : null,
                    online,
                    force_online: forceOnline,
                    delete_source: deleteSource
                });
                setLoading(false);
                onClose();
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 overflow-y-auto">
                    <div className="w-full max-w-xl bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden animate-scale-in my-8">
                        <div className="px-6 py-4 border-b border-proxmox-border bg-gradient-to-r from-cyan-500/10 to-blue-500/10">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-cyan-500/20">
                                        <Icons.Globe />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold text-white">{t('crossClusterMigration')}</h3>
                                        <p className="text-sm text-gray-400">{t('crossClusterMigrateDesc')}</p>
                                    </div>
                                </div>
                                <button onClick={onClose} className="p-2 hover:bg-proxmox-border rounded-lg text-gray-400 hover:text-white">
                                    <Icons.X />
                                </button>
                            </div>
                        </div>
                        
                        <div className="p-6 space-y-4 max-h-[60vh] overflow-y-auto">
                            {/* Source VM Info */}
                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                <div className="text-xs text-gray-500 mb-2">{t('sourceVm')}</div>
                                <div className="flex items-center gap-3">
                                    <div className={`p-2 rounded-lg ${isQemu ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                        {isQemu ? <Icons.VM /> : <Icons.Container />}
                                    </div>
                                    <div>
                                        <div className="font-medium text-white">{vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`}</div>
                                        <div className="text-xs text-gray-400">
                                            ID {vm.vmid} · {vm.node} · {sourceCluster.name}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            {/* Migration Warnings */}
                            {(hasCdDvd || bootOrderIssues.length > 0) && (
                                <div className="space-y-2">
                                    {hasCdDvd && (
                                        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                                            <div className="flex items-start gap-2">
                                                <span className="text-red-400 text-lg">💿</span>
                                                <div className="flex-1">
                                                    <p className="text-red-400 font-medium text-sm">{t('isoMounted') || 'ISO/CD-ROM Mounted'}</p>
                                                    <p className="text-red-300/70 text-xs mt-1">
                                                        {t('isoMigrationWarning') || 'Migration may fail if the ISO is not available on the target node. Eject the CD/DVD or ensure the ISO exists on shared storage.'}
                                                    </p>
                                                    {detectedIsos && detectedIsos.length > 0 && (
                                                        <div className="mt-2 space-y-1">
                                                            {detectedIsos.map((iso, idx) => (
                                                                <div key={idx} className="flex items-center gap-2 text-xs flex-wrap">
                                                                    <span className="text-gray-400">{iso.device}:</span>
                                                                    <code className="text-red-300 bg-red-500/10 px-1 rounded break-all">{iso.iso}</code>
                                                                    {iso.isLocal && (
                                                                        <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px]">
                                                                            {t('localStorage') || 'Local'}
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    {bootOrderIssues.length > 0 && (
                                        <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-start gap-2">
                                            <span className="text-yellow-400 text-lg">⚠️</span>
                                            <div>
                                                <p className="text-yellow-400 font-medium text-sm">{t('bootOrderIssue') || 'Boot Order Issue'}</p>
                                                <p className="text-yellow-300/70 text-xs">
                                                    {t('bootOrderWarning') || 'Boot order references non-existent disks'}: <code className="bg-yellow-500/10 px-1 rounded">{bootOrderIssues.join(', ')}</code>
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Target Cluster */}
                            <div>
                                <label className="block text-sm text-gray-400 mb-2">{t('targetCluster')}</label>
                                <select
                                    value={targetCluster}
                                    onChange={(e) => setTargetCluster(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                >
                                    <option value="">{t('selectCluster')}</option>
                                    {availableClusters.map(c => (
                                        <option key={c.id} value={c.id}>{c.name}</option>
                                    ))}
                                </select>
                            </div>

                            {targetCluster && (
                                <>
                                    {loadingTarget && targetNodes.length === 0 ? (
                                        <div className="flex items-center justify-center py-4 text-gray-400">
                                            <Icons.RotateCw />
                                            <span className="ml-2">{t('loadingNodes')}</span>
                                        </div>
                                    ) : (
                                        <>
                                            {/* Target Node */}
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-2">{t('targetNode')}</label>
                                                <select
                                                    value={targetNode}
                                                    onChange={(e) => setTargetNode(e.target.value)}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                >
                                                    <option value="">{t('selectNode')}...</option>
                                                    {targetNodes.map(n => (
                                                        <option key={n.node} value={n.node}>
                                                            {n.node} ({n.status}) - CPU: {n.cpu_percent?.toFixed(1)}% RAM: {n.mem_percent?.toFixed(1)}%
                                                        </option>
                                                    ))}
                                                </select>
                                            </div>

                                            {targetNode && (
                                                <>
                                                    {loadingTarget ? (
                                                        <div className="flex items-center justify-center py-4 text-gray-400">
                                                            <Icons.RotateCw />
                                                            <span className="ml-2">{t('loadingStorageNetwork')}</span>
                                                        </div>
                                                    ) : (
                                                        <>
                                                            {/* Target Storage */}
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('targetStorage')}</label>
                                                                <select
                                                                    value={targetStorage}
                                                                    onChange={(e) => setTargetStorage(e.target.value)}
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    <option value="">{t('selectStorage')}</option>
                                                                    {targetStorages.map(s => (
                                                                        <option key={s.storage} value={s.storage}>
                                                                            {s.storage} ({s.type})
                                                                        </option>
                                                                    ))}
                                                                </select>
                                                            </div>

                                                            {/* Target Bridge */}
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('targetBridge')} / VNet</label>
                                                                <select
                                                                    value={targetBridge}
                                                                    onChange={(e) => setTargetBridge(e.target.value)}
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    {targetBridges.length === 0 && <option value="vmbr0">vmbr0</option>}
                                                                    {/* Local bridges */}
                                                                    {targetBridges.filter(b => b.source !== 'sdn').length > 0 && (
                                                                        <optgroup label="Local Bridges">
                                                                            {targetBridges.filter(b => b.source !== 'sdn').map(b => (
                                                                                <option key={b.iface} value={b.iface}>{b.iface}{b.comments ? ` - ${b.comments}` : ''}</option>
                                                                            ))}
                                                                        </optgroup>
                                                                    )}
                                                                    {/* SDN VNets */}
                                                                    {targetBridges.filter(b => b.source === 'sdn').length > 0 && (
                                                                        <optgroup label="SDN VNets">
                                                                            {targetBridges.filter(b => b.source === 'sdn').map(b => (
                                                                                <option key={b.iface} value={b.iface}>{b.iface} - {b.zone || 'SDN'}{b.alias ? ` (${b.alias})` : ''}</option>
                                                                            ))}
                                                                        </optgroup>
                                                                    )}
                                                                </select>
                                                            </div>

                                                            {/* Target VMID (optional) */}
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('newVmid')}</label>
                                                                <input
                                                                    type="number"
                                                                    value={targetVmid}
                                                                    onChange={(e) => setTargetVmid(e.target.value)}
                                                                    placeholder={`${t('sameIdPlaceholder')} (${vm.vmid})`}
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                            </div>

                                                            {/* Options */}
                                                            <div className="space-y-2">
                                                                {isQemu && (
                                                                    <label className="flex items-center gap-3 text-sm text-gray-300">
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={online}
                                                                            onChange={(e) => setOnline(e.target.checked)}
                                                                            className="w-4 h-4 rounded"
                                                                        />
                                                                        {t('liveMigrationOption')}
                                                                    </label>
                                                                )}
                                                                <label className="flex items-center gap-3 text-sm text-gray-300">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={deleteSource}
                                                                        onChange={(e) => setDeleteSource(e.target.checked)}
                                                                        className="w-4 h-4 rounded"
                                                                    />
                                                                    {t('deleteSourceAfter')}
                                                                </label>
                                                            </div>
                                                            
                                                            {/* Large Disk Warning */}
                                                            {estimatedDiskGb > 100 && online && isQemu && (
                                                                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg space-y-2">
                                                                    <div className="text-sm text-yellow-400">
                                                                        ⚠️ <strong>{t('largeDiskWarning') || 'Large Disk Detected'}</strong> ({estimatedDiskGb.toFixed(0)} GB)
                                                                    </div>
                                                                    <div className="text-xs text-yellow-400/80">
                                                                        {t('largeDiskExplanation') || 'Live migration for disks >100GB may fail with "401 Unauthorized" due to Proxmox WebSocket ticket timeout. The server will automatically use offline migration unless forced.'}
                                                                    </div>
                                                                    <label className="flex items-center gap-3 text-sm text-yellow-300 mt-2">
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={forceOnline}
                                                                            onChange={(e) => setForceOnline(e.target.checked)}
                                                                            className="w-4 h-4 rounded"
                                                                        />
                                                                        {t('forceOnlineMigration') || 'Force online migration anyway (may fail)'}
                                                                    </label>
                                                                </div>
                                                            )}
                                                        </>
                                                    )}
                                                </>
                                            )}
                                        </>
                                    )}
                                </>
                            )}

                            <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-sm text-green-400">
                                ✓ <strong>{t('autoTokenInfo').split('.')[0]}.</strong> {t('autoTokenInfo').split('.').slice(1).join('.')}
                            </div>
                            
                            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm text-blue-400">
                                💡 {t('clusterReachableInfo')}
                            </div>
                        </div>

                        <div className="flex justify-end gap-3 px-6 py-4 border-t border-proxmox-border bg-proxmox-dark">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                {t('cancel')}
                            </button>
                            <button
                                onClick={handleMigrate}
                                disabled={!targetCluster || !targetNode || !targetStorage || loading}
                                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 rounded-lg text-white hover:bg-cyan-700 disabled:opacity-50"
                            >
                                {loading && <Icons.RotateCw />}
                                <Icons.Globe />
                                {t('crossClusterMigrate')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Migration History Component
        // LW: Limited to 10 items by default (GitHub Issue - list was too long)
        function MigrationHistory({ logs, maxItems = 10 }) {
            const { t } = useTranslation();
            
            if (!logs || logs.length === 0) {
                return (
                    <div className="text-center py-8 text-gray-500">
                        <Icons.Activity />
                        <p className="mt-2">{t('noMigrationsYet')}</p>
                    </div>
                );
            }
            
            // LW: Only show last 10 migrations (newest first)
            const reversedLogs = logs.slice().reverse();
            const displayLogs = reversedLogs.slice(0, maxItems);
            const hiddenCount = reversedLogs.length - maxItems;

            return (
                <div className="space-y-4">
                    <div className="relative space-y-4">
                        <div className="timeline-line" />
                        {displayLogs.map((log, idx) => (
                            <div 
                                key={idx} 
                                className="relative pl-12 animate-slide-in"
                                style={{ animationDelay: `${idx * 50}ms` }}
                            >
                                <div className={`absolute left-2 w-6 h-6 rounded-full flex items-center justify-center ${
                                    log.success 
                                        ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
                                        : 'bg-red-500/20 text-red-400 border border-red-500/30'
                                }`}>
                                    {log.success ? <Icons.Check /> : <Icons.X />}
                                </div>
                                <div className="bg-proxmox-dark border border-proxmox-border rounded-lg p-4">
                                    <div className="flex items-center justify-between mb-2">
                                        <span className="font-medium text-white">{log.vm}</span>
                                        {log.dry_run && (
                                            <span className="text-xs bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded border border-yellow-500/20">
                                                Dry Run
                                            </span>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2 text-sm text-gray-400">
                                        <span className="font-mono">{log.from_node}</span>
                                        <Icons.ArrowRight />
                                        <span className="font-mono">{log.to_node}</span>
                                    </div>
                                    <div className="mt-2 text-xs text-gray-500">
                                        {new Date(log.timestamp).toLocaleString('de-DE')}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                    
                    {/* LW: Show count of hidden older migrations */}
                    {hiddenCount > 0 && (
                        <div className="text-center py-2 text-xs text-gray-500">
                            + {hiddenCount} {t('olderMigrations') || 'older migrations'}
                        </div>
                    )}
                </div>
            );
        }

        // MK: Group Overview - drills into a single cluster group
        // basically a scoped-down version of AllClustersOverview w/ LB stuff
        function GroupOverview({ group, clusters, allMetrics, clusterGroups = [], topGuests = [], onSelectCluster, onSelectVm, onOpenSettings, authFetch, API_URL }) {
            const { t } = useTranslation();
            const { isCorporate } = useLayout();
            const [sortBy, setSortBy] = useState('name');
            const [sortDir, setSortDir] = useState('asc');
            const [cpuHistory, setCpuHistory] = useState({});
            const [ramHistory, setRamHistory] = useState({});
            const [lbHistory, setLbHistory] = useState([]);
            const [groupStatus, setGroupStatus] = useState(null);

            // NS: only clusters that belong to this group
            const groupClusters = clusters.filter(c => c.group_id === group.id);

            // sparkline history - same as AllClustersOverview
            useEffect(() => {
                groupClusters.forEach(cluster => {
                    const status = allMetrics[cluster.id]?.data || {};
                    const cpu = status.resources?.cpu?.percent || 0;
                    const ram = status.resources?.memory?.percent || 0;

                    setCpuHistory(prev => ({
                        ...prev,
                        [cluster.id]: [...(prev[cluster.id] || []).slice(-9), cpu]
                    }));
                    setRamHistory(prev => ({
                        ...prev,
                        [cluster.id]: [...(prev[cluster.id] || []).slice(-9), ram]
                    }));
                });
            }, [allMetrics]);

            // LW: fetch LB history + group status
            useEffect(() => {
                if (!group?.id) return;
                (async () => {
                    try {
                        const r = await authFetch(`${API_URL}/cluster-groups/${group.id}/lb-history`);
                        if (r?.ok) {
                            const d = await r.json();
                            setLbHistory(Array.isArray(d) ? d : []);
                        }
                    } catch (err) {
                        console.error('Failed to fetch LB history:', err);
                    }
                })();
                (async () => {
                    try {
                        const r = await authFetch(`${API_URL}/cluster-groups/${group.id}/status`);
                        if (r?.ok) {
                            const d = await r.json();
                            setGroupStatus(d);
                        }
                    } catch (err) {
                        console.error('Failed to fetch group status:', err);
                    }
                })();
            }, [group?.id]);

            // stats per cluster - same calc as AllClustersOverview
            const clusterStats = groupClusters.map(cluster => {
                const status = allMetrics[cluster.id]?.data || {};
                const lastUpdate = allMetrics[cluster.id]?.lastUpdate;
                const nodes = status.nodes || {};
                const guests = status.guests || {};
                const resources = status.resources || {};

                const nodeCount = nodes.total || 0;
                const onlineNodes = nodes.online || 0;
                const offlineNodes = nodes.offline || 0;
                const avgCpu = resources.cpu?.percent || 0;
                const avgMem = resources.memory?.percent || 0;
                const avgStorage = resources.storage?.percent || 0;

                const vmsRunning = (guests.vms?.running || 0) + (guests.containers?.running || 0);
                const vmsStopped = (guests.vms?.stopped || 0) + (guests.containers?.stopped || 0);
                const totalVms = vmsRunning + vmsStopped;

                // health score - weighted average of metrics
                const healthScore = cluster.connected
                    ? Math.max(0, 100 - (avgCpu * 0.3 + avgMem * 0.3 + avgStorage * 0.2 + (nodeCount > 0 ? (offlineNodes / nodeCount) * 100 * 0.2 : 0)))
                    : 0;

                const alerts = [];
                if (!cluster.connected) alerts.push({ type: 'error', msg: 'Offline' });
                if (offlineNodes > 0) alerts.push({ type: 'warning', msg: `${offlineNodes} node(s) offline` });
                if (avgCpu > 90) alerts.push({ type: 'error', msg: 'CPU critical' });
                else if (avgCpu > 80) alerts.push({ type: 'warning', msg: 'CPU high' });
                if (avgMem > 90) alerts.push({ type: 'error', msg: 'RAM critical' });
                else if (avgMem > 80) alerts.push({ type: 'warning', msg: 'RAM high' });
                if (avgStorage > 90) alerts.push({ type: 'error', msg: 'Storage critical' });
                else if (avgStorage > 80) alerts.push({ type: 'warning', msg: 'Storage high' });

                return {
                    ...cluster,
                    nodeCount, onlineNodes, offlineNodes,
                    avgCpu, avgMem, avgStorage,
                    totalVms, runningVms: vmsRunning,
                    healthScore: Math.round(healthScore),
                    hasMetrics: nodeCount > 0 || cluster.connected,
                    lastUpdate,
                    alerts,
                    cpuHistory: cpuHistory[cluster.id] || [],
                    ramHistory: ramHistory[cluster.id] || []
                };
            });

            // sorting
            const sortedStats = [...clusterStats].sort((a, b) => {
                let aVal, bVal;
                switch (sortBy) {
                    case 'health': aVal = a.healthScore; bVal = b.healthScore; break;
                    case 'nodes': aVal = a.nodeCount; bVal = b.nodeCount; break;
                    case 'vms': aVal = a.totalVms; bVal = b.totalVms; break;
                    case 'cpu': aVal = a.avgCpu; bVal = b.avgCpu; break;
                    case 'ram': aVal = a.avgMem; bVal = b.avgMem; break;
                    default: aVal = (a.display_name || a.name).toLowerCase(); bVal = (b.display_name || b.name).toLowerCase();
                }
                if (typeof aVal === 'string') return sortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
            });

            // group totals
            const withMetrics = clusterStats.filter(c => c.hasMetrics);
            const totals = {
                clusters: groupClusters.length,
                connectedClusters: groupClusters.filter(c => c.connected).length,
                totalNodes: clusterStats.reduce((acc, c) => acc + c.nodeCount, 0),
                onlineNodes: clusterStats.reduce((acc, c) => acc + c.onlineNodes, 0),
                totalVms: clusterStats.reduce((acc, c) => acc + c.totalVms, 0),
                runningVms: clusterStats.reduce((acc, c) => acc + c.runningVms, 0),
                avgCpu: withMetrics.length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgCpu, 0) / withMetrics.length : 0,
                avgMem: withMetrics.length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgMem, 0) / withMetrics.length : 0,
                avgStorage: withMetrics.length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgStorage, 0) / withMetrics.length : 0,
                totalAlerts: clusterStats.reduce((acc, c) => acc + c.alerts.length, 0)
            };

            const lbEnabled = !!group.cross_cluster_lb_enabled;

            // NS: sparkline - same as AllClustersOverview
            const Sparkline = ({ data, color, height = 20, width = 60 }) => {
                if (!data || data.length < 2) return <div style={{ width, height }} className="bg-proxmox-dark/50 rounded" />;
                const max = Math.max(...data, 1);
                const min = Math.min(...data, 0);
                const range = max - min || 1;
                const points = data.map((v, i) => `${(i / (data.length - 1)) * width},${height - ((v - min) / range) * height}`).join(' ');
                return (
                    <svg width={width} height={height} className="overflow-visible">
                        <polyline fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" points={points} />
                        <circle cx={width} cy={height - ((data[data.length - 1] - min) / range) * height} r="2" fill={color} />
                    </svg>
                );
            };

            // circular progress gauge
            const CircularProgress = ({ value, size = 60, strokeWidth = 6, color }) => {
                const radius = (size - strokeWidth) / 2;
                const circumference = radius * 2 * Math.PI;
                const offset = circumference - (value / 100) * circumference;
                return (
                    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
                        <svg className="transform -rotate-90 overflow-visible" width={size} height={size}>
                            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor" strokeWidth={strokeWidth} className="text-gray-700" />
                            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} className="transition-all duration-500" />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                            <span className="text-xs font-bold text-white">{value.toFixed(0)}%</span>
                        </div>
                    </div>
                );
            };

            const getHealthColor = (score) => {
                if (score >= 80) return { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30', color: '#22c55e' };
                if (score >= 60) return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', color: '#eab308' };
                if (score >= 40) return { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', color: '#f97316' };
                return { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', color: '#ef4444' };
            };

            const formatLastUpdate = (date) => {
                if (!date) return '-';
                const now = new Date();
                const diff = Math.floor((now - new Date(date)) / 1000);
                if (diff < 10) return t('justNow') || 'just now';
                if (diff < 60) return `${diff}s ago`;
                if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
                return new Date(date).toLocaleTimeString();
            };

            const SortButton = ({ field, label }) => (
                <button
                    onClick={() => { setSortBy(field); setSortDir(sortBy === field && sortDir === 'asc' ? 'desc' : 'asc'); }}
                    className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${sortBy === field ? 'bg-proxmox-orange/20 text-proxmox-orange font-medium' : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'}`}
                >
                    {label} {sortBy === field && (sortDir === 'asc' ? '↑' : '↓')}
                </button>
            );

            // MK: cluster card - clickable, same layout as the all-clusters one
            const ClusterCard = ({ cluster }) => {
                const healthColors = getHealthColor(cluster.healthScore);
                const hasAlerts = cluster.alerts.length > 0;
                const errorCount = cluster.alerts.filter(a => a.type === 'error').length;

                return (
                    <div
                        onClick={() => onSelectCluster(cluster)}
                        className="group relative bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden cursor-pointer hover:border-proxmox-orange/50 transition-all duration-300 hover:shadow-lg hover:shadow-proxmox-orange/10"
                    >
                        <div className={`h-1.5 ${cluster.connected ? 'bg-gradient-to-r from-green-500 via-emerald-500 to-green-500' : 'bg-gradient-to-r from-red-500 via-red-600 to-red-500'}`} />

                        <div className="p-5">
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <div className={`relative w-12 h-12 rounded-xl ${cluster.connected ? 'bg-gradient-to-br from-green-500/20 to-emerald-500/20' : 'bg-gradient-to-br from-red-500/20 to-red-600/20'} flex items-center justify-center`}>
                                        <Icons.Server className={`w-6 h-6 ${cluster.connected ? 'text-green-400' : 'text-red-400'}`} />
                                        {cluster.connected && <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full border-2 border-proxmox-card animate-pulse" />}
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-white text-base group-hover:text-proxmox-orange transition-colors">
                                            {cluster.display_name || cluster.name}
                                        </h3>
                                        <p className="text-xs text-gray-500">{cluster.host}</p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-2">
                                    {hasAlerts && (
                                        <div className={`px-2.5 py-1 rounded-lg flex items-center gap-1.5 ${errorCount > 0 ? 'bg-red-500/20 border border-red-500/30' : 'bg-yellow-500/20 border border-yellow-500/30'}`}>
                                            <Icons.AlertTriangle className={`w-3.5 h-3.5 ${errorCount > 0 ? 'text-red-400' : 'text-yellow-400'}`} />
                                            <span className={`text-xs font-medium ${errorCount > 0 ? 'text-red-400' : 'text-yellow-400'}`}>{cluster.alerts.length}</span>
                                        </div>
                                    )}
                                    {cluster.connected ? (
                                        <div className={`px-2.5 py-1 rounded-lg ${healthColors.bg} ${healthColors.border} border`}>
                                            <span className={`text-xs font-semibold ${healthColors.text}`}>{cluster.healthScore}%</span>
                                        </div>
                                    ) : (
                                        <div className="px-2.5 py-1 rounded-lg bg-red-500/20 border border-red-500/30">
                                            <span className="text-xs font-semibold text-red-400">Offline</span>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {cluster.hasMetrics ? (
                                <div className="grid grid-cols-5 gap-3">
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className={`text-xl font-bold ${cluster.onlineNodes === cluster.nodeCount ? 'text-green-400' : 'text-yellow-400'}`}>
                                            {cluster.onlineNodes}/{cluster.nodeCount}
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('nodes')}</div>
                                    </div>
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex flex-col items-center gap-1">
                                            <CircularProgress value={cluster.avgCpu} size={44} strokeWidth={4} color={cluster.avgCpu > 80 ? '#ef4444' : cluster.avgCpu > 60 ? '#eab308' : '#22c55e'} />
                                            <Sparkline data={cluster.cpuHistory} color={cluster.avgCpu > 80 ? '#ef4444' : '#22c55e'} height={14} width={40} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">CPU</div>
                                    </div>
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex flex-col items-center gap-1">
                                            <CircularProgress value={cluster.avgMem} size={44} strokeWidth={4} color={cluster.avgMem > 80 ? '#ef4444' : cluster.avgMem > 60 ? '#eab308' : '#3b82f6'} />
                                            <Sparkline data={cluster.ramHistory} color={cluster.avgMem > 80 ? '#ef4444' : '#3b82f6'} height={14} width={40} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">RAM</div>
                                    </div>
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex justify-center">
                                            <CircularProgress value={cluster.avgStorage} size={44} strokeWidth={4} color={cluster.avgStorage > 80 ? '#ef4444' : cluster.avgStorage > 60 ? '#eab308' : '#8b5cf6'} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('storage') || 'Disk'}</div>
                                    </div>
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="text-xl font-bold">
                                            <span className="text-green-400">{cluster.runningVms}</span>
                                            <span className="text-gray-500 text-sm">/{cluster.totalVms}</span>
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('vms')}</div>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex items-center justify-center h-20 text-gray-500 text-sm">
                                    <Icons.AlertTriangle className="w-4 h-4 mr-2" />
                                    {t('noDataAvailable') || 'No data available'}
                                </div>
                            )}

                            <div className="mt-4 pt-3 border-t border-proxmox-border/50 flex items-center justify-between">
                                <span className="text-xs text-gray-500">
                                    {t('updated') || 'Updated'}: {formatLastUpdate(cluster.lastUpdate)}
                                </span>
                                <Icons.ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-proxmox-orange transition-colors" />
                            </div>
                        </div>
                    </div>
                );
            };

            // LW: Feb 2026 - Corporate variant for GroupOverview
            if (isCorporate) {
                const corpBarColor = (val) => val > 80 ? '#f54f47' : val > 60 ? '#efc006' : '#60b515';
                const groupClusterIds = groupClusters.map(c => c.id);
                const groupTopGuests = topGuests.filter(g => groupClusterIds.includes(g.cluster_id));
                return (
                    <div className="space-y-3">
                        {/* Header */}
                        <div className="flex items-center justify-between pb-2" style={{borderBottom: '1px solid #485764'}}>
                            <div className="flex items-center gap-2">
                                <Icons.Folder className="w-4 h-4" style={{color: group.color || '#E86F2D'}} />
                                <h2 className="text-[15px] font-semibold" style={{color: '#e9ecef'}}>{group.name}</h2>
                                <span className="text-[12px]" style={{color: '#728b9a'}}>{groupClusters.length} {t('clusters')}</span>
                            </div>
                            <div className="flex items-center gap-2">
                                {totals.totalAlerts > 0 && (
                                    <span className="text-[12px] flex items-center gap-1" style={{color: '#f54f47'}}>
                                        <Icons.AlertTriangle className="w-3.5 h-3.5" /> {totals.totalAlerts}
                                    </span>
                                )}
                                <button onClick={onOpenSettings} className="p-1" style={{color: '#728b9a'}} title={t('settings')}>
                                    <Icons.Settings className="w-4 h-4" />
                                </button>
                            </div>
                        </div>

                        {/* LB status compact */}
                        {lbEnabled && (
                            <div className="flex items-center gap-3 px-2 py-1.5 text-[12px]" style={{background: '#22343c', border: '1px solid #485764'}}>
                                <Icons.Scale className="w-3.5 h-3.5" style={{color: '#60b515'}} />
                                <span style={{color: '#adbbc4'}}>{t('crossClusterLB') || 'Cross-Cluster LB'}: <span style={{color: '#60b515'}}>{t('enabled') || 'Enabled'}</span></span>
                                {group.cross_cluster_dry_run && <span style={{color: '#efc006'}}>({t('simulationMode') || 'Simulation'})</span>}
                                <span style={{color: '#728b9a'}}>Threshold: {group.cross_cluster_threshold || 30}%</span>
                            </div>
                        )}

                        {/* Stats bar */}
                        <div className="flex items-center gap-0 flex-wrap text-[13px] px-2 py-2" style={{background: '#22343c', border: '1px solid #485764'}}>
                            <span style={{color: '#adbbc4'}}>{t('clusters')}: <b style={{color: '#e9ecef'}}>{totals.connectedClusters}/{totals.clusters}</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>{t('nodes')}: <b style={{color: '#e9ecef'}}>{totals.onlineNodes}/{totals.totalNodes}</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>VMs: <b style={{color: '#60b515'}}>{totals.runningVms}</b> / <b style={{color: '#728b9a'}}>{totals.totalVms - totals.runningVms}</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>CPU: <b style={{color: corpBarColor(totals.avgCpu)}}>{totals.avgCpu.toFixed(0)}%</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>RAM: <b style={{color: corpBarColor(totals.avgMem)}}>{totals.avgMem.toFixed(0)}%</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>{t('storage') || 'Storage'}: <b style={{color: corpBarColor(totals.avgStorage)}}>{totals.avgStorage.toFixed(0)}%</b></span>
                        </div>

                        {/* Cluster table */}
                        <table className="corp-datagrid">
                            <thead>
                                <tr>
                                    {[
                                        { field: 'name', label: t('name') || 'Name' },
                                        { field: null, label: t('status') || 'Status' },
                                        { field: 'nodes', label: t('nodes') || 'Nodes' },
                                        { field: 'vms', label: 'VMs' },
                                        { field: 'cpu', label: 'CPU' },
                                        { field: 'ram', label: 'RAM' },
                                        { field: null, label: t('storage') || 'Storage' },
                                        { field: 'health', label: t('health') || 'Health' },
                                    ].map((col, i) => (
                                        <th key={i}
                                            className={col.field ? 'cursor-pointer hover:text-white' : ''}
                                            onClick={col.field ? () => { setSortBy(col.field); setSortDir(sortBy === col.field && sortDir === 'asc' ? 'desc' : 'asc'); } : undefined}
                                            style={{textAlign: 'left'}}
                                        >
                                            {col.label} {sortBy === col.field && <span className="sort-indicator">{sortDir === 'asc' ? '▲' : '▼'}</span>}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {sortedStats.map(cluster => {
                                    const hc = getHealthColor(cluster.healthScore);
                                    return (
                                        <tr key={cluster.id} className="table-row-hover cursor-pointer" onClick={() => onSelectCluster(cluster)}>
                                            <td style={{fontWeight: 500}}>{cluster.display_name || cluster.name}</td>
                                            <td>
                                                <span className="inline-flex items-center gap-1.5">
                                                    <span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: cluster.connected ? '#60b515' : '#f54f47'}} />
                                                    <span style={{color: cluster.connected ? '#60b515' : '#f54f47', fontSize: '12px'}}>{cluster.connected ? 'online' : 'offline'}</span>
                                                </span>
                                            </td>
                                            <td>{cluster.onlineNodes}/{cluster.nodeCount}</td>
                                            <td><span style={{color: '#60b515'}}>{cluster.runningVms}</span> / <span style={{color: '#728b9a'}}>{cluster.totalVms - cluster.runningVms}</span></td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgCpu), minWidth: '28px'}}>{cluster.avgCpu.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgCpu, 100)}%`, background: corpBarColor(cluster.avgCpu)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgMem), minWidth: '28px'}}>{cluster.avgMem.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgMem, 100)}%`, background: corpBarColor(cluster.avgMem)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgStorage), minWidth: '28px'}}>{cluster.avgStorage.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgStorage, 100)}%`, background: corpBarColor(cluster.avgStorage)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td><span style={{color: hc.color, fontWeight: 500}}>{cluster.healthScore}%</span></td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>

                        {/* Top Resources */}
                        {groupTopGuests.length > 0 && (
                            <div>
                                <div className="flex items-center gap-2 py-1.5" style={{borderBottom: '1px solid #485764'}}>
                                    <Icons.Activity className="w-3.5 h-3.5" style={{color: '#49afd9'}} />
                                    <span className="text-[13px] font-semibold" style={{color: '#adbbc4'}}>{t('topResources') || 'Top Resources'}</span>
                                </div>
                                <table className="corp-datagrid">
                                    <thead><tr><th style={{width: '24px'}}></th><th>{t('name')}</th><th>{t('cluster')}</th><th>{t('node')}</th><th>CPU</th><th>RAM</th><th>{t('status')}</th></tr></thead>
                                    <tbody>
                                        {groupTopGuests.slice(0, 10).map(guest => {
                                            const cpuP = ((guest.cpu || 0) * 100).toFixed(1);
                                            const memP = guest.maxmem > 0 ? ((guest.mem / guest.maxmem) * 100).toFixed(1) : 0;
                                            const gc = clusters.find(c => c.id === guest.cluster_id);
                                            return (
                                                <tr key={`${guest.cluster_id}-${guest.vmid}`} className="table-row-hover cursor-pointer"
                                                    onClick={() => { if (gc && onSelectVm) onSelectVm(gc, guest.vmid, guest.node); }}>
                                                    <td><Icons.Monitor className="w-3.5 h-3.5" style={{color: guest.type === 'qemu' ? '#49afd9' : '#a178d9'}} /></td>
                                                    <td><span style={{fontWeight: 500}}>{guest.name || `VM ${guest.vmid}`}</span> <span style={{color: '#728b9a', fontSize: '11px'}}>#{guest.vmid}</span></td>
                                                    <td>{guest.cluster_name}</td>
                                                    <td style={{color: '#adbbc4'}}>{guest.node}</td>
                                                    <td><span style={{color: corpBarColor(cpuP)}}>{cpuP}%</span></td>
                                                    <td><span style={{color: corpBarColor(memP)}}>{memP}%</span></td>
                                                    <td>
                                                        <span className="inline-flex items-center gap-1">
                                                            <span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: guest.status === 'running' ? '#60b515' : '#728b9a'}} />
                                                            <span style={{color: guest.status === 'running' ? '#60b515' : '#728b9a', fontSize: '12px'}}>{guest.status === 'running' ? t('running') : t('stopped')}</span>
                                                        </span>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* LB History */}
                        {lbEnabled && lbHistory.length > 0 && (
                            <div>
                                <div className="flex items-center gap-2 py-1.5" style={{borderBottom: '1px solid #485764'}}>
                                    <Icons.Activity className="w-3.5 h-3.5" style={{color: '#a178d9'}} />
                                    <span className="text-[13px] font-semibold" style={{color: '#adbbc4'}}>{t('lbHistory') || 'LB History'}</span>
                                </div>
                                <table className="corp-datagrid">
                                    <thead><tr><th>{t('time')}</th><th>{t('action')}</th><th>{t('details')}</th></tr></thead>
                                    <tbody>
                                        {lbHistory.slice(0, 10).map((entry, i) => (
                                            <tr key={i} className="table-row-hover">
                                                <td style={{color: '#728b9a'}}>{new Date(entry.timestamp).toLocaleString()}</td>
                                                <td><span style={{color: entry.action === 'migrate' ? '#49afd9' : '#a178d9'}}>{entry.action}</span></td>
                                                <td style={{color: '#adbbc4'}}>{entry.details || '-'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {groupClusters.length === 0 && (
                            <div className="py-8 text-center text-[13px]" style={{color: '#728b9a'}}>
                                {t('noClustersInGroup') || 'No clusters in this group'}
                            </div>
                        )}
                    </div>
                );
            }

            // Modern layout (original)
            return (
                <div className="space-y-6">
                    {/* Header */}
                    <div className="relative overflow-hidden bg-gradient-to-r from-proxmox-card via-proxmox-dark to-proxmox-card border border-proxmox-border rounded-2xl p-6">
                        <div className="absolute inset-0 bg-gradient-to-r from-proxmox-orange/5 via-transparent to-blue-500/5" />
                        <div className="relative flex items-center justify-between flex-wrap gap-4">
                            <div className="flex items-center gap-4">
                                <div className="w-14 h-14 rounded-xl flex items-center justify-center shadow-lg" style={{ backgroundColor: (group.color || '#E86F2D') + '33' }}>
                                    <Icons.Folder className="w-7 h-7" style={{ color: group.color || '#E86F2D' }} />
                                </div>
                                <div>
                                    <h1 className="text-2xl font-bold text-white">{group.name}</h1>
                                    {group.description && <p className="text-gray-400 text-sm">{group.description}</p>}
                                    <p className="text-gray-500 text-xs mt-0.5">{groupClusters.length} {t('clusters')}</p>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                {totals.totalAlerts > 0 && (
                                    <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded-lg">
                                        <Icons.AlertTriangle className="w-4 h-4 text-red-400" />
                                        <span className="text-sm text-red-400 font-medium">{totals.totalAlerts} {t('alerts') || 'Alerts'}</span>
                                    </div>
                                )}
                                <button
                                    onClick={onOpenSettings}
                                    className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-proxmox-dark transition-colors"
                                    title={t('settings') || 'Settings'}
                                >
                                    <Icons.Settings className="w-5 h-5" />
                                </button>
                                <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-full">
                                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                    <span className="text-xs text-green-400 font-medium">Live</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* LW: Cross-Cluster LB status card - only show when enabled */}
                    {lbEnabled && (
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                                        <Icons.Scale className="w-5 h-5 text-green-400" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold flex items-center gap-2">
                                            {t('crossClusterLB') || 'Cross-Cluster Load Balancing'}
                                            <span className="bg-green-500/10 text-green-400 px-2 py-0.5 rounded-full text-xs">{t('enabled') || 'Enabled'}</span>
                                            {group.cross_cluster_dry_run && (
                                                <span className="bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded-full text-xs">{t('simulationMode') || 'Simulation Mode'}</span>
                                            )}
                                        </h3>
                                        <div className="flex items-center gap-4 text-xs text-gray-500 mt-1">
                                            <span>{t('threshold') || 'Threshold'}: {group.cross_cluster_threshold || 30}%</span>
                                            <span>{t('interval') || 'Interval'}: {group.cross_cluster_interval || 600}s</span>
                                            {groupStatus?.cross_cluster_lb?.last_run && (
                                                <span>{t('lastRun') || 'Last run'}: {formatLastUpdate(groupStatus.cross_cluster_lb.last_run)}</span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Stats Grid - same 7-column layout */}
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
                        {[
                            { icon: Icons.Server, value: `${totals.connectedClusters}/${totals.clusters}`, label: t('clusters'), color: 'proxmox-orange', hoverColor: 'proxmox-orange' },
                            { icon: Icons.Cpu, value: `${totals.onlineNodes}/${totals.totalNodes}`, label: t('nodesOnline') || 'Nodes', color: 'blue-400', hoverColor: 'blue-500' },
                            { icon: Icons.Play, value: totals.runningVms, label: t('vmsRunning') || 'Running', color: 'green-400', hoverColor: 'green-500', valueColor: 'text-green-400' },
                            { icon: Icons.Square, value: totals.totalVms - totals.runningVms, label: t('vmsStopped') || 'Stopped', color: 'gray-400', hoverColor: 'gray-500' },
                        ].map((stat, i) => (
                            <div key={i} className={`bg-gradient-to-br from-proxmox-card to-proxmox-dark border border-proxmox-border rounded-xl p-4 hover:border-${stat.hoverColor}/30 transition-all group`}>
                                <div className="flex items-center gap-3">
                                    <div className={`w-10 h-10 rounded-lg bg-${stat.color}/20 flex items-center justify-center group-hover:scale-110 transition-transform`}>
                                        <stat.icon className={`w-5 h-5 text-${stat.color}`} />
                                    </div>
                                    <div>
                                        <div className={`text-xl font-bold ${stat.valueColor || 'text-white'}`}>{stat.value}</div>
                                        <div className="text-xs text-gray-500">{stat.label}</div>
                                    </div>
                                </div>
                            </div>
                        ))}

                        {/* circular gauges */}
                        {[
                            { value: totals.avgCpu, label: 'CPU', color: totals.avgCpu > 80 ? '#ef4444' : totals.avgCpu > 60 ? '#eab308' : '#22c55e' },
                            { value: totals.avgMem, label: 'RAM', color: totals.avgMem > 80 ? '#ef4444' : totals.avgMem > 60 ? '#eab308' : '#3b82f6' },
                            { value: totals.avgStorage, label: t('storage') || 'Disk', color: totals.avgStorage > 80 ? '#ef4444' : totals.avgStorage > 60 ? '#eab308' : '#8b5cf6' },
                        ].map((stat, i) => (
                            <div key={i} className="bg-gradient-to-br from-proxmox-card to-proxmox-dark border border-proxmox-border rounded-xl p-4 hover:border-proxmox-border transition-all">
                                <div className="flex items-center gap-3">
                                    <CircularProgress value={stat.value || 0} size={44} strokeWidth={4} color={stat.color} />
                                    <div>
                                        <div className="text-sm font-bold text-white">{stat.label}</div>
                                        <div className="text-xs text-gray-500">{t('average') || 'Avg'}</div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Sort Controls */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm text-gray-500 mr-1">{t('sortBy') || 'Sort by'}:</span>
                            <SortButton field="name" label={t('name') || 'Name'} />
                            <SortButton field="health" label={t('health') || 'Health'} />
                            <SortButton field="nodes" label={t('nodes') || 'Nodes'} />
                            <SortButton field="vms" label="VMs" />
                            <SortButton field="cpu" label="CPU" />
                            <SortButton field="ram" label="RAM" />
                        </div>
                    </div>

                    {/* Cluster Cards */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {sortedStats.map(cluster => <ClusterCard key={cluster.id} cluster={cluster} />)}
                    </div>

                    {/* NS: Top Resources - filtered for this group */}
                    {(() => {
                        const groupClusterIds2 = groupClusters.map(c => c.id);
                        const groupTopGuests2 = topGuests.filter(g => groupClusterIds2.includes(g.cluster_id));
                        if (groupTopGuests2.length === 0) return null;
                        return (
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                                            <Icons.Activity className="w-5 h-5 text-cyan-400" />
                                        </div>
                                        <div>
                                            <h3 className="font-semibold text-white">{t('topResources') || 'Top Resources'}</h3>
                                            <p className="text-xs text-gray-500">{t('highestCpuUsage') || 'Highest CPU and RAM usage across all clusters'}</p>
                                        </div>
                                    </div>
                                    <span className="text-xs text-gray-500 bg-proxmox-dark px-2 py-1 rounded">Top 10</span>
                                </div>
                                <div className="overflow-x-auto">
                                    <table className="w-full">
                                        <thead className="bg-proxmox-dark/50">
                                            <tr className="text-left text-xs text-gray-400">
                                                <th className="px-4 py-3 font-medium">{t('type')}</th>
                                                <th className="px-4 py-3 font-medium">{t('name')}</th>
                                                <th className="px-4 py-3 font-medium">{t('cluster')}</th>
                                                <th className="px-4 py-3 font-medium">{t('node')}</th>
                                                <th className="px-4 py-3 font-medium">CPU</th>
                                                <th className="px-4 py-3 font-medium">RAM</th>
                                                <th className="px-4 py-3 font-medium">{t('status')}</th>
                                                <th className="px-4 py-3 w-10"></th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-proxmox-border/50">
                                            {groupTopGuests2.slice(0, 10).map((guest, idx) => {
                                                const cpuPercent = ((guest.cpu || 0) * 100).toFixed(1);
                                                const memPercent = guest.maxmem > 0 ? ((guest.mem / guest.maxmem) * 100).toFixed(1) : 0;
                                                const isVM = guest.type === 'qemu';
                                                const guestCluster = clusters.find(c => c.id === guest.cluster_id);
                                                return (
                                                    <tr
                                                        key={`${guest.cluster_id}-${guest.vmid}`}
                                                        className="hover:bg-proxmox-hover/50 transition-colors cursor-pointer group"
                                                        onClick={() => { if (guestCluster && onSelectVm) onSelectVm(guestCluster, guest.vmid, guest.node); }}
                                                        title={t('clickToOpenVm') || 'Click to open VM'}
                                                    >
                                                        <td className="px-4 py-3">
                                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isVM ? 'bg-blue-500/20' : 'bg-purple-500/20'}`}>
                                                                {isVM ? <Icons.Monitor className="w-4 h-4 text-blue-400" /> : <Icons.Layers className="w-4 h-4 text-purple-400" />}
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="font-medium text-white group-hover:text-proxmox-orange transition-colors">{guest.name || `VM ${guest.vmid}`}</div>
                                                            <div className="text-xs text-gray-500">ID: {guest.vmid}</div>
                                                        </td>
                                                        <td className="px-4 py-3"><span className="text-sm text-gray-300">{guest.cluster_name}</span></td>
                                                        <td className="px-4 py-3"><span className="text-sm text-gray-400">{guest.node}</span></td>
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <div className="w-16 h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                                    <div className={`h-full rounded-full ${cpuPercent > 80 ? 'bg-red-500' : cpuPercent > 60 ? 'bg-yellow-500' : 'bg-green-500'}`} style={{ width: `${Math.min(cpuPercent, 100)}%` }} />
                                                                </div>
                                                                <span className={`text-xs font-medium ${cpuPercent > 80 ? 'text-red-400' : cpuPercent > 60 ? 'text-yellow-400' : 'text-green-400'}`}>{cpuPercent}%</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <div className="flex items-center gap-2">
                                                                <div className="w-16 h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                                    <div className={`h-full rounded-full ${memPercent > 80 ? 'bg-red-500' : memPercent > 60 ? 'bg-yellow-500' : 'bg-blue-500'}`} style={{ width: `${Math.min(memPercent, 100)}%` }} />
                                                                </div>
                                                                <span className="text-xs text-gray-400">{memPercent}%</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${guest.status === 'running' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                                                                <div className={`w-1.5 h-1.5 rounded-full ${guest.status === 'running' ? 'bg-green-400' : 'bg-gray-400'}`} />
                                                                {guest.status === 'running' ? t('running') : t('stopped')}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <Icons.ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-proxmox-orange transition-colors" />
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        );
                    })()}

                    {/* NS: LB History table - only show if cross-cluster LB is on */}
                    {lbEnabled && (
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                            <div className="p-4 border-b border-proxmox-border flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                                    <Icons.Activity className="w-5 h-5 text-purple-400" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-white">{t('lbHistory') || 'Load Balancing History'}</h3>
                                    <p className="text-xs text-gray-500">{t('recentLbActions') || 'Recent cross-cluster LB actions'}</p>
                                </div>
                            </div>
                            {lbHistory.length > 0 ? (
                                <div className="overflow-x-auto">
                                    <table className="w-full">
                                        <thead className="bg-proxmox-dark/50">
                                            <tr className="text-left text-xs text-gray-400">
                                                <th className="px-4 py-3 font-medium">{t('time') || 'Time'}</th>
                                                <th className="px-4 py-3 font-medium">{t('action') || 'Action'}</th>
                                                <th className="px-4 py-3 font-medium">{t('details') || 'Details'}</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-proxmox-border/50">
                                            {lbHistory.slice(0, 20).map((entry, idx) => (
                                                <tr key={idx} className="hover:bg-proxmox-hover/50 transition-colors">
                                                    <td className="px-4 py-3 text-sm text-gray-400">
                                                        {new Date(entry.timestamp).toLocaleString()}
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
                                                            entry.action === 'migrate' ? 'bg-blue-500/20 text-blue-400'
                                                            : entry.action === 'rebalance' ? 'bg-purple-500/20 text-purple-400'
                                                            : 'bg-gray-500/20 text-gray-400'
                                                        }`}>
                                                            {entry.action}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-3 text-sm text-gray-300">{entry.details || '-'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="p-8 text-center text-gray-500 text-sm">
                                    <Icons.Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                    {t('noLbEvents') || 'No cross-cluster LB events yet'}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Empty State */}
                    {groupClusters.length === 0 && (
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-12 text-center">
                            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-proxmox-orange/20 to-orange-600/20 flex items-center justify-center">
                                <Icons.Server className="w-8 h-8 text-proxmox-orange" />
                            </div>
                            <h3 className="text-lg font-semibold text-white mb-2">{t('noClustersInGroup') || 'No clusters in this group'}</h3>
                            <p className="text-gray-500 text-sm">{t('addClustersToGroup') || 'Assign clusters to this group to see them here'}</p>
                        </div>
                    )}
                </div>
            );
        }

        // LW: All Clusters Overview - GitHub Feature Request #16
        // added a bunch of stuff here - storage, sparklines, sorting etc
        function AllClustersOverview({ clusters, allMetrics, clusterGroups = [], topGuests = [], onSelectCluster, onSelectVm }) {
            const { t } = useTranslation();
            const { isCorporate } = useLayout();
            const [sortBy, setSortBy] = useState('name');
            const [sortDir, setSortDir] = useState('asc');
            const [cpuHistory, setCpuHistory] = useState({});
            const [ramHistory, setRamHistory] = useState({});
            
            // sparkline history
            useEffect(() => {
                clusters.forEach(cluster => {
                    const status = allMetrics[cluster.id]?.data || {};
                    const cpu = status.resources?.cpu?.percent || 0;
                    const ram = status.resources?.memory?.percent || 0;
                    
                    setCpuHistory(prev => ({
                        ...prev,
                        [cluster.id]: [...(prev[cluster.id] || []).slice(-9), cpu]
                    }));
                    setRamHistory(prev => ({
                        ...prev,
                        [cluster.id]: [...(prev[cluster.id] || []).slice(-9), ram]
                    }));
                });
            }, [allMetrics]);
            
            // stats per cluster
            const clusterStats = clusters.map(cluster => {
                const status = allMetrics[cluster.id]?.data || {};
                const lastUpdate = allMetrics[cluster.id]?.lastUpdate;
                const nodes = status.nodes || {};
                const guests = status.guests || {};
                const resources = status.resources || {};
                
                const nodeCount = nodes.total || 0;
                const onlineNodes = nodes.online || 0;
                const offlineNodes = nodes.offline || 0;
                const avgCpu = resources.cpu?.percent || 0;
                const avgMem = resources.memory?.percent || 0;
                const avgStorage = resources.storage?.percent || 0;
                
                const vmsRunning = (guests.vms?.running || 0) + (guests.containers?.running || 0);
                const vmsStopped = (guests.vms?.stopped || 0) + (guests.containers?.stopped || 0);
                const totalVms = vmsRunning + vmsStopped;
                
                // health score calculation - cpu/ram/storage weighted
                const healthScore = cluster.connected 
                    ? Math.max(0, 100 - (avgCpu * 0.3 + avgMem * 0.3 + avgStorage * 0.2 + (nodeCount > 0 ? (offlineNodes / nodeCount) * 100 * 0.2 : 0)))
                    : 0;
                
                // Count alerts/warnings
                const alerts = [];
                if (!cluster.connected) alerts.push({ type: 'error', msg: 'Offline' });
                if (offlineNodes > 0) alerts.push({ type: 'warning', msg: `${offlineNodes} node(s) offline` });
                if (avgCpu > 90) alerts.push({ type: 'error', msg: 'CPU critical' });
                else if (avgCpu > 80) alerts.push({ type: 'warning', msg: 'CPU high' });
                if (avgMem > 90) alerts.push({ type: 'error', msg: 'RAM critical' });
                else if (avgMem > 80) alerts.push({ type: 'warning', msg: 'RAM high' });
                if (avgStorage > 90) alerts.push({ type: 'error', msg: 'Storage critical' });
                else if (avgStorage > 80) alerts.push({ type: 'warning', msg: 'Storage high' });
                
                return {
                    ...cluster,
                    nodeCount, onlineNodes, offlineNodes,
                    avgCpu, avgMem, avgStorage,
                    totalVms, runningVms: vmsRunning,
                    healthScore: Math.round(healthScore),
                    hasMetrics: nodeCount > 0 || cluster.connected,
                    lastUpdate,
                    alerts,
                    cpuHistory: cpuHistory[cluster.id] || [],
                    ramHistory: ramHistory[cluster.id] || []
                };
            });
            
            // sorting
            const sortedStats = [...clusterStats].sort((a, b) => {
                let aVal, bVal;
                switch (sortBy) {
                    case 'health': aVal = a.healthScore; bVal = b.healthScore; break;
                    case 'nodes': aVal = a.nodeCount; bVal = b.nodeCount; break;
                    case 'vms': aVal = a.totalVms; bVal = b.totalVms; break;
                    case 'cpu': aVal = a.avgCpu; bVal = b.avgCpu; break;
                    case 'ram': aVal = a.avgMem; bVal = b.avgMem; break;
                    default: aVal = (a.display_name || a.name).toLowerCase(); bVal = (b.display_name || b.name).toLowerCase();
                }
                if (typeof aVal === 'string') return sortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
            });
            
            // group by cluster group
            const groupedClusters = {};
            const ungroupedClusters = [];
            sortedStats.forEach(cluster => {
                const group = clusterGroups.find(g => g.id === cluster.group_id);
                if (group) {
                    if (!groupedClusters[group.id]) groupedClusters[group.id] = { group, clusters: [] };
                    groupedClusters[group.id].clusters.push(cluster);
                } else {
                    ungroupedClusters.push(cluster);
                }
            });
            
            // totals for the header cards
            const totals = {
                clusters: clusters.length,
                connectedClusters: clusters.filter(c => c.connected).length,
                totalNodes: clusterStats.reduce((acc, c) => acc + c.nodeCount, 0),
                onlineNodes: clusterStats.reduce((acc, c) => acc + c.onlineNodes, 0),
                totalVms: clusterStats.reduce((acc, c) => acc + c.totalVms, 0),
                runningVms: clusterStats.reduce((acc, c) => acc + c.runningVms, 0),
                avgCpu: clusterStats.filter(c => c.hasMetrics).length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgCpu, 0) / clusterStats.filter(c => c.hasMetrics).length : 0,
                avgMem: clusterStats.filter(c => c.hasMetrics).length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgMem, 0) / clusterStats.filter(c => c.hasMetrics).length : 0,
                avgStorage: clusterStats.filter(c => c.hasMetrics).length > 0 ? clusterStats.reduce((acc, c) => acc + c.avgStorage, 0) / clusterStats.filter(c => c.hasMetrics).length : 0,
                totalAlerts: clusterStats.reduce((acc, c) => acc + c.alerts.length, 0)
            };
            
            // NS: sparkline svg - kept it simple
            const Sparkline = ({ data, color, height = 20, width = 60 }) => {
                if (!data || data.length < 2) return <div style={{ width, height }} className="bg-proxmox-dark/50 rounded" />;
                const max = Math.max(...data, 1);
                const min = Math.min(...data, 0);
                const range = max - min || 1;
                const points = data.map((v, i) => `${(i / (data.length - 1)) * width},${height - ((v - min) / range) * height}`).join(' ');
                return (
                    <svg width={width} height={height} className="overflow-visible">
                        <polyline fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" points={points} />
                        <circle cx={width} cy={height - ((data[data.length - 1] - min) / range) * height} r="2" fill={color} />
                    </svg>
                );
            };
            
            // circular progress - reusable
            const CircularProgress = ({ value, size = 60, strokeWidth = 6, color }) => {
                const radius = (size - strokeWidth) / 2;
                const circumference = radius * 2 * Math.PI;
                const offset = circumference - (value / 100) * circumference;
                return (
                    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
                        <svg className="transform -rotate-90 overflow-visible" width={size} height={size}>
                            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor" strokeWidth={strokeWidth} className="text-gray-700" />
                            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} className="transition-all duration-500" />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                            <span className="text-xs font-bold text-white">{value.toFixed(0)}%</span>
                        </div>
                    </div>
                );
            };
            
            const getHealthColor = (score) => {
                if (score >= 80) return { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30', color: '#22c55e' };
                if (score >= 60) return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', color: '#eab308' };
                if (score >= 40) return { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', color: '#f97316' };
                return { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', color: '#ef4444' };
            };
            
            const formatLastUpdate = (date) => {
                if (!date) return '-';
                const now = new Date();
                const diff = Math.floor((now - new Date(date)) / 1000);
                if (diff < 10) return t('justNow') || 'just now';
                if (diff < 60) return `${diff}s ago`;
                if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
                return new Date(date).toLocaleTimeString();
            };
            
            const SortButton = ({ field, label }) => (
                <button
                    onClick={() => { setSortBy(field); setSortDir(sortBy === field && sortDir === 'asc' ? 'desc' : 'asc'); }}
                    className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${sortBy === field ? 'bg-proxmox-orange/20 text-proxmox-orange font-medium' : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'}`}
                >
                    {label} {sortBy === field && (sortDir === 'asc' ? '↑' : '↓')}
                </button>
            );
            
            // cluster card component
            const ClusterCard = ({ cluster }) => {
                const healthColors = getHealthColor(cluster.healthScore);
                const hasAlerts = cluster.alerts.length > 0;
                const errorCount = cluster.alerts.filter(a => a.type === 'error').length;
                
                return (
                    <div
                        onClick={() => onSelectCluster(cluster)}
                        className="group relative bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden cursor-pointer hover:border-proxmox-orange/50 transition-all duration-300 hover:shadow-lg hover:shadow-proxmox-orange/10"
                    >
                        <div className={`h-1.5 ${cluster.connected ? 'bg-gradient-to-r from-green-500 via-emerald-500 to-green-500' : 'bg-gradient-to-r from-red-500 via-red-600 to-red-500'}`} />
                        
                        <div className="p-5">
                            {/* Header */}
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <div className={`relative w-12 h-12 rounded-xl ${cluster.connected ? 'bg-gradient-to-br from-green-500/20 to-emerald-500/20' : 'bg-gradient-to-br from-red-500/20 to-red-600/20'} flex items-center justify-center`}>
                                        <Icons.Server className={`w-6 h-6 ${cluster.connected ? 'text-green-400' : 'text-red-400'}`} />
                                        {cluster.connected && <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full border-2 border-proxmox-card animate-pulse" />}
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-white text-base group-hover:text-proxmox-orange transition-colors">
                                            {cluster.display_name || cluster.name}
                                        </h3>
                                        <p className="text-xs text-gray-500">{cluster.host}</p>
                                    </div>
                                </div>
                                
                                <div className="flex items-center gap-2">
                                    {/* Alerts Badge */}
                                    {hasAlerts && (
                                        <div className="relative group/alerts">
                                            <div className={`px-2.5 py-1 rounded-lg flex items-center gap-1.5 ${errorCount > 0 ? 'bg-red-500/20 border border-red-500/30' : 'bg-yellow-500/20 border border-yellow-500/30'}`}>
                                                <Icons.AlertTriangle className={`w-3.5 h-3.5 ${errorCount > 0 ? 'text-red-400' : 'text-yellow-400'}`} />
                                                <span className={`text-xs font-medium ${errorCount > 0 ? 'text-red-400' : 'text-yellow-400'}`}>{cluster.alerts.length}</span>
                                            </div>
                                            {/* tooltip */}
                                            <div className="absolute right-0 top-full mt-1 z-50 hidden group-hover/alerts:block">
                                                <div className="bg-proxmox-dark border border-proxmox-border rounded-lg p-2 shadow-xl min-w-[160px]">
                                                    {cluster.alerts.map((alert, i) => (
                                                        <div key={i} className={`text-xs py-0.5 ${alert.type === 'error' ? 'text-red-400' : 'text-yellow-400'}`}>
                                                            • {alert.msg}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* Health Badge */}
                                    {cluster.connected && (
                                        <div className={`px-2.5 py-1 rounded-lg ${healthColors.bg} ${healthColors.border} border`}>
                                            <span className={`text-xs font-semibold ${healthColors.text}`}>{cluster.healthScore}%</span>
                                        </div>
                                    )}
                                    {!cluster.connected && (
                                        <div className="px-2.5 py-1 rounded-lg bg-red-500/20 border border-red-500/30">
                                            <span className="text-xs font-semibold text-red-400">Offline</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                            
                            {/* Stats Grid */}
                            {cluster.hasMetrics ? (
                                <div className="grid grid-cols-5 gap-3">
                                    {/* Nodes */}
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className={`text-xl font-bold ${cluster.onlineNodes === cluster.nodeCount ? 'text-green-400' : 'text-yellow-400'}`}>
                                            {cluster.onlineNodes}/{cluster.nodeCount}
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('nodes')}</div>
                                    </div>
                                    
                                    {/* CPU */}
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex flex-col items-center gap-1">
                                            <CircularProgress value={cluster.avgCpu} size={44} strokeWidth={4} color={cluster.avgCpu > 80 ? '#ef4444' : cluster.avgCpu > 60 ? '#eab308' : '#22c55e'} />
                                            <Sparkline data={cluster.cpuHistory} color={cluster.avgCpu > 80 ? '#ef4444' : '#22c55e'} height={14} width={40} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">CPU</div>
                                    </div>
                                    
                                    {/* RAM */}
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex flex-col items-center gap-1">
                                            <CircularProgress value={cluster.avgMem} size={44} strokeWidth={4} color={cluster.avgMem > 80 ? '#ef4444' : cluster.avgMem > 60 ? '#eab308' : '#3b82f6'} />
                                            <Sparkline data={cluster.ramHistory} color={cluster.avgMem > 80 ? '#ef4444' : '#3b82f6'} height={14} width={40} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">RAM</div>
                                    </div>
                                    
                                    {/* Storage */}
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="flex justify-center">
                                            <CircularProgress value={cluster.avgStorage} size={44} strokeWidth={4} color={cluster.avgStorage > 80 ? '#ef4444' : cluster.avgStorage > 60 ? '#eab308' : '#8b5cf6'} />
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('storage') || 'Disk'}</div>
                                    </div>
                                    
                                    {/* VMs */}
                                    <div className="text-center p-3 rounded-xl bg-proxmox-dark/50">
                                        <div className="text-xl font-bold">
                                            <span className="text-green-400">{cluster.runningVms}</span>
                                            <span className="text-gray-500 text-sm">/{cluster.totalVms}</span>
                                        </div>
                                        <div className="text-[10px] text-gray-500 uppercase mt-1">{t('vms')}</div>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex items-center justify-center h-20 text-gray-500 text-sm">
                                    <Icons.AlertTriangle className="w-4 h-4 mr-2" />
                                    {t('noDataAvailable') || 'No data available'}
                                </div>
                            )}
                            
                            {/* Footer */}
                            <div className="mt-4 pt-3 border-t border-proxmox-border/50 flex items-center justify-between">
                                <span className="text-xs text-gray-500">
                                    {t('updated') || 'Updated'}: {formatLastUpdate(cluster.lastUpdate)}
                                </span>
                                <Icons.ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-proxmox-orange transition-colors" />
                            </div>
                        </div>
                    </div>
                );
            };
            
            // LW: Feb 2026 - Corporate variant for AllClustersOverview
            if (isCorporate) {
                const corpBarColor = (val) => val > 80 ? '#f54f47' : val > 60 ? '#efc006' : '#60b515';
                return (
                    <div className="space-y-3">
                        {/* header */}
                        <div className="flex items-center justify-between pb-2" style={{borderBottom: '1px solid #485764'}}>
                            <div className="flex items-center gap-2">
                                <Icons.Grid className="w-4 h-4" style={{color: '#49afd9'}} />
                                <h2 className="text-[15px] font-semibold" style={{color: '#e9ecef'}}>{t('allClustersOverview') || 'All Clusters Overview'}</h2>
                            </div>
                            {totals.totalAlerts > 0 && (
                                <span className="text-[12px] flex items-center gap-1" style={{color: '#f54f47'}}>
                                    <Icons.AlertTriangle className="w-3.5 h-3.5" /> {totals.totalAlerts} {t('alerts') || 'alerts'}
                                </span>
                            )}
                        </div>

                        {/* stats bar */}
                        <div className="flex items-center gap-0 flex-wrap text-[13px] px-2 py-2" style={{background: '#22343c', border: '1px solid #485764'}}>
                            <span style={{color: '#adbbc4'}}>{t('clusters')}: <b style={{color: '#e9ecef'}}>{totals.connectedClusters}/{totals.clusters}</b> online</span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>{t('nodes')}: <b style={{color: '#e9ecef'}}>{totals.onlineNodes}/{totals.totalNodes}</b></span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>VMs: <b style={{color: '#60b515'}}>{totals.runningVms}</b> {t('running')?.toLowerCase()}, <b style={{color: '#728b9a'}}>{totals.totalVms - totals.runningVms}</b> {t('stopped')?.toLowerCase()}</span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>CPU: <b style={{color: corpBarColor(totals.avgCpu)}}>{totals.avgCpu.toFixed(0)}%</b></span>
                            <span className="inline-block mx-1" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative', verticalAlign: 'middle'}}>
                                <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(totals.avgCpu, 100)}%`, background: corpBarColor(totals.avgCpu)}} />
                            </span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>RAM: <b style={{color: corpBarColor(totals.avgMem)}}>{totals.avgMem.toFixed(0)}%</b></span>
                            <span className="inline-block mx-1" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative', verticalAlign: 'middle'}}>
                                <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(totals.avgMem, 100)}%`, background: corpBarColor(totals.avgMem)}} />
                            </span>
                            <span style={{color: '#485764', margin: '0 8px'}}>|</span>
                            <span style={{color: '#adbbc4'}}>{t('storage') || 'Storage'}: <b style={{color: corpBarColor(totals.avgStorage)}}>{totals.avgStorage.toFixed(0)}%</b></span>
                            <span className="inline-block mx-1" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative', verticalAlign: 'middle'}}>
                                <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(totals.avgStorage, 100)}%`, background: corpBarColor(totals.avgStorage)}} />
                            </span>
                        </div>

                        {/* cluster table */}
                        <table className="corp-datagrid">
                            <thead>
                                <tr>
                                    {[
                                        { field: 'name', label: t('name') || 'Name' },
                                        { field: null, label: t('status') || 'Status' },
                                        { field: 'nodes', label: t('nodes') || 'Nodes' },
                                        { field: 'vms', label: 'VMs' },
                                        { field: 'cpu', label: 'CPU' },
                                        { field: 'ram', label: 'RAM' },
                                        { field: null, label: t('storage') || 'Storage' },
                                        { field: 'health', label: t('health') || 'Health' },
                                    ].map((col, i) => (
                                        <th key={i}
                                            className={col.field ? 'cursor-pointer hover:text-white' : ''}
                                            onClick={col.field ? () => { setSortBy(col.field); setSortDir(sortBy === col.field && sortDir === 'asc' ? 'desc' : 'asc'); } : undefined}
                                            style={{textAlign: 'left'}}
                                        >
                                            {col.label} {sortBy === col.field && <span className="sort-indicator">{sortDir === 'asc' ? '▲' : '▼'}</span>}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {sortedStats.map(cluster => {
                                    const hc = getHealthColor(cluster.healthScore);
                                    return (
                                        <tr key={cluster.id} className="table-row-hover cursor-pointer" onClick={() => onSelectCluster(cluster)}>
                                            <td style={{fontWeight: 500}}>{cluster.display_name || cluster.name}</td>
                                            <td>
                                                <span className="inline-flex items-center gap-1.5">
                                                    <span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: cluster.connected ? '#60b515' : '#f54f47'}} />
                                                    <span style={{color: cluster.connected ? '#60b515' : '#f54f47', fontSize: '12px'}}>{cluster.connected ? 'online' : 'offline'}</span>
                                                </span>
                                            </td>
                                            <td>{cluster.onlineNodes}/{cluster.nodeCount}</td>
                                            <td>
                                                <span style={{color: '#60b515'}}>{cluster.runningVms}</span>
                                                <span style={{color: '#728b9a'}}> / {cluster.totalVms - cluster.runningVms}</span>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgCpu), minWidth: '28px'}}>{cluster.avgCpu.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgCpu, 100)}%`, background: corpBarColor(cluster.avgCpu)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgMem), minWidth: '28px'}}>{cluster.avgMem.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgMem, 100)}%`, background: corpBarColor(cluster.avgMem)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1.5">
                                                    <span style={{color: corpBarColor(cluster.avgStorage), minWidth: '28px'}}>{cluster.avgStorage.toFixed(0)}%</span>
                                                    <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                        <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cluster.avgStorage, 100)}%`, background: corpBarColor(cluster.avgStorage)}} />
                                                    </span>
                                                </div>
                                            </td>
                                            <td><span style={{color: hc.color, fontWeight: 500}}>{cluster.healthScore}%</span></td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>

                        {/* top resources */}
                        {topGuests.length > 0 && (
                            <div>
                                <div className="flex items-center gap-2 py-1.5" style={{borderBottom: '1px solid #485764'}}>
                                    <Icons.Activity className="w-3.5 h-3.5" style={{color: '#49afd9'}} />
                                    <span className="text-[13px] font-semibold" style={{color: '#adbbc4'}}>{t('topResources') || 'Top Resources'}</span>
                                    <span className="text-[11px]" style={{color: '#728b9a'}}>Top 10</span>
                                </div>
                                <table className="corp-datagrid">
                                    <thead>
                                        <tr>
                                            <th style={{width: '24px'}}></th>
                                            <th>{t('name')}</th>
                                            <th>{t('cluster')}</th>
                                            <th>{t('node')}</th>
                                            <th>CPU</th>
                                            <th>RAM</th>
                                            <th>{t('status')}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {topGuests.map((guest) => {
                                            const cpuP = ((guest.cpu || 0) * 100).toFixed(1);
                                            const memP = guest.maxmem > 0 ? ((guest.mem / guest.maxmem) * 100).toFixed(1) : 0;
                                            const gc = clusters.find(c => c.id === guest.cluster_id);
                                            return (
                                                <tr key={`${guest.cluster_id}-${guest.vmid}`} className="table-row-hover cursor-pointer"
                                                    onClick={() => { if (gc && onSelectVm) onSelectVm(gc, guest.vmid, guest.node); }}>
                                                    <td>
                                                        <Icons.Monitor className="w-3.5 h-3.5" style={{color: guest.type === 'qemu' ? '#49afd9' : '#a178d9'}} />
                                                    </td>
                                                    <td>
                                                        <span style={{fontWeight: 500}}>{guest.name || `VM ${guest.vmid}`}</span>
                                                        <span style={{color: '#728b9a', fontSize: '11px', marginLeft: '6px'}}>#{guest.vmid}</span>
                                                    </td>
                                                    <td>{guest.cluster_name}</td>
                                                    <td style={{color: '#adbbc4'}}>{guest.node}</td>
                                                    <td>
                                                        <div className="flex items-center gap-1.5">
                                                            <span style={{color: corpBarColor(cpuP), minWidth: '32px'}}>{cpuP}%</span>
                                                            <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                                <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(cpuP, 100)}%`, background: corpBarColor(cpuP)}} />
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <div className="flex items-center gap-1.5">
                                                            <span style={{color: corpBarColor(memP), minWidth: '32px'}}>{memP}%</span>
                                                            <span className="inline-block" style={{width: '40px', height: '2px', background: '#37474f', position: 'relative'}}>
                                                                <span style={{position: 'absolute', left: 0, top: 0, height: '2px', width: `${Math.min(memP, 100)}%`, background: corpBarColor(memP)}} />
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <span className="inline-flex items-center gap-1">
                                                            <span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: guest.status === 'running' ? '#60b515' : '#728b9a'}} />
                                                            <span style={{color: guest.status === 'running' ? '#60b515' : '#728b9a', fontSize: '12px'}}>{guest.status === 'running' ? t('running') : t('stopped')}</span>
                                                        </span>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {clusters.length === 0 && (
                            <div className="py-8 text-center text-[13px]" style={{color: '#728b9a'}}>
                                <Icons.Server className="w-6 h-6 mx-auto mb-2" style={{color: '#485764'}} />
                                {t('noClustersConfigured') || 'No clusters configured'}
                            </div>
                        )}
                    </div>
                );
            }

            // Modern layout (original)
            return (
                <div className="space-y-6">
                    {/* Header */}
                    <div className="relative overflow-hidden bg-gradient-to-r from-proxmox-card via-proxmox-dark to-proxmox-card border border-proxmox-border rounded-2xl p-6">
                        <div className="absolute inset-0 bg-gradient-to-r from-proxmox-orange/5 via-transparent to-blue-500/5" />
                        <div className="relative flex items-center justify-between flex-wrap gap-4">
                            <div className="flex items-center gap-4">
                                <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-proxmox-orange to-orange-600 flex items-center justify-center shadow-lg shadow-orange-500/20">
                                    <Icons.Grid className="w-7 h-7 text-white" />
                                </div>
                                <div>
                                    <h1 className="text-2xl font-bold text-white">{t('allClustersOverview') || 'All Clusters Overview'}</h1>
                                    <p className="text-gray-400 text-sm">{t('multiClusterSummary') || 'Summary of all managed clusters'}</p>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                {/* alerts */}
                                {totals.totalAlerts > 0 && (
                                    <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded-lg">
                                        <Icons.AlertTriangle className="w-4 h-4 text-red-400" />
                                        <span className="text-sm text-red-400 font-medium">{totals.totalAlerts} {t('alerts') || 'Alerts'}</span>
                                    </div>
                                )}

                                {/* Live indicator */}
                                <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-full">
                                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                    <span className="text-xs text-green-400 font-medium">Live</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
                        {[
                            { icon: Icons.Server, value: `${totals.connectedClusters}/${totals.clusters}`, label: t('clusters'), color: 'proxmox-orange', hoverColor: 'proxmox-orange' },
                            { icon: Icons.Cpu, value: `${totals.onlineNodes}/${totals.totalNodes}`, label: t('nodesOnline') || 'Nodes', color: 'blue-400', hoverColor: 'blue-500' },
                            { icon: Icons.Play, value: totals.runningVms, label: t('vmsRunning') || 'Running', color: 'green-400', hoverColor: 'green-500', valueColor: 'text-green-400' },
                            { icon: Icons.Square, value: totals.totalVms - totals.runningVms, label: t('vmsStopped') || 'Stopped', color: 'gray-400', hoverColor: 'gray-500' },
                        ].map((stat, i) => (
                            <div key={i} className={`bg-gradient-to-br from-proxmox-card to-proxmox-dark border border-proxmox-border rounded-xl p-4 hover:border-${stat.hoverColor}/30 transition-all group`}>
                                <div className="flex items-center gap-3">
                                    <div className={`w-10 h-10 rounded-lg bg-${stat.color}/20 flex items-center justify-center group-hover:scale-110 transition-transform`}>
                                        <stat.icon className={`w-5 h-5 text-${stat.color}`} />
                                    </div>
                                    <div>
                                        <div className={`text-xl font-bold ${stat.valueColor || 'text-white'}`}>{stat.value}</div>
                                        <div className="text-xs text-gray-500">{stat.label}</div>
                                    </div>
                                </div>
                            </div>
                        ))}

                        {/* circular gauges */}
                        {[
                            { value: totals.avgCpu, label: 'CPU', color: totals.avgCpu > 80 ? '#ef4444' : totals.avgCpu > 60 ? '#eab308' : '#22c55e' },
                            { value: totals.avgMem, label: 'RAM', color: totals.avgMem > 80 ? '#ef4444' : totals.avgMem > 60 ? '#eab308' : '#3b82f6' },
                            { value: totals.avgStorage, label: t('storage') || 'Disk', color: totals.avgStorage > 80 ? '#ef4444' : totals.avgStorage > 60 ? '#eab308' : '#8b5cf6' },
                        ].map((stat, i) => (
                            <div key={i} className="bg-gradient-to-br from-proxmox-card to-proxmox-dark border border-proxmox-border rounded-xl p-4 hover:border-proxmox-border transition-all">
                                <div className="flex items-center gap-3">
                                    <CircularProgress value={stat.value || 0} size={44} strokeWidth={4} color={stat.color} />
                                    <div>
                                        <div className="text-sm font-bold text-white">{stat.label}</div>
                                        <div className="text-xs text-gray-500">{t('average') || 'Avg'}</div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Sort Controls */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm text-gray-500 mr-1">{t('sortBy') || 'Sort by'}:</span>
                            <SortButton field="name" label={t('name') || 'Name'} />
                            <SortButton field="health" label={t('health') || 'Health'} />
                            <SortButton field="nodes" label={t('nodes') || 'Nodes'} />
                            <SortButton field="vms" label="VMs" />
                            <SortButton field="cpu" label="CPU" />
                            <SortButton field="ram" label="RAM" />
                        </div>
                    </div>

                    {/* Grouped Clusters */}
                    {Object.values(groupedClusters).map(({ group, clusters: groupClusters }) => (
                        <div key={group.id} className="space-y-4">
                            <div className="flex items-center gap-3 px-1">
                                <div className="w-4 h-4 rounded" style={{ backgroundColor: group.color || '#E86F2D' }} />
                                <h3 className="text-base font-semibold text-white">{group.name}</h3>
                                <span className="text-sm text-gray-500">({groupClusters.length} {t('clusters')})</span>
                            </div>
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {groupClusters.map(cluster => <ClusterCard key={cluster.id} cluster={cluster} />)}
                            </div>
                        </div>
                    ))}

                    {/* Ungrouped Clusters */}
                    {ungroupedClusters.length > 0 && (
                        <div className="space-y-4">
                            {Object.keys(groupedClusters).length > 0 && (
                                <div className="flex items-center gap-3 px-1">
                                    <Icons.Folder className="w-4 h-4 text-gray-500" />
                                    <h3 className="text-base font-semibold text-white">{t('ungrouped') || 'Ungrouped'}</h3>
                                    <span className="text-sm text-gray-500">({ungroupedClusters.length})</span>
                                </div>
                            )}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {ungroupedClusters.map(cluster => <ClusterCard key={cluster.id} cluster={cluster} />)}
                            </div>
                        </div>
                    )}

                    {/* top vms table */}
                    {topGuests.length > 0 && (
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                            <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                                        <Icons.Activity className="w-5 h-5 text-cyan-400" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-white">{t('topResources') || 'Top Resources'}</h3>
                                        <p className="text-xs text-gray-500">{t('highestCpuUsage') || 'Highest CPU and RAM usage across all clusters'}</p>
                                    </div>
                                </div>
                                <span className="text-xs text-gray-500 bg-proxmox-dark px-2 py-1 rounded">Top 10</span>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead className="bg-proxmox-dark/50">
                                        <tr className="text-left text-xs text-gray-400">
                                            <th className="px-4 py-3 font-medium">{t('type')}</th>
                                            <th className="px-4 py-3 font-medium">{t('name')}</th>
                                            <th className="px-4 py-3 font-medium">{t('cluster')}</th>
                                            <th className="px-4 py-3 font-medium">{t('node')}</th>
                                            <th className="px-4 py-3 font-medium">CPU</th>
                                            <th className="px-4 py-3 font-medium">RAM</th>
                                            <th className="px-4 py-3 font-medium">{t('status')}</th>
                                            <th className="px-4 py-3 w-10"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-proxmox-border/50">
                                        {topGuests.map((guest, idx) => {
                                            const cpuPercent = ((guest.cpu || 0) * 100).toFixed(1);
                                            const memPercent = guest.maxmem > 0 ? ((guest.mem / guest.maxmem) * 100).toFixed(1) : 0;
                                            const isVM = guest.type === 'qemu';
                                            const guestCluster = clusters.find(c => c.id === guest.cluster_id);

                                            return (
                                                <tr
                                                    key={`${guest.cluster_id}-${guest.vmid}`}
                                                    className="hover:bg-proxmox-hover/50 transition-colors cursor-pointer group"
                                                    onClick={() => {
                                                        if (guestCluster && onSelectVm) {
                                                            onSelectVm(guestCluster, guest.vmid, guest.node);
                                                        }
                                                    }}
                                                    title={t('clickToOpenVm') || 'Click to open VM'}
                                                >
                                                    <td className="px-4 py-3">
                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isVM ? 'bg-blue-500/20' : 'bg-purple-500/20'}`}>
                                                            {isVM ? (
                                                                <Icons.Monitor className="w-4 h-4 text-blue-400" />
                                                            ) : (
                                                                <Icons.Layers className="w-4 h-4 text-purple-400" />
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <div className="font-medium text-white group-hover:text-proxmox-orange transition-colors">{guest.name || `VM ${guest.vmid}`}</div>
                                                        <div className="text-xs text-gray-500">ID: {guest.vmid}</div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className="text-sm text-gray-300">{guest.cluster_name}</span>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className="text-sm text-gray-400">{guest.node}</span>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-16 h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                                <div
                                                                    className={`h-full rounded-full transition-all ${cpuPercent > 80 ? 'bg-red-500' : cpuPercent > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                                    style={{ width: `${Math.min(cpuPercent, 100)}%` }}
                                                                />
                                                            </div>
                                                            <span className={`text-xs font-medium ${cpuPercent > 80 ? 'text-red-400' : cpuPercent > 60 ? 'text-yellow-400' : 'text-green-400'}`}>
                                                                {cpuPercent}%
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-16 h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                                <div
                                                                    className={`h-full rounded-full transition-all ${memPercent > 80 ? 'bg-red-500' : memPercent > 60 ? 'bg-yellow-500' : 'bg-blue-500'}`}
                                                                    style={{ width: `${Math.min(memPercent, 100)}%` }}
                                                                />
                                                            </div>
                                                            <span className="text-xs text-gray-400">{memPercent}%</span>
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
                                                            guest.status === 'running' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                                                        }`}>
                                                            <div className={`w-1.5 h-1.5 rounded-full ${guest.status === 'running' ? 'bg-green-400' : 'bg-gray-400'}`} />
                                                            {guest.status === 'running' ? t('running') : t('stopped')}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <Icons.ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-proxmox-orange transition-colors" />
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Empty State */}
                    {clusters.length === 0 && (
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-12 text-center">
                            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-proxmox-orange/20 to-orange-600/20 flex items-center justify-center">
                                <Icons.Server className="w-8 h-8 text-proxmox-orange" />
                            </div>
                            <h3 className="text-lg font-semibold text-white mb-2">{t('noClustersConfigured') || 'No clusters configured'}</h3>
                            <p className="text-gray-500 text-sm">{t('addClusterToStart') || 'Add a cluster to get started'}</p>
                        </div>
                    )}
                </div>
            );
        }

        // NS: Feb 2026 - Group Settings Modal
        // settings + cross-cluster LB config for a specific group
        function GroupSettingsModal({ group, groupClusters = [], authFetch, addToast, onClose, onSave }) {
            const { t } = useTranslation();
            const [activeTab, setActiveTab] = useState('general');
            const [saving, setSaving] = useState(false);

            // Storage/bridge intersection state for cross-cluster LB dropdowns
            const [commonStorages, setCommonStorages] = useState([]);
            const [commonBridges, setCommonBridges] = useState([]);
            const [loadingResources, setLoadingResources] = useState(false);

            // Excluded VMs state per cluster
            const [excludedVMsByCluster, setExcludedVMsByCluster] = useState({});
            const [allVMsByCluster, setAllVMsByCluster] = useState({});
            const [loadingExcludedVMs, setLoadingExcludedVMs] = useState(false);
            const [expandedClusters, setExpandedClusters] = useState({});

            // Cross-cluster replication state
            const [xReplJobs, setXReplJobs] = useState([]);
            const [xReplLoading, setXReplLoading] = useState(false);
            const [showCreateXRepl, setShowCreateXRepl] = useState(false);
            const [xReplForm, setXReplForm] = useState({ source_cluster: '', vmid: '', vm_type: 'qemu', target_cluster: '', target_storage: '', target_bridge: 'vmbr0', schedule: '0 */6 * * *', retention: 3 });
            const [xReplSourceVMs, setXReplSourceVMs] = useState([]);
            const [xReplLoadingVMs, setXReplLoadingVMs] = useState(false);
            const [xReplTargetStorages, setXReplTargetStorages] = useState([]);
            const [xReplTargetBridges, setXReplTargetBridges] = useState([]);
            const [xReplLoadingResources, setXReplLoadingResources] = useState(false);

            // form state - init from group data
            // NS: field names must match DB column names exactly (cross_cluster_*)
            const [form, setForm] = useState({
                name: group.name || '',
                description: group.description || '',
                color: group.color || '#E86F2D',
                // cross-cluster LB fields - column names from cluster_groups table
                cross_cluster_lb_enabled: group.cross_cluster_lb_enabled || false,
                cross_cluster_threshold: group.cross_cluster_threshold || 30,
                cross_cluster_interval: group.cross_cluster_interval || 600,
                cross_cluster_dry_run: group.cross_cluster_dry_run !== undefined ? group.cross_cluster_dry_run : true,
                cross_cluster_target_storage: group.cross_cluster_target_storage || '',
                cross_cluster_target_bridge: group.cross_cluster_target_bridge || 'vmbr0',
                cross_cluster_max_migrations: group.cross_cluster_max_migrations || 1,
                cross_cluster_include_containers: group.cross_cluster_include_containers || false,
            });

            // Fetch storage/bridge lists from ALL clusters in group, compute intersection
            useEffect(() => {
                if (activeTab !== 'lb' || !form.cross_cluster_lb_enabled || groupClusters.length === 0 || !authFetch) return;

                let cancelled = false;

                const fetchAllClusterResources = async () => {
                    setLoadingResources(true);
                    const allStorageSets = [];
                    const allStorageInfo = {};
                    const allBridgeSets = [];
                    const allBridgeInfo = {};

                    for (const cluster of groupClusters) {
                        if (!cluster.connected) continue;
                        try {
                            const nodesRes = await authFetch(`${API_URL}/clusters/${cluster.id}/nodes`);
                            if (!nodesRes || !nodesRes.ok) continue;
                            const nodes = await nodesRes.json();
                            const onlineNode = nodes.find(n => n.status === 'online') || nodes[0];
                            if (!onlineNode) continue;
                            const nodeName = onlineNode.node;

                            const storageRes = await authFetch(`${API_URL}/clusters/${cluster.id}/nodes/${nodeName}/storage`);
                            if (storageRes && storageRes.ok) {
                                const storages = await storageRes.json();
                                const names = new Set();
                                storages.forEach(s => {
                                    names.add(s.storage);
                                    allStorageInfo[s.storage] = { storage: s.storage, type: s.type || 'unknown', content: s.content || '' };
                                });
                                allStorageSets.push(names);
                            }

                            const networkRes = await authFetch(`${API_URL}/clusters/${cluster.id}/nodes/${nodeName}/networks`);
                            if (networkRes && networkRes.ok) {
                                const networks = await networkRes.json();
                                const names = new Set();
                                networks.filter(n => n.type === 'bridge' || n.type === 'OVSBridge' || n.source === 'sdn').forEach(b => {
                                    names.add(b.iface);
                                    allBridgeInfo[b.iface] = { iface: b.iface, type: b.type, source: b.source || 'local', comments: b.comments || '', zone: b.zone || '', alias: b.alias || '' };
                                });
                                allBridgeSets.push(names);
                            }
                        } catch (err) {
                            console.error(`Failed to fetch resources for cluster ${cluster.id}:`, err);
                        }
                    }

                    if (cancelled) return;

                    if (allStorageSets.length > 0) {
                        const intersection = [...allStorageSets[0]].filter(name => allStorageSets.every(set => set.has(name)));
                        setCommonStorages(intersection.map(name => allStorageInfo[name]).filter(Boolean));
                    } else {
                        setCommonStorages([]);
                    }

                    if (allBridgeSets.length > 0) {
                        const intersection = [...allBridgeSets[0]].filter(name => allBridgeSets.every(set => set.has(name)));
                        setCommonBridges(intersection.map(name => allBridgeInfo[name]).filter(Boolean));
                    } else {
                        setCommonBridges([]);
                    }

                    setLoadingResources(false);
                };

                fetchAllClusterResources();
                return () => { cancelled = true; };
            }, [activeTab, form.cross_cluster_lb_enabled, groupClusters.length]);

            // Fetch excluded VMs for all clusters in group
            useEffect(() => {
                if (activeTab !== 'lb' || !form.cross_cluster_lb_enabled || groupClusters.length === 0 || !authFetch) return;
                let cancelled = false;
                const fetchExcludedVMs = async () => {
                    setLoadingExcludedVMs(true);
                    const excluded = {};
                    const allVMs = {};
                    for (const cluster of groupClusters) {
                        if (!cluster.connected) continue;
                        try {
                            const [exRes, vmRes] = await Promise.all([
                                authFetch(`${API_URL}/clusters/${cluster.id}/excluded-vms`),
                                authFetch(`${API_URL}/clusters/${cluster.id}/vms`)
                            ]);
                            if (!cancelled && exRes.ok) {
                                const exData = await exRes.json();
                                excluded[cluster.id] = exData.excluded_vms || [];
                            }
                            if (!cancelled && vmRes.ok) {
                                const vmData = await vmRes.json();
                                allVMs[cluster.id] = vmData.vms || vmData || [];
                            }
                        } catch (err) {
                            console.error(`Error fetching excluded VMs for cluster ${cluster.id}:`, err);
                        }
                    }
                    if (!cancelled) {
                        setExcludedVMsByCluster(excluded);
                        setAllVMsByCluster(allVMs);
                        setLoadingExcludedVMs(false);
                    }
                };
                fetchExcludedVMs();
                return () => { cancelled = true; };
            }, [activeTab, form.cross_cluster_lb_enabled, groupClusters.length]);

            const excludeVM = async (clusterId, vmid, vmName) => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/excluded-vms/${vmid}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ reason: 'Excluded via cross-cluster LB settings' })
                    });
                    if (res.ok) {
                        setExcludedVMsByCluster(prev => ({
                            ...prev,
                            [clusterId]: [...(prev[clusterId] || []), { vmid, name: vmName }]
                        }));
                    }
                } catch (e) {
                    console.error(e);
                }
            };

            const includeVM = async (clusterId, vmid) => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/excluded-vms/${vmid}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        setExcludedVMsByCluster(prev => ({
                            ...prev,
                            [clusterId]: (prev[clusterId] || []).filter(v => v.vmid !== vmid)
                        }));
                    }
                } catch (e) {
                    console.error(e);
                }
            };

            // NS: Fetch cross-cluster replication jobs for this group
            const groupClusterIds = groupClusters.map(c => c.id);
            const fetchXReplJobs = async () => {
                setXReplLoading(true);
                try {
                    const res = await authFetch(`${API_URL}/cross-cluster-replications`);
                    if (res && res.ok) {
                        const all = await res.json();
                        setXReplJobs(all.filter(j => groupClusterIds.includes(j.source_cluster) || groupClusterIds.includes(j.target_cluster)));
                    }
                } catch (e) { console.error('xrepl fetch:', e); }
                setXReplLoading(false);
            };

            useEffect(() => {
                if (activeTab !== 'replication' || !authFetch) return;
                fetchXReplJobs();
            }, [activeTab]);

            // NS: Fetch VMs when source cluster changes
            useEffect(() => {
                if (!xReplForm.source_cluster || !authFetch) return;
                let cancelled = false;
                const fetchVMs = async () => {
                    setXReplLoadingVMs(true);
                    setXReplSourceVMs([]);
                    try {
                        const res = await authFetch(`${API_URL}/clusters/${xReplForm.source_cluster}/vms`);
                        if (!cancelled && res && res.ok) {
                            const data = await res.json();
                            setXReplSourceVMs(data.vms || data || []);
                        }
                    } catch (e) { console.error('xrepl source vms:', e); }
                    if (!cancelled) setXReplLoadingVMs(false);
                };
                fetchVMs();
                return () => { cancelled = true; };
            }, [xReplForm.source_cluster]);

            // NS: Fetch target cluster storages/bridges when target cluster changes
            useEffect(() => {
                if (!xReplForm.target_cluster || !authFetch) return;
                let cancelled = false;
                const fetchTargetResources = async () => {
                    setXReplLoadingResources(true);
                    setXReplTargetStorages([]);
                    setXReplTargetBridges([]);
                    try {
                        const nodesRes = await authFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes`);
                        if (!nodesRes || !nodesRes.ok || cancelled) return;
                        const nodesData = await nodesRes.json();
                        const onlineNode = (Array.isArray(nodesData) ? nodesData : nodesData.nodes || []).find(n => n.status === 'online');
                        if (!onlineNode || cancelled) return;
                        const nodeName = onlineNode.node || onlineNode.name;
                        const [storRes, netRes] = await Promise.all([
                            authFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes/${nodeName}/storage`),
                            authFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes/${nodeName}/networks`)
                        ]);
                        if (cancelled) return;
                        if (storRes && storRes.ok) {
                            const storData = await storRes.json();
                            setXReplTargetStorages((Array.isArray(storData) ? storData : storData.storages || [])
                                .filter(s => s.content && (s.content.includes('images') || s.content.includes('rootdir'))));
                        }
                        if (netRes && netRes.ok) {
                            const netData = await netRes.json();
                            setXReplTargetBridges((Array.isArray(netData) ? netData : netData.networks || [])
                                .filter(n => n.type === 'bridge' || n.type === 'OVSBridge' || n.source === 'sdn'));
                        }
                    } catch (err) { console.error('xrepl target resources:', err); }
                    if (!cancelled) setXReplLoadingResources(false);
                };
                fetchTargetResources();
                return () => { cancelled = true; };
            }, [xReplForm.target_cluster]);

            // NS: Cross-cluster replication handlers
            const handleCreateXRepl = async () => {
                try {
                    const res = await authFetch(`${API_URL}/cross-cluster-replications`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            source_cluster: xReplForm.source_cluster,
                            target_cluster: xReplForm.target_cluster,
                            vmid: parseInt(xReplForm.vmid),
                            vm_type: xReplForm.vm_type || 'qemu',
                            target_storage: xReplForm.target_storage,
                            target_bridge: xReplForm.target_bridge,
                            schedule: xReplForm.schedule,
                            retention: parseInt(xReplForm.retention) || 3,
                        })
                    });
                    if (res && res.ok) {
                        if (addToast) addToast(t('xReplCreated') || 'Replication job created', 'success');
                        setShowCreateXRepl(false);
                        setXReplForm({ source_cluster: '', vmid: '', vm_type: 'qemu', target_cluster: '', target_storage: '', target_bridge: 'vmbr0', schedule: '0 */6 * * *', retention: 3 });
                        await fetchXReplJobs();
                    } else if (res) {
                        const err = await res.json();
                        if (addToast) addToast(err.error || t('xReplCreateFailed') || 'Failed to create replication job', 'error');
                    }
                } catch (e) {
                    if (addToast) addToast(t('connectionError') || 'Connection error', 'error');
                }
            };

            const handleDeleteXRepl = async (jobId) => {
                if (!confirm(t('confirmDeleteXRepl') || 'Delete this replication job?')) return;
                try {
                    const res = await authFetch(`${API_URL}/cross-cluster-replications/${jobId}`, { method: 'DELETE' });
                    if (res && res.ok) {
                        if (addToast) addToast(t('xReplDeleted') || 'Replication job deleted', 'success');
                        await fetchXReplJobs();
                    } else if (res) {
                        const err = await res.json();
                        if (addToast) addToast(err.error || t('xReplDeleteFailed') || 'Failed to delete', 'error');
                    }
                } catch (e) {
                    if (addToast) addToast(t('connectionError') || 'Connection error', 'error');
                }
            };

            const handleRunXReplNow = async (jobId) => {
                try {
                    const res = await authFetch(`${API_URL}/cross-cluster-replications/${jobId}/run`, { method: 'POST' });
                    if (res && res.ok) {
                        if (addToast) addToast(t('xReplStarted') || 'Replication started', 'success');
                    } else if (res) {
                        const err = await res.json();
                        if (addToast) addToast(err.error || t('xReplStartFailed') || 'Failed to start', 'error');
                    }
                } catch (e) {
                    if (addToast) addToast(t('connectionError') || 'Connection error', 'error');
                }
            };

            const handleSave = async () => {
                if (!form.name.trim()) return;
                setSaving(true);
                await onSave(form);
                setSaving(false);
            };

            // MK: tab config
            const tabs = [
                { id: 'general', label: t('general') || 'General', icon: Icons.Settings },
                { id: 'lb', label: t('crossClusterLB') || 'Cross-Cluster LB', icon: Icons.Scale },
                { id: 'replication', label: t('crossClusterReplication') || 'Replication', icon: Icons.Globe },
                { id: 'info', label: t('info') || 'Info', icon: Icons.Info },
            ];

            return (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto">
                        {/* Header */}
                        <div className="flex items-center justify-between p-5 border-b border-proxmox-border">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: (form.color || '#E86F2D') + '33' }}>
                                    <Icons.Folder className="w-5 h-5" style={{ color: form.color || '#E86F2D' }} />
                                </div>
                                <div>
                                    <h2 className="text-lg font-semibold text-white">{t('groupSettings') || 'Group Settings'}</h2>
                                    <p className="text-xs text-gray-500">{group.name}</p>
                                </div>
                            </div>
                            <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
                                <Icons.X />
                            </button>
                        </div>

                        {/* Tabs */}
                        <div className="flex border-b border-proxmox-border">
                            {tabs.map(tab => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
                                        activeTab === tab.id
                                            ? 'text-proxmox-orange border-b-2 border-proxmox-orange bg-proxmox-dark/50'
                                            : 'text-gray-400 hover:text-white hover:bg-proxmox-dark/30'
                                    }`}
                                >
                                    <tab.icon className="w-4 h-4" />
                                    {tab.label}
                                </button>
                            ))}
                        </div>

                        {/* Tab Content */}
                        <div className="p-5">
                            {activeTab === 'general' && (
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'} *</label>
                                        <input
                                            value={form.name}
                                            onChange={e => setForm(p => ({...p, name: e.target.value}))}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                            placeholder="Production Cluster Group"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('description') || 'Description'}</label>
                                        <textarea
                                            value={form.description}
                                            onChange={e => setForm(p => ({...p, description: e.target.value}))}
                                            rows={3}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange resize-none"
                                            placeholder="Optional description for this group..."
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('color') || 'Color'}</label>
                                        <div className="flex items-center gap-3">
                                            <input
                                                type="color"
                                                value={form.color}
                                                onChange={e => setForm(p => ({...p, color: e.target.value}))}
                                                className="w-10 h-10 rounded cursor-pointer border border-proxmox-border"
                                            />
                                            <input
                                                type="text"
                                                value={form.color}
                                                onChange={e => setForm(p => ({...p, color: e.target.value}))}
                                                className="w-28 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono focus:outline-none focus:border-proxmox-orange"
                                                placeholder="#E86F2D"
                                            />
                                            {/* LW: quick presets */}
                                            <div className="flex gap-1.5">
                                                {['#E86F2D', '#3B82F6', '#22C55E', '#EAB308', '#8B5CF6', '#EC4899'].map(c => (
                                                    <button
                                                        key={c}
                                                        onClick={() => setForm(p => ({...p, color: c}))}
                                                        className={`w-6 h-6 rounded-full border-2 transition-all ${form.color === c ? 'border-white scale-110' : 'border-transparent hover:border-gray-500'}`}
                                                        style={{ backgroundColor: c }}
                                                    />
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {activeTab === 'lb' && (
                                <div className="space-y-5">
                                    {/* enable toggle */}
                                    <div className="flex items-center justify-between p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                        <div>
                                            <h4 className="text-sm font-medium text-white">{t('enableCrossClusterLB') || 'Enable Cross-Cluster Load Balancing'}</h4>
                                            <p className="text-xs text-gray-500 mt-0.5">{t('lbDescription') || 'Automatically migrate VMs between clusters when resource thresholds are exceeded'}</p>
                                        </div>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={form.cross_cluster_lb_enabled}
                                                onChange={e => setForm(p => ({...p, cross_cluster_lb_enabled: e.target.checked}))}
                                                className="sr-only peer"
                                            />
                                            <div className="w-11 h-6 bg-gray-600 peer-checked:bg-proxmox-orange rounded-full peer-focus:ring-2 peer-focus:ring-proxmox-orange/50 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full"></div>
                                        </label>
                                    </div>

                                    {form.cross_cluster_lb_enabled && (
                                        <div className="space-y-4">
                                            {/* Dry run toggle */}
                                            <div className="flex items-center justify-between p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
                                                <div className="flex items-center gap-2">
                                                    <Icons.AlertTriangle className="w-4 h-4 text-yellow-400" />
                                                    <div>
                                                        <span className="text-sm text-yellow-300">{t('dryRunMode') || 'Dry Run / Simulation Mode'}</span>
                                                        <p className="text-xs text-gray-500">{t('dryRunDesc') || 'Log what would happen without actually migrating'}</p>
                                                    </div>
                                                </div>
                                                <label className="relative inline-flex items-center cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={form.cross_cluster_dry_run}
                                                        onChange={e => setForm(p => ({...p, cross_cluster_dry_run: e.target.checked}))}
                                                        className="sr-only peer"
                                                    />
                                                    <div className="w-11 h-6 bg-gray-600 peer-checked:bg-yellow-500 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full"></div>
                                                </label>
                                            </div>

                                            <Slider
                                                label={t('cpuThreshold') || 'CPU Threshold (%)'}
                                                description={t('crossClusterThresholdDesc') || 'CPU threshold for cluster imbalance (10-80%)'}
                                                value={form.cross_cluster_threshold}
                                                onChange={v => setForm(p => ({...p, cross_cluster_threshold: v}))}
                                                min={10}
                                                max={80}
                                            />

                                            <Slider
                                                label={t('checkInterval') || 'Check Interval'}
                                                description={t('crossClusterIntervalDesc') || 'Time between check cycles'}
                                                value={form.cross_cluster_interval}
                                                onChange={v => setForm(p => ({...p, cross_cluster_interval: v}))}
                                                min={300}
                                                max={3600}
                                                step={60}
                                                unit="s"
                                            />

                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('targetStorage') || 'Target Storage'}</label>
                                                    {loadingResources ? (
                                                        <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                            <Icons.RefreshCw className="w-4 h-4 animate-spin" />
                                                            {t('loadingCrossClusterResources') || 'Loading...'}
                                                        </div>
                                                    ) : commonStorages.length > 0 ? (
                                                        <select
                                                            value={form.cross_cluster_target_storage}
                                                            onChange={e => setForm(p => ({...p, cross_cluster_target_storage: e.target.value}))}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                        >
                                                            <option value="">{t('selectStorage') || 'Select storage...'}</option>
                                                            {commonStorages.map(s => (
                                                                <option key={s.storage} value={s.storage}>
                                                                    {s.storage} ({s.type})
                                                                </option>
                                                            ))}
                                                        </select>
                                                    ) : (
                                                        <div className="text-xs text-yellow-400 py-2">
                                                            <Icons.AlertTriangle className="w-3 h-3 inline mr-1" />
                                                            {t('noCommonStorages') || 'No common storage found across all clusters'}
                                                        </div>
                                                    )}
                                                    <p className="text-xs text-gray-600 mt-1">{t('commonStorageHint') || 'Only storages available on all clusters'}</p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('targetBridge') || 'Target Bridge'}</label>
                                                    {loadingResources ? (
                                                        <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                            <Icons.RefreshCw className="w-4 h-4 animate-spin" />
                                                            {t('loadingCrossClusterResources') || 'Loading...'}
                                                        </div>
                                                    ) : commonBridges.length > 0 ? (
                                                        <select
                                                            value={form.cross_cluster_target_bridge}
                                                            onChange={e => setForm(p => ({...p, cross_cluster_target_bridge: e.target.value}))}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                                                        >
                                                            {commonBridges.filter(b => b.source !== 'sdn').length > 0 && (
                                                                <optgroup label="Local Bridges">
                                                                    {commonBridges.filter(b => b.source !== 'sdn').map(b => (
                                                                        <option key={b.iface} value={b.iface}>
                                                                            {b.iface}{b.comments ? ` - ${b.comments}` : ''}
                                                                        </option>
                                                                    ))}
                                                                </optgroup>
                                                            )}
                                                            {commonBridges.filter(b => b.source === 'sdn').length > 0 && (
                                                                <optgroup label="SDN VNets">
                                                                    {commonBridges.filter(b => b.source === 'sdn').map(b => (
                                                                        <option key={b.iface} value={b.iface}>
                                                                            {b.iface} - {b.zone || 'SDN'}{b.alias ? ` (${b.alias})` : ''}
                                                                        </option>
                                                                    ))}
                                                                </optgroup>
                                                            )}
                                                        </select>
                                                    ) : (
                                                        <div className="text-xs text-yellow-400 py-2">
                                                            <Icons.AlertTriangle className="w-3 h-3 inline mr-1" />
                                                            {t('noCommonBridges') || 'No common bridge found across all clusters'}
                                                        </div>
                                                    )}
                                                    <p className="text-xs text-gray-600 mt-1">{t('commonBridgeHint') || 'Only bridges available on all clusters'}</p>
                                                </div>
                                            </div>

                                            <Slider
                                                label={t('maxMigrations') || 'Max Migrations per Cycle'}
                                                description={t('crossClusterMaxMigrationsDesc') || 'Max migrations per check cycle'}
                                                value={form.cross_cluster_max_migrations}
                                                onChange={v => setForm(p => ({...p, cross_cluster_max_migrations: v}))}
                                                min={1}
                                                max={5}
                                                step={1}
                                                unit=""
                                            />

                                            {/* Container Balancing Toggle */}
                                            <div className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div>
                                                    <span className="text-sm text-white">{t('includeContainers') || 'Include Containers'}</span>
                                                    <p className="text-xs text-gray-500 mt-0.5">{t('includeContainersDesc') || 'Include containers (LXC) in cross-cluster balancing'}</p>
                                                    {form.cross_cluster_include_containers && (
                                                        <p className="text-xs text-yellow-400 mt-1 flex items-center gap-1">
                                                            <Icons.AlertTriangle className="w-3 h-3" />
                                                            {t('containerMigrationWarning') || 'Containers are restarted during migration (downtime)'}
                                                        </p>
                                                    )}
                                                </div>
                                                <label className="relative inline-flex items-center cursor-pointer ml-4">
                                                    <input
                                                        type="checkbox"
                                                        checked={form.cross_cluster_include_containers}
                                                        onChange={e => setForm(p => ({...p, cross_cluster_include_containers: e.target.checked}))}
                                                        className="sr-only peer"
                                                    />
                                                    <div className="w-11 h-6 bg-gray-600 peer-checked:bg-proxmox-orange rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full"></div>
                                                </label>
                                            </div>

                                            {/* Excluded VMs per Cluster */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <h4 className="text-sm font-medium text-white mb-1">{t('excludedVMsCrossCluster') || 'Excluded VMs/Containers'}</h4>
                                                <p className="text-xs text-gray-500 mb-3">{t('excludedVMsCrossClusterDesc') || 'VMs and containers excluded from automatic cross-cluster balancing'}</p>

                                                {loadingExcludedVMs ? (
                                                    <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                        <Icons.RefreshCw className="w-4 h-4 animate-spin" />
                                                        {t('loading')}...
                                                    </div>
                                                ) : groupClusters.filter(c => c.connected).length === 0 ? (
                                                    <div className="text-xs text-gray-600 py-2">{t('noExcludedVMsInGroup') || 'No VMs excluded'}</div>
                                                ) : (
                                                    <div className="space-y-2">
                                                        {groupClusters.filter(c => c.connected).map(cluster => {
                                                            const excluded = excludedVMsByCluster[cluster.id] || [];
                                                            const allVMs = allVMsByCluster[cluster.id] || [];
                                                            const excludedIds = excluded.map(v => v.vmid);
                                                            const available = allVMs.filter(vm => !excludedIds.includes(vm.vmid));
                                                            const isExpanded = expandedClusters[cluster.id];

                                                            return (
                                                                <div key={cluster.id} className="border border-proxmox-border rounded-lg overflow-hidden">
                                                                    <button
                                                                        onClick={() => setExpandedClusters(prev => ({...prev, [cluster.id]: !prev[cluster.id]}))}
                                                                        className="w-full flex items-center justify-between p-2.5 bg-proxmox-dark/50 hover:bg-proxmox-dark text-left"
                                                                    >
                                                                        <div className="flex items-center gap-2">
                                                                            <Icons.Server className="w-3.5 h-3.5 text-proxmox-orange" />
                                                                            <span className="text-sm text-white">{cluster.name}</span>
                                                                            {excluded.length > 0 && (
                                                                                <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">{excluded.length}</span>
                                                                            )}
                                                                        </div>
                                                                        <Icons.ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                                                    </button>

                                                                    {isExpanded && (
                                                                        <div className="p-2.5 space-y-2 border-t border-proxmox-border">
                                                                            {excluded.length > 0 ? (
                                                                                <div className="space-y-1">
                                                                                    {excluded.map(vm => (
                                                                                        <div key={vm.vmid} className="flex items-center justify-between bg-proxmox-dark rounded px-2.5 py-1.5">
                                                                                            <div className="flex items-center gap-2">
                                                                                                <Icons.Monitor className="w-3.5 h-3.5 text-red-400" />
                                                                                                <span className="text-sm">{vm.name || `VM ${vm.vmid}`}</span>
                                                                                                <span className="text-xs text-gray-500">({vm.vmid})</span>
                                                                                            </div>
                                                                                            <button
                                                                                                onClick={() => includeVM(cluster.id, vm.vmid)}
                                                                                                className="text-xs text-green-400 hover:text-green-300"
                                                                                            >
                                                                                                {t('include') || 'Include'}
                                                                                            </button>
                                                                                        </div>
                                                                                    ))}
                                                                                </div>
                                                                            ) : (
                                                                                <div className="text-xs text-gray-600 p-2">{t('noExcludedVMsInGroup') || 'No VMs excluded'}</div>
                                                                            )}

                                                                            {available.length > 0 && (
                                                                                <div className="flex gap-2 mt-1">
                                                                                    <select
                                                                                        id={`xclb-exclude-${cluster.id}`}
                                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded px-2 py-1.5 text-sm"
                                                                                        defaultValue=""
                                                                                    >
                                                                                        <option value="" disabled>{t('selectVMToExclude') || 'Select VM to exclude...'}</option>
                                                                                        {available.map(vm => (
                                                                                            <option key={vm.vmid} value={vm.vmid}>
                                                                                                {vm.name || `VM ${vm.vmid}`} ({vm.vmid}) - {vm.node}
                                                                                            </option>
                                                                                        ))}
                                                                                    </select>
                                                                                    <button
                                                                                        onClick={() => {
                                                                                            const select = document.getElementById(`xclb-exclude-${cluster.id}`);
                                                                                            const vmid = parseInt(select?.value);
                                                                                            if (!vmid) return;
                                                                                            const vm = available.find(v => v.vmid === vmid);
                                                                                            excludeVM(cluster.id, vmid, vm?.name);
                                                                                            select.value = '';
                                                                                        }}
                                                                                        className="px-2.5 py-1.5 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 text-xs flex items-center gap-1"
                                                                                    >
                                                                                        <Icons.Ban className="w-3.5 h-3.5" />
                                                                                        {t('exclude') || 'Exclude'}
                                                                                    </button>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'replication' && (
                                <div className="space-y-4">
                                    {/* Header + Add button */}
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h4 className="text-sm font-medium text-white flex items-center gap-2">
                                                <Icons.Globe className="w-4 h-4 text-proxmox-orange" />
                                                {t('crossClusterReplication') || 'Cross-Cluster Replication'}
                                            </h4>
                                            <p className="text-xs text-gray-500 mt-0.5">{t('crossClusterReplicationDesc') || 'Replicate VM snapshots to another cluster (DR)'}</p>
                                        </div>
                                        {groupClusters.length >= 2 && (
                                            <button
                                                onClick={() => setShowCreateXRepl(true)}
                                                className="flex items-center gap-1.5 px-3 py-1.5 bg-proxmox-orange/10 text-proxmox-orange rounded-lg text-xs hover:bg-proxmox-orange/20 transition-colors"
                                            >
                                                <Icons.Plus className="w-3.5 h-3.5" />
                                                {t('addDrJob') || 'Add DR Job'}
                                            </button>
                                        )}
                                    </div>

                                    {groupClusters.length < 2 ? (
                                        <div className="text-center py-8 text-gray-500 text-sm">
                                            <Icons.AlertTriangle className="w-8 h-8 mx-auto mb-2 text-gray-600" />
                                            {t('needTwoClusters') || 'At least 2 clusters needed for cross-cluster replication'}
                                        </div>
                                    ) : xReplLoading ? (
                                        <div className="flex items-center justify-center gap-2 py-8 text-gray-500 text-sm">
                                            <Icons.RefreshCw className="w-4 h-4 animate-spin" />
                                            {t('loading')}...
                                        </div>
                                    ) : xReplJobs.length === 0 && !showCreateXRepl ? (
                                        <div className="text-center py-8 text-gray-500 text-sm">
                                            {t('noReplicationJobs') || 'No replication jobs configured'}
                                        </div>
                                    ) : (
                                        <div className="space-y-2">
                                            {xReplJobs.map(job => {
                                                const srcCluster = groupClusters.find(c => c.id === job.source_cluster);
                                                const tgtCluster = groupClusters.find(c => c.id === job.target_cluster);
                                                return (
                                                    <div key={job.id} className="bg-proxmox-dark rounded-lg p-3 flex items-center justify-between border border-proxmox-border">
                                                        <div className="flex-1 min-w-0">
                                                            <div className="flex items-center gap-2 flex-wrap">
                                                                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${job.enabled ? 'bg-green-500' : 'bg-gray-500'}`} />
                                                                <span className="text-sm text-white truncate">{srcCluster?.name || job.source_cluster}</span>
                                                                <Icons.ArrowRight className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
                                                                <span className="text-sm text-white truncate">{tgtCluster?.name || job.target_cluster}</span>
                                                                <span className="text-xs bg-proxmox-dark px-1.5 py-0.5 rounded text-gray-400 border border-proxmox-border">
                                                                    {job.vm_type === 'lxc' ? 'CT' : 'VM'} {job.vmid}
                                                                </span>
                                                            </div>
                                                            <div className="text-xs text-gray-500 mt-1 flex items-center gap-2 flex-wrap">
                                                                <span>{job.schedule}</span>
                                                                <span>&middot;</span>
                                                                <span>{job.target_storage || 'default'}</span>
                                                                {job.last_run && (
                                                                    <>
                                                                        <span>&middot;</span>
                                                                        <span>{t('lastRunPrefix') || 'Last'}: {new Date(job.last_run).toLocaleString()}</span>
                                                                    </>
                                                                )}
                                                                {job.last_status && (
                                                                    <span className={job.last_status === 'OK' ? 'text-green-400' : 'text-red-400'}>{job.last_status}</span>
                                                                )}
                                                                {job.last_error && <span className="text-red-400">{job.last_error}</span>}
                                                            </div>
                                                        </div>
                                                        <div className="flex gap-1 flex-shrink-0 ml-2">
                                                            <button onClick={() => handleRunXReplNow(job.id)} className="p-1.5 rounded hover:bg-green-500/10 text-gray-400 hover:text-green-400" title={t('runNow') || 'Run now'}>
                                                                <Icons.Play className="w-3.5 h-3.5" />
                                                            </button>
                                                            <button onClick={() => handleDeleteXRepl(job.id)} className="p-1.5 rounded hover:bg-red-500/10 text-gray-400 hover:text-red-400" title={t('delete') || 'Delete'}>
                                                                <Icons.Trash className="w-3.5 h-3.5" />
                                                            </button>
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    )}

                                    {/* Inline create form */}
                                    {showCreateXRepl && groupClusters.length >= 2 && (
                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-lg p-4">
                                            <h5 className="text-sm font-medium text-white mb-3">{t('newCrossClusterReplication') || 'New Cross-Cluster Replication'}</h5>
                                            <div className="grid grid-cols-2 gap-3">
                                                {/* Source Cluster */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('sourceCluster') || 'Source Cluster'}</label>
                                                    <select
                                                        value={xReplForm.source_cluster}
                                                        onChange={e => setXReplForm(f => ({ ...f, source_cluster: e.target.value, vmid: '', vm_type: 'qemu' }))}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="">{t('selectCluster') || 'Select cluster...'}</option>
                                                        {groupClusters.filter(c => c.connected).map(c => (
                                                            <option key={c.id} value={c.id}>{c.name}</option>
                                                        ))}
                                                    </select>
                                                </div>

                                                {/* VM Selection */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">VM</label>
                                                    {xReplLoadingVMs ? (
                                                        <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                            <Icons.RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                                            {t('loading')}...
                                                        </div>
                                                    ) : xReplForm.source_cluster ? (
                                                        <select
                                                            value={xReplForm.vmid}
                                                            onChange={e => {
                                                                const vmid = e.target.value;
                                                                const vm = xReplSourceVMs.find(v => String(v.vmid) === vmid);
                                                                setXReplForm(f => ({ ...f, vmid, vm_type: vm?.type || 'qemu' }));
                                                            }}
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            <option value="">{t('selectVM') || 'Select VM...'}</option>
                                                            {xReplSourceVMs.map(vm => (
                                                                <option key={vm.vmid} value={vm.vmid}>
                                                                    {vm.name || `VM ${vm.vmid}`} ({vm.vmid}) - {vm.type === 'lxc' ? 'CT' : 'VM'}
                                                                </option>
                                                            ))}
                                                        </select>
                                                    ) : (
                                                        <div className="text-xs text-gray-500 py-2">{t('selectClusterFirst') || 'Select a source cluster first'}</div>
                                                    )}
                                                </div>

                                                {/* Target Cluster */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('targetCluster') || 'Target Cluster'}</label>
                                                    <select
                                                        value={xReplForm.target_cluster}
                                                        onChange={e => setXReplForm(f => ({ ...f, target_cluster: e.target.value, target_storage: '', target_bridge: 'vmbr0' }))}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="">{t('selectCluster') || 'Select cluster...'}</option>
                                                        {groupClusters.filter(c => c.connected && c.id !== xReplForm.source_cluster).map(c => (
                                                            <option key={c.id} value={c.id}>{c.name}</option>
                                                        ))}
                                                    </select>
                                                </div>

                                                {/* Target Storage */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('targetStorage') || 'Target Storage'}</label>
                                                    {xReplLoadingResources ? (
                                                        <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                            <Icons.RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                                            {t('loading')}...
                                                        </div>
                                                    ) : xReplForm.target_cluster ? (
                                                        <select
                                                            value={xReplForm.target_storage}
                                                            onChange={e => setXReplForm(f => ({ ...f, target_storage: e.target.value }))}
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            <option value="">{t('selectStorage') || 'Select storage...'}</option>
                                                            {xReplTargetStorages.map(s => (
                                                                <option key={s.storage} value={s.storage}>{s.storage} ({s.type})</option>
                                                            ))}
                                                        </select>
                                                    ) : (
                                                        <div className="text-xs text-gray-500 py-2">{t('selectClusterFirst') || 'Select a target cluster first'}</div>
                                                    )}
                                                </div>

                                                {/* Target Bridge */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('targetBridge') || 'Target Bridge'}</label>
                                                    {xReplLoadingResources ? (
                                                        <div className="flex items-center gap-2 text-gray-500 text-sm py-2">
                                                            <Icons.RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                                            {t('loading')}...
                                                        </div>
                                                    ) : xReplForm.target_cluster ? (
                                                        <select
                                                            value={xReplForm.target_bridge}
                                                            onChange={e => setXReplForm(f => ({ ...f, target_bridge: e.target.value }))}
                                                            className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                        >
                                                            {xReplTargetBridges.filter(b => b.source !== 'sdn').length > 0 && (
                                                                <optgroup label="Local Bridges">
                                                                    {xReplTargetBridges.filter(b => b.source !== 'sdn').map(b => (
                                                                        <option key={b.iface} value={b.iface}>{b.iface}{b.comments ? ` - ${b.comments}` : ''}</option>
                                                                    ))}
                                                                </optgroup>
                                                            )}
                                                            {xReplTargetBridges.filter(b => b.source === 'sdn').length > 0 && (
                                                                <optgroup label="SDN VNets">
                                                                    {xReplTargetBridges.filter(b => b.source === 'sdn').map(b => (
                                                                        <option key={b.iface} value={b.iface}>{b.iface} - {b.zone || 'SDN'}{b.alias ? ` (${b.alias})` : ''}</option>
                                                                    ))}
                                                                </optgroup>
                                                            )}
                                                        </select>
                                                    ) : (
                                                        <div className="text-xs text-gray-500 py-2">{t('selectClusterFirst') || 'Select a target cluster first'}</div>
                                                    )}
                                                </div>

                                                {/* Schedule */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('scheduleCron') || 'Schedule (Cron)'}</label>
                                                    <input
                                                        type="text"
                                                        value={xReplForm.schedule}
                                                        onChange={e => setXReplForm(f => ({ ...f, schedule: e.target.value }))}
                                                        placeholder="0 */6 * * *"
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    />
                                                </div>

                                                {/* Retention */}
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('replicationRetention') || 'Retention'}</label>
                                                    <input
                                                        type="number"
                                                        min="1"
                                                        max="30"
                                                        value={xReplForm.retention}
                                                        onChange={e => setXReplForm(f => ({ ...f, retention: parseInt(e.target.value) || 1 }))}
                                                        className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    />
                                                </div>
                                            </div>
                                            <div className="flex gap-2 mt-3">
                                                <button
                                                    onClick={handleCreateXRepl}
                                                    disabled={!xReplForm.source_cluster || !xReplForm.vmid || !xReplForm.target_cluster}
                                                    className="px-3 py-1.5 bg-proxmox-orange text-white rounded-lg text-sm hover:bg-proxmox-orange/90 transition-colors disabled:opacity-50"
                                                >
                                                    {t('create') || 'Create'}
                                                </button>
                                                <button
                                                    onClick={() => setShowCreateXRepl(false)}
                                                    className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border text-gray-300 rounded-lg text-sm hover:bg-proxmox-darker transition-colors"
                                                >
                                                    {t('cancel') || 'Cancel'}
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'info' && (
                                <div className="space-y-4">
                                    <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                        <h4 className="text-sm font-medium text-white mb-3">{t('groupInfo') || 'Group Information'}</h4>
                                        <div className="space-y-2 text-sm">
                                            <div className="flex justify-between">
                                                <span className="text-gray-400">{t('groupId') || 'Group ID'}</span>
                                                <span className="text-white font-mono text-xs">{group.id}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-gray-400">{t('created') || 'Created'}</span>
                                                <span className="text-white">{group.created ? new Date(group.created).toLocaleString() : '-'}</span>
                                            </div>
                                            {group.tenant_id && (
                                                <div className="flex justify-between">
                                                    <span className="text-gray-400">{t('tenant') || 'Tenant'}</span>
                                                    <span className="text-white">{group.tenant_id}</span>
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* LB info */}
                                    {group.cross_cluster_lb_enabled && (
                                        <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                            <h4 className="text-sm font-medium text-white mb-3">{t('lbStatus') || 'Load Balancing Status'}</h4>
                                            <div className="space-y-2 text-sm">
                                                <div className="flex justify-between">
                                                    <span className="text-gray-400">{t('lastRun') || 'Last LB Run'}</span>
                                                    <span className="text-white">{group.last_lb_run ? new Date(group.last_lb_run).toLocaleString() : t('neverRun') || 'Never run'}</span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-gray-400">{t('mode') || 'Mode'}</span>
                                                    <span className={group.cross_cluster_dry_run ? 'text-yellow-400' : 'text-green-400'}>
                                                        {group.cross_cluster_dry_run ? t('simulation') || 'Simulation' : t('active') || 'Active'}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    <div className="p-4 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                                        <div className="flex items-start gap-3">
                                            <Icons.Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                                            <div className="text-sm text-gray-400">
                                                <p className="mb-2">{t('lbExplanation') || 'Cross-Cluster Load Balancing monitors CPU and RAM usage across all clusters in this group. When a cluster exceeds the configured threshold, VMs are automatically migrated to a less loaded cluster.'}</p>
                                                <p>{t('lbDryRunExplanation') || 'Enable Dry Run mode first to review what actions would be taken before enabling live migrations.'}</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Footer */}
                        <div className="flex items-center justify-end gap-3 p-5 border-t border-proxmox-border">
                            <button
                                onClick={onClose}
                                className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
                            >
                                {t('cancel') || 'Cancel'}
                            </button>
                            <button
                                onClick={handleSave}
                                disabled={saving || !form.name.trim()}
                                className="px-5 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                            >
                                {saving ? (
                                    <><Icons.RefreshCw className="w-4 h-4 animate-spin" /> {t('saving') || 'Saving...'}</>
                                ) : (
                                    <><Icons.Save className="w-4 h-4" /> {t('save') || 'Save'}</>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Cluster Health Widget
        function ClusterHealth({ metrics, isCorporate }) {
            const { t } = useTranslation();
            const nodes = Object.entries(metrics);
            if (nodes.length === 0) return null;

            const avgCpu = nodes.reduce((acc, [, m]) => acc + m.cpu_percent, 0) / nodes.length;
            const avgMem = nodes.reduce((acc, [, m]) => acc + m.mem_percent, 0) / nodes.length;
            const avgScore = nodes.reduce((acc, [, m]) => acc + m.score, 0) / nodes.length;
            const onlineNodes = nodes.filter(([, m]) => m.status === 'online' && !m.maintenance_mode).length;
            const maintenanceNodes = nodes.filter(([, m]) => m.maintenance_mode).length;

            const healthScore = Math.max(0, 100 - (avgScore / 2));
            const healthLabel = healthScore >= 80 ? t('excellent') : healthScore >= 60 ? t('good') : healthScore >= 40 ? t('warning') : t('critical');
            const healthColor = healthScore >= 80 ? '#22c55e' : healthScore >= 60 ? '#84cc16' : healthScore >= 40 ? '#eab308' : '#ef4444';

            // LW: Feb 2026 - corporate compact variant (Clarity dark theme)
            const corpHealthColor = healthScore >= 80 ? '#60b515' : healthScore >= 60 ? '#60b515' : healthScore >= 40 ? '#efc006' : '#f54f47';
            if (isCorporate) {
                return (
                    <div className="p-3" style={{background: '#22343c', border: '1px solid #485764'}}>
                        <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{color: '#728b9a'}}>{t('clusterHealth')}</h3>
                        <div className="flex items-center gap-4 flex-wrap">
                            <div className="flex items-center gap-2">
                                <div className="w-20 h-2 overflow-hidden" style={{background: '#1b2a32', borderRadius: '1px'}}>
                                    <div className="h-full" style={{width: `${healthScore}%`, backgroundColor: corpHealthColor, borderRadius: '1px'}}></div>
                                </div>
                                <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{healthScore.toFixed(0)}</span>
                                <span className="text-[11px]" style={{color: '#728b9a'}}>{healthLabel}</span>
                            </div>
                            <span className="text-[12px]" style={{color: '#adbbc4'}}>{t('nodesOnline')}: <span style={{color: '#e9ecef'}}>{onlineNodes}/{nodes.length}</span></span>
                            <span className="text-[12px]" style={{color: '#adbbc4'}}>CPU: <span style={{color: '#e9ecef'}}>{avgCpu.toFixed(1)}%</span></span>
                            <span className="text-[12px]" style={{color: '#adbbc4'}}>RAM: <span style={{color: '#e9ecef'}}>{avgMem.toFixed(1)}%</span></span>
                            {maintenanceNodes > 0 && (
                                <span className="text-[12px] flex items-center gap-1" style={{color: '#efc006'}}>
                                    <Icons.Wrench className="w-3 h-3" /> {maintenanceNodes} {t('maintenance')}
                                </span>
                            )}
                        </div>
                    </div>
                );
            }

            return (
                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">{t('clusterHealth')}</h3>

                    <div className="flex items-center justify-center mb-6">
                        <div className="relative">
                            <svg viewBox="0 0 100 100" className="w-32 h-32">
                                <circle cx="50" cy="50" r="45" fill="none" stroke="#30363D" strokeWidth="8" />
                                <circle
                                    cx="50"
                                    cy="50"
                                    r="45"
                                    fill="none"
                                    stroke={healthColor}
                                    strokeWidth="8"
                                    strokeLinecap="round"
                                    strokeDasharray={`${healthScore * 2.83} 283`}
                                    transform="rotate(-90 50 50)"
                                    className="transition-all duration-1000"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-2xl font-bold text-white">{healthScore.toFixed(0)}</span>
                                <span className="text-xs text-gray-400">{healthLabel}</span>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="text-center">
                            <div className="text-2xl font-bold text-white">{onlineNodes}/{nodes.length}</div>
                            <div className="text-xs text-gray-500">{t('nodesOnline')}</div>
                        </div>
                        <div className="text-center">
                            <div className="text-2xl font-bold text-white">{avgScore.toFixed(0)}</div>
                            <div className="text-xs text-gray-500">{t('avgScore')}</div>
                        </div>
                        <div className="text-center">
                            <div className="text-2xl font-bold text-white">{avgCpu.toFixed(1)}%</div>
                            <div className="text-xs text-gray-500">{t('avgCpu')}</div>
                        </div>
                        <div className="text-center">
                            <div className="text-2xl font-bold text-white">{avgMem.toFixed(1)}%</div>
                            <div className="text-xs text-gray-500">{t('avgRam')}</div>
                        </div>
                    </div>

                    {maintenanceNodes > 0 && (
                        <div className="mt-4 pt-4 border-t border-proxmox-border">
                            <div className="flex items-center justify-center gap-2 text-yellow-400">
                                <Icons.Wrench />
                                <span className="text-sm font-medium">{maintenanceNodes} Node(s) {t('maintenance')}</span>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // Create Snapshot Modal - NS: Feb 2026 enhanced with efficient mode
        function CreateSnapshotModal({ isQemu, onSubmit, onClose, loading, efficientInfo }) {
            const { t } = useTranslation();
            const [snapname, setSnapname] = useState(`snap_${Date.now()}`);
            const [description, setDescription] = useState('');
            const [vmstate, setVmstate] = useState(false);
            const [mode, setMode] = useState('standard');
            const [snapSizeGb, setSnapSizeGb] = useState(efficientInfo?.recommended_snap_size_gb || 10);

            const isEfficient = mode === 'efficient';
            const canEfficient = efficientInfo?.eligible;

            const handleSubmit = () => {
                if (!snapname.trim()) return;
                onSubmit(snapname.trim(), description, vmstate, isEfficient ? { mode: 'efficient', snap_size_gb: snapSizeGb } : { mode: 'standard' });
            };

            return (
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className={`w-full ${canEfficient ? 'max-w-lg' : 'max-w-md'} bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in`}>
                        <h3 className="text-lg font-semibold text-white mb-4">{t('createSnapshot')}</h3>
                        <div className="space-y-4">
                            {/* Mode toggle - only show when efficient snapshots are available */}
                            {canEfficient && (
                                <div>
                                    <label className="block text-sm text-gray-400 mb-2">{t('snapshotMode')}</label>
                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => setMode('standard')}
                                            className={`flex-1 px-3 py-2 rounded-lg text-sm border transition-colors ${
                                                !isEfficient
                                                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                                                    : 'bg-proxmox-dark border-proxmox-border text-gray-400 hover:border-gray-500'
                                            }`}
                                        >
                                            {t('normalMode')}
                                        </button>
                                        <button
                                            onClick={() => setMode('efficient')}
                                            className={`flex-1 px-3 py-2 rounded-lg text-sm border transition-colors ${
                                                isEfficient
                                                    ? 'bg-green-600/20 border-green-500 text-green-400'
                                                    : 'bg-proxmox-dark border-proxmox-border text-gray-400 hover:border-gray-500'
                                            }`}
                                        >
                                            <span className="flex items-center justify-center gap-1">
                                                <Icons.Zap />
                                                {t('efficientMode')}
                                            </span>
                                        </button>
                                    </div>
                                </div>
                            )}

                            {/* Space savings visualization */}
                            {isEfficient && efficientInfo && (
                                <div className="p-3 bg-proxmox-dark rounded-lg border border-green-500/30 space-y-3">
                                    <div className="text-sm font-medium text-green-400 flex items-center gap-1">
                                        <Icons.Zap />
                                        {t('spaceSavings')}: {efficientInfo.savings_percent}%
                                    </div>
                                    {/* Normal snapshot bar (red) */}
                                    <div>
                                        <div className="flex justify-between text-xs text-gray-400 mb-1">
                                            <span>{t('normalSnapshotSize')}</span>
                                            <span>{efficientInfo.total_disk_size_gb?.toFixed(1)} GB</span>
                                        </div>
                                        <div className="w-full h-3 bg-gray-700 rounded-full overflow-hidden">
                                            <div className="h-full bg-red-500 rounded-full" style={{width: '100%'}}></div>
                                        </div>
                                    </div>
                                    {/* Efficient snapshot bar (green) */}
                                    <div>
                                        <div className="flex justify-between text-xs text-gray-400 mb-1">
                                            <span>{t('efficientSnapshotSize')}</span>
                                            <span>~{snapSizeGb?.toFixed(1)} GB</span>
                                        </div>
                                        <div className="w-full h-3 bg-gray-700 rounded-full overflow-hidden">
                                            <div className="h-full bg-green-500 rounded-full" style={{width: `${Math.max(3, (snapSizeGb / efficientInfo.total_disk_size_gb) * 100)}%`}}></div>
                                        </div>
                                    </div>
                                    {/* Snapshot size input */}
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">
                                            {t('snapshotSizeGb')} ({t('recommended')}: {efficientInfo.recommended_snap_size_gb?.toFixed(1)} GB)
                                        </label>
                                        <input
                                            type="number"
                                            value={snapSizeGb}
                                            onChange={(e) => setSnapSizeGb(parseFloat(e.target.value) || 1)}
                                            min="1"
                                            max={efficientInfo.vg_free_gb - 2}
                                            step="1"
                                            className="w-full px-3 py-1.5 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                        />
                                    </div>
                                    {/* Guest agent status */}
                                    <div className={`text-xs flex items-center gap-1 ${efficientInfo.has_guest_agent ? 'text-green-400' : 'text-yellow-400'}`}>
                                        {efficientInfo.has_guest_agent ? <Icons.CheckCircle /> : <Icons.AlertTriangle />}
                                        {efficientInfo.has_guest_agent ? t('guestAgentDetected') : t('noGuestAgent')}
                                    </div>
                                    {/* Info text */}
                                    <div className="text-xs text-gray-500 italic">
                                        {t('managedByPegaprox')}
                                    </div>
                                </div>
                            )}

                            <div>
                                <label className="block text-sm text-gray-400 mb-1">{t('name')}</label>
                                <input
                                    type="text"
                                    value={snapname}
                                    onChange={(e) => setSnapname(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                    placeholder="snapshot-name"
                                />
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">{t('description')} ({t('optional')})</label>
                                <input
                                    type="text"
                                    value={description}
                                    onChange={(e) => setDescription(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                    placeholder={t('snapshotDescription')}
                                />
                            </div>
                            {isQemu && !isEfficient && (
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={vmstate}
                                        onChange={(e) => setVmstate(e.target.checked)}
                                        className="rounded"
                                    />
                                    {t('saveRamState')}
                                </label>
                            )}
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                {t('cancel')}
                            </button>
                            <button
                                onClick={handleSubmit}
                                disabled={loading || !snapname.trim()}
                                className="flex items-center gap-2 px-4 py-2 rounded-lg text-white disabled:opacity-50 bg-green-600 hover:bg-green-700"
                            >
                                {loading && <Icons.RotateCw />}
                                {isEfficient && <Icons.Zap />}
                                {t('create')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Create Replication Modal
        function CreateReplicationModal({ nodes, onSubmit, onClose, loading }) {
            const { t } = useTranslation();
            const [target, setTarget] = useState(nodes[0] || '');
            const [schedule, setSchedule] = useState('*/15');
            const [rate, setRate] = useState('');
            const [comment, setComment] = useState('');

            const scheduleOptions = [
                { value: '*/5', label: t('every5min') },
                { value: '*/15', label: t('every15min') },
                { value: '*/30', label: t('every30min') },
                { value: '0 *', label: t('hourly') },
                { value: '0 */2', label: t('every2hours') },
                { value: '0 */4', label: t('every4hours') },
                { value: '0 */6', label: t('every6hours') },
                { value: '0 */12', label: t('every12hours') },
                { value: '0 0', label: t('daily') },
            ];

            const handleSubmit = () => {
                if (!target) return;
                onSubmit(target, schedule, rate ? parseInt(rate) : null, comment);
            };

            return (
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('createReplicationJob')}</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">{t('targetNode')}</label>
                                <select
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                >
                                    {nodes.map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Schedule</label>
                                <select
                                    value={schedule}
                                    onChange={(e) => setSchedule(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                >
                                    {scheduleOptions.map(opt => (
                                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">{t('rateLimit')} ({t('optional')})</label>
                                <input
                                    type="number"
                                    value={rate}
                                    onChange={(e) => setRate(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                    placeholder={t('unlimited')}
                                    min="1"
                                />
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">{t('comment')} ({t('optional')})</label>
                                <input
                                    type="text"
                                    value={comment}
                                    onChange={(e) => setComment(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                    placeholder={t('commentPlaceholder')}
                                />
                            </div>
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                {t('cancel')}
                            </button>
                            <button
                                onClick={handleSubmit}
                                disabled={loading || !target}
                                className="flex items-center gap-2 px-4 py-2 bg-green-600 rounded-lg text-white hover:bg-green-700 disabled:opacity-50"
                            >
                                {loading && <Icons.RotateCw />}
                                {t('create')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // Shared form components (defined outside ConfigModal to prevent re-creation)
        // ns: could use a form library but this is fine for now
        const ConfigInputField = ({ label, value, onChange, type = 'text', disabled = false, suffix = '', options = null, placeholder = '', needsRestart = false, t }) => (
            <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">
                    {label}
                    {needsRestart && <span className="ml-2 text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-medium">{t ? t('needsRestart') : 'NEEDS RESTART'}</span>}
                </label>
                {options ? (
                    <select
                        value={value}
                        onChange={e => onChange(e.target.value)}
                        disabled={disabled}
                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {options.map(opt => (
                            <option key={typeof opt === 'string' ? opt : opt.value} value={typeof opt === 'string' ? opt : opt.value}>
                                {typeof opt === 'string' ? opt : opt.label}
                            </option>
                        ))}
                    </select>
                ) : (
                    <div className="relative">
                        <input
                            type={type}
                            value={value}
                            onChange={e => onChange(type === 'number' ? +e.target.value : e.target.value)}
                            disabled={disabled}
                            placeholder={placeholder}
                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange disabled:opacity-50 disabled:cursor-not-allowed"
                        />
                        {suffix && (
                            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">{suffix}</span>
                        )}
                    </div>
                )}
            </div>
        );

        // checkbox version
        const ConfigCheckboxField = ({ label, checked, onChange, disabled = false, needsRestart = false, t }) => (
            <label className="flex items-center gap-3 cursor-pointer">
                <input
                    type="checkbox"
                    checked={checked}
                    onChange={e => onChange(e.target.checked ? 1 : 0)}
                    disabled={disabled}
                    className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange focus:ring-proxmox-orange"
                />
                <span className="text-sm text-gray-300">{label}</span>
                {needsRestart && <span className="text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-medium">{t ? t('needsRestart') : 'RESTART'}</span>}
            </label>
        );

        // LW: Memory input with MB/GB unit selector - makes it easier to set RAM values
        const MemoryInputField = ({ label, value, onChange, disabled = false, needsRestart = false, minMB = 128, stepMB = 128, t }) => {
            // value is always in MB internally
            const [unit, setUnit] = useState(value >= 1024 ? 'GB' : 'MB');
            
            const displayValue = unit === 'GB' ? (value / 1024) : value;
            const step = unit === 'GB' ? 0.5 : stepMB;
            const min = unit === 'GB' ? (minMB / 1024) : minMB;
            
            const handleValueChange = (newValue) => {
                // Convert back to MB for storage
                const mbValue = unit === 'GB' ? Math.round(newValue * 1024) : newValue;
                onChange(mbValue);
            };
            
            const handleUnitChange = (newUnit) => {
                setUnit(newUnit);
                // Value stays the same in MB, just display changes
            };
            
            return (
                <div>
                    <label className="block text-xs font-medium text-gray-400 mb-1">
                        {label}
                        {needsRestart && <span className="ml-2 text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-medium">{t ? t('needsRestart') : 'NEEDS RESTART'}</span>}
                    </label>
                    <div className="flex gap-2">
                        <input
                            type="number"
                            value={displayValue}
                            onChange={e => handleValueChange(parseFloat(e.target.value) || 0)}
                            min={min}
                            step={step}
                            disabled={disabled}
                            className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange disabled:opacity-50"
                        />
                        <select
                            value={unit}
                            onChange={e => handleUnitChange(e.target.value)}
                            disabled={disabled}
                            className="w-20 px-2 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange"
                        >
                            <option value="MB">MB</option>
                            <option value="GB">GB</option>
                        </select>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                        {unit === 'MB' ? `${(value / 1024).toFixed(1)} GB` : `${value} MB`}
                    </p>
                </div>
            );
        };

