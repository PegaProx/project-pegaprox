        // ═══════════════════════════════════════════════
        // PegaProx - Tables & Cards
        // NodeCard + ResourceTable
        // ═══════════════════════════════════════════════
        function getProxmoxNodeHost(target = {}, fallbackName = '') {
            const candidates = [
                target.node_ip,
                target.nodeIp,
                target.host,
                target.current_host,
                target.management_ip,
                target.managementIp,
                target.ip_address,
                target.ipAddress,
                target.ip,
                target.hostname,
                target.node_host,
                target.nodeHost,
                fallbackName
            ];
            const match = candidates.find(value => typeof value === 'string' && value.trim());
            return match ? match.trim() : null;
        }

        function getProxmoxObjectUrl(target = {}) {
            const kind = target.kind || target.type;
            const nodeName = (kind === 'node') ? (target.name || target.node) : target.node;
            // #689 — when the cluster has a node FQDN suffix configured, link via <node>.<suffix>
            // (e.g. pve01.example.local) instead of the raw IP/host the API returns.
            const suffix = (target.node_ui_suffix || '').trim().replace(/^\.+/, '');
            const host = (suffix && nodeName) ? `${nodeName}.${suffix}`
                                              : getProxmoxNodeHost(target, target.node || target.name);
            if (!host) return null;

            if (kind === 'node') {
                if (!nodeName) return null;
                return `https://${host}:8006/#v1:0:=${encodeURIComponent(`node/${nodeName}`)}:4:=aptrepositories:=contentIso:::9::`;
            }

            if (kind === 'qemu' || kind === 'lxc') {
                if (target.vmid == null || target.vmid === '') return null;
                return `https://${host}:8006/#v1:0:=${encodeURIComponent(`${kind}/${target.vmid}`)}:4:::::::`;
            }

            return null;
        }

        function openProxmoxObject(target) {
            const url = getProxmoxObjectUrl(target);
            if (!url) return;
            window.open(url, '_blank', 'noopener,noreferrer');
        }

        function isGuestTemplate(resource = {}) {
            return resource.template === 1 || resource.template === '1' || resource.template === true;
        }

        function getGuestTypeLabel(resource = {}) {
            return resource.type === 'qemu' ? 'VM' : 'LXC';
        }

        function getGuestTypeIcon(resource = {}) {
            return resource.type === 'qemu' ? <Icons.VM /> : <Icons.Container />;
        }

        function getTemplateLabel(t) {
            return t('template') || 'Template';
        }

        function getGuestTypeTitle(resource = {}, t) {
            const typeLabel = getGuestTypeLabel(resource);
            return isGuestTemplate(resource) ? `${typeLabel} (${getTemplateLabel(t)})` : typeLabel;
        }

        // Node Card Component
        function NodeCard({ name, metrics, index, clusterId, nodeUiSuffix, onMaintenanceToggle, onStartUpdate, onOpenNodeConfig, onNodeAction, onRemoveNode, onMoveNode, isFavorite, onToggleFavorite, guestActions, onGuestsAction }) {
            const { t } = useTranslation();
            // #625 v2: a standby shows maintenance and update state, it does not change them
            const { getAuthHeaders, haReadOnly } = useAuth();
            // NS: 20 data points = last ~40s of sparkline at 2s polling interval
            const historyRef = useRef({
                cpu: Array(20).fill(0),
                mem: Array(20).fill(0),
                disk: Array(20).fill(0),
                netin: Array(20).fill(0),
                netout: Array(20).fill(0)
            });
            const [, forceUpdate] = useState(0);
            const [showMaintenanceConfirm, setShowMaintenanceConfirm] = useState(false);
            const [maintOptions, setMaintOptions] = useState({});  // off on each opening (#763, #954)
            const [showUpdateConfirm, setShowUpdateConfirm] = useState(false);
            const [updateWithReboot, setUpdateWithReboot] = useState(true);
            const [showUpdateLog, setShowUpdateLog] = useState(false);
            const [showRebootConfirm, setShowRebootConfirm] = useState(false);
            const [showShutdownConfirm, setShowShutdownConfirm] = useState(false);
            const [actionLoading, setActionLoading] = useState(null);
            const [expanded, setExpanded] = useState(false);
            const [guestsMenu, setGuestsMenu] = useState(false);
            const lastMetricsRef = useRef(null);

            // auto-dismiss update banner after 30s when completed (#183)
            useEffect(() => {
                if (!metrics?.is_updating || !metrics?.update_task) return;
                const st = metrics.update_task.status;
                if (st !== 'completed' && st !== 'failed') return;
                const timer = setTimeout(async () => {
                    try {
                        await fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/update`, {
                            method: 'DELETE', credentials: 'include', headers: getAuthHeaders()
                        });
                    } catch(e) {}
                }, st === 'completed' ? 30000 : 120000);  // 30s for success, 2min for failed
                return () => clearTimeout(timer);
            }, [metrics?.update_task?.status]);

            useEffect(() => {
                if (metrics && metrics !== lastMetricsRef.current) {
                    lastMetricsRef.current = metrics;

                    // #419 follow-up: backend netin/netout are already a rate (bytes/sec, rrddata AVERAGE),
                    // not a cumulative counter — divide directly, no delta-over-time.
                    historyRef.current = {
                        cpu: [...historyRef.current.cpu.slice(1), metrics.cpu_percent || 0],
                        mem: [...historyRef.current.mem.slice(1), metrics.mem_percent || 0],
                        disk: [...historyRef.current.disk.slice(1), metrics.disk_percent || 0],
                        netin: [...historyRef.current.netin.slice(1), (metrics.netin || 0) / 1048576], // MB/s
                        netout: [...historyRef.current.netout.slice(1), (metrics.netout || 0) / 1048576]
                    };
                    forceUpdate(n => n + 1);
                }
            }, [metrics?.cpu_percent, metrics?.mem_percent, metrics?.disk_percent, metrics?.netin, metrics?.netout]);
            
            const history = historyRef.current;

            const formatBytes = (bytes) => {
                if (!bytes) return '0 B';
                const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
            };

            const formatUptime = (seconds) => {
                const days = Math.floor(seconds / 86400);
                const hours = Math.floor((seconds % 86400) / 3600);
                const mins = Math.floor((seconds % 3600) / 60);
                if (days > 0) return `${days}d ${hours}h`;
                if (hours > 0) return `${hours}h ${mins}m`;
                return `${mins}m`;
            };

            if (!metrics) return null;

            const isInMaintenance = metrics.maintenance_mode;
            const maintenanceTask = metrics.maintenance_task;
            const isUpdating = metrics.is_updating;
            const updateTask = metrics.update_task;
            const isOffline = metrics.offline || metrics.status === 'offline';
            const proxmoxTarget = { ...metrics, kind: 'node', name, node: name, node_ui_suffix: nodeUiSuffix || '' };  // #689
            const proxmoxUrl = getProxmoxObjectUrl(proxmoxTarget);
            
            // Can only update if in maintenance and evacuation complete
            const canUpdate = isInMaintenance && 
                maintenanceTask?.status && 
                ['completed', 'completed_with_errors'].includes(maintenanceTask.status) &&
                !isUpdating;

            // Show simplified card for offline nodes
            if (isOffline) {
                return (
                    <div 
                        className="relative card-hover bg-proxmox-card border-2 border-red-500/50 rounded-xl p-5 animate-slide-up"
                        style={{ animationDelay: `${index * 100}ms` }}
                    >
                        <div className="absolute top-2 right-2 flex items-center gap-2">
                            {proxmoxUrl && (
                                <button
                                    onClick={() => openProxmoxObject(proxmoxTarget)}
                                    className="p-1.5 rounded-lg bg-proxmox-dark/80 text-gray-300 hover:text-white hover:bg-proxmox-hover transition-colors"
                                    title={t('openInProxmox') || 'Open in Proxmox'}
                                >
                                    <Icons.ExternalLink className="w-4 h-4" />
                                </button>
                            )}
                            <span className="px-2 py-1 bg-red-500 text-white text-xs font-bold rounded animate-pulse">
                                OFFLINE
                            </span>
                        </div>
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 bg-red-500/20 rounded-lg">
                                <Icons.Server className="text-red-400" />
                            </div>
                            <div>
                                <h3 className="font-semibold text-white">{name}</h3>
                                <div className="flex items-center gap-2 mt-1">
                                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                                    <span className="text-xs text-red-400">offline</span>
                                </div>
                            </div>
                        </div>
                        <div className="space-y-3 opacity-50">
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span className="text-gray-500">CPU</span>
                                    <span className="text-gray-500">--</span>
                                </div>
                                <div className="h-2 bg-proxmox-dark rounded-full" />
                            </div>
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span className="text-gray-500">RAM</span>
                                    <span className="text-gray-500">--</span>
                                </div>
                                <div className="h-2 bg-proxmox-dark rounded-full" />
                            </div>
                        </div>
                        {metrics.last_seen && (
                            <div className="mt-4 pt-3 border-t border-red-500/30 text-xs text-red-400">
                                <Icons.AlertTriangle className="inline w-3 h-3 mr-1" />
                                {t('lastSeen') || 'Last seen'}: {fmtDate(metrics.last_seen)}
                            </div>
                        )}
                    </div>
                );
            }

            return(
                <div 
                    className={`card-hover bg-proxmox-card border rounded-xl p-5 animate-slide-up ${
                        isUpdating ? 'border-blue-500/50 bg-blue-500/5' :
                        isInMaintenance ? 'border-yellow-500/50 bg-yellow-500/5' : 'border-proxmox-border'
                    }`}
                    style={{ animationDelay: `${index * 100}ms` }}
                >
                    {/* Update Banner */}
                    {isUpdating && updateTask && (
                        <div className="mb-4 -mt-1 -mx-1">
                            <div className={`${
                                updateTask.status === 'failed' ? 'bg-red-500/10 border-red-500/30' : 
                                updateTask.status === 'completed' ? 'bg-green-500/10 border-green-500/30' :
                                'bg-blue-500/10 border-blue-500/30'
                            } border rounded-lg p-3`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        {updateTask.status === 'completed' ? (
                                            <Icons.CheckCircle className="text-green-400" />
                                        ) : updateTask.status === 'failed' ? (
                                            <Icons.XCircle className="text-red-400" />
                                        ) : (
                                            <Icons.RotateCw className="animate-spin" />
                                        )}
                                        <span className={`${
                                            updateTask.status === 'failed' ? 'text-red-400' : 
                                            updateTask.status === 'completed' ? 'text-green-400' :
                                            'text-blue-400'
                                        } font-semibold text-sm`}>
                                            {updateTask.status === 'failed' ? t('updateFailed') : 
                                             updateTask.status === 'completed' ? t('updateCompleted') :
                                             t('updateRunning')}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className={`text-xs px-2 py-0.5 rounded ${
                                            updateTask.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                            updateTask.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                            'bg-blue-500/20 text-blue-400'
                                        }`}>
                                            {updateTask.phase === 'apt_update' ? 'apt update' :
                                             updateTask.phase === 'apt_upgrade' ? 'apt upgrade' :
                                             updateTask.phase === 'reboot' ? 'Reboot' :
                                             updateTask.phase === 'wait_online' ? t('waitingForNode') :
                                             updateTask.phase === 'done' ? t('done') :
                                             updateTask.status}
                                        </span>
                                        {/* Dismiss button for completed/failed */}
                                        {!haReadOnly && (updateTask.status === 'completed' || updateTask.status === 'failed') && (
                                            <button
                                                onClick={async (e) => {
                                                    e.stopPropagation();
                                                    try {
                                                        await fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/update`, { 
                                                            method: 'DELETE',
                                                            credentials: 'include',
                                                            headers: getAuthHeaders()
                                                        });
                                                    } catch (e) {}
                                                }}
                                                className="text-xs text-gray-300 hover:text-white px-2 py-1 bg-proxmox-hover hover:bg-proxmox-border rounded transition-colors"
                                                title={t('dismissUpdate') || 'Dismiss'}
                                            >
                                                ✕ {t('dismiss') || 'Dismiss'}
                                            </button>
                                        )}
                                    </div>
                                </div>
                                
                                {/* Log Output */}
                                <div 
                                    className="bg-proxmox-darker rounded p-2 font-mono text-xs max-h-32 overflow-y-auto cursor-pointer"
                                    onClick={() => setShowUpdateLog(true)}
                                >
                                    {updateTask.output_lines?.slice(-5).map((line, idx) => (
                                        <div key={idx} className="text-gray-400 truncate">
                                            {line.text}
                                        </div>
                                    ))}
                                </div>
                                
                                {updateTask.status === 'completed' && (
                                    <div className="mt-2 text-xs text-green-400">
                                        ✅ {t('updateCompleted')} {updateTask.packages_upgraded} {t('packagesUpdated')}
                                    </div>
                                )}
                                
                                {updateTask.status === 'failed' && (
                                    <div className="mt-2 space-y-2">
                                        <div className="text-xs text-red-400">
                                            ❌ {t('error')}: {updateTask.error}
                                        </div>
                                        {!haReadOnly && (
                                        <button
                                            onClick={async () => {
                                                // First clear the update status
                                                try {
                                                    await fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/update`, { 
                                                        method: 'DELETE',
                                                        credentials: 'include',
                                                        headers: getAuthHeaders()
                                                    });
                                                } catch (e) {}
                                                // Then exit maintenance mode
                                                if (onMaintenanceToggle) onMaintenanceToggle(name, false);
                                            }}
                                            className="w-full px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-red-400 text-xs font-medium transition-colors"
                                        >
                                            {t('cancelAndExitMaintenance')}
                                        </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Maintenance Banner */}
                    {isInMaintenance && !isUpdating && (
                        <div className="mb-4 -mt-1 -mx-1">
                            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <Icons.Wrench />
                                        <span className="text-yellow-400 font-semibold text-sm">{t('maintenanceMode')}</span>
                                    </div>
                                    <span className={`text-xs px-2 py-0.5 rounded ${
                                        maintenanceTask?.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                        maintenanceTask?.status === 'completed_with_errors' ? 'bg-orange-500/20 text-orange-400' :
                                        maintenanceTask?.status === 'evacuating' ? 'bg-blue-500/20 text-blue-400' :
                                        maintenanceTask?.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                        'bg-yellow-500/20 text-yellow-400'
                                    }`}>
                                        {maintenanceTask?.status === 'completed' ? t('ready') :
                                         maintenanceTask?.status === 'completed_with_errors' ? t('completedWithErrors') :
                                         maintenanceTask?.status === 'evacuating' ? t('evacuating') :
                                         maintenanceTask?.status === 'failed' ? t('failed') :
                                         t('starting')}
                                    </span>
                                </div>
                                
                                {maintenanceTask && maintenanceTask.status === 'evacuating' && (
                                    <>
                                        <div className="mb-2">
                                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                                                <span>{t('progress')}</span>
                                                <span>{maintenanceTask.migrated_vms} / {maintenanceTask.total_vms} VMs</span>
                                            </div>
                                            <div className="h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                <div 
                                                    className="h-full bg-gradient-to-r from-yellow-500 to-yellow-400 transition-all duration-500"
                                                    style={{ width: `${maintenanceTask.progress_percent}%` }}
                                                />
                                            </div>
                                        </div>
                                        {maintenanceTask.current_vm && (
                                            <div className="text-xs text-gray-400">
                                                {t('migrating')}: <span className="text-white font-mono">{maintenanceTask.current_vm.name}</span>
                                            </div>
                                        )}
                                    </>
                                )}
                                
                                {/* Completed with errors - some VMs could not migrate (e.g. local storage) */}
                                {maintenanceTask?.status === 'completed_with_errors' && !metrics.maintenance_acknowledged && (
                                    <div className="space-y-3 mt-2">
                                        {/* Warning banner about failed migrations */}
                                        <div className="p-3 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                                            <div className="flex items-start gap-2 text-orange-400 text-xs">
                                                <Icons.AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                                <div>
                                                    <p className="font-medium">{t('migrationIncomplete') || 'Migration Incomplete'}</p>
                                                    <p className="text-orange-300/80 mt-1">
                                                        {t('someVmsOnLocalStorage') || 'Some VMs could not be migrated (likely local storage). They will be stopped during reboot.'}
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* Show which VMs failed */}
                                        {maintenanceTask?.failed_vms?.length > 0 && (
                                            <div className="p-2 bg-proxmox-dark rounded-lg">
                                                <p className="text-xs text-gray-400 mb-1">{t('failedToMigrate') || 'Failed to migrate'}:</p>
                                                <div className="flex flex-wrap gap-1">
                                                    {maintenanceTask.failed_vms.slice(0, 5).map((vm, idx) => (
                                                        <span key={idx} className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded font-mono">
                                                            {vm.name || vm.vmid || `VM ${idx + 1}`}
                                                        </span>
                                                    ))}
                                                    {maintenanceTask.failed_vms.length > 5 && (
                                                        <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 text-xs rounded">
                                                            +{maintenanceTask.failed_vms.length - 5} {t('more') || 'more'}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                        
                                        {/* Proceed or Exit buttons */}
                                        {!haReadOnly && (
                                        <div className="flex gap-2">
                                            <button
                                                onClick={async () => {
                                                    if (confirm(t('forceMaintenanceWarning') || '⚠️ WARNING: Proceeding will allow actions that may stop the remaining VMs. Continue?')) {
                                                        // Acknowledge the warning - unlock full menu
                                                        try {
                                                            await fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/maintenance/acknowledge`, {
                                                                method: 'POST',
                                                                credentials: 'include',
                                                                headers: { 'Content-Type': 'application/json' }
                                                            });
                                                        } catch (e) { console.error(e); }
                                                    }
                                                }}
                                                className="flex-1 flex items-center justify-center gap-2 px-3 py-1.5 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded-lg text-orange-400 text-xs font-medium transition-colors"
                                            >
                                                <Icons.AlertTriangle />
                                                {t('proceedAnyway') || 'Proceed Anyway'}
                                            </button>
                                            <button
                                                onClick={() => onMaintenanceToggle(name, false)}
                                                className="flex-1 px-3 py-1.5 bg-gray-500/20 hover:bg-gray-500/30 border border-gray-500/30 rounded-lg text-gray-400 text-xs font-medium transition-colors"
                                            >
                                                {t('exitMaintenance')}
                                            </button>
                                        </div>
                                        )}
                                    </div>
                                )}
                                
                                {/* After acknowledging completed_with_errors OR normal completed - show full menu */}
                                {!haReadOnly && (maintenanceTask?.status === 'completed' || (maintenanceTask?.status === 'completed_with_errors' && metrics.maintenance_acknowledged)) && (
                                    <div className="space-y-2 mt-2">
                                        {/* Show warning reminder if there were errors */}
                                        {maintenanceTask?.status === 'completed_with_errors' && maintenanceTask?.failed_vms?.length > 0 && (
                                            <div className="p-2 bg-orange-500/10 border border-orange-500/20 rounded-lg text-xs text-orange-400 flex items-center gap-2">
                                                <Icons.AlertTriangle className="w-3 h-3" />
                                                {maintenanceTask.failed_vms.length} {t('vmsWillBeStopped') || 'VM(s) will be stopped during reboot'}
                                            </div>
                                        )}
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setShowUpdateConfirm(true)}
                                                className="flex-1 flex items-center justify-center gap-2 px-3 py-1.5 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-400 text-xs font-medium transition-colors"
                                            >
                                                <Icons.Download />
                                                {t('updateAndReboot')}
                                            </button>
                                            <button
                                                onClick={() => onMaintenanceToggle(name, false)}
                                                className="flex-1 px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-400 text-xs font-medium transition-colors"
                                            >
                                                {t('exitMaintenance')}
                                            </button>
                                        </div>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setShowRebootConfirm(true)}
                                                disabled={actionLoading}
                                                className="flex-1 flex items-center justify-center gap-2 px-3 py-1.5 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded-lg text-orange-400 text-xs font-medium transition-colors disabled:opacity-50"
                                            >
                                                <Icons.RefreshCw />
                                                {t('rebootNode')}
                                            </button>
                                            <button
                                                onClick={() => setShowShutdownConfirm(true)}
                                                disabled={actionLoading}
                                                className="flex-1 flex items-center justify-center gap-2 px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-red-400 text-xs font-medium transition-colors disabled:opacity-50"
                                            >
                                                <Icons.Power />
                                                {t('shutdownNode')}
                                            </button>
                                        </div>
                                        
                                        {/* Remove / Move Node - NS: Feb 2026 - only available after maintenance */}
                                        <div className="mt-3 pt-3 border-t border-proxmox-border/50 flex gap-2">
                                            <button
                                                onClick={() => onMoveNode && onMoveNode(name)}
                                                className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg text-blue-400 text-xs font-medium transition-colors"
                                            >
                                                <Icons.ArrowRight className="w-3 h-3" />
                                                {t('moveNodeToCluster') || 'Move to Cluster'}
                                            </button>
                                            <button
                                                onClick={() => onRemoveNode && onRemoveNode(name)}
                                                className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-lg text-red-400 text-xs font-medium transition-colors"
                                            >
                                                <Icons.Trash className="w-3 h-3" />
                                                {t('removeNodeFromCluster') || 'Remove'}
                                            </button>
                                        </div>
                                    </div>
                                )}
                                
                                {maintenanceTask?.failed_vms?.length > 0 && !['completed', 'completed_with_errors'].includes(maintenanceTask?.status) && (
                                    <div className="mt-2 text-xs text-red-400">
                                        ⚠️ {maintenanceTask.failed_vms.length} {t('vmsCouldNotMigrate')}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <div className={`p-2 rounded-lg ${
                                isUpdating ? 'bg-blue-500/10' :
                                isInMaintenance ? 'bg-yellow-500/10' : 'bg-proxmox-orange/10'
                            }`}>
                                {isUpdating ? <Icons.RotateCw /> : isInMaintenance ? <Icons.Wrench /> : <Icons.Server />}
                            </div>
                            <div>
                                <h3 className="font-semibold text-white">{name}</h3>
                                <div className="flex items-center gap-2 mt-0.5">
                                    <span className={`w-2 h-2 rounded-full ${
                                        isUpdating ? 'bg-blue-500 animate-pulse' :
                                        isInMaintenance ? 'bg-yellow-500' :
                                        metrics.status === 'online' ? 'bg-green-500 status-online' : 'bg-gray-500'
                                    }`} />
                                    <span className="text-xs text-gray-400">
                                        {isUpdating ? t('updating') : isInMaintenance ? t('maintenance') : metrics.status === 'online' ? t('online') : metrics.status === 'offline' ? t('offline') : metrics.status}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            {/* LW Oct 2026 - the star and the guests of the node, what the
                                right-click menu of a node offers in the corporate tree */}
                            {!haReadOnly && onToggleFavorite && (
                                <button
                                    onClick={() => onToggleFavorite(name)}
                                    className="p-2 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all"
                                    title={isFavorite ? t('favRemove') : t('favAdd')}
                                    data-fav={isFavorite ? 'on' : 'off'}
                                >
                                    <Icons.Star className={`w-5 h-5 ${isFavorite ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                                </button>
                            )}
                            {!haReadOnly && onGuestsAction && (guestActions || []).length > 0 && (
                                <div className="relative">
                                    <button
                                        onClick={() => setGuestsMenu(v => !v)}
                                        className="p-2 rounded-lg bg-proxmox-dark hover:bg-green-500/20 text-gray-400 hover:text-green-400 transition-all"
                                        title={t('nodeGuestsMenu')}
                                        aria-haspopup="menu"
                                        aria-expanded={guestsMenu}
                                        data-node-guests={name}
                                    >
                                        <Icons.Layers />
                                    </button>
                                    {guestsMenu && (
                                        <>
                                            <div className="fixed inset-0 z-40" onClick={() => setGuestsMenu(false)} />
                                            <div className="absolute right-0 top-full mt-1 w-48 bg-proxmox-card border border-proxmox-border rounded-lg shadow-xl z-50 py-1" role="menu">
                                                {guestActions.map(a => (
                                                    <button
                                                        key={a}
                                                        role="menuitem"
                                                        onClick={() => { setGuestsMenu(false); onGuestsAction(name, a); }}
                                                        className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                        data-action={a}
                                                    >
                                                        {a === 'startall' ? <Icons.PlayCircle /> : a === 'stopall' ? <Icons.Power /> : <Icons.ArrowRight />}
                                                        {t(a === 'startall' ? 'nodeGuestsStartAll' : a === 'stopall' ? 'nodeGuestsStopAll' : 'nodeGuestsMigrateAll')}
                                                    </button>
                                                ))}
                                            </div>
                                        </>
                                    )}
                                </div>
                            )}
                            {!haReadOnly && !isInMaintenance && !isUpdating && (
                                <button
                                    onClick={() => { setMaintOptions({}); setShowMaintenanceConfirm(true); }}
                                    className="p-2 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all"
                                    title={t('enterMaintenance')}
                                >
                                    <Icons.Wrench />
                                </button>
                            )}
                            <button
                                onClick={() => onOpenNodeConfig && onOpenNodeConfig(name)}
                                className="p-2 rounded-lg bg-proxmox-dark hover:bg-proxmox-orange/20 text-gray-400 hover:text-proxmox-orange transition-all"
                                title={t('nodeConfiguration')}
                            >
                                <Icons.Cog />
                            </button>
                            <div className="text-right">
                                <div className="text-xs text-gray-500">{t('score')}</div>
                                <div className={`font-mono font-bold text-lg ${
                                    metrics.score < 100 ? 'text-green-400' : metrics.score < 150 ? 'text-yellow-400' : 'text-red-400'
                                }`}>
                                    {metrics.score.toFixed(0)}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4 mb-4">
                        <Gauge value={metrics.cpu_percent} label="CPU" />
                        <Gauge value={metrics.mem_percent} label="RAM" />
                    </div>

                    <div className="space-y-3 pt-3 border-t border-proxmox-border">
                        <div className="flex items-center justify-between">
                            <span className="text-xs text-gray-500 flex items-center gap-2">
                                <Icons.Cpu /> {t('cpuHistory')}
                            </span>
                            <Sparkline data={history.cpu} width={80} height={24} />
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-xs text-gray-500 flex items-center gap-2">
                                <Icons.Memory /> {t('ramHistory')}
                            </span>
                            <Sparkline data={history.mem} width={80} height={24} />
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-gray-500">{t('ramUsage')}</span>
                            <span className="text-gray-300 font-mono">
                                {formatBytes(metrics.mem_used)} / {formatBytes(metrics.mem_total)}
                            </span>
                        </div>
                        {metrics.ksm && metrics.ksm.shared > 0 && (
                            <div className="flex items-center justify-between text-xs">
                                <span className="text-gray-500">{t('ksmSharing') || 'KSM Sharing'}</span>
                                <span className="text-purple-400 font-mono">{formatBytes(metrics.ksm.shared)}</span>
                            </div>
                        )}
                        
                        {/* Expandable Details */}
                        <button 
                            onClick={() => setExpanded(!expanded)}
                            className="w-full flex items-center justify-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors pt-2"
                        >
                            {expanded ? t('showLess') : t('showMore')}
                            <Icons.ChevronDown className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                        </button>
                        
                        {expanded && (
                            <div className="space-y-3 pt-2 border-t border-gray-700/50 animate-fade-in">
                                {/* Disk Usage - hidden for XCP-ng (no dom0 disk stats) */}
                                {metrics.disk_percent != null && <><div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500 flex items-center gap-2">
                                        <Icons.HardDrive /> {t('disk')}
                                    </span>
                                    <div className="flex items-center gap-2">
                                        <div className="w-16 h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                            <div
                                                className={`h-full rounded-full ${
                                                    metrics.disk_percent > 90 ? 'bg-red-500' :
                                                    metrics.disk_percent > 75 ? 'bg-yellow-500' : 'bg-green-500'
                                                }`}
                                                style={{ width: `${metrics.disk_percent || 0}%` }}
                                            />
                                        </div>
                                        <span className="text-gray-300 font-mono w-12 text-right">
                                            {(metrics.disk_percent || 0).toFixed(1)}%
                                        </span>
                                    </div>
                                </div>
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500">{t('diskUsage')}</span>
                                    <span className="text-gray-300 font-mono">
                                        {formatBytes(metrics.disk_used || 0)} / {formatBytes(metrics.disk_total || 0)}
                                    </span>
                                </div></>}
                                
                                {/* Network */}
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500 flex items-center gap-2">
                                        <Icons.Network /> {t('networkIn')}
                                    </span>
                                    <div className="flex items-center gap-2">
                                        <Sparkline data={history.netin} width={50} height={16} color="#22c55e" />
                                        <span className="text-green-400 font-mono w-16 text-right">
                                            {history.netin[history.netin.length-1]?.toFixed(1) || '0.0'} MB/s
                                        </span>
                                    </div>
                                </div>
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500 flex items-center gap-2">
                                        <Icons.Network /> {t('networkOut')}
                                    </span>
                                    <div className="flex items-center gap-2">
                                        <Sparkline data={history.netout} width={50} height={16} color="#f97316" />
                                        <span className="text-orange-400 font-mono w-16 text-right">
                                            {history.netout[history.netout.length-1]?.toFixed(1) || '0.0'} MB/s
                                        </span>
                                    </div>
                                </div>
                                
                                {/* Load Average */}
                                {metrics.loadavg && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500 flex items-center gap-2">
                                            <Icons.Activity /> {t('loadAverage')}
                                        </span>
                                        <span className="text-gray-300 font-mono">
                                            {Array.isArray(metrics.loadavg) ? 
                                                metrics.loadavg.map(l => typeof l === 'number' ? l.toFixed(2) : l).join(' / ') :
                                                typeof metrics.loadavg === 'number' ? metrics.loadavg.toFixed(2) : '-'
                                            }
                                        </span>
                                    </div>
                                )}
                                
                                {/* CPU Info */}
                                {metrics.cpuinfo && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500">{t('cores')}</span>
                                        <span className="text-gray-300">
                                            {metrics.cpuinfo.cores || metrics.cpuinfo.cpus || '-'} × {metrics.cpuinfo.sockets || 1} {t('socket')}
                                        </span>
                                    </div>
                                )}
                                
                                {/* Kernel Version */}
                                {metrics.kversion && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500">{t('kernel')}</span>
                                        <span className="text-gray-400 font-mono text-[10px] truncate max-w-32">
                                            {metrics.kversion.split(' ')[0] || metrics.kversion}
                                        </span>
                                    </div>
                                )}
                                
                                {/* Hypervisor Version */}
                                {metrics.pveversion && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500">{metrics.pveversion.startsWith('XCP') ? 'XCP-ng' : 'PVE'}</span>
                                        <span className="text-gray-400 font-mono text-[10px]">
                                            {metrics.pveversion}
                                        </span>
                                    </div>
                                )}
                            </div>
                        )}
                        
                        {metrics.uptime > 0 && (
                            <div className="flex items-center justify-between text-xs">
                                <span className="text-gray-500 flex items-center gap-1">
                                    <Icons.Clock /> {t('uptime')}
                                </span>
                                <span className="text-gray-300 font-mono">{formatUptime(metrics.uptime)}</span>
                            </div>
                        )}
                    </div>

                    {/* Maintenance Confirmation Modal */}
                    {showMaintenanceConfirm && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60" onClick={() => setShowMaintenanceConfirm(false)}>
                            <div
                                className="w-full max-w-md max-h-[90vh] overflow-y-auto bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl"
                                data-testid="maint-dialog"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-6 border-b border-proxmox-border">
                                    <div className="flex items-center gap-3">
                                        <div className="p-3 bg-yellow-500/10 rounded-xl">
                                            <Icons.Wrench />
                                        </div>
                                        <div>
                                            <h2 className="text-lg font-bold text-white">{t('maintenanceModeTitle')}</h2>
                                            <p className="text-sm text-gray-400">{name}</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6">
                                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-4">
                                        <p className="text-sm text-yellow-200">
                                            <strong>{t('warning')}:</strong> {t('maintenanceWarning').replace('Warning: ', '')}
                                        </p>
                                    </div>
                                    <p className="text-sm text-gray-400 mb-4">
                                        {t('maintenanceDesc')}
                                    </p>
                                    {/* LW Oct 2026 (#763, #954) - the evacuation options of the rolling update, for this node */}
                                    <div className="mb-6">
                                        <MaintenanceEvacOptions clusterId={clusterId} node={name} value={maintOptions} onChange={setMaintOptions} />
                                    </div>
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setShowMaintenanceConfirm(false)}
                                            className="flex-1 px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors"
                                        >
                                            {t('cancel')}
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowMaintenanceConfirm(false);
                                                onMaintenanceToggle(name, true, maintOptions);
                                            }}
                                            className="flex-1 px-4 py-2.5 bg-yellow-500 hover:bg-yellow-600 rounded-lg text-black font-medium transition-colors"
                                        >
                                            {t('startMaintenance')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Update Confirmation Modal */}
                    {showUpdateConfirm && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60" onClick={() => setShowUpdateConfirm(false)}>
                            <div 
                                className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-6 border-b border-proxmox-border">
                                    <div className="flex items-center gap-3">
                                        <div className="p-3 bg-blue-500/10 rounded-xl">
                                            <Icons.Download />
                                        </div>
                                        <div>
                                            <h2 className="text-lg font-bold text-white">{t('updateNode')}</h2>
                                            <p className="text-sm text-gray-400">{name}</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6">
                                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 mb-4">
                                        <p className="text-sm text-blue-200">
                                            {t('updateCommand')}
                                        </p>
                                    </div>
                                    
                                    <label className="flex items-center gap-3 mb-6 cursor-pointer">
                                        <input 
                                            type="checkbox" 
                                            checked={updateWithReboot}
                                            onChange={(e) => setUpdateWithReboot(e.target.checked)}
                                            className="w-5 h-5 rounded border-proxmox-border bg-proxmox-dark text-blue-500 focus:ring-blue-500"
                                        />
                                        <div>
                                            <span className="text-white font-medium">{t('rebootAfterUpdate')}</span>
                                            <p className="text-xs text-gray-500">{t('recommendedForKernel')}</p>
                                        </div>
                                    </label>
                                    
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setShowUpdateConfirm(false)}
                                            className="flex-1 px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors"
                                        >
                                            {t('cancel')}
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowUpdateConfirm(false);
                                                onStartUpdate(name, updateWithReboot);
                                            }}
                                            className="flex-1 px-4 py-2.5 bg-blue-500 hover:bg-blue-600 rounded-lg text-white font-medium transition-colors"
                                        >
                                            {t('startUpdate')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Update Log Modal */}
                    {showUpdateLog && updateTask && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/60" onClick={() => setShowUpdateLog(false)}>
                            <div 
                                className="w-full max-w-2xl bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl animate-scale-in overflow-hidden"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <Icons.Terminal />
                                        <h2 className="font-bold text-white">Update Log - {name}</h2>
                                    </div>
                                    <button
                                        onClick={() => setShowUpdateLog(false)}
                                        className="p-2 hover:bg-proxmox-hover rounded-lg transition-colors"
                                    >
                                        <Icons.X />
                                    </button>
                                </div>
                                <div className="p-4 bg-proxmox-darker font-mono text-xs max-h-96 overflow-y-auto">
                                    {updateTask.output_lines?.map((line, idx) => (
                                        <div key={idx} className="py-0.5 text-gray-300 hover:bg-proxmox-card/50">
                                            <span className="text-gray-600 mr-2">{new Date(line.timestamp).toLocaleTimeString('de-DE')}</span>
                                            {line.text}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Reboot Confirmation Modal */}
                    {showRebootConfirm && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/60" onClick={() => setShowRebootConfirm(false)}>
                            <div 
                                className="w-full max-w-md bg-proxmox-card border border-orange-500/30 rounded-2xl shadow-2xl animate-scale-in overflow-hidden"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-6 border-b border-orange-500/30 bg-orange-500/10">
                                    <div className="flex items-center gap-3">
                                        <div className="p-3 bg-orange-500/20 rounded-xl">
                                            <Icons.RefreshCw />
                                        </div>
                                        <div>
                                            <h2 className="text-lg font-bold text-white">{t('rebootNode')}</h2>
                                            <p className="text-sm text-orange-400">{name}</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6">
                                    <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 mb-4">
                                        <p className="text-sm text-orange-200">
                                            {t('rebootNodeWarning')}
                                        </p>
                                    </div>
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setShowRebootConfirm(false)}
                                            className="flex-1 px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors"
                                        >
                                            {t('cancel')}
                                        </button>
                                        <button
                                            onClick={async () => {
                                                setActionLoading('reboot');
                                                setShowRebootConfirm(false);
                                                if (onNodeAction) await onNodeAction(name, 'reboot');
                                                setActionLoading(null);
                                            }}
                                            disabled={actionLoading}
                                            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-orange-500 hover:bg-orange-600 rounded-lg text-white font-medium transition-colors disabled:opacity-50"
                                        >
                                            {actionLoading === 'reboot' ? <Icons.RotateCw /> : <Icons.RefreshCw />}
                                            {t('rebootNow')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Shutdown Confirmation Modal */}
                    {showShutdownConfirm && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/60" onClick={() => setShowShutdownConfirm(false)}>
                            <div 
                                className="w-full max-w-md bg-proxmox-card border border-red-500/30 rounded-2xl shadow-2xl animate-scale-in overflow-hidden"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="p-6 border-b border-red-500/30 bg-red-500/10">
                                    <div className="flex items-center gap-3">
                                        <div className="p-3 bg-red-500/20 rounded-xl">
                                            <Icons.Power />
                                        </div>
                                        <div>
                                            <h2 className="text-lg font-bold text-white">{t('shutdownNode')}</h2>
                                            <p className="text-sm text-red-400">{name}</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-6">
                                    <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-4">
                                        <p className="text-sm text-red-200">
                                            {t('shutdownNodeWarning')}
                                        </p>
                                    </div>
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setShowShutdownConfirm(false)}
                                            className="flex-1 px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors"
                                        >
                                            {t('cancel')}
                                        </button>
                                        <button
                                            onClick={async () => {
                                                setActionLoading('shutdown');
                                                setShowShutdownConfirm(false);
                                                if (onNodeAction) await onNodeAction(name, 'shutdown');
                                                setActionLoading(null);
                                            }}
                                            disabled={actionLoading}
                                            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-red-500 hover:bg-red-600 rounded-lg text-white font-medium transition-colors disabled:opacity-50"
                                        >
                                            {actionLoading === 'shutdown' ? <Icons.RotateCw /> : <Icons.Power />}
                                            {t('shutdownNow')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // LW: Feb 2026 - compact node row for corporate overview
        // NS: Mar 2026 - added sparkline history + detail cards
        function NodeCompactRow({ name, metrics, clusterId, nodeUiSuffix, onOpenNodeConfig, onMaintenanceToggle, onStartUpdate, onNodeAction, onRemoveNode, onMoveNode }) {
            const { t } = useTranslation();
            const { getAuthHeaders, haReadOnly } = useAuth();  // #625: read-only on a standby
            const [expanded, setExpanded] = useState(false);
            const [showMaintenanceConfirm, setShowMaintenanceConfirm] = useState(false);
            const [maintOptions, setMaintOptions] = useState({});  // #763, #954
            const [showRebootConfirm, setShowRebootConfirm] = useState(false);
            const [showShutdownConfirm, setShowShutdownConfirm] = useState(false);
            const [showUpdateConfirm, setShowUpdateConfirm] = useState(false);
            const [updateWithReboot, setUpdateWithReboot] = useState(true);
            const [actionLoading, setActionLoading] = useState(null);
            // sparkline history buffer - 20 pts like NodeCard
            const histRef = useRef({ cpu: Array(20).fill(0), mem: Array(20).fill(0) });
            const lastValRef = useRef(null);
            const [, bump] = useState(0);

            useEffect(() => {
                if (metrics && metrics !== lastValRef.current) {
                    lastValRef.current = metrics;
                    histRef.current = {
                        cpu: [...histRef.current.cpu.slice(1), metrics.cpu_percent || 0],
                        mem: [...histRef.current.mem.slice(1), metrics.mem_percent || (metrics.memory ? (metrics.memory.used / metrics.memory.total) * 100 : 0)]
                    };
                    bump(n => n + 1);
                }
            }, [metrics?.cpu_percent, metrics?.mem_percent]);

            const isOffline = !metrics || metrics.status === 'offline';
            const cpuPercent = metrics?.cpu_percent?.toFixed(1) || (metrics?.cpu ? (metrics.cpu * 100).toFixed(1) : '0');
            const ramPercent = metrics?.mem_percent?.toFixed(1) || (metrics?.memory ? ((metrics.memory.used / metrics.memory.total) * 100).toFixed(1) : '0');
            const isInMaintenance = metrics?.maintenance_mode;
            const maintenanceTask = metrics?.maintenance_task;
            const isUpdating = metrics?.is_updating;
            const updateTask = metrics?.update_task;
            const canUpdate = isInMaintenance && maintenanceTask?.status && (['completed', 'completed_with_errors'].includes(maintenanceTask.status) || metrics?.maintenance_acknowledged) && !isUpdating;
            const proxmoxTarget = { ...metrics, kind: 'node', name, node: name, node_ui_suffix: nodeUiSuffix || '' };  // #689
            const proxmoxUrl = getProxmoxObjectUrl(proxmoxTarget);

            const formatBytes = (bytes) => { if(!bytes)return'0 B';const k=1024,s=['B','KB','MB','GB','TB','PB'],i=Math.floor(Math.log(bytes)/Math.log(k));return(bytes/Math.pow(k,i)).toFixed(1)+' '+s[i]; };
            const formatUptime = (uptime) => {
                if(!uptime) return '-';
                const days = Math.floor(uptime / 86400);
                const hours = Math.floor((uptime % 86400) / 3600);
                const mins = Math.floor((uptime % 3600) / 60);
                if(days > 0) return `${days}d ${hours}h`;
                if(hours > 0) return `${hours}h ${mins}m`;
                return `${mins}m`;
            };

            // Status colors - Clarity dark theme
            const statusDotStyle = isOffline ? {background: '#f54f47'} : isInMaintenance ? {background: '#efc006'} : isUpdating ? {background: '#49afd9'} : {background: '#60b515'};
            const statusLabel = isOffline ? '' : isInMaintenance ? t('maintenance') : isUpdating ? (updateTask?.phase || t('updating')) : '';

            const nodeStatusCls = isOffline ? 'node-offline' : isInMaintenance ? 'node-maintenance' : 'node-online';
            return (
                <div className={`corp-node-row ${nodeStatusCls}`}>
                    {/* Main Row */}
                    <div className={`flex items-center gap-3 px-3 py-2 text-[13px] cursor-pointer ${isOffline ? 'opacity-50' : ''}`} onClick={() => !isOffline && setExpanded(!expanded)}>
                        {!isOffline && <Icons.ChevronRight className="w-3 h-3 flex-shrink-0 transition-transform" style={{color: '#728b9a', transform: expanded ? 'rotate(90deg)' : 'none'}} />}
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={statusDotStyle}></span>
                        <span className="font-medium w-32 truncate" style={{color: '#e9ecef'}}>{name}</span>
                        {!isOffline ? (
                            <>
                                {statusLabel && <span className={`corp-badge ${isInMaintenance ? 'corp-badge-locked' : 'corp-badge-ha'}`}>{statusLabel}</span>}
                                {isUpdating && updateTask && !isInMaintenance && (
                                    <span className="corp-badge" style={{
                                        background: updateTask.status === 'failed' ? 'rgba(245,79,71,0.15)' : updateTask.status === 'completed' ? 'rgba(96,181,21,0.15)' : 'rgba(73,175,217,0.15)',
                                        color: updateTask.status === 'failed' ? '#f54f47' : updateTask.status === 'completed' ? '#60b515' : '#49afd9',
                                        border: `1px solid ${updateTask.status === 'failed' ? 'rgba(245,79,71,0.3)' : updateTask.status === 'completed' ? 'rgba(96,181,21,0.3)' : 'rgba(73,175,217,0.3)'}`
                                    }}>
                                        {updateTask.status === 'completed' ? '✓ ' : updateTask.status === 'failed' ? '✕ ' : '⟳ '}
                                        {updateTask.status === 'failed' ? t('updateFailed') : updateTask.status === 'completed' ? t('updateCompleted') : `${t('updating') || 'Updating'}: ${updateTask.phase || '...'}`}
                                    </span>
                                )}
                                <span className="w-8" style={{color: '#728b9a'}}>CPU</span>
                                <div className="w-20 h-1.5 flex-shrink-0 overflow-hidden" style={{background: 'var(--corp-bar-track)', borderRadius: '1px'}}>
                                    <div className="h-full" style={{width: `${Math.min(cpuPercent, 100)}%`, background: '#49afd9', borderRadius: '1px'}}></div>
                                </div>
                                <span className="w-12 text-right" style={{color: '#adbbc4'}}>{cpuPercent}%</span>
                                {(() => { const d = histRef.current.cpu; const mx = Math.max(...d, 1); const pts = d.map((v,i) => `${(i/19)*40},${12-((v/mx)*12)}`).join(' '); return <svg width="40" height="12" className="corp-sparkline-inline"><polyline fill="none" stroke="#49afd9" strokeWidth="1" points={pts} /><circle cx="40" cy={12-((d[19]/mx)*12)} r="1.5" fill="#49afd9" /></svg>; })()}
                                <span className="w-8 ml-2" style={{color: '#728b9a'}}>RAM</span>
                                <div className="w-20 h-1.5 flex-shrink-0 overflow-hidden" style={{background: 'var(--corp-bar-track)', borderRadius: '1px'}}>
                                    <div className="h-full" style={{width: `${Math.min(ramPercent, 100)}%`, background: '#9b59b6', borderRadius: '1px'}}></div>
                                </div>
                                <span className="w-12 text-right" style={{color: '#adbbc4'}}>{ramPercent}%</span>
                                {(() => { const d = histRef.current.mem; const mx = Math.max(...d, 1); const pts = d.map((v,i) => `${(i/19)*40},${12-((v/mx)*12)}`).join(' '); return <svg width="40" height="12" className="corp-sparkline-inline"><polyline fill="none" stroke="#9b59b6" strokeWidth="1" points={pts} /><circle cx="40" cy={12-((d[19]/mx)*12)} r="1.5" fill="#9b59b6" /></svg>; })()}
                                {metrics.score != null && <span className="ml-3 w-16" style={{color: '#728b9a'}}>{t('score')}: <span style={{color: '#adbbc4'}}>{Number(metrics.score).toFixed(1)}</span></span>}
                                <span className="ml-3" style={{color: '#728b9a'}}>{formatUptime(metrics.uptime)}</span>
                                <span className="flex-1"></span>
                                {isInMaintenance && maintenanceTask && maintenanceTask.status === 'running' && (
                                    <span className="text-[11px] mr-2" style={{color: '#efc006'}}>{maintenanceTask.migrated_count || 0}/{maintenanceTask.total_vms || '?'} VMs</span>
                                )}
                                {proxmoxUrl && (
                                    <button onClick={(e) => { e.stopPropagation(); openProxmoxObject(proxmoxTarget); }} className="p-0.5 hover:text-white" style={{color: '#49afd9'}} title={t('openInProxmox') || 'Open in Proxmox'}>
                                        <Icons.ExternalLink className="w-3.5 h-3.5" />
                                    </button>
                                )}
                                <button onClick={(e) => { e.stopPropagation(); onOpenNodeConfig && onOpenNodeConfig(name); }} className="p-0.5 hover:text-white" style={{color: '#728b9a'}} title={t('settings') || 'Settings'}>
                                    <Icons.Settings className="w-3.5 h-3.5" />
                                </button>
                            </>
                        ) : (
                            <span className="text-[12px]" style={{color: '#f54f47'}}>{t('nodeUnreachable') || 'Node unreachable'}</span>
                        )}
                    </div>

                    {/* Expanded Detail Panel */}
                    {expanded && !isOffline && metrics && (
                        <div className="px-3 pb-3 pt-1 ml-5" style={{borderTop: '1px solid var(--corp-divider)'}}>
                            {/* Update Banner */}
                            {isUpdating && updateTask && (
                                <div className="mb-2 p-2 text-[12px]" style={{
                                    background: updateTask.status === 'failed' ? 'rgba(245,79,71,0.08)' : updateTask.status === 'completed' ? 'rgba(96,181,21,0.08)' : 'rgba(73,175,217,0.08)',
                                    border: `1px solid ${updateTask.status === 'failed' ? 'rgba(245,79,71,0.2)' : updateTask.status === 'completed' ? 'rgba(96,181,21,0.2)' : 'rgba(73,175,217,0.2)'}`
                                }}>
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2" style={{color: updateTask.status === 'failed' ? '#f54f47' : updateTask.status === 'completed' ? '#60b515' : '#49afd9'}}>
                                            {updateTask.status === 'completed' ? <Icons.CheckCircle className="w-3 h-3" /> : updateTask.status === 'failed' ? <Icons.XCircle className="w-3 h-3" /> : <Icons.Download className="w-3 h-3" />}
                                            <span className="font-medium">{
                                                updateTask.status === 'failed' ? t('updateFailed') :
                                                updateTask.status === 'completed' ? t('updateCompleted') :
                                                t('updateRunning')
                                            }: {updateTask.phase || '...'}</span>
                                        </div>
                                        {!haReadOnly && (updateTask.status === 'completed' || updateTask.status === 'failed') && (
                                            <button onClick={(e) => { e.stopPropagation();
                                                fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/update`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() }).catch(() => {});
                                            }} className="text-[10px] px-1.5 py-0.5 hover:text-white" style={{color: '#728b9a'}}>✕</button>
                                        )}
                                    </div>
                                    {updateTask.output && updateTask.output.length > 0 && (
                                        <pre className="mt-1 text-[10px] font-mono max-h-16 overflow-y-auto" style={{color: '#728b9a'}}>{(updateTask.output_lines || updateTask.output).slice(-3).map(l => typeof l === 'object' ? l.text : l).join('\n')}</pre>
                                    )}
                                    {updateTask.status === 'completed' && updateTask.packages_upgraded && (
                                        <div className="mt-1" style={{color: '#60b515'}}>{t('updateCompleted')} - {updateTask.packages_upgraded} {t('packagesUpdated')}</div>
                                    )}
                                    {updateTask.status === 'failed' && updateTask.error && (
                                        <div className="mt-1" style={{color: '#f54f47'}}>{updateTask.error}</div>
                                    )}
                                </div>
                            )}

                            {/* Maintenance Banner */}
                            {isInMaintenance && maintenanceTask && (
                                <div className="mb-2 p-2 text-[12px]" style={{background: 'rgba(239, 192, 6, 0.08)', border: '1px solid rgba(239, 192, 6, 0.2)'}}>
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2" style={{color: '#efc006'}}>
                                            <Icons.Wrench className="w-3 h-3" />
                                            <span className="font-medium">{t('maintenance')}</span>
                                            <span style={{color: '#728b9a'}}>- {
                                                maintenanceTask.status === 'completed' ? t('ready') :
                                                maintenanceTask.status === 'completed_with_errors' ? t('completedWithErrors') :
                                                maintenanceTask.status === 'evacuating' ? t('evacuating') :
                                                maintenanceTask.status === 'failed' ? t('failed') :
                                                maintenanceTask.status === 'running' ? t('running') || 'Running' :
                                                maintenanceTask.status
                                            }</span>
                                        </div>
                                        {(maintenanceTask.status === 'running' || maintenanceTask.status === 'evacuating') && maintenanceTask.total_vms > 0 && (
                                            <div className="flex items-center gap-2">
                                                <div className="w-16 h-1 overflow-hidden" style={{background: 'var(--corp-bar-track)', borderRadius: '1px'}}>
                                                    <div className="h-full" style={{width: `${(((maintenanceTask.migrated_count || maintenanceTask.migrated_vms || 0)) / maintenanceTask.total_vms) * 100}%`, background: '#efc006', borderRadius: '1px'}}></div>
                                                </div>
                                                <span style={{color: '#efc006'}}>{maintenanceTask.migrated_count || maintenanceTask.migrated_vms || 0}/{maintenanceTask.total_vms}</span>
                                            </div>
                                        )}
                                    </div>
                                    {maintenanceTask.failed_vms && maintenanceTask.failed_vms.length > 0 && (
                                        <div className="mt-1" style={{color: '#f54f47'}}>
                                            {t('failedToMigrate')}: {maintenanceTask.failed_vms.map(v => v.name || v.vmid).join(', ')}
                                        </div>
                                    )}
                                    {/* NS: force/exit buttons - only when NOT yet acknowledged */}
                                    {!haReadOnly && !metrics.maintenance_acknowledged && (maintenanceTask.status === 'completed_with_errors' || (maintenanceTask.failed_vms && maintenanceTask.failed_vms.length > 0)) && (
                                        <div className="mt-1.5 flex items-center gap-2">
                                            <button onClick={(e) => { e.stopPropagation();
                                                if (confirm(t('forceMaintenanceWarning') || 'Proceeding may stop remaining VMs. Continue?')) {
                                                    fetch(`${API_URL}/clusters/${clusterId}/nodes/${name}/maintenance/acknowledge`, { method: 'POST', credentials: 'include', headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' } }).catch(() => {});
                                                }
                                            }} className="px-2 py-0.5 text-[11px] font-medium" style={{background: 'rgba(239,192,6,0.15)', color: '#efc006', border: '1px solid rgba(239,192,6,0.3)'}}>
                                                <Icons.AlertTriangle className="w-2.5 h-2.5 inline mr-1" />{t('proceedAnyway')}
                                            </button>
                                            <button onClick={(e) => { e.stopPropagation(); onMaintenanceToggle && onMaintenanceToggle(name, false); }}
                                                className="px-2 py-0.5 text-[11px] font-medium" style={{background: 'rgba(96,181,21,0.1)', color: '#60b515', border: '1px solid rgba(96,181,21,0.3)'}}>
                                                {t('exitMaintenance')}
                                            </button>
                                        </div>
                                    )}
                                    {/* after acknowledge: show warning + unlocked actions like modern */}
                                    {metrics.maintenance_acknowledged && maintenanceTask.failed_vms && maintenanceTask.failed_vms.length > 0 && (
                                        <div className="mt-1.5 text-[11px]" style={{color: '#efc006'}}>
                                            <Icons.AlertTriangle className="w-2.5 h-2.5 inline mr-1" />
                                            {maintenanceTask.failed_vms.length} {t('vmsWillBeStopped') || 'VM(s) will be stopped during reboot'}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* NS Mar 2026 - property cards instead of flat text grid */}
                            <div className="corp-node-detail-grid">
                                <div className="corp-node-detail-card">
                                    <div className="corp-node-detail-label">{t('disk')}</div>
                                    <div className="corp-node-detail-value">{metrics.disk_percent?.toFixed(1) || '-'}%</div>
                                    <div className="corp-node-detail-sub">{metrics.disk_total ? `${formatBytes(metrics.disk_used || 0)} / ${formatBytes(metrics.disk_total)}` : '-'}</div>
                                </div>
                                <div className="corp-node-detail-card">
                                    <div className="corp-node-detail-label">Load</div>
                                    <div className="corp-node-detail-value">{
                                        Array.isArray(metrics.loadavg) ? metrics.loadavg.map(l => typeof l === 'number' ? l.toFixed(2) : l).join(' / ') :
                                        typeof metrics.loadavg === 'number' ? metrics.loadavg.toFixed(2) : (metrics.loadavg || '-')
                                    }</div>
                                    <div className="corp-node-detail-sub">{t('cpuCores')}: {metrics.cpus || metrics.cpu_count || (metrics.cpuinfo ? `${metrics.cpuinfo.cores || metrics.cpuinfo.cpus || '-'} × ${metrics.cpuinfo.sockets || 1}` : '-')}</div>
                                </div>
                                <div className="corp-node-detail-card">
                                    <div className="corp-node-detail-label">{t('uptime')}</div>
                                    <div className="corp-node-detail-value">{formatUptime(metrics.uptime)}</div>
                                    <div className="corp-node-detail-sub">{(metrics.kernel_version || metrics.kversion) ? (metrics.kernel_version || metrics.kversion.split(' ')[0]) : ''}</div>
                                </div>
                                <div className="corp-node-detail-card">
                                    <div className="corp-node-detail-label">{(metrics.pveversion || '').startsWith('XCP') ? 'XCP-ng' : 'PVE'}</div>
                                    <div className="corp-node-detail-value" style={{fontSize: 13}}>{metrics.pve_version || metrics.pveversion || '-'}</div>
                                    <div className="corp-node-detail-sub">{metrics.kernel_version || (metrics.kversion ? metrics.kversion.split(' ')[0] : '')}</div>
                                </div>
                            </div>

                    {/* Action Buttons */}
                    <div className="corp-toolbar flex flex-wrap items-center gap-1 pt-1" style={{borderTop: '1px solid var(--corp-divider)'}}>
                        {proxmoxUrl && (
                            <button onClick={() => openProxmoxObject(proxmoxTarget)}>
                                <Icons.ExternalLink className="w-3 h-3" style={{color: '#49afd9'}} /> {t('openInProxmox') || 'Open in Proxmox'}
                            </button>
                        )}
                        {!haReadOnly && (<>
                        {!isInMaintenance ? (
                            <button onClick={() => { setMaintOptions({}); setShowMaintenanceConfirm(true); }}>
                                <Icons.Wrench className="w-3 h-3" style={{color: '#efc006'}} /> {t('enterMaintenance') || t('maintenance')}
                                    </button>
                                ) : (
                                    <>
                                        <button onClick={() => onMaintenanceToggle && onMaintenanceToggle(name, false)}>
                                            <Icons.X className="w-3 h-3" style={{color: '#60b515'}} /> {t('exitMaintenance')}
                                        </button>
                                        {canUpdate && (
                                            <button onClick={() => setShowUpdateConfirm(true)}>
                                                <Icons.Download className="w-3 h-3" style={{color: '#49afd9'}} /> {t('startUpdate')}
                                            </button>
                                        )}
                                        {maintenanceTask?.status && (['completed', 'completed_with_errors'].includes(maintenanceTask.status) || metrics?.maintenance_acknowledged) && (
                                            <>
                                                {onRemoveNode && <button onClick={() => onRemoveNode(name)}><Icons.Trash className="w-3 h-3" style={{color: '#f54f47'}} /> {t('removeNodeFromCluster')}</button>}
                                                {onMoveNode && <button onClick={() => onMoveNode(name)}><Icons.ArrowRight className="w-3 h-3" /> {t('moveNodeToCluster')}</button>}
                                            </>
                                        )}
                                    </>
                                )}
                                <button onClick={() => setShowRebootConfirm(true)}>
                                    <Icons.RotateCw className="w-3 h-3" style={{color: '#efc006'}} /> {t('reboot')}
                                </button>
                                <button onClick={() => setShowShutdownConfirm(true)}>
                                    <Icons.Power className="w-3 h-3" style={{color: '#f54f47'}} /> {t('shutdown')}
                                </button>
                                </>)}
                            </div>
                        </div>
                    )}

                    {/* Confirmation Modals */}
                    {showMaintenanceConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-sm max-h-[90vh] overflow-y-auto bg-proxmox-card border border-proxmox-border p-5" data-testid="maint-dialog">
                                <h3 className="text-[14px] font-semibold mb-2" style={{color: '#e9ecef'}}>{t('enterMaintenance') || 'Enter Maintenance Mode'}</h3>
                                <p className="text-[13px] mb-4" style={{color: '#adbbc4'}}>{t('maintenanceWarning') || `All VMs on ${name} will be migrated to other nodes.`}</p>
                                {/* LW Oct 2026 (#763, #954) */}
                                <div className="mb-4">
                                    <MaintenanceEvacOptions clusterId={clusterId} node={name} value={maintOptions} onChange={setMaintOptions} />
                                </div>
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowMaintenanceConfirm(false)} className="px-3 py-1.5 text-[13px] border border-proxmox-border hover:text-white" style={{color: '#adbbc4'}}>{t('cancel')}</button>
                                    <button onClick={() => { onMaintenanceToggle && onMaintenanceToggle(name, true, maintOptions); setShowMaintenanceConfirm(false); }} className="px-3 py-1.5 text-[13px] text-white" style={{background: '#efc006', border: '1px solid #d4a905'}}>{t('confirm') || 'Confirm'}</button>
                                </div>
                            </div>
                        </div>
                    )}
                    {showUpdateConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border p-5">
                                <h3 className="text-[14px] font-semibold mb-2" style={{color: '#e9ecef'}}>{t('startUpdate') || 'Start Update'}</h3>
                                <label className="flex items-center gap-2 text-[13px] mb-4" style={{color: '#adbbc4'}}>
                                    <input type="checkbox" checked={updateWithReboot} onChange={(e) => setUpdateWithReboot(e.target.checked)} />
                                    {t('rebootAfterUpdate') || 'Reboot after update'}
                                </label>
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowUpdateConfirm(false)} className="px-3 py-1.5 text-[13px] border border-proxmox-border hover:text-white" style={{color: '#adbbc4'}}>{t('cancel')}</button>
                                    <button onClick={() => { onStartUpdate && onStartUpdate(name, updateWithReboot); setShowUpdateConfirm(false); }} className="px-3 py-1.5 text-[13px] text-white" style={{background: '#49afd9', border: '1px solid #3d9bc2'}}>{t('startUpdate') || 'Start'}</button>
                                </div>
                            </div>
                        </div>
                    )}
                    {showRebootConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border p-5">
                                <h3 className="text-[14px] font-semibold mb-2" style={{color: '#e9ecef'}}>{t('rebootNode') || `Reboot ${name}`}</h3>
                                <p className="text-[13px] mb-4" style={{color: '#adbbc4'}}>{t('rebootWarning') || 'This will reboot the node. All VMs will be affected.'}</p>
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowRebootConfirm(false)} className="px-3 py-1.5 text-[13px] border border-proxmox-border hover:text-white" style={{color: '#adbbc4'}}>{t('cancel')}</button>
                                    <button onClick={() => { onNodeAction && onNodeAction(name, 'reboot'); setShowRebootConfirm(false); }} className="px-3 py-1.5 text-[13px] text-white" style={{background: '#efc006', border: '1px solid #d4a905'}}>{t('reboot')}</button>
                                </div>
                            </div>
                        </div>
                    )}
                    {showShutdownConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border p-5">
                                <h3 className="text-[14px] font-semibold mb-2" style={{color: '#e9ecef'}}>{t('shutdownNode') || `Shutdown ${name}`}</h3>
                                <p className="text-[13px] mb-4" style={{color: '#adbbc4'}}>{t('shutdownWarning') || 'This will shut down the node.'}</p>
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowShutdownConfirm(false)} className="px-3 py-1.5 text-[13px] border border-proxmox-border hover:text-white" style={{color: '#adbbc4'}}>{t('cancel')}</button>
                                    <button onClick={() => { onNodeAction && onNodeAction(name, 'shutdown'); setShowShutdownConfirm(false); }} className="px-3 py-1.5 text-[13px] text-white" style={{background: '#f54f47', border: '1px solid #d4433d'}}>{t('shutdown')}</button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // LW Oct 2026 - optional columns of the guest table, in this order. Both come from what
        // the list already carries, no call per guest: the agent from the server's agent sweep,
        // the throughput from PVE's read/write counters
        const VM_LIST_EXTRA_COLS = ['agent', 'diskio'];

        // the counters are bytes since the guest started, and uptime comes from the same
        // pvestatd sample, so two samples give bytes per second whatever the refresh rhythm
        function guestIoSample(prev, r) {
            const up = Number(r.uptime), rd = Number(r.diskread), wr = Number(r.diskwrite);
            if (!(up > 0) || !isFinite(rd) || !isFinite(wr)) return null;
            const fresh = { up, rd, wr, read: null, write: null };
            if (!prev) return fresh;
            if (up === prev.up) return prev;
            // a read that arrives late is a little older, a restart starts over
            if (up < prev.up) return prev.up - up <= 30 ? prev : fresh;
            if (rd < prev.rd || wr < prev.wr) return fresh;
            const dt = up - prev.up;
            return { up, rd, wr, read: (rd - prev.rd) / dt, write: (wr - prev.wr) / dt };
        }

        function fmtIoRate(bps) {
            if (bps < 1024) return `${Math.round(bps)} B/s`;
            const units = ['KB/s', 'MB/s', 'GB/s'];
            let v = bps, i = -1;
            do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
            return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
        }

        // Resource Table Component
        // LW: The main VM/CT list - supports cards, table, and detail view
        // NS: Added bulk select for mass operations (migration, etc.)
        // This component does a lot... might need to split it up eventually
        // NS: filtering + sorting uses useMemo below (lines 1320+)
        function ResourceTable({ resources, clusterId, clusters, sourceCluster, onVmAction, onOpenConsole, onOpenSpice, onOpenConfig, onMigrate, onBulkMigrate, onDelete, onClone, onForceStop, onCrossClusterMigrate, nodes, datastores, onOpenTags, highlightedVm, addToast, pendingVmAction, onPendingActionConsumed, onVmNavigate, backupStatus, authFetch, onBulkDone, favorites, onToggleFavorite }) {
            const { t } = useTranslation();
            const { getAuthHeaders, user, haReadOnly, haConsolesElsewhere } = useAuth();
            // #625 v2 - a standby shows the guests live but acts on none of them: no power,
            // console, migrate, clone or delete buttons. Config, metrics and Proxmox links stay.
            // One that forwards acts through the active again, but a console only runs on a
            // standby that serves users: elsewhere a link opens the guest's console on the active
            const acts = !haReadOnly;
            const consoles = !haConsolesElsewhere;
            const { isCorporate } = useLayout(); // LW: Feb 2026 - corporate defaults to table view
            // NS Mar 2026 - per-VM sparkline history for table view
            const vmHistRef = useRef({});
            useEffect(() => {
                if (!resources || !isCorporate) return;
                const buf = vmHistRef.current;
                resources.forEach(r => {
                    if (r.status !== 'running') return;
                    const id = r.vmid;
                    if (!buf[id]) buf[id] = { cpu: Array(15).fill(0), mem: Array(15).fill(0) };
                    buf[id].cpu = [...buf[id].cpu.slice(1), r.cpu_percent || 0];
                    buf[id].mem = [...buf[id].mem.slice(1), r.mem_percent || 0];
                });
            }, [resources]);
            const [search, setSearch] = useState('');
            const [filter, setFilter] = useState('all');
            const [nodeFilter, setNodeFilter] = useState('all');
            const [tagFilter, setTagFilter] = useState('all');
            // NS #431: remember the table sort per user (localStorage, keyed by
            // username so a shared browser keeps each operator's choice).
            const _sortKey = `pegaprox-vmsort-${user?.username || '_'}`;
            const _savedSort = (() => { try { return JSON.parse(localStorage.getItem(_sortKey) || '{}'); } catch (e) { return {}; } })();
            const [sortBy, setSortBy] = useState(_savedSort.by || 'vmid');
            const [sortDir, setSortDir] = useState(_savedSort.dir || 'asc');
            // the optional columns, kept per user next to the sort
            const _colsKey = `pegaprox-vmcols-${user?.username || '_'}`;
            const [extraCols, setExtraCols] = useState(() => {
                try {
                    const v = JSON.parse(localStorage.getItem(_colsKey) || '[]');
                    return Array.isArray(v) ? VM_LIST_EXTRA_COLS.filter(k => v.includes(k)) : [];
                } catch (e) { return []; }
            });
            const [showColMenu, setShowColMenu] = useState(false);
            const colMenuRef = useRef(null);
            // a click anywhere else or Escape closes the column menu
            useEffect(() => {
                if (!showColMenu) return;
                const away = (e) => { if (colMenuRef.current && !colMenuRef.current.contains(e.target)) setShowColMenu(false); };
                const esc = (e) => { if (e.key === 'Escape') setShowColMenu(false); };
                document.addEventListener('mousedown', away);
                document.addEventListener('keydown', esc);
                return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc); };
            }, [showColMenu]);
            const toggleExtraCol = (key) => {
                const next = VM_LIST_EXTRA_COLS.filter(k => (k === key) !== extraCols.includes(k));
                setExtraCols(next);
                try { localStorage.setItem(_colsKey, JSON.stringify(next)); } catch (e) {}
            };
            const showAgent = extraCols.includes('agent');
            const showIo = extraCols.includes('diskio');
            const ioKey = (r) => `${r._clusterId || clusterId}:${r.vmid}`;
            const ioRef = useRef(new Map());
            const ioFedRef = useRef(null);
            const [ioTick, setIoTick] = useState(0);
            // true when a rate moved; a frame with the same pvestatd sample changes nothing
            const feedIo = (rows) => {
                const seen = ioRef.current, next = new Map();
                let moved = false;
                rows.forEach(r => {
                    if (!r || r.status !== 'running') return;
                    const prev = seen.get(ioKey(r));
                    const s = guestIoSample(prev, r);
                    if (s) next.set(ioKey(r), s);
                    if (s !== prev) moved = true;
                });
                ioRef.current = next;
                return moved || next.size !== seen.size;
            };
            // the list keeps its array while names, status and load stay put, so the rates
            // also take every frame the dashboard receives for this cluster
            useEffect(() => {
                if (!showIo) return;
                const onFrame = (e) => {
                    const d = (e && e.detail) || {};
                    if (d.cluster_id !== clusterId || !Array.isArray(d.rows)) return;
                    if (feedIo(d.rows)) setIoTick(n => n + 1);
                };
                window.addEventListener('pegaprox-resources-frame', onFrame);
                return () => window.removeEventListener('pegaprox-resources-frame', onFrame);
            }, [showIo, clusterId]);
            const ioRates = useMemo(() => {
                if (!showIo || !resources) { ioRef.current = new Map(); ioFedRef.current = null; return null; }
                if (ioFedRef.current !== resources) {
                    ioFedRef.current = resources;
                    feedIo(resources);
                }
                return new Map(ioRef.current);
            }, [resources, showIo, ioTick]);
            const ioTotal = (r) => {
                const s = ioRates && ioRates.get(ioKey(r));
                return s && s.read !== null ? s.read + s.write : -1;
            };
            // the rates re-sort the list only while it is sorted by them
            const ioSortRates = sortBy === 'diskio' ? ioRates : null;
            const agentRank = (r) => r.agent_running === true ? 2 : r.agent_running === false ? 1 : 0;
            const [viewMode, setViewMode] = useState(isCorporate ? 'table' : 'cards'); // LW: corporate defaults to table
            const [actionLoading, setActionLoading] = useState({});
            const [selectedVms, setSelectedVms] = useState([]);
            const [showMigrateModal, setShowMigrateModal] = useState(null);
            const [showBulkMigrate, setShowBulkMigrate] = useState(false);
            const [bulkGuests, setBulkGuests] = useState(null);  // {action, guests}
            const [showDeleteConfirm, setShowDeleteConfirm] = useState(null);
            const [showCloneModal, setShowCloneModal] = useState(null);
            const [selectedDetailVm, setSelectedDetailVm] = useState(null); // For detail view

            // NS: Mar 2026 - consume pending action from context menu
            useEffect(() => {
                if (!pendingVmAction) return;
                const { vm, action } = pendingVmAction;
                if (action === 'migrate') setShowMigrateModal(vm);
                else if (action === 'clone') setShowCloneModal(vm);
                else if (action === 'delete') setShowDeleteConfirm(vm);
                else if (action === 'crossCluster') setShowCrossClusterMigrate(vm);
                onPendingActionConsumed?.();
            }, [pendingVmAction]);
            const highlightedRowRef = useRef(null);
            
            // Pagination states - MK Jan 2026
            // LW: Moved up 25.01.2026 - must be declared before useEffect that uses them
            // This was breaking pre-compiled builds (GitHub Issue #4)
            // Browser-Babel was more forgiving but compiled JS enforces strict declaration order
            const [currentPage, setCurrentPage] = useState(1);
            const [itemsPerPage, setItemsPerPage] = useState(50); // Default 50, options: 50, 100, 200, 500
            
            // NS: scroll to highlighted VM from global search
            // claude helped with the pagination math here - kept getting off-by-one errors
            useEffect(() => {
                if (highlightedVm) {
                    // clear filters first
                    setSearch('');
                    setFilter('all');
                    
                    // jump to correct page
                    const vmIndex = resources.findIndex(r => r.vmid === highlightedVm.vmid);
                    if (vmIndex !== -1) {
                        const targetPage = Math.floor(vmIndex / itemsPerPage) + 1;
                        setCurrentPage(targetPage);
                    }
                    
                    // wait for render then scroll
                    setTimeout(() => {
                        if (highlightedRowRef.current) {
                            highlightedRowRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }
                    }, 100);
                }
            }, [highlightedVm, resources, itemsPerPage]);
            
            // NS: Update selectedDetailVm when resources change (via SSE)
            // This ensures the detail view shows the current status without re-selecting the VM
            useEffect(() => {
                if (selectedDetailVm && resources) {
                    const updatedVm = resources.find(r => 
                        r.vmid === selectedDetailVm.vmid
                    );
                    if (updatedVm) {
                        // Check if any relevant field changed
                        if (updatedVm.status !== selectedDetailVm.status ||
                            updatedVm.cpu !== selectedDetailVm.cpu ||
                            updatedVm.mem !== selectedDetailVm.mem ||
                            updatedVm.maxmem !== selectedDetailVm.maxmem ||
                            updatedVm.uptime !== selectedDetailVm.uptime ||
                            updatedVm.node !== selectedDetailVm.node ||
                            updatedVm.name !== selectedDetailVm.name ||
                            updatedVm.netin !== selectedDetailVm.netin ||
                            updatedVm.netout !== selectedDetailVm.netout ||
                            updatedVm.diskread !== selectedDetailVm.diskread ||
                            updatedVm.diskwrite !== selectedDetailVm.diskwrite
                        ) {
                            setSelectedDetailVm(updatedVm);
                        }
                    } else {
                        // VM was deleted or no longer in list
                        setSelectedDetailVm(null);
                    }
                }
            }, [resources]);
            
            const [showCrossClusterMigrate, setShowCrossClusterMigrate] = useState(null);
            const [showMetricsModal, setShowMetricsModal] = useState(null); // For VM metrics
            const [openDropdown, setOpenDropdown] = useState(null); // action dropdown menu
            const prevResources = useRef(resources);  // for comparison, not really used

            // NS: #127 - lazy-load IPs from guest agent for running qemu VMs
            const ipCache = useRef({});
            const [ipTick, setIpTick] = useState(0);

            const filterLabels = {
                all: t('all'),
                running: t('active'),
                stopped: t('stopped'),
                vm: 'VM',
                lxc: 'LXC'
            };

            // NS #431: IP sorts by octet value, not as a string. Pull the IP from
            // the lazy guest-agent cache (qemu) or off the resource (lxc); blanks last.
            const getIp = (r) => {
                const c = ipCache.current[r.vmid];
                return (c && c !== 'loading') ? c : (r.ip || '');
            };
            const ipSortKey = (ip) => {
                const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
                if (!m) return Number.MAX_SAFE_INTEGER;  // no IPv4 (empty / IPv6 / loading) → bottom
                return (((+m[1] * 256) + +m[2]) * 256 + +m[3]) * 256 + +m[4];
            };

            // LW: filter + sort in one useMemo for perf
            // MK: added tag/node/ip search, people kept complaining they couldnt find stuff
            const filteredResources = useMemo(() => {
                let filtered = resources.filter(r => {
                    // search by name, vmid, ip, node, or tags
                    const s = search.toLowerCase();
                    const matchesSearch = !search ||
                        r.name?.toLowerCase().includes(s) ||
                        r.vmid?.toString().includes(s) ||
                        (r.node || '').toLowerCase().includes(s) ||
                        (r.ip || '').toLowerCase().includes(s) ||
                        (r.tags || '').toLowerCase().includes(s);
                    const matchesFilter =
                        filter === 'all' ||
                        (filter === 'running' && r.status === 'running') ||
                        (filter === 'stopped' && r.status === 'stopped') ||
                        (filter === 'vm' && r.type === 'qemu') ||
                        (filter === 'lxc' && r.type === 'lxc');
                    const matchesNode = nodeFilter === 'all' || r.node === nodeFilter;
                    const matchesTag = tagFilter === 'all' || (Array.isArray(r.tags) ? r.tags : (r.tags || '').split(';')).some(t => t.trim().toLowerCase() === tagFilter.toLowerCase());
                    return matchesSearch && matchesFilter && matchesNode && matchesTag;
                });
                
                // sort; a saved sort on a column that is switched off falls back to the ID
                const by = VM_LIST_EXTRA_COLS.includes(sortBy) && !extraCols.includes(sortBy) ? 'vmid' : sortBy;
                filtered.sort((a, b) => {
                    const dir = sortDir === 'asc' ? 1 : -1;
                    if (by === 'ip') {  // NS #431: per-octet numeric, not lexical
                        return (ipSortKey(getIp(a)) - ipSortKey(getIp(b))) * dir;
                    }
                    if (by === 'agent') return (agentRank(a) - agentRank(b)) * dir;
                    if (by === 'diskio') return (ioTotal(a) - ioTotal(b)) * dir;
                    const aVal = a[by];
                    const bVal = b[by];
                    if (typeof aVal === 'number') return(aVal - bVal) * dir;
                    return String(aVal).localeCompare(String(bVal)) * dir;
                });

                return filtered;
            }, [resources, search, filter, nodeFilter, tagFilter, sortBy, sortDir, ipTick, extraCols, ioSortRates]);
            
            // Reset page when filters change - MK Jan 2026
            // NS: Also reset when cluster changes (via clusterId) to avoid showing empty page
            useEffect(() => {
                setCurrentPage(1);
            }, [search, filter, nodeFilter, tagFilter, sortBy, sortDir, itemsPerPage, clusterId]);
            
            // Paginated resources - MK Jan 2026
            const totalPages = Math.max(1, Math.ceil(filteredResources.length / itemsPerPage));
            
            // NS: Clamp currentPage to valid bounds - direct calculation, no effect loop
            const effectivePage = Math.max(1, Math.min(currentPage, totalPages));
            
            // NS: Auto-correct if currentPage is out of bounds (e.g., after cluster switch)
            useEffect(() => {
                if (currentPage > totalPages && totalPages > 0) {
                    setCurrentPage(1);  // Reset to first page
                }
            }, [filteredResources.length]);  // Only when data changes
            
            const paginatedResources = useMemo(() => {
                const startIndex = (effectivePage - 1) * itemsPerPage;
                return filteredResources.slice(startIndex, startIndex + itemsPerPage);
            }, [filteredResources, effectivePage, itemsPerPage]);

            // fetch IPs for visible running qemu VMs - #127
            useEffect(() => {
                if (!paginatedResources?.length) return;
                const toFetch = paginatedResources.filter(r =>
                    r.type === 'qemu' && r.status === 'running' && !ipCache.current[r.vmid]
                );
                if (!toFetch.length) return;
                toFetch.forEach(vm => {
                    ipCache.current[vm.vmid] = 'loading';
                    const cid = vm._clusterId || clusterId;
                    fetch(`/api/clusters/${cid}/vms/${vm.node}/qemu/${vm.vmid}/guest-info`, {
                        credentials: 'include', headers: getAuthHeaders()
                    })
                    .then(r => r.ok ? r.json() : null)
                    .then(data => {
                        ipCache.current[vm.vmid] = data?.ip_addresses?.length ? data.ip_addresses[0] : null;
                        setIpTick(t => t + 1);
                    })
                    .catch(() => { ipCache.current[vm.vmid] = null; });
                });
            }, [paginatedResources]);

            const handleSort = (col) => {
                let nextBy = col, nextDir = 'asc';
                if (sortBy === col) {
                    nextDir = sortDir === 'asc' ? 'desc' : 'asc';
                    setSortDir(nextDir);
                } else {
                    setSortBy(col);
                    setSortDir('asc');  // reset to asc on new column
                }
                // NS #431: persist the choice per user
                try { localStorage.setItem(_sortKey, JSON.stringify({ by: nextBy, dir: nextDir })); } catch (e) {}
            };

            // NS: 1073741824 = 1024^3 (GB), 1048576 = 1024^2 (MB)
            const formatBytes = (bytes) => {
                const gb = bytes / 1073741824;
                return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1048576).toFixed(0)} MB`;
            };

            const getVmProxmoxTarget = (resource) => ({
                ...resource,
                type: resource.type,
                node: resource.node,
                node_ip: resource.node_ip || resource.nodeIp || sourceCluster?.current_host || sourceCluster?.host,
                node_ui_suffix: sourceCluster?.node_ui_suffix || ''   // #689
            });
            
            // old version for reference
            // const formatBytes2 = (b) => b >= 1073741824 ? `${(b/1073741824).toFixed(1)} GB` : `${(b/1048576).toFixed(0)} MB`;

            const handleAction = async (resource, action) => {
                const key = `${resource.vmid}-${action}`;
                setActionLoading(prev => ({ ...prev, [key]: true }));
                await onVmAction(resource, action);
                setActionLoading(prev => ({ ...prev, [key]: false }));
            };

            const toggleSelect = (resource) => {
                setSelectedVms(prev => {
                    const exists = prev.find(v => v.vmid === resource.vmid);
                    if (exists) {
                        return prev.filter(v => v.vmid !== resource.vmid);
                    }
                    return [...prev, { vmid: resource.vmid, node: resource.node, type: resource.type, name: resource.name }];
                });
            };

            const toggleSelectAll = () => {
                if (selectedVms.length === filteredResources.length) {
                    setSelectedVms([]);
                } else {
                    setSelectedVms(filteredResources.map(r => ({ vmid: r.vmid, node: r.node, type: r.type, name: r.name })));
                }
            };

            // LW Oct 2026 - the bulk dialog gets the live row of each picked guest as it is at
            // the click, so a guest that stopped since it was ticked counts as stopped
            const openBulk = (action) => {
                const byId = new Map(resources.map(r => [r.vmid, r]));
                const guests = selectedVms.map(s => byId.get(s.vmid) || s)
                    .map(r => ({ ...r, _clusterId: r._clusterId || clusterId }));
                setBulkGuests({ action, guests });
            };
            const bulkButtons = [
                { action: 'start', label: t('start'), cls: 'bg-green-600 hover:bg-green-700', icon: <Icons.PlayCircle /> },
                { action: 'shutdown', label: t('shutdown'), cls: 'bg-yellow-600 hover:bg-yellow-700', icon: <Icons.Power /> },
                { action: 'reboot', label: t('reboot'), cls: 'bg-orange-500 hover:bg-orange-600', icon: <Icons.RefreshCw /> },
                { action: 'stop', label: t('forceStop'), cls: 'bg-red-600 hover:bg-red-700', icon: <Icons.XCircle /> },
                { action: 'snapshot', label: t('snapshot'), cls: 'bg-purple-600 hover:bg-purple-700', icon: <Icons.Camera /> },
                { action: 'tags', label: t('tags'), cls: 'bg-gray-600 hover:bg-gray-500', icon: <Icons.Tag /> },
            ];

            // the star of a guest, where the dashboard hands the favorites down
            const favSet = useMemo(() => new Set(((favorites && favorites.vms) || []).map(f => `${f.cluster_id}:${f.vmid}`)), [favorites]);
            const isFav = (r) => favSet.has(`${r._clusterId || clusterId}:${r.vmid}`);
            const canStar = acts && !!onToggleFavorite;

            const availableNodes = useMemo(() => {
                const nodeSet = new Set(resources.map(r => r.node).filter(Boolean));
                return Array.from(nodeSet).sort();
            }, [resources]);

            const availableTags = useMemo(() => {
                const tagSet = new Set();
                resources.forEach(r => {
                    if (r.tags) {
                        const tags = Array.isArray(r.tags) ? r.tags : r.tags.split(';');
                        tags.filter(t => t.trim()).forEach(t => tagSet.add(t.trim()));
                    }
                });
                return Array.from(tagSet).sort();
            }, [resources]);

            const groupedByNode = useMemo(() => {
                const groups = {};
                filteredResources.forEach(r => {
                    if (!groups[r.node]) groups[r.node] = [];
                    groups[r.node].push(r);
                });
                return groups;
            }, [filteredResources]);

            const extraColText = {
                agent: [t('listColAgent'), t('listColAgentHint')],
                diskio: [t('listColDiskIo'), t('listColDiskIoHint')],
            };
            const colPicker = (corp) => (
                <div className="relative" ref={colMenuRef}>
                    <button onClick={() => setShowColMenu(v => !v)} data-col-picker title={t('listColumns')}
                        className={corp ? `corp-toolbar-filter ${extraCols.length ? 'active' : ''}`
                            : 'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-proxmox-dark text-gray-400 hover:text-white border border-proxmox-border'}>
                        {!corp && <Icons.Settings />}
                        {t('listColumns')}
                    </button>
                    {showColMenu && (
                        <div className="absolute right-0 top-full mt-1 w-64 bg-proxmox-card border border-proxmox-border rounded-lg shadow-xl z-50 py-1" data-col-menu>
                            {VM_LIST_EXTRA_COLS.map(k => (
                                <label key={k} data-col-toggle={k} className="flex items-start gap-2 px-3 py-2 text-sm text-gray-300 hover:bg-proxmox-hover cursor-pointer">
                                    <input type="checkbox" checked={extraCols.includes(k)} onChange={() => toggleExtraCol(k)} className="w-4 h-4 mt-0.5 rounded" />
                                    <span className="flex-1 min-w-0">
                                        <span className="block">{extraColText[k][0]}</span>
                                        <span className="block text-xs text-gray-500">{extraColText[k][1]}</span>
                                    </span>
                                </label>
                            ))}
                        </div>
                    )}
                </div>
            );

            const agentCell = (r) => {
                if (r.type !== 'qemu' || r.status !== 'running' || typeof r.agent_running !== 'boolean') {
                    return <span className="text-xs text-gray-500" data-agent="none"
                        title={r.type === 'qemu' && r.status === 'running' ? t('listColAgentUnknown') : undefined}>-</span>;
                }
                return (
                    <span className={`inline-flex items-center gap-1.5 text-xs ${r.agent_running ? 'text-green-400' : 'text-gray-400'}`}
                        data-agent={r.agent_running ? 'up' : 'down'}>
                        <span className={`w-1.5 h-1.5 rounded-full ${r.agent_running ? 'bg-green-400' : 'bg-gray-500'}`} />
                        {r.agent_running ? t('yes') : t('no')}
                    </span>
                );
            };

            const ioCell = (r) => {
                const s = r.status === 'running' && ioRates ? ioRates.get(ioKey(r)) : null;
                if (!s || s.read === null) {
                    return <span className="text-xs text-gray-500" data-io="none"
                        title={r.status === 'running' ? t('listColDiskIoWait') : undefined}>-</span>;
                }
                return (
                    <div className="text-xs font-mono text-gray-400 whitespace-nowrap" data-io="rate"
                        data-io-read={Math.round(s.read)} data-io-write={Math.round(s.write)}>
                        <div>{t('listColRead')} {fmtIoRate(s.read)}</div>
                        <div>{t('listColWrite')} {fmtIoRate(s.write)}</div>
                    </div>
                );
            };

            const tableCols = [
                { key: 'vmid', label: 'ID' },
                { key: 'name', label: t('name') },
                { key: 'type', label: t('type') },
                { key: 'node', label: 'Node' },
                { key: 'ip', label: 'IP' },
                { key: 'cpu_percent', label: 'CPU' },
                { key: 'mem', label: 'RAM' },
                { key: 'disk', label: t('disk') },
                ...(showAgent ? [{ key: 'agent', label: t('listColAgent') }] : []),
                ...(showIo ? [{ key: 'diskio', label: t('listColDiskIo') }] : []),
                { key: 'status', label: 'Status' },
                { key: 'actions', label: t('actions') },
            ];

            return(
                <div className={isCorporate ? 'space-y-0' : 'space-y-4'}>
                    {/* LW: Mar 2026 - corporate flat toolbar vs modern rounded pills */}
                    {isCorporate ? (
                        <div className="corp-vm-toolbar" style={{flexWrap: 'wrap'}}>
                            <div className="relative">
                                <Icons.Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2" style={{color: '#728b9a'}} />
                                <input
                                    type="text"
                                    placeholder={t('searchByNameOrId')}
                                    value={search}
                                    onChange={(e) => setSearch(e.target.value)}
                                    className="pr-3 py-1 text-[13px] bg-transparent border text-white placeholder-gray-600 focus:outline-none w-56"
                                    style={{paddingLeft: '28px', borderColor: 'var(--corp-border-medium)', borderRadius: '2px'}}
                                />
                            </div>
                            <span className="corp-toolbar-divider" />
                            {['all', 'running', 'stopped', 'vm', 'lxc'].map(f => (
                                <button key={f} onClick={() => setFilter(f)}
                                    className={`corp-toolbar-filter ${filter === f ? 'active' : ''}`}>
                                    {filterLabels[f]}
                                </button>
                            ))}
                            <span className="corp-toolbar-divider" />
                            <span className="text-[11px]" style={{color: '#728b9a'}}>
                                {filteredResources.length} {t('items') || 'items'}
                            </span>
                            {viewMode === 'table' && (<>
                                <span className="corp-toolbar-divider" />
                                {colPicker(true)}
                            </>)}
                            <div style={{flex: 1}} />
                            {selectedVms.length > 0 && (
                                <>
                                    <span className="text-[11px]" style={{color: '#49afd9'}}>
                                        {selectedVms.length} {t('selectedItems') || 'selected'}
                                    </span>
                                    {/* LW Sep 2026 (#798) - the bulk bar below is suppressed in corporate
                                        because it was meant to live up here, but only the count ever made
                                        it across, so selecting rows in this layout did nothing at all. */}
                                    {acts && (<>
                                    {bulkButtons.map(b => (
                                        <button key={b.action} onClick={() => openBulk(b.action)} data-bulk={b.action}
                                            className="corp-toolbar-filter" style={b.action === 'stop' ? {color: '#f54f47'} : undefined}>
                                            {b.label}
                                        </button>
                                    ))}
                                    <button onClick={() => setShowBulkMigrate(true)} data-bulk="migrate"
                                        className="corp-toolbar-filter" style={{color: '#49afd9'}}>
                                        {t('migrate')}
                                    </button>
                                    </>)}
                                    <button onClick={() => setSelectedVms([])}
                                        className="corp-toolbar-filter">
                                        {t('clearSelection') || 'Clear selection'}
                                    </button>
                                </>
                            )}
                        </div>
                    ) : (
                    <div className="flex flex-wrap items-center gap-3">
                        <div className="relative flex-1 min-w-[200px]">
                            <Icons.Search />
                            <input
                                type="text"
                                placeholder={t('searchByNameOrId')}
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                                className="w-full pl-10 pr-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                            />
                            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">
                                <Icons.Search />
                            </div>
                        </div>
                        <div className={`flex items-center gap-2 ${isCorporate ? 'corp-toolbar-filter-group' : ''}`}>
                            {['all', 'running', 'stopped', 'vm', 'lxc'].map(f => (
                                <button
                                    key={f}
                                    onClick={() => setFilter(f)}
                                    className={isCorporate
                                        ? `corp-toolbar-filter ${filter === f ? 'active' : ''}`
                                        : `px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                                            filter === f
                                                ? 'bg-proxmox-orange text-white'
                                                : 'bg-proxmox-dark text-gray-400 hover:text-white border border-proxmox-border'
                                        }`}
                                >
                                    {filterLabels[f]}
                                </button>
                            ))}
                            {availableNodes.length > 1 && (
                                <select
                                    value={nodeFilter}
                                    onChange={e => setNodeFilter(e.target.value)}
                                    className={isCorporate
                                        ? `corp-toolbar-filter ${nodeFilter !== 'all' ? 'active' : ''}`
                                        : `px-3 py-1.5 text-xs font-medium rounded-lg transition-all cursor-pointer ${
                                            nodeFilter !== 'all'
                                                ? 'bg-proxmox-orange text-white'
                                                : 'bg-proxmox-dark text-gray-400 border border-proxmox-border'
                                        }`}
                                >
                                    <option value="all">{t('allNodes') || 'All Nodes'}</option>
                                    {availableNodes.map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            )}
                            {availableTags.length > 0 && (
                                <select
                                    value={tagFilter}
                                    onChange={e => setTagFilter(e.target.value)}
                                    className={isCorporate
                                        ? `corp-toolbar-filter ${tagFilter !== 'all' ? 'active' : ''}`
                                        : `px-3 py-1.5 text-xs font-medium rounded-lg transition-all cursor-pointer ${
                                            tagFilter !== 'all'
                                                ? 'bg-proxmox-orange text-white'
                                                : 'bg-proxmox-dark text-gray-400 border border-proxmox-border'
                                        }`}
                                >
                                    <option value="all">{t('allTags') || 'All Tags'}</option>
                                    {availableTags.map(tag => <option key={tag} value={tag}>{tag}</option>)}
                                </select>
                            )}
                        </div>
                        {viewMode === 'table' && colPicker(false)}
                        {isCorporate ? (
                        <div className="corp-toolbar-group">
                            <button onClick={() => setViewMode('cards')} className={`p-1.5 ${viewMode === 'cards' ? 'bg-proxmox-orange text-white' : 'bg-proxmox-dark text-gray-400 hover:text-white'}`} title={t('gridView')}>
                                <Icons.Grid />
                            </button>
                            <button onClick={() => setViewMode('table')} className={`p-1.5 ${viewMode === 'table' ? 'bg-proxmox-orange text-white' : 'bg-proxmox-dark text-gray-400 hover:text-white'}`} title={t('listView')}>
                                <Icons.List />
                            </button>
                            <button onClick={() => setViewMode('detail')} className={`p-1.5 ${viewMode === 'detail' ? 'bg-proxmox-orange text-white' : 'bg-proxmox-dark text-gray-400 hover:text-white'}`} title={t('compactView')}>
                                <Icons.Eye />
                            </button>
                        </div>
                        ) : (
                        <div className="flex items-center gap-1 p-1 bg-proxmox-dark rounded-lg border border-proxmox-border">
                            <button
                                onClick={() => setViewMode('cards')}
                                className={`p-1.5 rounded transition-colors ${viewMode === 'cards' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white'}`}
                                title={t('gridView')}
                            >
                                <Icons.Grid />
                            </button>
                            <button
                                onClick={() => setViewMode('table')}
                                className={`p-1.5 rounded transition-colors ${viewMode === 'table' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white'}`}
                                title={t('listView')}
                            >
                                <Icons.List />
                            </button>
                            <button
                                onClick={() => setViewMode('detail')}
                                className={`p-1.5 rounded transition-colors ${viewMode === 'detail' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white'}`}
                                title={t('compactView')}
                            >
                                <Icons.Eye />
                            </button>
                        </div>
                        )}
                    </div>
                    )}

                    {/* Bulk Actions Bar (hidden in corporate - integrated in toolbar) */}
                    {!isCorporate && acts && selectedVms.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2 p-3 bg-proxmox-orange/10 border border-proxmox-orange/30 rounded-lg">
                            <span className="text-sm text-proxmox-orange font-medium mr-1">
                                {selectedVms.length} {t('selectedItems')}
                            </span>
                            {bulkButtons.map(b => (
                                <button key={b.action} onClick={() => openBulk(b.action)} data-bulk={b.action}
                                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-white text-sm ${b.cls}`}>
                                    {b.icon}
                                    {b.label}
                                </button>
                            ))}
                            <button
                                onClick={() => setShowBulkMigrate(true)}
                                data-bulk="migrate"
                                className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 rounded-lg text-white text-sm hover:bg-blue-700"
                            >
                                <Icons.ArrowRight />
                                {t('migrate')}
                            </button>
                            <button
                                onClick={() => setSelectedVms([])}
                                className="px-3 py-1.5 text-gray-400 hover:text-white text-sm"
                            >
                                {t('deselectAll')}
                            </button>
                        </div>
                    )}

                    {/* Cards View */}
                    {viewMode === 'cards' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                            {paginatedResources.length === 0 ? (
                                <div className="col-span-full text-center py-12 text-gray-500">
                                    {t('noResults')}
                                </div>
                            ) : (
                                paginatedResources.map((resource, idx) => (
                                    <div 
                                        key={resource.vmid}
                                        ref={highlightedVm?.vmid === resource.vmid ? highlightedRowRef : null}
                                        className={`bg-proxmox-card border rounded-xl overflow-hidden transition-all hover:border-proxmox-orange/50 animate-fade-in ${
                                            selectedVms.find(v => v.vmid === resource.vmid) 
                                                ? 'border-proxmox-orange bg-proxmox-orange/5' 
                                                : highlightedVm?.vmid === resource.vmid
                                                    ? 'ring-2 ring-proxmox-orange border-proxmox-orange bg-proxmox-orange/20'
                                                    : 'border-proxmox-border'
                                        }`}
                                        style={{ animationDelay: `${idx * 30}ms` }}
                                    >
                                        {/* Card Header */}
                                        <div className="flex items-center justify-between p-4 border-b border-proxmox-border bg-proxmox-dark/50">
                                            <div className="flex items-center gap-3">
                                                <input 
                                                    type="checkbox"
                                                    checked={!!selectedVms.find(v => v.vmid === resource.vmid)}
                                                    onChange={() => toggleSelect(resource)}
                                                    className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange"
                                                />
                                                <div
                                                    className={`p-2 rounded-lg ${isGuestTemplate(resource) ? 'bg-gray-200/60 text-gray-700 border border-gray-300/40' : resource.type === 'qemu' ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}
                                                    title={getGuestTypeTitle(resource, t)}
                                                >
                                                    {getGuestTypeIcon(resource)}
                                                </div>
                                                <div>
                                                    <div className={`font-medium truncate ${onVmNavigate ? 'text-blue-400 hover:text-blue-300 hover:underline cursor-pointer' : 'text-white'}`} style={{maxWidth:'min(200px, 20vw)'}} onClick={onVmNavigate ? (e) => { e.stopPropagation(); onVmNavigate(resource); } : undefined}>
                                                        {resource.name || `${resource.type === 'qemu' ? 'VM' : 'CT'} ${resource.vmid}`}
                                                    </div>
                                                    <div className="text-xs text-gray-500">ID: {resource.vmid}</div>
                                                </div>
                                            </div>
                                            <span className={`w-2.5 h-2.5 rounded-full ${
                                                resource.status === 'running' ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                                            }`} />
                                        </div>
                                        
                                        {/* Card Body */}
                                        <div className="p-4 space-y-3">
                                            <div className="flex items-center justify-between text-sm">
                                                <span className="text-gray-500">{t('node')}</span>
                                                <span className="text-gray-300 font-mono">{resource.node}</span>
                                            </div>
                                            <div className="flex items-center justify-between text-sm">
                                                <span className="text-gray-500">{t('status')}</span>
                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                    resource.status === 'running' 
                                                        ? 'bg-green-500/10 text-green-400' 
                                                        : 'bg-red-500/10 text-red-400'
                                                }`}>
                                                    {resource.status === 'running' ? t('running') : t('stopped')}
                                                </span>
                                            </div>
                                            {/* IP Address - shown for running VMs with guest agent */}
                                            {resource.status === 'running' && resource.ip && (
                                                <div className="flex items-center justify-between text-sm">
                                                    <span className="text-gray-500">IP</span>
                                                    <span className="text-gray-300 font-mono text-xs">{resource.ip}</span>
                                                </div>
                                            )}
                                            {/* VM Tags */}
                                            {resource.tags && (
                                                <div className="flex flex-wrap gap-1">
                                                    {(Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).map((tag, i) => (
                                                        <span key={i} className="px-1.5 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                            {tag.trim()}
                                                        </span>
                                                    ))}
                                                </div>
                                            )}
                                            {/* NS May 2026 — backup status pill */}
                                            {backupStatus && backupStatus[resource.vmid] && window.PegaProxBackupStatusPill && (
                                                <div className="flex items-center justify-between text-sm">
                                                    <span className="text-gray-500 text-xs">Backup</span>
                                                    {React.createElement(window.PegaProxBackupStatusPill, {
                                                        status: backupStatus[resource.vmid].status,
                                                        lastAgeHours: backupStatus[resource.vmid].last_backup_age_hours,
                                                        encrypted: backupStatus[resource.vmid].encrypted,
                                                        verifyAgeHours: backupStatus[resource.vmid].last_verify_age_hours,
                                                        count30d: backupStatus[resource.vmid].count_30d,
                                                    })}
                                                </div>
                                            )}
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="text-gray-500">{t('ram')}</span>
                                                    <span className="text-gray-400 font-mono">
                                                        {formatBytes(resource.mem)} / {formatBytes(resource.maxmem)}
                                                    </span>
                                                </div>
                                                <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                    <div 
                                                        className="h-full rounded-full transition-all"
                                                        style={{
                                                            width: `${resource.mem_percent || 0}%`,
                                                            background: resource.mem_percent < 50 ? '#22c55e' : resource.mem_percent < 80 ? '#eab308' : '#ef4444'
                                                        }}
                                                    />
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="text-gray-500">{t('cpu')}</span>
                                                    <span className="text-gray-400 font-mono">
                                                        {(resource.cpu_percent || 0).toFixed(1)}% {resource.maxcpu && `(${resource.maxcpu} ${t('cores')})`}
                                                    </span>
                                                </div>
                                                <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full transition-all"
                                                        style={{
                                                            width: `${Math.min(resource.cpu_percent || 0, 100)}%`,
                                                            background: (resource.cpu_percent || 0) < 50 ? '#3b82f6' : (resource.cpu_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                                        }}
                                                    />
                                                </div>
                                            </div>
                                            {resource.maxdisk > 0 && (
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="text-gray-500">{t('disk')}</span>
                                                    <span className="text-gray-400 font-mono">
                                                        {resource.disk > 0 ? `${formatBytes(resource.disk)} / ${formatBytes(resource.maxdisk)}` : formatBytes(resource.maxdisk)}
                                                    </span>
                                                </div>
                                                {resource.disk > 0 && (
                                                <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full transition-all"
                                                        style={{
                                                            width: `${resource.disk_percent || 0}%`,
                                                            background: (resource.disk_percent || 0) < 75 ? '#22c55e' : (resource.disk_percent || 0) < 90 ? '#eab308' : '#ef4444'
                                                        }}
                                                    />
                                                </div>
                                                )}
                                            </div>
                                            )}
                                        </div>

                                        {/* Card Actions */}
                                        <div className="flex items-center justify-between p-3 border-t border-proxmox-border bg-proxmox-dark/30">
                                            {/* Primary Actions - Always visible */}
                                            <div className="flex items-center gap-1">
                                                {getProxmoxObjectUrl(getVmProxmoxTarget(resource)) && (
                                                    <button
                                                        onClick={() => openProxmoxObject(getVmProxmoxTarget(resource))}
                                                        className="p-1.5 rounded-lg hover:bg-cyan-500/20 text-gray-400 hover:text-cyan-400 transition-all"
                                                        title={t('openInProxmox') || 'Open in Proxmox'}
                                                    >
                                                        <Icons.ExternalLink />
                                                    </button>
                                                )}
                                                {!acts ? null : resource.status === 'stopped' ? (
                                                    <button
                                                        onClick={() => handleAction(resource, 'start')}
                                                        disabled={actionLoading[`${resource.vmid}-start`]}
                                                        className="p-1.5 rounded-lg hover:bg-green-500/20 text-gray-400 hover:text-green-400 transition-all disabled:opacity-50"
                                                        title={t('start')}
                                                    >
                                                        {actionLoading[`${resource.vmid}-start`] ? <Icons.RotateCw className="animate-spin" /> : <Icons.PlayCircle />}
                                                    </button>
                                                ) : (
                                                    <>
                                                        <button
                                                            onClick={() => handleAction(resource, 'shutdown')}
                                                            disabled={actionLoading[`${resource.vmid}-shutdown`]}
                                                            className="p-1.5 rounded-lg hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all disabled:opacity-50"
                                                            title={t('shutdown')}
                                                        >
                                                            {actionLoading[`${resource.vmid}-shutdown`] ? <Icons.RotateCw className="animate-spin" /> : <Icons.Power />}
                                                        </button>
                                                        <button
                                                            onClick={() => handleAction(resource, 'reboot')}
                                                            disabled={actionLoading[`${resource.vmid}-reboot`]}
                                                            className="p-1.5 rounded-lg hover:bg-orange-500/20 text-gray-400 hover:text-orange-400 transition-all disabled:opacity-50"
                                                            title={t('reboot')}
                                                        >
                                                            {actionLoading[`${resource.vmid}-reboot`] ? <Icons.RotateCw className="animate-spin" /> : <Icons.RefreshCw />}
                                                        </button>
                                                    </>
                                                )}
                                                {consoles && resource.status === 'running' && (
                                                    <button
                                                        onClick={() => onOpenConsole(resource)}
                                                        className="p-1.5 rounded-lg hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                        title={t('console')}
                                                    >
                                                        <Icons.Monitor />
                                                    </button>
                                                )}
                                                {!consoles && resource.status === 'running' && (
                                                    <HaOnActiveLink vm={resource} clusterId={clusterId} iconOnly
                                                        className="p-1.5 rounded-lg hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all" />
                                                )}
                                                {consoles && resource.status === 'running' && resource.type === 'qemu' && onOpenSpice && (
                                                    <button
                                                        onClick={() => onOpenSpice(resource)}
                                                        className="p-1.5 rounded-lg hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                        title={t('spiceConsole') || 'SPICE'}
                                                    >
                                                        <Icons.ExternalLink />
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => onOpenConfig(resource)}
                                                    className="p-1.5 rounded-lg hover:bg-purple-500/20 text-gray-400 hover:text-purple-400 transition-all"
                                                    title={t('configuration')}
                                                >
                                                    <Icons.Cog />
                                                </button>
                                                {acts && (
                                                <button
                                                    onClick={() => setShowMigrateModal(resource)}
                                                    className="p-1.5 rounded-lg hover:bg-cyan-500/20 text-gray-400 hover:text-cyan-400 transition-all"
                                                    title={t('migrate')}
                                                >
                                                    <Icons.ArrowRight />
                                                </button>
                                                )}
                                            </div>
                                            
                                            {/* More Actions Dropdown */}
                                            <div className="relative">
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        setOpenDropdown(openDropdown === resource.vmid ? null : resource.vmid);
                                                    }}
                                                    className="p-1.5 rounded-lg hover:bg-proxmox-hover text-gray-400 hover:text-white transition-all"
                                                    title={t('moreActions')}
                                                >
                                                    <Icons.MoreVertical />
                                                </button>
                                                
                                                {openDropdown === resource.vmid && (
                                                    <>
                                                        <div className="fixed inset-0 z-40" onClick={() => setOpenDropdown(null)} />
                                                        <div className="absolute right-0 bottom-full mb-1 w-48 bg-proxmox-card border border-proxmox-border rounded-lg shadow-xl z-50 py-1 animate-fade-in">
                                                            {acts && (<>
                                                            <button
                                                                onClick={() => { setShowMigrateModal(resource); setOpenDropdown(null); }}
                                                                className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                            >
                                                                <Icons.ArrowRight className="w-4 h-4" />
                                                                {t('migrate')}
                                                            </button>
                                                            {clusters && clusters.length > 1 && (
                                                                <button
                                                                    onClick={() => { setShowCrossClusterMigrate(resource); setOpenDropdown(null); }}
                                                                    className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                                >
                                                                    <Icons.Globe className="w-4 h-4" />
                                                                    {t('crossClusterMigrate')}
                                                                </button>
                                                            )}
                                                            </>)}
                                                            {canStar && (
                                                                <button
                                                                    onClick={() => { onToggleFavorite(resource); setOpenDropdown(null); }}
                                                                    className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                                    data-fav={isFav(resource) ? 'on' : 'off'}
                                                                >
                                                                    <Icons.Star className={`w-4 h-4 ${isFav(resource) ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                                                                    {isFav(resource) ? t('favRemove') : t('favAdd')}
                                                                </button>
                                                            )}
                                                            <button
                                                                onClick={() => { setShowMetricsModal(resource); setOpenDropdown(null); }}
                                                                className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                            >
                                                                <Icons.BarChart className="w-4 h-4" />
                                                                {t('performance')}
                                                            </button>
                                                            {acts && (<>
                                                            <button
                                                                onClick={() => { setShowCloneModal(resource); setOpenDropdown(null); }}
                                                                className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                            >
                                                                <Icons.Copy className="w-4 h-4" />
                                                                {t('clone')}
                                                            </button>
                                                            {resource.status === 'running' && (
                                                                <>
                                                                    {/* Force Reset - QEMU only */}
                                                                    {resource.type === 'qemu' && (
                                                                        <button
                                                                            onClick={() => { onVmAction(resource, 'reset'); setOpenDropdown(null); }}
                                                                            className="w-full px-3 py-2 text-left text-sm text-yellow-400 hover:bg-yellow-500/10 flex items-center gap-2"
                                                                        >
                                                                            <Icons.Zap className="w-4 h-4" />
                                                                            {t('forceReset')}
                                                                        </button>
                                                                    )}
                                                                    <button
                                                                        onClick={() => { onForceStop(resource); setOpenDropdown(null); }}
                                                                        className="w-full px-3 py-2 text-left text-sm text-yellow-400 hover:bg-yellow-500/10 flex items-center gap-2"
                                                                    >
                                                                        <Icons.XCircle className="w-4 h-4" />
                                                                        {t('forceStop')}
                                                                    </button>
                                                                </>
                                                            )}
                                                            <div className="border-t border-proxmox-border my-1" />
                                                            <button
                                                                onClick={() => { setShowDeleteConfirm(resource); setOpenDropdown(null); }}
                                                                className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-500/10 flex items-center gap-2"
                                                            >
                                                                <Icons.Trash className="w-4 h-4" />
                                                                {t('delete')}
                                                            </button>
                                                            </>)}
                                                        </div>
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}

                    {/* LW: Feb 2026 - table view, corporate data-grid */}
                    {viewMode === 'table' && (
                        <div className={isCorporate ? 'overflow-hidden border border-proxmox-border' : 'overflow-hidden rounded-xl border border-proxmox-border'}>
                            <table className={`w-full ${isCorporate ? 'corp-datagrid corp-datagrid-striped' : ''}`}>
                                <thead>
                                    <tr className={isCorporate ? 'text-left' : 'bg-proxmox-dark text-left'} style={isCorporate ? {background: 'var(--corp-header-bg)'} : undefined}>
                                        <th className={isCorporate ? 'px-2 py-1.5 w-8' : 'px-4 py-3 w-10'}>
                                            <input
                                                type="checkbox"
                                                checked={selectedVms.length === filteredResources.length && filteredResources.length > 0}
                                                onChange={toggleSelectAll}
                                                className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange focus:ring-proxmox-orange"
                                            />
                                        </th>
                                        {tableCols.map(col => (
                                            <th
                                                key={col.key}
                                                data-col={col.key}
                                                onClick={() => col.key !== 'actions' && !col.noSort && handleSort(col.key)}
                                                className={isCorporate
                                                    ? `text-xs font-semibold uppercase tracking-wider ${col.key !== 'actions' && !col.noSort ? 'cursor-pointer hover:text-white' : ''}`
                                                    : `px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider ${col.key !== 'actions' && !col.noSort ? 'cursor-pointer hover:text-white' : ''} transition-colors`
                                                }
                                                style={isCorporate ? {color: '#adbbc4', padding: '6px 8px', fontSize: '12px'} : undefined}
                                            >
                                                <div className="flex items-center gap-1">
                                                    {col.label}
                                                    {isCorporate ? (
                                                        sortBy === col.key ? (
                                                            <svg className="corp-sort-icon" viewBox="0 0 8 8"><path d={sortDir === 'asc' ? 'M4 1L7 6H1z' : 'M4 7L1 2h6z'} /></svg>
                                                        ) : col.key !== 'actions' && !col.noSort ? (
                                                            <svg className="corp-sort-icon corp-sort-hint" viewBox="0 0 8 8"><path d="M4 1L7 6H1z" /></svg>
                                                        ) : null
                                                    ) : (
                                                        sortBy === col.key && (
                                                            <span className="text-proxmox-orange">{sortDir === 'asc' ? '↑' : '↓'}</span>
                                                        )
                                                    )}
                                                </div>
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className={isCorporate ? '' : 'divide-y divide-proxmox-border'}>
                                    {paginatedResources.length === 0 ? (
                                        <tr>
                                            <td colSpan={tableCols.length + 1} className={isCorporate ? 'px-2 py-4 text-center text-gray-500' : 'px-4 py-8 text-center text-gray-500'}>
                                                {t('noResults')}
                                            </td>
                                        </tr>
                                    ) : (
                                        paginatedResources.map((resource, idx) => (
                                            <tr
                                                key={resource.vmid}
                                                ref={highlightedVm?.vmid === resource.vmid ? highlightedRowRef : null}
                                                className={isCorporate
                                                    ? `table-row-hover ${selectedVms.find(v => v.vmid === resource.vmid) ? 'corp-row-selected' : ''} ${highlightedVm?.vmid === resource.vmid ? 'corp-row-selected' : ''}`
                                                    : `table-row-hover bg-proxmox-card animate-fade-in ${selectedVms.find(v => v.vmid === resource.vmid) ? 'bg-proxmox-orange/5' : ''} ${highlightedVm?.vmid === resource.vmid ? 'ring-2 ring-proxmox-orange bg-proxmox-orange/20' : ''}`
                                                }
                                                style={isCorporate ? undefined : { animationDelay: `${idx * 30}ms` }}
                                            >
                                                <td className="px-4 py-3">
                                                    <input 
                                                        type="checkbox"
                                                        checked={!!selectedVms.find(v => v.vmid === resource.vmid)}
                                                        onChange={() => toggleSelect(resource)}
                                                        className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange focus:ring-proxmox-orange"
                                                    />
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="font-mono text-sm text-gray-300">{resource.vmid}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div>
                                                        <div className="flex items-center gap-1.5">
                                                            <span className={`font-medium truncate block ${onVmNavigate ? 'text-blue-400 hover:text-blue-300 hover:underline cursor-pointer' : 'text-white'}`} style={{maxWidth:'min(220px, 18vw)'}} onClick={onVmNavigate ? (e) => { e.stopPropagation(); onVmNavigate(resource); } : undefined} title={resource.name}>{resource.name || '-'}</span>
                                                            {/* NS May 2026 — backup status pill (table-row layout) */}
                                                            {backupStatus && backupStatus[resource.vmid] && window.PegaProxBackupStatusPill && React.createElement(window.PegaProxBackupStatusPill, {
                                                                status: backupStatus[resource.vmid].status,
                                                                lastAgeHours: backupStatus[resource.vmid].last_backup_age_hours,
                                                                encrypted: backupStatus[resource.vmid].encrypted,
                                                                verifyAgeHours: backupStatus[resource.vmid].last_verify_age_hours,
                                                                count30d: backupStatus[resource.vmid].count_30d,
                                                            })}
                                                        </div>
                                                        {resource.tags && (
                                                            <div className="flex flex-wrap gap-1 mt-1">
                                                                {(Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).slice(0, 3).map((tag, i) => (
                                                                    <span key={i} className="px-1.5 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                                        {tag.trim()}
                                                                    </span>
                                                                ))}
                                                                {(Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).length > 3 && (
                                                                    <span className="px-1.5 py-0.5 text-xs rounded bg-gray-500/20 text-gray-400">
                                                                        +{(Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).length - 3}
                                                                    </span>
                                                                )}
                                                            </div>
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium ${
                                                        isGuestTemplate(resource)
                                                            ? 'bg-gray-200/60 text-gray-700 border border-gray-300/40'
                                                            : resource.type === 'qemu' 
                                                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                                            : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                                                    }`} title={getGuestTypeTitle(resource, t)}>
                                                        {getGuestTypeIcon(resource)}
                                                        {getGuestTypeLabel(resource)}
                                                        {isGuestTemplate(resource) && (
                                                            <span className="text-amber-300">({getTemplateLabel(t)})</span>
                                                        )}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="text-sm text-gray-300 truncate block" style={{maxWidth:'min(140px, 12vw)'}} title={resource.node}>{resource.node}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="text-xs font-mono text-gray-400">{ipCache.current[resource.vmid] && ipCache.current[resource.vmid] !== 'loading' ? ipCache.current[resource.vmid] : '-'}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 max-w-[60px]">
                                                            <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                                <div className="h-full rounded-full transition-all"
                                                                    style={{
                                                                        width: `${Math.min(resource.cpu_percent || 0, 100)}%`,
                                                                        background: (resource.cpu_percent || 0) < 50 ? '#3b82f6' : (resource.cpu_percent || 0) < 80 ? '#eab308' : '#ef4444'
                                                                    }}
                                                                />
                                                            </div>
                                                        </div>
                                                        <span className="text-xs text-gray-400 font-mono">{(resource.cpu_percent || 0).toFixed(0)}%</span>
                                                        {isCorporate && resource.status === 'running' && (() => {
                                                            const h = (vmHistRef.current[resource.vmid] || {}).cpu;
                                                            if (!h || h.length < 2) return null;
                                                            const mx = Math.max(...h, 1);
                                                            const pts = h.map((v,i) => `${(i/14)*30},${10-((v/mx)*10)}`).join(' ');
                                                            return <svg width="30" height="10" className="corp-vm-sparkline"><polyline fill="none" stroke="#49afd9" strokeWidth="1" points={pts} /></svg>;
                                                        })()}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 max-w-[60px]">
                                                            <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                                <div
                                                                    className="h-full rounded-full transition-all"
                                                                    style={{
                                                                        width: `${resource.mem_percent || 0}%`,
                                                                        background: resource.mem_percent < 50 ? '#22c55e' : resource.mem_percent < 80 ? '#eab308' : '#ef4444'
                                                                    }}
                                                                />
                                                            </div>
                                                        </div>
                                                        <span className="text-xs text-gray-400 font-mono whitespace-nowrap">
                                                            {formatBytes(resource.mem)} / {formatBytes(resource.maxmem)}
                                                        </span>
                                                        {isCorporate && resource.status === 'running' && (() => {
                                                            const h = (vmHistRef.current[resource.vmid] || {}).mem;
                                                            if (!h || h.length < 2) return null;
                                                            const mx = Math.max(...h, 1);
                                                            const pts = h.map((v,i) => `${(i/14)*30},${10-((v/mx)*10)}`).join(' ');
                                                            return <svg width="30" height="10" className="corp-vm-sparkline"><polyline fill="none" stroke="#9b59b6" strokeWidth="1" points={pts} /></svg>;
                                                        })()}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        {resource.disk > 0 && (
                                                        <div className="flex-1 max-w-[60px]">
                                                            <div className="h-1.5 rounded-full bg-proxmox-border overflow-hidden">
                                                                <div
                                                                    className="h-full rounded-full transition-all"
                                                                    style={{
                                                                        width: `${resource.disk_percent || 0}%`,
                                                                        background: (resource.disk_percent || 0) < 75 ? '#22c55e' : (resource.disk_percent || 0) < 90 ? '#eab308' : '#ef4444'
                                                                    }}
                                                                />
                                                            </div>
                                                        </div>
                                                        )}
                                                        <span className="text-xs text-gray-400 font-mono whitespace-nowrap">
                                                            {resource.disk > 0 ? `${formatBytes(resource.disk)} / ${formatBytes(resource.maxdisk || 0)}` : formatBytes(resource.maxdisk || 0)}
                                                        </span>
                                                    </div>
                                                </td>
                                                {showAgent && <td className="px-4 py-3" data-col="agent">{agentCell(resource)}</td>}
                                                {showIo && <td className="px-4 py-3" data-col="diskio">{ioCell(resource)}</td>}
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium ${
                                                        resource.status === 'running'
                                                            ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                                                            : resource.status === 'stopped'
                                                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                                                            : 'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                                                    }`}>
                                                        <span className={`w-1.5 h-1.5 rounded-full ${
                                                            resource.status === 'running' ? 'bg-green-400' : 'bg-red-400'
                                                        }`} />
                                                        {resource.status}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3" style={{whiteSpace:'nowrap'}}>
                                                    {isCorporate ? (
                                                    <div className="flex items-center gap-0">
                                                        {getProxmoxObjectUrl(getVmProxmoxTarget(resource)) && (
                                                            <>
                                                                <button onClick={() => openProxmoxObject(getVmProxmoxTarget(resource))} className="corp-action-btn" title={t('openInProxmox') || 'Open in Proxmox'}><Icons.ExternalLink className="w-3.5 h-3.5" /></button>
                                                                <span className="corp-toolbar-divider" style={{margin: '0 3px'}} />
                                                            </>
                                                        )}
                                                        {/* power group */}
                                                        {acts && (<>
                                                        <div className="corp-action-group">
                                                            {resource.status === 'stopped' ? (
                                                                <button onClick={() => handleAction(resource, 'start')} disabled={actionLoading[`${resource.vmid}-start`]} className="corp-action-btn" title={t('start')}>
                                                                    {actionLoading[`${resource.vmid}-start`] ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.PlayCircle className="w-3.5 h-3.5" />}
                                                                </button>
                                                            ) : (
                                                                <>
                                                                    <button onClick={() => handleAction(resource, 'shutdown')} disabled={actionLoading[`${resource.vmid}-shutdown`]} className="corp-action-btn" title={t('shutdown')}>
                                                                        {actionLoading[`${resource.vmid}-shutdown`] ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.Power className="w-3.5 h-3.5" />}
                                                                    </button>
                                                                    <button onClick={() => handleAction(resource, 'reboot')} disabled={actionLoading[`${resource.vmid}-reboot`]} className="corp-action-btn" title={t('reboot')}>
                                                                        {actionLoading[`${resource.vmid}-reboot`] ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.RefreshCw className="w-3.5 h-3.5" />}
                                                                    </button>
                                                                </>
                                                            )}
                                                        </div>
                                                        <span className="corp-toolbar-divider" style={{margin: '0 3px'}} />
                                                        </>)}
                                                        {/* management group */}
                                                        <div className="corp-action-group">
                                                            {consoles && resource.status === 'running' && (
                                                                <button onClick={() => onOpenConsole(resource)} className="corp-action-btn" title={t('openConsole')}><Icons.Monitor className="w-3.5 h-3.5" /></button>
                                                            )}
                                                            {!consoles && resource.status === 'running' && (
                                                                <HaOnActiveLink vm={resource} clusterId={clusterId} iconOnly className="corp-action-btn" iconClass="w-3.5 h-3.5" />
                                                            )}
                                                            {consoles && resource.status === 'running' && resource.type === 'qemu' && onOpenSpice && (
                                                                <button onClick={() => onOpenSpice(resource)} className="corp-action-btn" title={t('spiceConsole') || 'SPICE'}><Icons.ExternalLink className="w-3.5 h-3.5" /></button>
                                                            )}
                                                            <button onClick={() => onOpenConfig(resource)} className="corp-action-btn" title={t('configuration')}><Icons.Cog className="w-3.5 h-3.5" /></button>
                                                            {canStar && (
                                                                <button onClick={() => onToggleFavorite(resource)} className="corp-action-btn" data-fav={isFav(resource) ? 'on' : 'off'}
                                                                    title={isFav(resource) ? t('favRemove') : t('favAdd')}>
                                                                    <Icons.Star className={`w-3.5 h-3.5 ${isFav(resource) ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                                                                </button>
                                                            )}
                                                            {acts && (<>
                                                            <button onClick={() => setShowMigrateModal(resource)} className="corp-action-btn" title={t('migrate')}><Icons.ArrowRight className="w-3.5 h-3.5" /></button>
                                                            <button onClick={() => setShowCloneModal(resource)} className="corp-action-btn" title={t('clone')}><Icons.Copy className="w-3.5 h-3.5" /></button>
                                                            </>)}
                                                        </div>
                                                        {acts && (<>
                                                        <span className="corp-toolbar-divider" style={{margin: '0 3px'}} />
                                                        <button onClick={() => setShowDeleteConfirm(resource)} className="corp-action-btn danger" title={t('delete')}><Icons.Trash className="w-3.5 h-3.5" /></button>
                                                        </>)}
                                                    </div>
                                                    ) : (
                                                    <div className="flex items-center gap-1">
                                                        {getProxmoxObjectUrl(getVmProxmoxTarget(resource)) && (
                                                            <button
                                                                onClick={() => openProxmoxObject(getVmProxmoxTarget(resource))}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-cyan-500/20 text-gray-400 hover:text-cyan-400 transition-all"
                                                                title={t('openInProxmox') || 'Open in Proxmox'}
                                                            >
                                                                <Icons.ExternalLink />
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => onOpenConfig(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-purple-500/20 text-gray-400 hover:text-purple-400 transition-all"
                                                            title={t('configuration')}
                                                        >
                                                            <Icons.Cog />
                                                        </button>
                                                        {canStar && (
                                                        <button
                                                            onClick={() => onToggleFavorite(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all"
                                                            data-fav={isFav(resource) ? 'on' : 'off'}
                                                            title={isFav(resource) ? t('favRemove') : t('favAdd')}
                                                        >
                                                            <Icons.Star className={`w-5 h-5 ${isFav(resource) ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                                                        </button>
                                                        )}
                                                        {acts && (
                                                        <button
                                                            onClick={() => onOpenTags && onOpenTags(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all"
                                                            title={t('tags')}
                                                        >
                                                            <Icons.Tag />
                                                        </button>
                                                        )}
                                                        <button
                                                            onClick={() => setShowMetricsModal(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                            title={t('metrics')}
                                                        >
                                                            <Icons.BarChart />
                                                        </button>
                                                        {acts && (<>
                                                        <button
                                                            onClick={() => setShowMigrateModal(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-cyan-500/20 text-gray-400 hover:text-cyan-400 transition-all"
                                                            title={t('migrate')}
                                                        >
                                                            <Icons.ArrowRight />
                                                        </button>
                                                        {clusters && clusters.length > 1 && (
                                                            <button
                                                                onClick={() => setShowCrossClusterMigrate(resource)}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-emerald-500/20 text-gray-400 hover:text-emerald-400 transition-all"
                                                                title={t('crossClusterMigrate')}
                                                            >
                                                                <Icons.Globe />
                                                            </button>
                                                        )}
                                                        {consoles && resource.status === 'running' && (
                                                            <button
                                                                onClick={() => onOpenConsole(resource)}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                                title={t('openConsole')}
                                                            >
                                                                <Icons.Monitor />
                                                            </button>
                                                        )}
                                                        {consoles && resource.status === 'running' && resource.type === 'qemu' && onOpenSpice && (
                                                            <button
                                                                onClick={() => onOpenSpice(resource)}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                                title={t('spiceConsole') || 'SPICE'}
                                                            >
                                                                <Icons.ExternalLink />
                                                            </button>
                                                        )}
                                                        {resource.status === 'stopped' ? (
                                                            <button
                                                                onClick={() => handleAction(resource, 'start')}
                                                                disabled={actionLoading[`${resource.vmid}-start`]}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-green-500/20 text-gray-400 hover:text-green-400 transition-all disabled:opacity-50"
                                                                title={t('start')}
                                                            >
                                                                {actionLoading[`${resource.vmid}-start`] ? <Icons.RotateCw /> : <Icons.PlayCircle />}
                                                            </button>
                                                        ) : (
                                                            <>
                                                                <button
                                                                    onClick={() => handleAction(resource, 'shutdown')}
                                                                    disabled={actionLoading[`${resource.vmid}-shutdown`]}
                                                                    className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all disabled:opacity-50"
                                                                    title={t('shutdown')}
                                                                >
                                                                    {actionLoading[`${resource.vmid}-shutdown`] ? <Icons.RotateCw /> : <Icons.Power />}
                                                                </button>
                                                                <button
                                                                    onClick={() => onForceStop(resource)}
                                                                    disabled={actionLoading[`${resource.vmid}-stop`]}
                                                                    className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-all disabled:opacity-50"
                                                                    title={t('forceStop')}
                                                                >
                                                                    {actionLoading[`${resource.vmid}-stop`] ? <Icons.RotateCw /> : <Icons.XCircle />}
                                                                </button>
                                                                <button
                                                                    onClick={() => handleAction(resource, 'reboot')}
                                                                    disabled={actionLoading[`${resource.vmid}-reboot`]}
                                                                    className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-orange-500/20 text-gray-400 hover:text-orange-400 transition-all disabled:opacity-50"
                                                                    title={t('reboot')}
                                                                >
                                                                    {actionLoading[`${resource.vmid}-reboot`] ? <Icons.RotateCw /> : <Icons.RefreshCw />}
                                                                </button>
                                                                {resource.type === 'qemu' && (
                                                                    <button
                                                                        onClick={() => handleAction(resource, 'reset')}
                                                                        disabled={actionLoading[`${resource.vmid}-reset`]}
                                                                        className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-orange-500/20 text-gray-400 hover:text-orange-400 transition-all disabled:opacity-50"
                                                                        title={t('forceReset')}
                                                                    >
                                                                        {actionLoading[`${resource.vmid}-reset`] ? <Icons.RotateCw /> : <Icons.Zap />}
                                                                    </button>
                                                                )}
                                                            </>
                                                        )}
                                                        <button
                                                            onClick={() => setShowCloneModal(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                            title={t('clone')}
                                                        >
                                                            <Icons.Copy />
                                                        </button>
                                                        <button
                                                            onClick={() => setShowDeleteConfirm(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-all"
                                                            title={t('delete')}
                                                        >
                                                            <Icons.Trash />
                                                        </button>
                                                        </>)}
                                                        {!consoles && resource.status === 'running' && (
                                                            <HaOnActiveLink vm={resource} clusterId={clusterId} iconOnly
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all" />
                                                        )}
                                                    </div>
                                                    )}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Detail View - Split Panel */}
                    {viewMode === 'detail' && (
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            {/* VM List — LW 2026-04-24: viewport-proportional height so it
                                matches the detail panel on the right and never exceeds the
                                visible area. Header + list scroll independently. */}
                            <div className="lg:col-span-1 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden flex flex-col"
                                 style={{maxHeight: 'calc(100vh - 260px)', minHeight: '400px'}}>
                                <div className="p-3 border-b border-proxmox-border bg-proxmox-dark/50 flex-shrink-0">
                                    <h3 className="text-sm font-medium text-gray-300">VMs & Container ({filteredResources.length})</h3>
                                </div>
                                <div className="flex-1 overflow-y-auto" style={{scrollbarWidth: 'thin'}}>
                                    {paginatedResources.map(resource => (
                                        <div
                                            key={resource.vmid}
                                            onClick={() => setSelectedDetailVm(resource)}
                                            className={`flex items-center gap-3 p-3 cursor-pointer transition-all border-b border-gray-700/50 ${
                                                selectedDetailVm?.vmid === resource.vmid
                                                    ? 'bg-proxmox-orange/10 border-l-2 border-l-proxmox-orange'
                                                    : 'hover:bg-proxmox-dark/50'
                                            }`}
                                        >
                                            <div
                                                className={`p-1.5 rounded ${isGuestTemplate(resource) ? 'bg-gray-300/50 text-gray-800 border border-gray-400/50' : resource.type === 'qemu' ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}
                                                title={getGuestTypeTitle(resource, t)}
                                            >
                                                {getGuestTypeIcon(resource)}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <div className="font-medium text-white text-sm truncate">
                                                    {resource.name || `${resource.type === 'qemu' ? 'VM' : 'CT'} ${resource.vmid}`}
                                                </div>
                                                <div className="text-xs text-gray-500">ID: {resource.vmid} · {resource.node}</div>
                                                <div className="flex flex-wrap gap-1 mt-1 items-center">
                                                    {/* NS May 2026 — backup status pill (mobile stack layout) */}
                                                    {backupStatus && backupStatus[resource.vmid] && window.PegaProxBackupStatusPill && React.createElement(window.PegaProxBackupStatusPill, {
                                                        status: backupStatus[resource.vmid].status,
                                                        lastAgeHours: backupStatus[resource.vmid].last_backup_age_hours,
                                                        encrypted: backupStatus[resource.vmid].encrypted,
                                                        verifyAgeHours: backupStatus[resource.vmid].last_verify_age_hours,
                                                        count30d: backupStatus[resource.vmid].count_30d,
                                                    })}
                                                    {resource.tags && (Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).slice(0, 2).map((tag, i) => (
                                                        <span key={i} className="px-1 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                            {tag.trim()}
                                                        </span>
                                                    ))}
                                                    {resource.tags && (Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).length > 2 && (
                                                        <span className="px-1 py-0.5 text-xs rounded bg-gray-500/20 text-gray-400">
                                                            +{(Array.isArray(resource.tags) ? resource.tags : resource.tags.split(';')).filter(t => t.trim()).length - 2}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                            {getProxmoxObjectUrl(getVmProxmoxTarget(resource)) && (
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        openProxmoxObject(getVmProxmoxTarget(resource));
                                                    }}
                                                    className="p-1.5 rounded-lg text-gray-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-all"
                                                    title={t('openInProxmox') || 'Open in Proxmox'}
                                                >
                                                    <Icons.ExternalLink className="w-4 h-4" />
                                                </button>
                                            )}
                                            <span className={`w-2 h-2 rounded-full ${
                                                resource.status === 'running' ? 'bg-green-500' : 'bg-red-500'
                                            }`} />
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Detail Panel */}
                            <div className="lg:col-span-2">
                                {selectedDetailVm ? (
                                    <VmDetailPanel
                                        vm={selectedDetailVm}
                                        clusterId={clusterId}
                                        onAction={handleAction}
                                        onOpenConsole={onOpenConsole}
                                        onOpenSpice={onOpenSpice}
                                        onOpenConfig={onOpenConfig}
                                        onMigrate={() => setShowMigrateModal(selectedDetailVm)}
                                        onClone={() => setShowCloneModal(selectedDetailVm)}
                                        onForceStop={onForceStop}
                                        onDelete={() => setShowDeleteConfirm(selectedDetailVm)}
                                        onCrossClusterMigrate={(vm) => setShowCrossClusterMigrate(vm)}
                                        showCrossCluster={clusters && clusters.length > 1}
                                        actionLoading={actionLoading}
                                        onShowMetrics={(vm) => setShowMetricsModal(vm)}
                                        addToast={addToast}
                                    />
                                ) : (
                                    <div className="h-full flex items-center justify-center bg-proxmox-card border border-proxmox-border rounded-xl p-12">
                                        <div className="text-center text-gray-500">
                                            <Icons.Eye />
                                            <p className="mt-2">{t('selectVmFromList') || 'Select a VM from the list'}</p>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Pagination Controls - MK Jan 2026 */}
                    <div className="flex flex-wrap items-center justify-between gap-4 text-sm text-gray-400 py-2">
                        <div className="flex items-center gap-4">
                            <span>
                                {t('showing')} {((effectivePage - 1) * itemsPerPage) + 1}-{Math.min(effectivePage * itemsPerPage, filteredResources.length)} {t('of')} {filteredResources.length} {t('resources')}
                                {filteredResources.length !== resources.length && ` (${resources.length} ${t('total')})`}
                            </span>
                            <div className="flex items-center gap-2">
                                <span className="text-gray-500">{t('perPage')}:</span>
                                <select
                                    value={itemsPerPage}
                                    onChange={(e) => setItemsPerPage(Number(e.target.value))}
                                    className="bg-proxmox-dark border border-proxmox-border rounded px-2 py-1 text-sm"
                                >
                                    <option value={50}>50</option>
                                    <option value={100}>100</option>
                                    <option value={200}>200</option>
                                    <option value={500}>500</option>
                                </select>
                            </div>
                        </div>
                        
                        {totalPages > 1 && (
                            <div className="flex items-center gap-1">
                                <button
                                    onClick={() => setCurrentPage(1)}
                                    disabled={effectivePage === 1}
                                    className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border disabled:opacity-30 hover:bg-proxmox-hover disabled:hover:bg-proxmox-dark"
                                    title="First page"
                                >
                                    ««
                                </button>
                                <button
                                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                                    disabled={effectivePage === 1}
                                    className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border disabled:opacity-30 hover:bg-proxmox-hover disabled:hover:bg-proxmox-dark"
                                >
                                    «
                                </button>
                                
                                {/* Page numbers */}
                                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                                    let pageNum;
                                    if (totalPages <= 5) {
                                        pageNum = i + 1;
                                    } else if (effectivePage <= 3) {
                                        pageNum = i + 1;
                                    } else if (effectivePage >= totalPages - 2) {
                                        pageNum = totalPages - 4 + i;
                                    } else {
                                        pageNum = effectivePage - 2 + i;
                                    }
                                    return (
                                        <button
                                            key={pageNum}
                                            onClick={() => setCurrentPage(pageNum)}
                                            className={`px-3 py-1 rounded border ${
                                                effectivePage === pageNum
                                                    ? 'bg-proxmox-orange text-white border-proxmox-orange'
                                                    : 'bg-proxmox-dark border-proxmox-border hover:bg-proxmox-hover'
                                            }`}
                                        >
                                            {pageNum}
                                        </button>
                                    );
                                })}
                                
                                <button
                                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                                    disabled={effectivePage === totalPages}
                                    className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border disabled:opacity-30 hover:bg-proxmox-hover disabled:hover:bg-proxmox-dark"
                                >
                                    »
                                </button>
                                <button
                                    onClick={() => setCurrentPage(totalPages)}
                                    disabled={effectivePage === totalPages}
                                    className="px-2 py-1 rounded bg-proxmox-dark border border-proxmox-border disabled:opacity-30 hover:bg-proxmox-hover disabled:hover:bg-proxmox-dark"
                                    title="Last page"
                                >
                                    »»
                                </button>
                            </div>
                        )}
                        
                        <span className="text-gray-500">{Object.keys(groupedByNode).length} Nodes</span>
                    </div>

                    {/* Delete Confirmation Modal */}
                    {showDeleteConfirm && (
                        <DeleteVmModal
                            vm={showDeleteConfirm}
                            clusterId={clusterId}
                            onDelete={onDelete}
                            onClose={() => setShowDeleteConfirm(null)}
                        />
                    )}

                    {/* Clone VM Modal */}
                    {showCloneModal && (
                        <CloneVmModal
                            vm={showCloneModal}
                            nodes={nodes}
                            clusterId={clusterId}
                            storages={datastores}
                            onClone={onClone}
                            onClose={() => setShowCloneModal(null)}
                        />
                    )}

                    {/* Single VM Migrate Modal */}
                    {showMigrateModal && (
                        <MigrateModal
                            vm={showMigrateModal}
                            nodes={nodes}
                            clusterId={clusterId}
                            onMigrate={onMigrate}
                            onClose={() => setShowMigrateModal(null)}
                        />
                    )}

                    {/* Bulk Migrate Modal */}
                    {showBulkMigrate && (
                        <BulkMigrateModal
                            vms={selectedVms}
                            nodes={nodes}
                            clusterId={clusterId}
                            onMigrate={onBulkMigrate}
                            onClose={() => {
                                setShowBulkMigrate(false);
                                setSelectedVms([]);
                            }}
                        />
                    )}

                    {bulkGuests && authFetch && (
                        <GuestBulkActionModal
                            action={bulkGuests.action}
                            guests={bulkGuests.guests}
                            authFetch={authFetch}
                            onFinished={onBulkDone}
                            onClose={() => setBulkGuests(null)}
                        />
                    )}

                    {/* Cross-Cluster Migrate Modal */}
                    {showCrossClusterMigrate && clusters && clusters.length > 1 && (
                        <CrossClusterMigrateModal
                            vm={showCrossClusterMigrate}
                            sourceCluster={sourceCluster}
                            clusters={clusters}
                            onMigrate={onCrossClusterMigrate}
                            onClose={() => setShowCrossClusterMigrate(null)}
                        />
                    )}

                    {/* VM Metrics Modal */}
                    {showMetricsModal && (
                        <VmMetricsModal
                            vm={showMetricsModal}
                            clusterId={clusterId}
                            onClose={() => setShowMetricsModal(null)}
                        />
                    )}
                </div>
            );
        }

        // LW Oct 2026 - All Guests: every guest of every cluster the user may see, in one table.
        // The server filters, sorts and cuts it to a page (GET /inventory/guests/page), so 10k
        // guests are never all in the browser, and the picked ones stay picked from page to page.
        // The actions are the bulk dialogs of the guest table: one request per guest to its own
        // route, and the bulk migration (#952) for guests of one cluster. A row says what its
        // guest takes from this user; on a standby there is nothing to pick.
        const ALL_GUESTS_SIZES = [50, 100, 250, 500];
        const ALL_GUESTS_POLL_MS = 30000;
        const ALL_GUESTS_SIZE_KEY = 'pegaprox-all-guests-size';

        function allGuestsUptime(s) {
            if (!s) return '-';
            const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
            return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
        }

        function AllGuestsView({ clusters, authFetch, addToast, onOpenGuest, onBulkMigrate }) {
            const { t, language } = useTranslation();
            const { haReadOnly } = useAuth();
            const { isCorporate } = useLayout();
            const acts = !haReadOnly;
            const [query, setQuery] = useState('');
            const [view, setView] = useState(() => {
                let size = 100;
                try { size = parseInt(localStorage.getItem(ALL_GUESTS_SIZE_KEY) || '100', 10); } catch (e) {}
                return { q: '', cluster: '', status: '', type: '', tag: '', by: 'name', dir: 'asc',
                    size: ALL_GUESTS_SIZES.includes(size) ? size : 100, page: 0 };
            });
            const [data, setData] = useState(null);
            const [loading, setLoading] = useState(false);
            const [picked, setPicked] = useState({});
            const [bulk, setBulk] = useState(null);
            const [migrate, setMigrate] = useState(null);
            const [tick, setTick] = useState(0);
            const seq = useRef(0);
            // another filter or order starts on the first page
            const refine = (patch) => setView(v => ({ ...v, ...patch, page: 0 }));
            const keyOf = (g) => `${g.cluster_id}:${g.vmid}`;

            useEffect(() => {
                const id = setTimeout(() => {
                    const q = query.trim().slice(0, 200);
                    setView(v => v.q === q ? v : { ...v, q, page: 0 });
                }, 350);
                return () => clearTimeout(id);
            }, [query]);

            const load = async () => {
                const mine = ++seq.current;
                setLoading(true);
                const p = new URLSearchParams({ limit: String(view.size), offset: String(view.page * view.size), sort: view.by, dir: view.dir });
                ['q', 'cluster', 'status', 'type', 'tag'].forEach(k => { if (view[k]) p.set(k, view[k]); });
                const res = await authFetch(`${API_URL}/inventory/guests/page?${p.toString()}`);
                const body = res && res.ok ? await res.json().catch(() => null) : null;
                if (mine !== seq.current) return;  // a newer read is on its way
                setLoading(false);
                if (!body || !Array.isArray(body.guests)) {
                    // what was read stays shown
                    setData(prev => ({ ...(prev || {}), failed: true }));
                    return;
                }
                setData(body);
                // a picked guest takes the figures of this read: the dialogs go by its status
                setPicked(prev => {
                    let changed = false;
                    const next = { ...prev };
                    body.guests.forEach(g => { if (next[keyOf(g)]) { next[keyOf(g)] = g; changed = true; } });
                    return changed ? next : prev;
                });
            };
            useEffect(() => { load(); }, [view, tick]);
            useEffect(() => {
                const id = setInterval(() => { if (!document.hidden) setTick(n => n + 1); }, ALL_GUESTS_POLL_MS);
                return () => clearInterval(id);
            }, []);
            // fewer guests than before, past the last page: back to the last one
            useEffect(() => {
                if (data && !data.failed && data.total > 0 && view.page * view.size >= data.total) {
                    setView(v => ({ ...v, page: Math.max(0, Math.ceil(data.total / v.size) - 1) }));
                }
            }, [data]);

            const names = useMemo(() => new Map((clusters || []).map(c => [c.id, c.display_name || c.name])), [clusters]);
            const label = (id, fallback) => names.get(id) || fallback || id;
            const rows = (data && data.guests) || [];
            const total = (data && data.total) || 0;
            const counts = (data && data.status_counts) || null;
            const pickedList = Object.values(picked);
            const pageAll = rows.length > 0 && rows.every(g => picked[keyOf(g)]);
            const togglePage = () => setPicked(prev => {
                const next = { ...prev };
                rows.forEach(g => { if (pageAll) delete next[keyOf(g)]; else next[keyOf(g)] = g; });
                return next;
            });
            const toggleOne = (g) => setPicked(prev => {
                const next = { ...prev };
                if (next[keyOf(g)]) delete next[keyOf(g)]; else next[keyOf(g)] = g;
                return next;
            });
            const openGuest = (g) => {
                const cl = (clusters || []).find(c => c.id === g.cluster_id);
                if (cl && onOpenGuest) onOpenGuest(cl, { vmid: g.vmid, node: g.node, type: g.type, name: g.name, status: g.status });
            };

            const actions = [
                { action: 'start', can: 'start', label: t('start'), icon: <Icons.PlayCircle />, cls: 'bg-green-600 hover:bg-green-700' },
                { action: 'shutdown', can: 'stop', label: t('shutdown'), icon: <Icons.Power />, cls: 'bg-yellow-600 hover:bg-yellow-700' },
                { action: 'reboot', can: 'reboot', label: t('reboot'), icon: <Icons.RefreshCw />, cls: 'bg-orange-500 hover:bg-orange-600' },
                { action: 'stop', can: 'stop', label: t('forceStop'), icon: <Icons.XCircle />, cls: 'bg-red-600 hover:bg-red-700' },
                { action: 'snapshot', can: 'snapshot', label: t('snapshot'), icon: <Icons.Camera />, cls: 'bg-purple-600 hover:bg-purple-700' },
            ].concat(onBulkMigrate ? [{ action: 'migrate', can: 'migrate', label: t('migrate'), icon: <Icons.ArrowRight />, cls: 'bg-blue-600 hover:bg-blue-700' }] : []);
            const allowedFor = (a) => pickedList.filter(g => g.can && g.can[a.can]);
            const spread = (list) => new Set(list.map(g => g.cluster_id)).size;
            const blocked = (a) => { const ok = allowedFor(a); return !ok.length || (a.action === 'migrate' && spread(ok) > 1); };
            const hint = (a) => {
                const ok = allowedFor(a);
                if (a.action === 'migrate' && spread(ok) > 1) return t('allGuestsOneCluster');
                if (ok.length < pickedList.length) return t('allGuestsNoPermission').replace('{n}', pickedList.length - ok.length);
                return '';
            };
            const runAction = async (a) => {
                const ok = allowedFor(a);
                if (!ok.length || blocked(a)) return;
                if (ok.length < pickedList.length) addToast?.(t('allGuestsLeftOut').replace('{n}', pickedList.length - ok.length), 'info');
                if (a.action !== 'migrate') {
                    setBulk({ action: a.action, guests: ok.map(g => ({ ...g, _clusterId: g.cluster_id })) });
                    return;
                }
                const cid = ok[0].cluster_id;
                let nodes = [];
                const res = await authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/metrics`);
                const m = res && res.ok ? await res.json().catch(() => null) : null;
                if (m && typeof m === 'object' && !Array.isArray(m)) {
                    nodes = Object.entries(m).filter(([, n]) => n && typeof n === 'object' && !n.offline && (n.status || 'online') === 'online')
                        .map(([name]) => name).sort();
                }
                // without the node figures: the nodes its guests are on, as far as they are known here
                if (!nodes.length) nodes = [...new Set(rows.concat(pickedList).filter(g => g.cluster_id === cid).map(g => g.node).filter(Boolean))].sort();
                setMigrate({ clusterId: cid, nodes, vms: ok.map(g => ({ vmid: g.vmid, node: g.node, type: g.type, name: g.name })) });
            };
            const later = (ms) => setTimeout(() => setTick(n => n + 1), ms);

            // text sorts A to Z first, figures the largest first
            const sortOn = (by) => setView(v => v.by === by
                ? { ...v, dir: v.dir === 'asc' ? 'desc' : 'asc', page: 0 }
                : { ...v, by, dir: ['name', 'vmid', 'cluster', 'node', 'status'].includes(by) ? 'asc' : 'desc', page: 0 });
            const columns = [
                { by: 'vmid', label: 'ID' }, { by: 'name', label: t('name') }, { by: 'cluster', label: t('cluster') },
                { by: 'node', label: t('node') }, { by: 'status', label: t('status') }, { by: 'cpu', label: 'CPU' },
                { by: 'mem', label: 'RAM' }, { by: 'disk', label: t('disk') }, { by: 'uptime', label: t('uptime') },
                { by: '', label: 'IP' }, { by: '', label: t('tags') },
            ];
            const stateOf = (g) => g.status === 'running' ? 'running' : g.status === 'stopped' ? 'stopped' : 'other';
            const statusText = (g) => ({ running: t('running'), stopped: t('stopped'), paused: t('paused') })[g.status] || g.status;
            const cpuText = (g) => g.status === 'running' ? `${Math.round((g.cpu || 0) * 100)}%` : '-';
            const memText = (g) => g.status === 'running' && g.mem ? `${formatBytes(g.mem)} / ${formatBytes(g.memory)}` : formatBytes(g.memory);
            const diskText = (g) => g.disk > 0 ? `${formatBytes(g.disk)} / ${formatBytes(g.disk_size)}` : formatBytes(g.disk_size);
            const ipText = (g) => (g.ip_addresses || []).length ? g.ip_addresses[0] + (g.ip_addresses.length > 1 ? ` +${g.ip_addresses.length - 1}` : '') : '-';
            const unlisted = ((data && data.clusters) || []).filter(c => c.state !== 'ok');
            const stateNames = { offline: t('allGuestsOffline'), unreadable: t('allGuestsUnreadable') };
            const from = total ? view.page * view.size + 1 : 0;
            const to = Math.min(total, (view.page + 1) * view.size);
            // figures in the language of the page, not of the browser
            const num = (n) => { try { return Number(n || 0).toLocaleString(language || undefined); } catch (e) { return String(n || 0); } };
            const range = t('allGuestsRange').replace('{from}', num(from)).replace('{to}', num(to)).replace('{total}', num(total));
            const setSize = (n) => {
                try { localStorage.setItem(ALL_GUESTS_SIZE_KEY, String(n)); } catch (e) {}
                refine({ size: n });
            };

            const chip = (s, text, cls, style) => counts && (
                <button type="button" key={s} data-all-guests-count={s} onClick={() => refine({ status: view.status === s ? '' : s })}
                    className={cls} style={style}>
                    {num(counts[s])} {text}
                </button>
            );
            const refreshButton = (
                <button type="button" data-all-guests-refresh onClick={() => setTick(n => n + 1)} title={t('refresh')} disabled={loading}
                    className="p-1.5 rounded text-gray-500 hover:text-proxmox-orange hover:bg-proxmox-hover disabled:opacity-50">
                    <span className={`inline-flex ${loading ? 'animate-spin' : ''}`}><Icons.RefreshCw /></span>
                </button>
            );
            const selectCls = isCorporate ? 'corp-toolbar-filter' : 'px-3 py-1.5 text-xs bg-proxmox-dark text-gray-300 border border-proxmox-border rounded-lg cursor-pointer';
            const filters = (<>
                <div className="relative">
                    <Icons.Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input type="text" data-all-guests-search value={query} maxLength={200} onChange={e => setQuery(e.target.value)} placeholder={t('allGuestsSearch')}
                        className={isCorporate ? 'pr-2 py-1 text-[13px] bg-transparent border text-white placeholder-gray-500 focus:outline-none w-56'
                            : 'pr-2 py-1.5 text-sm bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange w-64'}
                        style={isCorporate ? { paddingLeft: '28px', borderColor: 'var(--corp-border-medium)', borderRadius: '2px' } : { paddingLeft: '1.75rem' }} />
                </div>
                <select data-all-guests-cluster value={view.cluster} onChange={e => refine({ cluster: e.target.value })} className={selectCls}>
                    <option value="">{t('allGuestsAnyCluster')}</option>
                    {((data && data.clusters) || []).map(c => <option key={c.cluster_id} value={c.cluster_id}>{label(c.cluster_id, c.cluster_name)}</option>)}
                </select>
                <select data-all-guests-status value={view.status} onChange={e => refine({ status: e.target.value })} className={selectCls}>
                    <option value="">{t('allGuestsAnyStatus')}</option>
                    <option value="running">{t('running')}</option>
                    <option value="stopped">{t('stopped')}</option>
                    <option value="other">{t('allGuestsOther')}</option>
                </select>
                <select data-all-guests-type value={view.type} onChange={e => refine({ type: e.target.value })} className={selectCls}>
                    <option value="">{t('allGuestsAnyType')}</option>
                    <option value="qemu">{t('virtualMachines')}</option>
                    <option value="lxc">{t('containers')}</option>
                    <option value="template">{t('allGuestsTemplates')}</option>
                </select>
                {(data && data.tags && data.tags.length > 0 || view.tag) && (
                    <select data-all-guests-tag value={view.tag} onChange={e => refine({ tag: e.target.value })} className={selectCls}>
                        <option value="">{t('allTags')}</option>
                        {((data && data.tags) || []).map(x => <option key={x} value={x}>{x}</option>)}
                    </select>
                )}
            </>);
            const pager = (
                <div className="flex items-center justify-between gap-3 flex-wrap text-xs text-gray-500">
                    <div className="flex items-center gap-3 flex-wrap">
                        {unlisted.length > 0 && (
                            <span data-all-guests-unlisted className="text-amber-400">
                                {t('allGuestsNotListed')} {unlisted.map(c => `${label(c.cluster_id, c.cluster_name)} (${stateNames[c.state] || c.state})`).join(', ')}
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        <label className="flex items-center gap-1.5">
                            {t('perPage')}
                            <select data-all-guests-size value={view.size} onChange={e => setSize(parseInt(e.target.value, 10))}
                                className={isCorporate ? 'corp-toolbar-filter' : 'px-2 py-1 text-xs bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300'}>
                                {ALL_GUESTS_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
                            </select>
                        </label>
                        <span data-all-guests-range>{range}</span>
                        <button type="button" data-all-guests-prev disabled={view.page === 0} title={t('allGuestsPrevPage')}
                            onClick={() => setView(v => ({ ...v, page: Math.max(0, v.page - 1) }))}
                            className="p-1 rounded text-gray-400 hover:text-white hover:bg-proxmox-hover disabled:opacity-30">
                            <Icons.ChevronLeft className="w-4 h-4" />
                        </button>
                        <button type="button" data-all-guests-next disabled={to >= total} title={t('allGuestsNextPage')}
                            onClick={() => setView(v => ({ ...v, page: v.page + 1 }))}
                            className="p-1 rounded text-gray-400 hover:text-white hover:bg-proxmox-hover disabled:opacity-30">
                            <Icons.ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                </div>
            );
            const notes = (<>
                {!data && <div className="text-sm text-gray-500 p-3">{t('loading')}</div>}
                {data && data.failed && <div data-all-guests-failed className="text-sm text-amber-400 p-3">{t('allGuestsFailed')}</div>}
                {data && !data.failed && rows.length === 0 && (
                    <div data-all-guests-empty className="text-sm text-gray-400 p-3">{data.count ? t('allGuestsNoMatch') : t('allGuestsEmpty')}</div>
                )}
            </>);
            const modals = (<>
                {bulk && (
                    <GuestBulkActionModal action={bulk.action} guests={bulk.guests} authFetch={authFetch}
                        onFinished={() => later(1500)} onClose={() => setBulk(null)} />
                )}
                {migrate && onBulkMigrate && (
                    <BulkMigrateModal vms={migrate.vms} nodes={migrate.nodes} clusterId={migrate.clusterId}
                        onMigrate={async (args) => { const r = await onBulkMigrate(args); if (r && r.ok) later(3000); return r; }}
                        onClose={() => setMigrate(null)} />
                )}
            </>);
            const pickBox = (g) => (
                <input type="checkbox" data-all-guests-pick={keyOf(g)} checked={!!picked[keyOf(g)]} onChange={() => toggleOne(g)}
                    className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark" />
            );
            const pageBox = (
                <input type="checkbox" data-all-guests-pick-page checked={pageAll} onChange={togglePage} title={t('allGuestsPickPage')}
                    className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark" />
            );

            if (isCorporate) {
                const dot = { running: '#60b515', stopped: '#728b9a', other: '#efc006' };
                return (
                    <div data-all-guests>
                        <div className="corp-content-header">
                            <div className="flex items-center gap-2">
                                <span className="flex" style={{color: 'var(--corp-accent)'}}><Icons.Monitor /></span>
                                <span className="corp-header-title">{t('allGuestsTitle')}</span>
                                {data && !data.failed && <span data-all-guests-total className="text-[11px]" style={{color: '#728b9a'}}>{num(data.count)}</span>}
                            </div>
                            <div className="flex items-center gap-3 text-[12px]">
                                {chip('running', t('running'), 'hover:underline capitalize', { color: dot.running })}
                                {chip('stopped', t('stopped'), 'hover:underline capitalize', { color: dot.stopped })}
                                {counts && counts.other > 0 && chip('other', t('allGuestsOther'), 'hover:underline capitalize', { color: dot.other })}
                                {refreshButton}
                            </div>
                        </div>
                        <div className="corp-vm-toolbar" style={{flexWrap: 'wrap'}}>
                            {filters}
                            <div style={{flex: 1}} />
                            {acts && pickedList.length > 0 && (<>
                                <span data-all-guests-picked className="text-[11px]" style={{color: '#49afd9'}}>{pickedList.length} {t('selectedItems')}</span>
                                {actions.map(a => (
                                    <button key={a.action} type="button" data-all-guests-action={a.action} onClick={() => runAction(a)} disabled={blocked(a)} title={hint(a)}
                                        className="corp-toolbar-filter disabled:opacity-40"
                                        style={a.action === 'stop' ? {color: '#f54f47'} : a.action === 'migrate' ? {color: '#49afd9'} : undefined}>
                                        {a.label}
                                    </button>
                                ))}
                                <button type="button" data-all-guests-clear onClick={() => setPicked({})} className="corp-toolbar-filter">{t('clearSelection')}</button>
                            </>)}
                        </div>
                        {notes}
                        {rows.length > 0 && (
                            <table className="corp-datagrid corp-datagrid-striped">
                                <thead>
                                    <tr>
                                        {acts && <th style={{width: '28px'}}>{pageBox}</th>}
                                        {columns.map((c, i) => (
                                            <th key={i} data-all-guests-sort={c.by || undefined} className={c.by ? 'cursor-pointer' : ''} style={{textAlign: 'left'}}
                                                onClick={c.by ? () => sortOn(c.by) : undefined}>
                                                {c.label} {c.by && view.by === c.by && <span className="sort-indicator">{view.dir === 'asc' ? '▲' : '▼'}</span>}
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.map(g => (
                                        <tr key={keyOf(g)} data-all-guests-row={keyOf(g)} className={picked[keyOf(g)] ? 'corp-row-selected' : ''}>
                                            {acts && <td>{pickBox(g)}</td>}
                                            <td style={{color: '#728b9a'}}>{g.vmid}</td>
                                            <td>
                                                <button type="button" data-all-guests-open={keyOf(g)} onClick={() => openGuest(g)} title={t('allGuestsOpen')}
                                                    className="inline-flex items-center gap-1.5 hover:underline" style={{fontWeight: 500}}>
                                                    <span className="flex" style={{color: g.type === 'qemu' ? '#49afd9' : '#a178d9'}}>{g.type === 'qemu' ? <Icons.Monitor /> : <Icons.Layers />}</span>
                                                    {g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}`}
                                                </button>
                                                {g.template && <span className="ml-2 text-[10px] uppercase" style={{color: '#728b9a'}}>{t('template')}</span>}
                                            </td>
                                            <td>{label(g.cluster_id, g.cluster_name)}</td>
                                            <td style={{color: '#adbbc4'}}>{g.node || '-'}</td>
                                            <td>
                                                <span className="inline-flex items-center gap-1">
                                                    <span className="w-1.5 h-1.5 rounded-full inline-block" style={{background: dot[stateOf(g)]}} />
                                                    <span className="capitalize" style={{color: dot[stateOf(g)], fontSize: '12px'}}>{statusText(g)}</span>
                                                </span>
                                            </td>
                                            <td title={`${g.vcpus} vCPU`}>{cpuText(g)}</td>
                                            <td>{memText(g)}</td>
                                            <td>{diskText(g)}</td>
                                            <td style={{color: '#adbbc4'}}>{g.status === 'running' ? allGuestsUptime(g.uptime) : '-'}</td>
                                            <td style={{color: '#adbbc4'}} title={(g.ip_addresses || []).join(', ')}>{ipText(g)}</td>
                                            <td style={{color: '#728b9a', fontSize: '12px'}}>{(g.tags || []).join(', ')}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                        <div className="p-2">{pager}</div>
                        {modals}
                    </div>
                );
            }

            const badge = { running: 'bg-green-500/20 text-green-400', stopped: 'bg-gray-500/20 text-gray-400', other: 'bg-yellow-500/20 text-yellow-400' };
            const pill = (s) => `px-2 py-1 rounded-lg text-xs font-medium capitalize border ${view.status === s ? 'border-proxmox-orange text-white' : 'border-proxmox-border text-gray-400 hover:text-white'}`;
            return (
                <div data-all-guests className="space-y-4">
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center text-blue-400">
                                <Icons.Monitor />
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-white">
                                    {t('allGuestsTitle')} {data && !data.failed && <span data-all-guests-total className="text-sm font-normal text-gray-500">({num(data.count)})</span>}
                                </h2>
                                <p className="text-xs text-gray-500">{t('allGuestsDesc')}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            {chip('running', t('running'), pill('running'))}
                            {chip('stopped', t('stopped'), pill('stopped'))}
                            {counts && counts.other > 0 && chip('other', t('allGuestsOther'), pill('other'))}
                            {refreshButton}
                        </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">{filters}</div>
                    {acts && pickedList.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2 p-3 bg-proxmox-orange/10 border border-proxmox-orange/30 rounded-lg">
                            <span data-all-guests-picked className="text-sm text-proxmox-orange font-medium mr-1">{pickedList.length} {t('selectedItems')}</span>
                            {actions.map(a => (
                                <button key={a.action} type="button" data-all-guests-action={a.action} onClick={() => runAction(a)} disabled={blocked(a)} title={hint(a)}
                                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-white text-sm disabled:opacity-40 ${a.cls}`}>
                                    {a.icon}
                                    {a.label}
                                </button>
                            ))}
                            <button type="button" data-all-guests-clear onClick={() => setPicked({})} className="px-3 py-1.5 text-gray-400 hover:text-white text-sm">
                                {t('clearSelection')}
                            </button>
                        </div>
                    )}
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                        {notes}
                        {rows.length > 0 && (
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead className="bg-proxmox-dark/50">
                                        <tr className="text-left text-xs text-gray-400">
                                            {acts && <th className="px-3 py-3 w-10">{pageBox}</th>}
                                            {columns.map((c, i) => (
                                                <th key={i} data-all-guests-sort={c.by || undefined} onClick={c.by ? () => sortOn(c.by) : undefined}
                                                    className={`px-3 py-3 font-medium whitespace-nowrap ${c.by ? 'cursor-pointer hover:text-white' : ''}`}>
                                                    {c.label}{c.by && view.by === c.by && <span className="ml-1">{view.dir === 'asc' ? '▲' : '▼'}</span>}
                                                </th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-proxmox-border/50">
                                        {rows.map(g => (
                                            <tr key={keyOf(g)} data-all-guests-row={keyOf(g)}
                                                className={`${picked[keyOf(g)] ? 'bg-proxmox-orange/10' : ''} hover:bg-proxmox-hover/50 transition-colors`}>
                                                {acts && <td className="px-3 py-2">{pickBox(g)}</td>}
                                                <td className="px-3 py-2 text-xs text-gray-500">{g.vmid}</td>
                                                <td className="px-3 py-2">
                                                    <button type="button" data-all-guests-open={keyOf(g)} onClick={() => openGuest(g)} title={t('allGuestsOpen')}
                                                        className="flex items-center gap-2 text-left text-sm font-medium text-white hover:text-proxmox-orange">
                                                        <span className={`flex ${g.type === 'qemu' ? 'text-blue-400' : 'text-purple-400'}`}>{g.type === 'qemu' ? <Icons.Monitor /> : <Icons.Layers />}</span>
                                                        <span className="truncate">{g.name || `${g.type === 'lxc' ? 'CT' : 'VM'} ${g.vmid}`}</span>
                                                        {g.template && <span className="px-1.5 py-0.5 text-[10px] rounded bg-proxmox-dark text-gray-400 uppercase">{t('template')}</span>}
                                                    </button>
                                                </td>
                                                <td className="px-3 py-2 text-sm text-gray-300">{label(g.cluster_id, g.cluster_name)}</td>
                                                <td className="px-3 py-2 text-sm text-gray-400">{g.node || '-'}</td>
                                                <td className="px-3 py-2">
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium capitalize ${badge[stateOf(g)]}`}>{statusText(g)}</span>
                                                </td>
                                                <td className="px-3 py-2 text-sm text-gray-300" title={`${g.vcpus} vCPU`}>{cpuText(g)}</td>
                                                <td className="px-3 py-2 text-xs text-gray-300 whitespace-nowrap">{memText(g)}</td>
                                                <td className="px-3 py-2 text-xs text-gray-300 whitespace-nowrap">{diskText(g)}</td>
                                                <td className="px-3 py-2 text-xs text-gray-400 whitespace-nowrap">{g.status === 'running' ? allGuestsUptime(g.uptime) : '-'}</td>
                                                <td className="px-3 py-2 text-xs text-gray-400 font-mono" title={(g.ip_addresses || []).join(', ')}>{ipText(g)}</td>
                                                <td className="px-3 py-2">
                                                    <div className="flex flex-wrap gap-1">
                                                        {(g.tags || []).slice(0, 3).map(x => <span key={x} className="px-1.5 py-0.5 text-[10px] rounded bg-proxmox-dark text-gray-400">{x}</span>)}
                                                        {(g.tags || []).length > 3 && <span className="text-[10px] text-gray-500">+{g.tags.length - 3}</span>}
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        <div className="p-3 border-t border-proxmox-border">{pager}</div>
                    </div>
                    {modals}
                </div>
            );
        }
