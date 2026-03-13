        // ═══════════════════════════════════════════════
        // PegaProx - Tables & Cards
        // NodeCard + ResourceTable
        // ═══════════════════════════════════════════════
        // Node Card Component
        function NodeCard({ name, metrics, index, clusterId, onMaintenanceToggle, onStartUpdate, onOpenNodeConfig, onNodeAction, onRemoveNode, onMoveNode }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
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
            const [showUpdateConfirm, setShowUpdateConfirm] = useState(false);
            const [updateWithReboot, setUpdateWithReboot] = useState(true);
            const [showUpdateLog, setShowUpdateLog] = useState(false);
            const [showRebootConfirm, setShowRebootConfirm] = useState(false);
            const [showShutdownConfirm, setShowShutdownConfirm] = useState(false);
            const [actionLoading, setActionLoading] = useState(null);
            const [expanded, setExpanded] = useState(false);
            const lastMetricsRef = useRef(null);
            const lastNetRef = useRef({ netin: 0, netout: 0, time: Date.now() });

            useEffect(() => {
                if (metrics && metrics !== lastMetricsRef.current) {
                    lastMetricsRef.current = metrics;
                    
                    // calc network rate
                    const now = Date.now();
                    const timeDiff = (now - lastNetRef.current.time) / 1000;
                    const netinRate = timeDiff > 0 ? Math.max(0, (metrics.netin - lastNetRef.current.netin) / timeDiff) : 0;
                    const netoutRate = timeDiff > 0 ? Math.max(0, (metrics.netout - lastNetRef.current.netout) / timeDiff) : 0;
                    lastNetRef.current = { netin: metrics.netin || 0, netout: metrics.netout || 0, time: now };
                    
                    historyRef.current = {
                        cpu: [...historyRef.current.cpu.slice(1), metrics.cpu_percent || 0],
                        mem: [...historyRef.current.mem.slice(1), metrics.mem_percent || 0],
                        disk: [...historyRef.current.disk.slice(1), metrics.disk_percent || 0],
                        netin: [...historyRef.current.netin.slice(1), netinRate / 1048576], // MB/s
                        netout: [...historyRef.current.netout.slice(1), netoutRate / 1048576]
                    };
                    forceUpdate(n => n + 1);
                }
            }, [metrics?.cpu_percent, metrics?.mem_percent, metrics?.netin, metrics?.netout]);
            
            const history = historyRef.current;

            const formatBytes = (bytes) => {
                const gb = bytes / 1073741824;
                return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1048576).toFixed(1)} MB`;
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
                        <div className="absolute top-2 right-2">
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
                                {t('lastSeen') || 'Last seen'}: {new Date(metrics.last_seen).toLocaleString()}
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
                                        {(updateTask.status === 'completed' || updateTask.status === 'failed') && (
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
                                                className="text-xs text-gray-400 hover:text-white px-2 py-0.5 hover:bg-proxmox-hover rounded transition-colors"
                                            >
                                                ✕
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
                                    </div>
                                )}
                                
                                {/* After acknowledging completed_with_errors OR normal completed - show full menu */}
                                {(maintenanceTask?.status === 'completed' || (maintenanceTask?.status === 'completed_with_errors' && metrics.maintenance_acknowledged)) && (
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
                                        {isUpdating ? t('updating') : isInMaintenance ? t('maintenance') : metrics.status}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            {!isInMaintenance && !isUpdating && (
                                <button
                                    onClick={() => setShowMaintenanceConfirm(true)}
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
                                <div className="text-xs text-gray-500">Score</div>
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
                                {/* Disk Usage */}
                                <div className="flex items-center justify-between text-xs">
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
                                </div>
                                
                                {/* Network */}
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500 flex items-center gap-2">
                                        <Icons.Network /> Network In
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
                                        <Icons.Network /> Network Out
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
                                            <Icons.Activity /> Load Avg
                                        </span>
                                        <span className="text-gray-300 font-mono">
                                            {Array.isArray(metrics.loadavg) ? 
                                                metrics.loadavg.map(l => l.toFixed(2)).join(' / ') :
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
                                            {metrics.cpuinfo.cores || metrics.cpuinfo.cpus || '-'} × {metrics.cpuinfo.sockets || 1} Socket
                                        </span>
                                    </div>
                                )}
                                
                                {/* Kernel Version */}
                                {metrics.kversion && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500">Kernel</span>
                                        <span className="text-gray-400 font-mono text-[10px] truncate max-w-32">
                                            {metrics.kversion.split(' ')[0] || metrics.kversion}
                                        </span>
                                    </div>
                                )}
                                
                                {/* PVE Version */}
                                {metrics.pveversion && (
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-gray-500">PVE</span>
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
                                className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden"
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
                                    <p className="text-sm text-gray-400 mb-6">
                                        {t('maintenanceDesc')}
                                    </p>
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
                                                onMaintenanceToggle(name, true);
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
        function NodeCompactRow({ name, metrics, clusterId, onOpenNodeConfig, onMaintenanceToggle, onStartUpdate, onNodeAction, onRemoveNode, onMoveNode }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [expanded, setExpanded] = useState(false);
            const [showMaintenanceConfirm, setShowMaintenanceConfirm] = useState(false);
            const [showRebootConfirm, setShowRebootConfirm] = useState(false);
            const [showShutdownConfirm, setShowShutdownConfirm] = useState(false);
            const [showUpdateConfirm, setShowUpdateConfirm] = useState(false);
            const [updateWithReboot, setUpdateWithReboot] = useState(true);
            const [actionLoading, setActionLoading] = useState(null);

            const isOffline = !metrics || metrics.status === 'offline';
            const cpuPercent = metrics?.cpu_percent?.toFixed(1) || (metrics?.cpu ? (metrics.cpu * 100).toFixed(1) : '0');
            const ramPercent = metrics?.mem_percent?.toFixed(1) || (metrics?.memory ? ((metrics.memory.used / metrics.memory.total) * 100).toFixed(1) : '0');
            const isInMaintenance = metrics?.maintenance_mode;
            const maintenanceTask = metrics?.maintenance_task;
            const isUpdating = metrics?.is_updating;
            const updateTask = metrics?.update_task;
            const canUpdate = isInMaintenance && maintenanceTask?.status && ['completed', 'completed_with_errors'].includes(maintenanceTask.status) && !isUpdating;

            const formatBytes = (bytes) => { const gb = bytes / 1073741824; return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1048576).toFixed(1)} MB`; };
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

            return (
                <div className="corp-node-row">
                    {/* Main Row */}
                    <div className={`flex items-center gap-3 px-3 py-2 text-[13px] cursor-pointer ${isOffline ? 'opacity-50' : ''}`} onClick={() => !isOffline && setExpanded(!expanded)}>
                        {!isOffline && <Icons.ChevronRight className={`w-3 h-3 flex-shrink-0`} style={{color: '#728b9a', transform: expanded ? 'rotate(90deg)' : 'none'}} />}
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={statusDotStyle}></span>
                        <span className="font-medium w-32 truncate" style={{color: '#e9ecef'}}>{name}</span>
                        {!isOffline ? (
                            <>
                                {statusLabel && <span className={`corp-badge ${isInMaintenance ? 'corp-badge-locked' : 'corp-badge-ha'}`}>{statusLabel}</span>}
                                <span className="w-8" style={{color: '#728b9a'}}>CPU</span>
                                <div className="w-20 h-1.5 flex-shrink-0 overflow-hidden" style={{background: '#1b2a32', borderRadius: '1px'}}>
                                    <div className="h-full" style={{width: `${Math.min(cpuPercent, 100)}%`, background: '#49afd9', borderRadius: '1px'}}></div>
                                </div>
                                <span className="w-12 text-right" style={{color: '#adbbc4'}}>{cpuPercent}%</span>
                                <span className="w-8 ml-2" style={{color: '#728b9a'}}>RAM</span>
                                <div className="w-20 h-1.5 flex-shrink-0 overflow-hidden" style={{background: '#1b2a32', borderRadius: '1px'}}>
                                    <div className="h-full" style={{width: `${Math.min(ramPercent, 100)}%`, background: '#9b59b6', borderRadius: '1px'}}></div>
                                </div>
                                <span className="w-12 text-right" style={{color: '#adbbc4'}}>{ramPercent}%</span>
                                {metrics.score != null && <span className="ml-3 w-16" style={{color: '#728b9a'}}>{t('score')}: <span style={{color: '#adbbc4'}}>{metrics.score}</span></span>}
                                <span className="ml-3" style={{color: '#728b9a'}}>{formatUptime(metrics.uptime)}</span>
                                <span className="flex-1"></span>
                                {isInMaintenance && maintenanceTask && maintenanceTask.status === 'running' && (
                                    <span className="text-[11px] mr-2" style={{color: '#efc006'}}>{maintenanceTask.migrated_count || 0}/{maintenanceTask.total_vms || '?'} VMs</span>
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
                        <div className="px-3 pb-3 pt-1 ml-5" style={{borderTop: '1px solid #37474f'}}>
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
                                        {(updateTask.status === 'completed' || updateTask.status === 'failed') && (
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
                                                <div className="w-16 h-1 overflow-hidden" style={{background: '#1b2a32', borderRadius: '1px'}}>
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
                                    {maintenanceTask.status === 'completed_with_errors' && !metrics.maintenance_acknowledged && (
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
                                </div>
                            )}

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-[12px] mb-2">
                                <div><span style={{color: '#728b9a'}}>{t('disk')}: </span><span style={{color: '#adbbc4'}}>{metrics.disk_percent?.toFixed(1) || '-'}%</span>
                                    {metrics.disk_total && <span style={{color: '#728b9a'}}> ({formatBytes(metrics.disk_used || 0)} / {formatBytes(metrics.disk_total)})</span>}
                                </div>
                                <div><span style={{color: '#728b9a'}}>Load: </span><span style={{color: '#adbbc4'}}>{
                                    Array.isArray(metrics.loadavg) ? metrics.loadavg.map(l => typeof l === 'number' ? l.toFixed(2) : l).join(' / ') :
                                    typeof metrics.loadavg === 'number' ? metrics.loadavg.toFixed(2) : (metrics.loadavg || '-')
                                }</span></div>
                                <div><span style={{color: '#728b9a'}}>{t('cpuCores')}: </span><span style={{color: '#adbbc4'}}>{metrics.cpus || metrics.cpu_count || (metrics.cpuinfo ? `${metrics.cpuinfo.cores || metrics.cpuinfo.cpus || '-'} × ${metrics.cpuinfo.sockets || 1}` : '-')}</span></div>
                                <div><span style={{color: '#728b9a'}}>{t('uptime')}: </span><span style={{color: '#adbbc4'}}>{formatUptime(metrics.uptime)}</span></div>
                                {(metrics.kernel_version || metrics.kversion) && <div><span style={{color: '#728b9a'}}>{t('kernel') || 'Kernel'}: </span><span style={{color: '#adbbc4'}}>{metrics.kernel_version || (metrics.kversion ? metrics.kversion.split(' ')[0] : '')}</span></div>}
                                {(metrics.pve_version || metrics.pveversion) && <div><span style={{color: '#728b9a'}}>PVE: </span><span style={{color: '#adbbc4'}}>{metrics.pve_version || metrics.pveversion}</span></div>}
                            </div>

                            {/* Action Buttons */}
                            <div className="corp-toolbar flex flex-wrap items-center gap-1 pt-1" style={{borderTop: '1px solid #37474f'}}>
                                {!isInMaintenance ? (
                                    <button onClick={() => setShowMaintenanceConfirm(true)}>
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
                                        {maintenanceTask?.status && ['completed', 'completed_with_errors'].includes(maintenanceTask.status) && (
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
                            </div>
                        </div>
                    )}

                    {/* Confirmation Modals */}
                    {showMaintenanceConfirm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border p-5">
                                <h3 className="text-[14px] font-semibold mb-2" style={{color: '#e9ecef'}}>{t('enterMaintenance') || 'Enter Maintenance Mode'}</h3>
                                <p className="text-[13px] mb-4" style={{color: '#adbbc4'}}>{t('maintenanceWarning') || `All VMs on ${name} will be migrated to other nodes.`}</p>
                                <div className="flex justify-end gap-2">
                                    <button onClick={() => setShowMaintenanceConfirm(false)} className="px-3 py-1.5 text-[13px] border border-proxmox-border hover:text-white" style={{color: '#adbbc4'}}>{t('cancel')}</button>
                                    <button onClick={() => { onMaintenanceToggle && onMaintenanceToggle(name, true); setShowMaintenanceConfirm(false); }} className="px-3 py-1.5 text-[13px] text-white" style={{background: '#efc006', border: '1px solid #d4a905'}}>{t('confirm') || 'Confirm'}</button>
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

        // Resource Table Component
        // LW: The main VM/CT list - supports cards, table, and detail view
        // NS: Added bulk select for mass operations (migration, etc.)
        // This component does a lot... might need to split it up eventually
        // FIXME: rerenders too often, useMemo wuold help probably
        function ResourceTable({ resources, clusterId, clusters, sourceCluster, onVmAction, onOpenConsole, onOpenConfig, onMigrate, onBulkMigrate, onDelete, onClone, onForceStop, onCrossClusterMigrate, nodes, onOpenTags, highlightedVm, addToast }) {
            const { t } = useTranslation();
            const { isCorporate } = useLayout(); // LW: Feb 2026 - corporate defaults to table view
            const [search, setSearch] = useState('');
            const [filter, setFilter] = useState('all');
            const [sortBy, setSortBy] = useState('vmid');
            const [sortDir, setSortDir] = useState('asc');
            const [viewMode, setViewMode] = useState(isCorporate ? 'table' : 'cards'); // LW: corporate defaults to table
            const [actionLoading, setActionLoading] = useState({});
            const [selectedVms, setSelectedVms] = useState([]);
            const [showMigrateModal, setShowMigrateModal] = useState(null);
            const [showBulkMigrate, setShowBulkMigrate] = useState(false);
            const [showDeleteConfirm, setShowDeleteConfirm] = useState(null);
            const [showCloneModal, setShowCloneModal] = useState(null);
            const [selectedDetailVm, setSelectedDetailVm] = useState(null); // For detail view
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

            const filterLabels = {
                all: t('all'),
                running: t('active'),
                stopped: t('stopped'),
                vm: 'VM',
                lxc: 'LXC'
            };

            // LW: filter + sort in one useMemo for perf
            // TODO: maybe split this up, its getting complex
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
                    return matchesSearch && matchesFilter;
                });
                
                // sort
                filtered.sort((a, b) => {
                    const aVal = a[sortBy];
                    const bVal = b[sortBy];
                    const dir = sortDir === 'asc' ? 1 : -1;
                    if (typeof aVal === 'number') return(aVal - bVal) * dir;
                    return String(aVal).localeCompare(String(bVal)) * dir;
                });
                
                return filtered;
            }, [resources, search, filter, sortBy, sortDir]);
            
            // Reset page when filters change - MK Jan 2026
            // NS: Also reset when cluster changes (via clusterId) to avoid showing empty page
            useEffect(() => {
                setCurrentPage(1);
            }, [search, filter, sortBy, sortDir, itemsPerPage, clusterId]);
            
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

            const handleSort = (col) => {
                if (sortBy === col) {
                    setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
                } else {
                    setSortBy(col);
                    setSortDir('asc');  // reset to asc on new column
                }
            };

            // NS: 1073741824 = 1024^3 (GB), 1048576 = 1024^2 (MB)
            const formatBytes = (bytes) => {
                const gb = bytes / 1073741824;
                return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1048576).toFixed(0)} MB`;
            };
            
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

            const groupedByNode = useMemo(() => {
                const groups = {};
                filteredResources.forEach(r => {
                    if (!groups[r.node]) groups[r.node] = [];
                    groups[r.node].push(r);
                });
                return groups;
            }, [filteredResources]);

            return(
                <div className="space-y-4">
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
                        <div className="flex items-center gap-2">
                            {['all', 'running', 'stopped', 'vm', 'lxc'].map(f => (
                                <button
                                    key={f}
                                    onClick={() => setFilter(f)}
                                    className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                                        filter === f 
                                            ? 'bg-proxmox-orange text-white' 
                                            : 'bg-proxmox-dark text-gray-400 hover:text-white border border-proxmox-border'
                                    }`}
                                >
                                    {filterLabels[f]}
                                </button>
                            ))}
                        </div>
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
                    </div>

                    {/* Bulk Actions Bar */}
                    {selectedVms.length > 0 && (
                        <div className="flex items-center gap-3 p-3 bg-proxmox-orange/10 border border-proxmox-orange/30 rounded-lg">
                            <span className="text-sm text-proxmox-orange font-medium">
                                {selectedVms.length} {t('selectedItems')}
                            </span>
                            <button
                                onClick={() => setShowBulkMigrate(true)}
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
                                                <div className={`p-2 rounded-lg ${resource.type === 'qemu' ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                                    {resource.type === 'qemu' ? <Icons.VM /> : <Icons.Container />}
                                                </div>
                                                <div>
                                                    <div className="font-medium text-white truncate max-w-[150px]">
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
                                            {/* VM Tags */}
                                            {resource.tags && (
                                                <div className="flex flex-wrap gap-1">
                                                    {resource.tags.split(';').filter(t => t.trim()).map((tag, i) => (
                                                        <span key={i} className="px-1.5 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                            {tag.trim()}
                                                        </span>
                                                    ))}
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
                                        </div>
                                        
                                        {/* Card Actions */}
                                        <div className="flex items-center justify-between p-3 border-t border-proxmox-border bg-proxmox-dark/30">
                                            {/* Primary Actions - Always visible */}
                                            <div className="flex items-center gap-1">
                                                {resource.status === 'stopped' ? (
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
                                                {resource.status === 'running' && (
                                                    <button
                                                        onClick={() => onOpenConsole(resource)}
                                                        className="p-1.5 rounded-lg hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                        title={t('console')}
                                                    >
                                                        <Icons.Monitor />
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => onOpenConfig(resource)}
                                                    className="p-1.5 rounded-lg hover:bg-purple-500/20 text-gray-400 hover:text-purple-400 transition-all"
                                                    title={t('configuration')}
                                                >
                                                    <Icons.Cog />
                                                </button>
                                                <button
                                                    onClick={() => setShowMigrateModal(resource)}
                                                    className="p-1.5 rounded-lg hover:bg-cyan-500/20 text-gray-400 hover:text-cyan-400 transition-all"
                                                    title={t('migrate')}
                                                >
                                                    <Icons.ArrowRight />
                                                </button>
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
                                                            <button
                                                                onClick={() => { setShowMetricsModal(resource); setOpenDropdown(null); }}
                                                                className="w-full px-3 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2"
                                                            >
                                                                <Icons.BarChart className="w-4 h-4" />
                                                                {t('performance')}
                                                            </button>
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
                            <table className={`w-full ${isCorporate ? 'corp-datagrid' : ''}`}>
                                <thead>
                                    <tr className={isCorporate ? 'text-left' : 'bg-proxmox-dark text-left'} style={isCorporate ? {background: '#22343c'} : undefined}>
                                        <th className={isCorporate ? 'px-2 py-1.5 w-8' : 'px-4 py-3 w-10'}>
                                            <input
                                                type="checkbox"
                                                checked={selectedVms.length === filteredResources.length && filteredResources.length > 0}
                                                onChange={toggleSelectAll}
                                                className="w-4 h-4 rounded border-proxmox-border bg-proxmox-dark text-proxmox-orange focus:ring-proxmox-orange"
                                            />
                                        </th>
                                        {[
                                            { key: 'vmid', label: 'ID' },
                                            { key: 'name', label: t('name') },
                                            { key: 'type', label: t('type') },
                                            { key: 'node', label: 'Node' },
                                            { key: 'mem', label: 'RAM' },
                                            { key: 'status', label: 'Status' },
                                            { key: 'actions', label: t('actions') },
                                        ].map(col => (
                                            <th
                                                key={col.key}
                                                onClick={() => col.key !== 'actions' && handleSort(col.key)}
                                                className={isCorporate
                                                    ? `text-xs font-semibold uppercase tracking-wider ${col.key !== 'actions' ? 'cursor-pointer hover:text-white' : ''}`
                                                    : `px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider ${col.key !== 'actions' ? 'cursor-pointer hover:text-white' : ''} transition-colors`
                                                }
                                                style={isCorporate ? {color: '#adbbc4', padding: '6px 8px', fontSize: '12px'} : undefined}
                                            >
                                                <div className="flex items-center gap-1">
                                                    {col.label}
                                                    {sortBy === col.key && (
                                                        <span className={isCorporate ? 'sort-indicator' : 'text-proxmox-orange'} style={isCorporate ? {color: '#49afd9'} : undefined}>{sortDir === 'asc' ? '↑' : '↓'}</span>
                                                    )}
                                                </div>
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className={isCorporate ? '' : 'divide-y divide-proxmox-border'}>
                                    {paginatedResources.length === 0 ? (
                                        <tr>
                                            <td colSpan={8} className={isCorporate ? 'px-2 py-4 text-center text-gray-500' : 'px-4 py-8 text-center text-gray-500'}>
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
                                                        <span className="font-medium text-white">{resource.name || '-'}</span>
                                                        {resource.tags && (
                                                            <div className="flex flex-wrap gap-1 mt-1">
                                                                {resource.tags.split(';').filter(t => t.trim()).slice(0, 3).map((tag, i) => (
                                                                    <span key={i} className="px-1.5 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                                        {tag.trim()}
                                                                    </span>
                                                                ))}
                                                                {resource.tags.split(';').filter(t => t.trim()).length > 3 && (
                                                                    <span className="px-1.5 py-0.5 text-xs rounded bg-gray-500/20 text-gray-400">
                                                                        +{resource.tags.split(';').filter(t => t.trim()).length - 3}
                                                                    </span>
                                                                )}
                                                            </div>
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium ${
                                                        resource.type === 'qemu' 
                                                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                                            : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                                                    }`}>
                                                        {resource.type === 'qemu' ? <Icons.VM /> : <Icons.Container />}
                                                        {resource.type === 'qemu' ? 'VM' : 'LXC'}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="text-sm text-gray-300">{resource.node}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 max-w-[100px]">
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
                                                    </div>
                                                </td>
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
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-1">
                                                        <button
                                                            onClick={() => onOpenConfig(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-purple-500/20 text-gray-400 hover:text-purple-400 transition-all"
                                                            title={t('configuration')}
                                                        >
                                                            <Icons.Cog />
                                                        </button>
                                                        <button
                                                            onClick={() => onOpenTags && onOpenTags(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-yellow-500/20 text-gray-400 hover:text-yellow-400 transition-all"
                                                            title={t('tags')}
                                                        >
                                                            <Icons.Tag />
                                                        </button>
                                                        <button
                                                            onClick={() => setShowMetricsModal(resource)}
                                                            className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                            title={t('metrics')}
                                                        >
                                                            <Icons.BarChart />
                                                        </button>
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
                                                        {resource.status === 'running' && (
                                                            <button
                                                                onClick={() => onOpenConsole(resource)}
                                                                className="p-1.5 rounded-lg bg-proxmox-dark hover:bg-blue-500/20 text-gray-400 hover:text-blue-400 transition-all"
                                                                title={t('openConsole')}
                                                            >
                                                                <Icons.Monitor />
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
                                                                {/* Force Reset - QEMU only */}
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
                                                    </div>
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
                            {/* VM List */}
                            <div className="lg:col-span-1 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-3 border-b border-proxmox-border bg-proxmox-dark/50">
                                    <h3 className="text-sm font-medium text-gray-300">VMs & Container ({filteredResources.length})</h3>
                                </div>
                                <div className="max-h-[600px] overflow-y-auto">
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
                                            <div className={`p-1.5 rounded ${resource.type === 'qemu' ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                                {resource.type === 'qemu' ? <Icons.VM /> : <Icons.Container />}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <div className="font-medium text-white text-sm truncate">
                                                    {resource.name || `${resource.type === 'qemu' ? 'VM' : 'CT'} ${resource.vmid}`}
                                                </div>
                                                <div className="text-xs text-gray-500">ID: {resource.vmid} · {resource.node}</div>
                                                {resource.tags && (
                                                    <div className="flex flex-wrap gap-1 mt-1">
                                                        {resource.tags.split(';').filter(t => t.trim()).slice(0, 2).map((tag, i) => (
                                                            <span key={i} className="px-1 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange">
                                                                {tag.trim()}
                                                            </span>
                                                        ))}
                                                        {resource.tags.split(';').filter(t => t.trim()).length > 2 && (
                                                            <span className="px-1 py-0.5 text-xs rounded bg-gray-500/20 text-gray-400">
                                                                +{resource.tags.split(';').filter(t => t.trim()).length - 2}
                                                            </span>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
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

