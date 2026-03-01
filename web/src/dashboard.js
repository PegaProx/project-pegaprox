        // ═══════════════════════════════════════════════
        // PegaProx - Dashboard & App
        // TaskBar, Dashboard, App component, ReactDOM.render
        // ═══════════════════════════════════════════════
        // Task Bar Component with Task Viewer
        function TaskBar({ tasks, onClear, onClose, onCancel, onRefresh, clusterId, autoExpandEnabled = true }) {
            const { t } = useTranslation();
            const [expanded, setExpanded] = useState(false);
            const [selectedTask, setSelectedTask] = useState(null);
            const [taskLog, setTaskLog] = useState('');
            const [taskLogLoading, setTaskLogLoading] = useState(false);
            const [filter, setFilter] = useState('all'); // all, running, error, today
            const { getAuthHeaders } = useAuth();
            const prevRunningCount = React.useRef(0);
            
            // LW: Resizable height - Feb 2026
            const [height, setHeight] = useState(() => {
                const saved = localStorage.getItem('pegaprox-taskbar-height');
                return saved ? parseInt(saved) : 384; // default h-96 = 384px
            });
            const [isResizing, setIsResizing] = useState(false);
            const resizeRef = React.useRef(null);
            
            // Ensure tasks is an array
            const safeTasks = Array.isArray(tasks) ? tasks : [];
            
            const runningCount = safeTasks.filter(task => task && task.status === 'running').length;
            const failedCount = safeTasks.filter(task => task && (task.status === 'failed' || task.status === 'error')).length;
            
            // NS: Auto-expand when new task starts (if enabled in user preferences)
            React.useEffect(() => {
                if (autoExpandEnabled && runningCount > prevRunningCount.current && runningCount > 0) {
                    setExpanded(true);
                }
                prevRunningCount.current = runningCount;
            }, [runningCount, autoExpandEnabled]);
            
            // NS: Handle resize drag
            React.useEffect(() => {
                if (!isResizing) return;
                
                // Set cursor on body during resize
                document.body.style.cursor = 'ns-resize';
                document.body.style.userSelect = 'none';
                
                const handleMouseMove = (e) => {
                    const newHeight = window.innerHeight - e.clientY;
                    // Limit between 150px and 80% of viewport
                    const clampedHeight = Math.max(150, Math.min(newHeight, window.innerHeight * 0.8));
                    setHeight(clampedHeight);
                };
                
                const handleMouseUp = () => {
                    setIsResizing(false);
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                    // Save to localStorage
                    localStorage.setItem('pegaprox-taskbar-height', height.toString());
                };
                
                document.addEventListener('mousemove', handleMouseMove);
                document.addEventListener('mouseup', handleMouseUp);
                
                return () => {
                    document.removeEventListener('mousemove', handleMouseMove);
                    document.removeEventListener('mouseup', handleMouseUp);
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                };
            }, [isResizing, height]);
            
            // Filter tasks
            const filteredTasks = safeTasks.filter(task => {
                if (!task) return false;
                if (filter === 'running') return task.status === 'running';
                if (filter === 'error') return task.status === 'failed' || task.status === 'error';
                if (filter === 'today') {
                    const today = new Date();
                    today.setHours(0, 0, 0, 0);
                    return task.starttime && (task.starttime * 1000) >= today.getTime();
                }
                return true;
            });
            
            const formatTaskType = (type) => {
                if (!type) return 'Task';
                const types = {
                    'qmigrate': 'VM Migration', 'vzmigrate': 'CT Migration',
                    'qmstart': 'VM Start', 'vzstart': 'CT Start',
                    'qmstop': 'VM Stop', 'vzstop': 'CT Stop',
                    'qmshutdown': 'VM Shutdown', 'vzshutdown': 'CT Shutdown',
                    'qmreboot': 'VM Reboot', 'vzreboot': 'CT Reboot',
                    'qmcreate': 'VM Create', 'vzcreate': 'CT Create',
                    'qmdestroy': 'VM Delete', 'vzdestroy': 'CT Delete',
                    'qmclone': 'VM Clone', 'vzclone': 'CT Clone',
                    'qmsnapshot': 'Snapshot', 'vzsnapshot': 'Snapshot',
                    'imgcopy': 'Disk Copy', 'move_volume': 'Disk Move',
                    'resize': 'Disk Resize', 'download': 'Download',
                    'vzdump': 'Backup', 'qmrestore': 'Restore', 'vzrestore': 'Restore',
                };
                return types[type] || type;
            };
            
            const formatDuration = (start, end) => {
                if (!start) return '-';
                const endTime = end || Math.floor(Date.now() / 1000);
                const duration = endTime - start;
                const hours = Math.floor(duration / 3600);
                const mins = Math.floor((duration % 3600) / 60);
                const secs = duration % 60;
                if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
                if (mins > 0) return `${mins}m ${secs}s`;
                return `${secs}s`;
            };
            
            // Fetch task log
            const fetchTaskLog = async (task) => {
                if (!task || !task.node || !task.upid || !clusterId) return;
                
                setTaskLogLoading(true);
                setTaskLog('');
                
                try {
                    const response = await fetch(
                        `${API_URL}/clusters/${clusterId}/nodes/${task.node}/tasks/${encodeURIComponent(task.upid)}/log`,
                        { headers: getAuthHeaders() }
                    );
                    
                    if (response.ok) {
                        const data = await response.json();
                        setTaskLog(data.log || t('noOutput'));
                    } else {
                        setTaskLog(t('errorLoadingLog'));
                    }
                } catch (err) {
                    setTaskLog(t('errorLoadingLog'));
                } finally {
                    setTaskLogLoading(false);
                }
            };
            
            // Open task detail
            const openTaskDetail = (task) => {
                setSelectedTask(task);
                fetchTaskLog(task);
            };
            
            return (
                <div 
                    className={`fixed bottom-0 left-0 right-0 z-40 transition-all ${isResizing ? '' : 'duration-300'}`}
                    style={{ height: expanded ? `${height}px` : '40px' }}
                >
                    {/* NS: Resize Handle - only visible when expanded */}
                    {expanded && (
                        <div 
                            className="absolute top-0 left-0 right-0 h-2 cursor-ns-resize group z-10"
                            onMouseDown={(e) => {
                                e.preventDefault();
                                setIsResizing(true);
                            }}
                            title={t('dragToResize') || 'Drag to resize'}
                        >
                            <div className="absolute top-0 left-1/2 transform -translate-x-1/2 w-16 h-1 bg-gray-600 rounded-full group-hover:bg-proxmox-orange transition-colors" />
                        </div>
                    )}
                    
                    {/* Task Detail Modal */}
                    {selectedTask && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" onClick={() => setSelectedTask(null)}>
                            <div className="w-full max-w-3xl bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                {/* Header */}
                                <div className="flex items-center justify-between p-4 border-b border-proxmox-border bg-proxmox-dark">
                                    <div className="flex items-center gap-3">
                                        <span className={`w-3 h-3 rounded-full ${
                                            selectedTask.status === 'running' ? 'bg-blue-500 animate-pulse' :
                                            selectedTask.status === 'failed' || selectedTask.status === 'error' ? 'bg-red-500' :
                                            'bg-green-500'
                                        }`} />
                                        <div>
                                            <h3 className="text-white font-semibold">
                                                {formatTaskType(selectedTask.type)} {selectedTask.vmid ? `(${selectedTask.vmid})` : ''}
                                            </h3>
                                            <p className="text-xs text-gray-400">
                                                {selectedTask.node} • {selectedTask.pegaprox_user || (selectedTask.user ? selectedTask.user.split('@')[0] : '-')}
                                            </p>
                                        </div>
                                    </div>
                                    <button onClick={() => setSelectedTask(null)} className="p-2 hover:bg-proxmox-border rounded">
                                        <Icons.X />
                                    </button>
                                </div>
                                
                                {/* Info Grid */}
                                <div className="p-4 border-b border-proxmox-border grid grid-cols-4 gap-4 text-sm">
                                    <div>
                                        <span className="text-gray-500 block">{t('status')}</span>
                                        <span className={`font-medium ${
                                            selectedTask.status === 'running' ? 'text-blue-400' :
                                            selectedTask.status === 'failed' || selectedTask.status === 'error' ? 'text-red-400' :
                                            'text-green-400'
                                        }`}>{selectedTask.status || '-'}</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block">{t('startTime')}</span>
                                        <span className="text-white">
                                            {selectedTask.starttime ? new Date(selectedTask.starttime * 1000).toLocaleString() : '-'}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block">{t('endTime')}</span>
                                        <span className="text-white">
                                            {selectedTask.endtime ? new Date(selectedTask.endtime * 1000).toLocaleString() : '-'}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block">{t('duration')}</span>
                                        <span className="text-white">{formatDuration(selectedTask.starttime, selectedTask.endtime)}</span>
                                    </div>
                                </div>
                                
                                {/* Task Log */}
                                <div className="p-4">
                                    <div className="flex items-center justify-between mb-2">
                                        <span className="text-sm text-gray-400">{t('taskOutput')}</span>
                                        <button 
                                            onClick={() => fetchTaskLog(selectedTask)}
                                            className="text-xs text-gray-400 hover:text-white"
                                        >
                                            <Icons.RefreshCw />
                                        </button>
                                    </div>
                                    <div className={`h-64 overflow-auto rounded-lg font-mono text-xs p-3 ${
                                        selectedTask.status === 'failed' || selectedTask.status === 'error'
                                            ? 'bg-red-500/5 border border-red-500/20 text-red-300'
                                            : 'bg-proxmox-darker border border-proxmox-border text-gray-300'
                                    }`}>
                                        {taskLogLoading ? (
                                            <span className="text-gray-500">{t('loading')}...</span>
                                        ) : (
                                            <pre className="whitespace-pre-wrap">{taskLog || selectedTask.error || selectedTask.exitstatus || t('noOutput')}</pre>
                                        )}
                                    </div>
                                </div>
                                
                                {/* Actions */}
                                {selectedTask.status === 'running' && onCancel && (
                                    <div className="p-4 border-t border-proxmox-border bg-proxmox-dark">
                                        <button
                                            onClick={() => { onCancel(selectedTask); setSelectedTask(null); }}
                                            className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white text-sm"
                                        >
                                            {t('cancelTask')}
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                    
                    <div className="h-full bg-proxmox-darker border-t border-proxmox-border flex flex-col">
                        {/* Header Bar */}
                        <div 
                            className="h-10 min-h-[40px] px-4 flex items-center justify-between cursor-pointer hover:bg-proxmox-dark/50"
                            onClick={() => setExpanded(!expanded)}
                        >
                            <div className="flex items-center gap-3">
                                <div className="flex items-center gap-2 text-sm">
                                    <Icons.Layers />
                                    <span className="font-medium">{t('tasks')}</span>
                                </div>
                                
                                {runningCount > 0 && (
                                    <span className="px-2 py-0.5 rounded-full bg-blue-500 text-white text-xs font-medium animate-pulse flex items-center gap-1">
                                        <span className="w-2 h-2 bg-white rounded-full animate-ping"></span>
                                        {runningCount} {t('running')}
                                    </span>
                                )}
                                {failedCount > 0 && (
                                    <span className="px-2 py-0.5 rounded-full bg-red-500 text-white text-xs font-medium">
                                        {failedCount} {t('failed')}
                                    </span>
                                )}
                            </div>
                            
                            <div className="flex items-center gap-2">
                                <span className={`transition-transform ${expanded ? 'rotate-180' : ''}`}>
                                    <Icons.ChevronDown />
                                </span>
                            </div>
                        </div>
                        
                        {/* Expanded Task Viewer */}
                        {expanded && (
                            <div className="flex-1 flex flex-col overflow-hidden">
                                {/* Toolbar */}
                                <div className="px-4 py-2 border-b border-proxmox-border flex items-center justify-between bg-proxmox-dark/50">
                                    <div className="flex items-center gap-2">
                                        <select
                                            value={filter}
                                            onChange={e => setFilter(e.target.value)}
                                            className="px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded text-sm text-white"
                                        >
                                            <option value="all">{t('allTasks')}</option>
                                            <option value="running">{t('runningTasks')}</option>
                                            <option value="error">{t('failedTasks')}</option>
                                            <option value="today">{t('todaysTasks')}</option>
                                        </select>
                                        <span className="text-xs text-gray-500">
                                            {filteredTasks.length} {t('tasksShown')}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {onRefresh && (
                                            <button 
                                                onClick={(e) => { e.stopPropagation(); onRefresh(); }}
                                                className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-border rounded"
                                                title={t('refresh')}
                                            >
                                                <Icons.RefreshCw />
                                            </button>
                                        )}
                                        <button 
                                            onClick={(e) => { e.stopPropagation(); onClear(); }}
                                            className="px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-proxmox-border rounded"
                                        >
                                            {t('clearCompleted')}
                                        </button>
                                        <button 
                                            onClick={(e) => { e.stopPropagation(); onClose(); }}
                                            className="p-1.5 text-gray-400 hover:text-white hover:bg-proxmox-border rounded"
                                        >
                                            <Icons.X />
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Task Table */}
                                <div className="flex-1 overflow-auto bg-proxmox-darker">
                                    <table className="w-full text-sm">
                                        <thead className="sticky top-0 bg-proxmox-dark">
                                            <tr className="border-b border-proxmox-border text-left">
                                                <th className="px-4 py-2 text-gray-400 font-medium w-10"></th>
                                                <th className="px-4 py-2 text-gray-400 font-medium">{t('startTime')}</th>
                                                <th className="px-4 py-2 text-gray-400 font-medium">{t('endTime')}</th>
                                                <th className="px-4 py-2 text-gray-400 font-medium">{t('node')}</th>
                                                <th className="px-4 py-2 text-gray-400 font-medium" title={t('userColumnHint') || 'Shows PegaProx user if available, otherwise Proxmox user'}>{t('user')}</th>
                                                <th className="px-4 py-2 text-gray-400 font-medium">{t('description')}</th>
                                                <th className="px-4 py-2 text-gray-400 font-medium">{t('status')}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {filteredTasks.length === 0 ? (
                                                <tr>
                                                    <td colSpan="7" className="px-4 py-8 text-center text-gray-500">
                                                        {t('noTasks')}
                                                    </td>
                                                </tr>
                                            ) : filteredTasks.map((task, idx) => {
                                                if (!task) return null;
                                                const isRunning = task.status === 'running';
                                                const isFailed = task.status === 'failed' || task.status === 'error';
                                                
                                                return (
                                                    <tr 
                                                        key={task.upid || `task-${idx}`}
                                                        className="border-b border-gray-700/50 hover:bg-proxmox-dark/50 cursor-pointer"
                                                        onClick={() => openTaskDetail(task)}
                                                    >
                                                        <td className="px-4 py-2">
                                                            <span className={`inline-block w-2 h-2 rounded-full ${
                                                                isRunning ? 'bg-blue-500 animate-pulse' :
                                                                isFailed ? 'bg-red-500' :
                                                                'bg-green-500'
                                                            }`} />
                                                        </td>
                                                        <td className="px-4 py-2 text-gray-400 whitespace-nowrap">
                                                            {task.starttime ? new Date(task.starttime * 1000).toLocaleString() : '-'}
                                                        </td>
                                                        <td className="px-4 py-2 text-gray-400 whitespace-nowrap">
                                                            {task.endtime ? new Date(task.endtime * 1000).toLocaleString() : '-'}
                                                        </td>
                                                        <td className="px-4 py-2 text-white">{task.node || '-'}</td>
                                                        <td className="px-4 py-2 text-gray-300" title={task.pegaprox_user ? `PegaProx: ${task.pegaprox_user}\nProxmox: ${task.user || '-'}` : (task.user || '-')}>
                                                            {task.pegaprox_user || (task.user ? task.user.split('@')[0] : '-')}
                                                            {task.pegaprox_user && <span className="ml-1 text-proxmox-orange text-xs">●</span>}
                                                        </td>
                                                        <td className="px-4 py-2 text-white">
                                                            {formatTaskType(task.type)}
                                                            {task.vmid && <span className="text-gray-500 ml-1">({task.vmid})</span>}
                                                        </td>
                                                        <td className="px-4 py-2">
                                                            <span className={`px-2 py-0.5 rounded text-xs ${
                                                                isRunning ? 'bg-blue-500/20 text-blue-400' : 
                                                                isFailed ? 'bg-red-500/20 text-red-400' : 
                                                                'bg-green-500/20 text-green-400'
                                                            }`}>
                                                                {task.status || '-'}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        // Main Dashboard Component
        // NS: This is the heart of the app, everything connects here
        // State management is a bit messy but it works // shrug
        // LW: Password Expiry Warning Banner - Dec 2025
        // Shows a warning when user's password is about to expire or has expired
        function PasswordExpiryBanner({ onChangePassword }) {
            const { t } = useTranslation();
            const { passwordExpiry, user } = useAuth();
            const [dismissed, setDismissed] = useState(false);
            
            // Don't show if no expiry info or dismissed
            // NS: removed admin check here - backend now handles include_admins setting
            if (!passwordExpiry || !passwordExpiry.enabled || dismissed) return null;
            
            const { expired, warning, days_until_expiry } = passwordExpiry;
            
            // only show if expired or in warning period
            if (!expired && !warning) return null;
            
            return (
                <div className={`px-4 py-3 ${expired ? 'bg-red-500/20 border-red-500/50' : 'bg-yellow-500/20 border-yellow-500/50'} border-b`}>
                    <div className="max-w-7xl mx-auto flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className={`p-1.5 rounded-full ${expired ? 'bg-red-500/30' : 'bg-yellow-500/30'}`}>
                                <Icons.AlertTriangle className={`w-4 h-4 ${expired ? 'text-red-400' : 'text-yellow-400'}`} />
                            </div>
                            <div>
                                <span className={`font-medium ${expired ? 'text-red-400' : 'text-yellow-400'}`}>
                                    {expired 
                                        ? (t('passwordExpired') || 'Ihr Passwort ist abgelaufen!')
                                        : (t('passwordExpiresIn') || `Ihr Passwort läuft in ${days_until_expiry} Tagen ab`).replace('{days}', days_until_expiry)
                                    }
                                </span>
                                <span className="text-gray-400 ml-2 text-sm">
                                    {expired
                                        ? (t('pleaseChangeNow') || 'Bitte ändern Sie es jetzt.')
                                        : (t('pleaseChangeSoon') || 'Bitte ändern Sie es rechtzeitig.')
                                    }
                                </span>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={onChangePassword}
                                className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                                    expired 
                                        ? 'bg-red-500 hover:bg-red-600 text-white' 
                                        : 'bg-yellow-500 hover:bg-yellow-600 text-black'
                                }`}
                            >
                                {t('changePassword') || 'Passwort ändern'}
                            </button>
                            {!expired && (
                                <button
                                    onClick={() => setDismissed(true)}
                                    className="p-1.5 text-gray-400 hover:text-white rounded"
                                    title={t('dismissForNow') || 'Später erinnern'}
                                >
                                    <Icons.X className="w-4 h-4" />
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

        // Cluster Sidebar Item Component - NS Jan 2026
        function ClusterSidebarItem({ cluster, idx, selectedCluster, setSelectedCluster, nodeAlerts, clusterGroups, isAdmin, handleDeleteCluster, setShowAssignGroup, t, getAuthHeaders, fetchClusters, addToast, isCorporate, expandedSidebarClusters, toggleSidebarCluster }) {
            const offlineNodesCount = Object.values(nodeAlerts || {})
                .filter(alert => alert.cluster_id === cluster.id && alert.status === 'offline')
                .length;
            const hasOfflineNodes = offlineNodesCount > 0;

            const statusColor = cluster.connected === false
                ? 'bg-red-500' : hasOfflineNodes
                ? 'bg-orange-500' : cluster.status === 'running'
                ? 'bg-green-500' : 'bg-gray-500';

            // LW: Feb 2026 - Corporate tree-style sidebar item with tree connectors
            if (isCorporate) {
                const isSelected = selectedCluster?.id === cluster.id;
                const isExpanded = expandedSidebarClusters?.[cluster.id];
                const clrStatusDot = cluster.connected === false ? '#f54f47' : hasOfflineNodes ? '#efc006' : cluster.status === 'running' ? '#60b515' : '#728b9a';
                const clusterIcon = cluster.connected === false
                    ? <Icons.Server className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#f54f47'}} />
                    : hasOfflineNodes
                    ? <Icons.Database className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#efc006'}} />
                    : <Icons.Database className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />;
                return (
                    <div
                        onClick={() => setSelectedCluster(cluster)}
                        tabIndex={0}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedCluster(cluster); } }}
                        className="corp-tree-item cursor-pointer flex items-center gap-1.5 pl-1 pr-2 py-0.5 text-[13px] leading-5"
                        style={isSelected ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}}
                        onMouseEnter={(e) => { if (!isSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }}}
                        onMouseLeave={(e) => { if (!isSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }}}
                    >
                        <span onClick={(e) => { e.stopPropagation(); toggleSidebarCluster && toggleSidebarCluster(cluster.id); }} className="flex-shrink-0 p-0.5 hover:bg-white/10 rounded">
                            {isExpanded
                                ? <Icons.ChevronDown className="w-3 h-3" style={{color: '#728b9a'}} />
                                : <Icons.ChevronRight className="w-3 h-3" style={{color: '#728b9a'}} />
                            }
                        </span>
                        {clusterIcon}
                        <span className="truncate flex-1 font-medium">{cluster.name}</span>
                        {cluster.connected === false && <span className="text-[9px] px-1 py-0 font-medium" style={{background: 'rgba(245,79,71,0.15)', color: '#f54f47'}}>OFFLINE</span>}
                        {hasOfflineNodes && cluster.connected !== false && <span className="text-[9px] px-1 py-0 font-medium" style={{background: 'rgba(239,192,6,0.15)', color: '#efc006'}}>{offlineNodesCount}&#9888;</span>}
                        <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background: clrStatusDot}} />
                    </div>
                );
            }

            return (
                <div
                    onClick={() => setSelectedCluster(cluster)}
                    className={`card-hover cursor-pointer rounded-lg p-2 border transition-all animate-slide-up ${
                        selectedCluster?.id === cluster.id
                            ? 'bg-proxmox-orange/10 border-proxmox-orange/50'
                            : cluster.connected === false
                            ? 'bg-red-500/5 border-red-500/30'
                            : hasOfflineNodes
                            ? 'bg-orange-500/5 border-orange-500/30'
                            : 'bg-proxmox-card border-proxmox-border hover:border-proxmox-orange/30'
                    }`}
                    style={{ animationDelay: `${idx * 30}ms` }}
                >
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColor} ${
                                cluster.connected === false ? 'animate-pulse' : hasOfflineNodes ? 'animate-pulse' : cluster.status === 'running' ? 'status-online' : ''
                            }`} />
                            <div className="min-w-0">
                                <h3 className="font-medium text-sm truncate">{cluster.name}</h3>
                                <p className="text-xs text-gray-500 truncate">{cluster.host}</p>
                            </div>
                        </div>
                        <div className="flex gap-0.5 flex-shrink-0">
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    handleDeleteCluster(cluster.id);
                                }}
                                className="p-1 rounded hover:bg-red-500/10 text-gray-500 hover:text-red-400 transition-colors"
                                title={t('delete')}
                            >
                                <Icons.Trash className="w-3.5 h-3.5" />
                            </button>
                            {isAdmin && (
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        setShowAssignGroup(cluster);
                                    }}
                                    className="p-1 rounded hover:bg-blue-500/10 text-gray-500 hover:text-blue-400 transition-colors"
                                    title={t('assignToGroup')}
                                >
                                    <Icons.FolderInput className="w-3.5 h-3.5" />
                                </button>
                            )}
                        </div>
                    </div>
                    {/* Status Tags */}
                    <div className="flex gap-1 mt-2 flex-wrap">
                        {cluster.connected === false && (
                            <span className="text-[10px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded">Offline</span>
                        )}
                        {hasOfflineNodes && cluster.connected !== false && (
                            <span className="text-[10px] bg-orange-500/10 text-orange-400 px-1.5 py-0.5 rounded animate-pulse">
                                {offlineNodesCount} Node{offlineNodesCount > 1 ? 's' : ''} ⚠
                            </span>
                        )}
                        {cluster.dry_run && (
                            <span className="text-[10px] bg-yellow-500/10 text-yellow-400 px-1.5 py-0.5 rounded">Dry</span>
                        )}
                        {cluster.auto_migrate && (
                            <span className="text-[10px] bg-green-500/10 text-green-400 px-1.5 py-0.5 rounded">Auto</span>
                        )}
                        {!cluster.enabled && (
                            <span className="text-[10px] bg-gray-500/10 text-gray-400 px-1.5 py-0.5 rounded">Paused</span>
                        )}
                    </div>
                </div>
            );
        }

        function PegaProxDashboard() {
            const { t } = useTranslation();
            const { user, sessionId, logout, getAuthHeaders, isAdmin, passwordExpiry } = useAuth();
            const { isCorporate } = useLayout(); // LW: Feb 2026 - corporate layout
            const [clusters, setClusters] = useState([]);
            const [clusterGroups, setClusterGroups] = useState([]); // NS Jan 2026 - for grouping
            const [collapsedGroups, setCollapsedGroups] = useState({}); // Track which groups are collapsed
            const [showGroupManager, setShowGroupManager] = useState(false); // Group management modal
            const [showAssignGroup, setShowAssignGroup] = useState(null); // Cluster to assign to group
            const [selectedGroup, setSelectedGroup] = useState(null); // LW: Feb 2026 - folder overlay
            const [showGroupSettings, setShowGroupSettings] = useState(null); // group settings modal
            const [selectedCluster, setSelectedCluster] = useState(null);
            const [clusterMetrics, setClusterMetrics] = useState({});
            const [allClusterMetrics, setAllClusterMetrics] = useState({}); // LW: metrics cache for overview page
            const [topGuests, setTopGuests] = useState([]); // top vms for overview table
            const [knownNodes, setKnownNodes] = useState({}); // NS: Track all nodes ever seen to show offline ones
            const [clusterResources, setClusterResources] = useState([]);
            const [lastUpdate, setLastUpdate] = useState(null);
            const [migrationLogs, setMigrationLogs] = useState([]);
            const [nodeAlerts, setNodeAlerts] = useState({}); // Track node offline/online alerts
            const [showAddModal, setShowAddModal] = useState(false);
            const [showAddDropdown, setShowAddDropdown] = useState(false);
            const [addClusterType, setAddClusterType] = useState('proxmox');
            const [showCreateVm, setShowCreateVm] = useState(null); // 'qemu' or 'lxc'
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState(null);
            const [toasts, setToasts] = useState([]);
            const [activeTab, setActiveTab] = useState('overview');
            const [resourcesSubTab, setResourcesSubTab] = useState('management'); 
            const [showUserMenu, setShowUserMenu] = useState(false);
            const [showSettings, setShowSettings] = useState(false);
            const [showProfile, setShowProfile] = useState(false);
            const [wsConnected, setWsConnected] = useState(false);
            const wsConnectedRef = useRef(false);  // NS: Ref for health check access
            const [tasks, setTasks] = useState([]);
            const [showUpdateNotification, setShowUpdateNotification] = useState(false); // LW: Show update modal on login
            const [pendingUpdate, setPendingUpdate] = useState(null); // LW: Store update info for notification
            
            // LW: Feb 2026 - Proxmox Backup Server state
            const [pbsServers, setPbsServers] = useState([]);
            const [selectedPBS, setSelectedPBS] = useState(null);
            const [pbsStatus, setPbsStatus] = useState(null);
            const [pbsDatastores, setPbsDatastores] = useState([]);
            const [pbsSnapshots, setPbsSnapshots] = useState([]);
            const [pbsGroups, setPbsGroups] = useState([]);
            const [pbsTasks, setPbsTasks] = useState([]);
            const [pbsJobs, setPbsJobs] = useState({});
            const [pbsActiveTab, setPbsActiveTab] = useState('dashboard');
            const [pbsSelectedStore, setPbsSelectedStore] = useState(null);
            const [showAddPBS, setShowAddPBS] = useState(false);
            const [pbsLoading, setPbsLoading] = useState(false);
            const [editingPBS, setEditingPBS] = useState(null); // null = add mode, object = edit mode
            const [pbsForm, setPbsForm] = useState({ name: '', host: '', port: 8007, user: 'root@pam', password: '', api_token_id: '', api_token_secret: '', fingerprint: '', ssl_verify: false, linked_clusters: [], notes: '' });
            const [pbsTestResult, setPbsTestResult] = useState(null);
            const [pbsTestLoading, setPbsTestLoading] = useState(false);
            const [pbsActionLoading, setPbsActionLoading] = useState({});
            const [pbsPruneForm, setPbsPruneForm] = useState({ keep_last: 3, keep_daily: 7, keep_weekly: 4, keep_monthly: 6, keep_yearly: 1, dry_run: true });
            const [pbsSelectedGroup, setPbsSelectedGroup] = useState(null);
            const [pbsTaskLog, setPbsTaskLog] = useState(null);
            const [pbsNamespaces, setPbsNamespaces] = useState([]);
            const [pbsDisks, setPbsDisks] = useState([]);
            const [pbsRemotes, setPbsRemotes] = useState([]);
            const [pbsNotifications, setPbsNotifications] = useState({ targets: [], matchers: [] });
            const [pbsTrafficControl, setPbsTrafficControl] = useState([]);
            const [pbsSyslog, setPbsSyslog] = useState([]);
            const [pbsCatalog, setPbsCatalog] = useState([]);
            const [pbsCatalogPath, setPbsCatalogPath] = useState('/');
            const [pbsCatalogSnapshot, setPbsCatalogSnapshot] = useState(null);
            const [showPbsFileBrowser, setShowPbsFileBrowser] = useState(false);
            const [pbsEditingNotes, setPbsEditingNotes] = useState(null);
            const [pbsNotesText, setPbsNotesText] = useState('');
            
            // VMware Server state
            const [vmwareServers, setVmwareServers] = useState([]);
            const [selectedVMware, setSelectedVMware] = useState(null);
            const [vmwareVms, setVmwareVms] = useState([]);
            const [vmwareHosts, setVmwareHosts] = useState([]);
            const [vmwareDatastores, setVmwareDatastores] = useState([]);
            const [vmwareNetworks, setVmwareNetworks] = useState([]);
            const [vmwareLoading, setVmwareLoading] = useState(false);
            const [vmwareActiveTab, setVmwareActiveTab] = useState('vms');
            const [vmwareSelectedVm, setVmwareSelectedVm] = useState(null);
            const [vmwareVmDetail, setVmwareVmDetail] = useState(null);
            const [vmwareActionLoading, setVmwareActionLoading] = useState({});
            const [showAddVMware, setShowAddVMware] = useState(false);
            const [vmwareForm, setVmwareForm] = useState({ name: '', host: '', port: 443, username: 'root', password: '', ssl_verify: false, notes: '' });
            const [vmwareTestResult, setVmwareTestResult] = useState(null);
            const [vmwareTestLoading, setVmwareTestLoading] = useState(false);
            const [vmwareVmTab, setVmwareVmTab] = useState('overview');
            const [showVmwareClone, setShowVmwareClone] = useState(false);
            const [vmwareCloneName, setVmwareCloneName] = useState('');
            const [showVmwareDelete, setShowVmwareDelete] = useState(false);
            const [vmwareConfigEdit, setVmwareConfigEdit] = useState({ cpu: '', memory: '', notes: '', cpu_hot_add: false, memory_hot_add: false });
            const [vmwareConfigSaving, setVmwareConfigSaving] = useState(false);
            const [showVmwareMigrate, setShowVmwareMigrate] = useState(false);
            const [vmwareMigrationPlan, setVmwareMigrationPlan] = useState(null);
            const [vmwareMigrations, setVmwareMigrations] = useState([]);
            const [vmwareMigrateForm, setVmwareMigrateForm] = useState({target_cluster:'',target_node:'',target_storage:'',esxi_password:'',network_bridge:'vmbr0',start_after:true,remove_source:false,transfer_mode:'auto'});
            const [vmwareMigrateLoading, setVmwareMigrateLoading] = useState(false);
            const [vmwareConsoleUrl, setVmwareConsoleUrl] = useState(null);
            const [showVmwareConsole, setShowVmwareConsole] = useState(false);
            const [vmwareHealthData, setVmwareHealthData] = useState(null);
            const [vmwareRenameName, setVmwareRenameName] = useState('');
            const [vmwareEvents, setVmwareEvents] = useState([]);
            const [vmwareEventsLoading, setVmwareEventsLoading] = useState(false);
            const [vmwareSelectedDs, setVmwareSelectedDs] = useState(null);
            const [vmwareDsDetail, setVmwareDsDetail] = useState(null);
            const [vmwareClusters, setVmwareClusters] = useState([]);
            const [vmwareConnectionOk, setVmwareConnectionOk] = useState(true);
            const [vmwareSelectedMigration, setVmwareSelectedMigration] = useState(null);
            const [vmwareMigrationDetail, setVmwareMigrationDetail] = useState(null);
            const [showVmwareRename, setShowVmwareRename] = useState(false);
            const [vmwareSearch, setVmwareSearch] = useState('');
            const [vmwareFilter, setVmwareFilter] = useState('all'); // all, running, stopped
            const [vmwareSortBy, setVmwareSortBy] = useState('name');
            const [editingVMware, setEditingVMware] = useState(null);

            // LW: Feb 2026 - corporate sidebar inventory tree state
            const [expandedSidebarNodes, setExpandedSidebarNodes] = useState({});
            const [selectedSidebarVm, setSelectedSidebarVm] = useState(null);
            const [selectedSidebarNode, setSelectedSidebarNode] = useState(null); // LW: Feb 2026 - corporate node detail
            const [expandedVmwareSidebarHosts, setExpandedVmwareSidebarHosts] = useState({});
            // LW: Feb 2026 - multi-cluster sidebar expansion (independent of selectedCluster)
            const [expandedSidebarClusters, setExpandedSidebarClusters] = useState({});
            const [sidebarClusterData, setSidebarClusterData] = useState({}); // { clusterId: { metrics: {}, resources: [] } }

            // LW: Feb 2026 - clear VM/Node selection on cluster/tab change, auto-expand selected
            useEffect(() => { setSelectedSidebarVm(null); setSelectedSidebarNode(null); if (selectedCluster && isCorporate) setExpandedSidebarClusters(prev => ({ ...prev, [selectedCluster.id]: true })); }, [selectedCluster?.id]);
            useEffect(() => { if (activeTab !== 'resources') setSelectedSidebarVm(null); if (activeTab !== 'overview') setSelectedSidebarNode(null); }, [activeTab]);

            // LW: Feb 2026 - keep selectedSidebarVm fresh with latest metrics (preserve _clusterId)
            useEffect(() => {
                if (!selectedSidebarVm || !clusterResources) return;
                // Only update if the VM is in the currently selected cluster
                if (selectedSidebarVm._clusterId && selectedSidebarVm._clusterId !== selectedCluster?.id) return;
                const updated = clusterResources.find(r => r.vmid === selectedSidebarVm.vmid && r.type === selectedSidebarVm.type);
                if (updated && (updated.cpu !== selectedSidebarVm.cpu || updated.mem !== selectedSidebarVm.mem || updated.status !== selectedSidebarVm.status)) {
                    setSelectedSidebarVm({...updated, _clusterId: selectedSidebarVm._clusterId});
                }
            }, [clusterResources]);

            // NS: Duration formatter for PBS tasks (needs to be in this scope)
            const pbsFormatDuration = (start, end) => {
                if (!start) return '-';
                const endTime = end || Math.floor(Date.now() / 1000);
                const duration = endTime - start;
                const hours = Math.floor(duration / 3600);
                const mins = Math.floor((duration % 3600) / 60);
                const secs = duration % 60;
                if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
                if (mins > 0) return `${mins}m ${secs}s`;
                return `${secs}s`;
            };
            
            // NS: Task update timestamp to prevent race conditions
            // This was causing tasks to "jump back" when SSE and polling raced
            const taskUpdateTimestamp = useRef(0);
            const initialTaskFetchPending = useRef(true);  // NS: skip stale check on initial load
            const [showTaskBar, setShowTaskBar] = useState(true);  // localStorage.getItem('showTaskBar') !== 'false'
            const [actionLoading, setActionLoading] = useState({});
            const [warningBannerDismissed, setWarningBannerDismissed] = useState(false);
            // LW: Feb 2026 - corporate sidebar resize
            const [sidebarWidth, setSidebarWidth] = useState(() => parseInt(localStorage.getItem('corp-sidebar-w')) || 224);
            const sidebarResizing = useRef(false);
            const wsRef = useRef(null);
            const retryCount = useRef(0);  // unused but might need later
            const selectedClusterRef = useRef(null);  // for ws callback, dont ask
            const selectedVMwareRef = useRef(null);  // for SSE VMware events
            const vmwareSelectedVmRef = useRef(null);  // for SSE VMware VM detail
            const vmwareSelectedMigrationRef = useRef(null);  // for SSE migration updates
            
            // NS: Keep wsConnectedRef in sync with state for health check
            useEffect(() => {
                wsConnectedRef.current = wsConnected;
            }, [wsConnected]);
            
            const [connectionError, setConnectionError] = useState(null);
            const [lastRefresh, setLastRefresh] = useState(null);  // not used yet
            
            // HA Settings state
            // NS: these defaults should probably come from backend
            const [haSettings, setHaSettings] = useState({
                quorum_enabled: true,
                quorum_hosts: '',
                quorum_gateway: '',
                quorum_required_votes: 2,
                self_fence_enabled: true,
                verify_network: true,
                recovery_delay: 30,  // seconds
                failure_threshold: 3,
                // 2-Node Cluster Mode - NS Jan 2026
                two_node_mode: false,
                // Storage-based Split-Brain Protection - NS Jan 2026
                storage_heartbeat_enabled: false,
                storage_heartbeat_path: '',
                storage_heartbeat_timeout: 30,
                poison_pill_enabled: true,
                strict_fencing: false,
            });
            const [haStatus, setHaStatus] = useState(null);
            const [showHaSettings, setShowHaSettings] = useState(false);
            
            // NS: Global Search state - Jan 2026
            const [globalSearchQuery, setGlobalSearchQuery] = useState('');
            const [globalSearchResults, setGlobalSearchResults] = useState(null);
            const [globalSearchLoading, setGlobalSearchLoading] = useState(false);
            const [showGlobalSearch, setShowGlobalSearch] = useState(false);
            const [globalSearchIndex, setGlobalSearchIndex] = useState(0);
            const globalSearchRef = React.useRef(null);
            const globalSearchTimerRef = React.useRef(null);
            const [highlightedVm, setHighlightedVm] = useState(null);  // {vmid, node} - for scrolling to VM in table
            
            // NS: User Favorites state
            const [favorites, setFavorites] = useState({ vms: [], nodes: [], clusters: [] });
            const [datacenterSummary, setDatacenterSummary] = useState(null);
            
            // NS: VM Tags state - Jan 2026
            const [vmTags, setVmTags] = useState({});  // cluster -> vmid -> tags
            const [clusterTags, setClusterTags] = useState([]);  // available tags in current cluster
            const [showTagEditor, setShowTagEditor] = useState(null);  // {clusterId, vmid, vmName}
            const [newTagName, setNewTagName] = useState('');
            
            
            const [snapshotFilterDate, setSnapshotFilterDate] = useState('');
            const [globalSnapshots, setGlobalSnapshots] = useState([]);
            const [snapshotSortBy, setSnapshotSortBy] = useState('age'); // vmid, vm_name, node, snapshot_name, snapshot_date, age
            const [snapshotSortDir, setSnapshotSortDir] = useState('desc');
            
            // NS: Scheduled Actions state
            const [schedules, setSchedules] = useState([]);
            const [showScheduleModal, setShowScheduleModal] = useState(false);
            const [editingSchedule, setEditingSchedule] = useState(null);
            
            // NS: Automation Tab state - Jan 2026
            const [automationSubTab, setAutomationSubTab] = useState('schedules');
            const [clusterAlerts, setClusterAlerts] = useState([]);
            const [showAlertModal, setShowAlertModal] = useState(false);
            const [clusterAffinityRules, setClusterAffinityRules] = useState([]);
            const [showAffinityModal, setShowAffinityModal] = useState(false);
            
            // Custom Scripts state - MK Jan 2026
            const [customScripts, setCustomScripts] = useState([]);
            const [showScriptModal, setShowScriptModal] = useState(false);
            const [editingScript, setEditingScript] = useState(null);
            // Script execution state - MK Jan 2026
            const [showScriptRunModal, setShowScriptRunModal] = useState(null); // script to run
            const [scriptRunPassword, setScriptRunPassword] = useState('');
            const [scriptRunning, setScriptRunning] = useState(false);
            const [scriptOutput, setScriptOutput] = useState(null); // {name, output, results}
            
            // NS: Reports/Analytics state
            const [reportData, setReportData] = useState(null);
            const [reportPeriod, setReportPeriod] = useState('day');
            const [reportLoading, setReportLoading] = useState(false);
            const [topVms, setTopVms] = useState([]);
            
            // Auth fetch helper - simple version without timeout abort
            // TODO: add retry logic? - LW
            // TODO: maybe use axios instead? -ns
            const authFetch = async (url, opts = {}) => {
                try {
                    const res = await fetch(url, {
                        ...opts,
                        credentials: 'include',
                        headers: { ...opts.headers, ...getAuthHeaders() }
                    });
                    setConnectionError(null);
                    return res;
                } catch (err) {
                    console.error('authFetch err:', err);
                    // setConnectionError('Network error');  // too annoying
                    return null;
                }
            };
            
            // Keep ref in sync with state
            // NS: this is a hack for the websocket callback closure issue
            // NS: Reset ref IMMEDIATELY when cluster changes to prevent cross-cluster data leaks
            useEffect(() => {
                // First update the ref synchronously
                selectedClusterRef.current = selectedCluster;
            }, [selectedCluster]);
            
            useEffect(() => { selectedVMwareRef.current = selectedVMware; }, [selectedVMware]);
            useEffect(() => { vmwareSelectedVmRef.current = vmwareSelectedVm; }, [vmwareSelectedVm]);
            useEffect(() => { vmwareSelectedMigrationRef.current = vmwareSelectedMigration; }, [vmwareSelectedMigration]);

            const addToast = (message, type = 'success') => {
                const id = Date.now();
                setToasts(prev => [...prev, { id, message, type }]);
                // auto remove after 5 seconds
                setTimeout(() => {
                    setToasts(prev => prev.filter(t => t.id !== id));
                }, 5000);
            };

            const removeToast = (id) => {
                setToasts(prev => prev.filter(toast => toast.id !== id));
            };

            // LW: Feb 2026 - corporate sidebar resize handlers
            const handleSidebarResizeStart = (e) => {
                e.preventDefault();
                sidebarResizing.current = true;
                const startX = e.clientX;
                const startW = sidebarWidth;
                let lastW = startW;
                const onMove = (ev) => {
                    if (!sidebarResizing.current) return;
                    lastW = Math.max(150, Math.min(450, startW + ev.clientX - startX));
                    setSidebarWidth(lastW);
                };
                const onUp = () => {
                    sidebarResizing.current = false;
                    localStorage.setItem('corp-sidebar-w', String(lastW));
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                };
                document.body.style.cursor = 'col-resize';
                document.body.style.userSelect = 'none';
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            };

            // LW: Feb 2026 - task tracking stubs (used by VM actions)
            const addRecentTask = () => Date.now();
            const updateRecentTask = () => {};

            // LW: Feb 2026 - corporate inline inventory tree: nodes + VMs flat under cluster
            const renderInlineNodeTree = (clusterId) => {
                if (!isCorporate || !expandedSidebarClusters[clusterId]) return null;

                // LW: use selectedCluster data or cached sidebar data
                const isSelected = selectedCluster && selectedCluster.id === clusterId;
                const cMetrics = isSelected ? clusterMetrics : (sidebarClusterData[clusterId]?.metrics || {});
                const cResources = isSelected ? clusterResources : (sidebarClusterData[clusterId]?.resources || []);

                // LW: merge live nodes + offline from knownNodes + nodeAlerts
                const allNodes = {};
                Object.entries(cMetrics).forEach(([name, metrics]) => {
                    if (name === 'error' || name === 'offline') return;
                    allNodes[name] = { name, metrics, online: metrics.status !== 'offline' };
                });
                if (isSelected) {
                    Object.entries(knownNodes).forEach(([name, data]) => {
                        if (!allNodes[name] && data.status === 'offline') {
                            allNodes[name] = { name, metrics: null, online: false };
                        }
                    });
                }
                Object.entries(nodeAlerts).forEach(([name, alert]) => {
                    if (!allNodes[name] && alert.cluster_id === clusterId && alert.status === 'offline') {
                        allNodes[name] = { name, metrics: null, online: false };
                    }
                });

                const sortedNodes = Object.values(allNodes).sort((a, b) => a.name.localeCompare(b.name));
                // LW: all VMs/CTs across all nodes, sorted alphabetically
                const allVms = (cResources || [])
                    .filter(r => r.type === 'qemu' || r.type === 'lxc')
                    .sort((a, b) => (a.name || '').localeCompare(b.name || ''));

                if (sortedNodes.length === 0 && allVms.length === 0) return null;

                // LW: keyboard nav helper, all items in one flat list
                const treeNavDown = (e) => {
                    e.preventDefault();
                    const all = Array.from(e.currentTarget.closest('.corp-inline-tree').querySelectorAll('[tabindex="0"]'));
                    const idx = all.indexOf(e.currentTarget);
                    if (idx >= 0 && idx < all.length - 1) all[idx + 1].focus();
                };
                const treeNavUp = (e) => {
                    e.preventDefault();
                    const all = Array.from(e.currentTarget.closest('.corp-inline-tree').querySelectorAll('[tabindex="0"]'));
                    const idx = all.indexOf(e.currentTarget);
                    if (idx > 0) all[idx - 1].focus();
                };

                return (
                    <div className="ml-5 corp-inline-tree">
                        {/* Nodes first */}
                        {sortedNodes.map(({ name: nodeName, metrics: nodeMetrics, online: nodeOnline }) => {
                            const isMaint = nodeMetrics?.maintenance_mode;
                            const isUpdating = nodeMetrics?.is_updating;
                            const statusSuffix = isMaint ? ` (${t('maintenance')})` : isUpdating ? ` (${t('updating')})` : !nodeOnline ? ' (Offline)' : '';
                            const isNodeSelected = selectedSidebarNode?.name === nodeName && selectedSidebarNode?.clusterId === clusterId;
                            return (
                                <div
                                    key={`node-${nodeName}`}
                                    className="corp-tree-child flex items-center gap-1.5 pl-1 pr-2 py-0.5 text-[13px] leading-5 cursor-pointer"
                                    tabIndex={0}
                                    onClick={() => { setSelectedSidebarNode({ name: nodeName, clusterId }); setSelectedSidebarVm(null); setActiveTab('overview'); }}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') { e.preventDefault(); setSelectedSidebarNode({ name: nodeName, clusterId }); setSelectedSidebarVm(null); setActiveTab('overview'); }
                                        else if (e.key === 'ArrowDown') treeNavDown(e);
                                        else if (e.key === 'ArrowUp') treeNavUp(e);
                                    }}
                                    style={isNodeSelected ? {background: '#324f61', color: '#e9ecef'} : {color: nodeOnline ? '#adbbc4' : '#728b9a'}}
                                    onMouseEnter={(e) => { if (!isNodeSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }}}
                                    onMouseLeave={(e) => { if (!isNodeSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = nodeOnline ? '#adbbc4' : '#728b9a'; }}}
                                >
                                    {isMaint ? (
                                        <Icons.Wrench className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#efc006'}} />
                                    ) : isUpdating ? (
                                        <Icons.Download className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                    ) : !nodeOnline ? (
                                        <Icons.Server className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#f54f47'}} />
                                    ) : (
                                        <Icons.Server className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                    )}
                                    <span className="truncate flex-1" style={{opacity: nodeOnline ? 1 : 0.5}}>{nodeName}{statusSuffix}</span>
                                </div>
                            );
                        })}
                        {/* Then VMs/CTs at same level */}
                        {allVms.map(vm => {
                            const vmRunning = vm.status === 'running';
                            const isVmSelected = selectedSidebarVm?.vmid === vm.vmid && selectedSidebarVm?._clusterId === clusterId;
                            return (
                                <div
                                    key={`vm-${clusterId}-${vm.vmid}`}
                                    tabIndex={0}
                                    onClick={() => { setSelectedSidebarVm({...vm, _clusterId: clusterId}); setSelectedSidebarNode(null); setActiveTab('resources'); setResourcesSubTab('management'); }}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') { e.preventDefault(); setSelectedSidebarVm({...vm, _clusterId: clusterId}); setSelectedSidebarNode(null); setActiveTab('resources'); setResourcesSubTab('management'); }
                                        else if (e.key === 'ArrowDown') treeNavDown(e);
                                        else if (e.key === 'ArrowUp') treeNavUp(e);
                                    }}
                                    className="corp-tree-child flex items-center gap-1.5 pl-1 pr-2 py-0.5 text-[13px] leading-5 cursor-pointer"
                                    style={isVmSelected ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}}
                                    onMouseEnter={(e) => { if (!isVmSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }}}
                                    onMouseLeave={(e) => { if (!isVmSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }}}
                                >
                                    <span className="relative flex-shrink-0" style={{width: '14px', height: '14px'}}>
                                        {vm.type === 'lxc'
                                            ? <Icons.Box className="w-3.5 h-3.5" style={{color: vmRunning ? '#49afd9' : '#728b9a'}} />
                                            : <Icons.Monitor className="w-3.5 h-3.5" style={{color: vmRunning ? '#60b515' : '#728b9a'}} />
                                        }
                                        {vmRunning && <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full" style={{background: vm.type === 'lxc' ? '#49afd9' : '#60b515'}} />}
                                    </span>
                                    <span className="truncate flex-1">{vm.name || `${vm.type === 'lxc' ? 'CT' : 'VM'} ${vm.vmid}`}</span>
                                </div>
                            );
                        })}
                    </div>
                );
            };

            // NS: Global Search function - Jan 2026
            const performGlobalSearch = async (query) => {
                if (!query || query.length < 2) {
                    setGlobalSearchResults(null);
                    return;
                }
                
                setGlobalSearchLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/global/search?q=${encodeURIComponent(query)}`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setGlobalSearchResults(data);
                        setGlobalSearchIndex(0);
                    }
                } catch (err) {
                    console.error('Global search error:', err);
                }
                setGlobalSearchLoading(false);
            };
            
            // MK: debounce so we dont spam the API on every keystroke
            // claude helped rewrite the whole search dropdown, chatgpt did the keyboard nav
            const debouncedSearch = (query) => {
                if (globalSearchTimerRef.current) clearTimeout(globalSearchTimerRef.current);
                if (!query || query.length < 2) {
                    setGlobalSearchResults(null);
                    return;
                }
                globalSearchTimerRef.current = setTimeout(() => performGlobalSearch(query), 300);
            };
            
            // NS: ctrl+k shortcut like every other app these days
            React.useEffect(() => {
                const handleKeyDown = (e) => {
                    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                        e.preventDefault();
                        if (globalSearchRef.current) {
                            globalSearchRef.current.focus();
                            setShowGlobalSearch(true);
                        }
                    }
                };
                document.addEventListener('keydown', handleKeyDown);
                return () => document.removeEventListener('keydown', handleKeyDown);
            }, []);
            
            // LW: jump to VM in the right cluster when clicking a search result
            const navigateToResult = (result) => {
                const cluster = clusters.find(c => c.id === result.cluster_id);
                if (cluster) {
                    setSelectedCluster(cluster);
                    if (result.type === 'vm' || result.type === 'ct' || result.type === 'qemu' || result.type === 'lxc') {
                        setTimeout(() => {
                            setHighlightedVm({ vmid: result.vmid, node: result.node });
                            setTimeout(() => setHighlightedVm(null), 3000);
                        }, 300);
                    }
                }
                setShowGlobalSearch(false);
                setGlobalSearchQuery('');
            };
            
            // NS: Load user favorites
            const loadFavorites = async () => {
                try {
                    const response = await authFetch(`${API_URL}/user/favorites`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setFavorites(data);
                    }
                } catch (err) {
                    console.error('Load favorites error:', err);
                }
            };
            
            // NS: Toggle favorite
            const toggleFavorite = async (type, clusterId, vmid = null, vmType = null, nodeName = null) => {
                const currentFavs = favorites[type + 's'] || [];
                let isFavorite = false;
                
                if (type === 'vm') {
                    isFavorite = currentFavs.some(f => f.cluster_id === clusterId && f.vmid === vmid);
                } else if (type === 'node') {
                    isFavorite = currentFavs.some(f => f.cluster_id === clusterId && f.node === nodeName);
                } else if (type === 'cluster') {
                    isFavorite = currentFavs.includes(clusterId);
                }
                
                const action = isFavorite ? 'remove' : 'add';
                
                try {
                    const body = { action, type, cluster_id: clusterId };
                    if (vmid) body.vmid = vmid;
                    if (vmType) body.vm_type = vmType;
                    if (nodeName) body.node = nodeName;
                    
                    const response = await authFetch(`${API_URL}/user/favorites`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                    
                    if (response && response.ok) {
                        const data = await response.json();
                        setFavorites(data.favorites);
                    }
                } catch (err) {
                    console.error('Toggle favorite error:', err);
                }
            };
            
            // NS: Check if item is favorite
            const isFavorite = (type, clusterId, vmid = null, nodeName = null) => {
                if (type === 'vm') {
                    return (favorites.vms || []).some(f => f.cluster_id === clusterId && f.vmid === vmid);
                } else if (type === 'node') {
                    return (favorites.nodes || []).some(f => f.cluster_id === clusterId && f.node === nodeName);
                } else if (type === 'cluster') {
                    return (favorites.clusters || []).includes(clusterId);
                }
                return false;
            };
            
            // NS: Load datacenter summary
            const loadDatacenterSummary = async () => {
                try {
                    const response = await authFetch(`${API_URL}/global/summary`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setDatacenterSummary(data);
                    }
                } catch (err) {
                    console.error('Datacenter summary error:', err);
                }
            };
            
            // ============================================
            // VM Tags Functions - NS Jan 2026
            // ============================================
            
            const loadClusterTags = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/tags`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setClusterTags(data);
                    }
                } catch (err) {
                    console.error('Failed to load cluster tags:', err);
                }
            };
            
            const loadVmTags = async (clusterId, vmid) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vmid}/tags`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setVmTags(prev => ({
                            ...prev,
                            [clusterId]: { ...(prev[clusterId] || {}), [vmid]: data }
                        }));
                    }
                } catch (err) {
                    console.error('Failed to load VM tags:', err);
                }
            };
            
            const addTagToVm = async (clusterId, vmid, tagName, color = null) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vmid}/tags`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ tag: tagName, color })
                    });
                    if (response && response.ok) {
                        const data = await response.json();
                        setVmTags(prev => ({
                            ...prev,
                            [clusterId]: { ...(prev[clusterId] || {}), [vmid]: data.tags }
                        }));
                        loadClusterTags(clusterId);
                        return true;
                    }
                } catch (err) {
                    console.error('Failed to add tag:', err);
                }
                return false;
            };
            
            const removeTagFromVm = async (clusterId, vmid, tagName) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vmid}/tags/${encodeURIComponent(tagName)}`, {
                        method: 'DELETE'
                    });
                    if (response && response.ok) {
                        // Remove from local state
                        setVmTags(prev => {
                            const clusterTags = prev[clusterId] || {};
                            const vmTagList = (clusterTags[vmid] || []).filter(
                                t => (t.name || t) !== tagName
                            );
                            return {
                                ...prev,
                                [clusterId]: { ...clusterTags, [vmid]: vmTagList }
                            };
                        });
                    }
                } catch (err) {
                    console.error('Failed to remove tag:', err);
                }
            };
            
            // Get tags for a VM (from local state)
            const getVmTags = (clusterId, vmid) => {
                return vmTags[clusterId]?.[vmid] || [];
            };
            
            // ============================================
              
            // LW: Added cluster filter and sorting
            // ============================================
            
            const fetchGlobalSnapshots = async (clusterId = null, filterDate = null) => {
                try {
                    const body = {};
                    if (clusterId) body.cluster_id = clusterId;
                    if (filterDate) body.date = filterDate;
                    
                    const res = await authFetch(`${API_URL}/snapshots/overview`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                    if (res && res.ok) {
                        const data = await res.json();
                        setGlobalSnapshots(data.snapshots ?? data ?? []);
                    } else {
                        setGlobalSnapshots([]);
                    }
                } catch (err) {
                    console.error('Snapshot fetch failed:', err);
                    setGlobalSnapshots([]);
                }
            };
            
            const applySnapshotFilter = async (clusterId) => {
                await fetchGlobalSnapshots(clusterId, snapshotFilterDate || null);
            };
            
            const deleteGlobalSnapshot = async (snap, clusterId) => {
                if (!window.confirm(`Delete snapshot "${snap.snapshot_name}" from VM ${snap.vmid}?`)) {
                    return;
                }
                try {
                    await authFetch(`${API_URL}/snapshots/delete`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ snapshots: [snap] })
                    });
                    addToast('Snapshot deleted', 'success');
                    await fetchGlobalSnapshots(clusterId, snapshotFilterDate || null);
                } catch (err) {
                    console.error('Snapshot delete failed:', err);
                    addToast('Failed to delete snapshot', 'error')
                }
            };
            
            
            const sortedSnapshots = useMemo(() => {
                if (!globalSnapshots || globalSnapshots.length === 0) return [];
                
                return [...globalSnapshots].sort((a, b) => {
                    let aVal = a[snapshotSortBy];
                    let bVal = b[snapshotSortBy];
                    
                    // Handle age specially - extract number
                    if (snapshotSortBy === 'age') {
                        const extractNum = (val) => {
                            if (!val) return 0;
                            const match = val.match(/(\d+)/);
                            return match ? parseInt(match[1]) : 0;
                        };
                        aVal = extractNum(aVal);
                        bVal = extractNum(bVal);
                    }
                    
                    // Handle numeric fields
                    if (snapshotSortBy === 'vmid') {
                        aVal = parseInt(aVal) || 0;
                        bVal = parseInt(bVal) || 0;
                    }
                    
                    if (aVal < bVal) return snapshotSortDir === 'asc' ? -1 : 1;
                    if (aVal > bVal) return snapshotSortDir === 'asc' ? 1 : -1;
                    return 0;
                });
            }, [globalSnapshots, snapshotSortBy, snapshotSortDir]);
            
            const toggleSnapshotSort = (field) => {
                if (snapshotSortBy === field) {
                    setSnapshotSortDir(snapshotSortDir === 'asc' ? 'desc' : 'asc');
                } else {
                    setSnapshotSortBy(field);
                    setSnapshotSortDir('asc');
                }
            };
            
            // ============================================
            // Scheduled Actions Functions - MK Jan 2026  
            // ============================================
            
            const loadSchedules = async () => {
                try {
                    const response = await authFetch(`${API_URL}/schedules`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setSchedules(data);
                    }
                } catch (err) {
                    console.error('Failed to load schedules:', err);
                }
            };
            
            const createSchedule = async (scheduleData) => {
                try {
                    const response = await authFetch(`${API_URL}/schedules`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(scheduleData)
                    });
                    if (response && response.ok) {
                        await loadSchedules();
                        addToast(t('scheduleCreated') || 'Schedule created', 'success');
                        return true;
                    } else {
                        const err = await response.json();
                        addToast(err.error || 'Failed to create schedule', 'error');
                    }
                } catch (err) {
                    console.error('Failed to create schedule:', err);
                    addToast('Failed to create schedule', 'error');
                }
                return false;
            };
            
            const deleteSchedule = async (scheduleId) => {
                try {
                    const response = await authFetch(`${API_URL}/schedules/${scheduleId}`, {
                        method: 'DELETE'
                    });
                    if (response && response.ok) {
                        setSchedules(prev => prev.filter(s => s.id !== scheduleId));
                        addToast(t('scheduleDeleted') || 'Schedule deleted', 'success');
                    }
                } catch (err) {
                    console.error('Failed to delete schedule:', err);
                }
            };
            
            const toggleScheduleEnabled = async (scheduleId, enabled) => {
                try {
                    const response = await authFetch(`${API_URL}/schedules/${scheduleId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled })
                    });
                    if (response && response.ok) {
                        setSchedules(prev => prev.map(s => 
                            s.id === scheduleId ? { ...s, enabled } : s
                        ));
                    }
                } catch (err) {
                    console.error('Failed to toggle schedule:', err);
                }
            };
            
            // ============================================
            // Cluster Alerts Functions - NS Jan 2026
            // ============================================
            
            const loadClusterAlerts = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/alerts`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setClusterAlerts(data.alerts || []);
                    } else {
                        setClusterAlerts([]);
                    }
                } catch (err) {
                    console.error('Failed to load cluster alerts:', err);
                    setClusterAlerts([]);
                }
            };
            
            const createClusterAlert = async (alertData) => {
                if (!selectedCluster?.id) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/alerts`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(alertData)
                    });
                    if (response && response.ok) {
                        setShowAlertModal(false);
                        loadClusterAlerts(selectedCluster.id);
                        addToast(t('alertCreated') || 'Alert created', 'success');
                    }
                } catch (err) {
                    console.error('Failed to create alert:', err);
                }
            };
            
            const deleteClusterAlert = async (alertId) => {
                if (!selectedCluster?.id) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/alerts/${alertId}`, {
                        method: 'DELETE'
                    });
                    if (response && response.ok) {
                        setClusterAlerts(prev => prev.filter(a => a.id !== alertId));
                    }
                } catch (err) {
                    console.error('Failed to delete alert:', err);
                }
            };
            
            const toggleAlertEnabled = async (alertId, enabled) => {
                if (!selectedCluster?.id) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/alerts/${alertId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled })
                    });
                    if (response && response.ok) {
                        setClusterAlerts(prev => prev.map(a => 
                            a.id === alertId ? { ...a, enabled } : a
                        ));
                    }
                } catch (err) {
                    console.error('Failed to toggle alert:', err);
                }
            };
            
            // ============================================
            // Cluster Affinity Rules Functions - NS Jan 2026
            // ============================================
            
            const loadClusterAffinityRules = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/affinity-rules`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setClusterAffinityRules(data.rules || []);
                    } else {
                        setClusterAffinityRules([]);
                    }
                } catch (err) {
                    console.error('Failed to load affinity rules:', err);
                    setClusterAffinityRules([]);
                }
            };
            
            const createClusterAffinityRule = async (ruleData) => {
                if (!selectedCluster?.id) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/affinity-rules`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(ruleData)
                    });
                    if (response && response.ok) {
                        setShowAffinityModal(false);
                        loadClusterAffinityRules(selectedCluster.id);
                        addToast(t('ruleCreated') || 'Rule created', 'success');
                    }
                } catch (err) {
                    console.error('Failed to create affinity rule:', err);
                }
            };
            
            const deleteClusterAffinityRule = async (ruleId) => {
                if (!selectedCluster?.id) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/affinity-rules/${ruleId}`, {
                        method: 'DELETE'
                    });
                    if (response && response.ok) {
                        setClusterAffinityRules(prev => prev.filter(r => r.id !== ruleId));
                    }
                } catch (err) {
                    console.error('Failed to delete affinity rule:', err);
                }
            };
            
            // ============================================
            // Reports/Analytics Functions - NS Jan 2026
            // Now cluster-based, not global
            // ============================================
            
            const loadReportSummary = async (period = 'day', clusterId = null) => {
                const clId = clusterId || selectedCluster?.id;
                if (!clId) return;
                
                setReportLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clId}/reports/summary?period=${period}`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setReportData(data);
                    } else {
                        setReportData(null);
                    }
                } catch (err) {
                    console.error('Failed to load report:', err);
                    setReportData(null);
                }
                setReportLoading(false);
            };
            
            const loadTopVms = async (metric = 'cpu', limit = 10, clusterId = null) => {
                const clId = clusterId || selectedCluster?.id;
                if (!clId) return;
                
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clId}/reports/top-vms?metric=${metric}&limit=${limit}`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setTopVms(data);
                    } else {
                        setTopVms([]);
                    }
                } catch (err) {
                    console.error('Failed to load top VMs:', err);
                    setTopVms([]);
                }
            };
            
            // Load favorites and summary on mount
            useEffect(() => {
                if (user) {
                    loadFavorites();
                    loadDatacenterSummary();
                    loadSchedules();  // Also load schedules
                }
            }, [user]);
            
            // Load reports when tab changes to reports OR cluster changes
            useEffect(() => {
                if (activeTab === 'reports' && selectedCluster?.id) {
                    loadReportSummary(reportPeriod, selectedCluster.id);
                    loadTopVms('cpu', 10, selectedCluster.id);
                }
            }, [activeTab, reportPeriod, selectedCluster?.id]);
            
            // Load automation data when tab changes to automation OR cluster changes
            useEffect(() => {
                if (activeTab === 'automation' && selectedCluster?.id) {
                    loadClusterTags(selectedCluster.id);
                    loadClusterAlerts(selectedCluster.id);
                    loadClusterAffinityRules(selectedCluster.id);
                    loadCustomScripts(selectedCluster.id);
                }
            }, [activeTab, selectedCluster?.id]);
            
            // Load custom scripts
            const loadCustomScripts = async (clusterId) => {
                if (!clusterId) return;
                console.log('[Scripts] Loading scripts for cluster:', clusterId);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/scripts`);
                    console.log('[Scripts] Response:', res?.status, res?.ok);
                    if (res && res.ok) {
                        const data = await res.json();
                        console.log('[Scripts] Loaded:', data?.length, 'scripts', data);
                        setCustomScripts(data || []);
                    } else {
                        const errorData = await res.json().catch(() => ({}));
                        console.error('[Scripts] Failed to load, status:', res?.status, 'error:', errorData);
                        setCustomScripts([]);
                    }
                } catch (e) {
                    console.error('[Scripts] Error loading scripts:', e);
                    setCustomScripts([]);
                }
            };

            // HA Settings functions
            const fetchHAStatus = async (clusterId) => {
                if (!clusterId) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/ha/status`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setHaStatus(data);
                        setHaSettings({
                            quorum_enabled: data.split_brain_prevention?.quorum_enabled ?? true,
                            quorum_hosts: (data.split_brain_prevention?.quorum_hosts || []).join(', '),
                            quorum_gateway: data.split_brain_prevention?.quorum_gateway || '',
                            quorum_required_votes: data.split_brain_prevention?.quorum_required_votes || 2,
                            self_fence_enabled: data.split_brain_prevention?.self_fence_enabled ?? true,
                            verify_network: data.split_brain_prevention?.verify_network ?? true,
                            recovery_delay: data.split_brain_prevention?.recovery_delay || 30,
                            failure_threshold: data.failure_threshold || 3,
                            // 2-Node Mode
                            two_node_mode: data.split_brain_prevention?.two_node_mode ?? false,
                            // Storage-based Split-Brain Protection - NS Jan 2026
                            storage_heartbeat_enabled: data.split_brain_prevention?.storage_heartbeat_enabled ?? false,
                            storage_heartbeat_path: data.split_brain_prevention?.storage_heartbeat_path || '',
                            storage_heartbeat_timeout: data.split_brain_prevention?.storage_heartbeat_timeout || 30,
                            poison_pill_enabled: data.split_brain_prevention?.poison_pill_enabled ?? true,
                            strict_fencing: data.split_brain_prevention?.strict_fencing ?? false,
                        });
                        
                        // update nodeAlerts based on HA status
                        // LW: Include cluster_id to filter correctly!
                        if (data.nodes && clusterId) {
                            const newAlerts = { ...nodeAlerts };
                            Object.entries(data.nodes).forEach(([nodeName, nodeData]) => {
                                if (nodeData.status === 'offline') {
                                    // Add to alerts if not already there
                                    if (!newAlerts[nodeName]) {
                                        newAlerts[nodeName] = {
                                            status: 'offline',
                                            message: `Node ${nodeName} is offline`,
                                            timestamp: nodeData.last_seen || new Date().toISOString(),
                                            severity: 'critical',
                                            cluster_id: clusterId  // Important for filtering!
                                        };
                                    }
                                } else if (nodeData.status === 'online' && newAlerts[nodeName]) {
                                    // Remove from alerts if back online
                                    delete newAlerts[nodeName];
                                }
                            });
                            setNodeAlerts(newAlerts);
                        }
                    }
                } catch (err) {
                    console.error('fetching HA status:', err);
                }
            };

            const handleSaveHASettings = async () => {
                if (!selectedCluster) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/ha/config`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            quorum_enabled: haSettings.quorum_enabled,
                            quorum_hosts: haSettings.quorum_hosts.split(',').map(h => h.trim()).filter(h => h),
                            quorum_gateway: haSettings.quorum_gateway,
                            quorum_required_votes: parseInt(haSettings.quorum_required_votes) || 2,
                            self_fence_enabled: haSettings.self_fence_enabled,
                            verify_network: haSettings.verify_network,
                            recovery_delay: parseInt(haSettings.recovery_delay) || 30,
                            failure_threshold: parseInt(haSettings.failure_threshold) || 3,
                            // 2-Node Cluster Mode - uses cluster credentials automatically
                            two_node_mode: haSettings.two_node_mode,
                            force_quorum_on_failure: haSettings.two_node_mode,
                            // Storage-based Split-Brain Protection - NS Jan 2026
                            storage_heartbeat_enabled: haSettings.storage_heartbeat_enabled,
                            storage_heartbeat_path: haSettings.storage_heartbeat_path,
                            storage_heartbeat_timeout: parseInt(haSettings.storage_heartbeat_timeout) || 30,
                            poison_pill_enabled: haSettings.poison_pill_enabled,
                            strict_fencing: haSettings.strict_fencing,
                        })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('haSettingsSaved'));
                        setShowHaSettings(false);
                        fetchHAStatus(selectedCluster.id);
                    } else {
                        const err = await response?.json();
                        addToast(err?.error || t('operationFailed'), 'error');
                    }
                } catch (err) {
                    addToast(t('operationFailed'), 'error');
                }
            };

            // Task management
            const addTask = (task) => {
                if (!task) return;
                taskUpdateTimestamp.current = Date.now();
                setTasks(prev => {
                    // update existing task or add new one
                    const existing = prev.findIndex(item => item && item.upid === task.upid);
                    if (existing >= 0) {
                        const updated = [...prev];
                        updated[existing] = { ...updated[existing], ...task };
                        return updated;
                    }
                    // Add new task and sort by starttime
                    return [task, ...prev]
                        .sort((a, b) => (b.starttime || 0) - (a.starttime || 0))
                        .slice(0, 50);
                });
            };

            const clearCompletedTasks = () => {
                taskUpdateTimestamp.current = Date.now();
                setTasks(prev => prev.filter(item => item && item.status === 'running'));
            };

            // Cancel a running task
            const cancelTask = async (task) => {
                if (!selectedCluster || !task || !task.upid || !task.node) return;
                
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${selectedCluster.id}/nodes/${task.node}/tasks/${encodeURIComponent(task.upid)}`,
                        { method: 'DELETE' }
                    );
                    
                    if (response && response.ok) {
                        addToast(t('taskCancelled'), 'success');
                        // update task status locally
                        setTasks(prev => prev.map(t => 
                            t && t.upid === task.upid ? { ...t, status: 'cancelled' } : t
                        ));
                    } else {
                        const err = await response?.json();
                        addToast(err?.error || t('taskCancelFailed'), 'error');
                    }
                } catch (error) {
                    console.error('cancelling task:', error);
                    addToast(t('taskCancelFailed'), 'error');
                }
            };

            // Fetch tasks from cluster
            const fetchTasks = async (clusterId) => {
                const fetchStartTime = Date.now();
                const isInitialFetch = initialTaskFetchPending.current;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/tasks`);
                    if (response && response.ok) {
                        const data = await response.json();
                        
                        if (Array.isArray(data)) {
                            // NS: On initial fetch, always accept response (no stale check)
                            // SSE events during fetch would otherwise cause "stale" rejection
                            if (!isInitialFetch && fetchStartTime < taskUpdateTimestamp.current) {
                                console.log('Skipping stale task fetch response');
                                return;
                            }
                            
                            // Mark initial fetch as done
                            if (isInitialFetch) {
                                initialTaskFetchPending.current = false;
                            }
                            
                            taskUpdateTimestamp.current = Date.now();
                            
                            setTasks(prev => {
                                // If no new data, keep existing
                                if (data.length === 0) return prev;
                                
                                const taskMap = new Map();
                                // Add existing tasks
                                prev.forEach(task => {
                                    if (task && task.upid) taskMap.set(task.upid, task);
                                });
                                // Add/update new tasks
                                data.forEach(task => {
                                    if (task && task.upid) {
                                        const existing = taskMap.get(task.upid);
                                        taskMap.set(task.upid, existing ? { ...existing, ...task } : task);
                                    }
                                });
                                // Convert back to array, sort by starttime desc, limit to 50
                                return Array.from(taskMap.values())
                                    .sort((a, b) => (b.starttime || 0) - (a.starttime || 0))
                                    .slice(0, 50);
                            });
                        }
                    }
                } catch (err) {
                    console.error('fetching tasks:', err);
                }
            };

            // Fetch tasks when cluster changes
            useEffect(() => {
                if (selectedCluster) {
                    console.log('Cluster changed, fetching tasks for:', selectedCluster.id);
                    // NS: Reset flags for new cluster - allows initial fetch to bypass stale check
                    taskUpdateTimestamp.current = 0;
                    initialTaskFetchPending.current = true;
                    setTasks([]);  // Clear old tasks immediately
                    fetchTasks(selectedCluster.id);
                    fetchHAStatus(selectedCluster.id);
                    
                    // Poll HA status every 30 seconds to detect offline nodes
                    const haInterval = setInterval(() => {
                        fetchHAStatus(selectedCluster.id);
                    }, 30000);
                    
                    return () => clearInterval(haInterval);
                } else {
                    setTasks([]);
                    setNodeAlerts({});
                }
            }, [selectedCluster?.id]);  // Use ID, not whole object to prevent loop

            // SSE (Server-Sent Events) connection for live updates
            // More reliable than WebSocket - no threading issues on server
            useEffect(() => {
                if (!user || !sessionId) {
                    console.log('SSE: Waiting for user/session', { user: !!user, sessionId: !!sessionId });
                    return;
                }
                
                let eventSource = null;
                let reconnectTimeout = null;
                let reconnectAttempts = 0;
                let isClosing = false;
                let sseToken = null;
                let tokenRefreshInterval = null;
                
                // Get SSE token (more secure than session ID in URL)
                const getSseToken = async () => {
                    try {
                        const resp = await authFetch(`${API_URL}/sse/token`, { method: 'POST' });
                        if (resp && resp.ok) {
                            const data = await resp.json();
                            sseToken = data.token;
                            console.log('SSE token obtained (expires in', data.expires_in, 's)');
                            return true;
                        }
                    } catch (e) {
                        console.warn('Failed to get SSE token, falling back to session:', e);
                    }
                    return false;
                };
                
                const connectSSE = async () => {
                    if (isClosing) return;
                    
                    console.log('Connecting to SSE...');
                    
                    // Try to get SSE token first (preferred - doesn't expose session in logs)
                    await getSseToken();
                    
                    // Use token if available, otherwise fall back to session
                    let sseUrl;
                    if (sseToken) {
                        sseUrl = `${API_URL}/sse/updates?token=${encodeURIComponent(sseToken)}`;
                    } else {
                        // Fallback to session (legacy, less secure)
                        console.warn('SSE: Using session ID (token unavailable)');
                        sseUrl = `${API_URL}/sse/updates?session=${encodeURIComponent(sessionId)}`;
                    }
                    
                    eventSource = new EventSource(sseUrl, { withCredentials: true });
                    
                    eventSource.onopen = () => {
                        console.log('SSE connected');
                        reconnectAttempts = 0;
                        setWsConnected(true);
                        
                        // NS: Refresh token every 5 minutes (token valid for 10 min now)
                        // This gives us buffer time if refresh fails
                        if (tokenRefreshInterval) clearInterval(tokenRefreshInterval);
                        tokenRefreshInterval = setInterval(async () => {
                            console.log('SSE: Token refresh cycle starting...');
                            const gotToken = await getSseToken();
                            if (gotToken) {
                                console.log('SSE: Got new token, reconnecting...');
                                // Close current connection - onerror will NOT trigger reconnect
                                // because we set isClosing temporarily
                                const wasClosing = isClosing;
                                isClosing = true;  // Prevent onerror from reconnecting
                                if (eventSource) {
                                    eventSource.close();
                                }
                                isClosing = wasClosing;
                                // Now reconnect with new token
                                setTimeout(connectSSE, 100);  // Small delay to ensure clean close
                            } else {
                                console.warn('SSE: Token refresh failed, keeping existing connection');
                                // Don't reconnect - existing connection might still work
                            }
                        }, 5 * 60 * 1000);  // 5 minutes
                    };
                    
                    eventSource.onmessage = (event) => {
                        try {
                            const data = JSON.parse(event.data);
                            const currentCluster = selectedClusterRef.current;
                            
                            if (data.type === 'connected') {
                                console.log('SSE authenticated');
                            } else if (data.type === 'tasks') {
                                // Tasks kommen mit cluster_id - nur vom aktuellen Cluster anzeigen
                                if (currentCluster && data.cluster_id === currentCluster.id) {
                                    if (Array.isArray(data.data)) {
                                        console.log(`SSE tasks received for cluster ${data.cluster_id}:`, data.data.length);
                                        // NS: Use merge logic same as fetchTasks to prevent jumping
                                        taskUpdateTimestamp.current = Date.now();
                                        setTasks(prev => {
                                            const taskMap = new Map();
                                            // Add existing tasks first
                                            prev.forEach(task => {
                                                if (task && task.upid) taskMap.set(task.upid, task);
                                            });
                                            // SSE data is authoritative - update/add all
                                            data.data.forEach(task => {
                                                if (task && task.upid) {
                                                    taskMap.set(task.upid, task);
                                                }
                                            });
                                            // Sort by starttime desc, limit to 50
                                            return Array.from(taskMap.values())
                                                .sort((a, b) => (b.starttime || 0) - (a.starttime || 0))
                                                .slice(0, 50);
                                        });
                                    }
                                } else if (!currentCluster) {
                                    // MK: Feb 2026 - Fixed oscillation bug in "Alle Cluster" view
                                    // Old logic: replace cluster tasks + global slice(50) = constant flickering
                                    // because each cluster's update would cut the other cluster's tasks
                                    // New logic: Map-based merge with per-cluster fair-share limit
                                    if (Array.isArray(data.data)) {
                                        setTasks(prev => {
                                            const taskMap = new Map();
                                            // Keep existing tasks from ALL clusters
                                            prev.forEach(task => {
                                                if (task && task.upid) taskMap.set(task.upid, task);
                                            });
                                            // Update/add tasks from this cluster
                                            data.data.forEach(task => {
                                                if (task && task.upid) {
                                                    taskMap.set(task.upid, {...task, cluster_id: data.cluster_id});
                                                }
                                            });
                                            // Remove tasks from this cluster that are no longer reported
                                            // (task completed and fell off the Proxmox task list)
                                            const reportedUpids = new Set(data.data.map(t => t.upid).filter(Boolean));
                                            for (const [upid, task] of taskMap) {
                                                if (task.cluster_id === data.cluster_id && !reportedUpids.has(upid)) {
                                                    taskMap.delete(upid);
                                                }
                                            }
                                            const sorted = Array.from(taskMap.values())
                                                .sort((a, b) => (b.starttime || 0) - (a.starttime || 0))
                                                .slice(0, 100);
                                            // Skip re-render if nothing actually changed
                                            if (sorted.length === prev.length && 
                                                sorted.every((t, i) => prev[i]?.upid === t.upid && prev[i]?.status === t.status)) {
                                                return prev;
                                            }
                                            taskUpdateTimestamp.current = Date.now();
                                            return sorted;
                                        });
                                    }
                                }
                            } else if (data.type === 'metrics') {
                                // Only update detailed clusterMetrics for the selected cluster
                                // LW: allClusterMetrics is updated via fetchClusters using datacenter/status API
                                if (currentCluster && data.cluster_id === currentCluster.id) {
                                    setClusterMetrics(data.data);
                                    setLastUpdate(new Date());
                                    
                                    // NS: Track all nodes - nodes in metrics are online
                                    setKnownNodes(prev => {
                                        const updated = { ...prev };
                                        const now = new Date().toISOString();
                                        
                                        // Mark all nodes in metrics as online
                                        Object.keys(data.data || {}).forEach(nodeName => {
                                            updated[nodeName] = {
                                                status: 'online',
                                                lastSeen: now,
                                                metrics: data.data[nodeName]
                                            };
                                        });
                                        
                                        // DON'T mark nodes as offline based on metrics
                                        // Let the node_status SSE event handle offline detection
                                        
                                        return updated;
                                    });
                                }
                            } else if (data.type === 'resources') {
                                // NS: ONLY process resources for the currently selected cluster
                                if (currentCluster && data.cluster_id === currentCluster.id) {
                                    setClusterResources(data.data);
                                    // MK: Store in window for access from ConfigModal reassign feature
                                    window.pegaproxVmList = data.data;
                                    setLastUpdate(new Date());
                                }
                            } else if (data.type === 'vm_config') {
                                // NS: Live VM config updates - dispatch event for modals to listen
                                if (currentCluster && data.cluster_id === currentCluster.id) {
                                    const vmConfig = data.data;
                                    console.log(`SSE vm_config update for ${vmConfig.vm_type}/${vmConfig.vmid}`);
                                    // Dispatch custom event that modals can listen to
                                    window.dispatchEvent(new CustomEvent('pegaprox-vm-config', {
                                        detail: {
                                            vmid: vmConfig.vmid,
                                            node: vmConfig.node,
                                            vm_type: vmConfig.vm_type,
                                            config: vmConfig.config,
                                            cluster_id: data.cluster_id
                                        }
                                    }));
                                }
                            } else if (data.type === 'action') {
                                const action = data.data;
                                const currentUser = user?.username;
                                
                                // NS: Optimistic UI update - immediately update VM status in the list
                                if (currentCluster && data.cluster_id === currentCluster.id && action.resource_id) {
                                    const vmid = parseInt(action.resource_id);
                                    const newStatus = {
                                        'start': 'running',
                                        'stop': 'stopped',
                                        'shutdown': 'stopped',
                                        'reboot': 'running',
                                        'delete': null  // Will be removed
                                    }[action.action];
                                    
                                    if (newStatus !== undefined) {
                                        setClusterResources(prev => {
                                            if (!prev) return prev;
                                            if (newStatus === null) {
                                                // Delete - remove from list
                                                return prev.filter(r => r.vmid !== vmid);
                                            }
                                            // Update status
                                            return prev.map(r => 
                                                r.vmid === vmid ? { ...r, status: newStatus } : r
                                            );
                                        });
                                    }
                                }
                                
                                // Show toast for other users' actions
                                if (action.user && action.user !== currentUser) {
                                    const actionNames = {
                                        'start': t('started'), 'stop': t('stopped'),
                                        'shutdown': t('stopped'), 'reboot': t('restarted'),
                                        'delete': t('deleted'), 'create': t('created')
                                    };
                                    const actionName = actionNames[action.action] || action.action;
                                    const resourceType = action.resource_type === 'qemu' ? 'VM' : 'CT';
                                    addToast(`${action.user}: ${resourceType} ${action.resource_id} ${actionName}`, 'info');
                                }
                            } else if (data.type === 'node_status') {
                                // handle node online/offline events
                                // NS: ONLY process events for the currently selected cluster!
                                const nodeEvent = data.data;
                                
                                // NS: Feb 2026 - Cluster reconnect events are shown for ANY cluster
                                if (nodeEvent.event === 'cluster_reconnected') {
                                    addToast(`✓ ${nodeEvent.message}`, 'success');
                                } else if (currentCluster && nodeEvent.cluster_id === currentCluster.id) {
                                    if (nodeEvent.event === 'node_offline') {
                                        // Show critical alert for node offline
                                        addToast(`⚠️ CRITICAL: ${nodeEvent.message}`, 'error');
                                        setNodeAlerts(prev => ({
                                            ...prev,
                                            [nodeEvent.node]: {
                                                status: 'offline',
                                                message: nodeEvent.message,
                                                timestamp: new Date().toISOString(),
                                                severity: 'critical',
                                                cluster_id: nodeEvent.cluster_id
                                            }
                                        }));
                                    } else if (nodeEvent.event === 'node_online') {
                                        // Node is back online
                                        addToast(`✓ ${nodeEvent.message}`, 'success');
                                        setNodeAlerts(prev => {
                                            const newAlerts = { ...prev };
                                            delete newAlerts[nodeEvent.node];
                                            return newAlerts;
                                        });
                                    }
                                }
                            
                            // ── VMware SSE Events ──
                            } else if (data.type === 'vmware_servers') {
                                // Update VMware servers list from SSE
                                if (Array.isArray(data.data)) {
                                    setVmwareServers(prev => {
                                        // Merge: SSE data is authoritative
                                        const merged = [...data.data];
                                        // Keep any extra fields from previous state
                                        prev.forEach(old => {
                                            const idx = merged.findIndex(n => n.id === old.id);
                                            if (idx >= 0) merged[idx] = { ...old, ...merged[idx] };
                                        });
                                        return merged;
                                    });
                                }
                            } else if (data.type === 'vmware_vms') {
                                // Update VM list for a specific VMware server
                                const payload = data.data;
                                const curVmw = selectedVMwareRef.current;
                                if (payload && curVmw?.id === payload.vmware_id && Array.isArray(payload.vms)) {
                                    setVmwareVms(payload.vms);
                                }
                            } else if (data.type === 'vmware_vm_detail') {
                                // Update VM detail for a specific VM
                                const payload = data.data;
                                const curVmw = selectedVMwareRef.current;
                                const curVm = vmwareSelectedVmRef.current;
                                if (payload && curVmw?.id === payload.vmware_id && 
                                    curVm === payload.vm_id && payload.data) {
                                    setVmwareVmDetail(payload.data);
                                }
                            } else if (data.type === 'vmware_migration') {
                                // Real-time migration status update via SSE
                                const m = data.data;
                                if (m && m.id) {
                                    setVmwareMigrations(prev => {
                                        const idx = prev.findIndex(x => x.id === m.id);
                                        if (idx >= 0) {
                                            const updated = [...prev];
                                            updated[idx] = { ...updated[idx], ...m };
                                            return updated;
                                        }
                                        return [m, ...prev];
                                    });
                                    // Update selected migration detail if viewing it
                                    if (vmwareSelectedMigrationRef.current === m.id) {
                                        setVmwareMigrationDetail(prev => prev ? { ...prev, ...m } : m);
                                    }
                                }
                            } else if (data.type === 'vmware_migration_log') {
                                // Real-time log line for active migration
                                const m = data.data;
                                if (m && m.id && vmwareSelectedMigrationRef.current === m.id) {
                                    setVmwareMigrationDetail(prev => {
                                        if (!prev) return prev;
                                        const newLog = [...(prev.log || [])];
                                        if (m.line && !newLog.includes(m.line)) newLog.push(m.line);
                                        return { ...prev, log: newLog, progress: m.progress || prev.progress, phase: m.phase || prev.phase };
                                    });
                                }
                            }
                        } catch (e) {
                            console.error('SSE message error:', e);
                        }
                    };
                    
                    eventSource.onerror = (error) => {
                        console.error('SSE error:', error);
                        setWsConnected(false);
                        
                        // Only close if not already closed
                        if (eventSource && eventSource.readyState !== EventSource.CLOSED) {
                            eventSource.close();
                        }
                        
                        if (!isClosing) {
                            // NS: Get fresh token before reconnecting
                            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
                            reconnectAttempts++;
                            console.log(`SSE: Reconnecting in ${delay}ms (attempt ${reconnectAttempts})...`);
                            reconnectTimeout = setTimeout(async () => {
                                // Get fresh token first
                                await getSseToken();
                                connectSSE();
                            }, delay);
                        }
                    };
                };
                
                connectSSE();
                
                // NS: Health check - if disconnected for >30 seconds, force reconnect
                const healthCheckInterval = setInterval(() => {
                    if (!wsConnectedRef.current && !isClosing && eventSource?.readyState === EventSource.CLOSED) {
                        console.log('SSE: Health check detected closed connection, reconnecting...');
                        reconnectAttempts = 0;  // Reset attempts
                        connectSSE();
                    }
                }, 30000);
                
                return () => {
                    isClosing = true;
                    if (reconnectTimeout) clearTimeout(reconnectTimeout);
                    if (tokenRefreshInterval) clearInterval(tokenRefreshInterval);
                    if (healthCheckInterval) clearInterval(healthCheckInterval);
                    if (eventSource) eventSource.close();
                };
            }, [user, sessionId]);  // React to both user and sessionId changes
            
            // update WebSocket subscription when selected cluster changes
            useEffect(() => {
                if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN && selectedCluster) {
                    wsRef.current.send(JSON.stringify({
                        type: 'subscribe',
                        clusters: [selectedCluster.id]
                    }));
                }
            }, [selectedCluster?.id]);

            useEffect(() => {
                fetchClusters();
                fetchClusterGroups();
                const interval = setInterval(fetchClusters, 30000);
                return () => clearInterval(interval);
            }, []);
            
            // LW: Feb 2026 - PBS fetch functions
            const fetchPBSServers = async () => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setPbsServers(data);
                    }
                } catch (e) { console.warn('PBS fetch error:', e); }
            };
            
            const fetchPBSStatus = async (pbsId) => {
                setPbsLoading(true);
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/status`);
                    if (resp && resp.ok) setPbsStatus(await resp.json());
                } catch (e) { console.warn('PBS status error:', e); }
                finally { setPbsLoading(false); }
            };
            
            const fetchPBSDatastores = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/datastores`);
                    if (resp && resp.ok) setPbsDatastores(await resp.json());
                } catch (e) { console.warn('PBS datastores error:', e); }
            };
            
            const fetchPBSSnapshots = async (pbsId, store) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/datastores/${store}/snapshots`);
                    if (resp && resp.ok) setPbsSnapshots(await resp.json());
                } catch (e) { console.warn('PBS snapshots error:', e); }
            };
            
            const fetchPBSGroups = async (pbsId, store) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/datastores/${store}/groups`);
                    if (resp && resp.ok) setPbsGroups(await resp.json());
                } catch (e) { console.warn('PBS groups error:', e); }
            };
            
            const fetchPBSTasks = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/tasks?limit=30`);
                    if (resp && resp.ok) setPbsTasks(await resp.json());
                } catch (e) { console.warn('PBS tasks error:', e); }
            };
            
            const fetchPBSJobs = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/jobs`);
                    if (resp && resp.ok) setPbsJobs(await resp.json());
                } catch (e) { console.warn('PBS jobs error:', e); }
            };
            
            const fetchPBSNamespaces = async (pbsId, store) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/datastores/${store}/namespaces`);
                    if (resp && resp.ok) setPbsNamespaces(await resp.json());
                    else setPbsNamespaces([]);
                } catch (e) { setPbsNamespaces([]); }
            };
            
            const fetchPBSDisks = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/disks`);
                    if (resp && resp.ok) setPbsDisks(await resp.json());
                } catch (e) { console.warn('PBS disks error:', e); }
            };
            
            const fetchPBSRemotes = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/remotes`);
                    if (resp && resp.ok) setPbsRemotes(await resp.json());
                } catch (e) { console.warn('PBS remotes error:', e); }
            };
            
            const fetchPBSNotifications = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/notifications`);
                    if (resp && resp.ok) setPbsNotifications(await resp.json());
                } catch (e) { console.warn('PBS notifications error:', e); }
            };
            
            const fetchPBSTrafficControl = async (pbsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/traffic-control`);
                    if (resp && resp.ok) setPbsTrafficControl(await resp.json());
                } catch (e) { console.warn('PBS traffic control error:', e); }
            };
            
            const fetchPBSSyslog = async (pbsId, limit = 100) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/syslog?limit=${limit}`);
                    if (resp && resp.ok) setPbsSyslog(await resp.json());
                } catch (e) { console.warn('PBS syslog error:', e); }
            };
            
            const fetchPBSCatalog = async (pbsId, store, snapshot, filepath = '/') => {
                try {
                    const params = new URLSearchParams({
                        'backup-type': snapshot['backup-type'],
                        'backup-id': snapshot['backup-id'],
                        'backup-time': snapshot['backup-time'],
                        filepath
                    });
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}/datastores/${store}/catalog?${params}`);
                    if (resp && resp.ok) {
                        setPbsCatalog(await resp.json());
                    } else {
                        setPbsCatalog([]);
                        addToast('Catalog not available for this snapshot (may be encrypted or non-pxar)', 'warning');
                    }
                } catch (e) { 
                    console.warn('PBS catalog error:', e); 
                    setPbsCatalog([]);
                }
            };
            
            const pbsOpenFileBrowser = (snapshot) => {
                setPbsCatalogSnapshot(snapshot);
                setPbsCatalogPath('/');
                setPbsCatalog([]);
                setShowPbsFileBrowser(true);
                fetchPBSCatalog(selectedPBS.id, pbsSelectedStore, snapshot, '/');
            };
            
            const pbsNavigateCatalog = (path) => {
                setPbsCatalogPath(path);
                fetchPBSCatalog(selectedPBS.id, pbsSelectedStore, pbsCatalogSnapshot, path);
            };
            
            const pbsDownloadFile = (filepath) => {
                const snap = pbsCatalogSnapshot;
                const params = new URLSearchParams({
                    'backup-type': snap['backup-type'],
                    'backup-id': snap['backup-id'],
                    'backup-time': snap['backup-time'],
                    filepath
                });
                // Open download in new tab/trigger download
                window.open(`${API_URL}/pbs/${selectedPBS.id}/datastores/${pbsSelectedStore}/file-download?${params}`, '_blank');
            };
            
            const pbsSaveNotes = async (type, params) => {
                try {
                    const endpoint = type === 'snapshot' ? 'notes' : 'group-notes';
                    const resp = await authFetch(`${API_URL}/pbs/${selectedPBS.id}/datastores/${pbsSelectedStore}/${endpoint}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ...params, notes: pbsNotesText })
                    });
                    if (resp && resp.ok) {
                        addToast('Notes saved', 'success');
                        setPbsEditingNotes(null);
                        // Refresh data
                        if (type === 'snapshot') fetchPBSSnapshots(selectedPBS.id, pbsSelectedStore);
                        else fetchPBSGroups(selectedPBS.id, pbsSelectedStore);
                    } else {
                        addToast('Failed to save notes', 'error');
                    }
                } catch (e) { addToast('Error saving notes: ' + e.message, 'error'); }
            };
            
            const pbsToggleProtected = async (snapshot) => {
                try {
                    const newState = !snapshot.protected;
                    const resp = await authFetch(`${API_URL}/pbs/${selectedPBS.id}/datastores/${pbsSelectedStore}/protected`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            'backup-type': snapshot['backup-type'],
                            'backup-id': snapshot['backup-id'],
                            'backup-time': snapshot['backup-time'],
                            'protected': newState
                        })
                    });
                    if (resp && resp.ok) {
                        addToast(`Snapshot ${newState ? 'protected' : 'unprotected'}`, 'success');
                        fetchPBSSnapshots(selectedPBS.id, pbsSelectedStore);
                    } else {
                        addToast('Failed to update protection', 'error');
                    }
                } catch (e) { addToast('Error: ' + e.message, 'error'); }
            };
            
            // Load PBS when selected
            useEffect(() => {
                if (selectedPBS) {
                    fetchPBSStatus(selectedPBS.id);
                    fetchPBSDatastores(selectedPBS.id);
                    fetchPBSTasks(selectedPBS.id);
                    fetchPBSJobs(selectedPBS.id);
                    fetchPBSDisks(selectedPBS.id);
                    fetchPBSRemotes(selectedPBS.id);
                    fetchPBSNotifications(selectedPBS.id);
                    fetchPBSTrafficControl(selectedPBS.id);
                    const interval = setInterval(() => {
                        fetchPBSStatus(selectedPBS.id);
                        fetchPBSDatastores(selectedPBS.id);
                    }, 30000);
                    return () => clearInterval(interval);
                }
            }, [selectedPBS?.id]);
            
            // Load PBS datastore detail when selected
            useEffect(() => {
                if (selectedPBS && pbsSelectedStore) {
                    fetchPBSSnapshots(selectedPBS.id, pbsSelectedStore);
                    fetchPBSGroups(selectedPBS.id, pbsSelectedStore);
                    fetchPBSNamespaces(selectedPBS.id, pbsSelectedStore);
                }
            }, [selectedPBS?.id, pbsSelectedStore]);
            
            // Initial PBS load
            useEffect(() => {
                fetchPBSServers();
                const pbsInterval = setInterval(fetchPBSServers, 60000);
                return () => clearInterval(pbsInterval);
            }, []);
            
            // LW: Feb 2026 - PBS action functions
            const handleAddPBS = async (config) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        addToast('PBS server added successfully', 'success');
                        setShowAddPBS(false);
                        fetchPBSServers();
                        setSelectedPBS(data);
                        setSelectedCluster(null);
                        setPbsActiveTab('dashboard');
                        return { success: true };
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        return { success: false, error: err.error || `HTTP ${resp?.status}` };
                    }
                } catch (e) { return { success: false, error: e.message }; }
            };
            
            const handleUpdatePBS = async (pbsId, config) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (resp && resp.ok) {
                        addToast('PBS server updated', 'success');
                        fetchPBSServers();
                        if (selectedPBS?.id === pbsId) fetchPBSStatus(pbsId);
                        return { success: true };
                    }
                    const err = resp ? await resp.json().catch(() => ({})) : {};
                    return { success: false, error: err.error || 'Update failed' };
                } catch (e) { return { success: false, error: e.message }; }
            };
            
            const handleDeletePBS = async (pbsId) => {
                if (!confirm('Delete this PBS server? This cannot be undone.')) return;
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${pbsId}`, { method: 'DELETE' });
                    if (resp && resp.ok) {
                        addToast('PBS server deleted', 'success');
                        if (selectedPBS?.id === pbsId) setSelectedPBS(null);
                        fetchPBSServers();
                    }
                } catch (e) { addToast('Delete failed: ' + e.message, 'error'); }
            };
            
            const handleTestPBS = async (config) => {
                try {
                    const resp = await authFetch(`${API_URL}/pbs/test-connection`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (resp && resp.ok) return await resp.json();
                    const err = resp ? await resp.json().catch(() => ({})) : {};
                    return { success: false, error: err.error || `HTTP ${resp?.status}` };
                } catch (e) { return { success: false, error: e.message }; }
            };
            
            const pbsAction = async (action, store, data = {}) => {
                if (!selectedPBS) return;
                const pbsId = selectedPBS.id;
                try {
                    let url, method = 'POST';
                    if (action === 'gc') url = `${API_URL}/pbs/${pbsId}/datastores/${store}/gc`;
                    else if (action === 'verify') url = `${API_URL}/pbs/${pbsId}/datastores/${store}/verify`;
                    else if (action === 'prune') url = `${API_URL}/pbs/${pbsId}/datastores/${store}/prune`;
                    else if (action === 'delete-snapshot') {
                        url = `${API_URL}/pbs/${pbsId}/datastores/${store}/snapshots`;
                        method = 'DELETE';
                    }
                    const resp = await authFetch(url, {
                        method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data),
                    });
                    if (resp && resp.ok) {
                        const result = await resp.json();
                        const upid = result?.data;
                        addToast(`${action} started on ${store}${upid ? ' (task: ' + String(upid).slice(-8) + ')' : ''}`, 'success');
                        // Refresh tasks
                        setTimeout(() => {
                            fetchPBSTasks(pbsId);
                            if (action === 'delete-snapshot' || action === 'prune') {
                                fetchPBSSnapshots(pbsId, store);
                                fetchPBSGroups(pbsId, store);
                            }
                        }, 1000);
                        return result;
                    }
                    const err = resp ? await resp.json().catch(() => ({})) : {};
                    addToast(`${action} failed: ${err.error || 'unknown'}`, 'error');
                } catch (e) { addToast(`${action} error: ${e.message}`, 'error'); }
            };
            
            const pbsRunJob = async (jobType, jobId) => {
                if (!selectedPBS) return;
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${selectedPBS.id}/jobs/${jobType}/${jobId}/run`, {
                        method: 'POST',
                    });
                    if (resp && resp.ok) {
                        addToast(`${jobType} job '${jobId}' started`, 'success');
                        setTimeout(() => fetchPBSTasks(selectedPBS.id), 1000);
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        addToast(`Job failed: ${err.error || 'unknown'}`, 'error');
                    }
                } catch (e) { addToast('Job error: ' + e.message, 'error'); }
            };
            
            const viewPBSTaskLog = async (upid) => {
                if (!selectedPBS) return;
                try {
                    const resp = await authFetch(`${API_URL}/pbs/${selectedPBS.id}/tasks/${encodeURIComponent(upid)}`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setPbsTaskLog({ upid, ...data });
                    }
                } catch (e) { addToast('Failed to load task log', 'error'); }
            };
            
            
            // PBS prune dialog  
            const [showPbsPrune, setShowPbsPrune] = useState(null);
            
            // ============================================================
            // VMware Server Functions
            // ============================================================
            const fetchVMwareServers = async () => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareServers(Array.isArray(data) ? data : data.data || []);
                    }
                } catch (e) { console.warn('VMware fetch error:', e); }
            };
            
            const fetchVMwareVms = async (vmwId) => {
                if (!vmwId) return;
                setVmwareLoading(true);
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/vms`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareVms(Array.isArray(data) ? data : data.data || []);
                        setVmwareConnectionOk(true);
                    } else {
                        setVmwareConnectionOk(false);
                    }
                } catch (e) { console.warn('VMware VMs error:', e); setVmwareConnectionOk(false); }
                setVmwareLoading(false);
            };
            
            const fetchVMwareHosts = async (vmwId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/hosts`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareHosts(Array.isArray(data) ? data : data.data || []);
                    }
                } catch (e) { console.warn('VMware hosts error:', e); }
            };
            
            const fetchVMwareDatastores = async (vmwId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/datastores`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareDatastores(Array.isArray(data) ? data : data.data || []);
                    }
                } catch (e) { console.warn('VMware datastores error:', e); }
            };
            
            const fetchVMwareDsDetail = async (vmwId, dsId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/datastores/${dsId}`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareDsDetail(data);
                    }
                } catch (e) { console.warn('VMware DS detail error:', e); }
            };
            
            const fetchVMwareNetworks = async (vmwId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/networks`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareNetworks(Array.isArray(data) ? data : data.data || []);
                    }
                } catch (e) { console.warn('VMware networks error:', e); }
            };
            
            const fetchVMwareClusters = async (vmwId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/clusters`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareClusters(Array.isArray(data) ? data : data.data || []);
                    }
                } catch (e) { console.warn('VMware clusters error:', e); }
            };
            
            const toggleVMwareDRS = async (vmwId, clusterId, enabled, automation) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/clusters/${clusterId}/drs`, {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ enabled, automation: automation || 'FULLY_AUTOMATED' })
                    });
                    if (resp && resp.ok) {
                        addToast(`DRS ${enabled ? 'enabled' : 'disabled'}`, 'success');
                        fetchVMwareClusters(vmwId);
                    } else {
                        const err = await resp.json().catch(() => ({}));
                        addToast(err.error || 'DRS toggle failed', 'error');
                    }
                } catch (e) { addToast('DRS toggle error: ' + e.message, 'error'); }
            };
            
            const toggleVMwareHA = async (vmwId, clusterId, enabled) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/clusters/${clusterId}/ha`, {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ enabled })
                    });
                    if (resp && resp.ok) {
                        addToast(`HA ${enabled ? 'enabled' : 'disabled'}`, 'success');
                        fetchVMwareClusters(vmwId);
                    } else {
                        const err = await resp.json().catch(() => ({}));
                        addToast(err.error || 'HA toggle failed', 'error');
                    }
                } catch (e) { addToast('HA toggle error: ' + e.message, 'error'); }
            };
            
            const fetchVMwareVmDetail = async (vmwId, vmId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}/vms/${vmId}`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setVmwareVmDetail(data.data || data);
                    }
                } catch (e) { console.warn('VMware VM detail error:', e); }
            };
            
            const vmwarePowerAction = async (vmId, action) => {
                if (!selectedVMware) return;
                setVmwareActionLoading(prev => ({...prev, [vmId]: action}));
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/power/${action}`, {
                        method: 'POST'
                    });
                    if (resp && resp.ok) {
                        addToast(`VM ${action} initiated`, 'success');
                        setTimeout(() => fetchVMwareVms(selectedVMware.id), 2000);
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        addToast(`Power action failed: ${err.error || 'unknown'}`, 'error');
                    }
                } catch (e) { addToast('Power action error: ' + e.message, 'error'); }
                setVmwareActionLoading(prev => ({...prev, [vmId]: null}));
            };
            
            const vmwareSnapshotAction = async (vmId, action, data = {}) => {
                if (!selectedVMware) return;
                try {
                    const method = action === 'delete' ? 'DELETE' : 'POST';
                    const url = action === 'delete' 
                        ? `${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/snapshots/${data.snapshot_id}`
                        : `${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/snapshots`;
                    const resp = await authFetch(url, {
                        method,
                        headers: { 'Content-Type': 'application/json' },
                        body: action !== 'delete' ? JSON.stringify(data) : undefined,
                    });
                    if (resp && resp.ok) {
                        addToast(`Snapshot ${action} successful`, 'success');
                        if (vmwareSelectedVm) fetchVMwareVmDetail(selectedVMware.id, vmId);
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        addToast(`Snapshot ${action} failed: ${err.error || 'unknown'}`, 'error');
                    }
                } catch (e) { addToast('Snapshot error: ' + e.message, 'error'); }
            };
            
            const handleAddVMware = async (config) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (resp && resp.ok) {
                        addToast('ESXi server added', 'success');
                        setShowAddVMware(false);
                        setVmwareForm({ name: '', host: '', port: 443, username: 'root', password: '', ssl_verify: false, notes: '' });
                        fetchVMwareServers();
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        addToast(`Failed: ${err.error || 'unknown'}`, 'error');
                    }
                } catch (e) { addToast('Error: ' + e.message, 'error'); }
            };
            
            const handleUpdateVMware = async (vmwId, config) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (resp && resp.ok) {
                        addToast('ESXi server updated', 'success');
                        setShowAddVMware(false);
                        setEditingVMware(null);
                        fetchVMwareServers();
                    } else {
                        const err = resp ? await resp.json().catch(() => ({})) : {};
                        addToast(`Update failed: ${err.error || 'unknown'}`, 'error');
                    }
                } catch (e) { addToast('Error: ' + e.message, 'error'); }
            };
            
            const handleDeleteVMware = async (vmwId) => {
                if (!confirm('Delete this ESXi server?')) return;
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${vmwId}`, { method: 'DELETE' });
                    if (resp && resp.ok) {
                        addToast('ESXi server deleted', 'success');
                        if (selectedVMware?.id === vmwId) setSelectedVMware(null);
                        fetchVMwareServers();
                    }
                } catch (e) { addToast('Delete error: ' + e.message, 'error'); }
            };
            
            const handleTestVMware = async (config) => {
                setVmwareTestLoading(true);
                setVmwareTestResult(null);
                try {
                    const resp = await authFetch(`${API_URL}/vmware/test-connection`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    const data = resp && resp.ok ? await resp.json() : { error: 'Connection failed' };
                    setVmwareTestResult(data);
                } catch (e) { setVmwareTestResult({ error: e.message }); }
                setVmwareTestLoading(false);
            };
            
            // VMware initial load (SSE handles ongoing updates)
            useEffect(() => {
                fetchVMwareServers();
                // Fallback poll at 120s in case SSE disconnects
                const vmwInterval = setInterval(fetchVMwareServers, 120000);
                return () => clearInterval(vmwInterval);
            }, []);
            
            // Fetch VMs when a VMware server is selected
            useEffect(() => {
                if (selectedVMware?.id) {
                    fetchVMwareVms(selectedVMware.id);
                    fetchVMwareHosts(selectedVMware.id);
                    fetchVMwareDatastores(selectedVMware.id);
                    fetchVMwareNetworks(selectedVMware.id);
                    fetchVMwareClusters(selectedVMware.id);
                    // SSE pushes vmware_vms every ~10s -- keep a slow fallback
                    const interval = setInterval(() => {
                        fetchVMwareHosts(selectedVMware.id);
                        fetchVMwareDatastores(selectedVMware.id);
                    }, 60000);
                    const clInterval = setInterval(() => fetchVMwareClusters(selectedVMware.id), 120000);
                    return () => { clearInterval(interval); clearInterval(clInterval); };
                }
            }, [selectedVMware?.id]);
            
            // Watch VM detail via SSE (replaces 10s polling)
            useEffect(() => {
                if (selectedVMware?.id && vmwareSelectedVm) {
                    // Initial fetch
                    fetchVMwareVmDetail(selectedVMware.id, vmwareSelectedVm);
                    // Register watch -- SSE will push detail every ~5s
                    const watchVm = () => {
                        authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmwareSelectedVm}/watch`, {
                            method: 'POST'
                        }).catch(() => {});
                    };
                    watchVm();
                    // Renew watch every 60s (TTL is 120s)
                    const renewInterval = setInterval(watchVm, 60000);
                    // Fallback poll at 30s in case SSE is down
                    const fallbackInterval = setInterval(() => {
                        fetchVMwareVmDetail(selectedVMware.id, vmwareSelectedVm);
                    }, 30000);
                    return () => {
                        clearInterval(renewInterval);
                        clearInterval(fallbackInterval);
                        // Unwatch
                        authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmwareSelectedVm}/watch`, {
                            method: 'DELETE'
                        }).catch(() => {});
                    };
                } else {
                    setVmwareVmDetail(null);
                }
            }, [selectedVMware?.id, vmwareSelectedVm]);
            
            // Fetch datastore detail when selected
            useEffect(() => {
                if (selectedVMware?.id && vmwareSelectedDs) {
                    const dsId = typeof vmwareSelectedDs === 'object' ? (vmwareSelectedDs.datastore || vmwareSelectedDs.id) : vmwareSelectedDs;
                    if (dsId) fetchVMwareDsDetail(selectedVMware.id, dsId);
                } else {
                    setVmwareDsDetail(null);
                }
            }, [selectedVMware?.id, vmwareSelectedDs]);
            
            // VMware Clone VM
            const handleVmwareClone = async (vmId, cloneName) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/clone`, {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ name: cloneName })
                    });
                    if (resp?.ok) {
                        addToast(t('success') || 'Success', `VM cloned as '${cloneName}'`, 'success');
                        setShowVmwareClone(false);
                        fetchVMwareVms(selectedVMware.id);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(t('error') || 'Error', err.error || 'Clone failed', 'error');
                    }
                } catch(e) { addToast('Error', e.message, 'error'); }
            };
            
            // VMware Delete VM
            const handleVmwareDeleteVm = async (vmId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}`, { method: 'DELETE' });
                    if (resp?.ok) {
                        addToast(t('success') || 'Success', 'VM deleted', 'success');
                        setShowVmwareDelete(false);
                        setVmwareSelectedVm(null);
                        fetchVMwareVms(selectedVMware.id);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(t('error') || 'Error', err.error || 'Delete failed', 'error');
                    }
                } catch(e) { addToast('Error', e.message, 'error'); }
            };
            
            // VMware Rename VM
            const handleVmwareRename = async (vmId, newName) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/rename`, {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ name: newName })
                    });
                    if (resp?.ok) {
                        addToast(t('success') || 'Success', `VM renamed to '${newName}'`, 'success');
                        setShowVmwareRename(false);
                        fetchVMwareVms(selectedVMware.id);
                        fetchVMwareVmDetail(selectedVMware.id, vmId);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(t('error') || 'Error', err.error || 'Rename failed', 'error');
                    }
                } catch(e) { addToast('Error', e.message, 'error'); }
            };
            
            // VMware VM Config Save
            const handleVmwareConfigSave = async (vmId) => {
                setVmwareConfigSaving(true);
                try {
                    const payload = {};
                    if (vmwareConfigEdit.cpu) payload.cpu_count = parseInt(vmwareConfigEdit.cpu);
                    if (vmwareConfigEdit.memory) payload.memory_mb = parseInt(vmwareConfigEdit.memory);
                    if (vmwareConfigEdit.notes !== undefined && vmwareConfigEdit.notes !== null) payload.notes = vmwareConfigEdit.notes;
                    if (vmwareConfigEdit.cpu_hot_add !== undefined) payload.cpu_hot_add = vmwareConfigEdit.cpu_hot_add;
                    if (vmwareConfigEdit.memory_hot_add !== undefined) payload.memory_hot_add = vmwareConfigEdit.memory_hot_add;
                    
                    if (Object.keys(payload).length === 0) {
                        addToast('No changes', 'warning');
                        setVmwareConfigSaving(false);
                        return;
                    }
                    
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/config`, {
                        method: 'PUT', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify(payload)
                    });
                    if (resp?.ok) {
                        addToast('VM configuration updated', 'success');
                        fetchVMwareVmDetail(selectedVMware.id, vmId);
                        fetchVMwareVms(selectedVMware.id);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(err.error || 'Config update failed', 'error');
                    }
                } catch(e) { addToast('Error: ' + e.message, 'error'); }
                setVmwareConfigSaving(false);
            };
            
            const handleVmwareNetworkChange = async (vmId, nicKey, networkName) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/network`, {
                        method: 'PUT', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ nic_key: nicKey, network: networkName })
                    });
                    if (resp?.ok) {
                        addToast(`Network changed to '${networkName}'`, 'success');
                        fetchVMwareVmDetail(selectedVMware.id, vmId);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(err.error || 'Network change failed', 'error');
                    }
                } catch(e) { addToast('Error: ' + e.message, 'error'); }
            };
            
            const handleVmwareBootOrderSave = async (vmId, bootOrder) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/boot-order`, {
                        method: 'PUT', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({ boot_order: bootOrder })
                    });
                    if (resp?.ok) {
                        addToast('Boot order updated', 'success');
                        fetchVMwareVmDetail(selectedVMware.id, vmId);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast(err.error || 'Boot order change failed', 'error');
                    }
                } catch(e) { addToast('Error: ' + e.message, 'error'); }
            };
            
            // VMware Migration Plan
            const fetchMigrationPlan = async (vmId) => {
                try {
                    setVmwareMigrateLoading(true);
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/migration-plan`);
                    if (resp?.ok) {
                        const data = await resp.json();
                        setVmwareMigrationPlan(data);
                        setShowVmwareMigrate(true);
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast('Error', err.error || 'Failed to get migration plan', 'error');
                    }
                } catch(e) { addToast('Error', e.message, 'error'); }
                finally { setVmwareMigrateLoading(false); }
            };
            
            // Start VMware Migration
            const startVmwareMigration = async (vmId) => {
                try {
                    setVmwareMigrateLoading(true);
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/migrate`, {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify(vmwareMigrateForm)
                    });
                    if (resp?.ok) {
                        const data = await resp.json();
                        addToast('Migration Started', `Migration ID: ${data.migration_id}`, 'success');
                        setShowVmwareMigrate(false);
                        fetchVmwareMigrations();
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        addToast('Migration Error', err.error || 'Failed to start migration', 'error');
                    }
                } catch(e) { addToast('Error', e.message, 'error'); }
                finally { setVmwareMigrateLoading(false); }
            };
            
            // List VMware Migrations
            const fetchVmwareMigrations = async () => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/migrations`);
                    if (resp?.ok) {
                        const data = await resp.json();
                        setVmwareMigrations(Array.isArray(data) ? data : []);
                    }
                } catch(e) {}
            };
            
            // VMware Events/Tasks
            const fetchVmwareEvents = async () => {
                try {
                    setVmwareEventsLoading(true);
                    const resp = await authFetch(`${API_URL}/audit?action=vmware&limit=100`);
                    if (resp?.ok) {
                        const data = await resp.json();
                        setVmwareEvents(Array.isArray(data) ? data : []);
                    }
                } catch(e) {} finally { setVmwareEventsLoading(false); }
            };
            
            const fetchMigrationDetail = async (mid) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/migrations/${mid}`);
                    if (resp?.ok) {
                        const data = await resp.json();
                        setVmwareMigrationDetail(data);
                    }
                } catch(e) {}
            };
            
            React.useEffect(() => {
                if (selectedVMware && vmwareActiveTab === 'tasks') {
                    fetchVmwareEvents();
                    fetchVmwareMigrations();
                    // SSE handles real-time updates; polling is just a fallback
                    const pollInterval = wsConnected ? 30000 : 5000;
                    const intv = setInterval(() => fetchVmwareMigrations(), pollInterval);
                    return () => clearInterval(intv);
                }
            }, [selectedVMware?.id, vmwareActiveTab, wsConnected]);
            
            React.useEffect(() => {
                if (vmwareSelectedMigration) {
                    fetchMigrationDetail(vmwareSelectedMigration);
                    // SSE streams logs in real-time; poll less aggressively as fallback
                    const pollInterval = wsConnected ? 15000 : 3000;
                    const intv = setInterval(() => fetchMigrationDetail(vmwareSelectedMigration), pollInterval);
                    return () => clearInterval(intv);
                }
            }, [vmwareSelectedMigration, wsConnected]);
            
            // VMware Console Ticket
            const openVmwareConsole = async (vmId) => {
                try {
                    const resp = await authFetch(`${API_URL}/vmware/${selectedVMware.id}/vms/${vmId}/console`, { method: 'POST' });
                    if (resp?.ok) {
                        const data = await resp.json();
                        // Priority: web_url (works in browser) > vmrc_url > url (websocket)
                        if (data.web_url) {
                            window.open(data.web_url, '_blank', 'width=1024,height=768,menubar=no,toolbar=no');
                            addToast(`Console opened for VM`, 'success');
                        } else if (data.vmrc_url) {
                            // Try VMRC protocol link
                            window.location.href = data.vmrc_url;
                            addToast('Opening VMRC...', 'info');
                        } else if (data.url) {
                            // WebSocket URL -- need WebMKS viewer (fallback: open ESXi UI)
                            const fallbackUrl = `https://${selectedVMware.host}/ui/`;
                            window.open(fallbackUrl, '_blank');
                            addToast('Console ticket obtained - opening vSphere UI', 'info');
                        } else {
                            // Direct fallback: open vSphere web UI
                            const directUrl = selectedVMware.server_type === 'esxi' 
                                ? `https://${selectedVMware.host}/ui/#/host/vms`
                                : `https://${selectedVMware.host}/ui/`;
                            window.open(directUrl, '_blank');
                            addToast('Opening vSphere web console', 'info');
                        }
                    } else {
                        const err = await resp?.json().catch(() => ({}));
                        // Fallback: just open the web UI
                        const directUrl = `https://${selectedVMware.host}/ui/`;
                        window.open(directUrl, '_blank');
                        addToast('Could not get ticket - opened vSphere UI instead', 'warning');
                    }
                } catch(e) { 
                    // Even on error, try to open the web UI
                    window.open(`https://${selectedVMware.host}/ui/`, '_blank');
                    addToast('Opening vSphere web UI', 'info');
                }
            };
            
            // LW: Check for updates on login (admins only)
            useEffect(() => {
                if (!isAdmin) return;
                
                const checkForUpdate = async () => {
                    try {
                        const resp = await fetch(`${API_URL}/pegaprox/check-update`, {
                            credentials: 'include',
                            headers: getAuthHeaders()
                        });
                        if (resp.ok) {
                            const data = await resp.json();
                            if (data.update_available) {
                                setPendingUpdate(data);
                                setShowUpdateNotification(true);
                            }
                        }
                    } catch (e) {
                        console.log('Update check failed:', e);
                    }
                };
                
                // Delay check slightly to let UI settle
                const timer = setTimeout(checkForUpdate, 2000);
                return () => clearTimeout(timer);
            }, [isAdmin]);

            useEffect(() => {
                // Reset data when switching clusters to avoid showing old data
                // NS: Always reset first, even if no cluster selected (prevents cross-cluster leaks)
                setClusterMetrics({});
                setClusterResources([]);
                setTasks([]);
                setKnownNodes({}); // NS: Clear known nodes when switching clusters
                setNodeAlerts({}); // Also clear node alerts
                setGlobalSnapshots([]); 
                setResourcesSubTab('management');
                setSnapshotFilterDate(''); 
                setSnapshotSortBy('age'); 
                setSnapshotSortDir('desc');
                
                if (selectedCluster) {
                    // Fetch new data
                    fetchClusterMetrics(selectedCluster.id);
                    fetchClusterResources(selectedCluster.id);
                    fetchMigrationLogs(selectedCluster.id);
                    fetchTasks(selectedCluster.id);
                    
                    // Auto-refresh polling
                    // NS: If SSE is connected, we poll less frequently as backup only
                    // SSE provides real-time updates, polling is just a fallback
                    const taskInterval = setInterval(() => {
                        // Skip polling if SSE just updated us (within last 3 seconds)
                        if (Date.now() - taskUpdateTimestamp.current < 3000) {
                            return;
                        }
                        fetchTasks(selectedCluster.id);
                    }, 5000);
                    
                    const resourceInterval = setInterval(() => {
                        fetchClusterMetrics(selectedCluster.id);
                        fetchClusterResources(selectedCluster.id);
                    }, 15000);
                    
                    const logsInterval = setInterval(() => {
                        fetchMigrationLogs(selectedCluster.id);
                    }, 30000);
                    
                    return () => {
                        clearInterval(taskInterval);
                        clearInterval(resourceInterval);
                        clearInterval(logsInterval);
                    };
                }
            }, [selectedCluster?.id]);

            const fetchClusters = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setClusters(data);
                        // NS: Use ref to avoid stale closure overriding "Alle Cluster" (null) selection
                        const currentSelected = selectedClusterRef.current;
                        if (currentSelected) {
                            const updated = data.find(c => c.id === currentSelected.id);
                            if (updated) setSelectedCluster(updated);
                        }
                        
                        // fetch status for all clusters (overview)
                        const connectedClusters = data.filter(c => c.connected);
                        const allGuests = [];
                        
                        for (const cluster of connectedClusters) {
                            try {
                                // datacenter status
                                const statusResp = await authFetch(`${API_URL}/clusters/${cluster.id}/datacenter/status`);
                                if (statusResp && statusResp.ok) {
                                    const statusData = await statusResp.json();
                                    setAllClusterMetrics(prev => ({
                                        ...prev,
                                        [cluster.id]: {
                                            data: statusData,
                                            lastUpdate: new Date()
                                        }
                                    }));
                                }
                                
                                // get vms/cts for the top guests table
                                const resourcesResp = await authFetch(`${API_URL}/clusters/${cluster.id}/resources`);
                                if (resourcesResp && resourcesResp.ok) {
                                    const resources = await resourcesResp.json();
                                    resources.filter(r => r.type === 'qemu' || r.type === 'lxc').forEach(r => {
                                        allGuests.push({
                                            ...r,
                                            cluster_id: cluster.id,
                                            cluster_name: cluster.display_name || cluster.name
                                        });
                                    });
                                }
                            } catch (e) {
                                console.log(`Failed to fetch data for cluster ${cluster.id}:`, e);
                            }
                        }
                        
                        // sort by combined cpu+ram usage
                        const runningGuests = allGuests.filter(g => g.status === 'running');
                        runningGuests.sort((a, b) => {
                            const aScore = ((a.cpu || 0) * 100) + (a.maxmem > 0 ? (a.mem / a.maxmem) * 100 : 0);
                            const bScore = ((b.cpu || 0) * 100) + (b.maxmem > 0 ? (b.mem / b.maxmem) * 100 : 0);
                            return bScore - aScore;
                        });
                        setTopGuests(runningGuests.slice(0, 10));
                    }
                } catch (error) {
                    console.error('fetching clusters:', error);
                }
            };
            
            // NS Jan 2026 - fetch cluster groups for sidebar display
            const fetchClusterGroups = async () => {
                try {
                    const response = await authFetch(`${API_URL}/cluster-groups`);
                    if (response && response.ok) {
                        setClusterGroups(await response.json());
                    }
                } catch (error) {
                    console.error('fetching cluster groups:', error);
                }
            };

            const fetchClusterMetrics = async (clusterId) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/metrics`);
                    if (response && response.ok) {
                        const data = await response.json();
                        
                        // Don't update if we got an error response
                        if (data.error) {
                            console.warn('Metrics returned error:', data.error);
                            return; // Keep old data
                        }
                        
                        setClusterMetrics(data);
                        
                        // NS: Also update knownNodes when fetching metrics
                        setKnownNodes(prev => {
                            const updated = { ...prev };
                            const now = new Date().toISOString();
                            
                            // Mark all nodes in metrics as online
                            Object.keys(data || {}).forEach(nodeName => {
                                // Skip error keys
                                if (nodeName === 'error' || nodeName === 'offline') return;
                                
                                updated[nodeName] = {
                                    status: 'online',
                                    lastSeen: now,
                                    metrics: data[nodeName]
                                };
                            });
                            
                            // DON'T mark nodes as offline just because they're missing from metrics
                            // This could be a temporary connection issue - let HA events handle this
                            
                            return updated;
                        });
                    } else if (response && response.status === 503) {
                        // Cluster temporarily offline - don't clear data
                        console.warn('Cluster temporarily offline, keeping cached data');
                    }
                } catch (error) {
                    console.error('fetching metrics:', error);
                    // Don't update state on error - keep old data
                }
            };

            const fetchClusterResources = async (clusterId) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/resources`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setClusterResources(data);
                        // MK: Store in window for access from ConfigModal reassign feature
                        window.pegaproxVmList = data;
                        setLastUpdate(new Date());
                        
                        // NS: Also track nodes from resources - this includes offline nodes!
                        const nodeResources = (data || []).filter(r => r.type === 'node');
                        if (nodeResources.length > 0) {
                            setKnownNodes(prev => {
                                const updated = { ...prev };
                                const now = new Date().toISOString();
                                
                                nodeResources.forEach(nodeRes => {
                                    const nodeName = nodeRes.node;
                                    const isOnline = nodeRes.status === 'online';
                                    
                                    if (isOnline) {
                                        updated[nodeName] = {
                                            status: 'online',
                                            lastSeen: now,
                                            resourceData: nodeRes
                                        };
                                    } else if (!updated[nodeName] || updated[nodeName].status === 'online') {
                                        // Node went offline or is new and offline
                                        updated[nodeName] = {
                                            ...updated[nodeName],
                                            status: 'offline',
                                            offlineSince: updated[nodeName]?.lastSeen || now,
                                            resourceData: nodeRes
                                        };
                                    }
                                });
                                
                                return updated;
                            });
                        }
                    }
                } catch (error) {
                    // silently fail, will retry on next interval
                }
            };

            // LW: Feb 2026 - fetch metrics+resources for sidebar expansion of non-selected clusters
            const fetchSidebarClusterData = async (clusterId) => {
                try {
                    const [metricsRes, resourcesRes] = await Promise.all([
                        authFetch(`${API_URL}/clusters/${clusterId}/metrics`),
                        authFetch(`${API_URL}/clusters/${clusterId}/resources`)
                    ]);
                    const metrics = metricsRes && metricsRes.ok ? await metricsRes.json() : {};
                    const resources = resourcesRes && resourcesRes.ok ? await resourcesRes.json() : [];
                    setSidebarClusterData(prev => ({ ...prev, [clusterId]: { metrics, resources } }));
                } catch (e) { console.error('sidebar fetch:', e); }
            };

            // LW: Feb 2026 - toggle sidebar cluster expansion
            const toggleSidebarCluster = (clusterId) => {
                setExpandedSidebarClusters(prev => {
                    const next = { ...prev };
                    if (next[clusterId]) { delete next[clusterId]; }
                    else {
                        next[clusterId] = true;
                        // Fetch data if not the selected cluster (selected has data from clusterMetrics)
                        if (!selectedCluster || selectedCluster.id !== clusterId) {
                            fetchSidebarClusterData(clusterId);
                        }
                    }
                    return next;
                });
            };

            const fetchMigrationLogs = async (clusterId) => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/migrations`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setMigrationLogs(data);
                    }
                } catch (e) {}  // dont care if this fails
            };

            const handleAddCluster = async (config) => {
                setLoading(true);
                setError(null);
                
                try {
                    const response = await authFetch(`${API_URL}/clusters`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config)
                    });
                    
                    if (response && response.ok) {
                        await fetchClusters();
                        setShowAddModal(false);
                        addToast(t('clusterAdded') || 'Cluster added successfully');
                    } else {
                        const err = await response.json();
                        setError(err.error || t('connectionFailed'));
                    }
                } catch (error) {
                    setError(t('connectionError') + ': ' + error.message);
                }
                setLoading(false);
            };

            const handleDeleteCluster = async (clusterId) => {
                if (!window.confirm(t('deleteClusterConfirm'))) return;
                
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}`, { method: 'DELETE' });
                    if (response && response.ok) {
                        await fetchClusters();
                        if (selectedCluster?.id === clusterId) setSelectedCluster(null);
                        addToast(t('clusterDeleted') || 'Cluster deleted');
                    }
                } catch (error) {
                    addToast(t('deleteError') || 'Delete error', 'error');
                }
            };

            // Debounced config update - batches rapid changes
            const pendingConfigUpdates = useRef({});
            const configUpdateTimer = useRef(null);
            
            const updateConfig = (key, value) => {
                if (!selectedCluster) return;
                
                // Special handling for HA enable/disable
                if (key === 'ha_enabled') {
                    handleHAToggle(value);
                    return;
                }
                
                // update local state immediately for responsive UI
                setSelectedCluster(prev => prev ? {...prev, [key]: value} : prev);
                
                // Batch the update
                pendingConfigUpdates.current[key] = value;
                
                // Debounce the API call
                if (configUpdateTimer.current) {
                    clearTimeout(configUpdateTimer.current);
                }
                
                configUpdateTimer.current = setTimeout(async () => {
                    const updates = {...pendingConfigUpdates.current};
                    pendingConfigUpdates.current = {};
                    
                    try {
                        const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/config`, {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(updates)
                        });
                        
                        if (response && response.ok) {
                            // Don't refetch - we already updated local state
                            addToast(t('settingsSaved') || 'Settings saved');
                        } else {
                            // Revert on error
                            fetchClusters();
                            addToast(t('saveError') || 'Error saving', 'error');
                        }
                    } catch (error) {
                        fetchClusters();
                        addToast(t('saveError') || 'Error saving', 'error');
                    }
                }, 500); // Wait 500ms after last change before saving
            };
            
            const handleHAToggle = async (enable) => {
                if (!selectedCluster) return;
                
                try {
                    const endpoint = enable ? 'enable' : 'disable';
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/ha/${endpoint}`, {
                        method: 'POST'
                    });
                    
                    if (response && response.ok) {
                        setSelectedCluster(prev => prev ? {...prev, ha_enabled: enable} : prev);
                        addToast(enable ? t('haEnabled') : t('haDisabled'));
                        
                        // Also update the clusters list
                        setClusters(prev => prev.map(c => 
                            c.id === selectedCluster.id ? {...c, ha_enabled: enable} : c
                        ));
                    } else {
                        const err = await response?.json();
                        addToast(err?.error || t('operationFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('operationFailed'), 'error');
                }
            };

            const handleMaintenanceToggle = async (nodeName, enable) => {
                if (!selectedCluster) return;
                
                try {
                    if (enable) {
                        addToast(`${t('startingMaintenanceMode') || 'Starting maintenance mode'}: ${nodeName}...`, 'info');
                        const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/nodes/${nodeName}/maintenance`, {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ enable: true })
                        });
                        
                        if (response && response.ok) {
                            addToast(`${t('maintenanceModeEnabled') || 'Maintenance mode enabled'}: ${nodeName}`);
                            await fetchClusterMetrics(selectedCluster.id);
                        } else {
                            const err = await response.json();
                            addToast(err.error || t('activationError') || 'Activation error', 'error');
                        }
                    } else {
                        const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/nodes/${nodeName}/maintenance`, {
                            method: 'DELETE'
                        });
                        
                        if (response && response.ok) {
                            addToast(`${t('nodeMaintenanceExited') || 'Maintenance mode exited'}: ${nodeName}`);
                            await fetchClusterMetrics(selectedCluster.id);
                        } else {
                            const err = await response.json();
                            addToast(err.error || t('deactivationError') || 'Deactivation error', 'error');
                        }
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleStartUpdate = async (nodeName, reboot) => {
                if (!selectedCluster) return;
                
                try {
                    addToast(t('startingUpdateFor') + ` ${nodeName}...`, 'info');
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/nodes/${nodeName}/update`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ reboot })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('updateStartedFor') + ` ${nodeName}`);
                        await fetchClusterMetrics(selectedCluster.id);
                    } else {
                        const err = await response.json();
                        addToast(err.error || t('errorStartingUpdate'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleNodeAction = async (nodeName, action) => {
                if (!selectedCluster) return;
                
                try {
                    const actionText = action === 'reboot' ? t('rebootNode') : t('shutdownNode');
                    addToast(`${actionText}: ${nodeName}...`, 'info');
                    
                    const response = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/nodes/${nodeName}/action/${action}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    
                    if (response && response.ok) {
                        addToast(`${nodeName} ${action === 'reboot' ? t('rebootInitiated') : t('shutdownInitiated')}`, 'success');
                        await fetchClusterMetrics(selectedCluster.id);
                    } else {
                        const err = await response.json();
                        if (err.error?.includes('sudo')) {
                            addToast(t('sudoNotAvailable'), 'error');
                        } else {
                            addToast(err.error || t('nodeActionFailed'), 'error');
                        }
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleVmAction = async (resource, action) => {
                const cId = resource._clusterId || selectedCluster?.id;
                if (!cId) return;
                
                // LW: Optimistic UI update - show expected status immediately
                // This makes the UI feel much snappier while we wait for Proxmox
                const expectedStatus = {
                    'start': 'running',
                    'stop': 'stopped',
                    'shutdown': 'stopped',
                    'reboot': 'running',
                    'reset': 'running',
                    'suspend': 'suspended',
                    'resume': 'running'
                };
                
                if (expectedStatus[action]) {
                    setClusterResources(prev => 
                        prev.map(r => 
                            r.vmid === resource.vmid && r.node === resource.node 
                                ? { ...r, status: expectedStatus[action], _optimistic: true }
                                : r
                        )
                    );
                }
                
                // LW: Feb 2026 - track task for corporate panel
                const taskId = addRecentTask(`${action} VM`, resource.name || `VM ${resource.vmid}`, 'running');
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${cId}/vms/${resource.node}/${resource.type}/${resource.vmid}/${action}`,
                        { method: 'POST' }
                    );

                    if (response && response.ok) {
                        addToast(`${action} ${t('successful') || 'successful'}: ${resource.name || resource.vmid}`);
                        updateRecentTask(taskId, 'completed');
                        // NS: SSE push_immediate_update will send real status within 500ms
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || `${action} ${t('actionFailed')}`, 'error');
                        updateRecentTask(taskId, 'failed');
                        fetchClusterResources(selectedCluster.id);
                    } else {
                        addToast(t('connectionError'), 'error');
                        updateRecentTask(taskId, 'failed');
                        fetchClusterResources(selectedCluster.id);
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                    updateRecentTask(taskId, 'failed');
                    // Revert optimistic update on error
                    fetchClusterResources(selectedCluster.id);
                }
            };

            const handleMigrate = async (vm, targetNode, online, options = {}) => {
                const cId = vm._clusterId || selectedCluster?.id;
                if (!cId) return;
                // NS: Feb 2026 - Track migration task
                const taskId = addRecentTask('Migrate VM', `${vm.name || vm.vmid} → ${targetNode}`, 'running');
                try {
                    addToast(t('startingMigration') + ` ${vm.name || vm.vmid}...`);
                    const response = await authFetch(
                        `${API_URL}/clusters/${cId}/vms/${vm.node}/${vm.type}/${vm.vmid}/migrate`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                target: targetNode,
                                online,
                                targetstorage: options.targetStorage || null,
                                'with-local-disks': options.withLocalDisks || false,
                                force: options.forceConntrack || false
                            })
                        }
                    );

                    if (response && response.ok) {
                        addToast(t('migrationStarted') + ` ${vm.name || vm.vmid} ↑ ${targetNode}`);
                        updateRecentTask(taskId, 'completed');
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('migrationFailed'), 'error');
                        updateRecentTask(taskId, 'failed');
                    } else {
                        addToast(t('connectionError'), 'error');
                        updateRecentTask(taskId, 'failed');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                    updateRecentTask(taskId, 'failed');
                }
            };

            const handleBulkMigrate = async (vms, targetNode, online) => {
                if (!selectedCluster) return;
                
                try {
                    addToast(`${t('startingBulkMigration')} ${vms.length} VMs...`);
                    const response = await authFetch(
                        `${API_URL}/clusters/${selectedCluster.id}/vms/bulk-migrate`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ vms, target: targetNode, online })
                        }
                    );
                    
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(`${result.successful}/${result.total} ${t('migrationsStarted') || 'migrations started'}`);
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 3000);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('bulkMigrationFailed'), 'error');
                    } else {
                        addToast(t('connectionError'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleCreateVm = async (vmType, node, config) => {
                if (!selectedCluster) return;
                
                try {
                    const endpoint = vmType === 'qemu' ? 'qemu' : 'lxc';
                    const response = await authFetch(
                        `${API_URL}/clusters/${selectedCluster.id}/nodes/${node}/${endpoint}`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(config)
                        }
                    );
                    
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(`${vmType === 'qemu' ? 'VM' : 'Container'} ${result.vmid} ${t('created') || 'created'}`);
                        setShowCreateVm(null);
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 2000);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('creationFailed'), 'error');
                    } else {
                        addToast(t('connectionError'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleDeleteVm = async (vm, options = {}) => {
                const cId = vm._clusterId || selectedCluster?.id;
                if (!cId) return;

                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${cId}/vms/${vm.node}/${vm.type}/${vm.vmid}`,
                        {
                            method: 'DELETE',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(options)
                        }
                    );
                    
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(result.message || `${vm.type === 'qemu' ? 'VM' : 'Container'} ${vm.vmid} deleted`);
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 2000);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Delete failed', 'error');
                    } else {
                        addToast(t('connectionError'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleCloneVm = async (vm, cloneConfig) => {
                const cId = vm._clusterId || selectedCluster?.id;
                if (!cId) return;

                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${cId}/vms/${vm.node}/${vm.type}/${vm.vmid}/clone`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                newid: parseInt(cloneConfig.newid),
                                name: cloneConfig.name,
                                full: cloneConfig.full,
                                target_node: cloneConfig.target_node,
                                description: cloneConfig.description
                            })
                        }
                    );
                    
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(result.message || `${t('cloneStarted') || 'Clone started'}: ${vm.vmid} ↑ ${cloneConfig.newid}`);
                        setShowCloneModal(null);
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 3000);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('cloneFailed'), 'error');
                    } else {
                        addToast(t('connectionError'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleForceStop = async (resource) => {
                const cId = resource._clusterId || selectedCluster?.id;
                if (!cId) return;

                if (!confirm(`${resource.name || resource.vmid} ${t('forceStopConfirm')}`)) return;

                setActionLoading(prev => ({...prev, [`${resource.vmid}-stop`]: true}));

                const url = `${API_URL}/clusters/${cId}/vms/${resource.node}/${resource.type}/${resource.vmid}/stop`;
                console.log('Force Stop URL:', url);
                console.log('Force Stop body:', JSON.stringify({ force: true }));
                
                try {
                    const response = await authFetch(url, { 
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ force: true })
                    });
                    
                    console.log('Force Stop response:', response);
                    
                    if (response && response.ok) {
                        addToast(`${resource.name || resource.vmid} ${t('forceStopping')}`);
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 2000);
                    } else if (response) {
                        const err = await response.json();
                        console.log('Force Stop error:', err);
                        addToast(err.error || t('forceStopFailed'), 'error');
                    } else {
                        console.log('No response from authFetch');
                        addToast(t('connectionFailed'), 'error');
                    }
                } catch (error) {
                    console.error('Force Stop exception:', error);
                    addToast(t('connectionError'), 'error');
                }
                
                setActionLoading(prev => ({...prev, [`${resource.vmid}-stop`]: false}));
            };

            const handleCrossClusterMigrate = async (migrationConfig) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/cross-cluster-migrate`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(migrationConfig)
                        }
                    );
                    
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(result.message || t('crossClusterStarted'));
                        setTimeout(() => fetchClusterResources(selectedCluster.id), 5000);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('crossClusterFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const [consoleVm, setConsoleVm] = useState(null);
            const [consoleInfo, setConsoleInfo] = useState(null);
            const [corpMetricsVm, setCorpMetricsVm] = useState(null); // LW: Feb 2026 - metrics modal for corporate view
            const [configVm, setConfigVm] = useState(null);
            const [configNode, setConfigNode] = useState(null);
            const [showRemoveNodeDash, setShowRemoveNodeDash] = useState(false);
            const [nodeToRemoveDash, setNodeToRemoveDash] = useState(null);
            const [showMoveNodeDash, setShowMoveNodeDash] = useState(false);
            const [nodeToMoveDash, setNodeToMoveDash] = useState(null);

            const handleOpenConsole = async (resource) => {
                const cId = resource._clusterId || selectedCluster?.id;
                if (!cId) return;
                // NS: Feb 2026 - Use correct cluster's host for cross-cluster console
                const cluster = clusters.find(c => c.id === cId) || selectedCluster;
                setConsoleInfo({
                    vmid: resource.vmid,
                    node: resource.node,
                    type: resource.type,
                    host: cluster?.host
                });
                setConsoleVm(resource);
            };

            const handleCloseConsole = () => {
                setConsoleVm(null);
                setConsoleInfo(null);
            };

            const handleOpenConfig = (resource) => {
                setConfigVm(resource);
            };

            const handleCloseConfig = () => {
                // NS: Feb 2026 - Refresh correct cluster's resources after config changes
                const cId = configVm?._clusterId || selectedCluster?.id;
                setConfigVm(null);
                if (cId) fetchClusterResources(cId);
            };

            return (
                <div className="min-h-screen bg-proxmox-darker text-white">
                    {/* LW: Password Expiry Warning */}
                    <PasswordExpiryBanner onChangePassword={() => setShowProfile(true)} />
                    
                    {/* Node Offline Alert Banner */}
                    <NodeAlertBanner 
                        alerts={nodeAlerts} 
                        currentClusterId={selectedCluster?.id}
                        onDismiss={(nodeName) => setNodeAlerts(prev => {
                            const newAlerts = { ...prev };
                            delete newAlerts[nodeName];
                            return newAlerts;
                        })}
                    />
                    
                    {/* Background gradient mesh - hidden in corporate mode via CSS */}
                    {!isCorporate && <div className="fixed inset-0 gradient-mesh pointer-events-none" />}
                    
                    {/* LW: Feb 2026 - header, compact in corporate */}
                    <header className={`sticky top-0 z-30 border-b border-proxmox-border ${isCorporate ? 'bg-proxmox-darker' : 'bg-proxmox-dark/80 backdrop-blur-xl'}`}>
                        <div className={`${isCorporate ? 'max-w-full px-3 py-1.5' : 'max-w-[1600px] mx-auto px-6 py-4'}`}>
                            <div className="flex items-center justify-between">
                                {/* MK: Click logo to return to All Clusters Overview */}
                                <div className="flex items-center gap-3">
                                <button
                                    onClick={() => { setSelectedCluster(null); setSelectedPBS(null); setSelectedVMware(null); }}
                                    className={`flex items-center ${isCorporate ? 'gap-2' : 'gap-4'} hover:opacity-80 transition-opacity`}
                                    title={t('allClustersOverview') || 'All Clusters Overview'}
                                >
                                    {/* PegaProx Logo */}
                                    <img
                                        src="/images/pegaprox.png"
                                        alt="PegaProx"
                                        className={`${isCorporate ? 'w-6 h-6' : 'w-10 h-10 rounded-xl'} object-contain`}
                                        onError={(e) => {
                                            e.target.style.display = 'none';
                                            e.target.nextSibling.style.display = 'flex';
                                        }}
                                    />
                                    <div className={`${isCorporate ? 'w-6 h-6 bg-proxmox-orange' : 'w-10 h-10 rounded-xl bg-gradient-to-br from-proxmox-orange to-orange-600 shadow-lg glow-orange'} items-center justify-center hidden`}>
                                        <svg viewBox="0 0 24 24" className={`${isCorporate ? 'w-3.5 h-3.5' : 'w-6 h-6'} text-white`} fill="currentColor">
                                            <path d="M12 2C9.5 2 7 3.5 6 6c-1.5 0-3 1-3 3 0 1.5 1 2.5 2 3l1 6c0 1 1 2 2 2h8c1 0 2-1 2-2l1-6c1-.5 2-1.5 2-3 0-2-1.5-3-3-3-1-2.5-3.5-4-6-4zm0 2c2 0 3.5 1 4 3H8c.5-2 2-3 4-3zM5 9h14c.5 0 1 .5 1 1s-.5 1.5-1 2l-1 5H6l-1-5c-.5-.5-1-1-1-2s.5-1 1-1zm7 1a2 2 0 100 4 2 2 0 000-4z"/>
                                        </svg>
                                    </div>
                                    {isCorporate ? (
                                        <span className="text-sm font-semibold">PegaProx</span>
                                    ) : (
                                        <div className="text-left">
                                            <h1 className="text-xl font-bold">PegaProx</h1>
                                            <p className="text-xs text-gray-500">{t('clusterManagement')}</p>
                                        </div>
                                    )}
                                </button>
                                {/* LW: Feb 2026 - corporate breadcrumb */}
                                {isCorporate && (
                                    <div className="flex items-center gap-1 text-[13px] text-gray-400 ml-1 border-l border-proxmox-border pl-3">
                                        <span className="hover:text-white cursor-pointer" onClick={() => { setSelectedCluster(null); setSelectedPBS(null); setSelectedVMware(null); setSelectedGroup(null); }}>
                                            {t('breadcrumbAll') || 'All'}
                                        </span>
                                        {(selectedGroup || selectedCluster || selectedPBS || selectedVMware) && (
                                            <><Icons.ChevronRight className="w-3 h-3 text-gray-600" /><span className={selectedCluster || selectedPBS || selectedVMware ? 'hover:text-white cursor-pointer' : 'text-gray-200'}>{selectedGroup?.name || selectedCluster?.name || selectedPBS?.name || selectedVMware?.name}</span></>
                                        )}
                                        {selectedCluster && selectedGroup && (
                                            <><Icons.ChevronRight className="w-3 h-3 text-gray-600" /><span className="text-gray-200">{selectedCluster.name}</span></>
                                        )}
                                        {activeTab && selectedCluster && (
                                            <><Icons.ChevronRight className="w-3 h-3 text-gray-600" /><span className={(selectedSidebarVm || selectedSidebarNode) ? 'hover:text-white cursor-pointer' : 'text-gray-300'} onClick={() => { if (selectedSidebarVm) setSelectedSidebarVm(null); if (selectedSidebarNode) setSelectedSidebarNode(null); }}>{t(activeTab)}</span></>
                                        )}
                                        {selectedSidebarVm && activeTab === 'resources' && (
                                            <><Icons.ChevronRight className="w-3 h-3 text-gray-600" /><span className="text-gray-200">{selectedSidebarVm.name || `VM ${selectedSidebarVm.vmid}`}</span></>
                                        )}
                                        {selectedSidebarNode && activeTab === 'overview' && (
                                            <><Icons.ChevronRight className="w-3 h-3 text-gray-600" /><span className="text-gray-200">{selectedSidebarNode.name}</span></>
                                        )}
                                    </div>
                                )}
                                </div>
                                <div className={`flex items-center ${isCorporate ? 'gap-2 flex-1 justify-end' : 'gap-3'}`}>
                                    {/* NS: Global Search - now with tag search + ctrl+k, LW: wider in corporate */}
                                    <div className={`relative ${isCorporate ? 'flex-1' : ''}`}>
                                        <div className={`flex items-center ${isCorporate ? 'bg-[#17242b]' : 'bg-proxmox-dark'} border border-proxmox-border rounded-lg overflow-hidden focus-within:border-proxmox-orange/50 transition-colors`}>
                                            <Icons.Search className="w-4 h-4 ml-3 text-gray-500 flex-shrink-0" />
                                            <input
                                                ref={globalSearchRef}
                                                type="text"
                                                placeholder={isCorporate ? (t('searchAllInventories') || 'Search in all inventories...') : (t('searchAllClusters') || 'Search all clusters...')}
                                                value={globalSearchQuery}
                                                onChange={(e) => {
                                                    setGlobalSearchQuery(e.target.value);
                                                    debouncedSearch(e.target.value);
                                                }}
                                                onFocus={() => setShowGlobalSearch(true)}
                                                onKeyDown={(e) => {
                                                    const items = globalSearchResults?.results || [];
                                                    if (e.key === 'ArrowDown') {
                                                        e.preventDefault();
                                                        setGlobalSearchIndex(prev => Math.min(prev + 1, Math.min(items.length - 1, 19)));
                                                    } else if (e.key === 'ArrowUp') {
                                                        e.preventDefault();
                                                        setGlobalSearchIndex(prev => Math.max(prev - 1, 0));
                                                    } else if (e.key === 'Enter' && items.length > 0) {
                                                        e.preventDefault();
                                                        navigateToResult(items[globalSearchIndex]);
                                                    } else if (e.key === 'Escape') {
                                                        setShowGlobalSearch(false);
                                                        e.target.blur();
                                                    }
                                                }}
                                                className={`${isCorporate ? 'w-48 md:w-72 lg:w-96 px-2 py-1.5' : 'w-48 md:w-72 lg:w-80 px-2 py-2'} bg-transparent text-white placeholder-gray-500 focus:outline-none text-sm`}
                                            />
                                            {globalSearchLoading ? (
                                                <Icons.RotateCw className="w-4 h-4 mr-3 text-gray-400 animate-spin flex-shrink-0" />
                                            ) : (
                                                <kbd className="hidden md:inline-flex mr-3 px-1.5 py-0.5 text-xs text-gray-500 bg-proxmox-secondary rounded border border-proxmox-border flex-shrink-0">
                                                    {navigator.platform?.includes('Mac') ? '⌘' : 'Ctrl+'}K
                                                </kbd>
                                            )}
                                        </div>
                                        
                                        {/* Search Results Dropdown */}
                                        {showGlobalSearch && globalSearchResults && (
                                            <>
                                                <div className="fixed inset-0 z-40" onClick={() => setShowGlobalSearch(false)} />
                                                <div className="absolute top-full right-0 md:left-0 mt-2 w-[28rem] max-h-[32rem] overflow-y-auto bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl z-50">
                                                    {/* Header with count and prefix hints */}
                                                    <div className="p-3 border-b border-proxmox-border">
                                                        <div className="flex justify-between items-center">
                                                            <span className="text-sm text-gray-400">
                                                                {globalSearchResults.count} {t('results') || 'results'}
                                                                {globalSearchResults.query?.startsWith('tag:') && ' (Tag-Suche)'}
                                                            </span>
                                                            <button onClick={() => setShowGlobalSearch(false)} className="text-gray-500 hover:text-white">
                                                                <Icons.X className="w-4 h-4" />
                                                            </button>
                                                        </div>
                                                        {/* MK: clickable tag pills for quick filtering */}
                                                        {globalSearchResults.tag_suggestions?.length > 0 && !globalSearchQuery.startsWith('tag:') && (
                                                            <div className="flex flex-wrap gap-1 mt-2">
                                                                <span className="text-xs text-gray-500 mr-1">Tags:</span>
                                                                {globalSearchResults.tag_suggestions.slice(0, 6).map((tag, i) => (
                                                                    <button key={i} onClick={() => {
                                                                        setGlobalSearchQuery(`tag:${tag}`);
                                                                        performGlobalSearch(`tag:${tag}`);
                                                                    }} className="px-1.5 py-0.5 text-xs rounded bg-proxmox-orange/20 text-proxmox-orange hover:bg-proxmox-orange/30 transition-colors">
                                                                        {tag}
                                                                    </button>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                    {globalSearchResults.results.length === 0 ? (
                                                        <div className="p-6 text-center text-gray-500">
                                                            <Icons.Search className="mx-auto mb-2 opacity-50" />
                                                            <p>{t('noResults') || 'No results'}</p>
                                                            <p className="text-xs mt-2 text-gray-600">
                                                                Tipp: tag:web, node:pve1, ip:192.168
                                                            </p>
                                                        </div>
                                                    ) : (
                                                        <div className="divide-y divide-proxmox-border">
                                                            {globalSearchResults.results.slice(0, 20).map((result, idx) => (
                                                                <div
                                                                    key={idx}
                                                                    className={`p-3 hover:bg-proxmox-hover cursor-pointer flex items-center gap-3 transition-colors ${idx === globalSearchIndex ? 'bg-proxmox-orange/10 border-l-2 border-proxmox-orange' : 'border-l-2 border-transparent'}`}
                                                                    onClick={() => navigateToResult(result)}
                                                                    onMouseEnter={() => setGlobalSearchIndex(idx)}
                                                                >
                                                                    <span className="text-lg flex-shrink-0">
                                                                        {result.type === 'node' ? '🖧' : result.type === 'ct' ? '📦' : '🖥️'}
                                                                    </span>
                                                                    <div className="flex-1 min-w-0">
                                                                        <div className="flex items-center gap-2 flex-wrap">
                                                                            <span className="font-medium truncate">{result.name}</span>
                                                                            {result.vmid && (
                                                                                <span className="text-xs text-gray-500">#{result.vmid}</span>
                                                                            )}
                                                                            <span className={`px-1.5 py-0.5 text-xs rounded ${
                                                                                result.status === 'running' ? 'bg-green-500/20 text-green-400' :
                                                                                result.status === 'stopped' ? 'bg-gray-500/20 text-gray-400' :
                                                                                'bg-yellow-500/20 text-yellow-400'
                                                                            }`}>
                                                                                {result.status}
                                                                            </span>
                                                                            {result.match_field === 'tag' && (
                                                                                <span className="px-1.5 py-0.5 text-xs rounded bg-purple-500/20 text-purple-400">Tag-Match</span>
                                                                            )}
                                                                        </div>
                                                                        <div className="text-xs text-gray-500 flex items-center gap-2 mt-0.5">
                                                                            <span>{result.cluster_name}</span>
                                                                            {result.node && <span>• {result.node}</span>}
                                                                            {result.ip && <span>• {result.ip}</span>}
                                                                        </div>
                                                                        {/* tags - highlight matching ones in orange */}
                                                                        {result.tags && (
                                                                            <div className="flex flex-wrap gap-1 mt-1">
                                                                                {result.tags.split(';').filter(t => t.trim()).slice(0, 4).map((tag, i) => (
                                                                                    <span key={i} className={`px-1.5 py-0.5 text-xs rounded ${
                                                                                        globalSearchQuery.toLowerCase().replace('tag:', '').split(',').some(q => tag.trim().toLowerCase().includes(q.trim()))
                                                                                        ? 'bg-proxmox-orange/30 text-proxmox-orange ring-1 ring-proxmox-orange/50'
                                                                                        : 'bg-proxmox-dark text-gray-400'
                                                                                    }`}>
                                                                                        {tag.trim()}
                                                                                    </span>
                                                                                ))}
                                                                                {result.tags.split(';').filter(t => t.trim()).length > 4 && (
                                                                                    <span className="px-1.5 py-0.5 text-xs rounded bg-proxmox-dark text-gray-500">
                                                                                        +{result.tags.split(';').filter(t => t.trim()).length - 4}
                                                                                    </span>
                                                                                )}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                    <button
                                                                        onClick={(e) => {
                                                                            e.stopPropagation();
                                                                            toggleFavorite(result.type, result.cluster_id, result.vmid, result.type === 'vm' ? 'qemu' : 'lxc', result.name);
                                                                        }}
                                                                        className="p-1 hover:bg-proxmox-dark rounded text-gray-500 hover:text-yellow-400 flex-shrink-0"
                                                                        title={t('toggleFavorite') || 'Toggle favorite'}
                                                                    >
                                                                        <Icons.Star className={`w-4 h-4 ${isFavorite(result.type, result.cluster_id, result.vmid, result.name) ? 'fill-yellow-400 text-yellow-400' : ''}`} />
                                                                    </button>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                    {/* Keyboard hints */}
                                                    {globalSearchResults.results.length > 0 && (
                                                        <div className="p-2 border-t border-proxmox-border text-xs text-gray-500 flex items-center gap-3">
                                                            <span className="flex items-center gap-1">
                                                                <kbd className="px-1 py-0.5 bg-proxmox-dark rounded text-gray-400">↑↓</kbd>
                                                                navigate
                                                            </span>
                                                            <span className="flex items-center gap-1">
                                                                <kbd className="px-1.5 py-0.5 bg-proxmox-dark rounded text-gray-400">↵</kbd>
                                                                {t('pressEnterToOpen') || 'jump to VM'}
                                                            </span>
                                                            <span className="flex items-center gap-1">
                                                                <kbd className="px-1 py-0.5 bg-proxmox-dark rounded text-gray-400">esc</kbd>
                                                                close
                                                            </span>
                                                        </div>
                                                    )}
                                                    {/* Keyboard hint */}
                                                    {globalSearchResults.results.length > 0 && (
                                                        <div className="p-2 border-t border-proxmox-border text-xs text-gray-500 flex items-center gap-2">
                                                            <kbd className="px-1.5 py-0.5 bg-proxmox-dark rounded text-gray-400">↑µ</kbd>
                                                            <span>{t('pressEnterToOpen') || 'Press Enter to jump to VM'}</span>
                                                        </div>
                                                    )}
                                                </div>
                                            </>
                                        )}
                                    </div>
                                    
                                    {/* language switcher + settings */}
                                    <LanguageSwitcher />

                                    {isAdmin && (
                                        <button
                                            onClick={() => setShowSettings(true)}
                                            className={`${isCorporate ? 'p-1.5' : 'p-2.5'} bg-proxmox-dark border border-proxmox-border rounded-lg hover:border-proxmox-orange/50 transition-colors text-gray-400 hover:text-white`}
                                            title={t('pegaproxSettings')}
                                        >
                                            <Icons.Settings className={isCorporate ? 'w-4 h-4' : undefined} />
                                        </button>
                                    )}

                                    {/* Live Status Indicator (corporate: status in bottom panel) */}
                                    {!isCorporate && (
                                        <div className="flex items-center gap-2 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" title={wsConnected ? 'Live-Updates aktiv' : 'Polling-Modus'}>
                                            <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`}></div>
                                            <span className="text-xs text-gray-400 hidden sm:inline">{wsConnected ? 'Live' : 'Polling'}</span>
                                        </div>
                                    )}

                                    {/* Add Cluster Dropdown (corporate: via sidebar or right-click) */}
                                    {!isCorporate && isAdmin && (
                                        <div className="relative">
                                            <button
                                                onClick={() => setShowAddDropdown(!showAddDropdown)}
                                                className="flex items-center gap-2 px-4 py-2.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg font-medium transition-all hover:shadow-lg hover:shadow-proxmox-orange/25"
                                            >
                                                <Icons.Plus />
                                                <span>{t('addCluster')}</span>
                                                <Icons.ChevronDown className="w-3.5 h-3.5 ml-0.5 opacity-70" />
                                            </button>
                                            {showAddDropdown && (
                                                <>
                                                    <div className="fixed inset-0 z-40" onClick={() => setShowAddDropdown(false)} />
                                                    <div className="absolute right-0 top-full mt-2 w-64 bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl z-50 overflow-hidden animate-scale-in">
                                                        {[
                                                            { id: 'proxmox', label: 'Proxmox VE', desc: t('pveClusterDesc') || 'Virtual machines & containers', icon: Icons.Server, color: 'text-orange-400', bg: 'bg-orange-500/10' },
                                                            { id: 'pbs', label: 'Proxmox Backup Server', desc: t('pbsDesc') || 'Backup management', icon: Icons.Shield, color: 'text-blue-400', bg: 'bg-blue-500/10' },
                                                            { id: 'vmware', label: 'ESXi', desc: t('vmwareDesc') || 'ESXi infrastructure', icon: Icons.Cloud, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
                                                        ].map(item => (
                                                            <button
                                                                key={item.id}
                                                                onClick={() => {
                                                                    setAddClusterType(item.id);
                                                                    setShowAddDropdown(false);
                                                                    setShowAddModal(true);
                                                                }}
                                                                className="w-full flex items-center gap-3 px-4 py-3 hover:bg-proxmox-dark/80 transition-colors text-left"
                                                            >
                                                                <div className={`p-2 rounded-lg ${item.bg}`}>
                                                                    <item.icon className={`w-4 h-4 ${item.color}`} />
                                                                </div>
                                                                <div>
                                                                    <div className="text-sm font-medium text-white">{item.label}</div>
                                                                    <div className="text-xs text-gray-500">{item.desc}</div>
                                                                </div>
                                                            </button>
                                                        ))}
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                    )}
                                    
                                    {/* Task Bar Toggle - disabled for debugging */}
                                    {false && !showTaskBar && tasks.length > 0 && (
                                        <button
                                            onClick={() => setShowTaskBar(true)}
                                            className="relative flex items-center gap-2 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg hover:border-proxmox-orange/50 transition-colors"
                                            title={t('tasks')}
                                        >
                                            <Icons.Layers />
                                            {tasks.filter(task => task && task.status === 'running').length > 0 && (
                                                <span className="absolute -top-1 -right-1 w-4 h-4 bg-blue-500 rounded-full text-xs flex items-center justify-center animate-pulse">
                                                    {tasks.filter(task => task && task.status === 'running').length}
                                                </span>
                                            )}
                                            {tasks.filter(task => task && (task.status === 'failed' || task.status === 'error')).length > 0 && (
                                                <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-xs flex items-center justify-center">
                                                    {tasks.filter(task => task && (task.status === 'failed' || task.status === 'error')).length}
                                                </span>
                                            )}
                                        </button>
                                    )}
                                    
                                    {/* LW: Feb 2026 - user menu, compact in corporate */}
                                    <div className="relative z-50">
                                        <button
                                            onClick={() => setShowUserMenu(!showUserMenu)}
                                            className={`flex items-center gap-2 ${isCorporate ? 'px-2 py-1' : 'px-3 py-2'} bg-proxmox-dark border border-proxmox-border rounded-lg hover:border-proxmox-orange/50 transition-colors`}
                                        >
                                            <div className={`${isCorporate ? 'w-6 h-6 text-[11px]' : 'w-8 h-8'} rounded-full bg-proxmox-orange/20 flex items-center justify-center text-proxmox-orange font-semibold`}>
                                                {user?.username?.[0]?.toUpperCase() || 'U'}
                                            </div>
                                            {!isCorporate && <span className="text-sm text-gray-300 hidden sm:inline">{user?.display_name || user?.username}</span>}
                                            <Icons.ChevronDown className={isCorporate ? 'w-3 h-3' : undefined} />
                                        </button>
                                        
                                        {showUserMenu && (
                                            <>
                                                <div className="fixed inset-0 z-40" onClick={() => setShowUserMenu(false)} />
                                                <div className="absolute right-0 top-full mt-2 w-56 bg-proxmox-card border border-proxmox-border rounded-xl shadow-xl z-50 overflow-hidden">
                                                    <div className="p-3 border-b border-proxmox-border">
                                                        <p className="font-medium text-white">{user?.display_name || user?.username}</p>
                                                        <p className="text-xs text-gray-400">{user?.role === 'admin' ? t('roleAdmin') : user?.role === 'user' ? t('roleUser') : t('roleViewer')}</p>
                                                    </div>
                                                    <div className="py-1">
                                                        <button
                                                            onClick={() => {
                                                                setShowUserMenu(false);
                                                                setShowProfile(true);
                                                            }}
                                                            className="w-full px-4 py-2 text-left text-gray-300 hover:bg-proxmox-hover transition-colors flex items-center gap-2"
                                                        >
                                                            <Icons.User />
                                                            {t('myProfile')}
                                                        </button>
                                                        {isAdmin && (
                                                            <button
                                                                onClick={() => {
                                                                    setShowUserMenu(false);
                                                                    setShowSettings(true);
                                                                }}
                                                                className="w-full px-4 py-2 text-left text-gray-300 hover:bg-proxmox-hover transition-colors flex items-center gap-2"
                                                            >
                                                                <Icons.Settings />
                                                                {t('pegaproxSettings')}
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => {
                                                                setShowUserMenu(false);
                                                                logout();
                                                            }}
                                                            className="w-full px-4 py-2 text-left text-red-400 hover:bg-red-500/10 transition-colors flex items-center gap-2"
                                                        >
                                                            <Icons.LogOut />
                                                            {t('logout')}
                                                        </button>
                                                    </div>
                                                </div>
                                            </>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </header>

                    {/* LW: Feb 2026 - corporate warning banner */}
                    {isCorporate && !warningBannerDismissed && (() => {
                        const alertMessages = [];
                        const offlineAlerts = Object.values(nodeAlerts || {}).filter(a => a.status === 'offline');
                        if (offlineAlerts.length > 0) alertMessages.push(`${offlineAlerts.length} node(s) offline`);
                        const disconnected = clusters.filter(c => c.connected === false);
                        if (disconnected.length > 0) alertMessages.push(`${disconnected.length} cluster(s) disconnected`);
                        if (alertMessages.length === 0) return null;
                        return (
                            <div className="corp-warning-banner">
                                <div className="flex items-center gap-2">
                                    <Icons.AlertTriangle className="w-4 h-4 flex-shrink-0" style={{color: '#efc006'}} />
                                    <span>{alertMessages.join(' | ')}</span>
                                </div>
                                <button className="corp-warning-dismiss" onClick={() => setWarningBannerDismissed(true)}>
                                    {t('dismiss') || 'DISMISS'}
                                </button>
                            </div>
                        );
                    })()}

                    <div className={`relative ${isCorporate ? 'max-w-full mx-0 px-0 py-0' : 'max-w-[1600px] mx-auto px-6 py-6'}`}>
                        <div className={`flex ${isCorporate ? 'gap-0' : 'gap-6'}`}>
                            {/* LW: Feb 2026 - sidebar, resizable in corporate */}
                            <div className={`${isCorporate ? 'flex-shrink-0 corporate-sidebar' : 'w-72 flex-shrink-0'}`} style={isCorporate ? {width: sidebarWidth + 'px'} : undefined}>
                                <div className={`sticky top-6 ${isCorporate ? 'space-y-0.5 px-1 py-2' : 'space-y-3 pr-1'} pb-4`} style={{ maxHeight: 'calc(100vh - 3rem)', overflowY: 'auto', overflowX: 'hidden', scrollbarWidth: 'thin', scrollbarColor: '#4a4a4a transparent' }}>
                                    {/* LW: Feb 2026 - group management header, compact in corporate */}
                                    <div className="flex items-center justify-between px-1">
                                        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">{t('clusters')}</h2>
                                        {isAdmin && (
                                            isCorporate ? (
                                                <button
                                                    onClick={() => { setAddClusterType('proxmox'); setShowAddModal(true); }}
                                                    className="p-0.5 text-gray-600 hover:text-gray-300 transition-colors"
                                                    title={t('addCluster') || 'Add Cluster'}
                                                >
                                                    <Icons.Plus className="w-3 h-3" />
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() => setShowGroupManager(true)}
                                                    className="p-1 text-gray-500 hover:text-proxmox-orange rounded transition-colors"
                                                    title={t('manageGroups') || 'Manage Groups'}
                                                >
                                                    <Icons.FolderPlus className="w-4 h-4" />
                                                </button>
                                            )
                                        )}
                                    </div>
                                    
                                    {clusters.length === 0 ? (
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 text-center">
                                            <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-proxmox-dark flex items-center justify-center">
                                                <Icons.Server />
                                            </div>
                                            <p className="text-gray-400 text-sm">{t('noClusterSelected')}</p>
                                            <button
                                                onClick={() => setShowAddModal(true)}
                                                className="mt-3 text-proxmox-orange text-sm hover:underline"
                                            >
                                                {t('addFirstCluster')}
                                            </button>
                                        </div>
                                    ) : (
                                        <div className="space-y-3">
                                            {/* MK: overview button, LW: compact for corporate */}
                                            <button
                                                onClick={() => { setSelectedCluster(null); setSelectedPBS(null); setSelectedVMware(null); setSelectedGroup(null); }}
                                                className={`w-full flex items-center ${
                                                    isCorporate
                                                        ? 'gap-1.5 pl-1 pr-2 py-0.5 text-[13px] leading-5'
                                                        : `gap-3 px-3 py-2.5 rounded-xl transition-all ${
                                                            !selectedCluster && !selectedPBS && !selectedVMware && !selectedGroup
                                                                ? 'bg-gradient-to-r from-proxmox-orange/20 to-orange-600/10 border border-proxmox-orange/30 text-white'
                                                                : 'bg-proxmox-card border border-proxmox-border hover:border-proxmox-orange/30 text-gray-300 hover:text-white'
                                                          }`
                                                }`}
                                                style={isCorporate ? (!selectedCluster && !selectedPBS && !selectedVMware && !selectedGroup ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}) : undefined}
                                                onMouseEnter={isCorporate ? (e) => { if (selectedCluster || selectedPBS || selectedVMware || selectedGroup) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }} : undefined}
                                                onMouseLeave={isCorporate ? (e) => { if (selectedCluster || selectedPBS || selectedVMware || selectedGroup) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }} : undefined}
                                            >
                                                {isCorporate ? (
                                                    <Icons.Database className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                ) : (
                                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                                                        !selectedCluster && !selectedPBS && !selectedVMware && !selectedGroup ? 'bg-proxmox-orange/20' : 'bg-proxmox-dark'
                                                    }`}>
                                                        <Icons.Grid className="w-4 h-4" />
                                                    </div>
                                                )}
                                                <span className={isCorporate ? 'flex-1 text-left truncate' : 'flex-1 text-left'}>
                                                    {isCorporate ? (t('allClusters') || 'All Clusters') : (
                                                        <div>
                                                            <div className="text-sm font-medium">{t('allClusters') || 'All Clusters'}</div>
                                                            <div className="text-xs text-gray-500">{clusters.length} {t('clusters').toLowerCase()}</div>
                                                        </div>
                                                    )}
                                                </span>
                                                {!isCorporate && !selectedCluster && !selectedPBS && !selectedVMware && !selectedGroup && (
                                                    <div className="w-2 h-2 rounded-full bg-proxmox-orange" />
                                                )}
                                            </button>
                                            
                                            {/* Grouped Clusters */}
                                            {clusterGroups.map(group => {
                                                const groupClusters = clusters.filter(c => c.group_id === group.id);
                                                if (groupClusters.length === 0) return null;

                                                const isCollapsed = collapsedGroups[group.id];

                                                return (
                                                    <div key={group.id} className="space-y-2">
                                                        {/* Group Header - NS: split chevron vs folder click */}
                                                        <div className={`w-full flex items-center gap-2 px-2 ${isCorporate ? 'py-1' : 'py-1.5 rounded-lg'} hover:bg-proxmox-hover transition-colors ${
                                                            selectedGroup?.id === group.id ? (isCorporate ? 'bg-proxmox-hover text-white' : 'bg-proxmox-orange/5 border-l-2 border-l-proxmox-orange') : ''
                                                        }`}>
                                                            {/* NS: chevron toggles collapse */}
                                                            <button
                                                                onClick={() => setCollapsedGroups(prev => ({...prev, [group.id]: !prev[group.id]}))}
                                                                className="w-4 h-4 flex items-center justify-center text-gray-500 hover:text-white"
                                                            >
                                                                {isCollapsed ? <Icons.ChevronRight className="w-3 h-3" /> : <Icons.ChevronDown className="w-3 h-3" />}
                                                            </button>
                                                            {/* MK: clicking the folder name opens group overlay */}
                                                            <button
                                                                onClick={() => { setSelectedGroup(group); setSelectedCluster(null); setSelectedPBS(null); setSelectedVMware(null); }}
                                                                className={`flex items-center gap-2 flex-1 text-left ${selectedGroup?.id === group.id ? 'text-white' : 'text-gray-300 hover:text-white'}`}
                                                            >
                                                                <Icons.Folder className="w-4 h-4" style={{ color: group.color || '#E86F2D' }} />
                                                                <span className="text-sm flex-1">{group.name}</span>
                                                            </button>
                                                            <span className="text-xs text-gray-500">{groupClusters.length}</span>
                                                        </div>
                                                        
                                                        {/* Group Clusters */}
                                                        {!isCollapsed && (
                                                            <div className={isCorporate ? 'ml-5 space-y-0' : 'ml-4 space-y-1.5'}>
                                                                {groupClusters.map((cluster, idx) => (
                                                                    <React.Fragment key={cluster.id}>
                                                                        <ClusterSidebarItem
                                                                            cluster={cluster}
                                                                            idx={idx}
                                                                            selectedCluster={selectedCluster}
                                                                            setSelectedCluster={setSelectedCluster}
                                                                            nodeAlerts={nodeAlerts}
                                                                            clusterGroups={clusterGroups}
                                                                            isAdmin={isAdmin}
                                                                            handleDeleteCluster={handleDeleteCluster}
                                                                            setShowAssignGroup={setShowAssignGroup}
                                                                            t={t}
                                                                            getAuthHeaders={getAuthHeaders}
                                                                            fetchClusters={fetchClusters}
                                                                            addToast={addToast}
                                                                            isCorporate={isCorporate}
                                                                            expandedSidebarClusters={expandedSidebarClusters}
                                                                            toggleSidebarCluster={toggleSidebarCluster}
                                                                        />
                                                                        {renderInlineNodeTree(cluster.id)}
                                                                    </React.Fragment>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })}
                                            
                                            {/* Ungrouped Clusters */}
                                            {(() => {
                                                const ungroupedClusters = clusters.filter(c => !c.group_id || !clusterGroups.find(g => g.id === c.group_id));
                                                if (ungroupedClusters.length === 0) return null;
                                                
                                                return (
                                                    <div className={isCorporate ? 'space-y-0' : 'space-y-1.5'}>
                                                        {clusterGroups.length > 0 && (
                                                            <div className={`flex items-center gap-2 px-2 ${isCorporate ? 'py-0.5' : 'py-1.5'} text-gray-500`}>
                                                                <Icons.Server className={isCorporate ? 'w-3.5 h-3.5' : 'w-4 h-4'} />
                                                                <span className="text-xs uppercase tracking-wider">{t('ungrouped')}</span>
                                                            </div>
                                                        )}
                                                        {ungroupedClusters.map((cluster, idx) => (
                                                            <React.Fragment key={cluster.id}>
                                                                <ClusterSidebarItem
                                                                    cluster={cluster}
                                                                    idx={idx}
                                                                    selectedCluster={selectedCluster}
                                                                    setSelectedCluster={setSelectedCluster}
                                                                    nodeAlerts={nodeAlerts}
                                                                    clusterGroups={clusterGroups}
                                                                    isAdmin={isAdmin}
                                                                    handleDeleteCluster={handleDeleteCluster}
                                                                    setShowAssignGroup={setShowAssignGroup}
                                                                    t={t}
                                                                    getAuthHeaders={getAuthHeaders}
                                                                    fetchClusters={fetchClusters}
                                                                    addToast={addToast}
                                                                    isCorporate={isCorporate}
                                                                    expandedSidebarClusters={expandedSidebarClusters}
                                                                    toggleSidebarCluster={toggleSidebarCluster}
                                                                />
                                                                {renderInlineNodeTree(cluster.id)}
                                                            </React.Fragment>
                                                        ))}
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                    )}

                                {/* LW: Feb 2026 - Proxmox Backup Servers */}
                                {pbsServers.length > 0 && (
                                    <div className="mt-4 pt-4 border-t border-proxmox-border">
                                        <div className="flex items-center justify-between px-1 mb-2">
                                            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Backup Servers</h2>
                                            {isAdmin && (
                                                <button onClick={() => setShowAddPBS(true)} className="p-1 text-gray-500 hover:text-proxmox-orange rounded transition-colors" title="Add PBS">
                                                    <Icons.Plus className="w-4 h-4" />
                                                </button>
                                            )}
                                        </div>
                                        <div className="space-y-1.5">
                                            {pbsServers.map(pbs => (
                                                <button
                                                    key={pbs.id}
                                                    onClick={() => { setSelectedPBS(pbs); setSelectedCluster(null); setSelectedVMware(null); setPbsActiveTab('dashboard'); setPbsSelectedStore(null); }}
                                                    className={isCorporate
                                                        ? 'w-full flex items-center gap-1.5 pl-3 pr-2 py-0.5 text-[13px] leading-5'
                                                        : `w-full flex items-center gap-3 px-3 py-2 rounded-xl transition-all ${
                                                            selectedPBS?.id === pbs.id && !selectedCluster
                                                                ? 'bg-gradient-to-r from-blue-500/20 to-blue-600/10 border border-blue-500/30 text-white'
                                                                : 'bg-proxmox-card border border-proxmox-border hover:border-blue-500/30 text-gray-300 hover:text-white'
                                                          }`
                                                    }
                                                    style={isCorporate ? (selectedPBS?.id === pbs.id && !selectedCluster ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}) : undefined}
                                                    onMouseEnter={isCorporate ? (e) => { if (!(selectedPBS?.id === pbs.id && !selectedCluster)) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }} : undefined}
                                                    onMouseLeave={isCorporate ? (e) => { if (!(selectedPBS?.id === pbs.id && !selectedCluster)) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }} : undefined}
                                                >
                                                    {isCorporate ? (
                                                        <Icons.Shield className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                    ) : (
                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${selectedPBS?.id === pbs.id && !selectedCluster ? 'bg-blue-500/20' : 'bg-proxmox-dark'}`}>
                                                            <Icons.Shield className="w-4 h-4 text-blue-400" />
                                                        </div>
                                                    )}
                                                    <div className="flex-1 text-left min-w-0">
                                                        <div className={`${isCorporate ? 'text-[13px]' : 'text-sm'} font-medium truncate`}>{pbs.name}</div>
                                                        {!isCorporate && <div className="text-xs text-gray-500 truncate">{pbs.host}:{pbs.port}</div>}
                                                    </div>
                                                    <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{background: pbs.connected ? '#60b515' : '#f54f47'}} />
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                
                                {/* add PBS button - hidden in corporate */}
                                {!isCorporate && pbsServers.length === 0 && isAdmin && (
                                    <div className="mt-4 pt-4 border-t border-proxmox-border">
                                        <button onClick={() => setShowAddPBS(true)} className="w-full flex items-center gap-2 px-3 py-2 rounded-xl bg-proxmox-card border border-dashed border-proxmox-border text-gray-500 hover:text-blue-400 hover:border-blue-500/30 transition-all text-sm">
                                            <Icons.Shield className="w-4 h-4" />
                                            <span>Add Backup Server</span>
                                        </button>
                                    </div>
                                )}
                                
                                {/* VMware Servers */}
                                {vmwareServers.length > 0 && (
                                    <div className="mt-4 pt-4 border-t border-proxmox-border">
                                        <div className="flex items-center justify-between px-1 mb-2">
                                            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">ESXi</h2>
                                            {isAdmin && (
                                                <button onClick={() => { setEditingVMware(null); setVmwareForm({ name: '', host: '', port: 443, username: 'root', password: '', ssl_verify: false, notes: '' }); setShowAddVMware(true); }} className="p-1 text-gray-500 hover:text-proxmox-orange rounded transition-colors" title="Add ESXi Server">
                                                    <Icons.Plus className="w-4 h-4" />
                                                </button>
                                            )}
                                        </div>
                                        <div className="space-y-1.5">
                                            {vmwareServers.map(vmw => {
                                                const vmwSelected = selectedVMware?.id === vmw.id && !selectedCluster && !selectedPBS;
                                                return (
                                                <button
                                                    key={vmw.id}
                                                    onClick={() => { setSelectedVMware(vmw); setSelectedCluster(null); setSelectedPBS(null); setVmwareActiveTab('vms'); setVmwareSelectedVm(null); }}
                                                    className={isCorporate
                                                        ? 'w-full flex items-center gap-1.5 pl-3 pr-2 py-0.5 text-[13px] leading-5'
                                                        : `w-full flex items-center gap-3 px-3 py-2 rounded-xl transition-all ${
                                                            vmwSelected
                                                                ? 'bg-gradient-to-r from-emerald-500/20 to-green-600/10 border border-emerald-500/30 text-white'
                                                                : 'bg-proxmox-card border border-proxmox-border hover:border-emerald-500/30 text-gray-300 hover:text-white'
                                                          }`
                                                    }
                                                    style={isCorporate ? (vmwSelected ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}) : undefined}
                                                    onMouseEnter={isCorporate ? (e) => { if (!vmwSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }} : undefined}
                                                    onMouseLeave={isCorporate ? (e) => { if (!vmwSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }} : undefined}
                                                >
                                                    {isCorporate ? (
                                                        <Icons.Cloud className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                    ) : (
                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${vmwSelected ? 'bg-emerald-500/20' : 'bg-proxmox-dark'}`}>
                                                            <Icons.Cloud className="w-4 h-4 text-emerald-400" />
                                                        </div>
                                                    )}
                                                    <div className="flex-1 text-left min-w-0">
                                                        <div className={`${isCorporate ? 'text-[13px]' : 'text-sm'} font-medium truncate`}>{vmw.name || vmw.host}</div>
                                                        {!isCorporate && <div className="text-xs text-gray-500 truncate">{vmw.host}</div>}
                                                    </div>
                                                    <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{background: vmw.connected !== false ? '#60b515' : '#f54f47'}} />
                                                </button>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* LW: Feb 2026 - corporate VMware inventory tree */}
                                {isCorporate && selectedVMware && (vmwareHosts.length > 0 || vmwareVms.length > 0) && (
                                    <div className="mt-2 pt-2 border-t border-proxmox-border">
                                        <div className="flex items-center justify-between px-1 mb-1">
                                            <h2 className="text-[11px] font-semibold uppercase tracking-wider" style={{color: '#728b9a'}}>Hosts</h2>
                                            <span className="text-[11px]" style={{color: '#728b9a'}}>{vmwareHosts.length}</span>
                                        </div>
                                        <div className="space-y-0">
                                            {vmwareHosts
                                                .sort((a, b) => (a.name || '').localeCompare(b.name || ''))
                                                .map(host => {
                                                    const hostVms = vmwareVms.filter(vm => {
                                                        const vmHost = (vm.host || vm.host_name || '').split('.')[0];
                                                        const hName = (host.name || '').split('.')[0];
                                                        return vmHost === hName;
                                                    });
                                                    const isExpanded = expandedVmwareSidebarHosts[host.host_id || host.name];
                                                    const hostOnline = host.connection_state === 'CONNECTED' || host.connection_state === 'connected';
                                                    return (
                                                        <div key={host.host_id || host.name}>
                                                            <div className="flex items-center">
                                                                <button
                                                                    onClick={() => setExpandedVmwareSidebarHosts(prev => ({...prev, [host.host_id || host.name]: !prev[host.host_id || host.name]}))}
                                                                    className="w-4 h-4 flex items-center justify-center flex-shrink-0"
                                                                    style={{color: '#728b9a'}}
                                                                >
                                                                    {hostVms.length > 0 ? (
                                                                        isExpanded ? <Icons.ChevronDown className="w-3 h-3" /> : <Icons.ChevronRight className="w-3 h-3" />
                                                                    ) : <span className="w-3" />}
                                                                </button>
                                                                <div className="flex items-center gap-1.5 flex-1 pl-0.5 pr-2 py-0.5 text-[13px] leading-5 cursor-default"
                                                                    style={{color: hostOnline ? '#adbbc4' : '#728b9a'}}
                                                                >
                                                                    <Icons.Server className="w-3.5 h-3.5 flex-shrink-0" style={{color: hostOnline ? '#49afd9' : '#f54f47'}} />
                                                                    <span className="truncate flex-1">{(host.name || 'Unknown').split('.')[0]}</span>
                                                                    <span className="text-[11px] flex-shrink-0" style={{color: '#728b9a'}}>{hostVms.length}</span>
                                                                </div>
                                                            </div>
                                                            {isExpanded && hostVms.length > 0 && (
                                                                <div className="ml-4 border-l" style={{borderColor: '#485764'}}>
                                                                    {hostVms
                                                                        .sort((a, b) => (a.name || '').localeCompare(b.name || ''))
                                                                        .map(vm => {
                                                                            const vmId = vm.vm || vm.vm_id || vm.id;
                                                                            const isOn = vm.power_state === 'POWERED_ON';
                                                                            const isSuspended = vm.power_state === 'SUSPENDED';
                                                                            const isVmSelected = vmwareSelectedVm === vmId;
                                                                            return (
                                                                                <div
                                                                                    key={vmId}
                                                                                    onClick={() => { setVmwareSelectedVm(vmId); setVmwareActiveTab('vms'); }}
                                                                                    className="flex items-center gap-1.5 pl-3 pr-2 py-px text-[12px] leading-4 cursor-pointer"
                                                                                    style={isVmSelected
                                                                                        ? {background: '#324f61', color: '#e9ecef'}
                                                                                        : {color: '#adbbc4'}
                                                                                    }
                                                                                    onMouseEnter={(e) => { if (!isVmSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }}}
                                                                                    onMouseLeave={(e) => { if (!isVmSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }}}
                                                                                >
                                                                                    <span className="relative flex-shrink-0" style={{width: '14px', height: '14px'}}>
                                                                                        <Icons.Monitor className="w-3 h-3" style={{color: isOn ? '#60b515' : isSuspended ? '#efc006' : '#728b9a'}} />
                                                                                        {isOn && <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full" style={{background: '#60b515'}} />}
                                                                                    </span>
                                                                                    <span className="truncate flex-1">{vm.name || `VM ${vmId}`}</span>
                                                                                    <span className="text-[10px] flex-shrink-0" style={{color: '#728b9a'}}>{isOn ? 'ON' : isSuspended ? 'SUS' : 'OFF'}</span>
                                                                                </div>
                                                                            );
                                                                        })}
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })}
                                            {/* VMs without a known host */}
                                            {(() => {
                                                const orphanVms = vmwareVms.filter(vm => {
                                                    const vmHost = (vm.host || vm.host_name || '').split('.')[0];
                                                    return !vmHost || !vmwareHosts.some(h => (h.name || '').split('.')[0] === vmHost);
                                                });
                                                if (orphanVms.length === 0) return null;
                                                return (
                                                    <div>
                                                        <div className="flex items-center gap-1.5 pl-5 pr-2 py-0.5 text-[12px] leading-5" style={{color: '#728b9a'}}>
                                                            <Icons.Monitor className="w-3 h-3 flex-shrink-0" />
                                                            <span className="truncate flex-1 uppercase text-[11px] tracking-wider">Unassigned ({orphanVms.length})</span>
                                                        </div>
                                                        <div className="ml-4 border-l" style={{borderColor: '#485764'}}>
                                                            {orphanVms.sort((a, b) => (a.name || '').localeCompare(b.name || '')).map(vm => {
                                                                const vmId = vm.vm || vm.vm_id || vm.id;
                                                                const isOn = vm.power_state === 'POWERED_ON';
                                                                const isSuspended = vm.power_state === 'SUSPENDED';
                                                                const isVmSelected = vmwareSelectedVm === vmId;
                                                                return (
                                                                    <div
                                                                        key={vmId}
                                                                        onClick={() => { setVmwareSelectedVm(vmId); setVmwareActiveTab('vms'); }}
                                                                        className="flex items-center gap-1.5 pl-3 pr-2 py-px text-[12px] leading-4 cursor-pointer"
                                                                        style={isVmSelected ? {background: '#324f61', color: '#e9ecef'} : {color: '#adbbc4'}}
                                                                        onMouseEnter={(e) => { if (!isVmSelected) { e.currentTarget.style.background = '#29414e'; e.currentTarget.style.color = '#e9ecef'; }}}
                                                                        onMouseLeave={(e) => { if (!isVmSelected) { e.currentTarget.style.background = ''; e.currentTarget.style.color = '#adbbc4'; }}}
                                                                    >
                                                                        <span className="relative flex-shrink-0" style={{width: '14px', height: '14px'}}>
                                                                            <Icons.Monitor className="w-3 h-3" style={{color: isOn ? '#60b515' : isSuspended ? '#efc006' : '#728b9a'}} />
                                                                            {isOn && <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full" style={{background: '#60b515'}} />}
                                                                        </span>
                                                                        <span className="truncate flex-1">{vm.name || `VM ${vmId}`}</span>
                                                                        <span className="text-[10px] flex-shrink-0" style={{color: '#728b9a'}}>{isOn ? 'ON' : isSuspended ? 'SUS' : 'OFF'}</span>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                    </div>
                                )}

                                {/* add VMware button - hidden in corporate */}
                                {!isCorporate && vmwareServers.length === 0 && isAdmin && (
                                    <div className="mt-4 pt-4 border-t border-proxmox-border">
                                        <button onClick={() => { setEditingVMware(null); setVmwareForm({ name: '', host: '', port: 443, username: 'root', password: '', ssl_verify: false, notes: '' }); setShowAddVMware(true); }} className="w-full flex items-center gap-2 px-3 py-2 rounded-xl bg-proxmox-card border border-dashed border-proxmox-border text-gray-500 hover:text-emerald-400 hover:border-emerald-500/30 transition-all text-sm">
                                            <Icons.Cloud className="w-4 h-4" />
                                            <span>Add ESXi Server</span>
                                        </button>
                                    </div>
                                )}
                                </div>
                            </div>
                            {/* LW: sidebar resize handle */}
                            {isCorporate && (
                                <div className="corp-resize-handle" onMouseDown={handleSidebarResizeStart} title="Drag to resize" />
                            )}
                            <div className={`flex-1 min-w-0 ${isCorporate ? 'px-4 py-3' : ''}`}>
                                {selectedCluster ? (
                                    <div className={isCorporate ? 'space-y-3' : 'space-y-6'}>
                                        {/* LW: Feb 2026 - tabs, underline in corporate vs pills in modern */}
                                        <div className={isCorporate
                                            ? 'flex items-center border-b border-proxmox-border'
                                            : 'flex items-center gap-1 p-1 bg-proxmox-card border border-proxmox-border rounded-xl w-fit flex-wrap'
                                        }>
                                            {[
                                                { id: 'overview', labelKey: 'overview', icon: Icons.Activity },
                                                { id: 'resources', labelKey: 'resources', icon: Icons.Server },
                                                { id: 'datacenter', labelKey: 'datacenter', icon: Icons.HardDrive },
                                                { id: 'datastore', labelKey: 'datastore', icon: Icons.Database },
                                                { id: 'automation', labelKey: 'automation', icon: Icons.Zap },
                                                { id: 'reports', labelKey: 'reports', icon: Icons.BarChart },
                                                { id: 'settings', labelKey: 'settings', icon: Icons.Settings },
                                            ].map(tab => (
                                                <button
                                                    key={tab.id}
                                                    onClick={() => setActiveTab(tab.id)}
                                                    className={isCorporate
                                                        ? `flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px ${
                                                            activeTab === tab.id
                                                                ? 'border-blue-500 text-white font-medium'
                                                                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
                                                          }`
                                                        : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                                            activeTab === tab.id
                                                                ? 'bg-proxmox-orange text-white'
                                                                : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                          }`
                                                    }
                                                >
                                                    <tab.icon className={isCorporate ? 'w-3 h-3' : undefined} />
                                                    {t(tab.labelKey)}
                                                </button>
                                            ))}
                                        </div>

                                        {/* Overview Tab */}
                                        {activeTab === 'overview' && (
                                            isCorporate && selectedSidebarNode ? (
                                            <CorporateNodeDetailView
                                                node={selectedSidebarNode.name}
                                                clusterId={selectedSidebarNode.clusterId}
                                                clusterMetrics={selectedSidebarNode.clusterId === selectedCluster?.id ? clusterMetrics : (sidebarClusterData[selectedSidebarNode.clusterId]?.metrics || {})}
                                                clusterResources={selectedSidebarNode.clusterId === selectedCluster?.id ? clusterResources : (sidebarClusterData[selectedSidebarNode.clusterId]?.resources || [])}
                                                onBack={() => setSelectedSidebarNode(null)}
                                                onOpenNodeConfig={(nodeName) => setConfigNode(nodeName)}
                                                onMaintenanceToggle={handleMaintenanceToggle}
                                                onNodeAction={handleNodeAction}
                                                onStartUpdate={handleStartUpdate}
                                                onSelectVm={(vm) => { setSelectedSidebarVm({...vm, _clusterId: selectedSidebarNode.clusterId}); setSelectedSidebarNode(null); setActiveTab('resources'); setResourcesSubTab('management'); }}
                                                addToast={addToast}
                                            />
                                            ) : (
                                            <div className={isCorporate ? 'space-y-3' : 'grid grid-cols-1 xl:grid-cols-3 gap-6'}>
                                                <div className={isCorporate ? '' : 'xl:col-span-2 space-y-6'}>
                                                    {/* LW: Feb 2026 - corporate uses compact node rows */}
                                                    <div>
                                                        <h2 className={`font-semibold text-gray-400 uppercase tracking-wider ${isCorporate ? 'text-xs mb-2' : 'text-sm mb-4'}`}>{t('nodes')}</h2>
                                                        {isCorporate ? (
                                                        <div className="border border-proxmox-border bg-proxmox-card">
                                                            {/* Corporate: compact node rows */}
                                                            {Object.entries(clusterMetrics)
                                                                .sort(([a], [b]) => a.localeCompare(b))
                                                                .map(([node, metrics]) => (
                                                                <NodeCompactRow
                                                                    key={node}
                                                                    name={node}
                                                                    metrics={metrics}
                                                                    clusterId={selectedCluster.id}
                                                                    onOpenNodeConfig={(nodeName) => setConfigNode(nodeName)}
                                                                    onMaintenanceToggle={handleMaintenanceToggle}
                                                                    onStartUpdate={handleStartUpdate}
                                                                    onNodeAction={handleNodeAction}
                                                                    onRemoveNode={(nodeName) => { setNodeToRemoveDash({ name: nodeName }); setShowRemoveNodeDash(true); }}
                                                                    onMoveNode={(nodeName) => { setNodeToMoveDash(nodeName); setShowMoveNodeDash(true); }}
                                                                />
                                                            ))}
                                                            {/* Offline nodes compact */}
                                                            {Object.entries(knownNodes)
                                                                .filter(([nodeName, nodeData]) => nodeData.status === 'offline' && !clusterMetrics[nodeName])
                                                                .map(([nodeName]) => (
                                                                <NodeCompactRow key={`offline-${nodeName}`} name={nodeName} metrics={null} clusterId={selectedCluster.id} />
                                                            ))}
                                                            {Object.entries(nodeAlerts)
                                                                .filter(([nodeName, alert]) => alert.cluster_id === selectedCluster.id && !clusterMetrics[nodeName] && !knownNodes[nodeName]?.status)
                                                                .map(([nodeName]) => (
                                                                <NodeCompactRow key={`alert-${nodeName}`} name={nodeName} metrics={null} clusterId={selectedCluster.id} />
                                                            ))}
                                                        </div>
                                                        ) : (
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                            {/* Modern: full node cards */}
                                                            {Object.entries(clusterMetrics)
                                                                .sort(([a], [b]) => a.localeCompare(b))
                                                                .map(([node, metrics], idx) => (
                                                                <NodeCard
                                                                    key={node}
                                                                    name={node}
                                                                    metrics={metrics}
                                                                    index={idx}
                                                                    clusterId={selectedCluster.id}
                                                                    onMaintenanceToggle={handleMaintenanceToggle}
                                                                    onStartUpdate={handleStartUpdate}
                                                                    onOpenNodeConfig={(nodeName) => setConfigNode(nodeName)}
                                                                    onNodeAction={handleNodeAction}
                                                                    onRemoveNode={(nodeName) => { setNodeToRemoveDash({ name: nodeName }); setShowRemoveNodeDash(true); }}
                                                                    onMoveNode={(nodeName) => { setNodeToMoveDash(nodeName); setShowMoveNodeDash(true); }}
                                                                />
                                                            ))}
                                                            {/* Offline nodes from knownNodes */}
                                                            {Object.entries(knownNodes)
                                                                .filter(([nodeName, nodeData]) => nodeData.status === 'offline' && !clusterMetrics[nodeName])
                                                                .map(([nodeName, nodeData], idx) => (
                                                                <div 
                                                                    key={`offline-${nodeName}`}
                                                                    className="relative bg-proxmox-card border-2 border-red-500/50 rounded-xl p-4"
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
                                                                            <h3 className="font-semibold text-white">{nodeName}</h3>
                                                                            <p className="text-xs text-red-400">{t('nodeUnreachable') || 'Node unreachable'}</p>
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
                                                                    <div className="mt-4 pt-3 border-t border-red-500/30 text-xs text-red-400">
                                                                        <Icons.AlertTriangle className="inline w-3 h-3 mr-1" />
                                                                        {t('offlineSince') || 'Offline since'}: {nodeData.offlineSince ? new Date(nodeData.offlineSince).toLocaleTimeString() : 'Unknown'}
                                                                    </div>
                                                                    <div className="text-xs text-gray-500 mt-2">
                                                                        {t('lastSeen') || 'Last seen'}: {nodeData.lastSeen ? new Date(nodeData.lastSeen).toLocaleString() : 'Unknown'}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                            {/* Also show nodes from nodeAlerts (SSE events) - filter by cluster */}
                                                            {Object.entries(nodeAlerts)
                                                                .filter(([nodeName, alert]) => 
                                                                    alert.cluster_id === selectedCluster.id && 
                                                                    !clusterMetrics[nodeName] && 
                                                                    !knownNodes[nodeName]?.status
                                                                )
                                                                .map(([nodeName, alert], idx) => (
                                                                <div 
                                                                    key={`alert-${nodeName}`}
                                                                    className="relative bg-proxmox-card border-2 border-red-500/50 rounded-xl p-4 animate-pulse"
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
                                                                            <h3 className="font-semibold text-white">{nodeName}</h3>
                                                                            <p className="text-xs text-red-400">{t('nodeUnreachable') || 'Node unreachable'}</p>
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
                                                                    <div className="mt-4 pt-3 border-t border-red-500/30 text-xs text-red-400">
                                                                        <Icons.AlertTriangle className="inline w-3 h-3 mr-1" />
                                                                        {t('offlineSince') || 'Offline since'}: {new Date(alert.timestamp).toLocaleTimeString()}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                        )}
                                                        {Object.keys(clusterMetrics).length === 0 && Object.keys(nodeAlerts).length === 0 && (
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center">
                                                                {connectionError ? (
                                                                    <div className="text-red-400">
                                                                        <Icons.AlertTriangle className="mx-auto mb-2" />
                                                                        <p className="font-medium">{t('connectionError') || 'Connection Error'}</p>
                                                                        <p className="text-sm text-gray-500 mt-1">{connectionError}</p>
                                                                        <button 
                                                                            onClick={() => { setConnectionError(null); fetchClusterMetrics(selectedCluster.id); }}
                                                                            className="mt-3 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white"
                                                                        >
                                                                            {t('retry') || 'Retry'}
                                                                        </button>
                                                                    </div>
                                                                ) : (
                                                                    <div>
                                                                        <Icons.RotateCw className="mx-auto mb-2 animate-spin text-gray-500" />
                                                                        <p className="text-gray-500">{t('loadingMetrics') || 'Loading metrics...'}</p>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>

                                                <div className={isCorporate ? 'space-y-3' : 'space-y-6'}>
                                                    {/* Cluster Health */}
                                                    <ClusterHealth metrics={clusterMetrics} isCorporate={isCorporate} />

                                                    {/* Migration History */}
                                                    <div className={isCorporate
                                                        ? 'bg-proxmox-card border border-proxmox-border p-3'
                                                        : 'bg-proxmox-card border border-proxmox-border rounded-xl p-5'
                                                    }>
                                                        <h3 className={`font-semibold text-gray-400 uppercase tracking-wider ${isCorporate ? 'text-xs mb-2' : 'text-sm mb-4'}`}>
                                                            {t('lastMigrations')}
                                                        </h3>
                                                        <MigrationHistory logs={migrationLogs} />
                                                    </div>
                                                </div>
                                            </div>
                                            )
                                        )}

                                        {/* LW: Feb 2026 - resources tab with corporate sub-tabs */}
                                        {activeTab === 'resources' && (
                                            <div className={isCorporate ? 'space-y-2' : 'space-y-4'}>
                                                {/* LW: corporate VM detail when sidebar VM selected */}
                                                {isCorporate && selectedSidebarVm ? (
                                                    <CorporateVmDetailView
                                                        vm={selectedSidebarVm}
                                                        clusterId={selectedSidebarVm._clusterId || selectedCluster.id}
                                                        onAction={handleVmAction}
                                                        onOpenConsole={handleOpenConsole}
                                                        onOpenConfig={handleOpenConfig}
                                                        onBack={() => setSelectedSidebarVm(null)}
                                                        onMigrate={handleMigrate}
                                                        onClone={handleCloneVm}
                                                        onForceStop={handleForceStop}
                                                        onDelete={handleDeleteVm}
                                                        onCrossClusterMigrate={handleCrossClusterMigrate}
                                                        showCrossCluster={clusters.length > 1}
                                                        actionLoading={actionLoading}
                                                        onShowMetrics={(vm) => setCorpMetricsVm(vm)}
                                                        addToast={addToast}
                                                    />
                                                ) : (<>
                                                {/* Sub-Tab Navigation */}
                                                <div className={`flex items-center ${isCorporate ? 'border-b border-proxmox-border' : 'gap-1 border-b border-proxmox-border pb-2'}`}>
                                                    <button
                                                        onClick={() => setResourcesSubTab('management')}
                                                        className={isCorporate
                                                            ? 'flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px'
                                                            : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                                                                resourcesSubTab === 'management' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                              }`
                                                        }
                                                        style={isCorporate ? (resourcesSubTab === 'management' ? {borderColor: '#49afd9', color: '#e9ecef', fontWeight: 500} : {borderColor: 'transparent', color: '#adbbc4'}) : undefined}
                                                    >
                                                        <Icons.Server className={isCorporate ? 'w-3 h-3' : 'w-4 h-4'} />
                                                        {t('resourcesLabel') || 'Resources'}
                                                    </button>
                                                    <button
                                                        onClick={() => { setResourcesSubTab('snapshots'); fetchGlobalSnapshots(selectedCluster.id); }}
                                                        className={isCorporate
                                                            ? 'flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px'
                                                            : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                                                                resourcesSubTab === 'snapshots' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                              }`
                                                        }
                                                        style={isCorporate ? (resourcesSubTab === 'snapshots' ? {borderColor: '#49afd9', color: '#e9ecef', fontWeight: 500} : {borderColor: 'transparent', color: '#adbbc4'}) : undefined}
                                                    >
                                                        <Icons.Camera className={isCorporate ? 'w-3 h-3' : 'w-4 h-4'} />
                                                        {t('snapshotsOverview') || 'Snapshot Overview'}
                                                    </button>
                                                </div>
                                                
                                                {/* Resources Management Sub-Tab */}
                                                {/* LW: Resources management with VM table */}
                                                {resourcesSubTab === 'management' && (
                                                    <div className={isCorporate ? 'p-0' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6'}>
                                                        <ResourceTable 
                                                            resources={clusterResources} 
                                                            clusterId={selectedCluster.id}
                                                            clusters={clusters}
                                                            sourceCluster={selectedCluster}
                                                            onVmAction={handleVmAction}
                                                            onOpenConsole={handleOpenConsole}
                                                            onOpenConfig={handleOpenConfig}
                                                            onMigrate={handleMigrate}
                                                            onBulkMigrate={handleBulkMigrate}
                                                            onDelete={handleDeleteVm}
                                                            onClone={handleCloneVm}
                                                            onForceStop={handleForceStop}
                                                            onCrossClusterMigrate={handleCrossClusterMigrate}
                                                            nodes={Object.keys(clusterMetrics)}
                                                            onOpenTags={(resource) => {
                                                                loadVmTags(selectedCluster.id, resource.vmid);
                                                                loadClusterTags(selectedCluster.id);
                                                                setShowTagEditor({ 
                                                                    clusterId: selectedCluster.id, 
                                                                    vmid: resource.vmid, 
                                                                    vmName: resource.name || `VM ${resource.vmid}` 
                                                                });
                                                            }}
                                                            highlightedVm={highlightedVm}
                                                            addToast={addToast}
                                                        />
                                                        
                                                        {/* Create VM/CT Buttons */}
                                                        <div className={`flex gap-3 ${isCorporate ? 'mt-2' : 'mt-4'}`}>
                                                            <button
                                                                onClick={() => setShowCreateVm('qemu')}
                                                                className={isCorporate
                                                                    ? 'flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-[13px] text-white hover:bg-blue-700 border border-blue-700'
                                                                    : 'flex items-center gap-2 px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700 transition-colors'
                                                                }
                                                            >
                                                                <Icons.Plus className={isCorporate ? 'w-3 h-3' : ''} />
                                                                {t('createVm')}
                                                            </button>
                                                            <button
                                                                onClick={() => setShowCreateVm('lxc')}
                                                                className={isCorporate
                                                                    ? 'flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 text-[13px] text-white hover:bg-purple-700 border border-purple-700'
                                                                    : 'flex items-center gap-2 px-4 py-2 bg-purple-600 rounded-lg text-white hover:bg-purple-700 transition-colors'
                                                                }
                                                            >
                                                                <Icons.Plus className={isCorporate ? 'w-3 h-3' : ''} />
                                                                {t('createContainer')}
                                                            </button>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* Snapshot Overview Sub-Tab @gyptazy */}
                                                {resourcesSubTab === 'snapshots' && (
                                                    <div className={isCorporate
                                                        ? 'bg-proxmox-card border border-proxmox-border p-4 space-y-3'
                                                        : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6 space-y-4'
                                                    }>
                                                        <div className="flex items-center justify-between">
                                                            <div>
                                                                <h3 className="text-lg font-semibold text-white">{t('snapshotsOverview') || 'Snapshot Overview'}</h3>
                                                                <p className="text-sm text-gray-400 mt-1">
                                                                    {t('snapshotsDesc') || 'Overview of the oldest snapshots in this cluster'}
                                                                </p>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <input
                                                                    type="date"
                                                                    value={snapshotFilterDate}
                                                                    onChange={(e) => setSnapshotFilterDate(e.target.value)}
                                                                    className="rounded-lg bg-proxmox-dark border border-proxmox-border px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-proxmox-orange"
                                                                />
                                                                <button
                                                                    onClick={() => applySnapshotFilter(selectedCluster.id)}
                                                                    disabled={!snapshotFilterDate}
                                                                    className="rounded-lg bg-proxmox-orange px-4 py-2 text-sm font-medium text-white hover:bg-proxmox-orange/90 disabled:opacity-50 disabled:cursor-not-allowed"
                                                                >
                                                                    {t('filter') || 'Filter'}
                                                                </button>
                                                                <button
                                                                    onClick={() => fetchGlobalSnapshots(selectedCluster.id)}
                                                                    className="p-2 rounded-lg bg-proxmox-dark border border-proxmox-border text-gray-400 hover:text-white"
                                                                    title="Refresh"
                                                                >
                                                                    <Icons.RotateCw className="w-4 h-4" />
                                                                </button>
                                                            </div>
                                                        </div>

                                                        {!Array.isArray(sortedSnapshots) || sortedSnapshots.length === 0 ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Camera className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">
                                                                    {t('noSnapshots') || 'No snapshots found'}
                                                                </p>
                                                                <p className="text-xs text-gray-600 mt-2">
                                                                    {t('snapshotsHint') || 'Create snapshots on VMs to see them listed here'}
                                                                </p>
                                                            </div>
                                                        ) : (
                                                            <div className="overflow-x-auto bg-proxmox-dark rounded-xl border border-gray-800">
                                                                <table className="min-w-full text-sm">
                                                                    <thead className="bg-black/40 text-gray-400">
                                                                        <tr>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('vmid')}
                                                                            >
                                                                                VM ID {snapshotSortBy === 'vmid' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('vm_name')}
                                                                            >
                                                                                VM Name {snapshotSortBy === 'vm_name' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('vm_type')}
                                                                            >
                                                                                {t('snapshotsType') || 'Type'} {snapshotSortBy === 'vm_type' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('node')}
                                                                            >
                                                                                Node {snapshotSortBy === 'node' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('snapshot_name')}
                                                                            >
                                                                                Snapshot {snapshotSortBy === 'snapshot_name' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('snapshot_date')}
                                                                            >
                                                                                {t('snapshotsDate') || 'Created'} {snapshotSortBy === 'snapshot_date' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th 
                                                                                className="px-4 py-3 text-left cursor-pointer hover:text-white"
                                                                                onClick={() => toggleSnapshotSort('age')}
                                                                            >
                                                                                {t('snapshotsAge') || 'Age'} {snapshotSortBy === 'age' && (snapshotSortDir === 'asc' ? '↑' : '↓')}
                                                                            </th>
                                                                            <th className="px-4 py-3 text-right w-12">{t('snapshotsAction') || 'Action'}</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody className="divide-y divide-gray-800">
                                                                        {sortedSnapshots.map((snap, idx) => (
                                                                            <tr
                                                                                key={`${snap.vmid}-${snap.snapshot_name}-${idx}`}
                                                                                className="group hover:bg-white/5 transition-colors"
                                                                            >
                                                                                <td className="px-4 py-3 text-gray-300">{snap.vmid ?? '-'}</td>
                                                                                <td className="px-4 py-3 text-gray-200">{snap.vm_name ?? '-'}</td>
                                                                                <td className="px-4 py-3">
                                                                                    <span className={`px-2 py-1 rounded text-xs ${snap.vm_type === 'qemu' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'}`}>
                                                                                        {snap.vm_type === 'qemu' ? 'VM' : 'CT'}
                                                                                    </span>
                                                                                </td>
                                                                                <td className="px-4 py-3 text-gray-300">{snap.node ?? '-'}</td>
                                                                                <td className="px-4 py-3 font-mono text-gray-200">{snap.snapshot_name ?? '-'}</td>
                                                                                <td className="px-4 py-3 text-gray-300">{snap.snapshot_date ?? '-'}</td>
                                                                                <td className="px-4 py-3 text-yellow-400">{snap.age ?? '-'}</td>
                                                                                <td className="px-4 py-3 text-right">
                                                                                    <button
                                                                                        onClick={() => deleteGlobalSnapshot(snap, selectedCluster.id)}
                                                                                        className="opacity-0 group-hover:opacity-100 transition text-red-500 hover:text-red-400"
                                                                                        title="Delete snapshot"
                                                                                    >
                                                                                        <Icons.Trash className="w-4 h-4" />
                                                                                    </button>
                                                                                </td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                </>)}
                                            </div>
                                        )}

                                        {/* Datacenter Tab */}
                                        {activeTab === 'datacenter' && (
                                            <DatacenterTab clusterId={selectedCluster.id} addToast={addToast} />
                                        )}

                                        {/* Datastore Tab */}
                                        {activeTab === 'datastore' && (
                                            <DatastoreTab clusterId={selectedCluster.id} addToast={addToast} />
                                        )}

                                        {/* Automation Tab - NS Jan 2026 - Combines Schedules, Tags, Alerts, Affinity, Scripts */}
                                        {activeTab === 'automation' && (
                                            <div className="space-y-6">
                                                {/* LW: Feb 2026 - sub-tab nav, corporate underline style */}
                                                <div className={isCorporate
                                                    ? 'flex items-center border-b border-proxmox-border'
                                                    : 'flex items-center gap-1 border-b border-proxmox-border pb-2'
                                                }>
                                                    {[
                                                        { id: 'schedules', label: t('scheduledActions') || 'Schedules', icon: Icons.Clock },
                                                        { id: 'tags', label: t('tagsLabels') || 'Tags', icon: Icons.Tag },
                                                        { id: 'alerts', label: t('alerts') || 'Alerts', icon: Icons.Bell },
                                                        { id: 'affinity', label: t('affinityRules') || 'Affinity', icon: Icons.Link },
                                                        { id: 'scripts', label: t('customScripts') || 'Scripts', icon: Icons.Terminal }
                                                    ].map(sub => (
                                                        <button
                                                            key={sub.id}
                                                            onClick={() => setAutomationSubTab(sub.id)}
                                                            className={isCorporate
                                                                ? `flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px ${
                                                                    automationSubTab === sub.id
                                                                        ? 'border-blue-500 text-white font-medium'
                                                                        : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
                                                                  }`
                                                                : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                                                                    automationSubTab === sub.id
                                                                        ? 'bg-proxmox-orange text-white'
                                                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                                }`
                                                            }
                                                        >
                                                            <sub.icon className={isCorporate ? 'w-3 h-3' : 'w-4 h-4'} />
                                                            {sub.label}
                                                        </button>
                                                    ))}
                                                </div>
                                                
                                                {/* Schedules Sub-Tab */}
                                                {automationSubTab === 'schedules' && (
                                                    <div className="space-y-4">
                                                        <div className="flex justify-between items-center">
                                                            <p className="text-sm text-gray-400">{t('schedulesDesc') || 'Automatically start, stop, reboot or snapshot VMs on a schedule'}</p>
                                                            <button
                                                                onClick={() => { setEditingSchedule(null); setShowScheduleModal(true); }}
                                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                            >
                                                                <Icons.Plus /> {t('newSchedule') || 'New Schedule'}
                                                            </button>
                                                        </div>
                                                        
                                                        {schedules.filter(s => s.cluster_id === selectedCluster?.id).length === 0 ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Clock className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">{t('noSchedules') || 'No scheduled actions for this cluster'}</p>
                                                            </div>
                                                        ) : (
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                                <table className="w-full">
                                                                    <thead className="bg-proxmox-dark">
                                                                        <tr className="text-left text-xs text-gray-500 uppercase">
                                                                            <th className="p-3">{t('status') || 'Status'}</th>
                                                                            <th className="p-3">{t('name') || 'Name'}</th>
                                                                            <th className="p-3">VM</th>
                                                                            <th className="p-3">{t('action') || 'Action'}</th>
                                                                            <th className="p-3">{t('schedule') || 'Schedule'}</th>
                                                                            <th className="p-3">{t('lastRun') || 'Last Run'}</th>
                                                                            <th className="p-3 w-16"></th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody className="divide-y divide-proxmox-border">
                                                                        {schedules.filter(s => s.cluster_id === selectedCluster?.id).map(schedule => (
                                                                            <tr key={schedule.id} className="hover:bg-proxmox-hover">
                                                                                <td className="p-3">
                                                                                    <button
                                                                                        onClick={() => toggleScheduleEnabled(schedule.id, !schedule.enabled)}
                                                                                        className={`w-9 h-5 rounded-full relative transition-colors ${schedule.enabled ? 'bg-green-500' : 'bg-gray-600'}`}
                                                                                    >
                                                                                        <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${schedule.enabled ? 'left-4' : 'left-0.5'}`} />
                                                                                    </button>
                                                                                </td>
                                                                                <td className="p-3 font-medium">{schedule.name}</td>
                                                                                <td className="p-3 text-sm">{schedule.vm_type === 'lxc' ? '📦' : '🖥️'} {schedule.vmid}</td>
                                                                                <td className="p-3">
                                                                                    <span className={`px-2 py-1 rounded text-xs ${
                                                                                        schedule.action === 'start' ? 'bg-green-500/20 text-green-400' :
                                                                                        schedule.action === 'stop' ? 'bg-red-500/20 text-red-400' :
                                                                                        schedule.action === 'snapshot' ? 'bg-blue-500/20 text-blue-400' :
                                                                                        'bg-yellow-500/20 text-yellow-400'
                                                                                    }`}>{schedule.action}</span>
                                                                                </td>
                                                                                <td className="p-3 text-sm text-gray-400">
                                                                                    {schedule.time} • {schedule.schedule_type === 'daily' ? t('daily') || 'Daily' :
                                                                                     schedule.schedule_type === 'weekdays' ? t('weekdays') || 'Weekdays' :
                                                                                     schedule.schedule_type === 'weekends' ? t('weekends') || 'Weekends' :
                                                                                     schedule.schedule_type === 'weekly' ? (schedule.days || []).join(', ') :
                                                                                     schedule.date}
                                                                                </td>
                                                                                <td className="p-3 text-xs text-gray-500">
                                                                                    {schedule.last_run || '-'}
                                                                                    {schedule.run_count > 0 && ` (${schedule.run_count}x)`}
                                                                                </td>
                                                                                <td className="p-3">
                                                                                    <button onClick={() => deleteSchedule(schedule.id)} className="p-1 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400">
                                                                                        <Icons.Trash className="w-4 h-4" />
                                                                                    </button>
                                                                                </td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                
                                                {/* Tags Sub-Tab */}
                                                {automationSubTab === 'tags' && (
                                                    <div className="space-y-4">
                                                        <p className="text-sm text-gray-400">{t('tagsDesc') || 'Organize VMs with tags. Click the tag icon on any VM to add tags.'}</p>
                                                        
                                                        {clusterTags.length === 0 ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Tag className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">{t('noTagsInCluster') || 'No tags in this cluster yet'}</p>
                                                                <p className="text-xs text-gray-600 mt-2">{t('addTagHint') || 'Use the tag button on VMs in the Resources tab'}</p>
                                                            </div>
                                                        ) : (
                                                            <div className="space-y-4">
                                                                <div className="flex flex-wrap gap-2">
                                                                    {clusterTags.map((tag, idx) => (
                                                                        <span
                                                                            key={idx}
                                                                            className="flex items-center gap-2 px-3 py-1.5 rounded-full border"
                                                                            style={{ backgroundColor: (tag.color || '#6b7280') + '20', borderColor: tag.color || '#6b7280', color: tag.color || '#9ca3af' }}
                                                                        >
                                                                            {tag.name}
                                                                            <span className="text-xs opacity-60">({tag.count || 0})</span>
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                                <div className="text-xs text-gray-500">
                                                                    {clusterTags.length} {t('tagsTotal') || 'tags'} • {t('clickVmTag') || 'Click tag icon on VMs to manage'}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                
                                                {/* Alerts Sub-Tab */}
                                                {automationSubTab === 'alerts' && (
                                                    <div className="space-y-4">
                                                        <div className="flex justify-between items-center">
                                                            <p className="text-sm text-gray-400">{t('alertsDesc') || 'Get notified when resources exceed thresholds'}</p>
                                                            <button
                                                                onClick={() => setShowAlertModal(true)}
                                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                            >
                                                                <Icons.Plus /> {t('newAlert') || 'New Alert'}
                                                            </button>
                                                        </div>
                                                        
                                                        {clusterAlerts.length === 0 ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Bell className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">{t('noAlertsCluster') || 'No alerts for this cluster'}</p>
                                                            </div>
                                                        ) : (
                                                            <div className="space-y-2">
                                                                {clusterAlerts.map(alert => (
                                                                    <div key={alert.id} className={`flex items-center justify-between p-3 rounded-lg border ${alert.enabled ? 'bg-proxmox-dark border-proxmox-border' : 'bg-proxmox-darker border-proxmox-darker opacity-60'}`}>
                                                                        <div className="flex items-center gap-3">
                                                                            <button
                                                                                onClick={() => toggleAlertEnabled(alert.id, !alert.enabled)}
                                                                                className={`w-9 h-5 rounded-full relative transition-colors ${alert.enabled ? 'bg-green-500' : 'bg-gray-600'}`}
                                                                            >
                                                                                <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${alert.enabled ? 'left-4' : 'left-0.5'}`} />
                                                                            </button>
                                                                            <div>
                                                                                <div className="font-medium flex items-center gap-2">
                                                                                    {alert.name}
                                                                                    <span className={`px-1.5 py-0.5 text-xs rounded ${
                                                                                        alert.target_type === 'vm' ? 'bg-blue-500/20 text-blue-400' :
                                                                                        alert.target_type === 'node' ? 'bg-purple-500/20 text-purple-400' :
                                                                                        'bg-gray-500/20 text-gray-400'
                                                                                    }`}>
                                                                                        {alert.target_type === 'vm' ? `VM ${alert.target_id || ''}` :
                                                                                         alert.target_type === 'node' ? `Node ${alert.target_id || ''}` :
                                                                                         t('cluster') || 'Cluster'}
                                                                                    </span>
                                                                                </div>
                                                                                <div className="text-xs text-gray-500">
                                                                                    {alert.metric?.toUpperCase()} {alert.operator} {alert.threshold}%
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                        <button onClick={() => deleteClusterAlert(alert.id)} className="p-1.5 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400">
                                                                            <Icons.Trash className="w-4 h-4" />
                                                                        </button>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                
                                                {/* Affinity Sub-Tab */}
                                                {automationSubTab === 'affinity' && (
                                                    <div className="space-y-4">
                                                        <div className="flex justify-between items-center">
                                                            <p className="text-sm text-gray-400">{t('affinityDesc') || 'Keep VMs together or separate across nodes'}</p>
                                                            <button
                                                                onClick={() => setShowAffinityModal(true)}
                                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                            >
                                                                <Icons.Plus /> {t('newRule') || 'New Rule'}
                                                            </button>
                                                        </div>
                                                        
                                                        {clusterAffinityRules.length === 0 ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Link className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">{t('noAffinityCluster') || 'No affinity rules for this cluster'}</p>
                                                            </div>
                                                        ) : (
                                                            <div className="space-y-2">
                                                                {clusterAffinityRules.map(rule => (
                                                                    <div key={rule.id} className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                                        <div className="flex items-center gap-3">
                                                                            <span className={`px-2 py-1 rounded text-xs ${rule.type === 'together' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                                                                {rule.type === 'together' ? t('together') || 'Together' : t('separate') || 'Separate'}
                                                                            </span>
                                                                            {rule.enforce && <span className="px-1.5 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">{t('enforced') || 'Enforced'}</span>}
                                                                            <span className="text-sm text-white font-medium">{rule.name || rule.id}</span>
                                                                            <span className="text-sm text-gray-400">VMs: {(rule.vm_ids || rule.vms || []).join(', ')}</span>
                                                                        </div>
                                                                        <button onClick={() => deleteClusterAffinityRule(rule.id)} className="p-1.5 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400">
                                                                            <Icons.Trash className="w-4 h-4" />
                                                                        </button>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                
                                                {/* Custom Scripts Sub-Tab */}
                                                {automationSubTab === 'scripts' && (
                                                    <div className="space-y-4">
                                                        <div className="flex justify-between items-center">
                                                            <p className="text-sm text-gray-400">{t('scriptsDesc') || 'Run custom .sh or .py scripts on cluster nodes with permission control'}</p>
                                                            <div className="flex items-center gap-2">
                                                                <button
                                                                    onClick={() => loadCustomScripts(selectedCluster?.id)}
                                                                    className="flex items-center gap-1 px-3 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm text-gray-400"
                                                                    title={t('refresh') || 'Refresh'}
                                                                >
                                                                    <Icons.RefreshCw className="w-4 h-4" />
                                                                </button>
                                                                <button
                                                                    onClick={() => { setEditingScript(null); setShowScriptModal(true); }}
                                                                    className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                                >
                                                                    <Icons.Plus /> {t('newScript') || 'New Script'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                        
                                                        {/* Scripts List */}
                                                        {(!customScripts || customScripts.length === 0) ? (
                                                            <div className="bg-proxmox-dark rounded-xl p-8 text-center">
                                                                <Icons.Terminal className="mx-auto mb-3 w-10 h-10 text-gray-600" />
                                                                <p className="text-gray-500">{t('noScripts') || 'No custom scripts configured'}</p>
                                                                <p className="text-xs text-gray-600 mt-2">{t('scriptsInfo') || 'Create scripts to automate tasks across your cluster nodes'}</p>
                                                            </div>
                                                        ) : (
                                                            <div className="space-y-3">
                                                                {customScripts.map(script => (
                                                                    <div key={script.id} className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                        <div className="flex items-center justify-between">
                                                                            <div className="flex items-center gap-3">
                                                                                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                                                                                    script.type === 'python' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'
                                                                                }`}>
                                                                                    {script.type === 'python' ? '🐍' : '📜'}
                                                                                </div>
                                                                                <div>
                                                                                    <h4 className="font-medium text-white">{script.name}</h4>
                                                                                    <p className="text-xs text-gray-500">
                                                                                        {script.type === 'python' ? 'Python' : 'Bash'} • {script.target_nodes === 'all' ? 'All Nodes' : script.target_nodes}
                                                                                        {script.created_by && <span className="ml-2">• Created by {script.created_by}</span>}
                                                                                    </p>
                                                                                </div>
                                                                            </div>
                                                                            <div className="flex items-center gap-2">
                                                                                {/* Run Script - opens password confirmation */}
                                                                                <button
                                                                                    onClick={() => setShowScriptRunModal(script)}
                                                                                    className="p-2 rounded-lg bg-green-500/20 text-green-400 hover:bg-green-500/30"
                                                                                    title={t('runScript') || 'Run Script'}
                                                                                    disabled={!script.enabled}
                                                                                >
                                                                                    <Icons.Play className="w-4 h-4" />
                                                                                </button>
                                                                                {/* View Last Output */}
                                                                                {script.last_run && (
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            try {
                                                                                                const res = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/scripts/${script.id}/output`);
                                                                                                if (res.ok) {
                                                                                                    const data = await res.json();
                                                                                                    setScriptOutput({ name: data.name, output: data.output, last_run: data.last_run, last_status: data.last_status });
                                                                                                }
                                                                                            } catch (e) {
                                                                                                addToast('Error loading output', 'error');
                                                                                            }
                                                                                        }}
                                                                                        className="p-2 rounded-lg bg-blue-500/20 text-blue-400 hover:bg-blue-500/30"
                                                                                        title={t('viewOutput') || 'View Last Output'}
                                                                                    >
                                                                                        <Icons.FileText className="w-4 h-4" />
                                                                                    </button>
                                                                                )}
                                                                                <button
                                                                                    onClick={() => { setEditingScript(script); setShowScriptModal(true); }}
                                                                                    className="p-2 rounded-lg bg-proxmox-dark text-gray-400 hover:bg-proxmox-hover hover:text-white"
                                                                                >
                                                                                    <Icons.Edit className="w-4 h-4" />
                                                                                </button>
                                                                                <button
                                                                                    onClick={async () => {
                                                                                        if (!confirm(t('confirmDeleteScript') || 'Delete this script? It will be permanently removed after 20 days.')) return;
                                                                                        try {
                                                                                            const res = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/scripts/${script.id}`, { method: 'DELETE' });
                                                                                            if (res.ok) {
                                                                                                const result = await res.json();
                                                                                                addToast(result.message || t('scriptMarkedForDeletion') || 'Script marked for deletion (20 days)', 'success');
                                                                                                setCustomScripts(prev => prev.filter(s => s.id !== script.id));
                                                                                            }
                                                                                        } catch (e) {
                                                                                            addToast('Error deleting script', 'error');
                                                                                        }
                                                                                    }}
                                                                                    className="p-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30"
                                                                                >
                                                                                    <Icons.Trash className="w-4 h-4" />
                                                                                </button>
                                                                            </div>
                                                                        </div>
                                                                        {script.description && (
                                                                            <p className="text-sm text-gray-400 mt-2">{script.description}</p>
                                                                        )}
                                                                        {script.last_run && (
                                                                            <p className="text-xs text-gray-600 mt-2">
                                                                                Last run: {new Date(script.last_run).toLocaleString()} - 
                                                                                <span className={
                                                                                    script.last_status === 'success' ? 'text-green-400 ml-1' :
                                                                                    script.last_status === 'partial' ? 'text-yellow-400 ml-1' :
                                                                                    'text-red-400 ml-1'
                                                                                }>{script.last_status}</span>
                                                                            </p>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                        
                                                        {/* Permissions Info */}
                                                        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                                                            <div className="flex items-start gap-3">
                                                                <Icons.Shield className="text-blue-400 w-5 h-5 mt-0.5" />
                                                                <div>
                                                                    <h4 className="font-medium text-blue-300">{t('scriptPermissions') || 'Script Permissions'}</h4>
                                                                    <p className="text-sm text-gray-400 mt-1">
                                                                        {t('scriptPermissionsDesc') || 'Scripts require SSH access to nodes. Configure SSH key in cluster settings. Scripts run with the SSH user\'s permissions.'}
                                                                    </p>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Reports Tab - NS Jan 2026 - Now cluster-based */}
                                        {activeTab === 'reports' && (
                                            <div className="space-y-6">
                                                <div className="flex justify-between items-center">
                                                    <h2 className="text-lg font-semibold flex items-center gap-2">
                                                        <Icons.BarChart />
                                                        {t('reportsAnalytics') || 'Reports & Analytics'}: {selectedCluster?.name}
                                                    </h2>
                                                    {/* LW: corporate flat buttons */}
                                                    <div className="flex items-center gap-2">
                                                        {['hour', 'day', 'week'].map(p => (
                                                            <button
                                                                key={p}
                                                                onClick={() => setReportPeriod(p)}
                                                                className={isCorporate
                                                                    ? `px-3 py-1 text-[13px] border ${
                                                                        reportPeriod === p
                                                                            ? 'border-blue-500 bg-blue-500/10 text-white'
                                                                            : 'border-proxmox-border text-gray-400 hover:text-white hover:border-gray-500'
                                                                      }`
                                                                    : `px-3 py-1.5 rounded-lg text-sm ${
                                                                        reportPeriod === p
                                                                            ? 'bg-proxmox-orange text-white'
                                                                            : 'bg-proxmox-dark text-gray-400 hover:text-white'
                                                                    }`
                                                                }
                                                            >
                                                                {p === 'hour' ? t('lastHour') || 'Last Hour' :
                                                                 p === 'day' ? t('last24h') || 'Last 24h' :
                                                                 t('lastWeek') || 'Last Week'}
                                                            </button>
                                                        ))}
                                                        <button
                                                            onClick={() => { loadReportSummary(reportPeriod); loadTopVms(); }}
                                                            className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                                        >
                                                            <Icons.RotateCw className={reportLoading ? 'animate-spin' : ''} />
                                                        </button>
                                                    </div>
                                                </div>
                                                
                                                {reportLoading ? (
                                                    <div className="flex items-center justify-center py-12">
                                                        <Icons.RotateCw className="animate-spin w-8 h-8 text-gray-500" />
                                                    </div>
                                                ) : (
                                                    <div className="space-y-6">
                                                        {/* Live Metrics Row */}
                                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 text-center">
                                                                <div className="text-3xl font-bold text-blue-400">{reportData?.cpu?.current || reportData?.live?.cpu_percent || 0}%</div>
                                                                <div className="text-sm text-gray-500">CPU</div>
                                                                {reportData?.data_points > 0 && (
                                                                    <div className="text-xs text-gray-600 mt-1">avg: {reportData?.cpu?.avg || 0}%</div>
                                                                )}
                                                            </div>
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 text-center">
                                                                <div className="text-3xl font-bold text-green-400">{reportData?.memory?.current || reportData?.live?.mem_percent || 0}%</div>
                                                                <div className="text-sm text-gray-500">Memory</div>
                                                                {reportData?.data_points > 0 && (
                                                                    <div className="text-xs text-gray-600 mt-1">avg: {reportData?.memory?.avg || 0}%</div>
                                                                )}
                                                            </div>
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 text-center">
                                                                <div className="text-3xl font-bold text-orange-400">{reportData?.live?.vms_running || reportData?.vms_running?.current || 0}</div>
                                                                <div className="text-sm text-gray-500">VMs</div>
                                                            </div>
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 text-center">
                                                                <div className="text-3xl font-bold text-purple-400">{reportData?.live?.cts_running || 0}</div>
                                                                <div className="text-sm text-gray-500">Container</div>
                                                            </div>
                                                        </div>
                                                        
                                                        {/* Historical info */}
                                                        {reportData?.data_points > 0 && (
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                <h3 className="font-semibold mb-3 text-sm text-gray-400">{t('historicalRange') || 'Historical Range'}</h3>
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                                                                            <span>CPU</span>
                                                                            <span>{reportData.cpu?.min || 0}% - {reportData.cpu?.max || 0}%</span>
                                                                        </div>
                                                                        <div className="h-2 bg-proxmox-dark rounded-full overflow-hidden relative">
                                                                            <div className="absolute h-full bg-blue-500/30" style={{ left: `${reportData.cpu?.min || 0}%`, width: `${(reportData.cpu?.max || 0) - (reportData.cpu?.min || 0)}%` }} />
                                                                            <div className="absolute h-full w-1 bg-blue-400" style={{ left: `${reportData.cpu?.current || 0}%` }} />
                                                                        </div>
                                                                    </div>
                                                                    <div>
                                                                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                                                                            <span>Memory</span>
                                                                            <span>{reportData.memory?.min || 0}% - {reportData.memory?.max || 0}%</span>
                                                                        </div>
                                                                        <div className="h-2 bg-proxmox-dark rounded-full overflow-hidden relative">
                                                                            <div className="absolute h-full bg-green-500/30" style={{ left: `${reportData.memory?.min || 0}%`, width: `${(reportData.memory?.max || 0) - (reportData.memory?.min || 0)}%` }} />
                                                                            <div className="absolute h-full w-1 bg-green-400" style={{ left: `${reportData.memory?.current || 0}%` }} />
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                                <div className="text-xs text-gray-600 text-center mt-3">
                                                                    {reportData.data_points} {t('dataPoints') || 'data points'} • {reportData.period}
                                                                </div>
                                                            </div>
                                                        )}
                                                        
                                                        {/* Top VMs - CPU and Memory side by side */}
                                                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                                            {/* Top VMs by CPU */}
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                <h3 className="font-semibold mb-3 flex items-center gap-2 text-sm">
                                                                    <Icons.Cpu className="text-blue-400 w-4 h-4" />
                                                                    {t('topVmsCpu') || 'Highest CPU Usage'}
                                                                </h3>
                                                                <div className="space-y-2">
                                                                    {topVms.length > 0 ? topVms.slice(0, 5).map((vm, idx) => (
                                                                        <div key={idx} className="flex items-center gap-2 p-2 bg-proxmox-dark rounded-lg text-sm">
                                                                            <span className="text-xs text-gray-500 w-4">{idx + 1}</span>
                                                                            <span>{vm.type === 'lxc' ? '📦' : '🖥️'}</span>
                                                                            <span className="flex-1 truncate">{vm.name || `VM ${vm.vmid}`}</span>
                                                                            <div className="w-16 h-1.5 bg-proxmox-hover rounded-full overflow-hidden">
                                                                                <div className="h-full bg-blue-500" style={{ width: `${Math.min((vm.cpu || 0) * 100, 100)}%` }} />
                                                                            </div>
                                                                            <span className="font-mono text-xs w-10 text-right">{((vm.cpu || 0) * 100).toFixed(0)}%</span>
                                                                        </div>
                                                                    )) : (
                                                                        <p className="text-gray-500 text-center py-4 text-sm">{t('noRunningVms') || 'No running VMs'}</p>
                                                                    )}
                                                                </div>
                                                            </div>
                                                            
                                                            {/* Top VMs by Memory */}
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                <h3 className="font-semibold mb-3 flex items-center gap-2 text-sm">
                                                                    <Icons.HardDrive className="text-green-400 w-4 h-4" />
                                                                    {t('topVmsMem') || 'Highest Memory Usage'}
                                                                </h3>
                                                                <div className="space-y-2">
                                                                    {topVms.length > 0 ? [...topVms].sort((a, b) => (b.mem_percent || 0) - (a.mem_percent || 0)).slice(0, 5).map((vm, idx) => (
                                                                        <div key={idx} className="flex items-center gap-2 p-2 bg-proxmox-dark rounded-lg text-sm">
                                                                            <span className="text-xs text-gray-500 w-4">{idx + 1}</span>
                                                                            <span>{vm.type === 'lxc' ? '📦' : '🖥️'}</span>
                                                                            <span className="flex-1 truncate">{vm.name || `VM ${vm.vmid}`}</span>
                                                                            <div className="w-16 h-1.5 bg-proxmox-hover rounded-full overflow-hidden">
                                                                                <div className="h-full bg-green-500" style={{ width: `${Math.min(vm.mem_percent || 0, 100)}%` }} />
                                                                            </div>
                                                                            <span className="font-mono text-xs w-10 text-right">{(vm.mem_percent || 0).toFixed(0)}%</span>
                                                                        </div>
                                                                    )) : (
                                                                        <p className="text-gray-500 text-center py-4 text-sm">{t('noRunningVms') || 'No running VMs'}</p>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Settings Tab */}
                                        {activeTab === 'settings' && (
                                            <div className={`grid grid-cols-1 lg:grid-cols-2 ${isCorporate ? 'gap-3' : 'gap-6'}`}>
                                                <div className={isCorporate ? 'border border-proxmox-border p-4 space-y-4' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6 space-y-6'}>
                                                    <h3 className={isCorporate ? 'font-semibold text-sm' : 'font-semibold'}>{t('balancingConfig')}</h3>
                                                    
                                                    <Slider
                                                        label={t('migrationThreshold')}
                                                        description={t('migrationThresholdDesc')}
                                                        value={selectedCluster.migration_threshold}
                                                        onChange={v => updateConfig('migration_threshold', v)}
                                                        min={5}
                                                        max={100}
                                                    />
                                                    
                                                    <Slider
                                                        label={t('checkInterval')}
                                                        description={t('intervalBetweenChecks')}
                                                        value={selectedCluster.check_interval}
                                                        onChange={v => updateConfig('check_interval', v)}
                                                        min={60}
                                                        max={3600}
                                                        step={60}
                                                        unit="s"
                                                    />
                                                    
                                                    {/* LW: Excluded Nodes Section - GitHub Feature Request */}
                                                    <div className="pt-4 border-t border-proxmox-border">
                                                        <h4 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
                                                            <Icons.Ban className="w-4 h-4 text-red-400" />
                                                            {t('excludedNodes') || 'Excluded Nodes'}
                                                        </h4>
                                                        <p className="text-xs text-gray-500 mb-3">
                                                            {t('excludedNodesDesc') || 'These nodes will never be targets for automatic VM balancing.'}
                                                        </p>
                                                        
                                                        {/* Current excluded nodes */}
                                                        {(selectedCluster.excluded_nodes || []).length > 0 ? (
                                                            <div className="space-y-2 mb-3">
                                                                {(selectedCluster.excluded_nodes || []).map(nodeName => (
                                                                    <div key={nodeName} className="flex items-center justify-between bg-proxmox-dark rounded-lg p-2">
                                                                        <div className="flex items-center gap-2">
                                                                            <Icons.Server className="w-4 h-4 text-red-400" />
                                                                            <span className="text-sm">{nodeName}</span>
                                                                        </div>
                                                                        <button
                                                                            onClick={async () => {
                                                                                try {
                                                                                    const res = await fetch(`${API_URL}/clusters/${selectedCluster.id}/excluded-nodes/${nodeName}`, {
                                                                                        method: 'DELETE',
                                                                                        credentials: 'include',
                                                                                        headers: getAuthHeaders()
                                                                                    });
                                                                                    if (res.ok) {
                                                                                        fetchClusters();
                                                                                        addToast(`${nodeName} ${t('reincludedInBalancing') || 're-included in balancing'}`, 'success');
                                                                                    }
                                                                                } catch(e) { console.error(e); }
                                                                            }}
                                                                            className="text-xs text-green-400 hover:text-green-300"
                                                                        >
                                                                            {t('include') || 'Include'}
                                                                        </button>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        ) : (
                                                            <div className="text-xs text-gray-600 mb-3 p-2 bg-proxmox-dark rounded-lg">
                                                                {t('noExcludedNodes') || 'No nodes excluded'}
                                                            </div>
                                                        )}
                                                        
                                                        {/* Add node dropdown */}
                                                        <div className="flex gap-2">
                                                            <select
                                                                id="excludeNodeSelect"
                                                                className="flex-1 bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-sm"
                                                                defaultValue=""
                                                            >
                                                                <option value="" disabled>{t('selectNodeToExclude') || 'Select node to exclude...'}</option>
                                                                {Object.keys(clusterMetrics || {})
                                                                    .filter(n => !(selectedCluster.excluded_nodes || []).includes(n))
                                                                    .map(nodeName => (
                                                                        <option key={nodeName} value={nodeName}>{nodeName}</option>
                                                                    ))
                                                                }
                                                            </select>
                                                            <button
                                                                onClick={async () => {
                                                                    const select = document.getElementById('excludeNodeSelect');
                                                                    const nodeName = select?.value;
                                                                    if (!nodeName) return;
                                                                    try {
                                                                        const res = await fetch(`${API_URL}/clusters/${selectedCluster.id}/excluded-nodes/${nodeName}`, {
                                                                            method: 'POST',
                                                                            credentials: 'include',
                                                                            headers: getAuthHeaders()
                                                                        });
                                                                        if (res.ok) {
                                                                            fetchClusters();
                                                                            addToast(`${nodeName} ${t('excludedFromBalancing') || 'excluded from balancing'}`, 'success');
                                                                            select.value = '';
                                                                        }
                                                                    } catch(e) { console.error(e); }
                                                                }}
                                                                className="px-3 py-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 text-sm flex items-center gap-1"
                                                            >
                                                                <Icons.Ban className="w-4 h-4" />
                                                                {t('exclude') || 'Exclude'}
                                                            </button>
                                                        </div>
                                                    </div>
                                                    
                                                    {/* MK: Excluded VMs Section */}
                                                    <div className="pt-4 border-t border-proxmox-border">
                                                        <h4 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
                                                            <Icons.Monitor className="w-4 h-4 text-red-400" />
                                                            {t('excludedVMs') || 'Excluded VMs'}
                                                        </h4>
                                                        <p className="text-xs text-gray-500 mb-3">
                                                            {t('excludedVMsDesc') || 'These VMs will never be automatically migrated during load balancing.'}
                                                        </p>
                                                        
                                                        {/* Current excluded VMs */}
                                                        <ExcludedVMsList clusterId={selectedCluster.id} clusterMetrics={clusterMetrics} addToast={addToast} getAuthHeaders={getAuthHeaders} />
                                                    </div>
                                                </div>

                                                <div className={isCorporate ? 'border border-proxmox-border p-4 space-y-4' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6 space-y-6'}>
                                                    <h3 className={isCorporate ? 'font-semibold text-sm' : 'font-semibold'}>{t('optionsTitle')}</h3>
                                                    
                                                    <div className="space-y-4">
                                                        <Toggle
                                                            checked={selectedCluster.enabled}
                                                            onChange={v => updateConfig('enabled', v)}
                                                            label={t('balancingEnabled')}
                                                        />
                                                        <Toggle
                                                            checked={selectedCluster.auto_migrate}
                                                            onChange={v => updateConfig('auto_migrate', v)}
                                                            label={t('autoMigrate')}
                                                        />
                                                        <Toggle
                                                            checked={selectedCluster.dry_run}
                                                            onChange={v => updateConfig('dry_run', v)}
                                                            label={t('dryRun')}
                                                        />
                                                        
                                                        {/* Container Balancing */}
                                                        <div className="pt-3 border-t border-gray-700/50">
                                                            <Toggle
                                                                checked={selectedCluster.balance_containers || false}
                                                                onChange={v => updateConfig('balance_containers', v)}
                                                                label={t('balanceContainers')}
                                                            />
                                                            {selectedCluster.balance_containers && (
                                                                <div className="mt-2 ml-12 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                                    <div className="flex items-start gap-2">
                                                                        <span className="text-yellow-500">⚠️</span>
                                                                        <div className="text-xs text-yellow-200">
                                                                            {t('containerBalanceWarning')}
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                        
                                                        {/* Local Disk Balancing - NS: new feature, use with caution */}
                                                        <div className="pt-3 border-t border-gray-700/50">
                                                            <Toggle
                                                                checked={selectedCluster.balance_local_disks || false}
                                                                onChange={v => updateConfig('balance_local_disks', v)}
                                                                label={t('balanceLocalDisks')}
                                                            />
                                                            <div className="text-xs text-gray-500 pl-12 mt-1">
                                                                {t('balanceLocalDisksDesc')}
                                                            </div>
                                                            {selectedCluster.balance_local_disks && (
                                                                <div className="mt-2 ml-12 p-3 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                                                                    <div className="flex items-start gap-2">
                                                                        <span className="text-orange-500">💾</span>
                                                                        <div className="text-xs text-orange-200">
                                                                            {t('localDiskBalanceWarning')}
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* HA Section */}
                                                    <div className="pt-4 border-t border-proxmox-border">
                                                        <h4 className="text-sm font-medium text-gray-400 mb-3">{t('highAvailability')}</h4>
                                                        <div className="space-y-3">
                                                            <Toggle
                                                                checked={selectedCluster.ha_enabled || false}
                                                                onChange={v => updateConfig('ha_enabled', v)}
                                                                label={t('haEnabled')}
                                                            />
                                                            <div className="text-xs text-gray-500 pl-12">
                                                                {t('haMonitorDesc')}
                                                            </div>
                                                            {selectedCluster.ha_enabled && (
                                                                <>
                                                                    <div className="ml-12 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                                                                        <div className="flex items-center gap-2 text-green-400 text-sm">
                                                                            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                                                            {t('haMonitorActive')}
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    {/* Auto-discovered Fallback Hosts */}
                                                                    <div className="ml-12 mt-3 p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                                        <div className="text-xs text-gray-400 mb-2">
                                                                            {t('fallbackHostsAuto')}
                                                                        </div>
                                                                        <div className="flex items-center gap-2">
                                                                            <span className="text-gray-500">{t('primary')}:</span>
                                                                            <span className="font-mono text-sm text-white">{selectedCluster.host}</span>
                                                                            {selectedCluster.current_host && selectedCluster.current_host !== selectedCluster.host && (
                                                                                <span className="text-yellow-400 text-xs">({t('fallback')})</span>
                                                                            )}
                                                                        </div>
                                                                        {selectedCluster.fallback_hosts && selectedCluster.fallback_hosts.length > 0 ? (
                                                                            <div className="flex items-center gap-2 mt-1">
                                                                                <span className="text-gray-500">{t('fallbacks')}:</span>
                                                                                <span className="font-mono text-sm text-gray-300">
                                                                                    {selectedCluster.fallback_hosts.join(', ')}
                                                                                </span>
                                                                            </div>
                                                                        ) : (
                                                                            <div className="text-xs text-gray-600 mt-1">
                                                                                {t('noFallbackHosts')}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                </>
                                                            )}
                                                            
                                                            {/* Split-Brain Prevention Settings Button */}
                                                            {selectedCluster.ha_enabled && (
                                                                <button
                                                                    onClick={() => { setShowHaSettings(true); fetchHAStatus(selectedCluster.id); }}
                                                                    className="ml-12 mt-2 text-xs text-proxmox-orange hover:text-orange-400 flex items-center gap-1"
                                                                >
                                                                    <Icons.Settings className="w-3 h-3" />
                                                                    {t('splitBrainPrevention')} ({t('important2NodeCluster')})
                                                                </button>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* Proxmox Native HA Section */}
                                                    <div className="pt-4 border-t border-proxmox-border">
                                                        <h4 className="text-sm font-medium text-gray-400 mb-3">{t('proxmoxNativeHa')}</h4>
                                                        <div className="text-xs text-gray-500 mb-3">
                                                            {t('nativeHaDesc')}
                                                        </div>
                                                        <ProxmoxHaSection clusterId={selectedCluster.id} />
                                                    </div>

                                                    <div className="pt-4 border-t border-proxmox-border">
                                                        <h4 className="text-sm font-medium text-gray-400 mb-3">{t('clusterInfo')}</h4>
                                                        <div className="space-y-2 text-sm">
                                                            <div className="flex justify-between">
                                                                <span className="text-gray-500">{t('primaryHost')}</span>
                                                                <span className="font-mono">{selectedCluster.host}</span>
                                                            </div>
                                                            {selectedCluster.current_host && selectedCluster.current_host !== selectedCluster.host && (
                                                                <div className="flex justify-between">
                                                                    <span className="text-gray-500">{t('connectedTo')}</span>
                                                                    <span className="font-mono text-yellow-400">{selectedCluster.current_host} ({t('fallback')})</span>
                                                                </div>
                                                            )}
                                                            {selectedCluster.fallback_hosts && selectedCluster.fallback_hosts.length > 0 && (
                                                                <div className="flex justify-between">
                                                                    <span className="text-gray-500">{t('fallbackHosts')}</span>
                                                                    <span className="font-mono text-xs text-gray-400">{selectedCluster.fallback_hosts.length} {t('configured')}</span>
                                                                </div>
                                                            )}
                                                            <div className="flex justify-between">
                                                                <span className="text-gray-500">{t('status')}</span>
                                                                <span className={selectedCluster.status === 'running' ? 'text-green-400' : 'text-gray-400'}>
                                                                    {selectedCluster.status === 'running' ? t('running') : selectedCluster.status}
                                                                </span>
                                                            </div>
                                                            {selectedCluster.last_run && (
                                                                <div className="flex justify-between">
                                                                    <span className="text-gray-500">{t('lastCheck')}</span>
                                                                    <span>{new Date(selectedCluster.last_run).toLocaleString()}</span>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                {/* Update Manager Section */}
                                                <div className="lg:col-span-2">
                                                    <UpdateManagerSection key={selectedCluster.id} clusterId={selectedCluster.id} addToast={addToast} />
                                                </div>
                                                
                                                {/* SMBIOS Auto-Configurator Section */}
                                                <div className={`lg:col-span-2 ${isCorporate ? 'border border-proxmox-border p-4' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6'}`}>
                                                    <SmbiosAutoConfigSection 
                                                        clusterId={selectedCluster?.id} 
                                                        selectedCluster={selectedCluster}
                                                        updateConfig={updateConfig}
                                                        addToast={addToast}
                                                    />
                                                </div>
                                                
                                                {/* Appearance Info - Now in My Profile */}
                                                <div className={`lg:col-span-2 ${isCorporate ? 'border border-proxmox-border p-4' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-6'}`}>
                                                    <h3 className="font-semibold mb-4 flex items-center gap-2">
                                                        <Icons.Palette className="w-5 h-5" />
                                                        {t('appearance') || 'Appearance'}
                                                    </h3>
                                                    <div className="flex items-center gap-4">
                                                        <div 
                                                            className="w-16 h-16 rounded-xl relative overflow-hidden flex-shrink-0"
                                                            style={{ 
                                                                background: PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.colors?.darker || '#080B0E',
                                                                border: `2px solid ${PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.colors?.border || '#30363D'}`
                                                            }}
                                                        >
                                                            <div className="absolute left-0 top-0 bottom-0 w-3" style={{ background: PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.colors?.dark || '#0F1419' }} />
                                                            <div className="absolute right-1 top-1 bottom-1 left-4 rounded" style={{ background: PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.colors?.card || '#161B22' }}>
                                                                <div className="w-2/3 h-1 rounded-full m-1" style={{ background: PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.colors?.primary || '#E57000' }} />
                                                            </div>
                                                        </div>
                                                        <div className="flex-1">
                                                            <p className="text-white font-medium flex items-center gap-2">
                                                                <span className="text-xl">{PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.icon || '🌙'}</span>
                                                                {PEGAPROX_THEMES[user?.theme || 'proxmoxDark']?.name || 'Proxmox Dark'}
                                                            </p>
                                                            <p className="text-sm text-gray-400 mt-1">
                                                                {t('themeInProfile') || 'Change your theme in My Profile (click your username in the top right)'}
                                                            </p>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ) : selectedPBS ? (
                                    /* LW: Feb 2026 - PBS view */
                                    <div className={isCorporate ? 'space-y-4' : 'space-y-6'}>
                                        {/* LW: Feb 2026 - PBS header */}
                                        <div className={`flex items-center justify-between ${isCorporate ? 'px-4 py-3 border-b' : ''}`} style={isCorporate ? {borderColor: '#485764', background: '#22343c'} : {}}>
                                            <div className="flex items-center gap-4">
                                                {isCorporate ? (
                                                    <Icons.Shield className="w-5 h-5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                ) : (
                                                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/20 to-cyan-500/10 border border-blue-500/30 flex items-center justify-center">
                                                        <Icons.Shield className="w-6 h-6 text-blue-400" />
                                                    </div>
                                                )}
                                                <div>
                                                    <h1 className={isCorporate ? 'text-[15px] font-medium' : 'text-2xl font-bold'} style={{color: '#e9ecef'}}>{selectedPBS.name}</h1>
                                                    <div className={`flex items-center gap-3 ${isCorporate ? 'text-[12px]' : 'text-sm'}`} style={{color: '#adbbc4'}}>
                                                        <span>{selectedPBS.host}:{selectedPBS.port}</span>
                                                        <span className="flex items-center gap-1" style={{color: selectedPBS.connected ? '#60b515' : '#f54f47'}}>
                                                            <span className="w-2 h-2 rounded-full" style={{background: selectedPBS.connected ? '#60b515' : '#f54f47'}}></span>
                                                            {selectedPBS.connected ? 'Connected' : 'Disconnected'}
                                                        </span>
                                                        {pbsStatus?.version && <span>v{pbsStatus.version.version}</span>}
                                                    </div>
                                                </div>
                                            </div>
                                            <div className={isCorporate ? 'corp-toolbar flex items-center gap-1' : 'flex items-center gap-2'}>
                                                {isAdmin && (
                                                    <>
                                                        <button onClick={() => { setEditingPBS(selectedPBS); setPbsForm({ name: selectedPBS.name, host: selectedPBS.host, port: selectedPBS.port, user: selectedPBS.user, password: '********', api_token_id: selectedPBS.api_token_id || '', api_token_secret: selectedPBS.using_api_token ? '********' : '', fingerprint: selectedPBS.fingerprint || '', ssl_verify: selectedPBS.ssl_verify || false, linked_clusters: selectedPBS.linked_clusters || [], notes: selectedPBS.notes || '' }); setShowAddPBS(true); }} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-white hover:border-blue-500/30 transition-all text-sm flex items-center gap-2'}>
                                                            <Icons.Edit className="w-4 h-4" /> Edit
                                                        </button>
                                                        <button onClick={() => handleDeletePBS(selectedPBS.id)} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-red-400 hover:border-red-500/30 transition-all text-sm flex items-center gap-2'}>
                                                            <Icons.Trash className="w-4 h-4" /> Delete
                                                        </button>
                                                    </>
                                                )}
                                                <button onClick={() => { fetchPBSStatus(selectedPBS.id); fetchPBSDatastores(selectedPBS.id); fetchPBSTasks(selectedPBS.id); fetchPBSJobs(selectedPBS.id); }} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-white hover:border-proxmox-orange/30 transition-all text-sm flex items-center gap-2'}>
                                                    <Icons.RefreshCw className={`w-4 h-4 ${pbsLoading ? 'animate-spin' : ''}`} /> Refresh
                                                </button>
                                            </div>
                                        </div>

                                        {/* LW: Feb 2026 - PBS tabs */}
                                        <div className={isCorporate
                                            ? 'flex items-center border-b border-proxmox-border'
                                            : 'flex items-center gap-1 p-1 bg-proxmox-card border border-proxmox-border rounded-xl w-fit'
                                        }>
                                            {[
                                                { id: 'dashboard', label: 'Dashboard', icon: Icons.Activity },
                                                { id: 'datastores', label: 'Datastores', icon: Icons.Database },
                                                { id: 'tasks', label: 'Tasks', icon: Icons.ClipboardList },
                                                { id: 'jobs', label: 'Jobs', icon: Icons.Clock },
                                            ].map(tab => (
                                                <button key={tab.id} onClick={() => setPbsActiveTab(tab.id)}
                                                    className={isCorporate
                                                        ? `flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px ${
                                                            pbsActiveTab === tab.id
                                                                ? 'border-blue-500 text-white font-medium'
                                                                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
                                                          }`
                                                        : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                                            pbsActiveTab === tab.id ? 'bg-blue-500 text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                          }`
                                                    }>
                                                    <tab.icon className={isCorporate ? 'w-3 h-3' : undefined} /> {tab.label}
                                                </button>
                                            ))}
                                        </div>

                                        {/* Dashboard Tab */}
                                        {pbsActiveTab === 'dashboard' && pbsStatus && (
                                            <div className="space-y-6">
                                                {/* Resource Gauges */}
                                                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                                                    {(() => {
                                                        const srv = pbsStatus.server || {};
                                                        const cpuPct = ((srv.cpu || 0) * 100).toFixed(1);
                                                        const memUsed = srv.memory?.used || 0;
                                                        const memTotal = srv.memory?.total || 1;
                                                        const memPct = ((memUsed / memTotal) * 100).toFixed(1);
                                                        const rootUsed = srv.root?.used || 0;
                                                        const rootTotal = srv.root?.total || 1;
                                                        const rootPct = ((rootUsed / rootTotal) * 100).toFixed(1);
                                                        const uptime = srv.uptime || 0;
                                                        const days = Math.floor(uptime / 86400);
                                                        const hours = Math.floor((uptime % 86400) / 3600);
                                                        const mins = Math.floor((uptime % 3600) / 60);
                                                        // LW: corporate Clarity gauge cards
                                                        const cardCls = isCorporate ? 'p-3 border-b' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-4';
                                                        const cardStyle = isCorporate ? {borderColor: '#37474f', background: '#22343c'} : {};
                                                        const barBg = isCorporate ? '#1b2a32' : undefined;
                                                        const barRadius = isCorporate ? '1px' : undefined;
                                                        const barH = isCorporate ? 'h-1.5' : 'h-2';
                                                        const barRound = isCorporate ? '' : 'rounded-full';
                                                        const pbsBarColor = (pct, threshHigh, threshMid, colorLow) => {
                                                            if (parseFloat(pct) > threshHigh) return isCorporate ? '#f54f47' : undefined;
                                                            if (parseFloat(pct) > threshMid) return isCorporate ? '#efc006' : undefined;
                                                            return isCorporate ? colorLow : undefined;
                                                        };
                                                        return (
                                                            <>
                                                                <div className={cardCls} style={cardStyle}>
                                                                    <div className="flex items-center justify-between mb-3">
                                                                        <span className={isCorporate ? 'text-[12px]' : 'text-sm'} style={{color: '#adbbc4'}}>CPU</span>
                                                                        <span className={isCorporate ? 'text-[14px] font-medium' : 'text-lg font-bold'} style={{color: '#e9ecef'}}>{cpuPct}%</span>
                                                                    </div>
                                                                    <div className={`w-full ${barH} ${isCorporate ? '' : 'bg-proxmox-dark'} ${barRound} overflow-hidden`} style={barBg ? {background: barBg, borderRadius: barRadius} : {}}>
                                                                        <div className={`h-full ${barRound} transition-all ${!isCorporate ? (parseFloat(cpuPct) > 80 ? 'bg-red-500' : parseFloat(cpuPct) > 50 ? 'bg-yellow-500' : 'bg-blue-500') : ''}`} style={{width: `${cpuPct}%`, ...(isCorporate ? {background: pbsBarColor(cpuPct, 80, 50, '#49afd9'), borderRadius: barRadius} : {})}}></div>
                                                                    </div>
                                                                    <div className="text-xs mt-2" style={{color: '#728b9a'}}>{srv.cpuinfo?.cpus || '?'} CPUs - {srv.cpuinfo?.model || ''}</div>
                                                                </div>
                                                                <div className={cardCls} style={cardStyle}>
                                                                    <div className="flex items-center justify-between mb-3">
                                                                        <span className={isCorporate ? 'text-[12px]' : 'text-sm'} style={{color: '#adbbc4'}}>Memory</span>
                                                                        <span className={isCorporate ? 'text-[14px] font-medium' : 'text-lg font-bold'} style={{color: '#e9ecef'}}>{memPct}%</span>
                                                                    </div>
                                                                    <div className={`w-full ${barH} bg-proxmox-dark ${barRound} overflow-hidden`} style={barBg ? {background: barBg, borderRadius: barRadius} : {}}>
                                                                        <div className={`h-full ${barRound} transition-all ${parseFloat(memPct) > 80 ? 'bg-red-500' : parseFloat(memPct) > 50 ? 'bg-yellow-500' : 'bg-green-500'}`} style={isCorporate ? {width: `${memPct}%`, background: pbsBarColor(memPct, 80, 50, '#49afd9'), borderRadius: barRadius} : {width: `${memPct}%`}}></div>
                                                                    </div>
                                                                    <div className="text-xs mt-2" style={{color: '#728b9a'}}>{formatBytes(memUsed)} / {formatBytes(memTotal)}</div>
                                                                </div>
                                                                <div className={cardCls} style={cardStyle}>
                                                                    <div className="flex items-center justify-between mb-3">
                                                                        <span className={isCorporate ? 'text-[12px]' : 'text-sm'} style={{color: '#adbbc4'}}>Root Disk</span>
                                                                        <span className={isCorporate ? 'text-[14px] font-medium' : 'text-lg font-bold'} style={{color: '#e9ecef'}}>{rootPct}%</span>
                                                                    </div>
                                                                    <div className={`w-full ${barH} bg-proxmox-dark ${barRound} overflow-hidden`} style={barBg ? {background: barBg, borderRadius: barRadius} : {}}>
                                                                        <div className={`h-full ${barRound} transition-all ${parseFloat(rootPct) > 85 ? 'bg-red-500' : parseFloat(rootPct) > 60 ? 'bg-yellow-500' : 'bg-cyan-500'}`} style={isCorporate ? {width: `${rootPct}%`, background: pbsBarColor(rootPct, 85, 60, '#49afd9'), borderRadius: barRadius} : {width: `${rootPct}%`}}></div>
                                                                    </div>
                                                                    <div className="text-xs mt-2" style={{color: '#728b9a'}}>{formatBytes(rootUsed)} / {formatBytes(rootTotal)}</div>
                                                                </div>
                                                                <div className={cardCls} style={cardStyle}>
                                                                    <div className="flex items-center justify-between mb-3">
                                                                        <span className={isCorporate ? 'text-[12px]' : 'text-sm'} style={{color: '#adbbc4'}}>Uptime</span>
                                                                        <Icons.Clock className="w-4 h-4" style={{color: '#728b9a'}} />
                                                                    </div>
                                                                    <div className={isCorporate ? 'text-[14px] font-medium' : 'text-lg font-bold'} style={{color: '#e9ecef'}}>{days}d {hours}h {mins}m</div>
                                                                    <div className="text-xs mt-2" style={{color: '#728b9a'}}>Load: {(srv.loadavg || [0,0,0]).map(v => v.toFixed(2)).join(', ')}</div>
                                                                </div>
                                                            </>
                                                        );
                                                    })()}
                                                </div>

                                                {/* LW: Feb 2026 - datastore cards */}
                                                <div>
                                                    <h2 className={isCorporate ? 'corp-section-header' : 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4'}>Datastores ({pbsDatastores.length})</h2>
                                                    <div className={isCorporate ? 'space-y-0' : 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4'}>
                                                        {pbsDatastores.map(ds => {
                                                            const used = ds.used || 0;
                                                            const total = ds.total || ds.avail ? (ds.used || 0) + (ds.avail || 0) : 1;
                                                            const pct = total > 0 ? ((used / total) * 100).toFixed(1) : 0;
                                                            const detail = ds.detail || {};
                                                            const gcStatus = detail['gc-status'] || {};
                                                            const pctColor = isCorporate ? (parseFloat(pct) > 85 ? '#f54f47' : parseFloat(pct) > 60 ? '#efc006' : '#60b515') : undefined;
                                                            return (
                                                                <div key={ds.name || ds.store}
                                                                    className={isCorporate ? 'flex items-center gap-3 px-3 py-2 cursor-pointer' : 'bg-proxmox-card border border-proxmox-border rounded-xl p-4 hover:border-blue-500/30 transition-all cursor-pointer'}
                                                                    style={isCorporate ? {borderBottom: '1px solid #37474f'} : {}}
                                                                    onClick={() => { setPbsActiveTab('datastores'); setPbsSelectedStore(ds.name || ds.store); }}
                                                                    onMouseEnter={isCorporate ? (e) => { e.currentTarget.style.background = '#29414e'; } : undefined}
                                                                    onMouseLeave={isCorporate ? (e) => { e.currentTarget.style.background = ''; } : undefined}
                                                                >
                                                                    {isCorporate ? (
                                                                        <>
                                                                            <Icons.Database className="w-3.5 h-3.5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                                            <span className="text-[13px] font-medium w-32 truncate" style={{color: '#e9ecef'}}>{ds.name || ds.store}</span>
                                                                            <div className="flex-1 h-1.5 overflow-hidden" style={{background: '#1b2a32', borderRadius: '1px'}}>
                                                                                <div className="h-full" style={{width: `${pct}%`, background: pctColor, borderRadius: '1px'}}></div>
                                                                            </div>
                                                                            <span className="text-[12px] w-12 text-right" style={{color: pctColor}}>{pct}%</span>
                                                                            <span className="text-[11px]" style={{color: '#728b9a'}}>{formatBytes(used)} / {formatBytes(total)}</span>
                                                                            {gcStatus.index && <span className="text-[11px]" style={{color: '#49afd9'}}>{(gcStatus['dedup-factor'] || 1).toFixed(1)}x</span>}
                                                                        </>
                                                                    ) : (
                                                                        <>
                                                                            <div className="flex items-center justify-between mb-3">
                                                                                <div className="flex items-center gap-2">
                                                                                    <Icons.Database className="w-5 h-5 text-blue-400" />
                                                                                    <span className="font-semibold text-white">{ds.name || ds.store}</span>
                                                                                </div>
                                                                                <span className={`text-sm font-bold ${parseFloat(pct) > 85 ? 'text-red-400' : parseFloat(pct) > 60 ? 'text-yellow-400' : 'text-green-400'}`}>{pct}%</span>
                                                                            </div>
                                                                            <div className="w-full h-2 bg-proxmox-dark rounded-full overflow-hidden mb-3">
                                                                                <div className={`h-full rounded-full ${parseFloat(pct) > 85 ? 'bg-red-500' : parseFloat(pct) > 60 ? 'bg-yellow-500' : 'bg-blue-500'}`} style={{width: `${pct}%`}}></div>
                                                                            </div>
                                                                            <div className="grid grid-cols-2 gap-2 text-xs">
                                                                                <div><span className="text-gray-500">Used:</span> <span className="text-gray-300">{formatBytes(used)}</span></div>
                                                                                <div><span className="text-gray-500">Total:</span> <span className="text-gray-300">{formatBytes(total)}</span></div>
                                                                                {gcStatus.index && (
                                                                                    <>
                                                                                        <div><span className="text-gray-500">Dedup:</span> <span className="text-cyan-400">{(gcStatus['dedup-factor'] || 1).toFixed(2)}x</span></div>
                                                                                        <div><span className="text-gray-500">Chunks:</span> <span className="text-gray-300">{(gcStatus['disk-chunks'] || 0).toLocaleString()}</span></div>
                                                                                    </>
                                                                                )}
                                                                                {detail['total-snapshots'] !== undefined && (
                                                                                    <div className="col-span-2"><span className="text-gray-500">Snapshots:</span> <span className="text-gray-300">{detail['total-snapshots']}</span></div>
                                                                                )}
                                                                            </div>
                                                                            {isAdmin && (
                                                                                <div className="flex gap-2 mt-3 pt-3 border-t border-proxmox-border/50">
                                                                                    <button onClick={e => { e.stopPropagation(); setPbsActionLoading(p => ({...p, [`gc-${ds.name||ds.store}`]: true})); pbsAction('gc', ds.name || ds.store).finally(() => setPbsActionLoading(p => ({...p, [`gc-${ds.name||ds.store}`]: false}))); }} className="flex-1 px-2 py-1 rounded bg-proxmox-dark text-xs text-gray-400 hover:text-white hover:bg-blue-500/20 transition-all" disabled={pbsActionLoading[`gc-${ds.name||ds.store}`]}>
                                                                                        {pbsActionLoading[`gc-${ds.name||ds.store}`] ? 'Starting...' : 'GC'}
                                                                                    </button>
                                                                                    <button onClick={e => { e.stopPropagation(); pbsAction('verify', ds.name || ds.store); }} className="flex-1 px-2 py-1 rounded bg-proxmox-dark text-xs text-gray-400 hover:text-white hover:bg-green-500/20 transition-all">Verify</button>
                                                                                </div>
                                                                            )}
                                                                        </>
                                                                    )}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </div>

                                                {/* LW: disk info */}
                                                {pbsDisks.length > 0 && (
                                                    <div>
                                                        <h2 className={isCorporate ? 'corp-section-header' : 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4'}>Disks ({pbsDisks.length})</h2>
                                                        <div className={isCorporate ? 'overflow-hidden' : 'bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden'}>
                                                            <table className={isCorporate ? 'corp-datagrid' : 'w-full text-sm'}>
                                                                <thead><tr className={isCorporate ? '' : 'border-b border-proxmox-border text-gray-500 text-xs'}>
                                                                    <th className={isCorporate ? '' : 'text-left p-3'}>Device</th><th className={isCorporate ? '' : 'text-left p-3'}>Type</th><th className={isCorporate ? '' : 'text-left p-3'}>Size</th><th className={isCorporate ? '' : 'text-left p-3'}>Model</th><th className={isCorporate ? '' : 'text-left p-3'}>Status</th>
                                                                </tr></thead>
                                                                <tbody>
                                                                    {pbsDisks.map((disk, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50">
                                                                            <td className="p-3 text-white font-medium font-mono text-xs">{disk.devpath || '-'}</td>
                                                                            <td className="p-3 text-gray-400">{disk.disk_type || disk['disk-type'] || '-'}</td>
                                                                            <td className="p-3 text-gray-300">{disk.size ? formatBytes(disk.size) : '-'}</td>
                                                                            <td className="p-3 text-gray-400 truncate max-w-[200px]">{disk.model || disk.vendor || '-'}</td>
                                                                            <td className="p-3">
                                                                                <span className={`px-2 py-0.5 rounded text-xs ${disk.health === 'PASSED' || disk.health === 'OK' ? 'bg-green-500/20 text-green-400' : disk.health === 'UNKNOWN' ? 'bg-gray-500/20 text-gray-400' : 'bg-red-500/20 text-red-400'}`}>
                                                                                    {disk.health || disk.wearout || 'N/A'}
                                                                                </span>
                                                                            </td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* recent tasks */}
                                                {pbsTasks.length > 0 && (
                                                    <div>
                                                        <h2 className={isCorporate ? 'corp-section-header' : 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4'}>Recent Tasks</h2>
                                                        <div className={isCorporate ? 'overflow-hidden' : 'bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden'}>
                                                            <table className={isCorporate ? 'corp-datagrid' : 'w-full text-sm'}>
                                                                <thead><tr className={isCorporate ? '' : 'border-b border-proxmox-border text-gray-500 text-xs'}>
                                                                    <th className={isCorporate ? '' : 'text-left p-3'}>Type</th><th className={isCorporate ? '' : 'text-left p-3'}>Status</th><th className={isCorporate ? '' : 'text-left p-3'}>Started</th><th className={isCorporate ? '' : 'text-left p-3'}>Duration</th><th className={isCorporate ? '' : 'text-left p-3'}>Worker</th>
                                                                </tr></thead>
                                                                <tbody>
                                                                    {pbsTasks.slice(0, 10).map((task, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30 cursor-pointer" onClick={() => viewPBSTaskLog(task.upid)}>
                                                                            <td className="p-3 text-white font-medium">{task.worker_type || '-'}</td>
                                                                            <td className="p-3">
                                                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                                    task.status === 'OK' || task.status === 'ok' ? 'bg-green-500/20 text-green-400' :
                                                                                    task.status && task.status.startsWith && task.status.startsWith('WARNINGS') ? 'bg-yellow-500/20 text-yellow-400' :
                                                                                    !task.endtime ? 'bg-blue-500/20 text-blue-400' :
                                                                                    'bg-red-500/20 text-red-400'
                                                                                }`}>
                                                                                    {!task.endtime ? 'running' : (task.status || '?')}
                                                                                </span>
                                                                            </td>
                                                                            <td className="p-3 text-gray-400">{task.starttime ? new Date(task.starttime * 1000).toLocaleString() : '-'}</td>
                                                                            <td className="p-3 text-gray-400">{task.starttime ? pbsFormatDuration(task.starttime, task.endtime) : '-'}</td>
                                                                            <td className="p-3 text-gray-500 truncate max-w-[200px]">{task.worker_id || '-'}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Linked Clusters */}
                                                {selectedPBS.linked_clusters && selectedPBS.linked_clusters.length > 0 && (
                                                    <div>
                                                        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Linked PVE Clusters</h2>
                                                        <div className="flex gap-2 flex-wrap">
                                                            {selectedPBS.linked_clusters.map(cid => {
                                                                const cl = clusters.find(c => c.id === cid);
                                                                return cl ? (
                                                                    <button key={cid} onClick={() => { setSelectedCluster(cl); setSelectedPBS(null); }} className="px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-sm text-gray-300 hover:text-white hover:border-proxmox-orange/30 transition-all flex items-center gap-2">
                                                                        <Icons.Server className="w-4 h-4 text-proxmox-orange" />{cl.name}
                                                                    </button>
                                                                ) : null;
                                                            })}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Traffic Control / Bandwidth Limits */}
                                                {pbsTrafficControl && pbsTrafficControl.length > 0 && (
                                                    <div>
                                                        <h2 className={isCorporate ? 'corp-section-header' : 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4'}>Traffic Control</h2>
                                                        <div className={isCorporate ? 'overflow-hidden' : 'bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden'}>
                                                            <table className={isCorporate ? 'corp-datagrid' : 'w-full text-sm'}>
                                                                <thead><tr className={isCorporate ? '' : 'border-b border-proxmox-border text-gray-500 text-xs'}>
                                                                    <th className={isCorporate ? '' : 'text-left p-3'}>Name</th><th className={isCorporate ? '' : 'text-left p-3'}>Rate In</th><th className={isCorporate ? '' : 'text-left p-3'}>Rate Out</th><th className={isCorporate ? '' : 'text-left p-3'}>Burst In</th><th className={isCorporate ? '' : 'text-left p-3'}>Burst Out</th><th className={isCorporate ? '' : 'text-left p-3'}>Network</th><th className={isCorporate ? '' : 'text-left p-3'}>Timeframe</th>
                                                                </tr></thead>
                                                                <tbody>
                                                                    {pbsTrafficControl.map((tc, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30">
                                                                            <td className="p-3 text-white font-medium">{tc.name || '-'}</td>
                                                                            <td className="p-3 text-cyan-400">{tc['rate-in'] ? formatBytes(tc['rate-in']) + '/s' : 'unlimited'}</td>
                                                                            <td className="p-3 text-cyan-400">{tc['rate-out'] ? formatBytes(tc['rate-out']) + '/s' : 'unlimited'}</td>
                                                                            <td className="p-3 text-gray-400">{tc['burst-in'] ? formatBytes(tc['burst-in']) : '-'}</td>
                                                                            <td className="p-3 text-gray-400">{tc['burst-out'] ? formatBytes(tc['burst-out']) : '-'}</td>
                                                                            <td className="p-3 text-gray-400">{(tc.network || []).join(', ') || 'all'}</td>
                                                                            <td className="p-3 text-gray-500">{tc.timeframe || 'always'}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Notification Targets */}
                                                {pbsNotifications && (pbsNotifications.targets?.length > 0 || pbsNotifications.matchers?.length > 0) && (
                                                    <div>
                                                        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Notifications</h2>
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                            {pbsNotifications.targets?.length > 0 && (
                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                    <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                                                                        <Icons.Bell className="w-4 h-4 text-blue-400" />Targets ({pbsNotifications.targets.length})
                                                                    </h3>
                                                                    <div className="space-y-2">
                                                                        {pbsNotifications.targets.map((t, i) => (
                                                                            <div key={i} className="flex items-center justify-between p-2 rounded bg-proxmox-dark/50">
                                                                                <div className="flex items-center gap-2">
                                                                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                                        t.type === 'sendmail' ? 'bg-green-500/20 text-green-400' :
                                                                                        t.type === 'smtp' ? 'bg-blue-500/20 text-blue-400' :
                                                                                        t.type === 'gotify' ? 'bg-purple-500/20 text-purple-400' :
                                                                                        t.type === 'webhook' ? 'bg-orange-500/20 text-orange-400' :
                                                                                        'bg-gray-500/20 text-gray-400'
                                                                                    }`}>{t.type || 'unknown'}</span>
                                                                                    <span className="text-white text-sm">{t.name || t.endpoint || '-'}</span>
                                                                                </div>
                                                                                {t.disable && <span className="text-xs text-red-400">disabled</span>}
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {pbsNotifications.matchers?.length > 0 && (
                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                    <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                                                                        <Icons.Filter className="w-4 h-4 text-yellow-400" />Matchers ({pbsNotifications.matchers.length})
                                                                    </h3>
                                                                    <div className="space-y-2">
                                                                        {pbsNotifications.matchers.map((m, i) => (
                                                                            <div key={i} className="flex items-center justify-between p-2 rounded bg-proxmox-dark/50">
                                                                                <div>
                                                                                    <span className="text-white text-sm">{m.name || '-'}</span>
                                                                                    {m.target && <span className="text-xs text-gray-500 ml-2">to: {Array.isArray(m.target) ? m.target.join(', ') : m.target}</span>}
                                                                                </div>
                                                                                {m.disable && <span className="text-xs text-red-400">disabled</span>}
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Syslog (latest entries) */}
                                                <div>
                                                    <div className="flex items-center justify-between mb-4">
                                                        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">System Log</h2>
                                                        <button onClick={() => fetchPBSSyslog(selectedPBS.id, 200)} className="text-xs text-gray-500 hover:text-white transition-colors flex items-center gap-1">
                                                            <Icons.RefreshCw className="w-3 h-3" />Load More
                                                        </button>
                                                    </div>
                                                    {pbsSyslog.length > 0 ? (
                                                        <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-3 max-h-64 overflow-y-auto font-mono text-xs">
                                                            {pbsSyslog.map((entry, i) => (
                                                                <div key={i} className={`py-0.5 ${
                                                                    (entry.t || entry.n || '').toLowerCase().includes('error') ? 'text-red-400' :
                                                                    (entry.t || entry.n || '').toLowerCase().includes('warn') ? 'text-yellow-400' :
                                                                    'text-gray-400'
                                                                }`}>{entry.t || entry.n || JSON.stringify(entry)}</div>
                                                            ))}
                                                        </div>
                                                    ) : (
                                                        <button onClick={() => fetchPBSSyslog(selectedPBS.id)} className="w-full text-center py-6 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl hover:border-blue-500/30 transition-all cursor-pointer">
                                                            <Icons.Terminal className="w-6 h-6 mx-auto mb-2 opacity-30" />
                                                            <span className="text-sm">Click to load syslog</span>
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        )}

                                        {/* Datastores Tab */}
                                        {pbsActiveTab === 'datastores' && (
                                            <div className="flex gap-6">
                                                {/* Datastore List */}
                                                <div className="w-64 shrink-0 space-y-2">
                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Datastores</h3>
                                                    {pbsDatastores.map(ds => {
                                                        const name = ds.name || ds.store;
                                                        const used = ds.used || 0;
                                                        const total = ds.used && ds.avail ? ds.used + ds.avail : 1;
                                                        const pct = total > 0 ? ((used / total) * 100).toFixed(0) : 0;
                                                        return (
                                                            <button key={name} onClick={() => { setPbsSelectedStore(name); setPbsSelectedGroup(null); }}
                                                                className={`w-full text-left px-3 py-2.5 rounded-xl transition-all ${
                                                                    pbsSelectedStore === name ? 'bg-blue-500/20 border border-blue-500/30 text-white' : 'bg-proxmox-card border border-proxmox-border text-gray-300 hover:border-blue-500/20'
                                                                }`}>
                                                                <div className="flex items-center justify-between">
                                                                    <span className="text-sm font-medium truncate">{name}</span>
                                                                    <span className="text-xs text-gray-500">{pct}%</span>
                                                                </div>
                                                                <div className="w-full h-1 bg-proxmox-dark rounded-full mt-1.5 overflow-hidden">
                                                                    <div className="h-full bg-blue-500 rounded-full" style={{width: `${pct}%`}}></div>
                                                                </div>
                                                            </button>
                                                        );
                                                    })}
                                                </div>

                                                {/* Datastore Detail */}
                                                <div className="flex-1 min-w-0 space-y-6">
                                                    {pbsSelectedStore ? (
                                                        <>
                                                            {/* Datastore Actions */}
                                                            {isAdmin && (
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <button onClick={() => { setPbsActionLoading(p => ({...p, gc: true})); pbsAction('gc', pbsSelectedStore).finally(() => setPbsActionLoading(p => ({...p, gc: false}))); }} disabled={pbsActionLoading.gc} className="px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-sm text-gray-300 hover:text-white hover:border-blue-500/30 transition-all flex items-center gap-2 disabled:opacity-50">
                                                                        <Icons.Trash className="w-4 h-4" /> {pbsActionLoading.gc ? 'Starting...' : 'Garbage Collection'}
                                                                    </button>
                                                                    <button onClick={() => { setPbsActionLoading(p => ({...p, verify: true})); pbsAction('verify', pbsSelectedStore).finally(() => setPbsActionLoading(p => ({...p, verify: false}))); }} disabled={pbsActionLoading.verify} className="px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-sm text-gray-300 hover:text-white hover:border-green-500/30 transition-all flex items-center gap-2 disabled:opacity-50">
                                                                        <Icons.CheckCircle className="w-4 h-4" /> {pbsActionLoading.verify ? 'Starting...' : 'Verify'}
                                                                    </button>
                                                                    <button onClick={() => setShowPbsPrune(pbsSelectedStore)} className="px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-sm text-gray-300 hover:text-white hover:border-yellow-500/30 transition-all flex items-center gap-2">
                                                                        <Icons.Archive className="w-4 h-4" /> Prune
                                                                    </button>
                                                                </div>
                                                            )}

                                                            {/* Namespace Selector + GC Status */}
                                                            {(() => {
                                                                const currentDs = pbsDatastores.find(d => (d.name || d.store) === pbsSelectedStore);
                                                                const gcStatus = currentDs?.detail?.['gc-status'] || {};
                                                                return (
                                                                    <div className="flex flex-wrap gap-4 items-start">
                                                                        {pbsNamespaces.length > 0 && (
                                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-3 flex items-center gap-2">
                                                                                <span className="text-xs text-gray-500">Namespace:</span>
                                                                                <select className="bg-proxmox-dark border border-proxmox-border rounded px-2 py-1 text-sm text-white" defaultValue="">
                                                                                    <option value="">Root</option>
                                                                                    {pbsNamespaces.map((ns, i) => <option key={i} value={ns.ns || ns.name}>{ns.ns || ns.name}</option>)}
                                                                                </select>
                                                                            </div>
                                                                        )}
                                                                        {gcStatus['last-run-endtime'] && (
                                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-3 flex-1 min-w-[300px]">
                                                                                <span className="text-xs text-gray-500 block mb-1.5">Garbage Collection</span>
                                                                                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                                                                                    <span className="text-gray-500">Last GC:</span><span className="text-gray-300">{new Date(gcStatus['last-run-endtime'] * 1000).toLocaleString()}</span>
                                                                                    <span className="text-gray-500">Duration:</span><span className="text-gray-300">{gcStatus['last-run-duration'] ? `${Math.floor(gcStatus['last-run-duration'] / 60)}m ${gcStatus['last-run-duration'] % 60}s` : '-'}</span>
                                                                                    <span className="text-gray-500">Dedup Factor:</span><span className="text-cyan-400 font-medium">{(gcStatus['dedup-factor'] || 1).toFixed(2)}x</span>
                                                                                    <span className="text-gray-500">Disk Chunks:</span><span className="text-gray-300">{(gcStatus['disk-chunks'] || 0).toLocaleString()}</span>
                                                                                    <span className="text-gray-500">Disk Bytes:</span><span className="text-gray-300">{formatBytes(gcStatus['disk-bytes'] || 0)}</span>
                                                                                    {gcStatus['pending-chunks'] > 0 && (
                                                                                        <><span className="text-gray-500">Pending:</span><span className="text-yellow-400">{gcStatus['pending-chunks']} chunks ({formatBytes(gcStatus['pending-bytes'] || 0)})</span></>
                                                                                    )}
                                                                                    {gcStatus['removed-chunks'] > 0 && (
                                                                                        <><span className="text-gray-500">Removed:</span><span className="text-green-400">{gcStatus['removed-chunks']} chunks ({formatBytes(gcStatus['removed-bytes'] || 0)})</span></>
                                                                                    )}
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })()}

                                                            {/* Backup Groups */}
                                                            <div>
                                                                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Backup Groups ({pbsGroups.length})</h3>
                                                                {pbsGroups.length > 0 ? (
                                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                                        <table className="w-full text-sm">
                                                                            <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                                <th className="text-left p-3">Type</th><th className="text-left p-3">ID</th><th className="text-left p-3">Backups</th><th className="text-left p-3">Last Backup</th><th className="text-left p-3">Size</th><th className="text-right p-3">Notes</th>
                                                                            </tr></thead>
                                                                            <tbody>
                                                                                {pbsGroups.sort((a, b) => `${a['backup-type']}/${a['backup-id']}`.localeCompare(`${b['backup-type']}/${b['backup-id']}`)).map((grp, i) => (
                                                                                    <tr key={i} className={`border-b border-proxmox-border/50 hover:bg-proxmox-hover/30 cursor-pointer ${pbsSelectedGroup === `${grp['backup-type']}/${grp['backup-id']}` ? 'bg-blue-500/10' : ''}`}
                                                                                        onClick={() => setPbsSelectedGroup(`${grp['backup-type']}/${grp['backup-id']}`)}>
                                                                                        <td className="p-3">
                                                                                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                                                grp['backup-type'] === 'vm' ? 'bg-blue-500/20 text-blue-400' :
                                                                                                grp['backup-type'] === 'ct' ? 'bg-green-500/20 text-green-400' :
                                                                                                'bg-purple-500/20 text-purple-400'
                                                                                            }`}>{grp['backup-type']}</span>
                                                                                        </td>
                                                                                        <td className="p-3 text-white font-medium">{grp['backup-id']}</td>
                                                                                        <td className="p-3 text-gray-300">{grp['backup-count'] || grp.count || '-'}</td>
                                                                                        <td className="p-3 text-gray-400">{grp['last-backup'] ? new Date(grp['last-backup'] * 1000).toLocaleString() : '-'}</td>
                                                                                        <td className="p-3 text-gray-400">{grp.size ? formatBytes(grp.size) : '-'}</td>
                                                                                        <td className="p-3 text-right" onClick={(e) => e.stopPropagation()}>
                                                                                            <button onClick={() => { setPbsEditingNotes({ type: 'group', params: { 'backup-type': grp['backup-type'], 'backup-id': grp['backup-id'] }, label: `${grp['backup-type']}/${grp['backup-id']}` }); setPbsNotesText(grp.comment || grp.notes || ''); }} className="px-2 py-1 rounded text-xs text-gray-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-all" title="Group Notes">
                                                                                                <Icons.FileText className="w-3.5 h-3.5" />
                                                                                            </button>
                                                                                        </td>
                                                                                    </tr>
                                                                                ))}
                                                                            </tbody>
                                                                        </table>
                                                                    </div>
                                                                ) : (
                                                                    <div className="text-center py-8 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl">No backup groups found</div>
                                                                )}
                                                            </div>

                                                            {/* Snapshots for selected group */}
                                                            <div>
                                                                <div className="flex items-center justify-between mb-3">
                                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
                                                                        Snapshots {pbsSelectedGroup ? `- ${pbsSelectedGroup}` : `(All)`}
                                                                    </h3>
                                                                    {pbsSelectedGroup && (
                                                                        <button onClick={() => setPbsSelectedGroup(null)} className="text-xs text-gray-500 hover:text-white transition-colors">Show All</button>
                                                                    )}
                                                                </div>
                                                                {(() => {
                                                                    const filtered = pbsSelectedGroup 
                                                                        ? pbsSnapshots.filter(s => `${s['backup-type']}/${s['backup-id']}` === pbsSelectedGroup)
                                                                        : pbsSnapshots;
                                                                    const sorted = [...filtered].sort((a, b) => (b['backup-time'] || 0) - (a['backup-time'] || 0));
                                                                    return sorted.length > 0 ? (
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                                            <table className="w-full text-sm">
                                                                                <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                                    <th className="text-left p-3">Type/ID</th><th className="text-left p-3">Time</th><th className="text-left p-3">Size</th><th className="text-left p-3">Verified</th><th className="text-center p-3">Protected</th>
                                                                                    <th className="text-right p-3">Actions</th>
                                                                                </tr></thead>
                                                                                <tbody>
                                                                                    {sorted.slice(0, 50).map((snap, i) => (
                                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30">
                                                                                            <td className="p-3">
                                                                                                <span className="text-white">{snap['backup-type']}/{snap['backup-id']}</span>
                                                                                            </td>
                                                                                            <td className="p-3 text-gray-300">{snap['backup-time'] ? new Date(snap['backup-time'] * 1000).toLocaleString() : '-'}</td>
                                                                                            <td className="p-3 text-gray-400">{snap.size ? formatBytes(snap.size) : '-'}</td>
                                                                                            <td className="p-3">
                                                                                                {snap.verification ? (
                                                                                                    <span className={`px-2 py-0.5 rounded text-xs ${snap.verification.state === 'ok' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                                                                                        {snap.verification.state}
                                                                                                    </span>
                                                                                                ) : <span className="text-gray-600">-</span>}
                                                                                            </td>
                                                                                            <td className="p-3 text-center">
                                                                                                <button onClick={() => isAdmin && pbsToggleProtected(snap)} className={`px-2 py-0.5 rounded text-xs transition-all ${snap.protected ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-proxmox-dark text-gray-600 border border-proxmox-border'} ${isAdmin ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`} title={isAdmin ? 'Toggle protection' : (snap.protected ? 'Protected' : 'Unprotected')}>
                                                                                                    {snap.protected ? Icons.Shield ? <Icons.Shield className="w-3.5 h-3.5 inline" /> : 'Yes' : '-'}
                                                                                                </button>
                                                                                            </td>
                                                                                            <td className="p-3 text-right flex items-center justify-end gap-1">
                                                                                                {snap['backup-type'] === 'host' ? (
                                                                                                    <button onClick={() => pbsOpenFileBrowser(snap)} className="px-2 py-1 rounded text-xs text-gray-500 hover:text-blue-400 hover:bg-blue-500/10 transition-all" title="Browse Files">
                                                                                                        {Icons.FolderOpen ? <Icons.FolderOpen className="w-3.5 h-3.5" /> : <Icons.Folder className="w-3.5 h-3.5" />}
                                                                                                    </button>
                                                                                                ) : (
                                                                                                    <button onClick={() => pbsOpenFileBrowser(snap)} className="px-2 py-1 rounded text-xs text-gray-600 hover:text-blue-400 hover:bg-blue-500/10 transition-all" title="Browse Catalog (if available)">
                                                                                                        <Icons.Folder className="w-3.5 h-3.5" />
                                                                                                    </button>
                                                                                                )}
                                                                                                <button onClick={() => { setPbsEditingNotes({ type: 'snapshot', params: { 'backup-type': snap['backup-type'], 'backup-id': snap['backup-id'], 'backup-time': snap['backup-time'] }, label: `${snap['backup-type']}/${snap['backup-id']}` }); setPbsNotesText(snap.comment || snap.notes || ''); }} className="px-2 py-1 rounded text-xs text-gray-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-all" title="Notes">
                                                                                                    <Icons.FileText className="w-3.5 h-3.5" />
                                                                                                </button>
                                                                                                {isAdmin && (
                                                                                                    <button onClick={() => { if (confirm(`Delete snapshot ${snap['backup-type']}/${snap['backup-id']} @ ${new Date(snap['backup-time'] * 1000).toLocaleString()}?`)) pbsAction('delete-snapshot', pbsSelectedStore, { backup_type: snap['backup-type'], backup_id: snap['backup-id'], backup_time: snap['backup-time'] }); }} className="px-2 py-1 rounded text-xs text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-all" title="Delete">
                                                                                                        <Icons.Trash className="w-3.5 h-3.5" />
                                                                                                    </button>
                                                                                                )}
                                                                                            </td>
                                                                                        </tr>
                                                                                    ))}
                                                                                </tbody>
                                                                            </table>
                                                                            {sorted.length > 50 && <div className="text-center py-2 text-xs text-gray-500">Showing 50 of {sorted.length} snapshots</div>}
                                                                        </div>
                                                                    ) : (
                                                                        <div className="text-center py-8 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl">No snapshots found</div>
                                                                    );
                                                                })()}
                                                            </div>
                                                        </>
                                                    ) : (
                                                        <div className="text-center py-16 text-gray-500">
                                                            <Icons.Database className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                                            <p>Select a datastore to view details</p>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )}

                                        {/* Tasks Tab */}
                                        {pbsActiveTab === 'tasks' && (
                                            <div className="space-y-4">
                                                <div className="flex items-center justify-between">
                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Tasks ({pbsTasks.length})</h3>
                                                    <button onClick={() => fetchPBSTasks(selectedPBS.id)} className="text-xs text-gray-500 hover:text-white transition-colors flex items-center gap-1">
                                                        <Icons.RefreshCw className="w-3 h-3" /> Refresh
                                                    </button>
                                                </div>
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                    <table className="w-full text-sm">
                                                        <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                            <th className="text-left p-3">Type</th><th className="text-left p-3">Worker ID</th><th className="text-left p-3">Status</th><th className="text-left p-3">Started</th><th className="text-left p-3">Duration</th><th className="text-left p-3">User</th>
                                                        </tr></thead>
                                                        <tbody>
                                                            {pbsTasks.map((task, i) => (
                                                                <tr key={i} className={`border-b border-proxmox-border/50 hover:bg-proxmox-hover/30 cursor-pointer ${pbsTaskLog?.upid === task.upid ? 'bg-blue-500/10' : ''}`}
                                                                    onClick={() => viewPBSTaskLog(task.upid)}>
                                                                    <td className="p-3 text-white font-medium">{task.worker_type || '-'}</td>
                                                                    <td className="p-3 text-gray-300 truncate max-w-[200px]">{task.worker_id || '-'}</td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                            task.status === 'OK' || task.status === 'ok' ? 'bg-green-500/20 text-green-400' :
                                                                            task.status && task.status.startsWith && task.status.startsWith('WARNINGS') ? 'bg-yellow-500/20 text-yellow-400' :
                                                                            !task.endtime ? 'bg-blue-500/20 text-blue-400 animate-pulse' :
                                                                            'bg-red-500/20 text-red-400'
                                                                        }`}>{!task.endtime ? 'running' : (task.status || '?')}</span>
                                                                    </td>
                                                                    <td className="p-3 text-gray-400">{task.starttime ? new Date(task.starttime * 1000).toLocaleString() : '-'}</td>
                                                                    <td className="p-3 text-gray-400">{task.starttime ? pbsFormatDuration(task.starttime, task.endtime) : '-'}</td>
                                                                    <td className="p-3 text-gray-500">{task.user || '-'}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                    {pbsTasks.length === 0 && <div className="text-center py-8 text-gray-500">No tasks found</div>}
                                                </div>

                                                {/* Task Log Viewer */}
                                                {pbsTaskLog && (
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="flex items-center justify-between p-3 border-b border-proxmox-border">
                                                            <span className="text-sm font-medium text-white">Task Log</span>
                                                            <button onClick={() => setPbsTaskLog(null)} className="text-gray-500 hover:text-white"><Icons.X className="w-4 h-4" /></button>
                                                        </div>
                                                        <div className="p-3">
                                                            <div className="text-xs text-gray-500 mb-2">
                                                                Status: <span className={pbsTaskLog.status?.status === 'stopped' ? 'text-green-400' : 'text-blue-400'}>{pbsTaskLog.status?.status || '?'}</span>
                                                                {pbsTaskLog.status?.exitstatus && <span> | Exit: {pbsTaskLog.status.exitstatus}</span>}
                                                            </div>
                                                            <pre className="text-xs text-gray-300 font-mono bg-proxmox-dark rounded p-3 max-h-64 overflow-auto whitespace-pre-wrap">
                                                                {(pbsTaskLog.log || []).map(l => l.t || l.d || '').join('\n') || 'No log output'}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Jobs Tab */}
                                        {pbsActiveTab === 'jobs' && (
                                            <div className="space-y-6">
                                                {/* Sync Jobs */}
                                                <div>
                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Sync Jobs ({(pbsJobs.sync || []).length})</h3>
                                                    {(pbsJobs.sync || []).length > 0 ? (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <table className="w-full text-sm">
                                                                <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                    <th className="text-left p-3">ID</th><th className="text-left p-3">Store</th><th className="text-left p-3">Remote</th><th className="text-left p-3">Schedule</th><th className="text-left p-3">Last Run</th>
                                                                    {isAdmin && <th className="text-right p-3">Actions</th>}
                                                                </tr></thead>
                                                                <tbody>
                                                                    {(pbsJobs.sync || []).map((job, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30">
                                                                            <td className="p-3 text-white font-medium">{job.id}</td>
                                                                            <td className="p-3 text-gray-300">{job.store}</td>
                                                                            <td className="p-3 text-gray-400">{job.remote || '-'} / {job['remote-store'] || '-'}</td>
                                                                            <td className="p-3 text-gray-400">{job.schedule || 'manual'}</td>
                                                                            <td className="p-3 text-gray-500">{job['last-run-endtime'] ? new Date(job['last-run-endtime'] * 1000).toLocaleString() : '-'}</td>
                                                                            {isAdmin && (
                                                                                <td className="p-3 text-right">
                                                                                    <button onClick={() => pbsRunJob('sync', job.id)} className="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 transition-all flex items-center gap-1 ml-auto">
                                                                                        <Icons.Play className="w-3 h-3" /> Run
                                                                                    </button>
                                                                                </td>
                                                                            )}
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    ) : <div className="text-center py-6 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl text-sm">No sync jobs configured</div>}
                                                </div>

                                                {/* Verify Jobs */}
                                                <div>
                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Verify Jobs ({(pbsJobs.verify || []).length})</h3>
                                                    {(pbsJobs.verify || []).length > 0 ? (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <table className="w-full text-sm">
                                                                <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                    <th className="text-left p-3">ID</th><th className="text-left p-3">Store</th><th className="text-left p-3">Schedule</th><th className="text-left p-3">Ignore Verified</th><th className="text-left p-3">Last Run</th>
                                                                    {isAdmin && <th className="text-right p-3">Actions</th>}
                                                                </tr></thead>
                                                                <tbody>
                                                                    {(pbsJobs.verify || []).map((job, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30">
                                                                            <td className="p-3 text-white font-medium">{job.id}</td>
                                                                            <td className="p-3 text-gray-300">{job.store}</td>
                                                                            <td className="p-3 text-gray-400">{job.schedule || 'manual'}</td>
                                                                            <td className="p-3 text-gray-400">{job['ignore-verified'] ? 'Yes' : 'No'}</td>
                                                                            <td className="p-3 text-gray-500">{job['last-run-endtime'] ? new Date(job['last-run-endtime'] * 1000).toLocaleString() : '-'}</td>
                                                                            {isAdmin && (
                                                                                <td className="p-3 text-right">
                                                                                    <button onClick={() => pbsRunJob('verify', job.id)} className="px-2 py-1 rounded text-xs bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-all flex items-center gap-1 ml-auto">
                                                                                        <Icons.Play className="w-3 h-3" /> Run
                                                                                    </button>
                                                                                </td>
                                                                            )}
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    ) : <div className="text-center py-6 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl text-sm">No verify jobs configured</div>}
                                                </div>

                                                {/* Prune Jobs */}
                                                <div>
                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Prune Jobs ({(pbsJobs.prune || []).length})</h3>
                                                    {(pbsJobs.prune || []).length > 0 ? (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <table className="w-full text-sm">
                                                                <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                    <th className="text-left p-3">ID</th><th className="text-left p-3">Store</th><th className="text-left p-3">Schedule</th><th className="text-left p-3">Retention</th><th className="text-left p-3">Last Run</th>
                                                                    {isAdmin && <th className="text-right p-3">Actions</th>}
                                                                </tr></thead>
                                                                <tbody>
                                                                    {(pbsJobs.prune || []).map((job, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/30">
                                                                            <td className="p-3 text-white font-medium">{job.id}</td>
                                                                            <td className="p-3 text-gray-300">{job.store}</td>
                                                                            <td className="p-3 text-gray-400">{job.schedule || 'manual'}</td>
                                                                            <td className="p-3 text-gray-400 text-xs">
                                                                                {[job['keep-last'] && `L:${job['keep-last']}`, job['keep-daily'] && `D:${job['keep-daily']}`, job['keep-weekly'] && `W:${job['keep-weekly']}`, job['keep-monthly'] && `M:${job['keep-monthly']}`, job['keep-yearly'] && `Y:${job['keep-yearly']}`].filter(Boolean).join(' ') || '-'}
                                                                            </td>
                                                                            <td className="p-3 text-gray-500">{job['last-run-endtime'] ? new Date(job['last-run-endtime'] * 1000).toLocaleString() : '-'}</td>
                                                                            {isAdmin && (
                                                                                <td className="p-3 text-right">
                                                                                    <button onClick={() => pbsRunJob('prune', job.id)} className="px-2 py-1 rounded text-xs bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 transition-all flex items-center gap-1 ml-auto">
                                                                                        <Icons.Play className="w-3 h-3" /> Run
                                                                                    </button>
                                                                                </td>
                                                                            )}
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    ) : <div className="text-center py-6 text-gray-500 bg-proxmox-card border border-proxmox-border rounded-xl text-sm">No prune jobs configured</div>}
                                                </div>

                                                {/* Remotes */}
                                                {pbsRemotes.length > 0 && (
                                                    <div>
                                                        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Remotes ({pbsRemotes.length})</h3>
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <table className="w-full text-sm">
                                                                <thead><tr className="border-b border-proxmox-border text-gray-500 text-xs">
                                                                    <th className="text-left p-3">Name</th><th className="text-left p-3">Host</th><th className="text-left p-3">Auth ID</th><th className="text-left p-3">Fingerprint</th>
                                                                </tr></thead>
                                                                <tbody>
                                                                    {pbsRemotes.map((remote, i) => (
                                                                        <tr key={i} className="border-b border-proxmox-border/50">
                                                                            <td className="p-3 text-white font-medium">{remote.name}</td>
                                                                            <td className="p-3 text-gray-300">{remote.host || '-'}</td>
                                                                            <td className="p-3 text-gray-400">{remote['auth-id'] || remote.userid || '-'}</td>
                                                                            <td className="p-3 text-gray-500 font-mono text-xs truncate max-w-[200px]">{remote.fingerprint ? remote.fingerprint.substring(0, 23) + '...' : '-'}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Prune Dialog */}
                                        {showPbsPrune && (
                                            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl w-full max-w-md animate-scale-in">
                                                    <div className="p-6">
                                                        <h2 className="text-xl font-bold text-white mb-1">Prune Datastore</h2>
                                                        <p className="text-sm text-gray-400 mb-4">{showPbsPrune}</p>
                                                        <div className="space-y-3">
                                                            {[{k: 'keep_last', l: 'Keep Last'}, {k: 'keep_daily', l: 'Keep Daily'}, {k: 'keep_weekly', l: 'Keep Weekly'}, {k: 'keep_monthly', l: 'Keep Monthly'}, {k: 'keep_yearly', l: 'Keep Yearly'}].map(f => (
                                                                <div key={f.k} className="flex items-center justify-between">
                                                                    <label className="text-sm text-gray-300">{f.l}</label>
                                                                    <input type="number" min="0" max="365" value={pbsPruneForm[f.k] || ''} onChange={e => setPbsPruneForm(p => ({...p, [f.k]: parseInt(e.target.value) || 0}))} className="w-20 bg-proxmox-dark border border-proxmox-border rounded px-2 py-1 text-sm text-white text-center" />
                                                                </div>
                                                            ))}
                                                            <div className="flex items-center justify-between pt-2">
                                                                <label className="text-sm text-gray-300">Dry Run (preview only)</label>
                                                                <button onClick={() => setPbsPruneForm(p => ({...p, dry_run: !p.dry_run}))} className={`w-10 h-5 rounded-full transition-all ${pbsPruneForm.dry_run ? 'bg-blue-500' : 'bg-red-500'}`}>
                                                                    <div className={`w-4 h-4 bg-white rounded-full transition-transform ${pbsPruneForm.dry_run ? 'translate-x-5' : 'translate-x-0.5'}`}></div>
                                                                </button>
                                                            </div>
                                                            {!pbsPruneForm.dry_run && (
                                                                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-xs text-red-400">
                                                                    Warning: This will permanently delete backups that don't match the retention policy!
                                                                </div>
                                                            )}
                                                        </div>
                                                        <div className="flex justify-end gap-2 mt-6">
                                                            <button onClick={() => setShowPbsPrune(null)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 hover:text-white transition-colors text-sm">Cancel</button>
                                                            <button onClick={() => { pbsAction('prune', showPbsPrune, pbsPruneForm); setShowPbsPrune(null); }} className={`px-4 py-2 rounded-lg text-white text-sm font-medium ${pbsPruneForm.dry_run ? 'bg-blue-500 hover:bg-blue-600' : 'bg-red-500 hover:bg-red-600'}`}>
                                                                {pbsPruneForm.dry_run ? 'Preview Prune' : 'Execute Prune'}
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ) : selectedVMware ? (
                                    /* VMware Server Management View */
                                    <div className={isCorporate ? 'space-y-4' : 'space-y-6'}>
                                        {/* LW: Feb 2026 - VMware header */}
                                        <div className={`flex items-center justify-between ${isCorporate ? 'px-4 py-3 border-b' : ''}`} style={isCorporate ? {borderColor: '#485764', background: '#22343c'} : {}}>
                                            <div className="flex items-center gap-4">
                                                {isCorporate ? (
                                                    <Icons.Cloud className="w-5 h-5 flex-shrink-0" style={{color: '#49afd9'}} />
                                                ) : (
                                                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-green-500/10 border border-emerald-500/30 flex items-center justify-center">
                                                        <Icons.Cloud className="w-6 h-6 text-emerald-400" />
                                                    </div>
                                                )}
                                                <div>
                                                    <h1 className={isCorporate ? 'text-[15px] font-medium' : 'text-2xl font-bold'} style={{color: '#e9ecef'}}>{selectedVMware.name || selectedVMware.host}</h1>
                                                    <div className={`flex items-center gap-3 ${isCorporate ? 'text-[12px]' : 'text-sm'}`} style={{color: '#adbbc4'}}>
                                                        <span>{selectedVMware.host}:{selectedVMware.port || 443}</span>
                                                        <span>•</span>
                                                        <span>{vmwareVms.length} VMs</span>
                                                        <span>•</span>
                                                        <span>{vmwareHosts.length} Hosts</span>
                                                        <span>•</span>
                                                        <span>{vmwareDatastores.length} Datastores</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className={isCorporate ? 'corp-toolbar flex items-center gap-1' : 'flex items-center gap-2'}>
                                                {isAdmin && (
                                                    <>
                                                        <button onClick={() => { setEditingVMware(selectedVMware); setVmwareForm({ name: selectedVMware.name || '', host: selectedVMware.host, port: selectedVMware.port || 443, username: selectedVMware.username || 'root', password: '', ssl_verify: selectedVMware.ssl_verify || false, notes: selectedVMware.notes || '' }); setShowAddVMware(true); }} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-white text-sm'}>
                                                            <Icons.Settings className="w-4 h-4" />
                                                        </button>
                                                        <button onClick={() => handleDeleteVMware(selectedVMware.id)} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-red-400 hover:text-red-300 text-sm'}>
                                                            <Icons.Trash className="w-4 h-4" />
                                                        </button>
                                                    </>
                                                )}
                                                <button onClick={() => fetchVMwareVms(selectedVMware.id)} className={isCorporate ? '' : 'px-3 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-white text-sm'}>
                                                    <Icons.RefreshCw className={`w-4 h-4 ${vmwareLoading ? 'animate-spin' : ''}`} />
                                                </button>
                                            </div>
                                        </div>
                                        
                                        {/* LW: Feb 2026 - VMware tabs */}
                                        <div className={isCorporate
                                            ? 'flex items-center border-b border-proxmox-border'
                                            : 'flex items-center gap-1 p-1 bg-proxmox-card border border-proxmox-border rounded-xl w-fit'
                                        }>
                                            {[
                                                { id: 'vms', label: 'Virtual Machines', icon: Icons.Monitor },
                                                { id: 'hosts', label: 'Hosts', icon: Icons.Server },
                                                { id: 'datastores', label: 'Datastores', icon: Icons.Database },
                                                { id: 'networks', label: 'Networks', icon: Icons.Globe },
                                                { id: 'clusters', label: 'Clusters', icon: Icons.Layers },
                                                { id: 'tasks', label: 'Tasks & Events', icon: Icons.ClipboardList },
                                            ].map(tab => (
                                                <button
                                                    key={tab.id}
                                                    onClick={() => { setVmwareActiveTab(tab.id); setVmwareSelectedVm(null); setVmwareSelectedDs(null); }}
                                                    className={isCorporate
                                                        ? `flex items-center gap-1 px-3 py-1.5 text-[13px] border-b-2 -mb-px ${
                                                            vmwareActiveTab === tab.id
                                                                ? 'border-blue-500 text-white font-medium'
                                                                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
                                                          }`
                                                        : `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                                            vmwareActiveTab === tab.id
                                                                ? 'bg-emerald-500 text-white'
                                                                : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                                        }`
                                                    }
                                                >
                                                    <tab.icon className={isCorporate ? 'w-3 h-3' : 'w-4 h-4'} />
                                                    {tab.label}
                                                </button>
                                            ))}
                                        </div>
                                        
                                        {/* VMs Tab */}
                                        {/* Connection Warning */}
                                        {!vmwareConnectionOk && (
                                            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 flex items-center gap-3">
                                                <Icons.AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
                                                <div className="flex-1">
                                                    <span className="text-yellow-300 text-sm font-medium">Connection lost</span>
                                                    <span className="text-yellow-400/70 text-sm ml-2">Session expired - data may be stale</span>
                                                </div>
                                                <button onClick={() => { fetchVMwareVms(selectedVMware.id); fetchVMwareHosts(selectedVMware.id); fetchVMwareDatastores(selectedVMware.id); }} 
                                                    className="px-3 py-1.5 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-300 rounded-lg text-xs font-medium">
                                                    Reconnect
                                                </button>
                                            </div>
                                        )}
                                        
                                        {vmwareActiveTab === 'vms' && !vmwareSelectedVm && (
                                            <div className="space-y-4">
                                                {/* LW: search + filter */}
                                                <div className="flex items-center gap-3">
                                                    <div className="flex-1 relative">
                                                        <Icons.Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{color: '#728b9a'}} />
                                                        <input
                                                            value={vmwareSearch}
                                                            onChange={e => setVmwareSearch(e.target.value)}
                                                            placeholder="Search VMs..."
                                                            className={isCorporate ? 'w-full pl-10 pr-4 py-2 text-[13px] text-white placeholder-gray-500 focus:outline-none' : 'w-full pl-10 pr-4 py-2.5 bg-proxmox-card border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500/50 text-sm'}
                                                            style={isCorporate ? {background: '#22343c', border: '1px solid #485764', borderRadius: '2px'} : {}}
                                                        />
                                                    </div>
                                                    <div className={isCorporate ? 'flex items-center gap-0' : 'flex items-center gap-1 p-1 bg-proxmox-card border border-proxmox-border rounded-xl'} style={isCorporate ? {border: '1px solid #485764', borderRadius: '2px'} : {}}>
                                                        {['all', 'running', 'stopped'].map(f => (
                                                            <button key={f} onClick={() => setVmwareFilter(f)}
                                                                className={isCorporate
                                                                    ? `px-3 py-1.5 text-[12px] font-medium ${vmwareFilter === f ? 'text-white' : 'hover:text-white'}`
                                                                    : `px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${vmwareFilter === f ? 'bg-emerald-500/20 text-emerald-400' : 'text-gray-500 hover:text-white'}`
                                                                }
                                                                style={isCorporate ? {color: vmwareFilter === f ? '#e9ecef' : '#728b9a', background: vmwareFilter === f ? '#324f61' : 'transparent', borderRight: '1px solid #485764'} : {}}
                                                            >
                                                                {f === 'all' ? `All (${vmwareVms.length})` : f === 'running' ? `Running (${vmwareVms.filter(v => v.power_state === 'POWERED_ON').length})` : `Stopped (${vmwareVms.filter(v => v.power_state !== 'POWERED_ON').length})`}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                                
                                                {/* VM Table */}
                                                {vmwareLoading && vmwareVms.length === 0 ? (
                                                    <div className="text-center py-12 text-gray-500">Loading VMs...</div>
                                                ) : (
                                                    <div className={isCorporate ? 'overflow-hidden' : 'bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden'}>
                                                        <table className={isCorporate ? 'corp-datagrid' : 'w-full'}>
                                                            <thead>
                                                                <tr className={isCorporate ? '' : 'border-b border-proxmox-border'}>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>Status</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>Name</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>Guest OS</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>CPUs</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>Memory</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>IP Address</th>
                                                                    <th className={isCorporate ? '' : 'text-left p-3 text-xs font-semibold text-gray-500 uppercase'}>Host</th>
                                                                    <th className={isCorporate ? 'text-right' : 'text-right p-3 text-xs font-semibold text-gray-500 uppercase'}>Actions</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                {vmwareVms
                                                                    .filter(vm => {
                                                                        if (vmwareFilter === 'running') return vm.power_state === 'POWERED_ON';
                                                                        if (vmwareFilter === 'stopped') return vm.power_state !== 'POWERED_ON';
                                                                        return true;
                                                                    })
                                                                    .filter(vm => !vmwareSearch || (vm.name || '').toLowerCase().includes(vmwareSearch.toLowerCase()) || (vm.guest_os || '').toLowerCase().includes(vmwareSearch.toLowerCase()))
                                                                    .sort((a, b) => {
                                                                        if (vmwareSortBy === 'status') return (a.power_state || '').localeCompare(b.power_state || '');
                                                                        return (a.name || '').localeCompare(b.name || '');
                                                                    })
                                                                    .map(vm => {
                                                                        const isOn = vm.power_state === 'POWERED_ON';
                                                                        const isSuspended = vm.power_state === 'SUSPENDED';
                                                                        const memGB = vm.memory_size_MiB ? (vm.memory_size_MiB / 1024).toFixed(1) : vm.memory_mb ? (vm.memory_mb / 1024).toFixed(1) : '-';
                                                                        const ip = vm.guest_info?.ip_address || vm.ip_address || vm.guest_ip || '-';
                                                                        const actionLoading = vmwareActionLoading[vm.vm || vm.vm_id || vm.id];
                                                                        
                                                                        return (
                                                                            <tr key={vm.vm || vm.vm_id || vm.id} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/50 cursor-pointer transition-colors" onClick={() => setVmwareSelectedVm(vm.vm || vm.vm_id || vm.id)}>
                                                                                <td className="p-3">
                                                                                    <div className={`w-3 h-3 rounded-full ${isOn ? 'bg-green-400 shadow-lg shadow-green-400/30' : isSuspended ? 'bg-yellow-400' : 'bg-gray-500'}`} title={vm.power_state} />
                                                                                </td>
                                                                                <td className="p-3">
                                                                                    <div className="font-medium text-white text-sm">{vm.name}</div>
                                                                                </td>
                                                                                <td className="p-3 text-gray-400 text-sm">{(vm.guest_OS || vm.guest_os || '-').replace('Guest', '').replace('_', ' ').substring(0, 25)}</td>
                                                                                <td className="p-3 text-gray-400 text-sm">{vm.cpu_count || vm.num_cpu || '-'}</td>
                                                                                <td className="p-3 text-gray-400 text-sm">{memGB} GB</td>
                                                                                <td className="p-3 text-gray-400 text-sm font-mono text-xs">{ip}</td>
                                                                                <td className="p-3 text-gray-400 text-sm">{(vm.host || vm.host_name || '-').split('.')[0]}</td>
                                                                                <td className="p-3 text-right" onClick={e => e.stopPropagation()}>
                                                                                    <div className="flex items-center justify-end gap-1">
                                                                                        {!isOn ? (
                                                                                            <button onClick={() => vmwarePowerAction(vm.vm || vm.vm_id || vm.id, 'start')} disabled={!!actionLoading} className="p-1.5 rounded-lg text-green-400 hover:bg-green-500/10 disabled:opacity-50" title="Start">
                                                                                                {actionLoading === 'start' ? <Icons.RefreshCw className="w-4 h-4 animate-spin" /> : <Icons.Play className="w-4 h-4" />}
                                                                                            </button>
                                                                                        ) : (
                                                                                            <>
                                                                                                <button onClick={() => vmwarePowerAction(vm.vm || vm.vm_id || vm.id, 'stop')} disabled={!!actionLoading} className="p-1.5 rounded-lg text-red-400 hover:bg-red-500/10 disabled:opacity-50" title="Shutdown">
                                                                                                    {actionLoading === 'stop' ? <Icons.RefreshCw className="w-4 h-4 animate-spin" /> : <Icons.Square className="w-4 h-4" />}
                                                                                                </button>
                                                                                                <button onClick={() => vmwarePowerAction(vm.vm || vm.vm_id || vm.id, 'reset')} disabled={!!actionLoading} className="p-1.5 rounded-lg text-yellow-400 hover:bg-yellow-500/10 disabled:opacity-50" title="Reset">
                                                                                                    <Icons.RotateCw className="w-4 h-4" />
                                                                                                </button>
                                                                                                <button onClick={() => vmwarePowerAction(vm.vm || vm.vm_id || vm.id, 'suspend')} disabled={!!actionLoading} className="p-1.5 rounded-lg text-blue-400 hover:bg-blue-500/10 disabled:opacity-50" title="Suspend">
                                                                                                    <Icons.Pause className="w-4 h-4" />
                                                                                                </button>
                                                                                            </>
                                                                                        )}
                                                                                    </div>
                                                                                </td>
                                                                            </tr>
                                                                        );
                                                                    })}
                                                            </tbody>
                                                        </table>
                                                        {vmwareVms.length === 0 && !vmwareLoading && (
                                                            <div className="text-center py-12 text-gray-500">No virtual machines found</div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                        
                                        {/* VM Detail View */}
                                        {vmwareActiveTab === 'vms' && vmwareSelectedVm && (
                                            <div className="space-y-4">
                                                <button onClick={() => { setVmwareSelectedVm(null); setVmwareVmTab('overview'); }} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
                                                    <span style={{display:"inline-block",transform:"rotate(180deg)"}}><Icons.ChevronRight className="w-4 h-4" /></span> Back to VM List
                                                </button>
                                                
                                                {vmwareVmDetail ? (() => {
                                                    const vm = vmwareVmDetail;
                                                    const isOn = vm.power_state === 'POWERED_ON';
                                                    const isSuspended = vm.power_state === 'SUSPENDED';
                                                    const memMiB = vm.memory?.size_MiB || vm.memory_size_MiB || vm.memory_mb || 0;
                                                    const memGB = memMiB ? (memMiB / 1024).toFixed(1) : '-';
                                                    const cpuCount = vm.cpu?.count || vm.cpu_count || vm.num_cpu || 0;
                                                    const guestOS = vm.guest_OS || vm.guest_os || '-';
                                                    const toolsStatus = vm.guest_info?.tools_status || vm.vmware_tools_status || '';
                                                    const ipAddr = vm.guest_info?.ip_address || vm.ip_address || vm.guest_ip || '';
                                                    const hostName = vm.guest_info?.host_name || vm.hostname || '';
                                                    const hwVersion = vm.hardware?.version || '';
                                                    const disksList = vm.disks ? (Array.isArray(vm.disks) ? vm.disks : Object.values(vm.disks)) : [];
                                                    const netsList = vm.networks ? (Array.isArray(vm.networks) ? vm.networks : Object.values(vm.networks)) : [];
                                                    const snapsList = vm.snapshots && Array.isArray(vm.snapshots) ? vm.snapshots : [];
                                                    const totalDiskGB = disksList.reduce((sum, d) => sum + (d.capacity ? d.capacity / (1024*1024*1024) : d.capacity_gb || 0), 0);
                                                    
                                                    return (
                                                        <div className="space-y-4">
                                                            {/* VM Header Card */}
                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-5">
                                                                <div className="flex items-center justify-between">
                                                                    <div className="flex items-center gap-4">
                                                                        <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${isOn ? 'bg-green-500/10 border border-green-500/30' : isSuspended ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-gray-500/10 border border-gray-500/30'}`}>
                                                                            <Icons.Monitor className={`w-7 h-7 ${isOn ? 'text-green-400' : isSuspended ? 'text-yellow-400' : 'text-gray-500'}`} />
                                                                        </div>
                                                                        <div>
                                                                            <div className="flex items-center gap-3">
                                                                                <h2 className="text-xl font-bold text-white">{vm.name}</h2>
                                                                                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${isOn ? 'bg-green-500/20 text-green-400' : isSuspended ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-500/20 text-gray-400'}`}>
                                                                                    {isOn ? 'ON' : isSuspended ? 'SUSPENDED' : 'OFF'}
                                                                                </span>
                                                                                {hwVersion && <span className="text-xs text-gray-600">{hwVersion}</span>}
                                                                            </div>
                                                                            <div className="flex items-center gap-4 text-xs text-gray-500 mt-1">
                                                                                <span>{guestOS}</span>
                                                                                {cpuCount > 0 && <span>{cpuCount} vCPU</span>}
                                                                                {memGB !== '-' && <span>{memGB} GB RAM</span>}
                                                                                {totalDiskGB > 0 && <span>{totalDiskGB.toFixed(0)} GB Disk</span>}
                                                                                {toolsStatus && <span className={toolsStatus.includes('Not') ? 'text-yellow-500' : 'text-gray-500'}>Tools: {toolsStatus.replace('toolsStatus','').replace('tools','')}</span>}
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                    <div className="flex items-center gap-2">
                                                                        {/* Power Actions */}
                                                                        {!isOn ? (
                                                                            <button onClick={() => vmwarePowerAction(vmwareSelectedVm, 'start')} className="px-4 py-2 rounded-lg bg-green-500/20 text-green-400 hover:bg-green-500/30 text-sm font-medium flex items-center gap-1.5">
                                                                                <Icons.Play className="w-4 h-4" /> Start
                                                                            </button>
                                                                        ) : (
                                                                            <>
                                                                                <button onClick={() => vmwarePowerAction(vmwareSelectedVm, 'stop')} className="px-3 py-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 text-sm font-medium flex items-center gap-1.5">
                                                                                    <Icons.Square className="w-3.5 h-3.5" /> Stop
                                                                                </button>
                                                                                <button onClick={() => vmwarePowerAction(vmwareSelectedVm, 'reset')} className="p-2 rounded-lg bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20" title="Reset">
                                                                                    <Icons.RotateCw className="w-4 h-4" />
                                                                                </button>
                                                                                <button onClick={() => vmwarePowerAction(vmwareSelectedVm, 'suspend')} className="p-2 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20" title="Suspend">
                                                                                    <Icons.Pause className="w-4 h-4" />
                                                                                </button>
                                                                            </>
                                                                        )}
                                                                        <div className="w-px h-8 bg-proxmox-border mx-1" />
                                                                        {/* Console */}
                                                                        {isOn && (
                                                                            <button onClick={() => openVmwareConsole(vmwareSelectedVm)} className="p-2 rounded-lg bg-purple-500/10 text-purple-400 hover:bg-purple-500/20" title="Console (VMRC)">
                                                                                <Icons.Terminal className="w-4 h-4" />
                                                                            </button>
                                                                        )}
                                                                        {/* More Actions Dropdown */}
                                                                        <div className="relative group">
                                                                            <button className="p-2 rounded-lg bg-proxmox-dark border border-proxmox-border text-gray-400 hover:text-white">
                                                                                <Icons.Settings className="w-4 h-4" />
                                                                            </button>
                                                                            <div className="absolute right-0 top-full mt-1 w-48 bg-proxmox-card border border-proxmox-border rounded-xl shadow-xl z-50 hidden group-hover:block">
                                                                                <div className="py-1">
                                                                                    <button onClick={() => { setVmwareRenameName(vm.name || ''); setShowVmwareRename(true); }} className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2">
                                                                                        <Icons.Edit className="w-3.5 h-3.5" /> Rename
                                                                                    </button>
                                                                                    <button onClick={() => { setVmwareCloneName(`${vm.name}-clone`); setShowVmwareClone(true); }} className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-proxmox-hover flex items-center gap-2">
                                                                                        <Icons.Copy className="w-3.5 h-3.5" /> Clone
                                                                                    </button>
                                                                                    <button onClick={() => { fetchMigrationPlan(vmwareSelectedVm); }} className="w-full text-left px-4 py-2 text-sm text-emerald-400 hover:bg-proxmox-hover flex items-center gap-2">
                                                                                        <Icons.FolderInput className="w-3.5 h-3.5" /> Migrate to Proxmox
                                                                                    </button>
                                                                                    <div className="border-t border-proxmox-border my-1" />
                                                                                    <button onClick={() => setShowVmwareDelete(true)} disabled={isOn} className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-proxmox-hover flex items-center gap-2 disabled:opacity-30 disabled:cursor-not-allowed">
                                                                                        <Icons.Trash className="w-3.5 h-3.5" /> Delete VM {isOn ? '(stop first)' : ''}
                                                                                    </button>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* VM Detail Tabs */}
                                                            <div className="flex items-center gap-1 border-b border-proxmox-border">
                                                                {[
                                                                    { id: 'overview', label: 'Overview' },
                                                                    { id: 'settings', label: 'Settings' },
                                                                    { id: 'config', label: 'Hardware' },
                                                                    { id: 'snapshots', label: `Snapshots (${snapsList.length})` },
                                                                    { id: 'migrate', label: 'Migration' },
                                                                ].map(tab => (
                                                                    <button key={tab.id} onClick={() => setVmwareVmTab(tab.id)}
                                                                        className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-all ${
                                                                            vmwareVmTab === tab.id
                                                                                ? 'border-emerald-400 text-emerald-400'
                                                                                : 'border-transparent text-gray-500 hover:text-gray-300'
                                                                        }`}
                                                                    >{tab.label}</button>
                                                                ))}
                                                            </div>
                                                            
                                                            {/* Overview Tab */}
                                                            {vmwareVmTab === 'overview' && (
                                                                <div className="space-y-4">
                                                                    {/* Resource Cards */}
                                                                    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <div className="flex items-center justify-between mb-2">
                                                                                <span className="text-xs text-gray-500 uppercase font-semibold">CPU</span>
                                                                                <Icons.Cpu className="w-4 h-4 text-blue-400" />
                                                                            </div>
                                                                            <div className="text-2xl font-bold text-white">{cpuCount}</div>
                                                                            <div className="text-xs text-gray-500">vCPUs</div>
                                                                        </div>
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <div className="flex items-center justify-between mb-2">
                                                                                <span className="text-xs text-gray-500 uppercase font-semibold">Memory</span>
                                                                                <Icons.Memory className="w-4 h-4 text-purple-400" />
                                                                            </div>
                                                                            <div className="text-2xl font-bold text-white">{memGB}</div>
                                                                            <div className="text-xs text-gray-500">GB RAM</div>
                                                                        </div>
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <div className="flex items-center justify-between mb-2">
                                                                                <span className="text-xs text-gray-500 uppercase font-semibold">Storage</span>
                                                                                <Icons.HardDrive className="w-4 h-4 text-emerald-400" />
                                                                            </div>
                                                                            <div className="text-2xl font-bold text-white">{totalDiskGB > 0 ? totalDiskGB.toFixed(0) : '-'}</div>
                                                                            <div className="text-xs text-gray-500">GB ({disksList.length} disks)</div>
                                                                        </div>
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <div className="flex items-center justify-between mb-2">
                                                                                <span className="text-xs text-gray-500 uppercase font-semibold">Network</span>
                                                                                <Icons.Globe className="w-4 h-4 text-cyan-400" />
                                                                            </div>
                                                                            <div className="text-lg font-mono font-bold text-white">{ipAddr || '-'}</div>
                                                                            <div className="text-xs text-gray-500">{hostName || `${netsList.length} adapters`}</div>
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    {/* Guest Info + VM Info */}
                                                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">VM Information</h3>
                                                                            <div className="space-y-2 text-sm">
                                                                                {[
                                                                                    ['VM ID', vm.vm || vmwareSelectedVm],
                                                                                    ['Guest OS', guestOS],
                                                                                    ['Hardware Version', hwVersion || '-'],
                                                                                    ['Guest Tools', toolsStatus || 'Not installed'],
                                                                                    ['Power State', vm.power_state || '-'],
                                                                                    ['IP Address', ipAddr || 'N/A'],
                                                                                    ['Hostname', hostName || 'N/A'],
                                                                                ].map(([label, value]) => (
                                                                                    <div key={label} className="flex justify-between">
                                                                                        <span className="text-gray-500">{label}</span>
                                                                                        <span className="text-white font-mono text-xs">{value}</span>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Disks</h3>
                                                                            {disksList.length > 0 ? (
                                                                                <div className="space-y-2">
                                                                                    {disksList.map((disk, idx) => {
                                                                                        const capGB = disk.capacity ? (disk.capacity / (1024*1024*1024)).toFixed(1) : disk.capacity_gb || '?';
                                                                                        return (
                                                                                            <div key={idx} className="flex items-center justify-between p-2.5 bg-proxmox-dark rounded-lg">
                                                                                                <div className="flex items-center gap-2">
                                                                                                    <Icons.HardDrive className="w-4 h-4 text-gray-500" />
                                                                                                    <div>
                                                                                                        <div className="text-sm text-white">{disk.label || `Disk ${idx}`}</div>
                                                                                                        {disk.backing?.thin_provisioned && <div className="text-xs text-gray-600">Thin provisioned</div>}
                                                                                                    </div>
                                                                                                </div>
                                                                                                <div className="text-right">
                                                                                                    <div className="text-sm text-white font-medium">{capGB} GB</div>
                                                                                                    {disk.backing?.datastore && <div className="text-xs text-gray-600">{disk.backing.datastore}</div>}
                                                                                                </div>
                                                                                            </div>
                                                                                        );
                                                                                    })}
                                                                                </div>
                                                                            ) : <div className="text-gray-600 text-sm">No disks found</div>}
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    {/* Network Adapters */}
                                                                    {netsList.length > 0 && (
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Network Adapters</h3>
                                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                                                {netsList.map((nic, idx) => (
                                                                                    <div key={idx} className="flex items-center justify-between p-2.5 bg-proxmox-dark rounded-lg">
                                                                                        <div className="flex items-center gap-2">
                                                                                            <Icons.Globe className="w-4 h-4 text-gray-500" />
                                                                                            <span className="text-sm text-white">{nic.label || nic.name || `NIC ${idx}`}</span>
                                                                                        </div>
                                                                                        <span className="text-xs text-gray-400 font-mono">{nic.mac_address || '-'}</span>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                            
                                                            {/* Settings Tab -- Editable VM Configuration */}
                                                            {vmwareVmTab === 'settings' && (() => {
                                                                // Initialize edit form from VM detail
                                                                const initCpu = vmwareConfigEdit.cpu || cpuCount || 1;
                                                                const initMem = vmwareConfigEdit.memory || memGB * 1024 || 2048;
                                                                const initNotes = vmwareConfigEdit.notes !== undefined && vmwareConfigEdit.notes !== '' ? vmwareConfigEdit.notes : (vm.annotation || vm.notes || vm.config?.annotation || '');
                                                                const perfData = vm.performance || {};
                                                                
                                                                return (
                                                                    <div className="space-y-4">
                                                                        {/* Power State Warning */}
                                                                        {isOn && (
                                                                            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3">
                                                                                <div className="flex items-center gap-2 text-yellow-400 text-sm">
                                                                                    <Icons.AlertTriangle className="w-4 h-4" />
                                                                                    <span>VM is powered on - some changes (CPU, Memory) may require the VM to be powered off or need hot-add enabled.</span>
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                        
                                                                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                                                            {/* CPU & Memory */}
                                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                                                                    <Icons.Cpu className="w-4 h-4" /> Compute Resources
                                                                                </h3>
                                                                                <div className="space-y-4">
                                                                                    <div>
                                                                                        <label className="block text-xs text-gray-500 mb-1.5">vCPUs</label>
                                                                                        <div className="flex items-center gap-2">
                                                                                            <input type="number" min="1" max="128" 
                                                                                                value={vmwareConfigEdit.cpu || cpuCount || ''} 
                                                                                                onChange={e => setVmwareConfigEdit(p => ({...p, cpu: e.target.value}))}
                                                                                                className="flex-1 bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-white text-sm" />
                                                                                            <span className="text-xs text-gray-500 w-16">cores</span>
                                                                                        </div>
                                                                                    </div>
                                                                                    <div>
                                                                                        <label className="block text-xs text-gray-500 mb-1.5">Memory (MB)</label>
                                                                                        <div className="flex items-center gap-2">
                                                                                            <input type="number" min="256" step="256"
                                                                                                value={vmwareConfigEdit.memory || (memGB * 1024) || ''} 
                                                                                                onChange={e => setVmwareConfigEdit(p => ({...p, memory: e.target.value}))}
                                                                                                className="flex-1 bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-white text-sm" />
                                                                                            <span className="text-xs text-gray-500 w-16">MB</span>
                                                                                        </div>
                                                                                        <div className="flex gap-2 mt-1">
                                                                                            {[1024, 2048, 4096, 8192, 16384].map(v => (
                                                                                                <button key={v} onClick={() => setVmwareConfigEdit(p => ({...p, memory: String(v)}))}
                                                                                                    className={`px-2 py-0.5 rounded text-xs ${parseInt(vmwareConfigEdit.memory || memGB * 1024) === v ? 'bg-emerald-500/20 text-emerald-400' : 'bg-proxmox-dark text-gray-500 hover:text-white'}`}>
                                                                                                    {v >= 1024 ? `${v/1024}G` : `${v}M`}
                                                                                                </button>
                                                                                            ))}
                                                                                        </div>
                                                                                    </div>
                                                                                    
                                                                                    {/* Hot-Add Toggles */}
                                                                                    <div className="pt-2 border-t border-proxmox-border/50 space-y-2">
                                                                                        <label className="flex items-center justify-between cursor-pointer">
                                                                                            <span className="text-sm text-gray-400">CPU Hot-Add</span>
                                                                                            <div onClick={() => setVmwareConfigEdit(p => ({...p, cpu_hot_add: !p.cpu_hot_add}))}
                                                                                                className={`w-10 h-5 rounded-full transition-colors cursor-pointer flex items-center ${vmwareConfigEdit.cpu_hot_add ? 'bg-emerald-500' : 'bg-gray-700'}`}>
                                                                                                <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform ${vmwareConfigEdit.cpu_hot_add ? 'translate-x-5' : 'translate-x-0.5'}`} />
                                                                                            </div>
                                                                                        </label>
                                                                                        <label className="flex items-center justify-between cursor-pointer">
                                                                                            <span className="text-sm text-gray-400">Memory Hot-Add</span>
                                                                                            <div onClick={() => setVmwareConfigEdit(p => ({...p, memory_hot_add: !p.memory_hot_add}))}
                                                                                                className={`w-10 h-5 rounded-full transition-colors cursor-pointer flex items-center ${vmwareConfigEdit.memory_hot_add ? 'bg-emerald-500' : 'bg-gray-700'}`}>
                                                                                                <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform ${vmwareConfigEdit.memory_hot_add ? 'translate-x-5' : 'translate-x-0.5'}`} />
                                                                                            </div>
                                                                                        </label>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                            
                                                                            {/* Notes & Boot Order */}
                                                                            <div className="space-y-4">
                                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                                                                        <Icons.FileText className="w-4 h-4" /> Notes
                                                                                    </h3>
                                                                                    <textarea
                                                                                        value={vmwareConfigEdit.notes !== undefined && vmwareConfigEdit.notes !== '' ? vmwareConfigEdit.notes : (vm.annotation || vm.notes || vm.config?.annotation || '')}
                                                                                        onChange={e => setVmwareConfigEdit(p => ({...p, notes: e.target.value}))}
                                                                                        placeholder="VM description / notes..."
                                                                                        rows={4}
                                                                                        className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-white text-sm resize-none"
                                                                                    />
                                                                                </div>
                                                                                
                                                                                {/* Boot Order */}
                                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                                                                        <Icons.Play className="w-4 h-4" /> Boot Order
                                                                                    </h3>
                                                                                    <div className="space-y-2">
                                                                                        {[
                                                                                            { key: 'disk', label: 'Hard Disk', icon: '💾' },
                                                                                            { key: 'cdrom', label: 'CD-ROM', icon: '💿' },
                                                                                            { key: 'net', label: 'Network (PXE)', icon: '🌐' },
                                                                                        ].map((item, idx) => (
                                                                                            <div key={item.key} className="flex items-center gap-3 p-2.5 bg-proxmox-dark rounded-lg">
                                                                                                <span className="text-xs text-gray-500 w-5">{idx + 1}.</span>
                                                                                                <span>{item.icon}</span>
                                                                                                <span className="text-sm text-white flex-1">{item.label}</span>
                                                                                            </div>
                                                                                        ))}
                                                                                        <button onClick={() => handleVmwareBootOrderSave(vmwareSelectedVm, ['disk', 'cdrom', 'net'])}
                                                                                            className="text-xs text-gray-500 hover:text-emerald-400 transition-colors">
                                                                                            Reset to default (Disk → CD → Network)
                                                                                        </button>
                                                                                    </div>
                                                                                </div>
                                                                                
                                                                                {/* Network */}
                                                                                {netsList.length > 0 && (
                                                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                        <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4 flex items-center gap-2">
                                                                                            <Icons.Globe className="w-4 h-4" /> Network Adapters
                                                                                        </h3>
                                                                                        <div className="space-y-3">
                                                                                            {netsList.map((nic, idx) => (
                                                                                                <div key={idx} className="p-3 bg-proxmox-dark rounded-lg">
                                                                                                    <div className="flex items-center justify-between mb-2">
                                                                                                        <span className="text-sm text-white font-medium">{nic.label || `NIC ${idx + 1}`}</span>
                                                                                                        <span className="text-xs text-gray-500 font-mono">{nic.mac_address || ''}</span>
                                                                                                    </div>
                                                                                                    <div className="flex items-center gap-2">
                                                                                                        <select 
                                                                                                            value={nic.network || nic.backing?.network_name || ''}
                                                                                                            onChange={e => handleVmwareNetworkChange(vmwareSelectedVm, nic.key || 0, e.target.value)}
                                                                                                            className="flex-1 bg-proxmox-card border border-proxmox-border rounded px-2 py-1.5 text-sm text-gray-300">
                                                                                                            <option value={nic.network || nic.backing?.network_name || ''}>{nic.network || nic.backing?.network_name || 'Current Network'}</option>
                                                                                                            {vmwareNetworks.filter(n => n.name !== (nic.network || nic.backing?.network_name)).map(n => (
                                                                                                                <option key={n.network || n.name} value={n.name}>{n.name}</option>
                                                                                                            ))}
                                                                                                        </select>
                                                                                                    </div>
                                                                                                </div>
                                                                                            ))}
                                                                                        </div>
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        {/* Performance Stats (if available) */}
                                                                        {perfData.cpu_usage_mhz !== undefined && (
                                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Live Performance</h3>
                                                                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                        <div className="text-lg font-bold text-blue-400">{perfData.cpu_usage_mhz || 0} MHz</div>
                                                                                        <div className="text-xs text-gray-500">CPU Usage</div>
                                                                                    </div>
                                                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                        <div className="text-lg font-bold text-purple-400">{perfData.memory_usage_mb || 0} MB</div>
                                                                                        <div className="text-xs text-gray-500">Memory Used</div>
                                                                                    </div>
                                                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                        <div className="text-lg font-bold text-emerald-400">{perfData.disk_committed ? (perfData.disk_committed / (1024**3)).toFixed(1) : '0'} GB</div>
                                                                                        <div className="text-xs text-gray-500">Disk Used</div>
                                                                                    </div>
                                                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                        <div className="text-lg font-bold text-cyan-400">{perfData.uptime_seconds ? Math.floor(perfData.uptime_seconds / 3600) + 'h' : '0h'}</div>
                                                                                        <div className="text-xs text-gray-500">Uptime</div>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                        
                                                                        {/* Save Button */}
                                                                        <div className="flex justify-end gap-3">
                                                                            <button onClick={() => setVmwareConfigEdit({ cpu: '', memory: '', notes: '', cpu_hot_add: false, memory_hot_add: false })}
                                                                                className="px-4 py-2 rounded-lg bg-proxmox-card border border-proxmox-border text-gray-400 hover:text-white text-sm">
                                                                                Reset
                                                                            </button>
                                                                            <button onClick={() => handleVmwareConfigSave(vmwareSelectedVm)}
                                                                                disabled={vmwareConfigSaving}
                                                                                className="px-6 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium disabled:opacity-50 flex items-center gap-2">
                                                                                {vmwareConfigSaving ? <Icons.RefreshCw className="w-4 h-4 animate-spin" /> : <Icons.Check className="w-4 h-4" />}
                                                                                Save Changes
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                );
                                                            })()}
                                                            
                                                            {/* Hardware Tab (read-only) */}
                                                            {vmwareVmTab === 'config' && (
                                                                <div className="space-y-4">
                                                                    <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3">
                                                                        <div className="flex items-center gap-2 text-blue-400 text-sm">
                                                                            <Icons.Info className="w-4 h-4" />
                                                                            <span>Hardware overview (read-only). Use the Settings tab to change CPU, Memory, and Network.</span>
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                                                        {/* Current Config */}
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4">Current Configuration</h3>
                                                                            <div className="space-y-3">
                                                                                <div className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                                                    <div className="flex items-center gap-3">
                                                                                        <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center"><Icons.Cpu className="w-4 h-4 text-blue-400" /></div>
                                                                                        <div><div className="text-sm text-white font-medium">CPU</div><div className="text-xs text-gray-500">Virtual CPUs</div></div>
                                                                                    </div>
                                                                                    <div className="text-lg font-bold text-white">{cpuCount}</div>
                                                                                </div>
                                                                                <div className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                                                    <div className="flex items-center gap-3">
                                                                                        <div className="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center"><Icons.Memory className="w-4 h-4 text-purple-400" /></div>
                                                                                        <div><div className="text-sm text-white font-medium">Memory</div><div className="text-xs text-gray-500">RAM allocation</div></div>
                                                                                    </div>
                                                                                    <div className="text-lg font-bold text-white">{memGB} GB</div>
                                                                                </div>
                                                                                {disksList.map((disk, idx) => {
                                                                                    const capGB = disk.capacity ? (disk.capacity / (1024*1024*1024)).toFixed(1) : disk.capacity_gb || '?';
                                                                                    return (
                                                                                        <div key={idx} className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                                                            <div className="flex items-center gap-3">
                                                                                                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center"><Icons.HardDrive className="w-4 h-4 text-emerald-400" /></div>
                                                                                                <div><div className="text-sm text-white font-medium">{disk.label || `Disk ${idx}`}</div><div className="text-xs text-gray-500">{disk.backing?.thin_provisioned ? 'Thin' : 'Thick'} - {disk.backing?.datastore || ''}</div></div>
                                                                                            </div>
                                                                                            <div className="text-lg font-bold text-white">{capGB} GB</div>
                                                                                        </div>
                                                                                    );
                                                                                })}
                                                                                {netsList.map((nic, idx) => (
                                                                                    <div key={idx} className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                                                        <div className="flex items-center gap-3">
                                                                                            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 flex items-center justify-center"><Icons.Globe className="w-4 h-4 text-cyan-400" /></div>
                                                                                            <div><div className="text-sm text-white font-medium">{nic.label || nic.name || `NIC ${idx}`}</div><div className="text-xs text-gray-500 font-mono">{nic.mac_address || ''}</div></div>
                                                                                        </div>
                                                                                        <div className="text-sm text-gray-400">{nic.network || nic.name || ''}</div>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        {/* Quick Actions */}
                                                                        <div className="space-y-4">
                                                                            {/* VMware Hardware Details */}
                                                                            {vm.hardware && (vm.hardware.firmware || vm.hardware.scsi_controller) && (
                                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                    <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4">Hardware Details</h3>
                                                                                    <div className="space-y-2 text-sm">
                                                                                        <div className="flex justify-between p-2 bg-proxmox-dark rounded-lg">
                                                                                            <span className="text-gray-400">Firmware</span>
                                                                                            <span className="text-white font-medium">{(vm.hardware.firmware || 'BIOS').toUpperCase()}</span>
                                                                                        </div>
                                                                                        <div className="flex justify-between p-2 bg-proxmox-dark rounded-lg">
                                                                                            <span className="text-gray-400">SCSI Controller</span>
                                                                                            <div className="text-right">
                                                                                                <div className="text-white font-medium">{vm.hardware.scsi_controller || 'N/A'}</div>
                                                                                                <div className="text-xs text-gray-500">→ Proxmox: {vm.hardware.scsi_controller_pve || 'auto'}</div>
                                                                                            </div>
                                                                                        </div>
                                                                                        <div className="flex justify-between p-2 bg-proxmox-dark rounded-lg">
                                                                                            <span className="text-gray-400">Network Adapter</span>
                                                                                            <div className="text-right">
                                                                                                <div className="text-white font-medium">{vm.hardware.nic_type || 'N/A'}</div>
                                                                                                <div className="text-xs text-gray-500">→ Proxmox: {vm.hardware.nic_type_pve || 'auto'}</div>
                                                                                            </div>
                                                                                        </div>
                                                                                        <div className="flex justify-between p-2 bg-proxmox-dark rounded-lg">
                                                                                            <span className="text-gray-400">Disk Bus</span>
                                                                                            <span className="text-white font-medium">{(vm.hardware.disk_bus || 'SCSI').toUpperCase()}</span>
                                                                                        </div>
                                                                                        {vm.hardware.version && (
                                                                                            <div className="flex justify-between p-2 bg-proxmox-dark rounded-lg">
                                                                                                <span className="text-gray-400">HW Version</span>
                                                                                                <span className="text-white font-medium">{vm.hardware.version}</span>
                                                                                            </div>
                                                                                        )}
                                                                                    </div>
                                                                                </div>
                                                                            )}
                                                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                                <h3 className="text-sm font-semibold text-gray-400 uppercase mb-4">Quick Actions</h3>
                                                                                <div className="space-y-2">
                                                                                    <button onClick={() => { setVmwareRenameName(vm.name || ''); setShowVmwareRename(true); }} className="w-full flex items-center gap-3 p-3 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors text-left">
                                                                                        <Icons.Edit className="w-5 h-5 text-blue-400" />
                                                                                        <div><div className="text-sm text-white">Rename VM</div><div className="text-xs text-gray-500">Change the display name</div></div>
                                                                                    </button>
                                                                                    <button onClick={() => { setVmwareCloneName(`${vm.name}-clone`); setShowVmwareClone(true); }} className="w-full flex items-center gap-3 p-3 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors text-left">
                                                                                        <Icons.Copy className="w-5 h-5 text-green-400" />
                                                                                        <div><div className="text-sm text-white">Clone VM</div><div className="text-xs text-gray-500">Create an identical copy</div></div>
                                                                                    </button>
                                                                                    <button onClick={() => fetchMigrationPlan(vmwareSelectedVm)} disabled={vmwareMigrateLoading} className="w-full flex items-center gap-3 p-3 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors text-left">
                                                                                        <Icons.FolderInput className="w-5 h-5 text-emerald-400" />
                                                                                        <div><div className="text-sm text-white">Migrate to Proxmox</div><div className="text-xs text-gray-500">Near-zero downtime V2P migration</div></div>
                                                                                    </button>
                                                                                    <button onClick={() => setShowVmwareDelete(true)} disabled={isOn} className="w-full flex items-center gap-3 p-3 bg-proxmox-dark rounded-lg hover:bg-red-500/5 transition-colors text-left disabled:opacity-40">
                                                                                        <Icons.Trash className="w-5 h-5 text-red-400" />
                                                                                        <div><div className="text-sm text-red-400">Delete VM</div><div className="text-xs text-gray-500">{isOn ? 'Power off first to delete' : 'Permanently remove this VM'}</div></div>
                                                                                    </button>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            )}
                                                            
                                                            {/* Snapshots Tab */}
                                                            {vmwareVmTab === 'snapshots' && (
                                                                <div className="space-y-4">
                                                                    <div className="flex items-center justify-between">
                                                                        <h3 className="text-sm font-semibold text-gray-400">Snapshots ({snapsList.length})</h3>
                                                                        <button onClick={async () => {
                                                                            const name = prompt('Snapshot name:');
                                                                            if (name) {
                                                                                await vmwareSnapshotAction(vmwareSelectedVm, 'create', { name, description: '' });
                                                                                fetchVMwareVmDetail(selectedVMware.id, vmwareSelectedVm);
                                                                            }
                                                                        }} className="px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 text-sm font-medium">
                                                                            + Create Snapshot
                                                                        </button>
                                                                    </div>
                                                                    {snapsList.length > 0 ? (
                                                                        <div className="space-y-2">
                                                                            {snapsList.map((snap, idx) => (
                                                                                <div key={idx} className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 flex items-center justify-between">
                                                                                    <div className="flex items-center gap-3">
                                                                                        <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                                                                                            <Icons.Camera className="w-4 h-4 text-blue-400" />
                                                                                        </div>
                                                                                        <div>
                                                                                            <div className="text-sm font-medium text-white">{snap.name}</div>
                                                                                            {snap.description && <div className="text-xs text-gray-500">{snap.description}</div>}
                                                                                            {snap.created && <div className="text-xs text-gray-600">{new Date(snap.created).toLocaleString()}</div>}
                                                                                        </div>
                                                                                    </div>
                                                                                    <button onClick={() => vmwareSnapshotAction(vmwareSelectedVm, 'delete', { snapshot_id: snap.id || snap.snapshot })} className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg" title="Delete snapshot">
                                                                                        <Icons.Trash className="w-4 h-4" />
                                                                                    </button>
                                                                                </div>
                                                                            ))}
                                                                        </div>
                                                                    ) : (
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center text-gray-500">
                                                                            <Icons.Camera className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                                                            <div className="text-sm">No snapshots. Create one to save the current VM state.</div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                            
                                                            {/* Migration Tab */}
                                                            {vmwareVmTab === 'migrate' && (
                                                                <div className="space-y-4">
                                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-5">
                                                                        <div className="flex items-center gap-3 mb-4">
                                                                            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                                                                                <Icons.FolderInput className="w-5 h-5 text-emerald-400" />
                                                                            </div>
                                                                            <div>
                                                                                <h3 className="text-white font-semibold">Migrate to Proxmox VE</h3>
                                                                                <p className="text-xs text-gray-500">Near-zero downtime ESXi to Proxmox migration using block-level delta sync</p>
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        <div className="grid grid-cols-3 gap-3 mb-4">
                                                                            <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                <div className="text-lg font-bold text-white">{totalDiskGB.toFixed(0)} GB</div>
                                                                                <div className="text-xs text-gray-500">Total Disk</div>
                                                                            </div>
                                                                            <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                <div className="text-lg font-bold text-emerald-400">~{Math.max(2, Math.round(totalDiskGB * 0.08))} min</div>
                                                                                <div className="text-xs text-gray-500">Est. Downtime</div>
                                                                            </div>
                                                                            <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                                <div className="text-lg font-bold text-white">{disksList.length}</div>
                                                                                <div className="text-xs text-gray-500">Disks to Transfer</div>
                                                                            </div>
                                                                        </div>
                                                                        
                                                                        <div className="space-y-2 mb-4 text-xs text-gray-500">
                                                                            <div className="font-semibold text-gray-400 mb-1">How it works:</div>
                                                                            <div>1. Pre-sync: Full disk copy via HTTPS while VM runs (no downtime)</div>
                                                                            <div>2. Pre-compute: Proxmox block checksums while VM still runs</div>
                                                                            <div>3. Stop VM: Brief downtime starts, VMDKs unlock</div>
                                                                            <div>4. Delta sync: Only changed blocks transferred via SSH (fast!)</div>
                                                                            <div>5. Start on Proxmox: VM boots, downtime ends</div>
                                                                        </div>
                                                                        
                                                                        <button onClick={() => fetchMigrationPlan(vmwareSelectedVm)} disabled={vmwareMigrateLoading} className="w-full py-2.5 rounded-lg bg-emerald-500 text-white font-medium hover:bg-emerald-600 disabled:opacity-50 text-sm">
                                                                            {vmwareMigrateLoading ? 'Loading Migration Plan...' : 'Start Migration Wizard'}
                                                                        </button>
                                                                    </div>
                                                                    
                                                                    {/* Active Migrations */}
                                                                    {vmwareMigrations.length > 0 && (
                                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Active Migrations</h3>
                                                                            <div className="space-y-2">
                                                                                {vmwareMigrations.map(m => (
                                                                                    <div key={m.id} className="p-3 bg-proxmox-dark rounded-lg">
                                                                                        <div className="flex items-center justify-between mb-2">
                                                                                            <span className="text-sm text-white font-medium">{m.vm_name || m.id}</span>
                                                                                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                                                m.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                                                                                m.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                                                                                m.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                                                                                                'bg-gray-500/20 text-gray-400'
                                                                                            }`}>{m.status}</span>
                                                                                        </div>
                                                                                        {m.progress !== undefined && (
                                                                                            <div className="w-full h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                                                                                <div className="h-full bg-emerald-400 rounded-full transition-all" style={{width: `${m.progress}%`}} />
                                                                                            </div>
                                                                                        )}
                                                                                        {m.current_step && <div className="text-xs text-gray-500 mt-1">{m.current_step}</div>}
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })() : (
                                                    <div className="text-center py-12 text-gray-500">
                                                        <Icons.RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin opacity-30" />
                                                        Loading VM details...
                                                    </div>
                                                )}
                                                
                                                {/* Clone Modal */}
                                                {showVmwareClone && (
                                                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowVmwareClone(false)}>
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                                                            <h3 className="text-lg font-bold text-white mb-4">Clone VM</h3>
                                                            <input value={vmwareCloneName} onChange={e => setVmwareCloneName(e.target.value)} placeholder="Clone name..." className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-xl text-white mb-4 focus:outline-none focus:border-emerald-500/50" />
                                                            <div className="flex gap-2 justify-end">
                                                                <button onClick={() => setShowVmwareClone(false)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 text-sm">Cancel</button>
                                                                <button onClick={() => handleVmwareClone(vmwareSelectedVm, vmwareCloneName)} disabled={!vmwareCloneName.trim()} className="px-4 py-2 rounded-lg bg-emerald-500 text-white text-sm font-medium disabled:opacity-50">Clone</button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* Rename Modal */}
                                                {showVmwareRename && (
                                                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowVmwareRename(false)}>
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                                                            <h3 className="text-lg font-bold text-white mb-4">Rename VM</h3>
                                                            <input value={vmwareRenameName} onChange={e => setVmwareRenameName(e.target.value)} placeholder="New name..." className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-xl text-white mb-4 focus:outline-none focus:border-emerald-500/50" />
                                                            <div className="flex gap-2 justify-end">
                                                                <button onClick={() => setShowVmwareRename(false)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 text-sm">Cancel</button>
                                                                <button onClick={() => handleVmwareRename(vmwareSelectedVm, vmwareRenameName)} disabled={!vmwareRenameName.trim()} className="px-4 py-2 rounded-lg bg-blue-500 text-white text-sm font-medium disabled:opacity-50">Rename</button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* Delete Confirmation */}
                                                {showVmwareDelete && (
                                                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowVmwareDelete(false)}>
                                                        <div className="bg-proxmox-card border border-red-500/30 rounded-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                                                            <h3 className="text-lg font-bold text-red-400 mb-2">Delete VM</h3>
                                                            <p className="text-gray-400 text-sm mb-4">Are you sure you want to permanently delete <strong className="text-white">{vmwareVmDetail?.name}</strong>? This action cannot be undone.</p>
                                                            <div className="flex gap-2 justify-end">
                                                                <button onClick={() => setShowVmwareDelete(false)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 text-sm">Cancel</button>
                                                                <button onClick={() => handleVmwareDeleteVm(vmwareSelectedVm)} className="px-4 py-2 rounded-lg bg-red-500 text-white text-sm font-medium">Delete VM</button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* Migration Wizard Modal */}
                                                {showVmwareMigrate && vmwareMigrationPlan && (
                                                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowVmwareMigrate(false)}>
                                                        <div className="bg-proxmox-card border border-emerald-500/30 rounded-2xl p-6 w-full max-w-lg max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                                                            <h3 className="text-lg font-bold text-white mb-1">Migrate to Proxmox</h3>
                                                            <p className="text-xs text-gray-500 mb-4">Method: {vmwareMigrationPlan.method || 'HTTPS + Delta Sync'}</p>
                                                            
                                                            <div className="space-y-3">
                                                                {/* Target Cluster */}
                                                                <div>
                                                                    <label className="text-xs text-gray-500 mb-1 block">Target Cluster</label>
                                                                    <select value={vmwareMigrateForm.target_cluster} onChange={e => {
                                                                        setVmwareMigrateForm({...vmwareMigrateForm, target_cluster: e.target.value, target_node: '', target_storage: ''});
                                                                    }} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                        <option value="">Select cluster...</option>
                                                                        {(vmwareMigrationPlan.targets || []).map(t => (
                                                                            <option key={t.cluster_id} value={t.cluster_id}>{t.cluster_name}</option>
                                                                        ))}
                                                                    </select>
                                                                </div>
                                                                
                                                                {/* Target Node */}
                                                                {vmwareMigrateForm.target_cluster && (
                                                                    <div>
                                                                        <label className="text-xs text-gray-500 mb-1 block">Target Node</label>
                                                                        <select value={vmwareMigrateForm.target_node} onChange={e => {
                                                                            setVmwareMigrateForm({...vmwareMigrateForm, target_node: e.target.value, target_storage: ''});
                                                                        }} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                            <option value="">Select node...</option>
                                                                            {((vmwareMigrationPlan.targets || []).find(t => t.cluster_id === vmwareMigrateForm.target_cluster)?.nodes || []).map(n => (
                                                                                <option key={n} value={n}>{n}</option>
                                                                            ))}
                                                                        </select>
                                                                    </div>
                                                                )}
                                                                
                                                                {/* Target Storage */}
                                                                {vmwareMigrateForm.target_node && (
                                                                    <div>
                                                                        <label className="text-xs text-gray-500 mb-1 block">Target Storage</label>
                                                                        <select value={vmwareMigrateForm.target_storage} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, target_storage: e.target.value})} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                            <option value="">Select storage...</option>
                                                                            {((vmwareMigrationPlan.targets || []).find(t => t.cluster_id === vmwareMigrateForm.target_cluster)?.storages?.[vmwareMigrateForm.target_node] || []).map(s => (
                                                                                <option key={s} value={s}>{s}</option>
                                                                            ))}
                                                                        </select>
                                                                    </div>
                                                                )}
                                                                
                                                                {/* ESXi Password */}
                                                                <div>
                                                                    <label className="text-xs text-gray-500 mb-1 block">ESXi Root Password (for SSH access)</label>
                                                                    <input type="password" value={vmwareMigrateForm.esxi_password} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, esxi_password: e.target.value})} placeholder="ESXi root password" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                
                                                                {/* Network Bridge */}
                                                                <div>
                                                                    <label className="text-xs text-gray-500 mb-1 block">Network Bridge</label>
                                                                    <input value={vmwareMigrateForm.network_bridge} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, network_bridge: e.target.value})} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                
                                                                {/* Transfer Mode */}
                                                                <div>
                                                                    <label className="text-xs text-gray-500 mb-1 block">Transfer Mode</label>
                                                                    <select value={vmwareMigrateForm.transfer_mode} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, transfer_mode: e.target.value})} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                        <option value="auto">Auto (Pre-Sync + Delta)</option>
                                                                        <option value="sshfs_boot">QEMU SSH Boot + Live Copy (Near-Zero Downtime)</option>
                                                                        <option value="offline">Offline Copy (Full Downtime)</option>
                                                                    </select>
                                                                    <p className="text-xs text-gray-600 mt-1">
                                                                        {vmwareMigrateForm.transfer_mode === 'auto' && 'Tries pre-sync while VM runs, falls back to QEMU SSH boot if locked'}
                                                                        {vmwareMigrateForm.transfer_mode === 'sshfs_boot' && 'Boots Proxmox VM via QEMU SSH driver (~15s downtime), copies disks in background while VM runs. Recommended: max. 1 VM at a time.'}
                                                                        {vmwareMigrateForm.transfer_mode === 'offline' && 'Stops VM, copies disks via SSH, then starts on Proxmox (full downtime)'}
                                                                    </p>
                                                                </div>
                                                                
                                                                {/* Options */}
                                                                <div className="flex items-center gap-4">
                                                                    <label className="flex items-center gap-2 text-sm text-gray-400">
                                                                        <input type="checkbox" checked={vmwareMigrateForm.start_after} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, start_after: e.target.checked})} className="rounded" />
                                                                        Start VM after migration
                                                                    </label>
                                                                    <label className="flex items-center gap-2 text-sm text-gray-400">
                                                                        <input type="checkbox" checked={vmwareMigrateForm.remove_source} onChange={e => setVmwareMigrateForm({...vmwareMigrateForm, remove_source: e.target.checked})} className="rounded" />
                                                                        Remove source VM
                                                                    </label>
                                                                </div>
                                                                
                                                                {/* Requirements */}
                                                                {vmwareMigrationPlan.requirements && (
                                                                    <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3">
                                                                        <div className="text-xs text-yellow-400 font-semibold mb-1">Requirements:</div>
                                                                        {vmwareMigrationPlan.requirements.map((r, i) => (
                                                                            <div key={i} className="text-xs text-yellow-400/70">- {r}</div>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                            
                                                            <div className="flex gap-2 justify-end mt-4">
                                                                <button onClick={() => setShowVmwareMigrate(false)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 text-sm">Cancel</button>
                                                                <button onClick={() => startVmwareMigration(vmwareSelectedVm)} disabled={!vmwareMigrateForm.target_cluster || !vmwareMigrateForm.target_node || !vmwareMigrateForm.target_storage || !vmwareMigrateForm.esxi_password || vmwareMigrateLoading} className="px-4 py-2 rounded-lg bg-emerald-500 text-white text-sm font-medium disabled:opacity-50">
                                                                    {vmwareMigrateLoading ? 'Starting...' : 'Start Migration'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                        
                                        {/* Hosts Tab */}
                                        {vmwareActiveTab === 'hosts' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <table className="w-full">
                                                    <thead>
                                                        <tr className="border-b border-proxmox-border">
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Name</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Model</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">CPUs</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Memory</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">VMs</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {vmwareHosts.map(host => (
                                                            <tr key={host.host_id || host.name} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/50">
                                                                <td className="p-3"><div className={`w-3 h-3 rounded-full ${host.connection_state === 'CONNECTED' || host.connection_state === 'connected' ? 'bg-green-400' : 'bg-red-400'}`} /></td>
                                                                <td className="p-3 text-white text-sm font-medium">{host.name}</td>
                                                                <td className="p-3 text-gray-400 text-sm">{host.model || '-'}</td>
                                                                <td className="p-3 text-gray-400 text-sm">
                                                                    <div>{host.cpu_cores || host.num_cpu_cores || '-'} cores</div>
                                                                    {host.cpu_usage !== undefined && (
                                                                        <div className="w-20 h-1.5 bg-proxmox-dark rounded-full mt-1 overflow-hidden">
                                                                            <div className={`h-full rounded-full ${host.cpu_usage > 80 ? 'bg-red-400' : host.cpu_usage > 60 ? 'bg-yellow-400' : 'bg-emerald-400'}`} style={{width: `${Math.min(100, host.cpu_usage || 0)}%`}} />
                                                                        </div>
                                                                    )}
                                                                </td>
                                                                <td className="p-3 text-gray-400 text-sm">
                                                                    <div>{host.memory_gb ? `${host.memory_gb} GB` : host.memory_bytes ? `${(host.memory_bytes / (1024*1024*1024)).toFixed(0)} GB` : '-'}</div>
                                                                    {host.memory_usage_pct !== undefined && (
                                                                        <div className="w-20 h-1.5 bg-proxmox-dark rounded-full mt-1 overflow-hidden">
                                                                            <div className={`h-full rounded-full ${host.memory_usage_pct > 80 ? 'bg-red-400' : host.memory_usage_pct > 60 ? 'bg-yellow-400' : 'bg-purple-400'}`} style={{width: `${Math.min(100, host.memory_usage_pct || 0)}%`}} />
                                                                        </div>
                                                                    )}
                                                                </td>
                                                                <td className="p-3 text-gray-400 text-sm">{host.vm_count || '-'}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                                {vmwareHosts.length === 0 && <div className="text-center py-8 text-gray-500">No hosts found</div>}
                                            </div>
                                        )}
                                        
                                        {/* Datastores Tab */}
                                        {vmwareActiveTab === 'datastores' && !vmwareSelectedDs && (
                                            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                                                {vmwareDatastores.map(ds => {
                                                    const capGB = ds.capacity ? (ds.capacity / (1024*1024*1024)).toFixed(1) : ds.capacity_gb || 0;
                                                    const freeGB = ds.free_space ? (ds.free_space / (1024*1024*1024)).toFixed(1) : ds.free_gb || 0;
                                                    const usedGB = capGB && freeGB ? (capGB - freeGB).toFixed(1) : 0;
                                                    const pct = ds.capacity && ds.free_space ? ((1 - ds.free_space / ds.capacity) * 100).toFixed(0) : null;
                                                    return (
                                                        <div key={ds.datastore_id || ds.datastore || ds.name}
                                                             onClick={() => setVmwareSelectedDs(ds)}
                                                             className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 hover:border-emerald-500/30 cursor-pointer transition-all group">
                                                            <div className="flex items-center gap-3 mb-3">
                                                                <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                                                                    <Icons.Database className="w-5 h-5 text-blue-400" />
                                                                </div>
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="text-sm font-semibold text-white truncate group-hover:text-emerald-400 transition-colors">{ds.name}</div>
                                                                    <div className="text-xs text-gray-500">{ds.type || 'VMFS'}</div>
                                                                </div>
                                                            </div>
                                                            {pct !== null && (
                                                                <div className="mb-2">
                                                                    <div className="h-2 bg-proxmox-dark rounded-full overflow-hidden">
                                                                        <div className={`h-full rounded-full ${parseInt(pct) > 85 ? 'bg-red-400' : parseInt(pct) > 65 ? 'bg-yellow-400' : 'bg-emerald-400'}`} style={{width: `${pct}%`}} />
                                                                    </div>
                                                                    <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                                        <span>{usedGB} GB used</span>
                                                                        <span>{freeGB} GB free / {capGB} GB</span>
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })}
                                                {vmwareDatastores.length === 0 && <div className="col-span-3 text-center py-12 text-gray-500">No datastores found</div>}
                                            </div>
                                        )}
                                        
                                        {/* Datastore Detail */}
                                        {vmwareActiveTab === 'datastores' && vmwareSelectedDs && (() => {
                                            const ds = vmwareSelectedDs;
                                            const detail = vmwareDsDetail || {};
                                            const capGB = (ds.capacity || detail.capacity) ? ((ds.capacity || detail.capacity) / (1024*1024*1024)).toFixed(1) : ds.capacity_gb || 0;
                                            const freeGB = (ds.free_space || detail.free_space) ? ((ds.free_space || detail.free_space) / (1024*1024*1024)).toFixed(1) : ds.free_gb || 0;
                                            const usedGB = capGB && freeGB ? (capGB - freeGB).toFixed(1) : 0;
                                            const pct = (ds.capacity || detail.capacity) && (ds.free_space || detail.free_space) ? ((1 - (ds.free_space || detail.free_space) / (ds.capacity || detail.capacity)) * 100).toFixed(0) : 0;
                                            // Use server-side VMs if available, else client-side filter
                                            const dsVms = detail.vms && detail.vms.length > 0 ? detail.vms : vmwareVms.filter(v => {
                                                const vmDs = (v.datastore || '').toLowerCase();
                                                return vmDs.includes((ds.name || '').toLowerCase());
                                            });
                                            const dsHosts = detail.hosts || [];
                                            return (
                                                <div className="space-y-4">
                                                    <button onClick={() => { setVmwareSelectedDs(null); setVmwareDsDetail(null); }} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
                                                        <span style={{display:"inline-block",transform:"rotate(180deg)"}}><Icons.ChevronRight className="w-4 h-4" /></span> Back to Datastores
                                                    </button>
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-5">
                                                        <div className="flex items-center gap-4 mb-4">
                                                            <div className="w-14 h-14 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
                                                                <Icons.Database className="w-7 h-7 text-blue-400" />
                                                            </div>
                                                            <div>
                                                                <h2 className="text-xl font-bold text-white">{ds.name}</h2>
                                                                <div className="text-sm text-gray-500">{ds.type || detail.type || 'VMFS'} • {capGB} GB total{detail.multiple_host_access ? ' • Shared' : ''}</div>
                                                            </div>
                                                        </div>
                                                        <div className="mb-4">
                                                            <div className="h-4 bg-proxmox-dark rounded-full overflow-hidden">
                                                                <div className={`h-full rounded-full ${parseInt(pct) > 85 ? 'bg-red-400' : parseInt(pct) > 65 ? 'bg-yellow-400' : 'bg-emerald-400'}`} style={{width: `${pct}%`}} />
                                                            </div>
                                                            <div className="flex justify-between mt-1 text-sm"><span className="text-gray-400">{usedGB} GB used ({pct}%)</span><span className="text-emerald-400">{freeGB} GB free</span></div>
                                                        </div>
                                                        <div className="grid grid-cols-4 gap-3">
                                                            {[['Capacity', capGB, 'text-white'], ['Used', usedGB, 'text-white'], ['Free', freeGB, 'text-emerald-400'], ['VMs', dsVms.length, 'text-white']].map(([l, v, c]) => (
                                                                <div key={l} className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                                    <div className={`text-lg font-bold ${c}`}>{v}</div>
                                                                    <div className="text-xs text-gray-500">{l === 'VMs' ? l : `GB ${l}`}</div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                    
                                                    {/* Hosts */}
                                                    {dsHosts.length > 0 && (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <div className="p-4 border-b border-proxmox-border">
                                                                <h3 className="text-sm font-semibold text-gray-400 uppercase">Connected Hosts ({dsHosts.length})</h3>
                                                            </div>
                                                            <div className="divide-y divide-proxmox-border/50">
                                                                {dsHosts.map(h => (
                                                                    <div key={h.host || h.name} className="px-4 py-2.5 flex items-center gap-3">
                                                                        <div className="w-2 h-2 rounded-full bg-green-400" />
                                                                        <span className="text-sm text-white">{h.name}</span>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                    
                                                    {/* VMs on Datastore */}
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="p-4 border-b border-proxmox-border">
                                                            <h3 className="text-sm font-semibold text-gray-400 uppercase">VMs on {ds.name} ({dsVms.length})</h3>
                                                        </div>
                                                        {dsVms.length > 0 ? (
                                                            <table className="w-full">
                                                                <thead><tr className="border-b border-proxmox-border">
                                                                    <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
                                                                    <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Name</th>
                                                                    <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">OS</th>
                                                                </tr></thead>
                                                                <tbody>
                                                                    {dsVms.map(vm => (
                                                                        <tr key={vm.vm || vm.vm_id || vm.name} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/50 cursor-pointer"
                                                                            onClick={() => { setVmwareActiveTab('vms'); setVmwareSelectedVm(vm.vm || vm.vm_id); setVmwareSelectedDs(null); }}>
                                                                            <td className="p-3"><div className={`w-3 h-3 rounded-full ${vm.power_state === 'POWERED_ON' ? 'bg-green-400' : 'bg-gray-500'}`} /></td>
                                                                            <td className="p-3 text-white text-sm font-medium">{vm.name}</td>
                                                                            <td className="p-3 text-gray-400 text-sm">{(vm.guest_OS || vm.guest_os || '-').substring(0, 25)}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        ) : <div className="p-8 text-center text-gray-500 text-sm">No VMs on this datastore</div>}
                                                    </div>
                                                </div>
                                            );
                                        })()}
                                        
                                        {/* Networks Tab */}
                                        {vmwareActiveTab === 'networks' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <table className="w-full">
                                                    <thead>
                                                        <tr className="border-b border-proxmox-border">
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Name</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">Type</th>
                                                            <th className="text-left p-3 text-xs font-semibold text-gray-500 uppercase">VLAN</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {vmwareNetworks.map(net => (
                                                            <tr key={net.network_id || net.name} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/50">
                                                                <td className="p-3 text-white text-sm font-medium">{net.name}</td>
                                                                <td className="p-3 text-gray-400 text-sm">{net.type || 'Standard'}</td>
                                                                <td className="p-3 text-gray-400 text-sm">{net.vlan_id || '-'}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                                {vmwareNetworks.length === 0 && <div className="text-center py-8 text-gray-500">No networks found</div>}
                                            </div>
                                        )}
                                        
                                        {/* Clusters Tab -- DRS/HA Management */}
                                        {vmwareActiveTab === 'clusters' && (
                                            <div className="space-y-4">
                                                {vmwareClusters.length === 0 ? (
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center text-gray-500">
                                                        <Icons.Layers className="w-12 h-12 mx-auto mb-3 opacity-30" />
                                                        <p>No compute clusters found</p>
                                                        <p className="text-xs mt-1">Clusters are only available on vCenter (not standalone ESXi)</p>
                                                    </div>
                                                ) : (
                                                    vmwareClusters.map(cl => (
                                                        <div key={cl.cluster || cl.name} className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <div className="p-4 border-b border-proxmox-border">
                                                                <div className="flex items-center justify-between">
                                                                    <div className="flex items-center gap-3">
                                                                        <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                                                                            <Icons.Layers className="w-5 h-5 text-purple-400" />
                                                                        </div>
                                                                        <div>
                                                                            <h3 className="text-white font-semibold">{cl.name}</h3>
                                                                            <p className="text-xs text-gray-500">{cl.num_hosts || 0} Hosts • {cl.cluster}</p>
                                                                        </div>
                                                                    </div>
                                                                    <button onClick={() => fetchVMwareClusters(selectedVMware.id)} className="text-gray-500 hover:text-white">
                                                                        <Icons.RefreshCw className="w-4 h-4" />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* Resource Summary */}
                                                            <div className="grid grid-cols-3 gap-4 p-4 border-b border-proxmox-border/50">
                                                                <div className="text-center">
                                                                    <div className="text-xs text-gray-500">CPU</div>
                                                                    <div className="text-sm text-white font-medium">{cl.total_cpu ? (cl.total_cpu / 1000).toFixed(1) + ' GHz' : 'N/A'}</div>
                                                                </div>
                                                                <div className="text-center">
                                                                    <div className="text-xs text-gray-500">Memory</div>
                                                                    <div className="text-sm text-white font-medium">{cl.total_memory ? (cl.total_memory / (1024**3)).toFixed(0) + ' GB' : 'N/A'}</div>
                                                                </div>
                                                                <div className="text-center">
                                                                    <div className="text-xs text-gray-500">Hosts</div>
                                                                    <div className="text-sm text-white font-medium">{cl.num_hosts || 0}</div>
                                                                </div>
                                                            </div>
                                                            
                                                            {/* DRS & HA Controls */}
                                                            <div className="p-4 space-y-4">
                                                                {/* DRS */}
                                                                <div className="flex items-center justify-between p-3 rounded-lg bg-proxmox-dark/50">
                                                                    <div className="flex items-center gap-3">
                                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${cl.drs_enabled ? 'bg-blue-500/20' : 'bg-gray-800'}`}>
                                                                            <Icons.RotateCw className={`w-4 h-4 ${cl.drs_enabled ? 'text-blue-400' : 'text-gray-600'}`} />
                                                                        </div>
                                                                        <div>
                                                                            <div className="text-sm text-white font-medium">DRS (Distributed Resource Scheduler)</div>
                                                                            <div className="text-xs text-gray-500">
                                                                                {cl.drs_enabled ? `Active - ${(cl.drs_automation || 'MANUAL').replace(/_/g, ' ').toLowerCase()}` : 'Disabled'}
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                    <div className="flex items-center gap-2">
                                                                        {cl.drs_enabled && (
                                                                            <select 
                                                                                value={cl.drs_automation || 'MANUAL'}
                                                                                onChange={(e) => toggleVMwareDRS(selectedVMware.id, cl.cluster, true, e.target.value)}
                                                                                className="bg-proxmox-card border border-proxmox-border rounded px-2 py-1 text-xs text-gray-300"
                                                                            >
                                                                                <option value="FULLY_AUTOMATED">Fully Automated</option>
                                                                                <option value="PARTIALLY_AUTOMATED">Partially Automated</option>
                                                                                <option value="MANUAL">Manual</option>
                                                                            </select>
                                                                        )}
                                                                        <button 
                                                                            onClick={() => toggleVMwareDRS(selectedVMware.id, cl.cluster, !cl.drs_enabled)}
                                                                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                                                                                cl.drs_enabled 
                                                                                    ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30' 
                                                                                    : 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30'
                                                                            }`}
                                                                        >
                                                                            {cl.drs_enabled ? 'Disable' : 'Enable'}
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                                
                                                                {/* HA */}
                                                                <div className="flex items-center justify-between p-3 rounded-lg bg-proxmox-dark/50">
                                                                    <div className="flex items-center gap-3">
                                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${cl.ha_enabled ? 'bg-green-500/20' : 'bg-gray-800'}`}>
                                                                            <Icons.Shield className={`w-4 h-4 ${cl.ha_enabled ? 'text-green-400' : 'text-gray-600'}`} />
                                                                        </div>
                                                                        <div>
                                                                            <div className="text-sm text-white font-medium">HA (High Availability)</div>
                                                                            <div className="text-xs text-gray-500">
                                                                                {cl.ha_enabled 
                                                                                    ? `Active${cl.ha_admission_control ? ' - Admission Control enabled' : ''}`
                                                                                    : 'Disabled'}
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                    <button 
                                                                        onClick={() => toggleVMwareHA(selectedVMware.id, cl.cluster, !cl.ha_enabled)}
                                                                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                                                                            cl.ha_enabled 
                                                                                ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30' 
                                                                                : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                                                                        }`}
                                                                    >
                                                                        {cl.ha_enabled ? 'Disable' : 'Enable'}
                                                                    </button>
                                                                </div>
                                                                
                                                                {/* Cluster Hosts */}
                                                                {cl.hosts && cl.hosts.length > 0 && (
                                                                    <div className="mt-2">
                                                                        <div className="text-xs text-gray-500 mb-2 font-semibold uppercase">Cluster Hosts</div>
                                                                        <div className="space-y-1">
                                                                            {cl.hosts.map(h => (
                                                                                <div key={h.host || h.name} className="flex items-center justify-between py-1.5 px-2 rounded bg-proxmox-dark/30">
                                                                                    <div className="flex items-center gap-2">
                                                                                        <div className={`w-2 h-2 rounded-full ${h.connection_state === 'CONNECTED' ? 'bg-green-400' : 'bg-red-400'}`} />
                                                                                        <span className="text-sm text-gray-300">{h.name}</span>
                                                                                    </div>
                                                                                    <div className="flex items-center gap-2">
                                                                                        {h.maintenance && <span className="text-xs bg-yellow-500/20 text-yellow-400 px-1.5 py-0.5 rounded">Maintenance</span>}
                                                                                        <span className="text-xs text-gray-500">{h.connection_state}</span>
                                                                                    </div>
                                                                                </div>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))
                                                )}
                                            </div>
                                        )}
                                        
                                        {/* Tasks & Events Tab */}
                                        {vmwareActiveTab === 'tasks' && (
                                            <div className="space-y-4">
                                                {/* Active Migrations */}
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                    <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                        <h3 className="text-sm font-semibold text-gray-400 uppercase flex items-center gap-2">
                                                            <Icons.FolderInput className="w-4 h-4 text-emerald-400" /> Migrations ({vmwareMigrations.length})
                                                        </h3>
                                                        <button onClick={fetchVmwareMigrations} className="text-xs text-gray-500 hover:text-white"><Icons.RefreshCw className="w-3.5 h-3.5" /></button>
                                                    </div>
                                                    {vmwareMigrations.length > 0 ? (
                                                        <div className="divide-y divide-proxmox-border/50">
                                                            {vmwareMigrations.map(m => {
                                                                const isActive = m.status === 'running';
                                                                const phaseLabel = { planning:'Planning', pre_sync:'Pre-Sync', delta_sync:'Delta Sync', cutover:'Cutover', verify:'Verify', cleanup:'Cleanup', completed:'Done', failed:'Failed' };
                                                                return (
                                                                    <div key={m.id} className={`p-4 hover:bg-proxmox-hover/30 cursor-pointer ${vmwareSelectedMigration === m.id ? 'bg-emerald-500/5 border-l-2 border-l-emerald-400' : ''}`}
                                                                         onClick={() => setVmwareSelectedMigration(vmwareSelectedMigration === m.id ? null : m.id)}>
                                                                        <div className="flex items-center justify-between mb-2">
                                                                            <div className="flex items-center gap-3">
                                                                                <div className={`w-2.5 h-2.5 rounded-full ${isActive ? 'bg-blue-400 animate-pulse' : m.status === 'completed' ? 'bg-green-400' : m.status === 'failed' ? 'bg-red-400' : 'bg-gray-500'}`} />
                                                                                <span className="text-sm font-medium text-white">{m.vm_name || m.vm_id}</span>
                                                                                <span className="text-xs px-1.5 py-0.5 rounded bg-proxmox-dark text-gray-400">{phaseLabel[m.phase] || m.phase}</span>
                                                                            </div>
                                                                            <div className="flex items-center gap-3">
                                                                                {m.total_downtime_seconds != null && <span className="text-xs text-gray-500">Downtime: {m.total_downtime_seconds}s</span>}
                                                                                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${m.status === 'completed' ? 'bg-green-500/20 text-green-400' : m.status === 'failed' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'}`}>{m.status}</span>
                                                                            </div>
                                                                        </div>
                                                                        <div className="flex items-center gap-3 mb-1">
                                                                            <div className="flex-1 h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                                                                <div className={`h-full rounded-full transition-all duration-500 ${m.status === 'failed' ? 'bg-red-400' : m.status === 'completed' ? 'bg-green-400' : 'bg-emerald-400'}`} style={{width: `${m.progress || 0}%`}} />
                                                                            </div>
                                                                            <span className="text-xs text-gray-500 w-8 text-right">{m.progress || 0}%</span>
                                                                        </div>
                                                                        <div className="flex items-center gap-4 text-xs text-gray-600">
                                                                            <span>→ {m.target_node}/{m.target_storage}</span>
                                                                            {m.started_at && <span>{new Date(m.started_at).toLocaleString()}</span>}
                                                                            {m.proxmox_vmid && <span>PVE: {m.proxmox_vmid}</span>}
                                                                        </div>
                                                                        {m.phase_times && Object.keys(m.phase_times).length > 1 && (
                                                                            <div className="flex items-center gap-0.5 mt-2">
                                                                                {['planning','pre_sync','delta_sync','cutover','verify','cleanup','completed'].map((ph, idx) => {
                                                                                    const pt = m.phase_times[ph]; const isCur = m.phase === ph; const isDone = pt && pt.end;
                                                                                    return (<React.Fragment key={ph}>
                                                                                        {idx > 0 && <div className={`flex-1 h-px ${isDone ? 'bg-emerald-500' : isCur ? 'bg-emerald-500/40' : 'bg-proxmox-border'}`} />}
                                                                                        <div title={`${ph}${pt?.duration ? ` (${pt.duration}s)` : ''}`} className={`w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-bold border ${isDone ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400' : isCur ? 'bg-blue-500/20 border-blue-400 text-blue-400 animate-pulse' : 'bg-proxmox-dark border-proxmox-border text-gray-600'}`}>
                                                                                            {isDone ? '✓' : idx+1}
                                                                                        </div>
                                                                                    </React.Fragment>);
                                                                                })}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    ) : <div className="p-8 text-center text-gray-600 text-sm">No migrations yet. Start one from a VM's Migration tab.</div>}
                                                </div>
                                                
                                                {/* Migration Log Viewer */}
                                                {vmwareSelectedMigration && vmwareMigrationDetail && (
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                            <h3 className="text-sm font-semibold text-white">Migration Log - {vmwareMigrationDetail.vm_name} <span className="text-gray-500 font-normal">({vmwareSelectedMigration})</span></h3>
                                                            <button onClick={() => setVmwareSelectedMigration(null)} className="text-xs text-gray-500 hover:text-white px-2 py-1 rounded bg-proxmox-dark">Close</button>
                                                        </div>
                                                        {vmwareMigrationDetail.disk_progress && Object.keys(vmwareMigrationDetail.disk_progress).length > 0 && (
                                                            <div className="p-4 border-b border-proxmox-border/50 space-y-2">
                                                                <div className="text-xs text-gray-500 uppercase font-semibold">Disk Transfer</div>
                                                                {Object.entries(vmwareMigrationDetail.disk_progress).map(([key, dp]) => (
                                                                    <div key={key}>
                                                                        <div className="flex justify-between text-xs text-gray-400 mb-0.5">
                                                                            <span>{key}</span>
                                                                            <span>{dp.pct}% - {(dp.copied/(1024*1024*1024)).toFixed(1)}/{(dp.total/(1024*1024*1024)).toFixed(1)} GB</span>
                                                                        </div>
                                                                        <div className="h-2 bg-proxmox-dark rounded-full overflow-hidden"><div className="h-full bg-emerald-400 rounded-full transition-all" style={{width:`${dp.pct}%`}} /></div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                        <div className="p-3 bg-black/30 max-h-60 overflow-y-auto font-mono text-xs leading-relaxed">
                                                            {(vmwareMigrationDetail.log || []).map((line, i) => (
                                                                <div key={i} className={line.includes('FAIL') || line.includes('ERROR') ? 'text-red-400' : line.includes('Phase:') ? 'text-emerald-400 font-bold' : line.includes('===') ? 'text-blue-400' : 'text-gray-500'}>{line}</div>
                                                            ))}
                                                        </div>
                                                        {vmwareMigrationDetail.error && <div className="p-3 bg-red-500/10 border-t border-red-500/20 text-red-400 text-xs">Error: {vmwareMigrationDetail.error}</div>}
                                                        {vmwareMigrationDetail.status === 'completed' && <div className="p-3 bg-green-500/10 border-t border-green-500/20 text-green-400 text-xs">✓ Completed! VMID: {vmwareMigrationDetail.proxmox_vmid}{vmwareMigrationDetail.total_downtime_seconds ? ` - Downtime: ${vmwareMigrationDetail.total_downtime_seconds}s` : ''}</div>}
                                                    </div>
                                                )}
                                                
                                                {/* Audit Events */}
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                    <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                        <h3 className="text-sm font-semibold text-gray-400 uppercase flex items-center gap-2">
                                                            <Icons.FileText className="w-4 h-4 text-blue-400" /> Recent ESXi Events
                                                        </h3>
                                                        <button onClick={fetchVmwareEvents} disabled={vmwareEventsLoading} className="text-xs text-gray-500 hover:text-white">
                                                            <Icons.RefreshCw className={`w-3.5 h-3.5 ${vmwareEventsLoading ? 'animate-spin' : ''}`} />
                                                        </button>
                                                    </div>
                                                    {vmwareEvents.filter(e => (e.action || '').includes('vmware')).length > 0 ? (
                                                        <div className="divide-y divide-proxmox-border/50 max-h-96 overflow-y-auto">
                                                            {vmwareEvents.filter(e => (e.action || '').includes('vmware')).slice(0, 50).map((evt, i) => {
                                                                const a = evt.action || '';
                                                                const iconMap = { start:'▶', stop:'■', reset:'↻', suspend:'⏸', cloned:'⧉', deleted:'×', renamed:'✎', 'snapshot.created':'📸', 'snapshot.deleted':'🗑', 'migration.started':'→', added:'+', updated:'↑' };
                                                                const colorMap = { start:'text-green-400', stop:'text-red-400', reset:'text-yellow-400', suspend:'text-blue-400', cloned:'text-cyan-400', deleted:'text-red-400', renamed:'text-blue-400', 'snapshot.created':'text-purple-400', 'snapshot.deleted':'text-orange-400', 'migration.started':'text-emerald-400' };
                                                                const actionKey = Object.keys(iconMap).find(k => a.includes(k)) || '';
                                                                const icon = iconMap[actionKey] || '•';
                                                                const color = colorMap[actionKey] || 'text-gray-400';
                                                                const label = a.split('.').pop() || a;
                                                                return (
                                                                    <div key={i} className="px-4 py-2.5 hover:bg-proxmox-hover/30 flex items-start gap-3">
                                                                        <span className={`text-sm leading-none mt-0.5 ${color}`}>{icon}</span>
                                                                        <div className="flex-1 min-w-0">
                                                                            <div className="flex items-center gap-2">
                                                                                <span className={`text-xs font-semibold ${color}`}>{label}</span>
                                                                                <span className="text-xs text-gray-600">{evt.user || 'system'}</span>
                                                                            </div>
                                                                            <div className="text-xs text-gray-500 truncate">{evt.details || '-'}</div>
                                                                        </div>
                                                                        <span className="text-xs text-gray-600 whitespace-nowrap">{evt.timestamp ? new Date(evt.timestamp).toLocaleString() : ''}</span>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    ) : <div className="p-8 text-center text-gray-600 text-sm">{vmwareEventsLoading ? 'Loading...' : 'No ESXi events in audit log'}</div>}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ) : selectedGroup ? (
                                    // LW: Feb 2026 - folder overlay for group
                                    <GroupOverview
                                        group={selectedGroup}
                                        clusters={clusters}
                                        allMetrics={allClusterMetrics}
                                        clusterGroups={clusterGroups}
                                        topGuests={topGuests}
                                        onSelectCluster={(cluster) => { setSelectedGroup(null); setSelectedCluster(cluster); }}
                                        onSelectVm={(cluster, vmid, node) => { setSelectedGroup(null); setSelectedCluster(cluster); setHighlightedVm({ vmid, node }); setTimeout(() => setHighlightedVm(null), 5000); }}
                                        onOpenSettings={() => setShowGroupSettings(selectedGroup)}
                                        authFetch={authFetch}
                                        API_URL={API_URL}
                                    />
                                ) : (
                                    <AllClustersOverview
                                        clusters={clusters}
                                        allMetrics={allClusterMetrics}
                                        clusterGroups={clusterGroups}
                                        topGuests={topGuests}
                                        onSelectCluster={setSelectedCluster}
                                        onSelectVm={(cluster, vmid, node) => {
                                            // jump to vm
                                            setSelectedCluster(cluster);
                                            setHighlightedVm({ vmid, node });
                                            setTimeout(() => setHighlightedVm(null), 5000);
                                        }}
                                    />
                                )}
                            </div>
                        </div>

                    </div>

                    {/* LW: Feb 2026 - add/edit PBS server modal */}
                    {showAddPBS && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl w-full max-w-lg animate-scale-in max-h-[90vh] overflow-y-auto">
                                <div className="p-6">
                                    <h2 className="text-xl font-bold text-white mb-4">{editingPBS ? 'Edit PBS Server' : 'Add Proxmox Backup Server'}</h2>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Name *</label>
                                            <input value={pbsForm.name} onChange={e => setPbsForm(p => ({...p, name: e.target.value}))} placeholder="My PBS Server" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                        </div>
                                        <div className="grid grid-cols-3 gap-3">
                                            <div className="col-span-2">
                                                <label className="block text-sm text-gray-400 mb-1">Host *</label>
                                                <input value={pbsForm.host} onChange={e => setPbsForm(p => ({...p, host: e.target.value}))} placeholder="pbs.example.com" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Port</label>
                                                <input type="number" value={pbsForm.port} onChange={e => setPbsForm(p => ({...p, port: parseInt(e.target.value) || 8007}))} className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                        </div>

                                        <div className="border-t border-proxmox-border pt-4">
                                            <p className="text-xs text-gray-500 mb-3">Provide either Username + Password OR API Token (recommended)</p>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Username</label>
                                                <input value={pbsForm.user} onChange={e => setPbsForm(p => ({...p, user: e.target.value}))} placeholder="root@pam" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                            <div className="mt-3">
                                                <label className="block text-sm text-gray-400 mb-1">Password</label>
                                                <input type="password" value={pbsForm.password} onChange={e => setPbsForm(p => ({...p, password: e.target.value}))} placeholder="Password" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                            <div className="mt-3">
                                                <label className="block text-sm text-gray-400 mb-1">API Token ID</label>
                                                <input value={pbsForm.api_token_id} onChange={e => setPbsForm(p => ({...p, api_token_id: e.target.value}))} placeholder="user@pam!tokenname" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                            <div className="mt-3">
                                                <label className="block text-sm text-gray-400 mb-1">API Token Secret</label>
                                                <input type="password" value={pbsForm.api_token_secret} onChange={e => setPbsForm(p => ({...p, api_token_secret: e.target.value}))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white" />
                                            </div>
                                        </div>

                                        <div className="border-t border-proxmox-border pt-4">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Fingerprint (optional)</label>
                                                <input value={pbsForm.fingerprint} onChange={e => setPbsForm(p => ({...p, fingerprint: e.target.value}))} placeholder="AA:BB:CC:..." className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white font-mono text-xs" />
                                            </div>
                                            <div className="flex items-center gap-3 mt-3">
                                                <button onClick={() => setPbsForm(p => ({...p, ssl_verify: !p.ssl_verify}))} className={`w-10 h-5 rounded-full transition-all ${pbsForm.ssl_verify ? 'bg-green-500' : 'bg-gray-600'}`}>
                                                    <div className={`w-4 h-4 bg-white rounded-full transition-transform ${pbsForm.ssl_verify ? 'translate-x-5' : 'translate-x-0.5'}`}></div>
                                                </button>
                                                <span className="text-sm text-gray-300">Verify SSL Certificate</span>
                                            </div>
                                        </div>

                                        {/* Link to PVE Clusters */}
                                        {clusters.length > 0 && (
                                            <div className="border-t border-proxmox-border pt-4">
                                                <label className="block text-sm text-gray-400 mb-2">Link to PVE Clusters</label>
                                                <div className="space-y-1.5">
                                                    {clusters.map(cl => (
                                                        <label key={cl.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-proxmox-dark hover:bg-proxmox-hover cursor-pointer transition-colors">
                                                            <input type="checkbox" checked={(pbsForm.linked_clusters || []).includes(cl.id)} onChange={e => {
                                                                const linked = pbsForm.linked_clusters || [];
                                                                setPbsForm(p => ({...p, linked_clusters: e.target.checked ? [...linked, cl.id] : linked.filter(id => id !== cl.id)}));
                                                            }} className="rounded border-proxmox-border" />
                                                            <Icons.Server className="w-4 h-4 text-proxmox-orange" />
                                                            <span className="text-sm text-gray-300">{cl.name}</span>
                                                        </label>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Notes</label>
                                            <textarea value={pbsForm.notes} onChange={e => setPbsForm(p => ({...p, notes: e.target.value}))} rows={2} placeholder="Optional notes..." className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2.5 text-sm text-white resize-none" />
                                        </div>

                                        {/* Test Result */}
                                        {pbsTestResult && (
                                            <div className={`p-3 rounded-lg text-sm ${pbsTestResult.success ? 'bg-green-500/10 border border-green-500/30 text-green-400' : 'bg-red-500/10 border border-red-500/30 text-red-400'}`}>
                                                {pbsTestResult.success ? (
                                                    <span>Connection successful! PBS v{pbsTestResult.version?.version} - {pbsTestResult.datastores} datastore(s)</span>
                                                ) : (
                                                    <span>Connection failed: {pbsTestResult.error}</span>
                                                )}
                                            </div>
                                        )}
                                    </div>

                                    <div className="flex justify-between mt-6">
                                        <button onClick={async () => {
                                            setPbsTestLoading(true); setPbsTestResult(null);
                                            const result = await handleTestPBS(pbsForm);
                                            setPbsTestResult(result);
                                            setPbsTestLoading(false);
                                        }} disabled={pbsTestLoading || !pbsForm.host} className="px-4 py-2 rounded-lg bg-proxmox-dark border border-proxmox-border text-gray-300 hover:text-white text-sm flex items-center gap-2 disabled:opacity-50">
                                            {pbsTestLoading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Zap className="w-4 h-4" />}
                                            Test Connection
                                        </button>
                                        <div className="flex gap-2">
                                            <button onClick={() => { setShowAddPBS(false); setEditingPBS(null); setPbsTestResult(null); setPbsForm({ name: '', host: '', port: 8007, user: 'root@pam', password: '', api_token_id: '', api_token_secret: '', fingerprint: '', ssl_verify: false, linked_clusters: [], notes: '' }); }} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 hover:text-white transition-colors text-sm">Cancel</button>
                                            <button onClick={async () => {
                                                if (!pbsForm.name || !pbsForm.host) { addToast('Name and host are required', 'error'); return; }
                                                if (!pbsForm.api_token_id && !pbsForm.password) { addToast('Provide password or API token', 'error'); return; }
                                                let result;
                                                if (editingPBS) {
                                                    result = await handleUpdatePBS(editingPBS.id, pbsForm);
                                                } else {
                                                    result = await handleAddPBS(pbsForm);
                                                }
                                                if (result?.success) {
                                                    setShowAddPBS(false); setEditingPBS(null); setPbsTestResult(null);
                                                    setPbsForm({ name: '', host: '', port: 8007, user: 'root@pam', password: '', api_token_id: '', api_token_secret: '', fingerprint: '', ssl_verify: false, linked_clusters: [], notes: '' });
                                                } else if (result?.error) {
                                                    addToast(result.error, 'error');
                                                }
                                            }} disabled={!pbsForm.name || !pbsForm.host} className="px-4 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium disabled:opacity-50">
                                                {editingPBS ? 'Save Changes' : 'Add Server'}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* PBS Notes Edit Modal */}
                    {pbsEditingNotes && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={() => setPbsEditingNotes(null)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl max-w-lg w-full animate-scale-in" onClick={e => e.stopPropagation()}>
                                <div className="p-6">
                                    <div className="flex items-center justify-between mb-4">
                                        <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                            <Icons.FileText className="w-5 h-5 text-cyan-400" />
                                            {pbsEditingNotes.type === 'snapshot' ? 'Snapshot' : 'Group'} Notes
                                        </h2>
                                        <button onClick={() => setPbsEditingNotes(null)} className="text-gray-500 hover:text-white transition-colors">
                                            <Icons.X className="w-5 h-5" />
                                        </button>
                                    </div>
                                    <p className="text-sm text-gray-400 mb-3">{pbsEditingNotes.label}</p>
                                    <textarea
                                        value={pbsNotesText}
                                        onChange={e => setPbsNotesText(e.target.value)}
                                        className="w-full h-40 p-3 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm resize-y focus:outline-none focus:border-cyan-500/50"
                                        placeholder="Enter notes..."
                                    />
                                    <div className="flex justify-end gap-3 mt-4">
                                        <button onClick={() => setPbsEditingNotes(null)} className="px-4 py-2 rounded-lg bg-proxmox-dark text-gray-400 hover:text-white transition-colors text-sm">Cancel</button>
                                        <button onClick={() => pbsSaveNotes(pbsEditingNotes.type, pbsEditingNotes.params)} className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors text-sm font-medium">Save Notes</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* PBS File Browser Modal */}
                    {showPbsFileBrowser && pbsCatalogSnapshot && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={() => setShowPbsFileBrowser(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl max-w-3xl w-full max-h-[80vh] flex flex-col animate-scale-in" onClick={e => e.stopPropagation()}>
                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between shrink-0">
                                    <div>
                                        <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                            <Icons.Folder className="w-5 h-5 text-blue-400" />
                                            File Browser
                                        </h2>
                                        <p className="text-xs text-gray-500 mt-1">
                                            {pbsCatalogSnapshot['backup-type']}/{pbsCatalogSnapshot['backup-id']} @ {new Date(pbsCatalogSnapshot['backup-time'] * 1000).toLocaleString()}
                                        </p>
                                    </div>
                                    <button onClick={() => setShowPbsFileBrowser(false)} className="text-gray-500 hover:text-white transition-colors">
                                        <Icons.X className="w-5 h-5" />
                                    </button>
                                </div>
                                {/* Breadcrumb path */}
                                <div className="px-4 py-2 border-b border-proxmox-border/50 flex items-center gap-1 text-sm bg-proxmox-dark/50 shrink-0 overflow-x-auto">
                                    <button onClick={() => pbsNavigateCatalog('/')} className="text-blue-400 hover:text-blue-300 transition-colors">/</button>
                                    {pbsCatalogPath.split('/').filter(Boolean).map((seg, i, arr) => {
                                        const path = '/' + arr.slice(0, i + 1).join('/');
                                        return (
                                            <span key={i} className="flex items-center gap-1">
                                                <span className="text-gray-600">/</span>
                                                <button onClick={() => pbsNavigateCatalog(path)} className="text-blue-400 hover:text-blue-300 transition-colors">{seg}</button>
                                            </span>
                                        );
                                    })}
                                </div>
                                {/* File listing */}
                                <div className="flex-1 overflow-y-auto p-2">
                                    {pbsCatalogPath !== '/' && (
                                        <div onClick={() => { const parts = pbsCatalogPath.split('/').filter(Boolean); parts.pop(); pbsNavigateCatalog('/' + parts.join('/')); }}
                                            className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-proxmox-hover/30 cursor-pointer text-sm text-gray-400 hover:text-white transition-all">
                                            <Icons.ArrowLeft className="w-4 h-4" />
                                            <span>..</span>
                                        </div>
                                    )}
                                    {pbsCatalog.length > 0 ? pbsCatalog.sort((a, b) => {
                                        // Directories first, then files
                                        const aDir = a.type === 'Directory' || a.type === 'd' ? 0 : 1;
                                        const bDir = b.type === 'Directory' || b.type === 'd' ? 0 : 1;
                                        if (aDir !== bDir) return aDir - bDir;
                                        return (a.text || a.filename || '').localeCompare(b.text || b.filename || '');
                                    }).map((entry, i) => {
                                        const name = entry.text || entry.filename || entry.name || '-';
                                        const isDir = entry.type === 'Directory' || entry.type === 'd';
                                        const size = entry.size || entry.leaf_size || 0;
                                        const mtime = entry.mtime ? new Date(entry.mtime * 1000).toLocaleString() : '';
                                        const fullPath = (pbsCatalogPath === '/' ? '/' : pbsCatalogPath + '/') + name;
                                        return (
                                            <div key={i}
                                                onClick={() => isDir ? pbsNavigateCatalog(fullPath) : null}
                                                className={`flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-proxmox-hover/30 text-sm transition-all ${isDir ? 'cursor-pointer' : ''}`}>
                                                {isDir ? (
                                                    <Icons.Folder className="w-4 h-4 text-yellow-400 shrink-0" />
                                                ) : (
                                                    <Icons.File className="w-4 h-4 text-gray-500 shrink-0" />
                                                )}
                                                <span className={`flex-1 truncate ${isDir ? 'text-white' : 'text-gray-300'}`}>{name}</span>
                                                {!isDir && size > 0 && <span className="text-xs text-gray-500 shrink-0">{formatBytes(size)}</span>}
                                                {mtime && <span className="text-xs text-gray-600 shrink-0">{mtime}</span>}
                                                {!isDir && (
                                                    <button onClick={(e) => { e.stopPropagation(); pbsDownloadFile(fullPath); }} className="px-2 py-1 rounded text-xs text-gray-500 hover:text-green-400 hover:bg-green-500/10 transition-all shrink-0" title="Download">
                                                        <Icons.Download className="w-3.5 h-3.5" />
                                                    </button>
                                                )}
                                            </div>
                                        );
                                    }) : (
                                        <div className="text-center py-12 text-gray-500">
                                            <Icons.Folder className="w-8 h-8 mx-auto mb-3 opacity-30" />
                                            <p className="text-sm">No files found or catalog unavailable</p>
                                            <p className="text-xs text-gray-600 mt-1">File browsing is only available for host/file-level (pxar) backups</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* LW: Update Notification Modal - shown on login when update available */}
                    {showUpdateNotification && pendingUpdate && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl max-w-md w-full animate-scale-in overflow-hidden">
                                <div className="p-6 text-center">
                                    <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-green-500/20 to-emerald-500/20 flex items-center justify-center">
                                        <Icons.Download className="w-8 h-8 text-green-400" />
                                    </div>
                                    <h2 className="text-xl font-bold text-white mb-2">
                                        {t('newVersionAvailable') || 'New Version Available!'}
                                    </h2>
                                    <p className="text-gray-400 mb-2">
                                        {t('updateTo') || 'Update to'} <span className="text-green-400 font-semibold">{pendingUpdate.latest_version}</span>
                                    </p>
                                    <p className="text-sm text-gray-500 mb-6">
                                        {t('currentVersion') || 'Current version'}: {pendingUpdate.current_version}
                                    </p>
                                    
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setShowUpdateNotification(false)}
                                            className="flex-1 px-4 py-2.5 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-gray-300 transition-colors"
                                        >
                                            {t('later') || 'Later'}
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowUpdateNotification(false);
                                                setShowSettings(true);
                                                // Small delay to let settings modal open, then navigate to updates tab
                                                setTimeout(() => {
                                                    const event = new CustomEvent('pegaprox-navigate-updates');
                                                    window.dispatchEvent(event);
                                                }, 100);
                                            }}
                                            className="flex-1 px-4 py-2.5 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 rounded-lg text-white font-medium transition-all"
                                        >
                                            {t('viewUpdate') || 'View Update'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Config Modal */}
                    {configVm && (configVm._clusterId || selectedCluster) && (
                        <ConfigModal
                            vm={configVm}
                            clusterId={configVm._clusterId || selectedCluster.id}
                            allClusters={clusters}
                            dashboardAuthFetch={authFetch}
                            onClose={handleCloseConfig}
                            addToast={addToast}
                        />
                    )}

                    {/* Node Config Modal */}
                    {configNode && selectedCluster && (
                        <NodeModal 
                            node={configNode}
                            clusterId={selectedCluster.id}
                            onClose={() => setConfigNode(null)}
                            addToast={addToast}
                        />
                    )}

                    {/* Remove Node Modal - NS Feb 2026 */}
                    {showRemoveNodeDash && nodeToRemoveDash && selectedCluster && (
                        <RemoveNodeConfirmModal 
                            isOpen={showRemoveNodeDash} 
                            onClose={() => { setShowRemoveNodeDash(false); setNodeToRemoveDash(null); }} 
                            node={nodeToRemoveDash} 
                            clusterId={selectedCluster.id} 
                            onSuccess={() => { fetchClusterMetrics(selectedCluster.id); fetchClusterResources(selectedCluster.id); }} 
                            addToast={addToast} 
                        />
                    )}

                    {/* Move Node Modal - NS Feb 2026 */}
                    {showMoveNodeDash && nodeToMoveDash && selectedCluster && (
                        <MoveNodeModal 
                            isOpen={showMoveNodeDash} 
                            onClose={() => { setShowMoveNodeDash(false); setNodeToMoveDash(null); }} 
                            nodeName={nodeToMoveDash} 
                            currentClusterId={selectedCluster.id} 
                            clusters={clusters} 
                            onSuccess={() => { fetchClusterMetrics(selectedCluster.id); fetchClusterResources(selectedCluster.id); }} 
                            addToast={addToast} 
                        />
                    )}

                    {/* Create VM/CT Modal */}
                    {showCreateVm && selectedCluster && (
                        <CreateVmModal
                            vmType={showCreateVm}
                            clusterId={selectedCluster.id}
                            nodes={Object.keys(clusterMetrics)}
                            onCreate={handleCreateVm}
                            onClose={() => setShowCreateVm(null)}
                        />
                    )}
                    
                    {/* Add/Edit VMware Server Modal */}
                    {showAddVMware && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-2xl w-full max-w-lg shadow-2xl">
                                <div className="p-6 border-b border-proxmox-border flex items-center justify-between">
                                    <h2 className="text-lg font-bold text-white">{editingVMware ? 'Edit ESXi Server' : 'Add ESXi Server'}</h2>
                                    <button onClick={() => { setShowAddVMware(false); setEditingVMware(null); setVmwareTestResult(null); }} className="p-1 text-gray-500 hover:text-white rounded"><Icons.X className="w-5 h-5" /></button>
                                </div>
                                <div className="p-6 space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Name</label>
                                        <input value={vmwareForm.name} onChange={e => setVmwareForm(f => ({...f, name: e.target.value}))} placeholder="My ESXi Host" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50" />
                                    </div>
                                    <div className="grid grid-cols-3 gap-3">
                                        <div className="col-span-2">
                                            <label className="block text-sm text-gray-400 mb-1">Host</label>
                                            <input value={vmwareForm.host} onChange={e => setVmwareForm(f => ({...f, host: e.target.value}))} placeholder="192.168.1.100" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Port</label>
                                            <input type="number" value={vmwareForm.port} onChange={e => setVmwareForm(f => ({...f, port: parseInt(e.target.value) || 443}))} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50" />
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Username</label>
                                            <input value={vmwareForm.username} onChange={e => setVmwareForm(f => ({...f, username: e.target.value}))} placeholder="root" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Password</label>
                                            <input type="password" value={vmwareForm.password} onChange={e => setVmwareForm(f => ({...f, password: e.target.value}))} placeholder={editingVMware ? '(unchanged)' : 'Password'} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50" />
                                        </div>
                                    </div>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input type="checkbox" checked={vmwareForm.ssl_verify} onChange={e => setVmwareForm(f => ({...f, ssl_verify: e.target.checked}))} className="rounded" />
                                        <span className="text-sm text-gray-400">Verify SSL certificate</span>
                                    </label>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Notes</label>
                                        <textarea value={vmwareForm.notes} onChange={e => setVmwareForm(f => ({...f, notes: e.target.value}))} rows={2} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500/50 resize-none" />
                                    </div>

                                    <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
                                        <div className="text-xs text-blue-400 font-semibold mb-1">Requirements</div>
                                        <div className="text-xs text-blue-400/70">- SSH must be enabled on the ESXi host</div>
                                        <div className="text-xs text-blue-400/70">- ESXi root credentials are required for VM migration</div>
                                    </div>

                                    {vmwareTestResult && (
                                        <div className={`p-3 rounded-lg text-sm ${vmwareTestResult.error ? 'bg-red-500/10 border border-red-500/30 text-red-400' : 'bg-green-500/10 border border-green-500/30 text-green-400'}`}>
                                            {vmwareTestResult.error ? `Connection failed: ${vmwareTestResult.error}` : 'Connection successful!'}
                                        </div>
                                    )}
                                </div>
                                <div className="p-6 border-t border-proxmox-border flex items-center justify-between">
                                    <button onClick={() => handleTestVMware(vmwareForm)} disabled={vmwareTestLoading || !vmwareForm.host} className="px-4 py-2 rounded-lg bg-proxmox-dark border border-proxmox-border text-gray-400 hover:text-white text-sm disabled:opacity-50">
                                        {vmwareTestLoading ? 'Testing...' : 'Test Connection'}
                                    </button>
                                    <div className="flex items-center gap-2">
                                        <button onClick={() => { setShowAddVMware(false); setEditingVMware(null); setVmwareTestResult(null); }} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white text-sm">Cancel</button>
                                        <button onClick={() => editingVMware ? handleUpdateVMware(editingVMware.id, vmwareForm) : handleAddVMware(vmwareForm)} disabled={!vmwareForm.host || (!editingVMware && !vmwareForm.password)} className="px-4 py-2 rounded-lg bg-emerald-500 text-white text-sm font-medium hover:bg-emerald-600 disabled:opacity-50">
                                            {editingVMware ? 'Update' : 'Add Server'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Console Modal */}
                    {consoleVm && consoleInfo && (
                        <ConsoleModal
                            vm={consoleVm}
                            consoleInfo={consoleInfo}
                            clusterId={consoleVm._clusterId || selectedCluster?.id}
                            onClose={handleCloseConsole}
                        />
                    )}

                    {/* LW: Feb 2026 - corporate VM metrics modal */}
                    {corpMetricsVm && selectedCluster && (
                        <VmMetricsModal
                            vm={corpMetricsVm}
                            clusterId={selectedCluster.id}
                            onClose={() => setCorpMetricsVm(null)}
                        />
                    )}

                    {/* HA Split-Brain Prevention Settings Modal */}
                    {showHaSettings && selectedCluster && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowHaSettings(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-xl max-h-[85vh] overflow-hidden" onClick={e => e.stopPropagation()}>
                                <div className="flex justify-between items-center p-4 border-b border-proxmox-border bg-proxmox-dark">
                                    <div>
                                        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                                            <Icons.Shield className="text-green-400" />
                                            {t('splitBrainProtection')}
                                        </h2>
                                        <p className="text-sm text-gray-500">{selectedCluster.name}</p>
                                    </div>
                                    <button onClick={() => setShowHaSettings(false)} className="p-2 hover:bg-proxmox-hover rounded-lg">
                                        <Icons.X />
                                    </button>
                                </div>
                                
                                <div className="p-4 overflow-y-auto" style={{ maxHeight: 'calc(85vh - 140px)' }}>
                                    {/* SELF-FENCE - Main Feature */}
                                    <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-xl mb-4">
                                        <div className="flex items-center gap-2 mb-3">
                                            <span className="text-2xl">🛡️</span>
                                            <h4 className="text-green-400 font-medium">{t('selfFenceProtection')}</h4>
                                            <span className="px-2 py-1 rounded text-xs bg-green-500/20 text-green-400 ml-auto">
                                                {t('recommended')}
                                            </span>
                                        </div>
                                        
                                        <p className="text-sm text-gray-300 mb-3">
                                            {t('selfFenceExplain')}
                                        </p>
                                        
                                        {/* Status */}
                                        {haStatus?.self_fence_installed ? (
                                            <div className="p-3 bg-green-500/20 rounded-lg">
                                                <div className="flex items-center justify-between">
                                                    <div>
                                                        <p className="text-green-400 font-medium">✅ {t('selfFenceActive')}</p>
                                                        <p className="text-xs text-gray-400 mt-1">
                                                            {t('agentInstalledOnNodes')}: {haStatus.self_fence_nodes?.join(', ') || t('allNodes')}
                                                        </p>
                                                    </div>
                                                    <button
                                                        onClick={async () => {
                                                            if (!confirm(t('confirmUninstallAgent'))) return;
                                                            try {
                                                                const res = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/ha/uninstall-self-fence`, { method: 'POST' });
                                                                if (res.ok) {
                                                                    addToast(t('selfFenceUninstalling'), 'success');
                                                                    setTimeout(() => fetchHAStatus(selectedCluster.id), 3000);
                                                                }
                                                            } catch (e) {
                                                                addToast(t('error') + ': ' + e.message, 'error');
                                                            }
                                                        }}
                                                        className="px-3 py-1 text-xs bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg"
                                                    >
                                                        {t('uninstall')}
                                                    </button>
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="space-y-3">
                                                <div className="p-3 bg-yellow-500/20 rounded-lg">
                                                    <p className="text-yellow-400 font-medium">⚡ {t('selfFenceNotInstalled')}</p>
                                                    <p className="text-xs text-gray-300 mt-1">{t('selfFenceInstallHint')}</p>
                                                </div>
                                                <button
                                                    onClick={async () => {
                                                        try {
                                                            const res = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/ha/install-self-fence`, { method: 'POST' });
                                                            if (res.ok) {
                                                                addToast(t('selfFenceInstalling'), 'success');
                                                                setTimeout(() => fetchHAStatus(selectedCluster.id), 5000);
                                                            }
                                                        } catch (e) {
                                                            addToast(t('error') + ': ' + e.message, 'error');
                                                        }
                                                    }}
                                                    className="w-full px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg text-white font-medium"
                                                >
                                                    🛡️ {t('installSelfFenceAgent')}
                                                </button>
                                            </div>
                                        )}
                                        
                                        <div className="mt-3 text-xs text-gray-400">
                                            ✓ {t('noSharedStorageNeeded')} • ✓ {t('worksWithLvmIscsi')}
                                        </div>
                                    </div>
                                    
                                    {/* 2-Node Cluster Mode */}
                                    <label className="flex items-center gap-3 p-3 bg-proxmox-dark border border-proxmox-border rounded-xl mb-4 cursor-pointer hover:border-proxmox-orange/50">
                                        <input
                                            type="checkbox"
                                            checked={haSettings.two_node_mode}
                                            onChange={(e) => setHaSettings({...haSettings, two_node_mode: e.target.checked})}
                                            className="w-5 h-5 rounded border-proxmox-border bg-proxmox-darker text-proxmox-orange"
                                        />
                                        <div>
                                            <span className="text-white font-medium">{t('enable2NodeMode')}</span>
                                            <p className="text-xs text-gray-500">{t('twoNodeModeDesc')}</p>
                                        </div>
                                    </label>
                                    
                                    {/* Basic Settings */}
                                    <div className="grid grid-cols-2 gap-4 mb-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('recoveryDelay')}</label>
                                            <input
                                                type="number"
                                                min="10"
                                                max="300"
                                                value={haSettings.recovery_delay}
                                                onChange={(e) => setHaSettings({...haSettings, recovery_delay: parseInt(e.target.value) || 30})}
                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-white"
                                            />
                                            <p className="text-xs text-gray-500 mt-1">{t('recoveryDelayHint')}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('failureThreshold')}</label>
                                            <input
                                                type="number"
                                                min="1"
                                                max="10"
                                                value={haSettings.failure_threshold}
                                                onChange={(e) => setHaSettings({...haSettings, failure_threshold: parseInt(e.target.value) || 3})}
                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2 text-white"
                                            />
                                            <p className="text-xs text-gray-500 mt-1">{t('failureThresholdHint')}</p>
                                        </div>
                                    </div>
                                    
                                    {/* Advanced Settings - Collapsed */}
                                    <details className="bg-proxmox-dark border border-proxmox-border rounded-xl overflow-hidden">
                                        <summary className="p-3 cursor-pointer hover:bg-proxmox-hover flex items-center justify-between text-sm">
                                            <span className="text-gray-400">{t('advancedSettings')}</span>
                                            <Icons.ChevronDown className="w-4 h-4 text-gray-400" />
                                        </summary>
                                        <div className="p-3 pt-0 space-y-3 border-t border-proxmox-border">
                                            <div className="grid grid-cols-2 gap-3">
                                                <label className="flex items-center gap-2 p-2 bg-proxmox-darker rounded-lg">
                                                    <input
                                                        type="checkbox"
                                                        checked={haSettings.self_fence_enabled}
                                                        onChange={(e) => setHaSettings({...haSettings, self_fence_enabled: e.target.checked})}
                                                        className="w-4 h-4 rounded"
                                                    />
                                                    <span className="text-sm text-white">{t('selfFencing')}</span>
                                                </label>
                                                <label className="flex items-center gap-2 p-2 bg-proxmox-darker rounded-lg">
                                                    <input
                                                        type="checkbox"
                                                        checked={haSettings.verify_network}
                                                        onChange={(e) => setHaSettings({...haSettings, verify_network: e.target.checked})}
                                                        className="w-4 h-4 rounded"
                                                    />
                                                    <span className="text-sm text-white">{t('networkCheck')}</span>
                                                </label>
                                            </div>
                                            
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('additionalQuorumHosts')}</label>
                                                <input
                                                    type="text"
                                                    value={haSettings.quorum_hosts}
                                                    onChange={(e) => setHaSettings({...haSettings, quorum_hosts: e.target.value})}
                                                    placeholder="8.8.8.8, 1.1.1.1"
                                                    className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg px-3 py-2 text-white text-sm"
                                                />
                                            </div>
                                            
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('gatewayIp')}</label>
                                                <input
                                                    type="text"
                                                    value={haSettings.quorum_gateway}
                                                    onChange={(e) => setHaSettings({...haSettings, quorum_gateway: e.target.value})}
                                                    placeholder="192.168.1.1"
                                                    className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg px-3 py-2 text-white text-sm"
                                                />
                                            </div>
                                        </div>
                                    </details>
                                </div>
                                
                                {/* Footer */}
                                <div className="flex justify-end gap-2 p-4 border-t border-proxmox-border bg-proxmox-dark">
                                    <button
                                        onClick={() => setShowHaSettings(false)}
                                        className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg"
                                    >
                                        {t('cancel')}
                                    </button>
                                    <button
                                        onClick={handleSaveHASettings}
                                        className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg"
                                    >
                                        <Icons.Save className="w-4 h-4" />
                                        {t('saveSettings')}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Sponsor Footer */}
                    <footer className="border-t border-proxmox-border bg-proxmox-dark/50 mt-8">
                        <div className="max-w-[800px] mx-auto px-6 py-6">
                            <div className="text-center mb-4">
                                <p className="text-sm text-gray-400">
                                    ❤️ {t('thanksToSponsors') || 'Thanks to our Sponsors'}
                                </p>
                            </div>
                            <div className="flex justify-center gap-3 flex-wrap">
                                {/* Sponsor logos from /images/sponsors/ folder */}
                                {[1, 2, 3, 4, 5, 6, 7, 8].map(num => (
                                    <SponsorSlot key={num} num={num} />
                                ))}
                            </div>
                            <div className="text-center mt-4 text-xs text-gray-600">
                                <p>PegaProx {PEGAPROX_VERSION} • {t('madeWithLove') || 'Made with ❤️ for the Proxmox community'}</p>
                            </div>
                        </div>
                    </footer>

                    {/* Toast Notifications */}
                    <div className="fixed bottom-6 right-6 z-50 space-y-2">
                        {toasts.map(toast => (
                            <Toast
                                key={toast.id}
                                message={toast.message}
                                type={toast.type}
                                onClose={() => removeToast(toast.id)}
                            />
                        ))}
                    </div>

                    {/* Schedule Modal - MK Jan 2026 */}
                    {showScheduleModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md">
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="text-lg font-semibold">
                                        {editingSchedule ? (t('editSchedule') || 'Edit Schedule') : (t('newSchedule') || 'New Schedule')}
                                    </h3>
                                    <button onClick={() => setShowScheduleModal(false)} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X />
                                    </button>
                                </div>
                                <form onSubmit={async (e) => {
                                    e.preventDefault();
                                    const form = e.target;
                                    const data = {
                                        cluster_id: selectedCluster?.id,
                                        vmid: parseInt(form.vmid.value),
                                        vm_type: form.vm_type.value,
                                        action: form.action.value,
                                        schedule_type: form.schedule_type.value,
                                        time: form.time.value,
                                        name: form.name.value || `${form.action.value} VM ${form.vmid.value}`,
                                        date: form.date?.value,
                                        days: Array.from(form.querySelectorAll('input[name="days"]:checked')).map(cb => cb.value)
                                    };
                                    const success = await createSchedule(data);
                                    if (success) setShowScheduleModal(false);
                                }} className="p-4 space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                        <input name="name" type="text" placeholder={t('optionalName') || 'Optional name'} 
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">VMID</label>
                                            <input name="vmid" type="number" required 
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                            <select name="vm_type" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value="qemu">VM (QEMU)</option>
                                                <option value="lxc">Container (LXC)</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('action') || 'Action'}</label>
                                        <select name="action" required className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                            <option value="start">{t('start') || 'Start'}</option>
                                            <option value="stop">{t('stop') || 'Stop'}</option>
                                            <option value="shutdown">{t('shutdown') || 'Shutdown'}</option>
                                            <option value="reboot">{t('reboot') || 'Reboot'}</option>
                                            <option value="snapshot">{t('snapshot') || 'Snapshot'}</option>
                                        </select>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('scheduleType') || 'Schedule Type'}</label>
                                            <select name="schedule_type" required className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value="daily">{t('daily') || 'Daily'}</option>
                                                <option value="weekdays">{t('weekdays') || 'Weekdays'}</option>
                                                <option value="weekends">{t('weekends') || 'Weekends'}</option>
                                                <option value="weekly">{t('weekly') || 'Weekly'}</option>
                                                <option value="once">{t('once') || 'Once'}</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('time') || 'Time'}</label>
                                            <input name="time" type="time" required 
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('date') || 'Date'} ({t('forOnce') || 'for once'})</label>
                                        <input name="date" type="date" 
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('days') || 'Days'} ({t('forWeekly') || 'for weekly'})</label>
                                        <div className="flex flex-wrap gap-2">
                                            {['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'].map(day => (
                                                <label key={day} className="flex items-center gap-1 text-sm">
                                                    <input type="checkbox" name="days" value={day} className="rounded" />
                                                    {day.slice(0, 3)}
                                                </label>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-2">
                                        <button type="button" onClick={() => setShowScheduleModal(false)}
                                            className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg">
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button type="submit" className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg">
                                            {t('save') || 'Save'}
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* Tag Editor Modal - NS Jan 2026 */}
                    {showTagEditor && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowTagEditor(null)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-sm" onClick={e => e.stopPropagation()}>
                                <div className="p-4 border-b border-proxmox-border">
                                    <h3 className="font-semibold flex items-center gap-2">
                                        <Icons.Tag />
                                        {t('manageTags') || 'Manage Tags'}: {showTagEditor.vmName}
                                    </h3>
                                </div>
                                <div className="p-4 space-y-4">
                                    {/* Current tags */}
                                    <div className="flex flex-wrap gap-2">
                                        {getVmTags(showTagEditor.clusterId, showTagEditor.vmid).map((tag, idx) => (
                                            <span 
                                                key={idx}
                                                className="flex items-center gap-1 px-2 py-1 rounded-full text-xs"
                                                style={{ backgroundColor: (tag.color || '#6b7280') + '30', color: tag.color || '#9ca3af' }}
                                            >
                                                {tag.name || tag}
                                                <button 
                                                    onClick={() => removeTagFromVm(showTagEditor.clusterId, showTagEditor.vmid, tag.name || tag)}
                                                    className="hover:text-red-400"
                                                >
                                                    <Icons.X className="w-3 h-3" />
                                                </button>
                                            </span>
                                        ))}
                                        {getVmTags(showTagEditor.clusterId, showTagEditor.vmid).length === 0 && (
                                            <span className="text-gray-500 text-sm">{t('noTags') || 'No tags'}</span>
                                        )}
                                    </div>
                                    
                                    {/* Add new tag */}
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            value={newTagName}
                                            onChange={e => setNewTagName(e.target.value)}
                                            onKeyDown={async e => {
                                                if (e.key === 'Enter' && newTagName.trim()) {
                                                    await addTagToVm(showTagEditor.clusterId, showTagEditor.vmid, newTagName.trim());
                                                    setNewTagName('');
                                                }
                                            }}
                                            placeholder={t('newTag') || 'New tag...'}
                                            className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm"
                                        />
                                        <button
                                            onClick={async () => {
                                                if (newTagName.trim()) {
                                                    await addTagToVm(showTagEditor.clusterId, showTagEditor.vmid, newTagName.trim());
                                                    setNewTagName('');
                                                }
                                            }}
                                            className="px-3 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg"
                                        >
                                            <Icons.Plus className="w-4 h-4" />
                                        </button>
                                    </div>
                                    
                                    {/* Suggested tags from cluster */}
                                    {clusterTags.length > 0 && (
                                        <div>
                                            <p className="text-xs text-gray-500 mb-2">{t('existingTags') || 'Existing tags'}:</p>
                                            <div className="flex flex-wrap gap-1">
                                                {clusterTags.filter(t => 
                                                    !getVmTags(showTagEditor.clusterId, showTagEditor.vmid).some(vt => (vt.name || vt) === t.name)
                                                ).slice(0, 10).map((tag, idx) => (
                                                    <button
                                                        key={idx}
                                                        onClick={() => addTagToVm(showTagEditor.clusterId, showTagEditor.vmid, tag.name, tag.color)}
                                                        className="px-2 py-0.5 rounded-full text-xs hover:opacity-80"
                                                        style={{ backgroundColor: (tag.color || '#6b7280') + '30', color: tag.color || '#9ca3af' }}
                                                    >
                                                        + {tag.name}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                                <div className="p-4 border-t border-proxmox-border">
                                    <button
                                        onClick={() => setShowTagEditor(null)}
                                        className="w-full px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                    >
                                        {t('close') || 'Close'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Alert Modal - NS Jan 2026 - Supports Cluster/Node/VM targeting */}
                    {showAlertModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowAlertModal(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="text-lg font-semibold">{t('newAlert') || 'New Alert'}</h3>
                                    <button onClick={() => setShowAlertModal(false)} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X />
                                    </button>
                                </div>
                                <form onSubmit={async (e) => {
                                    e.preventDefault();
                                    const form = e.target;
                                    await createClusterAlert({
                                        name: form.name.value,
                                        target_type: form.target_type.value,
                                        target_id: form.target_id.value || null,
                                        metric: form.metric.value,
                                        operator: form.operator.value,
                                        threshold: parseInt(form.threshold.value),
                                        action: form.action.value,
                                        enabled: true
                                    });
                                }} className="p-4 space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                        <input name="name" required placeholder="High CPU Alert" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    
                                    {/* Target Type Selection */}
                                    <div className="grid grid-cols-2 gap-3">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('targetType') || 'Apply to'}</label>
                                            <select name="target_type" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value="cluster">{t('entireCluster') || 'Entire Cluster'}</option>
                                                <option value="node">{t('specificNode') || 'Specific Node'}</option>
                                                <option value="vm">{t('specificVm') || 'Specific VM'}</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('targetId') || 'Target'} <span className="text-xs text-gray-600">({t('optional') || 'optional'})</span></label>
                                            <input name="target_id" placeholder="node1 or VMID" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        </div>
                                    </div>
                                    
                                    <div className="grid grid-cols-3 gap-3">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('metric') || 'Metric'}</label>
                                            <select name="metric" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value="cpu">CPU</option>
                                                <option value="memory">Memory</option>
                                                <option value="disk">Disk</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('condition') || 'Condition'}</label>
                                            <select name="operator" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value=">">&gt; above</option>
                                                <option value="<">&lt; below</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('threshold') || 'Threshold'} %</label>
                                            <input name="threshold" type="number" min="0" max="100" defaultValue="80" required className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('action') || 'Action'}</label>
                                        <select name="action" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                            <option value="log">Log Only</option>
                                            <option value="email">Email</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-2">
                                        <button type="button" onClick={() => setShowAlertModal(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg">
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button type="submit" className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg">
                                            {t('create') || 'Create'}
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* Affinity Rule Modal - NS Jan 2026 */}
                    {showAffinityModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowAffinityModal(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="text-lg font-semibold">{t('newRule') || 'New Affinity Rule'}</h3>
                                    <button onClick={() => setShowAffinityModal(false)} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X />
                                    </button>
                                </div>
                                <form onSubmit={async (e) => {
                                    e.preventDefault();
                                    const form = e.target;
                                    const vmIds = form.vm_ids.value.split(',').map(id => parseInt(id.trim())).filter(Boolean);
                                    await createClusterAffinityRule({
                                        name: form.rule_name.value || 'New Rule',
                                        type: form.type.value,
                                        vm_ids: vmIds,
                                        enforce: form.enforce.checked
                                    });
                                }} className="p-4 space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('ruleName') || 'Rule Name'}</label>
                                        <input name="rule_name" placeholder="e.g. DB Cluster Affinity" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('ruleType') || 'Rule Type'}</label>
                                        <select name="type" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                            <option value="together">{t('together') || 'Together'} - VMs/CTs on same node</option>
                                            <option value="separate">{t('separate') || 'Separate'} - VMs/CTs on different nodes</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">VM/CT IDs ({t('commaSeparated') || 'comma-separated'})</label>
                                        <input name="vm_ids" required placeholder="100, 101, 102" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input name="enforce" type="checkbox" className="rounded" />
                                        <span className="text-sm">{t('enforced') || 'Enforce'}</span>
                                        <span className="text-xs text-gray-500">({t('enforceHint') || 'Block migrations that violate rule'})</span>
                                    </label>
                                    <div className="flex gap-2 justify-end pt-2">
                                        <button type="button" onClick={() => setShowAffinityModal(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg">
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button type="submit" className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg">
                                            {t('create') || 'Create'}
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* Script Run Confirmation Modal - Password required */}
                    {showScriptRunModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowScriptRunModal(null)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
                                <div className="flex items-center justify-between p-4 border-b border-proxmox-border">
                                    <h3 className="text-lg font-semibold">{t('runScript') || 'Run Script'}</h3>
                                    <button onClick={() => setShowScriptRunModal(null)} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X className="w-5 h-5" />
                                    </button>
                                </div>
                                <form className="p-4 space-y-4" onSubmit={async (e) => {
                                    e.preventDefault();
                                    const password = e.target.password.value;
                                    if (!password) return;
                                    
                                    try {
                                        const res = await authFetch(`${API_URL}/clusters/${selectedCluster.id}/scripts/${showScriptRunModal.id}/run`, {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ password })
                                        });
                                        
                                        if (res && res.ok) {
                                            const data = await res.json();
                                            addToast(data.message || (t('scriptStarted') || 'Script execution started'), 'success');
                                            setShowScriptRunModal(null);
                                            // Reload scripts to show last_run update
                                            setTimeout(() => loadCustomScripts(selectedCluster.id), 1000);
                                        } else {
                                            const err = await res.json().catch(() => ({}));
                                            addToast(err.error || 'Failed to run script', 'error');
                                        }
                                    } catch (e) {
                                        addToast('Error: ' + e.message, 'error');
                                    }
                                }}>
                                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-300 text-sm">
                                        <strong>{t('warning') || 'Warning'}:</strong> {t('scriptWarning') || 'Scripts run with SSH user permissions. Ensure scripts are safe before running.'}
                                    </div>
                                    
                                    <div className="bg-proxmox-dark rounded-lg p-3">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                                                showScriptRunModal.type === 'python' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'
                                            }`}>
                                                {showScriptRunModal.type === 'python' ? '🐍' : '📜'}
                                            </div>
                                            <div>
                                                <h4 className="font-medium text-white">{showScriptRunModal.name}</h4>
                                                <p className="text-xs text-gray-500">{showScriptRunModal.description || 'No description'}</p>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('confirmPassword') || 'Confirm your password'} *</label>
                                        <input 
                                            name="password" 
                                            type="password" 
                                            required 
                                            autoFocus
                                            placeholder={t('enterPassword') || 'Enter your password'}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" 
                                        />
                                        <p className="text-xs text-gray-500 mt-1">{t('passwordRequiredForScripts') || 'Password confirmation required for security'}</p>
                                    </div>
                                    
                                    <div className="flex justify-end gap-3 pt-2">
                                        <button type="button" onClick={() => setShowScriptRunModal(null)} className="px-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg hover:bg-proxmox-hover">
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button type="submit" className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg flex items-center gap-2">
                                            <Icons.Play className="w-4 h-4" />
                                            {t('runScript') || 'Run Script'}
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* Script Output Modal */}
                    {scriptOutput && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setScriptOutput(null)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
                                <div className="flex items-center justify-between p-4 border-b border-proxmox-border">
                                    <div>
                                        <h3 className="text-lg font-semibold">{scriptOutput.name} - {t('output') || 'Output'}</h3>
                                        <p className="text-xs text-gray-500">
                                            {t('lastRun') || 'Last run'}: {scriptOutput.last_run ? new Date(scriptOutput.last_run).toLocaleString() : (t('never') || 'Never')} 
                                            {scriptOutput.last_status && (
                                                <span className={`ml-2 px-2 py-0.5 rounded text-xs ${
                                                    scriptOutput.last_status === 'success' ? 'bg-green-500/20 text-green-400' :
                                                    scriptOutput.last_status === 'partial' ? 'bg-yellow-500/20 text-yellow-400' :
                                                    'bg-red-500/20 text-red-400'
                                                }`}>
                                                    {scriptOutput.last_status}
                                                </span>
                                            )}
                                        </p>
                                    </div>
                                    <button onClick={() => setScriptOutput(null)} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X className="w-5 h-5" />
                                    </button>
                                </div>
                                <div className="p-4 flex-1 overflow-auto">
                                    <pre className="bg-proxmox-dark p-4 rounded-lg text-sm font-mono whitespace-pre-wrap text-gray-300 max-h-[60vh] overflow-auto">
                                        {scriptOutput.output || t('noOutput') || 'No output available'}
                                    </pre>
                                </div>
                                <div className="p-4 border-t border-proxmox-border flex justify-end">
                                    <button onClick={() => setScriptOutput(null)} className="px-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg hover:bg-proxmox-hover">
                                        {t('close') || 'Close'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Custom Script Modal */}
                    {showScriptModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => { setShowScriptModal(false); setEditingScript(null); }}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                                <div className="flex items-center justify-between p-4 border-b border-proxmox-border">
                                    <h3 className="text-lg font-semibold">{editingScript ? (t('editScript') || 'Edit Script') : (t('newScript') || 'New Script')}</h3>
                                    <button onClick={() => { setShowScriptModal(false); setEditingScript(null); }} className="p-1 hover:bg-proxmox-hover rounded">
                                        <Icons.X className="w-5 h-5" />
                                    </button>
                                </div>
                                <form className="p-4 space-y-4" onSubmit={async (e) => {
                                    e.preventDefault();
                                    const form = e.target;
                                    const data = {
                                        name: form.name.value,
                                        description: form.description.value,
                                        type: form.type.value,
                                        content: form.content.value,
                                        target_nodes: form.target_nodes.value,
                                        enabled: form.enabled.checked
                                    };
                                    
                                    try {
                                        const url = editingScript 
                                            ? `${API_URL}/clusters/${selectedCluster.id}/scripts/${editingScript.id}`
                                            : `${API_URL}/clusters/${selectedCluster.id}/scripts`;
                                        console.log('[Script] Saving to:', url, 'Data:', data);
                                        const res = await authFetch(url, {
                                            method: editingScript ? 'PUT' : 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify(data)
                                        });
                                        console.log('[Script] Response:', res?.status, res?.ok);
                                        
                                        if (res && res.ok) {
                                            addToast(editingScript ? (t('scriptUpdated') || 'Script updated') : (t('scriptCreated') || 'Script created'), 'success');
                                            setShowScriptModal(false);
                                            setEditingScript(null);
                                            // Reload scripts
                                            loadCustomScripts(selectedCluster.id);
                                        } else {
                                            const err = await res.json().catch(() => ({}));
                                            console.error('[Script] Error response:', err);
                                            addToast(err.error || 'Failed to save script', 'error');
                                        }
                                    } catch (e) {
                                        console.error('[Script] Exception:', e);
                                        addToast('Error saving script: ' + e.message, 'error');
                                    }
                                }}>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'} *</label>
                                            <input name="name" required defaultValue={editingScript?.name || ''} placeholder="my-script" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                            <select name="type" defaultValue={editingScript?.type || 'bash'} className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg">
                                                <option value="bash">Bash (.sh)</option>
                                                <option value="python">Python (.py)</option>
                                            </select>
                                        </div>
                                    </div>
                                    
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('description') || 'Description'}</label>
                                        <input name="description" defaultValue={editingScript?.description || ''} placeholder="What does this script do?" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                    </div>
                                    
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('targetNodes') || 'Target Nodes'}</label>
                                        <input name="target_nodes" defaultValue={editingScript?.target_nodes || 'all'} placeholder="all or node1,node2" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg" />
                                        <p className="text-xs text-gray-600 mt-1">Use "all" for all nodes or comma-separated node names</p>
                                    </div>
                                    
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('scriptContent') || 'Script Content'} *</label>
                                        <textarea 
                                            name="content" 
                                            required 
                                            rows={12}
                                            defaultValue={editingScript?.content || (editingScript?.type === 'python' ? '#!/usr/bin/env python3\n# Your script here\n\nprint("Hello from PegaProx!")' : '#!/bin/bash\n# Your script here\n\necho "Hello from PegaProx!"')}
                                            placeholder="#!/bin/bash"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg font-mono text-sm"
                                        />
                                    </div>
                                    
                                    <label className="flex items-center gap-2">
                                        <input type="checkbox" name="enabled" defaultChecked={editingScript?.enabled !== false} className="w-4 h-4 rounded" />
                                        <span>{t('enabled') || 'Enabled'}</span>
                                    </label>
                                    
                                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                                        <div className="flex items-start gap-2">
                                            <Icons.AlertTriangle className="text-yellow-500 w-5 h-5 mt-0.5" />
                                            <div className="text-sm text-yellow-200">
                                                <strong>{t('warning') || 'Warning'}:</strong> {t('scriptWarning') || 'Scripts run with SSH user permissions. Ensure scripts are safe before running.'}
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div className="flex gap-2 justify-end pt-2">
                                        <button type="button" onClick={() => { setShowScriptModal(false); setEditingScript(null); }} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg">
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button type="submit" className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg">
                                            {editingScript ? (t('update') || 'Update') : (t('create') || 'Create')}
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* Add Cluster Modal */}
                    <AddClusterModal
                        isOpen={showAddModal}
                        initialType={addClusterType}
                        onClose={() => {
                            setShowAddModal(false);
                            setError(null);
                        }}
                        onSubmit={handleAddCluster}
                        onAddPBS={async (config) => {
                            const result = await handleAddPBS(config);
                            if (result !== false) { setShowAddModal(false); setError(null); }
                        }}
                        onAddVMware={async (config) => {
                            const result = await handleAddVMware(config);
                            if (result !== false) { setShowAddModal(false); setError(null); }
                        }}
                        loading={loading}
                        error={error}
                    />
                    
                    {/* User Profile Modal */}
                    <UserProfileModal
                        isOpen={showProfile}
                        onClose={() => setShowProfile(false)}
                        addToast={addToast}
                    />
                    
                    {/* PegaProx Settings Modal */}
                    <PegaProxSettingsModal
                        isOpen={showSettings}
                        onClose={() => setShowSettings(false)}
                        addToast={addToast}
                    />
                    
                    {/* Group Manager Modal */}
                    {showGroupManager && (
                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg p-6 max-h-[80vh] overflow-auto">
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-lg font-semibold">{t('clusterGroups')}</h3>
                                    <button onClick={() => setShowGroupManager(false)} className="text-gray-400 hover:text-white">
                                        <Icons.X />
                                    </button>
                                </div>
                                
                                <p className="text-sm text-gray-400 mb-4">
                                    {t('clusterGroupsDesc')}
                                </p>
                                
                                {/* Add New Group */}
                                <div className="mb-4 p-3 bg-proxmox-dark rounded-lg">
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            placeholder={t('groupName') + '...'}
                                            id="newGroupName"
                                            className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded text-white text-sm"
                                        />
                                        <input
                                            type="color"
                                            defaultValue="#E86F2D"
                                            id="newGroupColor"
                                            className="w-10 h-10 rounded cursor-pointer"
                                        />
                                        <button
                                            onClick={async () => {
                                                const name = document.getElementById('newGroupName').value;
                                                const color = document.getElementById('newGroupColor').value;
                                                if (!name) return;
                                                try {
                                                    const r = await fetch(`${API_URL}/cluster-groups`, {
                                                        method: 'POST',
                                                        credentials: 'include',
                                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ name, color })
                                                    });
                                                    if (r.ok) {
                                                        document.getElementById('newGroupName').value = '';
                                                        fetchClusterGroups();
                                                        addToast(t('groupCreated'), 'success');
                                                    }
                                                } catch(e) {}
                                            }}
                                            className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded text-sm font-medium"
                                        >
                                            {t('add')}
                                        </button>
                                    </div>
                                </div>
                                
                                {/* Groups List */}
                                <div className="space-y-2">
                                    {clusterGroups.length === 0 ? (
                                        <p className="text-gray-500 text-center py-4">{t('noGroupsYet')}</p>
                                    ) : (
                                        clusterGroups.map(group => {
                                            const groupClusters = clusters.filter(c => c.group_id === group.id);
                                            const tenant = group.tenant_id ? 
                                                // We don't have tenants here, show ID
                                                group.tenant_id : null;
                                            return (
                                                <div key={group.id} className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: group.color || '#E86F2D' }} />
                                                        <div>
                                                            <span className="text-white font-medium">{group.name}</span>
                                                            <span className="text-xs text-gray-500 ml-2">({groupClusters.length} clusters)</span>
                                                            {tenant && (
                                                                <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-blue-500/20 text-blue-400 rounded">
                                                                    Tenant: {tenant}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>
                                                    <button
                                                        onClick={async () => {
                                                            if (!confirm(`Delete group "${group.name}"?`)) return;
                                                            try {
                                                                const r = await fetch(`${API_URL}/cluster-groups/${group.id}`, {
                                                                    method: 'DELETE',
                                                                    credentials: 'include',
                                                                    headers: getAuthHeaders()
                                                                });
                                                                if (r.ok) {
                                                                    fetchClusterGroups();
                                                                    fetchClusters();
                                                                    addToast('Group deleted', 'success');
                                                                }
                                                            } catch(e) {}
                                                        }}
                                                        className="p-1 text-red-400 hover:bg-red-500/20 rounded"
                                                    >
                                                        <Icons.Trash className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            );
                                        })
                                    )}
                                </div>
                                
                                <div className="mt-4 pt-4 border-t border-proxmox-border">
                                    <p className="text-xs text-gray-500">
                                        {t('groupsTip')}
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Assign Group Modal */}
                    {showAssignGroup && (
                        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-sm p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-lg font-semibold">{t('assignToGroup')}</h3>
                                    <button onClick={() => setShowAssignGroup(null)} className="text-gray-400 hover:text-white">
                                        <Icons.X />
                                    </button>
                                </div>
                                
                                <p className="text-sm text-gray-400 mb-4">
                                    {t('assignToGroup')}: <span className="text-white font-medium">{showAssignGroup.name}</span>
                                </p>
                                
                                <div className="space-y-2">
                                    <button
                                        onClick={async () => {
                                            try {
                                                const r = await fetch(`${API_URL}/clusters/${showAssignGroup.id}/group`, {
                                                    method: 'PUT',
                                                    credentials: 'include',
                                                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                    body: JSON.stringify({ group_id: null })
                                                });
                                                if (r.ok) {
                                                    fetchClusters();
                                                    setShowAssignGroup(null);
                                                    addToast(t('removeFromGroup'), 'success');
                                                }
                                            } catch(e) {}
                                        }}
                                        className={`w-full p-3 rounded-lg text-left transition-colors ${
                                            !showAssignGroup.group_id ? 'bg-proxmox-orange/20 border border-proxmox-orange' : 'bg-proxmox-dark hover:bg-proxmox-hover border border-transparent'
                                        }`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <Icons.Server className="w-4 h-4 text-gray-400" />
                                            <span className="text-gray-300">{t('noGroup')} ({t('ungrouped')})</span>
                                        </div>
                                    </button>
                                    
                                    {clusterGroups.map(group => (
                                        <button
                                            key={group.id}
                                            onClick={async () => {
                                                try {
                                                    const r = await fetch(`${API_URL}/clusters/${showAssignGroup.id}/group`, {
                                                        method: 'PUT',
                                                        credentials: 'include',
                                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ group_id: group.id })
                                                    });
                                                    if (r.ok) {
                                                        fetchClusters();
                                                        setShowAssignGroup(null);
                                                        addToast(t('groupUpdated'), 'success');
                                                    }
                                                } catch(e) {}
                                            }}
                                            className={`w-full p-3 rounded-lg text-left transition-colors ${
                                                showAssignGroup.group_id === group.id ? 'bg-proxmox-orange/20 border border-proxmox-orange' : 'bg-proxmox-dark hover:bg-proxmox-hover border border-transparent'
                                            }`}
                                        >
                                            <div className="flex items-center gap-3">
                                                <Icons.Folder className="w-4 h-4" style={{ color: group.color || '#E86F2D' }} />
                                                <span className="text-gray-300">{group.name}</span>
                                            </div>
                                        </button>
                                    ))}
                                </div>
                                
                                {clusterGroups.length === 0 && (
                                    <p className="text-sm text-gray-500 text-center mt-4">
                                        {t('createGroupFirst')}
                                    </p>
                                )}
                            </div>
                        </div>
                    )}
                    
                    {/* LW: Feb 2026 - group settings modal */}
                    {showGroupSettings && (() => {
                        // local state via closure - keeps it simple without extra component
                        const grp = showGroupSettings;
                        return (
                            <GroupSettingsModal
                                group={grp}
                                groupClusters={clusters.filter(c => c.group_id === grp.id)}
                                authFetch={authFetch}
                                addToast={addToast}
                                onClose={() => setShowGroupSettings(null)}
                                onSave={async (updatedFields) => {
                                    try {
                                        const r = await authFetch(`${API_URL}/cluster-groups/${grp.id}`, {
                                            method: 'PUT',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify(updatedFields)
                                        });
                                        if (r && r.ok) {
                                            fetchClusterGroups();
                                            // update selectedGroup if it's the same one
                                            if (selectedGroup?.id === grp.id) {
                                                setSelectedGroup(prev => ({ ...prev, ...updatedFields }));
                                            }
                                            addToast('Group settings saved', 'success');
                                            setShowGroupSettings(null);
                                        } else {
                                            addToast('Failed to save group settings', 'error');
                                        }
                                    } catch (e) {
                                        addToast('Error saving group settings', 'error');
                                    }
                                }}
                            />
                        );
                    })()}

                    {/* Task Bar */}
                    {showTaskBar && (
                        <TaskBar
                            tasks={tasks}
                            onClear={clearCompletedTasks}
                            onClose={() => setShowTaskBar(false)}
                            onCancel={cancelTask}
                            onRefresh={() => selectedCluster && fetchTasks(selectedCluster.id)}
                            clusterId={selectedCluster?.id}
                            autoExpandEnabled={user?.taskbar_auto_expand !== false}
                        />
                    )}
                </div>
            );
        }

        // Main App with Auth Check
        // NS: Feb 2026 - Forced 2FA setup modal (shown when admin requires 2FA and user hasn't set it up yet)
        function Force2FASetupModal() {
            const { t } = useTranslation();
            const { getAuthHeaders, setRequires2FASetup } = useAuth();
            const [step, setStep] = useState('intro'); // intro, scan, verify
            const [qrData, setQrData] = useState(null);
            const [verifyCode, setVerifyCode] = useState('');
            const [error, setError] = useState('');
            const [loading, setLoading] = useState(false);
            
            const startSetup = async () => {
                setLoading(true);
                setError('');
                try {
                    const r = await fetch(`${API_URL}/auth/2fa/setup`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' }
                    });
                    const data = await r.json();
                    if (r.ok) {
                        setQrData(data);
                        setStep('scan');
                    } else {
                        setError(data.error || 'Failed to start 2FA setup');
                    }
                } catch(e) {
                    setError(e.message);
                }
                setLoading(false);
            };
            
            const verifySetup = async () => {
                if (!verifyCode || verifyCode.length !== 6) return;
                setLoading(true);
                setError('');
                try {
                    const r = await fetch(`${API_URL}/auth/2fa/verify`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                        body: JSON.stringify({ code: verifyCode })
                    });
                    const data = await r.json();
                    if (r.ok && data.success) {
                        setRequires2FASetup(false);
                    } else {
                        setError(data.error || t('invalid2FACode') || 'Invalid code');
                        setVerifyCode('');
                    }
                } catch(e) {
                    setError(e.message);
                }
                setLoading(false);
            };
            
            return (
                <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-[100] p-4">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md shadow-2xl">
                        <div className="p-6">
                            <div className="flex items-center gap-3 mb-4">
                                <div className="p-2 bg-proxmox-orange/20 rounded-lg">
                                    <Icons.Shield className="w-6 h-6 text-proxmox-orange" />
                                </div>
                                <h2 className="text-lg font-semibold text-white">
                                    {t('force2FASetupTitle') || '2FA Setup Required'}
                                </h2>
                            </div>
                            
                            {step === 'intro' && (
                                <div className="space-y-4">
                                    <p className="text-gray-400 text-sm">
                                        {t('force2FASetupDesc') || 'Your administrator has made Two-Factor Authentication mandatory. Please set up 2FA to continue.'}
                                    </p>
                                    <button
                                        onClick={startSetup}
                                        disabled={loading}
                                        className="w-full px-4 py-3 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-white font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                                    >
                                        {loading ? <Icons.RotateCw className="w-4 h-4 animate-spin" /> : <Icons.Shield className="w-4 h-4" />}
                                        {t('setup2FA') || 'Setup 2FA'}
                                    </button>
                                </div>
                            )}
                            
                            {step === 'scan' && qrData && (
                                <div className="space-y-4">
                                    <p className="text-gray-400 text-sm">
                                        {t('scan2FACode') || 'Scan QR code with authenticator app'}
                                    </p>
                                    <div className="flex justify-center p-4 bg-white rounded-lg">
                                        <img src={qrData.qr_code} alt="QR Code" className="w-48 h-48" />
                                    </div>
                                    <div className="p-3 bg-proxmox-dark rounded-lg">
                                        <p className="text-xs text-gray-500 mb-1">{t('secretKey') || 'Secret Key'}:</p>
                                        <code className="text-sm text-proxmox-orange break-all select-all">{qrData.secret}</code>
                                    </div>
                                    <button
                                        onClick={() => setStep('verify')}
                                        className="w-full px-4 py-2.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-white font-medium transition-colors"
                                    >
                                        {t('next') || 'Next'}
                                    </button>
                                </div>
                            )}
                            
                            {step === 'verify' && (
                                <div className="space-y-4">
                                    <p className="text-gray-400 text-sm">
                                        {t('enter2FACode') || 'Enter 6-digit code'}
                                    </p>
                                    <input
                                        type="text"
                                        value={verifyCode}
                                        onChange={e => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                        onKeyDown={e => e.key === 'Enter' && verifySetup()}
                                        placeholder="000000"
                                        className="w-full text-center text-2xl tracking-[0.5em] bg-proxmox-dark border border-proxmox-border rounded-lg p-3 text-white font-mono"
                                        autoFocus
                                    />
                                    <button
                                        onClick={verifySetup}
                                        disabled={loading || verifyCode.length !== 6}
                                        className="w-full px-4 py-2.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-white font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                                    >
                                        {loading && <Icons.RotateCw className="w-4 h-4 animate-spin" />}
                                        {t('verify2FA') || 'Verify'}
                                    </button>
                                </div>
                            )}
                            
                            {error && (
                                <div className="mt-4 p-3 bg-red-500/20 border border-red-500/30 rounded-lg">
                                    <p className="text-sm text-red-400">{error}</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

        function App() {
            const { user, loading, requires2FASetup } = useAuth();
            
            if (loading) {
                return (
                    <div className="min-h-screen bg-proxmox-darker flex items-center justify-center">
                        <div className="text-center">
                            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-proxmox-orange mb-4">
                                <svg className="w-8 h-8 text-white animate-spin" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                            </div>
                            <p className="text-gray-400">Loading...</p>
                        </div>
                    </div>
                );
            }
            
            if (!user) {
                return <LoginScreen />;
            }
            
            // NS: Block access until 2FA is set up (if admin requires it)
            if (requires2FASetup) {
                return (
                    <div className="min-h-screen bg-proxmox-darker">
                        <Force2FASetupModal />
                    </div>
                );
            }
            
            return <PegaProxDashboard />;
        }

        ReactDOM.render(
            <LanguageProvider>
                <AuthProvider>
                    <App />
                </AuthProvider>
            </LanguageProvider>,
            document.getElementById('root')
        );
        
        // LW: Hide loading screen after React renders
        const loadingScreen = document.getElementById('loading-screen');
        if (loadingScreen) {
            loadingScreen.style.opacity = '0';
            loadingScreen.style.transition = 'opacity 0.3s ease';
            setTimeout(() => loadingScreen.remove(), 300);
        }
